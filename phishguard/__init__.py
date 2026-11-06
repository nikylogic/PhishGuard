"""PhishGuard: a sandboxed link inspector for Windows.

create_app() builds the Flask app. Everything that touches the disk lives in
the instance folder (database, secrets, screenshots, quarantine), so tests can
point it at a temporary folder.
"""
import secrets
from pathlib import Path

from flask import Flask, jsonify

from . import db

ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"   # never listen on the network
PORT = 5157

CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; "
    "form-action 'self'; object-src 'none'"
)


def read_or_create_secret(path: Path, nbytes: int = 32) -> str:
    """Return the secret stored in `path`, creating it the first time."""
    if path.exists():
        value = path.read_text(encoding="utf-8").strip()
        if value:
            return value
    path.parent.mkdir(parents=True, exist_ok=True)
    value = secrets.token_urlsafe(nbytes)
    path.write_text(value, encoding="utf-8")
    return value


def create_app(overrides: dict | None = None) -> Flask:
    overrides = overrides or {}
    instance = Path(overrides.get("INSTANCE_DIR", ROOT / "instance"))
    instance.mkdir(parents=True, exist_ok=True)
    for sub in ("shots", "quarantine"):
        (instance / sub).mkdir(exist_ok=True)

    app = Flask(__name__, instance_path=str(instance))
    app.config.update(
        INSTANCE_DIR=str(instance),
        DATABASE=str(instance / "phishguard.db"),
        SECRET_KEY=read_or_create_secret(instance / "secret.key"),
        LAUNCHER_TOKEN=read_or_create_secret(instance / "launcher.token"),
        HOST=HOST,
        PORT=PORT,
        SESSION_COOKIE_HTTPONLY=True,
        SESSION_COOKIE_SAMESITE="Strict",
        MAX_CONTENT_LENGTH=256 * 1024,
    )
    app.config.update(overrides)

    db.init_db(app.config["DATABASE"])
    app.teardown_appcontext(db.close_db)

    @app.after_request
    def security_headers(resp):
        resp.headers["Content-Security-Policy"] = CSP
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "no-referrer"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        return resp

    @app.get("/health")
    def health():
        return jsonify(ok=True, app="phishguard")

    return app
