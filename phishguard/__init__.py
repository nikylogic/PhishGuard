"""PhishGuard: a sandboxed link inspector for Windows.

create_app() builds the Flask app. Everything that touches the disk lives in
the instance folder (database, secrets, screenshots, quarantine), so tests can
point it at a temporary folder.
"""
import secrets
from datetime import timedelta
from pathlib import Path

from flask import Flask, g, jsonify, request
from werkzeug.exceptions import HTTPException

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


def instance_id(path) -> str:
    """A short fingerprint of the data folder (the same formula is in launcher/pglaunch.py)."""
    import hashlib
    return hashlib.sha256(str(Path(path).resolve()).lower().encode("utf-8")).hexdigest()[:16]


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
        PERMANENT_SESSION_LIFETIME=timedelta(days=30),   # personal mode stays signed in
        REGISTRY_BASE="Software",        # tests point these three at throwaway places
        SHORTCUT_PATH=None,
        OPEN_SETTINGS=None,
    )
    app.config.update(overrides)

    db.init_db(app.config["DATABASE"])
    app.teardown_appcontext(db.close_db)

    from . import auth
    from .api import auth_bp, bp as api_bp
    app.before_request(auth.check_request)
    app.register_blueprint(auth_bp)
    app.register_blueprint(api_bp)
    try:
        from .views import bp as views_bp
        app.register_blueprint(views_bp)
    except ImportError:
        pass

    @app.errorhandler(HTTPException)
    def http_error(e):
        if request.path.startswith("/api/") or request.path.startswith("/shots/"):
            return jsonify(error=e.description or e.name), e.code
        return e

    # The scan service: sandbox worker + judging pipeline. Tests pass their own.
    if "SERVICE" in overrides:
        service = overrides["SERVICE"]
    else:
        from .services import ScanService
        service = ScanService(app.config["DATABASE"], instance)
        if app.config.get("START_WORKER"):
            from .sandbox import Sandbox
            from .worker import ScanWorker
            service.worker = ScanWorker(
                lambda: Sandbox(instance / "shots", instance / "quarantine", route=service.privacy_route),
                on_done=service.on_capture, on_start=service.mark_running).start()
    app.extensions["pg_service"] = service

    @app.after_request
    def security_headers(resp):
        csp = CSP
        nonce = g.get("csp_nonce")
        if nonce:
            # Radix dialogs and menus add one small <style> tag (scroll lock); only tags carrying
            # this page's one-time nonce may do that. Still no 'unsafe-inline'.
            csp = csp.replace("style-src 'self'", f"style-src 'self' 'nonce-{nonce}'")
        resp.headers["Content-Security-Policy"] = csp
        resp.headers["X-Content-Type-Options"] = "nosniff"
        resp.headers["X-Frame-Options"] = "DENY"
        resp.headers["Referrer-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Opener-Policy"] = "same-origin"
        resp.headers["Cross-Origin-Resource-Policy"] = "same-origin"
        return resp

    @app.get("/health")
    def health():
        # "instance" lets the launcher tell its own engine from another PhishGuard copy on the same port.
        return jsonify(ok=True, app="phishguard", instance=instance_id(app.config["INSTANCE_DIR"]))

    return app
