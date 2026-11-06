"""HTML pages. Every page is the same small shell that loads the shadcn/ui (React) app built
from web/ into static/app/. Who may see which page is still decided here, on the server."""
import hmac
import json
import secrets
from functools import lru_cache
from pathlib import Path

from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, session, url_for

from .auth import attempt_login, create_user, csrf_token, current_user, login_required, password_ok
from .db import get_db

bp = Blueprint("views", __name__)

APP_DIR = Path(__file__).resolve().parent / "static" / "app"


@lru_cache(maxsize=1)
def _bundle_files(mtime: float) -> dict:
    """The entry's JS and CSS file names, read from Vite's manifest (cached until the build changes)."""
    manifest = json.loads((APP_DIR / ".vite" / "manifest.json").read_text(encoding="utf-8"))
    entry = manifest["src/main.tsx"]
    return {"js": "app/" + entry["file"], "css": ["app/" + c for c in entry.get("css", [])]}


def bundle() -> dict:
    path = APP_DIR / ".vite" / "manifest.json"
    if not path.exists():
        abort(500, "The UI is not built. Run: cd web && npm install && npm run build")
    return _bundle_files(path.stat().st_mtime)


def page(name: str, tab_title: str, status: int = 200, **data):
    user = current_user()
    g.csp_nonce = secrets.token_urlsafe(16)
    boot = {
        "page": name,
        "nonce": g.csp_nonce,
        "csrf": csrf_token(),
        "user": json.dumps({"id": user["id"], "username": user["username"], "role": user["role"]}) if user else "",
        **{k: str(v) for k, v in data.items()},
    }
    return render_template("app.html", title=tab_title, boot=boot, assets=bundle()), status


def _no_users() -> bool:
    return get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


@bp.get("/setup")
def setup():
    """First run only: create the first admin account."""
    if not _no_users():
        return redirect(url_for("views.login"))
    return page("setup", "Welcome")


@bp.post("/api/setup")
def setup_api():
    if not _no_users():
        return jsonify(error="PhishGuard is already set up."), 409
    data = request.get_json(silent=True) or {}
    name = str(data.get("username", "")).strip()[:40]
    pw = str(data.get("password", ""))[:200]
    problem = password_ok(pw)
    if not name or not name.replace("_", "").replace(".", "").isalnum():
        return jsonify(error="Usernames can use letters, numbers, dots and underscores."), 400
    if problem:
        return jsonify(error=problem), 400
    if pw != str(data.get("password2", "")):
        return jsonify(error="The two passwords do not match."), 400
    create_user(get_db(), name, pw, "admin")
    user, _, _ = attempt_login(name, pw)
    return jsonify(user=user, csrf=session.get("csrf"))


@bp.get("/login")
def login():
    if _no_users():
        return redirect(url_for("views.setup"))
    if current_user():
        return redirect(url_for("views.home"))
    nxt = request.args.get("next", "/")
    return page("login", "Log in", next=nxt if nxt.startswith("/") and not nxt.startswith("//") else "/")


@bp.get("/")
@login_required()
def home():
    return page("home", "Home")


@bp.get("/check/<int:sid>")
def check(sid):
    """The Airlock. Opened by the launcher with a one-time ticket, or from History."""
    ticket = request.args.get("t")
    if ticket:
        row = get_db().execute("SELECT ticket FROM scans WHERE id = ?", (sid,)).fetchone()
        if row and row["ticket"] and hmac.compare_digest(row["ticket"], ticket):
            session["tickets"] = (session.get("tickets", []) + [sid])[-20:]
            get_db().execute("UPDATE scans SET ticket = NULL WHERE id = ?", (sid,))
            get_db().commit()
        return redirect(url_for("views.check", sid=sid))       # keep the ticket out of history
    if not current_user() and sid not in session.get("tickets", []):
        return redirect(url_for("views.login", next=request.path))
    return page("check", "Airlock", sid=sid, standalone="0" if current_user() else "1")


@bp.get("/history")
@login_required()
def history():
    return page("history", "History")


@bp.get("/lists")
@login_required()
def lists():
    return page("lists", "Trusted & blocked")


@bp.get("/guard")
@login_required()
def guard():
    return page("guard", "AI Guard lab")


@bp.get("/settings")
@login_required("admin")
def settings():
    return page("settings", "Settings")


@bp.app_errorhandler(403)
def forbidden(e):
    if request.path.startswith("/api/"):
        return e
    return page("message", "Not allowed", 403, title="Not allowed",
                text="PhishGuard refused this request. Only admins can open some pages, and every change must come from PhishGuard itself.")


@bp.app_errorhandler(404)
def not_found(e):
    if request.path.startswith(("/api/", "/shots/", "/static/")):
        return e
    return page("message", "Nothing here", 404, title="Nothing here", text="This page does not exist.")
