"""HTML pages. Every page is the same small shell that loads the shadcn/ui (React) app built
from web/ into static/app/. Who may see which page is still decided here, on the server."""
import hmac
import json
import secrets
from functools import lru_cache
from pathlib import Path

from flask import Blueprint, abort, current_app, g, jsonify, redirect, render_template, request, session, url_for

from .auth import (attempt_login, audit, auth_mode, create_user, csrf_token, current_user, entry_codes, hash_password,
                   login_required, owner_id, password_ok, set_setting, start_session)
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
        "mode": auth_mode(),
        **{k: str(v) for k, v in data.items()},
    }
    return render_template("app.html", title=tab_title, boot=boot, assets=bundle()), status


def account_problem(data) -> tuple[str, str, str | None]:
    """Check a new admin username and password. Returns (name, password, problem)."""
    name = str(data.get("username", "")).strip()[:40]
    pw = str(data.get("password", ""))[:200]
    if not name or not name.replace("_", "").replace(".", "").isalnum():
        return name, pw, "Usernames can use letters, numbers, dots and underscores."
    problem = password_ok(pw)
    if problem:
        return name, pw, problem
    if pw != str(data.get("password2", "")):
        return name, pw, "The two passwords do not match."
    return name, pw, None


def make_owner(con) -> int:
    """The built-in account personal mode uses. Its password is random and never shown,
    so nobody can log in with it; the way in is the launcher's one-time code."""
    import secrets as _s
    cur = con.execute("INSERT INTO users(username, pw_hash, role) VALUES (?, ?, 'admin')",
                      ("you", hash_password(_s.token_urlsafe(32))))
    return cur.lastrowid


@bp.get("/setup")
def setup():
    """First run only: choose personal mode (no passwords) or accounts."""
    if auth_mode() != "unset":
        return redirect(url_for("views.login"))
    return page("setup", "Welcome")


@bp.post("/api/setup")
def setup_api():
    con = get_db()
    if auth_mode(con) != "unset":
        return jsonify(error="PhishGuard is already set up."), 409
    data = request.get_json(silent=True) or {}
    if data.get("mode", "accounts") == "personal":
        uid = make_owner(con)
        set_setting(con, "auth_mode", "personal")
        set_setting(con, "owner_id", str(uid))
        con.commit()
        start_session(uid, permanent=True)
        audit("setup", "personal mode")
        return jsonify(user=current_user(), csrf=session["csrf"], mode="personal")
    name, pw, problem = account_problem(data)
    if problem:
        return jsonify(error=problem), 400
    create_user(con, name, pw, "admin")
    set_setting(con, "auth_mode", "accounts")
    con.commit()
    user, _, _ = attempt_login(name, pw)
    return jsonify(user=user, csrf=session.get("csrf"), mode="accounts")


@bp.get("/enter/<code>")
def enter(code):
    """Personal mode: the launcher's Start-menu shortcut opens the dashboard through here."""
    if auth_mode() == "personal" and entry_codes.redeem(code) and owner_id():
        start_session(owner_id(), permanent=True)
        return redirect(url_for("views.home"))
    return redirect(url_for("views.login"))


@bp.get("/login")
def login():
    mode = auth_mode()
    if mode == "unset":
        return redirect(url_for("views.setup"))
    if current_user():
        return redirect(url_for("views.home"))
    if mode == "personal":
        return page("message", "Open PhishGuard", 401, title="Open PhishGuard from the Start menu",
                    text="PhishGuard is in personal mode, so there is no password. Open it with the PhishGuard "
                         "shortcut in the Start menu.")
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
