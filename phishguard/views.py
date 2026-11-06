"""HTML pages. They are thin shells: data comes from the JSON API via small scripts."""
import hmac

from flask import Blueprint, abort, redirect, render_template, request, session, url_for

from .auth import attempt_login, create_user, csrf_token, current_user, login_required, password_ok
from .db import get_db

bp = Blueprint("views", __name__)


@bp.app_context_processor
def inject():
    return {"csrf_token": csrf_token, "me": current_user()}


def _no_users() -> bool:
    return get_db().execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0


@bp.route("/setup", methods=["GET", "POST"])
def setup():
    """First run only: create the first admin account."""
    if not _no_users():
        return redirect(url_for("views.login"))
    error = None
    if request.method == "POST":
        name = request.form.get("username", "").strip()[:40]
        pw = request.form.get("password", "")
        problem = password_ok(pw)
        if not name or not name.replace("_", "").replace(".", "").isalnum():
            error = "Usernames can use letters, numbers, dots and underscores."
        elif problem:
            error = problem
        elif pw != request.form.get("password2", ""):
            error = "The two passwords do not match."
        else:
            create_user(get_db(), name, pw, "admin")
            attempt_login(name, pw)
            return redirect(url_for("views.home"))
    return render_template("setup.html", error=error)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if _no_users():
        return redirect(url_for("views.setup"))
    error = None
    if request.method == "POST":
        user, error, _ = attempt_login(request.form.get("username", "")[:80], request.form.get("password", "")[:200])
        if user:
            nxt = request.args.get("next", "")
            return redirect(nxt if nxt.startswith("/") and not nxt.startswith("//") else url_for("views.home"))
    return render_template("login.html", error=error)


@bp.post("/logout")
def logout():
    session.clear()
    return redirect(url_for("views.login"))


@bp.get("/")
@login_required()
def home():
    return render_template("home.html", page="home")


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
    return render_template("check.html", page="check", sid=sid, standalone=not current_user())


@bp.get("/history")
@login_required()
def history():
    return render_template("history.html", page="history")


@bp.get("/lists")
@login_required()
def lists():
    return render_template("lists.html", page="lists")


@bp.get("/guard")
@login_required()
def guard():
    return render_template("guard.html", page="guard")


@bp.get("/settings")
@login_required("admin")
def settings():
    return render_template("settings.html", page="settings")


@bp.app_errorhandler(403)
def forbidden(e):
    if request.path.startswith("/api/"):
        return e
    return render_template("message.html", title="Not allowed", text="PhishGuard refused this request. Only admins can open some pages, and every form must come from PhishGuard itself."), 403


@bp.app_errorhandler(404)
def not_found(e):
    if request.path.startswith(("/api/", "/shots/", "/static/")):
        return e
    return render_template("message.html", title="Nothing here", text="This page does not exist."), 404
