"""Login, roles, CSRF protection, request origin checks and the audit log."""
import hmac
import secrets
import threading
import time
from functools import wraps

from flask import abort, current_app, g, jsonify, request, session
from werkzeug.security import check_password_hash, generate_password_hash

from .db import get_db

ROLES = ("admin", "analyst")
ALLOWED_HOSTS = {"127.0.0.1", "localhost"}
MAX_FAILS, WINDOW, LOCK = 5, 60, 60          # 5 failures within 60 s locks the name for 60 s


# --- passwords and users -----------------------------------------------------------------

def hash_password(pw: str) -> str:
    return generate_password_hash(pw, method="scrypt")


def password_ok(pw: str) -> str | None:
    """Return a problem with the password, or None if it is acceptable."""
    if len(pw) < 8:
        return "Use at least 8 characters."
    if pw.lower() in {"password", "12345678", "phishguard", "qwertyui", "11111111"}:
        return "That password is too common."
    return None


def create_user(con, username: str, password: str, role: str) -> int:
    if role not in ROLES:
        raise ValueError("unknown role")
    cur = con.execute("INSERT INTO users(username, pw_hash, role) VALUES (?, ?, ?)",
                      (username.strip(), hash_password(password), role))
    con.commit()
    return cur.lastrowid


def current_user():
    if "user" in g:
        return g.user
    uid = session.get("uid")
    g.user = None
    if uid:
        row = get_db().execute("SELECT id, username, role FROM users WHERE id = ?", (uid,)).fetchone()
        if row:
            g.user = dict(row)
    return g.user


# --- audit log ------------------------------------------------------------------------------

def audit(action: str, detail: str = "", user_id=None, con=None):
    con = con or get_db()
    if user_id is None:
        u = current_user() if request else None
        user_id = u["id"] if u else None
    ip = request.remote_addr if request else None
    con.execute("INSERT INTO audit_log(user_id, action, detail, ip) VALUES (?, ?, ?, ?)",
                (user_id, action, detail[:500], ip))
    con.commit()


# --- brute-force protection -------------------------------------------------------------------

class LoginLimiter:
    def __init__(self):
        self.fails: dict[str, list[float]] = {}
        self.lock = threading.Lock()

    def locked(self, key: str) -> int:
        """Seconds left on a lock, or 0."""
        now = time.time()
        with self.lock:
            recent = [t for t in self.fails.get(key, []) if now - t < WINDOW + LOCK]
            self.fails[key] = recent
            if len([t for t in recent if now - t < WINDOW]) >= MAX_FAILS:
                return int(LOCK - (now - recent[-1])) + 1
        return 0

    def fail(self, key: str):
        with self.lock:
            self.fails.setdefault(key, []).append(time.time())

    def clear(self, key: str):
        with self.lock:
            self.fails.pop(key, None)


limiter = LoginLimiter()


def attempt_login(username: str, password: str) -> tuple[dict | None, str | None, int]:
    """Returns (user, error, http_status)."""
    key = username.strip().lower()
    wait = limiter.locked(key)
    if wait:
        return None, f"Too many failed attempts. Try again in {wait} s.", 429
    row = get_db().execute("SELECT id, username, role, pw_hash FROM users WHERE lower(username) = ?",
                           (key,)).fetchone()
    # Always run one hash check so a wrong username takes as long as a wrong password.
    ok = check_password_hash(row["pw_hash"] if row else _DUMMY_HASH, password)
    if not row or not ok:
        limiter.fail(key)
        audit("login_failed", f"username={username[:40]}", user_id=None)
        return None, "Wrong username or password.", 401
    limiter.clear(key)
    session.clear()
    session["uid"] = row["id"]
    session["csrf"] = secrets.token_urlsafe(32)
    session.permanent = False
    get_db().execute("UPDATE users SET last_login = datetime('now') WHERE id = ?", (row["id"],))
    audit("login", "", user_id=row["id"])
    return {"id": row["id"], "username": row["username"], "role": row["role"]}, None, 200


_DUMMY_HASH = generate_password_hash("not-a-real-password", method="scrypt")


# --- CSRF, origin and host checks ----------------------------------------------------------------

def csrf_token() -> str:
    if "csrf" not in session:
        session["csrf"] = secrets.token_urlsafe(32)
    return session["csrf"]


def launcher_authenticated() -> bool:
    token = request.headers.get("X-PhishGuard-Token", "")
    expected = current_app.config["LAUNCHER_TOKEN"]
    return bool(token) and hmac.compare_digest(token.encode(), expected.encode())


def check_request():
    """Runs before every request."""
    # 1. DNS-rebinding defence: only answer to our own host names.
    host = (request.host or "").rsplit(":", 1)[0].strip("[]").lower()
    if host not in ALLOWED_HOSTS:
        abort(421, "Misdirected request")
    if request.method in ("GET", "HEAD", "OPTIONS"):
        return
    # 2. Cross-site requests: if the browser says where the request came from, it must be us.
    origin = request.headers.get("Origin")
    if origin and origin != "null":
        o_host = origin.split("://", 1)[-1].split("/", 1)[0].rsplit(":", 1)[0].lower()
        if o_host not in ALLOWED_HOSTS:
            abort(403, "Cross-site request refused")
    elif origin == "null":
        abort(403, "Cross-site request refused")
    # 3. CSRF token for anything that uses the login cookie. The launcher uses its own token.
    if launcher_authenticated():
        g.via_launcher = True
        return
    if request.endpoint in ("auth.login_api",) and not session.get("csrf"):
        abort(403, "Missing CSRF token")
    sent = request.headers.get("X-CSRF-Token") or request.form.get("csrf_token", "")
    if not sent or not session.get("csrf") or not hmac.compare_digest(sent, session["csrf"]):
        abort(403, "Missing or wrong CSRF token")


# --- decorators --------------------------------------------------------------------------------------

def login_required(role: str | None = None):
    def deco(fn):
        @wraps(fn)
        def wrapper(*a, **kw):
            u = current_user()
            if not u:
                if request.path.startswith("/api/"):
                    return jsonify(error="Please log in."), 401
                from flask import redirect, url_for
                return redirect(url_for("views.login", next=request.path))
            if role and u["role"] != role:
                if request.path.startswith("/api/"):
                    return jsonify(error="Only an admin can do this."), 403
                abort(403)
            return fn(*a, **kw)
        return wrapper
    return deco
