"""JSON API used by the app window and the launcher."""
import hmac
import json

from flask import Blueprint, current_app, g, jsonify, request, send_from_directory, session
from werkzeug.exceptions import NotFound

from . import browser
from .auth import (ROLES, attempt_login, audit, create_user, csrf_token, current_user, login_required,
                   password_ok)
from .db import get_db
from .services import get_settings, scan_row
from .urltools import UnsafeURL, clean_url, registrable_domain

bp = Blueprint("api", __name__, url_prefix="/api")
auth_bp = Blueprint("auth", __name__)

SETTING_KEYS = {"browser_path", "llm_provider", "llm_api_key", "llm_model"}
LLM_PROVIDERS = {"none", "gemini", "groq", "ollama"}


def svc():
    return current_app.extensions["pg_service"]


def err(msg, code=400):
    return jsonify(error=msg), code


# --- session ------------------------------------------------------------------------------------

@auth_bp.get("/api/csrf")
def csrf():
    return jsonify(csrf=csrf_token())


@auth_bp.post("/api/login")
def login_api():
    data = request.get_json(silent=True) or request.form
    user, error, code = attempt_login(str(data.get("username", ""))[:80], str(data.get("password", ""))[:200])
    if error:
        return err(error, code)
    return jsonify(user=user, csrf=session["csrf"])


@auth_bp.post("/api/logout")
def logout_api():
    u = current_user()
    if u:
        audit("logout", "")
    session.clear()
    return jsonify(ok=True)


@bp.get("/me")
@login_required()
def me():
    return jsonify(user=current_user(), csrf=csrf_token())


# --- scans ------------------------------------------------------------------------------------------

def _may_view(sid: int) -> bool:
    """Logged-in users may view any scan. The launcher's window holds a one-time ticket
    for exactly one scan, so it can show the Airlock without a login."""
    if current_user():
        return True
    return sid in session.get("tickets", [])


@bp.post("/scan")
def create_scan():
    via_launcher = g.get("via_launcher", False)
    u = current_user()
    if not via_launcher and not u:
        return err("Please log in.", 401)
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", ""))[:4096]
    try:
        out = svc().create_scan(url, "launcher" if via_launcher else "manual", u["id"] if u else None)
    except UnsafeURL as e:
        return err(f"PhishGuard will not open this: {e}", 422)
    audit("scan", f"#{out['id']} {url[:200]}", user_id=u["id"] if u else None)
    return jsonify(out), 201


@bp.get("/ticket/<int:sid>/<ticket>")
def redeem_ticket(sid, ticket):
    row = get_db().execute("SELECT ticket FROM scans WHERE id = ?", (sid,)).fetchone()
    if not row or not row["ticket"] or not hmac.compare_digest(row["ticket"], ticket):
        return err("This link has expired.", 404)
    tickets = session.get("tickets", [])
    session["tickets"] = (tickets + [sid])[-20:]
    csrf_token()
    get_db().execute("UPDATE scans SET ticket = NULL WHERE id = ?", (sid,))     # one use only
    get_db().commit()
    return jsonify(ok=True, csrf=session["csrf"])


@bp.get("/scan/<int:sid>")
def get_scan(sid):
    if not _may_view(sid):
        return err("Please log in.", 401)
    d = scan_row(get_db(), sid)
    if not d:
        return err("No such scan.", 404)
    d["screenshot_url"] = f"/shots/{sid}.jpg" if d.get("screenshot") else None
    d.pop("screenshot", None)
    try:
        d["clean_url"], d["params_removed"] = clean_url(d["url"])
    except ValueError:
        d["clean_url"], d["params_removed"] = d["url"], []
    return jsonify(d)


@bp.post("/scan/<int:sid>/decision")
def decide(sid):
    if not _may_view(sid):
        return err("Please log in.", 401)
    data = request.get_json(silent=True) or {}
    action = data.get("action")
    con = get_db()
    row = con.execute("SELECT id, url, final_url, level, status, domain FROM scans WHERE id = ?", (sid,)).fetchone()
    if not row:
        return err("No such scan.", 404)
    u = current_user()
    uid = u["id"] if u else None

    if action in ("open", "open_clean", "open_direct"):
        if action == "open_direct":
            target = row["url"]          # one-time links: skip the sandbox result entirely
        else:
            target = row["final_url"] or row["url"]
            if action == "open_clean":
                target, _ = clean_url(target)
        if row["level"] == "danger" and data.get("confirm") is not True:
            return err("This link is marked DANGER. Confirm that you really want to open it.", 409)
        if row["level"] == "pending" and action != "open_direct":
            return err("The check is not finished yet.", 409)
        ok = browser.open_url(target, get_settings(con).get("browser_path"),
                              popen=current_app.config.get("POPEN") or __import__("subprocess").Popen)
        if not ok:
            return err("No browser was found. Set your browser in Settings.", 500)
        con.execute("UPDATE scans SET decision = 'opened' WHERE id = ?", (sid,))
        audit("open", f"#{sid} level={row['level']} {target[:200]}", user_id=uid)
    elif action == "block":
        dom = row["domain"]
        con.execute("INSERT INTO domain_lists(domain, kind, note, added_by) VALUES (?, 'block', ?, ?) "
                    "ON CONFLICT(domain) DO UPDATE SET kind = 'block'", (dom, f"from scan #{sid}", uid))
        con.execute("UPDATE scans SET decision = 'blocked' WHERE id = ?", (sid,))
        con.commit()
        svc().write_allowlist_cache()
        audit("block", f"#{sid} {dom}", user_id=uid)
    elif action == "ignore":
        con.execute("UPDATE scans SET decision = 'ignored' WHERE id = ?", (sid,))
        audit("ignore", f"#{sid}", user_id=uid)
    else:
        return err("Unknown action.")
    con.commit()
    return jsonify(ok=True)


@bp.get("/scans")
@login_required()
def list_scans():
    q = request.args.get("q", "").strip()[:100]
    level = request.args.get("level", "")
    limit = min(max(int(request.args.get("limit", 50) or 50), 1), 200)
    sql = ("SELECT id, url, domain, level, score, s_phishing, s_malware, s_tracking, s_abuse, status, decision, "
           "source, title, created_at FROM scans WHERE 1=1")
    args = []
    if q:
        sql += " AND (url LIKE ? OR title LIKE ?)"
        args += [f"%{q}%", f"%{q}%"]
    if level in ("clear", "caution", "danger", "pending"):
        sql += " AND level = ?"
        args.append(level)
    sql += " ORDER BY id DESC LIMIT ?"
    args.append(limit)
    return jsonify(scans=[dict(r) for r in get_db().execute(sql, args)])


@bp.get("/stats")
@login_required()
def stats():
    con = get_db()
    one = lambda sql, *a: con.execute(sql, a).fetchone()[0]  # noqa: E731
    days = [dict(r) for r in con.execute(
        "SELECT date(created_at) AS day, SUM(level='clear') AS clear, SUM(level='caution') AS caution, "
        "SUM(level='danger') AS danger FROM scans WHERE created_at >= datetime('now', '-6 days') "
        "GROUP BY day ORDER BY day")]
    top = [dict(r) for r in con.execute(
        "SELECT domain, COUNT(*) AS n FROM scans WHERE level = 'danger' GROUP BY domain ORDER BY n DESC LIMIT 5")]
    trackers = 0
    for r in con.execute("SELECT trackers_json FROM privacy p JOIN scans s ON s.id = p.scan_id "
                         "WHERE date(s.created_at) = date('now')"):
        trackers += len(json.loads(r[0] or "[]"))
    return jsonify(
        today=one("SELECT COUNT(*) FROM scans WHERE date(created_at) = date('now')"),
        stopped_today=one("SELECT COUNT(*) FROM scans WHERE date(created_at) = date('now') AND level = 'danger'"),
        trackers_today=trackers, total=one("SELECT COUNT(*) FROM scans"),
        by_level={lv: one("SELECT COUNT(*) FROM scans WHERE level = ?", lv) for lv in ("clear", "caution", "danger")},
        days=days, top_dangerous=top)


# --- screenshots -------------------------------------------------------------------------------------

@auth_bp.get("/shots/<int:sid>.jpg")
def shot(sid):
    if not _may_view(sid):
        return err("Please log in.", 401)
    row = get_db().execute("SELECT screenshot FROM scans WHERE id = ?", (sid,)).fetchone()
    if not row or not row["screenshot"]:
        raise NotFound()
    resp = send_from_directory(current_app.config["INSTANCE_DIR"] + "/shots", row["screenshot"], mimetype="image/jpeg")
    resp.headers["Cache-Control"] = "private, max-age=3600"
    return resp


# --- allow and block lists -------------------------------------------------------------------------------

@bp.get("/lists")
@login_required()
def get_lists():
    rows = get_db().execute("SELECT d.id, d.domain, d.kind, d.note, d.created_at, u.username AS added_by "
                            "FROM domain_lists d LEFT JOIN users u ON u.id = d.added_by ORDER BY d.domain")
    return jsonify(items=[dict(r) for r in rows])


@bp.post("/lists")
@login_required()
def add_list_item():
    data = request.get_json(silent=True) or {}
    kind = data.get("kind")
    raw = str(data.get("domain", "")).strip().lower()[:253]
    if kind not in ("allow", "block") or not raw:
        return err("Give a website and choose Trusted or Blocked.")
    try:
        dom = registrable_domain(raw if "://" in raw else f"https://{raw}")
    except (UnsafeURL, ValueError):
        return err("That does not look like a website name.")
    if "." not in dom:
        return err("That does not look like a website name.")
    con = get_db()
    con.execute("INSERT INTO domain_lists(domain, kind, note, added_by) VALUES (?, ?, ?, ?) "
                "ON CONFLICT(domain) DO UPDATE SET kind = excluded.kind, note = excluded.note",
                (dom, kind, str(data.get("note", ""))[:200], current_user()["id"]))
    con.commit()
    svc().write_allowlist_cache()
    audit(f"list_{kind}", dom)
    return jsonify(ok=True, domain=dom), 201


@bp.delete("/lists/<int:item_id>")
@login_required()
def delete_list_item(item_id):
    con = get_db()
    row = con.execute("SELECT domain, kind FROM domain_lists WHERE id = ?", (item_id,)).fetchone()
    if not row:
        return err("Not found.", 404)
    con.execute("DELETE FROM domain_lists WHERE id = ?", (item_id,))
    con.commit()
    svc().write_allowlist_cache()
    audit("list_remove", f"{row['kind']} {row['domain']}")
    return jsonify(ok=True)


# --- AI Guard playground ---------------------------------------------------------------------------------

@bp.post("/guard")
@login_required()
def guard_check():
    g_ = svc().guard
    if g_ is None:
        return err("The AI Guard model is not installed.", 503)
    text = str((request.get_json(silent=True) or {}).get("text", ""))[:8000]
    r = g_.check(text)
    con = get_db()
    con.execute("INSERT INTO guard_events(source, text_snippet, score, label) VALUES ('playground', ?, ?, ?)",
                (text[:280], r["score"], r["label"]))
    con.commit()
    return jsonify(r)


# --- admin: settings, users, audit --------------------------------------------------------------------------

@bp.get("/settings")
@login_required("admin")
def read_settings():
    s = get_settings(get_db())
    key = s.get("llm_api_key") or ""
    s["llm_api_key"] = ("•" * 8 + key[-4:]) if key else ""
    s["browsers"] = browser.detect()
    return jsonify(s)


@bp.post("/settings")
@login_required("admin")
def write_settings():
    data = request.get_json(silent=True) or {}
    con = get_db()
    changed = []
    for k, v in data.items():
        if k not in SETTING_KEYS:
            return err(f"Unknown setting: {k}")
        v = str(v)[:500]
        if k == "llm_provider" and v not in LLM_PROVIDERS:
            return err("Unknown AI provider.")
        if k == "browser_path" and v and not (v.lower().endswith(".exe") and browser.Path(v).exists()):
            return err("That browser program was not found.")
        if k == "llm_api_key" and v.startswith("•"):
            continue                       # the masked value came back unchanged
        con.execute("INSERT INTO settings(key, value) VALUES (?, ?) ON CONFLICT(key) DO UPDATE SET value = excluded.value",
                    (k, v))
        changed.append(k)
    con.commit()
    audit("settings", ", ".join(changed))
    return jsonify(ok=True, changed=changed)


@bp.get("/users")
@login_required("admin")
def list_users():
    rows = get_db().execute("SELECT id, username, role, created_at, last_login FROM users ORDER BY id")
    return jsonify(users=[dict(r) for r in rows])


@bp.post("/users")
@login_required("admin")
def add_user():
    data = request.get_json(silent=True) or {}
    name, pw, role = str(data.get("username", "")).strip()[:40], str(data.get("password", "")), data.get("role")
    if not name or not name.replace("_", "").replace(".", "").isalnum():
        return err("Usernames can use letters, numbers, dots and underscores.")
    if role not in ROLES:
        return err("Choose admin or analyst.")
    problem = password_ok(pw)
    if problem:
        return err(problem)
    con = get_db()
    if con.execute("SELECT 1 FROM users WHERE lower(username) = lower(?)", (name,)).fetchone():
        return err("That username is taken.", 409)
    uid = create_user(con, name, pw, role)
    audit("user_add", f"{name} ({role})")
    return jsonify(ok=True, id=uid), 201


@bp.delete("/users/<int:uid>")
@login_required("admin")
def delete_user(uid):
    if uid == current_user()["id"]:
        return err("You cannot delete yourself.")
    con = get_db()
    row = con.execute("SELECT username, role FROM users WHERE id = ?", (uid,)).fetchone()
    if not row:
        return err("Not found.", 404)
    if row["role"] == "admin" and con.execute("SELECT COUNT(*) FROM users WHERE role = 'admin'").fetchone()[0] <= 1:
        return err("PhishGuard needs at least one admin.")
    con.execute("DELETE FROM users WHERE id = ?", (uid,))
    con.commit()
    audit("user_delete", row["username"])
    return jsonify(ok=True)


@bp.get("/audit")
@login_required("admin")
def audit_log():
    rows = get_db().execute("SELECT a.id, a.action, a.detail, a.ip, a.created_at, u.username FROM audit_log a "
                            "LEFT JOIN users u ON u.id = a.user_id ORDER BY a.id DESC LIMIT 300")
    return jsonify(items=[dict(r) for r in rows])
