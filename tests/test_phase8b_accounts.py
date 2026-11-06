"""Phase 8b: personal mode (no passwords for one person), switching modes, the dashboard shortcut,
and the "Make PhishGuard my default browser" button.

Registry tests write under a throwaway HKCU key and a temporary shortcut path; Windows Settings is
never really opened (a recorder stands in for it).
"""
import os
import subprocess
import sys
import uuid
import winreg
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "launcher"))

import pglaunch  # noqa: E402
import registry  # noqa: E402
from phishguard import create_app  # noqa: E402
from phishguard.auth import create_user, entry_codes, limiter  # noqa: E402
from phishguard.db import connect  # noqa: E402

from .test_phase8_launcher import PG_OPEN, Recorder, free_port  # noqa: E402


@pytest.fixture
def reg_base():
    base = rf"Software\PhishGuardTest-{uuid.uuid4().hex[:8]}"
    yield base
    registry._delete_tree(base)


@pytest.fixture
def opened():
    return []


@pytest.fixture
def app(tmp_path, reg_base, opened):
    limiter.fails.clear()
    return create_app({"INSTANCE_DIR": str(tmp_path / "instance"), "TESTING": True, "REGISTRY_BASE": reg_base,
                       "SHORTCUT_PATH": str(tmp_path / "Start Menu" / "PhishGuard.lnk"),
                       "OPEN_SETTINGS": opened.append})


def fresh(app):
    c = app.test_client()
    c.csrf = c.get("/api/csrf").get_json()["csrf"]
    return c


def post(c, url, body=None, **headers):
    r = c.post(url, json=body or {}, headers={"X-CSRF-Token": c.csrf, **headers})
    if r.is_json and isinstance(r.get_json(), dict) and r.get_json().get("csrf"):
        c.csrf = r.get_json()["csrf"]
    return r


def token(app):
    return app.config["LAUNCHER_TOKEN"]


def personal(app):
    c = fresh(app)
    r = post(c, "/api/setup", {"mode": "personal"})
    assert r.status_code == 200 and r.get_json()["mode"] == "personal"
    return c


# ---------------------------------------------------------------- first run

def test_first_run_offers_just_me_or_several_people(app):
    c = fresh(app)
    page = c.get("/login", follow_redirects=True)
    assert 'data-page="setup"' in page.text and 'data-mode="unset"' in page.text


def test_just_me_needs_no_password_and_signs_you_in(app):
    c = personal(app)
    me = c.get("/api/me").get_json()
    assert me["mode"] == "personal" and me["user"]["role"] == "admin"
    assert c.get("/").status_code == 200 and 'data-mode="personal"' in c.get("/").text
    assert c.get("/settings").status_code == 200


def test_setup_cannot_run_twice(app):
    personal(app)
    assert post(fresh(app), "/api/setup", {"mode": "personal"}).status_code == 409
    assert post(fresh(app), "/api/setup", {"mode": "accounts", "username": "eve", "password": "long-enough-1",
                                           "password2": "long-enough-1"}).status_code == 409


def test_the_owner_account_has_no_usable_password(app):
    personal(app)
    for pw in ("", "!", "you", "password", "admin"):
        assert post(fresh(app), "/api/login", {"username": "you", "password": pw}).status_code in (401, 409)


def test_personal_mode_session_survives_closing_the_window(app):
    c = personal(app)
    cookie = c.get_cookie("session")
    assert cookie is not None and cookie.expires is not None       # a lasting cookie, not a session one


# ---------------------------------------------------------------- strangers cannot get in

def test_a_stranger_in_personal_mode_gets_no_dashboard(app):
    personal(app)
    s = fresh(app)
    assert s.get("/api/me").status_code == 401
    assert s.get("/api/scans").status_code == 401
    page = s.get("/", follow_redirects=True)
    assert 'data-page="message"' in page.text and "Start menu" in page.text
    assert post(s, "/api/login", {"username": "you", "password": "x"}).status_code == 409


def test_only_the_launcher_can_get_an_entry_code(app):
    personal(app)
    s = fresh(app)
    assert post(s, "/api/entry").status_code == 403                                  # a web page
    assert post(s, "/api/entry", **{"X-PhishGuard-Token": "guess"}).status_code == 403
    r = s.post("/api/entry", headers={"X-PhishGuard-Token": token(app)})            # the launcher
    assert r.status_code == 200 and len(r.get_json()["code"]) >= 40


def test_an_entry_code_works_once(app):
    personal(app)
    code = fresh(app).post("/api/entry", headers={"X-PhishGuard-Token": token(app)}).get_json()["code"]
    a = fresh(app)
    r = a.get(f"/enter/{code}")
    assert r.status_code == 302 and r.headers["Location"].endswith("/")
    assert a.get("/api/me").status_code == 200
    b = fresh(app)
    assert b.get(f"/enter/{code}").headers["Location"].endswith("/login")            # used up
    assert b.get("/api/me").status_code == 401
    assert fresh(app).get("/enter/made-up-code").headers["Location"].endswith("/login")


def test_an_entry_code_expires(app, monkeypatch):
    personal(app)
    code = fresh(app).post("/api/entry", headers={"X-PhishGuard-Token": token(app)}).get_json()["code"]
    monkeypatch.setitem(entry_codes.codes, code, 0)                                   # pretend a minute passed
    c = fresh(app)
    c.get(f"/enter/{code}")
    assert c.get("/api/me").status_code == 401


def test_accounts_mode_gives_the_launcher_no_code(app):
    c = fresh(app)
    post(c, "/api/setup", {"mode": "accounts", "username": "boss", "password": "long-enough-1",
                           "password2": "long-enough-1"})
    r = fresh(app).post("/api/entry", headers={"X-PhishGuard-Token": token(app)})
    assert r.get_json() == {"code": None, "mode": "accounts"}


# ---------------------------------------------------------------- switching modes

def test_switch_personal_to_accounts_and_back(app):
    c = personal(app)
    bad = post(c, "/api/account-mode", {"mode": "accounts", "username": "nikhil", "password": "short",
                                        "password2": "short"})
    assert bad.status_code == 400
    r = post(c, "/api/account-mode", {"mode": "accounts", "username": "nikhil", "password": "long-enough-1",
                                      "password2": "long-enough-1"})
    assert r.status_code == 200 and r.get_json()["mode"] == "accounts"
    assert c.get("/api/me").get_json()["user"]["username"] == "nikhil"                # still signed in
    # Now the password works from a fresh browser, and the launcher gets no code.
    s = fresh(app)
    assert post(s, "/api/login", {"username": "nikhil", "password": "long-enough-1"}).status_code == 200
    assert fresh(app).post("/api/entry", headers={"X-PhishGuard-Token": token(app)}).get_json()["code"] is None
    # Back to personal mode needs the password.
    assert post(s, "/api/account-mode", {"mode": "personal", "password": "wrong"}).status_code == 403
    assert post(s, "/api/account-mode", {"mode": "personal", "password": "long-enough-1"}).get_json()["mode"] == "personal"
    assert fresh(app).post("/api/entry", headers={"X-PhishGuard-Token": token(app)}).get_json()["code"]


def test_switching_to_personal_locks_out_other_accounts(app):
    c = fresh(app)
    post(c, "/api/setup", {"mode": "accounts", "username": "boss", "password": "long-enough-1",
                           "password2": "long-enough-1"})
    con = connect(app.config["DATABASE"])
    create_user(con, "helper", "helper-pass-1", "analyst")
    con.close()
    h = fresh(app)
    assert post(h, "/api/login", {"username": "helper", "password": "helper-pass-1"}).status_code == 200
    assert post(c, "/api/account-mode", {"mode": "personal", "password": "long-enough-1"}).status_code == 200
    assert h.get("/api/me").status_code == 401                                      # the helper is out
    assert c.get("/api/me").status_code == 200                                      # the owner stays in


def test_analysts_cannot_switch_modes(app):
    c = fresh(app)
    post(c, "/api/setup", {"mode": "accounts", "username": "boss", "password": "long-enough-1",
                           "password2": "long-enough-1"})
    con = connect(app.config["DATABASE"])
    create_user(con, "helper", "helper-pass-1", "analyst")
    con.close()
    h = fresh(app)
    post(h, "/api/login", {"username": "helper", "password": "helper-pass-1"})
    assert post(h, "/api/account-mode", {"mode": "personal", "password": "helper-pass-1"}).status_code == 403


def test_old_databases_with_users_count_as_accounts(app):
    con = connect(app.config["DATABASE"])
    create_user(con, "admin", "correct-horse-1", "admin")
    con.close()
    c = fresh(app)
    assert 'data-page="login"' in c.get("/login").text
    assert post(c, "/api/login", {"username": "admin", "password": "correct-horse-1"}).status_code == 200


# ---------------------------------------------------------------- the launcher's dashboard shortcut

def test_launcher_dashboard_opens_the_entry_page(tmp_path):
    inst = tmp_path / "instance"
    port = free_port()
    env = {**os.environ, "PHISHGUARD_INSTANCE": str(inst), "PHISHGUARD_PORT": str(port), "PHISHGUARD_NO_WORKER": "1",
           "PHISHGUARD_NO_DIALOGS": "1"}
    base = f"http://127.0.0.1:{port}"
    try:
        # Before setup there is no owner yet: the dashboard window shows the first-run page.
        p = subprocess.run([sys.executable, str(PG_OPEN), "--dashboard", "--no-window"], env=env,
                           capture_output=True, text=True, timeout=90)
        assert p.returncode == 0, p.stderr
        assert p.stdout.strip() == base + "/login"
        s = requests.Session()
        assert "/setup" in s.get(base + "/login", timeout=5).url
        tok = s.get(base + "/api/csrf", timeout=5).json()["csrf"]
        assert s.post(base + "/api/setup", json={"mode": "personal"}, headers={"X-CSRF-Token": tok},
                      timeout=5).status_code == 200

        p = subprocess.run([sys.executable, str(PG_OPEN), "--dashboard", "--no-window"], env=env,
                           capture_output=True, text=True, timeout=30)
        url = p.stdout.strip()
        assert p.returncode == 0 and url.startswith(base + "/enter/")
        w = requests.Session()                       # the window: a browser with no cookies yet
        assert w.get(url, timeout=5).url == base + "/"
        assert w.get(base + "/api/me", timeout=5).json()["mode"] == "personal"
        assert requests.get(url, timeout=5).url.endswith("/login")                    # used up
    finally:
        pid_file = inst / "server.pid"
        if pid_file.exists():
            subprocess.run(["taskkill", "/PID", pid_file.read_text(encoding="utf-8"), "/T", "/F"], capture_output=True)


def test_launcher_dashboard_fails_with_a_message(tmp_path):
    inst = tmp_path / "instance"
    inst.mkdir()
    alerts = []
    old = pglaunch.START_TIMEOUT
    pglaunch.START_TIMEOUT = 0.3
    try:
        code = pglaunch.main(["pg_open.pyw", "--dashboard"], popen=Recorder(), alert=alerts.append,
                             window=lambda u, c: u(),
                             env={"PHISHGUARD_INSTANCE": str(inst), "PHISHGUARD_PORT": str(free_port())})
    finally:
        pglaunch.START_TIMEOUT = old
    assert code == 1 and len(alerts) == 1 and "dashboard" in alerts[0]


# ---------------------------------------------------------------- "Make PhishGuard my default browser"

def test_default_browser_button_registers_and_opens_windows_settings(app, reg_base, opened, tmp_path):
    c = personal(app)
    assert c.get("/api/windows").get_json() == {"supported": True, "registered": False, "default": False,
                                                "shortcut": False}
    r = post(c, "/api/windows/default")
    assert r.status_code == 200, r.get_json()
    assert r.get_json() == {"supported": True, "registered": True, "default": False, "shortcut": True}
    # Windows Settings opened on PhishGuard's own page; nothing else was opened.
    assert opened == ["ms-settings:defaultapps?registeredAppUser=PhishGuard"]
    # The registry entries are the same ones register_windows.py writes.
    k = registry.keys(reg_base)
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, rf"{k['capabilities']}\URLAssociations") as key:
        assert winreg.QueryValueEx(key, "https")[0] == "PhishGuardURL"
    # The Start menu shortcut runs the launcher's dashboard mode.
    lnk = tmp_path / "Start Menu" / "PhishGuard.lnk"
    ps = (f"$s = (New-Object -ComObject WScript.Shell).CreateShortcut('{lnk}'); $s.TargetPath + '|' + $s.Arguments")
    target, args = subprocess.run(["powershell", "-NoProfile", "-Command", ps], capture_output=True, text=True,
                                  check=True).stdout.strip().split("|")
    assert target.lower().endswith("pythonw.exe") and args == f'"{registry.LAUNCHER}" --dashboard'


def test_windows_reports_when_phishguard_is_the_default(app, reg_base):
    c = personal(app)
    post(c, "/api/windows/default")
    # Stand in for the user pressing "Set default" in Windows Settings (under the throwaway base).
    for scheme in ("http", "https"):
        path = rf"{reg_base}\Microsoft\Windows\Shell\Associations\UrlAssociations\{scheme}\UserChoice"
        with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path) as key:
            winreg.SetValueEx(key, "ProgId", 0, winreg.REG_SZ, "PhishGuardURL")
    assert c.get("/api/windows").get_json()["default"] is True


def test_remove_undoes_everything_and_opens_the_default_apps_list(app, reg_base, opened, tmp_path):
    c = personal(app)
    post(c, "/api/windows/default")
    r = post(c, "/api/windows/remove")
    assert r.get_json() == {"supported": True, "registered": False, "default": False, "shortcut": False}
    assert opened[-1] == "ms-settings:defaultapps"
    assert registry.dump(reg_base) == [] and not (tmp_path / "Start Menu" / "PhishGuard.lnk").exists()


def test_only_admins_can_touch_windows(app, opened):
    c = fresh(app)
    post(c, "/api/setup", {"mode": "accounts", "username": "boss", "password": "long-enough-1",
                           "password2": "long-enough-1"})
    con = connect(app.config["DATABASE"])
    create_user(con, "helper", "helper-pass-1", "analyst")
    con.close()
    h = fresh(app)
    post(h, "/api/login", {"username": "helper", "password": "helper-pass-1"})
    assert post(h, "/api/windows/default").status_code == 403
    assert post(fresh(app), "/api/windows/default").status_code == 401
    assert c.post("/api/windows/default").status_code == 403                        # no CSRF token
    assert opened == []
