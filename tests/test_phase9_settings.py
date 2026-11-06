"""Settings: start with Windows, history clean-up, the phishing-lists status, the version.

Registry tests write under a throwaway HKCU key, never the real Run key.
"""
import sys
import uuid
import winreg
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "launcher"))

import appmain  # noqa: E402
import pglaunch  # noqa: E402
import registry  # noqa: E402
from phishguard import __version__, create_app  # noqa: E402
from phishguard.auth import create_user, limiter  # noqa: E402
from phishguard.db import connect  # noqa: E402
from phishguard.services import ScanService  # noqa: E402


@pytest.fixture
def reg_base():
    base = rf"Software\PhishGuardTest-{uuid.uuid4().hex[:8]}"
    yield base
    registry._delete_tree(base)


def read(path, name):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
        return winreg.QueryValueEx(k, name)[0]


# ---------------------------------------------------------------- start with Windows

def test_startup_writes_and_removes_only_its_own_run_value(reg_base):
    run, approved = registry.run_keys(reg_base)
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, run) as k:      # another app's start-up entry
        winreg.SetValueEx(k, "OtherApp", 0, winreg.REG_SZ, r"C:\Other\other.exe")
    assert registry.startup_enabled(reg_base) is False
    assert registry.set_startup(True, reg_base, pythonw=r"C:\Py\pythonw.exe") is True
    assert read(run, "PhishGuard") == rf'"C:\Py\pythonw.exe" "{registry.LAUNCHER}" --background'
    assert registry.set_startup(False, reg_base) is False
    with pytest.raises(FileNotFoundError):
        read(run, "PhishGuard")
    assert read(run, "OtherApp") == r"C:\Other\other.exe"


def test_switched_off_in_task_manager_counts_as_off_and_turning_on_clears_it(reg_base):
    run, approved = registry.run_keys(reg_base)
    registry.set_startup(True, reg_base)
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, approved) as k:   # what Task Manager writes
        winreg.SetValueEx(k, "PhishGuard", 0, winreg.REG_BINARY, bytes([3]) + bytes(11))
    assert registry.startup_enabled(reg_base) is False
    assert registry.set_startup(True, reg_base) is True


def test_installed_app_starts_phishguard_exe_in_the_background(reg_base, monkeypatch):
    monkeypatch.setattr(registry, "FROZEN", True)
    monkeypatch.setattr(registry.sys, "executable", r"C:\Apps\PhishGuard\PhishGuardEngine.exe")
    assert registry.startup_command() == r'"C:\Apps\PhishGuard\PhishGuard.exe" --background'


def test_startup_is_on_by_default_once_and_then_the_users_choice_stands(tmp_path, reg_base, monkeypatch):
    calls = []
    fake = SimpleNamespace(FROZEN=True, set_startup=lambda on: calls.append(on))
    appmain.first_run_startup(tmp_path, fake)
    appmain.first_run_startup(tmp_path, fake)          # second run: the user's choice is left alone
    assert calls == [True]
    # Tests and dev runs never touch the real Run key.
    appmain.first_run_startup(tmp_path / "other", SimpleNamespace(FROZEN=False, set_startup=calls.append))
    assert calls == [True]


def test_background_start_shows_nothing_and_never_alerts(tmp_path):
    started, alerts, windows = [], [], []
    old = pglaunch.BACKGROUND_TIMEOUT
    pglaunch.BACKGROUND_TIMEOUT = 0.5
    code = pglaunch.main(["pg_open.pyw", "--background"],
                         env={"PHISHGUARD_INSTANCE": str(tmp_path), "PHISHGUARD_PORT": "1"},
                         popen=lambda *a, **k: started.append(a) or SimpleNamespace(pid=0),
                         alert=alerts.append, window=lambda *a: windows.append(a))
    pglaunch.BACKGROUND_TIMEOUT = old
    assert started                                     # it tried to start the engine
    assert alerts == [] and windows == []              # quiet at sign-in, even when it fails
    assert code == 1
    assert "background start failed" in (tmp_path / "launcher.log").read_text(encoding="utf-8")


# ---------------------------------------------------------------- the API

class FakeWorker:
    def submit(self, sid, url):
        pass


@pytest.fixture
def env(tmp_path, reg_base):
    inst = tmp_path / "inst"
    inst.mkdir()
    from phishguard import db as dbm
    dbm.init_db(str(inst / "phishguard.db"))
    service = ScanService(str(inst / "phishguard.db"), inst, worker=FakeWorker(), guard=None)
    app = create_app({"INSTANCE_DIR": str(inst), "TESTING": True, "SERVICE": service, "REGISTRY_BASE": reg_base,
                      "SHORTCUT_PATH": str(tmp_path / "PhishGuard.lnk"), "OPEN_SETTINGS": lambda p: None})
    con = connect(app.config["DATABASE"])
    create_user(con, "admin", "correct-horse-1", "admin")
    create_user(con, "analyst", "battery-staple-2", "analyst")
    con.close()
    limiter.fails.clear()
    yield SimpleNamespace(app=app, service=service, inst=inst, reg=reg_base)
    service.llm_pool.shutdown(wait=True)


def client(env, user="admin"):
    c = env.app.test_client()
    c.csrf = c.get("/api/csrf").get_json()["csrf"]
    pw = {"admin": "correct-horse-1", "analyst": "battery-staple-2"}[user]
    r = c.post("/api/login", json={"username": user, "password": pw}, headers={"X-CSRF-Token": c.csrf})
    c.csrf = r.get_json().get("csrf", c.csrf)
    return c


def post(c, url, body=None):
    return c.post(url, json=body or {}, headers={"X-CSRF-Token": c.csrf})


def add_scan(env, days_ago, status="done"):
    con = connect(str(env.inst / "phishguard.db"))
    cur = con.execute("INSERT INTO scans(url, domain, source, status, level, screenshot, created_at) "
                      "VALUES ('https://a.example/', 'a.example', 'manual', ?, 'clear', ?, datetime('now', ?))",
                      (status, None, f"-{days_ago} days"))
    sid = cur.lastrowid
    con.execute("UPDATE scans SET screenshot = ? WHERE id = ?", (f"{sid}.jpg", sid))
    con.execute("INSERT INTO findings(scan_id, code, category, weight, message, stage) "
                "VALUES (?, 'X', 'phishing', 1, 'm', 'url')", (sid,))
    con.commit()
    con.close()
    (env.inst / "shots" / f"{sid}.jpg").write_bytes(b"jpg")
    (env.inst / "quarantine" / str(sid)).mkdir(parents=True, exist_ok=True)
    (env.inst / "quarantine" / str(sid) / "file.bin").write_bytes(b"x")
    return sid


def scan_ids(env):
    con = connect(str(env.inst / "phishguard.db"))
    try:
        return {r[0] for r in con.execute("SELECT id FROM scans")}
    finally:
        con.close()


def test_startup_switch_through_the_api(env):
    c = client(env)
    assert c.get("/api/windows").get_json()["startup"] is False
    r = post(c, "/api/windows/startup", {"on": True})
    assert r.status_code == 200 and r.get_json()["startup"] is True
    assert registry.startup_enabled(env.reg)
    assert post(c, "/api/windows/startup", {"on": "yes"}).status_code == 400
    assert post(client(env, "analyst"), "/api/windows/startup", {"on": False}).status_code == 403
    assert post(c, "/api/windows/startup", {"on": False}).get_json()["startup"] is False
    assert not registry.startup_enabled(env.reg)


def test_history_keeps_90_days_by_default_and_deletes_files_too(env):
    old, new, running = add_scan(env, 120), add_scan(env, 5), add_scan(env, 400, status="running")
    assert env.service.keep_days() == 90
    assert env.service.purge() == 1
    assert scan_ids(env) == {new, running}            # a running check is never touched
    assert not (env.inst / "shots" / f"{old}.jpg").exists()
    assert not (env.inst / "quarantine" / str(old)).exists()
    assert (env.inst / "shots" / f"{new}.jpg").exists()
    con = connect(str(env.inst / "phishguard.db"))
    assert con.execute("SELECT COUNT(*) FROM findings WHERE scan_id = ?", (old,)).fetchone()[0] == 0
    con.close()


def test_changing_how_long_to_keep_applies_at_once(env):
    add_scan(env, 40)
    keep = add_scan(env, 10)
    c = client(env)
    assert post(c, "/api/settings", {"keep_days": "7"}).status_code == 400
    assert post(c, "/api/settings", {"keep_days": "0"}).status_code == 200
    assert len(scan_ids(env)) == 2                      # keep everything
    assert post(c, "/api/settings", {"keep_days": "30"}).status_code == 200
    assert scan_ids(env) == {keep}
    st = c.get("/api/history").get_json()
    assert st["keep_days"] == 30 and st["checks"] == 1 and st["bytes"] > 0


def test_delete_all_history_is_admin_only_and_keeps_lists_and_audit(env):
    add_scan(env, 1)
    add_scan(env, 2)
    c = client(env)
    post(c, "/api/lists", {"domain": "wikipedia.org", "kind": "allow"})
    assert post(client(env, "analyst"), "/api/history/clear").status_code == 403
    r = post(c, "/api/history/clear")
    assert r.status_code == 200 and r.get_json()["deleted"] == 2 and r.get_json()["checks"] == 0
    assert list((env.inst / "shots").iterdir()) == []
    assert any(i["domain"] == "wikipedia.org" for i in c.get("/api/lists").get_json()["items"])
    assert any(a["action"] == "history_clear" for a in c.get("/api/audit").get_json()["items"])


def test_phishing_lists_status_has_its_own_address(env):
    """It used to share /api/lists with Trusted & blocked, so the Settings card never showed."""
    c = client(env)
    assert c.get("/api/feeds").get_json() == {"enabled": False, "sources": [], "hosts": 0, "urls": 0, "ready": False}
    assert "items" in c.get("/api/lists").get_json()


def test_version_is_shown(env):
    assert client(env).get("/api/about").get_json() == {"version": __version__}


def test_dashboard_days_follow_the_pcs_clock_not_utc(env):
    """Checks are stored in UTC. One made a minute after local midnight is 'today' for the user,
    even where UTC is still on yesterday (00:00-05:30 in India)."""
    con = connect(str(env.inst / "phishguard.db"))
    con.execute("INSERT INTO scans(url, domain, source, status, level, created_at) VALUES "
                "('https://a.example/', 'a.example', 'manual', 'done', 'danger', "
                "datetime('now', 'localtime', 'start of day', '+1 minute', 'utc'))")
    con.commit()
    today = con.execute("SELECT date('now', 'localtime')").fetchone()[0]
    con.close()
    s = client(env).get("/api/stats").get_json()
    if s["today"] == 0:   # only possible in the first minute after midnight, when the check is in the future
        pytest.skip("ran within a minute of local midnight")
    assert s["today"] == 1 and s["stopped_today"] == 1
    assert [d["day"] for d in s["days"]] == [today]
