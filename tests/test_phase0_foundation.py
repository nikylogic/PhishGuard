"""Phase 0: the app starts, the database is correct, and the server is local-only."""
import os
import socket
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent

EXPECTED_COLUMNS = {
    "users": {"id", "username", "pw_hash", "role", "created_at", "last_login"},
    "scans": {"id", "url", "final_url", "domain", "source", "status", "score", "level",
              "s_phishing", "s_malware", "s_tracking", "s_abuse", "title", "screenshot",
              "redirect_json", "page_json", "llm_json", "guard_score", "decision", "error",
              "ticket", "user_id", "created_at", "finished_at"},
    "findings": {"id", "scan_id", "stage", "category", "code", "weight", "message"},
    "downloads": {"id", "scan_id", "filename", "declared_type", "real_type", "size",
                  "sha256", "verdict", "quarantine_path"},
    "privacy": {"scan_id", "trackers_json", "fingerprint_json", "ip_logger", "webrtc",
                "params_removed_json"},
    "domain_lists": {"id", "domain", "kind", "note", "added_by", "created_at"},
    "intel_lists": {"id", "kind", "value", "source"},
    "guard_events": {"id", "scan_id", "source", "text_snippet", "score", "label", "created_at"},
    "settings": {"key", "value"},
    "audit_log": {"id", "user_id", "action", "detail", "ip", "created_at"},
}


def test_health_returns_ok(client):
    r = client.get("/health")
    assert r.status_code == 200
    assert r.get_json() == {"ok": True, "app": "phishguard"}


@pytest.mark.parametrize("table", sorted(EXPECTED_COLUMNS))
def test_table_has_expected_columns(con, table):
    cols = {row["name"] for row in con.execute(f"PRAGMA table_info({table})")}
    assert cols == EXPECTED_COLUMNS[table]


def test_foreign_keys_and_wal_are_on(con):
    assert con.execute("PRAGMA foreign_keys").fetchone()[0] == 1
    assert con.execute("PRAGMA journal_mode").fetchone()[0] == "wal"


@pytest.mark.parametrize("sql", [
    "INSERT INTO users(username, pw_hash, role) VALUES ('x', 'h', 'superuser')",
    "INSERT INTO scans(url, domain, source) VALUES ('u', 'd', 'email')",
    "INSERT INTO scans(url, domain, source, score) VALUES ('u', 'd', 'manual', 150)",
    "INSERT INTO scans(url, domain, source, level) VALUES ('u', 'd', 'manual', 'evil')",
    "INSERT INTO domain_lists(domain, kind) VALUES ('a.com', 'maybe')",
    "INSERT INTO intel_lists(kind, value) VALUES ('rumour', 'x')",
])
def test_check_constraints_reject_bad_values(con, sql):
    with pytest.raises(sqlite3.IntegrityError):
        con.execute(sql)


def test_findings_need_a_real_scan(con):
    with pytest.raises(sqlite3.IntegrityError):
        con.execute("INSERT INTO findings(scan_id, stage, category, code, weight, message) "
                    "VALUES (999, 'url', 'phishing', 'X', 1, 'm')")


def test_deleting_a_scan_deletes_its_findings(con):
    cur = con.execute("INSERT INTO scans(url, domain, source) VALUES ('http://a.com', 'a.com', 'manual')")
    sid = cur.lastrowid
    con.execute("INSERT INTO findings(scan_id, stage, category, code, weight, message) "
                "VALUES (?, 'url', 'phishing', 'X', 5, 'm')", (sid,))
    con.execute("DELETE FROM scans WHERE id = ?", (sid,))
    assert con.execute("SELECT COUNT(*) FROM findings").fetchone()[0] == 0


def test_security_headers_present(client):
    h = client.get("/health").headers
    assert "default-src 'self'" in h["Content-Security-Policy"]
    assert "frame-ancestors 'none'" in h["Content-Security-Policy"]
    assert h["X-Content-Type-Options"] == "nosniff"
    assert h["X-Frame-Options"] == "DENY"
    assert h["Referrer-Policy"] == "no-referrer"


def test_secrets_are_created_once_and_reused(app, tmp_path):
    from phishguard import create_app
    again = create_app({"INSTANCE_DIR": app.config["INSTANCE_DIR"]})
    assert again.config["SECRET_KEY"] == app.config["SECRET_KEY"]
    assert again.config["LAUNCHER_TOKEN"] == app.config["LAUNCHER_TOKEN"]
    assert len(app.config["LAUNCHER_TOKEN"]) >= 40


def test_session_cookie_is_locked_down(app):
    assert app.config["SESSION_COOKIE_HTTPONLY"] is True
    assert app.config["SESSION_COOKIE_SAMESITE"] == "Strict"


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(("10.255.255.255", 1))   # no packet is sent; this just picks the outgoing interface
        return s.getsockname()[0]
    except OSError:
        return None
    finally:
        s.close()


def test_real_server_listens_on_loopback_only(tmp_path):
    port = _free_port()
    env = dict(os.environ, PHISHGUARD_INSTANCE=str(tmp_path / "inst"), PHISHGUARD_PORT=str(port), PHISHGUARD_NO_WORKER="1")
    proc = subprocess.Popen([sys.executable, str(ROOT / "run.py")], env=env, cwd=ROOT,
                            stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
    try:
        for _ in range(50):
            try:
                if requests.get(f"http://127.0.0.1:{port}/health", timeout=0.5).ok:
                    break
            except requests.ConnectionError:
                time.sleep(0.1)
        else:
            pytest.fail("server did not start")
        lan = _lan_ip()
        if lan and not lan.startswith("127."):
            with pytest.raises(requests.ConnectionError):
                requests.get(f"http://{lan}:{port}/health", timeout=1)
    finally:
        proc.terminate()
        proc.wait(timeout=5)
