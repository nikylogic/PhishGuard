"""Phase 8: Windows integration. The launcher Windows runs for every clicked link, and the registry entries.

Most tests call the launcher in-process with fake "start a program" and "show a message" functions,
so nothing real is opened. Two tests run the real pg_open.pyw as its own process, the way Windows
does. Registry tests write under a throwaway HKCU key, never the real handler keys.
"""
import os
import socket
import statistics
import subprocess
import sys
import time
import uuid
import winreg
from pathlib import Path
from types import SimpleNamespace

import pytest
import requests

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "launcher"))

import pglaunch  # noqa: E402
import registry  # noqa: E402
from phishguard import browser  # noqa: E402

PG_OPEN = ROOT / "launcher" / "pg_open.pyw"
WHERE = r"C:\Windows\System32\where.exe"      # a harmless stand-in "browser" for real-process tests


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


class Recorder:
    """Stands in for subprocess.Popen and for the message box."""

    def __init__(self):
        self.calls = []

    def __call__(self, args, **kw):
        self.calls.append(args)
        return SimpleNamespace(pid=0)


@pytest.fixture
def inst(tmp_path):
    d = tmp_path / "instance"
    d.mkdir()
    fake_chrome = tmp_path / "Chrome" / "chrome.exe"
    fake_chrome.parent.mkdir()
    fake_chrome.write_bytes(b"MZ")
    (d / "allowlist.txt").write_text("wikipedia.org\ngithub.com\n", encoding="utf-8")
    (d / "browser.txt").write_text(str(fake_chrome) + "\n", encoding="utf-8")
    return SimpleNamespace(dir=d, chrome=str(fake_chrome),
                           env={"PHISHGUARD_INSTANCE": str(d), "PHISHGUARD_PORT": str(free_port()),
                                "PHISHGUARD_NO_DIALOGS": "1"})


def run(inst, url, timeout=0.5):
    popen, alerts, windows = Recorder(), [], []
    old = pglaunch.START_TIMEOUT
    pglaunch.START_TIMEOUT = timeout
    try:
        code = pglaunch.main(["pg_open.pyw", url], env=inst.env, popen=popen, alert=alerts.append,
                             window=lambda u, cfg: windows.append(u))
    finally:
        pglaunch.START_TIMEOUT = old
    return SimpleNamespace(code=code, popen=popen.calls, alerts=alerts, windows=windows)


# ---------------------------------------------------------------- refusing what is not a web link

@pytest.mark.parametrize("url", [
    "javascript:alert(document.cookie)",
    "file:///C:/Windows/win.ini",
    "ms-msdt:/id PCWDiagnostic /skip force",
    "vbscript:msgbox(1)",
    "data:text/html,<script>alert(1)</script>",
    "search-ms:query=invoice",
    "http://",
    "https://exa\u200bmple.com/",
    "",
])
def test_launcher_refuses_anything_that_is_not_a_web_link(inst, url):
    r = run(inst, url)
    assert r.code == 2
    assert r.popen == [] and r.windows == []                 # nothing started, no server, no browser
    assert len(r.alerts) == 1 and "not opened" in r.alerts[0]


# ---------------------------------------------------------------- trusted sites: the fast path

def test_trusted_link_opens_directly_in_the_real_browser(inst):
    t = time.perf_counter()
    r = run(inst, "https://en.wikipedia.org/wiki/Phishing")
    ms = (time.perf_counter() - t) * 1000
    assert r.code == 0 and r.alerts == [] and r.windows == []
    assert r.popen == [[inst.chrome, "--", "https://en.wikipedia.org/wiki/Phishing"]]
    assert ms < 300, ms


@pytest.mark.parametrize("url", ["https://wikipedia.org.login-check.top/", "https://notwikipedia.org/",
                                 "https://github.com.evil.example/"])
def test_lookalikes_of_trusted_sites_are_not_trusted(inst, url):
    r = run(inst, url, timeout=0.3)
    # Not opened directly: it tried to reach the engine instead (and, with none running, failed closed).
    assert all(url not in " ".join(map(str, c)) for c in r.popen)
    assert r.windows == [] and r.code == 1 and "could not check" in r.alerts[0]


def test_trusted_link_from_a_real_click_takes_under_300_ms(inst):
    """Runs pg_open.pyw as its own process, as Windows does. where.exe stands in for the browser."""
    (inst.dir / "browser.txt").write_text(WHERE + "\n", encoding="utf-8")
    env = {**os.environ, **inst.env}
    times = []
    for _ in range(7):
        t = time.perf_counter()
        p = subprocess.run([sys.executable, str(PG_OPEN), "https://github.com/"], env=env, capture_output=True,
                           timeout=20)
        times.append((time.perf_counter() - t) * 1000)
        assert p.returncode == 0, p.stderr
    log = (inst.dir / "launcher.log").read_text(encoding="utf-8")
    assert log.count("trusted, opened directly: github.com") == 7
    assert statistics.median(times) < 300, times


# ---------------------------------------------------------------- the engine

def test_launcher_starts_the_engine_when_it_is_not_running(tmp_path):
    inst = tmp_path / "instance"
    port = free_port()
    env = {**os.environ, "PHISHGUARD_INSTANCE": str(inst), "PHISHGUARD_PORT": str(port), "PHISHGUARD_NO_WORKER": "1",
           "PHISHGUARD_NO_DIALOGS": "1"}
    base = f"http://127.0.0.1:{port}"
    with pytest.raises(requests.ConnectionError):
        requests.get(base + "/health", timeout=0.5)
    try:
        p = subprocess.run([sys.executable, str(PG_OPEN), "--no-window", "http://invoice-download.example.top/x"],
                           env=env, capture_output=True, text=True, timeout=90)
        assert p.returncode == 0, (p.stdout, p.stderr, (inst / "launcher.log").read_text(encoding="utf-8"))
        check_url = p.stdout.strip()
        assert check_url.startswith(base + "/check/") and "?t=" in check_url
        assert requests.get(base + "/health", timeout=2).json()["app"] == "phishguard"
        pid = (inst / "server.pid").read_text(encoding="utf-8")

        # The one-time ticket lets the Airlock window see this one check without a login...
        s = requests.Session()
        page = s.get(check_url, timeout=5)
        assert page.status_code == 200 and 'data-page="check"' in page.text
        sid = check_url.split("/check/")[1].split("?")[0]
        assert s.get(f"{base}/api/scan/{sid}", timeout=5).json()["url"] == "http://invoice-download.example.top/x"
        # ...only once, and only for that check.
        again = requests.get(check_url, timeout=5)                             # a used ticket gets you nothing
        assert again.url.split("?")[0].endswith(("/login", "/setup")) and 'data-page="check"' not in again.text
        assert s.get(f"{base}/api/scan/{int(sid) + 1}", timeout=5).status_code in (401, 404)

        # A second click reuses the running engine.
        p2 = subprocess.run([sys.executable, str(PG_OPEN), "--no-window", "http://second.example.top/"],
                            env=env, capture_output=True, text=True, timeout=30)
        assert p2.returncode == 0 and (inst / "server.pid").read_text(encoding="utf-8") == pid
    finally:
        pid_file = inst / "server.pid"
        if pid_file.exists():
            subprocess.run(["taskkill", "/PID", pid_file.read_text(encoding="utf-8"), "/T", "/F"], capture_output=True)


def test_launcher_fails_closed_when_the_engine_cannot_start(inst):
    r = run(inst, "http://unknown-site.example.top/login", timeout=0.4)
    assert r.code == 1 and r.windows == []
    assert len(r.alerts) == 1 and "could not check this link" in r.alerts[0] and "not opened" in r.alerts[0]
    # The only program it tried to start was the engine, never a browser with the link.
    assert len(r.popen) == 1 and r.popen[0][-1].endswith("run.py")


def test_launcher_fails_closed_when_the_engine_is_someone_else(inst, monkeypatch):
    monkeypatch.setattr(pglaunch, "healthy", lambda cfg, timeout=0.5: False)
    r = run(inst, "http://unknown-site.example.top/", timeout=0.3)
    assert r.code == 1 and r.windows == [] and "not opened" in r.alerts[0]


def test_another_phishguard_on_the_port_gets_a_clear_message(inst, tmp_path):
    """A different PhishGuard copy (another data folder) already answers on the port: say so plainly,
    and do not send it the link."""
    import threading
    from waitress.server import create_server
    from phishguard import create_app
    other = create_app({"INSTANCE_DIR": str(tmp_path / "other-copy"), "TESTING": True})
    srv = create_server(other, host="127.0.0.1", port=int(inst.env["PHISHGUARD_PORT"]))
    threading.Thread(target=srv.run, daemon=True).start()
    try:
        r = run(inst, "http://unknown-site.example.top/")
        d = pglaunch.main(["pg_open.pyw", "--dashboard"], env=inst.env, popen=Recorder(), alert=r.alerts.append,
                          window=lambda u, c: pytest.fail("no window"))
    finally:
        srv.close()
    assert r.code == 1 and d == 1 and r.windows == []
    assert all("Another copy of PhishGuard is already running" in a for a in r.alerts)
    assert "launcher key" not in " ".join(r.alerts)


# ---------------------------------------------------------------- never looping back into PhishGuard

def test_phishguard_is_never_chosen_as_the_real_browser(inst, tmp_path):
    pyw = str(Path(sys.executable).with_name("pythonw.exe"))
    assert not browser.is_browser(pyw) and not browser.is_browser(sys.executable)
    assert browser.choose(pyw) != pyw
    # Even if browser.txt pointed at Python, the launcher would refuse to hand the link to it.
    (inst.dir / "browser.txt").write_text(pyw + "\n", encoding="utf-8")
    r = run(inst, "https://en.wikipedia.org/")
    assert r.popen == [] and r.code == 1 and "browser was not found" in r.alerts[0]


def test_settings_refuse_python_as_the_real_browser(client):
    tok = client.get("/api/csrf").get_json()["csrf"]
    r = client.post("/api/setup", json={"username": "admin", "password": "correct-horse-1",
                                        "password2": "correct-horse-1"}, headers={"X-CSRF-Token": tok})
    tok = r.get_json()["csrf"]
    r = client.post("/api/settings", json={"browser_path": sys.executable}, headers={"X-CSRF-Token": tok})
    assert r.status_code == 400 and "not found" in r.get_json()["error"]


def test_the_launcher_never_asks_windows_to_open_a_link(inst, monkeypatch):
    """os.startfile / webbrowser would send the link to the default browser, which is PhishGuard."""
    import webbrowser

    def boom(*a, **k):
        raise AssertionError("asked Windows to open a link")

    monkeypatch.setattr(os, "startfile", boom, raising=False)
    monkeypatch.setattr(webbrowser, "open", boom)
    assert run(inst, "https://github.com/x").popen[0][0] == inst.chrome
    src = (ROOT / "launcher" / "pglaunch.py").read_text(encoding="utf-8") + (ROOT / "phishguard" / "browser.py").read_text(
        encoding="utf-8")
    assert "startfile" not in src and "webbrowser" not in src and "shell=True" not in src


def test_engine_writes_the_browser_file_for_the_launcher(app):
    exe = (Path(app.config["INSTANCE_DIR"]) / "browser.txt").read_text(encoding="utf-8").strip()
    assert exe == "" or browser.is_browser(exe)


# ---------------------------------------------------------------- registry (HKCU only)

@pytest.fixture
def reg_base():
    base = rf"Software\PhishGuardTest-{uuid.uuid4().hex[:8]}"
    yield base
    registry._delete_tree(base)


def read(path, name=""):
    with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
        return winreg.QueryValueEx(k, name or None)[0]


def exists(path):
    try:
        winreg.OpenKey(winreg.HKEY_CURRENT_USER, path).Close()
        return True
    except FileNotFoundError:
        return False


def test_register_writes_the_handler_keys(reg_base):
    k = registry.register(reg_base, pythonw=r"C:\Py\pythonw.exe")
    cmd = read(rf"{k['progid']}\shell\open\command")
    assert cmd == rf'"C:\Py\pythonw.exe" "{registry.LAUNCHER}" "%1"'
    assert read(k["progid"], "URL Protocol") == ""
    assert read(rf"{k['capabilities']}\URLAssociations", "http") == "PhishGuardURL"
    assert read(rf"{k['capabilities']}\URLAssociations", "https") == "PhishGuardURL"
    assert read(k["capabilities"], "ApplicationName") == "PhishGuard"
    assert read(k["registered"], "PhishGuard") == k["capabilities"]
    # Only the current user is touched: every key lives under HKCU\<base>.
    assert all(p.startswith(reg_base) for p in k.values())


def test_unregister_removes_only_what_register_wrote(reg_base):
    k = registry.keys(reg_base)
    with winreg.CreateKey(winreg.HKEY_CURRENT_USER, k["registered"]) as reg:      # another app's entry
        winreg.SetValueEx(reg, "SomeOtherBrowser", 0, winreg.REG_SZ, r"Software\Other\Capabilities")
    registry.register(reg_base)
    assert registry.dump(reg_base)
    removed = registry.unregister(reg_base)
    assert len(removed) == 3
    assert not exists(k["progid"]) and not exists(k["client"])
    assert read(k["registered"], "SomeOtherBrowser") == r"Software\Other\Capabilities"
    with pytest.raises(FileNotFoundError):
        read(k["registered"], "PhishGuard")
    assert registry.dump(reg_base) == []
    assert registry.unregister(reg_base) == []                  # running it twice is harmless


def test_registered_command_really_runs_the_launcher(reg_base, inst):
    """Run the exact command line Windows would run, with the link in place of %1."""
    k = registry.register(reg_base, pythonw=sys.executable)    # python.exe so the test can wait for it
    cmd = read(rf"{k['progid']}\shell\open\command").replace("%1", "javascript:alert(1)")
    p = subprocess.run(cmd + " --no-window", env={**os.environ, **inst.env}, capture_output=True, text=True, timeout=20)
    assert p.returncode == 2                                     # refused, as it must be
    assert "refused" in (inst.dir / "launcher.log").read_text(encoding="utf-8")
