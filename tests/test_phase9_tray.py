"""The notification-area (tray) icon and the one-window dashboard.

The icon test shows a real tray icon for a moment (its own, under this test's process) and removes
it. Programs it would start are recorded instead, and it never looks at your windows or clipboard.
"""
import socket
import sys
from pathlib import Path
from types import SimpleNamespace

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "launcher"))

import enginemain  # noqa: E402
import pglaunch  # noqa: E402
import tray  # noqa: E402


@pytest.mark.parametrize("text, want", [
    ("https://example.com/a?b=1", "https://example.com/a?b=1"),
    ("  http://bank.test/login  ", "http://bank.test/login"),
    ("www.example.com/x", "https://www.example.com/x"),
    ('"https://quoted.example/"', "https://quoted.example/"),
    ("javascript:alert(1)", None),
    ("file:///C:/Windows/win.ini", None),
    ("hello there https://example.com", None),     # a sentence, not a link
    ("", None),
    (None, None),
])
def test_only_a_copied_web_link_is_checked(text, want):
    assert tray.link_in(text) == want


class FakeRegistry:
    def __init__(self):
        self.on = True

    def startup_enabled(self):
        return self.on

    def set_startup(self, on):
        self.on = on


def test_tray_icon_appears_and_its_menu_commands_work(tmp_path, monkeypatch):
    started, quits, notes = [], [], []
    monkeypatch.setattr(tray, "focus_window", lambda title=tray.TITLE: False)
    reg = FakeRegistry()
    t = tray.Tray(tmp_path, on_quit=lambda: quits.append(1), popen=lambda args, **kw: started.append(args),
                  registry=reg, hint=False).start()
    try:
        assert t.ok, "Windows did not accept the tray icon"
        t.command(tray.OPEN)
        assert started[-1][-1].endswith(("PhishGuard.exe", "pg_open.pyw"))
        monkeypatch.setattr(tray, "clipboard_text", lambda: "https://copied.example/x")
        t.command(tray.CHECK_COPIED)
        assert started[-1][-1] == "https://copied.example/x"
        monkeypatch.setattr(tray, "clipboard_text", lambda: "just some words")
        monkeypatch.setattr(t, "notify", lambda title, text, warning=False: notes.append(title))
        t.command(tray.CHECK_COPIED)
        assert notes == ["Copy a link first"] and len(started) == 2      # nothing was opened
        t.command(tray.STARTUP)
        assert reg.on is False
        t.command(tray.QUIT)
        assert quits == [1]
    finally:
        t.stop()


def test_open_brings_the_dashboard_forward_instead_of_a_second_window(tmp_path, monkeypatch):
    started = []
    monkeypatch.setattr(tray, "focus_window", lambda title=tray.TITLE: True)
    t = tray.Tray(tmp_path, popen=lambda args, **kw: started.append(args), hint=False)
    t.open_app()
    assert started == []


def test_first_start_says_where_phishguard_went_once(tmp_path, monkeypatch):
    notes = []
    t = tray.Tray(tmp_path, hint=True)
    monkeypatch.setattr(t, "notify", lambda title, text, warning=False: notes.append(title))
    t._first_hint()
    t._first_hint()
    assert notes == ["PhishGuard is running"]


def test_a_second_engine_shows_no_second_icon():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    s.listen()
    try:
        assert enginemain.port_free(s.getsockname()[1]) is False
    finally:
        s.close()


def test_link_checks_get_their_own_window_title(tmp_path):
    """The dashboard is found by its title "PhishGuard"; a link check must not be mistaken for it."""
    seen = []
    env = {"PHISHGUARD_INSTANCE": str(tmp_path), "PHISHGUARD_PORT": "1", "PHISHGUARD_NO_DIALOGS": "1"}
    (tmp_path / "allowlist.txt").write_text("", encoding="utf-8")
    pglaunch.main(["pg_open.pyw", "https://example.org/x"], env=env, popen=lambda *a, **k: SimpleNamespace(pid=0),
                  alert=lambda m: None, window=lambda u, cfg: seen.append(cfg.get("title")))
    assert seen == ["PhishGuard \u00b7 example.org"]


def test_tests_never_touch_a_real_phishguard_window(monkeypatch):
    monkeypatch.setattr(tray, "focus_window", lambda title=tray.TITLE: pytest.fail("looked for a real window"))
    assert pglaunch.focus_existing({"PHISHGUARD_NO_DIALOGS": "1"}) is False
