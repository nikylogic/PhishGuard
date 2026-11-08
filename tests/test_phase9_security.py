"""Phase 9 security self-test findings, kept as regression tests.

Backslash confusion: Python's urlsplit keeps "\\" as a normal character, while Chrome and Edge read
it as "/" in web links. So for https://evil.example\\@en.wikipedia.org/ PhishGuard used to see the
trusted wikipedia.org (and open the link directly) while the browser went to evil.example.
"""
import io
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "launcher"))

import pglaunch  # noqa: E402
from phishguard.rules import url_findings, verdict  # noqa: E402
from phishguard.urltools import browser_slashes, parse  # noqa: E402

BS = "\\"

# (link, the host Chrome really opens) - Chrome's answers were measured with new URL() in Chrome.
CASES = [
    (f"https://evil.example{BS}@en.wikipedia.org/", "evil.example"),
    (f"https://evil.example{BS}.wikipedia.org/", "evil.example"),
    (f"https:{BS}{BS}evil.example{BS}x", "evil.example"),
    (f"https://evil.example{BS}{BS}@paypal.com/login", "evil.example"),
    ("https://evil.example%5c@wikipedia.org/", "wikipedia.org"),     # encoded: Chrome agrees with us
]


@pytest.mark.parametrize("url,real_host", CASES)
def test_engine_judges_the_host_the_browser_opens(url, real_host):
    assert parse(url).host == real_host


@pytest.mark.parametrize("url,real_host", CASES)
def test_launcher_judges_the_host_the_browser_opens(url, real_host):
    _, host = pglaunch.check_link(url)
    assert host == real_host


def test_backslash_after_a_trusted_name_is_not_trusted(tmp_path):
    (tmp_path / "allowlist.txt").write_text("wikipedia.org\n", encoding="utf-8")
    browser = tmp_path / "browser.exe"
    browser.write_bytes(b"MZ")
    (tmp_path / "browser.txt").write_text(str(browser), encoding="utf-8")
    opened, shown = [], []
    env = {"PHISHGUARD_INSTANCE": str(tmp_path), "PHISHGUARD_PORT": "1", "PHISHGUARD_NO_DIALOGS": "1"}
    code = pglaunch.main(["pg_open.pyw", "--no-window", f"https://evil.example{BS}@en.wikipedia.org/"], env=env,
                         popen=lambda a, **k: opened.append(a), alert=shown.append, window=lambda *a: None,
                         out=io.StringIO())
    assert not any(str(browser) in a for a in opened)   # the browser was NOT started as for a trusted link
    assert any("run.py" in " ".join(a) or "Engine" in " ".join(a) for a in opened)   # the full check began
    assert code == 1                    # the fake engine never answers, so it fails closed


def test_backslashes_in_the_query_are_left_alone():
    url = f"https://example.com/search?q=C:{BS}Users{BS}me"
    assert browser_slashes(url) == url
    assert parse(url).query == f"q=C:{BS}Users{BS}me"


def test_backslash_trick_is_judged_on_the_real_site():
    p = parse(f"https://login-check.top{BS}@www.paypal.com/signin")
    assert p.registrable == "login-check.top"           # not paypal.com
    codes = {f.code for f in url_findings(p)}
    assert codes                                        # the brand name in the path is still noticed
    assert verdict(url_findings(p))["score"] > 0


@pytest.mark.parametrize("name", ["PhishGuard.exe", "PhishGuardEngine.exe", "pythonw.exe"])
def test_phishguard_itself_is_never_the_real_browser(tmp_path, name):
    """The installed PhishGuard.exe is the default browser; handing it a link would loop forever."""
    from phishguard import browser
    exe = tmp_path / name
    exe.write_bytes(b"MZ")
    assert not browser.is_browser(str(exe))
    (tmp_path / "browser.txt").write_text(str(exe), encoding="utf-8")
    assert pglaunch.real_browser({"instance": tmp_path}) is None
