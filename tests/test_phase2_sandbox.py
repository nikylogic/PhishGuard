"""Phase 2: the sandbox opens fake attack pages and records exactly what they do.

One warm browser is shared by all tests in this file (like the real app).
Screenshots and timings are copied to proof/phase-2/ as evidence.
"""
import shutil
import time
from pathlib import Path

import pytest

from phishguard import filetypes
from phishguard.sandbox import Sandbox
from phishguard.worker import ScanWorker
from tests.sites.server import FAKE_EXE, FakeResolver, FakeSites

ROOT = Path(__file__).resolve().parent.parent
PROOF = ROOT / "proof" / "phase-2"
TIMINGS = []


@pytest.fixture(scope="module")
def sites():
    s = FakeSites().start()
    yield s
    s.stop()


@pytest.fixture(scope="module")
def env(sites, tmp_path_factory):
    base = tmp_path_factory.mktemp("sandbox")
    shots, quarantine = base / "shots", base / "quarantine"

    def factory():
        return Sandbox(shots, quarantine, resolver_factory=FakeResolver,
                       exempt={("127.0.0.1", sites.port)}, extra_args=sites.chrome_args(),
                       nav_timeout=15, total_timeout=20)

    w = ScanWorker(factory).start()
    assert w.ready.wait(30)
    yield {"worker": w, "shots": shots, "quarantine": quarantine, "sites": sites}
    w.stop()
    _write_timings()


_counter = iter(range(1, 10_000))


def scan(env, host, path, name=None, timeout=40):
    sid = next(_counter)
    url = env["sites"].url(host, path)
    t0 = time.monotonic()
    cap = env["worker"].submit(url, sid).result(timeout=timeout)
    took = time.monotonic() - t0
    if name:
        TIMINGS.append((name, path, cap.status, took))
        if cap.screenshot:
            (PROOF / "shots").mkdir(parents=True, exist_ok=True)
            shutil.copyfile(env["shots"] / cap.screenshot, PROOF / "shots" / f"{name}.jpg")
    return cap


def _write_timings():
    if not TIMINGS:
        return
    PROOF.mkdir(parents=True, exist_ok=True)
    lines = ["# Sandbox timings (warm browser, local fake sites)", "",
             "| Fake page | Path | Status | Seconds |", "|---|---|---|---|"]
    lines += [f"| {n} | `{p}` | {s} | {t:.2f} |" for n, p, s, t in TIMINGS]
    (PROOF / "timings.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


def kinds(cap, t):
    return [e for e in cap.events if e.get("t") == t]


# --- the basics ------------------------------------------------------------------

def test_plain_page_is_captured(env):
    cap = scan(env, "plain.test", "/plain", "plain")
    assert cap.status == "done", cap.error
    assert cap.title == "Bengaluru weather"
    assert "Sunny" in cap.visible_text
    assert cap.screenshot and (env["shots"] / cap.screenshot).stat().st_size > 1000
    assert cap.http_status == 200
    assert cap.downloads == [] and cap.protocol_attempts == []


def test_redirect_chain_is_recorded(env):
    cap = scan(env, "short.test", "/r1", "redirect-chain")
    urls = [h["url"].split(":%d" % env["sites"].port)[-1] for h in cap.redirects]
    assert urls == ["/r1", "/r2", "/r3", "/r4", "/landing"]
    assert [h["status"] for h in cap.redirects[:4]] == [301, 302, 301, 302]
    assert cap.redirects[-1]["kind"] == "final"
    assert cap.final_url.endswith("/landing")


def test_script_redirect_is_recorded(env):
    cap = scan(env, "short.test", "/js-redirect")
    assert cap.final_url.endswith("/landing")
    assert any(h["kind"] == "final" and h["url"].endswith("/landing") for h in cap.redirects)
    assert len(cap.redirects) >= 2


def test_password_form_and_its_target_are_recorded(env):
    cap = scan(env, "bank.test", "/bank", "fake-bank-login")
    assert cap.title == "HDFC Bank NetBanking Login"
    pw = [f for f in cap.forms if f["password"]]
    assert len(pw) == 1
    assert "collect.test" in pw[0]["action"] and pw[0]["method"] == "post"
    assert "suspended" in cap.visible_text


# --- downloads: caught, identified, never run -------------------------------------

def test_exe_download_is_quarantined_and_identified(env):
    cap = scan(env, "files.test", "/invoice", "exe-download")
    assert len(cap.downloads) == 1
    d = cap.downloads[0]
    assert d["filename"] == "invoice.pdf.exe"
    assert d["quarantine_path"].endswith(".bin")
    q = Path(d["quarantine_path"])
    assert q.read_bytes() == FAKE_EXE
    assert d["sha256"] == filetypes.sha256_of(q)
    assert d["real_type"] == "windows-program" and d["executable"] is True
    assert filetypes.has_double_extension(d["filename"])


def test_downloaded_script_is_never_executed(env, tmp_path):
    marker = tmp_path / "EXECUTED.txt"
    cap = scan(env, "files.test", f"/bat?marker={marker}")
    assert len(cap.downloads) == 1
    d = cap.downloads[0]
    assert d["filename"] == "update.bat" and d["real_type"] == "script"
    time.sleep(1.0)
    assert not marker.exists(), "the downloaded script must never run"


# --- tracking and fingerprinting ---------------------------------------------------

def test_fingerprinting_techniques_are_reported(env):
    cap = scan(env, "plain.test", "/fingerprint", "fingerprinting")
    fp = {e["k"] for e in kinds(cap, "fp")}
    assert {"canvas", "fonts", "audio", "hardware"} <= fp, fp
    assert kinds(cap, "webrtc"), "WebRTC peer connection should be reported"


def test_ip_logger_hop_is_in_the_chain(env):
    cap = scan(env, "short.test", "/go", "ip-logger")
    hosts = [h["url"].split("//")[1].split(":")[0] for h in cap.redirects]
    assert "grabify.link" in hosts


# --- scams and browser abuse ----------------------------------------------------------

def test_clickfix_clipboard_command_is_captured(env):
    cap = scan(env, "evil.test", "/clickfix", "clickfix")
    clip = " ".join(e["text"] for e in kinds(cap, "clipboard"))
    assert "powershell" in clip and "iex" in clip


def test_dangerous_protocol_launch_is_blocked_and_reported(env):
    cap = scan(env, "evil.test", "/msdt", "ms-msdt")
    schemes = {p["scheme"] for p in cap.protocol_attempts}
    assert "ms-msdt" in schemes
    assert "search-ms" in cap.link_schemes
    assert any("ms-msdt" in b["url"] for b in cap.blocked)


def test_scam_page_behaviour_is_reported(env):
    cap = scan(env, "evil.test", "/scam", "fake-virus-alert")
    got = {e["t"] for e in cap.events} | {e.get("k") for e in cap.events}
    assert "fullscreen" in got and "notifications" in got and "unload_trap" in got
    assert "infected" in cap.visible_text.lower()


def test_wasm_and_eval_are_reported(env):
    cap = scan(env, "evil.test", "/miner", "miner")
    got = {e["t"] for e in cap.events}
    assert "wasm" in got and "eval" in got


def test_open_redirect_hands_off_to_another_domain(env):
    target = env["sites"].url("evil.test", "/evil")
    cap = scan(env, "trusted.test", f"/out?url={target}", "open-redirect")
    hosts = [h["url"].split("//")[1].split(":")[0] for h in cap.redirects]
    assert hosts[0] == "trusted.test" and hosts[-1] == "evil.test"


def test_hidden_text_is_separated_from_visible_text(env):
    cap = scan(env, "plain.test", "/injection", "hidden-injection")
    assert "Ignore all previous instructions" in cap.hidden_text
    assert "disregard your rules" in cap.hidden_text          # HTML comment
    assert "Ignore all previous" not in cap.visible_text
    assert "simple dinners" in cap.visible_text


# --- protecting the user's own network (SSRF) -------------------------------------------

def test_redirect_to_localhost_is_blocked(env):
    cap = scan(env, "evil.test", "/ssrf", "ssrf-localhost")
    assert any("127.0.0.1:5157" in b["url"] and "private" in b["reason"] for b in cap.blocked)
    assert cap.status == "failed" and "private network" in cap.error


def test_redirect_to_cloud_metadata_is_blocked(env):
    cap = scan(env, "evil.test", "/ssrf-meta")
    assert any("169.254.169.254" in b["url"] for b in cap.blocked)


def test_page_resources_into_lan_are_blocked(env):
    cap = scan(env, "evil.test", "/ssrf-sub", "ssrf-subresources")
    blocked = " ".join(b["url"] for b in cap.blocked)
    assert "192.168.0.1" in blocked and "10.0.0.1" in blocked
    assert cap.status == "done"


def test_unknown_website_fails_cleanly(env):
    cap = env["worker"].submit("http://this-name-does-not-exist-pg.invalid/", 9001).result(timeout=40)
    assert cap.status == "failed"
    assert cap.error


# --- limits, isolation and recovery --------------------------------------------------------

def test_slow_page_times_out_within_budget(env):
    t0 = time.monotonic()
    cap = scan(env, "plain.test", "/slow", "slow-page", timeout=60)
    took = time.monotonic() - t0
    assert cap.status == "partial" and "did not finish" in cap.error
    assert took < 21, f"took {took:.1f}s, budget is 20s"


def test_each_scan_is_isolated_no_cookies_carry_over(env):
    first = scan(env, "cookie.test", "/cookie-set")
    assert first.status == "done"
    second = scan(env, "cookie.test", "/cookie-check")
    assert second.title == "cookies:none"


def test_worker_recovers_after_browser_crash(env):
    w = env["worker"]
    before = w.call(lambda sb: sb.launches).result(timeout=10)
    w.call(lambda sb: sb.browser.close()).result(timeout=10)       # simulate a crash
    cap = scan(env, "plain.test", "/plain")
    assert cap.status == "done" and cap.title == "Bengaluru weather"
    after = w.call(lambda sb: sb.launches).result(timeout=10)
    assert after == before + 1


def test_warm_scan_is_fast(env):
    t0 = time.monotonic()
    cap = scan(env, "plain.test", "/plain")
    took = time.monotonic() - t0
    assert cap.status == "done"
    assert took < 8, f"plain page took {took:.1f}s"
