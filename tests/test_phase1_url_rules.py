"""Phase 1: URL normalising, parsing, the URL rules and scoring."""
import time

import pytest

from phishguard import rules, urltools
from phishguard.urltools import UnsafeURL


def codes(url, **kw):
    return {f.code for f in rules.url_findings(urltools.parse(url), **kw)}


# --- normalising and refusing -------------------------------------------------

@pytest.mark.parametrize("raw", [
    "javascript:alert(1)", "file:///C:/Windows/system32", "ms-msdt:/id PCWDiagnostic",
    "search-ms:query=x", "data:text/html,<script>1</script>", "ftp://example.com/a",
    "vbscript:msgbox", "ms-officecmd:x", "", "   ", "http://", "https://exa mple.com\n/x",
])
def test_non_web_or_broken_links_are_refused(raw):
    with pytest.raises(UnsafeURL):
        urltools.parse(raw)


@pytest.mark.parametrize("raw,expected", [
    ("example.com", "https://example.com/"),
    ("  <https://Example.COM/Path>  ", "https://example.com/Path"),
    ("HTTP://WWW.Example.com", "http://www.example.com/"),
    ("//cdn.example.com/x.js", "https://cdn.example.com/x.js"),
    ('"https://example.com/a?b=1#c"', "https://example.com/a?b=1#c"),
])
def test_normalise(raw, expected):
    assert urltools.normalise(raw) == expected


def test_overlong_link_refused():
    with pytest.raises(UnsafeURL):
        urltools.normalise("https://a.com/" + "x" * 5000)


@pytest.mark.parametrize("url,reg", [
    ("https://login.paypal.co.uk/x", "paypal.co.uk"),
    ("https://a.b.c.example.com", "example.com"),
    ("https://onlinesbi.sbi/", "onlinesbi.sbi"),
    ("http://192.168.1.1/", "192.168.1.1"),
    ("http://3232235777/", "192.168.1.1"),
    ("http://0xC0A80001/", "192.168.0.1"),
    ("http://[::1]:8080/", "::1"),
])
def test_registrable_domain(url, reg):
    assert urltools.parse(url).registrable == reg


@pytest.mark.parametrize("ip,private", [
    ("127.0.0.1", True), ("10.0.0.5", True), ("192.168.0.1", True), ("172.16.3.4", True),
    ("169.254.169.254", True), ("100.64.1.1", True), ("0.0.0.0", True), ("::1", True),
    ("fe80::1", True), ("::ffff:127.0.0.1", True), ("224.0.0.1", True),
    ("8.8.8.8", False), ("1.1.1.1", False), ("2606:4700:4700::1111", False),
])
def test_private_ip_detection(ip, private):
    assert urltools.is_private_ip(ip) is private


@pytest.mark.parametrize("a,b", [("google.com", "mail.google.com"), ("google.com", "google.com")])
def test_domain_matches(a, b):
    assert urltools.domain_matches(b, a)


def test_domain_match_is_not_a_plain_suffix():
    assert not urltools.domain_matches("evilgoogle.com", "google.com")


# --- each rule, positive and negative -------------------------------------------

CASES = [
    # url, must contain, must not contain
    ("https://www.google.com/search?q=cats", set(), {"BRAND_LOOKALIKE", "BRAND_IMPERSONATION", "NO_HTTPS", "LURE_WORDS"}),
    ("https://accounts.google.com/signin", set(), {"LURE_WORDS", "BRAND_IN_SUBDOMAIN"}),
    ("https://www.paypal.com/signin", set(), {"BRAND_LOOKALIKE", "LURE_WORDS"}),
    ("https://onlinesbi.sbi/", set(), {"BRAND_IMPERSONATION"}),
    ("https://en.wikipedia.org/wiki/Phishing", set(), {"BRAND_LOOKALIKE", "LURE_WORDS", "RISKY_TLD"}),
    ("http://198.51.100.7/login", {"IP_HOST", "NO_HTTPS", "LURE_WORDS"}, set()),
    ("http://3232235777/", {"IP_HOST"}, set()),
    ("https://www.google.com@evil.example/", {"USERINFO_AT"}, set()),
    ("https://paypa1.com/login", {"BRAND_LOOKALIKE", "LURE_WORDS"}, set()),
    ("https://g00gle.com/", {"BRAND_LOOKALIKE"}, set()),
    ("https://goggle.com/", {"BRAND_LOOKALIKE"}, set()),
    ("https://micros0ft-support.com/", {"BRAND_LOOKALIKE"}, set()),
    ("https://rnicrosoft.com/", {"BRAND_LOOKALIKE"}, set()),
    ("https://faceb00k.net/", {"BRAND_LOOKALIKE"}, set()),
    ("https://paypal.xyz/", {"BRAND_IMPERSONATION", "RISKY_TLD"}, set()),
    ("https://netflix-billing.top/update", {"BRAND_IMPERSONATION", "RISKY_TLD", "LURE_WORDS"}, set()),
    ("https://paypal.com.secure-check.net/", {"BRAND_IN_SUBDOMAIN"}, {"BRAND_IMPERSONATION"}),
    ("https://apple.id.verify-now.info/", {"BRAND_IN_SUBDOMAIN", "LURE_WORDS"}, set()),
    ("https://xn--pple-43d.com/", {"BRAND_LOOKALIKE"}, set()),                       # Cyrillic a + pple
    ("https://xn--80ak6aa92e.com/", {"PUNYCODE"}, set()),                            # all-Cyrillic "apple"
    ("https://xn--mnchen-3ya.de/", {"PUNYCODE"}, {"MIXED_SCRIPT", "BRAND_LOOKALIKE"}),  # münchen: fine but flagged softly
    ("https://a.b.c.d.example.com/", {"MANY_SUBDOMAINS"}, set()),
    ("https://shop.example.com/", set(), {"MANY_SUBDOMAINS"}),
    ("https://free-prize.zip/", {"RISKY_TLD", "LURE_WORDS"}, set()),
    ("https://example.com/", set(), {"RISKY_TLD"}),
    ("https://bit.ly/3xyz", {"SHORTENER"}, set()),
    ("https://tinyurl.com/abc", {"SHORTENER"}, set()),
    ("http://example.com/", {"NO_HTTPS"}, set()),
    ("https://example.com/", set(), {"NO_HTTPS"}),
    ("https://example.com/" + "a" * 120, {"LONG_URL"}, set()),
    ("https://example.com:8443/", {"UNUSUAL_PORT"}, set()),
    ("https://example.com:443/", set(), {"UNUSUAL_PORT"}),
    ("https://secure-bank-login-portal.com/", {"MANY_HYPHENS", "LURE_WORDS"}, set()),
    ("https://my-site.com/", set(), {"MANY_HYPHENS"}),
    ("https://example.com/account/verify", {"LURE_WORDS"}, set()),
    ("https://example.com/blog/verified-recipes", set(), {"LURE_WORDS"}),
    ("https://grabify.link/ABC123", {"IP_LOGGER"}, set()),
    ("https://iplogger.org/2abc", {"IP_LOGGER"}, set()),
    ("https://stopify.co/xyz", {"IP_LOGGER"}, set()),
    ("https://example.com/?utm_source=x&fbclid=y", {"TRACKING_PARAMS"}, set()),
    ("https://example.com/?page=2", set(), {"TRACKING_PARAMS"}),
    ("https://example.com/out?url=https%3A%2F%2Fevil.example%2F", {"REDIRECT_PARAM"}, set()),
    ("https://example.com/out?next=https://example.com/home", set(), {"REDIRECT_PARAM"}),
    ("https://steampowered.com/", set(), {"BRAND_LOOKALIKE"}),
    ("https://stream.com/", set(), {"BRAND_LOOKALIKE"}),
    ("https://telegraph.co.uk/", set(), {"BRAND_LOOKALIKE"}),
    ("https://amaz0n-delivery.in/", {"BRAND_LOOKALIKE"}, set()),
    ("https://hdfcbank-kyc.co/", {"BRAND_IMPERSONATION", "LURE_WORDS"}, set()),
    ("https://sbi.co.in/", set(), {"BRAND_IMPERSONATION"}),
]


@pytest.mark.parametrize("url,must,must_not", CASES, ids=[c[0][:60] for c in CASES])
def test_url_rule(url, must, must_not):
    got = codes(url)
    assert must <= got, f"missing {must - got} in {got}"
    assert not (must_not & got), f"unexpected {must_not & got}"


def test_blocklist_matches_domain_and_subdomains():
    assert "BLOCKLISTED" in codes("https://evil.example/x", blocklist=["evil.example"])
    assert "BLOCKLISTED" in codes("https://a.evil.example/x", blocklist=["evil.example"])
    assert "BLOCKLISTED" not in codes("https://notevil.example/", blocklist=["evil.example"])


def test_every_finding_has_a_known_category_and_message():
    for url, *_ in CASES:
        for f in rules.url_findings(urltools.parse(url)):
            assert f.category in rules.CATEGORIES
            assert f.message and "{" not in f.message


# --- scoring --------------------------------------------------------------------

def test_level_boundaries():
    assert rules.level_for(0) == "clear"
    assert rules.level_for(19) == "clear"
    assert rules.level_for(20) == "caution"
    assert rules.level_for(49) == "caution"
    assert rules.level_for(50) == "danger"
    assert rules.level_for(100) == "danger"


def test_score_is_capped_and_per_category():
    fs = [rules.make("BLOCKLISTED"), rules.make("IP_HOST"), rules.make("TRACKING_PARAMS", params="x")]
    v = rules.verdict(fs)
    assert v["subs"]["phishing"] == 100
    assert v["subs"]["tracking"] == 5
    assert v["score"] == 100 and v["level"] == "danger"


def test_same_rule_never_counts_twice():
    fs = [rules.make("NO_HTTPS"), rules.make("NO_HTTPS")]
    assert rules.verdict(fs)["score"] == 15


def test_clean_site_is_clear():
    v = rules.verdict(rules.url_findings(urltools.parse("https://en.wikipedia.org/wiki/Bengaluru")))
    assert v["level"] == "clear" and v["score"] == 0


def test_obvious_phish_is_danger():
    v = rules.verdict(rules.url_findings(urltools.parse("http://paypa1-secure.top/login/verify")))
    assert v["level"] == "danger"


# --- clean link -------------------------------------------------------------------

def test_clean_url_removes_only_tracking():
    clean, removed = urltools.clean_url(
        "https://shop.example.com/item?id=42&utm_source=mail&utm_campaign=x&fbclid=abc&gclid=z&color=red")
    assert clean == "https://shop.example.com/item?id=42&color=red"
    assert set(removed) == {"utm_source", "utm_campaign", "fbclid", "gclid"}


def test_clean_url_leaves_untracked_link_untouched():
    url = "https://example.com/a?q=hello%20world&x=1#top"
    assert urltools.clean_url(url) == (url, [])


# --- speed ------------------------------------------------------------------------

def test_benchmark_1000_urls_under_1ms_each(tmp_path):
    urls = [c[0] for c in CASES] * (1000 // len(CASES) + 1)
    urls = urls[:1000]
    t0 = time.perf_counter()
    for u in urls:
        rules.verdict(rules.url_findings(urltools.parse(u)))
    avg_ms = (time.perf_counter() - t0) * 1000 / len(urls)
    from pathlib import Path
    out = Path(__file__).resolve().parent.parent / "proof" / "phase-1"
    out.mkdir(parents=True, exist_ok=True)
    (out / "bench.txt").write_text(
        f"URL verdict benchmark\nURLs scored: {len(urls)}\nAverage per URL: {avg_ms:.3f} ms\n"
        f"Target: < 1 ms\n", encoding="utf-8")
    assert avg_ms < 1.0
