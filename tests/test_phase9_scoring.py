"""Scoring: threats decide the verdict; tracking is a privacy note; weak signals need corroboration.

Background: x.com came out "Caution 40/100" only because it fingerprints the device, scrambles its
code and opens WebRTC, which nearly every big site does. Google Safe Browsing's danger types are
social engineering, malware and unwanted software; tracking is not one of them.
"""
from phishguard.pagerules import make as page_make
from phishguard.rules import make, role, verdict


def codes(v):
    return set(v["counted"])


def test_big_site_that_only_tracks_is_clear():
    """The real x.com findings: fingerprinting (6 techniques), scrambled code, WebRTC."""
    f = [page_make("FINGERPRINT", stage="page", weight=36, techniques="battery, canvas"),
         page_make("OBFUSCATED", stage="page"),
         page_make("WEBRTC", stage="page"),
         make("TRACKING_PARAMS", params="s, t")]
    v = verdict(f)
    assert v["level"] == "clear" and v["score"] == 0 and codes(v) == set()
    assert v["subs"]["tracking"] > 0          # still shown in the breakdown


def test_many_trackers_alone_is_clear():
    v = verdict([page_make("TRACKERS_MANY", stage="page", n=30)])
    assert v["level"] == "clear"


def test_ip_logger_is_still_danger():
    """An IP logger exists only to unmask whoever clicks, so it stays a threat."""
    assert verdict([make("IP_LOGGER")])["level"] == "danger"
    assert verdict([page_make("IP_LOGGER_HOP", stage="page", host="grabify.link")])["level"] == "danger"


def test_scrambled_code_alone_does_not_count():
    assert verdict([page_make("OBFUSCATED", stage="page")])["level"] == "clear"
    assert verdict([make("LONG_URL"), make("MANY_HYPHENS")])["score"] == 0


def test_scrambled_code_adds_to_a_real_threat():
    """A fake-alert page that also hides its code scores higher than the alert alone."""
    alone = verdict([page_make("FAKE_ALERT", stage="page")])
    both = verdict([page_make("FAKE_ALERT", stage="page"), page_make("OBFUSCATED", stage="page")])
    assert both["score"] == alone["score"] + 15 and "OBFUSCATED" in codes(both)


def test_phishing_and_malware_unchanged():
    login = [page_make("BRAND_LOGIN", stage="page", brand="PayPal"),
             page_make("PW_OFFSITE", stage="page", target="collect.test"), make("RISKY_TLD", tld="top")]
    assert verdict(login)["level"] == "danger"
    assert verdict([page_make("DL_EXECUTABLE", stage="page", name="invoice.pdf.exe")])["level"] == "danger"
    assert verdict([page_make("CLICKFIX", stage="page")])["level"] == "danger"


def test_tracking_cannot_push_a_weak_threat_over_the_line():
    """No HTTPS (15) on its own is clear; heavy tracking next to it must not make it Caution."""
    v = verdict([make("NO_HTTPS"), page_make("TRACKERS_MANY", stage="page", n=40),
                 page_make("FINGERPRINT", stage="page", weight=36, techniques="canvas")])
    assert v["level"] == "clear" and v["score"] == 15


def test_roles():
    assert role(page_make("WEBRTC", stage="page")) == "privacy"
    assert role(make("IP_LOGGER")) == "threat"
    assert role(page_make("OBFUSCATED", stage="page")) == "supporting"
    assert role(make("BRAND_LOOKALIKE", brand="PayPal")) == "threat"


def test_weak_signals_never_turn_clear_into_caution():
    """Found on the held-out benchmark: lencr.org -> letsencrypt.org with a fresh certificate was
    Caution. A weak redirect (10) plus a new certificate stays Clear; a real threat still grows."""
    v = verdict([page_make("REDIRECTED_AWAY", stage="page", hops=2, final="letsencrypt.org"),
                 page_make("CERT_NEW", stage="page", days=3)])
    assert v["level"] == "clear" and "CERT_NEW" not in v["counted"]
    v2 = verdict([page_make("BRAND_LOGIN", stage="page", brand="PayPal"), page_make("CERT_NEW", stage="page", days=3)])
    assert v2["score"] == 40 and "CERT_NEW" in v2["counted"]


def test_extension_probes_are_not_app_launches():
    """Also found on the held-out benchmark: vinted.de and woocommerce.com probe chrome-extension:
    links (ad-blocker checks), which cannot start a Windows program."""
    from phishguard.pagerules import page_findings
    from phishguard.intel import Intel
    cap = {"url": "https://vinted.de/", "final_url": "https://vinted.de/",
           "protocol_attempts": [{"scheme": "chrome-extension"}], "link_schemes": ["chrome-extension"]}
    assert "PROTOCOL_LAUNCH" not in {f.code for f in page_findings(cap, Intel())}
