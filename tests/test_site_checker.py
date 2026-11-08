"""The website's link checker (site/checker.js) must judge addresses exactly like the engine.

Runs the same links through phishguard.rules and through checker.js under Node, with the data
scripts/build_site_data.py exports, and compares findings, messages and verdicts.
"""
import json
import shutil
import subprocess
import sys
from pathlib import Path

import pytest

from phishguard import rules, urltools

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
import build_site_data  # noqa: E402

NODE = shutil.which("node")
pytestmark = pytest.mark.skipif(NODE is None, reason="Node.js is not installed")

LINKS = [
    "https://hdfc-login-kyc.top/verify",
    "https://www.hdfcbank.com/personal",
    "https://netbanking.hdfcbank.com/netbanking/",
    "https://hdfc.bank.in/",
    "https://onlinesbi.sbi/",
    "https://sbi-kyc-update.xyz/login",
    "http://paypa1.com/signin",
    "https://paypal.com-secure-help.site/",
    "https://secure.paypal.com.account-verify.info/webscr",
    "https://www.paypal.com/myaccount/summary",
    "https://xn--pypal-4ve.com/",
    "https://xn--80ak6aa92e.com/",
    "https://xn--mnchen-3ya.de/",
    "https://amaz0n-prime-billing.com/update",
    "https://www.amazon.in/gp/cart",
    "https://appleid.apple.com.verify-id.icu/",
    "https://apple.com/",
    "https://www.apple.com/in/iphone/",
    "https://googleplaydown.com/app",
    "https://office365licensingsupport.com/",
    "https://facebooklogin17.blogspot.com/",
    "https://microsoft-account.vercel.app/login",
    "https://sites.google.com/view/hdfc-reward",
    "https://en.wikipedia.org/wiki/Phishing",
    "https://github.com/nikylogic/PhishGuard",
    "https://192.168.1.10/admin",
    "http://3232235777/",
    "https://0xC0A80001/x",
    "https://bank.com@evil.example/login",
    "https://evil.example\\@bank.com/",
    "https://bit.ly/3abcde",
    "https://grabify.link/ABC123",
    "https://example.com:8443/portal",
    "https://a.b.c.d.e.example.com/",
    "https://my-secure-bank-login-portal.com/",
    "https://example.com/?utm_source=x&fbclid=abc&gclid=1",
    "https://example.com/redirect?url=https://evil.example/phish",
    "https://news.example.com/?next=https://news.example.com/a",
    "https://www.google.com/url?q=https://phish.example/&sa=D",
    "https://wallet-connect-claim.click/reward",
    "https://example.co.uk/login",
    "https://foo.bar.ck/",
    "https://www.ck/",
    "https://www.netflix.com/browse",
    "https://netflix-billing-update.com/account",
    "https://steamcommunity.com/id/x",
    "https://steamcommunlty.com/tradeoffer",
    "https://booking.com/",
    "https://cooking.com/recipes",
    "https://hsbc.com/",
    "https://icici-bank-kyc.com/",
    "https://www.icicibank.com/",
    "https://whatsapp-web-login.net/",
    "https://web.whatsapp.com/",
    "example.com/invoice.pdf.exe",
    "//cdn.example.org/x.js",
    "https://LOGIN.MICROSOFTONLINE.COM/common/oauth2",
    "https://xn--80aswg.xn--p1ai/",
    "https://paytm.com-kyc.top/",
    "https://phonepe-cashback.xyz/claim",
    "https://irs-refund-verify.com/?id=1",
    "https://accounts.google.com.signin.verify-session.info/",
    "javascript:alert(1)",
    "ms-msdt:/id PCWDiagnostic",
    "file:///C:/Windows/System32/calc.exe",
]

RUNNER = r"""
const fs = require("fs")
const { Engine } = require(process.argv[2])
const E = new Engine(JSON.parse(fs.readFileSync(process.argv[3], "utf8")))
const out = {}
for (const link of JSON.parse(fs.readFileSync(process.argv[4], "utf8"))) {
  try {
    const p = E.parse(link)
    const f = E.urlFindings(p)
    const v = E.verdict(f)
    out[link] = { reg: p.registrable, findings: f.map((x) => [x.code, x.message]).sort(),
                  score: v.score, level: v.level }
  } catch (e) { out[link] = { error: true } }
}
process.stdout.write(JSON.stringify(out))
"""


def python_side(link):
    try:
        p = urltools.parse(link)
    except urltools.UnsafeURL:
        return {"error": True}
    f = rules.url_findings(p)
    v = rules.verdict(f)
    return {"reg": p.registrable, "findings": sorted([x.code, x.message] for x in f),
            "score": v["score"], "level": v["level"]}


@pytest.fixture(scope="module")
def js_results(tmp_path_factory):
    tmp = tmp_path_factory.mktemp("site")
    (tmp / "engine.json").write_text(json.dumps(build_site_data.engine(), ensure_ascii=False), encoding="utf-8")
    (tmp / "links.json").write_text(json.dumps(LINKS), encoding="utf-8")
    (tmp / "run.js").write_text(RUNNER, encoding="utf-8")
    done = subprocess.run([NODE, str(tmp / "run.js"), str(ROOT / "site" / "checker.js"),
                           str(tmp / "engine.json"), str(tmp / "links.json")],
                          capture_output=True, text=True, encoding="utf-8", timeout=60, check=True)
    return json.loads(done.stdout)


@pytest.mark.parametrize("link", LINKS)
def test_same_verdict_as_the_engine(js_results, link):
    assert js_results[link] == python_side(link)
