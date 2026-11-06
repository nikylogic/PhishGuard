"""Who does this page claim to be, and is it really them?

The reference-based method from phishing research (Phishpedia, USENIX Security 2021;
PhishIntention, USENIX Security 2022): a phishing page has to pretend to be someone, or nobody
would type their password. So instead of asking "does the address look like a brand?", ask:

  1. Which brand does the page present itself as?  (favicon, logo, title, site name, text)
  2. Does it ask for something worth stealing?      (password, OTP, card, ID number, login)
  3. Is it on that brand's own website?

A page that claims HSBC, asks for a password and is not on an HSBC domain is phishing, however
its address is spelled. hdfcbank.com showing the HDFC logo is fine; it is HDFC's own site.

Pages that claim no brand (a fake college portal) are judged on where they live: a login form on
a free hosting platform, or on a website registered a few days ago (PhishIntention's idea that the
credential-taking intent matters as much as the look).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from urllib.parse import urlsplit, unquote

from . import intel
from .rules import Finding, make
from .urltools import registrable_domain

TEXT_LIMIT = 3000          # the start of the visible text, where a login page says who it is
LOGO_ZONE = 450            # pixels from the top of the page where a logo sits


def _norm(s: str) -> str:
    return " " + re.sub(r"[^a-z0-9]+", " ", (s or "").lower()).strip() + " "


def _reg(url: str) -> str:
    try:
        return registrable_domain(url)
    except ValueError:
        return ""


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


# One pattern for every brand word, longest first, so "union bank of india" wins over "bank of india".
_WORDS = sorted({(_norm(w).strip(), k) for k, b in intel.BRAND_INFO.items() for w in b["words"]},
                key=lambda x: -len(x[0]))
_WORD_BRAND = {w: k for w, k in reversed(_WORDS)}
_WORD_RE = re.compile(r"(?<= )(" + "|".join(re.escape(w) for w, _ in _WORDS) + r")(?= )")


def brands_in(text: str) -> dict[str, int]:
    """Brand -> number of times the text names it."""
    out: dict[str, int] = {}
    for m in _WORD_RE.finditer(_norm(text)):
        k = _WORD_BRAND[m.group(1)]
        out[k] = out.get(k, 0) + 1
    return out


@dataclass
class Claim:
    brand: str
    points: int = 0
    strong: bool = False              # favicon, logo or site name: a deliberate copy of the brand
    evidence: list = field(default_factory=list)


def claims(cap: dict, min_points: int = 3) -> list[Claim]:
    """Every brand the page presents itself as, strongest first. Three points are needed (two
    signals, or one deliberate copy such as the favicon); two are enough on a page that asks for
    a password, OTP or card, because "PayPal: Log in" above a password box is already a claim."""
    found: dict[str, Claim] = {}

    def add(brand, pts, why, strong=False):
        c = found.setdefault(brand, Claim(brand))
        if why not in c.evidence:
            c.points += pts
            c.strong = c.strong or strong
            c.evidence.append(why)

    fav_hash = cap.get("favicon_sha256") or ""
    if fav_hash in intel.FAVICON_BRANDS:
        add(intel.FAVICON_BRANDS[fav_hash], 3, "its favicon is a copy of the brand's", strong=True)
    fav_reg = _reg(cap.get("favicon") or "")
    for k, b in intel.BRAND_INFO.items():
        if fav_reg and fav_reg in b["domains"]:
            add(k, 3, f"its favicon is loaded from {fav_reg}", strong=True)

    for img in cap.get("images") or []:
        if (img.get("top") or 0) > LOGO_ZONE or (img.get("w") or 0) > 600:
            continue
        src = img.get("src") or ""
        name = unquote(urlsplit(src).path.rsplit("/", 1)[-1]) if src else ""
        for k in brands_in(f"{img.get('alt', '')} {re.sub(r'[_.-]', ' ', name)}"):
            add(k, 2, "its logo", strong=True)
        img_reg = _reg(src)
        for k, b in intel.BRAND_INFO.items():
            if img_reg and img_reg in b["domains"]:
                add(k, 2, f"it shows images from {img_reg}", strong=True)

    for k in brands_in(cap.get("site_name") or ""):
        add(k, 2, "its site name", strong=True)
    for k in brands_in(cap.get("title") or ""):
        add(k, 2, "its title")
    for k, n in brands_in((cap.get("visible_text") or "")[:TEXT_LIMIT]).items():
        add(k, 2 if n >= 3 else 1, "its text")

    out = []
    for c in found.values():
        b = intel.BRAND_INFO[c.brand]
        if c.points < min_points:
            continue
        if b["strict"] and not c.strong:      # "apple", "chase", "steam" are ordinary words too
            continue
        out.append(c)
    return sorted(out, key=lambda c: (-c.points, -int(c.strong)))


# --- what the page asks you to type --------------------------------------------------------

_KINDS = [
    ("password", re.compile(r"\b(password|passwd|passcode|pass word|pwd|senha|contrase)")),
    ("OTP", re.compile(r"\b(otp|one time|one-time|mpin|m-pin|tpin|t-pin|verification code|security code|"
                       r"sms code|2fa|authenticator code|pin(?! ?code))\b")),
    ("card details", re.compile(r"\b(card ?number|cardnumber|cc-?num|cvv|cvc|cvv2|expiry|exp date|"
                                r"expiration|card holder|cardholder|debit card|credit card)")),
    ("ID number", re.compile(r"\b(aadhaar|aadhar|pan number|pan card|ssn|social security|"
                             r"date of birth|dob|mother.?s maiden)")),
    ("account login", re.compile(r"\b(e-?mail|username|user ?name|user ?id|userid|login ?id|customer ?id|"
                                 r"client ?id|account ?number|mobile ?number|phone ?number|netbanking id)")),
]
STRONG = {"password", "OTP", "card details", "ID number"}
LOGIN_WORDS = re.compile(r"\b(sign ?in|log ?in|logon|verify|verification|unlock|confirm your|"
                         r"re-?activate|validate|update your|secure your|password)\b")


def asks_for(cap: dict) -> set[str]:
    """What the page asks you to type: password, OTP, card details, ID number, account login."""
    kinds: set[str] = set()
    for i in cap.get("inputs") or []:
        typ = i.get("type") or ""
        if typ in ("hidden", "submit", "button", "checkbox", "radio", "search", "image", "reset", "file"):
            continue
        if typ == "password":
            kinds.add("password")
            continue
        if (i.get("ac") or "").startswith("cc-"):
            kinds.add("card details")
            continue
        if (i.get("ac") or "") == "one-time-code":
            kinds.add("OTP")
            continue
        hay = " ".join(str(i.get(k) or "") for k in ("name", "id", "ph", "label", "ac"))
        hay = re.sub(r"[_\-]+", " ", hay.lower())
        for kind, rx in _KINDS:
            if rx.search(hay):
                kinds.add(kind)
                break
        else:
            if typ == "email":
                kinds.add("account login")
            elif typ == "tel":
                kinds.add("account login")
    # Captures from before inputs were recorded.
    if any(f.get("password") for f in cap.get("forms") or []) or (cap.get("loose_password_fields") or 0) > 0:
        kinds.add("password")
    return kinds


def _describe(kinds: set[str]) -> str:
    order = ["password", "OTP", "card details", "ID number", "account login"]
    words = {"password": "your password", "OTP": "an OTP or PIN", "card details": "your card details",
             "ID number": "your ID number", "account login": "your login details"}
    picked = [words[k] for k in order if k in kinds][:2]
    return " and ".join(picked)


def looks_like_login(cap: dict) -> bool:
    return bool(LOGIN_WORDS.search(_norm(f"{cap.get('title', '')} {(cap.get('visible_text') or '')[:2000]}")))


# --- the findings ---------------------------------------------------------------------------

# Words scam domains are built from. A site name made only of these is not a name of its own.
GENERIC_WORDS = sorted({
    "bank", "banking", "netbanking", "net", "online", "secure", "security", "safe", "login", "logon", "signin",
    "sign", "in", "auth", "verify", "verification", "account", "accounts", "acc", "update", "portal", "my",
    "web", "www", "support", "service", "services", "help", "helpdesk", "customer", "care", "kyc", "pay",
    "payment", "payments", "wallet", "reward", "rewards", "offer", "offers", "claim", "gift", "bonus", "alert",
    "notice", "info", "center", "centre", "app", "apps", "mobile", "id", "user", "client", "access", "official",
    "india", "global", "direct", "home", "page", "site", "e", "i", "m", "the", "and", "now", "today", "card",
    "cards", "credit", "debit", "upi", "refund", "tax", "income", "loan", "cash", "money", "finance",
}, key=len, reverse=True)


def only_generic(name: str) -> bool:
    """True when `name` splits completely into GENERIC_WORDS (and digits): 'securelogin', 'bank24'."""
    name = re.sub(r"\d+", "", name)
    ok = [True] + [False] * len(name)
    for i in range(len(name)):
        if ok[i]:
            for w in GENERIC_WORDS:
                if name.startswith(w, i):
                    ok[i + len(w)] = True
    return ok[-1]


def identity_findings(cap: dict, facts: dict | None = None) -> list[Finding]:
    facts = facts or {}
    final = cap.get("final_url") or cap.get("url") or ""
    host, reg = _host(final), _reg(final)
    if not reg:
        return []
    out: list[Finding] = []
    free = intel.is_free_host(host, reg)
    kinds = asks_for(cap)
    strong_ask = bool(kinds & STRONG)
    login = strong_ask or (bool(kinds) and looks_like_login(cap))
    what = _describe(kinds)
    site = host.removeprefix("www.") if free else reg

    # 1-3. The brand the page presents itself as, against where it really is.
    own = re.sub(r"[^a-z0-9]", "", reg.split(".")[0])
    # A name made only of everyday words (bank.test, secure-login.top) appears in any bank's
    # title, so it says nothing about who runs the site and never counts as naming itself.
    self_named = (len(own) >= 4 and not only_generic(own)
                  and own in re.sub(r"[^a-z0-9]", "", f"{cap.get('title', '')} {cap.get('site_name', '')}".lower()))
    for c in claims(cap, min_points=2 if strong_ask else 3)[:1]:
        b = intel.BRAND_INFO[c.brand]
        on_own_site = reg in b["domains"] and not free
        if on_own_site or intel.is_restricted(reg):
            break
        # "Names itself" only counts when the site's own name is not the brand's: on
        # hdfc-bank.example the title "HDFC Bank" names the brand, not some news site.
        brand_names = {re.sub(r"[^a-z0-9]", "", w) for w in b["words"]} | set(b["tokens"])
        names_itself = self_named and not any(len(n) >= 3 and n in own for n in brand_names)
        if intel.is_established(host, reg) or (names_itself and not c.strong):
            break       # a known site, or one that names itself, talking about a brand (news, forums)
        if strong_ask:
            out.append(make("IMPERSONATION_LOGIN", "page", brand=b["name"], what=what, site=site))
        elif kinds and (c.strong or looks_like_login(cap)):
            out.append(make("IMPERSONATION_ID", "page", brand=b["name"], what=what, site=site))
        else:
            # Real brands do not publish on free hosting platforms, so a claim there weighs more.
            out.append(make("IMPERSONATION", "page", weight=30 if free else 15, brand=b["name"], site=site))

    # 4-5. A login with no brand: judged on where it lives.
    if login and free:
        out.append(make("LOGIN_FREE_HOST", "page", what=what, host=site))
    age = facts.get("age_days")
    if age is not None and not free and not intel.is_established(host, reg) and not intel.is_restricted(reg):
        if login and age < 30:
            out.append(make("LOGIN_NEW_DOMAIN", "page", what=what, days=age))
        if age < 7:
            out.append(make("DOMAIN_NEW", "page", weight=20, reg=reg, days=age, how=facts.get("how", "registered")))
        elif age < 30:
            out.append(make("DOMAIN_NEW", "page", weight=10, reg=reg, days=age, how=facts.get("how", "registered")))
    return out
