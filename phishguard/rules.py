"""The risk engine. Pure functions: facts in, findings out, no I/O.

Every rule has one line in RULES: its category, its weight and the plain-English
message a person sees. Tuning PhishGuard means editing this table.
"""
import re
from dataclasses import dataclass
from urllib.parse import parse_qsl, unquote

from . import intel
from .urltools import (ParsedURL, deconfuse, domain_matches, edit_distance, is_tracking_param,
                       registrable_domain, scripts_in, to_unicode_host)

CATEGORIES = ("phishing", "malware", "tracking", "abuse")

# code: (category, weight, message)
RULES = {
    # URL rules - phishing
    "BLOCKLISTED":        ("phishing", 100, "You (or an admin) put this website on the block list."),
    "IP_HOST":            ("phishing", 25, "The link uses a raw IP address instead of a website name."),
    "USERINFO_AT":        ("phishing", 20, "The link hides its real destination after an '@' sign."),
    "PUNYCODE":           ("phishing", 15, "The website name uses special international characters."),
    "MIXED_SCRIPT":       ("phishing", 30, "The website name mixes alphabets, a classic lookalike trick."),
    "BRAND_LOOKALIKE":    ("phishing", 30, "The website name imitates {brand} but is not {brand}."),
    "BRAND_IMPERSONATION": ("phishing", 30, "The website uses the name {brand} but is not run by {brand}."),
    "BRAND_IN_SUBDOMAIN": ("phishing", 25, "'{brand}' appears in the address, but the real website is {reg}."),
    "MANY_SUBDOMAINS":    ("phishing", 10, "The address is padded with many sub-domains to look official."),
    "RISKY_TLD":          ("phishing", 10, "The '.{tld}' ending is heavily used by scam sites."),
    "SHORTENER":          ("phishing", 10, "A link shortener hides where this link really goes."),
    "NO_HTTPS":           ("phishing", 15, "The link is not encrypted (http, not https)."),
    "LONG_URL":           ("phishing", 5, "The link is unusually long, which can hide its real target."),
    "LURE_WORDS":         ("phishing", 10, "The link uses bait words like '{words}'."),
    "UNUSUAL_PORT":       ("phishing", 10, "The link points to an unusual network port ({port})."),
    "MANY_HYPHENS":       ("phishing", 5, "The website name is stitched together with many hyphens."),
    # URL rules - tracking and abuse
    "IP_LOGGER":          ("tracking", 60, "This is an IP-logger link: opening it records your IP address and device."),
    "TRACKING_PARAMS":    ("tracking", 5, "The link carries tracking tags ({params})."),
    "REDIRECT_PARAM":     ("abuse", 10, "The link carries another website's address inside it ({target})."),
}


@dataclass(frozen=True)
class Finding:
    code: str
    category: str
    weight: int
    message: str
    stage: str = "url"


def make(code: str, stage: str = "url", weight: int | None = None, **fmt) -> Finding:
    category, w, message = RULES[code]
    return Finding(code, category, w if weight is None else weight,
                   message.format(**fmt) if fmt else message, stage)


# --- URL rules -----------------------------------------------------------------------

def _brand_findings(p: ParsedURL) -> list[Finding]:
    if p.is_ip or p.registrable in intel.ALL_BRAND_DOMAINS:
        return []
    name_u = to_unicode_host(p.domain_name.lower())
    # (as written, de-confused) pairs for the main name and its hyphen parts
    tokens = [(t, deconfuse(t)) for t in {name_u, *name_u.split("-")} if t]
    sub_tokens = set()
    for part in p.subdomain.lower().split("."):
        sub_tokens.update(t for t in part.split("-") if t)
    sub_dc = sub_tokens | {deconfuse(t) for t in sub_tokens}
    out = []
    for brand, homes in intel.BRANDS.items():
        if p.registrable in homes:
            continue
        limit = 2 if len(brand) >= 9 else 1 if len(brand) >= 6 else 0
        hit = None
        for tok, dc in tokens:
            if tok == brand:
                hit = "BRAND_IMPERSONATION"
            elif dc == brand:
                hit = "BRAND_LOOKALIKE"
            elif limit and abs(len(dc) - len(brand)) <= limit and 0 < edit_distance(dc, brand) <= limit:
                hit = "BRAND_LOOKALIKE"
            if hit:
                break
        if hit:
            out.append(make(hit, brand=intel.brand_name(brand)))
        elif brand in sub_dc:
            out.append(make("BRAND_IN_SUBDOMAIN", brand=intel.brand_name(brand), reg=p.registrable))
        if out:
            break   # one brand finding is enough; stacking them would double-count
    return out[:1]   # one brand finding is enough; stacking them would double-count


def url_findings(p: ParsedURL, blocklist=()) -> list[Finding]:
    f: list[Finding] = []
    host = p.host

    if any(domain_matches(host, d) for d in blocklist):
        f.append(make("BLOCKLISTED"))

    if p.is_ip:
        f.append(make("IP_HOST"))
    if p.has_userinfo:
        f.append(make("USERINFO_AT"))

    if "xn--" in host:
        labels = p.host_unicode.split(".")
        if any(len(scripts_in(lb)) > 1 for lb in labels):
            f.append(make("MIXED_SCRIPT"))
        else:
            f.append(make("PUNYCODE"))

    f.extend(_brand_findings(p))

    if not p.is_ip and p.subdomain and len(p.subdomain.split(".")) > 3:
        f.append(make("MANY_SUBDOMAINS"))
    if p.suffix and p.suffix.split(".")[-1] in intel.RISKY_TLDS:
        f.append(make("RISKY_TLD", tld=p.suffix.split(".")[-1]))
    if p.registrable in intel.URL_SHORTENERS:
        f.append(make("SHORTENER"))
    if p.scheme == "http":
        f.append(make("NO_HTTPS"))
    if len(p.url) > 100:
        f.append(make("LONG_URL"))
    if p.port not in (None, 80, 443):
        f.append(make("UNUSUAL_PORT", port=p.port))
    if p.domain_name.count("-") >= 3:
        f.append(make("MANY_HYPHENS"))

    if p.registrable not in intel.ALL_BRAND_DOMAINS:
        hay = f"{p.subdomain} {p.domain_name} {unquote(p.path)} {unquote(p.query)}".lower()
        words = sorted(intel.LURE_WORDS.intersection(re.split(r"[^a-z0-9]+", hay)))
        if words:
            f.append(make("LURE_WORDS", words="', '".join(words[:3])))

    if any(domain_matches(host, d) for d in intel.IP_LOGGERS):
        f.append(make("IP_LOGGER"))

    pairs = parse_qsl(p.query, keep_blank_values=True)
    tracked = sorted({k for k, _ in pairs if is_tracking_param(k)})
    if tracked:
        f.append(make("TRACKING_PARAMS", params=", ".join(tracked[:4])))
    for _, v in pairs:
        v = unquote(v).strip().lower()
        if v.startswith(("http://", "https://", "//")):
            try:
                target = registrable_domain(v if "://" in v else "https:" + v)
            except ValueError:
                continue
            if target != p.registrable:
                f.append(make("REDIRECT_PARAM", target=target))
                break
    return f


# --- scoring -------------------------------------------------------------------------

def sub_scores(findings) -> dict[str, int]:
    s = {c: 0 for c in CATEGORIES}
    seen = set()
    for x in findings:
        if (x.code, x.stage) in seen:   # the same rule never counts twice
            continue
        seen.add((x.code, x.stage))
        s[x.category] += x.weight
    return {c: min(100, v) for c, v in s.items()}


def level_for(score: int) -> str:
    if score >= 50:
        return "danger"
    if score >= 20:
        return "caution"
    return "clear"


def verdict(findings) -> dict:
    subs = sub_scores(findings)
    score = max(subs.values())
    return {"score": score, "level": level_for(score), "subs": subs}
