"""Page rules: judge what the sandbox recorded, and assemble the full verdict.

Input is a Capture as a dict (Capture.to_dict()), so these functions are pure and
can be tested with hand-written examples, without a browser.
"""
import re
import time
from urllib.parse import urlsplit

from . import filetypes, intel
from .identity import identity_findings
from .rules import RULES, Finding, make, url_findings, verdict
from .urltools import UnsafeURL, clean_url, domain_matches, parse, registrable_domain

RULES.update({
    # phishing
    "PW_NO_HTTPS":     ("phishing", 35, "This page asks for a password on an unencrypted (http) connection."),
    "PW_OFFSITE":      ("phishing", 30, "This page asks for your password but sends it to another website ({target})."),
    "BRAND_LOGIN":     ("phishing", 30, "This page looks like a {brand} login, but it is not on {brand}'s website."),
    "REDIRECTED_AWAY": ("phishing", 10, "The link bounced through {hops} hop(s) and ended on a different website ({final})."),
    "CERT_NEW":        ("phishing", 10, "The website's security certificate is only {days} day(s) old."),
    # identity check (identity.py) and domain facts (domaininfo.py)
    "IMPERSONATION_LOGIN": ("phishing", 70, "This page presents itself as {brand} and asks for {what}, but it is not on {brand}'s website ({site})."),
    "IMPERSONATION_ID":    ("phishing", 50, "This page presents itself as {brand} and asks for {what}, but it is not on {brand}'s website ({site})."),
    "IMPERSONATION":       ("phishing", 15, "This page presents itself as {brand}, but it is not on {brand}'s website ({site})."),
    "LOGIN_FREE_HOST":     ("phishing", 30, "This page asks for {what} on a free website-hosting service ({host}), where anyone can publish a page."),
    "LOGIN_NEW_DOMAIN":    ("phishing", 40, "This page asks for {what} on a website registered only {days} day(s) ago."),
    "DOMAIN_NEW":          ("phishing", 10, "The website {reg} was {how} only {days} day(s) ago."),
    "PHISH_LISTED":        ("phishing", 100, "This address is on a public list of reported phishing sites ({source})."),
    # malware
    "MALWARE_URL":     ("malware", 100, "This address is on the known-malware list."),
    "DL_KNOWN_BAD":    ("malware", 100, "The downloaded file matches a known malware fingerprint (SHA-256)."),
    "DL_EXECUTABLE":   ("malware", 50, "The page tried to download a program or script ({name})."),
    "DL_DISGUISED":    ("malware", 40, "The download is disguised: '{name}' is really a {real}."),
    "DL_ARCHIVE_EXE":  ("malware", 35, "The download is an archive or disk image hiding a program ({name})."),
    "DL_NO_CLICK":     ("malware", 15, "The page started a download by itself, without any click."),
    # tracking
    "FINGERPRINT":     ("tracking", 6, "The page fingerprints your device ({techniques})."),
    "WEBRTC":          ("tracking", 10, "The page opened a WebRTC connection, which can reveal your local IP address."),
    "TRACKERS_MANY":   ("tracking", 15, "The page loads {n} known trackers."),
    "IP_LOGGER_HOP":   ("tracking", 60, "The link passes through an IP logger ({host}) that records who opens it."),
    # scams and browser abuse
    "CLICKFIX":        ("abuse", 70, "The page secretly copied a command to your clipboard and wants you to run it."),
    "PROTOCOL_LAUNCH": ("abuse", 60, "The page tried to launch a Windows app through a '{scheme}:' link."),
    "PROTOCOL_LINK":   ("abuse", 25, "The page contains links that launch Windows apps ('{scheme}:')."),
    "MINER":           ("abuse", 50, "The page runs a crypto-miner that would use your computer's power."),
    "FAKE_ALERT":      ("abuse", 40, "The page shows a fake security alert and tries to trap you on it."),
    "KEYBOARD_LOCK":   ("abuse", 20, "The page tries to lock your keyboard so you cannot press Esc."),
    "PERMISSION_GRAB": ("abuse", 15, "The page immediately asks for permission to use {what}."),
    "OBFUSCATED":      ("abuse", 15, "The page hides what its code does (heavy obfuscation)."),
    "OPEN_REDIRECT":   ("abuse", 25, "A trusted website ({trusted}) was used to bounce you to {final}."),
    "PROMPT_INJECTION": ("abuse", 20, "The page hides instructions aimed at AI assistants (prompt injection)."),
})

CLICKFIX_RE = re.compile(
    r"powershell|pwsh|\bcmd(\.exe)?\s*/[ck]\b|mshta|\biex\b|invoke-expression|invoke-webrequest|\biwr\b|"
    r"certutil|bitsadmin|rundll32|regsvr32|wscript|cscript|msiexec|start-process|"
    r"curl\s[^|]*\|\s*(ba)?sh|wget\s[^|]*\|\s*(ba)?sh|frombase64string", re.I)
FAKE_ALERT_RE = re.compile(
    r"(your|this) (computer|pc|device|windows|system) (is|has been|was) (infected|locked|blocked|compromised)|"
    r"virus(es)? (detected|found)|call (microsoft|windows|apple|technical|tech) support|"
    r"do not (close|restart|shut down) (this|your)|"
    r"trojan|spyware (detected|alert)", re.I)
MILD_ALERT_RE = re.compile(r"toll[- ]free|security alert", re.I)
MINER_RE = re.compile(r"coinhive|cryptonight|crypto-?loot|coinimp|webminepool|hashrate|"
                      r"\bminer\.start\(|monero|\bxmr\b|throttle\s*:", re.I)
DANGEROUS_SCHEMES = {
    "ms-msdt", "search-ms", "search", "ms-officecmd", "ms-word", "ms-excel", "ms-powerpoint",
    "ms-appinstaller", "ms-cxh", "ms-cxh-full", "ms-settings", "ms-windows-store", "ms-help",
    "ms-search", "msteams", "ms-gamingoverlay", "file", "jnlp", "steam", "itms-services",
    "vbscript", "res", "mk", "hcp", "ms-its",
}
HARMLESS_SCHEMES = {"http", "https", "mailto", "tel", "sms", "javascript", "data", "blob", "about",
                    # The browser's own pages and extensions: sites probe these (ad-blocker and
                    # extension checks); they cannot start a Windows program.
                    "chrome-extension", "moz-extension", "ms-browser-extension", "extension", "chrome", "edge"}


def _host(url: str) -> str:
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def _web(url) -> bool:
    return isinstance(url, str) and url.lower().startswith(("http://", "https://"))


def _same_owner(a: str, b: str) -> bool:
    """Both sites belong to the same brand, or both are in a verified zone (hdfcbank.com ->
    hdfc.bank.in, epfindia.gov.in -> epfo.gov.in)."""
    if intel.is_restricted(b) and (intel.is_restricted(a) or a in intel.ALL_BRAND_DOMAINS):
        return True     # a bank or government site moving to its verified .bank.in / .gov.in address
    return any(a in br["domains"] and b in br["domains"] for br in intel.BRAND_INFO.values())


def _reg(url: str) -> str:
    try:
        return registrable_domain(url)
    except ValueError:
        return _host(url)


def tracker_hosts(cap: dict, intel_db) -> list[str]:
    return sorted({hit for h in cap.get("request_domains") or []
                   if (hit := intel_db.host_in("tracker", h))})


def page_findings(cap: dict, intel_db, allowlist=(), blocklist=(), now: float | None = None) -> list[Finding]:
    f: list[Finding] = []
    start = cap.get("url", "")
    chain = [h["url"] for h in cap.get("redirects") or [] if _web(h.get("url"))] or [start]
    # The browser's own error page (chrome-error://...) is not a website the link went to.
    final = cap.get("final_url") if _web(cap.get("final_url")) else (chain[-1] if chain else start)
    final = final or start
    start_reg, final_reg = _reg(start), _reg(final)
    events = cap.get("events") or []
    kinds = {e.get("t") for e in events}

    # --- phishing -----------------------------------------------------------------
    pw_forms = [x for x in cap.get("forms") or [] if x.get("password")]
    has_pw = bool(pw_forms) or cap.get("loose_password_fields", 0) > 0
    if has_pw and final.lower().startswith("http://"):
        f.append(make("PW_NO_HTTPS", "page"))
    for form in pw_forms:
        action = form.get("action") or final
        target = _reg(action) if _web(action) else ""
        if target and target != final_reg and not _same_owner(target, final_reg):
            f.append(make("PW_OFFSITE", "page", target=target))
            break
    # Which brand the page claims to be, and whether it is really that brand: identity.py.
    hops = max(0, len(chain) - 1)
    moved = final_reg and start_reg and final_reg != start_reg and not _same_owner(start_reg, final_reg)
    if hops > 3 or moved:
        f.append(make("REDIRECTED_AWAY", "page", hops=hops, final=final_reg or final))
    valid_from = (cap.get("tls") or {}).get("validFrom")
    if valid_from:
        days = int(((now or time.time()) - float(valid_from)) // 86400)
        if 0 <= days < 7:
            f.append(make("CERT_NEW", "page", days=days))

    # Every hop of the chain is checked against the lists.
    for hop in dict.fromkeys(chain + [final]):
        h = _host(hop)
        if not h:
            continue
        if any(domain_matches(h, d) for d in blocklist):
            f.append(make("BLOCKLISTED", "page"))
        if intel_db.url_listed(hop):
            f.append(make("MALWARE_URL", "page"))
        hit = intel_db.host_in("ip_logger", h)
        if hit:
            f.append(make("IP_LOGGER_HOP", "page", host=hit))

    # --- malware -------------------------------------------------------------------
    downloads = cap.get("downloads") or []
    for d in downloads:
        name = d.get("filename") or "download"
        ext = filetypes.extension_of(name)
        real = d.get("real_type", "unknown")
        if d.get("sha256") and d["sha256"].lower() in intel_db.sets["bad_hash"]:
            f.append(make("DL_KNOWN_BAD", "page"))
        if real == "disk-image" or (real == "zip" and d.get("inner_executables")):
            f.append(make("DL_ARCHIVE_EXE", "page", name=name))
        elif d.get("executable") or ext in filetypes.EXECUTABLE_EXT:
            f.append(make("DL_EXECUTABLE", "page", name=name))
        if filetypes.has_double_extension(name) or (ext in filetypes.DOC_EXT and d.get("executable")):
            f.append(make("DL_DISGUISED", "page", name=name, real=real.replace("-", " ")))
        if d.get("url") and intel_db.url_listed(d["url"]):
            f.append(make("MALWARE_URL", "page"))
    if downloads:
        f.append(make("DL_NO_CLICK", "page"))

    # --- tracking ------------------------------------------------------------------
    techniques = sorted({e.get("k") for e in events if e.get("t") == "fp" and e.get("k")})
    if techniques:
        f.append(make("FINGERPRINT", "page", weight=min(30, 6 * len(techniques)),
                      techniques=", ".join(techniques)))
    if "webrtc" in kinds:
        f.append(make("WEBRTC", "page"))
    trackers = tracker_hosts(cap, intel_db)
    if len(trackers) > 10:
        f.append(make("TRACKERS_MANY", "page", n=len(trackers)))

    # --- scams and browser abuse -------------------------------------------------------
    clip = " ".join(e.get("text", "") for e in events if e.get("t") == "clipboard")
    if clip and CLICKFIX_RE.search(clip):
        f.append(make("CLICKFIX", "page"))
    launched = [p["scheme"] for p in cap.get("protocol_attempts") or [] if p.get("scheme") not in HARMLESS_SCHEMES]
    linked = [s for s in cap.get("link_schemes") or [] if s in DANGEROUS_SCHEMES]
    if launched:
        f.append(make("PROTOCOL_LAUNCH", "page", scheme=launched[0]))
    elif linked:
        f.append(make("PROTOCOL_LINK", "page", scheme=linked[0]))
    script = cap.get("inline_script") or ""
    miner_host = any(intel_db.host_in("miner", h) for h in cap.get("request_domains") or [])
    if miner_host or ("wasm" in kinds and MINER_RE.search(script)):
        f.append(make("MINER", "page"))
    text = f"{cap.get('title', '')} {cap.get('visible_text', '')}"
    # Scareware: alarming words plus a trap. "Security alert" and "toll-free" also appear in banks'
    # fraud-awareness banners, and many ordinary pages warn before you leave, so the mild words
    # only count with a real trap (full screen, keyboard lock).
    traps = kinds & {"fullscreen", "keylock", "unload_trap"}
    if (FAKE_ALERT_RE.search(text) and traps) or (MILD_ALERT_RE.search(text) and traps - {"unload_trap"}):
        f.append(make("FAKE_ALERT", "page"))
    if "keylock" in kinds:
        f.append(make("KEYBOARD_LOCK", "page"))
    perms = sorted({e.get("k") for e in events if e.get("t") == "perm" and e.get("k")})
    if perms:
        f.append(make("PERMISSION_GRAB", "page", what=", ".join(perms)))
    if (kinds & {"eval", "atob"} or re.search(r"[A-Za-z0-9+/]{1500,}={0,2}", script)
            or len(re.findall(r"\\x[0-9a-f]{2}", script, re.I)) > 200 or script.count("fromCharCode") > 20):
        f.append(make("OBFUSCATED", "page"))
    trusted = set(allowlist) | intel.ALL_BRAND_DOMAINS
    if (len(chain) > 1 and start_reg in trusted and final_reg and final_reg != start_reg
            and not any(domain_matches(_host(final), t) for t in trusted)
            and not _same_owner(start_reg, final_reg) and not intel.is_established(_host(final), final_reg)):
        f.append(make("OPEN_REDIRECT", "page", trusted=start_reg, final=final_reg))
    return f


def merge(*groups) -> list[Finding]:
    """Combine findings from all stages. A rule counts once, whichever stage found it."""
    out, seen = [], set()
    for group in groups:
        for x in group:
            key = "IP_LOGGER" if x.code in ("IP_LOGGER", "IP_LOGGER_HOP") else x.code
            if key not in seen:
                seen.add(key)
                out.append(x)
    return out


def list_findings(cap: dict, feeds) -> list[Finding]:
    """Every address the page went through, against the public phishing lists (feeds.py)."""
    if feeds is None:
        return []
    chain = [h["url"] for h in cap.get("redirects") or []]
    for u in dict.fromkeys([cap.get("url"), *chain, cap.get("final_url")]):
        if u and (source := feeds.check(u)):
            return [make("PHISH_LISTED", "page", source=source)]
    return []


def analyse(cap: dict, intel_db, allowlist=(), blocklist=(), extra=(), ignore=(), facts=None, feeds=None,
            identity=True) -> dict:
    """The full verdict for a finished capture: findings, scores and a privacy report.

    facts: what domaininfo.py learned about the website (its age); feeds: the phishing lists.
    ignore: rule codes to leave out (used only by tests whose local server is plain http)."""
    url_level = []
    for u in dict.fromkeys([cap.get("url"), cap.get("final_url")]):
        if u:
            try:
                url_level.extend(url_findings(parse(u), blocklist=blocklist))
            except UnsafeURL:
                pass
    allowed = any(domain_matches(_host(cap.get("final_url") or cap.get("url") or ""), d) for d in allowlist)
    id_level = identity_findings(cap, facts) if identity and not allowed else []
    findings = merge(list_findings(cap, feeds), url_level, page_findings(cap, intel_db, allowlist, blocklist),
                     id_level, extra)
    findings = [x for x in findings if x.code not in ignore]
    v = verdict(findings)
    events = cap.get("events") or []
    try:
        _, removed = clean_url(cap.get("url") or "")
    except ValueError:
        removed = []
    v["findings"] = findings
    v["privacy"] = {
        "trackers": tracker_hosts(cap, intel_db),
        "fingerprinting": sorted({e.get("k") for e in events if e.get("t") == "fp" and e.get("k")}),
        "ip_logger": any(x.code in ("IP_LOGGER", "IP_LOGGER_HOP") for x in findings),
        "webrtc": any(e.get("t") == "webrtc" for e in events),
        "params_removed": removed,
    }
    return v
