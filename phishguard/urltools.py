"""Small, pure helpers for reading URLs safely.

Nothing here touches the network. Domain parsing uses tldextract's bundled
copy of the Public Suffix List, so it works offline and never fetches.
"""
import ipaddress
import re
import unicodedata
from dataclasses import dataclass
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import tldextract

# bank.in and fin.in: the RBI's verified zones for Indian banks and finance companies (2025). The
# bundled public-suffix snapshot predates them, so without this every bank would be "bank.in".
EXTRA_SUFFIXES = ("bank.in", "fin.in")
_extract = tldextract.TLDExtract(suffix_list_urls=(), cache_dir=None, extra_suffixes=EXTRA_SUFFIXES)

MAX_URL_LENGTH = 4096
ALLOWED_SCHEMES = {"http", "https"}


class UnsafeURL(ValueError):
    """Raised for anything that is not a plain http(s) link we are willing to inspect."""


@dataclass(frozen=True)
class ParsedURL:
    url: str            # normalised URL
    scheme: str
    host: str           # lower-case, ASCII (punycode) form
    host_unicode: str   # what a person would see
    port: int | None
    path: str
    query: str
    has_userinfo: bool
    subdomain: str
    domain_name: str    # "paypal" in login.paypal.co.uk
    suffix: str         # "co.uk"
    registrable: str    # "paypal.co.uk", or the IP / host when there is no suffix
    is_ip: bool


def browser_slashes(s: str) -> str:
    """Read backslashes the way browsers do: before the ? or #, a "\\" in a web link is a "/".

    Python's urlsplit keeps "\\" as an ordinary character, so for https://evil.example\\@bank.com/
    it reports the host bank.com, while Chrome and Edge open evil.example. PhishGuard must judge
    the site the browser will really open (found in the Phase 9 security self-test)."""
    cut = min((i for i in (s.find("?"), s.find("#")) if i >= 0), default=len(s))
    return s[:cut].replace("\\", "/") + s[cut:]


def normalise(raw: str) -> str:
    """Clean what a user pasted or Windows handed us, and refuse non-web schemes."""
    if raw is None:
        raise UnsafeURL("empty link")
    s = browser_slashes(raw.strip().strip("<>\"'").strip())
    if not s:
        raise UnsafeURL("empty link")
    if len(s) > MAX_URL_LENGTH:
        raise UnsafeURL("link is too long")
    if any(ord(c) < 32 for c in s):
        raise UnsafeURL("link contains control characters")
    m = re.match(r"^([a-zA-Z][a-zA-Z0-9+.\-]*):", s)
    if m and m.group(1).lower() not in ALLOWED_SCHEMES:
        # "localhost:8080" also matches this pattern, but a host:port without a
        # scheme is rare from Windows; we only accept explicit web links.
        raise UnsafeURL(f"'{m.group(1).lower()}:' links are not web pages and are never opened")
    if not m:
        if s.startswith("//"):
            s = "https:" + s
        else:
            s = "https://" + s
    parts = urlsplit(s)
    if parts.scheme.lower() not in ALLOWED_SCHEMES:
        raise UnsafeURL("only http and https links are inspected")
    if not parts.hostname:
        raise UnsafeURL("link has no website address")
    netloc = parts.netloc
    # Lower-case the host part but keep any user:pass@ prefix as written.
    if "@" in netloc:
        userinfo, hostport = netloc.rsplit("@", 1)
        netloc = f"{userinfo}@{hostport.lower()}"
    else:
        netloc = netloc.lower()
    path = parts.path or "/"
    return urlunsplit((parts.scheme.lower(), netloc, path, parts.query, parts.fragment))


def _numeric_ip(host: str) -> str | None:
    """Browsers accept 3232235777 or 0xC0A80001 as IP addresses. Return dotted form."""
    try:
        if re.fullmatch(r"0x[0-9a-f]+", host):
            n = int(host, 16)
        elif re.fullmatch(r"\d+", host):
            n = int(host)
        else:
            return None
        if 0 <= n <= 0xFFFFFFFF:
            return str(ipaddress.IPv4Address(n))
    except ValueError:
        return None
    return None


def host_as_ip(host: str):
    """Return an ip_address object if the host is an IP in any notation, else None."""
    h = host.strip("[]")
    try:
        return ipaddress.ip_address(h)
    except ValueError:
        pass
    dotted = _numeric_ip(h)
    if dotted:
        return ipaddress.ip_address(dotted)
    return None


def is_private_ip(ip) -> bool:
    """True for anything that is not a normal public internet address."""
    if isinstance(ip, str):
        ip = ipaddress.ip_address(ip)
    if ip.version == 6 and ip.ipv4_mapped:
        ip = ip.ipv4_mapped
    return (ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast
            or ip.is_reserved or ip.is_unspecified
            or (ip.version == 4 and ip in ipaddress.ip_network("100.64.0.0/10")))


def to_unicode_host(host: str) -> str:
    labels = []
    for label in host.split("."):
        if label.startswith("xn--"):
            try:
                labels.append(label.encode("ascii").decode("idna"))
                continue
            except UnicodeError:
                pass
        labels.append(label)
    return ".".join(labels)


def to_ascii_host(host: str) -> str:
    try:
        return host.encode("idna").decode("ascii")
    except UnicodeError:
        return host


def parse(url: str) -> ParsedURL:
    url = normalise(url)
    p = urlsplit(url)
    raw_host = (p.hostname or "").rstrip(".")
    host = to_ascii_host(raw_host)
    host_u = to_unicode_host(host)
    ip = host_as_ip(raw_host)
    try:
        port = p.port
    except ValueError as exc:
        raise UnsafeURL("link has an invalid port") from exc
    if ip is not None:
        sub, name, suffix, reg = "", str(ip), "", str(ip)
    else:
        ext = _extract(host)
        sub, name, suffix = ext.subdomain, ext.domain, ext.suffix
        reg = f"{name}.{suffix}" if suffix and name else host
    return ParsedURL(
        url=url, scheme=p.scheme, host=host, host_unicode=host_u, port=port,
        path=p.path, query=p.query, has_userinfo="@" in p.netloc,
        subdomain=sub, domain_name=name, suffix=suffix, registrable=reg, is_ip=ip is not None,
    )


def registrable_domain(url_or_host: str) -> str:
    if "://" in url_or_host:
        return parse(url_or_host).registrable
    ip = host_as_ip(url_or_host)
    if ip is not None:
        return str(ip)
    ext = _extract(to_ascii_host(url_or_host.lower().rstrip(".")))
    return f"{ext.domain}.{ext.suffix}" if ext.suffix and ext.domain else url_or_host.lower()


def domain_matches(host: str, listed: str) -> bool:
    """True when host is the listed domain or one of its subdomains."""
    host, listed = host.lower().rstrip("."), listed.lower().rstrip(".")
    return host == listed or host.endswith("." + listed)


# --- tracking parameters -------------------------------------------------------

TRACKING_PARAMS = {
    "fbclid", "gclid", "dclid", "gbraid", "wbraid", "msclkid", "yclid", "igshid",
    "mc_cid", "mc_eid", "_hsenc", "_hsmkt", "mkt_tok", "twclid", "ttclid", "li_fat_id",
    "oly_anon_id", "oly_enc_id", "vero_id", "rb_clickid", "s_cid", "epik",
}


def is_tracking_param(name: str) -> bool:
    n = name.lower()
    return n.startswith("utm_") or n in TRACKING_PARAMS


def clean_url(url: str) -> tuple[str, list[str]]:
    """Remove tracking parameters. Returns (clean_url, removed_names)."""
    p = urlsplit(url)
    pairs = parse_qsl(p.query, keep_blank_values=True)
    kept = [(k, v) for k, v in pairs if not is_tracking_param(k)]
    removed = [k for k, _ in pairs if is_tracking_param(k)]
    query = urlencode(kept, doseq=True) if removed else p.query
    return urlunsplit((p.scheme, p.netloc, p.path, query, p.fragment)), removed


# --- lookalike helpers ----------------------------------------------------------

# Letters from other alphabets that look like Latin letters.
CONFUSABLES = str.maketrans({
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x", "у": "y", "і": "i",
    "ј": "j", "ѕ": "s", "һ": "h", "ԁ": "d", "ɡ": "g", "ո": "n", "ս": "u", "ν": "v",
    "ο": "o", "α": "a", "ρ": "p", "τ": "t", "κ": "k", "ı": "i", "ӏ": "l",
})
# Digits and pairs people use to fake letters.
LEET = [("rn", "m"), ("vv", "w"), ("0", "o"), ("1", "l"), ("3", "e"), ("4", "a"),
        ("5", "s"), ("7", "t"), ("8", "b"), ("9", "g"), ("$", "s"), ("@", "a")]


def deconfuse(text: str) -> str:
    t = unicodedata.normalize("NFKC", text.lower()).translate(CONFUSABLES)
    for a, b in LEET:
        t = t.replace(a, b)
    return t


def scripts_in(label: str) -> set[str]:
    """Which alphabets the letters of a label come from (LATIN, CYRILLIC, GREEK, ...)."""
    out = set()
    for ch in label:
        if ch.isalpha():
            try:
                out.add(unicodedata.name(ch).split(" ")[0])
            except ValueError:
                out.add("UNKNOWN")
    return out


def edit_distance(a: str, b: str) -> int:
    if a == b:
        return 0
    if len(a) < len(b):
        a, b = b, a
    prev = list(range(len(b) + 1))
    for i, ca in enumerate(a, 1):
        cur = [i]
        for j, cb in enumerate(b, 1):
            cur.append(min(prev[j] + 1, cur[j - 1] + 1, prev[j - 1] + (ca != cb)))
        prev = cur
    return prev[-1]
