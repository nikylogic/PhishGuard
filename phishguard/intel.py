"""Built-in threat knowledge: brands, shorteners, risky TLDs and IP-logger domains.

These lists are deliberately small and readable. Larger lists (trackers, miners,
malware URLs and hashes) are loaded from files in phishguard/data/ in Phase 3.
"""

import json as _json
from pathlib import Path as _P

# --- brands (phishguard/data/brands.json) -----------------------------------------------
# Each brand: its real registrable domains, how it appears in addresses (tokens) and how a page
# names it (words). The URL rules work per token; the identity check (identity.py) per brand.
_BRAND_FILE = _P(__file__).with_name("data") / "brands.json"
BRAND_INFO: dict[str, dict] = {
    k: {"key": k, "name": v["name"], "domains": set(v["domains"]), "tokens": list(v.get("tokens", [])),
        "words": list(v.get("words", [])), "strict": bool(v.get("strict")), "fuzzy": v.get("fuzzy", True),
        "favicons": set(v.get("favicons", []))}
    for k, v in _json.loads(_BRAND_FILE.read_text(encoding="utf-8"))["brands"].items()
}

# Token -> the real domains of the brand(s) it stands for (used by the URL rules).
BRANDS: dict[str, set[str]] = {}
BRAND_DISPLAY: dict[str, str] = {}
NO_FUZZ: set[str] = set()           # tokens that are also ordinary words: exact matches only
for _b in BRAND_INFO.values():
    for _t in _b["tokens"]:
        BRANDS.setdefault(_t, set()).update(_b["domains"])
        BRAND_DISPLAY.setdefault(_t, _b["name"])
        # An ordinary word ("apple", "steam", "booking") is matched exactly, never fuzzily or
        # inside longer names; distinctive tokens of the same brand ("appleid") still are.
        if (_b["strict"] and _t in [w for w in _b["words"] if " " not in w]) or not _b["fuzzy"]:
            NO_FUZZ.add(_t)
ALL_BRAND_DOMAINS = set().union(*BRANDS.values())
# Favicon fingerprint -> brand. A fingerprint two brands share is a generic icon (a hosting or
# framework default), so it identifies no one and is left out.
_fav_count: dict[str, int] = {}
for _b in BRAND_INFO.values():
    for _h in _b["favicons"]:
        _fav_count[_h] = _fav_count.get(_h, 0) + 1
FAVICON_BRANDS = {h: b["key"] for b in BRAND_INFO.values() for h in b["favicons"] if _fav_count[h] == 1}


def brand_name(brand: str) -> str:
    if brand in BRAND_INFO:
        return BRAND_INFO[brand]["name"]
    return BRAND_DISPLAY.get(brand, brand.capitalize())


# --- popular domains, free hosting, restricted zones -------------------------------------

def _lines(name: str) -> set[str]:
    path = _P(__file__).with_name("data") / name
    if not path.exists():
        return set()
    return {ln.strip().lower() for ln in path.read_text(encoding="utf-8").splitlines()
            if ln.strip() and not ln.startswith("#")}


# Tranco top 10,000 registrable domains. Used only to keep a shared phishing list or a look-alike
# rule from condemning a whole popular domain; never as proof that a page is safe (an NDSS 2026
# study found top lists cover a minority of false alarms, and expired listed domains get reused).
POPULAR = _lines("popular.txt")

# Platforms where anyone can publish a site under the platform's own name. Most phishing now lives
# here (vercel.app, pages.dev, blogspot ...), so these never count as "popular" or "established".
FREE_HOSTS = {
    "vercel.app", "pages.dev", "workers.dev", "netlify.app", "github.io", "gitlab.io", "blogspot.com",
    "weebly.com", "weeblysite.com", "wixsite.com", "wix.com", "square.site", "cpanel.site", "typedream.app",
    "gitbook.io", "firebaseapp.com", "web.app", "glitch.me", "replit.app", "repl.co", "replit.dev",
    "000webhostapp.com", "duckdns.org", "ngrok-free.app", "ngrok.io", "ngrok.app", "r2.dev", "onrender.com",
    "herokuapp.com", "azurewebsites.net", "amplifyapp.com", "surge.sh", "framer.website", "framer.app",
    "webflow.io", "wordpress.com", "godaddysites.com", "mystrikingly.com", "jimdosite.com", "carrd.co",
    "notion.site", "appspot.com", "firebasestorage.app", "translate.goog", "ipfs.io", "dweb.link",
    "fleek.co", "on-fleek.app", "4everland.app", "backblazeb2.com", "b-cdn.net", "myshopify.com",
    "bubbleapps.io", "softr.app", "glide.page", "webcindario.com", "yolasite.com", "site123.me",
    "sharepoint.com", "my.canva.site", "canva.site", "start.page", "linktr.ee", "lovable.app",
    "bolt.host", "netlify.com", "codesandbox.io", "csb.app", "stackblitz.io", "deno.dev", "fly.dev",
    "railway.app", "up.railway.app", "koyeb.app", "pythonanywhere.com", "000webhost.com", "byethost.com",
    "infinityfreeapp.com", "rf.gd", "epizy.com", "freevar.com", "unaux.com", "wuaze.com", "kesug.com",
}
# Hosts on big domains where anyone can publish under one shared host name.
FREE_HOST_NAMES = {
    "sites.google.com", "docs.google.com", "forms.gle", "drive.google.com", "storage.googleapis.com",
    "firebasestorage.googleapis.com", "script.google.com", "forms.office.com", "s3.amazonaws.com",
    "notion.so", "www.notion.so",
    "form.jotform.com", "typeform.com", "forms.zohopublic.in", "pub.dev",
}
# Zones only verified organisations can register (Indian banks moved to .bank.in in 2025).
RESTRICTED = ("gov.in", "nic.in", "bank.in", "ac.in", "edu.in", "res.in", "mil.in", "gov", "mil", "edu",
              "gov.uk", "ac.uk", "gov.au", "edu.au", "gc.ca", "bank", "sbi", "hsbc", "google", "microsoft",
              "apple", "amazon", "barclays", "citi", "chase", "icici", "hdfc", "hdfcbank", "axisbank")


def is_free_host(host: str, reg: str) -> bool:
    host = (host or "").lower().removeprefix("www.")
    return reg in FREE_HOSTS or host in FREE_HOST_NAMES or any(host.endswith("." + h) for h in FREE_HOSTS)


def is_restricted(reg: str) -> bool:
    return any(reg == z or reg.endswith("." + z) for z in RESTRICTED)


def is_established(host: str, reg: str) -> bool:
    """A popular site under its own name (not a page on a free hosting platform)."""
    return reg in POPULAR and not is_free_host(host, reg)


URL_SHORTENERS = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "is.gd", "ow.ly", "cutt.ly", "rebrand.ly",
    "buff.ly", "shorturl.at", "rb.gy", "t.ly", "s.id", "tiny.cc", "bit.do", "lnkd.in",
    "shorte.st", "adf.ly", "v.gd", "qr.ae", "tr.im", "bl.ink", "short.io",
}

# Top-level domains with a high share of abuse in public reports. Configurable.
RISKY_TLDS = {
    "zip", "mov", "top", "xyz", "click", "country", "gq", "tk", "ml", "cf", "ga", "work",
    "rest", "cam", "icu", "quest", "sbs", "cfd", "lol", "monster", "buzz", "support",
    "loan", "win", "bid", "kim", "men", "date", "racing", "review", "stream", "download",
}

# Services whose main purpose is recording the IP address of whoever opens a link.
# Community-compiled; includes the decoy domains Grabify offers.
IP_LOGGERS = {
    "grabify.link", "iplogger.org", "iplogger.com", "iplogger.ru", "iplogger.co",
    "iplogger.info", "2no.co", "yip.su", "iplis.ru", "blasze.com", "ps3cfw.com",
    "bmwforum.co", "leancoding.co", "spottyfly.com", "stopify.co", "joinmy.site",
    "curiouscat.club", "catsnthings.fun", "catsnthing.com", "crabrave.pw",
    "quickmessage.us", "screenshare.pics", "myprivate.pics", "noodshare.pics",
    "lovebird.guru", "trulove.guru", "dateing.club", "otherhalf.life", "shrekis.life",
    "datasig.io", "datauth.io", "headshot.monster", "gaming-at-my.best",
    "progaming.monster", "yourmy.monster", "imageshare.best", "screenshot.best",
    "gamingfun.me", "canarytokens.com",
}

# Words phishing links use to look urgent or official.
LURE_WORDS = {
    "login", "signin", "logon", "verify", "verification", "update", "secure",
    "account", "banking", "confirm", "password", "wallet", "kyc", "suspend", "suspended",
    "unlock", "billing", "invoice", "refund", "reward", "prize", "otp", "recover",
}


# --- lists loaded from files (and from the database's intel_lists table) ------------

import re as _re
from pathlib import Path as _Path

DATA_DIR = _Path(__file__).with_name("data")
FILES = {"tracker": "trackers.txt", "miner": "miners.txt",
         "malware_url": "malware_urls.txt", "bad_hash": "bad_hashes.txt"}


def _read_list(path: _Path) -> set[str]:
    out = set()
    if path.exists():
        for line in path.read_text(encoding="utf-8").splitlines():
            line = line.split("#", 1)[0].strip().lower()
            if line:
                out.add(line)
    return out


class Intel:
    """All threat lists in memory, as sets, so every lookup is O(1)."""

    def __init__(self, tracker=(), miner=(), malware_url=(), bad_hash=(), ip_logger=None):
        self.sets = {
            "tracker": set(tracker), "miner": set(miner),
            "malware_url": set(malware_url), "bad_hash": {h.lower() for h in bad_hash},
            "ip_logger": set(IP_LOGGERS if ip_logger is None else ip_logger),
        }

    @classmethod
    def load(cls, data_dir=DATA_DIR, extra_rows=()):
        """Load the bundled files, plus (kind, value) rows from the database."""
        lists = {k: _read_list(_Path(data_dir) / f) for k, f in FILES.items()}
        intel = cls(**lists)
        for kind, value in extra_rows:
            if kind in intel.sets:
                intel.sets[kind].add(value.lower())
        return intel

    def count(self, kind):
        return len(self.sets[kind])

    def host_in(self, kind: str, host: str) -> str | None:
        """Return the listed domain if host is it or one of its sub-domains."""
        s = self.sets[kind]
        labels = host.lower().rstrip(".").split(".")
        for i in range(len(labels) - 1):
            cand = ".".join(labels[i:])
            if cand in s:
                return cand
        return None

    def url_listed(self, url: str) -> bool:
        """Malware list entries may be full URLs or bare hosts."""
        s = self.sets["malware_url"]
        if not s:
            return False
        u = url.lower()
        if u in s or u.rstrip("/") in s:
            return True
        host = _re.sub(r"^[a-z]+://", "", u).split("/", 1)[0].split(":", 1)[0]
        return self.host_in("malware_url", host) is not None
