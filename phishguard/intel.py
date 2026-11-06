"""Built-in threat knowledge: brands, shorteners, risky TLDs and IP-logger domains.

These lists are deliberately small and readable. Larger lists (trackers, miners,
malware URLs and hashes) are loaded from files in phishguard/data/ in Phase 3.
"""

# Brand name -> its real registrable domains. Used to spot lookalikes.
BRANDS = {
    "paypal": {"paypal.com", "paypal.me"},
    "google": {"google.com", "google.co.in", "youtube.com", "gmail.com", "goo.gl", "g.co"},
    "gmail": {"gmail.com", "google.com"},
    "youtube": {"youtube.com", "youtu.be"},
    "microsoft": {"microsoft.com", "live.com", "office.com", "microsoftonline.com", "outlook.com"},
    "outlook": {"outlook.com", "live.com", "office.com", "microsoft.com"},
    "office": {"office.com", "microsoft.com", "microsoftonline.com"},
    "apple": {"apple.com", "icloud.com"},
    "icloud": {"icloud.com", "apple.com"},
    "amazon": {"amazon.com", "amazon.in", "amazon.co.uk", "amzn.to", "aws.amazon.com"},
    "facebook": {"facebook.com", "fb.com", "fb.me"},
    "instagram": {"instagram.com"},
    "whatsapp": {"whatsapp.com", "wa.me"},
    "netflix": {"netflix.com"},
    "linkedin": {"linkedin.com", "lnkd.in"},
    "dropbox": {"dropbox.com"},
    "github": {"github.com", "github.io"},
    "yahoo": {"yahoo.com"},
    "flipkart": {"flipkart.com"},
    "paytm": {"paytm.com"},
    "phonepe": {"phonepe.com"},
    "hdfcbank": {"hdfcbank.com"},
    "icicibank": {"icicibank.com"},
    "axisbank": {"axisbank.com"},
    "onlinesbi": {"onlinesbi.sbi", "sbi.co.in"},
    "irctc": {"irctc.co.in"},
    "incometax": {"incometax.gov.in"},
    "binance": {"binance.com"},
    "coinbase": {"coinbase.com"},
    "steam": {"steampowered.com", "steamcommunity.com"},
    "discord": {"discord.com", "discord.gg"},
    "telegram": {"telegram.org", "t.me"},
    "dhl": {"dhl.com"},
    "fedex": {"fedex.com"},
}
ALL_BRAND_DOMAINS = set().union(*BRANDS.values())

# How each brand is written for people.
BRAND_DISPLAY = {
    "paypal": "PayPal", "youtube": "YouTube", "icloud": "iCloud", "linkedin": "LinkedIn",
    "github": "GitHub", "whatsapp": "WhatsApp", "phonepe": "PhonePe", "hdfcbank": "HDFC Bank",
    "icicibank": "ICICI Bank", "axisbank": "Axis Bank", "onlinesbi": "SBI", "irctc": "IRCTC",
    "incometax": "Income Tax India", "dhl": "DHL", "fedex": "FedEx",
}


def brand_name(brand: str) -> str:
    return BRAND_DISPLAY.get(brand, brand.capitalize())

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
