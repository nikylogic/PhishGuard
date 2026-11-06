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
