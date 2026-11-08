"""Export what the website's link checker needs, straight from the engine.

    python scripts/build_site_data.py            # rules, brands and lists, plus fresh phishing lists
    python scripts/build_site_data.py --no-feeds # skip downloading the phishing lists

Writes site/data/ (not committed; the Website workflow builds it on every deploy and every 6 hours):

  engine.json   the address rules, brands, lists and public-suffix rules (phishguard/rules.py,
                intel.py, urltools.py), so the browser runs the same checks as the app
  feed/xx.json  the public phishing lists, as 64-bit SHA-256 prefixes split into 256 shards by the
                first byte. The browser fetches only the shard for the address it checks, so the
                address itself never leaves the visitor's browser, and the site does not publish
                a readable list of live phishing links.
  meta.json     when the lists were built and how many entries each has

OpenPhish is left out: its free feed is for non-commercial use and may not be redistributed.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishguard import feeds, intel, rules, urltools  # noqa: E402

OUT = ROOT / "site" / "data"
SHARE_FEEDS = ("phishunt.io", "Phishing.Database")


def engine() -> dict:
    ext = urltools._extract._get_tld_extractor()
    suffixes = sorted(set(ext.tlds_excl_private) | set(urltools.EXTRA_SUFFIXES))
    page_rules = {k: v for k, v in __import__("phishguard.pagerules", fromlist=["RULES"]).RULES.items()
                  if k in ("PHISH_LISTED", "DOMAIN_NEW")}
    return {
        "rules": {k: list(v) for k, v in {**rules.RULES, **page_rules}.items()},
        "supporting": sorted(rules.SUPPORTING),
        "threatTracking": sorted(rules.THREAT_TRACKING),
        # token -> [real domains]; display names; exact-match-only tokens. Order matters: the
        # engine stops at the first brand that matches, so keep intel.BRANDS order.
        "brands": [[t, sorted(d)] for t, d in intel.BRANDS.items()],
        "brandNames": {t: intel.brand_name(t) for t in intel.BRANDS},
        "noFuzz": sorted(intel.NO_FUZZ),
        "popular": sorted(intel.POPULAR),
        "freeHosts": sorted(intel.FREE_HOSTS),
        "freeHostNames": sorted(intel.FREE_HOST_NAMES),
        "restricted": list(intel.RESTRICTED),
        "shorteners": sorted(intel.URL_SHORTENERS),
        "riskyTlds": sorted(intel.RISKY_TLDS),
        "ipLoggers": sorted(intel.IP_LOGGERS),
        "lureWords": sorted(intel.LURE_WORDS),
        "trackingParams": sorted(urltools.TRACKING_PARAMS),
        "confusables": {chr(k): v for k, v in urltools.CONFUSABLES.items()},
        "leet": urltools.LEET,
        "suffixes": suffixes,
    }


def prefix(kind: str, value: str) -> str:
    return hashlib.sha256(f"{kind}:{value}".encode()).hexdigest()[:16]


def build_feeds() -> dict:
    sources = {k: v for k, v in feeds.SOURCES.items() if k in SHARE_FEEDS}
    with tempfile.TemporaryDirectory() as tmp:
        f = feeds.Feeds(Path(tmp), sources=sources)
        f.refresh(force=True)
        status = f.status()
        names = list(sources)
        shards: dict[str, dict[str, int]] = {f"{i:02x}": {} for i in range(256)}
        for kind, table in (("h", f.hosts), ("u", f.urls)):
            for value, source in table.items():
                p = prefix(kind, value)
                shards[p[:2]].setdefault(p, names.index(source))
    folder = OUT / "feed"
    folder.mkdir(parents=True, exist_ok=True)
    for name, entries in shards.items():
        (folder / f"{name}.json").write_text(json.dumps(entries, separators=(",", ":")), encoding="utf-8")
    return {"sources": names, "status": status["sources"], "entries": sum(map(len, shards.values()))}


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--no-feeds", action="store_true")
    args = ap.parse_args()
    OUT.mkdir(parents=True, exist_ok=True)
    (OUT / "engine.json").write_text(json.dumps(engine(), ensure_ascii=False, separators=(",", ":")),
                                     encoding="utf-8")
    meta = {"built": int(time.time())}
    if not args.no_feeds:
        meta["feeds"] = build_feeds()
        if meta["feeds"]["entries"] < 1000:
            sys.exit("the phishing lists came back nearly empty; not publishing them")
    (OUT / "meta.json").write_text(json.dumps(meta), encoding="utf-8")
    print(json.dumps(meta, indent=1))


if __name__ == "__main__":
    main()
