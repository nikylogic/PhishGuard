"""Record the SHA-256 of every brand's real favicon(s) in phishguard/data/brands.json.

Phishing kits usually copy the brand's favicon file byte for byte, so the identity check
(identity.py) can recognise "this page wears HDFC's icon" from the hash alone. Run again when
brands change their icons:

    .venv\\Scripts\\python scripts\\brand_favicons.py
"""
import hashlib
import json
import re
import sys
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parent.parent
FILE = ROOT / "phishguard" / "data" / "brands.json"
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) "
      "Chrome/130.0.0.0 Safari/537.36")


class Icons(HTMLParser):
    def __init__(self):
        super().__init__()
        self.hrefs = []

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if tag == "link" and "icon" in (a.get("rel") or "").lower() and a.get("href"):
            self.hrefs.append(a["href"])


def get(url, limit):
    req = urllib.request.Request(url, headers={"User-Agent": UA, "Accept": "*/*"})
    with urllib.request.urlopen(req, timeout=15) as r:
        return r.geturl(), r.read(limit)


def icons_of(domain):
    hashes, notes = set(), []
    for start in (f"https://www.{domain}/", f"https://{domain}/"):
        try:
            final, html = get(start, 600_000)
        except Exception as e:  # noqa: BLE001
            notes.append(f"{start}: {type(e).__name__}")
            continue
        p = Icons()
        try:
            p.feed(html.decode("utf-8", "replace"))
        except Exception:  # noqa: BLE001
            pass
        for href in dict.fromkeys(p.hrefs + ["/favicon.ico"]):
            if href.startswith("data:"):
                continue
            url = urljoin(final, href)
            if urlsplit(url).scheme != "https":
                continue
            try:
                _, data = get(url, 300_001)
            except Exception:  # noqa: BLE001
                continue
            if 0 < len(data) <= 300_000 and not re.match(rb"\s*<", data[:50]):
                hashes.add(hashlib.sha256(data).hexdigest())
        if hashes:
            break
    return hashes, notes


def main():
    doc = json.loads(FILE.read_text(encoding="utf-8"))
    brands = doc["brands"]
    jobs = {k: [d for d in b["domains"] if d.count(".") <= 2][:2] for k, b in brands.items()}

    def one(item):
        k, domains = item
        found = set()
        for d in domains:
            h, _ = icons_of(d)
            found |= h
        return k, found

    with ThreadPoolExecutor(8) as ex:
        results = dict(ex.map(one, jobs.items()))
    got = 0
    for k, hs in results.items():
        if hs:
            brands[k]["favicons"] = sorted(hs)
            got += 1
        print(f"{k:14} {len(hs)} icon(s)")
    # One brand per line, so the file stays easy to read and review.
    rows = [f'    {json.dumps(k)}: {json.dumps(v, ensure_ascii=False)}' for k, v in brands.items()]
    FILE.write_text('{\n  "_about": ' + json.dumps(doc["_about"], ensure_ascii=False) + ',\n  "brands": {\n'
                    + ",\n".join(rows) + "\n  }\n}\n", encoding="utf-8")
    print(f"{got}/{len(brands)} brands have favicon fingerprints", file=sys.stderr)


if __name__ == "__main__":
    main()
