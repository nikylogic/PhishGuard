"""The website's pages are generated (scripts/build_site_pages.py) and committed.

These tests fail when someone edits a source page or an engine rule without rebuilding, and
when a page links to another page or file that does not exist.
"""
import re
import sys
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import urljoin, urlsplit

ROOT = Path(__file__).resolve().parents[1]
SITE = ROOT / "site"
sys.path.insert(0, str(ROOT / "scripts"))
import build_site_pages  # noqa: E402

# Served next to the site by the Website workflow, not stored in site/.
GENERATED = ("images/", "data/")


def test_committed_pages_are_up_to_date(tmp_path):
    fresh = build_site_pages.build(tmp_path)
    stale = []
    for f in fresh:
        rel = f.relative_to(tmp_path)
        committed = SITE / rel
        if not committed.exists() or committed.read_text(encoding="utf-8") != f.read_text(encoding="utf-8"):
            stale.append(str(rel))
    assert not stale, f"run: python scripts/build_site_pages.py (out of date: {stale})"


class Links(HTMLParser):
    def __init__(self):
        super().__init__()
        self.refs, self.ids = [], set()

    def handle_starttag(self, tag, attrs):
        a = dict(attrs)
        if "id" in a:
            self.ids.add(a["id"])
        for key in ("href", "src"):
            if key in a and a[key]:
                self.refs.append(a[key])


def _parse(path: Path) -> Links:
    p = Links()
    p.feed(path.read_text(encoding="utf-8"))
    return p


def test_internal_links_resolve():
    pages = [p for p in SITE.rglob("*.html") if "_src" not in p.parts]
    assert len(pages) >= 9
    ids = {p.resolve(): _parse(p).ids for p in pages}
    broken = []
    for page in pages:
        base = "http://site/" + page.relative_to(SITE).as_posix()
        for ref in _parse(page).refs:
            if ref.startswith(("http:", "https:", "mailto:", "data:")) or ref.startswith("#check"):
                continue
            u = urlsplit(urljoin(base, ref))
            rel = u.path.lstrip("/")
            if rel.startswith(GENERATED):
                continue
            target = (SITE / rel)
            if rel == "" or rel.endswith("/"):
                target = target / "index.html"
            if not target.exists():
                broken.append(f"{page.name}: {ref}")
            elif u.fragment and target.suffix == ".html" and u.fragment not in ids.get(target.resolve(), set()):
                broken.append(f"{page.name}: {ref} (no #{u.fragment})")
    assert not broken, broken


def test_every_page_has_its_own_title_description_and_canonical():
    seen_titles, seen_desc = set(), set()
    for page in SITE.rglob("*.html"):
        if "_src" in page.parts:
            continue
        html = page.read_text(encoding="utf-8")
        title = re.search(r"<title>(.+?)</title>", html).group(1)
        desc = re.search(r'<meta name="description" content="([^"]+)"', html).group(1)
        assert re.search(r'<link rel="canonical" href="https://nikylogic\.github\.io/PhishGuard/', html), page
        assert "{{" not in html, f"{page}: unfilled placeholder"
        assert 20 <= len(title) <= 70, (page.name, len(title), title)
        assert 70 <= len(desc) <= 165, (page.name, len(desc))
        assert title not in seen_titles and desc not in seen_desc, page
        seen_titles.add(title)
        seen_desc.add(desc)


def test_docs_list_every_engine_rule():
    from phishguard import pagerules
    html = (SITE / "docs" / "detection.html").read_text(encoding="utf-8")
    missing = [code for code in pagerules.RULES if f"<code>{code}</code>" not in html]
    assert not missing, missing
