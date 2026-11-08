"""Build the website's pages from site/_src/pages/ into site/.

    python scripts/build_site_pages.py

Each source page starts with a comment holding its settings:

    <!--page {"path": "docs/privacy.html", "title": "...", "description": "...", "kind": "doc",
               "nav": "Privacy", "order": 5} -->

kind is "home", "doc" or "guide". Docs get the sidebar, a table of contents and next/previous
links. Facts that live in the engine are filled in at build time, so the site cannot drift from
the code:

    {{root}}             relative path back to the site root ("", "../")
    {{version}}          phishguard.__version__
    {{brand_count}}      brands in phishguard/data/brands.json
    {{favicon_count}}    brand favicon fingerprints
    {{rules:url}}        every address rule, its weight and its message (rules.RULES)
    {{rules:page}}       every page rule (pagerules.RULES)
    {{brands}}           every brand and its real domains

The output is committed; tests/test_site_pages.py fails when it is out of date.
"""
from __future__ import annotations

import html
import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from phishguard import __version__, intel, pagerules, rules  # noqa: E402

SITE = ROOT / "site"
SRC = SITE / "_src" / "pages"
BASE = "https://nikylogic.github.io/PhishGuard/"
REPO = "https://github.com/nikylogic/PhishGuard"
DOWNLOAD = REPO + "/releases/latest"

CATEGORY = {"phishing": "Phishing", "malware": "Malware", "tracking": "Tracking", "abuse": "Tricks"}


# --- generated facts -------------------------------------------------------------------------

def _message(m: str) -> str:
    """The rule's message with its {placeholders} shown as readable blanks."""
    return re.sub(r"\{(\w+)\}", lambda x: f"<var>{x.group(1)}</var>", html.escape(m))


def rules_table(table: dict) -> str:
    rows = []
    for cat in CATEGORY:
        items = [(code, w, msg) for code, (c, w, msg) in table.items() if c == cat]
        if not items:
            continue
        rows.append(f'<tr class="group"><th colspan="3">{CATEGORY[cat]}</th></tr>')
        for code, w, msg in sorted(items, key=lambda x: -x[1]):
            role = ("supporting" if code in rules.SUPPORTING else
                    "privacy" if cat == "tracking" and code not in rules.THREAT_TRACKING else "")
            tag = {"supporting": ' <span class="chip">adds to others</span>',
                   "privacy": ' <span class="chip">shown, not scored</span>'}.get(role, "")
            rows.append(f"<tr><td><code>{code}</code></td><td class=\"num\">{w}</td><td>{_message(msg)}{tag}</td></tr>")
    return ('<div class="table"><table><thead><tr><th>Rule</th><th class="num">Points</th>'
            '<th>What you are told</th></tr></thead><tbody>' + "".join(rows) + "</tbody></table></div>")


def brands_table() -> str:
    rows = []
    for b in sorted(intel.BRAND_INFO.values(), key=lambda b: b["name"].lower()):
        doms = ", ".join(sorted(b["domains"]))
        rows.append(f"<tr><td>{html.escape(b['name'])}</td><td><code>{html.escape(doms)}</code></td></tr>")
    return ('<div class="table tall"><table><thead><tr><th>Brand</th><th>Its real domains</th></tr></thead><tbody>'
            + "".join(rows) + "</tbody></table></div>")


def _address_codes() -> set[str]:
    """The rules rules.py itself defines. (pagerules.py adds its own to the same table on import.)"""
    import ast
    tree = ast.parse(Path(rules.__file__).read_text(encoding="utf-8"))
    for node in tree.body:
        if isinstance(node, ast.Assign) and any(getattr(t, "id", "") == "RULES" for t in node.targets):
            return {k.value for k in node.value.keys}
    raise SystemExit("RULES not found in rules.py")


def facts() -> dict:
    address = _address_codes()
    url_rules = {k: v for k, v in pagerules.RULES.items() if k in address}
    page_rules = {k: v for k, v in pagerules.RULES.items() if k not in address}
    return {
        "{{version}}": __version__,
        "{{brand_count}}": str(len(intel.BRAND_INFO)),
        "{{favicon_count}}": str(sum(len(b["favicons"]) for b in intel.BRAND_INFO.values())),
        "{{rules:url}}": rules_table(url_rules),
        "{{rules:page}}": rules_table(page_rules),
        "{{brands}}": brands_table(),
    }


# --- layout ----------------------------------------------------------------------------------

def slug(text: str) -> str:
    return re.sub(r"[^a-z0-9]+", "-", re.sub(r"<[^>]+>", "", text).lower()).strip("-")


def add_ids(body: str) -> tuple[str, list[tuple[str, str]]]:
    toc = []

    def fix(m):
        attrs, inner = m.group(1), m.group(2)
        if "id=" in attrs:
            sid = re.search(r'id="([^"]+)"', attrs).group(1)
        else:
            sid = slug(inner)
            attrs += f' id="{sid}"'
        toc.append((sid, re.sub(r"<[^>]+>", "", inner)))
        return f"<h2{attrs}>{inner}</h2>"

    return re.sub(r"<h2([^>]*)>(.*?)</h2>", fix, body), toc


def read_pages() -> list[dict]:
    pages = []
    for f in sorted(SRC.glob("*.html")):
        text = f.read_text(encoding="utf-8")
        m = re.match(r"\s*<!--page\s+(\{.*?\})\s*-->\s*", text, re.S)
        if not m:
            raise SystemExit(f"{f.name}: missing <!--page {{...}} --> header")
        meta = json.loads(m.group(1))
        meta["body"] = text[m.end():]
        pages.append(meta)
    return pages


# The app's own mark (web/src/components/logo.tsx, packaging/make_icon.py): keep them the same.
ICON = ('<svg class="mark" viewBox="0 0 32 32" aria-hidden="true"><rect width="32" height="32" rx="6.4" fill="#171717"/>'
        '<path d="M16 6.4 25.6 9.6V16L16 26.24 6.4 16V9.6Z" fill="none" stroke="#fff" stroke-width="2"/>'
        '<path d="M12.16 16 15.04 18.88 20.16 13.12" fill="none" stroke="#fff" stroke-width="2.3" '
        'stroke-linecap="round" stroke-linejoin="round"/></svg>')


def header(root: str, active: str) -> str:
    def link(href, label, key):
        cur = ' aria-current="page"' if key == active else ""
        return f'<a href="{href}"{cur}>{label}</a>'
    return f"""<header class="top">
  <div class="top-in">
    <a class="brand" href="{root}./">{ICON}<span>PhishGuard</span></a>
    <nav aria-label="Main">
      {link(root + "./", "Link checker", "home")}
      {link(root + "docs/", "Docs", "doc")}
      {link(root + "guides/spot-a-phishing-link.html", "Guide", "guide")}
      <a href="{REPO}">GitHub</a>
    </nav>
    <a class="pill" href="{DOWNLOAD}" data-dl>Download</a>
  </div>
</header>"""


def footer(root: str, docs: list[dict]) -> str:
    doc_links = "".join(f'<a href="{root}{d["path"].replace("index.html", "")}">{d["nav"]}</a>' for d in docs)
    return f"""<footer class="foot">
  <div class="foot-in">
    <div class="foot-brand">
      <a class="brand" href="{root}./">{ICON}<span>PhishGuard</span></a>
      <p>A link airlock for Windows. Every link from your apps opens in a hidden browser first.</p>
      <a class="go small" href="{DOWNLOAD}" data-dl>Download for Windows</a>
    </div>
    <nav aria-label="Docs"><h2>Docs</h2>{doc_links}</nav>
    <nav aria-label="Project"><h2>Project</h2>
      <a href="{root}./">Free link checker</a>
      <a href="{root}guides/spot-a-phishing-link.html">Spot a phishing link</a>
      <a href="{REPO}">Source code</a>
      <a href="{REPO}/releases">Releases</a>
      <a href="{REPO}/issues/new/choose">Report a miss</a>
      <a href="{REPO}/security">Security</a>
    </nav>
  </div>
  <p class="fine">Made by Nikhil P · Free for personal use under the
    <a href="{REPO}/blob/main/LICENSE">PolyForm Noncommercial License</a> · Version {__version__}</p>
</footer>"""


def head(page: dict, root: str, extra_ld: list[dict]) -> str:
    url = BASE + page["path"].replace("index.html", "")
    title = page["title"]
    desc = page["description"]
    image = BASE + page.get("image", "images/airlock-danger.png")
    crumbs = [{"@type": "ListItem", "position": 1, "name": "PhishGuard", "item": BASE}]
    if page["kind"] == "doc" and page["path"] != "docs/index.html":
        crumbs.append({"@type": "ListItem", "position": 2, "name": "Docs", "item": BASE + "docs/"})
    if page["kind"] != "home":
        crumbs.append({"@type": "ListItem", "position": len(crumbs) + 1, "name": page.get("nav", title), "item": url})
    ld = [*extra_ld]
    if page["kind"] != "home":
        ld.append({"@context": "https://schema.org", "@type": "BreadcrumbList", "itemListElement": crumbs})
        ld.append({"@context": "https://schema.org",
                   "@type": "Article" if page["kind"] == "guide" else "TechArticle",
                   "headline": page.get("h1", title), "description": desc, "url": url,
                   "author": {"@type": "Person", "name": "Nikhil P"}, "image": image,
                   "publisher": {"@type": "Organization", "name": "PhishGuard", "url": BASE}})
    lds = "\n".join(f'<script type="application/ld+json">{json.dumps(x, ensure_ascii=False)}</script>' for x in ld)
    e = html.escape
    return f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{e(title)}</title>
<meta name="description" content="{e(desc)}">
<link rel="canonical" href="{url}">
<meta name="theme-color" content="#f5f1e8" media="(prefers-color-scheme: light)">
<meta name="theme-color" content="#12110e" media="(prefers-color-scheme: dark)">
<meta property="og:type" content="{'website' if page['kind'] == 'home' else 'article'}">
<meta property="og:site_name" content="PhishGuard">
<meta property="og:title" content="{e(page.get('og_title', title))}">
<meta property="og:description" content="{e(desc)}">
<meta property="og:url" content="{url}">
<meta property="og:image" content="{image}">
<meta name="twitter:card" content="summary_large_image">
<link rel="icon" href="{root}favicon.svg" type="image/svg+xml">
<link rel="preload" href="{root}fonts/instrument-serif.woff2" as="font" type="font/woff2" crossorigin>
<link rel="preload" href="{root}fonts/plex-sans.woff2" as="font" type="font/woff2" crossorigin>
<link rel="stylesheet" href="{root}style.css">
{lds}
</head>"""


def render(page: dict, docs: list[dict], fill: dict) -> str:
    page = dict(page)
    for key in ("title", "description", "lead", "h1"):
        if key in page:
            for k, v in fill.items():
                if k.startswith("{{rules") or k == "{{brands}}":
                    continue
                page[key] = page[key].replace(k, v)
    depth = page["path"].count("/")
    root = "../" * depth
    body = page["body"].replace("{{root}}", root)
    for k, v in fill.items():
        body = body.replace(k, v)
    extra_ld = page.get("ld", [])
    if page["kind"] == "home":
        main = body
        scripts = f'<script src="{root}checker.js" defer></script>\n<script src="{root}main.js" defer></script>'
    else:
        body, toc = add_ids(body)
        crumbs = f'<a href="{root}./">Home</a> <span>/</span> '
        if page["kind"] == "doc":
            crumbs += f'<a href="{root}docs/">Docs</a>'
        else:
            crumbs += "Guides"
        side = ""
        if page["kind"] == "doc":
            items = "".join(
                f'<a href="{root}{d["path"].replace("index.html", "")}"'
                + (' aria-current="page"' if d["path"] == page["path"] else "") + f'>{d["nav"]}</a>' for d in docs)
            side = f'<nav class="side" aria-label="Docs">{items}</nav>'
        on_page = "".join(f'<a href="#{i}">{html.escape(t)}</a>' for i, t in toc)
        toc_html = f'<nav class="toc" aria-label="On this page"><h2>On this page</h2>{on_page}</nav>' if len(toc) > 2 else ""
        pager = ""
        if page["kind"] == "doc":
            i = [d["path"] for d in docs].index(page["path"])
            prev_ = docs[i - 1] if i > 0 else None
            next_ = docs[i + 1] if i + 1 < len(docs) else None
            def pl(d, label, cls):
                return (f'<a class="{cls}" href="{root}{d["path"].replace("index.html", "")}"><span>{label}</span>{d["nav"]}</a>'
                        if d else "<span></span>")
            pager = f'<nav class="pager" aria-label="More docs">{pl(prev_, "Previous", "prev")}{pl(next_, "Next", "next")}</nav>'
        main = f"""<div class="doc-wrap{' with-side' if side else ''}">
  {side}
  <article class="prose">
    <p class="crumbs">{crumbs}</p>
    <h1>{page.get("h1", page["title"])}</h1>
    {f'<p class="lead">{page["lead"]}</p>' if page.get("lead") else ""}
    {body}
    {pager}
  </article>
  {toc_html}
</div>"""
        scripts = f'<script src="{root}main.js" defer></script>'
    active = page["kind"]
    return f"""{head(page, root, extra_ld)}
<body class="{page['kind']}">
<a class="skip" href="#main">Skip to content</a>
{header(root, active)}
<main id="main">
{main}
</main>
{footer(root, docs)}
{scripts}
</body>
</html>
"""


def build(out: Path = SITE) -> list[Path]:
    pages = read_pages()
    docs = sorted((p for p in pages if p["kind"] == "doc"), key=lambda p: p["order"])
    fill = facts()
    written = []
    for page in pages:
        target = out / page["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_text(render(page, docs, fill), encoding="utf-8", newline="\n")
        written.append(target)
    urls = "\n".join(
        f'  <url><loc>{BASE}{p["path"].replace("index.html", "")}</loc><lastmod>__BUILT__</lastmod></url>'
        for p in sorted(pages, key=lambda p: (p["kind"] != "home", p.get("order", 99), p["path"])))
    sm = out / "sitemap.xml"
    sm.write_text('<?xml version="1.0" encoding="UTF-8"?>\n'
                  '<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">\n' + urls + "\n</urlset>\n",
                  encoding="utf-8", newline="\n")
    written.append(sm)
    return written


if __name__ == "__main__":
    for p in build():
        print(p.relative_to(ROOT))
