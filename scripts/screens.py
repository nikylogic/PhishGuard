"""Screenshot every screen of the running demo (python scripts/demo.py first).

    python scripts/screens.py [out_dir]

Captures light and dark themes at 1366x768, plus 1920x1080 for the key screens.
Also records console errors per page, which the UI tests check.
"""
import json
import sys
from pathlib import Path

from playwright.sync_api import sync_playwright

ROOT = Path(__file__).resolve().parent.parent
OUT = Path(sys.argv[1]) if len(sys.argv) > 1 else ROOT / "proof" / "phase-7" / "screens"
BASE = "http://127.0.0.1:5157"


def main():
    OUT.mkdir(parents=True, exist_ok=True)
    errors = {}
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome")
        for scheme in ("light", "dark"):
            for w, hgt in ((1366, 768), (1920, 1080)):
                if scheme == "dark" and w == 1920:
                    continue
                ctx = b.new_context(viewport={"width": w, "height": hgt}, color_scheme=scheme, device_scale_factor=1.5)
                page = ctx.new_page()
                page.on("console", lambda m, k=None: m.type == "error" and errors.setdefault(page.url, []).append(m.text))
                page.on("pageerror", lambda e: errors.setdefault(page.url, []).append(str(e)))
                tag = f"{scheme}-{w}"
                page.goto(f"{BASE}/login")
                page.wait_for_timeout(300)
                page.screenshot(path=str(OUT / f"login-{tag}.png"))
                page.fill("#username", "admin")
                page.fill("#password", "airlock-admin-1")
                page.click("button[type=submit]")
                page.wait_for_url(f"{BASE}/")
                page.wait_for_timeout(900)
                page.screenshot(path=str(OUT / f"home-{tag}.png"), full_page=True)
                scans = page.evaluate("fetch('/api/scans?limit=200').then(r => r.json())")["scans"]
                pick = {}
                for s in scans:
                    key = s["domain"] + (s["title"] or "")
                    pick.setdefault(key, s)
                for s in pick.values():
                    page.goto(f"{BASE}/check/{s['id']}")
                    page.wait_for_timeout(1400)
                    name = (s["title"] or s["domain"]).lower()
                    name = "".join(c if c.isalnum() else "-" for c in name)[:40].strip("-")
                    page.screenshot(path=str(OUT / f"check-{s['id']:02d}-{name}-{tag}.png"), full_page=True)
                for path in ("history", "lists", "guard", "settings"):
                    page.goto(f"{BASE}/{path}")
                    page.wait_for_timeout(700)
                    if path == "guard":
                        page.click("text=Hidden attack")
                        page.wait_for_timeout(900)
                    page.screenshot(path=str(OUT / f"{path}-{tag}.png"), full_page=True)
                ctx.close()
        b.close()
    (OUT / "console-errors.json").write_text(json.dumps(errors, indent=1), encoding="utf-8")
    print("screens:", len(list(OUT.glob("*.png"))), "console errors:", sum(len(v) for v in errors.values()))


if __name__ == "__main__":
    main()
