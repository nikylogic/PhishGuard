"""Screenshots for proof/phase-8b: first run, personal-mode dashboard and Settings, locked-out stranger.
Uses a throwaway instance and registry key; Windows Settings is not opened."""
import sys
import tempfile
import threading
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))
sys.path.insert(0, str(ROOT / "launcher"))

from playwright.sync_api import sync_playwright  # noqa: E402
from waitress.server import create_server  # noqa: E402

import registry  # noqa: E402
from phishguard import create_app  # noqa: E402

OUT = ROOT / "proof" / "phase-8b"
OUT.mkdir(parents=True, exist_ok=True)
tmp = Path(tempfile.mkdtemp())
base_key = rf"Software\PhishGuardShots-{uuid.uuid4().hex[:8]}"
app = create_app({"INSTANCE_DIR": str(tmp / "instance"), "REGISTRY_BASE": base_key,
                  "SHORTCUT_PATH": str(tmp / "PhishGuard.lnk"), "OPEN_SETTINGS": lambda p: None})
srv = create_server(app, host="127.0.0.1", port=0)
port = srv.effective_port
threading.Thread(target=srv.run, daemon=True).start()
base = f"http://127.0.0.1:{port}"

errors = []
try:
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome")
        pg = b.new_page(viewport={"width": 1280, "height": 820})
        pg.on("console", lambda m: m.type == "error" and errors.append(m.text))
        pg.goto(base + "/")
        pg.wait_for_selector("text=Just me")
        pg.screenshot(path=str(OUT / "first-run.png"))
        pg.click("text=Several people")
        pg.wait_for_selector("text=Create the admin account")
        pg.screenshot(path=str(OUT / "first-run-accounts.png"))
        pg.click("text=Back")
        pg.click("text=Just me")
        pg.wait_for_url(base + "/")
        pg.wait_for_selector("text=Dashboard")
        pg.goto(base + "/settings")
        pg.wait_for_selector("text=Who uses PhishGuard")
        pg.wait_for_selector("text=Make PhishGuard my default browser")
        pg.screenshot(path=str(OUT / "settings-personal.png"))
        pg.click("text=Make PhishGuard my default browser")
        pg.wait_for_selector("text=Windows Settings is open")
        pg.screenshot(path=str(OUT / "settings-default-clicked.png"))
        stranger = b.new_page(viewport={"width": 1280, "height": 820})
        stranger.goto(base + "/")
        stranger.wait_for_selector("text=Start menu")
        stranger.screenshot(path=str(OUT / "stranger-locked-out.png"))
        b.close()
finally:
    registry._delete_tree(base_key)
    srv.close()
print("console errors:", errors or "none")
