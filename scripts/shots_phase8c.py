"""End-to-end proof for Hide my IP with the real Tor network (proof/phase-8c).

A throwaway PhishGuard instance with the real sandbox worker: pick Tor in Settings, download it,
save, press Test, then check https://check.torproject.org/ and screenshot the Airlock.
IP addresses are blurred out of the screenshots.
"""
import sys
import tempfile
import threading
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from playwright.sync_api import sync_playwright  # noqa: E402
from waitress.server import create_server  # noqa: E402

from phishguard import create_app  # noqa: E402

OUT = ROOT / "proof" / "phase-8c"
OUT.mkdir(parents=True, exist_ok=True)
tmp = Path(tempfile.mkdtemp())
app = create_app({"INSTANCE_DIR": str(tmp / "instance"), "START_WORKER": True})
srv = create_server(app, host="127.0.0.1", port=0, threads=8)
base = f"http://127.0.0.1:{srv.effective_port}"
threading.Thread(target=srv.run, daemon=True).start()
BLUR = "document.querySelectorAll('.font-mono').forEach(e => { if (/\\d+\\.\\d+\\.\\d+|:/.test(e.textContent)) e.style.filter = 'blur(6px)' })"

errors = []
service = app.extensions["pg_service"]
try:
    with sync_playwright() as p:
        b = p.chromium.launch(channel="chrome")
        pg = b.new_page(viewport={"width": 1280, "height": 900})
        pg.on("console", lambda m: m.type == "error" and errors.append(m.text))
        pg.goto(base + "/")
        pg.click("text=Just me")
        pg.wait_for_url(base + "/")
        pg.goto(base + "/settings")
        pg.click("#route")
        pg.click("role=option[name='Tor (built in, free)']")
        pg.click("text=Download Tor")
        pg.wait_for_selector("text=Downloading Tor", timeout=20000)
        pg.screenshot(path=str(OUT / "settings-tor-downloading.png"))
        pg.wait_for_selector("text=is downloaded", timeout=180000)
        pg.click("button:has-text('Save')")
        pg.wait_for_selector("text=Connected to the Tor network", timeout=120000)
        pg.click("button:has-text('Test')")
        pg.wait_for_selector("text=Sites see", timeout=90000)
        pg.evaluate(BLUR)
        pg.screenshot(path=str(OUT / "settings-tor-test.png"))
        shown = pg.inner_text("text=Sites see")
        print("test line:", "a Tor address" in shown)

        tok = pg.evaluate("document.getElementById('root').dataset.csrf")
        r = pg.request.post(base + "/api/scan", data={"url": "https://check.torproject.org/"},
                            headers={"X-CSRF-Token": tok})
        sid = r.json()["id"]
        pg.goto(f"{base}/check/{sid}")
        pg.wait_for_selector("text=Opened in", timeout=120000)
        pg.wait_for_timeout(1500)
        pg.screenshot(path=str(OUT / "airlock-through-tor.png"))
        pg.click("role=tab[name=/Technical/]")
        pg.wait_for_selector("text=Your IP address")
        pg.screenshot(path=str(OUT / "airlock-through-tor-details.png"))
        scan = pg.request.get(f"{base}/api/scan/{sid}").json()
        print("route:", scan.get("page", {}).get("route"), "| title:", scan.get("title"))
        b.close()
finally:
    service.tor.stop()
    if service.worker:
        service.worker.stop()
    srv.close()
print("console errors:", errors or "none")
