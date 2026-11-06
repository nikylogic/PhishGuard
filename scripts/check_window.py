"""Check the borderless PhishGuard window for real (proof for the window-controls change).

Starts a throwaway engine, opens the same window the launcher opens, then presses the header's own
buttons through the page (no mouse) and measures the real window with GetWindowRect:
no Windows title bar, maximize, restore, resize from the left edge (right edge stays put), minimize, close.
"""
import ctypes
import json
import os
import sys
import tempfile
import threading
import time
import urllib.request
from ctypes import wintypes
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "launcher"))
import pglaunch  # noqa: E402

OUT = ROOT / "proof" / "phase-9-installer"
user32 = ctypes.windll.user32
results = []


def rect(hwnd):
    r = wintypes.RECT()
    user32.GetWindowRect(hwnd, ctypes.byref(r))
    return r.left, r.top, r.right, r.bottom


def shot(hwnd, name):
    from PIL import ImageGrab
    user32.SetForegroundWindow(hwnd)
    time.sleep(0.6)
    ImageGrab.grab(bbox=rect(hwnd), all_screens=True).save(OUT / name)


def check(name, ok, detail=""):
    results.append((name, bool(ok), detail))


def run(window, controls):
    time.sleep(1.0)
    window.events.loaded.wait(30)
    deadline = time.time() + 20
    while time.time() < deadline and not window.evaluate_js("!!(window.pywebview && window.pywebview.api && "
                                                            "document.querySelector('[aria-label=Close]'))"):
        time.sleep(0.3)
    hwnd = int(window.native.Handle.ToInt64())       # this test's own window, never another PhishGuard
    style = user32.GetWindowLongW(hwnd, -16)
    check("no Windows title bar", not (style & 0x00C00000), hex(style))
    check("buttons are in the page header",
          window.evaluate_js("!!document.querySelector('header [aria-label=Minimize]') && "
                             "!!document.querySelector('header [aria-label=Maximize]') && "
                             "!!document.querySelector('header [aria-label=Close]')"))
    check("header is the drag area", window.evaluate_js("document.querySelector('header').classList.contains('pywebview-drag-region')"))
    shot(hwnd, "window-header-controls.png")

    before = rect(hwnd)
    window.evaluate_js("document.querySelector('[aria-label=Maximize]').click()")
    time.sleep(1.0)
    big = rect(hwnd)
    work = wintypes.RECT()
    user32.SystemParametersInfoW(0x0030, 0, ctypes.byref(work), 0)          # SPI_GETWORKAREA: screen minus taskbar
    check("Maximize fills the screen but not the taskbar",
          big == (work.left, work.top, work.right, work.bottom) and controls.is_maximized(), f"{before} -> {big}")
    check("button turns into Restore", window.evaluate_js("!!document.querySelector('[aria-label=Restore]')"))
    window.evaluate_js("document.querySelector('[aria-label=Restore]').click()")
    time.sleep(1.0)
    back = rect(hwnd)
    check("Restore brings the old size back", abs((back[2] - back[0]) - (before[2] - before[0])) <= 2, f"{back}")

    # Resize from the left edge: the right edge must stay where it is.
    window.evaluate_js("window.pywebview.api.resize(window.outerWidth - 150, window.outerHeight, 'w')")
    time.sleep(0.8)
    narrower = rect(hwnd)
    check("left-edge resize keeps the right edge", abs(narrower[2] - back[2]) <= 2 and narrower[0] > back[0],
          f"{back} -> {narrower}")
    window.evaluate_js("window.pywebview.api.resize(100, 100, 'se')")
    time.sleep(0.8)
    small = rect(hwnd)
    scale = user32.GetDpiForWindow(hwnd) / 96
    check("cannot be made smaller than 900 x 640", (small[2] - small[0]) >= int(899 * scale), f"{small}")
    check("edges refuse junk", window.evaluate_js("window.pywebview.api.resize(1000, 800, 'x; rm').then(() => true)") is not False)

    window.evaluate_js("document.querySelector('[aria-label=Minimize]').click()")
    time.sleep(0.8)
    check("Minimize", user32.IsIconic(hwnd))
    user32.ShowWindow(hwnd, 9)
    time.sleep(0.8)
    window.evaluate_js("document.querySelector('[aria-label=Close]').click()")


def main():
    inst = Path(tempfile.mkdtemp())
    env = dict(os.environ, PHISHGUARD_INSTANCE=str(inst), PHISHGUARD_PORT="5298", PHISHGUARD_NO_WORKER="1")
    cfg = pglaunch.config(env)
    pglaunch.ensure_server(cfg, env=env)
    try:
        import http.cookiejar
        web = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(http.cookiejar.CookieJar()))
        tok = json.loads(web.open(cfg["base"] + "/api/csrf").read())["csrf"]
        req = urllib.request.Request(cfg["base"] + "/api/setup", data=b'{"mode":"personal"}', method="POST",
                                     headers={"Content-Type": "application/json", "X-CSRF-Token": tok})
        web.open(req)
        url = pglaunch.dashboard_url(cfg)

        import webview
        controls = pglaunch.WindowControls()
        window = webview.create_window("PhishGuard", url, width=1220, height=880,
                                       min_size=(pglaunch.MIN_W, pglaunch.MIN_H), frameless=True, easy_drag=False,
                                       js_api=controls, text_select=True)
        controls.attach(window)
        t0 = time.time()
        webview.start(run, (window, controls))
        check("Close closes the window", time.time() - t0 < 60)
    finally:
        pid = (inst / "server.pid").read_text()
        os.system(f"taskkill /PID {pid} /T /F >nul 2>&1")
    lines = [f"{'PASS' if ok else 'FAIL'}  {name}  {detail}" for name, ok, detail in results]
    (OUT / "window-controls.txt").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))
    sys.exit(0 if all(ok for _, ok, _ in results) else 1)


if __name__ == "__main__":
    main()
