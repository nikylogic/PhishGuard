"""Find and start the user's real browser.

Links are always handed to the browser's own program file, never to Windows'
"open this URL" mechanism. PhishGuard IS the default browser, so asking Windows
to open the link would send it straight back to PhishGuard in an endless loop.
"""
import os
import subprocess
from pathlib import Path

from .urltools import UnsafeURL, normalise

CANDIDATES = [
    ("Google Chrome", r"%ProgramFiles%\Google\Chrome\Application\chrome.exe"),
    ("Google Chrome", r"%ProgramFiles(x86)%\Google\Chrome\Application\chrome.exe"),
    ("Google Chrome", r"%LocalAppData%\Google\Chrome\Application\chrome.exe"),
    ("Microsoft Edge", r"%ProgramFiles(x86)%\Microsoft\Edge\Application\msedge.exe"),
    ("Microsoft Edge", r"%ProgramFiles%\Microsoft\Edge\Application\msedge.exe"),
    ("Mozilla Firefox", r"%ProgramFiles%\Mozilla Firefox\firefox.exe"),
    ("Brave", r"%ProgramFiles%\BraveSoftware\Brave-Browser\Application\brave.exe"),
    ("Brave", r"%LocalAppData%\BraveSoftware\Brave-Browser\Application\brave.exe"),
]


def detect() -> list[dict]:
    out, seen = [], set()
    for name, raw in CANDIDATES:
        p = Path(os.path.expandvars(raw))
        if "%" not in str(p) and p.exists() and str(p).lower() not in seen:
            seen.add(str(p).lower())
            out.append({"name": name, "path": str(p)})
    return out


# Programs that are PhishGuard itself (the launcher runs under Python; the installed app is
# PhishGuard.exe). A link is never handed to one of these, or it would come straight back into PhishGuard.
NOT_A_BROWSER = {"python.exe", "pythonw.exe", "py.exe", "pyw.exe", "phishguard.exe", "phishguardengine.exe"}


def is_browser(path: str) -> bool:
    return path.lower().endswith(".exe") and Path(path).name.lower() not in NOT_A_BROWSER and Path(path).exists()


def choose(setting: str | None) -> str | None:
    if setting and is_browser(setting):
        return setting
    found = detect()
    return found[0]["path"] if found else None


def open_url(url: str, browser_path: str | None, popen=subprocess.Popen) -> bool:
    """Open url in the real browser. Returns True if a browser was started."""
    try:
        url = normalise(url)            # only http/https ever reaches the real browser
    except UnsafeURL:
        return False
    exe = choose(browser_path)
    if not exe:
        return False
    # A list argument (no shell) means the URL can never be read as a command.
    popen([exe, "--", url] if "chrome" in exe.lower() or "msedge" in exe.lower() or "brave" in exe.lower()
          else [exe, url], close_fds=True)
    return True
