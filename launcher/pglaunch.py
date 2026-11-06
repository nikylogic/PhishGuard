"""PhishGuard's link launcher: what Windows runs when a link is clicked anywhere.

    pythonw pg_open.pyw "<url>"            (registered as the http/https handler)
    python  pg_open.pyw --no-window <url>  (prints the Airlock address instead of opening it; used by tests)
    pythonw pg_open.pyw --dashboard        (the Start menu shortcut: opens the dashboard)

1. Only http and https links are accepted. Anything else (javascript:, file:, ms-msdt: ...) is refused.
2. Trusted (allowlisted) sites open straight away in the real browser. This reads two small
   files the server keeps up to date (allowlist.txt, browser.txt), so it needs no network call.
3. Every other link is sent to the PhishGuard server (started first if it isn't running), and
   the Airlock opens in its own window with a one-time ticket.
4. If anything goes wrong, a message box says so. The link is NEVER opened unchecked.

Only the standard library is used (plus pywebview for the window), so a click stays fast.
The real browser is always started by its program file, never through Windows' "open URL",
because PhishGuard IS the default browser and that would loop straight back here.
"""
from __future__ import annotations

import json
import os
import subprocess
import sys
import time
import unicodedata
import urllib.error
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

ROOT = Path(__file__).resolve().parent.parent
HOST = "127.0.0.1"
NOT_A_BROWSER = {"python.exe", "pythonw.exe", "py.exe", "pyw.exe"}
CHROMIUM = ("chrome", "msedge", "brave")
START_TIMEOUT = 30.0       # first start loads the AI Guard model and the sandbox browser

TITLE = "PhishGuard"
ICON_WARNING, TOPMOST = 0x30, 0x40000


class Refused(Exception):
    """The link is not something PhishGuard will open."""


class Failed(Exception):
    """PhishGuard could not check the link."""


# --- configuration ------------------------------------------------------------------------

def config(env=os.environ) -> dict:
    instance = Path(env.get("PHISHGUARD_INSTANCE") or ROOT / "instance")
    port = int(env.get("PHISHGUARD_PORT") or 5157)
    return {"instance": instance, "port": port, "base": f"http://{HOST}:{port}"}


def log(cfg: dict, line: str) -> None:
    try:
        with open(cfg["instance"] / "launcher.log", "a", encoding="utf-8") as f:
            f.write(time.strftime("%Y-%m-%d %H:%M:%S ") + line[:300] + "\n")
    except OSError:
        pass


# --- the link -----------------------------------------------------------------------------

def check_link(raw: str) -> tuple[str, str]:
    """Return (url, host) for an http(s) link, or raise Refused."""
    url = (raw or "").strip().strip('"')
    if not url:
        raise Refused("There was no link.")
    # Spaces, control characters and invisible "format" characters (zero-width spaces, right-to-left
    # overrides) have no place in a clicked link and are a classic way to disguise one.
    if len(url) > 4096 or any(ord(c) < 33 or c == "\x7f" or unicodedata.category(c) == "Cf" for c in url):
        raise Refused("This link contains hidden or unusual characters.")
    try:
        parts = urlsplit(url)
        host = (parts.hostname or "").rstrip(".").lower()
    except ValueError:
        raise Refused("This is not a valid web link.") from None
    if parts.scheme.lower() not in ("http", "https"):
        shown = parts.scheme or url.split(":", 1)[0]
        raise Refused(f"PhishGuard only opens web links (http and https). This one starts with '{shown}:'.")
    if not host:
        raise Refused("This web link has no website name.")
    try:
        host = host.encode("idna").decode("ascii")
    except UnicodeError:
        pass                                # odd names simply go through the full check
    return url, host


def allowlisted(host: str, cfg: dict) -> bool:
    try:
        lines = (cfg["instance"] / "allowlist.txt").read_text(encoding="utf-8").split()
    except OSError:
        return False
    return any(host == d or host.endswith("." + d) for d in (x.strip().lower() for x in lines) if d)


# --- the real browser -----------------------------------------------------------------------

def real_browser(cfg: dict) -> str | None:
    try:
        exe = (cfg["instance"] / "browser.txt").read_text(encoding="utf-8").strip()
    except OSError:
        return None
    if not exe.lower().endswith(".exe") or Path(exe).name.lower() in NOT_A_BROWSER or not Path(exe).is_file():
        return None
    return exe


def open_in_browser(exe: str, url: str, popen=subprocess.Popen) -> None:
    # A list argument (no shell) means the link can never be read as a command.
    args = [exe, "--", url] if any(k in Path(exe).name.lower() for k in CHROMIUM) else [exe, url]
    popen(args, close_fds=True)


# --- the server -----------------------------------------------------------------------------

def healthy(cfg: dict, timeout: float = 0.5) -> bool:
    try:
        with urllib.request.urlopen(cfg["base"] + "/health", timeout=timeout) as r:
            return json.loads(r.read()).get("app") == "phishguard"
    except (OSError, ValueError):
        return False


def start_server(cfg: dict, popen=subprocess.Popen, env=os.environ) -> None:
    exe = Path(sys.executable)
    pyw = exe.with_name("pythonw.exe")
    python = str(pyw if pyw.exists() else exe)
    flags = 0
    if os.name == "nt":
        flags = subprocess.DETACHED_PROCESS | subprocess.CREATE_NEW_PROCESS_GROUP | subprocess.CREATE_NO_WINDOW
    cfg["instance"].mkdir(parents=True, exist_ok=True)
    out = open(cfg["instance"] / "server.log", "ab")
    child_env = dict(env)
    child_env["PHISHGUARD_INSTANCE"] = str(cfg["instance"])
    child_env["PHISHGUARD_PORT"] = str(cfg["port"])
    if getattr(sys, "frozen", False):      # the installed app: the engine is PhishGuardEngine.exe next to us
        here = Path(sys.executable).parent
        cmd, cwd = [str(here / "PhishGuardEngine.exe")], str(here)
    else:
        cmd, cwd = [python, str(ROOT / "run.py")], str(ROOT)
    proc = popen(cmd, cwd=cwd, env=child_env, stdout=out, stderr=out,
                 stdin=subprocess.DEVNULL, creationflags=flags, close_fds=True)
    (cfg["instance"] / "server.pid").write_text(str(proc.pid), encoding="utf-8")


def ensure_server(cfg: dict, popen=subprocess.Popen, env=os.environ, timeout: float | None = None) -> None:
    if healthy(cfg):
        return
    start_server(cfg, popen=popen, env=env)
    end = time.monotonic() + (START_TIMEOUT if timeout is None else timeout)
    while time.monotonic() < end:
        if healthy(cfg):
            return
        time.sleep(0.2)
    raise Failed("The PhishGuard engine did not start.")


def post(path: str, body: dict, cfg: dict) -> dict:
    """POST to the engine with the launcher's secret token."""
    try:
        token = (cfg["instance"] / "launcher.token").read_text(encoding="utf-8").strip()
    except OSError:
        raise Failed("The launcher key is missing.") from None
    req = urllib.request.Request(cfg["base"] + path, data=json.dumps(body).encode(), method="POST",
                                 headers={"Content-Type": "application/json", "X-PhishGuard-Token": token})
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            return json.loads(r.read())
    except urllib.error.HTTPError as e:
        try:
            msg = json.loads(e.read()).get("error") or ""
        except ValueError:
            msg = ""
        if e.code == 422:
            raise Refused(msg or "PhishGuard will not open this link.") from None
        raise Failed(msg or f"The engine answered {e.code}.") from None
    except (OSError, ValueError):
        raise Failed("The PhishGuard engine did not answer.") from None


def submit(url: str, cfg: dict) -> dict:
    return post("/api/scan", {"url": url}, cfg)


def dashboard_url(cfg: dict) -> str:
    """Personal mode: a one-time code signs the window in. Accounts mode: the login page."""
    code = post("/api/entry", {}, cfg).get("code")
    if code and not str(code).replace("-", "").replace("_", "").isalnum():
        raise Failed("The engine sent an odd entry code.")
    return f"{cfg['base']}/enter/{code}" if code else f"{cfg['base']}/login"


# --- what the user sees ----------------------------------------------------------------------

def message_box(text: str) -> None:
    if os.name == "nt" and os.environ.get("PHISHGUARD_NO_DIALOGS") != "1":   # tests turn dialogs off
        import ctypes
        ctypes.windll.user32.MessageBoxW(None, text, TITLE, ICON_WARNING | TOPMOST)
    else:
        print(text, file=sys.stderr)


def open_window(check_url: str, cfg: dict, popen=subprocess.Popen) -> None:
    """Show the Airlock in its own small app window. If that is not possible, show the Airlock
    page (a local PhishGuard page, never the unchecked link) in the real browser."""
    try:
        import webview
        webview.create_window("PhishGuard", check_url, width=1220, height=880, min_size=(900, 640))
        webview.start()
        return
    except Exception as e:  # noqa: BLE001 - any window problem falls back to the browser
        log(cfg, f"window failed ({type(e).__name__}); using the browser")
    exe = real_browser(cfg)
    if not exe:
        raise Failed("No window or browser was available to show the check.")
    open_in_browser(exe, check_url, popen)


def emit(text: str, out, cfg: dict) -> None:
    """--no-window (tests): print the address. The installed app has no console, so it goes to the log."""
    if out is not None:
        print(text, file=out)
    else:
        log(cfg, f"address: {text}")


# --- main -------------------------------------------------------------------------------------

def main(argv: list[str], env=os.environ, popen=subprocess.Popen, alert=message_box, window=open_window,
         out=sys.stdout) -> int:
    flags = {"--no-window", "--dashboard"}
    args = [a for a in argv[1:] if a not in flags]
    no_window = "--no-window" in argv[1:]
    cfg = config(env)
    raw = args[0] if args else ""
    if "--dashboard" in argv[1:]:
        try:
            ensure_server(cfg, popen=popen, env=env)
            target = dashboard_url(cfg)
            if no_window:
                emit(target, out, cfg)
            else:
                window(target, cfg)
            return 0
        except Exception as e:  # noqa: BLE001
            log(cfg, f"dashboard failed: {type(e).__name__}: {e}")
            alert(f"PhishGuard could not open its dashboard.\n\n({e})")
            return 1
    try:
        url, host = check_link(raw)
        if allowlisted(host, cfg):
            exe = real_browser(cfg)
            if not exe:
                raise Failed("Your real browser was not found. Choose it in PhishGuard's Settings.")
            open_in_browser(exe, url, popen)
            log(cfg, f"trusted, opened directly: {host}")
            return 0
        ensure_server(cfg, popen=popen, env=env)
        scan = submit(url, cfg)
        check_url = f"{cfg['base']}/check/{int(scan['id'])}?t={scan['ticket']}"
        log(cfg, f"check #{scan['id']}: {host}")
        if no_window:
            emit(check_url, out, cfg)
        else:
            window(check_url, cfg)
        return 0
    except Refused as e:
        log(cfg, f"refused: {raw[:80]!r}")
        alert(f"{e}\n\nThe link was not opened.\n\n{raw[:300]}")
        return 2
    except Exception as e:  # noqa: BLE001 - fail closed on anything at all
        log(cfg, f"failed: {type(e).__name__}: {e}")
        alert(f"PhishGuard could not check this link, so it was not opened.\n\n{raw[:300]}\n\n({e})")
        return 1
