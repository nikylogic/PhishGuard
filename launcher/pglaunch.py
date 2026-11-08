"""PhishGuard's link launcher: what Windows runs when a link is clicked anywhere.

    pythonw pg_open.pyw "<url>"            (registered as the http/https handler)
    python  pg_open.pyw --no-window <url>  (prints the Airlock address instead of opening it; used by tests)
    pythonw pg_open.pyw --dashboard        (the Start menu shortcut: opens the dashboard)
    pythonw pg_open.pyw --background       (at Windows sign-in: start the engine, show nothing)

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
NOT_A_BROWSER = {"python.exe", "pythonw.exe", "py.exe", "pyw.exe", "phishguard.exe", "phishguardengine.exe"}
CHROMIUM = ("chrome", "msedge", "brave")
START_TIMEOUT = 30.0       # first start loads the AI Guard model and the sandbox browser
BACKGROUND_TIMEOUT = 120.0  # at sign-in the PC is busy; there is no one waiting
STARTED = time.monotonic()  # for the timings written to launcher.log

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
    # Browsers read "\" as "/" before the ? or #: https://evil.example\@bank.com/ opens evil.example.
    # Judge (and pass on) the link exactly as the browser will read it, or a trusted name after a
    # backslash would skip the check. Same rule as phishguard/urltools.py browser_slashes().
    cut = min((i for i in (url.find("?"), url.find("#")) if i >= 0), default=len(url))
    url = url[:cut].replace("\\", "/") + url[cut:]
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

def instance_id(path) -> str:
    """A short fingerprint of the data folder (the same formula is in phishguard/__init__.py)."""
    import hashlib
    return hashlib.sha256(str(Path(path).resolve()).lower().encode("utf-8")).hexdigest()[:16]


class OtherCopy(Failed):
    """Another PhishGuard (a different install or data folder) already uses our port."""


def healthy(cfg: dict, timeout: float = 0.5) -> bool:
    """True when OUR engine answers. Raises OtherCopy when a different PhishGuard answers instead."""
    try:
        with urllib.request.urlopen(cfg["base"] + "/health", timeout=timeout) as r:
            info = json.loads(r.read())
    except (OSError, ValueError):
        return False
    if info.get("app") != "phishguard":
        return False
    if info.get("instance") != instance_id(cfg["instance"]):
        raise OtherCopy(f"Another copy of PhishGuard is already running on this PC (port {cfg['port']}). "
                        "Close it, then try again.")
    return True


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


UPDATE_LOCK = "updating.json"   # written by the engine just before an update installs (phishguard/updater.py)
UPDATE_WAIT = 90.0              # an update takes 20-40 s; the installer starts the new engine itself
UPDATE_STALE = 300.0


def updating(cfg: dict) -> bool:
    """True while an update is being installed (the lock is fresh and the engine is down)."""
    try:
        return time.time() - (cfg["instance"] / UPDATE_LOCK).stat().st_mtime < UPDATE_STALE
    except OSError:
        return False


def ensure_server(cfg: dict, popen=subprocess.Popen, env=os.environ, timeout: float | None = None,
                  wait_update: bool = True) -> None:
    if healthy(cfg):
        return
    if wait_update and updating(cfg):
        # Starting the old engine now would lock files the installer is replacing. Wait for the
        # new engine instead; if it does not come, start whatever is installed.
        log(cfg, "update in progress: waiting for the new engine")
        end = time.monotonic() + UPDATE_WAIT
        while time.monotonic() < end:
            if healthy(cfg):
                return
            time.sleep(0.5)
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


MIN_W, MIN_H = 900, 640


def light_theme() -> bool:
    """Windows' app colour setting, so the window does not flash the wrong colour while loading."""
    try:
        import winreg
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER,
                            r"Software\Microsoft\Windows\CurrentVersion\Themes\Personalize") as k:
            return bool(winreg.QueryValueEx(k, "AppsUseLightTheme")[0])
    except OSError:
        return True


class WindowControls:
    """What the page may ask of its window, and nothing more: minimize, maximize or restore, close,
    and resize from an edge. The window has no Windows title bar; PhishGuard's own header has these
    buttons (web/src/components/window-controls.tsx)."""

    def __init__(self):
        self._window = None
        self._maximized = False
        self._saved = None              # the window's place before maximizing

    def attach(self, window) -> None:
        self._window = window

    def minimize(self) -> None:
        self._window.minimize()

    def _hwnd(self) -> int:
        return int(self._window.native.Handle.ToInt64())

    def toggle_maximize(self) -> bool:
        """Maximize to the monitor's work area (the screen minus the taskbar), or back.
        Windows' own maximize would cover the taskbar, because the window has no frame."""
        import ctypes
        from ctypes import wintypes
        user32 = ctypes.windll.user32
        user32.MonitorFromWindow.restype = wintypes.HMONITOR
        hwnd, flags = self._hwnd(), 0x0004 | 0x0010            # SWP_NOZORDER | SWP_NOACTIVATE
        if not self._maximized:
            r = wintypes.RECT()
            user32.GetWindowRect(hwnd, ctypes.byref(r))
            self._saved = (r.left, r.top, r.right - r.left, r.bottom - r.top)

            class MONITORINFO(ctypes.Structure):
                _fields_ = [("cbSize", wintypes.DWORD), ("rcMonitor", wintypes.RECT), ("rcWork", wintypes.RECT),
                            ("dwFlags", wintypes.DWORD)]
            info = MONITORINFO(cbSize=ctypes.sizeof(MONITORINFO))
            user32.GetMonitorInfoW(user32.MonitorFromWindow(hwnd, 2), ctypes.byref(info))   # the nearest monitor
            w = info.rcWork
            user32.SetWindowPos(hwnd, None, w.left, w.top, w.right - w.left, w.bottom - w.top, flags)
            self._maximized = True
        else:
            if self._saved:
                user32.SetWindowPos(hwnd, None, *self._saved, flags)
            self._maximized = False
        return self._maximized

    def is_maximized(self) -> bool:
        return self._maximized

    def close(self) -> None:
        self._window.destroy()

    def resize(self, width, height, edge) -> None:
        from webview.window import FixPoint
        edge = str(edge)
        if self._maximized or not edge or set(edge) - set("nsew"):
            return
        w = max(MIN_W, min(int(width), 10000))
        h = max(MIN_H, min(int(height), 10000))
        # Keep the opposite edge where it is: dragging the left edge must not move the right one.
        fix = (FixPoint.SOUTH if "n" in edge else FixPoint.NORTH) | (FixPoint.EAST if "w" in edge else FixPoint.WEST)
        self._window.resize(w, h, fix)


SPLASH = """<!doctype html><html><head><meta charset="utf-8"><style>
html,body{margin:0;height:100%;background:BG;color:FG;font:15px "Segoe UI",system-ui,sans-serif}
body{display:flex;flex-direction:column;align-items:center;justify-content:center;gap:14px}
.spin{width:22px;height:22px;border:2px solid MUTED;border-top-color:FG;border-radius:50%;animation:r .8s linear infinite}
@keyframes r{to{transform:rotate(360deg)}}
.drag{position:fixed;left:0;right:0;top:0;height:40px}
</style></head><body><div class="drag pywebview-drag-region"></div><div class="spin"></div><div>Starting PhishGuard…</div></body></html>"""


def splash(light: bool) -> str:
    bg, fg, muted = ("#ffffff", "#171717", "#e5e5e5") if light else ("#0a0a0a", "#fafafa", "#333333")
    return SPLASH.replace("MUTED", muted).replace("BG", bg).replace("FG", fg)


def open_window(target, cfg: dict, popen=subprocess.Popen) -> None:
    """Show PhishGuard in its own app window. `target` is an address, or a function that gets one
    (starting the engine if needed); then a "Starting PhishGuard…" screen shows at once instead of
    nothing. If no window is possible, the page (a local PhishGuard page, never the unchecked link)
    opens in the real browser instead."""
    prepare = target if callable(target) else (lambda: target)
    problem: list[Exception] = []
    try:
        import webview
        light = light_theme()
        controls = WindowControls()
        first = None if callable(target) else target
        # The dashboard is titled "PhishGuard" (the tray and a second launch find it by that name);
        # each link check gets its own title, so it is never mistaken for the dashboard.
        window = webview.create_window(cfg.get("title", "PhishGuard"), url=first, html=None if first else splash(light),
                                       width=1220, height=880, min_size=(MIN_W, MIN_H), frameless=True,
                                       easy_drag=False, js_api=controls, text_select=True,
                                       background_color="#ffffff" if light else "#0a0a0a")
        controls.attach(window)
        # Timings in launcher.log, so a slow start can be explained ("window 0.6 s, page 1.2 s").
        window.events.shown += lambda *a: log(cfg, f"window shown at {time.monotonic() - STARTED:.1f} s")
        window.events.loaded += lambda *a: log(cfg, f"page loaded at {time.monotonic() - STARTED:.1f} s")

        def load():
            if first:
                return
            try:
                window.load_url(prepare())
            except Exception as e:  # noqa: BLE001 - reported after the window closes
                problem.append(e)
                window.destroy()
        webview.start(load)
    except Exception as e:  # noqa: BLE001 - any window problem falls back to the browser
        log(cfg, f"window failed ({type(e).__name__}); using the browser")
        exe = real_browser(cfg)
        if not exe:
            raise Failed("No window or browser was available to show the check.") from None
        open_in_browser(exe, prepare(), popen)
        return
    if problem:
        raise problem[0]


def emit(text: str, out, cfg: dict) -> None:
    """--no-window (tests): print the address. The installed app has no console, so it goes to the log."""
    if out is not None:
        print(text, file=out)
    else:
        log(cfg, f"address: {text}")


def focus_existing(env=os.environ) -> bool:
    """A Windows app opens once: if the dashboard is already open, bring it forward instead.
    Tests (PHISHGUARD_NO_DIALOGS) never look for, or touch, a real PhishGuard window."""
    if env.get("PHISHGUARD_NO_DIALOGS") == "1":
        return False
    try:
        import tray  # noqa: PLC0415 - standard library only
        return tray.focus_window()
    except Exception:  # noqa: BLE001
        return False


# --- main -------------------------------------------------------------------------------------

def main(argv: list[str], env=os.environ, popen=subprocess.Popen, alert=message_box, window=open_window,
         out=sys.stdout) -> int:
    flags = {"--no-window", "--dashboard", "--background", "--after-update"}
    args = [a for a in argv[1:] if a not in flags]
    no_window = "--no-window" in argv[1:]
    cfg = config(env)
    raw = args[0] if args else ""
    if "--background" in argv[1:] or "--after-update" in argv[1:]:
        # Start with Windows: get the engine ready so the first link is checked at once. Quiet on
        # failure (no dialog at sign-in); the next click starts the engine anyway.
        # --after-update: the installer has finished an update and starts the new engine at once.
        try:
            ensure_server(cfg, popen=popen, env=env, timeout=BACKGROUND_TIMEOUT,
                          wait_update="--after-update" not in argv[1:])
            log(cfg, f"background: engine ready at {time.monotonic() - STARTED:.1f} s")
            return 0
        except Exception as e:  # noqa: BLE001
            log(cfg, f"background start failed: {type(e).__name__}: {e}")
            return 1
    if "--dashboard" in argv[1:]:
        def dashboard() -> str:
            ensure_server(cfg, popen=popen, env=env)
            log(cfg, f"dashboard: engine ready at {time.monotonic() - STARTED:.1f} s")
            return dashboard_url(cfg)
        try:
            if no_window:
                emit(dashboard(), out, cfg)
            elif focus_existing(env):
                log(cfg, "dashboard: brought the open window to the front")
            else:
                window(dashboard, cfg)          # the window opens at once and shows "Starting PhishGuard…"
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
        def airlock() -> str:
            ensure_server(cfg, popen=popen, env=env)
            scan = submit(url, cfg)
            log(cfg, f"check #{scan['id']}: {host}")
            return f"{cfg['base']}/check/{int(scan['id'])}?t={scan['ticket']}"
        if no_window:
            emit(airlock(), out, cfg)
        else:
            cfg["title"] = f"PhishGuard · {host}"
            window(airlock, cfg)                # the window opens at once; the check fills it when ready
        return 0
    except Refused as e:
        log(cfg, f"refused: {raw[:80]!r}")
        alert(f"{e}\n\nThe link was not opened.\n\n{raw[:300]}")
        return 2
    except Exception as e:  # noqa: BLE001 - fail closed on anything at all
        log(cfg, f"failed: {type(e).__name__}: {e}")
        alert(f"PhishGuard could not check this link, so it was not opened.\n\n{raw[:300]}\n\n({e})")
        return 1
