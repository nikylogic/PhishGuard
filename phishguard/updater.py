"""Automatic updates for the installed app.

How an update reaches a PC:

1. The release workflow builds PhishGuard-Setup-X.Y.Z.exe and writes update.json next to it:
   {"version": "X.Y.Z", "file": "PhishGuard-Setup-X.Y.Z.exe", "sha256": "...", "size": N}.
   It signs update.json with the PhishGuard release key (Ed25519; the private key is a GitHub
   secret) and publishes update.json.sig as well.
2. The engine asks GitHub for the latest release ten minutes after it starts and then twice a day.
   It accepts the release only if update.json carries a valid signature from the key built into
   this program, names a newer version and names the matching installer. Then it downloads the
   installer and checks its size and SHA-256 against the signed values.
3. In "auto" mode the installer runs silently once nobody is in the middle of checking a link. The
   installer stops the engine, replaces the program files and starts PhishGuard again; history and
   settings are untouched. In "ask" mode the dashboard shows the update with an Install button.

A tampered installer, a fake release or an older version (downgrade) is refused, even if GitHub or
the connection were compromised, because only the holder of the private key can sign update.json.
"""
from __future__ import annotations

import base64
import hashlib
import json
import logging
import os
import re
import subprocess
import sys
import threading
import time
from pathlib import Path

from . import __version__
from .ed25519 import verify

log = logging.getLogger("phishguard.updater")

REPO = "nikylogic/PhishGuard"
LATEST = f"https://api.github.com/repos/{REPO}/releases/latest"
RELEASES_PAGE = f"https://github.com/{REPO}/releases"
# The public half of the release key. The private half signs update.json in the release workflow.
PUBLIC_KEY = bytes.fromhex("6f7188f2476146f97bd2c81dae167d9cc2b853e9114507b2b5515579131544db")

MODES = ("auto", "ask", "off")
DEFAULT_MODE = "auto"
FIRST_CHECK = 10 * 60          # after the engine starts: let sign-in and the first links go first
CHECK_EVERY = 12 * 3600
RETRY_INSTALL = 5 * 60         # an update waiting for a quiet moment is retried this often
MAX_INSTALLER = 400 * 1024 * 1024
MAX_SMALL = 64 * 1024
LOCK = "updating.json"         # written just before the installer starts; the launcher waits on it
RESULT = "update-result.json"
UA = {"User-Agent": f"PhishGuard/{__version__} (update check)", "Accept": "application/vnd.github+json"}
FILE_RE = re.compile(r"PhishGuard-Setup-(\d+\.\d+\.\d+)\.exe")


class UpdateError(Exception):
    pass


def parse_version(v: str) -> tuple[int, int, int]:
    m = re.fullmatch(r"v?(\d{1,4})\.(\d{1,4})\.(\d{1,4})", str(v or "").strip())
    if not m:
        raise UpdateError(f"Not a version number: {str(v)[:30]!r}")
    return tuple(int(x) for x in m.groups())


def check_manifest(raw: bytes, sig_b64: bytes, current: str, public_key: bytes = PUBLIC_KEY) -> dict:
    """Verify the signed update.json and return it. Raises UpdateError when anything is off."""
    try:
        sig = base64.b64decode(sig_b64.strip(), validate=True)
    except ValueError:
        raise UpdateError("The update signature is not readable.") from None
    if not verify(public_key, raw, sig):
        raise UpdateError("The update is not signed by PhishGuard. It was not installed.")
    try:
        m = json.loads(raw)
    except ValueError:
        raise UpdateError("The update description is not readable.") from None
    if not isinstance(m, dict):
        raise UpdateError("The update description is not readable.")
    version = str(m.get("version", ""))
    parse_version(version)
    if m.get("file") != f"PhishGuard-Setup-{version}.exe":
        raise UpdateError("The update names an unexpected file.")
    if not re.fullmatch(r"[0-9a-f]{64}", str(m.get("sha256", ""))):
        raise UpdateError("The update has no valid fingerprint.")
    if not isinstance(m.get("size"), int) or not 0 < m["size"] <= MAX_INSTALLER:
        raise UpdateError("The update has an unexpected size.")
    m["newer"] = parse_version(version) > parse_version(current)
    return m


class Http:
    """The three requests the updater makes, kept apart so tests can replace them."""

    def __init__(self):
        import requests  # noqa: PLC0415
        self.s = requests.Session()
        self.s.headers.update(UA)

    def json(self, url: str):
        r = self.s.get(url, timeout=20)
        if r.status_code == 404:
            return None                          # no release published yet
        r.raise_for_status()
        return r.json()

    def small(self, url: str) -> bytes:
        with self.s.get(url, timeout=30, stream=True) as r:
            r.raise_for_status()
            data = r.raw.read(MAX_SMALL + 1, decode_content=True)
        if len(data) > MAX_SMALL:
            raise UpdateError("The update description is unexpectedly large.")
        return data

    def download(self, url: str, dest: Path, limit: int, progress=None) -> None:
        with self.s.get(url, timeout=60, stream=True) as r:
            r.raise_for_status()
            done = 0
            with open(dest, "wb") as f:
                for chunk in r.iter_content(1024 * 256):
                    done += len(chunk)
                    if done > limit:
                        raise UpdateError("The download is larger than the signed size.")
                    f.write(chunk)
                    if progress:
                        progress(done)


def launch_installer(installer: Path, log_file: Path) -> None:
    """Run the installer silently, detached from the engine.

    The installer stops the engine (and everything the engine started), so it must not be the
    engine's child: cmd's `start` hands it over and exits, and the installer outlives the engine.
    """
    for p in (installer, log_file):
        if '"' in str(p) or "%" in str(p):
            raise UpdateError("Unexpected characters in the update folder path.")
    cmd = (f'cmd.exe /d /s /c "start "" "{installer}" /VERYSILENT /SUPPRESSMSGBOXES /NORESTART /SP- '
           f'/LOG="{log_file}""')
    flags = 0
    if os.name == "nt":
        flags = subprocess.CREATE_NO_WINDOW | subprocess.CREATE_NEW_PROCESS_GROUP
    subprocess.Popen(cmd, creationflags=flags, close_fds=True, stdin=subprocess.DEVNULL,  # noqa: S602
                     stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def settle(instance: Path, current: str = __version__) -> str | None:
    """Called when the engine starts. If an update was just installed, record how it went and
    return a short message for the tray ("PhishGuard was updated to 1.2.0")."""
    lock = Path(instance) / LOCK
    try:
        info = json.loads(lock.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return None
    lock.unlink(missing_ok=True)
    target = str(info.get("version", ""))
    ok = target == current
    result = {"ok": ok, "version": target, "from": info.get("from", ""), "at": int(time.time()),
              "log": str(Path(instance) / "updates" / "install.log")}
    try:
        (Path(instance) / RESULT).write_text(json.dumps(result), encoding="utf-8")
    except OSError:
        pass
    if ok:
        return f"PhishGuard was updated to {target}."
    return f"The update to {target} did not finish. PhishGuard {current} is still installed."


class Updater:
    def __init__(self, instance: Path, settings, busy, current: str = __version__, http=None,
                 launch=launch_installer, public_key: bytes = PUBLIC_KEY, supported: bool | None = None,
                 audit=None):
        self.instance = Path(instance)
        self.folder = self.instance / "updates"
        self.settings = settings              # () -> dict of saved settings
        self.busy = busy                      # () -> True while someone is checking a link
        self.current = current
        self.http = http
        self.launch = launch
        self.public_key = public_key
        self.supported = bool(getattr(sys, "frozen", False)) if supported is None else supported
        self.audit = audit or (lambda action, detail: None)
        self.lock = threading.Lock()
        self._stop = threading.Event()
        self._wake = threading.Event()
        self.state = {"state": "idle", "latest": None, "checked_at": None, "error": "", "progress": 0,
                      "size": 0, "notes": ""}
        self.ready: dict | None = None        # the verified manifest of a downloaded installer

    # --- settings and status ---------------------------------------------------------------------
    def mode(self) -> str:
        m = self.settings().get("update_mode") or DEFAULT_MODE
        return m if m in MODES else DEFAULT_MODE

    def _set(self, **kw):
        with self.lock:
            self.state.update(kw)

    def status(self) -> dict:
        with self.lock:
            out = dict(self.state)
        out.update(current=self.current, mode=self.mode(), supported=self.supported, releases=RELEASES_PAGE)
        try:
            out["last_result"] = json.loads((self.instance / RESULT).read_text(encoding="utf-8"))
        except (OSError, ValueError):
            out["last_result"] = None
        return out

    # --- the work ------------------------------------------------------------------------------
    def check(self, install: bool = True) -> dict:
        """Look for a newer release; download and verify it. Returns status()."""
        if not self.supported:
            self._set(state="unsupported", error="Updates are installed by the installed app only.")
            return self.status()
        if self.state["state"] in ("checking", "downloading", "installing"):
            return self.status()
        self._set(state="checking", error="")
        try:
            self._check()
        except Exception as e:  # noqa: BLE001 - the dashboard shows what went wrong; retried later
            log.warning("update check failed: %s", e)
            msg = str(e) if isinstance(e, UpdateError) else "Could not reach GitHub to look for updates."
            self._set(state="error", error=msg)
        self._set(checked_at=int(time.time()))
        if install and self.ready and self.mode() == "auto":
            self.install_when_quiet()
        return self.status()

    def _check(self):
        http = self.http or Http()
        self.http = http
        rel = http.json(LATEST)
        if not rel:
            self._set(state="up_to_date", latest=None)
            return
        assets = {a.get("name"): a.get("browser_download_url", "") for a in rel.get("assets") or []}
        if "update.json" not in assets or "update.json.sig" not in assets:
            raise UpdateError("The latest release has no signed update description.")
        for url in (assets["update.json"], assets["update.json.sig"]):
            if not url.startswith(f"https://github.com/{REPO}/releases/download/"):
                raise UpdateError("The update is not hosted on PhishGuard's GitHub page.")
        raw = http.small(assets["update.json"])
        sig = http.small(assets["update.json.sig"])
        m = check_manifest(raw, sig, self.current, self.public_key)
        if rel.get("tag_name") != f"v{m['version']}":
            raise UpdateError("The release and its update description disagree.")
        self._set(latest=m["version"], notes=rel.get("html_url") or RELEASES_PAGE)
        if not m["newer"]:
            self.ready = None
            self._set(state="up_to_date")
            return
        url = assets.get(m["file"], "")
        if not url.startswith(f"https://github.com/{REPO}/releases/download/"):
            raise UpdateError("The latest release has no installer.")
        self.folder.mkdir(parents=True, exist_ok=True)
        dest = self.folder / m["file"]
        if not (dest.exists() and self._sha256(dest) == m["sha256"]):
            for old in self.folder.glob("PhishGuard-Setup-*.exe*"):
                old.unlink(missing_ok=True)     # never keep more than one installer
            part = dest.with_suffix(".exe.part")
            self._set(state="downloading", progress=0, size=m["size"])
            http.download(url, part, m["size"], progress=lambda n: self._set(progress=n))
            if part.stat().st_size != m["size"] or self._sha256(part) != m["sha256"]:
                part.unlink(missing_ok=True)
                raise UpdateError("The downloaded installer does not match the signed fingerprint. "
                                  "It was deleted.")
            part.replace(dest)
        self.ready = m
        self._set(state="ready", progress=m["size"], size=m["size"])

    @staticmethod
    def _sha256(path: Path) -> str:
        h = hashlib.sha256()
        with open(path, "rb") as f:
            for chunk in iter(lambda: f.read(1024 * 1024), b""):
                h.update(chunk)
        return h.hexdigest()

    def install_when_quiet(self) -> bool:
        if self.busy():
            log.info("update %s waits until no link is being checked", self.ready and self.ready["version"])
            return False
        return self.install()

    def install(self) -> bool:
        """Start the verified installer. The engine is stopped by it moments later."""
        m = self.ready
        if not m or not self.supported:
            return False
        dest = self.folder / m["file"]
        # Check again right before running: the file sits in the data folder until now.
        if not dest.exists() or self._sha256(dest) != m["sha256"]:
            self.ready = None
            self._set(state="error", error="The downloaded update changed on disk. It was not run.")
            return False
        (self.instance / LOCK).write_text(json.dumps({"version": m["version"], "from": self.current,
                                                      "at": int(time.time())}), encoding="utf-8")
        self._set(state="installing")
        self.audit("update", f"installing {m['version']} (from {self.current})")
        try:
            self.launch(dest, self.folder / "install.log")
        except Exception as e:  # noqa: BLE001
            (self.instance / LOCK).unlink(missing_ok=True)
            self._set(state="error", error=f"The installer did not start: {e}")
            return False
        return True

    # --- background loop ---------------------------------------------------------------------------
    def start(self, first: float = FIRST_CHECK) -> "Updater":
        if not self.supported:
            return self

        def loop():
            next_check = time.monotonic() + first
            while not self._stop.is_set():
                if self._wake.wait(timeout=max(1.0, min(RETRY_INSTALL, next_check - time.monotonic()))):
                    self._wake.clear()
                if self._stop.is_set():
                    return
                mode = self.mode()
                if mode == "off":
                    next_check = time.monotonic() + CHECK_EVERY
                    continue
                if time.monotonic() >= next_check:
                    next_check = time.monotonic() + CHECK_EVERY
                    self.check()
                elif self.ready and mode == "auto" and self.state["state"] == "ready":
                    self.install_when_quiet()

        threading.Thread(target=loop, name="pg-updater", daemon=True).start()
        return self

    def check_soon(self) -> None:
        """Check now, in the background (the dashboard's Check now button)."""
        threading.Thread(target=lambda: self.check(install=False), name="pg-update-now", daemon=True).start()

    def stop(self) -> None:
        self._stop.set()
        self._wake.set()
