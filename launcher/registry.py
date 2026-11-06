"""Register PhishGuard with Windows as a web-link handler (current user only, no admin rights).

Windows 11 then lists PhishGuard under Settings > Apps > Default apps. The user chooses it there
once; Windows does not let programs make themselves the default, and that is on purpose.

Everything is written under HKEY_CURRENT_USER\\<base> (base = "Software" normally; tests use a
throwaway base), and unregister() removes exactly what register() wrote.
"""
from __future__ import annotations

import os
import subprocess
import sys
import winreg
from pathlib import Path

APP = "PhishGuard"
PROGID = "PhishGuardURL"
ROOT = Path(__file__).resolve().parent.parent
LAUNCHER = ROOT / "launcher" / "pg_open.pyw"


def default_pythonw() -> str:
    exe = Path(sys.executable)
    pyw = exe.with_name("pythonw.exe")
    return str(pyw if pyw.exists() else exe)


def command(pythonw: str | None = None, script: Path = LAUNCHER) -> str:
    return f'"{pythonw or default_pythonw()}" "{script}" "%1"'


def keys(base: str = "Software") -> dict[str, str]:
    client = rf"{base}\Clients\StartMenuInternet\{APP}"
    return {
        "progid": rf"{base}\Classes\{PROGID}",
        "client": client,
        "capabilities": rf"{client}\Capabilities",
        "registered": rf"{base}\RegisteredApplications",
    }


def _set(path: str, values: dict[str, str]) -> None:
    with winreg.CreateKeyEx(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_WRITE) as k:
        for name, value in values.items():
            winreg.SetValueEx(k, name or None, 0, winreg.REG_SZ, value)


def register(base: str = "Software", pythonw: str | None = None, script: Path = LAUNCHER) -> dict[str, str]:
    k = keys(base)
    cmd = command(pythonw, script)
    icon = f'"{pythonw or default_pythonw()}",0'
    # The link type Windows hands links to.
    _set(k["progid"], {"": "PhishGuard link", "URL Protocol": "", "FriendlyTypeName": "PhishGuard link"})
    _set(rf"{k['progid']}\DefaultIcon", {"": icon})
    _set(rf"{k['progid']}\shell\open\command", {"": cmd})
    # The app itself, with what it can open.
    _set(k["client"], {"": APP})
    _set(rf"{k['client']}\DefaultIcon", {"": icon})
    _set(rf"{k['client']}\shell\open\command", {"": cmd})
    _set(k["capabilities"], {
        "ApplicationName": APP,
        "ApplicationDescription": "Opens every link in a sandbox first and checks it before it reaches your browser.",
        "ApplicationIcon": icon,
    })
    _set(rf"{k['capabilities']}\URLAssociations", {"http": PROGID, "https": PROGID})
    _set(rf"{k['capabilities']}\StartMenu", {"StartMenuInternet": APP})
    # Tell Windows the app exists, so it shows up in Default apps.
    _set(k["registered"], {APP: k["capabilities"]})
    return k


def _delete_tree(path: str) -> bool:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path, 0, winreg.KEY_ALL_ACCESS) as k:
            while True:
                try:
                    child = winreg.EnumKey(k, 0)
                except OSError:
                    break
                _delete_tree(rf"{path}\{child}")
        winreg.DeleteKey(winreg.HKEY_CURRENT_USER, path)
        return True
    except FileNotFoundError:
        return False


def unregister(base: str = "Software") -> list[str]:
    k = keys(base)
    removed = [p for p in (k["progid"], k["client"]) if _delete_tree(p)]
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, k["registered"], 0, winreg.KEY_SET_VALUE) as reg:
            winreg.DeleteValue(reg, APP)      # only our value: other apps live in this key too
            removed.append(rf"{k['registered']}\{APP}")
    except FileNotFoundError:
        pass
    return removed


def dump(base: str = "Software") -> list[str]:
    """A readable listing of every PhishGuard key and value (for the proof files)."""
    out: list[str] = []

    def walk(path: str) -> None:
        try:
            with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
                out.append(rf"[HKCU\{path}]")
                i = 0
                while True:
                    try:
                        name, value, _ = winreg.EnumValue(k, i)
                    except OSError:
                        break
                    out.append(f'  {name or "(default)"} = {value}')
                    i += 1
                subs, i = [], 0
                while True:
                    try:
                        subs.append(winreg.EnumKey(k, i))
                    except OSError:
                        break
                    i += 1
        except FileNotFoundError:
            return
        for s in subs:
            walk(rf"{path}\{s}")

    k = keys(base)
    walk(k["progid"])
    walk(k["client"])
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, k["registered"]) as reg:
            value, _ = winreg.QueryValueEx(reg, APP)
            out.append(rf"[HKCU\{k['registered']}]")
            out.append(f"  {APP} = {value}")
    except FileNotFoundError:
        pass
    return out


# --- is PhishGuard the default? -------------------------------------------------------------

def _read(path: str, name: str) -> str | None:
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, path) as k:
            return str(winreg.QueryValueEx(k, name)[0])
    except OSError:
        return None


def is_registered(base: str = "Software") -> bool:
    return _read(keys(base)["registered"], APP) is not None


def is_default(base: str = "Software") -> bool:
    """True when Windows hands both http and https links to PhishGuard. Windows keeps the user's
    choice under UserChoice; only the Settings app can write it, so we only ever read it."""
    root = rf"{base}\Microsoft\Windows\Shell\Associations\UrlAssociations"
    return all(_read(rf"{root}\{s}\UserChoice", "ProgId") == PROGID for s in ("http", "https"))


SETTINGS_PAGE = f"ms-settings:defaultapps?registeredAppUser={APP}"   # opens PhishGuard's own page
SETTINGS_LIST = "ms-settings:defaultapps"


# --- the Start menu shortcut (opens the dashboard) -------------------------------------------

def shortcut_path() -> Path:
    return Path(os.environ["APPDATA"]) / "Microsoft" / "Windows" / "Start Menu" / "Programs" / f"{APP}.lnk"


def make_shortcut(path: Path | None = None, pythonw: str | None = None, script: Path = LAUNCHER) -> Path:
    path = path or shortcut_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    # Values go in through environment variables, so no path is ever pasted into the script text.
    env = dict(os.environ, PG_LNK=str(path), PG_EXE=pythonw or default_pythonw(), PG_ARGS=f'"{script}" --dashboard',
               PG_DIR=str(ROOT))
    ps = ("$s = (New-Object -ComObject WScript.Shell).CreateShortcut($env:PG_LNK); "
          "$s.TargetPath = $env:PG_EXE; $s.Arguments = $env:PG_ARGS; $s.WorkingDirectory = $env:PG_DIR; "
          "$s.Description = 'Open the PhishGuard dashboard'; $s.Save()")
    subprocess.run(["powershell", "-NoProfile", "-NonInteractive", "-Command", ps], env=env, check=True,
                   capture_output=True, creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    return path


def remove_shortcut(path: Path | None = None) -> bool:
    path = path or shortcut_path()
    try:
        path.unlink()
        return True
    except FileNotFoundError:
        return False
