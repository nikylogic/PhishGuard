"""Making PhishGuard the default browser, from the Settings page.

Windows does not let any program make itself the default browser: the choice is stored with a
check value only the Settings app can produce. So the button does the two things a program may do:
  1. register PhishGuard for the current user (HKCU only, no admin rights) and add the Start menu
     shortcut, then
  2. open Windows Settings directly on PhishGuard's page, where the user presses "Set default".
The user confirms in Windows itself, so nothing can quietly take over their browser.
"""
from __future__ import annotations

import importlib.util
import os
import sys
from pathlib import Path

from flask import current_app

_REG = Path(__file__).resolve().parent.parent / "launcher" / "registry.py"


def registry():
    if os.name != "nt":
        return None
    if "pg_registry" not in sys.modules:
        spec = importlib.util.spec_from_file_location("pg_registry", _REG)
        mod = importlib.util.module_from_spec(spec)
        sys.modules["pg_registry"] = mod
        spec.loader.exec_module(mod)
    return sys.modules["pg_registry"]


def _open_settings(page: str) -> None:
    opener = current_app.config.get("OPEN_SETTINGS")
    if opener:
        opener(page)
    else:
        os.startfile(page)            # a fixed ms-settings: address, never anything from a request


def _shortcut() -> Path | None:
    p = current_app.config.get("SHORTCUT_PATH")
    return Path(p) if p else None


def status() -> dict:
    reg = registry()
    if not reg:
        return {"supported": False, "registered": False, "default": False, "shortcut": False}
    base = current_app.config["REGISTRY_BASE"]
    shortcut = _shortcut() or reg.shortcut_path()
    return {"supported": True, "registered": reg.is_registered(base), "default": reg.is_default(base),
            "shortcut": shortcut.exists()}


def make_default() -> dict:
    reg = registry()
    if not reg:
        raise RuntimeError("This only works on Windows.")
    reg.register(current_app.config["REGISTRY_BASE"])
    reg.make_shortcut(_shortcut())
    _open_settings(reg.SETTINGS_PAGE)
    return status()


def remove() -> dict:
    reg = registry()
    if not reg:
        raise RuntimeError("This only works on Windows.")
    reg.unregister(current_app.config["REGISTRY_BASE"])
    reg.remove_shortcut(_shortcut())
    _open_settings(reg.SETTINGS_LIST)    # so the user can pick their old browser again
    return status()
