"""PhishGuardEngine.exe: the background engine of the installed app (web server, sandbox, AI Guard).

PhishGuard.exe starts it when a link needs checking (or at sign-in, with Start with Windows). It is a
separate program so that PhishGuard.exe stays small and a click on a trusted link stays fast. While
it runs, its icon sits in the notification area next to the clock (tray.py).
"""
import os
import socket
import sys

from appmain import data_dir


def port_free(port: int) -> bool:
    """True when no other PhishGuard engine already serves this port (so we never show two icons)."""
    s = socket.socket()
    try:
        s.bind(("127.0.0.1", port))
        return True
    except OSError:
        return False
    finally:
        s.close()


def main() -> int:
    # PhishGuard.exe always starts the engine with no arguments. An older build registered this
    # program as the link handler, so a click could land here: pass the link on to PhishGuard.exe
    # instead of starting a second engine that can never get the port.
    if len(sys.argv) > 1:
        import subprocess  # noqa: PLC0415
        from pathlib import Path  # noqa: PLC0415
        app = Path(sys.executable).with_name("PhishGuard.exe")
        if app.exists():
            subprocess.Popen([str(app), *sys.argv[1:]], close_fds=True)
        return 0
    os.environ.setdefault("PHISHGUARD_INSTANCE", str(data_dir()))
    port = int(os.environ.get("PHISHGUARD_PORT") or 5157)
    if os.environ.get("PHISHGUARD_NO_TRAY") != "1" and port_free(port):
        try:
            import registry  # noqa: PLC0415
            import tray  # noqa: PLC0415
            from pathlib import Path  # noqa: PLC0415

            from phishguard.updater import settle  # noqa: PLC0415
            instance = Path(os.environ["PHISHGUARD_INSTANCE"])
            updated = settle(instance)          # "PhishGuard was updated to 1.2.0", once
            icon = tray.Tray(instance, registry=registry).start()
            if updated:
                icon.notify("PhishGuard", updated, warning="did not" in updated)
        except Exception:  # noqa: BLE001 - the engine works without its icon
            pass
    import run  # noqa: PLC0415
    run.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
