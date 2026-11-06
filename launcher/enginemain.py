"""PhishGuardEngine.exe: the background engine of the installed app (web server, sandbox, AI Guard).

PhishGuard.exe starts it when a link needs checking. It is a separate program so that PhishGuard.exe
stays small and a click on a trusted link stays fast.
"""
import os
import sys

from appmain import data_dir


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
    import run  # noqa: PLC0415
    run.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
