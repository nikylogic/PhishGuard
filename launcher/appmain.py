"""PhishGuard.exe: the installed app. One program, four jobs.

    PhishGuard.exe                 open the dashboard (the Start menu shortcut)
    PhishGuard.exe "<url>"         check a clicked link (what Windows runs once PhishGuard is the default)
    PhishGuard.exe --unregister    remove the Windows registration (run by the uninstaller)
    PhishGuard.exe --stop          stop the engine and Tor (run before an update or uninstall)

The engine (web server, sandbox, AI Guard) is the separate PhishGuardEngine.exe next to it, started
when a link needs checking. Keeping it separate keeps this program small, so a click stays fast.
Data lives in %LOCALAPPDATA%\\PhishGuard, which only this Windows account can read.
"""
from __future__ import annotations

import os
import subprocess
import sys
from pathlib import Path


def data_dir() -> Path:
    return Path(os.environ.get("LOCALAPPDATA") or Path.home() / "AppData" / "Local") / "PhishGuard"


def stop(instance: Path) -> None:
    pid_file = instance / "server.pid"
    try:
        pid = int(pid_file.read_text(encoding="utf-8").strip())
    except (OSError, ValueError):
        return
    subprocess.run(["taskkill", "/PID", str(pid), "/T", "/F"], capture_output=True,
                   creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
    pid_file.unlink(missing_ok=True)


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    os.environ.setdefault("PHISHGUARD_INSTANCE", str(data_dir()))
    instance = Path(os.environ["PHISHGUARD_INSTANCE"])
    instance.mkdir(parents=True, exist_ok=True)
    args = argv[1:]
    if args[:1] == ["--unregister"]:
        import registry                               # noqa: PLC0415
        registry.unregister()
        registry.remove_shortcut()
        return 0
    if args[:1] == ["--stop"]:
        stop(instance)
        return 0
    import pglaunch                                   # noqa: PLC0415
    if not args:
        return pglaunch.main([argv[0], "--dashboard"])
    return pglaunch.main(argv)


if __name__ == "__main__":
    sys.exit(main())
