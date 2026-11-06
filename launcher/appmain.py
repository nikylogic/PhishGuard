"""PhishGuard.exe: the installed app. One program, four jobs.

    PhishGuard.exe                 open the dashboard (the Start menu shortcut)
    PhishGuard.exe "<url>"         check a clicked link (what Windows runs once PhishGuard is the default)
    PhishGuard.exe --background    start the engine quietly (Start with Windows)
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


def first_run_startup(instance: Path, registry) -> None:
    """Start with Windows is on by default. It is switched on once, the first time the app runs;
    after that only the user's choice in Settings (or Task Manager) counts, also across updates."""
    mark = instance / "startup.set"
    if not registry.FROZEN or mark.exists():   # only the installed app, never tests or dev runs
        return
    registry.set_startup(True)
    mark.write_text("on by default at first run\n", encoding="utf-8")


def main(argv: list[str] | None = None) -> int:
    argv = list(sys.argv if argv is None else argv)
    os.environ.setdefault("PHISHGUARD_INSTANCE", str(data_dir()))
    instance = Path(os.environ["PHISHGUARD_INSTANCE"])
    instance.mkdir(parents=True, exist_ok=True)
    args = argv[1:]
    if args[:1] == ["--unregister"]:
        import registry                               # noqa: PLC0415
        registry.unregister()
        registry.set_startup(False)
        registry.remove_shortcut()
        return 0
    if args[:1] == ["--stop"]:
        stop(instance)
        return 0
    try:                                              # fix a link command left by an older build
        import registry                               # noqa: PLC0415
        registry.repair()
        registry.repair_startup()
        first_run_startup(instance, registry)
    except Exception:                                 # noqa: BLE001  never block opening a link
        pass
    import pglaunch                                   # noqa: PLC0415
    if not args:
        return pglaunch.main([argv[0], "--dashboard"])
    return pglaunch.main(argv)


if __name__ == "__main__":
    sys.exit(main())
