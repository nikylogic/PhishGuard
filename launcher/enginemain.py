"""PhishGuardEngine.exe: the background engine of the installed app (web server, sandbox, AI Guard).

PhishGuard.exe starts it when a link needs checking. It is a separate program so that PhishGuard.exe
stays small and a click on a trusted link stays fast.
"""
import os
import sys

from appmain import data_dir


def main() -> int:
    os.environ.setdefault("PHISHGUARD_INSTANCE", str(data_dir()))
    import run  # noqa: PLC0415
    run.main()
    return 0


if __name__ == "__main__":
    sys.exit(main())
