"""Run one phase's tests and save the proof.

    python scripts/prove.py 0 tests/test_phase0_foundation.py [more test files]

Writes proof/phase-N/pytest.txt (full verbose log with a header) and junit.xml.
Exits with pytest's exit code, so a failing phase is obvious.
"""
import datetime as dt
import platform
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    phase, files = sys.argv[1], sys.argv[2:]
    out = ROOT / "proof" / f"phase-{phase}"
    out.mkdir(parents=True, exist_ok=True)
    cmd = [sys.executable, "-m", "pytest", "-v", "-p", "no:cacheprovider",
           f"--junitxml={out / 'junit.xml'}", *files]
    started = dt.datetime.now()
    res = subprocess.run(cmd, cwd=ROOT, capture_output=True, text=True, encoding="utf-8", errors="replace")
    header = (
        f"PhishGuard - Phase {phase} test run\n"
        f"Started : {started:%Y-%m-%d %H:%M:%S}\n"
        f"Finished: {dt.datetime.now():%Y-%m-%d %H:%M:%S}\n"
        f"Python  : {platform.python_version()} on {platform.system()} {platform.release()}\n"
        f"Command : pytest -v {' '.join(files)}\n"
        f"Exit    : {res.returncode}\n" + "=" * 78 + "\n"
    )
    (out / "pytest.txt").write_text(header + res.stdout + res.stderr, encoding="utf-8")
    print(res.stdout[-3000:])
    print(res.stderr[-2000:])
    sys.exit(res.returncode)


if __name__ == "__main__":
    main()
