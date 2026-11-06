"""Check real, well-known websites through the real sandbox and print their verdicts.

Used to confirm the scoring change: big honest sites that only track should come out Clear,
with their tracking listed as privacy notes. Needs an internet connection.

    .venv\\Scripts\\python scripts\\real_sites_check.py [url ...]
"""
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishguard.intel import Intel  # noqa: E402
from phishguard.pagerules import analyse  # noqa: E402
from phishguard.sandbox import Sandbox  # noqa: E402
from phishguard.worker import ScanWorker  # noqa: E402

SITES = [
    "https://x.com/jjukic22/status/2118131432891523413",
    "https://www.youtube.com/watch?v=-E2nR4HpMxI",
    "https://github.com/nikylogic/ivibe",
    "https://www.amazon.in/",
    "https://www.wikipedia.org/",
]


def main(urls):
    intel = Intel.load()
    base = Path(tempfile.mkdtemp(prefix="pg-real-"))
    w = ScanWorker(lambda: Sandbox(base / "shots", base / "q")).start()
    assert w.ready.wait(60), "sandbox did not start"
    print("| Site | Verdict | Score | Tracking bar | Counted | Privacy notes |")
    print("|---|---|---:|---:|---|---|")
    try:
        for i, url in enumerate(urls):
            c = w.submit(url, f"real-{i}").result(timeout=90)
            v = analyse(c.to_dict(), intel)
            notes = sorted({f.code for f in v["findings"] if f.code not in v["counted"]})
            print(f"| {url[:48]} | **{v['level'].upper()}** | {v['score']} | {v['subs']['tracking']} "
                  f"| {', '.join(v['counted']) or '-'} | {', '.join(notes) or '-'} |", flush=True)
    finally:
        w.stop()


if __name__ == "__main__":
    main(sys.argv[1:] or SITES)
