"""End-to-end check of the real pipeline: scan service, sandbox, live phishing lists, RDAP.

Runs in a throwaway instance folder (never your PhishGuard data). Needs internet.

    .venv\\Scripts\\python scripts\\live_pipeline_check.py URL [URL ...]
"""
import sys
import tempfile
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from phishguard import db  # noqa: E402
from phishguard.rules import role, Finding  # noqa: E402
from phishguard.sandbox import Sandbox  # noqa: E402
from phishguard.services import ScanService, scan_row  # noqa: E402
from phishguard.worker import ScanWorker  # noqa: E402


def main(urls):
    inst = Path(tempfile.mkdtemp(prefix="pg-live-"))
    db.init_db(inst / "phishguard.db")
    svc = ScanService(inst / "phishguard.db", inst)
    svc.enable_lookups()
    print("downloading the phishing lists...", flush=True)
    svc.feeds.refresh(force=True)
    print("lists:", ", ".join(f"{s['name']} {s['count']:,}" for s in svc.feeds.status()["sources"]), flush=True)
    svc.worker = ScanWorker(lambda: Sandbox(inst / "shots", inst / "quarantine", route=svc.privacy_route),
                            on_done=svc.on_capture, on_start=svc.mark_running).start()
    assert svc.worker.ready.wait(60)
    for url in urls:
        t = time.monotonic()
        sid = svc.create_scan(url, "manual")["id"]
        while True:
            con = svc._con()
            d = scan_row(con, sid)
            con.close()
            if d["status"] in ("done", "partial", "failed"):
                break
            time.sleep(0.3)
        age = (d["page"] or {}).get("domain_age") or {}
        listed = any(f["code"] == "PHISH_LISTED" for f in d["findings"])
        # The same verdict without the lists, to show what the detection logic alone decides.
        from phishguard.rules import verdict
        rest = [Finding(f["code"], f["category"], f["weight"], f["message"], f["stage"])
                for f in d["findings"] if f["code"] != "PHISH_LISTED"]
        alone = verdict(rest)
        why = [f["message"] for f in d["findings"] if f["counted"] and f["code"] != "PHISH_LISTED"][:3]
        print(f"\n{url}\n  verdict {d['level'].upper()} {d['score']}  |  without lists: {alone['level'].upper()} "
              f"{alone['score']}  |  on a list: {'yes' if listed else 'no'}  |  site age: "
              f"{str(age.get('age_days', '-')) + ' days (' + str(age.get('source')) + ')' if age else 'not looked up'}"
              f"  |  {time.monotonic() - t:.1f} s")
        for w in why:
            print("   -", w)
    svc.worker.stop()


if __name__ == "__main__":
    main(sys.argv[1:])
