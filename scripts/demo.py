"""Run PhishGuard with demo data, for the walkthrough, screenshots and the viva.

    python scripts/demo.py              fill a demo database, then serve the app on 127.0.0.1:5157

It starts the local fake attack websites (bank.test, evil.test, ...) and points the
sandbox at them, and also inspects a few real public websites. Logins:
    admin / airlock-admin-1        analyst / airlock-analyst-1
Nothing here touches your real PhishGuard data: it uses the folder instance-demo/.
"""
import os
import shutil
import sys
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

from waitress import serve  # noqa: E402

from phishguard import create_app  # noqa: E402
from phishguard.auth import create_user  # noqa: E402
from phishguard.db import connect, init_db  # noqa: E402
from phishguard.sandbox import Sandbox  # noqa: E402
from phishguard.services import ScanService  # noqa: E402
from phishguard.worker import ScanWorker  # noqa: E402
from tests.sites.server import FakeResolver, FakeSites  # noqa: E402

INST = ROOT / "instance-demo"
PORT = int(os.environ.get("PHISHGUARD_PORT") or 5157)

DEMO = [
    ("plain.test", "/plain"),
    ("bank.test", "/bank"),
    ("files.test", "/invoice"),
    ("evil.test", "/clickfix"),
    ("short.test", "/go"),
    ("plain.test", "/fingerprint"),
    ("evil.test", "/scam"),
    ("evil.test", "/msdt"),
    ("plain.test", "/injection"),
    ("trusted.test", "/out?url=http://evil.test{port}/evil"),
    ("evil.test", "/miner"),
]
REAL = ["https://www.wikipedia.org/", "https://example.com/?utm_source=newsletter&utm_medium=email&fbclid=IwAR0demo"]


def main(fresh=True):
    if fresh and INST.exists():
        shutil.rmtree(INST)
    INST.mkdir(exist_ok=True)
    db_path = INST / "phishguard.db"
    init_db(str(db_path))

    sites = FakeSites()
    sites.start()
    port_part = f":{sites.port}"
    service = ScanService(str(db_path), INST)
    worker = ScanWorker(lambda: Sandbox(INST / "shots", INST / "quarantine", resolver_factory=FakeResolver,
                                        exempt={("127.0.0.1", sites.port)}, extra_args=sites.chrome_args()),
                        on_done=service.on_capture, on_start=service.mark_running).start()
    service.worker = worker
    app = create_app({"INSTANCE_DIR": str(INST), "SERVICE": service})

    con = connect(str(db_path))
    if not con.execute("SELECT 1 FROM users").fetchone():
        admin = create_user(con, "admin", "airlock-admin-1", "admin")
        create_user(con, "analyst", "airlock-analyst-1", "analyst")
        con.execute("INSERT INTO domain_lists(domain, kind, note, added_by) VALUES ('trusted.test', 'allow', 'demo: our own test site', ?)", (admin,))
        con.execute("INSERT INTO domain_lists(domain, kind, note, added_by) VALUES ('wikipedia.org', 'allow', 'demo', ?)", (admin,))
        con.execute("INSERT INTO domain_lists(domain, kind, note, added_by) VALUES ('paypa1-secure.top', 'block', 'demo', ?)", (admin,))
        con.commit()
        service.write_allowlist_cache()
        print("Inspecting demo links (about a minute)...", flush=True)
        for host, path in DEMO:
            url = f"http://{host}{port_part}{path.replace('{port}', port_part)}"
            service.create_scan(url, "launcher")
        for url in REAL:
            service.create_scan(url, "manual", admin)
        service.create_scan("http://paypa1-secure.top/login", "launcher")      # blocked instantly
        while con.execute("SELECT COUNT(*) FROM scans WHERE status IN ('queued', 'running')").fetchone()[0]:
            time.sleep(1)
    con.close()
    print(f"PhishGuard demo at http://127.0.0.1:{PORT}  (admin / airlock-admin-1)", flush=True)
    serve(app, host="127.0.0.1", port=PORT, threads=8, ident="PhishGuard")


if __name__ == "__main__":
    main(fresh="--keep" not in sys.argv)
