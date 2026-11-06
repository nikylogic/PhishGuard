"""The scan pipeline: queue a link, inspect it, judge it, store it.

    create_scan()  -> URL rules run at once (under 1 ms), the row is saved, the
                      sandbox job is queued, and the caller gets the id at once.
    _finish()      -> runs on the sandbox thread when the capture is ready:
                      page rules + AI Guard -> verdict saved (status done).
    _llm()         -> optional, on its own thread, AFTER the verdict is saved;
                      it can only raise the score.
"""
import json
import logging
import secrets
import shutil
import threading
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from urllib.parse import urlsplit

from . import browser
from . import privacy
from .domaininfo import DomainInfo
from .feeds import Feeds
from . import db as dbmod
from . import pagerules  # noqa: F401 - registers the page rules
# The AI Guard is imported in _load_guard (background), not here.
from .intel import Intel
from .llm import Reviewer, apply_opinion, provider_from_settings
from .pagerules import analyse
from .rules import Finding, make, role, url_findings, verdict
from .sandbox import Capture
from .urltools import UnsafeURL, domain_matches, parse, registrable_domain

log = logging.getLogger("phishguard.service")


def get_settings(con) -> dict:
    return {r["key"]: r["value"] for r in con.execute("SELECT key, value FROM settings")}


def get_lists(con) -> tuple[set[str], set[str]]:
    allow, block = set(), set()
    for r in con.execute("SELECT domain, kind FROM domain_lists"):
        (allow if r["kind"] == "allow" else block).add(r["domain"])
    return allow, block


class ScanService:
    def _load_guard(self):
        try:
            from .guard.guard import get_guard  # noqa: PLC0415 - imported here so start-up stays fast
            self._guard = get_guard()
        except Exception:  # noqa: BLE001 - checks still work without the AI Guard
            log.exception("AI Guard did not load")
        finally:
            self._guard_ready.set()

    @property
    def guard(self):
        self._guard_ready.wait(60)
        return self._guard

    @guard.setter
    def guard(self, value):
        self._guard = value
        self._guard_ready.set()

    def __init__(self, db_path, instance_dir, worker=None, intel=None, guard=None, reviewer_factory=None):
        self.db_path = db_path
        self.instance = Path(instance_dir)
        self.worker = worker                  # ScanWorker, or a fake one in tests
        self.intel = intel or Intel.load(extra_rows=self._intel_rows())
        # The AI Guard model (scikit-learn) takes about a second and a half to load. It is only needed
        # once a page has been captured, so it loads in the background and the engine answers at once.
        self._guard = guard
        self._guard_ready = threading.Event()
        if guard is not None:
            self._guard_ready.set()
        else:
            threading.Thread(target=self._load_guard, name="pg-guard-load", daemon=True).start()
        self.reviewer_factory = reviewer_factory or (lambda settings: Reviewer(provider_from_settings(settings)))
        self.llm_pool = ThreadPoolExecutor(max_workers=1, thread_name_prefix="pg-llm")
        # Phishing lists and domain age (feeds.py, domaininfo.py). Off until enable_lookups(), so
        # tests never touch the network.
        self.feeds = None
        self.domains = None
        self._facts: dict = {}
        self.lookup_pool = ThreadPoolExecutor(max_workers=2, thread_name_prefix="pg-lookup")
        self.lock = threading.Lock()
        self.recover()
        self.write_allowlist_cache()
        self.write_browser_cache()
        self.tor = privacy.Tor(self.instance)
        self.warp_finder = privacy.find_warp
        self.apply_privacy()

    def recover(self):
        """After a restart, nothing is still running: close off unfinished scans honestly."""
        con = self._con()
        try:
            con.execute("UPDATE scans SET status = 'failed', level = CASE WHEN level = 'pending' THEN 'caution' "
                        "ELSE level END, error = 'PhishGuard was closed before this check finished.', "
                        "finished_at = datetime('now') WHERE status IN ('queued', 'running')")
            con.commit()
        finally:
            con.close()

    def _con(self):
        return dbmod.connect(self.db_path)

    def _intel_rows(self):
        con = self._con()
        try:
            return [(r["kind"], r["value"]) for r in con.execute("SELECT kind, value FROM intel_lists")]
        finally:
            con.close()

    # --- lists ------------------------------------------------------------------------------
    def write_allowlist_cache(self):
        """The launcher reads this small file, so trusted links open without any database work."""
        con = self._con()
        try:
            allow, _ = get_lists(con)
        finally:
            con.close()
        tmp = self.instance / "allowlist.txt.tmp"
        tmp.write_text("\n".join(sorted(allow)) + "\n", encoding="utf-8")
        tmp.replace(self.instance / "allowlist.txt")

    def write_browser_cache(self):
        """The launcher opens trusted links itself, so it needs the real browser's program file."""
        con = self._con()
        try:
            exe = browser.choose(get_settings(con).get("browser_path")) or ""
        finally:
            con.close()
        tmp = self.instance / "browser.txt.tmp"
        tmp.write_text(exe + "\n", encoding="utf-8")
        tmp.replace(self.instance / "browser.txt")

    # --- history: how long checks are kept --------------------------------------------------
    KEEP_CHOICES = ("30", "90", "365", "0")         # days; 0 = keep everything
    KEEP_DEFAULT = "90"

    def keep_days(self) -> int:
        v = self.settings().get("keep_days") or self.KEEP_DEFAULT
        return int(v) if v in self.KEEP_CHOICES else int(self.KEEP_DEFAULT)

    def purge(self, days: int | None = None, everything: bool = False) -> int:
        """Delete finished checks older than `days` (default: the setting) with their screenshots and
        quarantined files. `everything` deletes all finished checks. Running checks are never touched;
        the audit log is kept. Returns how many checks were deleted."""
        days = self.keep_days() if days is None else days
        if not everything and days <= 0:
            return 0
        con = self._con()
        try:
            where = "status IN ('done', 'partial', 'failed')"
            args: tuple = ()
            if not everything:
                where += " AND created_at < datetime('now', ?)"
                args = (f"-{int(days)} days",)
            rows = con.execute(f"SELECT id, screenshot FROM scans WHERE {where}", args).fetchall()   # noqa: S608 - fixed text
            for r in rows:
                if r["screenshot"]:
                    (self.instance / "shots" / Path(r["screenshot"]).name).unlink(missing_ok=True)
                shutil.rmtree(self.instance / "quarantine" / str(int(r["id"])), ignore_errors=True)
            con.executemany("DELETE FROM scans WHERE id = ?", [(r["id"],) for r in rows])
            con.commit()
        finally:
            con.close()
        return len(rows)

    def storage(self) -> dict:
        """How much disk the history uses."""
        def size(path: Path) -> int:
            if path.is_file():
                return path.stat().st_size
            return sum(f.stat().st_size for f in path.rglob("*") if f.is_file()) if path.exists() else 0
        con = self._con()
        try:
            n = con.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
        finally:
            con.close()
        db = sum(size(Path(str(self.db_path) + x)) for x in ("", "-wal"))
        return {"checks": n, "bytes": db + size(self.instance / "shots") + size(self.instance / "quarantine"),
                "folder": str(self.instance)}

    def start_housekeeping(self):
        """Apply the history setting now and once a day."""
        def loop():
            while not self._stop_housekeeping.wait(0 if not self._housekept else 24 * 3600):
                self._housekept = True
                try:
                    n = self.purge()
                    if n:
                        log.info("history: deleted %d checks older than %d days", n, self.keep_days())
                except Exception:  # noqa: BLE001
                    log.exception("history clean-up failed")
        self._housekept = False
        self._stop_housekeeping = threading.Event()
        threading.Thread(target=loop, name="pg-housekeeping", daemon=True).start()
        return self

    # --- Hide my IP ----------------------------------------------------------------------------
    def settings(self) -> dict:
        con = self._con()
        try:
            return get_settings(con)
        finally:
            con.close()

    def privacy_route(self):
        """Called by the sandbox before every check (on its own thread)."""
        return privacy.route(self.settings(), self.tor, self.warp_finder)

    def apply_privacy(self):
        """Start Tor in the background when it is the chosen route; stop it when it is not."""
        if self.settings().get("privacy_mode") == "tor":
            if self.tor.installed():
                try:
                    self.tor.start()
                except Exception:  # noqa: BLE001 - the status shows the problem; checks fail closed
                    log.exception("Tor did not start")
        else:
            self.tor.stop()

    # --- phishing lists and domain age -----------------------------------------------------------
    def enable_lookups(self, feeds=None, domains=None):
        if feeds is None:
            import os  # noqa: PLC0415
            from .feeds import sources_for  # noqa: PLC0415
            business = os.environ.get("PHISHGUARD_BUSINESS") == "1"
            feeds = Feeds(self.instance / "feeds", sources=sources_for(business)).start()
        self.feeds = feeds
        self.domains = domains or DomainInfo(self.instance / "lookups", get=self._lookup_get)
        return self

    def _lookup_get(self, url, timeout, limit):
        """Domain lookups take the same route as the sandbox. If Hide my IP is on but its route
        is down, nothing is sent (privacy.Unavailable): the age is simply unknown."""
        return privacy.http_get(self.privacy_route(), url, timeout, limit)

    def _start_facts(self, sid, host, reg):
        if self.domains is not None:
            self._facts[sid] = (reg, self.lookup_pool.submit(self.domains.age, host, reg))

    def _facts_for(self, sid, final_url) -> dict:
        early = self._facts.pop(sid, None)
        if self.domains is None:
            return {}
        try:
            host, reg = (urlsplit(final_url).hostname or ""), registrable_domain(final_url)
        except ValueError:
            return {}
        try:
            if early and early[0] == reg:
                return early[1].result(timeout=15)
            return self.domains.age(host, reg)
        except Exception:  # noqa: BLE001  unknown age is fine; never block the verdict
            return {}

    # --- create -------------------------------------------------------------------------------
    def create_scan(self, raw_url: str, source: str, user_id=None) -> dict:
        p = parse(raw_url)                    # raises UnsafeURL for non-web links
        con = self._con()
        try:
            allow, block = get_lists(con)
            findings = url_findings(p, blocklist=block)
            v = verdict(findings)
            ticket = secrets.token_urlsafe(24)
            blocked = any(f.code == "BLOCKLISTED" for f in findings)
            cur = con.execute(
                "INSERT INTO scans(url, final_url, domain, source, status, score, level, s_phishing, s_malware, "
                "s_tracking, s_abuse, user_id, ticket) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (p.url, p.url, p.registrable, source, "done" if blocked else "queued", v["score"],
                 v["level"] if blocked else "pending", *[v["subs"][c] for c in ("phishing", "malware", "tracking", "abuse")],
                 user_id, ticket))
            sid = cur.lastrowid
            self._save_findings(con, sid, findings)
            if blocked:
                con.execute("UPDATE scans SET finished_at = datetime('now') WHERE id = ?", (sid,))
            con.commit()
        finally:
            con.close()
        if not blocked and self.worker is not None:
            # A blocked site is never opened, not even in the sandbox.
            self._start_facts(sid, p.host, p.registrable)
            self.worker.submit(p.url, sid)
        return {"id": sid, "ticket": ticket, "allowlisted": any(domain_matches(p.host, d) for d in allow),
                "blocked": blocked}

    @staticmethod
    def _save_findings(con, sid, findings, replace_stage=None):
        if replace_stage:
            con.execute("DELETE FROM findings WHERE scan_id = ? AND stage IN (%s)" %
                        ",".join("?" * len(replace_stage)), (sid, *replace_stage))
        con.executemany(
            "INSERT INTO findings(scan_id, stage, category, code, weight, message) VALUES (?, ?, ?, ?, ?, ?)",
            [(sid, f.stage, f.category, f.code, f.weight, f.message) for f in findings])

    def mark_running(self, sid):
        con = self._con()
        try:
            con.execute("UPDATE scans SET status = 'running' WHERE id = ? AND status = 'queued'", (sid,))
            con.commit()
        finally:
            con.close()

    # --- finish (sandbox thread) ---------------------------------------------------------------
    def on_capture(self, sid, cap: Capture):
        try:
            self._finish(sid, cap)
        except Exception:   # noqa: BLE001 - never leave a scan stuck in "running"
            log.exception("finishing scan %s failed", sid)
            con = self._con()
            con.execute("UPDATE scans SET status = 'failed', error = 'Internal error while judging the page.', "
                        "finished_at = datetime('now') WHERE id = ?", (sid,))
            con.commit()
            con.close()

    def _finish(self, sid, cap: Capture):
        c = cap.to_dict()
        con = self._con()
        try:
            allow, block = get_lists(con)
            extra, guard_result = [], None
            if self.guard is not None:
                hidden = self.guard.check(c.get("hidden_text") or "")
                visible = self.guard.check(c.get("visible_text") or "")
                guard_result = max(hidden, visible, key=lambda r: r["score"])
                # The model alone flags cookie banners and menus on about a third of real pages
                # (measured on 413 pages, Nov 2026). It counts only when an explicit injection
                # phrase ("ignore previous instructions") confirms it; the score is still shown.
                if hidden["label"] == "injection" and hidden.get("keywords"):
                    extra.append(make("PROMPT_INJECTION", "guard"))
                for src_name, r in (("hidden", hidden), ("visible", visible)):
                    if r["label"] == "injection" and r.get("keywords"):
                        con.execute("INSERT INTO guard_events(scan_id, source, text_snippet, score, label) "
                                    "VALUES (?, 'page', ?, ?, ?)", (sid, f"[{src_name}] {r['chunk'][:280]}",
                                                                    r["score"], r["label"]))
            facts = self._facts_for(sid, c.get("final_url") or c.get("url") or "")
            v = analyse(c, self.intel, allowlist=allow, blocklist=block, extra=extra, facts=facts, feeds=self.feeds)
            status = cap.status if cap.status in ("done", "partial", "failed") else "done"
            if status == "failed" and v["score"] == 0:
                level = "caution"          # we could not look inside; never stamp CLEAR blind
            else:
                level = v["level"]
            page = {k: c.get(k) for k in ("forms", "downloads", "protocol_attempts", "blocked", "link_schemes",
                                          "tls", "timings", "http_status", "request_domains", "route")}
            page["events"] = c.get("events", [])[:100]
            page["visible_text"] = (c.get("visible_text") or "")[:2000]
            page["hidden_text"] = (c.get("hidden_text") or "")[:2000]
            page["guard"] = guard_result
            page["privacy"] = v["privacy"]
            page["domain_age"] = facts
            con.execute(
                "UPDATE scans SET final_url = ?, status = ?, score = ?, level = ?, s_phishing = ?, s_malware = ?, "
                "s_tracking = ?, s_abuse = ?, title = ?, screenshot = ?, redirect_json = ?, page_json = ?, "
                "guard_score = ?, error = ?, finished_at = datetime('now') WHERE id = ?",
                (c.get("final_url") or c["url"], status, v["score"], level,
                 *[v["subs"][k] for k in ("phishing", "malware", "tracking", "abuse")],
                 (c.get("title") or "")[:300], c.get("screenshot") or None, json.dumps(c.get("redirects") or []),
                 json.dumps(page), guard_result["score"] if guard_result else None, c.get("error") or None, sid))
            self._save_findings(con, sid, v["findings"], replace_stage=("url", "page", "guard"))
            for d in c.get("downloads") or []:
                con.execute("INSERT INTO downloads(scan_id, filename, declared_type, real_type, size, sha256, verdict, "
                            "quarantine_path) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                            (sid, d.get("filename"), d.get("filename", "").rsplit(".", 1)[-1], d.get("real_type"),
                             d.get("size"), d.get("sha256"), "executable" if d.get("executable") else "file",
                             d.get("quarantine_path")))
            pv = v["privacy"]
            con.execute("INSERT OR REPLACE INTO privacy(scan_id, trackers_json, fingerprint_json, ip_logger, webrtc, "
                        "params_removed_json) VALUES (?, ?, ?, ?, ?, ?)",
                        (sid, json.dumps(pv["trackers"]), json.dumps(pv["fingerprinting"]), int(pv["ip_logger"]),
                         int(pv["webrtc"]), json.dumps(pv["params_removed"])))
            con.commit()
            settings = get_settings(con)
        finally:
            con.close()
        if (settings.get("llm_provider") or "none") != "none":
            self.llm_pool.submit(self._llm, sid, c, v["findings"], guard_result, settings)

    # --- LLM (own thread, after the verdict is saved) ---------------------------------------------
    def _llm(self, sid, c, findings: list[Finding], guard_result, settings):
        try:
            reviewer = self.reviewer_factory(settings)
            op = reviewer.review(dict(c, findings=findings), guard_result)
            if op is None:
                return
            v = apply_opinion(findings, op)
            con = self._con()
            try:
                con.execute("UPDATE scans SET llm_json = ?, score = ?, level = CASE WHEN level = 'pending' THEN level "
                            "ELSE ? END, s_phishing = ?, s_malware = ?, s_tracking = ?, s_abuse = ? WHERE id = ?",
                            (json.dumps({"risk": op.risk, "category": op.category, "reasons": op.reasons,
                                         "provider": op.provider}),
                             v["score"], v["level"], *[v["subs"][k] for k in ("phishing", "malware", "tracking", "abuse")],
                             sid))
                added = [f for f in v["findings"] if f.code == "LLM_OPINION"]
                self._save_findings(con, sid, added, replace_stage=("llm",))
                con.commit()
            finally:
                con.close()
        except Exception:   # noqa: BLE001
            log.exception("LLM review failed for scan %s", sid)


def scan_row(con, sid: int) -> dict | None:
    r = con.execute("SELECT * FROM scans WHERE id = ?", (sid,)).fetchone()
    if not r:
        return None
    d = dict(r)
    d["findings"] = [dict(f) for f in con.execute(
        "SELECT stage, category, code, weight, message FROM findings WHERE scan_id = ? ORDER BY weight DESC", (sid,))]
    # Which findings decided the verdict. Tracking is shown as privacy; weak signals count only
    # next to a real threat (see rules.verdict).
    roles = [role(Finding(f["code"], f["category"], f["weight"], f["message"], f["stage"])) for f in d["findings"]]
    threat = any(r == "threat" and f["weight"] > 0 for r, f in zip(roles, d["findings"]))
    for r, f in zip(roles, d["findings"]):
        f["role"] = r
        f["counted"] = r == "threat" or (r == "supporting" and threat)
    d["redirects"] = json.loads(d.pop("redirect_json") or "[]")
    d["page"] = json.loads(d.pop("page_json") or "{}")
    d["llm"] = json.loads(d.pop("llm_json") or "null")
    d.pop("ticket", None)
    return d


def is_unsafe(raw_url: str) -> str | None:
    try:
        parse(raw_url)
        return None
    except UnsafeURL as e:
        return str(e)
