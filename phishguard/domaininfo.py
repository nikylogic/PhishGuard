"""How old is this website?

Most phishing sites are days old: they are registered for one campaign and abandoned once they are
reported. Two free, public sources answer the question:

  RDAP     the registries' official replacement for WHOIS (structured JSON, no scraping). IANA
           publishes which server answers for each ending (.com, .in, .xyz ...).
  crt.sh   Certificate Transparency logs. Every HTTPS certificate is public, so the first one ever
           issued for a domain shows when it appeared online. Used when RDAP has no date.

Only the website's name (e.g. "example.com") is sent, never the full link, and the lookup goes
through Hide my IP's route when that is on. Popular sites, brands' own domains, restricted zones
(.gov.in, .bank.in) and free hosting platforms are never looked up: their age says nothing.
Answers are cached for a week.
"""
from __future__ import annotations

import json
import logging
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

from . import intel

log = logging.getLogger("phishguard.domaininfo")

BOOTSTRAP = "https://data.iana.org/rdap/dns.json"
RDAP_FALLBACK = "https://rdap.org/domain/"
CRTSH = "https://crt.sh/?q={d}&output=json&exclude=expired&deduplicate=Y"
TTL = 7 * 86400
NEG_TTL = 86400


def _parse_time(s: str) -> float | None:
    if not s:
        return None
    s = s.strip().replace("Z", "+00:00")
    for cut in (None, 19):
        try:
            t = datetime.fromisoformat(s if cut is None else s[:cut])
            if t.tzinfo is None:
                t = t.replace(tzinfo=timezone.utc)
            return t.timestamp()
        except ValueError:
            continue
    return None


def worth_asking(host: str, reg: str) -> bool:
    if not reg or "." not in reg or reg.replace(".", "").isdigit():
        return False
    if reg in intel.ALL_BRAND_DOMAINS or intel.is_restricted(reg) or intel.is_established(host, reg):
        return False
    return not intel.is_free_host(host, reg)


class DomainInfo:
    def __init__(self, folder: Path, get=None):
        """get(url, timeout, limit) -> (status, body bytes); services passes one that uses the
        Hide my IP route."""
        self.folder = Path(folder)
        self.get = get
        self._cache_file = self.folder / "domain-age.json"
        self._boot_file = self.folder / "rdap-bootstrap.json"
        self._lock = threading.Lock()
        try:
            self.cache = json.loads(self._cache_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.cache = {}
        self._servers: dict[str, str] | None = None

    # --- RDAP -----------------------------------------------------------------------------
    def _bootstrap(self) -> dict[str, str]:
        if self._servers is not None:
            return self._servers
        data = None
        try:
            if time.time() - self._boot_file.stat().st_mtime < 30 * 86400:
                data = json.loads(self._boot_file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            pass
        if data is None:
            status, body = self.get(BOOTSTRAP, 15, 2_000_000)
            if status != 200:
                raise OSError(f"RDAP bootstrap answered {status}")
            data = json.loads(body)
            self.folder.mkdir(parents=True, exist_ok=True)
            self._boot_file.write_bytes(body)
        servers = {}
        for tlds, urls in data.get("services", []):
            url = next((u for u in urls if u.startswith("https://")), urls[0] if urls else "")
            for t in tlds:
                servers[t.lower()] = url if url.endswith("/") else url + "/"
        self._servers = servers
        return servers

    def rdap_created(self, reg: str, timeout: float = 6) -> float | None:
        tld = reg.rsplit(".", 1)[-1]
        base = self._bootstrap().get(tld) or RDAP_FALLBACK.rsplit("domain/", 1)[0]
        status, body = self.get(f"{base}domain/{reg}", timeout, 400_000)
        if status != 200:
            return None
        data = json.loads(body)
        for ev in data.get("events", []):
            if (ev.get("eventAction") or "").lower() == "registration":
                return _parse_time(ev.get("eventDate") or "")
        return None

    def crtsh_first_seen(self, reg: str, timeout: float = 8) -> float | None:
        status, body = self.get(CRTSH.format(d=reg), timeout, 3_000_000)
        if status != 200:
            return None
        rows = json.loads(body or b"[]")
        times = [t for r in rows if (t := _parse_time(r.get("not_before") or ""))]
        return min(times) if times else None

    # --- the answer ----------------------------------------------------------------------
    def age(self, host: str, reg: str) -> dict:
        """{"age_days": n, "how": "registered" | "first seen online", "source": ...} or {}."""
        if self.get is None or not worth_asking(host, reg):
            return {}
        now = time.time()
        with self._lock:
            hit = self.cache.get(reg)
        if hit and now - hit["at"] < (TTL if hit.get("created") else NEG_TTL):
            return self._answer(hit, now)
        rec = {"at": now, "created": None, "source": None}
        try:
            rec["created"] = self.rdap_created(reg)
            rec["source"] = "RDAP" if rec["created"] else None
        except Exception as e:  # noqa: BLE001  any failure just means "unknown"
            log.info("RDAP lookup for %s failed: %s", reg, e)
        if not rec["created"]:
            try:
                rec["created"] = self.crtsh_first_seen(reg)
                rec["source"] = "crt.sh" if rec["created"] else None
            except Exception as e:  # noqa: BLE001
                log.info("crt.sh lookup for %s failed: %s", reg, e)
        with self._lock:
            self.cache[reg] = rec
            if len(self.cache) > 5000:
                for k in sorted(self.cache, key=lambda k: self.cache[k]["at"])[:1000]:
                    self.cache.pop(k, None)
            try:
                self.folder.mkdir(parents=True, exist_ok=True)
                self._cache_file.write_text(json.dumps(self.cache), encoding="utf-8")
            except OSError:
                pass
        return self._answer(rec, now)

    @staticmethod
    def _answer(rec: dict, now: float) -> dict:
        if not rec.get("created"):
            return {}
        days = max(0, int((now - rec["created"]) // 86400))
        how = "registered" if rec["source"] == "RDAP" else "first seen online"
        return {"age_days": days, "how": how, "source": rec["source"], "created": rec["created"]}
