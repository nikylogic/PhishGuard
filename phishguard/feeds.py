"""Public phishing lists, kept on disk and checked locally.

The lists are downloaded every few hours and every lookup happens on this PC, so the links you
open are never sent to anyone. Sources (all free; reviewed Nov 2026):

  OpenPhish community feed   ~300 live phishing links, refreshed every 12 h (free, non-commercial)
  phishunt.io                ~1,000 live phishing links, refreshed hourly (CC0)
  Phishing.Database          ~390,000 phishing domains, community-maintained (MIT licence)

PhishTank, the best-known list, has been closed to new users since 2020.

Shared lists contain mistakes and shared hosts: Phishing.Database lists sites.google.com,
amazon.ie and gravatar.com, because someone once put a phishing page there. So a list can name a
whole website only when that website is not a popular site under its own name (Tranco top 10,000),
not a brand's real domain, and not a free hosting platform itself. Otherwise only the exact
address that was reported matches.
"""
from __future__ import annotations

import logging
import threading
import time
import urllib.request
from pathlib import Path
from urllib.parse import urlsplit

from . import intel

log = logging.getLogger("phishguard.feeds")

SOURCES = {
    "OpenPhish": ("https://openphish.com/feed.txt", "urls"),
    "phishunt.io": ("https://phishunt.io/feed.txt", "urls"),
    "Phishing.Database": ("https://raw.githubusercontent.com/Phishing-Database/Phishing.Database/master/"
                          "phishing-domains-ACTIVE.txt", "domains"),
}
# Lists whose terms allow only non-commercial use. PhishGuard's own licence is free for personal
# and non-commercial use; a business copy (PHISHGUARD_BUSINESS=1, see LICENSING.md) leaves these out
# unless the business has its own licence from the list's owner.
NONCOMMERCIAL_ONLY = frozenset({"OpenPhish"})


def sources_for(business: bool) -> dict:
    return {k: v for k, v in SOURCES.items() if not (business and k in NONCOMMERCIAL_ONLY)}


REFRESH = 6 * 3600
MAX_BYTES = 40 * 1024 * 1024


def download(url: str, timeout: float = 60) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard/1.0 (phishing list update)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:   # noqa: S310  fixed https sources
        data = r.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        raise OSError("list is unexpectedly large")
    return data


def _host_key(host: str) -> str:
    return (host or "").lower().rstrip(".").removeprefix("www.")


def url_key(url: str) -> str | None:
    """host/path?query with www., the scheme and a trailing slash removed."""
    try:
        u = urlsplit(url.strip())
    except ValueError:
        return None
    if u.scheme not in ("http", "https") or not u.hostname:
        return None
    key = _host_key(u.hostname) + (u.path.rstrip("/") or "")
    return key + (f"?{u.query}" if u.query else "")


def _suffixes(host: str):
    labels = host.split(".")
    for i in range(len(labels) - 1):
        yield ".".join(labels[i:])


def may_list_host(host: str) -> bool:
    """Can a list condemn this whole host? Not a popular site, a brand's own domain, a free
    hosting platform's own name or a restricted zone."""
    if not host or "." not in host:
        return False
    if host in intel.FREE_HOSTS or host in intel.FREE_HOST_NAMES:
        return False
    for s in _suffixes(host):
        if s in intel.ALL_BRAND_DOMAINS:
            return False
        if s in intel.POPULAR and s not in intel.FREE_HOSTS:
            return False
        if intel.is_restricted(s):
            return False
    return True


class Feeds:
    def __init__(self, folder: Path, fetch=download, sources=SOURCES):
        self.folder = Path(folder)
        self.fetch = fetch
        self.sources = dict(sources)
        self.hosts: dict[str, str] = {}      # host -> list name
        self.urls: dict[str, str] = {}       # url key -> list name
        self.state: dict[str, dict] = {}     # list name -> {count, updated, error}
        self.loaded = threading.Event()
        self._lock = threading.Lock()
        self._stop = threading.Event()

    # --- reading -----------------------------------------------------------------------------
    def _file(self, name: str) -> Path:
        return self.folder / (name.replace(" ", "_").replace(".", "_") + ".txt")

    def load(self) -> None:
        hosts, urls, state = {}, {}, {}
        for name, (_, kind) in self.sources.items():
            path = self._file(name)
            if not path.exists():
                state[name] = {"count": 0, "updated": None, "error": self.state.get(name, {}).get("error")}
                continue
            n = 0
            for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                if kind == "domains":
                    h = _host_key(line)
                    if may_list_host(h):
                        hosts.setdefault(h, name)
                        n += 1
                    continue
                key = url_key(line)
                if not key:
                    continue
                host = key.split("/", 1)[0].split("?", 1)[0]
                if may_list_host(host):
                    hosts.setdefault(host, name)
                else:
                    urls.setdefault(key, name)
                n += 1
            state[name] = {"count": n, "updated": path.stat().st_mtime,
                           "error": self.state.get(name, {}).get("error")}
        with self._lock:
            self.hosts, self.urls, self.state = hosts, urls, state
        self.loaded.set()

    def check(self, url: str) -> str | None:
        """The list that reports this address, or None."""
        key = url_key(url)
        if not key:
            return None
        host = key.split("/", 1)[0].split("?", 1)[0]
        hosts, urls = self.hosts, self.urls
        for s in _suffixes(host):
            if s in hosts:
                return hosts[s]
        if urls:
            if key in urls:
                return urls[key]
            base = key.split("?", 1)[0]
            parts = base.split("/")
            for i in range(len(parts), 1, -1):          # the reported page, or a folder above it
                cand = "/".join(parts[:i])
                if cand in urls:
                    return urls[cand]
        return None

    # --- updating ----------------------------------------------------------------------------
    def stale(self, name: str) -> bool:
        p = self._file(name)
        return not p.exists() or time.time() - p.stat().st_mtime > REFRESH

    def refresh(self, force: bool = False) -> dict:
        self.folder.mkdir(parents=True, exist_ok=True)
        for name, (url, kind) in self.sources.items():
            if not force and not self.stale(name):
                continue
            try:
                data = self.fetch(url)
                text = data.decode("utf-8", errors="replace")
                lines = [ln for ln in text.splitlines() if ln.strip() and not ln.startswith("#")]
                ok = (lambda ln: ln.startswith(("http://", "https://"))) if kind == "urls" else \
                     (lambda ln: "." in ln and " " not in ln.strip() and "<" not in ln)
                if not lines or sum(map(ok, lines[:200])) < min(len(lines), 200) * 0.9:
                    raise OSError("the list did not look like a list of addresses")
                tmp = self._file(name).with_suffix(".tmp")
                tmp.write_text(text, encoding="utf-8")
                tmp.replace(self._file(name))
                self.state.setdefault(name, {})["error"] = None
            except Exception as e:  # noqa: BLE001  keep the old copy; try again next time
                log.warning("phishing list %s not updated: %s", name, e)
                self.state.setdefault(name, {})["error"] = str(e)[:200]
        self.load()
        return self.status()

    def status(self) -> dict:
        return {"sources": [{"name": n, "count": s.get("count", 0), "updated": s.get("updated"),
                             "error": s.get("error")} for n, s in self.state.items()],
                "hosts": len(self.hosts), "urls": len(self.urls), "ready": self.loaded.is_set()}

    def start(self) -> "Feeds":
        """Load what is on disk, then keep the lists fresh in the background."""
        def run():
            try:
                self.load()
            except Exception:  # noqa: BLE001
                log.exception("phishing lists could not be read")
            while not self._stop.is_set():
                try:
                    self.refresh()
                except Exception:  # noqa: BLE001
                    log.exception("phishing list update failed")
                self._stop.wait(REFRESH)
        threading.Thread(target=run, name="pg-feeds", daemon=True).start()
        return self

    def stop(self):
        self._stop.set()
