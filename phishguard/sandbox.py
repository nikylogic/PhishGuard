"""The sandbox: open a link in an isolated, throwaway browser and record what it does.

One Chrome process stays warm. Every capture gets a brand-new incognito context
(no cookies, no history, nothing from the user's real profile) that is closed
straight afterwards. All Playwright calls must happen on ONE thread; worker.py
makes sure of that.
"""
import ipaddress
import json
import secrets
import shutil
import socket
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

from playwright.sync_api import Error as PWError
from playwright.sync_api import TimeoutError as PWTimeout
from playwright.sync_api import sync_playwright

from . import filetypes
from . import privacy
from .egress import EgressProxy
from .urltools import registrable_domain

HOOKS_JS = (Path(__file__).with_name("hooks.js")).read_text(encoding="utf-8")
NO_WEBRTC_JS = """(() => {
  for (const name of ["RTCPeerConnection", "webkitRTCPeerConnection", "RTCDataChannel", "RTCIceCandidate",
                      "RTCSessionDescription", "RTCRtpSender", "RTCRtpReceiver", "RTCRtpTransceiver"]) {
    try { Object.defineProperty(window, name, { value: undefined, configurable: false, writable: false }); } catch (e) {}
  }
  try {
    if (navigator.mediaDevices) {
      Object.defineProperty(navigator, "mediaDevices", { value: undefined, configurable: false });
    }
  } catch (e) {}
})();"""

SAFE_SUB_SCHEMES = {"http", "https", "data", "blob", "about"}
MAX_TEXT = 8000
MAX_EVENTS = 300
MAX_DOWNLOAD = 25 * 1024 * 1024
UA = ("Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 "
      "(KHTML, like Gecko) Chrome/130.0.0.0 Safari/537.36")

EXTRACT_JS = r"""
() => {
  const LIM = 8000;
  let vis = "", hid = "";
  const push = (which, t) => {
    if (which === "v" && vis.length < LIM) vis += t + " ";
    if (which === "h" && hid.length < LIM) hid += t + " ";
  };
  const hiddenCache = new Map();
  const isHidden = (el) => {
    if (hiddenCache.has(el)) return hiddenCache.get(el);
    let h = false;
    for (let e = el; e && e.nodeType === 1; e = e.parentElement) {
      const s = getComputedStyle(e);
      if (s.display === "none" || s.visibility === "hidden" || parseFloat(s.opacity) === 0 ||
          parseFloat(s.fontSize) < 2 || e.hidden) { h = true; break; }
    }
    if (!h) {
      const r = el.getBoundingClientRect();
      if (r.width < 2 || r.height < 2 || r.right <= 0 || r.bottom <= 0) h = true;
      const s = getComputedStyle(el);
      if (s.color && s.color === s.backgroundColor) h = true;
    }
    hiddenCache.set(el, h);
    return h;
  };
  const root = document.body || document.documentElement;
  if (root) {
    const w = document.createTreeWalker(root, NodeFilter.SHOW_TEXT | NodeFilter.SHOW_COMMENT);
    let n;
    while ((n = w.nextNode())) {
      const t = (n.nodeValue || "").replace(/\s+/g, " ").trim();
      if (!t) continue;
      if (n.nodeType === 8) { push("h", t); continue; }
      const p = n.parentElement;
      if (!p || ["SCRIPT", "STYLE", "NOSCRIPT", "TEMPLATE"].includes(p.tagName)) continue;
      push(isHidden(p) ? "h" : "v", t);
      if (vis.length >= LIM && hid.length >= LIM) break;
    }
  }
  const forms = [...document.forms].slice(0, 20).map(f => ({
    action: f.action || location.href,
    method: (f.method || "get").toLowerCase(),
    password: !!f.querySelector("input[type=password]"),
    inputs: [...f.elements].slice(0, 25).map(e => (e.type || e.tagName || "").toLowerCase()),
  }));
  const loosePw = [...document.querySelectorAll("input[type=password]")].filter(i => !i.form).length;
  const links = [...document.querySelectorAll("a[href], iframe[src], form[action]")].slice(0, 2000)
    .map(e => e.getAttribute("href") || e.getAttribute("src") || e.getAttribute("action") || "");
  const schemes = [...new Set(links.map(h => { const m = /^\s*([a-z][a-z0-9+.\-]*):/i.exec(h); return m ? m[1].toLowerCase() : ""; })
                        .filter(Boolean))];
  let inline = "";
  for (const s of document.scripts) { if (!s.src && inline.length < 200000) inline += (s.text || "").slice(0, 50000) + "\n"; }
  return { visible: vis.trim().slice(0, LIM), hidden: hid.trim().slice(0, LIM), forms, loose_password_fields: loosePw,
           link_schemes: schemes, inline_script: inline, title: document.title || "" };
}
"""


@dataclass
class Capture:
    url: str
    final_url: str = ""
    status: str = "done"            # done | partial | failed
    error: str = ""
    title: str = ""
    http_status: int | None = None
    redirects: list = field(default_factory=list)       # [{url, status, kind}]
    screenshot: str = ""
    visible_text: str = ""
    hidden_text: str = ""
    forms: list = field(default_factory=list)
    loose_password_fields: int = 0
    link_schemes: list = field(default_factory=list)
    inline_script: str = ""
    downloads: list = field(default_factory=list)       # [{filename, url, size, sha256, ...}]
    events: list = field(default_factory=list)          # hook reports
    blocked: list = field(default_factory=list)         # [{url, reason}]
    protocol_attempts: list = field(default_factory=list)
    request_domains: list = field(default_factory=list)
    tls: dict = field(default_factory=dict)
    timings: dict = field(default_factory=dict)
    route: str = ""                                     # "Tor", "Cloudflare WARP", "Your proxy" or "" (direct)

    def to_dict(self):
        return asdict(self)

    def to_json(self):
        return json.dumps(self.to_dict())


class Resolver:
    """Resolve host names once per capture. Tests swap this for a fake one."""

    def __init__(self):
        self.cache = {}

    def ips(self, host: str) -> list[str]:
        if host in self.cache:
            return self.cache[host]
        try:
            ipaddress.ip_address(host.strip("[]"))
            out = [host.strip("[]")]
        except ValueError:
            try:
                out = sorted({ai[4][0] for ai in socket.getaddrinfo(host, None)})
            except (socket.gaierror, UnicodeError, OSError):
                out = []
        self.cache[host] = out
        return out


class Sandbox:
    """Owns the warm browser. Not thread-safe: use from one thread only."""

    def __init__(self, shots_dir, quarantine_dir, *, nav_timeout=15.0, total_timeout=20.0,
                 settle=1.5, resolver_factory=Resolver, exempt=(), extra_args=(),
                 channel="chrome", route=None):
        self.shots_dir = Path(shots_dir)
        self.quarantine_dir = Path(quarantine_dir)
        self.nav_timeout = nav_timeout
        self.total_timeout = total_timeout
        self.settle = settle
        self.extra_args = list(extra_args)
        self.channel = channel
        self.route = route              # Hide my IP: returns the route for the next check, or None (privacy.py)
        # Every connection the sandbox makes goes through this gatekeeper (see egress.py).
        self.egress = EgressProxy(resolver_factory, exempt=exempt).start()
        self._pw = None
        self.browser = None
        self.launches = 0

    # --- browser lifecycle ---------------------------------------------------------
    def start(self):
        if self._pw is None:
            self._pw = sync_playwright().start()
        args = ["--no-first-run", "--no-default-browser-check", "--disable-background-networking",
                "--disable-sync", "--disable-extensions", "--proxy-bypass-list=<-loopback>",
                *self.extra_args]
        # "<-loopback>" removes Chrome's built-in exception for localhost, so even
        # 127.0.0.1 must go through the gatekeeper (and gets refused there).
        proxy = {"server": self.egress.server, "bypass": "<-loopback>"}
        # Chrome if installed, else Microsoft Edge (on every Windows 10/11 PC), else Playwright's Chromium.
        channels = [c for c in (self.channel, "msedge") if c] + [None]
        for i, channel in enumerate(dict.fromkeys(channels)):
            try:
                opts = {"channel": channel} if channel else {}
                self.browser = self._pw.chromium.launch(headless=True, args=args, proxy=proxy, **opts)
                break
            except PWError:
                if i == len(dict.fromkeys(channels)) - 1:
                    raise
        self.launches += 1

    def ensure(self):
        if self.browser is None or not self.browser.is_connected():
            self.browser = None
            self.start()

    def close(self):
        try:
            if self.browser:
                self.browser.close()
        except PWError:
            pass
        self.browser = None
        if self._pw:
            self._pw.stop()
            self._pw = None
        self.egress.stop()

    # --- the capture -------------------------------------------------------------------
    def capture(self, url: str, scan_id: int | str) -> Capture:
        self.ensure()
        cap = Capture(url=url)
        t0 = time.monotonic()
        upstream = None
        if self.route is not None:
            try:
                upstream = self.route()
            except privacy.Unavailable as e:
                # Fail closed: Hide my IP is on but cannot be used, so the page is not opened at all.
                self.egress.begin_scan()
                return Capture(url=url, final_url=url, status="failed", error=str(e), route="unavailable")
        self.egress.begin_scan(upstream)
        cap.route = upstream.label if upstream else ""
        qdir = self.quarantine_dir / str(scan_id)
        binding = "__pg_" + secrets.token_hex(6)

        ctx = self.browser.new_context(
            accept_downloads=True, viewport={"width": 1366, "height": 768},
            user_agent=UA, locale="en-US", timezone_id="UTC" if upstream else "Asia/Kolkata",
            service_workers="block", java_script_enabled=True, permissions=[],
            bypass_csp=False, ignore_https_errors=False)
        try:
            def on_report(_source, payload):
                if len(cap.events) < MAX_EVENTS:
                    try:
                        cap.events.append(json.loads(payload))
                    except (ValueError, TypeError):
                        pass

            ctx.expose_binding(binding, on_report)
            ctx.add_init_script(HOOKS_JS.replace("__PG_BINDING__", binding))
            if upstream:
                # WebRTC talks UDP straight past any proxy, and a STUN server would then see this PC's
                # real address. With Hide my IP on, pages get no WebRTC at all (every frame).
                ctx.add_init_script(NO_WEBRTC_JS)

            page = ctx.new_page()
            main_navs: list[str] = []

            def on_request(req):
                scheme = urlsplit(req.url).scheme.lower()
                if scheme not in SAFE_SUB_SCHEMES and scheme not in ("ws", "wss"):
                    # Attempts to launch a Windows app (ms-msdt:, search-ms: ...). The headless
                    # sandbox has no app handlers, so these are aborted; we record them.
                    if len(cap.protocol_attempts) < 50:
                        cap.protocol_attempts.append({"scheme": scheme, "url": req.url[:300]})

            def on_frame_nav(frame):
                if frame == page.main_frame and frame.url not in ("about:blank",):
                    main_navs.append(frame.url)

            def on_console(msg):
                text = msg.text
                if "launch '" in text:
                    seg = text.split("launch '", 1)[1].split("'", 1)[0]
                    sch = seg.split(":", 1)[0].lower()
                    if not any(p["url"] == seg[:300] for p in cap.protocol_attempts):
                        cap.protocol_attempts.append({"scheme": sch, "url": seg[:300]})

            downloads = []
            page.on("request", on_request)
            page.on("framenavigated", on_frame_nav)
            page.on("console", on_console)
            page.on("download", lambda d: downloads.append(d))
            page.on("popup", lambda p: p.close())

            response = None
            try:
                response = page.goto(url, wait_until="load", timeout=self.nav_timeout * 1000)
            except PWTimeout:
                cap.status, cap.error = "partial", f"The page did not finish loading within {self.nav_timeout:.0f} s."
                # Stop the pending navigation, otherwise later calls wait for it to finish.
                try:
                    ctx.new_cdp_session(page).send("Page.stopLoading")
                except PWError:
                    pass
            except PWError as e:
                msg = str(e).split("\n")[0]
                if "Download is starting" in msg:
                    pass
                elif "ERR_BLOCKED_BY_CLIENT" in msg:
                    cap.status, cap.error = "failed", "PhishGuard blocked this address (it points into a private network)."
                elif "ERR_NAME_NOT_RESOLVED" in msg:
                    cap.status, cap.error = "failed", "This website does not exist (its name cannot be found)."
                elif "ERR_CERT" in msg:
                    cap.status, cap.error = "failed", "The website's security certificate is invalid."
                else:
                    cap.status, cap.error = "failed", "The page could not be opened: " + msg[:200]
            cap.timings["navigate"] = round(time.monotonic() - t0, 3)

            # Let late scripts, timers and JS redirects run, within the total budget.
            remaining = self.total_timeout - (time.monotonic() - t0) - 2.5
            if remaining > 0 and cap.status != "failed":
                page.wait_for_timeout(min(self.settle, remaining) * 1000)
                try:
                    page.wait_for_load_state("load", timeout=max(500, min(3000, remaining * 1000)))
                except (PWTimeout, PWError):
                    pass

            # Redirect chain: HTTP redirects of the first response, then later main-frame navigations.
            chain = []
            if response is not None:
                r, hops = response.request, []
                while r.redirected_from is not None:
                    r = r.redirected_from
                    hops.append(r)
                for req in reversed(hops):
                    try:
                        st = req.response().status if req.response() else None
                    except PWError:
                        st = None
                    chain.append({"url": req.url, "status": st, "kind": "http"})
                chain.append({"url": response.url, "status": response.status, "kind": "final"})
                cap.http_status = response.status
                try:
                    sd = response.security_details()
                    if sd:
                        cap.tls = {k: sd.get(k) for k in ("issuer", "protocol", "subjectName", "validFrom", "validTo")}
                except PWError:
                    pass
            for nav in main_navs:
                if not chain or nav != chain[-1]["url"]:
                    if chain and chain[-1]["kind"] == "final":
                        chain[-1]["kind"] = "http"
                    chain.append({"url": nav, "status": None, "kind": "script"})
            if chain:
                chain[-1]["kind"] = "final"
            cap.redirects = chain[:20]
            cap.final_url = page.url if page.url != "about:blank" else (chain[-1]["url"] if chain else url)

            # Page contents and screenshot.
            if cap.status != "failed" or page.url not in ("about:blank", ""):
                try:
                    info = page.evaluate(EXTRACT_JS)
                    cap.title = info["title"][:300]
                    cap.visible_text = info["visible"]
                    cap.hidden_text = info["hidden"]
                    cap.forms = info["forms"]
                    cap.loose_password_fields = info["loose_password_fields"]
                    cap.link_schemes = info["link_schemes"]
                    cap.inline_script = info["inline_script"]
                except PWError:
                    pass
                try:
                    self.shots_dir.mkdir(parents=True, exist_ok=True)
                    shot = self.shots_dir / f"{scan_id}.jpg"
                    page.screenshot(path=str(shot), type="jpeg", quality=72, timeout=5000)
                    cap.screenshot = shot.name
                except PWError:
                    pass

            # Quarantine downloads. Saved as .bin, never opened or run.
            for i, d in enumerate(downloads[:5]):
                info = {"filename": (d.suggested_filename or "download")[:200], "url": d.url[:500]}
                try:
                    tmp = d.path()
                    if tmp is None:
                        raise PWError(d.failure() or "download failed")
                    size = Path(tmp).stat().st_size
                    info["size"] = size
                    if size > MAX_DOWNLOAD:
                        info["note"] = "too large to keep; discarded"
                    else:
                        qdir.mkdir(parents=True, exist_ok=True)
                        dest = qdir / f"{i + 1}.bin"
                        shutil.copyfile(tmp, dest)
                        info.update(filetypes.identify(dest))
                        info["sha256"] = filetypes.sha256_of(dest)
                        info["quarantine_path"] = str(dest)
                except (PWError, OSError) as e:
                    info["note"] = f"could not be saved: {str(e)[:100]}"
                cap.downloads.append(info)

            with self.egress._lock:
                cap.request_domains = sorted(self.egress.hosts)
                cap.blocked = list(self.egress.blocked)
            for pa in cap.protocol_attempts:
                cap.blocked.append({"url": pa["url"], "reason": f"'{pa['scheme']}:' app launch blocked (never opened)"})
            final_blocked = response is not None and response.headers.get("x-phishguard") == "blocked"
            if final_blocked or (cap.status == "failed" and cap.blocked and "TUNNEL" in cap.error.upper()):
                cap.status, cap.error = "failed", "PhishGuard blocked this address (it points into a private network)."
            if not cap.final_url:
                cap.final_url = url
        finally:
            try:
                ctx.close()
            except PWError:
                pass
        cap.timings["total"] = round(time.monotonic() - t0, 3)
        return cap


def registrable_or_host(url: str) -> str:
    try:
        return registrable_domain(url)
    except ValueError:
        return urlsplit(url).hostname or ""
