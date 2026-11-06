"""Phase 8c: Hide my IP. The sandbox's traffic goes through Tor, Cloudflare WARP or the user's proxy.

The test sites have names ending in .invalid, which cannot be looked up on this PC at all. The fake
SOCKS5 / HTTP proxies below are the only things that know where those sites are, so a page that loads
proves its traffic went through the route. The proxies record every connection, and the gatekeeper's
resolver fails the test if anything tries to look a name up locally.
"""
import hashlib
import io
import json
import os
import socket
import socketserver
import tarfile
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from types import SimpleNamespace

import pytest

from phishguard import privacy
from phishguard.egress import EgressProxy
from phishguard.sandbox import Sandbox
from phishguard.worker import ScanWorker

# --------------------------------------------------------------------------- the test site

PAGE = b"""<!doctype html><meta charset=utf-8><title>Route test</title>
<h1>ROUTED-PAGE-OK</h1>
<img src="http://images.airlock.invalid/pixel.gif">
<script src="https://cdn-would-fail.airlock.invalid/x.js"></script>
<p id=tz></p><p id=rtc>RTC=pending</p><p id=fetch></p>
<script>
document.getElementById('tz').textContent = 'TZ=' + Intl.DateTimeFormat().resolvedOptions().timeZone;
fetch('http://api.airlock.invalid/data').then(r => r.text()).then(t => document.getElementById('fetch').textContent = t);
const found = [];
try {
  const pc = new RTCPeerConnection({iceServers: []});
  pc.createDataChannel('x');
  pc.onicecandidate = e => { if (e.candidate && e.candidate.candidate) found.push(e.candidate.candidate); };
  pc.createOffer().then(o => pc.setLocalDescription(o));
  setTimeout(() => { document.getElementById('rtc').textContent = 'RTC=' + found.length + ' ' + found.join(' | '); }, 700);
} catch (e) { document.getElementById('rtc').textContent = 'RTC=error ' + e; }
</script>"""


class Site(BaseHTTPRequestHandler):
    hits: list = []

    def do_GET(self):
        Site.hits.append((self.headers.get("Host"), self.path))
        if self.path == "/data":
            body, kind = b"FETCH-OK", "text/plain"
        elif self.path == "/pixel.gif":
            body, kind = b"GIF89a\x01\x00\x01\x00\x00\x00\x00;", "image/gif"
        elif self.path == "/ip":
            body, kind = json.dumps({"IsTor": True, "IP": "203.0.113.7"}).encode(), "application/json"
        else:
            body, kind = PAGE, "text/html"
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Content-Type", kind)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="module")
def site():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), Site)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield srv.server_address[1]
    srv.shutdown()


# --------------------------------------------------------------------------- fake routes

class FakeSocks(socketserver.ThreadingTCPServer):
    """A SOCKS5 proxy that only knows the *.airlock.invalid names, and records everything."""
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, site_port, need_login=False):
        self.site_port = site_port
        self.need_login = need_login
        self.log: list[dict] = []
        super().__init__(("127.0.0.1", 0), SocksHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.server_address[1]


class SocksHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s, srv = self.request, self.server
        _, n = s.recv(2)
        methods = s.recv(n)
        user = ""
        if srv.need_login:
            assert 2 in methods
            s.sendall(b"\x05\x02")
            s.recv(1)
            user = s.recv(s.recv(1)[0]).decode()
            s.recv(s.recv(1)[0])
            s.sendall(b"\x01\x00")
        else:
            s.sendall(b"\x05\x00")
        _, cmd, _, atyp = s.recv(4)
        if atyp == 3:
            host = s.recv(s.recv(1)[0]).decode()
        elif atyp == 1:
            host = socket.inet_ntoa(s.recv(4))
        else:
            host = socket.inet_ntop(socket.AF_INET6, s.recv(16))
        port = int.from_bytes(s.recv(2), "big")
        srv.log.append({"atyp": atyp, "host": host, "port": port, "user": user})
        if not host.endswith(".airlock.invalid"):
            s.sendall(b"\x05\x04\x00\x01" + bytes(6))           # host unreachable
            return
        if port == 443:
            s.sendall(b"\x05\x05\x00\x01" + bytes(6))           # no TLS on the test site: refused
            return
        up = socket.create_connection(("127.0.0.1", srv.site_port))
        s.sendall(b"\x05\x00\x00\x01" + bytes(6))
        pipe(s, up)


class FakeHttpProxy(socketserver.ThreadingTCPServer):
    daemon_threads = True
    allow_reuse_address = True

    def __init__(self, site_port):
        self.site_port = site_port
        self.log: list[str] = []
        super().__init__(("127.0.0.1", 0), HttpProxyHandler)
        threading.Thread(target=self.serve_forever, daemon=True).start()

    @property
    def port(self):
        return self.server_address[1]


class HttpProxyHandler(socketserver.BaseRequestHandler):
    def handle(self):
        s, srv = self.request, self.server
        data = b""
        while b"\r\n\r\n" not in data:
            data += s.recv(4096)
        line = data.split(b"\r\n", 1)[0].decode()
        srv.log.append(line)
        target = line.split(" ")[1]
        if not line.startswith("CONNECT ") or not target.split(":")[0].endswith(".airlock.invalid"):
            s.sendall(b"HTTP/1.1 403 Forbidden\r\n\r\n")
            return
        up = socket.create_connection(("127.0.0.1", srv.site_port))
        s.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
        pipe(s, up)


def pipe(a, b):
    import select
    try:
        while True:
            r, _, _ = select.select([a, b], [], [], 10)
            if not r:
                return
            for x in r:
                d = x.recv(65536)
                if not d:
                    return
                (b if x is a else a).sendall(d)
    except OSError:
        pass
    finally:
        b.close()


class NoLocalDNS:
    """The gatekeeper's resolver while a route is on: any local lookup fails the test."""
    calls: list = []

    def ips(self, host):
        NoLocalDNS.calls.append(host)
        return []


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


# --------------------------------------------------------------------------- the proxy address box

@pytest.mark.parametrize("text,kind,host,port,user", [
    ("socks5://127.0.0.1:1080", "socks5", "127.0.0.1", 1080, ""),
    ("socks5h://me:p%40ss@proxy.example.net:1080", "socks5", "proxy.example.net", 1080, "me"),
    ("http://10.0.0.5:3128", "http", "10.0.0.5", 3128, ""),
])
def test_proxy_addresses_that_are_accepted(text, kind, host, port, user):
    up = privacy.parse_proxy(text)
    assert (up.kind, up.host, up.port, up.user) == (kind, host, port, user)


@pytest.mark.parametrize("text", ["", "127.0.0.1:1080", "socks4://1.2.3.4:1080", "https://p.example:443",
                                  "socks5://host", "socks5://host:99999", "socks5://h:1080/path",
                                  "socks5://h:1080 ; rm", "ftp://h:21"])
def test_proxy_addresses_that_are_refused(text):
    with pytest.raises(ValueError):
        privacy.parse_proxy(text)


def test_the_proxy_password_is_never_shown():
    up = privacy.parse_proxy("socks5://me:secret-pw@127.0.0.1:1080")
    assert "secret-pw" not in privacy.shown(up) and "secret-pw" not in repr(up)


# --------------------------------------------------------------------------- the gatekeeper with a route

def raw_get(egress, url):
    """Send one plain-HTTP request through the gatekeeper, the way Chrome does."""
    with socket.create_connection(("127.0.0.1", egress.port), timeout=10) as c:
        c.sendall(f"GET {url} HTTP/1.1\r\nHost: {url.split('/')[2]}\r\nConnection: close\r\n\r\n".encode())
        data = b""
        while True:
            d = c.recv(65536)
            if not d:
                return data
            data += d


def connect(egress, hostport):
    with socket.create_connection(("127.0.0.1", egress.port), timeout=10) as c:
        c.sendall(f"CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n\r\n".encode())
        return c.recv(200)


@pytest.fixture
def egress():
    NoLocalDNS.calls = []
    e = EgressProxy(NoLocalDNS).start()
    yield e
    e.stop()


def test_names_go_to_the_route_and_are_never_looked_up_here(egress, site):
    socks = FakeSocks(site)
    egress.begin_scan(privacy.Upstream("socks5", "127.0.0.1", socks.port, label="Test"))
    out = raw_get(egress, f"http://page.airlock.invalid:{site}/data")
    assert b"FETCH-OK" in out
    assert socks.log[-1] == {"atyp": 3, "host": "page.airlock.invalid", "port": site, "user": ""}
    assert NoLocalDNS.calls == []                                      # no DNS lookup on this PC


def test_https_goes_through_the_route_as_a_name(egress, site):
    socks = FakeSocks(site)
    egress.begin_scan(privacy.Upstream("socks5", "127.0.0.1", socks.port, label="Test"))
    assert connect(egress, f"secure.airlock.invalid:{site}").startswith(b"HTTP/1.1 200")
    assert socks.log[-1]["atyp"] == 3 and socks.log[-1]["host"] == "secure.airlock.invalid"
    assert NoLocalDNS.calls == []


def test_an_http_proxy_route_works_too(egress, site):
    hp = FakeHttpProxy(site)
    egress.begin_scan(privacy.Upstream("http", "127.0.0.1", hp.port, label="Test"))
    assert b"FETCH-OK" in raw_get(egress, f"http://page.airlock.invalid:{site}/data")
    assert hp.log[-1] == f"CONNECT page.airlock.invalid:{site} HTTP/1.1"


def test_route_down_means_nothing_is_sent_directly(egress, site):
    Site.hits.clear()
    dead = free_port()                                                 # nothing listens here
    egress.begin_scan(privacy.Upstream("socks5", "127.0.0.1", dead, label="Tor"))
    out = raw_get(egress, f"http://127.0.0.1:{site}/data")             # even a reachable address
    assert out.startswith(b"HTTP/1.1 403") or out.startswith(b"HTTP/1.1 502")
    out = raw_get(egress, f"http://page.airlock.invalid:{site}/data")
    assert out.startswith(b"HTTP/1.1 502")
    assert Site.hits == []
    assert any("Nothing was sent directly" in b["reason"] for b in egress.blocked)


@pytest.mark.parametrize("target", ["http://localhost/", "http://printer/", "http://nas.local/",
                                    "http://router.home.arpa/", "http://10.1.2.3/", "http://192.168.1.1/",
                                    "http://[::1]/"])
def test_local_names_and_private_addresses_are_still_refused(egress, site, target):
    socks = FakeSocks(site)
    egress.begin_scan(privacy.Upstream("socks5", "127.0.0.1", socks.port, label="Test"))
    assert raw_get(egress, target).startswith(b"HTTP/1.1 403")
    assert socks.log == []                                             # never even handed to the route


def test_tor_gets_a_new_circuit_for_every_check(egress, site):
    socks = FakeSocks(site, need_login=True)
    tor = privacy.Upstream("socks5", "127.0.0.1", socks.port, label="Tor")
    users = set()
    for _ in range(3):
        egress.begin_scan(tor)
        raw_get(egress, f"http://page.airlock.invalid:{site}/data")
        users.add(socks.log[-1]["user"])
    assert len(users) == 3 and all(u.startswith("pg-") for u in users)


def test_without_a_route_nothing_changes(egress):
    egress.begin_scan(None)
    assert egress.upstream is None


# --------------------------------------------------------------------------- the real sandbox browser

@pytest.fixture(scope="module")
def browser_env(site, tmp_path_factory):
    base = tmp_path_factory.mktemp("privacy-sandbox")
    socks = FakeSocks(site)
    state = {"route": privacy.Upstream("socks5", "127.0.0.1", socks.port, label="Test route")}

    def route():
        r = state["route"]
        if isinstance(r, Exception):
            raise r
        return r

    w = ScanWorker(lambda: Sandbox(base / "shots", base / "q", resolver_factory=NoLocalDNS, route=route,
                                   nav_timeout=15, total_timeout=20)).start()
    assert w.ready.wait(30)
    yield SimpleNamespace(worker=w, socks=socks, state=state, base=base)
    w.stop()


def test_a_whole_page_loads_only_through_the_route(browser_env, site):
    NoLocalDNS.calls = []
    browser_env.socks.log.clear()
    cap = browser_env.worker.submit(f"http://www.airlock.invalid:{site}/", 1).result(timeout=60)
    assert cap.status in ("done", "partial"), cap.error
    assert "ROUTED-PAGE-OK" in cap.visible_text and "FETCH-OK" in cap.visible_text
    assert cap.route == "Test route"
    hosts = {e["host"] for e in browser_env.socks.log}
    assert {"www.airlock.invalid", "images.airlock.invalid", "api.airlock.invalid"} <= hosts
    assert all(e["atyp"] == 3 for e in browser_env.socks.log)        # always a name, never a local lookup
    assert NoLocalDNS.calls == []
    (Path(__file__).resolve().parent.parent / "proof" / "phase-8c").mkdir(parents=True, exist_ok=True)


def test_the_page_sees_a_neutral_time_zone_and_no_webrtc_addresses(browser_env, site):
    cap = browser_env.worker.submit(f"http://www.airlock.invalid:{site}/", 2).result(timeout=60)
    assert "TZ=UTC" in cap.visible_text
    rtc = cap.visible_text.split("RTC=", 1)[1].split(" ", 1)[0]
    assert rtc == "error", cap.visible_text                            # WebRTC does not exist for the page
    assert "candidate" not in cap.visible_text


def test_route_unavailable_means_the_page_is_never_opened(browser_env, site):
    Site.hits.clear()
    browser_env.state["route"] = privacy.Unavailable("Tor is still connecting (40%). Try again in a moment.")
    try:
        cap = browser_env.worker.submit(f"http://www.airlock.invalid:{site}/", 3).result(timeout=60)
    finally:
        browser_env.state["route"] = privacy.Upstream("socks5", "127.0.0.1", browser_env.socks.port,
                                                      label="Test route")
    assert cap.status == "failed" and "Tor is still connecting" in cap.error and cap.route == "unavailable"
    assert Site.hits == [] and cap.screenshot == ""


# --------------------------------------------------------------------------- Tor download and start

def fake_bundle(extra=()):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        def add(name, data=b"x", kind=tarfile.REGTYPE, link=""):
            info = tarfile.TarInfo(name)
            info.size, info.type, info.linkname = len(data), kind, link
            tar.addfile(info, io.BytesIO(data) if kind == tarfile.REGTYPE else None)
        add("tor/tor.exe", b"MZ fake tor")
        add("data/geoip", b"geo4")
        add("data/geoip6", b"geo6")
        add("tor/pluggable_transports/lyrebird.exe", b"MZ")
        add("../escape.txt", b"bad")
        add("docs/tor.txt", b"docs")
        for e in extra:
            add(**e)
    return buf.getvalue()


def opener_for(data):
    class R(io.BytesIO):
        headers = {"Content-Length": str(len(data))}

    return lambda url, timeout=None: R(data)


def test_tor_download_is_checked_and_only_three_files_are_unpacked(tmp_path):
    data = fake_bundle()
    tor = privacy.Tor(tmp_path, url="https://example.invalid/tor.tgz", sha256=hashlib.sha256(data).hexdigest())
    tor.install(opener=opener_for(data))
    files = sorted(str(p.relative_to(tor.dir)).replace("\\", "/") for p in tor.dir.rglob("*") if p.is_file())
    assert files == ["VERSION", "data/geoip", "data/geoip6", "tor/tor.exe"]
    assert not (tmp_path / "escape.txt").exists() and not (tmp_path.parent / "escape.txt").exists()
    assert tor.installed() and tor.status()["state"] == "installed"


def test_a_tampered_tor_download_is_thrown_away(tmp_path):
    tor = privacy.Tor(tmp_path, sha256=privacy.TOR_SHA256)
    with pytest.raises(OSError, match="checksum"):
        tor.install(opener=opener_for(fake_bundle()))
    assert not tor.installed() and tor.status()["state"] == "error"
    assert not any(p.is_file() for p in tor.dir.rglob("*"))           # nothing kept, not even the download


def test_a_tor_bundle_with_a_link_instead_of_tor_exe_is_refused(tmp_path):
    buf = io.BytesIO()
    with tarfile.open(fileobj=buf, mode="w:gz") as tar:
        info = tarfile.TarInfo("tor/tor.exe")
        info.type, info.linkname = tarfile.SYMTYPE, "C:/Windows/System32/cmd.exe"
        tar.addfile(info)
    data = buf.getvalue()
    tor = privacy.Tor(tmp_path, sha256=hashlib.sha256(data).hexdigest())
    with pytest.raises(OSError):
        tor.install(opener=opener_for(data))
    assert not tor.installed()


def test_the_pinned_tor_download_is_the_official_one():
    assert privacy.TOR_URL.startswith("https://archive.torproject.org/")
    assert len(privacy.TOR_SHA256) == 64 and privacy.TOR_VERSION in privacy.TOR_URL


class FakeTorProcess:
    def __init__(self, args, **kw):
        self.args = args
        self.alive = True
        self.stopped = threading.Event()
        self.stdout = self._lines()

    def _lines(self):
        # Like real Tor: the output stays open until the process ends.
        yield "[notice] Bootstrapped 10% (conn): Connecting\n"
        yield "[notice] Bootstrapped 100% (done): Done\n"
        self.stopped.wait(10)

    def poll(self):
        return None if self.alive else 0

    def terminate(self):
        self.alive = False
        self.stopped.set()

    def wait(self, t=None):
        return 0


def test_tor_is_started_privately_and_used_when_ready(tmp_path, monkeypatch):
    tor = privacy.Tor(tmp_path)
    tor.exe.parent.mkdir(parents=True)
    tor.exe.write_bytes(b"MZ")
    (tor.dir / "VERSION").write_text(privacy.TOR_VERSION)
    procs = []
    monkeypatch.setattr(tor, "start", lambda popen=None, _orig=tor.start: _orig(
        popen=lambda a, **k: procs.append(FakeTorProcess(a, **k)) or procs[-1]))
    up = tor.upstream(wait=5)
    args = procs[0].args
    assert args[args.index("--SocksPort") + 1] == f"127.0.0.1:{up.port}"          # only this PC can use it
    assert "--__OwningControllerProcess" in args and args[args.index("--ControlPort") + 1] == "0"
    assert up.label == "Tor" and tor.status()["state"] == "running"
    tor.stop()
    assert tor.status()["state"] == "installed"


def test_tor_not_downloaded_means_checks_fail_closed(tmp_path):
    with pytest.raises(privacy.Unavailable, match="Download Tor"):
        privacy.route({"privacy_mode": "tor"}, privacy.Tor(tmp_path))


# --------------------------------------------------------------------------- Cloudflare WARP

def test_warp_not_installed():
    def run(args):
        raise FileNotFoundError
    w = privacy.find_warp(run=run)
    assert not w["installed"] and not w["ready"]


def test_warp_installed_but_not_in_proxy_mode():
    w = privacy.find_warp(run=lambda a: "Mode: Warp\nAlways On: true", probe=lambda h, p: False)
    assert w["installed"] and not w["ready"] and "warp-cli mode proxy" in w["message"]


def test_warp_in_proxy_mode_is_found_on_its_port():
    w = privacy.find_warp(run=lambda a: "Mode: WarpProxy on port 40001\n", probe=lambda h, p: p == 40001)
    assert w == {"installed": True, "ready": True, "port": 40001, "message": "WARP proxy found on port 40001."}
    up = privacy.route({"privacy_mode": "warp"}, None, warp=lambda: w)
    assert (up.host, up.port, up.label) == ("127.0.0.1", 40001, "Cloudflare WARP")


def test_warp_chosen_but_disconnected_fails_closed():
    w = privacy.find_warp(run=lambda a: "Mode: WarpProxy on port 40000", probe=lambda h, p: False)
    with pytest.raises(privacy.Unavailable, match="warp-cli connect"):
        privacy.route({"privacy_mode": "warp"}, None, warp=lambda: w)


# --------------------------------------------------------------------------- Settings API

@pytest.fixture
def admin(tmp_path, site):
    from phishguard import create_app
    from phishguard.auth import limiter
    limiter.fails.clear()
    app = create_app({"INSTANCE_DIR": str(tmp_path / "instance"), "TESTING": True,
                      "WHOAMI_URL": f"http://who.airlock.invalid:{site}/ip"})
    app.extensions["pg_service"].warp_finder = lambda: {"installed": False, "ready": False, "port": None,
                                                         "message": "Cloudflare WARP is not installed."}
    c = app.test_client()
    tok = c.get("/api/csrf").get_json()["csrf"]
    c.csrf = c.post("/api/setup", json={"mode": "personal"}, headers={"X-CSRF-Token": tok}).get_json()["csrf"]
    c.app = app
    return c


def post(c, url, body=None):
    return c.post(url, json=body or {}, headers={"X-CSRF-Token": c.csrf})


def test_privacy_is_off_by_default(admin):
    s = admin.get("/api/privacy").get_json()
    assert s["mode"] == "off" and s["tor"]["installed"] is False and s["warp"]["installed"] is False
    assert admin.app.extensions["pg_service"].privacy_route() is None


def test_saving_a_custom_proxy(admin, site):
    assert post(admin, "/api/privacy", {"mode": "custom", "proxy": "socks4://x:1"}).status_code == 400
    assert post(admin, "/api/privacy", {"mode": "warp-unofficial"}).status_code == 400
    socks = FakeSocks(site)
    r = post(admin, "/api/privacy", {"mode": "custom", "proxy": f"socks5://me:hunter22@127.0.0.1:{socks.port}"})
    assert r.status_code == 200 and r.get_json()["mode"] == "custom"
    assert "hunter22" not in admin.get("/api/privacy").get_data(as_text=True)    # password never sent back
    up = admin.app.extensions["pg_service"].privacy_route()
    assert (up.port, up.user, up.password) == (socks.port, "me", "hunter22")
    # Saving again with the masked address shown on screen keeps the real password.
    masked = admin.get("/api/privacy").get_json()["proxy"]
    assert masked == f"socks5://me:***@127.0.0.1:{socks.port}"
    post(admin, "/api/privacy", {"mode": "custom", "proxy": masked})
    assert admin.app.extensions["pg_service"].privacy_route().password == "hunter22"


def test_the_test_button_shows_the_address_sites_see(admin, site):
    socks = FakeSocks(site)
    post(admin, "/api/privacy", {"mode": "custom", "proxy": f"socks5://127.0.0.1:{socks.port}"})
    r = post(admin, "/api/privacy/test").get_json()
    assert r["route"] == "Your proxy" and r["seen"] == {"ip": "203.0.113.7", "is_tor": True}
    assert socks.log[-1]["host"] == "who.airlock.invalid"


def test_the_test_button_explains_when_the_route_is_down(admin):
    post(admin, "/api/privacy", {"mode": "tor"})
    r = post(admin, "/api/privacy/test")
    assert r.status_code == 409 and "Download Tor" in r.get_json()["error"]


def test_only_admins_change_privacy(admin):
    from phishguard.auth import create_user
    from phishguard.db import connect
    other = admin.app.test_client()
    tok = other.get("/api/csrf").get_json()["csrf"]
    assert other.post("/api/privacy", json={"mode": "off"}, headers={"X-CSRF-Token": tok}).status_code == 401
    assert admin.post("/api/privacy", json={"mode": "off"}).status_code == 403            # no CSRF token


# --------------------------------------------------------------------------- the real Tor network (opt-in)

@pytest.mark.skipif(os.environ.get("PHISHGUARD_LIVE_TOR") != "1", reason="set PHISHGUARD_LIVE_TOR=1 to use the real Tor")
def test_real_tor_hides_the_address(tmp_path_factory):
    cache = Path(os.environ.get("PHISHGUARD_TOR_CACHE") or tmp_path_factory.mktemp("tor"))
    tor = privacy.Tor(cache)
    if not tor.installed():
        tor.install()
    t0 = time.monotonic()
    up = tor.upstream(wait=120)
    boot = time.monotonic() - t0
    try:
        seen = privacy.whoami(up)
        direct = privacy.whoami(None)
    finally:
        tor.stop()
    assert seen["is_tor"] is True and not direct["is_tor"] and seen["ip"] != direct["ip"]
    out = Path(__file__).resolve().parent.parent / "proof" / "phase-8c"
    out.mkdir(parents=True, exist_ok=True)
    (out / "live-tor.txt").write_text(
        f"Tor {privacy.TOR_VERSION}, connected in {boot:.1f} s\n"
        f"check.torproject.org through Tor: IsTor={seen['is_tor']}, a Tor exit address\n"
        f"check.torproject.org directly:    IsTor={direct['is_tor']}, this PC's address\n"
        f"The two addresses differ: {seen['ip'] != direct['ip']}\n", encoding="utf-8")
