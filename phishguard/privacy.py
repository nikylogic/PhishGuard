"""Hide my IP: send the sandbox's traffic through Tor, Cloudflare WARP or the user's own proxy.

The visited site then sees the route's address, not yours. Only the sandbox ever contacts the site
being checked, and all of its traffic already passes through the egress gatekeeper (egress.py), so
the gatekeeper is the one place that forwards onward. While a route is on:

  * nothing goes out directly. If the route is down, the check fails ("fail closed");
  * host names are NOT looked up on this PC. The route looks them up, so your DNS server and ISP
    do not see which sites were checked (SOCKS5 with a host name, or HTTP CONNECT host:port);
  * the sandbox reports a neutral time zone (UTC) and blocks WebRTC from leaking local addresses.

Routes:
  tor     PhishGuard downloads the official Tor Expert Bundle once from torproject.org, checks its
          SHA-256 against the value pinned below and runs tor.exe itself. Each check gets its own
          Tor circuit (a different SOCKS user name per check).
  warp    Cloudflare's free WARP app, if the user has it in proxy mode (warp-cli mode proxy).
  custom  a SOCKS5 or HTTP proxy address the user types in.
"""
from __future__ import annotations

import base64
import hashlib
import ipaddress
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import tarfile
import threading
import time
import urllib.request
from dataclasses import dataclass, field, replace
from pathlib import Path
from urllib.parse import unquote, urljoin, urlsplit

# The Tor Expert Bundle 16.0 for 64-bit Windows. The hash comes from Tor's sha256sums-signed-build.txt,
# whose signature was checked against the Tor Browser Developers key
# (EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290) before it was written here.
TOR_VERSION = "16.0"
TOR_URL = ("https://archive.torproject.org/tor-package-archive/torbrowser/16.0/"
           "tor-expert-bundle-windows-x86_64-16.0.tar.gz")
TOR_SHA256 = "2ee123e9167318a3742778ff704e75f01d4780f05a14522d451fe011011077c4"
TOR_FILES = {"tor/tor.exe", "data/geoip", "data/geoip6"}      # all that is needed; nothing else is unpacked
TOR_MAX_BYTES = 64 * 1024 * 1024

WHOAMI_URL = "https://check.torproject.org/api/ip"           # answers {"IsTor": bool, "IP": "..."}
MODES = ("off", "tor", "warp", "custom")
LOCAL_SUFFIXES = (".local", ".localhost", ".internal", ".lan", ".home", ".home.arpa", ".intranet", ".corp")
NO_WINDOW = getattr(subprocess, "CREATE_NO_WINDOW", 0)


class Unavailable(Exception):
    """Hide my IP is on but the route cannot be used right now. Nothing is sent directly instead."""


@dataclass(frozen=True)
class Upstream:
    kind: str                     # "socks5" or "http"
    host: str
    port: int
    user: str = ""
    password: str = field(default="", repr=False)
    label: str = ""

    def per_check(self) -> "Upstream":
        """Tor: a fresh circuit for each check (Tor keeps streams with different SOCKS logins apart)."""
        if self.label == "Tor":
            return replace(self, user="pg-" + secrets.token_hex(6), password="x")
        return self


# --- the custom proxy address -------------------------------------------------------------------

def parse_proxy(text: str) -> Upstream:
    """'socks5://host:port', 'socks5h://user:pass@host:port' or 'http://host:port'."""
    text = (text or "").strip()
    if not text:
        raise ValueError("Type a proxy address, for example socks5://127.0.0.1:1080")
    if len(text) > 300 or any(c.isspace() for c in text):
        raise ValueError("That proxy address has spaces or is too long.")
    u = urlsplit(text)
    scheme = u.scheme.lower()
    kinds = {"socks5": "socks5", "socks5h": "socks5", "http": "http"}
    if scheme not in kinds:
        raise ValueError("Use a socks5:// or http:// proxy address. (SOCKS4 and HTTPS proxies are not supported.)")
    try:
        port = u.port
    except ValueError:
        raise ValueError("The proxy port is not a number between 1 and 65535.") from None
    if not u.hostname or not port:
        raise ValueError("The proxy address needs a host and a port, for example socks5://127.0.0.1:1080")
    if u.path not in ("", "/") or u.query or u.fragment:
        raise ValueError("A proxy address is only scheme://host:port")
    return Upstream(kinds[scheme], u.hostname, port, unquote(u.username or ""), unquote(u.password or ""),
                    label="Your proxy")


def shown(up: Upstream | None) -> str:
    """The address without the password, for screens and logs."""
    if not up:
        return ""
    who = f"{up.user}:***@" if up.user else ""
    return f"{'socks5' if up.kind == 'socks5' else 'http'}://{who}{up.host}:{up.port}"


# --- opening a connection through the route -----------------------------------------------------

def _exact(s: socket.socket, n: int) -> bytes:
    out = b""
    while len(out) < n:
        chunk = s.recv(n - len(out))
        if not chunk:
            raise OSError("the proxy closed the connection")
        out += chunk
    return out


SOCKS_ERRORS = {1: "general failure", 2: "not allowed by the proxy", 3: "network unreachable",
                4: "host unreachable", 5: "connection refused", 6: "timed out", 7: "command not supported",
                8: "address type not supported"}


def _socks5(s: socket.socket, up: Upstream, host: str, port: int) -> bytes:
    methods = b"\x00\x02" if up.user else b"\x00"
    s.sendall(b"\x05" + bytes([len(methods)]) + methods)
    ver, method = _exact(s, 2)
    if ver != 5:
        raise OSError("that is not a SOCKS5 proxy")
    if method == 2:
        u, p = up.user.encode()[:255], up.password.encode()[:255]
        s.sendall(b"\x01" + bytes([len(u)]) + u + bytes([len(p)]) + p)
        if _exact(s, 2)[1] != 0:
            raise OSError("the proxy refused the user name or password")
    elif method != 0:
        raise OSError("the proxy wants a login PhishGuard does not have")
    try:
        ip = ipaddress.ip_address(host)
        addr = (b"\x01" if ip.version == 4 else b"\x04") + ip.packed
    except ValueError:
        name = host.encode("idna")
        if len(name) > 255:
            raise OSError("host name too long") from None
        addr = b"\x03" + bytes([len(name)]) + name      # the proxy looks the name up, not this PC
    s.sendall(b"\x05\x01\x00" + addr + port.to_bytes(2, "big"))
    head = _exact(s, 4)
    if head[1] != 0:
        raise OSError(f"the proxy could not reach the site ({SOCKS_ERRORS.get(head[1], head[1])})")
    atyp = head[3]
    _exact(s, {1: 4, 4: 16}.get(atyp) or _exact(s, 1)[0])
    _exact(s, 2)
    return b""


def _http_connect(s: socket.socket, up: Upstream, host: str, port: int) -> bytes:
    hostport = f"[{host}]:{port}" if ":" in host else f"{host}:{port}"
    req = f"CONNECT {hostport} HTTP/1.1\r\nHost: {hostport}\r\n"
    if up.user:
        token = base64.b64encode(f"{up.user}:{up.password}".encode()).decode()
        req += f"Proxy-Authorization: Basic {token}\r\n"
    s.sendall((req + "\r\n").encode("latin-1"))
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = s.recv(4096)
        if not chunk:
            raise OSError("the proxy closed the connection")
        data += chunk
        if len(data) > 16384:
            raise OSError("the proxy sent a strange answer")
    head, rest = data.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n", 1)[0].split(b" ")
    if len(status) < 2 or status[1] != b"200":
        raise OSError(f"the proxy answered {b' '.join(status[1:3]).decode('latin-1', 'replace')}")
    return rest


def open_tunnel(up: Upstream, host: str, port: int, timeout: float = 15.0) -> tuple[socket.socket, bytes]:
    """A connection to host:port through the route. Returns the socket and any bytes already read."""
    s = socket.create_connection((up.host, up.port), timeout=timeout)
    try:
        rest = (_socks5 if up.kind == "socks5" else _http_connect)(s, up, host, port)
        return s, rest
    except BaseException:
        s.close()
        raise


def local_name(host: str) -> bool:
    """Names that only mean something on your own network. Never sent to a route."""
    h = host.lower().rstrip(".")
    return "." not in h or h == "localhost" or h.endswith(LOCAL_SUFFIXES)


def http_get(up: Upstream | None, url: str, timeout: float = 25.0, limit: int = 65536,
             accept: str = "application/json", redirects: int = 3) -> tuple[int, bytes]:
    """A plain GET, through the route when there is one (so lookups about a link are hidden
    the same way the sandbox is). Returns (status, body). Follows a few redirects."""
    u = urlsplit(url)
    port = u.port or (443 if u.scheme == "https" else 80)
    if up:
        s, rest = open_tunnel(up.per_check(), u.hostname, port, timeout)
    else:
        s, rest = socket.create_connection((u.hostname, port), timeout=timeout), b""
    try:
        if u.scheme == "https":
            s = ssl.create_default_context().wrap_socket(s, server_hostname=u.hostname)
        target = (u.path or "/") + (f"?{u.query}" if u.query else "")
        s.sendall(f"GET {target} HTTP/1.1\r\nHost: {u.hostname}\r\nAccept: {accept}\r\n"
                  f"User-Agent: PhishGuard\r\nConnection: close\r\n\r\n".encode())
        data = rest
        while len(data) < limit:
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
    finally:
        s.close()
    head, _, body = data.partition(b"\r\n\r\n")
    lines = head.decode("latin-1").split("\r\n")
    try:
        status = int(lines[0].split()[1])
    except (IndexError, ValueError):
        raise OSError("the server gave an unexpected answer") from None
    headers = {k.strip().lower(): v.strip() for k, _, v in (ln.partition(":") for ln in lines[1:])}
    if status in (301, 302, 303, 307, 308) and redirects and headers.get("location"):
        nxt = urljoin(url, headers["location"])
        if urlsplit(nxt).scheme not in ("http", "https"):
            raise OSError("bad redirect")
        return http_get(up, nxt, timeout, limit, accept, redirects - 1)
    if "chunked" in headers.get("transfer-encoding", "").lower():
        body = _dechunk(body)
    return status, body


def whoami(up: Upstream | None, url: str = WHOAMI_URL, timeout: float = 25.0) -> dict:
    """Ask a public service which address it sees: the proof that Hide my IP works."""
    _, body = http_get(up, url, timeout)
    try:
        out = json.loads(body.decode("utf-8", "replace"))
    except ValueError:
        raise OSError("the address check gave an unexpected answer") from None
    return {"ip": str(out.get("IP", ""))[:64], "is_tor": bool(out.get("IsTor"))}


def _dechunk(body: bytes) -> bytes:
    out = b""
    while body:
        size_line, _, body = body.partition(b"\r\n")
        try:
            n = int(size_line.split(b";")[0], 16)
        except ValueError:
            break
        if n == 0:
            break
        out, body = out + body[:n], body[n + 2:]
    return out


def socks_answers(host: str, port: int, timeout: float = 1.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout) as s:
            s.sendall(b"\x05\x01\x00")
            return _exact(s, 2) == b"\x05\x00"
    except OSError:
        return False


# --- Cloudflare WARP -------------------------------------------------------------------------------

WARP_CLI = r"C:\Program Files\Cloudflare\Cloudflare WARP\warp-cli.exe"


def _run_cli(args: list[str]) -> str:
    cli = shutil.which("warp-cli") or (WARP_CLI if Path(WARP_CLI).is_file() else None)
    if not cli:
        raise FileNotFoundError
    p = subprocess.run([cli, "--accept-tos", *args], capture_output=True, text=True, timeout=6,
                       creationflags=NO_WINDOW)
    return (p.stdout or "") + (p.stderr or "")


def find_warp(run=_run_cli, probe=socks_answers) -> dict:
    """Is the WARP app installed, in proxy mode, and answering? Never changes WARP's settings."""
    try:
        settings = run(["settings"])
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return {"installed": False, "ready": False, "port": None,
                "message": "Cloudflare WARP is not installed. It is free from 1.1.1.1."}
    m = re.search(r"(?i)proxy[^\n]*?port\D{0,10}(\d{2,5})", settings)
    port = int(m.group(1)) if m else 40000
    if not re.search(r"(?i)proxy", settings):
        return {"installed": True, "ready": False, "port": None,
                "message": "WARP is installed but not in proxy mode. In a terminal run: warp-cli mode proxy"}
    if not probe("127.0.0.1", port):
        return {"installed": True, "ready": False, "port": port,
                "message": "WARP is in proxy mode but not connected. In a terminal run: warp-cli connect"}
    return {"installed": True, "ready": True, "port": port, "message": f"WARP proxy found on port {port}."}


# --- Tor -----------------------------------------------------------------------------------------------

class Tor:
    """Downloads (once) and runs the official tor.exe for this PhishGuard instance."""

    def __init__(self, instance: Path, url: str = TOR_URL, sha256: str = TOR_SHA256, version: str = TOR_VERSION):
        self.dir = Path(instance) / "tor"
        self.exe = self.dir / "tor" / "tor.exe"
        self.url, self.sha256, self.version = url, sha256, version
        self.state = "ready-to-install"     # downloading | installed | starting | running | error
        self.message = ""
        self.progress = 0                   # percent while downloading, then Tor's bootstrap percent
        self.proc: subprocess.Popen | None = None
        self.port: int | None = None
        self.lock = threading.Lock()
        self.ready = threading.Event()
        if self.installed():
            self.state = "installed"

    def installed(self) -> bool:
        try:
            return self.exe.is_file() and (self.dir / "VERSION").read_text(encoding="utf-8").strip() == self.version
        except OSError:
            return False

    def status(self) -> dict:
        alive = self.proc is not None and self.proc.poll() is None
        state = self.state
        if state in ("starting", "running") and not alive:
            state = "installed" if self.installed() else "ready-to-install"
        return {"state": state,
                "message": self.message, "progress": self.progress, "version": self.version,
                "installed": self.installed()}

    # Download and check ------------------------------------------------------------------------
    def install(self, opener=urllib.request.urlopen) -> None:
        with self.lock:
            if self.state == "downloading":
                return
            self.state, self.message, self.progress = "downloading", "Downloading Tor from torproject.org", 0
        part = self.dir / "bundle.part"
        try:
            self.dir.mkdir(parents=True, exist_ok=True)
            digest, size = hashlib.sha256(), 0
            with opener(self.url, timeout=60) as r, open(part, "wb") as f:
                total = int(r.headers.get("Content-Length") or 0)
                while True:
                    chunk = r.read(256 * 1024)
                    if not chunk:
                        break
                    size += len(chunk)
                    if size > TOR_MAX_BYTES:
                        raise OSError("the download is far bigger than Tor should be")
                    digest.update(chunk)
                    f.write(chunk)
                    if total:
                        self.progress = min(99, size * 100 // total)
            if digest.hexdigest() != self.sha256:
                raise OSError("the download does not match the official Tor checksum, so it was thrown away")
            self._unpack(part)
            (self.dir / "VERSION").write_text(self.version, encoding="utf-8")
            self.state, self.message, self.progress = "installed", f"Tor {self.version} is ready.", 100
        except Exception as e:  # noqa: BLE001
            self.state, self.message, self.progress = "error", f"Tor could not be installed: {e}", 0
            raise
        finally:
            part.unlink(missing_ok=True)

    def _unpack(self, archive: Path) -> None:
        found = set()
        with tarfile.open(archive, "r:gz") as tar:
            for m in tar.getmembers():
                if m.name not in TOR_FILES:
                    continue                                   # only the three named files, nothing else
                if not m.isfile() or m.size > TOR_MAX_BYTES:
                    raise OSError(f"unexpected entry {m.name}")
                dest = self.dir / m.name
                dest.parent.mkdir(parents=True, exist_ok=True)
                with tar.extractfile(m) as src, open(dest, "wb") as out:
                    shutil.copyfileobj(src, out)
                found.add(m.name)
        if found != TOR_FILES:
            raise OSError(f"the bundle is missing {sorted(TOR_FILES - found)}")

    # Run ------------------------------------------------------------------------------------------
    def start(self, popen=subprocess.Popen) -> None:
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                return
            if not self.installed():
                raise Unavailable("Tor is not downloaded yet. Open Settings > Hide my IP and press Download Tor.")
            self.ready.clear()
            self.port = _free_port()
            data = self.dir / "data"
            (data / "state").mkdir(parents=True, exist_ok=True)
            self.state, self.message, self.progress = "starting", "Connecting to the Tor network", 0
            self.proc = popen(
                [str(self.exe), "--SocksPort", f"127.0.0.1:{self.port}", "--DataDirectory", str(data / "state"),
                 "--GeoIPFile", str(data / "geoip"), "--GeoIPv6File", str(data / "geoip6"),
                 "--ClientOnly", "1", "--ControlPort", "0", "--Log", "notice stdout",
                 "--__OwningControllerProcess", str(os.getpid())],      # Tor quits if PhishGuard does
                stdout=subprocess.PIPE, stderr=subprocess.STDOUT, stdin=subprocess.DEVNULL,
                creationflags=NO_WINDOW, text=True, encoding="utf-8", errors="replace")
        threading.Thread(target=self._watch, args=(self.proc,), name="pg-tor", daemon=True).start()

    def _watch(self, proc) -> None:
        for line in proc.stdout:
            m = re.search(r"Bootstrapped (\d+)%", line)
            if m:
                self.progress = int(m.group(1))
                if self.progress == 100:
                    self.state, self.message = "running", "Connected to the Tor network."
                    self.ready.set()
            elif "[err]" in line or "[warn]" in line and "Problem bootstrapping" in line:
                self.message = line.split("]", 1)[-1].strip()[:200]
        if self.proc is proc:
            self.ready.clear()
            self.state = "error" if self.state != "stopped" else "stopped"
            self.message = self.message or "Tor stopped."

    def stop(self) -> None:
        with self.lock:
            if self.proc is not None and self.proc.poll() is None:
                self.state = "stopped"
                self.proc.terminate()
                try:
                    self.proc.wait(5)
                except subprocess.TimeoutExpired:
                    self.proc.kill()
            self.proc = None
            self.ready.clear()
            if self.installed():
                self.state = "installed"

    def upstream(self, wait: float = 45.0) -> Upstream:
        self.start()
        if not self.ready.wait(wait):
            raise Unavailable(f"Tor is still connecting ({self.progress}%). Try again in a moment.")
        return Upstream("socks5", "127.0.0.1", self.port, label="Tor")


def _free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


# --- choosing the route from the settings ---------------------------------------------------------------

def route(settings: dict, tor: Tor, warp=find_warp) -> Upstream | None:
    """None when Hide my IP is off. Raises Unavailable when it is on but cannot be used."""
    mode = settings.get("privacy_mode") or "off"
    if mode == "off":
        return None
    if mode == "tor":
        return tor.upstream()
    if mode == "warp":
        w = warp()
        if not w["ready"]:
            raise Unavailable("Hide my IP is set to Cloudflare WARP. " + w["message"])
        return Upstream("socks5", "127.0.0.1", w["port"], label="Cloudflare WARP")
    if mode == "custom":
        try:
            return parse_proxy(settings.get("privacy_proxy", ""))
        except ValueError as e:
            raise Unavailable(f"Hide my IP: {e}") from None
    raise Unavailable("Hide my IP has an unknown setting.")


def wait_until(pred, timeout: float) -> bool:
    end = time.monotonic() + timeout
    while time.monotonic() < end:
        if pred():
            return True
        time.sleep(0.1)
    return pred()
