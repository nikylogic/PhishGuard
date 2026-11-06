"""Egress gatekeeper: a tiny local proxy that every sandbox connection must pass through.

Why a proxy and not a browser request filter? Browser-level filters do not see
every hop of a redirect chain. A proxy sees every single connection (pages,
redirects, images, scripts, WebSockets, iframes). It resolves the host name
itself, checks the address, and then connects to exactly the IP it checked, so
a DNS answer cannot change between the check and the connection (DNS rebinding).
"""
import select
import socket
import threading
from urllib.parse import urlsplit

from .urltools import is_private_ip

BLOCK_PAGE = (b"<!doctype html><meta charset=utf-8><title>Blocked by PhishGuard</title>"
              b"<h1>Blocked by PhishGuard</h1><p>This address points into a private network.</p>")
MAX_HEADER = 64 * 1024


class EgressProxy:
    def __init__(self, resolver_factory, exempt=(), connect_timeout=8.0, idle_timeout=30.0):
        self.resolver_factory = resolver_factory
        self.exempt = set(exempt)            # {(ip, port)} allowed although private (tests only)
        self.connect_timeout = connect_timeout
        self.idle_timeout = idle_timeout
        self._lock = threading.Lock()
        self.begin_scan()
        self._srv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self._srv.bind(("127.0.0.1", 0))
        self._srv.listen(128)
        self.port = self._srv.getsockname()[1]
        self._running = True
        self._thread = threading.Thread(target=self._accept_loop, name="pg-egress", daemon=True)

    @property
    def server(self):
        return f"http://127.0.0.1:{self.port}"

    def start(self):
        self._thread.start()
        return self

    def stop(self):
        self._running = False
        try:
            self._srv.close()
        except OSError:
            pass

    # --- per-scan bookkeeping ------------------------------------------------------------
    def begin_scan(self):
        with self._lock:
            self.resolver = self.resolver_factory()
            self.blocked: list[dict] = []
            self.hosts: set[str] = set()

    def _block(self, url, reason):
        with self._lock:
            if len(self.blocked) < 200:
                self.blocked.append({"url": url[:500], "reason": reason})

    def check(self, host: str, port: int) -> tuple[str | None, str | None]:
        """Return (ip_to_connect, None) or (None, reason_for_blocking)."""
        host = host.strip("[]").lower()
        with self._lock:
            if len(self.hosts) < 1000:
                self.hosts.add(host)
            ips = self.resolver.ips(host)
        if not ips:
            return None, "host could not be resolved"
        for ip in ips:   # if ANY answer is private, refuse: attackers mix answers
            if is_private_ip(ip) and (ip, port) not in self.exempt:
                return None, f"private address {ip} (blocked to protect your network)"
        return ips[0], None

    # --- proxy plumbing ---------------------------------------------------------------------
    def _accept_loop(self):
        while self._running:
            try:
                c, _ = self._srv.accept()
            except OSError:
                break
            threading.Thread(target=self._handle, args=(c,), daemon=True).start()

    def _handle(self, c: socket.socket):
        up = None
        try:
            c.settimeout(self.idle_timeout)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = c.recv(8192)
                if not chunk:
                    return
                data += chunk
                if len(data) > MAX_HEADER:
                    return
            head, rest = data.split(b"\r\n\r\n", 1)
            lines = head.decode("latin-1").split("\r\n")
            method, target, version = lines[0].split(" ", 2)

            if method.upper() == "CONNECT":
                host, _, port_s = target.rpartition(":")
                port = int(port_s)
                ip, reason = self.check(host, port)
                if reason:
                    self._block(f"https://{host}:{port}/", reason)
                    c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                up = socket.create_connection((ip, port), timeout=self.connect_timeout)
                c.sendall(b"HTTP/1.1 200 Connection Established\r\n\r\n")
                if rest:
                    up.sendall(rest)
            else:
                u = urlsplit(target)
                if u.scheme.lower() not in ("http", "ws") or not u.hostname:
                    c.sendall(b"HTTP/1.1 400 Bad Request\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")
                    return
                port = u.port or 80
                ip, reason = self.check(u.hostname, port)
                if reason:
                    self._block(target, reason)
                    c.sendall(b"HTTP/1.1 403 Forbidden\r\nContent-Type: text/html\r\nX-PhishGuard: blocked\r\n"
                              b"Content-Length: " + str(len(BLOCK_PAGE)).encode() +
                              b"\r\nConnection: close\r\n\r\n" + BLOCK_PAGE)
                    return
                path = u.path or "/"
                if u.query:
                    path += "?" + u.query
                headers = [h for h in lines[1:]
                           if not h.lower().startswith(("proxy-connection:", "proxy-authorization:", "connection:"))]
                upgrade = any(h.lower().startswith("upgrade:") for h in headers)
                headers.append("Connection: Upgrade" if upgrade else "Connection: close")
                req = f"{method} {path} {version}\r\n" + "\r\n".join(headers) + "\r\n\r\n"
                up = socket.create_connection((ip, port), timeout=self.connect_timeout)
                up.sendall(req.encode("latin-1") + rest)
            self._pipe(c, up)
        except (OSError, ValueError):
            pass
        finally:
            for s in (c, up):
                if s is not None:
                    try:
                        s.close()
                    except OSError:
                        pass

    def _pipe(self, a: socket.socket, b: socket.socket):
        socks = [a, b]
        while True:
            r, _, x = select.select(socks, [], socks, self.idle_timeout)
            if x or not r:
                return
            for s in r:
                data = s.recv(65536)
                if not data:
                    return
                (b if s is a else a).sendall(data)
