# Phase 8c: Hide my IP

**Goal:** while PhishGuard checks a link, the website should not learn the user's IP address, DNS server or time zone. This must work at no cost, and if the private route is down the check must fail rather than quietly go out directly.

## How it works

The sandbox browser already sends every connection through PhishGuard's gatekeeper proxy (`egress.py`, built in Phase 2 to stop SSRF and DNS rebinding). Hide my IP adds one step: the gatekeeper forwards the connection onward through a **route** (`privacy.py`).

| Route | What it is | What the user does |
|---|---|---|
| **Tor** (built in) | PhishGuard downloads the official Tor Expert Bundle 16.0 once from `archive.torproject.org` and runs `tor.exe` itself | Choose Tor, press **Download Tor**, then **Save** |
| **Cloudflare WARP** | The free WARP app, used only if the user already runs it in proxy mode | `warp-cli mode proxy` and `warp-cli connect`, then choose WARP |
| **My own proxy** | Any SOCKS5 or HTTP proxy | Type its address |

While a route is on:

- **Nothing goes out directly.** If the route does not answer, the gatekeeper refuses the connection, and the check fails with a clear message. There is never a fallback to a direct connection.
- **No DNS lookups on this PC.** The gatekeeper passes the site's *name* to the route (a SOCKS5 domain request or HTTP `CONNECT name:port`), and the route looks it up. The user's DNS server and internet provider do not see which sites were checked.
- **Local addresses are still refused.** Names such as `localhost`, `printer`, `nas.local` and `router.home.arpa`, and private addresses such as `10.x`, `192.168.x` and `::1`, are blocked before they reach the route.
- **WebRTC is removed** from every page and frame. WebRTC can send UDP traffic that bypasses a proxy and reveal the real address to a STUN server. Testing showed that Chrome's command-line WebRTC switch did not take effect in the sandbox, so the APIs are removed with a script instead, and a test checks the result.
- **Neutral time zone.** Pages see the time zone as UTC.
- **A new Tor circuit for every check.** Each check uses a different SOCKS login, and Tor keeps those apart.

### Where Tor comes from

- The download URL and its SHA-256 (`2ee123e9…77c4`) are fixed in the code.
- The hash was taken from Tor's `sha256sums-signed-build.txt`. That file's signature was checked with gpg: "Good signature from Tor Browser Developers (signing key)", primary key `EF6E 286D DA85 EA2A 4BA7 DE68 4E2C 6E87 9329 8290`.
- If a download does not match the hash, it is deleted.
- Only three files are unpacked: `tor/tor.exe`, `data/geoip` and `data/geoip6`. Links, path tricks and every other file in the archive are ignored or refused.
- Tor listens only on `127.0.0.1` with a random port, and its control port is off.
- `__OwningControllerProcess` makes Tor quit when PhishGuard quits.

### Not offered, on purpose

- **Free public proxy lists.** They are often run by unknown parties who can read or change the traffic.
- **Unofficial WARP clients** (wgcf/wireproxy). They break Cloudflare's terms.

## Results

- **Real Tor network** (`live-tor.txt`):
  - Downloaded, checked, and connected in 9.8 s.
  - check.torproject.org answered `IsTor=True` through Tor and `IsTor=False` directly, and the two addresses differ. The addresses themselves are not recorded.
- **End to end in the app** (`scripts/shots_phase8c.py`, no console errors). In a throwaway instance:
  - Settings → Tor → Download Tor → Save → Test, which showed "Sites see … (a Tor address)".
  - A real check of `https://check.torproject.org/` returned the page "**Congratulations. This browser is configured to use Tor.**", and the Airlock says "Opened in 8.4 s through Tor".
  - Screenshots: `settings-tor-downloading.png`, `settings-tor-test.png` (your addresses blurred), `airlock-through-tor.png`, `airlock-through-tor-details.png`.

## Tests (`tests/test_phase8c_privacy.py`, 44 passed + 1 live test run separately)

The test sites have names ending in `.invalid`, which cannot be looked up on this PC at all. Only the fake SOCKS5 and HTTP proxies know where they are, so a page that loads proves its traffic used the route. The gatekeeper's resolver is replaced with one that records any local lookup, and the tests require it to stay empty.

- **Proxy address box:**
  - 3 address forms are accepted.
  - 9 bad forms are refused (SOCKS4, HTTPS, no port, a path, spaces, and so on).
  - The password is never shown or sent back.
  - Saving the masked address again keeps the real password.
- **Gatekeeper:**
  - Names go to the route as names, with no local lookup.
  - HTTPS works, and HTTP proxies work too.
  - With the route down, nothing reaches the site.
  - 7 local names and private addresses are refused before reaching the route.
  - Each Tor check uses a new login.
- **Real sandbox browser:**
  - A whole page loads through the route: the page, an image and a fetch, all sent as names.
  - The page sees `TZ=UTC` and has no WebRTC.
  - When the route is unavailable, the page is never opened: no screenshot, and the site gets no request.
- **Tor:**
  - A correct download unpacks exactly 3 files, and an `../escape.txt` entry is ignored.
  - A tampered download is deleted.
  - A symbolic link posing as `tor.exe` is refused.
  - The pinned URL is torproject.org's.
  - Tor is started on 127.0.0.1 with its control port off and quits with PhishGuard.
  - If Tor is not downloaded, checks fail closed.
- **WARP:** four cases: not installed, not in proxy mode, ready (with the port read correctly), and disconnected (fails closed).
- **Settings API:**
  - Hide my IP is off by default.
  - The custom proxy is saved and checked.
  - The Test button shows the address sites see.
  - When Tor is not ready, Test explains why.
  - Only admins can change these settings, and only with a CSRF token.

**Full suite after this phase:** 393 passed, 2 skipped (the live-LLM test, which needs an API key, and the live-Tor test, which is opt-in and was run separately).

## Honest limits

- Hide my IP covers the **check**. Opening the link afterwards in your own browser uses your normal connection, and the Settings card says so.
- Tor exit addresses are public, and some sites block them or show CAPTCHAs, so a check through Tor can sometimes see a different page than a normal visitor would.
- A custom proxy (and WARP) can see which sites are checked. Use only one you trust.
