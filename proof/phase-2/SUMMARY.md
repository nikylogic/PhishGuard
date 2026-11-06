# Phase 2: Sandbox engine and fake attack websites

**Result: 22 / 22 tests passed** (74 s, in real headless Chrome 156). Full log: `pytest.txt`. Screenshots taken by the sandbox: `shots/`. Timings: `timings.md`.

## What was built
- `tests/sites/server.py`: 25 local fake pages that behave like real attacks. They include a fake bank login, a 4-hop redirect chain, an `invoice.pdf.exe` drive-by download, a downloaded `.bat` script, a fingerprinting page, an IP-logger redirect, a ClickFix fake CAPTCHA, an `ms-msdt:` launcher, a fake virus alert, a WebAssembly "miner", an open redirect, hidden prompt-injection text, a 30-second slow page, and SSRF redirects to localhost, the cloud metadata address and LAN devices. Nothing is harmful: the "malware" is text with an executable header.
- `phishguard/sandbox.py`:
  - one warm Chrome, with a new incognito context for every scan
  - captures the redirect chain, screenshot, forms, visible and hidden text (including HTML comments), the link schemes on the page, TLS details and every contacted host
- `phishguard/hooks.js`: a watcher injected before any page script. It reports canvas, WebGL, audio, font, battery, hardware and device fingerprinting, WebRTC, clipboard writes, notification, location and camera permission requests, fullscreen, keyboard lock, beforeunload traps, pop-ups, WebAssembly, and eval/atob obfuscation.
- `phishguard/egress.py`: the **egress gatekeeper** proxy (see "Issues found" below).
- `phishguard/filetypes.py`: identifies quarantined files by their magic bytes (Windows program, shortcut, script, HTA, disk image, APK, ZIP with an executable inside, MSI, PDF, image) and detects double extensions.
- `phishguard/worker.py`: a single browser thread with a job queue, which relaunches the browser and retries once if Chrome crashes.

## What the tests prove
| Area | Proof |
|---|---|
| Redirect chain | HTTP 301/302 hops and a JavaScript redirect are recorded in order |
| Phishing form | The password form and its off-site target (`collect.test`) are recorded |
| Malware | `invoice.pdf.exe` is quarantined as `1.bin`, byte-identical, SHA-256 matches, identified as a Windows program |
| **Never executed** | A downloaded `.bat` that would create a marker file is quarantined; the marker never appears |
| Fingerprinting | canvas, fonts, audio, hardware and WebRTC are all reported |
| IP logger | The `grabify.link` hop appears in the chain |
| ClickFix | The PowerShell command copied to the clipboard is captured word for word |
| Windows protocols | `ms-msdt:` launch attempts are recorded and blocked; a `search-ms:` link on the page is detected |
| Scam pages | Fullscreen, notification request and "don't leave" trap are reported |
| SSRF | Redirects to `127.0.0.1:5157` (PhishGuard's own port) and `169.254.169.254` are blocked; images and fetches to `192.168.0.1` and `10.0.0.1` are blocked while the page itself still loads |
| Limits | A 30 s page is stopped at 16.7 s (budget 20 s) |
| Isolation | A cookie set in one scan is absent in the next |
| Recovery | After the browser is killed, the next scan relaunches it and succeeds |
| Speed | A typical warm scan takes about 1.7 s (target 3–8 s) |

## Issues found and fixed during this phase
1. **Security gap: the redirect SSRF bypass.** The first design filtered requests with Playwright's routing. The SSRF tests showed that this routing does not see later hops of a redirect chain, so a link could bounce the sandbox to `127.0.0.1` or a router. The fix is the egress gatekeeper: a local proxy that every connection must pass through, with Chrome's localhost exception removed. It resolves the address, checks it, and connects to the exact IP it checked, which also defeats DNS rebinding. All SSRF tests now pass.
2. **Slow pages overran the time budget** (30 s instead of 20 s): later steps waited for the unfinished navigation. The sandbox now stops the load (`Page.stopLoading`) when navigation times out.
3. **ClickFix test page** relied on the Clipboard API, which browsers only allow on HTTPS. The page now also uses the textarea + `execCommand('copy')` fallback that real ClickFix kits use. Both paths are watched.
4. Chrome refuses some ports by itself (`ERR_UNSAFE_PORT` for port 1), so the SSRF test now targets PhishGuard's own port 5157, which is a more realistic attack anyway.
5. One wrong expected value in a test (the order of the 301/302 statuses) was corrected.
