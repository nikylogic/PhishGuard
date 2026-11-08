# Phase 9: Code review

Reviewed on 8 Nov 2026: the engine (`phishguard/`, about 6,300 lines of Python), the launcher and tray
(`launcher/`), and the dashboard (`web/src`, about 7,100 lines of TypeScript/React). The review
followed the attack paths in ARCHITECTURE.md section 8 and was driven by the security self-test
(`security-selftest.md`): every place where outside data (a clicked link, a web page, a download,
an LLM reply, a request to the local server) enters the program was read.

## Found and fixed

| # | Severity | Where | Problem | Fix | Regression test |
|---|---|---|---|---|---|
| 1 | **High** | `urltools.normalise`, `pglaunch.check_link` | **Backslash confusion.** Python's `urlsplit` keeps `\` as an ordinary character; Chrome and Edge read it as `/` in web links. For `https://evil.example\@en.wikipedia.org/` PhishGuard saw the trusted `en.wikipedia.org`, so the launcher opened the link directly, while the browser went to `evil.example`. Any trusted name could be used to skip the airlock. | Both read `\` as `/` before the `?` or `#`, exactly as browsers do (`browser_slashes`). The launcher, the engine and Chrome now agree on the host (checked against Chrome's own `new URL()`). | `tests/test_phase9_security.py` (13 cases) |
| 2 | Low | `browser.NOT_A_BROWSER`, `pglaunch.NOT_A_BROWSER` | The installed `PhishGuard.exe` (the default browser) could be chosen as "your real browser" in Settings; every opened link would then come straight back into PhishGuard. | `PhishGuard.exe` and `PhishGuardEngine.exe` are refused as the real browser. | `test_phishguard_itself_is_never_the_real_browser` |

## Checked and found sound

- **No shell, ever.** Every program start (`browser.open_url`, `pglaunch.open_in_browser`, engine start) passes a list of arguments; Chromium browsers get `--` before the link so a link can never be read as a browser switch.
- **SQL:** every query uses `?` placeholders. The one f-string (`services.purge`) inserts fixed text only.
- **Only http/https reaches the real browser:** `browser.open_url` re-checks the final address with `normalise()` before starting the browser, so a page cannot redirect the "Open" button to `file:` or `ms-msdt:`.
- **Egress gatekeeper (`egress.py`):** resolves the name itself, refuses if *any* answer is private, then connects to the exact IP it checked, so DNS rebinding between check and connect is impossible. WebSocket upgrades and CONNECT tunnels go through the same check.
- **Request checks (`auth.check_request`):** Host allowlist (DNS rebinding), Origin check (`null` refused), CSRF token compared with `hmac.compare_digest`; the launcher token is a separate 256-bit secret.
- **Sessions and tickets:** Airlock tickets and dashboard entry codes are single-use, random (`secrets.token_urlsafe`) and bound to one check.
- **Passwords:** scrypt hashes; a wrong username costs the same hash time as a wrong password; 5 failures lock the name for 60 s.
- **Rendering:** the dashboard renders all page data through React text nodes; there is no `dangerouslySetInnerHTML`, no `innerHTML` and no `eval` in `web/src`. The CSP has no `unsafe-inline` for scripts.
- **Downloads:** written into quarantine under `<n>.bin`, never with the site's file name or extension, and never opened.
- **LLM:** the reply is validated against a fixed JSON shape and can only raise a sub-score (`llm.apply_opinion`).

## Noted, not changed

| Item | Why it stays |
|---|---|
| The egress gatekeeper listens on a random 127.0.0.1 port without a password while a check runs. | Only programs already running on this PC can reach it, and it refuses private addresses for them too. A local program could make internet requests directly anyway. |
| The installer is not code-signed, so Windows SmartScreen warns on first run. | A code-signing certificate costs money; the README tells users what to expect and how to build from source. |
| Local phishing-list snapshot and brand list need regular updates. | Lists update every 6 hours; brands are one line each in `phishguard/data/brands.json`. |
