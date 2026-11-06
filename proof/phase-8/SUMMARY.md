# Phase 8: Windows integration

**Goal:** a link clicked anywhere in Windows (a chat app, an email, a PDF, a text file) comes to PhishGuard first. Trusted sites open at once. Every other link opens in the Airlock window with its verdict, and nothing ever opens unchecked.

## What was built

- **`launcher/pg_open.pyw` + `launcher/pglaunch.py`:** the program Windows runs for every clicked link. It uses only the standard library (no Flask), so a click stays fast.
  1. **Only web links.** Anything that is not `http` or `https` is refused with a message box: `javascript:`, `file:`, `ms-msdt:` (the Follina attack), `vbscript:`, `data:` and `search-ms:`. Links containing spaces, control characters or invisible characters (zero-width spaces, right-to-left overrides) are also refused.
  2. **Trusted sites open directly.** The launcher reads `allowlist.txt` and `browser.txt`, which the engine keeps up to date, so this needs no network call. Exact domain or subdomain matches only: `wikipedia.org.login-check.top` is not trusted.
  3. **Every other link goes to the engine.** It is sent with the launcher's secret token. If the engine is not running, the launcher starts it in the background and waits for `/health`; it also checks that the program answering really is PhishGuard.
  4. **The Airlock opens in its own window** (pywebview, using Windows' built-in Edge WebView2). A one-time ticket lets that window see that one check without logging in. If the window cannot open, the Airlock page (a local PhishGuard page, never the unchecked link) is shown in the real browser instead.
  5. **Fails closed.** On any error, a message box says "PhishGuard could not check this link, so it was not opened."
- **No loop back into PhishGuard.** PhishGuard is the default browser, so asking Windows to "open this URL" would send the link straight back to it. The real browser is always started by its own program file. Python (`python.exe`, `pythonw.exe`) is never accepted as the "real browser": not in Settings, not in `browser.txt`, and not by the launcher.
- **`scripts/register_windows.py` / `unregister_windows.py`:**
  - Registration writes only under `HKEY_CURRENT_USER`, so no admin rights are needed. It writes a `PhishGuardURL` link type, an app entry with its http/https capabilities, and a `RegisteredApplications` entry.
  - Windows then lists PhishGuard in **Settings → Apps → Default apps**, and the user picks it there. Windows does not let programs make themselves the default, and that is on purpose.
  - Unregistering removes exactly what was written. It removes only PhishGuard's own value from `RegisteredApplications`, because other apps keep their entries in that same key.
- **Engine changes:**
  - The engine writes `browser.txt` at start-up and whenever the browser setting changes.
  - The Airlock tabs and cards were tidied after testing them in the real window.

## Results

- **Speed:** a trusted link, run as a separate process 20 times, takes **92 ms** median, including starting Python (target: under 300 ms). See `timings.md`.
- **Registry:** `registry.txt` lists every key and value as written, and shows that nothing is left after unregistering.
- **Real window:**
  - `launcher-window-danger.png` shows the real `pg_open.pyw` opening the Airlock window for `http://paypa1-secure.top/login?utm_source=mail`.
  - `launcher-refused-javascript.png` shows the message box for a `javascript:` link.

## Tests (`tests/test_phase8_launcher.py`, 24 passed)

- **Refusing:**
  - Nine kinds of non-web or disguised links are refused.
  - For each one: nothing is started, there is no server call and no window, and exactly one message box says the link was not opened.
- **Trusted sites:**
  - A trusted link opens directly in the real browser, passed as a list argument with `--`, in under 300 ms.
  - Three look-alikes of trusted sites are not trusted.
  - The real `pg_open.pyw` process opens a trusted link in under 300 ms (median of 7 runs).
- **Engine:**
  - With no engine running, the real launcher starts it, submits the link and prints the Airlock address.
  - The ticket works exactly once, and only for that check.
  - A second click reuses the running engine.
- **Failing closed:**
  - If the engine cannot start, the result is a message box and nothing opened.
  - The same holds if something else is answering on the engine's port.
- **No loop:**
  - Python is never chosen as the browser: not by `browser.choose`, not by the Settings API, and not by the launcher.
  - The launcher never calls `os.startfile` or `webbrowser`, or uses `shell=True`.
  - The engine's `browser.txt` only ever holds a real browser.
- **Registry (written under a throwaway HKCU key):**
  - Every key and value is correct.
  - Unregistering removes only PhishGuard's entries and leaves another app's entry alone, and running it twice is harmless.
  - The exact command line Windows would run really starts the launcher.

**Full suite after this phase:** 329 passed, 1 skipped (the live-LLM test, which needs an API key).

## Still to do by hand (the manual proof)

1. Run `python scripts/register_windows.py`.
2. In **Settings → Apps → Default apps → PhishGuard**, choose PhishGuard for HTTP and HTTPS.
3. Click real links from a text file, a PDF and a chat or email app, and take screenshots.
4. To undo: run `python scripts/unregister_windows.py`, then choose your normal browser again.

## Proof files

- `pytest.txt`, `junit.xml`: the Phase 8 test run.
- `registry.txt`: the registry before and after.
- `timings.md`: launcher speed.
- `launcher-window-danger.png`, `launcher-refused-javascript.png`: the real launcher in action.
