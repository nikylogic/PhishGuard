# Phase 6: Backend API, logins and security

**Result: 41 / 41 tests passed.** Full log: `pytest.txt`. Role matrix: `role-matrix.md`.
Phase 0 was re-run after adding the `ticket` column: still 24 / 24.

## What was built
- `phishguard/auth.py`
  - scrypt password hashing and a password policy (8+ characters, not a common password)
  - login with brute-force protection (5 failures in 60 s locks the name for 60 s), with equal timing for a wrong username and a wrong password
  - admin and analyst roles, and an audit log
  - before every request: a Host-header check (stops DNS rebinding), an Origin check (stops cross-site requests), and a CSRF token on every state-changing request. The launcher uses its own secret token instead, compared in constant time.
- `phishguard/services.py`: the scan pipeline.
  - URL rules run at once. Blocked sites are never even opened in the sandbox.
  - The sandbox capture leads to page rules plus AI Guard on the hidden and visible text, then the verdict is saved.
  - The optional LLM runs afterwards on its own thread and can only raise the score.
  - A scan that could not be inspected is never stamped CLEAR.
  - After a restart, unfinished scans are closed off honestly.
- `phishguard/api.py`:
  - scans, decisions (open, open clean, open directly, block, ignore), history, stats, screenshots
  - allow and block lists (kept in a small file for the launcher's fast path)
  - the AI Guard playground, settings (the API key is masked), users and the audit log
- `phishguard/browser.py`: finds Chrome, Edge, Firefox or Brave and starts it by its program path with an argument list and no shell. Chromium browsers get a `--` separator, so a URL can never be read as a browser switch.
- **One-time tickets:** the pop-up window opened by the launcher gets a ticket that works once, for one scan only, so it can show the Airlock without a login.

## What the tests prove
| Area | Tests |
|---|---|
| Login, wrong password, **lock after 5 failures**, hashed passwords, logout | 5 |
| **Refused:** no CSRF token, wrong token, cross-site Origin, `Origin: null`, a foreign Host header (DNS rebinding), a wrong launcher token | 7 |
| Launcher token works without a login | 1 |
| **Role matrix:** 11 endpoints × 3 roles = 33 checks (`role-matrix.md`) | 11 |
| Phishing page through the pipeline → DANGER with the right findings | 1 |
| `javascript:` refused before anything runs; a failed capture → CAUTION, never CLEAR | 2 |
| Hidden prompt injection → AI Guard finding plus a guard event | 1 |
| **DANGER needs a second confirmation**; the browser is started as `[chrome.exe, "--", url]` | 1 |
| Open clean link removes `utm_source` and `fbclid` | 1 |
| Blocking a domain makes the next scan DANGER at once, without opening the sandbox | 1 |
| The allowlist cache file follows list changes | 1 |
| The ticket works once, for one scan only | 1 |
| Screenshot route cannot be used for path traversal and needs permission | 1 |
| Every decision is in the audit log | 1 |
| The API key is never shown back; unknown settings, a bad provider and a non-exe browser path are refused | 2 |
| User rules: weak or common password, bad name, duplicate name, deleting yourself | 1 |
| LLM in the pipeline: it raises a CLEAR scan to DANGER; **an injected "safe" reply cannot lower a DANGER scan** | 2 |
| Restart recovery; the browser never receives non-web links | 2 |

## Issues found
None failed. One design change was made while writing this phase: the Phase 0 port test now starts the server without the sandbox worker (`PHISHGUARD_NO_WORKER=1`), so it doesn't launch Chrome just to check which address the server listens on.
