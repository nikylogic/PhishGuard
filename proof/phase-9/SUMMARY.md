# Phase 9: End-to-end checks, speed and security self-test

Run on 8 Nov 2026 on the development PC (Windows 11, AMD Ryzen with 16 threads, 16 GB RAM, Python 3.12.10).

## Results

| Check | Result | File |
|---|---|---|
| Full test suite | **511 passed, 0 failed, 2 skipped** (513 tests, 3 min 17 s). The two skips need a live LLM API key and a real Tor download; both were checked by hand in phases 5 and 8c. | `pytest.txt`, `junit.xml`, `test-cases.md`, `test-cases.csv` |
| Security self-test | **63 of 63 attacks stopped**: network exposure, DNS rebinding, CSRF, authentication, SQL injection, path traversal, unsafe links, parser confusion, SSRF (including real DNS names that point back to the PC), XSS in a real Chrome window, sandbox containment, prompt injection, the link launcher, password guessing. | `security-selftest.md`, `security-selftest.json`, `security/*.png` |
| Speed | **Every target met** (median of 20 runs): trusted link 0.23 s installed (target < 0.3 s), URL verdict 0.43 ms (< 50 ms), AI Guard 2.5 ms per text and 0.5 ms per chunk of a long page (< 5 ms), sandbox capture of a real site 2.25 s (3-8 s typical, 20 s limit). Click to full verdict on a real site: 2.36 s. | `performance.md`, `performance.json` |
| Code review | One high-severity and one low-severity problem found and fixed; the rest checked and sound. | `code-review.md` |

## Found and fixed in this phase

1. **Backslash confusion (high).** For `https://evil.example\@en.wikipedia.org/`, Python's URL parser reported the host `en.wikipedia.org` (trusted, so the launcher opened the link directly) while Chrome opens `evil.example`. Any trusted name could be used to skip the airlock. The launcher and the engine now read `\` as `/` before the `?` or `#`, exactly as browsers do; the hosts were compared against Chrome's own `new URL()`. Regression tests: `tests/test_phase9_security.py`.
2. **PhishGuard as its own "real browser" (low).** The installed `PhishGuard.exe` could be chosen as the real browser in Settings, which would send every opened link back into PhishGuard. It is now refused, like Python already was.

## Measurement pitfalls found (and how the numbers were kept honest)

- The first speed run showed 0.66 s for a trusted link in the installed app. The cause was the measuring script: it attached output pipes, and the timer waited for them to close. Windows starts the app without pipes; measured that way it is 0.23 s. The script now runs the app without pipes and says so.
- The 5 ms AI Guard target is per text. A 4,000-character page is cut into 10 chunks and takes about 6 ms in total (0.5 ms per chunk); both rows are reported.
- The installed app switches Start with Windows on at its first run in a data folder. The speed script now marks its throwaway folders as already set up, so measuring never touches the real registry. (The audit log showed the setting had never been changed by hand, and it was already on.)

## Scripts

- `scripts/phase9_perf.py`: the speed measurements.
- `scripts/phase9_security.py`: the security self-test (starts a real engine on a spare port, the local fake attack sites, the real sandbox and a real Chrome window).
- `scripts/phase9_testtable.py`: exports the final run as tables for the report.
- `tests/sites/server.py`: new `/xss` page whose title, text and form carry script payloads.
