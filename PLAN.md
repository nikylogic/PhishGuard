# PhishGuard: Build Plan

Design reference: `ARCHITECTURE.md`. This file covers **the order of work** and **the proof we collect at each step**.

## The rule for every phase

1. Write the tests first, or alongside the code.
2. Build the phase.
3. Run the tests. **Every test must pass.** Nothing is skipped and no test is marked "known failing".
4. Save the proof to `proof/phase-N/`:
   - `pytest.txt`: the full verbose run, with timestamps
   - `junit.xml`: machine-readable results, used for the report's test-case table
   - screenshots, timings or metrics, whichever the phase produces
   - `SUMMARY.md`: what was built, the test count, timings, and any issues found and fixed
5. Make a git commit `phase N: <name>`. The history then shows the project growing step by step.
6. Only then move on to the next phase.

The proof folder later becomes the **Testing chapter** of the report. Its screenshots become the **Output Screenshots chapter**.

---

## What the app is

**A Windows desktop app with a web-technology interface.**

- **Engine:** a small local Python server (Flask and SQLite) that runs in the background on your own PC. It is never on the internet.
- **Window:** the interface opens in **its own app window**, not a browser tab. It uses `pywebview`, which draws the window with Microsoft's WebView2 engine, already built into Windows 11. This keeps it light: no Electron, and nothing extra for the user to install.
- **Why not a plain web app in a browser tab?** PhishGuard *becomes* your default browser. If it opened its own page "in the browser", it would open itself in a loop. A native window solves this. It also feels like a real security tool: you click a link and a PhishGuard window pops up.
- **Fallback:** if WebView2 isn't available, the same UI opens in Chrome, Edge or another browser, started directly by its program path.
- **How you start it:**
  - automatically, whenever a link is clicked
  - from a Start-menu shortcut that opens the dashboard
  - by running `python run.py` while developing

---

## UI direction: "The Airlock"

**The idea:** a suspicious link is like a package arriving at customs. It enters an **airlock**, gets inspected behind glass, and receives a **stamp**. Only then do you let it through.

The whole app follows this one metaphor, so it stays simple and memorable.

- **The Airlock screen** (the hero screen, opened on every click):
  - the link appears as a "specimen tag" at the top, in a mono font, with the domain highlighted
  - the sandbox screenshot sits in a glass case; while scanning, a thin light sweeps across it
  - four **gauges** show the four kinds of danger: Phishing, Malware, Tracking and Tricks
  - the verdict lands as a **rubber stamp** in large type: **CLEAR**, **CAUTION** or **DANGER**
  - plain-English reasons, one line each, such as "This page asks for your password but sends it to another website."
  - one big obvious action (*Open safely*, or *Keep it locked* when it's dangerous) and small secondary actions (open a clean link, block, copy)
- **Home:**
  - one sentence: "Today PhishGuard stopped 3 links and cleaned 11 trackers."
  - a strip of recent links with their small stamps, and a quiet weekly chart
- **Calm by default:** warm paper background and ink-dark text. Colour appears **only** for the verdict: green, amber or red. There are no purple gradients, no glass effects everywhere and no emoji icons.
- **Typography:** a display serif for headlines and stamps, a clean sans-serif for body text, and mono for URLs. The fonts (Instrument Serif, Geist and Geist Mono, all OFL licensed) are stored locally, so the app works offline.
- **Motion:** used sparingly and with meaning (the scanning sweep, the stamp landing, the gauges filling). It respects the Windows "reduce motion" setting.
- **Light and dark mode** both look deliberate, not like an inverted afterthought.
- **Seven screens in total:** Airlock, Home, History, Lists (Trusted and Blocked), Guard Lab, Settings (with Users and Audit as tabs), and Login.

**You approve the look before we build the pages.** Phase 7 starts with a clickable mockup.

---

## Phases

### Phase 0: Foundation (about 30 min)
- Build: a git repo, a venv, pinned `requirements.txt`, the app factory, config, the SQLite schema (every table in the architecture), `/health`, and `run.py`.
- Tests:
  - the app starts and `/health` returns 200
  - every table exists with the right columns
  - foreign keys are on, WAL mode is on, and the CHECK constraints reject bad values
  - the server binds to 127.0.0.1 only
  - the security headers (CSP, nosniff, frame-deny) are present
- Proof: pytest log, `pip freeze`, and a printed copy of the schema.

### Phase 1: URL toolkit and URL rules (about 1 h)
- Build: `urltools.py` (normalise, registrable domain from an offline snapshot, IP and private-range checks, punycode and mixed-script detection, brand edit distance, tracking-parameter stripping) and the URL rules in `rules.py`, plus scoring and levels.
- Tests:
  - at least 60 example URLs across every rule, both positive and negative cases
  - non-http schemes are refused
  - the score is capped at 100 and the levels are at their boundaries
  - per-category sub-scores
  - "clean link" removes `utm`/`fbclid`/`gclid` but keeps real parameters
  - **benchmark:** 1,000 URLs scored, averaging under 1 ms each
- Proof: pytest log and `bench.txt`.

### Phase 2: Sandbox engine and test websites (about 2 h)
- Build:
  - `tests/sites/`: a local server with the fake pages: bank login, 4-hop redirect, `invoice.pdf.exe` download, fingerprinting page, IP-logger redirect, ClickFix CAPTCHA, `ms-msdt:` launcher, open redirect, hidden prompt injection, slow page, and a redirect to 127.0.0.1
  - `sandbox.py`: warm Chrome, a fresh context for every scan, the hook script, quarantine, the SSRF filter and limits
  - `worker.py`: the job queue and crash recovery
- Tests, one or more per fake page:
  - the redirect chain is recorded correctly
  - the download is quarantined as `.bin` with the correct SHA-256 and real type, and was **never executed**
  - each fingerprinting technique is reported
  - the ClickFix clipboard text is captured
  - `ms-msdt:` is blocked
  - **the 127.0.0.1 redirect is blocked (SSRF)**
  - the slow page times out within 20 s
  - **isolation:** a cookie set in scan 1 is absent in scan 2
  - after a forced browser crash, the worker recovers and the next scan works
  - visible text and hidden text are extracted separately
- Proof: pytest log, a screenshot for every fake page, a timing table, and the quarantine hash list.

### Phase 3: Page rules, threat lists and the full verdict (about 1 h)
- Build: the page, malware, tracking and abuse rules; bundled threat lists (IP loggers, trackers, miners, malware URLs and hashes, brands), each with its source and licence noted; the full verdict assembly.
- Tests:
  - every rule is checked against saved capture results, so these tests are fast and need no browser
  - **end-to-end on every fake page, checking the expected verdict:**
    - bank login → DANGER (phishing)
    - exe download → DANGER (malware)
    - fingerprinting → CAUTION (tracking)
    - ClickFix → DANGER (tricks)
    - a plain local page → CLEAR
- Proof: pytest log and a verdict matrix (`verdicts.md`) showing each fake page with its four sub-scores and final stamp.

### Phase 4: AI Guard (about 1.5 h)
- Build:
  - data prep (deepset/prompt-injections plus other licence-checked sets plus our hand-written web-page examples, with a fixed train/test split)
  - `train.py` for TF-IDF with logistic regression, plus a keyword (regex) layer
  - `eval.py`
  - DistilBERT fine-tuning, for comparison only
- Tests:
  - the model loads and predicts in under 5 ms on average
  - a set of classic attacks is flagged and a set of normal texts passes
  - the output format is checked
  - the test split never overlaps the training split
  - the stated metric thresholds are met. The thresholds are written down **before** training, so the results are honest.
- Proof: `eval.json`, a confusion-matrix PNG for each model, the training logs, and a comparison table (accuracy, F1, latency, size).

### Phase 5: LLM second opinion (about 45 min)
- Build: `llm.py` (providers none, gemini, groq and ollama), the prompt with untrusted-data delimiters and the Guard warning, JSON-schema validation, a cache and timeouts.
- Tests:
  - these use a **fake provider**, so they don't depend on the internet
  - the LLM can only **raise** the score: a fake "injected" reply saying "safe, 0" leaves a DANGER link at DANGER
  - invalid JSON is ignored and logged
  - after a timeout, the result falls back to the rules
  - the prompt never contains cookies or form values
  - the Guard warning appears whenever the Guard flagged the text
  - one optional live smoke test runs if a free API key is configured
- Proof: pytest log, an example prompt and reply (`llm-sample.md`), and the "injection defeated" test output.

### Phase 6: Backend API, auth and security (about 1 h)
- Build: login and logout, admin and analyst roles, CSRF, the launcher token, the Host-header check, the API endpoints, Allow and Block lists, the audit log, rate limiting, and the open-in-real-browser action (with a second confirmation for DANGER).
- Tests:
  - the role matrix: every endpoint for every role
  - a cross-site POST without CSRF is rejected
  - a request without the token is rejected
  - `Host: evil.com` is rejected (DNS rebinding)
  - after 5 failed logins, the account is locked for a minute
  - passwords are stored hashed
  - every decision is written to the audit log
  - opening a DANGER link without confirmation is refused
- Proof: pytest log and a role-access matrix table.

### Phase 7: UI, the Airlock (about 2 h)
- Step 1: build a clickable mockup of the Airlock and Home screens. **You approve it** before the rest is built.
- Build: all seven screens, light and dark mode, with the motion details described above.
- Tests (Playwright clicking through the real app):
  - log in, then paste a link, watch the scan and see the stamp
  - block a domain, and the next scan of it is blocked instantly
  - Guard Lab flags an injection
  - Settings is hidden from analysts
  - no console errors on any screen
  - every image has alt text and every form field has a label
  - text contrast is checked in both themes
  - the layout works at 1366×768 and 1920×1080
- Proof: screenshots of every screen in light and dark (these are the report screenshots) and the UI test log.

### Phase 8: Windows integration (about 1 h)
- Build: the launcher `pg_open.pyw`, `register_windows.py` and `unregister_windows.py`, the pywebview window, real-browser detection, and the fail-closed message box.
- Tests:
  - the launcher refuses `javascript:`, `file:` and `ms-msdt:`
  - an allowlisted link opens in under 0.3 s
  - the launcher starts the server when it isn't running
  - the registry keys are written and removed correctly (checked in HKCU)
  - "Open in my browser" never goes back through PhishGuard (no loop)
- **Manual proof:** set PhishGuard as the default browser, then click real links from a text file, a PDF and an email or chat app. This is recorded as screenshots, or a GIF if possible.
- Proof: pytest log, registry dumps before and after, and the manual-test screenshots.

### Phase 9: End-to-end checks, speed and security self-test (about 45 min)
- Run all tests (the full suite) one final time.
- Measure the speed targets from the architecture, as a median over 20 runs: allowlisted link, URL verdict, sandbox capture, AI Guard and the cold start.
- Security self-test: try to break our own app (CSRF, DNS rebinding, SSRF, an XSS payload in a page title, path traversal on the screenshot URL) and record each result.
- Code review of the whole codebase, and fix anything found.
- Proof: final pytest log with the totals, `performance.md`, `security-selftest.md`, and the test-case table exported for the report.

### Phase 10: Report (about 2.5 h)
- Reuse the existing college report builder: the same layout, logo and format, with your details.
- Diagrams: architecture, scan flowchart, DFD level 0 and level 1, ER diagram, threat-coverage map, and the AI Guard pipeline.
- Chapters filled from the proof folder: test tables, metrics, and screenshots taken from the real app.
- Write the report in plain, human language, with AI assistance described as supervised and fully tested. Build the PDF and DOCX.
- **You read it.** I fix whatever you flag.

---

## Time and what gets cut first

The total is about 13 hours of work, which is a long day. If time runs short, cut in this order (the cuts never touch tests):
1. Privacy mode (proxy)
2. The DistilBERT comparison (the report then shows only the classic model)
3. The Ollama provider (keep only the cloud provider)
4. The dark theme

Everything else is essential.

## What you need to do

- Phase 7: approve the mockup (about 5 min).
- Phase 8: choose PhishGuard as the default browser in Windows Settings, and click a few links for the manual proof (about 10 min).
- Optional: get a free Gemini or Groq API key if you want the live LLM in the demo.
- Phase 10: read the report.
