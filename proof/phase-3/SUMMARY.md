# Phase 3: Page rules, threat lists and the full verdict

**Result: 42 / 42 tests passed** (18.8 s). Full log: `pytest.txt`. Verdict matrix: `verdicts.md`.
Phase 2 was re-run after this phase's fix to the watcher script: still 22 / 22.

## What was built
- `phishguard/pagerules.py`: 25 page rules in four categories, and `analyse()`, which builds the full verdict.
  - **Phishing:** password on http, password sent to another site, a brand login page on the wrong domain, redirected away, a brand-new certificate.
  - **Malware:** known-malware URL (checked on every hop), known-bad SHA-256, executable download, disguised download, archive or disk image hiding a program, download without a click.
  - **Tracking:** fingerprinting (6 points per technique, capped at 30), WebRTC, more than 10 trackers, an IP logger in the chain.
  - **Tricks:** ClickFix clipboard command, Windows-app launch, Windows-app links, crypto-miner, fake alert with a trap, keyboard lock, permission grab, obfuscation, open redirect, prompt injection (used in Phase 4).
  - A rule counts once even if both the URL check and the page check find it. The privacy report lists trackers, fingerprinting techniques, IP logger, WebRTC and the tracking parameters removed.
- `phishguard/intel.py`: an `Intel` class that loads the threat lists into sets, so every lookup is constant-time and checks sub-domains too.
- `phishguard/data/`: a hand-compiled tracker list (95 domains) and miner list (18 domains), plus empty malware URL and hash lists ready for import.

## What the tests prove
- **Part A (32 tests, no browser):** every page rule fires on the right input and stays quiet on look-alike harmless input. Examples: a PayPal title without a password field is not flagged; a real paypal.com login is not flagged; a game using WebAssembly is not called a miner; an article that talks about scams is not a "fake alert"; mailto/tel links are not Windows-app launches.
- **Part B (10 tests, real sandbox):** every fake attack page gets the expected stamp, and the expected category leads:

| Fake page | Stamp | Leading category |
|---|---|---|
| Normal page | CLEAR | – |
| Fake bank login | DANGER | Phishing 95 |
| invoice.pdf.exe | DANGER | Malware 100 |
| Fingerprinting page | CAUTION | Tracking 40 |
| IP-logger link | DANGER | Tracking 60 |
| ClickFix | DANGER | Tricks 70 |
| ms-msdt launcher | DANGER | Tricks 60 |
| Fake virus alert | DANGER | Tricks 55 |
| Crypto-miner | DANGER | Tricks 65 |
| Open redirect via trusted site | CAUTION | Tricks 35 |

## Issues found and fixed during this phase
1. **False "obfuscation" on busy pages.** The watcher counted `eval` calls, and Playwright itself uses `eval` to answer each report, so pages that triggered several reports looked obfuscated. Calls from Playwright are now excluded, and a regression check was added to the end-to-end tests.
2. **Fingerprinting alone reached DANGER** (5 techniques at 8 points plus WebRTC at 15 = 55). Ad-heavy sites fingerprint too, so this was too harsh. The weights are now 6 per technique (capped at 30) and 10 for WebRTC, so fingerprinting alone gives CAUTION. An IP logger still gives DANGER.
3. **Windows Defender quarantined the fake miner page** (`Trojan:JS/CoinHive.B`) because it contained a real CoinHive call pattern. The fake page now uses a neutral miner-like configuration that the rule still detects. No antivirus exclusions were added.
4. **Threat feeds:** the abuse.ch bulk downloads (URLhaus, MalwareBazaar) now return HTTP 410 Gone, and OpenPhish redirects. So no third-party list is bundled; the admin can import any feed they are licensed to use.
5. Brand names now display properly ("HDFC Bank", "PayPal", "SBI").

## How end-to-end tests treat the local test server
The fake sites run on plain http at a random port, so the URL rules `NO_HTTPS` and `UNUSUAL_PORT` would add the same 25 points to every page. They are switched off in the Part B matrix only; Phase 1 tests them on their own.
