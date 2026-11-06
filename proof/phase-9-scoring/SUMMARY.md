# Scoring fix: threats decide the verdict, tracking is a privacy note

**Problem found in real use:** a normal x.com post came out **Caution 40/100**. Phishing and Malware were both 0. The 40 came only from tracking: the page fingerprints the device, scrambles its code and opens WebRTC, which nearly every big website does. The old rule took the highest of the four scores as the verdict, so tracking alone could make an honest site look risky. Warnings on normal sites teach people to ignore warnings.

## What the research said

- **Google Safe Browsing** names three kinds of dangerous page: social engineering (phishing and scams), malware, and unwanted software. Tracking is not one of them. ([advisory](https://developers.google.com/safe-browsing/v4/advisory), [threat types](https://developers.google.com/safe-browsing/reference/rest/v4/ThreatType))
- **"Popular sites are safe" lists are not enough on their own.** An NDSS 2026 study found top lists cover at most about 38% of false alarms, and attackers can re-register expired domains that are still on those lists. PhishGuard therefore does **not** trust a site just because it is popular. ([NDSS 2026](https://www.ndss-symposium.org/wp-content/uploads/2026-f1869-paper.pdf), [APWG 2023](https://docs.apwg.org/ecrimeresearch/2023/20240080211286378.pdf))

## The new rule (`phishguard/rules.py`, `verdict`)

1. **Threats decide the verdict:** phishing, malware, and scams/browser abuse.
2. **Tracking is privacy, not danger.** It is still measured and shown in full, but it never raises the verdict. The exception is an **IP logger**, whose only purpose is to unmask whoever clicks, so it still counts as a threat.
3. **Weak signals need corroboration.** Scrambled code, very long links, many hyphens and a link inside a link are common on honest sites, so they only add to a verdict that a real threat already started.

The Airlock now lists what decided the verdict under **Why**, and tracking under a separate **Privacy** heading. The Tracking bar is grey when it did not count.

## Results

Real websites through the real sandbox (`scripts/real_sites_check.py`, Nov 6 2026):

| Site | Before | Now | Tracking bar | Privacy notes |
|---|---|---|---:|---|
| x.com post | Caution 40 | **Clear 0** | 40 | fingerprinting, scrambled code, WebRTC |
| youtube.com video | Clear | **Clear 0** | 6 | fingerprinting, scrambled code |
| github.com repo | Clear | **Clear 0** | 0 | - |
| amazon.in | Clear | **Clear 0** | 18 | fingerprinting, scrambled code |
| wikipedia.org | Clear | **Clear 0** | 0 | - |

The fake attack pages keep their verdicts: fake bank login, `invoice.pdf.exe`, IP logger, ClickFix, `ms-msdt:`, fake virus alert and crypto-miner are all still **Danger**, and the open redirect is still **Caution**. The fingerprint-only test page changed from Caution to **Clear**, which is the intended change. `tests/test_phase9_scoring.py` adds 8 tests for the new rule.

**Still to measure:** how many real, current phishing links PhishGuard catches. That benchmark is planned for Phase 9.
