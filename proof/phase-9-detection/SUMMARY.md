# Phishing detection: every layer, measured on real phishing

**Goal:** tell a real website from a fake one reliably, including look-alike banks (HDFC vs HSBC), brand-new scam domains and phishing pages on free hosting, without warning on honest sites.

## The layers

| # | Layer | What it catches | Source (all free) |
|---|---|---|---|
| 1 | **Public phishing lists** (`feeds.py`), downloaded every 6 hours and checked on this PC | Phishing that someone has already reported | OpenPhish community feed, phishunt.io (CC0), Phishing.Database (MIT, ~390,000 domains) |
| 2 | **Domain age** (`domaininfo.py`) | Scam domains registered days ago | RDAP, the registries' official replacement for WHOIS |
| 3 | **Certificate history** (`domaininfo.py`) | The same, when RDAP has no date: the first HTTPS certificate shows when a site appeared | crt.sh (Certificate Transparency logs) |
| 4 | **Identity check** (`identity.py`): which brand does the page claim to be, and is this that brand's website? | Fake bank, payment and brand logins, however the address is spelled | The method of Phishpedia (USENIX Security 2021); 107 brands with their real domains and 284 favicon fingerprints |
| 5 | **Login with no brand** (`identity.py`) | Fake portals: a password/OTP/card form on a free hosting platform or a weeks-old domain | The idea of PhishIntention (USENIX Security 2022): what a page asks for matters as much as how it looks |
| - | Address rules, page behaviour, sandbox, AI layers | As before, plus brand names hidden inside longer names (`googleplaydown.com`) | - |

### Why HDFC is never mistaken for HSBC

The identity check never compares how names *look*. It asks what the page claims to be, from its copied favicon, logo, title, site name and text, and then whether the website is in that brand's list of real domains. The real `hdfcbank.com` shows HDFC's logo on HDFC's domain: clear. An HSBC login on any other domain: danger. Names only matter in the address rules, and there short tokens like `hdfc` and `hsbc` match exactly, never "nearly".

### Guards against false alarms

- **Shared hosts are never condemned whole.** Phishing.Database lists `sites.google.com`, `amazon.ie` and `gravatar.com` because a phishing page was once placed there. A list can name a whole site only if it is not popular (Tranco top 10,000), not a brand's own domain, not a free hosting platform itself and not in a verified zone. Otherwise only the exact reported address matches.
- **Verified zones:** `.gov.in`, `.bank.in` (the RBI's zone for Indian banks since 2025), `.ac.in` and brand endings like `.sbi` can only be registered by verified owners, so pages there are never "impersonations". The address parser was taught `bank.in` and `fin.in`, which its bundled list predates.
- **Popular sites** are not called look-alikes (`cooking.com` is not a fake `booking.com`), but the popularity list is never treated as proof of safety (an NDSS 2026 study found such lists are abused through expired domains).
- **Ordinary words** (apple, chase, steam, zoom) need a deliberate copy of the brand (favicon, logo, site name) before a page counts as claiming that brand.
- **News and forums:** a known site, or one that names itself in its title, writing about a brand is not an impersonation.
- **Privacy:** only the website's name (never the full link) goes to RDAP and crt.sh, through Hide my IP's route when it is on. Popular sites, brands' own domains and free hosting platforms are never looked up.

## Results

Two batches of real phishing links (OpenPhish, phishunt.io) and real websites, opened in PhishGuard's sandbox on 6 Nov 2026. `scripts/benchmark.py` collects and scores them. "Before" is the actual previous code (commit `33448cf`), run on the same saved pages.

| Batch | Version | Phishing called Danger | Phishing warned (Danger or Caution) | Real sites warned | Real sites called Danger |
|---|---|---:|---:|---:|---:|
| **Held-out, as measured** (71 phishing, 61 real; never used for tuning) | Before | 4/71 (6%) | 32/71 (45%) | 6/61 (10%) | 3/61 (5%) |
| | After, without the lists | 32/71 (45%) | 62/71 (87%) | 3/61 (5%) | 2/61 (3%) |
| Held-out, after the fixes it revealed, AI Guard included | Before | 4/71 (6%) | 35/71 (49%) | 21/61 (34%) | 3/61 (5%) |
| | After, without the lists | 32/71 (45%) | 62/71 (87%) | 0/61 (0%) | 0/61 (0%) |
| Tuning set (83 phishing, 109 real; the rules were adjusted on it), AI Guard included | Before | 2/83 (2%) | 41/83 (49%) | 27/109 (25%) | 4/109 (4%) |
| | After, without the lists | 35/83 (42%) | 72/83 (87%) | 1/109 (1%) | 0/109 (0%) |
| Both | After, all layers | 100% | 100% | as above | as above |

**How to read this honestly:**
- The **held-out, as measured** row is the fair one: pages collected after the rules were written, scored once. Detection logic alone (no lists) warns on **87%** of phishing, up from 45%, and calls **45%** Danger, up from 6%.
- The held-out batch revealed two general mistakes, which were then fixed: sites probing `chrome-extension:` links (ad-blocker checks) were treated as launching Windows apps, and weak signals could turn a harmless redirect into a Caution. The row after the fixes is no longer a pure blind test, which is why both are shown.
- **"All layers" is 100% only because** the test links came from the same public lists PhishGuard downloads. In real use a brand-new phishing page is not on any list yet; then the "without the lists" numbers apply.
- **Cloaking:** 49 + 40 of the listed links showed the sandbox a real website (Google, Yahoo, a real bank) or an unrelated decoy page instead of the phishing page. Page content cannot reveal those; only the lists and the address rules catch them. They are reported separately and not counted above.
- **Phishing that loaded but is still missed** (9 of 71 held-out) were mostly decoy pages ("403", a generic shop) or brands not yet in the registry (Kraken, KuCoin). Adding brands is one line each in `phishguard/data/brands.json`.
- **Real sites that the sandbox could not open** (some Indian bank home pages and PayPal's sign-in page refuse automated browsers) are not counted. In the app such a link shows "could not be checked" (Caution), never Clear.
- **AI Guard (hidden prompt injection):** the "as measured" rows leave it out. Scoring the full pipeline showed that the trained model on its own flagged ordinary hidden text (cookie banners, menus) on 109 of 413 saved pages, which is why "Before" warns on 25-34% of real sites once it is included. It now counts only when an explicit injection phrase ("ignore previous instructions", "[system]", ...) is also present, and two over-broad phrases ("new rules", "developer mode") were narrowed. With that, it adds no false alarms.
- **Live check** (`scripts/live_pipeline_check.py`: the real scan service, sandbox, downloaded lists and RDAP): four fresh phishing links were all Danger, three of them even without the lists; `hdfcbank.com`, `hsbc.co.in`, `x.com` and Wikipedia were Clear.
- The one remaining false alarm on the tuning set (`xvv1deos.com`, Caution) is a typo-domain that really shows a fake security alert.
- Sizes are small (about 70 to 110 pages per group), so each percentage is uncertain by roughly ±10 points.

## Files

`results-heldout.md` (as measured), `results-heldout-after-fixes.md`, `results-tuning.md`: the full tables, the rules that fired, the misses and every false alarm. The saved pages stay in `benchmark-data/` (outside git: they are live phishing material).
