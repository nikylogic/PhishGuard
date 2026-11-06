# Detection benchmark, held-out set (never used for tuning) (06 Nov 2026)

Real phishing links from OpenPhish and phishunt.io, and real websites, opened in PhishGuard's sandbox on 06 Nov 2026. Only pages that actually loaded count.

- **Phishing pages:** 71, plus 40 links that showed the sandbox a real website instead (cloaking), counted separately below.
- **Real websites:** 61: Indian banks, payment apps, government services, big brands' login pages, and a random sample of the Tranco top 5,000.

| Version | Phishing called Danger | Phishing warned (Danger or Caution) | Real sites warned (Caution or Danger) | Real sites called Danger |
|---|---:|---:|---:|---:|
| Before (previous version) | 4/71 (6%) | 32/71 (45%) | 6/61 (10%) | 3/61 (5%) |
| After, without the phishing lists | 32/71 (45%) | 62/71 (87%) | 3/61 (5%) | 2/61 (3%) |
| After, all layers | 71/71 (100%) | 71/71 (100%) | 3/61 (5%) | 2/61 (3%) |

**Read with care:** the phishing links came from the same public lists PhishGuard downloads, so "all layers" is bound to catch nearly all of them. The fair test of the detection logic is the row **without the phishing lists**: how PhishGuard does on phishing no list knows about yet.

## What caught the phishing pages (without the lists)

| Rule | Phishing pages |
|---|---:|
| `NO_HTTPS` | 22 |
| `BRAND_IMPERSONATION` | 20 |
| `CERT_NEW` | 17 |
| `IMPERSONATION` | 17 |
| `BRAND_IN_NAME` | 15 |
| `DOMAIN_NEW` | 15 |
| `BRAND_IN_SUBDOMAIN` | 12 |
| `OBFUSCATED` | 10 |
| `LOGIN_FREE_HOST` | 9 |
| `LURE_WORDS` | 8 |
| `IMPERSONATION_LOGIN` | 6 |
| `LONG_URL` | 4 |
| `RISKY_TLD` | 3 |
| `IMPERSONATION_ID` | 3 |
| `MANY_SUBDOMAINS` | 3 |

Domain age was known for 46 phishing sites on their own domain; 15 were under 30 days old. The rest of the phishing pages sat on free hosting platforms, where domain age says nothing.

**Cloaking:** 40 phishing links sent the sandbox to a real website (for example Yahoo or Google) instead of the phishing page, a common trick to hide from scanners. Those pages are genuinely the real sites, so no detector can flag their content; only the lists catch these links.

## Phishing pages still missed (without the lists)

- `https://perfectgiftchoice.life/paypal-gift/`
- `https://portal.mykraken.exchange`
- `https://basic-plum-tcsewvmy-dp96mj7jb2n6.edgeone.dev/`
- `https://www.22331565.com:1565/403.html?i=164.92.212.136&c=NL`
- `https://kucoinblock.com`
- `https://perplexity-beta-ads.com`
- `https://cpa.freeopenai.me`
- `https://apvdelhi.com/secure/Adobe_Installer.html`
- `https://www.eltajerveneto.it/wp-admin/maint/`

## Real websites that got a warning (all layers)

- `https://vinted.de/`: **danger** 75. The page tried to launch a Windows app through a 'chrome-extension:' link. The page hides what its code does (heavy obfuscation).
- `https://lencr.org/`: **caution** 20. The link bounced through 2 hop(s) and ended on a different website (letsencrypt.org). The website's security certificate is only 3 day(s) old.
- `https://woocommerce.com/`: **danger** 75. The page tried to launch a Windows app through a 'chrome-extension:' link. The page hides what its code does (heavy obfuscation).
