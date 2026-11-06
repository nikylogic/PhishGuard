# Detection benchmark, tuning set (full pipeline, AI Guard included) (06 Nov 2026)

Real phishing links from OpenPhish and phishunt.io, and real websites, opened in PhishGuard's sandbox on 06 Nov 2026. Only pages that actually loaded count.

- **Phishing pages:** 83, plus 49 links that showed the sandbox a real website instead (cloaking), counted separately below.
- **Real websites:** 109: Indian banks, payment apps, government services, big brands' login pages, and a random sample of the Tranco top 5,000.

| Version | Phishing called Danger | Phishing warned (Danger or Caution) | Real sites warned (Caution or Danger) | Real sites called Danger |
|---|---:|---:|---:|---:|
| Before (previous version) | 2/83 (2%) | 41/83 (49%) | 27/109 (25%) | 4/109 (4%) |
| After, without the phishing lists | 35/83 (42%) | 72/83 (87%) | 1/109 (1%) | 0/109 (0%) |
| After, all layers | 83/83 (100%) | 83/83 (100%) | 1/109 (1%) | 0/109 (0%) |

**Read with care:** the phishing links came from the same public lists PhishGuard downloads, so "all layers" is bound to catch nearly all of them. The fair test of the detection logic is the row **without the phishing lists**: how PhishGuard does on phishing no list knows about yet.

## What caught the phishing pages (without the lists)

| Rule | Phishing pages |
|---|---:|
| `NO_HTTPS` | 25 |
| `BRAND_IMPERSONATION` | 23 |
| `BRAND_IN_NAME` | 22 |
| `IMPERSONATION` | 19 |
| `BRAND_IN_SUBDOMAIN` | 17 |
| `CERT_NEW` | 16 |
| `DOMAIN_NEW` | 15 |
| `OBFUSCATED` | 9 |
| `LURE_WORDS` | 6 |
| `REDIRECTED_AWAY` | 4 |
| `LONG_URL` | 4 |
| `IMPERSONATION_ID` | 4 |
| `IMPERSONATION_LOGIN` | 3 |
| `LOGIN_FREE_HOST` | 3 |
| `MANY_SUBDOMAINS` | 2 |

Domain age was known for 54 phishing sites on their own domain; 15 were under 30 days old. The rest of the phishing pages sat on free hosting platforms, where domain age says nothing.

**Cloaking:** 49 phishing links sent the sandbox to a real website (for example Yahoo or Google) instead of the phishing page, a common trick to hide from scanners. Those pages are genuinely the real sites, so no detector can flag their content; only the lists catch these links.

## Phishing pages still missed (without the lists)

- `https://zaltiel.com.do`
- `https://xwd0gkcx.6lnov0.cn/`
- `https://www.22881565.com:1565/403.html?i=164.92.212.136&c=NL`
- `https://danielnegru.com/adobekr.html`
- `https://meraksoul.com/docv/Adobe_Installer.html`
- `https://soilmatengineers.com`
- `https://www.33221565.com:1565/403.html?i=164.92.212.136&c=NL`
- `https://www.22221565.com:1565/403.html?i=164.92.212.136&c=NL`
- `https://rbxshader.com`
- `https://rss2.rasmes.at/go/337413/z274y274`
- `https://alibaba188.org`

## Real websites that got a warning (all layers)

- `https://xvv1deos.com/`: **caution** 40. The page shows a fake security alert and tries to trap you on it.
