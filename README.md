<div align="center">

<img src="docs/images/logo.png" width="96" alt="PhishGuard logo">

# PhishGuard

**Every link checked in a sandbox before it reaches your browser.**

A free link airlock for Windows, with its full source code here on GitHub. Click a link in any app (Discord, WhatsApp, Telegram, Outlook, a PDF) and PhishGuard opens it in a hidden, throwaway browser first. It tells you whether the page is a fake bank login, a malware download or a scam, and **you** decide whether to open it.

[![Windows 11](https://img.shields.io/badge/Windows-11-0078D4?logo=windows&logoColor=white)](#install)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-3776AB?logo=python&logoColor=white)](#build-from-source)
[![Tests](https://img.shields.io/badge/tests-495%20passing-2ea44f)](#tested-on-real-phishing)
[![Runs locally](https://img.shields.io/badge/runs-100%25%20on%20your%20PC-555)](#privacy)
[![Cost](https://img.shields.io/badge/cost-free%20for%20personal%20use-2ea44f)](#license)
[![License](https://img.shields.io/badge/license-PolyForm%20Noncommercial-blue)](LICENSING.md)
[![CI](https://github.com/nikylogic/PhishGuard/actions/workflows/ci.yml/badge.svg)](https://github.com/nikylogic/PhishGuard/actions/workflows/ci.yml)

[Install](#install) · [How it works](#how-it-works) · [How it spots a fake site](#how-it-spots-a-fake-site) · [Results](#tested-on-real-phishing) · [Screenshots](#screenshots) · [Privacy](#privacy) · [Build](#build-from-source)

<img src="docs/images/airlock-danger.png" width="820" alt="PhishGuard stopping a fake HDFC Bank login page">

</div>

---

## Why

Phishing no longer looks fake. A message says your bank account is suspended, the link looks right, and the login page is a pixel-perfect copy. Blocklists only work *after* a site has been reported, and a brand-new phishing site is often reported only after people have already typed their passwords into it.

PhishGuard sits **between the click and the browser**:

- 🔒 **Unknown links never open unchecked.** They load in an isolated sandbox browser that has no access to your cookies, passwords or files. Only sites you marked as trusted skip the check.
- 🏦 **It knows which site is real.** For 107 banks, payment apps and big brands, a page that presents itself as the brand but isn't on the brand's own domain is stopped, however the address is spelled.
- 📦 **Downloads never run.** Every file the site tries to drop is caught in quarantine and identified by its contents.
- 🧾 **Every warning says why,** in plain words. No black-box score.
- 💸 **Free, local and private.** No account, no cloud, no subscription.

## How it works

```mermaid
flowchart LR
    A["You click a link in an app<br/>(Discord, WhatsApp, Outlook, PDF…)"] --> B{"PhishGuard<br/>(default browser)"}
    B -->|"on your trusted list"| R["Your real browser<br/>Chrome · Edge · Brave · Firefox"]
    B -->|"everything else"| S["Hidden sandbox browser<br/>no cookies · no files · downloads quarantined"]
    S --> J["Checks<br/>lists · domain age · identity · page behaviour · AI Guard"]
    J --> V{"Verdict"}
    V --> U["Airlock window<br/>✅ Clear · ⚠️ Caution · ⛔ Danger<br/>shows why · you decide"]
    U -->|"Open safely · Open clean link<br/>(Danger asks you to confirm)"| R
    U -->|"Keep it locked · Block this site"| X["Never opened"]
```

1. **PhishGuard registers as a browser** with Windows (current user only, no admin rights). You pick it once in *Settings → Default apps*. From then on, links you click in other apps come to PhishGuard. Links you click *inside* your browser stay in your browser.
2. **Trusted sites open instantly** (under 0.3 s), straight in your real browser.
3. **Every other link opens in the sandbox**: a separate copy of Chrome or Edge with a throwaway profile, a strict network gatekeeper and a 20-second limit. It records redirects, forms, scripts, trackers, permission prompts, downloads and a screenshot.
4. **The Airlock window** shows the verdict, the screenshot and every reason. Nothing opens until you choose: **Open safely**, **Open clean link** (the same link with tracking tags like `utm_source` and `fbclid` removed), **Keep it locked** or **Block this site**. Opening a Danger link needs a second confirmation. Your real browser is started directly, so links never loop back into PhishGuard.

## How it spots a fake site

PhishGuard does not rely on any single signal. It combines five independent layers. Any one can raise the alarm, and each finding is written out in plain language.

```mermaid
flowchart TB
    L["Link"] --> L1 & L2 & L3 & L4 & L5
    L1["1 · Public phishing lists<br/>OpenPhish · phishunt.io · Phishing.Database<br/>~380,000 known phishing domains, checked on your PC"]
    L2["2 · Website age<br/>RDAP (official WHOIS successor) + certificate history<br/>many scam domains are only days old"]
    L3["3 · Identity check<br/>which brand does the page claim to be?<br/>is this that brand's real domain?"]
    L4["4 · What the page asks for<br/>password · OTP · card · ID<br/>on free hosting or a weeks-old domain"]
    L5["5 · Address and behaviour rules<br/>look-alike names · fake alerts · keyboard traps<br/>hidden redirects · tracking · AI prompt injection"]
    L1 & L2 & L3 & L4 & L5 --> S["Score with written reasons<br/>⛔ Danger ≥ 50 · ⚠️ Caution ≥ 20 · ✅ Clear"]
```

### HDFC is never mistaken for HSBC

Many real names look alike on paper: HDFC and HSBC, booking.com and cooking.com. Comparing spellings either misses fakes or flags real sites. PhishGuard uses the method from the research systems **Phishpedia** (USENIX Security 2021) and **PhishIntention** (USENIX Security 2022):

```mermaid
flowchart LR
    P["Page in the sandbox"] --> C["Which brand does it claim?<br/>copied favicon · logo · site name · title"]
    C --> D{"Is the site on that<br/>brand's real domain?"}
    D -->|"yes: hdfcbank.com"| OK["✅ Clear"]
    D -->|"no, and it asks for a password or OTP"| BAD["⛔ Danger:<br/>'This page presents itself as HDFC Bank and asks<br/>for your password, but it is not on HDFC Bank's website.'"]
```

- **107 brands** (Indian banks and payment apps, government services, global brands) with their real domains and **284 favicon fingerprints**.
- Understands India's new **`.bank.in`** and **`.gov.in`** zones, which only verified owners can register.
- **Free hosting** (blogspot, vercel.app, pages.dev, firebaseapp…) is never trusted as a brand: much of today's phishing is hosted there.
- **News sites and forums** writing about a bank are not impersonations.

### More than phishing

| Threat | What PhishGuard does |
|---|---|
| Malware downloads | Every download is caught in quarantine and never run. The real file type is identified from its contents, so `invoice.pdf.exe` is exposed. |
| Tech-support scams | Detects fake virus alerts, full-screen traps and keyboard locks. |
| Tracking | A privacy report lists the trackers and fingerprinting scripts each site uses. Ordinary tracking is shown for your information and does not make a link unsafe; IP-logger links, which exist only to record your address, do. |
| AI prompt injection | **AI Guard**, a 1.3 MB model trained for this project, finds hidden text written to trick AI assistants (F1 0.915 on its test set, about 3 ms per text). |
| Your IP address | Optional **Hide my IP**: the sandbox reaches the site through Tor, Cloudflare WARP or your own proxy. |

## Tested on real phishing

Live phishing links from OpenPhish and phishunt.io, plus real websites, were opened in the sandbox on 6 Nov 2026. The **held-out** batch was collected after the rules were written and scored once.

| Held-out batch: 71 phishing pages, 61 real sites | Previous version | PhishGuard now, **without** the lists |
|---|---:|---:|
| Phishing called **Danger** | 6% | **45%** |
| Phishing **warned** (Danger or Caution) | 45% | **87%** |
| Real sites wrongly warned | 10% | **0–5%** |

- The "without the lists" column is what matters for a **brand-new** phishing site that nobody has reported yet. With the lists, every test link was caught, but that is because the links came from those same lists.
- Some phishing links showed the sandbox a decoy page (a real Google page, a "403"). Only the lists and the address rules can catch those; they are reported separately.
- Samples are small (60–110 pages per group), so each figure is uncertain by about ±10 points. The full tables, every miss and every false alarm are in [`proof/phase-9-detection`](proof/phase-9-detection/SUMMARY.md).

## Screenshots

| A safe site | A disguised download |
|---|---|
| <img src="docs/images/airlock-clear.png" alt="Wikipedia gets a Clear verdict"> | <img src="docs/images/airlock-download.png" alt="invoice.pdf.exe is caught and exposed as a Windows program"> |
| **Dashboard** | **Settings** |
| <img src="docs/images/dashboard.png" alt="Dashboard with today's checks"> | <img src="docs/images/settings.png" alt="Settings: start with Windows, default browser, real browser"> |

The danger examples are PhishGuard's built-in test sites (`bank.test`, `files.test`), which imitate real attacks safely; the safe example is the real Wikipedia.

## Install

1. Download **`PhishGuard-Setup-1.1.0.exe`** from [Releases](../../releases).
2. Run it. It installs for your Windows account only, with no admin rights. Google Chrome or Microsoft Edge must be installed (Windows 11 includes Edge).
3. Open PhishGuard, go to **Settings → General** and press **Make PhishGuard my default browser**. Windows opens its Settings on PhishGuard's page; press **Set default**.
4. Choose **your real browser** in Settings → General. Safe links open there.

PhishGuard starts quietly with Windows (you can turn this off), so the first link you click is checked straight away. While it runs, its shield icon sits in the notification area next to the clock: click it to open PhishGuard, or right-click to check a link you copied, switch Start with Windows on or off, or quit.

> **Windows SmartScreen** may warn that the installer is from an unknown publisher, because it is not code-signed yet. Choose *More info → Run anyway*, or build it yourself from source.

## Privacy

- **Everything runs on your PC.** Verdicts, screenshots and history stay in `%LOCALAPPDATA%\PhishGuard`, inside your own Windows user folder.
- **The phishing lists are downloaded** and checked locally. Your links are never sent to a lookup service.
- **Website age lookups send only the domain name** (never the full link), and skip popular sites and brands' own domains.
- **The AI second opinion is off by default.** If you turn it on, the link, the page title, PhishGuard's findings and up to 4,000 characters of the page's visible text go to the provider you choose (Gemini, Groq, or Ollama running offline on your PC). Never cookies, form values or screenshots. AI Guard warns the model about hidden instructions first, and the AI can only raise the risk, never lower it.
- History is deleted after 90 days by default (Settings → Privacy).

## Build from source

Requires Windows 11, Python 3.12, Node.js 22 and Google Chrome or Microsoft Edge.

```powershell
git clone https://github.com/nikylogic/PhishGuard.git
cd PhishGuard
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt

cd web; npm ci; npm run build; cd ..                   # the dashboard UI

.venv\Scripts\python run.py                            # engine on http://127.0.0.1:5157
.venv\Scripts\python scripts\register_windows.py       # register as a browser for your account
```

Run the tests with `.venv\Scripts\python -m pytest`. Build the installer with PyInstaller (`packaging/PhishGuard.spec`) and Inno Setup (`packaging/PhishGuard.iss`).

```mermaid
flowchart LR
    subgraph Windows
        LN["PhishGuard.exe<br/>link launcher · window"]
    end
    subgraph Engine["PhishGuardEngine.exe · 127.0.0.1 only"]
        API["Flask + Waitress<br/>API · dashboard"]
        W["Scan worker"]
        SB["Playwright sandbox<br/>+ egress gatekeeper"]
        RE["Risk engine<br/>rules · identity · lists · RDAP"]
        AG["AI Guard"]
        DB[("SQLite")]
    end
    LN -->|"one-time ticket"| API
    API --> W --> SB --> RE --> DB
    SB --> AG --> RE
    UI["React dashboard<br/>(Vite · Tailwind · shadcn/ui)"] --- API
```

| Part | Built with |
|---|---|
| Engine | Python 3.12, Flask, Waitress, SQLite |
| Sandbox | Playwright with the installed Chrome or Edge, throwaway profile, local egress proxy |
| Detection | tldextract, Tranco top-10k, RDAP, crt.sh, public phishing lists |
| AI Guard | scikit-learn (TF-IDF + logistic regression) |
| UI | React, Vite, Tailwind CSS, shadcn/ui, pywebview |
| Installer | PyInstaller, Inno Setup |

Design details are in [`ARCHITECTURE.md`](ARCHITECTURE.md). Each build phase has its own test output and evidence in [`proof/`](proof).

## Security of PhishGuard itself

A tool that opens dangerous links must not become the way in. The engine listens on `127.0.0.1` only. The pages use a strict Content-Security-Policy with per-page nonces and no inline scripts. Every change made from the dashboard needs a CSRF token, and the link launcher authenticates with its own secret token. Non-web links (`javascript:`, `file:`, `ms-msdt:`…) and links with hidden characters are refused outright. If anything fails, the link stays closed.

Found a vulnerability? Please open a private security advisory on this repository rather than a public issue.

## Contributing

The easiest way to help is to **add a brand**. Each one is a single entry in [`phishguard/data/brands.json`](phishguard/data/brands.json): its name, its real domains, and how it is written in web addresses and on pages. Banks, wallets and payment apps from your country are especially welcome. Missed phishing pages and false alarms are just as valuable: [open an issue](https://github.com/nikylogic/PhishGuard/issues/new/choose) with the link (defanged, e.g. `hxxps://example[.]com`) and what PhishGuard said.

Code changes are welcome too. [CONTRIBUTING.md](CONTRIBUTING.md) covers setup and tests; every pull request runs the tests on Windows automatically. On your first pull request a bot asks you to sign the [Contributor License Agreement](CLA.md) with a one-line comment. You keep the copyright to your work.

## License

PhishGuard is **free for personal use** and for noncommercial organisations such as schools, charities and public bodies, under the [PolyForm Noncommercial License 1.0.0](LICENSE). Using it in or for a business needs a commercial license; see [LICENSING.md](LICENSING.md). This makes PhishGuard *source-available* rather than OSI open source: anyone can read, build and change the code, and businesses that profit from it help pay for it.

## Credits

Phishing data from [OpenPhish](https://openphish.com) (community feed), [phishunt.io](https://phishunt.io) (CC0) and [Phishing.Database](https://github.com/Phishing-Database/Phishing.Database) (MIT). Popularity ranks from the [Tranco list](https://tranco-list.eu). The identity check follows the ideas of [Phishpedia](https://www.usenix.org/conference/usenixsecurity21/presentation/lin) and [PhishIntention](https://www.usenix.org/conference/usenixsecurity22/presentation/liu-ruofan).

<div align="center">

**If PhishGuard saved you from one bad click, give it a ⭐ so more people find it.**

</div>
