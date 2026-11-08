# Phase 9: Performance

Measured 2026-11-08 13:07 on Windows 11 (10.0.26300), AMD64 Family 23 Model 113 Stepping 0, AuthenticAMD, 16 logical CPUs, 16 GB RAM, Python 3.12.10.
Each row is the **median of 20 runs** unless the Runs column says otherwise. Throwaway data folders, spare port; real sites over the internet for the sandbox rows.

| Measurement | Median | Fastest | Slowest | Runs | Target | Met |
|---|---|---|---|---|---|---|
| URL verdict (rules only, per link) | 0.43 ms | 0.43 ms | 0.45 ms | 20 | < 50 ms | yes |
| AI Guard model load | 0.43 s | 0.41 s | 1.89 s | 5 | - | - |
| AI Guard check, short clean | 1.37 ms | 1.28 ms | 2.01 ms | 20 | < 5 ms | yes |
| AI Guard check, short injection | 2.51 ms | 2.43 ms | 3.59 ms | 20 | < 5 ms | yes |
| AI Guard check, page-sized (4,000 chars) | 5.95 ms | 5.88 ms | 6.16 ms | 20 | - | - |
| AI Guard check, per chunk of a long page | 0.50 ms | 0.49 ms | 0.51 ms | 20 | < 5 ms | yes |
| Trusted link, from source (python) | 0.09 s | 0.09 s | 0.09 s | 20 | < 0.3 s | yes |
| Trusted link, installed PhishGuard.exe | 0.23 s | 0.21 s | 0.25 s | 20 | < 0.3 s | yes |
| Sandbox browser launch (once per session) | 0.51 s | 0.51 s | 0.51 s | 1 | - | - |
| Sandbox capture, real site (warm browser) | 2.25 s | 1.80 s | 3.42 s | 20 | 3-8 s typical, 20 s hard limit | yes |
| Cold start, from source | 0.73 s | 0.72 s | 1.13 s | 20 | - | - |
| Cold start, installed PhishGuardEngine.exe | 0.73 s | 0.72 s | 0.76 s | 20 | - | - |
| Link accepted by the engine (POST /api/scan) | 30.86 ms | 17.36 ms | 59.97 ms | 20 | - | - |
| Click to full verdict, real site | 2.36 s | 1.82 s | 3.37 s | 20 | - | - |

## Notes

- **URL verdict (rules only, per link)**: 10 different links, from plain to lookalike; slowest link median 1.53 ms.
- **AI Guard model load**: Model file 1.32 MB, loaded once at start-up.
- **AI Guard check, short clean**: verdict: clean (0.02)
- **AI Guard check, short injection**: verdict: injection (1.00)
- **AI Guard check, page-sized (4,000 chars)**: 12 chunks of up to 400 characters, about 0.50 ms per chunk; verdict: clean (0.02)
- **AI Guard check, per chunk of a long page**: The page-sized row divided by its number of chunks.
- **Trusted link, from source (python)**: Whole process: start, check the link, read the trusted list, start the browser.
- **Trusted link, installed PhishGuard.exe**: Whole process: start, check the link, read the trusted list, start the browser.
- **Sandbox browser launch (once per session)**: Headless Chrome or Edge with a throwaway profile; kept warm afterwards.
- **Sandbox capture, real site (warm browser)**: 20/20 complete captures across example.com, www.wikipedia.org, www.python.org, github.com, www.bbc.com.
- **Cold start, from source**: Fresh data folder each time: database created, server answering /health.
- **Cold start, installed PhishGuardEngine.exe**: Fresh data folder each time: database created, server answering /health.
- **Link accepted by the engine (POST /api/scan)**: URL rules + database write; the Airlock window can open now.
- **Click to full verdict, real site**: Sandbox + page rules + phishing lists + domain age + identity + AI Guard. Verdicts: clear 20

Inside a sandbox capture (median seconds): navigate 0.52, total 2.25.

## Size

- Installer: PhishGuard-Setup-1.1.0.exe: 74.8 MB
- Installed app: 280 MB on disk
- AI Guard model: 1.32 MB
