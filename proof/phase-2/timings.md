# Sandbox timings (warm browser, local fake sites)

| Fake page | Path | Status | Seconds |
|---|---|---|---|
| plain | `/plain` | done | 1.70 |
| redirect-chain | `/r1` | done | 1.70 |
| fake-bank-login | `/bank` | done | 1.70 |
| exe-download | `/invoice` | done | 1.67 |
| fingerprinting | `/fingerprint` | done | 2.09 |
| ip-logger | `/go` | done | 1.67 |
| clickfix | `/clickfix` | done | 1.69 |
| ms-msdt | `/msdt` | done | 1.67 |
| fake-virus-alert | `/scam` | done | 1.67 |
| miner | `/miner` | done | 1.69 |
| open-redirect | `/out?url=http://evil.test:62751/evil` | done | 1.67 |
| hidden-injection | `/injection` | done | 1.67 |
| ssrf-localhost | `/ssrf` | failed | 1.69 |
| ssrf-subresources | `/ssrf-sub` | done | 1.67 |
| slow-page | `/slow` | partial | 16.67 |
