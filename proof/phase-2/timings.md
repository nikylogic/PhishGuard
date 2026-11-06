# Sandbox timings (warm browser, local fake sites)

| Fake page | Path | Status | Seconds |
|---|---|---|---|
| plain | `/plain` | done | 1.72 |
| redirect-chain | `/r1` | done | 1.75 |
| fake-bank-login | `/bank` | done | 1.69 |
| exe-download | `/invoice` | done | 1.69 |
| fingerprinting | `/fingerprint` | done | 2.12 |
| ip-logger | `/go` | done | 1.69 |
| clickfix | `/clickfix` | done | 1.69 |
| ms-msdt | `/msdt` | done | 1.67 |
| fake-virus-alert | `/scam` | done | 1.69 |
| miner | `/miner` | done | 1.67 |
| open-redirect | `/out?url=http://evil.test:58087/evil` | done | 1.69 |
| hidden-injection | `/injection` | done | 1.69 |
| ssrf-localhost | `/ssrf` | failed | 1.69 |
| ssrf-subresources | `/ssrf-sub` | done | 1.69 |
| slow-page | `/slow` | partial | 16.69 |
