# Launcher speed: a trusted link, 20 runs of pg_open.pyw as a separate process

| median | fastest | slowest |
|---|---|---|
| 92 ms | 90 ms | 108 ms |

Target: under 300 ms. This includes starting Python itself. A trusted link needs no network call:
the launcher reads `allowlist.txt` and `browser.txt`, which the engine keeps up to date.
