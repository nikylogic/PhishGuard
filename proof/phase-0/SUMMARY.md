# Phase 0: Foundation

**Result: 24 / 24 tests passed** (2.9 s). Full log: `pytest.txt`. Machine-readable results: `junit.xml`.

## What was built
- Git repository, Python 3.12 virtual environment, pinned `requirements.txt` (`pip-freeze.txt` lists every installed package).
- `phishguard/__init__.py`: an app factory that loads its config from the instance folder. Secrets (session key, launcher token) are generated randomly on first start and reused afterwards.
- `phishguard/db.py`: the 10-table SQLite schema (`schema.sql`), with WAL mode, foreign keys and a 5-second busy timeout.
- Security headers on every response: CSP, nosniff, frame-deny, no-referrer and cross-origin isolation.
- `run.py`: a production WSGI server (Waitress) bound to 127.0.0.1 only.

## What the tests prove
| Area | Tests |
|---|---|
| `/health` responds | 1 |
| Every table has exactly the designed columns | 10 |
| Foreign keys and WAL mode are on | 1 |
| CHECK constraints reject invalid roles, sources, scores, levels and list kinds | 6 |
| A finding cannot point to a missing scan; deleting a scan cascades | 2 |
| Security headers are present | 1 |
| Secrets persist across restarts and are long enough | 1 |
| Session cookie is HttpOnly and SameSite=Strict | 1 |
| **The real server answers on 127.0.0.1 and refuses connections on the LAN address (192.168.0.197)** | 1 |

## Issues found
None.
