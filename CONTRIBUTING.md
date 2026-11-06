# Contributing to PhishGuard

Thank you for helping people avoid scams. Every brand added, missed phishing page reported and false alarm fixed protects real people.

## Ways to help (no coding needed)

| You found… | Do this |
|---|---|
| A phishing page PhishGuard **missed** | [Report a missed phishing page](https://github.com/nikylogic/PhishGuard/issues/new?template=missed-phishing.yml) |
| A real site PhishGuard **wrongly warned** about | [Report a false alarm](https://github.com/nikylogic/PhishGuard/issues/new?template=false-alarm.yml) |
| A bank, wallet or app that scammers copy and PhishGuard doesn't know | [Request a brand](https://github.com/nikylogic/PhishGuard/issues/new?template=brand.yml) |
| Something broken | [Report a bug](https://github.com/nikylogic/PhishGuard/issues/new?template=bug.yml) |
| A security hole in PhishGuard itself | **Not an issue.** Follow [SECURITY.md](SECURITY.md). |

**Always defang phishing links** in issues so nobody clicks them by accident: `hxxps://fake-bank[.]top/login`.

## Your first code contribution

The easiest one is a **brand**. Each brand is one line under `"brands"` in [`phishguard/data/brands.json`](phishguard/data/brands.json):

```json
"kotak": {"name": "Kotak Mahindra Bank", "domains": ["kotak.com", "kotak.bank.in"], "tokens": ["kotak", "kotakbank"], "words": ["kotak mahindra", "kotak bank", "kotak"]},
```

- `domains`: the brand's **own** registrable domains only, never shared hosts like `github.io`.
- `tokens`: how the name appears inside web addresses.
- `words`: how a page names the brand in its title or text.
- Add `"strict": true` if the name is also an everyday word (Apple, Chase, Steam), so only a copied logo or favicon counts.

Then run `.venv\Scripts\python scripts\brand_favicons.py`, which downloads each brand's real favicon and records its fingerprint (`favicons`), and run the tests.

## Set up

Windows 11, Python 3.12, Node.js 22, and Chrome or Edge.

```powershell
git clone https://github.com/<you>/PhishGuard.git
cd PhishGuard
python -m venv .venv
.venv\Scripts\pip install -r requirements.txt
cd web; npm ci; npm run build; cd ..
.venv\Scripts\python run.py            # the engine and dashboard on http://127.0.0.1:5157
```

To see every screen with safe fake attack sites: `.venv\Scripts\python scripts\demo.py` (log in as `admin` / `airlock-admin-1`).

## Before you open a pull request

```powershell
.venv\Scripts\python -m pytest            # all tests, about 3 minutes
cd web; npx tsc --noEmit; npm run build   # if you changed the dashboard
```

- **Add a test** for what you changed. Detection changes need a test that shows the attack being caught *and* a real site not being flagged.
- **Detection changes:** if you have collected pages with `scripts/benchmark.py`, include the before/after table. A rule that catches more phishing but warns on more real sites is usually not an improvement.
- **Never commit live phishing material.** `benchmark-data/` is ignored for this reason.
- **Never weaken a security guard** (the Content-Security-Policy, CSRF checks, the egress gatekeeper, refusing non-web links) without opening an issue first.
- The full test run rewrites some files in `proof/`. Undo them before committing: `git checkout -- proof/phase-1 proof/phase-2 proof/phase-5 proof/phase-7/test-shots`
- Keep the UI plain: no decorative badges, gradients or filler text.
- Write user-facing text in short, plain sentences. Every warning must say *why* in words a non-technical person understands.

CI runs the same tests on Windows for every pull request. It must pass before merging.

## The Contributor License Agreement

PhishGuard is free for individuals and paid for businesses ([LICENSING.md](LICENSING.md)). So that your work can be offered both ways, you sign the [CLA](CLA.md) once, by replying to the bot on your first pull request. You keep the copyright in your work.

## Code of conduct

Be kind and assume good faith. See [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).
