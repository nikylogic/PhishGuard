"""Detection benchmark: real phishing links against real websites, through the real sandbox.

    collect   download fresh phishing links, open them and the real sites in the sandbox, save
              every capture (pages go offline within hours, so they are scored later from disk)
    score     run the saved captures through PhishGuard's detection and write the results

    .venv\\Scripts\\python scripts\\benchmark.py collect [--phish 160] [--legit-random 60]
    .venv\\Scripts\\python scripts\\benchmark.py score [--run DIR]

Saved pages are live phishing material, so they stay in benchmark-data/ (not in git). Only the
results table goes into proof/.
"""
from __future__ import annotations

import argparse
import json
import random
import sys
import threading
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from queue import Queue

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

DATA = ROOT / "benchmark-data"
FEEDS = {
    "openphish": "https://openphish.com/feed.txt",
    "phishunt": "https://phishunt.io/feed.txt",
}
TRANCO = ROOT / "phishguard" / "data" / "popular.txt"

# Real sites people are most likely to be tricked with: Indian banks, payment apps, government
# services, and the big brands' own login pages. Each is the genuine address.
LEGIT = """
https://www.hdfcbank.com/ https://netbanking.hdfcbank.com/netbanking/ https://www.onlinesbi.sbi/
https://sbi.co.in/ https://www.icicibank.com/ https://infinity.icicibank.com/corp/AuthenticationController
https://www.axisbank.com/ https://omni.axisbank.co.in/axisretailbanking/ https://www.kotak.com/en/home.html
https://netbanking.kotak.com/knb2/ https://www.pnbindia.in/ https://www.bankofbaroda.in/
https://canarabank.com/ https://www.unionbankofindia.co.in/ https://www.idfcfirstbank.com/
https://www.yesbank.in/ https://www.indusind.com/in/en/personal.html https://www.federalbank.co.in/
https://www.hsbc.co.in/ https://www.sc.com/in/ https://www.aubank.in/ https://www.rblbank.com/
https://bandhanbank.com/ https://www.iob.in/ https://www.centralbankofindia.co.in/
https://bankofindia.co.in/ https://www.indianbank.in/ https://www.ucobank.com/
https://karnatakabank.com/ https://www.kvb.co.in/ https://www.southindianbank.com/
https://www.dbs.com/in/ https://paytm.com/ https://www.phonepe.com/ https://razorpay.com/
https://www.paypal.com/signin https://www.amazon.in/ https://www.flipkart.com/ https://www.myntra.com/
https://www.irctc.co.in/nget/train-search https://www.incometax.gov.in/iec/foportal/
https://uidai.gov.in/ https://www.digilocker.gov.in/ https://www.epfindia.gov.in/
https://accounts.google.com/ https://login.microsoftonline.com/ https://outlook.live.com/owa/
https://account.apple.com/sign-in https://www.facebook.com/login/ https://www.instagram.com/accounts/login/
https://www.linkedin.com/login https://www.netflix.com/login https://github.com/login
https://www.dropbox.com/login https://x.com/i/flow/login https://www.hotstar.com/in
https://www.zomato.com/ https://www.swiggy.com/ https://www.hsbc.com/ https://www.hsbc.co.uk/
https://www.barclays.co.uk/ https://www.chase.com/ https://www.bankofamerica.com/
https://www.wellsfargo.com/ https://www.citi.com/ https://www.americanexpress.com/
https://www.office.com/ https://mail.yahoo.com/ https://www.coinbase.com/ https://www.binance.com/
https://www.roblox.com/login https://store.steampowered.com/login/ https://discord.com/login
https://web.whatsapp.com/ https://web.telegram.org/ https://www.ebay.com/signin/
https://www.walmart.com/account/login https://www.usps.com/ https://www.dhl.com/in-en/home.html
https://www.fedex.com/en-in/home.html https://www.adobe.com/ https://www.docusign.com/
https://www.wetransfer.com/ https://www.att.com/ https://www.allegro.pl/ https://www.mercadolibre.com.ar/
https://www.vercel.com/ https://pages.cloudflare.com/
""".split()


# --- collect ----------------------------------------------------------------------------------

def fetch(url: str) -> str:
    req = urllib.request.Request(url, headers={"User-Agent": "PhishGuard-benchmark/1.0"})
    with urllib.request.urlopen(req, timeout=60) as r:
        return r.read().decode("utf-8", "replace")


def earlier_hosts() -> set[str]:
    """Hosts used in earlier runs, so a fresh run tests on pages the rules have never seen."""
    out = set()
    for jobs in DATA.glob("*/jobs.json"):
        for j in json.loads(jobs.read_text(encoding="utf-8")):
            out.add(j["url"].split("/")[2].lower().removeprefix("www."))
    return out


def phishing_sample(n: int, seed: int, exclude: set[str] = frozenset()) -> list[dict]:
    from phishguard.urltools import registrable_domain
    seen_hosts, rows = set(exclude), []
    for name, url in FEEDS.items():
        for line in fetch(url).splitlines():
            u = line.strip()
            if not u.startswith(("http://", "https://")):
                continue
            host = u.split("/")[2].lower().removeprefix("www.")
            if host in seen_hosts:
                continue
            seen_hosts.add(host)
            try:
                reg = registrable_domain(u)
            except ValueError:
                continue
            rows.append({"url": u, "label": "phishing", "source": name, "reg": reg})
    random.Random(seed).shuffle(rows)
    # At most 3 links per registrable domain, so one big campaign cannot dominate the results.
    per, out = {}, []
    for r in rows:
        if per.get(r["reg"], 0) < 3:
            per[r["reg"]] = per.get(r["reg"], 0) + 1
            out.append(r)
        if len(out) >= n:
            break
    return out


def legit_sample(n_random: int, seed: int, n_curated: int | None = None) -> list[dict]:
    rows = [{"url": u, "label": "legit", "source": "curated"} for u in LEGIT[:n_curated]]
    top = [d.strip() for d in TRANCO.read_text(encoding="utf-8").splitlines()
           if d.strip() and not d.startswith("#")][:5000]
    for d in random.Random(seed).sample(top, n_random):
        rows.append({"url": f"https://{d}/", "label": "legit", "source": "tranco-top5k"})
    return rows


def loaded(cap: dict) -> bool:
    """Only pages that really loaded count: a dead phishing link tests nothing."""
    if cap.get("status") == "failed":
        return False
    if (cap.get("http_status") or 200) >= 400:
        return False
    return bool((cap.get("visible_text") or "").strip() or cap.get("forms") or cap.get("inputs"))


def collect(args):
    from phishguard.sandbox import Sandbox
    run = DATA / time.strftime("%Y%m%d-%H%M")
    (run / "captures").mkdir(parents=True, exist_ok=True)
    exclude = earlier_hosts() if args.fresh else set()
    legit = [j for j in legit_sample(args.legit_random, args.seed, args.legit_curated)
             if j["url"].split("/")[2].lower().removeprefix("www.") not in exclude]
    jobs = phishing_sample(args.phish, args.seed, exclude) + legit
    (run / "jobs.json").write_text(json.dumps(jobs, indent=1), encoding="utf-8")
    print(f"{len(jobs)} links -> {run}", flush=True)

    q: Queue = Queue()
    for i, j in enumerate(jobs):
        q.put((i, j))
    lock = threading.Lock()
    done = [0]

    def worker(k):
        sb = Sandbox(run / "shots", run / "quarantine")   # the same time limits as the app
        sb.start()
        try:
            while not q.empty():
                try:
                    i, job = q.get_nowait()
                except Exception:
                    return
                t = time.monotonic()
                try:
                    cap = sb.capture(job["url"], f"b{i:04d}").to_dict()
                except Exception as e:  # noqa: BLE001  one broken page must not stop the run
                    cap = {"url": job["url"], "status": "failed", "error": repr(e)[:300]}
                rec = dict(job, capture=cap, loaded=loaded(cap), seconds=round(time.monotonic() - t, 1),
                           captured_at=time.time())
                (run / "captures" / f"{i:04d}.json").write_text(json.dumps(rec), encoding="utf-8")
                with lock:
                    done[0] += 1
                    print(f"[{done[0]}/{len(jobs)}] {job['label']:8} {'ok ' if rec['loaded'] else 'dead'} "
                          f"{job['url'][:90]}", flush=True)
        finally:
            sb.close()

    with ThreadPoolExecutor(args.workers) as ex:
        list(ex.map(worker, range(args.workers)))
    print("done", run, flush=True)


# --- score ------------------------------------------------------------------------------------

def latest_run() -> Path:
    runs = sorted(p for p in DATA.iterdir() if (p / "captures").is_dir())
    return runs[-1]


def load_records(run: Path) -> list[dict]:
    return [json.loads(p.read_text(encoding="utf-8")) for p in sorted((run / "captures").glob("*.json"))]


OLD_COMMIT = "33448cf"     # the detection before the new layers (scoring fix only)

OLD_SCORER = r"""
import json, sys
sys.path.insert(0, sys.argv[1])
from phishguard.intel import Intel
from phishguard.pagerules import analyse
from phishguard.rules import make
from phishguard.guard.guard import get_guard
intel = Intel.load()
guard = get_guard()
out = []
for path in sys.argv[2:]:
    r = json.load(open(path, encoding="utf-8"))
    # The AI Guard as the app ran it then: the model's label alone.
    g = guard.check(r["capture"].get("hidden_text") or "")
    extra = [make("PROMPT_INJECTION", "guard")] if g["label"] == "injection" else []
    v = analyse(r["capture"], intel, extra=extra)
    out.append({"level": v["level"], "score": v["score"], "counted": v.get("counted", []),
                "why": [f.message for f in v["findings"] if f.code in v.get("counted", [])][:3]})
print(json.dumps(out))
"""


def old_scores(paths: list[Path]) -> list[dict]:
    """Score with the code as it was before the new layers, from a git worktree of that commit."""
    import subprocess
    import tempfile
    wt = Path(tempfile.gettempdir()) / f"pg-bench-{OLD_COMMIT}"
    if not wt.exists():
        subprocess.run(["git", "worktree", "add", "--detach", str(wt), OLD_COMMIT], cwd=ROOT, check=True,
                       capture_output=True)
    res = subprocess.run([sys.executable, "-X", "utf8", "-c", OLD_SCORER, str(wt), *map(str, paths)],
                         cwd=str(wt), capture_output=True, text=True, encoding="utf-8")
    if res.returncode:
        raise SystemExit(res.stderr[-2000:])
    return json.loads(res.stdout)


def cloaked(rec: dict) -> bool:
    """The phishing link showed the sandbox a real, popular website instead (cloaking)."""
    from urllib.parse import urlsplit

    from phishguard import intel
    from phishguard.urltools import registrable_domain
    final = rec["capture"].get("final_url") or rec["url"]
    try:
        reg = registrable_domain(final)
    except ValueError:
        return False
    return intel.is_established(urlsplit(final).hostname or "", reg) or reg in intel.ALL_BRAND_DOMAINS


def rate(rows, levels):
    return sum(r["level"] in levels for r in rows), len(rows)


def score(args):
    from urllib.parse import urlsplit

    from phishguard import privacy
    from phishguard.domaininfo import DomainInfo
    from phishguard.feeds import Feeds
    from phishguard.intel import Intel
    from phishguard.pagerules import analyse
    from phishguard.urltools import registrable_domain

    run = (Path(args.run) if args.run else latest_run()).resolve()
    recs, keep = [], []
    for pth in sorted((run / "captures").glob("*.json")):
        r = json.loads(pth.read_text(encoding="utf-8"))
        if r["loaded"]:
            recs.append(r)
            keep.append(pth)
    for r in recs:
        r["group"] = r["label"] if r["label"] == "legit" else ("cloaked" if cloaked(r) else "phishing")

    intel_db = Intel.load()
    di = DomainInfo(run / "lookups", get=lambda u, t, lim: privacy.http_get(None, u, t, lim))
    feeds = Feeds(run / "feeds")
    feeds.refresh()
    facts = []
    for r in recs:
        final = r["capture"].get("final_url") or r["url"]
        try:
            facts.append(di.age(urlsplit(final).hostname or "", registrable_domain(final)))
        except ValueError:
            facts.append({})

    from phishguard.guard.guard import get_guard
    from phishguard.rules import make
    guard = get_guard()

    def judge(cap, f, use_feeds):
        # The AI Guard exactly as the app runs it (services.py): the model plus an explicit phrase.
        g = guard.check(cap.get("hidden_text") or "")
        extra = [make("PROMPT_INJECTION", "guard")] if g["label"] == "injection" and g.get("keywords") else []
        v = analyse(cap, intel_db, facts=f, feeds=feeds if use_feeds else None, extra=extra)
        return {"level": v["level"], "score": v["score"], "counted": v.get("counted", []),
                "why": [x.message for x in v["findings"] if x.code in v.get("counted", [])][:3]}

    variants = {
        "Before (previous version)": old_scores(keep),
        "After, without the phishing lists": [judge(r["capture"], f, False) for r, f in zip(recs, facts)],
        "After, all layers": [judge(r["capture"], f, True) for r, f in zip(recs, facts)],
    }
    out = {name: [dict(v, url=r["url"], group=r["group"], source=r["source"]) for v, r in zip(vs, recs)]
           for name, vs in variants.items()}
    (run / "scores.json").write_text(json.dumps(out, indent=1), encoding="utf-8")
    report = make_report(recs, out, facts, args.title)
    dest = ROOT / "proof" / "phase-9-detection"
    dest.mkdir(parents=True, exist_ok=True)
    (dest / f"{args.name}.md").write_text(report, encoding="utf-8")
    print(report)


def make_report(recs, out, facts, title="Detection benchmark") -> str:
    n_ph = sum(r["group"] == "phishing" for r in recs)
    n_cl = sum(r["group"] == "cloaked" for r in recs)
    n_lg = sum(r["group"] == "legit" for r in recs)
    when = time.strftime("%d %b %Y", time.localtime(min(r["captured_at"] for r in recs)))

    def pct(a, b):
        return f"{a}/{b} ({100 * a / b:.0f}%)" if b else "-"

    L = [f"# {title} ({when})", "",
         f"Real phishing links from OpenPhish and phishunt.io, and real websites, opened in PhishGuard's "
         f"sandbox on {when}. Only pages that actually loaded count.", "",
         f"- **Phishing pages:** {n_ph}, plus {n_cl} links that showed the sandbox a real website instead "
         f"(cloaking), counted separately below.",
         f"- **Real websites:** {n_lg}: Indian banks, payment apps, government services, big brands' login "
         f"pages, and a random sample of the Tranco top 5,000.", "",
         "| Version | Phishing called Danger | Phishing warned (Danger or Caution) | Real sites warned "
         "(Caution or Danger) | Real sites called Danger |", "|---|---:|---:|---:|---:|"]
    for name, rows in out.items():
        ph = [x for x in rows if x["group"] == "phishing"]
        lg = [x for x in rows if x["group"] == "legit"]
        d, n = rate(ph, {"danger"})
        c, _ = rate(ph, {"danger", "caution"})
        fw, m = rate(lg, {"danger", "caution"})
        fd, _ = rate(lg, {"danger"})
        L.append(f"| {name} | {pct(d, n)} | {pct(c, n)} | {pct(fw, m)} | {pct(fd, m)} |")
    L += ["", "**Read with care:** the phishing links came from the same public lists PhishGuard downloads, so "
          "\"all layers\" is bound to catch nearly all of them. The fair test of the detection logic is the row "
          "**without the phishing lists**: how PhishGuard does on phishing no list knows about yet.", ""]
    after = out["After, without the phishing lists"]
    counts: dict[str, int] = {}
    for x in after:
        if x["group"] == "phishing" and x["level"] != "clear":
            for code in x["counted"]:
                counts[code] = counts.get(code, 0) + 1
    L += ["## What caught the phishing pages (without the lists)", "", "| Rule | Phishing pages |", "|---|---:|"]
    L += [f"| `{k}` | {v} |" for k, v in sorted(counts.items(), key=lambda kv: -kv[1])[:15]]
    ages = [f.get("age_days") for r, f in zip(recs, facts)
            if r["group"] == "phishing" and f.get("age_days") is not None]
    if ages:
        L += ["", f"Domain age was known for {len(ages)} phishing sites on their own domain; "
              f"{sum(a < 30 for a in ages)} were under 30 days old. The rest of the phishing pages sat on free "
              f"hosting platforms, where domain age says nothing."]
    cl = [x for x in after if x["group"] == "cloaked"]
    if cl:
        L += ["", f"**Cloaking:** {len(cl)} phishing links sent the sandbox to a real website (for example Yahoo "
              f"or Google) instead of the phishing page, a common trick to hide from scanners. Those pages are "
              f"genuinely the real sites, so no detector can flag their content; only the lists catch these links."]
    L += ["", "## Phishing pages still missed (without the lists)", ""]
    miss = [x for x in after if x["group"] == "phishing" and x["level"] == "clear"]
    L += [f"- `{x['url'][:90]}`" for x in miss[:30]] or ["- none"]
    L += ["", "## Real websites that got a warning (all layers)", ""]
    fa = [x for x in out["After, all layers"] if x["group"] == "legit" and x["level"] != "clear"]
    L += [f"- `{x['url'][:80]}`: **{x['level']}** {x['score']}. {' '.join(x['why'])}" for x in fa] or ["- none"]
    return "\n".join(L) + "\n"


def main():
    ap = argparse.ArgumentParser()
    sub = ap.add_subparsers(dest="cmd", required=True)
    c = sub.add_parser("collect")
    c.add_argument("--phish", type=int, default=160)
    c.add_argument("--legit-random", type=int, default=60)
    c.add_argument("--legit-curated", type=int, default=None, help="only the first N curated sites (smoke test)")
    c.add_argument("--workers", type=int, default=3)
    c.add_argument("--fresh", action="store_true", help="skip every host used in an earlier run")
    c.add_argument("--seed", type=int, default=7)
    s = sub.add_parser("score")
    s.add_argument("--run")
    s.add_argument("--name", default="results", help="report file name in proof/phase-9-detection/")
    s.add_argument("--title", default="Detection benchmark")
    args = ap.parse_args()
    {"collect": collect, "score": score}[args.cmd](args)


if __name__ == "__main__":
    main()
