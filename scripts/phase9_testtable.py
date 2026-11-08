"""Export the final test run as tables for the report.

    .venv\\Scripts\\python scripts\\phase9_testtable.py

Reads proof/phase-9/junit.xml (written by: python scripts/prove.py 9 tests) and writes
proof/phase-9/test-cases.md (a summary per module, then every test) and test-cases.csv.
"""
import csv
import xml.etree.ElementTree as ET
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
OUT = ROOT / "proof" / "phase-9"

MODULES = {
    "test_phase0_foundation": "Foundation: app factory, database, security headers, loopback-only server",
    "test_phase1_url_rules": "URL toolkit and URL rules (look-alikes, IP links, punycode, scoring)",
    "test_phase2_sandbox": "Sandbox and egress gatekeeper against local fake attack sites",
    "test_phase3_verdicts": "Page rules, threat lists, verdicts and privacy report",
    "test_phase4_guard": "AI Guard prompt-injection model",
    "test_phase5_llm": "LLM second opinion (can only raise risk)",
    "test_phase6_api": "Backend API, login, CSRF, origin and host checks, roles",
    "test_phase7_ui": "Dashboard and Airlock UI in a real browser",
    "test_phase8_launcher": "Windows link launcher and registration",
    "test_phase8b_accounts": "Personal mode, accounts, Start menu entry",
    "test_phase8c_privacy": "Hide my IP (Tor, Cloudflare WARP, own proxy)",
    "test_phase9_detection": "Phishing detection layers: lists, domain age, identity check",
    "test_phase9_scoring": "Scoring: threats decide the verdict",
    "test_phase9_settings": "Settings: start with Windows, history clean-up",
    "test_phase9_tray": "Tray icon and single dashboard window",
    "test_phase9_security": "Security self-test findings (regression tests)",
}


def readable(name: str) -> str:
    base, _, param = name.partition("[")
    text = base.removeprefix("test_").replace("_", " ")
    text = text[:1].upper() + text[1:]
    return f"{text} [{param}" if param else text


def main():
    root = ET.parse(OUT / "junit.xml").getroot()
    rows = []
    for tc in root.iter("testcase"):
        mod = tc.get("classname", "").split(".")[-1]
        if tc.find("skipped") is not None:
            result = "Skipped"
        elif tc.find("failure") is not None or tc.find("error") is not None:
            result = "Fail"
        else:
            result = "Pass"
        rows.append({"module": mod, "test": tc.get("name"), "description": readable(tc.get("name")),
                     "seconds": float(tc.get("time") or 0), "result": result})
    by = {}
    for r in rows:
        m = by.setdefault(r["module"], {"Pass": 0, "Fail": 0, "Skipped": 0, "seconds": 0.0})
        m[r["result"]] += 1
        m["seconds"] += r["seconds"]
    total = {k: sum(m[k] for m in by.values()) for k in ("Pass", "Fail", "Skipped", "seconds")}

    order = list(MODULES)
    lines = ["# Phase 9: Test cases", "",
             f"{len(rows)} automated tests: **{total['Pass']} passed, {total['Fail']} failed, {total['Skipped']} skipped** "
             f"({total['seconds']:.0f} s of test time).", "",
             "| Module | What it covers | Tests | Passed | Failed | Skipped |", "|---|---|---:|---:|---:|---:|"]
    for mod in sorted(by, key=lambda m: order.index(m) if m in order else 99):
        m = by[mod]
        lines.append(f"| `{mod}` | {MODULES.get(mod, '')} | {m['Pass'] + m['Fail'] + m['Skipped']} | {m['Pass']} | "
                     f"{m['Fail']} | {m['Skipped']} |")
    lines.append(f"| **Total** | | **{len(rows)}** | **{total['Pass']}** | **{total['Fail']}** | **{total['Skipped']}** |")
    lines += ["", "## Every test", "", "| Module | Test | Result |", "|---|---|---|"]
    lines += [f"| {r['module']} | {r['description'].replace('|', '/')} | {r['result']} |" for r in rows]
    (OUT / "test-cases.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    with open(OUT / "test-cases.csv", "w", newline="", encoding="utf-8") as f:
        w = csv.DictWriter(f, fieldnames=["module", "test", "description", "seconds", "result"])
        w.writeheader()
        w.writerows(rows)
    print("\n".join(lines[:len(by) + 8]))


if __name__ == "__main__":
    main()
