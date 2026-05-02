#!/usr/bin/env python3
"""
scripts/production_gate.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Production Stability Master Gate
=====================================================================
Runs the FULL suite of pre-push stability checks in one shot.
Mirrors what GitHub Actions CI runs so failures are caught locally
before any commit reaches the pipeline.

Checks performed:
  1. Python syntax  -- all scripts/*.py
  2. JS syntax      -- workers/intel-gateway/src/index.js (node --check)
  3. YAML syntax    -- all .github/workflows/*.yml
  4. JSON validity  -- version.json, data/stix/feed_manifest.json
  5. HTML encoding  -- fix_all_html_encoding.py (auto-fix + verify)
  6. Monetization   -- validate_monetization.py (full credential gate)

Exit 0 = ALL gates passed, safe to push.
Exit 1 = ONE OR MORE gates failed, DO NOT push.

Usage:
  python3 scripts/production_gate.py          # full suite
  python3 scripts/production_gate.py --fix    # auto-fix encoding then run suite

(c) 2026 CYBERDUDEBIVASH PRIVATE LIMITED. CONFIDENTIAL.
"""
from __future__ import annotations
import argparse, json, subprocess, sys, pathlib, time

REPO = pathlib.Path(__file__).resolve().parent.parent

# ── ANSI colours ─────────────────────────────────────────────────────────────
GREEN  = "\033[32m"
RED    = "\033[31m"
YELLOW = "\033[33m"
CYAN   = "\033[36m"
BOLD   = "\033[1m"
RESET  = "\033[0m"

PASSES:   list[str] = []
FAILURES: list[str] = []
WARNINGS: list[str] = []
T0 = time.monotonic()


def ok(msg: str) -> None:
    PASSES.append(msg)
    print(f"  {GREEN}[PASS]{RESET} {msg}")


def fail(msg: str) -> None:
    FAILURES.append(msg)
    print(f"  {RED}[FAIL]{RESET} {msg}")


def warn(msg: str) -> None:
    WARNINGS.append(msg)
    print(f"  {YELLOW}[WARN]{RESET} {msg}")


def section(title: str) -> None:
    print(f"\n{CYAN}{BOLD}{'─'*68}{RESET}")
    print(f"{CYAN}{BOLD}  {title}{RESET}")
    print(f"{CYAN}{'─'*68}{RESET}")


# ── Gate 1: Python syntax ─────────────────────────────────────────────────────
def gate_python_syntax() -> None:
    section("GATE 1 — Python Syntax (all scripts/*.py)")
    scripts = sorted((REPO / "scripts").glob("*.py"))
    if not scripts:
        warn("No Python scripts found in scripts/")
        return
    errors = 0
    for s in scripts:
        r = subprocess.run(
            [sys.executable, "-m", "py_compile", str(s)],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            fail(f"{s.name}: {r.stderr.strip()}")
            errors += 1
        else:
            ok(f"{s.name}: syntax OK")
    if errors == 0:
        ok(f"All {len(scripts)} Python scripts pass syntax check")


# ── Gate 2: JS syntax ─────────────────────────────────────────────────────────
def gate_js_syntax() -> None:
    section("GATE 2 — JS Syntax (node --check)")
    js_files = [
        REPO / "workers" / "intel-gateway" / "src" / "index.js",
    ]
    for js in js_files:
        if not js.exists():
            warn(f"{js.relative_to(REPO)}: not found — skipping")
            continue
        r = subprocess.run(
            ["node", "--check", str(js)],
            capture_output=True, text=True
        )
        if r.returncode != 0:
            fail(f"{js.relative_to(REPO)}: {r.stderr.strip()}")
        else:
            ok(f"{js.relative_to(REPO)}: syntax OK")


# ── Gate 3: YAML syntax ───────────────────────────────────────────────────────
def gate_yaml_syntax() -> None:
    section("GATE 3 — YAML Syntax (all .github/workflows/*.yml)")
    try:
        import yaml
    except ImportError:
        warn("PyYAML not installed — skipping YAML gate (pip install pyyaml)")
        return
    workflows = sorted((REPO / ".github" / "workflows").glob("*.yml"))
    errors = 0
    for wf in workflows:
        try:
            yaml.safe_load(wf.read_bytes())
            ok(f"{wf.name}: YAML valid")
        except Exception as e:
            fail(f"{wf.name}: {e}")
            errors += 1
    if errors == 0:
        ok(f"All {len(workflows)} workflow YAMLs are valid")


# ── Gate 4: JSON validity ─────────────────────────────────────────────────────
def gate_json_validity() -> None:
    section("GATE 4 — JSON Validity (critical data files)")
    targets = [
        REPO / "version.json",
        REPO / "data" / "stix" / "feed_manifest.json",
    ]
    for t in targets:
        rel = t.relative_to(REPO)
        if not t.exists():
            warn(f"{rel}: not found — skipping")
            continue
        try:
            data = json.loads(t.read_bytes())
            if isinstance(data, list):
                count = len(data)
            elif isinstance(data, dict):
                count = len(data.get("items", data.get("advisories", [data])))
            else:
                count = 1
            ok(f"{rel}: valid JSON ({count} entries)")
        except Exception as e:
            fail(f"{rel}: {e}")


# ── Gate 5: HTML encoding ─────────────────────────────────────────────────────
def gate_html_encoding(auto_fix: bool) -> None:
    section("GATE 5 — HTML Encoding (all 18 HTML files)")
    fix_script = REPO / "scripts" / "fix_all_html_encoding.py"
    if not fix_script.exists():
        fail("scripts/fix_all_html_encoding.py missing — cannot run encoding gate")
        return

    if auto_fix:
        print(f"  {CYAN}Running encoding auto-fix...{RESET}")
        r = subprocess.run([sys.executable, str(fix_script)], capture_output=True, text=True)
        if r.returncode != 0:
            fail(f"fix_all_html_encoding.py exited {r.returncode}")
            print(r.stdout[-500:] if r.stdout else "")
            return
        print(r.stdout[-300:] if r.stdout else "")

    # Verify: check no junk patterns remain in any HTML file
    JUNK = [b"\xc3\xa2", b"\xef\xbb\xbf"]
    html_files = sorted(REPO.glob("*.html"))
    dirty: list[str] = []
    for f in html_files:
        raw = f.read_bytes()
        found = [p.hex() for p in JUNK if p in raw]
        if found:
            dirty.append(f"{f.name} ({', '.join(found)})")

    if dirty:
        for d in dirty:
            fail(f"Encoding junk in: {d}")
        fail(f"Run: python3 scripts/fix_all_html_encoding.py")
    else:
        ok(f"All {len(html_files)} HTML files: BOM-free, mojibake-free")


# ── Gate 6: Monetization integrity ───────────────────────────────────────────
def gate_monetization() -> None:
    section("GATE 6 — Monetization Integrity Gate (v149.1)")
    script = REPO / "scripts" / "validate_monetization.py"
    if not script.exists():
        fail("scripts/validate_monetization.py missing")
        return
    r = subprocess.run(
        [sys.executable, str(script)],
        capture_output=True, text=True, cwd=str(REPO)
    )
    # Print the monetization gate output (summary lines only)
    for line in r.stdout.splitlines():
        stripped = line.strip()
        if stripped.startswith("[FAIL]") or stripped.startswith("X "):
            print(f"  {RED}{stripped}{RESET}")
        elif stripped.startswith("[WARN]") or stripped.startswith("-"):
            print(f"  {YELLOW}{stripped}{RESET}")
        elif stripped.startswith("[OK]") or "GATE: PASS" in stripped:
            print(f"  {GREEN}{stripped}{RESET}")
        elif stripped.startswith("RESULTS") or stripped.startswith("GATE:") or stripped.startswith("==="):
            print(f"  {BOLD}{stripped}{RESET}")
        elif stripped:
            print(f"  {stripped}")
    if r.returncode != 0:
        fail("Monetization gate FAILED — deployment blocked")
    else:
        ok("Monetization gate PASSED (45/45+)")


# ── Summary ───────────────────────────────────────────────────────────────────
def print_summary() -> None:
    elapsed = time.monotonic() - T0
    print(f"\n{BOLD}{'='*68}{RESET}")
    print(f"{BOLD}  SENTINEL APEX — PRODUCTION STABILITY MASTER GATE{RESET}")
    print(f"{BOLD}  Results: {GREEN}{len(PASSES)} passed{RESET}{BOLD}  "
          f"{YELLOW}{len(WARNINGS)} warnings{RESET}{BOLD}  "
          f"{RED}{len(FAILURES)} failures{RESET}  "
          f"({elapsed:.1f}s){RESET}")
    print(f"{BOLD}{'='*68}{RESET}")

    if WARNINGS:
        print(f"\n{YELLOW}  Warnings:{RESET}")
        for w in WARNINGS:
            print(f"    {YELLOW}•{RESET} {w}")

    if FAILURES:
        print(f"\n{RED}  FAILURES (DEPLOYMENT BLOCKED):{RESET}")
        for f_ in FAILURES:
            print(f"    {RED}✗{RESET} {f_}")
        print(f"\n{RED}{BOLD}  GATE: FAIL — DO NOT PUSH until all failures are resolved{RESET}")
        sys.exit(1)
    else:
        print(f"\n{GREEN}{BOLD}  GATE: PASS — All stability checks passed. Safe to push.{RESET}")
        sys.exit(0)


# ── Entry point ───────────────────────────────────────────────────────────────
def main() -> None:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Production Stability Gate")
    parser.add_argument("--fix", action="store_true",
                        help="Auto-fix HTML encoding before running encoding gate")
    args = parser.parse_args()

    print(f"\n{BOLD}{'='*68}{RESET}")
    print(f"{BOLD}  SENTINEL APEX — PRODUCTION STABILITY MASTER GATE{RESET}")
    print(f"{BOLD}  Running {6} gates. Exit 0 = safe to push.{RESET}")
    print(f"{BOLD}{'='*68}{RESET}")

    gate_python_syntax()
    gate_js_syntax()
    gate_yaml_syntax()
    gate_json_validity()
    gate_html_encoding(auto_fix=args.fix)
    gate_monetization()
    print_summary()


if __name__ == "__main__":
    main()
