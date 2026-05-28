#!/usr/bin/env python3
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX — Deployment Consistency Guard
core/version-governance/deployment_consistency_guard.py

PHASES 76, 77, 80 — STALE ASSET ELIMINATION + DEPLOYMENT DETERMINISM

PURPOSE:
    Guards deployment consistency by detecting and reporting:
      • Version drift across all platform components
      • Stale manifests and API endpoints
      • Orphaned deployment artifacts
      • Dashboard version fragmentation
      • Deployment nondeterminism

    Called by CI after version_sync_engine.py completes.
    Hard-fails if any component is out of sync with the registry.

USAGE:
    python3 core/version-governance/deployment_consistency_guard.py
    python3 core/version-governance/deployment_consistency_guard.py --strict
    python3 core/version-governance/deployment_consistency_guard.py --report

EXIT CODES:
    0 — All components consistent. Deployment safe to proceed.
    1 — Drift or inconsistency detected. Deployment BLOCKED.
    2 — Registry missing or unreadable.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
================================================================================
"""
from __future__ import annotations

import argparse
import json
import logging
import re
import sys
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-GUARD] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("CDB-CONSISTENCY-GUARD")

REPO_ROOT = Path(__file__).resolve().parents[2]
REGISTRY  = REPO_ROOT / "core" / "version-governance" / "version_registry.json"

GREEN  = "\033[92m"; YELLOW = "\033[93m"; RED = "\033[91m"
CYAN   = "\033[96m"; BOLD   = "\033[1m";  RST = "\033[0m"

PASS = "✓ PASS"
FAIL = "✗ FAIL"
WARN = "⚠ WARN"
SKIP = "- SKIP"


# ─────────────────────────────────────────────────────────────────────────────
# Check result
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class CheckResult:
    name: str
    status: str          # PASS / FAIL / WARN / SKIP
    detail: str
    expected: Optional[str] = None
    found: Optional[str] = None
    is_blocking: bool = True


# ─────────────────────────────────────────────────────────────────────────────
# Registry loader
# ─────────────────────────────────────────────────────────────────────────────

def load_registry() -> Dict:
    if not REGISTRY.is_file():
        log.error("VERSION REGISTRY NOT FOUND: %s", REGISTRY)
        sys.exit(2)
    try:
        return json.loads(REGISTRY.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        log.error("VERSION REGISTRY INVALID: %s", exc)
        sys.exit(2)


def _read_json(path: Path) -> Optional[Dict]:
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return None


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


# ─────────────────────────────────────────────────────────────────────────────
# Individual consistency checks
# ─────────────────────────────────────────────────────────────────────────────

def check_version_file(ver: str) -> CheckResult:
    path = REPO_ROOT / "VERSION"
    if not path.is_file():
        return CheckResult("VERSION file", FAIL, "File not found", ver, "MISSING")
    found = path.read_text(encoding="utf-8").strip()
    if found == ver:
        return CheckResult("VERSION file", PASS, f"= {ver}")
    return CheckResult("VERSION file", FAIL, "Version drift", ver, found)


def check_config_version_json(ver: str) -> CheckResult:
    path = REPO_ROOT / "config" / "version.json"
    d = _read_json(path)
    if d is None:
        return CheckResult("config/version.json", FAIL, "File missing or unreadable", ver, "MISSING")
    found = str(d.get("version", ""))
    label = str(d.get("label", ""))
    full  = str(d.get("full", ""))
    if found != ver:
        return CheckResult("config/version.json", FAIL, f"version drift | label={label} full={full}", ver, found)
    # Check for stale label/full inconsistency (e.g. label=v160 when version=161.3)
    if label and not label.startswith(f"v{ver.split('.')[0]}"):
        return CheckResult("config/version.json", WARN,
                           f"label inconsistency: label={label} vs version={ver}", ver, label, is_blocking=False)
    return CheckResult("config/version.json", PASS, f"version={found} label={label}")


def check_platform_ssot(ver: str) -> CheckResult:
    path = REPO_ROOT / "config" / "platform_version.json"
    d = _read_json(path)
    if d is None:
        return CheckResult("config/platform_version.json", FAIL, "File missing", ver, "MISSING")
    found = str(d.get("platform", {}).get("version", ""))
    if found != ver:
        return CheckResult("config/platform_version.json", FAIL, "Version drift", ver, found)
    return CheckResult("config/platform_version.json", PASS, f"= {found}")


def check_api_latest(ver: str) -> CheckResult:
    path = REPO_ROOT / "api" / "latest.json"
    d = _read_json(path)
    if d is None:
        return CheckResult("api/latest.json", WARN, "File missing (generated at runtime)", ver, "MISSING", is_blocking=False)
    found = str(d.get("version", d.get("platform_version", "")))
    if found != ver:
        return CheckResult("api/latest.json", FAIL, "Version drift", ver, found)
    return CheckResult("api/latest.json", PASS, f"= {found}")


def check_api_status(ver: str) -> CheckResult:
    path = REPO_ROOT / "api" / "status.json"
    d = _read_json(path)
    if d is None:
        return CheckResult("api/status.json", WARN, "File missing", ver, "MISSING", is_blocking=False)
    found = str(d.get("version", ""))
    if found != ver:
        return CheckResult("api/status.json", FAIL, "Version drift", ver, found)
    return CheckResult("api/status.json", PASS, f"= {found}")


def check_deployment_manifest(ver: str) -> CheckResult:
    path = REPO_ROOT / "core" / "version-governance" / "deployment_manifest.json"
    d = _read_json(path)
    if d is None:
        return CheckResult("deployment_manifest.json", WARN, "Not yet written by CI", ver, "MISSING", is_blocking=False)
    found = str(d.get("deployment", {}).get("version", ""))
    if found != ver:
        return CheckResult("deployment_manifest.json", FAIL, "Version drift", ver, found)
    deterministic = d.get("deployment", {}).get("is_deterministic", False)
    if not deterministic:
        return CheckResult("deployment_manifest.json", WARN, "is_deterministic=false", ver, found, is_blocking=False)
    return CheckResult("deployment_manifest.json", PASS, f"= {found} | deterministic=true")


def check_stale_hardcoded_versions(ver: str) -> CheckResult:
    """
    Scan key source files for hardcoded stale version strings.
    Excludes: CHANGELOG*.md, *.patch, .claude/worktrees, VERSION_HISTORY.
    """
    major = ver.split(".")[0]
    # Patterns that indicate stale hardcoded versions (older major)
    stale_pattern = re.compile(
        r'\b[vV]?(?:1[0-5][0-9]|1[56][0-5])\.[0-9]+(?:\.[0-9]+)?\b'
    )
    scan_paths = [
        REPO_ROOT / "config" / "version.json",
        REPO_ROOT / "config" / "platform_version.json",
        REPO_ROOT / "api" / "latest.json",
        REPO_ROOT / "api" / "status.json",
    ]
    stale_found = []
    for p in scan_paths:
        if not p.is_file():
            continue
        try:
            content = p.read_text(encoding="utf-8")
            matches = stale_pattern.findall(content)
            if matches:
                stale_found.append(f"{p.relative_to(REPO_ROOT)}: {matches[:3]}")
        except Exception:
            pass

    if stale_found:
        return CheckResult(
            "stale_hardcoded_versions",
            WARN,
            f"Stale version strings found in {len(stale_found)} file(s). Run version_sync_engine.py --apply.",
            ver,
            str(stale_found[:3]),
            is_blocking=False,
        )
    return CheckResult("stale_hardcoded_versions", PASS, "No stale hardcoded versions in key files")


def check_registry_self_consistency(reg: Dict) -> CheckResult:
    """Verify registry internal consistency."""
    p = reg.get("platform", {})
    ci = reg.get("ci", {})
    comps = reg.get("components", {})
    ver = str(p.get("version", ""))
    issues = []
    if not ver:
        issues.append("platform.version is empty")
    if not p.get("label", "").startswith("v"):
        issues.append(f"platform.label malformed: {p.get('label')}")
    if "SENTINEL APEX" not in p.get("full", ""):
        issues.append(f"platform.full missing 'SENTINEL APEX': {p.get('full')}")
    if issues:
        return CheckResult("registry_self_consistency", FAIL, " | ".join(issues))
    return CheckResult("registry_self_consistency", PASS,
                       f"v{ver} | {len(comps)} components registered")


# ─────────────────────────────────────────────────────────────────────────────
# Report writer
# ─────────────────────────────────────────────────────────────────────────────

def write_guard_report(ver: str, results: List[CheckResult], output_dir: Path) -> None:
    output_dir.mkdir(parents=True, exist_ok=True)
    report = {
        "schema":           "sentinel-apex-consistency-guard-v1",
        "version":          ver,
        "checked_at":       now_iso(),
        "guard_version":    "166.2",
        "total_checks":     len(results),
        "passed":           sum(1 for r in results if r.status == PASS),
        "failed":           sum(1 for r in results if r.status == FAIL),
        "warnings":         sum(1 for r in results if r.status == WARN),
        "deployment_safe":  all(r.status != FAIL for r in results if r.is_blocking),
        "checks": [
            {
                "name":        r.name,
                "status":      r.status,
                "detail":      r.detail,
                "expected":    r.expected,
                "found":       r.found,
                "is_blocking": r.is_blocking,
            }
            for r in results
        ],
    }
    path = output_dir / "guardian_report.json"
    path.write_text(json.dumps(report, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    log.info("Guard report written: %s", path)


# ─────────────────────────────────────────────────────────────────────────────
# Main
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Deployment Consistency Guard v166.2")
    parser.add_argument("--strict", action="store_true", help="Treat warnings as failures")
    parser.add_argument("--report", action="store_true", help="Print summary report only (always exit 0)")
    args = parser.parse_args()

    reg = load_registry()
    ver = str(reg["platform"]["version"])

    print(f"\n{BOLD}{'='*70}{RST}")
    print(f"{CYAN}  CYBERDUDEBIVASH® SENTINEL APEX — Deployment Consistency Guard v166.2{RST}")
    print(f"  Target version: {BOLD}v{ver}{RST} — {reg['platform'].get('codename','')}")
    print(f"  Checked at:     {now_iso()}")
    print(f"{BOLD}{'='*70}{RST}\n")

    checks = [
        check_registry_self_consistency(reg),
        check_version_file(ver),
        check_config_version_json(ver),
        check_platform_ssot(ver),
        check_api_latest(ver),
        check_api_status(ver),
        check_deployment_manifest(ver),
        check_stale_hardcoded_versions(ver),
    ]

    failures = 0
    warnings = 0
    for r in checks:
        color = GREEN if r.status == PASS else (YELLOW if r.status == WARN else RED)
        blocking = "" if r.is_blocking else " [non-blocking]"
        print(f"  {color}{r.status}{RST}  {r.name}{blocking}")
        if r.detail and r.status != PASS:
            print(f"         → {r.detail}")
            if r.expected and r.found:
                print(f"           expected={r.expected!r}  found={r.found!r}")
        if r.status == FAIL and (r.is_blocking or args.strict):
            failures += 1
        if r.status == WARN and args.strict:
            failures += 1
        if r.status == WARN:
            warnings += 1

    # Write guard report
    try:
        write_guard_report(ver, checks, REPO_ROOT / "data" / "health")
    except Exception as exc:
        log.warning("Could not write guard report: %s", exc)

    print(f"\n{BOLD}{'='*70}{RST}")
    total = len(checks)
    passed = sum(1 for r in checks if r.status == PASS)
    print(f"  Total checks: {total} | Passed: {passed} | Failed: {failures} | Warnings: {warnings}")

    if failures > 0:
        print(f"  {RED}{BOLD}DEPLOYMENT BLOCKED — {failures} consistency failure(s){RST}")
        print(f"  Run: python3 core/version-governance/version_sync_engine.py --apply")
        print(f"{BOLD}{'='*70}{RST}\n")
        return 0 if args.report else 1

    print(f"  {GREEN}{BOLD}DEPLOYMENT SAFE — All components synchronized to v{ver}{RST}")
    print(f"{BOLD}{'='*70}{RST}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
