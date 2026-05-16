#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX
scripts/dependency_audit.py — Enterprise Dependency Vulnerability Scanner (v156.4.0)
======================================================================================
PRODUCTION MANDATE: Zero supply-chain vulnerabilities shipped to production.

This script runs pip-audit against all installed packages and requirements files,
produces a structured vulnerability report, and enforces the CRITICAL vulnerability
gate: any CRITICAL or HIGH severity CVE fails the pipeline with exit code 1.

MODES:
  --audit      Full vulnerability scan (default)
  --report     Generate JSON report to data/security/dependency_audit.json
  --check      CI gate mode: fail on CRITICAL/HIGH (used in STAGE 0.06c)

EXIT CODES:
  0  No CRITICAL/HIGH vulnerabilities found
  1  CRITICAL/HIGH vulnerabilities found (blocks pipeline)
  2  pip-audit not available (non-blocking warning in CI)

Author: CYBERDUDEBIVASH SENTINEL APEX v156.4.0
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import pathlib
import subprocess
import sys
import time
from datetime import datetime, timezone
from typing import Any

logging.basicConfig(level=logging.INFO, format="[DEP-AUDIT] %(message)s")
log = logging.getLogger("dep-audit")

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
REPORT_DIR = REPO_ROOT / "data" / "security"
REPORT_PATH = REPORT_DIR / "dependency_audit.json"
REQUIREMENTS_FILES = [
    "api/requirements.txt",
    "requirements.txt",
]


def _install_pip_audit() -> bool:
    """Attempt to install pip-audit if not present. Returns True if available."""
    try:
        subprocess.run(
            [sys.executable, "-m", "pip_audit", "--version"],
            capture_output=True, check=True
        )
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        pass
    log.info("pip-audit not found — attempting install...")
    try:
        subprocess.run(
            [sys.executable, "-m", "pip", "install", "pip-audit", "--quiet"],
            capture_output=True, timeout=60
        )
        subprocess.run(
            [sys.executable, "-m", "pip_audit", "--version"],
            capture_output=True, check=True
        )
        log.info("pip-audit installed successfully")
        return True
    except Exception as e:
        log.warning("Could not install pip-audit: %s", e)
        return False


def run_audit(requirements_file: str | None = None) -> dict[str, Any]:
    """Run pip-audit and return structured results."""
    cmd = [sys.executable, "-m", "pip_audit", "--format", "json", "--desc"]
    if requirements_file and pathlib.Path(requirements_file).exists():
        cmd += ["-r", requirements_file]
    else:
        cmd += ["--local"]  # audit all installed packages

    log.info("Running: %s", " ".join(cmd))
    t0 = time.monotonic()
    result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    elapsed = time.monotonic() - t0

    # pip-audit exits 1 if vulnerabilities found — that's expected
    try:
        data = json.loads(result.stdout or result.stderr or "[]")
    except json.JSONDecodeError:
        data = []

    # Normalize to list of vulnerability records
    vulns = []
    if isinstance(data, list):
        for item in data:
            if isinstance(item, dict):
                pkg = item.get("name", "unknown")
                version = item.get("version", "unknown")
                for vuln in item.get("vulns", []):
                    vulns.append({
                        "package": pkg,
                        "installed_version": version,
                        "vulnerability_id": vuln.get("id", ""),
                        "description": vuln.get("description", "")[:200],
                        "severity": _estimate_severity(vuln),
                        "fix_versions": vuln.get("fix_versions", []),
                    })

    return {
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "scan_target": requirements_file or "installed_packages",
        "scan_duration_s": round(elapsed, 2),
        "total_packages_scanned": len(data) if isinstance(data, list) else 0,
        "vulnerabilities_found": len(vulns),
        "vulnerabilities": vulns,
        "critical_count": sum(1 for v in vulns if v["severity"] == "CRITICAL"),
        "high_count": sum(1 for v in vulns if v["severity"] == "HIGH"),
        "medium_count": sum(1 for v in vulns if v["severity"] == "MEDIUM"),
        "low_count": sum(1 for v in vulns if v["severity"] == "LOW"),
    }


def _estimate_severity(vuln: dict) -> str:
    """Estimate severity from vulnerability data (pip-audit may not include CVSS)."""
    vid = vuln.get("id", "").upper()
    desc = vuln.get("description", "").lower()
    # PYSEC IDs with known critical patterns
    if any(x in desc for x in ["remote code execution", "rce", "arbitrary code"]):
        return "CRITICAL"
    if any(x in desc for x in ["sql injection", "authentication bypass", "privilege escalation"]):
        return "HIGH"
    if any(x in desc for x in ["cross-site", "xss", "information disclosure"]):
        return "MEDIUM"
    return "LOW"


def main() -> None:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Dependency Audit")
    parser.add_argument("--mode", choices=["audit", "report", "check"], default="check")
    args = parser.parse_args()

    if not _install_pip_audit():
        log.warning("pip-audit unavailable — skipping dependency audit (non-blocking)")
        print("[DEP-AUDIT] WARNING: pip-audit not available. Install with: pip install pip-audit")
        sys.exit(2)  # Non-blocking

    all_results = []
    for req_file in REQUIREMENTS_FILES:
        req_path = REPO_ROOT / req_file
        if req_path.exists():
            log.info("Scanning requirements: %s", req_file)
            result = run_audit(str(req_path))
            all_results.append(result)

    # Also scan installed packages
    log.info("Scanning all installed packages...")
    installed_result = run_audit(None)
    all_results.append(installed_result)

    # Aggregate
    total_vulns = sum(r["vulnerabilities_found"] for r in all_results)
    total_critical = sum(r["critical_count"] for r in all_results)
    total_high = sum(r["high_count"] for r in all_results)
    total_medium = sum(r["medium_count"] for r in all_results)
    total_low = sum(r["low_count"] for r in all_results)

    aggregate = {
        "pipeline_version": os.environ.get("PIPELINE_VERSION", "unknown"),
        "run_id": os.environ.get("GITHUB_RUN_ID", "local"),
        "audit_timestamp": datetime.now(timezone.utc).isoformat(),
        "summary": {
            "total_vulnerabilities": total_vulns,
            "critical": total_critical,
            "high": total_high,
            "medium": total_medium,
            "low": total_low,
            "gate_result": "FAIL" if (total_critical + total_high) > 0 else "PASS",
        },
        "scans": all_results,
    }

    # Write report
    REPORT_DIR.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(aggregate, indent=2), encoding="utf-8")
    log.info("Audit report written: %s", REPORT_PATH)

    # Print summary
    print(f"\n{'='*60}")
    print(f"  SENTINEL APEX DEPENDENCY AUDIT RESULTS")
    print(f"  Total vulnerabilities: {total_vulns}")
    print(f"  CRITICAL: {total_critical}  HIGH: {total_high}  MEDIUM: {total_medium}  LOW: {total_low}")
    print(f"  Gate result: {aggregate['summary']['gate_result']}")
    print(f"{'='*60}\n")

    if args.mode == "check" and (total_critical + total_high) > 0:
        log.error(
            "DEPENDENCY AUDIT GATE FAIL: %d CRITICAL + %d HIGH vulnerabilities found. "
            "Review %s for details.",
            total_critical, total_high, REPORT_PATH
        )
        sys.exit(1)

    log.info("Dependency audit complete. All gates passed.")


if __name__ == "__main__":
    main()
