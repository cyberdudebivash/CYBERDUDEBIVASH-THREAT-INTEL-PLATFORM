#!/usr/bin/env python3
"""Fail-closed, read-only SENTINEL APEX P0 release evidence collector.

Run from repository root:
  python scripts/p0_release_certify.py
  python scripts/p0_release_certify.py --production

No deployment, cloud mutations, or GitHub Actions required.
The production mode additionally checks the canonical customer feed.
"""
import argparse
import json
import subprocess
import sys
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TESTS = (
    "tests/test_p0_nvd_pagination.py",
    "tests/test_p0_nvd_network_budget.py",
    "tests/test_true_intel_ingestor_p40.py",
    "tests/test_php2shell_coverage_gate.py",
)
LIVE_URL = "https://intel.cyberdudebivash.com/api/v1/intel/latest.json"


def run(name, args, timeout=180):
    try:
        result = subprocess.run(
            [sys.executable, *args], cwd=ROOT, capture_output=True,
            text=True, timeout=timeout, check=False,
        )
        return {
            "name": name, "passed": result.returncode == 0,
            "exit_code": result.returncode,
            "stdout_tail": result.stdout[-4000:],
            "stderr_tail": result.stderr[-2000:],
        }
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"name": name, "passed": False, "error": str(exc)}


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--production", action="store_true",
                        help="also verify live customer-facing PHP2Shell coverage")
    args = parser.parse_args()
    checks = [
        run("python_syntax", ["-m", "py_compile",
            "scripts/true_intel_ingestor.py",
            "scripts/php2shell_coverage_gate.py",
            "tests/test_p0_nvd_pagination.py",
            "tests/test_p0_nvd_network_budget.py",
            "tests/test_true_intel_ingestor_p40.py",
            "tests/test_php2shell_coverage_gate.py"]),
        run("p0_regressions", ["-m", "pytest", "-q", *TESTS], timeout=240),
    ]
    if args.production:
        checks.append(run("live_php2shell_coverage", [
            "scripts/php2shell_coverage_gate.py", "--url", LIVE_URL,
        ], timeout=30))
    passed = all(check["passed"] for check in checks)
    report = {
        "gate": "sentinel_apex_p0_release",
        "mode": "production" if args.production else "offline",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "passed": passed,
        "checks": checks,
        "scope_note": "P0 checks only; not full-platform certification",
    }
    print(json.dumps(report, indent=2))
    return 0 if passed else 1


if __name__ == "__main__":
    sys.exit(main())
