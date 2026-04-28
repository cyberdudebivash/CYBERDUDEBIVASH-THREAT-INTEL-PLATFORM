#!/usr/bin/env python3
"""
scripts/ci_report_count_check.py
SENTINEL APEX v141.7.0 -- CI Post-pipeline Report Count Gate
=============================================================
Called from STAGE 5.4 in sentinel-blogger.yml.
Verifies reports/ directory has at least 1 HTML report after pipeline execution.
Prevents deploying a zero-report GitHub Pages site.

Exit 0 = reports present. Exit 1 = zero reports (deployment blocked).

NO heredocs. NO inline Python. Called as a standalone script.
(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import sys
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
REPORTS_DIR = REPO / "reports"
MIN_REPORTS = 1


def main() -> int:
    print("=" * 60)
    print("STAGE 5.4 -- Post-pipeline Report Count Gate (v141.7.0)")
    print("=" * 60)

    if not REPORTS_DIR.is_dir():
        print(f"HARD FAIL: reports/ directory does not exist at {REPORTS_DIR}")
        print("Pipeline produced no output. Deployment BLOCKED.")
        return 1

    html_files = [f for f in REPORTS_DIR.rglob("*.html") if f.name != "index.html"]
    count = len(html_files)
    print(f"HTML report count: {count}")

    if count < MIN_REPORTS:
        print(f"HARD FAIL: {count} reports < {MIN_REPORTS} minimum required.")
        print("Report generation produced ZERO output. Deployment BLOCKED.")
        return 1

    print(f"Report gate PASSED: {count} reports available for deployment.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
