#!/usr/bin/env python3
"""
scripts/ci_preflight_check.py
SENTINEL APEX v141.7.0 -- CI Pre-flight: Critical Script Integrity Check
========================================================================
Called from STAGE 0.05 in sentinel-blogger.yml.
Validates all critical pipeline scripts before any execution begins.
Exit 0 = all OK. Exit 1 = at least one critical file is missing/truncated/corrupt.

NO heredocs. NO inline Python. Called as a standalone script.
(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import py_compile
import sys
import tempfile
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

CHECKS = {
    "scripts/run_pipeline.py":           55_000,
    "agent/sentinel_blogger.py":         25_000,
    "agent/export_stix.py":              30_000,
    "scripts/intel_dedup_engine.py":     15_000,
    "scripts/generate_intel_reports.py": 45_000,
    "scripts/validate_repo.py":          10_000,
}

def main() -> int:
    print("=" * 60)
    print("STAGE 0.05 -- CI Pre-flight File Integrity Check (v141.7.0)")
    print("=" * 60)

    failures = []
    for rel, min_b in CHECKS.items():
        p = REPO / rel
        if not p.exists():
            failures.append(f"MISSING: {rel}")
            continue

        sz = p.stat().st_size
        if sz < min_b:
            failures.append(f"TRUNCATED: {rel} ({sz} bytes < {min_b} threshold)")
            continue

        raw = p.read_bytes()
        null_bytes = raw.count(b"\x00")
        if null_bytes:
            failures.append(f"NULL_BYTES: {rel} ({null_bytes} null bytes)")
            continue

        try:
            with tempfile.NamedTemporaryFile(suffix=".pyc", delete=True) as tf:
                py_compile.compile(str(p), cfile=tf.name, doraise=True)
        except py_compile.PyCompileError as e:
            failures.append(f"SYNTAX_ERROR: {rel} -- {e}")
            continue

        print(f"  OK  {rel}  ({sz} bytes)")

    if failures:
        print(f"\nPRE-FLIGHT FAILURES ({len(failures)}):")
        for f in failures:
            print(f"  FAIL: {f}")
        print("\nHARD STOP: Fix the above files before re-running the pipeline.")
        return 1

    print(f"\nAll {len(CHECKS)} critical scripts passed integrity check. Pipeline safe to run.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
