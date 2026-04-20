#!/usr/bin/env python3
"""
python_syntax_guard.py - SENTINEL APEX P0 Safety Layer
=======================================================
Scans all Python files in the repo using ast.parse() to catch SyntaxErrors
BEFORE the pipeline runs.

Behaviour:
- PASS (exit 0): all files parse cleanly
- FAIL (exit 1): one or more files have SyntaxErrors; exact file + line reported
- Designed to be called as the FIRST step in run_pipeline.py
- Does NOT modify any files -- read-only safety gate

Usage:
    python3 scripts/python_syntax_guard.py
    python3 scripts/python_syntax_guard.py --dirs scripts agent core api tools
"""

from __future__ import annotations

import ast
import argparse
import logging
import os
import sys

logging.basicConfig(
    level=logging.INFO,
    format="[SyntaxGuard] %(levelname)s %(message)s",
)
log = logging.getLogger("python_syntax_guard")

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEFAULT_SCAN_DIRS = [
    "scripts",
    "agent",
    "core",
    "api",
    "tools",
]

SKIP_DIRS = set([
    ".git",
    "__pycache__",
    "node_modules",
    ".github",
    "threat",
    "sentinel-apex-api",
])


def scan_file(path):
    """
    Parse a single Python file with ast.parse().
    Returns (ok: bool, message: str).
    """
    try:
        source = open(path, "rb").read()
    except OSError as exc:
        return False, "Cannot read file: {}".format(exc)

    try:
        ast.parse(source, filename=path)
        return True, "OK"
    except SyntaxError as exc:
        return False, "SyntaxError at line {}: {}".format(exc.lineno, exc.msg)
    except Exception as exc:
        return False, "Unexpected error: {}".format(exc)


def scan_directory(scan_root):
    """
    Walk scan_root and parse every .py file.
    Returns list of (rel_path, error_message) for failures only.
    """
    failures = []
    if not os.path.isdir(scan_root):
        return failures

    for root, dirs, files in os.walk(scan_root):
        dirs[:] = sorted([d for d in dirs if d not in SKIP_DIRS])
        for fn in sorted(files):
            if not fn.endswith(".py"):
                continue
            path = os.path.join(root, fn)
            rel = os.path.relpath(path, REPO_ROOT)
            ok, msg = scan_file(path)
            if not ok:
                failures.append((rel, msg))

    return failures


def main():
    parser = argparse.ArgumentParser(
        description="Scan Python files for syntax errors before pipeline execution."
    )
    parser.add_argument(
        "--dirs",
        nargs="*",
        default=DEFAULT_SCAN_DIRS,
        help="Subdirectories to scan (relative to repo root)",
    )
    args = parser.parse_args()

    all_failures = []
    total_scanned = 0

    for subdir in args.dirs:
        scan_path = os.path.join(REPO_ROOT, subdir)
        log.info("Scanning: %s/", subdir)
        failures = scan_directory(scan_path)
        for root, dirs, files in os.walk(scan_path):
            dirs[:] = [d for d in dirs if d not in SKIP_DIRS]
            total_scanned += sum(1 for f in files if f.endswith(".py"))
        all_failures.extend(failures)

    if all_failures:
        log.error("SYNTAX GUARD FAILED -- %d file(s) with errors:", len(all_failures))
        for rel, msg in all_failures:
            log.error("  FAIL  %s  ->  %s", rel, msg)
        log.error(
            "Scanned %d files. Fix all errors above before running the pipeline.",
            total_scanned,
        )
        return 1
    else:
        log.info(
            "SYNTAX GUARD PASSED -- %d files scanned, zero errors.",
            total_scanned,
        )
        return 0


if __name__ == "__main__":
    sys.exit(main())
