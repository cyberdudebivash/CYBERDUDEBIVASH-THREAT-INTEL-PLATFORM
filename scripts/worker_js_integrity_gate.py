#!/usr/bin/env python3
"""
scripts/worker_js_integrity_gate.py
CYBERDUDEBIVASH(R) SENTINEL APEX v153.1 -- Worker JS Integrity Gate
====================================================================
Standalone pre-deploy gate for Cloudflare Worker source files.
Validates:
  1. Zero null bytes (esbuild fatal)
  2. Zero non-ASCII bytes (esbuild fatal for any byte > 127)
  3. Valid EOF token (file not truncated -- "Unexpected end of file")
  4. Minimum file size (1 KB -- guards against catastrophic truncation)
  5. No hardcoded secrets patterns

Exit 0 = ALL PASS (deploy safe)
Exit 1 = ANY FAIL (deploy blocked)

This is PURPOSE-BUILT to be fast: only scans workers/intel-gateway/src/*.js
No repo-wide walk, no 35k HTML report files, no timeout risk.

Usage:
  python3 scripts/worker_js_integrity_gate.py
"""
from __future__ import annotations
import pathlib, sys, re

WORKER_SRC = pathlib.Path(__file__).resolve().parent.parent / "workers" / "intel-gateway" / "src"
MIN_BYTES   = 1024   # 1 KB minimum per Worker JS file
VALID_EOF   = {"};", "},", "}", "});", "})", "//", "*/"}

SECRET_PATTERNS = [
    re.compile(r'CDB_JWT_SECRET.*\|\|.*["\'][a-zA-Z0-9]{8,}'),
    re.compile(r'generateSecret\(\)'),
    re.compile(r'Math\.random.*secret', re.IGNORECASE),
]

def check_file(f: pathlib.Path) -> list[str]:
    errors: list[str] = []
    try:
        data = f.read_bytes()
    except OSError as e:
        return [f"CANNOT READ: {e}"]

    # 1. Null bytes
    nulls = data.count(b"\x00")
    if nulls:
        errors.append(f"NULL_BYTES: {nulls} null bytes (esbuild fatal)")

    # 2. Non-ASCII
    non_ascii = sum(1 for b in data if b > 127)
    if non_ascii:
        errors.append(f"NON_ASCII: {non_ascii} non-ASCII bytes (esbuild fatal) -- run: python3 scripts/sanitize_encoding.py --fix")

    # 3. Minimum size
    if len(data) < MIN_BYTES:
        errors.append(f"TOO_SMALL: {len(data)} bytes < {MIN_BYTES} minimum (possible truncation)")

    # 4. Valid EOF
    try:
        text = data.decode("ascii", errors="replace")
        non_empty = [ln.rstrip() for ln in text.splitlines() if ln.strip()]
        last_line  = non_empty[-1].strip() if non_empty else ""
        if last_line not in VALID_EOF:
            errors.append(f"TRUNCATED_EOF: last non-empty line is {repr(last_line[:60])} (not a valid JS closing token)")
    except Exception as e:
        errors.append(f"EOF_CHECK_ERROR: {e}")

    # 5. Hardcoded secrets
    try:
        src_text = data.decode("ascii", errors="replace")
        for pat in SECRET_PATTERNS:
            if pat.search(src_text):
                errors.append(f"HARDCODED_SECRET: pattern {pat.pattern!r} found")
    except Exception:
        pass

    return errors


def main() -> int:
    print("=" * 70)
    print("SENTINEL APEX -- Worker JS Integrity Gate v153.1")
    print(f"Scanning: {WORKER_SRC}")
    print("=" * 70)

    js_files = sorted(WORKER_SRC.glob("*.js"))
    if not js_files:
        print(f"FATAL: No .js files found in {WORKER_SRC}")
        return 1

    all_passed = True
    for f in js_files:
        errors = check_file(f)
        if errors:
            all_passed = False
            print(f"\nFAIL: {f.name}")
            for e in errors:
                print(f"  - {e}")
        else:
            print(f"  OK: {f.name}")

    print()
    if all_passed:
        print(f"RESULT: ALL {len(js_files)} Worker JS files PASS -- deploy safe")
        return 0
    else:
        print("RESULT: INTEGRITY GATE FAILED -- deploy blocked")
        print("Fix:    python3 scripts/sanitize_encoding.py --fix")
        return 1


if __name__ == "__main__":
    sys.exit(main())
