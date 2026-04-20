#!/usr/bin/env python3
"""
scripts/sanitize_encoding.py
CYBERDUDEBIVASH(R) SENTINEL APEX v131.0.0 — Platform Encoding Sanitizer
=========================================================================
Permanently eliminates UTF-8 BOM and CRLF line endings from all source,
config, and workflow files in the repository.

Problem: Windows editors (Notepad, VS Code with wrong settings, PowerShell
heredocs) write UTF-8 BOM (\\xef\\xbb\\xbf) at the start of files. Python's
json.load() rejects BOM with JSONDecodeError. YAML parsers similarly fail.
Wrangler (Cloudflare) rejects TOML files with BOM.

Solution: Strip BOM + normalize CRLF -> LF on every CI run, BEFORE any
validation or deployment step.

Usage:
  python3 scripts/sanitize_encoding.py             # dry-run (show what would change)
  python3 scripts/sanitize_encoding.py --fix       # apply fixes
  python3 scripts/sanitize_encoding.py --fix --strict  # exit 1 if any BOM found

Integration (deploy-worker.yml):
  - name: "Sanitize encoding"
    run: python3 scripts/sanitize_encoding.py --fix

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import sys

# ── Configuration ─────────────────────────────────────────────────────────────

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Extensions to scan and sanitize
TEXT_EXTENSIONS = {
    ".json", ".yml", ".yaml", ".toml",
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".html", ".htm", ".css", ".md", ".txt",
    ".sh", ".env", ".cfg", ".ini", ".conf",
}

# Directories to skip entirely
SKIP_DIRS = {
    ".git",
    "node_modules",
    "__pycache__",
    ".venv",
    "venv",
    ".tox",
    "dist",
    "build",
}

BOM = b"\xef\xbb\xbf"


# ── Core logic ────────────────────────────────────────────────────────────────

def scan_repo(root: pathlib.Path) -> list[pathlib.Path]:
    """Return all text files under repo root, skipping ignored dirs."""
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        # Prune skip dirs in-place so os.walk doesn't descend into them
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            p = pathlib.Path(dirpath) / fname
            if p.suffix.lower() in TEXT_EXTENSIONS:
                result.append(p)
    return sorted(result)


def needs_fix(data: bytes) -> tuple[bool, bool]:
    """Return (has_bom, has_crlf)."""
    has_bom  = data.startswith(BOM)
    has_crlf = b"\r\n" in data
    return has_bom, has_crlf


def sanitize(data: bytes) -> bytes:
    """Strip BOM and normalize CRLF -> LF."""
    if data.startswith(BOM):
        data = data[3:]
    data = data.replace(b"\r\n", b"\n")
    return data


def run(root: pathlib.Path, fix: bool, strict: bool) -> int:
    """
    Main scan/fix loop.
    Returns exit code: 0 = clean, 1 = found issues (strict mode only).
    """
    files = scan_repo(root)
    infected: list[tuple[pathlib.Path, bool, bool]] = []

    for f in files:
        try:
            data = f.read_bytes()
        except OSError as e:
            print(f"  SKIP {f}: {e}")
            continue

        has_bom, has_crlf = needs_fix(data)
        if has_bom or has_crlf:
            infected.append((f, has_bom, has_crlf))
            rel = f.relative_to(root)
            flags = " ".join(filter(None, [
                "BOM"  if has_bom  else "",
                "CRLF" if has_crlf else "",
            ]))
            if fix:
                clean = sanitize(data)
                f.write_bytes(clean)
                print(f"  FIXED  [{flags}] {rel}")
            else:
                print(f"  FOUND  [{flags}] {rel}")

    total_files = len(files)
    total_infected = len(infected)

    print()
    print(f"Scanned : {total_files} files")
    print(f"Infected: {total_infected} files")

    if fix and total_infected:
        print(f"Fixed   : {total_infected} files")
        # Re-verify
        still_bad = [
            f for f, _, _ in infected
            if any(needs_fix(f.read_bytes()))
        ]
        if still_bad:
            print(f"ERROR: {len(still_bad)} files still have issues after fix!")
            for f in still_bad:
                print(f"  FAIL: {f.relative_to(root)}")
            return 1
        print("Verified: All fixed. Zero BOM/CRLF remaining.")
    elif total_infected == 0:
        print("Status  : ALL CLEAN - Zero encoding issues found")
    else:
        print("Status  : DRY RUN - Pass --fix to apply changes")

    if strict and total_infected > 0 and not fix:
        print("STRICT MODE: Exiting 1 (encoding issues found)")
        return 1

    return 0


# ── Entry point ───────────────────────────────────────────────────────────────

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX — Platform encoding sanitizer (BOM + CRLF)"
    )
    parser.add_argument(
        "--fix",
        action="store_true",
        help="Apply fixes (default: dry run)",
    )
    parser.add_argument(
        "--strict",
        action="store_true",
        help="Exit 1 if any issues found (CI enforcement mode)",
    )
    parser.add_argument(
        "--root",
        type=pathlib.Path,
        default=REPO_ROOT,
        help=f"Repository root (default: {REPO_ROOT})",
    )
    args = parser.parse_args()

    print("=" * 70)
    print(f"SENTINEL APEX — Encoding Sanitizer v131.0.0")
    print(f"Root   : {args.root}")
    print(f"Mode   : {'FIX' if args.fix else 'DRY-RUN'}")
    print(f"Strict : {args.strict}")
    print("=" * 70)

    rc = run(args.root, fix=args.fix, strict=args.strict)
    sys.exit(rc)


if __name__ == "__main__":
    main()
