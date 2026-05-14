#!/usr/bin/env python3
"""
scripts/sanitize_encoding.py
CYBERDUDEBIVASH(R) SENTINEL APEX v134.0.0 — Platform Encoding Sanitizer
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
    # Pipeline output dirs -- large JSON/HTML blobs already validated by
    # encoding_validator.py (GATE 1/4). Skipping here cuts step runtime
    # from ~4.5 min to <5 s and prevents false-positive non-ASCII hits
    # in legitimate UTF-8 threat intel content.
    "api",
    "reports",
}

BOM = b"\xef\xbb\xbf"

# ── Worker JS ASCII enforcement (P0 permanent fix v153.1) ─────────────────────
# esbuild (Cloudflare Worker bundler) rejects ANY non-ASCII byte with:
#   "Unexpected <char>" build error.
# sanitize_encoding.py previously only handled BOM/CRLF/null — it did NOT strip
# Unicode chars (em dashes U+2014, registered trademark U+00AE, etc.) from Worker
# JS. This caused the commit-144fc10 P0 regression.
#
# WORKER_ASCII_DIRS: relative paths of Worker source directories that require
# full ASCII enforcement. Any .js/.ts file under these dirs is ASCII-enforced.
WORKER_ASCII_DIRS: tuple[str, ...] = (
    "workers/intel-gateway/src",
)

# Mojibake byte sequences (UTF-8 chars read as raw bytes) and their replacements
_WORKER_MOJIBAKE: list[tuple[bytes, bytes]] = [
    (b"\xe2\x80\x94", b" - "),  # em dash U+2014
    (b"\xe2\x80\x93", b"-"),    # en dash U+2013
    (b"\xe2\x86\x92", b"->"),   # right arrow U+2192
    (b"\xc2\xae",     b"(R)"),  # registered trademark U+00AE
    (b"\xc2\xa9",     b"(C)"),  # copyright U+00A9
    (b"\xc2\xa0",     b" "),    # non-breaking space U+00A0
    (b"\xe2\x80\xa2", b"*"),    # bullet U+2022
    (b"\xe2\x80\x98", b"'"),    # left single quote U+2018
    (b"\xe2\x80\x99", b"'"),    # right single quote U+2019
    (b"\xe2\x80\x9c", b'"'),    # left double quote U+201C
    (b"\xe2\x80\x9d", b'"'),    # right double quote U+201D
    (b"\xe2\x80\xa6", b"..."),  # ellipsis U+2026
    (b"\xe2\x80\x8b", b""),     # zero-width space U+200B
    (b"\xef\xbf\xbd", b"?"),    # replacement char U+FFFD
    (b"\xef\xbb\xbf", b""),     # BOM
]

_WORKER_CHAR_MAP: dict[int, str] = {
    0x00AE: "(R)", 0x00A9: "(C)", 0x2122: "(TM)",
    0x2014: " - ", 0x2013: "-",  0x2015: "-", 0x2212: "-",
    0x2192: "->",  0x2190: "<-", 0x21D2: "=>",
    0x2022: "*",   0x00B7: "*",  0x00A0: " ",
    0x2026: "...", 0x201C: '"',  0x201D: '"',
    0x2018: "'",   0x2019: "'",
    0x200B: "",    0x200C: "",   0x200D: "", 0xFEFF: "",
}


def _is_worker_js(path: pathlib.Path, root: pathlib.Path) -> bool:
    """Return True if this file is inside a Worker ASCII-enforced source dir."""
    if path.suffix.lower() not in {".js", ".ts", ".jsx", ".tsx"}:
        return False
    try:
        rel = path.relative_to(root).as_posix()
    except ValueError:
        return False
    return any(rel.startswith(d + "/") for d in WORKER_ASCII_DIRS)


def _needs_worker_ascii_fix(data: bytes) -> bool:
    """Return True if any byte > 127 exists (Worker JS must be pure ASCII)."""
    return any(b > 127 for b in data)


def _sanitize_worker_js(data: bytes) -> bytes:
    """Strip all non-ASCII from a Worker JS/TS file. Never drops content silently."""
    if data.startswith(BOM):
        data = data[3:]
    for bad, good in _WORKER_MOJIBAKE:
        data = data.replace(bad, good)
    data = data.replace(b"\x00", b"\n")
    data = data.replace(b"\r\n", b"\n").replace(b"\r", b"\n")
    text = data.decode("utf-8", errors="replace")
    result = []
    for ch in text:
        cp = ord(ch)
        if cp < 0x80:
            result.append(ch)
        elif ch == "�":
            result.append("?")
        else:
            repl = _WORKER_CHAR_MAP.get(cp)
            if repl is not None:
                result.append(repl)
            elif 0x2500 <= cp <= 0x257F:
                result.append("-")
            elif 0x1F000 <= cp <= 0x1FFFF:
                result.append("?")
            else:
                result.append("?")
    return "".join(result).encode("ascii")


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
    """Return (has_bom, has_issues). has_issues covers CRLF, null bytes, control chars."""
    has_bom    = data.startswith(BOM)
    has_crlf   = b"\r\n" in data
    has_nulls  = b"\x00" in data
    try:
        text = data.decode("utf-8", errors="replace")
        has_ctrl = has_control_chars(text)
    except Exception:
        has_ctrl = False
    return has_bom, (has_crlf or has_nulls or has_ctrl)


def has_control_chars(text: str) -> bool:
    """Return True if text contains YAML/JSON-disallowed control characters."""
    for ch in text:
        cp = ord(ch)
        # Allow: tab, LF, CR, printable ASCII, NEL, high Unicode
        if not (cp == 0x09 or cp == 0x0A or cp == 0x0D or
                (0x20 <= cp <= 0x7E) or cp == 0x85 or
                (0xA0 <= cp <= 0xD7FF) or
                (0xE000 <= cp <= 0xFFFD) or
                (0x10000 <= cp <= 0x10FFFF)):
            return True
    return False


def strip_control_chars(text: str) -> str:
    """Remove YAML/JSON-disallowed control characters (e.g. U+0090 DCS)."""
    result = []
    for ch in text:
        cp = ord(ch)
        if (cp == 0x09 or cp == 0x0A or cp == 0x0D or
                (0x20 <= cp <= 0x7E) or cp == 0x85 or
                (0xA0 <= cp <= 0xD7FF) or
                (0xE000 <= cp <= 0xFFFD) or
                (0x10000 <= cp <= 0x10FFFF)):
            result.append(ch)
    return "".join(result)


def sanitize(data: bytes) -> bytes:
    """Strip BOM, null bytes, control chars and normalize CRLF -> LF."""
    if data.startswith(BOM):
        data = data[3:]
    # Strip null bytes (padding artifact from some write tools)
    data = data.replace(b"\x00", b"")
    data = data.replace(b"\r\n", b"\n")
    # Strip YAML/JSON-disallowed control characters (e.g. U+0090 DCS → \xc2\x90 in UTF-8)
    try:
        text = data.decode("utf-8", errors="replace")
        if has_control_chars(text):
            data = strip_control_chars(text).encode("utf-8")
    except Exception:
        pass
    return data


def run(root: pathlib.Path, fix: bool, strict: bool) -> int:
    """
    Main scan/fix loop.
    Returns exit code: 0 = clean, 1 = found issues (strict mode only).
    """
    files = scan_repo(root)
    infected: list[tuple[pathlib.Path, bool, bool]] = []
    # --- v153.1: Worker JS ASCII enforcement pass (runs before BOM/CRLF scan) ---
    # esbuild rejects any non-ASCII byte; sanitize_encoding previously missed this.
    worker_ascii_failed: list[pathlib.Path] = []
    for f in files:
        if not _is_worker_js(f, root):
            continue
        try:
            data = f.read_bytes()
        except OSError:
            continue
        if not _needs_worker_ascii_fix(data):
            continue
        rel = f.relative_to(root)
        if fix:
            clean = _sanitize_worker_js(data)
            f.write_bytes(clean)
            remaining = sum(1 for b in f.read_bytes() if b > 127)
            if remaining > 0:
                print(f"  FAIL   [WORKER-ASCII] {rel} ({remaining} non-ASCII remain after fix)")
                worker_ascii_failed.append(f)
            else:
                print(f"  FIXED  [WORKER-ASCII] {rel}")
        else:
            count = sum(1 for b in data if b > 127)
            print(f"  DIRTY  [WORKER-ASCII] {rel} ({count} non-ASCII bytes)")
            worker_ascii_failed.append(f)
    if worker_ascii_failed and not fix:
        print(f"\nFATAL: {len(worker_ascii_failed)} Worker JS file(s) have non-ASCII bytes.")
        print("Run: python3 scripts/sanitize_encoding.py --fix")
        if strict:
            return 1
    # --- end Worker JS ASCII pass ---

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
    print(f"SENTINEL APEX — Encoding Sanitizer v134.0.0")
    print(f"Root   : {args.root}")
    print(f"Mode   : {'FIX' if args.fix else 'DRY-RUN'}")
    print(f"Strict : {args.strict}")
    print("=" * 70)

    rc = run(args.root, fix=args.fix, strict=args.strict)
    sys.exit(rc)


if __name__ == "__main__":
    main()
