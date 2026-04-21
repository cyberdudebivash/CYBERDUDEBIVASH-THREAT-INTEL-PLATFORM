#!/usr/bin/env python3
"""
scripts/encoding_guard.py
CYBERDUDEBIVASH(R) SENTINEL APEX v134.0.0 -- Encoding Guard (P0 Permanent Fix)
================================================================================
MANDATORY FIRST STEP in every pipeline run.

Responsibilities:
  1.  Strip UTF-8 BOM (\xef\xbb\xbf) from ALL text files.
  2.  Normalise CRLF -> LF everywhere.
  3.  Remove null bytes.
  4.  YAML/Workflow files (.yml, .yaml): enforce pure ASCII-safe content --
        - Smart/curly quotes replaced with straight ASCII quotes.
        - Em dash (U+2014) and common mojibake forms replaced with ' - '.
        - Decorative Unicode arrows (U+2192 etc.) replaced with '->'.
        - Box-drawing chars (U+2500 range) replaced with '-'.
        - Emoji and all remaining non-ASCII stripped or substituted.
        This prevents shell heredoc failures, YAML parse errors, and
        'invalid byte sequence' crashes in downstream tools.
  5.  Python / Bash / TOML / config files: BOM + CRLF + null only
      (content-safe; do NOT corrupt string literals).
  6.  Exit 0 ALWAYS -- this script must never break the pipeline.

Usage:
  python3 scripts/encoding_guard.py          # dry-run
  python3 scripts/encoding_guard.py --fix    # apply all fixes
  python3 scripts/encoding_guard.py --fix --strict  # exit 1 if issues found before fix

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import os
import pathlib
import re
import sys

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent

# Extensions that get full ASCII enforcement (YAML/shell where non-ASCII breaks things)
YAML_EXTENSIONS = {".yml", ".yaml", ".sh", ".bash"}

# Extensions that get BOM/CRLF/null treatment only (content-safe)
SAFE_EXTENSIONS = {
    ".py", ".js", ".ts", ".jsx", ".tsx",
    ".json", ".toml", ".cfg", ".ini", ".conf",
    ".html", ".htm", ".css", ".md", ".txt", ".env",
}

ALL_EXTENSIONS = YAML_EXTENSIONS | SAFE_EXTENSIONS

SKIP_DIRS = {
    ".git", "node_modules", "__pycache__", ".venv", "venv",
    ".tox", "dist", "build", ".mypy_cache", ".pytest_cache",
    ".next", ".turbo", "coverage",
}

BOM = b"\xef\xbb\xbf"

# ---------------------------------------------------------------------------
# Unicode -> ASCII substitution map (applied to YAML/shell files only)
# ---------------------------------------------------------------------------

# Mojibake sequences that appear when UTF-8 multi-byte chars are
# misinterpreted as latin-1 then re-encoded.  Must be checked as
# BYTE patterns before decoding.
MOJIBAKE_BYTES: list[tuple[bytes, bytes]] = [
    # UTF-8 for em dash (U+2014) decoded as latin-1 -> 3 raw bytes
    (b"\xe2\x80\x94", b" - "),
    # UTF-8 for right arrow (U+2192) decoded as latin-1
    (b"\xe2\x86\x92", b"->"),
    # UTF-8 for left arrow (U+2190)
    (b"\xe2\x86\x90", b"<-"),
    # UTF-8 for check mark (U+2713)
    (b"\xe2\x9c\x93", b"[OK]"),
    # UTF-8 for heavy check mark (U+2714)
    (b"\xe2\x9c\x94", b"[OK]"),
    # UTF-8 for cross mark (U+2718)
    (b"\xe2\x9c\x98", b"[FAIL]"),
    # UTF-8 for heavy ballot X (U+2716)
    (b"\xe2\x9c\x96", b"[FAIL]"),
    # UTF-8 for registered sign (U+00AE) in common mojibake form
    (b"\xc2\xae", b"(R)"),
    # UTF-8 for copyright (U+00A9)
    (b"\xc2\xa9", b"(C)"),
    # UTF-8 for bullet (U+2022)
    (b"\xe2\x80\xa2", b"*"),
    # UTF-8 for en dash (U+2013)
    (b"\xe2\x80\x93", b"-"),
    # UTF-8 for horizontal ellipsis (U+2026)
    (b"\xe2\x80\xa6", b"..."),
    # UTF-8 for non-breaking space (U+00A0)
    (b"\xc2\xa0", b" "),
]

# Unicode codepoint -> ASCII string replacements (applied after decoding)
UNICODE_CHAR_MAP: dict[int, str] = {
    # Smart quotes -- mapped to HYPHEN not quote characters.
    # Replacing U+201C/201D with ASCII " is UNSAFE: if the smart quote appears
    # inside an already double-quoted YAML string or bash echo, the substituted "
    # terminates the outer quote and breaks syntax.  Using ' - ' is safe in all
    # contexts (comment, name field, string value, shell argument).
    0x201C: ' - ', # left double quotation mark  (was '"' -- broke YAML strings)
    0x201D: '',    # right double quotation mark  (drop trailing)
    0x2018: "'",   # left single quotation mark   (safe: apostrophe)
    0x2019: "'",   # right single quotation mark  (safe: apostrophe)
    0x201A: "'",   # single low-9 quotation mark
    0x201E: ' - ', # double low-9 quotation mark
    0x2032: "'",   # prime
    0x2033: '',    # double prime (drop)
    # Dashes
    0x2014: ' - ', # em dash
    0x2013: '-',   # en dash
    0x2015: '-',   # horizontal bar
    0x2212: '-',   # minus sign
    # Arrows
    0x2192: '->',
    0x2190: '<-',
    0x2194: '<->',
    0x21D2: '=>',
    0x21D0: '<=',
    # Check/cross marks
    0x2713: '[OK]',
    0x2714: '[OK]',
    0x2705: '[OK]',
    0x274C: '[FAIL]',
    0x274E: '[FAIL]',
    0x2718: '[FAIL]',
    0x2716: '[FAIL]',
    0x2717: '[FAIL]',
    0x2715: '[FAIL]',
    # Registered / copyright
    0x00AE: '(R)',
    0x00A9: '(C)',
    0x2122: '(TM)',
    # Bullets / dots
    0x2022: '*',
    0x00B7: '*',
    0x2027: '.',
    0x2026: '...',
    # Non-breaking space and other invisible chars
    0x00A0: ' ',
    0x200B: '',    # zero-width space
    0x200C: '',    # zero-width non-joiner
    0x200D: '',    # zero-width joiner
    0xFEFF: '',    # BOM (if slipped through as char)
    # Box-drawing (used in YAML comments)
    0x2500: '-',   # box drawings light horizontal
    0x2501: '-',
    0x2502: '|',
    0x2503: '|',
    0x2550: '=',   # box drawings double horizontal
    0x2551: '|',
    0x2502: '|',
    0x251C: '+',
    0x252C: '+',
    0x2524: '+',
    0x2534: '+',
    0x253C: '+',
    0x2514: '+',
    0x2518: '+',
    0x250C: '+',
    0x2510: '+',
    0x255E: '+',
    0x2561: '+',
    0x2566: '+',
    0x2569: '+',
    0x2560: '+',
    0x255F: '|',
    0x2562: '|',
    0x2563: '+',
    0x2564: '+',
    0x2567: '+',
    0x2568: '+',
    0x256A: '+',
    0x256B: '+',
    0x256C: '+',
    0x2554: '+',
    0x2557: '+',
    0x255A: '+',
    0x255D: '+',
    # Miscellaneous
    0x00B0: 'deg',
    0x00B1: '+/-',
    0x00D7: 'x',
    0x00F7: '/',
}


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def _fix_unicode_char_map() -> dict[int, str]:
    """Build the char map, excluding the syntax error placeholder."""
    m = {}
    for cp, repl in UNICODE_CHAR_MAP.items():
        if isinstance(cp, int):
            m[cp] = repl
    return m


CHAR_MAP = _fix_unicode_char_map()


def apply_mojibake_bytes(data: bytes) -> bytes:
    """Replace known mojibake byte sequences before decoding."""
    for bad, good in MOJIBAKE_BYTES:
        data = data.replace(bad, good)
    return data


def strip_non_ascii_yaml(text: str) -> str:
    """
    Replace non-ASCII chars in YAML/shell files with ASCII equivalents.
    Known chars use the CHAR_MAP; everything else is dropped.
    Emojis (U+1F000+) are removed entirely -- they break some shell parsers.
    """
    result = []
    i = 0
    while i < len(text):
        ch = text[i]
        cp = ord(ch)

        if cp < 0x80:
            # Pure ASCII -- always keep
            result.append(ch)
            i += 1
            continue

        # Emoji block (U+1F000 - U+1FFFF and modifier ranges)
        if 0x1F000 <= cp <= 0x1FFFF:
            # Emit nothing -- emojis are purely decorative in YAML step names
            i += 1
            continue

        # Known substitution
        repl = CHAR_MAP.get(cp)
        if repl is not None:
            result.append(repl)
            i += 1
            continue

        # Unknown non-ASCII: box-drawing range (U+2500-U+257F)
        if 0x2500 <= cp <= 0x257F:
            result.append('-')
            i += 1
            continue

        # Other block chars / Braille / etc. -- drop
        i += 1

    return "".join(result)


def sanitize_yaml(data: bytes) -> bytes:
    """Full encoding sanitize for YAML/shell files."""
    # 1. Strip BOM
    if data.startswith(BOM):
        data = data[3:]
    # 2. Apply mojibake byte substitutions (before decoding)
    data = apply_mojibake_bytes(data)
    # 3. Replace null bytes with newlines (stripping merges adjacent lines)
    data = data.replace(b"\x00", b"\n")
    # 4. Normalize CRLF -> LF
    data = data.replace(b"\r\n", b"\n")
    data = data.replace(b"\r", b"\n")
    # 5. Decode (replace unrecognised bytes)
    text = data.decode("utf-8", errors="replace")
    # 6. Strip replacement character (U+FFFD)
    text = text.replace("\ufffd", "")
    # 7. Strip all non-ASCII via substitution map
    text = strip_non_ascii_yaml(text)
    # 8. Re-encode as pure UTF-8 (now ASCII-only content)
    return text.encode("utf-8")


def sanitize_safe(data: bytes) -> bytes:
    """Minimal sanitize for Python/JSON/etc: BOM + CRLF + nulls only.
    NOTE: null bytes are replaced with newlines (not stripped).
    Stripping null bytes can merge adjacent lines into invalid syntax
    (e.g. '_ioc_confidence = None\x00import time' -> '_ioc_confidence = Noneimport time').
    Replacing with newline preserves statement boundaries safely.
    """
    if data.startswith(BOM):
        data = data[3:]
    data = data.replace(b"\x00", b"\n")   # null byte -> newline (preserves line boundaries)
    data = data.replace(b"\r\n", b"\n")
    data = data.replace(b"\r", b"\n")
    return data


def needs_sanitize_yaml(data: bytes) -> bool:
    """Quick check: does a YAML/shell file need sanitization?"""
    if data.startswith(BOM):
        return True
    if b"\r\n" in data or b"\r" in data or b"\x00" in data:
        return True
    # Any byte > 127 = non-ASCII = needs processing
    try:
        data.decode("ascii")
        return False
    except UnicodeDecodeError:
        return True


def needs_sanitize_safe(data: bytes) -> bool:
    """Quick check: does a safe file need BOM/CRLF/null fix?"""
    if data.startswith(BOM):
        return True
    if b"\r\n" in data or b"\r" in data or b"\x00" in data:
        return True
    return False


def scan_repo(root: pathlib.Path) -> list[pathlib.Path]:
    """Return all target text files, skipping ignored dirs."""
    result = []
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fname in filenames:
            p = pathlib.Path(dirpath) / fname
            if p.suffix.lower() in ALL_EXTENSIONS:
                result.append(p)
    return sorted(result)


def run(root: pathlib.Path, fix: bool, strict: bool) -> int:
    files = scan_repo(root)
    dirty: list[pathlib.Path] = []

    for f in files:
        try:
            data = f.read_bytes()
        except OSError as e:
            print(f"  SKIP  {f.relative_to(root)}: {e}")
            continue

        ext = f.suffix.lower()
        is_yaml = ext in YAML_EXTENSIONS

        if is_yaml:
            needs_fix = needs_sanitize_yaml(data)
        else:
            needs_fix = needs_sanitize_safe(data)

        if not needs_fix:
            continue

        dirty.append(f)
        rel = f.relative_to(root)

        if fix:
            if is_yaml:
                clean = sanitize_yaml(data)
            else:
                clean = sanitize_safe(data)
            f.write_bytes(clean)
            print(f"  FIXED  {rel}")
        else:
            print(f"  DIRTY  {rel}")

    print()
    print(f"Scanned : {len(files)} files")
    print(f"Dirty   : {len(dirty)} files")

    if fix and dirty:
        print(f"Fixed   : {len(dirty)} files")
        remaining = [f for f in dirty
                     if (needs_sanitize_yaml(f.read_bytes())
                         if f.suffix.lower() in YAML_EXTENSIONS
                         else needs_sanitize_safe(f.read_bytes()))]
        if remaining:
            print(f"ERROR: {len(remaining)} files still need fixes:")
            for f in remaining:
                print(f"  FAIL: {f.relative_to(root)}")
            return 1
        print("Verified: All files clean.")
    elif not dirty:
        print("Status  : ALL CLEAN")
    else:
        print("Status  : DRY RUN -- pass --fix to apply")

    if strict and dirty and not fix:
        return 1
    return 0


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX -- Encoding Guard (P0 Permanent Fix)"
    )
    parser.add_argument("--fix", action="store_true",
                        help="Apply fixes (default: dry run)")
    parser.add_argument("--strict", action="store_true",
                        help="Exit 1 if issues found in dry-run mode")
    parser.add_argument("--root", type=pathlib.Path, default=REPO_ROOT,
                        help=f"Repository root (default: {REPO_ROOT})")
    args = parser.parse_args()

    print("=" * 70)
    print("SENTINEL APEX -- Encoding Guard v134.0.0")
    print(f"Root   : {args.root}")
    print(f"Mode   : {'FIX' if args.fix else 'DRY-RUN'}")
    print(f"Strict : {args.strict}")
    print("=" * 70)

    try:
        rc = run(args.root, fix=args.fix, strict=args.strict)
        sys.exit(rc)
    except Exception as e:
        import traceback
        print(f"[GUARD] encoding_guard.py crashed -- exiting 0 to preserve pipeline: {e}")
        print(traceback.format_exc())
        sys.exit(0)


if __name__ == "__main__":
    main()
