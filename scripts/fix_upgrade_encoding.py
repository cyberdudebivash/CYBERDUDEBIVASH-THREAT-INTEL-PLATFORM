#!/usr/bin/env python3
"""
scripts/fix_upgrade_encoding.py
SENTINEL APEX v149.1 -- Encoding Fix for upgrade.html
======================================================
Replaces raw multi-byte UTF-8 sequences with safe ASCII/HTML/JS equivalents:
  - em-dash U+2014 (0xE2 0x80 0x94) in HTML comments -> ASCII --
  - rupee U+20B9  (0xE2 0x82 0xB9) in JS strings     -> JS escape ₹

Run: python scripts/fix_upgrade_encoding.py
"""
import pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent
path = REPO / "upgrade.html"

print("=== upgrade.html ENCODING FIX ===")
data = path.read_bytes()
original_len = len(data)

# 1. em-dash in HTML comment: "UPGRADE.HTML v149.0 — PAYMENT ENGINE"
#    Replace with ASCII double-hyphen -- (safe in comments and readable)
before = data.count(b"\xe2\x80\x94")
data = data.replace(b"\xe2\x80\x94", b"--")
print(f"  em-dash (U+2014): replaced {before} occurrence(s) with --")

# 2. rupee sign in JS single-quoted strings: textContent = '₹' (JS escape)
#    The byte sequence 0xE2 0x82 0xB9 is the UTF-8 encoding of U+20B9 (RUPEE SIGN)
#    Replace ALL occurrences with the JS unicode escape sequence ₹
before = data.count(b"\xe2\x82\xb9")
data = data.replace(b"\xe2\x82\xb9", b"\\u20b9")
print(f"  rupee (U+20B9):   replaced {before} occurrence(s) with \\u20b9 JS escape")

# Verify no junk patterns remain
JUNK = {
    b"\xe2\x80\x94": "em-dash U+2014",
    b"\xe2\x82\xb9": "rupee U+20B9",
    b"\xc3\xa2":     "mojibake-prefix Ã¢",
    b"\xc2\xa0":     "NBSP U+00A0",
    b"\xe2\x80\x9c": "left-dquote U+201C",
    b"\xe2\x80\x9d": "right-dquote U+201D",
    b"\xe2\x80\x98": "left-squote U+2018",
    b"\xf0\x9f\x85\xbf": "emoji-P U+1F17F",
}
remaining = {label: pat for pat, label in JUNK.items() if pat in data}
if remaining:
    print(f"\n  [FAIL] Junk patterns still present: {list(remaining.keys())}")
    import sys; sys.exit(1)

# BOM check
if data.startswith(b"\xef\xbb\xbf"):
    print("  [FAIL] BOM still present!")
    import sys; sys.exit(1)

# Atomic write: tmp -> fsync -> replace
tmp = path.with_suffix(".tmp")
tmp.write_bytes(data)
tmp.replace(path)

print(f"\n  [OK] upgrade.html: all junk patterns cleared")
print(f"  [OK] File size: {original_len} -> {len(data)} bytes")
print("  GATE: PASS -- upgrade.html is encoding-clean")
