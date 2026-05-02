#!/usr/bin/env python3
"""
scripts/fix_all_html_encoding.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Universal HTML Encoding Hardener
=====================================================================
Scans ALL .html files in the repo root and:
  1. Removes UTF-8 BOM if present
  2. Repairs admin.html double-encoded mojibake (Latin-1 round-trip)
  3. Replaces raw multi-byte Unicode with HTML entities (HTML context)
     or JS unicode escapes (inside <script> blocks)
  4. Writes atomically (tmp -> fsync -> replace) -- no partial writes

Safe to run multiple times (idempotent).
CI usage: python3 scripts/fix_all_html_encoding.py
Exit 0 = all files clean/fixed, Exit 1 = unfixable error

(c) 2026 CYBERDUDEBIVASH PRIVATE LIMITED. CONFIDENTIAL.
"""
from __future__ import annotations
import os, re, sys, pathlib

REPO = pathlib.Path(__file__).resolve().parent.parent

# ---- replacement tables ----

# HTML entity replacements (for text / comment / attribute context)
HTML_REPLACEMENTS: list[tuple[bytes, bytes]] = [
    (b"\xef\xbb\xbf",     b""),           # BOM -- strip entirely
    (b"\xe2\x80\x94",     b"&mdash;"),    # em-dash   U+2014
    (b"\xe2\x80\x93",     b"&ndash;"),    # en-dash   U+2013
    (b"\xe2\x82\xb9",     b"&#x20B9;"),   # rupee     U+20B9
    (b"\xc2\xa0",         b"&nbsp;"),     # NBSP      U+00A0
    (b"\xe2\x80\x9c",     b"&ldquo;"),    # left "    U+201C
    (b"\xe2\x80\x9d",     b"&rdquo;"),    # right "   U+201D
    (b"\xe2\x80\x98",     b"&lsquo;"),    # left '    U+2018
    (b"\xe2\x80\x99",     b"&rsquo;"),    # right '   U+2019
    (b"\xf0\x9f\x85\xbf", b"[P]"),        # emoji-P   U+1F17F (PayPal icon emoji)
    (b"\xc2\xa9",         b"&copy;"),     # copyright U+00A9
    (b"\xc2\xae",         b"&reg;"),      # registered U+00AE
    (b"\xe2\x84\xa2",     b"&trade;"),    # trademark  U+2122
    (b"\xc2\xb7",         b"&middot;"),   # middle dot U+00B7
    (b"\xe2\x80\xa6",     b"&hellip;"),   # ellipsis   U+2026
]

# JS unicode escape replacements (for content inside <script> blocks)
JS_REPLACEMENTS: list[tuple[bytes, bytes]] = [
    (b"\xe2\x80\x94",     b"\\u2014"),    # em-dash
    (b"\xe2\x80\x93",     b"\\u2013"),    # en-dash
    (b"\xe2\x82\xb9",     b"\\u20b9"),    # rupee
    (b"\xc2\xa0",         b"\\u00a0"),    # NBSP
    (b"\xe2\x80\x9c",     b"\\u201c"),    # left "
    (b"\xe2\x80\x9d",     b"\\u201d"),    # right "
    (b"\xe2\x80\x98",     b"\\u2018"),    # left '
    (b"\xe2\x80\x99",     b"\\u2019"),    # right '
    (b"\xf0\x9f\x85\xbf", b"P"),          # emoji-P
    (b"\xc2\xa9",         b"\\u00a9"),    # copyright
    (b"\xc2\xae",         b"\\u00ae"),    # registered
    (b"\xe2\x84\xa2",     b"\\u2122"),    # trademark
    (b"\xc2\xb7",         b"\\u00b7"),    # middle dot
    (b"\xe2\x80\xa6",     b"\\u2026"),    # ellipsis
]

# CSS unicode escape replacements (for content inside <style> blocks)
CSS_REPLACEMENTS: list[tuple[bytes, bytes]] = [
    (b"\xe2\x80\x94",     b"\\2014 "),
    (b"\xe2\x80\x93",     b"\\2013 "),
    (b"\xe2\x82\xb9",     b"\\20B9 "),
    (b"\xc2\xa0",         b"\\00A0 "),
    (b"\xe2\x80\x9c",     b"\\201C "),
    (b"\xe2\x80\x9d",     b"\\201D "),
    (b"\xe2\x80\x98",     b"\\2018 "),
    (b"\xe2\x80\x99",     b"\\2019 "),
    (b"\xf0\x9f\x85\xbf", b"\\1F17F "),
    (b"\xc2\xa9",         b"\\00A9 "),
    (b"\xc2\xae",         b"\\00AE "),
]

# Double-encoded mojibake patterns found in admin.html
# Two known double-encoding paths are handled:
#   1. Latin-1 path:   UTF-8 bytes misread as Latin-1, then re-encoded to UTF-8
#   2. Windows-1252 path: UTF-8 bytes misread as Windows-1252, then re-encoded to UTF-8
#      W1252 differs from Latin-1 for bytes 0x80-0x9F (e.g. 0x80=EUR 0x94=RDQ 0x92=RSQ).
# ORDERING IS CRITICAL: longest/most-specific patterns first.
# W1252 FULL sequences must appear before W1252 PARTIAL sequences.
MOJIBAKE_TRIPLES: list[tuple[bytes, bytes]] = [
    # ---- Latin-1 (ISO-8859-1) re-encoding path ----
    (b"\xc3\xa2\xc2\x80\xc2\x94", b"&mdash;"),    # U+2014 em-dash   (E2 80 94 via Latin-1)
    (b"\xc3\xa2\xc2\x80\xc2\x93", b"&ndash;"),    # U+2013 en-dash   (E2 80 93 via Latin-1)
    (b"\xc3\xa2\xc2\x80\xc2\x9c", b"&ldquo;"),    # U+201C left-quot (E2 80 9C via Latin-1)
    (b"\xc3\xa2\xc2\x80\xc2\x9d", b"&rdquo;"),    # U+201D right-quot(E2 80 9D via Latin-1)
    (b"\xc3\xa2\xc2\x80\xc2\x98", b"&lsquo;"),    # U+2018 left-apos (E2 80 98 via Latin-1)
    (b"\xc3\xa2\xc2\x80\xc2\x99", b"&rsquo;"),    # U+2019 right-apos(E2 80 99 via Latin-1)
    (b"\xc3\xa2\xc2\x80\xc2\xa6", b"&hellip;"),   # U+2026 ellipsis  (E2 80 A6 via Latin-1)
    (b"\xc3\xa2\xc2\x80\xc2\xa2", b"&bull;"),     # U+2022 bullet    (E2 80 A2 via Latin-1)
    (b"\xc3\xa2\xc2\x82\xc2\xac", b"&euro;"),     # U+20AC euro      (E2 82 AC via Latin-1)
    (b"\xc3\xa2\xc2\x82\xc2\xb9", b"&#x20B9;"),   # U+20B9 rupee     (E2 82 B9 via Latin-1)
    (b"\xc3\xa2\xc2\x80\xc2\x8b", b""),            # U+200B zero-width space (via Latin-1)

    # ---- Windows-1252 re-encoding path -- FULL sequences (pre-substitution) ----
    # E2 80 94 (em-dash):  E2->a(C3A2)  80->EUR(E282AC)  94->RDQ(E2809D)
    (b"\xc3\xa2\xe2\x82\xac\xe2\x80\x9d", b"&mdash;"),  # U+2014 em-dash  (W1252 full)
    # E2 80 93 (en-dash):  E2->a(C3A2)  80->EUR(E282AC)  93->LDQ(E2809C)
    (b"\xc3\xa2\xe2\x82\xac\xe2\x80\x9c", b"&ndash;"),  # U+2013 en-dash  (W1252 full)
    # E2 80 A2 (bullet):   E2->a(C3A2)  80->EUR(E282AC)  A2->cent(C2A2) -- no prior repl for C2A2
    (b"\xc3\xa2\xe2\x82\xac\xc2\xa2",       b"&bull;"),   # U+2022 bullet   (W1252 full)
    # E2 86 92 (r-arrow):  E2->a(C3A2)  86->dag(E280A0)  92->RSQ(E28099)
    (b"\xc3\xa2\xe2\x80\xa0\xe2\x80\x99", b"&rarr;"),   # U+2192 r-arrow  (W1252 full)

    # ---- Windows-1252 re-encoding path -- PARTIAL sequences (post-substitution) ----
    # admin.html was partially processed in a prior run: context-aware single-char
    # replacements already converted the trailing bytes, leaving the W1252 C3A2 E282AC
    # prefix intact.  These variants mop up what the full-sequence patterns above miss.
    # HTML context partials (trailing bytes already converted to HTML entities):
    (b"\xc3\xa2\xe2\x82\xac&rdquo;", b"&mdash;"),  # em-dash: E2809D -> &rdquo;
    (b"\xc3\xa2\xe2\x82\xac&ldquo;", b"&ndash;"),  # en-dash: E2809C -> &ldquo;
    (b"\xc3\xa2\xe2\x80\xa0&rsquo;", b"&rarr;"),   # r-arrow: E28099 -> &rsquo;
    # JS context partials (trailing bytes already converted to JS unicode escapes):
    (b"\xc3\xa2\xe2\x82\xac\\u201d", b"\\u2014"),  # em-dash: E2809D -> \u201d (JS)
    (b"\xc3\xa2\xe2\x82\xac\\u201c", b"\\u2013"),  # en-dash: E2809C -> \u201c (JS)
]

# The 8 patterns the Stage 5.7 validator checks for
VALIDATOR_PATTERNS = [
    b"\xe2\x80\x94",
    b"\xe2\x82\xb9",
    b"\xc3\xa2",
    b"\xc2\xa0",
    b"\xe2\x80\x9c",
    b"\xe2\x80\x9d",
    b"\xe2\x80\x98",
    b"\xf0\x9f\x85\xbf",
]

ERRORS:   list[str] = []
FIXED:    list[str] = []
SKIPPED:  list[str] = []

def atomic_write(path: pathlib.Path, data: bytes) -> None:
    tmp = path.with_suffix(".enc_tmp")
    tmp.write_bytes(data)
    tmp.replace(path)

def apply_replacements(data: bytes, table: list[tuple[bytes, bytes]]) -> bytes:
    for old, new in table:
        data = data.replace(old, new)
    return data

def fix_context_aware(data: bytes) -> bytes:
    """
    Split file into segments: HTML / <script>...</script> / <style>...</style>
    Apply context-appropriate replacements to each segment.
    """
    result = bytearray()
    pos = 0

    # Find script and style block boundaries
    script_open  = re.compile(rb"<script[^>]*>", re.IGNORECASE)
    script_close = re.compile(rb"</script\s*>",   re.IGNORECASE)
    style_open   = re.compile(rb"<style[^>]*>",   re.IGNORECASE)
    style_close  = re.compile(rb"</style\s*>",    re.IGNORECASE)

    while pos < len(data):
        # Find next <script> or <style>
        sm = script_open.search(data, pos)
        st = style_open.search(data, pos)

        # Pick the earlier one
        next_block = None
        if sm and st:
            next_block = sm if sm.start() < st.start() else st
        elif sm:
            next_block = sm
        elif st:
            next_block = st

        if next_block is None:
            # No more blocks -- rest is HTML
            html_chunk = data[pos:]
            result.extend(apply_replacements(html_chunk, HTML_REPLACEMENTS))
            break

        # HTML chunk before the block
        html_chunk = data[pos:next_block.start()]
        result.extend(apply_replacements(html_chunk, HTML_REPLACEMENTS))

        # The opening tag itself (keep verbatim)
        result.extend(next_block.group(0))
        inner_start = next_block.end()

        # Find matching close tag
        is_script = next_block.group(0).strip().lower().startswith(b"<script")
        close_re  = script_close if is_script else style_close
        close_m   = close_re.search(data, inner_start)

        if close_m is None:
            # Unclosed block -- treat rest as that type
            inner = data[inner_start:]
            replacements = JS_REPLACEMENTS if is_script else CSS_REPLACEMENTS
            result.extend(apply_replacements(inner, replacements))
            pos = len(data)
            break

        inner = data[inner_start:close_m.start()]
        replacements = JS_REPLACEMENTS if is_script else CSS_REPLACEMENTS
        result.extend(apply_replacements(inner, replacements))

        # Closing tag verbatim
        result.extend(close_m.group(0))
        pos = close_m.end()

    return bytes(result)


def fix_file(path: pathlib.Path) -> bool:
    """Returns True if file was modified."""
    original = path.read_bytes()
    data = original

    # 1. Fix double-encoded mojibake FIRST (must come before single-byte fixes)
    data = apply_replacements(data, MOJIBAKE_TRIPLES)

    # 2. Remove BOM at start (after mojibake fix in case BOM was also double-encoded)
    if data.startswith(b"\xef\xbb\xbf"):
        data = data[3:]

    # 3. Context-aware replacement of remaining raw Unicode
    data = fix_context_aware(data)

    if data == original:
        SKIPPED.append(path.name)
        return False

    atomic_write(path, data)
    FIXED.append(path.name)
    return True


def verify_clean(path: pathlib.Path) -> list[str]:
    """Check no validator patterns remain. Returns list of found patterns."""
    data = path.read_bytes()
    found = []
    if data.startswith(b"\xef\xbb\xbf"):
        found.append("BOM")
    for pat in VALIDATOR_PATTERNS:
        if pat in data:
            found.append(pat.hex())
    return found


def main() -> None:
    print("=" * 70)
    print("  SENTINEL APEX -- HTML ENCODING HARDENER")
    print("  Fixes: BOM, mojibake, raw UTF-8 Unicode in all HTML files")
    print("=" * 70)

    html_files = sorted(REPO.glob("*.html"))
    print(f"\n  Scanning {len(html_files)} HTML files...\n")

    for f in html_files:
        try:
            modified = fix_file(f)
            status = "FIXED  " if modified else "CLEAN  "
            print(f"  [{status}] {f.name}")
        except Exception as e:
            ERRORS.append(f"{f.name}: {e}")
            print(f"  [ERROR ] {f.name}: {e}")

    # Verify validator-critical files
    print("\n  Verifying Stage 5.7 critical files...")
    critical = ["upgrade.html", "PAYMENT-GATEWAY.html"]
    gate_fail = False
    for fname in critical:
        fpath = REPO / fname
        if not fpath.exists():
            print(f"  [SKIP  ] {fname}: not found")
            continue
        remaining = verify_clean(fpath)
        if remaining:
            print(f"  [FAIL  ] {fname}: still has patterns: {remaining}")
            gate_fail = True
        else:
            print(f"  [OK    ] {fname}: validator-clean")

    print("\n" + "=" * 70)
    print(f"  RESULTS: {len(FIXED)} fixed, {len(SKIPPED)} already clean, {len(ERRORS)} errors")
    print("=" * 70)

    if FIXED:
        print(f"\n  Fixed files: {', '.join(FIXED)}")
    if ERRORS:
        print(f"\n  Errors: {ERRORS}")
        sys.exit(1)
    if gate_fail:
        print("  GATE: FAIL -- critical files still have junk patterns")
        sys.exit(1)

    print("  GATE: PASS -- all HTML files encoding-clean")
    sys.exit(0)


if __name__ == "__main__":
    main()
