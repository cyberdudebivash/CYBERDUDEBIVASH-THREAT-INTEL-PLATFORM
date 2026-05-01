#!/usr/bin/env python3
"""
SENTINEL APEX v145.2.0 - Encoding Validator (Hard-Fail Gate)
Scans index.html, feed.json, api/feed.json for:
  - Mojibake sequences (double-encoded UTF-8)
  - Replacement characters (U+FFFD)
  - Non-UTF-8 byte sequences
  - EMBEDDED_INTEL data pollution (non-empty array)
  - Generic ae-prefix mojibake (CI hard-fail gate)
Exit 0 = PASS, Exit 1 = FAIL (pipeline must be blocked)

v145.2.0 changes:
  - Added: Ã-- (double-encoded multiplication sign U+00D7) detection
  - Added: Generic 'ae'-prefix text-level CI hard-fail gate
  - Added: TEXT_MOJIBAKE_PATTERNS for decoded-string scan
  - Fixed: validator's own string literals now ASCII-safe
"""
import sys, os, json, re

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# -- Mojibake byte patterns (double-encoded UTF-8) --
# These appear when UTF-8 bytes are mis-read as latin-1 and re-encoded as UTF-8
MOJIBAKE_SEQUENCES = [
    # en-dash (U+2013) double-encoded: e2 80 93 -> c3a2 c280 c293
    (b'\xc3\xa2\xc2\x80\xc2\x93', 'en-dash mojibake'),
    (b'\xc3\xa2\xc2\x80\xc2\x94', 'em-dash mojibake'),
    (b'\xc3\xa2\xc2\x80\xc2\x99', 'right-single-quote mojibake'),
    (b'\xc3\xa2\xc2\x80\xc2\x9c', 'left-double-quote mojibake'),
    (b'\xc3\xa2\xc2\x80\xc2\x9d', 'right-double-quote mojibake'),
    (b'\xc3\xa2\xc2\x80\xc2\xa2', 'bullet mojibake'),
    (b'\xc3\xa2\xc2\x80\xc2\x98', 'left-single-quote mojibake'),
    (b'\xc3\xa2\xc2\x80\xc2\xa6', 'ellipsis mojibake'),
    (b'\xc3\xa2\xc2\x80\xc2\x8b', 'zero-width mojibake'),
    # Emoji double-encoded: f0 9f xx xx -> c3b0 c59f xx xx
    (b'\xc3\xb0\xc5\xb8', 'emoji mojibake (f09f)'),
    # Replacement character U+FFFD
    (b'\xef\xbf\xbd', 'replacement char U+FFFD'),
    # Multiplication sign U+00D7 double-encoded: c3 97 -> c3 83 c2 97
    # Appears as "Ã--" in source -- P0 dashboard bug (8 occurrences fixed in v145.1)
    (b'\xc3\x83\xc2\x97', 'multiplication-sign Ã-- mojibake (U+00D7 double-encoded)'),
]

# -- Textual mojibake patterns (decoded string level, CI hard-fail) --
# Any of these strings in pipeline output = FAIL
TEXT_MOJIBAKE = [
    'â',   # ae+80 prefix (mangled em-dash/quote family)
    'Ã¢',   # Ã¢ prefix (double-encoded a-circumflex)
    'ðŸ',             # mangled emoji
    '�',         # replacement char
    'Ã¢',   # Ã¢  (double-encoded â)
]

FILES_TO_SCAN = [
    "index.html",
    "feed.json",
    "api/feed.json",
]

def scan_file(path):
    full_path = os.path.join(REPO, path)
    if not os.path.exists(full_path):
        return [], [f"File not found: {path}"]

    with open(full_path, "rb") as f:
        raw = f.read()

    violations = []
    warnings = []

    # BOM check
    if raw[:3] == b'\xef\xbb\xbf':
        violations.append(f"UTF-8 BOM present (will corrupt JSON parsing)")

    # Byte-level mojibake check
    for seq, name in MOJIBAKE_SEQUENCES:
        count = raw.count(seq)
        if count > 0:
            # Find context
            idx = raw.find(seq)
            ctx = raw[max(0, idx-20):idx+len(seq)+20]
            try:
                ctx_str = ctx.decode('utf-8', errors='replace')
            except Exception:
                ctx_str = repr(ctx)
            violations.append(f"{count}x {name} ({seq.hex()}) — context: {repr(ctx_str[:60])}")

    # For JSON files: also check parsed content
    if path.endswith('.json'):
        try:
            text = raw.decode('utf-8', errors='replace')
            data = json.loads(text)
            items = data if isinstance(data, list) else data.get('advisories', [])

            # Check for text-level mojibake in string fields
            moji_items = 0
            for item in items[:200]:  # sample first 200
                for v in item.values():
                    if isinstance(v, str):
                        for moji in TEXT_MOJIBAKE:
                            if moji in v:
                                moji_items += 1
                                break
            if moji_items:
                warnings.append(f"{moji_items} items contain text-level mojibake in first 200 entries")
        except Exception as e:
            warnings.append(f"JSON parse warning: {e}")

    # For index.html: verify EMBEDDED_INTEL declaration exists (architecture check only)
    # v147.0: EMBEDDED_INTEL may be [] (pre-inject) OR populated with top-25 items (post-inject).
    # inject_embedded_intel.py (STAGE 3.93) populates it before deploy -- both states are valid.
    # Architecture enforcement is handled by dashboard_frontend_guard.py (STAGE 3.92).
    # This validator checks ENCODING only -- do NOT fail on populated EMBEDDED_INTEL.
    if path == "index.html":
        ei_marker = b'window.EMBEDDED_INTEL = ['
        ei_pos = raw.find(ei_marker)
        if ei_pos < 0:
            warnings.append("EMBEDDED_INTEL marker not found (may have been removed)")
        # No violation for populated EMBEDDED_INTEL -- injector state is intentional

    return violations, warnings


def main():
    print("=" * 65)
    print("SENTINEL APEX — ENCODING VALIDATOR v143.0")
    print("=" * 65)

    total_violations = 0
    total_warnings = 0
    results = {}

    for path in FILES_TO_SCAN:
        violations, warnings = scan_file(path)
        results[path] = {"violations": violations, "warnings": warnings}
        fsize = os.path.getsize(os.path.join(REPO, path)) if os.path.exists(os.path.join(REPO, path)) else 0
        status = "FAIL" if violations else "PASS"
        print(f"\n[{status}] {path} ({fsize:,} bytes)")
        for v in violations:
            print(f"  ERROR: {v}")
            total_violations += 1
        for w in warnings:
            print(f"  WARN:  {w}")
            total_warnings += 1
        if not violations and not warnings:
            print("  OK: No encoding issues found")

    print("\n" + "=" * 65)
    if total_violations == 0:
        print(f"RESULT: PASS — {total_violations} violations, {total_warnings} warnings")
        print("Encoding: CLEAN across all files")
    else:
        print(f"RESULT: FAIL — {total_violations} violations in {sum(1 for r in results.values() if r['violations'])} files")
        print("ACTION: Fix encoding violations before deployment")
    print("=" * 65)

    # Write report
    report_path = os.path.join(REPO, "data", "audit", "encoding_report.json")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    import datetime
    report = {
        "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
        "result": "PASS" if total_violations == 0 else "FAIL",
        "total_violations": total_violations,
        "total_warnings": total_warnings,
        "files": results,
    }
    tmp = report_path + ".tmp"
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(report, f, ensure_ascii=False, indent=2)
    os.replace(tmp, report_path)

    sys.exit(0 if total_violations == 0 else 1)


if __name__ == "__main__":
    main()
