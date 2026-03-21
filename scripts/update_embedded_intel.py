#!/usr/bin/env python3
"""
CYBERDUDEBIVASH SENTINEL APEX v73.0 — Hardened EMBEDDED_INTEL Updater
=======================================================================
Surgically replaces ONLY the EMBEDDED_INTEL data array in index.html.
Everything else — functions, CSS, HTML, comments — is preserved byte-for-byte.

HOW IT WORKS:
  1. Finds `const EMBEDDED_INTEL = [` using string search (not regex)
  2. Brace-matches `[...]` to find the exact array boundaries
  3. Replaces ONLY the array content between [ and ]
  4. Verifies the result with 6 integrity checks
  5. If ANY check fails → restores backup, exits non-zero

WHAT IT PRESERVES:
  - renderTopThreats (v73 enhanced version)
  - All CSS, HTML structure, and meta tags
  - Brand strings (CYBERDUDEBIVASH SENTINEL APEX v73.0)
  - Every function, variable, and comment outside EMBEDDED_INTEL
  - The `const EMBEDDED_INTEL = ` prefix and `];` suffix (only array data changes)

SAFE: Creates backup before write. Rolls back on any assertion failure.
"""

import json
import os
import shutil
import sys
from pathlib import Path
from datetime import datetime, timezone

REPO_ROOT = Path(__file__).parent.parent
INDEX_HTML = REPO_ROOT / "index.html"
FEED_MANIFEST = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
ENRICHED_MANIFEST = REPO_ROOT / "data" / "v46_ultraintel" / "enriched_manifest.json"

ENRICHMENT_KEYS = [
    "actor_profile", "sector_tags", "exploit_status",
    "cwe_classification", "intel_quality"
]

# Minimum items to prevent empty dashboard
MIN_ITEMS = 5


def load_manifest(path: Path) -> list:
    """Load and normalise manifest into a flat list."""
    if not path.exists():
        print(f"[WARN] Manifest not found: {path}")
        return []
    with open(path, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    return data.get("items", data.get("entries", data.get("advisories", [])))


def merge_intelligence(feed: list, enriched: list) -> list:
    """Merge enriched v46 fields onto feed_manifest items."""
    enriched_lookup = {item.get("stix_id", ""): item for item in enriched}
    merged = []
    for item in feed:
        sid = item.get("stix_id", "")
        merged_item = dict(item)
        if sid in enriched_lookup:
            enc = enriched_lookup[sid]
            for key in ENRICHMENT_KEYS:
                if key in enc:
                    merged_item[key] = enc[key]
        merged.append(merged_item)
    return merged


def find_embedded_intel_boundaries(html: str) -> tuple:
    """Find the exact byte boundaries of the EMBEDDED_INTEL array using brace matching.
    
    Returns (array_start, array_end) where:
        html[array_start] == '['  (opening bracket)
        html[array_end - 1] == ']'  (closing bracket)
    
    The replacement zone is html[array_start:array_end].
    Everything before array_start and after array_end is UNTOUCHED.
    """
    # Step 1: Find the declaration
    marker = "const EMBEDDED_INTEL = ["
    pos = html.find(marker)
    if pos == -1:
        return -1, -1

    # Step 2: array_start is the '[' position
    array_start = pos + len("const EMBEDDED_INTEL = ")
    if array_start >= len(html) or html[array_start] != '[':
        return -1, -1

    # Step 3: Brace-match to find the closing ']'
    depth = 0
    i = array_start
    in_string = False
    escape = False

    while i < len(html):
        ch = html[i]

        if escape:
            escape = False
            i += 1
            continue

        if ch == '\\' and in_string:
            escape = True
            i += 1
            continue

        if ch == '"' and not escape:
            in_string = not in_string
            i += 1
            continue

        if not in_string:
            if ch == '[':
                depth += 1
            elif ch == ']':
                depth -= 1
                if depth == 0:
                    array_end = i + 1  # Include the ']'
                    return array_start, array_end

        i += 1

    return -1, -1


def compute_fingerprint(html: str, array_start: int, array_end: int) -> str:
    """Compute a fingerprint of everything OUTSIDE the EMBEDDED_INTEL array.
    Used to verify that only the array data changed."""
    before = html[:array_start]
    after = html[array_end:]
    return str(hash(before + "|||BOUNDARY|||" + after))


def patch_index_html(merged: list) -> bool:
    """Surgically replace ONLY the EMBEDDED_INTEL array data in index.html."""
    if not INDEX_HTML.exists():
        print("[ERROR] index.html not found")
        return False

    with open(INDEX_HTML, encoding="utf-8") as f:
        original_html = f.read()

    original_size = len(original_html)
    print(f"[INFO] Loaded index.html: {original_size:,} bytes")

    # ── Step 1: Find array boundaries ──
    array_start, array_end = find_embedded_intel_boundaries(original_html)
    if array_start == -1:
        print("[ERROR] EMBEDDED_INTEL array boundaries not found")
        print("[ERROR] Possible cause: missing declaration or corrupted file")
        return False

    old_array = original_html[array_start:array_end]
    print(f"[INFO] Found EMBEDDED_INTEL: [{array_start}:{array_end}] ({len(old_array):,} chars)")

    # ── Step 2: Compute fingerprint of everything OUTSIDE the array ──
    before_fingerprint = compute_fingerprint(original_html, array_start, array_end)

    # ── Step 3: Build new array data ──
    new_array = json.dumps(merged, separators=(",", ":"), ensure_ascii=False)

    # ── Step 4: Create backup ──
    backup_path = str(INDEX_HTML) + ".pre_intel_update"
    shutil.copy2(INDEX_HTML, backup_path)

    # ── Step 5: Surgical replacement — ONLY the array content ──
    patched_html = original_html[:array_start] + new_array + original_html[array_end:]

    # ══════════════════════════════════════════════════
    # POST-PATCH INTEGRITY CHECKS — all must pass
    # ══════════════════════════════════════════════════
    errors = []

    # Check 1: Fingerprint of surrounding code unchanged
    new_array_start, new_array_end = find_embedded_intel_boundaries(patched_html)
    if new_array_start == -1:
        errors.append("EMBEDDED_INTEL not found in patched output")
    else:
        after_fingerprint = compute_fingerprint(patched_html, new_array_start, new_array_end)
        if before_fingerprint != after_fingerprint:
            errors.append("Code outside EMBEDDED_INTEL was modified (fingerprint mismatch)")

    # Check 2: Exactly ONE EMBEDDED_INTEL declaration
    ei_count = patched_html.count("const EMBEDDED_INTEL")
    if ei_count != 1:
        errors.append(f"{ei_count} EMBEDDED_INTEL declarations (expected 1)")

    # Check 3: No git conflict markers
    for marker in ["<<<<<<<", ">>>>>>>"]:
        if marker in patched_html:
            errors.append(f"Git conflict marker '{marker}' found")

    # Check 4: EMBEDDED_INTEL parses as valid JSON
    if new_array_start != -1 and new_array_end != -1:
        try:
            check_data = json.loads(patched_html[new_array_start:new_array_end])
            if len(check_data) < MIN_ITEMS:
                errors.append(f"EMBEDDED_INTEL has {len(check_data)} items (min: {MIN_ITEMS})")
        except json.JSONDecodeError as e:
            errors.append(f"EMBEDDED_INTEL JSON parse error: {e}")

    # Check 5: Critical functions still exist
    for func_name in ["bootFromEmbeddedCache", "computeMetrics", "renderCards", "renderTopThreats"]:
        if f"function {func_name}" not in patched_html:
            errors.append(f"Function '{func_name}' missing after patch")

    # Check 6: Surrounding code size unchanged (data size may vary)
    original_surrounding = original_size - (array_end - array_start)
    patched_surrounding = len(patched_html) - (new_array_end - new_array_start) if new_array_start != -1 else 0
    if abs(original_surrounding - patched_surrounding) > 100:
        errors.append(f"Surrounding code size changed: {original_surrounding:,} → {patched_surrounding:,}")

    # ── Handle failures ──
    if errors:
        print("[FATAL] Post-patch integrity check FAILED:")
        for e in errors:
            print(f"  ✗ {e}")
        print("[ROLLBACK] Restoring original index.html from backup")
        shutil.copy2(backup_path, INDEX_HTML)
        os.remove(backup_path)
        return False

    # ── All checks passed — write the patched file ──
    with open(INDEX_HTML, "w", encoding="utf-8") as f:
        f.write(patched_html)

    # Clean up backup
    os.remove(backup_path)

    delta = len(patched_html) - original_size
    print(f"[OK] Check 1: Surrounding code fingerprint — UNCHANGED")
    print(f"[OK] Check 2: EMBEDDED_INTEL declarations — 1")
    print(f"[OK] Check 3: No conflict markers")
    print(f"[OK] Check 4: JSON valid — {len(merged)} items")
    print(f"[OK] Check 5: All critical functions preserved")
    print(f"[OK] Check 6: Surrounding code size — {len(patched_html) - (new_array_end - new_array_start):,} bytes (unchanged)")

    return True


def compute_kpis(merged: list) -> dict:
    """Compute summary KPIs for CI log output."""
    critical = sum(1 for i in merged if (i.get("risk_score") or 0) >= 9)
    high = sum(1 for i in merged if 7 <= (i.get("risk_score") or 0) < 9)
    kev = sum(1 for i in merged if i.get("kev_present"))
    enriched = sum(1 for i in merged if any(k in i for k in ENRICHMENT_KEYS))
    latest = max((i.get("timestamp", "") for i in merged), default="—")
    return {
        "total": len(merged), "critical": critical, "high": high,
        "kev": kev, "enriched": enriched, "latest": latest
    }


def main():
    print("=" * 60)
    print("CYBERDUDEBIVASH SENTINEL APEX — EMBEDDED_INTEL AUTO-UPDATER")
    print(f"Run: {datetime.now(timezone.utc).isoformat()}")
    print("=" * 60)

    feed = load_manifest(FEED_MANIFEST)
    enriched = load_manifest(ENRICHED_MANIFEST)

    if not feed:
        print("[ERROR] feed_manifest.json is empty or missing — aborting")
        sys.exit(1)

    print(f"[INFO] feed_manifest: {len(feed)} items")
    print(f"[INFO] enriched_manifest: {len(enriched)} items")

    merged = merge_intelligence(feed, enriched)
    kpis = compute_kpis(merged)

    print(
        f"[INFO] Merged: {kpis['total']} items | "
        f"CRITICAL:{kpis['critical']} HIGH:{kpis['high']} "
        f"KEV:{kpis['kev']} | Enriched:{kpis['enriched']} | "
        f"Latest: {kpis['latest']}"
    )

    success = patch_index_html(merged)
    if success:
        print("[SUCCESS] index.html EMBEDDED_INTEL patched ✓")
        print("[SUCCESS] All surrounding code preserved ✓")
    else:
        print("[ERROR] Patch failed — original file restored")
        sys.exit(1)

    print("=" * 60)


if __name__ == "__main__":
    main()
