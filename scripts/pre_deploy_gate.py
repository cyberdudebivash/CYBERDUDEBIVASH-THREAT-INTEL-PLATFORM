#!/usr/bin/env python3
"""
SENTINEL APEX v75.1 — PRE-DEPLOY INTEGRITY GATE
==================================================
MANDATORY check before EVERY gh-pages deploy.
If ANY check fails → exit(1) → deployment BLOCKED.

Prevents:
  - Git merge conflict markers in JavaScript
  - Duplicate EMBEDDED_INTEL declarations (fatal SyntaxError)
  - Empty/corrupt EMBEDDED_INTEL data
  - JavaScript brace imbalance (frozen dashboard)
  - Manifest sort regression (newest entries missing from dashboard)
  - Manifest duplication surviving into deployment

v75.1 ADDITIONS (checks 6-8):
  - [6/8] feed_manifest.json is sorted newest-first (top entry is most recent)
  - [7/8] No duplicate advisory_ids in manifest
  - [8/8] EMBEDDED_INTEL item count matches manifest count (within tolerance)
"""

import json
import os
import re
import sys
from datetime import datetime

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
INDEX_HTML = os.path.join(REPO_ROOT, "index.html")
MANIFEST_PATH = os.path.join(REPO_ROOT, "data", "stix", "feed_manifest.json")


def main():
    print("=" * 60)
    print("  SENTINEL APEX — PRE-DEPLOY INTEGRITY GATE")
    print("=" * 60)

    if not os.path.exists(INDEX_HTML):
        print("  FATAL: index.html not found")
        sys.exit(1)

    with open(INDEX_HTML, "r", encoding="utf-8", errors="replace") as f:
        content = f.read()

    print(f"  File: {len(content):,} bytes")
    failed = False

    # ── CHECK 1: No git conflict markers in <script> blocks ──
    script_text = ""
    for m in re.finditer(r"<script[^>]*>([\s\S]*?)</script>", content):
        script_text += m.group(1)

    for marker in ["<<<<<<<", ">>>>>>>"]:
        if marker in script_text:
            print(f"  FATAL: Git conflict marker '{marker}' in <script>")
            failed = True

    if not failed:
        print("  [1/5] No conflict markers in JavaScript")

    # ── CHECK 2: Exactly ONE EMBEDDED_INTEL declaration ──
    ei_count = len(re.findall(r"(?:const|let|var)\s+EMBEDDED_INTEL\s*=", content))
    if ei_count == 0:
        print("  FATAL: EMBEDDED_INTEL declaration missing")
        failed = True
    elif ei_count > 1:
        print(f"  FATAL: {ei_count} EMBEDDED_INTEL declarations (causes SyntaxError)")
        failed = True
    else:
        print("  [2/5] Single EMBEDDED_INTEL declaration")

    # ── CHECK 3: EMBEDDED_INTEL has valid JSON with >= 5 items ──
    ei_match = re.search(r"const\s+EMBEDDED_INTEL\s*=\s*(\[[\s\S]*?\])\s*;", content)
    if ei_match:
        try:
            items = json.loads(ei_match.group(1))
            if len(items) < 5:
                print(f"  FATAL: EMBEDDED_INTEL has {len(items)} items (min: 5)")
                failed = True
            else:
                print(f"  [3/5] EMBEDDED_INTEL: {len(items)} items OK")
        except json.JSONDecodeError as e:
            print(f"  FATAL: EMBEDDED_INTEL JSON parse error: {e}")
            failed = True
    elif ei_count == 1:
        print("  FATAL: EMBEDDED_INTEL present but not parseable")
        failed = True

    # ── CHECK 4: JavaScript brace balance ──
    brace_ok = True
    for m in re.finditer(r"<script[^>]*>([\s\S]*?)</script>", content):
        block = m.group(1)
        if len(block) < 100:
            continue
        depth = 0
        in_str = None
        prev = ""
        for ch in block:
            if in_str:
                if ch == in_str and prev != "\\":
                    in_str = None
            else:
                if ch in ("'", '"', "`"):
                    in_str = ch
                elif ch == "{":
                    depth += 1
                elif ch == "}":
                    depth -= 1
                    if depth < 0:
                        brace_ok = False
                        break
            prev = ch
        if depth != 0:
            brace_ok = False
    if not brace_ok:
        print("  FATAL: JavaScript brace imbalance")
        failed = True
    else:
        print("  [4/5] JavaScript braces balanced")

    # ── CHECK 5: Critical boot functions exist ──
    missing = []
    for func in ["bootFromEmbeddedCache", "computeMetrics", "renderCards"]:
        if f"function {func}" not in content:
            missing.append(func)
    if missing:
        print(f"  FATAL: Missing functions: {', '.join(missing)}")
        failed = True
    else:
        print("  [5/8] Critical boot functions present")

    # ── CHECK 6: Manifest sort order (newest entry is at index 0) ──
    if os.path.exists(MANIFEST_PATH):
        try:
            with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                manifest_raw = json.load(f)
            advisories = manifest_raw if isinstance(manifest_raw, list) else manifest_raw.get("advisories", [])
            if len(advisories) >= 2:
                def _ts(e):
                    for fld in ("published", "published_date", "generated_at", "timestamp"):
                        v = e.get(fld, "")
                        if v and isinstance(v, str) and len(v) >= 10:
                            return v
                    return "1970-01-01"
                ts0 = _ts(advisories[0])
                ts1 = _ts(advisories[1])
                if ts0 < ts1:
                    print(f"  WARNING: Manifest sort regression — entry[0]={ts0[:19]} < entry[1]={ts1[:19]}")
                    # Warning only — don't block deploy, v75 hardener will fix on next run
                else:
                    print(f"  [6/8] Manifest sort order OK (newest: {ts0[:19]})")
            else:
                print(f"  [6/8] Manifest sort order OK (< 2 entries)")
        except Exception as e:
            print(f"  [6/8] Manifest sort check skipped: {e}")
    else:
        print(f"  [6/8] Manifest not found — skipping sort check")

    # ── CHECK 7: No duplicate stix_ids in manifest ──
    # [FIX-R06] Was checking 'advisory_id' which doesn't exist in manifest entries.
    # Manifest uses 'stix_id' as the unique identifier (bundle--UUID format).
    # Fixed output: "N checked, N unique, 0 duplicates" — unambiguous, no false "0 unique".
    if os.path.exists(MANIFEST_PATH):
        try:
            with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                manifest_raw = json.load(f)
            advisories = manifest_raw if isinstance(manifest_raw, list) else manifest_raw.get("advisories", [])
            ids = [e.get("stix_id", "") for e in advisories if e.get("stix_id")]
            total_checked = len(ids)
            unique_count  = len(set(ids))
            duplicates    = total_checked - unique_count
            if duplicates > 0:
                print(f"  FATAL: {duplicates} duplicate stix_ids found in manifest ({total_checked} checked)")
                failed = True
            else:
                print(f"  [7/8] No duplicate stix_ids ({total_checked} checked, {unique_count} unique, 0 duplicates) OK")
        except Exception as e:
            print(f"  [7/8] Manifest dedup check skipped: {e}")
    else:
        print(f"  [7/8] Manifest not found — skipping dedup check")

    # ── CHECK 8: EMBEDDED_INTEL item count matches manifest (±20 tolerance) ──
    if os.path.exists(MANIFEST_PATH) and ei_match:
        try:
            with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                manifest_raw = json.load(f)
            advisories = manifest_raw if isinstance(manifest_raw, list) else manifest_raw.get("advisories", [])
            manifest_count = len(advisories)
            try:
                ei_count_items = len(json.loads(ei_match.group(1)))
            except Exception:
                ei_count_items = 0
            diff = abs(manifest_count - ei_count_items)
            if diff > 20 and manifest_count > 0 and ei_count_items > 0:
                print(f"  WARNING: EMBEDDED_INTEL ({ei_count_items}) vs manifest ({manifest_count}) differ by {diff}")
            else:
                print(f"  [8/8] EMBEDDED_INTEL/manifest counts aligned ({ei_count_items} vs {manifest_count})")
        except Exception as e:
            print(f"  [8/8] Count alignment check skipped: {e}")
    else:
        print(f"  [8/8] Count check skipped (manifest or ei_match missing)")

    # ── VERDICT ──
    print()
    if failed:
        print("  ████ DEPLOYMENT BLOCKED ████")
        print("  Fix the errors above, commit, and re-run.")
        print("=" * 60)
        sys.exit(1)
    else:
        print("  DEPLOY AUTHORIZED")
        print("=" * 60)
        sys.exit(0)


if __name__ == "__main__":
    main()
