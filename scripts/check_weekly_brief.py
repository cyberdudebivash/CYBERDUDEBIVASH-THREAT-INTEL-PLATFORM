#!/usr/bin/env python3
"""
scripts/verify_weekly_brief.py
CYBERDUDEBIVASH(R) SENTINEL APEX — Weekly Brief Verifier
=========================================================
Called from weekly-threat-brief.yml STEP 5.
Zero inline Python in YAML — this is the dedicated verifier script.
"""
import json
import sys
from pathlib import Path

REPO_ROOT   = Path(__file__).resolve().parent.parent
BRIEF_PATH  = REPO_ROOT / "api" / "v1" / "intel" / "weekly_brief.json"
HTML_PATH   = REPO_ROOT / "weekly-brief.html"

errors = []

# --- Verify JSON ---
if not BRIEF_PATH.exists():
    print(f"[FAIL] {BRIEF_PATH} not found")
    sys.exit(1)

try:
    with open(BRIEF_PATH, encoding="utf-8") as f:
        b = json.load(f)
except Exception as e:
    print(f"[FAIL] Cannot parse weekly_brief.json: {e}")
    sys.exit(1)

week        = b.get("week", "UNKNOWN")
period      = b.get("period", "UNKNOWN")
stats       = b.get("stats", {})
total       = stats.get("total_advisories", 0)
critical    = stats.get("critical_count", 0)
kev         = stats.get("kev_additions", 0)
sigma_count = stats.get("sigma_rules_available", 0)
top_threats = b.get("top_threats", [])
top_title   = top_threats[0].get("title", "N/A")[:70] if top_threats else "N/A"

print(f"  Week        : {week}")
print(f"  Period      : {period}")
print(f"  Advisories  : {total}")
print(f"  Critical    : {critical}")
print(f"  KEV         : {kev}")
print(f"  Sigma Rules : {sigma_count}")
print(f"  Top Threat  : {top_title}...")

if total == 0:
    errors.append("total_advisories is 0 — brief has no data")
if not week or week == "UNKNOWN":
    errors.append("week field missing")
if not top_threats:
    errors.append("top_threats list is empty")

# --- Verify HTML ---
if not HTML_PATH.exists():
    errors.append("weekly-brief.html not found")
else:
    size = HTML_PATH.stat().st_size
    if size < 1000:
        errors.append(f"weekly-brief.html too small: {size} bytes")
    else:
        print(f"  HTML size   : {size} bytes")

if errors:
    for e in errors:
        print(f"[FAIL] {e}")
    sys.exit(1)

print("[PASS] Weekly brief verified — JSON valid, HTML present, all fields populated")
