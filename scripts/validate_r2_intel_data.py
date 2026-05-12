#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/validate_r2_intel_data.py
# Extracted from r2-data-sync.yml (RULE 5 compliance)
# Validates intel data manifest before R2 upload.
# Exit 0 = valid | Exit 1 = invalid/missing manifest
# =============================================================================
import json
import sys
import os

manifest = "data/stix/feed_manifest.json"
if not os.path.exists(manifest):
    print(f"ERROR: {manifest} not found")
    sys.exit(1)

try:
    with open(manifest, encoding="utf-8") as f:
        data = json.load(f)
except Exception as e:
    print(f"ERROR: Could not parse {manifest}: {e}")
    sys.exit(1)

# Support both {advisories:[...]} and {reports:[...]} formats
items = (
    data.get("advisories")
    or data.get("reports")
    or (data if isinstance(data, list) else [])
)
count = len(items)

if count < 10:
    print(f"ERROR: Only {count} items in manifest -- refusing to upload stale/empty data to R2")
    sys.exit(1)

print(f"[R2-VALIDATE] Manifest OK: {count} items ready for R2 upload")
sys.exit(0)
