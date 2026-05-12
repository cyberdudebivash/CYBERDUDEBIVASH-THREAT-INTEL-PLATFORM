#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/validate_intel_pipeline_preflight.py
# Extracted from enterprise-intel-quality.yml Pre-Flight block (RULE 5)
# Validates feed_manifest.json exists and is parseable before pipeline.
# Exit 0 = OK | Exit 2 = CORRUPT manifest (pipeline must abort)
# =============================================================================
import json
import sys
from pathlib import Path

manifest_path = Path("data/stix/feed_manifest.json")
if not manifest_path.exists():
    print("[PRE-FLIGHT] No manifest found -- nothing to process")
    sys.exit(0)

try:
    with open(manifest_path, encoding="utf-8") as f:
        data = json.load(f)
except json.JSONDecodeError as e:
    print(f"[PRE-FLIGHT] CRITICAL: feed_manifest.json is corrupt: {e}")
    sys.exit(2)

if isinstance(data, list):
    advisories = data
elif isinstance(data, dict):
    advisories = data.get("items", data.get("advisories", data.get("bundles", [])))
else:
    advisories = []

print(f"[PRE-FLIGHT] Manifest valid ({type(data).__name__} format): {len(advisories)} entries")
sys.exit(0)
