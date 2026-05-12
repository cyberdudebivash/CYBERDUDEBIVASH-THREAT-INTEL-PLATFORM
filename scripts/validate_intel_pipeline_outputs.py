#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/validate_intel_pipeline_outputs.py
# Extracted from enterprise-intel-quality.yml Validate Pipeline Outputs (RULE 5)
# Validates all expected output files from the intelligence quality pipeline.
# Exit 0 = VALID | Exit 1 = VALIDATION ERRORS
# =============================================================================
import json
import sys
from pathlib import Path

CHECKS = [
    ("data/intelligence/ioc_depth_recovery.json",           ["results"]),
    ("data/intelligence/attck_context_results.json",        ["results"]),
    ("data/intelligence/explainable_confidence_scores.json", ["results"]),
    ("data/threat_memory/ioc_memory.json",                  ["ioc_entries"]),
]

errors = []

for rel, required_keys in CHECKS:
    p = Path(rel)
    if not p.exists():
        print(f"[VALIDATE] OPTIONAL file not present: {rel}")
        continue
    try:
        with open(p, encoding="utf-8") as f:
            data = json.load(f)
        for k in required_keys:
            if k not in data:
                errors.append(f"{rel}: missing key '{k}'")
    except json.JSONDecodeError as e:
        errors.append(f"{rel}: corrupt JSON: {e}")

# Manifest must still be valid after pipeline
mp = Path("data/stix/feed_manifest.json")
if mp.exists():
    try:
        with open(mp, encoding="utf-8") as f:
            json.load(f)
        print("[VALIDATE] feed_manifest.json: VALID")
    except json.JSONDecodeError:
        errors.append("feed_manifest.json: CORRUPT -- critical failure")

if errors:
    print(f"[VALIDATE] Validation ERRORS: {errors}")
    sys.exit(1)

print("[VALIDATE] All outputs VALID")
sys.exit(0)
