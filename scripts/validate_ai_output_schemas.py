#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/validate_ai_output_schemas.py
# Extracted from generate-and-sync.yml Stage 6 (RULE 5 compliance)
# Validates all AI tracker output files against required schema contracts.
# Exit 0 = PASS | Exit 1 = HARD FAIL (schema violation)
# =============================================================================
import json
import sys
import os

REQUIRED_OUTPUTS = {
    "api/ai/tracker.json": {
        "required_keys": ["schema", "version", "generated_at", "engine_alpha", "engine_beta", "engine_gamma"],
        "min_size_bytes": 10000,
        "schema_prefix": "sentinel-apex-ai-tracker",
    },
    "api/ai/health.json": {
        "required_keys": ["schema", "generated_at", "overall_health", "health_score"],
        "min_size_bytes": 500,
        "schema_prefix": "sentinel-apex",
    },
    "api/ai/executive-brief.json": {
        "required_keys": ["schema", "generated_at", "boardroom_summary"],
        "min_size_bytes": 500,
        "schema_prefix": "sentinel-apex",
    },
}

all_ok = True
total_size = 0

for path, spec in REQUIRED_OUTPUTS.items():
    if not os.path.exists(path):
        print(f"[WARN] {path} not generated -- may be dry-run or first run")
        continue
    try:
        size = os.path.getsize(path)
        total_size += size
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        missing = [k for k in spec["required_keys"] if k not in data]
        if missing:
            print(f"[ERROR] {path}: missing keys {missing}")
            all_ok = False
            continue
        if size < spec["min_size_bytes"]:
            print(f"[WARN] {path}: suspicious size {size}B (min {spec['min_size_bytes']}B)")
        schema = data.get("schema", "")
        if not schema.startswith(spec["schema_prefix"]):
            print(f"[ERROR] {path}: schema mismatch -- got '{schema}'")
            all_ok = False
            continue
        print(f"[OK] {path}: {size / 1024:.1f}KB | schema={schema} | keys={list(data.keys())[:6]}")
    except json.JSONDecodeError as e:
        print(f"[ERROR] {path}: JSON decode error: {e}")
        all_ok = False
    except Exception as e:
        print(f"[ERROR] {path}: {e}")
        all_ok = False

print(f"\n[TELEMETRY] Total AI output size: {total_size / 1024:.1f}KB")

if not all_ok:
    print("\n[FATAL] Schema validation FAILED -- aborting deployment")
    sys.exit(1)
else:
    print("\n[OK] All AI outputs validated -- schema contract preserved")
