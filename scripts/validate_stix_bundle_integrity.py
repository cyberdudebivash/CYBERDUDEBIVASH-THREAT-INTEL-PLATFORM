#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/validate_stix_bundle_integrity.py
# Extracted from enterprise-intel-quality.yml STIX Bundle Integrity Check (RULE 5)
# Spot-checks up to 20 STIX bundles for JSON corruption.
# Exit 0 = OK | Exit 1 = corrupt bundles found
# =============================================================================
import json
import sys
from pathlib import Path

stix_dir = Path("data/stix")
if not stix_dir.exists():
    print("[STIX] No STIX dir -- skip")
    sys.exit(0)

corrupt = 0
checked = 0
for f in list(stix_dir.glob("*.json"))[:20]:
    try:
        with open(f, encoding="utf-8") as fh:
            json.load(fh)
        checked += 1
    except json.JSONDecodeError:
        print(f"[STIX] CORRUPT: {f.name}")
        corrupt += 1

print(f"[STIX] Checked {checked} bundles, {corrupt} corrupt")
sys.exit(1 if corrupt > 0 else 0)
