#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX
# scripts/validate_manifest_integrity.py
# Extracted from multi-source-intel.yml (RULE 5 compliance)
# Validates feed_manifest.json and feed_state.json for cross-run integrity.
# Exit 0 = OK | Exit 1 = HARD FAIL (manifest parse error)
# =============================================================================
import json
import sys
from pathlib import Path

manifest_path = Path("data/stix/feed_manifest.json")
state_path = Path("data/cache/feed_state.json")

# --- Manifest check ---
if not manifest_path.exists():
    print("[WARN] feed_manifest.json does not exist yet (first run?)")
else:
    try:
        data = json.loads(manifest_path.read_text(encoding="utf-8"))
        entries = data if isinstance(data, list) else []
        total = len(entries)
        with_pub = sum(1 for e in entries if e.get("published_at"))
        print(f"[MANIFEST] total={total}  with_published_at={with_pub}  missing={total - with_pub}")
        if total > 0 and with_pub == 0:
            print("[WARN] All entries missing published_at - ingestion may need a reset")
    except Exception as e:
        print(f"[ERROR] Manifest parse failed: {e}")
        sys.exit(1)

# --- Feed state check ---
if not state_path.exists():
    print("[WARN] feed_state.json does not exist - first run will do full scan")
else:
    try:
        state = json.loads(state_path.read_text(encoding="utf-8"))
        sources = state.get("sources", {})
        count = len(sources)
        print(f"[FEED-STATE] Tracking {count} source(s) with last_seen timestamps")
        if count == 0:
            print("[WARN] feed_count=0 - next run will be a full scan (expected on first run)")
    except Exception as e:
        print(f"[WARN] Feed state parse failed: {e}")

print("[VALIDATE] OK")
