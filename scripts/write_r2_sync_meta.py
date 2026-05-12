#!/usr/bin/env python3
"""
CYBERDUDEBIVASH SENTINEL APEX
write_r2_sync_meta.py — Generate R2 sync metadata JSON

Reads feed_manifest.json to count advisories, then writes
/tmp/r2_sync_meta.json for the calling shell to upload to R2.

Output: /tmp/r2_sync_meta.json
"""

import json
import os
import sys
import tempfile
from datetime import datetime, timezone
from pathlib import Path


MANIFEST_PATH = Path("data/stix/feed_manifest.json")
OUTPUT_PATH = Path("/tmp/r2_sync_meta.json")


def count_advisories() -> int:
    """Count advisories in the feed manifest."""
    try:
        if not MANIFEST_PATH.exists():
            print(f"[WARN] Manifest not found at {MANIFEST_PATH}, defaulting count=0")
            return 0
        with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
            data = json.load(f)
        if isinstance(data, list):
            return len(data)
        items = (
            data.get("advisories")
            or data.get("reports")
            or data.get("items")
            or []
        )
        return len(items)
    except Exception as e:
        print(f"[WARN] Could not count advisories: {e}", file=sys.stderr)
        return 0


def main():
    advisory_count = count_advisories()
    version = os.environ.get("PIPELINE_VERSION", "143.0.0")

    meta = {
        "synced_at": datetime.now(timezone.utc).isoformat(),
        "advisory_count": advisory_count,
        "source": "sentinel-blogger",
        "version": version,
    }

    # Atomic write to /tmp
    tmp_fd, tmp_path = tempfile.mkstemp(suffix=".json", dir="/tmp")
    try:
        with os.fdopen(tmp_fd, "w", encoding="utf-8") as f:
            json.dump(meta, f, indent=2)
        os.replace(tmp_path, OUTPUT_PATH)
    except Exception:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass
        raise

    print(f"[META] Sync metadata written: {advisory_count} advisories, version={version}")
    print(f"[META] Output: {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
