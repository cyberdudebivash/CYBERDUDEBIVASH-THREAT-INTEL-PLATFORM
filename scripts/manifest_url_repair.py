#!/usr/bin/env python3
"""
scripts/manifest_url_repair.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Manifest URL Repair v1.0.0
Stage 5.9.1 (P1-004)

Syncs report_url from api/feed.json into feed_manifest.json entries
that are missing it. Non-blocking: always exits 0.
"""
from __future__ import annotations
import json
import os
import sys
from pathlib import Path

REPO     = Path(os.environ.get("GITHUB_WORKSPACE", Path(__file__).resolve().parent.parent))
MANIFEST = REPO / "data" / "stix" / "feed_manifest.json"
FEED     = REPO / "api" / "feed.json"


def main() -> int:
    print("[5.9.1] === Manifest URL Repair (P1-004) ===", flush=True)

    if not MANIFEST.exists():
        print("[5.9.1] feed_manifest.json not found -- skipping", flush=True)
        return 0

    # Build report_url lookup from api/feed.json (source of truth)
    url_map: dict = {}
    if FEED.exists():
        try:
            raw_feed = json.loads(FEED.read_text(encoding="utf-8"))
            items = (raw_feed if isinstance(raw_feed, list)
                     else raw_feed.get("advisories", raw_feed.get("items", [])))
            for item in items:
                for key in ("stix_id", "id"):
                    v = item.get(key, "")
                    if v and item.get("report_url"):
                        url_map[v] = item["report_url"]
        except Exception as e:
            print(f"[5.9.1] WARN: cannot parse api/feed.json: {e}", flush=True)

    print(f"[5.9.1] report_url lookup built: {len(url_map)} entries", flush=True)

    # Load manifest
    try:
        raw_m = json.loads(MANIFEST.read_text(encoding="utf-8"))
    except Exception as e:
        print(f"[5.9.1] ERROR: cannot parse feed_manifest.json: {e}", flush=True)
        return 0  # non-blocking

    m_list = (raw_m if isinstance(raw_m, list)
              else raw_m.get("advisories", raw_m.get("items", [])))

    # Repair missing report_url entries
    repaired = 0
    for item in m_list:
        if not item.get("report_url"):
            for key in ("stix_id", "id"):
                v = item.get(key, "")
                if v and url_map.get(v):
                    item["report_url"] = url_map[v]
                    repaired += 1
                    break

    print(f"[5.9.1] Repaired report_url on {repaired} manifest items", flush=True)

    if repaired == 0:
        print("[5.9.1] COMPLETE -- no repairs needed", flush=True)
        return 0

    # Atomic write: tmp-replace pattern
    tmp = MANIFEST.with_suffix(".tmp591")
    try:
        if isinstance(raw_m, list):
            out = m_list
        else:
            # Rebuild dict preserving all non-list keys
            out = {k: v for k, v in raw_m.items() if not isinstance(v, list)}
            # Find the original list key
            list_key = next(
                (k for k in ("advisories", "items", "data") if k in raw_m), "advisories"
            )
            out[list_key] = m_list

        tmp.write_text(
            json.dumps(out, ensure_ascii=False, indent=2),
            encoding="utf-8"
        )
        tmp.replace(MANIFEST)
        print("[5.9.1] COMPLETE -- manifest written", flush=True)
    except Exception as e:
        print(f"[5.9.1] ERROR writing manifest: {e}", flush=True)
        if tmp.exists():
            tmp.unlink(missing_ok=True)

    return 0


if __name__ == "__main__":
    sys.exit(main())
