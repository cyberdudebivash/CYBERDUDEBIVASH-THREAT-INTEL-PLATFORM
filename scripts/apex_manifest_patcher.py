#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX v23.0 — APEX Manifest Patcher
=============================================================
Backfills the "apex" field into existing feed_manifest.json entries
using the pre-built apex_index.json produced by apex_wrapper.

MANDATE:
  - ZERO DATA LOSS — never remove existing manifest fields
  - BACKWARD COMPAT — entries without apex still render correctly
  - IDEMPOTENT — safe to run multiple times
  - NON-BLOCKING — any error silently skips, never crashes pipeline

INVOKED: Stage 6b of sentinel-blogger.yml, after apex_wrapper run.
"""
import json
import logging
import os
import sys
import time
from pathlib import Path

logging.basicConfig(level=logging.INFO, format="%(asctime)s [APEX-PATCHER] %(message)s")
logger = logging.getLogger("APEX-PATCHER")

BASE_DIR        = Path(__file__).resolve().parent.parent
MANIFEST_PATH   = BASE_DIR / "data" / "stix" / "feed_manifest.json"
APEX_INDEX_PATH = BASE_DIR / "data" / "apex_enrichments" / "apex_index.json"


def _compact_apex(apex_raw: dict) -> dict:
    """Build the compact apex field written into manifest entries."""
    return {
        "predictive_score":   round(float(apex_raw.get("composite_score", 0.0)), 2),
        "campaign_id":        str(apex_raw.get("campaign_id", "")),
        "threat_category":    str(apex_raw.get("threat_category", "UNKNOWN")),
        "confidence":         round(float(apex_raw.get("priority_score", 0.0)), 2),
        "priority":           str(apex_raw.get("priority", "P4")),
        "threat_level":       str(apex_raw.get("threat_level", "UNKNOWN")),
        "behavioral_tags":    list(apex_raw.get("behavioral_tags", []))[:5],
        "ai_summary":         str(apex_raw.get("ai_summary", ""))[:300],
        "recommended_action": str(apex_raw.get("recommended_action", ""))[:150],
    }


def patch_manifest() -> dict:
    """
    Load apex_index.json and manifest, backfill apex field by stix_id match.
    Returns: {"patched": int, "total": int, "skipped": int}
    """
    if not APEX_INDEX_PATH.exists():
        logger.warning(f"apex_index.json not found at {APEX_INDEX_PATH} — skipping patch")
        return {"patched": 0, "total": 0, "skipped": 0}

    if not MANIFEST_PATH.exists():
        logger.warning(f"feed_manifest.json not found — skipping patch")
        return {"patched": 0, "total": 0, "skipped": 0}

    # Load apex index
    with open(APEX_INDEX_PATH, encoding="utf-8") as f:
        apex_index: dict = json.load(f)
    logger.info(f"Loaded apex_index: {len(apex_index)} enriched advisories")

    # Load manifest
    with open(MANIFEST_PATH, encoding="utf-8") as f:
        manifest: list = json.load(f)

    if not isinstance(manifest, list):
        logger.warning("Manifest is not a list — skipping patch")
        return {"patched": 0, "total": 0, "skipped": 0}

    patched = 0
    skipped = 0

    for entry in manifest:
        stix_id = entry.get("stix_id", "")
        if not stix_id:
            skipped += 1
            continue

        apex_raw = apex_index.get(stix_id)
        if not apex_raw:
            skipped += 1
            continue

        # Only overwrite if no apex yet OR enriched_at changed (fresh data wins)
        existing_apex = entry.get("apex")
        if existing_apex and existing_apex.get("predictive_score", 0) > 0:
            skipped += 1
            continue

        try:
            entry["apex"] = _compact_apex(apex_raw)
            patched += 1
        except Exception as e:
            logger.debug(f"Skip {stix_id[:30]}: {e}")
            skipped += 1

    logger.info(f"Manifest patch: {patched} enriched, {skipped} skipped, {len(manifest)} total")

    if patched == 0:
        logger.info("No new entries to patch — manifest already current")
        return {"patched": 0, "total": len(manifest), "skipped": skipped}

    # Atomic write via temp file
    tmp_path = str(MANIFEST_PATH) + ".apex_patch.tmp"
    raw = json.dumps(manifest, indent=2, default=str, ensure_ascii=False)
    with open(tmp_path, "wb") as f:
        f.write(raw.encode("utf-8"))
    os.replace(tmp_path, MANIFEST_PATH)
    logger.info(f"[APEX-PATCHER] Manifest updated: {patched} entries enriched with APEX data")

    return {"patched": patched, "total": len(manifest), "skipped": skipped}


if __name__ == "__main__":
    t0 = time.time()
    result = patch_manifest()
    elapsed = round(time.time() - t0, 2)
    print(f"[APEX-PATCHER] COMPLETE | patched={result['patched']} | "
          f"total={result['total']} | skipped={result['skipped']} | {elapsed}s")
    sys.exit(0)
