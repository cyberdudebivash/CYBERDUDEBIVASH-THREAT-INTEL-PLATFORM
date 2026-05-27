#!/usr/bin/env python3
"""
scripts/cve_id_backfill.py
CYBERDUDEBIVASH(R) SENTINEL APEX — CVE ID Backfill Engine v1.0.0
=================================================================
ROOT CAUSE FIX (P1.3 / P1.4 / P1.5):
  All items in api/feed.json and data/feed_manifest.json have cve_id=None
  even when the item title contains "CVE-XXXX-XXXXX". This means:
    - enrich_cvss_epss_batch.py cannot look up CVSS/EPSS (needs cve_id)
    - kev_feed_marker.py finds 0 KEV matches (checks cve_id field)
    - EPSS enrichment skips all items (cve_id null)

  This script runs BEFORE Stage 3.1.2 (CVSS/EPSS) and Stage 3.1.3 (KEV)
  to pre-populate cve_id so all downstream enrichment works correctly.

WHAT THIS SCRIPT DOES:
  1. Reads api/feed.json
  2. Reads data/feed_manifest.json
  3. Reads data/stix/feed_manifest.json (if present)
  4. For each item, regex-extracts the first CVE ID from:
       - title
       - description
       - source_url
       - stix_id (e.g. vulnerability--CVE-2024-1234)
  5. Writes item["cve_id"] = "CVE-XXXX-XXXXX" ONLY if currently null/empty
  6. Also writes item["cve_ids"] = [list] for multi-CVE items
  7. Saves atomically (tmp → rename) to all modified files
  8. Prints a summary of how many items were backfilled

IDEMPOTENT: Items that already have cve_id are never overwritten.

USAGE:
  python3 scripts/cve_id_backfill.py
  DRY_RUN=true python3 scripts/cve_id_backfill.py
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] CVE-BACKFILL %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("cve-backfill")

# ── Config ─────────────────────────────────────────────────────────────────────
REPO          = Path(__file__).resolve().parent.parent
DRY_RUN       = os.environ.get("DRY_RUN", "false").strip().lower() == "true"

TARGET_FILES  = [
    REPO / "api"  / "feed.json",
    REPO / "data" / "feed_manifest.json",
    REPO / "data" / "stix" / "feed_manifest.json",
]

# CVE regex — matches CVE-YYYY-NNNNN (4+ digit suffix per CVE spec)
CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


# ── Extraction ─────────────────────────────────────────────────────────────────

def extract_cve_ids(item: Dict[str, Any]) -> List[str]:
    """Return all unique CVE IDs found in an item's searchable fields."""
    found: list[str] = []
    for field in ("title", "description", "summary", "source_url", "stix_id",
                  "ai_summary", "executive_summary", "raw_title"):
        val = item.get(field)
        if not val or not isinstance(val, str):
            continue
        for m in CVE_RE.finditer(val):
            cve = m.group(0).upper()
            if cve not in found:
                found.append(cve)
    # Also check nested raw dict
    raw = item.get("raw")
    if isinstance(raw, dict):
        for field in ("title", "description", "summary"):
            val = raw.get(field)
            if val and isinstance(val, str):
                for m in CVE_RE.finditer(val):
                    cve = m.group(0).upper()
                    if cve not in found:
                        found.append(cve)
    return found


# ── File helpers ───────────────────────────────────────────────────────────────

def load_json(path: Path) -> Optional[Any]:
    if not path.exists():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.warning("Failed to load %s: %s", path, exc)
        return None


def save_json_atomic(path: Path, data: Any) -> None:
    """Write JSON to a temp file then atomically rename."""
    if DRY_RUN:
        log.info("[DRY_RUN] Would write %s", path)
        return
    tmp = path.with_suffix(".tmp_backfill")
    try:
        tmp.write_text(json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(path)
        log.info("Saved: %s", path)
    except Exception as exc:
        log.error("Failed to save %s: %s", path, exc)
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


# ── Core backfill ──────────────────────────────────────────────────────────────

def backfill_items(items: List[Dict[str, Any]], source_label: str) -> int:
    """
    Mutate items in-place: populate cve_id and cve_ids where null/empty.
    Returns the count of items that were modified.
    """
    modified = 0
    for item in items:
        if not isinstance(item, dict):
            continue

        existing_cve_id  = item.get("cve_id")
        existing_cve_ids = item.get("cve_ids") or []

        # Extract from searchable text fields
        found_ids = extract_cve_ids(item)

        if not found_ids:
            continue  # No CVE mentioned anywhere — skip

        primary_cve = found_ids[0]

        changed = False

        # Backfill primary cve_id (never overwrite an existing non-null value)
        if not existing_cve_id:
            item["cve_id"] = primary_cve
            changed = True
            log.info("[%s] backfill cve_id=%s  title=%s",
                     source_label, primary_cve,
                     str(item.get("title", ""))[:80])

        # Backfill cve_ids list (merge without duplicates)
        merged_ids = list(existing_cve_ids)
        for cve in found_ids:
            if cve not in merged_ids:
                merged_ids.append(cve)
        if merged_ids != existing_cve_ids:
            item["cve_ids"] = merged_ids
            changed = True

        if changed:
            modified += 1

    return modified


def process_file(path: Path) -> int:
    """Load, backfill, and save one JSON file. Returns items modified count."""
    data = load_json(path)
    if data is None:
        return 0  # File doesn't exist — skip silently

    # Handle both list-of-items and dict-with-items-key formats
    if isinstance(data, list):
        items = data
        modified = backfill_items(items, path.name)
        if modified > 0:
            save_json_atomic(path, data)
        return modified

    if isinstance(data, dict):
        # Try common wrapper keys — skip empty lists so we don't stop at "items": []
        # when the real data is in "advisories" or another key.
        for key in ("items", "advisories", "feed", "data", "vulnerabilities"):
            if key in data and isinstance(data[key], list) and len(data[key]) > 0:
                modified = backfill_items(data[key], path.name)
                if modified > 0:
                    save_json_atomic(path, data)
                return modified
        # Fallback: treat top-level dict values as a collection
        log.warning("Unrecognised JSON structure in %s — skipping", path)
        return 0

    log.warning("Unexpected JSON type %s in %s — skipping", type(data).__name__, path)
    return 0


# ── Main ───────────────────────────────────────────────────────────────────────

def main() -> int:
    log.info("CVE ID Backfill Engine v1.0.0 — DRY_RUN=%s", DRY_RUN)

    total_modified = 0
    total_files    = 0

    for path in TARGET_FILES:
        if not path.exists():
            log.info("Skipping (not found): %s", path)
            continue
        total_files += 1
        n = process_file(path)
        log.info("%-45s  backfilled=%d", path.name, n)
        total_modified += n

    log.info("=" * 60)
    log.info("CVE backfill complete: %d item(s) updated across %d file(s)",
             total_modified, total_files)

    if total_modified == 0:
        log.info("All items already have cve_id populated — no changes needed.")
    else:
        log.info("Downstream enrichment (CVSS/EPSS/KEV) will now have cve_id "
                 "available for all backfilled items.")

    return 0


if __name__ == "__main__":
    sys.exit(main())
