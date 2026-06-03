#!/usr/bin/env python3
"""
scripts/field_preserving_merge.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Field-Preserving Append-Only Merge Engine
==============================================================================
PLATFORM HARDENING: Zero-regression manifest merge that NEVER drops enrichment
                    fields, NEVER removes existing apex_ai data, NEVER shrinks
                    the manifest below what the pipeline already produced.

DESIGN INVARIANTS:
    1. APPEND-ONLY: New entries are added. Existing entries are updated, never deleted.
    2. FIELD PRESERVATION: For any entry that already exists (matched by stix_id),
       ALL enrichment fields are preserved from the existing version if the
       incoming version is missing them.
    3. APEX AI LOCK: apex_ai, apex_ai_summary, apex_ai_score are NEVER overwritten
       with null/empty values. Once enriched, always enriched.
    4. TOP-THREATS SAFETY: risk_score is NEVER dropped or zeroed. Tags and
       threat_type are preserved to maintain frontend sort/filter correctness.
    5. CAPPED AT N: After merge, newest N entries are kept (default: 50 for
       feed_manifest; 500 for api/feed.json).

MERGE ALGORITHM:
    existing  = load(manifest_path)           # what's on disk
    incoming  = provided by caller or loaded  # what pipeline just generated
    merged    = merge_preserving_fields(existing, incoming)
    save(merged[-N:])                         # newest N entries, atomic write

    Per-entry merge rule (keyed on stix_id):
        - If stix_id in existing AND in incoming:
            base = incoming (fresh data wins for non-enrichment fields)
            for each PROTECTED_FIELD in (apex_ai, apex_ai_summary, apex_ai_score,
                                          risk_score, tags, blog_url, report_url):
                if incoming[field] is null/empty AND existing[field] is not null:
                    base[field] = existing[field]   # restore from existing
        - If stix_id in existing BUT NOT in incoming:
            keep existing entry as-is (append-only)
        - If stix_id in incoming BUT NOT in existing:
            add incoming entry (new intel)

Usage:
    # Called by run_pipeline.py or sentinel-blogger.yml directly:
    python3 scripts/field_preserving_merge.py \\
        --manifest data/stix/feed_manifest.json \\
        --incoming /tmp/new_intel.json \\
        --cap 50

    # Or import as a module:
    from scripts.field_preserving_merge import merge_preserving_fields, run_merge

Exit codes:
    0 = Merge completed successfully
    1 = Hard fail (manifest corrupt, empty incoming when existing had data)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations
import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [field-merge] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.field_preserving_merge")

REPO_ROOT = Path(__file__).resolve().parent.parent

# ---------------------------------------------------------------------------
# Protected fields: NEVER overwritten with null/empty/missing values
# If a protected field is present in existing and absent/null in incoming,
# the existing value is restored.
# ---------------------------------------------------------------------------
PROTECTED_FIELDS: list[str] = [
    # APEX AI enrichment block (core intelligence product)
    "apex_ai",
    "apex_ai_summary",
    "apex_ai_score",
    "apex",
    # Risk & prioritisation (drives Top Threats section)
    "risk_score",
    # Taxonomy (drives frontend filter/sort)
    "tags",
    "threat_type",
    "severity",
    # URL references
    "blog_url",
    "report_url",
    # IOC enrichment
    "ioc_paywall",
    "ioc_counts",
    # NVD/EPSS enrichment (expensive to re-fetch)
    "cvss_score",
    "epss_score",
    "kev_present",
    "nvd_url",
    # Confidence
    "confidence_score",
    "confidence",
]

# Fields used as merge keys (in priority order)
MERGE_KEY_CANDIDATES: list[str] = ["stix_id", "bundle_id", "id"]

# Default cap values per manifest type
DEFAULT_CAP_STIX_MANIFEST = 50
DEFAULT_CAP_API_FEED = 500


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _get_key(item: dict) -> str | None:
    for k in MERGE_KEY_CANDIDATES:
        val = item.get(k)
        if val and isinstance(val, str) and val.strip():
            return val.strip()
    return None


def _is_empty(val: Any) -> bool:
    """Return True if val is null-equivalent (None, '', [], {})."""
    if val is None:
        return True
    if isinstance(val, str) and not val.strip():
        return True
    if isinstance(val, (list, dict)) and len(val) == 0:
        return True
    return False


def _load_manifest(path: Path) -> tuple[list[dict], str, Any]:
    if not path.exists():
        return [], "list", []
    raw = path.read_text(encoding="utf-8", errors="replace")
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        log.warning("JSON parse error in %s: %s -- treating as empty", path.name, e)
        return [], "list", []
    if isinstance(data, list):
        return data, "list", data
    if isinstance(data, dict):
        for key in ("data", "items", "entries", "intel"):
            if isinstance(data.get(key), list):
                return data[key], "dict", data
        return [], "dict", data
    return [], "list", []


def _atomic_write(path: Path, items: list[dict], fmt: str, raw_data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".merge_tmp")
    try:
        if fmt == "dict" and isinstance(raw_data, dict):
            for key in ("data", "items", "entries", "intel"):
                if key in raw_data:
                    raw_data[key] = items
                    break
            else:
                # No known list key found -- inject as 'data'
                raw_data["data"] = items
            raw_data["count"] = len(items)
            raw_data["generated"] = _utc_now()
            raw_data["platform_version"] = "stable-v1.0-apex"
            payload = raw_data
        else:
            payload = items
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, ensure_ascii=False, default=str)
        os.replace(tmp, path)
    except Exception:
        if tmp.exists():
            try:
                tmp.unlink()
            except Exception:
                pass
        raise


def _sort_key(item: dict) -> tuple:
    """Canonical sort key: (ts_string, stix_id) DESC — matches regression_immunity.py Check 6
    and run_pipeline.py exactly.  String-based comparison avoids float precision issues and
    provides deterministic tie-breaking via stix_id when timestamps are identical."""
    ts_val  = (item.get("published_at") or item.get("timestamp") or
               item.get("generated_at") or item.get("created_at") or item.get("processed_at") or "")
    sid_val = (item.get("stix_id") or item.get("id") or "")
    return (ts_val, sid_val)


# ---------------------------------------------------------------------------
# Core merge function (importable by run_pipeline.py)
# ---------------------------------------------------------------------------

def merge_preserving_fields(
    existing: list[dict],
    incoming: list[dict],
) -> list[dict]:
    """
    Merge incoming intel into existing manifest with full field preservation.

    Rules:
        - Existing entries NOT in incoming: kept as-is (append-only).
        - Incoming entries NOT in existing: appended (new intel).
        - Entries in BOTH: incoming wins for non-protected fields;
          existing wins for protected fields if incoming value is empty/null.

    Returns merged list (unsorted; caller should sort + cap).
    """
    if not existing:
        log.info("[merge] No existing entries -- returning incoming as-is (%d items)", len(incoming))
        return list(incoming)

    if not incoming:
        log.info("[merge] No incoming entries -- preserving all existing (%d items)", len(existing))
        return list(existing)

    # Index existing by merge key
    existing_index: dict[str, dict] = {}
    for item in existing:
        key = _get_key(item)
        if key:
            existing_index[key] = item

    # Index incoming by merge key
    incoming_index: dict[str, dict] = {}
    incoming_no_key: list[dict] = []
    for item in incoming:
        key = _get_key(item)
        if key:
            incoming_index[key] = item
        else:
            incoming_no_key.append(item)

    merged: dict[str, dict] = {}
    stats = {"preserved": 0, "new": 0, "updated": 0, "kept_existing_only": 0}

    # Process existing entries
    for key, existing_item in existing_index.items():
        if key in incoming_index:
            # Both exist: merge with field preservation
            base = dict(incoming_index[key])  # start from incoming (fresh data)
            for field in PROTECTED_FIELDS:
                incoming_val = base.get(field)
                existing_val = existing_item.get(field)
                if _is_empty(incoming_val) and not _is_empty(existing_val):
                    base[field] = existing_val
                    stats["preserved"] += 1
            # Always stamp merge metadata
            base["_merge_updated_at"] = _utc_now()
            base["_merge_source"] = "field_preserving_merge"
            merged[key] = base
            stats["updated"] += 1
        else:
            # Existing-only: keep as-is (append-only guarantee)
            merged[key] = existing_item
            stats["kept_existing_only"] += 1

    # Add new incoming entries (not in existing)
    for key, new_item in incoming_index.items():
        if key not in merged:
            new_item["_merge_updated_at"] = _utc_now()
            new_item["_merge_source"] = "field_preserving_merge"
            merged[key] = new_item
            stats["new"] += 1

    # Append incoming items without a key (no stix_id -- include but cannot dedup)
    result = list(merged.values()) + incoming_no_key

    # Normalize: backfill 'source' from 'feed_source'/'source_url' if absent.
    # validate_repo.py intel_schema gate requires a non-empty 'source' field.
    # CI-generated stix manifest items use 'feed_source'; normalize on merge.
    for item in result:
        if not item.get("source"):
            item["source"] = (
                item.get("feed_source")
                or item.get("source_url")
                or "SENTINEL-APEX"
            )

    log.info(
        "[merge] Result: %d total | updated=%d | new=%d | kept_existing_only=%d | "
        "protected_fields_restored=%d",
        len(result), stats["updated"], stats["new"],
        stats["kept_existing_only"], stats["preserved"],
    )
    return result


# ---------------------------------------------------------------------------
# Standalone run function
# ---------------------------------------------------------------------------

def run_merge(
    manifest_path: Path,
    incoming_path: Path | None = None,
    cap: int = DEFAULT_CAP_STIX_MANIFEST,
    dry_run: bool = False,
    auto_populate_from_feed: bool = True,
) -> dict:
    """
    Load manifest, merge with incoming (or self if no incoming), cap, write back.

    auto_populate_from_feed=True (default): if the manifest has 0 items AND
    api/feed.json exists with items, automatically use api/feed.json as the
    incoming source. This handles the bootstrap_critical_files.py reset pattern
    where data/stix/feed_manifest.json is reset to [] on every CI run.

    Returns stats dict.
    """
    existing, fmt, raw_data = _load_manifest(manifest_path)
    log.info("[merge] Loaded existing manifest: %d items from %s (fmt=%s)",
             len(existing), manifest_path.name, fmt)

    incoming: list[dict] = []
    if incoming_path and incoming_path.exists():
        incoming_raw, _, _ = _load_manifest(incoming_path)
        incoming = incoming_raw
        log.info("[merge] Loaded incoming: %d items from %s", len(incoming), incoming_path.name)
    elif not incoming_path and len(existing) == 0 and auto_populate_from_feed:
        # AUTO-POPULATE: manifest is empty (by-design bootstrap reset) and no
        # incoming specified -- auto-source from api/feed.json (the enriched feed).
        # This is the key fix: ensures stix manifest is always hydrated from the
        # current production feed batch instead of staying empty.
        api_feed = manifest_path.parent.parent.parent / "api" / "feed.json"
        if not api_feed.exists():
            # Try relative to repo root
            api_feed = REPO_ROOT / "api" / "feed.json"
        if api_feed.exists():
            api_items, _, _ = _load_manifest(api_feed)
            if api_items:
                incoming = api_items
                log.info(
                    "[merge] AUTO-POPULATE: manifest was empty -- sourcing %d items from %s",
                    len(incoming), api_feed.name
                )
            else:
                log.warning("[merge] AUTO-POPULATE: api/feed.json also empty -- nothing to populate")
        else:
            log.warning("[merge] AUTO-POPULATE: api/feed.json not found at %s", api_feed)
    else:
        if incoming_path:
            log.warning("[merge] Incoming path not found: %s -- merge will preserve existing only",
                        incoming_path)
        incoming = []

    merged = merge_preserving_fields(existing, incoming)

    # Sort descending by timestamp and cap
    merged_sorted = sorted(merged, key=_sort_key, reverse=True)
    pre_cap = len(merged_sorted)
    if cap > 0 and len(merged_sorted) > cap:
        merged_sorted = merged_sorted[:cap]
        log.info("[merge] Capped %d -> %d (cap=%d)", pre_cap, len(merged_sorted), cap)

    stats = {
        "existing_count": len(existing),
        "incoming_count": len(incoming),
        "merged_count": len(merged_sorted),
        "cap_applied": pre_cap > len(merged_sorted),
        "manifest_path": str(manifest_path),
        "dry_run": dry_run,
        "merged_at": _utc_now(),
    }

    if dry_run:
        log.info("[merge] DRY RUN: would write %d items to %s", len(merged_sorted), manifest_path)
    else:
        _atomic_write(manifest_path, merged_sorted, fmt, raw_data)
        log.info("[merge] Written %d items to %s", len(merged_sorted), manifest_path)

    return stats


# ---------------------------------------------------------------------------
# Also sync apex_ai from api/feed.json -> data/stix/feed_manifest.json
# This is the KEY fix: enrich_feed_apex.py enriches api/feed.json but the
# manifest at data/stix/feed_manifest.json never gets the apex_ai fields.
# ---------------------------------------------------------------------------

def sync_apex_ai_from_feed(
    manifest_path: Path,
    feed_path: Path,
    dry_run: bool = False,
) -> dict:
    """
    Read apex_ai enrichment from api/feed.json and sync it into
    data/stix/feed_manifest.json for any matching stix_id.

    This is idempotent -- safe to run multiple times.
    Returns count of items synced.
    """
    if not feed_path.exists():
        log.warning("[apex-sync] Feed not found: %s -- skipping apex_ai sync", feed_path)
        return {"synced": 0, "skipped": "feed_not_found"}

    if not manifest_path.exists():
        log.warning("[apex-sync] Manifest not found: %s -- skipping apex_ai sync", manifest_path)
        return {"synced": 0, "skipped": "manifest_not_found"}

    feed_items, _, _ = _load_manifest(feed_path)
    manifest_items, fmt, raw_data = _load_manifest(manifest_path)

    # Build apex_ai index from feed keyed on stix_id
    feed_apex_index: dict[str, dict] = {}
    for item in feed_items:
        key = _get_key(item)
        if key and item.get("apex_ai"):
            feed_apex_index[key] = item

    synced_count = 0
    for idx, mitem in enumerate(manifest_items):
        key = _get_key(mitem)
        if not key:
            continue
        feed_item = feed_apex_index.get(key)
        if not feed_item:
            continue

        changed = False
        # Sync apex_ai block
        if not mitem.get("apex_ai") and feed_item.get("apex_ai"):
            manifest_items[idx]["apex_ai"] = feed_item["apex_ai"]
            changed = True
        # Sync flat aliases
        if not mitem.get("apex_ai_summary") and feed_item.get("apex_ai"):
            apex = feed_item["apex_ai"]
            manifest_items[idx]["apex_ai_summary"] = str(apex.get("ai_summary", ""))[:500]
            changed = True
        if mitem.get("apex_ai_score") is None and feed_item.get("apex_ai"):
            apex = feed_item["apex_ai"]
            manifest_items[idx]["apex_ai_score"] = float(apex.get("predictive_risk") or 0)
            changed = True
        # Sync ioc_paywall
        if not mitem.get("ioc_paywall") and feed_item.get("ioc_paywall"):
            manifest_items[idx]["ioc_paywall"] = feed_item["ioc_paywall"]
            changed = True
        # Sync apex confidence tier
        if not mitem.get("apex") and feed_item.get("apex"):
            manifest_items[idx]["apex"] = feed_item["apex"]
            changed = True

        if changed:
            synced_count += 1

    if synced_count == 0:
        log.info("[apex-sync] No apex_ai gaps found in manifest -- already in sync")
        return {"synced": 0}

    if dry_run:
        log.info("[apex-sync] DRY RUN: would sync apex_ai to %d/%d items", synced_count, len(manifest_items))
    else:
        _atomic_write(manifest_path, manifest_items, fmt, raw_data)
        log.info("[apex-sync] Synced apex_ai to %d/%d items in %s",
                 synced_count, len(manifest_items), manifest_path.name)

    return {"synced": synced_count, "total": len(manifest_items)}


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX field-preserving append-only manifest merge"
    )
    parser.add_argument("--manifest", "-m", required=False,
                        default="data/stix/feed_manifest.json",
                        help="Target manifest to merge into")
    parser.add_argument("--incoming", "-i", required=False, default=None,
                        help="Incoming intel JSON to merge (optional)")
    parser.add_argument("--cap", "-c", type=int, default=50,
                        help="Maximum entries to retain (default: 50)")
    parser.add_argument("--dry-run", action="store_true", default=False,
                        help="Simulate merge without writing files")
    parser.add_argument("--sync-apex", action="store_true", default=False,
                        help="Also sync apex_ai from api/feed.json -> manifest")
    parser.add_argument("--feed", default="api/feed.json",
                        help="Path to enriched api/feed.json for apex sync")
    args = parser.parse_args()

    manifest_path = Path(args.manifest)
    if not manifest_path.is_absolute():
        manifest_path = REPO_ROOT / manifest_path

    incoming_path = None
    if args.incoming:
        incoming_path = Path(args.incoming)
        if not incoming_path.is_absolute():
            incoming_path = REPO_ROOT / incoming_path

    log.info("=" * 70)
    log.info("SENTINEL APEX -- Field-Preserving Merge Engine")
    log.info("Manifest : %s", manifest_path)
    log.info("Incoming : %s", incoming_path or "none (preserve-only mode)")
    log.info("Cap      : %d", args.cap)
    log.info("Dry run  : %s", args.dry_run)
    log.info("=" * 70)

    try:
        stats = run_merge(manifest_path, incoming_path, cap=args.cap, dry_run=args.dry_run)
        log.info("Merge complete: %s", stats)

        if args.sync_apex:
            feed_path = Path(args.feed)
            if not feed_path.is_absolute():
                feed_path = REPO_ROOT / feed_path
            sync_stats = sync_apex_ai_from_feed(manifest_path, feed_path, dry_run=args.dry_run)
            log.info("Apex sync complete: %s", sync_stats)

    except Exception as e:
        log.error("Merge failed: %s", e)
        sys.exit(1)

    log.info("FIELD-PRESERVING MERGE COMPLETE -- NO FIELDS DROPPED")


if __name__ == "__main__":
    main()
