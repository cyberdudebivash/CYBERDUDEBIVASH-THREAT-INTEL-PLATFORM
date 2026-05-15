#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/snapshot_integration.py
CYBERDUDEBIVASH® SENTINEL APEX v144.0.0 — Pipeline Snapshot Integration
========================================================================
Called by run_pipeline.py (Stage 3.95) after feed.json is finalised.

Responsibilities:
  1. Load the freshly-written api/feed.json (source of truth from pipeline)
  2. Create an immutable timestamped snapshot via SnapshotManager
  3. Update data/snapshots/current.json pointer
  4. Prune old snapshots (keep last 50)
  5. Write data/snapshots/snapshot_meta.json for dashboard / API
  6. Non-fatal: if snapshot fails, pipeline continues (data is in feed.json)

Usage (run_pipeline.py):
    from scripts.snapshot_integration import create_pipeline_snapshot
    create_pipeline_snapshot()          # call after stage_sync_root_feed_json()

Standalone:
    python3 scripts/snapshot_integration.py
    python3 scripts/snapshot_integration.py --source data/stix/feed_manifest.json

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path

log = logging.getLogger("sentinel.snapshot_integration")

REPO_ROOT    = Path(__file__).resolve().parent.parent
API_FEED     = REPO_ROOT / "api" / "feed.json"
ROOT_FEED    = REPO_ROOT / "feed.json"
MANIFEST     = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
SNAP_META    = REPO_ROOT / "data" / "snapshots" / "snapshot_meta.json"

KEEP_SNAPSHOTS = 50


def _load_feed(path: Path):
    """Load JSON from path, return list of items."""
    if not path.exists():
        return None, f"not found: {path}"
    try:
        raw = path.read_bytes()
        data = json.loads(raw.decode("utf-8"))
        if isinstance(data, list):
            return data, None
        # unwrap envelope
        for key in ("items", "entries", "advisories", "data", "objects"):
            if key in data and isinstance(data[key], list):
                return data[key], None
        return None, f"unrecognised JSON shape in {path}"
    except Exception as e:
        return None, str(e)


def create_pipeline_snapshot(
    source_path: Path = None,
    run_id: str = None,
    skip_dedup: bool = False,
) -> bool:
    """
    Create an immutable snapshot from the current pipeline output.
    Returns True on success, False on non-fatal failure.
    """
    # Import here to allow standalone execution without full pipeline import chain
    try:
        sys.path.insert(0, str(REPO_ROOT / "scripts"))
        from snapshot_manager import SnapshotManager
    except ImportError as e:
        log.error("[snap-integration] Cannot import SnapshotManager: %s", e)
        return False

    # Source priority: api/feed.json → feed.json → manifest
    source = source_path
    if source is None:
        for candidate in [API_FEED, ROOT_FEED, MANIFEST]:
            if candidate.exists():
                source = candidate
                break

    if source is None:
        log.error("[snap-integration] No feed source found — skipping snapshot")
        return False

    log.info("[snap-integration] Loading feed from: %s", source)
    items, err = _load_feed(source)
    if err:
        log.error("[snap-integration] Feed load error: %s — skipping snapshot", err)
        return False

    if not items:
        log.warning("[snap-integration] Feed is empty — skipping snapshot")
        return False

    log.info("[snap-integration] Loaded %d items from %s", len(items), source.name)

    mgr = SnapshotManager()
    try:
        # Create immutable snapshot
        snap_path = mgr.create_snapshot(
            items,
            run_id=run_id or os.environ.get("GITHUB_RUN_ID", "local"),
            skip_dedup=skip_dedup,
        )
        # Update current pointer
        mgr.update_current_pointer(snap_path)
        # Prune old snapshots
        pruned = mgr.prune_old_snapshots(keep=KEEP_SNAPSHOTS)

        # Write metadata for dashboard / API health endpoint
        meta = {
            "snapshot_file":  snap_path.name,
            "snapshot_path":  str(snap_path),
            "created_at":     datetime.now(timezone.utc).isoformat(),
            "total_items":    len(items),
            "source_feed":    str(source.relative_to(REPO_ROOT)) if source.is_absolute() and REPO_ROOT in source.parents else str(source),
            "pipeline_run":   os.environ.get("GITHUB_RUN_ID", "local"),
            "pruned_count":   pruned,
            "schema_version": "v144.0",
        }
        SNAP_META.parent.mkdir(parents=True, exist_ok=True)
        tmp = SNAP_META.with_suffix(".tmp")
        tmp.write_text(json.dumps(meta, indent=2, ensure_ascii=False), encoding="utf-8")
        tmp.replace(SNAP_META)

        log.info("[snap-integration] Snapshot created: %s (%d items)",
                 snap_path.name, len(items))
        return True

    except Exception as e:
        log.error("[snap-integration] Snapshot creation failed (non-fatal): %s", e, exc_info=True)
        return False


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [snap-integration] %(levelname)s: %(message)s",
    )

    parser = argparse.ArgumentParser(description="SENTINEL APEX Snapshot Integration v144.0.0")
    parser.add_argument("--source", type=Path, default=None,
                        help="Override source feed path")
    parser.add_argument("--skip-dedup", action="store_true",
                        help="Skip deduplication (data already deduped)")
    parser.add_argument("--run-id", type=str, default=None)
    args = parser.parse_args()

    ok = create_pipeline_snapshot(
        source_path=args.source,
        run_id=args.run_id,
        skip_dedup=args.skip_dedup,
    )
    sys.exit(0 if ok else 1)
