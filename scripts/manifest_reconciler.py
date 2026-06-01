#!/usr/bin/env python3
"""
scripts/manifest_reconciler.py
CYBERDUDEBIVASH® SENTINEL APEX -- Manifest Reconciler v1.0.0
=============================================================================
P0 ARCHITECTURAL FIX: Eliminate genuine_regression in Stage 3.91 permanently.

PROBLEM (forensic root cause):
  api/feed.json and data/stix/feed_manifest.json are generated independently
  by different pipeline stages. Any stage that adds items to api/feed.json
  without also updating feed_manifest.json causes Stage 3.91 HARD FAIL with
  missing_reason=genuine_regression.

  This is an architectural anti-pattern: two sources of truth that drift.

SOLUTION:
  Run this reconciler as a mandatory stage BEFORE Stage 3.91.
  It is the single authoritative sync point:
    api/feed.json (source of truth) → feed_manifest.json (derived artifact)

GUARANTEES:
  - All items in api/feed.json are present in feed_manifest.json at validation
  - Idempotent: safe to run multiple times (dedup by stix_id + id)
  - Atomic write: uses tmp-replace pattern, never partial state
  - Non-destructive: only ADDS items, never removes existing manifest entries
  - Zero external dependencies: pure stdlib

EXIT CODES:
  0 -- reconciliation succeeded (0 or more items synced)
  1 -- hard error (file corruption, unreadable JSON)

USAGE:
  python3 scripts/manifest_reconciler.py
  python3 scripts/manifest_reconciler.py --dry-run
  python3 scripts/manifest_reconciler.py --report data/health/reconciler_report.json
"""
from __future__ import annotations

import argparse
import json
import os
import sys
import hashlib
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT     = Path(__file__).resolve().parent.parent
FEED_PATH     = REPO_ROOT / "api" / "feed.json"
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"
SCRIPT_VER    = "1.0.0"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _sha16(path: Path) -> str:
    """16-char SHA256 hex of file contents."""
    try:
        h = hashlib.sha256(path.read_bytes()).hexdigest()
        return h[:16]
    except Exception:
        return "unknown"


def _load_json(path: Path, label: str):
    """Load JSON file. Returns parsed object or raises SystemExit on hard error."""
    if not path.exists():
        print(f"[RECONCILER] WARN: {label} not found at {path} -- skipping", flush=True)
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as e:
        print(f"[RECONCILER] ERROR: {label} is corrupt JSON: {e}", flush=True)
        sys.exit(1)


def _unwrap(raw, label: str) -> list:
    """Extract list of items from raw JSON (handles list or dict-wrapped formats)."""
    if isinstance(raw, list):
        return raw
    if isinstance(raw, dict):
        for key in ("advisories", "items", "data", "intel"):
            if isinstance(raw.get(key), list):
                return raw[key]
    print(f"[RECONCILER] WARN: {label} has unrecognized structure -- treating as empty", flush=True)
    return []


def _item_keys(item: dict) -> list[str]:
    """Return all ID keys for an item (stix_id, id). Filters empty strings."""
    keys = []
    for field in ("stix_id", "id"):
        v = item.get(field, "")
        if v and isinstance(v, str):
            keys.append(v)
    return keys


def _atomic_write(path: Path, data) -> None:
    """Write JSON atomically via tmp-replace. Binary mode avoids NTFS null-pad corruption."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp_reconcile")
    encoded = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
    try:
        with open(tmp, "wb") as fh:
            fh.write(encoded)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except Exception as e:
        print(f"[RECONCILER] ERROR: atomic write failed: {e}", flush=True)
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        sys.exit(1)


def reconcile(dry_run: bool = False) -> dict:
    """
    Core reconciliation logic.
    Returns a report dict with counts and outcome.
    """
    print("[RECONCILER] =" * 35, flush=True)
    print(f"[RECONCILER] SENTINEL APEX Manifest Reconciler v{SCRIPT_VER}", flush=True)
    print(f"[RECONCILER] Mode: {'DRY-RUN' if dry_run else 'LIVE'}", flush=True)
    print("[RECONCILER] =" * 35, flush=True)

    # ── Load api/feed.json (source of truth) ──────────────────────────────────
    raw_feed = _load_json(FEED_PATH, "api/feed.json")
    if raw_feed is None:
        print("[RECONCILER] SKIP: api/feed.json missing -- nothing to reconcile", flush=True)
        return {"status": "skipped", "reason": "api_feed_missing"}

    feed_items = _unwrap(raw_feed, "api/feed.json")
    print(f"[RECONCILER] api/feed.json: {len(feed_items)} items | sha={_sha16(FEED_PATH)}", flush=True)

    # ── Load feed_manifest.json ────────────────────────────────────────────────
    raw_manifest = _load_json(MANIFEST_PATH, "feed_manifest.json")
    if raw_manifest is None:
        # Manifest doesn't exist yet — bootstrap from feed
        print("[RECONCILER] feed_manifest.json not found -- bootstrapping from api/feed.json", flush=True)
        manifest_items: list = []
        raw_manifest = []
    else:
        manifest_items = _unwrap(raw_manifest, "feed_manifest.json")

    print(f"[RECONCILER] feed_manifest.json: {len(manifest_items)} items", flush=True)

    # ── Build manifest ID set (dual-field lookup: stix_id + id) ───────────────
    manifest_id_set: set[str] = set()
    for item in manifest_items:
        for k in _item_keys(item):
            manifest_id_set.add(k)

    # ── Compute delta: api items missing from manifest ─────────────────────────
    missing: list[dict] = []
    missing_ids: list[str] = []
    for item in feed_items:
        keys = _item_keys(item)
        if not any(k in manifest_id_set for k in keys):
            missing.append(item)
            missing_ids.append(keys[0] if keys else "(no-id)")

    print(f"[RECONCILER] Delta (api - manifest): {len(missing)} items need sync", flush=True)

    if not missing:
        print("[RECONCILER] ✅ Manifest is fully reconciled -- no action needed", flush=True)
        return {
            "status": "clean",
            "api_count": len(feed_items),
            "manifest_count": len(manifest_items),
            "synced": 0,
            "reconciled_at": _now(),
            "script_version": SCRIPT_VER,
        }

    # ── Report missing items ───────────────────────────────────────────────────
    print(f"[RECONCILER] Items to sync ({min(len(missing), 10)} shown):", flush=True)
    for item_id in missing_ids[:10]:
        print(f"[RECONCILER]   + {item_id}", flush=True)
    if len(missing) > 10:
        print(f"[RECONCILER]   ... and {len(missing) - 10} more", flush=True)

    if dry_run:
        print(f"[RECONCILER] DRY-RUN: would sync {len(missing)} items -- no files written", flush=True)
        return {
            "status": "dry_run",
            "api_count": len(feed_items),
            "manifest_count": len(manifest_items),
            "would_sync": len(missing),
            "would_sync_ids": missing_ids,
            "reconciled_at": _now(),
            "script_version": SCRIPT_VER,
        }

    # ── Append missing items to manifest ──────────────────────────────────────
    updated_manifest = manifest_items + missing
    # Register new IDs to avoid re-adding within the same run
    for item in missing:
        for k in _item_keys(item):
            manifest_id_set.add(k)

    # Preserve original wrapper structure if dict
    if isinstance(raw_manifest, dict):
        # Find which key holds the items list
        items_key = "advisories"
        for key in ("advisories", "items", "data", "intel"):
            if isinstance(raw_manifest.get(key), list):
                items_key = key
                break
        out_manifest = {**raw_manifest, items_key: updated_manifest}
    else:
        out_manifest = updated_manifest

    _atomic_write(MANIFEST_PATH, out_manifest)
    new_sha = _sha16(MANIFEST_PATH)
    print(f"[RECONCILER] ✅ Synced {len(missing)} items into feed_manifest.json", flush=True)
    print(f"[RECONCILER]    manifest now: {len(updated_manifest)} items | sha={new_sha}", flush=True)

    return {
        "status": "synced",
        "api_count": len(feed_items),
        "manifest_count_before": len(manifest_items),
        "manifest_count_after": len(updated_manifest),
        "synced": len(missing),
        "synced_ids": missing_ids,
        "manifest_sha_after": new_sha,
        "reconciled_at": _now(),
        "script_version": SCRIPT_VER,
    }


def main() -> int:
    ap = argparse.ArgumentParser(
        description="SENTINEL APEX Manifest Reconciler -- sync api/feed.json → feed_manifest.json"
    )
    ap.add_argument("--dry-run", action="store_true",
                    help="Report delta without writing any files")
    ap.add_argument("--report", metavar="PATH",
                    help="Write JSON reconciliation report to PATH")
    args = ap.parse_args()

    report = reconcile(dry_run=args.dry_run)

    if args.report:
        report_path = Path(args.report)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(report, indent=2, ensure_ascii=False),
            encoding="utf-8"
        )
        print(f"[RECONCILER] Report written: {report_path}", flush=True)

    print(f"[RECONCILER] Status: {report.get('status', 'unknown').upper()}", flush=True)
    # Always exit 0 -- reconciler never blocks the pipeline
    return 0


if __name__ == "__main__":
    sys.exit(main())
