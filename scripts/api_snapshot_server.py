#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/api_snapshot_server.py
CYBERDUDEBIVASH® SENTINEL APEX v184.0 — API Snapshot Reader
==============================================================
ARCHITECTURE: API reads ONLY from current snapshot — NO sorting,
NO dedup, NO mutation. The snapshot is the single source of truth.

Implements Phase 3 of the Permanent Production Transformation Protocol:
  ✔ Read ONLY from data/snapshots/current.json → snapshot file
  ✔ NO sorting (already sorted in snapshot)
  ✔ NO mutation (immutable snapshot)
  ✔ NO dedup (already deduped in snapshot)
  ✔ Consistent ordering (deterministic from snapshot)
  ✔ Version header sync (from config/version.json)
  ✔ No caching conflicts (snapshot is the cache)

This module is imported by:
  - Cloudflare Worker (via KV population step)
  - api/main.py (FastAPI / Railway deployment)
  - GitHub Pages static feed generation

Phase 5 (encoding sanitization) is baked into the snapshot itself,
so no re-sanitization is needed here. Raw pass-through only.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("sentinel.api_snapshot_server")

REPO_ROOT   = Path(__file__).resolve().parent.parent
SNAP_DIR    = REPO_ROOT / "data" / "snapshots"
CURRENT_PTR = SNAP_DIR / "current.json"
VERSION_CFG = REPO_ROOT / "config" / "version.json"
SNAP_META   = SNAP_DIR / "snapshot_meta.json"


def _load_json(path: Path) -> Tuple[Optional[Any], Optional[str]]:
    if not path.exists():
        return None, f"not found: {path}"
    try:
        return json.loads(path.read_bytes().decode("utf-8")), None
    except Exception as e:
        return None, str(e)


def _get_version() -> str:
    cfg, _ = _load_json(VERSION_CFG)
    if cfg:
        return cfg.get("platform", cfg.get("version", "184.0"))
    return "184.0"


def _resolve_snapshot_path() -> Tuple[Optional[Path], Optional[str]]:
    """Resolve current snapshot file from current.json pointer."""
    ptr, err = _load_json(CURRENT_PTR)
    if err:
        return None, f"current.json: {err}"
    snap_file = ptr.get("snapshot_file") or ""
    snap_path_str = ptr.get("snapshot_path") or ""

    # Try absolute path first
    snap_path = Path(snap_path_str)
    if snap_path.exists():
        return snap_path, None

    # Try relative to snapshot dir
    snap_path = SNAP_DIR / snap_file
    if snap_path.exists():
        return snap_path, None

    return None, f"snapshot not found: {snap_file}"


class SnapshotAPIServer:
    """
    Serves intelligence data ONLY from the current immutable snapshot.
    No sorting. No dedup. No mutation. Pure pass-through.
    """

    def __init__(self):
        self._cache: Optional[Dict] = None
        self._cache_snapshot_file: Optional[str] = None

    def _load_snapshot(self, force_reload: bool = False) -> Tuple[Optional[Dict], Optional[str]]:
        """
        Load (and cache) the current snapshot.
        Reloads if the current.json pointer changed.
        """
        ptr, err = _load_json(CURRENT_PTR)
        if err:
            return None, err
        current_file = ptr.get("snapshot_file", "")

        if not force_reload and self._cache and self._cache_snapshot_file == current_file:
            return self._cache, None

        snap_path, err = _resolve_snapshot_path()
        if err:
            return None, err

        data, err = _load_json(snap_path)
        if err:
            return None, err

        self._cache = data
        self._cache_snapshot_file = current_file
        log.info("[api-snapshot] Loaded snapshot: %s (%d items)",
                 snap_path.name, data.get("total_items", len(data.get("items", []))))
        return data, None

    # ── Public API ──────────────────────────────────────────────────────────

    def get_feed(
        self,
        limit: int = 500,
        offset: int = 0,
        severity: Optional[str] = None,
        min_risk: Optional[float] = None,
    ) -> Dict:
        """
        Return paginated items from the snapshot.
        NO sorting (snapshot is already sorted DESC).
        NO dedup (snapshot is already deduped).
        Filtering is read-only (no mutations).
        """
        data, err = self._load_snapshot()
        if err:
            return self._error(f"snapshot unavailable: {err}")

        items: List[Dict] = data.get("items", [])

        # Read-only filters (no mutation)
        if severity:
            sev_upper = severity.upper()
            items = [i for i in items
                     if (i.get("severity") or i.get("risk_level") or "").upper() == sev_upper]
        if min_risk is not None:
            items = [i for i in items
                     if float(i.get("risk_score") or 0) >= min_risk]

        total_filtered = len(items)
        page = items[offset: offset + limit]

        return {
            "status":        "ok",
            "version":       _get_version(),
            "snapshot_id":   data.get("snapshot_id", ""),
            "snapshot_at":   data.get("created_at", ""),
            "total_in_feed": data.get("total_items", 0),
            "total_filtered": total_filtered,
            "returned":      len(page),
            "offset":        offset,
            "limit":         limit,
            "items":         page,
            "served_at":     datetime.now(timezone.utc).isoformat(),
        }

    def get_preview(self, limit: int = 10) -> Dict:
        """Lightweight preview (10 items) for dashboard boot."""
        data, err = self._load_snapshot()
        if err:
            return self._error(f"snapshot unavailable: {err}")
        items = data.get("items", [])[:limit]
        return {
            "status":   "ok",
            "version":  _get_version(),
            "preview":  {
                "total_in_feed": data.get("total_items", 0),
                "generated_at":  data.get("created_at", ""),
                "snapshot_id":   data.get("snapshot_id", ""),
                "items":         items,
            },
        }

    def get_item(self, stix_id: str) -> Dict:
        """Fetch a single intel item by stix_id."""
        data, err = self._load_snapshot()
        if err:
            return self._error(f"snapshot unavailable: {err}")
        for item in data.get("items", []):
            if (item.get("stix_id") or item.get("id", "")) == stix_id:
                return {"status": "ok", "item": item}
        return self._error(f"not found: {stix_id}", code=404)

    def get_health(self) -> Dict:
        """Return snapshot health metadata."""
        ptr, err = _load_json(CURRENT_PTR)
        meta, _ = _load_json(SNAP_META)
        snap_path, snap_err = _resolve_snapshot_path()
        data = None
        if snap_path:
            data, _ = _load_json(snap_path)

        return {
            "status":         "ok" if not err and not snap_err else "degraded",
            "version":        _get_version(),
            "snapshot_file":  (ptr or {}).get("snapshot_file", "none"),
            "snapshot_at":    (ptr or {}).get("updated_at", ""),
            "total_items":    (data or {}).get("total_items", 0) if data else 0,
            "schema_version": (data or {}).get("schema_version", ""),
            "snapshot_error": snap_err,
            "served_at":      datetime.now(timezone.utc).isoformat(),
        }

    def build_static_feed_json(
        self,
        out_path: Path,
        limit: int = 500,
    ) -> bool:
        """
        Write a static api/feed.json from the current snapshot.
        Called by the pipeline after snapshot is created, so GitHub Pages
        and the Cloudflare Worker both serve from the same source.
        """
        data, err = self._load_snapshot()
        if err:
            log.error("[api-snapshot] Cannot build static feed: %s", err)
            return False

        items = data.get("items", [])[:limit]
        out_path.parent.mkdir(parents=True, exist_ok=True)
        tmp = out_path.with_suffix(".tmp")
        tmp.write_text(
            json.dumps(items, ensure_ascii=False, separators=(",", ":")),
            encoding="utf-8",
        )
        tmp.replace(out_path)
        log.info("[api-snapshot] Static feed written: %s (%d items)", out_path, len(items))
        return True

    @staticmethod
    def _error(msg: str, code: int = 500) -> Dict:
        return {"status": "error", "error": msg, "code": code}


# ---------------------------------------------------------------------------
# Module-level singleton
# ---------------------------------------------------------------------------
_server = SnapshotAPIServer()

def get_feed(**kwargs) -> Dict:         return _server.get_feed(**kwargs)
def get_preview(**kwargs) -> Dict:      return _server.get_preview(**kwargs)
def get_item(stix_id: str) -> Dict:     return _server.get_item(stix_id)
def get_health() -> Dict:               return _server.get_health()
def build_static_feed_json(out, lim=500): return _server.build_static_feed_json(out, lim)


# ---------------------------------------------------------------------------
# CLI / smoke test
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [api-snapshot] %(levelname)s: %(message)s",
    )
    parser = argparse.ArgumentParser(description="API Snapshot Server v184.0")
    parser.add_argument("cmd", choices=["health", "preview", "feed", "build-static"],
                        default="health", nargs="?")
    parser.add_argument("--limit", type=int, default=10)
    parser.add_argument("--out",   type=Path, default=None)
    args = parser.parse_args()

    if args.cmd == "health":
        print(json.dumps(get_health(), indent=2))
    elif args.cmd == "preview":
        print(json.dumps(get_preview(limit=args.limit), indent=2))
    elif args.cmd == "feed":
        result = get_feed(limit=args.limit)
        result["items"] = result["items"][:3]   # truncate for display
        print(json.dumps(result, indent=2))
    elif args.cmd == "build-static":
        out = args.out or (REPO_ROOT / "api" / "feed.json")
        ok = build_static_feed_json(out, limit=500)
        print("OK" if ok else "FAILED")
        sys.exit(0 if ok else 1)
