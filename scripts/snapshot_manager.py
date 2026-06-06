#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
scripts/snapshot_manager.py
CYBERDUDEBIVASH® SENTINEL APEX v144.0.0 - Immutable Snapshot System
====================================================================
ARCHITECTURE: SINGLE WRITER → IMMUTABLE DATA → READ-ONLY API → DUMB UI

Implements Phase 1+2 of the Permanent Production Transformation Protocol:

  Phase 1 - Immutable Snapshot System
    • Each pipeline run creates a NEW timestamped snapshot
    • NEVER overwrites a previous snapshot
    • Snapshot = deduplicated + sorted (published_at DESC) + clean UTF-8
    • data/snapshots/current.json → pointer to latest snapshot path

  Phase 2 - Pipeline Hardening
    • Atomic writes only: write → temp → validate → replace
    • Dedup: unique stix_id + hash(title+source+published_at) + ±6h window
    • Pipeline is the ONLY writer in the system

Usage (from run_pipeline.py):
    from scripts.snapshot_manager import SnapshotManager
    mgr = SnapshotManager()
    path = mgr.create_snapshot(items)          # creates timestamped snapshot
    mgr.update_current_pointer(path)           # atomically updates current.json
    latest = mgr.load_current()                # reads from current snapshot
    mgr.prune_old_snapshots(keep=50)           # retain last N snapshots

Standalone (post-pipeline validation):
    python3 scripts/snapshot_manager.py --validate
    python3 scripts/snapshot_manager.py --prune --keep 50

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("sentinel.snapshot_manager")
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [snapshot] %(levelname)s: %(message)s",
    stream=sys.stderr,
)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
REPO_ROOT      = Path(__file__).resolve().parent.parent
SNAPSHOT_DIR   = REPO_ROOT / "data" / "snapshots"
CURRENT_PTR    = SNAPSHOT_DIR / "current.json"
MAX_SNAPSHOTS  = 50          # prune to this many
MIN_ITEMS      = 1           # reject snapshot if fewer entries
DEDUP_WINDOW_H = 6           # ±6 h window for time-window dedup

MOJIBAKE_MAP = {
    "â": "-",   # â€" → en-dash
    "â": "-",   # â€" → em-dash
    "â": "'",   # â€™ → right single quote
    "â": """,   # â€œ → left double quote
    "â": """,   # â€ → right double quote
    "â¢": "•",   # â€¢ → bullet
    "Ã©": "é",          # Ã© → é
    "Ã¨": "è",          # Ã¨ → è
}

# Byte-level mojibake patterns that indicate double-encoded UTF-8
MOJIBAKE_BYTES = [
    (b"\xc3\xa2\xc2\x80\xc2\x93", "-"),
    (b"\xc3\xa2\xc2\x80\xc2\x94", "-"),
    (b"\xc3\xa2\xc2\x80\xc2\x99", "'"),
    (b"\xc3\xa2\xc2\x80\xc2\x9c", """),
    (b"\xc3\xa2\xc2\x80\xc2\x9d", """),
]


# ---------------------------------------------------------------------------
# Encoding sanitization
# ---------------------------------------------------------------------------
def sanitize_string(s: str) -> str:
    """Fix mojibake sequences in a string value."""
    if not isinstance(s, str):
        return s
    for bad, good in MOJIBAKE_MAP.items():
        s = s.replace(bad, good)
    return s


def sanitize_item(item: Any) -> Any:
    """Recursively sanitize all string values in a dict/list."""
    if isinstance(item, dict):
        return {k: sanitize_item(v) for k, v in item.items()}
    if isinstance(item, list):
        return [sanitize_item(v) for v in item]
    if isinstance(item, str):
        return sanitize_string(item)
    return item


def sanitize_bytes(raw: bytes) -> str:
    """Fix byte-level mojibake then decode as UTF-8."""
    for pattern, replacement in MOJIBAKE_BYTES:
        raw = raw.replace(pattern, replacement.encode("utf-8"))
    return raw.decode("utf-8", errors="replace")


# ---------------------------------------------------------------------------
# Dedup engine
# ---------------------------------------------------------------------------
def _ts_ms(item: Dict) -> int:
    """Return item timestamp as Unix milliseconds (0 if missing/unparseable)."""
    for field in ("published_at", "timestamp", "processed_at", "created"):
        v = item.get(field, "")
        if not v:
            continue
        try:
            if isinstance(v, (int, float)):
                return int(v * 1000) if v < 1e12 else int(v)
            dt = datetime.fromisoformat(str(v).replace("Z", "+00:00"))
            return int(dt.timestamp() * 1000)
        except Exception:
            pass
    return 0


def _dedup_primary_key(item: Dict) -> str:
    """Canonical dedup key: stix_id or hash(title+source+published_at)."""
    sid = item.get("stix_id") or item.get("id", "")
    if sid:
        return f"sid:{sid}"
    title  = (item.get("title") or "").strip().lower()
    source = (item.get("source") or item.get("feed_source") or "").strip().lower()
    pub    = (item.get("published_at") or item.get("timestamp") or "").strip()
    raw    = f"{title}|{source}|{pub}"
    return "h:" + hashlib.sha256(raw.encode()).hexdigest()


def _dedup_title_key(item: Dict) -> str:
    """Secondary dedup: normalised title (for ±6h window suppression)."""
    t = (item.get("title") or "").strip().lower()
    t = re.sub(r"\s+", " ", t)
    t = re.sub(r"[^a-z0-9 ]", "", t)
    return t[:120]


def deduplicate(items: List[Dict]) -> Tuple[List[Dict], int]:
    """
    Three-pass dedup:
      1. Primary key (stix_id / content-hash)
      2. Title + ±6h time window
    Returns (deduped_list, removed_count).
    """
    seen_primary: Dict[str, bool] = {}
    seen_title_ts: Dict[str, int]  = {}   # title_key → earliest ts_ms
    window_ms = DEDUP_WINDOW_H * 3600 * 1000
    out: List[Dict] = []
    removed = 0

    for item in items:
        pk = _dedup_primary_key(item)
        if pk in seen_primary:
            removed += 1
            continue
        seen_primary[pk] = True

        tk = _dedup_title_key(item)
        ts = _ts_ms(item)
        if tk and tk in seen_title_ts:
            existing_ts = seen_title_ts[tk]
            if ts and abs(ts - existing_ts) <= window_ms:
                removed += 1
                continue
        if tk:
            seen_title_ts[tk] = ts or seen_title_ts.get(tk, 0)

        out.append(item)

    return out, removed


# ---------------------------------------------------------------------------
# Sort
# ---------------------------------------------------------------------------
def sort_desc(items: List[Dict]) -> List[Dict]:
    """Sort by (published_at DESC, stix_id DESC) - deterministic."""
    def key(item):
        ts_val  = item.get("published_at") or item.get("timestamp") or item.get("processed_at") or ""
        sid_val = item.get("stix_id") or item.get("id") or ""
        return (ts_val, sid_val)

    return sorted(items, key=key, reverse=True)


# ---------------------------------------------------------------------------
# Atomic I/O
# ---------------------------------------------------------------------------
def _atomic_write_json(path: Path, data: Any, indent: int = 0) -> None:
    """Write JSON atomically: write → tmp → validate → rename."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    serialised = json.dumps(data, ensure_ascii=False, indent=indent or None,
                            separators=(None if indent else (",", ":")))
    # Validate before committing
    json.loads(serialised)
    tmp.write_text(serialised, encoding="utf-8")
    tmp.replace(path)


def _load_json_safe(path: Path) -> Tuple[Optional[Any], Optional[str]]:
    """Return (data, None) or (None, error_str)."""
    if not path.exists():
        return None, f"not found: {path}"
    try:
        raw = path.read_bytes()
        return json.loads(raw.decode("utf-8")), None
    except Exception as e:
        return None, str(e)


# ---------------------------------------------------------------------------
# SnapshotManager
# ---------------------------------------------------------------------------
class SnapshotManager:
    """
    Immutable snapshot system for SENTINEL APEX pipeline.

    Each pipeline run calls:
        path = mgr.create_snapshot(items)
        mgr.update_current_pointer(path)

    The API layer reads:
        latest = mgr.load_current()
    """

    def __init__(self, snapshot_dir: Optional[Path] = None):
        self.snapshot_dir = snapshot_dir or SNAPSHOT_DIR
        self.snapshot_dir.mkdir(parents=True, exist_ok=True)

    # ── Create ──────────────────────────────────────────────────────────────
    def create_snapshot(
        self,
        items: List[Dict],
        run_id: Optional[str] = None,
        skip_dedup: bool = False,
    ) -> Path:
        """
        Create a new immutable snapshot:
          1. Sanitize encoding
          2. Deduplicate (unless skip_dedup=True)
          3. Sort by published_at DESC
          4. Write atomically to data/snapshots/<ts>_<run_id>.json
          5. NEVER overwrites existing snapshots
        Returns path to the new snapshot.
        """
        now_utc = datetime.now(timezone.utc)
        ts_str  = now_utc.strftime("%Y%m%dT%H%M%SZ")
        run_tag = run_id or os.environ.get("GITHUB_RUN_ID", "local")
        fname   = f"{ts_str}_{run_tag}.json"
        path    = self.snapshot_dir / fname

        # Safety: never overwrite
        if path.exists():
            log.warning("[snapshot] File already exists - appending suffix: %s", path)
            path = path.with_name(path.stem + "_dup.json")

        log.info("[snapshot] Creating snapshot: %d raw items → %s", len(items), path.name)

        # Step 1: Encoding sanitization
        clean_items = [sanitize_item(i) for i in items]

        # Step 2: Dedup
        if not skip_dedup:
            deduped, removed = deduplicate(clean_items)
            log.info("[snapshot] Dedup: %d removed, %d remain", removed, len(deduped))
        else:
            deduped = clean_items

        # Step 3: Sort
        sorted_items = sort_desc(deduped)

        # Step 4: Build snapshot envelope
        snapshot = {
            "snapshot_id":   fname,
            "created_at":    now_utc.isoformat(),
            "pipeline_run":  run_tag,
            "total_items":   len(sorted_items),
            "schema_version": "v144.0",
            "dedup_removed": len(items) - len(deduped) if not skip_dedup else 0,
            "items":         sorted_items,
        }

        # Step 5: Validate item count
        if len(sorted_items) < MIN_ITEMS:
            raise ValueError(
                f"[snapshot] Refusing to write empty snapshot ({len(sorted_items)} items)"
            )

        # Step 6: Atomic write
        _atomic_write_json(path, snapshot)
        log.info("[snapshot] Written: %s (%d items, %.1f KB)",
                 path.name, len(sorted_items), path.stat().st_size / 1024)
        return path

    # ── Pointer ─────────────────────────────────────────────────────────────
    def update_current_pointer(self, snapshot_path: Path) -> None:
        """
        Atomically update data/snapshots/current.json to point at the
        latest snapshot. This is the SINGLE source of truth for the API.
        """
        rel = snapshot_path.relative_to(self.snapshot_dir)
        pointer = {
            "snapshot_file": str(rel),
            "snapshot_path": str(snapshot_path),
            "updated_at":    datetime.now(timezone.utc).isoformat(),
            "total_items":   self._peek_count(snapshot_path),
        }
        _atomic_write_json(CURRENT_PTR, pointer, indent=2)
        log.info("[snapshot] current.json → %s", rel)

    def _peek_count(self, path: Path) -> int:
        try:
            data = json.loads(path.read_bytes().decode("utf-8"))
            return data.get("total_items", len(data.get("items", [])))
        except Exception:
            return 0

    # ── Load ────────────────────────────────────────────────────────────────
    def load_current(self) -> Tuple[Optional[List[Dict]], Optional[str]]:
        """
        Load items from the current snapshot (as pointed to by current.json).
        Returns (items, None) or (None, error_str).
        API reads ONLY from here - NO sorting, NO mutation, NO dedup.
        """
        ptr, err = _load_json_safe(CURRENT_PTR)
        if err:
            return None, f"current.json: {err}"
        snap_path = Path(ptr.get("snapshot_path", ""))
        if not snap_path.exists():
            # Try relative path
            snap_path = self.snapshot_dir / ptr.get("snapshot_file", "")
        if not snap_path.exists():
            return None, f"snapshot not found: {snap_path}"
        data, err = _load_json_safe(snap_path)
        if err:
            return None, f"snapshot parse error: {err}"
        items = data.get("items", [])
        return items, None

    def load_current_envelope(self) -> Tuple[Optional[Dict], Optional[str]]:
        """Load the full snapshot envelope (metadata + items)."""
        ptr, err = _load_json_safe(CURRENT_PTR)
        if err:
            return None, err
        snap_path = Path(ptr.get("snapshot_path", ""))
        if not snap_path.exists():
            snap_path = self.snapshot_dir / ptr.get("snapshot_file", "")
        return _load_json_safe(snap_path)

    # ── Validation ──────────────────────────────────────────────────────────
    def validate_snapshot(self, path: Optional[Path] = None) -> Dict:
        """
        Validate a snapshot (or current) for integrity.
        Returns dict with keys: ok, path, total_items, issues.
        """
        if path is None:
            ptr, err = _load_json_safe(CURRENT_PTR)
            if err:
                return {"ok": False, "issues": [f"current.json: {err}"]}
            path = Path(ptr.get("snapshot_path", ""))
            if not path.exists():
                path = self.snapshot_dir / ptr.get("snapshot_file", "")

        issues = []
        if not path.exists():
            return {"ok": False, "path": str(path), "issues": ["file not found"]}

        try:
            raw = path.read_bytes()
            data = json.loads(raw.decode("utf-8"))
        except Exception as e:
            return {"ok": False, "path": str(path), "issues": [f"parse error: {e}"]}

        items = data.get("items", [])
        if len(items) < MIN_ITEMS:
            issues.append(f"too few items: {len(items)} < {MIN_ITEMS}")

        # Check for duplicate stix_ids
        seen: Dict[str, int] = {}
        for i, item in enumerate(items):
            sid = item.get("stix_id") or item.get("id", "")
            if sid:
                if sid in seen:
                    issues.append(f"duplicate stix_id at row {i}: {sid[:40]}")
                else:
                    seen[sid] = i

        # Check sort order
        out_of_order = 0
        for i in range(len(items) - 1):
            a = (items[i].get("published_at") or items[i].get("timestamp") or "")
            b = (items[i+1].get("published_at") or items[i+1].get("timestamp") or "")
            if a and b and a < b:
                out_of_order += 1
        if out_of_order > 0:
            issues.append(f"{out_of_order} out-of-order pairs (sort not DESC)")

        result = {
            "ok":          len(issues) == 0,
            "path":        str(path),
            "total_items": len(items),
            "schema_version": data.get("schema_version", "unknown"),
            "created_at":  data.get("created_at", "unknown"),
            "issues":      issues,
        }
        return result

    # ── Prune ───────────────────────────────────────────────────────────────
    def prune_old_snapshots(self, keep: int = MAX_SNAPSHOTS) -> int:
        """
        Delete oldest snapshots, keeping at most `keep` files.
        NEVER deletes the current snapshot.
        Returns number of files deleted.
        """
        ptr, _ = _load_json_safe(CURRENT_PTR)
        current_file = (ptr or {}).get("snapshot_file", "")

        snapshots = sorted(
            [f for f in self.snapshot_dir.glob("*.json") if f.name != "current.json"],
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        to_delete = snapshots[keep:]
        deleted = 0
        for f in to_delete:
            if f.name == current_file or str(f) == current_file:
                log.warning("[prune] Skipping current snapshot: %s", f.name)
                continue
            try:
                f.unlink()
                deleted += 1
                log.info("[prune] Deleted: %s", f.name)
            except Exception as e:
                log.warning("[prune] Could not delete %s: %s", f.name, e)
        log.info("[prune] Pruned %d old snapshots (kept %d)", deleted, min(len(snapshots), keep))
        return deleted

    # ── List ────────────────────────────────────────────────────────────────
    def list_snapshots(self) -> List[Dict]:
        """Return list of all snapshot metadata (newest first)."""
        files = sorted(
            [f for f in self.snapshot_dir.glob("*.json") if f.name != "current.json"],
            key=lambda f: f.stat().st_mtime,
            reverse=True,
        )
        result = []
        for f in files:
            try:
                data, _ = _load_json_safe(f)
                result.append({
                    "file":        f.name,
                    "created_at":  (data or {}).get("created_at", ""),
                    "total_items": (data or {}).get("total_items", 0),
                    "size_kb":     round(f.stat().st_size / 1024, 1),
                })
            except Exception:
                result.append({"file": f.name, "error": "unreadable"})
        return result


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _cli():
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Snapshot Manager v144.0.0"
    )
    sub = parser.add_subparsers(dest="cmd")

    sub.add_parser("validate",  help="Validate current snapshot")
    sub.add_parser("list",      help="List all snapshots")

    prune_p = sub.add_parser("prune", help="Prune old snapshots")
    prune_p.add_argument("--keep", type=int, default=MAX_SNAPSHOTS)

    sub.add_parser("pointer", help="Show current.json pointer")

    args = parser.parse_args()

    mgr = SnapshotManager()

    if args.cmd == "validate":
        result = mgr.validate_snapshot()
        print(json.dumps(result, indent=2))
        sys.exit(0 if result["ok"] else 1)

    elif args.cmd == "list":
        snaps = mgr.list_snapshots()
        print(json.dumps(snaps, indent=2))
        ptr, _ = _load_json_safe(CURRENT_PTR)
        if ptr:
            print(f"\nCurrent: {ptr.get('snapshot_file')} ({ptr.get('total_items')} items)")

    elif args.cmd == "prune":
        n = mgr.prune_old_snapshots(keep=args.keep)
        print(f"Pruned {n} old snapshots")

    elif args.cmd == "pointer":
        ptr, err = _load_json_safe(CURRENT_PTR)
        if err:
            print(f"ERROR: {err}"); sys.exit(1)
        print(json.dumps(ptr, indent=2))

    else:
        parser.print_help()


if __name__ == "__main__":
    _cli()
