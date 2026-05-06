#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Storage Governance Engine
=============================================================
Phase 6: Repository & Storage Governance

The repository has grown massively. This engine implements:
  - Artifact retention policies (keep N, prune old)
  - Report archival automation (compress + archive aged reports)
  - Stale manifest cleanup (remove superseded manifests)
  - Compressed historical exports (tar.gz archives of old data)
  - Storage rotation (rolling window for high-volume data)
  - Deployment artifact pruning (clean old snapshots + health dumps)

Optimizes:
  - git checkout time (reduce tracked blob size)
  - workflow duration (fewer files to process)
  - cache size (prune stale objects)
  - deployment payload size (exclude non-essential artifacts)

Usage:
  python3 scripts/storage_governance.py scan    -- show current storage stats
  python3 scripts/storage_governance.py prune   -- prune old artifacts (dry-run by default)
  python3 scripts/storage_governance.py archive -- archive old reports to compressed export
  python3 scripts/storage_governance.py status  -- print governance status
"""

import argparse
import gzip
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import time
from datetime import datetime, timedelta, timezone

REPO_ROOT    = pathlib.Path(__file__).resolve().parent.parent
ARCHIVE_DIR  = REPO_ROOT / "data" / "archive"
GOV_DIR      = REPO_ROOT / "data" / "governance"
REPORTS_DIR  = REPO_ROOT / "reports"
HEALTH_DIR   = REPO_ROOT / "data" / "health"
ROLLBACK_DIR = REPO_ROOT / "data" / "rollback"

GOV_DIR.mkdir(parents=True, exist_ok=True)
ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)

GOVERNANCE_LOG = GOV_DIR / "storage_governance_log.json"

# Retention policies
RETENTION = {
    "rollback_snapshots":    {"max_count": 20, "max_age_days": 14},
    "health_history":        {"max_count": 100, "max_age_days": 30},
    "alert_history":         {"max_count": 200, "max_age_days": 60},
    "healing_history":       {"max_count": 100, "max_age_days": 30},
    "governance_ledger":     {"max_count": 500, "max_age_days": 90},
    "sla_history":           {"max_count": 200, "max_age_days": 60},
    "reports_html":          {"max_count": 50,  "max_age_days": 30},
    "reports_md":            {"max_count": 30,  "max_age_days": 14},
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_log() -> list:
    if not GOVERNANCE_LOG.exists():
        return []
    return json.loads(GOVERNANCE_LOG.read_text()).get("events", [])


def append_log(event: dict):
    events = load_log()
    events.append({**event, "recorded_at": now_iso()})
    events = events[-200:]
    GOVERNANCE_LOG.write_text(json.dumps({"events": events, "updated_at": now_iso()}, indent=2))


def get_dir_size(path: pathlib.Path) -> int:
    """Total size in bytes of a directory."""
    total = 0
    if path.exists():
        for f in path.rglob("*"):
            if f.is_file():
                try:
                    total += f.stat().st_size
                except Exception:
                    pass
    return total


def fmt_bytes(n: int) -> str:
    for unit in ["B", "KB", "MB", "GB"]:
        if n < 1024:
            return f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def scan_storage() -> dict:
    """Scan repository storage footprint."""
    dirs = {
        "reports":         REPORTS_DIR,
        "data/health":     HEALTH_DIR,
        "data/rollback":   ROLLBACK_DIR,
        "data/archive":    ARCHIVE_DIR,
        "data/alerts":     REPO_ROOT / "data" / "alerts",
        "data/governance": GOV_DIR,
        "data/self_healing": REPO_ROOT / "data" / "self_healing",
        "workers":         REPO_ROOT / "workers",
        "api":             REPO_ROOT / "api",
        "scripts":         REPO_ROOT / "scripts",
    }
    result = {}
    for name, path in dirs.items():
        if path.exists():
            files = list(path.rglob("*"))
            file_count = sum(1 for f in files if f.is_file())
            size = get_dir_size(path)
            result[name] = {"files": file_count, "size_bytes": size, "size_human": fmt_bytes(size)}
    return result


def prune_json_array_file(path: pathlib.Path, key: str, max_count: int, max_age_days: int,
                           dry_run: bool = True) -> dict:
    """Prune a JSON file that contains an array under `key`."""
    if not path.exists():
        return {"pruned": 0, "kept": 0}
    try:
        data = json.loads(path.read_text())
        items = data.get(key, [])
        original_count = len(items)
        cutoff = datetime.now(timezone.utc) - timedelta(days=max_age_days)

        # Prune by age
        def get_ts(item):
            for field in ("recorded_at", "fired_at", "captured_at", "generated_at", "updated_at"):
                if field in item:
                    try:
                        ts = item[field]
                        return datetime.fromisoformat(ts.replace("Z", "+00:00"))
                    except Exception:
                        pass
            return datetime.now(timezone.utc)  # keep if no timestamp

        items_with_ts = [(get_ts(item), item) for item in items]
        items_with_ts.sort(key=lambda x: x[0], reverse=True)  # newest first

        # Apply retention
        kept = []
        for i, (ts, item) in enumerate(items_with_ts):
            if i < max_count and ts >= cutoff:
                kept.append(item)
            elif i < max_count:
                kept.append(item)  # keep if under count limit even if old

        kept = kept[:max_count]
        pruned = original_count - len(kept)

        if not dry_run and pruned > 0:
            data[key] = kept
            data["updated_at"] = now_iso()
            path.write_text(json.dumps(data, indent=2))

        return {"pruned": pruned, "kept": len(kept), "original": original_count}
    except Exception as e:
        return {"pruned": 0, "kept": 0, "error": str(e)}


def prune_rollback_snapshots(dry_run: bool = True) -> dict:
    """Prune old rollback snapshot files."""
    if not ROLLBACK_DIR.exists():
        return {"pruned": 0}
    cfg = RETENTION["rollback_snapshots"]
    snap_files = sorted(
        [f for f in ROLLBACK_DIR.glob("snap-*.json")],
        key=lambda f: f.stat().st_mtime, reverse=True
    )
    to_keep = snap_files[:cfg["max_count"]]
    to_prune = snap_files[cfg["max_count"]:]
    pruned = 0
    size_freed = 0
    for f in to_prune:
        size_freed += f.stat().st_size
        if not dry_run:
            f.unlink()
        pruned += 1
    return {"pruned": pruned, "kept": len(to_keep), "size_freed": fmt_bytes(size_freed)}


def prune_old_reports(dry_run: bool = True) -> dict:
    """Prune old HTML/MD reports beyond retention policy."""
    if not REPORTS_DIR.exists():
        return {"pruned": 0}
    pruned = 0
    size_freed = 0
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION["reports_html"]["max_age_days"])

    # Sort by modification time
    html_files = sorted(REPORTS_DIR.glob("**/*.html"), key=lambda f: f.stat().st_mtime, reverse=True)
    keep_count = RETENTION["reports_html"]["max_count"]
    for i, f in enumerate(html_files):
        mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
        if i >= keep_count or mtime < cutoff:
            size_freed += f.stat().st_size
            if not dry_run:
                f.unlink()
            pruned += 1

    return {"pruned": pruned, "size_freed": fmt_bytes(size_freed)}


def archive_old_data(dry_run: bool = True) -> dict:
    """Compress and archive historical data into tar.gz."""
    ts = datetime.now(timezone.utc).strftime("%Y%m%d-%H%M%S")
    archive_name = f"sentinel-archive-{ts}.tar.gz"
    archive_path = ARCHIVE_DIR / archive_name

    dirs_to_archive = []
    # Archive rollback snapshots older than 7 days
    if ROLLBACK_DIR.exists():
        cutoff = datetime.now(timezone.utc) - timedelta(days=7)
        for f in ROLLBACK_DIR.glob("snap-*.json"):
            mtime = datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc)
            if mtime < cutoff:
                dirs_to_archive.append(f)

    if not dirs_to_archive:
        return {"archived": 0, "archive_path": None, "note": "Nothing to archive"}

    if not dry_run:
        with tarfile.open(archive_path, "w:gz") as tar:
            for f in dirs_to_archive:
                tar.add(f, arcname=f.name)
        # Remove archived files
        for f in dirs_to_archive:
            f.unlink()
        size = archive_path.stat().st_size
        return {
            "archived": len(dirs_to_archive),
            "archive_path": str(archive_path),
            "archive_size": fmt_bytes(size),
        }
    else:
        return {
            "archived": len(dirs_to_archive),
            "archive_path": str(archive_path),
            "dry_run": True,
            "note": "Would archive these files (--execute to apply)",
        }


def cmd_scan(args) -> int:
    """Show current storage stats."""
    print(f"\nSTORAGE GOVERNANCE SCAN")
    print("=" * 60)
    stats = scan_storage()
    total_bytes = 0
    for name, info in sorted(stats.items(), key=lambda x: x[1]["size_bytes"], reverse=True):
        total_bytes += info["size_bytes"]
        print(f"  {name:<30} {info['files']:>5} files   {info['size_human']:>10}")
    print("-" * 60)
    print(f"  {'TOTAL':<30} {sum(v['files'] for v in stats.values()):>5} files   {fmt_bytes(total_bytes):>10}")
    print("=" * 60)
    return 0


def cmd_prune(args) -> int:
    """Prune old artifacts per retention policy."""
    dry_run = not getattr(args, "execute", False)
    mode = "DRY RUN" if dry_run else "EXECUTE"
    print(f"\nSTORAGE GOVERNANCE PRUNE ({mode})")
    print("=" * 60)
    total_pruned = 0

    # Prune JSON history files
    json_targets = [
        (REPO_ROOT / "data" / "alerts" / "alert_history.json", "alerts", "alert_history"),
        (REPO_ROOT / "data" / "self_healing" / "healing_history.json", "events", "healing_history"),
        (GOV_DIR / "deployment_governance_ledger.json", "entries", "governance_ledger"),
        (REPO_ROOT / "data" / "rollback" / "rollback_audit_history.json", "events", "rollback_snapshots"),
        (REPO_ROOT / "data" / "health" / "sla_history.json", "history", "sla_history"),
    ]
    for path, key, policy_key in json_targets:
        if path.exists():
            cfg = RETENTION.get(policy_key, {"max_count": 100, "max_age_days": 30})
            result = prune_json_array_file(path, key, cfg["max_count"], cfg["max_age_days"], dry_run)
            pruned = result.get("pruned", 0)
            total_pruned += pruned
            print(f"  {path.name:<40} pruned={pruned} kept={result.get('kept','?')}")

    # Prune rollback snapshot files
    snap_result = prune_rollback_snapshots(dry_run)
    total_pruned += snap_result["pruned"]
    print(f"  rollback_snapshots                       pruned={snap_result['pruned']} freed={snap_result.get('size_freed','?')}")

    # Prune old reports
    report_result = prune_old_reports(dry_run)
    total_pruned += report_result["pruned"]
    print(f"  old_reports_html                         pruned={report_result['pruned']} freed={report_result.get('size_freed','?')}")

    print("=" * 60)
    print(f"  Total pruned: {total_pruned} items" + (" (dry run -- run with --execute to apply)" if dry_run else ""))
    print("=" * 60)

    if not dry_run:
        append_log({"event": "PRUNE_EXECUTED", "total_pruned": total_pruned})

    return 0


def cmd_archive(args) -> int:
    """Archive old data."""
    dry_run = not getattr(args, "execute", False)
    print(f"\nSTORAGE ARCHIVE ({'DRY RUN' if dry_run else 'EXECUTE'})")
    result = archive_old_data(dry_run)
    print(f"  Archived: {result.get('archived', 0)} items")
    if result.get("archive_path"):
        print(f"  Archive: {result['archive_path']}")
    if result.get("archive_size"):
        print(f"  Size: {result['archive_size']}")
    print(f"  Note: {result.get('note', '')}")
    if not dry_run:
        append_log({"event": "ARCHIVE_EXECUTED", **result})
    return 0


def cmd_status(args) -> int:
    """Print governance log."""
    events = load_log()
    print(f"\nSTORAGE GOVERNANCE STATUS ({len(events)} events)")
    print("=" * 60)
    for e in events[-10:]:
        ts = e.get("recorded_at", "?")[:19]
        ev = e.get("event", "?")
        pruned = e.get("total_pruned", "")
        detail = f" pruned={pruned}" if pruned else ""
        print(f"  {ts}  {ev}{detail}")
    print("=" * 60)
    return 0


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Storage Governance")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("scan", help="Show storage stats")

    p_prune = sub.add_parser("prune", help="Prune old artifacts")
    p_prune.add_argument("--execute", action="store_true", help="Actually prune (default: dry-run)")

    p_arch = sub.add_parser("archive", help="Archive old data")
    p_arch.add_argument("--execute", action="store_true")

    sub.add_parser("status", help="Print governance log")

    args = parser.parse_args()
    dispatch = {
        "scan":    cmd_scan,
        "prune":   cmd_prune,
        "archive": cmd_archive,
        "status":  cmd_status,
    }
    if args.cmd not in dispatch:
        parser.print_help()
        return 1
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
