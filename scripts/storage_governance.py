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
import hashlib
import json
import os
import pathlib
import shutil
import subprocess
import sys
import tarfile
import time
import uuid
from datetime import datetime, timedelta, timezone

REPO_ROOT    = pathlib.Path(__file__).resolve().parent.parent
ARCHIVE_DIR  = REPO_ROOT / "data" / "archive"
GOV_DIR      = REPO_ROOT / "data" / "governance"
REPORTS_DIR  = REPO_ROOT / "reports"
HEALTH_DIR   = REPO_ROOT / "data" / "health"
ROLLBACK_DIR = REPO_ROOT / "data" / "rollback"
MANIFEST_BACKUPS_DIR = REPO_ROOT / "data" / ".manifest_backups"

# Phase 8 (storage sanitation): where verified backups of anything this
# script deletes are held before the delete is allowed to proceed, and
# where the manifests describing each batch are written.
DELETION_BACKUP_DIR = GOV_DIR / "deletion_backups"
EXECUTION_JOURNAL    = GOV_DIR / "execution_journal.jsonl"

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
    # Added by the Phase 8 storage-sanitation pass. Confirmed real consumer
    # (agent/autonomous_guardian/guardian.py restores from the newest valid
    # backup on manifest corruption) -- only the most recent few files are
    # ever actually read, so old snapshots are safe to prune with a backup.
    "manifest_backups":      {"max_count": 5,   "max_age_days": 180},
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


# ---------------------------------------------------------------------------
# Phase 8 -- Safe-delete machinery (checksums, backup, rollback, journal)
#
# Added for the Project Titan storage-sanitation pass. Existing prune
# functions (prune_rollback_snapshots, prune_old_reports) previously called
# path.unlink() directly with no backup. These helpers add a
# verified-backup-before-delete contract, modeled on the pattern already
# proven in cold_archive_automation.py (checksum before, checksum after,
# never remove the original until the copy is verified byte-identical).
# ---------------------------------------------------------------------------

def _sha256_file(path: pathlib.Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _new_batch_id() -> str:
    return f"{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}-{uuid.uuid4().hex[:8]}"


def _append_execution_journal(entry: dict) -> None:
    """Append-only, structured journal of every safe-delete operation attempted.

    Distinct from the existing GOVERNANCE_LOG (a small rolling summary of the
    last 200 high-level events) -- this is the detailed, per-file audit trail
    Phase 8 requires, one line of JSON per event, never truncated or rewritten.
    """
    GOV_DIR.mkdir(parents=True, exist_ok=True)
    record = {"ts": now_iso(), **entry}
    with open(EXECUTION_JOURNAL, "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


def backup_before_delete(paths: list, batch_id: str, dry_run: bool = True) -> dict:
    """
    Verified backup step that MUST precede any deletion.

    For each path: computes a checksum, copies the file into
    data/governance/deletion_backups/<batch_id>/ preserving its relative
    path from REPO_ROOT, re-checksums the copy, and only reports a path as
    "backed_up" if the two checksums match. Nothing is ever deleted based on
    a backup that failed verification -- the caller is expected to skip
    deletion for any path not present in the returned "verified" list
    (failure recovery: a bad backup blocks that file's deletion, it does not
    abort the whole batch).

    Returns a dict describing the batch: paths, checksums, sizes, backup
    locations, and which ones verified successfully.
    """
    batch_dir = DELETION_BACKUP_DIR / batch_id
    verified, failed = [], []
    entries = []

    for p in paths:
        p = pathlib.Path(p)
        if not p.exists() or not p.is_file():
            failed.append(str(p))
            _append_execution_journal({
                "event": "BACKUP_SKIPPED_MISSING", "batch_id": batch_id,
                "path": str(p), "dry_run": dry_run,
            })
            continue

        try:
            original_hash = _sha256_file(p)
            original_size = p.stat().st_size
            rel = p.resolve().relative_to(REPO_ROOT.resolve())
            backup_path = batch_dir / rel

            if dry_run:
                entries.append({
                    "path": str(rel), "sha256": original_hash, "size": original_size,
                    "backup_path": str(backup_path), "verified": None, "dry_run": True,
                })
                continue

            backup_path.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(p, backup_path)
            backup_hash = _sha256_file(backup_path)

            ok = (backup_hash == original_hash)
            entries.append({
                "path": str(rel), "sha256": original_hash, "size": original_size,
                "backup_path": str(backup_path), "verified": ok, "dry_run": False,
            })
            if ok:
                verified.append(str(p))
            else:
                failed.append(str(p))
                backup_path.unlink(missing_ok=True)  # don't keep a corrupt backup around
            _append_execution_journal({
                "event": "BACKUP_VERIFIED" if ok else "BACKUP_CHECKSUM_MISMATCH",
                "batch_id": batch_id, "path": str(rel), "sha256": original_hash,
                "dry_run": dry_run,
            })
        except Exception as e:
            failed.append(str(p))
            _append_execution_journal({
                "event": "BACKUP_FAILED", "batch_id": batch_id, "path": str(p),
                "error": str(e), "dry_run": dry_run,
            })

    return {
        "batch_id": batch_id, "batch_dir": str(batch_dir), "dry_run": dry_run,
        "entries": entries, "verified": verified, "failed": failed,
    }


def write_deletion_manifest(batch_id: str, backup_result: dict, operation: str) -> pathlib.Path:
    """Record exactly what this batch deleted (or would delete), with checksums."""
    GOV_DIR.mkdir(parents=True, exist_ok=True)
    path = GOV_DIR / f"deletion_manifest_{batch_id}.json"
    manifest = {
        "batch_id":   batch_id,
        "operation":  operation,
        "generated_at": now_iso(),
        "dry_run":    backup_result["dry_run"],
        "file_count": len(backup_result["entries"]),
        "verified_count": len(backup_result["verified"]),
        "failed_count":   len(backup_result["failed"]),
        "entries":    backup_result["entries"],
        "failed":     backup_result["failed"],
    }
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def write_rollback_manifest(batch_id: str, backup_result: dict, operation: str) -> pathlib.Path:
    """Record exactly how to undo this batch (backup path -> original path)."""
    GOV_DIR.mkdir(parents=True, exist_ok=True)
    path = GOV_DIR / f"rollback_manifest_{batch_id}.json"
    manifest = {
        "batch_id":  batch_id,
        "operation": operation,
        "generated_at": now_iso(),
        "restore_command": f"python3 scripts/storage_governance.py restore --batch {batch_id}",
        "restores": [
            {"original_path": e["path"], "backup_path": e["backup_path"], "sha256": e["sha256"]}
            for e in backup_result["entries"] if e.get("verified")
        ],
    }
    path.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
    return path


def restore_from_backup(batch_id: str) -> dict:
    """
    Restore verification + execution: reads rollback_manifest_<batch_id>.json,
    copies every backed-up file back to its original path, and verifies the
    restored file's checksum matches what was recorded before declaring
    success. This is the failure-recovery path -- if a deletion turns out to
    have been wrong, this is how it's undone without touching git history.
    """
    manifest_path = GOV_DIR / f"rollback_manifest_{batch_id}.json"
    if not manifest_path.exists():
        return {"restored": 0, "failed": 0, "error": f"No rollback manifest for batch {batch_id}"}

    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    restored, failed = [], []

    for entry in manifest.get("restores", []):
        src = pathlib.Path(entry["backup_path"])
        dst = REPO_ROOT / entry["original_path"]
        try:
            if not src.exists():
                failed.append(entry["original_path"])
                continue
            dst.parent.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, dst)
            restored_hash = _sha256_file(dst)
            if restored_hash == entry["sha256"]:
                restored.append(entry["original_path"])
            else:
                failed.append(entry["original_path"])
            _append_execution_journal({
                "event": "RESTORE_VERIFIED" if restored_hash == entry["sha256"] else "RESTORE_CHECKSUM_MISMATCH",
                "batch_id": batch_id, "path": entry["original_path"],
            })
        except Exception as e:
            failed.append(entry["original_path"])
            _append_execution_journal({
                "event": "RESTORE_FAILED", "batch_id": batch_id,
                "path": entry["original_path"], "error": str(e),
            })

    return {"restored": len(restored), "failed": len(failed), "failed_paths": failed}


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
        "data/.manifest_backups": MANIFEST_BACKUPS_DIR,
        # Observability only (Principle 7) -- no active pruning wired up yet.
        # Confirmed unbounded growth with a real writer/reader (see
        # SAFE_CLEANUP_PLAN.md 4.9); flagged for a future dedicated pass
        # rather than pruned here without stronger evidence of safe limits.
        "data/analyst":    REPO_ROOT / "data" / "analyst",
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
    """Prune old rollback snapshot files. Backs up + verifies before deleting
    (Phase 8) -- never unlinks a file whose backup didn't checksum-verify."""
    if not ROLLBACK_DIR.exists():
        return {"pruned": 0}
    cfg = RETENTION["rollback_snapshots"]
    snap_files = sorted(
        [f for f in ROLLBACK_DIR.glob("snap-*.json")],
        key=lambda f: f.stat().st_mtime, reverse=True
    )
    to_keep = snap_files[:cfg["max_count"]]
    to_prune = snap_files[cfg["max_count"]:]

    batch_id = _new_batch_id()
    backup = backup_before_delete(to_prune, batch_id, dry_run=dry_run)
    write_deletion_manifest(batch_id, backup, "prune_rollback_snapshots")
    if not dry_run and backup["verified"]:
        write_rollback_manifest(batch_id, backup, "prune_rollback_snapshots")

    pruned = 0
    size_freed = 0
    for f in to_prune:
        if not dry_run and str(f) not in backup["verified"]:
            continue  # failure recovery: no verified backup -> do not delete
        size_freed += f.stat().st_size if f.exists() else 0
        if not dry_run:
            f.unlink()
        pruned += 1
    return {
        "pruned": pruned, "kept": len(to_keep), "size_freed": fmt_bytes(size_freed),
        "batch_id": batch_id, "backup_failures": len(backup["failed"]),
    }


def prune_old_reports(dry_run: bool = True) -> dict:
    """Prune old HTML/MD reports beyond retention policy. Backs up + verifies
    before deleting (Phase 8) -- never unlinks a file whose backup didn't
    checksum-verify.

    NOTE: reports/ has a dedicated, more sophisticated archive tool
    (scripts/report_archive_manager.py, wired into sentinel-apex.yml
    STAGE 5.4.5b) that untracks via `git rm --cached` rather than deleting
    from disk, keeping historical reports recoverable from git history. This
    function remains as a filesystem-level safety net for report_html
    retention outside that git-aware flow (e.g. ad-hoc invocation), now with
    the same backup contract as everything else in this script -- it should
    not be treated as a replacement for report_archive_manager.py.
    """
    if not REPORTS_DIR.exists():
        return {"pruned": 0}
    cutoff = datetime.now(timezone.utc) - timedelta(days=RETENTION["reports_html"]["max_age_days"])

    # Sort by modification time
    html_files = sorted(REPORTS_DIR.glob("**/*.html"), key=lambda f: f.stat().st_mtime, reverse=True)
    keep_count = RETENTION["reports_html"]["max_count"]
    to_prune = [
        f for i, f in enumerate(html_files)
        if i >= keep_count or datetime.fromtimestamp(f.stat().st_mtime, tz=timezone.utc) < cutoff
    ]

    batch_id = _new_batch_id()
    backup = backup_before_delete(to_prune, batch_id, dry_run=dry_run)
    write_deletion_manifest(batch_id, backup, "prune_old_reports")
    if not dry_run and backup["verified"]:
        write_rollback_manifest(batch_id, backup, "prune_old_reports")

    pruned = 0
    size_freed = 0
    for f in to_prune:
        if not dry_run and str(f) not in backup["verified"]:
            continue
        size_freed += f.stat().st_size if f.exists() else 0
        if not dry_run:
            f.unlink()
        pruned += 1

    return {
        "pruned": pruned, "size_freed": fmt_bytes(size_freed),
        "batch_id": batch_id, "backup_failures": len(backup["failed"]),
    }


def prune_manifest_backups(dry_run: bool = True) -> dict:
    """Prune data/.manifest_backups/ to the newest N snapshots (Phase 8 addition).

    Confirmed real consumer: agent/autonomous_guardian/guardian.py restores
    from the newest valid backup on manifest corruption -- it only ever needs
    the most recent files, not the full history. Backs up + verifies before
    deleting, same contract as everything else in this script.
    """
    if not MANIFEST_BACKUPS_DIR.exists():
        return {"pruned": 0}
    cfg = RETENTION["manifest_backups"]
    files = sorted(
        [f for f in MANIFEST_BACKUPS_DIR.glob("*.json")],
        key=lambda f: f.stat().st_mtime, reverse=True
    )
    to_keep = files[:cfg["max_count"]]
    to_prune = files[cfg["max_count"]:]

    batch_id = _new_batch_id()
    backup = backup_before_delete(to_prune, batch_id, dry_run=dry_run)
    write_deletion_manifest(batch_id, backup, "prune_manifest_backups")
    if not dry_run and backup["verified"]:
        write_rollback_manifest(batch_id, backup, "prune_manifest_backups")

    pruned = 0
    size_freed = 0
    for f in to_prune:
        if not dry_run and str(f) not in backup["verified"]:
            continue
        size_freed += f.stat().st_size if f.exists() else 0
        if not dry_run:
            f.unlink()
        pruned += 1
    return {
        "pruned": pruned, "kept": len(to_keep), "size_freed": fmt_bytes(size_freed),
        "batch_id": batch_id, "backup_failures": len(backup["failed"]),
    }


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

    # Prune rollback snapshot files (backed up + checksum-verified first)
    snap_result = prune_rollback_snapshots(dry_run)
    total_pruned += snap_result["pruned"]
    print(f"  rollback_snapshots                       pruned={snap_result['pruned']} freed={snap_result.get('size_freed','?')} batch={snap_result.get('batch_id','-')}")

    # Prune old reports (backed up + checksum-verified first; see prune_old_reports
    # docstring -- reports/ itself is primarily governed by report_archive_manager.py)
    report_result = prune_old_reports(dry_run)
    total_pruned += report_result["pruned"]
    print(f"  old_reports_html                         pruned={report_result['pruned']} freed={report_result.get('size_freed','?')} batch={report_result.get('batch_id','-')}")

    # Prune stale manifest backups (Phase 8 addition, backed up + verified first)
    mb_result = prune_manifest_backups(dry_run)
    total_pruned += mb_result.get("pruned", 0)
    print(f"  manifest_backups                         pruned={mb_result.get('pruned',0)} freed={mb_result.get('size_freed','?')} batch={mb_result.get('batch_id','-')}")

    backup_failures = (
        snap_result.get("backup_failures", 0)
        + report_result.get("backup_failures", 0)
        + mb_result.get("backup_failures", 0)
    )

    print("=" * 60)
    print(f"  Total pruned: {total_pruned} items" + (" (dry run -- run with --execute to apply)" if dry_run else ""))
    if backup_failures:
        print(f"  WARNING: {backup_failures} file(s) skipped -- backup could not be verified, left in place")
    print(f"  Rollback: python3 scripts/storage_governance.py restore --batch <batch_id>  (see manifests in data/governance/)")
    print("=" * 60)

    if not dry_run:
        append_log({"event": "PRUNE_EXECUTED", "total_pruned": total_pruned, "backup_failures": backup_failures})
        _append_execution_journal({
            "event": "PRUNE_RUN_COMPLETE", "total_pruned": total_pruned,
            "backup_failures": backup_failures,
            "batches": [snap_result.get("batch_id"), report_result.get("batch_id"), mb_result.get("batch_id")],
        })

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


def cmd_restore(args) -> int:
    """Phase 8: restore a previously deleted batch from its verified backup."""
    result = restore_from_backup(args.batch)
    print(f"\nSTORAGE GOVERNANCE RESTORE (batch={args.batch})")
    print("=" * 60)
    if result.get("error"):
        print(f"  ERROR: {result['error']}")
        print("=" * 60)
        return 1
    print(f"  Restored : {result['restored']}")
    print(f"  Failed   : {result['failed']}")
    if result["failed"]:
        for p in result.get("failed_paths", [])[:10]:
            print(f"    FAILED: {p}")
    print("=" * 60)
    return 0 if result["failed"] == 0 else 1


def cmd_verify_backup(args) -> int:
    """Phase 8: checksum-verify a batch's backup without restoring anything."""
    manifest_path = GOV_DIR / f"deletion_manifest_{args.batch}.json"
    if not manifest_path.exists():
        print(f"No deletion manifest for batch {args.batch}")
        return 1
    manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
    ok, mismatched, missing = 0, 0, 0
    for e in manifest.get("entries", []):
        if not e.get("verified"):
            continue
        backup_path = pathlib.Path(e["backup_path"])
        if not backup_path.exists():
            missing += 1
            continue
        if _sha256_file(backup_path) == e["sha256"]:
            ok += 1
        else:
            mismatched += 1
    print(f"\nBACKUP VERIFY (batch={args.batch})")
    print("=" * 60)
    print(f"  OK: {ok}  Mismatched: {mismatched}  Missing: {missing}")
    print("=" * 60)
    return 0 if (mismatched == 0 and missing == 0) else 1


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Storage Governance")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("scan", help="Show storage stats")

    p_prune = sub.add_parser("prune", help="Prune old artifacts")
    p_prune.add_argument("--execute", action="store_true", help="Actually prune (default: dry-run)")

    p_arch = sub.add_parser("archive", help="Archive old data")
    p_arch.add_argument("--execute", action="store_true")

    sub.add_parser("status", help="Print governance log")

    p_restore = sub.add_parser("restore", help="Restore a pruned batch from its verified backup (Phase 8)")
    p_restore.add_argument("--batch", required=True, help="Batch ID from a deletion/rollback manifest")

    p_verify = sub.add_parser("verify-backup", help="Checksum-verify a batch's backup without restoring (Phase 8)")
    p_verify.add_argument("--batch", required=True, help="Batch ID from a deletion manifest")

    args = parser.parse_args()
    dispatch = {
        "scan":          cmd_scan,
        "prune":         cmd_prune,
        "archive":       cmd_archive,
        "status":        cmd_status,
        "restore":       cmd_restore,
        "verify-backup": cmd_verify_backup,
    }
    if args.cmd not in dispatch:
        parser.print_help()
        return 1
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
