#!/usr/bin/env python3
"""
scripts/runner_disk_governor.py
CYBERDUDEBIVASH(R) SENTINEL APEX v156.0 -- Runner Disk Governor
================================================================================
PURPOSE:
  Enterprise-grade runtime disk monitoring and emergency cleanup engine for
  GitHub Actions runners. Permanently eliminates the disk-exhaustion failure
  class that caused P0 incident #1199 (System.IO.IOException: No space left
  on device).

ROOT CAUSE OF INCIDENT #1199:
  - 64,743 tracked HTML reports checked out to runner (~2-4 GB)
  - build_dist_artifact.py (REPORT_RETENTION_DAYS=0) copied ALL reports to
    dist/ — doubling disk usage (~2-4 GB)
  - Combined with Python toolchain, STIX bundles (162/run), pip cache,
    telemetry → runner 14 GB disk exhausted before dist/ build completed

ARCHITECTURE:
  This script operates in three modes:

  1. --preflight   : Pre-pipeline disk gate. Fails HARD if < MIN_FREE_GB.
                     Runs as STAGE 0.00b before any pipeline work.

  2. --predist     : Pre-dist cleanup gate. Reclaims disk space before
                     build_dist_artifact.py copies reports to dist/.
                     Runs as STAGE 5.4.5c.

  3. --status      : Emit disk telemetry JSON. Non-blocking. Usable at any
                     stage for observability.

  4. --monitor N   : Continuous monitoring — sample disk every N seconds,
                     emit alert if threshold crossed. Suitable for long-running
                     stages (report generation, R2 upload).

DISK THRESHOLDS:
  CRITICAL   < 4 GB  — HARD FAIL (pipeline must stop)
  LOW        < 6 GB  — WARNING annotation + emergency reclaim attempt
  SAFE       < 8 GB  — WARNING annotation only
  OK        >= 8 GB  — No action required

RECLAIM ACTIONS (ordered by impact):
  1. Python __pycache__/ (multiple GB on large codebases)
  2. pip cache (~1-2 GB)
  3. apt cache (~500 MB)
  4. /tmp/ runner temp files
  5. data/stix/ prune — keep latest N bundles only
  6. data/telemetry/ -- remove files older than TELEMETRY_MAX_DAYS
  7. dist/ previous build wipe (before fresh rebuild)

EXIT CODES:
  0 = OK / cleanup completed / no action needed
  1 = HARD FAIL — disk critically low even after reclaim
  2 = WARNING — disk low but sufficient to proceed (non-blocking)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-DISK-GOV] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.disk_governor")

REPO_ROOT = Path(__file__).resolve().parent.parent

# ── Disk thresholds (GB) ──────────────────────────────────────────────────────
# v161.4 P0 FIX: Raised thresholds after OS-level disk sovereignty step now
# frees 15-20 GB at job start. dist/ build needs ~7 GB headroom minimum.
# CRITICAL raised 4->10 GB: if somehow < 10 GB free before dist, HARD FAIL early.
# LOW raised 6->12 GB: trigger aggressive reclaim at 12 GB (not 6).
# SAFE raised 8->15 GB: annotation threshold at 15 GB post-OS-cleanup.
THRESHOLD_CRITICAL_GB = 10   # HARD FAIL — pipeline must stop (raised from 4 GB)
THRESHOLD_LOW_GB      = 12   # WARNING + emergency reclaim (raised from 6 GB)
THRESHOLD_SAFE_GB     = 15   # WARNING annotation only (raised from 8 GB)

# ── STIX governance ───────────────────────────────────────────────────────────
STIX_DIR              = REPO_ROOT / "data" / "stix"
STIX_MAX_BUNDLES      = int(os.environ.get("STIX_MAX_BUNDLES", "50"))

# ── Telemetry governance ──────────────────────────────────────────────────────
TELEMETRY_DIR         = REPO_ROOT / "data" / "telemetry"
TELEMETRY_MAX_DAYS    = int(os.environ.get("TELEMETRY_MAX_DAYS", "7"))

# ── Telemetry output ──────────────────────────────────────────────────────────
DISK_TELEMETRY_PATH   = REPO_ROOT / "data" / "telemetry" / "runner_disk_telemetry.json"


# ─────────────────────────────────────────────────────────────────────────────
# DISK MEASUREMENT
# ─────────────────────────────────────────────────────────────────────────────

def get_disk_stats(path: Path = Path("/")) -> Dict:
    """Return disk usage stats for the given path."""
    usage = shutil.disk_usage(path)
    return {
        "total_gb":  round(usage.total / 1e9, 2),
        "used_gb":   round(usage.used  / 1e9, 2),
        "free_gb":   round(usage.free  / 1e9, 2),
        "used_pct":  round(usage.used  / usage.total * 100, 1),
        "free_pct":  round(usage.free  / usage.total * 100, 1),
    }


def get_dir_size_gb(path: Path) -> float:
    """Return total size of a directory in GB (best-effort)."""
    if not path.exists():
        return 0.0
    total = sum(f.stat().st_size for f in path.rglob("*") if f.is_file())
    return round(total / 1e9, 3)


def get_storage_hotspots() -> List[Dict]:
    """Identify the largest storage consumers in the repo."""
    hotspots = []
    candidates = [
        REPO_ROOT / "reports",
        REPO_ROOT / "dist",
        REPO_ROOT / "data" / "stix",
        REPO_ROOT / "data" / "telemetry",
        REPO_ROOT / "data" / "cache",
        REPO_ROOT / "data" / "audit",
        REPO_ROOT / "scripts",
        REPO_ROOT / "api",
    ]
    for p in candidates:
        if p.exists():
            size_gb = get_dir_size_gb(p)
            file_count = sum(1 for _ in p.rglob("*") if _.is_file())
            hotspots.append({
                "path":       str(p.relative_to(REPO_ROOT)),
                "size_gb":    size_gb,
                "file_count": file_count,
            })
    return sorted(hotspots, key=lambda x: x["size_gb"], reverse=True)


# ─────────────────────────────────────────────────────────────────────────────
# RECLAIM ACTIONS
# ─────────────────────────────────────────────────────────────────────────────

def reclaim_pycache() -> int:
    """Delete all __pycache__ dirs and .pyc files. Returns files removed."""
    removed = 0
    for d in REPO_ROOT.rglob("__pycache__"):
        if d.is_dir():
            removed += sum(1 for _ in d.rglob("*") if _.is_file())
            shutil.rmtree(d, ignore_errors=True)
    for f in REPO_ROOT.rglob("*.pyc"):
        try:
            f.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def reclaim_pip_cache() -> bool:
    """Purge pip cache."""
    try:
        subprocess.run(["pip", "cache", "purge"], capture_output=True, timeout=30)
        return True
    except Exception:
        return False


def reclaim_apt_cache() -> bool:
    """Clean apt cache (requires sudo)."""
    try:
        subprocess.run(["sudo", "apt-get", "clean"], capture_output=True, timeout=30)
        return True
    except Exception:
        return False


def reclaim_tmp() -> int:
    """Remove common runner /tmp/ temp files."""
    removed = 0
    for pattern in ["/tmp/pip-*", "/tmp/*.log", "/tmp/*.tmp", "/tmp/*.zip"]:
        import glob
        for p in glob.glob(pattern):
            try:
                if os.path.isdir(p):
                    shutil.rmtree(p, ignore_errors=True)
                else:
                    os.unlink(p)
                removed += 1
            except OSError:
                pass
    # Also clear pip user cache
    pip_user = Path.home() / ".cache" / "pip"
    if pip_user.exists():
        shutil.rmtree(pip_user, ignore_errors=True)
        removed += 1
    return removed


def reclaim_stix_bundles(keep_latest: int = STIX_MAX_BUNDLES) -> int:
    """Prune STIX bundles — keep only latest N by filename sort. Returns files removed."""
    if not STIX_DIR.exists():
        return 0
    bundles = sorted(STIX_DIR.glob("*.json"))
    to_remove = bundles[:-keep_latest] if len(bundles) > keep_latest else []
    removed = 0
    for b in to_remove:
        try:
            b.unlink()
            removed += 1
        except OSError:
            pass
    return removed


def reclaim_telemetry(max_days: int = TELEMETRY_MAX_DAYS) -> int:
    """Remove telemetry files older than max_days. Returns files removed."""
    if not TELEMETRY_DIR.exists():
        return 0
    cutoff = time.time() - (max_days * 86400)
    removed = 0
    for f in TELEMETRY_DIR.rglob("*.json"):
        try:
            if f.stat().st_mtime < cutoff:
                f.unlink()
                removed += 1
        except OSError:
            pass
    return removed


def reclaim_dist() -> int:
    """Wipe the dist/ directory before a fresh rebuild. Returns files removed."""
    dist = REPO_ROOT / "dist"
    if not dist.exists():
        return 0
    count = sum(1 for _ in dist.rglob("*") if _.is_file())
    shutil.rmtree(dist, ignore_errors=True)
    return count


def reclaim_old_html_reports(retention_days: int = 3) -> Dict:
    """
    Physically delete HTML report files from reports/ that are outside the
    retention window. This prevents the runner from holding gigabytes of old
    reports that would never be copied to dist/ anyway.

    v176.0 P0 FIX: The root cause of run #1616 failure was 34,382 May 2026
    HTML files (3.2 GB) in reports/ being copied into dist/ because
    REPORT_RETENTION_DAYS=30 included the entire boundary month. Even after
    fixing build_dist_artifact.py to use mtime-level filtering, physically
    deleting old reports from the runner before the dist build reduces peak
    disk usage and speeds up the copytree pass.

    Returns dict with keys: dirs_removed, files_removed, bytes_freed, report_mb_before.
    """
    reports_dir = REPO_ROOT / "reports"
    if not reports_dir.exists():
        return {"dirs_removed": 0, "files_removed": 0, "bytes_freed": 0, "report_mb_before": 0.0}

    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)
    cutoff_ts = cutoff.timestamp()
    report_mb_before = round(
        sum(f.stat().st_size for f in reports_dir.rglob("*") if f.is_file()) / 1e6, 1
    )

    log.info("  PRE-DIST REPORT PURGE: removing HTML reports older than %d days "
             "(cutoff %s) from runner disk...", retention_days, cutoff.strftime("%Y-%m-%d"))
    log.info("  reports/ size before: %.1f MB", report_mb_before)

    dirs_removed = 0
    files_removed = 0
    bytes_freed = 0

    for year_dir in sorted(reports_dir.iterdir()):
        if not year_dir.is_dir():
            continue
        try:
            year = int(year_dir.name)
        except ValueError:
            continue

        for month_dir in sorted(year_dir.iterdir()):
            if not month_dir.is_dir():
                continue
            try:
                month = int(month_dir.name)
            except ValueError:
                continue

            if (year, month) < (cutoff.year, cutoff.month):
                # Entire month before cutoff — delete directory
                sz = sum(f.stat().st_size for f in month_dir.rglob("*") if f.is_file())
                fc = sum(1 for _ in month_dir.rglob("*") if _.is_file())
                try:
                    shutil.rmtree(month_dir)
                    dirs_removed += 1
                    files_removed += fc
                    bytes_freed += sz
                    log.info("    PURGED %s/%02d  (%d files, %.1f MB freed)",
                             year, month, fc, sz / 1e6)
                except OSError as exc:
                    log.warning("    WARN: could not purge %s/%02d: %s", year, month, exc)

            elif (year, month) == (cutoff.year, cutoff.month):
                # Boundary month — delete individual files older than cutoff
                for fpath in list(month_dir.iterdir()):
                    if not fpath.is_file():
                        continue
                    try:
                        if fpath.stat().st_mtime < cutoff_ts:
                            sz = fpath.stat().st_size
                            fpath.unlink()
                            files_removed += 1
                            bytes_freed += sz
                    except OSError:
                        continue
                log.info("    BOUNDARY %s/%02d: removed %d old files",
                         year, month, files_removed)

    mb_freed = round(bytes_freed / 1e6, 1)
    log.info("  Report purge complete: %d dirs, %d files removed, %.1f MB freed",
             dirs_removed, files_removed, mb_freed)

    return {
        "dirs_removed": dirs_removed,
        "files_removed": files_removed,
        "bytes_freed": bytes_freed,
        "mb_freed": mb_freed,
        "report_mb_before": report_mb_before,
        "retention_days": retention_days,
    }


def run_full_reclaim(include_dist: bool = False) -> Dict:
    """Execute all reclaim actions. Returns summary dict."""
    log.info("Starting full disk reclaim sequence...")
    results = {}

    log.info("  [1/7] Reclaiming __pycache__...")
    results["pycache_files"] = reclaim_pycache()
    log.info("        Removed %d __pycache__ files", results["pycache_files"])

    log.info("  [2/7] Purging pip cache...")
    results["pip_cache"] = reclaim_pip_cache()

    log.info("  [3/7] Cleaning apt cache...")
    results["apt_cache"] = reclaim_apt_cache()

    log.info("  [4/7] Clearing /tmp/ temp files...")
    results["tmp_files"] = reclaim_tmp()
    log.info("        Removed %d /tmp entries", results["tmp_files"])

    log.info("  [5/7] Pruning STIX bundles (keep latest %d)...", STIX_MAX_BUNDLES)
    results["stix_pruned"] = reclaim_stix_bundles(STIX_MAX_BUNDLES)
    log.info("        Pruned %d STIX bundles", results["stix_pruned"])

    log.info("  [6/7] Rotating stale telemetry (> %d days)...", TELEMETRY_MAX_DAYS)
    results["telemetry_removed"] = reclaim_telemetry(TELEMETRY_MAX_DAYS)
    log.info("        Removed %d stale telemetry files", results["telemetry_removed"])

    # v176.0 P0 FIX: Purge old HTML reports from runner disk before dist build.
    # Uses same retention window as build_dist_artifact.py (default 3 days, cap 7).
    # This prevents 3+ GB of old reports from consuming runner disk and slowing
    # the copytree operation in build_dist_artifact.py.
    retention_days_env = int(os.environ.get("REPORT_RETENTION_DAYS", "3"))
    retention_days = min(retention_days_env, 7)
    log.info("  [7/7] Purging HTML reports older than %d days from runner disk...",
             retention_days)
    results["report_purge"] = reclaim_old_html_reports(retention_days)
    mb_freed = results["report_purge"].get("mb_freed", 0)
    log.info("        Report purge freed %.1f MB from runner disk", mb_freed)

    if include_dist:
        log.info("  [+dist] Wiping previous dist/ directory...")
        results["dist_files_removed"] = reclaim_dist()
        log.info("          Removed %d dist/ files", results["dist_files_removed"])

    return results


# ─────────────────────────────────────────────────────────────────────────────
# TELEMETRY EMISSION
# ─────────────────────────────────────────────────────────────────────────────

def emit_disk_telemetry(stats: Dict, label: str = "checkpoint", extra: Optional[Dict] = None):
    """Write disk telemetry JSON to data/telemetry/."""
    DISK_TELEMETRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    record = {
        "timestamp":    datetime.now(timezone.utc).isoformat(),
        "label":        label,
        "disk":         stats,
        "run_id":       os.environ.get("GITHUB_RUN_ID", "local"),
        "pipeline_version": os.environ.get("PIPELINE_VERSION", "unknown"),
    }
    if extra:
        record.update(extra)
    try:
        DISK_TELEMETRY_PATH.write_text(
            json.dumps(record, indent=2), encoding="utf-8"
        )
    except Exception as exc:
        log.warning("Could not write telemetry: %s", exc)


# ─────────────────────────────────────────────────────────────────────────────
# MODES
# ─────────────────────────────────────────────────────────────────────────────

def mode_preflight() -> int:
    """
    STAGE 0.00b: Pre-pipeline disk check.
    Fails hard if disk < THRESHOLD_CRITICAL_GB after reclaim attempt.
    """
    log.info("=" * 70)
    log.info("RUNNER DISK PRE-FLIGHT CHECK (v156.0)")
    log.info("=" * 70)
    stats = get_disk_stats()
    log.info("Disk state: %.2f GB free / %.2f GB total (%.1f%% used)",
             stats["free_gb"], stats["total_gb"], stats["used_pct"])

    emit_disk_telemetry(stats, "preflight_start")

    if stats["free_gb"] < THRESHOLD_CRITICAL_GB:
        log.error("CRITICAL: Only %.2f GB free (minimum: %d GB). Attempting reclaim...",
                  stats["free_gb"], THRESHOLD_CRITICAL_GB)
        run_full_reclaim(include_dist=True)
        stats2 = get_disk_stats()
        log.info("After reclaim: %.2f GB free", stats2["free_gb"])
        if stats2["free_gb"] < THRESHOLD_CRITICAL_GB:
            log.error("HARD FAIL: Disk still critically low (%.2f GB). "
                      "Pipeline cannot proceed safely.", stats2["free_gb"])
            emit_disk_telemetry(stats2, "preflight_hard_fail")
            return 1
        log.warning("Reclaim succeeded. Proceeding with caution (%.2f GB free).", stats2["free_gb"])
        return 2

    if stats["free_gb"] < THRESHOLD_LOW_GB:
        log.warning("LOW: %.2f GB free. Running preventive reclaim...", stats["free_gb"])
        run_full_reclaim(include_dist=False)
        stats2 = get_disk_stats()
        log.info("After preventive reclaim: %.2f GB free", stats2["free_gb"])
        emit_disk_telemetry(stats2, "preflight_low_reclaimed")
        return 2

    if stats["free_gb"] < THRESHOLD_SAFE_GB:
        log.warning("WARN: Only %.2f GB free (safe threshold: %d GB).",
                    stats["free_gb"], THRESHOLD_SAFE_GB)
        emit_disk_telemetry(stats, "preflight_warn")
        return 2

    log.info("OK: %.2f GB free — pre-flight passed.", stats["free_gb"])
    emit_disk_telemetry(stats, "preflight_ok")
    return 0


def mode_predist() -> int:
    """
    STAGE 5.4.5c: Pre-dist cleanup — reclaim before reports/ copy.
    This is the PRIMARY prevention for incident #1199.
    """
    log.info("=" * 70)
    log.info("PRE-DIST RUNNER DISK CLEANUP (v156.0 P0)")
    log.info("=" * 70)

    stats_before = get_disk_stats()
    log.info("Disk BEFORE cleanup: %.2f GB free / %.2f GB total",
             stats_before["free_gb"], stats_before["total_gb"])

    log.info("")
    log.info("Storage hotspots:")
    for h in get_storage_hotspots():
        log.info("  %-35s  %.3f GB  (%d files)",
                 h["path"], h["size_gb"], h["file_count"])

    log.info("")
    reclaim_results = run_full_reclaim(include_dist=True)

    stats_after = get_disk_stats()
    reclaimed_gb = round(stats_after["free_gb"] - stats_before["free_gb"], 2)
    log.info("")
    log.info("=" * 70)
    log.info("CLEANUP COMPLETE")
    log.info("  Before : %.2f GB free", stats_before["free_gb"])
    log.info("  After  : %.2f GB free", stats_after["free_gb"])
    log.info("  Reclaimed: +%.2f GB", reclaimed_gb)
    log.info("=" * 70)

    emit_disk_telemetry(stats_after, "predist_cleanup", {
        "reclaimed_gb": reclaimed_gb,
        "reclaim_details": reclaim_results,
        "before_free_gb": stats_before["free_gb"],
    })

    if stats_after["free_gb"] < THRESHOLD_CRITICAL_GB:
        log.error("HARD FAIL: Only %.2f GB free after full cleanup. "
                  "dist/ build cannot proceed (risk of runner OOM).", stats_after["free_gb"])
        return 1

    log.info("OK: %.2f GB free — safe to proceed with dist build.", stats_after["free_gb"])
    return 0


def mode_status() -> int:
    """Emit disk status JSON and log. Non-blocking."""
    stats = get_disk_stats()
    hotspots = get_storage_hotspots()
    log.info("=" * 60)
    log.info("RUNNER DISK STATUS")
    log.info("  Free    : %.2f GB", stats["free_gb"])
    log.info("  Used    : %.2f GB (%.1f%%)", stats["used_gb"], stats["used_pct"])
    log.info("  Total   : %.2f GB", stats["total_gb"])
    log.info("  Hotspots:")
    for h in hotspots[:5]:
        log.info("    %-30s %.3f GB (%d files)", h["path"], h["size_gb"], h["file_count"])
    log.info("=" * 60)
    emit_disk_telemetry(stats, "status_checkpoint", {"hotspots": hotspots})
    return 0


def mode_monitor(interval_s: int = 60) -> int:
    """Continuous disk monitor. Emits telemetry every interval_s seconds."""
    log.info("Starting continuous disk monitor (interval=%ds). Ctrl-C to stop.", interval_s)
    while True:
        stats = get_disk_stats()
        level = "OK"
        if stats["free_gb"] < THRESHOLD_CRITICAL_GB:
            level = "CRITICAL"
        elif stats["free_gb"] < THRESHOLD_LOW_GB:
            level = "LOW"
        elif stats["free_gb"] < THRESHOLD_SAFE_GB:
            level = "WARN"
        log.info("[%s] %.2f GB free / %.2f GB total (%.1f%% used)",
                 level, stats["free_gb"], stats["total_gb"], stats["used_pct"])
        emit_disk_telemetry(stats, f"monitor_{level.lower()}")
        if stats["free_gb"] < THRESHOLD_CRITICAL_GB:
            log.error("CRITICAL disk level detected — triggering emergency reclaim")
            run_full_reclaim(include_dist=False)
        try:
            time.sleep(interval_s)
        except KeyboardInterrupt:
            log.info("Monitor stopped.")
            break
    return 0


# ─────────────────────────────────────────────────────────────────────────────
# ENTRY POINT
# ─────────────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Runner Disk Governor v156.0"
    )
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--preflight",  action="store_true",
                       help="Pre-pipeline disk gate (STAGE 0.00b)")
    group.add_argument("--predist",    action="store_true",
                       help="Pre-dist cleanup (STAGE 5.4.5c)")
    group.add_argument("--status",     action="store_true",
                       help="Emit disk status telemetry (non-blocking)")
    group.add_argument("--monitor",    type=int, metavar="INTERVAL_S",
                       help="Continuous monitor every N seconds")
    args = parser.parse_args()

    if args.preflight:
        return mode_preflight()
    elif args.predist:
        return mode_predist()
    elif args.status:
        return mode_status()
    elif args.monitor is not None:
        return mode_monitor(args.monitor)
    else:
        parser.print_help()
        return 1


if __name__ == "__main__":
    sys.exit(main())
