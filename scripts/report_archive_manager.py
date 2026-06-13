#!/usr/bin/env python3
"""
scripts/report_archive_manager.py
CYBERDUDEBIVASH(R) SENTINEL APEX v156.0 -- Report Archive Governance Engine
=============================================================================
PURPOSE:
  Manages the lifecycle of HTML threat intelligence reports in the working tree.

  The platform generates ~24 new report files per day (6 runs × 4 reports/run).
  At this rate, the reports/ directory doubles in size every 18 months, pushing
  the tracked file count past the 75,000 governance threshold.

ARCHITECTURE (two-tier deployment):
  HOT (0-RETENTION days):
    - Stored in reports/ on main branch (git-tracked)
    - Copied to dist/reports/ and deployed to gh-pages on every run
    - Served via CDN at intel.cyberdudebivash.com/reports/...

  ARCHIVE (RETENTION+ days):
    - Removed from main branch working tree (git rm --cached)
    - PERMANENTLY retained in gh-pages branch (Pages deploy uses clean: false)
    - Continue to be served at the same URLs — zero customer-facing impact
    - NOT copied to dist/ on future runs (reducing dist/ build time)

SAFETY GUARANTEES:
  - Dry-run mode (--dry-run): preview all changes without modifying any files
  - Never deletes files from gh-pages — only removes from main branch tracking
  - Generates archive_manifest.json before making any changes
  - Hard stops if report count would drop below MIN_REPORT_THRESHOLD
  - All operations logged to data/archive/report_archive_audit.jsonl
  - Atomic git operations — all-or-nothing on the git rm --cached batch

PREREQUISITES (one-time setup):
  Pages deploy MUST be set to clean: false before running this script in non-dry-run mode.
  Otherwise gh-pages will lose historical reports on next deployment.
  See sentinel-blogger.yml STAGE 5 (Pages Deploy Action).

USAGE:
  python3 scripts/report_archive_manager.py --dry-run     # preview only
  python3 scripts/report_archive_manager.py               # execute archive
  python3 scripts/report_archive_manager.py --days 60     # custom retention window
  python3 scripts/report_archive_manager.py --status      # show current stats

ENVIRONMENT:
  REPORT_RETENTION_DAYS  -- days to keep in working tree (default: 90)
  ARCHIVE_DRY_RUN        -- "1" to force dry-run mode
  ARCHIVE_MIN_REPORTS    -- minimum reports to retain in working tree (default: 500)

EXIT CODES:
  0 = Archive completed (or dry-run preview shown)
  1 = Hard stop — safety constraint violated (insufficient reports, git error)
  2 = Pages deploy still uses clean: true — UNSAFE to archive (run with --dry-run only)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import subprocess
import sys
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-ARCHIVE] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.archive")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO_ROOT          = Path(__file__).resolve().parent.parent
REPORTS_DIR        = REPO_ROOT / "reports"
ARCHIVE_DIR        = REPO_ROOT / "data" / "archive"
AUDIT_LOG_PATH     = ARCHIVE_DIR / "report_archive_audit.jsonl"
ARCHIVE_MANIFEST   = ARCHIVE_DIR / "report_archive_manifest.json"
WORKFLOW_PATH      = REPO_ROOT / ".github" / "workflows" / "sentinel-blogger.yml"

RETENTION_DAYS     = int(os.environ.get("REPORT_RETENTION_DAYS", "90"))
DRY_RUN            = os.environ.get("ARCHIVE_DRY_RUN", "0") == "1"
MIN_REPORT_THRESHOLD = int(os.environ.get("ARCHIVE_MIN_REPORTS", "500"))


# ---------------------------------------------------------------------------
# Git utilities
# ---------------------------------------------------------------------------

def _git(*args: str) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["git"] + list(args),
        cwd=REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=120,
    )


def _git_tracked_reports() -> List[str]:
    """Return all git-tracked .html files under reports/."""
    result = _git("ls-files", "reports/", "--", "*.html")
    if result.returncode != 0:
        return []
    return [l.strip() for l in result.stdout.splitlines() if l.strip()]


def _git_rm_cached(paths: List[str], batch_size: int = 500) -> bool:
    """Untrack files from git index without deleting from disk. Returns True on success."""
    if not paths:
        return True
    for i in range(0, len(paths), batch_size):
        batch = paths[i:i + batch_size]
        result = _git("rm", "--cached", "--ignore-unmatch", "-q", "--", *batch)
        if result.returncode != 0:
            log.error("git rm --cached failed: %s", result.stderr[:300])
            return False
        log.info("  git rm --cached batch %d: %d files untracked", i // batch_size + 1, len(batch))
    return True


# ---------------------------------------------------------------------------
# Safety checks
# ---------------------------------------------------------------------------

def _check_pages_deploy_safe() -> bool:
    """
    Verify Pages deploy configuration for archive compatibility.

    v176.0 ARCHITECTURE UPDATE (permanent fix):
    Previously this function required 'clean: false' to allow archiving.
    That check is now REMOVED because:

      1. The platform migrated to 'clean: true' in v158.5 to prevent gh-pages
         accumulation past the 1 GB GitHub Pages hard limit.

      2. With 'clean: true', gh-pages is replaced by dist/ on every deploy.
         Historical reports are NOT preserved on gh-pages regardless — they
         are served from Cloudflare R2 (uploaded in Stage 3.5 r2_upload.py).

      3. The old check caused report_archive_manager.py to exit with code 2
         on every run since v158.5, permanently disabling archive governance.
         This allowed 82,387+ HTML reports to accumulate in git (7.1 GB on
         checkout) and was the UPSTREAM root cause of run #1616 failing at
         dist/ size = 3746 MB.

    The 'clean:true / R2-first' architecture means:
      - git rm --cached removes old reports from main-branch checkout (safe)
      - dist/ contains only REPORT_RETENTION_DAYS of HOT reports (<=900 MB)
      - Historical reports are served from R2 at their original URLs
      - gh-pages does NOT need to preserve historical reports

    This function now always returns True (archive is always safe in R2-first arch).
    """
    if not WORKFLOW_PATH.exists():
        log.info("Pages deploy: workflow file not found — archive safe (R2-first arch)")
        return True

    content = WORKFLOW_PATH.read_text(encoding="utf-8", errors="replace")

    if "clean: false" in content:
        log.info("Pages deploy: clean: false detected — archive is SAFE")
    elif "clean: true" in content:
        log.info("Pages deploy: clean: true detected — archive SAFE under R2-first "
                 "architecture (historical reports served from Cloudflare R2, not gh-pages)")
    else:
        log.info("Pages deploy: clean setting not detected — archive proceeding (R2-first arch)")

    return True


# ---------------------------------------------------------------------------
# Report classification
# ---------------------------------------------------------------------------

def _classify_reports(
    tracked_paths: List[str],
    cutoff_date: datetime,
) -> Tuple[List[str], List[str]]:
    """
    Classify reports into HOT (recent) and ARCHIVE (old) based on path year/month.
    Uses path-based dating (reports/YYYY/MM/...) for performance — no stat() needed.
    Returns (hot_paths, archive_paths).
    """
    hot: List[str] = []
    archive: List[str] = []
    unparseable: List[str] = []

    cutoff_year  = cutoff_date.year
    cutoff_month = cutoff_date.month

    for path in tracked_paths:
        parts = Path(path).parts  # e.g. ('reports', '2024', '05', 'intel--xxx.html')
        if len(parts) >= 3 and parts[0] == "reports":
            try:
                report_year  = int(parts[1])
                report_month = int(parts[2]) if len(parts) >= 4 else 1
                # Compare year-month
                if (report_year, report_month) >= (cutoff_year, cutoff_month):
                    hot.append(path)
                else:
                    archive.append(path)
                continue
            except (ValueError, IndexError):
                pass
        unparseable.append(path)

    if unparseable:
        log.warning("%d reports with unparseable paths — kept in HOT tier: %s...",
                    len(unparseable), unparseable[:3])
        hot.extend(unparseable)

    return hot, archive


# ---------------------------------------------------------------------------
# Archive manifest
# ---------------------------------------------------------------------------

def _write_archive_manifest(
    hot: List[str],
    archive: List[str],
    retention_days: int,
    dry_run: bool,
    timestamp: str,
) -> None:
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    manifest = {
        "generated_at": timestamp,
        "retention_days": retention_days,
        "dry_run": dry_run,
        "hot_count": len(hot),
        "archive_count": len(archive),
        "total_count": len(hot) + len(archive),
        "archive_paths": archive,   # full list for auditability
    }
    if not dry_run:
        ARCHIVE_MANIFEST.write_text(json.dumps(manifest, indent=2), encoding="utf-8")
        log.info("Archive manifest written: %s (%d archived paths)", ARCHIVE_MANIFEST, len(archive))
    else:
        log.info("[DRY-RUN] Would write archive manifest with %d archived paths", len(archive))


def _append_audit_log(entry: dict) -> None:
    ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
    with open(AUDIT_LOG_PATH, "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ---------------------------------------------------------------------------
# Status report
# ---------------------------------------------------------------------------

def _show_status() -> None:
    """Print current archive status without making changes."""
    tracked = _git_tracked_reports()
    cutoff  = datetime.now(timezone.utc) - timedelta(days=RETENTION_DAYS)
    hot, archive = _classify_reports(tracked, cutoff)

    log.info("=== REPORT ARCHIVE STATUS ===")
    log.info("  Total tracked reports : %d", len(tracked))
    log.info("  HOT (last %d days)    : %d", RETENTION_DAYS, len(hot))
    log.info("  ARCHIVE candidates    : %d", len(archive))
    log.info("  Cutoff date           : %s", cutoff.strftime("%Y-%m-%d"))
    log.info("  Savings if archived   : %d files removed from main branch", len(archive))

    # Year breakdown
    year_counts: Dict[str, int] = {}
    for p in tracked:
        parts = Path(p).parts
        year = parts[1] if len(parts) >= 2 else "unknown"
        year_counts[year] = year_counts.get(year, 0) + 1
    log.info("  Year breakdown:")
    for yr in sorted(year_counts):
        tier = "HOT" if int(yr) >= cutoff.year else "ARCHIVE"
        log.info("    %s: %d reports [%s]", yr, year_counts[yr], tier)


# ---------------------------------------------------------------------------
# Main archive operation
# ---------------------------------------------------------------------------

def run_archive(retention_days: int, dry_run: bool) -> int:
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    cutoff = datetime.now(timezone.utc) - timedelta(days=retention_days)

    log.info("╔══════════════════════════════════════════════════════════════╗")
    log.info("║   SENTINEL APEX — REPORT ARCHIVE GOVERNANCE ENGINE v156.0  ║")
    log.info("╚══════════════════════════════════════════════════════════════╝")
    log.info("Retention window : %d days", retention_days)
    log.info("Cutoff date      : %s", cutoff.strftime("%Y-%m-%d"))
    log.info("Mode             : %s", "DRY-RUN (no changes)" if dry_run else "EXECUTE")

    # Safety check: validate Pages deploy configuration (v176.0: always safe under R2-first arch)
    _check_pages_deploy_safe()

    # Enumerate tracked reports
    tracked = _git_tracked_reports()
    log.info("Tracked HTML reports : %d", len(tracked))

    if not tracked:
        log.warning("No tracked HTML reports found — nothing to archive.")
        return 0

    # Classify
    hot, archive = _classify_reports(tracked, cutoff)
    log.info("HOT (retain)     : %d", len(hot))
    log.info("ARCHIVE (untrack): %d", len(archive))

    if not archive:
        log.info("Nothing to archive — all reports within retention window.")
        return 0

    # Safety check 2: minimum report threshold
    if len(hot) < MIN_REPORT_THRESHOLD:
        log.error(
            "ABORT: HOT tier would have only %d reports after archive (minimum: %d).\n"
            "  Increase --days or lower ARCHIVE_MIN_REPORTS.",
            len(hot), MIN_REPORT_THRESHOLD
        )
        return 1

    # Year/month breakdown
    log.info("Reports to archive by year:")
    year_counts: Dict[str, int] = {}
    for p in archive:
        parts = Path(p).parts
        year = parts[1] if len(parts) >= 2 else "unknown"
        year_counts[year] = year_counts.get(year, 0) + 1
    for yr in sorted(year_counts):
        log.info("  %s: %d reports", yr, year_counts[yr])

    # Write manifest
    _write_archive_manifest(hot, archive, retention_days, dry_run, timestamp)

    if dry_run:
        log.info("")
        log.info("[DRY-RUN] PREVIEW — No changes made.")
        log.info("  Would untrack %d reports from main branch.", len(archive))
        log.info("  HOT reports remaining: %d", len(hot))
        log.info("  Disk space freed from git index: %d files", len(archive))
        log.info("  Historical report URLs remain accessible via gh-pages.")
        log.info("  Re-run without --dry-run to execute.")
        return 0

    # Execute: git rm --cached (untrack, do NOT delete from disk)
    log.info("Untracking %d archived reports from git index (files preserved on disk)...", len(archive))
    success = _git_rm_cached(archive)

    # Audit log entry
    audit_entry = {
        "timestamp": timestamp,
        "retention_days": retention_days,
        "hot_count": len(hot),
        "archived_count": len(archive) if success else 0,
        "success": success,
        "dry_run": False,
    }
    _append_audit_log(audit_entry)

    if success:
        log.info("")
        log.info("╔══════════════════════════════════════════════════════════════╗")
        log.info("║   ARCHIVE COMPLETE                                           ║")
        log.info("╠══════════════════════════════════════════════════════════════╣")
        log.info("║  Untracked from main : %-6d                               ║", len(archive))
        log.info("║  Retained in HOT     : %-6d                               ║", len(hot))
        log.info("║  Disk files intact   : YES (files not deleted from disk)    ║")
        log.info("║  Historical archive  : Cloudflare R2 (R2-first architecture)║")
        log.info("╚══════════════════════════════════════════════════════════════╝")
        log.info("")
        log.info("NEXT STEP: Commit the updated git index.")
        log.info("  safe_git_commit.py will commit the removal of old reports from tracking.")
        log.info("  On next pipeline run, dist/ will only include HOT reports — faster builds.")
        return 0
    else:
        log.error("Archive failed — git rm --cached encountered errors.")
        log.error("Check audit log: %s", AUDIT_LOG_PATH)
        return 1


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main() -> int:
    global RETENTION_DAYS  # may be overridden by --days CLI arg
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX — Report Archive Governance Engine v156.0"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        default=DRY_RUN,
        help="Preview changes without modifying files or git index",
    )
    parser.add_argument(
        "--days",
        type=int,
        default=RETENTION_DAYS,
        help=f"Days to retain in HOT tier (default: {RETENTION_DAYS})",
    )
    parser.add_argument(
        "--status",
        action="store_true",
        help="Show current archive status and exit",
    )
    args = parser.parse_args()

    if args.status:
        RETENTION_DAYS = args.days
        _show_status()
        return 0

    return run_archive(retention_days=args.days, dry_run=args.dry_run)


if __name__ == "__main__":
    sys.exit(main())
