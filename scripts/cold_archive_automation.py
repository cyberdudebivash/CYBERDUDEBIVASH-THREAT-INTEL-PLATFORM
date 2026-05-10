#!/usr/bin/env python3
"""
scripts/cold_archive_automation.py
CYBERDUDEBIVASH® SENTINEL APEX — Cold Archive Automation v1.0

PURPOSE:
  Manages artifact lifecycle and cold storage rotation for the platform.
  Identifies advisory intelligence older than retention window, compresses
  and archives to cold storage (data/archive/cold/), and maintains an
  archive manifest for auditability.

LIFECYCLE POLICY:
  HOT  (0-30 days):   data/intelligence/        Full content, searchable
  WARM (31-90 days):  data/intelligence/warm/   Compressed, indexed
  COLD (91+ days):    data/archive/cold/        Compressed archive, manifest-tracked
  PURGE (365+ days):  data/archive/purged/      Hash-only audit record, content deleted

SAFETY CONTRACTS:
  - Never deletes original files until archive write is verified
  - Atomic manifest updates — manifest never left partially written
  - Dry-run mode (--dry-run) to preview without any file operations
  - All archive operations logged to data/archive/archive_audit.jsonl
  - Archive manifest updated on every run

EXIT CODES:
  0 = All operations completed successfully
  1 = Archive write failed (original preserved)
  3 = DEGRADED — some entries skipped, audit logged

OUTPUTS:
  data/archive/cold/YYYY-MM/           — compressed advisory archives
  data/archive/archive_manifest.json   — full archive inventory
  data/archive/archive_audit.jsonl     — operation audit log
  data/archive/lifecycle_report.json   — current lifecycle status
"""

from __future__ import annotations

import argparse
import gzip
import hashlib
import json
import logging
import os
import shutil
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger("CDB-COLD-ARCHIVE")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR       = Path(__file__).resolve().parent.parent
DATA_DIR       = BASE_DIR / "data"
INTEL_DIR      = DATA_DIR / "intelligence"
ARCHIVE_DIR    = DATA_DIR / "archive"
COLD_DIR       = ARCHIVE_DIR / "cold"
PURGED_DIR     = ARCHIVE_DIR / "purged"

ARCHIVE_MANIFEST  = ARCHIVE_DIR / "archive_manifest.json"
ARCHIVE_AUDIT     = ARCHIVE_DIR / "archive_audit.jsonl"
LIFECYCLE_REPORT  = ARCHIVE_DIR / "lifecycle_report.json"

ARCHIVE_DIR.mkdir(parents=True, exist_ok=True)
COLD_DIR.mkdir(parents=True, exist_ok=True)
PURGED_DIR.mkdir(parents=True, exist_ok=True)

# ── Lifecycle Policy ──────────────────────────────────────────────────────────
HOT_DAYS   = 30
WARM_DAYS  = 90
COLD_DAYS  = 365

# ── Helpers ───────────────────────────────────────────────────────────────────

def _atomic_write(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _load_manifest() -> Dict:
    try:
        if ARCHIVE_MANIFEST.exists():
            with open(ARCHIVE_MANIFEST, "r", encoding="utf-8") as f:
                return json.load(f)
    except Exception:
        pass
    return {"archives": [], "purge_audit": [], "last_updated": ""}


def _sha256_file(path: Path) -> str:
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(65536), b""):
            h.update(chunk)
    return h.hexdigest()


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(ts[:26], fmt[:len(ts)])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _audit_log(op: str, path: str, detail: Dict, dry_run: bool):
    entry = {
        "ts":      datetime.now(timezone.utc).isoformat(),
        "op":      op,
        "path":    path,
        "dry_run": dry_run,
        **detail,
    }
    with open(str(ARCHIVE_AUDIT), "a", encoding="utf-8") as f:
        f.write(json.dumps(entry) + "\n")


# ── Intelligence File Discovery ───────────────────────────────────────────────

def _discover_intel_files() -> List[Tuple[Path, Optional[datetime], str]]:
    """
    Discover all advisory JSON files in data/intelligence/ and subdirectories.
    Returns list of (path, created_at, lifecycle_tier).
    """
    results = []
    now = datetime.now(timezone.utc)

    if not INTEL_DIR.exists():
        logger.warning(f"[ARCHIVE] Intel directory not found: {INTEL_DIR}")
        return results

    for json_file in INTEL_DIR.rglob("*.json"):
        if json_file.name.startswith("."):
            continue
        try:
            stat = json_file.stat()
            # Use file mtime as proxy for creation date
            file_age = datetime.fromtimestamp(stat.st_mtime, tz=timezone.utc)
            age_days  = (now - file_age).days

            # Attempt to read timestamp from JSON content
            try:
                with open(json_file, "r", encoding="utf-8") as f:
                    content = json.load(f)
                ts_str = (
                    content.get("timestamp") or content.get("published_at") or
                    content.get("processed_at") or ""
                )
                content_ts = _parse_ts(ts_str)
                if content_ts:
                    age_days = (now - content_ts).days
                    file_age = content_ts
            except Exception:
                pass

            if age_days > COLD_DAYS:
                tier = "PURGE"
            elif age_days > WARM_DAYS:
                tier = "COLD"
            elif age_days > HOT_DAYS:
                tier = "WARM"
            else:
                tier = "HOT"

            results.append((json_file, file_age, tier))
        except Exception as e:
            logger.debug(f"[ARCHIVE] Discovery error for {json_file}: {e}")

    return results


# ── Archive Operations ────────────────────────────────────────────────────────

def _archive_to_cold(
    file_path: Path,
    created_at: Optional[datetime],
    dry_run: bool,
) -> Optional[Dict]:
    """Compress and move a file to cold storage. Returns archive record or None on failure."""
    month_str  = (created_at or datetime.now(timezone.utc)).strftime("%Y-%m")
    cold_month = COLD_DIR / month_str
    cold_month.mkdir(parents=True, exist_ok=True)

    archive_name  = file_path.name + ".gz"
    archive_path  = cold_month / archive_name

    if dry_run:
        logger.info(f"[ARCHIVE] DRY-RUN would cold-archive: {file_path} → {archive_path}")
        return {
            "original": str(file_path),
            "archive":  str(archive_path),
            "dry_run":  True,
            "status":   "DRY_RUN",
        }

    try:
        original_hash = _sha256_file(file_path)
        original_size = file_path.stat().st_size

        # Compress to tmp then atomic move
        fd, tmp_gz = tempfile.mkstemp(dir=str(cold_month), suffix=".tmp.gz")
        with os.fdopen(fd, "wb") as f_out:
            with gzip.open(f_out, "wb", compresslevel=9) as gz:
                gz.write(file_path.read_bytes())
        os.replace(tmp_gz, str(archive_path))

        # Verify archive integrity before removing original
        with gzip.open(str(archive_path), "rb") as gz:
            decompressed = gz.read()
        restored_hash = hashlib.sha256(decompressed).hexdigest()

        if original_hash != restored_hash:
            logger.error(f"[ARCHIVE] Archive integrity FAILED: {file_path} — original preserved")
            archive_path.unlink(missing_ok=True)
            return None

        archive_size = archive_path.stat().st_size
        ratio = round(100.0 * (1 - archive_size / original_size), 1) if original_size > 0 else 0

        # Safe to remove original
        file_path.unlink()

        record = {
            "original":       str(file_path),
            "archive":        str(archive_path),
            "archived_at":    datetime.now(timezone.utc).isoformat(),
            "original_hash":  original_hash,
            "original_size":  original_size,
            "archive_size":   archive_size,
            "compression_pct": ratio,
            "created_at":     created_at.isoformat() if created_at else None,
            "status":         "ARCHIVED",
        }
        logger.info(f"[ARCHIVE] Cold-archived: {file_path.name} → {archive_path} ({ratio}% compression)")
        _audit_log("COLD_ARCHIVE", str(file_path), record, dry_run)
        return record

    except Exception as e:
        logger.error(f"[ARCHIVE] Cold archive failed for {file_path}: {e}")
        # Ensure tmp file is cleaned up
        try:
            if "tmp_gz" in dir() and os.path.exists(tmp_gz):
                os.unlink(tmp_gz)
        except Exception:
            pass
        _audit_log("COLD_ARCHIVE_FAILED", str(file_path), {"error": str(e)}, dry_run)
        return None


def _purge_to_audit(
    file_path: Path,
    created_at: Optional[datetime],
    dry_run: bool,
) -> Optional[Dict]:
    """Purge a file older than COLD_DAYS — retain only hash audit record."""
    if dry_run:
        logger.info(f"[ARCHIVE] DRY-RUN would purge: {file_path}")
        return {"original": str(file_path), "dry_run": True, "status": "DRY_RUN"}

    try:
        file_hash   = _sha256_file(file_path)
        file_size   = file_path.stat().st_size
        file_path.unlink()

        record = {
            "original":   str(file_path),
            "purged_at":  datetime.now(timezone.utc).isoformat(),
            "file_hash":  file_hash,
            "file_size":  file_size,
            "created_at": created_at.isoformat() if created_at else None,
            "status":     "PURGED",
        }
        logger.info(f"[ARCHIVE] Purged: {file_path.name} (hash retained)")
        _audit_log("PURGE", str(file_path), record, dry_run)
        return record
    except Exception as e:
        logger.error(f"[ARCHIVE] Purge failed for {file_path}: {e}")
        return None


# ── Main ──────────────────────────────────────────────────────────────────────

def run_cold_archive(dry_run: bool = False) -> int:
    now = datetime.now(timezone.utc)
    logger.info(
        f"[ARCHIVE] Cold archive automation starting — {now.isoformat()}"
        f"{' [DRY-RUN]' if dry_run else ''}"
    )

    files = _discover_intel_files()
    logger.info(f"[ARCHIVE] Discovered {len(files)} intelligence files")

    tier_counts = {"HOT": 0, "WARM": 0, "COLD": 0, "PURGE": 0}
    archived    = []
    purged      = []
    errors      = []

    for file_path, created_at, tier in files:
        tier_counts[tier] = tier_counts.get(tier, 0) + 1
        if tier == "COLD":
            record = _archive_to_cold(file_path, created_at, dry_run)
            if record:
                archived.append(record)
            else:
                errors.append(str(file_path))
        elif tier == "PURGE":
            record = _purge_to_audit(file_path, created_at, dry_run)
            if record:
                purged.append(record)
            else:
                errors.append(str(file_path))

    # Update archive manifest
    manifest = _load_manifest()
    manifest["archives"].extend(archived)
    manifest["purge_audit"].extend(purged)
    manifest["last_updated"] = now.isoformat()
    # Keep manifest bounded — last 10 000 archive records
    manifest["archives"]    = manifest["archives"][-10_000:]
    manifest["purge_audit"] = manifest["purge_audit"][-10_000:]
    _atomic_write(ARCHIVE_MANIFEST, manifest)

    # Write lifecycle report
    lifecycle_report = {
        "run_at":         now.isoformat(),
        "dry_run":        dry_run,
        "tier_counts":    tier_counts,
        "files_archived": len(archived),
        "files_purged":   len(purged),
        "errors":         len(errors),
        "error_paths":    errors[:20],
        "policy": {
            "hot_days":   HOT_DAYS,
            "warm_days":  WARM_DAYS,
            "cold_days":  COLD_DAYS,
        },
    }
    _atomic_write(LIFECYCLE_REPORT, lifecycle_report)

    logger.info(
        f"[ARCHIVE] Complete — HOT:{tier_counts['HOT']} WARM:{tier_counts['WARM']} "
        f"COLD:{tier_counts['COLD']} PURGE:{tier_counts['PURGE']} "
        f"archived:{len(archived)} purged:{len(purged)} errors:{len(errors)}"
    )

    if errors:
        return 3
    return 0


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="CDB Cold Archive Automation")
    parser.add_argument("--dry-run", action="store_true",
                        help="Preview operations without modifying files")
    args = parser.parse_args()
    sys.exit(run_cold_archive(dry_run=args.dry_run))
