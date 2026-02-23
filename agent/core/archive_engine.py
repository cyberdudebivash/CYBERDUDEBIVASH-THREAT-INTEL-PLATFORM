#!/usr/bin/env python3
"""
archive_engine.py — CyberDudeBivash SENTINEL APEX v17.0
INTELLIGENT REPORT ARCHIVING ENGINE

Mandate: Archive STIX bundles and reports older than 15 days
to data/archive/ to keep active workspace lean while preserving
full historical intelligence for auditing and analytics.

Features:
  - Archives STIX bundles older than 15 days (configurable)
  - Archives PDF whitepapers older than 15 days
  - Creates compressed .tar.gz archive batches by month
  - Updates feed_manifest.json to reflect archived entries
  - Updates manifest with archive reference pointer
  - Full structured logging throughout
  - NON-DESTRUCTIVE: moves, never deletes; data is always recoverable

Called by: janitor.py (monthly) and GitHub Actions archive step
"""

import os
import json
import gzip
import shutil
import tarfile
import logging
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Tuple, Optional

logger = logging.getLogger("CDB-ARCHIVE")

STIX_DIR = "data/stix"
WHITEPAPER_DIR = "data/whitepapers"
ARCHIVE_DIR = "data/archive"
MANIFEST_PATH = "data/stix/feed_manifest.json"
ARCHIVE_LOG_PATH = "data/archive/archive_log.json"

DEFAULT_RETENTION_DAYS = 15  # Archive items older than this


class ArchiveEngine:
    """
    Intelligent archiving engine for SENTINEL APEX intelligence data.
    Archives reports older than RETENTION_DAYS to data/archive/.
    Updates manifest to reflect archived entries with archive_ref pointers.
    """

    def __init__(self, retention_days: int = DEFAULT_RETENTION_DAYS):
        self.retention_days = retention_days
        self.cutoff_dt = datetime.now(timezone.utc) - timedelta(days=retention_days)
        os.makedirs(ARCHIVE_DIR, exist_ok=True)
        logger.info(
            f"🗄️  Archive Engine initialized | Retention: {retention_days} days | "
            f"Cutoff: {self.cutoff_dt.strftime('%Y-%m-%d %H:%M UTC')}"
        )

    def run_full_archive(self) -> Dict:
        """
        Execute full archiving pass:
          1. Archive STIX bundles older than retention_days
          2. Archive PDF whitepapers older than retention_days
          3. Compress archived batch into monthly tar.gz
          4. Update feed_manifest.json
          5. Log archive operation results

        Returns: summary dict with counts
        """
        logger.info("🗄️  INITIATING ARCHIVE PASS...")

        stix_archived = self._archive_stix_bundles()
        pdf_archived = self._archive_whitepapers()
        self._compress_old_archives()
        self._update_manifest_for_archived(stix_archived)

        summary = {
            "archive_run_at": datetime.now(timezone.utc).isoformat(),
            "retention_days": self.retention_days,
            "cutoff_date": self.cutoff_dt.isoformat(),
            "stix_bundles_archived": len(stix_archived),
            "whitepapers_archived": len(pdf_archived),
            "total_archived": len(stix_archived) + len(pdf_archived),
            "archived_files": stix_archived + pdf_archived,
        }

        self._persist_archive_log(summary)

        logger.info(
            f"✅ ARCHIVE COMPLETE | "
            f"STIX: {len(stix_archived)} | "
            f"PDFs: {len(pdf_archived)} | "
            f"Total: {summary['total_archived']} files archived"
        )

        return summary

    def _archive_stix_bundles(self) -> List[str]:
        """
        Move STIX JSON bundles older than retention_days to archive directory.
        Preserves feed_manifest.json in place.
        Returns list of archived filenames.
        """
        archived = []
        if not os.path.isdir(STIX_DIR):
            logger.warning(f"STIX directory not found: {STIX_DIR}")
            return archived

        stix_files = [
            f for f in os.listdir(STIX_DIR)
            if f.endswith(".json") and f != "feed_manifest.json"
        ]

        logger.info(f"📦 Scanning {len(stix_files)} STIX bundles for archival...")

        for filename in stix_files:
            filepath = os.path.join(STIX_DIR, filename)
            file_age_dt = self._get_file_datetime(filepath, filename)

            if file_age_dt and file_age_dt < self.cutoff_dt:
                dest_path = self._move_to_archive(filepath, filename, "stix")
                if dest_path:
                    archived.append(filename)
                    logger.info(
                        f"  📁 Archived STIX: {filename} "
                        f"(age: {self._age_str(file_age_dt)})"
                    )
            else:
                age_str = self._age_str(file_age_dt) if file_age_dt else "unknown age"
                logger.debug(f"  ⏸  Retained STIX: {filename} ({age_str})")

        return archived

    def _archive_whitepapers(self) -> List[str]:
        """
        Move PDF whitepapers older than retention_days to archive directory.
        Returns list of archived filenames.
        """
        archived = []
        if not os.path.isdir(WHITEPAPER_DIR):
            logger.debug(f"Whitepaper directory not found: {WHITEPAPER_DIR} — skipping")
            return archived

        pdf_files = [f for f in os.listdir(WHITEPAPER_DIR) if f.endswith(".pdf")]
        logger.info(f"📄 Scanning {len(pdf_files)} whitepapers for archival...")

        for filename in pdf_files:
            filepath = os.path.join(WHITEPAPER_DIR, filename)
            file_age_dt = self._get_file_datetime(filepath, filename)

            if file_age_dt and file_age_dt < self.cutoff_dt:
                dest_path = self._move_to_archive(filepath, filename, "whitepapers")
                if dest_path:
                    archived.append(filename)
                    logger.info(
                        f"  📁 Archived PDF: {filename} "
                        f"(age: {self._age_str(file_age_dt)})"
                    )

        return archived

    def _get_file_datetime(self, filepath: str, filename: str) -> Optional[datetime]:
        """
        Extract datetime from filename timestamp or file modification time.
        Filename format: CDB-APEX-{unix_timestamp}.json
        """
        # Try extracting Unix timestamp from filename (CDB-APEX-1771093953.json)
        parts = filename.replace(".json", "").replace(".pdf", "").split("-")
        for part in reversed(parts):
            if part.isdigit() and len(part) >= 9:
                try:
                    ts = int(part)
                    # Validate it's a plausible Unix timestamp (year 2020-2035)
                    if 1577836800 <= ts <= 2051222400:
                        return datetime.fromtimestamp(ts, tz=timezone.utc)
                except (ValueError, OSError):
                    pass

        # Fall back to file modification time
        try:
            mtime = os.path.getmtime(filepath)
            return datetime.fromtimestamp(mtime, tz=timezone.utc)
        except Exception:
            return None

    def _move_to_archive(self, src_path: str, filename: str, subfolder: str) -> Optional[str]:
        """Move a file to the archive directory, organized by month."""
        try:
            month_str = datetime.now(timezone.utc).strftime("%Y-%m")
            dest_dir = os.path.join(ARCHIVE_DIR, month_str, subfolder)
            os.makedirs(dest_dir, exist_ok=True)
            dest_path = os.path.join(dest_dir, filename)

            # Handle filename collision
            if os.path.exists(dest_path):
                base, ext = os.path.splitext(filename)
                dest_path = os.path.join(dest_dir, f"{base}_dup{ext}")

            shutil.move(src_path, dest_path)
            return dest_path
        except Exception as e:
            logger.error(f"  ❌ Failed to archive {filename}: {e}")
            return None

    def _compress_old_archives(self):
        """
        Compress archive subdirectories older than current month into .tar.gz.
        This keeps the archive directory organized and space-efficient.
        """
        current_month = datetime.now(timezone.utc).strftime("%Y-%m")
        if not os.path.isdir(ARCHIVE_DIR):
            return

        for month_dir in os.listdir(ARCHIVE_DIR):
            month_path = os.path.join(ARCHIVE_DIR, month_dir)
            if not os.path.isdir(month_path) or month_dir == current_month:
                continue
            # Check if already compressed
            tar_path = f"{month_path}.tar.gz"
            if os.path.exists(tar_path):
                continue
            try:
                with tarfile.open(tar_path, "w:gz") as tar:
                    tar.add(month_path, arcname=month_dir)
                shutil.rmtree(month_path)
                logger.info(f"🗜️  Compressed archive: {month_dir} → {tar_path}")
            except Exception as e:
                logger.warning(f"Compression failed for {month_dir}: {e}")

    def _update_manifest_for_archived(self, archived_filenames: List[str]):
        """
        Update feed_manifest.json to mark archived entries with
        archive_ref pointer instead of removing them.
        Preserves manifest integrity for dashboard.
        """
        if not archived_filenames or not os.path.exists(MANIFEST_PATH):
            return

        try:
            with open(MANIFEST_PATH, "r") as f:
                manifest = json.load(f)

            archived_set = set(archived_filenames)
            updated_count = 0

            for entry in manifest.get("entries", []):
                bundle_id = entry.get("bundle_id", "")
                # Match bundle_id suffix against archived filenames
                for archived_file in archived_set:
                    # CDB-APEX-{ts}.json → check if ts is in bundle_id
                    ts_part = archived_file.replace(".json", "").split("-")[-1]
                    if ts_part and ts_part in bundle_id:
                        entry["status"] = "archived"
                        entry["archive_ref"] = f"data/archive/{archived_file}"
                        updated_count += 1
                        break

            manifest["last_archive_run"] = datetime.now(timezone.utc).isoformat()
            manifest["archived_entry_count"] = sum(
                1 for e in manifest.get("entries", []) if e.get("status") == "archived"
            )

            with open(MANIFEST_PATH, "w") as f:
                json.dump(manifest, f, indent=2)

            logger.info(f"📋 Manifest updated: {updated_count} entries marked as archived")

        except Exception as e:
            logger.warning(f"Manifest archive update failed: {e}")

    def _persist_archive_log(self, summary: Dict):
        """Append archive run summary to rolling archive log."""
        try:
            existing = []
            if os.path.exists(ARCHIVE_LOG_PATH):
                with open(ARCHIVE_LOG_PATH, "r") as f:
                    existing = json.load(f)
            existing.append(summary)
            if len(existing) > 100:
                existing = existing[-100:]
            with open(ARCHIVE_LOG_PATH, "w") as f:
                json.dump(existing, f, indent=2)
        except Exception as e:
            logger.warning(f"Archive log persist failed: {e}")

    @staticmethod
    def _age_str(dt: Optional[datetime]) -> str:
        if not dt:
            return "unknown"
        age_days = (datetime.now(timezone.utc) - dt).days
        return f"{age_days}d old"


# Singleton instance
archive_engine = ArchiveEngine(retention_days=DEFAULT_RETENTION_DAYS)


def run_archive_pass(retention_days: int = DEFAULT_RETENTION_DAYS) -> Dict:
    """
    Convenience function: run archive pass with custom retention.
    Can be called directly: python -m agent.core.archive_engine
    """
    engine = ArchiveEngine(retention_days=retention_days)
    return engine.run_full_archive()


if __name__ == "__main__":
    import sys
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CDB-ARCHIVE] %(message)s"
    )
    days = int(sys.argv[1]) if len(sys.argv) > 1 else DEFAULT_RETENTION_DAYS
    result = run_archive_pass(days)
    print(json.dumps(result, indent=2))
