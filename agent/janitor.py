#!/usr/bin/env python3
"""
janitor.py — CYBERDUDEBIVASH® SENTINEL APEX v17.0
PRODUCTION WORKSPACE PURIFICATION + INTELLIGENCE ARCHIVING ENGINE

v17.0 ENHANCEMENTS (non-breaking):
  - Integrated archive engine: archives STIX + PDF reports older than 15 days
  - Full structured logging throughout purification and archiving
  - Runs archive pass before purification to prevent data loss
  - Reports comprehensive summary of all operations performed
"""

import os
import shutil
import logging
from datetime import datetime, timezone

# --- Institutional Logging ---
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-JANITOR] %(message)s"
)
logger = logging.getLogger("CDB-JANITOR")


class WorkspaceJanitor:
    def __init__(self):
        # Directories to be purged of test artifacts
        self.purge_targets = [
            "data/rule_packs",
            "data/playbooks",
            "data/certificates",
            "data/enterprise_kits",
            "data/temp"
        ]
        # Critical files to PRESERVE (Persistence)
        self.preservation_list = [
            "data/blogger_processed.json",
            "data/blogger_sentinel_manifest.json"
        ]

    def run_purification(self):
        """
        Surgically cleans the data/ directory for production.
        v17.0: Also runs archive pass for reports older than 15 days.
        """
        logger.info("🛡️  INITIATING WORKSPACE PURIFICATION + ARCHIVE PASS...")
        logger.info(f"   Timestamp: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M:%S UTC')}")

        # ── STEP 1: Archive old reports BEFORE purification (data safety first) ──
        self._run_archive_pass()

        # ── STEP 2: Purge test artifact directories ──
        purged_total = 0
        initialized_dirs = []

        for target in self.purge_targets:
            if os.path.exists(target):
                files = os.listdir(target)
                if files:
                    logger.info(f"🗑️  Purging {len(files)} test files from {target}...")
                    for f in files:
                        file_path = os.path.join(target, f)
                        try:
                            if os.path.isfile(file_path) or os.path.islink(file_path):
                                os.unlink(file_path)
                                purged_total += 1
                            elif os.path.isdir(file_path):
                                shutil.rmtree(file_path)
                                purged_total += 1
                        except Exception as e:
                            logger.error(f"   ❌ Failed to delete {file_path}: {e}")
                else:
                    logger.info(f"✅ Directory {target} is already clean.")
            else:
                os.makedirs(target, exist_ok=True)
                initialized_dirs.append(target)
                logger.info(f"📁 Initialized production directory: {target}")

        # ── STEP 3: Summary ──
        logger.info(
            f"✅ PURIFICATION COMPLETE | "
            f"Files purged: {purged_total} | "
            f"Dirs initialized: {len(initialized_dirs)} | "
            f"System ready for Sovereign Run v17.0."
        )

    def _run_archive_pass(self):
        """
        Run the archive engine to move reports older than 15 days.
        Non-destructive: moves to data/archive/, never deletes.
        """
        try:
            logger.info("🗄️  Running archive pass (retention: 15 days)...")
            from agent.core.archive_engine import ArchiveEngine
            engine = ArchiveEngine(retention_days=15)
            summary = engine.run_full_archive()
            logger.info(
                f"   Archive pass complete | "
                f"STIX archived: {summary.get('stix_bundles_archived', 0)} | "
                f"PDFs archived: {summary.get('whitepapers_archived', 0)} | "
                f"Total: {summary.get('total_archived', 0)}"
            )
        except ImportError:
            logger.warning("   Archive engine not available — skipping archive pass.")
        except Exception as e:
            logger.error(f"   Archive pass failed: {e} — continuing with purification.")


if __name__ == "__main__":
    janitor = WorkspaceJanitor()
    janitor.run_purification()
