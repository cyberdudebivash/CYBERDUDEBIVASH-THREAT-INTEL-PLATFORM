#!/usr/bin/env python3
"""
janitor.py — CYBERDUDEBIVASH® SENTINEL APEX
PRODUCTION WORKSPACE PURIFICATION ENGINE
Mandate: Remove test artifacts while preserving core persistence data.
"""

import os
import shutil
import logging

# --- Institutional Logging ---
logging.basicConfig(level=logging.INFO, format="[CDB-JANITOR] %(message)s")
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
        """Surgically cleans the data/ directory for production."""
        logger.info("🛡️ INITIATING WORKSPACE PURIFICATION...")

        for target in self.purge_targets:
            if os.path.exists(target):
                # Count files before deletion for reporting
                files = os.listdir(target)
                if files:
                    logger.info(f"Purging {len(files)} test files from {target}...")
                    for f in files:
                        file_path = os.path.join(target, f)
                        try:
                            if os.path.isfile(file_path) or os.path.islink(file_path):
                                os.unlink(file_path)
                            elif os.path.isdir(file_path):
                                shutil.rmtree(file_path)
                        except Exception as e:
                            logger.error(f"Failed to delete {file_path}: {e}")
                else:
                    logger.info(f"Directory {target} is already clean.")
            else:
                os.makedirs(target, exist_ok=True)
                logger.info(f"Initialized production directory: {target}")

        logger.info("✅ PURIFICATION COMPLETE. System is ready for Sovereign Run v16.2.")

if __name__ == "__main__":
    janitor = WorkspaceJanitor()
    janitor.run_purification()
