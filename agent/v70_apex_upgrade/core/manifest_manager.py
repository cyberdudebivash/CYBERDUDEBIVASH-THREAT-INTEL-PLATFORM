"""
SENTINEL APEX v70 — Manifest Manager
======================================
Versioned manifest management.
- manifest_latest.json = current production
- manifest_v{N}.json = immutable snapshots
- Never overwrites blindly
- Rollback capability
"""

import json
import logging
import os
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

from .schema_validator import (
    validate_manifest,
    safe_write_manifest,
    get_last_valid_manifest,
)
from .models import Advisory, Manifest

logger = logging.getLogger("sentinel.manifest_manager")


class ManifestManager:
    """
    Production manifest lifecycle manager.
    Handles versioning, validation, rollback, and atomic writes.
    """

    def __init__(self, data_dir: str = "data"):
        self.data_dir = data_dir
        self.latest_path = os.path.join(data_dir, "feed_manifest.json")
        self.versioned_dir = os.path.join(data_dir, "manifest_versions")
        self.backup_dir = os.path.join(data_dir, ".manifest_backups")
        os.makedirs(self.versioned_dir, exist_ok=True)
        os.makedirs(self.backup_dir, exist_ok=True)
        self._version_counter_file = os.path.join(self.versioned_dir, ".version_counter")

    def _next_version(self) -> int:
        """Get and increment the version counter."""
        v = 1
        if os.path.isfile(self._version_counter_file):
            try:
                with open(self._version_counter_file, "r") as f:
                    v = int(f.read().strip()) + 1
            except (ValueError, IOError):
                v = 1
        with open(self._version_counter_file, "w") as f:
            f.write(str(v))
        return v

    def load_current(self) -> Optional[Dict[str, Any]]:
        """Load the current valid manifest (with fallback to backups)."""
        data = get_last_valid_manifest(self.latest_path, self.backup_dir)
        if data is None:
            logger.warning("No valid manifest found — starting fresh")
        return data

    def load_current_advisories(self) -> List[Dict[str, Any]]:
        """Load just the advisories list from current manifest."""
        data = self.load_current()
        if data is None:
            return []
        return data.get("advisories", [])

    def publish(
        self,
        manifest: Manifest,
        advisories: Optional[List[Advisory]] = None,
    ) -> Tuple[bool, str]:
        """
        Publish a new manifest version.
        1. Validate
        2. Write versioned snapshot (immutable)
        3. Write latest (atomic with backup)
        """
        # Build the full manifest dict
        if advisories is not None:
            manifest.advisories = [a.to_legacy_dict() for a in advisories]
            manifest.total_advisories = len(advisories)

            # Count unique CVEs and IOCs
            all_cves = set()
            ioc_count = 0
            for a in advisories:
                all_cves.update(a.cves)
                ioc_count += len(a.iocs)
            manifest.total_cves = len(all_cves)
            manifest.total_iocs = ioc_count

        manifest_dict = manifest.to_dict()

        # Validate before writing
        is_valid, errors = validate_manifest(manifest_dict)
        if not is_valid:
            msg = f"Manifest validation failed: {'; '.join(errors[:5])}"
            logger.error(msg)
            return False, msg

        # Write versioned snapshot
        ver_num = self._next_version()
        versioned_path = os.path.join(
            self.versioned_dir,
            f"manifest_v{ver_num}.json",
        )
        try:
            with open(versioned_path, "w", encoding="utf-8") as f:
                json.dump(manifest_dict, f, indent=2, default=str)
            logger.info(f"Versioned snapshot: {versioned_path}")
        except Exception as e:
            logger.warning(f"Versioned snapshot write failed (non-fatal): {e}")

        # Write latest with validation + backup
        success, msg = safe_write_manifest(
            manifest_dict, self.latest_path, self.backup_dir
        )
        if success:
            logger.info(
                f"Published manifest v{ver_num}: "
                f"{manifest.total_advisories} advisories, "
                f"{manifest.total_cves} CVEs, "
                f"{manifest.total_iocs} IOCs"
            )
        return success, msg

    def rollback(self, version: Optional[int] = None) -> Tuple[bool, str]:
        """
        Rollback to a previous manifest version.
        If version is None, rolls back to most recent valid backup.
        """
        if version is not None:
            vp = os.path.join(self.versioned_dir, f"manifest_v{version}.json")
            if not os.path.isfile(vp):
                return False, f"Version {version} not found"
            try:
                with open(vp, "r", encoding="utf-8") as f:
                    data = json.load(f)
                is_valid, errors = validate_manifest(data)
                if not is_valid:
                    return False, f"Version {version} invalid: {errors[:3]}"
                return safe_write_manifest(data, self.latest_path, self.backup_dir)
            except Exception as e:
                return False, str(e)

        # Auto-rollback: find newest valid backup
        data = get_last_valid_manifest(self.latest_path, self.backup_dir)
        if data is None:
            return False, "No valid manifest found for rollback"
        return safe_write_manifest(data, self.latest_path, self.backup_dir)

    def get_version_history(self, limit: int = 20) -> List[Dict[str, Any]]:
        """List recent manifest versions with metadata."""
        if not os.path.isdir(self.versioned_dir):
            return []
        files = sorted(
            [f for f in os.listdir(self.versioned_dir) if f.startswith("manifest_v") and f.endswith(".json")],
            reverse=True,
        )[:limit]

        history = []
        for f in files:
            fp = os.path.join(self.versioned_dir, f)
            try:
                with open(fp, "r", encoding="utf-8") as fh:
                    data = json.load(fh)
                history.append({
                    "file": f,
                    "generated_at": data.get("generated_at", ""),
                    "total_advisories": data.get("total_advisories", len(data.get("advisories", []))),
                    "version": data.get("version", ""),
                })
            except Exception:
                continue
        return history
