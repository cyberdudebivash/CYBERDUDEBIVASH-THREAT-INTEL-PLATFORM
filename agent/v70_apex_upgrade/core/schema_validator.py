"""
SENTINEL APEX v70 — Schema Validation Engine
==============================================
Strict validation before any manifest write or deployment.
Rejects invalid data. Maintains last-known-good state.
"""

import json
import logging
import os
import shutil
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.schema_validator")


# ---------------------------------------------------------------------------
# Schema definitions
# ---------------------------------------------------------------------------

REQUIRED_MANIFEST_KEYS = {"version", "schema_version", "generated_at", "advisories"}
REQUIRED_ADVISORY_KEYS = {"title"}

VALID_SEVERITIES = {"critical", "high", "medium", "low", "info"}
VALID_THREAT_TYPES = {
    "vulnerability", "malware", "campaign", "intrusion-set",
    "tool", "attack-pattern", "indicator", "threat-report",
}
VALID_CONFIDENCE_LEVELS = {"confirmed", "high", "moderate", "low", "unverified"}

MAX_ADVISORY_TITLE_LEN = 1000
MAX_SUMMARY_LEN = 50000
MAX_ADVISORIES_PER_MANIFEST = 5000


# ---------------------------------------------------------------------------
# Validation Functions
# ---------------------------------------------------------------------------

class ValidationError(Exception):
    """Raised when schema validation fails."""
    def __init__(self, errors: List[str]):
        self.errors = errors
        super().__init__(f"Schema validation failed: {len(errors)} error(s)")


def validate_advisory(item: Dict[str, Any], index: int = 0) -> List[str]:
    """Validate a single advisory entry. Returns list of error messages."""
    errors = []
    prefix = f"advisory[{index}]"

    if not isinstance(item, dict):
        return [f"{prefix}: not a dict (type={type(item).__name__})"]

    # Required fields
    for key in REQUIRED_ADVISORY_KEYS:
        if key not in item or not item[key]:
            errors.append(f"{prefix}: missing or empty required field '{key}'")

    # Title length
    title = item.get("title", "")
    if isinstance(title, str) and len(title) > MAX_ADVISORY_TITLE_LEN:
        errors.append(f"{prefix}: title exceeds {MAX_ADVISORY_TITLE_LEN} chars")

    # Severity
    sev = item.get("severity", "")
    if sev and isinstance(sev, str) and sev.lower() not in VALID_SEVERITIES:
        errors.append(f"{prefix}: invalid severity '{sev}'")

    # Threat type
    tt = item.get("threat_type", "")
    if tt and isinstance(tt, str) and tt.lower() not in VALID_THREAT_TYPES:
        errors.append(f"{prefix}: invalid threat_type '{tt}'")

    # Confidence range
    conf = item.get("confidence", 0)
    if isinstance(conf, (int, float)):
        if conf < 0 or conf > 100:
            errors.append(f"{prefix}: confidence {conf} out of range [0,100]")

    # CVEs format
    cves = item.get("cves", [])
    if isinstance(cves, list):
        for cve in cves:
            if isinstance(cve, str) and cve.startswith("CVE-"):
                parts = cve.split("-")
                if len(parts) != 3:
                    errors.append(f"{prefix}: malformed CVE '{cve}'")

    # IOCs — must be list
    iocs = item.get("iocs", [])
    if not isinstance(iocs, list):
        errors.append(f"{prefix}: iocs must be a list")

    return errors


def validate_manifest(data: Dict[str, Any]) -> Tuple[bool, List[str]]:
    """
    Validate a complete manifest structure.
    Returns (is_valid, list_of_errors).
    """
    errors = []

    if not isinstance(data, dict):
        return False, ["manifest root is not a dict"]

    # Required top-level keys
    for key in REQUIRED_MANIFEST_KEYS:
        if key not in data:
            errors.append(f"missing required key '{key}'")

    # Advisories must be a list
    advisories = data.get("advisories", [])
    if not isinstance(advisories, list):
        errors.append("'advisories' is not a list")
        return False, errors

    # Count limit
    if len(advisories) > MAX_ADVISORIES_PER_MANIFEST:
        errors.append(
            f"advisory count {len(advisories)} exceeds max {MAX_ADVISORIES_PER_MANIFEST}"
        )

    # Validate each advisory
    for idx, item in enumerate(advisories):
        item_errors = validate_advisory(item, idx)
        errors.extend(item_errors)

    # generated_at must be parseable
    gen_at = data.get("generated_at", "")
    if gen_at:
        try:
            if isinstance(gen_at, str):
                datetime.fromisoformat(gen_at.replace("Z", "+00:00"))
        except ValueError:
            errors.append(f"generated_at '{gen_at}' is not valid ISO format")

    # Check for duplicate dedup_keys
    seen_keys = set()
    dupes = 0
    for item in advisories:
        dk = item.get("dedup_key", "")
        if dk and dk in seen_keys:
            dupes += 1
        seen_keys.add(dk)
    if dupes > 0:
        errors.append(f"{dupes} duplicate dedup_key(s) found in manifest")

    is_valid = len(errors) == 0
    return is_valid, errors


def validate_manifest_file(filepath: str) -> Tuple[bool, List[str]]:
    """Load and validate a manifest JSON file."""
    if not os.path.isfile(filepath):
        return False, [f"file not found: {filepath}"]

    try:
        with open(filepath, "r", encoding="utf-8") as f:
            data = json.load(f)
    except json.JSONDecodeError as e:
        return False, [f"JSON parse error: {e}"]
    except Exception as e:
        return False, [f"file read error: {e}"]

    return validate_manifest(data)


# ---------------------------------------------------------------------------
# Safe Write with Backup
# ---------------------------------------------------------------------------

def safe_write_manifest(
    data: Dict[str, Any],
    target_path: str,
    backup_dir: Optional[str] = None,
) -> Tuple[bool, str]:
    """
    Validate then atomically write manifest.
    Creates backup of previous version before overwrite.
    Returns (success, message).
    """
    # Validate first
    is_valid, errors = validate_manifest(data)
    if not is_valid:
        msg = f"Validation failed ({len(errors)} errors): {'; '.join(errors[:5])}"
        logger.error(msg)
        return False, msg

    # Backup existing file
    if os.path.isfile(target_path):
        if backup_dir is None:
            backup_dir = os.path.join(os.path.dirname(target_path), ".manifest_backups")
        os.makedirs(backup_dir, exist_ok=True)
        ts = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%S")
        backup_path = os.path.join(backup_dir, f"manifest_{ts}.json")
        try:
            shutil.copy2(target_path, backup_path)
            logger.info(f"Backed up previous manifest to {backup_path}")
        except Exception as e:
            logger.warning(f"Backup failed (non-fatal): {e}")

    # Atomic write: write to temp, then rename
    tmp_path = target_path + ".tmp"
    try:
        json_str = json.dumps(data, indent=2, default=str)
        with open(tmp_path, "w", encoding="utf-8") as f:
            f.write(json_str)

        # Validate the written file
        with open(tmp_path, "r", encoding="utf-8") as f:
            reloaded = json.load(f)
        re_valid, re_errors = validate_manifest(reloaded)
        if not re_valid:
            os.remove(tmp_path)
            return False, f"Post-write validation failed: {'; '.join(re_errors[:3])}"

        # Atomic rename
        os.replace(tmp_path, target_path)
        logger.info(f"Manifest written successfully: {target_path} ({len(data.get('advisories', []))} advisories)")
        return True, "OK"

    except Exception as e:
        if os.path.isfile(tmp_path):
            os.remove(tmp_path)
        msg = f"Write failed: {e}"
        logger.error(msg)
        return False, msg


def get_last_valid_manifest(
    primary_path: str,
    backup_dir: Optional[str] = None,
) -> Optional[Dict[str, Any]]:
    """
    Attempt to load primary manifest. If invalid, search backups for last valid.
    This is the fallback mechanism that ensures we NEVER serve broken data.
    """
    # Try primary
    if os.path.isfile(primary_path):
        try:
            with open(primary_path, "r", encoding="utf-8") as f:
                data = json.load(f)
            is_valid, _ = validate_manifest(data)
            if is_valid:
                return data
        except Exception:
            pass

    # Try backups (newest first)
    if backup_dir is None:
        backup_dir = os.path.join(os.path.dirname(primary_path), ".manifest_backups")

    if not os.path.isdir(backup_dir):
        return None

    backups = sorted(
        [f for f in os.listdir(backup_dir) if f.endswith(".json")],
        reverse=True,
    )
    for backup_file in backups:
        bp = os.path.join(backup_dir, backup_file)
        try:
            with open(bp, "r", encoding="utf-8") as f:
                data = json.load(f)
            is_valid, _ = validate_manifest(data)
            if is_valid:
                logger.warning(f"Fell back to backup manifest: {backup_file}")
                return data
        except Exception:
            continue

    return None
