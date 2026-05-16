#!/usr/bin/env python3
"""
agent/core/published_field_guardian.py — CYBERDUDEBIVASH® SENTINEL APEX v47.1
PUBLISHED FIELD GUARDIAN — Permanent P0 Fix for boolean 'published' regression

ROOT CAUSE (Run #793):
  export_stix.py writes "published": True (boolean Blogger flag).
  Pipeline schema expects "published": "2024-01-15T12:00:00Z" (ISO-8601 string).
  This mismatch caused AttributeError on .startswith() calls in pipeline_validator.py
  and dropped 446+ candidate items per run.

FIX STRATEGY:
  - Runs at pipeline ingestion, schema enforcement, and export stages
  - Converts boolean True  → published_at value or ISO timestamp
  - Converts boolean False → "" (unpublished, schema-safe)
  - Never destructive: preserves original value in 'published_bool' backup field
  - Zero-regression: existing string ISO-8601 values untouched

USAGE:
  from agent.core.published_field_guardian import enforce_published_field, bulk_repair

Author: CyberDudeBivash Pvt. Ltd.
"""

import re
import logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

log = logging.getLogger("CDB.PublishedGuardian")

# ISO-8601 date patterns the pipeline accepts
_ISO_PATTERN     = re.compile(r"^\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}")
_ISO_DATE_ONLY   = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_FALLBACK_TS     = "1970-01-01T00:00:00Z"  # Epoch sentinel — never confuses date filters

# Fields searched (in priority order) to recover a real timestamp
_CANDIDATE_FIELDS = [
    "published_at", "published_date", "date", "created",
    "modified", "first_seen", "timestamp", "updated_at",
]


def _is_valid_iso(value: Any) -> bool:
    """Return True if value is a non-empty ISO-8601-ish string."""
    if not isinstance(value, str) or not value.strip():
        return False
    return bool(_ISO_PATTERN.match(value.strip())) or bool(_ISO_DATE_ONLY.match(value.strip()))


def _recover_timestamp(entry: Dict[str, Any]) -> str:
    """
    Walk candidate fields to find the best available timestamp.
    Falls back to epoch sentinel — never returns a boolean or None.
    """
    for field in _CANDIDATE_FIELDS:
        val = entry.get(field)
        if _is_valid_iso(val):
            return val.strip()

    # Last resort: use current UTC time (better than epoch for new entries)
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def enforce_published_field(
    entry: Dict[str, Any],
    entry_id: Optional[str] = None,
    *,
    repair: bool = True,
) -> Tuple[Dict[str, Any], bool]:
    """
    Enforce that entry['published'] is a valid ISO-8601 string.

    Args:
        entry:    Advisory/report dict to check/repair
        entry_id: Identifier for logging (optional)
        repair:   If True (default), fix in-place. If False, just audit.

    Returns:
        (entry, was_repaired): Tuple of (potentially modified entry, repair flag)
    """
    pub = entry.get("published")
    eid = entry_id or entry.get("id", entry.get("cve_id", "unknown"))

    # ── Already valid — nothing to do ────────────────────────────────────────
    if _is_valid_iso(pub):
        return entry, False

    # ── Boolean True (Blogger publish flag mistaken for date) ─────────────────
    if pub is True:
        if not repair:
            log.warning("[AUDIT] %s: published=True (boolean) — would repair", eid)
            return entry, False

        recovered = _recover_timestamp(entry)
        entry["published_bool_backup"] = True   # preserve original
        entry["published"]             = recovered
        log.debug("[REPAIR] %s: published=True → '%s'", eid, recovered)
        return entry, True

    # ── Boolean False (unpublished item) ──────────────────────────────────────
    if pub is False:
        if not repair:
            return entry, False

        entry["published_bool_backup"] = False
        entry["published"]             = ""     # schema-safe empty string
        log.debug("[REPAIR] %s: published=False → '' (unpublished)", eid)
        return entry, True

    # ── None or missing ───────────────────────────────────────────────────────
    if pub is None or pub == "":
        if not repair:
            return entry, False

        recovered = _recover_timestamp(entry)
        entry["published"] = recovered
        log.debug("[REPAIR] %s: published=None → '%s'", eid, recovered)
        return entry, True

    # ── Non-string non-null (int, list, dict, etc.) ───────────────────────────
    if not isinstance(pub, str):
        if not repair:
            return entry, False

        recovered = _recover_timestamp(entry)
        entry["published_original_backup"] = pub
        entry["published"]                 = recovered
        log.warning("[REPAIR] %s: published=%r (unexpected type %s) → '%s'", eid, pub, type(pub).__name__, recovered)
        return entry, True

    # ── String but invalid format ─────────────────────────────────────────────
    # Try to coerce common variants: "2024/01/15", "15-01-2024", "Jan 15 2024"
    cleaned = pub.strip()
    for fmt in ("%Y/%m/%d", "%d-%m-%Y", "%B %d %Y", "%b %d %Y", "%Y%m%d"):
        try:
            dt = datetime.strptime(cleaned, fmt)
            fixed = dt.strftime("%Y-%m-%dT%H:%M:%SZ")
            if repair:
                entry["published_original_backup"] = pub
                entry["published"]                 = fixed
                log.debug("[REPAIR] %s: published='%s' (fmt=%s) → '%s'", eid, pub, fmt, fixed)
            return entry, repair
        except ValueError:
            continue

    # Cannot coerce — use recovered timestamp
    if repair:
        recovered = _recover_timestamp(entry)
        entry["published_original_backup"] = pub
        entry["published"]                 = recovered
        log.warning("[REPAIR] %s: published='%s' (unrecognised format) → '%s'", eid, pub, recovered)

    return entry, repair


def bulk_repair(
    entries: List[Dict[str, Any]],
    *,
    audit_only: bool = False,
) -> Tuple[List[Dict[str, Any]], int, int]:
    """
    Apply enforce_published_field to a list of advisory/report entries.

    Args:
        entries:    List of advisory dicts
        audit_only: If True, report issues without modifying entries

    Returns:
        (repaired_entries, repaired_count, error_count)
    """
    repaired  = 0
    errors    = 0
    result    = []

    for i, entry in enumerate(entries):
        try:
            fixed, was_repaired = enforce_published_field(
                entry,
                entry_id=entry.get("id", f"idx-{i}"),
                repair=not audit_only,
            )
            result.append(fixed)
            if was_repaired:
                repaired += 1
        except Exception as exc:
            log.error("[ERROR] Entry %d: %s", i, exc)
            result.append(entry)  # pass-through on exception (never drop entries)
            errors += 1

    if repaired or errors:
        mode = "AUDIT" if audit_only else "REPAIR"
        log.info(
            "[%s] published field check: %d/%d repaired | %d errors",
            mode, repaired, len(entries), errors,
        )

    return result, repaired, errors


def validate_manifest(manifest: Dict[str, Any], *, repair: bool = True) -> Dict[str, Any]:
    """
    Run bulk_repair across the 'advisories' key of a feed manifest dict.

    Args:
        manifest: feed_manifest.json-style dict with 'advisories' key
        repair:   Repair in-place if True

    Returns:
        manifest with advisories repaired
    """
    advisories = manifest.get("advisories", [])
    if not advisories:
        return manifest

    fixed, repaired, errors = bulk_repair(advisories, audit_only=not repair)
    manifest["advisories"] = fixed

    if repaired:
        log.info("[GUARDIAN] Manifest: %d 'published' field(s) repaired, %d errors", repaired, errors)

    return manifest
