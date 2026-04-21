#!/usr/bin/env python3
"""
Post-validation manifest status updater.

Runs after Stage 3.3 (validate_reports.py) completes successfully. For every
manifest entry whose HTML report exists on disk, exceeds the minimum size
threshold, and begins with a valid HTML signature, flip
`validation_status` from 'pending' to 'valid' and stamp 'validated_at'.

Idempotent — safe to re-run on every build.

CYBERDUDEBIVASH SENTINEL APEX v134.0.0
"""
from __future__ import annotations

import json
import pathlib
import sys
from datetime import datetime, timezone

if sys.stdout.encoding and sys.stdout.encoding.lower() != 'utf-8':
    try:
        sys.stdout.reconfigure(encoding='utf-8', errors='replace')  # type: ignore[attr-defined]
    except Exception:
        pass


REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
MANIFEST_PATH = REPO_ROOT / "data" / "stix" / "feed_manifest.json"

MIN_REPORT_BYTES = 1000          # any file below this is treated as stub
HTML_SIGNATURES = ("<!doctype html", "<html")


def is_valid_report(path: pathlib.Path) -> bool:
    if not path.exists() or not path.is_file():
        return False
    try:
        size = path.stat().st_size
    except OSError:
        return False
    if size < MIN_REPORT_BYTES:
        return False
    try:
        head = path.read_text(encoding='utf-8', errors='replace')[:512].lower()
    except Exception:
        return False
    return any(sig in head for sig in HTML_SIGNATURES)


def _resolve_report_path(entry: dict) -> pathlib.Path | None:
    """Given a manifest entry, locate the report file on disk."""
    for key in ("report_path", "report_local_path", "report_url"):
        val = entry.get(key)
        if not val or not isinstance(val, str):
            continue
        # Strip leading slash/host prefix for relative path resolution
        if val.startswith('http://') or val.startswith('https://'):
            # Extract path portion
            idx = val.find('/', 8)
            if idx > 0:
                val = val[idx:]
            else:
                continue
        rel = val.lstrip('/')
        p = REPO_ROOT / rel
        if p.exists():
            return p
    return None


def main() -> int:
    if not MANIFEST_PATH.exists():
        print(f"[validation-status] manifest missing at {MANIFEST_PATH}; no-op.")
        return 0

    manifest = json.loads(MANIFEST_PATH.read_text(encoding='utf-8'))
    # Manifest may be a bare list, or a dict with "items" / "advisories" /
    # "entries". Prefer the first non-empty list; fall back to "items" if
    # all candidate keys resolve to empty (schema stability).
    items: list = []
    items_key: str | None = None
    if isinstance(manifest, list):
        items = manifest
    else:
        # prefer non-empty candidate
        for candidate in ("advisories", "items", "entries"):
            v = manifest.get(candidate)
            if isinstance(v, list) and v:
                items, items_key = v, candidate
                break
        # fall back to first list-shaped key we find
        if not items_key:
            for candidate in ("items", "advisories", "entries"):
                if isinstance(manifest.get(candidate), list):
                    items_key = candidate
                    items = manifest[candidate]
                    break

    updated = 0
    skipped_missing = 0
    skipped_invalid = 0
    already_valid = 0
    now_iso = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    for entry in items:
        if not isinstance(entry, dict):
            continue
        current = entry.get("validation_status")
        if current == "valid":
            already_valid += 1
            continue
        report = _resolve_report_path(entry)
        if report is None:
            skipped_missing += 1
            continue
        if not is_valid_report(report):
            skipped_invalid += 1
            continue
        entry["validation_status"] = "valid"
        entry["validated_at"] = now_iso
        updated += 1

    if isinstance(manifest, list):
        MANIFEST_PATH.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding='utf-8',
        )
    else:
        if items_key:
            manifest[items_key] = items
        manifest["last_validation_sweep"] = now_iso
        MANIFEST_PATH.write_text(
            json.dumps(manifest, indent=2, ensure_ascii=False) + "\n",
            encoding='utf-8',
        )

    print(
        f"[validation-status] total={len(items)} "
        f"updated={updated} already_valid={already_valid} "
        f"missing_report={skipped_missing} invalid_html={skipped_invalid}"
    )
    return 0


if __name__ == '__main__':
    sys.exit(main())
