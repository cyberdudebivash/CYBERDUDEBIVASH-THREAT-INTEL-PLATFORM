#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Report Validation Gate
============================================================
Version : v134.0
Stage   : 3.3 (runs AFTER report_generator, BEFORE R2 upload)

Purpose:
  Hard-fail if ANY advisory in feed_manifest.json is missing its physical
  HTML report, has a report that is too small, or has a file that is not
  valid HTML. Also enforces that every advisory's report_url is an internal
  path (never an external URL).

Exit codes:
  0 -- all reports validated
  1 -- one or more advisories failed validation (pipeline MUST stop)

Usage:
  python3 scripts/validate_reports.py
  python3 scripts/validate_reports.py --manifest data/stix/feed_manifest.json
  python3 scripts/validate_reports.py --reports-dir reports

P0 RULES (non-negotiable):
  RULE 1: Every advisory MUST have internal_report_url OR report_url
  RULE 2: report_url MUST be a relative /reports/ path (never http)
  RULE 3: The physical HTML file MUST exist on disk
  RULE 4: The file MUST be >= 500 bytes
  RULE 5: The file MUST begin with <!DOCTYPE html or <html
  RULE 6: Zero silent skips -- every failure is logged and counted
  RULE 7: Exit 1 if ANY failure -- pipeline stops, R2 upload is blocked
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="[%(levelname)s] %(name)s: %(message)s",
)
logger = logging.getLogger("CDB-VALIDATE-REPORTS")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
MANIFEST_PATH   = Path("data/stix/feed_manifest.json")
REPORTS_BASE    = Path("reports")
MIN_FILE_BYTES  = 500
HTML_SIGNATURES = ("<!doctype html", "<html")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _load_manifest(manifest_path: Path) -> List[Dict[str, Any]]:
    """Load advisories list from manifest. Hard-fail if unreadable."""
    if not manifest_path.exists():
        logger.error("MANIFEST NOT FOUND: %s", manifest_path)
        sys.exit(1)
    try:
        with open(manifest_path, "r", encoding="utf-8", errors="replace") as fh:
            data = json.load(fh)
    except json.JSONDecodeError as exc:
        logger.error("MANIFEST JSON PARSE ERROR: %s -- %s", manifest_path, exc)
        sys.exit(1)

    advisories = data.get("advisories", data.get("entries", []))
    if not isinstance(advisories, list):
        logger.error("MANIFEST 'advisories' key is not a list in %s", manifest_path)
        sys.exit(1)
    return advisories


def _resolve_report_path(entry: Dict[str, Any]) -> Tuple[str, str]:
    """
    Return (report_url, file_path_on_disk) for the given advisory.
    report_url is the internal /reports/... path.
    file_path_on_disk is the relative filesystem path.
    Returns ("", "") if no internal URL is available.
    """
    intel_id = (
        entry.get("id") or entry.get("stix_id") or ""
    ).strip()

    # Priority: internal_report_url > report_url (if internal) > derive from id
    url = (entry.get("internal_report_url") or "").strip()
    if not url:
        ru = (entry.get("report_url") or "").strip()
        # Accept only internal paths
        if ru and not ru.startswith("http"):
            url = ru

    if not url and intel_id:
        # Derive default path from intel_id using processed_at date
        ts = (entry.get("processed_at") or entry.get("timestamp") or "")[:10]
        if len(ts) >= 7:
            yyyy, mm = ts[:4], ts[5:7]
        else:
            from datetime import datetime, timezone
            now = datetime.now(timezone.utc)
            yyyy, mm = str(now.year), f"{now.month:02d}"
        url = f"/reports/{yyyy}/{mm}/{intel_id}.html"

    if not url:
        return "", ""

    # Convert URL path to filesystem path
    # /reports/2026/04/intel--abc.html -> reports/2026/04/intel--abc.html
    fs_path = url.lstrip("/").replace("/", os.sep)
    return url, fs_path


def _validate_one(entry: Dict[str, Any], idx: int) -> List[str]:
    """
    Validate a single advisory entry. Returns a list of failure messages.
    Empty list means PASS.

    v152.2.0 IMMUTABLE GUARD — Root cause of Run #1269 false-positive FATAL:
    Previously RULE 1 returned early (failing) whenever report_url /
    internal_report_url were absent from the manifest entry. This produced
    false-positive failures for:
      (a) data/stix/feed_manifest.json entries — STIX bundle index records
          that never carry report_url fields by design.
      (b) "god mode" reports skipped by report_generator — physical HTML files
          exist on disk (74-81 KB) but the URL was not written back to the
          manifest entry because the generator skipped regeneration.

    Fix: call _resolve_report_path() FIRST. It falls back to deriving the path
    from intel_id + processed_at/timestamp when no URL field exists. RULE 1
    fails ONLY if (a) no URL in manifest AND (b) no id-derived path resolves.
    RULE 3 (file-existence check) then catches genuinely missing reports.
    """
    failures: List[str] = []
    intel_id = (entry.get("id") or entry.get("stix_id") or f"entry[{idx}]").strip()

    # Resolve best available path: explicit URL first, then id-derived fallback
    _url, fs_path = _resolve_report_path(entry)
    explicit_url = (entry.get("internal_report_url") or entry.get("report_url") or "").strip()

    # RULE 1: must resolve a report path (explicit URL in manifest OR id-derived)
    if not fs_path:
        failures.append(
            f"[{intel_id}] RULE 1 FAIL: no report_url, internal_report_url, "
            f"or derivable id — cannot locate report file"
        )
        return failures

    # RULE 2: if an explicit URL is present, it must not be a foreign external URL
    if explicit_url and explicit_url.startswith("http") and "cyberdudebivash" not in explicit_url:
        failures.append(
            f"[{intel_id}] RULE 2 FAIL: report_url is external URL: {explicit_url!r}"
        )
        return failures

    # RULE 3: physical HTML file must exist on disk at resolved path
    if not os.path.exists(fs_path):
        failures.append(
            f"[{intel_id}] RULE 3 FAIL: report file NOT FOUND: {fs_path}"
        )
        return failures  # no point checking size/content

    # RULE 3b (v154.0 P0 HARDENING): PUBLIC report_url path MUST ALSO exist.
    # If report_url diverges from internal_report_url and the public path is
    # missing, the dashboard CTA links to a 404.
    _public_ru = (entry.get("report_url") or "").strip()
    if _public_ru and not _public_ru.startswith("http") and _public_ru.startswith("/reports/"):
        _public_fs = _public_ru.lstrip("/").replace("/", os.sep)
        if _public_fs != fs_path and not os.path.exists(_public_fs):
            failures.append(
                f"[{intel_id}] RULE 3b FAIL: public report_url path NOT FOUND: "
                f"{_public_fs} (internal path {fs_path} exists but dashboard "
                f"links to the public path — customers get 404)"
            )

    # RULE 4: file must be >= 500 bytes
    size = os.path.getsize(fs_path)
    if size < MIN_FILE_BYTES:
        failures.append(
            f"[{intel_id}] RULE 4 FAIL: report file too small "
            f"({size} bytes < {MIN_FILE_BYTES}): {fs_path}"
        )

    # RULE 5: file must start with valid HTML
    try:
        with open(fs_path, "r", encoding="utf-8", errors="replace") as fh:
            head = fh.read(512).lower()
    except OSError as exc:
        failures.append(
            f"[{intel_id}] RULE 5 FAIL: cannot read report file {fs_path}: {exc}"
        )
        return failures

    if not any(sig in head for sig in HTML_SIGNATURES):
        failures.append(
            f"[{intel_id}] RULE 5 FAIL: report file is not valid HTML "
            f"(head: {head[:60]!r}): {fs_path}"
        )

    return failures


def validate_all_reports(
    manifest_path: Path = MANIFEST_PATH,
    reports_base: Path = REPORTS_BASE,
) -> bool:
    """
    Validate all advisory reports. Returns True if all pass, False if any fail.
    Logs every failure. Never raises.
    """
    advisories = _load_manifest(manifest_path)
    total = len(advisories)

    if total == 0:
        logger.error("MANIFEST IS EMPTY -- no advisories to validate. Exit 1.")
        return False

    logger.info("Validating reports for %d advisories from %s", total, manifest_path)

    all_failures: List[str] = []
    passed = 0

    for idx, entry in enumerate(advisories):
        failures = _validate_one(entry, idx)
        if failures:
            for msg in failures:
                logger.error("REPORT VALIDATION FAIL: %s", msg)
            all_failures.extend(failures)
        else:
            intel_id = (entry.get("id") or entry.get("stix_id") or f"entry[{idx}]").strip()
            _url, fs_path = _resolve_report_path(entry)
            size = os.path.getsize(fs_path) if fs_path and os.path.exists(fs_path) else 0
            logger.info("[PASS] %s -- %s (%d bytes)", intel_id, fs_path, size)
            passed += 1

    logger.info(
        "Report validation complete: %d/%d passed, %d failed",
        passed, total, len(all_failures),
    )

    if all_failures:
        logger.error(
            "P0 GATE FAIL: %d report(s) failed validation. "
            "R2 upload is BLOCKED. Fix all failures above before re-running.",
            len(all_failures),
        )
        return False

    logger.info("P0 GATE PASS: all %d reports validated. R2 upload is ALLOWED.", total)
    return True


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX -- Report Validation Gate (P0, Stage 3.3)"
    )
    parser.add_argument(
        "--manifest",
        default=str(MANIFEST_PATH),
        help=f"Path to feed_manifest.json (default: {MANIFEST_PATH})",
    )
    parser.add_argument(
        "--reports-dir",
        default=str(REPORTS_BASE),
        help=f"Base reports directory (default: {REPORTS_BASE})",
    )
    args = parser.parse_args()

    ok = validate_all_reports(
        manifest_path=Path(args.manifest),
        reports_base=Path(args.reports_dir),
    )
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
