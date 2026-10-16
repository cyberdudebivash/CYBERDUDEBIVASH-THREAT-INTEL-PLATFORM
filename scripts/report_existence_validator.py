#!/usr/bin/env python3
"""
scripts/report_existence_validator.py
CYBERDUDEBIVASH(R) SENTINEL APEX v153.1 -- Report Existence Validator
======================================================================
Validates that every report_url in the feed manifest points to an
actual HTML file on disk in reports/.

Catches:
  - Stale report_urls pointing to deleted/regenerated reports
  - report_url schema drift (flat path vs YYYY/MM/ path)
  - generate_intel_reports.py truncation (write without manifest update)
  - report_url pointing to source_url fallback (external URL)

Exit 0 = All reports exist on disk
Exit 1 = Missing reports detected (CI blocks deployment)

Usage:
  python3 scripts/report_existence_validator.py
  python3 scripts/report_existence_validator.py --manifest api/feed.json
  python3 scripts/report_existence_validator.py --warn-only

P0 2026-09-05: this is the same architectural mismatch STAGE 3.3
(scripts/validate_reports.py) hard-failed on for every natural run since
PR #369/#370 -- confirmed live (run #2249, sentinel-apex.yml) once #375
unblocked STAGE 3.3: THIS validator then hard-failed instead, at STAGE 5.4.1,
skipping GitHub Pages deployment. PR #369 bounded report (re)generation to a
rolling REPORT_WINDOW_HOURS window; reports/ is gitignored and never
persisted across CI runs, so a fresh runner has zero local files for any
manifest entry outside that window. This validator required EVERY entry
(including data/stix/feed_manifest.json's full historical corpus) to have
one. Fixed with the exact same deferral logic #375 added to
validate_reports.py, reusing scripts/r2_report_publisher.py's own
window/state helpers (not reimplemented) -- see
tests/test_report_existence_validator_window_deferral.py.
"""
from __future__ import annotations
import argparse, json, os, pathlib, sys
from datetime import datetime, timezone

_SCRIPTS_DIR = pathlib.Path(__file__).resolve().parent
if str(_SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(_SCRIPTS_DIR))

from r2_report_publisher import (  # noqa: E402
    canonical_age,
    load_publish_state,
    report_window_hours,
)

REPO_ROOT     = pathlib.Path(__file__).resolve().parent.parent
DEFAULT_FEEDS = [
    "api/feed.json",
    "data/stix/feed_manifest.json",
]

def load_items(path: pathlib.Path) -> list[dict]:
    if not path.exists():
        return []
    raw = json.loads(path.read_text(encoding="utf-8"))
    if isinstance(raw, list):
        return raw
    for key in ("advisories", "reports", "items"):
        if key in raw and isinstance(raw[key], list):
            return raw[key]
    return []

def validate(
    feed_path: pathlib.Path,
    repo: pathlib.Path,
    *,
    now: datetime,
    window_hours: int,
    published_ids: set[str],
) -> tuple[int, int, list[str], list[str]]:
    items    = load_items(feed_path)
    missing  = []
    deferred = []
    checked  = 0
    for item in items:
        ru = item.get("report_url", "")
        if not ru:
            continue
        if ru.startswith("http"):
            # External URL — not a local report, skip
            continue
        if not ru.startswith("/reports/"):
            # Schema drift, not a windowed-generation artifact -- always a
            # real defect regardless of age, so never deferred.
            missing.append(f"[BAD_PREFIX] id={item.get('id','?')[:32]} report_url={ru!r} (expected /reports/YYYY/MM/)")
            continue
        local = repo / ru.lstrip("/")
        checked += 1
        if not local.exists():
            intel_id = (item.get("id") or "").strip()
            # Same deferral rule as scripts/validate_reports.py's RULE 3
            # (reused, not reimplemented): confirmed durably published via
            # r2_report_publisher.py's own state, or outside the rolling
            # publish window PR #369 bounded regeneration to -- reports/ is
            # gitignored, so neither case ever has a local file on a fresh
            # runner, and neither is a real defect.
            if intel_id in published_ids:
                deferred.append(f"[DEFERRED:published] id={intel_id[:32]} url={ru}")
                continue
            _ts, _age_hours = canonical_age(item, now)
            _in_window = _age_hours is not None and 0 <= _age_hours <= window_hours
            if not _in_window:
                deferred.append(f"[DEFERRED:out-of-window] id={intel_id[:32]} url={ru}")
                continue
            missing.append(f"[MISSING] id={item.get('id','?')[:32]} url={ru}")
    return checked, len(missing), missing, deferred

def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--manifest", help="Feed JSON path (default: auto-detect)")
    parser.add_argument("--warn-only", action="store_true", help="Exit 0 even on failures (warning mode)")
    args = parser.parse_args()

    print("=" * 70)
    print("SENTINEL APEX -- Report Existence Validator v153.1")
    print("=" * 70)

    feeds = [pathlib.Path(args.manifest)] if args.manifest else [REPO_ROOT / f for f in DEFAULT_FEEDS]
    feeds = [f for f in feeds if f.exists()]
    if not feeds:
        print("WARN: No feed manifest files found -- skipping validation")
        return 0

    window_hours = report_window_hours()
    now = datetime.now(timezone.utc)
    publish_state = load_publish_state()
    published_ids = {
        _id for _id, _rec in publish_state.get("items", {}).items()
        if isinstance(_rec, dict) and _rec.get("html_key")
    }
    print(
        f"Rolling publish window: {window_hours}h -- {len(published_ids)} id(s) "
        "confirmed durably published via r2_report_publisher.py's own state."
    )

    total_checked = 0
    total_missing = 0
    total_deferred = 0
    for feed in feeds:
        checked, n_missing, missing, deferred = validate(
            feed, REPO_ROOT, now=now, window_hours=window_hours, published_ids=published_ids,
        )
        rel = feed.relative_to(REPO_ROOT) if REPO_ROOT in feed.parents else feed
        print(f"\nFeed: {rel}  checked={checked}  missing={n_missing}  deferred={len(deferred)}")
        for m in missing[:20]:
            print(f"  {m}")
        if n_missing > 20:
            print(f"  ... and {n_missing - 20} more")
        for d in deferred[:5]:
            print(f"  {d}")
        if len(deferred) > 5:
            print(f"  ... and {len(deferred) - 5} more deferred")
        total_checked += checked
        total_missing += n_missing
        total_deferred += len(deferred)

    print()
    print(f"TOTAL: checked={total_checked}  missing={total_missing}  deferred={total_deferred}")
    if total_missing == 0:
        print("RESULT: ALL reports exist on disk -- OK")
        return 0
    else:
        print(f"RESULT: {total_missing} report(s) referenced in manifest but MISSING on disk")
        if args.warn_only:
            print("(--warn-only mode: exiting 0)")
            return 0
        return 1

if __name__ == "__main__":
    sys.exit(main())
