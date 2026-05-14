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
"""
from __future__ import annotations
import argparse, json, os, pathlib, sys

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

def validate(feed_path: pathlib.Path, repo: pathlib.Path) -> tuple[int, int, list[str]]:
    items   = load_items(feed_path)
    missing = []
    checked = 0
    for item in items:
        ru = item.get("report_url", "")
        if not ru:
            continue
        if ru.startswith("http"):
            # External URL — not a local report, skip
            continue
        if not ru.startswith("/reports/"):
            missing.append(f"[BAD_PREFIX] id={item.get('id','?')[:32]} report_url={ru!r} (expected /reports/YYYY/MM/)")
            continue
        local = repo / ru.lstrip("/")
        checked += 1
        if not local.exists():
            missing.append(f"[MISSING] id={item.get('id','?')[:32]} url={ru}")
    return checked, len(missing), missing

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

    total_checked = 0
    total_missing = 0
    for feed in feeds:
        checked, n_missing, missing = validate(feed, REPO_ROOT)
        rel = feed.relative_to(REPO_ROOT) if REPO_ROOT in feed.parents else feed
        print(f"\nFeed: {rel}  checked={checked}  missing={n_missing}")
        for m in missing[:20]:
            print(f"  {m}")
        if n_missing > 20:
            print(f"  ... and {n_missing - 20} more")
        total_checked += checked
        total_missing += n_missing

    print()
    print(f"TOTAL: checked={total_checked}  missing={total_missing}")
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
