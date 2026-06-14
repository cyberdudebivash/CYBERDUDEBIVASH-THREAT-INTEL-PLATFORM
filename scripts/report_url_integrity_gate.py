"""
SENTINEL APEX — Report URL Integrity Gate
CYBERDUDEBIVASH PVT LTD

Scans all feed JSON files for malformed report_url fields.
Exits non-zero if any malformed URLs found so CI/CD fails loudly.

Malformed = empty, trailing slash, or missing YYYY/MM date path.

Usage:
    python3 scripts/report_url_integrity_gate.py
    python3 scripts/report_url_integrity_gate.py --fix     # auto-repair using disk index
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
from pathlib import Path

CDN_BASE = "https://intel.cyberdudebivash.com"
REPO_ROOT = Path(__file__).parent.parent

FEED_FILES = [
    "api/latest.json",
    "api/top10.json",
    "api/feed.json",
    "data/snapshots/current.json",
    "data/snapshots/20260501T123634Z_local.json",
    "data/snapshots/20260501T123726Z_local.json",
]

_DATE_PATH_RE = re.compile(r"/reports/\d{4}/\d{2}/")
_UNDATED_RE = re.compile(r"/reports/intel--[^/]+\.html$")


def is_malformed(url: str) -> bool:
    if not url:
        return True
    if url.endswith("/"):
        return True
    if _UNDATED_RE.search(url) and not _DATE_PATH_RE.search(url):
        return True
    return False


def build_disk_index() -> dict[str, str]:
    reports_root = REPO_ROOT / "reports"
    index: dict[str, str] = {}
    if not reports_root.is_dir():
        return index
    for year_dir in sorted(reports_root.iterdir(), reverse=True):
        if not year_dir.is_dir():
            continue
        for month_dir in sorted(year_dir.iterdir(), reverse=True):
            if not month_dir.is_dir():
                continue
            for fn in month_dir.iterdir():
                if fn.name.endswith(".html") and fn.name.startswith("intel--"):
                    h = fn.name[len("intel--"):-len(".html")]
                    if h not in index:
                        rel = f"reports/{year_dir.name}/{month_dir.name}/{fn.name}"
                        index[h] = f"{CDN_BASE}/{rel}"
    return index


def extract_hash(s: str) -> str | None:
    m = re.search(r"intel--([a-f0-9]+)", s or "")
    return m.group(1) if m else None


def date_from_entry(entry: dict) -> tuple[str | None, str | None]:
    ts = entry.get("published_at") or entry.get("timestamp") or entry.get("created_at") or ""
    m = re.match(r"(\d{4})-(\d{2})", ts)
    return (m.group(1), m.group(2).zfill(2)) if m else (None, None)


def get_items(data: dict | list) -> list:
    if isinstance(data, list):
        return data
    for key in ("data", "items", "advisories"):
        if key in data and isinstance(data[key], list):
            return data[key]
    return []


def _detect_ascii(raw: str) -> bool:
    """Return True if original file used ensure_ascii=True (no literal non-ASCII)."""
    try:
        raw.encode("ascii")
        return True
    except UnicodeEncodeError:
        return False


def scan_file(path: Path, fix: bool, disk_index: dict) -> tuple[int, int, int]:
    """Returns (total, malformed, fixed)."""
    if not path.exists():
        return 0, 0, 0

    raw = path.read_text(encoding="utf-8")
    data = json.loads(raw)
    items = get_items(data)
    if not items:
        return 0, 0, 0

    total = len(items)
    bad = [e for e in items if is_malformed(e.get("report_url", ""))]
    malformed = len(bad)

    if not fix or not bad:
        return total, malformed, 0

    repaired = 0
    for entry in bad:
        url = entry.get("report_url", "")
        h = extract_hash(url) or extract_hash(entry.get("id", "") or entry.get("entry_id", ""))
        if h and h in disk_index:
            entry["report_url"] = disk_index[h]
            repaired += 1
        else:
            year, month = date_from_entry(entry)
            if year and month and h:
                entry["report_url"] = f"{CDN_BASE}/reports/{year}/{month}/intel--{h}.html"
                repaired += 1

    ensure_ascii = _detect_ascii(raw)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=ensure_ascii) + "\n",
        encoding="utf-8",
    )
    return total, malformed, repaired


def main():
    parser = argparse.ArgumentParser(description="Report URL integrity gate")
    parser.add_argument("--fix", action="store_true", help="Auto-repair malformed URLs using disk index")
    args = parser.parse_args()

    disk_index = build_disk_index() if args.fix else {}
    if args.fix:
        print(f"[GATE G] Disk index: {len(disk_index)} reports indexed")

    total_bad = 0
    results = []

    for rel in FEED_FILES:
        path = REPO_ROOT / rel
        total, bad, fixed = scan_file(path, args.fix, disk_index)
        if total == 0:
            continue
        status = "PASS" if bad == 0 else ("FIXED" if fixed == bad else "FAIL")
        results.append((rel, total, bad, fixed, status))
        if bad > fixed:
            total_bad += bad - fixed

    print()
    print("=" * 68)
    print("SENTINEL APEX — Report URL Integrity Gate (GATE G)")
    print("=" * 68)
    for rel, total, bad, fixed, status in results:
        if bad == 0:
            print(f"  [PASS]  {rel} — {total} items, 0 malformed")
        elif fixed == bad:
            print(f"  [FIXED] {rel} — {total} items, {bad} malformed → repaired")
        else:
            remaining = bad - fixed
            print(f"  [FAIL]  {rel} — {total} items, {remaining} malformed (unfixable)")
    print("=" * 68)

    if total_bad > 0:
        print(f"[GATE G] FAIL: {total_bad} unresolved malformed report_url(s) across feed files")
        print("         Run with --fix to auto-repair, or re-run the pipeline to regenerate.")
        print()
        sys.exit(1)
    else:
        print("[GATE G] PASS: All report URLs are correctly formatted")
        print()
        sys.exit(0)


if __name__ == "__main__":
    main()
