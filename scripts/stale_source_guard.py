#!/usr/bin/env python3
"""
scripts/stale_source_guard.py
SENTINEL APEX -- Stale Source Guard (STAGE 1-3b and STAGE 3.93.18b)

Removes items whose SOURCE publication date is older than the window
(scripts/source_publication_age.py, INTEL_MAX_SOURCE_AGE_DAYS, default 14)
from the published feed and the manifest, unless they carry an
active-exploitation signal (CISA KEV confirmed or exploitation language).

Why a guard as well as the ingest gate: items written by earlier runs are
already in the R2 manifest (2026-09-26: 12 of 42 live items were articles
from 2026-01-14 .. 2026-08-07), and ~40 CI steps read-modify-write
api/feed.json between the orchestrator and the manifests (STAGE 4.06's
documented root cause). Runs twice:
  STAGE 1-3b   right after the orchestrator, before enrichment, report
               generation and R2 uploads (no report or R2 write for them)
  STAGE 3.93.18b right before the API manifests are regenerated, so
               /api/v1/intel/latest.json and api/feed.json agree.

Never empties the feed: a file is left unchanged when pruning would leave
fewer than MIN_KEEP items (the feed contract's floor), and says so.
Items without a readable source date are kept (missing is not old).
Exit code is always 0; data/quality/stale_source_guard_report.json records
what was removed and why.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO_ROOT / "scripts"))

from source_publication_age import (  # noqa: E402
    MAX_SOURCE_AGE_DAYS,
    is_stale_source,
    source_age_days,
)

TARGET_PATHS = [
    "api/feed.json",
    "feed.json",
    "data/stix/feed_manifest.json",
]
MIN_KEEP = 10  # run_pipeline.MIN_FRESHNESS_ENTRIES
REPORT_PATH = "data/quality/stale_source_guard_report.json"
LIST_KEYS = ("advisories", "items", "reports")


def _items_of(raw):
    if isinstance(raw, list):
        return raw, None
    if isinstance(raw, dict):
        for key in LIST_KEYS:
            if isinstance(raw.get(key), list):
                return raw[key], key
    return None, None


def guard_file(path: Path, now: datetime, max_age_days: int = None,
               min_keep: int = MIN_KEEP) -> dict:
    rel = str(path.relative_to(REPO_ROOT)) if path.is_relative_to(REPO_ROOT) else str(path)
    result = {"path": rel, "status": "SKIPPED", "before": 0, "after": 0, "removed": []}
    if not path.exists():
        result["reason"] = "not found"
        return result
    try:
        raw = json.loads(path.read_text(encoding="utf-8").rstrip("\x00"))
    except Exception as exc:
        result["reason"] = f"unparseable: {exc}"
        return result
    items, key = _items_of(raw)
    if items is None:
        result["reason"] = "no item list"
        return result

    keep, removed = [], []
    for it in items:
        if isinstance(it, dict) and is_stale_source(it, max_age_days=max_age_days, now=now):
            age = source_age_days(it, now=now)
            removed.append({
                "id": it.get("id") or it.get("stix_id"),
                "title": str(it.get("title") or "")[:120],
                "source_published_at": it.get("published_at") or it.get("published"),
                "source_age_days": round(age, 1) if age is not None else None,
            })
        else:
            keep.append(it)

    result["before"] = len(items)
    if not removed:
        result.update(status="CLEAN", after=len(items))
        return result
    if len(keep) < min_keep:
        result.update(status="HELD", after=len(items), removed=[],
                      would_remove=len(removed),
                      reason=f"pruning would leave {len(keep)} < {min_keep} items")
        return result

    if key is None:
        out = keep
    else:
        raw[key] = keep
        for count_key in ("count", "total", "total_advisories"):
            if isinstance(raw.get(count_key), int):
                raw[count_key] = len(keep)
        out = raw
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(out, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    tmp.replace(path)
    result.update(status="PRUNED", after=len(keep), removed=removed)
    return result


def main(argv=None) -> int:
    argv = list(sys.argv[1:] if argv is None else argv)
    stage = argv[0] if argv else "manual"
    now = datetime.now(timezone.utc)
    results = []
    for rel in TARGET_PATHS:
        try:
            res = guard_file(REPO_ROOT / rel, now)
        except Exception as exc:  # never fail the pipeline
            res = {"path": rel, "status": "ERROR", "reason": str(exc)}
        results.append(res)
        extra = f" ({res.get('reason')})" if res.get("reason") else ""
        print(f"[STALE-SOURCE-GUARD] {rel}: {res['status']} "
              f"{res.get('before', '?')} -> {res.get('after', '?')}{extra}")
        for r in res.get("removed", []):
            print(f"    removed {r['id']} (source {r['source_published_at']}, "
                  f"{r['source_age_days']}d): {r['title'][:70]}")
        if res["status"] == "HELD":
            print(f"::warning::Stale source guard held {rel}: {res['reason']}")

    report = {
        "report_type": "stale_source_guard",
        "stage": stage,
        "generated_at": now.strftime("%Y-%m-%dT%H:%M:%SZ"),
        "max_source_age_days": MAX_SOURCE_AGE_DAYS,
        "files": results,
        "removed_total": sum(len(r.get("removed", [])) for r in results),
    }
    try:
        out = REPO_ROOT / REPORT_PATH
        out.parent.mkdir(parents=True, exist_ok=True)
        out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    except Exception as exc:
        print(f"[STALE-SOURCE-GUARD] report not written: {exc}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
