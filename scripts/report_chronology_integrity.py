#!/usr/bin/env python3
"""Offline P0 audit: do not use hashed report filenames as publication chronology.

No HTTP, Cloudflare API, R2 LIST, Pages write, or mutation occurs here.
A pass proves catalogue syntax/chronology ONLY, not report publication or delivery.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timedelta, timezone
import json
from pathlib import Path
import re
import sys
from typing import Any

PATH_RX = re.compile(
    r"^/reports/(?P<year>20[0-9]{2})/(?P<month>0[1-9]|1[0-2])/"
    r"(?P<slug>intel--[a-f0-9]{16,64})\.html$"
)
UTC_RX = re.compile(
    r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}"
    r"(?:\.[0-9]{1,6})?(?:Z|\+00:00)$"
)
BASE = "https://intel.cyberdudebivash.com"
MAX_ERRORS = 40


def _utc(value: Any) -> datetime | None:
    """Naive timestamps are ambiguous; never infer a timezone."""
    if not isinstance(value, str) or not UTC_RX.fullmatch(value):
        return None
    try:
        d = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError:
        return None
    return d if d.utcoffset() == timedelta(0) else None


def audit_catalog(
    source: Any, *, latest_limit: int = 15, history_limit: int = 5,
    at: datetime | None = None, maximum_age_hours: int | None = None
) -> dict[str, Any]:
    if latest_limit < 1 or history_limit < 1:
        raise ValueError("Probe limits must be positive")
    clock = at if at is not None else datetime.now(timezone.utc)
    if clock.tzinfo is None or clock.utcoffset() is None:
        raise ValueError("Audit clock must be timezone-aware")
    defects: list[str] = []
    def fail(message: str) -> None:
        if len(defects) < MAX_ERRORS:
            defects.append(message)
    if not isinstance(source, dict) or not isinstance(source.get("reports"), list):
        return {"verdict": "BLOCKED", "total": 0,
                "defects": ["Missing reports catalogue array"],
                "latest": [], "historical": [], "delivery_certified": False}
    records = source["reports"]
    if not records:
        fail("Empty report catalogue")
    if maximum_age_hours is not None:
        if maximum_age_hours < 1:
            raise ValueError("maximum_age_hours must be positive")
        created = _utc(source.get("generated_at"))
        if created is None:
            fail("Catalogue generated_at lacks a canonical UTC timestamp")
        elif created > clock + timedelta(minutes=5):
            fail("Catalogue timestamp is in the future")
        elif clock - created > timedelta(hours=maximum_age_hours):
            fail("Catalogue generation is older than the requested freshness ceiling")
    seen: set[str] = set()
    checked: list[tuple[datetime, str]] = []
    for index, record in enumerate(records):
        prefix = f"reports[{index}]"
        if not isinstance(record, dict):
            fail(f"{prefix}: entry is not an object")
            continue
        path = record.get("path")
        m = PATH_RX.fullmatch(path) if isinstance(path, str) else None
        if not m:
            fail(f"{prefix}: unsafe, malformed or unrecognized canonical report path")
            continue
        if path in seen:
            fail(f"{prefix}: duplicate report path")
            continue
        seen.add(path)
        if record.get("id") != m.group("slug"):
            fail(f"{prefix}: report ID does not match canonical filename")
        url = record.get("url")
        if url != BASE + path:
            fail(f"{prefix}: report URL does not match canonical HTTPS path")
        published = _utc(record.get("timestamp"))
        if published is None:
            fail(f"{prefix}: timestamp not a validated explicit-UTC ISO timestamp")
            continue
        if (published.strftime("%Y"), published.strftime("%m")) != (
            m.group("year"), m.group("month")
        ):
            fail(f"{prefix}: path month and canonical UTC publication timestamp differ")
        if published > clock + timedelta(minutes=5):
            fail(f"{prefix}: report publication timestamp is in the future")
        checked.append((published, path))
    # Reject a partial selection. Otherwise a malicious or broken record could
    # disappear from the sample simply by omitting its timestamp.
    if defects:
        return {"verdict": "BLOCKED", "total": len(records),
                "valid_timestamped": len(checked), "defects": defects,
                "latest": [], "historical": [], "delivery_certified": False}
    # An alphabetical hash is only a deterministic tie-breaker after verified UTC.
    ordered = sorted(checked, key=lambda row: (row[0], row[1]))
    # Present latest newest-first. History excludes EVERY latest entry.
    latest = [BASE + path for _, path in reversed(ordered[-latest_limit:])]
    historical = [BASE + path for _, path in ordered[:-latest_limit][:history_limit]]
    return {"verdict": "CHRONOLOGY_PRECHECK_ONLY", "total": len(records),
            "valid_timestamped": len(checked), "defects": [],
            "latest": latest, "historical": historical,
            "delivery_certified": False,
            "remaining_gates": [
                "Match immutable Pages/R2 manifest and successful published-object state",
                "Check customer_ready and publication status per report",
                "Probe authorized customer routes under shared-account request budget",
                "Verify two successful production publisher cycles and entitlement revocation"
            ]}


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--catalog", type=Path, default=Path("api/reports/index.json"))
    p.add_argument("--max-age-hours", type=int, default=None,
                   help="Optional live-freshness budget; omit for historical catalogues")
    p.add_argument("--latest-limit", type=int, default=15)
    p.add_argument("--history-limit", type=int, default=5)
    args = p.parse_args(argv)
    try:
        if args.catalog.stat().st_size > 20_000_000:
            raise ValueError("Catalogue too large for bounded audit")
        data = json.loads(args.catalog.read_text(encoding="utf-8"))
        result = audit_catalog(data, latest_limit=args.latest_limit,
                               history_limit=args.history_limit,
                               maximum_age_hours=args.max_age_hours)
    except (OSError, UnicodeError, ValueError, json.JSONDecodeError) as exc:
        result = {"verdict": "BLOCKED", "total": 0,
                  "defects": [f"Catalogue unavailable or invalid: {type(exc).__name__}"],
                  "latest": [], "historical": [], "delivery_certified": False}
    print(json.dumps(result, indent=2, sort_keys=True))
    return 0 if result["verdict"] == "CHRONOLOGY_PRECHECK_ONLY" else 2


if __name__ == "__main__":
    sys.exit(main())
