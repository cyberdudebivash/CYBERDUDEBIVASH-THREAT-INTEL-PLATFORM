#!/usr/bin/env python3
"""Read-only P0 report-catalog vs Worker certification-feed coverage census.

This reproduces only the existing _resolveFeedItemsById() ID-selection order.
It DOES NOT query R2, infer P20-P26 quality, read private customer material,
or count a resolvable report as customer-ready. An unresolved catalog entry
may have a separately persisted valid certification: this audit cannot see it.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

SOURCES = ("latest_pro", "latest", "top10", "apex")
MAX_BYTES = 4_000_000
MAX_ITEMS = 50_000


def _canonical_id(value: Any) -> str | None:
    if not isinstance(value, str):
        return None
    v = value[:-5] if value.endswith(".html") else value
    return v if v.startswith("intel--") and 8 <= len(v) <= 85 and all(
        c in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
        for c in v
    ) else None


def _rows(document: Any, key: str) -> list[dict]:
    if not isinstance(document, dict):
        raise ValueError(key + ": document must be an object")
    field = "reports" if key == "catalog" else "items"
    records = document.get(field)
    if not isinstance(records, list) or len(records) > MAX_ITEMS:
        raise ValueError(key + ": missing, invalid or oversized " + field)
    if not records or any(not isinstance(v, dict) for v in records):
        raise ValueError(key + ": empty or malformed source")
    return records


def audit_coverage(catalog: Any, sources: dict[str, Any]) -> dict[str, Any]:
    """Count coverage without conflating ID resolution and certification."""
    if not isinstance(sources, dict) or set(sources) != set(SOURCES):
        raise ValueError("All four source snapshots are required")
    entries = _rows(catalog, "catalog")
    catalog_ids = []
    for entry in entries:
        report_id = _canonical_id(entry.get("id"))
        if not report_id:
            raise ValueError("Invalid catalog report identifier")
        catalog_ids.append(report_id)
    if len(set(catalog_ids)) != len(catalog_ids):
        raise ValueError("Duplicate catalog report identifier")
    selected: dict[str, str] = {}
    counts = {source: 0 for source in SOURCES}
    for source in SOURCES:
        records = _rows(sources[source], source)
        for record in records:
            # Exactly the Worker's existing precedence: stix_id || id,
            # and first matching source wins.
            raw = record.get("stix_id") or record.get("id")
            identifier = _canonical_id(raw)
            if identifier and identifier not in selected:
                selected[identifier] = source
    unresolved = 0
    for item_id in catalog_ids:
        where = selected.get(item_id)
        if where:
            counts[where] += 1
        else:
            unresolved += 1
    total = len(catalog_ids)
    return {
        "schema_version": "certification_source_coverage.v1",
        "verdict": "COVERAGE_INCOMPLETE" if unresolved else "COVERAGE_PRECHECK_ONLY",
        "catalog_candidates": total,
        "resolved_from_feed_windows": total - unresolved,
        "outside_feed_windows": unresolved,
        "outside_feed_windows_pct": round(100 * unresolved / total, 2),
        "first_source_counts": counts,
        "unresolved_requires_independent_persisted_certification": unresolved > 0,
        "persisted_certification_verified": False,
        "publication_gate_reasons_verified": False,
        "customer_release_certified": False,
        "cloudflare_requests": 0,
    }


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("catalog", *SOURCES):
        parser.add_argument("--" + name.replace("_", "-"), type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        snapshots = {}
        for key in ("catalog", *SOURCES):
            path = getattr(args, key)
            if path.stat().st_size > MAX_BYTES:
                raise ValueError("Snapshot size exceeds offline audit limit")
            snapshots[key] = json.loads(path.read_text(encoding="utf-8"))
        result = audit_coverage(
            snapshots.pop("catalog"), snapshots,
        )
    except (OSError, UnicodeError, ValueError, TypeError) as exc:
        result = {
            "schema_version": "certification_source_coverage.v1",
            "verdict": "BLOCKED_INVALID_OFFLINE_EVIDENCE",
            "reason": type(exc).__name__,
            "customer_release_certified": False,
            "cloudflare_requests": 0,
        }
    print(json.dumps(result, sort_keys=True, indent=2))
    return 0 if result["verdict"] == "COVERAGE_PRECHECK_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
