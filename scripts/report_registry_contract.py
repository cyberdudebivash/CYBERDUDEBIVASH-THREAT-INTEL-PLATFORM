#!/usr/bin/env python3
"""Offline, fail-closed same-run report-registry artifact contract.

Checks builder output (schema 1.0) before publication. This is not a
customer-ready catalog validator and cannot establish R2 object delivery.
No network, Cloudflare, billing or storage API calls.
"""
from __future__ import annotations
import argparse
import json
from pathlib import Path
from typing import Any

SEVERITIES = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "UNKNOWN")


def _nonnegative_int(value: Any) -> bool:
    return type(value) is int and value >= 0


def audit_registry(index: Any, latest: Any, stats: Any) -> dict[str, Any]:
    defects: list[str] = []
    parts = {"index": index, "latest": latest, "stats": stats}
    for name, payload in parts.items():
        if not isinstance(payload, dict):
            defects.append(f"{name}: expected object")
            continue
        if payload.get("schema_version") != "1.0":
            defects.append(f"{name}: unexpected schema (legacy/other writer?)")
        if not isinstance(payload.get("generated_at"), str) or not payload["generated_at"]:
            defects.append(f"{name}: missing generation timestamp")
        if not _nonnegative_int(payload.get("total_reports")):
            defects.append(f"{name}: invalid total_reports")
    if defects:
        return {"verdict": "BLOCKED", "defects": defects, "delivery_certified": False}
    if len({p["generated_at"] for p in parts.values()}) != 1:
        defects.append("registry artifacts do not share one generation timestamp")
    if len({p["total_reports"] for p in parts.values()}) != 1:
        defects.append("registry artifacts disagree on total_reports")
    for name, payload in (("index", index), ("latest", latest)):
        reports = payload.get("reports")
        count = payload.get("reports_listed")
        if not isinstance(reports, list) or not _nonnegative_int(count):
            defects.append(f"{name}: invalid reports array or reports_listed")
        elif count != len(reports):
            defects.append(f"{name}: reports_listed does not match reports length")
        elif count > payload["total_reports"]:
            defects.append(f"{name}: listed exceeds total")
    counts = stats.get("by_severity")
    if not isinstance(counts, dict) or set(counts) != set(SEVERITIES) or not all(
        _nonnegative_int(v) for v in counts.values()
    ):
        defects.append("stats: missing or invalid authoritative by_severity counts")
    elif _nonnegative_int(index.get("reports_listed")) and sum(counts.values()) != index["reports_listed"]:
        defects.append("stats: severity sum differs from indexed report count")
    # Counts alone are insufficient: a corrupted writer can swap severity buckets
    # while preserving the sum. Cross-check every indexed report against stats.
    if isinstance(counts, dict) and set(counts) == set(SEVERITIES) and all(
        _nonnegative_int(v) for v in counts.values()
    ) and isinstance(index.get("reports"), list):
        observed = {severity: 0 for severity in SEVERITIES}
        seen_ids: set[str] = set()
        for position, report in enumerate(index["reports"]):
            if not isinstance(report, dict):
                defects.append(f"index: reports[{position}] is not an object")
                continue
            severity = report.get("severity")
            if severity not in SEVERITIES:
                defects.append(f"index: reports[{position}] has invalid severity")
            else:
                observed[severity] += 1
            report_id = report.get("id")
            if not isinstance(report_id, str) or not report_id.strip():
                defects.append(f"index: reports[{position}] has invalid ID")
            elif report_id in seen_ids:
                defects.append(f"index: reports[{position}] has duplicate ID")
            else:
                seen_ids.add(report_id)
        if observed != counts:
            defects.append("stats: severity distribution disagrees with indexed reports")
    if isinstance(index.get("reports"), list) and isinstance(latest.get("reports"), list):
        expected = index["reports"][:len(latest["reports"])]
        if latest["reports"] != expected:
            defects.append("latest reports are not a prefix of the authoritative index")
    return {"verdict": "BLOCKED" if defects else "ARTIFACT_CONSISTENCY_ONLY",
            "defects": defects, "delivery_certified": False}


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--index", type=Path, required=True)
    parser.add_argument("--latest", type=Path, required=True)
    parser.add_argument("--stats", type=Path, required=True)
    args = parser.parse_args(argv)
    try:
        def load(path: Path) -> Any:
            if path.stat().st_size > 2_000_000:
                raise ValueError("artifact exceeds 2MB bound")
            return json.loads(path.read_text(encoding="utf-8"))
        result = audit_registry(load(args.index), load(args.latest), load(args.stats))
    except (OSError, ValueError, UnicodeError) as exc:
        result = {"verdict": "BLOCKED", "defects": [f"invalid artifact: {type(exc).__name__}"],
                  "delivery_certified": False}
    print(json.dumps(result, sort_keys=True))
    return 0 if result["verdict"] == "ARTIFACT_CONSISTENCY_ONLY" else 2


if __name__ == "__main__":
    raise SystemExit(main())
