#!/usr/bin/env python3
"""
scripts/ci_stats_extract.py
CI helper: extract summary stats from quality report JSON files for workflow display.
Usage: python3 scripts/ci_stats_extract.py <report_key>
  report_key: p21 | p22 | p23
Prints space-separated values on stdout; exits 0 always (non-blocking CI helper).
"""
from __future__ import annotations
import json, pathlib, sys

_ROOT = pathlib.Path(__file__).resolve().parent.parent

_REPORTS: dict = {
    "p21": (
        _ROOT / "data" / "quality" / "p21_certification_report.json",
        lambda d: [
            d.get("total_items", 0),
            d.get("average_score", 0),
            d.get("level_distribution", {}).get("PREMIUM_CERTIFIED", 0),
            d.get("level_distribution", {}).get("ENTERPRISE_READY", 0),
        ],
    ),
    "p22": (
        _ROOT / "data" / "quality" / "p22_contradiction_report.json",
        lambda d: [
            d.get("items_checked", 0),
            d.get("total_contradictions", 0),
            d.get("error_count", 0),
            d.get("warning_count", 0),
        ],
    ),
    "p23": (
        _ROOT / "data" / "quality" / "p23_patch_priority_report.json",
        lambda d: [
            d.get("items_processed", 0),
            d.get("immediate_count", 0),
        ],
    ),
    "p24": (
        _ROOT / "data" / "quality" / "p24_commercial_certification.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("overall_pct", 0),
            d.get("blocker_count", 0),
        ],
    ),
    "p25": (
        _ROOT / "data" / "quality" / "p25_enterprise_trust_gate.json",
        lambda d: [
            d.get("release_tier", "UNKNOWN"),
            d.get("blocker_count", 0),
            d.get("feed_items", 0),
        ],
    ),
}

_FALLBACKS = {"p21": "? ? ? ?", "p22": "? ? ? ?", "p23": "? ?", "p24": "UNKNOWN 0 0", "p25": "UNKNOWN 0 0"}


def main() -> None:
    key = sys.argv[1] if len(sys.argv) > 1 else ""
    if key not in _REPORTS:
        print(_FALLBACKS.get(key, "?"))
        return
    path, extractor = _REPORTS[key]
    try:
        data = json.loads(path.read_bytes())
        print(" ".join(str(v) for v in extractor(data)))
    except Exception:
        print(_FALLBACKS[key])


if __name__ == "__main__":
    main()
