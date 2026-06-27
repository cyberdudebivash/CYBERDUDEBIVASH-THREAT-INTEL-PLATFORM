#!/usr/bin/env python3
"""
scripts/p23_patch_prioritizer.py
CYBERDUDEBIVASH® SENTINEL APEX — P23.5 Risk-Based Patch Prioritizer v1.0.0
==========================================================================
P23.5 — Risk-Based Patch Prioritization

Replaces generic severity-based patching guidance with a multi-factor
risk score using real field data:

  KEV (CISA Known Exploited Vulnerabilities) — weight: 40pts
  CVSS score                                  — weight: 8–25pts
  EPSS (Exploitation Prediction Scoring)      — weight: 10–20pts
  Exploit maturity / public PoC              — weight: 15pts

Output tiers:
  PATCH IMMEDIATELY      — score ≥55 OR KEV confirmed
  PATCH WITHIN 24 HOURS  — score ≥35
  PATCH WITHIN 7 DAYS    — score ≥20
  PATCH THIS MONTH       — score ≥10
  MONITOR                — CVSS present but low score
  NO IMMEDIATE ACTION    — insufficient scoring data

ZERO FABRICATION — all scoring uses existing feed field data only.
ADDITIVE ONLY    — no schema, API, or KV namespace modified.

Exit codes:
  0 — processing complete (non-blocking)
  1 — feed unreadable or empty

Writes: data/quality/p23_patch_priority_report.json
"""
from __future__ import annotations

import json
import logging
import os
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] P23-PATCH %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("p23-patch")

REPO      = Path(__file__).resolve().parent.parent
DRY_RUN   = os.environ.get("DRY_RUN",   "false").strip().lower() == "true"
FEED_PATH = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
OUT_PATH  = REPO / "data" / "quality" / "p23_patch_priority_report.json"


def _score_item(item: Dict) -> Dict:
    cvss    = float(item.get("cvss_score") or item.get("cvss") or 0)
    epss    = float(item.get("epss_score") or 0)
    kev     = bool(item.get("kev_present") or item.get("kev"))
    exploit = str(item.get("exploit_maturity") or item.get("has_exploit") or "").lower()
    has_poc = any(kw in exploit for kw in ("poc", "exploited", "public", "wild", "true"))

    score   = 0
    reasons = []

    if kev:
        score += 40
        reasons.append("CISA KEV — confirmed active exploitation in the wild")
    if cvss >= 9.0:
        score += 25
        reasons.append(f"CVSS {cvss:.1f} — Critical (network-exploitable, no authentication required)")
    elif cvss >= 7.0:
        score += 15
        reasons.append(f"CVSS {cvss:.1f} — High severity")
    elif cvss >= 4.0:
        score += 8
        reasons.append(f"CVSS {cvss:.1f} — Medium severity")
    if epss >= 50.0:
        score += 20
        reasons.append(f"EPSS {epss:.1f}% — High probability of exploitation within 30 days")
    elif epss >= 10.0:
        score += 10
        reasons.append(f"EPSS {epss:.1f}% — Elevated exploitation probability")
    if has_poc:
        score += 15
        reasons.append("Public exploit code or PoC available — exploitation barrier is low")

    if kev or score >= 55:
        priority  = "PATCH IMMEDIATELY"
        timeframe = "Within 24 hours"
        rationale = "Immediate patch deployment is mandatory. Delays create unacceptable operational risk."
    elif score >= 35:
        priority  = "PATCH WITHIN 24 HOURS"
        timeframe = "Within 24 hours"
        rationale = "Treat as emergency change. Schedule out-of-band patching with change management approval."
    elif score >= 20:
        priority  = "PATCH WITHIN 7 DAYS"
        timeframe = "Within 7 days"
        rationale = "Patch in next security maintenance window. Apply compensating controls until patched."
    elif score >= 10:
        priority  = "PATCH THIS MONTH"
        timeframe = "Within 30 days"
        rationale = "Schedule in next planned maintenance cycle. Monitor for exploitation uptick."
    elif cvss > 0:
        priority  = "MONITOR"
        timeframe = "Track for changes"
        rationale = "No immediate patch required. Monitor KEV and EPSS for escalation."
    else:
        priority  = "NO IMMEDIATE ACTION"
        timeframe = "Standard review cycle"
        rationale = "Insufficient scoring data. Assess manually if asset exposure is relevant."

    return {
        "id":        item.get("stix_id") or item.get("id") or "unknown",
        "title":     str(item.get("title", ""))[:100],
        "cve":       item.get("cve_id") or (item.get("cve_ids") or [None])[0],
        "cvss":      cvss if cvss else None,
        "epss":      epss if epss else None,
        "kev":       kev,
        "severity":  item.get("severity"),
        "priority":  priority,
        "timeframe": timeframe,
        "score":     score,
        "reasons":   reasons,
        "rationale": rationale,
    }


def run(path: Path) -> Dict:
    if not path.exists():
        log.warning("Feed not found: %s", path)
        return {}
    try:
        raw  = path.read_bytes().rstrip(b"\x00").replace(b"\x00", b"")
        data = json.loads(raw.decode("utf-8", errors="replace"))
    except Exception as exc:
        log.error("Failed to load feed: %s", exc)
        return {}

    if isinstance(data, list):
        items = data
    elif isinstance(data, dict):
        items = next(
            (data[k] for k in ("items", "advisories", "feed", "data")
             if k in data and isinstance(data[k], list)),
            []
        )
    else:
        return {}

    results = []
    counts  = {
        "PATCH IMMEDIATELY":     0,
        "PATCH WITHIN 24 HOURS": 0,
        "PATCH WITHIN 7 DAYS":   0,
        "PATCH THIS MONTH":      0,
        "MONITOR":               0,
        "NO IMMEDIATE ACTION":   0,
    }

    for item in items:
        if not isinstance(item, dict):
            continue
        r = _score_item(item)
        results.append(r)
        counts[r["priority"]] = counts.get(r["priority"], 0) + 1

    immediate = counts["PATCH IMMEDIATELY"]
    log.info(
        "Processed %d items | IMMEDIATE: %d | 24H: %d | 7D: %d | 30D: %d | MONITOR: %d",
        len(results),
        immediate,
        counts["PATCH WITHIN 24 HOURS"],
        counts["PATCH WITHIN 7 DAYS"],
        counts["PATCH THIS MONTH"],
        counts["MONITOR"],
    )
    if immediate > 0:
        log.warning("P23.5: %d item(s) require IMMEDIATE patching — KEV or critical risk score", immediate)

    return {
        "version":           "P23.5",
        "generated_at":      datetime.now(timezone.utc).isoformat(),
        "feed_path":         str(path),
        "items_processed":   len(results),
        "priority_distribution": counts,
        "immediate_count":   immediate,
        "items":             results,
    }


def main() -> int:
    log.info("P23.5 Patch Prioritizer v1.0.0 — DRY_RUN=%s", DRY_RUN)

    report = run(FEED_PATH)
    if not report:
        log.error("No report generated — feed empty or unreadable")
        return 1

    if not DRY_RUN:
        OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
        tmp = OUT_PATH.with_suffix(".tmp_p23patch")
        try:
            tmp.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
            tmp.replace(OUT_PATH)
            log.info("Report written: %s", OUT_PATH)
        except Exception as exc:
            log.error("Failed to write report: %s", exc)
            tmp.unlink(missing_ok=True)
            return 1
    else:
        log.info("[DRY_RUN] Would write patch priority report: %d items", report["items_processed"])

    log.info("P23.5 Patch Prioritizer PASS")
    return 0


if __name__ == "__main__":
    sys.exit(main())
