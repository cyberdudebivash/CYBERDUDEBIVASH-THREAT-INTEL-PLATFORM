#!/usr/bin/env python3
"""
scripts/feed_freshness_governance.py
CYBERDUDEBIVASH® SENTINEL APEX — Feed Freshness Governance v1.0

PURPOSE:
  Validates feed freshness against commercial SLA thresholds.
  Detects stale feeds, last-seen gaps, and freshness SLA violations.
  Writes structured report for operational observability and customer SLA enforcement.

SLA TIERS:
  CRITICAL feeds: max 2 hours stale before SLA violation
  HIGH feeds:     max 6 hours
  STANDARD feeds: max 24 hours

EXIT CODES:
  0 = All feeds within SLA
  1 = One or more CRITICAL SLA violations (ops action required)
  3 = Soft violations (DEGRADED state — tracked but deployment allowed)

OUTPUTS:
  data/health/feed_freshness_report.json  — structured SLA report
  data/health/feed_sla_violations.jsonl   — append log of all violations
"""

from __future__ import annotations

import json
import logging
import os
import sys
import tempfile
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(name)s] %(levelname)s %(message)s",
)
logger = logging.getLogger("CDB-FEED-FRESHNESS")

# ── Paths ─────────────────────────────────────────────────────────────────────
BASE_DIR    = Path(__file__).resolve().parent.parent
DATA_DIR    = BASE_DIR / "data"
HEALTH_DIR  = DATA_DIR / "health"
STIX_DIR    = DATA_DIR / "stix"
FEED_MANIFEST = DATA_DIR / "feed_manifest.json"
ALT_MANIFEST  = STIX_DIR / "feed_manifest.json"

REPORT_PATH     = HEALTH_DIR / "feed_freshness_report.json"
VIOLATION_LOG   = HEALTH_DIR / "feed_sla_violations.jsonl"

HEALTH_DIR.mkdir(parents=True, exist_ok=True)

# ── SLA Thresholds (hours) ────────────────────────────────────────────────────
SLA_CRITICAL_HOURS = 2
SLA_HIGH_HOURS     = 6
SLA_STANDARD_HOURS = 24

# Feed priority tiers — feeds not listed default to STANDARD
FEED_PRIORITY: Dict[str, str] = {
    # CRITICAL: active threat intelligence feeds — SLA 2h
    "cisa.gov":                   "CRITICAL",
    "nvd.nist.gov":               "CRITICAL",
    "securelist.com":             "CRITICAL",
    "cloud.google.com":           "CRITICAL",
    "unit42.paloaltonetworks.com": "CRITICAL",
    "rapid7.com":                 "CRITICAL",
    "thehackernews.com":          "CRITICAL",
    "ransomware.live":            "CRITICAL",
    # HIGH: high-quality secondary sources — SLA 6h
    "krebsonsecurity.com":        "HIGH",
    "securityaffairs.com":        "HIGH",
    "cybersecuritynews.com":      "HIGH",
    "cyberscoop.com":             "HIGH",
    "bleepingcomputer.com":       "HIGH",
    "sentinelone.com":            "HIGH",
    "crowdstrike.com":            "HIGH",
    "checkpoint.com":             "HIGH",
    # STANDARD: enrichment and context feeds — SLA 24h
    "aws.amazon.com":             "STANDARD",
    "blogs.microsoft.com":        "STANDARD",
    "sploitus.com":               "STANDARD",
    "zerodayinitiative.com":      "STANDARD",
}


def _sla_hours(priority: str) -> int:
    return {
        "CRITICAL": SLA_CRITICAL_HOURS,
        "HIGH":     SLA_HIGH_HOURS,
        "STANDARD": SLA_STANDARD_HOURS,
    }.get(priority, SLA_STANDARD_HOURS)


def _get_domain(url: str) -> str:
    try:
        from urllib.parse import urlparse
        return urlparse(url).netloc.lower().lstrip("www.")
    except Exception:
        return ""


def _load_manifest() -> List[Dict]:
    for path in (FEED_MANIFEST, ALT_MANIFEST):
        if path.exists():
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                if isinstance(data, list):
                    return data
                for key in ("advisories", "entries", "reports", "items"):
                    if isinstance(data.get(key), list):
                        return data[key]
            except Exception as e:
                logger.warning(f"Manifest load error {path}: {e}")
    return []


def _parse_ts(ts: Optional[str]) -> Optional[datetime]:
    if not ts:
        return None
    for fmt in ("%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S.%fZ",
                "%Y-%m-%dT%H:%M:%S%z", "%Y-%m-%d"):
        try:
            dt = datetime.strptime(ts[:26], fmt[:len(ts)])
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    return None


def _atomic_write(path: Path, data: Any):
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        os.replace(tmp, str(path))
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def _append_violation_log(violation: Dict):
    with open(str(VIOLATION_LOG), "a", encoding="utf-8") as f:
        f.write(json.dumps(violation) + "\n")


# ── Core Governance ───────────────────────────────────────────────────────────

def run_feed_freshness_governance() -> int:
    """
    Main governance function. Returns exit code:
      0 = OK, 1 = CRITICAL violations, 3 = DEGRADED (soft violations).
    """
    now = datetime.now(timezone.utc)
    logger.info(f"[FRESHNESS] Feed freshness governance starting — {now.isoformat()}")

    entries = _load_manifest()
    if not entries:
        logger.warning("[FRESHNESS] No manifest entries found — DEGRADED")
        _atomic_write(REPORT_PATH, {
            "status": "DEGRADED",
            "reason": "No manifest entries",
            "run_at": now.isoformat(),
        })
        return 3

    # Group entries by domain, track latest timestamp per domain
    domain_latest: Dict[str, datetime] = {}
    domain_entry_count: Dict[str, int] = {}
    for entry in entries:
        url = entry.get("source_url", "") or entry.get("blog_url", "")
        ts_str = (
            entry.get("timestamp") or entry.get("published_at") or
            entry.get("processed_at") or ""
        )
        domain = _get_domain(url)
        if not domain:
            continue
        ts = _parse_ts(ts_str)
        domain_entry_count[domain] = domain_entry_count.get(domain, 0) + 1
        if ts:
            prev = domain_latest.get(domain)
            if prev is None or ts > prev:
                domain_latest[domain] = ts

    # Evaluate freshness against SLA per domain
    feed_results: List[Dict] = []
    critical_violations: List[str] = []
    soft_violations: List[str] = []

    for domain, latest_ts in sorted(domain_latest.items()):
        age_hours = (now - latest_ts).total_seconds() / 3600
        priority  = FEED_PRIORITY.get(domain, "STANDARD")
        sla_h     = _sla_hours(priority)
        within_sla = age_hours <= sla_h
        status = "OK" if within_sla else (
            "CRITICAL_VIOLATION" if priority == "CRITICAL" else "SLA_VIOLATION"
        )
        result = {
            "domain":         domain,
            "priority":       priority,
            "sla_hours":      sla_h,
            "latest_ts":      latest_ts.isoformat(),
            "age_hours":      round(age_hours, 2),
            "within_sla":     within_sla,
            "status":         status,
            "entry_count":    domain_entry_count.get(domain, 0),
        }
        feed_results.append(result)
        if not within_sla:
            violation = dict(result, run_at=now.isoformat())
            _append_violation_log(violation)
            if priority == "CRITICAL":
                critical_violations.append(domain)
                logger.error(
                    f"[FRESHNESS] CRITICAL SLA VIOLATION: {domain} "
                    f"— {age_hours:.1f}h stale (SLA: {sla_h}h)"
                )
            else:
                soft_violations.append(domain)
                logger.warning(
                    f"[FRESHNESS] SLA violation: {domain} "
                    f"— {age_hours:.1f}h stale (SLA: {sla_h}h)"
                )
        else:
            logger.info(
                f"[FRESHNESS] OK: {domain} — {age_hours:.1f}h old "
                f"(SLA: {sla_h}h, priority: {priority})"
            )

    # Check for feeds with NO recent entries (domain known but no timestamp)
    for domain in set(domain_entry_count) - set(domain_latest):
        priority = FEED_PRIORITY.get(domain, "STANDARD")
        result = {
            "domain":      domain,
            "priority":    priority,
            "sla_hours":   _sla_hours(priority),
            "latest_ts":   None,
            "age_hours":   None,
            "within_sla":  False,
            "status":      "NO_TIMESTAMP",
            "entry_count": domain_entry_count.get(domain, 0),
        }
        feed_results.append(result)
        logger.warning(f"[FRESHNESS] NO_TIMESTAMP: {domain} ({domain_entry_count[domain]} entries)")

    # Compute summary
    ok_count       = sum(1 for r in feed_results if r["status"] == "OK")
    total          = len(feed_results)
    freshness_pct  = round(100.0 * ok_count / total, 1) if total > 0 else 0.0
    overall_status = (
        "CRITICAL" if critical_violations else
        "DEGRADED" if soft_violations else
        "HEALTHY"
    )

    report = {
        "run_at":              now.isoformat(),
        "overall_status":      overall_status,
        "freshness_pct":       freshness_pct,
        "feeds_checked":       total,
        "feeds_ok":            ok_count,
        "critical_violations": critical_violations,
        "soft_violations":     soft_violations,
        "sla_thresholds": {
            "CRITICAL_hours": SLA_CRITICAL_HOURS,
            "HIGH_hours":     SLA_HIGH_HOURS,
            "STANDARD_hours": SLA_STANDARD_HOURS,
        },
        "feed_results": sorted(feed_results, key=lambda x: (x["within_sla"], x["domain"])),
    }

    _atomic_write(REPORT_PATH, report)
    logger.info(
        f"[FRESHNESS] Governance complete — status={overall_status} "
        f"freshness={freshness_pct}% "
        f"critical_violations={len(critical_violations)} "
        f"soft_violations={len(soft_violations)}"
    )

    if critical_violations:
        return 1
    if soft_violations:
        return 3
    return 0


if __name__ == "__main__":
    sys.exit(run_feed_freshness_governance())
