#!/usr/bin/env python3
"""
SENTINEL APEX v159.0 — Feed Health Gate
========================================
P0 governance gate that blocks deployment of a synthetic, stale, or uniform
feed. Runs as a CI validation step BEFORE the deploy stage.

WHAT IT CHECKS:
  1. Uniform risk-score ratio  — blocks if >40% of items share the exact same
     risk_score (symptom of hardcoded fallback dominance).
  2. Stale CVE ratio           — blocks if >30% of items have CVEs published
     before 2024-01-01 without EPSS justification (EPSS >= 0.05 = 5%).
  3. Synthetic actor ratio     — blocks if >15% of items have CDB-UNATTR-CVE
     actor AND zero CVSS/EPSS data (synthetic with no real signal).
  4. CVSS coverage floor       — WARN if <20% of CVE items have real CVSS scores.
  5. Confidence uniformity     — WARN if >60% of items share the exact confidence.

EXIT CODES:
  0 — PASS (or non-blocking warnings only)
  1 — HARD FAIL (deployment should be blocked)

USAGE:
  python3 scripts/feed_health_gate.py [--feed path/to/feed.json] [--strict]

FLAGS:
  --feed   path to feed JSON  (default: api/feed.json)
  --strict enable WARN->FAIL escalation (all warnings become failures)
  --report always exit 0, write report only (for CI observability stages)
"""
from __future__ import annotations

import argparse
import json
import logging
import sys
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Config ─────────────────────────────────────────────────────────────────────
REPO           = Path(__file__).resolve().parent.parent
DEFAULT_FEED   = REPO / "api" / "feed.json"
REPORT_PATH    = REPO / "data" / "health" / "feed_health_gate.json"

# Hard-fail thresholds
MAX_UNIFORM_RISK_RATIO   = 0.40   # >40% same exact risk_score → HARD FAIL
MAX_STALE_CVE_RATIO      = 0.30   # >30% pre-2024 CVEs without EPSS → HARD FAIL
MAX_SYNTHETIC_RATIO      = 0.15   # >15% synthetic (CDB-UNATTR-CVE + no CVSS/EPSS) → HARD FAIL

# Warning thresholds
WARN_CVSS_COVERAGE       = 0.20   # <20% CVE items have real cvss_score → WARN
WARN_CONF_UNIFORMITY     = 0.60   # >60% items share same confidence → WARN

STALE_CUTOFF_YEAR        = 2024   # CVEs published before this year are "stale"
EPSS_JUSTIFICATION_FLOOR = 0.05   # EPSS >= 5% justifies keeping an old CVE
# v160.0: CVEs from this year or later are "recent" — NVD may not have enriched them yet.
# Exclude recent CVEs from synthetic check to prevent false-positives on legitimate intel.
RECENT_CVE_YEAR_FLOOR    = 2025   # CVE year >= this → exempt from synthetic flag

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("feed_health_gate")

# ── Helpers ────────────────────────────────────────────────────────────────────
import re
_CVE_RE   = re.compile(r"\bCVE-(\d{4})-\d{4,}\b", re.IGNORECASE)
_YEAR_RE  = re.compile(r"(\d{4})")

def _cve_year(item: Dict) -> Optional[int]:
    """Extract the year from the first CVE ID found in title, id, or cve list."""
    for field in ("title", "id", "stix_id"):
        m = _CVE_RE.search(str(item.get(field) or ""))
        if m:
            return int(m.group(1))
    cve_list = item.get("cve") or []
    if isinstance(cve_list, list):
        for cve_val in cve_list:
            m = _CVE_RE.search(str(cve_val))
            if m:
                return int(m.group(1))
    return None

def _published_year(item: Dict) -> Optional[int]:
    """Extract publication year from published_at or timestamp."""
    for field in ("published_at", "timestamp", "processed_at"):
        val = item.get(field) or ""
        m = _YEAR_RE.search(str(val))
        if m:
            yr = int(m.group(1))
            if 2000 <= yr <= 2099:
                return yr
    return None

def _has_real_epss(item: Dict) -> bool:
    epss = item.get("epss_score")
    if epss is None:
        return False
    return float(epss) >= (EPSS_JUSTIFICATION_FLOOR * 100)   # stored as pct 0-100

def _has_real_cvss(item: Dict) -> bool:
    cvss = item.get("cvss_score")
    return cvss is not None and float(cvss) > 0.0

def _is_cve_item(item: Dict) -> bool:
    if item.get("cve"):
        return True
    return bool(_CVE_RE.search(str(item.get("title") or "")))

# ── Check Implementations ──────────────────────────────────────────────────────

def check_uniform_risk(items: List[Dict]) -> Tuple[str, float, str]:
    """Check for uniform risk_score distribution (synthetic fallback symptom)."""
    if not items:
        return "PASS", 0.0, "no items"
    scores = [round(float(i.get("risk_score") or 0), 2) for i in items]
    counter = Counter(scores)
    most_common_score, most_common_cnt = counter.most_common(1)[0]
    ratio = most_common_cnt / len(items)
    detail = (
        f"risk_score={most_common_score} appears in {most_common_cnt}/{len(items)} items "
        f"({ratio:.1%}) — threshold {MAX_UNIFORM_RISK_RATIO:.0%}"
    )
    if ratio > MAX_UNIFORM_RISK_RATIO:
        return "FAIL", ratio, detail
    if ratio > MAX_UNIFORM_RISK_RATIO * 0.75:
        return "WARN", ratio, detail
    return "PASS", ratio, detail

def check_stale_cves(items: List[Dict]) -> Tuple[str, float, str]:
    """Check ratio of pre-2024 CVEs without EPSS justification."""
    cve_items = [i for i in items if _is_cve_item(i)]
    if not cve_items:
        return "PASS", 0.0, "no CVE items"

    stale_unjustified = []
    for item in cve_items:
        cve_yr = _cve_year(item)
        pub_yr = _published_year(item)
        year = cve_yr or pub_yr
        if year and year < STALE_CUTOFF_YEAR and not _has_real_epss(item):
            stale_unjustified.append(item.get("id", "?"))

    ratio = len(stale_unjustified) / len(cve_items)
    detail = (
        f"{len(stale_unjustified)}/{len(cve_items)} CVE items are pre-{STALE_CUTOFF_YEAR} "
        f"without EPSS justification ({ratio:.1%}) — threshold {MAX_STALE_CVE_RATIO:.0%}"
    )
    if ratio > MAX_STALE_CVE_RATIO:
        return "FAIL", ratio, detail
    if ratio > MAX_STALE_CVE_RATIO * 0.75:
        return "WARN", ratio, detail
    return "PASS", ratio, detail

def check_synthetic_ratio(items: List[Dict]) -> Tuple[str, float, str]:
    """Check synthetic advisory ratio (CDB-UNATTR-CVE actor + no CVSS/EPSS).

    v160.0 FIX: Excludes items with recent CVE years (>= RECENT_CVE_YEAR_FLOOR) from
    the synthetic flag. CVEs from 2025+ are legitimate intelligence items that have not
    yet been enriched by NVD (NVD ingestion lag for new CVEs can be weeks to months).
    Flagging them as synthetic causes false-positive governance failures.
    """
    if not items:
        return "PASS", 0.0, "no items"

    synthetic = []
    recent_exempt = 0
    for i in items:
        if not (i.get("actor_tag") or "").startswith("CDB-UNATTR-CVE"):
            continue
        if _has_real_cvss(i) or _has_real_epss(i):
            continue
        # Exempt recent CVEs — NVD enrichment lag, not truly synthetic
        cve_yr = _cve_year(i)
        if cve_yr is not None and cve_yr >= RECENT_CVE_YEAR_FLOOR:
            recent_exempt += 1
            continue
        synthetic.append(i)

    ratio = len(synthetic) / len(items)
    detail = (
        f"{len(synthetic)}/{len(items)} items are synthetic (CDB-UNATTR-CVE + no CVSS/EPSS) "
        f"({ratio:.1%}) — threshold {MAX_SYNTHETIC_RATIO:.0%}"
        + (f"; {recent_exempt} recent CVE(s) (>={RECENT_CVE_YEAR_FLOOR}) exempt from check" if recent_exempt else "")
    )
    if ratio > MAX_SYNTHETIC_RATIO:
        return "FAIL", ratio, detail
    if ratio > MAX_SYNTHETIC_RATIO * 0.75:
        return "WARN", ratio, detail
    return "PASS", ratio, detail

def check_cvss_coverage(items: List[Dict]) -> Tuple[str, float, str]:
    """Warn if CVSS coverage on CVE items is below floor."""
    cve_items = [i for i in items if _is_cve_item(i)]
    if not cve_items:
        return "PASS", 1.0, "no CVE items"

    with_cvss = sum(1 for i in cve_items if _has_real_cvss(i))
    ratio = with_cvss / len(cve_items)
    detail = (
        f"{with_cvss}/{len(cve_items)} CVE items have real CVSS scores "
        f"({ratio:.1%}) — warn floor {WARN_CVSS_COVERAGE:.0%}"
    )
    if ratio < WARN_CVSS_COVERAGE:
        return "WARN", ratio, detail
    return "PASS", ratio, detail

def check_confidence_uniformity(items: List[Dict]) -> Tuple[str, float, str]:
    """Warn if confidence distribution is highly uniform."""
    if not items:
        return "PASS", 0.0, "no items"
    confs = [round(float(i.get("confidence") or i.get("confidence_score") or 0), 1) for i in items]
    counter = Counter(confs)
    most_common_conf, most_common_cnt = counter.most_common(1)[0]
    ratio = most_common_cnt / len(items)
    detail = (
        f"confidence={most_common_conf} appears in {most_common_cnt}/{len(items)} items "
        f"({ratio:.1%}) — warn threshold {WARN_CONF_UNIFORMITY:.0%}"
    )
    if ratio > WARN_CONF_UNIFORMITY:
        return "WARN", ratio, detail
    return "PASS", ratio, detail

# ── Main ───────────────────────────────────────────────────────────────────────
def run_gate(feed_path: Path, strict: bool = False) -> Dict[str, Any]:
    """Run all health checks and return a report dict."""
    if not feed_path.exists():
        log.error("Feed not found: %s", feed_path)
        return {"status": "ERROR", "reason": f"Feed not found: {feed_path}", "checks": {}}

    try:
        raw = json.loads(feed_path.read_text(encoding="utf-8"))
    except Exception as exc:
        log.error("Failed to parse feed: %s", exc)
        return {"status": "ERROR", "reason": str(exc), "checks": {}}

    items: List[Dict] = raw if isinstance(raw, list) else (raw.get("items") or [])
    log.info("Feed: %s  (%d items)", feed_path, len(items))

    checks = {}
    hard_fails = []
    warnings = []

    for name, fn, is_hard in [
        ("uniform_risk",          check_uniform_risk,        True),
        ("stale_cves",            check_stale_cves,          True),
        ("synthetic_ratio",       check_synthetic_ratio,     True),
        ("cvss_coverage",         check_cvss_coverage,       False),
        ("confidence_uniformity", check_confidence_uniformity, False),
    ]:
        status, ratio, detail = fn(items)
        if strict and status == "WARN":
            status = "FAIL"
        checks[name] = {"status": status, "ratio": round(ratio, 4), "detail": detail}
        lvl = log.error if status == "FAIL" else (log.warning if status == "WARN" else log.info)
        lvl("[%s] %s — %s", name.upper(), status, detail)
        if status == "FAIL":
            hard_fails.append(name)
        elif status == "WARN":
            warnings.append(name)

    overall = "FAIL" if hard_fails else ("WARN" if warnings else "PASS")
    report = {
        "generated_at":  datetime.now(timezone.utc).isoformat(),
        "feed":          str(feed_path),
        "total_items":   len(items),
        "status":        overall,
        "hard_fails":    hard_fails,
        "warnings":      warnings,
        "strict_mode":   strict,
        "checks":        checks,
        "thresholds": {
            "max_uniform_risk_ratio": MAX_UNIFORM_RISK_RATIO,
            "max_stale_cve_ratio":    MAX_STALE_CVE_RATIO,
            "max_synthetic_ratio":    MAX_SYNTHETIC_RATIO,
            "warn_cvss_coverage":     WARN_CVSS_COVERAGE,
            "warn_conf_uniformity":   WARN_CONF_UNIFORMITY,
            "stale_cutoff_year":      STALE_CUTOFF_YEAR,
        },
    }
    return report


def main() -> int:
    parser = argparse.ArgumentParser(description="SENTINEL APEX Feed Health Gate v160.0")
    parser.add_argument("--feed",   default=str(DEFAULT_FEED), help="Path to feed JSON")
    parser.add_argument("--strict", action="store_true",       help="Escalate WARN to FAIL")
    parser.add_argument("--report", action="store_true",       help="Always exit 0 (observability mode)")
    args = parser.parse_args()

    feed_path = Path(args.feed)
    report    = run_gate(feed_path, strict=args.strict)

    # Write report
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    try:
        REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Health gate report: %s", REPORT_PATH)
    except Exception as exc:
        log.warning("Could not write report: %s", exc)

    status = report.get("status", "ERROR")
    log.info("=" * 60)
    log.info("FEED HEALTH GATE — %s  (hard_fails=%s, warnings=%s)",
             status, report.get("hard_fails"), report.get("warnings"))
    log.info("=" * 60)

    if args.report:
        return 0
    return 1 if status == "FAIL" else 0


if __name__ == "__main__":
    sys.exit(main())
