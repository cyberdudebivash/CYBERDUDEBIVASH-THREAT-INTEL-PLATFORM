#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Confidence Calibrator
==========================================================
Enterprise Intelligence Quality: Phase 3

Multi-signal confidence scoring for threat intelligence items.

Confidence score (0-100) is the composite of:
  Signal                  Weight
  ----------------------  ------
  Source trust score      25%
  IOC count / richness    20%
  CVSS severity           15%
  EPSS exploitability     15%
  Item freshness          10%
  MITRE ATT&CK coverage   10%
  KEV membership          5%

Score bands:
  90-100  CRITICAL    (act immediately)
  75-89   HIGH        (prioritize this week)
  50-74   MEDIUM      (standard remediation)
  25-49   LOW         (monitor)
  0-24    INFORMATIONAL

Usage:
  python3 scripts/confidence_calibrator.py [--batch] [--report]
  Or import: from scripts.confidence_calibrator import calibrate_item
"""

import argparse
import json
import math
import pathlib
import datetime
from typing import Dict, List, Any, Optional

# ============================================================
# PATHS
# ============================================================
DATA_ROOT       = pathlib.Path("data")
MANIFEST_PATH   = DATA_ROOT / "intel_manifest.json"
FEED_PATH       = DATA_ROOT / "feed.json"
KEV_PATH        = DATA_ROOT / "quality" / "kev_catalog.json"
TRUST_PATH      = DATA_ROOT / "quality" / "source_trust_scores.json"
OUTPUT_PATH     = DATA_ROOT / "quality" / "confidence_calibration.json"

# ============================================================
# CONSTANTS
# ============================================================
MAX_AGE_HOURS   = 336      # 14 days freshness window
DEFAULT_TRUST   = 0.60


# ============================================================
# SIGNAL EXTRACTORS
# ============================================================

def _source_trust_score(item: Dict, trust_map: Dict) -> float:
    """0.0-1.0: source domain trust score."""
    return float(item.get("source_trust_score",
                          trust_map.get(item.get("source_domain", ""), {}).get("trust_score",
                          DEFAULT_TRUST)))


def _ioc_richness_score(item: Dict) -> float:
    """0.0-1.0: logarithmic IOC count scoring."""
    iocs  = item.get("iocs", [])
    count = item.get("ioc_count", len(iocs) if isinstance(iocs, list) else 0)
    if count == 0:
        return 0.0
    # 1 IOC = 0.30, 5 IOCs = 0.55, 20+ IOCs = 1.0
    return min(1.0, round(0.30 + math.log10(max(1, count)) * 0.35, 3))


def _cvss_score(item: Dict) -> float:
    """0.0-1.0: CVSS severity normalized."""
    cvss = item.get("cvss_score") or item.get("cvss")
    if cvss is None:
        return 0.40  # neutral when no CVSS
    try:
        v = float(cvss)
        return round(min(1.0, v / 10.0), 3)
    except (ValueError, TypeError):
        return 0.40


def _epss_score(item: Dict) -> float:
    """0.0-1.0: EPSS exploitability (already 0-1)."""
    epss = item.get("epss_score") or item.get("epss")
    if epss is None:
        return 0.20  # neutral when no EPSS
    try:
        return round(min(1.0, max(0.0, float(epss))), 3)
    except (ValueError, TypeError):
        return 0.20


def _freshness_score(item: Dict) -> float:
    """0.0-1.0: linear decay by item age."""
    pub = item.get("published_at", "")
    if not pub:
        return 0.70
    try:
        ts_str = str(pub).replace("Z", "+00:00").replace(" ", "T")
        ts = datetime.datetime.fromisoformat(ts_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=datetime.timezone.utc)
        now   = datetime.datetime.now(datetime.timezone.utc)
        age_h = max(0.0, (now - ts).total_seconds() / 3600)
        if age_h > 720:
            return 0.30
        return round(max(0.30, 1.0 - (age_h / MAX_AGE_HOURS) * 0.70), 3)
    except Exception:
        return 0.70


def _mitre_coverage_score(item: Dict) -> float:
    """0.0-1.0: MITRE ATT&CK technique depth."""
    tactics    = item.get("mitre_tactics", [])
    techniques = item.get("techniques", [])
    if isinstance(tactics, list):
        t_count = len(tactics)
    elif isinstance(tactics, dict):
        t_count = 1
    else:
        t_count = 0
    if isinstance(techniques, list):
        tech_count = len(techniques)
    else:
        tech_count = 0
    total = t_count + tech_count
    if total == 0:
        return 0.20
    return min(1.0, round(0.30 + math.log10(max(1, total)) * 0.40, 3))


def _kev_score(item: Dict, kev_ids: set) -> float:
    """1.0 if any CVE in item is in CISA KEV catalog, else 0.0."""
    # Check explicit kev flag first
    if item.get("in_kev") or item.get("is_kev") or item.get("kev"):
        return 1.0
    # Check IOC list for CVE IDs
    iocs = item.get("iocs", [])
    if isinstance(iocs, list):
        for ioc in iocs:
            ioc_str = str(ioc).upper()
            if ioc_str in kev_ids:
                return 1.0
    # Check title / description
    for field in ["title", "description", "summary"]:
        text = item.get(field, "")
        if not text:
            continue
        import re
        cves = re.findall(r"CVE-\d{4}-\d+", str(text), re.IGNORECASE)
        for cve in cves:
            if cve.upper() in kev_ids:
                return 1.0
    return 0.0


# ============================================================
# COMPOSITE CONFIDENCE SCORE
# v166.0 REBALANCED WEIGHTS — fixes BUG-03 / BUG-09
#
# Previous weights produced 7-14% confidence for CISA KEV-confirmed
# CVSS 9.1 advisories because:
#   - source_trust anchored baseline at 0.25×0.60 = 0.15 (15 pts) regardless of intelligence quality
#   - KEV was only 5% — a KEV-confirmed exploit added just 5 pts
#   - IOC richness penalised advisories that have real intelligence but few network IOCs
#
# New model:
#   - KEV becomes the dominant signal (20%) — binary verified exploitation truth
#   - CVSS and EPSS together are 35% — quantified severity/probability signals
#   - source_trust reduced to 15% — source quality matters less than verified facts
#   - IOC richness reduced to 10% — not all high-value intel has network IOCs
#   - Freshness kept at 10% — recency still matters
#   - MITRE kept at 10% — TTP depth is an intelligence quality proxy
#
# FLOORS (minimum confidence regardless of other signals):
#   KEV-confirmed:          ≥ 75%
#   CVSS ≥ 9.0:             ≥ 65%
#   EPSS ≥ 50%:             ≥ 60%
#   CVSS ≥ 7.0 + KEV:       ≥ 85%
#   CVSS ≥ 9.0 + KEV:       ≥ 90%
# ============================================================
WEIGHTS = {
    "cvss":         0.20,   # was 0.15 — quantified severity baseline
    "epss":         0.15,   # was 0.15 — real-world exploit probability
    "kev":          0.20,   # was 0.05 — binary CISA-confirmed exploitation truth ← BIG FIX
    "source_trust": 0.15,   # was 0.25 — source credibility (all ≥60%, so less differentiating)
    "ioc_richness": 0.10,   # was 0.20 — IOC count (not all quality intel has network IOCs)
    "freshness":    0.10,   # unchanged — recency
    "mitre":        0.10,   # unchanged — TTP depth / intelligence completeness
}
assert abs(sum(WEIGHTS.values()) - 1.0) < 1e-9, "Weights must sum to 1.0"

BAND_MAP = [
    (90, "VERIFIED"),
    (75, "HIGH"),
    (55, "MEDIUM"),
    (30, "LOW"),
    (0,  "PRELIMINARY"),
]


def score_to_band(score: float) -> str:
    for threshold, label in BAND_MAP:
        if score >= threshold:
            return label
    return "PRELIMINARY"


def _apply_confidence_floors(score: float, item: Dict, kev_val: float) -> float:
    """Apply minimum confidence floors based on authoritative signal combinations."""
    cvss = item.get("cvss_score") or item.get("cvss") or 0.0
    epss = item.get("epss_score") or item.get("epss") or 0.0
    try:
        cvss_f = float(cvss)
        epss_f = float(str(epss).rstrip("%"))
        if epss_f > 1.0:
            epss_f /= 100.0
    except (ValueError, TypeError):
        cvss_f = 0.0
        epss_f = 0.0

    # KEV-confirmed floors — CISA KEV is binary verified exploitation
    if kev_val > 0:
        if cvss_f >= 9.0:
            score = max(score, 90.0)   # CVSS≥9.0 + KEV = very high confidence
        elif cvss_f >= 7.0:
            score = max(score, 85.0)   # CVSS≥7.0 + KEV = high confidence
        else:
            score = max(score, 75.0)   # Any KEV = minimum 75%

    # Single-signal floors
    if cvss_f >= 9.0:
        score = max(score, 65.0)
    elif cvss_f >= 7.0:
        score = max(score, 50.0)
    if epss_f >= 0.50:
        score = max(score, 60.0)
    elif epss_f >= 0.20:
        score = max(score, 40.0)

    return round(min(score, 97.0), 1)


def calibrate_item(
    item: Dict,
    trust_map: Optional[Dict] = None,
    kev_ids:   Optional[set]   = None,
) -> Dict:
    """
    Compute and stamp composite confidence score onto item.
    Returns modified item dict.
    """
    if trust_map is None:
        trust_map = {}
    if kev_ids is None:
        kev_ids = set()

    kev_val = _kev_score(item, kev_ids)
    signals = {
        "cvss":         _cvss_score(item),
        "epss":         _epss_score(item),
        "kev":          kev_val,
        "source_trust": _source_trust_score(item, trust_map),
        "ioc_richness": _ioc_richness_score(item),
        "freshness":    _freshness_score(item),
        "mitre":        _mitre_coverage_score(item),
    }

    raw_score = sum(signals[k] * WEIGHTS[k] for k in signals)
    confidence = raw_score * 100.0

    # Apply authoritative signal floors (BUG-03 fix)
    confidence = _apply_confidence_floors(confidence, item, kev_val)

    item["confidence_score"]   = confidence
    item["confidence_band"]    = score_to_band(confidence)
    item["confidence_signals"] = {k: round(v, 3) for k, v in signals.items()}

    return item


# ============================================================
# BATCH CALIBRATION
# ============================================================
def load_trust_map() -> Dict:
    if TRUST_PATH.exists():
        try:
            raw = json.loads(TRUST_PATH.read_text(encoding="utf-8"))
            return raw.get("trust_scores", {})
        except Exception:
            pass
    return {}


def load_kev_ids() -> set:
    if KEV_PATH.exists():
        try:
            raw = json.loads(KEV_PATH.read_text(encoding="utf-8"))
            vulns = raw.get("vulnerabilities", raw if isinstance(raw, list) else [])
            return {v.get("cveID", v.get("cve_id", "")).upper()
                    for v in vulns if isinstance(v, dict)}
        except Exception:
            pass
    return set()


def load_items() -> List[Dict]:
    items: Dict[str, Dict] = {}
    for path in [MANIFEST_PATH, FEED_PATH]:
        if not path.exists():
            continue
        try:
            raw = json.loads(path.read_text(encoding="utf-8", errors="replace"))
            batch = raw if isinstance(raw, list) else raw.get("items", raw.get("advisories", []))
            for item in batch:
                sid = item.get("stix_id") or item.get("id", "")
                if sid:
                    items.setdefault(sid, item)
        except Exception as e:
            print(f"[CONF] Warning loading {path}: {e}")
    return list(items.values())


def run_batch_calibration(report: bool = False) -> Dict:
    """Full batch calibration pass over all intel items."""
    items      = load_items()
    trust_map  = load_trust_map()
    kev_ids    = load_kev_ids()

    print(f"[CONF] Calibrating {len(items)} items | "
          f"{len(trust_map)} trust entries | {len(kev_ids)} KEV IDs")

    calibrated = []
    band_counts: Dict[str, int] = {
        "VERIFIED": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "PRELIMINARY": 0
    }

    for item in items:
        c = calibrate_item(item, trust_map, kev_ids)
        calibrated.append(c)
        band = c.get("confidence_band", "INFORMATIONAL")
        band_counts[band] = band_counts.get(band, 0) + 1

    scores = [c.get("confidence_score", 0.0) for c in calibrated]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0
    max_score = round(max(scores), 1) if scores else 0.0
    min_score = round(min(scores), 1) if scores else 0.0

    summary = {
        "generated_at":    datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema":          "sentinel_apex_confidence_calibration_v1",
        "items_calibrated": len(calibrated),
        "avg_confidence":  avg_score,
        "max_confidence":  max_score,
        "min_confidence":  min_score,
        "band_distribution": band_counts,
        "signal_weights":  WEIGHTS,
    }

    output = {"summary": summary, "items": calibrated}

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[CONF] Summary written: {OUTPUT_PATH}")

    if report:
        print("\n" + "=" * 60)
        print("CONFIDENCE CALIBRATION REPORT")
        print("=" * 60)
        print(f"  Items calibrated:    {len(calibrated)}")
        print(f"  Avg confidence:      {avg_score}")
        print(f"  Max confidence:      {max_score}")
        print(f"  Min confidence:      {min_score}")
        print("\n  BAND DISTRIBUTION:")
        for band in ["VERIFIED", "HIGH", "MEDIUM", "LOW", "PRELIMINARY"]:
            cnt = band_counts.get(band, 0)
            pct = round(cnt / max(1, len(calibrated)) * 100, 1)
            bar = "#" * min(40, int(pct * 0.4))
            print(f"    {band:<15} {cnt:>5}  {pct:>5.1f}%  {bar}")
        print("=" * 60)

    return summary


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL APEX Confidence Calibrator")
    parser.add_argument("--batch",  action="store_true", help="Run full batch calibration")
    parser.add_argument("--report", action="store_true", help="Print report to stdout")
    args = parser.parse_args()

    if args.batch or args.report:
        run_batch_calibration(report=args.report)
    else:
        run_batch_calibration(report=True)
on(report: bool = False) -> Dict:
    """Full batch calibration pass over all intel items."""
    items      = load_items()
    trust_map  = load_trust_map()
    kev_ids    = load_kev_ids()

    print(f"[CONF] Calibrating {len(items)} items | "
          f"{len(trust_map)} trust entries | {len(kev_ids)} KEV IDs")

    calibrated = []
    band_counts: Dict[str, int] = {
        "VERIFIED": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "PRELIMINARY": 0
    }

    for item in items:
        c = calibrate_item(item, trust_map, kev_ids)
        calibrated.append(c)
        band = c.get("confidence_band", "PRELIMINARY")
        band_counts[band] = band_counts.get(band, 0) + 1

    scores = [c.get("confidence_score", 0.0) for c in calibrated]
    avg_score = round(sum(scores) / len(scores), 1) if scores else 0.0
    max_score = round(max(scores), 1) if scores else 0.0
    min_score = round(min(scores), 1) if scores else 0.0

    summary = {
        "generated_at":     datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ"),
        "schema":           "sentinel_apex_confidence_calibration_v2",
        "items_calibrated": len(calibrated),
        "avg_confidence":   avg_score,
        "max_confidence":   max_score,
        "min_confidence":   min_score,
        "band_distribution": band_counts,
        "signal_weights":   WEIGHTS,
    }

    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(summary, indent=2), encoding="utf-8")
    print(f"[CONF] Summary written: {OUTPUT_PATH}")

    if report:
        print("\n" + "=" * 60)
        print("CONFIDENCE CALIBRATION REPORT v166.0")
        print("=" * 60)
        print(f"  Items calibrated : {len(calibrated)}")
        print(f"  Avg confidence   : {avg_score}%")
        print(f"  Max confidence   : {max_score}%")
        print(f"  Min confidence   : {min_score}%")
        print("\n  BAND DISTRIBUTION:")
        for band in ["VERIFIED", "HIGH", "MEDIUM", "LOW", "PRELIMINARY"]:
            cnt = band_counts.get(band, 0)
            pct = round(cnt / max(1, len(calibrated)) * 100, 1)
            bar = "#" * min(40, int(pct * 0.4))
            print(f"    {band:<15} {cnt:>5}  {pct:>5.1f}%  {bar}")
        print("=" * 60)

    return summary


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL APEX Confidence Calibrator v166.0")
    parser.add_argument("--batch",  action="store_true", help="Run full batch calibration")
    parser.add_argument("--report", action="store_true", help="Print report to stdout")
    args = parser.parse_args()
    run_batch_calibration(report=True)
