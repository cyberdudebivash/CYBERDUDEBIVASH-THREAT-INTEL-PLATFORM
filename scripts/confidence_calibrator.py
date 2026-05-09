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
# ============================================================
WEIGHTS = {
    "source_trust": 0.25,
    "ioc_richness": 0.20,
    "cvss":         0.15,
    "epss":         0.15,
    "freshness":    0.10,
    "mitre":        0.10,
    "kev":          0.05,
}

BAND_MAP = [
    (90, "CRITICAL"),
    (75, "HIGH"),
    (50, "MEDIUM"),
    (25, "LOW"),
    (0,  "INFORMATIONAL"),
]


def score_to_band(score: float) -> str:
    for threshold, label in BAND_MAP:
        if score >= threshold:
            return label
    return "INFORMATIONAL"


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

    signals = {
        "source_trust": _source_trust_score(item, trust_map),
        "ioc_richness": _ioc_richness_score(item),
        "cvss":         _cvss_score(item),
        "epss":         _epss_score(item),
        "freshness":    _freshness_score(item),
        "mitre":        _mitre_coverage_score(item),
        "kev":          _kev_score(item, kev_ids),
    }

    raw_score = sum(signals[k] * WEIGHTS[k] for k in signals)
    confidence = round(raw_score * 100, 1)

    item["confidence_score"]  = confidence
    item["confidence_band"]   = score_to_band(confidence)
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
        "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFORMATIONAL": 0
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
        for band in ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFORMATIONAL"]:
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
