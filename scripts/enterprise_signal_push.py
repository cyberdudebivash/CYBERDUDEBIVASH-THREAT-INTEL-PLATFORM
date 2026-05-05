#!/usr/bin/env python3
"""
scripts/enterprise_signal_push.py
CYBERDUDEBIVASH(R) SENTINEL APEX v143.1.0 — Enterprise Signal Push Engine
==========================================================================
Generates Critical Threat Forecasts for the Enterprise Tier ($499/mo) using
Gradient Boosting sector-impact prediction.

PIPELINE INTEGRATION:
  - Runs after anomaly_radar_engine.py (Phase 2, crash-guard wrapped)
  - Reads api/feed.json + data/ai/anomaly_radar.json
  - Produces data/ai/enterprise_forecast.json (R2-uploadable)
  - Sector forecasts drive the $499/mo Enterprise Dashboard widget

SECTORS COVERED (v15.0 taxonomy):
  Financial Services | Healthcare | Critical Infrastructure | Government |
  Technology | Energy | Defense | Retail | Telecom | Manufacturing

FORECAST METHODOLOGY:
  Gradient Boosting Regressor trained on per-item feature vectors.
  Sector-specific impact weights derived from TTP tactic taxonomy.
  Output: sector_risk_score (0-10), forecast_confidence (0-100), trending_threats.

EXIT CODES:
  0 = OK — forecasts generated and written
  1 = FAIL — feed not found or feature matrix empty

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import json
import logging
import math
import sys
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [enterprise_signal] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.enterprise_signal")

# ── Optional heavy deps — graceful fallback ───────────────────────────────────
try:
    import numpy as np
    from sklearn.ensemble import GradientBoostingRegressor
    from sklearn.preprocessing import RobustScaler
    _SKLEARN = True
except ImportError:
    _SKLEARN = False
    log.warning("scikit-learn not available — using weighted heuristic scorer")

REPO = Path(__file__).resolve().parent.parent
FEED_PATH     = REPO / "api" / "feed.json"
RADAR_PATH    = REPO / "data" / "ai" / "anomaly_radar.json"
OUTPUT_PATH   = REPO / "data" / "ai" / "enterprise_forecast.json"


def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    with open(tmp, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False, default=str)
    tmp.rename(path)


# ── Sector taxonomy and TTP-to-sector impact weights ─────────────────────────

SECTORS: list[str] = [
    "Financial Services",
    "Healthcare",
    "Critical Infrastructure",
    "Government & Defense",
    "Technology",
    "Energy & Utilities",
    "Retail & E-Commerce",
    "Telecommunications",
    "Manufacturing",
    "Education & Research",
]

# Map ATT&CK tactic slugs to sector relevance multipliers.
# 1.0 = baseline impact; >1.0 = sector specifically targeted.
_SECTOR_TACTIC_WEIGHTS: dict[str, dict[str, float]] = {
    "Financial Services": {
        "credential-access": 1.8,
        "exfiltration":      1.7,
        "impact":            1.6,
        "initial-access":    1.5,
        "collection":        1.4,
        "lateral-movement":  1.3,
    },
    "Healthcare": {
        "impact":            1.9,   # ransomware critical
        "exfiltration":      1.8,
        "credential-access": 1.6,
        "collection":        1.5,
        "initial-access":    1.4,
    },
    "Critical Infrastructure": {
        "impact":            2.0,
        "command-and-control": 1.8,
        "lateral-movement":  1.7,
        "persistence":       1.6,
        "defense-evasion":   1.5,
    },
    "Government & Defense": {
        "exfiltration":      1.9,
        "collection":        1.8,
        "initial-access":    1.7,
        "credential-access": 1.6,
        "reconnaissance":    1.5,
    },
    "Technology": {
        "initial-access":    1.6,
        "execution":         1.5,
        "privilege-escalation": 1.5,
        "defense-evasion":   1.4,
        "persistence":       1.4,
    },
    "Energy & Utilities": {
        "impact":            1.9,
        "command-and-control": 1.7,
        "lateral-movement":  1.6,
        "initial-access":    1.5,
        "persistence":       1.5,
    },
    "Retail & E-Commerce": {
        "credential-access": 1.7,
        "collection":        1.6,
        "exfiltration":      1.5,
        "initial-access":    1.4,
        "impact":            1.3,
    },
    "Telecommunications": {
        "exfiltration":      1.8,
        "command-and-control": 1.7,
        "lateral-movement":  1.5,
        "credential-access": 1.5,
        "initial-access":    1.4,
    },
    "Manufacturing": {
        "impact":            1.7,
        "lateral-movement":  1.6,
        "persistence":       1.5,
        "initial-access":    1.4,
        "defense-evasion":   1.3,
    },
    "Education & Research": {
        "initial-access":    1.5,
        "exfiltration":      1.5,
        "credential-access": 1.4,
        "collection":        1.4,
        "impact":            1.3,
    },
}

# Threat type → sector multiplier
_THREAT_TYPE_SECTOR_BOOST: dict[str, dict[str, float]] = {
    "ransomware": {
        "Healthcare":            2.0,
        "Critical Infrastructure": 1.9,
        "Government & Defense":  1.7,
        "Manufacturing":         1.6,
        "Education & Research":  1.5,
    },
    "apt": {
        "Government & Defense":  2.0,
        "Technology":            1.8,
        "Energy & Utilities":    1.7,
        "Telecommunications":    1.6,
    },
    "data breach": {
        "Financial Services":    2.0,
        "Healthcare":            1.9,
        "Retail & E-Commerce":   1.8,
        "Technology":            1.6,
    },
    "supply chain": {
        "Technology":            2.0,
        "Critical Infrastructure": 1.8,
        "Government & Defense":  1.7,
        "Manufacturing":         1.6,
    },
}


def _extract_tactics(item: dict) -> list[str]:
    tactics = []
    for field in ("ttps", "mitre_tactics"):
        for ttp in (item.get(field) or []):
            if isinstance(ttp, dict):
                t = str(ttp.get("tactic", "")).lower().strip()
                if t:
                    tactics.append(t)
    return tactics


def _score_item_for_sector(item: dict, sector: str) -> float:
    """Compute sector-specific impact score for a single advisory (0-10)."""
    base_risk  = float(item.get("risk_score") or 0)
    kev_boost  = 2.0 if item.get("kev_present") else 0.0
    epss       = float(item.get("epss_score") or 0) * 10   # 0-1 → 0-10
    cvss       = float(item.get("cvss_score") or 0)

    base = base_risk * 0.5 + epss * 0.2 + cvss * 0.2 + kev_boost * 0.1
    tactic_weights = _SECTOR_TACTIC_WEIGHTS.get(sector, {})
    tactics = _extract_tactics(item)
    tactic_mult = max((tactic_weights.get(t, 1.0) for t in tactics), default=1.0)

    # Threat type boost
    threat_type = str(item.get("threat_type", "") or "").lower()
    type_boost = 1.0
    for key, sector_map in _THREAT_TYPE_SECTOR_BOOST.items():
        if key in threat_type:
            type_boost = max(type_boost, sector_map.get(sector, 1.0))

    score = base * tactic_mult * type_boost
    return min(10.0, max(0.0, score))


def _gradient_boost_sector_score(
    items: list[dict],
    sector: str,
    heuristic_scores: list[float],
) -> float:
    """
    Gradient Boosting sector forecast. Falls back to weighted average if sklearn absent.
    Returns a sector risk score 0-10.
    """
    if not _SKLEARN or len(items) < 5:
        # Weighted heuristic fallback: top-5 items drive the forecast
        top5 = sorted(heuristic_scores, reverse=True)[:5]
        return round(sum(top5) / max(len(top5), 1), 2)

    # Feature matrix: each item → [base_risk, kev, epss, cvss, ttp_count, ioc_count, heuristic]
    X_raw = []
    y_raw = []
    for item, h_score in zip(items, heuristic_scores):
        X_raw.append([
            float(item.get("risk_score") or 0),
            1.0 if item.get("kev_present") else 0.0,
            float(item.get("epss_score") or 0) * 10,
            float(item.get("cvss_score") or 0),
            min(float(len(item.get("ttps") or [])), 20),
            min(float(item.get("ioc_count") or 0), 50),
            h_score,
        ])
        y_raw.append(h_score)

    import numpy as np
    X = np.array(X_raw, dtype=np.float64)
    X = np.nan_to_num(X, nan=0.0, posinf=10.0, neginf=0.0)
    y = np.array(y_raw, dtype=np.float64)

    scaler = RobustScaler()
    X_s = scaler.fit_transform(X)

    gbr = GradientBoostingRegressor(
        n_estimators=100,
        max_depth=3,
        learning_rate=0.1,
        random_state=42,
        subsample=0.8,
    )
    gbr.fit(X_s, y)
    preds = gbr.predict(X_s)
    sector_score = float(np.percentile(preds, 85))   # 85th percentile = "forecast exposure"
    return round(min(10.0, max(0.0, sector_score)), 2)


def _trending_threats(items: list[dict], sector: str, top_n: int = 5) -> list[dict]:
    """Extract top trending threats most relevant to the given sector."""
    scored = []
    for item in items:
        score = _score_item_for_sector(item, sector)
        if score > 0:
            scored.append((score, item))
    scored.sort(key=lambda x: x[0], reverse=True)

    result = []
    for score, item in scored[:top_n]:
        result.append({
            "stix_id":    item.get("stix_id") or item.get("id"),
            "title":      (item.get("title") or "")[:180],
            "threat_type": item.get("threat_type"),
            "severity":   item.get("severity"),
            "risk_score": item.get("risk_score"),
            "kev":        item.get("kev_present", False),
            "sector_impact_score": round(score, 2),
            "report_url": item.get("report_url"),
            "source":     item.get("source"),
        })
    return result


def generate_forecasts(items: list[dict]) -> list[dict]:
    """Generate sector-specific threat forecasts for all sectors."""
    forecasts = []
    total = len(items)
    critical = sum(1 for it in items if str(it.get("severity", "")).upper() == "CRITICAL")
    kev_active = sum(1 for it in items if it.get("kev_present"))

    for sector in SECTORS:
        h_scores = [_score_item_for_sector(it, sector) for it in items]
        avg_score = sum(h_scores) / max(len(h_scores), 1)
        max_score = max(h_scores, default=0.0)

        # Gradient Boost forecast score
        gb_score = _gradient_boost_sector_score(items, sector, h_scores)

        # Confidence: higher when more items are relevant
        relevant = sum(1 for s in h_scores if s >= 3.0)
        confidence = min(95, int(50 + (relevant / max(total, 1)) * 45 + (kev_active * 5)))

        # Trend direction
        if gb_score >= 7.5:
            trend = "ESCALATING"
            alert_level = "CRITICAL"
        elif gb_score >= 5.0:
            trend = "ELEVATED"
            alert_level = "HIGH"
        elif gb_score >= 3.0:
            trend = "MODERATE"
            alert_level = "MEDIUM"
        else:
            trend = "NOMINAL"
            alert_level = "LOW"

        trending = _trending_threats(items, sector, top_n=5)

        forecasts.append({
            "sector":            sector,
            "sector_risk_score": gb_score,
            "avg_item_score":    round(avg_score, 2),
            "max_item_score":    round(max_score, 2),
            "forecast_confidence": confidence,
            "trend":             trend,
            "alert_level":       alert_level,
            "relevant_threats":  relevant,
            "trending_threats":  trending,
            "enterprise_action": _generate_action(sector, alert_level, gb_score),
        })

    return sorted(forecasts, key=lambda x: x["sector_risk_score"], reverse=True)


def _generate_action(sector: str, alert_level: str, score: float) -> str:
    if alert_level == "CRITICAL":
        return (
            f"IMMEDIATE ACTION REQUIRED: {sector} sector risk at {score:.1f}/10. "
            "Deploy STIX bundle to SIEM, activate SOC P1 playbook, escalate to CISO."
        )
    if alert_level == "HIGH":
        return (
            f"ELEVATED RISK: {sector} sector at {score:.1f}/10. "
            "Review SOC P2 queue, validate detection rules, brief security leadership."
        )
    if alert_level == "MEDIUM":
        return (
            f"MODERATE EXPOSURE: {sector} sector at {score:.1f}/10. "
            "Monitor trending threats, update threat watchlist, SOC P3 review."
        )
    return f"NOMINAL: {sector} sector at {score:.1f}/10. Standard threat monitoring applies."


def main() -> int:
    log.info("SENTINEL APEX v143.1.0 — Enterprise Signal Push starting")
    t0 = time.time()

    if not FEED_PATH.exists():
        log.error("api/feed.json not found")
        return 1

    try:
        items: list[dict] = json.loads(FEED_PATH.read_text(encoding="utf-8"))
    except Exception as e:
        log.error("Feed parse error: %s", e)
        return 1

    if not items:
        log.error("Feed is empty — cannot generate sector forecasts")
        return 1

    log.info("Loaded %d advisories for sector forecast", len(items))

    # Load anomaly radar if available
    radar_data: dict = {}
    if RADAR_PATH.exists():
        try:
            radar_data = json.loads(RADAR_PATH.read_text(encoding="utf-8"))
            zd_count = radar_data.get("zero_day_candidate_count", 0)
            log.info("Anomaly radar loaded: %d Zero-Day Candidates", zd_count)
        except Exception:
            pass

    forecasts = generate_forecasts(items)

    # Summary stats
    critical_sectors = [f for f in forecasts if f["alert_level"] == "CRITICAL"]
    high_sectors     = [f for f in forecasts if f["alert_level"] == "HIGH"]

    payload = {
        "generated_at":    _utc_now(),
        "engine":          "SENTINEL-APEX/143.1.0",
        "model":           "GradientBoosting" if _SKLEARN else "WeightedHeuristic",
        "tier":            "ENTERPRISE ($499/mo)",
        "total_advisories": len(items),
        "zero_day_candidates": radar_data.get("zero_day_candidate_count", 0),
        "critical_sectors":  len(critical_sectors),
        "high_alert_sectors": len(high_sectors),
        "sector_forecasts":  forecasts,
        "global_threat_level": forecasts[0]["alert_level"] if forecasts else "NOMINAL",
        "global_risk_score":  round(
            sum(f["sector_risk_score"] for f in forecasts) / max(len(forecasts), 1), 2
        ),
        "elapsed_seconds": round(time.time() - t0, 2),
    }

    _atomic_write(OUTPUT_PATH, payload)
    log.info("Enterprise Forecast written → %s", OUTPUT_PATH)
    log.info(
        "DONE: %d sectors | %d CRITICAL | %d HIGH | Global: %s (%.2f/10) | %.2fs",
        len(forecasts),
        len(critical_sectors),
        len(high_sectors),
        payload["global_threat_level"],
        payload["global_risk_score"],
        time.time() - t0,
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
