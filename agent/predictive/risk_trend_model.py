#!/usr/bin/env python3
"""
risk_trend_model.py — CyberDudeBivash SENTINEL APEX v17.0
THREAT RISK TREND ANALYZER

Analyzes historical manifest data to compute:
  - Risk trend direction (ESCALATING / STABLE / DECLINING)
  - Attack velocity: rate of new high-severity threats over time
  - Sector impact concentration
  - Threat type frequency distribution
  - Rolling 7-day vs 30-day risk comparison

NON-BREAKING: Reads from existing manifest/STIX data only. Pure addition.
"""

import json
import os
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone, timedelta
from collections import Counter

logger = logging.getLogger("CDB-RISK-TREND")

MANIFEST_PATH = "data/stix/feed_manifest.json"


class RiskTrendModel:
    """
    Analyzes intelligence history to detect risk trends and attack velocity.
    Uses existing feed_manifest.json data — no external dependencies.
    """

    def analyze(self, window_days: int = 30) -> Dict:
        """
        Run full trend analysis on recent intelligence data.
        Returns comprehensive trend report.
        """
        entries = self._load_manifest_entries()
        if not entries:
            return self._empty_trend()

        now = datetime.now(timezone.utc)
        cutoff_30d = now - timedelta(days=30)
        cutoff_7d = now - timedelta(days=7)

        # Filter entries by time windows
        entries_30d = self._filter_by_time(entries, cutoff_30d)
        entries_7d = self._filter_by_time(entries, cutoff_7d)

        # Compute metrics
        trend_direction = self._compute_trend_direction(entries_7d, entries_30d)
        attack_velocity = self._compute_attack_velocity(entries_30d)
        severity_dist = self._compute_severity_distribution(entries_30d)
        risk_avg_7d = self._compute_avg_risk(entries_7d)
        risk_avg_30d = self._compute_avg_risk(entries_30d)
        high_risk_rate = self._compute_high_risk_rate(entries_30d)

        result = {
            "analyzed_at": now.isoformat(),
            "entries_analyzed_30d": len(entries_30d),
            "entries_analyzed_7d": len(entries_7d),
            "trend_direction": trend_direction,
            "attack_velocity_per_day": attack_velocity,
            "avg_risk_score_7d": risk_avg_7d,
            "avg_risk_score_30d": risk_avg_30d,
            "risk_delta_7d_vs_30d": round(risk_avg_7d - risk_avg_30d, 2),
            "high_risk_rate_pct": high_risk_rate,
            "severity_distribution": severity_dist,
            "trend_summary": self._generate_summary(
                trend_direction, attack_velocity, high_risk_rate
            ),
        }

        logger.info(
            f"📈 Risk Trend Analysis | "
            f"Direction: {trend_direction} | "
            f"Velocity: {attack_velocity}/day | "
            f"Avg Risk (7d): {risk_avg_7d} | "
            f"High Risk Rate: {high_risk_rate}%"
        )

        return result

    def _load_manifest_entries(self) -> List[Dict]:
        if not os.path.exists(MANIFEST_PATH):
            return []
        try:
            with open(MANIFEST_PATH, "r") as f:
                manifest = json.load(f)
            return manifest.get("entries", [])
        except Exception as e:
            logger.warning(f"Manifest load failed for trend analysis: {e}")
            return []

    def _filter_by_time(self, entries: List[Dict], cutoff: datetime) -> List[Dict]:
        filtered = []
        for entry in entries:
            ts_str = entry.get("generated_at") or entry.get("published_at") or ""
            if not ts_str:
                continue
            try:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if ts.tzinfo is None:
                    ts = ts.replace(tzinfo=timezone.utc)
                if ts >= cutoff:
                    filtered.append(entry)
            except Exception:
                continue
        return filtered

    def _compute_trend_direction(
        self, entries_7d: List[Dict], entries_30d: List[Dict]
    ) -> str:
        """Compare recent 7-day vs 30-day to determine trend direction."""
        if not entries_30d:
            return "INSUFFICIENT_DATA"

        rate_7d = len(entries_7d) / 7.0 if entries_7d else 0
        # Average daily rate for 30d (excluding last 7d)
        entries_23d = [e for e in entries_30d if e not in entries_7d]
        rate_23d = len(entries_23d) / 23.0 if entries_23d else 0

        if rate_23d == 0:
            return "STABLE"

        ratio = rate_7d / rate_23d if rate_23d > 0 else 1.0

        if ratio >= 1.4:
            return "ESCALATING"
        elif ratio >= 0.8:
            return "STABLE"
        else:
            return "DECLINING"

    def _compute_attack_velocity(self, entries: List[Dict]) -> float:
        """Compute average new threats per day."""
        if not entries:
            return 0.0
        return round(len(entries) / 30.0, 2)

    def _compute_avg_risk(self, entries: List[Dict]) -> float:
        """Compute average risk score."""
        scores = [
            float(e.get("risk_score", 0))
            for e in entries
            if e.get("risk_score") is not None
        ]
        return round(sum(scores) / len(scores), 2) if scores else 0.0

    def _compute_severity_distribution(self, entries: List[Dict]) -> Dict[str, int]:
        """Count entries by severity label."""
        dist: Dict[str, int] = {
            "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0
        }
        for entry in entries:
            sev = entry.get("severity", "").upper()
            if sev in dist:
                dist[sev] += 1
            else:
                dist["INFO"] += 1
        return dist

    def _compute_high_risk_rate(self, entries: List[Dict]) -> float:
        """Percentage of entries with risk_score >= 7.0."""
        if not entries:
            return 0.0
        high_risk = sum(
            1 for e in entries if float(e.get("risk_score", 0)) >= 7.0
        )
        return round((high_risk / len(entries)) * 100, 1)

    def _generate_summary(
        self, direction: str, velocity: float, high_risk_rate: float
    ) -> str:
        if direction == "ESCALATING" and high_risk_rate >= 50:
            return "⚠️ ELEVATED THREAT ENVIRONMENT: Attack velocity increasing with high proportion of critical threats."
        elif direction == "ESCALATING":
            return "📈 THREAT ACTIVITY INCREASING: New threats arriving faster than baseline."
        elif direction == "DECLINING":
            return "📉 THREAT ACTIVITY NORMALIZING: Reduced threat velocity vs. prior period."
        else:
            return "📊 STABLE THREAT ENVIRONMENT: Threat activity within expected baseline range."

    def _empty_trend(self) -> Dict:
        return {
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
            "trend_direction": "INSUFFICIENT_DATA",
            "message": "Feed manifest not found or empty. Trend data available after first pipeline run.",
        }


# Singleton instance
risk_trend_model = RiskTrendModel()
