#!/usr/bin/env python3
"""
risk_trend_model.py — CyberDudeBivash v22.0 (SENTINEL APEX ULTRA)
THREAT RISK TREND ANALYZER — PRODUCTION UPGRADE

v22.0 ADDITIONS (fully additive):
  - KEV trend tracking: rate of KEV-confirmed threats over time
  - EPSS average tracking: mean EPSS across active threats
  - Supply chain threat frequency
  - Actor attribution trend
  - Top threat sources by feed
  - Severity momentum (critical/high rate acceleration)
  - 14-day intermediate window analysis
  - Sector impact estimation from title keywords

All existing analyze() output fields preserved. 100% backward compatible.
"""
import json
import os
import logging
from typing import Dict, List, Optional, Tuple
from datetime import datetime, timezone, timedelta
from collections import Counter

from agent.config import SUPPLY_CHAIN_SIGNALS

logger = logging.getLogger("CDB-RISK-TREND")

MANIFEST_PATH = "data/stix/feed_manifest.json"


class RiskTrendModel:
    """
    Analyzes intelligence history to detect risk trends, KEV acceleration,
    EPSS drift, and supply chain activity — all from existing manifest data.
    """

    # Sector classification keywords
    SECTOR_KEYWORDS = {
        "Healthcare":       ["hospital", "healthcare", "medical", "patient", "hipaa", "fhir"],
        "Finance":          ["bank", "financial", "fintech", "payment", "swift", "trading"],
        "Government":       ["government", "federal", "military", "defense", "nato", "cia"],
        "Technology":       ["software", "saas", "cloud", "aws", "azure", "github", "npm"],
        "Critical Infra":   ["power grid", "water", "energy", "pipeline", "utility", "scada"],
        "Retail/Commerce":  ["retail", "ecommerce", "shopify", "pos system", "customer data"],
        "Education":        ["university", "school", "education", "student", "campus"],
        "Manufacturing":    ["manufacturing", "industrial", "ics", "ot network", "factory"],
        "Telecom":          ["telecom", "isp", "carrier", "mobile", "5g", "voip"],
    }

    def analyze(self, window_days: int = 30) -> Dict:
        """
        Run full trend analysis on recent intelligence data.
        Returns comprehensive trend report with v22.0 extended fields.
        """
        entries = self._load_manifest_entries()
        if not entries:
            return self._empty_trend()

        now        = datetime.now(timezone.utc)
        cutoff_30d = now - timedelta(days=30)
        cutoff_14d = now - timedelta(days=14)
        cutoff_7d  = now - timedelta(days=7)

        entries_30d = self._filter_by_time(entries, cutoff_30d)
        entries_14d = self._filter_by_time(entries, cutoff_14d)
        entries_7d  = self._filter_by_time(entries, cutoff_7d)

        # ── Core metrics (preserved) ──
        trend_direction  = self._compute_trend_direction(entries_7d, entries_30d)
        attack_velocity  = self._compute_attack_velocity(entries_30d)
        severity_dist    = self._compute_severity_distribution(entries_30d)
        risk_avg_7d      = self._compute_avg_risk(entries_7d)
        risk_avg_14d     = self._compute_avg_risk(entries_14d)
        risk_avg_30d     = self._compute_avg_risk(entries_30d)
        high_risk_rate   = self._compute_high_risk_rate(entries_30d)

        # ── v22.0 extended metrics ──
        kev_trend        = self._compute_kev_trend(entries_7d, entries_30d)
        epss_avg_7d      = self._compute_avg_epss(entries_7d)
        epss_avg_30d     = self._compute_avg_epss(entries_30d)
        supply_chain_rate= self._compute_supply_chain_rate(entries_30d)
        top_actors       = self._compute_top_actors(entries_30d)
        top_sources      = self._compute_top_sources(entries_30d)
        sector_impact    = self._compute_sector_impact(entries_30d)
        severity_momentum= self._compute_severity_momentum(entries_7d, entries_30d)
        cve_rate         = self._compute_cve_rate(entries_30d)

        result = {
            # Preserved v17.0 fields
            "analyzed_at":              now.isoformat(),
            "entries_analyzed_30d":     len(entries_30d),
            "entries_analyzed_7d":      len(entries_7d),
            "trend_direction":          trend_direction,
            "attack_velocity_per_day":  attack_velocity,
            "avg_risk_score_7d":        risk_avg_7d,
            "avg_risk_score_30d":       risk_avg_30d,
            "risk_delta_7d_vs_30d":     round(risk_avg_7d - risk_avg_30d, 2),
            "high_risk_rate_pct":       high_risk_rate,
            "severity_distribution":    severity_dist,
            "trend_summary": self._generate_summary(
                trend_direction, attack_velocity, high_risk_rate
            ),
            # v22.0 NEW fields
            "entries_analyzed_14d":     len(entries_14d),
            "avg_risk_score_14d":       risk_avg_14d,
            "risk_delta_14d_vs_30d":    round(risk_avg_14d - risk_avg_30d, 2),
            "kev_trend":                kev_trend,
            "epss_avg_7d":              epss_avg_7d,
            "epss_avg_30d":             epss_avg_30d,
            "epss_delta":               round((epss_avg_7d or 0) - (epss_avg_30d or 0), 4),
            "supply_chain_rate_pct":    supply_chain_rate,
            "top_threat_actors":        top_actors,
            "top_feed_sources":         top_sources,
            "sector_impact":            sector_impact,
            "severity_momentum":        severity_momentum,
            "cve_rate_per_day":         cve_rate,
            "intelligence_density":     self._compute_intel_density(entries_30d),
        }

        logger.info(
            f"📈 Risk Trend v22.0 | Dir: {trend_direction} | "
            f"Velocity: {attack_velocity}/day | KEV rate: {kev_trend.get('kev_rate_7d', 0):.1%} | "
            f"SC rate: {supply_chain_rate}% | EPSS avg: {epss_avg_7d}"
        )

        return result

    # ── v22.0 NEW ANALYSIS METHODS ─────────────────────────────

    def _compute_kev_trend(
        self, entries_7d: List[Dict], entries_30d: List[Dict]
    ) -> Dict:
        """Compute KEV (CISA Known Exploited Vuln) detection rate trends."""
        kev_7d  = sum(1 for e in entries_7d  if e.get("kev_present"))
        kev_30d = sum(1 for e in entries_30d if e.get("kev_present"))

        rate_7d  = kev_7d  / max(len(entries_7d),  1)
        rate_30d = kev_30d / max(len(entries_30d), 1)

        direction = "STABLE"
        if rate_7d > rate_30d * 1.3:
            direction = "ESCALATING"
        elif rate_7d < rate_30d * 0.7:
            direction = "DECLINING"

        return {
            "kev_count_7d":   kev_7d,
            "kev_count_30d":  kev_30d,
            "kev_rate_7d":    round(rate_7d, 3),
            "kev_rate_30d":   round(rate_30d, 3),
            "trend":          direction,
            "interpretation": (
                "⚠️ KEV rate accelerating — confirmed exploitation increasing"
                if direction == "ESCALATING" else
                "📉 KEV rate declining — fewer confirmed exploitations"
                if direction == "DECLINING" else
                "📊 KEV rate stable"
            ),
        }

    def _compute_avg_epss(self, entries: List[Dict]) -> Optional[float]:
        """Compute mean EPSS score across entries that have it."""
        vals = [float(e["epss_score"]) for e in entries if e.get("epss_score") is not None]
        return round(sum(vals) / len(vals), 4) if vals else None

    def _compute_supply_chain_rate(self, entries: List[Dict]) -> float:
        """Percentage of entries matching supply chain signals."""
        if not entries:
            return 0.0
        sc_count = sum(
            1 for e in entries
            if any(sig in e.get("title", "").lower() for sig in SUPPLY_CHAIN_SIGNALS)
        )
        return round((sc_count / len(entries)) * 100, 1)

    def _compute_top_actors(self, entries: List[Dict]) -> List[Dict]:
        """Top 5 threat actors by frequency."""
        actors = [e.get("actor_tag", "") for e in entries
                  if e.get("actor_tag") and not e["actor_tag"].startswith("UNC-")]
        counts = Counter(actors)
        return [
            {"actor": actor, "count": count}
            for actor, count in counts.most_common(5)
        ]

    def _compute_top_sources(self, entries: List[Dict]) -> List[Dict]:
        """Top 5 feed sources by entry count."""
        sources = [e.get("feed_source", "UNKNOWN") for e in entries]
        counts  = Counter(sources)
        return [
            {"source": src, "count": cnt}
            for src, cnt in counts.most_common(5)
        ]

    def _compute_sector_impact(self, entries: List[Dict]) -> Dict[str, int]:
        """Count entries per sector by keyword matching in titles."""
        sector_counts: Dict[str, int] = {}
        for entry in entries:
            title_lower = entry.get("title", "").lower()
            for sector, keywords in self.SECTOR_KEYWORDS.items():
                if any(kw in title_lower for kw in keywords):
                    sector_counts[sector] = sector_counts.get(sector, 0) + 1
        return dict(sorted(sector_counts.items(), key=lambda x: x[1], reverse=True))

    def _compute_severity_momentum(
        self, entries_7d: List[Dict], entries_30d: List[Dict]
    ) -> Dict:
        """Compare critical+high rates between 7d and 30d windows."""
        def high_critical_rate(entries: List[Dict]) -> float:
            if not entries:
                return 0.0
            hc = sum(1 for e in entries if e.get("severity", "").upper() in ("CRITICAL", "HIGH"))
            return round(hc / len(entries), 3)

        rate_7d  = high_critical_rate(entries_7d)
        rate_30d = high_critical_rate(entries_30d)
        delta    = round(rate_7d - rate_30d, 3)
        label    = ("ACCELERATING" if delta >= 0.10 else
                    "DECLINING"    if delta <= -0.10 else "STABLE")
        return {
            "high_critical_rate_7d":  rate_7d,
            "high_critical_rate_30d": rate_30d,
            "momentum_delta":         delta,
            "label":                  label,
        }

    def _compute_cve_rate(self, entries: List[Dict]) -> float:
        """Average CVE-based entries per day over 30d window."""
        import re
        cve_pat = re.compile(r'CVE-\d{4}-\d+', re.IGNORECASE)
        cve_entries = sum(1 for e in entries if cve_pat.search(e.get("title", "")))
        return round(cve_entries / 30.0, 2)

    def _compute_intel_density(self, entries: List[Dict]) -> Dict:
        """Compute average IOC richness and MITRE coverage per entry."""
        if not entries:
            return {"avg_ioc_total": 0, "avg_mitre_count": 0}
        ioc_totals = [sum(e.get("ioc_counts", {}).values()) for e in entries]
        mitre_counts = [len(e.get("mitre_tactics", [])) for e in entries]
        return {
            "avg_ioc_total":    round(sum(ioc_totals) / len(entries), 1),
            "avg_mitre_count":  round(sum(mitre_counts) / len(entries), 1),
        }

    # ── PRESERVED v17.0 METHODS ────────────────────────────────

    def _load_manifest_entries(self) -> List[Dict]:
        if not os.path.exists(MANIFEST_PATH):
            return []
        try:
            with open(MANIFEST_PATH, "r") as f:
                manifest = json.load(f)
            if isinstance(manifest, list):
                return manifest
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
        if not entries_30d:
            return "INSUFFICIENT_DATA"
        rate_7d   = len(entries_7d) / 7.0 if entries_7d else 0
        entries_23d = [e for e in entries_30d if e not in entries_7d]
        rate_23d  = len(entries_23d) / 23.0 if entries_23d else 0
        if rate_23d == 0:
            return "STABLE"
        ratio = rate_7d / rate_23d
        if ratio >= 1.4:   return "ESCALATING"
        elif ratio >= 0.8: return "STABLE"
        return "DECLINING"

    def _compute_attack_velocity(self, entries: List[Dict]) -> float:
        return round(len(entries) / 30.0, 2) if entries else 0.0

    def _compute_avg_risk(self, entries: List[Dict]) -> float:
        scores = [float(e.get("risk_score", 0)) for e in entries if e.get("risk_score") is not None]
        return round(sum(scores) / len(scores), 2) if scores else 0.0

    def _compute_severity_distribution(self, entries: List[Dict]) -> Dict[str, int]:
        dist: Dict[str, int] = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for entry in entries:
            sev = entry.get("severity", "").upper()
            if sev in dist:
                dist[sev] += 1
            else:
                dist["INFO"] += 1
        return dist

    def _compute_high_risk_rate(self, entries: List[Dict]) -> float:
        if not entries:
            return 0.0
        high_risk = sum(1 for e in entries if float(e.get("risk_score", 0)) >= 7.0)
        return round((high_risk / len(entries)) * 100, 1)

    def _generate_summary(self, direction: str, velocity: float, high_risk_rate: float) -> str:
        if direction == "ESCALATING" and high_risk_rate >= 50:
            return "⚠️ ELEVATED THREAT ENVIRONMENT: Attack velocity increasing with high proportion of critical threats."
        elif direction == "ESCALATING":
            return "📈 THREAT ACTIVITY INCREASING: New threats arriving faster than baseline."
        elif direction == "DECLINING":
            return "📉 THREAT ACTIVITY NORMALIZING: Reduced threat velocity vs. prior period."
        return "📊 STABLE THREAT ENVIRONMENT: Threat activity within expected baseline range."

    def _empty_trend(self) -> Dict:
        return {
            "analyzed_at":    datetime.now(timezone.utc).isoformat(),
            "trend_direction":"INSUFFICIENT_DATA",
            "message":        "Feed manifest not found or empty. Trend data available after first pipeline run.",
        }


# Singleton instance
risk_trend_model = RiskTrendModel()
