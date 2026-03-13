#!/usr/bin/env python3
"""
intel_quality_scorer.py — CyberDudeBivash v46.0 (SENTINEL APEX ULTRA INTEL)
Intelligence Quality Score (IQS) engine.
Produces a 0–100 quality/completeness score per advisory across 8 dimensions:
  1. CVE Coverage       (has CVE extracted)
  2. CVSS Enrichment    (has CVSS score from NVD)
  3. EPSS Score         (has EPSS exploitation probability)
  4. IOC Richness       (non-zero IOC count)
  5. MITRE Depth        (≥2 MITRE ATT&CK techniques)
  6. Actor Attribution  (non-generic actor tag)
  7. Confidence Level   (confidence_score ≥ 40)
  8. Data Completeness  (extended_metrics populated, sector_tags, etc.)

IQS drives:
  - Dashboard quality ring badge on each card
  - Prioritization in watchlist
  - Premium report gating logic
  - Analytics dashboard signal quality gauge

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
import logging
from typing import Dict, List, Tuple

logger = logging.getLogger("CDB-INTEL-QUALITY-V46")

# ── SCORING DIMENSIONS (dimension, max_points, weight) ────────────────────────
QUALITY_DIMENSIONS: List[Tuple[str, int, float]] = [
    ("cve_coverage",       15, 1.0),   # Has CVE extracted
    ("cvss_enrichment",    15, 1.0),   # Has CVSS score
    ("epss_enrichment",    15, 1.0),   # Has EPSS score
    ("ioc_richness",       15, 1.0),   # Non-zero IOC count
    ("mitre_depth",        10, 1.0),   # ≥2 MITRE techniques
    ("actor_attribution",  10, 1.0),   # Non-generic actor
    ("confidence_level",   10, 1.0),   # Confidence ≥40
    ("enrichment_depth",   10, 1.0),   # sector_tags + exploit_status populated
]

# ── QUALITY TIER LABELS ───────────────────────────────────────────────────────
def _get_tier(score: int) -> Dict:
    if score >= 80:
        return {"tier": "GOLD", "label": "Gold", "color": "#fbbf24", "icon": "🥇"}
    elif score >= 60:
        return {"tier": "SILVER", "label": "Silver", "color": "#94a3b8", "icon": "🥈"}
    elif score >= 40:
        return {"tier": "BRONZE", "label": "Bronze", "color": "#d97706", "icon": "🥉"}
    elif score >= 20:
        return {"tier": "LOW", "label": "Low", "color": "#ea580c", "icon": "⚠️"}
    else:
        return {"tier": "MINIMAL", "label": "Minimal", "color": "#dc2626", "icon": "❌"}


class IntelQualityScorerV46:
    """
    Multi-dimensional intelligence quality scoring engine.
    Computes a 0–100 IQS score with per-dimension breakdown.
    """

    def score_item(self, item: Dict) -> Dict:
        """
        Score item across all quality dimensions.
        Returns dict with total_score, tier, dimension_scores, missing_signals.
        """
        scores = {}
        missing = []

        # ── 1. CVE Coverage ───────────────────────────────────────────────────
        import re
        cves = re.findall(r'CVE-\d{4}-\d{4,7}', item.get("title", ""), re.I)
        cve_from_ioc = item.get("ioc_counts", {}).get("cve", 0)
        if cves or cve_from_ioc > 0:
            scores["cve_coverage"] = 15
        else:
            scores["cve_coverage"] = 3  # partial credit for general threat intel
            missing.append("CVE identifier")

        # ── 2. CVSS Enrichment ────────────────────────────────────────────────
        cvss = item.get("cvss_score")
        if cvss is not None and cvss > 0:
            scores["cvss_enrichment"] = 15
        else:
            scores["cvss_enrichment"] = 0
            missing.append("CVSS score")

        # ── 3. EPSS Enrichment ────────────────────────────────────────────────
        epss = item.get("epss_score")
        if epss is not None and epss > 0:
            scores["epss_enrichment"] = 15
        else:
            scores["epss_enrichment"] = 0
            missing.append("EPSS score")

        # ── 4. IOC Richness ───────────────────────────────────────────────────
        ioc_counts = item.get("ioc_counts", {})
        total_iocs = sum(ioc_counts.values())
        if total_iocs >= 5:
            scores["ioc_richness"] = 15
        elif total_iocs >= 2:
            scores["ioc_richness"] = 10
        elif total_iocs == 1:
            scores["ioc_richness"] = 7
        else:
            scores["ioc_richness"] = 0
            missing.append("IOC indicators")

        # ── 5. MITRE Depth ────────────────────────────────────────────────────
        tactics = item.get("mitre_tactics", [])
        if len(tactics) >= 4:
            scores["mitre_depth"] = 10
        elif len(tactics) >= 2:
            scores["mitre_depth"] = 7
        elif len(tactics) == 1:
            scores["mitre_depth"] = 4
        else:
            scores["mitre_depth"] = 0
            missing.append("MITRE ATT&CK techniques")

        # ── 6. Actor Attribution ──────────────────────────────────────────────
        actor = item.get("actor_tag", "UNC-CDB-99")
        actor_profile = item.get("actor_profile", {})
        attr_conf = actor_profile.get("attribution_confidence", 0.0)

        if actor.startswith("UNC-CDB"):
            scores["actor_attribution"] = 0
            missing.append("Threat actor attribution")
        elif attr_conf >= 0.7:
            scores["actor_attribution"] = 10
        elif attr_conf >= 0.4:
            scores["actor_attribution"] = 7
        else:
            scores["actor_attribution"] = 4

        # ── 7. Confidence Level ───────────────────────────────────────────────
        conf = item.get("confidence_score", 0)
        if conf >= 70:
            scores["confidence_level"] = 10
        elif conf >= 40:
            scores["confidence_level"] = 7
        elif conf >= 20:
            scores["confidence_level"] = 4
        else:
            scores["confidence_level"] = 0
            missing.append("High confidence signals")

        # ── 8. Enrichment Depth ───────────────────────────────────────────────
        depth = 0
        if item.get("sector_tags"):
            depth += 3
        if item.get("exploit_status"):
            depth += 3
        if item.get("cwe_classification"):
            depth += 2
        if item.get("kev_present"):
            depth += 2
        scores["enrichment_depth"] = min(depth, 10)
        if depth < 5:
            missing.append("Sector/exploit enrichment")

        # ── Total Score ───────────────────────────────────────────────────────
        total = sum(scores.values())
        total = min(100, max(0, total))
        tier = _get_tier(total)

        return {
            "iqs_score": total,
            "iqs_tier": tier["tier"],
            "iqs_label": tier["label"],
            "iqs_color": tier["color"],
            "iqs_icon": tier["icon"],
            "dimension_scores": scores,
            "missing_signals": missing,
            "completeness_pct": round(total, 0),
        }

    def enrich_item(self, item: Dict) -> Dict:
        """Enrich item with intel_quality field."""
        item["intel_quality"] = self.score_item(item)
        return item

    def batch_enrich(self, items: List[Dict]) -> List[Dict]:
        """Batch enrich. Call AFTER all other enrichers."""
        enriched = []
        for item in items:
            try:
                enriched.append(self.enrich_item(item))
            except Exception as e:
                logger.warning(f"IQS scoring failed: {e}")
                item.setdefault("intel_quality", {
                    "iqs_score": 0, "iqs_tier": "MINIMAL",
                    "iqs_label": "Minimal", "iqs_color": "#dc2626",
                    "iqs_icon": "❌", "dimension_scores": {},
                    "missing_signals": [], "completeness_pct": 0,
                })
                enriched.append(item)
        return enriched

    def compute_platform_stats(self, items: List[Dict]) -> Dict:
        """Compute platform-level quality statistics."""
        if not items:
            return {}
        scored = [i.get("intel_quality", {}).get("iqs_score", 0) for i in items]
        tiers = [i.get("intel_quality", {}).get("iqs_tier", "MINIMAL") for i in items]
        tier_counts = {}
        for t in tiers:
            tier_counts[t] = tier_counts.get(t, 0) + 1
        return {
            "avg_iqs": round(sum(scored) / len(scored), 1),
            "min_iqs": min(scored),
            "max_iqs": max(scored),
            "tier_distribution": tier_counts,
            "gold_pct": round(tier_counts.get("GOLD", 0) / len(items) * 100, 1),
        }


intel_quality_scorer_v46 = IntelQualityScorerV46()
