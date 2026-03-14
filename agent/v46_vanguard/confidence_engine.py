#!/usr/bin/env python3
"""
confidence_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v46.0 VANGUARD
Multi-Dimensional Confidence Scoring Engine

FIXES: Previous additive confidence model in sentinel_blogger.py stacked
       bonuses (MITRE+actor+records+keywords) pushing scores past 100%
       before min() clamp. This inflated confidence for mid-quality intel
       to "HIGH" when it should be "MODERATE".

NEW MODEL:
  - Weighted-average across 6 confidence dimensions
  - Each dimension scored independently (0-100)
  - Final score = weighted combination, naturally bounded
  - Dimensions: IOC_RICHNESS, SOURCE_DEPTH, MITRE_COVERAGE,
                ACTOR_ATTRIBUTION, IMPACT_EVIDENCE, CVE_VERIFICATION

ARCHITECTURE:
  - Pure function, no state
  - Returns ConfidenceResult with score + per-dimension breakdown
  - Drop-in replacement: score is 0-100 float, same as before
  - Zero regression: existing pipeline continues to work if this fails

Usage:
    from agent.v46_vanguard.confidence_engine import confidence_engine
    result = confidence_engine.score(iocs=..., mitre_data=..., ...)
    # result.score → 67.3
    # result.label → "MODERATE"
    # result.dimensions → {"ioc_richness": 85.0, ...}
"""

import logging
from dataclasses import dataclass, field
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-CONFIDENCE")


@dataclass
class ConfidenceResult:
    """Structured confidence assessment."""
    score: float = 0.0
    label: str = "UNVERIFIED"
    dimensions: Dict[str, float] = field(default_factory=dict)
    rationale: str = ""


# ── Dimension Weights (must sum to 1.0) ──
WEIGHTS = {
    "ioc_richness":       0.30,  # Hash diversity, IP/domain presence
    "source_depth":       0.20,  # Full article fetched, word count
    "mitre_coverage":     0.18,  # Number and depth of MITRE techniques
    "actor_attribution":  0.12,  # Named APT vs UNC vs unattributed
    "impact_evidence":    0.10,  # Quantified records/financial impact
    "cve_verification":   0.10,  # NVD-verified, EPSS available, KEV
}


class ConfidenceEngine:
    """
    Multi-dimensional confidence scoring for threat intelligence reports.
    """

    def score(
        self,
        iocs: Dict[str, List[str]],
        mitre_data: Optional[List[Dict]] = None,
        actor_data: Optional[Dict] = None,
        impact_metrics: Optional[Dict] = None,
        fetched_article: Optional[Dict] = None,
        source_content: str = "",
        epss_score: Optional[float] = None,
        cvss_score: Optional[float] = None,
        kev_present: bool = False,
    ) -> ConfidenceResult:
        """
        Compute weighted multi-dimensional confidence score.
        Returns ConfidenceResult with score (0-100), label, and breakdown.
        """
        dims = {}

        # ── D1: IOC Richness (0-100) ──
        dims["ioc_richness"] = self._score_ioc_richness(iocs)

        # ── D2: Source Depth (0-100) ──
        dims["source_depth"] = self._score_source_depth(
            fetched_article, source_content
        )

        # ── D3: MITRE Coverage (0-100) ──
        dims["mitre_coverage"] = self._score_mitre(mitre_data or [])

        # ── D4: Actor Attribution (0-100) ──
        dims["actor_attribution"] = self._score_actor(actor_data or {})

        # ── D5: Impact Evidence (0-100) ──
        dims["impact_evidence"] = self._score_impact(impact_metrics or {})

        # ── D6: CVE Verification (0-100) ──
        dims["cve_verification"] = self._score_cve_verification(
            iocs.get("cve", []), epss_score, cvss_score, kev_present
        )

        # ── Weighted combination ──
        total = sum(dims[k] * WEIGHTS[k] for k in WEIGHTS)
        total = round(min(max(total, 0.0), 100.0), 1)

        label = self._label(total)
        rationale = self._build_rationale(dims, total)

        result = ConfidenceResult(
            score=total,
            label=label,
            dimensions=dims,
            rationale=rationale,
        )

        logger.info(
            f"Confidence v46: {total}% ({label}) | "
            f"IOC:{dims['ioc_richness']:.0f} SRC:{dims['source_depth']:.0f} "
            f"MITRE:{dims['mitre_coverage']:.0f} ACTOR:{dims['actor_attribution']:.0f} "
            f"IMPACT:{dims['impact_evidence']:.0f} CVE:{dims['cve_verification']:.0f}"
        )

        return result

    # ══════════════════════════════════════════════════════════════════════════
    # DIMENSION SCORERS
    # ══════════════════════════════════════════════════════════════════════════

    def _score_ioc_richness(self, iocs: Dict[str, List[str]]) -> float:
        """Score based on IOC type diversity and volume."""
        score = 0.0

        # Type presence (each category is worth points)
        type_scores = {
            "sha256": 20.0, "sha1": 12.0, "md5": 10.0,
            "ipv4": 15.0, "domain": 12.0, "url": 10.0,
            "email": 5.0, "cve": 8.0, "registry": 18.0,
            "artifacts": 10.0,
        }
        for ioc_type, weight in type_scores.items():
            if iocs.get(ioc_type):
                score += weight

        # Volume bonus (diminishing returns)
        total = sum(len(v) for v in iocs.values())
        if total >= 20:
            score += 15.0
        elif total >= 10:
            score += 10.0
        elif total >= 5:
            score += 5.0

        return min(score, 100.0)

    def _score_source_depth(
        self,
        fetched_article: Optional[Dict],
        source_content: str,
    ) -> float:
        """Score based on source article richness."""
        score = 20.0  # Baseline (RSS exists)

        if fetched_article and fetched_article.get("fetch_status") == "success":
            score += 30.0  # Full article fetched
            wc = fetched_article.get("word_count", 0)
            if wc >= 1000:
                score += 30.0
            elif wc >= 500:
                score += 20.0
            elif wc >= 200:
                score += 10.0

            para_count = len(fetched_article.get("paragraphs", []))
            if para_count >= 10:
                score += 20.0
            elif para_count >= 5:
                score += 10.0
        else:
            # Fallback: score based on raw content
            wc = len(source_content.split()) if source_content else 0
            if wc >= 500:
                score += 25.0
            elif wc >= 200:
                score += 15.0

        return min(score, 100.0)

    def _score_mitre(self, mitre_data: List[Dict]) -> float:
        """Score based on MITRE ATT&CK coverage depth."""
        count = len(mitre_data)
        if count >= 8:
            return 100.0
        elif count >= 5:
            return 80.0
        elif count >= 3:
            return 60.0
        elif count >= 1:
            return 35.0
        return 0.0

    def _score_actor(self, actor_data: Dict) -> float:
        """Score based on actor attribution quality."""
        tracking_id = actor_data.get("tracking_id", "")
        profile = actor_data.get("profile", {})

        # Named APT with high confidence
        if tracking_id and not tracking_id.startswith("UNC-"):
            conf = str(profile.get("confidence_score", "")).lower()
            if "high" in conf:
                return 95.0
            elif "medium" in conf:
                return 70.0
            return 55.0

        # UNC cluster (under investigation)
        if tracking_id.startswith("UNC-CDB-") and tracking_id != "UNC-CDB-99":
            return 30.0

        # Unattributed
        return 10.0

    def _score_impact(self, impact_metrics: Dict) -> float:
        """Score based on quantified impact evidence."""
        score = 0.0

        records = impact_metrics.get("records_affected", 0)
        if records >= 1_000_000:
            score += 50.0
        elif records >= 100_000:
            score += 40.0
        elif records >= 10_000:
            score += 25.0
        elif records > 0:
            score += 15.0

        financial = impact_metrics.get("financial_impact", 0)
        if financial >= 1_000_000:
            score += 30.0
        elif financial > 0:
            score += 15.0

        kw_count = len(impact_metrics.get("severity_keywords", []))
        if kw_count >= 5:
            score += 20.0
        elif kw_count >= 3:
            score += 10.0

        return min(score, 100.0)

    def _score_cve_verification(
        self,
        cve_ids: List[str],
        epss_score: Optional[float],
        cvss_score: Optional[float],
        kev_present: bool,
    ) -> float:
        """Score based on CVE verification signals."""
        if not cve_ids:
            return 50.0  # Neutral for non-CVE reports

        score = 20.0  # CVE ID present
        if cvss_score is not None:
            score += 25.0  # NVD verified
        if epss_score is not None:
            score += 20.0  # EPSS data available
            if epss_score >= 0.5:
                score += 10.0
        if kev_present:
            score += 25.0  # CISA confirmed

        return min(score, 100.0)

    # ══════════════════════════════════════════════════════════════════════════
    # LABELS AND RATIONALE
    # ══════════════════════════════════════════════════════════════════════════

    def _label(self, score: float) -> str:
        if score >= 80.0:
            return "HIGH"
        elif score >= 55.0:
            return "MODERATE"
        elif score >= 30.0:
            return "LOW"
        return "UNVERIFIED"

    def _build_rationale(self, dims: Dict[str, float], total: float) -> str:
        """Build human-readable rationale string."""
        strongest = max(dims, key=dims.get)
        weakest = min(dims, key=dims.get)
        return (
            f"Score {total}% driven primarily by {strongest.replace('_',' ')} "
            f"({dims[strongest]:.0f}%). "
            f"Weakest signal: {weakest.replace('_',' ')} ({dims[weakest]:.0f}%)."
        )


# ── Singleton ──
confidence_engine = ConfidenceEngine()
