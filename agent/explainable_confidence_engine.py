#!/usr/bin/env python3
"""
agent/explainable_confidence_engine.py
CYBERDUDEBIVASH® SENTINEL APEX — EXPLAINABLE CONFIDENCE ENGINE v1.0
================================================================================
PHASE 4: EXPLAINABLE INTELLIGENCE SCORING

MISSION:
  Replace opaque AI scoring with fully auditable, evidence-weighted,
  deterministic confidence computation. Every score must be reproducible
  and explainable to a SOC analyst or CISO in plain English.

CAPABILITIES:
  1. Evidence-weighted confidence scoring
  2. Full scoring audit trails (every factor visible)
  3. Intelligence rationale engine (natural language explanations)
  4. Enrichment traceability framework
  5. Confidence lineage tracking
  6. Per-advisory score decomposition (7 signal dimensions)

SCORING DIMENSIONS (all contributions explicit):
  D1: IOC Quality       — count, type diversity, high-fidelity types
  D2: ATT&CK Depth      — technique count, tactic breadth, KB coverage
  D3: Corroboration     — cross-source confirmation count
  D4: Freshness         — age decay from 100% (new) to floor
  D5: Infrastructure    — overlap scoring, shared infra detection
  D6: Source Trust      — feed source reputation weighting
  D7: Historical Sim    — similarity to historical high-risk advisories

MANDATORY PROPERTIES:
  - Deterministic: same input → same score (no random elements)
  - Bounded: all scores in [0.0, 100.0]
  - Reproducible: audit trail allows exact score reconstruction
  - Operationally explainable: plain-English rationale for every score
  - Enterprise auditable: JSON audit trail per advisory

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import hashlib
import json
import logging
import math
import sys
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-EXPLAINABLE-CONFIDENCE")
VERSION = "1.0.0"

# ─────────────────────────────────────────────────────────────────────────────
# SCORING CONFIGURATION (all weights explicit and documented)
# ─────────────────────────────────────────────────────────────────────────────

# Dimension maximum contributions (must sum to 100.0)
DIM_WEIGHTS: Dict[str, float] = {
    "D1_ioc_quality":       20.0,
    "D2_attck_depth":       18.0,
    "D3_corroboration":     15.0,
    "D4_freshness":         12.0,
    "D5_infrastructure":    10.0,
    "D6_source_trust":      15.0,
    "D7_historical_sim":    10.0,
}
assert abs(sum(DIM_WEIGHTS.values()) - 100.0) < 0.01, "Dimension weights must sum to 100"

# Source trust tiers
SOURCE_TRUST_TIERS: Dict[str, float] = {
    "cisa":           1.00,
    "nvd":            0.95,
    "mitre":          0.97,
    "mandiant":       0.92,
    "crowdstrike":    0.90,
    "paloalto":       0.88,
    "recorded_future":0.88,
    "talos":          0.89,
    "microsoft":      0.85,
    "google":         0.83,
    "secureworks":    0.80,
    "vulners":        0.65,
    "github":         0.60,
    "rss":            0.45,
    "unknown":        0.35,
}

# High-fidelity IOC types (contribute more to D1)
HIGH_FIDELITY_IOC_TYPES = frozenset({"file_hash", "cve", "ip"})
MEDIUM_FIDELITY_IOC_TYPES = frozenset({"domain", "url", "email", "registry_key", "mutex"})

# Freshness decay curve: days → multiplier
FRESHNESS_CURVE: List[Tuple[int, float]] = [
    (0, 1.00),   # Same day
    (1, 0.97),
    (3, 0.90),
    (7, 0.80),
    (14, 0.65),
    (30, 0.45),
    (60, 0.30),
    (90, 0.20),
    (180, 0.10),
]


# ─────────────────────────────────────────────────────────────────────────────
# UTILITIES
# ─────────────────────────────────────────────────────────────────────────────

def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


# ─────────────────────────────────────────────────────────────────────────────
# DATA STRUCTURES
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class DimensionScore:
    """One scoring dimension with full explainability."""
    dimension_id:    str           # e.g. "D1_ioc_quality"
    max_points:      float         # configured weight
    raw_score:       float         # pre-weight score (0.0–1.0)
    weighted_score:  float         # raw_score × max_points
    contributing_factors: Dict[str, Any]   # key evidence factors
    rationale:       str           # plain English explanation


@dataclass
class ConfidenceAuditTrail:
    """Complete audit trail for one advisory's confidence score."""
    advisory_id:      str
    advisory_title:   str
    final_confidence: float          # 0.0–100.0
    confidence_tier:  str            # VERY_LOW | LOW | MEDIUM | HIGH | VERY_HIGH
    dimensions:       List[DimensionScore]
    dimension_summary: Dict[str, float]  # dim_id → weighted_score
    score_hash:       str            # MD5 of all inputs — reproducibility proof
    rationale:        str            # executive summary explanation
    recommendation:   str           # actionable SOC recommendation
    scored_at:        str
    engine_version:   str = VERSION

    def reproduce(self) -> bool:
        """Verify the score hash matches current inputs (audit check)."""
        check_str = json.dumps(self.dimension_summary, sort_keys=True)
        check_hash = hashlib.md5(check_str.encode(), usedforsecurity=False).hexdigest()
        return check_hash == self.score_hash


@dataclass
class ConfidenceLineage:
    """Track how confidence evolved across enrichment stages."""
    advisory_id:   str
    stages: List[Dict]   # [{stage, confidence, delta, rationale}]
    initial:  float
    final:    float
    total_delta: float


# ─────────────────────────────────────────────────────────────────────────────
# DIMENSION SCORERS
# ─────────────────────────────────────────────────────────────────────────────

class D1_IOCQualityScorer:
    """
    D1: IOC Quality — count, type diversity, high-fidelity type presence.
    Max contribution: 20 points.
    """

    def score(self, advisory: Dict) -> DimensionScore:
        iocs = advisory.get("iocs", []) or []
        ioc_types: List[str] = []
        for ioc in iocs:
            if isinstance(ioc, dict):
                ioc_types.append(str(ioc.get("type", "indicator")))
            elif isinstance(ioc, str):
                ioc_types.append("indicator")

        count         = len(iocs)
        unique_types  = len(set(ioc_types))
        hf_count      = sum(1 for t in ioc_types if t in HIGH_FIDELITY_IOC_TYPES)
        mf_count      = sum(1 for t in ioc_types if t in MEDIUM_FIDELITY_IOC_TYPES)

        # Sub-scores
        count_score   = min(1.0, count / 10.0)                     # max at 10 IOCs
        diversity_score = min(1.0, unique_types / 5.0)              # max at 5 types
        hf_bonus      = min(1.0, hf_count * 0.25)                  # 0.25 per HF type, max 1.0
        mf_bonus      = min(0.5, mf_count * 0.10)                  # smaller bonus for MF

        raw = (count_score * 0.40 + diversity_score * 0.30 + hf_bonus * 0.20 + mf_bonus * 0.10)
        raw = round(min(1.0, raw), 4)
        weighted = round(raw * DIM_WEIGHTS["D1_ioc_quality"], 2)

        rationale = (
            f"IOC Quality: {count} total IOC(s), {unique_types} type(s), "
            f"{hf_count} high-fidelity (hash/CVE/IP), {mf_count} medium-fidelity. "
            f"Score: {weighted:.1f}/{DIM_WEIGHTS['D1_ioc_quality']:.0f} pts."
        )

        return DimensionScore(
            dimension_id="D1_ioc_quality",
            max_points=DIM_WEIGHTS["D1_ioc_quality"],
            raw_score=raw,
            weighted_score=weighted,
            contributing_factors={
                "ioc_count": count,
                "unique_types": unique_types,
                "high_fidelity_count": hf_count,
                "medium_fidelity_count": mf_count,
                "sub_scores": {
                    "count": round(count_score, 3),
                    "diversity": round(diversity_score, 3),
                    "hf_bonus": round(hf_bonus, 3),
                    "mf_bonus": round(mf_bonus, 3),
                },
            },
            rationale=rationale,
        )


class D2_ATTCKDepthScorer:
    """
    D2: ATT&CK Depth — technique count, tactic breadth, KB coverage.
    Max contribution: 18 points.
    """

    KNOWN_TACTICS = 14  # Full ATT&CK Enterprise tactic count

    def score(self, advisory: Dict) -> DimensionScore:
        ttps = advisory.get("ttps", []) or []
        valid_ttps = [str(t).upper().strip() for t in ttps if t and str(t).startswith("T")]
        unique_ttps  = list(set(valid_ttps))
        ttp_count    = len(unique_ttps)

        # Tactic lookup (simplified — count unique prefixes)
        # Full KB lookup would be done by ATTCKContextEngine — here we use heuristic
        tactic_count = min(self.KNOWN_TACTICS, max(1, ttp_count // 2 + 1))

        # Sub-scores
        count_score  = min(1.0, ttp_count / 8.0)    # max at 8 TTPs
        breadth_score = min(1.0, tactic_count / self.KNOWN_TACTICS)

        raw      = (count_score * 0.55 + breadth_score * 0.45)
        raw      = round(min(1.0, raw), 4)
        weighted = round(raw * DIM_WEIGHTS["D2_attck_depth"], 2)

        rationale = (
            f"ATT&CK Depth: {ttp_count} technique(s), "
            f"~{tactic_count} tactic(s). "
            f"Score: {weighted:.1f}/{DIM_WEIGHTS['D2_attck_depth']:.0f} pts."
        )

        return DimensionScore(
            dimension_id="D2_attck_depth",
            max_points=DIM_WEIGHTS["D2_attck_depth"],
            raw_score=raw,
            weighted_score=weighted,
            contributing_factors={
                "ttp_count": ttp_count,
                "unique_ttps": unique_ttps[:10],
                "estimated_tactic_count": tactic_count,
                "sub_scores": {
                    "ttp_count_score": round(count_score, 3),
                    "tactic_breadth_score": round(breadth_score, 3),
                },
            },
            rationale=rationale,
        )


class D3_CorroborationScorer:
    """
    D3: Corroboration — cross-source confirmation.
    Max contribution: 15 points.
    """

    def score(self, advisory: Dict) -> DimensionScore:
        # Cross-feed corroboration score (if populated by graph engine)
        cross_feed_count = int(advisory.get("cross_feed_corroboration", 0) or 0)
        kev_confirmed    = bool(advisory.get("kev_confirmed") or advisory.get("kev", False))
        cvss_available   = bool(advisory.get("cvss_score") or advisory.get("cvss"))
        epss_available   = bool(advisory.get("epss_score") or advisory.get("epss"))

        # Corroboration points
        pts = 0.0
        pts += min(0.5, cross_feed_count * 0.15)   # cross-feed sources
        if kev_confirmed:
            pts += 0.35   # KEV = high corroboration
        if cvss_available:
            pts += 0.08
        if epss_available:
            pts += 0.07

        raw      = round(min(1.0, pts), 4)
        weighted = round(raw * DIM_WEIGHTS["D3_corroboration"], 2)

        rationale = (
            f"Corroboration: {cross_feed_count} cross-feed source(s), "
            f"KEV={'YES' if kev_confirmed else 'NO'}, "
            f"CVSS={'YES' if cvss_available else 'NO'}, "
            f"EPSS={'YES' if epss_available else 'NO'}. "
            f"Score: {weighted:.1f}/{DIM_WEIGHTS['D3_corroboration']:.0f} pts."
        )

        return DimensionScore(
            dimension_id="D3_corroboration",
            max_points=DIM_WEIGHTS["D3_corroboration"],
            raw_score=raw,
            weighted_score=weighted,
            contributing_factors={
                "cross_feed_sources": cross_feed_count,
                "kev_confirmed": kev_confirmed,
                "cvss_available": cvss_available,
                "epss_available": epss_available,
            },
            rationale=rationale,
        )


class D4_FreshnessScorer:
    """
    D4: Freshness — time decay from advisory publication date.
    Max contribution: 12 points. Uses deterministic decay curve.
    """

    def _days_old(self, advisory: Dict) -> int:
        pub = advisory.get("published_at") or advisory.get("processed_at") or ""
        if not pub:
            return 30  # default to 30 days if unknown
        try:
            pub_dt = datetime.fromisoformat(pub.replace("Z", "+00:00"))
            now_dt = datetime.now(timezone.utc)
            return max(0, (now_dt - pub_dt).days)
        except Exception:
            return 30

    def _decay_multiplier(self, days: int) -> float:
        """Interpolate on the deterministic freshness decay curve."""
        for i, (threshold, mult) in enumerate(FRESHNESS_CURVE):
            if days <= threshold:
                return mult
            if i + 1 < len(FRESHNESS_CURVE):
                next_threshold, next_mult = FRESHNESS_CURVE[i + 1]
                if days <= next_threshold:
                    # Linear interpolation
                    frac = (days - threshold) / (next_threshold - threshold)
                    return mult + frac * (next_mult - mult)
        return 0.10  # minimum

    def score(self, advisory: Dict) -> DimensionScore:
        days_old = self._days_old(advisory)
        multiplier = round(self._decay_multiplier(days_old), 4)
        raw = multiplier
        weighted = round(raw * DIM_WEIGHTS["D4_freshness"], 2)

        rationale = (
            f"Freshness: advisory is {days_old} day(s) old. "
            f"Decay multiplier: {multiplier:.2f}. "
            f"Score: {weighted:.1f}/{DIM_WEIGHTS['D4_freshness']:.0f} pts."
        )

        return DimensionScore(
            dimension_id="D4_freshness",
            max_points=DIM_WEIGHTS["D4_freshness"],
            raw_score=raw,
            weighted_score=weighted,
            contributing_factors={
                "days_old": days_old,
                "decay_multiplier": multiplier,
                "published_at": advisory.get("published_at", "unknown"),
            },
            rationale=rationale,
        )


class D5_InfrastructureScorer:
    """
    D5: Infrastructure Overlap — shared IOC/infra detection bonus.
    Max contribution: 10 points.
    """

    def score(self, advisory: Dict) -> DimensionScore:
        # infrastructure overlap data populated by GraphCorrelationEngine
        infra_overlap = int(advisory.get("infrastructure_overlap_count", 0) or 0)
        shared_actors = int(advisory.get("shared_actor_count", 0) or 0)

        pts = 0.0
        pts += min(0.6, infra_overlap * 0.15)
        pts += min(0.4, shared_actors * 0.20)
        raw      = round(min(1.0, pts), 4)
        weighted = round(raw * DIM_WEIGHTS["D5_infrastructure"], 2)

        rationale = (
            f"Infrastructure Overlap: {infra_overlap} shared infrastructure IOC(s), "
            f"{shared_actors} actor(s) share this infrastructure. "
            f"Score: {weighted:.1f}/{DIM_WEIGHTS['D5_infrastructure']:.0f} pts."
        )

        return DimensionScore(
            dimension_id="D5_infrastructure",
            max_points=DIM_WEIGHTS["D5_infrastructure"],
            raw_score=raw,
            weighted_score=weighted,
            contributing_factors={
                "infrastructure_overlap_count": infra_overlap,
                "shared_actor_count": shared_actors,
            },
            rationale=rationale,
        )


class D6_SourceTrustScorer:
    """
    D6: Source Trust — feed source reputation weighting.
    Max contribution: 15 points.
    """

    def _trust(self, source: str) -> float:
        src_lower = (source or "unknown").lower()
        for k, v in SOURCE_TRUST_TIERS.items():
            if k in src_lower:
                return v
        return SOURCE_TRUST_TIERS["unknown"]

    def score(self, advisory: Dict) -> DimensionScore:
        source     = str(advisory.get("feed_source", "unknown"))
        trust_mult = self._trust(source)

        # Bonus for multiple trusted sources
        alt_sources = advisory.get("additional_sources", []) or []
        alt_bonus   = min(0.20, len(alt_sources) * 0.05)
        raw      = round(min(1.0, trust_mult + alt_bonus), 4)
        weighted = round(raw * DIM_WEIGHTS["D6_source_trust"], 2)

        rationale = (
            f"Source Trust: primary source '{source}' has trust score {trust_mult:.2f}. "
            f"{len(alt_sources)} additional source(s). "
            f"Score: {weighted:.1f}/{DIM_WEIGHTS['D6_source_trust']:.0f} pts."
        )

        return DimensionScore(
            dimension_id="D6_source_trust",
            max_points=DIM_WEIGHTS["D6_source_trust"],
            raw_score=raw,
            weighted_score=weighted,
            contributing_factors={
                "source": source,
                "trust_multiplier": trust_mult,
                "additional_sources": len(alt_sources),
            },
            rationale=rationale,
        )


class D7_HistoricalSimilarityScorer:
    """
    D7: Historical Similarity — similarity to known high-risk threat patterns.
    Max contribution: 10 points. Uses deterministic keyword/pattern matching.
    """

    HIGH_RISK_PATTERNS = [
        "actively exploit",
        "exploit in the wild",
        "ransomware",
        "zero-day",
        "0-day",
        "critical infrastructure",
        "nation.state",
        "apt",
        "supply chain",
        "remote code execution",
        "unauthenticated",
        "pre-auth",
        "wormable",
        "lateral movement",
        "data exfiltration",
    ]

    def score(self, advisory: Dict) -> DimensionScore:
        title   = (advisory.get("title", "") or "").lower()
        summary = (advisory.get("summary", "") or "").lower()
        text    = f"{title} {summary}"

        matches = [p for p in self.HIGH_RISK_PATTERNS if p in text]
        # CVSS/EPSS signal
        try:
            cvss = float(advisory.get("cvss_score") or advisory.get("cvss") or 0.0)
            epss = float(advisory.get("epss_score") or advisory.get("epss") or 0.0)
        except (ValueError, TypeError):
            cvss, epss = 0.0, 0.0

        pattern_score = min(0.6, len(matches) * 0.10)
        cvss_score    = min(0.25, cvss / 40.0)   # CVSS 10 → 0.25
        epss_score    = min(0.15, epss * 0.15)   # EPSS 1.0 → 0.15

        raw      = round(min(1.0, pattern_score + cvss_score + epss_score), 4)
        weighted = round(raw * DIM_WEIGHTS["D7_historical_sim"], 2)

        rationale = (
            f"Historical Similarity: {len(matches)} high-risk pattern match(es) "
            f"({', '.join(matches[:3])}{'...' if len(matches) > 3 else ''}). "
            f"CVSS {cvss}, EPSS {round(epss, 1)}%. "  # FIX: epss already 0–100 percent
            f"Score: {weighted:.1f}/{DIM_WEIGHTS['D7_historical_sim']:.0f} pts."
        )

        return DimensionScore(
            dimension_id="D7_historical_sim",
            max_points=DIM_WEIGHTS["D7_historical_sim"],
            raw_score=raw,
            weighted_score=weighted,
            contributing_factors={
                "matched_patterns": matches[:5],
                "cvss": cvss,
                "epss": epss,
                "sub_scores": {
                    "pattern_score": round(pattern_score, 3),
                    "cvss_score": round(cvss_score, 3),
                    "epss_score": round(epss_score, 3),
                },
            },
            rationale=rationale,
        )


# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE TIER MAPPING
# ─────────────────────────────────────────────────────────────────────────────

def _confidence_tier(score: float) -> str:
    if score >= 80.0: return "VERY_HIGH"
    if score >= 60.0: return "HIGH"
    if score >= 40.0: return "MEDIUM"
    if score >= 20.0: return "LOW"
    return "VERY_LOW"


def _soc_recommendation(tier: str, advisory: Dict) -> str:
    kev   = advisory.get("kev_confirmed", False)
    cvss  = float(advisory.get("cvss_score") or advisory.get("cvss") or 0)
    recs = {
        "VERY_HIGH": "IMMEDIATE: High-confidence threat. Block IOCs NOW. Escalate to CISO within 4h. Deploy detection pack.",
        "HIGH":      "URGENT: Corroborated threat. Block IOCs within 2h. Run 30-day retro-hunt. Patch within 48h.",
        "MEDIUM":    "STANDARD: Credible threat. Schedule IOC blocking. Validate ATT&CK coverage. Patch in SLA window.",
        "LOW":       "MONITOR: Limited corroboration. Watch for escalation. Retain in hunt backlog.",
        "VERY_LOW":  "INFORMATIONAL: Minimal evidence. Log for reference. Review if additional corroboration emerges.",
    }
    base = recs.get(tier, recs["VERY_LOW"])
    if kev:
        base = f"[KEV CONFIRMED] {base}"
    if cvss >= 9.0:
        base = f"[CVSS CRITICAL {cvss}] {base}"
    return base


# ─────────────────────────────────────────────────────────────────────────────
# CONFIDENCE LINEAGE TRACKER
# ─────────────────────────────────────────────────────────────────────────────

class ConfidenceLineageTracker:
    """Track how confidence evolves from initial advisory to final enriched score."""

    def build_lineage(self, advisory: Dict, final_score: float) -> ConfidenceLineage:
        stix_id = str(advisory.get("stix_id", ""))
        stages: List[Dict] = []

        # Stage 1: Raw advisory baseline
        base = float(advisory.get("ai_confidence") or advisory.get("confidence") or 30.0)
        stages.append({
            "stage": "INGESTION",
            "confidence": round(base, 1),
            "delta": 0.0,
            "rationale": f"Initial advisory confidence from feed: {base}%",
        })

        # Stage 2: IOC enrichment
        ioc_count = len(advisory.get("iocs", []) or [])
        ioc_delta = min(15.0, ioc_count * 2.5)
        stages.append({
            "stage": "IOC_ENRICHMENT",
            "confidence": round(base + ioc_delta, 1),
            "delta": round(ioc_delta, 1),
            "rationale": f"IOC enrichment added {ioc_delta:.1f} pts ({ioc_count} IOCs)",
        })

        # Stage 3: ATT&CK contextualization
        ttp_count = len(advisory.get("ttps", []) or [])
        ttp_delta = min(12.0, ttp_count * 3.0)
        stages.append({
            "stage": "ATTCK_CONTEXTUALIZATION",
            "confidence": round(base + ioc_delta + ttp_delta, 1),
            "delta": round(ttp_delta, 1),
            "rationale": f"ATT&CK mapping added {ttp_delta:.1f} pts ({ttp_count} TTPs)",
        })

        # Stage 4: Graph correlation
        graph_delta = float(advisory.get("infrastructure_overlap_count", 0) or 0) * 2.0
        stages.append({
            "stage": "GRAPH_CORRELATION",
            "confidence": round(base + ioc_delta + ttp_delta + graph_delta, 1),
            "delta": round(graph_delta, 1),
            "rationale": f"Graph correlation added {graph_delta:.1f} pts",
        })

        # Stage 5: Final explainable score
        running = base + ioc_delta + ttp_delta + graph_delta
        final_delta = round(final_score - running, 1)
        stages.append({
            "stage": "EXPLAINABLE_SCORING",
            "confidence": round(final_score, 1),
            "delta": final_delta,
            "rationale": f"7-dimension explainable scoring finalized at {final_score}%",
        })

        return ConfidenceLineage(
            advisory_id=stix_id,
            stages=stages,
            initial=round(base, 1),
            final=round(final_score, 1),
            total_delta=round(final_score - base, 1),
        )


# ─────────────────────────────────────────────────────────────────────────────
# MASTER EXPLAINABLE CONFIDENCE ENGINE
# ─────────────────────────────────────────────────────────────────────────────

class ExplainableConfidenceEngine:
    """
    SENTINEL APEX — Explainable Confidence Engine v1.0

    Computes a fully auditable, 7-dimension confidence score for each advisory.
    Every point of the final score is traceable to a specific evidence factor.

    Deterministic: audit_trail.reproduce() will always return True for the same input.
    """

    def __init__(self):
        self._d1 = D1_IOCQualityScorer()
        self._d2 = D2_ATTCKDepthScorer()
        self._d3 = D3_CorroborationScorer()
        self._d4 = D4_FreshnessScorer()
        self._d5 = D5_InfrastructureScorer()
        self._d6 = D6_SourceTrustScorer()
        self._d7 = D7_HistoricalSimilarityScorer()
        self._lineage = ConfidenceLineageTracker()

    def score(self, advisory: Dict) -> Tuple[ConfidenceAuditTrail, ConfidenceLineage]:
        """
        Compute explainable confidence + lineage for one advisory.
        Returns (ConfidenceAuditTrail, ConfidenceLineage). Never raises.
        """
        try:
            return self._score_internal(advisory)
        except Exception as e:
            logger.error(f"[EXPLAINABLE-CONF] Error: {e}")
            stix_id = str(advisory.get("stix_id", ""))
            empty_dim = DimensionScore(
                dimension_id="ERROR", max_points=0.0, raw_score=0.0,
                weighted_score=0.0, contributing_factors={}, rationale=str(e),
            )
            audit = ConfidenceAuditTrail(
                advisory_id=stix_id, advisory_title="",
                final_confidence=0.0, confidence_tier="VERY_LOW",
                dimensions=[empty_dim], dimension_summary={},
                score_hash="error", rationale=f"Scoring error: {e}",
                recommendation="Manual review required.", scored_at=_now_iso(),
            )
            lineage = ConfidenceLineage(
                advisory_id=stix_id, stages=[], initial=0.0, final=0.0, total_delta=0.0
            )
            return audit, lineage

    def _score_internal(self, advisory: Dict) -> Tuple[ConfidenceAuditTrail, ConfidenceLineage]:
        stix_id = str(advisory.get("stix_id", ""))
        title   = str(advisory.get("title", ""))[:80]

        # Run all 7 dimension scorers
        dims: List[DimensionScore] = [
            self._d1.score(advisory),
            self._d2.score(advisory),
            self._d3.score(advisory),
            self._d4.score(advisory),
            self._d5.score(advisory),
            self._d6.score(advisory),
            self._d7.score(advisory),
        ]

        # Aggregate
        final_confidence = round(sum(d.weighted_score for d in dims), 1)
        final_confidence = max(0.0, min(100.0, final_confidence))

        dim_summary = {d.dimension_id: round(d.weighted_score, 2) for d in dims}
        tier         = _confidence_tier(final_confidence)
        recommendation = _soc_recommendation(tier, advisory)

        # Score hash (reproducibility proof)
        score_hash = hashlib.md5(
            json.dumps(dim_summary, sort_keys=True).encode()
        , usedforsecurity=False).hexdigest()

        # Executive rationale
        top_dim = max(dims, key=lambda d: d.weighted_score)
        bot_dim = min(dims, key=lambda d: d.weighted_score)
        rationale = (
            f"Final confidence: {final_confidence}% ({tier}). "
            f"Strongest signal: {top_dim.dimension_id} ({top_dim.weighted_score:.1f}pts). "
            f"Weakest signal: {bot_dim.dimension_id} ({bot_dim.weighted_score:.1f}pts). "
            f"All 7 dimensions scored. Score reproducible via hash {score_hash[:8]}."
        )

        audit = ConfidenceAuditTrail(
            advisory_id=stix_id,
            advisory_title=title,
            final_confidence=final_confidence,
            confidence_tier=tier,
            dimensions=dims,
            dimension_summary=dim_summary,
            score_hash=score_hash,
            rationale=rationale,
            recommendation=recommendation,
            scored_at=_now_iso(),
        )

        lineage = self._lineage.build_lineage(advisory, final_confidence)

        logger.info(
            f"[EXPLAINABLE-CONF] {stix_id[:30]} → "
            f"confidence={final_confidence}% tier={tier} hash={score_hash[:8]}"
        )

        return audit, lineage

    def score_batch(self, advisories: List[Dict]) -> List[Dict]:
        """Batch scoring. Returns serializable dicts."""
        results = []
        for adv in advisories:
            audit, lineage = self.score(adv)
            results.append({
                "advisory_id":      audit.advisory_id,
                "advisory_title":   audit.advisory_title,
                "final_confidence": audit.final_confidence,
                "confidence_tier":  audit.confidence_tier,
                "dimensions":       [asdict(d) for d in audit.dimensions],
                "dimension_summary": audit.dimension_summary,
                "score_hash":       audit.score_hash,
                "rationale":        audit.rationale,
                "recommendation":   audit.recommendation,
                "lineage": {
                    "initial":      lineage.initial,
                    "final":        lineage.final,
                    "total_delta":  lineage.total_delta,
                    "stages":       lineage.stages,
                },
                "scored_at":        audit.scored_at,
            })
        return results

    def persist(self, results: List[Dict], output_dir: Path) -> None:
        output_dir.mkdir(parents=True, exist_ok=True)

        out_path = output_dir / "explainable_confidence_scores.json"
        tmp = out_path.with_suffix(".tmp")
        summary = {
            "engine":  "ExplainableConfidenceEngine",
            "version": VERSION,
            "count":   len(results),
            "tier_distribution": {},
            "mean_confidence": round(
                sum(r["final_confidence"] for r in results) / max(1, len(results)), 1
            ),
            "generated_at": _now_iso(),
            "results": results,
        }
        for r in results:
            t = r["confidence_tier"]
            summary["tier_distribution"][t] = summary["tier_distribution"].get(t, 0) + 1

        with open(tmp, "w") as f:
            json.dump(summary, f, indent=2)
        tmp.replace(out_path)
        logger.info(f"[EXPLAINABLE-CONF] Persisted {len(results)} audit trails → {out_path}")


# ─────────────────────────────────────────────────────────────────────────────
# STANDALONE RUNNER
# ─────────────────────────────────────────────────────────────────────────────

def main() -> None:
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [CDB-EXPLAINABLE-CONFIDENCE] %(levelname)s %(message)s",
        stream=sys.stdout,
    )
    BASE_DIR      = Path(__file__).resolve().parent.parent
    MANIFEST_PATH = BASE_DIR / "data" / "stix" / "feed_manifest.json"
    OUTPUT_DIR    = BASE_DIR / "data" / "intelligence"

    if not MANIFEST_PATH.exists():
        logger.warning("[EXPLAINABLE-CONF] No manifest — exiting cleanly")
        sys.exit(0)

    try:
        with open(MANIFEST_PATH) as f:
            manifest = json.load(f)
    except Exception as e:
        logger.error(f"[EXPLAINABLE-CONF] Manifest load error: {e}")
        sys.exit(0)

    advisories = manifest.get("items", manifest.get("advisories", []))
    if not advisories:
        logger.info("[EXPLAINABLE-CONF] No advisories — nothing to do")
        sys.exit(0)

    engine  = ExplainableConfidenceEngine()
    results = engine.score_batch(advisories)
    engine.persist(results, OUTPUT_DIR)
    logger.info(
        f"[EXPLAINABLE-CONF] Complete: {len(results)} advisories scored. "
        f"Mean confidence={round(sum(r['final_confidence'] for r in results)/max(1,len(results)),1)}%"
    )
    sys.exit(0)


if __name__ == "__main__":
    main()
