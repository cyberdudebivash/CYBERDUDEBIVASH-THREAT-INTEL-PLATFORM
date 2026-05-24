"""
SENTINEL APEX — APEX Intelligence Scorer v2.0
==============================================
10-dimension threat scoring engine:
1. Exploitability Score     (CVSS/EPSS based)
2. Actor Sophistication     (MITRE group tier)
3. IOC Confidence           (enrichment corroboration)
4. Temporal Relevance       (recency decay)
5. Geographic Risk          (geopolitical exposure)
6. Sector Impact            (CISA sector mapping)
7. Campaign Activity        (active vs historical)
8. KEV Status               (CISA known exploited)
9. Dark Web Signal          (underground mention count)
10. AI Prediction Score     (ML threat trajectory)

Output: 0.0 → 10.0 APEX score + severity label + confidence band
"""
from __future__ import annotations

import math
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Optional

import structlog

log = structlog.get_logger("sentinel.scorer")


class SeverityLabel(str, Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFORMATIONAL = "INFORMATIONAL"


@dataclass
class ScoringInput:
    # CVSS/EPSS
    cvss_base: Optional[float] = None       # 0.0 - 10.0
    cvss_temporal: Optional[float] = None
    epss_score: Optional[float] = None      # 0.0 - 1.0
    epss_percentile: Optional[float] = None

    # Actor
    actor_mitre_group_id: Optional[str] = None
    actor_nation_state: Optional[str] = None
    actor_sophistication: Optional[str] = None  # minimal/intermediate/advanced/expert

    # IOC enrichment
    ioc_count: int = 0
    ioc_corroborated: int = 0     # How many IOCs confirmed by >=2 sources
    virustotal_detections: Optional[int] = None
    virustotal_total: Optional[int] = None
    abuseipdb_confidence: Optional[float] = None

    # Temporal
    published_at: Optional[datetime] = None
    last_seen: Optional[datetime] = None

    # Geographic
    target_countries: list[str] = field(default_factory=list)
    origin_country: Optional[str] = None

    # Sector
    target_sectors: list[str] = field(default_factory=list)  # CISA sectors

    # Campaign
    is_active_campaign: bool = False
    campaign_age_days: Optional[int] = None

    # KEV
    is_kev: bool = False
    kev_date_added: Optional[datetime] = None

    # Dark web
    dark_web_mention_count: int = 0
    dark_web_forums: list[str] = field(default_factory=list)
    ransomware_group_mention: bool = False

    # AI prediction
    ai_prediction_score: Optional[float] = None  # 0.0 - 1.0 from ML model


@dataclass
class APEXScoreResult:
    apex_score: float                   # 0.0 - 10.0
    severity: SeverityLabel
    confidence: float                   # 0.0 - 1.0
    dimension_scores: dict[str, float]  # per-dimension breakdown
    risk_factors: list[str]             # human-readable risk factors
    recommended_actions: list[str]
    scoring_version: str = "v2.0"
    scored_at: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


class APEXScorer:
    """
    Production-grade 10-dimension APEX threat scoring engine.
    Weights are tunable via config; defaults below are research-calibrated.
    """

    DIMENSION_WEIGHTS = {
        "exploitability":      0.22,  # Highest weight — exploitation = immediate risk
        "actor_sophistication": 0.15,
        "ioc_confidence":      0.12,
        "temporal_relevance":  0.10,
        "kev_status":          0.12,  # CISA KEV = near-certain exploitation
        "campaign_activity":   0.08,
        "sector_impact":       0.07,
        "dark_web_signal":     0.07,
        "geographic_risk":     0.05,
        "ai_prediction":       0.02,  # Supplemental ML signal
    }

    # High-risk nation states (geopolitical intelligence)
    HIGH_RISK_ORIGINS = {"CN", "RU", "KP", "IR", "BY", "SY"}

    # Critical infrastructure sectors (CISA Tier 1)
    CRITICAL_SECTORS = {
        "energy", "water", "healthcare", "financial",
        "communications", "transportation", "defense",
        "nuclear", "chemical", "critical_manufacturing",
    }

    # APT groups with nation-state backing (tier mapping)
    APT_SOPHISTICATION_TIER = {
        "G0016": "expert",  # APT28 (Fancy Bear)
        "G0007": "expert",  # APT1
        "G0010": "expert",  # Turla
        "G0032": "expert",  # Lazarus
        "G0096": "advanced", # APT41
        "G0060": "advanced", # BRONZE BUTLER
    }

    @classmethod
    def score(cls, inp: ScoringInput) -> APEXScoreResult:
        dims: dict[str, float] = {}
        risk_factors: list[str] = []

        # ---------------------------------------------------------------
        # D1: Exploitability Score
        # ---------------------------------------------------------------
        exp_score = 0.0
        if inp.cvss_base is not None:
            exp_score = inp.cvss_base / 10.0
        if inp.epss_score is not None:
            # EPSS directly measures exploitation probability → strong signal
            epss_weight = 0.4
            exp_score = (exp_score * (1 - epss_weight)) + (inp.epss_score * epss_weight)
            if inp.epss_score > 0.5:
                risk_factors.append(f"HIGH exploitation probability: EPSS={inp.epss_score:.2%}")
        if inp.cvss_base and inp.cvss_base >= 9.0:
            risk_factors.append(f"Critical CVSS base score: {inp.cvss_base}")
        dims["exploitability"] = min(exp_score, 1.0)

        # ---------------------------------------------------------------
        # D2: Actor Sophistication
        # ---------------------------------------------------------------
        soph_map = {"minimal": 0.2, "intermediate": 0.5, "advanced": 0.75, "expert": 1.0}
        soph = inp.actor_sophistication or "intermediate"

        # Auto-elevate for known nation-state APTs
        if inp.actor_mitre_group_id in cls.APT_SOPHISTICATION_TIER:
            soph = cls.APT_SOPHISTICATION_TIER[inp.actor_mitre_group_id]
            risk_factors.append(f"Nation-state APT: {inp.actor_mitre_group_id}")

        if inp.actor_nation_state and inp.actor_nation_state.upper() in cls.HIGH_RISK_ORIGINS:
            risk_factors.append(f"High-risk nation state origin: {inp.actor_nation_state}")
            dims["actor_sophistication"] = max(soph_map.get(soph, 0.5), 0.65)
        else:
            dims["actor_sophistication"] = soph_map.get(soph, 0.5)

        # ---------------------------------------------------------------
        # D3: IOC Confidence
        # ---------------------------------------------------------------
        ioc_conf = 0.0
        if inp.ioc_count > 0:
            corroboration_ratio = inp.ioc_corroborated / inp.ioc_count
            ioc_conf = 0.3 + (corroboration_ratio * 0.7)
        if inp.virustotal_detections is not None and inp.virustotal_total:
            vt_ratio = inp.virustotal_detections / inp.virustotal_total
            ioc_conf = max(ioc_conf, vt_ratio)
            if vt_ratio > 0.5:
                risk_factors.append(f"High VT detection rate: {inp.virustotal_detections}/{inp.virustotal_total}")
        if inp.abuseipdb_confidence:
            ioc_conf = max(ioc_conf, inp.abuseipdb_confidence / 100.0)
        dims["ioc_confidence"] = min(ioc_conf, 1.0)

        # ---------------------------------------------------------------
        # D4: Temporal Relevance (recency decay — 30-day half-life)
        # ---------------------------------------------------------------
        temporal = 0.5  # default
        if inp.published_at:
            now = datetime.now(timezone.utc)
            ref = inp.last_seen or inp.published_at
            if ref.tzinfo is None:
                ref = ref.replace(tzinfo=timezone.utc)
            age_days = max((now - ref).days, 0)
            half_life = 30  # days
            temporal = math.exp(-0.693 * age_days / half_life)
        dims["temporal_relevance"] = min(temporal, 1.0)

        # ---------------------------------------------------------------
        # D5: KEV Status — CISA Known Exploited = near-guaranteed risk
        # ---------------------------------------------------------------
        if inp.is_kev:
            dims["kev_status"] = 1.0
            risk_factors.append("CISA KEV: Actively exploited in the wild")
        else:
            dims["kev_status"] = 0.0

        # ---------------------------------------------------------------
        # D6: Campaign Activity
        # ---------------------------------------------------------------
        camp = 0.3
        if inp.is_active_campaign:
            camp = 0.9
            risk_factors.append("Active campaign detected")
        elif inp.campaign_age_days is not None:
            if inp.campaign_age_days < 7:
                camp = 0.85
            elif inp.campaign_age_days < 30:
                camp = 0.6
            elif inp.campaign_age_days < 90:
                camp = 0.4
            else:
                camp = 0.2
        dims["campaign_activity"] = camp

        # ---------------------------------------------------------------
        # D7: Sector Impact
        # ---------------------------------------------------------------
        sector_risk = 0.3
        if inp.target_sectors:
            critical_count = sum(1 for s in inp.target_sectors if s.lower() in cls.CRITICAL_SECTORS)
            if critical_count >= 3:
                sector_risk = 1.0
                risk_factors.append(f"Targets {critical_count} critical infrastructure sectors")
            elif critical_count >= 1:
                sector_risk = 0.7
                risk_factors.append(f"Targets critical sector: {', '.join(inp.target_sectors[:2])}")
            else:
                sector_risk = 0.4
        dims["sector_impact"] = sector_risk

        # ---------------------------------------------------------------
        # D8: Dark Web Signal
        # ---------------------------------------------------------------
        dw = 0.0
        if inp.ransomware_group_mention:
            dw = 1.0
            risk_factors.append("Ransomware group dark web mention detected")
        elif inp.dark_web_mention_count > 0:
            dw = min(0.3 + (inp.dark_web_mention_count * 0.05), 0.9)
            if inp.dark_web_mention_count >= 5:
                risk_factors.append(f"High dark web activity: {inp.dark_web_mention_count} mentions")
        dims["dark_web_signal"] = dw

        # ---------------------------------------------------------------
        # D9: Geographic Risk
        # ---------------------------------------------------------------
        geo = 0.3
        if inp.origin_country and inp.origin_country.upper() in cls.HIGH_RISK_ORIGINS:
            geo = 0.85
        if inp.target_countries:
            # G7/Five Eyes targeting = higher visibility/urgency
            high_value_targets = {"US", "GB", "DE", "FR", "CA", "AU", "JP"}
            if any(c.upper() in high_value_targets for c in inp.target_countries):
                geo = max(geo, 0.65)
        dims["geographic_risk"] = min(geo, 1.0)

        # ---------------------------------------------------------------
        # D10: AI Prediction Score
        # ---------------------------------------------------------------
        dims["ai_prediction"] = inp.ai_prediction_score or 0.5

        # ---------------------------------------------------------------
        # Compute Weighted APEX Score (0.0 - 10.0)
        # ---------------------------------------------------------------
        raw_score = sum(
            dims[d] * w for d, w in cls.DIMENSION_WEIGHTS.items() if d in dims
        )
        apex_score = round(raw_score * 10.0, 2)
        confidence = min(1.0, (inp.ioc_count * 0.05) + (0.4 if inp.cvss_base else 0.0) + 0.3)

        # ---------------------------------------------------------------
        # Severity Label
        # ---------------------------------------------------------------
        if apex_score >= 9.0:
            severity = SeverityLabel.CRITICAL
        elif apex_score >= 7.0:
            severity = SeverityLabel.HIGH
        elif apex_score >= 5.0:
            severity = SeverityLabel.MEDIUM
        elif apex_score >= 2.0:
            severity = SeverityLabel.LOW
        else:
            severity = SeverityLabel.INFORMATIONAL

        # ---------------------------------------------------------------
        # Recommended Actions
        # ---------------------------------------------------------------
        recommendations = cls._generate_recommendations(severity, inp, risk_factors)

        log.info(
            "sentinel.scorer.scored",
            apex_score=apex_score,
            severity=severity,
            dimensions=dims,
        )

        return APEXScoreResult(
            apex_score=apex_score,
            severity=severity,
            confidence=round(confidence, 2),
            dimension_scores={k: round(v, 4) for k, v in dims.items()},
            risk_factors=risk_factors,
            recommended_actions=recommendations,
        )

    @classmethod
    def _generate_recommendations(
        cls,
        severity: SeverityLabel,
        inp: ScoringInput,
        risk_factors: list[str],
    ) -> list[str]:
        recs = []
        if severity == SeverityLabel.CRITICAL:
            recs.append("IMMEDIATE ACTION: Activate incident response plan within 1 hour")
            recs.append("Isolate affected systems and apply emergency patches")
            recs.append("Enable emergency threat hunting across all endpoints")
        elif severity == SeverityLabel.HIGH:
            recs.append("Apply patches within 24 hours")
            recs.append("Increase monitoring for IOCs in SIEM")
            recs.append("Deploy detection rules to all security tooling")
        elif severity == SeverityLabel.MEDIUM:
            recs.append("Schedule patching within 7 days")
            recs.append("Add IOCs to threat intelligence feeds")
        else:
            recs.append("Monitor for escalation")
            recs.append("Add to watchlist")

        if inp.is_kev:
            recs.insert(0, "CISA KEV: Apply patches IMMEDIATELY — actively exploited")
        if inp.ransomware_group_mention:
            recs.insert(0, "RANSOMWARE RISK: Contact cyber insurance, test backups NOW")
        if inp.actor_nation_state in cls.HIGH_RISK_ORIGINS:
            recs.append("Nation-state threat: Brief CISO and consider law enforcement notification")

        return recs[:6]  # Cap at 6 recommendations
