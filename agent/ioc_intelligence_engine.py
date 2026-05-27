"""
CYBERDUDEBIVASH® SENTINEL APEX — Advanced IOC Intelligence Engine
Phase 44: Operational Reality Convergence

Implements:
  - IOC confidence scoring (multi-dimensional)
  - IOC freshness analytics (time-decay model)
  - IOC decay modeling (exponential confidence decay)
  - Telemetry prevalence scoring (how widely seen in YOUR env)
  - IOC replay hit analytics
  - Environmental prevalence scoring
  - Infrastructure overlap scoring
  - IOC relationship graphing
  - Full IOC enrichment with provenance

ALL IOCs MUST INCLUDE:
  confidence | telemetry_provenance | first_seen | last_seen
  replay_hits | graph_overlap | environmental_prevalence
"""

from __future__ import annotations

import math
import hashlib
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Set, Tuple

logger = logging.getLogger("sentinel.ioc_intelligence")


# ─────────────────────────────────────────────────────────────
# ENUMERATIONS
# ─────────────────────────────────────────────────────────────

class IOCType(str, Enum):
    IPV4           = "ipv4"
    IPV6           = "ipv6"
    DOMAIN         = "domain"
    URL            = "url"
    FILE_HASH_MD5  = "md5"
    FILE_HASH_SHA1 = "sha1"
    FILE_HASH_SHA256 = "sha256"
    EMAIL          = "email"
    MUTEX          = "mutex"
    REGISTRY_KEY   = "registry_key"
    YARA_MATCH     = "yara_match"
    JARM           = "jarm"
    JA3            = "ja3"
    USER_AGENT     = "user_agent"
    ASN            = "asn"
    CIDR           = "cidr"

class IOCConfidenceTier(str, Enum):
    VERY_HIGH   = "VERY_HIGH"    # ≥0.90
    HIGH        = "HIGH"         # 0.75–0.89
    MEDIUM      = "MEDIUM"       # 0.55–0.74
    LOW         = "LOW"          # 0.35–0.54
    VERY_LOW    = "VERY_LOW"     # 0.15–0.34
    EXPIRED     = "EXPIRED"      # confidence decayed below 0.15
    REVOKED     = "REVOKED"      # explicitly revoked

class IOCRelationshipType(str, Enum):
    RESOLVES_TO     = "resolves_to"       # domain → IP
    HOSTED_ON       = "hosted_on"         # URL → domain
    COMMUNICATES    = "communicates"      # host → C2
    DROPS           = "drops"             # malware → file
    SAME_CAMPAIGN   = "same_campaign"     # IOC1 ↔ IOC2
    SAME_ACTOR      = "same_actor"        # IOC1 ↔ IOC2 (attributed)
    INFRASTRUCTURE_OVERLAP = "infra_overlap"
    CHILD_OF        = "child_of"          # subnet → CIDR
    VARIANT_OF      = "variant_of"        # malware variant lineage

# ─────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────

@dataclass
class IOCSourceReference:
    """Evidence provenance for a single IOC observation."""
    source_id: str
    source_name: str
    source_trust: float           # 0.0–1.0
    reported_at: str
    tlp: str
    observation_type: str         # telemetry | feed | honeynet | replay | manual
    hit_count: int = 0
    raw_context: str = ""

@dataclass
class IOCTelemetryContext:
    """Telemetry evidence for this IOC in the current environment."""
    first_seen_in_env: Optional[str] = None
    last_seen_in_env: Optional[str]  = None
    hit_count_env: int               = 0
    unique_hosts_hit: int            = 0
    network_hits: int                = 0
    endpoint_hits: int               = 0
    email_hits: int                  = 0
    honeynet_hits: int               = 0
    replay_hits: int                 = 0
    associated_processes: List[str]  = field(default_factory=list)
    associated_campaigns: List[str]  = field(default_factory=list)

@dataclass
class IOCRelationship:
    """Directed relationship between two IOCs."""
    source_ioc_id: str
    target_ioc_id: str
    relationship_type: IOCRelationshipType
    confidence: float
    evidence_basis: str
    created_at: str

@dataclass
class EnrichedIOC:
    """Complete enriched IOC with confidence, decay, telemetry, and graph data."""
    ioc_id: str
    ioc_type: IOCType
    ioc_value: str

    # Temporal
    first_seen: str
    last_seen: str
    report_date: str

    # Confidence
    raw_confidence: float            # Pre-decay confidence
    current_confidence: float        # Post-decay current confidence
    confidence_tier: IOCConfidenceTier
    confidence_band: Tuple[float, float]

    # Decay
    decay_rate: float               # Per-day decay coefficient
    days_since_last_seen: int
    decay_factor: float             # Applied decay multiplier

    # Attribution
    threat_actor: Optional[str]
    malware_family: Optional[str]
    campaign_ids: List[str]
    attck_techniques: List[str]
    tlp: str

    # Telemetry provenance
    telemetry: IOCTelemetryContext
    sources: List[IOCSourceReference]
    source_count: int

    # Environmental
    environmental_prevalence: float  # 0.0–1.0 how common in this org's env
    global_prevalence: float         # 0.0–1.0 how common across all tenants
    infrastructure_overlap_score: float

    # Graph
    graph_node_id: Optional[str]
    graph_cluster: Optional[str]
    related_ioc_count: int

    # Replay
    replay_hits: int
    replay_confirmed: bool

    # Status
    is_active: bool
    revoked: bool
    false_positive_score: float     # 0.0–1.0 (high = likely FP)

    scored_at: str


# ─────────────────────────────────────────────────────────────
# DECAY MODEL
# ─────────────────────────────────────────────────────────────

class IOCDecayModel:
    """
    Exponential confidence decay model.
    Different IOC types have different half-lives based on operational experience.
    """

    # Half-life in days per IOC type
    HALF_LIVES: Dict[IOCType, float] = {
        IOCType.IPV4:            30.0,   # IPs reuse quickly
        IOCType.IPV6:            45.0,
        IOCType.DOMAIN:          60.0,   # Domains persist longer
        IOCType.URL:             14.0,   # URLs change rapidly
        IOCType.FILE_HASH_MD5:   180.0,  # File hashes are stable
        IOCType.FILE_HASH_SHA1:  180.0,
        IOCType.FILE_HASH_SHA256:365.0,  # SHA256 very stable
        IOCType.EMAIL:           90.0,
        IOCType.MUTEX:           365.0,  # Mutexes very stable
        IOCType.REGISTRY_KEY:    365.0,
        IOCType.YARA_MATCH:      365.0,
        IOCType.JARM:            120.0,
        IOCType.JA3:             90.0,
        IOCType.USER_AGENT:      21.0,   # UAs change rapidly
        IOCType.ASN:             180.0,
        IOCType.CIDR:            60.0,
    }

    def compute_decay(
        self,
        ioc_type: IOCType,
        days_since_last_seen: int,
        replay_hits: int = 0,
        telemetry_hits: int = 0,
    ) -> Tuple[float, float]:
        """
        Compute decay factor and daily decay rate.
        Recent replay/telemetry hits reset the decay clock partially.

        Returns (decay_factor, daily_rate)
        """
        half_life = self.HALF_LIVES.get(ioc_type, 45.0)
        daily_rate = math.log(2) / half_life

        # Recent activity extends the IOC's relevance
        # Each replay hit adds 7 days to effective last-seen
        effective_days = max(0, days_since_last_seen - (replay_hits * 7) - (min(telemetry_hits, 10) * 2))
        effective_days = max(0, effective_days)

        decay_factor = math.exp(-daily_rate * effective_days)
        return round(decay_factor, 4), round(daily_rate, 6)

    def freshness_label(self, decay_factor: float) -> str:
        if decay_factor >= 0.90:  return "FRESH"
        if decay_factor >= 0.70:  return "RECENT"
        if decay_factor >= 0.50:  return "AGING"
        if decay_factor >= 0.25:  return "STALE"
        return "EXPIRED"


# ─────────────────────────────────────────────────────────────
# CONFIDENCE SCORER
# ─────────────────────────────────────────────────────────────

class IOCConfidenceScorer:
    """
    Multi-dimensional IOC confidence scoring.
    Combines source trust, telemetry density, replay validation,
    graph overlap, decay, and false-positive modeling.
    """

    def score(
        self,
        raw_confidence: float,
        decay_factor: float,
        sources: List[IOCSourceReference],
        telemetry: IOCTelemetryContext,
        replay_hits: int,
        graph_cluster_matches: int,
        infrastructure_overlap: float,
        false_positive_score: float,
    ) -> Tuple[float, IOCConfidenceTier, Tuple[float, float]]:
        """
        Returns (final_confidence, tier, confidence_band).
        """
        # Source trust aggregate
        if sources:
            avg_source_trust = sum(s.source_trust for s in sources) / len(sources)
            multi_source_bonus = min(len(sources) * 0.05, 0.20)
        else:
            avg_source_trust = 0.3
            multi_source_bonus = 0.0

        # Telemetry validation
        env_hits = telemetry.hit_count_env
        tel_factor = min(1.0, 0.5 + (env_hits / 50.0) * 0.5) if env_hits > 0 else 0.7

        # Replay validation — strong confirmatory signal
        replay_bonus = min(replay_hits * 0.08, 0.25)

        # Graph correlation
        graph_bonus = min(graph_cluster_matches * 0.04, 0.15)

        # FP penalty
        fp_penalty = false_positive_score * 0.30

        # Weighted assembly
        base = (
            raw_confidence * 0.30 +
            avg_source_trust * 0.20 +
            multi_source_bonus +
            tel_factor * 0.15 +
            replay_bonus +
            graph_bonus +
            infrastructure_overlap * 0.05
        )
        final = max(0.0, min(1.0, (base * decay_factor) - fp_penalty))

        # Confidence band
        signal_count = len(sources) + (1 if env_hits > 0 else 0) + (1 if replay_hits > 0 else 0)
        band_half = max(0.03, 0.20 * (1.0 - min(signal_count / 6.0, 1.0)))
        band = (round(max(0.0, final - band_half), 3), round(min(1.0, final + band_half * 0.5), 3))

        # Tier mapping
        if final >= 0.90:   tier = IOCConfidenceTier.VERY_HIGH
        elif final >= 0.75: tier = IOCConfidenceTier.HIGH
        elif final >= 0.55: tier = IOCConfidenceTier.MEDIUM
        elif final >= 0.35: tier = IOCConfidenceTier.LOW
        elif final >= 0.15: tier = IOCConfidenceTier.VERY_LOW
        else:               tier = IOCConfidenceTier.EXPIRED

        return round(final, 4), tier, band


# ─────────────────────────────────────────────────────────────
# IOC INTELLIGENCE ENGINE
# ─────────────────────────────────────────────────────────────

class AdvancedIOCIntelligenceEngine:
    """
    Main IOC intelligence processing engine.
    Produces fully enriched IOCs with confidence, decay, telemetry, and graph data.
    """

    def __init__(self):
        self.decay_model = IOCDecayModel()
        self.confidence_scorer = IOCConfidenceScorer()
        self._relationship_graph: Dict[str, List[IOCRelationship]] = {}

    def enrich(
        self,
        ioc_id: str,
        ioc_type: IOCType,
        ioc_value: str,
        first_seen: str,
        last_seen: str,
        raw_confidence: float,
        sources: List[IOCSourceReference],
        telemetry: IOCTelemetryContext,
        threat_actor: Optional[str] = None,
        malware_family: Optional[str] = None,
        campaign_ids: Optional[List[str]] = None,
        attck_techniques: Optional[List[str]] = None,
        graph_cluster: Optional[str] = None,
        graph_cluster_matches: int = 0,
        infrastructure_overlap_score: float = 0.0,
        global_prevalence: float = 0.0,
        false_positive_score: float = 0.0,
        tlp: str = "TLP:AMBER",
    ) -> EnrichedIOC:
        """Enrich a raw IOC into a fully-scored intelligence artifact."""

        # Compute decay
        try:
            last_seen_dt = datetime.fromisoformat(last_seen.replace("Z", "+00:00"))
            days_since = (datetime.now(timezone.utc) - last_seen_dt).days
        except Exception:
            days_since = 30

        decay_factor, daily_rate = self.decay_model.compute_decay(
            ioc_type=ioc_type,
            days_since_last_seen=days_since,
            replay_hits=telemetry.replay_hits,
            telemetry_hits=telemetry.hit_count_env,
        )

        # Score confidence
        final_conf, tier, band = self.confidence_scorer.score(
            raw_confidence=raw_confidence,
            decay_factor=decay_factor,
            sources=sources,
            telemetry=telemetry,
            replay_hits=telemetry.replay_hits,
            graph_cluster_matches=graph_cluster_matches,
            infrastructure_overlap=infrastructure_overlap_score,
            false_positive_score=false_positive_score,
        )

        # Environmental prevalence
        env_prevalence = min(telemetry.unique_hosts_hit / 100.0, 1.0)

        # Graph node ID
        graph_node_id = hashlib.sha256(
            f"{ioc_type.value}:{ioc_value}".encode()
        ).hexdigest()[:16]

        is_active = (
            tier not in (IOCConfidenceTier.EXPIRED, IOCConfidenceTier.REVOKED)
            and days_since <= 365
        )

        return EnrichedIOC(
            ioc_id=ioc_id,
            ioc_type=ioc_type,
            ioc_value=ioc_value,
            first_seen=first_seen,
            last_seen=last_seen,
            report_date=datetime.now(timezone.utc).isoformat(),
            raw_confidence=round(raw_confidence, 4),
            current_confidence=final_conf,
            confidence_tier=tier,
            confidence_band=band,
            decay_rate=daily_rate,
            days_since_last_seen=days_since,
            decay_factor=decay_factor,
            threat_actor=threat_actor,
            malware_family=malware_family,
            campaign_ids=campaign_ids or [],
            attck_techniques=attck_techniques or [],
            tlp=tlp,
            telemetry=telemetry,
            sources=sources,
            source_count=len(sources),
            environmental_prevalence=round(env_prevalence, 4),
            global_prevalence=round(global_prevalence, 4),
            infrastructure_overlap_score=round(infrastructure_overlap_score, 4),
            graph_node_id=graph_node_id,
            graph_cluster=graph_cluster,
            related_ioc_count=len(self._relationship_graph.get(ioc_id, [])),
            replay_hits=telemetry.replay_hits,
            replay_confirmed=telemetry.replay_hits > 0,
            is_active=is_active,
            revoked=False,
            false_positive_score=round(false_positive_score, 4),
            scored_at=datetime.now(timezone.utc).isoformat(),
        )

    def add_relationship(
        self,
        source_ioc_id: str,
        target_ioc_id: str,
        relationship_type: IOCRelationshipType,
        confidence: float,
        evidence_basis: str,
    ) -> IOCRelationship:
        """Register a directed relationship between two IOCs."""
        rel = IOCRelationship(
            source_ioc_id=source_ioc_id,
            target_ioc_id=target_ioc_id,
            relationship_type=relationship_type,
            confidence=round(confidence, 4),
            evidence_basis=evidence_basis,
            created_at=datetime.now(timezone.utc).isoformat(),
        )
        self._relationship_graph.setdefault(source_ioc_id, []).append(rel)
        return rel

    def get_related(self, ioc_id: str) -> List[IOCRelationship]:
        return self._relationship_graph.get(ioc_id, [])

    def filter_by_confidence(
        self,
        iocs: List[EnrichedIOC],
        min_confidence: float = 0.55,
        exclude_expired: bool = True,
        exclude_fps: bool = True,
        fp_threshold: float = 0.60,
    ) -> List[EnrichedIOC]:
        """Filter IOC list by confidence, freshness, and FP status."""
        result = []
        for ioc in iocs:
            if ioc.current_confidence < min_confidence:
                continue
            if exclude_expired and ioc.confidence_tier == IOCConfidenceTier.EXPIRED:
                continue
            if exclude_fps and ioc.false_positive_score >= fp_threshold:
                continue
            result.append(ioc)
        return sorted(result, key=lambda i: i.current_confidence, reverse=True)

    def bulk_enrich(
        self,
        raw_iocs: List[Dict[str, Any]],
    ) -> List[EnrichedIOC]:
        """Bulk enrich a list of raw IOC dicts."""
        enriched = []
        for raw in raw_iocs:
            try:
                ioc = self.enrich(**raw)
                enriched.append(ioc)
            except Exception as exc:
                logger.error("IOC enrichment failed for %s: %s", raw.get("ioc_id"), exc)
        return enriched

    def generate_prevalence_report(
        self,
        iocs: List[EnrichedIOC],
    ) -> Dict[str, Any]:
        """Generate IOC prevalence analytics across the fleet."""
        active = [i for i in iocs if i.is_active]
        by_type: Dict[str, int] = {}
        for ioc in active:
            by_type[ioc.ioc_type.value] = by_type.get(ioc.ioc_type.value, 0) + 1

        high_conf = [i for i in active if i.confidence_tier in (
            IOCConfidenceTier.VERY_HIGH, IOCConfidenceTier.HIGH
        )]
        replay_confirmed = [i for i in active if i.replay_confirmed]
        env_hits_total = sum(i.telemetry.hit_count_env for i in active)

        return {
            "total_iocs": len(iocs),
            "active_iocs": len(active),
            "high_confidence": len(high_conf),
            "replay_confirmed": len(replay_confirmed),
            "expired": len([i for i in iocs if i.confidence_tier == IOCConfidenceTier.EXPIRED]),
            "total_env_hits": env_hits_total,
            "by_type": by_type,
            "avg_confidence": round(
                sum(i.current_confidence for i in active) / max(len(active), 1), 3
            ),
            "freshness_distribution": {
                self.decay_model.freshness_label(i.decay_factor): 0
                for i in active
            },
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
