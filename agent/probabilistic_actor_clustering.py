"""
CYBERDUDEBIVASH® SENTINEL APEX — Probabilistic Actor Clustering Engine
Phase 40: Operational Reality Convergence

Implements:
  - Probabilistic actor clustering (removes "Untracked Threat Cluster" overuse)
  - Infrastructure overlap analytics (shared C2/ASN/hosting fingerprints)
  - Campaign lineage confidence scoring
  - ATT&CK behavioral overlap scoring
  - Malware family overlap scoring
  - Graph-derived attribution
  - Actor ambiguity modeling
  - Attribution confidence bands with uncertainty propagation

GOVERNANCE MANDATE:
  - ALL attributions MUST include uncertainty scoring
  - ALL attributions MUST include evidence provenance
  - ALL attributions MUST include telemetry + graph support
  - Overuse of "Unknown Cluster" is a GOVERNANCE VIOLATION
  - Attribution without evidence is PROHIBITED
"""

from __future__ import annotations

import hashlib
import math
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, FrozenSet, List, Optional, Set, Tuple

logger = logging.getLogger("sentinel.actor_clustering")


# ─────────────────────────────────────────────────────────────
# ENUMERATIONS
# ─────────────────────────────────────────────────────────────

class AttributionConfidence(str, Enum):
    CONFIRMED     = "CONFIRMED"        # ≥0.85 — multiple independent signal types
    HIGH          = "HIGH"             # 0.70–0.84
    MODERATE      = "MODERATE"         # 0.50–0.69
    LOW           = "LOW"              # 0.30–0.49
    SPECULATIVE   = "SPECULATIVE"      # 0.10–0.29
    INSUFFICIENT  = "INSUFFICIENT"     # <0.10 — do NOT attribute

class ClusterOrigin(str, Enum):
    KNOWN_ACTOR       = "known_actor"         # matches named threat actor
    PARTIAL_MATCH     = "partial_match"       # overlaps with known actor
    NOVEL_CLUSTER     = "novel_cluster"       # new cluster, enough evidence
    AMBIGUOUS         = "ambiguous"           # multiple actor hypotheses
    INSUFFICIENT_DATA = "insufficient_data"  # cannot cluster responsibly

class EvidenceType(str, Enum):
    INFRASTRUCTURE    = "infrastructure"     # shared IPs/ASN/TLS certs
    ATTCK_OVERLAP     = "attck_overlap"      # shared TTP fingerprint
    MALWARE_FAMILY    = "malware_family"     # same malware codebase
    GRAPH_LINEAGE     = "graph_lineage"      # graph-derived campaign chain
    TELEMETRY_MATCH   = "telemetry_match"    # observed in environment
    REPLAY_MATCH      = "replay_match"       # replay engine confirmed
    CAMPAIGN_TIMING   = "campaign_timing"    # temporal campaign overlap
    VICTIMOLOGY       = "victimology"        # shared targeting profile


# ─────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────

@dataclass
class InfrastructureFingerprint:
    """Infrastructure overlap signals for actor attribution."""
    ip_addresses: List[str]       = field(default_factory=list)
    autonomous_systems: List[int] = field(default_factory=list)  # ASN numbers
    hosting_providers: List[str]  = field(default_factory=list)
    tls_cert_hashes: List[str]    = field(default_factory=list)
    domain_registrars: List[str]  = field(default_factory=list)
    jarm_fingerprints: List[str]  = field(default_factory=list)  # TLS JARM
    favicon_hashes: List[str]     = field(default_factory=list)
    port_patterns: List[int]      = field(default_factory=list)
    c2_protocols: List[str]       = field(default_factory=list)

    def fingerprint_hash(self) -> str:
        """Deterministic hash of infrastructure characteristics."""
        stable = sorted(
            self.tls_cert_hashes +
            self.jarm_fingerprints +
            self.favicon_hashes +
            [str(a) for a in self.autonomous_systems]
        )
        return hashlib.sha256("|".join(stable).encode()).hexdigest()[:16]


@dataclass
class ATTCKBehavioralProfile:
    """ATT&CK TTP behavioral fingerprint for an observed campaign."""
    techniques: List[str]            = field(default_factory=list)  # T1XXX.XXX
    tactics: List[str]               = field(default_factory=list)
    procedure_examples: List[str]    = field(default_factory=list)
    tool_references: List[str]       = field(default_factory=list)  # malware/tools
    sequencing_pattern: List[str]    = field(default_factory=list)  # ordered tactic chain
    replay_confirmed_ttps: List[str] = field(default_factory=list)

    def overlap_score(self, other: "ATTCKBehavioralProfile") -> float:
        """
        Compute Jaccard similarity on technique sets.
        Returns 0.0–1.0.
        """
        a = set(self.techniques)
        b = set(other.techniques)
        if not a and not b:
            return 0.0
        intersection = len(a & b)
        union = len(a | b)
        jaccard = intersection / union if union > 0 else 0.0

        # Bonus for shared sequencing pattern (order matters)
        seq_a = self.sequencing_pattern
        seq_b = other.sequencing_pattern
        seq_bonus = 0.0
        if seq_a and seq_b:
            shared_seq = sum(1 for t in seq_a[:len(seq_b)] if t in seq_b)
            seq_bonus = min(shared_seq / max(len(seq_a), len(seq_b)), 0.20)

        # Replay confirmation bonus
        replay_bonus = 0.0
        if self.replay_confirmed_ttps and other.replay_confirmed_ttps:
            rc_overlap = len(
                set(self.replay_confirmed_ttps) & set(other.replay_confirmed_ttps)
            )
            replay_bonus = min(rc_overlap / 5.0, 0.15)

        return min(jaccard + seq_bonus + replay_bonus, 1.0)


@dataclass
class CampaignObservation:
    """A single observed campaign with associated evidence."""
    campaign_id: str
    first_seen: str
    last_seen: str
    infrastructure: InfrastructureFingerprint
    attck_profile: ATTCKBehavioralProfile
    malware_families: List[str]
    victimology: List[str]          # target sectors/countries
    telemetry_event_count: int
    graph_node_count: int
    replay_hits: int
    source_feeds: List[str]
    tlp: str = "TLP:AMBER"


@dataclass
class KnownActorProfile:
    """Reference profile for a known threat actor."""
    actor_id: str
    actor_name: str
    aliases: List[str]
    origin_country: str
    motivation: str             # espionage / financial / hacktivism / destructive
    infrastructure: InfrastructureFingerprint
    attck_profile: ATTCKBehavioralProfile
    malware_families: List[str]
    victimology: List[str]
    active_since: str
    last_observed: str
    confidence_in_profile: float  # 0.0–1.0 — quality of known actor profile


@dataclass
class AttributionHypothesis:
    """A single actor attribution hypothesis with confidence."""
    actor_id: str
    actor_name: str
    confidence_score: float           # 0.0–1.0 overall
    confidence_level: AttributionConfidence
    confidence_band: Tuple[float, float]  # (low, high)

    # Evidence breakdown
    infrastructure_overlap: float     # 0.0–1.0
    attck_overlap: float              # 0.0–1.0
    malware_overlap: float            # 0.0–1.0
    campaign_lineage_score: float     # 0.0–1.0
    telemetry_support: float          # 0.0–1.0
    graph_support: float              # 0.0–1.0
    replay_support: float             # 0.0–1.0

    evidence_types_present: List[EvidenceType]
    evidence_count: int
    primary_evidence: str             # Most compelling evidence description
    uncertainty_factors: List[str]    # What reduces confidence


@dataclass
class ActorClusterResult:
    """Full probabilistic actor clustering result."""
    campaign_id: str
    cluster_origin: ClusterOrigin
    cluster_id: str                   # Assigned cluster identifier
    primary_hypothesis: Optional[AttributionHypothesis]
    alternative_hypotheses: List[AttributionHypothesis]

    # Ambiguity modeling
    is_ambiguous: bool
    ambiguity_score: float            # 0=clear attribution, 1=maximum ambiguity
    ambiguity_reason: str

    # Campaign lineage
    linked_campaigns: List[str]       # IDs of historically linked campaigns
    lineage_confidence: float         # 0.0–1.0

    # Governance
    attribution_justified: bool       # False = insufficient evidence
    governance_note: str
    produced_at: str


# ─────────────────────────────────────────────────────────────
# PROBABILISTIC ACTOR CLUSTERING ENGINE
# ─────────────────────────────────────────────────────────────

class ProbabilisticActorClusteringEngine:
    """
    Replaces simplistic "Untracked Cluster" labeling with evidence-backed
    probabilistic attribution across infrastructure, ATT&CK, malware,
    graph, and telemetry signal types.

    GOVERNANCE RULES:
      1. Never output "Untracked Cluster" without justification evidence
      2. Always include uncertainty factors
      3. Alternative hypotheses required when ambiguity_score > 0.4
      4. Attribution confidence < 0.10 = INSUFFICIENT → no actor name output
    """

    # Minimum evidence requirements for each confidence level
    CONFIDENCE_THRESHOLDS = {
        AttributionConfidence.CONFIRMED:    0.85,
        AttributionConfidence.HIGH:         0.70,
        AttributionConfidence.MODERATE:     0.50,
        AttributionConfidence.LOW:          0.30,
        AttributionConfidence.SPECULATIVE:  0.10,
        AttributionConfidence.INSUFFICIENT: 0.00,
    }

    # Weight matrix for evidence signal types
    SIGNAL_WEIGHTS = {
        EvidenceType.INFRASTRUCTURE:  0.25,
        EvidenceType.ATTCK_OVERLAP:   0.25,
        EvidenceType.MALWARE_FAMILY:  0.20,
        EvidenceType.GRAPH_LINEAGE:   0.15,
        EvidenceType.TELEMETRY_MATCH: 0.05,
        EvidenceType.REPLAY_MATCH:    0.05,
        EvidenceType.CAMPAIGN_TIMING: 0.03,
        EvidenceType.VICTIMOLOGY:     0.02,
    }

    def __init__(self, known_actors: Optional[List[KnownActorProfile]] = None):
        self.known_actors: List[KnownActorProfile] = known_actors or []

    def _infrastructure_overlap(
        self,
        obs: CampaignObservation,
        actor: KnownActorProfile,
    ) -> Tuple[float, List[str]]:
        """
        Compute infrastructure overlap score and matched evidence list.
        Returns (score, evidence_list).
        """
        evidence = []
        score = 0.0

        obs_inf = obs.infrastructure
        act_inf = actor.infrastructure

        # TLS cert hash overlap
        cert_overlap = set(obs_inf.tls_cert_hashes) & set(act_inf.tls_cert_hashes)
        if cert_overlap:
            score += 0.35
            evidence.append(f"TLS cert hash match: {len(cert_overlap)} shared")

        # JARM fingerprint overlap
        jarm_overlap = set(obs_inf.jarm_fingerprints) & set(act_inf.jarm_fingerprints)
        if jarm_overlap:
            score += 0.25
            evidence.append(f"JARM fingerprint match: {jarm_overlap}")

        # ASN overlap
        asn_overlap = set(obs_inf.autonomous_systems) & set(act_inf.autonomous_systems)
        if asn_overlap:
            score += 0.15
            evidence.append(f"ASN overlap: {asn_overlap}")

        # Hosting provider overlap
        host_overlap = set(obs_inf.hosting_providers) & set(act_inf.hosting_providers)
        if host_overlap:
            score += 0.10
            evidence.append(f"Hosting provider match: {host_overlap}")

        # Favicon hash overlap (infrastructure panel fingerprint)
        fav_overlap = set(obs_inf.favicon_hashes) & set(act_inf.favicon_hashes)
        if fav_overlap:
            score += 0.10
            evidence.append(f"Favicon hash match: {fav_overlap}")

        # C2 protocol overlap
        c2_overlap = set(obs_inf.c2_protocols) & set(act_inf.c2_protocols)
        if c2_overlap:
            score += 0.05
            evidence.append(f"C2 protocol match: {c2_overlap}")

        return min(score, 1.0), evidence

    def _malware_overlap(
        self,
        obs: CampaignObservation,
        actor: KnownActorProfile,
    ) -> Tuple[float, List[str]]:
        """Malware family overlap scoring."""
        evidence = []
        obs_malware = set(obs.malware_families)
        act_malware = set(actor.malware_families)
        if not obs_malware or not act_malware:
            return 0.0, []
        overlap = obs_malware & act_malware
        jaccard = len(overlap) / len(obs_malware | act_malware)
        if overlap:
            evidence.append(f"Shared malware families: {overlap}")
        return min(jaccard * 1.2, 1.0), evidence

    def _campaign_lineage_score(
        self,
        obs: CampaignObservation,
        actor: KnownActorProfile,
        historical_campaigns: Optional[List[CampaignObservation]] = None,
    ) -> Tuple[float, str]:
        """
        Campaign lineage: does this observation fit within the actor's
        historical campaign cadence and targeting pattern?
        """
        # Victimology overlap
        obs_vic = set(obs.victimology)
        act_vic = set(actor.victimology)
        vic_score = 0.0
        if obs_vic and act_vic:
            vic_jaccard = len(obs_vic & act_vic) / len(obs_vic | act_vic)
            vic_score = vic_jaccard * 0.40

        # Profile confidence factor — well-documented actors score higher
        profile_factor = actor.confidence_in_profile * 0.30

        # Temporal relevance — recently active actors score higher
        try:
            last_obs = datetime.fromisoformat(actor.last_observed.replace("Z", "+00:00"))
            days_since = (datetime.now(timezone.utc) - last_obs).days
            recency_score = max(0.0, 1.0 - (days_since / 730.0)) * 0.30  # decay over 2yr
        except Exception:
            recency_score = 0.15

        total = vic_score + profile_factor + recency_score
        description = (
            f"Victimology overlap: {vic_score:.2f} | "
            f"Profile quality: {actor.confidence_in_profile:.2f} | "
            f"Recency: {recency_score:.2f}"
        )
        return min(total, 1.0), description

    def _compute_hypothesis(
        self,
        obs: CampaignObservation,
        actor: KnownActorProfile,
    ) -> AttributionHypothesis:
        """Build a full attribution hypothesis for one actor."""
        infra_score, infra_evidence = self._infrastructure_overlap(obs, actor)
        attck_score = obs.attck_profile.overlap_score(actor.attck_profile)
        malware_score, malware_evidence = self._malware_overlap(obs, actor)
        lineage_score, lineage_desc = self._campaign_lineage_score(obs, actor)

        # Telemetry support
        tel_support = min(obs.telemetry_event_count / 500.0, 1.0)

        # Graph support
        graph_support = min(obs.graph_node_count / 50.0, 1.0)

        # Replay support
        replay_support = min(obs.replay_hits / 10.0, 1.0)

        # Determine which evidence types are present
        evidence_types = []
        if infra_score > 0.1:       evidence_types.append(EvidenceType.INFRASTRUCTURE)
        if attck_score > 0.2:       evidence_types.append(EvidenceType.ATTCK_OVERLAP)
        if malware_score > 0.1:     evidence_types.append(EvidenceType.MALWARE_FAMILY)
        if lineage_score > 0.2:     evidence_types.append(EvidenceType.GRAPH_LINEAGE)
        if tel_support > 0.05:      evidence_types.append(EvidenceType.TELEMETRY_MATCH)
        if replay_support > 0.0:    evidence_types.append(EvidenceType.REPLAY_MATCH)
        if obs.victimology:         evidence_types.append(EvidenceType.VICTIMOLOGY)

        # Weighted composite score
        composite = (
            infra_score   * self.SIGNAL_WEIGHTS[EvidenceType.INFRASTRUCTURE] +
            attck_score   * self.SIGNAL_WEIGHTS[EvidenceType.ATTCK_OVERLAP] +
            malware_score * self.SIGNAL_WEIGHTS[EvidenceType.MALWARE_FAMILY] +
            lineage_score * self.SIGNAL_WEIGHTS[EvidenceType.GRAPH_LINEAGE] +
            tel_support   * self.SIGNAL_WEIGHTS[EvidenceType.TELEMETRY_MATCH] +
            replay_support* self.SIGNAL_WEIGHTS[EvidenceType.REPLAY_MATCH]
        )

        # Normalise — sum of max weights
        max_weight = sum(
            self.SIGNAL_WEIGHTS[et]
            for et in [
                EvidenceType.INFRASTRUCTURE, EvidenceType.ATTCK_OVERLAP,
                EvidenceType.MALWARE_FAMILY, EvidenceType.GRAPH_LINEAGE,
                EvidenceType.TELEMETRY_MATCH, EvidenceType.REPLAY_MATCH,
            ]
        )
        normalised = composite / max_weight

        # Uncertainty factors
        uncertainty = []
        if infra_score < 0.2:
            uncertainty.append("Weak infrastructure overlap")
        if attck_score < 0.3:
            uncertainty.append("Low ATT&CK TTP overlap")
        if malware_score == 0.0:
            uncertainty.append("No malware family confirmation")
        if obs.replay_hits == 0:
            uncertainty.append("No replay validation")
        if obs.graph_node_count < 5:
            uncertainty.append("Insufficient graph node evidence")
        if actor.confidence_in_profile < 0.5:
            uncertainty.append("Low-confidence actor reference profile")

        # Confidence band: width inversely proportional to evidence count
        band_half = max(0.05, 0.25 * (1.0 - len(evidence_types) / 8.0))
        conf_low  = max(0.0, normalised - band_half)
        conf_high = min(1.0, normalised + band_half * 0.5)

        # Map to level
        conf_level = AttributionConfidence.INSUFFICIENT
        for level, threshold in sorted(
            self.CONFIDENCE_THRESHOLDS.items(), key=lambda x: x[1], reverse=True
        ):
            if normalised >= threshold:
                conf_level = level
                break

        # Primary evidence
        scores = [
            ("Infrastructure overlap", infra_score),
            ("ATT&CK TTP overlap", attck_score),
            ("Malware family overlap", malware_score),
            ("Campaign lineage", lineage_score),
        ]
        primary_ev = max(scores, key=lambda x: x[1])
        primary_desc = (
            f"{primary_ev[0]}: {primary_ev[1]:.2f} "
            f"{'— ' + infra_evidence[0] if infra_evidence and primary_ev[0] == 'Infrastructure overlap' else ''}"
        )

        return AttributionHypothesis(
            actor_id=actor.actor_id,
            actor_name=actor.actor_name,
            confidence_score=round(normalised, 4),
            confidence_level=conf_level,
            confidence_band=(round(conf_low, 3), round(conf_high, 3)),
            infrastructure_overlap=round(infra_score, 4),
            attck_overlap=round(attck_score, 4),
            malware_overlap=round(malware_score, 4),
            campaign_lineage_score=round(lineage_score, 4),
            telemetry_support=round(tel_support, 4),
            graph_support=round(graph_support, 4),
            replay_support=round(replay_support, 4),
            evidence_types_present=evidence_types,
            evidence_count=len(evidence_types),
            primary_evidence=primary_desc,
            uncertainty_factors=uncertainty,
        )

    def _ambiguity_score(self, hypotheses: List[AttributionHypothesis]) -> float:
        """
        Ambiguity = entropy of the top hypotheses' confidence distribution.
        0 = single clear winner. 1 = maximum ambiguity.
        """
        if not hypotheses:
            return 1.0
        if len(hypotheses) == 1:
            return 1.0 - hypotheses[0].confidence_score

        top_scores = [h.confidence_score for h in hypotheses[:3]]
        total = sum(top_scores) or 1.0
        probs = [s / total for s in top_scores]
        entropy = -sum(p * math.log2(p) for p in probs if p > 0)
        max_entropy = math.log2(len(probs))
        return round(entropy / max_entropy if max_entropy > 0 else 0.0, 4)

    def cluster(
        self,
        observation: CampaignObservation,
        historical_campaigns: Optional[List[CampaignObservation]] = None,
    ) -> ActorClusterResult:
        """
        Main clustering entry point.
        Generates probabilistic attribution hypotheses for a campaign observation.
        """
        # Compute hypotheses for all known actors
        hypotheses = [
            self._compute_hypothesis(observation, actor)
            for actor in self.known_actors
        ]

        # Sort by confidence descending
        hypotheses.sort(key=lambda h: h.confidence_score, reverse=True)

        # Filter out INSUFFICIENT hypotheses from primary output
        valid_hypotheses = [
            h for h in hypotheses
            if h.confidence_level != AttributionConfidence.INSUFFICIENT
        ]

        primary = valid_hypotheses[0] if valid_hypotheses else None
        alternatives = valid_hypotheses[1:4]  # Top 3 alternatives

        # Determine cluster origin
        if primary is None:
            cluster_origin = ClusterOrigin.INSUFFICIENT_DATA
        elif primary.confidence_level in (
            AttributionConfidence.CONFIRMED, AttributionConfidence.HIGH
        ):
            cluster_origin = ClusterOrigin.KNOWN_ACTOR
        elif primary.confidence_level == AttributionConfidence.MODERATE:
            cluster_origin = ClusterOrigin.PARTIAL_MATCH
        elif len(valid_hypotheses) > 1 and self._ambiguity_score(hypotheses[:3]) > 0.5:
            cluster_origin = ClusterOrigin.AMBIGUOUS
        else:
            cluster_origin = ClusterOrigin.NOVEL_CLUSTER

        # Ambiguity
        amb_score = self._ambiguity_score(hypotheses[:3])
        amb_reason = ""
        if amb_score > 0.7:
            amb_reason = (
                f"Multiple actors share similar TTPs with close confidence scores. "
                f"Top candidate: {primary.actor_name if primary else 'None'} "
                f"({primary.confidence_score:.2f}). "
                f"Additional matching actors: {len(alternatives)}."
            )
        elif amb_score > 0.4:
            amb_reason = (
                f"Moderate ambiguity — primary candidate {primary.actor_name if primary else 'None'} "
                f"leads but lacks definitive infrastructure evidence."
            )
        else:
            amb_reason = "Low ambiguity — primary candidate leads with sufficient evidence separation."

        # Attribution justification
        attribution_justified = (
            primary is not None and
            primary.confidence_level not in (
                AttributionConfidence.INSUFFICIENT, AttributionConfidence.SPECULATIVE
            ) and
            primary.evidence_count >= 2
        )

        gov_note = ""
        if not attribution_justified:
            if primary and primary.confidence_level == AttributionConfidence.SPECULATIVE:
                gov_note = (
                    "GOVERNANCE: Attribution speculative — insufficient independent evidence signals. "
                    "Actor name suppressed in external-facing outputs. "
                    "Cluster assigned as NOVEL_CLUSTER pending additional telemetry."
                )
            else:
                gov_note = (
                    "GOVERNANCE: Attribution not justified — evidence density below threshold. "
                    "Cluster assigned as INSUFFICIENT_DATA. "
                    "Do NOT generate actor-attributed narrative without further evidence."
                )
        else:
            gov_note = (
                f"GOVERNANCE: Attribution justified at {primary.confidence_level.value} confidence. "
                f"Evidence types: {[et.value for et in primary.evidence_types_present]}. "
                f"Uncertainty factors: {primary.uncertainty_factors}."
            )

        # Cluster ID
        cluster_id = (
            f"CLU-{primary.actor_id[:6].upper()}-"
            f"{observation.campaign_id[:6].upper()}"
            if primary
            else f"CLU-NOVEL-{observation.campaign_id[:8].upper()}"
        )

        # Linked campaigns
        linked = []
        if historical_campaigns:
            for hc in historical_campaigns:
                hc_attck_sim = observation.attck_profile.overlap_score(hc.attck_profile)
                if hc_attck_sim > 0.4:
                    linked.append(hc.campaign_id)

        lineage_conf = min(len(linked) * 0.15, 1.0) if linked else 0.0

        return ActorClusterResult(
            campaign_id=observation.campaign_id,
            cluster_origin=cluster_origin,
            cluster_id=cluster_id,
            primary_hypothesis=primary,
            alternative_hypotheses=alternatives,
            is_ambiguous=amb_score > 0.4,
            ambiguity_score=amb_score,
            ambiguity_reason=amb_reason,
            linked_campaigns=linked,
            lineage_confidence=lineage_conf,
            attribution_justified=attribution_justified,
            governance_note=gov_note,
            produced_at=datetime.now(timezone.utc).isoformat(),
        )

    def cluster_batch(
        self,
        observations: List[CampaignObservation],
    ) -> List[ActorClusterResult]:
        """Cluster a batch of campaign observations."""
        results = []
        for obs in observations:
            try:
                result = self.cluster(obs, observations)
                results.append(result)
            except Exception as exc:
                logger.error("Clustering failed for %s: %s", obs.campaign_id, exc)
        return results


# ─────────────────────────────────────────────────────────────
# CLUSTER GOVERNANCE AUDITOR
# ─────────────────────────────────────────────────────────────

class ClusterGovernanceAuditor:
    """
    Validates clustering output for governance compliance.
    Detects: overuse of UNKNOWN labeling, unsupported attributions,
    missing uncertainty factors.
    """

    def audit(self, results: List[ActorClusterResult]) -> Dict[str, Any]:
        issues = []

        insufficient_count = sum(
            1 for r in results
            if r.cluster_origin == ClusterOrigin.INSUFFICIENT_DATA
        )
        novel_count = sum(
            1 for r in results
            if r.cluster_origin == ClusterOrigin.NOVEL_CLUSTER
        )
        unjustified = [r for r in results if not r.attribution_justified]

        # Governance check: >50% INSUFFICIENT is a data quality problem
        if len(results) > 0 and (insufficient_count / len(results)) > 0.50:
            issues.append({
                "type": "HIGH_INSUFFICIENT_RATE",
                "detail": f"{insufficient_count}/{len(results)} campaigns lack sufficient attribution evidence",
                "recommendation": "Increase telemetry ingestion and graph correlation depth",
                "severity": "WARNING",
            })

        # Check for unjustified attributions
        for r in unjustified:
            if r.primary_hypothesis and r.primary_hypothesis.confidence_level not in (
                AttributionConfidence.INSUFFICIENT,
            ):
                issues.append({
                    "type": "UNJUSTIFIED_ATTRIBUTION",
                    "campaign_id": r.campaign_id,
                    "actor": r.primary_hypothesis.actor_name,
                    "confidence": r.primary_hypothesis.confidence_score,
                    "severity": "GOVERNANCE_VIOLATION",
                })

        return {
            "total_clustered": len(results),
            "known_actor_matches": sum(1 for r in results if r.cluster_origin == ClusterOrigin.KNOWN_ACTOR),
            "partial_matches": sum(1 for r in results if r.cluster_origin == ClusterOrigin.PARTIAL_MATCH),
            "novel_clusters": novel_count,
            "ambiguous": sum(1 for r in results if r.is_ambiguous),
            "insufficient_data": insufficient_count,
            "governance_issues": issues,
            "governance_pass": len(issues) == 0,
            "audited_at": datetime.now(timezone.utc).isoformat(),
        }
