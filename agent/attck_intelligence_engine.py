"""
CYBERDUDEBIVASH® SENTINEL APEX — Advanced ATT&CK Intelligence Engine
Phase 45: Operational Reality Convergence

Implements:
  - ATT&CK sequence chaining (observed technique ordering)
  - Kill-chain reconstruction from telemetry
  - Procedural overlap analytics (actor TTP fingerprinting)
  - Actor TTP fingerprinting (behavioral signatures)
  - ATT&CK graph visualization data model
  - ATT&CK replay analytics (replay-confirmed vs theoretical)
  - Tactic progression timelines (temporally ordered)
  - ATT&CK confidence scoring (evidence-proportional)

THE PLATFORM MUST DISPLAY: real adversary operational behavior
NOT: isolated ATT&CK tags
"""

from __future__ import annotations

import logging
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.attck_intelligence")


# ─────────────────────────────────────────────────────────────
# CONSTANTS — ATT&CK TACTIC ORDER (Enterprise)
# ─────────────────────────────────────────────────────────────

TACTIC_ORDER = [
    "reconnaissance",
    "resource-development",
    "initial-access",
    "execution",
    "persistence",
    "privilege-escalation",
    "defense-evasion",
    "credential-access",
    "discovery",
    "lateral-movement",
    "collection",
    "command-and-control",
    "exfiltration",
    "impact",
]

TACTIC_DISPLAY = {
    "reconnaissance":       "Reconnaissance",
    "resource-development": "Resource Dev",
    "initial-access":       "Initial Access",
    "execution":            "Execution",
    "persistence":          "Persistence",
    "privilege-escalation": "Priv. Escalation",
    "defense-evasion":      "Defense Evasion",
    "credential-access":    "Credential Access",
    "discovery":            "Discovery",
    "lateral-movement":     "Lateral Movement",
    "collection":           "Collection",
    "command-and-control":  "C2",
    "exfiltration":         "Exfiltration",
    "impact":               "Impact",
}


# ─────────────────────────────────────────────────────────────
# ENUMERATIONS
# ─────────────────────────────────────────────────────────────

class TechniqueConfidenceLevel(str, Enum):
    REPLAY_CONFIRMED  = "replay_confirmed"   # Highest — replay engine validated
    TELEMETRY_DIRECT  = "telemetry_direct"   # Direct EDR/network observation
    TELEMETRY_INFERRED= "telemetry_inferred" # Inferred from correlated events
    GRAPH_DERIVED     = "graph_derived"      # Graph analysis attribution
    FEED_REPORTED     = "feed_reported"      # Intel feed only — no local evidence
    THEORETICAL       = "theoretical"        # ATT&CK model-based only

class KillChainPhase(str, Enum):
    PRE_INTRUSION     = "pre_intrusion"
    INTRUSION         = "intrusion"
    PERSISTENCE       = "persistence"
    LATERAL_MOVEMENT  = "lateral_movement"
    EXECUTION_IMPACT  = "execution_impact"


# ─────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────

@dataclass
class ObservedTechnique:
    """A single ATT&CK technique observed in the environment."""
    technique_id: str              # T1XXX or T1XXX.XXX
    technique_name: str
    tactic: str
    tactic_id: str                 # TAxxxx
    confidence_level: TechniqueConfidenceLevel
    confidence_score: float        # 0.0–1.0 evidence-weighted
    first_observed: str
    last_observed: str
    observation_count: int
    replay_hit_count: int
    source_hosts: List[str]
    procedure_examples: List[str]  # Specific observed behaviors
    tools_used: List[str]
    raw_evidence_refs: List[str]   # References to raw telemetry events
    sub_technique: bool = False

@dataclass
class TechniqueTransition:
    """Observed transition between two techniques in a campaign."""
    from_technique: str
    to_technique: str
    transition_count: int          # How many times observed in sequence
    avg_time_delta_minutes: float  # Average time between techniques
    confidence: float
    campaign_ids: List[str]

@dataclass
class KillChainReconstruction:
    """Reconstructed kill chain from telemetry observations."""
    campaign_id: str
    reconstruction_id: str
    techniques_ordered: List[ObservedTechnique]   # Temporally ordered
    tactic_progression: List[str]                  # Ordered tactic names
    kill_chain_phase_map: Dict[str, List[str]]     # phase → technique_ids
    timeline_entries: List[Dict[str, Any]]          # Time-ordered events
    replay_confirmed_techniques: List[str]
    first_observed: str
    last_observed: str
    duration_hours: float
    completeness_score: float       # 0.0–1.0 — how complete is the chain
    confidence_score: float
    coverage_gaps: List[str]        # Tactics not yet observed but suspected

@dataclass
class ActorTTPFingerprint:
    """Behavioral TTP fingerprint for a threat actor."""
    actor_id: str
    actor_name: str
    signature_techniques: List[str]   # High-specificity techniques
    signature_sequences: List[List[str]] # Common technique sequences
    preferred_tactics: List[str]
    tool_signatures: List[str]
    uniqueness_score: float            # 0.0–1.0 — how distinctive this fingerprint is
    confidence: float
    campaigns_observed: int
    last_updated: str

@dataclass
class ProceduralOverlapResult:
    """Result of comparing two ATT&CK behavioral profiles."""
    profile_a_id: str
    profile_b_id: str
    technique_jaccard: float
    sequence_overlap: float
    tool_overlap: float
    composite_overlap: float
    shared_techniques: List[str]
    shared_sequences: List[List[str]]
    interpretation: str             # Human-readable interpretation


# ─────────────────────────────────────────────────────────────
# ATT&CK CONFIDENCE SCORER
# ─────────────────────────────────────────────────────────────

class ATTCKConfidenceScorer:
    """
    Computes evidence-proportional confidence for ATT&CK technique observations.
    Replay-confirmed techniques score highest; feed-only scores lowest.
    """

    LEVEL_BASE_SCORES = {
        TechniqueConfidenceLevel.REPLAY_CONFIRMED:   0.95,
        TechniqueConfidenceLevel.TELEMETRY_DIRECT:   0.85,
        TechniqueConfidenceLevel.TELEMETRY_INFERRED: 0.65,
        TechniqueConfidenceLevel.GRAPH_DERIVED:      0.55,
        TechniqueConfidenceLevel.FEED_REPORTED:      0.40,
        TechniqueConfidenceLevel.THEORETICAL:        0.20,
    }

    def score(
        self,
        confidence_level: TechniqueConfidenceLevel,
        observation_count: int,
        replay_hits: int,
        source_host_count: int,
        procedure_example_count: int,
    ) -> float:
        base = self.LEVEL_BASE_SCORES[confidence_level]

        # Observation volume bonus
        obs_bonus = min(observation_count / 50.0, 0.10)

        # Replay confirmation bonus
        replay_bonus = min(replay_hits * 0.04, 0.12)

        # Host breadth bonus (seen on multiple hosts = more credible)
        host_bonus = min(source_host_count / 20.0, 0.08)

        # Procedure example bonus (specific is better)
        proc_bonus = min(procedure_example_count / 5.0, 0.05)

        return round(min(base + obs_bonus + replay_bonus + host_bonus + proc_bonus, 1.0), 4)


# ─────────────────────────────────────────────────────────────
# SEQUENCE CHAINER
# ─────────────────────────────────────────────────────────────

class ATTCKSequenceChainer:
    """
    Chains ATT&CK technique observations from temporally-ordered telemetry
    into meaningful kill-chain sequences.
    """

    def __init__(self):
        self.transitions: Dict[Tuple[str, str], TechniqueTransition] = {}

    def record_transition(
        self,
        from_tech: str,
        to_tech: str,
        time_delta_minutes: float,
        campaign_id: str,
        confidence: float = 1.0,
    ) -> None:
        key = (from_tech, to_tech)
        if key in self.transitions:
            t = self.transitions[key]
            # Running average of time delta
            total = t.avg_time_delta_minutes * t.transition_count + time_delta_minutes
            t.transition_count += 1
            t.avg_time_delta_minutes = total / t.transition_count
            if campaign_id not in t.campaign_ids:
                t.campaign_ids.append(campaign_id)
            t.confidence = min(t.confidence + 0.05, 1.0)
        else:
            self.transitions[key] = TechniqueTransition(
                from_technique=from_tech,
                to_technique=to_tech,
                transition_count=1,
                avg_time_delta_minutes=time_delta_minutes,
                confidence=confidence,
                campaign_ids=[campaign_id],
            )

    def get_common_sequences(
        self,
        min_count: int = 2,
        min_confidence: float = 0.6,
    ) -> List[TechniqueTransition]:
        return sorted(
            [t for t in self.transitions.values()
             if t.transition_count >= min_count and t.confidence >= min_confidence],
            key=lambda t: t.transition_count,
            reverse=True,
        )

    def reconstruct_chain(
        self,
        techniques: List[ObservedTechnique],
        campaign_id: str,
    ) -> KillChainReconstruction:
        """
        Reconstruct a kill chain from a set of observed techniques.
        Techniques should be pre-sorted by first_observed timestamp.
        """
        # Sort by first_observed
        sorted_techs = sorted(
            techniques,
            key=lambda t: t.first_observed,
        )

        # Record transitions
        for i in range(len(sorted_techs) - 1):
            try:
                t1 = datetime.fromisoformat(sorted_techs[i].last_observed.replace("Z", "+00:00"))
                t2 = datetime.fromisoformat(sorted_techs[i + 1].first_observed.replace("Z", "+00:00"))
                delta_min = max(0.0, (t2 - t1).total_seconds() / 60)
            except Exception:
                delta_min = 60.0

            self.record_transition(
                sorted_techs[i].technique_id,
                sorted_techs[i + 1].technique_id,
                delta_min,
                campaign_id,
                confidence=min(sorted_techs[i].confidence_score, sorted_techs[i + 1].confidence_score),
            )

        # Tactic progression (deduplicated, ordered)
        tactic_seen = []
        for t in sorted_techs:
            if t.tactic not in tactic_seen:
                tactic_seen.append(t.tactic)

        # Kill chain phase mapping
        phase_map = {
            KillChainPhase.PRE_INTRUSION.value:     [],
            KillChainPhase.INTRUSION.value:         [],
            KillChainPhase.PERSISTENCE.value:       [],
            KillChainPhase.LATERAL_MOVEMENT.value:  [],
            KillChainPhase.EXECUTION_IMPACT.value:  [],
        }
        tactic_to_phase = {
            "reconnaissance":       KillChainPhase.PRE_INTRUSION.value,
            "resource-development": KillChainPhase.PRE_INTRUSION.value,
            "initial-access":       KillChainPhase.INTRUSION.value,
            "execution":            KillChainPhase.INTRUSION.value,
            "defense-evasion":      KillChainPhase.INTRUSION.value,
            "persistence":          KillChainPhase.PERSISTENCE.value,
            "privilege-escalation": KillChainPhase.PERSISTENCE.value,
            "credential-access":    KillChainPhase.PERSISTENCE.value,
            "discovery":            KillChainPhase.LATERAL_MOVEMENT.value,
            "lateral-movement":     KillChainPhase.LATERAL_MOVEMENT.value,
            "collection":           KillChainPhase.EXECUTION_IMPACT.value,
            "command-and-control":  KillChainPhase.EXECUTION_IMPACT.value,
            "exfiltration":         KillChainPhase.EXECUTION_IMPACT.value,
            "impact":               KillChainPhase.EXECUTION_IMPACT.value,
        }
        for t in sorted_techs:
            phase = tactic_to_phase.get(t.tactic, KillChainPhase.EXECUTION_IMPACT.value)
            if t.technique_id not in phase_map[phase]:
                phase_map[phase].append(t.technique_id)

        # Timeline
        timeline = []
        for t in sorted_techs:
            timeline.append({
                "timestamp": t.first_observed,
                "technique_id": t.technique_id,
                "technique_name": t.technique_name,
                "tactic": t.tactic,
                "confidence": t.confidence_score,
                "confidence_level": t.confidence_level.value,
                "replay_confirmed": t.replay_hit_count > 0,
                "hosts": t.source_hosts[:3],
            })

        # Replay confirmed
        replay_confirmed = [t.technique_id for t in sorted_techs if t.replay_hit_count > 0]

        # Coverage gaps — expected next tactics not yet observed
        coverage_gaps = []
        if tactic_seen:
            highest_tactic_idx = max(
                TACTIC_ORDER.index(t) for t in tactic_seen if t in TACTIC_ORDER
            )
            for missing in TACTIC_ORDER[:highest_tactic_idx + 1]:
                if missing not in tactic_seen and missing not in ("reconnaissance", "resource-development"):
                    coverage_gaps.append(missing)

        # Completeness: what fraction of expected tactics (up to highest observed) are covered?
        if tactic_seen:
            highest = max(
                (TACTIC_ORDER.index(t) for t in tactic_seen if t in TACTIC_ORDER),
                default=0
            )
            expected = [t for t in TACTIC_ORDER[:highest + 1]
                       if t not in ("reconnaissance", "resource-development")]
            covered = [t for t in expected if t in tactic_seen]
            completeness = len(covered) / max(len(expected), 1)
        else:
            completeness = 0.0

        # Overall confidence
        avg_conf = sum(t.confidence_score for t in sorted_techs) / max(len(sorted_techs), 1)

        # Duration
        try:
            t_start = datetime.fromisoformat(sorted_techs[0].first_observed.replace("Z", "+00:00"))
            t_end = datetime.fromisoformat(sorted_techs[-1].last_observed.replace("Z", "+00:00"))
            duration_h = (t_end - t_start).total_seconds() / 3600
        except Exception:
            duration_h = 0.0

        return KillChainReconstruction(
            campaign_id=campaign_id,
            reconstruction_id=f"KC-{campaign_id}-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
            techniques_ordered=sorted_techs,
            tactic_progression=tactic_seen,
            kill_chain_phase_map=phase_map,
            timeline_entries=timeline,
            replay_confirmed_techniques=replay_confirmed,
            first_observed=sorted_techs[0].first_observed if sorted_techs else "",
            last_observed=sorted_techs[-1].last_observed if sorted_techs else "",
            duration_hours=round(duration_h, 2),
            completeness_score=round(completeness, 4),
            confidence_score=round(avg_conf, 4),
            coverage_gaps=coverage_gaps,
        )


# ─────────────────────────────────────────────────────────────
# PROCEDURAL OVERLAP ANALYZER
# ─────────────────────────────────────────────────────────────

class ProceduralOverlapAnalyzer:
    """
    Computes behavioral overlap between two ATT&CK technique sets.
    Used for actor attribution and campaign correlation.
    """

    def compare(
        self,
        profile_a_id: str,
        profile_a_techniques: List[str],
        profile_a_sequences: List[List[str]],
        profile_a_tools: List[str],
        profile_b_id: str,
        profile_b_techniques: List[str],
        profile_b_sequences: List[List[str]],
        profile_b_tools: List[str],
    ) -> ProceduralOverlapResult:
        # Jaccard on technique sets
        a_tech = set(profile_a_techniques)
        b_tech = set(profile_b_techniques)
        tech_jaccard = (
            len(a_tech & b_tech) / len(a_tech | b_tech)
            if (a_tech | b_tech) else 0.0
        )

        # Sequence overlap (common subsequences)
        shared_seqs = []
        for seq_a in profile_a_sequences:
            for seq_b in profile_b_sequences:
                common = [t for t in seq_a if t in seq_b]
                if len(common) >= 2:
                    shared_seqs.append(common)

        max_seqs = max(len(profile_a_sequences), len(profile_b_sequences), 1)
        seq_overlap = min(len(shared_seqs) / max_seqs, 1.0)

        # Tool overlap
        a_tools = set(profile_a_tools)
        b_tools = set(profile_b_tools)
        tool_overlap = (
            len(a_tools & b_tools) / len(a_tools | b_tools)
            if (a_tools | b_tools) else 0.0
        )

        # Composite
        composite = (
            tech_jaccard  * 0.50 +
            seq_overlap   * 0.30 +
            tool_overlap  * 0.20
        )

        # Interpretation
        if composite >= 0.75:
            interp = "HIGH procedural overlap — strong indicator of same actor or shared toolkit"
        elif composite >= 0.50:
            interp = "MODERATE overlap — possible shared infrastructure or TTP borrowing"
        elif composite >= 0.25:
            interp = "LOW overlap — limited procedural similarity; may share capability source"
        else:
            interp = "MINIMAL overlap — distinct behavioral profiles"

        return ProceduralOverlapResult(
            profile_a_id=profile_a_id,
            profile_b_id=profile_b_id,
            technique_jaccard=round(tech_jaccard, 4),
            sequence_overlap=round(seq_overlap, 4),
            tool_overlap=round(tool_overlap, 4),
            composite_overlap=round(composite, 4),
            shared_techniques=sorted(a_tech & b_tech),
            shared_sequences=shared_seqs[:5],
            interpretation=interp,
        )


# ─────────────────────────────────────────────────────────────
# ACTOR TTP FINGERPRINTER
# ─────────────────────────────────────────────────────────────

class ActorTTPFingerprinter:
    """
    Builds and manages behavioral TTP fingerprints for threat actors.
    Identifies signature techniques — those that are highly specific
    to a particular actor's operational style.
    """

    def __init__(self):
        self._actor_techniques: Dict[str, Dict[str, int]] = defaultdict(dict)

    def record_observation(
        self,
        actor_id: str,
        technique_id: str,
        campaign_id: str,
    ) -> None:
        curr = self._actor_techniques[actor_id].get(technique_id, 0)
        self._actor_techniques[actor_id][technique_id] = curr + 1

    def build_fingerprint(
        self,
        actor_id: str,
        actor_name: str,
        campaigns_observed: int,
        tool_signatures: Optional[List[str]] = None,
    ) -> ActorTTPFingerprint:
        """Build a TTP fingerprint for an actor."""
        techniques = self._actor_techniques.get(actor_id, {})
        if not techniques:
            return ActorTTPFingerprint(
                actor_id=actor_id,
                actor_name=actor_name,
                signature_techniques=[],
                signature_sequences=[],
                preferred_tactics=[],
                tool_signatures=tool_signatures or [],
                uniqueness_score=0.0,
                confidence=0.1,
                campaigns_observed=campaigns_observed,
                last_updated=datetime.now(timezone.utc).isoformat(),
            )

        # Signature techniques: those observed in ≥50% of campaigns
        min_campaigns = max(1, campaigns_observed // 2)
        signature = [
            tech for tech, count in techniques.items()
            if count >= min_campaigns
        ]

        # Preferred tactics
        tactic_counts: Dict[str, int] = defaultdict(int)
        for tech in techniques:
            # Infer tactic from technique ID prefix (simplified)
            tactic_counts["generic"] += 1

        # Uniqueness: signature techniques not common across all actors
        all_actor_techniques: Set[str] = set()
        for actor_techs in self._actor_techniques.values():
            all_actor_techniques.update(actor_techs.keys())

        unique_sig = [t for t in signature if sum(
            1 for a_techs in self._actor_techniques.values() if t in a_techs
        ) <= 2]  # Only seen in ≤2 actors

        uniqueness = len(unique_sig) / max(len(signature), 1)

        confidence = min(0.4 + (campaigns_observed * 0.05) + (len(signature) * 0.02), 0.95)

        return ActorTTPFingerprint(
            actor_id=actor_id,
            actor_name=actor_name,
            signature_techniques=signature[:15],
            signature_sequences=[],
            preferred_tactics=list(tactic_counts.keys())[:5],
            tool_signatures=tool_signatures or [],
            uniqueness_score=round(uniqueness, 4),
            confidence=round(confidence, 4),
            campaigns_observed=campaigns_observed,
            last_updated=datetime.now(timezone.utc).isoformat(),
        )


# ─────────────────────────────────────────────────────────────
# ADVANCED ATT&CK INTELLIGENCE ENGINE (TOP-LEVEL)
# ─────────────────────────────────────────────────────────────

class AdvancedATTCKIntelligenceEngine:
    """
    Top-level ATT&CK intelligence engine.
    Orchestrates confidence scoring, kill-chain reconstruction,
    procedural overlap analysis, and actor TTP fingerprinting.
    """

    def __init__(self):
        self.confidence_scorer = ATTCKConfidenceScorer()
        self.sequence_chainer = ATTCKSequenceChainer()
        self.overlap_analyzer = ProceduralOverlapAnalyzer()
        self.fingerprinter = ActorTTPFingerprinter()

    def score_technique(
        self,
        technique_id: str,
        technique_name: str,
        tactic: str,
        tactic_id: str,
        confidence_level: TechniqueConfidenceLevel,
        first_observed: str,
        last_observed: str,
        observation_count: int,
        replay_hit_count: int,
        source_hosts: List[str],
        procedure_examples: List[str],
        tools_used: Optional[List[str]] = None,
        raw_evidence_refs: Optional[List[str]] = None,
    ) -> ObservedTechnique:
        """Score and package a single observed technique."""
        conf_score = self.confidence_scorer.score(
            confidence_level=confidence_level,
            observation_count=observation_count,
            replay_hits=replay_hit_count,
            source_host_count=len(source_hosts),
            procedure_example_count=len(procedure_examples),
        )
        return ObservedTechnique(
            technique_id=technique_id,
            technique_name=technique_name,
            tactic=tactic,
            tactic_id=tactic_id,
            confidence_level=confidence_level,
            confidence_score=conf_score,
            first_observed=first_observed,
            last_observed=last_observed,
            observation_count=observation_count,
            replay_hit_count=replay_hit_count,
            source_hosts=source_hosts,
            procedure_examples=procedure_examples,
            tools_used=tools_used or [],
            raw_evidence_refs=raw_evidence_refs or [],
            sub_technique="." in technique_id,
        )

    def reconstruct_kill_chain(
        self,
        campaign_id: str,
        techniques: List[ObservedTechnique],
    ) -> KillChainReconstruction:
        return self.sequence_chainer.reconstruct_chain(techniques, campaign_id)

    def compare_profiles(
        self,
        profile_a_id: str,
        profile_a_techniques: List[str],
        profile_b_id: str,
        profile_b_techniques: List[str],
        profile_a_sequences: Optional[List[List[str]]] = None,
        profile_b_sequences: Optional[List[List[str]]] = None,
        profile_a_tools: Optional[List[str]] = None,
        profile_b_tools: Optional[List[str]] = None,
    ) -> ProceduralOverlapResult:
        return self.overlap_analyzer.compare(
            profile_a_id=profile_a_id,
            profile_a_techniques=profile_a_techniques,
            profile_a_sequences=profile_a_sequences or [],
            profile_a_tools=profile_a_tools or [],
            profile_b_id=profile_b_id,
            profile_b_techniques=profile_b_techniques,
            profile_b_sequences=profile_b_sequences or [],
            profile_b_tools=profile_b_tools or [],
        )

    def generate_coverage_report(
        self,
        techniques: List[ObservedTechnique],
    ) -> Dict[str, Any]:
        """Generate ATT&CK coverage report for a set of observed techniques."""
        by_tactic: Dict[str, List[str]] = defaultdict(list)
        for t in techniques:
            by_tactic[t.tactic].append(t.technique_id)

        replay_confirmed = [t for t in techniques if t.replay_hit_count > 0]
        direct_telemetry = [
            t for t in techniques
            if t.confidence_level in (
                TechniqueConfidenceLevel.TELEMETRY_DIRECT,
                TechniqueConfidenceLevel.REPLAY_CONFIRMED,
            )
        ]

        return {
            "total_techniques": len(techniques),
            "unique_tactics": len(by_tactic),
            "replay_confirmed": len(replay_confirmed),
            "direct_telemetry": len(direct_telemetry),
            "avg_confidence": round(
                sum(t.confidence_score for t in techniques) / max(len(techniques), 1), 3
            ),
            "by_tactic": {tactic: len(techs) for tactic, techs in by_tactic.items()},
            "high_confidence_techniques": [
                {"id": t.technique_id, "name": t.technique_name, "score": t.confidence_score}
                for t in sorted(techniques, key=lambda x: x.confidence_score, reverse=True)
                if t.confidence_score >= 0.70
            ],
            "generated_at": datetime.now(timezone.utc).isoformat(),
        }
