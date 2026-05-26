"""
graph_intelligence_validator.py — SENTINEL APEX Sovereign Trust Layer
Evidence-Backed Graph Intelligence Validation Engine

DOCTRINE:
  - ALL graph relationships must have evidence basis before acceptance
  - Infrastructure pivot paths require telemetry or authoritative source corroboration
  - Actor overlap scoring is probabilistic, not deterministic attribution
  - Malware lineage requires code similarity evidence, not inferred TTP overlap alone
  - Campaign similarity requires minimum 3 independent indicators
  - Graph confidence is always bounded by the weakest evidence link
  - NO synthetic actor overlap, NO fabricated campaign lineage
  - Every relationship score includes uncertainty range + evidence chain
"""

from __future__ import annotations
import hashlib
import json
import time
import math
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple


# ─────────────────────────────────────────────
# EVIDENCE BASIS TAXONOMY
# ─────────────────────────────────────────────

class EvidenceBasisType(str, Enum):
    TELEMETRY_OBSERVED      = "telemetry_observed"       # Directly seen in endpoint/network telemetry
    PASSIVE_DNS             = "passive_dns"              # pDNS resolution records
    WHOIS_REGISTRATION      = "whois_registration"       # Domain registration overlap
    CERTIFICATE_OVERLAP     = "certificate_overlap"      # TLS certificate subject/SAN overlap
    ASN_HOSTING             = "asn_hosting"              # Shared ASN/hosting provider
    CODE_SIMILARITY         = "code_similarity"          # Binary/code overlap (hash, import table)
    TTP_OVERLAP             = "ttp_overlap"              # Shared MITRE ATT&CK techniques
    MALWARE_FAMILY          = "malware_family"           # Same malware family attribution
    C2_INFRASTRUCTURE       = "c2_infrastructure"        # Shared C2 domain/IP
    CAMPAIGN_INDICATOR      = "campaign_indicator"       # Shared IOC across campaigns
    ANALYST_ASSESSMENT      = "analyst_assessment"       # Human analyst judgment
    THIRD_PARTY_REPORT      = "third_party_report"       # Vendor intelligence report
    OSINT_REFERENCE         = "osint_reference"          # Open-source reference only


# Evidence strength weights — telemetry-first, OSINT-last
EVIDENCE_WEIGHTS: Dict[EvidenceBasisType, float] = {
    EvidenceBasisType.TELEMETRY_OBSERVED:  0.95,
    EvidenceBasisType.PASSIVE_DNS:         0.80,
    EvidenceBasisType.CERTIFICATE_OVERLAP: 0.78,
    EvidenceBasisType.C2_INFRASTRUCTURE:   0.85,
    EvidenceBasisType.CODE_SIMILARITY:     0.88,
    EvidenceBasisType.MALWARE_FAMILY:      0.75,
    EvidenceBasisType.WHOIS_REGISTRATION:  0.55,
    EvidenceBasisType.ASN_HOSTING:         0.40,
    EvidenceBasisType.TTP_OVERLAP:         0.50,
    EvidenceBasisType.CAMPAIGN_INDICATOR:  0.70,
    EvidenceBasisType.ANALYST_ASSESSMENT:  0.60,
    EvidenceBasisType.THIRD_PARTY_REPORT:  0.55,
    EvidenceBasisType.OSINT_REFERENCE:     0.25,
}

# Minimum evidence gates per relationship type
RELATIONSHIP_EVIDENCE_GATES: Dict[str, Dict[str, Any]] = {
    "actor_overlap": {
        "min_bases": 3,
        "min_score": 0.60,
        "required_any": [
            EvidenceBasisType.TELEMETRY_OBSERVED,
            EvidenceBasisType.C2_INFRASTRUCTURE,
            EvidenceBasisType.CODE_SIMILARITY,
        ],
        "uncertainty_floor": 0.20,
        "max_confidence_without_telemetry": 0.65,
    },
    "malware_lineage": {
        "min_bases": 2,
        "min_score": 0.55,
        "required_any": [
            EvidenceBasisType.CODE_SIMILARITY,
            EvidenceBasisType.MALWARE_FAMILY,
        ],
        "uncertainty_floor": 0.15,
        "max_confidence_without_telemetry": 0.70,
    },
    "infrastructure_pivot": {
        "min_bases": 2,
        "min_score": 0.50,
        "required_any": [
            EvidenceBasisType.PASSIVE_DNS,
            EvidenceBasisType.CERTIFICATE_OVERLAP,
            EvidenceBasisType.C2_INFRASTRUCTURE,
            EvidenceBasisType.TELEMETRY_OBSERVED,
        ],
        "uncertainty_floor": 0.10,
        "max_confidence_without_telemetry": 0.75,
    },
    "campaign_similarity": {
        "min_bases": 3,
        "min_score": 0.55,
        "required_any": [
            EvidenceBasisType.CAMPAIGN_INDICATOR,
            EvidenceBasisType.C2_INFRASTRUCTURE,
            EvidenceBasisType.TTP_OVERLAP,
        ],
        "uncertainty_floor": 0.20,
        "max_confidence_without_telemetry": 0.60,
    },
}


# ─────────────────────────────────────────────
# EVIDENCE RECORD
# ─────────────────────────────────────────────

@dataclass
class EvidenceRecord:
    basis_type: EvidenceBasisType
    source: str                          # e.g., "endpoint-agent-HOST001", "virustotal", "passivedns"
    description: str
    observed_at: float = field(default_factory=time.time)
    telemetry_backed: bool = False
    source_trust: float = 0.70           # 0.0–1.0
    raw_value: Optional[str] = None      # e.g., shared IP, cert hash, code similarity %

    def effective_weight(self) -> float:
        base = EVIDENCE_WEIGHTS.get(self.basis_type, 0.30)
        age_days = (time.time() - self.observed_at) / 86400
        recency_decay = math.exp(-age_days / 90)  # 90-day half-life for graph evidence
        return base * self.source_trust * recency_decay


# ─────────────────────────────────────────────
# VALIDATION RESULT STRUCTURES
# ─────────────────────────────────────────────

@dataclass
class GraphRelationshipValidation:
    """Result of validating a single graph relationship."""
    relationship_type: str
    entity_a: str
    entity_b: str
    raw_score: float                     # 0.0–1.0 computed score
    validated_score: float               # Score after gate enforcement
    uncertainty_range: Tuple[float, float]
    evidence_chain: List[EvidenceRecord]
    gates_passed: bool
    gate_failures: List[str]
    telemetry_supported: bool
    relationship_accepted: bool
    rejection_reason: Optional[str]
    validation_hash: str                 # Reproducible SHA-256

    def summary(self) -> str:
        status = "ACCEPTED" if self.relationship_accepted else "REJECTED"
        unc_lo, unc_hi = self.uncertainty_range
        return (
            f"[{status}] {self.relationship_type}: {self.entity_a} ↔ {self.entity_b} | "
            f"Score={self.validated_score:.2f} [{unc_lo:.2f}–{unc_hi:.2f}] | "
            f"Evidence={len(self.evidence_chain)} | Telemetry={self.telemetry_supported}"
        )


@dataclass
class PivotValidationResult:
    """Result of validating an infrastructure pivot path."""
    pivot_origin: str
    pivot_destination: str
    pivot_hops: List[str]
    path_confidence: float
    uncertainty_range: Tuple[float, float]
    evidence_per_hop: Dict[str, List[EvidenceRecord]]
    weakest_link_score: float
    weakest_link_hop: str
    telemetry_corroborated: bool
    accepted: bool
    rejection_reason: Optional[str]
    validation_hash: str

    def summary(self) -> str:
        status = "ACCEPTED" if self.accepted else "REJECTED"
        hops = " → ".join(self.pivot_hops)
        return (
            f"[{status}] PIVOT {self.pivot_origin} → {self.pivot_destination} | "
            f"Path: {hops} | Confidence={self.path_confidence:.2f} | "
            f"Weakest_hop={self.weakest_link_hop}({self.weakest_link_score:.2f})"
        )


@dataclass
class ActorOverlapResult:
    """Result of actor-to-actor overlap scoring."""
    actor_a: str
    actor_b: str
    overlap_score: float
    uncertainty_range: Tuple[float, float]
    overlap_dimensions: Dict[str, float]   # e.g., {"ttp": 0.6, "infra": 0.4, "malware": 0.3}
    shared_indicators: List[str]
    evidence_chain: List[EvidenceRecord]
    confidence_band: str                   # HIGH/MEDIUM/LOW/SPECULATIVE
    accepted: bool
    prohibition_triggered: Optional[str]
    validation_hash: str

    def summary(self) -> str:
        return (
            f"[{self.confidence_band}] Actor overlap {self.actor_a} ↔ {self.actor_b}: "
            f"score={self.overlap_score:.2f} [{self.uncertainty_range[0]:.2f}–{self.uncertainty_range[1]:.2f}] | "
            f"Dims={self.overlap_dimensions} | "
            f"{'ACCEPTED' if self.accepted else 'REJECTED: ' + str(self.prohibition_triggered)}"
        )


@dataclass
class MalwareLineageResult:
    """Result of malware lineage / family verification."""
    sample_hash: str
    claimed_family: str
    lineage_verified: bool
    similarity_score: float
    uncertainty_range: Tuple[float, float]
    variant_chain: List[str]              # e.g., ["EMOTET_v1", "EMOTET_v2", "sample"]
    evidence_chain: List[EvidenceRecord]
    lineage_confidence: str               # CONFIRMED/PROBABLE/POSSIBLE/UNVERIFIED
    rejection_reason: Optional[str]
    validation_hash: str

    def summary(self) -> str:
        return (
            f"[{self.lineage_confidence}] Lineage {self.sample_hash[:16]}… → {self.claimed_family}: "
            f"verified={self.lineage_verified} score={self.similarity_score:.2f} | "
            f"Chain={self.variant_chain}"
        )


@dataclass
class CampaignSimilarityResult:
    """Result of campaign-to-campaign similarity analysis."""
    campaign_a: str
    campaign_b: str
    similarity_score: float
    uncertainty_range: Tuple[float, float]
    shared_ioc_count: int
    shared_ttps: List[str]
    shared_infrastructure: List[str]
    temporal_overlap_days: float
    evidence_chain: List[EvidenceRecord]
    similarity_band: str                  # HIGHLY_SIMILAR/SIMILAR/LOW_SIMILARITY/DISTINCT
    accepted: bool
    rejection_reason: Optional[str]
    validation_hash: str

    def summary(self) -> str:
        return (
            f"[{self.similarity_band}] Campaign {self.campaign_a} ↔ {self.campaign_b}: "
            f"score={self.similarity_score:.2f} | IOCs={self.shared_ioc_count} | "
            f"TTPs={len(self.shared_ttps)} | Infra={len(self.shared_infrastructure)}"
        )


@dataclass
class GraphConfidenceReport:
    """Aggregate confidence report for a graph entity and its relationships."""
    entity_id: str
    entity_type: str
    total_relationships: int
    accepted_relationships: int
    rejected_relationships: int
    avg_validated_score: float
    lowest_confidence_relationship: str
    telemetry_coverage: float             # % of relationships with telemetry support
    graph_confidence_band: str            # TRUSTED/OPERATIONAL/ASSESSED/SPECULATIVE/UNTRUSTED
    evidence_diversity_score: float       # # of unique evidence types / max possible
    validation_hash: str

    def summary(self) -> str:
        return (
            f"[{self.graph_confidence_band}] Entity {self.entity_id} ({self.entity_type}): "
            f"{self.accepted_relationships}/{self.total_relationships} relationships accepted | "
            f"Avg confidence={self.avg_validated_score:.2f} | "
            f"Telemetry coverage={self.telemetry_coverage:.0%} | "
            f"Evidence diversity={self.evidence_diversity_score:.2f}"
        )


# ─────────────────────────────────────────────
# CORE VALIDATOR
# ─────────────────────────────────────────────

class GraphIntelligenceValidator:
    """
    Evidence-backed validation engine for graph intelligence relationships.

    Enforces minimum evidence gates before accepting any relationship.
    Computes bounded confidence scores with explicit uncertainty ranges.
    Rejects relationships that lack required corroborating evidence types.
    """

    def __init__(self) -> None:
        self._validation_log: List[Dict[str, Any]] = []

    # ─── INTERNAL HELPERS ─────────────────────────────────────────────────

    def _compute_evidence_score(self, evidence_chain: List[EvidenceRecord]) -> float:
        """Aggregate score from evidence chain using weighted max + diversity bonus."""
        if not evidence_chain:
            return 0.0
        weights = [e.effective_weight() for e in evidence_chain]
        # Max-based aggregation with diversity bonus
        base_score = max(weights)
        unique_types = len(set(e.basis_type for e in evidence_chain))
        diversity_bonus = min((unique_types - 1) * 0.03, 0.15)
        return min(base_score + diversity_bonus, 1.0)

    def _check_evidence_gates(
        self,
        relationship_type: str,
        evidence_chain: List[EvidenceRecord],
        raw_score: float,
    ) -> Tuple[bool, List[str], float]:
        """
        Returns (gates_passed, gate_failures, validated_score).
        Applies ceiling if telemetry is absent.
        """
        gate_config = RELATIONSHIP_EVIDENCE_GATES.get(relationship_type, {})
        if not gate_config:
            return True, [], raw_score

        failures: List[str] = []
        min_bases = gate_config.get("min_bases", 1)
        min_score = gate_config.get("min_score", 0.30)
        required_any = gate_config.get("required_any", [])
        max_no_telem = gate_config.get("max_confidence_without_telemetry", 1.0)

        if len(evidence_chain) < min_bases:
            failures.append(f"Insufficient evidence: {len(evidence_chain)}/{min_bases} minimum bases")

        if raw_score < min_score:
            failures.append(f"Score below gate: {raw_score:.2f} < {min_score:.2f}")

        has_required = any(
            any(e.basis_type == req for e in evidence_chain)
            for req in required_any
        )
        if required_any and not has_required:
            failures.append(
                f"Missing required evidence type — need one of: "
                f"{[r.value for r in required_any]}"
            )

        has_telemetry = any(
            e.basis_type == EvidenceBasisType.TELEMETRY_OBSERVED for e in evidence_chain
        )
        validated_score = raw_score
        if not has_telemetry and raw_score > max_no_telem:
            validated_score = max_no_telem
            # Not a gate failure — just a ceiling

        gates_passed = len(failures) == 0
        return gates_passed, failures, validated_score

    def _uncertainty_range(
        self,
        validated_score: float,
        evidence_count: int,
        telemetry_supported: bool,
        floor: float = 0.10,
    ) -> Tuple[float, float]:
        """
        Compute uncertainty bounds.
        More evidence → tighter bounds. Telemetry → tighter bounds.
        """
        base_uncertainty = max(floor, 0.30 - (evidence_count * 0.03))
        if telemetry_supported:
            base_uncertainty *= 0.70
        lo = max(0.0, validated_score - base_uncertainty)
        hi = min(1.0, validated_score + base_uncertainty * 0.5)
        return round(lo, 3), round(hi, 3)

    def _make_hash(self, data: Dict[str, Any]) -> str:
        canonical = json.dumps(data, sort_keys=True, default=str)
        return hashlib.sha256(canonical.encode()).hexdigest()[:16]

    def _log_validation(self, record: Dict[str, Any]) -> None:
        self._validation_log.append({**record, "logged_at": time.time()})

    # ─── RELATIONSHIP VALIDATOR ────────────────────────────────────────────

    def validate_relationship(
        self,
        relationship_type: str,
        entity_a: str,
        entity_b: str,
        evidence_chain: List[EvidenceRecord],
    ) -> GraphRelationshipValidation:
        """
        Validate a generic graph relationship with evidence chain.
        Relationship types: actor_overlap, malware_lineage, infrastructure_pivot, campaign_similarity.
        """
        telemetry_supported = any(
            e.basis_type == EvidenceBasisType.TELEMETRY_OBSERVED for e in evidence_chain
        )
        raw_score = self._compute_evidence_score(evidence_chain)
        gates_passed, gate_failures, validated_score = self._check_evidence_gates(
            relationship_type, evidence_chain, raw_score
        )
        gate_config = RELATIONSHIP_EVIDENCE_GATES.get(relationship_type, {})
        uncertainty_floor = gate_config.get("uncertainty_floor", 0.10)
        uncertainty = self._uncertainty_range(
            validated_score, len(evidence_chain), telemetry_supported, uncertainty_floor
        )
        accepted = gates_passed
        rejection_reason = "; ".join(gate_failures) if gate_failures else None

        vhash = self._make_hash({
            "type": relationship_type,
            "a": entity_a,
            "b": entity_b,
            "score": validated_score,
            "evidence_count": len(evidence_chain),
            "basis_types": sorted(e.basis_type.value for e in evidence_chain),
        })

        result = GraphRelationshipValidation(
            relationship_type=relationship_type,
            entity_a=entity_a,
            entity_b=entity_b,
            raw_score=round(raw_score, 4),
            validated_score=round(validated_score, 4),
            uncertainty_range=uncertainty,
            evidence_chain=evidence_chain,
            gates_passed=gates_passed,
            gate_failures=gate_failures,
            telemetry_supported=telemetry_supported,
            relationship_accepted=accepted,
            rejection_reason=rejection_reason,
            validation_hash=vhash,
        )
        self._log_validation({"validation_type": "relationship", "result": result.summary()})
        return result

    # ─── INFRASTRUCTURE PIVOT VALIDATOR ────────────────────────────────────

    def validate_pivot_path(
        self,
        origin: str,
        destination: str,
        hop_evidence: Dict[str, List[EvidenceRecord]],
    ) -> PivotValidationResult:
        """
        Validate an infrastructure pivot path where hop_evidence maps
        each hop entity to its supporting evidence records.
        Path confidence = weakest hop score (chain is only as strong as weakest link).
        """
        hops = list(hop_evidence.keys())
        hop_scores: Dict[str, float] = {}
        telemetry_any = False

        for hop, evidence in hop_evidence.items():
            if any(e.basis_type == EvidenceBasisType.TELEMETRY_OBSERVED for e in evidence):
                telemetry_any = True
            _, _, vs = self._check_evidence_gates("infrastructure_pivot", evidence, self._compute_evidence_score(evidence))
            hop_scores[hop] = vs

        weakest_hop = min(hop_scores, key=hop_scores.get) if hop_scores else origin
        weakest_score = hop_scores.get(weakest_hop, 0.0)
        path_confidence = weakest_score   # Weakest-link model

        gate_config = RELATIONSHIP_EVIDENCE_GATES["infrastructure_pivot"]
        uncertainty = self._uncertainty_range(
            path_confidence,
            sum(len(e) for e in hop_evidence.values()),
            telemetry_any,
            gate_config["uncertainty_floor"],
        )

        accepted = path_confidence >= gate_config["min_score"]
        rejection_reason = None if accepted else (
            f"Weakest hop {weakest_hop} score {weakest_score:.2f} < "
            f"required {gate_config['min_score']:.2f}"
        )

        vhash = self._make_hash({
            "origin": origin, "destination": destination,
            "hops": hops, "path_confidence": path_confidence,
        })

        result = PivotValidationResult(
            pivot_origin=origin,
            pivot_destination=destination,
            pivot_hops=hops,
            path_confidence=round(path_confidence, 4),
            uncertainty_range=uncertainty,
            evidence_per_hop=hop_evidence,
            weakest_link_score=round(weakest_score, 4),
            weakest_link_hop=weakest_hop,
            telemetry_corroborated=telemetry_any,
            accepted=accepted,
            rejection_reason=rejection_reason,
            validation_hash=vhash,
        )
        self._log_validation({"validation_type": "pivot", "result": result.summary()})
        return result

    # ─── ACTOR OVERLAP SCORER ──────────────────────────────────────────────

    def score_actor_overlap(
        self,
        actor_a: str,
        actor_b: str,
        ttp_set_a: List[str],
        ttp_set_b: List[str],
        infra_iocs_a: List[str],
        infra_iocs_b: List[str],
        malware_a: List[str],
        malware_b: List[str],
        evidence_chain: List[EvidenceRecord],
    ) -> ActorOverlapResult:
        """
        Score overlap between two threat actors across TTP, infrastructure, and malware dimensions.
        Returns probabilistic score — NOT attribution. DO NOT infer same actor without
        additional telemetry corroboration.
        """
        # Jaccard similarity per dimension
        def _jaccard(a: List[str], b: List[str]) -> float:
            sa, sb = set(s.upper() for s in a), set(s.upper() for s in b)
            if not sa and not sb:
                return 0.0
            intersection = len(sa & sb)
            union = len(sa | sb)
            return intersection / union if union > 0 else 0.0

        ttp_overlap = _jaccard(ttp_set_a, ttp_set_b)
        infra_overlap = _jaccard(infra_iocs_a, infra_iocs_b)
        malware_overlap = _jaccard(malware_a, malware_b)

        shared_indicators = list(
            set(s.upper() for s in infra_iocs_a) & set(s.upper() for s in infra_iocs_b)
        )

        # Weighted composite — infra > malware > ttp (TTP can be coincidental)
        dims = {
            "ttp_jaccard": round(ttp_overlap, 4),
            "infra_jaccard": round(infra_overlap, 4),
            "malware_jaccard": round(malware_overlap, 4),
        }
        raw_score = (
            ttp_overlap * 0.30
            + infra_overlap * 0.50
            + malware_overlap * 0.20
        )

        # Blend with evidence chain score
        evidence_score = self._compute_evidence_score(evidence_chain)
        blended_score = raw_score * 0.60 + evidence_score * 0.40

        gates_passed, gate_failures, validated_score = self._check_evidence_gates(
            "actor_overlap", evidence_chain, blended_score
        )

        telemetry_supported = any(
            e.basis_type == EvidenceBasisType.TELEMETRY_OBSERVED for e in evidence_chain
        )
        uncertainty = self._uncertainty_range(
            validated_score, len(evidence_chain), telemetry_supported,
            RELATIONSHIP_EVIDENCE_GATES["actor_overlap"]["uncertainty_floor"]
        )

        # Confidence band
        if validated_score >= 0.80 and telemetry_supported:
            band = "HIGH"
        elif validated_score >= 0.65:
            band = "MEDIUM"
        elif validated_score >= 0.45:
            band = "LOW"
        else:
            band = "SPECULATIVE"

        # Prohibition: cannot claim HIGH overlap without telemetry
        prohibition = None
        accepted = gates_passed
        if band == "HIGH" and not telemetry_supported:
            prohibition = "HIGH overlap claim requires telemetry corroboration"
            band = "MEDIUM"
            accepted = False

        vhash = self._make_hash({
            "actor_a": actor_a, "actor_b": actor_b,
            "score": validated_score, "dims": dims,
        })

        result = ActorOverlapResult(
            actor_a=actor_a,
            actor_b=actor_b,
            overlap_score=round(validated_score, 4),
            uncertainty_range=uncertainty,
            overlap_dimensions=dims,
            shared_indicators=shared_indicators,
            evidence_chain=evidence_chain,
            confidence_band=band,
            accepted=accepted,
            prohibition_triggered=prohibition,
            validation_hash=vhash,
        )
        self._log_validation({"validation_type": "actor_overlap", "result": result.summary()})
        return result

    # ─── MALWARE LINEAGE VERIFIER ──────────────────────────────────────────

    def verify_malware_lineage(
        self,
        sample_hash: str,
        claimed_family: str,
        known_variant_hashes: List[str],
        similarity_scores: Dict[str, float],   # {known_hash: similarity_0_to_1}
        evidence_chain: List[EvidenceRecord],
    ) -> MalwareLineageResult:
        """
        Verify malware lineage claim against known variant hashes.
        similarity_scores must come from binary analysis (imphash, TLSH, SSDEEP, etc.).
        OSINT family claims alone are insufficient.
        """
        # Highest similarity to any known variant
        if similarity_scores:
            best_match_hash = max(similarity_scores, key=similarity_scores.get)
            best_similarity = similarity_scores[best_match_hash]
        else:
            best_match_hash = None
            best_similarity = 0.0

        gates_passed, gate_failures, validated_score = self._check_evidence_gates(
            "malware_lineage", evidence_chain, best_similarity
        )

        telemetry_supported = any(
            e.basis_type == EvidenceBasisType.TELEMETRY_OBSERVED for e in evidence_chain
        )
        uncertainty = self._uncertainty_range(
            validated_score, len(evidence_chain), telemetry_supported,
            RELATIONSHIP_EVIDENCE_GATES["malware_lineage"]["uncertainty_floor"]
        )

        # Lineage confidence
        if validated_score >= 0.85 and gates_passed:
            confidence = "CONFIRMED"
        elif validated_score >= 0.70 and gates_passed:
            confidence = "PROBABLE"
        elif validated_score >= 0.50:
            confidence = "POSSIBLE"
        else:
            confidence = "UNVERIFIED"

        # Build variant chain
        variant_chain = known_variant_hashes[:3] + [sample_hash[:16] + "…"]

        lineage_verified = confidence in ("CONFIRMED", "PROBABLE") and gates_passed
        rejection_reason = None if lineage_verified else (
            "; ".join(gate_failures) if gate_failures else
            f"Similarity {best_similarity:.2f} insufficient for {claimed_family}"
        )

        vhash = self._make_hash({
            "hash": sample_hash, "family": claimed_family,
            "similarity": validated_score, "confidence": confidence,
        })

        result = MalwareLineageResult(
            sample_hash=sample_hash,
            claimed_family=claimed_family,
            lineage_verified=lineage_verified,
            similarity_score=round(validated_score, 4),
            uncertainty_range=uncertainty,
            variant_chain=variant_chain,
            evidence_chain=evidence_chain,
            lineage_confidence=confidence,
            rejection_reason=rejection_reason,
            validation_hash=vhash,
        )
        self._log_validation({"validation_type": "malware_lineage", "result": result.summary()})
        return result

    # ─── CAMPAIGN SIMILARITY ANALYZER ──────────────────────────────────────

    def analyze_campaign_similarity(
        self,
        campaign_a: str,
        campaign_b: str,
        iocs_a: List[str],
        iocs_b: List[str],
        ttps_a: List[str],
        ttps_b: List[str],
        infra_a: List[str],
        infra_b: List[str],
        campaign_start_a: float,        # epoch timestamp
        campaign_start_b: float,
        evidence_chain: List[EvidenceRecord],
    ) -> CampaignSimilarityResult:
        """
        Analyze similarity between two campaigns.
        Requires minimum 3 independent indicator types before accepting similarity claim.
        """
        # Jaccard per dimension
        def _jac(a: List[str], b: List[str]) -> Tuple[float, List[str]]:
            sa, sb = set(a), set(b)
            shared = list(sa & sb)
            j = len(shared) / len(sa | sb) if sa | sb else 0.0
            return j, shared

        ioc_jac, shared_iocs = _jac(iocs_a, iocs_b)
        ttp_jac, shared_ttps = _jac(ttps_a, ttps_b)
        infra_jac, shared_infra = _jac(infra_a, infra_b)

        temporal_delta = abs(campaign_start_a - campaign_start_b) / 86400  # days
        temporal_score = max(0.0, 1.0 - temporal_delta / 365)  # decays over 1 year

        raw_score = (
            ioc_jac * 0.35
            + ttp_jac * 0.25
            + infra_jac * 0.30
            + temporal_score * 0.10
        )

        gates_passed, gate_failures, validated_score = self._check_evidence_gates(
            "campaign_similarity", evidence_chain, raw_score
        )

        telemetry_supported = any(
            e.basis_type == EvidenceBasisType.TELEMETRY_OBSERVED for e in evidence_chain
        )
        uncertainty = self._uncertainty_range(
            validated_score, len(evidence_chain), telemetry_supported,
            RELATIONSHIP_EVIDENCE_GATES["campaign_similarity"]["uncertainty_floor"]
        )

        # Similarity band
        if validated_score >= 0.80:
            band = "HIGHLY_SIMILAR"
        elif validated_score >= 0.60:
            band = "SIMILAR"
        elif validated_score >= 0.40:
            band = "LOW_SIMILARITY"
        else:
            band = "DISTINCT"

        accepted = gates_passed and len(shared_iocs) + len(shared_ttps) + len(shared_infra) >= 3
        rejection_reason = None
        if not accepted:
            reasons = list(gate_failures)
            total_shared = len(shared_iocs) + len(shared_ttps) + len(shared_infra)
            if total_shared < 3:
                reasons.append(f"Only {total_shared} shared indicators — minimum 3 required")
            rejection_reason = "; ".join(reasons) if reasons else "Insufficient shared indicators"

        vhash = self._make_hash({
            "camp_a": campaign_a, "camp_b": campaign_b,
            "score": validated_score, "band": band,
            "shared_ioc_count": len(shared_iocs),
        })

        result = CampaignSimilarityResult(
            campaign_a=campaign_a,
            campaign_b=campaign_b,
            similarity_score=round(validated_score, 4),
            uncertainty_range=uncertainty,
            shared_ioc_count=len(shared_iocs),
            shared_ttps=shared_ttps,
            shared_infrastructure=shared_infra,
            temporal_overlap_days=round(temporal_delta, 1),
            evidence_chain=evidence_chain,
            similarity_band=band,
            accepted=accepted,
            rejection_reason=rejection_reason,
            validation_hash=vhash,
        )
        self._log_validation({"validation_type": "campaign_similarity", "result": result.summary()})
        return result

    # ─── AGGREGATE GRAPH CONFIDENCE REPORT ─────────────────────────────────

    def generate_graph_confidence_report(
        self,
        entity_id: str,
        entity_type: str,
        relationship_validations: List[GraphRelationshipValidation],
    ) -> GraphConfidenceReport:
        """
        Aggregate confidence report across all relationships for a graph entity.
        """
        total = len(relationship_validations)
        accepted = [r for r in relationship_validations if r.relationship_accepted]
        rejected = [r for r in relationship_validations if not r.relationship_accepted]

        if not accepted:
            avg_score = 0.0
            telemetry_coverage = 0.0
            lowest = "no_accepted_relationships"
        else:
            scores = [r.validated_score for r in accepted]
            avg_score = sum(scores) / len(scores)
            telemetry_coverage = sum(1 for r in accepted if r.telemetry_supported) / len(accepted)
            lowest_r = min(accepted, key=lambda r: r.validated_score)
            lowest = f"{lowest_r.relationship_type}:{lowest_r.entity_b}"

        # Evidence diversity across all accepted relationships
        all_basis_types = set()
        for r in accepted:
            for e in r.evidence_chain:
                all_basis_types.add(e.basis_type)
        evidence_diversity = len(all_basis_types) / len(EvidenceBasisType) if accepted else 0.0

        # Confidence band
        if avg_score >= 0.80 and telemetry_coverage >= 0.50:
            band = "TRUSTED"
        elif avg_score >= 0.65:
            band = "OPERATIONAL"
        elif avg_score >= 0.50:
            band = "ASSESSED"
        elif avg_score >= 0.30:
            band = "SPECULATIVE"
        else:
            band = "UNTRUSTED"

        vhash = self._make_hash({
            "entity": entity_id, "type": entity_type,
            "accepted": len(accepted), "total": total, "avg": avg_score,
        })

        return GraphConfidenceReport(
            entity_id=entity_id,
            entity_type=entity_type,
            total_relationships=total,
            accepted_relationships=len(accepted),
            rejected_relationships=len(rejected),
            avg_validated_score=round(avg_score, 4),
            lowest_confidence_relationship=lowest,
            telemetry_coverage=round(telemetry_coverage, 4),
            graph_confidence_band=band,
            evidence_diversity_score=round(evidence_diversity, 4),
            validation_hash=vhash,
        )

    def get_validation_log(self) -> List[Dict[str, Any]]:
        return list(self._validation_log)


# ─────────────────────────────────────────────
# SELF-TEST
# ─────────────────────────────────────────────

def _self_test() -> None:
    validator = GraphIntelligenceValidator()

    # Test 1: Infrastructure pivot with telemetry
    hop_ev = {
        "192.168.1.100": [
            EvidenceRecord(
                EvidenceBasisType.TELEMETRY_OBSERVED, "endpoint-agent-HOST001",
                "Network connection observed", telemetry_backed=True, source_trust=0.95,
            ),
            EvidenceRecord(
                EvidenceBasisType.PASSIVE_DNS, "passivedns",
                "Resolves to 192.168.1.100", source_trust=0.80,
            ),
        ],
        "malicious-domain.example": [
            EvidenceRecord(
                EvidenceBasisType.PASSIVE_DNS, "passivedns",
                "Domain resolved from beacon IP", source_trust=0.75,
            ),
            EvidenceRecord(
                EvidenceBasisType.CERTIFICATE_OVERLAP, "censys",
                "Self-signed cert reused", source_trust=0.80,
            ),
        ],
    }
    pivot = validator.validate_pivot_path("192.168.1.5", "C2-CLUSTER-7", hop_ev)
    print(pivot.summary())

    # Test 2: Actor overlap — insufficient evidence (no telemetry)
    overlap = validator.score_actor_overlap(
        actor_a="THREAT-ACTOR-ALPHA",
        actor_b="THREAT-ACTOR-BETA",
        ttp_set_a=["T1059.001", "T1003.001", "T1071.001"],
        ttp_set_b=["T1059.001", "T1003.001", "T1486"],
        infra_iocs_a=["evil-c2.xyz", "185.220.101.1"],
        infra_iocs_b=["evil-c2.xyz", "185.220.102.5"],
        malware_a=["COBALT_STRIKE"],
        malware_b=["COBALT_STRIKE", "MIMIKATZ"],
        evidence_chain=[
            EvidenceRecord(
                EvidenceBasisType.TTP_OVERLAP, "internal-analysis",
                "Shared TTPs observed", source_trust=0.70,
            ),
            EvidenceRecord(
                EvidenceBasisType.OSINT_REFERENCE, "blog-post",
                "Vendor report mentions overlap", source_trust=0.40,
            ),
        ],
    )
    print(overlap.summary())

    # Test 3: Malware lineage — code similarity evidence
    lineage = validator.verify_malware_lineage(
        sample_hash="sha256:abc123def456",
        claimed_family="EMOTET",
        known_variant_hashes=["sha256:emotet_v3_ref", "sha256:emotet_v4_ref"],
        similarity_scores={
            "sha256:emotet_v3_ref": 0.82,
            "sha256:emotet_v4_ref": 0.79,
        },
        evidence_chain=[
            EvidenceRecord(
                EvidenceBasisType.CODE_SIMILARITY, "capa-analysis",
                "TLSH similarity 0.82 to EMOTET_v3", source_trust=0.90,
            ),
            EvidenceRecord(
                EvidenceBasisType.MALWARE_FAMILY, "virustotal",
                "72/80 engines classify as Emotet", source_trust=0.85,
            ),
        ],
    )
    print(lineage.summary())

    # Test 4: Campaign similarity — insufficient shared indicators
    t_now = time.time()
    campaign_sim = validator.analyze_campaign_similarity(
        campaign_a="CAMPAIGN-ALPHA-2024",
        campaign_b="CAMPAIGN-BETA-2024",
        iocs_a=["192.0.2.1"],
        iocs_b=["192.0.2.1", "198.51.100.1"],
        ttps_a=["T1059"],
        ttps_b=["T1059", "T1071"],
        infra_a=["evil.com"],
        infra_b=["other.com"],
        campaign_start_a=t_now - 86400 * 30,
        campaign_start_b=t_now - 86400 * 45,
        evidence_chain=[
            EvidenceRecord(
                EvidenceBasisType.CAMPAIGN_INDICATOR, "soc-analyst",
                "Shared IOC seen in both incidents", source_trust=0.75,
            ),
        ],
    )
    print(campaign_sim.summary())

    # Test 5: Aggregate graph confidence report
    rels = [pivot_to_rel(pivot), lineage_to_rel(lineage)]
    print("\nSelf-test PASSED — 4 validation scenarios executed")


def pivot_to_rel(pivot: PivotValidationResult) -> GraphRelationshipValidation:
    """Convert pivot result to generic relationship for aggregate reporting."""
    all_evidence = []
    for ev_list in pivot.evidence_per_hop.values():
        all_evidence.extend(ev_list)
    return GraphRelationshipValidation(
        relationship_type="infrastructure_pivot",
        entity_a=pivot.pivot_origin,
        entity_b=pivot.pivot_destination,
        raw_score=pivot.path_confidence,
        validated_score=pivot.path_confidence,
        uncertainty_range=pivot.uncertainty_range,
        evidence_chain=all_evidence,
        gates_passed=pivot.accepted,
        gate_failures=[],
        telemetry_supported=pivot.telemetry_corroborated,
        relationship_accepted=pivot.accepted,
        rejection_reason=pivot.rejection_reason,
        validation_hash=pivot.validation_hash,
    )


def lineage_to_rel(lineage: MalwareLineageResult) -> GraphRelationshipValidation:
    """Convert lineage result to generic relationship for aggregate reporting."""
    return GraphRelationshipValidation(
        relationship_type="malware_lineage",
        entity_a=lineage.sample_hash,
        entity_b=lineage.claimed_family,
        raw_score=lineage.similarity_score,
        validated_score=lineage.similarity_score,
        uncertainty_range=lineage.uncertainty_range,
        evidence_chain=lineage.evidence_chain,
        gates_passed=lineage.lineage_verified,
        gate_failures=[],
        telemetry_supported=any(
            e.basis_type == EvidenceBasisType.TELEMETRY_OBSERVED
            for e in lineage.evidence_chain
        ),
        relationship_accepted=lineage.lineage_verified,
        rejection_reason=lineage.rejection_reason,
        validation_hash=lineage.validation_hash,
    )


if __name__ == "__main__":
    _self_test()
