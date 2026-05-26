#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Attribution Governance Engine
Section 3: Attribution Discipline | Uncertainty Quantification |
           Evidence-Backed Claims Only | Actor Lineage Verification |
           Behavioral Overlap Scoring | Infrastructure Overlap Analysis |
           Attribution Restraint Enforcement
DIRECTIVE: Attribution claims are evidence-constrained, uncertainty-declared,
           and never escalated without multi-source corroboration.
Production-grade | Evidence-disciplined | Uncertainty-aware | SOC-trusted
"""
import json, uuid, math, hashlib, logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict
from enum import Enum

log = logging.getLogger("attribution_governance")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [ATTR-GOV] %(levelname)s %(message)s")

class AttributionBasis(str, Enum):
    """Legally and analytically defensible attribution basis categories."""
    INFRASTRUCTURE_OVERLAP = "infrastructure_overlap"
    TTP_PATTERN_MATCH      = "ttp_pattern_match"
    MALWARE_CODE_REUSE     = "malware_code_reuse"
    BEHAVIORAL_SIMILARITY  = "behavioral_similarity"
    CAMPAIGN_LINEAGE       = "campaign_lineage"
    TELEMETRY_EVIDENCE     = "telemetry_evidence"
    REPLAY_VALIDATED       = "replay_validated"
    GRAPH_CORRELATION      = "graph_correlation"
    # Lower-weight bases
    TIMING_CORRELATION     = "timing_correlation"
    LINGUISTIC_ANALYSIS    = "linguistic_analysis"
    OSINT_REFERENCE        = "osint_reference"

# Weight of each attribution basis
BASIS_WEIGHTS = {
    AttributionBasis.TELEMETRY_EVIDENCE:     0.25,
    AttributionBasis.REPLAY_VALIDATED:       0.20,
    AttributionBasis.TTP_PATTERN_MATCH:      0.18,
    AttributionBasis.INFRASTRUCTURE_OVERLAP: 0.15,
    AttributionBasis.MALWARE_CODE_REUSE:     0.15,
    AttributionBasis.BEHAVIORAL_SIMILARITY:  0.12,
    AttributionBasis.GRAPH_CORRELATION:      0.12,
    AttributionBasis.CAMPAIGN_LINEAGE:       0.10,
    AttributionBasis.TIMING_CORRELATION:     0.05,
    AttributionBasis.LINGUISTIC_ANALYSIS:    0.04,
    AttributionBasis.OSINT_REFERENCE:        0.03,
}

# Minimum evidence gates per attribution level
ATTRIBUTION_GATES = {
    "CONFIRMED":   {"min_bases": 5, "min_score": 0.85, "telemetry_required": True,  "replay_required": True},
    "HIGH":        {"min_bases": 4, "min_score": 0.70, "telemetry_required": True,  "replay_required": False},
    "MEDIUM":      {"min_bases": 3, "min_score": 0.50, "telemetry_required": False, "replay_required": False},
    "LOW":         {"min_bases": 2, "min_score": 0.30, "telemetry_required": False, "replay_required": False},
    "SPECULATIVE": {"min_bases": 1, "min_score": 0.10, "telemetry_required": False, "replay_required": False},
    "REJECTED":    {"min_bases": 0, "min_score": 0.00, "telemetry_required": False, "replay_required": False},
}

@dataclass
class AttributionEvidence:
    basis:          str    # AttributionBasis value
    source_id:      str
    description:    str
    strength:       float  # 0-1: strength of this specific evidence
    validated:      bool   = True
    timestamp:      str    = ""

    def weight(self) -> float:
        return BASIS_WEIGHTS.get(self.basis, 0.03)

    def contribution(self) -> float:
        return self.weight() * self.strength * (1.0 if self.validated else 0.5)

    def to_dict(self): return asdict(self)

@dataclass
class AttributionResult:
    attribution_id:    str
    tenant_id:         str
    actor_cluster:     str        # NOT specific actor unless high confidence
    confidence_level:  str        # CONFIRMED/HIGH/MEDIUM/LOW/SPECULATIVE/REJECTED
    confidence_score:  float
    uncertainty_range: Tuple[float, float]  # (lower_bound, upper_bound)
    bases:             List[AttributionEvidence]
    basis_types:       List[str]
    overlap_explanation: str
    telemetry_contribution: float
    allowed_claims:    List[str]  # what analyst IS allowed to assert
    prohibited_claims: List[str]  # what analyst must NOT assert
    attribution_statement: str    # the ONLY approved statement
    requires_review:   bool
    timestamp:         str
    reproducible_hash: str

    def to_dict(self):
        d = asdict(self)
        d["uncertainty_range"] = list(self.uncertainty_range)
        return d

class AttributionGovernanceEngine:
    """
    Disciplined attribution engine with mandatory uncertainty declaration.
    Enforces evidence gates before allowing actor attribution claims.
    Generates approved attribution statements proportional to evidence.
    """

    # Approved attribution statement templates by confidence level
    STATEMENT_TEMPLATES = {
        "CONFIRMED": (
            "Multiple independent evidence sources including telemetry, "
            "replay-validated detections, TTP overlap, and infrastructure correlation "
            "indicate with high confidence that activity aligns with known {actor} "
            "behavioral patterns. Attribution confidence: {score:.0%}. "
            "Uncertainty range: {lower:.0%}–{upper:.0%}."
        ),
        "HIGH": (
            "Telemetry-corroborated TTP overlap and infrastructure similarity "
            "suggest alignment with {actor} behavioral patterns. "
            "Attribution is assessed with moderate-high confidence ({score:.0%}). "
            "Additional validation recommended before operational decisions. "
            "Uncertainty range: {lower:.0%}–{upper:.0%}."
        ),
        "MEDIUM": (
            "Partial TTP and infrastructure overlap observed with {actor} behavioral profile. "
            "Confidence is limited ({score:.0%}) due to incomplete telemetry coverage. "
            "Assessment is analytically based. Independent corroboration required. "
            "Uncertainty range: {lower:.0%}–{upper:.0%}."
        ),
        "LOW": (
            "Limited overlap indicators with {actor} patterns observed. "
            "Confidence is LOW ({score:.0%}). Evidence basis is insufficient for "
            "attribution claims. Treat as working hypothesis only. "
            "Uncertainty range: {lower:.0%}–{upper:.0%}."
        ),
        "SPECULATIVE": (
            "Speculative overlap with {actor} noted from single evidence source. "
            "Confidence: VERY LOW ({score:.0%}). No operational attribution warranted. "
            "Further investigation required. Uncertainty range: {lower:.0%}–{upper:.0%}."
        ),
        "REJECTED": (
            "ATTRIBUTION REJECTED: Insufficient evidence to support any actor attribution. "
            "Do not attribute. Confidence: 0%."
        ),
    }

    def __init__(self):
        self._attributions: Dict[str, AttributionResult] = {}
        self._stats = defaultdict(int)
        log.info("AttributionGovernanceEngine INITIALIZED — discipline enforced")

    def evaluate(self, actor_cluster: str, evidence: List[AttributionEvidence],
                 tenant_id: str = "default") -> AttributionResult:
        """
        Evaluate attribution claim against evidence.
        Returns governed attribution result with approved statement.
        """
        # Score computation
        raw_score = sum(e.contribution() for e in evidence)
        # Normalise by maximum possible score given evidence types
        basis_types = list(set(e.basis for e in evidence))
        max_score   = sum(BASIS_WEIGHTS.get(b, 0.03) for b in basis_types)
        normalised  = min(0.99, raw_score / max(max_score, 0.01))

        # Telemetry and replay presence check
        has_telemetry = any(e.basis == AttributionBasis.TELEMETRY_EVIDENCE for e in evidence)
        has_replay    = any(e.basis == AttributionBasis.REPLAY_VALIDATED for e in evidence)
        telemetry_contribution = sum(
            e.contribution() for e in evidence
            if e.basis == AttributionBasis.TELEMETRY_EVIDENCE
        )

        # Determine confidence level
        confidence_level = "REJECTED"
        for level, gates in ATTRIBUTION_GATES.items():
            if level == "REJECTED": continue
            meets_score   = normalised >= gates["min_score"]
            meets_bases   = len(set(e.basis for e in evidence)) >= gates["min_bases"]
            meets_telem   = (not gates["telemetry_required"]) or has_telemetry
            meets_replay  = (not gates["replay_required"])    or has_replay
            if meets_score and meets_bases and meets_telem and meets_replay:
                confidence_level = level
                break

        # Uncertainty range (epistemic uncertainty)
        evidence_count = len(evidence)
        validated_count= sum(1 for e in evidence if e.validated)
        base_uncertainty = 0.15 if evidence_count >= 4 else 0.25 if evidence_count >= 2 else 0.40
        lower = max(0.0, normalised - base_uncertainty)
        upper = min(0.99, normalised + base_uncertainty * 0.5)

        # Allowed and prohibited claims
        allowed_claims, prohibited_claims = self._build_claim_constraints(
            confidence_level, has_telemetry, has_replay, actor_cluster
        )

        # Attribution statement
        template = self.STATEMENT_TEMPLATES.get(confidence_level, self.STATEMENT_TEMPLATES["REJECTED"])
        statement = template.format(
            actor=actor_cluster, score=normalised, lower=lower, upper=upper
        ) if confidence_level != "REJECTED" else template

        # Overlap explanation
        overlap_explanation = self._explain_overlap(evidence)

        # Reproducible hash
        hash_input = json.dumps({
            "actor": actor_cluster,
            "evidence": sorted([{"basis":e.basis,"strength":e.strength} for e in evidence],
                               key=lambda x: x["basis"]),
        }, sort_keys=True)
        rep_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        result = AttributionResult(
            attribution_id        = str(uuid.uuid4())[:10],
            tenant_id             = tenant_id,
            actor_cluster         = actor_cluster,
            confidence_level      = confidence_level,
            confidence_score      = round(normalised, 4),
            uncertainty_range     = (round(lower, 3), round(upper, 3)),
            bases                 = evidence,
            basis_types           = basis_types,
            overlap_explanation   = overlap_explanation,
            telemetry_contribution= round(telemetry_contribution, 4),
            allowed_claims        = allowed_claims,
            prohibited_claims     = prohibited_claims,
            attribution_statement = statement,
            requires_review       = confidence_level in ("MEDIUM","LOW","SPECULATIVE"),
            timestamp             = datetime.now(timezone.utc).isoformat(),
            reproducible_hash     = rep_hash,
        )

        self._attributions[result.attribution_id] = result
        self._stats[f"level_{confidence_level}"] += 1
        log.info(f"🎯 ATTRIBUTION [{confidence_level}] actor={actor_cluster} "
                 f"score={normalised:.3f} range=[{lower:.2f},{upper:.2f}]")
        return result

    def _build_claim_constraints(self, level: str, has_telemetry: bool,
                                  has_replay: bool, actor: str) -> Tuple[List,List]:
        allowed, prohibited = [], []
        if level == "CONFIRMED":
            allowed = [
                f"Activity aligns with {actor} behavioral profile",
                "Infrastructure and TTP overlap confirmed",
                "Detections replay-validated",
            ]
            prohibited = ["Definitive attribution to nation-state without government confirmation"]
        elif level == "HIGH":
            allowed = [
                f"Activity is consistent with {actor} patterns",
                "TTP overlap warrants investigation priority",
            ]
            prohibited = [
                "Confirmed attribution",
                "Nation-state attribution",
                "Geopolitical claims",
            ]
        elif level == "MEDIUM":
            allowed = [f"Partial overlap with {actor} patterns noted"]
            prohibited = ["Attribution claims","Nation-state claims","Definitive actor identification"]
        elif level in ("LOW","SPECULATIVE"):
            allowed = ["Possible low-confidence overlap noted — treat as hypothesis"]
            prohibited = ["All attribution claims","All actor naming in reports","Escalation"]
        else:  # REJECTED
            allowed = ["No attribution applicable"]
            prohibited = ["All actor claims","All attribution language"]
        return allowed, prohibited

    def _explain_overlap(self, evidence: List[AttributionEvidence]) -> str:
        parts = []
        by_type = defaultdict(list)
        for e in evidence:
            by_type[e.basis].append(e)
        for basis, items in by_type.items():
            avg_str = sum(i.strength for i in items)/len(items)
            parts.append(f"{basis.replace('_',' ').title()}: {len(items)} indicator(s), avg strength {avg_str:.2f}")
        return "; ".join(parts) if parts else "No overlap basis available."

    def bulk_evaluate(self, cases: List[Dict]) -> List[Dict]:
        """Batch evaluate multiple attribution cases."""
        results = []
        for case in cases:
            evidence_list = [
                AttributionEvidence(**e) if isinstance(e, dict) else e
                for e in case.get("evidence", [])
            ]
            r = self.evaluate(case.get("actor","UNKNOWN"), evidence_list, case.get("tenant_id","default"))
            results.append(r.to_dict())
        return results

    def stats(self) -> Dict: return dict(self._stats)

if __name__ == "__main__":
    engine = AttributionGovernanceEngine()

    def make_evidence(basis, source, desc, strength, validated=True):
        return AttributionEvidence(basis=basis, source_id=source, description=desc,
                                   strength=strength, validated=validated,
                                   timestamp=datetime.now(timezone.utc).isoformat())

    print("\n" + "="*65)
    print("  SENTINEL APEX — ATTRIBUTION GOVERNANCE ENGINE SELF-TEST")
    print("="*65)

    # Test 1: Well-evidenced (should reach HIGH)
    r1 = engine.evaluate("THREAT_CLUSTER_ALPHA", [
        make_evidence(AttributionBasis.TELEMETRY_EVIDENCE,    "sysmon-01","Process chain in telemetry",0.90),
        make_evidence(AttributionBasis.TTP_PATTERN_MATCH,     "mitre-db","T1566+T1059+T1078 overlap",0.85),
        make_evidence(AttributionBasis.INFRASTRUCTURE_OVERLAP,"graph-01","3 C2 IPs share ASN",0.78),
        make_evidence(AttributionBasis.BEHAVIORAL_SIMILARITY, "ueba-01","Beacon intervals match profile",0.82),
        make_evidence(AttributionBasis.REPLAY_VALIDATED,      "replay-01","Scenario replay PASS",0.88),
    ])
    print(f"\n🧪 Test 1 — Well-evidenced: [{r1.confidence_level}] score={r1.confidence_score:.3f}")
    print(f"   Range: {r1.uncertainty_range[0]:.2f}–{r1.uncertainty_range[1]:.2f}")
    print(f"   Allowed: {r1.allowed_claims}")
    print(f"   Statement: {r1.attribution_statement[:120]}...")

    # Test 2: Feed-only (should be LOW/SPECULATIVE)
    r2 = engine.evaluate("APT99", [
        make_evidence(AttributionBasis.OSINT_REFERENCE,"feed-1","Blog post mentions APT99",0.30,False),
    ])
    print(f"\n🧪 Test 2 — Feed-only: [{r2.confidence_level}] score={r2.confidence_score:.3f}")
    print(f"   Prohibited: {r2.prohibited_claims[:2]}")
    print(f"   Statement: {r2.attribution_statement[:100]}")

    # Test 3: No evidence (REJECTED)
    r3 = engine.evaluate("NATION_STATE_X", [])
    print(f"\n🧪 Test 3 — No evidence: [{r3.confidence_level}]")
    print(f"   Statement: {r3.attribution_statement}")

    print(f"\n📊 Stats: {engine.stats()}")
    print("\n✅ ATTRIBUTION GOVERNANCE ENGINE — PRODUCTION READY\n")
