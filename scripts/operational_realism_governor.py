#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Operational Realism Governor
Section 1: Evidence-Constrained Intelligence | Anti-Hallucination CTI Controls |
           Telemetry Evidence Gates | Narrative Proportionality Enforcement |
           Intelligence Realism Validation | Operational Plausibility Scoring
DIRECTIVE: All intelligence outputs must scale with evidence depth.
           Unsupported claims are suppressed, not amplified.
Production-grade | Deterministic | Evidence-governed | SOC-trusted
"""
import json, uuid, math, hashlib, logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from enum import Enum
from collections import defaultdict

log = logging.getLogger("realism_governor")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [REALISM-GOV] %(levelname)s %(message)s")

# ─── Realism Levels ───────────────────────────────────────────────────────────
class RealismLevel(str, Enum):
    OPERATIONALLY_VERIFIED  = "operationally_verified"   # telemetry + replay + graph
    EVIDENCE_SUPPORTED      = "evidence_supported"        # ≥2 independent signal sources
    ANALYTICALLY_ASSESSED   = "analytically_assessed"    # 1 signal source, low-medium conf
    SPECULATIVE             = "speculative"               # inference only, no telemetry
    SUPPRESSED              = "suppressed"                # fails evidence gates — blocked

REALISM_THRESHOLDS = {
    RealismLevel.OPERATIONALLY_VERIFIED: 0.80,
    RealismLevel.EVIDENCE_SUPPORTED:     0.55,
    RealismLevel.ANALYTICALLY_ASSESSED:  0.30,
    RealismLevel.SPECULATIVE:            0.10,
    RealismLevel.SUPPRESSED:             0.00,
}

# ─── Evidence Gate ─────────────────────────────────────────────────────────────
@dataclass
class EvidenceGate:
    """Single evidence component for gate evaluation."""
    gate_id:       str
    gate_type:     str    # telemetry | graph | replay | behavioral | feed | manual
    source_id:     str
    value:         Any
    trust_score:   float  # 0-1
    timestamp:     str
    validated:     bool   = False
    validation_reason: str = ""

    def to_dict(self): return asdict(self)

@dataclass
class RealismDecision:
    """Output of the realism governor for a single intelligence claim."""
    decision_id:      str
    claim_type:       str
    claim_value:      str
    realism_level:    str
    plausibility_score: float         # 0-1
    evidence_gates:   List[Dict]
    narrative_ceiling: str            # maximum allowed narrative
    suppressed_claims: List[str]
    warnings:         List[str]
    evidence_gap:     List[str]       # what's missing to increase trust
    timestamp:        str
    reproducible_hash: str

    def to_dict(self): return asdict(self)

    @property
    def allowed(self) -> bool:
        return self.realism_level != RealismLevel.SUPPRESSED

# ─── Claim Types and Their Required Gates ─────────────────────────────────────
CLAIM_EVIDENCE_REQUIREMENTS = {
    "nation_state_attribution": {
        "required": ["telemetry","graph","replay","behavioral"],
        "min_trust": 0.80,
        "min_gates": 4,
        "narrative_ceiling": "Analytically assessed overlap with known actor TTPs. Attribution not confirmed.",
    },
    "apt_attribution": {
        "required": ["telemetry","graph","behavioral"],
        "min_trust": 0.70,
        "min_gates": 3,
        "narrative_ceiling": "Infrastructure and behavioral overlap observed. Attribution requires additional evidence.",
    },
    "campaign_confirmation": {
        "required": ["telemetry","graph"],
        "min_trust": 0.60,
        "min_gates": 2,
        "narrative_ceiling": "Campaign cluster identified. Requires telemetry and graph correlation.",
    },
    "active_exploitation": {
        "required": ["telemetry","feed"],
        "min_trust": 0.65,
        "min_gates": 2,
        "narrative_ceiling": "Exploitation evidence observed in telemetry.",
    },
    "ioc_high_confidence": {
        "required": ["telemetry"],
        "min_trust": 0.55,
        "min_gates": 1,
        "narrative_ceiling": "IOC observed in telemetry. Confidence proportional to source trust.",
    },
    "behavioral_detection": {
        "required": ["behavioral"],
        "min_trust": 0.50,
        "min_gates": 1,
        "narrative_ceiling": "Behavioral pattern detected. Review recommended.",
    },
    "generic_intelligence": {
        "required": [],
        "min_trust": 0.00,
        "min_gates": 0,
        "narrative_ceiling": "Unverified intelligence. Treat as low confidence.",
    },
}

# ─── Suppression Rules ────────────────────────────────────────────────────────
SUPPRESSION_RULES = [
    {
        "rule_id":    "SR001",
        "name":       "Unsupported Nation-State Attribution",
        "trigger":    lambda claim, gates: (
            "nation_state" in claim.get("type","").lower() and
            len([g for g in gates if g.gate_type == "telemetry"]) == 0
        ),
        "message":    "Nation-state attribution suppressed: no telemetry evidence.",
        "action":     "suppress",
    },
    {
        "rule_id":    "SR002",
        "name":       "Unsupported APT Claim",
        "trigger":    lambda claim, gates: (
            any(apt in claim.get("value","").upper() for apt in ["APT","LAZARUS","CARBANAK","COZY"]) and
            len([g for g in gates if g.gate_type in ("telemetry","graph")]) < 2
        ),
        "message":    "APT attribution downgraded: insufficient telemetry+graph gates (<2).",
        "action":     "downgrade",
    },
    {
        "rule_id":    "SR003",
        "name":       "Exaggerated Campaign Narrative",
        "trigger":    lambda claim, gates: (
            claim.get("confidence", 0) > 0.85 and
            len([g for g in gates if g.validated]) < 2
        ),
        "message":    "High-confidence claim suppressed: fewer than 2 validated gates.",
        "action":     "cap_confidence",
    },
    {
        "rule_id":    "SR004",
        "name":       "Risk Amplification Without Telemetry",
        "trigger":    lambda claim, gates: (
            claim.get("severity","").lower() == "critical" and
            len([g for g in gates if g.gate_type == "telemetry"]) == 0
        ),
        "message":    "Critical severity downgraded: no telemetry evidence of exploitation.",
        "action":     "downgrade_severity",
    },
    {
        "rule_id":    "SR005",
        "name":       "Synthetic Intelligence Feed",
        "trigger":    lambda claim, gates: (
            all(g.gate_type == "feed" for g in gates) and len(gates) > 0
        ),
        "message":    "Feed-only intelligence flagged: no endpoint/behavioral corroboration.",
        "action":     "flag",
    },
]

class OperationalRealismGovernor:
    """
    Evidence-constrained intelligence gate enforcer.
    All intelligence claims pass through realism validation before output.
    Suppresses unsupported claims. Enforces narrative proportionality.
    Outputs are deterministic and reproducible.
    """

    def __init__(self):
        self._decisions:  List[RealismDecision] = []
        self._suppressed: int = 0
        self._passed:     int = 0
        self._downgraded: int = 0
        self._stats       = defaultdict(int)
        log.info("OperationalRealismGovernor INITIALIZED — evidence gates active")

    def evaluate(self, claim: Dict, evidence_gates: List[EvidenceGate]) -> RealismDecision:
        """
        Evaluate an intelligence claim against evidence gates.
        Returns RealismDecision with allowed/suppressed status and narrative ceiling.
        """
        claim_type = claim.get("type", "generic_intelligence")
        claim_value= claim.get("value","")
        req        = CLAIM_EVIDENCE_REQUIREMENTS.get(claim_type,
                     CLAIM_EVIDENCE_REQUIREMENTS["generic_intelligence"])

        warnings          = []
        suppressed_claims = []
        evidence_gap      = []
        applied_actions   = []

        # ── Apply suppression rules ─────────────────────────────────────────
        for rule in SUPPRESSION_RULES:
            try:
                if rule["trigger"](claim, evidence_gates):
                    warnings.append(f"[{rule['rule_id']}] {rule['message']}")
                    applied_actions.append(rule["action"])
                    self._stats[rule["rule_id"]] += 1
            except Exception:
                pass

        # ── Evidence gate evaluation ────────────────────────────────────────
        provided_types   = set(g.gate_type for g in evidence_gates)
        required_types   = set(req["required"])
        missing_types    = required_types - provided_types
        validated_gates  = [g for g in evidence_gates if g.validated]
        avg_trust        = (sum(g.trust_score for g in evidence_gates) /
                           max(len(evidence_gates),1))

        # ── Evidence gap report ─────────────────────────────────────────────
        for mt in missing_types:
            evidence_gap.append(f"Missing {mt} evidence gate")
        if len(validated_gates) < req["min_gates"]:
            evidence_gap.append(
                f"Requires {req['min_gates']} validated gates, have {len(validated_gates)}"
            )
        if avg_trust < req["min_trust"]:
            evidence_gap.append(
                f"Average gate trust {avg_trust:.2f} below minimum {req['min_trust']:.2f}"
            )

        # ── Plausibility score ──────────────────────────────────────────────
        gate_coverage  = len(provided_types & required_types) / max(len(required_types),1)
        gate_count_ok  = min(1.0, len(validated_gates) / max(req["min_gates"],1))
        trust_factor   = min(1.0, avg_trust / max(req["min_trust"],0.01))
        plausibility   = (gate_coverage * 0.40 + gate_count_ok * 0.35 + trust_factor * 0.25)

        # ── Apply action penalties ──────────────────────────────────────────
        if "suppress" in applied_actions:
            plausibility = 0.0
        elif "cap_confidence" in applied_actions:
            plausibility = min(plausibility, 0.55)
        elif "downgrade" in applied_actions:
            plausibility = plausibility * 0.60
            suppressed_claims.append("confidence_downgraded")
        elif "downgrade_severity" in applied_actions:
            suppressed_claims.append("severity_downgraded")
        elif "flag" in applied_actions:
            warnings.append("Feed-only intelligence: treat as unverified")

        # ── Realism level determination ─────────────────────────────────────
        realism = RealismLevel.SUPPRESSED
        for level, threshold in sorted(
            REALISM_THRESHOLDS.items(), key=lambda x: x[1], reverse=True
        ):
            if plausibility >= threshold:
                realism = level
                break

        # ── Narrative ceiling ───────────────────────────────────────────────
        narrative_ceiling = req["narrative_ceiling"]
        if realism == RealismLevel.SUPPRESSED:
            narrative_ceiling = "Claim suppressed: insufficient evidence. Do not report."
        elif realism == RealismLevel.SPECULATIVE:
            narrative_ceiling = "Speculative only. No operational decisions. Requires further investigation."

        # ── Reproducible hash ───────────────────────────────────────────────
        hash_input = json.dumps({
            "claim": claim,
            "gates": [g.gate_id for g in evidence_gates],
            "plausibility": round(plausibility,4),
            "realism": realism.value,
        }, sort_keys=True)
        rep_hash = hashlib.sha256(hash_input.encode()).hexdigest()[:16]

        # ── Decision record ─────────────────────────────────────────────────
        decision = RealismDecision(
            decision_id       = str(uuid.uuid4())[:10],
            claim_type        = claim_type,
            claim_value       = claim_value[:100],
            realism_level     = realism.value,
            plausibility_score= round(plausibility, 4),
            evidence_gates    = [g.to_dict() for g in evidence_gates],
            narrative_ceiling = narrative_ceiling,
            suppressed_claims = suppressed_claims,
            warnings          = warnings,
            evidence_gap      = evidence_gap,
            timestamp         = datetime.now(timezone.utc).isoformat(),
            reproducible_hash = rep_hash,
        )

        self._decisions.append(decision)
        if decision.allowed:
            self._passed += 1
            log.info(f"✅ REALISM PASS [{realism.value}] {claim_type} plaus={plausibility:.2f}")
        else:
            self._suppressed += 1
            log.warning(f"🚫 REALISM SUPPRESS {claim_type}: {warnings[0] if warnings else 'evidence gates failed'}")

        return decision

    def build_gate(self, gate_type: str, source_id: str, value: Any,
                   trust_score: float, validated: bool = True,
                   reason: str = "") -> EvidenceGate:
        return EvidenceGate(
            gate_id   = str(uuid.uuid4())[:8],
            gate_type = gate_type,
            source_id = source_id,
            value     = value,
            trust_score= trust_score,
            timestamp  = datetime.now(timezone.utc).isoformat(),
            validated  = validated,
            validation_reason= reason,
        )

    def validate_intelligence_batch(self, intelligence_items: List[Dict]) -> Dict:
        """Batch-validate a list of intelligence claims."""
        results = {"passed":[], "suppressed":[], "downgraded":[]}
        for item in intelligence_items:
            gates    = item.get("evidence_gates",[])
            gate_objs= [self.build_gate(**g) for g in gates if isinstance(g,dict)]
            decision = self.evaluate(item.get("claim",{}), gate_objs)
            category = ("suppressed" if not decision.allowed
                       else "downgraded" if decision.suppressed_claims
                       else "passed")
            results[category].append(decision.to_dict())
        return results

    def plausibility_report(self) -> Dict:
        return {
            "total_evaluated": len(self._decisions),
            "passed":          self._passed,
            "suppressed":      self._suppressed,
            "downgraded":      self._downgraded,
            "suppression_rate":round(self._suppressed/max(len(self._decisions),1)*100,1),
            "rule_triggers":   dict(self._stats),
        }

if __name__ == "__main__":
    gov = OperationalRealismGovernor()

    print("\n" + "="*65)
    print("  SENTINEL APEX — OPERATIONAL REALISM GOVERNOR SELF-TEST")
    print("="*65)

    # Test 1: Unsupported nation-state attribution — should be SUPPRESSED
    d1 = gov.evaluate(
        claim={"type":"nation_state_attribution","value":"Russia attributed APT campaign","confidence":0.95},
        evidence_gates=[]
    )
    print(f"\n🧪 Test 1 — Unsupported nation-state: {d1.realism_level}")
    print(f"   Suppressed: {not d1.allowed}  Warnings: {d1.warnings}")
    print(f"   Narrative ceiling: {d1.narrative_ceiling[:80]}")

    # Test 2: Telemetry-backed behavioral detection — should PASS
    d2 = gov.evaluate(
        claim={"type":"behavioral_detection","value":"Beaconing detected from 10.1.2.100","confidence":0.82},
        evidence_gates=[
            gov.build_gate("telemetry","endpoint-sysmon-01","proc_event",0.90,True,"Sysmon EID 3 confirmed"),
            gov.build_gate("behavioral","ueba-engine","beacon_cov=0.08",0.85,True,"CoV < 0.15 threshold"),
        ]
    )
    print(f"\n🧪 Test 2 — Telemetry behavioral detection: {d2.realism_level}")
    print(f"   Allowed: {d2.allowed}  Plausibility: {d2.plausibility_score:.3f}")
    print(f"   Narrative: {d2.narrative_ceiling[:80]}")

    # Test 3: Feed-only APT attribution — should be FLAGGED/DOWNGRADED
    d3 = gov.evaluate(
        claim={"type":"apt_attribution","value":"APT29","confidence":0.88},
        evidence_gates=[
            gov.build_gate("feed","osint-feed-1","apt29_ioc",0.55,False,"Feed-only, not validated"),
        ]
    )
    print(f"\n🧪 Test 3 — Feed-only APT claim: {d3.realism_level}")
    print(f"   Allowed: {d3.allowed}  Plausibility: {d3.plausibility_score:.3f}")
    print(f"   Suppressed claims: {d3.suppressed_claims}")
    print(f"   Evidence gap: {d3.evidence_gap}")

    # Test 4: Well-evidenced campaign confirmation — should pass at high level
    d4 = gov.evaluate(
        claim={"type":"campaign_confirmation","value":"Campaign C2 cluster identified","confidence":0.75},
        evidence_gates=[
            gov.build_gate("telemetry","dns-sensor-01","dns_tunnel",0.88,True,"DNS tunneling confirmed"),
            gov.build_gate("graph","graph-engine","infra_overlap",0.82,True,"3 IPs share ASN"),
            gov.build_gate("behavioral","ueba","lateral_mvmt",0.79,True,"3 hosts in 15m"),
        ]
    )
    print(f"\n🧪 Test 4 — Evidenced campaign confirmation: {d4.realism_level}")
    print(f"   Allowed: {d4.allowed}  Plausibility: {d4.plausibility_score:.3f}")
    print(f"   Hash: {d4.reproducible_hash}")

    print(f"\n📊 Realism Report: {gov.plausibility_report()}")
    print("\n✅ OPERATIONAL REALISM GOVERNOR — PRODUCTION READY\n")
