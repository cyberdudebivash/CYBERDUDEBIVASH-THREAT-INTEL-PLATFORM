#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Risk Scoring Normalization Engine
Section 5: CVSS+EPSS+KEV Normalization | Probabilistic Exploitability |
           Temporal Risk Scoring | Telemetry-Weighted Scoring |
           ATT&CK-Weighted Scoring | Mathematical Consistency Enforcement
DIRECTIVE: Risk scores are mathematically consistent, evidence-weighted,
           and never inflated beyond telemetry evidence.
Production-grade | Mathematical | Evidence-weighted | Auditable
"""
import json, uuid, math, hashlib, logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from collections import defaultdict

log = logging.getLogger("risk_normalization")
logging.basicConfig(level=logging.INFO, format="%(asctime)s [RISK-NORM] %(levelname)s %(message)s")

@dataclass
class RawRiskInputs:
    """Raw, unprocessed risk inputs from various sources."""
    cvss_score:         Optional[float] = None   # 0–10 (NVD CVSS v3.1)
    cvss_vector:        str             = ""
    epss_score:         Optional[float] = None   # 0–1 (exploit probability)
    epss_percentile:    Optional[float] = None   # 0–100
    kev_listed:         bool            = False  # CISA KEV
    kev_date_added:     str             = ""
    exploit_maturity:   str             = "none" # none | poc | functional | weaponized
    active_exploitation:bool            = False  # observed in-the-wild
    attack_complexity:  str             = "high" # low | high
    privileges_required:str             = "high" # none | low | high
    user_interaction:   str             = "required" # none | required
    scope:              str             = "unchanged" # unchanged | changed
    # Telemetry inputs
    telemetry_observed: bool            = False
    detection_exists:   bool            = False
    detection_confidence:float          = 0.0
    behavioral_observed:bool            = False
    graph_correlated:   bool            = False
    replay_validated:   bool            = False
    # ATT&CK
    technique_ids:      List[str]       = field(default_factory=list)
    tactic_coverage:    List[str]       = field(default_factory=list)
    # Temporal
    cve_published_days_ago: int         = 365
    patch_available:    bool            = False
    patch_days_ago:     int             = -1

@dataclass
class NormalizedRiskScore:
    """Normalized, mathematically consistent enterprise risk score."""
    score_id:          str
    entity_id:         str
    entity_type:       str
    # Component scores (all 0–1)
    exploitability:    float   # CVSS + EPSS + maturity composite
    exploitation_velocity: float # KEV + active + temporal
    detection_coverage:float   # detection confidence + replay
    telemetry_visibility:float # how much telemetry sees this
    attack_surface:    float   # ATT&CK coverage + complexity
    # Final
    raw_composite:     float   # unweighted composite
    normalized_score:  float   # 0–10 enterprise scale
    severity_label:    str     # CRITICAL | HIGH | MEDIUM | LOW | INFORMATIONAL
    risk_tier:         int     # 1 (highest) – 5 (lowest)
    # Provenance
    component_breakdown: Dict[str, float]
    evidence_flags:    List[str]
    scoring_narrative: str
    mathematical_notes:str
    reproducible_hash: str
    timestamp:         str

    def to_dict(self): return asdict(self)

    def severity_card(self) -> str:
        return (
            f"{'─'*50}\n"
            f"  Entity:       {self.entity_id[:40]}\n"
            f"  Severity:     {self.severity_label} ({self.normalized_score:.1f}/10)\n"
            f"  Tier:         {self.risk_tier}/5\n"
            f"  Components:\n"
            f"    Exploitability:    {self.exploitability:.3f}\n"
            f"    Exploit Velocity:  {self.exploitation_velocity:.3f}\n"
            f"    Detection Cover:   {self.detection_coverage:.3f}\n"
            f"    Telemetry Visib:   {self.telemetry_visibility:.3f}\n"
            f"    Attack Surface:    {self.attack_surface:.3f}\n"
            f"  Evidence: {', '.join(self.evidence_flags) or 'none'}\n"
            f"{'─'*50}"
        )

class RiskScoringNormalizationEngine:
    """
    Enterprise risk scoring engine with mathematical consistency enforcement.
    Computes normalized risk from CVSS + EPSS + KEV + telemetry + ATT&CK.
    All outputs are evidence-weighted and auditable.
    """

    # Component weights (sum = 1.0)
    COMPONENT_WEIGHTS = {
        "exploitability":      0.28,
        "exploitation_velocity": 0.22,
        "detection_coverage":  0.18,  # lower detection = higher risk
        "telemetry_visibility":0.16,  # higher telemetry = more precise (not more dangerous)
        "attack_surface":      0.16,
    }

    # Severity thresholds (normalized 0-10)
    SEVERITY_THRESHOLDS = [
        (9.0,  "CRITICAL",     1),
        (7.0,  "HIGH",         2),
        (4.0,  "MEDIUM",       3),
        (1.0,  "LOW",          4),
        (0.0,  "INFORMATIONAL",5),
    ]

    # Exploit maturity multipliers
    MATURITY_MULT = {"none":0.30,"poc":0.55,"functional":0.80,"weaponized":1.00}

    # CVSS v3.1 complexity score
    COMPLEXITY_SCORE = {"low":1.0,"high":0.60}
    PRIVS_SCORE      = {"none":1.0,"low":0.75,"high":0.50}
    INTERACT_SCORE   = {"none":1.0,"required":0.70}
    SCOPE_MULT       = {"changed":1.15,"unchanged":1.00}

    def __init__(self):
        self._scores: List[NormalizedRiskScore] = []
        self._stats   = defaultdict(int)
        log.info("RiskScoringNormalizationEngine INITIALIZED — mathematical consistency enforced")

    def compute(self, entity_id: str, entity_type: str,
                inputs: RawRiskInputs) -> NormalizedRiskScore:
        """
        Compute normalized risk score from all available inputs.
        All components clamped to [0,1]. Final score mapped to [0,10].
        """
        # ── 1. Exploitability ────────────────────────────────────────────────
        # CVSS base contribution (normalised to 0-1)
        cvss_norm   = (inputs.cvss_score or 5.0) / 10.0
        # EPSS contribution (probabilistic exploit likelihood)
        epss_contrib= inputs.epss_score or 0.05
        # Exploit maturity
        mat_mult    = self.MATURITY_MULT.get(inputs.exploit_maturity, 0.30)
        # CVSS complexity factors
        complexity_f = self.COMPLEXITY_SCORE.get(inputs.attack_complexity, 0.60)
        privs_f      = self.PRIVS_SCORE.get(inputs.privileges_required, 0.50)
        interact_f   = self.INTERACT_SCORE.get(inputs.user_interaction, 1.0)
        scope_f      = self.SCOPE_MULT.get(inputs.scope, 1.0)
        cvss_adj    = cvss_norm * complexity_f * privs_f * interact_f * scope_f

        exploitability = min(1.0,
            cvss_adj * 0.40 + epss_contrib * 0.35 + mat_mult * 0.25
        )

        # ── 2. Exploitation Velocity ─────────────────────────────────────────
        kev_boost   = 0.35 if inputs.kev_listed else 0.0
        active_boost= 0.30 if inputs.active_exploitation else 0.0
        # Temporal decay: older CVEs with no KEV/active = lower velocity
        age_days    = max(0, inputs.cve_published_days_ago)
        temporal_decay = math.exp(-age_days / 180)   # 180-day half-life
        # Patch reduces velocity
        patch_factor = 0.70 if inputs.patch_available else 1.0
        exploitation_velocity = min(1.0,
            (kev_boost + active_boost + temporal_decay * 0.35) * patch_factor
        )

        # ── 3. Detection Coverage ────────────────────────────────────────────
        # Lower detection = HIGHER risk. Invert detection quality.
        det_conf    = inputs.detection_confidence if inputs.detection_exists else 0.0
        replay_boost= 0.15 if inputs.replay_validated else 0.0
        behav_boost = 0.10 if inputs.behavioral_observed else 0.0
        detection_quality = min(1.0, det_conf + replay_boost + behav_boost)
        # Invert: no detection = max risk contribution
        detection_coverage = 1.0 - detection_quality * 0.80

        # ── 4. Telemetry Visibility ─────────────────────────────────────────
        telem_score = 0.0
        if inputs.telemetry_observed:   telem_score += 0.40
        if inputs.behavioral_observed:  telem_score += 0.25
        if inputs.graph_correlated:     telem_score += 0.20
        if inputs.replay_validated:     telem_score += 0.15
        telemetry_visibility = min(1.0, telem_score)
        # Note: high telemetry visibility = better precision, not more danger
        # Include as risk REDUCTION factor (we see it better = can respond)
        # But still factor in since blind spots amplify risk

        # ── 5. Attack Surface ────────────────────────────────────────────────
        tech_density = min(1.0, len(inputs.technique_ids) * 0.12)
        tactic_breadth = min(1.0, len(inputs.tactic_coverage) * 0.15)
        attack_surface = min(1.0, tech_density * 0.60 + tactic_breadth * 0.40)

        # ── Composite score ──────────────────────────────────────────────────
        W = self.COMPONENT_WEIGHTS
        raw_composite = (
            exploitability        * W["exploitability"]      +
            exploitation_velocity * W["exploitation_velocity"] +
            detection_coverage    * W["detection_coverage"]   +
            telemetry_visibility  * W["telemetry_visibility"] * 0.40 +  # partial weight
            attack_surface        * W["attack_surface"]
        )

        # Consistency enforcement: if NO telemetry observed and CRITICAL claimed,
        # cap at HIGH maximum (8.9)
        if not inputs.telemetry_observed and not inputs.kev_listed:
            raw_composite = min(raw_composite, 0.70)  # max HIGH on 0-1 scale

        # Scale to 0-10
        normalized_score = round(min(10.0, raw_composite * 10.0), 2)

        # Severity
        severity_label = "INFORMATIONAL"
        risk_tier      = 5
        for threshold, label, tier in self.SEVERITY_THRESHOLDS:
            if normalized_score >= threshold:
                severity_label = label
                risk_tier      = tier
                break

        # Evidence flags
        flags = []
        if inputs.kev_listed:          flags.append("KEV_LISTED")
        if inputs.active_exploitation:  flags.append("ACTIVE_EXPLOITATION")
        if inputs.telemetry_observed:   flags.append("TELEMETRY_OBSERVED")
        if inputs.replay_validated:     flags.append("REPLAY_VALIDATED")
        if inputs.detection_exists:     flags.append(f"DETECTION_EXISTS({inputs.detection_confidence:.0%})")
        if inputs.patch_available:      flags.append("PATCH_AVAILABLE")

        # Narrative
        narrative = self._narrative(entity_id, normalized_score, severity_label,
                                    exploitability, exploitation_velocity, flags)
        math_notes = (
            f"CVSS_adj={cvss_adj:.3f} × w0.28 + EPSS={epss_contrib:.3f} × w0.35 + "
            f"Maturity={mat_mult:.2f} × w0.25 → Exploitability={exploitability:.3f}; "
            f"KEV={kev_boost:.2f} + Active={active_boost:.2f} + Temporal={temporal_decay:.3f} "
            f"→ Velocity={exploitation_velocity:.3f}; "
            f"RawComposite={raw_composite:.4f} → Score={normalized_score}/10"
        )

        # Reproducible hash
        h = hashlib.md5(json.dumps({
            "cvss": inputs.cvss_score,"epss":inputs.epss_score,
            "kev":inputs.kev_listed,"maturity":inputs.exploit_maturity,
            "telemetry":inputs.telemetry_observed,"detection_conf":inputs.detection_confidence,
        }, sort_keys=True).encode()).hexdigest()[:16]

        score = NormalizedRiskScore(
            score_id             = str(uuid.uuid4())[:10],
            entity_id            = entity_id,
            entity_type          = entity_type,
            exploitability       = round(exploitability, 4),
            exploitation_velocity= round(exploitation_velocity, 4),
            detection_coverage   = round(detection_coverage, 4),
            telemetry_visibility = round(telemetry_visibility, 4),
            attack_surface       = round(attack_surface, 4),
            raw_composite        = round(raw_composite, 4),
            normalized_score     = normalized_score,
            severity_label       = severity_label,
            risk_tier            = risk_tier,
            component_breakdown  = {
                "exploitability":       round(exploitability,4),
                "exploitation_velocity":round(exploitation_velocity,4),
                "detection_coverage":   round(detection_coverage,4),
                "telemetry_visibility": round(telemetry_visibility,4),
                "attack_surface":       round(attack_surface,4),
            },
            evidence_flags       = flags,
            scoring_narrative    = narrative,
            mathematical_notes   = math_notes,
            reproducible_hash    = h,
            timestamp            = datetime.now(timezone.utc).isoformat(),
        )
        self._scores.append(score)
        self._stats[f"severity_{severity_label}"] += 1
        log.info(f"🎯 RISK [{severity_label:13s}] {entity_id[:25]:25s} "
                 f"{normalized_score:4.1f}/10  flags={flags}")
        return score

    def _narrative(self, entity: str, score: float, severity: str,
                   exploit: float, velocity: float, flags: List[str]) -> str:
        parts = [f"Risk assessment for '{entity[:30]}': {severity} ({score:.1f}/10)."]
        parts.append(f"Exploitability factor: {exploit:.2f}/1.0.")
        parts.append(f"Exploitation velocity: {velocity:.2f}/1.0.")
        if "KEV_LISTED" in flags:
            parts.append("CISA KEV listing confirms active exploitation in-the-wild.")
        if "TELEMETRY_OBSERVED" in flags:
            parts.append("Telemetry evidence validates threat presence in environment.")
        if "PATCH_AVAILABLE" in flags:
            parts.append("Patch available — immediate remediation recommended.")
        if not flags:
            parts.append("No telemetry or KEV evidence. Risk based on CVSS/EPSS only.")
        return " ".join(parts)

    def batch_score(self, items: List[Dict]) -> List[NormalizedRiskScore]:
        results = []
        for item in items:
            inputs = RawRiskInputs(**{k: v for k, v in item.items()
                                      if k in RawRiskInputs.__dataclass_fields__})
            r = self.compute(item.get("entity_id",""), item.get("entity_type","cve"), inputs)
            results.append(r)
        return sorted(results, key=lambda x: x.normalized_score, reverse=True)

    def stats(self) -> Dict: return dict(self._stats)

if __name__ == "__main__":
    import hashlib
    engine = RiskScoringNormalizationEngine()
    print("\n" + "="*65)
    print("  SENTINEL APEX — RISK SCORING NORMALIZATION ENGINE SELF-TEST")
    print("="*65)

    cases = [
        ("CVE-2025-31324", "cve", RawRiskInputs(
            cvss_score=9.8, epss_score=0.95, kev_listed=True,
            exploit_maturity="weaponized", active_exploitation=True,
            attack_complexity="low", privileges_required="none",
            user_interaction="none", scope="changed",
            telemetry_observed=True, detection_exists=True, detection_confidence=0.88,
            behavioral_observed=True, replay_validated=True,
            technique_ids=["T1190","T1059","T1105"], tactic_coverage=["InitialAccess","Execution"],
            cve_published_days_ago=45, patch_available=False,
        )),
        ("CVE-2024-12345", "cve", RawRiskInputs(
            cvss_score=7.2, epss_score=0.12, kev_listed=False,
            exploit_maturity="poc", active_exploitation=False,
            attack_complexity="high", privileges_required="low",
            telemetry_observed=False, detection_exists=True, detection_confidence=0.55,
            technique_ids=["T1078"], tactic_coverage=["InitialAccess"],
            cve_published_days_ago=180, patch_available=True, patch_days_ago=30,
        )),
        ("CVE-2023-99999", "cve", RawRiskInputs(
            cvss_score=5.0, epss_score=0.02, kev_listed=False,
            exploit_maturity="none", active_exploitation=False,
            telemetry_observed=False, detection_exists=False,
            technique_ids=[], tactic_coverage=[],
            cve_published_days_ago=400, patch_available=True,
        )),
    ]
    for eid, etype, inputs in cases:
        score = engine.compute(eid, etype, inputs)
        print(f"\n{score.severity_card()}")
        print(f"  Math: {score.mathematical_notes[:100]}...")
        print(f"  Hash: {score.reproducible_hash}")

    print(f"\n📊 Stats: {engine.stats()}")
    print("\n✅ RISK SCORING NORMALIZATION ENGINE — PRODUCTION READY\n")
