# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX
# agent/risk_narrative_scaler.py
# RISK NARRATIVE SCALER v1.0
# P0 FIX #3 — Risk Scoring Realism + Severity-Aware Narrative
# Production-safe | Non-blocking | Deterministic | KEV-aware
# =============================================================================
"""
Risk Narrative Scaler — Eliminates narrative/severity mismatch.

CORE PROBLEM FIXED:
  LOW severity CVEs (risk 0.47–1.82/10, no KEV, no EPSS) were receiving:
    - "board-level cyber risk event" language
    - "$878,400 most likely loss" financial projections
    - "emergency patching" directives
    - CISO escalation language
    - Nation-state APT framing
    - Ransomware escalation predictions
  This is OPERATIONALLY WRONG and destroys SOC analyst trust.

NARRATIVE SCALING RULES:
  ┌─────────────┬─────────────────────────────────────────────────────┐
  │ SEVERITY    │ NARRATIVE RULES                                      │
  ├─────────────┼─────────────────────────────────────────────────────┤
  │ LOW         │ Concise (≤150 words). No financial models.           │
  │ (risk <3.0) │ No board language. No geopolitics. No ransomware.   │
  │             │ Action: "Monitor & patch in next maintenance cycle"  │
  ├─────────────┼─────────────────────────────────────────────────────┤
  │ MEDIUM      │ Standard (≤300 words). Financial estimates OK.       │
  │ (risk 3–6)  │ No board language. SOC-level escalation.            │
  │             │ Action: "Assess exposure. Patch within 30 days."     │
  ├─────────────┼─────────────────────────────────────────────────────┤
  │ HIGH        │ Full dossier (≤500 words). CISO notification.        │
  │ (risk 6–8)  │ Financial quantification. Executive brief.           │
  │             │ Action: "Emergency patch + detection deployment."     │
  ├─────────────┼─────────────────────────────────────────────────────┤
  │ CRITICAL    │ Full strategic dossier (unlimited). Board language.  │
  │ (risk >8 OR │ Geopolitics if attribution exists. Full financial.   │
  │  KEV + RCE) │ Action: "IMMEDIATE — P0 INCIDENT RESPONSE."         │
  └─────────────┴─────────────────────────────────────────────────────┘

KEV-AWARE PRIORITIZATION:
  KEV = CISA Known Exploited Vulnerability. When KEV is confirmed:
    - Automatically promotes to HIGH minimum (even if CVSS is low)
    - Enables emergency patch language
    - Enables SOC-level escalation
    - 72-hour patch SLA applied
    - Detection engineering pack required

EXPLOITABILITY WEIGHTING:
  Severity-adjusted risk = base_risk × exploitation_multiplier
    - Active in-the-wild:  ×1.8 (immediate escalation)
    - KEV listed:          ×1.5 (confirmed exploitation risk)
    - EPSS > 30%:          ×1.3 (high exploitation probability)
    - EPSS > 10%:          ×1.15
    - Public PoC:          ×1.1
    - No EPSS data:        ×1.0 (no bonus — evidence absent)

BUSINESS IMPACT RULES:
  LOW severity → Business impact = "Informational tracking only"
    - Do NOT generate: "$X million exposure" figures
    - Do NOT generate: "3.4× risk multiplier" tables
    - Do NOT generate: "cyber-insurance disclosure" language
  HIGH/CRITICAL → Full financial quantification appropriate

WRITES:
  data/quality/narrative_scale_audit.jsonl
"""

from __future__ import annotations

import json
import logging
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.risk_narrative_scaler")

BASE_DIR  = Path(__file__).resolve().parent.parent
QUAL_DIR  = BASE_DIR / "data" / "quality"
AUDIT_LOG = QUAL_DIR / "narrative_scale_audit.jsonl"


# ── NARRATIVE SCALE TIERS ─────────────────────────────────────────────────────

@dataclass
class NarrativeScale:
    """Defines the narrative constraints for a risk tier."""
    tier:                  str
    label:                 str
    max_words:             int
    soc_action:            str
    patch_sla_hours:       int
    allow_financial:       bool
    allow_board_language:  bool
    allow_ciso_language:   bool
    allow_geopolitical:    bool
    allow_ransomware_framing: bool
    allow_apt_framing:     bool
    allow_emergency_patch: bool
    allow_breach_cost:     bool
    priority_label:        str
    icon:                  str
    business_impact_text:  str
    default_action_text:   str


NARRATIVE_SCALES: Dict[str, NarrativeScale] = {
    "LOW": NarrativeScale(
        tier="LOW", label="Informational Advisory",
        max_words=150, patch_sla_hours=720,  # 30 days
        soc_action="Monitor & log. Include in next maintenance patching cycle.",
        allow_financial=False,
        allow_board_language=False,
        allow_ciso_language=False,
        allow_geopolitical=False,
        allow_ransomware_framing=False,
        allow_apt_framing=False,
        allow_emergency_patch=False,
        allow_breach_cost=False,
        priority_label="P4 — INFORMATIONAL",
        icon="🔵",
        business_impact_text="Low-severity vulnerability. Informational tracking only. "
                             "No immediate operational impact expected.",
        default_action_text="Assess affected versions in your asset inventory. "
                            "Schedule patch in next standard maintenance window. "
                            "No emergency action required.",
    ),
    "MEDIUM": NarrativeScale(
        tier="MEDIUM", label="Standard Advisory",
        max_words=300, patch_sla_hours=168,  # 7 days
        soc_action="Assess exposure. Validate compensating controls. Patch within 7 days.",
        allow_financial=True,   # Estimates OK, not alarming
        allow_board_language=False,
        allow_ciso_language=False,
        allow_geopolitical=False,
        allow_ransomware_framing=False,
        allow_apt_framing=False,
        allow_emergency_patch=False,
        allow_breach_cost=True,   # Conservative estimates only
        priority_label="P3 — ACTIVE MONITORING",
        icon="🟡",
        business_impact_text="Medium-severity vulnerability. Exposure assessment and "
                             "compensating control review recommended.",
        default_action_text="Identify all affected assets. Apply vendor patch within 7 days. "
                            "Deploy detection rules. Review compensating controls.",
    ),
    "HIGH": NarrativeScale(
        tier="HIGH", label="High Severity — Escalate",
        max_words=500, patch_sla_hours=72,  # 72 hours
        soc_action="ESCALATE TO CISO. Emergency patch within 72 hours. Deploy detection pack.",
        allow_financial=True,
        allow_board_language=False,
        allow_ciso_language=True,
        allow_geopolitical=False,
        allow_ransomware_framing=True,
        allow_apt_framing=True,
        allow_emergency_patch=True,
        allow_breach_cost=True,
        priority_label="P2 — IMMEDIATE RESPONSE",
        icon="🟠",
        business_impact_text="High-severity vulnerability with significant exploitation risk. "
                             "CISO notification required. Emergency patch cycle activated.",
        default_action_text="Notify CISO immediately. Deploy emergency patch within 72 hours. "
                            "Activate detection engineering pack. Hunt for exploitation evidence "
                            "in 30-day SIEM retention.",
    ),
    "CRITICAL": NarrativeScale(
        tier="CRITICAL", label="CRITICAL — Immediate Incident Response",
        max_words=9999, patch_sla_hours=24,  # 24 hours
        soc_action="P0 INCIDENT RESPONSE. Patch IMMEDIATELY. Board notification if exploited.",
        allow_financial=True,
        allow_board_language=True,
        allow_ciso_language=True,
        allow_geopolitical=True,
        allow_ransomware_framing=True,
        allow_apt_framing=True,
        allow_emergency_patch=True,
        allow_breach_cost=True,
        priority_label="P0 — CRITICAL / IMMEDIATE",
        icon="🔴",
        business_impact_text="CRITICAL vulnerability with confirmed or imminent exploitation. "
                             "Full incident response posture. Board-level reporting required.",
        default_action_text="IMMEDIATE: Activate IR protocol. Emergency patch NOW. "
                            "Isolate affected systems. Notify CISO + Board if exploited. "
                            "Deploy full detection pack. 24-hour SLA.",
    ),
}


# ── RISK CALIBRATION ENGINE ───────────────────────────────────────────────────

@dataclass
class CalibratedRisk:
    """Result of risk + narrative calibration for one advisory."""
    advisory_id:            str
    raw_risk_score:         float
    calibrated_risk_score:  float
    narrative_tier:         str    # "LOW", "MEDIUM", "HIGH", "CRITICAL"
    narrative_scale:        NarrativeScale = field(repr=False)
    exploitation_multiplier: float = 1.0
    kev_promoted:           bool  = False
    kev_promotion_reason:   str   = ""
    narrative_guards:       Dict  = field(default_factory=dict)
    calibration_flags:      List[str] = field(default_factory=list)
    calibrated_at:          str   = ""

    def to_dict(self) -> Dict:
        d = {
            "advisory_id":            self.advisory_id,
            "raw_risk_score":         self.raw_risk_score,
            "calibrated_risk_score":  self.calibrated_risk_score,
            "narrative_tier":         self.narrative_tier,
            "exploitation_multiplier": self.exploitation_multiplier,
            "kev_promoted":           self.kev_promoted,
            "kev_promotion_reason":   self.kev_promotion_reason,
            "narrative_guards":       self.narrative_guards,
            "calibration_flags":      self.calibration_flags,
            "patch_sla_hours":        self.narrative_scale.patch_sla_hours,
            "soc_action":             self.narrative_scale.soc_action,
            "priority_label":         self.narrative_scale.priority_label,
            "default_action_text":    self.narrative_scale.default_action_text,
            "business_impact_text":   self.narrative_scale.business_impact_text,
            "allow_financial":        self.narrative_scale.allow_financial,
            "allow_board_language":   self.narrative_scale.allow_board_language,
            "allow_ciso_language":    self.narrative_scale.allow_ciso_language,
            "allow_breach_cost":      self.narrative_scale.allow_breach_cost,
            "calibrated_at":          self.calibrated_at,
        }
        return d

    def get_soc_summary(self) -> str:
        """Returns a concise SOC-facing risk summary."""
        icon = self.narrative_scale.icon
        lines = [
            f"{icon} {self.narrative_scale.priority_label}",
            f"Raw Risk: {self.raw_risk_score:.2f}/10 → "
            f"Calibrated: {self.calibrated_risk_score:.2f}/10"
            + (f" (×{self.exploitation_multiplier:.2f} exploit weight)" if self.exploitation_multiplier > 1.0 else ""),
        ]
        if self.kev_promoted:
            lines.append(f"⚠ KEV PROMOTION: {self.kev_promotion_reason}")
        lines.append(f"ACTION: {self.narrative_scale.soc_action}")
        if self.calibration_flags:
            lines.append(f"FLAGS: {' | '.join(self.calibration_flags[:3])}")
        return "\n".join(lines)


class RiskNarrativeScaler:
    """
    Severity-aware risk calibration + narrative guard engine.

    Ensures:
      1. Risk scores are exploitability-weighted (KEV, EPSS, active exploit)
      2. Narrative language matches evidence severity — LOW stays concise
      3. No board/CISO language for LOW advisories
      4. No financial models for LOW advisories
      5. KEV advisory promotion to minimum HIGH
      6. Business impact text scales with actual severity
    """

    def calibrate(self, advisory: Dict[str, Any]) -> CalibratedRisk:
        """
        Calibrate risk score + narrative tier for one advisory.

        Returns CalibratedRisk with all narrative guards set.
        """
        adv_id     = advisory.get("id") or advisory.get("stix_id") or "unknown"
        raw_risk   = float(advisory.get("risk_score", 0.0) or 0.0)
        cvss       = float(advisory.get("cvss_score", 0.0) or 0.0)
        epss       = float(advisory.get("epss_score", 0.0) or 0.0)
        kev        = self._parse_bool(advisory.get("kev", False))
        active     = advisory.get("active_exploit", False)
        severity   = str(advisory.get("severity", "LOW")).upper()
        poc_public = self._detect_poc(advisory)
        flags:     List[str] = []

        # ── Step 1: Exploitation Multiplier ──────────────────────────────────
        mult = 1.0
        if self._parse_bool(active):
            mult = max(mult, 1.8)
            flags.append("ACTIVE_EXPLOITATION_CONFIRMED")
        if kev:
            mult = max(mult, 1.5)
            flags.append("KEV_CONFIRMED")
        if epss > 0.30:
            mult = max(mult, 1.3)
            flags.append(f"EPSS_HIGH:{epss:.0%}")
        elif epss > 0.10:
            mult = max(mult, 1.15)
            flags.append(f"EPSS_MEDIUM:{epss:.0%}")
        if poc_public:
            mult = max(mult, 1.1)
            flags.append("PUBLIC_POC_DETECTED")
        if cvss >= 9.0:
            mult = max(mult, 1.2)
            flags.append(f"CVSS_CRITICAL:{cvss:.1f}")
        elif cvss >= 7.5:
            mult = max(mult, 1.1)
            flags.append(f"CVSS_HIGH:{cvss:.1f}")

        calibrated_risk = min(10.0, round(raw_risk * mult, 2))

        # ── Step 2: Determine Narrative Tier ─────────────────────────────────
        # Start from CVSS-informed base
        if cvss >= 9.0 or calibrated_risk >= 8.5:
            tier = "CRITICAL"
        elif cvss >= 7.0 or calibrated_risk >= 6.0:
            tier = "HIGH"
        elif cvss >= 4.0 or calibrated_risk >= 3.0:
            tier = "MEDIUM"
        else:
            tier = "LOW"

        # Override from severity field if more specific
        sev_map = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "MEDIUM": "MEDIUM", "LOW": "LOW"}
        declared_tier = sev_map.get(severity, "LOW")

        # Take the higher of computed vs declared
        tier_order = ["LOW", "MEDIUM", "HIGH", "CRITICAL"]
        final_tier = tier_order[max(tier_order.index(tier), tier_order.index(declared_tier))]

        # ── Step 3: KEV Promotion ─────────────────────────────────────────────
        kev_promoted = False
        kev_reason   = ""
        if kev and tier_order.index(final_tier) < tier_order.index("HIGH"):
            final_tier   = "HIGH"
            kev_promoted = True
            kev_reason   = ("CISA KEV listing confirms active exploitation in the wild. "
                           "Minimum advisory tier promoted to HIGH. "
                           "72-hour emergency patch SLA applies.")
            flags.append("KEV_TIER_PROMOTED_TO_HIGH")

        # ── Step 4: Build Narrative Guards ───────────────────────────────────
        scale = NARRATIVE_SCALES[final_tier]
        guards = {
            "allow_financial":            scale.allow_financial,
            "allow_board_language":       scale.allow_board_language,
            "allow_ciso_language":        scale.allow_ciso_language,
            "allow_geopolitical":         scale.allow_geopolitical,
            "allow_ransomware_framing":   scale.allow_ransomware_framing,
            "allow_apt_framing":          scale.allow_apt_framing,
            "allow_emergency_patch":      scale.allow_emergency_patch,
            "allow_breach_cost":          scale.allow_breach_cost,
            "max_narrative_words":        scale.max_words,
            "patch_sla_hours":            scale.patch_sla_hours,
        }

        # LOW-specific hard suppressions
        if final_tier == "LOW":
            suppressed = [
                "SUPPRESS_BOARD_LANGUAGE",
                "SUPPRESS_FINANCIAL_PROJECTIONS",
                "SUPPRESS_CISO_ESCALATION",
                "SUPPRESS_GEOPOLITICAL_FRAMING",
                "SUPPRESS_RANSOMWARE_NARRATIVE",
                "SUPPRESS_APT_ATTRIBUTION_LANGUAGE",
                "SUPPRESS_EMERGENCY_PATCH_DIRECTIVE",
            ]
            flags.extend(suppressed)

        result = CalibratedRisk(
            advisory_id=adv_id,
            raw_risk_score=raw_risk,
            calibrated_risk_score=calibrated_risk,
            narrative_tier=final_tier,
            narrative_scale=scale,
            exploitation_multiplier=mult,
            kev_promoted=kev_promoted,
            kev_promotion_reason=kev_reason,
            narrative_guards=guards,
            calibration_flags=flags,
            calibrated_at=datetime.now(timezone.utc).isoformat(),
        )

        self._log(result)
        return result

    def calibrate_batch(self, advisories: List[Dict[str, Any]]) -> List[CalibratedRisk]:
        return [self.calibrate(a) for a in advisories]

    def get_business_impact_text(self, cal: CalibratedRisk, advisory: Dict) -> str:
        """
        Returns severity-scaled business impact text.
        LOW advisories get concise tracking language only — no inflated projections.
        """
        scale = cal.narrative_scale
        base_text = scale.business_impact_text

        if not scale.allow_financial:
            return (
                f"{base_text}\n"
                f"Financial quantification not applicable at this severity tier. "
                f"No emergency patching cost model required."
            )

        # For MEDIUM+ tiers, add appropriate financial framing
        cvss = float(advisory.get("cvss_score", 0.0) or 0.0)
        if cvss >= 9.0:
            financial = "Potential breach cost: $2M–$10M (sector-dependent). Immediate action required."
        elif cvss >= 7.0:
            financial = "Potential breach cost: $500K–$2M if exploited. Emergency remediation advised."
        else:
            financial = "Potential breach cost: $50K–$500K if exploited. Standard remediation timeline."

        return f"{base_text}\n{financial}"

    def _detect_poc(self, advisory: Dict) -> bool:
        """Detect public PoC availability from advisory text."""
        text = (str(advisory.get("title", "")) + " " +
                str(advisory.get("description", ""))).lower()
        poc_signals = ["proof of concept", "poc available", "exploit code",
                       "metasploit module", "exploit-db", "github.com/exploit"]
        return any(sig in text for sig in poc_signals)

    def _parse_bool(self, val: Any) -> bool:
        if isinstance(val, bool):
            return val
        return str(val).upper() in ("YES", "TRUE", "1", "ACTIVE")

    def _log(self, cal: CalibratedRisk) -> None:
        try:
            AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
            record = {
                "advisory_id":           cal.advisory_id,
                "raw_risk":              cal.raw_risk_score,
                "calibrated_risk":       cal.calibrated_risk_score,
                "narrative_tier":        cal.narrative_tier,
                "exploitation_mult":     cal.exploitation_multiplier,
                "kev_promoted":          cal.kev_promoted,
                "flags":                 cal.calibration_flags,
                "calibrated_at":         cal.calibrated_at,
            }
            with AUDIT_LOG.open("a", encoding="utf-8") as f:
                f.write(json.dumps(record) + "\n")
        except Exception as e:
            logger.debug("narrative_scale audit log: %s", e)


# ── SINGLETON ─────────────────────────────────────────────────────────────────
_scaler: Optional[RiskNarrativeScaler] = None

def get_risk_narrative_scaler() -> RiskNarrativeScaler:
    global _scaler
    if _scaler is None:
        _scaler = RiskNarrativeScaler()
    return _scaler


# ── CLI DEMO ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    test_cases = [
        # Live data: LOW severity, no KEV, no EPSS
        {"id": "intel--dfec504aab91f9f0f3615a8c", "risk_score": 1.04,
         "cvss_score": 0.0, "epss_score": 0.0, "kev": False, "severity": "LOW",
         "source": "Vulners"},
        # Medium: CVSS 7.8, no KEV
        {"id": "intel--tanium-cmd-injection", "risk_score": 5.5,
         "cvss_score": 7.8, "epss_score": 0.08, "kev": False, "severity": "MEDIUM",
         "source": "NVD"},
        # KEV confirmed — should promote from LOW/MEDIUM to HIGH
        {"id": "intel--kev-promoted", "risk_score": 2.1,
         "cvss_score": 5.5, "epss_score": 0.02, "kev": True, "severity": "MEDIUM",
         "source": "CISA KEV"},
        # CRITICAL: active exploitation + EPSS 55% + CVSS 9.8
        {"id": "intel--ivanti-rce", "risk_score": 9.8,
         "cvss_score": 9.8, "epss_score": 0.55, "kev": True, "severity": "CRITICAL",
         "active_exploit": True, "source": "CISA KEV"},
    ]

    scaler = get_risk_narrative_scaler()
    print("\n=== RISK NARRATIVE SCALER DEMO ===\n")
    for adv in test_cases:
        cal = scaler.calibrate(adv)
        print(cal.get_soc_summary())
        print(f"  Narrative Max Words: {cal.narrative_scale.max_words}")
        print(f"  Allow Financial:     {cal.narrative_guards['allow_financial']}")
        print(f"  Allow Board Lang:    {cal.narrative_guards['allow_board_language']}")
        print(f"  Patch SLA:           {cal.narrative_scale.patch_sla_hours}h")
        print()
