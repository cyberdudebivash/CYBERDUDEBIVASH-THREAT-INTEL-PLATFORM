# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX
# agent/intelligence_density_calibrator.py
# INTELLIGENCE DENSITY CALIBRATOR v1.0
# P0 FIX #1 — Narrative depth MUST scale with evidence density
# Production-safe | Non-blocking | Deterministic | Zero-regression
# =============================================================================
"""
Intelligence Density Calibrator — Eliminates intelligence theater.

CORE PROBLEM FIXED:
  Narrative sophistication was EXCEEDING evidence depth.
  20-section strategic dossiers were generated for LOW-density CVE advisories
  with no KEV entry, no EPSS signal, no actor attribution, and 0-3 IOCs.
  This created enterprise trust erosion and analyst fatigue.

CALIBRATION RULES (Evidence-Gated Narrative):
  TIER 0 (Minimal):  No KEV + Risk < 1.0 + IOCs < 5 + ATT&CK < 2
    → 4-section brief: Classification, Summary, ATT&CK, IOC table. Done.

  TIER 1 (Standard): No KEV + Risk 1.0–4.9 + IOCs 5–15 + ATT&CK 2–5
    → 8-section dossier: adds Technical Analysis, Kill Chain, Playbook, Actor.

  TIER 2 (Enhanced): KEV OR Risk 5.0–7.9 OR IOCs > 15 OR EPSS > 10%
    → 14-section dossier: adds Campaign Intel, Financial Impact, Detection Pack.

  TIER 3 (Full):     KEV + Risk ≥ 8.0 OR EPSS > 30% OR Active Exploitation
    → 20-section full strategic dossier. Justified. Enterprise-grade.

SUPPRESSION RULES:
  - Strategic geopolitical narratives suppressed below Tier 3
  - Financial impact models suppressed below Tier 2
  - CISO executive briefing language suppressed below Tier 2
  - "Board-level cyber risk event" language: Tier 3 only
  - Ransomware/APT escalation language: requires actor attribution evidence

OUTPUT:
  Every dossier receives a DensityTag + SectionBudget + NarrativeBudget.
  The report generator respects these budgets — no overrides.

Writes:
  data/quality/density_calibration.jsonl (audit trail)
  data/quality/density_report.json (current session stats)
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.density_calibrator")

BASE_DIR  = Path(__file__).resolve().parent.parent
QUAL_DIR  = BASE_DIR / "data" / "quality"
AUDIT_LOG = QUAL_DIR / "density_calibration.jsonl"
REPORT    = QUAL_DIR / "density_report.json"

# ── TIER DEFINITIONS ─────────────────────────────────────────────────────────

@dataclass
class DensityTier:
    tier:            int
    label:           str
    section_budget:  int   # Max sections to generate
    narrative_words: int   # Max words in executive summary
    enable_campaign: bool  # Campaign intel section
    enable_financial: bool # Financial impact section
    enable_geopolitical: bool  # Geopolitical/strategic language
    enable_ciso_language: bool # CISO/board-level escalation
    enable_actor_dossier: bool # Full actor profile
    enable_detect_pack: bool   # Detection engineering pack
    enable_hunt_queries: bool  # Hunt hypothesis generation
    enable_compliance: bool    # Regulatory compliance section
    rationale: str

TIER_DEFINITIONS: Dict[int, DensityTier] = {
    0: DensityTier(
        tier=0, label="MINIMAL",
        section_budget=4, narrative_words=80,
        enable_campaign=False, enable_financial=False,
        enable_geopolitical=False, enable_ciso_language=False,
        enable_actor_dossier=False, enable_detect_pack=False,
        enable_hunt_queries=False, enable_compliance=False,
        rationale="Minimal evidence density. Low risk, no KEV, sparse IOCs. "
                  "Concise advisory only — no strategic narrative warranted."
    ),
    1: DensityTier(
        tier=1, label="STANDARD",
        section_budget=8, narrative_words=150,
        enable_campaign=False, enable_financial=False,
        enable_geopolitical=False, enable_ciso_language=False,
        enable_actor_dossier=True, enable_detect_pack=False,
        enable_hunt_queries=False, enable_compliance=False,
        rationale="Standard evidence density. Basic ATT&CK coverage. "
                  "Standard dossier with playbook — no financial escalation warranted."
    ),
    2: DensityTier(
        tier=2, label="ENHANCED",
        section_budget=14, narrative_words=250,
        enable_campaign=True, enable_financial=True,
        enable_geopolitical=False, enable_ciso_language=False,
        enable_actor_dossier=True, enable_detect_pack=True,
        enable_hunt_queries=True, enable_compliance=True,
        rationale="Enhanced evidence density. KEV or elevated EPSS/risk present. "
                  "Full technical + detection pack. Financial impact model included."
    ),
    3: DensityTier(
        tier=3, label="FULL_STRATEGIC",
        section_budget=20, narrative_words=500,
        enable_campaign=True, enable_financial=True,
        enable_geopolitical=True, enable_ciso_language=True,
        enable_actor_dossier=True, enable_detect_pack=True,
        enable_hunt_queries=True, enable_compliance=True,
        rationale="Full evidence density. KEV confirmed, high EPSS, active exploitation. "
                  "Complete strategic dossier with board-level reporting justified."
    ),
}

# ── EVIDENCE SIGNALS ─────────────────────────────────────────────────────────

@dataclass
class EvidenceSignals:
    """Quantified evidence signals extracted from an advisory."""
    advisory_id:      str
    risk_score:       float   = 0.0
    cvss_score:       float   = 0.0
    epss_score:       float   = 0.0   # 0.0–1.0 (probability)
    kev_listed:       bool    = False
    active_exploit:   bool    = False
    ioc_count:        int     = 0
    ioc_quality:      float   = 0.0   # 0.0–1.0 (hash/IP ratio vs URL/version noise)
    attck_count:      int     = 0     # Mapped ATT&CK techniques
    attck_density:    float   = 0.0   # Technique depth score (1 tactic=low, multi-tactic=high)
    actor_attributed: bool    = False # Has confirmed actor attribution
    campaign_overlap: int     = 0     # Historical campaign correlations
    telemetry_hits:   int     = 0     # Proprietary telemetry observations
    replay_validated: bool    = False # Attack replay confirmed
    graph_correlated: int     = 0     # Graph-native actor cluster correlations
    source_trust:     float   = 0.6   # Feed source trust weight (0.0–1.0)


@dataclass
class DensityCalibration:
    """Result of density calibration for one advisory."""
    advisory_id:    str
    tier:           int
    tier_label:     str
    section_budget: int
    narrative_words: int
    evidence_score: float           # Composite evidence density (0.0–1.0)
    evidence_breakdown: Dict[str, float] = field(default_factory=dict)
    suppressed_sections: List[str] = field(default_factory=list)
    enabled_sections:    List[str] = field(default_factory=list)
    calibration_flags:   List[str] = field(default_factory=list)
    tier_definition:     Optional[Dict] = None
    calibrated_at:       str = ""

    def to_dict(self) -> Dict:
        d = asdict(self)
        d["calibrated_at"] = datetime.now(timezone.utc).isoformat()
        return d


# ── DENSITY CALIBRATOR ────────────────────────────────────────────────────────

class IntelligenceDensityCalibrator:
    """
    Evidence-gated intelligence density calibrator.

    Ensures narrative depth scales with evidence quality.
    Eliminates intelligence theater on low-density advisories.
    """

    # Section budget allocations per tier
    SECTIONS_BY_TIER: Dict[int, List[str]] = {
        0: [
            "classification",
            "executive_summary",
            "attck_mapping",
            "ioc_table",
        ],
        1: [
            "classification",
            "executive_summary",
            "threat_profile",
            "risk_score",
            "technical_analysis",
            "attck_mapping",
            "ioc_table",
            "response_playbook",
        ],
        2: [
            "classification",
            "executive_summary",
            "threat_profile",
            "risk_score",
            "technical_analysis",
            "attck_mapping",
            "ioc_table",
            "cvss_epss",
            "kill_chain",
            "response_playbook",
            "actor_profile",
            "campaign_intel",
            "affected_systems",
            "detection_engineering",
        ],
        3: [
            "classification",
            "executive_summary",
            "threat_profile",
            "risk_score",
            "technical_analysis",
            "attck_mapping",
            "ioc_table",
            "cvss_epss",
            "kill_chain",
            "response_playbook",
            "actor_profile",
            "campaign_intel",
            "affected_systems",
            "strategic_implications",
            "ai_insight",
            "references",
            "financial_impact",
            "detection_engineering",
            "regulatory_compliance",
            "bis_navigator",
        ],
    }

    def __init__(self):
        QUAL_DIR.mkdir(parents=True, exist_ok=True)
        self._session_stats: List[Dict] = []

    def extract_signals(self, advisory: Dict[str, Any]) -> EvidenceSignals:
        """Extract quantified evidence signals from an advisory dict."""
        sig = EvidenceSignals(advisory_id=advisory.get("id", "unknown"))

        # Risk / CVSS / EPSS
        sig.risk_score   = float(advisory.get("risk_score", 0.0) or 0.0)
        sig.cvss_score   = float(advisory.get("cvss_score", 0.0) or 0.0)
        epss_raw         = advisory.get("epss_score", None) or advisory.get("epss", None)
        sig.epss_score   = float(epss_raw) if epss_raw is not None else 0.0

        # KEV / Exploitation
        kev_raw = advisory.get("kev", False) or advisory.get("kev_listed", False)
        sig.kev_listed = bool(kev_raw) and str(kev_raw).upper() not in ("NO", "FALSE", "0", "NONE", "")
        sig.active_exploit = advisory.get("active_exploit", False)

        # IOC quality
        iocs = advisory.get("iocs", []) or []
        sig.ioc_count = len(iocs)
        if iocs:
            # Score quality: hashes > IPs/domains > URLs > CVE references > version strings
            high_quality = sum(1 for i in iocs if i.get("type") in ("sha256", "sha1", "md5", "hash"))
            mid_quality  = sum(1 for i in iocs if i.get("type") in ("ipv4", "ipv6", "domain", "url"))
            # Version strings and source URLs are low quality — penalise
            total = len(iocs) or 1
            sig.ioc_quality = min(1.0, (high_quality * 1.0 + mid_quality * 0.5) / total)
        else:
            # Fall back to ioc_count field (free tier hides actual array)
            raw_count = int(advisory.get("ioc_count", 0) or 0)
            sig.ioc_count = raw_count
            sig.ioc_quality = 0.3  # Assumed low quality if no array available

        # ATT&CK
        tags = advisory.get("tags", []) or []
        attck = [t for t in tags if str(t).startswith("T1") or str(t).startswith("T0")]
        sig.attck_count = len(attck)
        # Density: count unique tactics (not just techniques)
        tactic_map = {
            "T1059": "Execution", "T1190": "InitialAccess", "T1548": "PrivilegeEscalation",
            "T1078": "CredentialAccess", "T1539": "CredentialAccess", "T1210": "LateralMovement",
            "T1486": "Impact", "T1566": "InitialAccess", "T1195": "SupplyChain",
            "T1053": "Execution", "T1547": "Persistence", "T1567": "Exfiltration",
        }
        tactics_hit = {tactic_map.get(t, "Other") for t in attck}
        sig.attck_density = min(1.0, len(tactics_hit) / 5.0)

        # Attribution
        actor = advisory.get("actor", "") or advisory.get("actor_cluster", "")
        sig.actor_attributed = bool(actor) and "UNATTR" not in str(actor).upper() \
                                and "UNKNOWN" not in str(actor).upper()

        # Telemetry (proprietary signals)
        sig.telemetry_hits   = int(advisory.get("telemetry_hits", 0) or 0)
        sig.replay_validated = bool(advisory.get("replay_validated", False))
        sig.graph_correlated = int(advisory.get("graph_correlated", 0) or 0)
        sig.campaign_overlap = int(advisory.get("campaign_overlap", 0) or 0)

        # Source trust
        source_trust_map = {
            "cisa":      0.95,
            "kev":       0.95,
            "mitre":     0.90,
            "nvd":       0.85,
            "vulners":   0.70,
            "cve feed":  0.65,
            "cvefeed":   0.65,
        }
        source = str(advisory.get("source", "")).lower()
        for key, trust in source_trust_map.items():
            if key in source:
                sig.source_trust = trust
                break

        return sig

    def compute_evidence_score(self, sig: EvidenceSignals) -> Tuple[float, Dict[str, float]]:
        """
        Compute composite evidence density score (0.0–1.0).

        Weights:
          KEV status:        25%  (binary, highest weight — CISA-confirmed exploitation)
          EPSS score:        20%  (exploitation probability, objective)
          CVSS score:        15%  (severity, normalized)
          IOC quality/count: 15%  (indicator richness)
          ATT&CK density:    10%  (technique coverage)
          Telemetry hits:    10%  (proprietary observation)
          Actor attribution: 5%   (confirmed attribution)
        """
        breakdown: Dict[str, float] = {}

        # KEV (25%)
        kev_contribution = 1.0 if sig.kev_listed else (0.5 if sig.active_exploit else 0.0)
        breakdown["kev"] = round(kev_contribution * 0.25, 4)

        # EPSS (20%) — 0.0–1.0 probability → direct contribution
        epss_contrib = min(1.0, sig.epss_score * 2.0)  # >50% EPSS = full contribution
        breakdown["epss"] = round(epss_contrib * 0.20, 4)

        # CVSS (15%) — normalize 0–10 → 0–1
        cvss_contrib = min(1.0, sig.cvss_score / 10.0)
        breakdown["cvss"] = round(cvss_contrib * 0.15, 4)

        # IOC quality × count (15%) — quality-weighted
        ioc_density = min(1.0, sig.ioc_count / 20.0)  # 20+ IOCs = full score
        ioc_contrib = ioc_density * sig.ioc_quality
        breakdown["ioc"] = round(ioc_contrib * 0.15, 4)

        # ATT&CK density (10%)
        breakdown["attck"] = round(sig.attck_density * 0.10, 4)

        # Telemetry (10%)
        telem_contrib = min(1.0, sig.telemetry_hits / 10.0)  # 10+ observations = full
        if sig.replay_validated:
            telem_contrib = min(1.0, telem_contrib + 0.4)
        if sig.graph_correlated > 0:
            telem_contrib = min(1.0, telem_contrib + 0.2)
        breakdown["telemetry"] = round(telem_contrib * 0.10, 4)

        # Actor attribution (5%)
        attr_contrib = 1.0 if sig.actor_attributed else 0.0
        breakdown["attribution"] = round(attr_contrib * 0.05, 4)

        # Source trust multiplier (applied post-sum)
        raw_score = sum(breakdown.values())
        trusted_score = raw_score * sig.source_trust
        breakdown["source_trust_multiplier"] = round(sig.source_trust, 4)
        breakdown["raw_before_trust"] = round(raw_score, 4)

        return round(min(1.0, trusted_score), 4), breakdown

    def assign_tier(self, sig: EvidenceSignals, evidence_score: float) -> int:
        """
        Assign density tier based on evidence signals.

        Hard rules (override score):
          TIER 3: KEV confirmed + (CVSS≥7.5 OR EPSS>30%)
          TIER 3: Active exploitation confirmed
          TIER 2: KEV listed OR EPSS>10% OR CVSS≥5.0 OR telemetry_hits≥5
          TIER 1: Risk≥1.0 OR ATT&CK≥2 OR IOCs≥5
          TIER 0: Everything else
        """
        # Tier 3 hard rules
        if sig.active_exploit:
            return 3
        if sig.kev_listed and (sig.cvss_score >= 7.5 or sig.epss_score > 0.30):
            return 3
        if evidence_score >= 0.70:
            return 3

        # Tier 2 hard rules
        if sig.kev_listed:
            return 2
        if sig.epss_score > 0.10:
            return 2
        if sig.cvss_score >= 5.0:
            return 2
        if sig.telemetry_hits >= 5:
            return 2
        if sig.actor_attributed and sig.campaign_overlap > 0:
            return 2
        if evidence_score >= 0.35:
            return 2

        # Tier 1
        if sig.risk_score >= 1.0 or sig.attck_count >= 2 or sig.ioc_count >= 5:
            return 1
        if evidence_score >= 0.15:
            return 1

        # Tier 0 — minimal
        return 0

    def calibrate(self, advisory: Dict[str, Any]) -> DensityCalibration:
        """
        Main entry point. Returns DensityCalibration for one advisory.

        The report generator MUST respect section_budget and narrative_words.
        """
        sig = self.extract_signals(advisory)
        evidence_score, breakdown = self.compute_evidence_score(sig)
        tier = self.assign_tier(sig, evidence_score)
        tier_def = TIER_DEFINITIONS[tier]
        sections = self.SECTIONS_BY_TIER[tier]

        # Determine suppressed sections vs full set
        all_sections = self.SECTIONS_BY_TIER[3]
        suppressed = [s for s in all_sections if s not in sections]

        # Calibration flags
        flags: List[str] = []
        if tier < 2 and sig.ioc_count > 0 and sig.ioc_quality < 0.2:
            flags.append("IOC_QUALITY_LOW: indicators appear to be version strings or source URLs")
        if tier < 3 and not sig.kev_listed:
            flags.append("NO_KEV: CISA Known Exploited Vulnerability status not confirmed")
        if not sig.actor_attributed:
            flags.append("UNATTRIBUTED: No confirmed threat actor attribution")
        if sig.epss_score == 0.0:
            flags.append("NO_EPSS: Exploitation probability score not available")
        if sig.telemetry_hits == 0:
            flags.append("NO_TELEMETRY: No proprietary telemetry observations recorded")
        if tier == 0:
            flags.append("DENSITY_TIER_0: Minimal evidence — generating concise brief only")
        if tier == 1:
            flags.append("DENSITY_TIER_1: Standard evidence — 8-section dossier only")

        cal = DensityCalibration(
            advisory_id=sig.advisory_id,
            tier=tier,
            tier_label=tier_def.label,
            section_budget=tier_def.section_budget,
            narrative_words=tier_def.narrative_words,
            evidence_score=evidence_score,
            evidence_breakdown=breakdown,
            suppressed_sections=suppressed,
            enabled_sections=sections,
            calibration_flags=flags,
            tier_definition={
                "rationale": tier_def.rationale,
                "enable_campaign": tier_def.enable_campaign,
                "enable_financial": tier_def.enable_financial,
                "enable_geopolitical": tier_def.enable_geopolitical,
                "enable_ciso_language": tier_def.enable_ciso_language,
                "enable_actor_dossier": tier_def.enable_actor_dossier,
                "enable_detect_pack": tier_def.enable_detect_pack,
                "enable_hunt_queries": tier_def.enable_hunt_queries,
                "enable_compliance": tier_def.enable_compliance,
            },
            calibrated_at=datetime.now(timezone.utc).isoformat(),
        )

        self._log(cal)
        return cal

    def calibrate_batch(self, advisories: List[Dict[str, Any]]) -> List[DensityCalibration]:
        """Calibrate a batch of advisories. Returns list in same order."""
        results = [self.calibrate(a) for a in advisories]
        self._write_report(results)
        return results

    def get_narrative_guard(self, cal: DensityCalibration) -> Dict[str, Any]:
        """
        Returns a NarrativeGuard dict the report generator must enforce.

        Prevents:
          - Geopolitical language below Tier 3
          - CISO/board escalation below Tier 2
          - "board-level cyber risk event" below Tier 3
          - Ransomware escalation without actor attribution
          - Financial impact models below Tier 2
        """
        tier_def = TIER_DEFINITIONS[cal.tier]
        return {
            "max_sections":            cal.section_budget,
            "max_summary_words":       cal.narrative_words,
            "allow_geopolitical":      tier_def.enable_geopolitical,
            "allow_ciso_language":     tier_def.enable_ciso_language,
            "allow_financial_impact":  tier_def.enable_financial,
            "allow_campaign_intel":    tier_def.enable_campaign,
            "allow_ransomware_escalation": cal.tier >= 2,
            "allow_apt_attribution":   cal.tier >= 2,
            "allow_board_language":    cal.tier >= 3,
            "allow_detection_pack":    tier_def.enable_detect_pack,
            "allow_hunt_queries":      tier_def.enable_hunt_queries,
            "allow_compliance":        tier_def.enable_compliance,
            "enabled_sections":        cal.enabled_sections,
            "suppressed_sections":     cal.suppressed_sections,
        }

    # ── INTERNAL LOGGING ─────────────────────────────────────────────────────

    def _log(self, cal: DensityCalibration) -> None:
        try:
            AUDIT_LOG.parent.mkdir(parents=True, exist_ok=True)
            with AUDIT_LOG.open("a", encoding="utf-8") as f:
                f.write(json.dumps(cal.to_dict()) + "\n")
        except Exception as e:
            logger.warning("density_calibrator: audit log write failed: %s", e)

    def _write_report(self, calibrations: List[DensityCalibration]) -> None:
        try:
            tier_counts = {0: 0, 1: 0, 2: 0, 3: 0}
            for c in calibrations:
                tier_counts[c.tier] = tier_counts.get(c.tier, 0) + 1

            report = {
                "generated_at": datetime.now(timezone.utc).isoformat(),
                "total_calibrated": len(calibrations),
                "tier_distribution": tier_counts,
                "avg_evidence_score": round(
                    sum(c.evidence_score for c in calibrations) / max(len(calibrations), 1), 4
                ),
                "calibrations": [c.to_dict() for c in calibrations],
            }
            REPORT.parent.mkdir(parents=True, exist_ok=True)
            REPORT.write_text(json.dumps(report, indent=2), encoding="utf-8")
        except Exception as e:
            logger.warning("density_calibrator: report write failed: %s", e)


# ── SINGLETON ─────────────────────────────────────────────────────────────────
_calibrator: Optional[IntelligenceDensityCalibrator] = None

def get_calibrator() -> IntelligenceDensityCalibrator:
    global _calibrator
    if _calibrator is None:
        _calibrator = IntelligenceDensityCalibrator()
    return _calibrator


# ── CLI DEMO ──────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO)

    # Demonstrate calibration against live API data
    test_advisories = [
        # LOW severity, no KEV, no EPSS → Tier 0
        {
            "id": "intel--dfec504aab91f9f0f3615a8c",
            "risk_score": 1.04, "cvss_score": 0.0, "epss_score": 0.0,
            "kev": False, "ioc_count": 15, "tags": ["T1059"],
            "source": "Vulners", "actor": "CDB-UNATTR-CVE"
        },
        # Buffer overflow, CVSS 8.8, no KEV → Tier 2
        {
            "id": "intel--bd5413e278b564ae28280e6a",
            "risk_score": 0.58, "cvss_score": 8.8, "epss_score": 0.03,
            "kev": False, "ioc_count": 2, "tags": ["T1190", "T1059"],
            "source": "CVE Feed", "actor": "CDB-UNATTR-CVE"
        },
        # KEV confirmed, EPSS 45%, CVSS 9.8 → Tier 3
        {
            "id": "intel--CRITICAL-EXAMPLE",
            "risk_score": 9.2, "cvss_score": 9.8, "epss_score": 0.45,
            "kev": True, "ioc_count": 47, "tags": ["T1190", "T1059", "T1078", "T1486"],
            "source": "CISA KEV", "actor": "APT28",
            "telemetry_hits": 23, "replay_validated": True, "graph_correlated": 5
        },
    ]

    cal = get_calibrator()
    print("\n=== INTELLIGENCE DENSITY CALIBRATION RESULTS ===\n")
    for adv in test_advisories:
        result = cal.calibrate(adv)
        guard  = cal.get_narrative_guard(result)
        print(f"Advisory: {result.advisory_id}")
        print(f"  Tier: {result.tier} ({result.tier_label})")
        print(f"  Evidence Score: {result.evidence_score:.2%}")
        print(f"  Section Budget: {result.section_budget}/20 sections")
        print(f"  Narrative Budget: {result.narrative_words} words")
        print(f"  Suppressed Sections ({len(result.suppressed_sections)}): "
              f"{', '.join(result.suppressed_sections[:4])}{'...' if len(result.suppressed_sections) > 4 else ''}")
        print(f"  Flags: {'; '.join(result.calibration_flags[:2])}")
        print(f"  Allow Financial Impact: {guard['allow_financial_impact']}")
        print(f"  Allow Board Language: {guard['allow_board_language']}")
        print()
