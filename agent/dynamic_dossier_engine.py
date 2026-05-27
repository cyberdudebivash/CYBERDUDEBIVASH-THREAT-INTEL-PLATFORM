"""
CYBERDUDEBIVASH® SENTINEL APEX — Dynamic Dossier Generation Engine
Phase 41: Operational Reality Convergence

Implements:
  - Telemetry-adaptive narrative generation
  - Dynamic dossier scaling (depth driven by evidence, not templates)
  - Variable intelligence density sections
  - Evidence-aware section generation (sections only generated if evidence exists)
  - Replay-aware operational guidance
  - Actor-aware reporting (adapts to attribution confidence)
  - Telemetry-aware remediation
  - Environment-aware response playbooks

GOVERNANCE MANDATE:
  - Template-feeling generation is PROHIBITED
  - Sections are generated IFF supporting evidence exists
  - Narrative depth MUST scale with telemetry richness, replay evidence,
    ATT&CK complexity, graph overlap, infrastructure correlation
  - Repeated remediation prose is PROHIBITED
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.dossier_engine")


# ─────────────────────────────────────────────────────────────
# ENUMERATIONS
# ─────────────────────────────────────────────────────────────

class DossierTier(str, Enum):
    FLASH         = "FLASH"         # Single-page — low density, time-sensitive
    TACTICAL      = "TACTICAL"      # 2-3 sections — medium density
    OPERATIONAL   = "OPERATIONAL"   # 4-6 sections — high density
    STRATEGIC     = "STRATEGIC"     # Full dossier — maximum density + attribution

class SectionPresence(str, Enum):
    MANDATORY     = "mandatory"     # Always included regardless of evidence
    EVIDENCE_GATED= "evidence_gated"# Only included if evidence threshold met
    OPTIONAL      = "optional"      # Included only if rich evidence exists


# ─────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────

@dataclass
class DossierEvidencePackage:
    """All evidence inputs that drive dossier generation decisions."""
    report_id: str

    # Telemetry
    telemetry_event_count: int      = 0
    enriched_event_count: int       = 0
    unique_affected_hosts: int      = 0
    telemetry_density: float        = 0.0   # 0.0–1.0

    # ATT&CK
    attck_techniques: List[str]     = field(default_factory=list)
    attck_tactics: List[str]        = field(default_factory=list)
    attck_procedure_examples: List[str] = field(default_factory=list)
    kill_chain_stages: List[str]    = field(default_factory=list)
    replay_confirmed_ttps: List[str]= field(default_factory=list)

    # IOCs
    ioc_count: int                  = 0
    high_confidence_iocs: int       = 0
    ioc_types: List[str]            = field(default_factory=list)

    # Graph
    graph_node_count: int           = 0
    graph_edge_count: int           = 0
    graph_cluster_matches: int      = 0
    campaign_lineage_depth: int     = 0   # linked campaign chain length

    # Replay
    replay_hit_count: int           = 0
    replay_bypass_confirmed: bool   = False
    replay_detection_gaps: List[str]= field(default_factory=list)

    # Attribution
    actor_name: Optional[str]       = None
    actor_confidence: float         = 0.0
    actor_confidence_band: Tuple[float, float] = (0.0, 0.0)
    attribution_justified: bool     = False
    actor_motivation: Optional[str] = None

    # Risk
    governed_risk_score: float      = 0.0
    kev_listed: bool                = False
    active_exploitation: bool       = False
    affected_asset_criticality: float = 0.5

    # Infrastructure
    infra_overlap_score: float      = 0.0
    shared_c2_count: int            = 0
    honeynet_observations: int      = 0


@dataclass
class DossierSection:
    """A single generated dossier section."""
    section_id: str
    title: str
    presence: SectionPresence
    content: str
    evidence_basis: str             # What evidence generated this section
    word_count: int
    generated: bool = True


@dataclass
class GeneratedDossier:
    """Complete generated dossier with all sections."""
    report_id: str
    dossier_tier: DossierTier
    title: str
    tlp: str
    sections: List[DossierSection]
    total_word_count: int
    evidence_signal_count: int
    telemetry_density: float
    sections_generated: int
    sections_suppressed: int
    suppressed_reasons: List[str]
    generated_at: str
    analyst_confidence_note: str


# ─────────────────────────────────────────────────────────────
# SECTION GENERATORS
# ─────────────────────────────────────────────────────────────

class SectionGenerators:
    """Individual section content generators — each is evidence-gated."""

    @staticmethod
    def executive_summary(ev: DossierEvidencePackage) -> str:
        actor_str = (
            f"attributed to {ev.actor_name} "
            f"(confidence: {ev.actor_confidence:.0%}, "
            f"band: [{ev.actor_confidence_band[0]:.0%}–{ev.actor_confidence_band[1]:.0%}])"
            if ev.attribution_justified and ev.actor_name
            else "with attribution pending further evidence"
        )
        kev_str = " CISA KEV-listed — active exploitation confirmed." if ev.kev_listed else ""
        risk_str = f"Governed risk score: {ev.governed_risk_score:.1f}/10."
        host_str = (
            f"{ev.unique_affected_hosts} host(s) confirmed affected in telemetry."
            if ev.unique_affected_hosts > 0 else "No confirmed host impact in current telemetry."
        )
        return (
            f"This report documents {ev.telemetry_event_count} telemetry events across "
            f"{ev.unique_affected_hosts} affected host(s), {actor_str}.{kev_str} "
            f"{risk_str} {host_str} "
            f"Telemetry density: {ev.telemetry_density:.2f}/1.00 — "
            f"report depth calibrated accordingly."
        )

    @staticmethod
    def telemetry_evidence(ev: DossierEvidencePackage) -> str:
        lines = [
            f"Telemetry basis: {ev.telemetry_event_count} raw events, "
            f"{ev.enriched_event_count} enriched events, "
            f"{ev.unique_affected_hosts} affected host(s).",
        ]
        if ev.honeynet_observations > 0:
            lines.append(
                f"Honeynet telemetry: {ev.honeynet_observations} sensor observations "
                f"providing proprietary behavioral data."
            )
        if ev.ioc_count > 0:
            lines.append(
                f"IOC corpus: {ev.ioc_count} total IOCs, "
                f"{ev.high_confidence_iocs} high-confidence "
                f"({', '.join(ev.ioc_types[:4]) if ev.ioc_types else 'mixed types'})."
            )
        if ev.infra_overlap_score > 0.2:
            lines.append(
                f"Infrastructure correlation: {ev.infra_overlap_score:.2f} overlap score, "
                f"{ev.shared_c2_count} shared C2 endpoint(s) identified."
            )
        return " ".join(lines)

    @staticmethod
    def attck_analysis(ev: DossierEvidencePackage) -> str:
        if not ev.attck_techniques:
            return ""
        tech_list = ", ".join(ev.attck_techniques[:10])
        tactic_list = ", ".join(ev.attck_tactics[:6]) if ev.attck_tactics else "multiple"
        kill_str = (
            f" Kill-chain progression: {' → '.join(ev.kill_chain_stages)}."
            if ev.kill_chain_stages else ""
        )
        replay_str = (
            f" Replay-confirmed techniques: {', '.join(ev.replay_confirmed_ttps[:5])}."
            if ev.replay_confirmed_ttps else ""
        )
        proc_str = (
            f" Procedural examples observed: {len(ev.attck_procedure_examples)}."
            if ev.attck_procedure_examples else ""
        )
        return (
            f"{len(ev.attck_techniques)} ATT&CK technique(s) identified across "
            f"{len(ev.attck_tactics)} tactic(s) ({tactic_list}): {tech_list}.{kill_str}"
            f"{replay_str}{proc_str}"
        )

    @staticmethod
    def actor_attribution(ev: DossierEvidencePackage) -> str:
        if not ev.attribution_justified or not ev.actor_name:
            return ""
        motiv = f" Motivation: {ev.actor_motivation}." if ev.actor_motivation else ""
        return (
            f"Primary attribution hypothesis: {ev.actor_name}. "
            f"Confidence: {ev.actor_confidence:.0%} "
            f"(band: {ev.actor_confidence_band[0]:.0%}–{ev.actor_confidence_band[1]:.0%}). "
            f"Attribution basis: infrastructure overlap, ATT&CK behavioral fingerprint, "
            f"graph-derived campaign lineage (depth: {ev.campaign_lineage_depth}).{motiv} "
            f"Alternative hypotheses exist — see cluster analysis for ambiguity scoring."
        )

    @staticmethod
    def graph_intelligence(ev: DossierEvidencePackage) -> str:
        if ev.graph_node_count < 3:
            return ""
        return (
            f"Graph analysis: {ev.graph_node_count} nodes, {ev.graph_edge_count} edges. "
            f"{ev.graph_cluster_matches} cluster match(es) to known actor infrastructure. "
            f"Campaign lineage depth: {ev.campaign_lineage_depth} linked historical campaigns. "
            f"Infrastructure overlap score: {ev.infra_overlap_score:.2f}."
        )

    @staticmethod
    def replay_analysis(ev: DossierEvidencePackage) -> str:
        if ev.replay_hit_count == 0:
            return ""
        bypass_str = (
            " Replay confirmed detection bypass — rule coverage gap identified."
            if ev.replay_bypass_confirmed else ""
        )
        gaps_str = (
            f" Detection gaps: {', '.join(ev.replay_detection_gaps[:3])}."
            if ev.replay_detection_gaps else ""
        )
        return (
            f"Replay validation: {ev.replay_hit_count} hit(s) against attack replay corpus.{bypass_str}{gaps_str} "
            f"Replay-confirmed TTPs: {', '.join(ev.replay_confirmed_ttps[:5]) if ev.replay_confirmed_ttps else 'none'}."
        )

    @staticmethod
    def operational_remediation(ev: DossierEvidencePackage) -> str:
        """
        Telemetry-aware, non-repeated remediation.
        Specific to THIS environment, THIS evidence.
        """
        actions = []
        if ev.kev_listed:
            actions.append("Apply KEV-listed patch immediately — CISA mandate applies")
        if ev.replay_bypass_confirmed and ev.replay_detection_gaps:
            actions.append(
                f"Close {len(ev.replay_detection_gaps)} replay-identified detection gap(s): "
                f"{', '.join(ev.replay_detection_gaps[:2])}"
            )
        if ev.unique_affected_hosts > 0:
            actions.append(
                f"Investigate {ev.unique_affected_hosts} confirmed host(s) "
                f"for lateral movement indicators"
            )
        if ev.attck_techniques:
            actions.append(
                f"Deploy detection coverage for {len(ev.attck_techniques)} "
                f"identified technique(s): {', '.join(ev.attck_techniques[:3])}"
            )
        if ev.shared_c2_count > 0:
            actions.append(f"Block {ev.shared_c2_count} shared C2 endpoint(s) at perimeter")
        if ev.high_confidence_iocs > 0:
            actions.append(
                f"Hunt for {ev.high_confidence_iocs} high-confidence IOC(s) "
                f"across endpoint and network telemetry"
            )

        if not actions:
            return "Monitor for reactivation. No immediate remediation actions required."

        return "Remediation actions (priority-ordered): " + "; ".join(
            [f"({i+1}) {a}" for i, a in enumerate(actions)]
        ) + "."

    @staticmethod
    def ioc_summary(ev: DossierEvidencePackage) -> str:
        if ev.ioc_count == 0:
            return ""
        return (
            f"IOC summary: {ev.ioc_count} total, {ev.high_confidence_iocs} high-confidence. "
            f"Types: {', '.join(ev.ioc_types) if ev.ioc_types else 'mixed'}. "
            f"Full IOC list available via API — filtered by confidence ≥0.70."
        )


# ─────────────────────────────────────────────────────────────
# DOSSIER TIER CLASSIFIER
# ─────────────────────────────────────────────────────────────

class DossierTierClassifier:
    """Determine appropriate dossier tier from evidence package."""

    def classify(self, ev: DossierEvidencePackage) -> DossierTier:
        """
        Evidence-driven tier classification.
        Template-feeling output from insufficient evidence is PROHIBITED.
        """
        density = ev.telemetry_density
        attck_depth = len(ev.attck_techniques)
        graph_rich = ev.graph_node_count >= 10
        attribution_rich = ev.attribution_justified and ev.actor_confidence >= 0.5
        replay_rich = ev.replay_hit_count >= 3

        # STRATEGIC: maximum evidence across all dimensions
        if (density >= 0.70 and attck_depth >= 6 and
                (graph_rich or attribution_rich) and replay_rich):
            return DossierTier.STRATEGIC

        # OPERATIONAL: good coverage, multiple signal types
        if (density >= 0.45 and attck_depth >= 3 and
                (graph_rich or attribution_rich or replay_rich)):
            return DossierTier.OPERATIONAL

        # TACTICAL: moderate evidence
        if density >= 0.20 or attck_depth >= 2 or ev.ioc_count >= 5:
            return DossierTier.TACTICAL

        # FLASH: minimal evidence — time-sensitive brief only
        return DossierTier.FLASH


# ─────────────────────────────────────────────────────────────
# SECTION CATALOGUE
# ─────────────────────────────────────────────────────────────

SECTION_CATALOGUE = [
    # (section_id, title, presence, min_tier, evidence_check_fn)
    ("executive_summary",  "Executive Summary",             SectionPresence.MANDATORY,      DossierTier.FLASH,       None),
    ("telemetry_evidence", "Telemetry Evidence",            SectionPresence.EVIDENCE_GATED, DossierTier.FLASH,       lambda ev: ev.telemetry_event_count > 0),
    ("ioc_summary",        "IOC Summary",                   SectionPresence.EVIDENCE_GATED, DossierTier.TACTICAL,    lambda ev: ev.ioc_count >= 3),
    ("attck_analysis",     "ATT&CK Behavioral Analysis",    SectionPresence.EVIDENCE_GATED, DossierTier.TACTICAL,    lambda ev: len(ev.attck_techniques) >= 1),
    ("replay_analysis",    "Replay Validation",             SectionPresence.EVIDENCE_GATED, DossierTier.TACTICAL,    lambda ev: ev.replay_hit_count > 0),
    ("graph_intelligence", "Graph Intelligence",            SectionPresence.EVIDENCE_GATED, DossierTier.OPERATIONAL, lambda ev: ev.graph_node_count >= 5),
    ("actor_attribution",  "Actor Attribution Analysis",    SectionPresence.EVIDENCE_GATED, DossierTier.OPERATIONAL, lambda ev: ev.attribution_justified),
    ("operational_remediation", "Operational Remediation",  SectionPresence.MANDATORY,      DossierTier.FLASH,       None),
]

# Section generator dispatch
SECTION_GENERATORS = {
    "executive_summary":       SectionGenerators.executive_summary,
    "telemetry_evidence":      SectionGenerators.telemetry_evidence,
    "ioc_summary":             SectionGenerators.ioc_summary,
    "attck_analysis":          SectionGenerators.attck_analysis,
    "replay_analysis":         SectionGenerators.replay_analysis,
    "graph_intelligence":      SectionGenerators.graph_intelligence,
    "actor_attribution":       SectionGenerators.actor_attribution,
    "operational_remediation": SectionGenerators.operational_remediation,
}


# ─────────────────────────────────────────────────────────────
# DYNAMIC DOSSIER GENERATION ENGINE
# ─────────────────────────────────────────────────────────────

class DynamicDossierEngine:
    """
    Generates evidence-adaptive intelligence dossiers.

    Core behaviour:
      - Classify tier from evidence package
      - Generate only sections where evidence threshold is met
      - Suppress sections with no supporting evidence (no placeholders)
      - Scale narrative length to evidence density
      - Actor-name output only when attribution is justified
    """

    TIER_ORDER = [
        DossierTier.FLASH,
        DossierTier.TACTICAL,
        DossierTier.OPERATIONAL,
        DossierTier.STRATEGIC,
    ]

    def __init__(self):
        self.classifier = DossierTierClassifier()

    def _tier_index(self, tier: DossierTier) -> int:
        return self.TIER_ORDER.index(tier)

    def generate(
        self,
        evidence: DossierEvidencePackage,
        tlp: str = "TLP:AMBER",
        override_tier: Optional[DossierTier] = None,
    ) -> GeneratedDossier:
        """
        Generate a complete intelligence dossier from an evidence package.

        Args:
            evidence: Full evidence package driving all generation decisions
            tlp: TLP classification for the output
            override_tier: Force a specific tier (for analyst override)

        Returns:
            GeneratedDossier with evidence-gated sections only
        """
        tier = override_tier or self.classifier.classify(evidence)
        tier_idx = self._tier_index(tier)

        sections: List[DossierSection] = []
        suppressed: List[str] = []

        for (sid, title, presence, min_tier, check_fn) in SECTION_CATALOGUE:
            min_tier_idx = self._tier_index(min_tier)

            # Tier gate: skip if dossier tier is below minimum for this section
            if tier_idx < min_tier_idx:
                suppressed.append(
                    f"{title}: suppressed — dossier tier {tier.value} < min {min_tier.value}"
                )
                continue

            # Evidence gate: skip if evidence check fails
            if presence == SectionPresence.EVIDENCE_GATED and check_fn is not None:
                try:
                    if not check_fn(evidence):
                        suppressed.append(
                            f"{title}: suppressed — insufficient evidence"
                        )
                        continue
                except Exception:
                    suppressed.append(f"{title}: suppressed — evidence check error")
                    continue

            # Generate section content
            generator = SECTION_GENERATORS.get(sid)
            if generator is None:
                continue

            try:
                content = generator(evidence)
            except Exception as exc:
                logger.warning("Section %s generation failed: %s", sid, exc)
                content = ""

            # Empty content = suppress section (no placeholders)
            if not content or not content.strip():
                suppressed.append(f"{title}: suppressed — generator returned empty content")
                continue

            word_count = len(content.split())
            evidence_basis = f"Tier: {tier.value} | Presence: {presence.value}"
            if check_fn and check_fn(evidence):
                evidence_basis += " | Evidence gate: PASSED"

            sections.append(DossierSection(
                section_id=sid,
                title=title,
                presence=presence,
                content=content,
                evidence_basis=evidence_basis,
                word_count=word_count,
                generated=True,
            ))

        # Build title
        actor_str = (
            f" — {evidence.actor_name}"
            if evidence.attribution_justified and evidence.actor_name else ""
        )
        title = (
            f"[{tier.value}] Threat Intelligence Report {evidence.report_id}{actor_str} "
            f"— {datetime.now(timezone.utc).strftime('%Y-%m-%d')}"
        )

        total_words = sum(s.word_count for s in sections)

        # Analyst confidence note
        if evidence.telemetry_density >= 0.70 and evidence.replay_hit_count >= 3:
            conf_note = "HIGH CONFIDENCE — rich telemetry + replay validation."
        elif evidence.telemetry_density >= 0.40:
            conf_note = "MODERATE CONFIDENCE — adequate telemetry basis."
        elif evidence.telemetry_density >= 0.15:
            conf_note = "LOW CONFIDENCE — limited telemetry. Findings should be treated as indicative."
        else:
            conf_note = (
                "VERY LOW CONFIDENCE — sparse telemetry. "
                "Do not act on findings without additional corroboration."
            )

        # Count evidence signals
        signal_count = sum([
            evidence.telemetry_event_count > 0,
            evidence.ioc_count > 0,
            len(evidence.attck_techniques) > 0,
            evidence.graph_node_count > 0,
            evidence.replay_hit_count > 0,
            evidence.attribution_justified,
            evidence.honeynet_observations > 0,
            evidence.infra_overlap_score > 0.1,
        ])

        return GeneratedDossier(
            report_id=evidence.report_id,
            dossier_tier=tier,
            title=title,
            tlp=tlp,
            sections=sections,
            total_word_count=total_words,
            evidence_signal_count=signal_count,
            telemetry_density=evidence.telemetry_density,
            sections_generated=len(sections),
            sections_suppressed=len(suppressed),
            suppressed_reasons=suppressed,
            generated_at=datetime.now(timezone.utc).isoformat(),
            analyst_confidence_note=conf_note,
        )

    def render_text(self, dossier: GeneratedDossier) -> str:
        """Render dossier as structured plain text."""
        lines = [
            "=" * 80,
            dossier.title,
            f"TLP: {dossier.tlp}  |  Tier: {dossier.dossier_tier.value}  |  "
            f"Density: {dossier.telemetry_density:.2f}",
            f"Generated: {dossier.generated_at}  |  "
            f"Signals: {dossier.evidence_signal_count}  |  "
            f"Confidence: {dossier.analyst_confidence_note}",
            "=" * 80,
            "",
        ]
        for i, sec in enumerate(dossier.sections, 1):
            lines.append(f"{i}. {sec.title.upper()}")
            lines.append("-" * 60)
            lines.append(sec.content)
            lines.append(f"  [Evidence basis: {sec.evidence_basis}]")
            lines.append("")

        if dossier.suppressed_reasons:
            lines.append("SUPPRESSED SECTIONS:")
            for reason in dossier.suppressed_reasons:
                lines.append(f"  — {reason}")
            lines.append("")

        lines.append(f"Total words: {dossier.total_word_count}")
        lines.append(f"Sections generated: {dossier.sections_generated}")
        lines.append(f"Sections suppressed: {dossier.sections_suppressed}")
        return "\n".join(lines)

    def render_json(self, dossier: GeneratedDossier) -> str:
        """Render dossier as structured JSON."""
        return json.dumps(asdict(dossier), indent=2, default=str)
