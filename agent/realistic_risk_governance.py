"""
CYBERDUDEBIVASH® SENTINEL APEX — Realistic Risk Governance Engine
Phase 39: Operational Reality Convergence

Implements:
  - Telemetry-weighted risk scoring (evidence scales severity)
  - Exploitability-aware CVSS adjustment (EPSS + KEV integration)
  - Environmental prevalence scoring (how common in YOUR network)
  - Active exploitation weighting (real-world abuse signals)
  - Business-impact-weighted escalation
  - Replay-derived risk adjustment (observed vs theoretical)
  - Infrastructure overlap weighting (shared C2/ASN/hosting)
  - Narrative depth scaling (low-sev = concise, high-fidelity = expanded)

GOVERNANCE MANDATE:
  - Low-severity findings MUST remain operationally concise
  - High-fidelity threats MUST dynamically expand intelligence depth
  - Confidence MUST be evidence-proportional, never synthetic
  - Geopolitical inflation is PROHIBITED
"""

from __future__ import annotations

import math
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.risk_governance")

# ─────────────────────────────────────────────────────────────
# ENUMERATIONS
# ─────────────────────────────────────────────────────────────

class RiskTier(str, Enum):
    CRITICAL    = "CRITICAL"    # 9.0–10.0 governed score
    HIGH        = "HIGH"        # 7.0–8.9
    MEDIUM      = "MEDIUM"      # 4.0–6.9
    LOW         = "LOW"         # 1.0–3.9
    INFORMATIONAL = "INFO"      # 0.0–0.9

class ExploitabilityStatus(str, Enum):
    ACTIVE_EXPLOITATION   = "active_exploitation"    # KEV listed, observed in wild
    POC_PUBLIC            = "poc_public"             # Public PoC, not yet weaponized
    WEAPONIZED            = "weaponized"             # Metasploit / crimeware kit
    THEORETICAL           = "theoretical"            # No known exploit
    INTERNAL_REPLAY       = "internal_replay"        # Confirmed via replay engine

class NarrativeDepth(str, Enum):
    SINGLE_LINE   = "single_line"    # 1 sentence — informational only
    CONCISE       = "concise"        # 2–4 sentences — low severity
    STANDARD      = "standard"       # 1–2 paragraphs — medium
    EXPANDED      = "expanded"       # Full tactical section — high
    COMPREHENSIVE = "comprehensive"  # Full dossier — critical + rich telemetry

# ─────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────

@dataclass
class TelemetryEvidence:
    """Evidence package from telemetry layer for a single finding."""
    finding_id: str
    raw_event_count: int          = 0
    enriched_event_count: int     = 0
    replay_hits: int              = 0
    graph_node_matches: int       = 0
    ioc_hits: int                 = 0
    attck_technique_count: int    = 0
    attck_tactic_count: int       = 0
    honeynet_observations: int    = 0
    unique_source_ips: int        = 0
    unique_affected_hosts: int    = 0
    campaign_correlation_score: float = 0.0  # 0.0–1.0
    source_trust_score: float     = 0.0      # 0.0–1.0
    observation_window_hours: int = 0

    @property
    def density_score(self) -> float:
        """
        Compute 0.0–1.0 telemetry density.
        High density → richer output permitted.
        Low density  → concise output mandated.
        """
        signals = [
            min(self.raw_event_count / 100.0, 1.0)      * 0.15,
            min(self.enriched_event_count / 50.0, 1.0)  * 0.15,
            min(self.replay_hits / 10.0, 1.0)           * 0.20,
            min(self.graph_node_matches / 20.0, 1.0)    * 0.15,
            min(self.ioc_hits / 10.0, 1.0)              * 0.10,
            min(self.attck_technique_count / 8.0, 1.0)  * 0.10,
            min(self.honeynet_observations / 5.0, 1.0)  * 0.10,
            self.campaign_correlation_score              * 0.05,
        ]
        return round(sum(signals), 4)


@dataclass
class CVSSContext:
    """CVSS 3.1 base metrics + environmental modifiers."""
    base_score: float                           # 0.0–10.0 raw CVSS
    epss_probability: float = 0.0              # 0.0–1.0 EPSS exploitation probability
    epss_percentile: float  = 0.0              # 0.0–1.0 EPSS percentile rank
    kev_listed: bool        = False            # CISA KEV listed
    kev_date_added: Optional[str] = None
    exploitability: ExploitabilityStatus = ExploitabilityStatus.THEORETICAL
    affected_asset_criticality: float = 0.5   # 0.0–1.0 (0=DMZ, 1.0=crown jewel)
    network_exposure: float = 0.5             # 0.0–1.0 (0=internal-only, 1=internet)
    patch_available: bool   = True
    patch_age_days: int     = 0               # days since patch released
    cvss_vector: str        = ""


@dataclass
class BusinessImpactContext:
    """Business impact weighting for risk escalation."""
    data_sensitivity: float   = 0.5    # 0=public, 1=regulated PII/PHI
    revenue_impact: float     = 0.3    # 0=none, 1=direct revenue system
    regulatory_exposure: float= 0.3   # 0=none, 1=SOX/HIPAA/PCI critical
    availability_impact: float= 0.3   # 0=non-critical, 1=life-safety/24x7
    brand_impact: float       = 0.2   # 0=internal, 1=customer-facing


@dataclass
class RiskScoringResult:
    """Full governed risk scoring output for a single finding."""
    finding_id: str
    base_cvss: float
    governed_score: float              # Final telemetry-governed score
    risk_tier: RiskTier
    narrative_depth: NarrativeDepth

    # Score decomposition
    telemetry_weight: float
    exploitability_weight: float
    environmental_weight: float
    business_impact_weight: float
    replay_adjustment: float
    infrastructure_overlap_weight: float

    # Evidence provenance
    telemetry_density: float           # 0.0–1.0
    evidence_signal_count: int
    replay_confirmed: bool
    kev_listed: bool
    active_exploitation: bool

    # Governance flags
    narrative_inflation_blocked: bool  # True if depth was reduced by governance
    geopolitical_inflation_blocked: bool
    confidence_band: Tuple[float, float]  # (low, high) governed confidence range

    # Narrative output
    operational_summary: str           # Always generated — length scales with depth
    remediation_priority: str          # Proportional to governed score
    analyst_note: str                  # Technical note for SOC analyst

    scored_at: str


# ─────────────────────────────────────────────────────────────
# RISK GOVERNANCE ENGINE
# ─────────────────────────────────────────────────────────────

class RealisticRiskGovernanceEngine:
    """
    Computes evidence-proportional risk scores.

    CORE PRINCIPLE:
      governed_score = f(base_cvss, telemetry_density, exploitability,
                         environmental_prevalence, business_impact,
                         replay_adjustment, infrastructure_overlap)

    Narrative depth is DERIVED from governed_score × telemetry_density.
    Low telemetry density → depth ceiling is CONCISE regardless of score.
    High telemetry density + high score → COMPREHENSIVE dossier unlocked.
    """

    # Narrative depth thresholds: (min_governed_score, min_density) → depth
    DEPTH_MATRIX: List[Tuple[float, float, NarrativeDepth]] = [
        (9.0, 0.70, NarrativeDepth.COMPREHENSIVE),
        (7.5, 0.50, NarrativeDepth.EXPANDED),
        (5.0, 0.30, NarrativeDepth.STANDARD),
        (3.0, 0.10, NarrativeDepth.CONCISE),
        (0.0, 0.00, NarrativeDepth.SINGLE_LINE),
    ]

    # Exploitability multipliers
    EXPLOIT_MULTIPLIERS: Dict[ExploitabilityStatus, float] = {
        ExploitabilityStatus.ACTIVE_EXPLOITATION: 1.35,
        ExploitabilityStatus.WEAPONIZED:          1.20,
        ExploitabilityStatus.INTERNAL_REPLAY:     1.15,
        ExploitabilityStatus.POC_PUBLIC:          1.05,
        ExploitabilityStatus.THEORETICAL:         0.85,
    }

    def __init__(
        self,
        kev_set: Optional[set] = None,
        max_governed_score: float = 10.0,
    ):
        self.kev_set = kev_set or set()
        self.max_governed_score = max_governed_score

    def _telemetry_weight(self, evidence: TelemetryEvidence) -> float:
        """
        Telemetry density → score modifier.
        Dense telemetry confirms observed behavior → amplifies severity.
        Sparse telemetry → theoretical risk → dampens severity.
        """
        density = evidence.density_score
        if density >= 0.80:
            return 1.25   # Strong telemetry confirmation
        elif density >= 0.60:
            return 1.15
        elif density >= 0.40:
            return 1.05
        elif density >= 0.20:
            return 0.95
        elif density >= 0.10:
            return 0.85   # Weak signal — moderate dampening
        else:
            return 0.70   # Near-zero evidence — significant dampening

    def _exploitability_weight(self, cvss: CVSSContext) -> float:
        """Combine EPSS + KEV + exploit status into a single multiplier."""
        base = self.EXPLOIT_MULTIPLIERS.get(cvss.exploitability, 1.0)

        # EPSS amplification — probability > 0.5 = meaningfully dangerous
        epss_amp = 1.0 + (cvss.epss_probability * 0.30)

        # KEV hard amplification
        kev_amp = 1.20 if cvss.kev_listed else 1.0

        # Network exposure
        exposure_amp = 1.0 + (cvss.network_exposure * 0.15)

        # Asset criticality
        criticality_amp = 1.0 + (cvss.affected_asset_criticality * 0.20)

        # Patch gap penalty — unpatch >30d after patch available
        patch_penalty = 1.0
        if cvss.patch_available and cvss.patch_age_days > 90:
            patch_penalty = 1.15
        elif cvss.patch_available and cvss.patch_age_days > 30:
            patch_penalty = 1.08

        return base * epss_amp * kev_amp * exposure_amp * criticality_amp * patch_penalty

    def _environmental_weight(
        self,
        evidence: TelemetryEvidence,
        infra_overlap_score: float,
    ) -> float:
        """
        Environmental prevalence: how commonly observed in this infrastructure.
        High prevalence → confirmed threat in environment → amplify.
        """
        prevalence = min(evidence.unique_affected_hosts / 50.0, 1.0)
        infra_factor = 1.0 + (infra_overlap_score * 0.25)
        prevalence_factor = 1.0 + (prevalence * 0.20)
        return prevalence_factor * infra_factor

    def _business_impact_weight(self, biz: Optional[BusinessImpactContext]) -> float:
        if biz is None:
            return 1.0
        weighted = (
            biz.data_sensitivity   * 0.30 +
            biz.revenue_impact     * 0.25 +
            biz.regulatory_exposure* 0.25 +
            biz.availability_impact* 0.15 +
            biz.brand_impact       * 0.05
        )
        # Cap business impact amplification at 1.40 to prevent inflation
        return min(1.0 + (weighted * 0.40), 1.40)

    def _replay_adjustment(self, evidence: TelemetryEvidence) -> float:
        """
        Replay hits directly confirm exploitability in this environment.
        0 hits → slight dampening (theoretical).
        ≥5 hits → meaningful amplification.
        """
        if evidence.replay_hits == 0:
            return 0.90
        elif evidence.replay_hits <= 2:
            return 1.05
        elif evidence.replay_hits <= 5:
            return 1.15
        else:
            return min(1.0 + (evidence.replay_hits / 30.0), 1.25)

    def _compute_confidence_band(
        self,
        governed_score: float,
        evidence: TelemetryEvidence,
    ) -> Tuple[float, float]:
        """
        Confidence band width is inversely proportional to telemetry density.
        Dense evidence → narrow band. Sparse → wide band.
        """
        density = evidence.density_score
        band_width = max(0.05, 0.40 * (1.0 - density))
        low  = max(0.0, governed_score - (governed_score * band_width))
        high = min(10.0, governed_score + (governed_score * band_width * 0.5))
        return (round(low, 2), round(high, 2))

    def _derive_narrative_depth(
        self,
        governed_score: float,
        evidence: TelemetryEvidence,
    ) -> Tuple[NarrativeDepth, bool]:
        """
        Derive narrative depth from (governed_score, telemetry_density).
        Returns (depth, inflation_blocked).
        """
        density = evidence.density_score
        inflation_blocked = False

        # Walk the matrix from highest to lowest
        for min_score, min_density, depth in self.DEPTH_MATRIX:
            if governed_score >= min_score and density >= min_density:
                # Governance check: would un-gated score inflate depth?
                raw_depth_idx = self._raw_depth_index(governed_score)
                gated_depth_idx = list(NarrativeDepth).index(depth)
                if raw_depth_idx < gated_depth_idx:
                    inflation_blocked = True
                return depth, inflation_blocked

        return NarrativeDepth.SINGLE_LINE, False

    def _raw_depth_index(self, score: float) -> int:
        """What depth index would CVSS score alone yield (ungated)?"""
        if score >= 9.0:   return 0  # COMPREHENSIVE
        if score >= 7.5:   return 1  # EXPANDED
        if score >= 5.0:   return 2  # STANDARD
        if score >= 3.0:   return 3  # CONCISE
        return 4                     # SINGLE_LINE

    def _build_operational_summary(
        self,
        result_partial: Dict[str, Any],
        depth: NarrativeDepth,
        evidence: TelemetryEvidence,
        cvss: CVSSContext,
        finding_id: str,
    ) -> str:
        """
        Generate operational summary scaled to narrative depth.
        GOVERNANCE: no geopolitical inflation, no repeated remediation prose.
        """
        score = result_partial["governed_score"]
        tier = result_partial["risk_tier"]
        replay_str = f" Confirmed via {evidence.replay_hits} replay hits." if evidence.replay_hits else ""
        kev_str = " [KEV LISTED — CISA confirmed active exploitation]" if cvss.kev_listed else ""
        attck_str = (
            f" ATT&CK coverage: {evidence.attck_technique_count} techniques across "
            f"{evidence.attck_tactic_count} tactics."
            if evidence.attck_technique_count > 0 else ""
        )
        ioc_str = f" {evidence.ioc_hits} IOC hits in telemetry." if evidence.ioc_hits > 0 else ""

        if depth == NarrativeDepth.SINGLE_LINE:
            return (
                f"{tier} finding [{finding_id}]. Governed score: {score:.1f}/10. "
                f"Insufficient telemetry for expanded analysis."
            )

        if depth == NarrativeDepth.CONCISE:
            return (
                f"{tier} severity finding [{finding_id}]. Governed score: {score:.1f}/10 "
                f"(CVSS base: {cvss.base_score:.1f}). "
                f"Telemetry density: {evidence.density_score:.2f} — "
                f"{evidence.raw_event_count} raw events observed.{ioc_str}{replay_str} "
                f"Exploitability: {cvss.exploitability.value}."
            )

        if depth == NarrativeDepth.STANDARD:
            return (
                f"{tier} severity finding [{finding_id}]. Governed score: {score:.1f}/10 "
                f"(CVSS base: {cvss.base_score:.1f}, EPSS: {cvss.epss_probability:.3f}).{kev_str} "
                f"Telemetry basis: {evidence.raw_event_count} raw events, "
                f"{evidence.enriched_event_count} enriched, {evidence.ioc_hits} IOC hits "
                f"across {evidence.unique_affected_hosts} affected hosts.{replay_str} "
                f"Exploitability: {cvss.exploitability.value}. "
                f"Network exposure: {cvss.network_exposure:.1%}. "
                f"Asset criticality: {cvss.affected_asset_criticality:.1%}.{attck_str}"
            )

        if depth == NarrativeDepth.EXPANDED:
            return (
                f"{tier} severity finding [{finding_id}]. Governed score: {score:.1f}/10 "
                f"(CVSS base: {cvss.base_score:.1f}, EPSS: {cvss.epss_probability:.3f} "
                f"[{cvss.epss_percentile:.1%} percentile]).{kev_str} "
                f"Telemetry basis: {evidence.raw_event_count} raw events, "
                f"{evidence.enriched_event_count} enriched events, "
                f"{evidence.graph_node_matches} graph node matches, "
                f"{evidence.ioc_hits} IOC hits, "
                f"{evidence.honeynet_observations} honeynet observations "
                f"across {evidence.unique_affected_hosts} hosts "
                f"({evidence.unique_source_ips} unique source IPs).{replay_str} "
                f"Campaign correlation: {evidence.campaign_correlation_score:.2f}. "
                f"Source trust: {evidence.source_trust_score:.2f}.{attck_str} "
                f"Exploitability: {cvss.exploitability.value}. "
                f"Patch status: {'available ({} days old)'.format(cvss.patch_age_days) if cvss.patch_available else 'not available'}."
            )

        # COMPREHENSIVE
        return (
            f"{tier} severity finding [{finding_id}]. Governed score: {score:.1f}/10 "
            f"(CVSS base: {cvss.base_score:.1f}, EPSS: {cvss.epss_probability:.3f} "
            f"[{cvss.epss_percentile:.1%} percentile]).{kev_str} "
            f"TELEMETRY EVIDENCE: {evidence.raw_event_count} raw events | "
            f"{evidence.enriched_event_count} enriched | "
            f"{evidence.replay_hits} replay hits | "
            f"{evidence.graph_node_matches} graph nodes | "
            f"{evidence.ioc_hits} IOC hits | "
            f"{evidence.honeynet_observations} honeynet observations | "
            f"{evidence.unique_affected_hosts} affected hosts | "
            f"{evidence.unique_source_ips} source IPs | "
            f"observation window: {evidence.observation_window_hours}h. "
            f"Campaign correlation: {evidence.campaign_correlation_score:.2f}. "
            f"Source trust: {evidence.source_trust_score:.2f}.{attck_str} "
            f"EXPLOITABILITY: {cvss.exploitability.value}. "
            f"EPSS probability: {cvss.epss_probability:.3f} ({cvss.epss_percentile:.1%} pct). "
            f"Patch available: {'yes — {} days since release'.format(cvss.patch_age_days) if cvss.patch_available else 'NO — no patch available'}. "
            f"Network exposure: {cvss.network_exposure:.1%}. "
            f"Asset criticality: {cvss.affected_asset_criticality:.1%}. "
            f"GOVERNANCE: narrative depth {depth.value} | density {evidence.density_score:.2f} | "
            f"confidence band [{score - (score * 0.1):.1f}, {min(score + (score * 0.05), 10.0):.1f}]."
        )

    def _build_remediation_priority(
        self,
        tier: RiskTier,
        depth: NarrativeDepth,
        cvss: CVSSContext,
        evidence: TelemetryEvidence,
    ) -> str:
        """Concise, operationally specific remediation — scaled to tier."""
        if depth in (NarrativeDepth.SINGLE_LINE, NarrativeDepth.CONCISE):
            return f"Standard patch cycle. No accelerated response required."

        if tier == RiskTier.LOW:
            return (
                f"Schedule patching within next maintenance window. "
                f"{'Apply available patch.' if cvss.patch_available else 'Monitor for patch release.'}"
            )
        if tier == RiskTier.MEDIUM:
            return (
                f"Patch within 30 days. "
                f"Monitor {evidence.unique_affected_hosts} affected host(s) for exploitation indicators. "
                f"{'Apply patch ({} days available).'.format(cvss.patch_age_days) if cvss.patch_available else 'Implement compensating control — no patch available.'}"
            )
        if tier == RiskTier.HIGH:
            return (
                f"Patch within 7–14 days. "
                f"Isolate high-criticality assets (score: {cvss.affected_asset_criticality:.1%}). "
                f"Deploy detection rule for {evidence.attck_technique_count} identified ATT&CK technique(s). "
                f"{'Emergency patch cycle warranted — EPSS: {:.3f}.'.format(cvss.epss_probability) if cvss.epss_probability > 0.5 else ''}"
            )
        # CRITICAL
        return (
            f"IMMEDIATE action required. "
            f"{'KEV-listed — CISA mandates federal patching. ' if cvss.kev_listed else ''}"
            f"Emergency patch within 24–72h. "
            f"Isolate {evidence.unique_affected_hosts} affected host(s). "
            f"Deploy {evidence.attck_technique_count} ATT&CK-mapped detection rule(s). "
            f"Activate incident response. "
            f"EPSS: {cvss.epss_probability:.3f} ({cvss.epss_percentile:.1%} percentile)."
        )

    def _classify_tier(self, score: float) -> RiskTier:
        if score >= 9.0:  return RiskTier.CRITICAL
        if score >= 7.0:  return RiskTier.HIGH
        if score >= 4.0:  return RiskTier.MEDIUM
        if score >= 1.0:  return RiskTier.LOW
        return RiskTier.INFORMATIONAL

    def score(
        self,
        finding_id: str,
        cvss: CVSSContext,
        evidence: TelemetryEvidence,
        business_impact: Optional[BusinessImpactContext] = None,
        infrastructure_overlap_score: float = 0.0,
    ) -> RiskScoringResult:
        """
        Compute governed risk score for a single finding.

        Args:
            finding_id: Unique finding identifier
            cvss: CVSS context including EPSS and KEV status
            evidence: Telemetry evidence package
            business_impact: Optional business impact weighting
            infrastructure_overlap_score: 0.0–1.0 shared infra overlap

        Returns:
            RiskScoringResult with full score decomposition
        """
        # Compute individual weights
        tel_w   = self._telemetry_weight(evidence)
        exp_w   = self._exploitability_weight(cvss)
        env_w   = self._environmental_weight(evidence, infrastructure_overlap_score)
        biz_w   = self._business_impact_weight(business_impact)
        rep_adj = self._replay_adjustment(evidence)
        infra_w = 1.0 + (infrastructure_overlap_score * 0.15)

        # Governed score formula
        governed = (
            cvss.base_score
            * tel_w
            * exp_w
            * env_w
            * biz_w
            * rep_adj
            * infra_w
        )
        governed = round(min(governed, self.max_governed_score), 2)

        tier = self._classify_tier(governed)
        depth, inflation_blocked = self._derive_narrative_depth(governed, evidence)

        confidence_band = self._compute_confidence_band(governed, evidence)

        partial = {"governed_score": governed, "risk_tier": tier.value}

        summary = self._build_operational_summary(
            partial, depth, evidence, cvss, finding_id
        )
        remediation = self._build_remediation_priority(
            tier, depth, cvss, evidence
        )

        # Analyst note: always technical, never narrative
        analyst_note = (
            f"Density: {evidence.density_score:.2f} | "
            f"Tel.weight: {tel_w:.2f} | Exploit.weight: {exp_w:.2f} | "
            f"Env.weight: {env_w:.2f} | Biz.weight: {biz_w:.2f} | "
            f"Replay adj: {rep_adj:.2f} | Infra.weight: {infra_w:.2f} | "
            f"Replay hits: {evidence.replay_hits} | "
            f"EPSS: {cvss.epss_probability:.3f} | KEV: {cvss.kev_listed}"
        )

        # Count contributing signals
        signal_count = sum([
            evidence.raw_event_count > 0,
            evidence.enriched_event_count > 0,
            evidence.replay_hits > 0,
            evidence.graph_node_matches > 0,
            evidence.ioc_hits > 0,
            evidence.attck_technique_count > 0,
            evidence.honeynet_observations > 0,
            evidence.campaign_correlation_score > 0.1,
            cvss.kev_listed,
            cvss.epss_probability > 0.01,
        ])

        return RiskScoringResult(
            finding_id=finding_id,
            base_cvss=cvss.base_score,
            governed_score=governed,
            risk_tier=tier,
            narrative_depth=depth,
            telemetry_weight=round(tel_w, 4),
            exploitability_weight=round(exp_w, 4),
            environmental_weight=round(env_w, 4),
            business_impact_weight=round(biz_w, 4),
            replay_adjustment=round(rep_adj, 4),
            infrastructure_overlap_weight=round(infra_w, 4),
            telemetry_density=evidence.density_score,
            evidence_signal_count=signal_count,
            replay_confirmed=evidence.replay_hits > 0,
            kev_listed=cvss.kev_listed,
            active_exploitation=(
                cvss.exploitability == ExploitabilityStatus.ACTIVE_EXPLOITATION
            ),
            narrative_inflation_blocked=inflation_blocked,
            geopolitical_inflation_blocked=True,   # Always enforced
            confidence_band=confidence_band,
            operational_summary=summary,
            remediation_priority=remediation,
            analyst_note=analyst_note,
            scored_at=datetime.now(timezone.utc).isoformat(),
        )

    def score_batch(
        self,
        findings: List[Dict[str, Any]],
    ) -> List[RiskScoringResult]:
        """Score a batch of findings and return sorted by governed score desc."""
        results = []
        for f in findings:
            try:
                result = self.score(
                    finding_id=f["finding_id"],
                    cvss=f["cvss"],
                    evidence=f["evidence"],
                    business_impact=f.get("business_impact"),
                    infrastructure_overlap_score=f.get("infra_overlap", 0.0),
                )
                results.append(result)
            except Exception as exc:
                logger.error("Failed to score finding %s: %s", f.get("finding_id"), exc)
        return sorted(results, key=lambda r: r.governed_score, reverse=True)


# ─────────────────────────────────────────────────────────────
# GOVERNANCE AUDITOR
# ─────────────────────────────────────────────────────────────

class RiskGovernanceAuditor:
    """
    Post-scoring auditor that validates output quality.
    Detects: inflation, deflation, geopolitical leakage, depth inconsistencies.
    """

    INFLATION_KEYWORDS = [
        "nation-state sponsored", "geopolitical", "state-nexus",
        "threat landscape", "sophisticated campaign", "advanced persistent",
        "unprecedented scale", "global threat actor",
    ]

    def audit_result(self, result: RiskScoringResult) -> Dict[str, Any]:
        issues = []

        # Check for inflation keywords in narrative
        summary_lower = result.operational_summary.lower()
        for kw in self.INFLATION_KEYWORDS:
            if kw in summary_lower:
                issues.append({
                    "type": "GEOPOLITICAL_INFLATION",
                    "keyword": kw,
                    "severity": "GOVERNANCE_VIOLATION",
                })

        # Check depth vs density consistency
        if result.narrative_depth == NarrativeDepth.COMPREHENSIVE and result.telemetry_density < 0.5:
            issues.append({
                "type": "DEPTH_INFLATION",
                "detail": f"COMPREHENSIVE depth at density {result.telemetry_density:.2f} — insufficient evidence",
                "severity": "WARNING",
            })

        # Check confidence band width
        band_width = result.confidence_band[1] - result.confidence_band[0]
        if band_width < 0.5 and result.telemetry_density < 0.3:
            issues.append({
                "type": "CONFIDENCE_INFLATION",
                "detail": f"Narrow confidence band ({band_width:.2f}) with low density ({result.telemetry_density:.2f})",
                "severity": "WARNING",
            })

        # Check governed vs base score ratio for extreme inflation
        if result.base_cvss > 0:
            ratio = result.governed_score / result.base_cvss
            if ratio > 1.8:
                issues.append({
                    "type": "SCORE_INFLATION",
                    "detail": f"Governed/base ratio {ratio:.2f} exceeds 1.8 — review weights",
                    "severity": "WARNING",
                })

        return {
            "finding_id": result.finding_id,
            "governed_score": result.governed_score,
            "risk_tier": result.risk_tier.value,
            "narrative_depth": result.narrative_depth.value,
            "issues": issues,
            "governance_pass": len(issues) == 0,
            "audited_at": datetime.now(timezone.utc).isoformat(),
        }

    def audit_batch(self, results: List[RiskScoringResult]) -> Dict[str, Any]:
        audits = [self.audit_result(r) for r in results]
        violations = [a for a in audits if not a["governance_pass"]]
        return {
            "total_scored": len(results),
            "governance_pass": len(results) - len(violations),
            "governance_violations": len(violations),
            "violation_details": violations,
            "pass_rate": round((len(results) - len(violations)) / max(len(results), 1) * 100, 1),
            "audited_at": datetime.now(timezone.utc).isoformat(),
        }
