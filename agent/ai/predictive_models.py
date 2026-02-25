#!/usr/bin/env python3
"""
predictive_models.py — CYBERDUDEBIVASH® SENTINEL APEX v24.0
AI-Driven Predictive Threat Intelligence Models.

Non-Breaking Addition: Standalone AI model module.
Does NOT modify existing risk_engine.py or any core pipeline module.

Models Included:
    1. ExploitProbabilityModel    — Beyond CVSS/EPSS: multi-signal exploit probability
    2. ThreatActorAttributionModel — Attribution confidence scoring
    3. IndustryImpactModel         — Sector/industry blast radius prediction
    4. FinancialImpactModel         — Estimated financial damage range
    5. TriagePrioritizationModel    — SOC triage score for analyst workflow
    6. ThreatMomentumModel          — Attack campaign velocity and momentum
    7. AttackSurfaceModel           — Attack surface exposure assessment

These models augment the existing risk scoring — they do NOT replace it.
All scores are additive fields in the manifest entry.

Author: CyberDudeBivash Pvt. Ltd.
Platform: https://intel.cyberdudebivash.com
"""

import re
import math
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple, Any

logger = logging.getLogger("CDB-AI-Models")

MODELS_VERSION = "1.0.0"


# ─────────────────────────────────────────────────────────────────────────────
# 1. Exploit Probability Model
# ─────────────────────────────────────────────────────────────────────────────

class ExploitProbabilityModel:
    """
    Multi-signal exploit probability prediction model.

    Goes beyond raw CVSS/EPSS by combining:
    - CVSS base score (normalized)
    - EPSS probability
    - KEV status (confirmed exploitation)
    - Public PoC availability
    - Threat actor interest level
    - Vulnerability age (newer = higher risk window)
    - Attack complexity and privileges required
    - Network accessibility

    Output: exploit_probability (0.0-1.0) + exploit_tier label
    """

    # Tier thresholds
    TIER_CRITICAL  = 0.85
    TIER_HIGH      = 0.65
    TIER_MEDIUM    = 0.40
    TIER_LOW       = 0.20

    def predict(self, entry: Dict) -> Dict:
        """
        Predict exploit probability for a threat advisory entry.

        Args:
            entry: Manifest entry dict with CVSS, EPSS, KEV, actor, etc.

        Returns:
            dict with: exploit_probability, exploit_tier, signal_breakdown, confidence_level
        """
        signals  = {}
        score    = 0.0
        max_score = 0.0

        # ── Signal 1: CVSS Score (0-10 → 0-0.30 weight) ──
        cvss = float(entry.get("cvss_score") or 0)
        if cvss > 0:
            cvss_contrib = min(cvss / 10.0, 1.0) * 0.25
            score       += cvss_contrib
            signals["cvss"] = round(cvss_contrib, 4)
        max_score += 0.25

        # ── Signal 2: EPSS Probability (0-1 → 0-0.30 weight) ──
        epss = float(entry.get("epss_score") or 0)
        if epss > 0:
            # Amplify high EPSS: non-linear scaling
            epss_contrib = (epss ** 0.5) * 0.30
            score       += epss_contrib
            signals["epss"] = round(epss_contrib, 4)
        max_score += 0.30

        # ── Signal 3: CISA KEV Status (confirmed exploitation = +0.25) ──
        kev = bool(entry.get("kev_present") or entry.get("kev_confirmed"))
        if kev:
            score         += 0.25
            signals["kev"] = 0.25
        max_score += 0.25

        # ── Signal 4: Public PoC Availability ──
        has_poc = bool(entry.get("poc_public") or self._detect_poc_signals(entry))
        if has_poc:
            score           += 0.10
            signals["poc"]   = 0.10
        max_score += 0.10

        # ── Signal 5: Nation-State Actor Attribution ──
        actor_tag = str(entry.get("actor_tag") or "")
        nation_state_keywords = ["apt", "ta", "lazarus", "sandworm", "cozy bear",
                                  "fancy bear", "charcoal typhoon", "volt typhoon", "salt typhoon"]
        is_nation_state = any(kw in actor_tag.lower() for kw in nation_state_keywords)
        if is_nation_state:
            score                   += 0.07
            signals["nation_state"]  = 0.07
        max_score += 0.07

        # ── Signal 6: Supply Chain Involvement ──
        supply_chain_keywords = ["supply chain", "npm", "pypi", "dependency", "build pipeline"]
        title_lower = (entry.get("title") or "").lower()
        is_supply_chain = any(kw in title_lower for kw in supply_chain_keywords)
        if is_supply_chain:
            score                     += 0.05
            signals["supply_chain"]    = 0.05
        max_score += 0.05

        # ── Signal 7: Active Exploitation Indicators ──
        active_exploit_keywords = ["actively exploited", "in the wild", "0-day", "zero-day",
                                    "zero day", "mass exploitation", "widespread exploitation"]
        is_active = any(kw in title_lower for kw in active_exploit_keywords)
        if is_active:
            score                    += 0.08
            signals["active_exploit"] = 0.08
        max_score += 0.08

        # Normalize to 0-1
        final_prob = min(score / max_score if max_score > 0 else 0, 1.0)
        final_prob = round(final_prob, 4)

        # Tier classification
        if final_prob >= self.TIER_CRITICAL:
            tier = "CRITICAL"
        elif final_prob >= self.TIER_HIGH:
            tier = "HIGH"
        elif final_prob >= self.TIER_MEDIUM:
            tier = "MEDIUM"
        elif final_prob >= self.TIER_LOW:
            tier = "LOW"
        else:
            tier = "MINIMAL"

        # Confidence based on signal richness
        signal_count = len(signals)
        confidence = min(signal_count / 7 * 100, 95)

        return {
            "exploit_probability":    final_prob,
            "exploit_probability_pct": round(final_prob * 100, 1),
            "exploit_tier":           tier,
            "signal_breakdown":       signals,
            "signal_count":           signal_count,
            "confidence_level":       round(confidence, 1),
            "model":                  "CDB-ExploitProb-v1",
            "computed_at":            datetime.now(timezone.utc).isoformat(),
        }

    def _detect_poc_signals(self, entry: Dict) -> bool:
        """Detect PoC availability signals from entry content."""
        poc_keywords = ["poc", "exploit", "proof of concept", "github.com/exploit",
                        "exploit-db", "nuclei template", "metasploit module"]
        text = " ".join([
            str(entry.get("title", "")),
            str(entry.get("source_url", "")),
        ]).lower()
        return any(kw in text for kw in poc_keywords)


# ─────────────────────────────────────────────────────────────────────────────
# 2. Threat Actor Attribution Confidence Model
# ─────────────────────────────────────────────────────────────────────────────

class ThreatActorAttributionModel:
    """
    Attribution confidence scoring for threat actor identification.

    Attribution is often uncertain — this model scores the confidence
    of an actor attribution based on available intelligence signals.
    """

    # Known APT/actor database for cross-referencing
    KNOWN_ACTORS = {
        "apt28": {"aliases": ["fancy bear", "sofacy", "pawn storm"], "nation": "Russia", "tier": "A"},
        "apt29": {"aliases": ["cozy bear", "nobelium", "midnight blizzard"], "nation": "Russia", "tier": "A"},
        "apt41": {"aliases": ["double dragon", "winnti"], "nation": "China", "tier": "A"},
        "lazarus": {"aliases": ["hidden cobra", "guardians of peace"], "nation": "North Korea", "tier": "A"},
        "sandworm": {"aliases": ["voodoo bear", "iridium"], "nation": "Russia", "tier": "A"},
        "volt_typhoon": {"aliases": ["volt typhoon", "bronze silhouette"], "nation": "China", "tier": "A"},
        "salt_typhoon": {"aliases": ["salt typhoon", "ghostemperor"], "nation": "China", "tier": "A"},
        "charcoal_typhoon": {"aliases": ["charcoal typhoon", "chromium"], "nation": "China", "tier": "B"},
        "fin7": {"aliases": ["navigator group", "sangria tempest"], "nation": "Unknown/RU", "tier": "B"},
        "ta505": {"aliases": ["evil corp adjacent"], "nation": "Russia", "tier": "B"},
        "lockbit": {"aliases": ["lockbit 3.0", "lb3"], "nation": "Unknown/RU", "tier": "B"},
        "alphv": {"aliases": ["blackcat", "alphvm", "noberus"], "nation": "Unknown/RU", "tier": "B"},
        "cl0p": {"aliases": ["ta505", "clop"], "nation": "Russia/Ukraine", "tier": "B"},
    }

    def score_attribution(self, entry: Dict) -> Dict:
        """
        Score the confidence of threat actor attribution in an entry.

        Returns:
            dict with: attribution_confidence, attributed_actor, actor_nation,
                       actor_tier, attribution_signals
        """
        actor_tag = str(entry.get("actor_tag") or "").lower()
        title     = str(entry.get("title") or "").lower()
        signals   = {}
        confidence = 0.0

        # Check for known actor match
        matched_actor = None
        for actor_id, actor_data in self.KNOWN_ACTORS.items():
            all_aliases = [actor_id] + actor_data.get("aliases", [])
            for alias in all_aliases:
                if alias.lower() in actor_tag or alias.lower() in title:
                    matched_actor = (actor_id, actor_data)
                    signals["known_actor_match"] = actor_id
                    confidence += 0.40
                    break
            if matched_actor:
                break

        # Tier A actor = higher confidence bonus
        if matched_actor and matched_actor[1].get("tier") == "A":
            confidence += 0.15
            signals["tier_a_actor"] = True

        # MITRE techniques reinforce attribution (shared TTPs)
        mitre_tactics = entry.get("mitre_tactics", [])
        if len(mitre_tactics) >= 3:
            confidence += 0.10
            signals["mitre_ttp_depth"] = len(mitre_tactics)

        # IOC richness (more IOCs = better forensic basis)
        ioc_count = int(entry.get("ioc_count") or len(entry.get("iocs", [])))
        if ioc_count >= 10:
            confidence += 0.15
            signals["ioc_richness"] = ioc_count
        elif ioc_count >= 5:
            confidence += 0.08

        # CVSS/risk alignment
        risk_score = float(entry.get("risk_score") or 0)
        if risk_score >= 8.0 and matched_actor:
            confidence += 0.10
            signals["high_risk_actor_alignment"] = risk_score

        # Structured actor_tag (not generic UNC-CDB-99)
        if actor_tag and "unc-cdb" not in actor_tag and actor_tag not in ("unknown", ""):
            confidence += 0.05
            signals["structured_actor_tag"] = True

        confidence = min(round(confidence, 4), 1.0)

        # Classification
        if confidence >= 0.80:
            attribution_label = "HIGH CONFIDENCE"
        elif confidence >= 0.55:
            attribution_label = "MODERATE CONFIDENCE"
        elif confidence >= 0.30:
            attribution_label = "LOW CONFIDENCE"
        else:
            attribution_label = "SUSPECTED / UNATTRIBUTED"

        result = {
            "attribution_confidence":     round(confidence * 100, 1),
            "attribution_confidence_raw": confidence,
            "attribution_label":          attribution_label,
            "attribution_signals":        signals,
            "model":                      "CDB-Attribution-v1",
            "computed_at":                datetime.now(timezone.utc).isoformat(),
        }

        if matched_actor:
            actor_id, actor_data = matched_actor
            result["attributed_actor"]   = actor_id
            result["actor_nation"]        = actor_data.get("nation", "Unknown")
            result["actor_tier"]          = actor_data.get("tier", "C")
            result["actor_aliases"]       = actor_data.get("aliases", [])

        return result


# ─────────────────────────────────────────────────────────────────────────────
# 3. Industry Impact Model
# ─────────────────────────────────────────────────────────────────────────────

class IndustryImpactModel:
    """
    Predicts industry/sector impact for each threat advisory.

    Maps threat characteristics → affected industries with impact scores.
    Outputs sector-specific risk levels for targeted alerting.
    """

    # Sector targeting patterns based on threat intelligence
    SECTOR_SIGNALS = {
        "healthcare": {
            "keywords": ["hospital", "medical", "healthcare", "health system", "ehr", "patient",
                         "ransomware hospital", "medibanl", "anthem", "hipaa"],
            "threat_types": ["ransomware", "data_breach", "phishing"],
            "base_risk": 8.5,
        },
        "financial": {
            "keywords": ["bank", "financial", "swift", "payment", "fintech", "trading",
                         "atm", "wire transfer", "credit card", "banking trojan"],
            "threat_types": ["banking_trojan", "fraud", "data_breach"],
            "base_risk": 9.0,
        },
        "critical_infrastructure": {
            "keywords": ["ics", "scada", "operational technology", "ot", "power grid",
                         "water treatment", "oil pipeline", "industrial control", "plc", "hmi"],
            "threat_types": ["apt", "nation_state", "sabotage"],
            "base_risk": 9.5,
        },
        "government": {
            "keywords": ["government", "federal", "agency", "ministry", "espionage",
                         "classified", "defense", "military", "state actor", "nato"],
            "threat_types": ["espionage", "nation_state", "apt"],
            "base_risk": 8.8,
        },
        "technology": {
            "keywords": ["software", "saas", "cloud", "api", "supply chain", "npm", "pypi",
                         "github", "aws", "azure", "gcp", "developer", "ci/cd"],
            "threat_types": ["supply_chain", "zero_day", "code_injection"],
            "base_risk": 8.0,
        },
        "retail": {
            "keywords": ["retail", "ecommerce", "shopping", "consumer", "point of sale",
                         "pos system", "magecart", "skimmer", "checkout"],
            "threat_types": ["magecart", "data_breach", "skimmer"],
            "base_risk": 7.0,
        },
        "telecommunications": {
            "keywords": ["telecom", "carrier", "isp", "telco", "5g", "ss7",
                         "sim swap", "cell tower", "network infrastructure"],
            "threat_types": ["nation_state", "espionage", "apt"],
            "base_risk": 8.2,
        },
        "education": {
            "keywords": ["university", "school", "college", "education", "student",
                         "academic", "research institution"],
            "threat_types": ["ransomware", "data_breach", "phishing"],
            "base_risk": 6.5,
        },
    }

    def predict_impact(self, entry: Dict) -> Dict:
        """
        Predict industry impact of a threat advisory.

        Returns:
            dict with: affected_sectors, primary_sector, sector_risk_scores,
                       blast_radius, industry_impact_level
        """
        title   = (entry.get("title") or "").lower()
        content = (entry.get("source_content") or entry.get("summary") or "").lower()
        full_text = f"{title} {content}"

        sector_scores = {}

        for sector, config in self.SECTOR_SIGNALS.items():
            score = 0.0
            matched_keywords = [kw for kw in config["keywords"] if kw in full_text]
            if matched_keywords:
                score += min(len(matched_keywords) * 0.15, 0.60)

            # Boost for high-risk sectors on high-severity threats
            risk = float(entry.get("risk_score") or 0)
            if risk >= 8.0:
                score += config["base_risk"] / 100

            if score > 0.1:
                sector_scores[sector] = round(score, 4)

        if not sector_scores:
            sector_scores["general_enterprise"] = 0.30

        # Primary sector = highest score
        primary = max(sector_scores, key=sector_scores.get) if sector_scores else "general_enterprise"
        max_impact = max(sector_scores.values()) if sector_scores else 0

        # Blast radius: how many sectors are affected
        high_impact = [s for s, v in sector_scores.items() if v > 0.3]
        if len(high_impact) >= 4:
            blast_radius = "WIDESPREAD"
        elif len(high_impact) >= 2:
            blast_radius = "MULTI-SECTOR"
        else:
            blast_radius = "TARGETED"

        # Overall level
        if max_impact >= 0.7:
            impact_level = "CRITICAL"
        elif max_impact >= 0.5:
            impact_level = "HIGH"
        elif max_impact >= 0.3:
            impact_level = "MEDIUM"
        else:
            impact_level = "LOW"

        return {
            "affected_sectors":     sorted(sector_scores.keys()),
            "primary_sector":       primary,
            "sector_risk_scores":   sector_scores,
            "blast_radius":         blast_radius,
            "industry_impact_level": impact_level,
            "high_impact_sectors":  high_impact,
            "model":                "CDB-IndustryImpact-v1",
            "computed_at":          datetime.now(timezone.utc).isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# 4. Financial Impact Model
# ─────────────────────────────────────────────────────────────────────────────

class FinancialImpactModel:
    """
    Estimates the financial damage range for a threat advisory.

    Based on:
    - Threat category (ransomware vs. data breach vs. espionage)
    - Organization size (SMB vs. enterprise vs. critical infrastructure)
    - Affected sectors (healthcare = higher regulatory fines)
    - Severity and exploitation status
    - Historical breach cost data (IBM Cost of a Data Breach 2024)

    Output: estimated_loss_min, estimated_loss_max, currency: USD
    """

    # Average breach costs by category (USD, IBM 2024 data + industry research)
    BASE_COSTS = {
        "ransomware":            {"min": 500_000, "max": 50_000_000},
        "data_breach":           {"min": 200_000, "max": 10_000_000},
        "nation_state":          {"min": 5_000_000, "max": 500_000_000},
        "critical_infra":        {"min": 10_000_000, "max": 1_000_000_000},
        "supply_chain":          {"min": 1_000_000, "max": 100_000_000},
        "business_email":        {"min": 50_000, "max": 2_000_000},
        "zero_day":              {"min": 1_000_000, "max": 50_000_000},
        "generic_malware":       {"min": 100_000, "max": 5_000_000},
    }

    # Sector multipliers (some sectors have higher regulatory exposure)
    SECTOR_MULTIPLIERS = {
        "healthcare":            2.5,   # HIPAA fines + breach notification
        "financial":             2.2,   # PCI-DSS + regulatory penalties
        "critical_infrastructure": 3.0,
        "government":            1.8,
        "technology":            1.5,
        "retail":                1.3,
        "education":             1.1,
        "telecommunications":    1.7,
    }

    def estimate(self, entry: Dict, sector: Optional[str] = None) -> Dict:
        """
        Estimate financial impact of a threat advisory.

        Args:
            entry:  Manifest entry dict.
            sector: Target sector (uses detection if None).

        Returns:
            dict with: loss_min_usd, loss_max_usd, loss_range_label,
                       confidence, threat_category, assumptions
        """
        title   = (entry.get("title") or "").lower()
        risk    = float(entry.get("risk_score") or 5.0)

        # Detect threat category
        category = "generic_malware"
        category_rules = [
            ("ransomware",       ["ransomware", "lockbit", "alphv", "cl0p", "conti", "akira"]),
            ("data_breach",      ["data breach", "leak", "exposed records", "data dump"]),
            ("nation_state",     ["nation state", "apt", "state-sponsored", "espionage"]),
            ("critical_infra",   ["scada", "ics", "power grid", "water treatment", "ot attack"]),
            ("supply_chain",     ["supply chain", "npm backdoor", "pypi malware", "build pipeline"]),
            ("business_email",   ["bec", "business email", "wire fraud"]),
            ("zero_day",         ["zero-day", "0-day", "zero day", "unpatched"]),
        ]
        for cat, keywords in category_rules:
            if any(kw in title for kw in keywords):
                category = cat
                break

        base = self.BASE_COSTS.get(category, self.BASE_COSTS["generic_malware"])

        # Risk score multiplier
        risk_mult = 1.0 + (risk - 5.0) / 10.0  # 0.5x at risk=0, 1.5x at risk=10
        risk_mult = max(0.5, min(risk_mult, 2.0))

        # Sector multiplier
        sector_mult = 1.0
        if sector:
            sector_mult = self.SECTOR_MULTIPLIERS.get(sector, 1.0)

        loss_min = int(base["min"] * risk_mult * sector_mult)
        loss_max = int(base["max"] * risk_mult * sector_mult)

        # KEV = confirmed exploitation → increase upper bound
        if entry.get("kev_present") or entry.get("kev_confirmed"):
            loss_max = int(loss_max * 1.5)
            loss_min = int(loss_min * 1.3)

        def _format_usd(n: int) -> str:
            if n >= 1_000_000_000:
                return f"${n/1_000_000_000:.1f}B"
            elif n >= 1_000_000:
                return f"${n/1_000_000:.1f}M"
            elif n >= 1_000:
                return f"${n/1_000:.0f}K"
            return f"${n:,}"

        return {
            "loss_min_usd":       loss_min,
            "loss_max_usd":       loss_max,
            "loss_min_formatted": _format_usd(loss_min),
            "loss_max_formatted": _format_usd(loss_max),
            "loss_range_label":   f"{_format_usd(loss_min)} – {_format_usd(loss_max)} USD",
            "threat_category":    category,
            "risk_multiplier":    round(risk_mult, 2),
            "sector_multiplier":  sector_mult,
            "confidence":         "INDICATIVE",
            "methodology":        "CDB Financial Impact Model v1.0 (IBM Cost of Data Breach 2024 baseline)",
            "disclaimer":         "Estimates are indicative ranges based on historical breach data and threat characterization. Actual costs vary significantly.",
            "model":              "CDB-FinancialImpact-v1",
            "computed_at":        datetime.now(timezone.utc).isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# 5. SOC Triage Prioritization Model
# ─────────────────────────────────────────────────────────────────────────────

class TriagePrioritizationModel:
    """
    SOC triage prioritization score for analyst workflow optimization.

    Generates a composite triage score (0-100) to help SOC analysts
    prioritize which threats to investigate first based on:
    - Exploitation urgency
    - Detection availability
    - Remediation complexity
    - Organizational relevance
    """

    def score(self, entry: Dict, org_sector: Optional[str] = None, has_detection: bool = False) -> Dict:
        """
        Compute SOC triage priority score.

        Args:
            entry:        Manifest entry dict.
            org_sector:   Your organization's sector (for relevance scoring).
            has_detection: Whether detection rules exist for this threat.

        Returns:
            dict with: triage_score, triage_priority, action_recommended, sla_hours
        """
        score = 0.0

        # ── Exploitation urgency (0-35 pts) ──
        risk_score = float(entry.get("risk_score") or 0)
        score += min(risk_score / 10 * 35, 35)

        if entry.get("kev_present") or entry.get("kev_confirmed"):
            score += 15  # Confirmed exploitation → immediate
        if entry.get("poc_public"):
            score += 5

        # ── Data quality (0-15 pts) ──
        quality_map = {"GOLD": 15, "SILVER": 10, "BRONZE": 6, "RAW": 2}
        score += quality_map.get(entry.get("data_quality", "RAW"), 2)

        # ── Detection coverage (0-20 pts) ──
        if has_detection:
            score += 10
        detection_rules = entry.get("detection_rules", {})
        if detection_rules:
            rule_count = sum(len(v) for v in detection_rules.values() if isinstance(v, (list, str)))
            score += min(rule_count * 2, 10)

        # ── Sector relevance (0-15 pts) ──
        if org_sector:
            impact_model = IndustryImpactModel()
            impact = impact_model.predict_impact(entry)
            if org_sector in impact.get("affected_sectors", []):
                sector_score = impact.get("sector_risk_scores", {}).get(org_sector, 0)
                score += sector_score * 15

        # ── IOC richness (0-10 pts) ──
        ioc_count = int(entry.get("ioc_count") or len(entry.get("iocs", [])))
        score += min(ioc_count * 0.5, 5)

        # MITRE coverage
        mitre_count = len(entry.get("mitre_tactics", []) or [])
        score += min(mitre_count * 1.0, 5)

        final_score = min(round(score), 100)

        # Priority tier
        if final_score >= 85:
            priority = "P0 — IMMEDIATE (< 15 min)"
            action   = "Escalate to IR team. Deploy detections NOW. Begin containment."
            sla_h    = 0.25
        elif final_score >= 70:
            priority = "P1 — CRITICAL (< 1 hour)"
            action   = "Assign to senior analyst. Review IOCs. Deploy detection rules."
            sla_h    = 1
        elif final_score >= 55:
            priority = "P2 — HIGH (< 4 hours)"
            action   = "Assign to analyst. Hunt in SIEM. Update block lists."
            sla_h    = 4
        elif final_score >= 35:
            priority = "P3 — MEDIUM (< 24 hours)"
            action   = "Review in next shift. Add to watchlist. Monitor for escalation."
            sla_h    = 24
        else:
            priority = "P4 — LOW (48-72 hours)"
            action   = "Log for awareness. Include in weekly threat brief."
            sla_h    = 72

        return {
            "triage_score":       final_score,
            "triage_priority":    priority,
            "action_recommended": action,
            "sla_hours":          sla_h,
            "score_breakdown": {
                "exploitation_urgency": min(risk_score / 10 * 35, 35),
                "data_quality":         quality_map.get(entry.get("data_quality", "RAW"), 2),
                "ioc_richness":         min(ioc_count * 0.5, 5),
            },
            "model":    "CDB-Triage-v1",
            "computed_at": datetime.now(timezone.utc).isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# 6. Threat Momentum Model
# ─────────────────────────────────────────────────────────────────────────────

class ThreatMomentumModel:
    """
    Detects and measures the velocity and momentum of attack campaigns.
    Identifies rapidly escalating threats before they peak.
    """

    def calculate_momentum(self, entries: List[Dict], threat_signature: str, window_days: int = 7) -> Dict:
        """
        Calculate momentum of a specific threat pattern over a time window.

        Args:
            entries:          List of manifest entries.
            threat_signature: Keyword/pattern to track (e.g., 'ransomware', 'CVE-2024-1234').
            window_days:      Analysis window in days.

        Returns:
            dict with: momentum_score, momentum_label, detection_count, velocity, trend
        """
        from datetime import timedelta
        cutoff = datetime.now(timezone.utc) - timedelta(days=window_days)

        matching     = []
        all_scores   = []

        for entry in entries:
            ts_str = entry.get("generated_at") or entry.get("timestamp") or ""
            title  = (entry.get("title") or "").lower()
            if threat_signature.lower() in title:
                try:
                    if ts_str:
                        ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                        if ts >= cutoff:
                            matching.append(entry)
                            all_scores.append(float(entry.get("risk_score") or 0))
                except Exception:
                    matching.append(entry)
                    all_scores.append(float(entry.get("risk_score") or 0))

        count     = len(matching)
        avg_score = sum(all_scores) / count if count > 0 else 0
        velocity  = count / window_days  # events per day

        # Momentum score: combination of frequency and severity
        momentum = min((velocity * 10) * (avg_score / 10), 10)
        momentum = round(momentum, 2)

        if momentum >= 8.0:
            label = "CRITICAL — RAPIDLY ESCALATING"
            trend = "SURGE"
        elif momentum >= 5.0:
            label = "HIGH — ACTIVE CAMPAIGN"
            trend = "RISING"
        elif momentum >= 2.0:
            label = "MEDIUM — SUSTAINED ACTIVITY"
            trend = "STABLE"
        elif momentum >= 0.5:
            label = "LOW — SPORADIC ACTIVITY"
            trend = "DECLINING"
        else:
            label = "MINIMAL — BACKGROUND NOISE"
            trend = "FLAT"

        return {
            "threat_signature":   threat_signature,
            "window_days":        window_days,
            "detection_count":    count,
            "velocity_per_day":   round(velocity, 2),
            "avg_risk_score":     round(avg_score, 2),
            "momentum_score":     momentum,
            "momentum_label":     label,
            "trend":              trend,
            "model":              "CDB-Momentum-v1",
            "computed_at":        datetime.now(timezone.utc).isoformat(),
        }


# ─────────────────────────────────────────────────────────────────────────────
# 7. Predictive Intelligence Engine (Orchestrator)
# ─────────────────────────────────────────────────────────────────────────────

class PredictiveIntelligenceEngine:
    """
    Master orchestrator for all AI predictive models.
    Applies all models to a manifest entry and returns enriched output.

    Non-Breaking: All predictions are additive fields — original entry unchanged.
    """

    def __init__(self):
        self.exploit_model     = ExploitProbabilityModel()
        self.attribution_model = ThreatActorAttributionModel()
        self.industry_model    = IndustryImpactModel()
        self.financial_model   = FinancialImpactModel()
        self.triage_model      = TriagePrioritizationModel()
        self.momentum_model    = ThreatMomentumModel()

    def enrich_entry(self, entry: Dict, org_sector: Optional[str] = None) -> Dict:
        """
        Apply all predictive models to a single manifest entry.

        Args:
            entry:      Original manifest entry dict.
            org_sector: Your org's sector for triage relevance.

        Returns:
            Enriched entry with 'ai_predictions' field added.
        """
        enriched = dict(entry)
        predictions = {}

        try:
            predictions["exploit_probability"] = self.exploit_model.predict(entry)
        except Exception as e:
            logger.warning(f"ExploitProbabilityModel failed: {e}")

        try:
            predictions["attribution"] = self.attribution_model.score_attribution(entry)
        except Exception as e:
            logger.warning(f"AttributionModel failed: {e}")

        try:
            impact = self.industry_model.predict_impact(entry)
            predictions["industry_impact"] = impact

            # Use detected sector for financial model
            sector = impact.get("primary_sector") or org_sector
            predictions["financial_impact"] = self.financial_model.estimate(entry, sector=sector)
        except Exception as e:
            logger.warning(f"ImpactModels failed: {e}")

        try:
            has_detection = bool(entry.get("detection_rules") or entry.get("sigma_rules"))
            predictions["triage"] = self.triage_model.score(entry, org_sector=org_sector, has_detection=has_detection)
        except Exception as e:
            logger.warning(f"TriageModel failed: {e}")

        predictions["model_version"] = MODELS_VERSION
        predictions["computed_at"]   = datetime.now(timezone.utc).isoformat()

        enriched["ai_predictions"] = predictions
        return enriched

    def enrich_manifest(self, entries: List[Dict], org_sector: Optional[str] = None) -> List[Dict]:
        """
        Apply all predictive models to a full manifest.

        Args:
            entries:    List of manifest entries.
            org_sector: Organization sector for triage relevance.

        Returns:
            List of enriched entries with AI predictions.
        """
        enriched = []
        for entry in entries:
            try:
                enriched.append(self.enrich_entry(entry, org_sector=org_sector))
            except Exception as e:
                logger.warning(f"Failed to enrich entry {entry.get('bundle_id', '?')}: {e}")
                enriched.append(entry)  # Return original if enrichment fails

        logger.info(f"AI predictions applied to {len(enriched)} manifest entries")
        return enriched

    def get_top_risks(self, entries: List[Dict], top_n: int = 10) -> List[Dict]:
        """
        Get top N highest-risk threats after AI enrichment.
        Sorted by triage score descending.
        """
        enriched = self.enrich_manifest(entries)
        scored   = [(e, e.get("ai_predictions", {}).get("triage", {}).get("triage_score", 0)) for e in enriched]
        sorted_e = sorted(scored, key=lambda x: x[1], reverse=True)
        return [e for e, _ in sorted_e[:top_n]]

    def generate_executive_summary(self, entries: List[Dict]) -> Dict:
        """
        Generate an AI-powered executive threat summary.
        """
        enriched = self.enrich_manifest(entries)

        # Aggregate stats
        exploit_probs = [
            e.get("ai_predictions", {}).get("exploit_probability", {}).get("exploit_probability", 0)
            for e in enriched
        ]
        triage_scores = [
            e.get("ai_predictions", {}).get("triage", {}).get("triage_score", 0)
            for e in enriched
        ]
        sectors_affected = set()
        financial_range_max = 0

        for e in enriched:
            preds = e.get("ai_predictions", {})
            for s in preds.get("industry_impact", {}).get("affected_sectors", []):
                sectors_affected.add(s)
            fin_max = preds.get("financial_impact", {}).get("loss_max_usd", 0)
            financial_range_max = max(financial_range_max, fin_max)

        avg_exploit_prob = sum(exploit_probs) / len(exploit_probs) if exploit_probs else 0
        avg_triage       = sum(triage_scores) / len(triage_scores) if triage_scores else 0

        critical_threats = [e for e in enriched if e.get("ai_predictions", {}).get("exploit_probability", {}).get("exploit_tier") == "CRITICAL"]

        return {
            "summary_type":            "AI Executive Threat Brief",
            "threat_count":            len(enriched),
            "critical_threat_count":   len(critical_threats),
            "avg_exploit_probability": round(avg_exploit_prob * 100, 1),
            "avg_triage_score":        round(avg_triage, 1),
            "sectors_at_risk":         sorted(sectors_affected),
            "max_financial_exposure":  financial_range_max,
            "max_financial_formatted": f"${financial_range_max/1_000_000:.1f}M" if financial_range_max >= 1_000_000 else f"${financial_range_max:,}",
            "platform":                "CYBERDUDEBIVASH SENTINEL APEX",
            "model_version":           MODELS_VERSION,
            "generated_at":            datetime.now(timezone.utc).isoformat(),
        }


if __name__ == "__main__":
    print(f"CDB Predictive Intelligence Engine v{MODELS_VERSION}")
    print("Models: ExploitProbability, Attribution, IndustryImpact, FinancialImpact, Triage, Momentum")

    # Demo with synthetic entry
    engine = PredictiveIntelligenceEngine()
    demo_entry = {
        "title": "CRITICAL: LockBit ransomware exploiting CVE-2024-1234 in healthcare networks",
        "severity": "CRITICAL",
        "risk_score": 9.2,
        "cvss_score": 9.8,
        "epss_score": 0.85,
        "kev_present": True,
        "actor_tag": "lockbit",
        "mitre_tactics": ["TA0001", "TA0002", "TA0003", "TA0040"],
        "ioc_count": 15,
        "data_quality": "GOLD",
        "cve_ids": ["CVE-2024-1234"],
    }

    result = engine.enrich_entry(demo_entry, org_sector="healthcare")
    preds  = result.get("ai_predictions", {})

    print(f"\nDemo Entry: {demo_entry['title'][:60]}...")
    print(f"Exploit Probability: {preds.get('exploit_probability', {}).get('exploit_probability_pct', 0)}%")
    print(f"Triage Score: {preds.get('triage', {}).get('triage_score', 0)}/100")
    print(f"Primary Sector: {preds.get('industry_impact', {}).get('primary_sector', 'N/A')}")
    print(f"Financial Exposure: {preds.get('financial_impact', {}).get('loss_range_label', 'N/A')}")
    print(f"Attribution: {preds.get('attribution', {}).get('attribution_label', 'N/A')}")
