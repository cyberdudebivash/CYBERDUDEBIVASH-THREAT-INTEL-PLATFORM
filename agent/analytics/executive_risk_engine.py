#!/usr/bin/env python3
"""
executive_risk_engine.py — CYBERDUDEBIVASH® SENTINEL APEX v55.0
EXECUTIVE FINANCIAL RISK QUANTIFICATION ENGINE

Maps technical findings (CVE, BOLA, Cloud misconfig, etc.) to:
  - Regional regulatory fines (GDPR, EU AI Act, India DPDP Act, CCPA, HIPAA)
  - Annualized Loss Exposure (ALE) = SLE × ARO
  - Return on Security Investment (ROSI)
  - Sector-specific breach cost multipliers
  - Executive-ready JSON + PDF-ready summaries

Integration:
    from agent.analytics.executive_risk_engine import executive_risk_engine
    report = executive_risk_engine.quantify(findings, region="EU", sector="FINANCE")

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
Founder & CEO — Bivash Kumar Nayak
"""

import json
import logging
import math
from datetime import datetime, timezone
from typing import Dict, List, Optional, Any, Tuple
from pathlib import Path
from enum import Enum

logger = logging.getLogger("CDB-EXEC-RISK")

# ═══════════════════════════════════════════════════════════
# REGULATORY FRAMEWORK DEFINITIONS (2025-2026)
# ═══════════════════════════════════════════════════════════

class Regulation(str, Enum):
    GDPR = "GDPR"
    EU_AI_ACT = "EU_AI_ACT"
    DPDP = "INDIA_DPDP"
    CCPA = "CCPA"
    HIPAA = "HIPAA"
    PCI_DSS = "PCI_DSS"
    SOX = "SOX"
    NIS2 = "NIS2"


# Maximum regulatory fines (2025-2026 enforcement levels)
REGULATORY_FINES: Dict[str, Dict[str, Any]] = {
    Regulation.GDPR: {
        "max_fine_eur": 20_000_000,
        "max_fine_pct_revenue": 0.04,      # 4% of annual global turnover
        "notification_window_hrs": 72,
        "applies_to": ["EU", "EEA", "UK"],
        "data_categories": ["PII", "HEALTH", "BIOMETRIC", "FINANCIAL", "LOCATION"],
        "aggravating_factors": {
            "no_dpo_appointed": 1.3,
            "no_dpia_conducted": 1.4,
            "repeat_offender": 1.5,
            "intentional_violation": 2.0,
            "minors_data": 1.8,
            "cross_border": 1.3,
        },
        "currency": "EUR",
    },
    Regulation.EU_AI_ACT: {
        "max_fine_eur": 35_000_000,
        "max_fine_pct_revenue": 0.07,      # 7% for prohibited AI practices
        "tier_fines": {
            "prohibited_practice": 35_000_000,    # Article 5 violations
            "high_risk_non_compliance": 15_000_000,
            "incorrect_information": 7_500_000,
        },
        "applies_to": ["EU", "EEA"],
        "ai_risk_categories": ["HIGH_RISK", "LIMITED_RISK", "MINIMAL_RISK", "PROHIBITED"],
        "currency": "EUR",
    },
    Regulation.DPDP: {
        "max_fine_inr": 2_500_000_000,     # ₹250 Crore (≈$30M)
        "breach_fine_inr": 2_000_000_000,  # ₹200 Crore for breach of personal data
        "child_data_fine_inr": 2_500_000_000,
        "applies_to": ["IN"],
        "notification_window_hrs": 72,
        "data_categories": ["PII", "CHILD_DATA", "FINANCIAL", "HEALTH"],
        "currency": "INR",
        "inr_to_usd": 0.012,              # Approximate conversion
    },
    Regulation.CCPA: {
        "max_fine_per_violation_usd": 7_500,  # Intentional
        "unintentional_per_violation_usd": 2_500,
        "private_action_per_consumer_usd": 750,
        "applies_to": ["US_CA"],
        "currency": "USD",
    },
    Regulation.HIPAA: {
        "max_fine_per_violation_usd": 1_811_071,  # Tier 4 (willful neglect)
        "tier_fines": {
            "did_not_know": 68_928,
            "reasonable_cause": 68_928,
            "willful_neglect_corrected": 68_928,
            "willful_neglect_uncorrected": 1_811_071,
        },
        "annual_cap_usd": 1_811_071,
        "applies_to": ["US"],
        "currency": "USD",
    },
    Regulation.PCI_DSS: {
        "monthly_fine_range_usd": (5_000, 100_000),
        "per_record_fine_usd": 150,        # Per compromised card
        "applies_to": ["GLOBAL"],
        "currency": "USD",
    },
    Regulation.NIS2: {
        "essential_entity_max_eur": 10_000_000,
        "essential_pct_revenue": 0.02,     # 2% of worldwide turnover
        "important_entity_max_eur": 7_000_000,
        "important_pct_revenue": 0.014,
        "applies_to": ["EU", "EEA"],
        "currency": "EUR",
    },
}

# ═══════════════════════════════════════════════════════════
# FINDING TYPE → IMPACT MATRIX
# ═══════════════════════════════════════════════════════════

# Base Single Loss Expectancy (SLE) per finding type (USD)
FINDING_SLE_MATRIX: Dict[str, Dict[str, Any]] = {
    "CVE_CRITICAL": {
        "base_sle_usd": 1_200_000,
        "aro": 0.8,          # Annual Rate of Occurrence
        "data_exposure": True,
        "regulatory_relevant": True,
        "breach_probability": 0.65,
    },
    "CVE_HIGH": {
        "base_sle_usd": 500_000,
        "aro": 0.5,
        "data_exposure": True,
        "regulatory_relevant": True,
        "breach_probability": 0.35,
    },
    "CVE_MEDIUM": {
        "base_sle_usd": 150_000,
        "aro": 0.3,
        "data_exposure": False,
        "regulatory_relevant": False,
        "breach_probability": 0.15,
    },
    "CVE_LOW": {
        "base_sle_usd": 25_000,
        "aro": 0.1,
        "data_exposure": False,
        "regulatory_relevant": False,
        "breach_probability": 0.05,
    },
    "BOLA": {
        "base_sle_usd": 800_000,
        "aro": 0.7,
        "data_exposure": True,
        "regulatory_relevant": True,
        "breach_probability": 0.55,
    },
    "CLOUD_MISCONFIGURATION": {
        "base_sle_usd": 950_000,
        "aro": 0.6,
        "data_exposure": True,
        "regulatory_relevant": True,
        "breach_probability": 0.50,
    },
    "CLOUD_BUCKET_EXPOSURE": {
        "base_sle_usd": 1_500_000,
        "aro": 0.5,
        "data_exposure": True,
        "regulatory_relevant": True,
        "breach_probability": 0.70,
    },
    "SUBDOMAIN_TAKEOVER": {
        "base_sle_usd": 350_000,
        "aro": 0.4,
        "data_exposure": False,
        "regulatory_relevant": False,
        "breach_probability": 0.25,
    },
    "SECRET_LEAK": {
        "base_sle_usd": 750_000,
        "aro": 0.6,
        "data_exposure": True,
        "regulatory_relevant": True,
        "breach_probability": 0.60,
    },
    "OPEN_PORT_CRITICAL": {
        "base_sle_usd": 200_000,
        "aro": 0.5,
        "data_exposure": False,
        "regulatory_relevant": False,
        "breach_probability": 0.20,
    },
    "SUPPLY_CHAIN": {
        "base_sle_usd": 2_500_000,
        "aro": 0.3,
        "data_exposure": True,
        "regulatory_relevant": True,
        "breach_probability": 0.45,
    },
    "RANSOMWARE_EXPOSURE": {
        "base_sle_usd": 4_200_000,       # IBM 2025 avg ransomware cost
        "aro": 0.25,
        "data_exposure": True,
        "regulatory_relevant": True,
        "breach_probability": 0.40,
    },
    "AI_MODEL_POISONING": {
        "base_sle_usd": 1_800_000,
        "aro": 0.2,
        "data_exposure": False,
        "regulatory_relevant": True,        # EU AI Act relevant
        "breach_probability": 0.30,
    },
    "ZERO_DAY": {
        "base_sle_usd": 3_000_000,
        "aro": 0.15,
        "data_exposure": True,
        "regulatory_relevant": True,
        "breach_probability": 0.75,
    },
}

# ═══════════════════════════════════════════════════════════
# SECTOR MULTIPLIERS (Industry vertical risk amplifiers)
# ═══════════════════════════════════════════════════════════

SECTOR_MULTIPLIERS: Dict[str, float] = {
    "FINANCE": 2.2,
    "HEALTHCARE": 2.5,          # Highest breach cost per IBM 2025
    "GOVERNMENT": 1.8,
    "DEFENSE": 2.0,
    "ENERGY": 1.9,
    "TECHNOLOGY": 1.5,
    "RETAIL": 1.3,
    "EDUCATION": 1.2,
    "MANUFACTURING": 1.4,
    "TELECOM": 1.6,
    "PHARMA": 2.3,
    "LEGAL": 1.7,
    "DEFAULT": 1.0,
}

# Average records exposed per finding type
AVG_RECORDS_EXPOSED: Dict[str, int] = {
    "BOLA": 50_000,
    "CLOUD_BUCKET_EXPOSURE": 500_000,
    "SECRET_LEAK": 100_000,
    "CVE_CRITICAL": 200_000,
    "RANSOMWARE_EXPOSURE": 150_000,
    "SUPPLY_CHAIN": 1_000_000,
    "DEFAULT": 10_000,
}


# ═══════════════════════════════════════════════════════════
# EXECUTIVE RISK ENGINE
# ═══════════════════════════════════════════════════════════

class ExecutiveRiskEngine:
    """
    Maps technical security findings to financial/regulatory impact.
    
    Produces executive-ready risk quantification with:
      - Per-finding ALE (Annualized Loss Exposure)
      - Aggregate portfolio risk
      - Regulatory fine exposure by jurisdiction
      - ROSI (Return on Security Investment)
      - Cost-of-inaction projections
    """

    def __init__(self):
        self._output_dir = Path("data/executive_risk")
        self._output_dir.mkdir(parents=True, exist_ok=True)
        self.authority = "CYBERDUDEBIVASH® SENTINEL APEX"

    def quantify(
        self,
        findings: List[Dict],
        region: str = "GLOBAL",
        sector: str = "DEFAULT",
        annual_revenue_usd: float = 10_000_000,
        platform_cost_usd: float = 50_000,
        records_at_risk: Optional[int] = None,
        aggravating_factors: Optional[List[str]] = None,
    ) -> Dict[str, Any]:
        """
        Core quantification engine.

        Args:
            findings: List of technical findings from BugHunter/ReasoningOrchestrator
            region: Regulatory region (EU, IN, US, US_CA, GLOBAL)
            sector: Industry vertical for multiplier
            annual_revenue_usd: Client annual revenue for pct-based fine calculation
            platform_cost_usd: Annual CDB subscription cost for ROSI
            records_at_risk: Estimated data records in scope
            aggravating_factors: GDPR/NIS2 aggravating factors

        Returns:
            Comprehensive executive risk report as Dict
        """
        if not findings:
            return self._empty_report(region, sector)

        sector_mult = SECTOR_MULTIPLIERS.get(sector.upper(), 1.0)
        agg_factors = aggravating_factors or []

        # ── Per-finding quantification ──
        finding_results = []
        total_ale = 0.0
        total_sle = 0.0
        regulatory_exposure = {}

        for finding in findings:
            result = self._quantify_single(
                finding, sector_mult, region, annual_revenue_usd,
                records_at_risk, agg_factors
            )
            finding_results.append(result)
            total_ale += result["ale_usd"]
            total_sle += result["sle_usd"]

            # Aggregate regulatory exposure
            for reg, amount in result.get("regulatory_fines", {}).items():
                regulatory_exposure[reg] = regulatory_exposure.get(reg, 0) + amount

        # ── ROSI Calculation ──
        mitigated_ale = total_ale * 0.95  # CDB platform mitigation rate
        rosi = ((mitigated_ale - platform_cost_usd) / platform_cost_usd) * 100 if platform_cost_usd > 0 else 0

        # ── Cost of Inaction (3-year projection) ──
        cost_of_inaction = self._project_cost_of_inaction(total_ale, findings)

        # ── Severity Distribution ──
        severity_dist = self._compute_severity_distribution(findings)

        # ── Build Report ──
        report = {
            "report_id": f"CDB-EXEC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "authority": self.authority,
            "parameters": {
                "region": region,
                "sector": sector,
                "sector_multiplier": sector_mult,
                "annual_revenue_usd": annual_revenue_usd,
                "platform_cost_usd": platform_cost_usd,
                "finding_count": len(findings),
            },
            "executive_summary": {
                "total_risk_exposure_usd": round(total_sle, 2),
                "annualized_loss_exposure_usd": round(total_ale, 2),
                "max_regulatory_fine_usd": round(sum(regulatory_exposure.values()), 2),
                "mitigated_value_usd": round(mitigated_ale, 2),
                "rosi_percentage": round(rosi, 1),
                "rosi_ratio": round(mitigated_ale / platform_cost_usd, 1) if platform_cost_usd > 0 else 0,
                "cost_of_inaction_3yr_usd": round(cost_of_inaction, 2),
                "risk_rating": self._risk_rating(total_ale),
            },
            "regulatory_exposure": {
                reg: {
                    "projected_fine_usd": round(amount, 2),
                    "framework": reg,
                    "max_statutory_fine": self._get_max_statutory_fine(reg, annual_revenue_usd),
                }
                for reg, amount in regulatory_exposure.items()
            },
            "severity_distribution": severity_dist,
            "finding_details": finding_results,
            "recommendations": self._generate_recommendations(
                total_ale, regulatory_exposure, severity_dist, sector
            ),
        }

        # Persist report
        self._persist_report(report)

        return report

    def _quantify_single(
        self,
        finding: Dict,
        sector_mult: float,
        region: str,
        annual_revenue: float,
        records_at_risk: Optional[int],
        agg_factors: List[str],
    ) -> Dict:
        """Quantify a single finding."""
        f_type = self._normalize_finding_type(finding)
        severity = finding.get("severity", "MEDIUM").upper()

        # Lookup base SLE
        sle_config = FINDING_SLE_MATRIX.get(f_type)
        if not sle_config:
            # Fallback: derive from severity
            severity_sle = {
                "CRITICAL": 1_200_000, "HIGH": 500_000,
                "MEDIUM": 150_000, "LOW": 25_000, "INFO": 5_000,
            }
            sle_config = {
                "base_sle_usd": severity_sle.get(severity, 150_000),
                "aro": 0.3,
                "data_exposure": severity in ("CRITICAL", "HIGH"),
                "regulatory_relevant": severity in ("CRITICAL", "HIGH"),
                "breach_probability": 0.2,
            }

        base_sle = sle_config["base_sle_usd"]
        aro = sle_config["aro"]

        # Apply sector multiplier
        adjusted_sle = base_sle * sector_mult

        # CVSS adjustment if available
        cvss = finding.get("cvss_score") or finding.get("cvss", 0)
        if cvss and float(cvss) > 0:
            cvss_mult = float(cvss) / 7.0  # Normalize around CVSS 7.0
            adjusted_sle *= max(0.5, min(cvss_mult, 2.5))

        # EPSS adjustment if available
        epss = finding.get("epss_score") or finding.get("epss", 0)
        if epss and float(epss) > 0:
            aro = max(aro, float(epss))  # Use higher of default ARO or EPSS

        # ALE = SLE × ARO
        ale = adjusted_sle * aro

        # ── Regulatory fine calculation ──
        reg_fines = {}
        if sle_config.get("regulatory_relevant"):
            reg_fines = self._calculate_regulatory_fines(
                f_type, region, annual_revenue, records_at_risk,
                agg_factors, sle_config.get("breach_probability", 0.3)
            )

        return {
            "finding_type": f_type,
            "original_type": finding.get("type", "UNKNOWN"),
            "severity": severity,
            "title": finding.get("title", finding.get("description", "")[:100]),
            "sle_usd": round(adjusted_sle, 2),
            "aro": round(aro, 3),
            "ale_usd": round(ale, 2),
            "breach_probability": sle_config.get("breach_probability", 0.2),
            "data_exposure": sle_config.get("data_exposure", False),
            "regulatory_fines": {k: round(v, 2) for k, v in reg_fines.items()},
            "cvss_applied": bool(cvss and float(cvss) > 0),
            "epss_applied": bool(epss and float(epss) > 0),
        }

    def _calculate_regulatory_fines(
        self,
        finding_type: str,
        region: str,
        annual_revenue: float,
        records_at_risk: Optional[int],
        agg_factors: List[str],
        breach_prob: float,
    ) -> Dict[str, float]:
        """Calculate potential regulatory fines by jurisdiction."""
        fines = {}
        estimated_records = records_at_risk or AVG_RECORDS_EXPOSED.get(finding_type, 10_000)

        # Determine applicable regulations
        applicable = self._get_applicable_regulations(region)

        for reg in applicable:
            reg_config = REGULATORY_FINES.get(reg, {})
            fine = 0.0

            if reg == Regulation.GDPR:
                # GDPR: max(€20M, 4% of annual turnover)
                pct_fine = annual_revenue * reg_config.get("max_fine_pct_revenue", 0.04)
                base_fine = min(pct_fine, reg_config.get("max_fine_eur", 20_000_000))
                # Scale by breach probability and severity
                fine = base_fine * breach_prob
                # Apply aggravating factors
                for factor in agg_factors:
                    mult = reg_config.get("aggravating_factors", {}).get(factor, 1.0)
                    fine *= mult
                fine *= 1.2  # EUR to USD approximation

            elif reg == Regulation.EU_AI_ACT:
                # EU AI Act: up to €35M or 7% for prohibited practices
                if finding_type in ("AI_MODEL_POISONING",):
                    fine = reg_config.get("tier_fines", {}).get("high_risk_non_compliance", 15_000_000)
                else:
                    fine = reg_config.get("tier_fines", {}).get("incorrect_information", 7_500_000)
                fine *= breach_prob * 1.2  # EUR to USD

            elif reg == Regulation.DPDP:
                # India DPDP: up to ₹250 Crore
                inr_to_usd = reg_config.get("inr_to_usd", 0.012)
                if finding_type in ("BOLA", "CLOUD_BUCKET_EXPOSURE", "SECRET_LEAK"):
                    fine_inr = reg_config.get("breach_fine_inr", 2_000_000_000)
                else:
                    fine_inr = reg_config.get("max_fine_inr", 2_500_000_000) * 0.3
                fine = fine_inr * inr_to_usd * breach_prob

            elif reg == Regulation.CCPA:
                # CCPA: $7,500 per intentional violation
                per_violation = reg_config.get("max_fine_per_violation_usd", 7_500)
                fine = min(per_violation * estimated_records * 0.01, 50_000_000)
                fine *= breach_prob

            elif reg == Regulation.HIPAA:
                fine = reg_config.get("annual_cap_usd", 1_811_071) * breach_prob

            elif reg == Regulation.PCI_DSS:
                per_record = reg_config.get("per_record_fine_usd", 150)
                monthly_max = reg_config.get("monthly_fine_range_usd", (5000, 100000))[1]
                fine = min(per_record * estimated_records * 0.01 + monthly_max * 6, 20_000_000)
                fine *= breach_prob

            elif reg == Regulation.NIS2:
                pct_fine = annual_revenue * reg_config.get("essential_pct_revenue", 0.02)
                fine = min(pct_fine, reg_config.get("essential_entity_max_eur", 10_000_000))
                fine *= breach_prob * 1.2

            if fine > 0:
                fines[reg] = fine

        return fines

    def _get_applicable_regulations(self, region: str) -> List[str]:
        """Determine which regulations apply to a region."""
        region = region.upper()
        applicable = []

        region_map = {
            "EU": [Regulation.GDPR, Regulation.EU_AI_ACT, Regulation.NIS2],
            "EEA": [Regulation.GDPR, Regulation.EU_AI_ACT, Regulation.NIS2],
            "UK": [Regulation.GDPR],
            "IN": [Regulation.DPDP],
            "INDIA": [Regulation.DPDP],
            "US": [Regulation.HIPAA],
            "US_CA": [Regulation.CCPA, Regulation.HIPAA],
            "GLOBAL": [Regulation.GDPR, Regulation.DPDP, Regulation.CCPA,
                       Regulation.HIPAA, Regulation.NIS2],
        }

        return region_map.get(region, [Regulation.GDPR])

    def _normalize_finding_type(self, finding: Dict) -> str:
        """Normalize finding type to match SLE matrix keys."""
        raw_type = finding.get("type", "").upper().replace(" ", "_").replace("-", "_")
        severity = finding.get("severity", "MEDIUM").upper()

        # Direct match
        if raw_type in FINDING_SLE_MATRIX:
            return raw_type

        # CVE with severity
        if "CVE" in raw_type:
            return f"CVE_{severity}"

        # Fuzzy matching
        type_aliases = {
            "BOLA": ["BOLA", "IDOR", "BROKEN_OBJECT_LEVEL", "INSECURE_DIRECT_OBJECT"],
            "CLOUD_MISCONFIGURATION": ["CLOUD", "CLOUD_MISCONFIG", "S3", "GCS", "AZURE_BLOB"],
            "CLOUD_BUCKET_EXPOSURE": ["BUCKET", "S3_PUBLIC", "CLOUD_LEAK", "STORAGE_EXPOSURE"],
            "SECRET_LEAK": ["SECRET", "API_KEY_LEAK", "CREDENTIAL", "HARDCODED"],
            "SUBDOMAIN_TAKEOVER": ["SUBDOMAIN", "TAKEOVER", "DANGLING_DNS"],
            "SUPPLY_CHAIN": ["SUPPLY_CHAIN", "DEPENDENCY", "SCA"],
            "RANSOMWARE_EXPOSURE": ["RANSOMWARE", "RANSOM"],
            "AI_MODEL_POISONING": ["AI_POISON", "MODEL_POISON", "ADVERSARIAL_ML"],
            "ZERO_DAY": ["ZERO_DAY", "0DAY", "0_DAY"],
            "OPEN_PORT_CRITICAL": ["OPEN_PORT", "PORT_SCAN", "EXPOSED_SERVICE"],
        }

        for canonical, aliases in type_aliases.items():
            for alias in aliases:
                if alias in raw_type:
                    return canonical

        return f"CVE_{severity}"

    def _project_cost_of_inaction(self, current_ale: float, findings: List[Dict]) -> float:
        """3-year projected cost if findings remain unremediated."""
        # Year 1: current ALE
        # Year 2: +15% compounding (attack surface expansion, new exploits)
        # Year 3: +25% compounding (regulatory enforcement escalation)
        year1 = current_ale
        year2 = current_ale * 1.15
        year3 = current_ale * 1.15 * 1.25

        # Add regulatory enforcement escalation
        critical_count = sum(1 for f in findings if f.get("severity", "").upper() == "CRITICAL")
        enforcement_premium = critical_count * 500_000  # Per-critical enforcement risk

        return year1 + year2 + year3 + enforcement_premium

    def _risk_rating(self, total_ale: float) -> str:
        """Assign risk rating based on total ALE."""
        if total_ale >= 5_000_000:
            return "CRITICAL"
        elif total_ale >= 2_000_000:
            return "HIGH"
        elif total_ale >= 500_000:
            return "MEDIUM"
        elif total_ale >= 100_000:
            return "LOW"
        return "INFORMATIONAL"

    def _compute_severity_distribution(self, findings: List[Dict]) -> Dict[str, int]:
        """Count findings by severity."""
        dist = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        for f in findings:
            sev = f.get("severity", "MEDIUM").upper()
            if sev in dist:
                dist[sev] += 1
            else:
                dist["MEDIUM"] += 1
        return dist

    def _get_max_statutory_fine(self, regulation: str, annual_revenue: float) -> str:
        """Return human-readable max statutory fine."""
        config = REGULATORY_FINES.get(regulation, {})
        if regulation == Regulation.GDPR:
            pct = config.get("max_fine_pct_revenue", 0.04)
            return f"max(€20M, {pct*100:.0f}% of annual turnover) ≈ ${max(20_000_000*1.2, annual_revenue*pct*1.2):,.0f}"
        elif regulation == Regulation.EU_AI_ACT:
            return f"up to €35M or 7% of turnover ≈ ${max(35_000_000*1.2, annual_revenue*0.07*1.2):,.0f}"
        elif regulation == Regulation.DPDP:
            return "up to ₹250 Crore (≈$30M)"
        elif regulation == Regulation.CCPA:
            return "$7,500 per intentional violation"
        elif regulation == Regulation.HIPAA:
            return "up to $1.8M per violation category per year"
        elif regulation == Regulation.NIS2:
            return f"max(€10M, 2% of turnover) ≈ ${max(10_000_000*1.2, annual_revenue*0.02*1.2):,.0f}"
        return "Varies by jurisdiction"

    def _generate_recommendations(
        self,
        total_ale: float,
        reg_exposure: Dict,
        severity_dist: Dict,
        sector: str,
    ) -> List[Dict]:
        """Generate prioritized remediation recommendations."""
        recs = []

        if severity_dist.get("CRITICAL", 0) > 0:
            recs.append({
                "priority": "P0",
                "action": "Remediate all CRITICAL findings within 24 hours",
                "impact": f"Reduces ALE by up to ${total_ale * 0.6:,.0f}",
                "compliance": "Required for GDPR 72h notification, NIS2 essential entity obligations",
            })

        if severity_dist.get("HIGH", 0) > 0:
            recs.append({
                "priority": "P1",
                "action": "Remediate HIGH findings within 7 days",
                "impact": f"Further ALE reduction of ${total_ale * 0.25:,.0f}",
                "compliance": "Aligns with PCI-DSS remediation SLAs",
            })

        if reg_exposure:
            top_reg = max(reg_exposure, key=reg_exposure.get)
            recs.append({
                "priority": "P0",
                "action": f"Address {top_reg} compliance gaps immediately",
                "impact": f"Max fine exposure: ${reg_exposure[top_reg]:,.0f}",
                "compliance": f"Direct {top_reg} enforcement risk",
            })

        recs.append({
            "priority": "P2",
            "action": "Deploy continuous CDB SENTINEL APEX monitoring",
            "impact": f"95% risk mitigation = ${total_ale * 0.95:,.0f} protected value",
            "compliance": "Demonstrates due diligence across all frameworks",
            "upgrade_url": "https://intel.cyberdudebivash.com/pricing",
        })

        return recs

    def _persist_report(self, report: Dict):
        """Save report to disk."""
        try:
            filename = f"{report['report_id']}.json"
            filepath = self._output_dir / filename
            with open(filepath, "w") as f:
                json.dump(report, f, indent=2, default=str)
            logger.info(f"Executive risk report saved: {filepath}")
        except Exception as e:
            logger.error(f"Failed to persist report: {e}")

    def _empty_report(self, region: str, sector: str) -> Dict:
        """Return empty report when no findings provided."""
        return {
            "report_id": f"CDB-EXEC-{datetime.now(timezone.utc).strftime('%Y%m%d%H%M%S')}",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "authority": self.authority,
            "parameters": {"region": region, "sector": sector, "finding_count": 0},
            "executive_summary": {
                "total_risk_exposure_usd": 0,
                "annualized_loss_exposure_usd": 0,
                "max_regulatory_fine_usd": 0,
                "mitigated_value_usd": 0,
                "rosi_percentage": 0,
                "rosi_ratio": 0,
                "cost_of_inaction_3yr_usd": 0,
                "risk_rating": "INFORMATIONAL",
            },
            "regulatory_exposure": {},
            "finding_details": [],
            "recommendations": [],
        }

    def format_executive_pdf_data(self, report: Dict) -> Dict:
        """
        Prepare report data for PDF generation by agent/pdf_generator.py.
        Returns structured data compatible with CDBWhitepaper.create_report().
        """
        summary = report.get("executive_summary", {})
        return {
            "headline": f"Executive Risk Assessment — {report.get('report_id', 'N/A')}",
            "risk_score": self._ale_to_score(summary.get("annualized_loss_exposure_usd", 0)),
            "iocs": [],
            "mitre_data": [],
            "sections": {
                "risk_exposure": f"${summary.get('total_risk_exposure_usd', 0):,.2f}",
                "annualized_loss": f"${summary.get('annualized_loss_exposure_usd', 0):,.2f}",
                "regulatory_fines": f"${summary.get('max_regulatory_fine_usd', 0):,.2f}",
                "rosi": f"{summary.get('rosi_percentage', 0):.1f}%",
                "3yr_inaction_cost": f"${summary.get('cost_of_inaction_3yr_usd', 0):,.2f}",
            },
            "regulatory_detail": report.get("regulatory_exposure", {}),
            "recommendations": report.get("recommendations", []),
        }

    @staticmethod
    def _ale_to_score(ale: float) -> float:
        """Convert ALE to a 0-10 risk score."""
        if ale <= 0:
            return 0
        score = min(10.0, math.log10(max(ale, 1)) / math.log10(50_000_000) * 10)
        return round(score, 1)


# ═══════════════════════════════════════════════════════════
# GLOBAL SINGLETON
# ═══════════════════════════════════════════════════════════

executive_risk_engine = ExecutiveRiskEngine()
