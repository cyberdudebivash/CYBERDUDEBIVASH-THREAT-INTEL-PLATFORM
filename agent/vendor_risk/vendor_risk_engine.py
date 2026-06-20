"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — VENDOR RISK INTELLIGENCE ENGINE v1.0   ║
║  Third-Party Risk Management · Supply Chain Security · Continuous Scoring ║
╚══════════════════════════════════════════════════════════════════════════════╝

Production-grade vendor risk intelligence.
Revenue: $499/mo (ENTERPRISE add-on) · $1999/mo (MSSP package)

Capabilities:
  1. Vendor security posture scoring (FAIR-aligned, 0–100)
  2. CVE exposure analysis for vendor products
  3. Data access risk classification (PII, PCI, PHI, IP)
  4. Third-party breach history correlation
  5. Contractual risk flagging (SLA, data processing, security clauses)
  6. Continuous monitoring signal scoring
  7. Vendor questionnaire gap analysis
  8. Regulatory compliance alignment (SOC 2, ISO 27001, GDPR)
  9. Geopolitical / sanctions exposure
  10. Business continuity / concentration risk
"""
from __future__ import annotations

import hashlib
import logging
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-VENDOR-RISK")


class RiskTier(str, Enum):
    CRITICAL = "CRITICAL"   # Score 0–39: Immediate action required
    HIGH     = "HIGH"       # Score 40–59: Enhanced monitoring
    MEDIUM   = "MEDIUM"     # Score 60–74: Standard monitoring
    LOW      = "LOW"        # Score 75–89: Annual review
    MINIMAL  = "MINIMAL"    # Score 90–100: Passive monitoring


class DataClassification(str, Enum):
    PII    = "PII"
    PCI    = "PCI"
    PHI    = "PHI"
    IP     = "INTELLECTUAL_PROPERTY"
    CONF   = "CONFIDENTIAL"
    PUBLIC = "PUBLIC"


class AccessLevel(str, Enum):
    NONE     = "NONE"
    READ     = "READ_ONLY"
    WRITE    = "READ_WRITE"
    ADMIN    = "ADMIN"
    ROOT     = "ROOT_ACCESS"


@dataclass
class VendorRiskScore:
    overall:           float  # 0–100 (higher = safer)
    security_posture:  float
    data_risk:         float
    compliance:        float
    business_continuity: float
    threat_intel:      float
    geopolitical:      float
    tier:              RiskTier
    confidence:        float  # 0.0–1.0
    scoring_method:    str = "FAIR-ALIGNED-v1"


@dataclass
class VendorProfile:
    vendor_id:         str
    name:              str
    domain:            str
    category:          str
    data_access:       List[DataClassification]
    access_level:      AccessLevel
    risk_score:        VendorRiskScore
    cve_exposure:      Dict[str, Any]
    breach_history:    List[Dict]
    compliance_certs:  List[str]
    contract_flags:    List[str]
    monitoring_signals: List[Dict]
    assessed_at:       str
    next_review:       str
    recommendations:   List[str]
    questionnaire_gaps: List[str]


# ── Known high-risk vendor categories (data from public breach intelligence) ─
HIGH_RISK_VENDOR_CATEGORIES = {
    "payroll_processor":    {"weight": 3.5, "rationale": "PII, banking data, broad employee access"},
    "cloud_storage":        {"weight": 3.0, "rationale": "Data concentration risk"},
    "identity_provider":    {"weight": 3.5, "rationale": "Authentication critical path"},
    "email_provider":       {"weight": 3.0, "rationale": "Communications access"},
    "erp_system":           {"weight": 3.0, "rationale": "Full business operations data"},
    "crm":                  {"weight": 2.5, "rationale": "Customer PII, sales data"},
    "edtech_lms":           {"weight": 2.0, "rationale": "Student PII (FERPA)"},
    "healthcare_ehr":       {"weight": 4.0, "rationale": "PHI — HIPAA critical"},
    "payment_processor":    {"weight": 4.0, "rationale": "PCI-DSS scope"},
    "mssp_soc":             {"weight": 3.0, "rationale": "Security telemetry access"},
    "it_management":        {"weight": 3.0, "rationale": "Network/endpoint access"},
    "law_firm":             {"weight": 3.5, "rationale": "Legal privilege, IP data"},
    "accounting_firm":      {"weight": 3.5, "rationale": "Financial and tax data"},
    "recruiting":           {"weight": 2.5, "rationale": "Employee PII"},
    "logistics":            {"weight": 2.0, "rationale": "Operational data"},
    "marketing":            {"weight": 1.5, "rationale": "Marketing data access"},
    "software_dev":         {"weight": 2.5, "rationale": "Source code access"},
    "generic":              {"weight": 1.0, "rationale": "Baseline risk"},
}

# ── Known major breach history indicators ─────────────────────────────────────
KNOWN_BREACH_INDICATORS: Dict[str, List[Dict]] = {
    "okta.com": [{"year": 2022, "severity": "HIGH", "type": "3rd party support breach", "records": 5000}],
    "lastpass.com": [{"year": 2022, "severity": "CRITICAL", "type": "Password vault theft", "records": 33_000_000}],
    "solarwinds.com": [{"year": 2020, "severity": "CRITICAL", "type": "Supply chain / SUNBURST", "records": None}],
    "kaseya.com": [{"year": 2021, "severity": "CRITICAL", "type": "MSP supply chain / REvil", "records": 60}],
    "log4j": [{"year": 2021, "severity": "CRITICAL", "type": "CVE-2021-44228 universal component", "records": None}],
}

# ── Vendor CVE risk lookup (known vendor product CVE exposure patterns) ───────
VENDOR_CVE_RISK_PATTERNS: Dict[str, Dict] = {
    "cisco": {"high_cve_probability": True, "cve_categories": ["RCE", "Auth bypass", "DoS"], "patch_velocity": "fast"},
    "fortinet": {"high_cve_probability": True, "cve_categories": ["Auth bypass", "RCE"], "patch_velocity": "moderate"},
    "palo alto": {"high_cve_probability": True, "cve_categories": ["Command injection", "XSS"], "patch_velocity": "fast"},
    "microsoft": {"high_cve_probability": True, "cve_categories": ["Privilege escalation", "RCE", "SPooling"], "patch_velocity": "fast"},
    "vmware": {"high_cve_probability": True, "cve_categories": ["VM escape", "Auth bypass", "SSRF"], "patch_velocity": "moderate"},
    "atlassian": {"high_cve_probability": True, "cve_categories": ["OGNL injection", "Auth bypass"], "patch_velocity": "moderate"},
    "apache": {"high_cve_probability": True, "cve_categories": ["RCE", "Path traversal"], "patch_velocity": "fast"},
}

# ── Compliance certificate scoring ───────────────────────────────────────────
COMPLIANCE_SCORES: Dict[str, float] = {
    "SOC 2 Type II":    25.0,
    "ISO 27001":        20.0,
    "PCI-DSS":          15.0,
    "HIPAA":            15.0,
    "FedRAMP":          20.0,
    "GDPR DPA":         10.0,
    "CSA STAR":         10.0,
    "NIST CSF":         10.0,
    "SOC 2 Type I":     10.0,
    "ISO 27017":        8.0,
    "ISO 27018":        8.0,
    "CCPA":             5.0,
    "CIS Benchmark":    5.0,
}

# ── Security questionnaire gap analysis ──────────────────────────────────────
QUESTIONNAIRE_DOMAINS = [
    "Encryption at rest and in transit",
    "Penetration testing cadence and scope",
    "Vulnerability management SLA",
    "Incident response plan and notification SLA",
    "Subprocessor management and notification",
    "Employee background checks",
    "Access control and privileged access management",
    "Multi-factor authentication enforcement",
    "Data retention and deletion procedures",
    "Business continuity and disaster recovery testing",
    "Security awareness training frequency",
    "SIEM/logging infrastructure",
    "Supply chain security for dependencies",
    "Patch management SLA",
    "Security team headcount and certifications",
]


class VendorRiskEngine:
    """
    Enterprise vendor risk intelligence engine.
    FAIR-aligned scoring, continuous monitoring, regulatory compliance tracking.
    """

    def __init__(self):
        self.assessments_total = 0
        self.vendor_registry: Dict[str, VendorProfile] = {}

    def assess_vendor(
        self,
        vendor_name:        str,
        vendor_domain:      str,
        vendor_category:    str = "generic",
        data_access:        Optional[List[str]] = None,
        access_level:       str = "READ",
        compliance_certs:   Optional[List[str]] = None,
        threat_advisories:  Optional[List[Dict]] = None,
        contract_data:      Optional[Dict] = None,
    ) -> VendorProfile:
        """
        Perform full vendor risk assessment.
        Returns a VendorProfile with scored risk across 6 dimensions.
        """
        t0 = time.time()
        vendor_id = f"VND-{hashlib.sha256(vendor_domain.encode()).hexdigest()[:12]}"

        data_classes = [DataClassification(d) for d in (data_access or ["CONFIDENTIAL"])
                        if d in DataClassification.__members__]
        access_lvl   = AccessLevel(access_level) if access_level in AccessLevel.__members__ else AccessLevel.READ
        certs        = compliance_certs or []

        # Dimension 1: Security Posture (0–100)
        sec_posture = self._score_security_posture(vendor_domain, vendor_category, certs)

        # Dimension 2: Data Risk (0–100, higher = LOWER risk)
        data_risk_score = self._score_data_risk(data_classes, access_lvl, vendor_category)

        # Dimension 3: Compliance (0–100)
        compliance_score = self._score_compliance(certs, vendor_category)

        # Dimension 4: Business Continuity (0–100)
        bc_score = self._score_business_continuity(vendor_category)

        # Dimension 5: Threat Intel Exposure (0–100)
        threat_score = self._score_threat_intel(vendor_domain, threat_advisories or [])

        # Dimension 6: Geopolitical Risk (0–100)
        geo_score = self._score_geopolitical(vendor_domain)

        # Weighted overall score
        weights = {
            "security":    0.30,
            "data":        0.25,
            "compliance":  0.20,
            "bc":          0.10,
            "threat":      0.10,
            "geo":         0.05,
        }
        overall = (
            sec_posture    * weights["security"]  +
            data_risk_score * weights["data"]     +
            compliance_score * weights["compliance"] +
            bc_score       * weights["bc"]        +
            threat_score   * weights["threat"]    +
            geo_score      * weights["geo"]
        )
        overall = round(min(100.0, max(0.0, overall)), 1)

        tier = (
            RiskTier.MINIMAL  if overall >= 90 else
            RiskTier.LOW      if overall >= 75 else
            RiskTier.MEDIUM   if overall >= 60 else
            RiskTier.HIGH     if overall >= 40 else
            RiskTier.CRITICAL
        )

        risk_score = VendorRiskScore(
            overall              = overall,
            security_posture     = round(sec_posture, 1),
            data_risk            = round(data_risk_score, 1),
            compliance           = round(compliance_score, 1),
            business_continuity  = round(bc_score, 1),
            threat_intel         = round(threat_score, 1),
            geopolitical         = round(geo_score, 1),
            tier                 = tier,
            confidence           = 0.75,
        )

        cve_exposure    = self._analyze_cve_exposure(vendor_domain, vendor_name)
        breach_history  = self._get_breach_history(vendor_domain)
        contract_flags  = self._analyze_contract(contract_data or {}, vendor_category)
        monitoring_sigs = self._generate_monitoring_signals(vendor_domain, vendor_category)
        recommendations = self._generate_recommendations(risk_score, vendor_category, data_classes, certs)
        q_gaps          = self._questionnaire_gap_analysis(contract_data or {}, certs)
        next_review     = self._calculate_review_cadence(tier)

        profile = VendorProfile(
            vendor_id          = vendor_id,
            name               = vendor_name,
            domain             = vendor_domain,
            category           = vendor_category,
            data_access        = data_classes,
            access_level       = access_lvl,
            risk_score         = risk_score,
            cve_exposure       = cve_exposure,
            breach_history     = breach_history,
            compliance_certs   = certs,
            contract_flags     = contract_flags,
            monitoring_signals = monitoring_sigs,
            assessed_at        = datetime.now(timezone.utc).isoformat(),
            next_review        = next_review,
            recommendations    = recommendations,
            questionnaire_gaps = q_gaps,
        )

        self.vendor_registry[vendor_id] = profile
        self.assessments_total += 1
        logger.info(f"[VENDOR-RISK] Assessed {vendor_name}: {tier.value} (score={overall})")
        return profile

    def bulk_assess(self, vendors: List[Dict]) -> Dict[str, Any]:
        """Assess multiple vendors and return risk portfolio view."""
        profiles = []
        for v in vendors:
            try:
                p = self.assess_vendor(**v)
                profiles.append(p)
            except Exception as e:
                logger.warning(f"[VENDOR-RISK] Failed to assess {v.get('vendor_name', '?')}: {e}")

        critical = [p for p in profiles if p.risk_score.tier == RiskTier.CRITICAL]
        high     = [p for p in profiles if p.risk_score.tier == RiskTier.HIGH]

        return {
            "portfolio_summary": {
                "total_vendors":    len(profiles),
                "critical_risk":    len(critical),
                "high_risk":        len(high),
                "medium_risk":      len([p for p in profiles if p.risk_score.tier == RiskTier.MEDIUM]),
                "low_risk":         len([p for p in profiles if p.risk_score.tier in (RiskTier.LOW, RiskTier.MINIMAL)]),
                "avg_risk_score":   round(sum(p.risk_score.overall for p in profiles) / max(1, len(profiles)), 1),
                "portfolio_risk":   "CRITICAL" if critical else "HIGH" if high else "MEDIUM",
            },
            "critical_vendors":    [self._serialize_profile(p) for p in critical],
            "high_risk_vendors":   [self._serialize_profile(p) for p in high],
            "all_vendors":         [self._serialize_profile(p) for p in profiles],
            "action_items":        self._generate_portfolio_actions(critical, high),
            "assessed_at":         datetime.now(timezone.utc).isoformat(),
        }

    def correlate_with_threat_feed(self, vendor_domain: str, advisories: List[Dict]) -> Dict:
        """Find threat intelligence relevant to a specific vendor."""
        vendor_lower = vendor_domain.lower().split(".")[0]
        hits = []
        for adv in advisories:
            title = (adv.get("title") or "").lower()
            summary = (adv.get("summary") or "").lower()
            feed_src = (adv.get("feed_source") or "").lower()
            if vendor_lower in title or vendor_lower in summary or vendor_lower in feed_src:
                hits.append({
                    "stix_id":      adv.get("stix_id"),
                    "title":        adv.get("title"),
                    "severity":     adv.get("severity"),
                    "risk_score":   adv.get("risk_score"),
                    "kev_present":  adv.get("kev_present"),
                    "threat_type":  adv.get("threat_type"),
                    "relevance":    "DIRECT" if vendor_lower in title else "INDIRECT",
                })
        return {
            "vendor":         vendor_domain,
            "matching_advisories": len(hits),
            "direct_matches": len([h for h in hits if h["relevance"] == "DIRECT"]),
            "advisories":     hits[:10],
            "risk_elevation": "HIGH" if any(h.get("kev_present") for h in hits) else
                              "MEDIUM" if hits else "NONE",
        }

    # ── Scoring Dimensions ────────────────────────────────────────────────────

    def _score_security_posture(self, domain: str, category: str, certs: List[str]) -> float:
        score = 50.0  # Baseline

        # Compliance certificates boost posture
        for cert in certs:
            score += COMPLIANCE_SCORES.get(cert, 0) * 0.5

        # Category-specific adjustments
        cat_info = HIGH_RISK_VENDOR_CATEGORIES.get(category, {"weight": 1.0})
        score -= cat_info["weight"] * 5  # Higher risk category = lower posture score

        # Known breach history penalty
        if domain in KNOWN_BREACH_INDICATORS:
            breaches = KNOWN_BREACH_INDICATORS[domain]
            for b in breaches:
                if b["severity"] == "CRITICAL":
                    score -= 25
                elif b["severity"] == "HIGH":
                    score -= 15

        # CVE pattern penalty
        for vendor_name, cve_data in VENDOR_CVE_RISK_PATTERNS.items():
            if vendor_name in domain:
                if cve_data["high_cve_probability"]:
                    score -= 10
                if cve_data["patch_velocity"] == "slow":
                    score -= 10
                break

        return round(max(0.0, min(100.0, score)), 1)

    def _score_data_risk(self, data_classes: List[DataClassification], access_lvl: AccessLevel, category: str) -> float:
        score = 80.0  # Start high (low risk)

        data_risk_map = {
            DataClassification.PHI:    30,
            DataClassification.PCI:    25,
            DataClassification.PII:    20,
            DataClassification.IP:     20,
            DataClassification.CONF:   10,
            DataClassification.PUBLIC:  0,
        }
        for dc in data_classes:
            score -= data_risk_map.get(dc, 5)

        access_risk = {
            AccessLevel.NONE:  0,
            AccessLevel.READ:  5,
            AccessLevel.WRITE: 15,
            AccessLevel.ADMIN: 25,
            AccessLevel.ROOT:  35,
        }
        score -= access_risk.get(access_lvl, 10)

        return round(max(0.0, min(100.0, score)), 1)

    def _score_compliance(self, certs: List[str], category: str) -> float:
        if not certs:
            return 20.0
        score = min(100.0, sum(COMPLIANCE_SCORES.get(c, 3.0) for c in certs))
        return round(score, 1)

    def _score_business_continuity(self, category: str) -> float:
        concentration_risk = {
            "identity_provider": 40,
            "payment_processor": 35,
            "cloud_storage":     30,
            "erp_system":        30,
            "email_provider":    35,
        }
        base   = 70.0
        deduct = concentration_risk.get(category, 0)
        return round(max(10.0, base - deduct), 1)

    def _score_threat_intel(self, domain: str, advisories: List[Dict]) -> float:
        score = 80.0
        if domain in KNOWN_BREACH_INDICATORS:
            score -= 30
        if advisories:
            critical_adv = [a for a in advisories if a.get("severity") in ("CRITICAL", "HIGH")]
            score -= min(40, len(critical_adv) * 10)
        return round(max(0.0, min(100.0, score)), 1)

    def _score_geopolitical(self, domain: str) -> float:
        tld = domain.split(".")[-1].lower() if "." in domain else ""
        high_risk_tlds = {"cn", "ru", "kp", "ir", "by", "cu", "sd", "sy", "ve"}
        medium_risk_tlds = {"in", "pk", "ng", "bd", "mm"}
        if tld in high_risk_tlds:
            return 20.0
        if tld in medium_risk_tlds:
            return 50.0
        return 85.0

    # ── Analysis Methods ──────────────────────────────────────────────────────

    def _analyze_cve_exposure(self, domain: str, vendor_name: str) -> Dict:
        domain_lower = domain.lower()
        for vendor_key, cve_info in VENDOR_CVE_RISK_PATTERNS.items():
            if vendor_key in domain_lower or vendor_key in vendor_name.lower():
                return {
                    "cve_risk":         "HIGH",
                    "known_categories": cve_info["cve_categories"],
                    "patch_velocity":   cve_info["patch_velocity"],
                    "recommendation":   "Subscribe to vendor security advisories; enforce patch SLA < 30 days",
                    "kev_exposure":     "Check CISA KEV for vendor-specific entries",
                }
        return {
            "cve_risk":       "MODERATE",
            "known_categories": ["General software vulnerabilities"],
            "patch_velocity": "unknown",
            "recommendation": "Require vendor to provide CVE patch SLA in contract",
        }

    def _get_breach_history(self, domain: str) -> List[Dict]:
        return KNOWN_BREACH_INDICATORS.get(domain, [])

    def _analyze_contract(self, contract_data: Dict, category: str) -> List[str]:
        flags = []
        if not contract_data:
            flags.append("No contract data provided — manual review required")
            return flags

        required_clauses = {
            "incident_notification_hours": 72,
            "audit_rights": True,
            "data_deletion_on_termination": True,
            "subprocessor_notification": True,
            "security_standards_sla": True,
        }
        for clause, expected in required_clauses.items():
            if clause not in contract_data:
                flags.append(f"MISSING CONTRACT CLAUSE: {clause.replace('_', ' ').title()}")

        if category in ("payroll_processor", "healthcare_ehr", "payment_processor"):
            if "data_processing_agreement" not in contract_data:
                flags.append("CRITICAL: Data Processing Agreement (DPA) required but missing")

        return flags

    def _generate_monitoring_signals(self, domain: str, category: str) -> List[Dict]:
        signals = [
            {"signal": "Certificate Transparency monitoring", "frequency": "Daily",    "source": "crt.sh"},
            {"signal": "DNS change detection",                "frequency": "Hourly",   "source": "Passive DNS"},
            {"signal": "CVE/advisory correlation",            "frequency": "Real-time","source": "SENTINEL APEX Feed"},
            {"signal": "Breach database correlation",         "frequency": "Daily",    "source": "HaveIBeenPwned, HIBP Enterprise"},
            {"signal": "Dark web mention monitoring",         "frequency": "Daily",    "source": "Dark web intelligence"},
        ]
        if category in ("identity_provider", "it_management"):
            signals.append({"signal": "Access log anomaly detection", "frequency": "Real-time", "source": "SIEM integration"})
        return signals

    def _generate_recommendations(
        self,
        score: VendorRiskScore,
        category: str,
        data_classes: List[DataClassification],
        certs: List[str],
    ) -> List[str]:
        recs = []
        if score.overall < 60:
            recs.append("IMMEDIATE: Conduct emergency vendor security review")
            recs.append("Require remediation plan with 30-day SLA")
        if not certs:
            recs.append("Require SOC 2 Type II attestation within 90 days")
        if score.compliance < 40:
            recs.append("Mandate compliance certification path with quarterly milestones")
        if DataClassification.PHI in data_classes and "HIPAA" not in certs:
            recs.append("CRITICAL: HIPAA BAA required — execute before any PHI sharing")
        if DataClassification.PCI in data_classes and "PCI-DSS" not in certs:
            recs.append("CRITICAL: PCI-DSS compliance evidence required")
        if score.threat_intel < 50:
            recs.append("Heightened monitoring: increase scan frequency to hourly")
        if AccessLevel.ADMIN in str(data_classes) or AccessLevel.ROOT in str(data_classes):
            recs.append("Implement PAM (Privileged Access Management) for vendor access sessions")
            recs.append("Require MFA on all privileged vendor accounts")
        recs.append("Conduct annual penetration test on vendor integration touchpoints")
        recs.append("Include right-to-audit clause in contract renewal")
        return recs[:8]

    def _questionnaire_gap_analysis(self, contract_data: Dict, certs: List[str]) -> List[str]:
        gaps = []
        for domain in QUESTIONNAIRE_DOMAINS:
            key = domain.lower().replace(" ", "_")
            if key not in contract_data and not any(c in certs for c in ["SOC 2 Type II", "ISO 27001"]):
                gaps.append(domain)
        return gaps[:10]

    def _calculate_review_cadence(self, tier: RiskTier) -> str:
        from datetime import timedelta
        now = datetime.now(timezone.utc)
        delta_days = {"CRITICAL": 30, "HIGH": 90, "MEDIUM": 180, "LOW": 365, "MINIMAL": 730}
        days = delta_days.get(tier.value, 365)
        review_dt = now + __import__("datetime").timedelta(days=days)
        return review_dt.strftime("%Y-%m-%d")

    def _generate_portfolio_actions(self, critical: List, high: List) -> List[Dict]:
        actions = []
        if critical:
            actions.append({
                "priority": "P1",
                "action":   f"Emergency review for {len(critical)} CRITICAL-tier vendors",
                "timeline": "Within 24 hours",
                "owners":   ["CISO", "Vendor Risk Team", "Legal"],
                "vendors":  [p.name for p in critical[:5]],
            })
        if high:
            actions.append({
                "priority": "P2",
                "action":   f"Enhanced monitoring for {len(high)} HIGH-tier vendors",
                "timeline": "Within 2 weeks",
                "owners":   ["Vendor Risk Team"],
                "vendors":  [p.name for p in high[:5]],
            })
        actions.append({
            "priority": "P3",
            "action":   "Quarterly vendor risk portfolio review",
            "timeline": "Next quarter",
            "owners":   ["Vendor Risk Team", "Procurement"],
        })
        return actions

    @staticmethod
    def _serialize_profile(p: VendorProfile) -> Dict:
        return {
            "vendor_id":           p.vendor_id,
            "name":                p.name,
            "domain":              p.domain,
            "category":            p.category,
            "data_access":         [d.value for d in p.data_access],
            "access_level":        p.access_level.value,
            "risk_score":          {
                "overall":             p.risk_score.overall,
                "tier":                p.risk_score.tier.value,
                "security_posture":    p.risk_score.security_posture,
                "data_risk":           p.risk_score.data_risk,
                "compliance":          p.risk_score.compliance,
                "business_continuity": p.risk_score.business_continuity,
                "threat_intel":        p.risk_score.threat_intel,
                "geopolitical":        p.risk_score.geopolitical,
                "confidence":          p.risk_score.confidence,
            },
            "cve_exposure":        p.cve_exposure,
            "breach_history":      p.breach_history,
            "compliance_certs":    p.compliance_certs,
            "contract_flags":      p.contract_flags,
            "monitoring_signals":  p.monitoring_signals,
            "assessed_at":         p.assessed_at,
            "next_review":         p.next_review,
            "recommendations":     p.recommendations,
            "questionnaire_gaps":  p.questionnaire_gaps,
        }

    def get_stats(self) -> Dict:
        return {
            "engine":             "VendorRiskEngine v1.0",
            "assessments_total":  self.assessments_total,
            "vendor_registry":    len(self.vendor_registry),
            "scoring_model":      "FAIR-ALIGNED-v1",
            "risk_dimensions":    6,
            "compliance_frameworks_tracked": len(COMPLIANCE_SCORES),
        }
