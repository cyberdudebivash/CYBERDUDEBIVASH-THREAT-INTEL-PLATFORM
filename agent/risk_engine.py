#!/usr/bin/env python3
"""
risk_engine.py — CyberDudeBivash v17.0 (SENTINEL APEX ULTRA)
ENHANCED: Content-Aware Dynamic Risk Scoring Engine + Predictive Intelligence Fields.

v17.0 ADDITIONS (fully non-breaking — all new fields are supplementary):
  - predictive_risk_delta: estimated risk change based on exploit signals
  - exploit_velocity: frequency-based momentum score (0.0-10.0)
  - intel_confidence_score: weighted multi-source confidence metric
  - threat_momentum_score: composite momentum (Sentinel Momentum Index™)
  - compute_extended_metrics(): returns all new fields as supplementary dict

All existing calculate_risk_score() output is UNCHANGED.
Extended fields are returned via compute_extended_metrics() only.

KEY FIX: The old engine ONLY scored IOCs, so a "2.5M record breach"
with zero IOCs scored 2.6/10 (LOW). Now the engine analyzes headline
+ article content for impact signals, threat type classification,
and record counts to produce realistic risk assessments.

Scoring dimensions:
1. IOC richness & diversity (preserved from v11)
2. Content threat severity analysis (NEW)
3. Impact magnitude extraction (NEW) 
4. MITRE technique depth
5. Actor attribution confidence
6. CVSS / EPSS signals
"""
import re
import logging
from typing import Dict, List, Optional, Tuple

from agent.config import RISK_WEIGHTS, TLP_MATRIX

logger = logging.getLogger("CDB-RISK-ENGINE")


class RiskScoringEngine:
    """
    Content-aware dynamic risk scoring with impact intelligence.
    """

    # ── Threat severity keywords with weights ──
    SEVERITY_SIGNALS = {
        # Critical severity (weight 3.0+)
        "zero-day": 3.5, "zero day": 3.5, "0-day": 3.5, "0day": 3.5,
        "actively exploited": 3.0, "in the wild": 2.5,
        "critical vulnerability": 3.0, "remote code execution": 3.0,
        "rce": 2.5, "pre-auth": 2.5,
        "nation-state": 2.5, "state-sponsored": 2.5,
        "ransomware attack": 2.5, "supply chain attack": 2.5,
        "supply chain compromise": 2.5,
        # High severity (weight 1.5-2.5)
        "data breach": 2.0, "records exposed": 2.0, "records leaked": 2.0,
        "customer records": 1.8, "customer data": 1.8,
        "personal data": 1.8, "pii exposed": 2.0,
        "ransomware": 2.0, "malware campaign": 1.8,
        "backdoor": 1.8, "rootkit": 2.0,
        "privilege escalation": 1.5, "authentication bypass": 2.0,
        "credential theft": 1.8, "credential stuffing": 1.5,
        "credential harvest": 1.8, "harvested credentials": 1.8,
        "session token": 1.8, "token theft": 1.8,
        "data exfiltration": 2.0, "data stolen": 2.0,
        "hackers leak": 2.0, "hackers claim": 1.5,
        "critical infrastructure": 2.0,
        "financial fraud": 1.8, "banking trojan": 1.8,
        "espionage": 2.0, "cyber espionage": 2.0,
        # Browser / Extension attacks (NEW)
        "malicious extension": 2.0, "fake extension": 2.0,
        "browser extension": 1.5, "chrome extension": 1.5,
        "malicious browser": 1.8, "fake browser": 1.8,
        "malicious plugin": 1.8, "fake plugin": 1.8,
        "webstore": 1.2, "web store": 1.2,
        "browser hijack": 2.0, "session hijack": 1.8,
        "oauth token": 1.5, "cookie theft": 1.8,
        "users duped": 1.8, "users tricked": 1.8,
        "users compromised": 1.8, "users affected": 1.5,
        "users impacted": 1.5, "users targeted": 1.5,
        "impersonat": 1.5,
        # Identity / MFA / Account Compromise (NEW for 0ktapus-style campaigns)
        "mfa bypass": 2.2, "mfa fatigue": 2.0, "mfa interception": 2.2,
        "multi-factor authentication": 1.8, "mfa codes": 1.8,
        "sim swap": 2.0, "sim swapping": 2.0,
        "account takeover": 2.0, "identity theft": 2.0,
        "identity credential": 1.8, "okta": 1.5,
        "credential phishing": 1.8, "spear phishing": 1.5,
        "smishing": 1.5, "sms phishing": 1.5,
        "authentication page": 1.5, "spoofed": 1.5, "mimicked": 1.5,
        "organizations being compromised": 2.0, "accounts compromised": 2.0,
        # Medium severity (weight 0.8-1.5)
        "vulnerability": 1.0, "exploit": 1.2,
        "phishing campaign": 1.2, "phishing attack": 1.2,
        "phishing": 1.0,
        "social engineering": 1.0, "clickfix": 1.2,
        "malware": 1.2, "trojan": 1.2, "stealer": 1.2,
        "botnet": 1.2, "infostealer": 1.2,
        "security flaw": 1.0, "security bug": 1.0,
        "patch": 0.8, "update": 0.5, "security update": 0.8,
        "denial of service": 1.0, "ddos": 1.0,
        "unauthorized access": 1.5,
        "leaked": 1.5, "exposed": 1.5,
        "compromised": 1.5, "breached": 1.5,
        "duped": 1.5, "tricked": 1.5,
        "fake ai": 1.5, "malicious ai": 1.5,
    }

    # ── Impact magnitude patterns ──
    # KEY FIXES in v12.1:
    # - \+? after K/M to handle "260K+" shorthand
    # - (?:\w+\s+){0,3} to handle multi-word gaps like "Chrome Users"
    # - More action verbs: installed, duped, tricked, targeted, infected, hit
    # - Patterns that work WITHOUT requiring action verb after entity
    ENTITY_WORDS = r'(?:records|users|customers|accounts|people|individuals|patients|loanees|members|victims|devices|systems|endpoints)'
    IMPACT_PATTERNS = [
        # ── K/M SHORTHAND (260K+, 2.5M, 600K) ──
        # Handles: "260K+ Chrome Users", "2.5M records exposed", "600K customer records"
        (r'(\d+(?:\.\d+)?)[Kk]\+?\s+(?:\w+\s+){0,3}' + ENTITY_WORDS, "records", 1_000),
        (r'(\d+(?:\.\d+)?)[Mm]\+?\s+(?:\w+\s+){0,3}' + ENTITY_WORDS, "records", 1_000_000),

        # ── MILLIONS: "2.5 million loanees", "over 1.2 million patient records" ──
        (r'(?:over\s+)?(\d+(?:\.\d+)?)\s*(?:million)\s+(?:\w+\s+){0,3}' + ENTITY_WORDS,
         "records", 1_000_000),
        (r'(\d+(?:\.\d+)?)\s*(?:million)\s+(?:affected|impacted|exposed|breached|compromised)',
         "affected", 1_000_000),

        # ── THOUSANDS: "50 thousand users" ──
        (r'(?:over\s+)?(\d+(?:\.\d+)?)\s*(?:thousand)\s+(?:\w+\s+){0,3}' + ENTITY_WORDS,
         "records", 1_000),

        # ── DIRECT NUMBERS: "260,000 Chrome users", "600000 customer records" ──
        # Up to 3 words between number and entity
        (r'(?:over\s+|more\s+than\s+)?(\d[\d,]+)\s+(?:\w+\s+){0,3}' + ENTITY_WORDS,
         "records", 1),

        # ── VERB-FIRST: "affected 500,000 users", "exposed 2.5M records" ──
        (r'(?:exposed|leaked|breached|stolen|compromised|affected|impacted|infected|hit|targeted|duped|tricked)\s+(?:\w+\s+){0,2}(\d[\d,]+)\s+(?:\w+\s+){0,2}' + ENTITY_WORDS,
         "records", 1),

        # ── DOLLAR AMOUNTS ──
        (r'\$\s*(\d+(?:\.\d+)?)\s*(?:million|M|billion|B)', "financial", 1_000_000),
        (r'(\d+(?:\.\d+)?)\s*(?:million|M)\s*(?:dollars|\$|USD)', "financial", 1_000_000),
    ]

    def __init__(self):
        self.weights = RISK_WEIGHTS

    def extract_impact_metrics(self, headline: str, content: str) -> Dict:
        """
        Extract quantified impact metrics from text.
        Returns: {records_affected, financial_impact, severity_keywords, impact_score}
        """
        text = f"{headline} {content}"
        metrics = {
            "records_affected": 0,
            "financial_impact": 0,
            "severity_keywords": [],
            "impact_score": 0.0,
            "affected_entities": [],
        }

        # Extract record/user counts
        for pattern, metric_type, multiplier in self.IMPACT_PATTERNS:
            matches = re.findall(pattern, text, re.IGNORECASE)
            for match in matches:
                try:
                    num = float(match.replace(',', ''))
                    value = num * multiplier
                    if metric_type == "records":
                        metrics["records_affected"] = max(metrics["records_affected"], int(value))
                    elif metric_type == "financial":
                        metrics["financial_impact"] = max(metrics["financial_impact"], value)
                except (ValueError, TypeError):
                    continue

        # Extract severity keywords found
        text_lower = text.lower()
        for keyword, weight in self.SEVERITY_SIGNALS.items():
            if keyword in text_lower:
                metrics["severity_keywords"].append((keyword, weight))

        # Calculate impact score from metrics
        impact = 0.0

        # Record count impact
        if metrics["records_affected"] >= 10_000_000:
            impact += 4.0
        elif metrics["records_affected"] >= 1_000_000:
            impact += 3.0
        elif metrics["records_affected"] >= 100_000:
            impact += 2.5
        elif metrics["records_affected"] >= 10_000:
            impact += 1.5
        elif metrics["records_affected"] >= 1_000:
            impact += 1.0

        # Keyword severity impact (take top 3 weights)
        if metrics["severity_keywords"]:
            sorted_kw = sorted(metrics["severity_keywords"], key=lambda x: x[1], reverse=True)
            top_weights = [w for _, w in sorted_kw[:3]]
            impact += sum(top_weights) / len(top_weights)  # Average of top 3

        # Financial impact
        if metrics["financial_impact"] >= 100_000_000:
            impact += 2.0
        elif metrics["financial_impact"] >= 1_000_000:
            impact += 1.0

        metrics["impact_score"] = round(min(impact, 6.0), 1)  # Cap content boost at 6.0

        return metrics

    def calculate_risk_score(
        self,
        iocs: Dict[str, List[str]],
        mitre_matches: Optional[List[Dict]] = None,
        actor_data: Optional[Dict] = None,
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        headline: str = "",
        content: str = "",
    ) -> float:
        """
        Calculate dynamic risk score (0.0 - 10.0).
        NOW CONTENT-AWARE: Analyzes headline + content for impact.
        """
        score = self.weights.get("base_score", 2.0)

        # ── IOC Diversity Scoring (preserved) ──
        ioc_categories_found = sum(1 for v in iocs.values() if v)
        score += ioc_categories_found * self.weights.get("base_ioc_count", 0.5)

        if iocs.get('sha256') or iocs.get('sha1') or iocs.get('md5'):
            score += self.weights.get("has_sha256", 1.5)
        if iocs.get('ipv4'):
            score += self.weights.get("has_ipv4", 1.0)
        if iocs.get('domain'):
            score += self.weights.get("has_domain", 0.8)
        if iocs.get('url'):
            score += self.weights.get("has_url", 0.7)
        if iocs.get('email'):
            score += self.weights.get("has_email", 0.5)
        if iocs.get('registry'):
            score += self.weights.get("has_registry", 1.2)
        if iocs.get('artifacts'):
            score += self.weights.get("has_artifacts", 1.0)

        # ── MITRE ATT&CK Scoring (preserved) ──
        if mitre_matches:
            score += len(mitre_matches) * self.weights.get("mitre_technique_count", 0.3)

        # ── Actor Attribution Scoring (preserved) ──
        if actor_data:
            tracking_id = actor_data.get('tracking_id', '')
            if tracking_id and not tracking_id.startswith('UNC-'):
                score += self.weights.get("actor_mapped", 1.0)
            else:
                score += 0.3

        # ── Vulnerability Scoring (preserved) ──
        if cvss_score and cvss_score >= 9.0:
            score += self.weights.get("cvss_above_9", 2.0)
        elif cvss_score and cvss_score >= 7.0:
            score += 1.0
        if epss_score and epss_score >= 0.9:
            score += self.weights.get("epss_above_09", 1.5)
        elif epss_score and epss_score >= 0.5:
            score += 0.8

        # ══════════════════════════════════════════════
        # NEW: Content-Aware Intelligence Analysis
        # This is the KEY FIX — analyzes headline + content
        # so "2.5M records breach" scores HIGH, not LOW
        # ══════════════════════════════════════════════
        if headline or content:
            impact = self.extract_impact_metrics(headline, content)
            content_boost = impact["impact_score"]
            if content_boost > 0:
                score += content_boost
                logger.info(f"Content intelligence boost: +{content_boost} "
                           f"(records: {impact['records_affected']:,}, "
                           f"keywords: {len(impact['severity_keywords'])})")

        # ── Cap at maximum ──
        max_score = self.weights.get("max_score", 10.0)
        final_score = min(round(score, 1), max_score)

        logger.info(f"Dynamic Risk Score: {final_score}/10 "
                    f"(IOC categories: {ioc_categories_found}, "
                    f"MITRE: {len(mitre_matches or [])}, "
                    f"Actor: {bool(actor_data)})")

        return final_score

    def get_severity_label(self, risk_score: float) -> str:
        if risk_score >= 8.5:
            return "CRITICAL"
        elif risk_score >= 6.5:
            return "HIGH"
        elif risk_score >= 4.0:
            return "MEDIUM"
        elif risk_score >= 2.0:
            return "LOW"
        return "INFO"

    def get_tlp_label(self, risk_score: float) -> Dict[str, str]:
        for level in ["RED", "AMBER", "GREEN", "CLEAR"]:
            tlp = TLP_MATRIX[level]
            if risk_score >= tlp["min_score"]:
                return {"label": tlp["label"], "color": tlp["color"]}
        return {"label": "TLP:CLEAR", "color": "#94a3b8"}

    # ══════════════════════════════════════════════════════════════
    # v17.0 EXTENDED METRICS — SUPPLEMENTARY INTELLIGENCE FIELDS
    # All methods below are ADDITIVE. They do not modify any
    # existing method output. Call compute_extended_metrics() after
    # calculate_risk_score() to get additional intelligence signals.
    # ══════════════════════════════════════════════════════════════

    def compute_extended_metrics(
        self,
        risk_score: float,
        headline: str = "",
        content: str = "",
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
        kev_present: bool = False,
        source_count: int = 1,
        iocs: Optional[Dict] = None,
        mitre_matches: Optional[List[Dict]] = None,
    ) -> Dict:
        """
        Compute supplementary intelligence metrics for a threat item.
        Returns a dict of new fields — NEVER modifies base risk_score.

        New fields:
          - predictive_risk_delta: estimated risk change signal (-3.0 to +3.0)
          - exploit_velocity: exploit momentum signal (0.0-10.0)
          - intel_confidence_score: multi-source confidence (0.0-100.0)
          - threat_momentum_score: Sentinel Momentum Index™ (0.0-10.0)
        """
        predictive_delta = self._compute_predictive_risk_delta(
            headline, content, cvss_score, epss_score, kev_present
        )
        exploit_velocity = self._compute_exploit_velocity(headline, content, cvss_score)
        intel_confidence = self._compute_intel_confidence(
            source_count, iocs or {}, mitre_matches or [], risk_score
        )
        momentum = self._compute_threat_momentum(exploit_velocity, predictive_delta)

        extended = {
            "predictive_risk_delta": round(predictive_delta, 2),
            "exploit_velocity": round(exploit_velocity, 2),
            "intel_confidence_score": round(intel_confidence, 1),
            "threat_momentum_score": round(momentum, 2),
            "threat_momentum_label": self._momentum_label(momentum),
        }

        logger.info(
            f"📊 Extended Metrics | "
            f"Δ Risk: {extended['predictive_risk_delta']:+.2f} | "
            f"Velocity: {extended['exploit_velocity']}/10 | "
            f"Confidence: {extended['intel_confidence_score']}% | "
            f"Momentum: {extended['threat_momentum_score']}/10 ({extended['threat_momentum_label']})"
        )

        return extended

    def _compute_predictive_risk_delta(
        self,
        headline: str,
        content: str,
        cvss_score: Optional[float],
        epss_score: Optional[float],
        kev_present: bool,
    ) -> float:
        """
        Estimate how risk is likely to change over the next 14 days.
        Positive delta = risk likely increasing. Negative = stabilizing.
        Range: -3.0 to +3.0
        """
        delta = 0.0
        text = f"{headline} {content}".lower()

        # Positive signals (risk escalating)
        if kev_present:
            delta += 1.5
        if epss_score and epss_score >= 0.9:
            delta += 1.0
        elif epss_score and epss_score >= 0.5:
            delta += 0.5
        if any(t in text for t in ["zero-day", "0-day", "actively exploited", "in the wild"]):
            delta += 1.0
        if any(t in text for t in ["ransomware", "nation-state", "supply chain attack"]):
            delta += 0.8
        if cvss_score and cvss_score >= 9.0:
            delta += 0.5

        # Negative signals (risk stabilizing)
        if any(t in text for t in ["patched", "fixed", "mitigated", "remediated", "update available"]):
            delta -= 1.0
        if any(t in text for t in ["no active exploitation", "not exploited", "theoretical"]):
            delta -= 0.8

        return max(-3.0, min(3.0, delta))

    def _compute_exploit_velocity(
        self,
        headline: str,
        content: str,
        cvss_score: Optional[float],
    ) -> float:
        """
        Compute exploit momentum: how quickly this threat is accelerating.
        Based on urgency signals + CVSS + content keywords.
        Range: 0.0 - 10.0
        """
        text = f"{headline} {content}".lower()
        velocity = 2.0  # Baseline

        # High velocity signals
        if "actively exploited" in text or "in the wild" in text:
            velocity += 3.0
        if "zero-day" in text or "0-day" in text:
            velocity += 2.5
        if "ransomware" in text:
            velocity += 2.0
        if "nation-state" in text or "state-sponsored" in text:
            velocity += 1.5
        if "poc available" in text or "proof of concept" in text:
            velocity += 1.5
        if "critical" in text:
            velocity += 1.0
        if cvss_score and cvss_score >= 9.0:
            velocity += 1.5
        elif cvss_score and cvss_score >= 7.0:
            velocity += 0.8

        # Velocity dampeners
        if "low severity" in text or "informational" in text:
            velocity -= 1.5
        if "patched" in text or "fixed" in text:
            velocity -= 1.0

        return max(0.0, min(10.0, velocity))

    def _compute_intel_confidence(
        self,
        source_count: int,
        iocs: Dict,
        mitre_matches: List[Dict],
        risk_score: float,
    ) -> float:
        """
        Weighted multi-source confidence score (0.0 - 100.0).
        Based on: source diversity, IOC richness, MITRE coverage, risk signal strength.
        """
        confidence = 20.0  # Base

        # Source diversity contribution (up to 25 pts)
        confidence += min(source_count * 5.0, 25.0)

        # IOC richness contribution (up to 30 pts)
        ioc_types_found = sum(1 for v in iocs.values() if v)
        confidence += min(ioc_types_found * 5.0, 30.0)

        # MITRE coverage contribution (up to 20 pts)
        confidence += min(len(mitre_matches) * 3.0, 20.0)

        # Risk score strength (up to 5 pts bonus for high-confidence threats)
        if risk_score >= 8.0:
            confidence += 5.0
        elif risk_score >= 6.0:
            confidence += 3.0

        return min(confidence, 100.0)

    def _compute_threat_momentum(
        self, exploit_velocity: float, predictive_delta: float
    ) -> float:
        """
        Sentinel Momentum Index™ (SMI) — composite threat acceleration score.
        Formula: SMI = (exploit_velocity × 0.6) + (predictive_delta_normalized × 0.4)
        Range: 0.0 - 10.0
        """
        # Normalize predictive_delta from [-3, 3] to [0, 10]
        delta_normalized = ((predictive_delta + 3.0) / 6.0) * 10.0
        momentum = (exploit_velocity * 0.6) + (delta_normalized * 0.4)
        return max(0.0, min(10.0, momentum))

    def _momentum_label(self, momentum: float) -> str:
        if momentum >= 8.0:
            return "SURGE"
        elif momentum >= 6.0:
            return "ACCELERATING"
        elif momentum >= 4.0:
            return "ACTIVE"
        elif momentum >= 2.0:
            return "STABLE"
        return "LOW"


risk_engine = RiskScoringEngine()
