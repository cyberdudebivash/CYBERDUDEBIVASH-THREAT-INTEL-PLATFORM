#!/usr/bin/env python3
"""
risk_engine.py — CyberDudeBivash v12.0 (SENTINEL APEX ULTRA)
COMPLETE REWRITE: Content-Aware Dynamic Risk Scoring Engine.

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
        "data exfiltration": 2.0, "data stolen": 2.0,
        "hackers leak": 2.0, "hackers claim": 1.5,
        "critical infrastructure": 2.0,
        "financial fraud": 1.8, "banking trojan": 1.8,
        "espionage": 2.0, "cyber espionage": 2.0,
        # Medium severity (weight 0.8-1.5)
        "vulnerability": 1.0, "exploit": 1.2,
        "phishing campaign": 1.2, "phishing attack": 1.2,
        "social engineering": 1.0, "clickfix": 1.2,
        "malware": 1.2, "trojan": 1.2, "stealer": 1.2,
        "botnet": 1.2, "infostealer": 1.2,
        "security flaw": 1.0, "security bug": 1.0,
        "patch": 0.8, "update": 0.5, "security update": 0.8,
        "denial of service": 1.0, "ddos": 1.0,
        "unauthorized access": 1.5,
        "leaked": 1.5, "exposed": 1.5,
        "compromised": 1.5, "breached": 1.5,
    }

    # ── Impact magnitude patterns ──
    IMPACT_PATTERNS = [
        # Millions - with optional adjective between number and entity
        (r'(\d+(?:\.\d+)?)\s*(?:million|M)\s+\w*\s*(?:records|users|customers|accounts|people|individuals|patients|loanees|members)',
         "records", 1_000_000),
        (r'(\d+(?:\.\d+)?)\s*(?:million|M)\s+(?:affected|impacted|exposed|breached|compromised)',
         "affected", 1_000_000),
        # Thousands - with optional adjective
        (r'(\d+(?:\.\d+)?)\s*(?:thousand|K)\s+\w*\s*(?:records|users|customers|accounts|people)',
         "records", 1_000),
        # Direct number + optional adjective + entity + action verb
        (r'(\d[\d,]*)\s+\w*\s*(?:records|users|customers|accounts|people|individuals|patients|loanees|members)\s+\w*\s*(?:exposed|leaked|breached|stolen|compromised|affected|impacted)',
         "records", 1),
        (r'(?:exposed|leaked|breached|stolen|compromised|affected|impacted)\s+(?:\w+\s+)?(\d[\d,]*)\s+\w*\s*(?:records|users|customers|accounts)',
         "records", 1),
        # Number directly followed by entity
        (r'(\d[\d,]*)\s+(?:records|users|customers|accounts|people|individuals|patients)\s+(?:exposed|leaked|breached|stolen|compromised|affected)',
         "records", 1),
        # Shorthand: 2.5M, 600K - with optional adjective
        (r'(\d+(?:\.\d+)?)[Mm]\s+\w*\s*(?:records|users|customers|accounts|people)', "records", 1_000_000),
        (r'(\d+(?:\.\d+)?)[Kk]\s+\w*\s*(?:records|users|customers|accounts|people)', "records", 1_000),
        # "over X million" pattern
        (r'over\s+(\d+(?:\.\d+)?)\s*(?:million|M)\s+\w*', "records", 1_000_000),
        # Dollar amounts
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


risk_engine = RiskScoringEngine()
