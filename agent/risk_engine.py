#!/usr/bin/env python3
"""
risk_engine.py — CyberDudeBivash v11.0 (SENTINEL APEX ULTRA)
NEW MODULE: Dynamic Risk Scoring Engine.
Replaces hardcoded risk_score=9.3 with weighted multi-factor analysis.
"""
import logging
from typing import Dict, List, Optional

from agent.config import RISK_WEIGHTS, TLP_MATRIX

logger = logging.getLogger("CDB-RISK-ENGINE")


class RiskScoringEngine:
    """
    Calculates dynamic risk scores based on:
    - IOC richness & diversity
    - Domain entropy
    - Actor attribution confidence
    - MITRE ATT&CK technique count
    - CVSS / EPSS signals (when available)
    """

    def __init__(self):
        self.weights = RISK_WEIGHTS

    def calculate_risk_score(
        self,
        iocs: Dict[str, List[str]],
        mitre_matches: Optional[List[Dict]] = None,
        actor_data: Optional[Dict] = None,
        cvss_score: Optional[float] = None,
        epss_score: Optional[float] = None,
    ) -> float:
        """
        Calculate dynamic risk score (0.0 - 10.0).

        Args:
            iocs: Extracted IOC dictionary
            mitre_matches: List of MITRE technique dicts
            actor_data: Actor attribution data
            cvss_score: CVSS base score if CVE present
            epss_score: EPSS probability if CVE present

        Returns:
            Float risk score capped at 10.0
        """
        score = self.weights.get("base_score", 2.0)

        # ── IOC Diversity Scoring ──
        ioc_categories_found = sum(1 for v in iocs.values() if v)
        score += ioc_categories_found * self.weights.get("base_ioc_count", 0.5)

        # Specific indicator bonuses
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

        # ── MITRE ATT&CK Scoring ──
        if mitre_matches:
            technique_count = len(mitre_matches)
            score += technique_count * self.weights.get("mitre_technique_count", 0.3)

        # ── Actor Attribution Scoring ──
        if actor_data:
            tracking_id = actor_data.get('tracking_id', '')
            if tracking_id and not tracking_id.startswith('UNC-'):
                # Known actor = higher confidence
                score += self.weights.get("actor_mapped", 1.0)
            else:
                score += 0.3  # Unknown cluster still gets partial credit

        # ── Vulnerability Scoring ──
        if cvss_score and cvss_score >= 9.0:
            score += self.weights.get("cvss_above_9", 2.0)
        elif cvss_score and cvss_score >= 7.0:
            score += 1.0

        if epss_score and epss_score >= 0.9:
            score += self.weights.get("epss_above_09", 1.5)
        elif epss_score and epss_score >= 0.5:
            score += 0.8

        # ── Cap at maximum ──
        max_score = self.weights.get("max_score", 10.0)
        final_score = min(round(score, 1), max_score)

        logger.info(f"Dynamic Risk Score: {final_score}/10 "
                     f"(IOC categories: {ioc_categories_found}, "
                     f"MITRE: {len(mitre_matches or [])}, "
                     f"Actor: {bool(actor_data)})")

        return final_score

    def get_severity_label(self, risk_score: float) -> str:
        """Map risk score to severity label."""
        if risk_score >= 8.5:
            return "CRITICAL"
        elif risk_score >= 6.5:
            return "HIGH"
        elif risk_score >= 4.0:
            return "MEDIUM"
        elif risk_score >= 2.0:
            return "LOW"
        else:
            return "INFO"

    def get_tlp_label(self, risk_score: float) -> Dict[str, str]:
        """Map risk score to TLP classification."""
        for level in ["RED", "AMBER", "GREEN", "CLEAR"]:
            tlp = TLP_MATRIX[level]
            if risk_score >= tlp["min_score"]:
                return {"label": tlp["label"], "color": tlp["color"]}
        return {"label": "TLP:CLEAR", "color": "#94a3b8"}


# Global singleton
risk_engine = RiskScoringEngine()
