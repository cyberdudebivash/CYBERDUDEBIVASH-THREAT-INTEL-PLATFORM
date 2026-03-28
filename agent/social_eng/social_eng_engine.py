"""
CYBERDUDEBIVASH® SENTINEL APEX
DEEPFAKE & SOCIAL ENGINEERING DETECTION ENGINE v1.0
AI-based phishing detection, voice/video anomaly indicators, BEC detection.
"""
import re, logging
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-SOCIAL-ENG")

PHISHING_INDICATORS = [
    r"urgent.*action.*required",
    r"verify.*account.*immediately",
    r"click.*here.*update.*credential",
    r"your.*account.*suspended",
    r"invoice.*attached.*overdue",
    r"password.*expir",
    r"unusual.*sign.*in.*activity",
    r"limited.*time.*offer",
    r"you.*won.*prize",
    r"wire.*transfer.*request",
    r"ceo.*request.*confidential",
    r"gift.*card.*purchase",
]

BEC_PATTERNS = [
    r"urgent\s+wire\s+transfer",
    r"change.*bank.*account.*details",
    r"payment.*redirect",
    r"vendor.*bank.*update",
    r"confidential.*financial",
    r"do not\s+discuss.*anyone",
    r"cfo.*urgent.*request",
]

DEEPFAKE_VOICE_SIGNALS = [
    "unexpected voice request for credentials",
    "voice call requesting urgent wire transfer",
    "audio quality inconsistency reported",
    "voice authentication bypass attempt",
    "synthetic voice detected in communication",
]


class SocialEngDetector:
    """
    Detects social engineering, phishing, BEC, and deepfake indicators
    in advisory text and communication metadata.
    """

    def __init__(self):
        self.detections = 0

    def analyze_advisory(self, advisory: Dict) -> Dict:
        """Analyze advisory for social engineering attack indicators."""
        text = f"{advisory.get('title','')} {advisory.get('summary','')}".lower()
        ttps = advisory.get("mitre_techniques", [])

        signals = []
        attack_types = []

        # Phishing indicators
        phish_hits = [p for p in PHISHING_INDICATORS if re.search(p, text)]
        if phish_hits or "T1566" in ttps:
            signals.append({"type": "PHISHING", "patterns": phish_hits[:3]})
            attack_types.append("PHISHING")

        # BEC indicators
        bec_hits = [p for p in BEC_PATTERNS if re.search(p, text)]
        if bec_hits:
            signals.append({"type": "BEC", "patterns": bec_hits[:3]})
            attack_types.append("BUSINESS_EMAIL_COMPROMISE")

        # Deepfake/voice signals
        for sig in DEEPFAKE_VOICE_SIGNALS:
            if any(word in text for word in sig.split()[:3]):
                signals.append({"type": "DEEPFAKE_VOICE", "signal": sig})
                attack_types.append("DEEPFAKE_VOICE")
                break

        # Social engineering TTPs
        se_ttps = {"T1566", "T1598", "T1534", "T1534"}
        ttp_matches = list(set(ttps) & se_ttps)
        if ttp_matches:
            signals.append({"type": "MITRE_TTP", "ttps": ttp_matches})

        risk_level = ("CRITICAL" if "BUSINESS_EMAIL_COMPROMISE" in attack_types
                      else "HIGH" if "PHISHING" in attack_types
                      else "MEDIUM" if signals else "LOW")

        self.detections += 1 if signals else 0
        return {
            "advisory_id":         advisory.get("stix_id", ""),
            "is_social_eng":       len(signals) > 0,
            "attack_types":        attack_types,
            "signals":             signals,
            "risk_level":          risk_level,
            "detection_confidence": min(0.95, len(signals) * 0.25),
            "countermeasures": self._get_countermeasures(attack_types),
            "analyzed_at": datetime.now(timezone.utc).isoformat(),
        }

    def _get_countermeasures(self, attack_types: List[str]) -> List[str]:
        measures = ["Security awareness training for all staff"]
        if "PHISHING" in attack_types:
            measures += ["Deploy DMARC/DKIM/SPF", "Enable email sandboxing",
                         "Anti-phishing browser extensions"]
        if "BUSINESS_EMAIL_COMPROMISE" in attack_types:
            measures += ["Verify all wire transfers via callback on known number",
                         "Implement dual-approval for financial transactions > threshold"]
        if "DEEPFAKE_VOICE" in attack_types:
            measures += ["Establish voice codewords for sensitive requests",
                         "Never authorize actions via unsolicited voice calls"]
        return measures

    def get_stats(self) -> Dict:
        return {"detections": self.detections, "engine": "SocialEngDetector v1.0"}
