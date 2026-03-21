"""
SENTINEL APEX v70 — Threat Classifier (AI-Powered)
====================================================
Hybrid classification engine:
1. Rule-based IOC type detection (regex, deterministic)
2. ML-based threat category classification (sklearn)
3. MITRE ATT&CK technique inference from text

Uses TF-IDF + SGDClassifier for fast, memory-efficient classification.
Falls back gracefully if ML dependencies unavailable.
"""

import logging
import re
from typing import Any, Dict, List, Optional, Tuple

from ..core.models import Advisory, IOC, IOCType, ThreatType

logger = logging.getLogger("sentinel.ai.classifier")

# ---------------------------------------------------------------------------
# ML Imports with graceful fallback
# ---------------------------------------------------------------------------
_ML_AVAILABLE = False
try:
    from sklearn.feature_extraction.text import TfidfVectorizer
    from sklearn.linear_model import SGDClassifier
    from sklearn.pipeline import Pipeline
    import numpy as np
    _ML_AVAILABLE = True
except ImportError:
    logger.warning("sklearn not available — falling back to rule-based classification")


# ---------------------------------------------------------------------------
# MITRE ATT&CK keyword mapping (lightweight inference)
# ---------------------------------------------------------------------------

MITRE_KEYWORD_MAP: Dict[str, List[str]] = {
    "T1566": ["phishing", "spear-phishing", "spearphishing", "email lure", "malicious attachment"],
    "T1190": ["exploit public", "internet-facing", "web exploit", "rce", "remote code execution"],
    "T1059": ["command", "powershell", "cmd", "bash", "script execution", "scripting"],
    "T1071": ["c2", "command and control", "c&c", "beacon", "callback"],
    "T1486": ["ransomware", "encrypt", "ransom", "data encrypted"],
    "T1027": ["obfuscated", "packed", "encoded payload", "obfuscation"],
    "T1078": ["valid accounts", "credential", "stolen credentials", "compromised account"],
    "T1055": ["process injection", "dll injection", "code injection", "hollowing"],
    "T1105": ["remote file copy", "download", "staged payload", "ingress tool transfer"],
    "T1053": ["scheduled task", "cron", "at job", "task scheduler"],
    "T1547": ["boot", "autostart", "persistence", "registry run key", "startup"],
    "T1021": ["rdp", "remote desktop", "ssh brute", "lateral movement", "remote service"],
    "T1110": ["brute force", "password spray", "credential stuffing"],
    "T1003": ["credential dump", "lsass", "mimikatz", "hashdump", "ntds"],
    "T1048": ["exfiltration", "data exfil", "data theft", "data leak"],
    "T1098": ["account manipulation", "add account", "permission change"],
    "T1569": ["service execution", "system service", "sc start"],
    "T1574": ["dll hijack", "dylib hijack", "path interception"],
    "T1562": ["disable security", "tamper protection", "defense evasion", "disable av"],
    "T1070": ["indicator removal", "log deletion", "clear logs", "timestomp"],
    "T1218": ["signed binary", "mshta", "rundll32", "regsvr32", "living off the land", "lolbin"],
    "T1583": ["infrastructure", "domain registration", "vps", "acquire infrastructure"],
    "T1595": ["scanning", "reconnaissance", "active scanning", "port scan"],
    "T1592": ["gather victim info", "target profiling", "victim host"],
}


def infer_mitre_techniques(text: str) -> List[str]:
    """Infer MITRE ATT&CK techniques from advisory text using keyword matching."""
    if not text:
        return []
    text_lower = text.lower()
    techniques = []
    for technique_id, keywords in MITRE_KEYWORD_MAP.items():
        for keyword in keywords:
            if keyword in text_lower:
                techniques.append(technique_id)
                break
    return list(set(techniques))


# ---------------------------------------------------------------------------
# Threat Category Classification
# ---------------------------------------------------------------------------

# Training data for threat category classifier
TRAINING_DATA: List[Tuple[str, str]] = [
    # Vulnerability
    ("critical vulnerability allows remote code execution", "vulnerability"),
    ("CVE security patch buffer overflow", "vulnerability"),
    ("zero-day exploit discovered in web server", "vulnerability"),
    ("privilege escalation vulnerability kernel", "vulnerability"),
    ("SQL injection flaw in enterprise application", "vulnerability"),
    ("cross-site scripting XSS vulnerability", "vulnerability"),
    ("authentication bypass security advisory", "vulnerability"),
    ("memory corruption vulnerability crash", "vulnerability"),
    ("unpatched software remote execution flaw", "vulnerability"),
    ("deserialization vulnerability code execution", "vulnerability"),

    # Malware
    ("new ransomware strain encrypts files demands bitcoin", "malware"),
    ("trojan horse backdoor remote access malware", "malware"),
    ("banking malware steals financial credentials", "malware"),
    ("botnet command control infrastructure discovered", "malware"),
    ("infostealer malware targets browser passwords", "malware"),
    ("wiper malware destroys data systems", "malware"),
    ("cryptominer malware hijacks CPU resources", "malware"),
    ("loader malware delivers secondary payload", "malware"),
    ("spyware surveillance keylogger monitoring", "malware"),
    ("rootkit persistence kernel level access", "malware"),

    # Campaign
    ("APT group launches targeted attack campaign", "campaign"),
    ("nation-state actor targets critical infrastructure", "campaign"),
    ("phishing campaign impersonates major brand", "campaign"),
    ("supply chain attack compromises software vendor", "campaign"),
    ("espionage campaign targets defense sector", "campaign"),
    ("threat actor group conducts multi-stage attack", "campaign"),
    ("coordinated attack targets financial institutions", "campaign"),
    ("watering hole attack targets specific industry", "campaign"),
    ("influence operation disinformation campaign", "campaign"),
    ("cyber espionage group targets government agencies", "campaign"),

    # Generic threat report
    ("security advisory general recommendation patch", "threat-report"),
    ("threat landscape overview trends analysis", "threat-report"),
    ("best practices security hardening guide", "threat-report"),
    ("industry report cybersecurity statistics", "threat-report"),
    ("compliance regulatory update security standard", "threat-report"),
]


class ThreatClassifier:
    """
    ML-powered threat classifier.
    Uses TF-IDF + SGDClassifier for fast inference.
    Falls back to rule-based when sklearn unavailable.
    """

    def __init__(self):
        self._model = None
        self._is_trained = False

        if _ML_AVAILABLE:
            self._build_model()

    def _build_model(self) -> None:
        """Train the classifier on built-in training data."""
        if not _ML_AVAILABLE:
            return

        texts = [t[0] for t in TRAINING_DATA]
        labels = [t[1] for t in TRAINING_DATA]

        self._model = Pipeline([
            ("tfidf", TfidfVectorizer(
                max_features=5000,
                ngram_range=(1, 2),
                stop_words="english",
                sublinear_tf=True,
            )),
            ("clf", SGDClassifier(
                loss="modified_huber",  # Gives probability estimates
                max_iter=1000,
                random_state=42,
                class_weight="balanced",
            )),
        ])

        self._model.fit(texts, labels)
        self._is_trained = True
        logger.info("Threat classifier trained on built-in dataset")

    def classify(self, advisory: Advisory) -> Tuple[str, float]:
        """
        Classify an advisory into a threat category.
        Returns (category, confidence).
        """
        text = f"{advisory.title} {advisory.summary}".strip()

        if self._is_trained and self._model is not None:
            try:
                probs = self._model.predict_proba([text])[0]
                classes = self._model.classes_
                max_idx = int(np.argmax(probs))
                category = classes[max_idx]
                confidence = float(probs[max_idx])
                return category, confidence
            except Exception as e:
                logger.warning(f"ML classification failed, using rules: {e}")

        # Rule-based fallback
        return self._rule_based_classify(text, advisory)

    def _rule_based_classify(
        self, text: str, advisory: Advisory
    ) -> Tuple[str, float]:
        """Rule-based classification fallback."""
        text_lower = text.lower()

        # CVE presence strongly indicates vulnerability
        if advisory.cves:
            return "vulnerability", 0.85

        # Keyword matching
        vuln_kw = ["vulnerability", "cve-", "patch", "exploit", "buffer overflow",
                    "rce", "privilege escalation", "injection", "bypass"]
        malware_kw = ["malware", "ransomware", "trojan", "botnet", "backdoor",
                      "wiper", "infostealer", "cryptominer", "spyware", "rootkit"]
        campaign_kw = ["apt", "campaign", "threat actor", "nation-state",
                       "supply chain", "espionage", "targeted attack", "threat group"]

        scores = {
            "vulnerability": sum(1 for kw in vuln_kw if kw in text_lower),
            "malware": sum(1 for kw in malware_kw if kw in text_lower),
            "campaign": sum(1 for kw in campaign_kw if kw in text_lower),
        }

        if max(scores.values()) == 0:
            return "threat-report", 0.40

        best = max(scores, key=scores.get)
        confidence = min(scores[best] / 5.0, 0.90)
        return best, confidence

    def classify_batch(self, advisories: List[Advisory]) -> List[Advisory]:
        """Classify all advisories in batch."""
        for adv in advisories:
            category, conf = self.classify(adv)
            adv.ai_classification = category
            # Map to ThreatType enum
            type_map = {
                "vulnerability": ThreatType.VULNERABILITY,
                "malware": ThreatType.MALWARE,
                "campaign": ThreatType.CAMPAIGN,
                "threat-report": ThreatType.GENERIC,
            }
            adv.threat_type = type_map.get(category, ThreatType.GENERIC)

            # Infer MITRE techniques if not already populated
            if not adv.mitre_techniques:
                text = f"{adv.title} {adv.summary}"
                adv.mitre_techniques = infer_mitre_techniques(text)

        logger.info(f"Classified {len(advisories)} advisories")
        return advisories
