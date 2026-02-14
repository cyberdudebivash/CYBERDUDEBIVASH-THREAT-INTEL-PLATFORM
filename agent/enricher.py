#!/usr/bin/env python3
"""
enricher.py — CyberDudeBivash v1.0
Automated Indicator Extraction & Intelligence Enrichment.
"""
import re
import logging
from typing import Dict, List, Set

logger = logging.getLogger("CDB-ENRICHER")

class ThreatEnricher:
    def __init__(self):
        # Professional-grade Regex Patterns for IoC extraction
        self.patterns = {
            "ipv4": r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
            "sha256": r"\b[A-Fa-f0-9]{64}\b",
            "md5": r"\b[A-Fa-f0-9]{32}\b",
            "domain": r"\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,6}\b",
            "cve": r"CVE-\d{4}-\d{4,7}"
        }

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Scans raw text and extracts unique threat indicators."""
        extracted = {}
        for ioc_type, pattern in self.patterns.items():
            # Find all matches and convert to a unique set to remove duplicates
            matches = list(set(re.findall(pattern, text, re.IGNORECASE)))
            if matches:
                extracted[ioc_type] = matches
        return extracted

    def categorize_threat(self, iocs: Dict[str, List[str]]) -> str:
        """Determines the 'Primary Vector' based on the types of IoCs found."""
        if "cve" in iocs:
            return "Vulnerability Exploitation"
        if "sha256" in iocs or "md5" in iocs:
            return "Malware Payload"
        if "ipv4" in iocs or "domain" in iocs:
            return "Command & Control (C2) / Phishing"
        return "General Intel"

# Global Instance for the Sentinel Orchestrator
enricher = ThreatEnricher()
