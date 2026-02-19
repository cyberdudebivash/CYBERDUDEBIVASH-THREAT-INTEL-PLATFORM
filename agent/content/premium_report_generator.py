#!/usr/bin/env python3
"""
enricher.py — CyberDudeBivash v16.4 (SENTINEL APEX ULTRA)
UNIFIED ENGINE: BeautifulSoup Deep-Scraping + Advanced Regex IOC Extraction.
MANDATE: Zero loss of v11.0 logic. Added v16.4 'enrich' handshake.
"""
import re
import math
import logging
import requests
from typing import Dict, List
from bs4 import BeautifulSoup

from agent.config import (
    PRIVATE_IP_RANGES, FALSE_POSITIVE_DOMAINS,
    JAVA_PACKAGE_PREFIXES, FALSE_POSITIVE_EXTENSIONS,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-ENRICHER] %(message)s")
logger = logging.getLogger("CDB-ENRICHER")

class IntelligenceEnricher:
    """Enhanced IOC extraction engine with validation and confidence scoring."""

    def __init__(self):
        # ── v11.0 Regex Patterns (PRESERVED) ──
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        self.google_group_pattern = r'googlegroups\.com/g/u/[\w-]+'
        self.registry_pattern = r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[\w-]+'
        self.artifacts = r'[a-zA-Z0-9_-]+\.(?:exe|dll|zip|iso|bin|bat|ps1|vbs|js|msi|scr|lnk|hta|cmd)'
        self.sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        self.sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        self.md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        self.url_pattern = r'https?://[^\s<>"\')\]]+(?:\.[a-zA-Z]{2,})[^\s<>"\')\]]*'
        self.email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        self.cve_pattern = r'CVE-\d{4}-\d{4,7}'
        
        # ── v16.4 Configuration (ADDED) ──
        self.headers = {
            "User-Agent": "CDB-Sentinel-Apex/16.4 (Enterprise Threat Intelligence)"
        }

    # ── Internal Validation Methods (v11.0 - ALL PRESERVED) ──
    def _is_private_ip(self, ip: str) -> bool:
        for prefix in PRIVATE_IP_RANGES:
            if ip.startswith(prefix): return True
        try:
            octets = ip.split('.')
            if len(octets) != 4: return True
            for octet in octets:
                if not 0 <= int(octet) <= 255: return True
        except (ValueError, IndexError): return True
        return False

    def _is_false_positive_domain(self, domain: str) -> bool:
        domain_lower = domain.lower()
        for fp in FALSE_POSITIVE_DOMAINS:
            if domain_lower == fp or domain_lower.endswith('.' + fp): return True
        for prefix in JAVA_PACKAGE_PREFIXES:
            if domain_lower.startswith(prefix): return True
        for ext in FALSE_POSITIVE_EXTENSIONS:
            if domain_lower.endswith(ext): return True
        parts = domain_lower.split('.')
        if len(parts) >= 2:
            tld = parts[-1]
            if tld in {'jar', 'class', 'dex', 'apk', 'so', 'exe', 'dll', 'chrome', 'test'}: return True
        return False

    def _is_false_positive_email(self, email: str) -> bool:
        email_lower = email.lower()
        if '.jar@' in email_lower or '@classes.' in email_lower: return True
        return any(email_lower.endswith(ext) for ext in ['.jar', '.dex', '.apk', '.class'])

    def _calculate_domain_entropy(self, domain: str) -> float:
        if not domain: return 0.0
        freq = {}
        for char in domain.lower(): freq[char] = freq.get(char, 0) + 1
        length = len(domain)
        entropy = -sum((count / length) * math.log2(count / length) for count in freq.values())
        return round(entropy, 3)

    # ── Core Extraction (v11.0 - PRESERVED) ──
    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        if not text: return self._empty_result()
        clean_text = re.sub(r'<[^<]+?>', ' ', text)
        raw_ips = set(re.findall(self.ip_pattern, clean_text))
        raw_domains = set(re.findall(self.domain_pattern, clean_text))
        raw_urls = set(re.findall(self.url_pattern, clean_text))

        valid_ips = sorted([ip for ip in raw_ips if not self._is_private_ip(ip)])
        valid_domains = sorted([d for d in raw_domains if not self._is_false_positive_domain(d) and len(d) > 4])
        valid_domains.extend(sorted(set(re.findall(self.google_group_pattern, clean_text, re.IGNORECASE))))

        return {
            'ipv4': valid_ips,
            'domain': sorted(list(set(valid_domains))),
            'url': sorted(list(raw_urls)),
            'sha256': sorted(list(set(re.findall(self.sha256_pattern, clean_text)))),
            'sha1': sorted(list(set(re.findall(self.sha1_pattern, clean_text)))),
            'md5': sorted(list(set(re.findall(self.md5_pattern, clean_text)))),
            'email': sorted([e for e in set(re.findall(self.email_pattern, clean_text)) if not self._is_false_positive_email(e)]),
            'cve': sorted(list(set(re.findall(self.cve_pattern, clean_text)))),
            'registry': sorted(list(set(re.findall(self.registry_pattern, clean_text)))),
            'artifacts': sorted(list(set(re.findall(self.artifacts, clean_text, re.IGNORECASE)))),
        }

    # ── v16.4 DEEP-DIVE ENRICHMENT (ADDED) ──
    def enrich(self, url: str) -> str:
        """
        Extracts full technical text from a URL using BeautifulSoup.
        This provides the context for the Premium Report Generator.
        """
        logger.info(f"🔍 ENRICHER: Investigating source: {url}")
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Noise Reduction
                for element in soup(["script", "style", "nav", "footer", "header"]):
                    element.extract()
                
                # Structured Extraction
                text = soup.get_text(separator=' ')
                lines = (line.strip() for line in text.splitlines())
                chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                clean_text = ' '.join(chunk for chunk in chunks if chunk)
                
                return clean_text[:5000] # Safe limit for API & processing
            else:
                logger.warning(f"⚠️ ENRICHER: HTTP {response.status_code}")
                return "Technical analysis pending: Source unreachable."
        except Exception as e:
            logger.error(f"✗ ENRICHER FAILURE: {e}")
            return f"Technical analysis offline: {str(e)}"

    def calculate_confidence(self, iocs: Dict[str, List[str]], actor_mapped: bool = False) -> float:
        score = 0.0
        if iocs.get('sha256'): score += 25
        if iocs.get('ipv4'): score += 15
        if iocs.get('domain'): score += 12
        if iocs.get('registry'): score += 15
        if actor_mapped: score += 10
        total_iocs = sum(len(v) for v in iocs.values())
        score += 10 if total_iocs >= 10 else 5 if total_iocs >= 5 else 0
        return min(round(score, 1), 100.0)

    def _empty_result(self) -> Dict[str, List[str]]:
        return {'ipv4': [], 'domain': [], 'url': [], 'sha256': [], 'sha1': [], 'md5': [], 'email': [], 'cve': [], 'registry': [], 'artifacts': []}

# Global Singleton (Backward Compatible)
enricher = IntelligenceEnricher()
