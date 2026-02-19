#!/usr/bin/env python3
"""
enricher.py — CyberDudeBivash v11.0 (SENTINEL APEX ULTRA)
UPGRADED: SHA256/MD5 extraction, URL extraction, email extraction,
private IP exclusion, false-positive domain filtering, confidence scoring.
"""
import re
import math
import logging
from typing import Dict, List

from agent.config import (
    PRIVATE_IP_RANGES, FALSE_POSITIVE_DOMAINS,
    JAVA_PACKAGE_PREFIXES, FALSE_POSITIVE_EXTENSIONS,
)

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-ENRICHER] %(message)s")
logger = logging.getLogger("CDB-ENRICHER")


class IntelligenceEnricher:
    """Enhanced IOC extraction engine with validation and confidence scoring."""

    def __init__(self):
        # ── Regex Patterns ──
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        self.google_group_pattern = r'googlegroups\.com/g/u/[\w-]+'
        self.registry_pattern = r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[\w-]+'
        self.artifacts = r'[a-zA-Z0-9_-]+\.(?:exe|dll|zip|iso|bin|bat|ps1|vbs|js|msi|scr|lnk|hta|cmd)'
        # NEW: SHA256, MD5, SHA1
        self.sha256_pattern = r'\b[a-fA-F0-9]{64}\b'
        self.sha1_pattern = r'\b[a-fA-F0-9]{40}\b'
        self.md5_pattern = r'\b[a-fA-F0-9]{32}\b'
        # NEW: URL extraction
        self.url_pattern = r'https?://[^\s<>"\')\]]+(?:\.[a-zA-Z]{2,})[^\s<>"\')\]]*'
        # NEW: Email extraction
        self.email_pattern = r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'
        # NEW: CVE extraction
        self.cve_pattern = r'CVE-\d{4}-\d{4,7}'

    def _is_private_ip(self, ip: str) -> bool:
        """Check if IP is in private/reserved ranges."""
        for prefix in PRIVATE_IP_RANGES:
            if ip.startswith(prefix):
                return True
        # Validate each octet is 0-255
        try:
            octets = ip.split('.')
            if len(octets) != 4:
                return True
            for octet in octets:
                if not 0 <= int(octet) <= 255:
                    return True
        except (ValueError, IndexError):
            return True
        return False

    def _is_false_positive_domain(self, domain: str) -> bool:
        """Check if domain is a known false positive, Java package, or file reference."""
        domain_lower = domain.lower()
        # Standard FP domain check
        for fp in FALSE_POSITIVE_DOMAINS:
            if domain_lower == fp or domain_lower.endswith('.' + fp):
                return True
        # v15.0: Java/Android package name detection (com.android.chrome, etc.)
        for prefix in JAVA_PACKAGE_PREFIXES:
            if domain_lower.startswith(prefix):
                return True
        # v15.0: File extension false positives (classes.jar, app.dex, etc.)
        for ext in FALSE_POSITIVE_EXTENSIONS:
            if domain_lower.endswith(ext):
                return True
        # v15.0: Reject domains that look like reversed package names
        # (no real TLD would be "chrome", "systemui", "test", etc.)
        parts = domain_lower.split('.')
        if len(parts) >= 2:
            tld = parts[-1]
            NON_TLDS = {'jar', 'class', 'dex', 'apk', 'so', 'exe', 'dll',
                        'chrome', 'systemui', 'wallpaper', 'launcher',
                        'settings', 'test', 'debug', 'internal'}
            if tld in NON_TLDS:
                return True
        return False

    def _is_false_positive_email(self, email: str) -> bool:
        """v15.0: Filter false positive emails (JAR paths, test addresses)."""
        email_lower = email.lower()
        # JAR path references (vndx_10x.jar@classes.jar)
        if '.jar@' in email_lower or '@classes.' in email_lower:
            return True
        # File reference patterns
        if any(email_lower.endswith(ext) for ext in ['.jar', '.dex', '.apk', '.class']):
            return True
        return False

    def _calculate_domain_entropy(self, domain: str) -> float:
        """Calculate Shannon entropy of a domain (high entropy = suspicious)."""
        if not domain:
            return 0.0
        freq = {}
        for char in domain.lower():
            freq[char] = freq.get(char, 0) + 1
        length = len(domain)
        entropy = -sum((count / length) * math.log2(count / length)
                       for count in freq.values())
        return round(entropy, 3)

    def extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """
        Extract all IOC types from text with validation.
        Returns dict with ipv4, domain, url, sha256, sha1, md5, email,
        cve, registry, artifacts categories.
        """
        if not text:
            return self._empty_result()

        # Strip HTML to reveal obfuscated indicators
        clean_text = re.sub(r'<[^<]+?>', ' ', text)

        # ── Extract Raw IOCs ──
        raw_ips = set(re.findall(self.ip_pattern, clean_text))
        raw_domains = set(re.findall(self.domain_pattern, clean_text))
        raw_urls = set(re.findall(self.url_pattern, clean_text))

        # ── Validate & Filter ──
        valid_ips = sorted([
            ip for ip in raw_ips
            if not self._is_private_ip(ip)
        ])

        valid_domains = sorted([
            d for d in raw_domains
            if not self._is_false_positive_domain(d)
            and len(d) > 4  # Skip very short matches
        ])

        # Promote Google Group URIs for SOC visibility
        google_uris = re.findall(self.google_group_pattern, clean_text, re.IGNORECASE)
        valid_domains.extend(sorted(set(google_uris)))

        results = {
            'ipv4': valid_ips,
            'domain': sorted(list(set(valid_domains))),
            'url': sorted(list(raw_urls)),
            'sha256': sorted(list(set(re.findall(self.sha256_pattern, clean_text)))),
            'sha1': sorted(list(set(re.findall(self.sha1_pattern, clean_text)))),
            'md5': sorted(list(set(re.findall(self.md5_pattern, clean_text)))),
            'email': sorted([
                e for e in set(re.findall(self.email_pattern, clean_text))
                if not self._is_false_positive_email(e)
            ]),
            'cve': sorted(list(set(re.findall(self.cve_pattern, clean_text)))),
            'registry': sorted(list(set(re.findall(self.registry_pattern, clean_text)))),
            'artifacts': sorted(list(set(re.findall(self.artifacts, clean_text, re.IGNORECASE)))),
        }

        return results

    def calculate_confidence(self, iocs: Dict[str, List[str]],
                              actor_mapped: bool = False) -> float:
        """
        Calculate IOC confidence score (0-100%) based on indicator richness.
        Higher = more trustworthy intelligence.
        """
        score = 0.0

        # Indicator presence scoring
        if iocs.get('sha256'):
            score += 25  # File hashes = high confidence
        if iocs.get('ipv4'):
            score += 15
        if iocs.get('domain'):
            score += 12
            # Bonus for high-entropy domains (likely malicious)
            for d in iocs['domain'][:5]:
                if self._calculate_domain_entropy(d) > 3.5:
                    score += 3
        if iocs.get('url'):
            score += 10
        if iocs.get('registry'):
            score += 15  # Registry = persistence indicators
        if iocs.get('artifacts'):
            score += 10
        if iocs.get('cve'):
            score += 8
        if iocs.get('email'):
            score += 5

        # Actor attribution bonus
        if actor_mapped:
            score += 10

        # IOC volume bonus (more IOCs = more confidence)
        total_iocs = sum(len(v) for v in iocs.values())
        if total_iocs >= 10:
            score += 10
        elif total_iocs >= 5:
            score += 5

        return min(round(score, 1), 100.0)

    def get_ioc_counts(self, iocs: Dict[str, List[str]]) -> Dict[str, int]:
        """Return count of each IOC category (for manifest storage)."""
        return {k: len(v) for k, v in iocs.items()}

    def _empty_result(self) -> Dict[str, List[str]]:
        return {
            'ipv4': [], 'domain': [], 'url': [],
            'sha256': [], 'sha1': [], 'md5': [],
            'email': [], 'cve': [],
            'registry': [], 'artifacts': [],
        }


# Global singleton (backward compatible)
enricher = IntelligenceEnricher()
