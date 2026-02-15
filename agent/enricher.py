#!/usr/bin/env python3
"""
enricher.py — CyberDudeBivash v10.1 (APEX PREDATOR)
Forensic Extraction: Google Group URI Patterns & Malware Artifacts.
"""
import re

class IntelligenceEnricher:
    def __init__(self):
        # Professional patterns for world-class triage
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        self.cve_pattern = r'CVE-\d{4}-\d{4,}'
        
        # v10.1 APEX Patterns: Google Groups & Ninja Browser
        self.google_group_pattern = r'googlegroups\.com/g/u/[\w-]+'
        self.malware_file_pattern = r'[a-zA-Z0-9_-]+\.(?:exe|dll|zip|iso)'
        self.registry_pattern = r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[\w-]+'

    def extract_iocs(self, text):
        """Extracts standard and campaign-specific indicators."""
        results = {
            'ipv4': list(set(re.findall(self.ip_pattern, text))),
            'domain': list(set(re.findall(self.domain_pattern, text))),
            'cve': list(set(re.findall(self.cve_pattern, text))),
            'google_groups': list(set(re.findall(self.google_group_pattern, text))),
            'artifacts': list(set(re.findall(self.malware_file_pattern, text)))
        }
        
        # Logic to append discovered Google Group paths to the domain list for the IOC table
        if results['google_groups']:
            results['domain'].extend(results['google_groups'])
            
        return results

    def extract_cve(self, text):
        """Specifically extracts the primary vulnerability ID."""
        match = re.search(self.cve_pattern, text)
        return match.group(0) if match else None

enricher = IntelligenceEnricher()
