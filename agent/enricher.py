#!/usr/bin/env python3
"""
enricher.py — CyberDudeBivash v10.1 (APEX PREDATOR)
Final Forensic Extraction Engine: Google Groups, Ninja Browser Artifacts & URI Patterns.
"""
import re
import logging

logger = logging.getLogger("CDB-ENRICHER")

class IntelligenceEnricher:
    def __init__(self):
        # 1. Standard Enterprise Indicators
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        self.cve_pattern = r'CVE-\d{4}-\d{4,}'
        
        # 2. v10.1 Apex Specialized Patterns: Google Groups & Malware Persistence
        # Extracts specific sub-paths: googlegroups.com/g/u/[Campaign_ID]
        self.google_group_pattern = r'googlegroups\.com/g/u/[\w-]+'
        
        # Extracts malware artifacts (e.g., NinjaBrowser.exe, Lumma_Payload.zip)
        self.malware_file_pattern = r'[a-zA-Z0-9_-]+\.(?:exe|dll|zip|iso|bin)'
        
        # Extracts Registry Persistence Keys mentioned in technical reports
        self.registry_pattern = r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[\w-]+'
        
        # Extracts User-Agent strings or specific C2 URI paths
        self.c2_path_pattern = r'/[a-zA-Z0-9]{1,8}/exfil'

    def extract_iocs(self, text):
        """
        Performs multi-layered forensic extraction to populate CTIF v1.0 sections.
        """
        if not text:
            return {'ipv4': [], 'domain': [], 'cve': [], 'google_groups': [], 'artifacts': []}

        # Deduplicate results using sets
        results = {
            'ipv4': list(set(re.findall(self.ip_pattern, text))),
            'domain': list(set(re.findall(self.domain_pattern, text))),
            'cve': list(set(re.findall(self.cve_pattern, text))),
            'google_groups': list(set(re.findall(self.google_group_pattern, text, re.IGNORECASE))),
            'artifacts': list(set(re.findall(self.malware_file_pattern, text, re.IGNORECASE))),
            'registry_keys': list(set(re.findall(self.registry_pattern, text, re.IGNORECASE)))
        }
        
        # Logic: If specialized Google Group URIs are found, ensure they are promoted 
        # to the primary Domain IOC table for SOC visibility.
        if results['google_groups']:
            logger.info(f"Detected {len(results['google_groups'])} campaign-specific URI patterns.")
            results['domain'].extend(results['google_groups'])
            
        return results

    def get_primary_cve(self, text):
        """Identifies the primary exploit vector for Pillar B triage."""
        match = re.search(self.cve_pattern, text)
        return match.group(0) if match else None

# Global Instance for Orchestrator
enricher = IntelligenceEnricher()
