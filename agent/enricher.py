#!/usr/bin/env python3
"""
enricher.py — CyberDudeBivash v10.1 (APEX ELITE)
Forensic Extraction Engine: High-Fidelity Pattern Matching for GOC Standards.
"""
import re
import logging

# Institutional Branding for GOC Logs
logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-ENRICHER] %(message)s")
logger = logging.getLogger("CDB-ENRICHER")

class IntelligenceEnricher:
    def __init__(self):
        # --- Core Forensic Indicators ---
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        self.cve_pattern = r'CVE-\d{4}-\d{4,}'
        
        # --- v10.1 Specialized Extraction Nodes ---
        # Targets specialized Google Group URI structures (/g/u/ paths)
        self.google_group_pattern = r'googlegroups\.com/g/u/[\w-]+'
        
        # Targets malware artifacts mentioned in CTM360/Lumma reports
        self.malware_file_pattern = r'[a-zA-Z0-9_-]+\.(?:exe|dll|zip|iso|bin)'
        
        # Targets Windows Registry persistence keys (HKCU/HKLM)
        self.registry_pattern = r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[\w-]+'

    def extract_iocs(self, text):
        """
        Performs multi-layered forensic extraction to populate CTIF v1.0 reports.
        """
        if not text:
            logger.warning("No input text received for enrichment.")
            return {'ipv4': [], 'domain': [], 'cve': [], 'google_groups': [], 'artifacts': [], 'registry_keys': []}

        # Step 1: Sanitize input by stripping HTML tags to prevent regex bypass
        clean_text = re.sub(r'<[^<]+?>', ' ', text)

        # Step 2: Deduplicate results using set logic for professional reporting
        results = {
            'ipv4': sorted(list(set(re.findall(self.ip_pattern, clean_text)))),
            'domain': sorted(list(set(re.findall(self.domain_pattern, clean_text)))),
            'cve': sorted(list(set(re.findall(self.cve_pattern, clean_text, re.IGNORECASE)))),
            'google_groups': sorted(list(set(re.findall(self.google_group_pattern, clean_text, re.IGNORECASE)))),
            'artifacts': sorted(list(set(re.findall(self.malware_file_pattern, clean_text, re.IGNORECASE)))),
            'registry_keys': sorted(list(set(re.findall(self.registry_pattern, clean_text, re.IGNORECASE))))
        }
        
        # Step 3: Pivot promotion logic
        # Ensure campaign-specific Google Groups appear in the primary Domain table for SOC visibility
        if results['google_groups']:
            logger.info(f"Extracted {len(results['google_groups'])} campaign-specific URI patterns.")
            results['domain'].extend(results['google_groups'])
            
        return results

# Static instance for global platform use
enricher = IntelligenceEnricher()
