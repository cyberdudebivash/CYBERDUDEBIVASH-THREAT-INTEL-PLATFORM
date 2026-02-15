import re
import logging

logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-ENRICHER] %(message)s")
logger = logging.getLogger("CDB-ENRICHER")

class IntelligenceEnricher:
    def __init__(self):
        # Tactical Patterns for UNC-CDB-99
        self.ip_pattern = r'\b(?:\d{1,3}\.){3}\d{1,3}\b'
        self.domain_pattern = r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}\b'
        self.google_group_pattern = r'googlegroups\.com/g/u/[\w-]+'
        self.registry_pattern = r'HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run\\[\w-]+'
        self.artifacts = r'[a-zA-Z0-9_-]+\.(?:exe|dll|zip|iso|bin)'

    def extract_iocs(self, text):
        if not text: return {'ipv4': [], 'domain': [], 'registry': [], 'artifacts': []}
        
        # Strip HTML to reveal obfuscated indicators
        clean_text = re.sub(r'<[^<]+?>', ' ', text)
        
        results = {
            'ipv4': sorted(list(set(re.findall(self.ip_pattern, clean_text)))),
            'domain': sorted(list(set(re.findall(self.domain_pattern, clean_text)))),
            'registry': sorted(list(set(re.findall(self.registry_pattern, clean_text)))),
            'artifacts': sorted(list(set(re.findall(self.artifacts, clean_text, re.IGNORECASE))))
        }
        
        # Promote Google Group URIs to domain list for SOC visibility
        google_uris = re.findall(self.google_group_pattern, clean_text, re.IGNORECASE)
        results['domain'].extend(list(set(google_uris)))
            
        return results

enricher = IntelligenceEnricher()
