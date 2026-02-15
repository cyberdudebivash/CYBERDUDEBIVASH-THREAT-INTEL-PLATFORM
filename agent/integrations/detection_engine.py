#!/usr/bin/env python3
"""
detection_engine.py — CyberDudeBivash v8.2
Signature Generation: Automated Sigma and YARA Rule Synthesis.
"""
import yaml

class DetectionEngine:
    def generate_sigma_rule(self, title, iocs):
        """Generates a SIEM-agnostic Sigma rule for network detection."""
        domains = iocs.get('domain', [])
        rule = {
            'title': f'CDB-Sentinel: {title}',
            'logsource': {'category': 'dns'},
            'detection': {
                'selection': {'query': domains},
                'condition': 'selection'
            },
            'falsepositives': ['Internal legitimate traffic'],
            'level': 'high'
        }
        return yaml.dump(rule, default_flow_style=False)

    def generate_yara_rule(self, title, iocs):
        """Generates a YARA rule for memory or disk forensics."""
        ips = iocs.get('ipv4', [])
        rule_name = title.replace(" ", "_").replace("-", "_")[:30]
        yara = f"rule CDB_{rule_name} {{\n"
        yara += "    meta:\n        author = \"CyberDudeBivash GOC\"\n"
        yara += "    strings:\n"
        for i, ip in enumerate(ips[:5]):
            yara += f"        $s{i} = \"{ip}\" ascii wide\n"
        yara += "    condition:\n        any of them\n}"
        return yara

detection_engine = DetectionEngine()
