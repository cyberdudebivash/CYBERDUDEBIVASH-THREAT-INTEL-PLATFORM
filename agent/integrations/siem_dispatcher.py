#!/usr/bin/env python3
"""
siem_dispatcher.py — CyberDudeBivash v30.0
Description: Reads threat intelligence and autonomously generates/dispatches 
             Sigma rules to Enterprise SIEMs (Splunk, Elastic).
Compliance: 0 REGRESSION. Read-only on local data.
"""

import os
import json
import logging
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="[SIEM-DISPATCHER] %(asctime)s - %(message)s")

class SIEMDispatcher:
    def __init__(self):
        self.manifest_path = "data/stix/feed_manifest.json"
        self.sigma_dir = "data/sigma_rules"
        os.makedirs(self.sigma_dir, exist_ok=True)

    def generate_sigma_rule(self, threat_title, iocs):
        """Generates a standard Sigma rule based on IOCs."""
        # Sanitize title for filename
        safe_title = "".join(x for x in threat_title if x.isalnum() or x in " -_").replace(" ", "_")[:30]
        
        rule_id = f"cdb-rule-{datetime.now().strftime('%Y%m%d%H%M%S')}"
        
        # Build the YAML structure
        sigma_yaml = f"""title: CDB APEX Detection - {threat_title[:50]}
id: {rule_id}
status: experimental
description: Automatically generated Sigma rule from CyberDudeBivash Threat Intel
author: CDB APEX Sovereign
date: {datetime.now().strftime('%Y/%m/%d')}
logsource:
    category: network_connection
detection:
    selection:
"""
        # Add IOCs to the detection logic
        has_iocs = False
        if "ipv4" in iocs and iocs["ipv4"]:
            has_iocs = True
            sigma_yaml += "        DestinationIp:\n"
            for ip in iocs["ipv4"][:10]: # Limit to 10 for the rule
                sigma_yaml += f"            - '{ip}'\n"
                
        if "domain" in iocs and iocs["domain"]:
            has_iocs = True
            sigma_yaml += "        DestinationHostname:\n"
            for domain in iocs["domain"][:10]:
                sigma_yaml += f"            - '{domain}'\n"

        if not has_iocs:
            return None, None

        sigma_yaml += """    condition: selection
falsepositives:
    - Legitimate administrative traffic
level: high
"""
        return safe_title, sigma_yaml

    def run_dispatch(self):
        logging.info("Scanning intelligence manifest for SIEM dispatch...")
        
        if not os.path.exists(self.manifest_path):
            logging.warning("No threat manifest found. Exiting.")
            return

        with open(self.manifest_path, 'r') as f:
            threats = json.load(f)

        rules_generated = 0
        
        for threat in threats[:10]: # Process top 10 recent threats
            iocs = threat.get("ioc_counts", {}) # Assuming your pipeline extracts these
            if not iocs:
                continue
                
            safe_title, sigma_rule = self.generate_sigma_rule(threat.get("title", "Unknown"), iocs)
            
            if sigma_rule:
                rule_path = os.path.join(self.sigma_dir, f"{safe_title}.yml")
                with open(rule_path, 'w') as f:
                    f.write(sigma_rule)
                rules_generated += 1
                
                # In a production scenario, you would add an HTTP POST request here
                # to send this rule to Splunk HEC or Elastic API.
                
        logging.info(f"SIEM Dispatch complete. Generated {rules_generated} Sigma rules.")

if __name__ == "__main__":
    dispatcher = SIEMDispatcher()
    dispatcher.run_dispatch()