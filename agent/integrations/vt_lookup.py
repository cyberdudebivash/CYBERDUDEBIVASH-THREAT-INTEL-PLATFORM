#!/usr/bin/env python3
"""
vt_lookup.py — CyberDudeBivash v1.1
Reputation Engine: VirusTotal v3 API Integration.
"""
import os
import logging
import requests
from typing import Dict

logger = logging.getLogger("CDB-VT-LOOKUP")

class VirusTotalLookup:
    def __init__(self):
        # Securely pulls the key you added to GitHub Secrets
        self.api_key = os.getenv("VT_API_KEY", "").strip()
        self.base_url = "https://www.virustotal.com/api/v3/"

    def get_reputation(self, ioc: str, ioc_type: str) -> str:
        """
        Queries VirusTotal for the reputation of an IP or File Hash.
        Returns a formatted 'Malicious/Total' string.
        """
        if not self.api_key:
            logger.warning("VT_API_KEY missing. Skipping reputation check.")
            return "No API Key"

        # Map internal types to VT v3 endpoints
        endpoint_map = {
            "ipv4": "ip_addresses",
            "sha256": "files",
            "md5": "files",
            "domain": "domains"
        }
        
        endpoint = endpoint_map.get(ioc_type)
        if not endpoint:
            return "N/A"

        headers = {"x-apikey": self.api_key}
        
        try:
            # Execute request with a 10s timeout to prevent pipeline hangs
            response = requests.get(f"{self.base_url}{endpoint}/{ioc}", headers=headers, timeout=10)
            
            if response.status_code == 200:
                data = response.json()
                stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                
                malicious = stats.get("malicious", 0)
                undetermined = stats.get("harmless", 0) + stats.get("undetected", 0)
                total = malicious + undetermined
                
                return f"{malicious}/{total} Flags"
            
            elif response.status_code == 404:
                return "0/0 (Clean/New)"
            elif response.status_code == 401:
                return "Auth Error"
            else:
                return f"Error {response.status_code}"

        except Exception as e:
            logger.error(f"VT Lookup failed for {ioc}: {e}")
            return "Lookup Error"

# Global Instance for the Sentinel Orchestrator
vt_lookup = VirusTotalLookup()
