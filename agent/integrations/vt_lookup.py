#!/usr/bin/env python3
"""
vt_lookup.py — CyberDudeBivash v1.0
Reputation Engine: VirusTotal Detection Scoring.
"""
import os
import logging
import requests
from typing import Dict

logger = logging.getLogger("CDB-VT-LOOKUP")

class VirusTotalLookup:
    def __init__(self):
        # Fetched from GitHub Secrets
        self.api_key = os.getenv("VT_API_KEY", "").strip()
        self.base_url = "https://www.virustotal.com/api/v3/"

    def get_reputation(self, ioc: str, ioc_type: str) -> str:
        """Retrieves detection counts for IPs or Hashes."""
        if not self.api_key:
            return "No Key"

        # Determine endpoint based on IoC type
        endpoint = "ip_addresses" if ioc_type == "ipv4" else "files" if "sha" in ioc_type or "md5" in ioc_type else None
        if not endpoint:
            return "-"

        headers = {"x-apikey": self.api_key}
        try:
            response = requests.get(f"{self.base_url}{endpoint}/{ioc}", headers=headers, timeout=10)
            if response.status_code == 200:
                stats = response.json().get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
                malicious = stats.get("malicious", 0)
                total = sum(stats.values())
                return f"{malicious}/{total} Flags"
            return "0 detections"
        except Exception as e:
            logger.error(f"VT Lookup failed for {ioc}: {e}")
            return "Error"

# Global Instance
vt_lookup = VirusTotalLookup()