"""
vt_lookup.py — CyberDudeBivash v1.2
Reputation Engine: VirusTotal v3 Resilience Layer.
"""
import os
import logging
import requests

logger = logging.getLogger("CDB-VT-LOOKUP")

class VirusTotalLookup:
    def __init__(self):
        # Securely pulls the key from GitHub Secrets
        self.api_key = os.getenv("VT_API_KEY", "").strip()
        self.base_url = "https://www.virustotal.com/api/v3/"

    def get_reputation(self, ioc: str, ioc_type: str) -> str:
        """Queries VT and returns a verdict string."""
        if not self.api_key:
            # Matches the warning seen in your current logs
            logger.warning("VT_API_KEY missing. Skipping reputation check.")
            return "No API Key"

        endpoint_map = {"ipv4": "ip_addresses", "sha256": "files", "md5": "files", "domain": "domains"}
        endpoint = endpoint_map.get(ioc_type)
        
        if not endpoint:
            return "N/A"

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
            logger.error(f"VT Lookup failure: {e}")
            return "Lookup Error"

vt_lookup = VirusTotalLookup()
