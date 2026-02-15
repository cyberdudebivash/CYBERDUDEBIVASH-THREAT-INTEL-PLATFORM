#!/usr/bin/env python3
"""
vt_lookup.py — CyberDudeBivash v7.5
Enterprise Enrichment: Extracts Community Comments and Analyst Tags.
"""
import os
import requests
import logging

logger = logging.getLogger("CDB-VT-LOOKUP")

class VTLookup:
    def __init__(self):
        self.api_key = os.environ.get('VT_API_KEY')
        self.base_url = "https://www.virustotal.com/api/v3"

    def get_reputation(self, observable, obs_type="ipv4"):
        """
        Enriches observables with reputation and crowdsourced analyst context.
        """
        if not self.api_key:
            return {"reputation": "Unknown", "tags": [], "comments": "API Key Missing"}

        endpoint = f"/{'ip_addresses' if obs_type == 'ipv4' else 'domains'}/{observable}"
        headers = {"x-apikey": self.api_key}

        try:
            response = requests.get(f"{self.base_url}{endpoint}", headers=headers, timeout=15)
            if response.status_code == 200:
                data = response.json().get('data', {}).get('attributes', {})
                
                # Extracting Enterprise-Grade Metadata
                stats = data.get('last_analysis_stats', {})
                tags = data.get('tags', [])
                
                # Fetching the most recent crowdsourced comment if available
                comments_resp = requests.get(f"{self.base_url}{endpoint}/comments", headers=headers, timeout=10)
                analyst_insight = "No community comments available."
                if comments_resp.status_code == 200:
                    comment_data = comments_resp.json().get('data', [])
                    if comment_data:
                        # Grab the top-voted or newest comment
                        analyst_insight = comment_data[0].get('attributes', {}).get('text', '')[:300]

                return {
                    "reputation": f"{stats.get('malicious', 0)}/90 Engines",
                    "tags": tags[:5], # Top 5 tags (e.g., 'apt', 'cobalt-strike')
                    "analyst_comments": analyst_insight,
                    "provider": "VirusTotal Intelligence"
                }
            return {"reputation": "Neutral", "tags": [], "analyst_comments": "N/A"}
        except Exception as e:
            logger.error(f"VT API Error: {e}")
            return {"reputation": "Error", "tags": [], "analyst_comments": "Lookup Failed"}

vt_lookup = VTLookup()
