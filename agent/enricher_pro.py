#!/usr/bin/env python3
"""
enricher_pro.py — CyberDudeBivash v1.0
Advanced Intelligence: Geo-IP, Whois, and Infrastructure Mapping.
"""
import socket
import logging
import requests
from typing import Dict, Optional

logger = logging.getLogger("CDB-ENRICHER-PRO")

class ProEnricher:
    def __init__(self):
        # Using a public API for Geo-IP (ip-api is free for non-commercial use)
        self.geo_url = "http://ip-api.com/json/"

    def get_ip_context(self, ip: str) -> Dict[str, str]:
        """Gathers Geographic and ISP context for a specific IPv4 address."""
        try:
            response = requests.get(f"{self.geo_url}{ip}", timeout=5)
            if response.status_code == 200:
                data = response.json()
                if data.get("status") == "success":
                    return {
                        "location": f"{data.get('city')}, {data.get('country')}",
                        "isp": data.get("isp"),
                        "asn": data.get("as")
                    }
            return {"location": "Unknown", "isp": "Unknown", "asn": "Unknown"}
        except Exception as e:
            logger.error(f"Geo-IP lookup failed for {ip}: {e}")
            return {"location": "Error", "isp": "Error", "asn": "Error"}

    def get_whois_domain(self, domain: str) -> Optional[str]:
        """Resolves a domain to its IP address for basic infrastructure mapping."""
        try:
            return socket.gethostbyname(domain)
        except socket.gaierror:
            return None

# Global Instance
enricher_pro = ProEnricher()
