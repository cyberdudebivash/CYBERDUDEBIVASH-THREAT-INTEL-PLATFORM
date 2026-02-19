#!/usr/bin/env python3
"""
enricher.py — CyberDudeBivash v16.4
The "Deep-Dive Scraper": Extracts technical context from raw URLs.
"""

import logging
import requests
from bs4 import BeautifulSoup

logger = logging.getLogger("CDB-ENRICHER")

class IntelligenceEnricher:
    def __init__(self):
        self.headers = {
            "User-Agent": "CDB-Sentinel-Apex/16.4 (Enterprise Threat Intelligence)"
        }

    def enrich(self, url: str) -> str:
        """
        Standardized method for extracting full-text technical data.
        """
        logger.info(f"🔍 ENRICHER: Investigating source: {url}")
        try:
            response = requests.get(url, headers=self.headers, timeout=15)
            if response.status_code == 200:
                soup = BeautifulSoup(response.text, 'html.parser')
                
                # Remove noise (scripts, styles, ads)
                for script in soup(["script", "style", "nav", "footer", "header"]):
                    script.extract()
                
                # Extract structured text
                text = soup.get_text(separator=' ')
                lines = (line.strip() for line in text.splitlines())
                chunks = (phrase.strip() for line in lines for phrase in line.split("  "))
                clean_text = ' '.join(chunk for chunk in chunks if chunk)
                
                return clean_text[:5000] # Cap for API safety
            else:
                logger.warning(f"⚠️ ENRICHER: Source returned status {response.status_code}")
                return "Technical analysis pending: Source unreachable."
        except Exception as e:
            logger.error(f"✗ ENRICHER FAILURE: {e}")
            return "Technical analysis offline: Connection error."

# Standardized Instance
enricher = IntelligenceEnricher()
