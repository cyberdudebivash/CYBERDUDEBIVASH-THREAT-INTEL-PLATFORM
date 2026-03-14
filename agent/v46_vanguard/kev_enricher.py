#!/usr/bin/env python3
"""
kev_enricher.py — CYBERDUDEBIVASH® SENTINEL APEX v46.0 VANGUARD
CISA Known Exploited Vulnerabilities (KEV) Live Enrichment Engine

FIXES: sentinel_blogger.py _enrich_cve_metadata() always returned
       kev_present=False because the KEV feed was never queried.
       This module provides a proper implementation with:
         - In-memory catalog cache (loaded once per session)
         - CVE lookup against the full CISA KEV catalog
         - KEV metadata extraction (date_added, due_date, action, vendor, product)

ARCHITECTURE:
  - Lazy-loads the KEV catalog on first use
  - Cache TTL: 6 hours (avoids hammering CISA)
  - Graceful degradation: returns False on any network failure
  - Zero impact on non-CVE report paths

Usage:
    from agent.v46_vanguard.kev_enricher import kev_enricher
    is_kev, kev_meta = kev_enricher.lookup("CVE-2024-12345")
"""

import json
import time
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Optional, Tuple

logger = logging.getLogger("CDB-KEV-ENRICHER")

KEV_FEED_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
CACHE_TTL_SECONDS = 6 * 3600  # 6 hours


class KEVEnricher:
    """
    CISA KEV catalog lookup with session caching.
    """

    def __init__(self):
        self._catalog: Dict[str, Dict] = {}  # CVE-ID → metadata
        self._last_load: float = 0.0
        self._load_attempted: bool = False

    def _load_catalog(self) -> bool:
        """Load KEV catalog from CISA. Returns True on success."""
        now = time.time()

        # Skip if recently loaded
        if self._catalog and (now - self._last_load) < CACHE_TTL_SECONDS:
            return True

        try:
            logger.info("Loading CISA KEV catalog...")
            req = urllib.request.Request(
                KEV_FEED_URL,
                headers={"User-Agent": "CyberDudeBivash-SentinelAPEX/46.0"}
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read().decode("utf-8"))

            vulnerabilities = data.get("vulnerabilities", [])
            self._catalog = {}
            for vuln in vulnerabilities:
                cve_id = vuln.get("cveID", "").upper().strip()
                if cve_id:
                    self._catalog[cve_id] = {
                        "vendor": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "name": vuln.get("vulnerabilityName", ""),
                        "date_added": vuln.get("dateAdded", ""),
                        "due_date": vuln.get("dueDate", ""),
                        "action": vuln.get("requiredAction", ""),
                        "notes": vuln.get("notes", ""),
                        "known_ransomware": vuln.get("knownRansomwareCampaignUse", "Unknown"),
                    }

            self._last_load = now
            self._load_attempted = True
            logger.info(f"KEV catalog loaded: {len(self._catalog)} entries")
            return True

        except Exception as e:
            logger.warning(f"KEV catalog load failed (non-critical): {e}")
            self._load_attempted = True
            return False

    def lookup(self, cve_id: str) -> Tuple[bool, Dict]:
        """
        Check if a CVE is in the CISA KEV catalog.
        Returns (is_kev, metadata_dict).
        metadata_dict is empty if not found or on failure.
        """
        if not cve_id:
            return False, {}

        cve_upper = cve_id.upper().strip()

        # Load catalog if needed
        if not self._catalog:
            self._load_catalog()

        if cve_upper in self._catalog:
            meta = self._catalog[cve_upper]
            logger.info(
                f"🚨 KEV CONFIRMED: {cve_upper} — "
                f"{meta.get('vendor', '?')}/{meta.get('product', '?')} "
                f"(added: {meta.get('date_added', '?')})"
            )
            return True, meta

        return False, {}

    def lookup_batch(self, cve_ids: List[str]) -> Dict[str, Tuple[bool, Dict]]:
        """Batch lookup for multiple CVEs."""
        if not self._catalog:
            self._load_catalog()

        results = {}
        for cve_id in cve_ids:
            results[cve_id] = self.lookup(cve_id)
        return results

    @property
    def catalog_size(self) -> int:
        return len(self._catalog)

    @property
    def is_loaded(self) -> bool:
        return bool(self._catalog)


# ── Singleton ──
kev_enricher = KEVEnricher()
