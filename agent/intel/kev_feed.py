"""
CISA Known Exploited Vulnerabilities (KEV) Feed Ingestion
FINAL • PRODUCTION • INTERFACE-HARDENED

This module provides a stable and resilient interface
for consuming the CISA KEV catalog across the platform.

It guarantees that all expected function names remain
available to prevent pipeline breakage.
"""

import requests
from typing import List, Dict

# Official CISA KEV feed
CISA_KEV_URL = (
    "https://www.cisa.gov/sites/default/files/feeds/"
    "known_exploited_vulnerabilities.json"
)


# =================================================
# INTERNAL FETCHER
# =================================================

def _fetch_kev_data() -> List[Dict]:
    """
    Fetch raw KEV vulnerability data from CISA.

    Raises:
        requests.RequestException on network / HTTP failure
    """
    response = requests.get(CISA_KEV_URL, timeout=30)
    response.raise_for_status()

    payload = response.json()
    return payload.get("vulnerabilities", [])


# =================================================
# PRIMARY PUBLIC API (MANDATORY)
# =================================================

def fetch_kev_catalog() -> List[Dict]:
    """
    Fetch the CISA Known Exploited Vulnerabilities catalog.

    This is the PRIMARY function expected by all orchestrators.
    It MUST remain stable.
    """
    try:
        return _fetch_kev_data()
    except Exception as exc:
        print(f"⚠️ KEV feed unavailable: {exc}")
        return []


# =================================================
# BACKWARD-COMPATIBILITY ALIASES
# =================================================
# These aliases ensure that older imports never break,
# even if naming conventions change elsewhere.
# =================================================

def fetch_kev_feed() -> List[Dict]:
    """
    Backward-compatible alias.
    """
    return fetch_kev_catalog()


def get_kev_catalog() -> List[Dict]:
    """
    Backward-compatible alias.
    """
    return fetch_kev_catalog()
