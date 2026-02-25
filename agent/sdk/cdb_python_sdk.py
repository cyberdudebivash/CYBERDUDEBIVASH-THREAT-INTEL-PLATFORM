#!/usr/bin/env python3
"""
cdb_python_sdk.py — CYBERDUDEBIVASH® SENTINEL APEX v24.0
Official Python SDK for the CDB Threat Intelligence Platform API.

Non-Breaking Addition: Standalone SDK module.
Does NOT modify any existing platform modules.

Install:
    pip install requests

Usage:
    from agent.sdk.cdb_python_sdk import CDBClient

    # Free tier
    client = CDBClient()
    threats = client.get_threats()

    # PRO tier
    client = CDBClient(api_key="cdb-pro-your-key")
    iocs = client.get_iocs(limit=100)

    # Enterprise tier
    client = CDBClient(api_key="cdb-ent-your-key")
    actors = client.get_actors()
    stix = client.get_stix_bundle("bundle--abc123")

Author: CyberDudeBivash Pvt. Ltd.
Platform: https://intel.cyberdudebivash.com
Docs: https://api.cyberdudebivash.com/docs
"""

import json
import time
import logging
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone

try:
    import requests
    _REQUESTS_AVAILABLE = True
except ImportError:
    _REQUESTS_AVAILABLE = False

logger = logging.getLogger("CDB-SDK")

# ──────────────────────────────────────────────
# SDK Constants
# ──────────────────────────────────────────────
SDK_VERSION       = "1.0.0"
DEFAULT_BASE_URL  = "https://api.cyberdudebivash.com"
DEFAULT_TIMEOUT   = 30
DEFAULT_MAX_RETRY = 3
DEFAULT_RETRY_BACKOFF = 2  # seconds


class CDBAPIError(Exception):
    """Raised when the CDB API returns an error response."""
    def __init__(self, status_code: int, message: str, detail: Any = None):
        self.status_code = status_code
        self.message     = message
        self.detail      = detail
        super().__init__(f"CDB API Error [{status_code}]: {message}")


class CDBAuthError(CDBAPIError):
    """Raised on authentication / tier access errors."""
    pass


class CDBRateLimitError(CDBAPIError):
    """Raised when rate limit is exceeded."""
    pass


class CDBClient:
    """
    Official Python client for the CYBERDUDEBIVASH SENTINEL APEX API.

    Tier Access:
        FREE       — No API key required. 60 req/min. Latest 10 threats.
        PRO        — API key (cdb-pro-xxx). 300 req/min. Full IOC + detection feed.
        ENTERPRISE — API key (cdb-ent-xxx). 1000 req/min. Full intelligence + STIX + actors.

    Get API Key: https://cyberdudebivash.gumroad.com
    """

    def __init__(
        self,
        api_key: Optional[str] = None,
        base_url: str = DEFAULT_BASE_URL,
        timeout: int = DEFAULT_TIMEOUT,
        max_retries: int = DEFAULT_MAX_RETRY,
        auto_retry: bool = True,
        verbose: bool = False,
    ):
        if not _REQUESTS_AVAILABLE:
            raise ImportError(
                "requests library required. Run: pip install requests"
            )

        self.api_key     = api_key
        self.base_url    = base_url.rstrip("/")
        self.timeout     = timeout
        self.max_retries = max_retries
        self.auto_retry  = auto_retry
        self._jwt_token  = None
        self._jwt_expiry = 0

        if verbose:
            logging.basicConfig(level=logging.DEBUG)

        logger.debug(f"CDB SDK v{SDK_VERSION} initialized. Base URL: {self.base_url}")

    # ──────────────────────────────────────────
    # Internal HTTP layer
    # ──────────────────────────────────────────

    def _headers(self) -> Dict[str, str]:
        """Build request headers with auth."""
        headers = {
            "User-Agent":       f"CDB-Python-SDK/{SDK_VERSION}",
            "Accept":           "application/json",
            "X-SDK-Version":    SDK_VERSION,
        }
        if self.api_key:
            headers["X-CDB-API-Key"] = self.api_key
        if self._jwt_token and time.time() < self._jwt_expiry:
            headers["Authorization"] = f"Bearer {self._jwt_token}"
        return headers

    def _request(
        self,
        method: str,
        path: str,
        params: Optional[Dict] = None,
        json_body: Optional[Dict] = None,
    ) -> Any:
        """Execute HTTP request with retry logic."""
        url = f"{self.base_url}{path}"
        last_error = None

        for attempt in range(self.max_retries):
            try:
                response = requests.request(
                    method,
                    url,
                    headers=self._headers(),
                    params=params,
                    json=json_body,
                    timeout=self.timeout,
                )

                if response.status_code == 429:
                    retry_after = int(response.headers.get("Retry-After", 60))
                    if self.auto_retry and attempt < self.max_retries - 1:
                        logger.warning(f"Rate limited. Retrying in {retry_after}s...")
                        time.sleep(retry_after)
                        continue
                    raise CDBRateLimitError(
                        429, "Rate limit exceeded", response.json()
                    )

                if response.status_code == 401:
                    raise CDBAuthError(401, "Unauthorized. Check your API key.", response.json())

                if response.status_code == 403:
                    detail = response.json()
                    raise CDBAuthError(
                        403,
                        f"Insufficient tier. {detail.get('message', '')} "
                        f"Upgrade: {detail.get('upgrade_url', 'cyberdudebivash.gumroad.com')}",
                        detail,
                    )

                if response.status_code == 404:
                    raise CDBAPIError(404, "Resource not found.", response.json())

                if response.status_code >= 500:
                    if self.auto_retry and attempt < self.max_retries - 1:
                        wait = DEFAULT_RETRY_BACKOFF ** attempt
                        logger.warning(f"Server error {response.status_code}. Retrying in {wait}s...")
                        time.sleep(wait)
                        continue
                    raise CDBAPIError(response.status_code, "Server error", response.text)

                response.raise_for_status()
                return response.json()

            except (requests.ConnectionError, requests.Timeout) as e:
                last_error = e
                if attempt < self.max_retries - 1:
                    wait = DEFAULT_RETRY_BACKOFF ** attempt
                    logger.warning(f"Connection error: {e}. Retrying in {wait}s...")
                    time.sleep(wait)

        raise CDBAPIError(0, f"Max retries exceeded: {last_error}")

    # ──────────────────────────────────────────
    # Authentication
    # ──────────────────────────────────────────

    def authenticate(self) -> Dict:
        """
        Exchange API key for a 24hr JWT token.
        Automatically used for subsequent requests.

        Returns:
            dict: {access_token, tier, identity, expires_in_seconds}
        """
        result = self._request("POST", "/api/v1/auth/token")
        self._jwt_token  = result.get("access_token")
        self._jwt_expiry = time.time() + result.get("expires_in_seconds", 86400) - 60
        logger.info(f"Authenticated. Tier: {result.get('tier')}. Token valid 24hr.")
        return result

    # ──────────────────────────────────────────
    # Free Tier Endpoints
    # ──────────────────────────────────────────

    def health(self) -> Dict:
        """Platform health check (FREE). Returns operational status."""
        return self._request("GET", "/api/v1/health")

    def stats(self) -> Dict:
        """Platform statistics (FREE). Returns advisory counts, KEV stats, avg EPSS."""
        return self._request("GET", "/api/v1/stats")

    def get_threats(self) -> Dict:
        """
        Latest 10 threat advisories — FREE tier.
        IOC details stripped. Use PRO/ENTERPRISE for full data.
        """
        return self._request("GET", "/api/v1/threats")

    def get_feed(self) -> Dict:
        """Public threat feed manifest (FREE)."""
        return self._request("GET", "/api/v1/feed")

    def get_threat(self, threat_id: str) -> Dict:
        """
        Single threat summary by ID (FREE).

        Args:
            threat_id: Threat/bundle ID from the manifest.
        """
        return self._request("GET", f"/api/v1/threat/{threat_id}")

    # ──────────────────────────────────────────
    # PRO Tier Endpoints
    # ──────────────────────────────────────────

    def get_full_threats(self, limit: int = 50) -> Dict:
        """
        Full threat list with extended metadata (PRO tier).
        Includes: severity, TLP, MITRE, actor, CVSS/EPSS.

        Args:
            limit: Max threats to return (up to 100).

        Requires: PRO API key
        """
        return self._request("GET", "/api/v1/pro/threats", params={"limit": limit})

    def get_iocs(self, limit: int = 50) -> Dict:
        """
        IOC export feed — IPs, domains, hashes, URLs, CVEs (PRO tier).
        Ready for SIEM ingestion.

        Args:
            limit: Max IOCs to return (up to 200).

        Requires: PRO API key
        """
        return self._request("GET", "/api/v1/pro/iocs", params={"limit": limit})

    def get_detections(self) -> Dict:
        """
        Detection rules feed — Sigma, YARA, KQL, SPL, Suricata (PRO tier).
        Ready for direct SIEM/EDR import.

        Requires: PRO API key
        """
        return self._request("GET", "/api/v1/pro/detections")

    # ──────────────────────────────────────────
    # Enterprise Tier Endpoints
    # ──────────────────────────────────────────

    def get_enterprise_threats(self, limit: int = 100, include_archived: bool = False) -> Dict:
        """
        Full threat intelligence with complete IOC details (ENTERPRISE tier).

        Args:
            limit: Max threats (up to 500).
            include_archived: Include archived threats.

        Requires: ENTERPRISE API key
        """
        return self._request(
            "GET", "/api/v1/enterprise/threats",
            params={"limit": limit, "include_archived": include_archived}
        )

    def get_stix_bundle(self, bundle_id: str) -> Dict:
        """
        Full STIX 2.1 bundle by ID (ENTERPRISE tier).

        Args:
            bundle_id: STIX bundle ID (e.g., 'bundle--abc123').

        Requires: ENTERPRISE API key
        """
        return self._request("GET", f"/api/v1/enterprise/stix/{bundle_id}")

    def get_actors(self) -> Dict:
        """
        Actor intelligence registry — APT groups, nation-state actors (ENTERPRISE tier).

        Requires: ENTERPRISE API key
        """
        return self._request("GET", "/api/v1/enterprise/actors")

    def get_campaigns(self) -> Dict:
        """
        Active threat campaign tracking with IOC clusters (ENTERPRISE tier).

        Requires: ENTERPRISE API key
        """
        return self._request("GET", "/api/v1/enterprise/campaigns")

    def get_exploit_forecast(self, threat_id: str) -> Dict:
        """
        Exploit probability forecast for a threat (ENTERPRISE tier).

        Args:
            threat_id: Threat ID to forecast.

        Requires: ENTERPRISE API key
        """
        return self._request("GET", f"/api/v1/enterprise/forecast/{threat_id}")

    def get_batch_forecast(self, threat_ids: List[str]) -> Dict:
        """
        Batch exploit probability forecasting (ENTERPRISE tier).

        Args:
            threat_ids: List of threat IDs.

        Requires: ENTERPRISE API key
        """
        return self._request(
            "POST", "/api/v1/enterprise/forecast/batch",
            json_body={"threat_ids": threat_ids}
        )

    def get_metrics(self) -> Dict:
        """
        Platform telemetry metrics (ENTERPRISE tier).

        Requires: ENTERPRISE API key
        """
        return self._request("GET", "/api/v1/enterprise/metrics")

    def search_threats(
        self,
        query: str = "",
        severity: Optional[str] = None,
        actor: Optional[str] = None,
        cve: Optional[str] = None,
        mitre: Optional[str] = None,
        tlp: Optional[str] = None,
    ) -> Dict:
        """
        Full-text + filtered threat search (ENTERPRISE tier).

        Args:
            query:    Free-text search query.
            severity: Filter by severity (CRITICAL/HIGH/MEDIUM/LOW).
            actor:    Filter by threat actor name.
            cve:      Filter by CVE ID.
            mitre:    Filter by MITRE technique ID.
            tlp:      Filter by TLP classification.

        Requires: ENTERPRISE API key
        """
        body = {"query": query}
        if severity: body["severity"] = severity
        if actor:    body["actor"]    = actor
        if cve:      body["cve"]      = cve
        if mitre:    body["mitre"]    = mitre
        if tlp:      body["tlp"]      = tlp

        return self._request("POST", "/api/v1/enterprise/search", json_body=body)

    def get_supply_chain_intel(self) -> Dict:
        """
        Supply chain attack intelligence feed (ENTERPRISE tier).

        Requires: ENTERPRISE API key
        """
        return self._request("GET", "/api/v1/enterprise/supply-chain")

    def get_epss_enrichment(self, cve_ids: List[str]) -> Dict:
        """
        Bulk EPSS score enrichment for CVE IDs (ENTERPRISE tier).

        Args:
            cve_ids: List of CVE IDs (e.g., ['CVE-2024-1234', 'CVE-2024-5678']).

        Requires: ENTERPRISE API key
        """
        cve_str = ",".join(cve_ids)
        return self._request("GET", "/api/v1/enterprise/epss", params={"cve_ids": cve_str})

    def get_risk_trend(self, window_hours: int = 168) -> Dict:
        """
        Risk trend analytics over a rolling window (ENTERPRISE tier).

        Args:
            window_hours: Analysis window in hours (default: 168 = 7 days, max: 720).

        Requires: ENTERPRISE API key
        """
        return self._request(
            "GET", "/api/v1/enterprise/risk-trend",
            params={"window_hours": window_hours}
        )

    # ──────────────────────────────────────────
    # TAXII 2.1
    # ──────────────────────────────────────────

    def get_taxii_collections(self) -> Dict:
        """TAXII 2.1 collection listing (FREE)."""
        return self._request("GET", "/api/v1/taxii/collections")

    def get_taxii_objects(self, collection_id: str, limit: int = 20) -> Dict:
        """
        TAXII 2.1 object fetch (ENTERPRISE tier).

        Args:
            collection_id: TAXII collection ID.
            limit:         Max objects to return.

        Requires: ENTERPRISE API key
        """
        return self._request(
            "GET", f"/api/v1/taxii/collections/{collection_id}/objects",
            params={"limit": limit}
        )

    # ──────────────────────────────────────────
    # Convenience / Helper Methods
    # ──────────────────────────────────────────

    def get_critical_threats(self, limit: int = 20) -> List[Dict]:
        """
        Shortcut: Get CRITICAL severity threats only (ENTERPRISE tier).

        Args:
            limit: Max threats to return.
        """
        result = self.search_threats(severity="CRITICAL")
        data   = result.get("data", result.get("threats", []))
        return data[:limit]

    def get_iocs_by_type(self, ioc_type: str, limit: int = 100) -> List[Dict]:
        """
        Shortcut: Get IOCs filtered by type (PRO tier).

        Args:
            ioc_type: IOC type (ipv4, domain, url, sha256, sha1, md5, email, cve, registry).
            limit:    Max IOCs to return.
        """
        result = self.get_iocs(limit=limit)
        iocs   = result.get("data", result.get("iocs", []))
        return [i for i in iocs if i.get("type", "").lower() == ioc_type.lower()]

    def export_iocs_to_json(self, filepath: str, limit: int = 200) -> str:
        """
        Export IOC feed to a JSON file (PRO tier).

        Args:
            filepath: Output file path.
            limit:    Max IOCs to export.

        Returns:
            filepath of written file.
        """
        ioc_data = self.get_iocs(limit=limit)
        with open(filepath, "w") as f:
            json.dump(ioc_data, f, indent=2)
        logger.info(f"IOC feed exported to {filepath}")
        return filepath

    def export_stix_bundle(self, bundle_id: str, filepath: str) -> str:
        """
        Export a STIX 2.1 bundle to a JSON file (ENTERPRISE tier).

        Args:
            bundle_id: STIX bundle ID.
            filepath:  Output file path.

        Returns:
            filepath of written file.
        """
        bundle = self.get_stix_bundle(bundle_id)
        with open(filepath, "w") as f:
            json.dump(bundle, f, indent=2)
        logger.info(f"STIX bundle exported to {filepath}")
        return filepath

    def get_platform_summary(self) -> Dict:
        """
        Shortcut: Combine health + stats into a single platform summary (FREE).
        """
        health = self.health()
        stats  = self.stats()
        return {
            "timestamp":     datetime.now(timezone.utc).isoformat(),
            "sdk_version":   SDK_VERSION,
            "health":        health,
            "stats":         stats,
            "platform":      "CYBERDUDEBIVASH SENTINEL APEX",
            "documentation": "https://api.cyberdudebivash.com/docs",
        }

    def __repr__(self) -> str:
        tier = "FREE"
        if self.api_key:
            tier = "PRO" if self.api_key.startswith("cdb-pro-") else "ENTERPRISE"
        return f"<CDBClient tier={tier} base_url={self.base_url} sdk_version={SDK_VERSION}>"


# ──────────────────────────────────────────────────────────────────
# Quick-start CLI demo (python -m agent.sdk.cdb_python_sdk)
# ──────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import sys

    api_key = sys.argv[1] if len(sys.argv) > 1 else None

    print(f"""
╔══════════════════════════════════════════════════════════╗
║  CyberDudeBivash Python SDK v{SDK_VERSION}                       ║
║  Platform: https://intel.cyberdudebivash.com             ║
║  API Docs: https://api.cyberdudebivash.com/docs          ║
╚══════════════════════════════════════════════════════════╝
    """)

    client = CDBClient(api_key=api_key, verbose=True)
    print(f"Client: {client}\n")

    print("→ Fetching platform health...")
    try:
        h = client.health()
        print(f"   Status: {h.get('status', 'N/A')}")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n→ Fetching public stats...")
    try:
        s = client.stats()
        print(f"   Data: {json.dumps(s, indent=4)}")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n→ Fetching latest threats (FREE tier)...")
    try:
        t = client.get_threats()
        print(f"   Returned {len(t.get('data', t.get('threats', [])))} threats")
    except Exception as e:
        print(f"   Error: {e}")

    print("\n✅ SDK demo complete. Get your API key: https://cyberdudebivash.gumroad.com")
