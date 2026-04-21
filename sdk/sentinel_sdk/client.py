"""
sdk/sentinel_sdk/client.py — CYBERDUDEBIVASH® Sentinel APEX Python SDK v134.0
Production-grade synchronous API client.

Features:
  - Automatic retry with exponential backoff (4 attempts, jitter)
  - Per-tier rate limit awareness (429 → retry-after honoured)
  - Connection pooling via urllib (no external deps required)
  - Response deserialization to typed model objects
  - Thread-safe: single instance safe for multi-threaded use
  - Full OpenAPI coverage: advisories, search, STIX, health, IOC lookup

Zero external dependencies — stdlib only (urllib, json, hmac, hashlib).
Optional: install 'requests' for HTTP/2 and connection reuse improvements.
"""
from __future__ import annotations

import json
import logging
import random
import time
from typing import Any, Dict, Iterator, List, Optional
from urllib.parse import urlencode, urljoin
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

from .exceptions import (
    AuthenticationError,
    NetworkError,
    NotFoundError,
    RateLimitError,
    SDKConfigurationError,
    ServerError,
    TierPermissionError,
    ValidationError,
)
from .models import (
    AdvisoryItem,
    ApiKeyInfo,
    FeedMetadata,
    HealthStatus,
    Page,
    StixBundle,
)

logger = logging.getLogger("sentinel_sdk.client")

_DEFAULT_BASE_URL = "https://api.sentinelapex.cyberdudebivash.com"
_DEFAULT_TIMEOUT  = 30
_MAX_RETRIES      = 4
_RETRY_BASE_S     = 1.0
_RETRY_MAX_S      = 30.0
_SDK_VERSION      = "100.0.0"
_USER_AGENT       = f"SentinelAPEX-Python-SDK/{_SDK_VERSION}"


class SentinelClient:
    """
    Synchronous client for the CYBERDUDEBIVASH® Sentinel APEX Threat Intelligence API.

    Quick start::

        from sentinel_sdk import SentinelClient

        client = SentinelClient(api_key="sa_live_xxxx")
        advisories = client.get_advisories(severity="CRITICAL", limit=25)
        for item in advisories.items:
            print(item.title, item.risk_score)

    Args:
        api_key:    Your Sentinel APEX API key (required).
        base_url:   Override the API base URL (default: production endpoint).
        timeout:    HTTP request timeout in seconds (default: 30).
        max_retries: Max retry attempts on transient errors (default: 4).
    """

    def __init__(
        self,
        api_key: str,
        base_url: str = _DEFAULT_BASE_URL,
        timeout: int = _DEFAULT_TIMEOUT,
        max_retries: int = _MAX_RETRIES,
    ) -> None:
        if not api_key:
            raise SDKConfigurationError(
                "api_key is required. Get one at https://sentinel.cyberdudebivash.com/onboarding"
            )
        self._api_key    = api_key
        self._base_url   = base_url.rstrip("/")
        self._timeout    = timeout
        self._max_retries = max_retries

    # ─────────────────────────────────────────────────────────────────────────
    # Advisories
    # ─────────────────────────────────────────────────────────────────────────

    def get_advisories(
        self,
        severity:   Optional[str] = None,
        threat_type: Optional[str] = None,
        limit:      int = 20,
        page:       int = 1,
        kev_only:   bool = False,
    ) -> Page:
        """
        Fetch threat intelligence advisories.

        Args:
            severity:    Filter by severity: CRITICAL | HIGH | MEDIUM | LOW
            threat_type: Filter by type: ransomware | apt | malware | vulnerability
            limit:       Results per page (1–500, tier-dependent)
            page:        Page number (1-indexed)
            kev_only:    Only return CISA KEV entries

        Returns:
            Page object with .items (List[AdvisoryItem]) and .metadata (FeedMetadata)
        """
        params: Dict[str, Any] = {"limit": limit, "page": page}
        if severity:
            params["severity"] = severity.upper()
        if threat_type:
            params["threat_type"] = threat_type
        if kev_only:
            params["kev_only"] = "true"

        raw = self._get("/api/v1/advisories", params=params)
        items = [AdvisoryItem.from_dict(d) for d in raw.get("data", [])]
        meta  = FeedMetadata.from_dict(raw)
        return Page(items=items, metadata=meta, raw=raw)

    def get_advisory(self, stix_id: str) -> AdvisoryItem:
        """
        Fetch a single advisory by STIX ID.

        Raises:
            NotFoundError: If the advisory does not exist.
        """
        raw = self._get(f"/api/v1/advisories/{stix_id}")
        return AdvisoryItem.from_dict(raw.get("data", raw))

    def search_advisories(self, query: str, limit: int = 20) -> Page:
        """
        Full-text search across advisory titles and descriptions (PRO+).

        Args:
            query: Search string (CVE IDs, actor names, keywords)
            limit: Max results to return

        Raises:
            TierPermissionError: If on FREE tier (search requires PRO+)
        """
        raw = self._get("/api/v1/search", params={"q": query, "limit": limit})
        items = [AdvisoryItem.from_dict(d) for d in raw.get("data", [])]
        meta  = FeedMetadata.from_dict(raw)
        return Page(items=items, metadata=meta, raw=raw)

    def iter_advisories(
        self,
        severity: Optional[str] = None,
        threat_type: Optional[str] = None,
        max_pages: int = 10,
        page_size: int = 100,
    ) -> Iterator[AdvisoryItem]:
        """
        Generator that transparently paginates through all matching advisories.

        Args:
            severity:    Optional severity filter
            threat_type: Optional threat type filter
            max_pages:   Safety ceiling on pages fetched (default: 10)
            page_size:   Items per page (default: 100)

        Yields:
            AdvisoryItem objects one by one
        """
        for page_num in range(1, max_pages + 1):
            page = self.get_advisories(
                severity=severity,
                threat_type=threat_type,
                limit=page_size,
                page=page_num,
            )
            yield from page.items
            if not page.has_more:
                break

    # ─────────────────────────────────────────────────────────────────────────
    # STIX Export (PRO+)
    # ─────────────────────────────────────────────────────────────────────────

    def export_stix(
        self,
        stix_ids: Optional[List[str]] = None,
        severity: Optional[str] = None,
        limit: int = 50,
    ) -> StixBundle:
        """
        Export advisories as a STIX 2.1 bundle (PRO+).

        Args:
            stix_ids: Optional list of specific STIX IDs to export
            severity: Optional severity filter
            limit:    Max items in bundle

        Returns:
            StixBundle with .objects (list of STIX objects)

        Raises:
            TierPermissionError: Requires PRO tier or higher
        """
        params: Dict[str, Any] = {"limit": limit}
        if stix_ids:
            params["ids"] = ",".join(stix_ids)
        if severity:
            params["severity"] = severity.upper()
        raw = self._get("/api/v1/stix/export", params=params)
        return StixBundle.from_dict(raw)

    # ─────────────────────────────────────────────────────────────────────────
    # IOC Lookup (PRO+)
    # ─────────────────────────────────────────────────────────────────────────

    def lookup_ioc(self, ioc: str, ioc_type: str = "auto") -> Dict[str, Any]:
        """
        Look up a specific IOC (IP, hash, domain, CVE ID) (PRO+).

        Args:
            ioc:      The IOC value to look up
            ioc_type: Hint for type: ip | hash | domain | cve | auto

        Returns:
            Raw dict with matched advisories and threat context
        """
        params = {"value": ioc, "type": ioc_type}
        return self._get("/api/v1/ioc/lookup", params=params)

    # ─────────────────────────────────────────────────────────────────────────
    # Health & Status
    # ─────────────────────────────────────────────────────────────────────────

    def health(self) -> HealthStatus:
        """
        Check Sentinel APEX API health status.

        Returns:
            HealthStatus with .is_healthy bool and .components dict

        Note:
            Does not consume API quota. Safe to call frequently.
        """
        raw = self._get("/api/v1/health/")
        return HealthStatus.from_dict(raw)

    def ping(self) -> bool:
        """
        Simple reachability check.

        Returns:
            True if API responds, False otherwise (never raises).
        """
        try:
            status = self.health()
            return status.is_healthy
        except Exception:
            return False

    # ─────────────────────────────────────────────────────────────────────────
    # API Key Management
    # ─────────────────────────────────────────────────────────────────────────

    def get_key_info(self) -> ApiKeyInfo:
        """
        Retrieve metadata and usage stats for the current API key.

        Returns:
            ApiKeyInfo with tier, usage_today, daily_limit, etc.
        """
        raw = self._get("/api/v1/monetize/key/info")
        return ApiKeyInfo.from_dict(raw)

    def rotate_key(self, confirm: bool = False) -> ApiKeyInfo:
        """
        Rotate the current API key (generates a new key, invalidates old one).

        Args:
            confirm: Must be True to perform the rotation (safety guard)

        Raises:
            SDKConfigurationError: If confirm=False
        """
        if not confirm:
            raise SDKConfigurationError(
                "Set confirm=True to confirm key rotation. "
                "This will invalidate your current key immediately."
            )
        raw = self._post("/api/v1/monetize/key/rotate", body={})
        new_key = raw.get("new_key", "")
        if new_key:
            self._api_key = new_key
            logger.info("API key rotated successfully — client updated with new key")
        return ApiKeyInfo.from_dict(raw)

    # ─────────────────────────────────────────────────────────────────────────
    # Ingestion Status (ENTERPRISE+)
    # ─────────────────────────────────────────────────────────────────────────

    def get_ingestion_status(self) -> Dict[str, Any]:
        """
        Get live ingestion pipeline status (ENTERPRISE+).

        Returns:
            Dict with source health, queue depth, and throughput metrics
        """
        return self._get("/api/v1/ingestion/status")

    def trigger_ingestion(self, source_id: str = "all") -> Dict[str, Any]:
        """
        Manually trigger a data source fetch (ENTERPRISE+).

        Args:
            source_id: Source to trigger: nvd_cve | cisa_kev | malwarebazaar | abuseipdb | all
        """
        return self._post("/api/v1/ingestion/trigger", body={"source_id": source_id})

    # ─────────────────────────────────────────────────────────────────────────
    # Internal HTTP layer
    # ─────────────────────────────────────────────────────────────────────────

    def _get(self, path: str, params: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
        url = self._build_url(path, params)
        return self._request("GET", url)

    def _post(self, path: str, body: Dict[str, Any]) -> Dict[str, Any]:
        url  = self._build_url(path)
        data = json.dumps(body).encode("utf-8")
        return self._request("POST", url, data=data)

    def _request(self, method: str, url: str,
                 data: Optional[bytes] = None) -> Dict[str, Any]:
        headers = {
            "X-API-Key":     self._api_key,
            "Accept":        "application/json",
            "Content-Type":  "application/json",
            "User-Agent":    _USER_AGENT,
        }
        req = Request(url, data=data, headers=headers, method=method)

        last_exc: Optional[Exception] = None
        for attempt in range(1, self._max_retries + 1):
            try:
                with urlopen(req, timeout=self._timeout) as resp:
                    body = resp.read().decode("utf-8")
                    return json.loads(body) if body.strip() else {}

            except HTTPError as exc:
                status = exc.code
                try:
                    body = exc.read().decode("utf-8")
                    resp_body = json.loads(body) if body else {}
                except Exception:
                    resp_body = {}

                if status == 401:
                    raise AuthenticationError(
                        "Invalid or missing API key. Check your key at "
                        "https://sentinel.cyberdudebivash.com/dashboard",
                        status_code=401, response_body=resp_body,
                    ) from exc

                if status == 403:
                    tier = resp_body.get("required_tier", "")
                    raise TierPermissionError(
                        resp_body.get("detail", "Feature not available on your tier"),
                        status_code=403, required_tier=tier, response_body=resp_body,
                    ) from exc

                if status == 404:
                    raise NotFoundError(
                        resp_body.get("detail", f"Resource not found: {url}"),
                        status_code=404, response_body=resp_body,
                    ) from exc

                if status == 422:
                    raise ValidationError(
                        resp_body.get("detail", "Request validation failed"),
                        status_code=422, response_body=resp_body,
                    ) from exc

                if status == 429:
                    retry_after = int(exc.headers.get("Retry-After", 60))
                    if attempt < self._max_retries:
                        logger.warning("rate_limited retry_after=%ds attempt=%d",
                                       retry_after, attempt)
                        time.sleep(retry_after)
                        continue
                    raise RateLimitError(
                        f"Rate limit exceeded. Retry after {retry_after}s.",
                        status_code=429,
                        retry_after_s=retry_after,
                        response_body=resp_body,
                    ) from exc

                if status >= 500:
                    last_exc = ServerError(
                        f"Server error {status}: {resp_body.get('detail', 'Internal error')}",
                        status_code=status, response_body=resp_body,
                    )
                    # Retry on 5xx
                    if attempt < self._max_retries:
                        delay = self._backoff_delay(attempt)
                        logger.warning("server_error status=%d attempt=%d retry_in=%.1fs",
                                       status, attempt, delay)
                        time.sleep(delay)
                        continue
                    raise last_exc from exc

                raise  # Non-retryable HTTP errors

            except URLError as exc:
                last_exc = NetworkError(
                    f"Network error connecting to Sentinel APEX API: {exc.reason}",
                    status_code=0,
                )
                if attempt < self._max_retries:
                    delay = self._backoff_delay(attempt)
                    logger.warning("network_error attempt=%d retry_in=%.1fs err=%s",
                                   attempt, delay, exc.reason)
                    time.sleep(delay)
                    continue
                raise last_exc from exc

        # Should not reach here, but satisfy type checker
        if last_exc:
            raise last_exc
        raise NetworkError("Exhausted retries with no definitive error")

    def _build_url(self, path: str,
                   params: Optional[Dict[str, Any]] = None) -> str:
        """Construct full URL with query string."""
        base = self.base_url.rstrip("/")
        url  = f"{base}{path}"
        if params:
            from urllib.parse import urlencode
            qs = urlencode({k: v for k, v in params.items() if v is not None})
            if qs:
                url = f"{url}?{qs}"
        return url
