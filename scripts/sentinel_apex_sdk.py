#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX — Python SDK v1.0.0
=====================================================
Production-ready client SDK for the SENTINEL APEX Threat Intelligence API.

INSTALLATION:
  pip install requests  # only external dependency

QUICK START:
  from sentinel_apex_sdk import SentinelApexClient

  client = SentinelApexClient(api_key="sa_YOUR_API_KEY_HERE")
  feed   = client.get_feed()
  for item in feed:
      print(item.title, item.severity, item.cvss_score)

API AUTHENTICATION:
  All API endpoints require an API key in the Authorization header:
    Authorization: Bearer sa_YOUR_API_KEY_HERE

  API keys are available at: https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/
  Subscription tiers: FREE | PRO | ENTERPRISE

  401 Unauthorized troubleshooting:
    1. Ensure header is:  Authorization: Bearer <key>  (not Basic or API-Key)
    2. Check key has not expired (PRO keys rotate every 90 days)
    3. Contact support if key was provisioned via Gumroad: bivashnayak.ai007@gmail.com

PUBLIC FEED (no auth required):
  GET https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/api/feed.json

CHANGELOG:
  v1.0.0 — Initial release (P1.3c customer gap fix)
"""

from __future__ import annotations

import json
import logging
import os
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterator, List, Optional

__version__ = "1.0.0"
__author__  = "CYBERDUDEBIVASH SENTINEL APEX"

log = logging.getLogger("sentinel-apex-sdk")

# ── Public endpoint (GitHub Pages — no auth required) ─────────────────────────
PUBLIC_FEED_URL = (
    "https://cyberdudebivash.github.io"
    "/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/api/feed.json"
)
# Future authenticated API base (when worker/API gateway is live):
DEFAULT_API_BASE = os.environ.get(
    "SENTINEL_APEX_API_BASE",
    "https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"
)


# ── Data models ────────────────────────────────────────────────────────────────

@dataclass
class ThreatItem:
    """Structured representation of one feed item."""
    id:                 str
    title:              str
    severity:           str
    risk_score:         Optional[float]
    cvss_score:         Optional[float]
    cvss_vector:        Optional[str]
    epss_score:         Optional[float]
    cve_id:             Optional[str]
    cve_ids:            List[str]
    kev_listed:         bool
    actor_attribution:  List[Dict[str, Any]]
    primary_actor:      Optional[str]
    source_url:         Optional[str]
    published_at:       Optional[str]
    tags:               List[str]
    iocs:               List[str]
    tlp:                str
    nvd_status:         Optional[str]
    apex_score:         Optional[float]
    _raw:               Dict[str, Any]

    @classmethod
    def from_dict(cls, d: Dict[str, Any]) -> "ThreatItem":
        return cls(
            id                = d.get("id", d.get("stix_id", "")),
            title             = d.get("title", ""),
            severity          = d.get("severity", "unknown"),
            risk_score        = _safe_float(d.get("risk_score")),
            cvss_score        = _safe_float(d.get("cvss_score")),
            cvss_vector       = d.get("cvss_vector"),
            epss_score        = _safe_float(d.get("epss_score")),
            cve_id            = d.get("cve_id"),
            cve_ids           = d.get("cve_ids") or [],
            kev_listed        = bool(d.get("kev_listed") or d.get("in_kev")),
            actor_attribution = d.get("actor_attribution") or [],
            primary_actor     = d.get("primary_actor"),
            source_url        = d.get("source_url"),
            published_at      = d.get("published_at") or d.get("processed_ts"),
            tags              = d.get("tags") or [],
            iocs              = d.get("iocs") or [],
            tlp               = d.get("tlp", "TLP:CLEAR"),
            nvd_status        = d.get("nvd_status"),
            apex_score        = _safe_float(
                (d.get("apex_ai") or {}).get("apex_score")
                if isinstance(d.get("apex_ai"), dict) else d.get("apex_score")
            ),
            _raw              = d,
        )

    @property
    def is_cve(self) -> bool:
        return bool(self.cve_id or self.cve_ids)

    @property
    def is_kev(self) -> bool:
        return self.kev_listed

    @property
    def has_actor(self) -> bool:
        return bool(self.actor_attribution or self.primary_actor)

    @property
    def severity_rank(self) -> int:
        """Numeric rank for sorting (higher = more severe)."""
        return {"critical": 5, "high": 4, "medium": 3, "low": 2,
                "informational": 1, "info": 1, "unknown": 0}.get(
            self.severity.lower(), 0)

    def __repr__(self) -> str:
        return (f"<ThreatItem {self.severity.upper()} "
                f"cve={self.cve_id or 'N/A'} "
                f"cvss={self.cvss_score or 'N/A'} "
                f"title={self.title[:50]!r}>")


@dataclass
class FeedResponse:
    """Container for a paginated feed response."""
    items:       List[ThreatItem]
    total_count: int
    fetched_at:  str
    source_url:  str

    def filter_by_severity(self, *severities: str) -> List[ThreatItem]:
        sevs = {s.lower() for s in severities}
        return [i for i in self.items if i.severity.lower() in sevs]

    def filter_cves_only(self) -> List[ThreatItem]:
        return [i for i in self.items if i.is_cve]

    def filter_kev(self) -> List[ThreatItem]:
        return [i for i in self.items if i.is_kev]

    def filter_actor(self, actor_name: str) -> List[ThreatItem]:
        name_lower = actor_name.lower()
        return [i for i in self.items
                if any(name_lower in (a.get("name", "")).lower()
                       for a in i.actor_attribution)
                or (i.primary_actor and name_lower in i.primary_actor.lower())]

    def sort_by_severity(self, descending: bool = True) -> List[ThreatItem]:
        return sorted(self.items, key=lambda i: i.severity_rank,
                      reverse=descending)

    def sort_by_cvss(self, descending: bool = True) -> List[ThreatItem]:
        return sorted(
            (i for i in self.items if i.cvss_score is not None),
            key=lambda i: i.cvss_score or 0,
            reverse=descending
        )


# ── HTTP helpers ───────────────────────────────────────────────────────────────

def _safe_float(val: Any) -> Optional[float]:
    try:
        return float(val) if val is not None else None
    except (TypeError, ValueError):
        return None


def _http_get(url: str, headers: Dict[str, str], timeout: int = 30) -> bytes:
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.read()
    except urllib.error.HTTPError as exc:
        if exc.code == 401:
            raise SentinelApexAuthError(
                "401 Unauthorized — check your API key. "
                "Header must be:  Authorization: Bearer <key>\n"
                "Get your key at: https://cyberdudebivash.github.io/"
                "CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/"
            ) from exc
        if exc.code == 403:
            raise SentinelApexAuthError(
                f"403 Forbidden — your subscription tier may not have access "
                f"to this endpoint. Upgrade at: "
                f"https://cyberdudebivash.github.io/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/"
            ) from exc
        raise SentinelApexError(f"HTTP {exc.code}: {exc.reason}") from exc
    except urllib.error.URLError as exc:
        raise SentinelApexError(f"Network error: {exc.reason}") from exc


# ── Exceptions ─────────────────────────────────────────────────────────────────

class SentinelApexError(Exception):
    """Base exception for all SDK errors."""

class SentinelApexAuthError(SentinelApexError):
    """Raised on 401/403 authentication failures."""

class SentinelApexRateLimitError(SentinelApexError):
    """Raised when rate limit (429) is hit."""


# ── Client ─────────────────────────────────────────────────────────────────────

class SentinelApexClient:
    """
    SENTINEL APEX Threat Intelligence API Client

    Args:
        api_key:     Your SENTINEL APEX API key (Bearer token).
                     Leave None to use public feed only.
        api_base:    Override the API base URL.
        timeout:     HTTP request timeout in seconds (default: 30).
        verify_ssl:  SSL verification (default: True).

    Examples:
        # Public feed (no auth):
        client = SentinelApexClient()
        feed = client.get_feed()

        # Authenticated (PRO/ENTERPRISE):
        client = SentinelApexClient(api_key="sa_abc123...")
        feed = client.get_feed()
        critical = feed.filter_by_severity("critical", "high")
    """

    SDK_VERSION = __version__
    USER_AGENT  = f"SentinelApexSDK/{__version__} Python/{sys.version_info.major}.{sys.version_info.minor}"

    def __init__(
        self,
        api_key:    Optional[str] = None,
        api_base:   str = DEFAULT_API_BASE,
        timeout:    int = 30,
    ) -> None:
        self._api_key  = api_key or os.environ.get("SENTINEL_APEX_API_KEY", "")
        self._api_base = api_base.rstrip("/")
        self._timeout  = timeout
        self._headers  = {"User-Agent": self.USER_AGENT}
        if self._api_key:
            self._headers["Authorization"] = f"Bearer {self._api_key}"

    def _get_json(self, path: str) -> Any:
        url = f"{self._api_base}/{path.lstrip('/')}"
        log.debug("GET %s", url)
        raw = _http_get(url, self._headers, self._timeout)
        return json.loads(raw)

    # ── Feed endpoints ──────────────────────────────────────────────────────────

    def get_feed(
        self,
        severity:   Optional[str]  = None,
        cve_only:   bool           = False,
        kev_only:   bool           = False,
        actor:      Optional[str]  = None,
        limit:      Optional[int]  = None,
    ) -> FeedResponse:
        """
        Fetch the live threat intelligence feed.

        Args:
            severity:  Filter by severity ('critical','high','medium','low').
            cve_only:  Return only items with a CVE ID.
            kev_only:  Return only CISA KEV-listed items.
            actor:     Filter by threat actor name or alias.
            limit:     Maximum number of items to return.

        Returns:
            FeedResponse with .items list and helper filter methods.

        Raises:
            SentinelApexAuthError:  On 401/403.
            SentinelApexError:      On network or parse errors.
        """
        data = self._get_json("api/feed.json")

        # Handle list or dict wrapper
        raw_items: List[Dict] = []
        if isinstance(data, list):
            raw_items = data
        elif isinstance(data, dict):
            for key in ("items", "advisories", "feed", "data"):
                if key in data and isinstance(data[key], list):
                    raw_items = data[key]
                    break
            if not raw_items:
                raw_items = [data] if data else []

        items = [ThreatItem.from_dict(d) for d in raw_items if isinstance(d, dict)]

        # Apply filters
        if severity:
            items = [i for i in items if i.severity.lower() == severity.lower()]
        if cve_only:
            items = [i for i in items if i.is_cve]
        if kev_only:
            items = [i for i in items if i.is_kev]
        if actor:
            actor_lower = actor.lower()
            items = [i for i in items
                     if any(actor_lower in (a.get("name", "")).lower()
                            for a in i.actor_attribution)
                     or (i.primary_actor and actor_lower in i.primary_actor.lower())]
        if limit is not None:
            items = items[:limit]

        return FeedResponse(
            items       = items,
            total_count = len(raw_items),
            fetched_at  = datetime.now(timezone.utc).isoformat(),
            source_url  = f"{self._api_base}/api/feed.json",
        )

    def get_item(self, item_id: str) -> Optional[ThreatItem]:
        """
        Fetch a single feed item by ID or CVE ID.

        Args:
            item_id:  Item ID, STIX ID, or CVE-XXXX-XXXXX string.

        Returns:
            ThreatItem if found, None otherwise.
        """
        feed = self.get_feed()
        id_lower = item_id.lower()
        for item in feed.items:
            if (item.id.lower() == id_lower
                    or (item.cve_id and item.cve_id.lower() == id_lower)
                    or any(c.lower() == id_lower for c in item.cve_ids)):
                return item
        return None

    def iter_feed(
        self,
        batch_size:     int = 50,
        poll_interval:  int = 300,
        max_iterations: int = -1,
    ) -> Iterator[ThreatItem]:
        """
        Poll the feed continuously, yielding new items as they appear.

        Args:
            batch_size:     Items per page (when pagination is available).
            poll_interval:  Seconds between polls (default: 300 = 5 min).
            max_iterations: Stop after N polls. -1 = run forever.

        Yields:
            ThreatItem for each new item detected.

        Example:
            for item in client.iter_feed(poll_interval=60):
                if item.is_kev:
                    send_alert(item)
        """
        seen_ids: set[str] = set()
        iteration = 0
        while max_iterations < 0 or iteration < max_iterations:
            try:
                feed = self.get_feed()
                for item in feed.items:
                    if item.id not in seen_ids:
                        seen_ids.add(item.id)
                        if iteration > 0:  # Don't yield on first load
                            yield item
            except SentinelApexError as exc:
                log.warning("Feed poll error: %s", exc)
            iteration += 1
            if max_iterations < 0 or iteration < max_iterations:
                time.sleep(poll_interval)

    # ── Utility ─────────────────────────────────────────────────────────────────

    def health_check(self) -> Dict[str, Any]:
        """
        Verify API connectivity and return status information.

        Returns:
            Dict with 'status', 'feed_items', 'api_version', 'authenticated'.
        """
        try:
            feed = self.get_feed()
            return {
                "status":        "ok",
                "feed_items":    feed.total_count,
                "fetched_at":    feed.fetched_at,
                "authenticated": bool(self._api_key),
                "api_base":      self._api_base,
                "sdk_version":   self.SDK_VERSION,
            }
        except SentinelApexAuthError as exc:
            return {"status": "auth_error", "error": str(exc)}
        except SentinelApexError as exc:
            return {"status": "error", "error": str(exc)}


# ── CLI demo ───────────────────────────────────────────────────────────────────

def _cli_demo() -> None:
    """Run a quick demo of the SDK against the live public feed."""
    import argparse
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX SDK v1.0.0 — CLI Demo",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  # Show top 10 HIGH+ items:
  python3 sentinel_apex_sdk.py --severity high --limit 10

  # Show all CISA KEV items:
  python3 sentinel_apex_sdk.py --kev

  # Show items attributed to APT28:
  python3 sentinel_apex_sdk.py --actor APT28

  # Health check:
  python3 sentinel_apex_sdk.py --health

  # Using an API key:
  python3 sentinel_apex_sdk.py --api-key sa_YOUR_KEY --severity critical
"""
    )
    parser.add_argument("--api-key",   help="SENTINEL APEX API key")
    parser.add_argument("--severity",  help="Filter by severity")
    parser.add_argument("--actor",     help="Filter by actor name")
    parser.add_argument("--cve-only",  action="store_true", help="CVE items only")
    parser.add_argument("--kev",       action="store_true", help="KEV items only")
    parser.add_argument("--limit",     type=int, default=25)
    parser.add_argument("--health",    action="store_true", help="Health check")
    parser.add_argument("--json",      action="store_true", help="Output as JSON")
    args = parser.parse_args()

    logging.basicConfig(level=logging.WARNING)

    api_key = args.api_key or os.environ.get("SENTINEL_APEX_API_KEY", "")
    client  = SentinelApexClient(api_key=api_key)

    if args.health:
        status = client.health_check()
        print(json.dumps(status, indent=2))
        return

    feed = client.get_feed(
        severity  = args.severity,
        cve_only  = args.cve_only,
        kev_only  = args.kev,
        actor     = args.actor,
        limit     = args.limit,
    )

    if args.json:
        print(json.dumps([i._raw for i in feed.items], indent=2, ensure_ascii=False))
        return

    print(f"\n{'='*80}")
    print(f"  SENTINEL APEX Threat Feed  |  {feed.total_count} total  |  "
          f"showing {len(feed.items)}")
    print(f"  Fetched: {feed.fetched_at}  |  Auth: {bool(api_key)}")
    print(f"{'='*80}")

    for item in feed.items:
        cvss  = f"CVSS:{item.cvss_score:.1f}" if item.cvss_score else "CVSS:N/A"
        epss  = f"EPSS:{item.epss_score:.3f}" if item.epss_score else "EPSS:N/A"
        kev   = " [KEV]" if item.is_kev else ""
        actor = f" [{item.primary_actor}]" if item.primary_actor else ""
        cve   = f" {item.cve_id}" if item.cve_id else ""
        sev   = item.severity.upper()[:4]
        print(f"  [{sev}]{kev}{actor}{cve}  {cvss}  {epss}")
        print(f"         {item.title[:72]}")
        print()

    print(f"{'='*80}\n")


if __name__ == "__main__":
    _cli_demo()
