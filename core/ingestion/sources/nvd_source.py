"""
core/ingestion/sources/nvd_source.py — CYBERDUDEBIVASH® SENTINEL APEX v100.0
NVD CVE API v2.0 source adapter.

Capabilities:
  - Full paginated CVE feed (resultsPerPage up to 2000)
  - Date-range delta fetching (pubStartDate / pubEndDate)
  - CVSS v3.1 + v2.0 metric extraction
  - CWE, CPE affected configurations, reference URL harvest
  - EPSS score enrichment (api.first.org) per CVE
  - Automatic retry via backoff; respects NVD's 6 req/30s rate limit
"""
from __future__ import annotations

import os
import time
import logging
from datetime import datetime, timezone, timedelta
from typing import Any, Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
import json

from .base import (
    BaseSource, FetchResult, FetchStatus, RawIntelItem, SourceType,
    RateLimitError, AuthError, ParseError,
)

logger = logging.getLogger("sentinel.ingestion.nvd")

# NVD allows 50 req/30s with API key, 5 req/30s without
_NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_EPSS_API_BASE = "https://api.first.org/data/v1/epss"
_PAGE_SIZE     = 2000   # NVD max results per page
_CONNECT_TIMEOUT = 30


class NVDSource(BaseSource):
    """
    NIST NVD CVE API v2.0 ingestion source.
    Fetches CVE records with full CVSS, CWE, CPE, and reference data.
    Optionally enriches with EPSS scores.
    """

    SOURCE_ID   = "nvd_cve"
    SOURCE_TYPE = SourceType.CVE

    # With API key: 50/30s ≈ 100/min. Without: 5/30s ≈ 10/min.
    REQUESTS_PER_MINUTE = 90   # conservative
    BURST = 10
    TIMEOUT_S = 45

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._api_key = (
            self.config.get("api_key")
            or os.environ.get("NVD_API_KEY", "")
        )
        self._enrich_epss: bool = self.config.get("enrich_epss", True)
        self._default_lookback_hours: int = self.config.get("lookback_hours", 24)

    # ── Public helpers ────────────────────────────────────────────────────────

    def fetch_since(self, hours: int = 24) -> FetchResult:
        """Convenience: fetch CVEs published in the last N hours."""
        return self.fetch(lookback_hours=hours)

    def fetch_cve(self, cve_id: str) -> Optional[RawIntelItem]:
        """Fetch a single CVE by ID."""
        result = self.fetch(cve_id=cve_id)
        return result.items[0] if result.items else None

    # ── Core implementation ───────────────────────────────────────────────────

    def _do_fetch(self, **kwargs) -> List[RawIntelItem]:
        cve_id       = kwargs.get("cve_id")
        lookback_hrs = kwargs.get("lookback_hours", self._default_lookback_hours)

        if cve_id:
            return self._fetch_single(cve_id)
        else:
            now = datetime.now(timezone.utc)
            start = now - timedelta(hours=lookback_hrs)
            return self._fetch_range(start, now)

    def _fetch_single(self, cve_id: str) -> List[RawIntelItem]:
        url = f"{_NVD_API_BASE}?cveId={cve_id}"
        data = self._get_json(url)
        vulns = data.get("vulnerabilities", [])
        return [self._parse_vulnerability(v) for v in vulns if "cve" in v]

    def _fetch_range(self, start: datetime, end: datetime) -> List[RawIntelItem]:
        """Fetch all CVEs in [start, end] with full pagination."""
        items: List[RawIntelItem] = []
        start_str = start.strftime("%Y-%m-%dT%H:%M:%S.000")
        end_str   = end.strftime("%Y-%m-%dT%H:%M:%S.000")
        offset    = 0

        while True:
            params = (
                f"pubStartDate={start_str}"
                f"&pubEndDate={end_str}"
                f"&resultsPerPage={_PAGE_SIZE}"
                f"&startIndex={offset}"
            )
            url  = f"{_NVD_API_BASE}?{params}"
            data = self._get_json(url)

            total      = data.get("totalResults", 0)
            vulns      = data.get("vulnerabilities", [])

            for v in vulns:
                if "cve" in v:
                    try:
                        items.append(self._parse_vulnerability(v))
                    except Exception as exc:
                        self.log.warning("parse_skip cve=%s err=%s",
                                         v.get("cve", {}).get("id", "?"), exc)

            offset += len(vulns)
            self.log.debug("nvd_page offset=%d total=%d fetched=%d",
                           offset, total, len(items))

            if offset >= total or not vulns:
                break

            # NVD requires a brief pause between pages
            time.sleep(0.7)

        # EPSS enrichment batch
        if self._enrich_epss and items:
            self._enrich_with_epss(items)

        return items

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _parse_vulnerability(self, vuln_wrapper: Dict[str, Any]) -> RawIntelItem:
        cve = vuln_wrapper["cve"]
        cve_id = cve.get("id", "UNKNOWN")

        # CVSS v3.1
        cvss_v3: Dict[str, Any] = {}
        cvss_v2: Dict[str, Any] = {}
        for metric in cve.get("metrics", {}).get("cvssMetricV31", []):
            if metric.get("type") == "Primary":
                cvss_v3 = metric.get("cvssData", {})
                cvss_v3["exploitabilityScore"] = metric.get("exploitabilityScore")
                cvss_v3["impactScore"]         = metric.get("impactScore")
                break

        for metric in cve.get("metrics", {}).get("cvssMetricV2", []):
            if metric.get("type") == "Primary":
                cvss_v2 = metric.get("cvssData", {})
                break

        # CWE IDs
        cwes = [
            w.get("description", [{}])[0].get("value", "")
            for w in cve.get("weaknesses", [])
            if w.get("description")
        ]

        # References
        refs = [r.get("url", "") for r in cve.get("references", [])]

        # CPE configs (affected products)
        affected_cpes: List[str] = []
        for cfg in cve.get("configurations", []):
            for node in cfg.get("nodes", []):
                for cpe_match in node.get("cpeMatch", []):
                    if cpe_match.get("vulnerable"):
                        affected_cpes.append(cpe_match.get("criteria", ""))

        # Description (English)
        description = next(
            (d["value"] for d in cve.get("descriptions", [])
             if d.get("lang") == "en"),
            ""
        )

        raw_data = {
            "cve_id":        cve_id,
            "source":        "NVD",
            "published":     cve.get("published"),
            "lastModified":  cve.get("lastModified"),
            "vulnStatus":    cve.get("vulnStatus", ""),
            "description":   description,
            "cvss_v3":       cvss_v3,
            "cvss_v2":       cvss_v2,
            "base_score":    cvss_v3.get("baseScore") or cvss_v2.get("baseScore"),
            "severity":      cvss_v3.get("baseSeverity") or cvss_v2.get("baseSeverity"),
            "vector_string": cvss_v3.get("vectorString") or cvss_v2.get("vectorString"),
            "cwes":          [c for c in cwes if c],
            "references":    refs[:20],   # cap to avoid bloat
            "affected_cpes": affected_cpes[:50],
            "epss_score":    None,        # filled by enrichment pass
            "epss_percentile": None,
        }

        return self._make_item(
            raw_id=cve_id,
            raw_data=raw_data,
            metadata={"base_score": raw_data["base_score"], "severity": raw_data["severity"]},
        )

    # ── EPSS enrichment ───────────────────────────────────────────────────────

    def _enrich_with_epss(self, items: List[RawIntelItem]) -> None:
        """
        Batch-enrich items with EPSS scores.
        FIRST API processes up to 100 CVEs per request.
        """
        cve_ids = [item.raw_id for item in items if item.raw_id.startswith("CVE-")]
        if not cve_ids:
            return

        # Process in batches of 100
        for i in range(0, len(cve_ids), 100):
            batch = cve_ids[i:i + 100]
            try:
                cve_param = ",".join(batch)
                url = f"{_EPSS_API_BASE}?cve={cve_param}&limit=100"
                resp = self._get_json(url)
                epss_map: Dict[str, Dict] = {
                    e["cve"]: e for e in resp.get("data", [])
                }
                for item in items:
                    if item.raw_id in epss_map:
                        ed = epss_map[item.raw_id]
                        item.raw_data["epss_score"]       = float(ed.get("epss", 0))
                        item.raw_data["epss_percentile"]  = float(ed.get("percentile", 0))
                time.sleep(0.3)
            except Exception as exc:
                self.log.warning("epss_enrich_failed batch_start=%d err=%s", i, exc)

    # ── HTTP ──────────────────────────────────────────────────────────────────

    def _get_json(self, url: str) -> Dict[str, Any]:
        headers = {"Accept": "application/json"}
        if self._api_key:
            headers["apiKey"] = self._api_key

        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=self.TIMEOUT_S) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
                raise ParseError(f"NVD HTTP {resp.status}")
        except HTTPError as exc:
            if exc.code == 403:
                raise AuthError(f"NVD API key rejected: {exc}") from exc
            if exc.code == 429:
                raise RateLimitError(f"NVD rate limit: {exc}") from exc
            raise
        except URLError as exc:
            raise ConnectionError(f"NVD unreachable: {exc}") from exc
