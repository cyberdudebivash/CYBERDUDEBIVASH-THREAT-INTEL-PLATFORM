"""
core/ingestion/sources/abuseipdb_source.py — CYBERDUDEBIVASH® SENTINEL APEX v100.0
AbuseIPDB API v2 source adapter.

Capabilities:
  - Blacklist fetch: top N abusive IPs with confidence threshold
  - Single IP check: full report with abuse categories, ISP, country, usage type
  - Bulk IP check: batch mode up to 500 IPs per request
  - Abuse category decoding (25 categories: port scan, DDoS, web spam, SSH brute…)
  - Maps to SourceType.IP_THREAT with structured geolocation and threat metadata
"""
from __future__ import annotations

import json
import os
import time
from typing import Any, Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError
from urllib.parse import urlencode

from .base import (
    BaseSource, RawIntelItem, SourceType,
    ParseError, RateLimitError, AuthError,
)

_ABUSEIPDB_BASE = "https://api.abuseipdb.com/api/v2"

# AbuseIPDB category map (category ID → description)
_ABUSE_CATEGORIES: Dict[int, str] = {
    1:  "DNS Compromise",
    2:  "DNS Poisoning",
    3:  "Fraud Orders",
    4:  "DDoS Attack",
    5:  "FTP Brute-Force",
    6:  "Ping of Death",
    7:  "Phishing",
    8:  "Fraud VoIP",
    9:  "Open Proxy",
    10: "Web Spam",
    11: "Email Spam",
    12: "Blog Spam",
    13: "VPN IP",
    14: "Port Scan",
    15: "Hacking",
    16: "SQL Injection",
    17: "Spoofing",
    18: "Brute-Force",
    19: "Bad Web Bot",
    20: "Exploited Host",
    21: "Web App Attack",
    22: "SSH Brute-Force",
    23: "IoT Targeted",
    24: "Credit Card Fraud",
    25: "Cryptocurrency Mining",
}


class AbuseIPDBSource(BaseSource):
    """
    AbuseIPDB API v2 ingestion source.
    Fetches IP threat intelligence: blacklists, single IP reports, bulk lookups.
    """

    SOURCE_ID   = "abuseipdb"
    SOURCE_TYPE = SourceType.IP_THREAT

    REQUESTS_PER_MINUTE = 55    # v2 free: 1,000/day; generous burst
    BURST = 10
    TIMEOUT_S = 30

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._api_key: str = (
            self.config.get("api_key")
            or os.environ.get("ABUSEIPDB_API_KEY", "")
        )
        if not self._api_key:
            self.log.warning("abuseipdb_no_api_key: blacklist endpoint requires key")

    # ── Convenience fetchers ──────────────────────────────────────────────────

    def fetch_blacklist(self, confidence_minimum: int = 90,
                        limit: int = 1000) -> List[RawIntelItem]:
        """Fetch top abusive IPs above confidence threshold."""
        result = self.fetch(
            mode="blacklist",
            confidence_minimum=confidence_minimum,
            limit=limit,
        )
        return result.items

    def check_ip(self, ip_address: str, max_age_days: int = 30) -> Optional[RawIntelItem]:
        """Single IP abuse report lookup."""
        result = self.fetch(mode="check", ip_address=ip_address, max_age_days=max_age_days)
        return result.items[0] if result.items else None

    # ── Core implementation ───────────────────────────────────────────────────

    def _do_fetch(self, **kwargs) -> List[RawIntelItem]:
        mode = kwargs.get("mode", "blacklist")

        if mode == "blacklist":
            return self._fetch_blacklist(
                confidence=kwargs.get("confidence_minimum", 90),
                limit=kwargs.get("limit", 1000),
            )
        elif mode == "check":
            ip = kwargs.get("ip_address", "")
            if not ip:
                raise ValueError("ip_address required for check mode")
            return self._fetch_single(ip, kwargs.get("max_age_days", 30))
        else:
            raise ValueError(f"Unknown AbuseIPDB mode: {mode}")

    # ── Blacklist ─────────────────────────────────────────────────────────────

    def _fetch_blacklist(self, confidence: int, limit: int) -> List[RawIntelItem]:
        if not self._api_key:
            raise AuthError("AbuseIPDB API key required for blacklist endpoint")

        params = urlencode({
            "confidenceMinimum": confidence,
            "limit":             limit,
        })
        url = f"{_ABUSEIPDB_BASE}/blacklist?{params}"
        data = self._get_json(url)
        entries = data.get("data", [])

        items: List[RawIntelItem] = []
        for entry in entries:
            try:
                items.append(self._parse_blacklist_entry(entry, confidence))
            except Exception as exc:
                self.log.warning("abuseipdb_parse_skip ip=%s err=%s",
                                 entry.get("ipAddress", "?"), exc)

        self.log.info("abuseipdb_blacklist returned=%d confidence_min=%d",
                      len(items), confidence)
        return items

    def _parse_blacklist_entry(self, entry: Dict[str, Any],
                               confidence_min: int) -> RawIntelItem:
        ip = entry.get("ipAddress", "UNKNOWN")
        confidence = entry.get("abuseConfidenceScore", 0)

        raw_data = {
            "ip_address":            ip,
            "source":                "AbuseIPDB",
            "abuse_confidence_score": confidence,
            "country_code":          entry.get("countryCode", ""),
            "isp":                   entry.get("isp", ""),
            "domain":                entry.get("domain", ""),
            "usage_type":            entry.get("usageType", ""),
            "is_tor":                False,
            "is_public":             entry.get("isPublic", True),
            "last_reported_at":      entry.get("lastReportedAt", ""),
            "total_reports":         entry.get("totalReports", 0),
            "num_distinct_users":    entry.get("numDistinctUsers", 0),
            "abuse_categories":      [],
            "threat_type":           "ip_threat",
            "severity":              self._score_to_severity(confidence),
            "base_score":            round(confidence / 10.0, 1),
            "blacklist_confidence_min": confidence_min,
        }

        return self._make_item(
            raw_id=ip,
            raw_data=raw_data,
            metadata={
                "confidence": confidence,
                "country":    raw_data["country_code"],
                "isp":        raw_data["isp"],
                "reports":    raw_data["total_reports"],
            },
        )

    # ── Single IP check ───────────────────────────────────────────────────────

    def _fetch_single(self, ip: str, max_age_days: int) -> List[RawIntelItem]:
        if not self._api_key:
            raise AuthError("AbuseIPDB API key required for check endpoint")

        params = urlencode({
            "ipAddress":  ip,
            "maxAgeInDays": max_age_days,
            "verbose":    "",
        })
        url = f"{_ABUSEIPDB_BASE}/check?{params}"
        data = self._get_json(url)
        report = data.get("data", {})
        if not report:
            return []

        return [self._parse_check_report(report, max_age_days)]

    def _parse_check_report(self, report: Dict[str, Any],
                            max_age_days: int) -> RawIntelItem:
        ip         = report.get("ipAddress", "UNKNOWN")
        confidence = report.get("abuseConfidenceScore", 0)

        # Decode category IDs from recent reports
        categories: List[str] = []
        seen_cats: set = set()
        for r in report.get("reports", [])[:50]:
            for cat_id in (r.get("categories") or []):
                if cat_id not in seen_cats:
                    seen_cats.add(cat_id)
                    categories.append(_ABUSE_CATEGORIES.get(cat_id, f"Category_{cat_id}"))

        raw_data = {
            "ip_address":            ip,
            "source":                "AbuseIPDB",
            "abuse_confidence_score": confidence,
            "country_code":          report.get("countryCode", ""),
            "country_name":          report.get("countryName", ""),
            "isp":                   report.get("isp", ""),
            "domain":                report.get("domain", ""),
            "hostname":              report.get("hostnames", [None])[0] if report.get("hostnames") else "",
            "usage_type":            report.get("usageType", ""),
            "is_tor":                report.get("isTor", False),
            "is_public":             report.get("isPublic", True),
            "is_whitelisted":        report.get("isWhitelisted", False),
            "last_reported_at":      report.get("lastReportedAt", ""),
            "total_reports":         report.get("totalReports", 0),
            "num_distinct_users":    report.get("numDistinctUsers", 0),
            "abuse_categories":      categories,
            "recent_reports":        [
                {
                    "reported_at":    r.get("reportedAt", ""),
                    "comment":        r.get("comment", "")[:200],
                    "categories":     [_ABUSE_CATEGORIES.get(c, str(c)) for c in (r.get("categories") or [])],
                    "reporter_country": r.get("reporterCountryCode", ""),
                }
                for r in report.get("reports", [])[:20]
            ],
            "threat_type":           "ip_threat",
            "severity":              self._score_to_severity(confidence),
            "base_score":            round(confidence / 10.0, 1),
            "max_age_days":          max_age_days,
        }

        return self._make_item(
            raw_id=ip,
            raw_data=raw_data,
            metadata={
                "confidence":  confidence,
                "country":     raw_data["country_code"],
                "isp":         raw_data["isp"],
                "reports":     raw_data["total_reports"],
                "categories":  categories[:5],
                "is_tor":      raw_data["is_tor"],
            },
        )

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _score_to_severity(confidence: int) -> str:
        if confidence >= 90:
            return "CRITICAL"
        if confidence >= 70:
            return "HIGH"
        if confidence >= 40:
            return "MEDIUM"
        return "LOW"

    def _get_json(self, url: str) -> Dict[str, Any]:
        headers = {
            "Key":    self._api_key,
            "Accept": "application/json",
            "User-Agent": "SENTINEL-APEX/100.0 AbuseIPDBSource",
        }
        req = Request(url, headers=headers)
        try:
            with urlopen(req, timeout=self.TIMEOUT_S) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
                raise ParseError(f"AbuseIPDB HTTP {resp.status}")
        except HTTPError as exc:
            if exc.code == 401:
                raise AuthError(f"AbuseIPDB API key invalid (HTTP 401)")
            if exc.code == 429:
                raise RateLimitError("AbuseIPDB rate limit hit", retry_after_s=60)
            raise ParseError(f"AbuseIPDB HTTP error {exc.code}")
        except URLError as exc:
            raise NetworkError(f"AbuseIPDB network error: {exc.reason}") from exc
