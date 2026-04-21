"""
core/ingestion/sources/kev_source.py — CYBERDUDEBIVASH® SENTINEL APEX v134.0
CISA Known Exploited Vulnerabilities (KEV) catalog source adapter.

Capabilities:
  - Full KEV catalog download (JSON feed from CISA CDN)
  - Delta detection: tracks last-seen catalog timestamp to emit only new entries
  - Extracts vendorProject, product, vulnerabilityName, dateAdded, dueDate, shortDescription
  - Maps to SourceType.KEV with HIGH baseline severity
  - No API key required; no rate limit concerns (single periodic bulk fetch)
"""
from __future__ import annotations

import json
import os
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import HTTPError, URLError

from .base import (
    BaseSource, RawIntelItem, SourceType,
    ParseError, RateLimitError,
)

_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_CACHE_PATH = "/tmp/sentinel_kev_cache.json"


class KEVSource(BaseSource):
    """
    CISA KEV catalog ingestion source.
    Fetches the full KEV JSON feed and returns only entries added since
    the last successful fetch (delta mode). Falls back to full mode.
    """

    SOURCE_ID   = "cisa_kev"
    SOURCE_TYPE = SourceType.KEV

    REQUESTS_PER_MINUTE = 2   # single bulk fetch; extremely conservative
    BURST = 1
    TIMEOUT_S = 60

    def __init__(self, config: Optional[Dict[str, Any]] = None) -> None:
        super().__init__(config)
        self._cache_path: str = self.config.get("cache_path", _CACHE_PATH)
        self._last_catalog_version: Optional[str] = self._load_cached_version()

    # ── Core implementation ───────────────────────────────────────────────────

    def _do_fetch(self, **kwargs) -> List[RawIntelItem]:
        delta_only: bool = kwargs.get("delta_only", True)
        raw_catalog = self._download_catalog()

        catalog_version = raw_catalog.get("catalogVersion", "")
        vuln_list: List[Dict] = raw_catalog.get("vulnerabilities", [])

        if not vuln_list:
            raise ParseError("KEV catalog returned empty vulnerabilities list")

        # Delta: return only entries added after last seen catalog version
        if delta_only and self._last_catalog_version:
            try:
                last_ver_dt = datetime.fromisoformat(self._last_catalog_version)
                new_entries = [
                    v for v in vuln_list
                    if self._parse_date(v.get("dateAdded", "")) > last_ver_dt
                ]
                if not new_entries:
                    self.log.info("kev_no_delta version=%s", catalog_version)
                    vuln_list = []   # nothing new
                else:
                    self.log.info("kev_delta new_entries=%d", len(new_entries))
                    vuln_list = new_entries
            except Exception as exc:
                self.log.warning("kev_delta_parse_failed err=%s; returning full set", exc)

        # Persist catalog version for next run
        self._save_cached_version(catalog_version)
        self._last_catalog_version = catalog_version

        items = [self._parse_kev_entry(v) for v in vuln_list]
        self.log.info("kev_fetch complete total_catalog=%d returned=%d version=%s",
                      len(raw_catalog.get("vulnerabilities", [])), len(items), catalog_version)
        return items

    # ── Parsing ───────────────────────────────────────────────────────────────

    def _parse_kev_entry(self, entry: Dict[str, Any]) -> RawIntelItem:
        cve_id = entry.get("cveID", "UNKNOWN")

        raw_data = {
            "cve_id":               cve_id,
            "source":               "CISA_KEV",
            "vendor_project":       entry.get("vendorProject", ""),
            "product":              entry.get("product", ""),
            "vulnerability_name":   entry.get("vulnerabilityName", ""),
            "date_added":           entry.get("dateAdded", ""),
            "short_description":    entry.get("shortDescription", ""),
            "required_action":      entry.get("requiredAction", ""),
            "due_date":             entry.get("dueDate", ""),
            "known_ransomware":     entry.get("knownRansomwareCampaignUse", "Unknown"),
            "notes":                entry.get("notes", ""),
            # KEV entries are by definition actively exploited → HIGH minimum severity
            "severity":             "CRITICAL",
            "base_score":           9.0,   # conservative KEV floor (actively exploited)
            "actively_exploited":   True,
            "cisa_mandated":        True,
        }

        return self._make_item(
            raw_id=cve_id,
            raw_data=raw_data,
            metadata={
                "vendor_project": entry.get("vendorProject", ""),
                "product":        entry.get("product", ""),
                "date_added":     entry.get("dateAdded", ""),
                "due_date":       entry.get("dueDate", ""),
                "known_ransomware": entry.get("knownRansomwareCampaignUse", "Unknown"),
            },
        )

    # ── Network ───────────────────────────────────────────────────────────────

    def _download_catalog(self) -> Dict[str, Any]:
        req = Request(_KEV_URL, headers={"Accept": "application/json",
                                          "User-Agent": "SENTINEL-APEX/100.0 KEVSource"})
        try:
            with urlopen(req, timeout=self.TIMEOUT_S) as resp:
                if resp.status == 200:
                    return json.loads(resp.read().decode("utf-8"))
                raise ParseError(f"KEV HTTP {resp.status}")
        except HTTPError as exc:
            if exc.code == 429:
                raise RateLimitError(f"KEV CDN rate limit: {exc}") from exc
            raise ParseError(f"KEV HTTP error {exc.code}") from exc
        except URLError as exc:
            raise ConnectionError(f"CISA KEV unreachable: {exc}") from exc

    # ── Persistence helpers ───────────────────────────────────────────────────

    def _load_cached_version(self) -> Optional[str]:
        try:
            if os.path.exists(self._cache_path):
                with open(self._cache_path, "r") as f:
                    return json.load(f).get("catalog_version")
        except Exception:
            pass
        return None

    def _save_cached_version(self, version: str) -> None:
        try:
            tmp = self._cache_path + ".tmp"
            with open(tmp, "w") as f:
                json.dump({"catalog_version": version, "saved_at": time.time()}, f)
            os.replace(tmp, self._cache_path)
        except Exception as exc:
            self.log.warning("kev_cache_save_failed err=%s", exc)

    @staticmethod
    def _parse_date(date_str: str) -> datetime:
        try:
            for fmt in ("%Y-%m-%d", "%m/%d/%Y", "%Y-%m-%dT%H:%M:%SZ", "%Y-%m-%dT%H:%M:%S"):
                try:
                    return datetime.strptime(date_str, fmt)
                except ValueError:
                    continue
            return datetime.fromisoformat(date_str.replace("Z", "+00:00"))
        except Exception:
            return datetime(1970, 1, 1)
