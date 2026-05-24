#!/usr/bin/env python3
"""
scripts/true_intel_ingestor.py
CYBERDUDEBIVASH(R) SENTINEL APEX — True Incremental Intelligence Ingestor
==========================================================================
P0 FIX: Genuine incremental ingestion with timestamp integrity.

ROOT CAUSES FIXED:
  [RC-1] published_at was empty in all manifest items (STIX bundles had no x_published_at)
  [RC-2] master_p0_fix stamped processed_at=NOW on EVERY item EVERY run → fake freshness
  [RC-3] feed_state.json had feed_count=0 → no per-source last_seen tracking → full re-scan every run
  [RC-4] dedup fingerprint used processed_at fallback → unstable → duplicate items always passed
  [RC-5] ManifestMerger class didn't exist in multi_source_intel.py → workflow silently dead

INGESTION CONTRACT:
  1. For each source: load last_seen_timestamp[source] from feed_state.json
  2. Fetch ONLY items WHERE source_published_at > last_seen_timestamp[source]
  3. SHA256 dedup via dedup_state.py (fingerprint = source_url + title + published_at)
  4. Write ONLY new items to data/stix/feed_manifest.json (additive merge)
  5. Update feed_state.json + processed_intel.json atomically after success
  6. NEVER set published_at = NOW_UTC — always preserve source date

SOURCES:
  - CISA KEV API (dateAdded field — authoritative government timestamp)
  - NVD CVE API v2 (publishedDate field)
  - GitHub Security Advisory API (publishedAt field)
  - ransomware.live API (discovered field)
  - URLhaus feed (dateadded field)
  - All RSS feeds from agent/config.py (RSS <pubDate> / feedparser published)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import re
import sys
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlparse, urlencode

# ---------------------------------------------------------------------------
# Bootstrap path so we can import dedup_state from scripts/
# ---------------------------------------------------------------------------
_REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(_REPO / "scripts"))
sys.path.insert(0, str(_REPO))

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [true-ingestor] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("sentinel.true_ingestor")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
MANIFEST_PATH  = _REPO / "data" / "stix" / "feed_manifest.json"
FEED_STATE_PATH = _REPO / "data" / "cache" / "feed_state.json"
DEDUP_STATE_PATH = _REPO / "data" / "processed_intel.json"

FEED_STATE_SCHEMA_VERSION = "142.0"
MANIFEST_MAX_ENTRIES = 5000

# ---------------------------------------------------------------------------
# Network constants
# ---------------------------------------------------------------------------
REQUEST_TIMEOUT = 15
CISA_KEV_URL    = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL     = "https://services.nvd.nist.gov/rest/json/cves/2.0"
GITHUB_ADVISORY_URL = "https://api.github.com/graphql"
RANSOMWARE_LIVE_URL = "https://api.ransomware.live/v2/recentvictims"
URLHAUS_URL     = "https://urlhaus-api.abuse.ch/v1/urls/recent/"

# NVD: look back max 2 days per run (CI runs 4x/day)
NVD_LOOKBACK_HOURS = 48


# ═══════════════════════════════════════════════════════════════════════════
# FEED STATE — per-source last_seen_timestamp
# ═══════════════════════════════════════════════════════════════════════════

def _utc_now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _utc_epoch() -> str:
    """Epoch start — items with no prior state are treated as brand new."""
    return "2020-01-01T00:00:00Z"


def _parse_ts(ts_str: str) -> Optional[datetime]:
    """Parse ISO-8601 string to tz-aware datetime. Returns None on failure."""
    if not ts_str:
        return None
    for fmt in (
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S+00:00",
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%S%z",
        "%Y-%m-%d",
        "%a, %d %b %Y %H:%M:%S %z",
        "%a, %d %b %Y %H:%M:%S GMT",
    ):
        try:
            dt = datetime.strptime(ts_str.strip(), fmt)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            return dt
        except ValueError:
            continue
    # feedparser sometimes emits 9-tuples
    if isinstance(ts_str, (list, tuple)) and len(ts_str) >= 6:
        try:
            dt = datetime(*ts_str[:6], tzinfo=timezone.utc)
            return dt
        except Exception:
            pass
    return None


def _ts_to_str(dt: Optional[datetime]) -> str:
    if dt is None:
        return ""
    return dt.strftime("%Y-%m-%dT%H:%M:%SZ")


class FeedState:
    """
    Persistent per-source last_seen_timestamp store.
    Schema: { "_meta": {...}, "sources": { "source_key": { "last_seen": "ISO-8601", ... } } }
    """

    def __init__(self, path: Path = FEED_STATE_PATH) -> None:
        self._path = path
        self._state: Dict = {}

    def load(self) -> "FeedState":
        self._path.parent.mkdir(parents=True, exist_ok=True)
        if self._path.exists():
            try:
                raw = json.loads(self._path.read_text(encoding="utf-8"))
                if isinstance(raw, dict):
                    self._state = raw
                    count = len(self._state.get("sources", {}))
                    log.info("[FEED-STATE] Loaded: %d source(s) tracked", count)
                    return self
                log.warning("[FEED-STATE] Unexpected schema — reinitialising")
            except Exception as e:
                log.warning("[FEED-STATE] Corrupt state file (%s) — reinitialising", e)
        self._state = {
            "_meta": {
                "schema_version": FEED_STATE_SCHEMA_VERSION,
                "last_updated": _utc_now(),
                "feed_count": 0,
            },
            "sources": {},
        }
        log.info("[FEED-STATE] Initialised fresh state")
        return self

    def save(self) -> None:
        sources = self._state.get("sources", {})
        self._state.setdefault("_meta", {}).update({
            "schema_version": FEED_STATE_SCHEMA_VERSION,
            "last_updated": _utc_now(),
            "feed_count": len(sources),
        })
        tmp = self._path.with_suffix(".tmp")
        try:
            tmp.write_text(json.dumps(self._state, indent=2, ensure_ascii=False), encoding="utf-8")
            os.replace(tmp, self._path)
            log.info("[FEED-STATE] Saved: %d source(s)", len(sources))
        except Exception as e:
            log.error("[FEED-STATE] Save failed: %s", e)

    def get_last_seen(self, source_key: str) -> Optional[datetime]:
        ts_str = self._state.get("sources", {}).get(source_key, {}).get("last_seen", "")
        if not ts_str:
            return None
        return _parse_ts(ts_str)

    def update_last_seen(self, source_key: str, newest_ts: datetime) -> None:
        current = self.get_last_seen(source_key)
        if current is None or newest_ts > current:
            self._state.setdefault("sources", {})[source_key] = {
                "last_seen": _ts_to_str(newest_ts),
                "updated_at": _utc_now(),
            }

    def is_new(self, source_key: str, item_ts: Optional[datetime]) -> bool:
        """Returns True if item_ts is strictly newer than last_seen for this source."""
        if item_ts is None:
            # No timestamp → treat as new (conservative: don't block unknown-date items)
            return True
        last = self.get_last_seen(source_key)
        if last is None:
            return True
        return item_ts > last


# ═══════════════════════════════════════════════════════════════════════════
# DEDUP ENGINE (wraps dedup_state.py)
# ═══════════════════════════════════════════════════════════════════════════

class _IngestorDedup:
    """Thin wrapper around dedup_state.DedupState for this ingestor."""

    def __init__(self) -> None:
        self._state = None

    def load(self) -> "_IngestorDedup":
        try:
            from dedup_state import DedupState
            self._state = DedupState(DEDUP_STATE_PATH).load()
            log.info("[DEDUP] Loaded: %d fingerprints", self._state.get_stats()["total_fingerprints"])
        except Exception as e:
            log.warning("[DEDUP] dedup_state import failed (%s) — in-memory fallback", e)
            self._state = None
        return self

    def is_duplicate(self, item: Dict) -> bool:
        if self._state:
            return self._state.is_duplicate(item)
        return False  # If dedup unavailable, allow all through

    def mark_seen(self, item: Dict) -> None:
        if self._state:
            self._state.mark_seen(item)

    def save(self) -> None:
        if self._state:
            self._state.save()


# ═══════════════════════════════════════════════════════════════════════════
# HTTP HELPER
# ═══════════════════════════════════════════════════════════════════════════

def _get_json(url: str, headers: Optional[Dict] = None, timeout: int = REQUEST_TIMEOUT) -> Optional[Dict]:
    try:
        import urllib.request as _ur
        req = _ur.Request(url, headers={
            "User-Agent": "CyberDudeBivash-SentinelAPEX/142.0 (Intel-Ingestor)",
            **(headers or {}),
        })
        with _ur.urlopen(req, timeout=timeout) as resp:
            raw = resp.read()
            return json.loads(raw)
    except Exception as e:
        log.warning("[HTTP] GET %s → %s", url[:80], e)
        return None


def _get_text(url: str, headers: Optional[Dict] = None, timeout: int = REQUEST_TIMEOUT) -> Optional[str]:
    try:
        import urllib.request as _ur
        req = _ur.Request(url, headers={
            "User-Agent": "CyberDudeBivash-SentinelAPEX/142.0 (Intel-Ingestor)",
            **(headers or {}),
        })
        with _ur.urlopen(req, timeout=timeout) as resp:
            return resp.read().decode("utf-8", errors="replace")
    except Exception as e:
        log.warning("[HTTP] GET-TEXT %s → %s", url[:80], e)
        return None


# ═══════════════════════════════════════════════════════════════════════════
# NORMALISE ITEM
# ═══════════════════════════════════════════════════════════════════════════

def _normalize_item(
    source_key: str,
    title: str,
    source_url: str,
    published_at: str,   # AUTHORITATIVE from source — NEVER overridden
    description: str = "",
    tags: Optional[List[str]] = None,
    severity: str = "MEDIUM",
    threat_type: str = "CVE",
    cves: Optional[List[str]] = None,
    risk_score: float = 5.0,
) -> Dict:
    """
    Build a normalised manifest item.
    CRITICAL: processed_at = pipeline time. published_at = SOURCE time. NEVER swap.
    """
    now = _utc_now()
    return {
        "id":           f"intel--{hashlib.sha256((source_url + title).encode()).hexdigest()[:16]}",
        "stix_id":      f"indicator--{hashlib.sha256((source_url + title).encode()).hexdigest()[:32]}",
        "title":        str(title).strip()[:300],
        "description":  str(description).strip()[:1000],
        "source_url":   str(source_url).strip(),
        "feed_source":  str(source_key),
        "published_at": str(published_at).strip(),   # SOURCE date — immutable after this point
        "processed_at": now,                          # Pipeline time — OK to be NOW
        "timestamp":    str(published_at).strip() or now,  # UI sort key: prefer source date
        "severity":     severity,
        "risk_score":   risk_score,
        "threat_type":  threat_type,
        "tags":         tags or [],
        "cves":         cves or [],
        "iocs":         [],
        "ioc_count":    0,
        "tlp":          "TLP:CLEAR",
        "actor_tag":    "UNC-CDB-INGEST",
    }


# ═══════════════════════════════════════════════════════════════════════════
# SOURCE: CISA KEV
# ═══════════════════════════════════════════════════════════════════════════

def ingest_cisa_kev(feed_state: FeedState) -> List[Dict]:
    """
    CISA Known Exploited Vulnerabilities catalogue.
    Published date field: 'dateAdded' (YYYY-MM-DD) — authoritative.
    Incremental: only items with dateAdded > last_seen.
    """
    SOURCE_KEY = "cisa_kev"
    log.info("[CISA-KEV] Fetching catalogue...")

    data = _get_json(CISA_KEV_URL)
    if not data or "vulnerabilities" not in data:
        log.warning("[CISA-KEV] No data received")
        return []

    vulns = data.get("vulnerabilities", [])
    log.info("[CISA-KEV] Total catalogue: %d entries", len(vulns))

    items: List[Dict] = []
    newest_ts: Optional[datetime] = None

    for v in vulns:
        date_str = v.get("dateAdded", "").strip()
        item_ts = _parse_ts(date_str)

        if not feed_state.is_new(SOURCE_KEY, item_ts):
            continue

        cve_id   = v.get("cveID", "")
        title    = f"{cve_id}: {v.get('vulnerabilityName', 'Known Exploited Vulnerability')}"
        product  = v.get("product", "")
        vendor   = v.get("vendorProject", "")
        action   = v.get("requiredAction", "")
        desc     = f"{v.get('shortDescription', '')} | Vendor: {vendor} | Product: {product} | Action: {action}"

        item = _normalize_item(
            source_key   = SOURCE_KEY,
            title        = title,
            source_url   = f"https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
            published_at = date_str,
            description  = desc,
            tags         = ["kev", "cisa", "exploitation", vendor.lower(), product.lower()],
            severity     = "CRITICAL",
            threat_type  = "KEV",
            cves         = [cve_id] if cve_id else [],
            risk_score   = 9.5,
        )
        # Use stable URL per CVE
        item["source_url"] = f"https://nvd.nist.gov/vuln/detail/{cve_id}" if cve_id else item["source_url"]
        # v161.3 P0 FIX: KEV items are ALWAYS current (actively exploited).
        # Override timestamp to processed_at (now) so ANTI_STALE_MAX_AGE_DAYS
        # filter does NOT quarantine them based on their old KEV dateAdded value.
        # published_at retains the authoritative CISA dateAdded for audit trail.
        item["timestamp"]    = item["processed_at"]
        item["kev_present"]  = True
        item["kev_date"]     = date_str
        item["kev_product"]  = f"{vendor} {product}".strip()
        item["tlp"]          = "TLP:RED"   # KEV = actively exploited = highest urgency
        items.append(item)

        if item_ts and (newest_ts is None or item_ts > newest_ts):
            newest_ts = item_ts

    if newest_ts:
        feed_state.update_last_seen(SOURCE_KEY, newest_ts)

    log.info("[CISA-KEV] New items: %d", len(items))
    return items


# ═══════════════════════════════════════════════════════════════════════════
# SOURCE: NVD CVE API v2
# ═══════════════════════════════════════════════════════════════════════════

def ingest_nvd_cves(feed_state: FeedState, lookback_hours: int = NVD_LOOKBACK_HOURS) -> List[Dict]:
    """
    NVD CVE API v2 — recent CVEs by publishedDate window.
    Incremental: uses last_seen to set pubStartIndex window.
    """
    SOURCE_KEY = "nvd_cve"

    last_seen = feed_state.get_last_seen(SOURCE_KEY)
    if last_seen:
        start_dt = last_seen
    else:
        start_dt = datetime.now(timezone.utc) - timedelta(hours=lookback_hours)

    end_dt = datetime.now(timezone.utc)
    pub_start = start_dt.strftime("%Y-%m-%dT%H:%M:%S.000")
    pub_end   = end_dt.strftime("%Y-%m-%dT%H:%M:%S.000")

    url = f"{NVD_API_URL}?pubStartDate={pub_start}&pubEndDate={pub_end}&resultsPerPage=100"
    log.info("[NVD] Fetching CVEs from %s to %s", pub_start[:10], pub_end[:10])

    data = _get_json(url)
    if not data:
        log.warning("[NVD] No data received")
        return []

    vulns = data.get("vulnerabilities", [])
    log.info("[NVD] Raw CVEs received: %d", len(vulns))

    items: List[Dict] = []
    newest_ts: Optional[datetime] = None

    for v in vulns:
        cve = v.get("cve", {})
        cve_id = cve.get("id", "")
        published_str = cve.get("published", "")
        item_ts = _parse_ts(published_str)

        if not feed_state.is_new(SOURCE_KEY, item_ts):
            continue

        # Extract description
        descs = cve.get("descriptions", [])
        desc = next((d["value"] for d in descs if d.get("lang") == "en"), "")

        # Extract CVSS score
        metrics = cve.get("metrics", {})
        cvss_score = None
        severity = "MEDIUM"
        for m_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            ms = metrics.get(m_key, [])
            if ms:
                cvss_data = ms[0].get("cvssData", {})
                cvss_score = cvss_data.get("baseScore")
                sev = cvss_data.get("baseSeverity", "").upper()
                if sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
                    severity = sev
                break

        risk_score = min(float(cvss_score or 5.0), 10.0) if cvss_score else 5.0

        title = f"{cve_id}: {desc[:120]}" if desc else cve_id
        nvd_url = f"https://nvd.nist.gov/vuln/detail/{cve_id}"

        item = _normalize_item(
            source_key   = SOURCE_KEY,
            title        = title,
            source_url   = nvd_url,
            published_at = published_str,
            description  = desc,
            tags         = ["nvd", "cve", severity.lower()],
            severity     = severity,
            threat_type  = "CVE",
            cves         = [cve_id],
            risk_score   = risk_score,
        )
        items.append(item)

        if item_ts and (newest_ts is None or item_ts > newest_ts):
            newest_ts = item_ts

    if newest_ts:
        feed_state.update_last_seen(SOURCE_KEY, newest_ts)

    log.info("[NVD] New items: %d", len(items))
    return items


# ═══════════════════════════════════════════════════════════════════════════
# SOURCE: GitHub Security Advisory (REST — no auth required for public)
# ═══════════════════════════════════════════════════════════════════════════

def ingest_github_advisories(feed_state: FeedState) -> List[Dict]:
    """
    GitHub Security Advisory Database via REST API (public, no auth).
    Endpoint: GET /advisories?direction=desc&sort=published&per_page=100
    Incremental by published timestamp.
    """
    SOURCE_KEY = "github_advisory"
    url = "https://api.github.com/advisories?direction=desc&sort=published&per_page=100&type=reviewed"

    gh_token = os.environ.get("GITHUB_TOKEN_INTEL") or os.environ.get("GITHUB_TOKEN", "")
    headers: Dict = {"Accept": "application/vnd.github+json", "X-GitHub-Api-Version": "2022-11-28"}
    if gh_token:
        headers["Authorization"] = f"Bearer {gh_token}"

    log.info("[GH-ADVISORY] Fetching GitHub advisories...")
    data = _get_json(url, headers=headers)
    if not data or not isinstance(data, list):
        log.warning("[GH-ADVISORY] No data or unexpected format")
        return []

    items: List[Dict] = []
    newest_ts: Optional[datetime] = None

    for adv in data:
        published_str = adv.get("published_at", "") or adv.get("created_at", "")
        item_ts = _parse_ts(published_str)

        if not feed_state.is_new(SOURCE_KEY, item_ts):
            continue

        ghsa_id  = adv.get("ghsa_id", "")
        title    = adv.get("summary", "") or ghsa_id
        severity = (adv.get("severity") or "medium").upper()
        desc     = adv.get("description", "")[:800]
        html_url = adv.get("html_url", f"https://github.com/advisories/{ghsa_id}")

        # CVEs from identifiers
        identifiers = adv.get("identifiers", []) or adv.get("cve_ids", [])
        cves = []
        if isinstance(identifiers, list):
            for ident in identifiers:
                if isinstance(ident, dict):
                    val = ident.get("value", "")
                    if val.startswith("CVE-"):
                        cves.append(val)
                elif isinstance(ident, str) and ident.startswith("CVE-"):
                    cves.append(ident)

        cvss = adv.get("cvss", {}) or {}
        cvss_score = cvss.get("score") if isinstance(cvss, dict) else None
        risk = min(float(cvss_score or 5.0), 10.0) if cvss_score else 5.0

        item = _normalize_item(
            source_key   = SOURCE_KEY,
            title        = title,
            source_url   = html_url,
            published_at = published_str,
            description  = desc,
            tags         = ["github", "advisory", severity.lower(), "oss"],
            severity     = severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW") else "MEDIUM",
            threat_type  = "OSS-ADVISORY",
            cves         = cves,
            risk_score   = risk,
        )
        items.append(item)

        if item_ts and (newest_ts is None or item_ts > newest_ts):
            newest_ts = item_ts

    if newest_ts:
        feed_state.update_last_seen(SOURCE_KEY, newest_ts)

    log.info("[GH-ADVISORY] New items: %d", len(items))
    return items


# ═══════════════════════════════════════════════════════════════════════════
# SOURCE: ransomware.live
# ═══════════════════════════════════════════════════════════════════════════

def ingest_ransomware_live(feed_state: FeedState) -> List[Dict]:
    """
    ransomware.live API — recent ransomware victims.
    Field: 'discovered' (ISO-8601 timestamp from source).
    """
    SOURCE_KEY = "ransomware_live"
    log.info("[RANSOMWARE-LIVE] Fetching recent victims...")

    data = _get_json(RANSOMWARE_LIVE_URL, timeout=20)
    if not data or not isinstance(data, list):
        log.warning("[RANSOMWARE-LIVE] No data or unexpected format")
        return []

    items: List[Dict] = []
    newest_ts: Optional[datetime] = None

    for victim in data[:50]:  # Cap at 50 to avoid manifest flood
        discovered_str = victim.get("discovered", "") or victim.get("published", "")
        item_ts = _parse_ts(discovered_str)

        if not feed_state.is_new(SOURCE_KEY, item_ts):
            continue

        group   = victim.get("group_name", "Unknown") or victim.get("group", "Unknown")
        name    = victim.get("post_title", "") or victim.get("victim", "") or victim.get("name", "Unknown")
        country = victim.get("country", "")
        website = victim.get("website", "")
        desc    = f"Ransomware group '{group}' listed '{name}' as victim. Country: {country}. Site: {website}"
        title   = f"[RANSOMWARE] {group}: {name}"

        item = _normalize_item(
            source_key   = SOURCE_KEY,
            title        = title,
            source_url   = f"https://www.ransomware.live/group/{group.replace(' ', '-').lower()}",
            published_at = discovered_str,
            description  = desc,
            tags         = ["ransomware", group.lower(), country.lower(), "extortion"],
            severity     = "HIGH",
            threat_type  = "RANSOMWARE",
            risk_score   = 8.0,
        )
        items.append(item)

        if item_ts and (newest_ts is None or item_ts > newest_ts):
            newest_ts = item_ts

    if newest_ts:
        feed_state.update_last_seen(SOURCE_KEY, newest_ts)

    log.info("[RANSOMWARE-LIVE] New items: %d", len(items))
    return items


# ═══════════════════════════════════════════════════════════════════════════
# SOURCE: URLhaus
# ═══════════════════════════════════════════════════════════════════════════

def ingest_urlhaus(feed_state: FeedState) -> List[Dict]:
    """
    abuse.ch URLhaus — recent malicious URLs.
    Uses JSON API endpoint (no auth required).
    Field: 'dateadded' from API.
    """
    SOURCE_KEY = "urlhaus"
    log.info("[URLHAUS] Fetching recent malicious URLs...")

    try:
        import urllib.request as _ur
        req = _ur.Request(
            URLHAUS_URL,
            data=b"",
            method="POST",
            headers={"User-Agent": "CyberDudeBivash-SentinelAPEX/142.0"},
        )
        with _ur.urlopen(req, timeout=15) as resp:
            data = json.loads(resp.read())
    except Exception as e:
        log.warning("[URLHAUS] Fetch failed: %s", e)
        return []

    urls_list = data.get("urls", []) if isinstance(data, dict) else []
    if not urls_list:
        log.warning("[URLHAUS] Empty response")
        return []

    items: List[Dict] = []
    newest_ts: Optional[datetime] = None

    for entry in urls_list[:30]:  # Cap at 30 per run
        date_str = entry.get("dateadded", "") or entry.get("date_added", "")
        item_ts = _parse_ts(date_str)

        if not feed_state.is_new(SOURCE_KEY, item_ts):
            continue

        url_val  = entry.get("url", "")
        urlhaus_url = entry.get("urlhaus_link", "https://urlhaus.abuse.ch/")
        threat   = entry.get("threat", "malware")
        tags_raw = entry.get("tags", []) or []
        if isinstance(tags_raw, str):
            tags_raw = [t.strip() for t in tags_raw.split(",") if t.strip()]

        title = f"[URLhaus] {threat.upper()}: {url_val[:80]}"
        desc  = f"Malicious URL detected by URLhaus. Threat: {threat}. URL: {url_val}"

        item = _normalize_item(
            source_key   = SOURCE_KEY,
            title        = title,
            source_url   = urlhaus_url,
            published_at = date_str,
            description  = desc,
            tags         = ["urlhaus", "malware", threat.lower()] + tags_raw[:5],
            severity     = "HIGH",
            threat_type  = "MALWARE-URL",
            risk_score   = 7.5,
        )
        item["iocs"] = [{"type": "url", "value": url_val}] if url_val else []
        item["ioc_count"] = len(item["iocs"])
        items.append(item)

        if item_ts and (newest_ts is None or item_ts > newest_ts):
            newest_ts = item_ts

    if newest_ts:
        feed_state.update_last_seen(SOURCE_KEY, newest_ts)

    log.info("[URLHAUS] New items: %d", len(items))
    return items


# ═══════════════════════════════════════════════════════════════════════════
# SOURCE: RSS FEEDS (from agent/config.py)
# ═══════════════════════════════════════════════════════════════════════════

def _rss_source_key(feed_url: str) -> str:
    """Stable per-feed key from URL."""
    parsed = urlparse(feed_url)
    key = re.sub(r"[^a-z0-9_]", "_", (parsed.netloc + parsed.path).lower())
    return f"rss_{key[:60]}"


def _parse_feedparser_entry(entry: object) -> Tuple[str, str, str, str]:
    """Extract (title, url, published_at, description) from a feedparser entry."""
    try:
        title = getattr(entry, "title", "") or ""
        link  = getattr(entry, "link", "") or ""
        desc_raw = (
            getattr(entry, "summary", "") or
            getattr(entry, "description", "") or ""
        )
        # Strip HTML tags from description
        desc = re.sub(r"<[^>]+>", " ", desc_raw).strip()[:500]

        # Published date: prefer published_parsed (struct_time), then published string
        published_at = ""
        pub_parsed = getattr(entry, "published_parsed", None)
        if pub_parsed:
            try:
                dt = datetime(*pub_parsed[:6], tzinfo=timezone.utc)
                published_at = _ts_to_str(dt)
            except Exception:
                pass
        if not published_at:
            pub_str = getattr(entry, "published", "") or getattr(entry, "updated", "") or ""
            if pub_str:
                dt = _parse_ts(pub_str)
                if dt:
                    published_at = _ts_to_str(dt)

        return str(title), str(link), published_at, str(desc)
    except Exception as e:
        log.debug("[RSS-PARSE] Entry parse error: %s", e)
        return "", "", "", ""


def ingest_rss_feeds(feed_state: FeedState, max_per_feed: int = 10) -> List[Dict]:
    """
    Ingest all RSS feeds from agent/config.py RSS_FEEDS list.
    Uses feedparser to parse. Preserves source published date from RSS <pubDate>.
    Incremental: only items WHERE rss_published > last_seen[feed_url].
    """
    try:
        import feedparser
    except ImportError:
        log.error("[RSS] feedparser not installed — skipping RSS ingestion. Run: pip install feedparser")
        return []

    # Load RSS feeds from config
    rss_feeds: List[str] = []
    try:
        sys.path.insert(0, str(_REPO / "agent"))
        from config import RSS_FEEDS as _RSS_FEEDS
        rss_feeds = _RSS_FEEDS
        log.info("[RSS] Loaded %d feeds from agent/config.py", len(rss_feeds))
    except Exception as e:
        log.warning("[RSS] Could not load agent/config.py: %s — using fallback list", e)
        rss_feeds = [
            "https://feeds.feedburner.com/TheHackersNews",
            "https://krebsonsecurity.com/feed/",
            "https://www.cisa.gov/cybersecurity-advisories/all.xml",
            "https://cvefeed.io/rssfeed/latest.xml",
        ]

    all_items: List[Dict] = []
    feed_stats: Dict[str, Dict] = {}

    for feed_url in rss_feeds:
        # Skip non-RSS looking URLs (some config entries are API endpoints)
        if not any(feed_url.startswith(p) for p in ("http://", "https://")):
            continue
        # Skip obvious non-feed endpoints
        if any(x in feed_url for x in ("/api/v1/", "/graphql", "shadowserver.org/api")):
            log.debug("[RSS] Skipping API endpoint: %s", feed_url[:60])
            continue

        source_key = _rss_source_key(feed_url)
        stats = {"total": 0, "new": 0, "skipped": 0, "no_date": 0}
        newest_ts: Optional[datetime] = None

        try:
            parsed = feedparser.parse(feed_url)
            entries = getattr(parsed, "entries", [])
            if not entries:
                log.debug("[RSS] No entries: %s", feed_url[:60])
                feed_stats[source_key] = stats
                continue

            stats["total"] = len(entries)
            new_items_this_feed = 0

            for entry in entries:
                if new_items_this_feed >= max_per_feed:
                    break

                title, link, published_at, desc = _parse_feedparser_entry(entry)
                if not title:
                    continue

                item_ts = _parse_ts(published_at) if published_at else None

                if not item_ts:
                    stats["no_date"] += 1
                    # Items with no date: only include if no prior state for this feed
                    # (conservative — don't block first-run items without dates)
                    if feed_state.get_last_seen(source_key) is not None:
                        stats["skipped"] += 1
                        continue

                if not feed_state.is_new(source_key, item_ts):
                    stats["skipped"] += 1
                    continue

                # Determine severity from title/desc
                combined = (title + " " + desc).lower()
                if any(k in combined for k in ("critical", "zero-day", "0-day", "actively exploit", "ransomware")):
                    severity = "CRITICAL"
                    risk = 8.5
                elif any(k in combined for k in ("high", "exploit", "rce", "remote code")):
                    severity = "HIGH"
                    risk = 7.0
                else:
                    severity = "MEDIUM"
                    risk = 5.0

                # Extract CVEs
                cves = re.findall(r"CVE-\d{4}-\d{4,7}", title + " " + desc, re.IGNORECASE)
                cves = list(dict.fromkeys(c.upper() for c in cves))[:5]

                item = _normalize_item(
                    source_key   = source_key,
                    title        = title,
                    source_url   = link,
                    published_at = published_at,
                    description  = desc,
                    tags         = cves + ["rss", urlparse(feed_url).netloc],
                    severity     = severity,
                    threat_type  = "THREAT-INTEL",
                    cves         = cves,
                    risk_score   = risk,
                )
                all_items.append(item)
                stats["new"] += 1
                new_items_this_feed += 1

                if item_ts and (newest_ts is None or item_ts > newest_ts):
                    newest_ts = item_ts

            if newest_ts:
                feed_state.update_last_seen(source_key, newest_ts)

        except Exception as e:
            log.warning("[RSS] Feed parse error %s: %s", feed_url[:60], e)

        feed_stats[source_key] = stats

    # Summary log
    total_new = sum(s["new"] for s in feed_stats.values())
    total_skip = sum(s["skipped"] for s in feed_stats.values())
    log.info(
        "[RSS] Ingestion complete: %d feeds, %d new items, %d skipped",
        len(rss_feeds), total_new, total_skip,
    )
    return all_items


# ═══════════════════════════════════════════════════════════════════════════
# MANIFEST I/O
# ═══════════════════════════════════════════════════════════════════════════

def _load_manifest() -> List[Dict]:
    if not MANIFEST_PATH.exists():
        return []
    try:
        raw = json.loads(MANIFEST_PATH.read_text(encoding="utf-8"))
        if isinstance(raw, list):
            return raw
        # Handle dict-wrapped manifests
        for key in ("entries", "items", "advisories", "data"):
            if key in raw and isinstance(raw[key], list):
                return raw[key]
        return []
    except Exception as e:
        log.error("[MANIFEST] Load failed: %s", e)
        return []


def _save_manifest(entries: List[Dict]) -> None:
    MANIFEST_PATH.parent.mkdir(parents=True, exist_ok=True)
    # Sort by published_at desc, falling back to processed_at
    def _sort_key(e: Dict) -> str:
        return str(e.get("published_at") or e.get("timestamp") or e.get("processed_at") or "")

    entries_sorted = sorted(entries, key=_sort_key, reverse=True)
    trimmed = entries_sorted[:MANIFEST_MAX_ENTRIES]

    tmp = MANIFEST_PATH.with_suffix(".tmp")
    try:
        tmp.write_text(json.dumps(trimmed, indent=2, ensure_ascii=False), encoding="utf-8")
        os.replace(tmp, MANIFEST_PATH)
        log.info("[MANIFEST] Saved: %d entries", len(trimmed))
    except Exception as e:
        log.error("[MANIFEST] Save failed: %s", e)


# ═══════════════════════════════════════════════════════════════════════════
# MERGE NEW ITEMS INTO MANIFEST (additive, deduped)
# ═══════════════════════════════════════════════════════════════════════════

def _merge_into_manifest(new_items: List[Dict], dedup: _IngestorDedup) -> Tuple[int, int]:
    """
    Load existing manifest, append new_items (dedup-filtered), save.
    Returns (items_added, items_skipped).
    """
    import html as _html_mod
    existing = _load_manifest()
    log.info("[MERGE] Existing manifest: %d entries", len(existing))

    # v145.0: Build in-manifest dedup sets so state-file failures never cause
    # duplicates. Checks stix_id, id, AND HTML-unescaped title.
    existing_sids: set = set()
    existing_ids: set = set()
    existing_titles: set = set()
    for e in existing:
        sid = e.get("stix_id") or ""
        eid = e.get("id") or ""
        ttl = _html_mod.unescape(e.get("title") or "").strip().lower()
        if sid: existing_sids.add(sid)
        if eid: existing_ids.add(eid)
        if ttl: existing_titles.add(ttl)

    added = 0
    skipped = 0

    for item in new_items:
        sid = item.get("stix_id") or ""
        eid = item.get("id") or ""
        ttl = _html_mod.unescape(item.get("title") or "").strip().lower()
        # Skip if already in manifest by stix_id, id, OR normalised title
        if (sid and sid in existing_sids) or \
           (eid and eid in existing_ids) or \
           (ttl and ttl in existing_titles):
            skipped += 1
            log.debug("[MERGE] In-manifest dedup skip: %s", ttl[:60])
            continue
        if dedup.is_duplicate(item):
            skipped += 1
            continue
        dedup.mark_seen(item)
        existing.append(item)
        if sid: existing_sids.add(sid)
        if eid: existing_ids.add(eid)
        if ttl: existing_titles.add(ttl)
        added += 1

    _save_manifest(existing)
    return added, skipped


# ═══════════════════════════════════════════════════════════════════════════
# MAIN INGESTION RUN
# ═══════════════════════════════════════════════════════════════════════════

class SourceStats:
    def __init__(self):
        self.sources: Dict[str, Dict] = {}

    def record(self, source: str, fetched: int, new: int, skipped: int, error: bool = False):
        self.sources[source] = {
            "fetched": fetched,
            "new": new,
            "skipped": skipped,
            "error": error,
        }

    def summary(self) -> Dict:
        total_fetched = sum(s["fetched"] for s in self.sources.values())
        total_new = sum(s["new"] for s in self.sources.values())
        total_skipped = sum(s["skipped"] for s in self.sources.values())
        return {
            "sources": self.sources,
            "total_fetched": total_fetched,
            "total_new": total_new,
            "total_skipped": total_skipped,
            "run_at": _utc_now(),
        }


def run_ingestion() -> Dict:
    """
    Full incremental ingestion run across all sources.
    Returns run stats dict.
    """
    log.info("=" * 70)
    log.info("CYBERDUDEBIVASH SENTINEL APEX — True Incremental Ingestor v142.0")
    log.info("=" * 70)

    feed_state = FeedState().load()
    dedup = _IngestorDedup().load()
    stats = SourceStats()

    all_new_items: List[Dict] = []

    # ── CISA KEV ────────────────────────────────────────────────────────────
    try:
        items = ingest_cisa_kev(feed_state)
        all_new_items.extend(items)
        stats.record("cisa_kev", len(items), len(items), 0)
    except Exception as e:
        log.error("[CISA-KEV] Source failed: %s", e)
        stats.record("cisa_kev", 0, 0, 0, error=True)

    # ── NVD CVE ─────────────────────────────────────────────────────────────
    try:
        items = ingest_nvd_cves(feed_state)
        all_new_items.extend(items)
        stats.record("nvd_cve", len(items), len(items), 0)
    except Exception as e:
        log.error("[NVD] Source failed: %s", e)
        stats.record("nvd_cve", 0, 0, 0, error=True)

    # ── GitHub Advisories ───────────────────────────────────────────────────
    try:
        items = ingest_github_advisories(feed_state)
        all_new_items.extend(items)
        stats.record("github_advisory", len(items), len(items), 0)
    except Exception as e:
        log.error("[GH-ADVISORY] Source failed: %s", e)
        stats.record("github_advisory", 0, 0, 0, error=True)

    # ── ransomware.live ─────────────────────────────────────────────────────
    try:
        items = ingest_ransomware_live(feed_state)
        all_new_items.extend(items)
        stats.record("ransomware_live", len(items), len(items), 0)
    except Exception as e:
        log.error("[RANSOMWARE-LIVE] Source failed: %s", e)
        stats.record("ransomware_live", 0, 0, 0, error=True)

    # ── URLhaus ─────────────────────────────────────────────────────────────
    try:
        items = ingest_urlhaus(feed_state)
        all_new_items.extend(items)
        stats.record("urlhaus", len(items), len(items), 0)
    except Exception as e:
        log.error("[URLHAUS] Source failed: %s", e)
        stats.record("urlhaus", 0, 0, 0, error=True)

    # ── RSS Feeds ────────────────────────────────────────────────────────────
    try:
        rss_items = ingest_rss_feeds(feed_state)
        all_new_items.extend(rss_items)
        stats.record("rss_feeds", len(rss_items), len(rss_items), 0)
    except Exception as e:
        log.error("[RSS] Source failed: %s", e)
        stats.record("rss_feeds", 0, 0, 0, error=True)

    log.info("[INGESTOR] Total candidate items across all sources: %d", len(all_new_items))

    # ── Merge into manifest (dedup-gated) ────────────────────────────────────
    added, skipped_dedup = _merge_into_manifest(all_new_items, dedup)
    log.info("[INGESTOR] Manifest update: +%d new, %d skipped (dedup)", added, skipped_dedup)

    # ── Persist state ────────────────────────────────────────────────────────
    feed_state.save()
    dedup.save()

    summary = stats.summary()
    summary["manifest_added"] = added
    summary["manifest_dedup_skipped"] = skipped_dedup

    # Print summary
    log.info("=" * 70)
    log.info("INGESTION COMPLETE")
    log.info("  Total new candidates : %d", summary["total_new"])
    log.info("  Manifest entries added: %d", added)
    log.info("  Dedup skipped        : %d", skipped_dedup)
    log.info("=" * 70)
    for src, s in summary["sources"].items():
        status = "ERROR" if s["error"] else "OK"
        log.info("  [%s] %s → fetched=%d new=%d skipped=%d",
                 status, src, s["fetched"], s["new"], s["skipped"])

    return summary


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="CyberDudeBivash True Intel Ingestor v142.0")
    parser.add_argument("--dry-run", action="store_true", help="Fetch and report without writing manifest")
    parser.add_argument("--reset-state", action="store_true", help="Reset feed_state.json (full re-scan)")
    parser.add_argument("--source", choices=["kev", "nvd", "github", "ransomware", "urlhaus", "rss"],
                        help="Run only a specific source")
    args = parser.parse_args()

    if args.reset_state:
        if FEED_STATE_PATH.exists():
            FEED_STATE_PATH.unlink()
            log.info("[RESET] feed_state.json deleted — next run will be full scan")

    if args.dry_run:
        log.info("[DRY-RUN] Fetching without manifest write")
        feed_state = FeedState().load()
        dedup = _IngestorDedup().load()

        sources = {
            "kev": lambda: ingest_cisa_kev(feed_state),
            "nvd": lambda: ingest_nvd_cves(feed_state),
            "github": lambda: ingest_github_advisories(feed_state),
            "ransomware": lambda: ingest_ransomware_live(feed_state),
            "urlhaus": lambda: ingest_urlhaus(feed_state),
            "rss": lambda: ingest_rss_feeds(feed_state),
        }

        if args.source:
            items = sources[args.source]()
            log.info("[DRY-RUN] %s: %d items would be ingested", args.source, len(items))
            for item in items[:5]:
                print(f"  → [{item.get('severity')}] {item.get('title', '')[:80]} | pub: {item.get('published_at')}")
        else:
            for src_name, fn in sources.items():
                items = fn()
                log.info("[DRY-RUN] %s: %d new items", src_name, len(items))
    else:
        result = run_ingestion()
        sys.exit(0 if result.get("manifest_added", 0) >= 0 else 1)
