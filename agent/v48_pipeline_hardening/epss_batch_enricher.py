#!/usr/bin/env python3
"""
epss_batch_enricher.py — CYBERDUDEBIVASH® SENTINEL APEX v48.0
Batch EPSS/CVSS enrichment with persistent local cache.

FIXES BUG-03: 70% of manifest entries have null epss_score/cvss_score
because _enrich_cve_metadata() in sentinel_blogger.py uses individual
API calls with 6-8s timeouts that frequently fail in GitHub Actions.

SOLUTION:
  1. Cache all EPSS/CVSS scores locally (24h TTL)
  2. Batch EPSS lookups (up to 30 CVEs per API call)
  3. Rate-limited NVD CVSS lookups with API key support
  4. Runs as post-pipeline enrichment pass

Usage:
    python agent/v48_pipeline_hardening/epss_batch_enricher.py
"""

import json
import os
import re
import time
import logging
import urllib.request
import urllib.error
from typing import Dict, List, Optional

logger = logging.getLogger("CDB-EPSS-BATCH")

EPSS_CACHE_FILE = "data/enrichment/epss_cache.json"
EPSS_CACHE_TTL = 24 * 3600  # 24 hours
EPSS_BATCH_API = "https://api.first.org/data/v1/epss"
NVD_CVE_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"
MANIFEST_PATH = "data/stix/feed_manifest.json"


class EPSSBatchEnricher:

    def __init__(self):
        self._cache: Dict[str, Dict] = {}
        self._loaded = False

    def _load_cache(self):
        if self._loaded:
            return
        try:
            if os.path.exists(EPSS_CACHE_FILE):
                with open(EPSS_CACHE_FILE, "r") as f:
                    raw = json.load(f)
                now = time.time()
                self._cache = {
                    k: v for k, v in raw.items()
                    if now - v.get("ts", 0) < EPSS_CACHE_TTL
                }
        except Exception:
            self._cache = {}
        self._loaded = True

    def _save_cache(self):
        try:
            os.makedirs(os.path.dirname(EPSS_CACHE_FILE) or ".", exist_ok=True)
            if len(self._cache) > 5000:
                items = sorted(self._cache.items(), key=lambda x: x[1].get("ts", 0), reverse=True)
                self._cache = dict(items[:3000])
            with open(EPSS_CACHE_FILE, "w") as f:
                json.dump(self._cache, f)
        except Exception as e:
            logger.debug(f"Cache save failed: {e}")

    def _fetch_epss_batch(self, cve_ids: List[str]) -> Dict[str, float]:
        """Fetch EPSS for up to 30 CVEs in one call."""
        if not cve_ids:
            return {}
        results = {}
        try:
            param = ",".join(cve_ids[:30])
            url = f"{EPSS_BATCH_API}?cve={param}"
            req = urllib.request.Request(url, headers={
                "User-Agent": "CDB-Sentinel/48.0",
                "Accept": "application/json",
            })
            with urllib.request.urlopen(req, timeout=20) as resp:
                data = json.loads(resp.read())
            for entry in data.get("data", []):
                cve = entry.get("cve", "").upper()
                epss = entry.get("epss")
                if cve and epss is not None:
                    results[cve] = round(float(epss) * 100, 2)
        except Exception as e:
            logger.warning(f"EPSS batch failed: {e}")
        return results

    def _fetch_cvss(self, cve_id: str) -> Optional[float]:
        """Fetch CVSS from NVD."""
        try:
            headers = {"User-Agent": "CDB-Sentinel/48.0"}
            nvd_key = os.getenv("NVD_API_KEY", "")
            if nvd_key:
                headers["apiKey"] = nvd_key
            url = f"{NVD_CVE_API}?cveId={cve_id.upper()}"
            req = urllib.request.Request(url, headers=headers)
            with urllib.request.urlopen(req, timeout=15) as resp:
                data = json.loads(resp.read())
            vuln = data.get("vulnerabilities", [{}])[0].get("cve", {})
            metrics = vuln.get("metrics", {})
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                if key in metrics and metrics[key]:
                    score = metrics[key][0].get("cvssData", {}).get("baseScore")
                    if score:
                        return float(score)
        except Exception:
            pass
        return None

    def enrich_manifest(self, manifest_path: str = MANIFEST_PATH) -> int:
        """Batch-enrich all manifest entries. Returns count updated."""
        self._load_cache()

        if not os.path.exists(manifest_path):
            return 0

        try:
            with open(manifest_path) as f:
                manifest = json.load(f)
        except Exception:
            return 0

        if not isinstance(manifest, list):
            return 0

        # Phase 1: Apply cached values first (instant)
        updated = 0
        cves_need_epss = []
        cves_need_cvss = []

        for entry in manifest:
            cve_match = re.search(r"CVE-\d{4}-\d{4,7}", entry.get("title", ""), re.IGNORECASE)
            if not cve_match:
                continue
            cve_id = cve_match.group().upper()

            # Apply from cache
            if cve_id in self._cache:
                cached = self._cache[cve_id]
                if entry.get("epss_score") is None and cached.get("epss") is not None:
                    entry["epss_score"] = cached["epss"]
                    updated += 1
                if entry.get("cvss_score") is None and cached.get("cvss") is not None:
                    entry["cvss_score"] = cached["cvss"]
                    updated += 1
                continue

            if entry.get("epss_score") is None:
                cves_need_epss.append((cve_id, entry))
            if entry.get("cvss_score") is None:
                cves_need_cvss.append((cve_id, entry))

        # Phase 2: Batch EPSS API calls
        epss_ids = list(set(c[0] for c in cves_need_epss))
        for i in range(0, len(epss_ids), 30):
            batch = epss_ids[i:i + 30]
            scores = self._fetch_epss_batch(batch)
            for cve_id in batch:
                if cve_id in scores:
                    self._cache.setdefault(cve_id, {"ts": time.time()})
                    self._cache[cve_id]["epss"] = scores[cve_id]
                    self._cache[cve_id]["ts"] = time.time()
            # Apply to entries
            for cve_id, entry in cves_need_epss:
                if cve_id in scores and entry.get("epss_score") is None:
                    entry["epss_score"] = scores[cve_id]
                    updated += 1
            time.sleep(1)

        # Phase 3: NVD CVSS (rate-limited, max 15 per run)
        cvss_ids = list(set(c[0] for c in cves_need_cvss))
        for cve_id in cvss_ids[:15]:
            cvss = self._fetch_cvss(cve_id)
            if cvss is not None:
                self._cache.setdefault(cve_id, {"ts": time.time()})
                self._cache[cve_id]["cvss"] = cvss
                self._cache[cve_id]["ts"] = time.time()
                # Apply to all matching entries
                for c, entry in cves_need_cvss:
                    if c == cve_id and entry.get("cvss_score") is None:
                        entry["cvss_score"] = cvss
                        updated += 1
            time.sleep(2)  # NVD rate limit

        # Write back
        if updated > 0:
            try:
                with open(manifest_path, "w") as f:
                    json.dump(manifest, f, indent=4)
                logger.info(f"EPSS/CVSS batch: {updated} fields enriched")
            except Exception as e:
                logger.warning(f"Manifest write failed: {e}")

        self._save_cache()
        return updated


# CLI entry point
if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [CDB-EPSS] %(message)s")
    enricher = EPSSBatchEnricher()
    count = enricher.enrich_manifest()
    print(f"EPSS/CVSS batch enrichment complete: {count} fields updated")
