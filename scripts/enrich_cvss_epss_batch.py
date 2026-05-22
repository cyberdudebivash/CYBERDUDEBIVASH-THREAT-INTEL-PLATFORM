#!/usr/bin/env python3
"""
SENTINEL APEX v148.1.0 — Batch CVSS / EPSS Enrichment Engine
=============================================================
ROOT CAUSE FIXED (v148.1.0):
  ALL items in api/feed.json had cvss_score: null (0 out of 207 had a real
  CVSS value). Intel reports therefore displayed "Pending" for CVSS and EPSS
  throughout every advisory, even for CVEs that have known NVD scores.

WHAT THIS SCRIPT DOES:
  1. Reads api/feed.json (the live feed powering the Worker / dashboard)
  2. Identifies items where a CVE ID appears in title/source_url and
     cvss_score is null / 0
  3. Batch-fetches CVSS v3.1 from NVD API v2.0
  4. Batch-fetches EPSS (30-day exploitation probability) from FIRST.org
  5. Writes enriched values back to api/feed.json (atomic swap)
  6. Writes a summary enrichment_report.json for pipeline observability

RATE LIMITING:
  Without NVD_API_KEY: 1 req / 6.5s  (≈ 5 req/30s — NVD free tier)
  With    NVD_API_KEY: 1 req / 0.7s  (≈ 50 req/30s)
  EPSS (first.org):    batch endpoint — up to 2000 CVEs per single call

ENVIRONMENT VARIABLES:
  NVD_API_KEY       — optional, increases NVD rate limit 10×
  FEED_PATH         — override feed location (default: api/feed.json)
  MAX_ENRICH        — cap CVEs to enrich per run (default: 150)
  DRY_RUN           — if "true", print changes without writing

USAGE:
  python3 scripts/enrich_cvss_epss_batch.py
  NVD_API_KEY=<key> python3 scripts/enrich_cvss_epss_batch.py
  MAX_ENRICH=50 python3 scripts/enrich_cvss_epss_batch.py
"""

from __future__ import annotations

import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ── Config ─────────────────────────────────────────────────────────────────────
REPO          = Path(__file__).resolve().parent.parent
FEED_PATH     = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
REPORT_PATH   = REPO / "data" / "enrichment_report.json"
MAX_ENRICH    = int(os.environ.get("MAX_ENRICH", "150"))
DRY_RUN       = os.environ.get("DRY_RUN", "false").strip().lower() == "true"

NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
NVD_API_KEY   = os.environ.get("NVD_API_KEY", "").strip()

# Rate limits
_THROTTLE_NO_KEY   = 6.5    # 5 req/30s with buffer
_THROTTLE_WITH_KEY = 0.7    # 50 req/30s with buffer
_last_nvd_call     = 0.0

# ── Logging ────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("enrich_cvss_epss")

# ── CVE ID Extractor ───────────────────────────────────────────────────────────
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)

def extract_cve_id(item: Dict) -> Optional[str]:
    """Extract the first CVE ID from title, source_url, id, or cve list fields.

    P0-FIX v159.0: also checks the 'cve' list field (set by run_pipeline.py
    STIX reconstruction path as intel_obj['cve'] = cve_ids). Without this fix
    all STIX-reconstructed CVE items were invisible to the enricher because
    their CVE IDs lived in the list field, not in title/id/source_url.
    """
    # Check scalar string fields first
    for field in ("title", "id", "stix_id", "source_url", "blog_url"):
        val = item.get(field) or ""
        m = _CVE_RE.search(str(val))
        if m:
            return m.group(0).upper()
    # Check the 'cve' list field (STIX reconstruction path)
    cve_list = item.get("cve") or []
    if isinstance(cve_list, list):
        for cve_val in cve_list:
            m = _CVE_RE.search(str(cve_val))
            if m:
                return m.group(0).upper()
    elif isinstance(cve_list, str):
        m = _CVE_RE.search(cve_list)
        if m:
            return m.group(0).upper()
    return None

# ── HTTP Helper ────────────────────────────────────────────────────────────────
def _http_get(url: str, headers: Optional[Dict] = None, timeout: int = 15) -> Optional[Dict]:
    try:
        req = urllib.request.Request(url, headers=headers or {})
        req.add_header("User-Agent", "CYBERDUDEBIVASH-SENTINEL-APEX/148.1.0 CVSS-Enricher")
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return json.loads(resp.read().decode("utf-8", errors="replace"))
    except urllib.error.HTTPError as exc:
        log.warning("HTTP %d for %s", exc.code, url[:100])
        return None
    except Exception as exc:
        log.warning("Request failed (%s): %s", url[:80], exc)
        return None

# ── NVD Rate Limiter ───────────────────────────────────────────────────────────
def _nvd_throttle() -> None:
    global _last_nvd_call
    wait    = _THROTTLE_WITH_KEY if NVD_API_KEY else _THROTTLE_NO_KEY
    elapsed = time.time() - _last_nvd_call
    if elapsed < wait:
        time.sleep(wait - elapsed)
    _last_nvd_call = time.time()

# ── CVSS Parser ────────────────────────────────────────────────────────────────
def _parse_cvss(nvd_item: Dict) -> Tuple[Optional[float], Optional[str]]:
    """
    Extract CVSS v3.1 (preferred) → v3.0 → v2.0 base score + vector.
    Returns (score, vector_string) or (None, None) if not available.
    """
    metrics = (nvd_item.get("cve") or {}).get("metrics") or {}
    # v3.1 (preferred)
    for entry in metrics.get("cvssMetricV31", []):
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        vec   = data.get("vectorString")
        if score is not None:
            return float(score), vec
    # v3.0 fallback
    for entry in metrics.get("cvssMetricV30", []):
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        vec   = data.get("vectorString")
        if score is not None:
            return float(score), vec
    # v2.0 last resort
    for entry in metrics.get("cvssMetricV2", []):
        data = entry.get("cvssData") or {}
        score = data.get("baseScore")
        vec   = data.get("vectorString")
        if score is not None:
            return float(score), vec
    return None, None

# ── NVD Fetch ──────────────────────────────────────────────────────────────────
def fetch_nvd_cvss(cve_id: str) -> Tuple[Optional[float], Optional[str]]:
    """Fetch CVSS score + vector from NVD API v2.0 for a single CVE."""
    _nvd_throttle()
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY
    url  = f"{NVD_API_BASE}?cveId={urllib.parse.quote(cve_id)}"
    data = _http_get(url, headers=headers, timeout=20)
    if not data or not data.get("vulnerabilities"):
        log.debug("NVD: no data for %s", cve_id)
        return None, None
    nvd_item = data["vulnerabilities"][0]
    score, vec = _parse_cvss(nvd_item)
    log.debug("NVD %s → CVSS %.1f  %s", cve_id, score or 0, vec or "")
    return score, vec

# ── EPSS Batch Fetch ───────────────────────────────────────────────────────────
def fetch_epss_batch(cve_ids: List[str]) -> Dict[str, float]:
    """
    Fetch EPSS exploitation-probability scores from FIRST.org in one call.
    Returns {cve_id: epss_pct_as_0_to_100} — e.g., {"CVE-2026-1234": 67.01}
    """
    if not cve_ids:
        return {}
    # FIRST.org supports comma-separated list (up to 2000 per call)
    chunk_size = 200
    results: Dict[str, float] = {}
    for i in range(0, len(cve_ids), chunk_size):
        chunk = cve_ids[i : i + chunk_size]
        cve_param = ",".join(chunk)
        url  = f"{EPSS_API_BASE}?cve={urllib.parse.quote(cve_param)}&limit={chunk_size}"
        data = _http_get(url, timeout=30)
        if data and data.get("data"):
            for entry in data["data"]:
                cid   = (entry.get("cve") or "").upper()
                score = entry.get("epss")
                if cid and score is not None:
                    # FIRST.org returns 0-1 fraction; convert to 0-100 percentage
                    results[cid] = round(float(score) * 100, 4)
        log.info("EPSS batch %d-%d: %d scores fetched", i, i + len(chunk), len(results))
        if i + chunk_size < len(cve_ids):
            time.sleep(0.5)  # polite pause between chunks
    return results

# ── Severity Derived from CVSS ─────────────────────────────────────────────────
def cvss_to_severity(score: float) -> str:
    if score >= 9.0:  return "CRITICAL"
    if score >= 7.0:  return "HIGH"
    if score >= 4.0:  return "MEDIUM"
    if score > 0.0:   return "LOW"
    return "NONE"

# ── Main Enrichment Engine ─────────────────────────────────────────────────────
def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX — CVSS/EPSS Batch Enrichment v148.1.0")
    log.info("Feed  : %s", FEED_PATH)
    log.info("DryRun: %s | MaxEnrich: %d | NVD key: %s",
             DRY_RUN, MAX_ENRICH, "YES" if NVD_API_KEY else "NO (rate-limited)")
    log.info("=" * 60)

    if not FEED_PATH.exists():
        log.error("Feed file not found: %s", FEED_PATH)
        return 1

    # Load feed
    try:
        raw = FEED_PATH.read_text(encoding="utf-8")
        feed_data = json.loads(raw)
    except Exception as exc:
        log.error("Failed to parse feed JSON: %s", exc)
        return 1

    items: List[Dict] = feed_data if isinstance(feed_data, list) else (feed_data.get("items") or [])
    if not items:
        log.warning("Feed has 0 items — nothing to enrich")
        return 0

    log.info("Loaded feed: %d items", len(items))

    # ── Pass 1: Identify CVE items needing enrichment ─────────────────────────
    needs_enrich: List[Tuple[int, str]] = []   # (index, cve_id)
    for idx, item in enumerate(items):
        cve_id = extract_cve_id(item)
        if not cve_id:
            continue
        # Needs enrichment if cvss_score missing/zero or epss_score missing
        cvss_null = item.get("cvss_score") is None or float(item.get("cvss_score") or 0) == 0.0
        epss_null = item.get("epss_score") is None
        if cvss_null or epss_null:
            needs_enrich.append((idx, cve_id))

    if not needs_enrich:
        log.info("All CVE items already have CVSS + EPSS data — nothing to do")
        return 0

    log.info("CVE items needing enrichment: %d (capped at %d)", len(needs_enrich), MAX_ENRICH)
    needs_enrich = needs_enrich[:MAX_ENRICH]

    # ── Pass 2: Batch-fetch EPSS for all CVE IDs at once ─────────────────────
    all_cve_ids = list({cve_id for _, cve_id in needs_enrich})
    log.info("Fetching EPSS for %d unique CVE IDs from FIRST.org...", len(all_cve_ids))
    epss_map = fetch_epss_batch(all_cve_ids)
    log.info("EPSS results: %d / %d CVEs scored", len(epss_map), len(all_cve_ids))

    # ── Pass 3: Fetch CVSS from NVD (per-CVE, rate-limited) ──────────────────
    cvss_map: Dict[str, Tuple[Optional[float], Optional[str]]] = {}
    cvss_needed = [cid for cid in all_cve_ids if float(
        # Fetch NVD only if item still has no CVSS score
        items[next(idx for idx, c in needs_enrich if c == cid)].get("cvss_score") or 0
    ) == 0.0]

    log.info("Fetching CVSS from NVD for %d CVEs...", len(cvss_needed))
    for i, cve_id in enumerate(cvss_needed):
        score, vec = fetch_nvd_cvss(cve_id)
        cvss_map[cve_id] = (score, vec)
        if score:
            log.info("[%d/%d] %s → CVSS %.1f", i + 1, len(cvss_needed), cve_id, score)
        else:
            log.info("[%d/%d] %s → CVSS not in NVD yet", i + 1, len(cvss_needed), cve_id)

    # ── Pass 4: Apply enrichments to feed items ───────────────────────────────
    enriched_count  = 0
    cvss_count      = 0
    epss_count      = 0
    skipped_count   = 0

    for idx, cve_id in needs_enrich:
        item          = items[idx]
        changed       = False

        # Apply CVSS
        cvss_score, cvss_vec = cvss_map.get(cve_id, (None, None))
        existing_cvss = float(item.get("cvss_score") or 0)
        if cvss_score and existing_cvss == 0.0:
            item["cvss_score"]   = cvss_score
            item["cvss_vector"]  = cvss_vec or item.get("cvss_vector")
            # Re-derive severity from CVSS (authoritative — overrides synthetic fallbacks)
            derived_sev  = cvss_to_severity(cvss_score)
            item["severity"] = derived_sev
            # P0-FIX v159.0: also update risk_score when _score_source is fallback.
            # run_pipeline.py STIX reconstruction used hardcoded 7.5/6.5 for all CVEs.
            # Now that we have real NVD CVSS data, overwrite the synthetic fallback value.
            _score_src = item.get("_score_source", "")
            existing_risk = float(item.get("risk_score") or 0)
            _is_synthetic_fallback = (
                _score_src == "fallback"
                or existing_risk in (7.5, 6.5)   # exact hardcoded fallback values
                or existing_risk == 0.0
            )
            if _is_synthetic_fallback:
                item["risk_score"]    = cvss_score
                item["_score_source"] = "nvd_cvss"
            changed    = True
            cvss_count += 1

        # Apply EPSS
        epss_pct = epss_map.get(cve_id)
        if epss_pct is not None and item.get("epss_score") is None:
            item["epss_score"] = epss_pct
            changed    = True
            epss_count += 1

        if changed:
            item["_enriched_at"]     = datetime.now(timezone.utc).isoformat()
            item["_enriched_by"]     = "enrich_cvss_epss_batch.py v148.1.0"
            enriched_count          += 1
        else:
            skipped_count += 1

    # ── Pass 5: Write back ─────────────────────────────────────────────────────
    log.info("─" * 60)
    log.info("Enrichment summary:")
    log.info("  Items processed : %d", len(needs_enrich))
    log.info("  CVSS updated    : %d", cvss_count)
    log.info("  EPSS updated    : %d", epss_count)
    log.info("  Items enriched  : %d", enriched_count)
    log.info("  Skipped (no data): %d", skipped_count)

    if DRY_RUN:
        log.info("[DRY RUN] Would write %d enriched items — skipping write", enriched_count)
        return 0

    if enriched_count == 0:
        log.info("No enrichments applied — feed unchanged")
        return 0

    # Atomic write (write to .tmp then rename)
    tmp_path = FEED_PATH.with_suffix(".tmp_enrich")
    try:
        out_data = items if isinstance(feed_data, list) else {**feed_data, "items": items}
        tmp_path.write_text(json.dumps(out_data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(FEED_PATH)
        log.info("Feed written: %s (%d items)", FEED_PATH, len(items))
    except Exception as exc:
        log.error("Write failed: %s", exc)
        tmp_path.unlink(missing_ok=True)
        return 1

    # Write enrichment report for pipeline observability
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at":    datetime.now(timezone.utc).isoformat(),
        "script":          "enrich_cvss_epss_batch.py",
        "version":         "148.1.0",
        "feed_total_items": len(items),
        "cve_items_found": len(needs_enrich),
        "cvss_enriched":   cvss_count,
        "epss_enriched":   epss_count,
        "total_enriched":  enriched_count,
        "skipped":         skipped_count,
        "nvd_key_used":    bool(NVD_API_KEY),
        "dry_run":         DRY_RUN,
    }
    try:
        REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Enrichment report: %s", REPORT_PATH)
    except Exception:
        pass  # non-fatal

    log.info("=" * 60)
    log.info("CVSS/EPSS enrichment complete — %d items updated", enriched_count)
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
