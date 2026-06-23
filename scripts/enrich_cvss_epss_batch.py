#!/usr/bin/env python3
"""
SENTINEL APEX v185.0 — Batch CVSS / EPSS Enrichment Engine
===========================================================
GOD-MODE PRODUCTION HARDENING (v185.0):
  Complete rewrite of timeout/reliability architecture to guarantee:
  1. Partial enrichment is ALWAYS persisted — never silently lost
  2. NVD 503 storms are survived via retry+circuit-breaker
  3. Wall-clock budget prevents step-timeout data loss
  4. Reduced per-request timeout keeps NVD calls fast
  5. Year-based NVD skip avoids wasting time on 2026 CVEs not yet in NVD
  6. Full observability: per-item outcome logged with elapsed time

ROOT CAUSE FIXED (v148.1.0 original):
  ALL items in api/feed.json had cvss_score: null (0 out of 207 had a real
  CVSS value). Intel reports therefore displayed "Pending" for CVSS and EPSS
  throughout every advisory, even for CVEs that have known NVD scores.

ROOT CAUSE FIXED (v185.0 production hardening):
  STAGE 3.1.2 was timing out at 12 min because 89 sequential NVD API calls
  each burning up to 20s per 503/timeout = 29+ minutes total. The atomic
  write-at-end pattern lost ALL partial work when GitHub Actions killed the
  process. Now: wall-clock budget flushes partial results before timeout.

WHAT THIS SCRIPT DOES:
  1. Reads api/feed.json (the live feed powering the Worker / dashboard)
  2. Identifies items where a CVE ID appears in title/source_url and
     cvss_score is null / 0
  3. Batch-fetches EPSS (30-day exploitation probability) from FIRST.org
  4. Fetches CVSS v3.1 from NVD API v2.0 (per-CVE, rate-limited + retry)
  5. Flushes partial results if wall-clock budget is exceeded (never loses work)
  6. Writes enriched values back to api/feed.json (atomic swap)
  7. Writes enrichment_report.json for pipeline observability

RATE LIMITING:
  Without NVD_API_KEY: 1 req / 6.5s  (≈ 5 req/30s — NVD free tier)
  With    NVD_API_KEY: 1 req / 0.7s  (≈ 50 req/30s)
  EPSS (first.org):    batch endpoint — up to 2000 CVEs per single call

ENVIRONMENT VARIABLES:
  NVD_API_KEY         — optional; increases NVD rate limit 10×
  FEED_PATH           — override feed location (default: api/feed.json)
  MAX_ENRICH          — cap CVEs to enrich per run (default: 100)
  DRY_RUN             — if "true", print changes without writing
  WALL_CLOCK_BUDGET   — seconds budget before partial flush (default: 600)

USAGE:
  python3 scripts/enrich_cvss_epss_batch.py
  NVD_API_KEY=<key> MAX_ENRICH=100 python3 scripts/enrich_cvss_epss_batch.py
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
from typing import Any, Dict, List, Optional, Set, Tuple

# ── Config ──────────────────────────────────────────────────────────────────────
REPO          = Path(__file__).resolve().parent.parent
FEED_PATH     = Path(os.environ.get("FEED_PATH", str(REPO / "api" / "feed.json")))
REPORT_PATH   = REPO / "data" / "enrichment_report.json"
MAX_ENRICH    = int(os.environ.get("MAX_ENRICH", "100"))
DRY_RUN       = os.environ.get("DRY_RUN", "false").strip().lower() == "true"

NVD_API_BASE  = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EPSS_API_BASE = "https://api.first.org/data/v1/epss"
NVD_API_KEY   = os.environ.get("NVD_API_KEY", "").strip()

# Rate limits
_THROTTLE_NO_KEY   = 6.5   # 5 req/30s — NVD free tier (with buffer)
_THROTTLE_WITH_KEY = 0.7   # 50 req/30s — NVD with API key (with buffer)
_last_nvd_call     = 0.0

# ── v185.0 GOD-MODE: Wall-clock budget + fast timeout + circuit breaker ─────────
# Wall-clock budget: flush partial results before GitHub Actions kills the process.
# Default 600s (10 min) leaves 2+ min headroom before the 20-min step timeout.
_WALL_CLOCK_BUDGET_SECONDS = int(os.environ.get("WALL_CLOCK_BUDGET", "600"))
_PIPELINE_START_TIME       = time.monotonic()

# Per-request NVD timeout: 8s (was 20s). With 0.7s throttle + retry this is
# aggressive enough to catch slow responses without burning 20s per 503.
_NVD_REQUEST_TIMEOUT = 8

# Retry config: up to 2 retries on 503/timeout with exponential backoff.
# This survives short NVD rate-limit windows without full job failure.
_NVD_MAX_RETRIES  = 2
_NVD_RETRY_BASE_S = 2.0  # 2s, then 4s

# Circuit breaker: if _CB_FAIL_THRESHOLD consecutive NVD calls fail,
# skip remaining NVD calls and flush partial results (NVD is down).
_CB_FAIL_THRESHOLD   = 8
_consecutive_nvd_failures = 0

# Current year for PRELIMINARY skip optimisation
_CURRENT_YEAR = datetime.now(timezone.utc).year

# ── Logging ─────────────────────────────────────────────────────────────────────
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%H:%M:%S",
)
log = logging.getLogger("enrich_cvss_epss")

# ── CVE ID Extractor ────────────────────────────────────────────────────────────
_CVE_RE = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.IGNORECASE)


def extract_cve_id(item: Dict) -> Optional[str]:
    """Extract the first CVE ID from title, source_url, id, or cve list fields."""
    for field in ("title", "id", "stix_id", "source_url", "blog_url"):
        val = item.get(field) or ""
        m = _CVE_RE.search(str(val))
        if m:
            return m.group(0).upper()
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


def _cve_year(cve_id: str) -> int:
    """Extract year from CVE-YYYY-NNNNN. Returns 0 on parse failure."""
    try:
        return int(cve_id.split("-")[1])
    except Exception:
        return 0


# ── Budget helpers ───────────────────────────────────────────────────────────────
def _elapsed() -> float:
    return time.monotonic() - _PIPELINE_START_TIME


def _budget_remaining() -> float:
    return _WALL_CLOCK_BUDGET_SECONDS - _elapsed()


def _budget_ok(reserve: float = 45.0) -> bool:
    """True if enough budget remains for at least one more NVD round-trip."""
    return _budget_remaining() > reserve


# ── HTTP helper with retry + backoff ────────────────────────────────────────────
def _http_get(
    url: str,
    headers: Optional[Dict] = None,
    timeout: int = 15,
    retries: int = 0,
    retry_base: float = 2.0,
) -> Optional[Dict]:
    """HTTP GET with retry on 429/503. Returns parsed JSON or None."""
    attempt = 0
    while True:
        try:
            req = urllib.request.Request(url, headers=headers or {})
            req.add_header(
                "User-Agent",
                "CYBERDUDEBIVASH-SENTINEL-APEX/185.0 CVSS-Enricher (production)",
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                return json.loads(resp.read().decode("utf-8", errors="replace"))
        except urllib.error.HTTPError as exc:
            if exc.code in (429, 503) and attempt < retries:
                wait = retry_base * (2 ** attempt)
                log.warning("HTTP %d — retry %d/%d in %.0fs (%s)", exc.code, attempt + 1, retries, wait, url[:80])
                time.sleep(wait)
                attempt += 1
                continue
            log.warning("HTTP %d for %s", exc.code, url[:100])
            return None
        except Exception as exc:
            if attempt < retries:
                wait = retry_base * (2 ** attempt)
                log.warning("Request error — retry %d/%d in %.0fs (%s): %s", attempt + 1, retries, wait, url[:60], exc)
                time.sleep(wait)
                attempt += 1
                continue
            log.warning("Request failed (%s): %s", url[:80], exc)
            return None


# ── Atomic write helper ──────────────────────────────────────────────────────────
def _write_feed(feed_data: Any, items: List[Dict], feed_path: Path, label: str = "") -> bool:
    """Atomic write via tmp-then-rename. Returns True on success."""
    tmp_path = feed_path.with_suffix(".tmp_enrich")
    try:
        out_data = items if isinstance(feed_data, list) else {**feed_data, "items": items}
        tmp_path.write_text(json.dumps(out_data, ensure_ascii=False, indent=2), encoding="utf-8")
        tmp_path.replace(feed_path)
        lbl = f" [{label}]" if label else ""
        log.info("Feed written%s: %s (%d items)", lbl, feed_path, len(items))
        return True
    except Exception as exc:
        log.error("Write failed: %s", exc)
        tmp_path.unlink(missing_ok=True)
        return False


# ── NVD Rate Limiter ─────────────────────────────────────────────────────────────
def _nvd_throttle() -> None:
    global _last_nvd_call
    wait    = _THROTTLE_WITH_KEY if NVD_API_KEY else _THROTTLE_NO_KEY
    elapsed = time.time() - _last_nvd_call
    if elapsed < wait:
        time.sleep(wait - elapsed)
    _last_nvd_call = time.time()


# ── CVSS Parser ─────────────────────────────────────────────────────────────────
def _parse_cvss(nvd_item: Dict) -> Tuple[Optional[float], Optional[str]]:
    """Extract CVSS v3.1 → v3.0 → v2.0 base score + vector. Returns (score, vec)."""
    metrics = (nvd_item.get("cve") or {}).get("metrics") or {}
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        for entry in metrics.get(key, []):
            data  = entry.get("cvssData") or {}
            score = data.get("baseScore")
            vec   = data.get("vectorString")
            if score is not None:
                return float(score), vec
    return None, None


# ── NVD Fetch with circuit breaker ───────────────────────────────────────────────
def fetch_nvd_cvss(cve_id: str) -> Tuple[Optional[float], Optional[str]]:
    """Fetch CVSS from NVD with retry + circuit-breaker.

    v185.0 GOD-MODE changes vs v148:
      - Timeout 20s → 8s (fast-fail on slow NVD)
      - Retry 0 → 2 times on 503/429 with exponential backoff
      - Circuit-breaker: after _CB_FAIL_THRESHOLD consecutive failures, returns
        (None, None) immediately without hitting NVD (it's down)
    """
    global _consecutive_nvd_failures

    if _consecutive_nvd_failures >= _CB_FAIL_THRESHOLD:
        log.warning("NVD circuit-breaker OPEN (%d consecutive fails) — skipping %s",
                    _consecutive_nvd_failures, cve_id)
        return None, None

    _nvd_throttle()
    headers = {}
    if NVD_API_KEY:
        headers["apiKey"] = NVD_API_KEY

    url  = f"{NVD_API_BASE}?cveId={urllib.parse.quote(cve_id)}"
    data = _http_get(url, headers=headers, timeout=_NVD_REQUEST_TIMEOUT,
                     retries=_NVD_MAX_RETRIES, retry_base=_NVD_RETRY_BASE_S)

    if not data or not data.get("vulnerabilities"):
        _consecutive_nvd_failures += 1
        return None, None

    # Success — reset circuit breaker
    _consecutive_nvd_failures = 0
    nvd_item = data["vulnerabilities"][0]
    score, vec = _parse_cvss(nvd_item)
    return score, vec


# ── EPSS Batch Fetch ─────────────────────────────────────────────────────────────
def fetch_epss_batch(cve_ids: List[str]) -> Dict[str, float]:
    """Batch-fetch EPSS scores from FIRST.org. Returns {cve_id: 0-1 fraction}."""
    if not cve_ids:
        return {}
    chunk_size = 200
    results: Dict[str, float] = {}
    for i in range(0, len(cve_ids), chunk_size):
        chunk    = cve_ids[i : i + chunk_size]
        cve_param = ",".join(chunk)
        url      = f"{EPSS_API_BASE}?cve={urllib.parse.quote(cve_param)}&limit={chunk_size}"
        data     = _http_get(url, timeout=30, retries=1, retry_base=3.0)
        if data and data.get("data"):
            for entry in data["data"]:
                cid   = (entry.get("cve") or "").upper()
                score = entry.get("epss")
                if cid and score is not None:
                    raw = float(score)
                    if raw > 1.0:
                        raw = min(raw / 100.0, 1.0)
                        log.warning("EPSS anomaly corrected: %.4f → %.6f (%s)", float(score), raw, cid)
                    results[cid] = round(max(0.0, min(1.0, raw)), 6)
        log.info("EPSS batch %d-%d: %d scores fetched", i, i + len(chunk), len(results))
        if i + chunk_size < len(cve_ids):
            time.sleep(0.5)
    return results


# ── Severity from CVSS ───────────────────────────────────────────────────────────
def cvss_to_severity(score: float) -> str:
    if score >= 9.0: return "CRITICAL"
    if score >= 7.0: return "HIGH"
    if score >= 4.0: return "MEDIUM"
    if score > 0.0:  return "LOW"
    return "NONE"


# ── Main ─────────────────────────────────────────────────────────────────────────
def main() -> int:
    log.info("=" * 60)
    log.info("SENTINEL APEX — CVSS/EPSS Batch Enrichment v185.0 [GOD-MODE]")
    log.info("Feed    : %s", FEED_PATH)
    log.info("DryRun  : %s | MaxEnrich: %d | NVD key: %s",
             DRY_RUN, MAX_ENRICH, "YES" if NVD_API_KEY else "NO")
    log.info("Budget  : %ds | Timeout/req: %ds | Retries: %d | CB threshold: %d",
             _WALL_CLOCK_BUDGET_SECONDS, _NVD_REQUEST_TIMEOUT,
             _NVD_MAX_RETRIES, _CB_FAIL_THRESHOLD)
    log.info("=" * 60)

    if not FEED_PATH.exists():
        log.error("Feed not found: %s", FEED_PATH)
        return 1

    try:
        raw       = FEED_PATH.read_text(encoding="utf-8")
        feed_data = json.loads(raw)
    except Exception as exc:
        log.error("Failed to parse feed: %s", exc)
        return 1

    items: List[Dict] = feed_data if isinstance(feed_data, list) else (feed_data.get("items") or [])
    if not items:
        log.warning("Feed has 0 items — nothing to enrich")
        return 0

    log.info("Loaded feed: %d items", len(items))

    # ── Pass 0: EPSS normalization — canonical 0-1 decimal fraction ─────────────
    epss_repaired = 0
    for item in items:
        existing = item.get("epss_score")
        if existing is None:
            continue
        try:
            val = float(existing)
            if val > 1.0:
                item["epss_score"] = min(round(val / 100.0, 6), 1.0)
                log.warning("EPSS normalize: %.4f → %.6f (%s)", val, item["epss_score"],
                            str(item.get("title", ""))[:55])
                epss_repaired += 1
            elif val < 0.0:
                item["epss_score"] = 0.0
                epss_repaired += 1
        except (TypeError, ValueError):
            item["epss_score"] = None
            epss_repaired += 1
    if epss_repaired:
        log.info("EPSS normalization: corrected %d item(s)", epss_repaired)

    # ── Pass 1: Identify CVE items needing enrichment ───────────────────────────
    needs_enrich: List[Tuple[int, str]] = []
    for idx, item in enumerate(items):
        cve_id = extract_cve_id(item)
        if not cve_id:
            continue
        cvss_null = item.get("cvss_score") is None or float(item.get("cvss_score") or 0) == 0.0
        epss_null = item.get("epss_score") is None
        if cvss_null or epss_null:
            needs_enrich.append((idx, cve_id))

    if not needs_enrich:
        log.info("All CVE items already have CVSS + EPSS data — nothing to do")
        return 0

    log.info("CVE items needing enrichment: %d (capped at %d)", len(needs_enrich), MAX_ENRICH)
    needs_enrich = needs_enrich[:MAX_ENRICH]

    # ── Pass 2: Batch EPSS from FIRST.org (single call, all CVEs) ───────────────
    all_cve_ids = list({cve_id for _, cve_id in needs_enrich})
    log.info("Fetching EPSS for %d unique CVEs from FIRST.org...", len(all_cve_ids))
    epss_map = fetch_epss_batch(all_cve_ids)
    log.info("EPSS: %d / %d CVEs scored", len(epss_map), len(all_cve_ids))

    # ── Pass 3: NVD CVSS (per-CVE, rate-limited + retry + circuit-breaker) ──────
    cvss_map: Dict[str, Tuple[Optional[float], Optional[str]]] = {}
    _cve_first_idx: Dict[str, int] = {}
    for _idx, _cid in needs_enrich:
        _cve_first_idx.setdefault(_cid, _idx)
    cvss_needed = [
        cid for cid in all_cve_ids
        if cid in _cve_first_idx
        and float(items[_cve_first_idx[cid]].get("cvss_score") or 0) == 0.0
    ]

    log.info("Fetching CVSS from NVD for %d CVEs...", len(cvss_needed))
    nvd_not_found:   Set[str] = set()
    nvd_skipped_prelim = 0   # CVEs skipped because already PRELIMINARY from a prior run
    budget_interrupted = False
    cb_tripped         = False

    for i, cve_id in enumerate(cvss_needed):
        # Budget check: flush partial work if time is almost up
        if not _budget_ok(reserve=50):
            log.warning(
                "WALL-CLOCK BUDGET exhausted at item %d/%d (%.0fs / %ds) — "
                "flushing partial enrichment to preserve work.",
                i + 1, len(cvss_needed), _elapsed(), _WALL_CLOCK_BUDGET_SECONDS,
            )
            budget_interrupted = True
            for remaining in cvss_needed[i:]:
                if remaining not in cvss_map:
                    cvss_map[remaining] = (None, None)
                    nvd_not_found.add(remaining)
            break

        # Circuit-breaker check
        if _consecutive_nvd_failures >= _CB_FAIL_THRESHOLD:
            log.warning(
                "NVD circuit-breaker OPEN — skipping remaining %d CVEs "
                "(NVD appears down; partial results will be flushed).",
                len(cvss_needed) - i,
            )
            cb_tripped = True
            for remaining in cvss_needed[i:]:
                if remaining not in cvss_map:
                    cvss_map[remaining] = (None, None)
                    nvd_not_found.add(remaining)
            break

        # v185.0 optimisation: skip NVD call for current-year CVEs already
        # tagged PRELIMINARY in a prior run — NVD won't have them yet.
        item_idx = next((idx for idx, c in needs_enrich if c == cve_id), None)
        if item_idx is not None:
            item_nvd_status = items[item_idx].get("nvd_status", "")
            if item_nvd_status == "PRELIMINARY" and _cve_year(cve_id) >= _CURRENT_YEAR:
                cvss_map[cve_id] = (None, None)
                nvd_not_found.add(cve_id)
                nvd_skipped_prelim += 1
                log.debug("[%d/%d] %s — skip NVD (already PRELIMINARY, year=%d)",
                          i + 1, len(cvss_needed), cve_id, _cve_year(cve_id))
                continue

        score, vec = fetch_nvd_cvss(cve_id)
        cvss_map[cve_id] = (score, vec)
        if score is not None:
            log.info("[%d/%d] %s → CVSS %.1f (%.0fs elapsed)",
                     i + 1, len(cvss_needed), cve_id, score, _elapsed())
        else:
            nvd_not_found.add(cve_id)
            log.warning("[%d/%d] %s → NOT IN NVD — nvd_status=PRELIMINARY",
                        i + 1, len(cvss_needed), cve_id)

    # ── Pass 4: Apply enrichments to feed items ──────────────────────────────────
    enriched_count = cvss_count = epss_count = skipped_count = preliminary_count = 0

    for idx, cve_id in needs_enrich:
        item    = items[idx]
        changed = False

        # Apply CVSS
        cvss_score, cvss_vec = cvss_map.get(cve_id, (None, None))
        if cvss_score is not None and float(item.get("cvss_score") or 0) == 0.0:
            item["cvss_score"]  = cvss_score
            item["cvss_vector"] = cvss_vec or item.get("cvss_vector")
            item["severity"]    = cvss_to_severity(cvss_score)
            _src = item.get("_score_source", "")
            _risk = float(item.get("risk_score") or 0)
            if _src == "fallback" or _risk in (7.5, 6.5) or _risk == 0.0:
                item["risk_score"]    = cvss_score
                item["_score_source"] = "nvd_cvss"
            item["nvd_status"]     = "CONFIRMED"
            item["nvd_checked_at"] = datetime.now(timezone.utc).isoformat()
            changed    = True
            cvss_count += 1

        elif cve_id in nvd_not_found and item.get("nvd_status") not in ("CONFIRMED",):
            if item.get("nvd_status") not in ("CONFIRMED", "PRELIMINARY"):
                item["nvd_status"]     = "PRELIMINARY"
                item["nvd_checked_at"] = datetime.now(timezone.utc).isoformat()
                item["nvd_disclosure"] = (
                    "This CVE ID was not found in the NIST NVD database at time of "
                    "enrichment. Intelligence is preliminary and unverified by NVD. "
                    "CVSS score and severity are analyst-estimated until NVD confirmation."
                )
                changed = True
                preliminary_count += 1

        # Migrate legacy EPSS 0-100 → 0-1
        existing_epss = item.get("epss_score")
        if existing_epss is not None:
            try:
                _ev = float(existing_epss)
                if _ev > 1.0:
                    item["epss_score"] = round(min(_ev / 100.0, 1.0), 6)
                    changed = True
            except (TypeError, ValueError):
                item["epss_score"] = None

        # Apply EPSS
        epss_frac = epss_map.get(cve_id)
        if epss_frac is not None and item.get("epss_score") is None:
            item["epss_score"] = round(min(max(epss_frac, 0.0), 1.0), 6)
            changed    = True
            epss_count += 1

        if changed:
            item["_enriched_at"] = datetime.now(timezone.utc).isoformat()
            item["_enriched_by"] = "enrich_cvss_epss_batch.py v185.0"
            enriched_count += 1
        else:
            skipped_count += 1

    # ── Pass 4.5: source_url for CVE items missing it ────────────────────────────
    PLATFORM_BASE    = "https://intel.cyberdudebivash.com"
    source_url_count = blog_url_count = 0
    for item in items:
        if not item.get("source_url"):
            item_cve = extract_cve_id(item)
            if item_cve:
                confirmed = (item.get("nvd_status") == "CONFIRMED"
                             or float(item.get("cvss_score") or 0) > 0)
                item["source_url"] = (
                    f"https://nvd.nist.gov/vuln/detail/{item_cve}" if confirmed
                    else f"https://cve.mitre.org/cgi-bin/cvename.cgi?name={item_cve}"
                )
                source_url_count += 1
        if not item.get("blog_url"):
            item_id = str(item.get("id") or item.get("stix_id") or "").strip()
            if item_id:
                item["blog_url"] = f"{PLATFORM_BASE}/reports/{item_id}/"
                blog_url_count  += 1

    # ── Pass 4.7: Severity realignment ───────────────────────────────────────────
    sev_aligned = 0
    for item in items:
        try:
            risk = float(item.get("risk_score") or item.get("cvss_score") or 0)
        except (TypeError, ValueError):
            continue
        if risk <= 0:
            continue
        correct = cvss_to_severity(risk)
        current = (item.get("severity") or "").upper().strip()
        if current and current != correct:
            item["severity"] = correct
            sev_aligned += 1

    if source_url_count:
        log.info("Pass 4.5: source_url filled for %d items", source_url_count)
    if blog_url_count:
        log.info("Pass 4.6: blog_url filled for %d items", blog_url_count)
    if sev_aligned:
        log.info("Pass 4.7: severity realigned for %d items", sev_aligned)

    # ── Pass 5: Write (always — even on budget interrupt / CB trip) ──────────────
    elapsed_total = _elapsed()
    write_label   = (
        "BUDGET-PARTIAL" if budget_interrupted
        else "CB-PARTIAL" if cb_tripped
        else "FULL"
    )
    if nvd_skipped_prelim:
        log.info("NVD skip optimisation: %d CVEs skipped (already PRELIMINARY, year >= %d)",
                 nvd_skipped_prelim, _CURRENT_YEAR)
    log.info("-" * 60)
    log.info("Enrichment summary [%s] (elapsed: %.0fs / budget: %ds):", write_label, elapsed_total, _WALL_CLOCK_BUDGET_SECONDS)
    log.info("  Items processed   : %d", len(needs_enrich))
    log.info("  CVSS confirmed    : %d (NVD)", cvss_count)
    log.info("  EPSS updated      : %d", epss_count)
    log.info("  PRELIMINARY tagged: %d", preliminary_count)
    log.info("  Items enriched    : %d", enriched_count)
    log.info("  Skipped (no data) : %d", skipped_count)
    log.info("  NVD CB trips      : %d consecutive fails at trip", _consecutive_nvd_failures if cb_tripped else 0)

    if preliminary_count:
        log.warning(
            "NVD-PRELIMINARY GATE: %d CVE(s) not confirmed in NVD. "
            "Tagged PRELIMINARY with disclosure. Review before claiming NVD-validated intel.",
            preliminary_count,
        )
    if budget_interrupted:
        log.warning(
            "BUDGET-INTERRUPT: cut short at %.0fs — %d CVEs not reached. "
            "Partial enrichment flushed. Remaining CVEs enriched on next run.",
            elapsed_total, sum(1 for c in cvss_needed if (c not in cvss_map or cvss_map[c] == (None, None)) and c not in nvd_not_found),
        )
    if cb_tripped:
        log.warning("CIRCUIT-BREAKER: NVD appears unreachable — skipped remaining CVEs. "
                    "Partial enrichment flushed. Will retry on next run.")

    if DRY_RUN:
        log.info("[DRY RUN] Would write %d enriched items — skipping", enriched_count)
        return 0

    total_changes = enriched_count + source_url_count + blog_url_count + sev_aligned
    if total_changes == 0:
        log.info("No enrichments applied — feed unchanged")
        return 0

    if not _write_feed(feed_data, items, FEED_PATH, label=write_label):
        return 1

    # Observability report
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    report = {
        "generated_at":        datetime.now(timezone.utc).isoformat(),
        "script":              "enrich_cvss_epss_batch.py",
        "version":             "185.0",
        "write_label":         write_label,
        "elapsed_seconds":     round(elapsed_total, 1),
        "budget_seconds":      _WALL_CLOCK_BUDGET_SECONDS,
        "budget_interrupted":  budget_interrupted,
        "circuit_breaker_tripped": cb_tripped,
        "nvd_skipped_prelim":  nvd_skipped_prelim,
        "feed_total_items":    len(items),
        "cve_items_found":     len(needs_enrich),
        "cvss_confirmed":      cvss_count,
        "epss_enriched":       epss_count,
        "preliminary_tagged":  preliminary_count,
        "total_enriched":      enriched_count,
        "source_url_filled":   source_url_count,
        "blog_url_filled":     blog_url_count,
        "severity_aligned":    sev_aligned,
        "skipped":             skipped_count,
        "nvd_key_used":        bool(NVD_API_KEY),
        "dry_run":             DRY_RUN,
    }
    try:
        REPORT_PATH.write_text(json.dumps(report, indent=2, ensure_ascii=False), encoding="utf-8")
        log.info("Enrichment report: %s", REPORT_PATH)
    except Exception:
        pass

    log.info("=" * 60)
    log.info("CVSS/EPSS enrichment [%s] complete — %d items updated in %.0fs",
             write_label, enriched_count, elapsed_total)
    log.info("=" * 60)
    return 0


if __name__ == "__main__":
    sys.exit(main())
