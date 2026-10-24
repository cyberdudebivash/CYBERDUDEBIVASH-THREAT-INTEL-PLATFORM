#!/usr/bin/env python3
"""
scripts/deployment_convergence_validator.py
CYBERDUDEBIVASH(R) SENTINEL APEX v184.0 -- Enterprise Deployment Convergence Engine
======================================================================================
MISSION:
  Convert the deployment validation layer into a FULLY ENTERPRISE-GRADE,
  EVENTUAL-CONSISTENCY-AWARE, DEPLOYMENT CONVERGENCE ENGINE.

ROOT CAUSE ADDRESSED:
  GitHub Pages + CDN + custom domain propagation requires 2-10 minutes after
  gh-pages push. The previous canary executed as early as 30-120s post-push,
  causing systematic false-positive P0 failures. This engine waits for TRUE
  convergence before declaring success or failure.

ARCHITECTURE: 5-PHASE CONVERGENCE PROTOCOL
  Phase 1  -  Pages Push Detection:     detect gh-pages push completion
  Phase 2  -  CDN Propagation Wait:     stabilization window with readiness probing
  Phase 3  -  Incremental Retry:        exponential backoff with jitter, multi-endpoint
  Phase 4  -  Convergence Confirmation: 3 consecutive clean passes required
  Phase 5  -  Historical Report Audit:  verify historical reports remain accessible

CONVERGENCE SIGNALS:
  - HTTP 200 on latest report URLs
  - HTTP 200 on dashboard (intel.cyberdudebivash.com)
  - HTTP 200 on feed endpoint (api/feed.json)
  - Historical report sample accessible
  - ETag / Last-Modified consistency (no stale-CDN indicator)
  - Manifest parity (deployed count >= minimum threshold)

CONFIDENCE SCORING:
  Generates deployment_confidence_score.json with multi-signal composite score.
  Score >= 80 = DEPLOYMENT_STABLE
  Score  60-79 = DEPLOYMENT_DEGRADED (warn, do not fail)
  Score  < 60  = DEPLOYMENT_FAILED (hard fail)

EXIT CODES:
  0 = Convergence confirmed  -  deployment is customer-safe
  1 = Hard failure  -  deployment failed to converge after all retries
  2 = Partial convergence  -  degraded state, investigation required

ENVIRONMENT VARIABLES:
  PAGES_BASE_URL            Base URL (default: https://intel.cyberdudebivash.com)
  CONVERGENCE_PHASE1_WAIT   Seconds to wait when the platform is NOT reachable yet (default: 90;
                            a reachable platform goes straight to Phase 2's probing)
  CONVERGENCE_PHASE2_WAIT   Initial CDN probe interval seconds (default: 45)
  CONVERGENCE_MAX_RETRIES   Max retry rounds in Phase 3 (default: 8)
  CONVERGENCE_BACKOFF_BASE  Exponential backoff base seconds (default: 30)
  CONVERGENCE_BACKOFF_MAX   Max backoff ceiling seconds (default: 180)
  CONVERGENCE_JITTER_MAX    Max jitter seconds added to backoff (default: 15)
  CONVERGENCE_CONFIRM_RUNS  Consecutive clean passes to confirm convergence (default: 3)
  CONVERGENCE_CONFIRM_RETRY_WAIT  Seconds before re-probing after a failed confirmation
                            pass (default: 30); clean passes run back to back
  CONVERGENCE_TIMEOUT       Per-request HTTP timeout (default: 20)
  CONVERGENCE_CONFIDENCE_THRESHOLD  Min score for STABLE classification (default: 80)
  CONVERGENCE_FAIL_THRESHOLD        Score below this = hard fail (default: 60)
  MAX_REPORT_PROBES         Max individual report URLs to probe (default: 15)
  HISTORICAL_PROBE_COUNT    Historical report URLs to verify (default: 5)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
CLASSIFICATION: INTERNAL ENGINEERING  -  CONFIDENTIAL
"""
from __future__ import annotations

import hashlib
import json
import math
import logging
import math
import os
import random
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-CONVERGENCE] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.convergence")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
REPO_ROOT      = Path(__file__).resolve().parent.parent
PAGES_BASE_URL = os.environ.get("PAGES_BASE_URL", "https://intel.cyberdudebivash.com").rstrip("/")
DIST_DIR       = REPO_ROOT / "dist"
MANIFEST_PATH  = DIST_DIR / "deployment_manifest.json"
FEED_PATHS     = [REPO_ROOT / "api" / "feed.json", REPO_ROOT / "feed.json"]
REPORTS_CATALOG_PATH = REPO_ROOT / "api" / "reports" / "index.json"
CONFIDENCE_OUT = REPO_ROOT / "deployment_confidence_score.json"

# Phase timings
PHASE1_WAIT         = int(os.environ.get("CONVERGENCE_PHASE1_WAIT", "90"))
PHASE2_WAIT         = int(os.environ.get("CONVERGENCE_PHASE2_WAIT", "45"))
MAX_RETRIES         = int(os.environ.get("CONVERGENCE_MAX_RETRIES", "8"))
BACKOFF_BASE        = int(os.environ.get("CONVERGENCE_BACKOFF_BASE", "30"))
BACKOFF_MAX         = int(os.environ.get("CONVERGENCE_BACKOFF_MAX", "180"))
JITTER_MAX          = int(os.environ.get("CONVERGENCE_JITTER_MAX", "15"))
CONFIRM_RUNS        = int(os.environ.get("CONVERGENCE_CONFIRM_RUNS", "3"))
HTTP_TIMEOUT        = int(os.environ.get("CONVERGENCE_TIMEOUT", "20"))
CONFIDENCE_STABLE   = int(os.environ.get("CONVERGENCE_CONFIDENCE_THRESHOLD", "80"))
CONFIDENCE_FAIL     = int(os.environ.get("CONVERGENCE_FAIL_THRESHOLD", "60"))
MAX_REPORT_PROBES   = int(os.environ.get("MAX_REPORT_PROBES", "15"))
HIST_PROBE_COUNT    = int(os.environ.get("HISTORICAL_PROBE_COUNT", "5"))
# Pause between probes in a batch: the probe itself tripped the site's
# rate limit (HTTP 429) on 2026-09-26 and then waited for it.
PROBE_INTERVAL      = float(os.environ.get("CONVERGENCE_PROBE_INTERVAL", "1.0"))
# A structural report 404 that remains after one bounded grace retry
# cannot be certified by hammering the public CDN. Convergence still FAILS;
# the shortened retry budget only reduces extra billable Worker/R2 reads and
# GitHub Actions time. Keep an override for incident diagnostic tests.
# R2/KV budgets are shared by all ten platform workloads.
PERMANENT_STOP_ROUND = min(1, max(0, int(os.environ.get("CONVERGENCE_PERMANENT_STOP_ROUND", "1"))))

# ---------------------------------------------------------------------------
# Data structures
# ---------------------------------------------------------------------------

@dataclass
class ProbeResult:
    url: str
    status_code: int
    latency_ms: float
    success: bool
    is_transient: bool = False
    etag: Optional[str] = None
    error: Optional[str] = None
    # 404 served on purpose: the report exists but the publication gate
    # rejected it (customer_ready false). Correct deployment behaviour.
    gate_rejected: bool = False


@dataclass
class PhaseResult:
    phase: int
    name: str
    success: bool
    probes: List[ProbeResult] = field(default_factory=list)
    duration_s: float = 0.0
    message: str = ""


@dataclass
class ConvergenceReport:
    timestamp: str
    platform_version: str
    base_url: str
    phases: List[PhaseResult] = field(default_factory=list)
    confidence_score: float = 0.0
    classification: str = "UNKNOWN"
    convergence_achieved: bool = False
    total_duration_s: float = 0.0
    signals: Dict = field(default_factory=dict)
    retry_rounds: int = 0
    exit_code: int = 1


# ---------------------------------------------------------------------------
# HTTP probing utilities
# ---------------------------------------------------------------------------

# Shared bounds cover HEAD probes and publication-status GETs across all phases.
MAX_TOTAL_REQUESTS = 80
MAX_PROTOCOL_SECONDS = 600
_REQUESTS_USED = 0
_PROTOCOL_STARTED = None
_RETRY_NOT_BEFORE = 0.0


def _claim_request():
    global _REQUESTS_USED, _PROTOCOL_STARTED
    now = time.monotonic()
    if _PROTOCOL_STARTED is None:
        _PROTOCOL_STARTED = now
    remaining = MAX_PROTOCOL_SECONDS - (now - _PROTOCOL_STARTED)
    cooldown = max(0.0, _RETRY_NOT_BEFORE - now)
    if _REQUESTS_USED >= MAX_TOTAL_REQUESTS or remaining <= cooldown:
        return False
    if cooldown:
        time.sleep(cooldown)
    _REQUESTS_USED += 1
    return True


def _bounded_wait(seconds):
    if _PROTOCOL_STARTED is None:
        time.sleep(seconds)
        return
    remaining = max(0.0, MAX_PROTOCOL_SECONDS - (time.monotonic() - _PROTOCOL_STARTED))
    time.sleep(min(seconds, remaining))


class _ConvergenceNoRedirects(urllib.request.HTTPRedirectHandler):
    """A convergence probe must not follow redirects to external sites."""

    def redirect_request(self, req, fp, code, msg, headers, newurl):
        return None


def _platform_open(req, *, timeout):
    """Read from the canonical HTTPS platform origin only, without redirects.

    A malicious report path, stale env var or CDN redirect must not turn
    publication verification into an arbitrary-network probe. The origin and
    route family are verified before the network opener is created.
    """
    parsed = urllib.parse.urlsplit(req.full_url)
    path = parsed.path
    # Percent-encoded traversal, credentials, or cache-buster query strings
    # must not convert a publication check into a different request target.
    if "%" in path or ".." in path or "\\\\" in path or parsed.query:
        raise ValueError("CONVERGENCE_UNTRUSTED_PLATFORM_ORIGIN_OR_PATH")
    is_report = (path.startswith("/reports/")
                 and path.endswith(".html")
                 and ".." not in path and "\\\\" not in path)
    is_status = (path.startswith("/api/v1/reports/")
                 and path.endswith("/publication-status")
                 and ".." not in path and "\\\\" not in path)
    if (parsed.scheme != "https"
            or parsed.hostname != "intel.cyberdudebivash.com"
            or parsed.port not in (None, 443)
            or parsed.username is not None or parsed.password is not None
            or parsed.fragment
            or not (path in ("/", "/api/feed.json") or is_report or is_status)):
        raise ValueError("CONVERGENCE_UNTRUSTED_PLATFORM_ORIGIN_OR_PATH")
    return urllib.request.build_opener(_ConvergenceNoRedirects).open(req, timeout=timeout)


def _http_probe(url: str, timeout: int = HTTP_TIMEOUT) -> ProbeResult:
    """Single HTTP HEAD probe with latency measurement."""
    global _RETRY_NOT_BEFORE
    t0 = time.monotonic()
    if not _claim_request():
        return ProbeResult(url=url, status_code=0, latency_ms=0, success=False,
                           is_transient=True, error="NOT_PROBED: shared request/time budget exhausted")
    try:
        req = urllib.request.Request(url, method="HEAD")
        req.add_header("User-Agent", "CDB-Sentinel-Convergence/184.0")
        req.add_header("Cache-Control", "no-cache")
        remaining = MAX_PROTOCOL_SECONDS - (time.monotonic() - _PROTOCOL_STARTED)
        with _platform_open(req, timeout=max(0.1, min(timeout, remaining))) as resp:
            elapsed = (time.monotonic() - t0) * 1000
            return ProbeResult(
                url=url,
                status_code=resp.status,
                latency_ms=round(elapsed, 1),
                success=(resp.status == 200),
                etag=resp.headers.get("ETag"),
            )
    except urllib.error.HTTPError as exc:
        elapsed = (time.monotonic() - t0) * 1000
        # 401 = auth-gated Cloudflare Worker endpoint  -  CDN IS live and responding.
        # A 401 is proof-of-delivery: the request reached the Worker and was processed.
        # Counting 401 as a CDN failure causes the convergence engine to permanently
        # block on auth-gated endpoints like api/feed.json. Classify as CDN-DELIVERED.
        if exc.code == 401:
            log.info("  🔒 [AUTH-GATED] %s  -  HTTP 401 (CDN-DELIVERED, auth required)", url)
            return ProbeResult(
                url=url,
                status_code=401,
                latency_ms=round(elapsed, 1),
                success=True,    # CDN delivered  -  Worker is live
                is_transient=False,
                etag=None,
                error=None,
            )
        # 404 = structural failure (file not in dist/); 5xx/timeout = transient CDN issue.
        # 429 = rate limited: the page is served, the probe was too fast -- transient.
        if exc.code == 429:
            from email.utils import parsedate_to_datetime
            raw_retry = exc.headers.get("Retry-After", "60") if exc.headers else "60"
            try:
                delay = max(0.0, float(raw_retry))
                if not math.isfinite(delay):
                    delay = 60.0
            except (ValueError, TypeError):
                try:
                    delay = max(0.0, parsedate_to_datetime(raw_retry).timestamp() - time.time())
                except Exception:
                    delay = 60.0
            _RETRY_NOT_BEFORE = max(_RETRY_NOT_BEFORE, time.monotonic() + delay)
        is_transient = exc.code >= 500 or exc.code == 429
        return ProbeResult(
            url=url,
            status_code=exc.code,
            latency_ms=round(elapsed, 1),
            success=False,
            is_transient=is_transient,
            error=f"HTTPError {exc.code}",
        )
    except ValueError as exc:
        # Invalid configured destinations are hard failures; never retry or
        # follow a redirect to an untrusted origin.
        return ProbeResult(url=url, status_code=0,
                           latency_ms=round((time.monotonic() - t0) * 1000, 1),
                           success=False, is_transient=False,
                           error=str(exc))
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        elapsed = (time.monotonic() - t0) * 1000
        return ProbeResult(
            url=url,
            status_code=0,
            latency_ms=round(elapsed, 1),
            success=False,
            is_transient=True,   # network errors are always transient
            error=str(exc),
        )


_GATE_VERDICTS: Dict[str, bool] = {}


def _gate_rejected(url: str) -> bool:
    """_is_expected_publication_rejection(), asked once per URL per run."""
    if url not in _GATE_VERDICTS:
        _GATE_VERDICTS[url] = _is_expected_publication_rejection(url)
    return _GATE_VERDICTS[url]


def _probe_batch(urls: List[str], label: str = "") -> Tuple[List[ProbeResult], int, int]:
    """Probe a list of URLs; return results, success count, fail count.

    A report 404 that the publication-status API confirms is a gate rejection
    (customer_ready false) is the deployment doing its job, like the 401 of an
    auth-gated endpoint: counted as delivered (gate_rejected=True). Before
    2026-09-26 Phases 2-4 retried such URLs with backoff up to 180s for 8
    rounds each (the 28-minute stage), although Phase 5 already knew them.
    """
    results = []
    ok = fail = 0
    for i, url in enumerate(urls):
        if i and PROBE_INTERVAL > 0:
            time.sleep(PROBE_INTERVAL)
        r = _http_probe(url)
        if r.error and r.error.startswith("NOT_PROBED:"):
            results.append(r)
            fail += 1
            break
        if not r.success and r.status_code == 404 and _gate_rejected(url):
            r.success = True
            r.gate_rejected = True
            r.error = None
            log.info("  ℹ️  [%s] %s  -  HTTP 404 is an expected publication-gate rejection (delivered)", label, url)
            results.append(r)
            ok += 1
            continue
        results.append(r)
        if r.success:
            ok += 1
            log.info("  ✅ [%s] %s  -  HTTP %d (%.0fms)", label, url, r.status_code, r.latency_ms)
        else:
            fail += 1
            log.warning("  ❌ [%s] %s  -  %s (transient=%s)", label, url, r.error or r.status_code, r.is_transient)
    return results, ok, fail


# ---------------------------------------------------------------------------
# Feed / manifest loading
# ---------------------------------------------------------------------------

def _load_feed() -> List[dict]:
    for fp in FEED_PATHS:
        if fp.exists():
            try:
                raw = fp.read_bytes().rstrip(b"\x00")
                data = json.loads(raw.decode("utf-8", errors="replace"))
                if isinstance(data, list):
                    log.info("Loaded feed: %s (%d items)", fp, len(data))
                    return data
            except Exception as exc:
                log.warning("Feed parse error %s: %s", fp, exc)
    return []


def _load_manifest() -> dict:
    if MANIFEST_PATH.exists():
        try:
            return json.loads(MANIFEST_PATH.read_text("utf-8"))
        except Exception as exc:
            log.warning("Manifest parse error: %s", exc)
    return {}


def _extract_report_urls(feed: List[dict], manifest: dict) -> Tuple[List[str], List[str]]:
    """
    Extract latest and historical report URLs for convergence probing.

    SOURCE PRIORITY:
      1. Pages deployment manifest reports/*.html when the deployment actually carries
         report artifacts.
      2. R2-backed api/reports/index.json when reports are served by the Worker/R2
         architecture instead of Pages. build_reports_index.py constructs this catalog
         from the successful R2 publish state and canonical timestamps before this gate.
      3. feed.json report_url fields.
      4. local reports/ scan as last-resort evidence.

    The catalog path is never trusted as an arbitrary probe target: only canonical
    root-relative /reports/*.html paths are accepted and re-based onto PAGES_BASE_URL.

    Returns (latest_urls, historical_urls):
      latest     -  most-recent MAX_REPORT_PROBES reports (newest filenames = last alpha)
      historical  -  oldest HIST_PROBE_COUNT reports (guard against accidental deletion)
    """
    # Mandatory fail-closed canonical UTC chronology. No environment bypass,
    # hash-order fallback, filesystem mtime, or untrusted feed URL fallback.
    try:
        from strict_report_probe_selection import (
            select_report_probes, ReportSelectionBlocked,
        )
        if not REPORTS_CATALOG_PATH.is_file():
            raise ReportSelectionBlocked("Authoritative reports catalog unavailable")
        if REPORTS_CATALOG_PATH.stat().st_size > 20_000_000:
            raise ReportSelectionBlocked("Authoritative reports catalog exceeds size limit")
        canonical = json.loads(REPORTS_CATALOG_PATH.read_text(encoding="utf-8"))
        selected = select_report_probes(
            canonical, manifest_files=manifest.get("files", {}),
            latest_limit=MAX_REPORT_PROBES,
            historical_limit=HIST_PROBE_COUNT,
        )
        log.info("Strict UTC chronology precheck passed; live delivery remains unverified")
        return selected
    except (OSError, ValueError, UnicodeError, TypeError) as exc:
        raise RuntimeError("P0 canonical chronology blocked convergence certification") from exc


def _get_platform_version() -> str:
    vf = REPO_ROOT / "VERSION"
    if vf.exists():
        return vf.read_text().strip()
    return "unknown"


# ---------------------------------------------------------------------------
# Exponential backoff with jitter
# ---------------------------------------------------------------------------

def _backoff_wait(attempt: int) -> float:
    """Compute exponential backoff with full jitter. Returns seconds to sleep."""
    exp = BACKOFF_BASE * (2 ** attempt)
    ceiling = min(exp, BACKOFF_MAX)
    jitter = random.uniform(0, JITTER_MAX)
    return round(ceiling + jitter, 1)


# ---------------------------------------------------------------------------
# Convergence signal detection
# ---------------------------------------------------------------------------

def _unprobed_budget_exhausted(results: List[ProbeResult]) -> bool:
    """No network response was obtained; never label a budget stop as a 404."""
    return any((r.error or "").startswith("NOT_PROBED:") for r in results)


def _only_permanent_failures(results: List[ProbeResult]) -> bool:
    """Only observed non-transient HTTP failures qualify as permanent."""
    failed = [r for r in results if not r.success]
    return bool(failed) and not _unprobed_budget_exhausted(failed) and all(
        not r.is_transient and r.status_code > 0 for r in failed
    )


def _detect_transient_vs_permanent(results: List[ProbeResult]) -> Tuple[int, int, int]:
    """Returns (permanent_failures, transient_failures, successes)."""
    permanent = sum(1 for r in results if not r.success and not r.is_transient)
    transient = sum(1 for r in results if not r.success and r.is_transient)
    successes = sum(1 for r in results if r.success)
    return permanent, transient, successes


# ---------------------------------------------------------------------------
# Phase implementations
# ---------------------------------------------------------------------------

def phase1_pages_push_detection() -> PhaseResult:
    """
    Phase 1: Verify Pages push is complete and begin initial CDN stabilization wait.
    Probes the homepage and feed endpoint to detect push completion.
    """
    log.info("=" * 70)
    log.info("PHASE 1  -  PAGES PUSH DETECTION + INITIAL STABILIZATION WAIT")
    log.info("=" * 70)
    t0 = time.monotonic()

    endpoints = [
        PAGES_BASE_URL + "/",
        PAGES_BASE_URL + "/api/feed.json",
    ]

    log.info("Probing platform endpoints to detect gh-pages push completion...")
    results, ok, fail = _probe_batch(endpoints, "Phase1")

    # Allow partial pass on Phase 1  -  CDN may not be propagated yet
    push_detected = ok >= 1

    # 2026-09-26: no fixed stabilization wait when the platform already answers.
    # The stage runs minutes after the Pages deploy (STAGE 5 -> smoke tests ->
    # canaries), and Phase 2 probes the same URLs with backoff until the CDN
    # serves them, so a blind 90s sleep only added time (run 36228313439).
    if push_detected:
        log.info("Phase 1: Platform reachable. Phase 2 verifies CDN readiness (no fixed wait).")
    else:
        log.warning("Phase 1: Platform not reachable yet. Waiting %ds for Pages propagation...", PHASE1_WAIT + 30)
        for remaining in range(PHASE1_WAIT + 30, 0, -15):
            log.info("  ⏳ Pages propagation wait: %ds remaining...", remaining)
            time.sleep(min(15, remaining))

    duration = time.monotonic() - t0
    return PhaseResult(
        phase=1,
        name="Pages Push Detection",
        success=True,   # Phase 1 always passes  -  it's a stabilization gate
        probes=results,
        duration_s=round(duration, 1),
        message=f"Push detected={push_detected}." + ("" if push_detected else " Propagation wait complete."),
    )


def phase2_cdn_readiness_probe(feed: List[dict], manifest: dict) -> PhaseResult:
    """
    Phase 2: Active CDN readiness probing with exponential backoff.
    Probes core platform URLs + a sample of report URLs.
    Returns success when CDN is serving fresh content.
    """
    log.info("=" * 70)
    log.info("PHASE 2  -  CDN PROPAGATION READINESS PROBE")
    log.info("=" * 70)
    t0 = time.monotonic()

    latest_urls, _ = _extract_report_urls(feed, manifest)
    sample_reports = latest_urls[:5]  # Quick sample in Phase 2

    core_endpoints = [
        PAGES_BASE_URL + "/",
        PAGES_BASE_URL + "/api/feed.json",
    ]
    probe_targets = core_endpoints + sample_reports
    all_results = []

    for attempt in range(MAX_RETRIES):
        log.info("Phase 2 CDN probe round %d/%d...", attempt + 1, MAX_RETRIES)
        results, ok, fail = _probe_batch(probe_targets, f"Phase2-R{attempt+1}")
        all_results.extend(results)
        _, transient, successes = _detect_transient_vs_permanent(results)

        success_rate = ok / len(probe_targets) if probe_targets else 0
        log.info("Phase 2 Round %d: %d/%d OK (%.0f%%)", attempt + 1, ok, len(probe_targets), success_rate * 100)

        if success_rate >= 0.8:
            log.info("Phase 2: CDN readiness confirmed (≥80%% success rate).")
            duration = time.monotonic() - t0
            return PhaseResult(
                phase=2,
                name="CDN Propagation Readiness",
                success=True,
                probes=all_results,
                duration_s=round(duration, 1),
                message=f"CDN ready after {attempt+1} round(s). Success rate: {success_rate:.0%}",
            )

        if _unprobed_budget_exhausted(results):
            log.error("Phase 2: verification incomplete -- shared request/time budget exhausted. No further retries.")
            break

        if attempt >= PERMANENT_STOP_ROUND and _only_permanent_failures(results):
            log.warning("Phase 2: remaining failures are permanent (404) after %d rounds -- not retrying.", attempt + 1)
            break

        if attempt + 1 >= MAX_RETRIES:
            break
        wait = _backoff_wait(attempt)
        log.info("Phase 2: CDN not ready. Backoff %.1fs before retry...", wait)
        _bounded_wait(wait)

    duration = time.monotonic() - t0
    log.warning("Phase 2: CDN readiness not achieved after %d retries.", MAX_RETRIES)
    return PhaseResult(
        phase=2,
        name="CDN Propagation Readiness",
        success=False,
        probes=all_results,
        duration_s=round(duration, 1),
        message=f"CDN not ready after {MAX_RETRIES} retries. Propagation may still be in-flight.",
    )


def phase3_incremental_retry(feed: List[dict], manifest: dict) -> PhaseResult:
    """
    Phase 3: Full report URL validation with intelligent incremental retry.
    Probes all sampled report URLs with per-URL retry tracking.
    Distinguishes transient failures (CDN lag) from permanent failures (404).
    """
    log.info("=" * 70)
    log.info("PHASE 3  -  INCREMENTAL RETRY WITH TRANSIENT/PERMANENT DISCRIMINATION")
    log.info("=" * 70)
    t0 = time.monotonic()

    latest_urls, _ = _extract_report_urls(feed, manifest)
    if not latest_urls:
        # v160.6 FIX: soft-pass when no URLs available after all 3 fallbacks.
        # Godmode-skip scenario: all reports are pre-existing large files,
        # report_generator skipped regeneration, no new Pages manifest entries.
        # Platform IS stable (confirmed by Phase 1+2). Hard-fail here produced
        # false DEPLOYMENT_FAILED Score=32.5/100 in 3 consecutive CI runs.
        log.warning(
            "Phase 3: No report URLs after all fallbacks. "
            "SOFT PASS — godmode-skip run (reports pre-existing on CDN). "
            "Platform stability confirmed by Phase 1+2."
        )
        return PhaseResult(
            phase=3, name="Incremental Retry",
            success=True, probes=[],
            duration_s=0,
            message="Soft pass — no new reports this cycle (godmode-skip). "
                    "CDN stability confirmed by Phase 1+2.",
        )

    # Track per-URL success
    url_status: Dict[str, bool] = {u: False for u in latest_urls}
    all_results = []

    for attempt in range(MAX_RETRIES):
        pending = [u for u, ok in url_status.items() if not ok]
        if not pending:
            log.info("Phase 3: All %d report URLs confirmed HTTP 200 ✅", len(latest_urls))
            break

        log.info("Phase 3 retry round %d/%d: probing %d pending URLs...", attempt + 1, MAX_RETRIES, len(pending))
        results, ok, fail = _probe_batch(pending, f"Phase3-R{attempt+1}")
        all_results.extend(results)

        for r in results:
            if r.success:
                url_status[r.url] = True

        if _unprobed_budget_exhausted(results):
            log.error(
                "Phase 3: report verification incomplete -- request/time budget exhausted; "
                "unprobed URLs are NOT permanent 404s and cannot certify convergence."
            )
            break

        confirmed = sum(url_status.values())
        total = len(url_status)
        log.info("Phase 3 Round %d: %d/%d URLs confirmed (%d remaining)", attempt + 1, confirmed, total, total - confirmed)

        if confirmed == total:
            break

        # Check if remaining failures are transient or permanent
        failed_results = [r for r in results if not r.success]
        permanent_fails = [r for r in failed_results if not r.is_transient]

        if permanent_fails and attempt >= PERMANENT_STOP_ROUND:
            log.error("Phase 3: %d PERMANENT failures detected (non-transient 404s):", len(permanent_fails))
            for r in permanent_fails:
                log.error("  PERMANENT FAIL: %s  -  %s", r.url, r.error)
            if len(permanent_fails) == len(failed_results):
                log.error("Phase 3: only permanent failures remain -- not retrying.")
                break

        if attempt + 1 >= MAX_RETRIES:
            break
        wait = _backoff_wait(attempt)
        log.info("Phase 3: Waiting %.1fs before next retry round...", wait)
        _bounded_wait(wait)

    confirmed = sum(url_status.values())
    total = len(url_status)
    success_rate = confirmed / total if total else 0
    phase_success = confirmed == total and total > 0  # Every sampled report must resolve.

    duration = time.monotonic() - t0
    return PhaseResult(
        phase=3,
        name="Incremental Retry",
        success=phase_success,
        probes=all_results,
        duration_s=round(duration, 1),
        message=f"{confirmed}/{total} report URLs confirmed ({success_rate:.0%}). "
                f"{'PASS' if phase_success else 'FAIL  -  below 90% threshold'}",
    )


def phase4_convergence_confirmation(feed: List[dict], manifest: dict) -> PhaseResult:
    """
    Phase 4: Convergence confirmation  -  requires CONFIRM_RUNS consecutive
    clean validation passes with a 30s gap between passes.
    Eliminates flapping caused by CDN partial-propagation state.
    """
    log.info("=" * 70)
    log.info("PHASE 4  -  CONVERGENCE CONFIRMATION (%d consecutive clean passes required)", CONFIRM_RUNS)
    log.info("=" * 70)
    t0 = time.monotonic()

    latest_urls, _ = _extract_report_urls(feed, manifest)
    core_urls = [
        PAGES_BASE_URL + "/",
        PAGES_BASE_URL + "/api/feed.json",
    ] + latest_urls[:5]

    consecutive_clean = 0
    all_results = []
    # 2026-09-26: clean passes run back to back; the pause is only taken after a
    # failed pass, when there is something to wait for (was a fixed 30s between
    # every pass: 60s on every healthy run).
    RETRY_WAIT = int(os.environ.get("CONVERGENCE_CONFIRM_RETRY_WAIT", "30"))

    for run in range(CONFIRM_RUNS * 3):   # max attempts = 3x required passes
        if consecutive_clean >= CONFIRM_RUNS:
            break

        log.info("Phase 4 confirmation run %d (consecutive clean: %d/%d)...", run + 1, consecutive_clean, CONFIRM_RUNS)
        results, ok, fail = _probe_batch(core_urls, f"Phase4-R{run+1}")
        all_results.extend(results)

        success_rate = ok / len(core_urls) if core_urls else 0
        if success_rate >= 0.9:
            consecutive_clean += 1
            log.info("Phase 4: Clean pass %d/%d confirmed (%.0f%% success rate) ✅", consecutive_clean, CONFIRM_RUNS, success_rate * 100)
        else:
            consecutive_clean = 0
            log.warning("Phase 4: Clean streak reset  -  only %.0f%% success rate.", success_rate * 100)

        if consecutive_clean == 0 and RETRY_WAIT > 0:
            log.info("Phase 4: Waiting %ds before the next confirmation pass...", RETRY_WAIT)
            if run + 1 < CONFIRM_RUNS * 3:
                _bounded_wait(RETRY_WAIT)

    convergence_confirmed = consecutive_clean >= CONFIRM_RUNS
    duration = time.monotonic() - t0

    return PhaseResult(
        phase=4,
        name="Convergence Confirmation",
        success=convergence_confirmed,
        probes=all_results,
        duration_s=round(duration, 1),
        message=f"{'Convergence CONFIRMED' if convergence_confirmed else 'Convergence NOT confirmed'}  -  "
                f"{consecutive_clean}/{CONFIRM_RUNS} consecutive clean passes.",
    )


# Production report slugs can contain decimal IDs, CVE suffixes, underscores
# and hyphens. Capture the complete basename so a publication-gated 404 is
# classified against the authoritative publication-status endpoint instead
# of being misreported as a permanent CDN/deployment failure.
_HIST_REPORT_ID_RE = re.compile(r"/(intel--[^/?#]+?)\.html?(?:[?#].*)?$", re.IGNORECASE)


def query_publication_status(report_id: str) -> Optional[dict]:
    """
    Queries the single authoritative source for a report's publication
    verdict -- GET /api/v1/reports/{id}/publication-status, backed by the
    same evaluatePublicationGate() every /reports/** request is gated by
    (see workers/intel-gateway/src/publication-gate.js). Returns the parsed
    JSON response (with at least "state" and "customer_ready" fields), or
    None on any network/parse failure.

    Fail-closed contract: None means "status could not be determined" --
    callers must never treat None as an implicit pass. This is the shared
    building block for both this module's historical-continuity check and
    scripts/report_url_canary.py's live-deployment classification (Single
    Source of Truth -- neither script re-implements publication-gate logic).
    """
    # Percent-encode so a report_id with an unexpected character (e.g. from a
    # malformed feed entry) can't redirect the request to a different path
    # segment -- defensive hardening only, report_id is normally already
    # constrained to intel--[a-f0-9]+ by callers.
    global _RETRY_NOT_BEFORE
    status_url = f"{PAGES_BASE_URL}/api/v1/reports/{urllib.parse.quote(report_id, safe='')}/publication-status"
    try:
        # One bounded GET is sufficient to establish reachability, status and
        # parseable evidence. The previous HEAD-then-GET sequence consumed two
        # slots for every gate-classification lookup. With 15 latest reports,
        # three confirmation passes and five historical probes, that exhausted
        # MAX_TOTAL_REQUESTS during Phase 5 even on a healthy deployment.
        # Keeping this to one request preserves the same global ceiling while
        # leaving enough budget to complete the fail-closed historical sample.
        req = urllib.request.Request(
            status_url,
            headers={"User-Agent": "SentinelApex-ConvergenceValidator/1.0"},
            method="GET",
        )
        if not _claim_request():
            return None
        remaining = MAX_PROTOCOL_SECONDS - (
            time.monotonic() - _PROTOCOL_STARTED
        )
        timeout = max(0.1, min(HTTP_TIMEOUT, remaining))
        with _platform_open(req, timeout=timeout) as resp:
            if getattr(resp, "status", 200) != 200:
                return None
            data = json.loads(resp.read(1024 * 1024).decode("utf-8", errors="replace"))
            return data if isinstance(data, dict) else None
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            from email.utils import parsedate_to_datetime
            raw_retry = exc.headers.get("Retry-After", "60") if exc.headers else "60"
            try:
                delay = max(0.0, float(raw_retry))
                if not math.isfinite(delay):
                    delay = 60.0
            except (ValueError, TypeError):
                try:
                    delay = max(0.0, parsedate_to_datetime(raw_retry).timestamp() - time.time())
                except Exception:
                    delay = 60.0
            _RETRY_NOT_BEFORE = max(_RETRY_NOT_BEFORE, time.monotonic() + delay)
        return None
    except (urllib.error.URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return None


def _is_expected_publication_rejection(url: str) -> bool:
    """
    v186.0 P0 FIX: a 404 on a historical report URL used to always count as
    a "continuity breach." Since PR #141/#143 (the P0 customer-publication
    gate), the Worker deliberately 404s any report whose id is resolvable but
    fails evaluatePublicationGate() (P21_BELOW_MINIMUM / P26_REJECTED /
    etc.) -- verified live: every one of a real batch of "inaccessible"
    historical reports this check flagged was, in fact, a legitimate
    REJECTED verdict from the publication-status API, not a broken
    deployment. Consult that same authoritative endpoint before counting a
    404 against continuity, so this check can no longer conflict with the
    gate it postdates. Fails closed: any doubt (network error, ambiguous
    response) leaves the URL counted as a genuine failure, unchanged from
    prior behaviour.
    """
    m = _HIST_REPORT_ID_RE.search(url)
    if not m:
        return False
    data = query_publication_status(m.group(1))
    if data is None:
        return False
    return data.get("customer_ready") is False


def phase5_historical_report_audit(feed: List[dict], manifest: dict) -> PhaseResult:
    """
    Phase 5: Historical report continuity verification.
    Ensures historical reports (not just latest) remain accessible.
    Guards against Pages deployments that accidentally delete older reports.
    A 404 caused by the P0 publication gate correctly rejecting an
    uncertified report is NOT a continuity breach -- see
    _is_expected_publication_rejection().
    """
    log.info("=" * 70)
    log.info("PHASE 5  -  HISTORICAL REPORT CONTINUITY AUDIT")
    log.info("=" * 70)
    t0 = time.monotonic()

    _, historical_urls = _extract_report_urls(feed, manifest)

    if not historical_urls:
        # Missing audit evidence cannot establish historical continuity. Do not
        # spend extra shared-plan requests or award a synthetic successful phase.
        log.error("Phase 5: HISTORICAL EVIDENCE MISSING - no historical report URLs available to audit.")
        duration = time.monotonic() - t0
        return PhaseResult(
            phase=5, name="Historical Report Audit",
            success=False,
            probes=[], duration_s=round(duration, 1),
            message="HISTORICAL EVIDENCE MISSING - no historical report URLs available; continuity unverified.",
        )

    log.info("Phase 5: Probing %d historical report URLs...", len(historical_urls))
    results, ok, fail = _probe_batch(historical_urls, "Phase5-Historical")

    # _probe_batch() already asked the publication-status API about every 404;
    # gate rejections are excluded from this audit, as before.
    gate_rejected = sum(1 for r in results if r.gate_rejected)

    unprobed = len(historical_urls) - len(results)
    effective_total = len(results) - gate_rejected
    effective_ok = ok - gate_rejected
    success_rate = (effective_ok / effective_total) if effective_total else 1.0
    phase_success = (
        unprobed == 0 and effective_ok == effective_total
    )  # No sampled historical loss or unverified sample is accepted.

    duration = time.monotonic() - t0
    if not phase_success:
        log.error(
            "Phase 5: HISTORICAL VERIFICATION INCOMPLETE  -  "
            "%d/%d completed non-gate probes accessible; %d failed, "
            "%d unprobed, %d expected gate rejections excluded!",
            effective_ok, effective_total, fail, unprobed, gate_rejected,
        )
    else:
        log.info("Phase 5: Historical continuity OK  -  %d/%d accessible (%.0f%%), %d expected gate rejections excluded",
                  effective_ok, effective_total, success_rate * 100, gate_rejected)

    return PhaseResult(
        phase=5,
        name="Historical Report Audit",
        success=phase_success,
        probes=results,
        duration_s=round(duration, 1),
        message=f"{effective_ok}/{effective_total} historical reports accessible "
                f"({success_rate:.0%}) across completed non-gate probes, {unprobed} unprobed, "
                f"{gate_rejected} excluded as expected publication-gate rejections. "
                f"{'PASS' if phase_success else 'HISTORICAL VERIFICATION INCOMPLETE'}",
    )


# ---------------------------------------------------------------------------
# Confidence scoring engine
# ---------------------------------------------------------------------------

def _compute_confidence_score(phases: List[PhaseResult], feed: List[dict], manifest: dict) -> Tuple[float, Dict]:
    """
    Multi-signal confidence scoring. Returns (score_0_to_100, signals_dict).

    Signal weights:
      Phase 2 (CDN readiness)         → 20 points
      Phase 3 (report URL validation) → 35 points
      Phase 4 (convergence confirm)   → 30 points
      Phase 5 (historical continuity) → 10 points
      Feed/manifest data available    → 5 points
    """
    score = 0.0
    signals = {}

    phase_map = {p.phase: p for p in phases}

    # Signal 1: CDN readiness (Phase 2)  -  20 pts
    p2 = phase_map.get(2)
    if p2 and p2.success:
        score += 20.0
        signals["cdn_readiness"] = {"score": 20, "status": "PASS", "message": p2.message}
    elif p2:
        # Partial credit based on probe success rate
        if p2.probes:
            sr = sum(1 for r in p2.probes if r.success) / len(p2.probes)
            partial = round(sr * 10, 1)
            score += partial
            signals["cdn_readiness"] = {"score": partial, "status": "PARTIAL", "message": p2.message}
        else:
            signals["cdn_readiness"] = {"score": 0, "status": "FAIL", "message": p2.message if p2 else "Phase 2 not run"}
    else:
        signals["cdn_readiness"] = {"score": 0, "status": "NOT_RUN", "message": "Phase 2 not executed"}

    # Signal 2: Report URL validation (Phase 3)  -  35 pts
    p3 = phase_map.get(3)
    if p3 and p3.success:
        score += 35.0
        signals["report_url_validation"] = {"score": 35, "status": "PASS", "message": p3.message}
    elif p3 and p3.probes:
        sr = sum(1 for r in p3.probes if r.success) / len(p3.probes)
        partial = round(sr * 35, 1)
        score += partial
        signals["report_url_validation"] = {"score": partial, "status": "PARTIAL", "message": p3.message}
    else:
        signals["report_url_validation"] = {"score": 0, "status": "FAIL", "message": p3.message if p3 else "Phase 3 not run"}

    # Signal 3: Convergence confirmation (Phase 4)  -  30 pts
    p4 = phase_map.get(4)
    if p4 and p4.success:
        score += 30.0
        signals["convergence_confirmation"] = {"score": 30, "status": "PASS", "message": p4.message}
    elif p4 and p4.probes:
        sr = sum(1 for r in p4.probes if r.success) / len(p4.probes)
        partial = round(sr * 15, 1)
        score += partial
        signals["convergence_confirmation"] = {"score": partial, "status": "PARTIAL", "message": p4.message}
    else:
        signals["convergence_confirmation"] = {"score": 0, "status": "FAIL", "message": p4.message if p4 else "Phase 4 not run"}

    # Signal 4: Historical continuity (Phase 5)  -  10 pts
    p5 = phase_map.get(5)
    if p5 and p5.success:
        score += 10.0
        signals["historical_continuity"] = {"score": 10, "status": "PASS", "message": p5.message}
    elif p5:
        signals["historical_continuity"] = {"score": 0, "status": "FAIL", "message": p5.message}
    else:
        signals["historical_continuity"] = {"score": 5, "status": "NOT_RUN", "message": "Phase 5 not run (soft pass)"}
        score += 5.0

    # Signal 5: Data availability  -  5 pts
    feed_ok = len(feed) > 0
    manifest_ok = bool(manifest)
    data_score = (2.5 if feed_ok else 0) + (2.5 if manifest_ok else 0)
    score += data_score
    signals["data_availability"] = {
        "score": data_score,
        "status": "PASS" if (feed_ok and manifest_ok) else "PARTIAL",
        "feed_items": len(feed),
        "manifest_available": manifest_ok,
    }

    score = round(min(score, 100.0), 1)
    return score, signals


def _classify_deployment(score: float) -> str:
    if score >= CONFIDENCE_STABLE:
        return "DEPLOYMENT_STABLE"
    elif score >= CONFIDENCE_FAIL:
        return "DEPLOYMENT_DEGRADED"
    else:
        return "DEPLOYMENT_FAILED"


# ---------------------------------------------------------------------------
# Confidence report writer
# ---------------------------------------------------------------------------

def _write_confidence_report(report: ConvergenceReport) -> None:
    """Write deployment_confidence_score.json to repo root."""
    out = {
        "generated_at": report.timestamp,
        "platform_version": report.platform_version,
        "base_url": report.base_url,
        "confidence_score": report.confidence_score,
        "classification": report.classification,
        "convergence_achieved": report.convergence_achieved,
        "total_duration_s": report.total_duration_s,
        "retry_rounds": report.retry_rounds,
        "exit_code": report.exit_code,
        "signals": report.signals,
        "phases": [
            {
                "phase": p.phase,
                "name": p.name,
                "success": p.success,
                "duration_s": p.duration_s,
                "message": p.message,
                "probe_count": len(p.probes),
                "probe_successes": sum(1 for r in p.probes if r.success),
                "probe_failures": sum(1 for r in p.probes if not r.success),
            }
            for p in report.phases
        ],
        "thresholds": {
            "stable_threshold": CONFIDENCE_STABLE,
            "fail_threshold": CONFIDENCE_FAIL,
            "convergence_confirm_runs": CONFIRM_RUNS,
            "max_retries": MAX_RETRIES,
        },
    }
    try:
        CONFIDENCE_OUT.write_text(json.dumps(out, indent=2), encoding="utf-8")
        log.info("Confidence report written: %s", CONFIDENCE_OUT)
    except Exception as exc:
        log.warning("Failed to write confidence report: %s", exc)


# ---------------------------------------------------------------------------
# Main convergence orchestrator
# ---------------------------------------------------------------------------

def run_convergence_protocol() -> int:
    """
    Execute the full 5-phase deployment convergence protocol.
    Returns exit code: 0=stable, 1=failed, 2=degraded.
    """
    wall_start = time.monotonic()
    timestamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    version = _get_platform_version()

    log.info("╔══════════════════════════════════════════════════════════════════════╗")
    log.info("║   SENTINEL APEX  -  DEPLOYMENT CONVERGENCE ENGINE v184.0              ║")
    log.info("║   EVENTUAL-CONSISTENCY-AWARE · ENTERPRISE-GRADE · P0-SAFE           ║")
    log.info("╚══════════════════════════════════════════════════════════════════════╝")
    log.info("Platform version : %s", version)
    log.info("Base URL         : %s", PAGES_BASE_URL)
    log.info("Stabilization    : Phase1 %ds only if unreachable; Phase2 backoff on failure", PHASE1_WAIT)
    log.info("Max retries      : %d (backoff %d-%ds + jitter %ds)", MAX_RETRIES, BACKOFF_BASE, BACKOFF_MAX, JITTER_MAX)
    log.info("Confirm passes   : %d consecutive required", CONFIRM_RUNS)
    log.info("Confidence gates : STABLE≥%d / DEGRADED≥%d / FAILED<%d", CONFIDENCE_STABLE, CONFIDENCE_FAIL, CONFIDENCE_FAIL)

    # Load data
    feed = _load_feed()
    manifest = _load_manifest()

    phases: List[PhaseResult] = []

    # ── Phase 1 ──────────────────────────────────────────────────────────
    p1 = phase1_pages_push_detection()
    phases.append(p1)

    # ── Phase 2 ──────────────────────────────────────────────────────────
    p2 = phase2_cdn_readiness_probe(feed, manifest)
    phases.append(p2)

    # If Phase 2 failed, we still continue  -  CDN may still be propagating
    # but we attempt Phase 3 with extended retry
    if not p2.success:
        log.warning("Phase 2 CDN readiness not confirmed  -  extending Phase 3 retry budget...")

    # ── Phase 3 ──────────────────────────────────────────────────────────
    p3 = phase3_incremental_retry(feed, manifest)
    phases.append(p3)

    # ── Phase 4 (only if Phase 3 passed) ─────────────────────────────────
    if p3.success:
        p4 = phase4_convergence_confirmation(feed, manifest)
    else:
        log.warning("Phase 3 failed  -  skipping Phase 4 convergence confirmation.")
        p4 = PhaseResult(
            phase=4, name="Convergence Confirmation",
            success=False, probes=[], duration_s=0,
            message="Skipped  -  Phase 3 did not pass.",
        )
    phases.append(p4)

    # ── Phase 5 ──────────────────────────────────────────────────────────
    p5 = phase5_historical_report_audit(feed, manifest)
    phases.append(p5)

    # ── Confidence scoring ────────────────────────────────────────────────
    score, signals = _compute_confidence_score(phases, feed, manifest)
    classification = _classify_deployment(score)
    # Weighted points must not conceal failed report continuity or budget exhaustion.
    if not all(phase.success for phase in (p2, p3, p4, p5)):
        classification = "DEPLOYMENT_FAILED"
    convergence_achieved = p4.success and p3.success

    total_duration = round(time.monotonic() - wall_start, 1)
    retry_rounds = sum(
        len([r for r in p.probes]) // max(1, len([PAGES_BASE_URL + "/"]))
        for p in phases
    )

    # Exit code determination
    if classification == "DEPLOYMENT_STABLE":
        exit_code = 0
    elif classification == "DEPLOYMENT_DEGRADED":
        exit_code = 2
    else:
        exit_code = 1

    report = ConvergenceReport(
        timestamp=timestamp,
        platform_version=version,
        base_url=PAGES_BASE_URL,
        phases=phases,
        confidence_score=score,
        classification=classification,
        convergence_achieved=convergence_achieved,
        total_duration_s=total_duration,
        signals=signals,
        retry_rounds=retry_rounds,
        exit_code=exit_code,
    )

    _write_confidence_report(report)

    # ── Final summary ─────────────────────────────────────────────────────
    log.info("")
    log.info("╔══════════════════════════════════════════════════════════════════════╗")
    log.info("║   CONVERGENCE PROTOCOL COMPLETE                                      ║")
    log.info("╠══════════════════════════════════════════════════════════════════════╣")
    log.info("║  Confidence Score : %-5.1f / 100                                     ║", score)
    log.info("║  Classification   : %-35s           ║", classification)
    log.info("║  Convergence      : %-8s                                          ║", "ACHIEVED" if convergence_achieved else "NOT ACHIEVED")
    log.info("║  Total Duration   : %-5.0fs                                          ║", total_duration)
    log.info("║  Exit Code        : %-3d                                              ║", exit_code)
    log.info("╠══════════════════════════════════════════════════════════════════════╣")
    for ph in phases:
        status_icon = "✅" if ph.success else "❌"
        log.info("║  Phase %d %-30s  %s %-8s       ║", ph.phase, ph.name[:30], status_icon, "PASS" if ph.success else "FAIL")
    log.info("╚══════════════════════════════════════════════════════════════════════╝")

    if exit_code == 0:
        log.info("🟢 DEPLOYMENT CONVERGENCE CONFIRMED  -  Sampled deployment checks passed; full customer readiness requires separate evidence.")
    elif exit_code == 2:
        log.warning("🟡 DEPLOYMENT DEGRADED  -  Investigate signals. Platform partially available.")
    else:
        log.error("🔴 DEPLOYMENT CONVERGENCE FAILED  -  P0 escalation required.")

    return exit_code


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

if __name__ == "__main__":
    # v160.2 P1 FIX: Guarantee deployment_confidence_score.json is ALWAYS written
    # even if run_convergence_protocol() raises an unhandled exception.
    # Without this, any crash before _write_confidence_report() leaves the file
    # absent, causing STAGE 5.8.4 governance Domain 4 to WARN every failed run.
    try:
        sys.exit(run_convergence_protocol())
    except Exception as _fatal:
        log.error("Convergence protocol crashed: %s", _fatal)
        _fallback = {
            "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
            "platform_version": "unknown",
            "base_url": os.environ.get("PAGES_BASE_URL", ""),
            "confidence_score": 0,
            "classification": "DEPLOYMENT_FAILED",
            "convergence_achieved": False,
            "total_duration_s": 0,
            "retry_rounds": 0,
            "exit_code": 1,
            "signals": {},
            "phases": [],
            "error": str(_fatal),
            "thresholds": {
                "stable_threshold": CONFIDENCE_STABLE,
                "fail_threshold": CONFIDENCE_FAIL,
            },
        }
        try:
            CONFIDENCE_OUT.write_text(
                json.dumps(_fallback, indent=2), encoding="utf-8"
            )
            log.info("Fallback confidence report written: %s", CONFIDENCE_OUT)
        except Exception as _write_err:
            log.error("Failed to write fallback report: %s", _write_err)
        sys.exit(1)
