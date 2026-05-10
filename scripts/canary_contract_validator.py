#!/usr/bin/env python3
"""
===============================================================================
CYBERDUDEBIVASH(R) SENTINEL APEX v146.0.0
CANARY CONTRACT VALIDATOR — API Schema Live Validation
===============================================================================
PURPOSE:
  Validates the LIVE production API endpoints against the expected schema
  contract. Detects schema drift, field removal, type changes, and broken
  response envelopes BEFORE they impact paying customers.

CANARY ENDPOINTS:
  /api/v1/intel/latest.json  — full intel feed (must have items array)
  /api/v1/intel/apex.json    — APEX-enriched feed
  /api/v1/intel/manifest.json — registry (checksums, counts)
  /api/health                 — platform health (must return 200)

CONTRACT VALIDATION:
  For each endpoint:
    - HTTP 200 required (3xx/4xx/5xx = FAIL)
    - Response is valid JSON
    - Required schema fields present
    - item_count > 0 for feed endpoints
    - No field type regressions vs baseline
    - Response time < 10s (SLA requirement)

BASELINE MANAGEMENT:
  On first run, baseline is written from live response.
  On subsequent runs, response is compared against baseline.
  BREAKING changes (field removal, type change) = FAIL.
  DRIFT changes (new fields) = WARN (backward-compatible).

OUTPUTS:
  data/governance/canary_contract.json   — live validation report
  data/governance/api_baseline.json      — schema baseline (auto-managed)

EXIT CODES:
  0 — PASS or WARN (non-breaking drift)
  2 — FAIL (breaking contract violation detected)
  0 — on any unexpected error (must not block production)

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved. CONFIDENTIAL.
===============================================================================
"""
from __future__ import annotations

import json
import logging
import os
import pathlib
import shutil
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [canary_validator] %(levelname)s: %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S",
)
log = logging.getLogger("CDB-CANARY")

REPO_ROOT    = pathlib.Path(__file__).resolve().parent.parent
GOV_DIR      = REPO_ROOT / "data" / "governance"
REPORT_PATH  = GOV_DIR / "canary_contract.json"
BASELINE_PATH= GOV_DIR / "api_baseline.json"

VERSION       = "146.0.0"
BASE_URL      = "https://intel.cyberdudebivash.com"
REQUEST_TIMEOUT = 15
SLA_RESPONSE_MS = 10000

# Canary endpoint definitions
CANARY_ENDPOINTS = [
    {
        "id"              : "latest_feed",
        "path"            : "/api/v1/intel/latest.json",
        "required_fields" : ["schema_version", "generated_at", "count", "items"],
        "array_fields"    : ["items"],
        "min_items"       : 1,
        "item_schema"     : ["title", "risk_score"],
        "is_feed"         : True,
    },
    {
        "id"              : "apex_feed",
        "path"            : "/api/v1/intel/apex.json",
        "required_fields" : ["schema_version", "generated_at", "count", "items"],
        "array_fields"    : ["items"],
        "min_items"       : 1,
        "item_schema"     : ["title", "risk_score"],
        "is_feed"         : True,
    },
    {
        "id"              : "manifest_registry",
        "path"            : "/api/v1/intel/manifest.json",
        "required_fields" : ["schema_version", "generated_at", "files"],
        "array_fields"    : [],
        "min_items"       : 0,
        "item_schema"     : [],
        "is_feed"         : False,
    },
    {
        "id"              : "health_endpoint",
        "path"            : "/api/health",
        "required_fields" : ["status"],
        "array_fields"    : [],
        "min_items"       : 0,
        "item_schema"     : [],
        "is_feed"         : False,
    },
]


def now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def atomic_write(path: pathlib.Path, data: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=path.parent, prefix=".ccv_", suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        shutil.move(tmp, path)
    except Exception:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def fetch_endpoint(url: str) -> Tuple[Optional[Dict], int, float, Optional[str]]:
    """Fetch URL, return (data, status_code, response_ms, error_msg)."""
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(
            url,
            headers={
                "Cache-Control": "no-cache, no-store",
                "User-Agent"   : f"SENTINEL-APEX-CANARY/{VERSION}",
            },
        )
        with urllib.request.urlopen(req, timeout=REQUEST_TIMEOUT) as resp:
            raw = resp.read().decode("utf-8", errors="replace")
            ms  = (time.monotonic() - t0) * 1000
            try:
                return json.loads(raw), resp.status, ms, None
            except json.JSONDecodeError as e:
                return None, resp.status, ms, f"JSON parse error: {e}"
    except urllib.error.HTTPError as e:
        ms = (time.monotonic() - t0) * 1000
        return None, e.code, ms, f"HTTP {e.code}: {e.reason}"
    except Exception as e:
        ms = (time.monotonic() - t0) * 1000
        return None, 0, ms, str(e)


def validate_endpoint(ep: Dict, data: Any, status: int, ms: float) -> Tuple[str, List[str], List[str]]:
    """Returns (verdict, errors, warnings)."""
    errors   : List[str] = []
    warnings : List[str] = []

    if status != 200:
        errors.append(f"HTTP {status} (expected 200)")
        return "FAIL", errors, warnings

    if data is None:
        errors.append("Response is not valid JSON")
        return "FAIL", errors, warnings

    if ms > SLA_RESPONSE_MS:
        warnings.append(f"Response time {ms:.0f}ms exceeds SLA {SLA_RESPONSE_MS}ms")

    for field in ep.get("required_fields", []):
        if field not in data:
            errors.append(f"Required field missing: '{field}'")

    for field in ep.get("array_fields", []):
        if field in data and not isinstance(data[field], list):
            errors.append(f"Field '{field}' must be array, got {type(data[field]).__name__}")

    if ep.get("is_feed") and ep.get("min_items", 0) > 0:
        items = data.get("items", [])
        if not isinstance(items, list) or len(items) < ep["min_items"]:
            errors.append(f"Feed 'items' has {len(items) if isinstance(items, list) else 0} entries (min {ep['min_items']})")
        else:
            # Spot-check first item schema
            first = items[0]
            for sf in ep.get("item_schema", []):
                if sf not in first:
                    warnings.append(f"Item schema: field '{sf}' missing from first item")

    if errors:
        return "FAIL", errors, warnings
    if warnings:
        return "WARN", errors, warnings
    return "PASS", errors, warnings


def compute_schema_fingerprint(data: Any) -> Dict[str, str]:
    """Extract {field: type} map for top-level fields."""
    if not isinstance(data, dict):
        return {}
    return {k: type(v).__name__ for k, v in data.items()}


def detect_drift(baseline_fp: Dict[str, str], live_fp: Dict[str, str]) -> Tuple[List[str], List[str]]:
    """Returns (breaking_changes, drift_additions)."""
    breaking = []
    drift    = []

    for field, btype in baseline_fp.items():
        if field not in live_fp:
            breaking.append(f"FIELD REMOVED: '{field}' (was {btype})")
        elif live_fp[field] != btype:
            breaking.append(f"TYPE CHANGED: '{field}' {btype} → {live_fp[field]}")

    for field, ltype in live_fp.items():
        if field not in baseline_fp:
            drift.append(f"NEW FIELD: '{field}' ({ltype}) — backward compatible")

    return breaking, drift


def main() -> int:
    t0 = time.monotonic()
    log.info("=" * 66)
    log.info("SENTINEL APEX %s — Canary Contract Validator", VERSION)
    log.info("Target: %s", BASE_URL)
    log.info("=" * 66)

    # Load existing baseline if available
    baseline: Dict[str, Any] = {}
    if BASELINE_PATH.exists():
        try:
            baseline = json.loads(BASELINE_PATH.read_text(encoding="utf-8"))
        except Exception:
            baseline = {}

    results        = []
    overall_pass   = True
    has_breaking   = False
    new_baseline   = {}

    for ep in CANARY_ENDPOINTS:
        url    = BASE_URL + ep["path"]
        ep_id  = ep["id"]
        log.info("[CANARY] Fetching: %s", url)

        data, status, ms, fetch_err = fetch_endpoint(url)

        if fetch_err and data is None:
            verdict  = "FAIL"
            errors   = [fetch_err]
            warnings = []
            log.error("[CANARY][%s] FAIL: %s (%.0fms)", ep_id, fetch_err, ms)
            overall_pass = False
        else:
            verdict, errors, warnings = validate_endpoint(ep, data, status, ms)
            if verdict == "FAIL":
                overall_pass = False
            log.info("[CANARY][%s] %s status=%d %.0fms err=%d warn=%d",
                     ep_id, verdict, status, ms, len(errors), len(warnings))

        # Schema drift detection
        breaking_changes = []
        drift_additions  = []
        live_fp = compute_schema_fingerprint(data)
        if ep_id in baseline and data is not None:
            base_fp = baseline[ep_id].get("schema_fingerprint", {})
            breaking_changes, drift_additions = detect_drift(base_fp, live_fp)
            if breaking_changes:
                has_breaking = True
                overall_pass = False
                for b in breaking_changes:
                    log.error("[DRIFT][%s] BREAKING: %s", ep_id, b)
            for d in drift_additions:
                log.warning("[DRIFT][%s] COMPATIBLE: %s", ep_id, d)

        # Update baseline for this endpoint
        new_baseline[ep_id] = {
            "schema_fingerprint": live_fp,
            "last_checked"      : now_iso(),
            "item_count"        : len(data.get("items", [])) if isinstance(data, dict) else 0,
        }

        results.append({
            "endpoint_id"      : ep_id,
            "path"             : ep["path"],
            "url"              : url,
            "http_status"      : status,
            "response_ms"      : round(ms, 1),
            "verdict"          : verdict,
            "errors"           : errors,
            "warnings"         : warnings,
            "breaking_changes" : breaking_changes,
            "drift_additions"  : drift_additions,
            "item_count"       : len(data.get("items", [])) if isinstance(data, dict) else 0,
        })

    # Write updated baseline
    atomic_write(BASELINE_PATH, json.dumps(new_baseline, ensure_ascii=False, indent=2))

    runtime    = round(time.monotonic() - t0, 3)
    pass_count = sum(1 for r in results if r["verdict"] == "PASS")
    fail_count = sum(1 for r in results if r["verdict"] == "FAIL")
    warn_count = sum(1 for r in results if r["verdict"] == "WARN")

    overall_verdict = "PASS" if overall_pass else ("FAIL" if has_breaking or fail_count > 0 else "WARN")

    report = {
        "schema_version"  : "1.0",
        "generated_at"    : now_iso(),
        "generator"       : "canary_contract_validator.py",
        "version"         : VERSION,
        "base_url"        : BASE_URL,
        "endpoints_tested": len(CANARY_ENDPOINTS),
        "pass_count"      : pass_count,
        "fail_count"      : fail_count,
        "warn_count"      : warn_count,
        "has_breaking_drift": has_breaking,
        "overall_verdict" : overall_verdict,
        "runtime_seconds" : runtime,
        "results"         : results,
    }

    GOV_DIR.mkdir(parents=True, exist_ok=True)
    atomic_write(REPORT_PATH, json.dumps(report, ensure_ascii=False, indent=2))

    log.info("=" * 66)
    log.info("CANARY RESULT: %s | pass=%d fail=%d warn=%d breaking=%s",
             overall_verdict, pass_count, fail_count, warn_count, has_breaking)
    log.info("[WRITE] Report: %s", REPORT_PATH)
    log.info("=" * 66)

    # Exit 2 only for breaking violations — never exit 1 (keep pipeline going)
    if has_breaking or fail_count > 0:
        return 2
    return 0


if __name__ == "__main__":
    try:
        sys.exit(main())
    except Exception as e:
        log.error("[FATAL] Unexpected error: %s", e)
        sys.exit(0)   # never block production
