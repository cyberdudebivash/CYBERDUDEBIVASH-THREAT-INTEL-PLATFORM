#!/usr/bin/env python3
"""
scripts/feed_contract_validator.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Feed & Worker Contract Validator v1.0
=========================================================================
MANDATE: Prevent ALL future canary false-negatives caused by schema drift
         between the Cloudflare Worker response envelopes and the deployment
         canary expectations. The Canary B "items=0" false-negative (Run
         25621416977) was caused by exactly this type of contract drift.

CONTRACT REGISTRY: defines the canonical response schema for every endpoint
that the deployment canary validates. If the Worker changes its envelope
shape without updating this contract, this script raises a HARD FAIL and
blocks the deployment pipeline before any canary even runs.

CHECKS:
  CONTRACT-1 : /api/preview  -- envelope shape (preview.items, total_preview)
  CONTRACT-2 : /api/health   -- envelope shape (status, version, checks)
  CONTRACT-3 : /api/feed     -- auth gate (401/403 is valid, 200 requires shape)
  CONTRACT-4 : /version.json -- envelope shape (version, platform)
  CONTRACT-5 : Worker index.js handlePreview() returns nested envelope
               and canary_b_preview() can parse it (cross-validation)
  CONTRACT-6 : Preview item schema -- required fields on each preview item
  CONTRACT-7 : No envelope drift -- compare live vs. registered contract
  CONTRACT-8 : Canary MIN_PREVIEW_ITEMS gate alignment with live feed
  CONTRACT-9 : Feed manifest Worker compatibility (normaliseManifestData path)
  CONTRACT-10: KV cache envelope matches live envelope (cache coherence)

SEVERITY TIERS:
  HARD FAIL  -- blocks pipeline (exit code 1) -- unacceptable regression
  SOFT FAIL  -- degrades signal (exit code 3) -- tracked, non-blocking
  WARN       -- advisory (exit code 0)         -- logged, no gate impact

CI Usage:
  python3 scripts/feed_contract_validator.py [--live] [--base-url URL]
          [--timeout 30] [--strict] [--report PATH]

  --live   : Hit real endpoints (requires network). Default: offline/local mode.
  --strict : Treat SOFT FAILs as HARD FAILs.

(c) 2026 CYBERDUDEBIVASH PRIVATE LIMITED. CONFIDENTIAL.
"""
from __future__ import annotations

import argparse
import json
import logging
import os
import re
import sys
import time
import urllib.error
import urllib.request
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [CDB-CONTRACT] %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
)
log = logging.getLogger("CDB-CONTRACT")

SCRIPT_VERSION  = "1.0.0"
PLATFORM_BASE   = "https://intel.cyberdudebivash.com"
DEFAULT_TIMEOUT = 20

# ─── Canonical Contract Registry ───────────────────────────────────────────
# These contracts mirror exactly what the Cloudflare Worker emits.
# If the Worker changes its envelope, update the contract here AND update
# the deployment canary simultaneously — drift between the two causes false
# negatives or false positives.

CONTRACTS: Dict[str, Dict] = {
    "/api/preview": {
        "description": "Public preview feed endpoint",
        "canary": "B",
        "http_status": [200],
        "content_type_prefix": "application/json",
        # Top-level envelope required keys
        "envelope_required": ["status", "preview"],
        "envelope_types": {
            "status": str,
            "preview": dict,
        },
        "envelope_values": {
            "status": "ok",
        },
        # Nested: preview object required keys
        "nested": {
            "preview": {
                "required": ["items", "total_preview"],
                "types": {
                    "items": list,
                    "total_preview": int,
                },
                "items_min_count": 3,  # must match MIN_PREVIEW_ITEMS in deployment_canary.py
            }
        },
        # Per-item schema inside preview.items
        "item_schema": {
            "required_fields": ["id", "title", "severity", "risk_score", "stix_id"],
            "optional_fields": [
                "description", "tags", "threat_type", "confidence",
                "processed_at", "timestamp", "published_at", "source",
                "report_url", "kev_present", "ttps", "ttp_count",
                "ioc_count", "apex_ai", "mitre_tactics",
            ],
            "type_checks": {
                "id":         str,
                "title":      str,
                "severity":   str,
                "risk_score": (int, float),
                "stix_id":    str,
                "tags":       list,
                "ttps":       list,
            },
        },
    },

    "/api/health": {
        "description": "API health / gateway status endpoint",
        "canary": "A",
        "http_status": [200, 207],  # 207 = degraded but alive
        "content_type_prefix": "application/json",
        "envelope_required": ["status", "version", "checks"],
        "envelope_types": {
            "status":  str,
            "version": str,
            "checks":  dict,
        },
        "envelope_values": {
            # status must be one of these — canary_a_health checks .get("status") in (healthy/ok/operational)
            "status:oneof": ["healthy", "ok", "operational", "degraded"],
        },
        "nested": {
            "checks": {
                "required": [],  # at least one check key must be present
                "min_keys": 1,
            }
        },
    },

    "/api/feed": {
        "description": "Authenticated intel feed endpoint",
        "canary": "C",
        # Auth gate: 200 (authenticated), 401 (no key), 403 (forbidden) all VALID
        "http_status": [200, 401, 403],
        "content_type_prefix": "application/json",
        # No envelope checks needed — canary C only checks HTTP status
        "envelope_required": [],
    },

    "/version.json": {
        "description": "Platform version file",
        "canary": "E",
        "http_status": [200],
        "content_type_prefix": "application/json",
        "envelope_required": ["version"],
        "envelope_types": {
            "version": str,
        },
    },

    "/": {
        "description": "Dashboard HTML frontend",
        "canary": "D",
        "http_status": [200],
        "content_type_prefix": "text/html",
        "body_contains": ["<!DOCTYPE", "<!doctype"],
        "body_excludes": ["500 Internal Server Error", "502 Bad Gateway"],
    },
}

# Alignment: MIN_PREVIEW_ITEMS in deployment_canary.py (must stay in sync)
CANARY_MIN_PREVIEW_ITEMS = 3

# Worker JS source path (relative to repo root) — for static analysis
WORKER_SRC_PATH = Path("workers") / "intel-gateway" / "src" / "index.js"
CANARY_SCRIPT   = Path("scripts") / "deployment_canary.py"


# ─── Data Structures ────────────────────────────────────────────────────────

@dataclass
class ContractViolation:
    endpoint:    str
    contract_id: str
    severity:    str  # HARD | SOFT | WARN
    message:     str
    detail:      str = ""


@dataclass
class ContractReport:
    run_at:         str
    script_version: str
    mode:           str  # live | offline
    base_url:       str
    checks_run:     int                       = 0
    checks_passed:  int                       = 0
    checks_failed:  int                       = 0
    hard_fails:     List[ContractViolation]   = field(default_factory=list)
    soft_fails:     List[ContractViolation]   = field(default_factory=list)
    warnings:       List[ContractViolation]   = field(default_factory=list)
    overall_pass:   bool                      = True
    exit_code:      int                       = 0
    summary:        str                       = ""


# ─── HTTP Fetch ─────────────────────────────────────────────────────────────

def _fetch(url: str, timeout: int, token: Optional[str] = None) -> Tuple[int, str, Dict[str, str]]:
    """Returns (status_code, body_text, headers_dict)."""
    headers = {"User-Agent": "SentinelApex-ContractValidator/1.0"}
    if token:
        headers["Authorization"] = "Bearer %s" % token
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body    = resp.read(131072).decode("utf-8", errors="replace")
            hdrs    = dict(resp.headers)
            return resp.status, body, hdrs
    except urllib.error.HTTPError as exc:
        hdrs = dict(exc.headers) if exc.headers else {}
        return exc.code, str(exc), hdrs
    except Exception as exc:
        return 0, str(exc), {}


# ─── Contract Engine ─────────────────────────────────────────────────────────

class FeedContractValidator:
    def __init__(self, base_url: str, timeout: int, live: bool, repo_root: Path):
        self.base        = base_url.rstrip("/")
        self.timeout     = timeout
        self.live        = live
        self.repo_root   = repo_root
        self.report      = ContractReport(
            run_at         = datetime.now(timezone.utc).isoformat(),
            script_version = SCRIPT_VERSION,
            mode           = "live" if live else "offline",
            base_url       = base_url,
        )

    # ── violation helpers ───────────────────────────────────────────────────

    def _hard(self, endpoint: str, cid: str, msg: str, detail: str = "") -> ContractViolation:
        v = ContractViolation(endpoint, cid, "HARD", msg, detail)
        self.report.hard_fails.append(v)
        self.report.checks_failed += 1
        self.report.overall_pass   = False
        log.error("[HARD] %s | %s | %s", endpoint, cid, msg)
        return v

    def _soft(self, endpoint: str, cid: str, msg: str, detail: str = "") -> ContractViolation:
        v = ContractViolation(endpoint, cid, "SOFT", msg, detail)
        self.report.soft_fails.append(v)
        self.report.checks_failed += 1
        log.warning("[SOFT] %s | %s | %s", endpoint, cid, msg)
        return v

    def _warn(self, endpoint: str, cid: str, msg: str, detail: str = "") -> ContractViolation:
        v = ContractViolation(endpoint, cid, "WARN", msg, detail)
        self.report.warnings.append(v)
        log.info("[WARN] %s | %s | %s", endpoint, cid, msg)
        return v

    def _pass(self, endpoint: str, cid: str, msg: str = "") -> None:
        self.report.checks_passed += 1
        self.report.checks_run    += 1
        log.info("[PASS] %s | %s%s", endpoint, cid, " | " + msg if msg else "")

    def _tick(self) -> None:
        self.report.checks_run += 1

    # ── CONTRACT-5 / CONTRACT-7: static source analysis ────────────────────

    def check_worker_source_contracts(self) -> None:
        """CONTRACT-5 + CONTRACT-7: Parse index.js to verify envelope shapes
        match the registered contracts. No network required."""
        wp = self.repo_root / WORKER_SRC_PATH
        if not wp.exists():
            self._warn("/worker/src", "CONTRACT-7",
                       "Worker source index.js not found — skipping static analysis",
                       str(wp))
            return

        src = wp.read_text(encoding="utf-8", errors="replace")

        # CONTRACT-5: Verify handlePreview() returns nested envelope
        # We expect: preview: { items: [...], total_preview: N, ... }
        self._tick()
        # Check that the previewPayload pattern is present
        if "total_preview:" in src and "preview:" in src:
            # Verify the structure: previewPayload has items + total_preview
            if re.search(r"previewPayload\s*=\s*\{[^}]*\bitems\b", src, re.DOTALL):
                self._pass("/api/preview", "CONTRACT-5",
                           "handlePreview() emits previewPayload.items (nested envelope confirmed)")
            else:
                self._hard("/api/preview", "CONTRACT-5",
                           "handlePreview() previewPayload structure changed -- canary B may false-negative",
                           "Expected: previewPayload = { items: [...], total_preview: N }")
        else:
            self._hard("/api/preview", "CONTRACT-5",
                       "handlePreview() envelope missing 'items' or 'total_preview' keys in Worker source",
                       "Root cause of Run 25621416977 canary B false-negative")

        # CONTRACT-5b: Verify the final jsonResponse wraps preview: previewPayload
        self._tick()
        # The response must be: { status:"ok", preview: previewPayload, ... }
        if re.search(r'preview\s*:\s*previewPayload', src):
            self._pass("/api/preview", "CONTRACT-5b",
                       "handlePreview() final response wraps payload under 'preview' key")
        else:
            self._hard("/api/preview", "CONTRACT-5b",
                       "handlePreview() may not nest payload under 'preview' key",
                       "Contract requires: { status:'ok', preview: { items:[...], total_preview:N }}")

        # CONTRACT-7: Verify canary parser alignment with Worker envelope
        cp = self.repo_root / CANARY_SCRIPT
        if cp.exists():
            csrc = cp.read_text(encoding="utf-8", errors="replace")
            self._tick()
            # The canary must check data["preview"] (not just data["items"])
            if 'data.get("preview")' in csrc or "data.get('preview')" in csrc:
                self._pass("/api/preview", "CONTRACT-7",
                           "canary_b_preview() reads data['preview'] -- aligned with Worker envelope")
            else:
                self._hard("/api/preview", "CONTRACT-7",
                           "canary_b_preview() does NOT read data['preview'] -- WILL false-negative",
                           "Fix: check isinstance(data.get('preview'), dict) -> data['preview']['items']")

            # CONTRACT-8: MIN_PREVIEW_ITEMS alignment
            self._tick()
            m = re.search(r'MIN_PREVIEW_ITEMS\s*=\s*(\d+)', csrc)
            if m:
                canary_min = int(m.group(1))
                contract_min = CONTRACTS["/api/preview"]["nested"]["preview"]["items_min_count"]
                if canary_min == contract_min == CANARY_MIN_PREVIEW_ITEMS:
                    self._pass("/api/preview", "CONTRACT-8",
                               "MIN_PREVIEW_ITEMS aligned: canary=%d contract=%d" % (canary_min, contract_min))
                else:
                    self._soft("/api/preview", "CONTRACT-8",
                               "MIN_PREVIEW_ITEMS drift: canary=%d vs contract=%d vs validator=%d" % (
                                   canary_min, contract_min, CANARY_MIN_PREVIEW_ITEMS),
                               "Update all three locations to stay in sync")
            else:
                self._warn("/api/preview", "CONTRACT-8",
                           "Cannot read MIN_PREVIEW_ITEMS from deployment_canary.py")
        else:
            self._warn("/api/preview", "CONTRACT-7",
                       "deployment_canary.py not found -- cannot cross-validate envelope parser")

        # CONTRACT-9: Feed manifest normaliseManifestData compatibility
        self._tick()
        # Worker checks data.advisories first (bootstrap_critical_files.py writes { advisories: [...] })
        if "normaliseManifestData" in src:
            if re.search(r'\.advisories', src) and re.search(r'\.reports', src):
                self._pass("/api/feed", "CONTRACT-9",
                           "normaliseManifestData() handles both advisories and reports keys")
            else:
                self._soft("/api/feed", "CONTRACT-9",
                           "normaliseManifestData() may not handle all manifest shapes",
                           "Expected: checks data.advisories, data.reports, direct array, data.items")
        else:
            self._warn("/api/feed", "CONTRACT-9",
                       "normaliseManifestData() not found in Worker source -- function may have been renamed")

        # CONTRACT-10a: Health endpoint status values align with canary expectation
        self._tick()
        canary_health_values = {"healthy", "ok", "operational"}
        # Worker emits: "healthy" | "ok" | "degraded"
        worker_health_values = set()
        for m in re.finditer(r'"(healthy|ok|degraded|operational)"', src):
            worker_health_values.add(m.group(1))
        overlap = canary_health_values & worker_health_values
        if overlap:
            self._pass("/api/health", "CONTRACT-10a",
                       "Health status values overlap (Worker emits, canary accepts): %s" % sorted(overlap))
        else:
            self._hard("/api/health", "CONTRACT-10a",
                       "No overlap between Worker health status values and canary acceptable values",
                       "canary expects: %s; found in Worker: %s" % (
                           sorted(canary_health_values), sorted(worker_health_values)))

    # ── CONTRACT-1 through CONTRACT-4: live endpoint validation ────────────

    def _validate_envelope(self, endpoint: str, data: Any, contract: Dict) -> None:
        """Validate JSON response data against a contract definition."""

        # Required top-level keys
        for key in contract.get("envelope_required", []):
            self._tick()
            if not isinstance(data, dict) or key not in data:
                self._hard(endpoint, "CONTRACT-ENV",
                           "Missing required envelope key: '%s'" % key,
                           "Actual keys: %s" % (list(data.keys()) if isinstance(data, dict) else type(data).__name__))
            else:
                self._pass(endpoint, "CONTRACT-ENV", "key '%s' present" % key)

        # Type checks
        for key, expected_type in contract.get("envelope_types", {}).items():
            if not isinstance(data, dict) or key not in data:
                continue  # already caught above
            self._tick()
            val = data[key]
            if isinstance(expected_type, tuple):
                ok = isinstance(val, expected_type)
            else:
                ok = isinstance(val, expected_type)
            if ok:
                self._pass(endpoint, "CONTRACT-TYPE", "key '%s' type OK" % key)
            else:
                self._hard(endpoint, "CONTRACT-TYPE",
                           "Key '%s' wrong type: expected %s got %s" % (
                               key, expected_type, type(val).__name__))

        # Value checks
        for key, expected in contract.get("envelope_values", {}).items():
            if ":oneof" in key:
                real_key = key.replace(":oneof", "")
                if isinstance(data, dict) and real_key in data:
                    self._tick()
                    if data[real_key] in expected:
                        self._pass(endpoint, "CONTRACT-VAL",
                                   "key '%s' = '%s' (in allowed set)" % (real_key, data[real_key]))
                    else:
                        self._hard(endpoint, "CONTRACT-VAL",
                                   "key '%s' value '%s' not in allowed set %s" % (
                                       real_key, data[real_key], expected))
            else:
                if isinstance(data, dict) and key in data:
                    self._tick()
                    if data[key] == expected:
                        self._pass(endpoint, "CONTRACT-VAL",
                                   "key '%s' = '%s'" % (key, expected))
                    else:
                        self._hard(endpoint, "CONTRACT-VAL",
                                   "key '%s' expected '%s' got '%s'" % (key, expected, data[key]))

        # Nested object checks
        for nest_key, nest_contract in contract.get("nested", {}).items():
            if not isinstance(data, dict) or nest_key not in data:
                continue
            nested = data[nest_key]
            if not isinstance(nested, dict):
                self._hard(endpoint, "CONTRACT-NEST",
                           "Key '%s' expected dict, got %s" % (nest_key, type(nested).__name__))
                continue

            for req_key in nest_contract.get("required", []):
                self._tick()
                if req_key not in nested:
                    self._hard(endpoint, "CONTRACT-NEST",
                               "Nested '%s.%s' required but missing" % (nest_key, req_key),
                               "Actual nested keys: %s" % list(nested.keys()))
                else:
                    self._pass(endpoint, "CONTRACT-NEST",
                               "nested '%s.%s' present" % (nest_key, req_key))

            # Type checks on nested keys
            for nk, nt in nest_contract.get("types", {}).items():
                if nk not in nested:
                    continue
                self._tick()
                if isinstance(nested[nk], nt):
                    self._pass(endpoint, "CONTRACT-NEST-TYPE",
                               "nested '%s.%s' type OK" % (nest_key, nk))
                else:
                    self._hard(endpoint, "CONTRACT-NEST-TYPE",
                               "nested '%s.%s' type wrong: expected %s got %s" % (
                                   nest_key, nk, nt.__name__, type(nested[nk]).__name__))

            # Minimum item count
            min_count = nest_contract.get("items_min_count")
            if min_count is not None and "items" in nested:
                self._tick()
                actual = len(nested["items"]) if isinstance(nested["items"], list) else 0
                if actual >= min_count:
                    self._pass(endpoint, "CONTRACT-NEST-COUNT",
                               "items count %d >= min %d" % (actual, min_count))
                else:
                    self._hard(endpoint, "CONTRACT-NEST-COUNT",
                               "items count %d < min %d (canary B would HARD FAIL)" % (actual, min_count),
                               "Either live feed is empty or Worker is returning wrong envelope")

            # Minimum key count
            min_keys = nest_contract.get("min_keys")
            if min_keys is not None:
                self._tick()
                if len(nested) >= min_keys:
                    self._pass(endpoint, "CONTRACT-NEST-KEYS",
                               "nested '%s' has %d keys (min %d)" % (nest_key, len(nested), min_keys))
                else:
                    self._soft(endpoint, "CONTRACT-NEST-KEYS",
                               "nested '%s' has %d keys, expected >= %d" % (
                                   nest_key, len(nested), min_keys))

    def _validate_preview_items(self, endpoint: str, items: List, item_schema: Dict) -> None:
        """CONTRACT-6: Validate each preview item schema."""
        if not items:
            return

        required = item_schema.get("required_fields", [])
        type_checks = item_schema.get("type_checks", {})

        errors = 0
        for idx, item in enumerate(items[:5]):  # sample first 5 items
            if not isinstance(item, dict):
                self._hard(endpoint, "CONTRACT-6",
                           "Item[%d] is not a dict: %s" % (idx, type(item).__name__))
                errors += 1
                continue

            for req_field in required:
                self._tick()
                if req_field not in item:
                    self._hard(endpoint, "CONTRACT-6",
                               "Item[%d] missing required field '%s'" % (idx, req_field),
                               "Present fields: %s" % list(item.keys())[:10])
                    errors += 1
                else:
                    self._pass(endpoint, "CONTRACT-6",
                               "item[%d].%s present" % (idx, req_field))

            for field_name, expected_type in type_checks.items():
                if field_name not in item:
                    continue
                self._tick()
                if isinstance(expected_type, tuple):
                    ok = isinstance(item[field_name], expected_type)
                else:
                    ok = isinstance(item[field_name], expected_type)
                if ok:
                    self._pass(endpoint, "CONTRACT-6-TYPE",
                               "item[%d].%s type OK" % (idx, field_name))
                else:
                    self._soft(endpoint, "CONTRACT-6-TYPE",
                               "item[%d].%s type mismatch: expected %s got %s" % (
                                   idx, field_name, expected_type, type(item[field_name]).__name__))

        if errors == 0 and items:
            log.info("[CONTRACT-6] Preview item schema: OK (sampled %d items)", min(5, len(items)))

    def check_live_endpoints(self) -> None:
        """Run live HTTP contract validation against all registered endpoint contracts."""
        for endpoint, contract in CONTRACTS.items():
            url = self.base + endpoint
            log.info("Checking contract: %s %s", endpoint, contract["description"])
            t0 = time.monotonic()
            status, body, hdrs = _fetch(url, self.timeout)
            latency = int((time.monotonic() - t0) * 1000)

            # HTTP status check
            self._tick()
            allowed_statuses = contract.get("http_status", [200])
            if status in allowed_statuses:
                self._pass(endpoint, "CONTRACT-HTTP",
                           "HTTP %d OK (%dms)" % (status, latency))
            elif status == 0:
                self._hard(endpoint, "CONTRACT-HTTP",
                           "Connection failed (timeout/network): %s" % body[:100],
                           "URL: %s" % url)
                continue  # cannot validate further
            else:
                self._hard(endpoint, "CONTRACT-HTTP",
                           "HTTP %d not in allowed set %s (%dms)" % (
                               status, allowed_statuses, latency),
                           "URL: %s" % url)
                # Continue for content-type + body checks even on bad status

            # Content-type check
            ct_prefix = contract.get("content_type_prefix")
            if ct_prefix:
                self._tick()
                ct_actual = hdrs.get("Content-Type", hdrs.get("content-type", ""))
                if ct_actual.startswith(ct_prefix):
                    self._pass(endpoint, "CONTRACT-CT",
                               "Content-Type '%s' OK" % ct_actual.split(";")[0])
                else:
                    self._soft(endpoint, "CONTRACT-CT",
                               "Content-Type mismatch: expected prefix '%s' got '%s'" % (
                                   ct_prefix, ct_actual))

            # JSON contracts
            if contract.get("content_type_prefix") == "application/json" and body:
                try:
                    data = json.loads(body)
                except Exception as exc:
                    self._hard(endpoint, "CONTRACT-JSON",
                               "Response is not valid JSON: %s" % str(exc)[:80],
                               "Body (first 200 chars): %s" % body[:200])
                    continue

                # Only validate envelope if HTTP status was acceptable
                if status in allowed_statuses:
                    self._validate_envelope(endpoint, data, contract)

                    # CONTRACT-6: preview item schema
                    if endpoint == "/api/preview" and isinstance(data, dict):
                        preview = data.get("preview", {})
                        if isinstance(preview, dict):
                            items = preview.get("items", [])
                            if items:
                                self._validate_preview_items(
                                    endpoint, items,
                                    contract.get("item_schema", {})
                                )

            # HTML body checks
            if contract.get("content_type_prefix") == "text/html" and body:
                for expected in contract.get("body_contains", []):
                    self._tick()
                    if expected in body:
                        self._pass(endpoint, "CONTRACT-HTML",
                                   "body contains '%s'" % expected)
                    else:
                        self._hard(endpoint, "CONTRACT-HTML",
                                   "body missing expected string '%s'" % expected)

                for excluded in contract.get("body_excludes", []):
                    self._tick()
                    if excluded not in body:
                        self._pass(endpoint, "CONTRACT-HTML",
                                   "body clean (no '%s')" % excluded)
                    else:
                        self._hard(endpoint, "CONTRACT-HTML",
                                   "body contains error marker '%s'" % excluded)

    # ── CONTRACT-9: Feed manifest local validation ──────────────────────────

    def check_local_manifest_contract(self) -> None:
        """CONTRACT-9 (local): Validate that feed_manifest.json uses the schema
        that normaliseManifestData() in the Worker can parse."""
        manifest_path = self.repo_root / "data" / "stix" / "feed_manifest.json"
        if not manifest_path.exists():
            self._warn("/manifest", "CONTRACT-9-LOCAL",
                       "data/stix/feed_manifest.json not found (normal at pipeline start)",
                       "bootstrap_critical_files.py resets this to 0 entries before rebuild")
            return

        try:
            data = json.loads(manifest_path.read_text(encoding="utf-8"))
        except Exception as exc:
            self._hard("/manifest", "CONTRACT-9-LOCAL",
                       "feed_manifest.json is not valid JSON: %s" % exc)
            return

        self._tick()
        # Worker normaliseManifestData() priority: advisories → reports → direct array → items/entries/feed/data
        if isinstance(data, list):
            items = data
            shape = "direct_array"
        elif isinstance(data.get("advisories"), list):
            items = data["advisories"]
            shape = "advisories"
        elif isinstance(data.get("reports"), list):
            items = data["reports"]
            shape = "reports"
        else:
            for alt_key in ("items", "entries", "feed", "data"):
                if isinstance(data.get(alt_key), list):
                    items = data[alt_key]
                    shape = alt_key
                    break
            else:
                items = []
                shape = "unknown"

        if shape == "unknown" or not items:
            count = len(items)
            if count == 0:
                self._warn("/manifest", "CONTRACT-9-LOCAL",
                           "Manifest is empty (0 items) -- normal at pipeline start, non-fatal",
                           "shape=%s" % shape)
            else:
                self._hard("/manifest", "CONTRACT-9-LOCAL",
                           "feed_manifest.json shape '%s' not parseable by normaliseManifestData()" % shape,
                           "Expected one of: list | {advisories:[]} | {reports:[]} | {items:[]}")
        else:
            self._pass("/manifest", "CONTRACT-9-LOCAL",
                       "feed_manifest.json shape '%s' with %d items is parseable" % (shape, len(items)))

        # Validate generated_at field
        self._tick()
        if "generated_at" in data or isinstance(data, list):
            self._pass("/manifest", "CONTRACT-9-LOCAL-TS",
                       "generated_at present")
        else:
            self._warn("/manifest", "CONTRACT-9-LOCAL-TS",
                       "generated_at missing from manifest -- Worker freshness display may be stale")

    # ── CONTRACT-10b: KV cache coherence (live only) ────────────────────────

    def check_kv_cache_coherence(self) -> None:
        """CONTRACT-10b: Verify that the cached response (if any) returned
        from /api/preview has the same envelope shape as an uncached response.
        This is live-only and uses the 'cached' flag in the Worker response."""
        if not self.live:
            return

        url = self.base + "/api/preview"
        _, body, _ = _fetch(url, self.timeout)
        try:
            data = json.loads(body)
        except Exception:
            return

        self._tick()
        cached_flag = data.get("cached", None)
        if cached_flag is None:
            self._warn("/api/preview", "CONTRACT-10b",
                       "Response has no 'cached' flag -- cannot determine KV hit/miss")
        elif cached_flag is True:
            # Cached response -- validate that preview.items still parses correctly
            preview = data.get("preview", {})
            items   = preview.get("items", []) if isinstance(preview, dict) else []
            if len(items) >= CANARY_MIN_PREVIEW_ITEMS:
                self._pass("/api/preview", "CONTRACT-10b",
                           "KV-cached response has %d items (>= min %d) -- cache coherent" % (
                               len(items), CANARY_MIN_PREVIEW_ITEMS))
            else:
                self._hard("/api/preview", "CONTRACT-10b",
                           "KV-cached response has %d items < min %d -- stale/corrupt KV cache" % (
                               len(items), CANARY_MIN_PREVIEW_ITEMS),
                           "Invalidate idx:preview KV key or wait for TTL expiry (5min)")
        else:
            self._pass("/api/preview", "CONTRACT-10b",
                       "Live (uncached) response -- KV cache coherence check skipped")

    # ── Main run ────────────────────────────────────────────────────────────

    def run(self) -> ContractReport:
        log.info("=" * 60)
        log.info("SENTINEL APEX Feed Contract Validator v%s", SCRIPT_VERSION)
        log.info("Mode   : %s", "LIVE" if self.live else "OFFLINE (static analysis only)")
        log.info("Base   : %s", self.base)
        log.info("=" * 60)

        # Always run static source analysis (no network needed)
        self.check_worker_source_contracts()

        # Always run local manifest contract check
        self.check_local_manifest_contract()

        # Live checks only when --live flag is provided
        if self.live:
            log.info("Running live endpoint contract checks...")
            self.check_live_endpoints()
            self.check_kv_cache_coherence()
        else:
            log.info("Skipping live endpoint checks (use --live to enable)")

        # Final assessment
        report = self.report
        report.checks_run = (
            report.checks_passed + report.checks_failed
        )
        hard_count = len(report.hard_fails)
        soft_count = len(report.soft_fails)
        warn_count = len(report.warnings)

        if hard_count > 0:
            report.exit_code  = 1
            report.overall_pass = False
            report.summary = (
                "HARD FAIL: %d contract violations (%d hard, %d soft, %d warn). "
                "Deployment BLOCKED." % (hard_count + soft_count, hard_count, soft_count, warn_count)
            )
        elif soft_count > 0:
            report.exit_code  = 3
            report.summary = (
                "DEGRADED: %d soft violations (%d soft, %d warn). "
                "Deployment allowed with caution." % (soft_count, soft_count, warn_count)
            )
        else:
            report.exit_code  = 0
            report.overall_pass = True
            report.summary = (
                "ALL CONTRACTS VALID: %d checks passed, %d warnings. "
                "Deployment safe." % (report.checks_passed, warn_count)
            )

        return report


# ─── Reporting ───────────────────────────────────────────────────────────────

def print_report(report: ContractReport) -> None:
    print()
    print("=" * 66)
    print("  SENTINEL APEX FEED CONTRACT VALIDATOR REPORT")
    print("  %s" % report.run_at)
    print("  Mode: %s | Base: %s" % (report.mode.upper(), report.base_url))
    print("=" * 66)

    if report.hard_fails:
        print("\n  ── HARD FAILURES (DEPLOYMENT BLOCKED) ──")
        for v in report.hard_fails:
            print("  [HARD] %s | %s" % (v.endpoint, v.message))
            if v.detail:
                print("         Detail: %s" % v.detail)

    if report.soft_fails:
        print("\n  ── SOFT FAILURES (monitor, non-blocking) ──")
        for v in report.soft_fails:
            print("  [SOFT] %s | %s" % (v.endpoint, v.message))
            if v.detail:
                print("         Detail: %s" % v.detail)

    if report.warnings:
        print("\n  ── WARNINGS ──")
        for v in report.warnings:
            print("  [WARN] %s | %s" % (v.endpoint, v.message))

    print()
    print("  Checks: %d passed / %d failed / %d total" % (
        report.checks_passed, report.checks_failed, report.checks_run))
    print()
    icon = "PASS" if report.exit_code == 0 else ("HARD FAIL" if report.exit_code == 1 else "DEGRADED")
    print("  Result: [%s] %s" % (icon, report.summary))
    print("=" * 66)
    print()


def write_json_report(report: ContractReport, path: Path) -> None:
    """Write machine-readable JSON report for CI artifact ingestion."""
    path.parent.mkdir(parents=True, exist_ok=True)

    def _conv(obj):
        if isinstance(obj, ContractViolation):
            return asdict(obj)
        raise TypeError("Unserializable: %s" % type(obj))

    payload = {
        "run_at":         report.run_at,
        "script_version": report.script_version,
        "mode":           report.mode,
        "base_url":       report.base_url,
        "checks_passed":  report.checks_passed,
        "checks_failed":  report.checks_failed,
        "checks_run":     report.checks_run,
        "overall_pass":   report.overall_pass,
        "exit_code":      report.exit_code,
        "summary":        report.summary,
        "hard_fails":     [asdict(v) for v in report.hard_fails],
        "soft_fails":     [asdict(v) for v in report.soft_fails],
        "warnings":       [asdict(v) for v in report.warnings],
    }

    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
    tmp.replace(path)
    log.info("Contract report written: %s", path)


# ─── CLI ────────────────────────────────────────────────────────────────────

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Feed & Worker Contract Validator"
    )
    parser.add_argument("--live", action="store_true",
                        help="Hit live endpoints (requires network). Default: static analysis only.")
    parser.add_argument("--base-url", default=PLATFORM_BASE,
                        help="Platform base URL (default: %s)" % PLATFORM_BASE)
    parser.add_argument("--timeout", type=int, default=DEFAULT_TIMEOUT,
                        help="HTTP timeout per request in seconds")
    parser.add_argument("--strict", action="store_true",
                        help="Treat SOFT FAILs as HARD FAILs (exit code 1)")
    parser.add_argument("--report", default="data/governance/contract_report.json",
                        help="Path to write JSON report (default: data/governance/contract_report.json)")
    parser.add_argument("--repo-root", default=".",
                        help="Repository root directory (default: current directory)")
    args = parser.parse_args()

    repo_root = Path(args.repo_root).resolve()

    validator = FeedContractValidator(
        base_url  = args.base_url,
        timeout   = args.timeout,
        live      = args.live,
        repo_root = repo_root,
    )

    report = validator.run()

    print_report(report)

    report_path = repo_root / args.report
    write_json_report(report, report_path)

    # --strict: promote soft fails to hard fails
    if args.strict and report.soft_fails and report.exit_code == 3:
        log.error("--strict mode: %d soft fail(s) promoted to HARD FAIL", len(report.soft_fails))
        return 1

    return report.exit_code


if __name__ == "__main__":
    sys.exit(main())
