#!/usr/bin/env python3
"""
scripts/deployment_health_contract.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- deployment vs. customer-intelligence health contract.

Why this exists (P0, 2026-09-24): after PR #488, /api/health answers HTTP 503
while customer intelligence is stale (the truthful contract). The
post-deploy release gate still required /api/health == 200 as its
"availability" probe, so a healthy Worker deployment failed validation
purely because the feed was stale -- and the only way to turn it green
would have been to make /api/health lie again. That is a contract drift in
the gate, not in the Worker.

This module separates the two questions every health consumer asks:

  1. LIVENESS / DEPLOYMENT AVAILABILITY -- is the new Worker serving?
     Proven by GET /api/health/live: HTTP 200, status "alive",
     service "sentinel-apex", non-empty version. Never data-dependent.

  2. CUSTOMER INTELLIGENCE HEALTH -- is what customers receive fresh?
     Proven by GET /api/health evaluated against the Worker's structured
     contract (workers/intel-gateway/src/freshness-contract.js ->
     evaluatePublicIntelligence):
        200 + status "ok"        + intelligence fresh              -> healthy
        503 + status "degraded"  + reason intelligence_stale       -> degraded
        503 + status "unhealthy" + one machine-readable reason     -> unhealthy
     A 503 is accepted as a VALID DEGRADED STATE only when it carries a
     well-formed SENTINEL body. Anything else -- HTML/Cloudflare error page,
     empty or malformed body, uncaught-exception 5xx, gateway failure,
     wrong service identity, a status/HTTP contradiction, a body that
     disagrees with the canonical freshness classifier, or a public body
     exposing secret/config fields -- is INVALID and fails deployment.

Deployment validation passes on (1) + a structurally valid (2) in any
state. It never certifies customer health: STAGE 5.9.10
(scripts/public_feed_freshness_gate.py) remains the fail-closed release
freshness gate, and `customer_intelligence_healthy` is reported separately
so no consumer can mistake "deployed" for "fresh".

No new threshold: freshness is re-derived with scripts/public_freshness_contract.py
(config/public_freshness_contract.json), the single authority.

CLI: python3 scripts/deployment_health_contract.py [--base-url URL]
  exit 0 = deployment operational (health state printed + GITHUB_OUTPUT)
  exit 1 = deployment NOT operational (liveness failed or health invalid)
Read-only: two GETs, no R2, no KV, no writes to production.
"""
from __future__ import annotations

import argparse
import json
import os
import re
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
if str(SCRIPTS_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPTS_DIR))

import public_freshness_contract as contract  # noqa: E402

DEFAULT_BASE = "https://intel.cyberdudebivash.com"
SERVICE_ID = "sentinel-apex"
USER_AGENT = "SENTINEL-APEX-DeployHealthContract/1.0 (+https://intel.cyberdudebivash.com)"
MAX_BODY_BYTES = 256 * 1024  # health bodies are ~1 KB; anything huge is not our contract

# Public /api/health envelope allowlist. Mirrors PUBLIC_TOP_LEVEL /
# PUBLIC_CHECKS / FORBIDDEN in
# workers/intel-gateway/src/__tests__/health-freshness-contract.test.js;
# tests/test_deployment_health_contract.py fails on drift.
PUBLIC_TOP_LEVEL = frozenset({
    "status", "service", "version", "reason", "advisory_count", "critical_count", "kev_confirmed", "last_sync",
    "feed_index", "platform_reachable", "intelligence_available", "intelligence", "checks", "generated_at",
})
PUBLIC_CHECKS = frozenset({
    "gateway", "worker_runtime", "intelligence_available", "intelligence_freshness", "publication_integrity", "feed_index",
})
PUBLIC_INTELLIGENCE = frozenset({"status", "generated_at", "age_seconds", "max_age_seconds", "advisory_count"})
FORBIDDEN_KEY_RE = re.compile(
    r"jwt|secret|razorpay|resend|admin|kv_|r2_|bucket|namespace|account|binding|token|security", re.I)

# Worker reasons (freshness-contract.js evaluatePublicIntelligence).
DEGRADED_REASON = "intelligence_stale"
REASON_TO_INTEL_STATUS = {
    "feed_unavailable": {"unavailable"},
    "invalid_feed_structure": {"invalid"},
    "generated_at_in_future": {contract.FUTURE},
    "generated_at_missing": {contract.MISSING},
    "generated_at_invalid": {contract.INVALID},
    # Items/count problems are evaluated independently of freshness.
    "no_intelligence_items": {contract.FRESH, contract.STALE, contract.FUTURE, contract.MISSING, contract.INVALID},
    "publication_count_mismatch": {contract.FRESH, contract.STALE, contract.FUTURE, contract.MISSING, contract.INVALID},
}

HEALTHY, DEGRADED, UNHEALTHY, INVALID = "healthy", "degraded", "unhealthy", "invalid"


def _walk_keys(obj, prefix=""):
    if isinstance(obj, dict):
        for k, v in obj.items():
            yield f"{prefix}{k}"
            yield from _walk_keys(v, f"{prefix}{k}.")
    elif isinstance(obj, list):
        for v in obj:
            yield from _walk_keys(v, prefix)


def evaluate_liveness(status, body, err=None) -> dict:
    """GET /api/health/live -> {"alive": bool, "version": str|None, "failures": [...]}."""
    failures: list[str] = []
    if status is None:
        failures.append(f"/api/health/live unreachable ({err or 'no response'})")
    elif status != 200:
        failures.append(f"/api/health/live returned HTTP {status} (expected 200)")
    if status is not None and not isinstance(body, dict):
        failures.append(f"/api/health/live body is not a JSON object ({err or type(body).__name__})")
        body = {}
    body = body if isinstance(body, dict) else {}
    if status is not None and isinstance(body, dict) and body:
        if body.get("status") != "alive":
            failures.append(f"/api/health/live status={body.get('status')!r} (expected 'alive')")
        if body.get("service") != SERVICE_ID:
            failures.append(f"/api/health/live service={body.get('service')!r} (expected {SERVICE_ID!r})")
    version = body.get("version")
    if status is not None and not (isinstance(version, str) and version.strip()):
        failures.append("/api/health/live carries no version")
    return {"alive": not failures, "version": version if isinstance(version, str) else None, "failures": failures}


def evaluate_health(status, body, err=None, now=None, expected_version=None) -> dict:
    """GET /api/health -> {"state": healthy|degraded|unhealthy|invalid, "valid": bool,
    "customer_healthy": bool, "reason": str|None, "failures": [...]}.

    `valid` means "a well-formed SENTINEL health contract response"; only
    `customer_healthy` means the intelligence customers receive is fresh.
    """
    failures: list[str] = []

    def out(state):
        ok_state = state if not failures else INVALID
        return {
            "state": ok_state,
            "valid": not failures,
            "customer_healthy": ok_state == HEALTHY,
            "http_status": status,
            "reason": body.get("reason") if isinstance(body, dict) else None,
            "intelligence": body.get("intelligence") if isinstance(body, dict) else None,
            "failures": failures,
        }

    if status is None:
        failures.append(f"/api/health unreachable ({err or 'no response'})")
        return out(INVALID)
    if status not in (200, 503):
        failures.append(f"/api/health returned HTTP {status}; the contract only defines 200 (ok) and 503 (degraded/unhealthy)")
        return out(INVALID)
    if not isinstance(body, dict) or not body:
        failures.append(f"/api/health HTTP {status} without a SENTINEL JSON body ({err or 'empty/non-object body'}) "
                        "-- generic/HTML/Cloudflare/exception responses are not a valid degraded state")
        return out(INVALID)

    # Identity + structure
    if body.get("service") != SERVICE_ID:
        failures.append(f"/api/health service={body.get('service')!r} (expected {SERVICE_ID!r})")
    h_status = body.get("status")
    if h_status not in ("ok", "degraded", "unhealthy"):
        failures.append(f"/api/health status={h_status!r} is not a contract state (ok|degraded|unhealthy)")
    version = body.get("version")
    if not (isinstance(version, str) and version.strip()):
        failures.append("/api/health carries no version")
    elif expected_version and version != expected_version:
        failures.append(f"/api/health served by version {version!r}, expected current Worker {expected_version!r}")
    intel = body.get("intelligence")
    checks = body.get("checks")
    if not isinstance(intel, dict):
        failures.append("/api/health missing structured `intelligence` object")
        intel = {}
    if not isinstance(checks, dict):
        failures.append("/api/health missing structured `checks` object")
        checks = {}
    elif checks.get("worker_runtime") != "ok":
        failures.append(f"/api/health checks.worker_runtime={checks.get('worker_runtime')!r} (expected 'ok')")

    # Public-exposure contract (allowlist + forbidden key names at any depth)
    extra_top = sorted(set(body) - PUBLIC_TOP_LEVEL)
    extra_checks = sorted(set(checks) - PUBLIC_CHECKS)
    extra_intel = sorted(set(intel) - PUBLIC_INTELLIGENCE)
    leaked = sorted({k for k in _walk_keys(body) if FORBIDDEN_KEY_RE.search(k)})
    if extra_top or extra_checks or extra_intel or leaked:
        failures.append("public /api/health exposes non-contract fields: "
                        f"top={extra_top} checks={extra_checks} intelligence={extra_intel} sensitive={leaked}")

    if failures:
        return out(INVALID)

    # Status <-> HTTP <-> body consistency
    reason = body.get("reason")
    i_status = intel.get("status")
    gen = intel.get("generated_at")
    derived = contract.classify_manifest_freshness(gen, now=now)["state"]

    if h_status == "ok":
        if status != 200:
            failures.append(f"contradiction: HTTP {status} with status 'ok'")
        if reason:
            failures.append(f"contradiction: status 'ok' with reason {reason!r}")
        if i_status != contract.FRESH or checks.get("intelligence_freshness") not in (None, contract.FRESH):
            failures.append(f"contradiction: status 'ok' but intelligence.status={i_status!r}")
        if derived != contract.FRESH:
            failures.append(f"contradiction: status 'ok' but generated_at={gen!r} classifies {derived!r} "
                            "under the canonical freshness contract")
        if not (isinstance(intel.get("advisory_count"), int) and intel["advisory_count"] > 0):
            failures.append("contradiction: status 'ok' with no intelligence items")
        return out(HEALTHY)

    if status != 503:
        failures.append(f"contradiction: HTTP {status} with status {h_status!r} (non-ok states must be 503)")
    if h_status == "degraded":
        if reason != DEGRADED_REASON:
            failures.append(f"status 'degraded' requires reason {DEGRADED_REASON!r}, got {reason!r}")
        if i_status != contract.STALE:
            failures.append(f"contradiction: status 'degraded' but intelligence.status={i_status!r}")
        if derived == contract.FRESH:
            failures.append(f"contradiction: status 'degraded' but generated_at={gen!r} is fresh under the canonical contract")
        return out(DEGRADED)

    # unhealthy
    allowed = REASON_TO_INTEL_STATUS.get(reason)
    if allowed is None:
        failures.append(f"status 'unhealthy' requires a machine-readable contract reason, got {reason!r}")
    elif i_status not in allowed:
        failures.append(f"contradiction: reason {reason!r} with intelligence.status={i_status!r}")
    return out(UNHEALTHY)


def evaluate_deployment(live, health, now=None) -> dict:
    """live/health are (status, body, err) triples. Deployment is operational
    when the Worker is alive AND /api/health answers with a valid contract
    body in ANY state; customer health is reported separately."""
    lv = evaluate_liveness(*live)
    hv = evaluate_health(*health, now=now, expected_version=lv["version"] if lv["alive"] else None)
    operational = lv["alive"] and hv["valid"]
    return {
        "gate": "deployment_health_contract",
        "deployment_verdict": "PASS" if operational else "FAIL",
        "deployment_operational": operational,
        "customer_intelligence_state": hv["state"],
        "customer_intelligence_healthy": hv["customer_healthy"],
        "release_freshness_certifiable": operational and hv["customer_healthy"],
        "liveness": lv,
        "health": hv,
        "failures": lv["failures"] + hv["failures"],
    }


def fetch_json(url: str, timeout: float, headers: dict | None = None):
    """(status|None, body|None, err|None). Keeps HTTP error bodies (503 envelopes)."""
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache", **(headers or {})})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read(MAX_BODY_BYTES + 1)
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read(MAX_BODY_BYTES + 1)
    except Exception as e:  # DNS / TLS / reset / timeout
        return None, None, f"{type(e).__name__}: {e}"
    if len(raw) > MAX_BODY_BYTES:
        return status, None, "body exceeds health contract size"
    if not raw.strip():
        return status, None, "empty body"
    try:
        return status, json.loads(raw.decode("utf-8")), None
    except Exception as e:
        return status, None, f"invalid JSON: {e}"


def probe(base: str, timeout: float = 15.0) -> tuple:
    cb = str(int(time.time()))
    base = base.rstrip("/")
    return (fetch_json(f"{base}/api/health/live?deploy_gate={cb}", timeout),
            fetch_json(f"{base}/api/health?deploy_gate={cb}", timeout))


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default=DEFAULT_BASE)
    ap.add_argument("--timeout", type=float, default=15.0)
    args = ap.parse_args(argv)

    live, health = probe(args.base_url, args.timeout)
    report = evaluate_deployment(live, health)
    print(json.dumps(report, indent=2))

    gh_out = os.environ.get("GITHUB_OUTPUT")
    if gh_out:
        with open(gh_out, "a", encoding="utf-8") as fh:
            fh.write(f"deployment_operational={str(report['deployment_operational']).lower()}\n")
            fh.write(f"intelligence_state={report['customer_intelligence_state']}\n")
            fh.write(f"intelligence_healthy={str(report['customer_intelligence_healthy']).lower()}\n")

    if not report["deployment_operational"]:
        for f in report["failures"]:
            print(f"::error::DEPLOYMENT HEALTH CONTRACT: {f}", flush=True)
        return 1
    if not report["customer_intelligence_healthy"]:
        print(f"::warning::Worker deployment OPERATIONAL; customer intelligence {report['customer_intelligence_state'].upper()} "
              f"(reason={report['health']['reason']}). Release freshness certification remains blocked "
              "until STAGE 5.9.10 (scripts/public_feed_freshness_gate.py) passes.", flush=True)
    else:
        print("::notice::Worker deployment OPERATIONAL; customer intelligence HEALTHY (fresh).", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
