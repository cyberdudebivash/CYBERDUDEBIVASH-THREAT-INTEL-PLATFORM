#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Post-Deploy Validator
==========================================================
Phase 6: Production Validation Gates

Executed automatically after every successful deploy-worker run.
Verifies all production endpoints are healthy and serving correct data.

Exit codes:
  0 = ALL GATES PASSED -- deployment validated
  1 = VALIDATION FAILED -- manual intervention required
  2 = PARTIAL FAILURE -- degraded but acceptable

Gates:
  GATE A: API endpoint availability (latest.json, top10.json, apex.json, feed.json) +
          Worker liveness and /api/health structured contract (valid 503 = operational)
  GATE B: Version match (live Worker == config/version.json)
  GATE C: Manifest freshness (generated_at < 4h)
  GATE D: Advisory count >= minimum threshold
  GATE E: JWT configured (auth system operational)
  GATE F: R2 intel binding active
"""

import argparse
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
WORKER_BASE = "https://intel.cyberdudebivash.com"
# Aligned with GATE C's threshold in post-deploy-validation.yml (v184.0 fix).
# R2 is synced by r2-data-sync.yml on its own schedule, independent of the
# Worker deploy, so a fresh deploy can briefly show fewer items than the repo.
# 10 confirms the feed is non-empty and substantive without false-failing on
# that lag. Do not raise above 10 without first confirming r2-data-sync runs
# and populates R2 before this validator does.
MIN_ADVISORY_COUNT = 10
# Canonical customer-visible freshness contract (config/public_freshness_contract.json)
# -- the same authority as the R2 upload guard, /api/health and STAGE 5.9.10.
sys.path.insert(0, str(pathlib.Path(__file__).resolve().parent))
import public_freshness_contract as _freshness  # noqa: E402

import deployment_health_contract as _deploy_health  # noqa: E402

MAX_MANIFEST_AGE_HOURS = _freshness.max_public_manifest_age_hours()

HARD_FAIL_GATES = {"A", "B", "E"}   # these block a deployment green state
SOFT_FAIL_GATES = {"C", "D", "F"}   # these warn but don't block

# GATE A read cap. Must stay comfortably above the largest live endpoint's actual response size
# -- latest.json/feed.json were observed at ~2.06MB on 2026-08-06 (root-caused a run of false
# GATE A failures: the old 1 MiB cap truncated their body, json.loads() then raised on the
# truncated bytes, and that exception was indistinguishable from a real connection failure --
# see probe_json()'s error handling below). 8 MiB gives ~4x headroom over that measurement.
# This platform's feed is append-heavy (incremental ingest), so re-check this constant if GATE A
# starts failing again with `body_too_large` in the error field.
MAX_PROBE_BODY_BYTES = 8 * 1024 * 1024


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def probe_json(url: str, timeout: int = 20, headers: dict | None = None) -> dict:
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SENTINEL-APEX-VALIDATOR/1.0", **(headers or {})})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            # Read one byte past the cap so a body that's actually larger is distinguishable
            # from one that happens to be exactly MAX_PROBE_BODY_BYTES.
            raw = resp.read(MAX_PROBE_BODY_BYTES + 1)
            latency_ms = int((time.monotonic() - t0) * 1000)
            if len(raw) > MAX_PROBE_BODY_BYTES:
                # A genuine HTTP success truncated by our own read cap must not be reported as
                # status 0 -- that's indistinguishable from "never connected" and has previously
                # caused a real, healthy deployment to be flagged as a hard GATE A failure. Report
                # the real status and say exactly what happened.
                return {
                    "ok": False, "status": resp.status, "latency_ms": latency_ms, "body": None,
                    "error": f"body_too_large: exceeds {MAX_PROBE_BODY_BYTES} byte probe cap (see MAX_PROBE_BODY_BYTES)",
                }
            try:
                body = json.loads(raw.decode("utf-8", errors="replace"))
            except json.JSONDecodeError as e:
                # Connected and got a full response, but it wasn't valid JSON -- also a real
                # status, not a connection failure.
                return {"ok": False, "status": resp.status, "latency_ms": latency_ms, "body": None, "error": f"invalid_json: {e}"}
            return {"ok": True, "status": resp.status, "latency_ms": latency_ms, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        # Keep a parseable error body (e.g. /api/health's 503 "degraded"
        # envelope) so callers can read it; ok stays False.
        try:
            err_body = json.loads(e.read(MAX_PROBE_BODY_BYTES).decode("utf-8", errors="replace"))
        except Exception:
            err_body = None
        return {"ok": False, "status": e.code, "latency_ms": 0, "body": err_body, "error": str(e)}
    except Exception as e:
        # Genuine connection-level failure (DNS, refused, reset, timeout, TLS) -- no response was
        # ever received, so status 0 is honest here.
        return {"ok": False, "status": 0, "latency_ms": 0, "body": None, "error": str(e)}


def load_expected_version() -> str:
    try:
        with open(REPO_ROOT / "config" / "version.json", encoding="utf-8") as f:
            return json.load(f).get("version", "")
    except Exception:
        return ""


def _valid_sha(value: str) -> bool:
    return isinstance(value, str) and len(value) == 40 and all(
        ch in "0123456789abcdef" for ch in value
    )


def evaluate_customer_intel_readiness(gates: dict, health: dict, expected_sha: str, live_sha: str) -> dict:
    """Separate evidence-only customer-intel readiness from Worker operability.

    Paid-tier authorization, complete report delivery and R2 parity are outside
    this validator, and must never be represented as certified here.
    """
    source_match = _valid_sha(expected_sha) and _valid_sha(live_sha) and expected_sha == live_sha
    mandatory = ("A", "B", "C", "D", "E", "F")
    gates_pass = all(gates.get(name, {}).get("passed") is True for name in mandatory)
    customer_fresh = health.get("customer_intelligence_healthy") is True
    failures = []
    if not source_match:
        failures.append("DEPLOYED_WORKER_SHA_UNVERIFIED_OR_MISMATCH")
    if not customer_fresh:
        failures.append("CUSTOMER_INTELLIGENCE_NOT_FRESH")
    if not gates_pass:
        failures.append("DEPLOYMENT_READINESS_GATE_FAILURE")
    return {
        "gateway_readiness_passed": bool(source_match and gates_pass and customer_fresh),
        "deployed_source_parity_passed": bool(source_match),
        "customer_intelligence_fresh": bool(customer_fresh),
        "paid_entitlement_certified": False,
        "all_customer_reports_certified": False,
        "worldwide_customer_release_certified": False,
        "failures": failures,
    }


def run_validation(expected_version: str, *, expected_deploy_sha: str | None = None,
                   strict_customer_readiness: bool = False) -> dict:
    if strict_customer_readiness and not _valid_sha(expected_deploy_sha):
        raise ValueError("STRICT_READINESS_REQUIRES_EXACT_40_CHAR_APPROVED_SHA")
    results = {}
    gate_results = {}
    all_passed = True
    hard_failed = False

    print(f"\n{'='*60}")
    print(f"SENTINEL APEX Post-Deploy Validator -- {now_iso()}")
    print(f"Worker: {WORKER_BASE}")
    print(f"Expected version: {expected_version}")
    print(f"{'='*60}\n")

    # GATE A: Endpoint Availability
    print("GATE A: Endpoint Availability")
    # /api/health is evaluated below as a structured contract, not as a
    # 200-only availability probe (it truthfully answers 503 while
    # intelligence is stale -- see scripts/deployment_health_contract.py).
    endpoints = {
        "latest_json":   f"{WORKER_BASE}/api/v1/intel/latest.json",
        "top10_json":    f"{WORKER_BASE}/api/v1/intel/top10.json",
        "apex_json":     f"{WORKER_BASE}/api/v1/intel/apex.json",
        "feed_json":     f"{WORKER_BASE}/api/feed.json",
    }
    ep_results = {}
    endpoint_probes = {}
    all_endpoints_ok = True
    for name, url in endpoints.items():
        r = probe_json(url, timeout=20)
        endpoint_probes[name] = r
        ep_results[name] = {
            "url": url, "ok": r["ok"], "status": r["status"],
            "latency_ms": r["latency_ms"], "error": r["error"]
        }
        status_str = f"HTTP {r['status']} {r['latency_ms']}ms"
        symbol = "OK" if r["ok"] else "FAIL"
        print(f"  [{symbol}] {name}: {status_str}")
        if not r["ok"]:
            all_endpoints_ok = False
    # Worker liveness (/api/health/live) + /api/health structured contract.
    # A valid SENTINEL 503 (degraded/unhealthy) keeps the deployment
    # operational; generic/HTML/malformed 503s, contradictions and exposed
    # secret/config fields fail. Customer freshness is reported, never
    # certified here (STAGE 5.9.10 owns release freshness).
    health_contract = _deploy_health.evaluate_deployment(*_deploy_health.probe(WORKER_BASE))
    hc = health_contract["health"]
    ep_results["health"] = {
        "url": f"{WORKER_BASE}/api/health", "ok": health_contract["deployment_operational"],
        "status": hc["http_status"], "latency_ms": None, "error": "; ".join(health_contract["failures"]) or None,
        "contract_state": health_contract["customer_intelligence_state"],
        "customer_intelligence_healthy": health_contract["customer_intelligence_healthy"],
    }
    symbol = "OK" if health_contract["deployment_operational"] else "FAIL"
    print(f"  [{symbol}] health: HTTP {hc['http_status']} contract={health_contract['customer_intelligence_state']} "
          f"live={'yes' if health_contract['liveness']['alive'] else 'NO'}")
    for f in health_contract["failures"]:
        print(f"         {f}")
    if not health_contract["deployment_operational"]:
        all_endpoints_ok = False
    gate_results["A"] = {"passed": all_endpoints_ok, "detail": ep_results,
                         "customer_intelligence_state": health_contract["customer_intelligence_state"]}
    if not all_endpoints_ok:
        hard_failed = True
    print(f"  GATE A: {'PASS' if all_endpoints_ok else 'FAIL'}\n")

    # GATE B: Version Match
    print("GATE B: Version Match")
    # Liveness endpoint: Worker version with no data dependency (/api/health
    # answers 503 while intelligence is stale; that must not mask a version check).
    health_r = probe_json(f"{WORKER_BASE}/api/health/live", timeout=15)
    live_version = ""
    if health_r["ok"] and health_r["body"]:
        live_version = health_r["body"].get("version", "") if isinstance(health_r["body"], dict) else ""
    live_sha = health_r["body"].get("deploy_commit_sha", "") if (
        health_r["ok"] and isinstance(health_r["body"], dict)) else ""
    version_ok = bool(live_version and live_version == expected_version)
    print(f"  Expected: {expected_version}")
    print(f"  Live:     {live_version if live_version else '(not found)'}")
    print(f"  GATE B: {'PASS' if version_ok else 'FAIL'}")
    gate_results["B"] = {"passed": version_ok, "expected": expected_version, "live": live_version}
    if not version_ok:
        hard_failed = True
    print()

    # GATE C: Manifest Freshness
    print("GATE C: Manifest Freshness")
    # Evaluate freshness and count from the exact response already checked by Gate A.
    latest_r = endpoint_probes["latest_json"]
    latest_body = latest_r["body"] if isinstance(latest_r["body"], dict) else {}
    manifest_fresh = False
    manifest_age_h = None
    if latest_r["ok"] and latest_body:
        fresh = _freshness.classify_manifest_freshness(latest_body.get("generated_at"))
        if fresh["age_seconds"] is not None:
            manifest_age_h = round(fresh["age_seconds"] / 3600, 1)
        manifest_fresh = fresh["state"] == _freshness.FRESH
    print(f"  Age: {manifest_age_h}h (threshold: {MAX_MANIFEST_AGE_HOURS}h)")
    print(f"  GATE C: {'PASS' if manifest_fresh else 'WARN (soft)'}")
    gate_results["C"] = {"passed": manifest_fresh, "age_hours": manifest_age_h, "threshold_hours": MAX_MANIFEST_AGE_HOURS}
    print()

    # GATE D: Advisory Count
    print("GATE D: Advisory Count")
    raw_count = latest_body.get("count") if latest_r["ok"] else None
    # JSON booleans, strings, fractional/negative numbers are not measured counts.
    count_valid = type(raw_count) is int and raw_count >= 0
    advisory_count = raw_count if count_valid else None
    count_ok = count_valid and advisory_count >= MIN_ADVISORY_COUNT
    print(f"  Count: {advisory_count if count_valid else 'measurement unavailable'} (minimum: {MIN_ADVISORY_COUNT})")
    print(f"  GATE D: {'PASS' if count_ok else 'WARN (soft)'}")
    gate_results["D"] = {"passed": count_ok, "minimum": MIN_ADVISORY_COUNT, "measurement_valid": count_valid,
                         "measurement_state": "MEASURED" if count_valid else "INVALID_OR_UNAVAILABLE",
                         **({"count": advisory_count} if count_valid else {})}
    print()

    # GATE E: JWT Configured
    print("GATE E: JWT Configured")
    # jwt_configured / r2_intel are operator-only fields of /api/health (not
    # returned to anonymous callers). Authenticate with the Worker's
    # ADMIN_SECRET; fail closed when it is not provided.
    admin_secret = os.environ.get("ADMIN_SECRET", "").strip()
    op_body = {}
    if admin_secret:
        op_r = probe_json(f"{WORKER_BASE}/api/health", timeout=15, headers={"X-Admin-Key": admin_secret})
        op_body = op_r["body"] if isinstance(op_r["body"], dict) else {}
    else:
        print("  ADMIN_SECRET not set -- cannot read the operator health view")
    op_checks = op_body.get("checks", {})
    op_checks = op_checks if isinstance(op_checks, dict) else {}
    jwt_ok = op_checks.get("jwt_configured", False) is True
    print(f"  JWT configured: {jwt_ok}")
    if not jwt_ok:
        print(f"  FIX: openssl rand -hex 32 | npx wrangler secret put CDB_JWT_SECRET"
              f"{'' if admin_secret else '  (or provide ADMIN_SECRET to this validator)'}")
        hard_failed = True
    print(f"  GATE E: {'PASS' if jwt_ok else 'FAIL'}")
    gate_results["E"] = {"passed": jwt_ok}
    print()

    # GATE F: R2 Intel Binding
    print("GATE F: R2 Intel Binding")
    r2_ok = False
    r2_status = "unknown"
    if op_body:
        r2_status = op_checks.get("r2_intel", "unknown")
        r2_ok = r2_status == "ok"
    print(f"  R2 intel status: {r2_status}")
    print(f"  GATE F: {'PASS' if r2_ok else 'WARN (soft)'}")
    gate_results["F"] = {"passed": r2_ok, "r2_status": r2_status}
    print()

    # Release-source and data readiness is separate from deploy operability.
    # Strict mode consumes the SAME liveness response; no new network calls.
    readiness = evaluate_customer_intel_readiness(
        gate_results, health_contract, expected_deploy_sha or "", live_sha,
    )
    if strict_customer_readiness:
        gate_results["G"] = {
            "passed": readiness["deployed_source_parity_passed"],
            "expected_deploy_sha": expected_deploy_sha,
            "live_deploy_sha": live_sha,
        }
        if not readiness["gateway_readiness_passed"]:
            hard_failed = True
    # Final determination
    hard_gates_passed = all(gate_results.get(g, {}).get("passed", False) for g in HARD_FAIL_GATES)
    soft_gates_passed = all(gate_results.get(g, {}).get("passed", False) for g in SOFT_FAIL_GATES)
    all_gates_passed = hard_gates_passed and soft_gates_passed

    if strict_customer_readiness:
        # A live Worker with old code or stale intelligence must never get a
        # customer readiness exit-0 verdict, even if routine operations are up.
        overall = "GATEWAY_READINESS_PASSED_NOT_WORLDWIDE_RELEASE" if readiness["gateway_readiness_passed"] else "GATEWAY_READINESS_BLOCKED"
        exit_code = 0 if readiness["gateway_readiness_passed"] else 1
    elif hard_gates_passed and soft_gates_passed:
        overall = "ALL_PASSED"
        exit_code = 0
    elif hard_gates_passed:
        overall = "SOFT_WARNINGS"
        exit_code = 0
    else:
        overall = "HARD_FAILURE"
        exit_code = 1

    print(f"{'='*60}")
    print(f"POST-DEPLOY VALIDATION: {overall}")
    for gate_id, result in gate_results.items():
        gate_type = "HARD" if gate_id in HARD_FAIL_GATES else "SOFT"
        symbol = "PASS" if result["passed"] else "FAIL"
        print(f"  Gate {gate_id} [{gate_type}]: {symbol}")
    print(f"{'='*60}")

    # Write validation result to health dir
    validation_result = {
        "schema_version": "1.0",
        "validated_at": now_iso(),
        "expected_version": expected_version,
        "overall": overall,
        "exit_code": exit_code,
        "hard_gates_passed": hard_gates_passed,
        "soft_gates_passed": soft_gates_passed,
        "gates": gate_results,
        "strict_customer_readiness": strict_customer_readiness,
        "expected_deploy_sha": expected_deploy_sha,
        "live_deploy_sha": live_sha,
        "gateway_readiness": readiness,
        "worldwide_customer_release_certified": False,
    }
    health_dir = REPO_ROOT / "data" / "health"
    health_dir.mkdir(parents=True, exist_ok=True)
    (health_dir / "last_deploy_validation.json").write_text(
        json.dumps(validation_result, indent=2), encoding="utf-8"
    )

    return validation_result, exit_code


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX post-deploy operations and strict gateway readiness")
    parser.add_argument("--strict-customer-readiness", action="store_true",
                        help="Require all readiness checks, current feed and exact deployed approved SHA. "
                             "This does NOT certify paid entitlements or worldwide release.")
    parser.add_argument("--expected-deploy-sha", default=os.environ.get("EXPECTED_DEPLOY_SHA", ""),
                        help="Exact owner-approved 40-character source commit for strict readiness")
    args = parser.parse_args()
    expected_version = os.environ.get("PLATFORM_VERSION", "") or load_expected_version()
    if not expected_version:
        print("FATAL: Cannot determine expected version (set PLATFORM_VERSION env or config/version.json)")
        sys.exit(2)
    if args.strict_customer_readiness and not _valid_sha(args.expected_deploy_sha):
        print("FATAL: strict readiness requires exact approved 40-character deploy SHA")
        sys.exit(2)

    _, exit_code = run_validation(expected_version,
                                  expected_deploy_sha=args.expected_deploy_sha or None,
                                  strict_customer_readiness=args.strict_customer_readiness)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
