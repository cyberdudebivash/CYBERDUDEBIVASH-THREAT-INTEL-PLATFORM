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
  GATE A: API endpoint availability (latest.json, top10.json, apex.json, feed.json, health)
  GATE B: Version match (live Worker == config/version.json)
  GATE C: Manifest freshness (generated_at < 4h)
  GATE D: Advisory count >= minimum threshold
  GATE E: JWT configured (auth system operational)
  GATE F: R2 intel binding active
"""

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
MIN_ADVISORY_COUNT = 50
MAX_MANIFEST_AGE_HOURS = 6

HARD_FAIL_GATES = {"A", "B", "E"}   # these block a deployment green state
SOFT_FAIL_GATES = {"C", "D", "F"}   # these warn but don't block


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def probe_json(url: str, timeout: int = 20) -> dict:
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SENTINEL-APEX-VALIDATOR/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.monotonic() - t0) * 1000)
            body = json.loads(resp.read(1048576).decode("utf-8", errors="replace"))
            return {"ok": True, "status": resp.status, "latency_ms": latency_ms, "body": body, "error": None}
    except urllib.error.HTTPError as e:
        return {"ok": False, "status": e.code, "latency_ms": 0, "body": None, "error": str(e)}
    except Exception as e:
        return {"ok": False, "status": 0, "latency_ms": 0, "body": None, "error": str(e)}


def load_expected_version() -> str:
    try:
        with open(REPO_ROOT / "config" / "version.json", encoding="utf-8") as f:
            return json.load(f).get("version", "")
    except Exception:
        return ""


def run_validation(expected_version: str) -> dict:
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
    endpoints = {
        "health":        f"{WORKER_BASE}/api/health",
        "latest_json":   f"{WORKER_BASE}/api/v1/intel/latest.json",
        "top10_json":    f"{WORKER_BASE}/api/v1/intel/top10.json",
        "apex_json":     f"{WORKER_BASE}/api/v1/intel/apex.json",
        "feed_json":     f"{WORKER_BASE}/api/feed.json",
    }
    ep_results = {}
    all_endpoints_ok = True
    for name, url in endpoints.items():
        r = probe_json(url, timeout=20)
        ep_results[name] = {
            "url": url, "ok": r["ok"], "status": r["status"],
            "latency_ms": r["latency_ms"], "error": r["error"]
        }
        status_str = f"HTTP {r['status']} {r['latency_ms']}ms"
        symbol = "OK" if r["ok"] else "FAIL"
        print(f"  [{symbol}] {name}: {status_str}")
        if not r["ok"]:
            all_endpoints_ok = False
    gate_results["A"] = {"passed": all_endpoints_ok, "detail": ep_results}
    if not all_endpoints_ok:
        hard_failed = True
    print(f"  GATE A: {'PASS' if all_endpoints_ok else 'FAIL'}\n")

    # GATE B: Version Match
    print("GATE B: Version Match")
    health_r = probe_json(f"{WORKER_BASE}/api/health", timeout=15)
    live_version = ""
    if health_r["ok"] and health_r["body"]:
        live_version = health_r["body"].get("version", "")
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
    latest_r = probe_json(f"{WORKER_BASE}/api/v1/intel/latest.json", timeout=20)
    manifest_fresh = False
    manifest_age_h = None
    if latest_r["ok"] and latest_r["body"]:
        gen_at = latest_r["body"].get("generated_at", "")
        if gen_at:
            try:
                ts = datetime.fromisoformat(gen_at.replace("Z", "+00:00"))
                age_s = (datetime.now(timezone.utc) - ts).total_seconds()
                manifest_age_h = round(age_s / 3600, 1)
                manifest_fresh = age_s < (MAX_MANIFEST_AGE_HOURS * 3600)
            except Exception:
                pass
    print(f"  Age: {manifest_age_h}h (threshold: {MAX_MANIFEST_AGE_HOURS}h)")
    print(f"  GATE C: {'PASS' if manifest_fresh else 'WARN (soft)'}")
    gate_results["C"] = {"passed": manifest_fresh, "age_hours": manifest_age_h, "threshold_hours": MAX_MANIFEST_AGE_HOURS}
    print()

    # GATE D: Advisory Count
    print("GATE D: Advisory Count")
    advisory_count = 0
    if latest_r["ok"] and latest_r["body"]:
        advisory_count = latest_r["body"].get("count", 0)
    count_ok = advisory_count >= MIN_ADVISORY_COUNT
    print(f"  Count: {advisory_count} (minimum: {MIN_ADVISORY_COUNT})")
    print(f"  GATE D: {'PASS' if count_ok else 'WARN (soft)'}")
    gate_results["D"] = {"passed": count_ok, "count": advisory_count, "minimum": MIN_ADVISORY_COUNT}
    print()

    # GATE E: JWT Configured
    print("GATE E: JWT Configured")
    jwt_ok = False
    if health_r["ok"] and health_r["body"]:
        jwt_ok = health_r["body"].get("checks", {}).get("jwt_configured", False) is True
    print(f"  JWT configured: {jwt_ok}")
    if not jwt_ok:
        print(f"  FIX: openssl rand -hex 32 | npx wrangler secret put CDB_JWT_SECRET")
        hard_failed = True
    print(f"  GATE E: {'PASS' if jwt_ok else 'FAIL'}")
    gate_results["E"] = {"passed": jwt_ok}
    print()

    # GATE F: R2 Intel Binding
    print("GATE F: R2 Intel Binding")
    r2_ok = False
    r2_status = "unknown"
    if health_r["ok"] and health_r["body"]:
        r2_status = health_r["body"].get("checks", {}).get("r2_intel", "unknown")
        r2_ok = r2_status == "ok"
    print(f"  R2 intel status: {r2_status}")
    print(f"  GATE F: {'PASS' if r2_ok else 'WARN (soft)'}")
    gate_results["F"] = {"passed": r2_ok, "r2_status": r2_status}
    print()

    # Final determination
    hard_gates_passed = all(gate_results.get(g, {}).get("passed", False) for g in HARD_FAIL_GATES)
    soft_gates_passed = all(gate_results.get(g, {}).get("passed", False) for g in SOFT_FAIL_GATES)
    all_gates_passed = hard_gates_passed and soft_gates_passed

    if hard_gates_passed and soft_gates_passed:
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
    }
    health_dir = REPO_ROOT / "data" / "health"
    health_dir.mkdir(parents=True, exist_ok=True)
    (health_dir / "last_deploy_validation.json").write_text(
        json.dumps(validation_result, indent=2), encoding="utf-8"
    )

    return validation_result, exit_code


def main():
    expected_version = os.environ.get("PLATFORM_VERSION", "") or load_expected_version()
    if not expected_version:
        print("FATAL: Cannot determine expected version (set PLATFORM_VERSION env or config/version.json)")
        sys.exit(2)

    result, exit_code = run_validation(expected_version)
    sys.exit(exit_code)


if __name__ == "__main__":
    main()
