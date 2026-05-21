#!/usr/bin/env python3
# =============================================================================
# CYBERDUDEBIVASH(R) SENTINEL APEX — Observability Engine v1
# scripts/sentinel_observability_engine.py
#
# PURPOSE:
#   Collects runtime telemetry, API health scores, manifest drift metrics,
#   SLA trend data, and deployment analytics. Writes structured JSON outputs
#   to data/telemetry/ for consumption by dashboard and CI/CD gates.
#
# OUTPUTS:
#   data/telemetry/runtime_telemetry.json      — live platform health snapshot
#   data/telemetry/deployment_analytics.json   — deployment history & stability
#   data/telemetry/sla_trends.json             — SLA performance over time
#   data/telemetry/sync_report.json            — version sync state (also written by global_version_sync.py)
#
# USAGE:
#   python3 scripts/sentinel_observability_engine.py [--mode snapshot|full|ci]
#
# EXIT CODES:
#   0 — All health checks passed
#   1 — Degraded or critical health detected
#   2 — Fatal engine error
#
# =============================================================================

import argparse
import json
import os
import re
import sys
import datetime
import hashlib
import time
import urllib.request
import urllib.error

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SSOT_PATH = os.path.join(REPO_ROOT, "config", "platform_version.json")
TELEMETRY_DIR = os.path.join(REPO_ROOT, "data", "telemetry")
DIST_DIR = os.path.join(REPO_ROOT, "dist")
MANIFEST_PATH = os.path.join(DIST_DIR, "deployment_manifest.json")

RESET  = "\033[0m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
RED    = "\033[91m"
CYAN   = "\033[96m"
BOLD   = "\033[1m"
DIM    = "\033[2m"

def log_ok(msg):    print(f"{GREEN}[OBS-OK  ]{RESET} {msg}")
def log_warn(msg):  print(f"{YELLOW}[OBS-WARN]{RESET} {msg}")
def log_fail(msg):  print(f"{RED}[OBS-FAIL]{RESET} {msg}")
def log_info(msg):  print(f"{CYAN}[OBS-INFO]{RESET} {msg}")
def log_dim(msg):   print(f"{DIM}[OBS-DBG ]{RESET} {msg}")

NOW_UTC = datetime.datetime.utcnow()
NOW_ISO = NOW_UTC.strftime("%Y-%m-%dT%H:%M:%SZ")
NOW_DATE = NOW_UTC.strftime("%Y-%m-%d")


# =============================================================================
# LOAD SSOT
# =============================================================================

def load_ssot() -> dict:
    if not os.path.isfile(SSOT_PATH):
        log_fail(f"SSOT missing: {SSOT_PATH}")
        sys.exit(2)
    with open(SSOT_PATH, "r", encoding="utf-8") as fh:
        return json.load(fh)


# =============================================================================
# HEALTH PROBE — Live API endpoints
# =============================================================================

HEALTH_ENDPOINTS = [
    {
        "name": "Platform Root",
        "url": "https://intel.cyberdudebivash.com",
        "expected_status": [200],
        "sla_ms": 3000,
        "tier": "critical"
    },
    {
        "name": "API Health",
        "url": "https://intel.cyberdudebivash.com/api/health",
        "expected_status": [200],
        "sla_ms": 2000,
        "tier": "critical"
    },
    {
        "name": "Feed JSON",
        "url": "https://intel.cyberdudebivash.com/api/feed.json",
        "expected_status": [200],
        "sla_ms": 3000,
        "tier": "high"
    },
    {
        "name": "Intel Latest",
        "url": "https://intel.cyberdudebivash.com/api/v1/intel/latest.json",
        "expected_status": [200],
        "sla_ms": 3000,
        "tier": "high"
    },
    {
        "name": "Version API",
        "url": "https://intel.cyberdudebivash.com/version.json",
        "expected_status": [200],
        "sla_ms": 2000,
        "tier": "high"
    },
    {
        "name": "Service Worker",
        "url": "https://intel.cyberdudebivash.com/service-worker.js",
        "expected_status": [200],
        "sla_ms": 2000,
        "tier": "medium"
    },
    {
        "name": "Payment Gateway",
        "url": "https://intel.cyberdudebivash.com/PAYMENT-GATEWAY.html",
        "expected_status": [200],
        "sla_ms": 3000,
        "tier": "critical"
    },
    {
        "name": "Blog",
        "url": "https://blog.cyberdudebivash.in",
        "expected_status": [200],
        "sla_ms": 5000,
        "tier": "medium"
    },
    {
        "name": "Tools Hub",
        "url": "https://tools.cyberdudebivash.com",
        "expected_status": [200],
        "sla_ms": 5000,
        "tier": "medium"
    },
    {
        "name": "Security Hub",
        "url": "https://cyberdudebivash.in",
        "expected_status": [200],
        "sla_ms": 5000,
        "tier": "medium"
    },
]


def probe_endpoint(ep: dict, timeout: int = 8) -> dict:
    url = ep["url"]
    name = ep["name"]
    sla_ms = ep.get("sla_ms", 3000)
    expected = ep.get("expected_status", [200])

    result = {
        "name": name,
        "url": url,
        "tier": ep.get("tier", "medium"),
        "status_code": None,
        "response_ms": None,
        "sla_ms": sla_ms,
        "within_sla": False,
        "healthy": False,
        "error": None
    }

    try:
        req = urllib.request.Request(
            url,
            headers={"User-Agent": "SentinelApex-ObservabilityEngine/1.0"}
        )
        t0 = time.time()
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            elapsed_ms = int((time.time() - t0) * 1000)
            result["status_code"] = resp.status
            result["response_ms"] = elapsed_ms
            result["within_sla"] = elapsed_ms <= sla_ms
            result["healthy"] = resp.status in expected
    except urllib.error.HTTPError as exc:
        result["status_code"] = exc.code
        result["healthy"] = exc.code in expected
        result["error"] = f"HTTP {exc.code}: {exc.reason}"
    except urllib.error.URLError as exc:
        result["error"] = f"URLError: {exc.reason}"
    except Exception as exc:
        result["error"] = f"Exception: {type(exc).__name__}: {exc}"

    return result


def run_health_probes(mode: str) -> list:
    """Run endpoint health probes. In CI mode, only probe critical tier."""
    results = []
    targets = HEALTH_ENDPOINTS if mode != "ci" else [
        ep for ep in HEALTH_ENDPOINTS if ep["tier"] == "critical"
    ]
    log_info(f"Probing {len(targets)} endpoints (mode={mode})...")
    for ep in targets:
        r = probe_endpoint(ep)
        if r["healthy"]:
            sla_note = f"{r['response_ms']}ms" if r["response_ms"] else "N/A"
            sla_flag = "" if r["within_sla"] else f" {YELLOW}[SLA BREACH: {r['response_ms']}ms > {r['sla_ms']}ms]{RESET}"
            log_ok(f"{ep['name']} → HTTP {r['status_code']} ({sla_note}){sla_flag}")
        else:
            err_msg = r.get("error") or f"HTTP {r['status_code']}"
            log_fail(f"{ep['name']} → {err_msg}")
        results.append(r)
    return results


# =============================================================================
# HEALTH SCORE CALCULATOR
# =============================================================================

def calculate_health_score(probe_results: list) -> dict:
    total = len(probe_results)
    if total == 0:
        return {"score": 0, "grade": "UNKNOWN", "status": "NO_DATA"}

    healthy = sum(1 for r in probe_results if r["healthy"])
    critical_total = sum(1 for r in probe_results if r["tier"] == "critical")
    critical_healthy = sum(1 for r in probe_results if r["tier"] == "critical" and r["healthy"])
    sla_breaches = sum(1 for r in probe_results if r["healthy"] and not r["within_sla"])

    # Weighted score: critical endpoints worth 3x, high 2x, medium 1x
    tier_weights = {"critical": 3, "high": 2, "medium": 1}
    weighted_max = sum(tier_weights.get(r["tier"], 1) for r in probe_results)
    weighted_score = sum(
        tier_weights.get(r["tier"], 1)
        for r in probe_results if r["healthy"]
    )
    base_score = int((weighted_score / weighted_max) * 100) if weighted_max > 0 else 0

    # SLA penalty: -2 per SLA breach
    sla_penalty = sla_breaches * 2
    final_score = max(0, base_score - sla_penalty)

    # Grade assignment
    if final_score >= 95 and critical_healthy == critical_total:
        grade, status = "A+", "OPERATIONAL"
    elif final_score >= 85 and critical_healthy == critical_total:
        grade, status = "A", "OPERATIONAL"
    elif final_score >= 70:
        grade, status = "B", "DEGRADED"
    elif final_score >= 50:
        grade, status = "C", "DEGRADED"
    elif critical_healthy < critical_total:
        grade, status = "F", "CRITICAL"
    else:
        grade, status = "D", "DEGRADED"

    return {
        "score": final_score,
        "grade": grade,
        "status": status,
        "total_endpoints": total,
        "healthy_endpoints": healthy,
        "critical_total": critical_total,
        "critical_healthy": critical_healthy,
        "sla_breaches": sla_breaches,
        "weighted_score_raw": base_score,
        "sla_penalty": sla_penalty
    }


# =============================================================================
# MANIFEST DRIFT DETECTOR
# =============================================================================

def detect_manifest_drift(ssot: dict) -> dict:
    result = {
        "manifest_found": False,
        "platform_version_match": False,
        "pipeline_version_match": False,
        "drift_detected": False,
        "manifest_platform_version": None,
        "manifest_pipeline_version": None,
        "expected_platform_version": ssot["platform"]["version"],
        "expected_pipeline_version": ssot["ci"]["pipeline_version"],
        "total_files": None,
        "report_count": None,
        "run_id": None
    }

    if not os.path.isfile(MANIFEST_PATH):
        log_warn("deployment_manifest.json not found — skipping manifest drift check")
        result["error"] = "manifest_not_found"
        return result

    try:
        with open(MANIFEST_PATH, "r", encoding="utf-8") as fh:
            manifest = json.load(fh)
    except Exception as exc:
        result["error"] = f"manifest_parse_error: {exc}"
        return result

    result["manifest_found"] = True
    result["total_files"] = manifest.get("total_files")
    result["report_count"] = manifest.get("report_count")
    result["run_id"] = manifest.get("pipeline_run_id")

    # Check platform version
    mani_ver = manifest.get("platform_version") or manifest.get("version")
    result["manifest_platform_version"] = mani_ver
    result["platform_version_match"] = mani_ver == ssot["platform"]["version"]

    # Check pipeline version
    pipe_ver = manifest.get("pipeline_version")
    result["manifest_pipeline_version"] = pipe_ver
    result["pipeline_version_match"] = pipe_ver == ssot["ci"]["pipeline_version"]

    drift = not (result["platform_version_match"] and result["pipeline_version_match"])
    result["drift_detected"] = drift

    if drift:
        log_warn(f"Manifest drift: platform={mani_ver} (expected {ssot['platform']['version']}), pipeline={pipe_ver} (expected {ssot['ci']['pipeline_version']})")
    else:
        log_ok(f"Manifest clean: platform={mani_ver}, pipeline={pipe_ver}, files={result['total_files']}, reports={result['report_count']}")

    return result


# =============================================================================
# REPO INTEGRITY CHECKS
# =============================================================================

def check_repo_integrity(ssot: dict) -> dict:
    checks = {}

    # Critical files presence
    critical_files = [
        "index.html",
        "service-worker.js",
        "version.json",
        "config/platform_version.json",
        "config/version.json",
        "PAYMENT-GATEWAY.html",
        "api/ai/health.json",
        "scripts/global_version_sync.py",
        "scripts/sentinel_observability_engine.py",
        "scripts/build_dist_artifact.py",
        "scripts/dist_artifact_verifier.py",
        "scripts/dashboard_frontend_guard.py",
    ]

    missing = []
    present = []
    for f in critical_files:
        path = os.path.join(REPO_ROOT, f)
        if os.path.isfile(path):
            present.append(f)
        else:
            missing.append(f)
            log_warn(f"Critical file missing: {f}")

    checks["critical_files_present"] = len(present)
    checks["critical_files_missing"] = missing
    checks["critical_files_ok"] = len(missing) == 0

    # VERSION file match
    version_file = os.path.join(REPO_ROOT, "VERSION")
    if os.path.isfile(version_file):
        with open(version_file, "r", encoding="utf-8") as fh:
            ver_content = fh.read().strip()
        checks["version_file_match"] = ver_content == ssot["platform"]["version"]
        checks["version_file_content"] = ver_content
    else:
        checks["version_file_match"] = False
        checks["version_file_content"] = None

    # index.html PLATFORM_VERSION
    index_path = os.path.join(REPO_ROOT, "index.html")
    if os.path.isfile(index_path):
        with open(index_path, "r", encoding="utf-8", errors="replace") as fh:
            idx_content = fh.read()
        m = re.search(r"(?:const|let|var)\s+PLATFORM_VERSION\s*=\s*['\"]([^'\"]+)['\"]", idx_content)
        if m:
            found_pv = m.group(1)
            checks["index_platform_version"] = found_pv
            checks["index_platform_version_correct"] = found_pv == ssot["platform"]["version"]
            if not checks["index_platform_version_correct"]:
                log_warn(f"index.html PLATFORM_VERSION={found_pv} (expected {ssot['platform']['version']})")
            else:
                log_ok(f"index.html PLATFORM_VERSION={found_pv}")
        else:
            checks["index_platform_version"] = None
            checks["index_platform_version_correct"] = False

    # Telemetry directory
    checks["telemetry_dir_exists"] = os.path.isdir(TELEMETRY_DIR)

    if missing:
        log_fail(f"Repo integrity: {len(missing)} critical files missing: {missing}")
    else:
        log_ok(f"Repo integrity: all {len(present)} critical files present")

    return checks


# =============================================================================
# DEPLOYMENT ANALYTICS
# =============================================================================

def collect_deployment_analytics(ssot: dict, probe_results: list, health_score: dict, manifest_drift: dict) -> dict:
    platform = ssot.get("platform", {})
    ci = ssot.get("ci", {})

    # Load existing analytics for historical append
    analytics_path = os.path.join(TELEMETRY_DIR, "deployment_analytics.json")
    existing = {}
    if os.path.isfile(analytics_path):
        try:
            with open(analytics_path, "r", encoding="utf-8") as fh:
                existing = json.load(fh)
        except Exception:
            existing = {}

    history = existing.get("history", [])

    # Append new snapshot (keep last 30 runs)
    snapshot = {
        "timestamp": NOW_ISO,
        "platform_version": platform.get("version"),
        "pipeline_version": ci.get("pipeline_version"),
        "health_score": health_score.get("score"),
        "health_grade": health_score.get("grade"),
        "health_status": health_score.get("status"),
        "critical_healthy": health_score.get("critical_healthy"),
        "critical_total": health_score.get("critical_total"),
        "sla_breaches": health_score.get("sla_breaches"),
        "manifest_drift": manifest_drift.get("drift_detected"),
        "total_files_in_dist": manifest_drift.get("total_files"),
        "report_count": manifest_drift.get("report_count")
    }
    history.append(snapshot)
    history = history[-30:]  # Keep last 30

    # Stability score: % of last N runs with OPERATIONAL status
    recent = history[-10:]
    stable_runs = sum(1 for h in recent if h.get("health_status") == "OPERATIONAL")
    stability_pct = int((stable_runs / len(recent)) * 100) if recent else 0

    analytics = {
        "_schema": "sentinel-apex-deployment-analytics-v1",
        "_generated": NOW_ISO,
        "_generated_by": "sentinel_observability_engine.py",
        "platform_version": platform.get("version"),
        "pipeline_version": ci.get("pipeline_version"),
        "current_health_score": health_score.get("score"),
        "current_health_grade": health_score.get("grade"),
        "current_health_status": health_score.get("status"),
        "stability_score_10_runs": stability_pct,
        "deployment_stable": stability_pct >= 80,
        "history": history
    }

    os.makedirs(TELEMETRY_DIR, exist_ok=True)
    with open(analytics_path, "w", encoding="utf-8") as fh:
        json.dump(analytics, fh, indent=2)
    log_ok(f"Deployment analytics written → data/telemetry/deployment_analytics.json (stability={stability_pct}%)")
    return analytics


# =============================================================================
# SLA TRENDS
# =============================================================================

def collect_sla_trends(probe_results: list) -> dict:
    sla_path = os.path.join(TELEMETRY_DIR, "sla_trends.json")
    existing = {}
    if os.path.isfile(sla_path):
        try:
            with open(sla_path, "r", encoding="utf-8") as fh:
                existing = json.load(fh)
        except Exception:
            existing = {}

    history = existing.get("history", [])

    # Per-endpoint response times for this run
    endpoint_snapshot = {}
    for r in probe_results:
        endpoint_snapshot[r["name"]] = {
            "response_ms": r.get("response_ms"),
            "healthy": r.get("healthy"),
            "within_sla": r.get("within_sla"),
            "sla_ms": r.get("sla_ms"),
            "status_code": r.get("status_code")
        }

    run_entry = {
        "timestamp": NOW_ISO,
        "endpoints": endpoint_snapshot,
        "total_probed": len(probe_results),
        "sla_breaches": sum(1 for r in probe_results if r["healthy"] and not r["within_sla"]),
        "failures": sum(1 for r in probe_results if not r["healthy"])
    }

    history.append(run_entry)
    history = history[-30:]

    # Compute per-endpoint avg response time from recent history
    endpoint_stats = {}
    for ep_name in endpoint_snapshot:
        times = [
            h["endpoints"][ep_name]["response_ms"]
            for h in history
            if ep_name in h.get("endpoints", {})
            and h["endpoints"][ep_name].get("response_ms") is not None
        ]
        if times:
            endpoint_stats[ep_name] = {
                "avg_ms": int(sum(times) / len(times)),
                "min_ms": min(times),
                "max_ms": max(times),
                "samples": len(times)
            }

    trends = {
        "_schema": "sentinel-apex-sla-trends-v1",
        "_generated": NOW_ISO,
        "_generated_by": "sentinel_observability_engine.py",
        "endpoint_avg_stats": endpoint_stats,
        "history": history
    }

    with open(sla_path, "w", encoding="utf-8") as fh:
        json.dump(trends, fh, indent=2)
    log_ok(f"SLA trends written → data/telemetry/sla_trends.json")
    return trends


# =============================================================================
# RUNTIME TELEMETRY (master snapshot)
# =============================================================================

def write_runtime_telemetry(
    ssot: dict,
    probe_results: list,
    health_score: dict,
    manifest_drift: dict,
    repo_integrity: dict,
    analytics: dict
) -> dict:
    platform = ssot.get("platform", {})
    ci = ssot.get("ci", {})
    tiers = ssot.get("tiers", {})
    payment = ssot.get("payment", {})

    telemetry = {
        "_schema": "sentinel-apex-runtime-telemetry-v1",
        "_generated": NOW_ISO,
        "_generated_by": "sentinel_observability_engine.py",

        "platform": {
            "version": platform.get("version"),
            "label": platform.get("label"),
            "full": platform.get("full"),
            "codename": platform.get("codename"),
            "release_date": platform.get("release_date"),
            "display": platform.get("display")
        },

        "pipeline": {
            "version": ci.get("pipeline_version"),
            "label": ci.get("pipeline_label")
        },

        "health": health_score,

        "endpoints": [
            {
                "name": r["name"],
                "url": r["url"],
                "tier": r["tier"],
                "status_code": r["status_code"],
                "response_ms": r["response_ms"],
                "sla_ms": r["sla_ms"],
                "within_sla": r["within_sla"],
                "healthy": r["healthy"],
                "error": r.get("error")
            }
            for r in probe_results
        ],

        "manifest": manifest_drift,

        "repo_integrity": repo_integrity,

        "monetization": {
            "payment_methods": payment.get("methods", []),
            "upi_id": payment.get("upi_id"),
            "tiers": {
                k: {
                    "label": v.get("label"),
                    "price_usd": v.get("price_usd"),
                    "price_inr": v.get("price_inr"),
                    "api_calls_day": v.get("api_calls_day")
                }
                for k, v in tiers.items()
            }
        },

        "stability": {
            "score_10_runs": analytics.get("stability_score_10_runs"),
            "deployment_stable": analytics.get("deployment_stable")
        }
    }

    telem_path = os.path.join(TELEMETRY_DIR, "runtime_telemetry.json")
    os.makedirs(TELEMETRY_DIR, exist_ok=True)
    with open(telem_path, "w", encoding="utf-8") as fh:
        json.dump(telemetry, fh, indent=2)
    log_ok(f"Runtime telemetry written → data/telemetry/runtime_telemetry.json")
    return telemetry


# =============================================================================
# MAIN
# =============================================================================

def main() -> int:
    parser = argparse.ArgumentParser(
        description="SENTINEL APEX Observability Engine v1 — runtime telemetry and health scoring"
    )
    parser.add_argument(
        "--mode",
        choices=["snapshot", "full", "ci"],
        default="snapshot",
        help="snapshot=fast local checks only | full=include live endpoint probes | ci=critical endpoints + hard fail on degraded"
    )
    parser.add_argument(
        "--no-probes",
        action="store_true",
        help="Skip live endpoint probing (local checks only)"
    )
    args = parser.parse_args()

    print()
    print(f"{BOLD}{CYAN}============================================================{RESET}")
    print(f"{BOLD}{CYAN}  SENTINEL APEX — Observability Engine v1{RESET}")
    print(f"{BOLD}{CYAN}  Generated: {NOW_ISO}{RESET}")
    print(f"{BOLD}{CYAN}  Mode: {args.mode.upper()}{RESET}")
    print(f"{BOLD}{CYAN}============================================================{RESET}")
    print()

    ssot = load_ssot()
    log_info(f"Platform: {ssot['platform']['full']}  |  Pipeline: {ssot['ci']['pipeline_version']}")
    print()

    # --- Repo integrity ---
    log_info("--- Repo Integrity Checks ---")
    repo_integrity = check_repo_integrity(ssot)
    print()

    # --- Manifest drift ---
    log_info("--- Manifest Drift Detection ---")
    manifest_drift = detect_manifest_drift(ssot)
    print()

    # --- Live endpoint probes ---
    probe_results = []
    if not args.no_probes:
        log_info("--- Live Endpoint Health Probes ---")
        probe_results = run_health_probes(args.mode)
        print()

    # --- Health score ---
    health_score = calculate_health_score(probe_results)
    grade_color = GREEN if health_score["score"] >= 85 else (YELLOW if health_score["score"] >= 60 else RED)
    print(f"{BOLD}  Health Score: {grade_color}{health_score['score']}/100 [{health_score['grade']}] — {health_score['status']}{RESET}")
    print()

    # --- Analytics & trends ---
    log_info("--- Deployment Analytics ---")
    analytics = collect_deployment_analytics(ssot, probe_results, health_score, manifest_drift)
    print()

    log_info("--- SLA Trends ---")
    collect_sla_trends(probe_results)
    print()

    log_info("--- Runtime Telemetry ---")
    write_runtime_telemetry(ssot, probe_results, health_score, manifest_drift, repo_integrity, analytics)
    print()

    # --- Final summary ---
    print(f"{BOLD}{CYAN}============================================================{RESET}")
    print(f"{BOLD}  OBSERVABILITY SUMMARY{RESET}")
    print(f"{BOLD}{CYAN}============================================================{RESET}")
    print(f"  Platform version : {ssot['platform']['version']}")
    print(f"  Pipeline version : {ssot['ci']['pipeline_version']}")
    print(f"  Health score     : {health_score['score']}/100 [{health_score['grade']}]")
    print(f"  Status           : {health_score['status']}")
    print(f"  Critical healthy : {health_score.get('critical_healthy', 'N/A')}/{health_score.get('critical_total', 'N/A')}")
    print(f"  SLA breaches     : {health_score.get('sla_breaches', 0)}")
    print(f"  Manifest drift   : {'YES' if manifest_drift.get('drift_detected') else 'NO'}")
    print(f"  Repo integrity   : {'OK' if repo_integrity.get('critical_files_ok') else 'FAIL — missing files'}")
    print(f"  Stability (10r)  : {analytics.get('stability_score_10_runs', 'N/A')}%")
    print()

    # CI gate: exit 1 if critical or degraded in ci mode
    if args.mode == "ci":
        if health_score["status"] in ("CRITICAL", "DEGRADED"):
            log_fail(f"CI GATE FAIL: health_status={health_score['status']} score={health_score['score']}")
            return 1
        if not repo_integrity.get("critical_files_ok"):
            log_fail(f"CI GATE FAIL: missing critical files: {repo_integrity.get('critical_files_missing')}")
            return 1
        log_ok("CI gate passed — platform OPERATIONAL")

    return 0


if __name__ == "__main__":
    sys.exit(main())
in__":
    sys.exit(main())
xit(main())
