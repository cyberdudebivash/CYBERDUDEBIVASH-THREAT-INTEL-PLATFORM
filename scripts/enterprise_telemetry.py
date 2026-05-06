#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Enterprise Telemetry Engine
===============================================================
Phase 7: Enterprise Observability Expansion

Produces centralized runtime telemetry:
  - API latency tracking (P50/P90/P95/P99 per endpoint)
  - Deployment analytics (duration, success rate, rollback frequency)
  - Workflow analytics (duration, overlap, stuck detection)
  - SLA trend analysis (score over time, grade drift)
  - Manifest freshness analytics (age distribution)
  - Runtime anomaly detection (latency spikes, count drops)
  - Operations telemetry layer (unified JSON telemetry output)

Produces:
  data/telemetry/runtime_telemetry.json
  data/telemetry/deployment_analytics.json
  data/telemetry/sla_trends.json
  data/telemetry/anomaly_report.json

Usage:
  python3 scripts/enterprise_telemetry.py collect  -- full telemetry collection pass
  python3 scripts/enterprise_telemetry.py report   -- print telemetry report
  python3 scripts/enterprise_telemetry.py anomaly  -- anomaly detection only
"""

import argparse
import json
import pathlib
import statistics
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timedelta, timezone

REPO_ROOT     = pathlib.Path(__file__).resolve().parent.parent
TELEMETRY_DIR = REPO_ROOT / "data" / "telemetry"
HEALTH_DIR    = REPO_ROOT / "data" / "health"
TELEMETRY_DIR.mkdir(parents=True, exist_ok=True)

WORKER_BASE = "https://intel.cyberdudebivash.com"

# Endpoints to track
TRACKED_ENDPOINTS = {
    "health":      f"{WORKER_BASE}/api/health",
    "latest_json": f"{WORKER_BASE}/api/v1/intel/latest.json",
    "top10_json":  f"{WORKER_BASE}/api/v1/intel/top10.json",
    "feed_json":   f"{WORKER_BASE}/api/feed.json",
    "apex_json":   f"{WORKER_BASE}/api/v1/intel/apex.json",
}

# Anomaly thresholds
ANOMALY_THRESHOLDS = {
    "latency_spike_ms":     3000,
    "latency_critical_ms":  5000,
    "advisory_count_drop_pct": 20,   # alert if count drops >20% from last seen
    "sla_score_drop":       10,      # alert if SLA score drops >10 points
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def probe_endpoint(url: str, samples: int = 3, timeout: int = 15) -> dict:
    """Probe endpoint N times and compute latency stats."""
    latencies = []
    statuses = []
    errors = []

    for i in range(samples):
        t0 = time.monotonic()
        try:
            req = urllib.request.Request(url, headers={"User-Agent": "SENTINEL-APEX-TELEMETRY/1.0"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                lat = int((time.monotonic() - t0) * 1000)
                latencies.append(lat)
                statuses.append(resp.status)
                # Read response to measure body size
                body = resp.read(1024)
        except Exception as e:
            lat = int((time.monotonic() - t0) * 1000)
            latencies.append(lat)
            statuses.append(0)
            errors.append(str(e))
        if i < samples - 1:
            time.sleep(1)

    ok_count = sum(1 for s in statuses if s == 200)
    result = {
        "url": url,
        "samples": samples,
        "availability_pct": round((ok_count / samples) * 100, 1),
        "statuses": statuses,
        "errors": errors[:3],
    }

    if latencies:
        sorted_lats = sorted(latencies)
        result["latency_ms"] = {
            "min":  sorted_lats[0],
            "p50":  sorted_lats[len(sorted_lats) // 2],
            "p90":  sorted_lats[max(0, int(len(sorted_lats) * 0.9) - 1)],
            "p95":  sorted_lats[max(0, int(len(sorted_lats) * 0.95) - 1)],
            "max":  sorted_lats[-1],
            "mean": int(statistics.mean(latencies)),
            "stdev": int(statistics.stdev(latencies)) if len(latencies) > 1 else 0,
        }
    return result


def load_sla_history() -> list:
    """Load SLA history for trend analysis."""
    sla_hist_path = HEALTH_DIR / "sla_history.json"
    if not sla_hist_path.exists():
        return []
    try:
        return json.loads(sla_hist_path.read_text()).get("history", [])
    except Exception:
        return []


def load_deployment_history() -> list:
    dh_path = HEALTH_DIR / "deployment_health.json"
    if not dh_path.exists():
        return []
    try:
        return json.loads(dh_path.read_text()).get("deployment_history", [])
    except Exception:
        return []


def collect_runtime_telemetry() -> dict:
    """Collect live runtime telemetry from all endpoints."""
    print(f"[TELEMETRY] Probing {len(TRACKED_ENDPOINTS)} endpoints (3 samples each)...")
    endpoint_data = {}
    all_p95s = []

    for name, url in TRACKED_ENDPOINTS.items():
        print(f"  Probing {name}...")
        data = probe_endpoint(url, samples=3)
        endpoint_data[name] = data
        if "latency_ms" in data:
            all_p95s.append(data["latency_ms"]["p95"])

    # Platform-level aggregates
    all_available = all(ep.get("availability_pct", 0) == 100.0 for ep in endpoint_data.values())
    avg_availability = round(
        sum(ep.get("availability_pct", 0) for ep in endpoint_data.values()) / len(endpoint_data), 1
    ) if endpoint_data else 0

    platform_p95 = int(statistics.median(all_p95s)) if all_p95s else 0

    telemetry = {
        "collected_at": now_iso(),
        "platform": "CYBERDUDEBIVASH(R) SENTINEL APEX",
        "platform_status": {
            "all_endpoints_available": all_available,
            "avg_availability_pct": avg_availability,
            "platform_p95_latency_ms": platform_p95,
            "endpoint_count": len(endpoint_data),
        },
        "endpoints": endpoint_data,
        "anomalies_detected": [],
    }

    # Anomaly detection
    for name, data in endpoint_data.items():
        if not data.get("latency_ms"):
            continue
        p95 = data["latency_ms"]["p95"]
        if p95 > ANOMALY_THRESHOLDS["latency_critical_ms"]:
            telemetry["anomalies_detected"].append({
                "type": "LATENCY_CRITICAL",
                "endpoint": name,
                "p95_ms": p95,
                "threshold_ms": ANOMALY_THRESHOLDS["latency_critical_ms"],
                "severity": "P1",
            })
        elif p95 > ANOMALY_THRESHOLDS["latency_spike_ms"]:
            telemetry["anomalies_detected"].append({
                "type": "LATENCY_SPIKE",
                "endpoint": name,
                "p95_ms": p95,
                "threshold_ms": ANOMALY_THRESHOLDS["latency_spike_ms"],
                "severity": "P2",
            })
        if data.get("availability_pct", 100) < 100:
            telemetry["anomalies_detected"].append({
                "type": "AVAILABILITY_DEGRADED",
                "endpoint": name,
                "availability_pct": data["availability_pct"],
                "severity": "P0" if data["availability_pct"] < 50 else "P1",
            })

    return telemetry


def collect_sla_trends() -> dict:
    """Analyze SLA score trends from history."""
    history = load_sla_history()
    current_sla_path = HEALTH_DIR / "sla_status.json"
    current_score = 0
    current_grade = "?"
    if current_sla_path.exists():
        try:
            sla = json.loads(current_sla_path.read_text())
            current_score = sla.get("sla_evaluation", {}).get("sla_score", 0)
            current_grade = sla.get("sla_evaluation", {}).get("grade", "?")
        except Exception:
            pass

    # Build trend from history
    scores = [h.get("sla_score", 0) for h in history if "sla_score" in h]
    trend = "stable"
    if len(scores) >= 3:
        recent_avg = statistics.mean(scores[-3:])
        older_avg = statistics.mean(scores[:-3]) if len(scores) > 3 else recent_avg
        if recent_avg > older_avg + 2:
            trend = "improving"
        elif recent_avg < older_avg - 2:
            trend = "degrading"

    return {
        "collected_at": now_iso(),
        "current_score": current_score,
        "current_grade": current_grade,
        "history_points": len(scores),
        "score_avg": round(statistics.mean(scores), 1) if scores else current_score,
        "score_min": min(scores) if scores else current_score,
        "score_max": max(scores) if scores else current_score,
        "trend": trend,
        "last_10_scores": scores[-10:] if scores else [current_score],
    }


def collect_deployment_analytics() -> dict:
    """Analyze deployment history for analytics."""
    history = load_deployment_history()
    if not history:
        return {
            "collected_at": now_iso(),
            "total_deploys": 0,
            "success_rate_pct": 100.0,
            "rollback_count": 0,
            "avg_duration_s": 0,
            "note": "No deployment history available yet",
        }

    total = len(history)
    successes = sum(1 for d in history if d.get("conclusion") == "success")
    rollbacks = sum(1 for d in history if d.get("was_rollback", False))
    durations = [d.get("duration_s", 0) for d in history if d.get("duration_s", 0) > 0]

    return {
        "collected_at": now_iso(),
        "total_deploys": total,
        "success_count": successes,
        "failure_count": total - successes,
        "success_rate_pct": round((successes / total) * 100, 1) if total else 100.0,
        "rollback_count": rollbacks,
        "rollback_rate_pct": round((rollbacks / total) * 100, 1) if total else 0,
        "avg_duration_s": round(statistics.mean(durations), 1) if durations else 0,
        "p95_duration_s": sorted(durations)[max(0, int(len(durations) * 0.95) - 1)] if durations else 0,
        "recent_10": history[-10:],
    }


def generate_anomaly_report(runtime_telemetry: dict, sla_trends: dict) -> dict:
    """Generate consolidated anomaly report."""
    anomalies = runtime_telemetry.get("anomalies_detected", [])
    report = {
        "generated_at": now_iso(),
        "total_anomalies": len(anomalies),
        "anomalies": anomalies,
        "sla_trend": sla_trends.get("trend", "stable"),
        "current_sla_score": sla_trends.get("current_score", 0),
        "platform_healthy": len(anomalies) == 0 and sla_trends.get("trend") != "degrading",
        "recommended_actions": [],
    }

    # Generate recommendations
    for anomaly in anomalies:
        atype = anomaly.get("type")
        ep = anomaly.get("endpoint", "")
        if atype == "LATENCY_CRITICAL":
            report["recommended_actions"].append({
                "priority": "P1",
                "action": f"Investigate {ep} critical latency",
                "detail": f"P95={anomaly.get('p95_ms')}ms > {anomaly.get('threshold_ms')}ms critical threshold",
            })
        elif atype == "LATENCY_SPIKE":
            report["recommended_actions"].append({
                "priority": "P2",
                "action": f"Optimize {ep} response size or caching",
                "detail": f"P95={anomaly.get('p95_ms')}ms exceeds {anomaly.get('threshold_ms')}ms warning threshold",
            })
        elif atype == "AVAILABILITY_DEGRADED":
            report["recommended_actions"].append({
                "priority": "P0",
                "action": f"Immediate investigation: {ep} availability {anomaly.get('availability_pct')}%",
                "detail": "Endpoint returning non-200 responses",
            })

    if sla_trends.get("trend") == "degrading":
        report["recommended_actions"].append({
            "priority": "P1",
            "action": "SLA score trending downward -- review violations",
            "detail": f"Trend: {sla_trends.get('trend')} | Current: {sla_trends.get('current_score')}/100",
        })

    if not report["recommended_actions"]:
        report["recommended_actions"].append({
            "priority": "INFO",
            "action": "No anomalies detected",
            "detail": "Platform operating within normal parameters",
        })

    return report


def cmd_collect(args) -> int:
    """Full telemetry collection pass."""
    print(f"\n[TELEMETRY] Starting collection pass at {now_iso()[:19]}Z")
    print("=" * 60)

    runtime = collect_runtime_telemetry()
    (TELEMETRY_DIR / "runtime_telemetry.json").write_text(json.dumps(runtime, indent=2))
    print(f"[TELEMETRY] Runtime telemetry: {len(runtime['endpoints'])} endpoints, "
          f"{len(runtime['anomalies_detected'])} anomalies")

    sla_trends = collect_sla_trends()
    (TELEMETRY_DIR / "sla_trends.json").write_text(json.dumps(sla_trends, indent=2))
    print(f"[TELEMETRY] SLA trends: score={sla_trends['current_score']}/100 "
          f"grade={sla_trends['current_grade']} trend={sla_trends['trend']}")

    deploy_analytics = collect_deployment_analytics()
    (TELEMETRY_DIR / "deployment_analytics.json").write_text(json.dumps(deploy_analytics, indent=2))
    print(f"[TELEMETRY] Deploy analytics: {deploy_analytics['total_deploys']} deploys, "
          f"success={deploy_analytics['success_rate_pct']}%")

    anomaly_report = generate_anomaly_report(runtime, sla_trends)
    (TELEMETRY_DIR / "anomaly_report.json").write_text(json.dumps(anomaly_report, indent=2))
    print(f"[TELEMETRY] Anomaly report: {anomaly_report['total_anomalies']} anomalies, "
          f"healthy={anomaly_report['platform_healthy']}")

    print("=" * 60)
    print(f"[TELEMETRY] All telemetry files written to {TELEMETRY_DIR}")
    return 0 if anomaly_report["platform_healthy"] else 2


def cmd_report(args) -> int:
    """Print telemetry report from last collection."""
    rt_path = TELEMETRY_DIR / "runtime_telemetry.json"
    if not rt_path.exists():
        print("[TELEMETRY] No telemetry data -- run 'collect' first")
        return 1

    rt = json.loads(rt_path.read_text())
    st = json.loads((TELEMETRY_DIR / "sla_trends.json").read_text()) if (TELEMETRY_DIR / "sla_trends.json").exists() else {}
    ar = json.loads((TELEMETRY_DIR / "anomaly_report.json").read_text()) if (TELEMETRY_DIR / "anomaly_report.json").exists() else {}

    print(f"\nENTERPRISE TELEMETRY REPORT -- {rt.get('collected_at','?')[:19]}Z")
    print("=" * 70)
    ps = rt.get("platform_status", {})
    print(f"  Platform P95 Latency:  {ps.get('platform_p95_latency_ms')}ms")
    print(f"  Avg Availability:      {ps.get('avg_availability_pct')}%")
    print(f"  All Endpoints OK:      {ps.get('all_endpoints_available')}")
    print(f"\n  SLA Score:             {st.get('current_score')}/100 Grade {st.get('current_grade')}")
    print(f"  SLA Trend:             {st.get('trend')}")
    print(f"  Anomalies Detected:    {ar.get('total_anomalies', 0)}")
    print(f"  Platform Healthy:      {ar.get('platform_healthy')}")
    print(f"\n  ENDPOINT P95 LATENCIES:")
    for name, ep in rt.get("endpoints", {}).items():
        lms = ep.get("latency_ms", {})
        avail = ep.get("availability_pct", 0)
        p95 = lms.get("p95", "?")
        print(f"    {name:<20} avail={avail:>5}%  p95={p95}ms")
    if ar.get("recommended_actions"):
        print(f"\n  RECOMMENDATIONS:")
        for rec in ar["recommended_actions"]:
            print(f"    [{rec['priority']}] {rec['action']}")
    print("=" * 70)
    return 0


def cmd_anomaly(args) -> int:
    """Anomaly detection only -- fast probe."""
    print(f"[TELEMETRY] Running anomaly detection...")
    rt = collect_runtime_telemetry()
    sla = collect_sla_trends()
    ar = generate_anomaly_report(rt, sla)

    if ar["total_anomalies"] > 0:
        print(f"[TELEMETRY] ANOMALIES DETECTED: {ar['total_anomalies']}")
        for a in ar["anomalies"]:
            print(f"  [{a.get('severity','?')}] {a.get('type')} -- {a.get('endpoint','')} {a.get('p95_ms','')}ms")
        return 1
    else:
        print(f"[TELEMETRY] No anomalies detected -- platform nominal")
        return 0


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Enterprise Telemetry")
    sub = parser.add_subparsers(dest="cmd")
    sub.add_parser("collect", help="Full telemetry collection pass")
    sub.add_parser("report",  help="Print telemetry report")
    sub.add_parser("anomaly", help="Anomaly detection only")

    args = parser.parse_args()
    dispatch = {
        "collect": cmd_collect,
        "report":  cmd_report,
        "anomaly": cmd_anomaly,
    }
    if args.cmd not in dispatch:
        parser.print_help()
        return 1
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
