#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Operations Health Aggregator
================================================================
Enterprise Operations & Observability: Phase 4

Aggregates ALL platform health signals into a single unified
operational status JSON. This is the single source of truth for:
  - Platform SLA readiness
  - API health
  - Intelligence feed health
  - Workflow pipeline health
  - Monetization system health
  - Subscription quota status
  - Security posture

Produces:
  data/health/ops_status.json    -- unified ops dashboard (SSOT)
  data/health/ops_summary.json   -- compact status for external consumers

Usage:
  python3 scripts/ops_health_aggregator.py [--report] [--strict]
  Exit 0 = all green  |  Exit 1 = degraded  |  Exit 2 = critical
"""

import argparse
import json
import pathlib
import datetime
import sys
from typing import Dict, Any, List, Optional, Tuple

# ============================================================
# PATHS
# ============================================================
DATA      = pathlib.Path("data")
HEALTH    = DATA / "health"
TELEMETRY = DATA / "telemetry"
QUALITY   = DATA / "quality"
AUDIT     = DATA / "audit"
BILLING   = DATA / "billing"
AUTH      = DATA / "auth"

OUTPUT_FULL    = HEALTH / "ops_status.json"
OUTPUT_SUMMARY = HEALTH / "ops_summary.json"

# ============================================================
# SAFE JSON LOADER
# ============================================================
def _load(path: pathlib.Path, default=None) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except Exception:
        pass
    return default


def _utcnow() -> str:
    return datetime.datetime.utcnow().strftime("%Y-%m-%dT%H:%M:%SZ")


def _age_hours(ts_str: str) -> Optional[float]:
    """Return age in hours of an ISO timestamp, or None if unparseable."""
    if not ts_str:
        return None
    try:
        ts_str = str(ts_str).replace("Z", "+00:00").replace(" ", "T")
        ts = datetime.datetime.fromisoformat(ts_str)
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=datetime.timezone.utc)
        return max(0.0, (datetime.datetime.now(datetime.timezone.utc) - ts).total_seconds() / 3600)
    except Exception:
        return None


# ============================================================
# HEALTH PROBE FUNCTIONS
# ============================================================

def probe_sla(sla_path: pathlib.Path) -> Dict:
    raw = _load(sla_path, {})
    if not raw:
        return {"status": "UNKNOWN", "tier": "UNKNOWN", "uptime_pct": None,
                "p95_latency_ms": None, "score": None}
    uptime = raw.get("uptime_estimate_pct", raw.get("uptime_pct"))
    p95    = raw.get("api_probe", {}).get("p95_latency_ms")
    score  = raw.get("sla_score")
    tier   = raw.get("sla_tier", raw.get("tier", "UNKNOWN"))
    age    = _age_hours(raw.get("generated_at", ""))

    status = "OK"
    if uptime is not None and float(uptime) < 99.0:
        status = "DEGRADED"
    if uptime is not None and float(uptime) < 95.0:
        status = "CRITICAL"
    if age and age > 48:
        status = "STALE"

    return {
        "status":        status,
        "tier":          tier,
        "uptime_pct":    uptime,
        "p95_latency_ms": p95,
        "score":         score,
        "data_age_hours": round(age, 1) if age is not None else None,
    }


def probe_feed(data_dir: pathlib.Path) -> Dict:
    """Check intel feed health — item count, freshness, IOC coverage."""
    feed_path     = data_dir / "feed.json"
    manifest_path = data_dir / "intel_manifest.json"

    feed     = _load(feed_path, [])
    manifest = _load(manifest_path, [])

    feed_items = feed if isinstance(feed, list) else feed.get("items", []) if isinstance(feed, dict) else []
    man_items  = manifest if isinstance(manifest, list) else manifest.get("advisories", []) if isinstance(manifest, dict) else []

    feed_count = len(feed_items)
    man_count  = len(man_items)

    # IOC coverage
    ioc_items = sum(1 for i in man_items if (i.get("ioc_count", 0) or 0) > 0)
    ioc_rate  = round(ioc_items / max(1, man_count) * 100, 1)

    # Freshness — age of newest item
    newest_age = None
    for items in [feed_items, man_items]:
        for item in items[:10]:
            age = _age_hours(item.get("published_at", item.get("timestamp", "")))
            if age is not None:
                newest_age = age if newest_age is None else min(newest_age, age)

    status = "OK"
    if feed_count == 0:
        status = "CRITICAL"
    elif feed_count < 10:
        status = "DEGRADED"
    elif newest_age and newest_age > 48:
        status = "STALE"

    return {
        "status":          status,
        "feed_count":      feed_count,
        "manifest_count":  man_count,
        "ioc_coverage_pct": ioc_rate,
        "newest_item_age_hours": round(newest_age, 1) if newest_age else None,
    }


def probe_workflow(health_dir: pathlib.Path) -> Dict:
    """Check CI/CD workflow health."""
    wf_health = _load(health_dir / "workflow_health.json", {})
    dep_health = _load(health_dir / "deployment_health.json", {})

    last_deploy_ts = (
        dep_health.get("last_deploy_at")
        or dep_health.get("deployed_at")
        or wf_health.get("last_success")
    )
    deploy_age = _age_hours(last_deploy_ts)
    success_rate = wf_health.get("success_rate", dep_health.get("success_rate"))

    status = "OK"
    if deploy_age and deploy_age > 72:
        status = "STALE"
    if success_rate is not None and float(success_rate) < 0.80:
        status = "DEGRADED"
    if success_rate is not None and float(success_rate) < 0.50:
        status = "CRITICAL"

    return {
        "status":              status,
        "last_deploy_at":      last_deploy_ts,
        "deploy_age_hours":    round(deploy_age, 1) if deploy_age else None,
        "success_rate":        success_rate,
        "total_runs":          wf_health.get("total_runs"),
        "consecutive_failures": wf_health.get("consecutive_failures", 0),
    }


def probe_monetization(billing_dir: pathlib.Path, auth_dir: pathlib.Path) -> Dict:
    """Check subscription and API key health."""
    customers = _load(billing_dir / "customers.json", {})
    api_keys  = _load(auth_dir / "api_keys.json", {})

    cust_list = customers.get("customers", []) if isinstance(customers, dict) else customers
    keys_raw  = api_keys.get("keys", {}) if isinstance(api_keys, dict) else {}
    # keys can be a list or a dict keyed by hash
    key_list: List[Dict] = (
        list(keys_raw.values()) if isinstance(keys_raw, dict) else
        keys_raw if isinstance(keys_raw, list) else []
    )

    active_customers = sum(1 for c in cust_list if isinstance(c, dict) and c.get("active", True))
    active_keys      = sum(1 for k in key_list  if isinstance(k, dict) and k.get("active", True))

    tier_counts: Dict[str, int] = {}
    for k in key_list:
        if isinstance(k, dict):
            tier = k.get("tier", "UNKNOWN")
            tier_counts[tier] = tier_counts.get(tier, 0) + 1

    status = "OK"
    if active_keys == 0:
        status = "DEGRADED"

    return {
        "status":           status,
        "active_customers": active_customers,
        "total_customers":  len(cust_list),
        "active_api_keys":  active_keys,
        "total_api_keys":   len(key_list),
        "tier_distribution": tier_counts,
    }


def probe_intelligence_quality(quality_dir: pathlib.Path) -> Dict:
    """Check intelligence quality metrics."""
    trust_raw  = _load(quality_dir / "source_trust_scores.json", {})
    conf_raw   = _load(quality_dir / "confidence_calibration.json", {})

    platform_stats = trust_raw.get("platform_stats", {})
    summary        = conf_raw.get("summary", conf_raw)

    avg_trust   = platform_stats.get("avg_trust_score")
    avg_conf    = summary.get("avg_confidence")
    band_dist   = summary.get("band_distribution", {})
    total_src   = platform_stats.get("total_sources", 0)

    status = "OK"
    if avg_conf is not None and float(avg_conf) < 30:
        status = "DEGRADED"
    if avg_trust is not None and float(avg_trust) < 0.50:
        status = "DEGRADED"

    return {
        "status":             status,
        "avg_source_trust":   avg_trust,
        "avg_confidence":     avg_conf,
        "total_sources":      total_src,
        "platinum_sources":   platform_stats.get("platinum_sources", 0),
        "band_distribution":  band_dist,
    }


def probe_telemetry(telemetry_dir: pathlib.Path) -> Dict:
    """Check telemetry freshness."""
    ci_run = _load(telemetry_dir / "ci_run_latest.json", {})
    rt     = _load(telemetry_dir / "runtime_telemetry.json", {})

    ci_ts  = ci_run.get("recorded_at")
    rt_ts  = rt.get("generated_at") if isinstance(rt, dict) else None
    ci_age = _age_hours(ci_ts)
    rt_age = _age_hours(rt_ts)

    status = "OK"
    if ci_age and ci_age > 48:
        status = "STALE"
    if not ci_ts and not rt_ts:
        status = "UNKNOWN"

    return {
        "status":                 status,
        "ci_run_id":              ci_run.get("run_id"),
        "ci_pipeline_version":    ci_run.get("pipeline_version"),
        "ci_recorded_at":         ci_ts,
        "ci_age_hours":           round(ci_age, 1) if ci_age else None,
        "runtime_telemetry_age_hours": round(rt_age, 1) if rt_age else None,
    }


# ============================================================
# OVERALL HEALTH ROLLUP
# ============================================================
STATUS_RANK = {"OK": 0, "UNKNOWN": 1, "STALE": 2, "DEGRADED": 3, "CRITICAL": 4}


def rollup_status(statuses: List[str]) -> str:
    if not statuses:
        return "UNKNOWN"
    return max(statuses, key=lambda s: STATUS_RANK.get(s, 0))


# ============================================================
# MAIN AGGREGATOR
# ============================================================
def run_aggregation(report: bool = False, strict: bool = False) -> Tuple[Dict, int]:
    generated_at = _utcnow()

    probes = {
        "sla":                 probe_sla(HEALTH / "sla_status.json"),
        "feed":                probe_feed(DATA),
        "workflow":            probe_workflow(HEALTH),
        "monetization":        probe_monetization(BILLING, AUTH),
        "intelligence_quality": probe_intelligence_quality(QUALITY),
        "telemetry":           probe_telemetry(TELEMETRY),
    }

    all_statuses = [v["status"] for v in probes.values()]
    overall      = rollup_status(all_statuses)
    critical_cnt = sum(1 for s in all_statuses if s == "CRITICAL")
    degraded_cnt = sum(1 for s in all_statuses if s in ("CRITICAL", "DEGRADED"))

    version_file = pathlib.Path("config/version.json")
    version_raw  = _load(version_file, {})
    platform_ver = (
        version_raw.get("version")
        or pathlib.Path("VERSION").read_text(encoding="utf-8").strip()
        if pathlib.Path("VERSION").exists() else "unknown"
    )

    full_output = {
        "generated_at":       generated_at,
        "schema":             "sentinel_apex_ops_status_v1",
        "platform_version":   platform_ver,
        "overall_status":     overall,
        "critical_probes":    critical_cnt,
        "degraded_probes":    degraded_cnt,
        "probe_results":      probes,
        "operational_notes":  _build_notes(probes, overall),
    }

    summary_output = {
        "generated_at":    generated_at,
        "platform_version": platform_ver,
        "overall_status":  overall,
        "sla_status":      probes["sla"]["status"],
        "feed_count":      probes["feed"]["feed_count"],
        "active_api_keys": probes["monetization"]["active_api_keys"],
        "avg_confidence":  probes["intelligence_quality"]["avg_confidence"],
    }

    HEALTH.mkdir(parents=True, exist_ok=True)
    OUTPUT_FULL.write_text(json.dumps(full_output, indent=2), encoding="utf-8")
    OUTPUT_SUMMARY.write_text(json.dumps(summary_output, indent=2), encoding="utf-8")

    if report:
        print("\n" + "=" * 68)
        print("SENTINEL APEX OPERATIONS HEALTH REPORT")
        print(f"Generated: {generated_at}")
        print("=" * 68)
        print(f"  OVERALL STATUS:  {overall}")
        print(f"  Platform:        v{platform_ver}")
        print(f"  Critical probes: {critical_cnt}")
        print(f"  Degraded probes: {degraded_cnt}")
        print()
        for probe_name, probe_data in probes.items():
            status = probe_data["status"]
            indicator = {"OK": "OK", "DEGRADED": "WARN", "CRITICAL": "CRIT",
                         "STALE": "STALE", "UNKNOWN": "??"}
            mark = indicator.get(status, status)
            print(f"  [{mark:<5}] {probe_name}")
            for k, v in probe_data.items():
                if k != "status" and v is not None:
                    print(f"           {k}: {v}")
        if full_output["operational_notes"]:
            print("\n  OPERATIONAL NOTES:")
            for note in full_output["operational_notes"]:
                print(f"    - {note}")
        print("=" * 68)

    exit_code = 0
    if overall == "CRITICAL":
        exit_code = 2
    elif overall in ("DEGRADED", "STALE"):
        exit_code = 1

    if strict and exit_code > 0:
        return full_output, exit_code

    return full_output, 0


def _build_notes(probes: Dict, overall: str) -> List[str]:
    notes = []
    if probes["feed"]["status"] == "CRITICAL":
        notes.append("CRITICAL: Feed is empty — intelligence pipeline may be broken")
    if probes["feed"].get("ioc_coverage_pct", 100) < 10:
        notes.append(f"IOC coverage low ({probes['feed'].get('ioc_coverage_pct')}%) — IOC extraction needs attention")
    if probes["sla"].get("p95_latency_ms") and probes["sla"]["p95_latency_ms"] > 2000:
        notes.append(f"API p95 latency elevated: {probes['sla']['p95_latency_ms']}ms (target <1000ms)")
    if probes["workflow"].get("consecutive_failures", 0) > 2:
        notes.append(f"CI pipeline has {probes['workflow']['consecutive_failures']} consecutive failures")
    if probes["monetization"]["active_api_keys"] == 0:
        notes.append("No active API keys detected — monetization system may need initialization")
    if probes["telemetry"]["status"] == "STALE":
        notes.append("Telemetry data is stale (>48h) — CI pipeline may not be running")
    return notes


# ============================================================
# ENTRY POINT
# ============================================================
if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="SENTINEL APEX Operations Health Aggregator")
    parser.add_argument("--report", action="store_true", help="Print full report to stdout")
    parser.add_argument("--strict", action="store_true", help="Exit non-zero if any probe fails")
    args = parser.parse_args()

    result, exit_code = run_aggregation(report=args.report or True, strict=args.strict)
    overall = result["overall_status"]
    print(f"[OPS] Done. Overall status: {overall} | "
          f"Critical: {result['critical_probes']} | "
          f"Degraded: {result['degraded_probes']}")
    sys.exit(exit_code)
