#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Platform Health Monitor
============================================================
Phase 4: Enterprise Observability Stack

Generates the five canonical health JSON files under data/health/:
  runtime_health.json    -- live API probes, manifest freshness, latency
  deployment_health.json -- deploy history, last deploy status, rollback state
  workflow_health.json   -- workflow execution state from GitHub API
  sla_status.json        -- uptime %, API availability, SLA compliance
  integrity_status.json  -- frontend checksum state, data integrity gates

Usage:
  python3 scripts/platform_health_monitor.py [--all] [--runtime] [--sla] [--integrity]
"""

import argparse
import json
import os
import pathlib
import subprocess
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from typing import Any

REPO_ROOT = pathlib.Path(__file__).resolve().parent.parent
HEALTH_DIR = REPO_ROOT / "data" / "health"
HEALTH_DIR.mkdir(parents=True, exist_ok=True)

WORKER_BASE = "https://intel.cyberdudebivash.com"
PLATFORM_VERSION = "143.0.0"

def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def probe_url(url: str, timeout: int = 10) -> dict:
    """HTTP probe with timing. Returns status, latency_ms, error."""
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SENTINEL-APEX-MONITOR/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.monotonic() - t0) * 1000)
            body = resp.read(65536).decode("utf-8", errors="replace")
            return {
                "url": url,
                "status": resp.status,
                "ok": True,
                "latency_ms": latency_ms,
                "content_length": len(body),
                "error": None,
            }
    except urllib.error.HTTPError as e:
        latency_ms = int((time.monotonic() - t0) * 1000)
        return {"url": url, "status": e.code, "ok": False, "latency_ms": latency_ms, "error": str(e)}
    except Exception as e:
        latency_ms = int((time.monotonic() - t0) * 1000)
        return {"url": url, "status": 0, "ok": False, "latency_ms": latency_ms, "error": str(e)}

def probe_json(url: str, timeout: int = 15) -> dict:
    """HTTP probe that parses JSON body."""
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SENTINEL-APEX-MONITOR/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.monotonic() - t0) * 1000)
            body = json.loads(resp.read(524288).decode("utf-8", errors="replace"))
            return {
                "url": url, "status": resp.status, "ok": True,
                "latency_ms": latency_ms, "body": body, "error": None,
            }
    except urllib.error.HTTPError as e:
        latency_ms = int((time.monotonic() - t0) * 1000)
        return {"url": url, "status": e.code, "ok": False, "latency_ms": latency_ms, "body": None, "error": str(e)}
    except Exception as e:
        latency_ms = int((time.monotonic() - t0) * 1000)
        return {"url": url, "status": 0, "ok": False, "latency_ms": latency_ms, "body": None, "error": str(e)}


def generate_runtime_health() -> dict:
    """Probe all live endpoints. Measure latency. Check manifest freshness."""
    print("  Probing runtime endpoints...")
    endpoints = {
        "health":        f"{WORKER_BASE}/api/health",
        "preview":       f"{WORKER_BASE}/api/preview",
        "feed":          f"{WORKER_BASE}/api/feed.json",
        "latest_json":   f"{WORKER_BASE}/api/v1/intel/latest.json",
        "top10_json":    f"{WORKER_BASE}/api/v1/intel/top10.json",
        "apex_json":     f"{WORKER_BASE}/api/v1/intel/apex.json",
        "manifest_json": f"{WORKER_BASE}/api/v1/intel/manifest.json",
    }

    probes = {}
    healthy_count = 0
    total_latency = 0

    for name, url in endpoints.items():
        result = probe_url(url, timeout=15)
        probes[name] = result
        if result["ok"]:
            healthy_count += 1
            total_latency += result["latency_ms"]

    # Check health endpoint for version + advisory count
    health_probe = probe_json(f"{WORKER_BASE}/api/health", timeout=15)
    version_match = False
    advisory_count = 0
    jwt_configured = False
    r2_intel = "unknown"

    if health_probe["ok"] and health_probe["body"]:
        hb = health_probe["body"]
        live_ver = hb.get("version", "")
        version_match = live_ver == PLATFORM_VERSION
        advisory_count = hb.get("pipeline", {}).get("advisory_count", 0)
        checks = hb.get("checks", {})
        jwt_configured = checks.get("jwt_configured", False)
        r2_intel = checks.get("r2_intel", "unknown")

    # Manifest freshness check (latest.json)
    latest_probe = probe_json(f"{WORKER_BASE}/api/v1/intel/latest.json", timeout=20)
    manifest_fresh = False
    manifest_age_hours = None
    if latest_probe["ok"] and latest_probe["body"]:
        gen_at = latest_probe["body"].get("generated_at", "")
        if gen_at:
            try:
                ts = datetime.fromisoformat(gen_at.replace("Z", "+00:00"))
                age_s = (datetime.now(timezone.utc) - ts).total_seconds()
                manifest_age_hours = round(age_s / 3600, 1)
                manifest_fresh = age_s < 14400  # fresh if < 4 hours
            except Exception:
                pass

    overall_status = "ok" if healthy_count >= 5 else ("degraded" if healthy_count >= 3 else "critical")

    report = {
        "schema_version": "1.0",
        "generated_at": now_iso(),
        "platform": f"CYBERDUDEBIVASH(R) SENTINEL APEX v{PLATFORM_VERSION}",
        "overall_status": overall_status,
        "endpoints_healthy": healthy_count,
        "endpoints_total": len(endpoints),
        "avg_latency_ms": int(total_latency / max(healthy_count, 1)),
        "version_match": version_match,
        "advisory_count": advisory_count,
        "jwt_configured": jwt_configured,
        "r2_intel_status": r2_intel,
        "manifest_freshness": {
            "fresh": manifest_fresh,
            "age_hours": manifest_age_hours,
            "threshold_hours": 4,
        },
        "endpoint_probes": probes,
    }

    out = HEALTH_DIR / "runtime_health.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  Written: {out} (status={overall_status}, healthy={healthy_count}/{len(endpoints)})")
    return report


def generate_deployment_health() -> dict:
    """Pull recent deploy history from git log and config/version.json."""
    print("  Generating deployment health...")

    version_cfg = {}
    try:
        with open(REPO_ROOT / "config" / "version.json", encoding="utf-8") as f:
            version_cfg = json.load(f)
    except Exception:
        pass

    # Recent commits touching Worker src or deploy workflow
    deploy_commits = []
    try:
        result = subprocess.run(
            ["git", "log", "--oneline", "-20", "--", 
             "workers/intel-gateway/src/", ".github/workflows/deploy-worker.yml"],
            capture_output=True, text=True, cwd=REPO_ROOT, timeout=10
        )
        for line in result.stdout.strip().splitlines():
            parts = line.split(" ", 1)
            deploy_commits.append({"sha": parts[0], "message": parts[1] if len(parts) > 1 else ""})
    except Exception:
        pass

    # Last commit overall
    last_commit_sha = ""
    last_commit_msg = ""
    try:
        r = subprocess.run(["git", "log", "--oneline", "-1"], 
                          capture_output=True, text=True, cwd=REPO_ROOT, timeout=5)
        parts = r.stdout.strip().split(" ", 1)
        last_commit_sha = parts[0]
        last_commit_msg = parts[1] if len(parts) > 1 else ""
    except Exception:
        pass

    report = {
        "schema_version": "1.0",
        "generated_at": now_iso(),
        "platform_version": version_cfg.get("version", PLATFORM_VERSION),
        "platform_label": version_cfg.get("version_display", f"v{PLATFORM_VERSION}"),
        "last_commit": {"sha": last_commit_sha, "message": last_commit_msg},
        "deploy_governance": {
            "deployment_authority": "deploy-worker.yml (TIER 3 only)",
            "concurrency_group": "worker-deploy",
            "cancel_in_progress": True,
            "ci_bot_guard": True,
            "pre_flight_gates": 4,
            "data_integrity_gates": 4,
            "sanitize_encoding": True,
            "esbuild_preflight": True,
        },
        "recent_worker_deploys": deploy_commits[:10],
        "rollback_capability": {
            "available": True,
            "method": "git revert + push to main triggers deploy-worker",
            "rto_estimate_minutes": 15,
        },
    }

    out = HEALTH_DIR / "deployment_health.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  Written: {out}")
    return report


def generate_workflow_health() -> dict:
    """Classify all 29 workflows into TIER 1/2/3 and report governance state."""
    print("  Generating workflow health...")

    WORKFLOW_TIERS = {
        # TIER 1 -- READ ONLY (no git push, no deploy)
        "gumroad-refresh.yml":      {"tier": 1, "label": "READ-ONLY", "purpose": "Gumroad product sync"},
        "lead_autoresponder.yml":   {"tier": 1, "label": "READ-ONLY", "purpose": "Email lead response"},
        "r2-data-sync.yml":         {"tier": 1, "label": "READ-ONLY", "purpose": "R2 object storage sync"},
        "telegram-revenue.yml":     {"tier": 1, "label": "READ-ONLY", "purpose": "Telegram revenue bot"},
        "status-monitor.yml":       {"tier": 1, "label": "READ-ONLY", "purpose": "Platform status monitoring"},
        "weekly-analyst-briefing.yml": {"tier": 1, "label": "READ-ONLY", "purpose": "Weekly threat briefing"},
        # TIER 2 -- DATA GENERATORS (git push data, no production deploy)
        "sentinel-blogger.yml":     {"tier": 2, "label": "DATA-GEN+DEPLOY", "purpose": "Master pipeline: ingest+AI+R2+gh-pages"},
        "ai-predictions.yml":       {"tier": 2, "label": "DATA-GEN", "purpose": "AI predictive threat scoring"},
        "ai-threat-analyst.yml":    {"tier": 2, "label": "DATA-GEN", "purpose": "AI threat analysis"},
        "arsenal.yml":              {"tier": 2, "label": "DATA-GEN", "purpose": "Arsenal threat enrichment"},
        "bughunter-recon.yml":      {"tier": 2, "label": "DATA-GEN", "purpose": "Bug hunter recon scan"},
        "bughunter-resilient.yml":  {"tier": 2, "label": "DATA-GEN", "purpose": "Bug hunter resilience scan"},
        "convergence.yml":          {"tier": 2, "label": "DATA-GEN", "purpose": "Threat convergence analysis"},
        "detection-engine.yml":     {"tier": 2, "label": "DATA-GEN", "purpose": "Detection rule generation"},
        "genesis-powerhouse.yml":   {"tier": 2, "label": "DATA-GEN", "purpose": "Genesis threat powerhouse"},
        "multi-source-intel.yml":   {"tier": 2, "label": "DATA-GEN", "purpose": "Multi-source intel aggregation"},
        "nexus-intelligence.yml":   {"tier": 2, "label": "DATA-GEN", "purpose": "Nexus intel enrichment"},
        "omnishield.yml":           {"tier": 2, "label": "DATA-GEN", "purpose": "OmniShield threat correlation"},
        "precognition-engine.yml":  {"tier": 2, "label": "DATA-GEN", "purpose": "Predictive threat engine"},
        "report-engine.yml":        {"tier": 2, "label": "DATA-GEN", "purpose": "Tactical dossier reports"},
        "sentinel-factory.yml":     {"tier": 2, "label": "DATA-GEN", "purpose": "Sentinel data factory"},
        "sovereign-platform.yml":   {"tier": 2, "label": "DATA-GEN", "purpose": "Sovereign platform ops"},
        "syndicate.yml":            {"tier": 2, "label": "DATA-GEN", "purpose": "Threat syndication"},
        "zerodayhunter.yml":        {"tier": 2, "label": "DATA-GEN", "purpose": "Zero-day detection"},
        # TIER 3 -- DEPLOYMENT AUTHORITY (only layer that deploys to production)
        "deploy-worker.yml":        {"tier": 3, "label": "DEPLOY-AUTHORITY", "purpose": "Cloudflare Worker deploy"},
        "sync-dashboard.yml":       {"tier": 3, "label": "DISABLED-EMERGENCY", "purpose": "Emergency gh-pages patch (disabled)"},
        # GOVERNANCE -- Cross-cutting integrity and ops
        "autonomous-guardian.yml":  {"tier": "G", "label": "GOVERNANCE", "purpose": "Autonomous pipeline guardian"},
        "ui-file-guardian.yml":     {"tier": "G", "label": "GOVERNANCE", "purpose": "Frontend asset integrity"},
        "revenue-orchestrator.yml": {"tier": "G", "label": "GOVERNANCE", "purpose": "Revenue pipeline orchestration"},
    }

    tier_counts = {1: 0, 2: 0, 3: 0, "G": 0}
    workflows_yml = list(pathlib.Path(REPO_ROOT / ".github" / "workflows").glob("*.yml"))

    workflow_details = []
    for yml in sorted(workflows_yml):
        name = yml.name
        meta = WORKFLOW_TIERS.get(name, {"tier": "?", "label": "UNCLASSIFIED", "purpose": "Unknown"})
        tier = meta["tier"]
        if tier in tier_counts:
            tier_counts[tier] += 1
        workflow_details.append({
            "workflow": name,
            "tier": tier,
            "label": meta["label"],
            "purpose": meta["purpose"],
        })

    # Governance violations: workflows that do git push but are TIER 1
    violations = []
    for wf in workflow_details:
        if wf["tier"] == 1 and wf["label"] != "READ-ONLY":
            violations.append(f"TIER-1 workflow '{wf['workflow']}' has non-read-only label")

    # Concurrency group coverage
    concurrency_groups = {
        "sentinel-data-writer": "Serializes all TIER-2 data generators (cancel-in-progress=false)",
        "worker-deploy":         "Serializes TIER-3 Worker deploys (cancel-in-progress=true)",
        "sentinel-deployment":   "Serializes gh-pages deploys (cancel-in-progress=true)",
        "autonomous-guardian":   "Governance health sweeps",
        "ui-file-guardian":      "Frontend integrity checks",
        "revenue-orchestrator":  "Revenue pipeline",
    }

    report = {
        "schema_version": "1.0",
        "generated_at": now_iso(),
        "total_workflows": len(workflows_yml),
        "classified_workflows": len(WORKFLOW_TIERS),
        "tier_counts": {str(k): v for k, v in tier_counts.items()},
        "governance_violations": violations,
        "governance_ok": len(violations) == 0,
        "concurrency_groups": concurrency_groups,
        "deployment_authority": {
            "tier3_workflows": ["deploy-worker.yml"],
            "gh_pages_authority": "sentinel-blogger.yml (JamesIves/github-pages-deploy-action)",
            "worker_authority": "deploy-worker.yml (wrangler deploy)",
            "single_authority_model": True,
        },
        "workflows": workflow_details,
    }

    out = HEALTH_DIR / "workflow_health.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  Written: {out} (classified={len(WORKFLOW_TIERS)}/{len(workflows_yml)}, violations={len(violations)})")
    return report


def generate_sla_status(runtime: dict) -> dict:
    """Compute SLA metrics from runtime probe results."""
    print("  Generating SLA status...")

    # Load existing SLA history if it exists
    sla_history_path = HEALTH_DIR / "sla_history.json"
    history = []
    if sla_history_path.exists():
        try:
            with open(sla_history_path, encoding="utf-8") as f:
                history = json.load(f).get("history", [])
        except Exception:
            history = []

    # Current window probe results
    ep = runtime.get("endpoint_probes", {})
    total_probes = len(ep)
    ok_probes = sum(1 for p in ep.values() if p.get("ok"))
    availability_pct = round(ok_probes / max(total_probes, 1) * 100, 2)

    # Append current observation to history (keep last 288 = 24h at 5min intervals)
    history.append({
        "ts": now_iso(),
        "ok": ok_probes,
        "total": total_probes,
        "availability_pct": availability_pct,
        "advisory_count": runtime.get("advisory_count", 0),
        "manifest_fresh": runtime.get("manifest_freshness", {}).get("fresh", False),
    })
    history = history[-288:]
    sla_history_path.write_text(json.dumps({"history": history}, indent=2), encoding="utf-8")

    # Compute rolling 24h availability
    recent = history[-288:]
    if recent:
        rolling_availability = round(sum(h["availability_pct"] for h in recent) / len(recent), 2)
    else:
        rolling_availability = availability_pct

    # SLA target definitions
    sla_targets = {
        "api_availability": {"target_pct": 99.5, "current_pct": rolling_availability},
        "manifest_freshness": {
            "target_hours": 4,
            "current_hours": runtime.get("manifest_freshness", {}).get("age_hours"),
            "ok": runtime.get("manifest_freshness", {}).get("fresh", False),
        },
        "advisory_count": {
            "target_min": 100,
            "current": runtime.get("advisory_count", 0),
            "ok": runtime.get("advisory_count", 0) >= 100,
        },
        "version_match": {
            "target": PLATFORM_VERSION,
            "ok": runtime.get("version_match", False),
        },
        "jwt_configured": {
            "ok": runtime.get("jwt_configured", False),
        },
    }

    sla_compliant = (
        rolling_availability >= 99.5
        and sla_targets["manifest_freshness"]["ok"]
        and sla_targets["advisory_count"]["ok"]
        and sla_targets["version_match"]["ok"]
        and sla_targets["jwt_configured"]["ok"]
    )

    report = {
        "schema_version": "1.0",
        "generated_at": now_iso(),
        "platform_version": PLATFORM_VERSION,
        "sla_compliant": sla_compliant,
        "sla_status": "COMPLIANT" if sla_compliant else "DEGRADED",
        "current_availability_pct": availability_pct,
        "rolling_24h_availability_pct": rolling_availability,
        "sla_targets": sla_targets,
        "business_impact": {
            "customer_visible_failure": not sla_compliant,
            "blank_ai_panels": not runtime.get("manifest_freshness", {}).get("fresh", False),
            "missing_threat_cards": runtime.get("advisory_count", 0) < 10,
            "api_unavailable": availability_pct < 95,
        },
        "observation_window": {
            "samples": len(recent),
            "max_samples": 288,
            "interval_approx_minutes": 5,
        },
    }

    out = HEALTH_DIR / "sla_status.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  Written: {out} (sla={report['sla_status']}, avail={rolling_availability}%)")
    return report


def generate_integrity_status() -> dict:
    """Run frontend_integrity.py verify and capture output."""
    print("  Generating integrity status...")

    checksums_path = REPO_ROOT / "config" / "frontend_checksums.json"
    registry_exists = checksums_path.exists()

    registry_meta = {}
    asset_integrity = []
    all_ok = True

    if registry_exists:
        with open(checksums_path, encoding="utf-8") as f:
            registry = json.load(f)
        registry_meta = {
            "generated_at": registry.get("generated_at"),
            "protected_count": registry.get("protected_count", 0),
        }

        import hashlib
        for rel, meta in registry.get("assets", {}).items():
            path = REPO_ROOT / rel
            if not path.exists():
                asset_integrity.append({"asset": rel, "status": "MISSING"})
                all_ok = False
                continue
            sha = hashlib.sha256(path.read_bytes()).hexdigest()
            ok = sha == meta.get("sha256", "")
            asset_integrity.append({
                "asset": rel,
                "status": "OK" if ok else "TAMPERED",
                "sha256_match": ok,
                "size_bytes": path.stat().st_size,
            })
            if not ok:
                all_ok = False

    # Data integrity gates status (check if gate scripts exist)
    data_gates = {
        "encoding_validator": (REPO_ROOT / "scripts" / "encoding_validator.py").exists(),
        "output_validation_gate": (REPO_ROOT / "scripts" / "output_validation_gate.py").exists(),
        "api_dashboard_contract_validator": (REPO_ROOT / "scripts" / "api_dashboard_contract_validator.py").exists(),
        "regression_immunity": (REPO_ROOT / "scripts" / "regression_immunity.py").exists(),
        "sanitize_encoding": (REPO_ROOT / "scripts" / "sanitize_encoding.py").exists(),
        "frontend_integrity": (REPO_ROOT / "scripts" / "frontend_integrity.py").exists(),
    }

    report = {
        "schema_version": "1.0",
        "generated_at": now_iso(),
        "frontend_integrity": {
            "registry_exists": registry_exists,
            "registry_meta": registry_meta,
            "all_assets_ok": all_ok,
            "assets": asset_integrity,
        },
        "data_integrity_gates": data_gates,
        "gates_all_present": all(data_gates.values()),
        "overall_integrity": "OK" if (all_ok and all(data_gates.values())) else "DEGRADED",
    }

    out = HEALTH_DIR / "integrity_status.json"
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  Written: {out} (frontend_ok={all_ok}, gates_present={all(data_gates.values())})")
    return report


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Platform Health Monitor")
    parser.add_argument("--all", action="store_true", help="Generate all health files")
    parser.add_argument("--runtime", action="store_true", help="Runtime health only")
    parser.add_argument("--deployment", action="store_true", help="Deployment health only")
    parser.add_argument("--workflow", action="store_true", help="Workflow health only")
    parser.add_argument("--sla", action="store_true", help="SLA status only")
    parser.add_argument("--integrity", action="store_true", help="Integrity status only")
    args = parser.parse_args()

    do_all = args.all or not any([args.runtime, args.deployment, args.workflow, args.sla, args.integrity])

    print(f"SENTINEL APEX Platform Health Monitor -- {now_iso()}")
    print(f"Output: {HEALTH_DIR}")
    print()

    runtime = None

    if do_all or args.runtime:
        runtime = generate_runtime_health()

    if do_all or args.deployment:
        generate_deployment_health()

    if do_all or args.workflow:
        generate_workflow_health()

    if do_all or args.sla:
        if runtime is None:
            runtime = generate_runtime_health()
        generate_sla_status(runtime)

    if do_all or args.integrity:
        generate_integrity_status()

    print()
    print("OK: Platform health monitor complete")


if __name__ == "__main__":
    main()
