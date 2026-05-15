"""
enterprise_observability.py — CYBERDUDEBIVASH Threat Intelligence Platform
Phase 5: Enterprise Observability Engine

Structured telemetry aggregation, platform health scoring, SLA compliance tracking,
pipeline performance metrics, anomaly detection, and SIEM-ready event emission.

Consumes:
  data/ocios/coordinator_report.json       — stage timings, success/failure
  data/ocios/soc_priority_queue.json       — SOC tier distribution + scores
  data/ocios/executive_dashboard.json      — risk posture, velocity
  data/ocios/escalation_matrix.json        — escalation counts
  data/ocios/remediation_tiers.json        — remediation load per tier
  data/ocios/analyst_workload.json         — analyst distribution
  data/ocios/ocios_manifest.json           — corpus manifest
  data/trust/trust_engine_summary.json     — trust posture metrics
  data/trust/platform_trust_summary.json   — publishable %, violations
  data/mssp/mssp_engine_summary.json       — MSSP risk posture, KEV count
  data/mssp/financial_exposure_model.json  — financial risk quantification

Produces:
  data/ocios/observability_telemetry.json       — full CEF-compatible event stream
  data/ocios/platform_health_dashboard.json     — unified platform health aggregate
  data/ocios/sla_compliance_report.json         — SLA adherence per SOC tier
  data/ocios/pipeline_performance_metrics.json  — latency / throughput / error rates
  data/ocios/anomaly_detection_report.json      — detected regressions + alerts
  data/ocios/observability_manifest.json        — master observability record

Author: CYBERDUDEBIVASH Pvt. Ltd.
Version: 1.0.0
"""

from __future__ import annotations

import json
import logging
import math
import os
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s — %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
log = logging.getLogger("enterprise_observability")

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------
_ENGINE   = "enterprise_observability"
_VERSION  = "1.0.0"
_SCHEMA   = "1.0"

# SLA windows in hours (per SOC tier)
_SLA_WINDOWS_H: Dict[str, float] = {
    "P0_critical": 4.0,
    "P1_high":     24.0,
    "P2_medium":   72.0,
    "P3_low":      720.0,   # 30 days
    "P4_monitor":  2160.0,  # 90 days
}

# Health score weights — each subsystem contributes to overall platform health
_HEALTH_WEIGHTS: Dict[str, float] = {
    "pipeline_execution":  0.30,   # OCIOS coordinator stage success rate
    "intel_trust":         0.25,   # publishable % and avg trust score
    "threat_coverage":     0.20,   # KEV coverage, tier distribution
    "sla_compliance":      0.15,   # items within SLA
    "anomaly_rate":        0.10,   # inverse of anomaly density
}

# Anomaly thresholds
_ANOMALY_THRESHOLDS = {
    "trust_score_critical_low":    30.0,   # avg trust below this → CRITICAL
    "trust_score_warn_low":        50.0,   # avg trust below this → WARNING
    "publishable_pct_critical_low": 5.0,   # publishable % below this → CRITICAL
    "violation_rate_high":         15.0,   # violation % above this → WARNING
    "stage_failure_any":            1,     # any failed OCIOS stage → WARNING
    "p0_items_present":             1,     # any P0 items → ALERT
    "kev_items_min":                1,     # KEV present → ensure SOC escalation
    "pipeline_latency_warn_s":     10.0,   # coordinator > 10s → WARNING
    "pipeline_latency_critical_s": 30.0,   # coordinator > 30s → CRITICAL
    "financial_exposure_critical": 10_000_000,  # >$10M ALE → CRITICAL
    "financial_exposure_high":      5_000_000,  # >$5M ALE → HIGH
}

# CEF severity mapping
_CEF_SEVERITY = {
    "CRITICAL": 9,
    "HIGH":     7,
    "MEDIUM":   5,
    "LOW":      3,
    "INFO":     1,
}

# ---------------------------------------------------------------------------
# Utility: safe atomic file write
# ---------------------------------------------------------------------------
def _atomic_write(path: Path, data: Any) -> None:
    """Write JSON atomically via tmp → fsync → os.replace."""
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(".tmp")
    try:
        payload = json.dumps(data, indent=2, ensure_ascii=False)
        with open(tmp, "w", encoding="utf-8") as fh:
            fh.write(payload)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
        log.debug("Written: %s", path)
    except Exception as exc:
        log.error("Atomic write failed for %s: %s", path, exc)
        if tmp.exists():
            tmp.unlink(missing_ok=True)
        raise


def _now_utc() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def _load_json(path: Path, default: Any = None) -> Any:
    """Safe JSON loader — returns default on any failure."""
    try:
        with open(path, "r", encoding="utf-8") as fh:
            return json.load(fh)
    except Exception as exc:
        log.warning("Could not load %s: %s", path, exc)
        return default


# ---------------------------------------------------------------------------
# Data Loading
# ---------------------------------------------------------------------------
def _resolve_repo_root() -> Path:
    """Walk up from this script's location to find the repo root."""
    here = Path(__file__).resolve()
    for candidate in [here.parent.parent, Path.cwd(), Path.cwd().parent]:
        if (candidate / "data").exists():
            return candidate
    return here.parent.parent


def load_all_engine_data(repo: Path) -> Dict[str, Any]:
    """Load all engine outputs into a unified context dict."""
    ocios = repo / "data" / "ocios"
    trust = repo / "data" / "trust"
    mssp  = repo / "data" / "mssp"

    ctx: Dict[str, Any] = {}

    # OCIOS
    ctx["coordinator"]    = _load_json(ocios / "coordinator_report.json",       {})
    ctx["soc_queue"]      = _load_json(ocios / "soc_priority_queue.json",        {})
    ctx["exec_dashboard"] = _load_json(ocios / "executive_dashboard.json",       {})
    ctx["escalation"]     = _load_json(ocios / "escalation_matrix.json",         {})
    ctx["remediation"]    = _load_json(ocios / "remediation_tiers.json",         {})
    ctx["analyst_wl"]     = _load_json(ocios / "analyst_workload.json",          {})
    ctx["ocios_manifest"] = _load_json(ocios / "ocios_manifest.json",            {})
    ctx["soc_summary"]    = _load_json(ocios / "soc_prioritization_summary.json",{})

    # Trust
    ctx["trust_summary"]   = _load_json(trust / "trust_engine_summary.json",  {})
    ctx["platform_trust"]  = _load_json(trust / "platform_trust_summary.json",{})

    # MSSP
    ctx["mssp_summary"]   = _load_json(mssp / "mssp_engine_summary.json",      {})
    ctx["financial_model"]= _load_json(mssp / "financial_exposure_model.json", {})

    loaded = sum(1 for v in ctx.values() if v)
    log.info("Loaded %d/%d engine data sources", loaded, len(ctx))
    return ctx


# ---------------------------------------------------------------------------
# Telemetry Event Builder
# ---------------------------------------------------------------------------
def _make_event(
    event_type: str,
    severity: str,
    source_engine: str,
    message: str,
    details: Optional[Dict] = None,
    event_id: Optional[str] = None,
) -> Dict[str, Any]:
    """Produce a structured telemetry event (CEF-compatible JSON)."""
    return {
        "event_id":    event_id or str(uuid.uuid4()),
        "timestamp":   _now_utc(),
        "schema":      "cyberdudebivash-observability/1.0",
        "event_type":  event_type,
        "severity":    severity,
        "cef_severity": _CEF_SEVERITY.get(severity.upper(), 1),
        "source":      f"platform/{source_engine}",
        "product":     "CYBERDUDEBIVASH-ThreatIntelPlatform",
        "vendor":      "CYBERDUDEBIVASH Pvt. Ltd.",
        "version":     _VERSION,
        "message":     message,
        "details":     details or {},
    }


def build_telemetry_stream(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build a comprehensive telemetry event stream from all engine data.

    Returns structured document with:
      - pipeline events (per OCIOS stage)
      - trust governance events
      - MSSP / financial risk events
      - SOC coverage events
    """
    events: List[Dict] = []
    run_id = str(uuid.uuid4())[:8]

    # --- 1. OCIOS coordinator stage events ---
    coord = ctx.get("coordinator", {})
    stage_results = coord.get("stage_results", [])
    for stage in stage_results:
        name    = stage.get("stage", "unknown")
        status  = stage.get("status", "unknown")
        elapsed = stage.get("elapsed_s", 0.0)
        error   = stage.get("error")
        metrics = stage.get("metrics", {})

        sev = "INFO" if status == "success" else "HIGH"
        msg = f"OCIOS stage [{name}] completed with status={status} in {elapsed:.2f}s"
        if error:
            msg += f" | error: {error}"

        events.append(_make_event(
            event_type="pipeline.stage.execution",
            severity=sev,
            source_engine="ocios_coordinator",
            message=msg,
            details={
                "stage":   name,
                "status":  status,
                "elapsed_s": elapsed,
                "error":   error,
                "metrics": metrics,
            }
        ))

    # Overall coordinator event
    overall_status = coord.get("overall_status", "unknown")
    total_elapsed  = coord.get("total_elapsed_s", 0.0)
    advisory_count = coord.get("advisory_count", 0)
    sev = "INFO" if overall_status == "success" else "CRITICAL"
    events.append(_make_event(
        event_type="pipeline.run.complete",
        severity=sev,
        source_engine="ocios_coordinator",
        message=f"OCIOS pipeline completed: status={overall_status}, advisories={advisory_count}, elapsed={total_elapsed:.2f}s",
        details={
            "run_id":         coord.get("run_id"),
            "overall_status": overall_status,
            "advisory_count": advisory_count,
            "total_elapsed_s": total_elapsed,
            "stage_count":    coord.get("stage_count", 0),
            "tier_breakdown": coord.get("tier_breakdown", {}),
        }
    ))

    # Pipeline latency alert
    if total_elapsed >= _ANOMALY_THRESHOLDS["pipeline_latency_critical_s"]:
        events.append(_make_event(
            event_type="pipeline.performance.degradation",
            severity="CRITICAL",
            source_engine="ocios_coordinator",
            message=f"Pipeline latency CRITICAL: {total_elapsed:.2f}s exceeds threshold of {_ANOMALY_THRESHOLDS['pipeline_latency_critical_s']}s",
            details={"elapsed_s": total_elapsed, "threshold_s": _ANOMALY_THRESHOLDS["pipeline_latency_critical_s"]}
        ))
    elif total_elapsed >= _ANOMALY_THRESHOLDS["pipeline_latency_warn_s"]:
        events.append(_make_event(
            event_type="pipeline.performance.degradation",
            severity="MEDIUM",
            source_engine="ocios_coordinator",
            message=f"Pipeline latency elevated: {total_elapsed:.2f}s",
            details={"elapsed_s": total_elapsed, "threshold_s": _ANOMALY_THRESHOLDS["pipeline_latency_warn_s"]}
        ))

    # --- 2. Trust governance events ---
    ts = ctx.get("trust_summary", {})
    pt = ctx.get("platform_trust", {})
    avg_trust    = ts.get("average_trust_score", 0.0)
    publishable  = ts.get("publishable_pct", 0.0)
    violations   = ts.get("violation_count", 0)
    items_assessed = ts.get("items_assessed", 0)
    posture      = pt.get("platform_trust_posture", "UNKNOWN")

    trust_sev = "INFO"
    if avg_trust < _ANOMALY_THRESHOLDS["trust_score_critical_low"]:
        trust_sev = "CRITICAL"
    elif avg_trust < _ANOMALY_THRESHOLDS["trust_score_warn_low"]:
        trust_sev = "HIGH"

    events.append(_make_event(
        event_type="trust.corpus.assessment",
        severity=trust_sev,
        source_engine="intel_trust_governance",
        message=(
            f"Corpus trust assessment: posture={posture}, "
            f"avg_trust={avg_trust:.1f}/100, publishable={publishable:.1f}%, "
            f"violations={violations}/{items_assessed}"
        ),
        details={
            "platform_trust_posture": posture,
            "average_trust_score": avg_trust,
            "publishable_pct": publishable,
            "publishable_count": ts.get("publishable_count", 0),
            "violation_count": violations,
            "items_assessed": items_assessed,
            "tier_distribution": pt.get("tier_distribution", {}),
        }
    ))

    if publishable < _ANOMALY_THRESHOLDS["publishable_pct_critical_low"]:
        events.append(_make_event(
            event_type="trust.publishable.critical_low",
            severity="CRITICAL",
            source_engine="intel_trust_governance",
            message=f"Publishable intel critically low: {publishable:.1f}% — enrichment pipeline audit required",
            details={"publishable_pct": publishable, "threshold": _ANOMALY_THRESHOLDS["publishable_pct_critical_low"]}
        ))

    violation_rate = (violations / max(items_assessed, 1)) * 100
    if violation_rate > _ANOMALY_THRESHOLDS["violation_rate_high"]:
        events.append(_make_event(
            event_type="trust.violations.elevated",
            severity="HIGH",
            source_engine="intel_trust_governance",
            message=f"Trust violation rate elevated: {violation_rate:.1f}% of corpus has violations",
            details={"violation_rate_pct": round(violation_rate, 2), "violation_count": violations}
        ))

    # --- 3. MSSP / Financial events ---
    ms = ctx.get("mssp_summary", {})
    fm = ctx.get("financial_model", {})
    risk_posture = ms.get("risk_posture", "UNKNOWN")
    kev_count    = ms.get("kev_count", 0)
    critical_count = ms.get("critical_count", 0)
    ale_usd      = fm.get("total_exposure_usd", 0) or fm.get("annual_loss_expectancy_usd", 0)

    mssp_sev = {"CRITICAL": "CRITICAL", "HIGH": "HIGH", "ELEVATED": "MEDIUM"}.get(risk_posture, "INFO")
    events.append(_make_event(
        event_type="mssp.risk.posture",
        severity=mssp_sev,
        source_engine="mssp_executive_engine",
        message=(
            f"Enterprise risk posture: {risk_posture} | KEV count: {kev_count} | "
            f"Critical advisories: {critical_count} | ALE: ${ale_usd:,.0f}"
        ),
        details={
            "risk_posture":    risk_posture,
            "kev_count":       kev_count,
            "critical_count":  critical_count,
            "ale_usd":         ale_usd,
            "items_analyzed":  ms.get("items_analyzed", 0),
        }
    ))

    if ale_usd >= _ANOMALY_THRESHOLDS["financial_exposure_critical"]:
        events.append(_make_event(
            event_type="mssp.financial.critical_exposure",
            severity="CRITICAL",
            source_engine="mssp_executive_engine",
            message=f"Annual loss expectancy CRITICAL: ${ale_usd:,.0f} — immediate risk mitigation required",
            details={"ale_usd": ale_usd, "threshold": _ANOMALY_THRESHOLDS["financial_exposure_critical"]}
        ))
    elif ale_usd >= _ANOMALY_THRESHOLDS["financial_exposure_high"]:
        events.append(_make_event(
            event_type="mssp.financial.high_exposure",
            severity="HIGH",
            source_engine="mssp_executive_engine",
            message=f"Annual loss expectancy elevated: ${ale_usd:,.0f}",
            details={"ale_usd": ale_usd, "threshold": _ANOMALY_THRESHOLDS["financial_exposure_high"]}
        ))

    if kev_count > 0:
        events.append(_make_event(
            event_type="mssp.kev.active",
            severity="HIGH",
            source_engine="mssp_executive_engine",
            message=f"Active KEV advisories: {kev_count} CISA Known Exploited Vulnerabilities require immediate SOC response",
            details={"kev_count": kev_count, "escalation_required": True}
        ))

    # --- 4. SOC coverage events ---
    sq = ctx.get("soc_queue", {})
    items = sq.get("items", [])
    total = len(items)
    tier_breakdown = coord.get("tier_breakdown", {})
    p0_count = tier_breakdown.get("P0_critical", 0)
    p1_count = tier_breakdown.get("P1_high", 0)

    events.append(_make_event(
        event_type="soc.queue.snapshot",
        severity="INFO",
        source_engine="ocios_soc_prioritization_engine",
        message=f"SOC queue snapshot: {total} advisories classified | P0={p0_count} P1={p1_count}",
        details={
            "total_advisories": total,
            "tier_breakdown":   tier_breakdown,
            "exec_escalations": sum(1 for i in items if i.get("executive_escalation")),
        }
    ))

    if p0_count >= _ANOMALY_THRESHOLDS["p0_items_present"]:
        events.append(_make_event(
            event_type="soc.escalation.p0_active",
            severity="CRITICAL",
            source_engine="ocios_soc_prioritization_engine",
            message=f"P0 CRITICAL items active: {p0_count} advisories require immediate response (<4h SLA)",
            details={"p0_count": p0_count, "sla_window_hours": _SLA_WINDOWS_H["P0_critical"]}
        ))

    # Engine health events (each engine ran successfully or not)
    for eng_name, summary_key in [
        ("intel_trust_governance", "trust_summary"),
        ("mssp_executive_engine",  "mssp_summary"),
    ]:
        summary = ctx.get(summary_key, {})
        status  = summary.get("status", "unknown")
        elapsed = summary.get("elapsed_seconds", 0.0)
        errors  = summary.get("errors", [])
        sev = "INFO" if status == "success" else "HIGH"
        events.append(_make_event(
            event_type=f"engine.{eng_name}.run",
            severity=sev,
            source_engine=eng_name,
            message=f"Engine {eng_name}: status={status}, elapsed={elapsed:.2f}s, errors={len(errors)}",
            details={"status": status, "elapsed_s": elapsed, "error_count": len(errors)}
        ))

    log.info("Built telemetry stream: %d events", len(events))

    return {
        "schema_version":  _SCHEMA,
        "engine":          _ENGINE,
        "version":         _VERSION,
        "run_id":          run_id,
        "generated_at":    _now_utc(),
        "event_count":     len(events),
        "severity_counts": _count_severities(events),
        "events":          events,
    }


def _count_severities(events: List[Dict]) -> Dict[str, int]:
    counts: Dict[str, int] = {}
    for e in events:
        sev = e.get("severity", "UNKNOWN")
        counts[sev] = counts.get(sev, 0) + 1
    return counts


# ---------------------------------------------------------------------------
# Platform Health Dashboard
# ---------------------------------------------------------------------------
def _score_pipeline_execution(ctx: Dict[str, Any]) -> Tuple[float, str, Dict]:
    """Score pipeline execution health 0-100."""
    coord = ctx.get("coordinator", {})
    stage_results = coord.get("stage_results", [])
    if not stage_results:
        return 0.0, "No pipeline data available", {}

    total  = len(stage_results)
    passed = sum(1 for s in stage_results if s.get("status") == "success")
    rate   = passed / max(total, 1)

    # Latency penalty
    elapsed = coord.get("total_elapsed_s", 0.0)
    if elapsed >= _ANOMALY_THRESHOLDS["pipeline_latency_critical_s"]:
        latency_factor = 0.5
    elif elapsed >= _ANOMALY_THRESHOLDS["pipeline_latency_warn_s"]:
        latency_factor = 0.8
    else:
        latency_factor = 1.0

    score = rate * 100 * latency_factor
    label = "HEALTHY" if score >= 90 else "DEGRADED" if score >= 60 else "UNHEALTHY"
    detail = {
        "stages_total": total,
        "stages_passed": passed,
        "success_rate_pct": round(rate * 100, 1),
        "total_elapsed_s": elapsed,
        "latency_factor": latency_factor,
    }
    return round(score, 1), label, detail


def _score_intel_trust(ctx: Dict[str, Any]) -> Tuple[float, str, Dict]:
    """Score intel trust health 0-100."""
    ts = ctx.get("trust_summary", {})
    pt = ctx.get("platform_trust", {})
    if not ts:
        return 0.0, "No trust data available", {}

    avg_trust   = ts.get("average_trust_score", 0.0)
    publishable = ts.get("publishable_pct", 0.0)
    violations  = ts.get("violation_count", 0)
    total       = ts.get("items_assessed", 1)

    # Normalize: trust score on 0-100, publishable adds bonus
    trust_component      = avg_trust                      # 0-100 base
    publishable_component = min(publishable * 5, 30)      # up to +30 bonus
    violation_penalty    = min((violations / max(total, 1)) * 200, 30)  # up to -30

    score = max(0.0, min(100.0, trust_component + publishable_component - violation_penalty))
    posture = pt.get("platform_trust_posture", "UNKNOWN")
    label = (
        "CERTIFIED"      if score >= 75 else
        "STANDARD"       if score >= 50 else
        "BELOW-STANDARD" if score >= 25 else
        "CRITICAL"
    )
    detail = {
        "average_trust_score": avg_trust,
        "publishable_pct":     publishable,
        "violation_count":     violations,
        "platform_trust_posture": posture,
        "trust_component":     round(trust_component, 1),
        "publishable_bonus":   round(publishable_component, 1),
        "violation_penalty":   round(violation_penalty, 1),
    }
    return round(score, 1), label, detail


def _score_threat_coverage(ctx: Dict[str, Any]) -> Tuple[float, str, Dict]:
    """Score threat coverage health 0-100."""
    ms  = ctx.get("mssp_summary", {})
    soc = ctx.get("soc_summary", {})
    sq  = ctx.get("soc_queue",   {})
    if not ms:
        return 50.0, "Insufficient data", {}

    total     = len(sq.get("items", []))
    kev_count = ms.get("kev_count", 0)
    risk      = ms.get("risk_posture", "UNKNOWN")

    # Coverage is scored by: tiered classification coverage
    tier_bd = ctx.get("coordinator", {}).get("tier_breakdown", {})
    p0 = tier_bd.get("P0_critical", 0)
    p1 = tier_bd.get("P1_high",     0)
    p2 = tier_bd.get("P2_medium",   0)

    # Penalize if KEV items exist but no P0/P1 response
    kev_handling_score = 100.0
    if kev_count > 0 and (p0 + p1) == 0:
        # KEV present but not escalated to P0/P1 — scoring gap
        kev_handling_score = max(0, 100 - kev_count * 5)

    # Coverage rate — all items classified
    classified_pct = min(100.0, ((p0 + p1 + p2) / max(total, 1)) * 100 * 3)
    score = (kev_handling_score * 0.6 + classified_pct * 0.4)
    score = min(100.0, max(0.0, score))

    label = (
        "CRITICAL" if risk == "CRITICAL" and kev_count > 0 and (p0 + p1) == 0
        else "HIGH"     if risk in ("CRITICAL", "HIGH")
        else "ELEVATED" if risk == "ELEVATED"
        else "STANDARD"
    )
    detail = {
        "risk_posture":       risk,
        "kev_count":          kev_count,
        "total_advisories":   total,
        "p0_items":           p0,
        "p1_items":           p1,
        "p2_items":           p2,
        "kev_handling_score": round(kev_handling_score, 1),
    }
    return round(score, 1), label, detail


def _score_sla_compliance(ctx: Dict[str, Any]) -> Tuple[float, str, Dict]:
    """Score SLA compliance 0-100 based on tier distribution vs capacity."""
    sq = ctx.get("soc_queue", {})
    items = sq.get("items", [])
    aw = ctx.get("analyst_wl", {})
    analyst_data = aw.get("analysts", [])
    total_items = len(items)

    if total_items == 0:
        return 100.0, "NO_ITEMS", {"message": "No advisory items to evaluate"}

    # Derive analyst capacity
    total_analysts = len(analyst_data) if analyst_data else 1
    # Each analyst can handle: P0=2/day, P1=5/day, P2=10/day, P3=20/day
    capacity_map = {"P0_critical": 2, "P1_high": 5, "P2_medium": 10, "P3_low": 20, "P4_monitor": 50}
    coord = ctx.get("coordinator", {})
    tier_bd = coord.get("tier_breakdown", {})

    demand  = 0
    capacity = 0
    tier_sla: Dict[str, Dict] = {}

    for tier_key, count in tier_bd.items():
        cap_per_analyst = capacity_map.get(tier_key, 10)
        tier_capacity   = cap_per_analyst * total_analysts
        tier_compliant  = min(count, tier_capacity)
        rate            = (tier_compliant / max(count, 1)) * 100
        tier_sla[tier_key] = {
            "item_count":      count,
            "analyst_capacity": tier_capacity,
            "estimated_compliant": tier_compliant,
            "compliance_rate_pct": round(rate, 1),
            "sla_hours":       _SLA_WINDOWS_H.get(tier_key, 0),
        }
        demand   += count
        capacity += tier_capacity

    overall_rate = min(100.0, (capacity / max(demand, 1)) * 100)
    label = "COMPLIANT" if overall_rate >= 90 else "AT_RISK" if overall_rate >= 70 else "BREACHED"
    detail = {
        "total_items":     total_items,
        "total_analysts":  total_analysts,
        "overall_rate_pct": round(overall_rate, 1),
        "tier_sla":        tier_sla,
    }
    return round(min(overall_rate, 100.0), 1), label, detail


def _score_anomaly_rate(telemetry: Dict[str, Any]) -> Tuple[float, str, Dict]:
    """Score anomaly health 0-100 (100=clean, 0=high anomaly density)."""
    events = telemetry.get("events", [])
    total  = len(events)
    if total == 0:
        return 100.0, "NO_EVENTS", {}

    high_sev = sum(1 for e in events if e.get("severity") in ("CRITICAL", "HIGH"))
    rate = high_sev / total
    score = max(0.0, 100.0 - (rate * 100))

    label = "CLEAN" if score >= 90 else "ELEVATED" if score >= 70 else "ANOMALOUS"
    detail = {
        "total_events":       total,
        "high_sev_events":    high_sev,
        "anomaly_rate_pct":   round(rate * 100, 1),
        "severity_breakdown": telemetry.get("severity_counts", {}),
    }
    return round(score, 1), label, detail


def build_platform_health_dashboard(ctx: Dict[str, Any], telemetry: Dict[str, Any]) -> Dict[str, Any]:
    """
    Build unified platform health dashboard with composite health score.
    Each subsystem scored 0-100, weighted composite produces overall score.
    """
    pe_score, pe_label, pe_detail = _score_pipeline_execution(ctx)
    it_score, it_label, it_detail = _score_intel_trust(ctx)
    tc_score, tc_label, tc_detail = _score_threat_coverage(ctx)
    sl_score, sl_label, sl_detail = _score_sla_compliance(ctx)
    an_score, an_label, an_detail = _score_anomaly_rate(telemetry)

    # Weighted composite
    composite = (
        pe_score * _HEALTH_WEIGHTS["pipeline_execution"] +
        it_score * _HEALTH_WEIGHTS["intel_trust"] +
        tc_score * _HEALTH_WEIGHTS["threat_coverage"] +
        sl_score * _HEALTH_WEIGHTS["sla_compliance"] +
        an_score * _HEALTH_WEIGHTS["anomaly_rate"]
    )
    composite = round(composite, 1)

    overall_label = (
        "HEALTHY"    if composite >= 80 else
        "DEGRADED"   if composite >= 60 else
        "UNHEALTHY"  if composite >= 40 else
        "CRITICAL"
    )

    # Operational grade
    grade = (
        "A" if composite >= 90 else
        "B" if composite >= 80 else
        "C" if composite >= 70 else
        "D" if composite >= 60 else
        "F"
    )

    subsystems = {
        "pipeline_execution": {
            "score":  pe_score,
            "label":  pe_label,
            "weight": _HEALTH_WEIGHTS["pipeline_execution"],
            "weighted_contribution": round(pe_score * _HEALTH_WEIGHTS["pipeline_execution"], 2),
            "detail": pe_detail,
        },
        "intel_trust": {
            "score":  it_score,
            "label":  it_label,
            "weight": _HEALTH_WEIGHTS["intel_trust"],
            "weighted_contribution": round(it_score * _HEALTH_WEIGHTS["intel_trust"], 2),
            "detail": it_detail,
        },
        "threat_coverage": {
            "score":  tc_score,
            "label":  tc_label,
            "weight": _HEALTH_WEIGHTS["threat_coverage"],
            "weighted_contribution": round(tc_score * _HEALTH_WEIGHTS["threat_coverage"], 2),
            "detail": tc_detail,
        },
        "sla_compliance": {
            "score":  sl_score,
            "label":  sl_label,
            "weight": _HEALTH_WEIGHTS["sla_compliance"],
            "weighted_contribution": round(sl_score * _HEALTH_WEIGHTS["sla_compliance"], 2),
            "detail": sl_detail,
        },
        "anomaly_rate": {
            "score":  an_score,
            "label":  an_label,
            "weight": _HEALTH_WEIGHTS["anomaly_rate"],
            "weighted_contribution": round(an_score * _HEALTH_WEIGHTS["anomaly_rate"], 2),
            "detail": an_detail,
        },
    }

    # Identify weakest subsystem
    weakest = min(subsystems.items(), key=lambda x: x[1]["score"])

    # Priority recommendations based on scores
    recommendations = _build_health_recommendations(subsystems, ctx)

    log.info(
        "Platform health: composite=%.1f grade=%s label=%s",
        composite, grade, overall_label
    )

    return {
        "schema_version":    _SCHEMA,
        "engine":            _ENGINE,
        "version":           _VERSION,
        "generated_at":      _now_utc(),
        "platform_name":     "CYBERDUDEBIVASH AI Security Hub",
        "overall_health_score": composite,
        "overall_label":     overall_label,
        "operational_grade": grade,
        "weakest_subsystem": {
            "name":  weakest[0],
            "score": weakest[1]["score"],
            "label": weakest[1]["label"],
        },
        "subsystems":        subsystems,
        "recommendations":   recommendations,
        "health_weights":    _HEALTH_WEIGHTS,
    }


def _build_health_recommendations(subsystems: Dict, ctx: Dict) -> List[Dict]:
    """Generate prioritized recommendations based on health scores."""
    recs: List[Dict] = []

    it = subsystems.get("intel_trust", {})
    if it.get("score", 100) < 50:
        detail = it.get("detail", {})
        recs.append({
            "priority": "P0",
            "subsystem": "intel_trust",
            "action": "Run full enrichment pipeline — add CVSS, EPSS, and KEV cross-reference",
            "metric": f"Current avg trust: {detail.get('average_trust_score', 0):.1f}/100",
            "impact": "Increases publishable intel from {:.1f}% to target >25%".format(
                detail.get("publishable_pct", 0)
            ),
        })

    pe = subsystems.get("pipeline_execution", {})
    if pe.get("score", 100) < 80:
        detail = pe.get("detail", {})
        failed = detail.get("stages_total", 0) - detail.get("stages_passed", 0)
        if failed > 0:
            recs.append({
                "priority": "P1",
                "subsystem": "pipeline_execution",
                "action": f"Investigate and resolve {failed} failed pipeline stage(s)",
                "metric": f"Success rate: {detail.get('success_rate_pct', 0)}%",
                "impact": "Ensures complete intelligence corpus for SOC operations",
            })

    tc = subsystems.get("threat_coverage", {})
    ms = ctx.get("mssp_summary", {})
    kev_count = ms.get("kev_count", 0)
    if kev_count > 0 and tc.get("detail", {}).get("p0_items", 0) == 0:
        recs.append({
            "priority": "P0",
            "subsystem": "threat_coverage",
            "action": f"Escalate {kev_count} KEV-confirmed advisories to P0 SOC tier — update scoring with CVSS data",
            "metric": f"KEV count: {kev_count}, P0 items: 0",
            "impact": "Ensures critical exploitable vulnerabilities receive <4h response",
        })

    sl = subsystems.get("sla_compliance", {})
    if sl.get("score", 100) < 80:
        recs.append({
            "priority": "P1",
            "subsystem": "sla_compliance",
            "action": "Increase SOC analyst headcount or redistribute advisory load across tiers",
            "metric": f"Compliance rate: {sl.get('score', 0)}%",
            "impact": "Prevents SLA breach for high-priority advisories",
        })

    an = subsystems.get("anomaly_rate", {})
    if an.get("score", 100) < 70:
        recs.append({
            "priority": "P2",
            "subsystem": "anomaly_rate",
            "action": "Review and triage all CRITICAL/HIGH telemetry events — resolve root causes",
            "metric": f"Anomaly score: {an.get('score', 0)}",
            "impact": "Reduces noise and improves signal quality for SOC analysts",
        })

    return recs


# ---------------------------------------------------------------------------
# SLA Compliance Report
# ---------------------------------------------------------------------------
def build_sla_compliance_report(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detailed SLA compliance report per SOC tier.
    Models compliance as function of item count, analyst capacity, and SLA window.
    """
    sq    = ctx.get("soc_queue", {})
    items = sq.get("items", [])
    coord = ctx.get("coordinator", {})
    tier_bd = coord.get("tier_breakdown", {})
    aw    = ctx.get("analyst_wl", {})
    ts    = ctx.get("trust_summary", {})

    total_analysts = max(len(aw.get("analysts", [])), 1)
    items_per_analyst = len(items) / total_analysts if items else 0

    # Per-tier SLA analysis
    tier_analysis: Dict[str, Dict] = {}
    total_at_risk  = 0
    total_compliant = 0

    # Items by tier
    tier_items: Dict[str, List] = {}
    for item in items:
        tier = item.get("soc_tier", {})
        tier_key = _normalize_tier_key(tier.get("tier", "P4_monitor"))
        tier_items.setdefault(tier_key, []).append(item)

    for tier_key, sla_h in _SLA_WINDOWS_H.items():
        count      = tier_bd.get(tier_key, 0)
        tier_list  = tier_items.get(tier_key, [])
        sla_label  = _tier_key_to_label(tier_key)

        # Capacity: hours in SLA window × analysts / hours per advisory
        # Assume 1 analyst handles: P0→2h/item, P1→4h, P2→6h, P3→8h, P4→2h
        hours_per_item_map = {"P0_critical": 2, "P1_high": 4, "P2_medium": 6, "P3_low": 8, "P4_monitor": 2}
        h_per_item = hours_per_item_map.get(tier_key, 6)
        analyst_capacity = math.floor(sla_h * total_analysts / h_per_item)
        at_risk = max(0, count - analyst_capacity)
        compliant = max(0, count - at_risk)

        total_at_risk   += at_risk
        total_compliant += compliant

        sla_status = (
            "COMPLIANT"  if at_risk == 0 else
            "AT_RISK"    if at_risk <= count * 0.2 else
            "BREACHED"
        )

        # Average composite priority for this tier
        scores = [i.get("composite_priority", 0) for i in tier_list]
        avg_score = sum(scores) / len(scores) if scores else 0.0
        max_score = max(scores, default=0.0)

        tier_analysis[tier_key] = {
            "tier_label":          sla_label,
            "sla_window_hours":    sla_h,
            "item_count":          count,
            "analyst_capacity":    analyst_capacity,
            "compliant_estimate":  compliant,
            "at_risk_estimate":    at_risk,
            "sla_status":          sla_status,
            "avg_composite_score": round(avg_score, 1),
            "max_composite_score": round(max_score, 1),
            "hours_per_item":      h_per_item,
        }

    total_items  = len(items)
    overall_rate = (total_compliant / max(total_items, 1)) * 100
    overall_status = (
        "COMPLIANT"  if overall_rate >= 90 else
        "AT_RISK"    if overall_rate >= 70 else
        "BREACHED"
    )

    # MTTD / MTTR estimates (modeled)
    mttd_h = _estimate_mttd(ctx)
    mttr_h = _estimate_mttr(ctx, tier_bd)

    return {
        "schema_version":    _SCHEMA,
        "engine":            _ENGINE,
        "version":           _VERSION,
        "generated_at":      _now_utc(),
        "sla_windows":       _SLA_WINDOWS_H,
        "total_analysts":    total_analysts,
        "total_advisories":  total_items,
        "items_per_analyst": round(items_per_analyst, 1),
        "overall_sla_status": overall_status,
        "overall_compliance_rate_pct": round(overall_rate, 1),
        "total_compliant":   total_compliant,
        "total_at_risk":     total_at_risk,
        "mttd_hours":        mttd_h,
        "mttr_hours":        mttr_h,
        "tier_analysis":     tier_analysis,
        "sla_recommendations": _build_sla_recommendations(tier_analysis, total_analysts),
    }


def _normalize_tier_key(tier_str: str) -> str:
    """Normalize tier strings like 'P0-CRITICAL' → 'P0_critical'."""
    mapping = {
        "P0-CRITICAL": "P0_critical", "P0_CRITICAL": "P0_critical", "P0": "P0_critical",
        "P1-HIGH":     "P1_high",     "P1_HIGH":     "P1_high",     "P1": "P1_high",
        "P2-MEDIUM":   "P2_medium",   "P2_MEDIUM":   "P2_medium",   "P2": "P2_medium",
        "P3-LOW":      "P3_low",      "P3_LOW":      "P3_low",      "P3": "P3_low",
        "P4-MONITOR":  "P4_monitor",  "P4_MONITOR":  "P4_monitor",  "P4": "P4_monitor",
    }
    return mapping.get(tier_str, "P4_monitor")


def _tier_key_to_label(key: str) -> str:
    return {
        "P0_critical": "P0 — CRITICAL (< 4h)",
        "P1_high":     "P1 — HIGH (< 24h)",
        "P2_medium":   "P2 — MEDIUM (< 72h)",
        "P3_low":      "P3 — LOW (< 30d)",
        "P4_monitor":  "P4 — MONITOR (< 90d)",
    }.get(key, key)


def _estimate_mttd(ctx: Dict[str, Any]) -> float:
    """
    Estimate Mean Time To Detect (hours) based on pipeline cadence and trust quality.
    Lower publishable % → longer MTTD due to more manual triage.
    """
    ts = ctx.get("trust_summary", {})
    publishable = ts.get("publishable_pct", 0.0)
    coord_elapsed = ctx.get("coordinator", {}).get("total_elapsed_s", 0.0)

    # Base MTTD: pipeline runs every N hours (assume 4h cadence)
    pipeline_cadence_h = 4.0
    # Manual triage overhead: inversely proportional to publishable %
    triage_overhead_h  = max(0, (100 - publishable) / 100 * 8)   # up to 8h overhead
    pipeline_time_h    = coord_elapsed / 3600

    return round(pipeline_cadence_h + triage_overhead_h + pipeline_time_h, 2)


def _estimate_mttr(ctx: Dict[str, Any], tier_bd: Dict[str, int]) -> float:
    """
    Estimate Mean Time To Respond (hours) weighted by tier distribution.
    """
    weights = {
        "P0_critical": (_SLA_WINDOWS_H["P0_critical"],  0.5),
        "P1_high":     (_SLA_WINDOWS_H["P1_high"],      0.35),
        "P2_medium":   (_SLA_WINDOWS_H["P2_medium"],    0.25),
        "P3_low":      (_SLA_WINDOWS_H["P3_low"],       0.1),
        "P4_monitor":  (_SLA_WINDOWS_H["P4_monitor"],   0.05),
    }
    total = sum(tier_bd.values()) or 1
    weighted_sum = 0.0
    for tier_key, count in tier_bd.items():
        if tier_key in weights:
            target_h, completion_factor = weights[tier_key]
            weighted_sum += (count / total) * target_h * completion_factor

    return round(max(1.0, weighted_sum), 2)


def _build_sla_recommendations(tier_analysis: Dict, analysts: int) -> List[str]:
    recs = []
    for tk, ta in tier_analysis.items():
        if ta["sla_status"] == "BREACHED":
            recs.append(
                f"[{tk}] SLA BREACHED — {ta['at_risk_estimate']} items at risk. "
                f"Add analysts or reduce advisory scope."
            )
        elif ta["sla_status"] == "AT_RISK":
            recs.append(
                f"[{tk}] SLA AT_RISK — {ta['at_risk_estimate']} items may miss SLA. "
                f"Prioritize by composite score."
            )
    if not recs:
        recs.append("All tiers within SLA capacity. Continue monitoring.")
    return recs


# ---------------------------------------------------------------------------
# Pipeline Performance Metrics
# ---------------------------------------------------------------------------
def build_pipeline_performance_metrics(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """
    Detailed per-stage performance breakdown + throughput analysis.
    """
    coord = ctx.get("coordinator", {})
    stage_results = coord.get("stage_results", [])
    advisory_count = coord.get("advisory_count", 0)
    total_elapsed  = coord.get("total_elapsed_s", 0.0)

    stage_metrics: List[Dict] = []
    bottleneck_stage = None
    bottleneck_elapsed = 0.0

    for stage in stage_results:
        name    = stage.get("stage", "unknown")
        elapsed = stage.get("elapsed_s", 0.0)
        status  = stage.get("status", "unknown")
        metrics = stage.get("metrics", {})
        outputs = stage.get("outputs", [])

        # Throughput for stages that process items
        items_proc = metrics.get("items_processed", 0) or metrics.get("items_scored", 0) or 0
        throughput = round(items_proc / max(elapsed, 0.001), 1) if items_proc > 0 else None

        # Percentage of total pipeline time
        pct_of_total = round((elapsed / max(total_elapsed, 0.001)) * 100, 1)

        if elapsed > bottleneck_elapsed:
            bottleneck_elapsed = elapsed
            bottleneck_stage   = name

        stage_metrics.append({
            "stage":           name,
            "status":          status,
            "elapsed_s":       elapsed,
            "pct_of_pipeline": pct_of_total,
            "items_processed": items_proc,
            "throughput_per_s": throughput,
            "output_count":    len(outputs),
            "error":           stage.get("error"),
            "key_metrics":     {k: v for k, v in metrics.items()
                                if k not in ("items_processed", "files_written", "errors")},
        })

    # Platform-level throughput
    platform_throughput = round(advisory_count / max(total_elapsed, 0.001), 1)

    # Engine summary metrics
    engine_perf: List[Dict] = []
    for eng_key, label in [
        ("trust_summary",  "intel_trust_governance"),
        ("mssp_summary",   "mssp_executive_engine"),
    ]:
        summary = ctx.get(eng_key, {})
        if summary:
            elapsed_e = summary.get("elapsed_seconds", 0.0)
            items_e   = summary.get("items_assessed") or summary.get("items_analyzed") or 0
            tput_e    = round(items_e / max(elapsed_e, 0.001), 1) if items_e else None
            engine_perf.append({
                "engine":           label,
                "status":           summary.get("status", "unknown"),
                "elapsed_s":        elapsed_e,
                "items_processed":  items_e,
                "throughput_per_s": tput_e,
                "files_written":    summary.get("files_written", 0),
                "errors":           len(summary.get("errors", [])),
            })

    return {
        "schema_version":       _SCHEMA,
        "engine":               _ENGINE,
        "version":              _VERSION,
        "generated_at":         _now_utc(),
        "pipeline_summary": {
            "total_elapsed_s":       total_elapsed,
            "advisory_count":        advisory_count,
            "platform_throughput_per_s": platform_throughput,
            "stage_count":           len(stage_metrics),
            "stages_passed":         sum(1 for s in stage_metrics if s["status"] == "success"),
            "stages_failed":         sum(1 for s in stage_metrics if s["status"] != "success"),
            "bottleneck_stage":      bottleneck_stage,
            "bottleneck_elapsed_s":  bottleneck_elapsed,
        },
        "stage_metrics":        stage_metrics,
        "engine_performance":   engine_perf,
        "performance_targets": {
            "pipeline_latency_warn_s":     _ANOMALY_THRESHOLDS["pipeline_latency_warn_s"],
            "pipeline_latency_critical_s": _ANOMALY_THRESHOLDS["pipeline_latency_critical_s"],
            "target_throughput_per_s":     50.0,
        },
    }


# ---------------------------------------------------------------------------
# Anomaly Detection
# ---------------------------------------------------------------------------
def build_anomaly_detection_report(
    ctx: Dict[str, Any],
    telemetry: Dict[str, Any],
    health: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Detect platform anomalies across all subsystems.
    Produces a prioritized anomaly list with root cause analysis and remediation.
    """
    anomalies: List[Dict] = []
    anomaly_id = 0

    def _add(sev: str, category: str, title: str, evidence: str,
             root_cause: str, remediation: str, affected: str) -> None:
        nonlocal anomaly_id
        anomaly_id += 1
        anomalies.append({
            "anomaly_id":    f"ANOM-{anomaly_id:04d}",
            "severity":      sev,
            "category":      category,
            "title":         title,
            "evidence":      evidence,
            "root_cause":    root_cause,
            "remediation":   remediation,
            "affected_subsystem": affected,
            "detected_at":   _now_utc(),
        })

    # --- Trust anomalies ---
    ts  = ctx.get("trust_summary", {})
    avg_trust   = ts.get("average_trust_score", 0.0)
    publishable = ts.get("publishable_pct", 0.0)
    violations  = ts.get("violation_count", 0)
    items_total = ts.get("items_assessed", 1)

    if avg_trust < _ANOMALY_THRESHOLDS["trust_score_critical_low"]:
        _add(
            sev="CRITICAL", category="trust_collapse",
            title=f"Corpus trust score critically low: {avg_trust:.1f}/100",
            evidence=f"average_trust_score={avg_trust:.1f}, threshold={_ANOMALY_THRESHOLDS['trust_score_critical_low']}",
            root_cause="Majority of advisories lack CVSS scoring, EPSS probability data, or verified IOC attribution. Enrichment pipeline may be failing or data source quality is degraded.",
            remediation="1. Run enrich_cvss_epss_batch.py against apex_v2_manifest.json. 2. Validate NVD API key and rate limits. 3. Re-run intel_trust_governance.py after enrichment.",
            affected="intel_trust_governance",
        )
    elif avg_trust < _ANOMALY_THRESHOLDS["trust_score_warn_low"]:
        _add(
            sev="HIGH", category="trust_degraded",
            title=f"Corpus trust score below threshold: {avg_trust:.1f}/100",
            evidence=f"average_trust_score={avg_trust:.1f}, target ≥ 50",
            root_cause="Partial enrichment — CVSS and EPSS data present for subset of advisories only.",
            remediation="Prioritize CVSS/EPSS backfill for KEV-confirmed and HIGH severity advisories.",
            affected="intel_trust_governance",
        )

    if publishable < _ANOMALY_THRESHOLDS["publishable_pct_critical_low"]:
        _add(
            sev="CRITICAL", category="publishable_pct_critical",
            title=f"Publishable intel critically low: {publishable:.1f}%",
            evidence=f"publishable_pct={publishable:.1f}%, threshold={_ANOMALY_THRESHOLDS['publishable_pct_critical_low']}%",
            root_cause="Enrichment gap: advisories missing CVSS ≥ 7.0, verified IOCs, and TTP attribution fail trust certification. Source data quality below enterprise publishing threshold.",
            remediation="1. Enable apex_intelligence_upgrade.py for all HIGH/CRITICAL advisories. 2. Add NVD CVSS enrichment pass. 3. Validate IOC extraction removing source-domain contamination.",
            affected="intel_trust_governance",
        )

    violation_rate_pct = (violations / max(items_total, 1)) * 100
    if violation_rate_pct > _ANOMALY_THRESHOLDS["violation_rate_high"]:
        _add(
            sev="HIGH", category="ioc_contamination",
            title=f"IOC trust violation rate elevated: {violation_rate_pct:.1f}%",
            evidence=f"{violations} violations in {items_total} advisories",
            root_cause="Source URL domains appearing as actionable IOCs. _SOURCE_DOMAINS suppression list may be incomplete, or new news/vendor domains added without updating filter.",
            remediation="1. Audit apex_intelligence_upgrade.py _SOURCE_DOMAINS list. 2. Run ioc_quality_hardener.py against current manifest. 3. Re-run trust governance after IOC cleanup.",
            affected="intel_trust_governance",
        )

    # --- Pipeline anomalies ---
    coord = ctx.get("coordinator", {})
    stage_results = coord.get("stage_results", [])
    failed_stages  = [s for s in stage_results if s.get("status") != "success"]
    total_elapsed  = coord.get("total_elapsed_s", 0.0)

    for stage in failed_stages:
        _add(
            sev="HIGH", category="pipeline_stage_failure",
            title=f"Pipeline stage failure: {stage['stage']}",
            evidence=f"status={stage.get('status')}, error={stage.get('error')}",
            root_cause=f"Stage [{stage['stage']}] encountered an exception during execution. This may indicate missing input files, import errors, or data schema mismatches.",
            remediation=f"1. Check logs for {stage['stage']}. 2. Validate input files exist. 3. Re-run ocios_coordinator.py with --stage {stage['stage']} in isolation.",
            affected="ocios_coordinator",
        )

    if total_elapsed >= _ANOMALY_THRESHOLDS["pipeline_latency_critical_s"]:
        _add(
            sev="CRITICAL", category="pipeline_latency",
            title=f"Pipeline latency critical: {total_elapsed:.1f}s",
            evidence=f"total_elapsed={total_elapsed:.1f}s, threshold={_ANOMALY_THRESHOLDS['pipeline_latency_critical_s']}s",
            root_cause="Pipeline execution exceeds acceptable latency. Possible causes: large manifest, network I/O during enrichment, or compute resource contention.",
            remediation="1. Profile bottleneck stage. 2. Enable parallel processing for independent stages. 3. Review manifest size and chunking strategy.",
            affected="ocios_coordinator",
        )

    # --- Threat coverage anomalies ---
    ms = ctx.get("mssp_summary", {})
    kev_count = ms.get("kev_count", 0)
    tier_bd   = coord.get("tier_breakdown", {})
    p0_count  = tier_bd.get("P0_critical", 0)
    p1_count  = tier_bd.get("P1_high", 0)

    if kev_count > 0 and (p0_count + p1_count) == 0:
        _add(
            sev="CRITICAL", category="kev_escalation_gap",
            title=f"KEV advisories not escalated to P0/P1: {kev_count} KEV items at P3/P4",
            evidence=f"kev_count={kev_count}, P0={p0_count}, P1={p1_count}",
            root_cause="SOC scoring engine doesn't have CVSS scores for KEV advisories (from base feed_manifest.json). KEV items exist in apex_v2_manifest.json but coordinator runs against feed_manifest.json which lacks enrichment fields.",
            remediation="1. Run ocios_coordinator.py with --manifest data/apex_v2_manifest.json. 2. Ensure feed_manifest.json enrichment pass completes before OCIOS run. 3. Verify kev_present field propagation in enrichment pipeline.",
            affected="ocios_soc_prioritization_engine",
        )

    # --- Financial anomalies ---
    fm = ctx.get("financial_model", {})
    ale = fm.get("total_exposure_usd", 0) or fm.get("annual_loss_expectancy_usd", 0)
    risk_posture = ms.get("risk_posture", "UNKNOWN")

    if risk_posture == "CRITICAL":
        _add(
            sev="CRITICAL", category="risk_posture_critical",
            title=f"Enterprise risk posture: CRITICAL | ALE: ${ale:,.0f}",
            evidence=f"risk_posture={risk_posture}, kev_count={kev_count}, ale_usd={ale}",
            root_cause="Portfolio contains actively exploitable KEV vulnerabilities with high financial exposure. Ransomware and APT TTPs present across corpus.",
            remediation="1. Immediately patch all KEV-confirmed CVEs. 2. Activate SOC incident response for top P0/P1 items. 3. Validate backup and DR posture for ransomware-linked advisories.",
            affected="mssp_executive_engine",
        )

    # --- Health score anomalies ---
    overall_health = health.get("overall_health_score", 100.0)
    weakest = health.get("weakest_subsystem", {})
    if overall_health < 60.0:
        _add(
            sev="HIGH", category="platform_health_degraded",
            title=f"Platform health score degraded: {overall_health}/100 (grade {health.get('operational_grade', 'F')})",
            evidence=f"overall_health={overall_health}, weakest={weakest.get('name')} at {weakest.get('score')}/100",
            root_cause=f"Multiple subsystems operating below threshold. Weakest subsystem: [{weakest.get('name')}] at {weakest.get('score')}/100.",
            remediation="Follow recommendations in platform_health_dashboard.json. Prioritize P0/P1 actions first.",
            affected="enterprise_observability",
        )

    # Sort by severity
    sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
    anomalies.sort(key=lambda a: sev_order.get(a["severity"], 9))

    sev_counts: Dict[str, int] = {}
    for a in anomalies:
        sev_counts[a["severity"]] = sev_counts.get(a["severity"], 0) + 1

    overall_anomaly_status = (
        "CRITICAL"  if sev_counts.get("CRITICAL", 0) > 0 else
        "HIGH"      if sev_counts.get("HIGH", 0) > 0 else
        "MEDIUM"    if sev_counts.get("MEDIUM", 0) > 0 else
        "CLEAN"
    )

    log.info("Anomaly detection: %d anomalies, status=%s", len(anomalies), overall_anomaly_status)

    return {
        "schema_version":       _SCHEMA,
        "engine":               _ENGINE,
        "version":              _VERSION,
        "generated_at":         _now_utc(),
        "total_anomalies":      len(anomalies),
        "overall_status":       overall_anomaly_status,
        "severity_counts":      sev_counts,
        "anomalies":            anomalies,
        "detection_thresholds": _ANOMALY_THRESHOLDS,
    }


# ---------------------------------------------------------------------------
# Observability Manifest
# ---------------------------------------------------------------------------
def build_observability_manifest(
    ctx: Dict[str, Any],
    telemetry: Dict[str, Any],
    health: Dict[str, Any],
    sla: Dict[str, Any],
    perf: Dict[str, Any],
    anomalies: Dict[str, Any],
    elapsed_s: float,
) -> Dict[str, Any]:
    """Master observability manifest — summarizes all observability outputs."""

    ts = ctx.get("trust_summary", {})
    ms = ctx.get("mssp_summary", {})

    return {
        "schema_version": _SCHEMA,
        "engine":         _ENGINE,
        "version":        _VERSION,
        "generated_at":   _now_utc(),
        "status":         "success",
        "elapsed_seconds": round(elapsed_s, 3),

        "platform_summary": {
            "name":                 "CYBERDUDEBIVASH AI Security Hub",
            "overall_health_score": health.get("overall_health_score"),
            "operational_grade":    health.get("operational_grade"),
            "overall_label":        health.get("overall_label"),
            "risk_posture":         ms.get("risk_posture", "UNKNOWN"),
            "trust_posture":        ctx.get("platform_trust", {}).get("platform_trust_posture", "UNKNOWN"),
            "kev_count":            ms.get("kev_count", 0),
            "advisory_count":       ctx.get("coordinator", {}).get("advisory_count", 0),
        },

        "telemetry": {
            "event_count":     telemetry.get("event_count", 0),
            "severity_counts": telemetry.get("severity_counts", {}),
        },

        "anomaly_detection": {
            "total_anomalies": anomalies.get("total_anomalies", 0),
            "overall_status":  anomalies.get("overall_status", "UNKNOWN"),
            "severity_counts": anomalies.get("severity_counts", {}),
        },

        "sla_compliance": {
            "overall_status":        sla.get("overall_sla_status", "UNKNOWN"),
            "compliance_rate_pct":   sla.get("overall_compliance_rate_pct", 0),
            "total_at_risk":         sla.get("total_at_risk", 0),
            "mttd_hours":            sla.get("mttd_hours", 0),
            "mttr_hours":            sla.get("mttr_hours", 0),
        },

        "pipeline_performance": {
            "total_elapsed_s":          perf.get("pipeline_summary", {}).get("total_elapsed_s", 0),
            "advisory_count":           perf.get("pipeline_summary", {}).get("advisory_count", 0),
            "throughput_per_s":         perf.get("pipeline_summary", {}).get("platform_throughput_per_s", 0),
            "stages_passed":            perf.get("pipeline_summary", {}).get("stages_passed", 0),
            "stages_failed":            perf.get("pipeline_summary", {}).get("stages_failed", 0),
            "bottleneck_stage":         perf.get("pipeline_summary", {}).get("bottleneck_stage"),
        },

        "outputs": [
            "data/ocios/observability_telemetry.json",
            "data/ocios/platform_health_dashboard.json",
            "data/ocios/sla_compliance_report.json",
            "data/ocios/pipeline_performance_metrics.json",
            "data/ocios/anomaly_detection_report.json",
            "data/ocios/observability_manifest.json",
        ],
    }


# ---------------------------------------------------------------------------
# Main Entry Point
# ---------------------------------------------------------------------------
def run_observability_engine(
    repo_root: Optional[Path] = None,
    run_id: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Execute full observability pipeline.

    Returns:
        Summary dict with status, counts, elapsed.
    """
    t_start = time.time()
    if repo_root is None:
        repo_root = _resolve_repo_root()
    if run_id is None:
        run_id = datetime.now(timezone.utc).strftime("obs_%Y%m%d_%H%M%S")

    log.info("=" * 70)
    log.info("CYBERDUDEBIVASH Enterprise Observability Engine v%s", _VERSION)
    log.info("Run ID: %s | Repo: %s", run_id, repo_root)
    log.info("=" * 70)

    ocios_out = repo_root / "data" / "ocios"
    errors: List[str] = []

    # ── Stage 1: Load all engine data ──────────────────────────────────────
    log.info("[Stage 1/6] Loading engine data...")
    ctx = load_all_engine_data(repo_root)

    # ── Stage 2: Build telemetry event stream ──────────────────────────────
    log.info("[Stage 2/6] Building telemetry event stream...")
    try:
        telemetry = build_telemetry_stream(ctx)
        _atomic_write(ocios_out / "observability_telemetry.json", telemetry)
        log.info("  ✓ Telemetry: %d events", telemetry["event_count"])
    except Exception as exc:
        log.error("Telemetry build failed: %s", exc)
        errors.append(f"telemetry: {exc}")
        telemetry = {"events": [], "event_count": 0, "severity_counts": {}}

    # ── Stage 3: Build platform health dashboard ───────────────────────────
    log.info("[Stage 3/6] Scoring platform health...")
    try:
        health = build_platform_health_dashboard(ctx, telemetry)
        _atomic_write(ocios_out / "platform_health_dashboard.json", health)
        log.info(
            "  ✓ Health: score=%.1f grade=%s label=%s",
            health["overall_health_score"],
            health["operational_grade"],
            health["overall_label"],
        )
    except Exception as exc:
        log.error("Health dashboard failed: %s", exc)
        errors.append(f"health: {exc}")
        health = {"overall_health_score": 0, "operational_grade": "F", "overall_label": "CRITICAL"}

    # ── Stage 4: SLA compliance report ────────────────────────────────────
    log.info("[Stage 4/6] Computing SLA compliance...")
    try:
        sla = build_sla_compliance_report(ctx)
        _atomic_write(ocios_out / "sla_compliance_report.json", sla)
        log.info(
            "  ✓ SLA: status=%s compliance=%.1f%% MTTD=%.1fh MTTR=%.1fh",
            sla["overall_sla_status"],
            sla["overall_compliance_rate_pct"],
            sla["mttd_hours"],
            sla["mttr_hours"],
        )
    except Exception as exc:
        log.error("SLA report failed: %s", exc)
        errors.append(f"sla: {exc}")
        sla = {"overall_sla_status": "UNKNOWN", "overall_compliance_rate_pct": 0,
               "mttd_hours": 0, "mttr_hours": 0, "total_at_risk": 0}

    # ── Stage 5: Pipeline performance metrics ─────────────────────────────
    log.info("[Stage 5/6] Generating performance metrics...")
    try:
        perf = build_pipeline_performance_metrics(ctx)
        _atomic_write(ocios_out / "pipeline_performance_metrics.json", perf)
        ps = perf["pipeline_summary"]
        log.info(
            "  ✓ Performance: elapsed=%.2fs throughput=%.1f/s bottleneck=%s",
            ps["total_elapsed_s"],
            ps["platform_throughput_per_s"],
            ps["bottleneck_stage"],
        )
    except Exception as exc:
        log.error("Performance metrics failed: %s", exc)
        errors.append(f"performance: {exc}")
        perf = {"pipeline_summary": {}}

    # ── Stage 6: Anomaly detection ────────────────────────────────────────
    log.info("[Stage 6/6] Running anomaly detection...")
    try:
        anomalies = build_anomaly_detection_report(ctx, telemetry, health)
        _atomic_write(ocios_out / "anomaly_detection_report.json", anomalies)
        log.info(
            "  ✓ Anomalies: %d detected, status=%s",
            anomalies["total_anomalies"],
            anomalies["overall_status"],
        )
    except Exception as exc:
        log.error("Anomaly detection failed: %s", exc)
        errors.append(f"anomalies: {exc}")
        anomalies = {"total_anomalies": 0, "overall_status": "UNKNOWN", "severity_counts": {}}

    # ── Write manifest ─────────────────────────────────────────────────────
    elapsed_s = time.time() - t_start
    manifest  = build_observability_manifest(ctx, telemetry, health, sla, perf, anomalies, elapsed_s)
    _atomic_write(ocios_out / "observability_manifest.json", manifest)

    summary = {
        "engine":            _ENGINE,
        "version":           _VERSION,
        "run_id":            run_id,
        "status":            "success" if not errors else "partial",
        "errors":            errors,
        "elapsed_seconds":   round(elapsed_s, 3),
        "files_written":     6,
        "overall_health_score": health.get("overall_health_score", 0),
        "operational_grade":    health.get("operational_grade", "F"),
        "overall_label":        health.get("overall_label", "UNKNOWN"),
        "total_anomalies":      anomalies.get("total_anomalies", 0),
        "anomaly_status":       anomalies.get("overall_status", "UNKNOWN"),
        "sla_status":           sla.get("overall_sla_status", "UNKNOWN"),
        "telemetry_events":     telemetry.get("event_count", 0),
    }

    log.info("=" * 70)
    log.info("OBSERVABILITY ENGINE COMPLETE")
    log.info("  Status:        %s", summary["status"])
    log.info("  Health Score:  %.1f / 100 (grade %s)", summary["overall_health_score"], summary["operational_grade"])
    log.info("  Anomalies:     %d (%s)", summary["total_anomalies"], summary["anomaly_status"])
    log.info("  SLA Status:    %s", summary["sla_status"])
    log.info("  Events:        %d telemetry events", summary["telemetry_events"])
    log.info("  Files Written: %d", summary["files_written"])
    log.info("  Elapsed:       %.3fs", summary["elapsed_seconds"])
    log.info("=" * 70)

    return summary


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH Enterprise Observability Engine"
    )
    parser.add_argument(
        "--repo",
        type=Path,
        default=None,
        help="Path to repo root (auto-detected if omitted)",
    )
    parser.add_argument(
        "--run-id",
        type=str,
        default=None,
        help="Run identifier (auto-generated if omitted)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output summary as JSON to stdout",
    )
    args = parser.parse_args()

    result = run_observability_engine(
        repo_root=args.repo,
        run_id=args.run_id,
    )

    if args.json:
        print(json.dumps(result, indent=2))
    else:
        print(f"\n{'='*60}")
        print(f"  Platform Health : {result['overall_health_score']}/100 (Grade {result['operational_grade']})")
        print(f"  Status          : {result['overall_label']}")
        print(f"  Anomalies       : {result['total_anomalies']} ({result['anomaly_status']})")
        print(f"  SLA             : {result['sla_status']}")
        print(f"  Telemetry Events: {result['telemetry_events']}")
        print(f"  Files Written   : {result['files_written']}")
        print(f"  Elapsed         : {result['elapsed_seconds']:.3f}s")
        print("=" * 60)
        sys.exit(0 if result["status"] == "success" else 1)
