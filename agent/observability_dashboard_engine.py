# =============================================================================
# CYBERDUDEBIVASH® SENTINEL APEX
# agent/observability_dashboard_engine.py
# PHASE 9 — ENTERPRISE OBSERVABILITY DASHBOARDS ENGINE v1.0
# Zero-regression | Deterministic | Fully auditable | Non-blocking
# =============================================================================

"""
Enterprise Observability Dashboards Engine — Phase 9 of Enterprise Observability Layer.

Aggregates all 8 observability modules into a unified dashboard data payload:
  - Reads all observability reports from data/observability/
  - Computes an OMNIGOD OBSERVABILITY SCORE (0-100) across all dimensions
  - Produces data/observability/dashboard_payload.json for frontend rendering
  - Produces data/observability/dashboard_summary.json for quick status
  - Produces an HTML dashboard at data/observability/dashboard.html

Dashboard panels:
  1. Graph Integrity Score
  2. Reproducibility Rate
  3. Scoring Drift Status
  4. Enrichment Health
  5. IOC Quality Score
  6. ATT&CK Coverage Score
  7. Actor Clustering Health
  8. FP Risk Score
  9. Omnigod Observability Score (composite)
 10. Pipeline run timeline (from telemetry JSONL files)

Never raises — all errors caught and surfaced in dashboard.
"""

from __future__ import annotations

import hashlib
import json
import logging
import time
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.obs_dashboard")

# ── PATHS ────────────────────────────────────────────────────────────────────
BASE_DIR   = Path(__file__).resolve().parent.parent
DATA_DIR   = BASE_DIR / "data"
OBS_DIR    = DATA_DIR / "observability"
DASH_PAYLOAD_PATH = OBS_DIR / "dashboard_payload.json"
DASH_SUMMARY_PATH = OBS_DIR / "dashboard_summary.json"
DASH_HTML_PATH    = OBS_DIR / "dashboard.html"

# Report paths from each observability engine
GRAPH_REPORT_PATH   = OBS_DIR / "graph_integrity_report.json"
REPRO_REPORT_PATH   = OBS_DIR / "reproducibility_report.json"
DRIFT_REPORT_PATH   = OBS_DIR / "scoring_drift_report.json"
ENRICH_REPORT_PATH  = OBS_DIR / "enrichment_observability_report.json"
IOC_REPORT_PATH     = OBS_DIR / "ioc_quality_report.json"
ATTCK_REPORT_PATH   = OBS_DIR / "attck_coverage_report.json"
ACTOR_REPORT_PATH   = OBS_DIR / "actor_clustering_report.json"
FP_REPORT_PATH      = OBS_DIR / "fp_observability_report.json"

# Telemetry JSONL paths
TELEM_FILES = {
    "graph_integrity":   OBS_DIR / "graph_integrity_telemetry.jsonl",
    "reproducibility":   OBS_DIR / "reproducibility_telemetry.jsonl",
    "scoring_drift":     OBS_DIR / "scoring_drift_telemetry.jsonl",
    "enrichment":        OBS_DIR / "enrichment_observability_telemetry.jsonl",
    "ioc_quality":       OBS_DIR / "ioc_quality_telemetry.jsonl",
    "attck_coverage":    OBS_DIR / "attck_coverage_telemetry.jsonl",
    "actor_clustering":  OBS_DIR / "actor_clustering_telemetry.jsonl",
    "fp_observability":  OBS_DIR / "fp_observability_telemetry.jsonl",
}

# Dimension weights for Omnigod Observability Score
OMNIGOD_WEIGHTS = {
    "graph_integrity":   15.0,
    "reproducibility":   15.0,
    "scoring_drift":     12.0,
    "enrichment":        13.0,
    "ioc_quality":       12.0,
    "attck_coverage":    12.0,
    "actor_clustering":  11.0,
    "fp_risk":           10.0,
}
assert abs(sum(OMNIGOD_WEIGHTS.values()) - 100.0) < 0.01, "Weights must sum to 100"


# ── DATA STRUCTURES ───────────────────────────────────────────────────────────
@dataclass
class PanelData:
    panel_id: str
    title: str
    score: float            # 0–100
    tier: str
    primary_metric: str
    primary_value: Any
    secondary_metrics: Dict[str, Any] = field(default_factory=dict)
    status: str = "ok"      # ok | stale | no_data
    generated_at: Optional[str] = None

@dataclass
class OmnigodScore:
    score: float
    tier: str
    dimension_scores: Dict[str, float]
    dimension_weights: Dict[str, float]
    computed_at: str

@dataclass
class DashboardPayload:
    dashboard_id: str
    generated_at: str
    omnigod_score: OmnigodScore
    panels: List[PanelData]
    telemetry_history: Dict[str, List[Dict]]
    alert_count: int
    critical_alerts: List[str]
    pipeline_health: str
    duration_ms: float = 0.0


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()

def _short_id(s: str) -> str:
    return hashlib.md5(s.encode(), usedforsecurity=False).hexdigest()[:12]

def _atomic_write(path: Path, data: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.replace(path)

def _load_json(path: Path) -> Any:
    if not path.exists():
        return {}
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:
        return {}

def _load_jsonl_tail(path: Path, n: int = 20) -> List[Dict]:
    if not path.exists():
        return []
    lines: List[Dict] = []
    try:
        for line in path.read_text(encoding="utf-8").strip().splitlines()[-n:]:
            try:
                lines.append(json.loads(line))
            except Exception:
                pass
    except Exception:
        pass
    return lines

def _tier_to_score(tier: str, invert: bool = False) -> float:
    """Convert string tier to numeric score. invert=True for risk tiers (low=good)."""
    fwd = {
        "EXCELLENT": 95.0, "GOOD": 80.0, "ACCEPTABLE": 65.0,
        "POOR": 40.0, "DEGRADED": 30.0, "CRITICAL": 10.0,
        "FAILING": 5.0, "NONE": 100.0,
    }
    inv = {
        "LOW": 95.0, "MODERATE": 80.0, "ELEVATED": 60.0,
        "HIGH": 30.0, "CRITICAL": 10.0,
    }
    mapping = inv if invert else fwd
    return mapping.get(tier, 50.0)


# ── PANEL BUILDERS ───────────────────────────────────────────────────────────
def _build_graph_panel() -> Tuple[PanelData, float]:
    r = _load_json(GRAPH_REPORT_PATH)
    if not r:
        return PanelData("graph_integrity", "Graph Integrity", 50.0, "UNKNOWN",
                         "score", "N/A", status="no_data"), 50.0
    score = float(r.get("overall_integrity_score", 50.0))
    tier  = r.get("integrity_tier", "UNKNOWN")
    return PanelData(
        panel_id="graph_integrity", title="Graph Integrity",
        score=score, tier=tier,
        primary_metric="integrity_score", primary_value=score,
        secondary_metrics={
            "nodes": r.get("node_count", 0),
            "edges": r.get("edge_count", 0),
            "findings": len(r.get("findings", [])),
            "drift": r.get("drift_detected", False),
        },
        generated_at=r.get("generated_at"),
    ), score

def _build_repro_panel() -> Tuple[PanelData, float]:
    r = _load_json(REPRO_REPORT_PATH)
    if not r:
        return PanelData("reproducibility", "Reproducibility", 50.0, "UNKNOWN",
                         "rate", "N/A", status="no_data"), 50.0
    rate  = float(r.get("reproducibility_rate", 50.0))
    tier  = r.get("reproducibility_tier", "UNKNOWN")
    return PanelData(
        panel_id="reproducibility", title="Intelligence Reproducibility",
        score=rate, tier=tier,
        primary_metric="reproducibility_rate_pct", primary_value=rate,
        secondary_metrics={
            "audited": r.get("advisories_audited", 0),
            "reproduced": r.get("reproduced_count", 0),
            "failed": r.get("failed_count", 0),
            "snapshots": r.get("total_snapshots", 0),
        },
        generated_at=r.get("generated_at"),
    ), rate

def _build_drift_panel() -> Tuple[PanelData, float]:
    r = _load_json(DRIFT_REPORT_PATH)
    if not r:
        return PanelData("scoring_drift", "Scoring Drift", 80.0, "UNKNOWN",
                         "drift_detected", False, status="no_data"), 80.0
    drift     = r.get("drift_detected", False)
    severity  = r.get("drift_severity", "NONE")
    # No drift = good (high score); severe drift = bad
    score = _tier_to_score(severity, invert=True) if drift else 95.0
    return PanelData(
        panel_id="scoring_drift", title="Scoring Drift",
        score=score, tier=severity if drift else "STABLE",
        primary_metric="drift_detected", primary_value=drift,
        secondary_metrics={
            "mean": r.get("current_stats", {}).get("mean"),
            "std": r.get("current_stats", {}).get("std_dev"),
            "mean_drift": r.get("mean_drift"),
            "anomalies": r.get("anomaly_count", 0),
        },
        generated_at=r.get("generated_at"),
    ), score

def _build_enrich_panel() -> Tuple[PanelData, float]:
    r = _load_json(ENRICH_REPORT_PATH)
    if not r:
        return PanelData("enrichment", "Enrichment Health", 50.0, "UNKNOWN",
                         "health", "N/A", status="no_data"), 50.0
    health = float(r.get("enrichment_health_score", 50.0))
    tier   = r.get("completeness_tier", "UNKNOWN")
    return PanelData(
        panel_id="enrichment", title="Enrichment Health",
        score=health, tier=tier,
        primary_metric="enrichment_health_score", primary_value=health,
        secondary_metrics={
            "completeness": r.get("mean_completeness_score"),
            "ioc_coverage": r.get("ioc_telemetry", {}).get("ioc_coverage_pct"),
            "tech_coverage": r.get("attck_telemetry", {}).get("technique_coverage_pct"),
            "failures": len(r.get("failures", [])),
        },
        generated_at=r.get("generated_at"),
    ), health

def _build_ioc_panel() -> Tuple[PanelData, float]:
    r = _load_json(IOC_REPORT_PATH)
    if not r:
        return PanelData("ioc_quality", "IOC Quality", 50.0, "UNKNOWN",
                         "quality", "N/A", status="no_data"), 50.0
    quality = float(r.get("overall_quality_score", 50.0))
    tier    = r.get("quality_tier", "UNKNOWN")
    return PanelData(
        panel_id="ioc_quality", title="IOC Quality",
        score=quality, tier=tier,
        primary_metric="overall_quality_score", primary_value=quality,
        secondary_metrics={
            "total": r.get("total_iocs_analyzed", 0),
            "unique": r.get("unique_ioc_count", 0),
            "hf_rate": r.get("high_fidelity_rate_pct"),
            "multi_source": r.get("multi_source_rate_pct"),
            "active_rate": r.get("lifecycle", {}).get("active_rate_pct") if r.get("lifecycle") else None,
        },
        generated_at=r.get("generated_at"),
    ), quality

def _build_attck_panel() -> Tuple[PanelData, float]:
    r = _load_json(ATTCK_REPORT_PATH)
    if not r:
        return PanelData("attck_coverage", "ATT&CK Coverage", 50.0, "UNKNOWN",
                         "score", "N/A", status="no_data"), 50.0
    score = float(r.get("coverage_score", 50.0))
    tier  = r.get("coverage_tier", "UNKNOWN")
    return PanelData(
        panel_id="attck_coverage", title="ATT&CK Coverage",
        score=score, tier=tier,
        primary_metric="coverage_score", primary_value=score,
        secondary_metrics={
            "covered_tactics": r.get("total_unique_tactics"),
            "techniques": r.get("total_unique_techniques"),
            "tech_coverage_pct": r.get("technique_coverage_pct"),
            "missing_hp": len(r.get("missing_high_priority", [])),
        },
        generated_at=r.get("generated_at"),
    ), score

def _build_actor_panel() -> Tuple[PanelData, float]:
    r = _load_json(ACTOR_REPORT_PATH)
    if not r:
        return PanelData("actor_clustering", "Actor Clustering", 50.0, "UNKNOWN",
                         "score", "N/A", status="no_data"), 50.0
    score = float(r.get("clustering_health_score", 50.0))
    tier  = r.get("clustering_tier", "UNKNOWN")
    return PanelData(
        panel_id="actor_clustering", title="Actor Clustering",
        score=score, tier=tier,
        primary_metric="clustering_health_score", primary_value=score,
        secondary_metrics={
            "actors": r.get("total_actors"),
            "clusters": r.get("total_clusters"),
            "phantom": r.get("phantom_actor_count"),
            "volatile": r.get("volatile_actor_count"),
        },
        generated_at=r.get("generated_at"),
    ), score

def _build_fp_panel() -> Tuple[PanelData, float]:
    r = _load_json(FP_REPORT_PATH)
    if not r:
        return PanelData("fp_risk", "FP Risk", 80.0, "UNKNOWN",
                         "risk_score", "N/A", status="no_data"), 80.0
    fp_risk_score = float(r.get("overall_fp_risk_score", 20.0))
    tier = r.get("fp_risk_tier", "UNKNOWN")
    # Invert: low FP risk = high observability score
    obs_score = round(max(0.0, 100.0 - fp_risk_score), 2)
    return PanelData(
        panel_id="fp_risk", title="False-Positive Risk",
        score=obs_score, tier=tier,
        primary_metric="fp_risk_score", primary_value=fp_risk_score,
        secondary_metrics={
            "signals": r.get("total_fp_signals"),
            "signal_rate": r.get("fp_signal_rate_pct"),
            "conf_inflation": r.get("confidence_inflation_count"),
            "over_corr": len(r.get("over_correlated_iocs", [])),
        },
        generated_at=r.get("generated_at"),
    ), obs_score


# ── OMNIGOD SCORE ────────────────────────────────────────────────────────────
def _compute_omnigod(dim_scores: Dict[str, float]) -> OmnigodScore:
    total = sum(
        dim_scores.get(dim, 50.0) * (weight / 100.0)
        for dim, weight in OMNIGOD_WEIGHTS.items()
    )
    total = round(max(0.0, min(100.0, total)), 2)
    tier = (
        "OMNIGOD"    if total >= 92 else
        "EXCELLENT"  if total >= 82 else
        "GOOD"       if total >= 70 else
        "ACCEPTABLE" if total >= 55 else
        "DEGRADED"   if total >= 40 else
        "CRITICAL"
    )
    return OmnigodScore(
        score=total,
        tier=tier,
        dimension_scores=dim_scores,
        dimension_weights=OMNIGOD_WEIGHTS,
        computed_at=_now_iso(),
    )


# ── HTML GENERATOR ────────────────────────────────────────────────────────────
def _generate_html(payload: DashboardPayload) -> str:
    og = payload.omnigod_score
    tier_colors = {
        "OMNIGOD": "#00ff88", "EXCELLENT": "#22c55e", "GOOD": "#84cc16",
        "ACCEPTABLE": "#eab308", "DEGRADED": "#f97316", "CRITICAL": "#ef4444",
        "STABLE": "#22c55e", "NONE": "#22c55e", "UNKNOWN": "#6b7280",
        "LOW": "#22c55e", "MODERATE": "#84cc16", "ELEVATED": "#eab308",
        "HIGH": "#f97316", "POOR": "#f97316", "FAILING": "#ef4444",
    }

    def tier_color(tier: str) -> str:
        return tier_colors.get(tier, "#6b7280")

    panels_html = ""
    for p in payload.panels:
        color = tier_color(p.tier)
        bar_w = max(2, int(p.score))
        sec_rows = "".join(
            f"<tr><td style='color:#94a3b8;padding:2px 6px'>{k}</td>"
            f"<td style='color:#e2e8f0;padding:2px 6px;text-align:right'>{v}</td></tr>"
            for k, v in p.secondary_metrics.items() if v is not None
        )
        panels_html += f"""
        <div class="panel">
          <div class="panel-title">{p.title}</div>
          <div class="panel-score" style="color:{color}">{p.score:.1f}</div>
          <div class="tier-badge" style="background:{color}22;color:{color};border:1px solid {color}44">{p.tier}</div>
          <div class="bar-bg"><div class="bar-fill" style="width:{bar_w}%;background:{color}"></div></div>
          <table style="width:100%;margin-top:8px;font-size:11px">{sec_rows}</table>
          <div style="font-size:10px;color:#475569;margin-top:6px">{p.generated_at or 'N/A'}</div>
        </div>"""

    og_color = tier_color(og.tier)
    alerts_html = "".join(f"<li style='color:#fbbf24'>{a}</li>" for a in payload.critical_alerts[:5])

    return f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SENTINEL APEX — Enterprise Observability Dashboard</title>
<style>
  *{{box-sizing:border-box;margin:0;padding:0}}
  body{{background:#0f172a;color:#e2e8f0;font-family:'Segoe UI',system-ui,sans-serif;padding:20px}}
  .header{{text-align:center;padding:20px 0 30px}}
  .header h1{{font-size:1.8rem;color:{og_color};letter-spacing:2px}}
  .header p{{color:#64748b;font-size:0.85rem;margin-top:4px}}
  .omnigod{{background:#1e293b;border:2px solid {og_color}44;border-radius:16px;
            padding:30px;text-align:center;margin-bottom:30px}}
  .omnigod .og-score{{font-size:5rem;font-weight:800;color:{og_color};line-height:1}}
  .omnigod .og-tier{{font-size:1.4rem;color:{og_color};margin-top:8px;letter-spacing:3px}}
  .panels{{display:grid;grid-template-columns:repeat(auto-fill,minmax(260px,1fr));gap:16px;margin-bottom:24px}}
  .panel{{background:#1e293b;border-radius:12px;padding:18px;border:1px solid #334155}}
  .panel-title{{font-size:0.75rem;color:#94a3b8;text-transform:uppercase;letter-spacing:1px;margin-bottom:8px}}
  .panel-score{{font-size:2.4rem;font-weight:700;line-height:1}}
  .tier-badge{{display:inline-block;padding:3px 10px;border-radius:20px;font-size:0.7rem;
               font-weight:600;letter-spacing:1px;margin-top:6px}}
  .bar-bg{{background:#334155;border-radius:4px;height:6px;margin-top:10px}}
  .bar-fill{{height:6px;border-radius:4px;transition:width .3s}}
  .alerts{{background:#1e293b;border:1px solid #7f1d1d;border-radius:12px;padding:16px;margin-bottom:24px}}
  .alerts h3{{color:#ef4444;font-size:0.85rem;margin-bottom:8px}}
  .alerts ul{{padding-left:16px;font-size:0.8rem}}
  .footer{{text-align:center;color:#334155;font-size:0.75rem;padding-top:16px}}
</style>
</head>
<body>
<div class="header">
  <h1>👑 SENTINEL APEX ENTERPRISE OBSERVABILITY</h1>
  <p>Generated: {payload.generated_at} &nbsp;|&nbsp; Dashboard ID: {payload.dashboard_id}</p>
</div>
<div class="omnigod">
  <div style="font-size:0.75rem;color:#64748b;letter-spacing:2px;margin-bottom:8px">OMNIGOD OBSERVABILITY SCORE</div>
  <div class="og-score">{og.score}</div>
  <div class="og-tier">{og.tier}</div>
  <div style="margin-top:16px;display:flex;justify-content:center;gap:16px;flex-wrap:wrap">
    {"".join(f'<span style="font-size:0.7rem;color:#64748b">{k.replace("_"," ").upper()}: <span style="color:{og_color}">{v:.1f}</span></span>' for k,v in og.dimension_scores.items())}
  </div>
</div>
{"<div class='alerts'><h3>⚠ CRITICAL ALERTS</h3><ul>" + alerts_html + "</ul></div>" if payload.critical_alerts else ""}
<div class="panels">{panels_html}</div>
<div class="footer">
  CYBERDUDEBIVASH® SENTINEL APEX &nbsp;|&nbsp;
  Pipeline Health: <strong style="color:{'#22c55e' if payload.pipeline_health=='HEALTHY' else '#ef4444'}">{payload.pipeline_health}</strong>
  &nbsp;|&nbsp; Alerts: {payload.alert_count}
</div>
</body></html>"""


# ── MAIN ENGINE ──────────────────────────────────────────────────────────────
class ObservabilityDashboardEngine:

    def run_full_pipeline(self) -> DashboardPayload:
        t0 = time.time()
        dash_id = f"dash_{_short_id(_now_iso())}"
        logger.info("[OBS-DASH] Building observability dashboard %s", dash_id)

        panels: List[PanelData] = []
        dim_scores: Dict[str, float] = {}

        builders = [
            ("graph_integrity",  _build_graph_panel),
            ("reproducibility",  _build_repro_panel),
            ("scoring_drift",    _build_drift_panel),
            ("enrichment",       _build_enrich_panel),
            ("ioc_quality",      _build_ioc_panel),
            ("attck_coverage",   _build_attck_panel),
            ("actor_clustering", _build_actor_panel),
            ("fp_risk",          _build_fp_panel),
        ]

        for dim, builder in builders:
            try:
                panel, score = builder()
                panels.append(panel)
                dim_scores[dim] = score
            except Exception as exc:
                logger.warning("[OBS-DASH] Panel %s error: %s", dim, exc)
                dim_scores[dim] = 50.0

        omnigod = _compute_omnigod(dim_scores)

        # Critical alerts
        critical_alerts: List[str] = []
        for p in panels:
            if p.tier in ("CRITICAL", "FAILING"):
                critical_alerts.append(f"{p.title}: {p.tier} (score={p.score:.1f})")

        pipeline_health = "HEALTHY" if omnigod.score >= 60 else "DEGRADED"

        # Telemetry history (last 10 entries per module)
        telem_history: Dict[str, List[Dict]] = {}
        for name, path in TELEM_FILES.items():
            try:
                telem_history[name] = _load_jsonl_tail(path, 10)
            except Exception:
                telem_history[name] = []

        payload = DashboardPayload(
            dashboard_id=dash_id,
            generated_at=_now_iso(),
            omnigod_score=omnigod,
            panels=panels,
            telemetry_history=telem_history,
            alert_count=len(critical_alerts),
            critical_alerts=critical_alerts,
            pipeline_health=pipeline_health,
            duration_ms=round((time.time() - t0) * 1000, 2),
        )

        self._persist(payload)
        logger.info(
            "[OBS-DASH] Dashboard %s: omnigod=%.1f tier=%s alerts=%d",
            dash_id, omnigod.score, omnigod.tier, len(critical_alerts)
        )
        return payload

    def _persist(self, payload: DashboardPayload) -> None:
        try:
            payload_dict = asdict(payload)
            _atomic_write(DASH_PAYLOAD_PATH, payload_dict)

            summary = {
                "dashboard_id": payload.dashboard_id,
                "generated_at": payload.generated_at,
                "omnigod_score": payload.omnigod_score.score,
                "omnigod_tier": payload.omnigod_score.tier,
                "pipeline_health": payload.pipeline_health,
                "alert_count": payload.alert_count,
                "critical_alerts": payload.critical_alerts,
                "panels": {p.panel_id: {"score": p.score, "tier": p.tier} for p in payload.panels},
            }
            _atomic_write(DASH_SUMMARY_PATH, summary)

            html = _generate_html(payload)
            tmp_html = DASH_HTML_PATH.with_suffix(".tmp")
            OBS_DIR.mkdir(parents=True, exist_ok=True)
            tmp_html.write_text(html, encoding="utf-8")
            tmp_html.replace(DASH_HTML_PATH)
        except Exception as exc:
            logger.error("[OBS-DASH] Persist error: %s", exc)

    def get_summary(self) -> Dict[str, Any]:
        s = _load_json(DASH_SUMMARY_PATH)
        if not s:
            return {"status": "no_dashboard"}
        return {"status": "ok", **s}


# ── CLI ENTRY ────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s %(message)s")
    engine = ObservabilityDashboardEngine()
    result = engine.run_full_pipeline()
    print(f"\n[OBS-DASH] Dashboard: {result.dashboard_id}")
    print(f"  OMNIGOD Score: {result.omnigod_score.score:.1f}  Tier: {result.omnigod_score.tier}")
    print(f"  Pipeline Health: {result.pipeline_health}  Alerts: {result.alert_count}")
    for p in result.panels:
        print(f"  [{p.tier:12s}] {p.title}: {p.score:.1f}")
    sys.exit(0 if result.pipeline_health == "HEALTHY" else 1)
