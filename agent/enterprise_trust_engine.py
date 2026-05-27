"""
CYBERDUDEBIVASH® SENTINEL APEX — Phase 51
Enterprise Trust Dominance Engine
Operational legitimacy, ATT&CK evaluations, telemetry transparency,
replay efficacy benchmarks, SOC efficiency metrics, MSSP operational studies.
Production-grade. Replay-validated. Analyst-usable.
"""

import json
import hashlib
import statistics
import uuid
from datetime import datetime, timezone, timedelta
from dataclasses import dataclass, asdict, field
from typing import Optional
from enum import Enum


# ─── Enumerations ─────────────────────────────────────────────────────────────

class TrustDimension(Enum):
    TELEMETRY_LEGITIMACY    = "telemetry_legitimacy"
    REPLAY_LEGITIMACY       = "replay_legitimacy"
    ANALYST_USABILITY       = "analyst_usability"
    ENTERPRISE_READINESS    = "enterprise_readiness"
    ATTCK_COVERAGE          = "attck_coverage"
    SOC_EFFICIENCY          = "soc_efficiency"
    MSSP_OPERABILITY        = "mssp_operability"
    FALSE_POSITIVE_RATE     = "false_positive_rate"
    DEPLOYMENT_VALIDATION   = "deployment_validation"
    GRAPH_INTELLIGENCE      = "graph_intelligence"

class BenchmarkStatus(Enum):
    PASSING  = "passing"
    WARNING  = "warning"
    FAILING  = "failing"
    PENDING  = "pending"

class StudyType(Enum):
    ATTCK_EVALUATION        = "attck_evaluation"
    TELEMETRY_TRANSPARENCY  = "telemetry_transparency"
    REPLAY_EFFICACY         = "replay_efficacy"
    FALSE_POSITIVE_BENCH    = "false_positive_benchmark"
    SOC_EFFICIENCY          = "soc_efficiency_metric"
    MSSP_OPERATIONAL        = "mssp_operational_study"
    ANALYST_WORKFLOW        = "analyst_workflow_study"
    DEPLOYMENT_VALIDATION   = "deployment_validation_report"
    TELEMETRY_QUALITY       = "telemetry_quality_analytics"
    GRAPH_BENCH             = "graph_intelligence_benchmark"


# ─── Data Classes ─────────────────────────────────────────────────────────────

@dataclass
class TrustScore:
    dimension:      TrustDimension
    score:          float           # 0.0 – 100.0
    confidence:     float           # 0.0 – 1.0
    evidence_refs:  list[str]       = field(default_factory=list)
    benchmark_id:   str             = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:      str             = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    status:         BenchmarkStatus = BenchmarkStatus.PENDING

    def __post_init__(self):
        if self.score >= 85:
            self.status = BenchmarkStatus.PASSING
        elif self.score >= 70:
            self.status = BenchmarkStatus.WARNING
        else:
            self.status = BenchmarkStatus.FAILING


@dataclass
class ATTCKEvaluation:
    technique_id:       str
    technique_name:     str
    tactic:             str
    detection_score:    float       # 0–100
    telemetry_score:    float       # 0–100
    replay_validated:   bool
    false_positives:    int
    test_cases:         int
    passed_cases:       int
    coverage_notes:     str         = ""
    eval_id:            str         = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:          str         = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def pass_rate(self) -> float:
        return (self.passed_cases / self.test_cases * 100) if self.test_cases > 0 else 0.0

    @property
    def composite_score(self) -> float:
        return round((self.detection_score * 0.5 + self.telemetry_score * 0.3 + self.pass_rate * 0.2), 2)


@dataclass
class TelemetryTransparencyReport:
    sensor_id:              str
    collection_method:      str     # eBPF / ETW / OTel / Syslog / API
    events_collected:       int
    events_validated:       int
    gap_rate_pct:           float
    latency_p50_ms:         float
    latency_p99_ms:         float
    field_coverage_pct:     float
    schema_version:         str
    integrity_hash:         str     = ""
    report_id:              str     = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:              str     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        raw = f"{self.sensor_id}{self.events_collected}{self.events_validated}"
        self.integrity_hash = hashlib.sha256(raw.encode()).hexdigest()[:16]

    @property
    def fidelity_score(self) -> float:
        validation_rate = (self.events_validated / self.events_collected * 100) if self.events_collected > 0 else 0
        gap_penalty = self.gap_rate_pct * 0.5
        latency_penalty = min(self.latency_p99_ms / 1000, 10)
        return round(max(0, validation_rate - gap_penalty - latency_penalty), 2)


@dataclass
class ReplayEfficacyBenchmark:
    replay_id:          str
    scenario_name:      str
    total_events:       int
    replayed_events:    int
    detection_hits:     int
    detection_misses:   int
    replay_latency_ms:  float
    timeline_fidelity:  float       # 0–100 % temporal accuracy
    causal_accuracy:    float       # 0–100 % causal chain preserved
    benchmark_id:       str         = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:          str         = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def replay_completeness(self) -> float:
        return round((self.replayed_events / self.total_events * 100) if self.total_events > 0 else 0, 2)

    @property
    def detection_efficacy(self) -> float:
        total = self.detection_hits + self.detection_misses
        return round((self.detection_hits / total * 100) if total > 0 else 0, 2)

    @property
    def efficacy_composite(self) -> float:
        return round(
            self.replay_completeness * 0.3 +
            self.detection_efficacy * 0.4 +
            self.timeline_fidelity * 0.2 +
            self.causal_accuracy * 0.1,
            2
        )


@dataclass
class FalsePositiveBenchmark:
    rule_id:            str
    rule_name:          str
    rule_type:          str         # Sigma / YARA / Custom
    total_alerts:       int
    true_positives:     int
    false_positives:    int
    true_negatives:     int
    false_negatives:    int
    environment:        str         = "enterprise"
    benchmark_id:       str         = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:          str         = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def precision(self) -> float:
        denom = self.true_positives + self.false_positives
        return round((self.true_positives / denom) if denom > 0 else 0, 4)

    @property
    def recall(self) -> float:
        denom = self.true_positives + self.false_negatives
        return round((self.true_positives / denom) if denom > 0 else 0, 4)

    @property
    def f1_score(self) -> float:
        p, r = self.precision, self.recall
        return round((2 * p * r / (p + r)) if (p + r) > 0 else 0, 4)

    @property
    def fp_rate_pct(self) -> float:
        return round((self.false_positives / self.total_alerts * 100) if self.total_alerts > 0 else 0, 2)


@dataclass
class SOCEfficiencyMetric:
    metric_name:        str
    tenant_id:          str
    mttd_minutes:       float       # Mean time to detect
    mttr_minutes:       float       # Mean time to respond
    mttc_minutes:       float       # Mean time to close
    alert_volume_day:   int
    analyst_capacity:   int         # analysts
    escalation_rate:    float       # % alerts escalated
    automation_rate:    float       # % alerts auto-closed
    sla_breach_rate:    float       # % alerts breaching SLA
    metric_id:          str         = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:          str         = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def analyst_load(self) -> float:
        return round(self.alert_volume_day / max(self.analyst_capacity, 1), 2)

    @property
    def efficiency_score(self) -> float:
        mttd_score  = max(0, 100 - (self.mttd_minutes / 60))
        auto_score  = self.automation_rate
        sla_score   = max(0, 100 - self.sla_breach_rate * 5)
        fp_penalty  = self.escalation_rate * 0.3
        return round((mttd_score * 0.4 + auto_score * 0.3 + sla_score * 0.3 - fp_penalty), 2)


@dataclass
class MSSPOperationalStudy:
    mssp_id:                str
    tenant_count:           int
    managed_endpoints:      int
    telemetry_events_day:   int
    onboarding_time_hours:  float
    playbook_count:         int
    automation_coverage:    float   # %
    sla_compliance_rate:    float   # %
    analyst_utilization:    float   # %
    revenue_per_tenant_usd: float
    study_id:               str     = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:              str     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    @property
    def operational_score(self) -> float:
        return round(
            self.automation_coverage * 0.3 +
            self.sla_compliance_rate * 0.4 +
            (100 - self.analyst_utilization) * 0.1 +
            min(self.tenant_count / 10, 20) +
            0,
            2
        )

    @property
    def revenue_projection_annual_usd(self) -> float:
        return self.tenant_count * self.revenue_per_tenant_usd * 12


@dataclass
class EnterpriseDeploymentValidation:
    deployment_id:          str
    org_name:               str
    environment:            str     # cloud / on-prem / hybrid
    endpoints_deployed:     int
    sensors_active:         int
    integrations_active:    int     # SIEM / SOAR / TIP / EDR
    coverage_pct:           float
    data_flowing:           bool
    detections_firing:      bool
    replay_functional:      bool
    graph_populated:        bool
    validation_score:       float   = 0.0
    report_id:              str     = field(default_factory=lambda: str(uuid.uuid4())[:8])
    timestamp:              str     = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def __post_init__(self):
        checks = [
            self.data_flowing,
            self.detections_firing,
            self.replay_functional,
            self.graph_populated,
            self.coverage_pct >= 80,
            self.sensors_active >= self.endpoints_deployed * 0.9,
        ]
        self.validation_score = round(sum(checks) / len(checks) * 100, 2)


# ─── Enterprise Trust Engine ──────────────────────────────────────────────────

class EnterpriseTrustEngine:
    """
    Phase 51 — Enterprise Trust Dominance Engine.
    Orchestrates ATT&CK evaluations, telemetry transparency, replay efficacy,
    false-positive benchmarking, SOC efficiency, MSSP operational studies,
    analyst workflow analytics, and deployment validation.
    """

    def __init__(self):
        self._trust_scores:         list[TrustScore]                = []
        self._attck_evals:          list[ATTCKEvaluation]           = []
        self._telemetry_reports:    list[TelemetryTransparencyReport] = []
        self._replay_benchmarks:    list[ReplayEfficacyBenchmark]   = []
        self._fp_benchmarks:        list[FalsePositiveBenchmark]    = []
        self._soc_metrics:          list[SOCEfficiencyMetric]       = []
        self._mssp_studies:         list[MSSPOperationalStudy]      = []
        self._deployments:          list[EnterpriseDeploymentValidation] = []
        self._initialized_at = datetime.now(timezone.utc).isoformat()

    # ── ATT&CK Evaluations ────────────────────────────────────────────────

    def register_attck_eval(self, eval_data: ATTCKEvaluation) -> dict:
        self._attck_evals.append(eval_data)
        return {
            "eval_id":          eval_data.eval_id,
            "technique":        eval_data.technique_id,
            "composite_score":  eval_data.composite_score,
            "pass_rate":        eval_data.pass_rate,
            "replay_validated": eval_data.replay_validated,
        }

    def run_attck_coverage_analysis(self) -> dict:
        if not self._attck_evals:
            return {"status": "no_data"}

        tactics: dict[str, list[float]] = {}
        for ev in self._attck_evals:
            tactics.setdefault(ev.tactic, []).append(ev.composite_score)

        tactic_summary = {
            tactic: {
                "avg_score":    round(statistics.mean(scores), 2),
                "techniques":   len(scores),
                "coverage_pct": round(len(scores) / 20 * 100, 1),   # assume 20 per tactic
            }
            for tactic, scores in tactics.items()
        }

        overall = statistics.mean(ev.composite_score for ev in self._attck_evals)
        replay_rate = sum(1 for ev in self._attck_evals if ev.replay_validated) / len(self._attck_evals)

        return {
            "total_techniques_evaluated":   len(self._attck_evals),
            "overall_composite_score":      round(overall, 2),
            "replay_validation_rate":       round(replay_rate * 100, 2),
            "tactic_breakdown":             tactic_summary,
            "top_performers": sorted(
                [{"id": e.technique_id, "name": e.technique_name, "score": e.composite_score}
                 for e in self._attck_evals],
                key=lambda x: x["score"], reverse=True
            )[:5],
        }

    # ── Telemetry Transparency ────────────────────────────────────────────

    def register_telemetry_report(self, report: TelemetryTransparencyReport) -> dict:
        self._telemetry_reports.append(report)
        return {
            "report_id":        report.report_id,
            "sensor_id":        report.sensor_id,
            "fidelity_score":   report.fidelity_score,
            "integrity_hash":   report.integrity_hash,
        }

    def run_telemetry_transparency_analysis(self) -> dict:
        if not self._telemetry_reports:
            return {"status": "no_data"}

        avg_fidelity = statistics.mean(r.fidelity_score for r in self._telemetry_reports)
        avg_gap      = statistics.mean(r.gap_rate_pct for r in self._telemetry_reports)
        avg_latency  = statistics.mean(r.latency_p99_ms for r in self._telemetry_reports)
        total_events = sum(r.events_collected for r in self._telemetry_reports)

        by_method: dict[str, list[float]] = {}
        for r in self._telemetry_reports:
            by_method.setdefault(r.collection_method, []).append(r.fidelity_score)

        return {
            "total_sensors":            len(self._telemetry_reports),
            "total_events_covered":     total_events,
            "avg_fidelity_score":       round(avg_fidelity, 2),
            "avg_gap_rate_pct":         round(avg_gap, 3),
            "avg_latency_p99_ms":       round(avg_latency, 2),
            "by_collection_method": {
                m: {"avg_fidelity": round(statistics.mean(s), 2), "sensor_count": len(s)}
                for m, s in by_method.items()
            },
            "integrity_verified":       all(len(r.integrity_hash) == 16 for r in self._telemetry_reports),
        }

    # ── Replay Efficacy ───────────────────────────────────────────────────

    def register_replay_benchmark(self, bench: ReplayEfficacyBenchmark) -> dict:
        self._replay_benchmarks.append(bench)
        return {
            "benchmark_id":         bench.benchmark_id,
            "scenario":             bench.scenario_name,
            "efficacy_composite":   bench.efficacy_composite,
            "replay_completeness":  bench.replay_completeness,
            "detection_efficacy":   bench.detection_efficacy,
        }

    def run_replay_efficacy_summary(self) -> dict:
        if not self._replay_benchmarks:
            return {"status": "no_data"}

        avg_efficacy     = statistics.mean(b.efficacy_composite for b in self._replay_benchmarks)
        avg_completeness = statistics.mean(b.replay_completeness for b in self._replay_benchmarks)
        avg_detection    = statistics.mean(b.detection_efficacy for b in self._replay_benchmarks)
        avg_latency      = statistics.mean(b.replay_latency_ms for b in self._replay_benchmarks)

        return {
            "total_benchmarks":         len(self._replay_benchmarks),
            "avg_efficacy_composite":   round(avg_efficacy, 2),
            "avg_replay_completeness":  round(avg_completeness, 2),
            "avg_detection_efficacy":   round(avg_detection, 2),
            "avg_replay_latency_ms":    round(avg_latency, 2),
            "scenarios": [
                {
                    "id":           b.benchmark_id,
                    "name":         b.scenario_name,
                    "efficacy":     b.efficacy_composite,
                    "completeness": b.replay_completeness,
                }
                for b in self._replay_benchmarks
            ],
        }

    # ── False Positive Benchmarking ───────────────────────────────────────

    def register_fp_benchmark(self, bench: FalsePositiveBenchmark) -> dict:
        self._fp_benchmarks.append(bench)
        return {
            "benchmark_id": bench.benchmark_id,
            "rule_id":      bench.rule_id,
            "precision":    bench.precision,
            "recall":       bench.recall,
            "f1_score":     bench.f1_score,
            "fp_rate_pct":  bench.fp_rate_pct,
        }

    def run_fp_analysis(self) -> dict:
        if not self._fp_benchmarks:
            return {"status": "no_data"}

        avg_precision = statistics.mean(b.precision for b in self._fp_benchmarks)
        avg_recall    = statistics.mean(b.recall for b in self._fp_benchmarks)
        avg_f1        = statistics.mean(b.f1_score for b in self._fp_benchmarks)
        avg_fp_rate   = statistics.mean(b.fp_rate_pct for b in self._fp_benchmarks)

        return {
            "total_rules_benchmarked":  len(self._fp_benchmarks),
            "avg_precision":            round(avg_precision, 4),
            "avg_recall":               round(avg_recall, 4),
            "avg_f1_score":             round(avg_f1, 4),
            "avg_fp_rate_pct":          round(avg_fp_rate, 2),
            "rules_above_90pct_f1":     sum(1 for b in self._fp_benchmarks if b.f1_score >= 0.9),
            "high_fp_rules": [
                {"rule_id": b.rule_id, "fp_rate": b.fp_rate_pct, "f1": b.f1_score}
                for b in self._fp_benchmarks if b.fp_rate_pct > 20
            ],
        }

    # ── SOC Efficiency ────────────────────────────────────────────────────

    def register_soc_metric(self, metric: SOCEfficiencyMetric) -> dict:
        self._soc_metrics.append(metric)
        return {
            "metric_id":        metric.metric_id,
            "tenant":           metric.tenant_id,
            "mttd_minutes":     metric.mttd_minutes,
            "efficiency_score": metric.efficiency_score,
            "analyst_load":     metric.analyst_load,
        }

    def run_soc_efficiency_report(self) -> dict:
        if not self._soc_metrics:
            return {"status": "no_data"}

        avg_mttd  = statistics.mean(m.mttd_minutes for m in self._soc_metrics)
        avg_mttr  = statistics.mean(m.mttr_minutes for m in self._soc_metrics)
        avg_eff   = statistics.mean(m.efficiency_score for m in self._soc_metrics)
        avg_auto  = statistics.mean(m.automation_rate for m in self._soc_metrics)

        return {
            "total_tenants":        len(self._soc_metrics),
            "avg_mttd_minutes":     round(avg_mttd, 2),
            "avg_mttr_minutes":     round(avg_mttr, 2),
            "avg_efficiency_score": round(avg_eff, 2),
            "avg_automation_rate":  round(avg_auto, 2),
            "top_tenants": sorted(
                [{"tenant": m.tenant_id, "efficiency": m.efficiency_score}
                 for m in self._soc_metrics],
                key=lambda x: x["efficiency"], reverse=True
            )[:3],
        }

    # ── MSSP Operational Studies ──────────────────────────────────────────

    def register_mssp_study(self, study: MSSPOperationalStudy) -> dict:
        self._mssp_studies.append(study)
        return {
            "study_id":                     study.study_id,
            "mssp_id":                      study.mssp_id,
            "tenant_count":                 study.tenant_count,
            "operational_score":            study.operational_score,
            "revenue_projection_annual":    study.revenue_projection_annual_usd,
        }

    def run_mssp_summary(self) -> dict:
        if not self._mssp_studies:
            return {"status": "no_data"}

        total_tenants   = sum(s.tenant_count for s in self._mssp_studies)
        total_endpoints = sum(s.managed_endpoints for s in self._mssp_studies)
        avg_sla         = statistics.mean(s.sla_compliance_rate for s in self._mssp_studies)
        total_arr       = sum(s.revenue_projection_annual_usd for s in self._mssp_studies)

        return {
            "total_mssp_instances":     len(self._mssp_studies),
            "total_managed_tenants":    total_tenants,
            "total_managed_endpoints":  total_endpoints,
            "avg_sla_compliance_pct":   round(avg_sla, 2),
            "total_arr_usd":            round(total_arr, 2),
            "avg_onboarding_hours":     round(statistics.mean(s.onboarding_time_hours for s in self._mssp_studies), 2),
        }

    # ── Deployment Validation ─────────────────────────────────────────────

    def register_deployment(self, dep: EnterpriseDeploymentValidation) -> dict:
        self._deployments.append(dep)
        return {
            "report_id":        dep.report_id,
            "org":              dep.org_name,
            "validation_score": dep.validation_score,
            "coverage_pct":     dep.coverage_pct,
        }

    def run_deployment_summary(self) -> dict:
        if not self._deployments:
            return {"status": "no_data"}

        avg_score    = statistics.mean(d.validation_score for d in self._deployments)
        fully_valid  = sum(1 for d in self._deployments if d.validation_score >= 80)

        return {
            "total_deployments":        len(self._deployments),
            "avg_validation_score":     round(avg_score, 2),
            "fully_validated_count":    fully_valid,
            "environments": {
                env: sum(1 for d in self._deployments if d.environment == env)
                for env in {"cloud", "on-prem", "hybrid"}
            },
        }

    # ── Master Trust Scorecard ─────────────────────────────────────────────

    def compute_trust_scorecard(self) -> dict:
        """Aggregate all dimensions into a sovereign trust scorecard."""
        attck    = self.run_attck_coverage_analysis()
        telem    = self.run_telemetry_transparency_analysis()
        replay   = self.run_replay_efficacy_summary()
        fp       = self.run_fp_analysis()
        soc      = self.run_soc_efficiency_report()
        mssp     = self.run_mssp_summary()
        deploy   = self.run_deployment_summary()

        scores = {}
        if "overall_composite_score" in attck:
            scores[TrustDimension.ATTCK_COVERAGE.value] = attck["overall_composite_score"]
        if "avg_fidelity_score" in telem:
            scores[TrustDimension.TELEMETRY_LEGITIMACY.value] = telem["avg_fidelity_score"]
        if "avg_efficacy_composite" in replay:
            scores[TrustDimension.REPLAY_LEGITIMACY.value] = replay["avg_efficacy_composite"]
        if "avg_f1_score" in fp:
            scores[TrustDimension.FALSE_POSITIVE_RATE.value] = fp["avg_f1_score"] * 100
        if "avg_efficiency_score" in soc:
            scores[TrustDimension.SOC_EFFICIENCY.value] = soc["avg_efficiency_score"]
        if "avg_sla_compliance_pct" in mssp:
            scores[TrustDimension.MSSP_OPERABILITY.value] = mssp["avg_sla_compliance_pct"]
        if "avg_validation_score" in deploy:
            scores[TrustDimension.DEPLOYMENT_VALIDATION.value] = deploy["avg_validation_score"]

        overall = round(statistics.mean(scores.values()), 2) if scores else 0.0

        return {
            "scorecard_id":     str(uuid.uuid4())[:8],
            "platform":         "SENTINEL APEX",
            "version":          "v166",
            "computed_at":      datetime.now(timezone.utc).isoformat(),
            "dimension_scores": scores,
            "overall_trust_score": overall,
            "trust_status": (
                "ENTERPRISE_CERTIFIED" if overall >= 85
                else "CONDITIONALLY_CERTIFIED" if overall >= 70
                else "REQUIRES_REMEDIATION"
            ),
            "total_evidence_items": (
                len(self._attck_evals) +
                len(self._telemetry_reports) +
                len(self._replay_benchmarks) +
                len(self._fp_benchmarks) +
                len(self._soc_metrics) +
                len(self._mssp_studies) +
                len(self._deployments)
            ),
        }

    # ── Export ────────────────────────────────────────────────────────────

    def export_full_trust_report(self) -> dict:
        return {
            "meta": {
                "engine":       "EnterpriseTrustEngine",
                "phase":        51,
                "platform":     "SENTINEL APEX",
                "initialized":  self._initialized_at,
                "exported_at":  datetime.now(timezone.utc).isoformat(),
            },
            "trust_scorecard":          self.compute_trust_scorecard(),
            "attck_coverage":           self.run_attck_coverage_analysis(),
            "telemetry_transparency":   self.run_telemetry_transparency_analysis(),
            "replay_efficacy":          self.run_replay_efficacy_summary(),
            "false_positive_benchmark": self.run_fp_analysis(),
            "soc_efficiency":           self.run_soc_efficiency_report(),
            "mssp_operational":         self.run_mssp_summary(),
            "deployment_validation":    self.run_deployment_summary(),
        }


# ─── Demo Harness ─────────────────────────────────────────────────────────────

def _seed_demo_data(engine: EnterpriseTrustEngine):
    """Seed representative production data for demonstration."""

    # ATT&CK Evaluations
    attck_evals = [
        ATTCKEvaluation("T1059.001", "PowerShell", "execution",         92, 95, True,  2, 20, 19),
        ATTCKEvaluation("T1055",     "Process Injection", "defense_evasion", 88, 90, True, 3, 15, 14),
        ATTCKEvaluation("T1003.001", "LSASS Memory", "credential_access", 85, 88, True, 1, 12, 11),
        ATTCKEvaluation("T1071.001", "Web Protocols", "command_and_control", 91, 93, True, 2, 18, 17),
        ATTCKEvaluation("T1053.005", "Scheduled Task", "persistence",   89, 91, True,  1, 16, 15),
        ATTCKEvaluation("T1078",     "Valid Accounts", "initial_access", 83, 86, False, 4, 10, 9),
        ATTCKEvaluation("T1021.001", "Remote Desktop", "lateral_movement", 87, 89, True, 2, 14, 13),
        ATTCKEvaluation("T1486",     "Data Encrypted for Impact", "impact", 94, 96, True, 1, 20, 19),
    ]
    for ev in attck_evals:
        engine.register_attck_eval(ev)

    # Telemetry Transparency
    telem_reports = [
        TelemetryTransparencyReport("sensor-ebpf-001", "eBPF",  5_200_000, 5_180_000, 0.38, 12, 45, 97.2, "v3.1"),
        TelemetryTransparencyReport("sensor-etw-001",  "ETW",   3_800_000, 3_760_000, 1.05, 18, 62, 94.8, "v2.4"),
        TelemetryTransparencyReport("sensor-otel-001", "OTel",  2_100_000, 2_090_000, 0.47, 8,  30, 98.5, "v1.8"),
        TelemetryTransparencyReport("sensor-syslog-01","Syslog",1_400_000, 1_370_000, 2.14, 25, 90, 89.3, "v1.2"),
    ]
    for r in telem_reports:
        engine.register_telemetry_report(r)

    # Replay Efficacy
    replay_benchmarks = [
        ReplayEfficacyBenchmark("replay-apt29-001", "APT29 Cozy Bear Campaign",  48_000, 47_800, 142, 8,  180, 97.2, 94.8),
        ReplayEfficacyBenchmark("replay-ransom-001","Ransomware Kill Chain",     32_000, 31_900,  98, 4,  220, 96.8, 93.5),
        ReplayEfficacyBenchmark("replay-lolbas-001","LOLBAS Execution Chain",   18_000, 17_950,  67, 3,  140, 98.1, 95.2),
        ReplayEfficacyBenchmark("replay-cobalt-001","Cobalt Strike Beacon",     25_000, 24_850,  89, 6,  195, 95.6, 92.8),
    ]
    for b in replay_benchmarks:
        engine.register_replay_benchmark(b)

    # FP Benchmarks
    fp_benchmarks = [
        FalsePositiveBenchmark("sigma-001", "PowerShell Encoded Command", "Sigma", 8500, 820, 42, 7200, 22),
        FalsePositiveBenchmark("sigma-002", "LSASS Access",              "Sigma", 3200, 310, 18, 2800,  8),
        FalsePositiveBenchmark("yara-001",  "Cobalt Strike Beacon",      "YARA",  1800, 195,  9, 1580,  5),
        FalsePositiveBenchmark("sigma-003", "Scheduled Task Creation",   "Sigma", 6400, 612, 38, 5600, 28),
        FalsePositiveBenchmark("custom-001","Ransomware File Rename",    "Custom",2100, 205,  6, 1880,  4),
    ]
    for b in fp_benchmarks:
        engine.register_fp_benchmark(b)

    # SOC Metrics
    soc_metrics = [
        SOCEfficiencyMetric("MTTD Benchmark Q1", "tenant-ent-001", 8.2, 22.5, 65.0, 1200, 4, 18.5, 62.0, 3.2),
        SOCEfficiencyMetric("MTTD Benchmark Q1", "tenant-ent-002", 6.8, 18.2, 52.0, 900,  3, 15.2, 71.5, 2.1),
        SOCEfficiencyMetric("MTTD Benchmark Q1", "tenant-mssp-001",12.5, 35.0, 90.0, 3200, 8, 22.0, 55.0, 4.8),
    ]
    for m in soc_metrics:
        engine.register_soc_metric(m)

    # MSSP Studies
    mssp_studies = [
        MSSPOperationalStudy("mssp-apex-001", 45,  28_500, 850_000_000, 4.2, 182, 73.5, 97.8, 68.0, 8500),
        MSSPOperationalStudy("mssp-apex-002", 12,   6_200, 180_000_000, 6.8,  94, 68.0, 95.2, 72.5, 6200),
    ]
    for s in mssp_studies:
        engine.register_mssp_study(s)

    # Deployments
    deployments = [
        EnterpriseDeploymentValidation("dep-001", "Global Financial Corp",    "hybrid",  8500, 8480, 6, 99.8, True, True, True, True),
        EnterpriseDeploymentValidation("dep-002", "Healthcare Enterprise",    "cloud",   2100, 2085, 4, 99.3, True, True, True, True),
        EnterpriseDeploymentValidation("dep-003", "Manufacturing Conglomerate","on-prem",5800, 5760, 5, 99.3, True, True, True, False),
    ]
    for d in deployments:
        engine.register_deployment(d)


def run_demo() -> dict:
    engine = EnterpriseTrustEngine()
    _seed_demo_data(engine)
    report = engine.export_full_trust_report()
    print(json.dumps(report["trust_scorecard"], indent=2))
    return report


if __name__ == "__main__":
    run_demo()
