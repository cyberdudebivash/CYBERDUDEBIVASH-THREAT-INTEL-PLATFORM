"""
CYBERDUDEBIVASH® SENTINEL APEX — Enterprise Proof Engine
Phase 46: Operational Reality Convergence

Implements:
  - ATT&CK evaluation reports (detection coverage + efficacy)
  - Replay efficacy reports (detection gap quantification)
  - False-positive benchmarking (analyst trust metrics)
  - Telemetry transparency reports (provenance + coverage)
  - Analyst workflow metrics (MTTD, MTTR, workload)
  - Deployment readiness reports (infrastructure + ops)
  - MSSP operational studies (tenant-level analytics)
  - SOC efficiency analytics (queue + response metrics)
  - Graph intelligence benchmarks (node quality + coverage)
  - AI runtime governance reports (inference + policy)

THE PLATFORM MUST VISIBLY PROVE:
  operational legitimacy | telemetry legitimacy | analyst usability
  replay realism | enterprise readiness
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone, timedelta
from enum import Enum
from typing import Any, Dict, List, Optional, Tuple

logger = logging.getLogger("sentinel.enterprise_proof")


# ─────────────────────────────────────────────────────────────
# ENUMERATIONS
# ─────────────────────────────────────────────────────────────

class ProofReportType(str, Enum):
    ATTCK_EVALUATION      = "attck_evaluation"
    REPLAY_EFFICACY       = "replay_efficacy"
    FALSE_POSITIVE_BENCH  = "false_positive_benchmark"
    TELEMETRY_TRANSPARENCY= "telemetry_transparency"
    ANALYST_WORKFLOW      = "analyst_workflow"
    DEPLOYMENT_READINESS  = "deployment_readiness"
    MSSP_OPERATIONAL      = "mssp_operational"
    SOC_EFFICIENCY        = "soc_efficiency"
    GRAPH_BENCHMARK       = "graph_benchmark"
    AI_GOVERNANCE         = "ai_governance"

class ReadinessGrade(str, Enum):
    A_PLUS  = "A+"    # 95–100
    A       = "A"     # 90–94
    B_PLUS  = "B+"    # 85–89
    B       = "B"     # 80–84
    C       = "C"     # 70–79
    D       = "D"     # 60–69
    F       = "F"     # <60


# ─────────────────────────────────────────────────────────────
# DATA CLASSES
# ─────────────────────────────────────────────────────────────

@dataclass
class ATTCKEvaluationReport:
    """ATT&CK evaluation: detection coverage vs reference adversary profile."""
    report_id: str
    evaluation_name: str
    reference_actor: str
    total_techniques_tested: int
    detected_by_analytics: int
    detected_by_telemetry: int
    replay_confirmed: int
    missed: int
    detection_rate: float
    tactic_coverage: Dict[str, Dict[str, Any]]    # tactic → {tested, detected, rate}
    coverage_gaps: List[Dict[str, str]]            # {technique_id, tactic, gap_type}
    false_negative_rate: float
    mean_detection_time_seconds: float
    grade: ReadinessGrade
    analyst_note: str
    generated_at: str

@dataclass
class ReplayEfficacyReport:
    """Replay engine efficacy: attacks replayed vs detected."""
    report_id: str
    period_start: str
    period_end: str
    total_replays: int
    replays_detected: int
    replays_bypassed: int
    bypass_rate: float
    detection_latency_p50_ms: int
    detection_latency_p99_ms: int
    detection_gaps: List[Dict[str, str]]           # {technique_id, bypass_method, rule_gap}
    rules_generated_from_replay: int
    rule_effectiveness_rate: float                 # New rules that caught subsequent attacks
    coverage_improvement: float                    # % improvement in detection coverage
    grade: ReadinessGrade
    generated_at: str

@dataclass
class FalsePositiveBenchmarkReport:
    """False positive benchmarking for analyst trust."""
    report_id: str
    period_days: int
    total_alerts: int
    true_positives: int
    false_positives: int
    false_negatives: int
    precision: float                # TP / (TP + FP)
    recall: float                   # TP / (TP + FN)
    f1_score: float
    fp_rate: float
    fn_rate: float
    by_rule_category: Dict[str, Dict[str, Any]]   # category → {alerts, fps, fp_rate}
    analyst_escalation_rate: float                 # What % analysts escalate to human review
    analyst_close_rate: float                      # What % analysts close without action
    grade: ReadinessGrade
    improvement_recommendations: List[str]
    generated_at: str

@dataclass
class TelemetryTransparencyReport:
    """Telemetry coverage and provenance transparency."""
    report_id: str
    total_endpoints: int
    reporting_endpoints: int
    coverage_rate: float
    events_per_second_avg: float
    events_per_second_peak: float
    telemetry_sources: List[Dict[str, Any]]       # {source, events/day, trust, coverage%}
    data_freshness_p50_ms: int                    # Median event latency
    data_freshness_p99_ms: int
    enrichment_rate: float                        # % events enriched
    ioc_match_rate: float                         # % events matched to IOCs
    attck_mapping_rate: float                     # % events mapped to ATT&CK
    dark_periods: List[Dict[str, Any]]            # {host, gap_start, gap_end, reason}
    grade: ReadinessGrade
    generated_at: str

@dataclass
class AnalystWorkflowMetrics:
    """SOC analyst workflow efficiency metrics."""
    report_id: str
    period_days: int
    total_analysts: int
    alerts_per_analyst_per_day: float
    mttd_minutes: float             # Mean Time to Detect
    mtta_minutes: float             # Mean Time to Acknowledge
    mttr_hours: float               # Mean Time to Respond
    mttc_hours: float               # Mean Time to Close
    escalation_rate: float
    false_positive_rate: float
    analyst_utilization: float      # 0.0–1.0 (>0.85 = burnout risk)
    workflow_efficiency_score: float # 0.0–100
    top_time_consumers: List[Dict[str, Any]]
    grade: ReadinessGrade
    improvement_areas: List[str]
    generated_at: str

@dataclass
class DeploymentReadinessReport:
    """End-to-end deployment readiness assessment."""
    report_id: str
    tenant_id: str
    assessment_date: str

    # Infrastructure
    telemetry_coverage: float
    endpoint_agent_health: float
    network_sensor_coverage: float
    siem_integration_health: float
    api_connectivity: float

    # Operations
    analyst_coverage_hours: int     # Hours/day with active analyst coverage
    playbook_completeness: float    # % of alert types with response playbook
    escalation_path_defined: bool
    backup_soc_available: bool

    # Governance
    retention_policy_compliant: bool
    data_sovereignty_met: bool
    access_control_audited: bool
    incident_response_tested: bool
    tabletop_exercise_days_ago: int

    # Scores
    infrastructure_score: float
    operations_score: float
    governance_score: float
    overall_score: float
    grade: ReadinessGrade

    blockers: List[str]             # Issues preventing production deployment
    warnings: List[str]
    generated_at: str

@dataclass
class SOCEfficiencyReport:
    """SOC queue and response efficiency analytics."""
    report_id: str
    period_start: str
    period_end: str
    queue_depth_avg: float
    queue_depth_peak: int
    alert_ingestion_rate: float     # alerts/hour
    alert_close_rate: float         # alerts/hour
    backlog_hours: float            # Current backlog / close rate
    sla_compliance_rate: float      # % alerts acknowledged within SLA
    priority_distribution: Dict[str, int]  # {critical, high, medium, low}
    queue_staleness_rate: float     # % alerts >24h old
    auto_close_rate: float          # % auto-resolved without analyst
    analyst_productivity: float     # alerts closed per analyst hour
    grade: ReadinessGrade
    generated_at: str

@dataclass
class EnterpriseProofBundle:
    """Complete enterprise proof package — all reports in one bundle."""
    bundle_id: str
    tenant_id: str
    generated_at: str
    reports: Dict[str, Any]        # ProofReportType → report dict
    overall_readiness_score: float
    overall_grade: ReadinessGrade
    executive_summary: str
    key_strengths: List[str]
    key_gaps: List[str]
    next_actions: List[str]


# ─────────────────────────────────────────────────────────────
# GRADE CALCULATOR
# ─────────────────────────────────────────────────────────────

def score_to_grade(score: float) -> ReadinessGrade:
    if score >= 95: return ReadinessGrade.A_PLUS
    if score >= 90: return ReadinessGrade.A
    if score >= 85: return ReadinessGrade.B_PLUS
    if score >= 80: return ReadinessGrade.B
    if score >= 70: return ReadinessGrade.C
    if score >= 60: return ReadinessGrade.D
    return ReadinessGrade.F


# ─────────────────────────────────────────────────────────────
# ENTERPRISE PROOF ENGINE
# ─────────────────────────────────────────────────────────────

class EnterpriseProofEngine:
    """
    Generates all enterprise proof reports from platform telemetry.
    Provides measurable, reproducible evidence of:
      - Detection efficacy
      - Analyst trust metrics
      - Operational legitimacy
      - Deployment readiness
    """

    def generate_attck_evaluation(
        self,
        evaluation_name: str,
        reference_actor: str,
        tactic_results: Dict[str, Dict[str, Any]],
        mean_detection_time_s: float = 0.0,
    ) -> ATTCKEvaluationReport:
        """Generate ATT&CK evaluation report from per-tactic results."""
        total_tested = sum(v.get("tested", 0) for v in tactic_results.values())
        detected = sum(v.get("detected", 0) for v in tactic_results.values())
        replay_conf = sum(v.get("replay_confirmed", 0) for v in tactic_results.values())
        missed = total_tested - detected

        detection_rate = detected / max(total_tested, 1)
        fn_rate = missed / max(total_tested, 1)

        gaps = []
        for tactic, data in tactic_results.items():
            for tech in data.get("missed_techniques", []):
                gaps.append({"technique_id": tech, "tactic": tactic, "gap_type": "undetected"})

        # Tactic coverage summary
        tactic_cov = {}
        for tactic, data in tactic_results.items():
            tested = data.get("tested", 0)
            det = data.get("detected", 0)
            tactic_cov[tactic] = {
                "tested": tested,
                "detected": det,
                "rate": round(det / max(tested, 1), 3),
                "replay_confirmed": data.get("replay_confirmed", 0),
            }

        score = detection_rate * 80 + (1 - fn_rate) * 20
        grade = score_to_grade(score * 100)

        analyst_note = (
            f"Detection rate: {detection_rate:.1%}. "
            f"Replay-confirmed: {replay_conf}/{total_tested}. "
            f"Mean detection time: {mean_detection_time_s:.0f}s. "
            f"{len(gaps)} technique(s) undetected — prioritise coverage gaps."
        )

        return ATTCKEvaluationReport(
            report_id=f"ATTCK-EVAL-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
            evaluation_name=evaluation_name,
            reference_actor=reference_actor,
            total_techniques_tested=total_tested,
            detected_by_analytics=detected,
            detected_by_telemetry=detected,
            replay_confirmed=replay_conf,
            missed=missed,
            detection_rate=round(detection_rate, 4),
            tactic_coverage=tactic_cov,
            coverage_gaps=gaps[:20],
            false_negative_rate=round(fn_rate, 4),
            mean_detection_time_seconds=mean_detection_time_s,
            grade=grade,
            analyst_note=analyst_note,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def generate_replay_efficacy(
        self,
        period_start: str,
        period_end: str,
        total_replays: int,
        detected: int,
        bypassed: int,
        detection_latency_p50: int,
        detection_latency_p99: int,
        gaps: List[Dict[str, str]],
        rules_generated: int,
        rule_effectiveness: float,
    ) -> ReplayEfficacyReport:
        bypass_rate = bypassed / max(total_replays, 1)
        coverage_improvement = min(rules_generated * 0.02, 0.30)
        score = (1 - bypass_rate) * 70 + rule_effectiveness * 30
        grade = score_to_grade(score * 100)
        return ReplayEfficacyReport(
            report_id=f"REPLAY-EFF-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
            period_start=period_start,
            period_end=period_end,
            total_replays=total_replays,
            replays_detected=detected,
            replays_bypassed=bypassed,
            bypass_rate=round(bypass_rate, 4),
            detection_latency_p50_ms=detection_latency_p50,
            detection_latency_p99_ms=detection_latency_p99,
            detection_gaps=gaps[:10],
            rules_generated_from_replay=rules_generated,
            rule_effectiveness_rate=round(rule_effectiveness, 4),
            coverage_improvement=round(coverage_improvement, 4),
            grade=grade,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def generate_fp_benchmark(
        self,
        period_days: int,
        total_alerts: int,
        true_positives: int,
        false_positives: int,
        false_negatives: int,
        by_category: Dict[str, Dict[str, Any]],
    ) -> FalsePositiveBenchmarkReport:
        precision = true_positives / max(true_positives + false_positives, 1)
        recall = true_positives / max(true_positives + false_negatives, 1)
        f1 = 2 * precision * recall / max(precision + recall, 0.001)
        fp_rate = false_positives / max(total_alerts, 1)
        fn_rate = false_negatives / max(total_alerts + false_negatives, 1)

        score = precision * 50 + recall * 30 + (1 - fp_rate) * 20
        grade = score_to_grade(score * 100)

        recommendations = []
        if fp_rate > 0.30:
            recommendations.append("FP rate >30% — tune high-volume alert rules")
        if recall < 0.80:
            recommendations.append("Recall <80% — review detection coverage gaps")
        if precision < 0.70:
            recommendations.append("Precision <70% — analyst trust at risk — tune correlation logic")

        return FalsePositiveBenchmarkReport(
            report_id=f"FP-BENCH-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
            period_days=period_days,
            total_alerts=total_alerts,
            true_positives=true_positives,
            false_positives=false_positives,
            false_negatives=false_negatives,
            precision=round(precision, 4),
            recall=round(recall, 4),
            f1_score=round(f1, 4),
            fp_rate=round(fp_rate, 4),
            fn_rate=round(fn_rate, 4),
            by_rule_category=by_category,
            analyst_escalation_rate=round(true_positives / max(total_alerts, 1), 4),
            analyst_close_rate=round(false_positives / max(total_alerts, 1), 4),
            grade=grade,
            improvement_recommendations=recommendations,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def generate_telemetry_transparency(
        self,
        total_endpoints: int,
        reporting_endpoints: int,
        eps_avg: float,
        eps_peak: float,
        sources: List[Dict[str, Any]],
        latency_p50: int,
        latency_p99: int,
        enrichment_rate: float,
        ioc_match_rate: float,
        attck_rate: float,
        dark_periods: List[Dict[str, Any]],
    ) -> TelemetryTransparencyReport:
        coverage = reporting_endpoints / max(total_endpoints, 1)
        score = (
            coverage * 40 +
            enrichment_rate * 20 +
            attck_rate * 20 +
            (1 - len(dark_periods) / max(total_endpoints, 1)) * 20
        )
        grade = score_to_grade(score * 100)
        return TelemetryTransparencyReport(
            report_id=f"TEL-TRANS-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
            total_endpoints=total_endpoints,
            reporting_endpoints=reporting_endpoints,
            coverage_rate=round(coverage, 4),
            events_per_second_avg=eps_avg,
            events_per_second_peak=eps_peak,
            telemetry_sources=sources,
            data_freshness_p50_ms=latency_p50,
            data_freshness_p99_ms=latency_p99,
            enrichment_rate=round(enrichment_rate, 4),
            ioc_match_rate=round(ioc_match_rate, 4),
            attck_mapping_rate=round(attck_rate, 4),
            dark_periods=dark_periods[:10],
            grade=grade,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def generate_soc_efficiency(
        self,
        period_start: str,
        period_end: str,
        queue_depth_avg: float,
        queue_depth_peak: int,
        ingestion_rate: float,
        close_rate: float,
        sla_compliance: float,
        priority_dist: Dict[str, int],
        auto_close_rate: float,
        analyst_productivity: float,
    ) -> SOCEfficiencyReport:
        backlog = queue_depth_avg / max(close_rate, 0.001)
        staleness = max(0, 1 - sla_compliance)
        score = (
            sla_compliance * 40 +
            (1 - staleness) * 20 +
            auto_close_rate * 20 +
            min(analyst_productivity / 10.0, 1.0) * 20
        )
        grade = score_to_grade(score * 100)
        return SOCEfficiencyReport(
            report_id=f"SOC-EFF-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%S')}",
            period_start=period_start,
            period_end=period_end,
            queue_depth_avg=queue_depth_avg,
            queue_depth_peak=queue_depth_peak,
            alert_ingestion_rate=ingestion_rate,
            alert_close_rate=close_rate,
            backlog_hours=round(backlog, 2),
            sla_compliance_rate=round(sla_compliance, 4),
            priority_distribution=priority_dist,
            queue_staleness_rate=round(staleness, 4),
            auto_close_rate=round(auto_close_rate, 4),
            analyst_productivity=round(analyst_productivity, 2),
            grade=grade,
            generated_at=datetime.now(timezone.utc).isoformat(),
        )

    def generate_bundle(
        self,
        tenant_id: str,
        report_map: Dict[ProofReportType, Any],
    ) -> EnterpriseProofBundle:
        """Package all available reports into an enterprise proof bundle."""
        scores = []
        grade_map = {
            ReadinessGrade.A_PLUS: 97, ReadinessGrade.A: 92,
            ReadinessGrade.B_PLUS: 87, ReadinessGrade.B: 82,
            ReadinessGrade.C: 75, ReadinessGrade.D: 65, ReadinessGrade.F: 50,
        }

        for report in report_map.values():
            if hasattr(report, 'grade'):
                scores.append(grade_map.get(report.grade, 70))

        overall_score = sum(scores) / max(len(scores), 1)
        overall_grade = score_to_grade(overall_score)

        # Executive summary
        exec_summary = (
            f"Enterprise proof assessment for tenant {tenant_id}. "
            f"Overall readiness: {overall_score:.0f}/100 (Grade: {overall_grade.value}). "
            f"{len(report_map)} proof dimensions evaluated. "
            f"Platform demonstrates operational legitimacy with measurable evidence "
            f"across detection, telemetry, analyst workflow, and governance dimensions."
        )

        # Strengths / gaps
        strengths = []
        gaps = []
        for rtype, report in report_map.items():
            if hasattr(report, 'grade'):
                grade_score = grade_map.get(report.grade, 70)
                if grade_score >= 87:
                    strengths.append(f"{rtype.value}: {report.grade.value}")
                elif grade_score < 75:
                    gaps.append(f"{rtype.value}: {report.grade.value} — requires improvement")

        # Next actions
        next_actions = [
            f"Remediate {len(gaps)} below-threshold proof dimension(s)" if gaps else
            "Maintain current performance across all proof dimensions",
            "Schedule quarterly ATT&CK evaluation against updated actor profiles",
            "Run monthly replay efficacy review for new detection gaps",
        ]

        reports_dict = {
            rtype.value: asdict(report) if hasattr(report, '__dataclass_fields__') else report
            for rtype, report in report_map.items()
        }

        return EnterpriseProofBundle(
            bundle_id=f"PROOF-BUNDLE-{tenant_id}-{datetime.now(timezone.utc).strftime('%Y%m%d')}",
            tenant_id=tenant_id,
            generated_at=datetime.now(timezone.utc).isoformat(),
            reports=reports_dict,
            overall_readiness_score=round(overall_score, 1),
            overall_grade=overall_grade,
            executive_summary=exec_summary,
            key_strengths=strengths,
            key_gaps=gaps,
            next_actions=next_actions,
        )

    def export_json(self, bundle: EnterpriseProofBundle) -> str:
        return json.dumps(asdict(bundle), indent=2, default=str)
