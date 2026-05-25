#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/detection_drift_monitor.py — Detection Drift Monitoring Engine v162.0
================================================================================
Version : 162.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

PURPOSE:
  Monitors detection rules for quality/coverage drift over pipeline runs.
  Tracks: coverage regression, technique abandonment, FP rate inflation,
  format degradation, logsource category drift.

DRIFT CATEGORIES:
  ATT&CK Coverage Drift    — techniques no longer covered by new rules
  Format Coverage Drift    — rule formats going missing across runs
  FP Score Drift           — FP probability creeping upward
  Technique Depth Drift    — average techniques per rule declining
  Production Readiness Drift — gates_passed score declining over time
================================================================================
"""
from __future__ import annotations
import hashlib,json,logging,os,time
from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
from pathlib import Path
from typing import Any,Dict,List,Optional,Tuple

ENGINE_VERSION = "162.0.0"
ENGINE_ID      = "APEX-DDM"
log = logging.getLogger("apex.detection_drift")

DRIFT_THRESHOLD_CRITICAL = 20.0   # >20% decline = CRITICAL
DRIFT_THRESHOLD_WARN     = 10.0   # >10% decline = WARN
DRIFT_STATE_FILE         = "data/audit/detection_drift_state.json"
DRIFT_HISTORY_FILE       = "data/audit/detection_drift_history.json"


@dataclass
class DriftMetric:
    name: str
    current_value: float
    previous_value: float
    delta: float = 0.0
    delta_pct: float = 0.0
    status: str = "STABLE"      # STABLE | WARN | CRITICAL | IMPROVED
    direction: str = "FLAT"     # UP | DOWN | FLAT

    def __post_init__(self):
        self.delta = round(self.current_value - self.previous_value, 4)
        self.delta_pct = round((self.delta/self.previous_value*100) if self.previous_value!=0 else 0, 2)
        if self.delta > 0:
            self.direction = "UP"
            self.status = "IMPROVED"
        elif self.delta < 0:
            self.direction = "DOWN"
            if abs(self.delta_pct) >= DRIFT_THRESHOLD_CRITICAL:
                self.status = "CRITICAL"
            elif abs(self.delta_pct) >= DRIFT_THRESHOLD_WARN:
                self.status = "WARN"
            else:
                self.status = "STABLE"
        else:
            self.direction = "FLAT"
            self.status = "STABLE"

    def to_dict(self): return asdict(self)


@dataclass
class DriftReport:
    run_id: str
    timestamp: str
    overall_status: str = "STABLE"  # STABLE | WARN | CRITICAL | IMPROVED
    metrics: List[DriftMetric] = field(default_factory=list)
    critical_drifts: List[str] = field(default_factory=list)
    warn_drifts: List[str]     = field(default_factory=list)
    improvements: List[str]    = field(default_factory=list)
    drift_score: float = 0.0   # 0=stable, higher=more drift
    recommendations: List[str] = field(default_factory=list)
    engine_version: str = ENGINE_VERSION

    def compute_overall(self):
        for m in self.metrics:
            if m.status == "CRITICAL": self.critical_drifts.append(f"{m.name}: {m.delta_pct:+.1f}%")
            elif m.status == "WARN":   self.warn_drifts.append(f"{m.name}: {m.delta_pct:+.1f}%")
            elif m.status == "IMPROVED": self.improvements.append(f"{m.name}: {m.delta_pct:+.1f}%")

        if self.critical_drifts:   self.overall_status = "CRITICAL"
        elif self.warn_drifts:     self.overall_status = "WARN"
        elif self.improvements:    self.overall_status = "IMPROVED"
        else:                      self.overall_status = "STABLE"

        negative = [m for m in self.metrics if m.status in ("WARN","CRITICAL")]
        self.drift_score = sum(abs(m.delta_pct) for m in negative)

        if self.critical_drifts:
            self.recommendations.append("CRITICAL DRIFT: Immediately review detection generation pipeline — quality has regressed")
        if self.warn_drifts:
            self.recommendations.append("WARN DRIFT: Review recent changes to detection templates or ATT&CK mapping logic")
        if not self.critical_drifts and not self.warn_drifts:
            self.recommendations.append("Detection quality is stable — continue monitoring")

    def to_dict(self): return asdict(self)


class DetectionStateSnapshot:
    """Captures detection quality state from validation results."""

    def capture(self, validation_results:List[Dict]) -> Dict:
        """Build state snapshot from a list of ValidationResult dicts."""
        if not validation_results:
            return {}

        total = len(validation_results)
        production_ready = sum(1 for r in validation_results if r.get("production_ready",False))
        all_techniques = []
        all_formats = []
        fp_scores = []
        gates_passed = []
        coverage_scores = []

        for r in validation_results:
            all_techniques.extend(r.get("attack_techniques",[]))
            all_formats.append(r.get("rule_format","unknown"))
            fp = r.get("fp_probability_score",50)
            if fp: fp_scores.append(fp)
            gp = r.get("gates_passed",0)
            gt = r.get("gates_total",10)
            if gt: gates_passed.append(gp/gt*100)
            cs = r.get("coverage_score",0)
            if cs: coverage_scores.append(cs)

        unique_techniques = list(set(all_techniques))
        unique_formats    = list(set(all_formats))

        return {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "total_rules": total,
            "production_ready_count": production_ready,
            "production_ready_pct": round(production_ready/total*100 if total>0 else 0,2),
            "unique_techniques_covered": len(unique_techniques),
            "techniques_list": unique_techniques,
            "formats_covered": unique_formats,
            "format_count": len(unique_formats),
            "avg_fp_probability": round(sum(fp_scores)/len(fp_scores) if fp_scores else 50,2),
            "avg_gates_passed_pct": round(sum(gates_passed)/len(gates_passed) if gates_passed else 0,2),
            "avg_coverage_score": round(sum(coverage_scores)/len(coverage_scores) if coverage_scores else 0,2),
            "techniques_per_rule": round(len(all_techniques)/total if total>0 else 0,2),
        }


class DetectionDriftMonitor:
    """Compares current state to baseline and detects quality drift."""

    def __init__(self, repo_root:str="."):
        self.repo_root  = repo_root
        self.state_file = os.path.join(repo_root, DRIFT_STATE_FILE)
        self.hist_file  = os.path.join(repo_root, DRIFT_HISTORY_FILE)
        self.snapshotter = DetectionStateSnapshot()

    def load_baseline(self) -> Optional[Dict]:
        """Load previous state from disk."""
        if os.path.exists(self.state_file):
            try:
                with open(self.state_file,"r",encoding="utf-8") as f:
                    return json.load(f)
            except Exception as e:
                log.warning(f"[DDM] Could not load drift state: {e}")
        return None

    def save_state(self, state:Dict):
        """Persist current state as new baseline."""
        os.makedirs(os.path.dirname(self.state_file), exist_ok=True)
        with open(self.state_file,"w",encoding="utf-8") as f:
            json.dump(state, f, indent=2)
        # Append to history
        history=[]
        if os.path.exists(self.hist_file):
            try:
                with open(self.hist_file,"r",encoding="utf-8") as f:
                    history = json.load(f)
            except: pass
        history.append(state)
        history = history[-50:]  # Keep last 50 runs
        with open(self.hist_file,"w",encoding="utf-8") as f:
            json.dump(history, f, indent=2)

    def detect_drift(self, current_results:List[Dict], run_id:str="") -> DriftReport:
        """Main entry: detect drift between current run and baseline."""
        if not run_id:
            run_id = f"run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

        current_state = self.snapshotter.capture(current_results)
        baseline      = self.load_baseline()

        report = DriftReport(
            run_id=run_id,
            timestamp=datetime.now(timezone.utc).isoformat()
        )

        if not baseline:
            # No baseline — establish one
            log.info(f"[DDM] No baseline found — establishing new detection baseline")
            self.save_state(current_state)
            report.overall_status = "BASELINE_ESTABLISHED"
            report.recommendations.append("Baseline established — subsequent runs will detect drift against this snapshot")
            report.drift_score = 0.0
            return report

        # Compare key metrics
        metric_defs = [
            ("production_ready_pct",     "Production Ready %",      True),   # Higher = better
            ("unique_techniques_covered","ATT&CK Technique Coverage",True),
            ("format_count",             "Rule Format Coverage",     True),
            ("avg_gates_passed_pct",     "Avg Gates Passed %",       True),
            ("avg_coverage_score",       "Avg Coverage Score",       True),
            ("techniques_per_rule",      "Techniques Per Rule",      True),
            ("avg_fp_probability",       "Avg FP Probability",       False), # Lower = better
        ]

        for key, label, higher_is_better in metric_defs:
            curr = float(current_state.get(key,0))
            prev = float(baseline.get(key,0))
            if not higher_is_better:
                # Invert so we can use same drift logic (increase = bad)
                dm = DriftMetric(name=label, current_value=100-curr, previous_value=100-prev)
                dm.name = label  # re-set after inversion
            else:
                dm = DriftMetric(name=label, current_value=curr, previous_value=prev)
            report.metrics.append(dm)

        # Technique disappearance check
        prev_techs = set(baseline.get("techniques_list",[]))
        curr_techs = set(current_state.get("techniques_list",[]))
        dropped_techs = prev_techs - curr_techs
        new_techs     = curr_techs - prev_techs
        if dropped_techs:
            report.warn_drifts.append(f"Techniques no longer covered: {', '.join(list(dropped_techs)[:5])}")
        if new_techs:
            report.improvements.append(f"New techniques now covered: {', '.join(list(new_techs)[:5])}")

        # Format disappearance check
        prev_fmts = set(baseline.get("formats_covered",[]))
        curr_fmts = set(current_state.get("formats_covered",[]))
        dropped_fmts = prev_fmts - curr_fmts
        if dropped_fmts:
            report.critical_drifts.append(f"Rule formats no longer generated: {', '.join(dropped_fmts)}")

        report.compute_overall()
        self.save_state(current_state)
        return report

    def get_drift_history(self) -> List[Dict]:
        """Return historical drift data."""
        if os.path.exists(self.hist_file):
            try:
                with open(self.hist_file,"r",encoding="utf-8") as f:
                    return json.load(f)
            except: pass
        return []


if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    monitor = DetectionDriftMonitor(repo_root="/tmp/apex_test")
    # Simulate current run with some results
    mock_results = [
        {"production_ready":True,"attack_techniques":["T1190","T1059"],
         "rule_format":"sigma","fp_probability_score":25,"gates_passed":8,"gates_total":10,"coverage_score":70},
        {"production_ready":True,"attack_techniques":["T1055","T1078"],
         "rule_format":"kql","fp_probability_score":20,"gates_passed":9,"gates_total":10,"coverage_score":75},
    ]
    report = monitor.detect_drift(mock_results, run_id="test-run-001")
    print(json.dumps(report.to_dict(),indent=2,default=str))
    print(f"\n[DDM] Drift Status: {report.overall_status} | Score: {report.drift_score}")
