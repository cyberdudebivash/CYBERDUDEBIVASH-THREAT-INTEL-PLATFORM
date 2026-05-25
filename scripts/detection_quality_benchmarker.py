#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/detection_quality_benchmarker.py — Detection Quality Benchmarking v162.0
================================================================================
Version : 162.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

PURPOSE:
  Benchmarks detection rule quality against SOC-grade standards.
  Produces enterprise confidence scores, quality grades, and
  peer comparison against industry frameworks (Sigma Mature Rules,
  CISA CSET, MITRE D3FEND standards).

BENCHMARK DIMENSIONS (10):
  D1: Syntactic Correctness   (0-100)
  D2: ATT&CK Coverage Depth   (0-100)
  D3: FP Resilience Score     (0-100)
  D4: Telemetry Completeness  (0-100)
  D5: Tuning Guidance Quality (0-100)
  D6: Multi-Platform Reach    (0-100)
  D7: Retro-Hunt Coverage     (0-100)
  D8: Deployment Readiness    (0-100)
  D9: Documentation Quality   (0-100)
  D10: Adversary Correlation  (0-100)

QUALITY GRADES: S | A | B | C | D | F
================================================================================
"""
from __future__ import annotations
import json,logging,re,statistics
from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
from typing import Any,Dict,List,Optional

ENGINE_VERSION = "162.0.0"
ENGINE_ID      = "APEX-DQB"
log = logging.getLogger("apex.quality_benchmarker")

GRADE_THRESHOLDS = {
    "S": 90, "A": 80, "B": 70, "C": 60, "D": 50, "F": 0
}

INDUSTRY_BENCHMARKS = {
    "sigma_mature_rule": {
        "syntactic": 95, "attack_coverage": 85, "fp_resilience": 75,
        "telemetry": 80, "tuning": 70, "platforms": 60,
        "retro_hunt": 50, "deployment": 85, "documentation": 80, "adversary": 65,
    },
    "cisa_best_practice": {
        "syntactic": 100, "attack_coverage": 90, "fp_resilience": 80,
        "telemetry": 85, "tuning": 85, "platforms": 70,
        "retro_hunt": 65, "deployment": 90, "documentation": 85, "adversary": 75,
    },
    "apex_enterprise": {
        "syntactic": 90, "attack_coverage": 80, "fp_resilience": 70,
        "telemetry": 75, "tuning": 75, "platforms": 65,
        "retro_hunt": 60, "deployment": 80, "documentation": 75, "adversary": 70,
    }
}


@dataclass
class BenchmarkDimension:
    name: str
    score: float         # 0-100
    max_score: float = 100.0
    weight: float = 1.0
    findings: List[str] = field(default_factory=list)
    benchmark_delta: float = 0.0  # vs industry benchmark

    @property
    def weighted_score(self) -> float:
        return self.score * self.weight

    def to_dict(self): return asdict(self)


@dataclass
class QualityBenchmarkResult:
    rule_id: str
    advisory_id: str
    rule_format: str
    title: str = ""
    dimensions: List[BenchmarkDimension] = field(default_factory=list)
    composite_score: float = 0.0
    grade: str = "F"
    enterprise_confidence: float = 0.0
    soc_ready: bool = False
    benchmark_comparison: Dict[str,float] = field(default_factory=dict)
    improvement_plan: List[str] = field(default_factory=list)
    strengths: List[str] = field(default_factory=list)
    weaknesses: List[str] = field(default_factory=list)
    benchmarked_at: str = ""
    engine_version: str = ENGINE_VERSION

    def compute(self):
        if not self.dimensions: return
        total_weight = sum(d.weight for d in self.dimensions)
        weighted_sum = sum(d.weighted_score for d in self.dimensions)
        self.composite_score = round(weighted_sum/total_weight if total_weight>0 else 0, 2)

        for grade, threshold in sorted(GRADE_THRESHOLDS.items(), key=lambda x: -x[1]):
            if self.composite_score >= threshold:
                self.grade = grade
                break

        self.enterprise_confidence = min(100.0, self.composite_score * 1.05)
        self.soc_ready = self.composite_score >= 70 and self.grade in ("S","A","B")
        self.benchmarked_at = datetime.now(timezone.utc).isoformat()

        # Strengths and weaknesses
        sorted_dims = sorted(self.dimensions, key=lambda d: d.score, reverse=True)
        self.strengths  = [f"{d.name}: {d.score:.0f}/100 ({'+' if d.benchmark_delta>=0 else ''}{d.benchmark_delta:.0f} vs benchmark)" for d in sorted_dims[:3]]
        self.weaknesses = [f"{d.name}: {d.score:.0f}/100 (needs +{100-d.score:.0f} to max)" for d in sorted_dims[-3:] if d.score < 80]

    def to_dict(self): return asdict(self)


class DetectionQualityBenchmarker:
    """Benchmarks detection rules across 10 quality dimensions."""

    DIMENSION_WEIGHTS = {
        "syntactic_correctness":   2.0,   # Most important — broken rules deploy silently
        "attack_coverage_depth":   1.8,
        "fp_resilience":           1.5,
        "telemetry_completeness":  1.5,
        "tuning_guidance_quality": 1.2,
        "multi_platform_reach":    1.0,
        "retro_hunt_coverage":     1.0,
        "deployment_readiness":    1.5,
        "documentation_quality":   0.8,
        "adversary_correlation":   1.2,
    }

    def benchmark(self, validation_result:Dict, normalized_ruleset:Optional[Dict]=None,
                  telemetry_mapping:Optional[Dict]=None, advisory:Optional[Dict]=None) -> QualityBenchmarkResult:
        """Run full quality benchmark on a validated detection rule."""

        rule_id  = validation_result.get("rule_id","")
        adv_id   = validation_result.get("advisory_id","")
        fmt      = validation_result.get("rule_format","")
        title    = validation_result.get("title","")

        result = QualityBenchmarkResult(
            rule_id=rule_id, advisory_id=adv_id,
            rule_format=fmt, title=title
        )

        # D1: Syntactic Correctness
        d1 = self._score_syntax(validation_result)
        result.dimensions.append(d1)

        # D2: ATT&CK Coverage Depth
        d2 = self._score_attack(validation_result, advisory or {})
        result.dimensions.append(d2)

        # D3: FP Resilience
        d3 = self._score_fp_resilience(validation_result)
        result.dimensions.append(d3)

        # D4: Telemetry Completeness
        d4 = self._score_telemetry(validation_result, telemetry_mapping or {})
        result.dimensions.append(d4)

        # D5: Tuning Guidance Quality
        d5 = self._score_tuning(validation_result)
        result.dimensions.append(d5)

        # D6: Multi-Platform Reach
        d6 = self._score_platforms(normalized_ruleset or {})
        result.dimensions.append(d6)

        # D7: Retro-Hunt Coverage
        d7 = self._score_retro_hunt(validation_result)
        result.dimensions.append(d7)

        # D8: Deployment Readiness
        d8 = self._score_deployment(validation_result, normalized_ruleset or {})
        result.dimensions.append(d8)

        # D9: Documentation Quality
        d9 = self._score_documentation(validation_result, advisory or {})
        result.dimensions.append(d9)

        # D10: Adversary Correlation
        d10 = self._score_adversary(advisory or {}, validation_result)
        result.dimensions.append(d10)

        # Compute benchmark deltas vs APEX enterprise benchmark
        apex_bench = INDUSTRY_BENCHMARKS["apex_enterprise"]
        bench_keys = ["syntactic","attack_coverage","fp_resilience","telemetry",
                      "tuning","platforms","retro_hunt","deployment","documentation","adversary"]
        for dim, bench_key in zip(result.dimensions, bench_keys):
            bench_val = apex_bench.get(bench_key, 70)
            dim.benchmark_delta = round(dim.score - bench_val, 2)
            result.benchmark_comparison[dim.name] = dim.score

        # Improvement plan
        weak_dims = sorted(result.dimensions, key=lambda d: d.score)[:4]
        for dim in weak_dims:
            if dim.score < 70 and dim.findings:
                result.improvement_plan.append(f"Improve {dim.name}: {dim.findings[0]}")

        result.compute()
        return result

    def benchmark_batch(self, validation_results:List[Dict],
                       advisories:Optional[List[Dict]]=None) -> Dict:
        """Benchmark a full batch of validation results."""
        adv_map = {}
        if advisories:
            for adv in advisories:
                adv_map[adv.get("stix_id","")] = adv

        benchmark_results=[]
        scores=[]
        grades={"S":0,"A":0,"B":0,"C":0,"D":0,"F":0}

        for vr in validation_results:
            adv = adv_map.get(vr.get("advisory_id",""),{})
            br  = self.benchmark(vr, advisory=adv)
            benchmark_results.append(br.to_dict())
            scores.append(br.composite_score)
            grades[br.grade] = grades.get(br.grade,0) + 1

        avg_score   = round(statistics.mean(scores) if scores else 0, 2)
        soc_ready   = sum(1 for r in benchmark_results if r.get("soc_ready"))
        avg_grade   = self._score_to_grade(avg_score)

        return {
            "engine_version": ENGINE_VERSION,
            "benchmarked_at": datetime.now(timezone.utc).isoformat(),
            "total_rules": len(validation_results),
            "average_score": avg_score,
            "average_grade": avg_grade,
            "soc_ready_count": soc_ready,
            "soc_ready_pct": round(soc_ready/len(validation_results)*100 if validation_results else 0,2),
            "grade_distribution": grades,
            "results": benchmark_results
        }

    # ── Dimension Scorers ────────────────────────────────────────────────────

    def _score_syntax(self, vr:Dict) -> BenchmarkDimension:
        findings=[]
        score = 0.0
        if vr.get("gate_syntax"):
            score = 100.0
        else:
            errs = vr.get("syntax_errors",[])
            score = max(0.0, 100 - len(errs)*20)
            findings.extend(errs[:3])
        if vr.get("rule_fingerprint"):
            score = min(score, 95)  # Fingerprinted = good
        return BenchmarkDimension(
            name="syntactic_correctness", score=round(score,2),
            weight=self.DIMENSION_WEIGHTS["syntactic_correctness"],
            findings=findings
        )

    def _score_attack(self, vr:Dict, advisory:Dict) -> BenchmarkDimension:
        findings=[]
        techs = vr.get("attack_techniques",[])
        score = 0.0
        if len(techs) == 0:
            score = 0.0
            findings.append("No ATT&CK techniques mapped — critical gap")
        elif len(techs) == 1:
            score = 55.0
            findings.append("Single technique — add sub-technique for precision")
        elif len(techs) == 2:
            score = 70.0
        elif len(techs) >= 3:
            score = 85.0
        if len(techs) >= 5:
            score = min(100.0, score + 10)
        # Check for sub-techniques (T1059.001 style)
        sub_techs = [t for t in techs if "." in t]
        if sub_techs:
            score = min(100.0, score + 5)
        else:
            findings.append("Use sub-techniques (e.g. T1059.001) for higher detection precision")
        return BenchmarkDimension(
            name="attack_coverage_depth", score=round(score,2),
            weight=self.DIMENSION_WEIGHTS["attack_coverage_depth"],
            findings=findings
        )

    def _score_fp_resilience(self, vr:Dict) -> BenchmarkDimension:
        findings=[]
        fp_prob = float(vr.get("fp_probability_score",50))
        # Invert: low FP probability = high resilience
        score = max(0.0, 100 - fp_prob)
        if fp_prob > 60:
            findings.append(f"High FP probability ({fp_prob:.0f}%) — add allowlist conditions")
        elif fp_prob > 40:
            findings.append(f"Medium FP probability ({fp_prob:.0f}%) — consider threshold tuning")
        else:
            findings.append(f"Good FP resilience (FP: {fp_prob:.0f}%)")
        tuning = vr.get("tuning_recommendations",[])
        if not tuning:
            findings.append("Missing tuning recommendations")
            score = max(0.0, score - 10)
        return BenchmarkDimension(
            name="fp_resilience", score=round(score,2),
            weight=self.DIMENSION_WEIGHTS["fp_resilience"],
            findings=findings
        )

    def _score_telemetry(self, vr:Dict, tm:Dict) -> BenchmarkDimension:
        findings=[]
        deps = vr.get("telemetry_deps",[])
        score = 0.0
        if not deps:
            score = 0.0
            findings.append("No telemetry dependencies declared")
        elif len(deps) == 1:
            score = 50.0
            findings.append("Single telemetry source — add alternatives for resilience")
        elif len(deps) == 2:
            score = 70.0
        elif len(deps) >= 3:
            score = 85.0
        # Telemetry mapping bonus
        feasibility = tm.get("deployment_feasibility_score",0) if isinstance(tm,dict) else 0
        score = min(100.0, score + feasibility*0.15)
        if feasibility < 50:
            findings.append(f"Low deployment feasibility ({feasibility:.0f}%) — deploy required agents")
        return BenchmarkDimension(
            name="telemetry_completeness", score=round(score,2),
            weight=self.DIMENSION_WEIGHTS["telemetry_completeness"],
            findings=findings
        )

    def _score_tuning(self, vr:Dict) -> BenchmarkDimension:
        findings=[]
        recs = vr.get("tuning_recommendations",[])
        score = 0.0
        if not recs:
            score = 10.0
            findings.append("No tuning recommendations generated")
        elif len(recs) == 1:
            score = 50.0
        elif len(recs) == 2:
            score = 70.0
        elif len(recs) >= 3:
            score = 90.0
        # Quality of recommendations
        actionable = sum(1 for r in recs if any(keyword in r.lower()
                         for keyword in ["add","deploy","scope","filter","monitor","threshold"]))
        score = min(100.0, score + actionable * 5)
        if not findings:
            findings.append(f"{len(recs)} actionable tuning recommendations present")
        return BenchmarkDimension(
            name="tuning_guidance_quality", score=round(score,2),
            weight=self.DIMENSION_WEIGHTS["tuning_guidance_quality"],
            findings=findings
        )

    def _score_platforms(self, nr:Dict) -> BenchmarkDimension:
        findings=[]
        platforms = nr.get("platforms_generated",[]) if nr else []
        count = len(platforms)
        score = min(100.0, count * 10)
        if count == 0:
            findings.append("No platform normalization generated — only Sigma available")
        elif count < 3:
            findings.append(f"Limited platform coverage ({count} platforms) — add KQL, SPL, EQL")
        elif count < 6:
            findings.append(f"Good platform coverage ({count} platforms)")
        else:
            findings.append(f"Excellent platform coverage ({count} platforms)")
        return BenchmarkDimension(
            name="multi_platform_reach", score=round(score,2),
            weight=self.DIMENSION_WEIGHTS["multi_platform_reach"],
            findings=findings
        )

    def _score_retro_hunt(self, vr:Dict) -> BenchmarkDimension:
        findings=[]
        has_retro = bool(vr.get("retro_hunt_query",""))
        gate_rh   = vr.get("gate_retro_hunt",False)
        score = 0.0
        if has_retro and len(vr.get("retro_hunt_query","")) > 100:
            score = 85.0
            findings.append("KQL retro-hunt query present")
        elif gate_rh:
            score = 65.0
            findings.append("Retro-hunt gate passed (binary format — no KQL needed)")
        else:
            score = 20.0
            findings.append("No retro-hunt query — add for threat hunting enablement")
        return BenchmarkDimension(
            name="retro_hunt_coverage", score=round(score,2),
            weight=self.DIMENSION_WEIGHTS["retro_hunt_coverage"],
            findings=findings
        )

    def _score_deployment(self, vr:Dict, nr:Dict) -> BenchmarkDimension:
        findings=[]
        prod_ready   = vr.get("production_ready",False)
        gates_passed = vr.get("gates_passed",0)
        gates_total  = vr.get("gates_total",10)
        envs         = vr.get("deployment_environments",[])
        platforms    = nr.get("platforms_generated",[]) if nr else []
        dep_notes    = nr.get("deployment_notes",{}) if nr else {}

        score = (gates_passed/gates_total*60) if gates_total>0 else 0
        if prod_ready: score += 20
        if envs:       score += min(10, len(envs)*2)
        if dep_notes:  score += 10

        if not prod_ready:
            findings.append(f"Not production-ready — {gates_total-gates_passed} gates failing")
        if not envs:
            findings.append("No deployment environments tagged")
        if not dep_notes:
            findings.append("No deployment notes/guidance generated")
        else:
            findings.append(f"Deployment notes present for: {', '.join(list(dep_notes.keys())[:3])}")

        return BenchmarkDimension(
            name="deployment_readiness", score=min(100.0,round(score,2)),
            weight=self.DIMENSION_WEIGHTS["deployment_readiness"],
            findings=findings
        )

    def _score_documentation(self, vr:Dict, advisory:Dict) -> BenchmarkDimension:
        findings=[]
        score = 40.0  # Base
        if advisory.get("title"):           score += 10
        if advisory.get("description"):     score += 10
        if vr.get("attack_techniques"):     score += 10
        if advisory.get("cves") or re.search(r'CVE-\d',str(advisory.get("title",""))): score += 5
        if advisory.get("actor_tag","") or advisory.get("actor",""):           score += 5
        if advisory.get("threat_type"):     score += 5
        if advisory.get("source_url"):      score += 5
        if not advisory:
            findings.append("No advisory metadata linked to rule")
            score = 30.0
        else:
            findings.append("Advisory metadata linked")
        return BenchmarkDimension(
            name="documentation_quality", score=min(100.0,round(score,2)),
            weight=self.DIMENSION_WEIGHTS["documentation_quality"],
            findings=findings
        )

    def _score_adversary(self, advisory:Dict, vr:Dict) -> BenchmarkDimension:
        findings=[]
        score = 20.0
        actor = advisory.get("actor_tag","") or advisory.get("actor","")
        techs = vr.get("attack_techniques",[])
        if actor and actor not in ("CDB-UNATTR-CVE","CDB-UNATTR-PHI","UNKNOWN"):
            score += 30
            findings.append(f"Known actor attribution: {actor}")
        elif actor:
            score += 10
            findings.append("Generic actor cluster — no specific group attribution")
        if techs:
            score += min(30, len(techs)*10)
        kev = advisory.get("kev_present",False) or advisory.get("kev",False)
        if kev:
            score += 20
            findings.append("KEV-listed — known active exploitation")
        epss = float(advisory.get("epss_score") or advisory.get("epss",0) or 0)
        if epss > 0.1:
            score += 10
            findings.append(f"High EPSS ({epss*100:.1f}%) — likely exploitation")
        if not findings:
            findings.append("No adversary correlation data available")
        return BenchmarkDimension(
            name="adversary_correlation", score=min(100.0,round(score,2)),
            weight=self.DIMENSION_WEIGHTS["adversary_correlation"],
            findings=findings
        )

    def _score_to_grade(self, score:float) -> str:
        for grade, threshold in sorted(GRADE_THRESHOLDS.items(), key=lambda x: -x[1]):
            if score >= threshold: return grade
        return "F"


def benchmark_detection_pack(validation_pack:Dict, advisory:Dict={}) -> Dict:
    """Pipeline entry point: benchmark a full advisory detection pack."""
    benchmarker = DetectionQualityBenchmarker()
    results_by_format = validation_pack.get("results_by_format",{})
    if not results_by_format:
        # Single rule validation result
        br = benchmarker.benchmark(validation_pack, advisory=advisory)
        return br.to_dict()

    all_results=[]
    for fmt, vr in results_by_format.items():
        br = benchmarker.benchmark(vr, advisory=advisory)
        all_results.append(br.to_dict())

    scores = [r["composite_score"] for r in all_results]
    avg    = round(sum(scores)/len(scores) if scores else 0, 2)
    return {"advisory_id":advisory.get("stix_id",""),
            "pack_average_score":avg,
            "pack_grade":benchmarker._score_to_grade(avg),
            "format_results":all_results,
            "engine_version":ENGINE_VERSION}


if __name__=="__main__":
    logging.basicConfig(level=logging.INFO)
    benchmarker = DetectionQualityBenchmarker()
    mock_vr = {
        "rule_id":"apex-sigma-test","advisory_id":"intel--test001",
        "rule_format":"sigma","title":"APEX SSRF Test Rule",
        "gate_syntax":True,"gate_attack_mapping":True,"gate_telemetry_deps":True,
        "gate_fp_probability":True,"gate_tuning_recs":True,"gate_logsource":True,
        "gate_uniqueness":True,"gate_coverage_score":True,"gate_retro_hunt":True,
        "gate_deployment_env":True,"gates_passed":10,"gates_total":10,
        "production_ready":True,"fp_probability_score":25,
        "attack_techniques":["T1190","T1059.001"],"coverage_score":75,
        "telemetry_deps":["Sysmon EventID 1","Defender XDR Process Telemetry"],
        "tuning_recommendations":["Add exclusions for scanners","Monitor first 48h","Baseline 7 days"],
        "deployment_environments":["Microsoft Sentinel","Splunk ES"],
        "retro_hunt_query":"// KQL retro-hunt query...",
    }
    mock_adv = {"stix_id":"intel--test001","title":"KnowledgeDeliver Zero-Day",
                "actor":"CDB-RU-02","kev":True,"epss":0.08,
                "threat_type":"Vulnerability","source_url":"https://example.com"}
    result = benchmarker.benchmark(mock_vr, advisory=mock_adv)
    print(f"[DQB] Score: {result.composite_score} | Grade: {result.grade} | SOC-Ready: {result.soc_ready}")
    for dim in result.dimensions:
        print(f"  {dim.name:30s} {dim.score:5.1f}/100  Δ{dim.benchmark_delta:+.1f}")
    print(f"\nStrengths: {result.strengths}")
    print(f"Weaknesses: {result.weaknesses}")
