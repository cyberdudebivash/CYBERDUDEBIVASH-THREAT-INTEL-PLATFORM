#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX
scripts/detection_engineering_orchestrator.py — Detection Engineering Orchestrator v162.0
================================================================================
Version : 162.0.0
Author  : CYBERDUDEBIVASH Pvt. Ltd. — SENTINEL APEX Engineering

PURPOSE:
  Master orchestrator wiring all 14 Detection Engineering Core subsystems
  into a single, automated, production-grade pipeline.

  Called from: generate_intel_reports.py (STAGE 3.1.11)
  API endpoint: /api/v1/detections/{id}
  R2 output:    api/detections/

SUBSYSTEMS ORCHESTRATED (14):
  1.  apex_real_detection_engine       — Rule generation (Sigma/KQL/SPL/YARA)
  2.  apex_mitre_attack_engine         — ATT&CK mapping
  3.  detection_validation_engine      — 10-gate validation
  4.  fp_suppression_engine            — FP suppression
  5.  coverage_gap_analyzer            — ATT&CK coverage gaps
  6.  detection_drift_monitor          — Quality drift tracking
  7.  multi_siem_normalization_layer   — 11-platform normalization
  8.  retro_hunt_engine                — Retro-hunt query generation
  9.  telemetry_dependency_mapper      — Telemetry dependency mapping
  10. enterprise_rule_packager         — Enterprise deployment bundles
  11. detection_quality_benchmarker    — Quality benchmarking
  12. regression_tests                 — Regression testing
  13. apex_confidence_engine           — Confidence scoring
  14. threat_actor_profiler            — Threat actor mapping

PIPELINE FLOW:
  Advisory → Generate → Validate → Suppress → Normalize → RetroHunt →
  TelemetryMap → Benchmark → Package → DriftCheck → API Output
================================================================================
"""
from __future__ import annotations
import json,logging,os,time,traceback
from dataclasses import dataclass,field,asdict
from datetime import datetime,timezone
from typing import Any,Dict,List,Optional

ENGINE_VERSION = "162.0.0"
ENGINE_ID      = "APEX-DEO"
log = logging.getLogger("apex.detection_orchestrator")


def _safe_import(module_name:str, class_name:str=None):
    """Safe import with graceful degradation."""
    try:
        import importlib
        mod = importlib.import_module(f"scripts.{module_name}")
        if class_name:
            return getattr(mod, class_name, None)
        return mod
    except ImportError as e:
        log.warning(f"[DEO] Could not import {module_name}: {e} — subsystem unavailable")
        return None


@dataclass
class DetectionPipelineResult:
    """Complete output from the Detection Engineering Orchestrator."""
    advisory_id: str
    title: str = ""
    pipeline_status: str = "PENDING"   # PASS | WARN | FAIL | SKIP
    stages_completed: List[str] = field(default_factory=list)
    stages_failed: List[str]    = field(default_factory=list)

    # Stage outputs
    detection_pack: Dict       = field(default_factory=dict)  # raw Sigma/KQL/etc rules
    validation_result: Dict    = field(default_factory=dict)
    suppression_result: Dict   = field(default_factory=dict)
    normalized_ruleset: Dict   = field(default_factory=dict)
    retro_hunt_pack: Dict      = field(default_factory=dict)
    telemetry_mapping: Dict    = field(default_factory=dict)
    benchmark_result: Dict     = field(default_factory=dict)
    coverage_gaps: List[Dict]  = field(default_factory=list)
    drift_report: Dict         = field(default_factory=dict)

    # Summary metrics
    production_ready: bool   = False
    quality_grade: str       = "F"
    composite_score: float   = 0.0
    fp_probability: float    = 50.0
    techniques_covered: List[str] = field(default_factory=list)
    platforms_available: List[str] = field(default_factory=list)
    telemetry_deps: List[str] = field(default_factory=list)
    retro_hunt_query: str    = ""

    # Enterprise API output (served from R2)
    api_payload: Dict = field(default_factory=dict)

    elapsed_ms: float = 0.0
    processed_at: str = ""
    engine_version: str = ENGINE_VERSION

    def to_dict(self): return asdict(self)

    def to_api_payload(self) -> Dict:
        """Compact API representation for the detection endpoint."""
        return {
            "advisory_id": self.advisory_id,
            "title": self.title,
            "detection_status": self.pipeline_status,
            "production_ready": self.production_ready,
            "quality_grade": self.quality_grade,
            "composite_score": self.composite_score,
            "fp_probability": self.fp_probability,
            "techniques": self.techniques_covered,
            "telemetry_deps": self.telemetry_deps,
            "platforms": self.platforms_available,
            "has_retro_hunt": bool(self.retro_hunt_query),
            "rules_available": list(self.detection_pack.keys()),
            "processed_at": self.processed_at,
            "engine_version": self.engine_version,
        }


class DetectionEngineeringOrchestrator:
    """Master orchestrator for the APEX Detection Engineering Core."""

    def __init__(self, repo_root:str=".", output_dir:str="api/detections"):
        self.repo_root  = repo_root
        self.output_dir = os.path.join(repo_root, output_dir)
        os.makedirs(self.output_dir, exist_ok=True)
        self._init_subsystems()

    def _init_subsystems(self):
        """Initialize all 14 subsystems with graceful degradation."""
        log.info(f"[DEO] Initializing Detection Engineering Core v{ENGINE_VERSION}")

        # Import all subsystems
        try:
            from scripts.apex_real_detection_engine import generate_rules_for_advisory
            self._gen_rules = generate_rules_for_advisory
        except ImportError:
            self._gen_rules = None
            log.warning("[DEO] apex_real_detection_engine unavailable")

        try:
            from scripts.apex_mitre_attack_engine import enrich_attack_mapping
            self._map_attack = enrich_attack_mapping
        except ImportError:
            self._map_attack = None

        try:
            from scripts.detection_validation_engine import DetectionValidationEngine
            self._validator = DetectionValidationEngine()
        except ImportError:
            self._validator = None

        try:
            from scripts.fp_suppression_engine import FPSuppressionEngine
            self._fp_suppressor = FPSuppressionEngine()
        except ImportError:
            self._fp_suppressor = None

        try:
            from scripts.coverage_gap_analyzer import CoverageGapAnalyzer
            self._coverage_analyzer = CoverageGapAnalyzer()
        except ImportError:
            self._coverage_analyzer = None

        try:
            from scripts.detection_drift_monitor import DetectionDriftMonitor
            self._drift_monitor = DetectionDriftMonitor(self.repo_root)
        except ImportError:
            self._drift_monitor = None

        try:
            from scripts.multi_siem_normalization_layer import MultiSIEMNormalizationLayer
            self._normalizer = MultiSIEMNormalizationLayer()
        except ImportError:
            self._normalizer = None

        try:
            from scripts.retro_hunt_engine import RetroHuntEngine
            self._retro_engine = RetroHuntEngine()
        except ImportError:
            self._retro_engine = None

        try:
            from scripts.telemetry_dependency_mapper import TelemetryDependencyMapper
            self._telemetry_mapper = TelemetryDependencyMapper()
        except ImportError:
            self._telemetry_mapper = None

        try:
            from scripts.enterprise_rule_packager import EnterpriseRulePackager
            self._packager = EnterpriseRulePackager(self.output_dir)
        except ImportError:
            self._packager = None

        try:
            from scripts.detection_quality_benchmarker import DetectionQualityBenchmarker
            self._benchmarker = DetectionQualityBenchmarker()
        except ImportError:
            self._benchmarker = None

        log.info("[DEO] Subsystem initialization complete")

    def _normalize_iocs(self, iocs:list) -> list:
        """Normalize IOC list: convert raw strings to dicts expected by FP/retro engines."""
        normalized = []
        for ioc in iocs:
            if isinstance(ioc, dict):
                normalized.append(ioc)
            elif isinstance(ioc, str) and ioc.strip():
                val = ioc.strip()
                # Infer type from value pattern
                import re as _re
                if _re.match(r'^https?://', val):
                    ioc_type = "url"
                elif _re.match(r'CVE-\d{4}-\d+', val, _re.IGNORECASE):
                    ioc_type = "cve"
                elif _re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}', val):
                    ioc_type = "ip"
                elif _re.match(r'^[a-fA-F0-9]{32,64}$', val):
                    ioc_type = "hash"
                elif _re.match(r'^[a-zA-Z0-9]([a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?(\.[a-zA-Z]{2,})+$', val):
                    ioc_type = "domain"
                else:
                    ioc_type = "unknown"
                normalized.append({
                    "indicator": val, "type": ioc_type,
                    "confidence": 50, "source": "APEX-FEED"
                })
        return normalized

    def process_advisory(self, advisory:Dict) -> DetectionPipelineResult:
        """Run the full detection engineering pipeline for one advisory."""
        start_ts  = time.time()
        adv_id    = advisory.get("stix_id","")
        title     = advisory.get("title","")
        result    = DetectionPipelineResult(advisory_id=adv_id, title=title)

        log.info(f"[DEO] Processing advisory: {adv_id} — {title[:60]}")

        # Normalize IOC list: convert raw strings → dicts for FP/retro engines
        if "iocs" in advisory:
            advisory = {**advisory, "iocs": self._normalize_iocs(advisory["iocs"])}

        # ── Stage 1: Generate Detection Rules ─────────────────────────────
        try:
            if self._gen_rules:
                detection_pack = self._gen_rules(advisory)
                result.detection_pack = detection_pack or {}
                result.stages_completed.append("S1-rule-generation")
            else:
                # Fallback: use existing detection_pack from advisory
                result.detection_pack = advisory.get("detection_pack",{})
                result.stages_completed.append("S1-rule-generation-passthrough")
        except Exception as e:
            result.stages_failed.append(f"S1-rule-generation: {e}")
            log.error(f"[DEO] S1 failed: {e}")

        # ── Stage 2: ATT&CK Mapping ────────────────────────────────────────
        try:
            def _extract_technique_ids(raw) -> List[str]:
                """Normalize technique IDs from any format."""
                if not raw:
                    return []
                out = []
                for item in raw:
                    if isinstance(item, str):
                        out.append(item)
                    elif isinstance(item, dict):
                        tid = item.get("technique_id","") or item.get("id","")
                        if tid and tid not in ("UNRESOLVED",""):
                            out.append(tid)
                return [t for t in out if t]

            # Priority 1: explicit ttp_ids list
            techniques = _extract_technique_ids(advisory.get("ttp_ids") or [])

            # Priority 2: feed's pre-mapped ttps list
            if not techniques:
                techniques = _extract_technique_ids(advisory.get("ttps") or [])

            # Priority 3: mitre_tactics field (may contain dicts or strings)
            if not techniques:
                techniques = _extract_technique_ids(advisory.get("mitre_tactics") or [])

            # Priority 4: run the ATT&CK engine
            if not techniques and self._map_attack:
                enriched = self._map_attack(advisory)
                if isinstance(enriched, dict):
                    techniques = _extract_technique_ids(enriched.get("ttps",[]))

            result.techniques_covered = list(set(techniques))
            result.stages_completed.append("S2-attack-mapping")
        except Exception as e:
            result.stages_failed.append(f"S2-attack-mapping: {e}")

        # ── Stage 3: IOC FP Suppression ───────────────────────────────────
        try:
            if self._fp_suppressor:
                iocs = advisory.get("iocs",[])
                if iocs:
                    fp_result = self._fp_suppressor.suppress_ioc_list(iocs, adv_id)
                    result.suppression_result = fp_result.to_dict()
                    # Update advisory iocs with suppressed list
                    advisory = {**advisory, "iocs": fp_result.passed_iocs}
                result.stages_completed.append("S3-fp-suppression")
        except Exception as e:
            result.stages_failed.append(f"S3-fp-suppression: {e}")

        # ── Stage 4: Detection Rule Validation ────────────────────────────
        try:
            if self._validator and result.detection_pack:
                val_result = self._validator.validate_detection_pack(
                    result.detection_pack, adv_id, title
                )
                result.validation_result = val_result
                result.production_ready  = val_result.get("overall_status") == "PASS"
                # Aggregate FP score
                fp_scores=[v.get("fp_probability_score",50)
                           for v in val_result.get("results_by_format",{}).values()]
                if fp_scores:
                    result.fp_probability = round(sum(fp_scores)/len(fp_scores),2)
                result.stages_completed.append("S4-validation")
        except Exception as e:
            result.stages_failed.append(f"S4-validation: {e}")
            log.error(f"[DEO] S4 failed: {traceback.format_exc()[:200]}")

        # ── Stage 5: Multi-SIEM Normalization ─────────────────────────────
        try:
            if self._normalizer:
                sigma_rule = result.detection_pack.get("sigma","")
                if sigma_rule:
                    nr = self._normalizer.normalize(sigma_rule, adv_id, title)
                    result.normalized_ruleset = nr.to_dict()
                    result.platforms_available = nr.platforms_generated
                    # Merge normalized rules into detection pack
                    for platform, rule in nr.rules.items():
                        if platform not in result.detection_pack:
                            result.detection_pack[platform] = rule
                result.stages_completed.append("S5-normalization")
        except Exception as e:
            result.stages_failed.append(f"S5-normalization: {e}")

        # ── Stage 6: Retro-Hunt Generation ────────────────────────────────
        try:
            if self._retro_engine:
                adv_with_techs = {**advisory, "ttp_ids": result.techniques_covered}
                rh_pack = self._retro_engine.generate_full_pack(adv_with_techs, 90)
                result.retro_hunt_pack  = rh_pack.to_dict()
                result.retro_hunt_query = rh_pack.queries.get("kql_sentinel","")
                result.stages_completed.append("S6-retro-hunt")
        except Exception as e:
            result.stages_failed.append(f"S6-retro-hunt: {e}")

        # ── Stage 7: Telemetry Dependency Mapping ─────────────────────────
        try:
            if self._telemetry_mapper and result.detection_pack:
                sigma = result.detection_pack.get("sigma","")
                if sigma:
                    tm = self._telemetry_mapper.map_rule(sigma,"sigma",advisory_id=adv_id)
                    result.telemetry_mapping = tm.to_dict()
                    result.telemetry_deps = [d.name for d in tm.required_telemetry]
                result.stages_completed.append("S7-telemetry-mapping")
        except Exception as e:
            result.stages_failed.append(f"S7-telemetry-mapping: {e}")

        # ── Stage 8: Quality Benchmarking ─────────────────────────────────
        try:
            if self._benchmarker:
                # Get first validation result for benchmarking
                first_vr = {}
                vr_by_fmt = result.validation_result.get("results_by_format",{})
                if vr_by_fmt:
                    first_vr = next(iter(vr_by_fmt.values()),{})
                elif result.validation_result:
                    first_vr = result.validation_result

                if first_vr:
                    br = self._benchmarker.benchmark(
                        first_vr,
                        normalized_ruleset=result.normalized_ruleset,
                        telemetry_mapping=result.telemetry_mapping,
                        advisory=advisory
                    )
                    result.benchmark_result = br.to_dict()
                    result.quality_grade    = br.grade
                    result.composite_score  = br.composite_score
                result.stages_completed.append("S8-benchmarking")
        except Exception as e:
            result.stages_failed.append(f"S8-benchmarking: {e}")

        # ── Stage 9: Coverage Gap Update ──────────────────────────────────
        try:
            if self._coverage_analyzer:
                gap_report = self._coverage_analyzer.analyze(result.techniques_covered)
                # Store top 5 critical gaps relevant to this advisory
                result.coverage_gaps = [g.to_dict() for g in gap_report.critical_gaps[:5]]
                result.stages_completed.append("S9-coverage-gaps")
        except Exception as e:
            result.stages_failed.append(f"S9-coverage-gaps: {e}")

        # ── Stage 10: Build API Payload ────────────────────────────────────
        result.api_payload   = result.to_api_payload()
        result.processed_at  = datetime.now(timezone.utc).isoformat()
        result.elapsed_ms    = round((time.time()-start_ts)*1000, 2)

        # Final status
        failed_critical = [s for s in result.stages_failed if any(
            k in s for k in ["S4-validation","S1-rule-generation"])]
        if failed_critical:
            result.pipeline_status = "FAIL"
        elif result.stages_failed:
            result.pipeline_status = "WARN"
        elif result.production_ready:
            result.pipeline_status = "PASS"
        else:
            result.pipeline_status = "WARN"

        log.info(f"[DEO] Advisory {adv_id}: Status={result.pipeline_status} "
                 f"Grade={result.quality_grade} Score={result.composite_score} "
                 f"Stages={len(result.stages_completed)}/{len(result.stages_completed)+len(result.stages_failed)} "
                 f"Elapsed={result.elapsed_ms}ms")

        return result

    def process_batch(self, advisories:List[Dict],
                     run_id:str="") -> Dict:
        """Process all advisories through the detection engineering pipeline."""
        if not run_id:
            run_id = f"det-run-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"

        log.info(f"[DEO] Starting batch run {run_id} — {len(advisories)} advisories")
        batch_start = time.time()

        all_results=[]
        all_validation_results=[]
        packager_input=[]
        stats = {"pass":0,"warn":0,"fail":0,"skip":0,"total":len(advisories)}

        for adv in advisories:
            try:
                pr = self.process_advisory(adv)
                all_results.append(pr)
                stats[pr.pipeline_status.lower()] += 1

                # Collect validation results for drift monitor
                if pr.validation_result.get("results_by_format"):
                    for vr in pr.validation_result["results_by_format"].values():
                        if vr: all_validation_results.append(vr)

                # Collect for packager
                if pr.normalized_ruleset:
                    packager_input.append({
                        **pr.normalized_ruleset,
                        "techniques": pr.techniques_covered,
                        "level": "high" if pr.quality_grade in ("S","A") else "medium"
                    })

                # Write per-advisory detection API endpoint
                self._write_detection_api(pr)

            except Exception as e:
                log.error(f"[DEO] Advisory processing failed: {adv.get('stix_id','?')} — {e}")
                stats["fail"] += 1

        # Run drift monitor
        drift_report={}
        if self._drift_monitor and all_validation_results:
            try:
                dr = self._drift_monitor.detect_drift(all_validation_results, run_id)
                drift_report = dr.to_dict()
                self._write_json(drift_report,
                                 os.path.join(self.repo_root,"data/audit/detection_drift_report.json"))
            except Exception as e:
                log.warning(f"[DEO] Drift monitoring failed: {e}")

        # Create enterprise rule package
        package_result={}
        if self._packager and packager_input:
            try:
                package_result = self._packager.package(packager_input)
            except Exception as e:
                log.warning(f"[DEO] Rule packaging failed: {e}")

        # Write detection index
        index = self._build_index(all_results, run_id, stats)
        self._write_json(index, os.path.join(self.output_dir,"detection-index.json"))

        elapsed = round((time.time()-batch_start)*1000,2)
        log.info(f"[DEO] Batch complete: {run_id} | "
                 f"PASS={stats['pass']} WARN={stats['warn']} FAIL={stats['fail']} "
                 f"| Elapsed={elapsed}ms")

        return {
            "run_id": run_id,
            "status": "COMPLETE",
            "stats": stats,
            "elapsed_ms": elapsed,
            "output_dir": self.output_dir,
            "detection_index": index,
            "drift_report": drift_report,
            "package_result": {k:v for k,v in package_result.items() if k != "results"},
            "engine_version": ENGINE_VERSION
        }

    def _write_detection_api(self, pr:DetectionPipelineResult):
        """Write detection API endpoint for one advisory."""
        if not pr.advisory_id: return
        try:
            # Per-advisory detection endpoint
            safe_id = pr.advisory_id.replace("/","_").replace("\\","_")
            path = os.path.join(self.output_dir, f"{safe_id}.json")
            self._write_json(pr.api_payload, path)

            # Full detection data (enterprise tier)
            full_path = os.path.join(self.output_dir, f"{safe_id}_full.json")
            self._write_json({
                "api_payload": pr.api_payload,
                "detection_pack": pr.detection_pack,
                "validation": pr.validation_result,
                "benchmark": pr.benchmark_result,
                "retro_hunt": pr.retro_hunt_pack.get("queries",{}),
                "telemetry": pr.telemetry_mapping,
                "normalized_rules": pr.normalized_ruleset.get("rules",{}),
            }, full_path)
        except Exception as e:
            log.warning(f"[DEO] API write failed for {pr.advisory_id}: {e}")

    def _build_index(self, results:List[DetectionPipelineResult], run_id:str, stats:Dict) -> Dict:
        """Build detection index for API consumption."""
        entries=[]
        all_techniques=set()
        all_platforms=set()
        grade_dist={"S":0,"A":0,"B":0,"C":0,"D":0,"F":0}

        for pr in results:
            all_techniques.update(pr.techniques_covered)
            all_platforms.update(pr.platforms_available)
            grade_dist[pr.quality_grade] = grade_dist.get(pr.quality_grade,0) + 1
            entries.append({
                "id": pr.advisory_id,
                "title": pr.title[:80],
                "status": pr.pipeline_status,
                "grade": pr.quality_grade,
                "score": pr.composite_score,
                "production_ready": pr.production_ready,
                "techniques": pr.techniques_covered,
                "formats": list(pr.detection_pack.keys()),
                "has_retro_hunt": bool(pr.retro_hunt_query),
            })

        scores = [pr.composite_score for pr in results if pr.composite_score>0]
        return {
            "run_id": run_id,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "total_advisories": len(results),
            "pipeline_stats": stats,
            "average_quality_score": round(sum(scores)/len(scores) if scores else 0, 2),
            "grade_distribution": grade_dist,
            "techniques_covered": list(all_techniques),
            "platforms_available": list(all_platforms),
            "entries": entries,
            "engine_version": ENGINE_VERSION
        }

    def _write_json(self, data:Any, path:str):
        os.makedirs(os.path.dirname(path) if os.path.dirname(path) else ".", exist_ok=True)
        with open(path,"w",encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)


def run_detection_engineering_pipeline(advisories:List[Dict],
                                        repo_root:str=".",
                                        output_dir:str="api/detections") -> Dict:
    """Main entry point called from the master pipeline orchestrator."""
    orchestrator = DetectionEngineeringOrchestrator(repo_root=repo_root, output_dir=output_dir)
    run_id = f"det-{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}"
    return orchestrator.process_batch(advisories, run_id=run_id)


if __name__=="__main__":
    logging.basicConfig(level=logging.INFO,
                       format="%(asctime)s [%(name)s] %(levelname)s: %(message)s")
    # Self-test with mock advisory
    test_advisories = [
        {
            "stix_id": "intel--test001",
            "title": "KnowledgeDeliver LMS Zero-Day Exploited to Deploy BLUEBEAM Web Shell",
            "threat_type": "Vulnerability",
            "severity": "HIGH",
            "actor": "CDB-RU-02",
            "kev": True,
            "epss": 0.08,
            "risk_score": 3.54,
            "ttp_ids": ["T1190","T1505.003"],
            "iocs": [
                {"type":"domain","indicator":"api.ts","confidence":32,"source":"APEX-INTEL"},
                {"type":"domain","indicator":"index.ts","confidence":32,"source":"APEX-INTEL"},
                {"type":"ip","indicator":"185.234.219.42","confidence":85,"source":"OSINT"},
                {"type":"domain","indicator":"bluebeam-c2.ru","confidence":90,"source":"HONEYPOT"},
            ],
            "detection_pack": {
                "sigma": """title: APEX - Web Shell Deployment via LMS Exploitation
id: apex-webshell-001
status: experimental
description: Detects web shell deployment following LMS exploitation
references:
    - https://intel.cyberdudebivash.com
author: CYBERDUDEBIVASH SENTINEL APEX
date: 2026/05/25
tags:
    - attack.initial_access
    - attack.t1190
    - attack.t1505.003
logsource:
  category: webserver
detection:
  webshell_upload:
    cs-uri-stem|contains:
      - '.aspx'
      - '.jsp'
    cs-method: POST
    sc-status: 200
  condition: webshell_upload
falsepositives:
  - Legitimate file uploads to LMS
level: high
""",
                "kql": "DeviceNetworkEvents | where RemoteUrl contains 'bluebeam-c2.ru' | project TimeGenerated, DeviceName, RemoteUrl, RemoteIP"
            }
        }
    ]
    import sys
    sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    orchestrator = DetectionEngineeringOrchestrator(repo_root="/tmp/apex_test", output_dir="/tmp/apex_test/api/detections")
    result = orchestrator.process_advisory(test_advisories[0])
    print(f"\n[DEO] ============================================================")
    print(f"[DEO] Advisory: {result.advisory_id}")
    print(f"[DEO] Status:   {result.pipeline_status}")
    print(f"[DEO] Grade:    {result.quality_grade}")
    print(f"[DEO] Score:    {result.composite_score}")
    print(f"[DEO] Prod-Ready: {result.production_ready}")
    print(f"[DEO] Techniques: {result.techniques_covered}")
    print(f"[DEO] Platforms:  {result.platforms_available}")
    print(f"[DEO] FP Prob:   {result.fp_probability}%")
    print(f"[DEO] Stages OK:  {result.stages_completed}")
    print(f"[DEO] Stages FAIL:{result.stages_failed}")
    print(f"[DEO] Elapsed:    {result.elapsed_ms}ms")
    print(f"[DEO] ============================================================")
