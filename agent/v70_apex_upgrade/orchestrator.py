"""
SENTINEL APEX v70 — Master Pipeline Orchestrator (PATCHED)
=============================================================
CRITICAL FIX: Removes early-exit. Always processes data. Hard fails on 0 advisories.

Single entry point that executes all phases in order:
1. Load existing manifest (from data_bridge output)
2. Convert to structured Advisory models
3. Deduplicate
4. AI Classification
5. AI Clustering
6. AI Summarization
7. AI Risk Prediction
8. Correlation
9. Threat Scoring
10. Confidence Scoring
11. Publish manifest (validated, versioned)
12. Pre-deploy validation
"""

import json
import logging
import os
import sys
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

# Core
from .core.models import Advisory, Manifest, advisory_from_legacy, CVERecord, IOC, IOCType, Severity, ThreatType
from .core.schema_validator import validate_manifest
from .core.manifest_manager import ManifestManager

# Engines
from .engines.dedup_engine import DedupEngine
from .engines.correlation_engine import CorrelationEngine
from .engines.threat_scoring import ThreatScoringEngine, ConfidenceEngine

# AI
from .ai.threat_classifier import ThreatClassifier
from .ai.threat_clusterer import ThreatClusterer
from .ai.summarizer import ThreatSummarizer
from .ai.risk_predictor import RiskPredictor

# Pipeline
from .pipeline.validator import PipelineValidator, PipelineValidationResult

logger = logging.getLogger("sentinel.orchestrator")


class OrchestratorConfig:
    """Configuration for the orchestrator run."""
    def __init__(
        self,
        data_dir: str = "data",
        dashboard_file: str = "index.html",
        enable_ai: bool = True,
        enable_blog_gen: bool = True,
        enable_correlation: bool = True,
        enable_dedup: bool = True,
        dry_run: bool = False,
    ):
        self.data_dir = data_dir
        self.dashboard_file = dashboard_file
        self.enable_ai = enable_ai
        self.enable_blog_gen = enable_blog_gen
        self.enable_correlation = enable_correlation
        self.enable_dedup = enable_dedup
        self.dry_run = dry_run


class OrchestratorResult:
    """Structured result of an orchestrator run."""
    def __init__(self):
        self.success = False
        self.phases: List[Dict[str, Any]] = []
        self.total_advisories = 0
        self.dedup_removed = 0
        self.correlations_found = 0
        self.campaigns_detected = 0
        self.blog_reports_generated = 0
        self.validation_result: Optional[PipelineValidationResult] = None
        self.duration_seconds = 0.0
        self.error: Optional[str] = None

    def add_phase(self, name: str, status: str, duration: float, details: Any = None):
        self.phases.append({
            "phase": name,
            "status": status,
            "duration_s": round(duration, 3),
            "details": details,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def to_dict(self) -> Dict[str, Any]:
        return {
            "success": self.success,
            "total_advisories": self.total_advisories,
            "dedup_removed": self.dedup_removed,
            "correlations_found": self.correlations_found,
            "campaigns_detected": self.campaigns_detected,
            "blog_reports_generated": self.blog_reports_generated,
            "duration_seconds": self.duration_seconds,
            "error": self.error,
            "phases": self.phases,
            "validation": self.validation_result.to_dict() if self.validation_result else None,
        }

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), indent=2, default=str)


def _convert_real_advisory(item: Dict[str, Any]) -> Advisory:
    """
    Convert an advisory from the ACTUAL repo data format.
    Handles both the STIX manifest format and legacy flat format.
    """
    import re

    title = item.get("title", "")

    # Extract CVEs from title if not in a 'cves' field
    cves = item.get("cves", [])
    if not cves and title:
        cves = re.findall(r"CVE-\d{4}-\d{4,}", title, re.IGNORECASE)

    # IOCs — may be a list of values or just a count
    iocs = []
    raw_iocs = item.get("iocs", [])
    for raw in raw_iocs:
        if isinstance(raw, str):
            iocs.append(IOC(value=raw, source=item.get("source", "")))
        elif isinstance(raw, dict):
            iocs.append(IOC(
                value=raw.get("value", ""),
                source=raw.get("source", item.get("source", "")),
            ))

    # Severity
    sev_str = (item.get("severity", "") or "").lower()
    severity = Severity.INFO
    for s in Severity:
        if s.value == sev_str:
            severity = s
            break

    # Threat type inference
    threat_type = ThreatType.GENERIC
    if cves:
        threat_type = ThreatType.VULNERABILITY
    elif any(kw in title.lower() for kw in ["malware", "ransomware", "trojan", "botnet"]):
        threat_type = ThreatType.MALWARE
    elif any(kw in title.lower() for kw in ["campaign", "apt", "threat actor", "espionage"]):
        threat_type = ThreatType.CAMPAIGN

    # MITRE techniques
    mitre_raw = item.get("mitre_techniques", item.get("mitre_tactics", ""))
    mitre_techniques = []
    if isinstance(mitre_raw, str) and mitre_raw:
        mitre_techniques = [t.strip() for t in mitre_raw.split(",") if t.strip()]
    elif isinstance(mitre_raw, list):
        mitre_techniques = mitre_raw

    # Actors
    actors = item.get("actors", [])
    actor_tag = item.get("actor_tag", "")
    if actor_tag and isinstance(actor_tag, str) and actor_tag.lower() not in ("", "none", "unknown", "n/a"):
        if actor_tag not in actors:
            actors.append(actor_tag)

    # Source name
    source_name = item.get("source", "") or item.get("source_name", "") or item.get("feed_source", "")

    return Advisory(
        advisory_id=item.get("advisory_id", ""),
        title=title,
        summary=item.get("description", "") or item.get("summary", "") or title,
        source_url=item.get("link", "") or item.get("source_url", ""),
        source_name=source_name,
        published_date=item.get("published", "") or item.get("published_date", "") or item.get("timestamp", ""),
        threat_type=threat_type,
        severity=severity,
        confidence=float(item.get("confidence", 0) or item.get("confidence_score", 0) or 0),
        cves=cves,
        iocs=iocs,
        actors=actors,
        mitre_techniques=mitre_techniques,
        tags=item.get("tags", []),
        threat_score=float(item.get("threat_score", 0) or item.get("risk_score", 0) or 0),
        blog_post_url=item.get("blog_post_url", "") or item.get("blog_url", ""),
        blog_post_id=item.get("blog_post_id", ""),
        stix_id=item.get("stix_id", ""),
    )


class Orchestrator:
    """
    Master pipeline orchestrator.
    Executes all v70 intelligence phases in sequence.
    NEVER exits early. HARD FAILS on 0 data.
    """

    def __init__(self, config: Optional[OrchestratorConfig] = None):
        self.config = config or OrchestratorConfig()
        self.manifest_mgr = ManifestManager(self.config.data_dir)

    def run(self) -> OrchestratorResult:
        """Execute the full pipeline. Returns structured result."""
        result = OrchestratorResult()
        start_time = time.time()

        try:
            # ─── Phase 0: Load existing data ───
            t0 = time.time()
            raw_advisories = self.manifest_mgr.load_current_advisories()
            logger.info(f"Phase 0: Loaded {len(raw_advisories)} existing advisories")
            result.add_phase("load_existing", "OK", time.time() - t0, {
                "count": len(raw_advisories),
                "manifest_path": self.manifest_mgr.latest_path,
            })

            # ─── CRITICAL: HARD FAIL on 0 advisories ───
            if not raw_advisories:
                msg = (
                    f"CRITICAL: 0 advisories loaded from {self.manifest_mgr.latest_path}. "
                    f"Data bridge may not have run, or STIX manifest is empty. "
                    f"Pipeline CANNOT proceed without data."
                )
                logger.error(msg)
                result.add_phase("data_check", "FAILED", 0, {"error": msg})
                result.error = msg
                result.success = False
                result.duration_seconds = round(time.time() - start_time, 3)
                return result

            result.add_phase("data_check", "OK", 0, {"count": len(raw_advisories)})

            # ─── Phase 1: Convert to structured models ───
            t0 = time.time()
            advisories = []
            convert_errors = 0
            for item in raw_advisories:
                try:
                    advisories.append(_convert_real_advisory(item))
                except Exception as e:
                    convert_errors += 1
                    if convert_errors <= 3:
                        logger.warning(f"Conversion error: {e}")

            logger.info(f"Phase 1: Converted {len(advisories)} advisories ({convert_errors} errors)")
            result.add_phase("model_conversion", "OK", time.time() - t0, {
                "converted": len(advisories),
                "errors": convert_errors,
            })

            if not advisories:
                result.error = "All advisory conversions failed"
                result.success = False
                result.duration_seconds = round(time.time() - start_time, 3)
                return result

            # ─── Phase 2: Deduplication ───
            if self.config.enable_dedup:
                t0 = time.time()
                dedup_engine = DedupEngine()
                pre_count = len(advisories)
                advisories = dedup_engine.deduplicate(advisories)
                removed = pre_count - len(advisories)
                result.dedup_removed = removed
                logger.info(f"Phase 2: Dedup {pre_count} -> {len(advisories)} ({removed} removed)")
                result.add_phase("deduplication", "OK", time.time() - t0, dedup_engine.stats)
            else:
                result.add_phase("deduplication", "SKIPPED", 0)

            # ─── Phase 3: AI Classification ───
            if self.config.enable_ai:
                t0 = time.time()
                try:
                    classifier = ThreatClassifier()
                    advisories = classifier.classify_batch(advisories)
                    logger.info("Phase 3: AI classification complete")
                    result.add_phase("ai_classification", "OK", time.time() - t0)
                except Exception as e:
                    logger.warning(f"Phase 3: AI classification failed (non-fatal): {e}")
                    result.add_phase("ai_classification", "DEGRADED", time.time() - t0, {"error": str(e)})
            else:
                result.add_phase("ai_classification", "SKIPPED", 0)

            # ─── Phase 4: AI Clustering ───
            if self.config.enable_ai:
                t0 = time.time()
                try:
                    clusterer = ThreatClusterer()
                    advisories = clusterer.cluster(advisories)
                    logger.info("Phase 4: AI clustering complete")
                    result.add_phase("ai_clustering", "OK", time.time() - t0, {
                        "clusters": len(clusterer.clusters),
                    })
                except Exception as e:
                    logger.warning(f"Phase 4: AI clustering failed (non-fatal): {e}")
                    result.add_phase("ai_clustering", "DEGRADED", time.time() - t0, {"error": str(e)})
            else:
                result.add_phase("ai_clustering", "SKIPPED", 0)

            # ─── Phase 5: Threat Scoring ───
            t0 = time.time()
            scoring_engine = ThreatScoringEngine()
            advisories = scoring_engine.score_batch(advisories)
            logger.info("Phase 5: Threat scoring complete")
            result.add_phase("threat_scoring", "OK", time.time() - t0)

            # ─── Phase 6: Confidence Scoring ───
            t0 = time.time()
            confidence_engine = ConfidenceEngine()
            advisories = confidence_engine.score_batch(advisories)
            logger.info("Phase 6: Confidence scoring complete")
            result.add_phase("confidence_scoring", "OK", time.time() - t0)

            # ─── Phase 7: Correlation ───
            if self.config.enable_correlation:
                t0 = time.time()
                try:
                    corr_engine = CorrelationEngine()
                    advisories = corr_engine.correlate(advisories)
                    result.correlations_found = len(corr_engine.links)
                    result.campaigns_detected = len(corr_engine.campaigns)
                    logger.info(f"Phase 7: {result.correlations_found} links, {result.campaigns_detected} campaigns")
                    result.add_phase("correlation", "OK", time.time() - t0)
                except Exception as e:
                    logger.warning(f"Phase 7: Correlation failed (non-fatal): {e}")
                    result.add_phase("correlation", "DEGRADED", time.time() - t0, {"error": str(e)})
            else:
                result.add_phase("correlation", "SKIPPED", 0)

            # ─── Phase 8: AI Summarization ───
            if self.config.enable_ai:
                t0 = time.time()
                try:
                    summarizer = ThreatSummarizer(use_transformers=False)
                    advisories = summarizer.summarize_batch(advisories)
                    logger.info("Phase 8: AI summarization complete")
                    result.add_phase("ai_summarization", "OK", time.time() - t0)
                except Exception as e:
                    logger.warning(f"Phase 8: Summarization failed (non-fatal): {e}")
                    result.add_phase("ai_summarization", "DEGRADED", time.time() - t0, {"error": str(e)})
            else:
                result.add_phase("ai_summarization", "SKIPPED", 0)

            # ─── Phase 9: AI Risk Prediction ───
            if self.config.enable_ai:
                t0 = time.time()
                try:
                    risk_pred = RiskPredictor()
                    advisories = risk_pred.predict_batch(advisories)
                    logger.info("Phase 9: Risk prediction complete")
                    result.add_phase("ai_risk_prediction", "OK", time.time() - t0)
                except Exception as e:
                    logger.warning(f"Phase 9: Risk prediction failed (non-fatal): {e}")
                    result.add_phase("ai_risk_prediction", "DEGRADED", time.time() - t0, {"error": str(e)})
            else:
                result.add_phase("ai_risk_prediction", "SKIPPED", 0)

            # ─── Phase 10: Publish Manifest ───
            t0 = time.time()
            manifest = Manifest(
                version="70.0",
                metadata={
                    "pipeline_version": "v70.0",
                    "phases_executed": len(result.phases),
                    "dedup_removed": result.dedup_removed,
                    "correlations": result.correlations_found,
                    "campaigns": result.campaigns_detected,
                },
            )

            if self.config.dry_run:
                logger.info("Phase 10: DRY RUN — skipping manifest write")
                result.add_phase("publish_manifest", "DRY_RUN", time.time() - t0)
            else:
                success, msg = self.manifest_mgr.publish(manifest, advisories)
                if success:
                    logger.info("Phase 10: Manifest published successfully")
                    result.add_phase("publish_manifest", "OK", time.time() - t0)
                else:
                    logger.error(f"Phase 10: Manifest publish failed: {msg}")
                    result.add_phase("publish_manifest", "FAILED", time.time() - t0, {"error": msg})
                    rb_success, rb_msg = self.manifest_mgr.rollback()
                    if rb_success:
                        logger.info("Rollback successful")
                    else:
                        logger.error(f"Rollback also failed: {rb_msg}")

            # ─── Phase 11: Pre-Deploy Validation ───
            t0 = time.time()
            validator = PipelineValidator(self.config.data_dir, self.config.dashboard_file)
            val_result = validator.validate_all()
            result.validation_result = val_result
            if val_result.passed:
                logger.info("Phase 11: Validation PASSED")
                result.add_phase("pre_deploy_validation", "OK", time.time() - t0)
            else:
                logger.error(f"Phase 11: Validation FAILED — {len(val_result.errors)} errors")
                result.add_phase("pre_deploy_validation", "FAILED", time.time() - t0, {
                    "errors": val_result.errors,
                })

            # ─── Finalize ───
            result.total_advisories = len(advisories)
            result.success = val_result.passed if not self.config.dry_run else True
            result.duration_seconds = round(time.time() - start_time, 3)

            logger.info(
                f"Pipeline COMPLETE: {result.total_advisories} advisories, "
                f"{result.dedup_removed} deduped, "
                f"{result.correlations_found} correlations, "
                f"{result.duration_seconds}s"
            )

        except Exception as e:
            result.error = str(e)
            result.success = False
            result.duration_seconds = round(time.time() - start_time, 3)
            logger.error(f"Pipeline FAILED: {e}", exc_info=True)

        return result


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main():
    """CLI entry point for the orchestrator."""
    import argparse
    parser = argparse.ArgumentParser(description="SENTINEL APEX v70 Pipeline Orchestrator")
    parser.add_argument("--data-dir", default="data", help="Data directory")
    parser.add_argument("--dashboard", default="index.html", help="Dashboard file")
    parser.add_argument("--no-ai", action="store_true", help="Skip AI phases")
    parser.add_argument("--no-dedup", action="store_true", help="Skip deduplication")
    parser.add_argument("--no-correlation", action="store_true", help="Skip correlation")
    parser.add_argument("--no-blog", action="store_true", help="Skip blog generation")
    parser.add_argument("--dry-run", action="store_true", help="Don't write files")
    parser.add_argument("--json", action="store_true", help="Output JSON result")
    args = parser.parse_args()

    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
    )

    config = OrchestratorConfig(
        data_dir=args.data_dir,
        dashboard_file=args.dashboard,
        enable_ai=not args.no_ai,
        enable_dedup=not args.no_dedup,
        enable_correlation=not args.no_correlation,
        enable_blog_gen=not args.no_blog,
        dry_run=args.dry_run,
    )

    orchestrator = Orchestrator(config)
    result = orchestrator.run()

    if args.json:
        print(result.to_json())
    else:
        print(f"\n{'='*60}")
        print(f"SENTINEL APEX v70 Pipeline {'PASSED' if result.success else 'FAILED'}")
        print(f"{'='*60}")
        for phase in result.phases:
            status_icon = {"OK": "+", "SKIPPED": ">", "DEGRADED": "!", "FAILED": "X", "DRY_RUN": "~"}.get(
                phase["status"], "?"
            )
            print(f"  [{status_icon}] {phase['phase']}: {phase['status']} ({phase['duration_s']}s)")
        print(f"\n  Advisories: {result.total_advisories}")
        print(f"  Dedup Removed: {result.dedup_removed}")
        print(f"  Correlations: {result.correlations_found}")
        print(f"  Campaigns: {result.campaigns_detected}")
        print(f"  Duration: {result.duration_seconds}s")
        if result.error:
            print(f"\n  ERROR: {result.error}")
        print(f"{'='*60}\n")

    sys.exit(0 if result.success else 1)


if __name__ == "__main__":
    main()
