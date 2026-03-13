"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Bug Hunter Engine (Top-Level Facade)
============================================================================
Primary entry point for the Bug Hunter subsystem.
Provides the integration bridge between Bug Hunter findings and
the Sentinel APEX threat intelligence pipeline.

Usage:
    from agent.v45_bughunter.bughunter_engine import BugHunterEngine

    engine = BugHunterEngine()
    result = await engine.run_scan("example.com")
    stix_indicators = engine.export_to_stix()
    report_path = engine.generate_report()

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import json
import os
import logging
from datetime import datetime, timezone
from typing import Dict, List, Optional

from agent.v45_bughunter import V45_VERSION, V45_CODENAME
from agent.v45_bughunter.models import BugHunterScan, BugHunterFinding
from agent.v45_bughunter.recon_pipeline import ReconPipeline
from agent.v45_bughunter.asset_delta import AssetDeltaAnalyzer
from agent.v45_bughunter.roi_engine import ROIEngine
from agent.v45_bughunter.report_generator import ReportGenerator

logger = logging.getLogger("CDB-BH-ENGINE")

_DATA_DIR = os.path.join(os.path.dirname(__file__), "..", "..", "data", "bughunter")


class BugHunterEngine:
    """
    Top-level facade for the CyberDudeBivash Bug Hunter subsystem.
    
    Capabilities:
      - Full recon pipeline execution (single domain or batch)
      - STIX 2.1 indicator export for Sentinel APEX feed integration
      - Asset delta analysis (attack surface drift tracking)
      - ROI/financial impact calculation
      - PDF/text audit report generation
      - Sentinel APEX dashboard data bridge
    """

    def __init__(self, god_mode: bool = True, wordlist: Optional[str] = None,
                 concurrency: int = 150):
        self.god_mode = god_mode
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.last_scan_result: Optional[Dict] = None
        self.pipeline: Optional[ReconPipeline] = None

        self.delta_analyzer = AssetDeltaAnalyzer()
        self.roi_engine = ROIEngine()
        self.report_gen = ReportGenerator()

        logger.info(
            f"[BH-ENGINE] Initialized v{V45_VERSION} '{V45_CODENAME}' | "
            f"God-Mode: {god_mode} | Concurrency: {concurrency}"
        )

    async def run_scan(self, domain: str) -> Dict:
        """Execute a full recon pipeline scan on a single domain."""
        self.pipeline = ReconPipeline(
            domain=domain,
            wordlist=self.wordlist,
            concurrency=self.concurrency,
            god_mode=self.god_mode,
        )
        self.last_scan_result = await self.pipeline.run()
        return self.last_scan_result

    async def run_batch_scan(self, domains: List[str]) -> List[Dict]:
        """Execute recon on multiple domains sequentially."""
        results = []
        for domain in domains:
            logger.info(f"[BATCH] Scanning {domain} ({len(results)+1}/{len(domains)})")
            result = await self.run_scan(domain)
            results.append(result)
        return results

    def export_to_stix(self) -> List[Dict]:
        """Convert last scan findings to STIX 2.1 indicators."""
        if not self.pipeline:
            return []
        return self.pipeline.to_stix_indicators()

    def analyze_drift(self, domain: str) -> Dict:
        """Compare current scan against previous baseline."""
        return self.delta_analyzer.analyze_drift(domain)

    def calculate_roi(self) -> Dict:
        """Calculate financial impact from last scan."""
        if not self.last_scan_result:
            return {}
        findings = self.last_scan_result.get("findings", [])
        return self.roi_engine.calculate_exposure(findings)

    def generate_report(self, fmt: str = "text") -> Optional[str]:
        """Generate audit report from last scan results."""
        if not self.last_scan_result:
            logger.warning("[BH-ENGINE] No scan results to generate report from")
            return None

        if fmt == "pdf":
            return self.report_gen.generate_pdf_report(self.last_scan_result)
        return self.report_gen.save_report(self.last_scan_result)

    def get_dashboard_data(self) -> Dict:
        """
        Returns structured data for the Sentinel APEX dashboard.
        This bridges Bug Hunter findings into the dashboard's rendering pipeline.
        """
        if not self.last_scan_result:
            return {"status": "no_data"}

        scan = self.last_scan_result
        findings = scan.get("findings", [])
        roi = scan.get("roi_metrics", {})

        return {
            "subsystem": "v45_bughunter",
            "version": V45_VERSION,
            "codename": V45_CODENAME,
            "scan_id": scan.get("scan_id"),
            "domain": scan.get("domain"),
            "timestamp": scan.get("timestamp"),
            "status": scan.get("status"),
            "duration_seconds": scan.get("duration_seconds", 0),
            "metrics": {
                "subdomains": scan.get("subdomain_count", 0),
                "live_hosts": scan.get("live_host_count", 0),
                "api_endpoints": scan.get("api_endpoint_count", 0),
                "total_findings": len(findings),
                "critical_findings": sum(1 for f in findings if f.get("severity") == "CRITICAL"),
                "high_findings": sum(1 for f in findings if f.get("severity") == "HIGH"),
                "risk_exposure": roi.get("total_risk_exposure", 0),
                "rosi": roi.get("rosi_percentage", 0),
            },
            "findings_summary": [
                {
                    "type": f.get("type"),
                    "severity": f.get("severity"),
                    "target": f.get("url") or f.get("host") or f.get("bucket", ""),
                }
                for f in findings[:50]  # Cap at 50 for dashboard performance
            ],
        }

    @staticmethod
    def get_engine_manifest() -> Dict:
        """Returns metadata about the Bug Hunter subsystem for platform introspection."""
        return {
            "subsystem_id": "v45_bughunter",
            "version": V45_VERSION,
            "codename": V45_CODENAME,
            "engine_count": 12,
            "engines": [
                {"id": "subdomain_engine", "name": "Subdomain Intelligence", "category": "discovery"},
                {"id": "http_probe", "name": "HTTP Probe Engine", "category": "discovery"},
                {"id": "tech_fingerprint", "name": "Technology Fingerprinter", "category": "analysis"},
                {"id": "js_endpoint_extractor", "name": "JS Endpoint Extractor", "category": "analysis"},
                {"id": "bola_agent", "name": "BOLA Intelligence Agent", "category": "vulnerability"},
                {"id": "cloud_bucket_hunter", "name": "Multi-Cloud Bucket Hunter", "category": "vulnerability"},
                {"id": "port_scanner", "name": "Port Scanner Engine", "category": "discovery"},
                {"id": "takeover_detector", "name": "Subdomain Takeover Detector", "category": "vulnerability"},
                {"id": "asset_delta", "name": "Asset Delta Analyzer", "category": "analytics"},
                {"id": "roi_engine", "name": "ROI & Risk Calculator", "category": "analytics"},
                {"id": "recon_pipeline", "name": "Recon Pipeline Orchestrator", "category": "orchestration"},
                {"id": "report_generator", "name": "Audit Report Generator", "category": "reporting"},
            ],
            "integration_points": [
                "stix_export",
                "dashboard_bridge",
                "sentinel_apex_feed",
            ],
        }
