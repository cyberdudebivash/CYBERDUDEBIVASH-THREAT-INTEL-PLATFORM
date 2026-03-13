"""
CYBERDUDEBIVASH® SENTINEL APEX v45.0 — Recon Pipeline Orchestrator
===================================================================
Full-stack recon pipeline: subdomain → probe → fingerprint → JS extraction
→ BOLA testing → cloud hunting → port scanning → takeover detection.

Integrates with Sentinel APEX threat intel feed via STIX bridge.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import asyncio
import logging
import time
from typing import List, Dict, Optional, Set

from agent.v45_bughunter.models import BugHunterScan, BugHunterFinding
from agent.v45_bughunter.subdomain_engine import SubdomainEngine
from agent.v45_bughunter.http_probe import HTTPProbeEngine
from agent.v45_bughunter.tech_fingerprint import TechFingerprinter
from agent.v45_bughunter.js_endpoint_extractor import JSEndpointExtractor
from agent.v45_bughunter.bola_agent import BOLAAgent
from agent.v45_bughunter.cloud_bucket_hunter import CloudBucketHunter
from agent.v45_bughunter.port_scanner import PortScanner
from agent.v45_bughunter.takeover_detector import TakeoverDetector
from agent.v45_bughunter.roi_engine import ROIEngine

logger = logging.getLogger("CDB-BH-PIPELINE")


class ReconPipeline:
    """
    Full God-Mode recon pipeline.
    
    Pipeline stages:
      1. Subdomain Discovery (CT + DNS bruteforce)
      2. HTTP Probing (live host detection)
      3. Technology Fingerprinting (parallel)
      4. JavaScript Endpoint Extraction
      5. BOLA Testing (on discovered API endpoints)
      6. Multi-Cloud Bucket Hunting
      7. Port Scanning
      8. Subdomain Takeover Detection
      9. ROI Calculation
      10. Sentinel APEX STIX Bridge (findings → threat intel)
    """

    def __init__(self, domain: str, wordlist: Optional[str] = None,
                 concurrency: int = 150, god_mode: bool = True):
        self.domain = domain.strip().lower()
        self.wordlist = wordlist
        self.concurrency = concurrency
        self.god_mode = god_mode

        self.scan = BugHunterScan(domain=self.domain)
        self.roi = ROIEngine()

    async def _phase_discovery(self):
        """Phase 1: Subdomain enumeration."""
        engine = SubdomainEngine(self.domain, self.wordlist, self.concurrency)
        self.scan.subdomains = await engine.run()
        logger.info(f"[P1] {len(self.scan.subdomains)} subdomains discovered")

    async def _phase_probing(self):
        """Phase 2: HTTP probing on discovered subdomains."""
        if not self.scan.subdomains:
            return
        prober = HTTPProbeEngine(concurrency=self.concurrency)
        self.scan.live_hosts = await prober.run(self.scan.subdomains)
        logger.info(f"[P2] {len(self.scan.live_hosts)} live hosts detected")

    async def _phase_fingerprint(self):
        """Phase 3: Technology fingerprinting (parallel)."""
        if not self.scan.live_hosts:
            return
        fp = TechFingerprinter()
        for host_entry in self.scan.live_hosts:
            url = host_entry.get("url", "")
            techs = await fp.fingerprint_url(url)
            tech_names = [t["technology"] for t in techs]
            self.scan.add_asset(
                hostname=url,
                technologies=tech_names,
            )

    async def _phase_js_extraction(self):
        """Phase 4: JavaScript endpoint + secret extraction."""
        if not self.scan.live_hosts:
            return
        urls = [h["url"] for h in self.scan.live_hosts]
        extractor = JSEndpointExtractor(concurrency=self.concurrency)
        results = await extractor.run(urls)

        for r in results:
            # Collect API endpoints for BOLA testing
            for ep in r.get("endpoints", []):
                if any(k in ep.lower() for k in ["/api/", "/v1/", "/v2/", "/graphql"]):
                    self.scan.api_endpoints.append(ep)

            # Record secret leaks as findings
            for secret in r.get("secrets", []):
                self.scan.add_finding({
                    "type": "SECRET_LEAK",
                    "url": r["host"],
                    "severity": "CRITICAL",
                    "evidence": f"{secret['token_type']}: {secret['prefix']}",
                })

        logger.info(f"[P4] {len(self.scan.api_endpoints)} API endpoints collected")

    async def _phase_bola(self):
        """Phase 5: BOLA testing on discovered APIs."""
        if not self.scan.api_endpoints:
            return
        agent = BOLAAgent(concurrency=30)
        findings = await agent.run_swarm(list(set(self.scan.api_endpoints)))
        for f in findings:
            self.scan.add_finding(f)

    async def _phase_cloud_hunting(self):
        """Phase 6: Multi-cloud bucket enumeration."""
        hunter = CloudBucketHunter(self.domain, concurrency=self.concurrency)
        results = await hunter.run()
        for r in results:
            if r.get("severity") == "CRITICAL":
                self.scan.add_finding(r)

    async def _phase_port_scan(self):
        """Phase 7: Port scanning on live host IPs."""
        if not self.scan.subdomains:
            return
        # Scan a subset to avoid excessive probing
        targets = self.scan.subdomains[:50]
        scanner = PortScanner(concurrency=300)
        results = await scanner.run(targets)
        for r in results:
            if r.get("severity") in ("CRITICAL", "HIGH"):
                self.scan.add_finding(r)

    async def _phase_takeover(self):
        """Phase 8: Subdomain takeover detection."""
        if not self.scan.subdomains:
            return
        detector = TakeoverDetector(concurrency=50)
        findings = await detector.run(self.scan.subdomains)
        for f in findings:
            self.scan.add_finding(f)

    async def run(self) -> Dict:
        """Execute the full pipeline."""
        start = time.time()
        logger.info(f"[PIPELINE] {'GOD-MODE' if self.god_mode else 'STANDARD'} scan: {self.domain}")

        try:
            # Phase 1: Discovery (sequential foundation)
            await self._phase_discovery()

            # Phases 2-8: Parallel execution for speed
            if self.god_mode:
                await asyncio.gather(
                    self._phase_probing(),
                    self._phase_cloud_hunting(),
                )
                # Probing must complete before fingerprint/JS/BOLA
                await asyncio.gather(
                    self._phase_fingerprint(),
                    self._phase_js_extraction(),
                    self._phase_port_scan(),
                    self._phase_takeover(),
                )
                await self._phase_bola()
            else:
                await self._phase_probing()
                await self._phase_fingerprint()
                await self._phase_js_extraction()
                await self._phase_cloud_hunting()

            duration = time.time() - start
            self.scan.finalize(status="COMPLETED", duration=duration)

            # Calculate ROI
            roi_data = self.roi.calculate_exposure(self.scan.findings)

            # Persist scan
            self.scan.save()

            logger.info(
                f"[PIPELINE] COMPLETE: {self.domain} in {duration:.1f}s | "
                f"{self.scan.critical_count} CRITICAL | "
                f"${roi_data['total_risk_exposure']:,.0f} exposure"
            )

            result = self.scan.to_dict()
            result["roi_metrics"] = roi_data
            return result

        except Exception as e:
            duration = time.time() - start
            self.scan.finalize(status="FAILED", duration=duration)
            logger.error(f"[PIPELINE] FAILURE for {self.domain}: {e}")
            return {"status": "FAILED", "domain": self.domain, "error": str(e)}

    def to_stix_indicators(self) -> List[Dict]:
        """Convert all findings to STIX 2.1 indicator stubs for Sentinel APEX."""
        indicators = []
        for f in self.scan.findings:
            finding = BugHunterFinding(
                finding_type=f.get("type", "UNKNOWN"),
                target=f.get("url") or f.get("host") or f.get("bucket", ""),
                severity=f.get("severity", "HIGH"),
                evidence=f.get("evidence"),
            )
            indicators.append(finding.to_stix_indicator())
        return indicators
