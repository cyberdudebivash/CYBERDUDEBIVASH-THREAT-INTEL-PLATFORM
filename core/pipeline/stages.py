#!/usr/bin/env python3
"""
<<<<<<< HEAD
stages.py — CYBERDUDEBIVASH® SENTINEL APEX v47.0 (COMMAND CENTER)
=======
stages.py — CYBERDUDEBIVASH® SENTINEL APEX v64.0 (COMMAND CENTER)
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
════════════════════════════════════════════════════════════════════
Pipeline Stages: Strict execution order enforcement.

  INGEST → NORMALIZE → ENRICH → CORRELATE → SCORE → STORE → PUBLISH

Each stage:
  - Receives a PipelineContext with items from the previous stage
  - Processes items and passes them to the next stage
  - Emits events via the Event Bus
  - Is idempotent and side-effect contained
  - Reports metrics for monitoring

Zero regression: wraps existing agent/ modules (risk_engine, deduplication,
export_stix, enricher) rather than replacing them.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import re
import json
import uuid
import hashlib
import logging
import time
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-PIPELINE")


# ═══════════════════════════════════════════════════════════
# PIPELINE CONTEXT
# ═══════════════════════════════════════════════════════════

class PipelineContext:
    """
    Shared context flowing through pipeline stages.
    Carries items, metadata, and execution state.
    """

    def __init__(self, run_id: str = ""):
        self.run_id = run_id or f"RUN-{uuid.uuid4().hex[:12]}"
        self.started_at = datetime.now(timezone.utc)
        self.items: List[Dict] = []
        self.metadata: Dict[str, Any] = {}
        self.errors: List[Dict] = []
        self.stages_completed: List[str] = []
        self.metrics: Dict[str, int] = {
            "ingested": 0,
            "normalized": 0,
            "enriched": 0,
            "correlated": 0,
            "scored": 0,
            "stored": 0,
            "published": 0,
            "deduplicated": 0,
            "detections": 0,
<<<<<<< HEAD
=======
            "reports_generated": 0,
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        }

    def add_error(self, stage: str, error: str, item_title: str = ""):
        self.errors.append({
            "stage": stage,
            "error": error,
            "item": item_title[:80],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

    def mark_stage_complete(self, stage: str):
        self.stages_completed.append(stage)

    @property
    def duration_seconds(self) -> float:
        return (datetime.now(timezone.utc) - self.started_at).total_seconds()

    def to_summary(self) -> Dict:
        return {
            "run_id": self.run_id,
            "started_at": self.started_at.isoformat(),
            "duration_seconds": round(self.duration_seconds, 2),
            "item_count": len(self.items),
            "stages_completed": self.stages_completed,
            "metrics": self.metrics,
            "error_count": len(self.errors),
        }


# ═══════════════════════════════════════════════════════════
# BASE STAGE
# ═══════════════════════════════════════════════════════════

class PipelineStage(ABC):
    """Base class for all pipeline stages."""

    @property
    @abstractmethod
    def name(self) -> str:
        pass

    @abstractmethod
    def execute(self, ctx: PipelineContext) -> PipelineContext:
        pass

    def _emit_event(self, event_type: str, payload: Dict):
        """Emit event to the event bus (lazy import to avoid circular deps)."""
        try:
            from core.event_bus import event_bus, EventTypes, EventPriority
            event_bus.emit(event_type, payload, source=f"pipeline.{self.name}")
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════
# STAGE 1: INGEST
# ═══════════════════════════════════════════════════════════

class IngestStage(PipelineStage):
    """
    Fault-tolerant multi-source intelligence ingestion.
    Wraps existing RSS feed collection from agent/config.py feeds.
    """

    name = "ingest"

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        logger.info(f"[{self.name}] Starting ingestion | Run: {ctx.run_id}")

        # If items are pre-loaded (from workflow or external trigger), skip fetching
        if ctx.items:
            ctx.metrics["ingested"] = len(ctx.items)
            ctx.mark_stage_complete(self.name)
            logger.info(f"[{self.name}] {len(ctx.items)} pre-loaded items")
            return ctx

        # Otherwise, collect from configured RSS feeds
        items = self._collect_feeds()
        ctx.items = items
        ctx.metrics["ingested"] = len(items)
        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.ingested", {
            "run_id": ctx.run_id, "count": len(items)
        })

        logger.info(f"[{self.name}] Ingested {len(items)} items")
        return ctx

    def _collect_feeds(self) -> List[Dict]:
        """Collect intelligence from configured RSS feeds."""
        items = []
        try:
            from agent.config import RSS_FEEDS, MAX_ENTRIES_PER_FEED, SOURCE_FETCH_TIMEOUT
            import feedparser
        except ImportError:
            logger.warning("[ingest] feedparser or agent.config not available")
            return items

        for feed_url in RSS_FEEDS:
            try:
                feed = feedparser.parse(feed_url, timeout=SOURCE_FETCH_TIMEOUT)
                for entry in feed.entries[:MAX_ENTRIES_PER_FEED]:
                    items.append({
                        "title": getattr(entry, "title", ""),
                        "content": getattr(entry, "summary", ""),
                        "source_url": getattr(entry, "link", ""),
                        "feed_source": feed_url,
                        "published": getattr(entry, "published", ""),
                        "raw_entry": {
                            "title": getattr(entry, "title", ""),
                            "link": getattr(entry, "link", ""),
                        },
                    })
            except Exception as e:
                logger.debug(f"[ingest] Feed failed {feed_url[:50]}: {e}")

        return items


# ═══════════════════════════════════════════════════════════
# STAGE 2: NORMALIZE
# ═══════════════════════════════════════════════════════════

class NormalizeStage(PipelineStage):
    """
    Normalizes and deduplicates ingested items.
    Wraps existing DeduplicationEngine from agent/deduplication.py.
    """

    name = "normalize"

    # IOC extraction patterns
    IOC_PATTERNS = {
        "ipv4": re.compile(r'\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b'),
        "domain": re.compile(r'\b(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+(?:com|net|org|io|info|gov|edu|mil|co|xyz|top|biz|site|club|online)\b', re.IGNORECASE),
        "sha256": re.compile(r'\b[a-fA-F0-9]{64}\b'),
        "sha1": re.compile(r'\b[a-fA-F0-9]{40}\b'),
        "md5": re.compile(r'\b[a-fA-F0-9]{32}\b'),
        "url": re.compile(r'https?://[^\s<>"{}|\\^`\[\]]+', re.IGNORECASE),
        "email": re.compile(r'\b[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}\b'),
        "cve": re.compile(r'CVE-\d{4}-\d{4,}', re.IGNORECASE),
    }

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        logger.info(f"[{self.name}] Normalizing {len(ctx.items)} items")

        # Load deduplication engine
        try:
            from agent.deduplication import DeduplicationEngine
            dedup = DeduplicationEngine()
        except ImportError:
            dedup = None

<<<<<<< HEAD
        # Also check against hardened manifest
        try:
            from core.manifest_manager import manifest_manager
            manifest_check = manifest_manager.is_duplicate
        except ImportError:
            manifest_check = None
=======
        # Check against hardened manifest (prefer test manifest if injected)
        manifest_check = None
        test_mm = ctx.metadata.get("_test_manifest_manager")
        if test_mm:
            manifest_check = test_mm.is_duplicate
        else:
            try:
                from core.manifest_manager import manifest_manager
                manifest_check = manifest_manager.is_duplicate
            except ImportError:
                pass
>>>>>>> claude/ai-threat-intelligence-system-eFwfT

        normalized = []
        dedup_count = 0

        for item in ctx.items:
            title = (item.get("title") or "").strip()
            if not title or len(title) < 10:
                continue

            # Dedup check
            source_url = item.get("source_url", "")
            if dedup and dedup.is_duplicate(title, source_url):
                dedup_count += 1
                continue
            if manifest_check and manifest_check(title, source_url):
                dedup_count += 1
                continue

            # Extract IOCs
            text = f"{title} {item.get('content', '')}"
            iocs = self._extract_iocs(text)

            # Normalize structure
            normalized.append({
                "title": title,
                "content": item.get("content", ""),
                "source_url": source_url,
                "feed_source": item.get("feed_source", ""),
                "published": item.get("published", ""),
                "iocs": iocs,
                "ioc_counts": {k: len(v) for k, v in iocs.items()},
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "intel_id": hashlib.sha256(f"{title}|{source_url}".lower().encode()).hexdigest()[:16],
            })

            # Mark as processed
            if dedup:
                dedup.mark_processed(title, source_url)

        ctx.items = normalized
        ctx.metrics["normalized"] = len(normalized)
        ctx.metrics["deduplicated"] = dedup_count
        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.normalized", {
            "run_id": ctx.run_id,
            "normalized": len(normalized),
            "deduplicated": dedup_count,
        })

        logger.info(f"[{self.name}] {len(normalized)} unique items ({dedup_count} duplicates)")
        return ctx

    def _extract_iocs(self, text: str) -> Dict[str, List[str]]:
        """Extract IOCs from text content."""
        iocs = {}
        for ioc_type, pattern in self.IOC_PATTERNS.items():
            matches = list(set(pattern.findall(text)))
            if matches:
                # Filter false positives
                filtered = self._filter_iocs(ioc_type, matches)
                if filtered:
                    iocs[ioc_type] = filtered[:20]
        return iocs

    def _filter_iocs(self, ioc_type: str, values: List[str]) -> List[str]:
        """Remove known false positive IOCs."""
        try:
            from agent.config import (
                PRIVATE_IP_RANGES, WELL_KNOWN_IPS,
                FALSE_POSITIVE_DOMAINS, FALSE_POSITIVE_EXTENSIONS,
            )
        except ImportError:
            return values

        filtered = []
        for val in values:
            if ioc_type == "ipv4":
                if any(val.startswith(r) for r in PRIVATE_IP_RANGES):
                    continue
                if val in WELL_KNOWN_IPS:
                    continue
            elif ioc_type == "domain":
                if val.lower() in FALSE_POSITIVE_DOMAINS:
                    continue
                if any(val.lower().endswith(ext) for ext in FALSE_POSITIVE_EXTENSIONS):
                    continue
            filtered.append(val)
        return filtered


# ═══════════════════════════════════════════════════════════
# STAGE 3: ENRICH
# ═══════════════════════════════════════════════════════════

class EnrichStage(PipelineStage):
    """
    Enriches intelligence with CVSS, EPSS, KEV, NVD data.
    Wraps existing IntelligenceQualityEngine from agent/core/intelligence_quality.py.
    """

    name = "enrich"

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        logger.info(f"[{self.name}] Enriching {len(ctx.items)} items")

        # Load quality engine
        try:
            from agent.core.intelligence_quality import IntelligenceQualityEngine
            quality_engine = IntelligenceQualityEngine()
            has_quality = True
        except ImportError:
            has_quality = False

        enriched_count = 0

        for item in ctx.items:
            try:
                # CVE enrichment
                cves = item.get("iocs", {}).get("cve", [])
                if cves:
                    enrichment = self._enrich_cves(cves)
                    item["cvss_score"] = enrichment.get("cvss_score")
                    item["epss_score"] = enrichment.get("epss_score")
                    item["kev_present"] = enrichment.get("kev_present", False)
                    item["nvd_url"] = enrichment.get("nvd_url")
                else:
                    item.setdefault("cvss_score", None)
                    item.setdefault("epss_score", None)
                    item.setdefault("kev_present", False)

                # MITRE ATT&CK mapping
                item["mitre_tactics"] = self._map_mitre(item)

                # Actor tag refinement
                item["actor_tag"] = self._refine_actor(item)

                # Quality engine enrichment
                if has_quality:
                    try:
                        quality_engine.enhance_entry(item)
                    except Exception:
                        pass

                item["enriched_at"] = datetime.now(timezone.utc).isoformat()
                enriched_count += 1

            except Exception as e:
                ctx.add_error(self.name, str(e), item.get("title", ""))

        ctx.metrics["enriched"] = enriched_count
        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.enriched", {
            "run_id": ctx.run_id, "enriched": enriched_count
        })

        logger.info(f"[{self.name}] {enriched_count} items enriched")
        return ctx

    def _enrich_cves(self, cve_ids: List[str]) -> Dict:
        """Fetch CVSS/EPSS/KEV data for CVEs."""
        result = {"cvss_score": None, "epss_score": None, "kev_present": False, "nvd_url": None}

        if not cve_ids:
            return result

        primary_cve = cve_ids[0].upper()
        result["nvd_url"] = f"https://nvd.nist.gov/vuln/detail/{primary_cve}"

        # EPSS lookup
        try:
            from agent.config import EPSS_API_URL, EPSS_FETCH_ENABLED, EPSS_FETCH_TIMEOUT
            if EPSS_FETCH_ENABLED:
                import urllib.request
                url = f"{EPSS_API_URL}?cve={primary_cve}"
                req = urllib.request.Request(url, headers={"Accept": "application/json"})
                with urllib.request.urlopen(req, timeout=EPSS_FETCH_TIMEOUT) as resp:
                    data = json.loads(resp.read())
                    if data.get("data"):
                        result["epss_score"] = float(data["data"][0].get("epss", 0))
        except Exception:
            pass

        # NVD CVSS lookup
        try:
            from agent.config import NVD_CVE_API_URL
            import urllib.request
            url = f"{NVD_CVE_API_URL}?cveId={primary_cve}"
            req = urllib.request.Request(url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=8) as resp:
                data = json.loads(resp.read())
                vulns = data.get("vulnerabilities", [])
                if vulns:
                    metrics = vulns[0].get("cve", {}).get("metrics", {})
                    # Try CVSS v3.1 first, then v3.0
                    for version_key in ["cvssMetricV31", "cvssMetricV30"]:
                        if metrics.get(version_key):
                            result["cvss_score"] = metrics[version_key][0].get("cvssData", {}).get("baseScore")
                            break
        except Exception:
            pass

        # KEV check via CISA catalog
        try:
            import urllib.request
            kev_url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
            req = urllib.request.Request(kev_url, headers={"Accept": "application/json"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                kev_data = json.loads(resp.read())
                kev_cves = {v.get("cveID", "").upper() for v in kev_data.get("vulnerabilities", [])}
                result["kev_present"] = primary_cve in kev_cves
        except Exception:
            pass

        return result

    def _map_mitre(self, item: Dict) -> List[str]:
<<<<<<< HEAD
        """Map intelligence item to MITRE ATT&CK techniques."""
        try:
            from agent.mitre_mapper import map_mitre_tactics
            return map_mitre_tactics(item.get("title", ""), item.get("content", ""))
        except ImportError:
            pass

        # Fallback: keyword-based mapping
=======
        """Map intelligence item to MITRE ATT&CK techniques using full mapper."""
        try:
            from agent.mitre_mapper import map_mitre_tactics
            return map_mitre_tactics(item.get("title", ""), item.get("content", ""))
        except (ImportError, Exception):
            pass

        # Fallback: keyword-based mapping (if mitre_mapper unavailable)
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        text = f"{item.get('title', '')} {item.get('content', '')}".lower()
        tactics = []
        mapping = {
            "T1190": ["exploit", "vulnerability", "rce", "remote code execution"],
            "T1059": ["command", "script", "powershell", "bash"],
            "T1566": ["phishing", "spear phishing", "email"],
            "T1078": ["credential", "valid account", "stolen credential"],
            "T1486": ["ransomware", "encrypt", "ransom"],
            "T1071": ["c2", "command and control", "beacon"],
            "T1098": ["account manipulation", "persistence"],
            "T1110": ["brute force", "credential stuffing"],
            "T1053": ["scheduled task", "cron", "at job"],
            "T1021": ["lateral movement", "rdp", "ssh"],
        }
        for technique_id, keywords in mapping.items():
            if any(kw in text for kw in keywords):
                tactics.append(technique_id)
<<<<<<< HEAD
        return tactics[:5]
=======
        return tactics[:10]
>>>>>>> claude/ai-threat-intelligence-system-eFwfT

    def _refine_actor(self, item: Dict) -> str:
        """Refine threat actor attribution from content."""
        text = f"{item.get('title', '')} {item.get('content', '')}".lower()
        known_actors = {
            "lazarus": "LAZARUS-GROUP", "apt28": "APT28-FANCY-BEAR",
            "fancy bear": "APT28-FANCY-BEAR", "cozy bear": "APT29-COZY-BEAR",
            "apt29": "APT29-COZY-BEAR", "volt typhoon": "VOLT-TYPHOON",
            "salt typhoon": "SALT-TYPHOON", "sandworm": "SANDWORM",
            "hafnium": "HAFNIUM", "charming kitten": "CHARMING-KITTEN",
            "kimsuky": "KIMSUKY", "turla": "TURLA",
            "lockbit": "LOCKBIT-RANSOMWARE", "blackcat": "ALPHV-BLACKCAT",
            "cl0p": "CL0P-RANSOMWARE", "clop": "CL0P-RANSOMWARE",
            "scattered spider": "SCATTERED-SPIDER",
        }
        for keyword, actor_tag in known_actors.items():
            if keyword in text:
                return actor_tag
        return item.get("actor_tag", "UNC-CDB-99")


# ═══════════════════════════════════════════════════════════
# STAGE 4: CORRELATE
# ═══════════════════════════════════════════════════════════

class CorrelateStage(PipelineStage):
    """
    AI-driven correlation: campaign detection, IOC clustering, CVE linking.
    Wraps the AI Intelligence Engine.
    """

    name = "correlate"

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        logger.info(f"[{self.name}] Correlating {len(ctx.items)} items")

        try:
            from core.ai_engine import ai_engine
            analysis = ai_engine.analyze(ctx.items)

            # Attach campaign IDs to items
            for campaign in analysis.get("campaigns", []):
                for member_title in campaign.get("member_titles", []):
                    for item in ctx.items:
                        if item.get("title") == member_title:
                            item["campaign_id"] = campaign["campaign_id"]
                            item["campaign_name"] = campaign["name"]

            # Attach cluster IDs
            for cluster in analysis.get("ioc_clusters", []):
                for source_id in cluster.get("source_intel", []):
                    for item in ctx.items:
                        if item.get("intel_id") == source_id or item.get("title") == source_id:
                            item["cluster_id"] = cluster["cluster_id"]

            ctx.metadata["ai_analysis"] = analysis.get("summary", {})
            ctx.metadata["campaigns"] = analysis.get("campaigns", [])
            ctx.metadata["ioc_clusters"] = analysis.get("ioc_clusters", [])
            ctx.metadata["cve_correlations"] = analysis.get("cve_correlations", [])
            ctx.metadata["anomalies"] = analysis.get("anomalies", [])
            ctx.metrics["correlated"] = len(ctx.items)

        except Exception as e:
            logger.warning(f"[{self.name}] AI correlation failed (non-fatal): {e}")
            ctx.metrics["correlated"] = len(ctx.items)

        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.correlated", {
            "run_id": ctx.run_id,
            "campaigns": len(ctx.metadata.get("campaigns", [])),
        })

        return ctx


# ═══════════════════════════════════════════════════════════
# STAGE 5: SCORE
# ═══════════════════════════════════════════════════════════

class ScoreStage(PipelineStage):
    """
    Dynamic risk scoring with AI enhancement.
    Wraps existing RiskScoringEngine + detection engine.
    """

    name = "score"

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        logger.info(f"[{self.name}] Scoring {len(ctx.items)} items")

        # Load scoring engine
        try:
            from agent.risk_engine import RiskScoringEngine
            scorer = RiskScoringEngine()
        except ImportError:
            scorer = None

        # Load detection engine
        try:
            from core.detection import detection_engine as det_engine
        except ImportError:
            det_engine = None

        # Load AI engine for quick scoring
        try:
            from core.ai_engine import ai_engine
        except ImportError:
            ai_engine = None

<<<<<<< HEAD
=======
        # Seed detection watchlists from current batch IOCs for cross-item matching
        if det_engine:
            for item in ctx.items:
                for ioc_type, values in item.get("iocs", {}).items():
                    if isinstance(values, list) and values:
                        det_engine.ioc_matcher.load_watchlist(ioc_type, values)

>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        total_detections = 0

        for item in ctx.items:
            # Base risk scoring
            if scorer:
                risk_score = scorer.calculate_risk_score(
                    iocs=item.get("iocs", {}),
                    mitre_matches=[{"id": t} for t in item.get("mitre_tactics", [])],
                    actor_data={"tracking_id": item.get("actor_tag", "UNC-CDB-99")},
                    cvss_score=item.get("cvss_score"),
                    epss_score=item.get("epss_score"),
                    headline=item.get("title", ""),
                    content=item.get("content", ""),
                    kev_present=item.get("kev_present", False),
                )
                item["risk_score"] = risk_score
                item["severity"] = scorer.get_severity_label(risk_score)
                item["tlp_label"] = scorer.get_tlp_label(risk_score)["label"]

                # Extended metrics
                extended = scorer.compute_extended_metrics(
                    risk_score=risk_score,
                    headline=item.get("title", ""),
                    content=item.get("content", ""),
                    cvss_score=item.get("cvss_score"),
                    epss_score=item.get("epss_score"),
                    kev_present=item.get("kev_present", False),
                    iocs=item.get("iocs"),
                    mitre_matches=[{"id": t} for t in item.get("mitre_tactics", [])],
                )
                item["extended_metrics"] = extended
            else:
                item.setdefault("risk_score", 3.0)
                item.setdefault("severity", "MEDIUM")
                item.setdefault("tlp_label", "TLP:GREEN")

            # AI-enhanced scoring
            if ai_engine:
                ai_signals = ai_engine.quick_score(item)
                modifier = ai_signals.get("ai_risk_modifier", 0)
                if modifier > 0:
                    item["risk_score"] = min(10.0, item["risk_score"] + modifier)
                    item["ai_analysis"] = ai_signals

            # Detection engine
            if det_engine:
                detections = det_engine.run_detections(item)
                if detections:
                    item["detections"] = detections
                    total_detections += len(detections)
                    # Boost risk for high-confidence detections
                    critical_detections = [d for d in detections if d.get("severity") == "CRITICAL"]
                    if critical_detections:
                        item["risk_score"] = min(10.0, item["risk_score"] + 1.0)

            # Recalculate severity after all adjustments
            if scorer:
                item["severity"] = scorer.get_severity_label(item["risk_score"])
                item["tlp_label"] = scorer.get_tlp_label(item["risk_score"])["label"]

            # Confidence score
            item["confidence_score"] = self._calculate_confidence(item)

        ctx.metrics["scored"] = len(ctx.items)
        ctx.metrics["detections"] = total_detections
        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.scored", {
            "run_id": ctx.run_id,
            "scored": len(ctx.items),
            "detections": total_detections,
        })

        logger.info(f"[{self.name}] {len(ctx.items)} items scored, {total_detections} detections")
        return ctx

    def _calculate_confidence(self, item: Dict) -> float:
        """Calculate confidence score based on available signals."""
        confidence = 20.0
        if item.get("cvss_score"):
            confidence += 15
        if item.get("epss_score"):
            confidence += 12
        if item.get("kev_present"):
            confidence += 20
        iocs = item.get("iocs", {})
        ioc_types = sum(1 for v in iocs.values() if v)
        confidence += min(30, ioc_types * 5)
        if item.get("mitre_tactics"):
            confidence += 10
        actor = item.get("actor_tag", "")
        if actor and not actor.startswith("UNC-"):
            confidence += 10
        if item.get("risk_score", 0) >= 7.0:
            confidence += 10
        if item.get("detections"):
            confidence += 8
        return min(100.0, confidence)


# ═══════════════════════════════════════════════════════════
# STAGE 6: STORE
# ═══════════════════════════════════════════════════════════

class StoreStage(PipelineStage):
    """
    Stores intelligence to database and hardened manifest.
    Generates STIX 2.1 bundles via existing exporter.
    """

    name = "store"

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        logger.info(f"[{self.name}] Storing {len(ctx.items)} items")

        stored_count = 0

        # Load STIX exporter
        try:
            from agent.export_stix import STIXExporter
            stix_exporter = STIXExporter()
        except ImportError:
            stix_exporter = None

<<<<<<< HEAD
        # Load manifest manager
        try:
            from core.manifest_manager import manifest_manager
        except ImportError:
            manifest_manager = None
=======
        # Load manifest manager (prefer test manifest if injected)
        manifest_manager = ctx.metadata.get("_test_manifest_manager")
        if not manifest_manager:
            try:
                from core.manifest_manager import manifest_manager
            except ImportError:
                manifest_manager = None
>>>>>>> claude/ai-threat-intelligence-system-eFwfT

        # Load database
        try:
            from core.storage import get_db
            db = get_db()
        except Exception:
            db = None

        for item in ctx.items:
            try:
                # Generate STIX bundle
                stix_id = ""
                if stix_exporter:
                    stix_id = stix_exporter.create_bundle(
                        title=item.get("title", ""),
                        iocs=item.get("iocs", {}),
                        risk_score=item.get("risk_score", 0),
                        metadata={"source_url": item.get("source_url", ""), "blog_url": item.get("blog_url", "")},
                        confidence=item.get("confidence_score", 0),
                        severity=item.get("severity", "MEDIUM"),
                        tlp_label=item.get("tlp_label", "TLP:CLEAR"),
                        ioc_counts=item.get("ioc_counts", {}),
                        actor_tag=item.get("actor_tag", "UNC-CDB-99"),
                        mitre_tactics=item.get("mitre_tactics", []),
                        feed_source=item.get("feed_source", ""),
                        epss_score=item.get("epss_score"),
                        cvss_score=item.get("cvss_score"),
                        kev_present=item.get("kev_present", False),
                        nvd_url=item.get("nvd_url"),
                    )
                    item["stix_id"] = stix_id

                # Store to hardened manifest
                if manifest_manager:
                    manifest_manager.append_entry({
                        "title": item.get("title", ""),
                        "stix_id": stix_id,
                        "risk_score": item.get("risk_score", 0),
                        "timestamp": item.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "severity": item.get("severity", "MEDIUM"),
                        "source_url": item.get("source_url", ""),
                        "confidence_score": item.get("confidence_score", 0),
                        "tlp_label": item.get("tlp_label", "TLP:CLEAR"),
                        "ioc_counts": item.get("ioc_counts", {}),
                        "actor_tag": item.get("actor_tag", "UNC-CDB-99"),
                        "mitre_tactics": item.get("mitre_tactics", []),
                        "feed_source": item.get("feed_source", ""),
                        "cvss_score": item.get("cvss_score"),
                        "epss_score": item.get("epss_score"),
                        "kev_present": item.get("kev_present", False),
                    }, caller="orchestrator")

                # Store to database
                if db:
                    item["pipeline_run_id"] = ctx.run_id
                    db.store_intelligence(item)

                    # Store IOCs
                    for ioc_type, values in item.get("iocs", {}).items():
                        if isinstance(values, list):
                            for val in values:
                                db.store_ioc({
                                    "intel_id": item.get("intel_id", ""),
                                    "ioc_type": ioc_type,
                                    "ioc_value": val,
                                    "confidence": item.get("confidence_score", 0),
                                    "source": "sentinel-apex-pipeline",
                                })

                stored_count += 1

            except Exception as e:
                ctx.add_error(self.name, str(e), item.get("title", ""))

        # Store campaigns
        if db:
            for campaign in ctx.metadata.get("campaigns", []):
                try:
                    db.store_campaign(campaign)
                except Exception:
                    pass

        ctx.metrics["stored"] = stored_count
        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.stored", {
            "run_id": ctx.run_id, "stored": stored_count
        })

        logger.info(f"[{self.name}] {stored_count} items stored")
        return ctx


# ═══════════════════════════════════════════════════════════
# STAGE 7: PUBLISH
# ═══════════════════════════════════════════════════════════

class PublishStage(PipelineStage):
    """
    Publishes intelligence to blog, dashboard, and notification channels.
<<<<<<< HEAD
=======
    Generates premium intelligence reports for high-severity items.
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
    Wraps existing publisher.py and sentinel_blogger.py.
    """

    name = "publish"

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        logger.info(f"[{self.name}] Publishing {len(ctx.items)} items")

        published_count = 0

<<<<<<< HEAD
=======
        # Load report engine for premium report generation
        try:
            from core.report_engine import report_engine
            has_reports = True
        except ImportError:
            has_reports = False

>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        for item in ctx.items:
            try:
                # Mark as ready for blog publishing (actual publish handled by workflows)
                item["status"] = "ready_to_publish"
                item["published_at"] = datetime.now(timezone.utc).isoformat()
<<<<<<< HEAD
=======

                # Generate premium report for HIGH+ severity items
                if has_reports and item.get("risk_score", 0) >= 6.0:
                    try:
                        report = report_engine.generate_report(item)
                        item["intel_report"] = report
                    except Exception as e:
                        logger.debug(f"Report generation skipped for '{item.get('title', '')[:40]}': {e}")

>>>>>>> claude/ai-threat-intelligence-system-eFwfT
                published_count += 1
            except Exception as e:
                ctx.add_error(self.name, str(e), item.get("title", ""))

<<<<<<< HEAD
=======
        # Generate executive briefing for the batch
        if has_reports and ctx.items:
            try:
                briefing = report_engine.generate_executive_briefing(ctx.items)
                ctx.metadata["executive_briefing"] = briefing
            except Exception:
                pass

        # Generate SOC action cards for top threats
        if has_reports and ctx.items:
            try:
                action_cards = report_engine.generate_soc_action_cards(ctx.items)
                ctx.metadata["soc_action_cards"] = action_cards
            except Exception:
                pass

>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        # Emit critical threat alerts
        critical_items = [i for i in ctx.items if i.get("severity") == "CRITICAL"]
        if critical_items:
            self._emit_event("threat.critical", {
                "run_id": ctx.run_id,
                "count": len(critical_items),
                "titles": [i.get("title", "")[:80] for i in critical_items[:5]],
            })

        # Emit zero-day alerts
        zero_days = [i for i in ctx.items if any(
            t in i.get("title", "").lower()
            for t in ["zero-day", "0-day", "zero day"]
        )]
        if zero_days:
            self._emit_event("threat.zero_day", {
                "run_id": ctx.run_id,
                "count": len(zero_days),
                "titles": [i.get("title", "")[:80] for i in zero_days[:5]],
            })

        ctx.metrics["published"] = published_count
<<<<<<< HEAD
        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.published", {
            "run_id": ctx.run_id, "published": published_count
        })

        logger.info(f"[{self.name}] {published_count} items published")
=======
        ctx.metrics["reports_generated"] = sum(
            1 for i in ctx.items if i.get("intel_report")
        )
        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.published", {
            "run_id": ctx.run_id,
            "published": published_count,
            "reports_generated": ctx.metrics["reports_generated"],
        })

        logger.info(
            f"[{self.name}] {published_count} items published, "
            f"{ctx.metrics['reports_generated']} reports generated"
        )
>>>>>>> claude/ai-threat-intelligence-system-eFwfT
        return ctx
