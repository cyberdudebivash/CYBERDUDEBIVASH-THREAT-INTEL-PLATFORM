#!/usr/bin/env python3
"""
stages.py — CYBERDUDEBIVASH® SENTINEL APEX v47.0 (COMMAND CENTER)
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
        """Collect intelligence from RSS feeds + Malware Pipeline."""
        items: List[Dict] = []

        # ── RSS feeds ─────────────────────────────────────────────────────────
        try:
            from agent.config import RSS_FEEDS, MAX_ENTRIES_PER_FEED, SOURCE_FETCH_TIMEOUT
            import feedparser
            for feed_url in RSS_FEEDS:
                try:
                    feed = feedparser.parse(feed_url, timeout=SOURCE_FETCH_TIMEOUT)
                    for entry in feed.entries[:MAX_ENTRIES_PER_FEED]:
                        items.append({
                            "title":      getattr(entry, "title", ""),
                            "content":    getattr(entry, "summary", ""),
                            "source_url": getattr(entry, "link", ""),
                            "feed_source": feed_url,
                            "published":  getattr(entry, "published", ""),
                            "raw_entry": {
                                "title": getattr(entry, "title", ""),
                                "link":  getattr(entry, "link", ""),
                            },
                        })
                except Exception as e:
                    logger.debug(f"[ingest] Feed failed {feed_url[:50]}: {e}")
        except ImportError:
            logger.warning("[ingest] feedparser or agent.config not available")

        # ── PHASE 3: Malware Pipeline ingestion ──────────────────────────────
        malware_items = self._collect_malware_samples()
        items.extend(malware_items)
        if malware_items:
            logger.info(f"[ingest] Malware pipeline contributed {len(malware_items)} samples")

        return items

    def _collect_malware_samples(self) -> List[Dict]:
        """
        Fetch recent malware samples from MalwareBazaar via MalwarePipeline,
        convert to IntelItems, and return for downstream processing.
        """
        results: List[Dict] = []
        try:
            from core.malware.malware_pipeline import get_pipeline
            mp = get_pipeline()
            samples = mp.fetch_recent_samples(limit=25)
            for sample in samples:
                intel_item = mp.to_intel_item(sample)
                # Normalise to pipeline schema
                iocs_flat = {
                    "sha256":  [sample.sha256] if sample.sha256 else [],
                    "sha1":    [sample.sha1]   if sample.sha1   else [],
                    "md5":     [sample.md5]    if sample.md5    else [],
                    "ipv4":    sample.iocs.get("ips", []),
                    "domain":  sample.iocs.get("domains", []),
                    "url":     sample.iocs.get("urls", []),
                }
                results.append({
                    "type":        "malware",
                    "title":       f"Malware Sample — {sample.family} [{sample.verdict.upper()}] {(sample.sha256 or sample.md5 or 'unknown')[:16]}",
                    "content":     f"Family: {sample.family}. File type: {sample.file_type}. Tags: {', '.join(sample.tags[:5])}. TTPs: {', '.join(sample.mitre_ttps[:5])}.",
                    "source_url":  f"https://bazaar.abuse.ch/sample/{sample.sha256}/",
                    "feed_source": "malwarebazaar",
                    "published":   sample.first_seen,
                    "iocs":        iocs_flat,
                    "mitre_tactics": sample.mitre_ttps,
                    "verdict":     sample.verdict,
                    "family":      sample.family,
                    "sources":     sample.sources,
                    "confidence_score": float(sample.confidence),
                    "yara_hits":   sample.yara_hits,
                    "malware_intel": intel_item,
                })
        except Exception as exc:
            logger.warning(f"[ingest] Malware pipeline collection failed: {exc}")
        return results


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

        # Also check against hardened manifest
        try:
            from core.manifest_manager import manifest_manager
            manifest_check = manifest_manager.is_duplicate
        except ImportError:
            manifest_check = None

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
        """Map intelligence item to MITRE ATT&CK techniques."""
        try:
            from agent.mitre_mapper import map_mitre_tactics
            return map_mitre_tactics(item.get("title", ""), item.get("content", ""))
        except ImportError:
            pass

        # Fallback: keyword-based mapping
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
        return tactics[:5]

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
# STAGE 4: CORRELATE  (v123.0.0 — AI CYBER BRAIN ACTIVE)
# ═══════════════════════════════════════════════════════════

class CorrelateStage(PipelineStage):
    """
    AI-driven correlation using the full AI Cyber Brain stack:
      1. CampaignClusterer  — DBSCAN groups items into named campaigns
      2. AnomalyDetector    — Isolation Forest flags novel/unknown threats
      3. Intelligence Graph — IOC ↔ actor ↔ campaign relationship mapping
      4. Legacy ai_engine   — backwards-compatible IOC clustering + CVE linking

    Each item is enriched with:
      campaign_id, campaign_name, is_anomaly, anomaly_type, anomaly_score,
      zero_day_probability, novelty_score, graph_node_ids
    """

    name = "correlate"

    # ── Baseline training (fit anomaly detector once per process) ──────────────
    _anomaly_baseline_fitted: bool = False
    _anomaly_baseline_lock: "threading.RLock | None" = None

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        import threading as _threading
        if CorrelateStage._anomaly_baseline_lock is None:
            CorrelateStage._anomaly_baseline_lock = _threading.RLock()

        logger.info(f"[{self.name}] Correlating {len(ctx.items)} items — AI Cyber Brain ACTIVE")

        # ── 1. Load AI singletons ─────────────────────────────────────────────
        anomaly_detector = None
        campaign_clusterer = None
        try:
            from core.ai import get_anomaly_detector, get_campaign_clusterer
            anomaly_detector   = get_anomaly_detector()
            campaign_clusterer = get_campaign_clusterer()
        except Exception as exc:
            logger.warning(f"[{self.name}] AI module load failed: {exc}")

        # ── 2. Fit anomaly detector baseline on first run ─────────────────────
        if anomaly_detector and not CorrelateStage._anomaly_baseline_fitted and len(ctx.items) >= 5:
            with CorrelateStage._anomaly_baseline_lock:
                if not CorrelateStage._anomaly_baseline_fitted:
                    try:
                        anomaly_detector.fit(ctx.items)
                        CorrelateStage._anomaly_baseline_fitted = True
                        logger.info(f"[{self.name}] AnomalyDetector fitted on {len(ctx.items)} baseline items")
                    except Exception as exc:
                        logger.warning(f"[{self.name}] AnomalyDetector fit failed: {exc}")

        # ── 3. Campaign clustering ────────────────────────────────────────────
        campaigns_output: List[Dict] = []
        if campaign_clusterer and ctx.items:
            try:
                # Build lightweight item proxy for clusterer (include all enrichment fields)
                cluster_items = []
                for item in ctx.items:
                    proxy = {
                        "id": item.get("intel_id", item.get("title", "")[:40]),
                        "title": item.get("title", ""),
                        "ttps": item.get("mitre_tactics", item.get("ttps", [])),
                        "iocs": self._flatten_iocs(item.get("iocs", {})),
                        "actor": item.get("actor_tag", item.get("actor", "unknown")),
                        "sector": item.get("sector", "unknown"),
                        "severity": item.get("severity", "medium"),
                        "cvss_score": item.get("cvss_score") or 0.0,
                        "epss_score": item.get("epss_score") or 0.0,
                        "kev": item.get("kev_present", False),
                        "disclosure_date": item.get("timestamp", item.get("published", "")),
                        "description": item.get("content", "")[:200],
                        "tags": item.get("tags", []),
                    }
                    cluster_items.append(proxy)

                raw_campaigns = campaign_clusterer.cluster(cluster_items)
                campaigns_output = self._build_campaign_metadata(raw_campaigns, ctx.items)

                # Attach campaign_id + campaign_name back to items
                for camp in raw_campaigns:
                    camp_id   = camp.get("campaign_id", "")
                    camp_name = camp.get("campaign_name", "")
                    is_singleton = camp.get("is_singleton", False)
                    if is_singleton:
                        continue
                    for member in camp.get("items", []):
                        member_id = member.get("id", "")
                        for item in ctx.items:
                            if item.get("intel_id", "") == member_id or item.get("title", "")[:40] == member_id:
                                item["campaign_id"]   = camp_id
                                item["campaign_name"] = camp_name
                                break

                logger.info(f"[{self.name}] Campaigns detected: {len([c for c in raw_campaigns if not c.get('is_singleton')])}")
            except Exception as exc:
                logger.warning(f"[{self.name}] Campaign clustering failed: {exc}")

        # ── 4. Anomaly detection per item ─────────────────────────────────────
        anomaly_items: List[Dict] = []
        if anomaly_detector:
            try:
                for item in ctx.items:
                    proxy = self._item_to_anomaly_proxy(item)
                    anomaly_result = anomaly_detector.detect(proxy)
                    zd_result      = anomaly_detector.detect_zero_day_indicators(proxy)
                    novelty        = anomaly_detector.get_novelty_score(proxy)

                    item["is_anomaly"]            = anomaly_result["is_anomaly"]
                    item["anomaly_score"]         = anomaly_result["anomaly_score"]
                    item["anomaly_type"]          = anomaly_result["anomaly_type"]
                    item["anomaly_explanation"]   = anomaly_result["explanation"]
                    item["novelty_score"]         = novelty
                    item["zero_day_probability"]  = zd_result["zero_day_probability"]
                    item["zero_day_indicators"]   = zd_result["indicators"]

                    if anomaly_result["is_anomaly"]:
                        anomaly_items.append({
                            "intel_id":    item.get("intel_id", ""),
                            "title":       item.get("title", "")[:80],
                            "anomaly_type": anomaly_result["anomaly_type"],
                            "anomaly_score": anomaly_result["anomaly_score"],
                            "zero_day_probability": zd_result["zero_day_probability"],
                        })

                # Temporal spike detection
                temporal = anomaly_detector.detect_temporal_anomaly(ctx.items)
                ctx.metadata["temporal_anomaly"] = temporal

                logger.info(f"[{self.name}] Anomalies flagged: {len(anomaly_items)}/{len(ctx.items)}")
            except Exception as exc:
                logger.warning(f"[{self.name}] Anomaly detection failed: {exc}")

        # ── 5. Intelligence Graph enrichment ─────────────────────────────────
        try:
            from core.intelligence.enrichment_graph import graph as intel_graph
            for item in ctx.items:
                ioc_flat = self._flatten_iocs(item.get("iocs", {}))
                node_ids = []
                for ioc_val in ioc_flat[:10]:   # limit to 10 IOCs per item for perf
                    try:
                        nid = intel_graph.add_ioc(
                            ioc_val,
                            source=item.get("feed_source", "pipeline"),
                            confidence=int(item.get("confidence_score", 50)),
                        )
                        node_ids.append(nid)
                    except Exception:
                        pass
                if node_ids:
                    item["graph_node_ids"] = node_ids
        except Exception as exc:
            logger.debug(f"[{self.name}] Graph enrichment skipped: {exc}")

        # ── 6. Legacy ai_engine (backwards compat) ────────────────────────────
        try:
            from core.ai_engine import ai_engine
            analysis = ai_engine.analyze(ctx.items)
            ctx.metadata.setdefault("ioc_clusters",     analysis.get("ioc_clusters", []))
            ctx.metadata.setdefault("cve_correlations", analysis.get("cve_correlations", []))
            ctx.metadata.setdefault("ai_analysis",      analysis.get("summary", {}))
        except Exception as exc:
            logger.debug(f"[{self.name}] Legacy ai_engine skipped: {exc}")

        # ── Persist to context ────────────────────────────────────────────────
        ctx.metadata["campaigns"]     = campaigns_output
        ctx.metadata["anomalies"]     = anomaly_items
        ctx.metrics["correlated"]     = len(ctx.items)
        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.correlated", {
            "run_id":    ctx.run_id,
            "campaigns": len(campaigns_output),
            "anomalies": len(anomaly_items),
        })

        return ctx

    # ── Helpers ───────────────────────────────────────────────────────────────

    @staticmethod
    def _flatten_iocs(iocs: Dict) -> List[str]:
        """Flatten iocs dict into a flat list of values."""
        flat = []
        for values in iocs.values():
            if isinstance(values, list):
                flat.extend(str(v) for v in values if v)
        return flat

    @staticmethod
    def _item_to_anomaly_proxy(item: Dict) -> Dict:
        """Translate a pipeline item dict to the anomaly detector's expected schema."""
        iocs = CorrelateStage._flatten_iocs(item.get("iocs", {}))
        ttps = item.get("mitre_tactics", item.get("ttps", []))
        return {
            "id":              item.get("intel_id", item.get("title", "")[:40]),
            "cvss_score":      item.get("cvss_score") or 0.0,
            "epss_score":      item.get("epss_score") or 0.0,
            "kev":             item.get("kev_present", False),
            "ttps":            ttps if isinstance(ttps, list) else [],
            "iocs":            iocs,
            "exploit_maturity": item.get("exploit_maturity", ""),
            "source":          item.get("feed_source", "unknown"),
            "sector":          item.get("sector", "unknown"),
            "severity":        item.get("severity", "medium"),
            "actor":           item.get("actor_tag", "unknown"),
            "disclosure_date": item.get("timestamp", item.get("published", "")),
            "vulnerability_id": (item.get("iocs", {}).get("cve") or [""])[0],
        }

    @staticmethod
    def _build_campaign_metadata(raw_campaigns: List[Dict], items: List[Dict]) -> List[Dict]:
        """Convert raw CampaignClusterer output to API-ready metadata dicts."""
        out = []
        for camp in raw_campaigns:
            if camp.get("is_singleton"):
                continue
            out.append({
                "campaign_id":       camp.get("campaign_id", ""),
                "campaign_name":     camp.get("campaign_name", ""),
                "item_count":        camp.get("item_count", 0),
                "threat_level":      camp.get("threat_level", "medium"),
                "confidence":        camp.get("confidence", 0.0),
                "actor_hypothesis":  camp.get("actor_hypothesis", "unknown"),
                "primary_sector":    camp.get("primary_sector", "unknown"),
                "common_ttps":       camp.get("common_ttps", [])[:10],
                "shared_iocs":       camp.get("shared_iocs", [])[:10],
                "start_date":        camp.get("start_date"),
                "end_date":          camp.get("end_date"),
                "member_titles":     [m.get("title", "")[:80] for m in camp.get("items", [])[:20]],
            })
        return out


# ═══════════════════════════════════════════════════════════
# STAGE 5: SCORE  (v123.0.0 — ThreatPredictor ACTIVE)
# ═══════════════════════════════════════════════════════════

class ScoreStage(PipelineStage):
    """
    Dynamic risk scoring with full AI enhancement:
      1. RiskScoringEngine    — multi-factor base score
      2. ThreatPredictor      — GBM predicted_severity + 30-day exploitation prob
      3. Anomaly boost        — anomaly_score modifier on risk
      4. DetectionEngine      — rule-based CRITICAL boosts
      5. Data Quality Gates   — no 0-IOC high-sev, CRITICAL confidence ≥ 70
    """

    name = "score"

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        logger.info(f"[{self.name}] Scoring {len(ctx.items)} items — ThreatPredictor ACTIVE")

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

        # Load AI engine for quick scoring (legacy)
        try:
            from core.ai_engine import ai_engine
        except ImportError:
            ai_engine = None

        # Load ThreatPredictor singleton
        threat_predictor = None
        try:
            from core.ai import get_threat_predictor
            threat_predictor = get_threat_predictor()
        except Exception as exc:
            logger.debug(f"[{self.name}] ThreatPredictor unavailable: {exc}")

        total_detections = 0

        for item in ctx.items:
            # ── Base risk scoring ─────────────────────────────────────────────
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

            # ── ThreatPredictor (GBM) — predicted_severity + 30d prob ───────
            if threat_predictor:
                try:
                    proxy = {
                        "cvss_score":      item.get("cvss_score") or 0.0,
                        "epss_score":      item.get("epss_score") or 0.0,
                        "kev":             item.get("kev_present", False),
                        "ttps":            item.get("mitre_tactics", []),
                        "iocs":            CorrelateStage._flatten_iocs(item.get("iocs", {})),
                        "exploit_maturity": item.get("exploit_maturity", ""),
                        "source":          item.get("feed_source", "unknown"),
                        "sector":          item.get("sector", "unknown"),
                        "actor":           item.get("actor_tag", "unknown"),
                        "disclosure_date": item.get("timestamp", item.get("published", "")),
                    }
                    pred = threat_predictor.predict(proxy)
                    item["predicted_severity"]         = pred["predicted_severity"]
                    item["prediction_confidence"]      = pred["confidence"]
                    item["risk_trajectory"]            = pred["risk_trajectory"]
                    item["exploitation_30d_prob"]      = pred["next_30d_exploitation_probability"]
                    item["top_risk_factors"]           = pred["feature_contributions"]

                    # Boost risk score if predictor says critical and trajectory escalating
                    if pred["severity_label_int"] >= 3 and pred["risk_trajectory"] in ("escalating", "rapidly_escalating"):
                        item["risk_score"] = min(10.0, item.get("risk_score", 3.0) + 1.5)
                    elif pred["severity_label_int"] >= 2 and pred["risk_trajectory"] == "rapidly_escalating":
                        item["risk_score"] = min(10.0, item.get("risk_score", 3.0) + 0.8)

                except Exception as exc:
                    logger.debug(f"[{self.name}] ThreatPredictor item failed: {exc}")

            # ── Anomaly risk boost ─────────────────────────────────────────────
            if item.get("is_anomaly"):
                anomaly_score = item.get("anomaly_score", 0.0)
                zd_prob = item.get("zero_day_probability", 0.0)
                # Anomalous items get risk boosted proportionally to zero-day probability
                boost = min(2.0, zd_prob * 2.5 + abs(anomaly_score) * 0.5)
                item["risk_score"] = min(10.0, item.get("risk_score", 3.0) + boost)

            # ── Legacy AI engine quick score ──────────────────────────────────
            if ai_engine:
                try:
                    ai_signals = ai_engine.quick_score(item)
                    modifier = ai_signals.get("ai_risk_modifier", 0)
                    if modifier > 0:
                        item["risk_score"] = min(10.0, item.get("risk_score", 3.0) + modifier)
                        item["ai_analysis"] = ai_signals
                except Exception:
                    pass

            # ── Detection engine ──────────────────────────────────────────────
            if det_engine:
                try:
                    detections = det_engine.run_detections(item)
                    if detections:
                        item["detections"] = detections
                        total_detections += len(detections)
                        critical_detections = [d for d in detections if d.get("severity") == "CRITICAL"]
                        if critical_detections:
                            item["risk_score"] = min(10.0, item.get("risk_score", 3.0) + 1.0)
                except Exception:
                    pass

            # ── Recalculate severity after all adjustments ────────────────────
            if scorer:
                item["severity"] = scorer.get_severity_label(item["risk_score"])
                item["tlp_label"] = scorer.get_tlp_label(item["risk_score"])["label"]

            # ── Confidence score ──────────────────────────────────────────────
            item["confidence_score"] = self._calculate_confidence(item)

            # ── PHASE 5: Data Quality Gates ───────────────────────────────────
            item = self._enforce_quality_gates(item)

        ctx.metrics["scored"] = len(ctx.items)
        ctx.metrics["detections"] = total_detections
        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.scored", {
            "run_id":    ctx.run_id,
            "scored":    len(ctx.items),
            "detections": total_detections,
        })

        logger.info(f"[{self.name}] {len(ctx.items)} items scored, {total_detections} detections")
        return ctx

    @staticmethod
    def _enforce_quality_gates(item: Dict) -> Dict:
        """
        PHASE 5 — Data Quality Enforcement (v123.2):
          1. HIGH/CRITICAL with 0 IOCs → attempt fallback enrichment first
             a. CVE→NVD reference URL extraction (NVD CPE vendors, affected products)
             b. Content re-parse with expanded IOC regex (looser matching)
             c. CVE ID itself promoted to indicator if no other IOC found
          2. If still 0 IOCs after fallback → downgrade severity + flag
          3. CRITICAL with confidence < 70 → downgrade to HIGH
          4. Multi-source validation flag
        """
        severity = item.get("severity", "MEDIUM").upper()
        iocs: Dict = item.get("iocs") or {}
        total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
        confidence = float(item.get("confidence_score") or 0.0)
        quality_flags: List[str] = list(item.get("quality_flags") or [])

        # ── Fallback enrichment for HIGH/CRITICAL with 0 IOCs ─────────────────
        if severity in ("HIGH", "CRITICAL") and total_iocs == 0:
            recovered = ScoreStage._fallback_ioc_expansion(item)
            if recovered:
                # Merge recovered IOCs back into item
                for ioc_type, vals in recovered.items():
                    existing = iocs.get(ioc_type, [])
                    merged = list(dict.fromkeys(existing + vals))  # deduplicate, preserve order
                    iocs[ioc_type] = merged
                item["iocs"] = iocs
                item["ioc_counts"] = {k: len(v) for k, v in iocs.items() if v}
                total_iocs = sum(len(v) for v in iocs.values() if isinstance(v, list))
                quality_flags.append(f"ioc_recovered:fallback({total_iocs})")
                logger.debug(f"Quality gate: {item.get('intel_id', '?')} recovered {total_iocs} IOCs via fallback")

        # Gate 1: Still 0 IOCs after fallback → downgrade
        if severity in ("HIGH", "CRITICAL") and total_iocs == 0:
            old_sev = severity
            item["severity"] = "MEDIUM"
            item["risk_score"] = min(item.get("risk_score", 5.0), 6.5)
            quality_flags.append(f"downgraded:{old_sev}→MEDIUM:zero_iocs")
            logger.warning(
                f"Quality gate: {item.get('intel_id', '?')} downgraded {old_sev}→MEDIUM "
                f"(zero IOCs after fallback expansion)"
            )

        # Gate 2: CRITICAL items need confidence ≥ 70
        if item.get("severity", "MEDIUM").upper() == "CRITICAL" and confidence < 70.0:
            item["severity"] = "HIGH"
            item["risk_score"] = min(item.get("risk_score", 8.0), 8.5)
            quality_flags.append(f"downgraded:CRITICAL→HIGH:low_confidence({confidence:.0f})")
            logger.debug(
                f"Quality gate: {item.get('intel_id', '?')} downgraded CRITICAL→HIGH "
                f"(confidence={confidence:.1f})"
            )

        # Gate 3: Multi-source validation
        sources = item.get("sources") or []
        if len(sources) >= 2:
            if "multi_source_validated" not in quality_flags:
                quality_flags.append("multi_source_validated")

        item["quality_flags"]    = quality_flags
        item["quality_ioc_count"] = total_iocs
        return item

    @staticmethod
    def _fallback_ioc_expansion(item: Dict) -> Dict[str, List[str]]:
        """
        Fallback IOC extraction for HIGH/CRITICAL items that have 0 IOCs.
        Attempts three strategies in order:
          1. Promote CVE IDs in title/content as vulnerability indicators
          2. Re-parse full content with expanded patterns (defanged IPs, partial hashes)
          3. Extract NVD CPE vendor strings / product references as contextual IOCs

        Returns dict of {ioc_type: [values]} — may be empty if nothing found.
        """
        recovered: Dict[str, List[str]] = {}

        title   = item.get("title", "") or ""
        content = item.get("content", "") or item.get("summary", "") or ""
        text    = f"{title} {content}"

        # Strategy 1: CVE IDs → vulnerability indicator
        import re as _re
        cves = list(set(_re.findall(r"CVE-\d{4}-\d{4,7}", text, _re.IGNORECASE)))
        if cves:
            recovered["cve"] = [c.upper() for c in cves[:10]]

        # Strategy 2: Defanged IOC patterns
        # Defanged IPs: 1[.]2[.]3[.]4 or 1(.)2(.)3(.)4
        defanged_ips = _re.findall(
            r"\b(\d{1,3}[\[\(]\.\]?\)?\d{1,3}[\[\(]\.\]?\)?\d{1,3}[\[\(]\.\]?\)?\d{1,3})\b", text
        )
        clean_ips = []
        for ip in defanged_ips:
            clean = _re.sub(r"[\[\](){}]", "", ip)
            if _re.match(r"^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$", clean):
                clean_ips.append(clean)
        if clean_ips:
            existing_ips = recovered.get("ipv4", [])
            recovered["ipv4"] = list(dict.fromkeys(existing_ips + clean_ips))[:5]

        # Defanged domains: evil[.]com or evil(.)com
        defanged_domains = _re.findall(
            r"\b([a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?[\[\(]\.[\]\)](?:[a-z]{2,10}))\b",
            text, _re.IGNORECASE
        )
        clean_domains = [_re.sub(r"[\[\](){}]", "", d) for d in defanged_domains]
        if clean_domains:
            existing_dom = recovered.get("domain", [])
            recovered["domain"] = list(dict.fromkeys(existing_dom + clean_domains))[:5]

        # Strategy 3: Partial SHA256 hashes (≥16 hex chars)
        partial_hashes = _re.findall(r"\b[0-9a-fA-F]{32,64}\b", text)
        if partial_hashes:
            # Only keep if they look like proper hashes (not just numbers)
            real_hashes = [h for h in partial_hashes if
                           sum(c.isalpha() for c in h) >= 4][:5]
            if real_hashes:
                recovered["md5_or_sha256"] = real_hashes

        # Strategy 4: Source URL as reference IOC (last resort)
        source_url = item.get("source_url", "") or ""
        if not recovered and source_url and source_url.startswith("http"):
            recovered["url"] = [source_url]

        return recovered

    def _calculate_confidence(self, item: Dict) -> float:
        """Calculate multi-signal confidence score [0-100]."""
        confidence = 20.0
        if item.get("cvss_score"):
            confidence += 15
        if item.get("epss_score"):
            confidence += 12
        if item.get("kev_present"):
            confidence += 20
        iocs = item.get("iocs", {})
        ioc_types = sum(1 for v in iocs.values() if v)
        confidence += min(20, ioc_types * 5)
        if item.get("mitre_tactics"):
            confidence += 8
        actor = item.get("actor_tag", "")
        if actor and not actor.startswith("UNC-"):
            confidence += 10
        if item.get("risk_score", 0) >= 7.0:
            confidence += 8
        if item.get("detections"):
            confidence += 8
        # Boost for predictor high confidence
        pred_conf = item.get("prediction_confidence", 0.0)
        if pred_conf >= 0.80:
            confidence += 10
        elif pred_conf >= 0.60:
            confidence += 5
        # Boost for multi-source malware
        if item.get("type") == "malware" and len(item.get("sources", [])) >= 2:
            confidence += 15
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

        # Load manifest manager
        try:
            from core.manifest_manager import manifest_manager
        except ImportError:
            manifest_manager = None

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

                # Store to hardened manifest (v123 — AI fields included)
                if manifest_manager:
                    manifest_manager.append_entry({
                        "title":              item.get("title", ""),
                        "stix_id":            stix_id,
                        "risk_score":         item.get("risk_score", 0),
                        "timestamp":          item.get("timestamp", datetime.now(timezone.utc).isoformat()),
                        "severity":           item.get("severity", "MEDIUM"),
                        "source_url":         item.get("source_url", ""),
                        "confidence_score":   item.get("confidence_score", 0),
                        "tlp_label":          item.get("tlp_label", "TLP:CLEAR"),
                        "ioc_counts":         item.get("ioc_counts", {}),
                        "actor_tag":          item.get("actor_tag", "UNC-CDB-99"),
                        "mitre_tactics":      item.get("mitre_tactics", []),
                        "feed_source":        item.get("feed_source", ""),
                        "cvss_score":         item.get("cvss_score"),
                        "epss_score":         item.get("epss_score"),
                        "kev_present":        item.get("kev_present", False),
                        # AI Cyber Brain outputs
                        "is_anomaly":         item.get("is_anomaly", False),
                        "anomaly_type":       item.get("anomaly_type", "normal"),
                        "anomaly_score":      item.get("anomaly_score", 0.0),
                        "zero_day_probability": item.get("zero_day_probability", 0.0),
                        "novelty_score":      item.get("novelty_score", 0.0),
                        "predicted_severity": item.get("predicted_severity", ""),
                        "exploitation_30d_prob": item.get("exploitation_30d_prob", 0.0),
                        "risk_trajectory":    item.get("risk_trajectory", "stable"),
                        "campaign_id":        item.get("campaign_id", ""),
                        "campaign_name":      item.get("campaign_name", ""),
                        "quality_flags":      item.get("quality_flags", []),
                        # Malware-specific
                        "type":               item.get("type", "intel"),
                        "family":             item.get("family", ""),
                        "verdict":            item.get("verdict", ""),
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
    Wraps existing publisher.py and sentinel_blogger.py.
    """

    name = "publish"

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        logger.info(f"[{self.name}] Publishing {len(ctx.items)} items")

        published_count = 0

        for item in ctx.items:
            try:
                # Mark as ready for blog publishing (actual publish handled by workflows)
                item["status"] = "ready_to_publish"
                item["published_at"] = datetime.now(timezone.utc).isoformat()
                published_count += 1
            except Exception as e:
                ctx.add_error(self.name, str(e), item.get("title", ""))

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
        ctx.mark_stage_complete(self.name)

        self._emit_event("intel.published", {
            "run_id": ctx.run_id, "published": published_count
        })

        logger.info(f"[{self.name}] {published_count} items published")
        return ctx


# ═══════════════════════════════════════════════════════════
# STAGE 8: R2 AI EXPORT
# ═══════════════════════════════════════════════════════════

class R2AIExportStage(PipelineStage):
    """
    Exports AI analysis outputs (campaigns, anomalies, intel graph) to
    Cloudflare R2 after each pipeline run so the Worker can serve them.

    R2 paths:
      data/ai/campaigns.json   — DBSCAN campaign clusters
      data/ai/anomalies.json   — Isolation Forest anomaly items
      data/ai/intel_graph.json — IOC enrichment graph snapshot

    Requires env vars:
      R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME
      (or boto3-compatible S3 endpoint via CF R2 S3 API)
    """

    name = "r2_ai_export"

    def execute(self, ctx: PipelineContext) -> PipelineContext:
        logger.info(f"[{self.name}] Exporting AI outputs to R2")

        try:
            import boto3
            from botocore.config import Config as BotoCfg

            account_id   = os.getenv("R2_ACCOUNT_ID", "")
            access_key   = os.getenv("R2_ACCESS_KEY_ID", "")
            secret_key   = os.getenv("R2_SECRET_ACCESS_KEY", "")
            bucket       = os.getenv("R2_BUCKET_NAME", "sentinel-apex-intel")

            if not (account_id and access_key and secret_key):
                logger.warning(f"[{self.name}] R2 credentials missing — skipping AI export")
                ctx.mark_stage_complete(self.name)
                return ctx

            r2 = boto3.client(
                "s3",
                endpoint_url=f"https://{account_id}.r2.cloudflarestorage.com",
                aws_access_key_id=access_key,
                aws_secret_access_key=secret_key,
                config=BotoCfg(signature_version="s3v4"),
                region_name="auto",
            )

            exported = []

            # ── Export campaigns ──────────────────────────────────────────────
            campaigns = ctx.metadata.get("campaigns", [])
            if campaigns:
                payload = json.dumps({
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "run_id":       ctx.run_id,
                    "campaigns":    campaigns,
                    "total":        len(campaigns),
                }, default=str)
                r2.put_object(
                    Bucket=bucket, Key="data/ai/campaigns.json",
                    Body=payload.encode(),
                    ContentType="application/json",
                )
                exported.append(f"campaigns({len(campaigns)})")

            # ── Export anomalies ──────────────────────────────────────────────
            anomalies = [
                {
                    "id":                  item.get("intel_id", ""),
                    "title":               item.get("title", ""),
                    "is_anomaly":          item.get("is_anomaly", False),
                    "anomaly_type":        item.get("anomaly_type", "normal"),
                    "anomaly_score":       item.get("anomaly_score", 0.0),
                    "zero_day_probability": item.get("zero_day_probability", 0.0),
                    "novelty_score":       item.get("novelty_score", 0.0),
                    "severity":            item.get("severity", ""),
                    "risk_score":          item.get("risk_score", 0.0),
                    "actor_tag":           item.get("actor_tag", ""),
                    "timestamp":           item.get("timestamp", ""),
                    "quality_flags":       item.get("quality_flags", []),
                    "zero_day_indicators": item.get("zero_day_indicators", []),
                }
                for item in ctx.items if item.get("is_anomaly")
            ]
            if anomalies:
                payload = json.dumps({
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "run_id":       ctx.run_id,
                    "anomalies":    anomalies,
                    "total":        len(anomalies),
                }, default=str)
                r2.put_object(
                    Bucket=bucket, Key="data/ai/anomalies.json",
                    Body=payload.encode(),
                    ContentType="application/json",
                )
                exported.append(f"anomalies({len(anomalies)})")

            # ── Export intel graph snapshot ───────────────────────────────────
            try:
                from core.intelligence.enrichment_graph import graph as intel_graph
                graph_data = intel_graph.export_snapshot() if hasattr(intel_graph, "export_snapshot") else None
                if not graph_data:
                    # Build minimal snapshot from graph's internal state
                    nodes = []
                    edges = []
                    if hasattr(intel_graph, "_graph"):
                        g = intel_graph._graph
                        for nid in g.nodes:
                            nd = g.nodes[nid]
                            nodes.append({
                                "id":           nid,
                                "type":         nd.get("ioc_type", "unknown"),
                                "value":        nd.get("ioc_value", nid),
                                "confidence":   nd.get("confidence", 0.0),
                                "source":       nd.get("source", ""),
                                "authority":    nd.get("authority_score", 0.0),
                                "threat_level": nd.get("threat_level", "unknown"),
                            })
                        for src, dst, edata in g.edges(data=True):
                            edges.append({
                                "source": src, "target": dst,
                                "relation": edata.get("relation", "related_to"),
                                "weight":   edata.get("weight", 1.0),
                            })
                    graph_data = {
                        "nodes": nodes,
                        "edges": edges,
                        "node_count": len(nodes),
                        "edge_count":  len(edges),
                    }
                payload = json.dumps({
                    "generated_at": datetime.now(timezone.utc).isoformat(),
                    "run_id":       ctx.run_id,
                    **graph_data,
                }, default=str)
                r2.put_object(
                    Bucket=bucket, Key="data/ai/intel_graph.json",
                    Body=payload.encode(),
                    ContentType="application/json",
                )
                exported.append(f"intel_graph({graph_data.get('node_count', 0)} nodes)")
            except Exception as ge:
                logger.warning(f"[{self.name}] Graph export skipped: {ge}")

            if exported:
                logger.info(f"[{self.name}] R2 AI exports: {', '.join(exported)}")
            else:
                logger.info(f"[{self.name}] No AI outputs to export this run")

        except ImportError:
            logger.warning(f"[{self.name}] boto3 not available — skipping R2 AI export")
        except Exception as e:
            logger.error(f"[{self.name}] R2 export error: {e}", exc_info=True)
            ctx.add_error(self.name, str(e), "r2_ai_export")

        ctx.mark_stage_complete(self.name)
        self._emit_event("ai.exported_to_r2", {"run_id": ctx.run_id})
        return ctx
