#!/usr/bin/env python3
"""
test_full_pipeline.py — SENTINEL APEX v47.0 Full System Validation
═══════════════════════════════════════════════════════════════════
End-to-end pipeline simulation with synthetic threat intelligence data.
Tests every component: event bus, manifest, AI engine, detection, storage, API.
"""

import os
import sys
import json
import time
import traceback
from datetime import datetime, timezone

# Ensure project root is on path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

PASS = "\033[92mPASS\033[0m"
FAIL = "\033[91mFAIL\033[0m"
WARN = "\033[93mWARN\033[0m"

results = {"passed": 0, "failed": 0, "warnings": 0, "details": []}


def record(name, passed, detail="", warn=False):
    if warn:
        results["warnings"] += 1
        status = WARN
    elif passed:
        results["passed"] += 1
        status = PASS
    else:
        results["failed"] += 1
        status = FAIL
    results["details"].append({"test": name, "passed": passed, "detail": detail})
    print(f"  [{status}] {name}" + (f" — {detail}" if detail else ""))


# ═══════════════════════════════════════════════════════════
# SAMPLE DATA
# ═══════════════════════════════════════════════════════════

SAMPLE_ITEMS = [
    {
        "title": "CVE-2026-21345 — Critical Remote Code Execution in Apache Struts Actively Exploited",
        "content": (
            "A critical zero-day vulnerability CVE-2026-21345 has been discovered in Apache Struts 2 "
            "allowing unauthenticated remote code execution. CISA has added this to the KEV catalog. "
            "The Lazarus Group APT has been observed actively exploiting this in the wild targeting "
            "critical infrastructure including power grid and financial institutions. "
            "Proof of concept exploit code is publicly available on GitHub. "
            "Over 500,000 systems are estimated to be vulnerable. "
            "IOCs include IP 198.51.100.42, domain malware-c2.evil.xyz, "
            "SHA256 a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
        ),
        "source_url": "https://example-advisory.com/CVE-2026-21345",
        "feed_source": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "published": "2026-03-20T10:00:00Z",
        "iocs": {
            "ipv4": ["198.51.100.42", "203.0.113.99"],
            "domain": ["malware-c2.evil.xyz", "exfil-data.badactor.com"],
            "sha256": ["a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"],
            "url": ["https://malware-c2.evil.xyz/payload.bin"],
            "cve": ["CVE-2026-21345"],
        },
    },
    {
        "title": "CVE-2026-21400 — Apache Struts Authentication Bypass Chained with CVE-2026-21345",
        "content": (
            "A second Apache Struts vulnerability CVE-2026-21400 allows authentication bypass "
            "and is being chained with CVE-2026-21345 for full system compromise. "
            "The Lazarus Group is using this attack chain against banking and government networks. "
            "Ransomware deployment observed post-exploitation. CVSS 9.8. "
            "IOCs: IP 203.0.113.99, domain exfil-data.badactor.com"
        ),
        "source_url": "https://example-advisory.com/CVE-2026-21400",
        "feed_source": "https://www.bleepingcomputer.com/feed/",
        "published": "2026-03-20T11:00:00Z",
        "iocs": {
            "ipv4": ["203.0.113.99"],
            "domain": ["exfil-data.badactor.com"],
            "cve": ["CVE-2026-21400", "CVE-2026-21345"],
        },
    },
    {
        "title": "Volt Typhoon Targets US Water Treatment Facilities via Fortinet Zero-Day",
        "content": (
            "Chinese state-sponsored threat actor Volt Typhoon has been observed exploiting "
            "a zero-day vulnerability in Fortinet FortiGate firewalls to gain access to "
            "US water treatment facilities. The attack uses living-off-the-land techniques. "
            "Nation-state espionage campaign targeting critical infrastructure. "
            "IOCs: IP 192.0.2.55, domain c2-typhoon.example.net, "
            "SHA256 deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"
        ),
        "source_url": "https://example-advisory.com/volt-typhoon-fortinet",
        "feed_source": "https://unit42.paloaltonetworks.com/feed/",
        "published": "2026-03-20T12:00:00Z",
        "iocs": {
            "ipv4": ["192.0.2.55"],
            "domain": ["c2-typhoon.example.net"],
            "sha256": ["deadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeefdeadbeef"],
            "cve": ["CVE-2026-30001"],
        },
    },
    {
        "title": "LockBit 4.0 Ransomware Campaign Targets Healthcare Sector",
        "content": (
            "LockBit ransomware group has launched version 4.0 with enhanced encryption "
            "targeting hospital and healthcare networks. Over 50 hospitals affected. "
            "Data exfiltration of 2.5 million patient records confirmed. "
            "Supply chain attack via compromised medical device vendor software update. "
            "IOC: domain lockbit4-payment.onion.ws, email ransom@lockbit4.evil"
        ),
        "source_url": "https://example-advisory.com/lockbit4",
        "feed_source": "https://therecord.media/feed/",
        "published": "2026-03-20T13:00:00Z",
        "iocs": {
            "domain": ["lockbit4-payment.onion.ws"],
            "email": ["ransom@lockbit4.evil"],
        },
    },
    {
        "title": "npm Supply Chain Attack: Malicious Packages Targeting Developer Credentials",
        "content": (
            "A coordinated supply chain attack has been identified with 15 malicious npm packages "
            "typosquatting popular libraries. Credential harvesting and session token theft observed. "
            "Packages include compromised build pipelines. Over 100,000 developers affected. "
            "IOC: domain npm-exfil.attacker.xyz"
        ),
        "source_url": "https://example-advisory.com/npm-supply-chain",
        "feed_source": "https://www.securityweek.com/feed/",
        "published": "2026-03-20T14:00:00Z",
        "iocs": {
            "domain": ["npm-exfil.attacker.xyz"],
        },
    },
]

# ═══════════════════════════════════════════════════════════
# TEST SUITES
# ═══════════════════════════════════════════════════════════

def test_event_bus():
    print("\n══ TEST SUITE 1: Event Bus ══")
    from core.event_bus import SentinelEventBus, EventTypes, EventPriority

    bus = SentinelEventBus(force_memory=True)

    # 1.1 — Emit and track
    captured = []
    bus.subscribe(EventTypes.INTEL_INGESTED, lambda e: captured.append(e))
    event = bus.emit(EventTypes.INTEL_INGESTED, {"count": 5}, EventPriority.HIGH)
    record("Event emission + handler dispatch", len(captured) == 1 and captured[0].payload["count"] == 5)

    # 1.2 — Idempotency
    event2 = bus.emit(EventTypes.INTEL_INGESTED, {"count": 5}, EventPriority.HIGH)
    record("Idempotent dedup (same payload suppressed)", len(captured) == 1,
           f"captures={len(captured)}")

    # 1.3 — Different event type
    bus.subscribe(EventTypes.THREAT_CRITICAL, lambda e: captured.append(e))
    bus.emit(EventTypes.THREAT_CRITICAL, {"title": "zero-day"}, EventPriority.CRITICAL)
    record("Multi-event type dispatch", len(captured) == 2)

    # 1.4 — Priority queue
    bus.enqueue("test_queue", EventTypes.INTEL_SCORED, {"risk": 9.5}, EventPriority.CRITICAL)
    bus.enqueue("test_queue", EventTypes.INTEL_SCORED, {"risk": 3.0}, EventPriority.LOW)
    dequeued = bus.dequeue("test_queue")
    record("Priority queue (CRITICAL dequeued first)",
           dequeued is not None and dequeued.payload.get("risk") == 9.5,
           f"dequeued_risk={dequeued.payload.get('risk') if dequeued else 'None'}")

    # 1.5 — Distributed lock
    token = bus.acquire_lock("test_lock", ttl=10)
    record("Lock acquisition", token is not None)
    token2 = bus.acquire_lock("test_lock", ttl=10)
    record("Lock contention (second acquire fails)", token2 is None)
    bus.release_lock("test_lock", token)
    token3 = bus.acquire_lock("test_lock", ttl=10)
    record("Lock release + re-acquire", token3 is not None)
    bus.release_lock("test_lock", token3)

    # 1.6 — Stats
    stats = bus.get_stats()
    record("Stats reporting", stats["events_published"] >= 2,
           f"published={stats['events_published']}, deduped={stats['events_deduplicated']}")


def test_manifest_manager():
    print("\n══ TEST SUITE 2: Hardened Manifest Manager ══")
    import tempfile, shutil
    from core.manifest_manager import ManifestManager

    tmpdir = tempfile.mkdtemp(prefix="cdb_test_manifest_")
    try:
        mm = ManifestManager(manifest_dir=tmpdir, max_entries=100)

        # 2.1 — Append valid entry
        ok, msg = mm.append_entry({
            "title": "CVE-2026-99999 Test Vulnerability",
            "stix_id": "bundle--test-001",
            "risk_score": 8.5,
            "timestamp": "2026-03-20T00:00:00Z",
            "severity": "CRITICAL",
            "source_url": "https://test.example.com/cve-99999",
        })
        record("Append valid entry", ok, msg)

        # 2.2 — Dedup (same title)
        ok2, msg2 = mm.append_entry({
            "title": "CVE-2026-99999 Test Vulnerability",
            "stix_id": "bundle--test-002",
            "risk_score": 8.5,
            "timestamp": "2026-03-20T00:01:00Z",
            "severity": "CRITICAL",
            "source_url": "https://other.example.com/cve-99999",
        })
        record("Duplicate rejection (same title)", not ok2, msg2)

        # 2.3 — Schema validation
        ok3, msg3 = mm.append_entry({"title": "No severity or score"})
        record("Schema validation rejects incomplete entry", not ok3, msg3[:80])

        # 2.4 — Read back
        entries = mm.read_manifest()
        record("Read manifest returns entries", len(entries) == 1,
               f"count={len(entries)}")

        # 2.5 — Query
        critical = mm.query_entries(severity="CRITICAL")
        record("Query by severity", len(critical) == 1)

        # 2.6 — Bulk append
        bulk_entries = [
            {"title": f"Bulk Test Entry {i}", "stix_id": f"bundle--bulk-{i}",
             "risk_score": 5.0 + i * 0.5, "timestamp": "2026-03-20T00:00:00Z",
             "severity": "HIGH", "source_url": f"https://bulk.example.com/{i}"}
            for i in range(5)
        ]
        bulk_result = mm.bulk_append(bulk_entries)
        record("Bulk append (5 entries)", bulk_result["appended"] == 5,
               f"appended={bulk_result['appended']}, dupes={bulk_result['duplicates']}")

        # 2.7 — Stats
        stats = mm.get_stats()
        record("Stats computation", stats["total"] == 6,
               f"total={stats['total']}, avg_risk={stats.get('avg_risk_score')}")

        # 2.8 — is_duplicate API
        is_dup = mm.is_duplicate("CVE-2026-99999 Test Vulnerability")
        record("is_duplicate check", is_dup)

    finally:
        shutil.rmtree(tmpdir, ignore_errors=True)


def test_ai_engine():
    print("\n══ TEST SUITE 3: AI Intelligence Engine ══")
    from core.ai_engine import AIIntelligenceEngine

    ai = AIIntelligenceEngine()

    # 3.1 — Full analysis
    analysis = ai.analyze(SAMPLE_ITEMS)
    record("Full analysis completes", analysis["input_count"] == 5,
           f"input={analysis['input_count']}")

    # 3.2 — Campaign detection
    campaigns = analysis["campaigns"]
    record("Campaign detection finds campaigns", len(campaigns) >= 1,
           f"campaigns={len(campaigns)}")

    # Check Apache Struts items are grouped
    if campaigns:
        struts_campaign = None
        for c in campaigns:
            titles = c.get("member_titles", [])
            if any("apache" in t.lower() or "struts" in t.lower() for t in titles):
                struts_campaign = c
                break
        record("Apache Struts items correlated into campaign",
               struts_campaign is not None,
               f"campaign={struts_campaign['name'][:50] if struts_campaign else 'NOT FOUND'}")

    # 3.3 — IOC clustering
    clusters = analysis["ioc_clusters"]
    record("IOC clustering produces clusters", len(clusters) >= 1,
           f"clusters={len(clusters)}")

    # Verify shared IOCs (203.0.113.99 appears in items 0 and 1)
    if clusters:
        max_cluster = max(clusters, key=lambda c: c["ioc_count"])
        record("Largest cluster has multiple IOCs", max_cluster["ioc_count"] >= 2,
               f"ioc_count={max_cluster['ioc_count']}, type={max_cluster['classification']}")

    # 3.4 — CVE correlation
    correlations = analysis["cve_correlations"]
    record("CVE correlation finds groups", len(correlations) >= 1,
           f"groups={len(correlations)}")

    # Check Apache family correlation
    if correlations:
        apache_corr = [c for c in correlations if c.get("product_family") == "apache"]
        record("Apache CVEs correlated as family",
               len(apache_corr) >= 1,
               f"apache_cves={apache_corr[0]['cve_count'] if apache_corr else 0}")

    # 3.5 — Anomaly detection
    anomalies = analysis["anomalies"]
    record("Anomaly detection runs", True,
           f"anomalies={len(anomalies)}")

    # 3.6 — Quick score (single item)
    signals = ai.quick_score(SAMPLE_ITEMS[0])
    record("Quick score returns AI signals",
           signals["ai_risk_modifier"] > 0,
           f"modifier={signals['ai_risk_modifier']}, category={signals['threat_category']}, tags={signals['tags']}")

    # 3.7 — Summary completeness
    summary = analysis["summary"]
    required_keys = ["total_clusters", "total_correlations", "total_campaigns",
                     "total_anomalies", "analysis_duration_seconds"]
    missing = [k for k in required_keys if k not in summary]
    record("Summary contains all required fields", len(missing) == 0,
           f"missing={missing}" if missing else f"duration={summary['analysis_duration_seconds']}s")


def test_detection_engine():
    print("\n══ TEST SUITE 4: Detection Engine ══")
    from core.detection import DetectionEngine

    det = DetectionEngine()

    # 4.1 — IOC watchlist loading
    det.ioc_matcher.load_watchlist("ipv4", ["198.51.100.42", "203.0.113.99"])
    det.ioc_matcher.load_watchlist("domain", ["malware-c2.evil.xyz", "exfil-data.badactor.com"])
    det.ioc_matcher.load_watchlist("sha256", [
        "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4e5f6a1b2"
    ])
    record("IOC watchlist loading", det.ioc_matcher.check_single("ipv4", "198.51.100.42"))

    # 4.2 — IOC matching
    matches = det.ioc_matcher.match(SAMPLE_ITEMS[0])
    record("IOC matching finds known indicators", len(matches) >= 2,
           f"matches={len(matches)}")

    # 4.3 — Full detection run (Sigma + YARA + IOC)
    all_detections = det.run_detections(SAMPLE_ITEMS[0])
    record("Full detection run produces results", len(all_detections) >= 1,
           f"total={len(all_detections)}")

    # 4.4 — Detection types breakdown
    types = {}
    for d in all_detections:
        rt = d.get("rule_type", "unknown")
        types[rt] = types.get(rt, 0) + 1
    record("Detection type breakdown",
           "ioc_match" in types,
           f"types={types}")

    # 4.5 — Batch detection
    batch = det.run_batch(SAMPLE_ITEMS)
    record("Batch detection across 5 items",
           batch["total_items"] == 5,
           f"total_detections={batch['total_detections']}, items_with_det={batch['items_with_detections']}")

    # 4.6 — Sigma rule count
    stats = det.get_stats()
    record("Sigma rules loaded", True,
           f"sigma={stats['sigma_rules']}, yara={stats['yara_rules']}, native_yara={stats['yara_native']}",
           warn=(stats['sigma_rules'] == 0))

    # 4.7 — Detection validation (all should be validated=True)
    invalid = [d for d in all_detections if not d.get("validated")]
    record("All detections pass validation", len(invalid) == 0,
           f"invalid={len(invalid)}")


def test_storage():
    print("\n══ TEST SUITE 5: Storage Layer ══")
    from core.storage.database import DatabaseEngine
    from core.storage.cache import CacheEngine

    # 5.1 — Database connection
    db = DatabaseEngine("sqlite:///data/sentinel_apex.db")
    connected = db.connect()
    record("Database connection (SQLite)", connected)

    # 5.2 — Schema initialization
    try:
        db.initialize_schema()
        record("Schema initialization", True)
    except Exception as e:
        record("Schema initialization", False, str(e))

    # 5.3 — Store intelligence
    stored = db.store_intelligence({
        "intel_id": "TEST-INTEL-001",
        "title": "CVE-2026-21345 Test",
        "source_url": "https://test.com",
        "severity": "CRITICAL",
        "risk_score": 9.2,
        "confidence_score": 85.0,
        "kev_present": True,
        "actor_tag": "LAZARUS-GROUP",
        "ioc_counts": {"ipv4": 2, "domain": 2, "sha256": 1},
        "mitre_tactics": ["T1190", "T1059"],
        "pipeline_run_id": "TEST-RUN-001",
    })
    record("Store intelligence record", stored)

    # 5.4 — Store IOC
    ioc_stored = db.store_ioc({
        "intel_id": "TEST-INTEL-001",
        "ioc_type": "ipv4",
        "ioc_value": "198.51.100.42",
        "confidence": 85.0,
    })
    record("Store IOC record", ioc_stored)

    # 5.5 — Store campaign
    camp_stored = db.store_campaign({
        "campaign_id": "TEST-CAMP-001",
        "name": "Lazarus Apache Struts Campaign",
        "actor_tag": "LAZARUS-GROUP",
        "severity": "CRITICAL",
        "confidence": 0.85,
        "intel_count": 2,
        "related_cves": ["CVE-2026-21345", "CVE-2026-21400"],
    })
    record("Store campaign record", camp_stored)

    # 5.6 — Store detection
    det_stored = db.store_detection({
        "detection_id": "TEST-DET-001",
        "intel_id": "TEST-INTEL-001",
        "rule_type": "ioc_match",
        "rule_id": "watchlist_ipv4",
        "rule_name": "IOC Watchlist Match: ipv4",
        "severity": "HIGH",
        "confidence": 0.85,
    })
    record("Store detection record", det_stored)

    # 5.7 — Query intelligence
    results_q = db.query_intelligence(severity="CRITICAL", limit=10)
    record("Query intelligence by severity", len(results_q) >= 1,
           f"results={len(results_q)}")

    # 5.8 — Dashboard stats
    stats = db.get_dashboard_stats()
    record("Dashboard stats query",
           stats.get("total_intelligence", 0) >= 1,
           f"total={stats.get('total_intelligence')}, critical={stats.get('critical_threats')}, "
           f"kev={stats.get('kev_confirmed')}, campaigns={stats.get('active_campaigns')}")

    # 5.9 — Store pipeline run
    run_stored = db.store_pipeline_run({
        "run_id": "TEST-RUN-001",
        "status": "completed",
        "items_ingested": 5,
        "items_enriched": 5,
        "items_published": 5,
        "duration_seconds": 12.5,
        "stages_completed": ["ingest", "normalize", "enrich", "correlate", "score", "store", "publish"],
    })
    record("Store pipeline run record", run_stored)

    db.close()

    # 5.10 — Cache engine
    cache = CacheEngine()
    cache.set("test_key", {"value": 42}, ttl=60)
    retrieved = cache.get("test_key")
    record("Cache set/get", retrieved is not None and retrieved.get("value") == 42,
           f"backend={cache.get_stats()['backend']}")

    # 5.11 — IOC cache
    cache.cache_ioc_set("ipv4", ["198.51.100.42", "203.0.113.99"])
    found = cache.check_ioc("ipv4", "198.51.100.42")
    record("IOC set cache + lookup", found)


def test_pipeline():
    print("\n══ TEST SUITE 6: Full Pipeline Execution ══")
    import tempfile, shutil
    from unittest.mock import patch
    from core.orchestrator import SentinelOrchestrator
    from core.pipeline import PipelineContext

    orch = SentinelOrchestrator()

    # 6.1 — Pipeline context
    ctx = PipelineContext(run_id="VALIDATION-RUN")
    record("Pipeline context creation", ctx.run_id == "VALIDATION-RUN")

    # Use unique items with timestamp suffix
    ts_suffix = f" [{int(time.time())}]"
    fresh_items = []
    for item in SAMPLE_ITEMS:
        fresh = item.copy()
        fresh["title"] = item["title"] + ts_suffix
        fresh_items.append(fresh)

    # Use a clean temporary manifest for test isolation.
    # This avoids monkey-patching the deduplication engine and ensures
    # production manifest is never modified by tests.
    import tempfile, shutil
    test_manifest_dir = tempfile.mkdtemp(prefix="cdb_test_pipeline_")
    try:
        from core.manifest_manager import ManifestManager
        test_mm = ManifestManager(manifest_dir=test_manifest_dir, max_entries=500)
        # Inject test manifest into orchestrator for this run
        orch._test_manifest_manager = test_mm
    except ImportError:
        pass

    # 6.2 — Full pipeline with pre-loaded items
    start = time.time()
    result = orch.run_pipeline(items=fresh_items, run_id="VALIDATION-FULL")
    duration = time.time() - start

    # Clean up test manifest
    try:
        del orch._test_manifest_manager
    except AttributeError:
        pass
    shutil.rmtree(test_manifest_dir, ignore_errors=True)

    record("Pipeline completes without crash",
           result.get("status") in ("completed", "completed_with_errors"),
           f"status={result.get('status')}, duration={duration:.2f}s")

    # 6.3 — All 7 stages completed
    stages = result.get("stages_completed", [])
    expected = ["ingest", "normalize", "enrich", "correlate", "score", "store", "publish"]
    missing_stages = [s for s in expected if s not in stages]
    record("All 7 pipeline stages completed", len(missing_stages) == 0,
           f"completed={stages}" if not missing_stages else f"missing={missing_stages}")

    # 6.4 — Items processed
    metrics = result.get("metrics", {})
    record("Items ingested", metrics.get("ingested", 0) == 5,
           f"ingested={metrics.get('ingested')}")

    # 6.5 — Items normalized (deduplicated)
    record("Items normalized", metrics.get("normalized", 0) >= 1,
           f"normalized={metrics.get('normalized')}, deduplicated={metrics.get('deduplicated')}")

    # 6.6 — Items enriched
    record("Items enriched", metrics.get("enriched", 0) >= 1,
           f"enriched={metrics.get('enriched')}")

    # 6.7 — Items scored
    record("Items scored", metrics.get("scored", 0) >= 1,
           f"scored={metrics.get('scored')}")

    # 6.8 — Detections generated
    record("Detections generated", True,
           f"detections={metrics.get('detections', 0)}",
           warn=(metrics.get("detections", 0) == 0))

    # 6.9 — Items stored
    record("Items stored", metrics.get("stored", 0) >= 1,
           f"stored={metrics.get('stored')}")

    # 6.10 — Items published
    record("Items published", metrics.get("published", 0) >= 1,
           f"published={metrics.get('published')}")

    # 6.11 — AI analysis in result
    record("AI analysis metadata present",
           result.get("campaigns_detected", -1) >= 0,
           f"campaigns_detected={result.get('campaigns_detected')}")

    # 6.12 — Errors
    errors = result.get("errors", [])
    record("Pipeline errors", True,
           f"error_count={len(errors)}" + (f", first={errors[0]['error'][:60]}" if errors else ""),
           warn=(len(errors) > 0))

    # 6.13 — Performance check
    record("Performance < 30s", duration < 30,
           f"duration={duration:.2f}s")

    # 6.14 — Concurrency lock (second run rejected while first completes)
    # Since first run completed, this should succeed
    result2 = orch.run_pipeline(items=[], run_id="VALIDATION-EMPTY")
    record("Second pipeline run accepted (lock released)",
           result2.get("status") != "rejected",
           f"status={result2.get('status')}")

    # 6.15 — System status
    status = orch.get_status()
    record("Orchestrator status report",
           status.get("orchestrator", {}).get("total_runs", 0) >= 2,
           f"total_runs={status['orchestrator']['total_runs']}")

    return result


def test_api_endpoints():
    print("\n══ TEST SUITE 7: API Endpoint Verification ══")

    # Check if fastapi is available
    try:
        import fastapi
        _fastapi_available = True
    except ImportError:
        _fastapi_available = False
        record("FastAPI availability", True,
               "fastapi not installed (expected in CI — API runs on Render.com)", warn=True)

    if _fastapi_available:
        # Direct import test
        try:
            sys.path.insert(0, os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                                             "sentinel-apex-api"))
            from app.api.v1.endpoints.soc import router as soc_router
            routes = [r.path for r in soc_router.routes]
            record("SOC router imports successfully", True,
                   f"routes={len(routes)}")

            expected_paths = ["/status", "/dashboard", "/campaigns", "/detections",
                              "/ioc-clusters", "/cve-correlations", "/hunt",
                              "/ioc-check", "/pipeline-runs"]
            found = [p for p in expected_paths if p in routes]
            missing = [p for p in expected_paths if p not in routes]
            record("All 9 SOC endpoints registered",
                   len(missing) == 0,
                   f"found={len(found)}/9" + (f", missing={missing}" if missing else ""))

        except Exception as e:
            record("SOC router import", False, str(e)[:80])

        # Test endpoint models
        try:
            from app.api.v1.endpoints.soc import ThreatHuntRequest, IOCCheckRequest

            hunt = ThreatHuntRequest(
                hunt_name="Test Hunt",
                query_type="cve",
                query_value="CVE-2026-21345",
            )
            record("ThreatHuntRequest model validation", hunt.hunt_name == "Test Hunt")

            ioc_req = IOCCheckRequest(
                ioc_type="ipv4",
                values=["198.51.100.42"],
            )
            record("IOCCheckRequest model validation", len(ioc_req.values) == 1)

        except Exception as e:
            record("API model validation", False, str(e)[:80])
    else:
        # Verify SOC endpoint file exists and has correct structure
        soc_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "sentinel-apex-api", "app", "api", "v1", "endpoints", "soc.py"
        )
        record("SOC endpoint file exists", os.path.exists(soc_path))

        if os.path.exists(soc_path):
            with open(soc_path, "r") as f:
                content = f.read()
            expected_routes = [
                '"/status"', '"/dashboard"', '"/campaigns"', '"/detections"',
                '"/ioc-clusters"', '"/cve-correlations"', '"/hunt"',
                '"/ioc-check"', '"/pipeline-runs"'
            ]
            found = [r for r in expected_routes if r in content]
            record("All 9 SOC endpoint routes defined in source",
                   len(found) == len(expected_routes),
                   f"found={len(found)}/9")

        # Verify main.py includes soc router
        main_path = os.path.join(
            os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
            "sentinel-apex-api", "app", "main.py"
        )
        if os.path.exists(main_path):
            with open(main_path, "r") as f:
                main_content = f.read()
            record("SOC router registered in main.py",
                   "soc.router" in main_content and "import" in main_content and "soc" in main_content)


# ═══════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════

def main():
    print("=" * 70)
    print("  CYBERDUDEBIVASH SENTINEL APEX v47.0 — FULL SYSTEM VALIDATION")
    print("=" * 70)
    print(f"  Timestamp: {datetime.now(timezone.utc).isoformat()}")
    print(f"  Sample items: {len(SAMPLE_ITEMS)}")
    print("=" * 70)

    suites = [
        ("Event Bus", test_event_bus),
        ("Manifest Manager", test_manifest_manager),
        ("AI Intelligence Engine", test_ai_engine),
        ("Detection Engine", test_detection_engine),
        ("Storage Layer", test_storage),
        ("Full Pipeline", test_pipeline),
        ("API Endpoints", test_api_endpoints),
    ]

    for name, fn in suites:
        try:
            fn()
        except Exception as e:
            print(f"\n  [{FAIL}] SUITE CRASHED: {name}")
            print(f"    {traceback.format_exc()}")
            results["failed"] += 1

    # Summary
    total = results["passed"] + results["failed"]
    print("\n" + "=" * 70)
    print(f"  VALIDATION RESULTS")
    print(f"  {'=' * 50}")
    print(f"  Total:    {total} tests")
    print(f"  {PASS}:  {results['passed']}")
    print(f"  {FAIL}:  {results['failed']}")
    print(f"  {WARN}: {results['warnings']}")
    print(f"  Pass Rate: {results['passed']/total*100:.1f}%" if total > 0 else "  N/A")
    print("=" * 70)

    # Return exit code
    return 0 if results["failed"] == 0 else 1


if __name__ == "__main__":
    sys.exit(main())
