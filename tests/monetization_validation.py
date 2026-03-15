#!/usr/bin/env python3
"""
monetization_validation.py — CYBERDUDEBIVASH® SENTINEL APEX v55.0
COMPREHENSIVE VALIDATION SUITE

Validates:
  1. Quota Manager: Tiered enforcement, Pulse Wave, Priority-10
  2. Executive Risk Engine: ALE/ROSI, regulatory fine mapping
  3. B2B Streaming: HMAC signing/verification, subscription CRUD
  4. Sales Conversion: Finding→Advisory→Dispatch pipeline
  5. Database Migrations: Schema creation and integrity
  6. Zero-Regression: Existing modules remain functional

Usage:
    python -m tests.monetization_validation                # Run all
    python -m pytest tests/monetization_validation.py -v   # Via pytest

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import sys
import json
import time
import asyncio
import unittest
import tempfile
import shutil
from datetime import datetime, timezone
from pathlib import Path

# Ensure project root is on path
ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT))

# Create required data directories for testing
for d in ["data/quota", "data/executive_risk", "data/b2b_streaming",
           "data/b2b_streaming/dead_letter_queue", "data/sales_conversion",
           "data/sales_conversion/advisories", "data/revenue", "data/intelligence"]:
    Path(d).mkdir(parents=True, exist_ok=True)


# ═══════════════════════════════════════════════════════════
# TEST 1: QUOTA MANAGER
# ═══════════════════════════════════════════════════════════

class TestQuotaManager(unittest.TestCase):
    """Validate multi-tiered quota enforcement."""

    def setUp(self):
        from agent.monetization.quota_manager import QuotaEngine
        self.engine = QuotaEngine()

    def test_01_free_tier_limits(self):
        """FREE tier should have 5,000 monthly API calls."""
        config = self.engine.get_quota_config("FREE")
        self.assertEqual(config["api_calls_monthly"], 5_000)
        self.assertEqual(config["delivery_mode"], "PULSE_WAVE")
        self.assertEqual(config["priority_level"], 1)
        self.assertFalse(config["shard_dedicated"])

    def test_02_pro_tier_limits(self):
        """PRO tier should have 100,000 monthly API calls, REALTIME delivery."""
        config = self.engine.get_quota_config("PRO")
        self.assertEqual(config["api_calls_monthly"], 100_000)
        self.assertEqual(config["delivery_mode"], "REALTIME")
        self.assertEqual(config["priority_level"], 5)

    def test_03_enterprise_priority_10(self):
        """ENTERPRISE tier should have Priority-10 with dedicated shard."""
        config = self.engine.get_quota_config("ENTERPRISE")
        self.assertEqual(config["api_calls_monthly"], 1_000_000)
        self.assertEqual(config["delivery_mode"], "PRIORITY_10")
        self.assertEqual(config["priority_level"], 10)
        self.assertTrue(config["shard_dedicated"])

    def test_04_consume_allowed(self):
        """Consuming within limits should be allowed."""
        result = self.engine.consume(
            org_id="test_org_001",
            metric="api_calls",
            cost=1,
            tier="PRO",
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["tier"], "PRO")
        self.assertEqual(result["delivery_mode"], "REALTIME")

    def test_05_enterprise_shard_key(self):
        """Enterprise consumers should receive a dedicated shard key."""
        result = self.engine.consume(
            org_id="ent_org_001",
            metric="api_calls",
            cost=1,
            tier="ENTERPRISE",
        )
        self.assertTrue(result["allowed"])
        self.assertEqual(result["delivery_mode"], "PRIORITY_10")
        self.assertTrue(result.get("shard_dedicated", False))
        self.assertIn("shard_key", result)

    def test_06_pulse_wave_enqueue(self):
        """Free tier Pulse Wave should buffer requests."""
        result = self.engine.enqueue_pulse_wave("free_org_001", {"test": True})
        self.assertEqual(result["status"], "QUEUED")
        self.assertEqual(result["delivery_mode"], "PULSE_WAVE")
        self.assertIn("next_wave_sec", result)

    def test_07_usage_snapshot(self):
        """Usage snapshot should return structured data."""
        # Consume a few units first
        self.engine.consume("snap_org", "api_calls", 5, tier="PRO")
        snapshot = self.engine.get_usage_snapshot("snap_org", tier="PRO")
        self.assertEqual(snapshot["tier"], "PRO")
        self.assertIn("monthly", snapshot)
        self.assertIn("hourly", snapshot)

    def test_08_admin_reset(self):
        """Admin reset should clear quota counters."""
        self.engine.consume("reset_org", "api_calls", 100, tier="FREE")
        self.engine.admin_reset("reset_org")
        snapshot = self.engine.get_usage_snapshot("reset_org", tier="FREE")
        # After reset, monthly usage should be 0
        self.assertEqual(snapshot["monthly"]["used"], 0)


# ═══════════════════════════════════════════════════════════
# TEST 2: EXECUTIVE RISK ENGINE
# ═══════════════════════════════════════════════════════════

class TestExecutiveRiskEngine(unittest.TestCase):
    """Validate financial risk quantification."""

    def setUp(self):
        from agent.analytics.executive_risk_engine import ExecutiveRiskEngine
        self.engine = ExecutiveRiskEngine()

    def test_01_basic_quantification(self):
        """Single CRITICAL CVE should produce non-zero ALE."""
        findings = [{
            "type": "CVE_CRITICAL",
            "severity": "CRITICAL",
            "title": "Remote Code Execution in Apache Log4j",
            "cvss_score": 10.0,
            "epss_score": 0.97,
        }]
        report = self.engine.quantify(findings, region="EU", sector="FINANCE")

        summary = report["executive_summary"]
        self.assertGreater(summary["annualized_loss_exposure_usd"], 0)
        self.assertGreater(summary["rosi_percentage"], 0)
        self.assertIn(summary["risk_rating"], ("CRITICAL", "HIGH"))
        self.assertEqual(len(report["finding_details"]), 1)

    def test_02_gdpr_fine_mapping(self):
        """EU region should include GDPR regulatory fine."""
        findings = [{
            "type": "BOLA",
            "severity": "CRITICAL",
            "title": "Broken Object Level Authorization",
        }]
        report = self.engine.quantify(findings, region="EU", sector="HEALTHCARE")

        reg = report.get("regulatory_exposure", {})
        self.assertIn("GDPR", reg)
        self.assertGreater(reg["GDPR"]["projected_fine_usd"], 0)

    def test_03_dpdp_fine_mapping(self):
        """India region should include DPDP regulatory fine."""
        findings = [{
            "type": "CLOUD_BUCKET_EXPOSURE",
            "severity": "CRITICAL",
            "title": "Public S3 bucket with PII data",
        }]
        report = self.engine.quantify(findings, region="IN", sector="FINANCE")

        reg = report.get("regulatory_exposure", {})
        self.assertIn("INDIA_DPDP", reg)
        self.assertGreater(reg["INDIA_DPDP"]["projected_fine_usd"], 0)

    def test_04_eu_ai_act_mapping(self):
        """AI-related finding in EU should trigger EU AI Act fine."""
        findings = [{
            "type": "AI_MODEL_POISONING",
            "severity": "CRITICAL",
            "title": "Adversarial ML Attack on Classification Model",
        }]
        report = self.engine.quantify(findings, region="EU", sector="TECHNOLOGY")

        reg = report.get("regulatory_exposure", {})
        self.assertIn("EU_AI_ACT", reg)

    def test_05_sector_multiplier(self):
        """HEALTHCARE sector should amplify risk vs DEFAULT."""
        findings = [{"type": "CVE_HIGH", "severity": "HIGH", "title": "SQL Injection"}]

        report_default = self.engine.quantify(findings, sector="DEFAULT")
        report_health = self.engine.quantify(findings, sector="HEALTHCARE")

        ale_default = report_default["executive_summary"]["annualized_loss_exposure_usd"]
        ale_health = report_health["executive_summary"]["annualized_loss_exposure_usd"]
        self.assertGreater(ale_health, ale_default)

    def test_06_cost_of_inaction(self):
        """3-year inaction cost should exceed single-year ALE."""
        findings = [{"type": "CVE_CRITICAL", "severity": "CRITICAL", "title": "RCE"}]
        report = self.engine.quantify(findings)

        summary = report["executive_summary"]
        self.assertGreater(
            summary["cost_of_inaction_3yr_usd"],
            summary["annualized_loss_exposure_usd"]
        )

    def test_07_empty_findings(self):
        """Empty findings list should return zero-value report."""
        report = self.engine.quantify([])
        self.assertEqual(report["executive_summary"]["annualized_loss_exposure_usd"], 0)
        self.assertEqual(report["executive_summary"]["risk_rating"], "INFORMATIONAL")

    def test_08_recommendations_generated(self):
        """CRITICAL findings should produce P0 recommendations."""
        findings = [{"type": "CVE_CRITICAL", "severity": "CRITICAL", "title": "Zero-Day"}]
        report = self.engine.quantify(findings, region="EU")

        recs = report.get("recommendations", [])
        self.assertTrue(len(recs) > 0)
        self.assertEqual(recs[0]["priority"], "P0")


# ═══════════════════════════════════════════════════════════
# TEST 3: B2B STREAMING API
# ═══════════════════════════════════════════════════════════

class TestB2BStreamingAPI(unittest.TestCase):
    """Validate B2B webhook subscription and HMAC signing."""

    def setUp(self):
        from agent.intel.b2b_streaming_api import B2BStreamingEngine, HMACSigner, ThreatPulse
        self.engine = B2BStreamingEngine()
        self.signer = HMACSigner()
        self.ThreatPulse = ThreatPulse

    def test_01_create_subscription(self):
        """Create STANDARD subscription successfully."""
        result = self.engine.create_subscription(
            org_id="test_b2b_org",
            webhook_url="https://soc.example.com/webhook",
            tier="STANDARD",
            event_filters=["THREAT_INTEL", "CVE_ALERT"],
        )
        self.assertIn("subscription_id", result)
        self.assertIn("hmac_secret", result)
        self.assertEqual(result["tier"], "STANDARD")
        self.assertFalse(result["mtls_required"])

    def test_02_create_enterprise_subscription(self):
        """Enterprise subscription should require mTLS."""
        result = self.engine.create_subscription(
            org_id="ent_b2b_org",
            webhook_url="https://enterprise-soc.example.com/webhook",
            tier="ENTERPRISE",
        )
        self.assertIn("subscription_id", result)
        self.assertTrue(result["mtls_required"])

    def test_03_reject_http_url(self):
        """Non-HTTPS webhook URL should be rejected."""
        result = self.engine.create_subscription(
            org_id="insecure_org",
            webhook_url="http://insecure.example.com/webhook",
        )
        self.assertIn("error", result)
        self.assertEqual(result["code"], "INSECURE_URL")

    def test_04_hmac_sign_verify(self):
        """HMAC signature should be verifiable."""
        secret = "test_hmac_secret_12345"
        payload = b'{"test": true, "event": "CVE_ALERT"}'

        signature, ts = self.signer.sign(payload, secret)
        self.assertTrue(signature.startswith("t="))
        self.assertIn("v1=", signature)

        # Verify
        is_valid, error = self.signer.verify(payload, signature, secret)
        self.assertTrue(is_valid)
        self.assertIsNone(error)

    def test_05_hmac_reject_tampered(self):
        """Tampered payload should fail verification."""
        secret = "test_secret"
        payload = b'{"original": true}'
        signature, _ = self.signer.sign(payload, secret)

        tampered = b'{"original": false}'
        is_valid, error = self.signer.verify(tampered, signature, secret)
        self.assertFalse(is_valid)
        self.assertEqual(error, "Signature mismatch")

    def test_06_hmac_reject_expired(self):
        """Expired timestamp should fail verification."""
        secret = "test_secret"
        payload = b'{"data": 1}'
        # Sign with old timestamp
        old_ts = int(time.time()) - 600  # 10 minutes ago
        signature, _ = self.signer.sign(payload, secret, timestamp=old_ts)

        is_valid, error = self.signer.verify(payload, signature, secret, tolerance_sec=300)
        self.assertFalse(is_valid)
        self.assertIn("Timestamp expired", error)

    def test_07_list_subscriptions(self):
        """Should list all subscriptions."""
        # Create a subscription first
        self.engine.create_subscription(
            org_id="list_test_org",
            webhook_url="https://list.example.com/hook",
        )
        subs = self.engine.list_subscriptions(org_id="list_test_org")
        self.assertTrue(len(subs) > 0)
        self.assertEqual(subs[0]["org_id"], "list_test_org")

    def test_08_revoke_subscription(self):
        """Revoked subscription should have REVOKED status."""
        result = self.engine.create_subscription(
            org_id="revoke_org",
            webhook_url="https://revoke.example.com/hook",
        )
        sub_id = result["subscription_id"]

        revoke_result = self.engine.revoke_subscription(sub_id)
        self.assertEqual(revoke_result["status"], "REVOKED")

    def test_09_create_pulse_from_finding(self):
        """Should convert a finding dict to ThreatPulse."""
        finding = {
            "type": "CVE_CRITICAL",
            "severity": "CRITICAL",
            "title": "Log4Shell RCE",
            "confidence_score": 0.99,
            "iocs": [{"type": "ip", "value": "192.168.1.100"}],
            "mitre_tactics": ["TA0001", "TA0002"],
        }
        pulse = self.engine.create_pulse_from_finding(finding)
        self.assertIsNotNone(pulse.pulse_id)
        self.assertEqual(pulse.severity, "CRITICAL")
        self.assertEqual(pulse.confidence, 0.99)
        self.assertEqual(len(pulse.indicators), 1)

    def test_10_engine_health(self):
        """Health endpoint should return operational metrics."""
        health = self.engine.get_health()
        self.assertEqual(health["engine"], "CDB-B2B-Streaming-v55")
        self.assertIn("total_subscriptions", health)
        self.assertIn("active", health)


# ═══════════════════════════════════════════════════════════
# TEST 4: SALES CONVERSION PIPELINE
# ═══════════════════════════════════════════════════════════

class TestSalesConversionPipeline(unittest.TestCase):
    """Validate autonomous lead conversion pipeline."""

    def setUp(self):
        from agent.automation.sales_conversion_hook import ConversionPipeline, ClientContext
        self.pipeline = ConversionPipeline()
        self.ClientContext = ClientContext

    def test_01_critical_finding_triggers_pipeline(self):
        """CRITICAL finding should reach RISK_QUANTIFIED stage minimum."""
        finding = {
            "type": "CVE_CRITICAL",
            "severity": "CRITICAL",
            "title": "Remote Code Execution",
            "org_id": "client_001",
            "org_name": "Acme Corp",
            "region": "EU",
            "sector": "FINANCE",
        }
        result = self.pipeline.process_finding(finding, auto_dispatch=False)

        self.assertIn(result["stage"], [
            "RISK_QUANTIFIED", "ADVISORY_GENERATED", "LEAD_CREATED"
        ])
        self.assertEqual(result["severity"], "CRITICAL")

    def test_02_medium_finding_skipped(self):
        """MEDIUM severity should not trigger auto-conversion."""
        finding = {
            "type": "CVE_MEDIUM",
            "severity": "MEDIUM",
            "title": "XSS in Search",
        }
        result = self.pipeline.process_finding(finding, auto_dispatch=False)
        self.assertEqual(result["stage"], "INGESTED")

    def test_03_client_context(self):
        """ClientContext should properly populate."""
        client = self.ClientContext(
            org_id="org_test",
            org_name="Test Corp",
            contact_email="security@test.com",
            region="IN",
            sector="HEALTHCARE",
        )
        self.assertEqual(client.region, "IN")
        self.assertEqual(client.sector, "HEALTHCARE")

    def test_04_advisory_generation(self):
        """CRITICAL finding with client context should generate advisory."""
        from agent.automation.sales_conversion_hook import AdvisoryPDFGenerator

        gen = AdvisoryPDFGenerator()
        risk_report = {
            "report_id": "CDB-TEST-001",
            "executive_summary": {
                "total_risk_exposure_usd": 2_500_000,
                "annualized_loss_exposure_usd": 1_200_000,
                "max_regulatory_fine_usd": 5_000_000,
                "mitigated_value_usd": 1_140_000,
                "rosi_percentage": 2180,
                "cost_of_inaction_3yr_usd": 4_200_000,
                "risk_rating": "CRITICAL",
            },
            "regulatory_exposure": {
                "GDPR": {"projected_fine_usd": 5_000_000, "framework": "GDPR"},
            },
            "recommendations": [
                {"priority": "P0", "action": "Patch immediately", "impact": "$1.2M risk reduction"},
            ],
        }
        client = self.ClientContext(org_name="Test Corp", region="EU", sector="FINANCE")
        findings = [{"severity": "CRITICAL", "type": "CVE_CRITICAL", "title": "RCE"}]

        path = gen.generate(risk_report, client, findings)
        self.assertIsNotNone(path)
        self.assertTrue(os.path.exists(path))

    def test_05_metrics_tracking(self):
        """Pipeline metrics should increment."""
        metrics = self.pipeline.get_metrics()
        self.assertIn("total_findings_processed", metrics)
        self.assertIn("conversion_rate", metrics)

    def test_06_batch_processing(self):
        """Batch processing should handle multiple findings."""
        findings = [
            {"type": "CVE_CRITICAL", "severity": "CRITICAL", "title": "RCE #1"},
            {"type": "BOLA", "severity": "HIGH", "title": "IDOR #1"},
            {"type": "CVE_LOW", "severity": "LOW", "title": "Info Leak"},
        ]
        client = self.ClientContext(org_name="Batch Corp", region="GLOBAL")
        result = self.pipeline.process_batch(findings, client, auto_dispatch=False)

        self.assertEqual(result["findings_total"], 3)
        self.assertEqual(result["findings_actionable"], 2)
        self.assertGreater(result["ale_usd"], 0)


# ═══════════════════════════════════════════════════════════
# TEST 5: DATABASE MIGRATIONS
# ═══════════════════════════════════════════════════════════

class TestDatabaseMigrations(unittest.TestCase):
    """Validate schema creation and migration integrity."""

    def test_01_migrations_apply(self):
        """All migrations should apply without errors."""
        from database.migrations import MigrationRunner
        runner = MigrationRunner()
        result = runner.migrate()

        self.assertEqual(len(result["errors"]), 0,
                         f"Migration errors: {result['errors']}")
        self.assertTrue(len(result["applied"]) > 0 or len(result["skipped"]) > 0)

    def test_02_migration_status(self):
        """Status should report all applied migrations."""
        from database.migrations import MigrationRunner
        runner = MigrationRunner()
        runner.migrate()  # Ensure applied
        status = runner.status()
        self.assertTrue(len(status["applied"]) > 0)

    def test_03_idempotent(self):
        """Running migrations twice should be safe."""
        from database.migrations import MigrationRunner
        runner = MigrationRunner()
        result1 = runner.migrate()
        result2 = runner.migrate()
        self.assertEqual(len(result2["errors"]), 0)


# ═══════════════════════════════════════════════════════════
# TEST 6: ZERO-REGRESSION — Existing Modules
# ═══════════════════════════════════════════════════════════

class TestZeroRegression(unittest.TestCase):
    """Verify existing platform modules remain functional."""

    def test_01_rate_limiter_intact(self):
        """Existing rate_limiter.py must still work."""
        from agent.api.rate_limiter import rate_limiter
        allowed, info = rate_limiter.check("test:regression", tier="FREE")
        self.assertTrue(allowed)
        self.assertIn("tier", info)
        self.assertIn("remaining", info)

    def test_02_auth_handler_intact(self):
        """Existing auth.py must still resolve tiers."""
        from agent.api.auth import auth_handler, TIER_FREE
        tier, identity, err = auth_handler.resolve_tier(remote_ip="127.0.0.1")
        self.assertEqual(tier, TIER_FREE)
        self.assertIsNone(err)

    def test_03_risk_engine_intact(self):
        """Existing risk_engine.py must still calculate scores."""
        from agent.risk_engine import RiskScoringEngine
        engine = RiskScoringEngine()
        self.assertIsNotNone(engine)
        self.assertIn("zero-day", engine.SEVERITY_SIGNALS)

    def test_04_revenue_engine_intact(self):
        """Existing revenue_engine.py must still initialize."""
        from agent.revenue_engine import CDBRevenueEngine
        engine = CDBRevenueEngine()
        self.assertIsNotNone(engine)
        self.assertEqual(engine.authority, "CYBERDUDEBIVASH OFFICIAL AUTHORITY")

    def test_05_apex_streamer_intact(self):
        """Existing cdb_apex_streamer.py must still initialize."""
        from agent.sdk.cdb_apex_streamer import ApexDataStreamer
        streamer = ApexDataStreamer()
        self.assertFalse(streamer.is_running)
        self.assertEqual(len(streamer.active_clients), 0)

    def test_06_lead_autoresponder_intact(self):
        """Existing lead_autoresponder.py must still import."""
        from agent.lead_autoresponder import ENTERPRISE_URL, STORE_URL
        self.assertEqual(ENTERPRISE_URL, "https://intel.cyberdudebivash.com/pricing")
        self.assertEqual(STORE_URL, "https://cyberdudebivash.gumroad.com")

    def test_07_subscription_manager_intact(self):
        """Existing v53 subscription manager must still work."""
        from agent.v53_subscription.manager import SubscriptionManager, TIER_CONFIG, Tier
        mgr = SubscriptionManager()
        pricing = mgr.get_pricing()
        self.assertIn("tiers", pricing)
        self.assertEqual(TIER_CONFIG[Tier.PRO]["price_monthly_usd"], 149)

    def test_08_bughunter_roi_intact(self):
        """Existing v45 ROI engine must still calculate."""
        from agent.v45_bughunter.roi_engine import ROIEngine
        engine = ROIEngine()
        findings = [{"type": "BOLA", "severity": "CRITICAL"}]
        result = engine.calculate_exposure(findings)
        self.assertGreater(result["total_risk_exposure"], 0)
        self.assertGreater(result["rosi_percentage"], 0)

    def test_09_config_imports(self):
        """Global config must still export all constants."""
        from agent.config import (
            RSS_FEEDS, BLOG_ID, STATE_FILE,
            API_RATE_LIMIT_PUBLIC, API_RATE_LIMIT_ENTERPRISE,
        )
        self.assertTrue(len(RSS_FEEDS) > 10)
        self.assertIsNotNone(BLOG_ID)

    def test_10_new_modules_dont_break_imports(self):
        """All new v55 modules must import without side effects."""
        from agent.monetization.quota_manager import quota_engine
        from agent.analytics.executive_risk_engine import executive_risk_engine
        from agent.intel.b2b_streaming_api import b2b_streaming_engine
        from agent.automation.sales_conversion_hook import conversion_pipeline

        self.assertIsNotNone(quota_engine)
        self.assertIsNotNone(executive_risk_engine)
        self.assertIsNotNone(b2b_streaming_engine)
        self.assertIsNotNone(conversion_pipeline)


# ═══════════════════════════════════════════════════════════
# RUNNER
# ═══════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Set working directory to project root
    os.chdir(str(ROOT))

    print("=" * 70)
    print("CYBERDUDEBIVASH SENTINEL APEX v55.0 — MONETIZATION VALIDATION")
    print("=" * 70)
    print()

    loader = unittest.TestLoader()
    suite = unittest.TestSuite()

    # Add all test classes
    suite.addTests(loader.loadTestsFromTestCase(TestQuotaManager))
    suite.addTests(loader.loadTestsFromTestCase(TestExecutiveRiskEngine))
    suite.addTests(loader.loadTestsFromTestCase(TestB2BStreamingAPI))
    suite.addTests(loader.loadTestsFromTestCase(TestSalesConversionPipeline))
    suite.addTests(loader.loadTestsFromTestCase(TestDatabaseMigrations))
    suite.addTests(loader.loadTestsFromTestCase(TestZeroRegression))

    runner = unittest.TextTestRunner(verbosity=2)
    result = runner.run(suite)

    print()
    print("=" * 70)
    if result.wasSuccessful():
        print("RESULT: ALL TESTS PASSED — 0 FAILURES — 0 REGRESSIONS")
        print("SENTINEL APEX v55.0 MONETIZATION STACK: VALIDATED")
    else:
        print(f"RESULT: {len(result.failures)} FAILURES, {len(result.errors)} ERRORS")
        for failure in result.failures:
            print(f"  FAIL: {failure[0]}")
        for error in result.errors:
            print(f"  ERROR: {error[0]}")
    print("=" * 70)

    sys.exit(0 if result.wasSuccessful() else 1)
