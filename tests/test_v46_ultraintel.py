#!/usr/bin/env python3
"""
test_v46_ultraintel.py — SENTINEL APEX v46.0 ULTRA INTEL Test Suite
60 comprehensive tests covering all 6 v46 enrichment engines.
Zero-regression validation included.

© 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
import json
import os
import sys
import pytest

sys.path.insert(0, os.path.join(os.path.dirname(__file__), ".."))

from agent.v46_ultraintel.actor_attribution import ActorAttributionEngineV46
from agent.v46_ultraintel.sector_tagger import SectorTaggerV46
from agent.v46_ultraintel.exploit_status_classifier import ExploitStatusClassifierV46
from agent.v46_ultraintel.cwe_classifier import CWEClassifierV46
from agent.v46_ultraintel.extended_metrics_builder import ExtendedMetricsBuilderV46
from agent.v46_ultraintel.intel_quality_scorer import IntelQualityScorerV46


# ── FIXTURES ──────────────────────────────────────────────────────────────────
@pytest.fixture
def actor_engine():
    return ActorAttributionEngineV46()

@pytest.fixture
def sector_engine():
    return SectorTaggerV46()

@pytest.fixture
def exploit_engine():
    return ExploitStatusClassifierV46()

@pytest.fixture
def cwe_engine():
    return CWEClassifierV46()

@pytest.fixture
def em_engine():
    return ExtendedMetricsBuilderV46()

@pytest.fixture
def iqs_engine():
    return IntelQualityScorerV46()

@pytest.fixture
def sample_cve_item():
    return {
        "title": "CVE-2026-1731 fuels ongoing attacks on BeyondTrust remote access products",
        "stix_id": "bundle--test-001",
        "risk_score": 10.0,
        "severity": "CRITICAL",
        "confidence_score": 53.0,
        "tlp_label": "TLP:RED",
        "ioc_counts": {"ipv4": 0, "domain": 1, "url": 0, "sha256": 0,
                       "sha1": 0, "md5": 0, "email": 0, "cve": 1,
                       "registry": 0, "artifacts": 0},
        "actor_tag": "UNC-CDB-99",
        "mitre_tactics": ["T1595", "T1190", "T1078", "T1203", "T1059.001"],
        "feed_source": "https://securityaffairs.com/feed",
        "cvss_score": None,
        "epss_score": None,
        "kev_present": False,
        "status": "active",
        "extended_metrics": {},
    }

@pytest.fixture
def sample_ransomware_item():
    return {
        "title": "LockBit ransomware exploits healthcare systems via RCE vulnerability",
        "stix_id": "bundle--test-002",
        "risk_score": 9.5,
        "severity": "CRITICAL",
        "confidence_score": 75.0,
        "tlp_label": "TLP:RED",
        "ioc_counts": {"ipv4": 2, "domain": 3, "url": 1, "sha256": 2,
                       "sha1": 0, "md5": 1, "email": 0, "cve": 2,
                       "registry": 1, "artifacts": 1},
        "actor_tag": "UNC-CDB-99",
        "mitre_tactics": ["T1486", "T1083", "T1021", "T1059", "T1105"],
        "feed_source": "https://securityaffairs.com/feed",
        "cvss_score": 9.8,
        "epss_score": 45.0,
        "kev_present": False,
        "status": "active",
        "extended_metrics": {},
    }

@pytest.fixture
def sample_iot_item():
    return {
        "title": "CVE-2026-3016 - UTT HiPER 810G formP2PLimitConfig strcpy buffer overflow",
        "stix_id": "bundle--test-003",
        "risk_score": 4.5,
        "severity": "MEDIUM",
        "confidence_score": 8.0,
        "tlp_label": "TLP:GREEN",
        "ioc_counts": {"ipv4": 0, "domain": 0, "url": 0, "sha256": 0,
                       "sha1": 0, "md5": 0, "email": 0, "cve": 1,
                       "registry": 0, "artifacts": 0},
        "actor_tag": "UNC-CDB-99",
        "mitre_tactics": ["T1203", "T1059"],
        "feed_source": "https://cvefeed.io/rssfeed/lat",
        "cvss_score": None,
        "epss_score": None,
        "kev_present": False,
        "status": "active",
        "extended_metrics": {},
    }

@pytest.fixture
def enriched_item(sample_cve_item, actor_engine, sector_engine, exploit_engine,
                  cwe_engine, em_engine, iqs_engine):
    """Fully enriched item through all engines."""
    item = dict(sample_cve_item)
    item = actor_engine.enrich_item(item)
    item = sector_engine.enrich_item(item)
    item = exploit_engine.enrich_item(item)
    item = cwe_engine.enrich_item(item)
    item = em_engine.enrich_item(item)
    item = iqs_engine.enrich_item(item)
    return item


# ── ACTOR ATTRIBUTION TESTS (10 tests) ────────────────────────────────────────
class TestActorAttributionV46:
    def test_lockbit_attribution(self, actor_engine):
        item = {"title": "LockBit ransomware hits healthcare provider",
                "actor_tag": "UNC-CDB-99", "mitre_tactics": []}
        result = actor_engine.enrich_item(item)
        assert result["actor_tag"] == "CDB-RAN-01"
        assert "LockBit" in result["actor_profile"]["name"]

    def test_apt28_attribution(self, actor_engine):
        item = {"title": "Fancy Bear APT28 targets NATO allies with spearphishing",
                "actor_tag": "UNC-CDB-99", "mitre_tactics": []}
        result = actor_engine.enrich_item(item)
        assert result["actor_tag"] == "CDB-APT-28"
        assert result["actor_profile"]["origin"] == "Russia"

    def test_volt_typhoon_attribution(self, actor_engine):
        item = {"title": "Volt Typhoon compromises critical infrastructure using LOTL",
                "actor_tag": "UNC-CDB-99", "mitre_tactics": []}
        result = actor_engine.enrich_item(item)
        assert result["actor_tag"] == "CDB-APT-22"

    def test_lazarus_attribution(self, actor_engine):
        item = {"title": "Lazarus Group targets cryptocurrency exchanges via TraderTraitor",
                "actor_tag": "UNC-CDB-99", "mitre_tactics": []}
        result = actor_engine.enrich_item(item)
        assert result["actor_tag"] == "CDB-FIN-09"
        assert result["actor_profile"]["origin"] == "North Korea"

    def test_iot_vendor_heuristic(self, actor_engine):
        item = {"title": "CVE-2026-3016 - UTT HiPER 810G buffer overflow",
                "actor_tag": "UNC-CDB-99", "mitre_tactics": []}
        result = actor_engine.enrich_item(item)
        assert result["actor_profile"]["tracking_id"] in ("CDB-WEB-02", "UNC-CDB-99")

    def test_actor_profile_fields_present(self, actor_engine, sample_ransomware_item):
        result = actor_engine.enrich_item(sample_ransomware_item)
        profile = result["actor_profile"]
        for field in ["tracking_id", "name", "origin", "motivation",
                      "sophistication", "attribution_confidence"]:
            assert field in profile, f"Missing field: {field}"

    def test_existing_real_actor_preserved(self, actor_engine):
        item = {"title": "Some threat", "actor_tag": "CDB-APT-28",
                "mitre_tactics": []}
        result = actor_engine.enrich_item(item)
        assert result["actor_tag"] == "CDB-APT-28"

    def test_unknown_defaults_correctly(self, actor_engine):
        item = {"title": "Some generic advisory with no known signals",
                "actor_tag": "UNC-CDB-99", "mitre_tactics": []}
        result = actor_engine.enrich_item(item)
        assert result["actor_profile"]["tracking_id"] in ("UNC-CDB-99", "CDB-WEB-01",
                                                            "CDB-WEB-02", "CDB-MAL-01")

    def test_batch_enrich_preserves_length(self, actor_engine):
        items = [{"title": f"Item {i}", "actor_tag": "UNC-CDB-99",
                  "mitre_tactics": []} for i in range(10)]
        result = actor_engine.batch_enrich(items)
        assert len(result) == 10

    def test_xmrig_cryptomining(self, actor_engine):
        item = {"title": "Wormable XMRig campaign leverages BYOVD",
                "actor_tag": "UNC-CDB-99", "mitre_tactics": []}
        result = actor_engine.enrich_item(item)
        assert result["actor_tag"] == "CDB-MAL-01"


# ── SECTOR TAGGER TESTS (10 tests) ────────────────────────────────────────────
class TestSectorTaggerV46:
    def test_healthcare_detection(self, sector_engine):
        item = {"title": "LockBit ransomware hits hospital systems",
                "mitre_tactics": [], "extended_metrics": {}}
        result = sector_engine.enrich_item(item)
        sectors = [s["sector"] for s in result["sector_tags"]]
        assert "Healthcare" in sectors

    def test_iot_detection(self, sector_engine):
        item = {"title": "CVE-2026-3016 - UTT HiPER 810G router buffer overflow",
                "mitre_tactics": [], "extended_metrics": {}}
        result = sector_engine.enrich_item(item)
        sectors = [s["sector"] for s in result["sector_tags"]]
        assert "IoT / Embedded" in sectors

    def test_finance_detection(self, sector_engine):
        item = {"title": "Banking trojan targets financial institutions via phishing",
                "mitre_tactics": [], "extended_metrics": {}}
        result = sector_engine.enrich_item(item)
        sectors = [s["sector"] for s in result["sector_tags"]]
        assert "Finance" in sectors

    def test_sector_tags_max_5(self, sector_engine):
        item = {"title": "Cloud banking government defense critical infrastructure hospital",
                "mitre_tactics": [], "extended_metrics": {}}
        result = sector_engine.enrich_item(item)
        assert len(result["sector_tags"]) <= 5

    def test_sector_has_icon(self, sector_engine, sample_cve_item):
        result = sector_engine.enrich_item(sample_cve_item)
        for tag in result["sector_tags"]:
            assert "icon" in tag
            assert "sector" in tag
            assert "priority" in tag
            assert "confidence" in tag

    def test_open_source_detection(self, sector_engine):
        item = {"title": "ImageMagick heap buffer overflow in YUV decoder",
                "mitre_tactics": [], "extended_metrics": {}}
        result = sector_engine.enrich_item(item)
        sectors = [s["sector"] for s in result["sector_tags"]]
        assert "Open Source Software" in sectors

    def test_fallback_no_crash(self, sector_engine):
        item = {"title": "", "mitre_tactics": [], "extended_metrics": {}}
        result = sector_engine.enrich_item(item)
        assert "sector_tags" in result
        assert len(result["sector_tags"]) >= 1

    def test_government_detection(self, sector_engine):
        item = {"title": "APT28 targets NATO government ministries",
                "mitre_tactics": [], "extended_metrics": {}}
        result = sector_engine.enrich_item(item)
        sectors = [s["sector"] for s in result["sector_tags"]]
        assert "Government" in sectors

    def test_batch_all_have_sector_tags(self, sector_engine):
        items = [{"title": f"CVE-2026-{i} advisory", "mitre_tactics": [],
                  "extended_metrics": {}} for i in range(5)]
        results = sector_engine.batch_enrich(items)
        for r in results:
            assert "sector_tags" in r
            assert len(r["sector_tags"]) >= 1

    def test_confidence_range(self, sector_engine, sample_iot_item):
        result = sector_engine.enrich_item(sample_iot_item)
        for tag in result["sector_tags"]:
            assert 0.0 <= tag["confidence"] <= 1.0


# ── EXPLOIT STATUS TESTS (10 tests) ──────────────────────────────────────────
class TestExploitStatusV46:
    def test_kev_is_itw(self, exploit_engine):
        item = {"title": "CVE test", "kev_present": True, "epss_score": None,
                "cvss_score": None, "risk_score": 5.0, "mitre_tactics": [],
                "ioc_counts": {}, "severity": "CRITICAL"}
        result = exploit_engine.enrich_item(item)
        assert result["exploit_status"]["status"] == "ITW"

    def test_itw_keyword_detection(self, exploit_engine):
        item = {"title": "CVE-2026-1731 fuels ongoing attacks on BeyondTrust",
                "kev_present": False, "epss_score": None, "cvss_score": None,
                "risk_score": 10.0, "mitre_tactics": [], "ioc_counts": {},
                "severity": "CRITICAL"}
        result = exploit_engine.enrich_item(item)
        assert result["exploit_status"]["status"] == "ITW"

    def test_high_epss_is_itw(self, exploit_engine):
        item = {"title": "CVE test", "kev_present": False, "epss_score": 65.0,
                "cvss_score": 8.0, "risk_score": 8.0, "mitre_tactics": [],
                "ioc_counts": {}, "severity": "HIGH"}
        result = exploit_engine.enrich_item(item)
        assert result["exploit_status"]["status"] == "ITW"

    def test_critical_cvss_active(self, exploit_engine):
        item = {"title": "CVE", "kev_present": False, "epss_score": None,
                "cvss_score": 9.5, "risk_score": 9.0, "mitre_tactics": ["T1190"],
                "ioc_counts": {}, "severity": "CRITICAL"}
        result = exploit_engine.enrich_item(item)
        assert result["exploit_status"]["status"] in ("ACTIVE", "ITW")

    def test_theoretical_low_cve(self, exploit_engine):
        item = {"title": "CVE-2026-9999 - minor XSS in CMS", "kev_present": False,
                "epss_score": None, "cvss_score": 3.0, "risk_score": 3.0,
                "mitre_tactics": ["T1059"], "ioc_counts": {}, "severity": "LOW"}
        result = exploit_engine.enrich_item(item)
        assert result["exploit_status"]["status"] in ("THEORETICAL", "POC_PUBLIC")

    def test_informational_no_cve(self, exploit_engine):
        item = {"title": "Alert fatigue is a major problem in SOCs",
                "kev_present": False, "epss_score": None, "cvss_score": None,
                "risk_score": 4.0, "mitre_tactics": ["T1566"], "ioc_counts": {},
                "severity": "MEDIUM"}
        result = exploit_engine.enrich_item(item)
        assert result["exploit_status"]["status"] == "INFORMATIONAL"

    def test_status_has_all_fields(self, exploit_engine, sample_cve_item):
        result = exploit_engine.enrich_item(sample_cve_item)
        status = result["exploit_status"]
        for field in ["status", "label", "short", "color", "icon",
                      "priority", "description", "rationale", "confidence"]:
            assert field in status

    def test_color_is_hex(self, exploit_engine, sample_cve_item):
        result = exploit_engine.enrich_item(sample_cve_item)
        color = result["exploit_status"]["color"]
        assert color.startswith("#")
        assert len(color) == 7

    def test_priority_ordering(self, exploit_engine):
        itw_item = {"title": "Actively exploited vulnerability", "kev_present": True,
                    "epss_score": None, "cvss_score": None, "risk_score": 10.0,
                    "mitre_tactics": [], "ioc_counts": {}, "severity": "CRITICAL"}
        info_item = {"title": "General advisory", "kev_present": False,
                     "epss_score": None, "cvss_score": None, "risk_score": 2.0,
                     "mitre_tactics": [], "ioc_counts": {}, "severity": "LOW"}
        itw_r = exploit_engine.enrich_item(itw_item)
        info_r = exploit_engine.enrich_item(info_item)
        assert itw_r["exploit_status"]["priority"] > info_r["exploit_status"]["priority"]

    def test_batch_all_have_status(self, exploit_engine):
        items = [{"title": f"CVE-2026-{i}", "kev_present": False,
                  "epss_score": None, "cvss_score": None, "risk_score": 5.0,
                  "mitre_tactics": [], "ioc_counts": {}, "severity": "MEDIUM"}
                 for i in range(5)]
        results = exploit_engine.batch_enrich(items)
        for r in results:
            assert "exploit_status" in r
            assert r["exploit_status"]["status"] in (
                "ITW", "ACTIVE", "POC_PUBLIC", "THEORETICAL", "INFORMATIONAL"
            )


# ── CWE CLASSIFIER TESTS (10 tests) ───────────────────────────────────────────
class TestCWEClassifierV46:
    def test_sql_injection(self, cwe_engine):
        r = cwe_engine.classify_title("CVE-2026-9999 - sql injection in login form")
        assert r is not None
        assert r["cwe_id"] == "CWE-89"

    def test_buffer_overflow(self, cwe_engine):
        r = cwe_engine.classify_title("UTT HiPER 810G strcpy buffer overflow")
        assert r is not None
        assert "CWE-12" in r["cwe_id"]

    def test_xss(self, cwe_engine):
        r = cwe_engine.classify_title("Reflected Cross-Site Scripting (XSS) in PideTuCita")
        assert r is not None
        assert r["cwe_id"] == "CWE-79"

    def test_ssrf(self, cwe_engine):
        r = cwe_engine.classify_title("Tiandy server-side request forgery in CLSBODownLoad")
        assert r is not None
        assert r["cwe_id"] == "CWE-918"

    def test_use_after_free(self, cwe_engine):
        r = cwe_engine.classify_title("ImageMagick has Use After Free in MSLStartElement")
        assert r is not None
        assert r["cwe_id"] == "CWE-416"

    def test_path_traversal(self, cwe_engine):
        r = cwe_engine.classify_title("HummerRisk Archive Extraction extractZip path traversal")
        assert r is not None
        assert r["cwe_id"] == "CWE-22"

    def test_missing_auth(self, cwe_engine):
        r = cwe_engine.classify_title("Missing authentication for critical endpoint")
        assert r is not None
        assert r["cwe_id"] == "CWE-306"

    def test_no_match_returns_none(self, cwe_engine):
        r = cwe_engine.classify_title("CrowdStrike annual threat report 2026")
        assert r is None

    def test_result_has_mitre_url(self, cwe_engine):
        r = cwe_engine.classify_title("SQL injection in web application")
        assert r is not None
        assert "mitre_cwe_url" in r
        assert "cwe.mitre.org" in r["mitre_cwe_url"]

    def test_enrich_item_adds_field(self, cwe_engine):
        item = {"title": "Command injection in router firmware"}
        result = cwe_engine.enrich_item(item)
        assert "cwe_classification" in result


# ── EXTENDED METRICS TESTS (10 tests) ─────────────────────────────────────────
class TestExtendedMetricsV46:
    def test_extended_metrics_populated(self, em_engine, sample_cve_item):
        result = em_engine.enrich_item(sample_cve_item)
        em = result["extended_metrics"]
        assert isinstance(em, dict)
        assert len(em) > 0

    def test_patch_priority_present(self, em_engine, sample_cve_item):
        result = em_engine.enrich_item(sample_cve_item)
        pp = result["extended_metrics"]["patch_priority"]
        assert "priority" in pp
        assert "sla_hours" in pp
        assert "label" in pp

    def test_geo_attribution_present(self, em_engine, sample_cve_item):
        sample_cve_item["actor_profile"] = {
            "origin": "Russia", "origin_flag": "🇷🇺"
        }
        result = em_engine.enrich_item(sample_cve_item)
        geo = result["extended_metrics"]["geo_attribution"]
        assert "attacker_origin" in geo
        assert "likely_victim_regions" in geo

    def test_product_detection_beyondtrust(self, em_engine):
        item = {"title": "BeyondTrust remote access products exploited",
                "kev_present": False, "epss_score": None, "cvss_score": None,
                "risk_score": 10.0, "severity": "CRITICAL",
                "ioc_counts": {}, "mitre_tactics": [], "feed_source": "",
                "source_url": "", "actor_profile": {"origin": "Unknown", "origin_flag": "❓"},
                "exploit_status": {"status": "ITW"}, "extended_metrics": {}}
        result = em_engine.enrich_item(item)
        products = result["extended_metrics"]["affected_products"]
        assert "BeyondTrust" in products

    def test_vuln_class_rce(self, em_engine):
        item = {"title": "Remote code execution vulnerability in XYZ",
                "kev_present": False, "epss_score": None, "cvss_score": 9.8,
                "risk_score": 9.5, "severity": "CRITICAL",
                "ioc_counts": {}, "mitre_tactics": [], "feed_source": "",
                "source_url": "", "actor_profile": {"origin": "Unknown", "origin_flag": "❓"},
                "exploit_status": {"status": "ACTIVE"}, "extended_metrics": {}}
        result = em_engine.enrich_item(item)
        vc = result["extended_metrics"]["vulnerability_class"]
        assert "RCE" in vc or "Remote Code Execution" in vc

    def test_immediate_priority_kev(self, em_engine, sample_cve_item):
        sample_cve_item["kev_present"] = True
        sample_cve_item["actor_profile"] = {"origin": "China", "origin_flag": "🇨🇳"}
        sample_cve_item["exploit_status"] = {"status": "ITW"}
        result = em_engine.enrich_item(sample_cve_item)
        assert result["extended_metrics"]["patch_priority"]["priority"] == "IMMEDIATE"

    def test_disclosure_type_present(self, em_engine, sample_cve_item):
        sample_cve_item["actor_profile"] = {"origin": "Unknown", "origin_flag": "❓"}
        sample_cve_item["exploit_status"] = {"status": "THEORETICAL"}
        result = em_engine.enrich_item(sample_cve_item)
        assert "disclosure_type" in result["extended_metrics"]

    def test_enrichment_version_tagged(self, em_engine, sample_cve_item):
        sample_cve_item["actor_profile"] = {"origin": "Unknown", "origin_flag": "❓"}
        sample_cve_item["exploit_status"] = {"status": "THEORETICAL"}
        result = em_engine.enrich_item(sample_cve_item)
        assert result["extended_metrics"]["enrichment_version"] == "v46.0"

    def test_no_existing_fields_destroyed(self, em_engine, sample_cve_item):
        original_stix_id = sample_cve_item["stix_id"]
        original_risk = sample_cve_item["risk_score"]
        sample_cve_item["actor_profile"] = {"origin": "Unknown", "origin_flag": "❓"}
        sample_cve_item["exploit_status"] = {"status": "THEORETICAL"}
        result = em_engine.enrich_item(sample_cve_item)
        assert result["stix_id"] == original_stix_id
        assert result["risk_score"] == original_risk

    def test_batch_100_percent_populated(self, em_engine):
        items = []
        for i in range(10):
            items.append({
                "title": f"CVE-2026-{i} test vulnerability",
                "kev_present": False, "epss_score": None, "cvss_score": None,
                "risk_score": 5.0, "severity": "MEDIUM", "ioc_counts": {},
                "mitre_tactics": [], "feed_source": "", "source_url": "",
                "actor_profile": {"origin": "Unknown", "origin_flag": "❓"},
                "exploit_status": {"status": "THEORETICAL"}, "extended_metrics": {},
                "timestamp": "2026-03-01T00:00:00+00:00",
            })
        results = em_engine.batch_enrich(items)
        for r in results:
            assert r["extended_metrics"] != {}


# ── INTEL QUALITY SCORER TESTS (10 tests) ─────────────────────────────────────
class TestIntelQualityScorerV46:
    def test_score_returns_0_100(self, iqs_engine, enriched_item):
        result = iqs_engine.enrich_item(enriched_item)
        score = result["intel_quality"]["iqs_score"]
        assert 0 <= score <= 100

    def test_gold_tier_high_quality(self, iqs_engine):
        item = {
            "title": "CVE-2026-9999 Remote Code Execution",
            "actor_tag": "CDB-APT-28",
            "actor_profile": {"attribution_confidence": 0.85},
            "sector_tags": [{"sector": "Healthcare"}],
            "exploit_status": {"status": "ITW"},
            "cwe_classification": {"cwe_id": "CWE-78"},
            "kev_present": True,
            "cvss_score": 9.8,
            "epss_score": 65.0,
            "confidence_score": 80.0,
            "mitre_tactics": ["T1190", "T1203", "T1059", "T1547"],
            "ioc_counts": {"ipv4": 3, "domain": 2, "cve": 1, "sha256": 1,
                           "url": 0, "sha1": 0, "md5": 0, "email": 0,
                           "registry": 0, "artifacts": 1},
        }
        result = iqs_engine.enrich_item(item)
        assert result["intel_quality"]["iqs_tier"] in ("GOLD", "SILVER")
        assert result["intel_quality"]["iqs_score"] >= 60

    def test_minimal_tier_empty_item(self, iqs_engine):
        item = {
            "title": "General advisory no CVE",
            "actor_tag": "UNC-CDB-99",
            "actor_profile": {"attribution_confidence": 0.0},
            "sector_tags": [],
            "exploit_status": {},
            "cwe_classification": None,
            "kev_present": False,
            "cvss_score": None,
            "epss_score": None,
            "confidence_score": 0.0,
            "mitre_tactics": [],
            "ioc_counts": {"ipv4": 0, "domain": 0, "cve": 0, "sha256": 0,
                           "url": 0, "sha1": 0, "md5": 0, "email": 0,
                           "registry": 0, "artifacts": 0},
        }
        result = iqs_engine.enrich_item(item)
        assert result["intel_quality"]["iqs_tier"] in ("MINIMAL", "LOW")

    def test_all_iqs_fields_present(self, iqs_engine, enriched_item):
        result = iqs_engine.enrich_item(enriched_item)
        iq = result["intel_quality"]
        for field in ["iqs_score", "iqs_tier", "iqs_label", "iqs_color",
                      "iqs_icon", "dimension_scores", "missing_signals",
                      "completeness_pct"]:
            assert field in iq

    def test_color_is_hex(self, iqs_engine, enriched_item):
        result = iqs_engine.enrich_item(enriched_item)
        color = result["intel_quality"]["iqs_color"]
        assert color.startswith("#")

    def test_dimension_scores_sum(self, iqs_engine, enriched_item):
        result = iqs_engine.enrich_item(enriched_item)
        ds = result["intel_quality"]["dimension_scores"]
        assert sum(ds.values()) <= 100

    def test_kev_boosts_score(self, iqs_engine):
        base = {"title": "CVE-9999", "actor_tag": "CDB-APT-28",
                "actor_profile": {"attribution_confidence": 0.8},
                "sector_tags": [{"sector": "Finance"}],
                "exploit_status": {"status": "THEORETICAL"},
                "cwe_classification": None, "kev_present": False,
                "cvss_score": 7.0, "epss_score": None, "confidence_score": 50.0,
                "mitre_tactics": ["T1190", "T1203"],
                "ioc_counts": {"cve": 1, "ipv4": 0, "domain": 0, "url": 0,
                               "sha256": 0, "sha1": 0, "md5": 0, "email": 0,
                               "registry": 0, "artifacts": 0}}
        kev = dict(base)
        kev["kev_present"] = True
        kev["exploit_status"] = {"status": "ITW"}
        r_base = iqs_engine.score_item(base)
        r_kev = iqs_engine.score_item(kev)
        assert r_kev["iqs_score"] >= r_base["iqs_score"]

    def test_platform_stats(self, iqs_engine):
        items = []
        for i in range(5):
            item = {"title": f"CVE-{i}", "actor_tag": "UNC-CDB-99",
                    "actor_profile": {"attribution_confidence": 0.0},
                    "sector_tags": [], "exploit_status": {}, "cwe_classification": None,
                    "kev_present": False, "cvss_score": None, "epss_score": None,
                    "confidence_score": 10.0, "mitre_tactics": [],
                    "ioc_counts": {"cve": 1, "ipv4": 0, "domain": 0, "url": 0,
                                   "sha256": 0, "sha1": 0, "md5": 0, "email": 0,
                                   "registry": 0, "artifacts": 0}}
            item = iqs_engine.enrich_item(item)
            items.append(item)
        stats = iqs_engine.compute_platform_stats(items)
        assert "avg_iqs" in stats
        assert "tier_distribution" in stats

    def test_missing_signals_list(self, iqs_engine):
        item = {"title": "General advisory", "actor_tag": "UNC-CDB-99",
                "actor_profile": {"attribution_confidence": 0.0},
                "sector_tags": [], "exploit_status": {}, "cwe_classification": None,
                "kev_present": False, "cvss_score": None, "epss_score": None,
                "confidence_score": 0.0, "mitre_tactics": [],
                "ioc_counts": {"cve": 0, "ipv4": 0, "domain": 0, "url": 0,
                               "sha256": 0, "sha1": 0, "md5": 0, "email": 0,
                               "registry": 0, "artifacts": 0}}
        result = iqs_engine.enrich_item(item)
        missing = result["intel_quality"]["missing_signals"]
        assert isinstance(missing, list)
        assert len(missing) > 0

    def test_batch_all_scored(self, iqs_engine):
        items = [{"title": f"CVE-{i}", "actor_tag": "UNC-CDB-99",
                  "actor_profile": {"attribution_confidence": 0.0},
                  "sector_tags": [], "exploit_status": {}, "cwe_classification": None,
                  "kev_present": False, "cvss_score": None, "epss_score": None,
                  "confidence_score": 0.0, "mitre_tactics": [],
                  "ioc_counts": {}} for i in range(10)]
        results = iqs_engine.batch_enrich(items)
        for r in results:
            assert "intel_quality" in r
            assert 0 <= r["intel_quality"]["iqs_score"] <= 100
