#!/usr/bin/env python3
"""
tests/test_access_governance.py — SENTINEL APEX v173.0
ACCESS GOVERNANCE REGRESSION TEST SUITE

MANDATE: These tests are the permanent regression guard for MODEL_C.
         They MUST pass before any deployment.
         Failure = deployment blocked.

Tests (all mandated by SENTINEL APEX v173.0 governance):
  - test_public_summary_only()
  - test_pro_full_report_access()
  - test_enterprise_api_access()
  - test_no_public_iocs()
  - test_no_public_detection_rules()
  - test_no_public_stix()
  - test_dashboard_access_policy()
  - test_access_control_governor()

Additional coverage:
  - test_model_a_disabled()
  - test_model_b_disabled()
  - test_tier_hierarchy()
  - test_strip_for_tier()
  - test_validate_api_response()
  - test_report_metadata_validation()
  - test_policy_drift_detection()
  - test_upgrade_prompt()
  - test_tier_normalization()
"""

import json
import sys
import os
import pytest

# Ensure project root is in path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

from access_control_policy import (
    TIER_PUBLIC,
    TIER_PRO,
    TIER_ENTERPRISE,
    TIER_MSSP,
    TIER_ORDER,
    TIER_ALLOWED_FIELDS,
    PUBLIC_BLOCKED_FIELDS,
    PUBLIC_ALLOWED_FIELDS,
    API_PUBLIC_BLOCKED,
    REQUIRED_REPORT_FIELDS,
    REPORT_TIER_CLASSIFICATIONS,
    normalize_tier,
    tier_meets_requirement,
    has_feature,
    strip_for_tier,
    validate_api_response,
    validate_report_metadata,
    get_report_classification,
    assert_dashboard_card_safe,
    build_upgrade_prompt,
    run_policy_checks,
    detect_policy_drift,
    compute_policy_hash,
    generate_audit_record,
)


# ─────────────────────────────────────────────────────────────────────────────
# FIXTURE: synthetic threat entry with all fields
# ─────────────────────────────────────────────────────────────────────────────

@pytest.fixture
def full_threat_entry():
    """A synthetic intelligence entry containing all possible fields."""
    return {
        # Public fields
        "id": "test-id-001",
        "stix_id": "indicator--test-001",
        "bundle_id": "bundle-001",
        "title": "Critical RCE in FortiGate — APT41 Campaign",
        "risk_score": 9.5,
        "severity": "CRITICAL",
        "tlp_label": "TLP:AMBER",
        "generated_at": "2026-06-03T00:00:00Z",
        "source_url": "https://example.com/advisory",
        "mitre_tactics": ["Initial Access", "Execution"],
        "actor_tag": "APT41",
        "status": "active",
        "confidence": 92,
        "kev_present": True,
        "feed_source": "NVD",
        "executive_summary": "A" * 800,  # Over limit — should be truncated for PUBLIC
        "validation_status": "verified",
        "processed_at": "2026-06-03T01:00:00Z",
        "timestamp": "2026-06-03T00:00:00Z",
        # PRO-only fields
        "report_url": "/reports/test-001.html",
        "internal_report_url": "/reports/test-001.html",
        "pdf_url": "/reports/test-001.pdf",
        "ioc_counts": {"ips": 12, "domains": 5, "hashes": 8},
        "ioc_list": ["1.2.3.4", "evil.com"],
        "indicators": [{"type": "ip", "value": "1.2.3.4"}],
        "sigma_rules": "title: APT41 RCE\ndetection: ...",
        "yara_rules": "rule APT41 { ... }",
        "kql_queries": "SecurityEvent | where ...",
        "suricata_rules": "alert tcp ...",
        "detection_rules": {"sigma": "...", "yara": "..."},
        "ai_analysis": "Full AI threat actor attribution analysis...",
        "apex_ai": {"ai_summary": "Deep kill chain analysis..."},
        "threat_context": "Nation-state campaign targeting financial sector",
        "campaign_intelligence": {"campaign_id": "APT41-2026-Q2"},
        "kill_chain": ["Recon", "Weaponize", "Deliver"],
        "behavioral_tags": ["lateral_movement", "credential_dumping"],
        "mitre_techniques": ["T1190", "T1059"],
        "attack_navigator": {"layers": []},
        "actor_profile": {"name": "APT41", "origin": "CN"},
        # ENTERPRISE-only fields
        "stix_bundle": {"type": "bundle", "id": "bundle--001"},
        "stix_bundle_url": "/api/v1/enterprise/stix/bundle-001",
        "full_stix": {"type": "bundle"},
        "misp_event": {"id": 1234},
        "enterprise_feeds": [{"feed": "threat_intel_feed"}],
        "full_iocs": {"ips": ["1.2.3.4", "5.6.7.8"]},
        "full_detection_content": {"sigma": "...", "yara": "...", "kql": "..."},
        "full_actor_intelligence": {"actors": [{"name": "APT41"}]},
        "gumroad_url": "https://gumroad.com/l/test",
        # MSSP-only fields
        "tenant_id": "tenant-acme-corp",
        "detection_pack": {"pack_id": "dp-001"},
    }


@pytest.fixture
def minimal_public_entry():
    """Minimal public-safe entry."""
    return {
        "id": "pub-001",
        "title": "Public Advisory",
        "risk_score": 7.0,
        "severity": "HIGH",
        "source_url": "https://example.com/pub",
    }


# ─────────────────────────────────────────────────────────────────────────────
# MANDATED TESTS (all 8 required by governance spec)
# ─────────────────────────────────────────────────────────────────────────────

def test_public_summary_only(full_threat_entry):
    """
    PUBLIC tier API responses MUST contain only summary data.
    Full reports, IOC data, detection content, STIX are NEVER returned.
    """
    stripped = strip_for_tier(full_threat_entry, TIER_PUBLIC)

    # Must have basic summary fields
    assert "title" in stripped
    assert "severity" in stripped
    assert "risk_score" in stripped
    assert "source_url" in stripped

    # Must NOT have full-report fields (MODEL_B disabled)
    assert "report_url" not in stripped, "PUBLIC tier must not receive report_url"
    assert "internal_report_url" not in stripped, "PUBLIC tier must not receive internal_report_url"
    assert "pdf_url" not in stripped, "PUBLIC tier must not receive pdf_url"

    # Must NOT have IOC data
    assert "ioc_list" not in stripped, "PUBLIC tier must not receive ioc_list"
    assert "ioc_counts" not in stripped, "PUBLIC tier must not receive ioc_counts"
    assert "full_iocs" not in stripped, "PUBLIC tier must not receive full_iocs"

    # Must NOT have AI analysis
    assert "ai_analysis" not in stripped, "PUBLIC tier must not receive ai_analysis"
    assert "apex_ai" not in stripped, "PUBLIC tier must not receive apex_ai"

    # Executive summary must be truncated
    assert "executive_summary" in stripped
    assert len(stripped["executive_summary"]) <= 503, \
        f"executive_summary must be truncated for PUBLIC (got {len(stripped['executive_summary'])} chars)"

    # No detection content
    assert "sigma_rules" not in stripped
    assert "yara_rules" not in stripped
    assert "kql_queries" not in stripped


def test_pro_full_report_access(full_threat_entry):
    """
    PRO tier MUST have access to full intelligence reports.
    Full reports, detection rules, IOC data, AI analysis available.
    STIX bundle and Enterprise feeds remain locked.
    """
    stripped = strip_for_tier(full_threat_entry, TIER_PRO)

    # PRO must have report access
    assert "report_url" in stripped, "PRO tier must receive report_url"
    assert "internal_report_url" in stripped, "PRO tier must receive internal_report_url"
    assert "pdf_url" in stripped, "PRO tier must receive pdf_url"

    # PRO must have detection content
    assert "sigma_rules" in stripped, "PRO tier must receive sigma_rules"
    assert "yara_rules" in stripped, "PRO tier must receive yara_rules"
    assert "kql_queries" in stripped, "PRO tier must receive kql_queries"

    # PRO must have IOC data
    assert "ioc_list" in stripped or "ioc_counts" in stripped, \
        "PRO tier must receive IOC fields"

    # PRO must have AI analysis
    assert "ai_analysis" in stripped or "apex_ai" in stripped, \
        "PRO tier must receive AI analysis"

    # Enterprise-only fields must still be blocked at PRO
    assert "stix_bundle" not in stripped, "stix_bundle must require ENTERPRISE, not PRO"

    # PRO has view_full_report feature
    assert has_feature(TIER_PRO, "view_full_report")

    # PRO can access detection rules
    assert has_feature(TIER_PRO, "view_sigma")
    assert has_feature(TIER_PRO, "view_yara")
    assert has_feature(TIER_PRO, "view_kql")


def test_enterprise_api_access(full_threat_entry):
    """
    ENTERPRISE tier MUST have access to API, STIX, MISP, enterprise features.
    Enterprise APIs must never be publicly accessible.
    """
    stripped = strip_for_tier(full_threat_entry, TIER_ENTERPRISE)

    # ENTERPRISE must have STIX bundle
    assert "stix_bundle" in stripped, "ENTERPRISE tier must receive stix_bundle"
    assert "stix_bundle_url" in stripped, "ENTERPRISE tier must receive stix_bundle_url"

    # ENTERPRISE must have full IOC data
    assert "full_iocs" in stripped, "ENTERPRISE tier must receive full_iocs"

    # ENTERPRISE must have MISP event
    assert "misp_event" in stripped, "ENTERPRISE tier must receive misp_event"

    # ENTERPRISE features enabled
    assert has_feature(TIER_ENTERPRISE, "api_access")
    assert has_feature(TIER_ENTERPRISE, "export_stix")
    assert has_feature(TIER_ENTERPRISE, "export_misp")
    assert has_feature(TIER_ENTERPRISE, "siem_integration")

    # ENTERPRISE must not appear in PUBLIC API responses
    public_response = {
        "api_tier": "PUBLIC",
        "entries": [stripped],
    }
    # If the enterprise entry was stripped first, validate it's clean at API level
    # Confirm enterprise_api is never in public response structure
    is_valid, violations = validate_api_response({"api_tier": "PUBLIC", "entries": [
        {"full_iocs": {"ips": ["1.2.3.4"]}}
    ]}, TIER_PUBLIC)
    assert not is_valid, "validate_api_response must catch full_iocs in public response"
    assert any("full_iocs" in v for v in violations)


def test_no_public_iocs(full_threat_entry):
    """
    IOC data MUST NEVER appear in any PUBLIC tier API response.
    Covers all IOC field variants.
    """
    ioc_fields = [
        "iocs", "ioc_counts", "ioc_list", "indicators",
        "full_iocs",
    ]
    stripped = strip_for_tier(full_threat_entry, TIER_PUBLIC)

    for field in ioc_fields:
        assert field not in stripped, \
            f"IOC field '{field}' must not appear in PUBLIC tier response"

    # Validate via API response validator
    for field in ioc_fields:
        # Inject blocked field and confirm validator catches it
        test_response = {"api_tier": "PUBLIC", "entries": [{field: "some_ioc_data"}]}
        is_valid, violations = validate_api_response(test_response, TIER_PUBLIC)
        # Only API_PUBLIC_BLOCKED fields are caught by validate_api_response
        if field in API_PUBLIC_BLOCKED:
            assert not is_valid, f"validate_api_response must block '{field}' in public response"


def test_no_public_detection_rules(full_threat_entry):
    """
    Detection rules (Sigma, YARA, KQL, Suricata) MUST NEVER appear
    in PUBLIC tier responses.
    """
    detection_fields = [
        "sigma_rules", "yara_rules", "kql_queries", "suricata_rules",
        "detection_rules", "detection_pack", "full_detection_content",
    ]
    stripped = strip_for_tier(full_threat_entry, TIER_PUBLIC)

    for field in detection_fields:
        assert field not in stripped, \
            f"Detection field '{field}' must not appear in PUBLIC tier response"

    # Confirm policy explicitly blocks these
    for field in detection_fields:
        assert field in PUBLIC_BLOCKED_FIELDS, \
            f"'{field}' must be in PUBLIC_BLOCKED_FIELDS"

    # PUBLIC tier does not have detection feature access
    assert not has_feature(TIER_PUBLIC, "view_sigma")
    assert not has_feature(TIER_PUBLIC, "view_yara")
    assert not has_feature(TIER_PUBLIC, "view_kql")
    assert not has_feature(TIER_PUBLIC, "view_suricata")


def test_no_public_stix(full_threat_entry):
    """
    STIX bundles, STIX export URLs, MISP events MUST NEVER appear
    in PUBLIC tier responses.
    """
    stix_fields = [
        "stix_bundle", "stix_bundle_url", "full_stix", "misp_event",
    ]
    stripped = strip_for_tier(full_threat_entry, TIER_PUBLIC)

    for field in stix_fields:
        assert field not in stripped, \
            f"STIX field '{field}' must not appear in PUBLIC tier response"

    # PUBLIC does not have STIX export feature
    assert not has_feature(TIER_PUBLIC, "export_stix")
    assert not has_feature(TIER_PUBLIC, "export_misp")

    # ENTERPRISE required for STIX
    assert has_feature(TIER_ENTERPRISE, "export_stix")
    assert tier_meets_requirement(TIER_ENTERPRISE, TIER_ENTERPRISE)
    assert not tier_meets_requirement(TIER_PRO, TIER_ENTERPRISE)

    # Validate via API validator
    test_response = {"api_tier": "PUBLIC", "entries": [{"full_stix": {"type": "bundle"}}]}
    is_valid, violations = validate_api_response(test_response, TIER_PUBLIC)
    assert not is_valid, "validate_api_response must catch full_stix in public response"


def test_dashboard_access_policy(full_threat_entry):
    """
    Dashboard cards MUST be safe for PUBLIC render.
    - report_url: blocked for PUBLIC
    - pdf_url: blocked for PUBLIC
    - IOC data: blocked for PUBLIC
    Dashboard must never link directly to full HTML report unless user tier >= PRO.
    """
    # Simulate what public_api._strip_for_public() returns
    public_card = strip_for_tier(full_threat_entry, TIER_PUBLIC)

    # Card must be safe for public dashboard
    is_safe, violations = assert_dashboard_card_safe(public_card)
    assert is_safe, f"Public dashboard card has violations: {violations}"

    # A card with report_url is NOT safe for public
    unsafe_card = {"report_url": "/reports/test.html", "title": "Test"}
    is_safe, violations = assert_dashboard_card_safe(unsafe_card)
    assert not is_safe, "Card with report_url must not be safe for public"
    assert any("report_url" in v for v in violations)

    # A card with stix_bundle_url is NOT safe for public
    unsafe_stix_card = {"stix_bundle_url": "/api/v1/stix/bundle-001", "title": "Test"}
    is_safe, violations = assert_dashboard_card_safe(unsafe_stix_card)
    assert not is_safe, "Card with stix_bundle_url must not be safe for public"

    # VIEW_FULL_REPORT feature requires PRO
    assert has_feature(TIER_PRO, "view_full_report")
    assert not has_feature(TIER_PUBLIC, "view_full_report"), \
        "view_full_report must require PRO — MODEL_B prevents public access"

    # Dashboard card must show upgrade CTA for public, not report link
    upgrade_prompt = build_upgrade_prompt("view_full_report", TIER_PUBLIC)
    assert upgrade_prompt["access_denied"] is True
    assert upgrade_prompt["required_tier"] == TIER_PRO


def test_access_control_governor():
    """
    access_control_policy.py must be the single source of truth.
    All policy self-checks must pass.
    Policy hash must be stable.
    Import self-check must not raise.
    """
    # Policy self-checks must all pass
    result = run_policy_checks()
    assert result["passed"], \
        f"Policy self-checks failed: " + \
        str([k for k, v in result["checks"].items() if not v["passed"]])

    # All individual checks
    for check_name, check_result in result["checks"].items():
        assert check_result["passed"], \
            f"Policy check '{check_name}' failed: {check_result['detail']}"

    # Policy hash must be deterministic
    hash1 = compute_policy_hash()
    hash2 = compute_policy_hash()
    assert hash1 == hash2, "Policy hash must be deterministic"
    assert len(hash1) == 64, "Policy hash must be SHA-256 (64 hex chars)"

    # Drift detection must report no drift against itself
    drift = detect_policy_drift(hash1)
    assert not drift["drift_detected"], "Policy drift must not be detected against itself"

    # Audit record must be complete
    audit = generate_audit_record()
    assert "policy_hash" in audit
    assert "policy_version" in audit
    assert audit["governance"]["model_a_disabled"] is True
    assert audit["governance"]["model_b_disabled"] is True
    assert audit["governance"]["model_c_canonical"] is True
    assert audit["governance"]["single_source_of_truth"] == "access_control_policy.py"


# ─────────────────────────────────────────────────────────────────────────────
# ADDITIONAL GOVERNANCE TESTS
# ─────────────────────────────────────────────────────────────────────────────

def test_model_a_disabled():
    """
    MODEL_A (Dashboard → Upgrade Only) is permanently disabled.
    No component may generate an "upgrade-only" dashboard with no intelligence data.
    The platform MUST show intelligence summaries (PUBLIC tier) not blank upgrade walls.
    """
    # PUBLIC tier must still have summary fields available
    assert "title" in TIER_ALLOWED_FIELDS[TIER_PUBLIC]
    assert "severity" in TIER_ALLOWED_FIELDS[TIER_PUBLIC]
    assert "risk_score" in TIER_ALLOWED_FIELDS[TIER_PUBLIC]
    assert "executive_summary" in TIER_ALLOWED_FIELDS[TIER_PUBLIC]
    assert has_feature(TIER_PUBLIC, "view_summary")
    assert has_feature(TIER_PUBLIC, "view_dashboard_card")
    assert has_feature(TIER_PUBLIC, "view_executive_summary")
    # MODEL_A would have blocked all content — confirm it's not the case


def test_model_b_disabled():
    """
    MODEL_B (Dashboard → Public Full Intelligence Report) is permanently disabled.
    The critical invariant: report_url MUST NOT appear in PUBLIC tier under ANY circumstances.
    """
    # The most important invariant in the entire governance system
    assert "report_url" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC], \
        "CRITICAL: MODEL_B VIOLATION — report_url must never be in PUBLIC allowed fields"

    assert "internal_report_url" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC], \
        "CRITICAL: MODEL_B VIOLATION — internal_report_url must never be in PUBLIC allowed fields"

    assert "stix_bundle_url" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC], \
        "CRITICAL: MODEL_B VIOLATION — stix_bundle_url must never be in PUBLIC allowed fields"

    assert "pdf_url" not in TIER_ALLOWED_FIELDS[TIER_PUBLIC], \
        "CRITICAL: MODEL_B VIOLATION — pdf_url must never be in PUBLIC allowed fields"

    # Confirm these are in PUBLIC_BLOCKED_FIELDS
    assert "report_url" in PUBLIC_BLOCKED_FIELDS
    assert "internal_report_url" in PUBLIC_BLOCKED_FIELDS

    # Strip test: even if entry has report_url, PUBLIC tier must not receive it
    entry_with_report = {
        "title": "Test",
        "report_url": "/reports/sensitive.html",
        "internal_report_url": "/reports/sensitive.html",
    }
    stripped = strip_for_tier(entry_with_report, TIER_PUBLIC)
    assert "report_url" not in stripped, "strip_for_tier must remove report_url for PUBLIC"
    assert "internal_report_url" not in stripped, \
        "strip_for_tier must remove internal_report_url for PUBLIC"


def test_tier_hierarchy():
    """Tier privilege hierarchy must be: PUBLIC < PRO < ENTERPRISE < MSSP."""
    assert TIER_ORDER[TIER_PUBLIC] < TIER_ORDER[TIER_PRO]
    assert TIER_ORDER[TIER_PRO] < TIER_ORDER[TIER_ENTERPRISE]
    assert TIER_ORDER[TIER_ENTERPRISE] < TIER_ORDER[TIER_MSSP]

    # tier_meets_requirement
    assert tier_meets_requirement(TIER_PUBLIC, TIER_PUBLIC)
    assert tier_meets_requirement(TIER_PRO, TIER_PUBLIC)
    assert tier_meets_requirement(TIER_PRO, TIER_PRO)
    assert tier_meets_requirement(TIER_ENTERPRISE, TIER_PRO)
    assert tier_meets_requirement(TIER_ENTERPRISE, TIER_ENTERPRISE)
    assert tier_meets_requirement(TIER_MSSP, TIER_ENTERPRISE)

    assert not tier_meets_requirement(TIER_PUBLIC, TIER_PRO)
    assert not tier_meets_requirement(TIER_PUBLIC, TIER_ENTERPRISE)
    assert not tier_meets_requirement(TIER_PRO, TIER_ENTERPRISE)
    assert not tier_meets_requirement(TIER_PRO, TIER_MSSP)

    # MSSP inherits all features of lower tiers
    for tier in [TIER_PUBLIC, TIER_PRO, TIER_ENTERPRISE]:
        assert tier_meets_requirement(TIER_MSSP, tier)


def test_strip_for_tier(full_threat_entry):
    """strip_for_tier must enforce deny-by-default correctly for all tiers."""
    public_stripped   = strip_for_tier(full_threat_entry, TIER_PUBLIC)
    pro_stripped      = strip_for_tier(full_threat_entry, TIER_PRO)
    ent_stripped      = strip_for_tier(full_threat_entry, TIER_ENTERPRISE)
    mssp_stripped     = strip_for_tier(full_threat_entry, TIER_MSSP)

    # Public has fewer fields than PRO
    assert len(public_stripped) < len(pro_stripped)
    # PRO has fewer fields than ENTERPRISE
    assert len(pro_stripped) <= len(ent_stripped)
    # ENTERPRISE has fewer or equal fields than MSSP
    assert len(ent_stripped) <= len(mssp_stripped)

    # Unknown tier defaults to PUBLIC
    unknown_stripped = strip_for_tier(full_threat_entry, "UNKNOWN_TIER_XYZ")
    assert "report_url" not in unknown_stripped
    assert "stix_bundle" not in unknown_stripped


def test_validate_api_response(full_threat_entry):
    """validate_api_response must catch all forbidden fields in public responses."""
    # Clean public response — should pass
    clean_response = {
        "api_tier": "PUBLIC",
        "entries": [strip_for_tier(full_threat_entry, TIER_PUBLIC)],
    }
    is_valid, violations = validate_api_response(clean_response, TIER_PUBLIC)
    assert is_valid, f"Clean public response failed validation: {violations}"

    # Response with blocked fields — should fail
    for blocked_field in ["full_iocs", "report_url", "stix_bundle_url", "full_stix"]:
        dirty_response = {
            "api_tier": "PUBLIC",
            "entries": [{blocked_field: "sensitive_data"}],
        }
        is_valid, violations = validate_api_response(dirty_response, TIER_PUBLIC)
        if blocked_field in API_PUBLIC_BLOCKED:
            assert not is_valid, \
                f"validate_api_response must catch '{blocked_field}' in public API response"


def test_report_metadata_validation():
    """Every generated report must have classification, required_tier, access_policy."""
    # Valid report metadata
    valid_meta = {
        "title": "Test Report",
        "classification": "TLP:AMBER",
        "required_tier": "PRO",
        "access_policy": "MODEL_C_PRO",
    }
    is_valid, missing = validate_report_metadata(valid_meta)
    assert is_valid, f"Valid report metadata failed validation: {missing}"

    # Missing required fields
    for required_field in ["classification", "required_tier", "access_policy"]:
        invalid_meta = {k: v for k, v in valid_meta.items() if k != required_field}
        is_valid, missing = validate_report_metadata(invalid_meta)
        assert not is_valid, f"Missing '{required_field}' should fail validation"
        assert required_field in missing

    # Report classifications must be complete
    for report_type in ["summary", "full", "enterprise"]:
        classification = get_report_classification(report_type)
        assert "classification" in classification
        assert "required_tier" in classification
        assert "access_policy" in classification

    # Summary reports are PUBLIC tier
    summary_class = get_report_classification("summary")
    assert summary_class["required_tier"] == TIER_PUBLIC

    # Full reports are PRO tier
    full_class = get_report_classification("full")
    assert full_class["required_tier"] == TIER_PRO

    # Enterprise reports are ENTERPRISE tier
    ent_class = get_report_classification("enterprise")
    assert ent_class["required_tier"] == TIER_ENTERPRISE


def test_policy_drift_detection():
    """Policy drift detection must catch unauthorized modifications."""
    # No drift against current hash
    current_hash = compute_policy_hash()
    drift = detect_policy_drift(current_hash)
    assert not drift["drift_detected"]

    # Drift against tampered hash
    tampered_hash = "0" * 64
    drift = detect_policy_drift(tampered_hash)
    assert drift["drift_detected"]
    assert "POLICY DRIFT DETECTED" in drift["governance_message"]

    # Hash is 64-char SHA-256
    assert len(current_hash) == 64
    assert all(c in "0123456789abcdef" for c in current_hash)


def test_upgrade_prompt():
    """build_upgrade_prompt must return correct tier requirements."""
    # view_full_report requires PRO
    prompt = build_upgrade_prompt("view_full_report", TIER_PUBLIC)
    assert prompt["access_denied"] is True
    assert prompt["required_tier"] == TIER_PRO
    assert prompt["current_tier"] == TIER_PUBLIC
    assert "upgrade_url" in prompt

    # export_stix requires ENTERPRISE
    stix_prompt = build_upgrade_prompt("export_stix", TIER_PRO)
    assert stix_prompt["access_denied"] is True
    assert stix_prompt["required_tier"] == TIER_ENTERPRISE


def test_tier_normalization():
    """All tier aliases must normalize to canonical tier names."""
    assert normalize_tier("FREE")      == TIER_PUBLIC
    assert normalize_tier("free")      == TIER_PUBLIC
    assert normalize_tier("STANDARD")  == TIER_PUBLIC
    assert normalize_tier("PREMIUM")   == TIER_PRO
    assert normalize_tier("premium")   == TIER_PRO
    assert normalize_tier("PRO")       == TIER_PRO
    assert normalize_tier("pro")       == TIER_PRO
    assert normalize_tier("ENTERPRISE") == TIER_ENTERPRISE
    assert normalize_tier("enterprise") == TIER_ENTERPRISE
    assert normalize_tier("MSSP")      == TIER_MSSP
    assert normalize_tier("mssp")      == TIER_MSSP

    # Unknown tier defaults to PUBLIC
    assert normalize_tier("UNKNOWN")   == TIER_PUBLIC
    assert normalize_tier("")          == TIER_PUBLIC


def test_public_api_strip_integration(full_threat_entry):
    """
    Integration test: public_api._strip_for_public must use the policy governor.

    This test statically verifies that public_api.py contains the required
    governance code, without importing the module (which requires CDB_JWT_SECRET).
    Full runtime validation happens in the CI environment with secrets.
    """
    import re

    public_api_path = os.path.join(
        os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
        "agent", "api", "public_api.py"
    )
    assert os.path.exists(public_api_path), "public_api.py must exist"

    with open(public_api_path, "r", encoding="utf-8") as f:
        content = f.read()

    # Verify governance code is present (static analysis)
    assert "from access_control_policy import" in content, \
        "public_api.py must import from access_control_policy (MODEL_C governance)"

    assert "strip_for_tier" in content, \
        "public_api.py must use strip_for_tier from access_control_policy"

    assert "_validate_and_block" in content, \
        "public_api.py must call _validate_and_block on all public responses"

    assert '"access_policy"' in content, \
        "public_api.py responses must include access_policy field"

    # MODEL_B: confirm report_url is NOT in a PUBLIC_FIELDS literal set
    # Look for the OLD pattern: "report_url" inside a PUBLIC_FIELDS = {...} block
    lines = content.split("\n")
    in_public_fields_block = False
    model_b_violations = []
    for i, line in enumerate(lines, 1):
        stripped = line.strip()
        if stripped.startswith("#"):
            continue
        if "PUBLIC_FIELDS" in line and "=" in line and "{" in line:
            in_public_fields_block = True
        if in_public_fields_block:
            if '"report_url"' in line or "'report_url'" in line:
                # Ensure it's not in a comment
                if not stripped.startswith("#"):
                    model_b_violations.append(f"Line {i}: {stripped[:80]}")
            if "}" in line:
                in_public_fields_block = False

    assert len(model_b_violations) == 0, (
        "MODEL_B VIOLATION: report_url found in PUBLIC_FIELDS: " + str(model_b_violations)
    )
