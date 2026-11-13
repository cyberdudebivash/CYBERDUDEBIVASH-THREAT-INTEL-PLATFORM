"""SENTINEL APEX commercial dossier: evidence-first executive/IOC display tests.

No network, Cloudflare, customer scans, payment or R2 writes. Every fixture
is deliberately hypothetical and must not be published as actual intelligence.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
for directory in (ROOT, ROOT / "scripts"):
    if str(directory) not in sys.path:
        sys.path.insert(0, str(directory))

import generate_intel_reports as gir  # noqa: E402
from agent.apex_intelligence_upgrade import generate_ai_insight_premium  # noqa: E402


def advisory(**overrides):
    base = {
        "id": "intel--offline-commercial-truth",
        "title": "Example advisory used for isolated quality tests",
        "description": "Hypothetical advisory, not a confirmed customer incident.",
        "severity": "LOW", "risk_score": 3.0,
        "threat_type": "threat-intel", "timestamp": "2026-10-19T16:00:00Z",
        "source_url": "https://example.org/advisory",
        "tlp": "TLP:CLEAR", "iocs": [], "ttps": [], "ioc_confidence": None,
    }
    return {**base, **overrides}


@pytest.mark.parametrize("raw", [None, "", "bogus", "NaN", float("inf"), -1, 101, True, False])
def test_missing_or_invalid_ioc_score_never_defaults_to_high(raw):
    assert gir._visible_ioc_signal_score({"ioc_confidence": raw}, 1) is None


def test_unvalidated_iocs_never_generate_an_assigned_confidence():
    assert gir._visible_ioc_signal_score({"ioc_confidence": 97}, 0) is None


def test_valid_evidence_bound_ioc_score_keeps_its_original_value():
    assert gir._visible_ioc_signal_score({"ioc_confidence": 0}, 1) == 0
    assert gir._visible_ioc_signal_score({"ioc_confidence": "42.5"}, 2) == 42.5


def test_public_ciso_executive_handoff_is_evidence_bound():
    html = gir.render_report(advisory(), "https://intel.cyberdudebivash.com")
    assert "SOURCE &amp; EVIDENCE" in html
    assert "SOC FIRST 30 MIN" in html
    assert "No independent customer-specific compromise" in html
    assert "0-10m: check whether the threat applies" in html
    assert "Recorded IOC signal score" in html
    assert "Not assessed" in html
    assert "No validated IOC confidence evidence available" in html
    assert "Source Reliability: Verified" not in html
    assert "12 months of threat intelligence" not in html


def test_cve_soc_handoff_uses_asset_exposure_not_generic_phishing_actions():
    item = advisory(
        title="Hypothetical CVE-2026-10000 vendor patch notice",
        cve_id="CVE-2026-10000", cvss_score=7.5, risk_score=7.5,
        severity="HIGH",
    )
    html = gir.build_report_sections(item)
    assert "0-10m: match the CVE/vendor advisory" in html
    assert "no customer-environment exposure" not in html or "CUSTOMER EXPOSURE: UNKNOWN" in html


def test_fallback_ai_section_never_invents_global_telemetry(monkeypatch):
    monkeypatch.setattr(gir, "_APEX_UPGRADE_AVAILABLE", False)
    html = gir.build_report_sections(advisory(ioc_confidence=75))
    assert "no validated IOC score" in html
    assert "Recorded IOC signal score" in html
    assert "12 months of threat intelligence" not in html
    assert "global telemetry" not in html


def test_active_analyst_summary_labels_metadata_heuristics_not_model_evidence():
    html = generate_ai_insight_premium(advisory())
    assert "Heuristic signal index" in html, html[:250]
    assert "No evidenced TTP chain available" in html
    assert "No customer-environment exposure" in html
    for claim in ("APEX ML corpus v16", "correlated against 12 months",
                  "Model confidence:", "Multi-stage adversary kill chain"):
        assert claim not in html
    assert "not a probability or calibrated confidence" in html


def test_dossier_source_reference_is_html_escaped():
    html = gir.build_report_sections(advisory(source_url='https://example.org/?q=<script>alert(1)</script>'))
    assert "<script>alert(1)</script>" not in html
    assert "&lt;script&gt;" in html



@pytest.mark.parametrize("raw_tag", [
    None, "", "UNATTRIBUTED", "UNC-UNKNOWN", "CDB-UNATTR-CVE",
    "UNC-CDB-INGEST", "Vulnerability Exploitation Cluster",
    "Unknown Threat Actor", "Unattributed APT Cluster",
])
def test_generic_category_is_not_paid_actor_attribution(raw_tag):
    # The live dossier previously falsely called a generic category 'ATTRIBUTED'.
    assert gir._is_real_attribution(raw_tag) is False


def test_public_dossier_does_not_claim_generic_actor_or_bogus_paid_endpoint():
    item = advisory(
        title="Synthetic CVE-2026-10000 generic vendor vulnerability",
        actor_tag="Vulnerability Exploitation Cluster",
        severity="HIGH", cvss_score=7.8, cve_id="CVE-2026-10000",
    )
    html = gir.build_report_sections(item)
    assert "NO THREAT ACTOR ATTRIBUTED" in html
    assert "ATTRIBUTED — ENTERPRISE ACCESS REQUIRED" not in html
    assert "Vulnerability Exploitation Cluster" not in html
    assert "/api/actor/UNATTRIBUTED" not in html
    assert item["actor_tag"] == "Vulnerability Exploitation Cluster", "source must be immutable"


def test_real_actor_name_is_still_masked_without_fabricating_endpoint():
    assert gir._is_real_attribution("APT29") is True
    item = advisory(
        title="Hypothetical CVE-2026-10000 vendor advisory",
        actor_tag="APT29", cvss_score=7.8, cve_id="CVE-2026-10000",
    )
    html = gir.build_report_sections(item)
    assert "ATTRIBUTED — ENTERPRISE ACCESS REQUIRED" in html
    assert "APT29" not in html, "public report must never disclose gated actor name"
    assert "Vulnerability Exploitation Cluster" not in html
    assert "/api/actor/UNATTRIBUTED" not in html
    assert "requires authenticated Enterprise actor-intelligence access" in html


def test_authoritative_cvss_severity_is_used_by_second_executive_summary():
    item = advisory(
        title="Hypothetical CVE-2026-10000 vendor vulnerability",
        severity="MEDIUM", cvss_score=7.8, cve_id="CVE-2026-10000",
    )
    html = gir.build_report_sections(item)
    section2 = html.split("id='s2'", 1)[1].split("id='s3'", 1)[0]
    assert "HIGH" in section2
    assert "MEDIUM-severity security advisory" not in section2
    assert "MEDIUM severity" not in section2
    assert item["severity"] == "MEDIUM", "never mutate producer source to fix HTML"
