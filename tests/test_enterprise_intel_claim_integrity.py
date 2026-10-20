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
    strip = html.split("<div class='confidence-strip'>", 1)[1].split("</div>", 1)[0]
    assert "Not assessed" not in strip  # label is in nested row, see full section
    assert "No validated IOC confidence evidence available" in html
    assert "Source Reliability: Verified" not in strip
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

