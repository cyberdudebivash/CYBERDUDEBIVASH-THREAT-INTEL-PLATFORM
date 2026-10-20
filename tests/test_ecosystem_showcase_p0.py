"""Commercial disclosure and independent placement on CTI tactical dossiers."""
from __future__ import annotations
import sys
from pathlib import Path
from html import unescape
from urllib.parse import urlparse
import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "scripts"))
from ecosystem_showcase import (  # noqa: E402
    OFFERINGS, ECOSYSTEM_CSS, relevant_offers, render_ecosystem_showcase,
)
import generate_intel_reports as gir  # noqa: E402


def fixture(**kwargs):
    return {
        "id": "intel--offline-ecosystem-showcase",
        "title": "Fictional defensive vulnerability bulletin",
        "description": "Fictional example; no customer impact is established.",
        "severity": "LOW",
        "risk_score": 2.0,
        "threat_type": "CVE_REPORT",
        "cve_id": "CVE-2026-11001",
        "tlp": "TLP:CLEAR",
        "source_url": "https://example.org/advisory",
        "timestamp": "2026-10-20T12:00:00Z",
        "iocs": [], "ttps": [],
        **kwargs,
    }


@pytest.mark.parametrize("category,expected", [
    ("AI security advisory", "ai"),
    ("RANSOMWARE incident", "intel"),
    ("CVE-2026-11001", "intel"),
    ("identity abuse", "trustx"),
    ("unspecified notice", "intel"),
])
def test_recommendation_is_contextual_and_only_from_approved_catalog(category, expected):
    recommendations = relevant_offers({"title": category})
    assert recommendations[0] == expected
    assert len(recommendations) == 3
    assert len(set(recommendations)) == 3
    assert all(key in OFFERINGS for key in recommendations)


def test_display_contains_all_real_catalog_links_and_private_preview_caveat():
    html = render_ecosystem_showcase(fixture())
    assert len(OFFERINGS) >= 9
    for name, label, _, url in OFFERINGS.values():
        assert urlparse(url).scheme == "https"
        assert name in unescape(html)
        assert url in html
    assert "Private preview" in html
    assert "contact@cyberdudebivash.in" in html
    assert "https://www.cyberdudebivash.com/ecosystem" in html
    assert "11 platforms &middot; 13 services &middot; 43 products &middot; 2 APIs" in html
    assert "Listings do not establish current availability" in html


def test_catalog_products_are_contextual_not_claims_of_available_inventory():
    ai = render_ecosystem_showcase(fixture(title="AI security agent advisory"))
    ransomware = render_ecosystem_showcase(fixture(title="Ransomware incident"))
    cve = render_ecosystem_showcase(fixture(title="CVE-2026-11001 vendor bulletin"))
    for name in ("AGENTGUARD PRO", "TrustGov AI™"):
        assert name in ai
    for name in ("Fortress Lockdown", "Ransomware IOC Blocker"):
        assert name in ransomware
    for name in ("QuickScan", "ReconX"):
        assert name in cve
    assert "Explore current listings" in ai
    assert "₹" not in ai and "$49" not in ai


def test_no_unverified_pricing_checkout_sla_or_audit_attestation():
    html = render_ecosystem_showcase(fixture())
    assert "Commercial disclosure:" in html
    assert "written permission" in html
    assert "separate from the threat intelligence findings" in html
    for unsupported in ("₹", "$49", "Guaranteed", "SOC 2 certified",
                        "999/month", "independently audited"):
        assert unsupported not in html
    assert "<script" not in html and "onclick=" not in html


def test_no_untrusted_item_description_is_embedded_in_ad_content():
    html = render_ecosystem_showcase(fixture(
        title="<img src=x onerror=alert(1)>", description="<script>alert(2)</script>"))
    assert "onerror" not in html
    assert "<img" not in html and "<script" not in html


def test_canonical_render_places_promotion_after_full_20_section_report():
    html = gir.render_report(fixture(), "https://intel.cyberdudebivash.com")
    assert html.count("data-cdb-owned-promotion='v1'") == 1
    assert html.count("id='cdb-ecosystem-promotion'") == 1
    assert html.index("data-cdb-owned-promotion='v1'") > html.index("Regulatory Compliance Impact")
    assert html.index("data-cdb-owned-promotion='v1'") > html.index("Detection Engineering Pack")
    assert html.index("data-cdb-owned-promotion='v1'") < html.index("</main>")
    assert "<style>" in html and ".cdb-eco-showcase" in html
    assert "https://example.org/advisory" in html


def test_print_and_accessibility_work_without_new_network_scripts():
    assert "@media print" in ECOSYSTEM_CSS
    assert "min-height:44px" in ECOSYSTEM_CSS
    assert "focus-visible" in ECOSYSTEM_CSS
    assert "prefers-reduced-motion" in ECOSYSTEM_CSS
    assert "@import" not in ECOSYSTEM_CSS
    html = render_ecosystem_showcase(fixture())
    assert "<details><summary>" in html
    assert "aria-label=" in html
    assert "target='_blank' rel='noopener noreferrer'" in html
