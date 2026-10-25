"""Offline guard against unsupported certification and fabricated static archive counts."""
from pathlib import Path

HTML = (Path(__file__).resolve().parents[1] / "index.html").read_text(encoding="utf-8")


def test_no_unverified_stix_certification():
    assert "STIX 2.1 CERTIFIED" not in HTML
    assert "STIX 2.1 EXPORT FORMAT" in HTML


def test_no_unsupported_third_party_endorsement():
    assert "CISA ALIGNED" not in HTML
    assert "CISA KEV REFERENCES" in HTML


def test_attack_reference_not_claimed_as_validated_mapping():
    assert "✔ MITRE ATT&amp;CK MAPPED" not in HTML
    assert "MITRE ATT&amp;CK REFERENCES" in HTML


def test_no_hardcoded_report_inventory_as_live():
    assert "22,433 published intelligence reports" not in HTML
    assert "2,144 CVE &amp; threat pages" not in HTML
    assert "Report inventory: publication-gated" in HTML
    assert "Counts shown after live validation" in HTML


def test_no_unverified_publication_cadence():
    assert "●</span>Updated weekly" not in HTML
    assert "Publication cadence varies" in HTML
