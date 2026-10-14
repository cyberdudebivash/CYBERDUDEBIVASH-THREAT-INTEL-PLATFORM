"""P0 public score truth after the final writer, preserving immutable evidence."""
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))

from p0_r44_publication_boundary import enforce_public_risk_truth


def row(**kw):
    return {"id": "intel--example", "title": "Public source report",
            "tlp": "TLP:CLEAR", "source": "Synthetic verified fixture",
            "risk_score": 9.0, "severity": "CRITICAL", **kw}


def test_unverified_risk_nine_capped_not_fabricated():
    original = row()
    out, count = enforce_public_risk_truth([original])
    assert count == 1
    assert out[0]["risk_score"] == 5.5
    assert out[0]["severity"] == "HIGH"
    assert original["risk_score"] == 9.0
    assert "_original_risk_score" not in out[0]
    assert not out[0].get("kev_present")


def test_verified_critical_score_kept_and_fake_kev_no_is_not_evidence():
    trustworthy = row(kev_present=True)
    fake = row(kev="NO", kev_present=False)
    out, count = enforce_public_risk_truth([trustworthy, fake])
    assert count == 1
    assert out[0]["risk_score"] == 9.0 and out[0]["severity"] == "CRITICAL"
    assert out[1]["risk_score"] < 9.0
    assert fake["kev"] == "NO"


def test_numeric_cvss_high_without_exploitation_caps_under_nine():
    out, count = enforce_public_risk_truth([row(cvss_score=9.8)])
    assert count == 1
    assert out[0]["risk_score"] == 8.5
    assert out[0]["cvss_score"] == 9.8


def test_low_risk_original_and_zero_new_claims():
    item = row()
    item.update(risk_score=6.0, severity="MEDIUM")
    out, count = enforce_public_risk_truth([item])
    assert count == 0 and out == [item]
    assert item == out[0]


def test_verified_sub_one_percent_epss_is_not_inflated_to_ninety_percent():
    item = row(exploit_available=True, epss_source="FIRST.org",
               epss_pct=0.9, epss_score=0.9, epss="0.9%")
    out, count = enforce_public_risk_truth([item])
    assert count == 1
    assert out[0]["risk_score"] == 6.5
    assert out[0]["epss_score"] == 0.9
    assert out[0]["epss"] == "0.9%"
    assert item["risk_score"] == 9.0


def test_ambiguous_epss_must_not_unlock_critical_public_risk():
    item = row(exploit_available=True, epss_score=0.9)
    out, count = enforce_public_risk_truth([item])
    assert count == 1
    assert out[0]["risk_score"] == 5.5
    assert out[0]["epss_score"] == 0.9
    assert item["risk_score"] == 9.0


def test_verified_high_epss_with_exploit_evidence_can_keep_critical_risk():
    item = row(exploit_available=True, epss_source="FIRST.org",
               epss_pct=30.0, epss_score=30.0, epss="30%")
    out, count = enforce_public_risk_truth([item])
    assert count == 0
    assert out[0]["risk_score"] == 9.0


def test_unverified_percent_string_mismatch_cannot_authorize_critical_risk():
    item = row(exploit_available=True, epss="90%", epss_score=0.9)
    out, count = enforce_public_risk_truth([item])
    assert count == 1
    assert out[0]["risk_score"] == 5.5
    assert out[0]["epss_score"] == 0.9
