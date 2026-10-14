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
