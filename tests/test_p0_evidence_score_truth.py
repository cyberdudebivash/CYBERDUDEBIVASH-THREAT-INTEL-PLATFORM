"""P0 truth regression: no fabricated KEV/EPSS evidence and no fail-open enforcer.

Synthetic fixtures only; no network, provider, secrets or production mutation.
"""
import copy
from pathlib import Path

from scripts import evidence_score_enforcer as enforcer

ROOT = Path(__file__).resolve().parents[1]


def test_explicit_no_is_not_kev_or_exploit_confirmation():
    row = {
        "id": "intel--synthetic-only", "title": "Unverified example",
        "risk_score": 9.4, "kev": "NO", "kev_present": False,
        "exploit_available": "NO", "has_exploit": "FALSE",
    }
    untouched = copy.deepcopy(row)
    corrected, adjustments = enforcer.enforce_feed([row])
    assert row == untouched
    assert len(corrected) == 1
    assert corrected[0]["risk_score"] == 5.5
    assert corrected[0]["_original_risk_score"] == 9.4
    assert len(adjustments) == 1
    assert adjustments[0]["kev"] is False
    assert adjustments[0]["exploit"] is False
    assert adjustments[0]["evidence_tier"] == "TIER0_NONE"


def test_small_fractional_epss_is_not_multiplied_twice():
    # Source 0.009 means 0.9 percent, not 90 percent. The backfill
    # converts once, the tier policy must treat the resulting 0.9 as percent.
    original = {"title": "EPSS below one percent", "risk_score": 9.2,
                "epss_score": 0.009, "kev": "NO", "exploit_available": "NO"}
    corrected, adjustments = enforcer.enforce_feed([original])
    assert original["epss_score"] == 0.009
    assert corrected[0]["epss_score"] == 0.9
    assert corrected[0]["risk_score"] == 6.5
    assert adjustments[0]["epss"] == 0.9
    assert adjustments[0]["evidence_tier"] == "TIER1_MINIMAL"


def test_true_kev_and_captured_exploitation_evidence_remains_high():
    confirmed = {"risk_score": 10.0, "kev": "YES",
                 "exploit_available": True, "epss_score": 0.8}
    corrected, adjustments = enforcer.enforce_feed([confirmed])
    assert corrected[0]["risk_score"] == 10.0
    assert corrected[0]["epss_score"] == 80.0
    assert adjustments == []


def test_boolean_evidence_is_explicit_not_python_truthiness():
    for value in ("NO", "FALSE", "0", "None", "", None, 0, False, [], {}):
        assert enforcer._affirmative_flag(value) is False
    for value in ("YES", "TRUE", "CONFIRMED", "1", 1, True):
        assert enforcer._affirmative_flag(value) is True


def test_publisher_evidence_enforcement_cannot_silently_succeed():
    workflow = (ROOT / ".github/workflows/sentinel-apex.yml").read_text(encoding="utf-8")
    name = 'STAGE 3.1.4b - Evidence Score Enforcer'
    start = workflow.index(name)
    body = workflow[start:start + 460]
    assert "python3 scripts/evidence_score_enforcer.py" in body
    assert "evidence_score_enforcer.py || true" not in body
    assert "continue-on-error: true" not in body


def test_missing_feed_is_hard_failure_without_modification(tmp_path, monkeypatch):
    missing = tmp_path / "missing-feed.json"
    monkeypatch.setattr(enforcer, "FEED_PATH", missing)
    assert enforcer.main() == 1
    assert not missing.exists()
