"""Offline regression: a high confidence score must not override failed release gates."""

import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))
import global_release_orchestrator as gro  # noqa: E402


@pytest.fixture(autouse=True)
def isolated_governance(monkeypatch, tmp_path):
    monkeypatch.setattr(gro, "BASE_DIR", tmp_path)
    monkeypatch.setattr(gro, "RESULTS", [])
    monkeypatch.setattr(gro, "HARD_FAIL_COUNT", 0)
    monkeypatch.setattr(gro, "WARN_COUNT", 0)
    monkeypatch.setattr(gro, "PASS_COUNT", 0)


def evidence(**changes):
    payload = {
        "confidence_score": 100,
        "classification": "DEPLOYMENT_STABLE",
        "exit_code": 0,
        "convergence_achieved": True,
        "generated_at": "2026-11-02T19:16:56Z",
        "phases": [{"phase": n, "success": True} for n in range(1, 6)],
    }
    payload.update(changes)
    return payload


def inspect(tmp_path, payload):
    (tmp_path / "deployment_confidence_score.json").write_text(
        json.dumps(payload), encoding="utf-8"
    )
    gro.check_deployment_convergence({})
    return {(item["check"], item["status"]) for item in gro.RESULTS}


def test_failed_historical_phase_blocks_even_with_score_90_and_cdn_true(tmp_path):
    payload = evidence(
        confidence_score=90,
        classification="DEPLOYMENT_FAILED",
        exit_code=1,
        phases=[{"phase": n, "success": n != 5} for n in range(1, 6)],
    )
    checks = inspect(tmp_path, payload)
    assert ("release_authorization", "HARD_FAIL") in checks
    assert ("deployment_stable", "PASS") not in checks
    assert gro.HARD_FAIL_COUNT == 1


def test_false_stable_metadata_cannot_mask_failed_phase(tmp_path):
    payload = evidence(
        confidence_score=90,
        phases=[{"phase": n, "success": n != 5} for n in range(1, 6)],
    )
    assert ("release_authorization", "HARD_FAIL") in inspect(tmp_path, payload)


@pytest.mark.parametrize("changes", [
    {"classification": None},
    {"exit_code": None},
    {"exit_code": 1},
    {"convergence_achieved": False},
    {"phases": []},
    {"phases": [{"phase": n, "success": True} for n in range(1, 5)]},
    {"confidence_score": "100"},
    {"confidence_score": True},
    {"confidence_score": 70},
])
def test_incomplete_or_invalid_release_evidence_blocks(tmp_path, changes):
    assert ("release_authorization", "HARD_FAIL") in inspect(
        tmp_path, evidence(**changes)
    )


def test_duplicate_mandatory_phase_blocks(tmp_path):
    payload = evidence(phases=[
        {"phase": n, "success": True} for n in range(1, 6)
    ] + [{"phase": 5, "success": True}])
    assert ("release_authorization", "HARD_FAIL") in inspect(tmp_path, payload)


def test_genuine_stable_release_passes(tmp_path):
    checks = inspect(tmp_path, evidence())
    assert ("release_authorization", "PASS") in checks
    assert ("deployment_stable", "PASS") in checks
    assert gro.HARD_FAIL_COUNT == 0


def test_stable_85_score_warns_but_does_not_block(tmp_path):
    checks = inspect(tmp_path, evidence(confidence_score=85))
    assert ("release_authorization", "PASS") in checks
    assert ("deployment_stable", "WARN") in checks
    assert gro.HARD_FAIL_COUNT == 0
