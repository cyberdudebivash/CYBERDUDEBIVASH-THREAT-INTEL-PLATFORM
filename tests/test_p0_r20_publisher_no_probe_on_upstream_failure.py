"""P0 R20: publisher must fail closed before live convergence on upstream failure."""
from __future__ import annotations

import json
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "scripts"))
from p0_r20_convergence_preflight import build_blocked_verdict, write_verdict

WORKFLOW = ROOT / ".github" / "workflows" / "sentinel-apex.yml"


@pytest.mark.parametrize("outcomes", [
    ("failure", "success", "success"),
    ("success", "failure", "success"),
    ("success", "success", "failure"),
    ("success", "success", "skipped"),
    ("skipped", "success", "success"),
    ("success", "", "success"),
    ("success", "cancelled", "success"),
])
def test_upstream_failure_never_certifies_or_consumes_requests(outcomes):
    verdict = build_blocked_verdict(*outcomes)
    assert verdict["classification"] == "UPSTREAM_BLOCKED"
    assert verdict["confidence_score"] == 0
    assert verdict["convergence_achieved"] is False
    assert verdict["release_go"] is False
    assert verdict["network_probes_attempted"] == 0
    assert verdict["verification_performed"] is False
    assert len(verdict["mandatory_stage_outcomes"]) == 3


def test_all_success_must_not_write_fictitious_hold():
    with pytest.raises(ValueError):
        build_blocked_verdict("success", "success", "success")


def test_atomic_diagnostic_output_is_safe_and_parseable(tmp_path):
    path = tmp_path / "evidence" / "deployment_confidence_score.json"
    verdict = build_blocked_verdict("success", "failure", "failure")
    write_verdict(path, verdict)
    assert json.loads(path.read_text(encoding="utf-8")) == verdict
    assert len(list(path.parent.iterdir())) == 1
    assert "secrets" not in path.read_text(encoding="utf-8").lower()


def _steps():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["generate-and-sync"]
    return {step["name"]: step for step in job["steps"] if "name" in step}


def test_release_workflow_ids_cover_mandatory_source_checks():
    steps = _steps()
    apex = steps["STAGE 3.1 - APEX AI Feed Enrichment (inject apex_ai into all items)"]
    regression = steps["STAGE 5.6 - Regression Test Suite"]
    assert apex["id"] == "p0_apex_enrichment"
    assert regression["id"] == "p0_regression_suite"
    assert not apex.get("continue-on-error", False)
    assert not regression.get("continue-on-error", False)


def test_convergence_uses_outcomes_and_short_circuits_network():
    steps = _steps()
    convergence = steps["STAGE 5.8.1c - Deployment Convergence Engine (v184.0 Enterprise Grade)"]
    body = convergence["run"]
    assert "steps.pipeline_stage_1_3.outcome" in convergence["env"]["UPSTREAM_PIPELINE_OUTCOME"]
    assert "steps.p0_apex_enrichment.outcome" in convergence["env"]["UPSTREAM_APEX_OUTCOME"]
    assert "steps.p0_regression_suite.outcome" in convergence["env"]["UPSTREAM_REGRESSION_OUTCOME"]
    assert 'if [ "$UPSTREAM_PIPELINE_OUTCOME" != \'success\' ]' in body
    assert 'if [ "$UPSTREAM_PIPELINE_OUTCOME" != \'success\' ]' in body[:body.index("timeout 1680")]
    assert "scripts/p0_r20_convergence_preflight.py" in body
    assert 'exit 1' in body[:body.index("timeout 1680")]
    assert "CONVERGENCE_EXIT_CODE=1" in body
    assert "timeout 1680 python3 scripts/deployment_convergence_validator.py" in body
    assert convergence["timeout-minutes"] == 30
    assert not convergence.get("continue-on-error", False)


def test_guard_runs_on_failed_steps_and_never_on_cancelled_job():
    convergence = _steps()["STAGE 5.8.1c - Deployment Convergence Engine (v184.0 Enterprise Grade)"]
    assert "!cancelled()" in convergence["if"]


def test_final_authoritative_r2_upload_is_forbidden_after_any_mandatory_failure():
    steps = _steps()
    upload = steps["Upload Intel State to R2 (post-manifest-repair, final)"]
    condition = upload["if"]
    assert "!cancelled()" in condition
    assert "PIPELINE_LOCKED != 'true'" in condition
    assert "steps.pipeline_stage_1_3.outcome == 'success'" in condition
    assert "steps.p0_apex_enrichment.outcome == 'success'" in condition
    assert "steps.p0_regression_suite.outcome == 'success'" in condition
    assert "r2_state_sync.py --upload" in upload["run"]
    # Nonfatal upload transport errors stay nonfatal, but unauthorized state
    # *must not* pass the precondition that enables the production PUT.



def test_intermediate_r2_manifest_resync_requires_apex_quality_success():
    steps = _steps()
    resync = steps["STAGE 4.1 - Final R2 Full Sync (v184.0 -- post-git-push complete feed)"]
    condition = resync["if"]
    assert "!cancelled()" in condition
    assert "steps.r2-manifest-integrity.outcome == 'success'" in condition
    assert "steps.pipeline_stage_1_3.outcome == 'success'" in condition
    assert "steps.p0_apex_enrichment.outcome == 'success'" in condition
    assert "r2_resync_manifests.py" in resync["run"]


def test_pre_regression_r2_state_sync_requires_apex_quality_success():
    steps = _steps()
    write = steps["Upload Intel State to R2 (final, post-enrichment)"]
    condition = write["if"]
    assert "!cancelled()" in condition
    assert "steps.pipeline_stage_1_3.outcome == 'success'" in condition
    assert "steps.r2-manifest-integrity.outcome == 'success'" in condition
    assert "steps.p0_apex_enrichment.outcome == 'success'" in condition
    assert "PIPELINE_LOCKED != 'true'" in condition
    assert "r2_state_sync.py --upload" in write["run"]
