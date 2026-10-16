"""F26 (2026-10-02): sentinel-apex.yml carries api/feed.baseline.json
between runs through R2, around STAGE 3.1.19 only.

The baseline was persisted only by STAGE 4's git push, refused since
2026-08-26, so every run read the 26 August copy back and the four
Enterprise/MSSP premium feeds built from it served August items. These tests
pin the replacement:
  * the explicit R2 download runs before the baseline engine;
  * the engine reports whether it wrote a new baseline;
  * the upload runs after the engine and before the tiered feed generator
    reads the baseline;
  * the upload is skipped unless the run started from R2's copy (or R2 had
    none yet) and the engine wrote a new baseline;
  * no broad state sweep moves the file.
"""
from __future__ import annotations

import sys
from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOW = REPO / ".github" / "workflows" / "sentinel-apex.yml"
DOWNLOAD = "python3 scripts/r2_state_sync.py --download --only api/feed.baseline.json"
UPLOAD = "python3 scripts/r2_state_sync.py --upload --only api/feed.baseline.json"


def _steps():
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    (job,) = workflow["jobs"].values()
    return job["steps"]


def _one(steps, predicate):
    hits = [i for i, step in enumerate(steps) if predicate(step)]
    assert len(hits) == 1, f"expected exactly one matching step, found {hits}"
    return hits[0]


def _runs(command):
    return lambda step: str(step.get("run", "")).strip() == command


def _named(prefix):
    return lambda step: str(step.get("name", "")).startswith(prefix)


def test_download_before_the_engine_and_upload_before_the_tier_generator():
    steps = _steps()
    download = _one(steps, _runs(DOWNLOAD))
    engine = _one(steps, _named("STAGE 3.1.19 - Premium Feed Baseline Engine"))
    upload = _one(steps, _runs(UPLOAD))
    tiers = _one(steps, _named("STAGE 3.1.20 - Tiered Product Feed Generator"))
    assert download < engine < upload < tiers


def test_upload_needs_a_successful_download_and_a_new_baseline():
    steps = _steps()
    download = steps[_one(steps, _runs(DOWNLOAD))]
    engine = steps[_one(steps, _named("STAGE 3.1.19 - Premium Feed Baseline Engine"))]
    upload = steps[_one(steps, _runs(UPLOAD))]
    assert download["id"] == "premium_baseline_state"
    assert engine["id"] == "premium_baseline"
    condition = upload["if"]
    assert "steps.premium_baseline_state.outcome == 'success'" in condition
    assert "steps.premium_baseline.outputs.updated == 'true'" in condition
    assert "always()" not in condition


def test_engine_reports_updated_only_when_it_wrote_a_new_baseline():
    steps = _steps()
    run = steps[_one(steps, _named("STAGE 3.1.19 - Premium Feed Baseline Engine"))]["run"]
    success_branch, separator, failure_branch = run.partition("\nelse\n")
    assert separator, "the engine step keeps its success / failure branches"
    assert 'if [ "$BASELINE_EXIT" -eq 0 ]' in success_branch
    assert 'echo "updated=true" >> "$GITHUB_OUTPUT"' in success_branch
    assert "updated=true" not in failure_branch


def test_both_state_steps_are_non_blocking_and_carry_r2_credentials():
    steps = _steps()
    for command in (DOWNLOAD, UPLOAD):
        step = steps[_one(steps, _runs(command))]
        assert step.get("continue-on-error") is True
        env = step["env"]
        for name, secret in (
            ("CF_ACCOUNT_ID", "secrets.CF_ACCOUNT_ID"),
            ("AWS_ACCESS_KEY_ID", "secrets.CF_R2_ACCESS_KEY_ID"),
            ("AWS_SECRET_ACCESS_KEY", "secrets.CF_R2_SECRET_ACCESS_KEY"),
        ):
            assert secret in env[name]


def test_no_broad_sweep_moves_the_baseline():
    sys.path.insert(0, str(REPO / "scripts"))
    import r2_state_sync as rs

    assert "api/feed.baseline.json" in rs.BROAD_SWEEP_EXCLUDED_PATHS
    assert dict(rs.STATE_FILES)["api/feed.baseline.json"] == "premium/state/feed.baseline.json"
