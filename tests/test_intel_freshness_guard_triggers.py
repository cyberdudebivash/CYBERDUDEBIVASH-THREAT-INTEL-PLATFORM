"""F3 (2026-10-02): the freshness guard also runs when frequent workflows complete.

GitHub delivered about 4 of the guard cron's 48 daily slots, so a 4h-old feed
usually reached the 6h breach before the guard looked. intel-freshness-guard.yml
therefore also listens for `workflow_run` completions of the workflows pinned
below. A `workflow_run` trigger names workflows by display name. A name that
no longer matches (a version bump, a rename) silently never fires: F4 found
four such chains. These tests turn that drift into a failure.
"""
from __future__ import annotations

from pathlib import Path

import yaml

REPO = Path(__file__).resolve().parents[1]
WORKFLOWS = REPO / ".github" / "workflows"
GUARD = WORKFLOWS / "intel-freshness-guard.yml"

# Chosen by replaying 09-28..10-02 run history: each is delivered about 3-5
# times a day at different times, and none is itself chained or PR-triggered.
# Changing this set is a reviewed decision (run rate and coverage), not drift.
EXPECTED_TRIGGER_FILES = {
    "enterprise-governance.yml",
    "enterprise-alerts.yml",
    "pipeline-staleness-monitor.yml",
    "self-healing.yml",
    "status-monitor.yml",
    "dashboard-feeds-sync.yml",
    "enterprise-intel-quality.yml",
    "production-hardening-final.yml",
    "multi-source-intel.yml",
    "ui-file-guardian.yml",
    "precognition-engine.yml",
    "generate-and-sync.yml",
    "sla-heartbeat.yml",
}


def _load(path: Path) -> dict:
    return yaml.safe_load(path.read_text(encoding="utf-8")) or {}


def _on(doc: dict) -> dict:
    on = doc.get(True, doc.get("on"))  # PyYAML parses a bare `on:` as True
    assert isinstance(on, dict), on
    return on


def _workflow_files_by_name() -> dict:
    by_name: dict = {}
    for path in sorted(WORKFLOWS.glob("*.yml")):
        name = _load(path).get("name")
        if name:
            by_name.setdefault(name, []).append(path.name)
    return by_name


def _unresolved(references, by_name) -> list:
    """References that do not name exactly one workflow in this repository."""
    return [ref for ref in references if len(by_name.get(ref, [])) != 1]


def _guard_trigger() -> dict:
    return _on(_load(GUARD))["workflow_run"]


def test_cron_and_manual_dispatch_are_kept():
    on = _on(_load(GUARD))
    assert on["schedule"] == [{"cron": "7,37 * * * *"}]
    assert "workflow_dispatch" in on


def test_runs_only_after_completed_runs_on_main():
    trigger = _guard_trigger()
    assert trigger["types"] == ["completed"]
    assert trigger["branches"] == ["main"]


def test_every_referenced_name_is_exactly_one_existing_workflow():
    names = _guard_trigger()["workflows"]
    assert names, "no workflow_run references"
    assert len(names) == len(set(names)), "duplicate reference"
    assert _unresolved(names, _workflow_files_by_name()) == []


def test_the_name_check_catches_names_that_no_longer_exist():
    # Negative control: F4's broken references, and a version-bumped name.
    by_name = _workflow_files_by_name()
    stale = ["deploy-worker", "CDB GENESIS Intelligence Powerhouse v184.0", "SLA Heartbeat v202.0"]
    assert _unresolved(stale, by_name) == stale


def test_the_trigger_set_is_the_reviewed_one():
    by_name = _workflow_files_by_name()
    files = {by_name[n][0] for n in _guard_trigger()["workflows"]}
    assert files == EXPECTED_TRIGGER_FILES


def test_neither_the_publisher_nor_the_guard_triggers_it():
    by_name = _workflow_files_by_name()
    files = {by_name[n][0] for n in _guard_trigger()["workflows"]}
    assert "sentinel-apex.yml" not in files
    assert GUARD.name not in files


def test_triggering_workflows_are_not_pr_triggered_or_chained():
    # No pull_request: a fork cannot start them. No workflow_run: the guard
    # stays one level deep, far inside GitHub's three-level chain limit.
    by_name = _workflow_files_by_name()
    for name in _guard_trigger()["workflows"]:
        on = _on(_load(WORKFLOWS / by_name[name][0]))
        for event in ("pull_request", "pull_request_target", "workflow_run"):
            assert event not in on, (name, event)
        assert "schedule" in on, name


def test_job_ignores_runs_from_other_repositories():
    job = _load(GUARD)["jobs"]["guard"]
    assert job["if"] == (
        "github.event_name != 'workflow_run' || "
        "github.event.workflow_run.head_repository.full_name == github.repository"
    )


def test_no_triggering_run_data_reaches_a_step():
    # Script-injection guard: branch names and titles of the triggering run
    # are attacker-influenced in general; the guard needs none of them.
    for step in _load(GUARD)["jobs"]["guard"]["steps"]:
        text = yaml.safe_dump(step)
        assert "github.event" not in text, step


def test_permissions_unchanged():
    assert _load(GUARD)["permissions"] == {"actions": "write", "contents": "read"}
