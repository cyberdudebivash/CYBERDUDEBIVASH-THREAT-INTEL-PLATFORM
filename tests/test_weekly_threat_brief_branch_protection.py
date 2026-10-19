import pathlib
import re

import yaml


REPO_ROOT = pathlib.Path(__file__).resolve().parents[1]
WORKFLOW = REPO_ROOT / ".github" / "workflows" / "weekly-threat-brief.yml"


def _load_workflow():
    return yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))


def _run_bodies(doc):
    for job in (doc.get("jobs") or {}).values():
        for step in job.get("steps") or []:
            run = step.get("run")
            if run:
                yield run


def test_weekly_threat_brief_never_pushes_protected_main():
    doc = _load_workflow()
    body = "\n".join(_run_bodies(doc))
    assert not re.search(r"git\s+push\s+origin\s+(?:main|HEAD(?::main)?)\b", body)
    assert not re.search(r"git\s+push\s+[^\n]*\bmain\b", body)


def test_weekly_threat_brief_keeps_shared_writer_concurrency():
    doc = _load_workflow()
    concurrency = doc.get("concurrency") or {}
    assert concurrency.get("group") == "sentinel-data-writer"
    assert concurrency.get("cancel-in-progress") is False


def test_weekly_threat_brief_pages_action_is_commit_pinned():
    doc = _load_workflow()
    steps = (doc["jobs"]["generate-brief"].get("steps") or [])
    # Locate every Pages deploy step by the action it uses, not by a step title that drifts when steps are
    # renumbered (the title lookup made this test fail on main with StopIteration, silently skipping the pin check).
    deploys = [step for step in steps if str(step.get("uses", "")).startswith("JamesIves/github-pages-deploy-action@")]
    assert deploys, "weekly-threat-brief must contain a gh-pages deploy step"
    for deploy in deploys:
        ref = deploy["uses"].split("@", 1)[1].split()[0]
        assert re.fullmatch(r"[0-9a-f]{40}", ref), deploy.get("name")



def test_weekly_threat_brief_publishes_api_json_through_budgeted_r2_path():
    doc = _load_workflow()
    steps = doc["jobs"]["generate-brief"].get("steps") or []
    r2_step = next(
        step for step in steps
        if step.get("name") == "STEP 7 — Publish Weekly Brief API JSON to canonical R2"
    )
    assert r2_step.get("run") == "python3 scripts/r2_upload.py --weekly-brief-only"
    env = r2_step.get("env") or {}
    assert "CF_ACCOUNT_ID" in env
    assert "AWS_ACCESS_KEY_ID" in env
    assert "AWS_SECRET_ACCESS_KEY" in env


def test_weekly_threat_brief_has_hard_live_api_release_verification():
    doc = _load_workflow()
    steps = doc["jobs"]["generate-brief"].get("steps") or []
    verify = next(
        step for step in steps
        if step.get("name") == "STEP 9 — Verify live Weekly Brief API"
    )
    assert verify.get("run") == "python3 scripts/verify_weekly_brief_live.py"
    assert verify.get("continue-on-error") is not True


def test_weekly_brief_r2_publisher_is_single_key_budgeted_and_fail_closed():
    source = (REPO_ROOT / "scripts" / "r2_upload.py").read_text(encoding="utf-8")
    assert 'WEEKLY_BRIEF_FILES: list[tuple[str, str]]' in source
    assert (
        '("api/v1/intel/weekly_brief.json", "api/v1/intel/weekly_brief.json")'
        in source
    )
    assert 'label="r2_upload_weekly_brief"' in source
    assert "enforce_budget(plan, budgets, is_report_plan=False)" in source
    assert 'elif "--weekly-brief-only" in sys.argv:' in source
    assert "main_weekly_brief_only()" in source

    build_plan = source.split("def build_upload_plan()", 1)[1].split(
        "def main()", 1
    )[0]
    assert "WEEKLY_BRIEF_FILES" not in build_plan


def test_weekly_brief_downloads_authoritative_r2_before_generating_and_removes_old_artifacts():
    doc = _load_workflow()
    steps = doc["jobs"]["generate-brief"]["steps"]
    download = next(i for i, step in enumerate(steps)
                    if step.get("name") == "P0 — Download canonical weekly source from R2")
    generate = next(i for i, step in enumerate(steps)
                    if step.get("name") == "STEP 4 — Generate Weekly Threat Brief")
    publish = next(i for i, step in enumerate(steps)
                   if step.get("name") == "STEP 7 — Publish Weekly Brief API JSON to canonical R2")
    assert download < generate < publish
    assert "python3 scripts/weekly_brief_source.py" in steps[download]["run"]
    assert "rm -f weekly-brief.html api/v1/intel/weekly_brief.json" in steps[generate]["run"]
    for name in ("CF_ACCOUNT_ID", "AWS_ACCESS_KEY_ID", "AWS_SECRET_ACCESS_KEY"):
        assert name in steps[download]["env"]


def test_main_branch_weekly_html_must_be_live_r2_client_and_fail_closed():
    html = (REPO_ROOT / "weekly-brief.html").read_text(encoding="utf-8")
    assert 'data-weekly-brief-live="r2"' in html
    assert "fetch('/api/v1/intel/weekly_brief.json'" in html
    assert "brief.week !== window.label" in html
    assert "root.hidden = true" in html
    assert "Week 35 2026" not in html


def test_subscriber_notifications_wait_for_successful_customer_delivery():
    doc = _load_workflow()
    steps = doc["jobs"]["generate-brief"]["steps"]
    generate = next(i for i, s in enumerate(steps) if s.get("name") == "STEP 4 — Generate Weekly Threat Brief")
    verify = next(i for i, s in enumerate(steps) if s.get("name") == "STEP 9 — Verify live Weekly Brief API")
    notify = next(i for i, s in enumerate(steps) if s.get("name") == "STEP 9b — Notify subscribers after verified publication")
    assert generate < verify < notify
    assert "--send-telegram" not in steps[generate]["run"]
    assert steps[notify]["run"] == "python3 scripts/weekly_threat_brief.py --notify-verified"
    assert "schedule" in str(steps[notify].get("if"))
