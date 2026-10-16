"""
Regression test for issue #278: STAGE 3.1.22b (sentinel-apex.yml) must
actually notify a human when generate_ai_tracker.py fails to produce
api/ai/health.json and api/ai/executive-brief.json, not just leave a
::warning:: visible only to someone reading Actions logs.

Explicit decision (owner sign-off): keep this non-blocking (warn + retain
prior data), but promote the warning to a real alert via the existing
pipeline_alert.py (reused, not reimplemented -- same script already wired
for pipeline-staleness-monitor.yml and elsewhere).

Run with: pytest tests/test_ai_output_alerting.py -v
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parent.parent
SENTINEL_BLOGGER_YML = REPO_ROOT / ".github" / "workflows" / "sentinel-apex.yml"
PIPELINE_ALERT_PY = REPO_ROOT / "scripts" / "pipeline_alert.py"


@pytest.fixture(scope="module")
def workflow_text() -> str:
    assert SENTINEL_BLOGGER_YML.exists()
    return SENTINEL_BLOGGER_YML.read_text(encoding="utf-8")


def test_sentinel_blogger_yml_is_valid_yaml(workflow_text: str):
    yaml.safe_load(workflow_text)


def test_stage_3_1_22b_calls_pipeline_alert_on_missing_output(workflow_text: str):
    match = re.search(
        r'name: "STAGE 3\.1\.22b.*?\n(.*?)\n\s*- name:',
        workflow_text, re.DOTALL,
    )
    assert match, "could not locate STAGE 3.1.22b step in sentinel-apex.yml"
    step_body = match.group(1)
    assert "scripts/pipeline_alert.py" in step_body, (
        "STAGE 3.1.22b must alert via pipeline_alert.py when health.json/"
        "executive-brief.json aren't produced -- a ::warning:: alone isn't "
        "visible outside someone reading Actions logs"
    )
    assert "--status warning" in step_body
    # Still non-blocking: the alert call itself must never fail the step
    alert_line = next(l for l in step_body.splitlines() if "pipeline_alert.py" in l)
    alert_call = "\n".join(
        step_body.splitlines()[step_body.splitlines().index(alert_line):step_body.splitlines().index(alert_line) + 3]
    )
    assert "|| true" in alert_call, "the alert call must not be able to fail this non-blocking step"


def test_pipeline_alert_warning_mode_never_blocks_without_telegram_secrets():
    """pipeline_alert.py must exit 0 even with no Telegram credentials
    configured -- this is what makes it safe to call from a non-blocking
    CI step."""
    result = subprocess.run(
        [sys.executable, str(PIPELINE_ALERT_PY), "--status", "warning", "--message", "test"],
        capture_output=True, text=True, timeout=15,
        env={"PATH": "/usr/bin:/bin"},  # deliberately no TELEGRAM_* vars
    )
    assert result.returncode == 0
