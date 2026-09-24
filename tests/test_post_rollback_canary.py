"""
Post-rollback canary (enterprise-rollback-governance.yml -> scripts/post_rollback_canary.py).

Regression: the canary probed https://intel.cyberdudebivash.com/api/v1/health,
a route the deployed gateway never served (legacy FastAPI only). It 404'd on
every run, capping the canary at 3/4 = 75% < 80%, so every post-rollback
canary failed however good the rollback was. It now checks the canonical
/api/health contract through scripts/deployment_health_contract.py.
"""
from __future__ import annotations

import re
import sys
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tests"))

import post_rollback_canary as prc  # noqa: E402
from test_deployment_health_contract import (  # noqa: E402
    HEALTH_FRESH, HEALTH_STALE, HEALTH_UNAVAILABLE, LIVE_OK,
)

WF = REPO / ".github" / "workflows" / "enterprise-rollback-governance.yml"
HTML_502 = (502, None, "invalid JSON: Expecting value")
LIVE_404 = (404, None, "invalid JSON")


def test_workflow_runs_the_script_and_no_longer_probes_api_v1_health():
    src = WF.read_text(encoding="utf-8")
    assert "python3 scripts/post_rollback_canary.py" in src
    assert not re.search(r"https://intel\.cyberdudebivash\.com/api/v1/health\b", src)
    assert "api/v1/health" not in (REPO / "scripts" / "post_rollback_canary.py").read_text().split('"""')[2]


def test_gateway_does_not_route_bare_api_v1_health():
    # Precondition for dropping the probe: no route to target (only /enterprise).
    src = (REPO / "workers" / "intel-gateway" / "src" / "index.js").read_text(encoding="utf-8")
    assert not re.search(r'path === "/api/v1/health"', src)


@pytest.mark.parametrize("health", [HEALTH_FRESH, HEALTH_STALE, HEALTH_UNAVAILABLE],
                         ids=["fresh-200", "stale-503", "unavailable-503"])
def test_good_rollback_passes_in_every_valid_intelligence_state(health):
    # A rollback restores Worker code; it cannot make a stale feed fresh.
    r = prc.evaluate(LIVE_OK, health, 200, 200)
    assert r["passed"] == 4 and r["canary_pass"], r["probes"]


def test_malformed_health_body_is_a_failed_probe():
    r = prc.evaluate(LIVE_OK, HTML_502, 200, 200)
    assert r["passed"] == 3
    assert not r["canary_pass"], "3/4 must stay below the unchanged 80% threshold"


def test_dead_worker_fails_the_canary():
    r = prc.evaluate(LIVE_404, HTML_502, 200, 200)
    assert r["passed"] == 2 and not r["canary_pass"]


def test_feed_or_dashboard_down_fails_the_canary():
    assert not prc.evaluate(LIVE_OK, HEALTH_STALE, 200, 500)["canary_pass"]
    assert not prc.evaluate(LIVE_OK, HEALTH_STALE, None, 200)["canary_pass"]


def test_negative_control_old_probe_set_could_never_pass():
    # Old behaviour: the 4th probe was a guaranteed 404, so 3 is the ceiling.
    ceiling = 3
    assert ceiling < 4 * prc.PASS_RATIO
