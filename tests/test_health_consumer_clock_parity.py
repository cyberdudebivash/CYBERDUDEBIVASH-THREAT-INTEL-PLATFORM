"""
Freshness boundary x every health consumer, on a PINNED clock.

Regression (2026-09-24): deployment_canary.canary_a_health() and
post_rollback_canary.evaluate() evaluated a fixture that is fresh relative to
its own clock (NOW - 10 min) against the REAL wall clock. Once the calendar
passed NOW + 6h the canonical classifier correctly said STALE and the
Intel Gateway release gate went red, although nothing in production had
changed. Both now take an injectable `now` (production callers omit it).

This suite:
  * runs one boundary matrix through the four consumers of the canonical
    freshness contract (deployment health contract, deployment canary A,
    post-rollback canary, public freshness gate) and requires them to agree;
  * pins the six-hour contract itself (config/public_freshness_contract.json)
    so the boundary cannot be widened to make a test green;
  * moves the wall clock years ahead and requires every pinned evaluation to
    be unchanged -- the direct regression test for the clock bug.
"""
from __future__ import annotations

import json
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
sys.path.insert(0, str(REPO / "tests"))

import deployment_canary as dc  # noqa: E402
import deployment_health_contract as dhc  # noqa: E402
import post_rollback_canary as prc  # noqa: E402
import public_feed_freshness_gate as gate  # noqa: E402
import public_freshness_contract as contract  # noqa: E402
from test_deployment_health_contract import LIVE_OK, NOW, _health, feed_body  # noqa: E402


def iso_ms(dt):
    return dt.strftime("%Y-%m-%dT%H:%M:%S.") + f"{dt.microsecond // 1000:03d}Z"


# case id -> (generated_at, expected canonical state, worker HTTP status, worker status, reason)
CASES = {
    "10min": (iso_ms(NOW - timedelta(minutes=10)), "fresh", 200, "ok", None),
    "5h59m59s": (iso_ms(NOW - timedelta(hours=5, minutes=59, seconds=59)), "fresh", 200, "ok", None),
    # Canonical boundary is INCLUSIVE: age == max is fresh (PR #485's `<=`).
    "exactly_6h": (iso_ms(NOW - timedelta(hours=6)), "fresh", 200, "ok", None),
    "6h_plus_1ms": (iso_ms(NOW - timedelta(hours=6, milliseconds=1)), "stale", 503, "degraded", "intelligence_stale"),
    "24h": (iso_ms(NOW - timedelta(hours=24)), "stale", 503, "degraded", "intelligence_stale"),
    "missing": (None, "missing_timestamp", 503, "unhealthy", "generated_at_missing"),
    "invalid": ("yesterday afternoon", "invalid_timestamp", 503, "unhealthy", "generated_at_invalid"),
    "gross_future": (iso_ms(NOW + timedelta(hours=24)), "future_timestamp", 503, "unhealthy", "generated_at_in_future"),
}
HEALTH_STATE = {"fresh": "healthy", "stale": "degraded"}  # everything else -> unhealthy


def worker_health(case):
    """/api/health exactly as the Worker answers for this feed (PUBLIC view)."""
    gen, state, http, status, reason = CASES[case]
    body = _health(status, reason, state, gen)
    body["checks"]["intelligence_freshness"] = state
    if state not in ("fresh", "stale"):
        body["intelligence"]["age_seconds"] = None
    return (http, body, None)


def fake_fetch(live, health):
    def f(url, timeout, headers=None):
        return live if url.split("?")[0].endswith("/api/health/live") else health
    return f


class _FutureDatetime(datetime):
    """Wall clock moved to 2031: a pinned evaluation must not notice."""

    @classmethod
    def now(cls, tz=None):
        return datetime(2031, 1, 1, tzinfo=timezone.utc)


@pytest.fixture(params=["real_clock", "wall_clock_2031"])
def wall_clock(request, monkeypatch):
    if request.param == "wall_clock_2031":
        monkeypatch.setattr(contract, "datetime", _FutureDatetime)
        monkeypatch.setattr(gate, "datetime", _FutureDatetime)
    return request.param


def test_six_hour_contract_is_unchanged():
    cfg = json.loads((REPO / "config" / "public_freshness_contract.json").read_text())
    assert cfg["max_public_manifest_age_hours"] == 6
    assert cfg["max_future_skew_hours"] == 3
    assert contract.max_public_manifest_age_hours() == 6


@pytest.mark.parametrize("case", list(CASES))
def test_canonical_classifier_boundary(case):
    gen, state, *_ = CASES[case]
    assert contract.classify_manifest_freshness(gen, now=NOW)["state"] == state


@pytest.mark.parametrize("case", list(CASES))
def test_every_consumer_agrees_on_a_pinned_clock(case, wall_clock, monkeypatch):
    gen, state, *_ = CASES[case]
    health = worker_health(case)
    expected_health_state = HEALTH_STATE.get(state, "unhealthy")

    # 1. deployment health contract
    hv = dhc.evaluate_health(*health, now=NOW, expected_version=LIVE_OK[1]["version"])
    assert hv["valid"], (case, hv["failures"])
    assert hv["state"] == expected_health_state, case
    dep = dhc.evaluate_deployment(LIVE_OK, health, now=NOW)
    assert dep["deployment_verdict"] == "PASS", (case, dep["failures"])
    assert dep["customer_intelligence_state"] == expected_health_state

    # 2. deployment canary A (a valid SENTINEL body passes in any state)
    monkeypatch.setattr(dc._deploy_health, "fetch_json", fake_fetch(LIVE_OK, health))
    ca = dc.canary_a_health("https://x", 5, now=NOW)
    assert ca["pass"] is True, (case, ca)
    assert ca["intelligence_state"] == expected_health_state

    # 3. post-rollback canary
    pr = prc.evaluate(LIVE_OK, health, 200, 200, now=NOW)
    assert pr["canary_pass"] and pr["passed"] == 4, (case, pr["probes"])
    assert pr["customer_intelligence_state"] == expected_health_state

    # 4. public freshness gate: PASS only when the feed is FRESH
    g = gate.evaluate(200, feed_body(gen), None, *health, now=NOW)
    assert g["feed"]["state"] == state, case
    assert (g["verdict"] == "PASS") is (state == "fresh"), (case, g["failures"])


@pytest.mark.parametrize("case", ["6h_plus_1ms", "24h", "missing", "invalid", "gross_future"])
def test_stale_or_unusable_data_can_never_be_reported_fresh(case, wall_clock, monkeypatch):
    """A Worker that LIES (200 ok/fresh) about a non-fresh feed fails every consumer."""
    gen, *_ = CASES[case]
    lying = (200, _health("ok", None, "fresh", gen), None)
    assert dhc.evaluate_health(*lying, now=NOW, expected_version="200.0")["valid"] is False, case
    monkeypatch.setattr(dc._deploy_health, "fetch_json", fake_fetch(LIVE_OK, lying))
    assert dc.canary_a_health("https://x", 5, now=NOW)["pass"] is False, case
    assert prc.evaluate(LIVE_OK, lying, 200, 200, now=NOW)["canary_pass"] is False, case
    assert gate.evaluate(200, feed_body(gen), None, *lying, now=NOW)["verdict"] == "FAIL", case


def test_production_callers_still_use_the_real_clock():
    """`now` is test-only: production call sites must not pin a clock."""
    canary = (REPO / "scripts" / "deployment_canary.py").read_text()
    assert "canary_a_health(base, timeout)," in canary
    rollback = (REPO / "scripts" / "post_rollback_canary.py").read_text()
    assert "r = evaluate(live, health, dash if not dash_err else None, feed if not feed_err else None)" in rollback
