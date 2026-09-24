#!/usr/bin/env python3
"""
tests/test_public_feed_freshness_gate.py -- offline tests for the external
post-deploy freshness gate (scripts/public_feed_freshness_gate.py).

The 2026-09-24 production state (feed generated 2026-08-26, /api/health 200
"ok") must FAIL; a fresh feed with an agreeing /api/health must PASS.
"""
import sys
from datetime import datetime, timezone
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))

import public_feed_freshness_gate as gate  # noqa: E402

NOW = datetime(2026, 9, 24, 6, 0, 0, tzinfo=timezone.utc)
ITEMS = [{"id": "intel--a"}, {"id": "intel--b"}]
FRESH = {"generated_at": "2026-09-24T05:00:00Z", "count": 2, "items": ITEMS}
STALE = {"generated_at": "2026-08-26T09:55:27Z", "count": 2, "items": ITEMS}
OK = {"status": "ok"}
DEGRADED = {"status": "degraded", "reason": "intelligence_stale"}


def run(feed=(200, FRESH, None), health=(200, OK, None)):
    return gate.evaluate(*feed, *health, now=NOW)


def test_fresh_feed_and_ok_health_pass():
    r = run()
    assert r["verdict"] == "PASS", r["failures"]


def test_incident_state_fails_on_both_counts():
    r = run(feed=(200, STALE, None), health=(200, OK, None))
    assert r["verdict"] == "FAIL"
    assert any("stale" in f for f in r["failures"])
    assert any("reports status 'ok'" in f for f in r["failures"])


def test_stale_feed_with_truthful_503_health_still_fails_release():
    r = run(feed=(200, STALE, None), health=(503, DEGRADED, None))
    assert r["verdict"] == "FAIL"
    assert not any("reports status 'ok'" in f for f in r["failures"])


def test_fresh_feed_but_unhealthy_health_fails():
    assert run(health=(503, DEGRADED, None))["verdict"] == "FAIL"


def test_empty_missing_invalid_and_unreachable_feeds_fail():
    for feed in [
        (200, {"generated_at": "2026-09-24T05:00:00Z", "items": []}, None),
        (200, {"items": ITEMS}, None),
        (200, {"generated_at": "not-a-date", "items": ITEMS}, None),
        (200, {"generated_at": "2099-01-01T00:00:00Z", "items": ITEMS}, None),
        (503, {"error": "Feed not available"}, None),
        (None, None, "URLError: timed out"),
        (200, None, "unparseable JSON"),
    ]:
        assert run(feed=feed, health=(503, DEGRADED, None))["verdict"] == "FAIL", feed


def test_unreachable_health_fails():
    assert run(health=(None, None, "URLError"))["verdict"] == "FAIL"


def test_gate_uses_the_canonical_contract_threshold():
    import public_freshness_contract as c
    assert gate.contract is c
    r = run()
    assert r["max_public_manifest_age_hours"] == c.max_public_manifest_age_hours()
