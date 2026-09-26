"""P0 2026-09-26: scripts/intel_freshness_guard.py decision table.

The publisher (sentinel-blogger) was displaced from the shared
sentinel-data-writer concurrency queue and the public feed went 9h stale.
The guard re-dispatches it -- but only when the PUBLISHED feed is stale, no
publisher run is in flight, and it is not hammering a broken pipeline.
"""
import sys
from datetime import datetime, timedelta, timezone
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "scripts"))
import intel_freshness_guard as g  # noqa: E402

NOW = datetime(2026, 9, 26, 5, 0, tzinfo=timezone.utc)


def health(status, age_hours):
    return {"status": "degraded" if status != "fresh" else "ok",
            "intelligence": {"status": status, "age_seconds": int(age_hours * 3600), "generated_at": "2026-09-25T19:49:35Z"}}


def run(minutes_ago, conclusion=None, status="completed"):
    return {"created_at": (NOW - timedelta(minutes=minutes_ago)).isoformat().replace("+00:00", "Z"),
            "status": status, "conclusion": conclusion}


def test_fresh_feed_needs_nothing():
    assert g.decide(health("fresh", 1), [], [], NOW)["action"] == "none"


def test_the_incident_stale_9h_no_publisher_dispatches():
    d = g.decide(health("stale", 9), [], [], NOW)
    assert d["action"] == "dispatch"
    assert d["reason"] == "stale_no_active_publisher"
    assert d["exit"] == 0


def test_approaching_stale_dispatches_before_the_contract_breaks():
    # fresh but already past DISPATCH_AT_HOURS: a ~80 min run must start now to land inside 6h
    d = g.decide(health("fresh", 4.5), [], [], NOW)
    assert d["action"] == "dispatch"
    assert d["reason"] == "approaching_stale"


def test_never_dispatches_while_a_publisher_run_is_active_or_queued():
    assert g.decide(health("stale", 9), [run(5, status="in_progress")], [], NOW)["reason"] == "publisher_active"
    assert g.decide(health("stale", 9), [run(1, status="queued")], [], NOW)["action"] == "none"


def test_cooldown_after_its_own_dispatch():
    d = g.decide(health("stale", 9), [], [run(30, conclusion="success")], NOW)
    assert d["reason"] == "cooldown"
    assert g.decide(health("stale", 9), [], [run(120, conclusion="success")], NOW)["action"] == "dispatch"


def test_a_displaced_dispatch_is_retried_at_once():
    # the exact failure mode: the pending run was cancelled by a newer queued run
    assert g.decide(health("stale", 9), [], [run(20, conclusion="cancelled")], NOW)["action"] == "dispatch"


def test_stops_and_alerts_when_the_publisher_itself_is_failing():
    d = g.decide(health("stale", 12), [], [run(100, conclusion="failure")], NOW)
    assert d["action"] == "alert"
    assert d["reason"] == "publisher_failing"
    assert d["exit"] == 1
    # an old failure (> 4h) no longer blocks a new attempt
    assert g.decide(health("stale", 12), [], [run(300, conclusion="failure")], NOW)["action"] == "dispatch"


def test_unreadable_health_alerts_and_never_dispatches_blind():
    for h in (None, {}, {"intelligence": {}}):
        d = g.decide(h, [], [], NOW)
        assert d["action"] == "alert"
        assert d["exit"] == 1


def test_untrustworthy_timestamp_states_are_cured_by_a_run():
    for state in ("missing_timestamp", "invalid_timestamp", "future_timestamp"):
        assert g.decide({"intelligence": {"status": state, "age_seconds": None}}, [], [], NOW)["action"] == "dispatch"


def test_a_zombie_active_run_does_not_suppress_dispatch_forever():
    # one sentinel-blogger run has sat "pending" since 2026-05-26
    zombie = run(60 * 24 * 123, status="pending")
    assert g.decide(health("stale", 9), [zombie], [], NOW)["action"] == "dispatch"
    assert g.decide(health("stale", 9), [zombie, run(10, status="in_progress")], [], NOW)["reason"] == "publisher_active"
