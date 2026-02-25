"""
test_feed_reliability.py — CyberDudeBivash SENTINEL APEX ULTRA
Unit tests for the Feed Reliability Layer (agent/feed_reliability.py).
"""
import pytest
from agent.feed_reliability import FeedHealthTracker, feed_health, USER_AGENTS


class TestFeedHealthTracker:
    def setup_method(self):
        """Fresh tracker for each test."""
        self.tracker = FeedHealthTracker()

    def test_initial_status_is_unknown(self):
        status = self.tracker.get_feed_status("TestFeed")
        assert status["status"] == "unknown"

    def test_record_success_sets_healthy(self):
        self.tracker.record_success("TestFeed", latency_ms=100)
        status = self.tracker.get_feed_status("TestFeed")
        assert status["status"] == "healthy"

    def test_record_failure_sets_degraded(self):
        # Only failures → degraded
        self.tracker.record_failure("TestFeed", error="Connection refused")
        status = self.tracker.get_feed_status("TestFeed")
        assert status["status"] in {"degraded", "intermittent"}

    def test_success_count_increments(self):
        self.tracker.record_success("Feed1", latency_ms=50)
        self.tracker.record_success("Feed1", latency_ms=75)
        status = self.tracker.get_feed_status("Feed1")
        assert status["success_count"] == 2

    def test_failure_count_increments(self):
        self.tracker.record_failure("Feed1", error="Timeout")
        self.tracker.record_failure("Feed1", error="HTTP 503")
        status = self.tracker.get_feed_status("Feed1")
        assert status["failure_count"] == 2

    def test_latency_average_computed(self):
        for ms in [100, 200, 300]:
            self.tracker.record_success("Feed1", latency_ms=ms)
        status = self.tracker.get_feed_status("Feed1")
        assert status["avg_latency_ms"] == 200.0

    def test_success_rate_100_pct(self):
        self.tracker.record_success("Feed1")
        self.tracker.record_success("Feed1")
        status = self.tracker.get_feed_status("Feed1")
        assert status["success_rate_pct"] == 100.0

    def test_success_rate_50_pct(self):
        self.tracker.record_success("Feed1")
        self.tracker.record_failure("Feed1", error="err")
        status = self.tracker.get_feed_status("Feed1")
        assert status["success_rate_pct"] == 50.0

    def test_get_summary_structure(self):
        self.tracker.record_success("FeedA")
        self.tracker.record_failure("FeedB", error="err")
        summary = self.tracker.get_summary()
        assert "total_feeds_tracked" in summary
        assert "healthy" in summary
        assert "degraded" in summary
        assert "feeds" in summary
        assert isinstance(summary["feeds"], list)

    def test_get_summary_counts_correctly(self):
        self.tracker.record_success("FeedA")
        self.tracker.record_failure("FeedB", error="err")
        summary = self.tracker.get_summary()
        assert summary["total_feeds_tracked"] == 2
        assert summary["healthy"] == 1
        assert summary["degraded"] >= 1

    def test_get_degraded_feeds_returns_only_degraded(self):
        self.tracker.record_success("GoodFeed")
        self.tracker.record_failure("BadFeed", error="err")
        degraded = self.tracker.get_degraded_feeds()
        names = [f["feed_name"] for f in degraded]
        assert "BadFeed" in names
        assert "GoodFeed" not in names

    def test_reset_single_feed(self):
        self.tracker.record_success("FeedA")
        self.tracker.record_success("FeedB")
        self.tracker.reset("FeedA")
        summary = self.tracker.get_summary()
        assert summary["total_feeds_tracked"] == 1

    def test_reset_all_feeds(self):
        self.tracker.record_success("FeedA")
        self.tracker.record_success("FeedB")
        self.tracker.reset()
        summary = self.tracker.get_summary()
        assert summary["total_feeds_tracked"] == 0

    def test_last_error_stored(self):
        self.tracker.record_failure("Feed1", error="ECONNREFUSED")
        status = self.tracker.get_feed_status("Feed1")
        assert "ECONNREFUSED" in status["last_error"]

    def test_multiple_feeds_tracked_independently(self):
        self.tracker.record_success("Feed1", latency_ms=100)
        self.tracker.record_failure("Feed2", error="timeout")
        s1 = self.tracker.get_feed_status("Feed1")
        s2 = self.tracker.get_feed_status("Feed2")
        assert s1["status"] == "healthy"
        assert s2["status"] in {"degraded", "intermittent"}

    def test_rolling_latency_max_20_samples(self):
        """Latency window must not grow unboundedly."""
        for i in range(50):
            self.tracker.record_success("Feed1", latency_ms=i * 10)
        # Internal samples list must be capped at 20
        assert len(self.tracker._feeds["Feed1"]["_latency_samples"]) <= 20


class TestModuleLevelSingleton:
    def test_feed_health_is_instance(self):
        assert isinstance(feed_health, FeedHealthTracker)

    def test_user_agents_non_empty(self):
        assert len(USER_AGENTS) >= 1
        for ua in USER_AGENTS:
            assert isinstance(ua, str)
            assert len(ua) > 10
