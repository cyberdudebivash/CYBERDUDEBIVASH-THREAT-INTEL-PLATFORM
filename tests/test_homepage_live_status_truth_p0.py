"""P0 source contract for the Threat Intel homepage's commercial truth.

These are intentionally static regressions, not substitutes for live/browser
certification. They guard against the concrete unverified-LIVE, frozen-source
count and unauthorized GitHub mirror behavior seen in the production source.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HTML = (ROOT / "index.html").read_text(encoding="utf-8")
ENGINE = (ROOT / "js/homepage-dashboard-engine.js").read_text(encoding="utf-8")


def test_startup_never_claims_unverified_live_or_74_feeds():
    assert 'id="sync-val" role="status" aria-live="polite"' in HTML
    assert 'SYNC: <span style="color:#ff9d00;">VERIFYING</span>' in HTML
    assert 'id="m-feed-count"' in HTML
    assert 'id="engine-feed-count">&mdash;</span> REGISTERED SOURCES' in HTML
    assert 'id="api-status-dot" role="status" aria-live="polite"' in HTML
    assert '● CHECKING</span>' in HTML
    assert 'id="ai-pulse-indicator" style="display:none" aria-hidden="true"' in HTML
    assert 'UPDATES EVERY &lt;2 HOURS' not in HTML


def test_current_js_cache_bust_and_authoritative_mirror_boundary():
    assert '/js/homepage-dashboard-engine.js?v=p0-20261012-authoritative-truth' in HTML
    # A raw repository mirror bypasses the gateway freshness/TLP read boundary.
    assert "'https://raw.githubusercontent.com/cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM/main/api/feed.json'" not in ENGINE
    assert "'api/feed.json'" in ENGINE
    assert "WORKER_PREVIEW_URL" in ENGINE


def test_only_gateway_freshness_can_authorize_sync_live():
    assert "function cdbApplyOperationalStatus(intel)" in ENGINE
    assert "published.text === 'LIVE' && intel && intel.freshness === 'FRESH'" in ENGINE
    assert "if (isApiSource && _knownStale)" in ENGINE
    assert "isApiSource && window.__CDB_FRESHNESS__ === 'FRESH'" in ENGINE
    assert "Manifest fetched; freshness unverified" in ENGINE
    assert "window.__CDB_FRESHNESS__ = 'UNAVAILABLE'" in ENGINE


def test_embedded_cache_is_never_invented_live_publication():
    assert "Embedded cache is not live publication evidence" in ENGINE
    assert "Embedded cache: source authority unavailable" in ENGINE
    assert "UNVERIFIED CACHE" in ENGINE
    assert "EMBEDDED LIVE';" not in ENGINE
    assert "FEED GENERATION: " in ENGINE
    assert "Number.isFinite(_syncedAt) ? timeSince(_syncedAt) : 'UNKNOWN'" in ENGINE


def test_registered_source_count_is_not_top_ten_bar_chart_length():
    assert "if (feedCountEl) feedCountEl.textContent = sorted.length" not in ENGINE
    assert "if (engineFeedEl) engineFeedEl.textContent = sorted.length" not in ENGINE
    assert "set('m-feed-count', _sourceCount.toLocaleString())" in ENGINE
    assert "set('engine-feed-count', _sourceCount.toLocaleString())" in ENGINE
    assert "intel.feed_count !== null && intel.feed_count !== undefined" in ENGINE


# The production Pages publisher uses Python's standard-library unittest,
# not pytest. Keep these contracts executable without installing dependencies.
import unittest


class TestHomepageReleaseTruth(unittest.TestCase):
    def test_initial_status(self):
        test_startup_never_claims_unverified_live_or_74_feeds()

    def test_authoritative_sources(self):
        test_current_js_cache_bust_and_authoritative_mirror_boundary()

    def test_worker_freshness(self):
        test_only_gateway_freshness_can_authorize_sync_live()

    def test_cache_truth(self):
        test_embedded_cache_is_never_invented_live_publication()

    def test_registry_count(self):
        test_registered_source_count_is_not_top_ten_bar_chart_length()

    def test_customer_claims(self):
        test_static_trust_bar_never_presents_unverified_standards_certifications()
