"""P0 regression contract for dashboard freshness semantics.

The gateway intentionally keeps two different timestamps:
* last_sync: newest source item's published timestamp (source recency)
* last_feed_sync_utc: feed artifact generated_at (pipeline sync recency)

Legacy dashboard JS renders stats.last_sync as "Last Sync".  The service worker
compatibility boundary must therefore normalize that browser response from the
authoritative last_feed_sync_utc field without fabricating a timestamp.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SW = ROOT / "service-worker.js"


def _source() -> str:
    return SW.read_text(encoding="utf-8")


def test_stats_route_uses_authoritative_feed_sync_timestamp():
    src = _source()
    assert "url.pathname === '/api/v1/intel/stats'" in src
    assert "payload.last_feed_sync_utc" in src
    assert "last_sync: payload.last_feed_sync_utc" in src


def test_source_publish_timestamp_is_preserved_not_discarded():
    src = _source()
    assert "latest_item_published_at" in src
    assert "payload.last_sync || null" in src


def test_stats_normalization_is_network_only_and_not_synthetic():
    src = _source()
    assert "fetch(request, { cache: 'no-store' })" in src
    assert "Date.now()" not in src
    assert "new Date()" not in src
    assert "X-Sentinel-Freshness-Semantics" in src


def test_runtime_code_and_intelligence_remain_network_only():
    src = _source()
    version = (ROOT / "VERSION").read_text(encoding="utf-8").strip()
    assert f"const CACHE_VERSION = 'sentinel-apex-v{version}-live'" in src
    assert "event.respondWith(fetch(request, { cache: 'no-store' }))" in src
