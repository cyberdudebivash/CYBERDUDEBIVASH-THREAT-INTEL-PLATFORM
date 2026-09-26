"""Customer-facing counts must come from the feed, not a fixed catalog."""
from __future__ import annotations

from pathlib import Path
from scripts.homepage_source import read_homepage_source  # index.html + extracted css/js

REPO = Path(__file__).resolve().parent.parent


def test_homepage_does_not_invent_origins_or_tor_coverage():
    src = read_homepage_source()
    for banned in (
        "TOR MONITORING",
        "Continuous monitoring of Tor",
        "Dark Web Surveillance",
        "2,847+",
        "99.7%",
        "AI MODELS ACTIVE",
        "v40 CORTEX",
        "v41 QUANTUM",
        "v42 SOVEREIGN",
        "ukrain",
    ):
        assert banned not in src, banned
    assert "No country tags" in src
    assert "NOT A CRAWL" in src
    assert "FEED ONLY" in src


def test_gateway_and_generator_do_not_ship_fixed_darkweb_totals():
    worker = (REPO / "workers/intel-gateway/src/index.js").read_text(encoding="utf-8")
    generator = (REPO / "scripts/generate_dashboard_feeds.py").read_text(encoding="utf-8")
    for banned in ("58K+", "sources_monitored: 127", "sources_monitored\":     127", "newVictims + 38", "stats.total * 0.15", "stats[\"total\"] * 0.15"):
        assert banned not in worker, banned
        assert banned not in generator, banned
    assert "crawl_connected: false" in worker
    assert "counted_from_country_fields" in generator
