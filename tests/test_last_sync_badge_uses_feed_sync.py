"""
Homepage "Last Sync" = when the platform last published its feed.

Production 2026-09-26T10:04Z: /api/platform/stats returned
last_sync 07:42:26Z (the newest ARTICLE's publish date) and
last_feed_sync_utc / publication_generated_at 09:41:49Z (the feed). The
homepage badge (#m-last-sync, fetchWorkerStats) read last_sync, so it said
"2h ago" for a feed published 22 minutes earlier; in a quiet news window it
reads as stale while the feed is fresh. js/sentinel-live-feeds.js already
uses last_feed_sync_utc. The expression is evaluated with node against the
live response shape.
"""
import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest
from scripts.homepage_source import read_homepage_source  # index.html + extracted css/js

REPO = Path(__file__).resolve().parent.parent
LIVE_STATS = {
    "last_sync": "2026-09-26T07:42:26Z",
    "last_feed_sync_utc": "2026-09-26T09:41:49Z",
    "publication_generated_at": "2026-09-26T09:41:49Z",
}


def _sync_expression():
    html = read_homepage_source()
    m = re.search(r"const _syncTs = ([^;]+);", html)
    assert m, "fetchWorkerStats no longer resolves _syncTs"
    return m.group(1)


def _eval(intel):
    if not shutil.which("node"):
        pytest.skip("node not installed")
    js = f"const intel = {json.dumps(intel)}; process.stdout.write(String({_sync_expression()}));"
    return subprocess.run(["node", "-e", js], capture_output=True, text=True, check=True).stdout


def test_badge_shows_feed_publication_time_not_newest_article():
    assert _eval(LIVE_STATS) == "2026-09-26T09:41:49Z"


def test_falls_back_when_older_workers_omit_the_feed_fields():
    assert _eval({"publication_generated_at": "2026-09-26T09:41:49Z", "last_sync": "x"}) == "2026-09-26T09:41:49Z"
    assert _eval({"last_sync": "2026-09-26T07:42:26Z"}) == "2026-09-26T07:42:26Z"
    assert _eval({}) == ""


def test_live_feeds_script_agrees():
    js = (REPO / "js" / "sentinel-live-feeds.js").read_text(encoding="utf-8")
    assert "stats.last_feed_sync_utc" in js
