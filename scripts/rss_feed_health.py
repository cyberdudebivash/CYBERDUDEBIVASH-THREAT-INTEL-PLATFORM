#!/usr/bin/env python3
"""
scripts/rss_feed_health.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- RSS Source Fabric Health Probe v1.0.0
=========================================================================
Probes every feed in agent/config.py's RSS_FEEDS and reports which ones
actually yield parseable entries.

WHY THIS EXISTS
---------------
ingest_rss_feeds() is deliberately fault-tolerant: a feed that 404s, times
out or returns HTML instead of XML is logged at debug level and skipped, so
the pipeline never fails because one publisher moved a URL. The cost of that
resilience is that a dead feed is INVISIBLE -- it simply stops contributing
and nothing reports the loss.

That is not hypothetical. When this probe was first run against the live
configuration, 40 of 91 unique feeds (44%) produced nothing:
  15  HTTP 404   publisher moved or retired the path
  15  HTTP 2xx   reachable but zero parseable entries (HTML, JSON, or an
                 API endpoint that is not a feed at all)
   3  HTTP 403   WAF/bot protection (may still succeed from other egress IPs)
   4  URLError / 2 timeouts / 1 HTTP 500
Ten of those were recoverable by pointing at the publisher's current URL --
JPCERT/CC, Google Security Blog, Volexity, MSRC, Sysdig, Proofpoint, Deep
Instinct, GreyNoise, Rapid7, Sophos X-Ops, plus CERT-FR -- which took
parseable entries available from 2,278 to 7,685.

Source breadth is a product quality signal for a commercial threat
intelligence platform. A feed list that silently rots is breadth quietly
draining away, so this makes the loss observable.

EGRESS SENSITIVITY -- READ BEFORE PRUNING
Some failures are egress-dependent, not publisher-dependent: a 403 from a
WAF or a timeout may reflect the IP this probe runs from rather than a
genuinely dead feed. HTTP 404 is publisher-side truth and safe to act on;
403/timeout/DNS results are NOT, and this report deliberately separates
them so nobody prunes a feed that works fine from the production runner.

NON-BLOCKING BY DESIGN. Third-party publisher availability is outside this
platform's control, so this never fails a build. It reports.

ENV
  RSS_HEALTH_TIMEOUT   per-feed timeout seconds (default: 20)
  RSS_HEALTH_WORKERS   probe concurrency (default: 12)
  RSS_HEALTH_OUTPUT    telemetry path (default: data/telemetry/rss_feed_health.json)
"""
from __future__ import annotations

import ast
import concurrent.futures as cf
import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Tuple

REPO_ROOT = Path(__file__).resolve().parent.parent
CONFIG_PATH = REPO_ROOT / "agent" / "config.py"
OUT_PATH = Path(os.environ.get(
    "RSS_HEALTH_OUTPUT", str(REPO_ROOT / "data" / "telemetry" / "rss_feed_health.json")))
TIMEOUT = int(os.environ.get("RSS_HEALTH_TIMEOUT", "20"))
WORKERS = int(os.environ.get("RSS_HEALTH_WORKERS", "12"))

# Matches ingest_rss_feeds()'s own skip rules, so this probe measures exactly
# the set that ingestion will actually attempt.
_NON_FEED_MARKERS = ("/api/v1/", "/graphql", "shadowserver.org/api")

# Failures that are publisher-side truth vs. ones that may just be this
# runner's egress IP. Only the former is safe to act on by pruning.
_PUBLISHER_TRUTH = ("HTTP 404", "HTTP 410", "HTTP 500")


def load_feeds() -> List[str]:
    """Read RSS_FEEDS without importing agent.config.

    config.py hard-exits at import time when CDB_JWT_SECRET is unset, which
    is the correct behaviour for the running platform but would make this
    probe unusable in any environment without that secret. Parsing the AST
    reads the same literal without executing the module.
    """
    tree = ast.parse(CONFIG_PATH.read_text(encoding="utf-8"))
    for node in ast.walk(tree):
        if isinstance(node, ast.Assign):
            for target in node.targets:
                if getattr(target, "id", None) == "RSS_FEEDS":
                    return list(ast.literal_eval(node.value))
    return []


def probe(url: str) -> Tuple[str, str, int]:
    """Return (url, status, entry_count). Never raises."""
    try:
        import feedparser  # noqa: PLC0415
    except ImportError:
        return (url, "NO_FEEDPARSER", 0)
    req = urllib.request.Request(
        url, headers={"User-Agent": "Mozilla/5.0 (compatible; SentinelAPEX/1.0)"})
    try:
        with urllib.request.urlopen(req, timeout=TIMEOUT) as resp:
            body = resp.read()
            status = f"HTTP {resp.status}"
    except urllib.error.HTTPError as e:
        return (url, f"HTTP {e.code}", 0)
    except Exception as e:  # noqa: BLE001 - a probe must never crash the run
        return (url, type(e).__name__, 0)
    try:
        return (url, status, len(feedparser.parse(body).entries))
    except Exception:  # noqa: BLE001
        return (url, status, 0)


def run() -> int:
    feeds = load_feeds()
    if not feeds:
        print("::warning::RSS_FEEDS not found in agent/config.py -- nothing probed")
        return 0

    unique = [u for u in dict.fromkeys(feeds)
              if u.startswith(("http://", "https://"))
              and not any(m in u for m in _NON_FEED_MARKERS)]
    duplicates = len(feeds) - len(dict.fromkeys(feeds))

    with cf.ThreadPoolExecutor(max_workers=WORKERS) as ex:
        results = list(ex.map(probe, unique))

    healthy = [r for r in results if r[2] > 0]
    dead_truth = [r for r in results if r[2] == 0 and r[1] in _PUBLISHER_TRUTH]
    dead_maybe = [r for r in results if r[2] == 0 and r[1] not in _PUBLISHER_TRUTH]
    total_entries = sum(r[2] for r in healthy)
    pct = (len(healthy) / len(unique) * 100) if unique else 0.0

    print(f"[rss-health] {len(healthy)}/{len(unique)} feeds yielding "
          f"({pct:.1f}%), {total_entries} entries available")
    if duplicates:
        print(f"[rss-health] {duplicates} duplicate URL(s) in RSS_FEEDS")

    if dead_truth:
        print(f"[rss-health] {len(dead_truth)} publisher-side dead "
              f"(404/410/500 -- safe to repoint or prune):")
        for url, status, _ in sorted(dead_truth):
            print(f"    {status:14s} {url}")
    if dead_maybe:
        print(f"[rss-health] {len(dead_maybe)} unreachable from THIS runner "
              f"(403/timeout/DNS -- may work from production egress, do not "
              f"prune on this evidence alone):")
        for url, status, _ in sorted(dead_maybe):
            print(f"    {status:14s} {url}")

    report: Dict[str, Any] = {
        "schema_version": "1.0.0",
        "generated_at": datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ"),
        "feeds_configured": len(feeds),
        "feeds_unique_probed": len(unique),
        "duplicate_urls": duplicates,
        "feeds_yielding": len(healthy),
        "feeds_yielding_pct": round(pct, 1),
        "entries_available": total_entries,
        "publisher_dead": [{"url": u, "status": s} for u, s, _ in sorted(dead_truth)],
        "unreachable_from_runner": [{"url": u, "status": s} for u, s, _ in sorted(dead_maybe)],
        "yielding": sorted(
            [{"url": u, "entries": n} for u, _, n in healthy],
            key=lambda r: -r["entries"]),
    }
    OUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = OUT_PATH.with_suffix(OUT_PATH.suffix + ".tmp")
    tmp.write_text(json.dumps(report, indent=2), encoding="utf-8")
    os.replace(tmp, OUT_PATH)
    print(f"[rss-health] wrote -> {OUT_PATH}")
    return 0


if __name__ == "__main__":
    sys.exit(run())
