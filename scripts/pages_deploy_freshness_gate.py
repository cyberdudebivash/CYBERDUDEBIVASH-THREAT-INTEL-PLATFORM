#!/usr/bin/env python3
"""
scripts/pages_deploy_freshness_gate.py -- GitHub Pages Deployment Freshness Gate (v184.1)

WHY THIS EXISTS:
  2026-08-06: 3 consecutive GitHub "pages build and deployment" runs got stuck in
  `deployment_queued` and timed out (~8min each) without ever publishing -- see
  TITAN_PAGES_DEPLOYMENT_INCIDENT_2026-08-06.md for the full root-cause analysis.
  JamesIves/github-pages-deploy-action (STAGE 5) only performs `git push`; it does
  not verify GitHub's Pages backend actually finished building/serving the new
  content, and reports success either way. STAGE 5.5.0 (post_deploy_smoke_test.py)
  checks HTTP status code and body size only -- its own smoke() docstring says
  "We'd need to re-fetch with content, skip content check in smoke test" -- and
  runs with continue-on-error: true, so a stuck deploy was invisible anywhere
  except manually reading the Actions tab (which is how this was first noticed).

  This gate closes that gap: it polls the live site's Last-Modified header,
  mirroring post_deploy_smoke_test.py's fetch-with-retries idiom, until it
  advances past the pre-deploy timestamp -- and HARD FAILS (no
  continue-on-error) if it never does within the retry budget, so a stuck
  deploy is loud and actionable instead of silent.

Exit codes:
  0 = live site's Last-Modified confirmed >= pre-deploy timestamp (deploy verified live)
  1 = Last-Modified never advanced within the retry budget (deploy did not propagate)

Environment vars:
  PLATFORM_URL           (default: https://intel.cyberdudebivash.com)
  PRE_DEPLOY_TIMESTAMP   (required, ISO8601 UTC, e.g. 2026-08-06T12:52:00Z --
                          captured by the workflow immediately before STAGE 5)
  FRESHNESS_TIMEOUT_MIN  (default: 12 -- comfortably clears both GitHub's own
                          ~8min internal Pages deployment timeout AND the
                          platform's observed 600s/10min CDN cache-control
                          max-age, so this gate's own failure is never a race
                          against a deploy that would have succeeded, or a
                          false failure from ordinary CDN propagation lag)
  FRESHNESS_POLL_SEC     (default: 20)

Usage: python3 scripts/pages_deploy_freshness_gate.py
"""
import os
import sys
import time
from datetime import datetime, timezone
from urllib import request, error

if hasattr(sys.stdout, "reconfigure"):
    try:
        sys.stdout.reconfigure(encoding="utf-8")
    except Exception:
        pass

PLATFORM_URL = os.environ.get("PLATFORM_URL", "https://intel.cyberdudebivash.com").rstrip("/")
PRE_DEPLOY_TIMESTAMP = os.environ.get("PRE_DEPLOY_TIMESTAMP")
TIMEOUT_MIN = float(os.environ.get("FRESHNESS_TIMEOUT_MIN", "12"))
POLL_SEC = float(os.environ.get("FRESHNESS_POLL_SEC", "20"))
REQUEST_TIMEOUT_SEC = 15


def parse_http_date(value):
    # Last-Modified is always RFC 7231 IMF-fixdate ("Thu, 06 Aug 2026 08:23:57 GMT") on this
    # platform -- confirmed by direct curl against the live site before writing this gate.
    return datetime.strptime(value, "%a, %d %b %Y %H:%M:%S GMT").replace(tzinfo=timezone.utc)


def parse_iso(value):
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def fetch_last_modified(url):
    # Cache-busting query param: the platform's own CDN layer was observed serving
    # `cache-control: max-age=600` with `x-cache: HIT` -- a plain repeated GET/HEAD to the same
    # URL can return a cached response and never reflect origin freshness within this gate's
    # budget. Appending a unique query string forces each poll to bypass that cache tier.
    bust_url = url + "/?_freshness_check=" + str(int(time.time() * 1000))
    req = request.Request(
        bust_url, method="HEAD", headers={"User-Agent": "SENTINEL-APEX-FRESHNESS-GATE/184.1"}
    )
    with request.urlopen(req, timeout=REQUEST_TIMEOUT_SEC) as r:
        return r.headers.get("Last-Modified")


def main():
    if not PRE_DEPLOY_TIMESTAMP:
        print("[FATAL] PRE_DEPLOY_TIMESTAMP not set -- cannot verify freshness, failing closed.")
        return 1

    pre_deploy_dt = parse_iso(PRE_DEPLOY_TIMESTAMP)
    deadline = time.time() + TIMEOUT_MIN * 60

    print("=" * 62)
    print("  GITHUB PAGES DEPLOYMENT FRESHNESS GATE")
    print("  Platform: " + PLATFORM_URL)
    print("  Pre-deploy timestamp: " + PRE_DEPLOY_TIMESTAMP)
    print("  Budget: " + str(TIMEOUT_MIN) + " min")
    print("=" * 62)

    attempt = 0
    last_seen = None
    while time.time() < deadline:
        attempt += 1
        try:
            lm = fetch_last_modified(PLATFORM_URL)
            if lm:
                last_seen = parse_http_date(lm)
                fresh = last_seen >= pre_deploy_dt
                print(
                    "  [attempt "
                    + str(attempt)
                    + "] Last-Modified="
                    + lm
                    + ("  -- FRESH" if fresh else "  -- still stale")
                )
                if fresh:
                    print("")
                    print("  DEPLOYMENT FRESHNESS: CONFIRMED -- live site reflects this run's deploy")
                    return 0
            else:
                print("  [attempt " + str(attempt) + "] no Last-Modified header returned -- retrying")
        except Exception as e:
            print("  [attempt " + str(attempt) + "] fetch failed: " + str(e) + " -- retrying")
        time.sleep(POLL_SEC)

    print("")
    print("  DEPLOYMENT FRESHNESS: FAILED")
    print(
        "  Live site's Last-Modified ("
        + (last_seen.isoformat() if last_seen else "unknown")
        + ") never advanced past the pre-deploy timestamp ("
        + PRE_DEPLOY_TIMESTAMP
        + ") within "
        + str(TIMEOUT_MIN)
        + " minutes."
    )
    print("  ACTION: check the 'pages build and deployment' run for this commit in the Actions tab.")
    print("  Known failure mode (see TITAN_PAGES_DEPLOYMENT_INCIDENT_2026-08-06.md): it gets stuck")
    print("  in 'deployment_queued' and times out without publishing. This is usually transient --")
    print("  the next scheduled/triggered sentinel-blogger.yml run typically succeeds once GitHub's")
    print("  Pages backend catches up. Investigate only if this recurs across multiple consecutive")
    print("  runs.")
    return 1


if __name__ == "__main__":
    sys.exit(main())
