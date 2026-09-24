#!/usr/bin/env python3
"""
scripts/post_rollback_canary.py -- post-rollback health canary
(enterprise-rollback-governance.yml, job post-rollback-canary).

Previously an inline heredoc that probed https://intel.cyberdudebivash.com/
api/v1/health. The deployed gateway never served that route (it exists only
in the legacy FastAPI apps under api/ and agent/), so it answered 404 on every
run: 3 of 4 probes passed = 75%, under the 80% threshold, so every
post-rollback canary failed regardless of the rollback's outcome.

That probe is replaced by a contract check of the canonical /api/health,
evaluated by scripts/deployment_health_contract.py (reused, not duplicated):
a well-formed SENTINEL body passes in any intelligence state, because a
rollback restores Worker code and cannot make a stale feed fresh. Customer
intelligence freshness remains owned by STAGE 5.9.10.

Probes (threshold unchanged: fail when fewer than 80% pass):
  1. /api/health/live  -- Worker liveness contract (evaluate_liveness)
  2. /api/health       -- structured health contract (evaluate_health.valid)
  3. www dashboard     -- HTTP 200/204
  4. /api/feed.json    -- HTTP 200/204
"""
from __future__ import annotations

import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
import deployment_health_contract as dhc  # noqa: E402

INTEL_BASE = "https://intel.cyberdudebivash.com"
DASHBOARD_URL = "https://www.cyberdudebivash.com/"
PASS_RATIO = 0.8


def _http_status(url: str, timeout: float) -> tuple[int | None, str | None]:
    req = urllib.request.Request(url, headers={"User-Agent": dhc.USER_AGENT, "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            return resp.status, None
    except urllib.error.HTTPError as e:
        return e.code, None
    except Exception as e:  # DNS / TLS / reset / timeout
        return None, f"{type(e).__name__}: {e}"


def evaluate(live, health, dashboard_status, feed_status) -> dict:
    """live/health are (status, body, err) triples; the others HTTP statuses."""
    lv = dhc.evaluate_liveness(*live)
    hv = dhc.evaluate_health(*health, expected_version=lv["version"] if lv["alive"] else None)
    probes = [
        ("API Health (liveness)", lv["alive"], "; ".join(lv["failures"]) or "alive"),
        ("API Health (contract)", hv["valid"],
         "; ".join(hv["failures"]) or f"valid, intelligence {hv['state']}"),
        ("Dashboard", dashboard_status in (200, 204), f"HTTP {dashboard_status}"),
        ("Feed API", feed_status in (200, 204), f"HTTP {feed_status}"),
    ]
    passed = sum(1 for _, ok, _ in probes if ok)
    return {
        "probes": probes,
        "passed": passed,
        "total": len(probes),
        "canary_pass": passed >= len(probes) * PASS_RATIO,
        "customer_intelligence_state": hv["state"],
    }


def main(timeout: float = 15.0) -> int:
    cb = str(int(time.time()))
    live = dhc.fetch_json(f"{INTEL_BASE}/api/health/live?rollback_canary={cb}", timeout)
    health = dhc.fetch_json(f"{INTEL_BASE}/api/health?rollback_canary={cb}", timeout)
    dash, dash_err = _http_status(DASHBOARD_URL, timeout)
    feed, feed_err = _http_status(f"{INTEL_BASE}/api/feed.json", timeout)
    r = evaluate(live, health, dash if not dash_err else None, feed if not feed_err else None)
    for name, ok, detail in r["probes"]:
        print(f"  {'PASS' if ok else 'FAIL'} {name}: {detail}")
    print(f"\nPost-rollback canary: {r['passed']}/{r['total']} passed "
          f"(customer intelligence: {r['customer_intelligence_state']})")
    if not r["canary_pass"]:
        print("::error::Post-rollback canary FAILED -- less than 80% probes passed.")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
