#!/usr/bin/env python3
"""
scripts/public_feed_freshness_gate.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- external post-deploy freshness gate (HARD FAIL).

Checks what CUSTOMERS actually receive, not internal generated files:
  1. GET <base>/api/v1/intel/latest.json (cache-busted) -- the authoritative
     public feed every tier's /api/feed and /api/v1/intel/latest.json serve.
     Must parse, contain >= 1 item with an id, and be FRESH under the ONE
     canonical contract (scripts/public_freshness_contract.py, the same
     MAX_PUBLIC_MANIFEST_AGE_HOURS PR #485's upload guard uses).
  2. GET <base>/api/health (cache-busted) -- must agree with (1): it may not
     report status "ok" while the public feed is not fresh, and must report
     "ok" with HTTP 200 when it is.

Why: on 2026-09-24 production served a feed generated 2026-08-26 while
/api/health returned 200 {"status":"ok"} and runs still certified. This gate
makes that state an automatic release failure.

Exit 0 = PASS, 1 = FAIL (including unreachable endpoints -- freshness that
cannot be proven is not certified). Writes data/quality/
public_feed_freshness_gate.json. Read-only: two GETs, no R2, no KV, no writes
to production.
"""
from __future__ import annotations

import argparse
import json
import sys
import time
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

SCRIPTS_DIR = Path(__file__).resolve().parent
sys.path.insert(0, str(SCRIPTS_DIR))

import public_freshness_contract as contract  # noqa: E402

REPO_ROOT = SCRIPTS_DIR.parent
REPORT_PATH = REPO_ROOT / "data" / "quality" / "public_feed_freshness_gate.json"
DEFAULT_BASE = "https://intel.cyberdudebivash.com"
USER_AGENT = "SENTINEL-APEX-FreshnessGate/1.0 (+https://intel.cyberdudebivash.com)"


def _get_json(url: str, timeout: float) -> tuple[int | None, object | None, str | None]:
    req = urllib.request.Request(url, headers={"User-Agent": USER_AGENT, "Cache-Control": "no-cache"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            status, raw = resp.status, resp.read()
    except urllib.error.HTTPError as e:
        status, raw = e.code, e.read()
    except Exception as e:  # network / TLS / timeout
        return None, None, f"{type(e).__name__}: {e}"
    try:
        return status, json.loads(raw.decode("utf-8")), None
    except Exception as e:
        return status, None, f"unparseable JSON: {e}"


def evaluate(feed_status, feed_body, feed_err, health_status, health_body, health_err, now=None) -> dict:
    """Pure decision function (unit-tested without network)."""
    failures: list[str] = []
    feed_eval: dict = {"http_status": feed_status}
    if feed_err or feed_status != 200 or not isinstance(feed_body, dict):
        failures.append(f"public feed unavailable (HTTP {feed_status}, {feed_err or 'not a JSON object'})")
        feed_fresh = False
    else:
        items = feed_body.get("items")
        valid = [i for i in items if isinstance(i, dict) and isinstance(i.get("id"), str) and i["id"].strip()] if isinstance(items, list) else []
        fresh = contract.classify_manifest_freshness(feed_body.get("generated_at"), now=now)
        feed_eval.update({"generated_at": feed_body.get("generated_at"), "advisory_count": len(valid), **fresh})
        if not valid:
            failures.append("public feed contains no intelligence items")
        if fresh["state"] != contract.FRESH:
            failures.append(
                f"public feed is {fresh['state']} (generated_at={feed_body.get('generated_at')}, "
                f"age_seconds={fresh['age_seconds']}, max_age_seconds={fresh['max_age_seconds']})"
            )
        feed_fresh = bool(valid) and fresh["state"] == contract.FRESH

    health_eval = {"http_status": health_status}
    h_status = health_body.get("status") if isinstance(health_body, dict) else None
    health_eval["status"] = h_status
    if health_err and health_status is None:
        failures.append(f"/api/health unreachable ({health_err})")
    elif h_status == "ok" and not feed_fresh:
        failures.append("/api/health reports status 'ok' while the public feed is not fresh (contract violation)")
    elif feed_fresh and (health_status != 200 or h_status != "ok"):
        failures.append(f"/api/health is not ok (HTTP {health_status}, status={h_status!r}) although the public feed is fresh")

    return {
        "gate": "public_feed_freshness",
        "verdict": "PASS" if not failures else "FAIL",
        "failures": failures,
        "feed": feed_eval,
        "health": health_eval,
        "max_public_manifest_age_hours": contract.max_public_manifest_age_hours(),
        "checked_at": (now or datetime.now(timezone.utc)).isoformat(timespec="seconds").replace("+00:00", "Z"),
    }


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--base-url", default=DEFAULT_BASE)
    ap.add_argument("--timeout", type=float, default=30.0)
    args = ap.parse_args(argv)

    cb = str(int(time.time()))
    base = args.base_url.rstrip("/")
    feed = _get_json(f"{base}/api/v1/intel/latest.json?freshness_gate={cb}", args.timeout)
    health = _get_json(f"{base}/api/health?freshness_gate={cb}", args.timeout)
    report = evaluate(*feed, *health)

    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
    print(json.dumps(report, indent=2))
    if report["verdict"] != "PASS":
        for f in report["failures"]:
            print(f"::error::PUBLIC FEED FRESHNESS GATE: {f}", flush=True)
        return 1
    print("::notice::PUBLIC FEED FRESHNESS GATE: PASS -- customer feed fresh and /api/health agrees.", flush=True)
    return 0


if __name__ == "__main__":
    sys.exit(main())
