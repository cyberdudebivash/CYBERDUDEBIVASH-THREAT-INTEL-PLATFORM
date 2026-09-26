#!/usr/bin/env python3
"""
scripts/intel_freshness_guard.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- self-healing public intelligence freshness guard

P0 2026-09-26. The public feed went 9h+ stale (contract: 6h,
config/public_freshness_contract.json) although ingestion itself worked:
the last completed sentinel-blogger run published advisories 17 minutes old.
Nothing had RUN. Evidence (GitHub Actions API):

  19:57:06Z  UI File Guardian starts in concurrency group sentinel-data-writer
  19:57:14Z  sentinel-blogger (the ingest + publish pipeline) queues PENDING
  20:00:38Z  Bug Hunter Resilient Recon queues in the same group
  20:00:39Z  GitHub cancels the pending sentinel-blogger run (a concurrency
             group keeps at most ONE pending run; the newer one wins)
  04:41:37Z  next scheduled sentinel-blogger start (GitHub cron delay ~4.7h)

29 workflows share sentinel-data-writer, so the publisher can be displaced
by any of them, and nothing re-queued it. The existing Pipeline Staleness
Monitor watches workflow-run history, not the published feed, and only
alerts.

This guard watches the PUBLISHED feed (the gateway's public /api/health,
which applies the canonical contract) and, when it is older than
DISPATCH_AT_HOURS with no sentinel-blogger run active or queued, dispatches
one. It never publishes, writes data or edits a timestamp itself: a stale
feed is only ever cured by a real pipeline run.

Loop safety: it dispatches only when no publisher run is in flight; a guard
dispatch is not repeated within COOLDOWN_MINUTES; and when the guard's own
recent dispatch FAILED (the pipeline itself is broken) it stops dispatching
and fails loudly instead of retrying a broken pipeline every 30 minutes.

Exit codes: 0 healthy / dispatched / waiting on an active run,
            1 needs a human (health unreadable, publisher failing,
              dispatch refused).
Stdlib only.
"""
from __future__ import annotations

import json
import os
import sys
import urllib.error
import urllib.request
from datetime import datetime, timezone

HEALTH_URL = os.environ.get("HEALTH_URL", "https://intel.cyberdudebivash.com/api/health")
REPO = os.environ.get("REPO", "cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM")
WORKFLOW = os.environ.get("PUBLISHER_WORKFLOW", "sentinel-blogger.yml")
REF = os.environ.get("PUBLISHER_REF", "main")
# The publisher takes ~75-85 min; dispatching at 4h keeps a displaced run's
# replacement inside the 6h contract.
DISPATCH_AT_HOURS = float(os.environ.get("DISPATCH_AT_HOURS", "4"))
COOLDOWN_MINUTES = float(os.environ.get("COOLDOWN_MINUTES", "90"))
DRY_RUN = os.environ.get("DRY_RUN", "") == "1"
ACTIVE_STATUSES = ("queued", "in_progress", "waiting", "pending", "requested")
# A real publisher run is killed by its own job timeout (130 min). An
# "active" run older than this is a zombie (one has sat "pending" since
# 2026-05-26) and must not suppress dispatch forever.
ACTIVE_MAX_AGE_HOURS = float(os.environ.get("ACTIVE_MAX_AGE_HOURS", "6"))
GUARD_ACTOR = "github-actions[bot]"


def decide(health: dict | None, active_runs: list, guard_dispatches: list, now: datetime) -> dict:
    """Pure decision. health: parsed /api/health JSON (or None when
    unreadable). active_runs: publisher runs in an ACTIVE_STATUSES state.
    guard_dispatches: this guard's recent workflow_dispatch runs of the
    publisher, newest first, each {created_at, status, conclusion}."""
    intel = (health or {}).get("intelligence") or {}
    age = intel.get("age_seconds")
    state = intel.get("status")
    if health is None or state is None:
        return {"action": "alert", "reason": "health_unreadable", "exit": 1}
    if state == "fresh" and isinstance(age, (int, float)) and age < DISPATCH_AT_HOURS * 3600:
        return {"action": "none", "reason": "fresh", "age_seconds": age, "exit": 0}
    # stale, aging toward stale, or an untrustworthy timestamp: the cure is a run.
    live_runs = [r for r in active_runs if (now - _parse(r["created_at"])).total_seconds() < ACTIVE_MAX_AGE_HOURS * 3600]
    if live_runs:
        return {"action": "none", "reason": "publisher_active", "age_seconds": age, "exit": 0}
    if guard_dispatches:
        last = guard_dispatches[0]
        mins = (now - _parse(last["created_at"])).total_seconds() / 60
        if last.get("conclusion") == "failure" and mins < 4 * 60:
            return {"action": "alert", "reason": "publisher_failing", "age_seconds": age, "exit": 1}
        if mins < COOLDOWN_MINUTES and last.get("conclusion") != "cancelled":
            return {"action": "none", "reason": "cooldown", "age_seconds": age, "exit": 0}
    return {"action": "dispatch", "reason": "stale_no_active_publisher" if state != "fresh" else "approaching_stale",
            "age_seconds": age, "exit": 0}


def _parse(iso: str) -> datetime:
    return datetime.fromisoformat(iso.replace("Z", "+00:00"))


def _get_json(url: str, token: str | None = None) -> tuple[int, dict | None]:
    req = urllib.request.Request(url, headers={"Accept": "application/json", "User-Agent": "cdb-intel-freshness-guard/1",
                                               **({"Authorization": f"Bearer {token}"} if token else {})})
    try:
        with urllib.request.urlopen(req, timeout=20) as r:
            return r.status, json.loads(r.read().decode("utf-8"))
    except urllib.error.HTTPError as e:  # /api/health answers 503 WITH a body when stale
        try:
            return e.code, json.loads(e.read().decode("utf-8"))
        except Exception:
            return e.code, None
    except Exception:
        return 0, None


def main() -> int:
    token = os.environ.get("GITHUB_TOKEN", "")
    now = datetime.now(timezone.utc)
    _, health = _get_json(HEALTH_URL)
    api = f"https://api.github.com/repos/{REPO}/actions/workflows/{WORKFLOW}/runs"
    active_by_id = {}
    for status in ACTIVE_STATUSES:  # GitHub's status filters overlap: dedupe by run id
        _, body = _get_json(f"{api}?status={status}&per_page=5", token)
        for r in (body or {}).get("workflow_runs", []):
            active_by_id[r["id"]] = r
    active = list(active_by_id.values())
    _, body = _get_json(f"{api}?event=workflow_dispatch&per_page=10", token)
    guard = [r for r in (body or {}).get("workflow_runs", []) if (r.get("actor") or {}).get("login") == GUARD_ACTOR]
    guard.sort(key=lambda r: r["created_at"], reverse=True)
    verdict = decide(health, active, guard, now)
    if verdict["action"] == "dispatch" and not DRY_RUN:
        req = urllib.request.Request(
            f"https://api.github.com/repos/{REPO}/actions/workflows/{WORKFLOW}/dispatches",
            data=json.dumps({"ref": REF}).encode(), method="POST",
            headers={"Accept": "application/vnd.github+json", "Authorization": f"Bearer {token}",
                     "Content-Type": "application/json", "User-Agent": "cdb-intel-freshness-guard/1"})
        try:
            with urllib.request.urlopen(req, timeout=20) as r:
                verdict["dispatch_status"] = r.status
        except urllib.error.HTTPError as e:
            verdict.update({"dispatch_status": e.code, "action": "alert", "reason": "dispatch_refused", "exit": 1})
    report = {"at": now.isoformat(), "health_url": HEALTH_URL, "workflow": WORKFLOW, "dry_run": DRY_RUN,
              "feed_generated_at": ((health or {}).get("intelligence") or {}).get("generated_at"),
              "active_publisher_runs": len(active), **verdict}
    print(json.dumps(report, indent=2))
    summary = os.environ.get("GITHUB_STEP_SUMMARY")
    if summary:
        with open(summary, "a", encoding="utf-8") as f:
            f.write(f"### Intel freshness guard: {verdict['action']} ({verdict['reason']})\n\n```json\n{json.dumps(report, indent=2)}\n```\n")
    if verdict["exit"]:
        print(f"::error title=Intel freshness guard::{verdict['reason']} -- feed age {verdict.get('age_seconds')}s", file=sys.stderr)
    return verdict["exit"]


if __name__ == "__main__":
    sys.exit(main())
