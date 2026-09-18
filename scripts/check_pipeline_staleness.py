#!/usr/bin/env python3
# v184.0 -- monetization gate wiring fix applied; sentinel-blogger re-trigger
"""
scripts/check_pipeline_staleness.py
CYBERDUDEBIVASH(R) SENTINEL APEX - Pipeline Staleness Monitor

Checks GitHub Actions workflows for staleness. Alerts via Telegram if
critical pipelines haven't succeeded within their expected cadence.

Env vars:
  GITHUB_TOKEN / GH_TOKEN  - GitHub token for API access
  TG_BOT_TOKEN             - Telegram bot token (optional - skip alert if missing)
  TG_CHAT_ID               - Telegram chat ID (optional)
  REPO                     - GitHub repo (default: cyberdudebivash/cyberdudebivash-threat-intel-platform)
  STALENESS_THRESHOLD_HOURS - Override default per-workflow threshold (optional)
"""
import os
import sys
import json
import urllib.request
import urllib.error
import datetime

REPO = os.environ.get("REPO", "cyberdudebivash/cyberdudebivash-threat-intel-platform")
GH_TOKEN = os.environ.get("GITHUB_TOKEN") or os.environ.get("GH_TOKEN", "")
TG_BOT_TOKEN = os.environ.get("TG_BOT_TOKEN", "")
TG_CHAT_ID = os.environ.get("TG_CHAT_ID", "")
OVERRIDE_THRESHOLD = os.environ.get("STALENESS_THRESHOLD_HOURS", "")

# v185.0 P0 FIX (2026-09-10): sentinel-blogger and status-monitor's
# thresholds were tighter than the workflows they monitor can ever actually
# satisfy, guaranteeing recurring false alarms regardless of platform health.
#
# Both run on the identical cron '0 0,8,16 * * *' (3x/day, nominal 8h gaps).
# status-monitor's threshold was 3h -- stale by this monitor's own definition
# for 5+ of every 8 hours, every single day, forever. Confirmed live via the
# GitHub Actions API (5 consecutive successful runs, 2026-09-08/09/10):
# observed gaps were 7h58m / 9h31m / 6h21m / 8h08m -- GitHub's own scheduler
# documents that cron runs "may be delayed during periods of high load",
# which this repository (dozens of scheduled workflows) clearly has, and the
# observed gaps confirm it empirically rather than assuming a clean 8h.
# sentinel-blogger shares that same cron with a 8h threshold -- zero margin
# for that same jitter, on the CRITICAL-severity entry whose alert firing
# hard-fails this job (sys.exit(1)), not just a soft Telegram notice.
#
# Fixed to 16h (2x the 8h nominal cadence) for both: comfortably clear of
# the worst gap observed above with room to spare for future jitter spikes,
# while still catching a genuine multi-cycle failure (radio silence for a
# full day+) far faster than the days-long undetected 2026-08-26 core-feed
# staleness incident this monitoring exists to prevent a repeat of.
#
# Writing that safety rule as an actual mechanical test (below) rather than
# hand-fixing just these two found a THIRD undersized threshold in the same
# list: Automated Backup's 26h against its own 24h daily cadence is only an
# 8% margin, not the 1.3x this incident establishes as the real bar. Left
# uncorrected, this would just be next month's version of today's alert.
# Raised to 32h (~1.33x, same margin generate-and-sync already had headroom
# for at 8h/6h) -- still same-day detection of a genuinely broken daily
# backup, not the 48h a strict 2x-cadence rule would have given it.
#
# test_pipeline_staleness_thresholds.py's test_threshold_has_real_safety_margin
# mechanically parses every entry's own workflow file cron schedule and
# fails the build if any threshold here ever again provides less than 1.3x
# headroom over that workflow's actual maximum scheduled gap -- so this
# exact misconfiguration class cannot silently return, for these rows or any
# added later.
MONITORED_WORKFLOWS = [
    {"file": "sentinel-blogger.yml",   "name": "sentinel-blogger",    "max_age_hours": 16, "severity": "CRITICAL"},
    {"file": "generate-and-sync.yml",  "name": "generate-and-sync",   "max_age_hours": 8,  "severity": "HIGH"},
    {"file": "automated-backup.yml",   "name": "Automated Backup",    "max_age_hours": 32, "severity": "HIGH"},
    {"file": "deploy-worker.yml",      "name": "Deploy Worker",       "max_age_hours": 0,  "severity": "INFO"},
    {"file": "status-monitor.yml",     "name": "CDB Platform Status", "max_age_hours": 16, "severity": "MEDIUM"},
    # P0 RUNTIME INTELLIGENCE STATE RECOVERY mission (2026-09-10): both run
    # on a 6h cron ('15 */6 * * *' / '45 */6 * * *'). 12h = 2x nominal
    # cadence, matching this list's own established ratio for the other
    # 6-8h-cadence entries above (sentinel-blogger/status-monitor also use
    # 2x). Verified against real observed gaps for these exact two
    # workflows during this mission's forensic pass (4h18m-7h47m,
    # non-uniform due to GitHub's own scheduling jitter under load) --12h
    # clears the worst observed gap (~7h47m) with ~1.5x real margin on top,
    # deliberately not repeating the earlier pipeline-monitor bug where a
    # 3h threshold monitored a workflow that naturally ran roughly every 8h.
    {"file": "sovereign-platform.yml",  "name": "sovereign-platform",  "max_age_hours": 12, "severity": "HIGH"},
    {"file": "genesis-powerhouse.yml",  "name": "genesis-powerhouse",  "max_age_hours": 12, "severity": "HIGH"},
]


def gh_get(path):
    url = f"https://api.github.com/repos/{REPO}{path}"
    headers = {
        "Accept": "application/vnd.github+json",
        "X-GitHub-Api-Version": "2022-11-28",
    }
    if GH_TOKEN:
        headers["Authorization"] = f"Bearer {GH_TOKEN}"
    req = urllib.request.Request(url, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read().decode("utf-8"))
    except urllib.error.HTTPError as e:
        print(f"  GH API {path} -> HTTP {e.code}")
        return None


def get_last_success(workflow_file):
    data = gh_get(f"/actions/workflows/{workflow_file}/runs?per_page=1&status=success")
    if not data or not data.get("workflow_runs"):
        return None
    run = data["workflow_runs"][0]
    return {
        "created_at": run["created_at"],
        "updated_at": run["updated_at"],
        "run_id": run["id"],
        "conclusion": run["conclusion"],
        "html_url": run["html_url"],
    }


def get_latest_run(workflow_file):
    """Most recent run of ANY status/conclusion -- diagnostics only, never
    used for the staleness decision itself (get_last_success()'s
    status=success query remains the sole source of truth for that).

    P0 FIX (2026-09-18, Telegram staleness-alert incident): a stale alert
    previously linked only to the last SUCCESSFUL run -- during the
    automated-backup.yml incident that was an 8-day-old green checkmark,
    which is exactly what made a real, ongoing failure (cf-data-backup
    cancelling every day since) look like a false alarm on inspection: the
    thing actually broken right now (the most recent run) was never shown,
    only the last time everything was fine. Used by _latest_run_suffix()
    below to append what's actually happening right now to every alert.
    """
    data = gh_get(f"/actions/workflows/{workflow_file}/runs?per_page=1")
    if not data or not data.get("workflow_runs"):
        return None
    run = data["workflow_runs"][0]
    return {
        "status": run["status"],
        "conclusion": run["conclusion"],
        "updated_at": run["updated_at"],
        "html_url": run["html_url"],
    }


def _latest_run_suffix(workflow_file):
    """Best-effort diagnostic suffix for an alert message -- swallows its
    own errors so a lookup that exists purely to make an alert more
    readable can never itself break primary alerting."""
    try:
        latest = get_latest_run(workflow_file)
    except Exception:
        return ""
    if not latest:
        return ""
    latest_age = age_hours(latest["updated_at"])
    outcome = latest["conclusion"] or latest["status"]
    return f" | Most recent run: {outcome} ({latest_age:.1f}h ago) - {latest['html_url']}"


def age_hours(iso_ts):
    if not iso_ts:
        return float("inf")
    dt = datetime.datetime.fromisoformat(iso_ts.replace("Z", "+00:00"))
    now = datetime.datetime.now(datetime.timezone.utc)
    return (now - dt).total_seconds() / 3600


def send_telegram(msg):
    if not TG_BOT_TOKEN or not TG_CHAT_ID:
        print("  Telegram not configured - skipping alert")
        return
    url = f"https://api.telegram.org/bot{TG_BOT_TOKEN}/sendMessage"
    body = json.dumps({"chat_id": TG_CHAT_ID, "text": msg, "parse_mode": "HTML"}).encode("utf-8")
    req = urllib.request.Request(url, data=body, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            print("  Telegram alert sent")
    except Exception as e:
        print(f"  WARN: Telegram alert failed: {e}")


def main():
    now = datetime.datetime.now(datetime.timezone.utc)
    print(f"=== SENTINEL APEX Pipeline Staleness Check | {now.strftime('%Y-%m-%d %H:%M UTC')} ===")

    override_hours = float(OVERRIDE_THRESHOLD) if OVERRIDE_THRESHOLD else None
    alerts = []
    status_lines = []

    for wf in MONITORED_WORKFLOWS:
        if wf["max_age_hours"] == 0:
            continue  # INFO-level, no staleness check

        threshold = override_hours if override_hours else wf["max_age_hours"]
        print(f"\n[{wf['name']}] (threshold: {threshold}h)")

        run = get_last_success(wf["file"])
        if not run:
            msg = f"No successful run found for {wf['name']}" + _latest_run_suffix(wf["file"])
            print(f"  STALE: {msg}")
            alerts.append((wf["severity"], wf["name"], msg))
            status_lines.append(f"[{wf['severity']}] {wf['name']}: NO RUNS")
            continue

        hours_ago = age_hours(run["updated_at"])
        print(f"  Last success: {run['updated_at']} ({hours_ago:.1f}h ago)")

        if hours_ago > threshold:
            msg = (
                f"Last success was {hours_ago:.1f}h ago (threshold: {threshold}h) - {run['html_url']}"
                + _latest_run_suffix(wf["file"])
            )
            print(f"  STALE: {msg}")
            alerts.append((wf["severity"], wf["name"], msg))
            status_lines.append(f"[{wf['severity']}] {wf['name']}: STALE ({hours_ago:.1f}h)")
        else:
            print(f"  OK")
            status_lines.append(f"[OK] {wf['name']}: {hours_ago:.1f}h ago")

    print(f"\n=== Summary ===")
    for line in status_lines:
        print(f"  {line}")

    if alerts:
        critical = [a for a in alerts if a[0] == "CRITICAL"]
        high = [a for a in alerts if a[0] == "HIGH"]

        tg_lines = [
            "<b>SENTINEL APEX - Pipeline Staleness Alert</b>",
            f"Time: {now.strftime('%Y-%m-%d %H:%M UTC')}",
            "",
        ]
        for sev, name, msg in alerts:
            emoji = "CRITICAL" if sev == "CRITICAL" else "WARNING" if sev == "HIGH" else "INFO"
            tg_lines.append(f"[{emoji}] <b>{name}</b>")
            tg_lines.append(f"  {msg}")

        send_telegram("\n".join(tg_lines))

        if critical:
            print(f"\nFATAL: {len(critical)} CRITICAL staleness alerts")
            sys.exit(1)
        elif high:
            print(f"\nWARN: {len(high)} HIGH staleness alerts")
            sys.exit(0)
    else:
        print("\nAll pipelines healthy.")


if __name__ == "__main__":
    main()
