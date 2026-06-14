#!/usr/bin/env python3
# v180.0 -- monetization gate wiring fix applied; sentinel-blogger re-trigger
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

MONITORED_WORKFLOWS = [
    {"file": "sentinel-blogger.yml",   "name": "sentinel-blogger",    "max_age_hours": 8,  "severity": "CRITICAL"},
    {"file": "generate-and-sync.yml",  "name": "generate-and-sync",   "max_age_hours": 8,  "severity": "HIGH"},
    {"file": "automated-backup.yml",   "name": "Automated Backup",    "max_age_hours": 26, "severity": "HIGH"},
    {"file": "deploy-worker.yml",      "name": "Deploy Worker",       "max_age_hours": 0,  "severity": "INFO"},
    {"file": "status-monitor.yml",     "name": "CDB Platform Status", "max_age_hours": 3,  "severity": "MEDIUM"},
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
            msg = f"No successful run found for {wf['name']}"
            print(f"  STALE: {msg}")
            alerts.append((wf["severity"], wf["name"], msg))
            status_lines.append(f"[{wf['severity']}] {wf['name']}: NO RUNS")
            continue

        hours_ago = age_hours(run["updated_at"])
        print(f"  Last success: {run['updated_at']} ({hours_ago:.1f}h ago)")

        if hours_ago > threshold:
            msg = f"Last success was {hours_ago:.1f}h ago (threshold: {threshold}h) - {run['html_url']}"
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
