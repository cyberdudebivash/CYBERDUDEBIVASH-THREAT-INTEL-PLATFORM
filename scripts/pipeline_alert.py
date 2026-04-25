#!/usr/bin/env python3
"""
pipeline_alert.py - SENTINEL APEX v141.0 Pipeline Failure/Success Alerting
===========================================================================
Sends structured Telegram alerts on pipeline state changes.
Called by GitHub Actions workflow on failure or significant events.

Usage:
  python3 scripts/pipeline_alert.py --status failure --run-id 123 --run-url https://...
  python3 scripts/pipeline_alert.py --status success --items 42 --version 141.0.0

Env:
  TELEGRAM_BOT_TOKEN  - Bot token from @BotFather
  TELEGRAM_CHAT_ID    - Chat/channel to post into
  GITHUB_REPOSITORY   - Auto-set by GitHub Actions
  GITHUB_RUN_ID       - Auto-set by GitHub Actions
"""
import os
import sys
import json
import argparse
import logging
import urllib.request
import urllib.error
from datetime import datetime, timezone

logging.basicConfig(level=logging.INFO, format="%(asctime)s [PIPELINE-ALERT] %(message)s")
log = logging.getLogger("pipeline-alert")


def send_telegram(token: str, chat_id: str, text: str) -> bool:
    """Send a Telegram message. Returns True on success."""
    url = f"https://api.telegram.org/bot{token}/sendMessage"
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": "HTML",
        "disable_web_page_preview": True,
    }).encode("utf-8")
    try:
        req = urllib.request.Request(
            url,
            data=payload,
            headers={"Content-Type": "application/json"},
            method="POST",
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            result = json.loads(resp.read())
            return result.get("ok", False)
    except Exception as e:
        log.error(f"Telegram send failed: {e}")
        return False


def build_failure_message(args) -> str:
    repo     = os.environ.get("GITHUB_REPOSITORY", "cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM")
    run_id   = os.environ.get("GITHUB_RUN_ID", args.run_id or "N/A")
    run_url  = args.run_url or f"https://github.com/{repo}/actions/runs/{run_id}"
    ts       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    return (
        f"🚨 <b>SENTINEL APEX — PIPELINE FAILURE</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⏱  <b>Time:</b> {ts}\n"
        f"🔢 <b>Run ID:</b> <code>{run_id}</code>\n"
        f"📦 <b>Repo:</b> <code>{repo}</code>\n"
        f"🔴 <b>Status:</b> FAILED\n"
        f"💬 <b>Detail:</b> {args.message or 'Pipeline step failed. Check workflow logs.'}\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🔗 <a href=\"{run_url}\">View Workflow Run →</a>\n"
        f"⚠️ Immediate review required — platform data may be stale."
    )


def build_success_message(args) -> str:
    repo     = os.environ.get("GITHUB_REPOSITORY", "cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM")
    run_id   = os.environ.get("GITHUB_RUN_ID", args.run_id or "N/A")
    ts       = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    items    = args.items or "N/A"
    version  = args.version or os.environ.get("PIPELINE_VERSION", "141.0.0")

    return (
        f"✅ <b>SENTINEL APEX — PIPELINE COMPLETE</b>\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"⏱  <b>Time:</b> {ts}\n"
        f"🔢 <b>Run:</b> <code>{run_id}</code> | <b>v{version}</b>\n"
        f"📊 <b>Intel advisories:</b> {items}\n"
        f"🟢 <b>Status:</b> HEALTHY\n"
        f"━━━━━━━━━━━━━━━━━━━━━━━━\n"
        f"🌐 <a href=\"https://intel.cyberdudebivash.com\">Open Platform →</a>"
    )


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX pipeline alerting")
    parser.add_argument("--status",  required=True, choices=["failure", "success", "warning"],
                        help="Pipeline execution outcome")
    parser.add_argument("--message", default="",    help="Optional detail message")
    parser.add_argument("--run-id",  default="",    help="Workflow run ID (auto from env)")
    parser.add_argument("--run-url", default="",    help="Direct URL to workflow run")
    parser.add_argument("--items",   default="",    help="Number of intel items processed")
    parser.add_argument("--version", default="",    help="Platform version string")
    args = parser.parse_args()

    token   = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    chat_id = os.environ.get("TELEGRAM_CHAT_ID", "").strip()

    if not token or not chat_id:
        log.warning("TELEGRAM_BOT_TOKEN or TELEGRAM_CHAT_ID not set — skipping alert.")
        sys.exit(0)

    if args.status == "failure":
        text = build_failure_message(args)
    elif args.status == "success":
        # Only send success alerts occasionally to avoid noise (can be suppressed)
        suppress = os.environ.get("TELEGRAM_SUPPRESS_SUCCESS", "true").lower()
        if suppress == "true":
            log.info("Success alert suppressed (TELEGRAM_SUPPRESS_SUCCESS=true). Set to 'false' to enable.")
            sys.exit(0)
        text = build_success_message(args)
    else:  # warning
        text = (
            f"⚠️ <b>SENTINEL APEX — PIPELINE WARNING</b>\n"
            f"Time: {datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')}\n"
            f"Detail: {args.message or 'Non-critical pipeline issue detected.'}"
        )

    ok = send_telegram(token, chat_id, text)
    if ok:
        log.info(f"Alert sent successfully — status={args.status}")
    else:
        log.error("Alert delivery failed.")
    # Never block the pipeline on alert failure
    sys.exit(0)


if __name__ == "__main__":
    main()
