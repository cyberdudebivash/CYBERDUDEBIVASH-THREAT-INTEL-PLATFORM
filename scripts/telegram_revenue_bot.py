#!/usr/bin/env python3
"""
scripts/telegram_revenue_bot.py
CYBERDUDEBIVASH® SENTINEL APEX v141.0.0 — Telegram Revenue Automation Bot
===========================================================================
AUTOMATED REVENUE ENGINE: Reads live feed → formats threat brief →
sends to Telegram channel → drives upgrade CTAs → captures leads.

Runs via GitHub Actions cron (daily 08:00 UTC) + manual trigger.

Revenue flows driven:
  1. Daily threat brief → paywall CTA → get-api-key.html (API subscriptions)
  2. Weekly top-10 → detection pack link → store.html (Gumroad products)
  3. Critical P1 alerts → immediate upsell message (urgency conversion)
  4. Monthly enterprise pitch → contact-enterprise.html (big ticket)

Environment variables required:
  TELEGRAM_BOT_TOKEN   — Bot token from @BotFather
  TELEGRAM_CHANNEL_ID  — Channel/group ID (e.g. @cdbsentinapex or -100XXXXXXX)

Optional:
  TELEGRAM_ALERT_CHAT_ID — Private chat for P1 critical alerts (admin only)
  FEED_PATH              — Path to feed.json (default: feed.json)

(c) 2026 CYBERDUDEBIVASH Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import json
import logging
import os
import sys
import urllib.request
import urllib.parse
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [TG-BOT] %(levelname)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("sentinel.telegram_bot")

# ── Constants ─────────────────────────────────────────────────────────────────
PLATFORM_URL   = "https://intel.cyberdudebivash.com"
STORE_URL      = f"{PLATFORM_URL}/store.html"
API_KEY_URL    = f"{PLATFORM_URL}/get-api-key.html"
ENTERPRISE_URL = f"{PLATFORM_URL}/contact-enterprise.html"
SERVICES_URL   = f"{PLATFORM_URL}/services.html"
PRICING_URL    = f"{PLATFORM_URL}/pricing.html"
TG_API_BASE    = "https://api.telegram.org/bot{token}"

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
}

TIER_UPSELL = {
    # revenue message mapped by content type
    "critical_threat": (
        "🔒 *FULL INTEL LOCKED* — IOC list, kill chain & STIX bundle require *Pro tier*.\n"
        f"⚡ [Unlock now — from $49/mo]({API_KEY_URL}?plan=pro&utm_source=tg_critical)"
    ),
    "daily_brief": (
        "📦 *Get the full detection pack* — Sigma + YARA + KQL rules for today's top threats.\n"
        f"🛒 [Browse Detection Packs — from $179]({STORE_URL}?utm_source=tg_daily#detection-packs)"
    ),
    "weekly_digest": (
        "🏢 *Enterprise SOC API* — STIX 2.1, SIEM webhooks, AI predictions, 117+ advisories/day.\n"
        f"📊 [Start Enterprise Trial]({ENTERPRISE_URL}?utm_source=tg_weekly)"
    ),
}


# ── Telegram API ──────────────────────────────────────────────────────────────
def tg_request(token: str, method: str, payload: dict) -> dict:
    url = TG_API_BASE.format(token=token) + f"/{method}"
    body = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=body,
                                  headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return json.loads(resp.read())
    except urllib.error.HTTPError as e:
        err = e.read().decode(errors="replace")
        log.error("TG %s HTTP %d: %s", method, e.code, err[:300])
        return {"ok": False, "error": err}
    except Exception as e:
        log.error("TG %s error: %s", method, e)
        return {"ok": False, "error": str(e)}


def send_message(token: str, chat_id: str, text: str,
                  parse_mode: str = "Markdown",
                  disable_web_page_preview: bool = True) -> bool:
    result = tg_request(token, "sendMessage", {
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": disable_web_page_preview,
    })
    ok = result.get("ok", False)
    if not ok:
        log.warning("sendMessage failed: %s", result.get("error", result))
    else:
        log.info("Message sent: %d chars", len(text))
    return ok


# ── Feed Loader ───────────────────────────────────────────────────────────────
def load_feed(feed_path: str = "feed.json") -> list[dict]:
    p = Path(feed_path)
    if not p.exists():
        p = Path("api/feed.json")
    if not p.exists():
        log.error("No feed.json found")
        return []
    with open(p, encoding="utf-8") as f:
        data = json.load(f)
    if isinstance(data, list):
        return data
    if isinstance(data, dict):
        return data.get("items", data.get("data", []))
    return []


def top_threats(feed: list[dict], n: int = 5,
                severity_filter: str | None = None) -> list[dict]:
    """Return top-N threats sorted by risk_score desc."""
    items = feed
    if severity_filter:
        items = [i for i in items if i.get("severity", "").upper() == severity_filter.upper()]
    return sorted(items, key=lambda x: float(x.get("risk_score", 0)), reverse=True)[:n]


# ── Message Formatters ────────────────────────────────────────────────────────
def fmt_threat_line(item: dict, idx: int = 0) -> str:
    sev   = item.get("severity", "UNKNOWN").upper()
    emoji = SEVERITY_EMOJI.get(sev, "⚪")
    title = item.get("title", "Unknown Threat")[:70]
    risk  = item.get("risk_score", 0)
    iocs  = item.get("ioc_count", 0)
    ttps  = item.get("ttp_count", 0)
    kev   = " ⚡KEV" if item.get("kev_present") else ""
    report = item.get("report_url", "")
    if report and not report.startswith("http"):
        report = PLATFORM_URL + report
    line = f"{emoji} *#{idx+1} {sev}* — Risk {risk}/10{kev}\n`{title}`\n"
    line += f"   IOCs: {iocs} | TTPs: {ttps}"
    if report:
        line += f" | [Full Report]({report})"
    return line


def build_daily_brief(feed: list[dict]) -> str:
    """Daily automated threat brief — sent 08:00 UTC."""
    now = datetime.now(timezone.utc)
    date_str = now.strftime("%d %b %Y")
    threats = top_threats(feed, n=5)
    criticals = [i for i in feed if i.get("severity", "").upper() == "CRITICAL"]
    kev_count = sum(1 for i in feed if i.get("kev_present"))
    total = len(feed)

    lines = [
        f"🛡️ *SENTINEL APEX — Daily Threat Brief*",
        f"📅 {date_str} | {now.strftime('%H:%M')} UTC\n",
        f"📊 Feed: *{total}* advisories | *{len(criticals)}* Critical | *{kev_count}* CISA KEV\n",
        "─" * 30,
        "*🔥 TOP THREATS TODAY:*\n",
    ]
    for i, t in enumerate(threats):
        lines.append(fmt_threat_line(t, i))
        lines.append("")

    lines += [
        "─" * 30,
        TIER_UPSELL["daily_brief"],
        "",
        f"🌐 [Live Dashboard]({PLATFORM_URL}) | "
        f"📖 [API Docs]({PLATFORM_URL}/api-docs.html) | "
        f"🏢 [Enterprise]({ENTERPRISE_URL})",
        "",
        f"_CYBERDUDEBIVASH® SENTINEL APEX v141.0.0_",
    ]
    return "\n".join(lines)


def build_weekly_digest(feed: list[dict]) -> str:
    """Weekly enterprise digest — sent Monday 06:00 UTC."""
    now = datetime.now(timezone.utc)
    threats = top_threats(feed, n=10)
    total = len(feed)
    critical_count = sum(1 for i in feed if i.get("severity","").upper() == "CRITICAL")
    kev_count = sum(1 for i in feed if i.get("kev_present"))

    # Technique frequency
    ttp_freq: dict[str, int] = {}
    for item in feed:
        for t in item.get("ttps", []):
            if isinstance(t, str) and t.startswith("T"):
                ttp_freq[t] = ttp_freq.get(t, 0) + 1
    top_ttps = sorted(ttp_freq.items(), key=lambda x: -x[1])[:5]

    lines = [
        "🏢 *SENTINEL APEX — Weekly Intelligence Digest*",
        f"📅 Week of {now.strftime('%d %b %Y')} | Enterprise Edition\n",
        f"📈 *Platform Stats:*",
        f"  • Total advisories: *{total}*",
        f"  • Critical threats: *{critical_count}*",
        f"  • CISA KEV active: *{kev_count}*",
        f"  • Top technique: *{top_ttps[0][0] if top_ttps else 'N/A'}* (×{top_ttps[0][1] if top_ttps else 0})\n",
        "─" * 30,
        "*🎯 TOP 10 THREATS THIS WEEK:*\n",
    ]
    for i, t in enumerate(threats):
        lines.append(fmt_threat_line(t, i))
        lines.append("")

    if top_ttps:
        lines += [
            "─" * 30,
            "*📊 Most Active ATT&CK Techniques:*",
        ]
        for ttp, cnt in top_ttps:
            lines.append(f"  `{ttp}` — ×{cnt} occurrences")
        lines.append("")

    lines += [
        "─" * 30,
        TIER_UPSELL["weekly_digest"],
        "",
        f"📦 [Detection Packs — from $179]({STORE_URL}?utm_source=tg_weekly#detection-packs)",
        f"🤝 [Managed SOC Services]({SERVICES_URL}?utm_source=tg_weekly)",
        f"💲 [View All Pricing]({PRICING_URL}?utm_source=tg_weekly)\n",
        f"_CYBERDUDEBIVASH® SENTINEL APEX v141.0.0_",
    ]
    return "\n".join(lines)


def build_p1_alert(item: dict) -> str:
    """Immediate P1 alert for critical/KEV threats — conversion urgency."""
    title  = item.get("title", "Unknown")[:80]
    risk   = item.get("risk_score", 10)
    iocs   = item.get("ioc_count", 0)
    kev    = item.get("kev_present", False)
    epss   = item.get("epss_score")
    cvss   = item.get("cvss_score")
    report = item.get("report_url", "")
    if report and not report.startswith("http"):
        report = PLATFORM_URL + report

    lines = [
        "🚨 *SENTINEL APEX — P1 CRITICAL ALERT*\n",
        f"⚠️ *{title}*\n",
        f"🔴 Risk: *{risk}/10* | CVSS: *{cvss or 'Pending'}* | EPSS: *{epss or 'Pending'}*",
    ]
    if kev:
        lines.append("⚡ *CISA KEV CONFIRMED — Active exploitation in the wild*")
    lines += [
        f"🧬 IOCs detected: *{iocs}* (Pro tier required for full list)",
        "",
        TIER_UPSELL["critical_threat"],
        "",
    ]
    if report:
        lines.append(f"📋 [View Full Tactical Dossier]({report})")
    lines += [
        f"🌐 [Live Feed]({PLATFORM_URL})",
        f"\n_CYBERDUDEBIVASH® SENTINEL APEX — SOC Priority 1_",
    ]
    return "\n".join(lines)


# ── Main Orchestration ────────────────────────────────────────────────────────
def main() -> int:
    token      = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
    channel_id = os.environ.get("TELEGRAM_CHANNEL_ID", "").strip()
    alert_chat = os.environ.get("TELEGRAM_ALERT_CHAT_ID", "").strip()
    mode       = os.environ.get("TELEGRAM_MODE", "daily").strip().lower()
    feed_path  = os.environ.get("FEED_PATH", "feed.json")

    if not token:
        log.error("TELEGRAM_BOT_TOKEN not set. Skipping.")
        return 0  # non-fatal
    if not channel_id:
        log.warning("TELEGRAM_CHANNEL_ID not set. Using alert chat only.")

    log.info("Loading feed from %s ...", feed_path)
    feed = load_feed(feed_path)
    if not feed:
        log.error("Empty feed — aborting.")
        return 1

    log.info("Feed loaded: %d advisories | mode=%s", len(feed), mode)

    success = True

    # Daily brief
    if mode in ("daily", "all") and channel_id:
        msg = build_daily_brief(feed)
        ok = send_message(token, channel_id, msg)
        if not ok:
            success = False
            log.error("Daily brief send FAILED")
        else:
            log.info("Daily brief sent to %s", channel_id)

    # Weekly digest (Monday runs)
    if mode in ("weekly", "all") and channel_id:
        msg = build_weekly_digest(feed)
        ok = send_message(token, channel_id, msg)
        if not ok:
            success = False
            log.error("Weekly digest send FAILED")
        else:
            log.info("Weekly digest sent to %s", channel_id)

    # P1 alerts — send top critical to alert chat
    if mode in ("alert", "all") and (alert_chat or channel_id):
        p1_items = [i for i in feed
                    if i.get("severity","").upper() == "CRITICAL"
                    and i.get("kev_present")]
        dest = alert_chat or channel_id
        for item in p1_items[:3]:  # max 3 alerts per run
            msg = build_p1_alert(item)
            ok = send_message(token, dest, msg)
            if ok:
                log.info("P1 alert sent: %s", item.get("title","")[:50])

    log.info("Telegram revenue bot complete. success=%s", success)
    return 0 if success else 1


if __name__ == "__main__":
    sys.exit(main())
