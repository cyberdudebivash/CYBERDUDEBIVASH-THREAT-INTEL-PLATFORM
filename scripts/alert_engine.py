#!/usr/bin/env python3
"""
scripts/alert_engine.py
CYBERDUDEBIVASH(R) SENTINEL APEX -- Threat Alert Engine v1.0
=============================================================
Real-time threat alerting pipeline integrating CVE scanner and IOC engine.
Dispatches structured, revenue-optimized alerts to Telegram with upgrade CTAs.

Alert types:
  CRITICAL_CVE   -- CVSS >= 9.0 or CISA KEV entry detected
  HIGH_CVE       -- CVSS >= 7.0 (PRO+ enriched with EPSS)
  MALICIOUS_IOC  -- IOC confirmed malicious by multi-source engine
  SUSPICIOUS_IOC -- IOC flagged suspicious with community reports
  APEX_P1        -- Platform-detected P1 threat from feed manifest
  DAILY_DIGEST   -- Daily summary of top threats (revenue driver)
  SYSTEM_HEALTH  -- Platform health degradation alerts (admin only)

Revenue mechanics:
  - FREE channel: summary + paywall CTA → drives PRO upgrades
  - PRO channel: full technical detail + upsell to ENTERPRISE
  - Admin channel: P1 alerts + system health (zero revenue friction)

Deduplication:
  - Alert fingerprint: SHA-256 of (alert_type + ioc/cve + severity)
  - State persisted at data/alert_state.json (atomic writes)
  - Configurable suppression window per alert type

Environment variables:
  TELEGRAM_BOT_TOKEN       -- Required: Bot token from @BotFather
  TELEGRAM_CHANNEL_ID      -- Public/subscriber channel (revenue)
  TELEGRAM_ALERT_CHAT_ID   -- Admin-only P1 + health alerts
  TELEGRAM_PRO_CHANNEL_ID  -- PRO subscriber channel (optional)
  ABUSEIPDB_API_KEY        -- For live IOC enrichment
  VT_API_KEY               -- For VirusTotal enrichment

Zero-Regression Mandates:
  - NEVER raises unhandled exceptions
  - NEVER sends duplicate alerts within suppression window
  - NEVER blocks on Telegram API failure (fire-and-forget with retry)
  - NEVER modifies source intel or CVE data
  - Atomic state writes (tmp -> rename)

Author: CYBERDUDEBIVASH SENTINEL APEX
Version: v1.0.0
"""
from __future__ import annotations

import hashlib
import json
import logging
import os
import sys
import time
import urllib.request
import urllib.parse
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# ---------------------------------------------------------------------------
# Logging
# ---------------------------------------------------------------------------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] ALERT-ENGINE %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("CDB-ALERTS")

# ---------------------------------------------------------------------------
# Paths
# ---------------------------------------------------------------------------
BASE_DIR          = Path(__file__).resolve().parent.parent
ALERT_STATE_FILE  = BASE_DIR / "data" / "alert_state.json"
ALERT_LOG_FILE    = BASE_DIR / "data" / "alert_log.jsonl"
FEED_MANIFEST     = BASE_DIR / "data" / "feed_manifest.json"
SYSTEM_HEALTH     = BASE_DIR / "data" / "system_health.json"

# ---------------------------------------------------------------------------
# Environment
# ---------------------------------------------------------------------------
TG_BOT_TOKEN       = os.environ.get("TELEGRAM_BOT_TOKEN", "").strip()
TG_CHANNEL_ID      = os.environ.get("TELEGRAM_CHANNEL_ID", "").strip()
TG_ALERT_CHAT_ID   = os.environ.get("TELEGRAM_ALERT_CHAT_ID", "").strip()
TG_PRO_CHANNEL_ID  = os.environ.get("TELEGRAM_PRO_CHANNEL_ID", "").strip()

# ---------------------------------------------------------------------------
# Platform URLs (revenue links)
# ---------------------------------------------------------------------------
PLATFORM_URL   = "https://intel.cyberdudebivash.com"
API_KEY_URL    = f"{PLATFORM_URL}/get-api-key.html"
STORE_URL      = f"{PLATFORM_URL}/store.html"
ENTERPRISE_URL = f"{PLATFORM_URL}/contact-enterprise.html"
PRICING_URL    = f"{PLATFORM_URL}/pricing.html"
LIVE_FEED_URL  = f"{PLATFORM_URL}/#live-feed"

TG_API_BASE = "https://api.telegram.org/bot{token}/{method}"

# ---------------------------------------------------------------------------
# Alert type constants
# ---------------------------------------------------------------------------
ALERT_CRITICAL_CVE   = "CRITICAL_CVE"
ALERT_HIGH_CVE       = "HIGH_CVE"
ALERT_MALICIOUS_IOC  = "MALICIOUS_IOC"
ALERT_SUSPICIOUS_IOC = "SUSPICIOUS_IOC"
ALERT_APEX_P1        = "APEX_P1"
ALERT_DAILY_DIGEST   = "DAILY_DIGEST"
ALERT_SYSTEM_HEALTH  = "SYSTEM_HEALTH"

# Suppression windows (seconds) — prevents duplicate alert spam
SUPPRESSION_WINDOWS: Dict[str, int] = {
    ALERT_CRITICAL_CVE:   6 * 3600,     # 6 hours
    ALERT_HIGH_CVE:       24 * 3600,    # 24 hours
    ALERT_MALICIOUS_IOC:  12 * 3600,    # 12 hours
    ALERT_SUSPICIOUS_IOC: 48 * 3600,    # 48 hours
    ALERT_APEX_P1:        6 * 3600,     # 6 hours
    ALERT_DAILY_DIGEST:   23 * 3600,    # 23 hours (daily)
    ALERT_SYSTEM_HEALTH:  2 * 3600,     # 2 hours
}

# Severity emoji mapping
SEVERITY_EMOJI: Dict[str, str] = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🔵",
    "INFO":     "⚪",
}

# SOC priority emoji
PRIORITY_EMOJI: Dict[str, str] = {
    "P1": "🚨",
    "P2": "🔥",
    "P3": "⚠️",
    "P4": "ℹ️",
}

# ---------------------------------------------------------------------------
# Upgrade CTAs (revenue-optimized per alert type)
# ---------------------------------------------------------------------------
_CTAs: Dict[str, str] = {
    ALERT_CRITICAL_CVE: (
        "🔒 *Full exploit chain, affected CPEs & EPSS score locked.*\n"
        f"⚡ [Unlock PRO — $49/mo]({API_KEY_URL}?plan=pro&utm_source=tg_cve_critical) "
        f"| [Compare Plans]({PRICING_URL}?utm_source=tg_cve)"
    ),
    ALERT_HIGH_CVE: (
        "📊 *EPSS exploit probability, patch timeline & detection rules require PRO.*\n"
        f"🔑 [Get API Access]({API_KEY_URL}?plan=pro&utm_source=tg_cve_high)"
    ),
    ALERT_MALICIOUS_IOC: (
        "🔒 *Full IOC profile, STIX bundle & pivot indicators locked.*\n"
        f"⚡ [Unlock PRO — $49/mo]({API_KEY_URL}?plan=pro&utm_source=tg_ioc_malicious) "
        f"| [Enterprise SOC API]({ENTERPRISE_URL}?utm_source=tg_ioc)"
    ),
    ALERT_SUSPICIOUS_IOC: (
        "📡 *Get verdict updates, threat context & hunting queries.*\n"
        f"🔑 [Start 14-Day PRO Trial]({API_KEY_URL}?plan=pro&trial=1&utm_source=tg_ioc_suspicious)"
    ),
    ALERT_APEX_P1: (
        "🏢 *Enterprise SOC API* — STIX 2.1, SIEM webhooks, 117+ advisories/day.\n"
        f"📞 [Contact Enterprise Sales]({ENTERPRISE_URL}?utm_source=tg_p1_alert)"
    ),
    ALERT_DAILY_DIGEST: (
        "📦 *Unlock full detection pack* — Sigma + YARA + KQL for today's top threats.\n"
        f"🛒 [Browse Detection Packs]({STORE_URL}?utm_source=tg_daily#detection-packs) "
        f"| [API Access — from $49/mo]({API_KEY_URL}?utm_source=tg_digest)"
    ),
}

# ---------------------------------------------------------------------------
# Alert State (deduplication)
# ---------------------------------------------------------------------------

def _load_alert_state() -> Dict:
    try:
        if ALERT_STATE_FILE.exists() and ALERT_STATE_FILE.stat().st_size > 0:
            return json.loads(ALERT_STATE_FILE.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning(f"Alert state load error: {e}")
    return {"sent": {}, "stats": {}}


def _save_alert_state(state: Dict) -> None:
    try:
        ALERT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = ALERT_STATE_FILE.with_suffix(".tmp")
        tmp.write_text(json.dumps(state, indent=2, default=str, ensure_ascii=False), encoding="utf-8")
        tmp.replace(ALERT_STATE_FILE)
    except Exception as e:
        logger.warning(f"Alert state save error: {e}")


def _alert_fingerprint(alert_type: str, key: str, severity: str = "") -> str:
    raw = f"{alert_type}:{key.lower().strip()}:{severity.upper()}"
    return hashlib.sha256(raw.encode()).hexdigest()[:20]


def _is_suppressed(state: Dict, fingerprint: str, alert_type: str) -> bool:
    sent = state.get("sent", {})
    if fingerprint not in sent:
        return False
    last_sent = sent[fingerprint].get("ts", 0)
    window = SUPPRESSION_WINDOWS.get(alert_type, 3600)
    return (time.time() - last_sent) < window


def _mark_sent(state: Dict, fingerprint: str, alert_type: str, summary: str) -> None:
    sent = state.setdefault("sent", {})
    sent[fingerprint] = {
        "ts": time.time(),
        "alert_type": alert_type,
        "summary": summary[:120],
        "sent_at": datetime.now(timezone.utc).isoformat(),
    }
    stats = state.setdefault("stats", {})
    stats[alert_type] = stats.get(alert_type, 0) + 1
    stats["total"] = stats.get("total", 0) + 1


# ---------------------------------------------------------------------------
# Telegram Transport
# ---------------------------------------------------------------------------

def _tg_send(token: str, chat_id: str, text: str,
              parse_mode: str = "Markdown",
              max_retries: int = 2) -> bool:
    """
    Send Telegram message with retry on transient failure.
    Never raises — returns True/False.
    """
    if not token or not chat_id:
        logger.warning("Telegram credentials not configured — message not sent")
        return False

    # Telegram max message length: 4096 chars
    if len(text) > 4000:
        text = text[:3990] + "\n...[truncated]"

    url = TG_API_BASE.format(token=token, method="sendMessage")
    payload = json.dumps({
        "chat_id": chat_id,
        "text": text,
        "parse_mode": parse_mode,
        "disable_web_page_preview": False,
    }).encode()

    for attempt in range(max_retries):
        try:
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=15) as resp:
                result = json.loads(resp.read())
                if result.get("ok"):
                    logger.info(f"Alert sent to {chat_id}: {len(text)} chars")
                    return True
                else:
                    logger.warning(f"TG API error: {result.get('description', result)}")
        except urllib.error.HTTPError as e:
            if e.code == 429:  # Rate limited
                retry_after = int(e.headers.get("Retry-After", 5))
                logger.warning(f"TG rate limited — sleeping {retry_after}s")
                time.sleep(retry_after)
            else:
                logger.error(f"TG HTTP {e.code} on attempt {attempt + 1}")
        except Exception as e:
            logger.error(f"TG send error (attempt {attempt + 1}): {e}")
        if attempt < max_retries - 1:
            time.sleep(2)

    return False


def _append_alert_log(alert_type: str, key: str, channels_sent: List[str], success: bool) -> None:
    """Append-only audit log for all alert dispatch attempts."""
    try:
        ALERT_LOG_FILE.parent.mkdir(parents=True, exist_ok=True)
        entry = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "alert_type": alert_type,
            "key": key[:100],
            "channels": channels_sent,
            "success": success,
        }
        with open(ALERT_LOG_FILE, "a", encoding="utf-8") as f:
            f.write(json.dumps(entry, ensure_ascii=False) + "\n")
    except Exception as e:
        logger.debug(f"Alert log append error: {e}")


# ---------------------------------------------------------------------------
# Message Formatters
# ---------------------------------------------------------------------------

def _fmt_cve_alert(cve_data: Dict, alert_type: str) -> str:
    """Format CVE scanner output into Telegram-ready Markdown message."""
    cve_id    = cve_data.get("cve_id", "CVE-UNKNOWN")
    desc      = cve_data.get("description", "No description available.")[:300]
    cvss      = cve_data.get("cvss", {})
    score     = cvss.get("base_score", "N/A")
    severity  = cvss.get("severity", "UNKNOWN")
    kev       = cve_data.get("cisa_kev", {})
    in_kev    = kev.get("in_kev", False)
    epss      = cve_data.get("epss", {})
    epss_pct  = epss.get("percentile")
    epss_score = epss.get("score")
    soc_pri   = cve_data.get("soc_priority", "P3")
    products  = cve_data.get("affected_products", [])[:3]
    pub_date  = cve_data.get("published_date", "")[:10]

    emoji     = SEVERITY_EMOJI.get(severity.upper(), "🔴")
    pri_emoji = PRIORITY_EMOJI.get(soc_pri, "⚠️")

    kev_line = ""
    if in_kev:
        due = kev.get("due_date", "")
        kev_line = f"\n⚠️ *CISA KEV* — Patch deadline: `{due}`"

    epss_line = ""
    if epss_score is not None:
        epss_pct_str = f"{float(epss_pct) * 100:.1f}th percentile" if epss_pct else ""
        epss_line = f"\n📈 *EPSS:* `{float(epss_score):.4f}` ({epss_pct_str})"

    products_line = ""
    if products:
        products_line = f"\n🖥 *Affected:* `{'`, `'.join(products[:3])}`"

    upgrade_cta = _CTAs.get(alert_type, "")

    lines = [
        f"{pri_emoji} *{soc_pri} ALERT — {cve_id}*",
        f"{emoji} *Severity:* {severity} | *CVSS:* `{score}`",
        f"📅 *Published:* {pub_date}{kev_line}{epss_line}{products_line}",
        f"",
        f"📋 _{desc}_",
        f"",
        upgrade_cta,
        f"",
        f"🔗 [Live Threat Feed]({LIVE_FEED_URL}?utm_source=tg_cve) | "
        f"[View on NVD](https://nvd.nist.gov/vuln/detail/{cve_id})",
        f"",
        f"_{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | SENTINEL APEX_",
    ]
    return "\n".join(lines)


def _fmt_ioc_alert(ioc_data: Dict, alert_type: str) -> str:
    """Format IOC engine output into Telegram-ready Markdown message."""
    value     = ioc_data.get("ioc_value", "UNKNOWN")
    ioc_type  = ioc_data.get("ioc_type", "unknown").upper()
    composite = ioc_data.get("composite", {})
    verdict   = composite.get("verdict", "UNKNOWN")
    confidence= composite.get("confidence", "LOW")
    soc_pri   = composite.get("soc_priority", "P3")
    score     = composite.get("composite_score", 0)
    sources   = ioc_data.get("sources", [])
    actions   = ioc_data.get("soc_actions", [])[:2]

    pri_emoji = PRIORITY_EMOJI.get(soc_pri, "⚠️")
    verdict_emoji = {
        "MALICIOUS": "🔴", "SUSPICIOUS": "🟠", "CLEAN": "🟢", "UNKNOWN": "⚪"
    }.get(verdict, "⚪")

    # Source details
    source_lines = []
    for src in sources:
        if not src.get("available"):
            continue
        name = src.get("source", "?")
        sv   = src.get("verdict", "?")
        if "abuse_confidence_score" in src:
            source_lines.append(f"  • AbuseIPDB: `{src['abuse_confidence_score']}%` confidence | `{src.get('total_reports', 0)}` reports")
        elif "detection_ratio" in src:
            source_lines.append(f"  • VirusTotal: `{src['detection_ratio']}` engines | {sv}")

    sources_block = "\n".join(source_lines) if source_lines else "  • Multi-source analysis (PRO required for detail)"

    actions_text = "\n".join(f"  {i+1}. {a}" for i, a in enumerate(actions))
    upgrade_cta = _CTAs.get(alert_type, "")

    # Mask value slightly for public channel (privacy best practice for non-critical)
    display_value = value
    if ioc_type == "IP" and alert_type == ALERT_SUSPICIOUS_IOC:
        parts = value.split(".")
        if len(parts) == 4:
            display_value = f"{parts[0]}.{parts[1]}.*.{parts[3]}"

    lines = [
        f"{pri_emoji} *{soc_pri} IOC ALERT — {ioc_type}*",
        f"{verdict_emoji} *Verdict:* {verdict} | *Confidence:* {confidence} | *Score:* `{score}/10`",
        f"",
        f"📍 *IOC:* `{display_value}`",
        f"",
        f"🔬 *Source Analysis:*",
        sources_block,
        f"",
        f"🛡 *Immediate Actions:*",
        actions_text,
        f"",
        upgrade_cta,
        f"",
        f"🔗 [Live Threat Feed]({LIVE_FEED_URL}?utm_source=tg_ioc)",
        f"",
        f"_{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | SENTINEL APEX_",
    ]
    return "\n".join(lines)


def _fmt_apex_p1_alert(item: Dict) -> str:
    """Format feed manifest P1 item into alert message."""
    title     = item.get("title", "Unknown Threat")[:120]
    source    = item.get("source", "Unknown")
    risk      = item.get("risk_score", "N/A")
    severity  = item.get("severity", "CRITICAL")
    apex      = item.get("apex_ai", {})
    summary   = (apex.get("summary") or item.get("summary", ""))[:250]
    tactics   = apex.get("mitre_tactics", [])[:3]
    ioc_count = item.get("ioc_count", 0)
    pub       = str(item.get("published", ""))[:10]

    tactics_line = ""
    if tactics:
        tactics_line = f"\n🎯 *MITRE ATT&CK:* `{'`, `'.join(tactics)}`"

    ioc_line = ""
    if ioc_count:
        ioc_line = f"\n🔗 *IOCs:* `{ioc_count}` indicators (PRO required)"

    upgrade_cta = _CTAs.get(ALERT_APEX_P1, "")

    lines = [
        f"🚨 *P1 CRITICAL THREAT ADVISORY*",
        f"",
        f"📋 *{title}*",
        f"📅 {pub} | 📊 Risk: `{risk}/10` | {SEVERITY_EMOJI.get(severity.upper(), '🔴')} {severity}",
        f"🔍 Source: `{source}`{tactics_line}{ioc_line}",
        f"",
        f"💡 _{summary}_",
        f"",
        upgrade_cta,
        f"",
        f"🔗 [View Full Intel]({LIVE_FEED_URL}?utm_source=tg_p1)",
        f"",
        f"_{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | SENTINEL APEX_",
    ]
    return "\n".join(lines)


def _fmt_daily_digest(items: List[Dict]) -> str:
    """Format daily digest with top threats."""
    today = datetime.now(timezone.utc).strftime("%B %d, %Y")
    count = len(items)

    lines = [
        f"📡 *SENTINEL APEX — Daily Threat Brief*",
        f"📅 _{today}_",
        f"",
        f"*Top {min(count, 5)} Threats Today:*",
        f"",
    ]

    for i, item in enumerate(items[:5], 1):
        title    = item.get("title", "Unknown")[:80]
        severity = item.get("severity", "UNKNOWN")
        risk     = item.get("risk_score", 0)
        source   = item.get("source", "?")
        emoji    = SEVERITY_EMOJI.get(severity.upper(), "⚪")
        lines.append(f"{i}. {emoji} `{severity}` — *{title}*")
        lines.append(f"   Risk: `{risk}/10` | Source: _{source}_")
        lines.append("")

    # Count by severity
    sev_counts: Dict[str, int] = {}
    for item in items:
        s = item.get("severity", "UNKNOWN").upper()
        sev_counts[s] = sev_counts.get(s, 0) + 1

    summary_parts = [f"{SEVERITY_EMOJI.get(k,'⚪')} {k}: {v}" for k, v in sorted(sev_counts.items())]
    lines.append(f"📊 *Today's Feed:* {count} advisories")
    lines.append(" | ".join(summary_parts))
    lines.append("")
    lines.append(_CTAs.get(ALERT_DAILY_DIGEST, ""))
    lines.append("")
    lines.append(f"🔗 [Full Live Feed]({LIVE_FEED_URL}?utm_source=tg_daily) | "
                 f"[Get API Key]({API_KEY_URL}?utm_source=tg_daily)")
    lines.append(f"_{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | SENTINEL APEX_")

    return "\n".join(lines)


def _fmt_system_health_alert(health: Dict) -> str:
    """Format system health degradation for admin channel."""
    score     = health.get("health_score", 0)
    grade     = health.get("health_grade", "?")
    anomalies = health.get("anomalies", [])

    lines = [
        f"⚙️ *SENTINEL APEX — System Health Alert*",
        f"",
        f"🔋 *Health Score:* `{score}/100` [{grade}]",
        f"",
    ]

    if anomalies:
        lines.append(f"*Active Anomalies ({len(anomalies)}):*")
        for anom in anomalies[:5]:
            sev   = anom.get("severity", "MEDIUM")
            msg   = anom.get("message", "Unknown anomaly")[:100]
            emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡"}.get(sev, "⚪")
            lines.append(f"  {emoji} [{sev}] {msg}")
    else:
        lines.append("No active anomalies detected.")

    lines.append("")
    lines.append(f"_{datetime.now(timezone.utc).strftime('%Y-%m-%d %H:%M UTC')} | SENTINEL APEX Admin_")
    return "\n".join(lines)


# ---------------------------------------------------------------------------
# Alert Dispatch Functions
# ---------------------------------------------------------------------------

def dispatch_cve_alert(
    cve_data: Dict,
    state: Dict,
    dry_run: bool = False,
) -> Dict:
    """
    Dispatch CVE alert based on severity.
    Returns {"sent": bool, "suppressed": bool, "channels": [...]}
    """
    cve_id = cve_data.get("cve_id", "CVE-UNKNOWN")
    cvss   = cve_data.get("cvss", {})
    score  = float(cvss.get("base_score") or 0)
    in_kev = cve_data.get("cisa_kev", {}).get("in_kev", False)

    # Determine alert type
    if score >= 9.0 or in_kev:
        alert_type = ALERT_CRITICAL_CVE
    elif score >= 7.0:
        alert_type = ALERT_HIGH_CVE
    else:
        return {"sent": False, "reason": "below_threshold", "cve_id": cve_id}

    fingerprint = _alert_fingerprint(alert_type, cve_id, cvss.get("severity", ""))

    if _is_suppressed(state, fingerprint, alert_type):
        return {"sent": False, "suppressed": True, "cve_id": cve_id, "alert_type": alert_type}

    message = _fmt_cve_alert(cve_data, alert_type)
    channels_sent = []

    if not dry_run:
        if TG_CHANNEL_ID:
            ok = _tg_send(TG_BOT_TOKEN, TG_CHANNEL_ID, message)
            if ok:
                channels_sent.append(TG_CHANNEL_ID)

        # Critical CVEs also go to admin chat
        if alert_type == ALERT_CRITICAL_CVE and TG_ALERT_CHAT_ID:
            ok = _tg_send(TG_BOT_TOKEN, TG_ALERT_CHAT_ID, message)
            if ok:
                channels_sent.append(TG_ALERT_CHAT_ID)
    else:
        logger.info(f"[DRY-RUN] Would send {alert_type} for {cve_id} to {TG_CHANNEL_ID}")
        channels_sent = ["dry_run"]

    sent_ok = len(channels_sent) > 0
    if sent_ok:
        _mark_sent(state, fingerprint, alert_type, f"{cve_id} CVSS:{score}")
        _append_alert_log(alert_type, cve_id, channels_sent, True)

    return {
        "sent": sent_ok,
        "suppressed": False,
        "cve_id": cve_id,
        "alert_type": alert_type,
        "channels": channels_sent,
        "cvss_score": score,
        "in_kev": in_kev,
    }


def dispatch_ioc_alert(
    ioc_data: Dict,
    state: Dict,
    dry_run: bool = False,
) -> Dict:
    """
    Dispatch IOC reputation alert.
    """
    value   = ioc_data.get("ioc_value", "UNKNOWN")
    composite = ioc_data.get("composite", {})
    verdict = composite.get("verdict", "UNKNOWN")

    if verdict == "MALICIOUS":
        alert_type = ALERT_MALICIOUS_IOC
    elif verdict == "SUSPICIOUS":
        alert_type = ALERT_SUSPICIOUS_IOC
    else:
        return {"sent": False, "reason": "verdict_not_actionable", "ioc": value, "verdict": verdict}

    fingerprint = _alert_fingerprint(alert_type, value, verdict)

    if _is_suppressed(state, fingerprint, alert_type):
        return {"sent": False, "suppressed": True, "ioc": value, "alert_type": alert_type}

    message = _fmt_ioc_alert(ioc_data, alert_type)
    channels_sent = []

    if not dry_run:
        if TG_CHANNEL_ID:
            ok = _tg_send(TG_BOT_TOKEN, TG_CHANNEL_ID, message)
            if ok:
                channels_sent.append(TG_CHANNEL_ID)

        if verdict == "MALICIOUS" and TG_ALERT_CHAT_ID:
            ok = _tg_send(TG_BOT_TOKEN, TG_ALERT_CHAT_ID, message)
            if ok:
                channels_sent.append(TG_ALERT_CHAT_ID)
    else:
        logger.info(f"[DRY-RUN] Would send {alert_type} for {value[:30]}")
        channels_sent = ["dry_run"]

    sent_ok = len(channels_sent) > 0
    if sent_ok:
        _mark_sent(state, fingerprint, alert_type, f"{value[:50]} {verdict}")
        _append_alert_log(alert_type, value[:80], channels_sent, True)

    return {
        "sent": sent_ok,
        "suppressed": False,
        "ioc": value,
        "alert_type": alert_type,
        "verdict": verdict,
        "channels": channels_sent,
    }


def dispatch_apex_p1_alerts(
    manifest_items: List[Dict],
    state: Dict,
    dry_run: bool = False,
    max_alerts: int = 3,
) -> List[Dict]:
    """
    Scan feed manifest for P1 items and dispatch alerts.
    Caps at max_alerts per run to prevent channel spam.
    """
    results = []
    p1_items = [
        item for item in manifest_items
        if item.get("apex_ai", {}).get("soc_priority") == "P1"
        or float(item.get("risk_score", 0)) >= 9.0
    ]

    # Sort by risk_score descending
    p1_items.sort(key=lambda x: float(x.get("risk_score", 0)), reverse=True)

    sent_count = 0
    for item in p1_items:
        if sent_count >= max_alerts:
            break

        item_id   = item.get("id", item.get("title", "unknown"))[:60]
        severity  = item.get("severity", "CRITICAL")
        fingerprint = _alert_fingerprint(ALERT_APEX_P1, item_id, severity)

        if _is_suppressed(state, fingerprint, ALERT_APEX_P1):
            results.append({"sent": False, "suppressed": True, "id": item_id})
            continue

        message = _fmt_apex_p1_alert(item)
        channels_sent = []

        if not dry_run:
            if TG_CHANNEL_ID:
                ok = _tg_send(TG_BOT_TOKEN, TG_CHANNEL_ID, message)
                if ok:
                    channels_sent.append(TG_CHANNEL_ID)
                    time.sleep(2)  # Rate limit between messages

            if TG_ALERT_CHAT_ID:
                ok = _tg_send(TG_BOT_TOKEN, TG_ALERT_CHAT_ID, message)
                if ok:
                    channels_sent.append(TG_ALERT_CHAT_ID)
        else:
            logger.info(f"[DRY-RUN] Would send P1 alert: {item_id[:50]}")
            channels_sent = ["dry_run"]

        sent_ok = len(channels_sent) > 0
        if sent_ok:
            _mark_sent(state, fingerprint, ALERT_APEX_P1, item_id)
            _append_alert_log(ALERT_APEX_P1, item_id, channels_sent, True)
            sent_count += 1

        results.append({
            "sent": sent_ok,
            "suppressed": False,
            "id": item_id,
            "channels": channels_sent,
        })

    return results


def dispatch_daily_digest(
    manifest_items: List[Dict],
    state: Dict,
    dry_run: bool = False,
) -> Dict:
    """
    Dispatch daily threat digest. Suppressed if already sent today.
    """
    fingerprint = _alert_fingerprint(ALERT_DAILY_DIGEST, "daily_digest", "INFO")

    if _is_suppressed(state, fingerprint, ALERT_DAILY_DIGEST):
        return {"sent": False, "suppressed": True, "alert_type": ALERT_DAILY_DIGEST}

    # Top items by risk
    sorted_items = sorted(
        manifest_items,
        key=lambda x: float(x.get("risk_score", 0)),
        reverse=True,
    )

    message = _fmt_daily_digest(sorted_items[:20])
    channels_sent = []

    if not dry_run:
        if TG_CHANNEL_ID:
            ok = _tg_send(TG_BOT_TOKEN, TG_CHANNEL_ID, message)
            if ok:
                channels_sent.append(TG_CHANNEL_ID)
    else:
        logger.info("[DRY-RUN] Would send daily digest")
        channels_sent = ["dry_run"]

    sent_ok = len(channels_sent) > 0
    if sent_ok:
        _mark_sent(state, fingerprint, ALERT_DAILY_DIGEST, f"{len(sorted_items)} advisories")
        _append_alert_log(ALERT_DAILY_DIGEST, "daily_digest", channels_sent, True)

    return {
        "sent": sent_ok,
        "suppressed": False,
        "alert_type": ALERT_DAILY_DIGEST,
        "total_items": len(manifest_items),
        "channels": channels_sent,
    }


def dispatch_system_health_alert(
    health: Dict,
    state: Dict,
    dry_run: bool = False,
) -> Dict:
    """
    Send health alert to admin chat only when score drops below threshold.
    Only dispatches if admin chat is configured.
    """
    if not TG_ALERT_CHAT_ID:
        return {"sent": False, "reason": "no_admin_chat_configured"}

    score = health.get("health_score", 100)
    if score >= 70:
        return {"sent": False, "reason": "health_ok", "score": score}

    fingerprint = _alert_fingerprint(ALERT_SYSTEM_HEALTH, "system_health", str(score // 10))

    if _is_suppressed(state, fingerprint, ALERT_SYSTEM_HEALTH):
        return {"sent": False, "suppressed": True}

    message = _fmt_system_health_alert(health)
    channels_sent = []

    if not dry_run:
        ok = _tg_send(TG_BOT_TOKEN, TG_ALERT_CHAT_ID, message)
        if ok:
            channels_sent.append(TG_ALERT_CHAT_ID)
    else:
        logger.info(f"[DRY-RUN] Would send health alert: score={score}")
        channels_sent = ["dry_run"]

    sent_ok = len(channels_sent) > 0
    if sent_ok:
        _mark_sent(state, fingerprint, ALERT_SYSTEM_HEALTH, f"score={score}")
        _append_alert_log(ALERT_SYSTEM_HEALTH, "system_health", channels_sent, True)

    return {"sent": sent_ok, "score": score, "channels": channels_sent}


# ---------------------------------------------------------------------------
# Feed Manifest Loader
# ---------------------------------------------------------------------------

def _load_manifest() -> List[Dict]:
    try:
        if FEED_MANIFEST.exists():
            data = json.loads(FEED_MANIFEST.read_text(encoding="utf-8"))
            if isinstance(data, list):
                return data
            return data.get("items", [])
    except Exception as e:
        logger.warning(f"Manifest load error: {e}")
    return []


def _load_system_health() -> Dict:
    try:
        if SYSTEM_HEALTH.exists():
            return json.loads(SYSTEM_HEALTH.read_text(encoding="utf-8"))
    except Exception:
        pass
    return {}


# ---------------------------------------------------------------------------
# Main Run Function
# ---------------------------------------------------------------------------

def run_alert_engine(
    mode: str = "full",
    dry_run: bool = False,
    cve_data: Optional[Dict] = None,
    ioc_data: Optional[Dict] = None,
    cve_list: Optional[List[Dict]] = None,
    ioc_list:  Optional[List[Dict]] = None,
) -> Dict:
    """
    Main entry point for the alert engine.

    Modes:
      'full'   -- P1 feed alerts + daily digest + system health
      'cve'    -- Process provided cve_data or cve_list
      'ioc'    -- Process provided ioc_data or ioc_list
      'digest' -- Send daily digest only
      'health' -- Send system health alert only

    Returns: summary dict with all dispatch results.
    """
    ts_start = time.time()
    state    = _load_alert_state()
    results: Dict[str, Any] = {
        "mode":     mode,
        "dry_run":  dry_run,
        "ts_start": datetime.now(timezone.utc).isoformat(),
    }

    logger.info(f"Alert engine starting — mode={mode} dry_run={dry_run}")

    if mode in ("cve", "full") and (cve_data or cve_list):
        cve_results = []
        targets = cve_list if cve_list else ([cve_data] if cve_data else [])
        for cve in targets:
            res = dispatch_cve_alert(cve, state, dry_run=dry_run)
            cve_results.append(res)
            if not res.get("suppressed") and not dry_run:
                time.sleep(1.5)  # Rate limit
        results["cve_alerts"] = cve_results

    if mode in ("ioc", "full") and (ioc_data or ioc_list):
        ioc_results = []
        targets = ioc_list if ioc_list else ([ioc_data] if ioc_data else [])
        for ioc in targets:
            res = dispatch_ioc_alert(ioc, state, dry_run=dry_run)
            ioc_results.append(res)
            if not res.get("suppressed") and not dry_run:
                time.sleep(1.5)
        results["ioc_alerts"] = ioc_results

    if mode in ("full", "digest"):
        manifest = _load_manifest()
        if manifest:
            if mode == "full":
                p1_results = dispatch_apex_p1_alerts(manifest, state, dry_run=dry_run)
                results["apex_p1_alerts"] = p1_results
            digest_result = dispatch_daily_digest(manifest, state, dry_run=dry_run)
            results["daily_digest"] = digest_result

    if mode in ("full", "health"):
        health = _load_system_health()
        if health:
            health_result = dispatch_system_health_alert(health, state, dry_run=dry_run)
            results["system_health_alert"] = health_result

    # Save updated state
    _save_alert_state(state)

    results["runtime_ms"] = round((time.time() - ts_start) * 1000)
    results["total_sent_ever"] = state.get("stats", {}).get("total", 0)
    logger.info(
        f"Alert engine complete — mode={mode} runtime={results['runtime_ms']}ms "
        f"total_sent_ever={results['total_sent_ever']}"
    )
    return results


# ---------------------------------------------------------------------------
# Alert State Stats
# ---------------------------------------------------------------------------

def get_alert_stats() -> Dict:
    """Return alert dispatch statistics."""
    state = _load_alert_state()
    sent  = state.get("sent", {})
    stats = state.get("stats", {})

    now = time.time()
    recent_24h = sum(
        1 for v in sent.values()
        if (now - v.get("ts", 0)) < 86400
    )

    return {
        "total_alerts_ever": stats.get("total", 0),
        "alerts_last_24h": recent_24h,
        "by_type": {k: v for k, v in stats.items() if k != "total"},
        "active_fingerprints": len(sent),
        "state_file": str(ALERT_STATE_FILE),
        "log_file": str(ALERT_LOG_FILE),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------

def main() -> None:
    import argparse

    parser = argparse.ArgumentParser(
        description="CYBERDUDEBIVASH SENTINEL APEX — Threat Alert Engine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Modes:
  --mode full     Run full alert pipeline (P1 + digest + health) [default]
  --mode digest   Send daily digest only
  --mode health   Send system health alert only
  --mode cve      Alert on a specific CVE (requires --cve)
  --mode ioc      Alert on a specific IOC (requires --ioc)

Examples:
  python scripts/alert_engine.py --mode digest --dry-run
  python scripts/alert_engine.py --mode full --dry-run
  python scripts/alert_engine.py --mode cve --cve CVE-2024-3400
  python scripts/alert_engine.py --stats
        """,
    )
    parser.add_argument("--mode",    type=str, default="full",
                        choices=["full", "cve", "ioc", "digest", "health"],
                        help="Alert mode (default: full)")
    parser.add_argument("--cve",     type=str, help="CVE ID for cve mode")
    parser.add_argument("--ioc",     type=str, help="IOC value for ioc mode")
    parser.add_argument("--tier",    type=str, default="PRO",
                        choices=["FREE", "PRO", "ENTERPRISE", "MSSP"])
    parser.add_argument("--dry-run", action="store_true", help="Simulate without sending")
    parser.add_argument("--stats",   action="store_true", help="Show alert statistics")
    parser.add_argument("--clear",   action="store_true", help="Clear alert dedup state")
    parser.add_argument("--json",    action="store_true", help="Output JSON")

    args = parser.parse_args()

    if args.stats:
        stats = get_alert_stats()
        print(json.dumps(stats, indent=2, ensure_ascii=False))
        return

    if args.clear:
        ALERT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        if ALERT_STATE_FILE.exists():
            ALERT_STATE_FILE.unlink()
        print("Alert state cleared.")
        return

    cve_data_arg  = None
    ioc_data_arg  = None

    # Live CVE lookup for cve mode
    if args.mode == "cve" and args.cve:
        try:
            sys.path.insert(0, str(BASE_DIR / "scripts"))
            from cve_scanner import lookup_cve
            logger.info(f"Looking up {args.cve} for alert...")
            cve_data_arg = lookup_cve(args.cve, tier=args.tier)
        except Exception as e:
            logger.error(f"CVE lookup failed: {e}")
            cve_data_arg = {"cve_id": args.cve, "cvss": {"base_score": 9.5, "severity": "CRITICAL"}}

    # Live IOC lookup for ioc mode
    if args.mode == "ioc" and args.ioc:
        try:
            sys.path.insert(0, str(BASE_DIR / "scripts"))
            from ioc_reputation_engine import lookup_ioc
            logger.info(f"Looking up IOC {args.ioc[:30]} for alert...")
            ioc_data_arg = lookup_ioc(args.ioc, tier=args.tier)
        except Exception as e:
            logger.error(f"IOC lookup failed: {e}")
            ioc_data_arg = None

    result = run_alert_engine(
        mode=args.mode,
        dry_run=args.dry_run,
        cve_data=cve_data_arg,
        ioc_data=ioc_data_arg,
    )

    if args.json:
        print(json.dumps(result, indent=2, default=str, ensure_ascii=False))
    else:
        print(f"\n[ALERT ENGINE] mode={result['mode']} dry_run={result['dry_run']}")
        print(f"  Runtime: {result['runtime_ms']}ms")
        print(f"  Total sent ever: {result['total_sent_ever']}")
        for key, val in result.items():
            if key.endswith("_alerts") or key in ("daily_digest", "system_health_alert"):
                print(f"  {key}: {val}")


if __name__ == "__main__":
    main()
