#!/usr/bin/env python3
"""
telegram_alerts.py — SENTINEL APEX Real-Time Alert Engine
==========================================================
Delivers instant threat notifications to Telegram.
Non-blocking, fault-tolerant, never crashes the pipeline.

Channel : https://t.me/cyberdudebivashSentinelApex
Activation: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID in GitHub Secrets ✅ ACTIVE
Thresholds : HIGH (>=7.0) and CRITICAL (>=9.0) threats only.
"""

import logging
import os
import time
import requests

logger = logging.getLogger("CDB-TELEGRAM")

# ── Configuration ──────────────────────────────────────────
BOT_TOKEN   = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID     = os.environ.get("TELEGRAM_CHAT_ID", "")
API_URL     = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
MIN_RISK    = 7.0   # Only alert HIGH (>=7.0) and CRITICAL (>=9.0)
TIMEOUT_SEC = 10
MAX_TITLE   = 180
MAX_CVE     = 3


def _severity_icon(risk: float) -> str:
    if risk >= 9.0:
        return "[CRITICAL]"
    if risk >= 7.0:
        return "[HIGH]"
    return "[MEDIUM]"


def send_threat_alert(
    title: str,
    risk: float,
    url: str,
    cves: list = None,
    ioc_count: int = 0,
    feed_source: str = "",
) -> bool:
    """
    Send a threat alert to Telegram. Returns True on success.
    NEVER raises — all errors are logged and swallowed.
    """
    if not BOT_TOKEN or not CHAT_ID:
        logger.debug("[TELEGRAM] Skipped — BOT_TOKEN/CHAT_ID not configured (degraded mode)")
        return False

    if risk < MIN_RISK:
        return False

    try:
        icon     = _severity_icon(risk)
        cve_line = ""
        if cves:
            cve_list = ", ".join(cves[:MAX_CVE])
            cve_line = f"\n*CVEs:* `{cve_list}`"

        ioc_line = f"\n*IOCs:* {ioc_count}" if ioc_count > 0 else ""
        src_line = f"\n*Source:* {feed_source[:40]}" if feed_source else ""

        message = (
            f"*SENTINEL APEX ALERT*\n"
            f"{icon} | Risk: *{risk:.1f}/10*\n\n"
            f"*{title[:MAX_TITLE]}*"
            f"{cve_line}"
            f"{ioc_line}"
            f"{src_line}\n\n"
            f"[Read Full Report]({url})\n\n"
            f"_CYBERDUDEBIVASH(R) Sentinel APEX_"
        )

        resp = requests.post(
            API_URL,
            json={
                "chat_id":                  CHAT_ID,
                "text":                     message,
                "parse_mode":               "Markdown",
                "disable_web_page_preview": False,
            },
            timeout=TIMEOUT_SEC,
        )

        if resp.status_code == 200:
            logger.info(f"[TELEGRAM] Alert sent (risk={risk:.1f}): {title[:60]}")
            return True
        elif resp.status_code == 429:
            retry_after = resp.json().get("parameters", {}).get("retry_after", 5)
            logger.warning(f"[TELEGRAM] Rate limited — retry after {retry_after}s")
            time.sleep(min(retry_after, 10))
            return False
        else:
            logger.warning(f"[TELEGRAM] Send failed HTTP {resp.status_code}: {resp.text[:100]}")
            return False

    except requests.exceptions.Timeout:
        logger.warning("[TELEGRAM] Request timed out (non-fatal)")
        return False
    except Exception as exc:
        logger.warning(f"[TELEGRAM] Alert error (non-fatal): {exc}")
        return False


def send_pipeline_summary(published: int, failed: int, critical: int, run_ts: str = "") -> bool:
    """
    Send end-of-run summary to Telegram. Called once per pipeline run.
    Only sends if at least 1 report was published.
    """
    if not BOT_TOKEN or not CHAT_ID:
        return False
    if published == 0:
        return False

    try:
        ts_line = f"\n_{run_ts}_" if run_ts else ""
        message = (
            f"*SENTINEL APEX — Run Complete*\n\n"
            f"Published: *{published}* reports\n"
            f"Critical threats: *{critical}*\n"
            f"Failed: {failed}\n"
            f"{ts_line}\n"
            f"[View Dashboard](https://intel.cyberdudebivash.com)"
        )
        resp = requests.post(
            API_URL,
            json={
                "chat_id":                  CHAT_ID,
                "text":                     message,
                "parse_mode":               "Markdown",
                "disable_web_page_preview": True,
            },
            timeout=TIMEOUT_SEC,
        )
        return resp.status_code == 200
    except Exception as exc:
        logger.warning(f"[TELEGRAM] Summary error (non-fatal): {exc}")
        return False
