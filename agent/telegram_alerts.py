#!/usr/bin/env python3
"""
telegram_alerts.py — SENTINEL APEX v134 Real-Time Alert Engine
==============================================================
Delivers instant threat notifications to Telegram.
Non-blocking, fault-tolerant, never crashes the pipeline.

Channel : https://t.me/cyberdudebivashSentinelApex
Activation: TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID in GitHub Secrets ✅ ACTIVE
Thresholds : HIGH (>=7.0) and CRITICAL (>=9.0) threats only.

v134 Changes (P0-1 ROOT CAUSE FIX):
  - 3-attempt exponential-backoff retry for guaranteed delivery
  - Delivery confirmation log with message_id tracking
  - Rate-limit aware (429 → retry-after respect, up to 30s)
  - Non-retryable 400/401/403 handled immediately (config error log)
  - Connection error recovery
  - Enriched alert format: severity, priority, detect, mitigation fields
  - Pipeline summary enhanced with delivery stats + KEV/IOC counts
  - get_delivery_stats() for pipeline health monitoring
"""

import logging
import os
import time
import datetime
import requests

logger = logging.getLogger("CDB-TELEGRAM")

# ── Configuration ──────────────────────────────────────────────────────────────
BOT_TOKEN    = os.environ.get("TELEGRAM_BOT_TOKEN", "")
CHAT_ID      = os.environ.get("TELEGRAM_CHAT_ID", "")
API_URL      = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
MIN_RISK     = 7.0       # Only alert HIGH (>=7.0) and CRITICAL (>=9.0)
TIMEOUT_SEC  = 15        # Increased from 10 for slow-network tolerance
MAX_TITLE    = 200
MAX_CVE      = 5
MAX_RETRIES  = 3         # Guaranteed delivery attempts
BACKOFF_BASE = 2         # Exponential backoff seconds

# ── Session delivery tracking ──────────────────────────────────────────────────
_delivery_log: dict = {"sent": 0, "failed": 0, "skipped": 0, "rate_limited": 0}


def _is_configured() -> bool:
    """Return True if Telegram credentials are present in environment."""
    if not BOT_TOKEN or not CHAT_ID:
        logger.debug(
            "[TELEGRAM] Degraded mode — BOT_TOKEN/CHAT_ID not set. "
            "Add TELEGRAM_BOT_TOKEN + TELEGRAM_CHAT_ID to GitHub Secrets."
        )
        return False
    return True


def _severity_icon(risk: float) -> str:
    if risk >= 9.0:
        return "\U0001f534 [CRITICAL]"
    if risk >= 7.0:
        return "\U0001f7e0 [HIGH]"
    return "\U0001f7e1 [MEDIUM]"


def _send_with_retry(payload: dict) -> bool:
    """
    POST to Telegram API with exponential-backoff retry.
    Returns True on confirmed 200 delivery, False after MAX_RETRIES exhausted.
    NEVER raises.
    """
    for attempt in range(1, MAX_RETRIES + 1):
        try:
            resp = requests.post(API_URL, json=payload, timeout=TIMEOUT_SEC)

            if resp.status_code == 200:
                msg_id = resp.json().get("result", {}).get("message_id", "N/A")
                logger.info(
                    f"[TELEGRAM] \u2705 Delivery confirmed (attempt {attempt}/{MAX_RETRIES}) "
                    f"message_id={msg_id}"
                )
                _delivery_log["sent"] += 1
                return True

            elif resp.status_code == 429:
                retry_after = resp.json().get("parameters", {}).get("retry_after", BACKOFF_BASE * attempt)
                wait = min(int(retry_after), 30)
                logger.warning(
                    f"[TELEGRAM] Rate limited (attempt {attempt}/{MAX_RETRIES}) — "
                    f"waiting {wait}s"
                )
                _delivery_log["rate_limited"] += 1
                time.sleep(wait)
                continue  # retry

            elif resp.status_code in (400, 401, 403):
                # Non-retryable — config problem
                logger.error(
                    f"[TELEGRAM] Non-retryable HTTP {resp.status_code}: {resp.text[:200]}. "
                    f"Verify BOT_TOKEN and CHAT_ID secrets are correct."
                )
                _delivery_log["failed"] += 1
                return False

            else:
                wait = BACKOFF_BASE ** attempt
                logger.warning(
                    f"[TELEGRAM] HTTP {resp.status_code} (attempt {attempt}/{MAX_RETRIES}) — "
                    f"retry in {wait}s | {resp.text[:80]}"
                )
                time.sleep(wait)
                continue

        except requests.exceptions.Timeout:
            wait = BACKOFF_BASE ** attempt
            logger.warning(
                f"[TELEGRAM] Timeout (attempt {attempt}/{MAX_RETRIES}) — retry in {wait}s"
            )
            time.sleep(wait)

        except requests.exceptions.ConnectionError as exc:
            wait = BACKOFF_BASE ** attempt
            logger.warning(
                f"[TELEGRAM] Connection error (attempt {attempt}/{MAX_RETRIES}): {exc} — "
                f"retry in {wait}s"
            )
            time.sleep(wait)

        except Exception as exc:
            wait = BACKOFF_BASE ** attempt
            logger.warning(
                f"[TELEGRAM] Error (attempt {attempt}/{MAX_RETRIES}): {exc} — retry in {wait}s"
            )
            time.sleep(wait)

    logger.error(
        f"[TELEGRAM] \u274c All {MAX_RETRIES} delivery attempts exhausted — message NOT delivered"
    )
    _delivery_log["failed"] += 1
    return False


def send_threat_alert(
    title: str,
    risk: float,
    url: str,
    cves: list = None,
    ioc_count: int = 0,
    feed_source: str = "",
    severity: str = "",
    priority: str = "",
    detect: str = "",
    mitigation: str = "",
) -> bool:
    """
    Send a threat alert to Telegram with retry guarantee.
    Returns True on confirmed delivery. NEVER raises.

    v134: severity, priority, detect, mitigation added for richer SOC alerts.
    """
    if not _is_configured():
        _delivery_log["skipped"] += 1
        return False

    if risk < MIN_RISK:
        _delivery_log["skipped"] += 1
        return False

    try:
        icon     = _severity_icon(risk)
        cve_line = ""
        if cves:
            cve_list = " | ".join(str(c) for c in cves[:MAX_CVE])
            cve_line = f"\n\U0001f4cc *CVEs:* `{cve_list}`"

        ioc_line = f"\n\U0001f50d *IOCs:* `{ioc_count}` indicators" if ioc_count > 0 else ""
        src_line = f"\n\U0001f4e1 *Source:* {feed_source[:50]}"           if feed_source else ""
        sev_line = f"\n\u26a1 *Severity:* `{severity}`"                   if severity   else ""
        pri_line = f"\n\U0001f3af *Priority:* `{priority}`"               if priority   else ""
        det_line = f"\n\U0001f6e1\ufe0f *Detect:* {detect[:120]}"         if detect     else ""
        mit_line = f"\n\U0001f527 *Mitigate:* {mitigation[:120]}"         if mitigation else ""
        ts_line  = f"\n\U0001f550 `{datetime.datetime.utcnow().strftime('%Y-%m-%dT%H:%M:%SZ')}`"

        message = (
            f"*SENTINEL APEX ALERT*\n"
            f"{icon} | Risk: *{risk:.1f}/10*\n\n"
            f"\U0001f4cb *{title[:MAX_TITLE]}*"
            f"{cve_line}"
            f"{ioc_line}"
            f"{src_line}"
            f"{sev_line}"
            f"{pri_line}"
            f"{det_line}"
            f"{mit_line}"
            f"{ts_line}\n\n"
            f"[\U0001f4ca View Full Report]({url})\n\n"
            f"_CYBERDUDEBIVASH\u00ae Sentinel APEX_"
        )

        payload = {
            "chat_id":                  CHAT_ID,
            "text":                     message,
            "parse_mode":               "Markdown",
            "disable_web_page_preview": False,
        }

        result = _send_with_retry(payload)
        level  = "INFO" if result else "WARNING"
        logger.log(
            logging.INFO if result else logging.WARNING,
            f"[TELEGRAM] Alert {'delivered' if result else 'FAILED'}: "
            f"{title[:60]} | risk={risk:.1f}"
        )
        return result

    except Exception as exc:
        logger.warning(f"[TELEGRAM] Alert preparation error (non-fatal): {exc}")
        _delivery_log["failed"] += 1
        return False


def send_pipeline_summary(
    published: int,
    failed: int,
    critical: int,
    run_ts: str = "",
    high: int = 0,
    kev_count: int = 0,
    total_iocs: int = 0,
) -> bool:
    """
    Send end-of-run pipeline summary to Telegram. Called once per run.
    Includes delivery stats and enriched metrics.
    Only fires when at least 1 report was published.
    """
    if not _is_configured():
        return False
    if published == 0:
        logger.debug("[TELEGRAM] Summary skipped — 0 reports published this run")
        return False

    try:
        ts_line   = f"\n\U0001f550 `{run_ts}`"                              if run_ts      else ""
        kev_line  = f"\n\u26a0\ufe0f *KEV Active:* `{kev_count}` (CISA)"   if kev_count   else ""
        ioc_line  = f"\n\U0001f50d *IOCs Extracted:* `{total_iocs:,}`"      if total_iocs  else ""
        high_line = f"\n\U0001f7e0 *High Severity:* `{high}`"               if high        else ""

        sent = _delivery_log.get("sent", 0)
        fail = _delivery_log.get("failed", 0)
        dl_line = f"\n\U0001f4ec *Alerts Delivered:* `{sent}` | Undelivered: `{fail}`"

        message = (
            f"*SENTINEL APEX \u2014 Run Complete \u2705*\n\n"
            f"\U0001f4ca *Published:* `{published}` threat reports\n"
            f"\U0001f534 *Critical:* `{critical}`"
            f"{high_line}"
            f"{kev_line}"
            f"{ioc_line}"
            f"{dl_line}\n"
            f"\u274c *Pipeline Errors:* `{failed}`"
            f"{ts_line}\n\n"
            f"[\U0001f310 View Dashboard](https://intel.cyberdudebivash.com)\n\n"
            f"_CYBERDUDEBIVASH\u00ae Sentinel APEX v102_"
        )

        payload = {
            "chat_id":                  CHAT_ID,
            "text":                     message,
            "parse_mode":               "Markdown",
            "disable_web_page_preview": True,
        }

        result = _send_with_retry(payload)
        if result:
            logger.info(
                f"[TELEGRAM] Pipeline summary delivered: "
                f"published={published} critical={critical} errors={failed}"
            )
        return result

    except Exception as exc:
        logger.warning(f"[TELEGRAM] Summary error (non-fatal): {exc}")
        return False


def get_delivery_stats() -> dict:
    """Return current session Telegram delivery statistics."""
    return dict(_delivery_log)
