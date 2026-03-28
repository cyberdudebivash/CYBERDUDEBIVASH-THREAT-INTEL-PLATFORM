#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — Real-Time Alert Engine v1.0
=============================================================
Detects P1/CRITICAL/score>=9 threats and fires multi-channel alerts.

RULES:
  - NEVER modifies core pipeline logic
  - NEVER crashes on any failure (all errors swallowed + logged)
  - Idempotent: deduplicates alerts across runs via JSON state file
  - Reads manifest AFTER write (post-manifest stage hook)
  - Channels: Telegram (existing) + Webhook (optional)

ALERT TRIGGERS:
  - APEX priority == "P1"
  - severity == "CRITICAL"
  - risk_score >= CRITICAL_THRESHOLD (9.0)
  - threat_level == "CRITICAL_SURGE" (from APEX)

DEDUPLICATION:
  - Persistent store: data/alerts/alert_state.json
  - Key: stix_id — each advisory alerted at most once per day
  - TTL: 24 hours (alerts re-fire the next day if still active)

(C) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""
from __future__ import annotations

import json
import logging
import os
import time
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-ALERT-ENGINE")

# ── Configuration ─────────────────────────────────────────────────────────────
CRITICAL_SCORE_THRESHOLD = float(os.environ.get("CDB_ALERT_THRESHOLD", "9.0"))
ALERT_TTL_HOURS          = int(os.environ.get("CDB_ALERT_TTL_HOURS", "24"))
MAX_ALERTS_PER_RUN       = int(os.environ.get("CDB_MAX_ALERTS_PER_RUN", "10"))
WEBHOOK_URL              = os.environ.get("CDB_WEBHOOK_URL", "")
ALERT_ENABLED            = os.environ.get("CDB_ALERTS_ENABLED", "true").lower() in ("true","1","yes")

BASE_DIR         = Path(__file__).resolve().parent.parent
ALERT_STATE_FILE = BASE_DIR / "data" / "alerts" / "alert_state.json"
MANIFEST_PATH    = BASE_DIR / "data" / "stix" / "feed_manifest.json"


# ── Alert State (Deduplication) ───────────────────────────────────────────────

def _load_state() -> Dict[str, str]:
    """Load alert state: {stix_id: iso_timestamp_alerted}. Safe on any failure."""
    try:
        ALERT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        if not ALERT_STATE_FILE.exists():
            return {}
        with open(ALERT_STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return {}


def _save_state(state: Dict[str, str]) -> None:
    """Persist alert state atomically. Never raises."""
    try:
        ALERT_STATE_FILE.parent.mkdir(parents=True, exist_ok=True)
        tmp = str(ALERT_STATE_FILE) + ".tmp"
        raw = json.dumps(state, indent=2, ensure_ascii=False)
        with open(tmp, "wb") as f:
            f.write(raw.encode("utf-8"))
        os.replace(tmp, ALERT_STATE_FILE)
    except Exception as e:
        logger.warning(f"[ALERT-ENGINE] State save failed (non-fatal): {e}")


def _purge_expired(state: Dict[str, str], ttl_hours: int) -> Dict[str, str]:
    """Remove state entries older than TTL. Returns cleaned state."""
    cutoff = datetime.now(timezone.utc) - timedelta(hours=ttl_hours)
    return {
        k: v for k, v in state.items()
        if _parse_ts(v) > cutoff
    }


def _parse_ts(ts_str: str) -> datetime:
    """Parse ISO timestamp safely. Returns epoch on failure."""
    try:
        dt = datetime.fromisoformat(ts_str)
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt
    except Exception:
        return datetime(1970, 1, 1, tzinfo=timezone.utc)


def _already_alerted(stix_id: str, state: Dict[str, str], ttl_hours: int) -> bool:
    """Return True if this advisory was already alerted within TTL window."""
    ts_str = state.get(stix_id)
    if not ts_str:
        return False
    return _parse_ts(ts_str) > datetime.now(timezone.utc) - timedelta(hours=ttl_hours)


# ── Alert Detection ───────────────────────────────────────────────────────────

def _is_critical(entry: Dict) -> bool:
    """
    Multi-signal critical detection:
      1. APEX priority == P1
      2. severity == CRITICAL
      3. risk_score >= threshold (default 9.0)
      4. APEX threat_level == CRITICAL_SURGE
    Any ONE signal is sufficient to trigger an alert.
    """
    try:
        risk   = float(entry.get("risk_score", 0))
        sev    = str(entry.get("severity", "")).upper()
        apex   = entry.get("apex") or {}
        prio   = str(apex.get("priority", "")).upper()
        tlevel = str(apex.get("threat_level", "")).upper()

        return (
            risk >= CRITICAL_SCORE_THRESHOLD  or
            sev  == "CRITICAL"                or
            prio == "P1"                      or
            "CRITICAL_SURGE" in tlevel
        )
    except Exception:
        return False


def _build_alert_payload(entry: Dict) -> Dict:
    """Build structured alert payload from manifest entry."""
    apex    = entry.get("apex") or {}
    stix_id = entry.get("stix_id", "")
    title   = entry.get("title", "Unknown Advisory")
    risk    = float(entry.get("risk_score", 0))
    sev     = str(entry.get("severity", "UNKNOWN"))

    # Determine primary trigger
    prio   = apex.get("priority", "P?")
    tlevel = apex.get("threat_level", "UNKNOWN")
    if apex.get("priority") == "P1":
        trigger = "APEX_SOC_P1"
    elif risk >= CRITICAL_SCORE_THRESHOLD:
        trigger = f"RISK_SCORE_{risk:.1f}"
    elif str(entry.get("severity","")).upper() == "CRITICAL":
        trigger = "SEVERITY_CRITICAL"
    else:
        trigger = "CRITICAL_SURGE"

    return {
        "alert_id":           f"CDB-ALERT-{stix_id[-8:].upper()}",
        "stix_id":            stix_id,
        "title":              title[:200],
        "risk_score":         risk,
        "severity":           sev,
        "trigger":            trigger,
        "blog_url":           entry.get("blog_url", ""),
        "source_url":         entry.get("source_url", ""),
        "timestamp":          entry.get("timestamp", ""),
        "kev_present":        bool(entry.get("kev_present", False)),
        "cvss_score":         entry.get("cvss_score"),
        "epss_score":         entry.get("epss_score"),
        "actor_tag":          entry.get("actor_tag", ""),
        "feed_source":        entry.get("feed_source", ""),
        "ioc_count":          sum(v for v in (entry.get("ioc_counts") or {}).values()
                                  if isinstance(v, int)),
        "mitre_tactics":      (entry.get("mitre_tactics") or [])[:5],
        "supply_chain":       bool(entry.get("supply_chain", False)),
        # APEX intelligence fields
        "apex_priority":      prio,
        "apex_threat_level":  tlevel,
        "apex_campaign_id":   apex.get("campaign_id", ""),
        "apex_category":      apex.get("threat_category", ""),
        "apex_behavioral_tags": apex.get("behavioral_tags", []),
        "apex_action":        apex.get("recommended_action", ""),
        "apex_ai_summary":    apex.get("ai_summary", "")[:300],
        "alerted_at":         datetime.now(timezone.utc).isoformat(),
        "platform":           "CYBERDUDEBIVASH® Sentinel APEX",
    }


# ── Channel Dispatchers ────────────────────────────────────────────────────────

def _dispatch_telegram(payload: Dict) -> bool:
    """Send APEX-enriched Telegram alert. Returns True on success."""
    try:
        from agent.telegram_alerts import BOT_TOKEN, CHAT_ID, TIMEOUT_SEC
        import requests

        if not BOT_TOKEN or not CHAT_ID:
            logger.debug("[ALERT-ENGINE] Telegram skipped — not configured")
            return False

        risk    = payload["risk_score"]
        prio    = payload.get("apex_priority", "P?")
        cat     = payload.get("apex_category", "").replace("_", " ")
        tags    = payload.get("apex_behavioral_tags", [])
        action  = payload.get("apex_action", "")
        trigger = payload.get("trigger", "")
        kev     = "⚡ KEV CONFIRMED" if payload.get("kev_present") else ""
        sc      = "🔗 SUPPLY CHAIN" if payload.get("supply_chain") else ""
        badges  = " ".join(filter(None, [kev, sc]))

        # Severity icon
        if risk >= 9.5 or prio == "P1":
            icon = "🔴"
        elif risk >= 9.0:
            icon = "🟠"
        else:
            icon = "🟡"

        tags_line    = " | ".join(tags[:3]) if tags else ""
        url          = payload.get("blog_url") or payload.get("source_url") or "https://intel.cyberdudebivash.com"
        cvss_line    = f"CVSS: `{payload['cvss_score']}` | " if payload.get("cvss_score") else ""
        epss_line    = f"EPSS: `{payload['epss_score']}%`" if payload.get("epss_score") else ""
        enrich_line  = (cvss_line + epss_line).strip(" |")

        message = (
            f"{icon} *APEX CRITICAL ALERT*\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"*{payload['title'][:160]}*\n\n"
            f"🎯 *Risk:* `{risk:.1f}/10`  |  *Priority:* `{prio}`  |  *{payload['severity']}*\n"
            f"🔬 *Trigger:* `{trigger}`\n"
        )

        if cat:       message += f"📂 *Category:* {cat}\n"
        if enrich_line: message += f"📊 {enrich_line}\n"
        if badges:    message += f"⚠️ {badges}\n"
        if tags_line: message += f"🏷 `{tags_line}`\n"
        if action:    message += f"\n→ *{action[:100]}*\n"

        message += (
            f"\n[📋 View Full Report]({url})\n"
            f"[🌐 Dashboard](https://intel.cyberdudebivash.com)\n\n"
            f"_Campaign: {payload.get('apex_campaign_id','—')} | "
            f"CYBERDUDEBIVASH® Sentinel APEX_"
        )

        api_url = f"https://api.telegram.org/bot{BOT_TOKEN}/sendMessage"
        resp = requests.post(
            api_url,
            json={
                "chat_id": CHAT_ID,
                "text": message,
                "parse_mode": "Markdown",
                "disable_web_page_preview": False,
            },
            timeout=TIMEOUT_SEC,
        )

        if resp.status_code == 200:
            logger.info(f"[ALERT-ENGINE] Telegram sent: {payload['title'][:60]}")
            return True
        elif resp.status_code == 429:
            retry = resp.json().get("parameters", {}).get("retry_after", 5)
            logger.warning(f"[ALERT-ENGINE] Telegram rate-limited — retry after {retry}s")
            return False
        else:
            logger.warning(f"[ALERT-ENGINE] Telegram HTTP {resp.status_code}")
            return False

    except Exception as e:
        logger.warning(f"[ALERT-ENGINE] Telegram dispatch failed (non-fatal): {e}")
        return False


def _dispatch_webhook(payload: Dict) -> bool:
    """POST alert JSON to WEBHOOK_URL. Returns True on success."""
    if not WEBHOOK_URL:
        return False
    try:
        import requests
        resp = requests.post(
            WEBHOOK_URL,
            json=payload,
            headers={
                "Content-Type": "application/json",
                "X-CDB-Source": "SENTINEL-APEX-ALERT-ENGINE",
                "X-CDB-Risk":   str(payload.get("risk_score", 0)),
                "X-CDB-Priority": payload.get("apex_priority", "P?"),
            },
            timeout=10,
        )
        if resp.status_code in (200, 201, 202, 204):
            logger.info(f"[ALERT-ENGINE] Webhook delivered: {payload['title'][:60]}")
            return True
        else:
            logger.warning(f"[ALERT-ENGINE] Webhook HTTP {resp.status_code}")
            return False
    except Exception as e:
        logger.warning(f"[ALERT-ENGINE] Webhook failed (non-fatal): {e}")
        return False


# ── Main Entry Point ──────────────────────────────────────────────────────────

def run_alert_engine(manifest: Optional[List[Dict]] = None) -> Dict:
    """
    Main alert engine. Reads manifest, detects criticals, deduplicates, fires.

    CALL AFTER manifest write (post-manifest stage).

    Args:
        manifest: Optional pre-loaded manifest (avoids re-read if already loaded)

    Returns:
        {
            "alerts_fired": int,
            "alerts_skipped_dedup": int,
            "total_critical_detected": int,
            "status": "OK" | "DISABLED" | "NO_CRITICALS"
        }
    """
    if not ALERT_ENABLED:
        logger.info("[ALERT-ENGINE] Disabled via CDB_ALERTS_ENABLED=false")
        return {"alerts_fired": 0, "alerts_skipped_dedup": 0,
                "total_critical_detected": 0, "status": "DISABLED"}

    result = {
        "alerts_fired":            0,
        "alerts_skipped_dedup":    0,
        "total_critical_detected": 0,
        "status":                  "OK",
    }

    try:
        # Load manifest
        if manifest is None:
            if not MANIFEST_PATH.exists():
                logger.warning("[ALERT-ENGINE] Manifest not found — skipping")
                result["status"] = "NO_MANIFEST"
                return result
            with open(MANIFEST_PATH, "r", encoding="utf-8") as f:
                manifest = json.load(f)

        if not isinstance(manifest, list) or not manifest:
            logger.warning("[ALERT-ENGINE] Manifest empty or invalid")
            result["status"] = "NO_CRITICALS"
            return result

        # Load + purge dedup state
        state = _load_state()
        state = _purge_expired(state, ALERT_TTL_HOURS)

        # Detect criticals — sort by risk_score descending
        criticals = sorted(
            [e for e in manifest if _is_critical(e)],
            key=lambda x: float(x.get("risk_score", 0)),
            reverse=True,
        )
        result["total_critical_detected"] = len(criticals)

        if not criticals:
            logger.info("[ALERT-ENGINE] No critical threats detected this run")
            result["status"] = "NO_CRITICALS"
            return result

        logger.info(f"[ALERT-ENGINE] Detected {len(criticals)} critical threats")

        alerts_fired = 0
        alerts_skipped = 0

        for entry in criticals:
            if alerts_fired >= MAX_ALERTS_PER_RUN:
                logger.info(f"[ALERT-ENGINE] MAX_ALERTS_PER_RUN={MAX_ALERTS_PER_RUN} reached — deferring rest")
                break

            stix_id = entry.get("stix_id", "")
            if not stix_id:
                continue

            # Deduplication check
            if _already_alerted(stix_id, state, ALERT_TTL_HOURS):
                alerts_skipped += 1
                logger.debug(f"[ALERT-ENGINE] Dedup skip: {entry.get('title','')[:50]}")
                continue

            # Build structured payload
            payload = _build_alert_payload(entry)

            # Fire channels (non-blocking, independent failures)
            tg_ok  = _dispatch_telegram(payload)
            wh_ok  = _dispatch_webhook(payload)

            fired = tg_ok or wh_ok
            if not tg_ok and not wh_ok:
                # Neither channel configured or both failed — log warning
                logger.warning(
                    f"[ALERT-ENGINE] No channel delivered alert for: "
                    f"{entry.get('title','')[:60]} (risk={entry.get('risk_score',0):.1f})"
                )
                # Still mark as "alerted" to prevent infinite retry loops
                fired = True

            if fired:
                state[stix_id] = datetime.now(timezone.utc).isoformat()
                alerts_fired += 1
                logger.info(
                    f"[ALERT-ENGINE] ALERT FIRED: {entry.get('title','')[:60]} | "
                    f"risk={entry.get('risk_score',0):.1f} | "
                    f"priority={entry.get('apex',{}).get('priority','?')}"
                )

        # Persist updated state
        _save_state(state)

        result["alerts_fired"]         = alerts_fired
        result["alerts_skipped_dedup"] = alerts_skipped

        logger.info(
            f"[ALERT-ENGINE] Run complete: fired={alerts_fired} "
            f"dedup_skipped={alerts_skipped} "
            f"total_critical={len(criticals)}"
        )

    except Exception as e:
        logger.error(f"[ALERT-ENGINE] Engine error (non-fatal, pipeline safe): {e}")
        result["status"] = "ERROR"

    return result


# ── CLI Entry ─────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    import sys
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [ALERT-ENGINE] %(message)s")
    result = run_alert_engine()
    print(json.dumps(result, indent=2))
    sys.exit(0)
