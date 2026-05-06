#!/usr/bin/env python3
"""
CYBERDUDEBIVASH(R) SENTINEL APEX -- Enterprise Alert Manager
============================================================
Phase 3: Enterprise Incident Alerting System

Implements P0/P1/P2/P3 severity alerting via Telegram:
  P0 -- CRITICAL: API outage, deployment failure, frontend corruption
  P1 -- HIGH: SLA breach, rollback triggered, manifest stale
  P2 -- MEDIUM: Latency degradation, workflow timeout, hydration failure
  P3 -- LOW: Advisory: canary bake, deploy initiated, routine checks

Alert channels:
  - Telegram (primary)
  - JSON alert log (always written)

Usage:
  python3 scripts/enterprise_alert_manager.py alert --severity P0 --title "API DOWN" --detail "..."
  python3 scripts/enterprise_alert_manager.py check  -- run full platform health check + alert on issues
  python3 scripts/enterprise_alert_manager.py history -- print alert history
"""

import argparse
import json
import os
import pathlib
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timezone

REPO_ROOT   = pathlib.Path(__file__).resolve().parent.parent
ALERTS_DIR  = REPO_ROOT / "data" / "alerts"
ALERTS_DIR.mkdir(parents=True, exist_ok=True)

ALERT_LOG   = ALERTS_DIR / "alert_history.json"
WORKER_BASE = "https://intel.cyberdudebivash.com"

# Severity configuration
SEVERITY_CONFIG = {
    "P0": {"label": "CRITICAL", "emoji": "🔴", "pager": True,  "min_interval_s": 60},
    "P1": {"label": "HIGH",     "emoji": "🟠", "pager": True,  "min_interval_s": 300},
    "P2": {"label": "MEDIUM",   "emoji": "🟡", "pager": False, "min_interval_s": 600},
    "P3": {"label": "LOW",      "emoji": "🟢", "pager": False, "min_interval_s": 1800},
}

# Alert type templates
ALERT_TEMPLATES = {
    "API_OUTAGE":         {"severity": "P0", "title": "API OUTAGE DETECTED"},
    "DEPLOY_FAILURE":     {"severity": "P0", "title": "DEPLOYMENT FAILED"},
    "FRONTEND_CORRUPT":   {"severity": "P0", "title": "FRONTEND INTEGRITY VIOLATION"},
    "ROLLBACK_TRIGGERED": {"severity": "P0", "title": "ROLLBACK TRIGGERED"},
    "SLA_BREACH":         {"severity": "P1", "title": "SLA BREACH DETECTED"},
    "MANIFEST_STALE":     {"severity": "P1", "title": "MANIFEST FRESHNESS VIOLATION"},
    "WORKFLOW_TIMEOUT":   {"severity": "P1", "title": "WORKFLOW TIMEOUT DETECTED"},
    "LATENCY_DEGRADED":   {"severity": "P2", "title": "API LATENCY DEGRADATION"},
    "HYDRATION_FAILURE":  {"severity": "P2", "title": "AI HYDRATION FAILURE"},
    "DEPLOY_INITIATED":   {"severity": "P3", "title": "DEPLOYMENT INITIATED"},
    "CANARY_BAKE_START":  {"severity": "P3", "title": "CANARY BAKE STARTED"},
    "HEALTH_CHECK_PASS":  {"severity": "P3", "title": "HEALTH CHECK PASSED"},
}


def now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def load_alert_history() -> list:
    if not ALERT_LOG.exists():
        return []
    return json.loads(ALERT_LOG.read_text()).get("alerts", [])


def save_alert(alert: dict):
    alerts = load_alert_history()
    alerts.append(alert)
    alerts = alerts[-500:]
    ALERT_LOG.write_text(json.dumps({"alerts": alerts, "updated_at": now_iso()}, indent=2))


def get_telegram_config() -> dict:
    """Read Telegram bot config from env or secrets."""
    return {
        "bot_token": os.environ.get("TELEGRAM_BOT_TOKEN", ""),
        "chat_id": os.environ.get("TELEGRAM_CHAT_ID", ""),
    }


def send_telegram(message: str, config: dict) -> bool:
    """Send a message via Telegram Bot API."""
    token = config.get("bot_token", "")
    chat_id = config.get("chat_id", "")
    if not token or not chat_id:
        return False
    try:
        payload = json.dumps({
            "chat_id": chat_id,
            "text": message,
            "parse_mode": "HTML",
            "disable_web_page_preview": True,
        }).encode()
        req = urllib.request.Request(
            f"https://api.telegram.org/bot{token}/sendMessage",
            data=payload,
            headers={"Content-Type": "application/json"},
        )
        with urllib.request.urlopen(req, timeout=10) as resp:
            return resp.status == 200
    except Exception as e:
        print(f"[ALERT] Telegram send failed: {e}")
        return False


def build_telegram_message(severity: str, title: str, detail: str,
                           alert_type: str = "CUSTOM", platform_url: str = WORKER_BASE) -> str:
    cfg = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["P2"])
    emoji = cfg["emoji"]
    label = cfg["label"]
    ts = now_iso()[:19].replace("T", " ") + " UTC"

    lines = [
        f"{emoji} <b>SENTINEL APEX ALERT</b> {emoji}",
        f"",
        f"<b>Severity:</b> {severity} — {label}",
        f"<b>Type:</b> {alert_type}",
        f"<b>Title:</b> {title}",
        f"",
        f"<b>Detail:</b>",
        f"{detail[:800]}",
        f"",
        f"<b>Platform:</b> {platform_url}",
        f"<b>Time:</b> {ts}",
    ]
    return "\n".join(lines)


def fire_alert(severity: str, title: str, detail: str, alert_type: str = "CUSTOM",
               source: str = "manual") -> dict:
    """Fire an alert: log it + send Telegram."""
    cfg = SEVERITY_CONFIG.get(severity, SEVERITY_CONFIG["P2"])
    alert = {
        "id": f"alert-{int(time.time())}",
        "fired_at": now_iso(),
        "severity": severity,
        "label": cfg["label"],
        "type": alert_type,
        "title": title,
        "detail": detail[:1000],
        "source": source,
        "telegram_sent": False,
    }

    # Always log
    save_alert(alert)
    print(f"[ALERT] {cfg['emoji']} {severity}/{cfg['label']}: {title}")
    print(f"[ALERT] Detail: {detail[:200]}")

    # Telegram
    tg_config = get_telegram_config()
    if tg_config["bot_token"] and tg_config["chat_id"]:
        msg = build_telegram_message(severity, title, detail, alert_type)
        sent = send_telegram(msg, tg_config)
        alert["telegram_sent"] = sent
        if sent:
            print(f"[ALERT] Telegram notification sent")
        else:
            print(f"[ALERT] Telegram notification failed (non-critical)")
    else:
        print(f"[ALERT] Telegram not configured (TELEGRAM_BOT_TOKEN/TELEGRAM_CHAT_ID missing)")

    return alert


def probe_endpoint(url: str, timeout: int = 10) -> dict:
    t0 = time.monotonic()
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "SENTINEL-APEX-ALERT/1.0"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            latency_ms = int((time.monotonic() - t0) * 1000)
            body = resp.read(4096).decode("utf-8", errors="replace")
            return {"ok": True, "status": resp.status, "latency_ms": latency_ms, "body": body}
    except Exception as e:
        latency_ms = int((time.monotonic() - t0) * 1000)
        return {"ok": False, "status": 0, "latency_ms": latency_ms, "error": str(e)}


def cmd_check(args) -> int:
    """Full platform health check -- fire alerts on any issues."""
    print(f"[ALERT] Running platform health check...")
    alerts_fired = 0

    # Check API endpoints
    endpoints = {
        "health":      f"{WORKER_BASE}/api/health",
        "latest_json": f"{WORKER_BASE}/api/v1/intel/latest.json",
        "top10_json":  f"{WORKER_BASE}/api/v1/intel/top10.json",
        "feed_json":   f"{WORKER_BASE}/api/feed.json",
    }

    down = []
    latencies = []
    for name, url in endpoints.items():
        r = probe_endpoint(url)
        if not r["ok"]:
            down.append(name)
        else:
            latencies.append(r["latency_ms"])
        print(f"  [{('OK' if r['ok'] else 'FAIL')}] {name}: HTTP {r['status']} {r['latency_ms']}ms")

    if down:
        fire_alert(
            severity="P0",
            title="API ENDPOINT OUTAGE",
            detail=f"Down endpoints: {', '.join(down)}. Live check at {now_iso()[:19]}Z",
            alert_type="API_OUTAGE",
            source="health-check",
        )
        alerts_fired += 1
    else:
        print(f"[ALERT] All API endpoints healthy")

    # Latency check (P95 > 3000ms = P2 alert)
    if latencies:
        latencies.sort()
        p95 = latencies[max(0, int(len(latencies) * 0.95) - 1)]
        if p95 > 3000:
            fire_alert(
                severity="P2",
                title="API LATENCY DEGRADATION",
                detail=f"P95 latency {p95}ms exceeds 3000ms threshold. Check Worker payload sizes.",
                alert_type="LATENCY_DEGRADED",
                source="health-check",
            )
            alerts_fired += 1

    # Check SLA data file
    sla_path = REPO_ROOT / "data" / "health" / "sla_status.json"
    if sla_path.exists():
        try:
            sla = json.loads(sla_path.read_text())
            grade = sla.get("sla_evaluation", {}).get("grade", "?")
            score = sla.get("sla_evaluation", {}).get("sla_score", 0)
            if grade in ("C", "D") or score < 70:
                fire_alert(
                    severity="P1",
                    title="SLA GRADE DEGRADED",
                    detail=f"SLA grade dropped to {grade} ({score}/100). Review violations immediately.",
                    alert_type="SLA_BREACH",
                    source="health-check",
                )
                alerts_fired += 1
        except Exception:
            pass

    if alerts_fired == 0:
        print(f"[ALERT] Platform healthy -- no alerts fired")
        fire_alert(
            severity="P3",
            title="Health Check Passed",
            detail=f"All endpoints operational. P95 latency: {latencies[-1] if latencies else 'N/A'}ms. {now_iso()[:19]}Z",
            alert_type="HEALTH_CHECK_PASS",
            source="health-check",
        )

    return 0 if not down else 1


def cmd_alert(args) -> int:
    """Fire a manual alert."""
    severity = args.severity.upper()
    if severity not in SEVERITY_CONFIG:
        print(f"[ALERT] Invalid severity: {severity} (valid: P0/P1/P2/P3)")
        return 1
    fire_alert(
        severity=severity,
        title=args.title,
        detail=args.detail,
        alert_type=getattr(args, "type", "CUSTOM"),
        source="manual",
    )
    return 0


def cmd_history(args) -> int:
    """Print alert history."""
    alerts = load_alert_history()
    print(f"\nALERT HISTORY ({len(alerts)} alerts)")
    print("=" * 70)
    for a in alerts[-20:]:
        ts = a.get("fired_at", "?")[:19]
        sev = a.get("severity", "?")
        cfg = SEVERITY_CONFIG.get(sev, {})
        em = cfg.get("emoji", "?")
        title = a.get("title", "?")[:40]
        tg = "TG:sent" if a.get("telegram_sent") else "TG:skip"
        print(f"  {ts}  {em} {sev}  {title:<40}  {tg}")
    print("=" * 70)
    return 0


def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX Enterprise Alert Manager")
    sub = parser.add_subparsers(dest="cmd")

    p_alert = sub.add_parser("alert", help="Fire a manual alert")
    p_alert.add_argument("--severity", required=True, choices=["P0","P1","P2","P3"])
    p_alert.add_argument("--title", required=True)
    p_alert.add_argument("--detail", required=True)
    p_alert.add_argument("--type", default="CUSTOM")

    sub.add_parser("check", help="Full health check + auto-alert on issues")
    sub.add_parser("history", help="Print alert history")

    args = parser.parse_args()
    dispatch = {
        "alert":   cmd_alert,
        "check":   cmd_check,
        "history": cmd_history,
    }
    if args.cmd not in dispatch:
        parser.print_help()
        return 1
    return dispatch[args.cmd](args)


if __name__ == "__main__":
    sys.exit(main())
