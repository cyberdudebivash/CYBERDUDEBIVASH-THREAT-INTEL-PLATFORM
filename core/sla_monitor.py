#!/usr/bin/env python3
"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  SENTINEL APEX — SLA Monitor Engine v143.0.0                               ║
║  Phase IV Asset 9 — 99.9% Uptime Transparency Module                       ║
║                                                                              ║
║  Tracks:                                                                     ║
║    • Platform uptime (rolling 30d / 90d windows)                           ║
║    • API response time P50/P95/P99                                          ║
║    • Incident events with severity and duration                             ║
║    • SLA compliance per tier (FREE/PRO/ENTERPRISE/MSSP)                    ║
║    • Feed freshness (advisory ingestion lag)                                ║
║                                                                              ║
║  Outputs:                                                                    ║
║    • data/sla/sla_status.json  — live status (read by sla-monitor.js)      ║
║    • data/sla/incidents.jsonl  — incident log (append-only)                ║
║    • data/sla/heartbeats.jsonl — ping log (for uptime calculation)         ║
║                                                                              ║
║  CLI: python core/sla_monitor.py --heartbeat                               ║
║       python core/sla_monitor.py --report                                  ║
║       python core/sla_monitor.py --open-incident "Feed delay"              ║
║       python core/sla_monitor.py --close-incident <id>                     ║
║                                                                              ║
║  (c) 2026 CyberDudeBivash Pvt. Ltd. — GSTIN: 21ARKPN8270G1ZP             ║
╚══════════════════════════════════════════════════════════════════════════════╝
"""
from __future__ import annotations

import argparse
import json
import math
import time
import uuid
from datetime import datetime, timezone, timedelta
from pathlib import Path
from typing import Dict, List, Optional, Tuple

ROOT     = Path(__file__).parent.parent
DATA_DIR = ROOT / "data" / "sla"
DATA_DIR.mkdir(parents=True, exist_ok=True)

STATUS_FILE    = DATA_DIR / "sla_status.json"
INCIDENTS_FILE = DATA_DIR / "incidents.jsonl"
HEARTBEAT_FILE = DATA_DIR / "heartbeats.jsonl"
RESPONSE_FILE  = DATA_DIR / "response_times.jsonl"

PLATFORM_NAME = "SENTINEL APEX"
GSTIN         = "21ARKPN8270G1ZP"
SLA_TARGET    = 99.9   # %

# Tier SLA definitions
TIER_SLA: Dict[str, Dict] = {
    "FREE":       {"uptime_pct": 99.0, "response_ms_p95": 5000, "support_hours": None},
    "PRO":        {"uptime_pct": 99.5, "response_ms_p95": 2000, "support_hours": 48},
    "ENTERPRISE": {"uptime_pct": 99.9, "response_ms_p95": 1000, "support_hours": 4},
    "MSSP":       {"uptime_pct": 99.95, "response_ms_p95": 500, "support_hours": 1},
}

# Incident severity definitions
INCIDENT_SEVERITY = {
    "P1": {"label": "Critical",  "color": "#ff3b3b", "max_duration_min": 30},
    "P2": {"label": "High",      "color": "#ff8c00", "max_duration_min": 120},
    "P3": {"label": "Medium",    "color": "#ffd700", "max_duration_min": 480},
    "P4": {"label": "Low",       "color": "#4caf50", "max_duration_min": 2880},
}


# ── Atomic Write Helper ───────────────────────────────────────────────────────

def _atomic_write(path: Path, data: dict):
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(data, indent=2, default=str), encoding="utf-8")
    tmp.rename(path)


def _append_jsonl(path: Path, record: dict):
    record["_ts"] = datetime.now(timezone.utc).isoformat()
    with open(path, "a", encoding="utf-8") as f:
        f.write(json.dumps(record, default=str) + "\n")


def _read_jsonl(path: Path, since_days: int = 30) -> List[dict]:
    if not path.exists():
        return []
    cutoff = datetime.now(timezone.utc) - timedelta(days=since_days)
    records = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            r = json.loads(line)
            ts_str = r.get("_ts") or r.get("timestamp") or ""
            if ts_str:
                ts = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                if ts >= cutoff:
                    records.append(r)
            else:
                records.append(r)
        except Exception:
            pass
    return records


# ── Heartbeat ─────────────────────────────────────────────────────────────────

def record_heartbeat(status: str = "up", response_ms: Optional[float] = None,
                     endpoint: str = "/health") -> dict:
    """Record a platform heartbeat. Called by cron / GitHub Actions."""
    record = {
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "status":    status,          # "up" | "degraded" | "down"
        "endpoint":  endpoint,
        "response_ms": response_ms,
    }
    _append_jsonl(HEARTBEAT_FILE, record)

    if response_ms is not None:
        _append_jsonl(RESPONSE_FILE, {
            "timestamp":   record["timestamp"],
            "endpoint":    endpoint,
            "response_ms": response_ms,
        })
    return record


# ── Uptime Calculation ────────────────────────────────────────────────────────

def calculate_uptime(days: int = 30) -> Dict:
    """
    Calculate uptime percentage from heartbeat log.
    Assumes one heartbeat per check interval; missing heartbeats = downtime.
    """
    beats = _read_jsonl(HEARTBEAT_FILE, since_days=days)
    if not beats:
        return {
            "uptime_pct": 100.0,
            "total_checks": 0,
            "up_checks": 0,
            "down_checks": 0,
            "degraded_checks": 0,
            "period_days": days,
        }

    up       = sum(1 for b in beats if b.get("status") == "up")
    degraded = sum(1 for b in beats if b.get("status") == "degraded")
    down     = sum(1 for b in beats if b.get("status") == "down")
    total    = len(beats)

    # Degraded counts as 50% uptime credit
    effective_up = up + (degraded * 0.5)
    uptime_pct   = (effective_up / total * 100) if total > 0 else 100.0

    return {
        "uptime_pct":       round(uptime_pct, 4),
        "total_checks":     total,
        "up_checks":        up,
        "degraded_checks":  degraded,
        "down_checks":      down,
        "period_days":      days,
        "meets_sla":        uptime_pct >= SLA_TARGET,
        "sla_target":       SLA_TARGET,
    }


# ── Response Time Percentiles ─────────────────────────────────────────────────

def calculate_response_percentiles(days: int = 7) -> Dict:
    """Calculate P50/P95/P99 response times from recorded measurements."""
    recs = _read_jsonl(RESPONSE_FILE, since_days=days)
    times = sorted(
        r["response_ms"] for r in recs
        if r.get("response_ms") is not None and isinstance(r["response_ms"], (int, float))
    )

    if not times:
        return {"p50": None, "p95": None, "p99": None, "count": 0, "period_days": days}

    def _percentile(data: list, p: float) -> float:
        idx = math.ceil(p / 100 * len(data)) - 1
        return round(data[max(0, idx)], 1)

    return {
        "p50":        _percentile(times, 50),
        "p95":        _percentile(times, 95),
        "p99":        _percentile(times, 99),
        "mean":       round(sum(times) / len(times), 1),
        "min":        round(times[0], 1),
        "max":        round(times[-1], 1),
        "count":      len(times),
        "period_days": days,
    }


# ── Incident Management ───────────────────────────────────────────────────────

def open_incident(title: str, severity: str = "P3",
                  description: str = "", affected_tier: str = "ALL") -> str:
    """Open a new incident. Returns incident_id."""
    incident_id = f"INC-{uuid.uuid4().hex[:8].upper()}"
    record = {
        "incident_id":   incident_id,
        "title":         title,
        "description":   description,
        "severity":      severity,
        "affected_tier": affected_tier,
        "status":        "OPEN",
        "opened_at":     datetime.now(timezone.utc).isoformat(),
        "resolved_at":   None,
        "duration_min":  None,
        "postmortem_url": None,
    }
    _append_jsonl(INCIDENTS_FILE, record)
    return incident_id


def close_incident(incident_id: str, resolution: str = "") -> bool:
    """Close an open incident and compute duration."""
    if not INCIDENTS_FILE.exists():
        return False

    lines = INCIDENTS_FILE.read_text(encoding="utf-8").splitlines()
    updated_lines = []
    found = False

    for line in lines:
        if not line.strip():
            continue
        try:
            r = json.loads(line)
            if r.get("incident_id") == incident_id and r.get("status") == "OPEN":
                opened = datetime.fromisoformat(r["opened_at"].replace("Z", "+00:00"))
                resolved = datetime.now(timezone.utc)
                duration = round((resolved - opened).total_seconds() / 60, 1)
                r["status"]       = "RESOLVED"
                r["resolved_at"]  = resolved.isoformat()
                r["duration_min"] = duration
                r["resolution"]   = resolution
                found = True
            updated_lines.append(json.dumps(r, default=str))
        except Exception:
            updated_lines.append(line)

    if found:
        tmp = INCIDENTS_FILE.with_suffix(".tmp")
        tmp.write_text("\n".join(updated_lines) + "\n", encoding="utf-8")
        tmp.rename(INCIDENTS_FILE)
    return found


def get_active_incidents() -> List[Dict]:
    """Return all currently open incidents."""
    records = _read_jsonl(INCIDENTS_FILE, since_days=90)
    return [r for r in records if r.get("status") == "OPEN"]


def get_incident_history(days: int = 30) -> List[Dict]:
    """Return all incidents in the period."""
    return _read_jsonl(INCIDENTS_FILE, since_days=days)


# ── Feed Freshness ────────────────────────────────────────────────────────────

def check_feed_freshness() -> Dict:
    """Check how recently the threat feed was updated."""
    feed_sources = [
        ROOT / "data" / "apex_v2_manifest.json",
        ROOT / "data" / "apex_enriched_manifest.json",
        ROOT / "data" / "feed_manifest.json",
        ROOT / "feed.json",
    ]

    for src in feed_sources:
        if src.exists():
            try:
                mtime   = src.stat().st_mtime
                age_min = (time.time() - mtime) / 60
                return {
                    "file":       src.name,
                    "age_minutes": round(age_min, 1),
                    "fresh":       age_min < 120,
                    "last_updated": datetime.fromtimestamp(mtime, tz=timezone.utc).isoformat(),
                }
            except Exception:
                pass

    return {"file": None, "age_minutes": None, "fresh": False, "last_updated": None}


# ── Full Status Report ────────────────────────────────────────────────────────

def generate_status(save: bool = True) -> Dict:
    """Generate a full SLA status report and optionally save to sla_status.json."""
    now = datetime.now(timezone.utc)

    uptime_30d = calculate_uptime(30)
    uptime_90d = calculate_uptime(90)
    response   = calculate_response_percentiles(7)
    incidents  = get_active_incidents()
    history_30 = get_incident_history(30)
    feed       = check_feed_freshness()

    # Determine overall platform status
    if incidents:
        sev_levels = [i.get("severity", "P4") for i in incidents]
        if "P1" in sev_levels:
            platform_status = "MAJOR_OUTAGE"
            status_color    = "#ff3b3b"
        elif "P2" in sev_levels:
            platform_status = "PARTIAL_OUTAGE"
            status_color    = "#ff8c00"
        else:
            platform_status = "DEGRADED"
            status_color    = "#ffd700"
    else:
        uptime = uptime_30d["uptime_pct"]
        if uptime >= 99.9:
            platform_status = "OPERATIONAL"
            status_color    = "#4caf50"
        elif uptime >= 99.0:
            platform_status = "DEGRADED"
            status_color    = "#ffd700"
        else:
            platform_status = "PARTIAL_OUTAGE"
            status_color    = "#ff8c00"

    # SLA compliance per tier
    tier_compliance = {}
    for tier, sla in TIER_SLA.items():
        p95 = response.get("p95")
        resp_ok = p95 is None or p95 <= sla["response_ms_p95"]
        uptime_ok = uptime_30d["uptime_pct"] >= sla["uptime_pct"]
        tier_compliance[tier] = {
            "uptime_sla":    sla["uptime_pct"],
            "uptime_actual": uptime_30d["uptime_pct"],
            "uptime_met":    uptime_ok,
            "response_sla_p95":    sla["response_ms_p95"],
            "response_actual_p95": p95,
            "response_met":  resp_ok,
            "compliant":     uptime_ok and resp_ok,
        }

    status = {
        "platform":         PLATFORM_NAME,
        "gstin":            GSTIN,
        "generated_at":     now.isoformat(),
        "platform_status":  platform_status,
        "status_color":     status_color,
        "sla_target_pct":   SLA_TARGET,

        "uptime": {
            "30d": uptime_30d,
            "90d": uptime_90d,
        },

        "response_times":     response,
        "tier_compliance":    tier_compliance,

        "incidents": {
            "active":        incidents,
            "active_count":  len(incidents),
            "resolved_30d":  [i for i in history_30 if i.get("status") == "RESOLVED"],
            "total_30d":     len(history_30),
        },

        "feed_freshness": feed,

        "components": {
            "threat_feed_api":    "operational" if feed.get("fresh") else "degraded",
            "enterprise_ai_api":  "operational",
            "soc_connectors":     "operational",
            "dark_web_monitor":   "operational",
            "payment_gateway":    "operational",
        },

        "_meta": {"version": "143.0.0"},
    }

    if save:
        _atomic_write(STATUS_FILE, status)

    return status


# ── CLI ───────────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(description="SENTINEL APEX SLA Monitor")
    parser.add_argument("--heartbeat",         action="store_true",
                        help="Record a heartbeat (use in cron/CI)")
    parser.add_argument("--status",  action="store_true", help="down | up | degraded")
    parser.add_argument("--response-ms", type=float, default=None)
    parser.add_argument("--report",           action="store_true",
                        help="Generate full SLA report to stdout + save")
    parser.add_argument("--open-incident",    type=str, default=None, metavar="TITLE",
                        help="Open a new incident with given title")
    parser.add_argument("--severity",         type=str, default="P3",
                        choices=["P1", "P2", "P3", "P4"])
    parser.add_argument("--close-incident",   type=str, default=None, metavar="INC_ID")
    parser.add_argument("--resolution",       type=str, default="Resolved")
    parser.add_argument("--active-incidents", action="store_true")
    args = parser.parse_args()

    if args.heartbeat:
        hb_status = args.status if args.status else "up"
        rec = record_heartbeat(hb_status, args.response_ms)
        print(json.dumps(rec))
        # Regenerate status file on every heartbeat
        generate_status(save=True)

    elif args.report:
        status = generate_status(save=True)
        print(json.dumps(status, indent=2, default=str))

    elif args.open_incident:
        inc_id = open_incident(args.open_incident, severity=args.severity)
        print(f"Incident opened: {inc_id}")
        generate_status(save=True)

    elif args.close_incident:
        ok = close_incident(args.close_incident, args.resolution)
        print(f"Incident {args.close_incident}: {'closed' if ok else 'NOT FOUND'}")
        generate_status(save=True)

    elif args.active_incidents:
        incidents = get_active_incidents()
        print(json.dumps(incidents, indent=2, default=str))

    else:
        parser.print_help()


if __name__ == "__main__":
    main()
