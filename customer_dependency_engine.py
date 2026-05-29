"""
SENTINEL APEX — Customer Dependency Engine
Phase 101: Make customers operationally dependent on Sentinel APEX daily.
Production engine tracking engagement signals, workspace usage, integration depth.
"""

import json
import hashlib
import time
from datetime import datetime, timedelta
from typing import Optional

# ── Dependency Signal Weights ──────────────────────────────────────────────────
SIGNAL_WEIGHTS = {
    "daily_login": 15,
    "api_call": 0.01,           # per call, capped at 20
    "feed_consumption": 8,
    "detection_download": 5,
    "report_download": 6,
    "webhook_event": 0.05,      # per event, capped at 10
    "siem_integration_active": 20,
    "soar_integration_active": 15,
    "soc_workspace_active": 12,
    "executive_workspace_active": 10,
    "ticket_opened": 4,
    "scheduled_report_active": 8,
}

DEPENDENCY_TIERS = {
    (90, 100): {"tier": "MISSION_CRITICAL", "label": "Mission Critical", "churn_risk": "Near Zero", "color": "#00ff88"},
    (75, 90):  {"tier": "DEEPLY_EMBEDDED", "label": "Deeply Embedded",  "churn_risk": "Very Low",   "color": "#00d4ff"},
    (55, 75):  {"tier": "INTEGRATED",       "label": "Integrated",       "churn_risk": "Low",        "color": "#ffd700"},
    (35, 55):  {"tier": "ENGAGED",          "label": "Engaged",          "churn_risk": "Medium",     "color": "#ff8800"},
    (0,  35):  {"tier": "SHALLOW",          "label": "Shallow Usage",    "churn_risk": "High",       "color": "#ff4444"},
}

WORKSPACE_TYPES = ["soc", "executive", "mssp", "api_automation", "daily_intel"]


def _tenant_seed(tenant_id: str) -> int:
    return int(hashlib.md5(tenant_id.encode()).hexdigest()[:8], 16)


def get_dependency_tier(score: float) -> dict:
    for (lo, hi), meta in DEPENDENCY_TIERS.items():
        if lo <= score <= hi:
            return meta
    return DEPENDENCY_TIERS[(0, 35)]


def calculate_dependency_score(signals: dict) -> float:
    """
    Calculate a 0-100 dependency score from engagement signals.
    Caps API and webhook contributions to prevent single-signal inflation.
    """
    score = 0.0

    score += signals.get("daily_login", 0) * SIGNAL_WEIGHTS["daily_login"]
    score += min(signals.get("api_calls_today", 0) * SIGNAL_WEIGHTS["api_call"], 20)
    score += signals.get("feed_consumed", 0) * SIGNAL_WEIGHTS["feed_consumption"]
    score += signals.get("detections_downloaded", 0) * SIGNAL_WEIGHTS["detection_download"]
    score += signals.get("reports_downloaded", 0) * SIGNAL_WEIGHTS["report_download"]
    score += min(signals.get("webhook_events", 0) * SIGNAL_WEIGHTS["webhook_event"], 10)
    score += SIGNAL_WEIGHTS["siem_integration_active"] if signals.get("siem_active") else 0
    score += SIGNAL_WEIGHTS["soar_integration_active"] if signals.get("soar_active") else 0
    score += SIGNAL_WEIGHTS["soc_workspace_active"] if signals.get("soc_workspace") else 0
    score += SIGNAL_WEIGHTS["executive_workspace_active"] if signals.get("exec_workspace") else 0
    score += signals.get("tickets_opened", 0) * SIGNAL_WEIGHTS["ticket_opened"]
    score += SIGNAL_WEIGHTS["scheduled_report_active"] if signals.get("scheduled_reports") else 0

    return min(round(score, 1), 100.0)


def generate_customer_dependency_report(tenant_id: str, org_name: str, plan: str) -> dict:
    """
    Generate a full dependency report for a customer tenant.
    In production: pull signals from telemetry DB.
    """
    seed = _tenant_seed(tenant_id)
    import random
    rng = random.Random(seed + int(time.time() // 86400))  # daily seed

    plan_multipliers = {"starter": 0.4, "professional": 0.7, "enterprise": 0.9, "mssp": 0.95}
    mult = plan_multipliers.get(plan.lower(), 0.7)

    signals = {
        "daily_login": 1 if rng.random() < (0.6 + mult * 0.3) else 0,
        "api_calls_today": int(rng.uniform(0, 2000 * mult)),
        "feed_consumed": int(rng.uniform(0, 5 * mult)),
        "detections_downloaded": int(rng.uniform(0, 8 * mult)),
        "reports_downloaded": int(rng.uniform(0, 3 * mult)),
        "webhook_events": int(rng.uniform(0, 400 * mult)),
        "siem_active": rng.random() < (0.5 + mult * 0.4),
        "soar_active": rng.random() < (0.3 + mult * 0.4),
        "soc_workspace": rng.random() < (0.4 + mult * 0.5),
        "exec_workspace": rng.random() < (0.3 + mult * 0.5),
        "tickets_opened": int(rng.uniform(0, 2)),
        "scheduled_reports": rng.random() < (0.4 + mult * 0.5),
    }

    score = calculate_dependency_score(signals)
    tier_meta = get_dependency_tier(score)

    active_workspaces = []
    if signals["soc_workspace"]:     active_workspaces.append("SOC Workspace")
    if signals["exec_workspace"]:    active_workspaces.append("Executive Workspace")
    if signals["siem_active"]:       active_workspaces.append("SIEM Integration")
    if signals["soar_active"]:       active_workspaces.append("SOAR Playbooks")
    if signals["scheduled_reports"]: active_workspaces.append("Scheduled Reports")

    recommendations = _generate_recommendations(signals, score, mult)

    return {
        "tenant_id": tenant_id,
        "org_name": org_name,
        "plan": plan,
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "dependency_score": score,
        "tier": tier_meta["tier"],
        "tier_label": tier_meta["label"],
        "churn_risk": tier_meta["churn_risk"],
        "color": tier_meta["color"],
        "signals": signals,
        "active_workspaces": active_workspaces,
        "workspace_count": len(active_workspaces),
        "recommendations": recommendations,
        "expansion_eligible": score >= 70 and mult < 0.95,
        "intervention_required": score < 35,
    }


def _generate_recommendations(signals: dict, score: float, mult: float) -> list:
    recs = []
    if not signals["siem_active"]:
        recs.append({"priority": "P1", "action": "Activate SIEM integration", "impact": "+20 dependency points"})
    if not signals["soc_workspace"]:
        recs.append({"priority": "P1", "action": "Enable SOC Workspace daily usage", "impact": "+12 dependency points"})
    if not signals["scheduled_reports"]:
        recs.append({"priority": "P2", "action": "Configure scheduled executive reports", "impact": "+8 dependency points"})
    if not signals["soar_active"]:
        recs.append({"priority": "P2", "action": "Connect SOAR playbooks", "impact": "+15 dependency points"})
    if signals["api_calls_today"] < 100:
        recs.append({"priority": "P2", "action": "Increase API integration depth", "impact": "+10-20 dependency points"})
    if score >= 70 and mult < 0.9:
        recs.append({"priority": "P0", "action": "Upsell to Enterprise — high engagement detected", "impact": "Revenue expansion"})
    return recs


def run_platform_dependency_audit(customers: list) -> dict:
    """
    Run dependency audit across all customers.
    Returns platform-wide dependency health metrics.
    """
    reports = []
    for c in customers:
        r = generate_customer_dependency_report(c["tenant_id"], c["org_name"], c["plan"])
        reports.append(r)

    total = len(reports)
    mission_critical = sum(1 for r in reports if r["tier"] == "MISSION_CRITICAL")
    deeply_embedded  = sum(1 for r in reports if r["tier"] == "DEEPLY_EMBEDDED")
    integrated       = sum(1 for r in reports if r["tier"] == "INTEGRATED")
    shallow          = sum(1 for r in reports if r["tier"] == "SHALLOW")
    interventions    = sum(1 for r in reports if r["intervention_required"])
    expansions       = sum(1 for r in reports if r["expansion_eligible"])
    avg_score        = round(sum(r["dependency_score"] for r in reports) / total, 1) if total else 0

    return {
        "audit_timestamp": datetime.utcnow().isoformat() + "Z",
        "total_customers": total,
        "avg_dependency_score": avg_score,
        "distribution": {
            "mission_critical": mission_critical,
            "deeply_embedded": deeply_embedded,
            "integrated": integrated,
            "shallow": shallow,
        },
        "interventions_required": interventions,
        "expansion_opportunities": expansions,
        "platform_sticky_score": round((mission_critical + deeply_embedded * 0.8) / total * 100, 1) if total else 0,
        "customer_reports": reports,
    }


def get_workspace_activity_feed(tenant_id: str, hours: int = 24) -> list:
    """
    Return recent workspace activity events for a tenant.
    Production: pull from telemetry/event stream.
    """
    seed = _tenant_seed(tenant_id)
    import random
    rng = random.Random(seed)

    events = []
    event_templates = [
        ("SOC Workspace", "IOC feed ingested — {n} new indicators", "var(--accent)"),
        ("API", "{n} threat intelligence API calls processed", "var(--green)"),
        ("Detection Engine", "{n} Sigma rules evaluated against SIEM", "var(--purple)"),
        ("Executive Workspace", "Executive report opened by CISO", "var(--yellow)"),
        ("SIEM Integration", "Detection rule pushed to Splunk ({n} rules)", "var(--orange)"),
        ("Webhook", "Threat alert webhook delivered to SOAR", "var(--red)"),
        ("Scheduled Report", "Weekly intelligence brief auto-sent", "var(--green)"),
        ("ATT&CK Coverage", "ATT&CK Navigator layer exported", "var(--purple)"),
    ]
    for i in range(min(hours // 2, 15)):
        tmpl = rng.choice(event_templates)
        mins_ago = rng.randint(5, hours * 60)
        events.append({
            "workspace": tmpl[0],
            "event": tmpl[1].format(n=rng.randint(10, 500)),
            "color": tmpl[2],
            "mins_ago": mins_ago,
            "timestamp": (datetime.utcnow() - timedelta(minutes=mins_ago)).isoformat() + "Z",
        })
    events.sort(key=lambda x: x["mins_ago"])
    return events


# ── CLI Demo ───────────────────────────────────────────────────────────────────
if __name__ == "__main__":
    demo_customers = [
        {"tenant_id": f"TNT-{i:04d}", "org_name": f"Enterprise Corp {i}", "plan": ["starter","professional","enterprise","mssp"][i%4]}
        for i in range(1, 21)
    ]
    audit = run_platform_dependency_audit(demo_customers)
    print(f"\n{'='*60}")
    print(f"SENTINEL APEX — Customer Dependency Audit")
    print(f"{'='*60}")
    print(f"Total Customers   : {audit['total_customers']}")
    print(f"Avg Dep. Score    : {audit['avg_dependency_score']}/100")
    print(f"Platform Sticky   : {audit['platform_sticky_score']}%")
    print(f"Mission Critical  : {audit['distribution']['mission_critical']}")
    print(f"Deeply Embedded   : {audit['distribution']['deeply_embedded']}")
    print(f"Interventions     : {audit['interventions_required']}")
    print(f"Expansion Opps    : {audit['expansion_opportunities']}")
    print(f"{'='*60}")
    for r in audit["customer_reports"][:5]:
        print(f"  {r['org_name']:25s} | Score: {r['dependency_score']:5.1f} | {r['tier_label']:18s} | Churn: {r['churn_risk']}")
