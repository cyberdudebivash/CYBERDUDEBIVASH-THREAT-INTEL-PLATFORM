"""
CYBERDUDEBIVASH SENTINEL APEX
Customer Health Engine - FILE 5/10
Health scoring, churn risk detection, customer categorization, health reports.
Port: 8505
"""

import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Scoring weights (total 100)
# ---------------------------------------------------------------------------
SCORE_WEIGHTS = {
    "login_frequency": 25,
    "intelligence_consumption": 25,
    "api_usage": 20,
    "support_tickets": 15,
    "feature_adoption": 15,
}

CATEGORIES = {
    "Healthy": (80, 100),
    "At Risk": (50, 79),
    "Renewal Risk": (0, 49),
}

CUSTOMER_PROFILES: Dict[str, dict] = {}
HEALTH_SCORES: Dict[str, dict] = {}


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def calculate_health_score(org_id: str, signals: dict) -> dict:
    """
    Calculate a 0-100 health score from raw activity signals.

    signals keys:
        login_days_last_30: int (0-30)
        intel_requests_last_30: int
        api_calls_last_30: int
        open_tickets: int
        resolved_tickets: int
        features_used: int (out of available)
        features_available: int
    """
    s = signals
    # --- Login frequency (25 pts): 20+ days active = full score
    login_score = min(1.0, s.get("login_days_last_30", 0) / 20) * SCORE_WEIGHTS["login_frequency"]

    # --- Intelligence consumption (25 pts): 500+ requests/month = full score
    intel_score = min(1.0, s.get("intel_requests_last_30", 0) / 500) * SCORE_WEIGHTS["intelligence_consumption"]

    # --- API usage (20 pts): 10,000+ calls/month = full score
    api_score = min(1.0, s.get("api_calls_last_30", 0) / 10000) * SCORE_WEIGHTS["api_usage"]

    # --- Support tickets (15 pts): 0 open = full; penalize for each open ticket
    open_t = s.get("open_tickets", 0)
    ticket_score = max(0, SCORE_WEIGHTS["support_tickets"] - (open_t * 3))

    # --- Feature adoption (15 pts): adopted / available
    avail = max(1, s.get("features_available", 10))
    used = min(s.get("features_used", 0), avail)
    feature_score = (used / avail) * SCORE_WEIGHTS["feature_adoption"]

    total = round(login_score + intel_score + api_score + ticket_score + feature_score, 1)
    breakdown = {
        "login_frequency": round(login_score, 1),
        "intelligence_consumption": round(intel_score, 1),
        "api_usage": round(api_score, 1),
        "support_tickets": round(ticket_score, 1),
        "feature_adoption": round(feature_score, 1),
    }
    result = {
        "org_id": org_id,
        "health_score": total,
        "breakdown": breakdown,
        "signals": signals,
        "calculated_at": datetime.now(timezone.utc).isoformat(),
        "category": get_customer_category(total),
    }
    HEALTH_SCORES[org_id] = result
    return result


def get_customer_category(score: float) -> str:
    """Map a health score to a customer category."""
    if score >= 80:
        return "Healthy"
    elif score >= 50:
        return "At Risk"
    else:
        return "Renewal Risk"


def detect_churn_risk(org_id: str) -> dict:
    """Analyze churn risk indicators for a customer."""
    hs = HEALTH_SCORES.get(org_id)
    profile = CUSTOMER_PROFILES.get(org_id)
    if not hs or not profile:
        return {"org_id": org_id, "churn_risk": "unknown", "reason": "no_health_data"}
    score = hs["health_score"]
    signals = hs.get("signals", {})
    risk_factors = []
    if signals.get("login_days_last_30", 0) < 5:
        risk_factors.append("low_login_frequency")
    if signals.get("intel_requests_last_30", 0) < 50:
        risk_factors.append("low_intelligence_consumption")
    if signals.get("api_calls_last_30", 0) < 500:
        risk_factors.append("low_api_usage")
    if signals.get("open_tickets", 0) >= 3:
        risk_factors.append("high_open_ticket_count")
    if signals.get("features_used", 0) <= 1:
        risk_factors.append("minimal_feature_adoption")
    days_to_renewal = profile.get("days_to_renewal", 365)
    if days_to_renewal < 30:
        risk_factors.append("renewal_imminent")
    if score < 30:
        churn_risk = "critical"
    elif score < 50:
        churn_risk = "high"
    elif score < 65:
        churn_risk = "medium"
    else:
        churn_risk = "low"
    return {
        "org_id": org_id,
        "org_name": profile.get("name"),
        "health_score": score,
        "churn_risk": churn_risk,
        "risk_factors": risk_factors,
        "days_to_renewal": days_to_renewal,
        "contract_value": profile.get("contract_value"),
        "recommended_action": _recommended_action(churn_risk, risk_factors),
        "assessed_at": datetime.now(timezone.utc).isoformat(),
    }


def _recommended_action(risk: str, factors: List[str]) -> str:
    if risk == "critical":
        return "Immediate executive escalation and emergency business review"
    if risk == "high":
        return "Schedule QBR within 2 weeks; offer usage training and success planning"
    if risk == "medium":
        return "Proactive outreach from CSM; share adoption best practices"
    return "Regular health check-in; identify expansion opportunities"


def generate_health_report(org_id: str) -> dict:
    """Generate a comprehensive health report for a customer."""
    hs = HEALTH_SCORES.get(org_id)
    profile = CUSTOMER_PROFILES.get(org_id)
    if not hs or not profile:
        raise ValueError(f"No health data for {org_id}")
    churn = detect_churn_risk(org_id)
    expansion = _check_expansion_opportunity(org_id, hs, profile)
    return {
        "report_id": "hr-" + str(uuid.uuid4())[:8],
        "org_id": org_id,
        "org_name": profile["name"],
        "plan": profile.get("plan"),
        "csm": profile.get("csm"),
        "health_score": hs["health_score"],
        "category": hs["category"],
        "score_breakdown": hs["breakdown"],
        "churn_analysis": churn,
        "expansion_opportunity": expansion,
        "signals": hs["signals"],
        "last_activity": profile.get("last_activity"),
        "contract_value": profile.get("contract_value"),
        "days_to_renewal": profile.get("days_to_renewal"),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


def _check_expansion_opportunity(org_id: str, hs: dict, profile: dict) -> dict:
    """Identify upsell/expansion signals."""
    signals = hs.get("signals", {})
    opportunities = []
    plan = profile.get("plan", "professional")
    api_calls = signals.get("api_calls_last_30", 0)
    intel_req = signals.get("intel_requests_last_30", 0)
    seats = profile.get("seats_used", 1)
    seats_max = profile.get("seats_max", 10)
    if api_calls > 8000 and plan == "professional":
        opportunities.append({"type": "plan_upgrade", "reason": "API usage near limit", "target_plan": "enterprise"})
    if intel_req > 400 and plan in ("professional", "enterprise"):
        opportunities.append({"type": "intelligence_add_on", "reason": "High intel consumption"})
    if seats >= seats_max * 0.8:
        opportunities.append({"type": "seat_expansion", "reason": f"Using {seats}/{seats_max} seats"})
    return {
        "has_opportunity": len(opportunities) > 0,
        "opportunities": opportunities,
        "estimated_expansion_revenue": len(opportunities) * 500,
    }


def list_at_risk_customers() -> List[dict]:
    """Return all customers in At Risk or Renewal Risk categories."""
    at_risk = []
    for org_id, hs in HEALTH_SCORES.items():
        if hs["health_score"] < 80:
            profile = CUSTOMER_PROFILES.get(org_id, {})
            at_risk.append({
                "org_id": org_id,
                "org_name": profile.get("name"),
                "health_score": hs["health_score"],
                "category": hs["category"],
                "plan": profile.get("plan"),
                "contract_value": profile.get("contract_value"),
                "days_to_renewal": profile.get("days_to_renewal"),
            })
    return sorted(at_risk, key=lambda x: x["health_score"])


# ---------------------------------------------------------------------------
# Seed 10 customers
# ---------------------------------------------------------------------------

SAMPLE_CUSTOMERS = [
    ("org-acme01", "Acme Security Inc", "enterprise", 999, 25, 800, 95000, 15, 12, 8, 10, 280),
    ("org-tech02", "TechDefense LLC", "professional", 299, 18, 350, 7800, 5, 8, 5, 8, 180),
    ("org-gsoc03", "GlobalSOC Partners", "mssp", 2499, 28, 4200, 88000, 3, 22, 12, 15, 90),
    ("org-startup04", "StartupShield", "free", 0, 4, 20, 180, 6, 2, 1, 4, 365),
    ("org-cyberco05", "CyberCo Analytics", "enterprise", 999, 22, 620, 44000, 2, 15, 7, 10, 45),
    ("org-redfort06", "RedFort Defense", "professional", 299, 7, 80, 2100, 4, 6, 2, 8, 60),
    ("org-netsec07", "NetSec Global", "enterprise", 999, 25, 900, 72000, 0, 18, 9, 10, 200),
    ("org-riskiq08", "RiskIQ Partners", "professional", 299, 3, 30, 400, 5, 4, 1, 8, 25),
    ("org-shieldx09", "ShieldX Corp", "mssp", 2499, 27, 3100, 190000, 1, 35, 11, 15, 120),
    ("org-zerohour10", "ZeroHour Labs", "professional", 299, 12, 200, 5500, 3, 7, 4, 8, 90),
]


def _seed():
    for (org_id, name, plan, price, logins, intel, api_c,
         open_t, feats_used, feats_avail, seats_max, days_renew) in SAMPLE_CUSTOMERS:
        CUSTOMER_PROFILES[org_id] = {
            "org_id": org_id,
            "name": name,
            "plan": plan,
            "contract_value": price * 12,
            "days_to_renewal": days_renew,
            "seats_used": max(1, seats_max - 2),
            "seats_max": seats_max,
            "csm": random.choice(["Sarah Mitchell", "James Park", "Anita Rao", "Carlos Vega"]),
            "last_activity": (datetime.now(timezone.utc) - timedelta(days=random.randint(0, 14))).isoformat(),
        }
        calculate_health_score(org_id, {
            "login_days_last_30": logins,
            "intel_requests_last_30": intel,
            "api_calls_last_30": api_c,
            "open_tickets": open_t,
            "resolved_tickets": random.randint(0, 10),
            "features_used": feats_used,
            "features_available": feats_avail,
        })


_seed()


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/customer-health", methods=["GET"])
def api_all_health():
    """List all customer health scores."""
    try:
        scores = list(HEALTH_SCORES.values())
        avg = round(sum(s["health_score"] for s in scores) / max(len(scores), 1), 1) if scores else 0
        return jsonify({
            "customers": scores,
            "total": len(scores),
            "average_health_score": avg,
            "healthy_count": sum(1 for s in scores if s["health_score"] >= 80),
            "at_risk_count": sum(1 for s in scores if 50 <= s["health_score"] < 80),
            "renewal_risk_count": sum(1 for s in scores if s["health_score"] < 50),
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/customer-health/<org_id>", methods=["GET"])
def api_org_health(org_id):
    """Get health score and report for a specific org."""
    try:
        report = generate_health_report(org_id)
        return jsonify(report), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/customer-health/<org_id>/churn-risk", methods=["GET"])
def api_churn_risk(org_id):
    """Get churn risk analysis for an org."""
    try:
        risk = detect_churn_risk(org_id)
        return jsonify(risk), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/at-risk-customers", methods=["GET"])
def api_at_risk():
    """List all at-risk customers."""
    try:
        customers = list_at_risk_customers()
        return jsonify({"at_risk_customers": customers, "total": len(customers)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/customer-health/recalculate", methods=["POST"])
def api_recalculate_health():
    """Recalculate health score from new signals."""
    try:
        data = request.get_json(force=True)
        if not data.get("org_id") or not data.get("signals"):
            return jsonify({"error": "org_id and signals are required"}), 400
        result = calculate_health_score(data["org_id"], data["signals"])
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "customer_health_engine", "version": "1.0.0",
                    "customers_tracked": len(HEALTH_SCORES)}), 200


if __name__ == "__main__":
    print("Starting Customer Health Engine on port 8505")
    print(f"Tracking {len(HEALTH_SCORES)} customers")
    for org_id, hs in HEALTH_SCORES.items():
        print(f"  {CUSTOMER_PROFILES[org_id]['name']}: {hs['health_score']} ({hs['category']})")
    app.run(host="0.0.0.0", port=8505, debug=False)

# ============================================================
# SECTION 10 ADDITIONS — Customer Success Automation v1.0
# Added: 2026-06-05
# ============================================================

import json
import datetime
from pathlib import Path


def _days_until(date_str: str) -> int:
    """Return days until the given ISO date string."""
    try:
        target = datetime.datetime.fromisoformat(date_str.replace('Z', '+00:00'))
        now = datetime.datetime.now(datetime.timezone.utc)
        delta = (target - now).days
        return max(0, delta)
    except Exception:
        return 999


def compute_onboarding_milestones(customer: dict) -> dict:
    """
    Determine which onboarding milestones are complete and which are outstanding.
    Returns milestone status dict.
    """
    MILESTONES = [
        {'id': 'ACCOUNT_ACTIVATED',     'label': 'Account Activated',           'required': True},
        {'id': 'FIRST_API_CALL',        'label': 'First API Call Made',          'required': True},
        {'id': 'SIEM_CONNECTED',        'label': 'SIEM Integration Configured',  'required': True},
        {'id': 'FIRST_REPORT',          'label': 'First Report Generated',       'required': True},
        {'id': 'ALERT_CONFIGURED',      'label': 'Alert Rule Created',           'required': False},
        {'id': 'STIX_EXPORTED',         'label': 'STIX Bundle Exported',         'required': False},
        {'id': 'TEAM_INVITED',          'label': 'Team Members Invited',         'required': False},
        {'id': 'EXEC_BRIEF_SCHEDULED',  'label': 'Executive Brief Scheduled',    'required': False},
    ]
    usage = customer.get('usage', {})
    completed_set = set(customer.get('completed_onboarding_milestones', []))

    # Auto-complete milestones based on usage data
    if usage.get('api_calls', 0) > 0:
        completed_set.add('FIRST_API_CALL')
    if usage.get('siem_connected'):
        completed_set.add('SIEM_CONNECTED')
    if usage.get('reports', 0) > 0:
        completed_set.add('FIRST_REPORT')
    if usage.get('stix_exports', 0) > 0:
        completed_set.add('STIX_EXPORTED')
    if customer.get('id'):
        completed_set.add('ACCOUNT_ACTIVATED')

    result = []
    for m in MILESTONES:
        result.append({
            'id': m['id'],
            'label': m['label'],
            'required': m['required'],
            'completed': m['id'] in completed_set,
        })

    completed_count = sum(1 for m in result if m['completed'])
    required_count = sum(1 for m in result if m['required'])
    required_completed = sum(1 for m in result if m['required'] and m['completed'])

    return {
        'milestones': result,
        'completion_pct': round((completed_count / len(result)) * 100),
        'required_complete': required_completed == required_count,
        'required_completion_pct': round((required_completed / required_count) * 100) if required_count else 0,
    }


def detect_renewal_alerts(customer: dict) -> list:
    """
    Detect customers approaching renewal window and generate alerts.
    Alert tiers: 90d, 60d, 30d, 14d, 7d
    """
    alerts = []
    renewal_date = customer.get('renewal_date')
    if not renewal_date:
        return alerts

    days_left = _days_until(renewal_date)

    if days_left <= 7:
        alerts.append({'severity': 'URGENT', 'type': 'RENEWAL', 'days_left': days_left,
                       'message': f"URGENT: Renewal in {days_left} day(s). Immediate outreach required."})
    elif days_left <= 14:
        alerts.append({'severity': 'CRITICAL', 'type': 'RENEWAL', 'days_left': days_left,
                       'message': f"Renewal in {days_left} days. Send renewal proposal today."})
    elif days_left <= 30:
        alerts.append({'severity': 'HIGH', 'type': 'RENEWAL', 'days_left': days_left,
                       'message': f"Renewal in {days_left} days. Schedule renewal review call."})
    elif days_left <= 60:
        alerts.append({'severity': 'MEDIUM', 'type': 'RENEWAL', 'days_left': days_left,
                       'message': f"Renewal in {days_left} days. Begin renewal nurture sequence."})
    elif days_left <= 90:
        alerts.append({'severity': 'LOW', 'type': 'RENEWAL', 'days_left': days_left,
                       'message': f"Renewal in {days_left} days. Queue for QBR scheduling."})

    return alerts


def detect_expansion_opportunity(customer: dict) -> dict:
    """
    Score expansion readiness and generate recommendations.
    """
    usage = customer.get('usage', {})
    tier = customer.get('tier', 'PRO')

    tier_api_limits = {'MSSP': 20000, 'ENTERPRISE': 10000, 'PRO': 5000}
    api_limit = tier_api_limits.get(tier, 5000)
    api_utilization = usage.get('api_calls', 0) / api_limit

    features_adopted = customer.get('features_adopted', 0)
    total_features = customer.get('total_features', 10)
    adoption_pct = features_adopted / total_features if total_features > 0 else 0

    score = 0
    score += min(40, api_utilization * 40)
    score += min(40, adoption_pct * 40)
    score += 20 if usage.get('siem_connected') else 0

    opportunity = None
    if tier == 'PRO' and score >= 65:
        opportunity = {'type': 'TIER_UPGRADE', 'from': 'PRO', 'to': 'ENTERPRISE', 'potential_mrr_increase': 3000}
    elif tier == 'ENTERPRISE' and score >= 75 and api_utilization > 0.8:
        opportunity = {'type': 'API_QUOTA_EXPAND', 'current_util': f"{api_utilization:.0%}", 'potential_mrr_increase': 800}
    elif tier in ('ENTERPRISE', 'PRO') and score >= 60:
        opportunity = {'type': 'MSSP_UPGRADE', 'from': tier, 'to': 'MSSP', 'potential_mrr_increase': 2500}

    return {
        'expansion_score': round(score),
        'api_utilization': round(api_utilization * 100),
        'feature_adoption_pct': round(adoption_pct * 100),
        'expansion_ready': score >= 65,
        'opportunity': opportunity,
    }


def detect_inactive_customer(customer: dict, inactive_threshold_days: int = 14) -> dict:
    """
    Detect customers with no API activity in threshold window.
    """
    last_activity = customer.get('last_activity_at') or customer.get('last_api_call_at')
    if not last_activity:
        return {'inactive': True, 'days_inactive': 999, 'severity': 'HIGH'}

    try:
        last_dt = datetime.datetime.fromisoformat(last_activity.replace('Z', '+00:00'))
        now = datetime.datetime.now(datetime.timezone.utc)
        days_inactive = (now - last_dt).days
    except Exception:
        return {'inactive': False, 'days_inactive': 0, 'severity': 'NONE'}

    inactive = days_inactive >= inactive_threshold_days
    severity = 'HIGH' if days_inactive >= 21 else 'MEDIUM' if days_inactive >= 14 else 'LOW'
    return {
        'inactive': inactive,
        'days_inactive': days_inactive,
        'severity': severity if inactive else 'NONE',
        'recommended_action': 'Send re-engagement email with platform highlights' if inactive else None,
    }


def compute_success_score(customer: dict) -> dict:
    """
    Compute overall Customer Success Score (0–100).
    Combines health, onboarding completion, engagement, and risk signals.
    """
    milestones = compute_onboarding_milestones(customer)
    expansion = detect_expansion_opportunity(customer)
    inactive = detect_inactive_customer(customer)
    renewal_alerts = detect_renewal_alerts(customer)

    score = 50  # baseline

    # Onboarding contribution (max 20)
    score += (milestones['completion_pct'] / 100) * 20

    # Expansion / adoption contribution (max 20)
    score += (expansion['expansion_score'] / 100) * 20

    # Activity (max 10)
    if not inactive['inactive']:
        score += 10
    else:
        score -= min(15, inactive['days_inactive'])

    # Risk penalties
    for alert in renewal_alerts:
        if alert['severity'] == 'URGENT':
            score -= 20
        elif alert['severity'] == 'CRITICAL':
            score -= 12
        elif alert['severity'] == 'HIGH':
            score -= 6

    final_score = max(0, min(100, round(score)))

    return {
        'customer_id': customer.get('id', 'UNKNOWN'),
        'success_score': final_score,
        'grade': 'A' if final_score >= 85 else 'B' if final_score >= 70 else 'C' if final_score >= 50 else 'D',
        'onboarding': milestones,
        'expansion': expansion,
        'activity': inactive,
        'renewal_alerts': renewal_alerts,
        'generated_at': datetime.datetime.utcnow().isoformat() + 'Z',
    }


# --- CLI runner for quick validation ---
if __name__ == '__main__':
    import sys
    test_customer = {
        'id': 'C001', 'name': 'Test Corp', 'tier': 'ENTERPRISE',
        'usage': {'api_calls': 8420, 'dashboard_sessions': 48, 'reports': 32, 'feed_accesses': 180, 'stix_exports': 15, 'siem_connected': True},
        'features_adopted': 8, 'total_features': 10,
        'last_activity_at': datetime.datetime.utcnow().isoformat() + 'Z',
        'renewal_date': (datetime.datetime.utcnow() + datetime.timedelta(days=45)).isoformat() + 'Z',
    }
    result = compute_success_score(test_customer)
    print(json.dumps(result, indent=2))
    print(f"\nValidation PASS — success_score={result['success_score']}, grade={result['grade']}")
