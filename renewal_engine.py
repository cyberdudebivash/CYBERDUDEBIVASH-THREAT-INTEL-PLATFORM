"""
CYBERDUDEBIVASH SENTINEL APEX
Renewal Engine - FILE 9/10
Renewal scoring, risk identification, expansion opportunities, revenue forecasting.
Port: 8509
"""

import uuid
import random
from datetime import datetime, timezone, timedelta
from typing import List, Dict, Optional
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
RENEWALS: Dict[str, dict] = {}
OUTREACH_LOG: List[dict] = []

RISK_LEVELS = {
    "Low":      (75, 100),
    "Medium":   (50, 74),
    "High":     (25, 49),
    "Critical": (0,  24),
}

PLAN_VALUES = {
    "free": 0, "professional": 3588, "enterprise": 11988, "mssp": 29988, "oem": 119988
}


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def calculate_renewal_score(org_id: str, health_score: float, usage_trend_pct: float,
                              support_incidents_last90d: int, contract_value: float,
                              days_to_renewal: int) -> dict:
    """
    Compute a 0-100 renewal likelihood score.

    Weights:
        health_score contribution: 40%
        usage_trend: 25%
        support history: 20%
        contract value (stickiness): 15%
    """
    # Health component (0-40)
    health_component = (health_score / 100) * 40

    # Usage trend component (0-25): positive trend = full, declining = 0
    if usage_trend_pct >= 20:
        trend_component = 25.0
    elif usage_trend_pct >= 0:
        trend_component = (usage_trend_pct / 20) * 25
    else:
        trend_component = max(0, 25 + (usage_trend_pct / 10))

    # Support history (0-20): 0 incidents = 20, each incident -3
    support_component = max(0, 20 - (support_incidents_last90d * 3))

    # Contract value stickiness (0-15): higher value = harder to churn
    if contract_value >= 10000:
        value_component = 15.0
    elif contract_value >= 3000:
        value_component = 10.0
    elif contract_value >= 1000:
        value_component = 7.0
    else:
        value_component = 3.0

    raw_score = health_component + trend_component + support_component + value_component
    # Urgency modifier: imminent renewals within 30 days get capped unless score is high
    if days_to_renewal < 30 and raw_score < 60:
        raw_score = raw_score * 0.9

    renewal_score = round(min(100, max(0, raw_score)), 1)
    risk_level = _score_to_risk(renewal_score)
    return {
        "renewal_score": renewal_score,
        "risk_level": risk_level,
        "score_breakdown": {
            "health_component": round(health_component, 1),
            "usage_trend_component": round(trend_component, 1),
            "support_component": round(support_component, 1),
            "value_component": round(value_component, 1),
        },
        "inputs": {
            "health_score": health_score,
            "usage_trend_pct": usage_trend_pct,
            "support_incidents_last90d": support_incidents_last90d,
            "contract_value": contract_value,
            "days_to_renewal": days_to_renewal,
        },
    }


def _score_to_risk(score: float) -> str:
    if score >= 75:
        return "Low"
    elif score >= 50:
        return "Medium"
    elif score >= 25:
        return "High"
    return "Critical"


def create_renewal_record(org_id: str, org_name: str, plan: str, contract_value: float,
                           contract_end_date: str, health_score: float, usage_trend_pct: float,
                           support_incidents_last90d: int = 0) -> dict:
    """Create or update a renewal tracking record."""
    renewal_id = "ren-" + str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc)
    end = datetime.fromisoformat(contract_end_date.replace("Z", "+00:00"))
    days_to_renewal = max(0, (end - now).days)
    score_data = calculate_renewal_score(org_id, health_score, usage_trend_pct,
                                          support_incidents_last90d, contract_value, days_to_renewal)
    record = {
        "renewal_id": renewal_id,
        "org_id": org_id,
        "org_name": org_name,
        "plan": plan,
        "contract_value": contract_value,
        "contract_end": contract_end_date,
        "days_to_renewal": days_to_renewal,
        "renewal_score": score_data["renewal_score"],
        "risk_level": score_data["risk_level"],
        "score_breakdown": score_data["score_breakdown"],
        "health_score": health_score,
        "usage_trend_pct": usage_trend_pct,
        "support_incidents_last90d": support_incidents_last90d,
        "recommended_action": _recommended_action(score_data["risk_level"], days_to_renewal),
        "outreach_triggered": False,
        "outreach_log": [],
        "expansion_opportunity": _check_expansion(health_score, usage_trend_pct, plan),
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
    }
    RENEWALS[renewal_id] = record
    return record


def _recommended_action(risk_level: str, days_to_renewal: int) -> str:
    actions = {
        "Low": "Standard renewal outreach 60 days before expiry",
        "Medium": "Proactive CSM engagement; schedule renewal call within 2 weeks",
        "High": "Immediate executive escalation; offer incentive pricing or feature add-ons",
        "Critical": "Emergency intervention: C-level call, retention offer, success plan review",
    }
    action = actions.get(risk_level, "Monitor and review")
    if days_to_renewal < 14 and risk_level in ("High", "Critical"):
        action = "URGENT: " + action
    return action


def _check_expansion(health_score: float, usage_trend: float, current_plan: str) -> dict:
    """Identify expansion opportunity signals."""
    plan_hierarchy = ["free", "professional", "enterprise", "mssp", "oem"]
    idx = plan_hierarchy.index(current_plan) if current_plan in plan_hierarchy else 0
    can_upgrade = idx < len(plan_hierarchy) - 1
    triggers = []
    if health_score >= 80 and usage_trend >= 15:
        triggers.append("high_engagement_growth")
    if usage_trend >= 25:
        triggers.append("rapid_usage_expansion")
    if health_score >= 85 and can_upgrade:
        triggers.append("platform_champion_identified")
    next_plan = plan_hierarchy[min(idx + 1, len(plan_hierarchy) - 1)] if can_upgrade else current_plan
    expansion_value = PLAN_VALUES.get(next_plan, 0) - PLAN_VALUES.get(current_plan, 0)
    return {
        "has_opportunity": len(triggers) > 0 and can_upgrade,
        "triggers": triggers,
        "current_plan": current_plan,
        "recommended_upgrade": next_plan if triggers else None,
        "expansion_revenue_usd": max(0, expansion_value),
    }


def identify_renewal_risks() -> List[dict]:
    """Return all renewals with High or Critical risk."""
    at_risk = [r for r in RENEWALS.values() if r["risk_level"] in ("High", "Critical")]
    return sorted(at_risk, key=lambda r: (r["renewal_score"], r["days_to_renewal"]))


def generate_expansion_opportunities() -> List[dict]:
    """Return all accounts with expansion opportunity."""
    return [r for r in RENEWALS.values() if r["expansion_opportunity"]["has_opportunity"]]


def trigger_renewal_outreach(renewal_id: str, channel: str = "email",
                              message: str = None, actor: str = "csm_system") -> dict:
    """Log and trigger renewal outreach activity."""
    renewal = RENEWALS.get(renewal_id)
    if not renewal:
        raise ValueError(f"Renewal record {renewal_id} not found")
    outreach_entry = {
        "outreach_id": "out-" + str(uuid.uuid4())[:8],
        "channel": channel,
        "message": message or f"Renewal outreach for {renewal['org_name']} - {renewal['risk_level']} risk",
        "triggered_by": actor,
        "triggered_at": datetime.now(timezone.utc).isoformat(),
        "status": "sent",
    }
    renewal["outreach_log"].append(outreach_entry)
    renewal["outreach_triggered"] = True
    renewal["updated_at"] = datetime.now(timezone.utc).isoformat()
    OUTREACH_LOG.append({**outreach_entry, "renewal_id": renewal_id, "org_id": renewal["org_id"]})
    return outreach_entry


def get_revenue_forecast() -> dict:
    """Forecast renewal revenue for the next 90 days."""
    now = datetime.now(timezone.utc)
    windows = {
        "30_days": [],
        "60_days": [],
        "90_days": [],
    }
    for r in RENEWALS.values():
        d = r["days_to_renewal"]
        bucket = "30_days" if d <= 30 else "60_days" if d <= 60 else "90_days" if d <= 90 else None
        if bucket:
            windows[bucket].append(r)
    def _forecast(renewals_list):
        total_at_risk = sum(r["contract_value"] for r in renewals_list)
        # Weight by renewal score probability
        expected_renewal = sum(r["contract_value"] * (r["renewal_score"] / 100) for r in renewals_list)
        churn_risk = total_at_risk - expected_renewal
        return {
            "count": len(renewals_list),
            "total_contract_value_usd": round(total_at_risk, 2),
            "expected_renewal_revenue_usd": round(expected_renewal, 2),
            "at_risk_revenue_usd": round(churn_risk, 2),
            "avg_renewal_score": round(sum(r["renewal_score"] for r in renewals_list) / max(len(renewals_list), 1), 1),
        }
    expansion_total = sum(r["expansion_opportunity"]["expansion_revenue_usd"]
                           for r in RENEWALS.values() if r["expansion_opportunity"]["has_opportunity"])
    all_renewals = list(RENEWALS.values())
    return {
        "forecast_generated_at": now.isoformat(),
        "total_tracked_renewals": len(all_renewals),
        "total_annual_contract_value_usd": round(sum(r["contract_value"] for r in all_renewals), 2),
        "renewal_windows": {k: _forecast(v) for k, v in windows.items()},
        "expansion_pipeline_usd": round(expansion_total, 2),
        "critical_risk_count": sum(1 for r in all_renewals if r["risk_level"] == "Critical"),
        "high_risk_count": sum(1 for r in all_renewals if r["risk_level"] == "High"),
    }


# ---------------------------------------------------------------------------
# Seed 10 customers
# ---------------------------------------------------------------------------

SAMPLE_RENEWALS = [
    ("org-acme01",    "Acme Security Inc",   "enterprise",   11988, 280, 92, 18,  1),
    ("org-tech02",    "TechDefense LLC",     "professional",  3588, 180, 74, 12,  0),
    ("org-gsoc03",    "GlobalSOC Partners",  "mssp",         29988,  90, 88, 22,  2),
    ("org-startup04", "StartupShield",       "free",             0, 365, 28, -5,  3),
    ("org-cyberco05", "CyberCo Analytics",   "enterprise",   11988,  45, 81, 10,  1),
    ("org-redfort06", "RedFort Defense",     "professional",  3588,  60, 42, -8,  4),
    ("org-netsec07",  "NetSec Global",       "enterprise",   11988, 200, 89, 25,  0),
    ("org-riskiq08",  "RiskIQ Partners",     "professional",  3588,  25, 31,-15,  5),
    ("org-shieldx09", "ShieldX Corp",        "mssp",         29988, 120, 85, 15,  1),
    ("org-zerohour10","ZeroHour Labs",        "professional",  3588,  75, 63,  5,  2),
]


def _seed():
    for (org_id, name, plan, value, days, health, trend, incidents) in SAMPLE_RENEWALS:
        end_date = (datetime.now(timezone.utc) + timedelta(days=days)).isoformat()
        r = create_renewal_record(org_id, name, plan, value, end_date, health, trend, incidents)
        # Trigger outreach for high/critical
        if r["risk_level"] in ("High", "Critical"):
            trigger_renewal_outreach(r["renewal_id"], "email", actor="auto_csm")


_seed()


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/renewals", methods=["GET"])
def api_list_renewals():
    """List all renewal records."""
    try:
        risk = request.args.get("risk")
        records = list(RENEWALS.values())
        if risk:
            records = [r for r in records if r["risk_level"].lower() == risk.lower()]
        return jsonify({"renewals": records, "total": len(records)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/renewals/at-risk", methods=["GET"])
def api_at_risk_renewals():
    """Get high/critical risk renewal accounts."""
    try:
        at_risk = identify_renewal_risks()
        return jsonify({"at_risk_renewals": at_risk, "total": len(at_risk)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/renewals/expansion", methods=["GET"])
def api_expansion_opportunities():
    """Get expansion opportunity accounts."""
    try:
        opps = generate_expansion_opportunities()
        total_pipeline = sum(o["expansion_opportunity"]["expansion_revenue_usd"] for o in opps)
        return jsonify({"expansion_opportunities": opps, "total": len(opps),
                        "total_pipeline_usd": round(total_pipeline, 2)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/revenue-forecast", methods=["GET"])
def api_revenue_forecast():
    """Get 90-day renewal revenue forecast."""
    try:
        forecast = get_revenue_forecast()
        return jsonify(forecast), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/renewals/<renewal_id>/outreach", methods=["POST"])
def api_trigger_outreach(renewal_id):
    """Trigger renewal outreach for a record."""
    try:
        data = request.get_json(force=True) or {}
        entry = trigger_renewal_outreach(renewal_id, data.get("channel", "email"),
                                          data.get("message"), actor=data.get("actor", "api"))
        return jsonify(entry), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/renewals/score", methods=["POST"])
def api_score_renewal():
    """Calculate renewal score for provided signals."""
    try:
        data = request.get_json(force=True)
        required = ["org_id", "health_score", "usage_trend_pct", "contract_value", "days_to_renewal"]
        for f in required:
            if f not in data:
                return jsonify({"error": f"{f} is required"}), 400
        result = calculate_renewal_score(
            data["org_id"], data["health_score"], data["usage_trend_pct"],
            data.get("support_incidents_last90d", 0), data["contract_value"], data["days_to_renewal"]
        )
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "renewal_engine", "version": "1.0.0",
                    "renewals_tracked": len(RENEWALS)}), 200


if __name__ == "__main__":
    print("Starting Renewal Engine on port 8509")
    print(f"Tracking {len(RENEWALS)} renewals")
    at_risk = identify_renewal_risks()
    print(f"  High/Critical risk: {len(at_risk)}")
    forecast = get_revenue_forecast()
    print(f"  90-day expected renewal: ${forecast['renewal_windows']['90_days'].get('expected_renewal_revenue_usd', 0):,.0f}")
    app.run(host="0.0.0.0", port=8509, debug=False)
