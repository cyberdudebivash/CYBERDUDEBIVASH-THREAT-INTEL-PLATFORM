"""
CYBERDUDEBIVASH SENTINEL APEX — Phase 94
Expansion & Upsell Engine
Port: 8516

Identifies, scores, and forecasts upsell and cross-sell opportunities across
the customer base. Generates personalized expansion recommendations with
talking points and ARR impact estimates.
"""

import uuid
import random
from datetime import datetime, timedelta
from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
expansion_opportunities: dict = {}
customer_health: dict = {}
org_registry: dict = {}

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------
def _seed():
    random.seed(94)
    now = datetime.utcnow()

    orgs = [
        {
            "org_id": "ORG-001",
            "name": "Apex FinGroup",
            "current_plan": "professional",
            "arr": 60000,
            "seats": 12,
            "api_calls_monthly": 45000,
            "quota_pct": 87,
            "health_score": 91,
            "api_growth_pct": 28,
            "new_users_pct": 60,
        },
        {
            "org_id": "ORG-002",
            "name": "NovaMed Health",
            "current_plan": "professional",
            "arr": 60000,
            "seats": 8,
            "api_calls_monthly": 22000,
            "quota_pct": 72,
            "health_score": 88,
            "api_growth_pct": 15,
            "new_users_pct": 35,
        },
        {
            "org_id": "ORG-003",
            "name": "ClearLogix LLC",
            "current_plan": "starter",
            "arr": 24000,
            "seats": 3,
            "api_calls_monthly": 8500,
            "quota_pct": 83,
            "health_score": 77,
            "api_growth_pct": 22,
            "new_users_pct": 0,
        },
        {
            "org_id": "ORG-004",
            "name": "DataVault Corp",
            "current_plan": "enterprise",
            "arr": 120000,
            "seats": 35,
            "api_calls_monthly": 180000,
            "quota_pct": 65,
            "health_score": 95,
            "api_growth_pct": 8,
            "new_users_pct": 15,
        },
    ]

    plan_upgrades = {
        "starter": "professional",
        "professional": "enterprise",
        "enterprise": "enterprise-plus",
    }

    for org in orgs:
        org_registry[org["org_id"]] = org

        triggers = []
        if org["quota_pct"] > 80:
            triggers.append(f"Quota usage at {org['quota_pct']}% — approaching limit")
        if org["health_score"] > 85:
            triggers.append(f"Health score {org['health_score']} — high expansion readiness")
        if org["api_growth_pct"] > 20:
            triggers.append(f"API call growth {org['api_growth_pct']}%/month — rapid adoption")
        if org["new_users_pct"] > 50:
            triggers.append(f"User base grew {org['new_users_pct']}% — seat expansion opportunity")

        if not triggers:
            continue  # No opportunities this cycle

        # Upsell opportunity
        if org["current_plan"] != "enterprise-plus":
            opp_id = _next_id("OPP")
            arr_increase = _estimate_arr_increase(org["current_plan"], plan_upgrades[org["current_plan"]], org["arr"])
            prob = _score_probability(org, triggers)
            expansion_opportunities[opp_id] = {
                "opp_id": opp_id,
                "org_id": org["org_id"],
                "type": "upsell",
                "current_plan": org["current_plan"],
                "recommended_plan": plan_upgrades[org["current_plan"]],
                "trigger_reason": "; ".join(triggers[:2]),
                "estimated_arr_increase": arr_increase,
                "probability_pct": prob,
                "status": "open",
                "notes": "",
                "created_at": (now - timedelta(days=random.randint(1, 14))).isoformat(),
            }

        # Seat expansion if applicable
        if org["new_users_pct"] > 40:
            opp_id = _next_id("OPP")
            seat_increase = max(3, int(org["seats"] * 0.5))
            seat_arr = seat_increase * 2400
            expansion_opportunities[opp_id] = {
                "opp_id": opp_id,
                "org_id": org["org_id"],
                "type": "seat-expansion",
                "current_plan": org["current_plan"],
                "recommended_plan": org["current_plan"],
                "trigger_reason": f"User base grew {org['new_users_pct']}% — add {seat_increase} seats",
                "estimated_arr_increase": seat_arr,
                "probability_pct": min(90, prob + 10),
                "status": "open",
                "notes": "",
                "created_at": (now - timedelta(days=random.randint(1, 7))).isoformat(),
            }

        # Cross-sell for enterprise
        if org["current_plan"] in ("professional", "enterprise"):
            opp_id = _next_id("OPP")
            expansion_opportunities[opp_id] = {
                "opp_id": opp_id,
                "org_id": org["org_id"],
                "type": "new-module",
                "current_plan": org["current_plan"],
                "recommended_plan": org["current_plan"] + " + Exposure Intelligence Add-on",
                "trigger_reason": "Strong detection adoption — Exposure Intelligence add-on is natural next step",
                "estimated_arr_increase": random.randint(8000, 20000),
                "probability_pct": min(85, prob - 5),
                "status": "open",
                "notes": "",
                "created_at": (now - timedelta(days=random.randint(3, 21))).isoformat(),
            }


def _next_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def _estimate_arr_increase(current: str, target: str, current_arr: int) -> int:
    multipliers = {
        ("starter", "professional"): 2.5,
        ("professional", "enterprise"): 2.0,
        ("enterprise", "enterprise-plus"): 1.4,
    }
    m = multipliers.get((current, target), 1.5)
    return int(current_arr * (m - 1))


def _score_probability(org: dict, triggers: list) -> int:
    score = 40
    if org["health_score"] > 90:
        score += 25
    elif org["health_score"] > 80:
        score += 15
    if org["quota_pct"] > 85:
        score += 15
    if org["api_growth_pct"] > 20:
        score += 10
    if len(triggers) >= 3:
        score += 10
    return min(95, score)

_seed()

# ---------------------------------------------------------------------------
# Business logic
# ---------------------------------------------------------------------------

def scan_expansion_opportunities(org_id: str) -> list:
    if org_id not in org_registry:
        raise KeyError(f"Org {org_id} not found")
    return [o for o in expansion_opportunities.values() if o["org_id"] == org_id and o["status"] == "open"]


def get_expansion_pipeline() -> list:
    open_opps = [o for o in expansion_opportunities.values() if o["status"] == "open"]
    return sorted(open_opps, key=lambda x: x["estimated_arr_increase"], reverse=True)


def generate_expansion_recommendation(org_id: str) -> dict:
    if org_id not in org_registry:
        raise KeyError(f"Org {org_id} not found")
    org = org_registry[org_id]
    opps = scan_expansion_opportunities(org_id)
    if not opps:
        return {
            "org_id": org_id,
            "recommended_action": "Maintain — no strong expansion signals at this time",
            "talking_points": ["Continue monitoring usage trends", "Schedule quarterly business review"],
            "estimated_value": 0,
        }

    best = max(opps, key=lambda x: x["estimated_arr_increase"] * x["probability_pct"])
    talking_points = [
        f"Your team has been using {org['current_plan']} at {org['quota_pct']}% of quota — you are close to limits",
        f"API call volume is growing {org['api_growth_pct']}% month-over-month — the platform is proving value",
        f"Upgrading to {best['recommended_plan']} unlocks additional threat intelligence feeds and higher API limits",
        f"Estimated ARR impact for your business: ${best['estimated_arr_increase']:,}/year in expanded coverage",
        "Our top customers in your industry are already on the next tier — let me show you what they get",
    ]
    return {
        "org_id": org_id,
        "org_name": org["name"],
        "recommended_action": f"Pursue {best['type']} → {best['recommended_plan']}",
        "talking_points": talking_points,
        "estimated_value": best["estimated_arr_increase"],
        "probability_pct": best["probability_pct"],
        "top_opportunity_id": best["opp_id"],
    }


def forecast_expansion_revenue(months: int = 3) -> list:
    now = datetime.utcnow()
    open_opps = get_expansion_pipeline()
    total_pipeline = sum(o["estimated_arr_increase"] for o in open_opps)

    forecast = []
    for i in range(1, months + 1):
        month = (now + timedelta(days=30 * i)).strftime("%Y-%m")
        # Probability-weighted close assumption: ~35% closes per month from pipeline
        close_rate = random.uniform(0.28, 0.42)
        expected_arr = int(total_pipeline * close_rate / months)
        forecast.append({
            "period": month,
            "pipeline_value": total_pipeline,
            "expected_closed_arr": expected_arr,
            "expansion_arr": expected_arr,
            "close_rate_assumed_pct": round(close_rate * 100, 1),
        })
        total_pipeline = max(0, total_pipeline - expected_arr)

    return forecast


def mark_opportunity(opp_id: str, status: str, notes: str = "") -> dict:
    opp = expansion_opportunities.get(opp_id)
    if not opp:
        raise KeyError(f"Opportunity {opp_id} not found")
    valid_statuses = ["open", "in_progress", "won", "lost", "deferred"]
    if status not in valid_statuses:
        raise ValueError(f"Status must be one of {valid_statuses}")
    opp["status"] = status
    opp["notes"] = notes
    return opp

# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route("/api/expansion/<org_id>/opportunities", methods=["GET"])
def api_org_opportunities(org_id):
    """Return all open expansion opportunities for an organization."""
    try:
        return jsonify(scan_expansion_opportunities(org_id))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/expansion/pipeline", methods=["GET"])
def api_pipeline():
    """Return all open expansion opportunities sorted by ARR value."""
    try:
        return jsonify(get_expansion_pipeline())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/expansion/<org_id>/recommendation", methods=["GET"])
def api_recommendation(org_id):
    """Return personalized expansion recommendation and talking points."""
    try:
        return jsonify(generate_expansion_recommendation(org_id))
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/expansion/forecast", methods=["GET"])
def api_forecast():
    """Return revenue expansion forecast for the next N months."""
    try:
        months = int(request.args.get("months", 3))
        return jsonify(forecast_expansion_revenue(months))
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/expansion/<opp_id>/status", methods=["PATCH"])
def api_update_status(opp_id):
    """Update the status of an expansion opportunity."""
    try:
        data = request.get_json(force=True) or {}
        status = data.get("status")
        notes = data.get("notes", "")
        if not status:
            return jsonify({"error": "status is required"}), 400
        record = mark_opportunity(opp_id, status, notes)
        return jsonify(record)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except ValueError as exc:
        return jsonify({"error": str(exc)}), 400
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "expansion_engine", "phase": 94})


if __name__ == "__main__":
    print("CYBERDUDEBIVASH SENTINEL APEX — Phase 94: Expansion & Upsell Engine")
    print("Running on http://0.0.0.0:8516")
    app.run(host="0.0.0.0", port=8516, debug=False)
