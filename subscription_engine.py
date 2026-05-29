"""
CYBERDUDEBIVASH SENTINEL APEX
Subscription Engine - FILE 3/10
Plan management, feature flags, trials, upgrades, cancellations, renewals.
Port: 8503
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Plan definitions
# ---------------------------------------------------------------------------
PLANS = {
    "free": {
        "name": "Free",
        "price_monthly": 0,
        "price_annual": 0,
        "seats": 2,
        "features": ["basic_ioc_lookup", "community_feeds", "5_api_calls_per_min"],
        "support": "community",
        "trial_days": 0,
    },
    "professional": {
        "name": "Professional",
        "price_monthly": 299,
        "price_annual": 2990,
        "seats": 10,
        "features": ["basic_ioc_lookup", "community_feeds", "threat_hunting", "sigma_rules",
                     "api_access", "siem_integration", "100_api_calls_per_min"],
        "support": "standard",
        "trial_days": 14,
    },
    "enterprise": {
        "name": "Enterprise",
        "price_monthly": 999,
        "price_annual": 9990,
        "seats": 100,
        "features": ["basic_ioc_lookup", "community_feeds", "threat_hunting", "sigma_rules",
                     "api_access", "siem_integration", "custom_feeds", "attck_mapping",
                     "sso", "scim", "white_label", "priority_support", "500_api_calls_per_min"],
        "support": "premium",
        "trial_days": 14,
    },
    "mssp": {
        "name": "MSSP",
        "price_monthly": 2499,
        "price_annual": 24990,
        "seats": 500,
        "features": ["basic_ioc_lookup", "community_feeds", "threat_hunting", "sigma_rules",
                     "api_access", "siem_integration", "custom_feeds", "attck_mapping",
                     "sso", "scim", "white_label", "priority_support", "mssp_dashboard",
                     "multi_tenant", "bulk_reporting", "1000_api_calls_per_min"],
        "support": "enterprise",
        "trial_days": 14,
    },
    "oem": {
        "name": "OEM",
        "price_monthly": None,  # Custom pricing
        "price_annual": None,
        "seats": 9999,
        "features": ["all_features", "source_access", "dedicated_infra", "custom_sla"],
        "support": "dedicated",
        "trial_days": 30,
    },
}

PLAN_ORDER = ["free", "professional", "enterprise", "mssp", "oem"]

SUBSCRIPTIONS: Dict[str, dict] = {}

# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def create_subscription(org_id: str, plan: str = "professional", seats: int = None,
                         billing_cycle: str = "monthly", trial: bool = False,
                         actor: str = "system") -> dict:
    """Create a new subscription for an organization."""
    if plan not in PLANS:
        raise ValueError(f"Invalid plan: {plan}. Valid: {list(PLANS.keys())}")
    plan_def = PLANS[plan]
    sub_id = "sub-" + str(uuid.uuid4())[:8]
    now = datetime.now(timezone.utc)
    if trial and plan_def["trial_days"] > 0:
        status = "trialing"
        start_date = now
        end_date = now + timedelta(days=plan_def["trial_days"])
        trial_end = end_date.isoformat()
    else:
        status = "active"
        start_date = now
        end_date = now + timedelta(days=365 if billing_cycle == "annual" else 30)
        trial_end = None
    sub = {
        "sub_id": sub_id,
        "org_id": org_id,
        "plan": plan,
        "plan_name": plan_def["name"],
        "status": status,
        "billing_cycle": billing_cycle,
        "seats": seats or plan_def["seats"],
        "features": plan_def["features"],
        "price_monthly": plan_def["price_monthly"],
        "price_annual": plan_def["price_annual"],
        "start_date": start_date.isoformat(),
        "end_date": end_date.isoformat(),
        "trial_end": trial_end,
        "auto_renew": True,
        "created_at": now.isoformat(),
        "updated_at": now.isoformat(),
        "created_by": actor,
        "cancellation_date": None,
        "cancellation_reason": None,
    }
    SUBSCRIPTIONS[sub_id] = sub
    return sub


def upgrade_plan(sub_id: str, new_plan: str, actor: str = "system") -> dict:
    """Upgrade a subscription to a higher tier plan."""
    sub = SUBSCRIPTIONS.get(sub_id)
    if not sub:
        raise ValueError(f"Subscription {sub_id} not found")
    if sub["status"] in ("cancelled", "expired"):
        raise ValueError("Cannot upgrade a cancelled or expired subscription")
    current_idx = PLAN_ORDER.index(sub["plan"]) if sub["plan"] in PLAN_ORDER else 0
    new_idx = PLAN_ORDER.index(new_plan) if new_plan in PLAN_ORDER else -1
    if new_idx <= current_idx:
        raise ValueError(f"Plan {new_plan} is not an upgrade from {sub['plan']}")
    plan_def = PLANS[new_plan]
    old_plan = sub["plan"]
    sub["plan"] = new_plan
    sub["plan_name"] = plan_def["name"]
    sub["features"] = plan_def["features"]
    sub["price_monthly"] = plan_def["price_monthly"]
    sub["price_annual"] = plan_def["price_annual"]
    sub["seats"] = plan_def["seats"]
    sub["status"] = "active"
    sub["updated_at"] = datetime.now(timezone.utc).isoformat()
    sub["upgrade_history"] = sub.get("upgrade_history", []) + [{
        "from": old_plan, "to": new_plan,
        "upgraded_at": datetime.now(timezone.utc).isoformat(),
        "upgraded_by": actor
    }]
    return sub


def downgrade_plan(sub_id: str, new_plan: str, actor: str = "system") -> dict:
    """Downgrade a subscription, effective at next renewal."""
    sub = SUBSCRIPTIONS.get(sub_id)
    if not sub:
        raise ValueError(f"Subscription {sub_id} not found")
    current_idx = PLAN_ORDER.index(sub["plan"]) if sub["plan"] in PLAN_ORDER else 0
    new_idx = PLAN_ORDER.index(new_plan) if new_plan in PLAN_ORDER else 99
    if new_idx >= current_idx:
        raise ValueError(f"Plan {new_plan} is not a downgrade from {sub['plan']}")
    sub["scheduled_downgrade"] = {
        "to_plan": new_plan,
        "effective_date": sub["end_date"],
        "requested_by": actor,
        "requested_at": datetime.now(timezone.utc).isoformat(),
    }
    sub["updated_at"] = datetime.now(timezone.utc).isoformat()
    return sub


def cancel_subscription(sub_id: str, reason: str = "customer_request",
                         immediate: bool = False, actor: str = "system") -> dict:
    """Cancel a subscription, optionally immediately."""
    sub = SUBSCRIPTIONS.get(sub_id)
    if not sub:
        raise ValueError(f"Subscription {sub_id} not found")
    if sub["status"] == "cancelled":
        raise ValueError("Subscription is already cancelled")
    now = datetime.now(timezone.utc)
    sub["status"] = "cancelled" if immediate else "cancel_pending"
    sub["cancellation_date"] = now.isoformat() if immediate else sub["end_date"]
    sub["cancellation_reason"] = reason
    sub["auto_renew"] = False
    sub["updated_at"] = now.isoformat()
    sub["cancelled_by"] = actor
    return sub


def renew_subscription(sub_id: str, actor: str = "system") -> dict:
    """Renew a subscription for another billing cycle."""
    sub = SUBSCRIPTIONS.get(sub_id)
    if not sub:
        raise ValueError(f"Subscription {sub_id} not found")
    if sub["status"] == "cancelled":
        raise ValueError("Cannot renew a cancelled subscription")
    now = datetime.now(timezone.utc)
    days = 365 if sub["billing_cycle"] == "annual" else 30
    sub["end_date"] = (now + timedelta(days=days)).isoformat()
    sub["status"] = "active"
    sub["updated_at"] = now.isoformat()
    sub["last_renewed_at"] = now.isoformat()
    sub["last_renewed_by"] = actor
    return sub


def get_subscription_status(org_id: str) -> dict:
    """Get the active subscription status for an organization."""
    subs = [s for s in SUBSCRIPTIONS.values() if s["org_id"] == org_id]
    if not subs:
        return {"org_id": org_id, "status": "no_subscription", "plan": None}
    active = next((s for s in subs if s["status"] in ("active", "trialing")), None)
    if not active:
        active = sorted(subs, key=lambda s: s["updated_at"], reverse=True)[0]
    plan_def = PLANS.get(active["plan"], {})
    now = datetime.now(timezone.utc)
    end = datetime.fromisoformat(active["end_date"].replace("Z", "+00:00"))
    days_remaining = max(0, (end - now).days)
    return {
        "org_id": org_id,
        "sub_id": active["sub_id"],
        "status": active["status"],
        "plan": active["plan"],
        "plan_name": active.get("plan_name"),
        "features": active["features"],
        "seats": active["seats"],
        "days_remaining": days_remaining,
        "end_date": active["end_date"],
        "trial_end": active.get("trial_end"),
        "auto_renew": active["auto_renew"],
        "billing_cycle": active["billing_cycle"],
    }


def check_feature_flag(org_id: str, feature: str) -> dict:
    """Check if a feature is available for an organization's plan."""
    status = get_subscription_status(org_id)
    if not status.get("features"):
        return {"org_id": org_id, "feature": feature, "enabled": False, "reason": "no_active_subscription"}
    enabled = feature in status["features"] or "all_features" in status["features"]
    return {
        "org_id": org_id,
        "feature": feature,
        "enabled": enabled,
        "plan": status["plan"],
        "reason": "feature_included" if enabled else "plan_upgrade_required",
    }


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

def _seed():
    create_subscription("org-acme01", "enterprise", billing_cycle="annual")
    create_subscription("org-tech02", "professional", billing_cycle="monthly")
    create_subscription("org-gsoc03", "mssp", billing_cycle="annual")
    create_subscription("org-startup04", "free")
    create_subscription("org-demo05", "professional", trial=True)


_seed()


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/subscriptions", methods=["GET"])
def api_list_subscriptions():
    """List all subscriptions."""
    try:
        org_id = request.args.get("org_id")
        subs = [s for s in SUBSCRIPTIONS.values() if not org_id or s["org_id"] == org_id]
        return jsonify({"subscriptions": subs, "total": len(subs)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/subscriptions", methods=["POST"])
def api_create_subscription():
    """Create a new subscription."""
    try:
        data = request.get_json(force=True)
        if not data.get("org_id"):
            return jsonify({"error": "org_id is required"}), 400
        sub = create_subscription(data["org_id"], data.get("plan", "professional"),
                                   data.get("seats"), data.get("billing_cycle", "monthly"),
                                   data.get("trial", False), actor=data.get("actor", "api"))
        return jsonify(sub), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/subscriptions/<sub_id>/upgrade", methods=["POST"])
def api_upgrade_subscription(sub_id):
    """Upgrade to a higher tier plan."""
    try:
        data = request.get_json(force=True)
        if not data.get("new_plan"):
            return jsonify({"error": "new_plan is required"}), 400
        sub = upgrade_plan(sub_id, data["new_plan"], actor=data.get("actor", "api"))
        return jsonify(sub), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/subscriptions/<sub_id>/downgrade", methods=["POST"])
def api_downgrade_subscription(sub_id):
    """Schedule a downgrade at next renewal."""
    try:
        data = request.get_json(force=True)
        sub = downgrade_plan(sub_id, data["new_plan"], actor=data.get("actor", "api"))
        return jsonify(sub), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/subscriptions/<sub_id>/cancel", methods=["POST"])
def api_cancel_subscription(sub_id):
    """Cancel a subscription."""
    try:
        data = request.get_json(force=True) or {}
        sub = cancel_subscription(sub_id, data.get("reason", "customer_request"),
                                   data.get("immediate", False), actor=data.get("actor", "api"))
        return jsonify(sub), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/subscriptions/<sub_id>/renew", methods=["POST"])
def api_renew_subscription(sub_id):
    """Renew a subscription."""
    try:
        data = request.get_json(force=True) or {}
        sub = renew_subscription(sub_id, actor=data.get("actor", "api"))
        return jsonify(sub), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/subscriptions/status/<org_id>", methods=["GET"])
def api_subscription_status(org_id):
    """Get subscription status for an organization."""
    try:
        status = get_subscription_status(org_id)
        return jsonify(status), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/feature-flags/<org_id>/<feature>", methods=["GET"])
def api_feature_flag(org_id, feature):
    """Check if a feature is enabled for an org."""
    try:
        result = check_feature_flag(org_id, feature)
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/plans", methods=["GET"])
def api_list_plans():
    """List all available plans."""
    return jsonify({"plans": PLANS}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "subscription_engine", "version": "1.0.0",
                    "subscriptions": len(SUBSCRIPTIONS)}), 200


if __name__ == "__main__":
    print("Starting Subscription Engine on port 8503")
    print(f"Seeded {len(SUBSCRIPTIONS)} subscriptions")
    app.run(host="0.0.0.0", port=8503, debug=False)
