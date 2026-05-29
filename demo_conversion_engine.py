"""
CYBERDUDEBIVASH SENTINEL APEX — Phase 96
Demo-to-Customer Conversion Engine
Port: 8511

Tracks the full lifecycle from demo request through trial to conversion or loss.
Provides funnel analytics and win/loss reporting.
"""

import uuid
import random
from datetime import datetime, timedelta
from flask import Flask, jsonify, request

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
demo_requests: dict = {}
trial_accounts: dict = {}

# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------
def _seed():
    now = datetime.utcnow()

    demos_seed = [
        {"org": "Apex FinGroup", "email": "security@apexfin.com", "tier": "enterprise", "status": "converted", "days_ago": 30},
        {"org": "NovaMed Health", "email": "it@novamed.io", "tier": "professional", "status": "completed", "days_ago": 20},
        {"org": "ClearLogix LLC", "email": "ops@clearlogix.net", "tier": "enterprise", "status": "scheduled", "days_ago": 5},
        {"org": "TerraStack Inc", "email": "admin@terrastack.com", "tier": "starter", "status": "lost", "days_ago": 45},
        {"org": "DataVault Corp", "email": "ciso@datavault.io", "tier": "enterprise", "status": "requested", "days_ago": 2},
    ]

    demo_ids = []
    for d in demos_seed:
        demo_id = str(uuid.uuid4())
        demo_ids.append(demo_id)
        created = now - timedelta(days=d["days_ago"])
        demo_requests[demo_id] = {
            "demo_id": demo_id,
            "org_name": d["org"],
            "email": d["email"],
            "tier_interest": d["tier"],
            "demo_date": (created + timedelta(days=3)).isoformat() if d["status"] not in ("requested",) else None,
            "status": d["status"],
            "notes": "",
            "created_at": created.isoformat(),
        }

    # 3 active trials — tied to first 3 demos
    trial_seeds = [
        {"demo_id": demo_ids[0], "org": "Apex FinGroup", "email": "security@apexfin.com", "usage": 82, "converted": True},
        {"demo_id": demo_ids[1], "org": "NovaMed Health", "email": "it@novamed.io", "usage": 61, "converted": False},
        {"demo_id": demo_ids[2], "org": "ClearLogix LLC", "email": "ops@clearlogix.net", "usage": 35, "converted": False},
    ]

    for t in trial_seeds:
        trial_id = str(uuid.uuid4())
        start = now - timedelta(days=random.randint(3, 12))
        trial_accounts[trial_id] = {
            "trial_id": trial_id,
            "demo_id": t["demo_id"],
            "org_name": t["org"],
            "email": t["email"],
            "trial_start": start.isoformat(),
            "trial_end": (start + timedelta(days=14)).isoformat(),
            "features_enabled": ["ioc_feeds", "threat_reports", "api_access", "dashboard"],
            "usage_score": t["usage"],
            "converted": t["converted"],
        }

_seed()

# ---------------------------------------------------------------------------
# Business logic
# ---------------------------------------------------------------------------

def _next_id(prefix: str) -> str:
    return f"{prefix}-{uuid.uuid4().hex[:8].upper()}"


def create_demo_request(org_name: str, email: str, tier: str) -> dict:
    demo_id = _next_id("DEMO")
    record = {
        "demo_id": demo_id,
        "org_name": org_name,
        "email": email,
        "tier_interest": tier,
        "demo_date": None,
        "status": "requested",
        "notes": "",
        "created_at": datetime.utcnow().isoformat(),
    }
    demo_requests[demo_id] = record
    return record


def schedule_demo(demo_id: str, date: str) -> dict:
    rec = demo_requests.get(demo_id)
    if not rec:
        raise KeyError(f"Demo {demo_id} not found")
    rec["demo_date"] = date
    rec["status"] = "scheduled"
    return rec


def start_trial(demo_id: str) -> dict:
    rec = demo_requests.get(demo_id)
    if not rec:
        raise KeyError(f"Demo {demo_id} not found")
    rec["status"] = "completed"
    trial_id = _next_id("TRIAL")
    now = datetime.utcnow()
    trial = {
        "trial_id": trial_id,
        "demo_id": demo_id,
        "org_name": rec["org_name"],
        "email": rec["email"],
        "trial_start": now.isoformat(),
        "trial_end": (now + timedelta(days=14)).isoformat(),
        "features_enabled": ["ioc_feeds", "threat_reports", "api_access", "dashboard", "detection_rules"],
        "usage_score": 0,
        "converted": False,
    }
    trial_accounts[trial_id] = trial
    return trial


def track_trial_usage(trial_id: str, feature: str, count: int) -> dict:
    trial = trial_accounts.get(trial_id)
    if not trial:
        raise KeyError(f"Trial {trial_id} not found")
    # Weight: each feature call contributes proportionally; cap at 100
    increment = min(count * 2, 20)
    trial["usage_score"] = min(100, trial["usage_score"] + increment)
    return trial


def convert_trial(trial_id: str, plan: str) -> dict:
    trial = trial_accounts.get(trial_id)
    if not trial:
        raise KeyError(f"Trial {trial_id} not found")
    trial["converted"] = True
    # Update parent demo
    demo = demo_requests.get(trial["demo_id"])
    if demo:
        demo["status"] = "converted"
        demo["notes"] = f"Converted to plan: {plan}"
    return {
        "subscription_created": True,
        "trial_id": trial_id,
        "org_name": trial["org_name"],
        "plan": plan,
        "converted_at": datetime.utcnow().isoformat(),
    }


def mark_lost(demo_id: str, reason: str) -> dict:
    rec = demo_requests.get(demo_id)
    if not rec:
        raise KeyError(f"Demo {demo_id} not found")
    rec["status"] = "lost"
    rec["notes"] = reason
    return rec


def get_conversion_funnel() -> dict:
    stages = {"requested": 0, "scheduled": 0, "completed": 0, "converted": 0, "lost": 0}
    for d in demo_requests.values():
        stages[d["status"]] = stages.get(d["status"], 0) + 1
    total = stages["requested"] + stages["scheduled"] + stages["completed"] + stages["converted"] + stages["lost"]
    conversion_rate = round((stages["converted"] / total * 100), 1) if total else 0.0
    return {
        "demo_requests": total,
        "trials_started": len(trial_accounts),
        "trials_active": sum(1 for t in trial_accounts.values() if not t["converted"]),
        "converted": stages["converted"],
        "lost": stages["lost"],
        "conversion_rate_pct": conversion_rate,
        "stages": stages,
    }


def get_win_loss_analytics() -> dict:
    won = [d for d in demo_requests.values() if d["status"] == "converted"]
    lost = [d for d in demo_requests.values() if d["status"] == "lost"]
    reasons = [d["notes"] for d in lost if d["notes"]]

    converted_trials = [t for t in trial_accounts.values() if t["converted"]]
    avg_trial_days = 0
    if converted_trials:
        days_list = []
        for t in converted_trials:
            start = datetime.fromisoformat(t["trial_start"])
            end = datetime.utcnow()
            days_list.append((end - start).days)
        avg_trial_days = round(sum(days_list) / len(days_list), 1)

    feature_counts: dict = {}
    for t in trial_accounts.values():
        for f in t["features_enabled"]:
            feature_counts[f] = feature_counts.get(f, 0) + 1
    top_features = sorted(feature_counts, key=lambda k: feature_counts[k], reverse=True)[:5]

    return {
        "won": len(won),
        "lost": len(lost),
        "loss_reasons": reasons,
        "avg_trial_days": avg_trial_days,
        "top_features_used": top_features,
    }


def list_active_trials() -> list:
    now = datetime.utcnow()
    result = []
    for t in trial_accounts.values():
        if t["converted"]:
            continue
        end = datetime.fromisoformat(t["trial_end"])
        days_remaining = max(0, (end - now).days)
        entry = dict(t)
        entry["days_remaining"] = days_remaining
        result.append(entry)
    return result

# ---------------------------------------------------------------------------
# Flask Routes
# ---------------------------------------------------------------------------

@app.route("/api/demos", methods=["POST"])
def api_create_demo():
    """Create a new demo request."""
    try:
        data = request.get_json(force=True) or {}
        org = data.get("org_name", "").strip()
        email = data.get("email", "").strip()
        tier = data.get("tier_interest", "starter").strip()
        if not org or not email:
            return jsonify({"error": "org_name and email are required"}), 400
        record = create_demo_request(org, email, tier)
        return jsonify(record), 201
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/demos/<demo_id>/schedule", methods=["PATCH"])
def api_schedule_demo(demo_id):
    """Schedule a demo for a specific date."""
    try:
        data = request.get_json(force=True) or {}
        date = data.get("demo_date")
        if not date:
            return jsonify({"error": "demo_date is required"}), 400
        record = schedule_demo(demo_id, date)
        return jsonify(record)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/demos/<demo_id>/trial", methods=["POST"])
def api_start_trial(demo_id):
    """Start a 14-day trial for a completed demo."""
    try:
        trial = start_trial(demo_id)
        return jsonify(trial), 201
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/trials/<trial_id>/convert", methods=["POST"])
def api_convert_trial(trial_id):
    """Convert an active trial to a paid subscription."""
    try:
        data = request.get_json(force=True) or {}
        plan = data.get("plan", "professional")
        result = convert_trial(trial_id, plan)
        return jsonify(result)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/conversion-funnel", methods=["GET"])
def api_funnel():
    """Return demo-to-customer conversion funnel metrics."""
    try:
        return jsonify(get_conversion_funnel())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/win-loss", methods=["GET"])
def api_win_loss():
    """Return win/loss analytics."""
    try:
        return jsonify(get_win_loss_analytics())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/trials/active", methods=["GET"])
def api_active_trials():
    """List all active (non-converted) trials with days remaining."""
    try:
        return jsonify(list_active_trials())
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/api/demos/<demo_id>/lost", methods=["PATCH"])
def api_mark_lost(demo_id):
    """Mark a demo as lost with a reason."""
    try:
        data = request.get_json(force=True) or {}
        reason = data.get("reason", "No reason provided")
        record = mark_lost(demo_id, reason)
        return jsonify(record)
    except KeyError as exc:
        return jsonify({"error": str(exc)}), 404
    except Exception as exc:
        return jsonify({"error": str(exc)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "demo_conversion_engine", "phase": 96})


if __name__ == "__main__":
    print("CYBERDUDEBIVASH SENTINEL APEX — Phase 96: Demo Conversion Engine")
    print("Running on http://0.0.0.0:8511")
    app.run(host="0.0.0.0", port=8511, debug=False)
