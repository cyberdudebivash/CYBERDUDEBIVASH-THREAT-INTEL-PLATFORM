"""
CYBERDUDEBIVASH SENTINEL APEX
Tenant Management Engine - FILE 2/10
Multi-tenant provisioning, isolation, quota tracking, health checks.
Port: 8502
"""

import uuid
from datetime import datetime, timezone, timedelta
from typing import Optional, List, Dict
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# In-memory stores
# ---------------------------------------------------------------------------
TENANTS: Dict[str, dict] = {}
TENANT_USAGE: Dict[str, dict] = {}

PLAN_QUOTAS = {
    "free":         {"api_calls_per_day": 500,   "intelligence_requests": 50,   "seats": 2,  "integrations": 1},
    "professional": {"api_calls_per_day": 10000, "intelligence_requests": 1000, "seats": 10, "integrations": 10},
    "enterprise":   {"api_calls_per_day": 100000,"intelligence_requests": 10000,"seats": 100,"integrations": 50},
    "mssp":         {"api_calls_per_day": 500000,"intelligence_requests": 50000,"seats": 500,"integrations": 200},
    "oem":          {"api_calls_per_day": 999999,"intelligence_requests": 999999,"seats": 9999,"integrations": 9999},
}

PLAN_FEATURES = {
    "free":         ["basic_ioc_lookup", "community_feeds"],
    "professional": ["basic_ioc_lookup", "community_feeds", "threat_hunting", "sigma_rules", "api_access"],
    "enterprise":   ["basic_ioc_lookup", "community_feeds", "threat_hunting", "sigma_rules", "api_access",
                     "custom_feeds", "attck_mapping", "siem_integration", "sso", "priority_support"],
    "mssp":         ["basic_ioc_lookup", "community_feeds", "threat_hunting", "sigma_rules", "api_access",
                     "custom_feeds", "attck_mapping", "siem_integration", "sso", "priority_support",
                     "multi_tenant", "white_label", "mssp_dashboard", "bulk_reporting"],
    "oem":          ["all_features", "white_label", "source_access", "dedicated_infra"],
}


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def provision_tenant(org_id: str, name: str, plan: str = "professional",
                     webhook_url: str = None, actor: str = "system") -> dict:
    """Provision a new isolated tenant with quota allocation."""
    if plan not in PLAN_QUOTAS:
        raise ValueError(f"Invalid plan: {plan}. Valid plans: {list(PLAN_QUOTAS.keys())}")
    tenant_id = "ten-" + str(uuid.uuid4())[:8]
    tenant = {
        "tenant_id": tenant_id,
        "org_id": org_id,
        "name": name,
        "plan": plan,
        "features": PLAN_FEATURES[plan],
        "api_quota": PLAN_QUOTAS[plan],
        "webhook_url": webhook_url,
        "status": "active",
        "isolation_namespace": f"ns-{tenant_id}",
        "created_at": datetime.now(timezone.utc).isoformat(),
        "updated_at": datetime.now(timezone.utc).isoformat(),
        "provisioned_by": actor,
    }
    TENANTS[tenant_id] = tenant
    # Initialize usage counters
    TENANT_USAGE[tenant_id] = _init_usage(tenant_id, org_id)
    return tenant


def _init_usage(tenant_id: str, org_id: str) -> dict:
    return {
        "tenant_id": tenant_id,
        "org_id": org_id,
        "date": datetime.now(timezone.utc).date().isoformat(),
        "api_calls_today": 0,
        "intelligence_requests_today": 0,
        "total_api_calls": 0,
        "total_intelligence_requests": 0,
        "active_seats": 0,
        "integrations_configured": 0,
        "storage_mb": 0,
        "last_activity": datetime.now(timezone.utc).isoformat(),
    }


def update_tenant(tenant_id: str, updates: dict, actor: str = "system") -> dict:
    """Update tenant configuration."""
    tenant = TENANTS.get(tenant_id)
    if not tenant:
        raise ValueError(f"Tenant {tenant_id} not found")
    allowed = {"name", "plan", "webhook_url", "features"}
    for k, v in updates.items():
        if k in allowed:
            if k == "plan":
                if v not in PLAN_QUOTAS:
                    raise ValueError(f"Invalid plan: {v}")
                tenant["api_quota"] = PLAN_QUOTAS[v]
                tenant["features"] = PLAN_FEATURES[v]
            tenant[k] = v
    tenant["updated_at"] = datetime.now(timezone.utc).isoformat()
    return tenant


def suspend_tenant(tenant_id: str, reason: str = "manual_suspension", actor: str = "system") -> dict:
    """Suspend a tenant, blocking all API access."""
    tenant = TENANTS.get(tenant_id)
    if not tenant:
        raise ValueError(f"Tenant {tenant_id} not found")
    tenant["status"] = "suspended"
    tenant["suspension_reason"] = reason
    tenant["suspended_at"] = datetime.now(timezone.utc).isoformat()
    tenant["suspended_by"] = actor
    return tenant


def reactivate_tenant(tenant_id: str, actor: str = "system") -> dict:
    """Reactivate a suspended tenant."""
    tenant = TENANTS.get(tenant_id)
    if not tenant:
        raise ValueError(f"Tenant {tenant_id} not found")
    tenant["status"] = "active"
    tenant.pop("suspension_reason", None)
    tenant.pop("suspended_at", None)
    return tenant


def record_usage(tenant_id: str, api_calls: int = 0, intel_requests: int = 0) -> dict:
    """Record resource consumption for a tenant."""
    usage = TENANT_USAGE.get(tenant_id)
    if not usage:
        raise ValueError(f"Usage record for tenant {tenant_id} not found")
    # Reset daily counters if date changed
    today = datetime.now(timezone.utc).date().isoformat()
    if usage["date"] != today:
        usage["date"] = today
        usage["api_calls_today"] = 0
        usage["intelligence_requests_today"] = 0
    usage["api_calls_today"] += api_calls
    usage["total_api_calls"] += api_calls
    usage["intelligence_requests_today"] += intel_requests
    usage["total_intelligence_requests"] += intel_requests
    usage["last_activity"] = datetime.now(timezone.utc).isoformat()
    return usage


def get_tenant_usage(tenant_id: str) -> dict:
    """Get usage statistics and quota remaining for a tenant."""
    tenant = TENANTS.get(tenant_id)
    usage = TENANT_USAGE.get(tenant_id)
    if not tenant or not usage:
        raise ValueError(f"Tenant {tenant_id} not found")
    quota = tenant["api_quota"]
    remaining_api = max(0, quota["api_calls_per_day"] - usage["api_calls_today"])
    remaining_intel = max(0, quota["intelligence_requests"] - usage["intelligence_requests_today"])
    utilization_pct = round((usage["api_calls_today"] / max(quota["api_calls_per_day"], 1)) * 100, 2)
    return {
        "tenant_id": tenant_id,
        "org_id": tenant["org_id"],
        "plan": tenant["plan"],
        "usage": usage,
        "quota": quota,
        "remaining": {"api_calls": remaining_api, "intelligence_requests": remaining_intel},
        "utilization_pct": utilization_pct,
        "quota_exceeded": utilization_pct >= 100,
    }


def list_tenants(org_id: str = None) -> List[dict]:
    """List all tenants, optionally filtered by org."""
    if org_id:
        return [t for t in TENANTS.values() if t["org_id"] == org_id]
    return list(TENANTS.values())


def check_tenant_health(tenant_id: str) -> dict:
    """Run health diagnostics for a tenant."""
    tenant = TENANTS.get(tenant_id)
    if not tenant:
        raise ValueError(f"Tenant {tenant_id} not found")
    usage = TENANT_USAGE.get(tenant_id, {})
    quota = tenant["api_quota"]
    api_util = (usage.get("api_calls_today", 0) / max(quota["api_calls_per_day"], 1)) * 100
    checks = {
        "tenant_active": tenant["status"] == "active",
        "api_quota_ok": api_util < 90,
        "webhook_configured": bool(tenant.get("webhook_url")),
        "isolation_namespace_ok": bool(tenant.get("isolation_namespace")),
    }
    health_score = sum(1 for v in checks.values() if v) / len(checks) * 100
    return {
        "tenant_id": tenant_id,
        "health_score": round(health_score, 1),
        "status": "healthy" if health_score >= 75 else "degraded" if health_score >= 50 else "critical",
        "checks": checks,
        "api_utilization_pct": round(api_util, 2),
        "checked_at": datetime.now(timezone.utc).isoformat(),
    }


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

def _seed():
    t1 = provision_tenant("org-acme01", "Acme-Primary", "enterprise", "https://hooks.acme.com/sentinel")
    t2 = provision_tenant("org-tech02", "TechDefense-Main", "professional", "https://hooks.techdefense.io/apex")
    t3 = provision_tenant("org-gsoc03", "GlobalSOC-MSSP", "mssp", "https://soc.globalsoc.com/webhook")
    t4 = provision_tenant("org-startup04", "StartupShield-Free", "free")

    # Simulate some usage
    record_usage(t1["tenant_id"], api_calls=4500, intel_requests=300)
    record_usage(t2["tenant_id"], api_calls=2100, intel_requests=180)
    record_usage(t3["tenant_id"], api_calls=88000, intel_requests=7200)
    record_usage(t4["tenant_id"], api_calls=120, intel_requests=10)


_seed()


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/tenants", methods=["GET"])
def api_list_tenants():
    """List all tenants."""
    try:
        org_id = request.args.get("org_id")
        tenants = list_tenants(org_id)
        return jsonify({"tenants": tenants, "total": len(tenants)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tenants", methods=["POST"])
def api_create_tenant():
    """Provision a new tenant."""
    try:
        data = request.get_json(force=True)
        if not data.get("org_id") or not data.get("name"):
            return jsonify({"error": "org_id and name are required"}), 400
        tenant = provision_tenant(data["org_id"], data["name"], data.get("plan", "professional"),
                                  data.get("webhook_url"), actor=data.get("actor", "api"))
        return jsonify(tenant), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tenants/<tenant_id>", methods=["GET"])
def api_get_tenant(tenant_id):
    """Get a specific tenant."""
    tenant = TENANTS.get(tenant_id)
    if not tenant:
        return jsonify({"error": "Tenant not found"}), 404
    return jsonify(tenant), 200


@app.route("/api/tenants/<tenant_id>", methods=["PATCH"])
def api_update_tenant(tenant_id):
    """Update tenant configuration."""
    try:
        data = request.get_json(force=True)
        tenant = update_tenant(tenant_id, data, actor=data.get("actor", "api"))
        return jsonify(tenant), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tenants/<tenant_id>/suspend", methods=["POST"])
def api_suspend_tenant(tenant_id):
    """Suspend a tenant."""
    try:
        data = request.get_json(force=True) or {}
        tenant = suspend_tenant(tenant_id, data.get("reason", "manual"), actor=data.get("actor", "api"))
        return jsonify(tenant), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tenants/<tenant_id>/reactivate", methods=["POST"])
def api_reactivate_tenant(tenant_id):
    """Reactivate a suspended tenant."""
    try:
        tenant = reactivate_tenant(tenant_id)
        return jsonify(tenant), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tenants/<tenant_id>/usage", methods=["GET"])
def api_tenant_usage(tenant_id):
    """Get usage and quota status for a tenant."""
    try:
        usage = get_tenant_usage(tenant_id)
        return jsonify(usage), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/tenants/<tenant_id>/health", methods=["GET"])
def api_tenant_health(tenant_id):
    """Run health check on a tenant."""
    try:
        health = check_tenant_health(tenant_id)
        return jsonify(health), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 404
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "tenant_management_engine", "version": "1.0.0",
                    "tenants": len(TENANTS)}), 200


if __name__ == "__main__":
    print("Starting Tenant Management Engine on port 8502")
    print(f"Seeded {len(TENANTS)} tenants")
    app.run(host="0.0.0.0", port=8502, debug=False)
