"""
CYBERDUDEBIVASH SENTINEL APEX
Customer Identity Engine - FILE 1/10
Handles organizations, tenants, users, RBAC, MFA, SSO/SCIM simulation, audit logging.
Port: 8501
"""

import uuid
import hashlib
import hmac
import json
from datetime import datetime, timezone
from dataclasses import dataclass, asdict, field
from typing import Optional, List, Dict, Any
from flask import Flask, request, jsonify

app = Flask(__name__)

# ---------------------------------------------------------------------------
# Data stores (in-memory)
# ---------------------------------------------------------------------------
ORGANIZATIONS: Dict[str, dict] = {}
TENANTS: Dict[str, dict] = {}
USERS: Dict[str, dict] = {}
AUDIT_LOG: List[dict] = []
ROLES = {"admin", "analyst", "viewer", "api_user", "mssp_admin"}
ROLE_PERMISSIONS = {
    "admin":      ["read", "write", "delete", "manage_users", "manage_billing", "manage_integrations"],
    "analyst":    ["read", "write", "manage_integrations"],
    "viewer":     ["read"],
    "api_user":   ["read", "write"],
    "mssp_admin": ["read", "write", "delete", "manage_users", "manage_integrations", "manage_mssp"],
}

# ---------------------------------------------------------------------------
# Audit logging
# ---------------------------------------------------------------------------

def audit(actor: str, action: str, resource: str, detail: dict = None):
    AUDIT_LOG.append({
        "log_id": str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "actor": actor,
        "action": action,
        "resource": resource,
        "detail": detail or {},
    })


# ---------------------------------------------------------------------------
# Core functions
# ---------------------------------------------------------------------------

def create_org(name: str, domain: str, tier: str = "professional", actor: str = "system") -> dict:
    """Create a new organization."""
    org_id = "org-" + str(uuid.uuid4())[:8]
    org = {
        "org_id": org_id,
        "name": name,
        "domain": domain,
        "tier": tier,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "active",
    }
    ORGANIZATIONS[org_id] = org
    audit(actor, "create_org", org_id, {"name": name, "domain": domain})
    return org


def get_org(org_id: str) -> Optional[dict]:
    """Retrieve an organization by ID."""
    return ORGANIZATIONS.get(org_id)


def create_tenant(org_id: str, name: str, config: dict = None, actor: str = "system") -> dict:
    """Create a tenant scoped to an organization."""
    if org_id not in ORGANIZATIONS:
        raise ValueError(f"Organization {org_id} not found")
    tenant_id = "ten-" + str(uuid.uuid4())[:8]
    tenant = {
        "tenant_id": tenant_id,
        "org_id": org_id,
        "name": name,
        "config": config or {"theme": "dark", "timezone": "UTC", "notifications": True},
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    TENANTS[tenant_id] = tenant
    audit(actor, "create_tenant", tenant_id, {"org_id": org_id, "name": name})
    return tenant


def create_user(org_id: str, email: str, role: str = "viewer", mfa_enabled: bool = False, actor: str = "system") -> dict:
    """Create a user within an organization."""
    if org_id not in ORGANIZATIONS:
        raise ValueError(f"Organization {org_id} not found")
    if role not in ROLES:
        raise ValueError(f"Invalid role: {role}. Valid roles: {ROLES}")
    user_id = "usr-" + str(uuid.uuid4())[:8]
    user = {
        "user_id": user_id,
        "org_id": org_id,
        "email": email,
        "role": role,
        "mfa_enabled": mfa_enabled,
        "mfa_secret": hashlib.sha256(email.encode()).hexdigest()[:16] if mfa_enabled else None,
        "last_login": None,
        "created_at": datetime.now(timezone.utc).isoformat(),
        "status": "active",
        "sso_provider": None,
        "scim_id": None,
    }
    USERS[user_id] = user
    audit(actor, "create_user", user_id, {"org_id": org_id, "email": email, "role": role})
    return user


def assign_role(user_id: str, new_role: str, actor: str = "system") -> dict:
    """Assign a new RBAC role to a user."""
    if user_id not in USERS:
        raise ValueError(f"User {user_id} not found")
    if new_role not in ROLES:
        raise ValueError(f"Invalid role: {new_role}")
    old_role = USERS[user_id]["role"]
    USERS[user_id]["role"] = new_role
    audit(actor, "assign_role", user_id, {"old_role": old_role, "new_role": new_role})
    return USERS[user_id]


def verify_mfa(user_id: str, token: str) -> dict:
    """Simulate TOTP MFA verification."""
    user = USERS.get(user_id)
    if not user:
        return {"verified": False, "reason": "user_not_found"}
    if not user["mfa_enabled"]:
        return {"verified": True, "reason": "mfa_not_required"}
    # Simulate: accept token matching last 6 chars of secret
    expected = user["mfa_secret"][-6:]
    verified = hmac.compare_digest(token.zfill(6), expected)
    audit(user_id, "verify_mfa", user_id, {"result": verified})
    return {"verified": verified, "reason": "totp_match" if verified else "totp_mismatch"}


def list_users(org_id: str = None) -> List[dict]:
    """List users, optionally filtered by organization."""
    if org_id:
        return [u for u in USERS.values() if u["org_id"] == org_id]
    return list(USERS.values())


def simulate_sso_login(email: str, provider: str = "okta") -> dict:
    """Simulate SSO assertion / token exchange."""
    user = next((u for u in USERS.values() if u["email"] == email), None)
    if not user:
        return {"success": False, "reason": "user_not_found"}
    user["last_login"] = datetime.now(timezone.utc).isoformat()
    user["sso_provider"] = provider
    audit(email, "sso_login", user["user_id"], {"provider": provider})
    return {
        "success": True,
        "user_id": user["user_id"],
        "email": email,
        "role": user["role"],
        "permissions": ROLE_PERMISSIONS.get(user["role"], []),
        "session_token": hashlib.sha256(f"{email}{datetime.now()}".encode()).hexdigest(),
    }


def simulate_scim_provision(org_id: str, email: str, role: str = "viewer") -> dict:
    """Simulate SCIM 2.0 user provisioning from IdP."""
    scim_id = "scim-" + str(uuid.uuid4())[:8]
    user = create_user(org_id, email, role, actor="scim_provisioner")
    user["scim_id"] = scim_id
    USERS[user["user_id"]] = user
    audit("scim_provisioner", "scim_provision", user["user_id"], {"scim_id": scim_id})
    return {"scim_id": scim_id, "user": user, "status": "provisioned"}


# ---------------------------------------------------------------------------
# Seed data
# ---------------------------------------------------------------------------

def _seed():
    o1 = create_org("Acme Security Inc", "acme-security.com", "enterprise")
    o2 = create_org("TechDefense LLC", "techdefense.io", "professional")
    o3 = create_org("GlobalSOC Partners", "globalsoc.com", "mssp")
    o4 = create_org("StartupShield", "startupshield.dev", "free")

    create_tenant(o1["org_id"], "Acme-Primary")
    create_tenant(o2["org_id"], "TechDefense-Main")
    create_tenant(o3["org_id"], "GlobalSOC-MSSP")

    create_user(o1["org_id"], "alice@acme-security.com", "admin", mfa_enabled=True)
    create_user(o1["org_id"], "bob@acme-security.com", "analyst")
    create_user(o2["org_id"], "carol@techdefense.io", "analyst", mfa_enabled=True)
    create_user(o3["org_id"], "dave@globalsoc.com", "mssp_admin", mfa_enabled=True)
    create_user(o4["org_id"], "eve@startupshield.dev", "viewer")


_seed()


# ---------------------------------------------------------------------------
# Flask routes
# ---------------------------------------------------------------------------

@app.route("/api/organizations", methods=["GET"])
def api_list_orgs():
    """List all organizations."""
    try:
        return jsonify({"organizations": list(ORGANIZATIONS.values()), "total": len(ORGANIZATIONS)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/organizations", methods=["POST"])
def api_create_org():
    """Create a new organization."""
    try:
        data = request.get_json(force=True)
        if not data.get("name") or not data.get("domain"):
            return jsonify({"error": "name and domain are required"}), 400
        org = create_org(data["name"], data["domain"], data.get("tier", "professional"), actor=data.get("actor", "api"))
        return jsonify(org), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/organizations/<org_id>", methods=["GET"])
def api_get_org(org_id):
    """Get a single organization."""
    org = get_org(org_id)
    if not org:
        return jsonify({"error": "Organization not found"}), 404
    return jsonify(org), 200


@app.route("/api/users", methods=["GET"])
def api_list_users():
    """List users, optionally filter by org_id."""
    try:
        org_id = request.args.get("org_id")
        users = list_users(org_id)
        # Strip secrets
        safe = [{k: v for k, v in u.items() if k != "mfa_secret"} for u in users]
        return jsonify({"users": safe, "total": len(safe)}), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/users", methods=["POST"])
def api_create_user():
    """Create a new user."""
    try:
        data = request.get_json(force=True)
        if not data.get("org_id") or not data.get("email"):
            return jsonify({"error": "org_id and email are required"}), 400
        user = create_user(data["org_id"], data["email"], data.get("role", "viewer"),
                           data.get("mfa_enabled", False), actor=data.get("actor", "api"))
        safe = {k: v for k, v in user.items() if k != "mfa_secret"}
        return jsonify(safe), 201
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/roles", methods=["GET"])
def api_list_roles():
    """List all RBAC roles and their permissions."""
    return jsonify({"roles": ROLE_PERMISSIONS}), 200


@app.route("/api/roles/assign", methods=["POST"])
def api_assign_role():
    """Assign a role to a user."""
    try:
        data = request.get_json(force=True)
        user = assign_role(data["user_id"], data["role"], actor=data.get("actor", "api"))
        return jsonify({k: v for k, v in user.items() if k != "mfa_secret"}), 200
    except ValueError as e:
        return jsonify({"error": str(e)}), 400
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/mfa/verify", methods=["POST"])
def api_verify_mfa():
    """Verify MFA token."""
    try:
        data = request.get_json(force=True)
        result = verify_mfa(data["user_id"], data["token"])
        return jsonify(result), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/sso/login", methods=["POST"])
def api_sso_login():
    """Simulate SSO login."""
    try:
        data = request.get_json(force=True)
        result = simulate_sso_login(data["email"], data.get("provider", "okta"))
        code = 200 if result["success"] else 401
        return jsonify(result), code
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/scim/users", methods=["POST"])
def api_scim_provision():
    """SCIM 2.0 user provisioning endpoint."""
    try:
        data = request.get_json(force=True)
        result = simulate_scim_provision(data["org_id"], data["email"], data.get("role", "viewer"))
        return jsonify(result), 201
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/audit-log", methods=["GET"])
def api_audit_log():
    """Retrieve audit log entries."""
    limit = int(request.args.get("limit", 50))
    return jsonify({"audit_log": AUDIT_LOG[-limit:], "total": len(AUDIT_LOG)}), 200


@app.route("/health", methods=["GET"])
def health():
    return jsonify({"status": "ok", "engine": "customer_identity_engine", "version": "1.0.0"}), 200


if __name__ == "__main__":
    print("Starting Customer Identity Engine on port 8501")
    print(f"Seeded {len(ORGANIZATIONS)} orgs, {len(USERS)} users")
    app.run(host="0.0.0.0", port=8501, debug=False)
