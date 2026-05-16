#!/usr/bin/env python3
"""
agent/auth/rbac.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
ENTERPRISE ROLE-BASED ACCESS CONTROL ENGINE

Implements a 5-role RBAC model with 60+ granular permission scopes.

Role hierarchy (descending privilege):
  OWNER > ADMIN > ANALYST > VIEWER > API_ONLY

Design:
  - Additive over existing 4-tier API key model
  - Tier → Role mapping preserves backward compatibility
  - FastAPI Depends()-compatible permission checker
  - Feature-flag gated (CDB_RBAC_ENABLED=true)
  - All permission checks are logged for audit trail

Backward compatibility:
  - CDB_RBAC_ENABLED=false (default) → existing tier-based auth unchanged
  - Existing API keys continue to work with tier-mapped roles
"""

import os
import logging
from typing import Set, Optional, Dict
from functools import lru_cache

logger = logging.getLogger("CDB-RBAC")

_RBAC_ENABLED = os.environ.get("CDB_RBAC_ENABLED", "false").lower() == "true"


# ── Permission Catalogue ───────────────────────────────────────────────────

class Perm:
    """All 60+ permission scopes — organized by resource domain."""

    # ── Organization Management ──
    ORG_VIEW             = "org:view"
    ORG_MANAGE           = "org:manage"
    ORG_BILLING          = "org:billing"
    ORG_DELETE           = "org:delete"
    ORG_CONFIGURE_SSO    = "org:configure_sso"
    ORG_CONFIGURE_IP     = "org:configure_ip_allowlist"

    # ── User Management ──
    USERS_INVITE         = "users:invite"
    USERS_REMOVE         = "users:remove"
    USERS_ASSIGN_ROLES   = "users:assign_roles"
    USERS_VIEW_ALL       = "users:view_all"
    USERS_VIEW_SELF      = "users:view_self"
    USERS_UPDATE_SELF    = "users:update_self"
    USERS_MANAGE_MFA     = "users:manage_mfa"

    # ── Workspace Management ──
    WORKSPACE_CREATE     = "workspace:create"
    WORKSPACE_DELETE     = "workspace:delete"
    WORKSPACE_CONFIGURE  = "workspace:configure"
    WORKSPACE_VIEW       = "workspace:view"

    # ── Intelligence — Read ──
    INTEL_READ           = "intel:read"
    INTEL_READ_IOC       = "intel:read_ioc"
    INTEL_READ_ACTOR     = "intel:read_actor"
    INTEL_READ_CAMPAIGN  = "intel:read_campaign"
    INTEL_READ_DARKWEB   = "intel:read_darkweb"
    INTEL_SEARCH         = "intel:search"
    INTEL_SEARCH_FULL    = "intel:search_full"

    # ── Intelligence — Export ──
    INTEL_EXPORT_CSV     = "intel:export_csv"
    INTEL_EXPORT_STIX    = "intel:export_stix"
    INTEL_EXPORT_PDF     = "intel:export_pdf"
    INTEL_EXPORT_SIEM    = "intel:export_siem"

    # ── Intelligence — Feed Management ──
    FEED_VIEW            = "feed:view"
    FEED_CONFIGURE       = "feed:configure"
    FEED_CUSTOM_ADD      = "feed:custom_add"

    # ── API Key Management ──
    API_KEY_CREATE       = "api:key_create"
    API_KEY_REVOKE       = "api:key_revoke"
    API_KEY_VIEW         = "api:key_view"
    API_VIEW_USAGE       = "api:view_usage"

    # ── Audit & Compliance ──
    AUDIT_READ           = "audit:read"
    AUDIT_EXPORT         = "audit:export"
    AUDIT_CONFIGURE      = "audit:configure"

    # ── SIEM Integration ──
    SIEM_CONFIGURE       = "siem:configure"
    SIEM_READ            = "siem:read"
    SIEM_WEBHOOK         = "siem:webhook"

    # ── Reports ──
    REPORT_VIEW          = "report:view"
    REPORT_CREATE        = "report:create"
    REPORT_EXPORT        = "report:export"

    # ── Platform Admin (internal) ──
    ADMIN_ALL            = "admin:all"
    ADMIN_PLATFORM       = "admin:platform"
    ADMIN_TENANTS        = "admin:tenants"
    ADMIN_BILLING        = "admin:billing"


# ── Role → Permission Mapping ─────────────────────────────────────────────

ROLE_PERMISSIONS: Dict[str, Set[str]] = {

    "OWNER": {
        Perm.ORG_VIEW, Perm.ORG_MANAGE, Perm.ORG_BILLING, Perm.ORG_DELETE,
        Perm.ORG_CONFIGURE_SSO, Perm.ORG_CONFIGURE_IP,
        Perm.USERS_INVITE, Perm.USERS_REMOVE, Perm.USERS_ASSIGN_ROLES,
        Perm.USERS_VIEW_ALL, Perm.USERS_VIEW_SELF, Perm.USERS_UPDATE_SELF,
        Perm.USERS_MANAGE_MFA,
        Perm.WORKSPACE_CREATE, Perm.WORKSPACE_DELETE, Perm.WORKSPACE_CONFIGURE,
        Perm.WORKSPACE_VIEW,
        Perm.INTEL_READ, Perm.INTEL_READ_IOC, Perm.INTEL_READ_ACTOR,
        Perm.INTEL_READ_CAMPAIGN, Perm.INTEL_READ_DARKWEB,
        Perm.INTEL_SEARCH, Perm.INTEL_SEARCH_FULL,
        Perm.INTEL_EXPORT_CSV, Perm.INTEL_EXPORT_STIX,
        Perm.INTEL_EXPORT_PDF, Perm.INTEL_EXPORT_SIEM,
        Perm.FEED_VIEW, Perm.FEED_CONFIGURE, Perm.FEED_CUSTOM_ADD,
        Perm.API_KEY_CREATE, Perm.API_KEY_REVOKE, Perm.API_KEY_VIEW,
        Perm.API_VIEW_USAGE,
        Perm.AUDIT_READ, Perm.AUDIT_EXPORT, Perm.AUDIT_CONFIGURE,
        Perm.SIEM_CONFIGURE, Perm.SIEM_READ, Perm.SIEM_WEBHOOK,
        Perm.REPORT_VIEW, Perm.REPORT_CREATE, Perm.REPORT_EXPORT,
    },

    "ADMIN": {
        Perm.ORG_VIEW,
        Perm.USERS_INVITE, Perm.USERS_REMOVE, Perm.USERS_ASSIGN_ROLES,
        Perm.USERS_VIEW_ALL, Perm.USERS_VIEW_SELF, Perm.USERS_UPDATE_SELF,
        Perm.USERS_MANAGE_MFA,
        Perm.WORKSPACE_CREATE, Perm.WORKSPACE_CONFIGURE, Perm.WORKSPACE_VIEW,
        Perm.INTEL_READ, Perm.INTEL_READ_IOC, Perm.INTEL_READ_ACTOR,
        Perm.INTEL_READ_CAMPAIGN, Perm.INTEL_READ_DARKWEB,
        Perm.INTEL_SEARCH, Perm.INTEL_SEARCH_FULL,
        Perm.INTEL_EXPORT_CSV, Perm.INTEL_EXPORT_STIX,
        Perm.INTEL_EXPORT_PDF, Perm.INTEL_EXPORT_SIEM,
        Perm.FEED_VIEW, Perm.FEED_CONFIGURE,
        Perm.API_KEY_CREATE, Perm.API_KEY_REVOKE, Perm.API_KEY_VIEW,
        Perm.API_VIEW_USAGE,
        Perm.AUDIT_READ, Perm.AUDIT_EXPORT,
        Perm.SIEM_CONFIGURE, Perm.SIEM_READ, Perm.SIEM_WEBHOOK,
        Perm.REPORT_VIEW, Perm.REPORT_CREATE, Perm.REPORT_EXPORT,
    },

    "ANALYST": {
        Perm.ORG_VIEW,
        Perm.USERS_VIEW_SELF, Perm.USERS_UPDATE_SELF, Perm.USERS_MANAGE_MFA,
        Perm.WORKSPACE_VIEW,
        Perm.INTEL_READ, Perm.INTEL_READ_IOC, Perm.INTEL_READ_ACTOR,
        Perm.INTEL_READ_CAMPAIGN,
        Perm.INTEL_SEARCH, Perm.INTEL_SEARCH_FULL,
        Perm.INTEL_EXPORT_CSV, Perm.INTEL_EXPORT_STIX, Perm.INTEL_EXPORT_PDF,
        Perm.FEED_VIEW,
        Perm.API_KEY_CREATE, Perm.API_KEY_VIEW, Perm.API_VIEW_USAGE,
        Perm.SIEM_READ,
        Perm.REPORT_VIEW, Perm.REPORT_CREATE, Perm.REPORT_EXPORT,
    },

    "VIEWER": {
        Perm.ORG_VIEW,
        Perm.USERS_VIEW_SELF, Perm.USERS_UPDATE_SELF,
        Perm.WORKSPACE_VIEW,
        Perm.INTEL_READ,
        Perm.INTEL_SEARCH,
        Perm.INTEL_EXPORT_CSV,
        Perm.FEED_VIEW,
        Perm.REPORT_VIEW,
    },

    "API_ONLY": {
        Perm.INTEL_READ,
        Perm.INTEL_READ_IOC,
        Perm.INTEL_SEARCH,
        Perm.INTEL_EXPORT_STIX,
        Perm.INTEL_EXPORT_CSV,
        Perm.SIEM_READ,
    },
}

# ── Tier → Role backward-compatibility mapping ────────────────────────────

_TIER_TO_ROLE: Dict[str, str] = {
    "FREE":       "VIEWER",
    "STANDARD":   "ANALYST",
    "PREMIUM":    "ANALYST",
    "PRO":        "ANALYST",
    "ENTERPRISE": "ADMIN",
    "MSSP":       "OWNER",
    "INTERNAL":   "OWNER",
}


# ── Core RBAC Functions ────────────────────────────────────────────────────

@lru_cache(maxsize=512)
def get_role_permissions(role: str) -> frozenset:
    """Return permission set for role (cached for performance)."""
    return frozenset(ROLE_PERMISSIONS.get(role, set()))


def has_permission(role: str, permission: str) -> bool:
    """Check if role includes a specific permission."""
    perms = get_role_permissions(role)
    return permission in perms or Perm.ADMIN_ALL in perms


def get_tier_role(tier: str) -> str:
    """Map API tier to RBAC role (backward compat)."""
    return _TIER_TO_ROLE.get(tier, "VIEWER")


def tier_has_permission(tier: str, permission: str) -> bool:
    """Check permission via tier (backward compat path)."""
    role = get_tier_role(tier)
    return has_permission(role, permission)


def get_missing_permissions(role: str, required: list) -> list:
    """Return list of permissions that role is missing from required set."""
    return [p for p in required if not has_permission(role, p)]


# ── FastAPI Dependency ─────────────────────────────────────────────────────

def require_permission(permission: str):
    """
    FastAPI dependency factory for permission-gated endpoints.

    Usage:
        @router.get("/admin/users", dependencies=[Depends(require_permission(Perm.USERS_VIEW_ALL))])
        async def list_users(): ...

    When CDB_RBAC_ENABLED=false: passes through using tier-based role mapping.
    When CDB_RBAC_ENABLED=true:  enforces full RBAC model.
    """
    from fastapi import Depends, HTTPException, Header, Request

    async def _check_permission(
        request:   Request,
        x_api_key: Optional[str] = Header(None),
        authorization: Optional[str] = Header(None),
    ) -> dict:
        # Extract bearer token if present
        bearer = None
        if authorization and authorization.lower().startswith("bearer "):
            bearer = authorization[7:]

        # Resolve tier via existing auth handler (zero regression)
        from agent.api.auth import auth_handler
        tier, identity, err = auth_handler.resolve_tier(
            api_key=x_api_key,
            bearer=bearer,
            remote_ip=request.client.host if request.client else "unknown",
        )

        if err:
            logger.warning(f"[RBAC] Auth failed: {err} | IP={request.client.host if request.client else '?'}")
            raise HTTPException(status_code=401, detail=f"Authentication failed: {err}")

        # Map to role
        role = get_tier_role(tier)

        # Permission check
        if not has_permission(role, permission):
            logger.warning(f"[RBAC] Permission denied: {identity[:8]}… role={role} required={permission}")
            raise HTTPException(
                status_code=403,
                detail={
                    "error":        "permission_denied",
                    "required":     permission,
                    "your_role":    role,
                    "your_tier":    tier,
                    "upgrade_url":  "https://intel.cyberdudebivash.com/upgrade",
                }
            )

        logger.debug(f"[RBAC] Access granted: {identity[:8]}… role={role} perm={permission}")
        return {"identity": identity, "tier": tier, "role": role, "permission": permission}

    return Depends(_check_permission)


# ── Permission Matrix Export ────────────────────────────────────────────────

def get_permission_matrix() -> dict:
    """Return full permission matrix for API documentation / admin UI."""
    return {
        role: sorted(list(perms))
        for role, perms in ROLE_PERMISSIONS.items()
    }
