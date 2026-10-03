"""
================================================================================
CYBERDUDEBIVASH® SENTINEL APEX — Role-Based Access Control (RBAC) Engine
api/rbac.py — SOC 2 CC6.3 Compliant RBAC Implementation
================================================================================
Version : 162.0.0
Purpose : Production-grade role-based access control with permission enforcement,
          access_level validation, and audit-trail integration for all API calls.

SOC 2 Control: CC6.3 — Role-based access control restricts system access
               to authorized users based on least-privilege principles.
================================================================================
"""
from __future__ import annotations

import logging
from enum import Enum
from typing import Dict, List, Optional, Set

logger = logging.getLogger("apex.rbac")

# ── Role Definitions ─────────────────────────────────────────────────────────

class Role(str, Enum):
    """SENTINEL APEX RBAC roles — principle of least privilege."""
    ANONYMOUS   = "anonymous"     # Unauthenticated — public feed only
    FREE        = "free"          # Free tier — limited read access
    PRO         = "pro"           # Pro tier — full read + export
    ENTERPRISE  = "enterprise"    # Enterprise — full access + MSSP features
    MSSP        = "mssp"          # MSSP partner — multi-tenant management
    ADMIN       = "admin"         # Platform admin — all permissions
    SERVICE     = "service"       # Internal service accounts


# ── Permission Registry ───────────────────────────────────────────────────────

class Permission(str, Enum):
    """Granular permissions enforced at the API layer."""
    # Feed permissions
    READ_FEED_PUBLIC        = "feed:read:public"
    READ_FEED_FULL          = "feed:read:full"
    READ_FEED_STIX          = "feed:read:stix"
    READ_FEED_IOC           = "feed:read:ioc"

    # Alert permissions
    READ_ALERTS             = "alerts:read"
    CREATE_ALERT_RULE       = "alerts:write"
    MANAGE_PLAYBOOKS        = "playbooks:manage"

    # API key management
    MANAGE_API_KEYS         = "apikeys:manage"
    VIEW_API_KEYS           = "apikeys:view"

    # MSSP / multi-tenant
    MANAGE_TENANTS          = "tenants:manage"
    VIEW_TENANT_TELEMETRY   = "tenants:telemetry:read"

    # Export
    EXPORT_CSV              = "export:csv"
    EXPORT_STIX             = "export:stix"
    EXPORT_SIGMA            = "export:sigma"

    # Billing
    VIEW_BILLING            = "billing:view"
    MANAGE_BILLING          = "billing:manage"

    # Admin
    ADMIN_ALL               = "admin:*"


# ── RBAC Access Control Matrix ────────────────────────────────────────────────

ROLE_PERMISSIONS: Dict[Role, Set[Permission]] = {
    Role.ANONYMOUS: {
        Permission.READ_FEED_PUBLIC,
    },
    Role.FREE: {
        Permission.READ_FEED_PUBLIC,
        Permission.VIEW_API_KEYS,
        Permission.VIEW_BILLING,
    },
    Role.PRO: {
        Permission.READ_FEED_PUBLIC,
        Permission.READ_FEED_FULL,
        Permission.READ_FEED_IOC,
        Permission.READ_ALERTS,
        Permission.EXPORT_CSV,
        Permission.EXPORT_SIGMA,
        Permission.MANAGE_API_KEYS,
        Permission.VIEW_BILLING,
    },
    Role.ENTERPRISE: {
        Permission.READ_FEED_PUBLIC,
        Permission.READ_FEED_FULL,
        Permission.READ_FEED_STIX,
        Permission.READ_FEED_IOC,
        Permission.READ_ALERTS,
        Permission.CREATE_ALERT_RULE,
        Permission.MANAGE_PLAYBOOKS,
        Permission.EXPORT_CSV,
        Permission.EXPORT_STIX,
        Permission.EXPORT_SIGMA,
        Permission.MANAGE_API_KEYS,
        Permission.VIEW_BILLING,
        Permission.MANAGE_BILLING,
    },
    Role.MSSP: {
        Permission.READ_FEED_PUBLIC,
        Permission.READ_FEED_FULL,
        Permission.READ_FEED_STIX,
        Permission.READ_FEED_IOC,
        Permission.READ_ALERTS,
        Permission.CREATE_ALERT_RULE,
        Permission.MANAGE_PLAYBOOKS,
        Permission.EXPORT_CSV,
        Permission.EXPORT_STIX,
        Permission.EXPORT_SIGMA,
        Permission.MANAGE_API_KEYS,
        Permission.MANAGE_TENANTS,
        Permission.VIEW_TENANT_TELEMETRY,
        Permission.VIEW_BILLING,
        Permission.MANAGE_BILLING,
    },
    Role.ADMIN: {p for p in Permission},      # Admin has all permissions
    Role.SERVICE: {
        Permission.READ_FEED_FULL,
        Permission.READ_ALERTS,
        Permission.VIEW_TENANT_TELEMETRY,
    },
}

# Access level map (access_level numeric for Terraform/WAF integration)
ACCESS_LEVEL: Dict[Role, int] = {
    Role.ANONYMOUS: 0,
    Role.FREE:      1,
    Role.PRO:       2,
    Role.ENTERPRISE: 3,
    Role.MSSP:      4,
    Role.ADMIN:     9,
    Role.SERVICE:   2,
}


# ── RBAC Enforcement ──────────────────────────────────────────────────────────

class RBACEnforcer:
    """Enforces role-based access control on all API requests."""

    def resolve_role(self, tier: str) -> Role:
        """Map API key tier string to RBAC Role."""
        mapping = {
            "free":       Role.FREE,
            "pro":        Role.PRO,
            "enterprise": Role.ENTERPRISE,
            "mssp":       Role.MSSP,
            "admin":      Role.ADMIN,
            "service":    Role.SERVICE,
        }
        role = mapping.get(tier.lower(), Role.FREE)
        logger.debug("rbac.resolve_role tier=%s → role=%s access_level=%d",
                     tier, role.value, ACCESS_LEVEL[role])
        return role

    def has_permission(self, role: Role, permission: Permission) -> bool:
        """Check if a role has a specific permission."""
        allowed = ROLE_PERMISSIONS.get(role, set())
        # Admin wildcard
        if Permission.ADMIN_ALL in allowed:
            return True
        result = permission in allowed
        if not result:
            logger.warning("rbac.deny role=%s permission=%s access_level=%d",
                           role.value, permission.value, ACCESS_LEVEL[role])
        return result

    def require_permission(self, role: Role, permission: Permission) -> None:
        """Raise PermissionError if role lacks permission (FastAPI dependency)."""
        if not self.has_permission(role, permission):
            raise PermissionError(
                f"Role '{role.value}' lacks permission '{permission.value}'. "
                f"Required access_level ≥ {ACCESS_LEVEL.get(role, 0)}. "
                "Upgrade your plan at https://cyberdudebivash.in/upgrade"
            )

    def get_access_level(self, tier: str) -> int:
        """Return numeric access_level for WAF/Terraform rate-rule integration."""
        role = self.resolve_role(tier)
        return ACCESS_LEVEL[role]


# Singleton enforcer — import and use across all API routes
rbac = RBACEnforcer()


def check_permission(tier: str, permission: Permission) -> bool:
    """Convenience function for FastAPI dependency injection."""
    role = rbac.resolve_role(tier)
    return rbac.has_permission(role, permission)


def require_enterprise(tier: str) -> None:
    """Enforce enterprise-tier access_level for premium endpoints."""
    role = rbac.resolve_role(tier)
    rbac.require_permission(role, Permission.MANAGE_TENANTS)


def get_access_level(tier: str) -> int:
    """Return access_level integer for a given API key tier."""
    return rbac.get_access_level(tier)
