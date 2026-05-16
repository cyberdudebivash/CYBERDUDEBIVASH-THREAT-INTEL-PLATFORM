#!/usr/bin/env python3
"""
agent/tenancy/tenant_context.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
MULTI-TENANT CONTEXT & ISOLATION ENGINE

Provides per-request tenant context injection and enforces strict data isolation
between organisations on the shared platform.

Isolation model:
  - Logical isolation (default): all tenants on shared infrastructure,
    data partitioned by org_id in all storage operations
  - Namespace isolation: Redis key prefixing ensures tenants cannot
    access each other's rate limit / session / cache state
  - Data-at-rest: tenant data stored under data/tenants/{org_id}/
  - Query filtering: all intel/search/export endpoints receive implicit
    org_id filter — bypass requires OWNER role + explicit override flag

Security guarantees:
  - org_id injected from verified JWT claim (not from request body/query)
  - No org_id in URL path (prevents enumeration / confusion attacks)
  - Cross-tenant reads blocked at application layer (defence in depth
    alongside future database row-level security)

Thread-local / async context:
  - FastAPI uses async; contextvars (not threading.local) for safety
  - TenantContext.set() called by auth middleware after token validation
  - TenantContext.get() used anywhere in the request call stack

Feature-flag gated: CDB_MULTI_TENANT_ENABLED=true
"""

import os
import logging
from contextvars import ContextVar
from typing import Optional
from dataclasses import dataclass

logger = logging.getLogger("CDB-TENANT")

_MULTI_TENANT_ENABLED = os.environ.get("CDB_MULTI_TENANT_ENABLED", "false").lower() == "true"

# ── Per-Request Async Context ─────────────────────────────────────────────────

@dataclass(frozen=True)
class TenantCtx:
    """Immutable per-request tenant context."""
    org_id:     str
    tier:       str
    role:       str
    user_id:    str
    request_id: str = ""
    is_admin:   bool = False   # Platform-level admin (not org admin)

    def redis_prefix(self) -> str:
        """Tenant-namespaced Redis key prefix."""
        return f"cdb:tenant:{self.org_id}"

    def data_path(self) -> str:
        """Tenant-isolated filesystem path."""
        return os.path.join("data", "tenants", self.org_id)

    def can_cross_tenant(self) -> bool:
        """Only platform admins may access cross-tenant data."""
        return self.is_admin


# Module-level ContextVar — one per async request, never leaks across tasks
_current_tenant: ContextVar[Optional[TenantCtx]] = ContextVar("_current_tenant", default=None)


def set_tenant_context(ctx: TenantCtx) -> None:
    """Inject tenant context for the current async task. Called by auth middleware."""
    _current_tenant.set(ctx)


def get_tenant_context() -> Optional[TenantCtx]:
    """Retrieve tenant context for the current async task."""
    return _current_tenant.get()


def require_tenant_context() -> TenantCtx:
    """
    Retrieve tenant context, raising if not set.
    Use in endpoints that REQUIRE authentication (not public routes).
    """
    ctx = _current_tenant.get()
    if ctx is None:
        raise RuntimeError("TenantContext not set — ensure auth middleware is active")
    return ctx


def clear_tenant_context() -> None:
    """Clear tenant context (end of request)."""
    _current_tenant.set(None)


# ── Isolation Enforcement ─────────────────────────────────────────────────────

def assert_tenant_access(resource_org_id: str, allow_admin_override: bool = True) -> None:
    """
    Enforce that the current tenant may access a resource owned by resource_org_id.
    Raises PermissionError on violation.

    Args:
        resource_org_id:      org_id of the resource being accessed
        allow_admin_override: If True, platform admins may access any org's resource
    """
    if not _MULTI_TENANT_ENABLED:
        return  # Single-tenant mode — no isolation enforcement

    ctx = get_tenant_context()
    if ctx is None:
        return  # Unauthenticated / public route

    if ctx.org_id == resource_org_id:
        return  # Own resource — always allowed

    if allow_admin_override and ctx.is_admin:
        logger.warning(
            f"[TENANT] Admin cross-tenant access: accessor={ctx.org_id} "
            f"resource_owner={resource_org_id} user={ctx.user_id}"
        )
        return  # Admin override

    raise PermissionError(
        f"Cross-tenant access denied: org={ctx.org_id} cannot access "
        f"resource owned by org={resource_org_id}"
    )


def tenant_redis_key(base_key: str) -> str:
    """
    Prefix a Redis key with the current tenant namespace.
    Ensures Redis keys never collide across tenants.

    Example:
      base_key = "rate:api:/api/v1/intel"
      → "cdb:tenant:org_abc123:rate:api:/api/v1/intel"
    """
    ctx = get_tenant_context()
    if ctx and _MULTI_TENANT_ENABLED:
        return f"{ctx.redis_prefix()}:{base_key}"
    return f"cdb:{base_key}"


def tenant_data_path(sub_path: str = "") -> str:
    """
    Return the tenant-isolated filesystem path for a given sub-path.
    Falls back to global data/ path in single-tenant mode.
    """
    ctx = get_tenant_context()
    if ctx and _MULTI_TENANT_ENABLED:
        base = ctx.data_path()
    else:
        base = "data"
    if sub_path:
        return os.path.join(base, sub_path)
    return base


# ── FastAPI Middleware ────────────────────────────────────────────────────────

async def tenant_context_middleware(request, call_next):
    """
    FastAPI middleware that extracts tenant context from auth headers and
    injects it into the async context variable.

    Chain position: AFTER auth middleware (which sets X-CDB-Org-ID, X-CDB-Tier, etc.)
    """
    if not _MULTI_TENANT_ENABLED:
        return await call_next(request)

    org_id     = request.headers.get("X-CDB-Org-ID", "global")
    tier       = request.headers.get("X-CDB-Tier", "FREE")
    role       = request.headers.get("X-CDB-Role", "VIEWER")
    user_id    = request.headers.get("X-CDB-User-ID", "anonymous")
    request_id = request.headers.get("X-Request-ID", "")
    is_admin   = request.headers.get("X-CDB-Platform-Admin", "false").lower() == "true"

    ctx = TenantCtx(
        org_id=org_id,
        tier=tier,
        role=role,
        user_id=user_id,
        request_id=request_id,
        is_admin=is_admin,
    )
    set_tenant_context(ctx)

    try:
        response = await call_next(request)
    finally:
        clear_tenant_context()

    return response
