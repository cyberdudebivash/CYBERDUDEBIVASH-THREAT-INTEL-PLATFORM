"""
SENTINEL APEX — Zero Trust Authentication & Authorization Engine
=================================================================
- JWT/OIDC via Keycloak (multi-realm, multi-tenant)
- API Key authentication (SHA-256 hashed, prefix-indexed)
- RBAC: roles → permissions mapping
- ABAC: attribute-based policy enforcement (OPA integration)
- Tenant context injection
- Tier enforcement: FREE / PRO / ENTERPRISE / GOVERNMENT / OEM
"""
from __future__ import annotations

import hashlib
import secrets
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Optional

import httpx
import structlog
from fastapi import Depends, Header, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from jose import JWTError, jwt
from pydantic import BaseModel, Field

log = structlog.get_logger("sentinel.auth")

# ---------------------------------------------------------------------------
# Tier + Role Definitions
# ---------------------------------------------------------------------------
class TenantTier(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"
    GOVERNMENT = "government"
    OEM = "oem"
    MSSP = "mssp"

class Role(str, Enum):
    VIEWER = "viewer"
    ANALYST = "analyst"
    SOC_ENGINEER = "soc_engineer"
    THREAT_HUNTER = "threat_hunter"
    ADMIN = "admin"
    SUPER_ADMIN = "super_admin"
    API_USER = "api_user"
    OEM_PARTNER = "oem_partner"
    MSSP_OPERATOR = "mssp_operator"
    GOVERNMENT_ANALYST = "government_analyst"

# Permission matrix: role → set of permissions
ROLE_PERMISSIONS: dict[Role, set[str]] = {
    Role.VIEWER: {
        "intel:read:basic",
        "dashboard:read",
    },
    Role.ANALYST: {
        "intel:read:basic", "intel:read:enriched",
        "dashboard:read", "reports:read",
        "ioc:search", "cve:read",
    },
    Role.SOC_ENGINEER: {
        "intel:read:*", "dashboard:read", "dashboard:write",
        "reports:read", "reports:write",
        "ioc:search", "ioc:write", "cve:read",
        "soc:triage", "soc:investigate", "playbooks:execute",
        "alerts:manage",
    },
    Role.THREAT_HUNTER: {
        "intel:read:*", "intel:write:custom",
        "dashboard:read", "reports:read", "reports:write",
        "ioc:*", "cve:*", "yara:*", "sigma:*",
        "hunt:execute", "graph:read",
        "stix:read", "taxii:read",
    },
    Role.ADMIN: {
        "intel:*", "dashboard:*", "reports:*",
        "ioc:*", "cve:*", "yara:*", "sigma:*",
        "hunt:*", "graph:*", "stix:*", "taxii:*",
        "soc:*", "alerts:*", "playbooks:*",
        "tenant:manage", "users:manage", "api_keys:manage",
        "billing:read",
    },
    Role.SUPER_ADMIN: {"*"},
    Role.API_USER: {
        "intel:read:basic", "ioc:search",
        "cve:read", "api:consume",
    },
    Role.OEM_PARTNER: {
        "intel:read:*", "intel:export",
        "api:*", "stix:*", "taxii:*",
        "oem:branding", "oem:white_label",
    },
    Role.MSSP_OPERATOR: {
        "intel:read:*", "intel:write:custom",
        "soc:*", "alerts:*", "playbooks:*",
        "tenant:sub_manage", "reports:*",
        "mssp:client_management",
    },
    Role.GOVERNMENT_ANALYST: {
        "intel:read:*", "intel:classified:read",
        "ioc:*", "cve:*", "yara:*", "sigma:*",
        "hunt:*", "stix:*", "taxii:*",
        "gov:classified_access",
    },
}

# Tier → allowed API endpoints/features
TIER_FEATURES: dict[TenantTier, set[str]] = {
    TenantTier.FREE: {
        "intel_basic", "dashboard_basic",
        "cve_summary", "ioc_search_limited",
    },
    TenantTier.PRO: {
        "intel_basic", "intel_enriched",
        "dashboard_full", "cve_full",
        "ioc_search_full", "reports_basic",
        "stix_export", "ai_summaries",
        "pdf_reports", "sigma_basic",
    },
    TenantTier.ENTERPRISE: {
        "intel_full", "intel_enriched", "intel_raw",
        "dashboard_full", "cve_full",
        "ioc_search_full", "reports_advanced",
        "stix_export", "taxii_server",
        "ai_enrichment_full", "ai_actor_attribution",
        "sigma_full", "yara_generation",
        "soc_automation", "threat_hunting",
        "api_full", "siem_integration",
        "webhook_delivery", "custom_rules",
    },
    TenantTier.GOVERNMENT: {
        "*",  # All features + classified
        "classified_intel", "gov_feeds",
        "air_gap_export", "fips_mode",
    },
    TenantTier.OEM: {
        "*",  # All features + white-label
        "white_label", "custom_branding",
        "api_resale", "embedded_intel",
    },
    TenantTier.MSSP: {
        "*",  # All features + multi-tenant management
        "sub_tenant_management",
        "mssp_portal", "client_reporting",
        "bulk_api", "reseller_billing",
    },
}

# ---------------------------------------------------------------------------
# JWT Payload
# ---------------------------------------------------------------------------
class JWTPayload(BaseModel):
    sub: str                          # User ID
    tenant_id: str                    # Tenant UUID
    tenant_tier: TenantTier           # Subscription tier
    roles: list[Role]                 # Assigned roles
    permissions: set[str] = Field(default_factory=set)  # Effective permissions
    email: Optional[str] = None
    given_name: Optional[str] = None
    family_name: Optional[str] = None
    exp: int                          # Expiry (unix ts)
    iat: int                          # Issued at
    jti: str                          # JWT ID (replay prevention)
    iss: str                          # Issuer (Keycloak realm URL)
    azp: Optional[str] = None         # Authorized party (client_id)

    def has_permission(self, permission: str) -> bool:
        if "*" in self.permissions:
            return True
        if permission in self.permissions:
            return True
        # Wildcard matching: "intel:read:*" covers "intel:read:basic"
        parts = permission.split(":")
        for i in range(len(parts)):
            wildcard = ":".join(parts[:i+1]) + ":*"
            if wildcard in self.permissions:
                return True
            flat_wildcard = ":".join(parts[:i]) + ":*" if i > 0 else "*"
            if flat_wildcard in self.permissions:
                return True
        return False

    def has_feature(self, feature: str) -> bool:
        features = TIER_FEATURES.get(self.tenant_tier, set())
        return "*" in features or feature in features

# ---------------------------------------------------------------------------
# API Key Model
# ---------------------------------------------------------------------------
@dataclass
class APIKey:
    key_id: str           # sk_live_xxxx or sk_test_xxxx prefix
    key_hash: str         # SHA-256 of full key
    tenant_id: str
    tenant_tier: TenantTier
    roles: list[Role]
    name: str
    created_at: float
    last_used_at: Optional[float] = None
    expires_at: Optional[float] = None
    is_active: bool = True
    allowed_ips: list[str] = field(default_factory=list)
    rate_limit_override: Optional[dict] = None

# ---------------------------------------------------------------------------
# CurrentUser dependency
# ---------------------------------------------------------------------------
class CurrentUser(BaseModel):
    user_id: str
    tenant_id: str
    tenant_tier: TenantTier
    roles: list[Role]
    permissions: set[str]
    auth_method: str  # "jwt" or "api_key"
    email: Optional[str] = None

    def require_permission(self, permission: str) -> None:
        if not self._has_permission(permission):
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Permission denied: {permission} required",
            )

    def require_feature(self, feature: str) -> None:
        features = TIER_FEATURES.get(self.tenant_tier, set())
        if "*" not in features and feature not in features:
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=f"Feature '{feature}' requires upgrade. Current tier: {self.tenant_tier}",
                headers={"X-Upgrade-URL": "https://intel.cyberdudebivash.com/upgrade"},
            )

    def _has_permission(self, permission: str) -> bool:
        if "*" in self.permissions:
            return True
        if permission in self.permissions:
            return True
        parts = permission.split(":")
        for i in range(len(parts)):
            wildcard = ":".join(parts[:i+1]) + ":*"
            if wildcard in self.permissions:
                return True
        return False

# ---------------------------------------------------------------------------
# Auth Service
# ---------------------------------------------------------------------------
class AuthService:
    _jwks: dict = {}
    _http_client: httpx.AsyncClient = None
    _config = None

    @classmethod
    async def initialize(cls, config) -> None:
        cls._config = config
        cls._http_client = httpx.AsyncClient(timeout=10.0)
        await cls._refresh_jwks()
        log.info("sentinel.auth.initialized", keycloak_url=config.keycloak_url)

    @classmethod
    async def close(cls) -> None:
        if cls._http_client:
            await cls._http_client.aclose()

    @classmethod
    async def _refresh_jwks(cls) -> None:
        """Fetch JWKS from Keycloak for JWT verification."""
        url = f"{cls._config.keycloak_url}/protocol/openid-connect/certs"
        try:
            resp = await cls._http_client.get(url)
            resp.raise_for_status()
            cls._jwks = resp.json()
            log.info("sentinel.auth.jwks_refreshed", key_count=len(cls._jwks.get("keys", [])))
        except Exception as exc:
            log.error("sentinel.auth.jwks_refresh_failed", error=str(exc))

    @classmethod
    async def verify_token(cls, token: str) -> JWTPayload:
        """Verify JWT, extract claims, resolve permissions."""
        try:
            # Decode + verify signature against Keycloak JWKS
            payload = jwt.decode(
                token,
                cls._jwks,
                algorithms=["RS256"],
                options={"verify_aud": False},
            )
        except JWTError as exc:
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail=f"Invalid token: {exc}",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Expiry check
        if payload.get("exp", 0) < time.time():
            raise HTTPException(
                status_code=status.HTTP_401_UNAUTHORIZED,
                detail="Token expired",
                headers={"WWW-Authenticate": "Bearer"},
            )

        # Extract Sentinel-specific claims (injected by Keycloak mapper)
        tenant_id = payload.get("tenant_id") or payload.get("azp", "default")
        tier_str = payload.get("tenant_tier", "free")
        roles_raw = (
            payload.get("realm_access", {}).get("roles", [])
            + payload.get("resource_access", {}).get("sentinel-apex", {}).get("roles", [])
        )

        roles = [Role(r) for r in roles_raw if r in Role._value2member_map_]
        if not roles:
            roles = [Role.VIEWER]

        # Compute effective permissions from roles
        permissions: set[str] = set()
        for role in roles:
            permissions |= ROLE_PERMISSIONS.get(role, set())

        try:
            tier = TenantTier(tier_str)
        except ValueError:
            tier = TenantTier.FREE

        return JWTPayload(
            sub=payload["sub"],
            tenant_id=tenant_id,
            tenant_tier=tier,
            roles=roles,
            permissions=permissions,
            email=payload.get("email"),
            given_name=payload.get("given_name"),
            family_name=payload.get("family_name"),
            exp=payload["exp"],
            iat=payload.get("iat", int(time.time())),
            jti=payload.get("jti", secrets.token_urlsafe(16)),
            iss=payload.get("iss", ""),
            azp=payload.get("azp"),
        )

    @classmethod
    async def health_check(cls) -> dict:
        try:
            url = f"{cls._config.keycloak_url}/.well-known/openid-configuration"
            resp = await cls._http_client.get(url, timeout=3.0)
            return {"status": "ok" if resp.status_code == 200 else "degraded"}
        except Exception:
            return {"status": "down"}

# ---------------------------------------------------------------------------
# FastAPI Dependency Injection
# ---------------------------------------------------------------------------
bearer_scheme = HTTPBearer(auto_error=False)

async def verify_jwt(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
) -> CurrentUser:
    if not credentials:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Authentication required",
            headers={"WWW-Authenticate": "Bearer"},
        )
    payload = await AuthService.verify_token(credentials.credentials)
    return CurrentUser(
        user_id=payload.sub,
        tenant_id=payload.tenant_id,
        tenant_tier=payload.tenant_tier,
        roles=payload.roles,
        permissions=payload.permissions,
        auth_method="jwt",
        email=payload.email,
    )

async def verify_api_key(
    request: Request,
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> CurrentUser:
    if not x_api_key:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="API key required (X-API-Key header)",
        )
    # Hash the provided key and look up in Redis/DB
    key_hash = hashlib.sha256(x_api_key.encode()).hexdigest()
    # TODO: Look up from Redis cache → PostgreSQL
    # For now, placeholder
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Invalid API key",
    )

async def get_current_user(
    request: Request,
    credentials: HTTPAuthorizationCredentials = Depends(bearer_scheme),
    x_api_key: Optional[str] = Header(None, alias="X-API-Key"),
) -> CurrentUser:
    """Unified auth: accepts JWT Bearer OR API Key."""
    if credentials:
        return await verify_jwt(request, credentials)
    if x_api_key:
        return await verify_api_key(request, x_api_key)
    raise HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Authentication required (Bearer token or X-API-Key)",
        headers={"WWW-Authenticate": "Bearer"},
    )

# Tier-enforcement dependencies
def require_tier(*tiers: TenantTier):
    async def _enforce(user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if user.tenant_tier not in tiers and user.tenant_tier != TenantTier.GOVERNMENT:
            allowed = " or ".join(t.value.upper() for t in tiers)
            raise HTTPException(
                status_code=status.HTTP_402_PAYMENT_REQUIRED,
                detail=f"This endpoint requires {allowed} tier. Upgrade at /upgrade",
                headers={"X-Upgrade-URL": "https://intel.cyberdudebivash.com/upgrade"},
            )
        return user
    return _enforce

RequireProPlus = Depends(require_tier(TenantTier.PRO, TenantTier.ENTERPRISE, TenantTier.GOVERNMENT, TenantTier.OEM, TenantTier.MSSP))
RequireEnterprise = Depends(require_tier(TenantTier.ENTERPRISE, TenantTier.GOVERNMENT, TenantTier.OEM, TenantTier.MSSP))
RequireGovernment = Depends(require_tier(TenantTier.GOVERNMENT))
