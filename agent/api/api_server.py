#!/usr/bin/env python3
"""
agent/api/api_server.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
UNIFIED ORCHESTRATION HUB (COMMUNITY + ENTERPRISE + VAULT)
Founder & CEO — CyberDudeBivash Pvt. Ltd.

v47.0 Enterprise Hardening (100% additive — zero breaking changes):
  - P0: CORS wildcard replaced with explicit allowlist (CDB_CORS_ALLOW_ALL=true to rollback)
  - Security headers middleware: HSTS, CSP, X-Frame-Options, X-Content-Type-Options
  - Request tracing: X-Request-ID injected on every response
  - Enterprise feature flags: all gated on CDB_* env vars, default OFF
  - Health + readiness endpoints: /api/v1/health, /api/v1/ready, /api/v1/version
  - OIDC discovery: /.well-known/openid-configuration, /.well-known/jwks.json
  - Prometheus metrics middleware (when CDB_METRICS_ENABLED=true)
  - OpenTelemetry tracing (when CDB_TRACING_ENABLED=true)
  - Structured JSON logging (when CDB_STRUCTURED_LOGGING=true)

All original routes preserved exactly:
  - public_api.router       (community layer)
  - premium_api.router      (SaaS revenue layer)
  - /v1/premium/vault/session-key (v46.0 vault middleware)
  - startup_event()
"""

import os
import uuid
import json
import time
import logging

from fastapi import FastAPI, Header, HTTPException, Depends, Request, Response
from fastapi.middleware.cors import CORSMiddleware
from starlette.middleware.base import BaseHTTPMiddleware

from agent.api import public_api, premium_api

# ACCESS GOVERNANCE v173.0 — Single Source of Truth
# All access decisions must flow through access_control_policy.
# This import also runs _self_check_on_import() which will raise on startup
# if the policy is in an invalid state — preventing a bad deploy from going live.
from access_control_policy import (
    TIER_PUBLIC, TIER_PRO, TIER_ENTERPRISE, TIER_MSSP,
    validate_api_response,
    run_policy_checks,
    detect_policy_drift,
    generate_audit_record,
    POLICY_CANONICAL_VERSION,
)

# Graceful config import — VERSION may be in config or config_v25
try:
    from agent.config import VERSION, AUTHORITY, API_HOST, API_PORT
except ImportError:
    VERSION   = os.environ.get("PLATFORM_VERSION", "152.0.0")
    AUTHORITY = "CyberDudeBivash Pvt. Ltd."
    API_HOST  = os.environ.get("API_HOST", "0.0.0.0")
    API_PORT  = int(os.environ.get("API_PORT", "8080"))

logger = logging.getLogger("CDB-API")

# ── Enterprise Feature Flags ───────────────────────────────────────────────────
# All default OFF — enable individually. Rollback = set env to "false".
_METRICS_ENABLED      = os.environ.get("CDB_METRICS_ENABLED",      "true").lower()  == "true"
_RBAC_ENABLED         = os.environ.get("CDB_RBAC_ENABLED",         "false").lower() == "true"
_MULTI_TENANT_ENABLED = os.environ.get("CDB_MULTI_TENANT_ENABLED", "false").lower() == "true"
_TRACING_ENABLED      = os.environ.get("CDB_TRACING_ENABLED",      "false").lower() == "true"
_AUDIT_ENABLED        = os.environ.get("CDB_AUDIT_ENABLED",        "false").lower() == "true"
_STRUCTURED_LOGGING   = os.environ.get("CDB_STRUCTURED_LOGGING",   "true").lower()  == "true"
_CDB_ENV              = os.environ.get("CDB_ENV", "production")

# ── Structured Logging Init ────────────────────────────────────────────────────
if _STRUCTURED_LOGGING:
    try:
        from agent.telemetry.structured_logging import configure_logging
        configure_logging()
    except Exception:
        logging.basicConfig(level=logging.INFO)
else:
    logging.basicConfig(level=logging.INFO)

# ── CORS Configuration ─────────────────────────────────────────────────────────
# P0 FIX: Replace wildcard with explicit allowlist.
# Rollback instantly: set CDB_CORS_ALLOW_ALL=true in environment.

def _build_allowed_origins() -> list:
    """Build CORS allowed-origins list from environment configuration."""
    if os.environ.get("CDB_CORS_ALLOW_ALL", "false").lower() == "true":
        logger.warning("[CORS] CDB_CORS_ALLOW_ALL=true — wildcard CORS active (insecure)")
        return ["*"]
    base = [
        "https://intel.cyberdudebivash.com",
        "https://cyberdudebivash.com",
        "https://www.cyberdudebivash.com",
        "https://cyberdudebivash.github.io",
    ]
    extra = os.environ.get("CDB_CORS_EXTRA_ORIGINS", "")
    if extra:
        base.extend(o.strip() for o in extra.split(",") if o.strip())
    if _CDB_ENV in ("development", "dev", "local"):
        base.extend(["http://localhost:3000", "http://localhost:8080", "http://127.0.0.1:3000"])
    return base

_ALLOWED_ORIGINS = _build_allowed_origins()

# ── FastAPI Application ────────────────────────────────────────────────────────

app = FastAPI(
    title="CYBERDUDEBIVASH® SENTINEL APEX",
    description="Global Cybersecurity Tools, Threat Intelligence & AI Security Platform",
    version=VERSION,
    docs_url="/api/docs" if _CDB_ENV != "production" else None,   # Disable Swagger in prod
    redoc_url="/api/redoc" if _CDB_ENV != "production" else None,
    openapi_url="/api/openapi.json" if _CDB_ENV != "production" else None,
)

# ── CORS Middleware (P0-fixed) ─────────────────────────────────────────────────
app.add_middleware(
    CORSMiddleware,
    allow_origins=_ALLOWED_ORIGINS,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "OPTIONS", "HEAD"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-Response-Time-Ms", "X-RateLimit-Remaining"],
)

# ── Security Headers Middleware ───────────────────────────────────────────────

@app.middleware("http")
async def security_headers_middleware(request: Request, call_next):
    """
    Inject security headers on every response.
    Enterprise hardening: HSTS, CSP, frame guard, content-type sniff guard.
    """
    # Inject X-Request-ID before processing
    request_id = request.headers.get("X-Request-ID") or str(uuid.uuid4())[:16]
    response   = await call_next(request)

    # Strict Transport Security — 1 year, include subdomains
    response.headers["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains; preload"
    # Content Security Policy — strict for API (no inline scripts/styles)
    response.headers["Content-Security-Policy"] = (
        "default-src 'none'; frame-ancestors 'none'; form-action 'none'"
    )
    response.headers["X-Frame-Options"]        = "DENY"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["Referrer-Policy"]        = "strict-origin-when-cross-origin"
    response.headers["Permissions-Policy"]     = "geolocation=(), microphone=(), camera=()"
    response.headers["X-Request-ID"]           = request_id

    # Remove server fingerprint headers
    response.headers.pop("server", None)
    response.headers.pop("x-powered-by", None)

    return response

# ── Prometheus Metrics Middleware (feature-flagged) ───────────────────────────
if _METRICS_ENABLED:
    try:
        from agent.telemetry.metrics import metrics_middleware, metrics_router
        app.middleware("http")(metrics_middleware)
        app.include_router(metrics_router)
        logger.info("[METRICS] Prometheus metrics middleware active → /metrics")
    except Exception as e:
        logger.warning(f"[METRICS] Could not initialise metrics middleware: {e}")

# ── OpenTelemetry Tracing (feature-flagged) ───────────────────────────────────
if _TRACING_ENABLED:
    try:
        from agent.telemetry.tracing import init_tracing
        init_tracing(app)
    except Exception as e:
        logger.warning(f"[TRACING] Could not initialise tracing: {e}")

# ── Structured Logging Context Middleware (feature-flagged) ───────────────────
if _STRUCTURED_LOGGING:
    try:
        from agent.telemetry.structured_logging import logging_context_middleware
        app.middleware("http")(logging_context_middleware)
    except Exception:
        pass

# ── Multi-Tenant Context Middleware (feature-flagged) ─────────────────────────
if _MULTI_TENANT_ENABLED:
    try:
        from agent.tenancy.tenant_context import tenant_context_middleware
        app.middleware("http")(tenant_context_middleware)
        logger.info("[TENANT] Multi-tenant context middleware active")
    except Exception as e:
        logger.warning(f"[TENANT] Could not initialise tenant middleware: {e}")


# ═══════════════════════════════════════════════════════════════════════════════
# EXISTING ROUTES — PRESERVED 100% (v46.0 and earlier)
# ═══════════════════════════════════════════════════════════════════════════════

# 1. COMMUNITY LAYER (Stable — v43)
app.include_router(public_api.router)

# 2. SaaS REVENUE & PRODUCT LAYER (v44 — v45)
app.include_router(premium_api.router)

# 3. v46.0 VAULT MIDDLEWARE (Additive — preserved exactly)
@app.get("/v1/premium/vault/session-key", tags=["Vault Protocol"])
async def get_vault_session_key(x_api_key: str = Header(None)):
    """Provides decryption keys for secure fulfillment (Internal v46 logic)."""
    from agent.subscription_manager import SUBSCRIPTION_CORE
    if not SUBSCRIPTION_CORE.is_active(x_api_key):
        raise HTTPException(status_code=403, detail="CDB: Enterprise Access Required")
    manifest_path = "data/vault/vault_manifest.json"
    if os.path.exists(manifest_path):
        with open(manifest_path, "r") as f:
            manifest = json.load(f)
            return {"key": manifest.get(x_api_key, {}).get("key")}
    raise HTTPException(status_code=404, detail="No active delivery sessions.")


# ═══════════════════════════════════════════════════════════════════════════════
# ENTERPRISE ADDITIONS v47.0 — ALL ADDITIVE, ZERO BREAKING CHANGES
# ═══════════════════════════════════════════════════════════════════════════════

# ── Health & Readiness Endpoints ──────────────────────────────────────────────

@app.get("/api/v1/health", tags=["Platform"], include_in_schema=False)
async def health_check():
    """
    Liveness probe — returns 200 when the process is alive.
    Used by: Docker HEALTHCHECK, Railway, Kubernetes liveness probe.
    """
    return {
        "status":  "ok",
        "version": VERSION,
        "ts":      int(time.time()),
    }


@app.get("/api/v1/ready", tags=["Platform"], include_in_schema=False)
async def readiness_check():
    """
    Readiness probe — returns 200 when all critical dependencies are reachable.
    Returns 503 if Redis unavailable (when REDIS_URL is configured).
    Used by: Kubernetes readiness probe, Railway health checks.
    """
    checks = {"api": "ok"}
    status_code = 200

    redis_url = os.environ.get("REDIS_URL", "")
    if redis_url:
        try:
            import redis as _redis
            r = _redis.from_url(redis_url, socket_timeout=1)
            r.ping()
            checks["redis"] = "ok"
        except Exception as e:
            checks["redis"] = f"unavailable: {e}"
            status_code = 503

    payload = {
        "status":  "ready" if status_code == 200 else "not_ready",
        "checks":  checks,
        "version": VERSION,
        "ts":      int(time.time()),
    }

    # Update health metrics
    try:
        from agent.telemetry.metrics import update_health_metrics
        for component, result in checks.items():
            update_health_metrics(component, "ok" if result == "ok" else "error")
    except Exception:
        pass

    return Response(
        content=json.dumps(payload),
        status_code=status_code,
        media_type="application/json",
    )


@app.get("/api/v1/version", tags=["Platform"])
async def get_version():
    """Platform version and build information."""
    return {
        "version":     VERSION,
        "authority":   AUTHORITY,
        "platform":    "CYBERDUDEBIVASH-SENTINEL-APEX",
        "env":         _CDB_ENV,
        "api_version": "v1",
        "features": {
            "metrics":      _METRICS_ENABLED,
            "tracing":      _TRACING_ENABLED,
            "rbac":         _RBAC_ENABLED,
            "multi_tenant": _MULTI_TENANT_ENABLED,
            "audit":        _AUDIT_ENABLED,
        },
    }


# ── OIDC Discovery Endpoints ──────────────────────────────────────────────────
# Enables SIEM federation, Okta/Auth0 integration, and JWT validation by
# external clients without hardcoding the public key.

@app.get("/.well-known/openid-configuration", tags=["Security"], include_in_schema=False)
async def openid_configuration(request: Request):
    """
    OpenID Connect Discovery Document.
    Allows SIEM tools and enterprise SSO to auto-configure JWT validation.
    """
    base_url = str(request.base_url).rstrip("/")
    return {
        "issuer":                                base_url,
        "jwks_uri":                              f"{base_url}/.well-known/jwks.json",
        "token_endpoint":                        f"{base_url}/api/v1/auth/token",
        "authorization_endpoint":                f"{base_url}/api/v1/auth/authorize",
        "response_types_supported":              ["token"],
        "subject_types_supported":               ["public"],
        "id_token_signing_alg_values_supported": ["RS256", "HS256"],
        "scopes_supported":                      ["openid", "profile", "intel:read", "intel:export"],
        "claims_supported":                      ["sub", "iss", "iat", "exp", "jti", "tier", "org_id", "role"],
        "token_endpoint_auth_methods_supported": ["client_secret_post", "client_secret_basic"],
    }


@app.get("/.well-known/jwks.json", tags=["Security"], include_in_schema=False)
async def jwks_endpoint():
    """
    JSON Web Key Set — exposes RSA public key for JWT signature verification.
    External clients (SIEM, Splunk, Elastic) use this to verify issued JWTs
    without needing a shared secret.
    """
    try:
        from agent.api.auth_v2 import auth_handler_v2
        return {"keys": [auth_handler_v2.get_jwks()]}
    except Exception:
        # Auth v2 not initialised — return empty JWKS (RS256 not configured)
        return {"keys": []}


# ── Startup Event (preserved + extended) ─────────────────────────────────────

@app.on_event("startup")
async def startup_event():
    # Original startup output — preserved exactly
    print(f"✅ CDB SENTINEL APEX v{VERSION}: ONLINE")
    print(f"🔐 DELIVERY VAULT: ACTIVE")
    print(f"💰 REVENUE ENGINE: MONITORING MRR")
    print(f"Authority: {AUTHORITY}")

    # ── ACCESS GOVERNANCE v173.0 STARTUP VALIDATION ──────────────────────────
    # Run policy self-checks at startup. If any check fails, log a CRITICAL
    # alert. The platform starts but the ops team is immediately notified.
    # A hard crash is avoided to preserve availability, but the CI deployment
    # gate (deployment_gate.py) will have already blocked bad code from shipping.
    policy_result = run_policy_checks()
    if policy_result["passed"]:
        logger.info(
            "[ACCESS-GOVERNANCE] Policy startup checks PASSED",
            extra={
                "policy_version":  POLICY_CANONICAL_VERSION,
                "checks_passed":   policy_result["checks_passed"],
                "total_checks":    policy_result["total_checks"],
                "model_c_active":  True,
                "model_a_disabled":True,
                "model_b_disabled":True,
            }
        )
        print(f"🛡️  ACCESS GOVERNANCE: POLICY v{POLICY_CANONICAL_VERSION} — ALL {policy_result['total_checks']} CHECKS PASSED")
    else:
        failed = [k for k, v in policy_result["checks"].items() if not v["passed"]]
        logger.critical(
            "[ACCESS-GOVERNANCE] POLICY STARTUP CHECK FAILED — COMMERCIAL ACCESS AT RISK",
            extra={"failed_checks": failed, "policy_version": POLICY_CANONICAL_VERSION}
        )
        print(f"🚨 ACCESS GOVERNANCE FAILURE: {len(failed)} checks failed — {failed}")

    # Persist startup audit snapshot
    try:
        import os, json
        os.makedirs("reports", exist_ok=True)
        audit = generate_audit_record()
        with open("reports/access_policy_audit.json", "w") as _af:
            json.dump(audit, _af, indent=2)
        logger.info("[ACCESS-GOVERNANCE] Audit snapshot written to reports/access_policy_audit.json")
    except Exception as _ae:
        logger.warning(f"[ACCESS-GOVERNANCE] Audit snapshot write failed: {_ae}")
    # ── END ACCESS GOVERNANCE STARTUP ──────────────────────────────────────────

    # Enterprise extensions — structured log for Railway/Docker log aggregator
    logger.info(
        "[STARTUP] SENTINEL APEX initialised",
        extra={
            "version":      VERSION,
            "env":          _CDB_ENV,
            "metrics":      _METRICS_ENABLED,
            "tracing":      _TRACING_ENABLED,
            "rbac":         _RBAC_ENABLED,
            "multi_tenant": _MULTI_TENANT_ENABLED,
            "audit":        _AUDIT_ENABLED,
            "cors_origins": len(_ALLOWED_ORIGINS),
        }
    )

    # Initialise active feed count metric
    if _METRICS_ENABLED:
        try:
            from agent.telemetry.metrics import _ACTIVE_FEEDS
            from agent.config import RSS_FEEDS
            _ACTIVE_FEEDS.set(len(RSS_FEEDS))
        except Exception:
            pass


# ── Entrypoint ────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(
        app,
        host=API_HOST,
        port=API_PORT,
        proxy_headers=True,
        forwarded_allow_ips="*",
    )
