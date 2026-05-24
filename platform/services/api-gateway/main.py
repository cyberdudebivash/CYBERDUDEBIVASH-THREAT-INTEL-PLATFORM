"""
SENTINEL APEX API GATEWAY v2.0
================================
Production-grade FastAPI gateway with:
- JWT/OIDC authentication (Keycloak)
- Multi-tenant RBAC/ABAC enforcement
- API key management + usage metering
- Rate limiting (Redis sliding window)
- Request signing + replay protection
- OpenTelemetry distributed tracing
- Zero Trust enforcement
- Tier gating (FREE/PRO/ENTERPRISE/GOVERNMENT)
"""
from __future__ import annotations

import asyncio
import hashlib
import hmac
import time
import uuid
from contextlib import asynccontextmanager
from typing import Annotated, Any, Optional

import structlog
from fastapi import Depends, FastAPI, Header, HTTPException, Request, Response, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse
from opentelemetry import trace
from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from opentelemetry.sdk.resources import SERVICE_NAME, Resource
from opentelemetry.sdk.trace import TracerProvider
from opentelemetry.sdk.trace.export import BatchSpanProcessor
from prometheus_fastapi_instrumentator import Instrumentator

from .auth import AuthService, CurrentUser, JWTPayload, verify_api_key, verify_jwt
from .config import GatewayConfig
from .middleware import (
    RateLimitMiddleware,
    RequestIDMiddleware,
    SecurityHeadersMiddleware,
    TenantContextMiddleware,
    ZeroTrustMiddleware,
)
from .proxy import IntelligenceProxy
from .quota import QuotaEnforcer
from .router import build_router
from .telemetry import setup_telemetry

log = structlog.get_logger("sentinel.gateway")

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------
config = GatewayConfig()

# ---------------------------------------------------------------------------
# OpenTelemetry Setup
# ---------------------------------------------------------------------------
def setup_otel() -> None:
    resource = Resource(attributes={SERVICE_NAME: "sentinel-apex-api-gateway"})
    provider = TracerProvider(resource=resource)
    exporter = OTLPSpanExporter(endpoint=config.otel_endpoint)
    provider.add_span_processor(BatchSpanProcessor(exporter))
    trace.set_tracer_provider(provider)

# ---------------------------------------------------------------------------
# Lifespan
# ---------------------------------------------------------------------------
@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("sentinel.gateway.startup", version="2.0", env=config.env)
    setup_otel()
    await AuthService.initialize(config)
    await QuotaEnforcer.initialize(config)
    await IntelligenceProxy.initialize(config)
    yield
    log.info("sentinel.gateway.shutdown")
    await AuthService.close()
    await QuotaEnforcer.close()
    await IntelligenceProxy.close()

# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------
app = FastAPI(
    title="SENTINEL APEX API Gateway",
    description="AI-Native Cyber Intelligence Infrastructure — Enterprise API Gateway",
    version="2.0.0",
    docs_url="/docs" if config.env != "production" else None,
    redoc_url="/redoc" if config.env != "production" else None,
    openapi_url="/openapi.json" if config.env != "production" else None,
    lifespan=lifespan,
)

# ---------------------------------------------------------------------------
# Middleware Stack (order matters — outer to inner)
# ---------------------------------------------------------------------------
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestIDMiddleware)
app.add_middleware(ZeroTrustMiddleware, config=config)
app.add_middleware(TenantContextMiddleware, config=config)
app.add_middleware(
    RateLimitMiddleware,
    redis_url=config.redis_url,
    limits={
        "free": {"requests_per_minute": 60, "requests_per_day": 500},
        "pro": {"requests_per_minute": 300, "requests_per_day": 10000},
        "enterprise": {"requests_per_minute": 3000, "requests_per_day": 500000},
        "government": {"requests_per_minute": 10000, "requests_per_day": 5000000},
    },
)
app.add_middleware(GZipMiddleware, minimum_size=1000)
app.add_middleware(
    CORSMiddleware,
    allow_origins=config.allowed_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "DELETE", "PATCH", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=["X-Request-ID", "X-RateLimit-Remaining", "X-RateLimit-Reset"],
)

# ---------------------------------------------------------------------------
# Prometheus Instrumentation
# ---------------------------------------------------------------------------
Instrumentator(
    should_group_status_codes=False,
    should_ignore_untemplated=True,
    excluded_handlers=["/health", "/metrics"],
).instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

# ---------------------------------------------------------------------------
# FastAPI OTel Instrumentation
# ---------------------------------------------------------------------------
FastAPIInstrumentor.instrument_app(app)

# ---------------------------------------------------------------------------
# Health + Readiness
# ---------------------------------------------------------------------------
@app.get("/health", include_in_schema=False)
async def health() -> dict:
    return {"status": "ok", "service": "api-gateway", "version": "2.0.0"}

@app.get("/readiness", include_in_schema=False)
async def readiness() -> dict:
    checks = {
        "auth": await AuthService.health_check(),
        "quota": await QuotaEnforcer.health_check(),
        "proxy": await IntelligenceProxy.health_check(),
    }
    all_ok = all(v["status"] == "ok" for v in checks.values())
    return {"status": "ok" if all_ok else "degraded", "checks": checks}

# ---------------------------------------------------------------------------
# Intelligence API Routes (proxied to intel-core service)
# ---------------------------------------------------------------------------
router = build_router(config)
app.include_router(router)

# ---------------------------------------------------------------------------
# Global Exception Handlers
# ---------------------------------------------------------------------------
@app.exception_handler(HTTPException)
async def http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    rid = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    log.warning(
        "sentinel.gateway.http_error",
        request_id=rid,
        status_code=exc.status_code,
        detail=exc.detail,
        path=request.url.path,
    )
    return JSONResponse(
        status_code=exc.status_code,
        content={
            "error": exc.detail,
            "request_id": rid,
            "timestamp": time.time(),
        },
        headers={"X-Request-ID": rid},
    )

@app.exception_handler(Exception)
async def generic_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    rid = request.headers.get("X-Request-ID", str(uuid.uuid4()))
    log.error(
        "sentinel.gateway.unhandled_error",
        request_id=rid,
        error=str(exc),
        path=request.url.path,
        exc_info=True,
    )
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "request_id": rid,
            "timestamp": time.time(),
        },
        headers={"X-Request-ID": rid},
    )
