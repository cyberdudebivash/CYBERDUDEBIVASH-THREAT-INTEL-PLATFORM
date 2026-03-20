"""
SENTINEL APEX — API Server
CYBERDUDEBIVASH PVT LTD
Production FastAPI application

Entry point: uvicorn app.main:app
"""
from __future__ import annotations

import logging
import sys
import time
from contextlib import asynccontextmanager
from datetime import datetime, timezone

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.middleware.gzip import GZipMiddleware
from fastapi.responses import JSONResponse

from app.api.v1.endpoints import auth, feed, keys, usage, soc
from app.core.config import get_settings
from app.db.client import close_client
from app.middleware.rate_limit import RateLimitMiddleware

# ── Logging Configuration ─────────────────────────────────────────────

settings = get_settings()

logging.basicConfig(
    level=getattr(logging, settings.LOG_LEVEL.upper(), logging.INFO),
    format="%(asctime)s | %(name)s | %(levelname)s | %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%S",
    stream=sys.stdout,
)
logger = logging.getLogger("sentinel")


# ── Application Lifecycle ─────────────────────────────────────────────

@asynccontextmanager
async def lifespan(app: FastAPI):
    logger.info(f"🛡️  SENTINEL APEX API v{settings.APP_VERSION} starting...")
    logger.info(f"   Environment: {settings.ENVIRONMENT.value}")
    logger.info(f"   Supabase: {settings.SUPABASE_URL[:40]}...")
    logger.info(f"   CORS Origins: {settings.cors_origin_list}")
    yield
    logger.info("Shutting down — closing database connections...")
    await close_client()
    logger.info("SENTINEL APEX API shutdown complete.")


# ── FastAPI Application ───────────────────────────────────────────────

app = FastAPI(
    title="SENTINEL APEX API",
    description=(
        "**CYBERDUDEBIVASH Threat Intelligence Platform API**\n\n"
        "AI-powered cybersecurity intelligence. STIX 2.1 native. Developer-first.\n\n"
        "- **Feed**: Paginated threat advisory feed with severity, CVSS, EPSS, KEV filters\n"
        "- **Search**: Full-text search across all advisories (Pro+)\n"
        "- **STIX**: Download STIX 2.1 bundles per advisory (Pro+)\n"
        "- **MITRE**: ATT&CK technique coverage statistics\n"
        "- **AI Analysis**: LLM-powered threat analysis (Enterprise)\n\n"
        "Get your API key: https://app.cyberdudebivash.com\n\n"
        "Documentation: https://docs.cyberdudebivash.com"
    ),
    version=settings.APP_VERSION,
    docs_url="/docs",
    redoc_url="/redoc",
    openapi_url="/openapi.json",
    lifespan=lifespan,
    license_info={
        "name": "Proprietary",
        "url": "https://cyberdudebivash.com/terms",
    },
    contact={
        "name": "CYBERDUDEBIVASH PVT LTD",
        "url": "https://cyberdudebivash.com",
        "email": "api@cyberdudebivash.com",
    },
)


# ── Middleware Stack (order matters: last added = first executed) ─────

# GZip compression for responses > 1KB
app.add_middleware(GZipMiddleware, minimum_size=1000)

# Rate limiting
app.add_middleware(RateLimitMiddleware)

# CORS
app.add_middleware(
    CORSMiddleware,
    allow_origins=settings.cors_origin_list,
    allow_credentials=True,
    allow_methods=["GET", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"],
    allow_headers=["*"],
    expose_headers=[
        "X-RateLimit-Limit",
        "X-RateLimit-Remaining",
        "X-RateLimit-Reset",
        "X-Request-ID",
    ],
    max_age=3600,
)


# ── Request Logging Middleware ────────────────────────────────────────

@app.middleware("http")
async def log_requests(request: Request, call_next):
    start = time.time()
    request_id = f"{int(start * 1000)}"

    response = await call_next(request)

    elapsed = (time.time() - start) * 1000
    logger.info(
        f"{request.method} {request.url.path} → {response.status_code} "
        f"({elapsed:.1f}ms) [{request.client.host if request.client else '?'}]"
    )

    response.headers["X-Request-ID"] = request_id
    response.headers["X-Response-Time"] = f"{elapsed:.1f}ms"
    response.headers["X-Powered-By"] = "SENTINEL APEX"

    return response


# ── Exception Handlers ────────────────────────────────────────────────

@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    logger.error(f"Unhandled error on {request.method} {request.url.path}: {exc}", exc_info=True)
    return JSONResponse(
        status_code=500,
        content={
            "error": "Internal server error",
            "detail": "An unexpected error occurred. Contact api@cyberdudebivash.com if this persists.",
            "status_code": 500,
        },
    )


# ── Routes ────────────────────────────────────────────────────────────

app.include_router(auth.router)
app.include_router(feed.router)
app.include_router(keys.router)
app.include_router(usage.router)
app.include_router(soc.router)


# ── Root & Health ─────────────────────────────────────────────────────

@app.get("/", tags=["Meta"])
async def root():
    return {
        "platform": "SENTINEL APEX",
        "vendor": "CYBERDUDEBIVASH PVT LTD",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "api_base": "/api/v1",
        "status": "operational",
        "links": {
            "dashboard": "https://intel.cyberdudebivash.com",
            "app": "https://app.cyberdudebivash.com",
            "github": "https://github.com/cyberdudebivash",
            "docs": "https://docs.cyberdudebivash.com",
        },
    }


@app.get("/health", tags=["Meta"])
async def health_check():
    """Health check for monitoring and Railway zero-downtime deploys."""
    services = {"api": "healthy"}

    # Test Supabase connectivity
    try:
        from app.db.client import SupabaseDB
        result = await SupabaseDB.query("tier_config", select="tier", limit=1)
        services["database"] = "healthy" if result["data"] else "degraded"
    except Exception as e:
        services["database"] = f"unhealthy: {e}"

    overall = "healthy" if all(v == "healthy" for v in services.values()) else "degraded"

    return {
        "status": overall,
        "version": settings.APP_VERSION,
        "environment": settings.ENVIRONMENT.value,
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "services": services,
    }
