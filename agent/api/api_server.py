#!/usr/bin/env python3
"""
api_server.py — CYBERDUDEBIVASH® SENTINEL APEX v23.0 ULTRA
PRODUCTION FASTAPI HTTP SERVER

The missing HTTP transport layer that exposes the existing enterprise_api.py
and public_api.py data modules as live REST endpoints.

Architecture:
  FastAPI app  →  auth_handler (api/auth.py)  →  rate_limiter (api/rate_limiter.py)
                →  PublicAPIHandler / EnterpriseAPIHandler
                →  feed_manifest.json + STIX bundles

Tier Routing:
  /api/v1/*              → Free tier (public, rate-limited)
  /api/v1/pro/*          → PRO tier (API key required)
  /api/v1/enterprise/*   → ENTERPRISE tier (API key required)

Non-Breaking Contract:
  - Does NOT import or modify sentinel_blogger.py
  - Does NOT modify risk_engine.py, enricher.py, export_stix.py
  - Does NOT modify any existing module signatures
  - Reads only from data/stix/feed_manifest.json (same source as dashboard)
  - All existing GitHub Actions workflows unchanged

Deploy:
  pip install fastapi uvicorn[standard]
  uvicorn agent.api.api_server:app --host 0.0.0.0 --port 8080
  # OR via Docker: see Dockerfile.api

Endpoint Summary:
  GET  /                               → Health + version banner
  GET  /api/v1/health                  → Platform health check
  GET  /api/v1/stats                   → Public statistics
  GET  /api/v1/threats                 → Latest 10 threats (free tier)
  GET  /api/v1/feed                    → Public manifest feed
  GET  /api/v1/threat/{id}             → Single threat summary
  GET  /api/v1/pro/threats             → Full threat list (PRO)
  GET  /api/v1/pro/iocs                → IOC export (PRO)
  GET  /api/v1/pro/detections          → Detection rules feed (PRO)
  GET  /api/v1/enterprise/threats      → Full threat intelligence (ENTERPRISE)
  GET  /api/v1/enterprise/stix/{id}    → STIX 2.1 bundle (ENTERPRISE)
  GET  /api/v1/enterprise/actors       → Actor intelligence (ENTERPRISE)
  GET  /api/v1/enterprise/campaigns    → Active campaigns (ENTERPRISE)
  GET  /api/v1/enterprise/forecast/{id}→ Exploit forecast (ENTERPRISE)
  GET  /api/v1/enterprise/metrics      → Platform metrics (ENTERPRISE)
  POST /api/v1/enterprise/search       → Full-text search (ENTERPRISE)
  GET  /api/v1/enterprise/supply-chain → Supply chain intel (ENTERPRISE)
  GET  /api/v1/enterprise/epss         → EPSS enrichment (ENTERPRISE)
  GET  /api/v1/enterprise/risk-trend   → Risk trend analytics (ENTERPRISE)
  POST /api/v1/enterprise/forecast/batch → Batch exploit forecasting (ENTERPRISE)
  POST /api/v1/auth/token              → Generate JWT (authenticated keys)
  GET  /api/v1/taxii/collections       → TAXII 2.1 collection listing
  GET  /api/v1/taxii/collections/{id}/objects → TAXII object fetch (ENTERPRISE)
"""

import os
import json
import time
import uuid
import logging
from typing import Optional, Dict, Any

logger = logging.getLogger("CDB-API-SERVER")

# ── Graceful FastAPI import (not a hard dependency for the pipeline) ──
try:
    from fastapi import FastAPI, Request, HTTPException, Header, Depends, Body
    from fastapi.responses import JSONResponse
    from fastapi.middleware.cors import CORSMiddleware
    from fastapi.middleware.gzip import GZipMiddleware
    _FASTAPI_AVAILABLE = True
except ImportError:
    _FASTAPI_AVAILABLE = False
    logger.warning(
        "FastAPI not installed. Run: pip install fastapi uvicorn[standard]\n"
        "API server will not start. Existing pipeline is unaffected."
    )

from agent.api.auth import auth_handler, TIER_FREE, TIER_PRO, TIER_ENTERPRISE
from agent.api.rate_limiter import rate_limiter
from agent.api.public_api import PublicAPIHandler
from agent.api.enterprise_api import EnterpriseAPIHandler
from agent.core.metrics import platform_metrics

# ─────────────────────────────────────────────────────────────
# Application Bootstrap
# ─────────────────────────────────────────────────────────────

PLATFORM_VERSION = "v23.0"
MANIFEST_PATH    = "data/stix/feed_manifest.json"

if _FASTAPI_AVAILABLE:
    app = FastAPI(
        title="CyberDudeBivash SENTINEL APEX API",
        description=(
            "CYBERDUDEBIVASH® Sentinel APEX — AI-Powered Global Threat Intelligence REST API.\n\n"
            "**Authentication:** Pass your API key as `X-CDB-API-Key` header.\n\n"
            "**Tiers:** FREE (public) · PRO ($19/kit) · ENTERPRISE (contact us)\n\n"
            "**Get your API key:** [cyberdudebivash.gumroad.com](https://cyberdudebivash.gumroad.com)"
        ),
        version=PLATFORM_VERSION,
        docs_url="/docs",
        redoc_url="/redoc",
        openapi_url="/openapi.json",
    )

    # ── CORS — allow all origins for public API, restrict enterprise in production ──
    app.add_middleware(
        CORSMiddleware,
        allow_origins=["*"],
        allow_credentials=True,
        allow_methods=["GET", "POST", "OPTIONS"],
        allow_headers=["*"],
    )

    # ── GZip for large STIX bundles ──
    app.add_middleware(GZipMiddleware, minimum_size=1024)

    # ─────────────────────────────────────────────────────────
    # Handlers (singleton per process)
    # ─────────────────────────────────────────────────────────
    _public_api    = PublicAPIHandler()
    _enterprise_api = EnterpriseAPIHandler()

    # ─────────────────────────────────────────────────────────
    # Request Middleware — latency logging + request ID injection
    # ─────────────────────────────────────────────────────────

    @app.middleware("http")
    async def request_telemetry(request: Request, call_next):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())[:8]
        request.state.req_id = req_id
        request.state.t0 = t0
        response = await call_next(request)
        latency = round((time.monotonic() - t0) * 1000, 2)
        response.headers["X-Request-ID"] = req_id
        response.headers["X-Latency-Ms"] = str(latency)
        response.headers["X-Platform"]   = "CDB-SENTINEL-APEX"
        logger.info(
            f"[{req_id}] {request.method} {request.url.path} "
            f"→ {response.status_code} ({latency}ms)"
        )
        return response

    # ─────────────────────────────────────────────────────────
    # Auth Dependency
    # ─────────────────────────────────────────────────────────

    async def resolve_credentials(
        request: Request,
        x_cdb_api_key: Optional[str] = Header(default=None),
        authorization: Optional[str] = Header(default=None),
    ) -> Dict:
        """
        Dependency that resolves tier + identity from headers.
        Returns: {"tier": str, "identity": str, "remote_ip": str}
        """
        bearer = None
        if authorization and authorization.startswith("Bearer "):
            bearer = authorization[7:]

        remote_ip = request.client.host if request.client else "unknown"
        tier, identity, error = auth_handler.resolve_tier(
            api_key=x_cdb_api_key,
            bearer=bearer,
            remote_ip=remote_ip,
        )
        return {"tier": tier, "identity": identity, "remote_ip": remote_ip}

    def require_tier(required: str):
        """Factory: returns a FastAPI dependency that enforces minimum tier."""
        async def _dep(
            creds: Dict = Depends(resolve_credentials),
            x_cdb_api_key: Optional[str] = Header(default=None),
        ):
            tier = creds["tier"]
            if not auth_handler.tier_allows(tier, required):
                raise HTTPException(
                    status_code=403,
                    detail={
                        "error": "TIER_INSUFFICIENT",
                        "your_tier": tier,
                        "required_tier": required,
                        "upgrade_url": "https://cyberdudebivash.gumroad.com",
                        "contact": "bivash@cyberdudebivash.com",
                        "message": (
                            f"This endpoint requires {required} tier. "
                            f"Your current tier: {tier}. "
                            "Upgrade at cyberdudebivash.gumroad.com"
                        ),
                    }
                )
            return creds
        return _dep

    # ─────────────────────────────────────────────────────────
    # ROOT & HEALTH
    # ─────────────────────────────────────────────────────────

    @app.get("/", tags=["Platform"])
    async def root():
        """Platform banner and API navigation."""
        return {
            "platform": "CYBERDUDEBIVASH® SENTINEL APEX",
            "version": PLATFORM_VERSION,
            "status": "OPERATIONAL",
            "api_base": "/api/v1",
            "documentation": "/docs",
            "tiers": {
                "FREE": {
                    "base_url": "/api/v1",
                    "rate_limit": "60 req/min",
                    "auth": "None required",
                },
                "PRO": {
                    "base_url": "/api/v1/pro",
                    "rate_limit": "300 req/min",
                    "auth": "X-CDB-API-Key header",
                    "purchase": "https://cyberdudebivash.gumroad.com",
                },
                "ENTERPRISE": {
                    "base_url": "/api/v1/enterprise",
                    "rate_limit": "1000 req/min",
                    "auth": "X-CDB-API-Key header or JWT Bearer",
                    "contact": "bivash@cyberdudebivash.com",
                },
            },
            "links": {
                "dashboard": "https://intel.cyberdudebivash.com",
                "blog":      "https://cyberbivash.blogspot.com",
                "gumroad":   "https://cyberdudebivash.gumroad.com",
                "website":   "https://cyberdudebivash.com",
            },
        }

    @app.get("/api/v1/health", tags=["Free Tier"])
    async def health_check(creds: Dict = Depends(resolve_credentials)):
        """Platform health status. Open to all tiers."""
        return _public_api.get_platform_health(identity=creds["identity"])

    @app.get("/api/v1/stats", tags=["Free Tier"])
    async def public_stats(creds: Dict = Depends(resolve_credentials)):
        """Platform statistics including KEV count and EPSS averages."""
        return _public_api.get_public_stats(identity=creds["identity"])

    # ─────────────────────────────────────────────────────────
    # FREE TIER ENDPOINTS
    # ─────────────────────────────────────────────────────────

    @app.get("/api/v1/threats", tags=["Free Tier"])
    async def get_public_threats(creds: Dict = Depends(resolve_credentials)):
        """
        Latest 10 threat advisories (IOC details stripped).
        Free tier — no API key required.
        """
        return _public_api.get_latest_threats(identity=creds["identity"])

    @app.get("/api/v1/feed", tags=["Free Tier"])
    async def get_public_feed(creds: Dict = Depends(resolve_credentials)):
        """Public threat feed manifest with limited metadata."""
        return _public_api.get_public_feed(identity=creds["identity"])

    @app.get("/api/v1/threat/{threat_id}", tags=["Free Tier"])
    async def get_single_threat(
        threat_id: str,
        creds: Dict = Depends(resolve_credentials),
    ):
        """Single threat summary by ID (no IOC detail — use enterprise for full data)."""
        result = _public_api.get_threat_summary(
            threat_id=threat_id,
            identity=creds["identity"],
        )
        if not result:
            raise HTTPException(status_code=404, detail={"error": "THREAT_NOT_FOUND", "id": threat_id})
        return result

    # ─────────────────────────────────────────────────────────
    # PRO TIER ENDPOINTS
    # ─────────────────────────────────────────────────────────

    @app.get("/api/v1/pro/threats", tags=["Pro Tier"])
    async def pro_get_threats(
        limit: int = 50,
        creds: Dict = Depends(require_tier(TIER_PRO)),
    ):
        """
        Full threat list with extended metadata (PRO tier).
        Includes: severity, TLP, MITRE tactics, actor tags, CVSS/EPSS scores.
        Requires PRO API key (X-CDB-API-Key header).
        Get your key: https://cyberdudebivash.gumroad.com
        """
        return _enterprise_api.get_all_threats(
            limit=min(limit, 100),
            include_archived=False,
            identity=creds["identity"],
            tier=TIER_PRO,
        )

    @app.get("/api/v1/pro/iocs", tags=["Pro Tier"])
    async def pro_get_iocs(
        limit: int = 50,
        creds: Dict = Depends(require_tier(TIER_PRO)),
    ):
        """
        IOC export feed — all extracted indicators (IPs, domains, hashes, URLs, CVEs).
        PRO tier. Suitable for SIEM ingestion.
        """
        return _enterprise_api.get_ioc_feed(
            limit=min(limit, 200),
            identity=creds["identity"],
            tier=TIER_PRO,
        )

    @app.get("/api/v1/pro/detections", tags=["Pro Tier"])
    async def pro_get_detections(creds: Dict = Depends(require_tier(TIER_PRO))):
        """
        Detection rules feed: Sigma, YARA, KQL, Suricata, SPL rules (PRO tier).
        Ready for direct import into your SIEM/EDR.
        """
        return _enterprise_api.get_detection_rules(
            identity=creds["identity"],
            tier=TIER_PRO,
        )

    # ─────────────────────────────────────────────────────────
    # ENTERPRISE TIER ENDPOINTS
    # ─────────────────────────────────────────────────────────

    @app.get("/api/v1/enterprise/threats", tags=["Enterprise Tier"])
    async def enterprise_get_threats(
        limit: int = 100,
        include_archived: bool = False,
        creds: Dict = Depends(require_tier(TIER_ENTERPRISE)),
    ):
        """
        Full threat intelligence with complete IOC details (ENTERPRISE tier).
        Includes: full IOCs, STIX IDs, EPSS, KEV status, actor attribution,
        extended metrics, exploit velocity, predictive risk delta.
        """
        return _enterprise_api.get_all_threats(
            limit=min(limit, 500),
            include_archived=include_archived,
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    @app.get("/api/v1/enterprise/stix/{bundle_id}", tags=["Enterprise Tier"])
    async def enterprise_get_stix(
        bundle_id: str,
        creds: Dict = Depends(require_tier(TIER_ENTERPRISE)),
    ):
        """
        Full STIX 2.1 bundle by ID (ENTERPRISE tier).
        Suitable for TAXII server ingestion, MISP import, or SIEM enrichment.
        """
        bundle = _enterprise_api.get_stix_bundle(
            bundle_id=bundle_id,
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )
        if not bundle:
            raise HTTPException(status_code=404, detail={"error": "STIX_BUNDLE_NOT_FOUND", "id": bundle_id})
        return bundle

    @app.get("/api/v1/enterprise/actors", tags=["Enterprise Tier"])
    async def enterprise_get_actors(creds: Dict = Depends(require_tier(TIER_ENTERPRISE))):
        """Actor intelligence registry — APT groups, nation-state actors, attribution data."""
        return _enterprise_api.get_actor_intelligence(
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    @app.get("/api/v1/enterprise/campaigns", tags=["Enterprise Tier"])
    async def enterprise_get_campaigns(creds: Dict = Depends(require_tier(TIER_ENTERPRISE))):
        """Active threat campaign tracking with IOC clusters."""
        return _enterprise_api.get_campaign_data(
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    @app.get("/api/v1/enterprise/forecast/{threat_id}", tags=["Enterprise Tier"])
    async def enterprise_get_forecast(
        threat_id: str,
        creds: Dict = Depends(require_tier(TIER_ENTERPRISE)),
    ):
        """Exploit probability forecast for a specific threat (ENTERPRISE tier)."""
        return _enterprise_api.get_exploit_forecast(
            threat_id=threat_id,
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    @app.get("/api/v1/enterprise/metrics", tags=["Enterprise Tier"])
    async def enterprise_get_metrics(creds: Dict = Depends(require_tier(TIER_ENTERPRISE))):
        """Platform telemetry metrics — pipeline performance, IOC throughput, feed reliability."""
        return _enterprise_api.get_platform_metrics(
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    @app.get("/api/v1/enterprise/archive", tags=["Enterprise Tier"])
    async def enterprise_get_archive(creds: Dict = Depends(require_tier(TIER_ENTERPRISE))):
        """Full archived threat intelligence history (ENTERPRISE tier)."""
        return _enterprise_api.get_archive_list(
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    @app.post("/api/v1/enterprise/search", tags=["Enterprise Tier"])
    async def enterprise_search(
        body: Dict = Body(..., example={"query": "ransomware", "severity": "CRITICAL", "actor": "APT28"}),
        creds: Dict = Depends(require_tier(TIER_ENTERPRISE)),
    ):
        """
        Full-text + filtered threat intelligence search (ENTERPRISE tier).
        Filter by: query text, severity, actor, CVE, MITRE technique, TLP.
        """
        return _enterprise_api.search_threats(
            query=body.get("query", ""),
            filters=body,
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    @app.get("/api/v1/enterprise/supply-chain", tags=["Enterprise Tier"])
    async def enterprise_supply_chain(creds: Dict = Depends(require_tier(TIER_ENTERPRISE))):
        """Supply chain attack intelligence feed — compromised packages, build pipeline threats."""
        return _enterprise_api.get_supply_chain_intel(
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    @app.get("/api/v1/enterprise/epss", tags=["Enterprise Tier"])
    async def enterprise_epss(
        cve_ids: str = "",
        creds: Dict = Depends(require_tier(TIER_ENTERPRISE)),
    ):
        """
        Bulk EPSS score enrichment for CVE IDs (ENTERPRISE tier).
        Pass comma-separated CVE IDs: ?cve_ids=CVE-2024-1234,CVE-2024-5678
        """
        cve_list = [c.strip() for c in cve_ids.split(",") if c.strip()]
        return _enterprise_api.get_epss_enrichment(
            cve_ids=cve_list,
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    @app.get("/api/v1/enterprise/risk-trend", tags=["Enterprise Tier"])
    async def enterprise_risk_trend(
        window_hours: int = 168,
        creds: Dict = Depends(require_tier(TIER_ENTERPRISE)),
    ):
        """Risk trend analysis over a configurable rolling window (default: 7 days)."""
        return _enterprise_api.get_risk_trend(
            window_hours=min(window_hours, 720),
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    @app.post("/api/v1/enterprise/forecast/batch", tags=["Enterprise Tier"])
    async def enterprise_batch_forecast(
        body: Dict = Body(..., example={"threat_ids": ["bundle--abc", "bundle--def"]}),
        creds: Dict = Depends(require_tier(TIER_ENTERPRISE)),
    ):
        """Batch exploit probability forecasting for multiple threats."""
        return _enterprise_api.get_batch_forecast(
            threat_ids=body.get("threat_ids", []),
            identity=creds["identity"],
            tier=TIER_ENTERPRISE,
        )

    # ─────────────────────────────────────────────────────────
    # AUTH ENDPOINT — JWT generation for authenticated keys
    # ─────────────────────────────────────────────────────────

    @app.post("/api/v1/auth/token", tags=["Authentication"])
    async def generate_token(
        x_cdb_api_key: Optional[str] = Header(default=None),
        request: Request = None,
    ):
        """
        Exchange an API key for a JWT bearer token (24hr expiry).
        Pass your API key in X-CDB-API-Key header.
        The JWT can then be used as: Authorization: Bearer <token>
        """
        if not x_cdb_api_key:
            raise HTTPException(
                status_code=401,
                detail={
                    "error": "API_KEY_REQUIRED",
                    "message": "Pass your API key in X-CDB-API-Key header",
                    "get_key": "https://cyberdudebivash.gumroad.com",
                }
            )
        remote_ip = request.client.host if request.client else "unknown"
        tier, identity, _ = auth_handler.resolve_tier(
            api_key=x_cdb_api_key, remote_ip=remote_ip
        )
        if tier == TIER_FREE and x_cdb_api_key:
            raise HTTPException(
                status_code=403,
                detail={
                    "error": "INVALID_API_KEY",
                    "message": "API key not recognized. Get your key at cyberdudebivash.gumroad.com",
                    "upgrade": "https://cyberdudebivash.gumroad.com",
                }
            )
        token = auth_handler.generate_jwt(identity=identity, tier=tier)
        return {
            "access_token": token,
            "token_type": "bearer",
            "tier": tier,
            "identity": identity,
            "expires_in_seconds": 86400,
            "usage": "Authorization: Bearer <token>",
        }

    # ─────────────────────────────────────────────────────────
    # TAXII 2.1 ENDPOINTS — Enterprise STIX/TAXII feed hosting
    # ─────────────────────────────────────────────────────────

    @app.get("/api/v1/taxii/collections", tags=["TAXII 2.1"])
    async def taxii_collections(creds: Dict = Depends(resolve_credentials)):
        """
        TAXII 2.1 collection listing.
        Free tier: collection metadata only.
        Enterprise tier: full object counts and access URLs.
        """
        collections = [
            {
                "id":          "cdb-daily-threat-feed",
                "title":       "CDB Daily Threat Intelligence Feed",
                "description": "AI-enriched daily threat advisories with IOCs, MITRE mapping, and risk scoring.",
                "can_read":    True,
                "can_write":   False,
                "media_types": ["application/stix+json;version=2.1"],
                "tier_required": "ENTERPRISE",
            },
            {
                "id":          "cdb-cve-intelligence",
                "title":       "CDB CVE Intelligence Feed",
                "description": "High-priority CVEs with EPSS scores, KEV status, and exploit forecasting.",
                "can_read":    True,
                "can_write":   False,
                "media_types": ["application/stix+json;version=2.1"],
                "tier_required": "PRO",
            },
            {
                "id":          "cdb-ioc-feed",
                "title":       "CDB IOC Feed",
                "description": "Structured IOC feed: IPs, domains, hashes, URLs, CVEs.",
                "can_read":    True,
                "can_write":   False,
                "media_types": ["application/stix+json;version=2.1"],
                "tier_required": "PRO",
            },
        ]
        return {
            "taxii_version": "2.1",
            "platform": "CyberDudeBivash SENTINEL APEX",
            "collections": collections,
            "access_note": (
                f"Your tier: {creds['tier']}. "
                "PRO/Enterprise access: cyberdudebivash.gumroad.com"
            ),
        }

    @app.get(
        "/api/v1/taxii/collections/{collection_id}/objects",
        tags=["TAXII 2.1"],
    )
    async def taxii_get_objects(
        collection_id: str,
        limit: int = 20,
        creds: Dict = Depends(require_tier(TIER_ENTERPRISE)),
    ):
        """
        TAXII 2.1 object fetch for a collection (ENTERPRISE tier).
        Returns STIX 2.1 bundle objects in TAXII envelope format.
        """
        # Load manifest and return as TAXII envelope
        try:
            if not os.path.exists(MANIFEST_PATH):
                raise HTTPException(status_code=503, detail={"error": "MANIFEST_UNAVAILABLE"})

            with open(MANIFEST_PATH, "r") as f:
                entries = json.load(f)

            active = [e for e in entries if e.get("status") != "archived"]
            selected = sorted(
                active,
                key=lambda x: x.get("generated_at", ""),
                reverse=True
            )[:min(limit, 100)]

            return {
                "taxii_version": "2.1",
                "collection_id": collection_id,
                "date_added_first": selected[-1].get("timestamp") if selected else None,
                "date_added_last":  selected[0].get("timestamp") if selected else None,
                "objects": selected,
                "more":    len(active) > min(limit, 100),
            }
        except Exception as e:
            logger.error(f"TAXII fetch error: {e}")
            raise HTTPException(status_code=500, detail={"error": "TAXII_FETCH_ERROR"})

    # ─────────────────────────────────────────────────────────
    # WEBHOOK — Stripe payment event receiver (async, non-blocking)
    # ─────────────────────────────────────────────────────────

    @app.post("/api/v1/webhooks/stripe", tags=["Billing"], include_in_schema=False)
    async def stripe_webhook(request: Request):
        """
        Stripe webhook endpoint for subscription lifecycle events.
        Configure in Stripe Dashboard: POST https://your-api-domain/api/v1/webhooks/stripe
        """
        try:
            payload = await request.body()
            sig_header = request.headers.get("stripe-signature", "")

            # Delegate to stripe_gateway module
            from agent.api.stripe_gateway import stripe_gateway
            result = stripe_gateway.handle_webhook(
                payload=payload,
                sig_header=sig_header,
            )
            return result
        except Exception as e:
            logger.error(f"Stripe webhook error: {e}")
            return JSONResponse(status_code=200, content={"received": True})

    # ─────────────────────────────────────────────────────────
    # GLOBAL EXCEPTION HANDLER
    # ─────────────────────────────────────────────────────────

    @app.exception_handler(Exception)
    async def global_exception_handler(request: Request, exc: Exception):
        logger.error(f"Unhandled error at {request.url.path}: {exc}", exc_info=True)
        return JSONResponse(
            status_code=500,
            content={
                "error": "INTERNAL_SERVER_ERROR",
                "message": "An unexpected error occurred. Contact bivash@cyberdudebivash.com",
                "request_id": getattr(request.state, "req_id", "unknown"),
            },
        )

else:
    # FastAPI not installed — create a stub so imports don't fail
    class _AppStub:
        def __getattr__(self, name):
            def _noop(*args, **kwargs):
                logger.warning(f"API server not available: FastAPI not installed. pip install fastapi uvicorn[standard]")
            return _noop

    app = _AppStub()


# ─────────────────────────────────────────────────────────────────────────────
# Entrypoint (for direct execution)
# ─────────────────────────────────────────────────────────────────────────────

if __name__ == "__main__":
    if not _FASTAPI_AVAILABLE:
        print("❌ FastAPI not installed. Run: pip install fastapi uvicorn[standard]")
        exit(1)

    import uvicorn  # type: ignore

    host = os.environ.get("API_HOST", "0.0.0.0")
    port = int(os.environ.get("API_PORT", "8080"))
    workers = int(os.environ.get("API_WORKERS", "2"))

    print(f"""
╔═══════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX API SERVER                ║
║  Version: {PLATFORM_VERSION}                                      ║
║  Host:    {host}:{port}                                   ║
║  Docs:    http://{host}:{port}/docs                       ║
╚═══════════════════════════════════════════════════════════╝
    """)

    uvicorn.run(
        "agent.api.api_server:app",
        host=host,
        port=port,
        workers=workers,
        log_level="info",
        access_log=True,
        reload=False,
    )
