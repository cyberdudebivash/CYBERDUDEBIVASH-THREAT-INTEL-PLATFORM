"""
CYBERDUDEBIVASH® SENTINEL APEX
APEX API ROUTER v1.0 — FastAPI endpoints for all 12 features
Mounts on /apex/v1/ prefix in main api/main.py
"""
import json
import logging
import os
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-APEX-API")

# ─── Try FastAPI import (graceful degradation if not installed) ───────────────
try:
    from fastapi import FastAPI, HTTPException, Depends, Header, Query
    from fastapi.middleware.cors import CORSMiddleware
    from pydantic import BaseModel
    FASTAPI_AVAILABLE = True
except ImportError:
    FASTAPI_AVAILABLE = False
    logger.warning("[APEX-API] FastAPI not available — API routes disabled")

# ─── Data models ──────────────────────────────────────────────────────────────
if FASTAPI_AVAILABLE:
    class CopilotRequest(BaseModel):
        query: str
        context: Optional[Dict] = None

    class SubscriptionRequest(BaseModel):
        tenant_id: str
        tier: str
        email: Optional[str] = ""

    class ValidateKeyRequest(BaseModel):
        api_key: str
        feature: Optional[str] = ""


def build_apex_router():
    """Build and return the APEX FastAPI router."""
    if not FASTAPI_AVAILABLE:
        return None

    from fastapi import APIRouter
    from agent.apex_engine import get_apex_engine

    router = APIRouter(prefix="/apex/v1", tags=["APEX Intelligence"])
    engine = get_apex_engine()

    @router.get("/status")
    async def get_status():
        """Engine health check — all 12 systems."""
        return engine.get_engine_status()

    @router.get("/predictions")
    async def get_predictions():
        """AI threat predictions for next 7 days."""
        return engine.get_predictions()

    @router.get("/graph/summary")
    async def get_graph_summary():
        """Threat intelligence graph summary."""
        return engine.get_graph_summary()

    @router.post("/copilot/query")
    async def copilot_query(req: CopilotRequest):
        """AI Security Copilot — natural language threat queries."""
        return engine.copilot_query(req.query, req.context)

    @router.get("/marketplace/catalog")
    async def get_catalog():
        """Threat intel marketplace catalog."""
        return engine.get_marketplace_catalog()

    @router.post("/marketplace/subscribe")
    async def create_subscription(req: SubscriptionRequest):
        """Create a new subscription."""
        engine._lazy_init()
        if engine._marketplace:
            return engine._marketplace.create_subscription(req.tenant_id, req.tier, req.email)
        raise HTTPException(status_code=503, detail="Marketplace unavailable")

    @router.post("/marketplace/validate")
    async def validate_key(req: ValidateKeyRequest):
        """Validate API key and check feature access."""
        engine._lazy_init()
        if engine._marketplace:
            return engine._marketplace.validate_api_key(req.api_key, req.feature)
        raise HTTPException(status_code=503, detail="Marketplace unavailable")

    @router.get("/marketplace/revenue")
    async def get_revenue():
        """Revenue summary dashboard."""
        engine._lazy_init()
        if engine._marketplace:
            return engine._marketplace.get_revenue_summary()
        raise HTTPException(status_code=503, detail="Marketplace unavailable")

    @router.get("/soc/status")
    async def get_soc_status():
        """Autonomous SOC engine status."""
        engine._lazy_init()
        if engine._soc:
            return engine._soc.get_engine_status()
        return {"status": "SOC_UNAVAILABLE"}

    @router.get("/scoring/top-risks")
    async def get_top_risks(limit: int = Query(10, ge=1, le=100)):
        """Get top risk advisories from manifest."""
        try:
            manifest_path = os.path.join(
                os.path.dirname(__file__), "..", "data", "stix", "feed_manifest.json"
            )
            with open(manifest_path, encoding="utf-8") as f:
                advisories = json.load(f)
            engine._lazy_init()
            if engine._scoring:
                return {"top_risks": engine._scoring.get_top_risks(advisories, limit)}
        except Exception as e:
            raise HTTPException(status_code=500, detail=str(e))

    @router.get("/quantum/roadmap")
    async def get_quantum_roadmap():
        """PQC migration roadmap."""
        engine._lazy_init()
        if engine._quantum:
            return engine._quantum.generate_pqc_roadmap()
        return {"status": "QUANTUM_ENGINE_UNAVAILABLE"}

    return router


def mount_apex_routes(app) -> None:
    """Mount APEX routes onto an existing FastAPI app."""
    router = build_apex_router()
    if router:
        app.include_router(router)
        logger.info("[APEX-API] Routes mounted: /apex/v1/*")
    else:
        logger.warning("[APEX-API] Routes NOT mounted (FastAPI unavailable)")
