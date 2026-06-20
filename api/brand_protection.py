"""
CYBERDUDEBIVASH® SENTINEL APEX — Brand Protection API Router
POST /api/v1/brand/scan      — Full brand protection scan
POST /api/v1/brand/check     — Check specific domain
GET  /api/v1/brand/health    — Engine health
Revenue tier: PRO ($299 add-on) · ENTERPRISE ($999 add-on) · MSSP (included)
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import List, Optional

logger = logging.getLogger("CDB-BRAND-API")
_FASTAPI_OK = False

try:
    from fastapi import APIRouter, HTTPException, Header
    from pydantic import BaseModel
    _FASTAPI_OK = True
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

if _FASTAPI_OK:
    brand_router = APIRouter(prefix="/api/v1/brand", tags=["Brand Protection Intelligence"])

    class BrandScanRequest(BaseModel):
        brand:   str
        domains: Optional[List[str]] = None

    class DomainCheckRequest(BaseModel):
        brand:  str
        domain: str

    @brand_router.post("/scan", summary="Full brand protection scan — typosquatting, phishing kits, social impersonation")
    async def brand_scan(req: BrandScanRequest, x_api_key: Optional[str] = Header(None)):
        if not req.brand or len(req.brand) < 2:
            raise HTTPException(400, {"error": "brand must be at least 2 characters"})
        if len(req.brand) > 50:
            raise HTTPException(400, {"error": "brand name too long (max 50 chars)"})
        try:
            from agent.brand_protection import BrandProtectionEngine
            engine = BrandProtectionEngine()
            result = engine.full_scan(req.brand, req.domains)
            return {"status": "success", **result}
        except Exception as e:
            logger.error(f"Brand scan error: {e}", exc_info=True)
            raise HTTPException(500, {"error": "Brand protection scan failed", "detail": str(e)})

    @brand_router.post("/check", summary="Score a specific domain for brand abuse risk")
    async def domain_check(req: DomainCheckRequest):
        if not req.brand or not req.domain:
            raise HTTPException(400, {"error": "Both brand and domain are required"})
        try:
            from agent.brand_protection import BrandProtectionEngine
            engine = BrandProtectionEngine()
            result = engine.check_domain(req.brand, req.domain)
            return {"status": "success", **result}
        except Exception as e:
            logger.error(f"Domain check error: {e}", exc_info=True)
            raise HTTPException(500, {"error": "Domain check failed", "detail": str(e)})

    @brand_router.get("/health", summary="Brand protection engine health")
    async def brand_health():
        try:
            from agent.brand_protection import BrandProtectionEngine
            engine = BrandProtectionEngine("test")
            stats  = engine.get_stats()
            return {"status": "ok", **stats}
        except Exception as e:
            return {"status": "degraded", "error": str(e)}

else:
    brand_router = None
