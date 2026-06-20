"""
CYBERDUDEBIVASH® SENTINEL APEX — Geopolitical Risk Intelligence API Router
GET  /api/v1/geopolitical/country/{code}   — Country threat profile
GET  /api/v1/geopolitical/landscape        — Current threat landscape
POST /api/v1/geopolitical/actor/{name}     — Actor geo attribution
POST /api/v1/geopolitical/supply-chain     — Supply chain geo risk
POST /api/v1/geopolitical/sanctions-check  — Sanctions compliance check
Revenue tier: ENTERPRISE add-on · MSSP included · Government custom pricing
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-GEO-API")
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
    geopolitical_router = APIRouter(prefix="/api/v1/geopolitical", tags=["Geopolitical Risk Intelligence"])

    class SupplyChainGeoRequest(BaseModel):
        vendors: List[Dict[str, str]]
        sector:  str = "generic"

    class SanctionsCheckRequest(BaseModel):
        entities: List[str]

    @geopolitical_router.get("/country/{country_code}", summary="Get geopolitical risk profile for a country")
    async def get_country(country_code: str):
        if len(country_code) not in (2, 3):
            raise HTTPException(400, {"error": "country_code must be ISO 3166-1 alpha-2 (e.g., CN, RU, US)"})
        try:
            from agent.geopolitical import GeopoliticalRiskEngine
            engine  = GeopoliticalRiskEngine()
            profile = engine.get_country_profile(country_code.upper())
            return {
                "status":          "success",
                "country_code":    profile.country_code,
                "country_name":    profile.country_name,
                "threat_level":    profile.threat_level,
                "cyber_risk_score": profile.cyber_risk_score,
                "apt_groups":      profile.nation_state_apt_groups,
                "sanctioned":      profile.sanctioned,
                "sanctions_bodies": profile.sanctions_bodies,
                "primary_targets": profile.primary_targets,
                "primary_ttps":    profile.primary_ttps,
                "alliance_bloc":   profile.alliance_bloc,
                "conflict_status": profile.conflict_status,
                "assessed_at":     profile.assessed_at,
            }
        except Exception as e:
            logger.error(f"Country profile error: {e}", exc_info=True)
            raise HTTPException(500, {"error": "Failed to retrieve country profile", "detail": str(e)})

    @geopolitical_router.get("/landscape", summary="Current global geopolitical cyber threat landscape")
    async def get_landscape():
        try:
            from agent.geopolitical import GeopoliticalRiskEngine
            engine = GeopoliticalRiskEngine()
            return {"status": "success", **engine.get_current_threat_landscape()}
        except Exception as e:
            logger.error(f"Landscape error: {e}", exc_info=True)
            raise HTTPException(500, {"error": "Failed to retrieve landscape", "detail": str(e)})

    @geopolitical_router.get("/actor/{actor_name}", summary="Geopolitical attribution for a threat actor")
    async def actor_attribution(actor_name: str):
        try:
            from agent.geopolitical import GeopoliticalRiskEngine
            engine = GeopoliticalRiskEngine()
            result = engine.assess_threat_actor_geo(actor_name)
            return {"status": "success", **result}
        except Exception as e:
            raise HTTPException(500, {"error": str(e)})

    @geopolitical_router.post("/supply-chain", summary="Geopolitical risk analysis of vendor supply chain")
    async def supply_chain_geo(req: SupplyChainGeoRequest):
        if not req.vendors:
            raise HTTPException(400, {"error": "vendors list is required"})
        try:
            from agent.geopolitical import GeopoliticalRiskEngine
            engine = GeopoliticalRiskEngine()
            result = engine.assess_supply_chain_geo_risk(req.vendors, req.sector)
            return {"status": "success", **result}
        except Exception as e:
            logger.error(f"Supply chain geo error: {e}", exc_info=True)
            raise HTTPException(500, {"error": "Supply chain geo assessment failed", "detail": str(e)})

    @geopolitical_router.post("/sanctions-check", summary="OFAC/EU/UN sanctions compliance check")
    async def sanctions_check(req: SanctionsCheckRequest):
        if not req.entities:
            raise HTTPException(400, {"error": "entities list is required"})
        if len(req.entities) > 100:
            raise HTTPException(400, {"error": "Max 100 entities per request"})
        try:
            from agent.geopolitical import GeopoliticalRiskEngine
            engine = GeopoliticalRiskEngine()
            result = engine.check_sanctions_exposure(req.entities)
            return {"status": "success", **result}
        except Exception as e:
            logger.error(f"Sanctions check error: {e}", exc_info=True)
            raise HTTPException(500, {"error": "Sanctions check failed", "detail": str(e)})

    @geopolitical_router.get("/health", summary="Geopolitical risk engine health")
    async def geo_health():
        try:
            from agent.geopolitical import GeopoliticalRiskEngine
            engine = GeopoliticalRiskEngine()
            return {"status": "ok", **engine.get_stats()}
        except Exception as e:
            return {"status": "degraded", "error": str(e)}

else:
    geopolitical_router = None
