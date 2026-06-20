"""
CYBERDUDEBIVASH® SENTINEL APEX — Vendor Risk Intelligence API Router
POST /api/v1/vendor-risk/assess    — Assess single vendor
POST /api/v1/vendor-risk/bulk      — Assess vendor portfolio
GET  /api/v1/vendor-risk/{id}      — Get vendor profile
GET  /api/v1/vendor-risk/health    — Engine health
Revenue tier: ENTERPRISE ($499/mo add-on) · MSSP (included at $1999/mo)
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-VENDOR-RISK-API")
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
    vendor_risk_router = APIRouter(prefix="/api/v1/vendor-risk", tags=["Vendor Risk Intelligence"])

    class VendorAssessRequest(BaseModel):
        vendor_name:      str
        vendor_domain:    str
        vendor_category:  str = "generic"
        data_access:      Optional[List[str]] = None
        access_level:     str = "READ"
        compliance_certs: Optional[List[str]] = None
        contract_data:    Optional[Dict[str, Any]] = None

    class BulkAssessRequest(BaseModel):
        vendors: List[VendorAssessRequest]

    @vendor_risk_router.post("/assess", summary="Assess vendor security risk across 6 FAIR-aligned dimensions")
    async def assess_vendor(req: VendorAssessRequest):
        if not req.vendor_name or not req.vendor_domain:
            raise HTTPException(400, {"error": "vendor_name and vendor_domain are required"})
        try:
            from agent.vendor_risk import VendorRiskEngine
            engine  = VendorRiskEngine()
            profile = engine.assess_vendor(
                vendor_name       = req.vendor_name,
                vendor_domain     = req.vendor_domain,
                vendor_category   = req.vendor_category,
                data_access       = req.data_access,
                access_level      = req.access_level,
                compliance_certs  = req.compliance_certs,
                contract_data     = req.contract_data or {},
            )
            return {"status": "success", "vendor": engine._serialize_profile(profile)}
        except Exception as e:
            logger.error(f"Vendor risk assess error: {e}", exc_info=True)
            raise HTTPException(500, {"error": "Vendor risk assessment failed", "detail": str(e)})

    @vendor_risk_router.post("/bulk", summary="Assess entire vendor portfolio")
    async def bulk_assess(req: BulkAssessRequest):
        if not req.vendors:
            raise HTTPException(400, {"error": "vendors list is required"})
        if len(req.vendors) > 100:
            raise HTTPException(400, {"error": "Maximum 100 vendors per bulk assessment"})
        try:
            from agent.vendor_risk import VendorRiskEngine
            engine  = VendorRiskEngine()
            vendors = [v.model_dump() for v in req.vendors]
            result  = engine.bulk_assess(vendors)
            return {"status": "success", **result}
        except Exception as e:
            logger.error(f"Bulk vendor risk error: {e}", exc_info=True)
            raise HTTPException(500, {"error": "Bulk assessment failed", "detail": str(e)})

    @vendor_risk_router.get("/health", summary="Vendor risk engine health")
    async def vendor_risk_health():
        try:
            from agent.vendor_risk import VendorRiskEngine
            engine = VendorRiskEngine()
            return {"status": "ok", **engine.get_stats()}
        except Exception as e:
            return {"status": "degraded", "error": str(e)}

else:
    vendor_risk_router = None
