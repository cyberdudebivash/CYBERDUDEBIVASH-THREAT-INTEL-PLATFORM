"""
CYBERDUDEBIVASH® SENTINEL APEX — TAXII 2.1 API Router
OASIS TAXII 2.1 Specification (CS02, November 2021)

GET  /taxii2/                                     → Discovery
GET  /taxii2/api-root/                            → API Root
GET  /taxii2/api-root/collections/               → List Collections
GET  /taxii2/api-root/collections/{id}/          → Get Collection
GET  /taxii2/api-root/collections/{id}/objects/  → Get STIX Objects
POST /taxii2/api-root/collections/{id}/objects/  → Add Objects (MSSP)
GET  /taxii2/api-root/collections/{id}/manifest/ → Object Manifest
GET  /taxii2/api-root/status/{status_id}/        → Status

Revenue: ENTERPRISE ($499+/mo) · MSSP ($1999/mo) · ISACs / Government partnership
"""
from __future__ import annotations

import logging
import os
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-TAXII-API")
_FASTAPI_OK = False

try:
    from fastapi import APIRouter, HTTPException, Header, Query, Request
    from fastapi.responses import JSONResponse
    from pydantic import BaseModel
    _FASTAPI_OK = True
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

TAXII_MEDIA_TYPE = "application/taxii+json;version=2.1"
STIX_MEDIA_TYPE  = "application/stix+json;version=2.1"
TAXII_ACCEPT     = f"{TAXII_MEDIA_TYPE}, {STIX_MEDIA_TYPE}"

API_ROOT_URL = os.getenv("TAXII_API_ROOT", "https://intel.cyberdudebivash.com/taxii2/api-root")

# Tier accessor helper
TIER_FROM_PREFIX = {
    "cdb_sk_live_free":       "FREE",
    "cdb_sk_live_pro":        "PRO",
    "cdb_sk_live_ent":        "ENTERPRISE",
    "cdb_sk_live_mssp":       "MSSP",
}

def _resolve_tier(api_key: Optional[str]) -> str:
    if not api_key:
        return "FREE"
    for prefix, tier in TIER_FROM_PREFIX.items():
        if api_key.startswith(prefix):
            return tier
    return "PRO"


if _FASTAPI_OK:
    taxii_router = APIRouter(prefix="/taxii2", tags=["TAXII 2.1 Intelligence Sharing"])

    class AddObjectsRequest(BaseModel):
        type:    str = "bundle"
        objects: List[Dict[str, Any]] = []

    def _taxii_headers() -> Dict[str, str]:
        return {"Content-Type": TAXII_MEDIA_TYPE, "X-TAXII-Version": "2.1"}

    @taxii_router.get("/", summary="TAXII 2.1 Discovery endpoint")
    async def taxii_discovery(x_api_key: Optional[str] = Header(None)):
        try:
            from agent.taxii import TaxiiServer
            server = TaxiiServer(API_ROOT_URL)
            return JSONResponse(content=server.discovery(), headers=_taxii_headers())
        except Exception as e:
            raise HTTPException(500, {"title": "Internal Error", "description": str(e)})

    @taxii_router.get("/api-root/", summary="TAXII 2.1 API Root")
    async def taxii_api_root(x_api_key: Optional[str] = Header(None)):
        try:
            from agent.taxii import TaxiiServer
            server = TaxiiServer(API_ROOT_URL)
            return JSONResponse(content=server.api_root(), headers=_taxii_headers())
        except Exception as e:
            raise HTTPException(500, {"title": "Internal Error", "description": str(e)})

    @taxii_router.get("/api-root/collections/", summary="List all TAXII 2.1 collections")
    async def list_collections(x_api_key: Optional[str] = Header(None)):
        tier = _resolve_tier(x_api_key)
        try:
            from agent.taxii import TaxiiServer
            server = TaxiiServer(API_ROOT_URL)
            result = server.list_collections(tier)
            return JSONResponse(content=result, headers=_taxii_headers())
        except Exception as e:
            raise HTTPException(500, {"title": "Internal Error", "description": str(e)})

    @taxii_router.get("/api-root/collections/{collection_id}/", summary="Get collection details")
    async def get_collection(collection_id: str, x_api_key: Optional[str] = Header(None)):
        tier = _resolve_tier(x_api_key)
        try:
            from agent.taxii import TaxiiServer
            server = TaxiiServer(API_ROOT_URL)
            found, result = server.get_collection(collection_id, tier)
            if not found:
                raise HTTPException(404, {"title": "Collection Not Found", "description": f"id: {collection_id}"})
            return JSONResponse(content=result, headers=_taxii_headers())
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"title": "Internal Error", "description": str(e)})

    @taxii_router.get("/api-root/collections/{collection_id}/objects/", summary="Get STIX 2.1 objects from collection")
    async def get_objects(
        collection_id: str,
        x_api_key:    Optional[str] = Header(None),
        limit:        int  = Query(100, ge=1, le=1000),
        offset:       int  = Query(0, ge=0),
        added_after:  Optional[str] = Query(None),
        match_type:   Optional[str] = Query(None, alias="match[type]"),
        match_id:     Optional[str] = Query(None, alias="match[id]"),
    ):
        tier = _resolve_tier(x_api_key)
        try:
            from agent.taxii import TaxiiServer
            server = TaxiiServer(API_ROOT_URL)
            ok, result = server.get_objects(
                collection_id = collection_id,
                tier          = tier,
                limit         = limit,
                offset        = offset,
                added_after   = added_after,
                object_type   = match_type,
                stix_id       = match_id,
            )
            if not ok:
                raise HTTPException(403, result)
            headers = {**_taxii_headers(), "X-TAXII-Total-Objects": str(result.get("total", 0))}
            if result.get("next"):
                headers["X-TAXII-Next"] = result["next"]
            return JSONResponse(content=result["bundle"], headers=headers)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"title": "Internal Error", "description": str(e)})

    @taxii_router.post("/api-root/collections/{collection_id}/objects/", summary="Add STIX 2.1 objects (MSSP only)")
    async def add_objects(
        collection_id: str,
        req: AddObjectsRequest,
        x_api_key: Optional[str] = Header(None),
    ):
        tier = _resolve_tier(x_api_key)
        try:
            from agent.taxii import TaxiiServer
            server = TaxiiServer(API_ROOT_URL)
            ok, result = server.add_objects(collection_id, tier, req.model_dump())
            if not ok:
                raise HTTPException(403, result)
            return JSONResponse(content=result, headers=_taxii_headers(), status_code=202)
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"title": "Internal Error", "description": str(e)})

    @taxii_router.get("/api-root/collections/{collection_id}/manifest/", summary="Get object manifest")
    async def get_manifest(
        collection_id: str,
        x_api_key:    Optional[str] = Header(None),
        limit:        int  = Query(100, ge=1, le=1000),
        offset:       int  = Query(0, ge=0),
        added_after:  Optional[str] = Query(None),
    ):
        tier = _resolve_tier(x_api_key)
        try:
            from agent.taxii import TaxiiServer
            server = TaxiiServer(API_ROOT_URL)
            ok, result = server.get_manifest(collection_id, tier, limit, offset, added_after)
            if not ok:
                raise HTTPException(403, result)
            return JSONResponse(content=result, headers=_taxii_headers())
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"title": "Internal Error", "description": str(e)})

    @taxii_router.get("/api-root/status/{status_id}/", summary="Get operation status")
    async def get_status(status_id: str, x_api_key: Optional[str] = Header(None)):
        return JSONResponse(
            content={
                "id":              status_id,
                "status":          "complete",
                "request_timestamp": "N/A",
                "total_count":     0,
                "success_count":   0,
                "failure_count":   0,
                "pending_count":   0,
            },
            headers=_taxii_headers(),
        )

    @taxii_router.get("/health", summary="TAXII server health")
    async def taxii_health():
        try:
            from agent.taxii import TaxiiServer
            server = TaxiiServer(API_ROOT_URL)
            return {"status": "ok", **server.get_stats()}
        except Exception as e:
            return {"status": "degraded", "error": str(e)}

else:
    taxii_router = None
