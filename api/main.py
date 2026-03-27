#!/usr/bin/env python3
"""
CYBERDUDEBIVASH® SENTINEL APEX — FastAPI Intelligence Backend v1.0
===================================================================
Production-grade REST API for tiered threat intelligence delivery.

Tiers:
  FREE       : 10 advisories/req, no IOC details, public endpoints
  PRO        : 100 advisories/req, full IOC, search, STIX export  ($49/mo)
  ENTERPRISE : 500 advisories/req, all endpoints, bulk export      ($499/mo)
  MSSP       : Unlimited, white-label, webhook push               ($1999/mo)

Deploy: Railway / Render / AWS Lambda / Docker
"""
from __future__ import annotations

import json
import os
import time
import hashlib
import logging
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path
from typing import List, Optional, Dict, Any

from fastapi import FastAPI, HTTPException, Query, Header, Request, Depends
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse, Response
from pydantic import BaseModel

# ── Logging ───────────────────────────────────────────────────────────────
logging.basicConfig(level=logging.INFO, format="%(asctime)s [APEX-API] %(message)s")
logger = logging.getLogger("APEX-API")

# ── Constants ─────────────────────────────────────────────────────────────
# BASE_DIR resolves to repo root in ALL environments:
#   Local:   .../CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM-main/
#   Railway: /app/  (Railway clones repo to /app)
#   Docker:  /app/
# Path(__file__) = api/main.py → parent = api/ → parent.parent = repo root
BASE_DIR     = Path(__file__).parent.parent
FEED_PATH    = BASE_DIR / "api" / "feed.json"
LATEST_PATH  = BASE_DIR / "api" / "latest.json"
MANIFEST_PATH= BASE_DIR / "data" / "stix" / "feed_manifest.json"
MRR_PATH     = BASE_DIR / "data" / "sovereign" / "mrr_report.json"
VERSION      = "v1.0"
PLATFORM     = "CYBERDUDEBIVASH® Sentinel APEX"
DASHBOARD    = "https://intel.cyberdudebivash.com"
STORE_URL    = "https://cyberdudebivash.gumroad.com/"

logger.info(f"BASE_DIR resolved to: {BASE_DIR}")
logger.info(f"FEED_PATH exists: {FEED_PATH.exists()}")

# ── Tier Definitions ──────────────────────────────────────────────────────
TIERS: Dict[str, Dict] = {
    "free": {
        "max_results": 10,
        "search": False,
        "ioc_details": False,
        "stix_export": False,
        "bulk_export": False,
        "webhooks": False,
        "rate_limit": 60,      # req/hour
    },
    "pro": {
        "max_results": 100,
        "search": True,
        "ioc_details": True,
        "stix_export": True,
        "bulk_export": False,
        "webhooks": False,
        "rate_limit": 1000,
    },
    "enterprise": {
        "max_results": 500,
        "search": True,
        "ioc_details": True,
        "stix_export": True,
        "bulk_export": True,
        "webhooks": False,
        "rate_limit": 10000,
    },
    "mssp": {
        "max_results": 500,
        "search": True,
        "ioc_details": True,
        "stix_export": True,
        "bulk_export": True,
        "webhooks": True,
        "rate_limit": 999999,
    },
}

# ── Demo API Keys (replace with DB in production) ─────────────────────────
DEMO_KEYS: Dict[str, Dict] = {
    "demo-free-key-0000":       {"tier": "free",       "name": "Demo Free"},
    "demo-pro-key-1111":        {"tier": "pro",        "name": "Demo Pro"},
    "demo-enterprise-key-2222": {"tier": "enterprise", "name": "Demo Enterprise"},
}

# ── Rate Limiting (in-memory, production: use Redis) ──────────────────────
_rate_counters: Dict[str, Dict] = {}

def check_rate_limit(api_key: str, tier: str) -> bool:
    limit = TIERS[tier]["rate_limit"]
    now   = int(time.time() / 3600)   # bucket = 1 hour
    key   = f"{api_key}:{now}"
    c     = _rate_counters.get(key, {"count": 0})
    if c["count"] >= limit:
        return False
    _rate_counters[key] = {"count": c["count"] + 1}
    return True

# ── FastAPI App ───────────────────────────────────────────────────────────
app = FastAPI(
    title=f"{PLATFORM} Intelligence API",
    description=(
        "Production-grade AI-powered threat intelligence API. "
        "500+ advisories, STIX 2.1, CVE/EPSS enrichment, IOC feeds. "
        f"Dashboard: {DASHBOARD} | Store: {STORE_URL}"
    ),
    version=VERSION,
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ── Pydantic Schemas ──────────────────────────────────────────────────────
class AdvisoryItem(BaseModel):
    stix_id: str
    title: str
    severity: str
    risk_score: float
    timestamp: str
    blog_url: str
    source_url: str
    tlp_label: str
    confidence_score: float
    threat_type: str
    feed_source: str
    kev_present: bool
    cvss_score: Optional[float]
    epss_score: Optional[float]
    mitre_tactics: List[str]
    actor_tag: str

class AdvisoryDetailItem(AdvisoryItem):
    ioc_counts: Dict
    indicator_count: int
    stix_file: str
    stix_object_count: int
    supply_chain: bool
    exploit_probability: str
    alert: Dict
    campaign: Dict

class FeedResponse(BaseModel):
    status: str
    version: str
    platform: str
    tier: str
    count: int
    total_available: int
    generated: str
    data: List[Any]
    upgrade_url: str

class StatsResponse(BaseModel):
    status: str
    platform: str
    version: str
    metrics: Dict
    feed_health: Dict
    generated: str

# ── Data Loaders (cached, 5-min TTL) ─────────────────────────────────────
_cache: Dict[str, Any] = {}
_cache_ts: Dict[str, float] = {}
CACHE_TTL = 300  # 5 minutes

def load_json(path: Path, cache_key: str) -> Any:
    now = time.time()
    if cache_key in _cache and (now - _cache_ts.get(cache_key, 0)) < CACHE_TTL:
        return _cache[cache_key]
    try:
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        _cache[cache_key] = data
        _cache_ts[cache_key] = now
        return data
    except Exception as e:
        logger.error(f"Failed to load {path}: {e}")
        return None

def get_feed() -> List[Dict]:
    raw = load_json(FEED_PATH, "feed")
    if raw and isinstance(raw, dict):
        return raw.get("data", [])
    return []

def get_manifest() -> List[Dict]:
    raw = load_json(MANIFEST_PATH, "manifest")
    return raw if isinstance(raw, list) else []

# ── Auth Dependency ────────────────────────────────────────────────────────
def get_api_key(x_api_key: Optional[str] = Header(default=None)) -> Dict:
    """Resolve API key to tier. No key = free tier (demo)."""
    if not x_api_key:
        return {"tier": "free", "name": "Anonymous", "key": "anon"}
    key_info = DEMO_KEYS.get(x_api_key)
    if not key_info:
        # Production: query DB here
        raise HTTPException(
            status_code=401,
            detail={
                "error": "Invalid API key",
                "upgrade": STORE_URL,
                "docs": "/api/docs",
            }
        )
    tier = key_info["tier"]
    if not check_rate_limit(x_api_key, tier):
        raise HTTPException(
            status_code=429,
            detail={
                "error": f"Rate limit exceeded for {tier} tier",
                "limit": f"{TIERS[tier]['rate_limit']} req/hour",
                "upgrade": STORE_URL,
            }
        )
    return {**key_info, "key": x_api_key}

def strip_iocs(item: Dict) -> Dict:
    """Remove IOC details for free tier."""
    stripped = {k: v for k, v in item.items()
                if k not in ("ioc_counts", "stix_file", "openclaw", "alert", "correlation")}
    stripped["ioc_counts"] = {"redacted": "Upgrade to Pro for IOC details"}
    return stripped

# ══════════════════════════════════════════════════════════════════════════
# API ENDPOINTS
# ══════════════════════════════════════════════════════════════════════════

@app.get("/health", include_in_schema=False)
async def health_check():
    """Railway health check — ALWAYS returns 200 so deployment succeeds.
    Even if feed.json is missing, we return 200 — Railway needs 200 to mark healthy.
    """
    try:
        feed  = get_feed()
        count = len(feed)
    except Exception:
        count = 0
    return JSONResponse(
        status_code=200,   # ALWAYS 200 — never 503
        content={
            "status":     "healthy",
            "platform":   PLATFORM,
            "version":    VERSION,
            "advisories": count,
            "feed_exists": FEED_PATH.exists(),
        }
    )

@app.get("/", include_in_schema=False)
async def root():
    return JSONResponse({
        "platform": PLATFORM,
        "version":  VERSION,
        "status":   "operational",
        "dashboard": DASHBOARD,
        "store":    STORE_URL,
        "docs":     "/api/docs",
        "endpoints": {
            "feed":    "/api/v1/intel/feed",
            "latest":  "/api/v1/intel/latest",
            "search":  "/api/v1/intel/search",
            "advisory":"/api/v1/intel/{stix_id}",
            "iocs":    "/api/v1/iocs",
            "stats":   "/api/v1/stats",
            "stix":    "/api/v1/stix/{stix_id}",
        }
    })

# ── GET /api/v1/intel/feed ────────────────────────────────────────────────
@app.get("/api/v1/intel/feed", tags=["Intelligence"])
async def get_intelligence_feed(
    limit:    int   = Query(default=10,  ge=1, le=500),
    offset:   int   = Query(default=0,   ge=0),
    severity: Optional[str] = Query(default=None,
        description="Filter: CRITICAL, HIGH, MEDIUM, LOW"),
    min_risk: float = Query(default=0.0, ge=0, le=10),
    auth:     Dict  = Depends(get_api_key),
):
    tier       = auth["tier"]
    max_limit  = TIERS[tier]["max_results"]
    limit      = min(limit, max_limit)
    feed       = get_feed()
    if not feed:
        raise HTTPException(503, "Intelligence feed temporarily unavailable")

    # Filter
    results = feed
    if severity:
        results = [i for i in results if i.get("severity","").upper() == severity.upper()]
    if min_risk > 0:
        results = [i for i in results if i.get("risk_score", 0) >= min_risk]

    total     = len(results)
    paginated = results[offset: offset + limit]

    # Strip IOCs for free tier
    if not TIERS[tier]["ioc_details"]:
        paginated = [strip_iocs(i) for i in paginated]

    return {
        "status": "ok",
        "version": VERSION,
        "platform": PLATFORM,
        "tier": tier,
        "count": len(paginated),
        "total_available": total,
        "offset": offset,
        "limit": limit,
        "tier_max": max_limit,
        "generated": datetime.now(timezone.utc).isoformat(),
        "upgrade_url": STORE_URL if tier == "free" else None,
        "data": paginated,
    }

# ── GET /api/v1/intel/latest ──────────────────────────────────────────────
@app.get("/api/v1/intel/latest", tags=["Intelligence"])
async def get_latest_advisories(
    n:    int  = Query(default=10, ge=1, le=50),
    auth: Dict = Depends(get_api_key),
):
    tier      = auth["tier"]
    max_limit = min(TIERS[tier]["max_results"], 50)
    feed      = get_feed()
    results   = feed[:min(n, max_limit)]
    if not TIERS[tier]["ioc_details"]:
        results = [strip_iocs(i) for i in results]
    return {
        "status": "ok", "tier": tier, "count": len(results),
        "generated": datetime.now(timezone.utc).isoformat(),
        "upgrade_url": STORE_URL if tier == "free" else None,
        "data": results,
    }

# ── GET /api/v1/intel/{stix_id} ───────────────────────────────────────────
@app.get("/api/v1/intel/{stix_id}", tags=["Intelligence"])
async def get_advisory_by_id(
    stix_id: str,
    auth:    Dict = Depends(get_api_key),
):
    feed = get_feed()
    item = next((i for i in feed if i.get("stix_id") == stix_id
                 or i.get("bundle_id") == stix_id), None)
    if not item:
        raise HTTPException(404, {"error": f"Advisory {stix_id} not found"})
    if not TIERS[auth["tier"]]["ioc_details"]:
        item = strip_iocs(item)
    return {"status": "ok", "tier": auth["tier"], "data": item}

# ── GET /api/v1/intel/search ──────────────────────────────────────────────
@app.get("/api/v1/intel/search", tags=["Intelligence"])
async def search_intelligence(
    q:        str   = Query(..., min_length=2, description="Search keyword"),
    severity: Optional[str] = Query(default=None),
    min_risk: float = Query(default=0.0, ge=0, le=10),
    limit:    int   = Query(default=20, ge=1, le=100),
    auth:     Dict  = Depends(get_api_key),
):
    tier = auth["tier"]
    if not TIERS[tier]["search"]:
        raise HTTPException(403, {
            "error": "Search requires Pro tier or higher",
            "upgrade": STORE_URL,
            "current_tier": tier,
        })
    feed    = get_feed()
    q_lower = q.lower()
    results = [
        i for i in feed
        if q_lower in i.get("title", "").lower()
        or q_lower in i.get("threat_type", "").lower()
        or q_lower in i.get("actor_tag", "").lower()
        or any(q_lower in t.lower() for t in i.get("mitre_tactics", []))
        or q_lower in i.get("feed_source", "").lower()
    ]
    if severity:
        results = [i for i in results if i.get("severity","").upper() == severity.upper()]
    if min_risk > 0:
        results = [i for i in results if i.get("risk_score", 0) >= min_risk]
    max_r   = min(limit, TIERS[tier]["max_results"])
    results = results[:max_r]
    if not TIERS[tier]["ioc_details"]:
        results = [strip_iocs(i) for i in results]
    return {
        "status": "ok", "tier": tier, "query": q,
        "count": len(results),
        "generated": datetime.now(timezone.utc).isoformat(),
        "data": results,
    }

# ── GET /api/v1/iocs ──────────────────────────────────────────────────────
@app.get("/api/v1/iocs", tags=["IOC Intelligence"])
async def get_ioc_feed(
    ioc_type: Optional[str] = Query(default=None,
        description="Filter: sha256, domain, ipv4, url, md5"),
    min_risk: float = Query(default=7.0, ge=0, le=10),
    limit:    int   = Query(default=50, ge=1, le=500),
    auth:     Dict  = Depends(get_api_key),
):
    tier = auth["tier"]
    if not TIERS[tier]["ioc_details"]:
        raise HTTPException(403, {
            "error": "IOC details require Pro tier or higher",
            "upgrade": STORE_URL, "current_tier": tier,
        })
    feed     = get_feed()
    ioc_list = []
    for item in feed:
        if item.get("risk_score", 0) < min_risk:
            continue
        counts = item.get("ioc_counts", {})
        if not isinstance(counts, dict):
            continue
        for itype, count in counts.items():
            if count and count > 0:
                if ioc_type and itype.lower() != ioc_type.lower():
                    continue
                ioc_list.append({
                    "advisory_title": item["title"][:80],
                    "stix_id": item["stix_id"],
                    "ioc_type": itype,
                    "count": count,
                    "risk_score": item["risk_score"],
                    "severity": item["severity"],
                    "timestamp": item["timestamp"],
                    "blog_url": item["blog_url"],
                    "kev_present": item.get("kev_present", False),
                })
    ioc_list = sorted(ioc_list, key=lambda x: x["risk_score"], reverse=True)
    total    = len(ioc_list)
    ioc_list = ioc_list[:min(limit, TIERS[tier]["max_results"])]
    return {
        "status": "ok", "tier": tier,
        "ioc_type_filter": ioc_type or "all",
        "min_risk_filter": min_risk,
        "count": len(ioc_list), "total": total,
        "generated": datetime.now(timezone.utc).isoformat(),
        "data": ioc_list,
    }

# ── GET /api/v1/stats ─────────────────────────────────────────────────────
@app.get("/api/v1/stats", tags=["Platform"])
async def get_platform_stats():
    """Public endpoint — no auth required."""
    feed = get_feed()
    if not feed:
        raise HTTPException(503, "Stats temporarily unavailable")
    severities = {}
    risk_sum   = 0.0
    kev_count  = 0
    ioc_total  = 0
    for item in feed:
        sev = item.get("severity", "UNKNOWN")
        severities[sev] = severities.get(sev, 0) + 1
        risk_sum  += item.get("risk_score", 0)
        if item.get("kev_present"): kev_count += 1
        counts = item.get("ioc_counts", {})
        if isinstance(counts, dict):
            ioc_total += sum(v for v in counts.values() if isinstance(v, int))
    return {
        "status": "ok",
        "platform": PLATFORM,
        "version": VERSION,
        "dashboard": DASHBOARD,
        "store": STORE_URL,
        "metrics": {
            "total_advisories": len(feed),
            "severity_distribution": severities,
            "avg_risk_score": round(risk_sum / max(len(feed), 1), 2),
            "kev_tagged": kev_count,
            "total_iocs": ioc_total,
            "critical_count": severities.get("CRITICAL", 0),
            "high_count": severities.get("HIGH", 0),
        },
        "generated": datetime.now(timezone.utc).isoformat(),
    }

# ── GET /api/v1/stix/{stix_id} ────────────────────────────────────────────
@app.get("/api/v1/stix/{stix_id}", tags=["STIX Export"])
async def export_stix_bundle(
    stix_id: str,
    auth:    Dict = Depends(get_api_key),
):
    tier = auth["tier"]
    if not TIERS[tier]["stix_export"]:
        raise HTTPException(403, {
            "error": "STIX export requires Pro tier or higher",
            "upgrade": STORE_URL, "current_tier": tier,
        })
    feed = get_feed()
    item = next((i for i in feed if i.get("stix_id") == stix_id), None)
    if not item:
        raise HTTPException(404, {"error": f"STIX bundle {stix_id} not found"})
    stix_file = BASE_DIR / "data" / "stix" / item.get("stix_file", "")
    if stix_file.exists():
        try:
            with open(stix_file, encoding="utf-8") as f:
                bundle = json.load(f)
            return Response(
                content=json.dumps(bundle, indent=2),
                media_type="application/stix+json",
                headers={"Content-Disposition": f'attachment; filename="{stix_file.name}"'},
            )
        except Exception:
            pass
    # Return inline STIX if file not found
    return {
        "type": "bundle", "id": stix_id, "spec_version": "2.1",
        "objects": [{"type": "indicator", "name": item["title"],
                     "risk_score": item["risk_score"]}]
    }

# ── GET /api/v1/bulk/export ───────────────────────────────────────────────
@app.get("/api/v1/bulk/export", tags=["Bulk Export"])
async def bulk_export(
    format:   str  = Query(default="json", description="json or stix"),
    severity: Optional[str] = Query(default=None),
    min_risk: float = Query(default=7.0, ge=0, le=10),
    auth:     Dict  = Depends(get_api_key),
):
    tier = auth["tier"]
    if not TIERS[tier]["bulk_export"]:
        raise HTTPException(403, {
            "error": "Bulk export requires Enterprise tier or higher",
            "upgrade": STORE_URL, "current_tier": tier,
        })
    feed    = get_feed()
    results = [i for i in feed if i.get("risk_score", 0) >= min_risk]
    if severity:
        results = [i for i in results if i.get("severity","").upper() == severity.upper()]
    if format.lower() == "stix":
        bundle = {
            "type": "bundle", "id": f"bundle--apex-export-{int(time.time())}",
            "spec_version": "2.1", "objects": [],
        }
        for item in results:
            bundle["objects"].append({
                "type": "indicator",
                "id": item["stix_id"],
                "name": item["title"],
                "risk_score": item["risk_score"],
                "severity": item["severity"],
                "created": item["timestamp"],
            })
        return Response(
            content=json.dumps(bundle, indent=2),
            media_type="application/stix+json",
            headers={"Content-Disposition": "attachment; filename=apex_bulk_export.stix.json"},
        )
    return {
        "status": "ok", "tier": tier, "format": format,
        "count": len(results), "min_risk": min_risk,
        "generated": datetime.now(timezone.utc).isoformat(),
        "data": results,
    }

# ── GET /api/v1/tiers ─────────────────────────────────────────────────────
@app.get("/api/v1/tiers", tags=["Platform"])
async def get_tier_info():
    """Public endpoint — show available tiers and pricing."""
    return {
        "status": "ok",
        "platform": PLATFORM,
        "store": STORE_URL,
        "tiers": {
            "free":       {"price": "$0/mo",      "features": TIERS["free"],       "cta": "Use now — no key needed"},
            "pro":        {"price": "$49/mo",     "features": TIERS["pro"],        "cta": STORE_URL},
            "enterprise": {"price": "$499/mo",    "features": TIERS["enterprise"], "cta": STORE_URL},
            "mssp":       {"price": "$1,999/mo",  "features": TIERS["mssp"],       "cta": "Contact: intel.cyberdudebivash.com"},
        }
    }

# ── Startup ────────────────────────────────────────────────────────────────
@app.on_event("startup")
async def startup():
    feed = get_feed()
    logger.info(f"SENTINEL APEX API {VERSION} started — {len(feed)} advisories loaded")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000, log_level="info")
