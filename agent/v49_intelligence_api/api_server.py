"""
CYBERDUDEBIVASH SENTINEL APEX v49 — Intelligence API Server
Production-grade FastAPI server exposing threat intelligence endpoints.

Endpoints:
    /api/ioc/search         — Search IOCs across all intelligence datasets
    /api/cve/intelligence   — CVE intelligence with CVSS/EPSS enrichment
    /api/threat-actors      — Threat actor registry and attribution
    /api/campaigns          — Campaign correlation and tracking
    /api/detection-rules    — Detection rule generation (Sigma/YARA/Suricata)
    /api/stix/bundle        — STIX 2.1 bundle export
    /api/health             — Platform health check

Authentication: API key via X-API-Key header
Rate Limiting: Tier-based (FREE/PRO/ENTERPRISE)
"""

import os
import json
import time
import hashlib
import logging
from datetime import datetime, timezone
from typing import Optional, List, Dict, Any
from pathlib import Path
from enum import Enum

from fastapi import FastAPI, HTTPException, Depends, Request, Query, Header
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
import uvicorn

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

BASE_DIR = Path(__file__).resolve().parent.parent.parent
DATA_DIR = BASE_DIR / "data"
STIX_DIR = DATA_DIR / "stix"
INTEL_DIR = DATA_DIR / "intelligence"
API_KEYS_FILE = INTEL_DIR / "api_keys.json"
USAGE_LOG_FILE = INTEL_DIR / "api_usage.json"
FEED_MANIFEST = STIX_DIR / "feed_manifest.json"

INTEL_DIR.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [SENTINEL-API] %(levelname)s %(message)s",
)
logger = logging.getLogger("sentinel_api")

# ---------------------------------------------------------------------------
# Tier Configuration
# ---------------------------------------------------------------------------

class SubscriptionTier(str, Enum):
    FREE = "FREE"
    PRO = "PRO"
    ENTERPRISE = "ENTERPRISE"

TIER_LIMITS: Dict[str, Dict[str, Any]] = {
    "FREE": {
        "requests_per_hour": 60,
        "requests_per_day": 500,
        "max_results": 25,
        "stix_export": False,
        "detection_rules": False,
        "campaign_access": False,
        "actor_full_profile": False,
    },
    "PRO": {
        "requests_per_hour": 600,
        "requests_per_day": 10000,
        "max_results": 100,
        "stix_export": True,
        "detection_rules": True,
        "campaign_access": True,
        "actor_full_profile": True,
    },
    "ENTERPRISE": {
        "requests_per_hour": 6000,
        "requests_per_day": 100000,
        "max_results": 500,
        "stix_export": True,
        "detection_rules": True,
        "campaign_access": True,
        "actor_full_profile": True,
    },
}

# ---------------------------------------------------------------------------
# Data Models
# ---------------------------------------------------------------------------

class IOCSearchRequest(BaseModel):
    query: str = Field(..., min_length=1, max_length=512, description="IOC value or pattern")
    ioc_type: Optional[str] = Field(None, description="Filter: ipv4, domain, url, sha256, sha1, md5, email, cve")
    min_risk_score: Optional[float] = Field(None, ge=0, le=100)
    limit: int = Field(25, ge=1, le=500)
    offset: int = Field(0, ge=0)

class CVERequest(BaseModel):
    cve_id: Optional[str] = Field(None, description="Specific CVE ID (e.g., CVE-2024-1234)")
    min_cvss: Optional[float] = Field(None, ge=0, le=10)
    min_epss: Optional[float] = Field(None, ge=0, le=1)
    kev_only: bool = Field(False, description="Only return Known Exploited Vulnerabilities")
    limit: int = Field(25, ge=1, le=500)

class DetectionRuleRequest(BaseModel):
    ioc_values: List[str] = Field(..., min_length=1, max_length=50)
    formats: List[str] = Field(["sigma"], description="sigma, yara, suricata, snort, kql, spl")

class APIKeyInfo(BaseModel):
    key_id: str
    tier: SubscriptionTier
    org_name: str
    created_at: str
    is_active: bool
    requests_today: int = 0
    requests_this_hour: int = 0

class APIResponse(BaseModel):
    status: str = "success"
    platform: str = "CYBERDUDEBIVASH SENTINEL APEX"
    version: str = "v49.0"
    timestamp: str
    data: Any
    meta: Optional[Dict[str, Any]] = None

# ---------------------------------------------------------------------------
# API Key Manager
# ---------------------------------------------------------------------------

class APIKeyManager:
    """Production API key management with tier-based access control."""

    def __init__(self):
        self._keys: Dict[str, Dict] = {}
        self._usage: Dict[str, List[Dict]] = {}
        self._load_keys()
        self._load_usage()

    def _load_keys(self):
        if API_KEYS_FILE.exists():
            try:
                with open(API_KEYS_FILE, "r") as f:
                    self._keys = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._keys = {}
                logger.warning("API keys file corrupted, starting fresh")

    def _save_keys(self):
        API_KEYS_FILE.parent.mkdir(parents=True, exist_ok=True)
        with open(API_KEYS_FILE, "w") as f:
            json.dump(self._keys, f, indent=2)

    def _load_usage(self):
        if USAGE_LOG_FILE.exists():
            try:
                with open(USAGE_LOG_FILE, "r") as f:
                    self._usage = json.load(f)
            except (json.JSONDecodeError, IOError):
                self._usage = {}

    def _save_usage(self):
        with open(USAGE_LOG_FILE, "w") as f:
            json.dump(self._usage, f, indent=2, default=str)

    def generate_key(self, org_name: str, tier: str = "FREE", contact_email: str = "") -> Dict:
        """Generate a new API key with tier assignment."""
        raw = f"{org_name}:{tier}:{time.time_ns()}:{os.urandom(32).hex()}"
        api_key = f"cdb_{hashlib.sha256(raw.encode()).hexdigest()[:48]}"
        key_id = hashlib.md5(api_key.encode()).hexdigest()[:12]

        record = {
            "key_id": key_id,
            "api_key_hash": hashlib.sha256(api_key.encode()).hexdigest(),
            "tier": tier,
            "org_name": org_name,
            "contact_email": contact_email,
            "created_at": datetime.now(timezone.utc).isoformat(),
            "is_active": True,
            "total_requests": 0,
        }
        self._keys[key_id] = record
        self._save_keys()

        logger.info(f"API key generated: org={org_name} tier={tier} key_id={key_id}")
        return {"api_key": api_key, "key_id": key_id, "tier": tier}

    def validate_key(self, api_key: str) -> Optional[Dict]:
        """Validate API key and return associated record."""
        key_hash = hashlib.sha256(api_key.encode()).hexdigest()
        for key_id, record in self._keys.items():
            if record.get("api_key_hash") == key_hash and record.get("is_active", False):
                return record
        return None

    def check_rate_limit(self, key_id: str, tier: str) -> bool:
        """Check if request is within tier rate limits."""
        now = time.time()
        limits = TIER_LIMITS.get(tier, TIER_LIMITS["FREE"])
        usage_list = self._usage.get(key_id, [])

        # Clean old entries (keep last 24h)
        cutoff_day = now - 86400
        cutoff_hour = now - 3600
        usage_list = [u for u in usage_list if u.get("ts", 0) > cutoff_day]
        self._usage[key_id] = usage_list

        hour_count = sum(1 for u in usage_list if u.get("ts", 0) > cutoff_hour)
        day_count = len(usage_list)

        if hour_count >= limits["requests_per_hour"]:
            return False
        if day_count >= limits["requests_per_day"]:
            return False
        return True

    def record_usage(self, key_id: str, endpoint: str, status_code: int):
        """Record API usage for tracking and billing."""
        if key_id not in self._usage:
            self._usage[key_id] = []

        self._usage[key_id].append({
            "ts": time.time(),
            "endpoint": endpoint,
            "status": status_code,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        })

        # Update total count
        if key_id in self._keys:
            self._keys[key_id]["total_requests"] = self._keys[key_id].get("total_requests", 0) + 1
            self._save_keys()

        # Periodic flush
        if len(self._usage[key_id]) % 50 == 0:
            self._save_usage()

    def get_usage_stats(self, key_id: str) -> Dict:
        """Return usage statistics for a key."""
        now = time.time()
        usage_list = self._usage.get(key_id, [])
        hour_count = sum(1 for u in usage_list if u.get("ts", 0) > now - 3600)
        day_count = sum(1 for u in usage_list if u.get("ts", 0) > now - 86400)
        return {
            "requests_last_hour": hour_count,
            "requests_last_24h": day_count,
            "total_requests": self._keys.get(key_id, {}).get("total_requests", 0),
        }

    def revoke_key(self, key_id: str) -> bool:
        if key_id in self._keys:
            self._keys[key_id]["is_active"] = False
            self._save_keys()
            return True
        return False


# ---------------------------------------------------------------------------
# Intelligence Data Loader
# ---------------------------------------------------------------------------

class IntelligenceLoader:
    """Load and index intelligence data from existing STIX/manifest datasets."""

    def __init__(self):
        self._manifest: List[Dict] = []
        self._stix_bundles: List[Dict] = []
        self._ioc_index: Dict[str, List[Dict]] = {}
        self._cve_index: Dict[str, List[Dict]] = {}
        self._actor_index: Dict[str, List[Dict]] = {}
        self._last_load = 0
        self._cache_ttl = 300  # 5 min cache

    def _needs_reload(self) -> bool:
        return (time.time() - self._last_load) > self._cache_ttl

    def load(self):
        """Load all intelligence data sources."""
        if not self._needs_reload() and self._manifest:
            return

        # Load feed manifest
        if FEED_MANIFEST.exists():
            try:
                with open(FEED_MANIFEST, "r") as f:
                    self._manifest = json.load(f)
                    if isinstance(self._manifest, dict):
                        self._manifest = self._manifest.get("entries", [])
            except Exception as e:
                logger.error(f"Failed to load manifest: {e}")
                self._manifest = []

        # Load STIX bundles
        self._stix_bundles = []
        if STIX_DIR.exists():
            for stix_file in STIX_DIR.glob("*.json"):
                if stix_file.name == "feed_manifest.json":
                    continue
                try:
                    with open(stix_file, "r") as f:
                        bundle = json.load(f)
                        if isinstance(bundle, dict) and bundle.get("type") == "bundle":
                            self._stix_bundles.append(bundle)
                except Exception:
                    continue

        # Build IOC index
        self._ioc_index = {}
        self._cve_index = {}
        self._actor_index = {}

        for entry in self._manifest:
            # Index IOCs
            iocs = entry.get("iocs", entry.get("ioc_counts", {}))
            if isinstance(iocs, dict):
                for ioc_type, values in iocs.items():
                    if isinstance(values, list):
                        for val in values:
                            key = str(val).lower()
                            if key not in self._ioc_index:
                                self._ioc_index[key] = []
                            self._ioc_index[key].append({
                                "ioc_value": val,
                                "ioc_type": ioc_type,
                                "source": entry.get("title", "Unknown"),
                                "risk_score": entry.get("risk_score", 0),
                                "timestamp": entry.get("timestamp", ""),
                                "mitre_tactics": entry.get("mitre_tactics", []),
                                "actor_tag": entry.get("actor_tag", ""),
                            })

            # Index CVEs
            cves = entry.get("cves", [])
            if isinstance(cves, list):
                for cve in cves:
                    cve_id = cve if isinstance(cve, str) else cve.get("id", "")
                    if cve_id:
                        if cve_id not in self._cve_index:
                            self._cve_index[cve_id] = []
                        self._cve_index[cve_id].append({
                            "cve_id": cve_id,
                            "source": entry.get("title", ""),
                            "cvss_score": entry.get("cvss_score", 0),
                            "epss_score": entry.get("epss_score", 0),
                            "kev_present": entry.get("kev_present", False),
                            "risk_score": entry.get("risk_score", 0),
                            "actor_tag": entry.get("actor_tag", ""),
                            "mitre_tactics": entry.get("mitre_tactics", []),
                        })

            # Index actors
            actor = entry.get("actor_tag", "")
            if actor and actor != "Unknown":
                if actor not in self._actor_index:
                    self._actor_index[actor] = []
                self._actor_index[actor].append({
                    "advisory": entry.get("title", ""),
                    "risk_score": entry.get("risk_score", 0),
                    "mitre_tactics": entry.get("mitre_tactics", []),
                    "timestamp": entry.get("timestamp", ""),
                    "cves": entry.get("cves", []),
                })

        self._last_load = time.time()
        logger.info(
            f"Intelligence loaded: {len(self._manifest)} advisories, "
            f"{len(self._ioc_index)} IOCs, {len(self._cve_index)} CVEs, "
            f"{len(self._actor_index)} actors"
        )

    def search_iocs(self, query: str, ioc_type: Optional[str] = None,
                    min_risk: float = 0, limit: int = 25, offset: int = 0) -> Dict:
        self.load()
        query_lower = query.lower().strip()
        results = []

        for key, entries in self._ioc_index.items():
            if query_lower in key:
                for entry in entries:
                    if ioc_type and entry.get("ioc_type") != ioc_type:
                        continue
                    if entry.get("risk_score", 0) >= min_risk:
                        results.append(entry)

        # Also search manifest titles/descriptions
        for entry in self._manifest:
            title = entry.get("title", "").lower()
            desc = entry.get("description", "").lower()
            if query_lower in title or query_lower in desc:
                results.append({
                    "ioc_value": query,
                    "ioc_type": "advisory_match",
                    "source": entry.get("title", ""),
                    "risk_score": entry.get("risk_score", 0),
                    "timestamp": entry.get("timestamp", ""),
                    "mitre_tactics": entry.get("mitre_tactics", []),
                    "actor_tag": entry.get("actor_tag", ""),
                })

        total = len(results)
        results = results[offset:offset + limit]
        return {"results": results, "total": total, "offset": offset, "limit": limit}

    def get_cve_intelligence(self, cve_id: Optional[str] = None,
                              min_cvss: float = 0, min_epss: float = 0,
                              kev_only: bool = False, limit: int = 25) -> Dict:
        self.load()
        results = []

        if cve_id:
            entries = self._cve_index.get(cve_id.upper(), [])
            results.extend(entries)
        else:
            for cve, entries in self._cve_index.items():
                for entry in entries:
                    if entry.get("cvss_score", 0) >= min_cvss:
                        if entry.get("epss_score", 0) >= min_epss:
                            if not kev_only or entry.get("kev_present", False):
                                results.append(entry)

        # Deduplicate by CVE ID
        seen = set()
        deduped = []
        for r in results:
            cid = r.get("cve_id", "")
            if cid not in seen:
                seen.add(cid)
                deduped.append(r)

        deduped.sort(key=lambda x: x.get("cvss_score", 0), reverse=True)
        return {"results": deduped[:limit], "total": len(deduped)}

    def get_threat_actors(self, actor_name: Optional[str] = None, limit: int = 25) -> Dict:
        self.load()
        results = []

        if actor_name:
            query = actor_name.lower()
            for actor, entries in self._actor_index.items():
                if query in actor.lower():
                    results.append({
                        "actor_name": actor,
                        "advisory_count": len(entries),
                        "avg_risk_score": round(
                            sum(e.get("risk_score", 0) for e in entries) / max(len(entries), 1), 1
                        ),
                        "tactics": list(set(
                            t for e in entries for t in e.get("mitre_tactics", [])
                        )),
                        "associated_cves": list(set(
                            c for e in entries for c in (e.get("cves", []) if isinstance(e.get("cves"), list) else [])
                        ))[:20],
                        "last_seen": max((e.get("timestamp", "") for e in entries), default=""),
                        "advisories": [e.get("advisory", "") for e in entries[:10]],
                    })
        else:
            for actor, entries in self._actor_index.items():
                results.append({
                    "actor_name": actor,
                    "advisory_count": len(entries),
                    "avg_risk_score": round(
                        sum(e.get("risk_score", 0) for e in entries) / max(len(entries), 1), 1
                    ),
                    "last_seen": max((e.get("timestamp", "") for e in entries), default=""),
                })

        results.sort(key=lambda x: x.get("advisory_count", 0), reverse=True)
        return {"results": results[:limit], "total": len(results)}

    def get_campaigns(self, limit: int = 25) -> Dict:
        """Derive campaign intelligence from correlated advisories."""
        self.load()
        campaigns = {}

        for entry in self._manifest:
            actor = entry.get("actor_tag", "Unknown")
            tactics = tuple(sorted(entry.get("mitre_tactics", [])))
            campaign_key = f"{actor}::{':'.join(tactics)}" if tactics else actor

            if campaign_key not in campaigns:
                campaigns[campaign_key] = {
                    "campaign_id": hashlib.md5(campaign_key.encode()).hexdigest()[:16],
                    "attributed_actor": actor,
                    "tactics": list(tactics),
                    "advisories": [],
                    "total_risk": 0,
                    "first_seen": entry.get("timestamp", ""),
                    "last_seen": entry.get("timestamp", ""),
                    "ioc_count": 0,
                }

            c = campaigns[campaign_key]
            c["advisories"].append(entry.get("title", ""))
            c["total_risk"] += entry.get("risk_score", 0)
            ts = entry.get("timestamp", "")
            if ts and ts < c["first_seen"]:
                c["first_seen"] = ts
            if ts and ts > c["last_seen"]:
                c["last_seen"] = ts
            ioc_counts = entry.get("ioc_counts", {})
            if isinstance(ioc_counts, dict):
                c["ioc_count"] += sum(
                    v if isinstance(v, int) else len(v) if isinstance(v, list) else 0
                    for v in ioc_counts.values()
                )

        results = sorted(campaigns.values(), key=lambda x: x.get("total_risk", 0), reverse=True)
        for r in results:
            r["avg_risk"] = round(r["total_risk"] / max(len(r["advisories"]), 1), 1)
            r["advisory_count"] = len(r["advisories"])
            r["advisories"] = r["advisories"][:5]  # Trim for response size

        return {"results": results[:limit], "total": len(results)}

    def get_stix_bundles(self) -> List[Dict]:
        self.load()
        return self._stix_bundles

    def get_manifest_stats(self) -> Dict:
        self.load()
        total = len(self._manifest)
        critical = sum(1 for e in self._manifest if e.get("risk_score", 0) >= 80)
        high = sum(1 for e in self._manifest if 60 <= e.get("risk_score", 0) < 80)
        medium = sum(1 for e in self._manifest if 40 <= e.get("risk_score", 0) < 60)
        low = sum(1 for e in self._manifest if e.get("risk_score", 0) < 40)

        return {
            "total_advisories": total,
            "severity_breakdown": {
                "critical": critical, "high": high, "medium": medium, "low": low
            },
            "total_iocs": len(self._ioc_index),
            "total_cves": len(self._cve_index),
            "total_actors": len(self._actor_index),
            "data_freshness": max(
                (e.get("timestamp", "") for e in self._manifest), default="N/A"
            ),
        }


# ---------------------------------------------------------------------------
# FastAPI Application
# ---------------------------------------------------------------------------

key_manager = APIKeyManager()
intel_loader = IntelligenceLoader()

app = FastAPI(
    title="CYBERDUDEBIVASH SENTINEL APEX — Intelligence API",
    description=(
        "Enterprise threat intelligence API providing IOC search, CVE intelligence, "
        "threat actor tracking, campaign correlation, and detection rule generation. "
        "© 2026 CyberDudeBivash Pvt. Ltd."
    ),
    version="49.0.0",
    docs_url="/api/docs",
    redoc_url="/api/redoc",
    openapi_url="/api/openapi.json",
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["https://intel.cyberdudebivash.com", "https://cyberdudebivash.com"],
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# ---------------------------------------------------------------------------
# Auth Dependency
# ---------------------------------------------------------------------------

async def verify_api_key(request: Request, x_api_key: str = Header(..., alias="X-API-Key")):
    """Validate API key, enforce rate limits, record usage."""
    if not x_api_key or not x_api_key.startswith("cdb_"):
        raise HTTPException(status_code=401, detail="Invalid API key format")

    record = key_manager.validate_key(x_api_key)
    if not record:
        raise HTTPException(status_code=401, detail="Invalid or revoked API key")

    key_id = record["key_id"]
    tier = record.get("tier", "FREE")

    if not key_manager.check_rate_limit(key_id, tier):
        limits = TIER_LIMITS.get(tier, TIER_LIMITS["FREE"])
        raise HTTPException(
            status_code=429,
            detail={
                "error": "Rate limit exceeded",
                "tier": tier,
                "limit_per_hour": limits["requests_per_hour"],
                "upgrade_url": "https://cyberdudebivash.com/pricing",
            },
        )

    # Attach to request state
    request.state.key_id = key_id
    request.state.tier = tier
    request.state.tier_limits = TIER_LIMITS.get(tier, TIER_LIMITS["FREE"])

    key_manager.record_usage(key_id, request.url.path, 200)
    return record


def _response(data: Any, meta: Optional[Dict] = None) -> Dict:
    return {
        "status": "success",
        "platform": "CYBERDUDEBIVASH SENTINEL APEX",
        "version": "v49.0",
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "data": data,
        "meta": meta,
    }


# ---------------------------------------------------------------------------
# Public Endpoints
# ---------------------------------------------------------------------------

@app.get("/api/health")
async def health_check():
    stats = intel_loader.get_manifest_stats()
    return _response({
        "status": "operational",
        "platform": "SENTINEL APEX Intelligence API",
        "intelligence_stats": stats,
    })


# ---------------------------------------------------------------------------
# Authenticated Endpoints
# ---------------------------------------------------------------------------

@app.post("/api/ioc/search")
async def search_iocs(req: IOCSearchRequest, request: Request, auth=Depends(verify_api_key)):
    max_results = min(req.limit, request.state.tier_limits["max_results"])
    results = intel_loader.search_iocs(
        query=req.query,
        ioc_type=req.ioc_type,
        min_risk=req.min_risk_score or 0,
        limit=max_results,
        offset=req.offset,
    )
    return _response(results, meta={"tier": request.state.tier})


@app.get("/api/ioc/search")
async def search_iocs_get(
    request: Request,
    q: str = Query(..., min_length=1, max_length=512),
    ioc_type: Optional[str] = None,
    min_risk: float = 0,
    limit: int = 25,
    offset: int = 0,
    auth=Depends(verify_api_key),
):
    max_results = min(limit, request.state.tier_limits["max_results"])
    results = intel_loader.search_iocs(q, ioc_type, min_risk, max_results, offset)
    return _response(results, meta={"tier": request.state.tier})


@app.post("/api/cve/intelligence")
async def cve_intelligence(req: CVERequest, request: Request, auth=Depends(verify_api_key)):
    max_results = min(req.limit, request.state.tier_limits["max_results"])
    results = intel_loader.get_cve_intelligence(
        cve_id=req.cve_id,
        min_cvss=req.min_cvss or 0,
        min_epss=req.min_epss or 0,
        kev_only=req.kev_only,
        limit=max_results,
    )
    return _response(results, meta={"tier": request.state.tier})


@app.get("/api/cve/intelligence")
async def cve_intelligence_get(
    request: Request,
    cve_id: Optional[str] = None,
    min_cvss: float = 0,
    min_epss: float = 0,
    kev_only: bool = False,
    limit: int = 25,
    auth=Depends(verify_api_key),
):
    max_results = min(limit, request.state.tier_limits["max_results"])
    results = intel_loader.get_cve_intelligence(cve_id, min_cvss, min_epss, kev_only, max_results)
    return _response(results, meta={"tier": request.state.tier})


@app.get("/api/threat-actors")
async def threat_actors(
    request: Request,
    name: Optional[str] = None,
    limit: int = 25,
    auth=Depends(verify_api_key),
):
    tier_limits = request.state.tier_limits
    if not tier_limits.get("actor_full_profile") and name:
        raise HTTPException(
            status_code=403,
            detail={"error": "Full actor profiles require PRO tier", "upgrade_url": "https://cyberdudebivash.com/pricing"},
        )
    results = intel_loader.get_threat_actors(name, min(limit, tier_limits["max_results"]))
    return _response(results, meta={"tier": request.state.tier})


@app.get("/api/campaigns")
async def campaigns(
    request: Request,
    limit: int = 25,
    auth=Depends(verify_api_key),
):
    tier_limits = request.state.tier_limits
    if not tier_limits.get("campaign_access"):
        raise HTTPException(
            status_code=403,
            detail={"error": "Campaign intelligence requires PRO tier", "upgrade_url": "https://cyberdudebivash.com/pricing"},
        )
    results = intel_loader.get_campaigns(min(limit, tier_limits["max_results"]))
    return _response(results, meta={"tier": request.state.tier})


@app.post("/api/detection-rules")
async def generate_detection_rules(req: DetectionRuleRequest, request: Request, auth=Depends(verify_api_key)):
    tier_limits = request.state.tier_limits
    if not tier_limits.get("detection_rules"):
        raise HTTPException(
            status_code=403,
            detail={"error": "Detection rule generation requires PRO tier", "upgrade_url": "https://cyberdudebivash.com/pricing"},
        )

    from .detection_rule_gen import DetectionRuleGenerator
    generator = DetectionRuleGenerator()
    rules = generator.generate(req.ioc_values, req.formats)
    return _response(rules, meta={"tier": request.state.tier, "formats": req.formats})


@app.get("/api/stix/bundle")
async def stix_bundle(request: Request, auth=Depends(verify_api_key)):
    tier_limits = request.state.tier_limits
    if not tier_limits.get("stix_export"):
        raise HTTPException(
            status_code=403,
            detail={"error": "STIX export requires PRO tier", "upgrade_url": "https://cyberdudebivash.com/pricing"},
        )
    bundles = intel_loader.get_stix_bundles()
    return _response({"bundles": bundles, "count": len(bundles)}, meta={"tier": request.state.tier})


@app.get("/api/usage")
async def usage_stats(request: Request, auth=Depends(verify_api_key)):
    stats = key_manager.get_usage_stats(request.state.key_id)
    stats["tier"] = request.state.tier
    stats["tier_limits"] = request.state.tier_limits
    return _response(stats)


# ---------------------------------------------------------------------------
# Admin Endpoints (internal — protected by master key)
# ---------------------------------------------------------------------------

ADMIN_KEY = os.environ.get("CDB_ADMIN_KEY", "")

async def verify_admin(x_admin_key: str = Header(..., alias="X-Admin-Key")):
    if not ADMIN_KEY or x_admin_key != ADMIN_KEY:
        raise HTTPException(status_code=403, detail="Admin access denied")


@app.post("/api/admin/keys/generate")
async def admin_generate_key(
    org_name: str = Query(...),
    tier: str = Query("FREE"),
    contact_email: str = Query(""),
    admin=Depends(verify_admin),
):
    if tier not in ("FREE", "PRO", "ENTERPRISE"):
        raise HTTPException(status_code=400, detail="Invalid tier")
    result = key_manager.generate_key(org_name, tier, contact_email)
    return _response(result)


@app.post("/api/admin/keys/revoke")
async def admin_revoke_key(key_id: str = Query(...), admin=Depends(verify_admin)):
    success = key_manager.revoke_key(key_id)
    if not success:
        raise HTTPException(status_code=404, detail="Key not found")
    return _response({"revoked": key_id})


@app.get("/api/admin/keys/list")
async def admin_list_keys(admin=Depends(verify_admin)):
    keys = []
    for kid, record in key_manager._keys.items():
        keys.append({
            "key_id": kid,
            "org_name": record.get("org_name", ""),
            "tier": record.get("tier", ""),
            "is_active": record.get("is_active", False),
            "total_requests": record.get("total_requests", 0),
            "created_at": record.get("created_at", ""),
        })
    return _response({"keys": keys, "total": len(keys)})


# ---------------------------------------------------------------------------
# Entry Point
# ---------------------------------------------------------------------------

def main():
    """Run the Intelligence API server."""
    uvicorn.run(
        "agent.v49_intelligence_api.api_server:app",
        host="0.0.0.0",
        port=8900,
        reload=False,
        log_level="info",
        access_log=True,
    )


if __name__ == "__main__":
    main()
