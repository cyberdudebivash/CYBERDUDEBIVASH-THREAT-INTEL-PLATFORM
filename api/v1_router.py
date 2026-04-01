"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — API V1 ROUTER v1.0                      ║
║  All /api/v1/ endpoints · Pydantic validated · Standardized responses     ║
║  Auth guard · Rate limiting · Billing enforcement · Zero-crash design     ║
╚══════════════════════════════════════════════════════════════════════════════╝
Endpoints:
  GET  /api/v1/threats              List threat advisories (paginated)
  GET  /api/v1/threats/{id}         Single threat by ID or CVE
  GET  /api/v1/iocs                 IOC intelligence feed
  POST /api/v1/predict              Agentic AI predictive analysis
  GET  /api/v1/identity-risk        Identity + stealer log risk
  GET  /api/v1/darkweb              Dark web intelligence
  GET  /api/v1/risk-score           Financial risk quantification
  GET  /api/v1/detections           MITRE ATT&CK + SIEM rules
  POST /api/v1/soar/action          SOAR workflow trigger
  GET  /api/v1/health               Platform health check
  GET  /api/v1/engines/status       All engine status
  GET  /api/v1/me                   API key info + quota
"""

from __future__ import annotations

import hashlib
import hmac
import json
import logging
import os
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

try:
    from fastapi import APIRouter, Depends, Header, HTTPException, Query, Request
    from fastapi.responses import JSONResponse
    _FASTAPI_OK = True
except ImportError:
    _FASTAPI_OK = False
    # Stub for syntax check when FastAPI not installed in build env
    class APIRouter:
        def get(self, *a, **kw): return lambda f: f
        def post(self, *a, **kw): return lambda f: f
    class Depends: pass
    class Header: pass
    class HTTPException(Exception): pass
    class Query: pass
    class Request: pass

from .schemas import (
    make_response, make_error,
    PredictRequest, SOARActionRequest,
)
from .rate_limiter import check_rate_limit, get_quota_remaining, get_tier_limit
from . import engine_connector as ec

logger = logging.getLogger("CDB-API-V1")

# ── Auth helpers ──────────────────────────────────────────────────────────────
BASE_DIR     = Path(__file__).parent.parent
AUTH_DB_PATH = BASE_DIR / "data" / "auth" / "api_keys.json"

# Tier → allowed scopes
TIER_SCOPES: Dict[str, List[str]] = {
    "FREE":       ["read"],
    "PRO":        ["read", "intel", "write"],
    "ENTERPRISE": ["read", "intel", "write", "admin"],
    "MSSP":       ["read", "intel", "write", "admin"],
}

# Endpoint → required scope + tier
ENDPOINT_REQUIREMENTS: Dict[str, Dict] = {
    "threats_list":    {"scope": "read",  "min_tier_rank": 0},
    "threats_detail":  {"scope": "read",  "min_tier_rank": 0},
    "iocs":            {"scope": "intel", "min_tier_rank": 1},   # PRO+
    "predict":         {"scope": "intel", "min_tier_rank": 1},   # PRO+
    "identity_risk":   {"scope": "intel", "min_tier_rank": 1},
    "darkweb":         {"scope": "intel", "min_tier_rank": 1},
    "risk_score":      {"scope": "read",  "min_tier_rank": 0},
    "detections":      {"scope": "intel", "min_tier_rank": 1},
    "soar":            {"scope": "write", "min_tier_rank": 2},   # ENTERPRISE+
    "health":          {"scope": None,    "min_tier_rank": 0},   # Public
    "engines_status":  {"scope": "read",  "min_tier_rank": 0},
    "me":              {"scope": None,    "min_tier_rank": 0},   # Key owner info
}

TIER_RANK = {"FREE": 0, "PRO": 1, "ENTERPRISE": 2, "MSSP": 3}


def _load_api_keys() -> Dict:
    """Load API key database. Returns empty dict on failure."""
    try:
        if AUTH_DB_PATH.exists():
            with open(AUTH_DB_PATH, encoding="utf-8") as f:
                return json.load(f)
    except Exception as e:
        logger.warning(f"api_keys.json load failed: {e}")
    return {}


def _validate_api_key(raw_key: str) -> Optional[Dict]:
    """
    Validates API key using constant-time SHA-256 comparison.
    Returns key record or None.
    """
    if not raw_key or len(raw_key) < 10:
        return None
    key_hash = "SHA256:" + hashlib.sha256(raw_key.encode()).hexdigest()
    db = _load_api_keys()
    for key_id, record in db.items():
        stored_hash = record.get("key_hash", "")
        if stored_hash.startswith("SHA256:"):
            # Constant-time comparison (hmac.compare_digest)
            if hmac.compare_digest(stored_hash.encode(), key_hash.encode()):
                if not record.get("revoked", False):
                    return {**record, "key_id": key_id}
    return None


def _get_dev_key_record() -> Dict:
    """Fallback dev key record when no real keys exist yet."""
    return {
        "key_id": "DEV_KEY",
        "tier": "FREE",
        "owner": "development",
        "scopes": ["read"],
        "revoked": False,
    }


def _get_auth(x_api_key: Optional[str]) -> Dict:
    """
    Authenticate from X-API-Key header.
    Returns auth record dict. Never raises directly — returns error dict.
    """
    if not x_api_key:
        return {"error": "Missing X-API-Key header", "code": 401}

    record = _validate_api_key(x_api_key)
    if not record:
        # Allow demo key for development
        demo_key = os.getenv("CDB_DEMO_API_KEY", "")
        if demo_key and hmac.compare_digest(x_api_key, demo_key):
            return _get_dev_key_record()
        return {"error": "Invalid or revoked API key", "code": 401}

    return record


def _check_scope(record: Dict, endpoint: str) -> Optional[Dict]:
    """Returns error dict if scope check fails, None if OK."""
    req = ENDPOINT_REQUIREMENTS.get(endpoint, {})
    required_scope = req.get("scope")
    min_rank = req.get("min_tier_rank", 0)

    if required_scope is None:
        return None  # Public endpoint

    tier = record.get("tier", "FREE").upper()
    tier_rank = TIER_RANK.get(tier, 0)

    if tier_rank < min_rank:
        tiers = ["FREE", "PRO", "ENTERPRISE", "MSSP"]
        required_tier = tiers[min_rank] if min_rank < len(tiers) else "ENTERPRISE"
        return {
            "error": f"This endpoint requires {required_tier} tier or higher",
            "code": 403,
        }

    allowed_scopes = TIER_SCOPES.get(tier, ["read"])
    if required_scope not in allowed_scopes:
        return {
            "error": f"Insufficient scope. Required: {required_scope}",
            "code": 403,
        }

    return None


def _enforce_rate_limit(record: Dict, req_id: str) -> Optional[JSONResponse]:
    """Returns JSONResponse if rate limited, None if OK."""
    try:
        tier = record.get("tier", "FREE")
        key_hash = record.get("key_hash", record.get("key_id", "unknown"))
        allowed, count, limit = check_rate_limit(key_hash, tier)
        if not allowed:
            return JSONResponse(
                status_code=429,
                content=make_error(
                    f"Rate limit exceeded. Tier {tier} allows {limit} requests/day. "
                    f"Upgrade at https://tools.cyberdudebivash.com/",
                    429, req_id,
                ),
            )
    except Exception as e:
        logger.warning(f"Rate limit check exception: {e}")
    return None


if not _FASTAPI_OK:
    # Stub mode — no router
    router = None
else:
    router = APIRouter(prefix="/api/v1", tags=["Sentinel APEX v1"])

    # ── /health ────────────────────────────────────────────────────────────────
    @router.get("/health", tags=["Platform"], summary="Platform health check")
    async def health_check():
        """Public endpoint — no auth required."""
        t0 = time.monotonic()
        engines = ec.get_engine_status()
        operational = sum(1 for e in engines if e["status"] == "OPERATIONAL")
        return JSONResponse(make_response({
            "platform_status": "OPERATIONAL",
            "engines_operational": operational,
            "engines_total": len(engines),
            "api_version": "v1",
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }, start_time=t0))

    # ── /engines/status ────────────────────────────────────────────────────────
    @router.get("/engines/status", summary="All engine status")
    async def engines_status(x_api_key: Optional[str] = Header(default=None)):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        scope_err = _check_scope(record, "engines_status")
        if scope_err:
            return JSONResponse(status_code=scope_err["code"],
                                content=make_error(scope_err["error"], scope_err["code"], req_id))

        rl = _enforce_rate_limit(record, req_id)
        if rl:
            return rl

        return JSONResponse(make_response({
            "engines": ec.get_engine_status(),
        }, req_id, t0))

    # ── /me ────────────────────────────────────────────────────────────────────
    @router.get("/me", summary="API key information and quota")
    async def get_me(x_api_key: Optional[str] = Header(default=None)):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        tier = record.get("tier", "FREE")
        key_hash = record.get("key_hash", record.get("key_id", "unknown"))
        limit = get_tier_limit(tier)
        remaining = get_quota_remaining(key_hash, tier)

        return JSONResponse(make_response({
            "key_id": record.get("key_id", ""),
            "owner": record.get("owner", ""),
            "tier": tier,
            "scopes": TIER_SCOPES.get(tier.upper(), ["read"]),
            "quota": {
                "daily_limit": limit if limit != -1 else "unlimited",
                "remaining_today": remaining if limit != -1 else "unlimited",
            },
            "upgrade_url": "https://tools.cyberdudebivash.com/",
        }, req_id, t0))

    # ── GET /threats ───────────────────────────────────────────────────────────
    @router.get("/threats", summary="List threat advisories")
    async def list_threats(
        x_api_key: Optional[str] = Header(default=None),
        page: int = Query(default=1, ge=1, le=1000),
        per_page: int = Query(default=20, ge=1, le=100),
        severity: Optional[str] = Query(default=None, regex="^(CRITICAL|HIGH|MEDIUM|LOW)$"),
        cve: Optional[str] = Query(default=None, max_length=30),
    ):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        scope_err = _check_scope(record, "threats_list")
        if scope_err:
            return JSONResponse(status_code=scope_err["code"],
                                content=make_error(scope_err["error"], scope_err["code"], req_id))

        rl = _enforce_rate_limit(record, req_id)
        if rl:
            return rl

        # Tier-based per_page cap
        tier = record.get("tier", "FREE").upper()
        if tier == "FREE":
            per_page = min(per_page, 10)

        try:
            result = ec.get_threats(page, per_page, severity, cve)
            return JSONResponse(make_response({
                "threats": result["threats"],
                "pagination": {
                    "total": result["total"],
                    "page": result["page"],
                    "per_page": result["per_page"],
                    "total_pages": result["total_pages"],
                },
            }, req_id, t0))
        except Exception as e:
            logger.error(f"list_threats error: {e}", exc_info=True)
            return JSONResponse(status_code=500,
                                content=make_error("Internal error", 500, req_id))

    # ── GET /threats/{id} ──────────────────────────────────────────────────────
    @router.get("/threats/{threat_id}", summary="Get single threat by ID or CVE")
    async def get_threat(
        threat_id: str,
        x_api_key: Optional[str] = Header(default=None),
    ):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        # Sanitize
        if len(threat_id) > 100 or not threat_id.replace("-", "").replace("_", "").isalnum():
            return JSONResponse(status_code=400,
                                content=make_error("Invalid threat_id format", 400, req_id))

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        rl = _enforce_rate_limit(record, req_id)
        if rl:
            return rl

        try:
            threat = ec.get_threat_by_id(threat_id)
            if threat is None:
                return JSONResponse(status_code=404,
                                    content=make_error(f"Threat '{threat_id}' not found", 404, req_id))
            return JSONResponse(make_response({"threat": threat}, req_id, t0))
        except Exception as e:
            logger.error(f"get_threat error: {e}", exc_info=True)
            return JSONResponse(status_code=500,
                                content=make_error("Internal error", 500, req_id))

    # ── GET /iocs ──────────────────────────────────────────────────────────────
    @router.get("/iocs", summary="IOC intelligence feed")
    async def list_iocs(
        x_api_key: Optional[str] = Header(default=None),
        page: int = Query(default=1, ge=1),
        per_page: int = Query(default=50, ge=1, le=200),
        ioc_type: Optional[str] = Query(default=None,
                                         regex="^(ipv4|sha256|md5|url|domain|manifest_ioc)$"),
        min_confidence: float = Query(default=0.0, ge=0.0, le=1.0),
    ):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        scope_err = _check_scope(record, "iocs")
        if scope_err:
            return JSONResponse(status_code=scope_err["code"],
                                content=make_error(scope_err["error"], scope_err["code"], req_id))

        rl = _enforce_rate_limit(record, req_id)
        if rl:
            return rl

        try:
            result = ec.get_iocs(page, per_page, ioc_type, min_confidence)
            return JSONResponse(make_response({
                "iocs": result["iocs"],
                "iocs_by_type": result["iocs_by_type"],
                "pagination": {
                    "total": result["total"],
                    "page": result["page"],
                    "per_page": result["per_page"],
                },
            }, req_id, t0))
        except Exception as e:
            logger.error(f"list_iocs error: {e}", exc_info=True)
            return JSONResponse(status_code=500,
                                content=make_error("Internal error", 500, req_id))

    # ── POST /predict ──────────────────────────────────────────────────────────
    @router.post("/predict", summary="Agentic AI predictive threat analysis")
    async def predict(
        body: PredictRequest,
        x_api_key: Optional[str] = Header(default=None),
    ):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        scope_err = _check_scope(record, "predict")
        if scope_err:
            return JSONResponse(status_code=scope_err["code"],
                                content=make_error(scope_err["error"], scope_err["code"], req_id))

        rl = _enforce_rate_limit(record, req_id)
        if rl:
            return rl

        try:
            result = ec.get_predictions(context=body.context)
            if not body.include_supply_chain:
                result.pop("supply_chain_summary", None)
            if not body.include_actor_attribution:
                result.pop("actor_attribution_available", None)
            return JSONResponse(make_response(result, req_id, t0))
        except Exception as e:
            logger.error(f"predict error: {e}", exc_info=True)
            return JSONResponse(status_code=500,
                                content=make_error("Internal error", 500, req_id))

    # ── GET /identity-risk ─────────────────────────────────────────────────────
    @router.get("/identity-risk", summary="Identity intelligence and stealer log risk")
    async def identity_risk(
        x_api_key: Optional[str] = Header(default=None),
    ):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        scope_err = _check_scope(record, "identity_risk")
        if scope_err:
            return JSONResponse(status_code=scope_err["code"],
                                content=make_error(scope_err["error"], scope_err["code"], req_id))

        rl = _enforce_rate_limit(record, req_id)
        if rl:
            return rl

        try:
            return JSONResponse(make_response(ec.get_identity_risk(), req_id, t0))
        except Exception as e:
            logger.error(f"identity_risk error: {e}", exc_info=True)
            return JSONResponse(status_code=500,
                                content=make_error("Internal error", 500, req_id))

    # ── GET /darkweb ───────────────────────────────────────────────────────────
    @router.get("/darkweb", summary="Dark web intelligence alerts")
    async def darkweb(
        x_api_key: Optional[str] = Header(default=None),
    ):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        scope_err = _check_scope(record, "darkweb")
        if scope_err:
            return JSONResponse(status_code=scope_err["code"],
                                content=make_error(scope_err["error"], scope_err["code"], req_id))

        rl = _enforce_rate_limit(record, req_id)
        if rl:
            return rl

        try:
            return JSONResponse(make_response(ec.get_darkweb_intel(), req_id, t0))
        except Exception as e:
            logger.error(f"darkweb error: {e}", exc_info=True)
            return JSONResponse(status_code=500,
                                content=make_error("Internal error", 500, req_id))

    # ── GET /risk-score ────────────────────────────────────────────────────────
    @router.get("/risk-score", summary="Financial risk quantification")
    async def risk_score(
        x_api_key: Optional[str] = Header(default=None),
        limit: int = Query(default=20, ge=1, le=100),
    ):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        scope_err = _check_scope(record, "risk_score")
        if scope_err:
            return JSONResponse(status_code=scope_err["code"],
                                content=make_error(scope_err["error"], scope_err["code"], req_id))

        rl = _enforce_rate_limit(record, req_id)
        if rl:
            return rl

        try:
            return JSONResponse(make_response(ec.get_risk_scores(limit), req_id, t0))
        except Exception as e:
            logger.error(f"risk_score error: {e}", exc_info=True)
            return JSONResponse(status_code=500,
                                content=make_error("Internal error", 500, req_id))

    # ── GET /detections ────────────────────────────────────────────────────────
    @router.get("/detections", summary="MITRE ATT&CK TTP coverage and SIEM rules")
    async def detections(
        x_api_key: Optional[str] = Header(default=None),
        limit: int = Query(default=50, ge=1, le=200),
    ):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        scope_err = _check_scope(record, "detections")
        if scope_err:
            return JSONResponse(status_code=scope_err["code"],
                                content=make_error(scope_err["error"], scope_err["code"], req_id))

        rl = _enforce_rate_limit(record, req_id)
        if rl:
            return rl

        try:
            return JSONResponse(make_response(ec.get_detections(limit), req_id, t0))
        except Exception as e:
            logger.error(f"detections error: {e}", exc_info=True)
            return JSONResponse(status_code=500,
                                content=make_error("Internal error", 500, req_id))

    # ── POST /soar/action ──────────────────────────────────────────────────────
    @router.post("/soar/action", summary="Trigger SOAR workflow action")
    async def soar_action(
        body: SOARActionRequest,
        x_api_key: Optional[str] = Header(default=None),
    ):
        t0 = time.monotonic()
        req_id = str(uuid.uuid4())

        record = _get_auth(x_api_key)
        if "error" in record:
            return JSONResponse(status_code=record["code"],
                                content=make_error(record["error"], record["code"], req_id))

        scope_err = _check_scope(record, "soar")
        if scope_err:
            return JSONResponse(status_code=scope_err["code"],
                                content=make_error(scope_err["error"], scope_err["code"], req_id))

        rl = _enforce_rate_limit(record, req_id)
        if rl:
            return rl

        # Destructive actions always require MSSP tier
        destructive = body.action_type in ("BLOCK_IP", "CREATE_INCIDENT")
        tier = record.get("tier", "FREE").upper()
        if destructive and not body.dry_run and tier != "MSSP":
            return JSONResponse(
                status_code=403,
                content=make_error(
                    "Live execution of destructive SOAR actions requires MSSP tier. "
                    "Use dry_run=true for simulation.",
                    403, req_id,
                ),
            )

        try:
            result = ec.get_soar_data(
                action_type=body.action_type,
                target=body.target,
                playbook=body.playbook,
            )
            result["dry_run"] = body.dry_run
            return JSONResponse(make_response(result, req_id, t0))
        except Exception as e:
            logger.error(f"soar_action error: {e}", exc_info=True)
            return JSONResponse(status_code=500,
                                content=make_error("Internal error", 500, req_id))
