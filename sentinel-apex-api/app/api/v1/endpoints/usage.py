"""
SENTINEL APEX — Usage & Pipeline Ingest Endpoints
API usage statistics + pipeline → PG advisory ingest
"""
from __future__ import annotations

import json
import logging
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, HTTPException, Request

from app.auth.dependencies import AuthenticatedUser, get_current_user
from app.core.config import get_settings
from app.db.client import SupabaseDB
from app.middleware.rate_limit import rate_limiter
from app.schemas.models import (
    BatchIngestRequest,
    IngestResponse,
    UsageDetailResponse,
    UsageStats,
)

logger = logging.getLogger("sentinel.usage")
settings = get_settings()
router = APIRouter(tags=["Usage & Pipeline"])

# ── Usage Endpoint ────────────────────────────────────────────────────

TIER_LIMITS = {"free": 10, "pro": 1000, "enterprise": 100000, "mssp": 100000}


@router.get("/api/v1/usage", response_model=UsageDetailResponse)
async def get_usage(user: AuthenticatedUser = Depends(get_current_user)):
    """
    Get API usage statistics for the current authenticated context.
    Shows daily call count, limits, and per-endpoint breakdown.
    """
    today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
    daily_limit = TIER_LIMITS.get(user.tier.value, 10)

    # Get usage from rate limiter (in-memory)
    if user.api_key_id:
        key = f"apikey:{user.api_key_id[:24]}"
    else:
        key = f"jwt:{user.user_id[:20] if user.user_id else 'unknown'}"

    calls_today = rate_limiter.get_count(key)

    # Try to get per-endpoint breakdown from PG
    endpoints: dict[str, int] = {}
    try:
        if user.api_key_id:
            result = await SupabaseDB.query(
                "api_usage",
                select="endpoint",
                filters={
                    "api_key_id": f"eq.{user.api_key_id}",
                    "created_at": f"gte.{today}T00:00:00Z",
                },
            )
            for row in result["data"]:
                ep = row.get("endpoint", "unknown")
                endpoints[ep] = endpoints.get(ep, 0) + 1
    except Exception:
        pass  # PG usage tracking is best-effort

    return UsageDetailResponse(
        current=UsageStats(
            api_key_id=user.api_key_id or "session",
            tier=user.tier,
            daily_limit=daily_limit,
            calls_today=calls_today,
            calls_remaining=max(0, daily_limit - calls_today) if daily_limit > 0 else -1,
            period=today,
        ),
        endpoints=endpoints,
    )


# ── Pipeline Ingest Endpoint ──────────────────────────────────────────

@router.post("/api/v1/ingest", response_model=IngestResponse, tags=["Pipeline"])
async def ingest_advisories(body: BatchIngestRequest, request: Request):
    """
    Pipeline → API advisory ingest endpoint.
    Called by GitHub Actions pipeline to write processed advisories to Supabase PG.
    Authenticated via pipeline_secret (shared secret, NOT user auth).
    """
    # Validate pipeline secret
    if not settings.PIPELINE_SECRET:
        raise HTTPException(status_code=503, detail="Pipeline ingest not configured")

    if body.pipeline_secret != settings.PIPELINE_SECRET:
        logger.warning(f"Invalid pipeline secret from {request.client.host}")
        raise HTTPException(status_code=403, detail="Invalid pipeline secret")

    if not body.advisories:
        return IngestResponse(ingested=0, errors=0, advisory_ids=[])

    ingested_ids: list[str] = []
    error_count = 0

    for advisory in body.advisories:
        try:
            row = {
                "id": advisory.id,
                "title": advisory.title,
                "description": advisory.description,
                "summary_ai": advisory.summary_ai,
                "risk_score": advisory.risk_score,
                "confidence": advisory.confidence,
                "severity": advisory.severity.value if advisory.severity else None,
                "cvss": advisory.cvss,
                "epss": advisory.epss,
                "kev": advisory.kev,
                "cve_id": advisory.cve_id,
                "mitre_techniques": json.dumps(advisory.mitre_techniques) if advisory.mitre_techniques else "[]",
                "iocs": json.dumps(advisory.iocs) if advisory.iocs else "[]",
                "stix_bundle_url": advisory.stix_bundle_url,
                "defense_kit": json.dumps(advisory.defense_kit) if advisory.defense_kit else "{}",
                "source": advisory.source,
                "source_url": advisory.source_url,
                "tags": advisory.tags,
                "published_at": advisory.published_at.isoformat() if advisory.published_at else None,
                "ingested_at": datetime.now(timezone.utc).isoformat(),
            }

            await SupabaseDB.insert("advisories", row, upsert=True)
            ingested_ids.append(advisory.id)

        except Exception as e:
            logger.error(f"Ingest error for {advisory.id}: {e}")
            error_count += 1

    logger.info(f"Pipeline ingest: {len(ingested_ids)} ingested, {error_count} errors")

    return IngestResponse(
        ingested=len(ingested_ids),
        errors=error_count,
        advisory_ids=ingested_ids,
    )


@router.post("/api/v1/ingest/single", tags=["Pipeline"])
async def ingest_single(request: Request):
    """
    Single advisory ingest with raw JSON body.
    Simpler interface for pipeline integration.
    """
    # Validate via header
    secret = request.headers.get("X-Pipeline-Secret", "")
    if not settings.PIPELINE_SECRET or secret != settings.PIPELINE_SECRET:
        raise HTTPException(status_code=403, detail="Invalid pipeline secret")

    body = await request.json()
    advisory_id = body.get("id")
    if not advisory_id:
        raise HTTPException(status_code=400, detail="Missing advisory 'id' field")

    try:
        # Clean JSONB fields
        for field in ("mitre_techniques", "iocs"):
            if field in body and isinstance(body[field], (list, dict)):
                body[field] = json.dumps(body[field])
        if "defense_kit" in body and isinstance(body["defense_kit"], dict):
            body["defense_kit"] = json.dumps(body["defense_kit"])

        body["ingested_at"] = datetime.now(timezone.utc).isoformat()

        await SupabaseDB.insert("advisories", body, upsert=True)

        return {"status": "ok", "advisory_id": advisory_id}

    except Exception as e:
        logger.error(f"Single ingest error: {e}")
        raise HTTPException(status_code=500, detail=str(e))
