"""
SENTINEL APEX — Feed Endpoints
Paginated threat intelligence feed, advisory detail, search
"""
from __future__ import annotations

import logging
from typing import Optional

from fastapi import APIRouter, Depends, HTTPException, Query

from app.auth.dependencies import (
    AuthenticatedUser,
    get_current_user,
    get_optional_user,
    require_tier,
)
from app.db.client import SupabaseDB
from app.middleware.rate_limit import rate_limiter
from app.schemas.models import (
    AdvisoryDetail,
    AdvisorySummary,
    FeedResponse,
    SeverityEnum,
    TierEnum,
)

logger = logging.getLogger("sentinel.feed")
router = APIRouter(prefix="/api/v1", tags=["Threat Intelligence Feed"])

# Fields to select for feed listing (excludes heavy fields)
FEED_SELECT = (
    "id,title,severity,risk_score,confidence,cvss,epss,kev,"
    "cve_id,source,published_at,ingested_at,summary_ai,tags"
)

# Full fields for detail view
DETAIL_SELECT = (
    "id,title,description,summary_ai,severity,risk_score,confidence,"
    "cvss,epss,kev,cve_id,mitre_techniques,iocs,stix_bundle_url,"
    "defense_kit,source,source_url,tags,published_at,ingested_at,updated_at"
)


@router.get("/feed", response_model=FeedResponse)
async def get_feed(
    page: int = Query(1, ge=1, description="Page number"),
    page_size: int = Query(25, ge=1, le=100, description="Results per page"),
    severity: Optional[SeverityEnum] = Query(None, description="Filter by severity"),
    min_risk_score: Optional[float] = Query(None, ge=0, le=100, description="Minimum risk score"),
    kev_only: bool = Query(False, description="Show only KEV-listed advisories"),
    source: Optional[str] = Query(None, description="Filter by source"),
    cve_id: Optional[str] = Query(None, description="Filter by CVE ID"),
    sort_by: str = Query("published_at", pattern="^(published_at|risk_score|ingested_at)$"),
    sort_order: str = Query("desc", pattern="^(asc|desc)$"),
    user: Optional[AuthenticatedUser] = Depends(get_optional_user),
):
    """
    Paginated threat intelligence feed.

    **Free tier**: Latest 10 advisories, 10 requests/day
    **Pro tier**: Full historical feed, 1000 requests/day
    **Enterprise**: Unlimited access with custom filters
    """
    # Determine limits based on tier
    tier = user.tier if user else TierEnum.FREE
    max_results = 10 if tier == TierEnum.FREE else 100

    # Clamp page_size for free tier
    if tier == TierEnum.FREE:
        page_size = min(page_size, 10)

    # Build filters
    filters: dict[str, str] = {}
    if severity:
        filters["severity"] = f"eq.{severity.value}"
    if min_risk_score is not None:
        filters["risk_score"] = f"gte.{min_risk_score}"
    if kev_only:
        filters["kev"] = "eq.true"
    if source:
        filters["source"] = f"eq.{source}"
    if cve_id:
        filters["cve_id"] = f"eq.{cve_id}"

    offset = (page - 1) * page_size

    # Query with count
    result = await SupabaseDB.query(
        "advisories",
        select=FEED_SELECT,
        filters=filters,
        order=f"{sort_by}.{sort_order}",
        limit=page_size,
        offset=offset,
        count=True,
    )

    total = result.get("count", len(result["data"]))
    advisories = [AdvisorySummary(**row) for row in result["data"]]

    # Free tier: strip AI summaries after 3/day
    if tier == TierEnum.FREE and user and user.api_key_id:
        ai_key = f"ai_summary:{user.api_key_id}"
        ai_count = rate_limiter.get_count(ai_key)
        if ai_count >= 3:
            for a in advisories:
                a.summary_ai = None

    return FeedResponse(
        data=advisories,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(offset + page_size) < total,
    )


@router.get("/feed/{advisory_id}", response_model=AdvisoryDetail)
async def get_advisory(
    advisory_id: str,
    user: Optional[AuthenticatedUser] = Depends(get_optional_user),
):
    """
    Get full advisory detail by ID.
    Includes IOCs, MITRE techniques, STIX bundle URL, and defense kit.
    """
    try:
        result = await SupabaseDB.query(
            "advisories",
            select=DETAIL_SELECT,
            filters={"id": f"eq.{advisory_id}"},
            single=True,
        )
    except Exception:
        raise HTTPException(status_code=404, detail=f"Advisory {advisory_id} not found")

    advisory = result["data"]

    # Gate STIX downloads for non-pro users
    tier = user.tier if user else TierEnum.FREE
    if tier == TierEnum.FREE:
        advisory["stix_bundle_url"] = None
        advisory["defense_kit"] = {}

    return AdvisoryDetail(**advisory)


@router.get("/search")
async def search_advisories(
    q: str = Query(..., min_length=2, max_length=500, description="Search query"),
    page: int = Query(1, ge=1),
    page_size: int = Query(25, ge=1, le=100),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.PRO, TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    """
    Full-text search across all advisories.
    **Pro+ tier required.**
    """
    # Use PostgreSQL full-text search via PostgREST
    offset = (page - 1) * page_size

    # Build tsquery from search terms
    terms = q.strip().split()
    tsquery = " & ".join(terms)

    result = await SupabaseDB.query(
        "advisories",
        select=FEED_SELECT,
        filters={"search_vector": f"fts.{tsquery}"},
        order="risk_score.desc",
        limit=page_size,
        offset=offset,
        count=True,
    )

    total = result.get("count", len(result["data"]))
    advisories = [AdvisorySummary(**row) for row in result["data"]]

    return FeedResponse(
        data=advisories,
        total=total,
        page=page,
        page_size=page_size,
        has_next=(offset + page_size) < total,
    )


@router.get("/mitre/coverage")
async def mitre_coverage(
    user: Optional[AuthenticatedUser] = Depends(get_optional_user),
):
    """
    MITRE ATT&CK technique coverage statistics.
    Shows which techniques are covered by current advisories.
    """
    result = await SupabaseDB.query(
        "advisories",
        select="mitre_techniques",
        filters={"mitre_techniques": "neq.[]"},
    )

    technique_counts: dict[str, int] = {}
    for row in result["data"]:
        techniques = row.get("mitre_techniques", [])
        if isinstance(techniques, list):
            for t in techniques:
                tid = t.get("technique_id") if isinstance(t, dict) else str(t)
                if tid:
                    technique_counts[tid] = technique_counts.get(tid, 0) + 1

    return {
        "total_techniques": len(technique_counts),
        "total_advisories_with_mitre": len(result["data"]),
        "techniques": dict(sorted(technique_counts.items(), key=lambda x: x[1], reverse=True)),
    }
