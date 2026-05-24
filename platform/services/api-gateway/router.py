"""
SENTINEL APEX API Gateway — Route Definitions
==============================================
All intelligence endpoints, proxied to downstream microservices.
"""
from __future__ import annotations

from typing import Any, List, Optional

from fastapi import APIRouter, Depends, Path, Query, Request, Response
from pydantic import BaseModel

from .auth import (
    CurrentUser,
    RequireEnterprise,
    RequireGovernment,
    RequireProPlus,
    TenantTier,
    get_current_user,
)


# ---------------------------------------------------------------------------
# Response Models
# ---------------------------------------------------------------------------
class IntelFeedResponse(BaseModel):
    schema_version: str
    count: int
    items: list[dict]
    tier: str
    next_cursor: Optional[str] = None

class AdvisoryResponse(BaseModel):
    id: str
    title: str
    severity: str
    risk_score: float
    source: str
    published: str
    apex_ai: Optional[dict] = None
    ioc_objects: Optional[list] = None
    cves: Optional[list] = None
    stix_bundle: Optional[dict] = None
    pdf_url: Optional[str] = None

class ThreatActorResponse(BaseModel):
    actor_id: str
    name: str
    aliases: list[str]
    mitre_group_id: Optional[str]
    nation_state: Optional[str]
    motivation: list[str]
    ttps: list[dict]
    campaigns: list[dict]
    iocs: list[dict]
    confidence: float

class IOCSearchResponse(BaseModel):
    query: str
    total: int
    results: list[dict]
    enrichment: Optional[dict] = None

class SigmaRuleResponse(BaseModel):
    rule_id: str
    title: str
    status: str
    level: str
    rule_yaml: str
    mitre_techniques: list[str]
    logsource: dict

class YARAResponse(BaseModel):
    rule_name: str
    rule_content: str
    meta: dict
    strings_count: int
    conditions: list[str]

# ---------------------------------------------------------------------------
# Router Builder
# ---------------------------------------------------------------------------
def build_router(config) -> APIRouter:
    from .proxy import IntelligenceProxy
    from .quota import QuotaEnforcer

    root = APIRouter()

    # -----------------------------------------------------------------------
    # V2 Intelligence API
    # -----------------------------------------------------------------------
    intel = APIRouter(prefix="/v2/intel", tags=["Intelligence"])

    @intel.get("/feed", response_model=IntelFeedResponse, summary="Get live threat intelligence feed")
    async def get_intel_feed(
        request: Request,
        limit: int = Query(10, ge=1, le=100),
        cursor: Optional[str] = Query(None),
        severity: Optional[str] = Query(None, regex="^(CRITICAL|HIGH|MEDIUM|LOW)$"),
        threat_type: Optional[str] = Query(None),
        source: Optional[str] = Query(None),
        user: CurrentUser = Depends(get_current_user),
    ):
        await QuotaEnforcer.check_and_increment(user.tenant_id, "intel_feed")
        return await IntelligenceProxy.get("/intel/feed", params={
            "limit": limit, "cursor": cursor,
            "severity": severity, "threat_type": threat_type,
            "source": source, "tier": user.tenant_tier,
        }, tenant_id=user.tenant_id)

    @intel.get("/advisory/{advisory_id}", response_model=AdvisoryResponse, summary="Get full advisory detail")
    async def get_advisory(
        request: Request,
        advisory_id: str = Path(..., regex=r"^intel--[0-9a-f]{24}$"),
        user: CurrentUser = Depends(get_current_user),
    ):
        await QuotaEnforcer.check_and_increment(user.tenant_id, "advisory_detail")
        return await IntelligenceProxy.get(
            f"/intel/advisory/{advisory_id}",
            params={"tier": user.tenant_tier},
            tenant_id=user.tenant_id,
        )

    @intel.get("/advisories", summary="List all advisories (paginated)")
    async def list_advisories(
        request: Request,
        page: int = Query(1, ge=1),
        per_page: int = Query(20, ge=1, le=200),
        severity: Optional[str] = None,
        user: CurrentUser = Depends(get_current_user),
    ):
        await QuotaEnforcer.check_and_increment(user.tenant_id, "advisory_list")
        return await IntelligenceProxy.get("/intel/advisories", params={
            "page": page, "per_page": per_page,
            "severity": severity, "tier": user.tenant_tier,
        }, tenant_id=user.tenant_id)

    # -----------------------------------------------------------------------
    # IOC Intelligence (PRO+)
    # -----------------------------------------------------------------------
    ioc = APIRouter(prefix="/v2/ioc", tags=["IOC Intelligence"])

    @ioc.get("/search", summary="Search IOC database")
    async def search_iocs(
        request: Request,
        q: str = Query(..., min_length=3, description="IOC value or hash"),
        ioc_type: Optional[str] = Query(None),
        limit: int = Query(20, ge=1, le=500),
        user: CurrentUser = Depends(RequireProPlus),
    ):
        user.require_feature("ioc_search_full")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "ioc_search")
        return await IntelligenceProxy.get("/ioc/search", params={
            "q": q, "type": ioc_type, "limit": limit, "tier": user.tenant_tier,
        }, tenant_id=user.tenant_id)

    @ioc.post("/enrich", summary="Enrich IOC with OSINT + AI analysis")
    async def enrich_ioc(
        request: Request,
        body: dict,
        user: CurrentUser = Depends(RequireProPlus),
    ):
        user.require_feature("intel_enriched")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "ioc_enrich")
        return await IntelligenceProxy.post("/ioc/enrich", body=body, tenant_id=user.tenant_id)

    # -----------------------------------------------------------------------
    # Threat Actor Intelligence (PRO+)
    # -----------------------------------------------------------------------
    actors = APIRouter(prefix="/v2/actors", tags=["Threat Actor Intelligence"])

    @actors.get("/{actor_id}", response_model=ThreatActorResponse, summary="Get threat actor profile")
    async def get_actor(
        request: Request,
        actor_id: str = Path(...),
        user: CurrentUser = Depends(RequireProPlus),
    ):
        user.require_feature("ai_actor_attribution")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "actor_lookup")
        return await IntelligenceProxy.get(f"/actors/{actor_id}", tenant_id=user.tenant_id)

    @actors.get("/", summary="List tracked threat actors")
    async def list_actors(
        request: Request,
        nation_state: Optional[str] = None,
        motivation: Optional[str] = None,
        user: CurrentUser = Depends(RequireProPlus),
    ):
        await QuotaEnforcer.check_and_increment(user.tenant_id, "actor_list")
        return await IntelligenceProxy.get("/actors", params={
            "nation_state": nation_state, "motivation": motivation,
        }, tenant_id=user.tenant_id)

    # -----------------------------------------------------------------------
    # Detection Engineering (ENTERPRISE+)
    # -----------------------------------------------------------------------
    detection = APIRouter(prefix="/v2/detection", tags=["Detection Engineering"])

    @detection.post("/sigma/generate", response_model=SigmaRuleResponse, summary="AI-generate Sigma rule from advisory")
    async def generate_sigma(
        request: Request,
        body: dict,
        user: CurrentUser = Depends(RequireEnterprise),
    ):
        user.require_feature("sigma_full")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "sigma_gen")
        return await IntelligenceProxy.post("/detection/sigma/generate", body=body, tenant_id=user.tenant_id)

    @detection.post("/yara/generate", response_model=YARAResponse, summary="AI-generate YARA rule from malware intel")
    async def generate_yara(
        request: Request,
        body: dict,
        user: CurrentUser = Depends(RequireEnterprise),
    ):
        user.require_feature("yara_generation")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "yara_gen")
        return await IntelligenceProxy.post("/detection/yara/generate", body=body, tenant_id=user.tenant_id)

    @detection.get("/rules", summary="Get detection rules library")
    async def get_rules(
        request: Request,
        platform: Optional[str] = Query(None, description="splunk|elastic|sentinel|chronicle"),
        mitre_technique: Optional[str] = Query(None),
        user: CurrentUser = Depends(RequireEnterprise),
    ):
        await QuotaEnforcer.check_and_increment(user.tenant_id, "rules_fetch")
        return await IntelligenceProxy.get("/detection/rules", params={
            "platform": platform, "technique": mitre_technique,
        }, tenant_id=user.tenant_id)

    # -----------------------------------------------------------------------
    # STIX/TAXII (PRO+)
    # -----------------------------------------------------------------------
    stix = APIRouter(prefix="/v2/stix", tags=["STIX/TAXII"])

    @stix.get("/bundle/{advisory_id}", summary="Get STIX 2.1 bundle for advisory")
    async def get_stix_bundle(
        request: Request,
        advisory_id: str = Path(...),
        user: CurrentUser = Depends(RequireProPlus),
    ):
        user.require_feature("stix_export")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "stix_export")
        return await IntelligenceProxy.get(f"/stix/bundle/{advisory_id}", tenant_id=user.tenant_id)

    @stix.get("/taxii/collections", summary="TAXII 2.1 collections list")
    async def taxii_collections(
        request: Request,
        user: CurrentUser = Depends(RequireEnterprise),
    ):
        user.require_feature("taxii_server")
        return await IntelligenceProxy.get("/stix/taxii/collections", tenant_id=user.tenant_id)

    # -----------------------------------------------------------------------
    # AI Intelligence Copilot (PRO+)
    # -----------------------------------------------------------------------
    ai = APIRouter(prefix="/v2/ai", tags=["AI Intelligence Copilot"])

    @ai.post("/copilot/query", summary="Query the AI threat intelligence copilot")
    async def ai_copilot_query(
        request: Request,
        body: dict,
        user: CurrentUser = Depends(RequireProPlus),
    ):
        user.require_feature("ai_summaries")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "ai_query")
        return await IntelligenceProxy.post("/ai/copilot/query", body=body, tenant_id=user.tenant_id)

    @ai.post("/threat-score", summary="AI-compute threat score for IOC/advisory")
    async def ai_threat_score(
        request: Request,
        body: dict,
        user: CurrentUser = Depends(RequireProPlus),
    ):
        user.require_feature("ai_enrichment_full")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "ai_threat_score")
        return await IntelligenceProxy.post("/ai/threat-score", body=body, tenant_id=user.tenant_id)

    @ai.post("/campaign-predict", summary="AI-predict campaign evolution")
    async def ai_campaign_predict(
        request: Request,
        body: dict,
        user: CurrentUser = Depends(RequireEnterprise),
    ):
        user.require_feature("ai_enrichment_full")
        return await IntelligenceProxy.post("/ai/campaign-predict", body=body, tenant_id=user.tenant_id)

    # -----------------------------------------------------------------------
    # SOC Automation (ENTERPRISE+)
    # -----------------------------------------------------------------------
    soc = APIRouter(prefix="/v2/soc", tags=["SOC Automation"])

    @soc.post("/triage", summary="AI-triage security alert")
    async def triage_alert(
        request: Request,
        body: dict,
        user: CurrentUser = Depends(RequireEnterprise),
    ):
        user.require_feature("soc_automation")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "soc_triage")
        return await IntelligenceProxy.post("/soc/triage", body=body, tenant_id=user.tenant_id)

    @soc.post("/hunt", summary="Execute AI threat hunt")
    async def threat_hunt(
        request: Request,
        body: dict,
        user: CurrentUser = Depends(RequireEnterprise),
    ):
        user.require_feature("threat_hunting")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "hunt_execute")
        return await IntelligenceProxy.post("/soc/hunt", body=body, tenant_id=user.tenant_id)

    @soc.get("/playbooks", summary="List automation playbooks")
    async def list_playbooks(
        request: Request,
        user: CurrentUser = Depends(RequireEnterprise),
    ):
        return await IntelligenceProxy.get("/soc/playbooks", tenant_id=user.tenant_id)

    @soc.post("/playbooks/{playbook_id}/execute", summary="Execute a playbook")
    async def execute_playbook(
        request: Request,
        playbook_id: str = Path(...),
        body: dict = None,
        user: CurrentUser = Depends(RequireEnterprise),
    ):
        user.require_permission("playbooks:execute")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "playbook_exec")
        return await IntelligenceProxy.post(f"/soc/playbooks/{playbook_id}/execute", body=body or {}, tenant_id=user.tenant_id)

    # -----------------------------------------------------------------------
    # PDF Reports
    # -----------------------------------------------------------------------
    reports = APIRouter(prefix="/v2/reports", tags=["Reports"])

    @reports.get("/pdf/{advisory_id}", summary="Get PDF report for advisory")
    async def get_pdf_report(
        request: Request,
        advisory_id: str = Path(...),
        user: CurrentUser = Depends(get_current_user),
    ):
        # Free tier gets basic PDF; PRO gets full enriched PDF
        if user.tenant_tier == TenantTier.FREE:
            user.require_feature("pdf_reports")
        await QuotaEnforcer.check_and_increment(user.tenant_id, "pdf_download")
        return await IntelligenceProxy.get(f"/reports/pdf/{advisory_id}", tenant_id=user.tenant_id)

    # -----------------------------------------------------------------------
    # Register all sub-routers
    # -----------------------------------------------------------------------
    root.include_router(intel)
    root.include_router(ioc)
    root.include_router(actors)
    root.include_router(detection)
    root.include_router(stix)
    root.include_router(ai)
    root.include_router(soc)
    root.include_router(reports)

    return root
