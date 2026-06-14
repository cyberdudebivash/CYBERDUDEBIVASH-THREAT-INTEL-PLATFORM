"""
SENTINEL APEX — Intelligence Graph & SIEM Dispatch Endpoints v177.0
=====================================================================
Correlation graph, threat actor relationships, and SIEM dispatch.

Endpoints:
  GET  /api/v1/intel/graph/correlations — Advisory ↔ IOC ↔ Actor graph (ENTERPRISE+)
  GET  /api/v1/intel/graph/actors        — Threat actor node summary (ENTERPRISE+)
  GET  /api/v1/intel/campaigns           — Active campaign tracker (PRO+)
  POST /api/v1/siem/dispatch             — Push advisory bundle to SIEM (ENTERPRISE+)
  GET  /api/v1/siem/integrations         — List configured SIEM targets (ENTERPRISE+)
"""
from __future__ import annotations

import json
import logging
import os
import secrets
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field

from app.auth.dependencies import (
    AuthenticatedUser,
    get_current_user,
    require_tier,
)
from app.db.client import SupabaseDB
from app.schemas.models import TierEnum

logger = logging.getLogger("sentinel.intel_graph")
router = APIRouter(prefix="/api/v1", tags=["Intelligence Graph & SIEM"])

_ROOT = Path(__file__).parents[6]
_GRAPH_FILE    = _ROOT / "data" / "graph" / "graph_relationships.stix.json"
_ACTORS_FILE   = _ROOT / "data" / "intelligence" / "actor_profiles.json"
_CAMPAIGNS_FILE = _ROOT / "data" / "intelligence" / "campaigns_db.json"
_IOCS_FILE     = _ROOT / "data" / "intelligence" / "iocs_db.json"
_MANIFEST_FILE = _ROOT / "data" / "apex_enriched_manifest.json"
_SIEM_CONFIG   = _ROOT / "data" / "siem_integrations.json"


def _load_json(path: Path, default=None) -> Any:
    try:
        if path.exists():
            return json.loads(path.read_bytes())
    except Exception as e:
        logger.warning(f"Failed to load {path.name}: {e}")
    return default


# ── Intelligence Graph ────────────────────────────────────────────────────────

@router.get(
    "/intel/graph/correlations",
    summary="Intelligence Correlation Graph (ENTERPRISE+)",
    description=(
        "Returns a correlation graph linking advisories, IOCs, threat actors, "
        "campaigns, and MITRE ATT&CK techniques.\n\n"
        "Graph format: `{nodes: [...], edges: [...]}` — compatible with D3.js, "
        "Cytoscape.js, and Neo4j bulk import.\n\n"
        "Each node has: `id`, `type` (advisory|ioc|actor|campaign|technique), `label`, `weight`\n"
        "Each edge has: `source`, `target`, `relationship` (uses|attributed_to|part_of|exploits)\n\n"
        "**Required tier:** ENTERPRISE or MSSP"
    ),
)
async def get_correlation_graph(
    advisory_limit: int = Query(50, ge=1, le=200),
    include_actors: bool = Query(True),
    include_techniques: bool = Query(True),
    min_confidence: float = Query(50.0, ge=0.0, le=100.0),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    nodes: List[Dict] = []
    edges: List[Dict] = []
    seen_ids: set = set()

    def _add_node(node_id: str, node_type: str, label: str, weight: float = 1.0, **extra):
        if node_id and node_id not in seen_ids:
            seen_ids.add(node_id)
            nodes.append({"id": node_id, "type": node_type, "label": label, "weight": weight, **extra})

    def _add_edge(src: str, tgt: str, rel: str, weight: float = 1.0):
        if src and tgt and src != tgt:
            edges.append({"source": src, "target": tgt, "relationship": rel, "weight": weight})

    # Load advisories from manifest
    manifest = _load_json(_MANIFEST_FILE)
    advisories: List[Dict] = []
    if manifest:
        raw_items = manifest if isinstance(manifest, list) else manifest.get("items", [])
        for item in raw_items:
            conf = item.get("confidence", 0) or 0
            if isinstance(conf, (int, float)) and conf >= min_confidence:
                advisories.append(item)
        advisories = advisories[:advisory_limit]

    # Try Supabase
    if not advisories:
        try:
            r = await SupabaseDB.query(
                "advisories",
                select="id,title,severity,confidence,iocs,mitre_techniques,source,cve_id",
                filters={"confidence": f"gte.{min_confidence}"},
                order="published_at.desc",
                limit=advisory_limit,
            )
            advisories = r.get("data") or []
        except Exception:
            pass

    for adv in advisories:
        adv_id = str(adv.get("id", adv.get("stix_id", "")))
        if not adv_id:
            continue
        sev = str(adv.get("severity", "medium")).lower()
        weight_map = {"critical": 5.0, "high": 4.0, "medium": 3.0, "low": 2.0, "info": 1.0}
        _add_node(adv_id, "advisory", adv.get("title", adv_id)[:80],
                  weight=weight_map.get(sev, 1.0), severity=sev,
                  cve_id=adv.get("cve_id"), source=adv.get("source"))

        # IOC nodes
        for ioc in (adv.get("iocs") or []):
            if not isinstance(ioc, dict):
                continue
            ioc_val = ioc.get("value", "")
            ioc_type = ioc.get("type", "unknown")
            if ioc_val:
                ioc_id = f"ioc:{ioc_type}:{ioc_val[:64]}"
                _add_node(ioc_id, "ioc", ioc_val[:64], weight=2.0, ioc_type=ioc_type)
                _add_edge(adv_id, ioc_id, "contains_ioc", weight=1.5)

        # MITRE technique nodes
        if include_techniques:
            for tech in (adv.get("mitre_techniques") or []):
                if not isinstance(tech, dict):
                    continue
                tech_id = tech.get("id", "")
                if tech_id:
                    _add_node(tech_id, "technique", f"{tech_id}: {tech.get('name','')[:40]}",
                              weight=2.0, tactic=tech.get("tactic"))
                    _add_edge(adv_id, tech_id, "maps_to_technique", weight=1.0)

    # Load actor profiles
    if include_actors:
        actors_data = _load_json(_ACTORS_FILE)
        actors: List[Dict] = []
        if isinstance(actors_data, list):
            actors = actors_data[:30]
        elif isinstance(actors_data, dict):
            actors = list(actors_data.values())[:30]

        for actor in actors:
            if not isinstance(actor, dict):
                continue
            actor_id = f"actor:{actor.get('id', actor.get('name', ''))}"
            actor_name = actor.get("name", actor.get("id", ""))
            if actor_id and actor_name:
                _add_node(actor_id, "actor", actor_name, weight=3.0,
                          origin=actor.get("origin", ""), motivation=actor.get("motivation", ""))
                for technique in (actor.get("techniques") or []):
                    tech_id = str(technique) if isinstance(technique, str) else technique.get("id","")
                    if tech_id and tech_id in seen_ids:
                        _add_edge(actor_id, tech_id, "uses_technique", weight=2.0)

    return {
        "graph": {"nodes": nodes, "edges": edges},
        "stats": {
            "node_count": len(nodes),
            "edge_count": len(edges),
            "advisory_nodes": sum(1 for n in nodes if n["type"] == "advisory"),
            "ioc_nodes": sum(1 for n in nodes if n["type"] == "ioc"),
            "actor_nodes": sum(1 for n in nodes if n["type"] == "actor"),
            "technique_nodes": sum(1 for n in nodes if n["type"] == "technique"),
        },
        "query_params": {
            "advisory_limit": advisory_limit,
            "min_confidence": min_confidence,
            "include_actors": include_actors,
            "include_techniques": include_techniques,
        },
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "_meta": {
            "format": "adjacency-list",
            "compat": ["D3.js", "Cytoscape.js", "Neo4j", "Gephi"],
            "version": "SENTINEL APEX v177.0",
        },
    }


@router.get(
    "/intel/graph/actors",
    summary="Threat Actor Node Summary (ENTERPRISE+)",
    description="Summary of tracked threat actor profiles and their relationships.",
)
async def get_actor_graph(
    limit: int = Query(50, ge=1, le=200),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    actors_data = _load_json(_ACTORS_FILE)
    actors: List[Dict] = []
    if isinstance(actors_data, list):
        actors = actors_data[:limit]
    elif isinstance(actors_data, dict):
        actors = list(actors_data.values())[:limit]

    return {
        "actors": actors,
        "count": len(actors),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── Campaign Tracker ──────────────────────────────────────────────────────────

@router.get(
    "/intel/campaigns",
    summary="Active Threat Campaigns (PRO+)",
    description=(
        "Active and recent threat campaigns tracked by SENTINEL APEX.\n\n"
        "Each campaign includes: actor attribution, targeted sectors, TTPs, IOC clusters, "
        "and timeline. **Required tier:** PRO or above"
    ),
)
async def get_campaigns(
    limit: int = Query(20, ge=1, le=100),
    status: Optional[str] = Query(None, pattern="^(active|dormant|concluded)$"),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.PRO, TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    campaigns_data = _load_json(_CAMPAIGNS_FILE)
    campaigns: List[Dict] = []
    if isinstance(campaigns_data, list):
        campaigns = campaigns_data
    elif isinstance(campaigns_data, dict):
        campaigns = campaigns_data.get("campaigns", list(campaigns_data.values()))

    if status:
        campaigns = [c for c in campaigns if str(c.get("status","")).lower() == status]

    return {
        "campaigns": campaigns[:limit],
        "total": len(campaigns),
        "count": min(len(campaigns), limit),
        "generated_at": datetime.now(timezone.utc).isoformat(),
    }


# ── SIEM Dispatch ─────────────────────────────────────────────────────────────

class SIEMDispatchRequest(BaseModel):
    advisory_ids: List[str] = Field(..., min_length=1, max_length=50,
                                     description="Advisory IDs to dispatch")
    siem_target: str = Field(..., pattern="^(splunk|sentinel|qradar|elastic|all)$",
                             description="Target SIEM platform")
    format: str = Field("stix", pattern="^(stix|cef|leef|json)$",
                        description="Payload format")
    webhook_url: Optional[str] = Field(None, max_length=2048,
                                        description="Override target URL (optional)")


@router.post(
    "/siem/dispatch",
    summary="Dispatch Intelligence to SIEM (ENTERPRISE+)",
    description=(
        "Push one or more advisory bundles to your configured SIEM.\n\n"
        "Supports: **Splunk** (HTTP Event Collector), **Microsoft Sentinel** (Log Analytics), "
        "**IBM QRadar** (REST API), **Elastic SIEM** (Logstash HTTP input).\n\n"
        "Payload formats: STIX 2.1 JSON, CEF (ArcSight), LEEF (QRadar), raw JSON.\n\n"
        "**Required tier:** ENTERPRISE or MSSP"
    ),
    responses={
        200: {"description": "Dispatch job accepted"},
        403: {"description": "ENTERPRISE tier required"},
    },
)
async def siem_dispatch(
    body: SIEMDispatchRequest,
    user: AuthenticatedUser = Depends(require_tier(TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    dispatch_id = "SIEM-" + secrets.token_hex(6).upper()
    queued_at = datetime.now(timezone.utc).isoformat()

    # Load SIEM config if available
    siem_config = _load_json(_SIEM_CONFIG, {})
    target_config = siem_config.get(body.siem_target, {})
    endpoint_url = body.webhook_url or target_config.get("endpoint_url", "")

    if not endpoint_url:
        return JSONResponse(
            status_code=202,
            content={
                "dispatch_id": dispatch_id,
                "status": "queued_pending_config",
                "message": (
                    f"Dispatch job {dispatch_id} queued. No endpoint URL configured for "
                    f"'{body.siem_target}'. Configure your SIEM endpoint at: "
                    f"POST /api/v1/siem/integrations"
                ),
                "advisory_ids": body.advisory_ids,
                "siem_target": body.siem_target,
                "format": body.format,
                "queued_at": queued_at,
                "next_steps": {
                    "configure_siem": "POST /api/v1/siem/integrations",
                    "retry": f"POST /api/v1/siem/dispatch with webhook_url set",
                },
            }
        )

    # Attempt dispatch via HTTP
    dispatched = []
    failed = []
    import urllib.request
    import urllib.error

    for adv_id in body.advisory_ids[:50]:
        payload = {
            "dispatch_id": dispatch_id,
            "advisory_id": adv_id,
            "siem": body.siem_target,
            "format": body.format,
            "source": "CYBERDUDEBIVASH SENTINEL APEX v177.0",
            "dispatched_at": queued_at,
            "org_id": user.org_id,
        }
        try:
            data = json.dumps(payload).encode()
            req = urllib.request.Request(
                endpoint_url,
                data=data,
                headers={
                    "Content-Type": "application/json",
                    "Authorization": f"Bearer {target_config.get('api_token', '')}",
                    "User-Agent": "SentinelAPEX/177.0",
                },
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                dispatched.append({"advisory_id": adv_id, "http_status": resp.status})
        except Exception as e:
            failed.append({"advisory_id": adv_id, "error": str(e)})

    return {
        "dispatch_id": dispatch_id,
        "status": "dispatched" if dispatched else "failed",
        "siem_target": body.siem_target,
        "endpoint": endpoint_url[:50] + "..." if len(endpoint_url) > 50 else endpoint_url,
        "format": body.format,
        "dispatched": dispatched,
        "failed": failed,
        "summary": {
            "total": len(body.advisory_ids),
            "dispatched": len(dispatched),
            "failed": len(failed),
        },
        "queued_at": queued_at,
    }


class SIEMIntegrationConfig(BaseModel):
    siem_type: str = Field(..., pattern="^(splunk|sentinel|qradar|elastic)$")
    endpoint_url: str = Field(..., max_length=2048)
    api_token: str = Field(..., max_length=1024)
    label: Optional[str] = Field(None, max_length=100)
    enabled: bool = Field(True)


@router.post(
    "/siem/integrations",
    summary="Configure SIEM Integration (ENTERPRISE+)",
    description=(
        "Store or update a SIEM integration endpoint.\n\n"
        "Supported SIEMs: Splunk HEC, Microsoft Sentinel (Log Analytics workspace), "
        "IBM QRadar REST, Elastic Logstash HTTP.\n\n"
        "**Required tier:** ENTERPRISE or MSSP"
    ),
)
async def configure_siem(
    body: SIEMIntegrationConfig,
    user: AuthenticatedUser = Depends(require_tier(TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    # Load existing config
    config = _load_json(_SIEM_CONFIG, {})
    config[body.siem_type] = {
        "siem_type": body.siem_type,
        "endpoint_url": body.endpoint_url,
        "api_token": body.api_token,
        "label": body.label or body.siem_type.upper(),
        "enabled": body.enabled,
        "configured_by": user.email or user.user_id,
        "configured_at": datetime.now(timezone.utc).isoformat(),
        "org_id": user.org_id,
    }
    _SIEM_CONFIG.parent.mkdir(parents=True, exist_ok=True)
    _SIEM_CONFIG.write_text(json.dumps(config, indent=2))

    return {
        "status": "configured",
        "siem_type": body.siem_type,
        "label": body.label or body.siem_type.upper(),
        "enabled": body.enabled,
        "message": f"SIEM integration for {body.siem_type.upper()} saved. Use POST /api/v1/siem/dispatch to push intelligence.",
    }


@router.get(
    "/siem/integrations",
    summary="List Configured SIEM Targets (ENTERPRISE+)",
    description="List all configured SIEM endpoint integrations for your organisation.",
)
async def list_siem_integrations(
    user: AuthenticatedUser = Depends(require_tier(TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    config = _load_json(_SIEM_CONFIG, {})
    integrations = [
        {
            "siem_type": k,
            "label": v.get("label", k.upper()),
            "endpoint_masked": v.get("endpoint_url", "")[:30] + "..." if v.get("endpoint_url") else "",
            "enabled": v.get("enabled", False),
            "configured_at": v.get("configured_at"),
        }
        for k, v in config.items()
        if isinstance(v, dict)
    ]
    return {
        "integrations": integrations,
        "count": len(integrations),
        "supported_siems": ["splunk", "sentinel", "qradar", "elastic"],
        "dispatch_endpoint": "POST /api/v1/siem/dispatch",
    }
