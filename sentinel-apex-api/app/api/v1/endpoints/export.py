"""
SENTINEL APEX — Export Endpoints v177.0
=========================================
Tier-gated export endpoints for bulk IOC/advisory data.

Endpoints:
  GET  /api/v1/export/csv          — Bulk IOC export as CSV (PRO+)
  GET  /api/v1/export/misp         — MISP 2.4 event JSON (ENTERPRISE+)
  GET  /api/v1/export/sigma        — Sigma detection rules (PRO+)
  GET  /api/v1/export/yara         — YARA detection rules (PRO+)
  GET  /api/v1/export/stix/{id}    — STIX 2.1 bundle for one advisory (PRO+)
  GET  /api/v1/export/kql          — KQL queries for Sentinel SIEM (ENTERPRISE+)
  GET  /api/v1/export/spl          — Splunk SPL queries (ENTERPRISE+)
"""
from __future__ import annotations

import csv
import io
import json
import logging
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from fastapi.responses import Response, StreamingResponse

from app.auth.dependencies import (
    AuthenticatedUser,
    get_current_user,
    require_tier,
)
from app.db.client import SupabaseDB
from app.schemas.models import TierEnum

logger = logging.getLogger("sentinel.export")
router = APIRouter(prefix="/api/v1/export", tags=["Export"])

_ROOT = Path(__file__).parents[6]
STIX_DIR    = _ROOT / "data" / "stix"
SIGMA_DIR   = _ROOT / "data" / "intelligence" / "detection_rules" / "sigma"
YARA_DIR    = _ROOT / "data" / "intelligence" / "detection_rules" / "yara"
KQL_DIR     = _ROOT / "data" / "intelligence" / "detection_rules" / "kql"
SPL_DIR     = _ROOT / "data" / "intelligence" / "detection_rules" / "spl"
IOCS_PATH   = _ROOT / "data" / "intelligence" / "iocs_db.json"
MANIFEST_PATH = _ROOT / "data" / "apex_enriched_manifest.json"


def _now() -> str:
    return datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")


# ── CSV Export ────────────────────────────────────────────────────────────────

@router.get(
    "/csv",
    summary="Bulk IOC Export — CSV",
    description=(
        "Export all Indicators of Compromise (IOCs) as RFC 4180-compliant CSV.\n\n"
        "Columns: `ioc_type`, `ioc_value`, `severity`, `confidence`, `source`, "
        "`cvss`, `epss`, `kev`, `cve_id`, `tags`, `published_at`\n\n"
        "**Required tier:** PRO or above"
    ),
    responses={
        200: {"description": "CSV file stream", "content": {"text/csv": {}}},
        403: {"description": "PRO tier required"},
    },
)
async def export_csv(
    severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low|info)$"),
    limit: int = Query(5000, ge=1, le=50000),
    kev_only: bool = Query(False),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.PRO, TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    max_limit = 50000 if user.is_enterprise else 5000
    limit = min(limit, max_limit)

    # Try Supabase first, fall back to local manifest
    rows: list[dict] = []
    try:
        filters: dict[str, str] = {}
        if severity:
            filters["severity"] = f"eq.{severity}"
        if kev_only:
            filters["kev"] = "eq.true"
        result = await SupabaseDB.query(
            "advisories",
            select="id,title,severity,confidence,cvss,epss,kev,cve_id,iocs,source,tags,published_at",
            filters=filters,
            limit=limit,
            order="published_at.desc",
        )
        advisories = result.get("data") or []
    except Exception:
        advisories = []

    # Fall back to local manifest
    if not advisories and MANIFEST_PATH.exists():
        try:
            raw = json.loads(MANIFEST_PATH.read_bytes())
            items = raw if isinstance(raw, list) else raw.get("items", [])
            if severity:
                items = [i for i in items if str(i.get("severity","")).lower() == severity]
            if kev_only:
                items = [i for i in items if i.get("kev")]
            advisories = items[:limit]
        except Exception as e:
            logger.warning(f"Manifest fallback failed: {e}")

    # Build CSV rows — expand IOCs
    for adv in advisories:
        iocs = adv.get("iocs") or []
        tags = adv.get("tags") or []
        tags_str = "|".join(tags) if isinstance(tags, list) else str(tags)
        if not iocs:
            rows.append({
                "ioc_type": "",
                "ioc_value": "",
                "advisory_id": adv.get("id", ""),
                "advisory_title": adv.get("title", ""),
                "severity": adv.get("severity", ""),
                "confidence": adv.get("confidence", ""),
                "cvss": adv.get("cvss", ""),
                "epss": adv.get("epss", ""),
                "kev": adv.get("kev", False),
                "cve_id": adv.get("cve_id", ""),
                "source": adv.get("source", ""),
                "tags": tags_str,
                "published_at": str(adv.get("published_at", "")),
            })
        else:
            for ioc in (iocs if isinstance(iocs, list) else []):
                ioc_type = ioc.get("type", "") if isinstance(ioc, dict) else ""
                ioc_val  = ioc.get("value", str(ioc)) if isinstance(ioc, dict) else str(ioc)
                rows.append({
                    "ioc_type": ioc_type,
                    "ioc_value": ioc_val,
                    "advisory_id": adv.get("id", ""),
                    "advisory_title": adv.get("title", ""),
                    "severity": adv.get("severity", ""),
                    "confidence": adv.get("confidence", ""),
                    "cvss": adv.get("cvss", ""),
                    "epss": adv.get("epss", ""),
                    "kev": adv.get("kev", False),
                    "cve_id": adv.get("cve_id", ""),
                    "source": adv.get("source", ""),
                    "tags": tags_str,
                    "published_at": str(adv.get("published_at", "")),
                })

    # Stream CSV
    output = io.StringIO()
    fieldnames = ["ioc_type","ioc_value","advisory_id","advisory_title",
                  "severity","confidence","cvss","epss","kev","cve_id",
                  "source","tags","published_at"]
    writer = csv.DictWriter(output, fieldnames=fieldnames, lineterminator="\r\n")
    writer.writeheader()
    writer.writerows(rows)

    filename = f"sentinel-apex-ioc-export-{_now()}.csv"
    return Response(
        content=output.getvalue(),
        media_type="text/csv",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-Export-Rows": str(len(rows)),
            "X-Export-Tier": user.tier.value,
            "X-Export-Generated": datetime.now(timezone.utc).isoformat(),
        },
    )


# ── MISP Export ───────────────────────────────────────────────────────────────

@router.get(
    "/misp",
    summary="MISP 2.4 Event Export — JSON",
    description=(
        "Export threat intelligence as a MISP 2.4 compatible event collection.\n\n"
        "Returns a MISP-import-ready JSON payload with attributes, tags, galaxy clusters, "
        "and relationship objects. Compatible with MISP 2.4.x `import_json` function.\n\n"
        "**Required tier:** ENTERPRISE or MSSP"
    ),
    responses={
        200: {"description": "MISP JSON export", "content": {"application/json": {}}},
        403: {"description": "ENTERPRISE tier required"},
    },
)
async def export_misp(
    limit: int = Query(200, ge=1, le=1000),
    severity: Optional[str] = Query(None, pattern="^(critical|high|medium|low|info)$"),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    # Fetch advisories
    try:
        filters: dict[str, str] = {}
        if severity:
            filters["severity"] = f"eq.{severity}"
        result = await SupabaseDB.query(
            "advisories",
            select="id,title,description,severity,cvss,epss,kev,cve_id,iocs,mitre_techniques,source,source_url,tags,published_at",
            filters=filters,
            limit=limit,
            order="published_at.desc",
        )
        advisories = result.get("data") or []
    except Exception:
        advisories = []

    # Fall back to manifest
    if not advisories and MANIFEST_PATH.exists():
        try:
            raw = json.loads(MANIFEST_PATH.read_bytes())
            items = raw if isinstance(raw, list) else raw.get("items", [])
            if severity:
                items = [i for i in items if str(i.get("severity","")).lower() == severity]
            advisories = items[:limit]
        except Exception:
            pass

    def _severity_to_threat_level(sev: str) -> int:
        return {"critical": 1, "high": 2, "medium": 3, "low": 4}.get(str(sev).lower(), 4)

    def _build_attributes(adv: dict) -> list:
        attrs = []
        if adv.get("cve_id"):
            attrs.append({"type": "vulnerability", "value": adv["cve_id"],
                          "category": "External analysis", "to_ids": False,
                          "comment": f"CVE CVSS:{adv.get('cvss','')} EPSS:{adv.get('epss','')} KEV:{adv.get('kev',False)}"})
        for ioc in (adv.get("iocs") or []):
            if not isinstance(ioc, dict):
                continue
            misp_type_map = {
                "ipv4": "ip-dst", "ipv6": "ip-dst", "domain": "domain",
                "url": "url", "sha256": "sha256", "md5": "md5",
                "sha1": "sha1", "email": "email-src", "filename": "filename",
                "mutex": "mutex", "regkey": "regkey",
            }
            ioc_type = misp_type_map.get(str(ioc.get("type","")).lower(), "other")
            attrs.append({
                "type": ioc_type,
                "value": ioc.get("value", ""),
                "category": "Network activity" if ioc_type in ("ip-dst","domain","url") else "Payload delivery",
                "to_ids": True,
                "comment": ioc.get("description", ""),
            })
        for tech in (adv.get("mitre_techniques") or []):
            if isinstance(tech, dict):
                attrs.append({"type": "text", "value": tech.get("id",""),
                              "category": "External analysis",
                              "comment": f"MITRE ATT&CK: {tech.get('name','')}"})
        for tag in (adv.get("tags") or []):
            if tag and ":" in str(tag):
                attrs.append({"type": "text", "value": str(tag),
                              "category": "External analysis", "to_ids": False})
        return attrs

    events = []
    for adv in advisories:
        events.append({
            "Event": {
                "uuid": str(adv.get("id", ""))[:36] or f"sentinel-{len(events)}",
                "info": adv.get("title", "Untitled"),
                "date": str(adv.get("published_at", ""))[:10],
                "threat_level_id": str(_severity_to_threat_level(adv.get("severity",""))),
                "analysis": "2",  # completed
                "distribution": "1",  # community
                "Orgc": {"name": "CYBERDUDEBIVASH SENTINEL APEX", "uuid": "sentinel-apex-org"},
                "Tag": [
                    {"name": "tlp:amber"},
                    {"name": "sentinel-apex:v177"},
                    *[{"name": str(t)} for t in (adv.get("tags") or [])],
                ],
                "Attribute": _build_attributes(adv),
                "SharingGroup": [],
                "RelatedEvent": [],
                "Galaxy": [],
                "Object": [],
                "source": adv.get("source", ""),
                "source_url": adv.get("source_url", ""),
            }
        })

    payload = {
        "response": events,
        "_meta": {
            "generator": "CYBERDUDEBIVASH SENTINEL APEX v177.0",
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "event_count": len(events),
            "misp_version": "2.4",
            "tlp": "amber",
            "org": "CYBERDUDEBIVASH SENTINEL APEX",
        }
    }

    filename = f"sentinel-apex-misp-{_now()}.json"
    return Response(
        content=json.dumps(payload, indent=2, default=str),
        media_type="application/json",
        headers={
            "Content-Disposition": f'attachment; filename="{filename}"',
            "X-MISP-Events": str(len(events)),
            "X-Export-Generated": datetime.now(timezone.utc).isoformat(),
        },
    )


# ── Sigma Rules Export ────────────────────────────────────────────────────────

@router.get(
    "/sigma",
    summary="Sigma Detection Rules (PRO+)",
    description=(
        "Download Sigma detection rules as a ZIP archive or individual YAML.\n\n"
        "Rules cover all MITRE ATT&CK techniques observed in the threat feed. "
        "Compatible with Splunk, Elastic, QRadar, Sentinel, and all major SIEMs via sigmac.\n\n"
        "**Required tier:** PRO or above"
    ),
)
async def export_sigma(
    format: str = Query("yaml", pattern="^(yaml|json|list)$"),
    limit: int = Query(50, ge=1, le=500),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.PRO, TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    max_limit = 500 if user.is_enterprise else 50
    limit = min(limit, max_limit)

    rules = []
    if SIGMA_DIR.exists():
        files = sorted(SIGMA_DIR.glob("*.yml"))[:limit]
        for f in files:
            try:
                content = f.read_text(encoding="utf-8")
                if format == "list":
                    rules.append({"filename": f.name, "size": f.stat().st_size})
                elif format == "json":
                    rules.append({"filename": f.name, "content": content})
                else:
                    rules.append(content)
            except Exception:
                continue

    if format == "yaml" and rules:
        combined = "\n---\n".join(rules)
        filename = f"sentinel-apex-sigma-{_now()}.yml"
        return Response(
            content=combined,
            media_type="text/yaml",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Rule-Count": str(len(rules)),
                "X-Total-Available": str(len(list(SIGMA_DIR.glob("*.yml"))) if SIGMA_DIR.exists() else 0),
                "X-Export-Generated": datetime.now(timezone.utc).isoformat(),
            },
        )

    return {
        "rules": rules,
        "count": len(rules),
        "total_available": len(list(SIGMA_DIR.glob("*.yml"))) if SIGMA_DIR.exists() else 0,
        "format": format,
        "tier": user.tier.value,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "_meta": {"generator": "SENTINEL APEX v177.0", "platform": "Sigma v1.0"},
    }


# ── YARA Rules Export ─────────────────────────────────────────────────────────

@router.get(
    "/yara",
    summary="YARA Detection Rules (PRO+)",
    description=(
        "Download YARA malware detection rules generated from IOC intelligence.\n\n"
        "Rules include string signatures, hash patterns, and behavioral indicators "
        "derived from threat feed IOCs. Compatible with YARA 4.x, ClamAV, and VirusTotal.\n\n"
        "**Required tier:** PRO or above"
    ),
)
async def export_yara(
    limit: int = Query(50, ge=1, le=500),
    format: str = Query("yar", pattern="^(yar|json|list)$"),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.PRO, TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    max_limit = 500 if user.is_enterprise else 50
    limit = min(limit, max_limit)

    rules = []
    if YARA_DIR.exists():
        files = sorted(YARA_DIR.glob("*.yar"))[:limit]
        for f in files:
            try:
                content = f.read_text(encoding="utf-8")
                if format == "list":
                    rules.append({"filename": f.name, "size": f.stat().st_size})
                elif format == "json":
                    rules.append({"filename": f.name, "content": content})
                else:
                    rules.append(content)
            except Exception:
                continue

    if format == "yar" and rules:
        combined = "\n\n".join(rules)
        filename = f"sentinel-apex-yara-{_now()}.yar"
        return Response(
            content=combined,
            media_type="text/plain",
            headers={
                "Content-Disposition": f'attachment; filename="{filename}"',
                "X-Rule-Count": str(len(rules)),
                "X-Total-Available": str(len(list(YARA_DIR.glob("*.yar"))) if YARA_DIR.exists() else 0),
                "X-Export-Generated": datetime.now(timezone.utc).isoformat(),
            },
        )

    return {
        "rules": rules,
        "count": len(rules),
        "total_available": len(list(YARA_DIR.glob("*.yar"))) if YARA_DIR.exists() else 0,
        "format": format,
        "tier": user.tier.value,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "_meta": {"generator": "SENTINEL APEX v177.0", "platform": "YARA 4.x"},
    }


# ── STIX Bundle Export ────────────────────────────────────────────────────────

@router.get(
    "/stix/{advisory_id}",
    summary="STIX 2.1 Bundle for Advisory (PRO+)",
    description=(
        "Download the full STIX 2.1 bundle for a specific advisory.\n\n"
        "Returns a STIX 2.1 bundle object containing: Indicators, Vulnerabilities, "
        "Malware objects, Attack Patterns (MITRE ATT&CK), and Relationships.\n\n"
        "**Required tier:** PRO or above"
    ),
)
async def export_stix_bundle(
    advisory_id: str,
    user: AuthenticatedUser = Depends(require_tier(TierEnum.PRO, TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    # Check local STIX directory first
    stix_file = STIX_DIR / f"{advisory_id}.json"
    if not stix_file.exists():
        # Try prefix match
        matches = list(STIX_DIR.glob(f"{advisory_id}*.json"))
        if matches:
            stix_file = matches[0]

    if stix_file.exists():
        content = stix_file.read_bytes()
        return Response(
            content=content,
            media_type="application/json",
            headers={
                "Content-Disposition": f'attachment; filename="stix-{advisory_id}.json"',
                "X-STIX-Version": "2.1",
                "X-Export-Generated": datetime.now(timezone.utc).isoformat(),
            },
        )

    # Try Supabase
    try:
        result = await SupabaseDB.query(
            "advisories",
            select="id,title,stix_bundle_url",
            filters={"id": f"eq.{advisory_id}"},
            single=True,
        )
        adv = result.get("data", {})
        if adv and adv.get("stix_bundle_url"):
            return {"stix_bundle_url": adv["stix_bundle_url"], "id": advisory_id}
    except Exception:
        pass

    raise HTTPException(status_code=404, detail=f"STIX bundle not found for advisory: {advisory_id}")


# ── KQL (Sentinel) Export ─────────────────────────────────────────────────────

@router.get(
    "/kql",
    summary="KQL Queries — Microsoft Sentinel (ENTERPRISE+)",
    description=(
        "Export KQL (Kusto Query Language) detection queries for Microsoft Sentinel.\n\n"
        "Queries are pre-tuned for Sentinel's SecurityEvent, CommonSecurityLog, "
        "and Syslog tables. Directly importable as Sentinel Analytics Rules.\n\n"
        "**Required tier:** ENTERPRISE or MSSP"
    ),
)
async def export_kql(
    limit: int = Query(100, ge=1, le=500),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    rules = []
    if KQL_DIR.exists():
        for f in sorted(KQL_DIR.glob("*.kql"))[:limit]:
            try:
                rules.append({"filename": f.name, "query": f.read_text(encoding="utf-8")})
            except Exception:
                continue
    else:
        rules = []

    return {
        "kql_queries": rules,
        "count": len(rules),
        "siem": "Microsoft Sentinel",
        "tier": user.tier.value,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "_meta": {
            "generator": "SENTINEL APEX v177.0",
            "usage": "Import via Sentinel > Analytics > Import rule query",
        }
    }


# ── SPL (Splunk) Export ───────────────────────────────────────────────────────

@router.get(
    "/spl",
    summary="SPL Queries — Splunk SIEM (ENTERPRISE+)",
    description=(
        "Export Splunk Processing Language (SPL) saved searches and correlation rules.\n\n"
        "Queries target standard Splunk CIM data models. Import via Splunk > Search "
        "& Reporting > Save Search.\n\n"
        "**Required tier:** ENTERPRISE or MSSP"
    ),
)
async def export_spl(
    limit: int = Query(100, ge=1, le=500),
    user: AuthenticatedUser = Depends(require_tier(TierEnum.ENTERPRISE, TierEnum.MSSP)),
):
    rules = []
    if SPL_DIR.exists():
        for f in sorted(SPL_DIR.glob("*.spl"))[:limit]:
            try:
                rules.append({"filename": f.name, "query": f.read_text(encoding="utf-8")})
            except Exception:
                continue

    return {
        "spl_queries": rules,
        "count": len(rules),
        "siem": "Splunk",
        "tier": user.tier.value,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "_meta": {
            "generator": "SENTINEL APEX v177.0",
            "usage": "Import via Splunk > Search & Reporting > Saved Searches",
        }
    }
