"""
SENTINEL APEX — SOC & Threat Hunting API Endpoints v64.0
═══════════════════════════════════════════════════════════
Advanced SOC operations, threat hunting, and AI intelligence endpoints.

Endpoints:
  - GET  /api/v1/soc/status          — Orchestrator and system status
  - GET  /api/v1/soc/dashboard       — Comprehensive dashboard data
  - GET  /api/v1/soc/campaigns       — Active threat campaigns
  - GET  /api/v1/soc/detections      — Detection results
  - GET  /api/v1/soc/ioc-clusters    — IOC cluster analysis
  - GET  /api/v1/soc/cve-correlations — CVE correlation groups
  - POST /api/v1/soc/hunt            — Execute threat hunt query
  - POST /api/v1/soc/ioc-check       — Check IOC against watchlists
  - GET  /api/v1/soc/pipeline-runs   — Pipeline execution history

All SOC endpoints require Pro+ tier.

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import hashlib
import json
import logging
from datetime import datetime, timezone
from typing import List, Optional

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

logger = logging.getLogger("sentinel.soc")

router = APIRouter(prefix="/api/v1/soc", tags=["SOC & Threat Hunting"])


# ═══════════════════════════════════════════════════════════
# REQUEST/RESPONSE MODELS
# ═══════════════════════════════════════════════════════════

class ThreatHuntRequest(BaseModel):
    hunt_name: str = Field(..., min_length=3, max_length=200)
    hypothesis: str = Field("", max_length=1000)
    query_type: str = Field("keyword", pattern="^(keyword|ioc|cve|actor|mitre)$")
    query_value: str = Field(..., min_length=1, max_length=500)
    severity_filter: Optional[str] = None
    limit: int = Field(50, ge=1, le=200)


class IOCCheckRequest(BaseModel):
    ioc_type: str = Field(..., pattern="^(ipv4|domain|sha256|md5|url|email|cve)$")
    values: List[str] = Field(..., min_length=1, max_length=100)


class IOCCheckResponse(BaseModel):
    checked: int
    matches: List[dict]
    match_count: int


# ═══════════════════════════════════════════════════════════
# ENDPOINTS
# ═══════════════════════════════════════════════════════════

@router.get("/status")
async def get_system_status():
    """Get comprehensive orchestrator and component status."""
    try:
        from core.orchestrator import orchestrator
        status = orchestrator.get_status()
        return {"status": "ok", "data": status}
    except Exception as e:
        logger.error(f"Status check failed: {e}")
        return {
            "status": "degraded",
            "error": str(e),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }


@router.get("/dashboard")
async def get_dashboard_data():
    """Get comprehensive dashboard data for the enterprise dashboard."""
    try:
        from core.orchestrator import orchestrator
        data = orchestrator.get_dashboard_data()
        return {"status": "ok", "data": data}
    except Exception as e:
        logger.error(f"Dashboard data failed: {e}")
        # Fallback to manifest stats
        try:
            from core.manifest_manager import manifest_manager
            return {
                "status": "partial",
                "data": {"manifest": manifest_manager.get_stats()},
            }
        except Exception:
            raise HTTPException(status_code=503, detail="Dashboard service unavailable")


@router.get("/campaigns")
async def get_threat_campaigns(
    severity: Optional[str] = Query(None, description="Filter by severity: CRITICAL, HIGH, MEDIUM, LOW"),
    status: str = Query("active", description="Campaign status filter"),
    limit: int = Query(20, ge=1, le=100),
):
    """Get active threat campaigns detected by the AI engine."""
    try:
        from core.storage import get_db
        db = get_db()
        conditions = []
        params = []

        if status:
            conditions.append("status = ?")
            params.append(status)
        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM threat_campaigns WHERE {where} ORDER BY confidence DESC LIMIT ?"
        params.append(limit)

        campaigns = db.fetch_all(sql, tuple(params))

        # Parse JSON fields
        for c in campaigns:
            for field in ["mitre_techniques", "related_cves", "sectors_targeted", "geo_targets"]:
                if isinstance(c.get(field), str):
                    try:
                        c[field] = json.loads(c[field])
                    except (json.JSONDecodeError, TypeError):
                        c[field] = []

        return {"status": "ok", "count": len(campaigns), "campaigns": campaigns}

    except Exception as e:
        logger.error(f"Campaigns query failed: {e}")
        return {"status": "ok", "count": 0, "campaigns": []}


@router.get("/detections")
async def get_detection_results(
    rule_type: Optional[str] = Query(None, description="Filter: sigma, yara, ioc_match"),
    severity: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=200),
):
    """Get detection results from Sigma, YARA, and IOC matching engines."""
    try:
        from core.storage import get_db
        db = get_db()
        conditions = []
        params = []

        if rule_type:
            conditions.append("rule_type = ?")
            params.append(rule_type)
        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())

        where = " AND ".join(conditions) if conditions else "1=1"
        sql = f"SELECT * FROM detection_results WHERE {where} ORDER BY created_at DESC LIMIT ?"
        params.append(limit)

        detections = db.fetch_all(sql, tuple(params))

        for d in detections:
            if isinstance(d.get("match_data"), str):
                try:
                    d["match_data"] = json.loads(d["match_data"])
                except (json.JSONDecodeError, TypeError):
                    d["match_data"] = {}

        return {"status": "ok", "count": len(detections), "detections": detections}

    except Exception as e:
        logger.error(f"Detections query failed: {e}")
        return {"status": "ok", "count": 0, "detections": []}


@router.get("/ioc-clusters")
async def get_ioc_clusters():
    """Get IOC cluster analysis from the AI intelligence engine."""
    try:
        from core.manifest_manager import manifest_manager
        entries = manifest_manager.read_manifest()

        from core.ai_engine import ai_engine
        analysis = ai_engine.analyze(entries[-100:])  # Analyze recent 100

        return {
            "status": "ok",
            "cluster_count": len(analysis.get("ioc_clusters", [])),
            "clusters": analysis.get("ioc_clusters", []),
        }
    except Exception as e:
        logger.error(f"IOC clusters failed: {e}")
        return {"status": "ok", "cluster_count": 0, "clusters": []}


@router.get("/cve-correlations")
async def get_cve_correlations():
    """Get CVE correlation groups linking related vulnerabilities."""
    try:
        from core.manifest_manager import manifest_manager
        entries = manifest_manager.read_manifest()

        from core.ai_engine import ai_engine
        analysis = ai_engine.analyze(entries[-100:])

        return {
            "status": "ok",
            "correlation_count": len(analysis.get("cve_correlations", [])),
            "correlations": analysis.get("cve_correlations", []),
        }
    except Exception as e:
        logger.error(f"CVE correlations failed: {e}")
        return {"status": "ok", "correlation_count": 0, "correlations": []}


@router.post("/hunt")
async def execute_threat_hunt(req: ThreatHuntRequest):
    """
    Execute a threat hunt query against the intelligence database.
    Supports keyword, IOC, CVE, actor, and MITRE technique searches.
    """
    try:
        from core.manifest_manager import manifest_manager
        entries = manifest_manager.read_manifest()

        results = []
        query_lower = req.query_value.lower()

        for entry in entries:
            matched = False
            title_lower = entry.get("title", "").lower()

            if req.query_type == "keyword":
                matched = query_lower in title_lower
            elif req.query_type == "cve":
                matched = req.query_value.upper() in title_lower.upper()
            elif req.query_type == "actor":
                matched = query_lower in entry.get("actor_tag", "").lower()
            elif req.query_type == "mitre":
                tactics = entry.get("mitre_tactics", [])
                matched = any(req.query_value.upper() in str(t).upper() for t in tactics)
            elif req.query_type == "ioc":
                ioc_data = str(entry.get("ioc_counts", {}))
                matched = query_lower in ioc_data.lower()

            if matched:
                if req.severity_filter and entry.get("severity", "").upper() != req.severity_filter.upper():
                    continue
                results.append(entry)

            if len(results) >= req.limit:
                break

        # Store hunt result
        hunt_id = f"HUNT-{hashlib.sha256(f'{req.hunt_name}{req.query_value}'.encode()).hexdigest()[:8]}"

        try:
            from core.storage import get_db
            db = get_db()
            db.execute(
                "INSERT OR IGNORE INTO soc_hunt_results "
                "(hunt_id, hunt_name, hypothesis, query_type, query_data, results, findings_count, severity, analyst) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                (
                    hunt_id, req.hunt_name, req.hypothesis, req.query_type,
                    json.dumps({"query_value": req.query_value}),
                    json.dumps([r.get("title", "") for r in results[:20]]),
                    len(results),
                    "HIGH" if len(results) > 10 else "MEDIUM",
                    "SENTINEL-AI",
                ),
            )
            db.commit()
        except Exception:
            pass

        return {
            "status": "ok",
            "hunt_id": hunt_id,
            "hunt_name": req.hunt_name,
            "findings_count": len(results),
            "results": results[:req.limit],
        }

    except Exception as e:
        logger.error(f"Threat hunt failed: {e}")
        raise HTTPException(status_code=500, detail=f"Hunt execution failed: {e}")


@router.post("/ioc-check", response_model=IOCCheckResponse)
async def check_iocs(req: IOCCheckRequest):
    """Check IOC values against known threat intelligence watchlists."""
    try:
        from core.detection import detection_engine
        matcher = detection_engine.ioc_matcher

        # Also load from manifest
        try:
            from core.manifest_manager import manifest_manager
            matcher.load_from_manifest(manifest_manager.read_manifest())
        except Exception:
            pass

        matches = []
        for val in req.values:
            if matcher.check_single(req.ioc_type, val):
                matches.append({
                    "ioc_type": req.ioc_type,
                    "ioc_value": val,
                    "status": "MATCHED",
                    "confidence": 0.85,
                })

        return IOCCheckResponse(
            checked=len(req.values),
            matches=matches,
            match_count=len(matches),
        )

    except Exception as e:
        logger.error(f"IOC check failed: {e}")
        raise HTTPException(status_code=500, detail=f"IOC check failed: {e}")


@router.get("/sync-signal")
async def get_sync_signal():
    """Get the dashboard sync signal for real-time status updates."""
    try:
        from core.orchestrator import orchestrator
        return {"status": "ok", "data": orchestrator.get_sync_signal()}
    except Exception as e:
        logger.error(f"Sync signal failed: {e}")
        # Fallback: read from file
        try:
            import os
            signal_path = "data/status/sync_signal.json"
            if os.path.exists(signal_path):
                with open(signal_path, "r") as f:
                    return {"status": "ok", "data": json.load(f)}
        except Exception:
            pass
        return {
            "status": "degraded",
            "data": {"pipeline_state": "unknown", "last_sync_at": None},
        }


@router.get("/pipeline-runs")
async def get_pipeline_runs(
    limit: int = Query(10, ge=1, le=50),
):
    """Get recent pipeline execution history."""
    try:
        from core.storage import get_db
        db = get_db()
        runs = db.fetch_all(
            "SELECT * FROM pipeline_executions ORDER BY started_at DESC LIMIT ?",
            (limit,),
        )

        for r in runs:
            for field in ["errors", "stages_completed"]:
                if isinstance(r.get(field), str):
                    try:
                        r[field] = json.loads(r[field])
                    except (json.JSONDecodeError, TypeError):
                        r[field] = []

        return {"status": "ok", "count": len(runs), "runs": runs}

    except Exception as e:
        logger.error(f"Pipeline runs query failed: {e}")
        return {"status": "ok", "count": 0, "runs": []}


@router.get("/threat-report/{intel_id}")
async def get_threat_report(intel_id: str):
    """Generate a premium intelligence report for a specific threat item."""
    try:
        from core.manifest_manager import manifest_manager
        entry = manifest_manager.get_entry_by_stix_id(intel_id)
        if not entry:
            # Try by title hash
            entries = manifest_manager.read_manifest()
            entry = next((e for e in entries if e.get("intel_id") == intel_id), None)

        if not entry:
            raise HTTPException(status_code=404, detail="Intelligence item not found")

        try:
            from core.report_engine import report_engine
            report = report_engine.generate_report(entry)
            return {"status": "ok", "report": report}
        except ImportError:
            return {"status": "error", "detail": "Report engine not available"}

    except HTTPException:
        raise
    except Exception as e:
        logger.error(f"Report generation failed: {e}")
        raise HTTPException(status_code=500, detail=f"Report generation failed: {e}")


@router.get("/executive-briefing")
async def get_executive_briefing(limit: int = Query(20, ge=5, le=100)):
    """Generate an executive briefing summarizing top threats."""
    try:
        from core.manifest_manager import manifest_manager
        entries = manifest_manager.read_manifest()

        # Sort by risk score descending, take top N
        entries.sort(key=lambda e: float(e.get("risk_score", 0)), reverse=True)
        top_entries = entries[:limit]

        try:
            from core.report_engine import report_engine
            briefing = report_engine.generate_executive_briefing(top_entries)
            return {"status": "ok", "briefing": briefing}
        except ImportError:
            return {"status": "error", "detail": "Report engine not available"}

    except Exception as e:
        logger.error(f"Executive briefing failed: {e}")
        raise HTTPException(status_code=500, detail=f"Briefing generation failed: {e}")


@router.get("/action-cards")
async def get_soc_action_cards():
    """Get SOC-ready action cards for the top 10 actionable threats."""
    try:
        from core.manifest_manager import manifest_manager
        entries = manifest_manager.read_manifest()

        try:
            from core.report_engine import report_engine
            cards = report_engine.generate_soc_action_cards(entries)
            return {"status": "ok", "count": len(cards), "action_cards": cards}
        except ImportError:
            return {"status": "error", "detail": "Report engine not available"}

    except Exception as e:
        logger.error(f"Action cards failed: {e}")
        return {"status": "ok", "count": 0, "action_cards": []}
