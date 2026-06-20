"""
CYBERDUDEBIVASH® SENTINEL APEX — Incident Response API Router
POST /api/v1/incidents/                        — Create incident
GET  /api/v1/incidents/                        — List incidents
GET  /api/v1/incidents/{id}                    — Get incident
POST /api/v1/incidents/{id}/advance-phase      — Advance NIST phase
POST /api/v1/incidents/{id}/evidence           — Add evidence
POST /api/v1/incidents/{id}/ioc                — Add IOC
POST /api/v1/incidents/{id}/root-cause         — Record root cause
GET  /api/v1/incidents/{id}/report             — Post-incident report
GET  /api/v1/incidents/{id}/stix               — STIX 2.1 incident object
GET  /api/v1/incidents/health                  — Engine health
"""
from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

logger = logging.getLogger("CDB-IR-API")
_FASTAPI_OK = False

try:
    from fastapi import APIRouter, HTTPException, Header
    from pydantic import BaseModel
    _FASTAPI_OK = True
except ImportError:
    pass

BASE_DIR = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(BASE_DIR))

# Module-level singleton (persists for session lifetime)
_ir_engine = None

def get_ir_engine():
    global _ir_engine
    if _ir_engine is None:
        from agent.incident_response import IncidentResponseEngine
        _ir_engine = IncidentResponseEngine()
    return _ir_engine


if _FASTAPI_OK:
    incident_router = APIRouter(prefix="/api/v1/incidents", tags=["Incident Response"])

    class CreateIncidentRequest(BaseModel):
        title:            str
        severity:         str = "P2_HIGH"
        threat_type:      str = "General"
        affected_systems: Optional[List[str]] = None
        affected_data:    Optional[List[str]] = None
        threat_actor:     str = "UNATTRIBUTED"
        ttps:             Optional[List[str]] = None
        assigned_to:      str = "SOC Team"

    class AdvancePhaseRequest(BaseModel):
        actor: str = "SOC Analyst"
        notes: str = ""

    class AddEvidenceRequest(BaseModel):
        evidence_type: str
        description:   str
        collected_by:  str
        location:      Optional[str] = None
        hash_sha256:   Optional[str] = None

    class AddIOCRequest(BaseModel):
        ioc_type:   str
        value:      str
        confidence: float = 0.8

    class RootCauseRequest(BaseModel):
        root_cause:      str
        lessons_learned: Optional[List[str]] = None

    @incident_router.post("/", summary="Create new security incident")
    async def create_incident(req: CreateIncidentRequest):
        if not req.title:
            raise HTTPException(400, {"error": "title is required"})
        valid_severities = {"P1_CRITICAL", "P2_HIGH", "P3_MEDIUM", "P4_LOW"}
        if req.severity not in valid_severities:
            raise HTTPException(400, {"error": f"severity must be one of: {valid_severities}"})
        try:
            engine   = get_ir_engine()
            incident = engine.create_incident(
                title            = req.title,
                severity         = req.severity,
                threat_type      = req.threat_type,
                affected_systems = req.affected_systems,
                affected_data    = req.affected_data,
                threat_actor     = req.threat_actor,
                ttps             = req.ttps,
                assigned_to      = req.assigned_to,
            )
            return {"status": "success", "incident": engine._serialize_incident(incident)}
        except Exception as e:
            logger.error(f"Create incident error: {e}", exc_info=True)
            raise HTTPException(500, {"error": "Failed to create incident", "detail": str(e)})

    @incident_router.get("/", summary="List all incidents")
    async def list_incidents(
        phase:    Optional[str] = None,
        severity: Optional[str] = None,
    ):
        try:
            engine = get_ir_engine()
            result = engine.list_incidents(phase=phase, severity=severity)
            return {"status": "success", "count": len(result), "incidents": result}
        except Exception as e:
            raise HTTPException(500, {"error": str(e)})

    @incident_router.get("/health", summary="Incident response engine health")
    async def ir_health():
        try:
            engine = get_ir_engine()
            return {"status": "ok", **engine.get_stats()}
        except Exception as e:
            return {"status": "degraded", "error": str(e)}

    @incident_router.get("/{incident_id}", summary="Get incident details")
    async def get_incident(incident_id: str):
        try:
            engine = get_ir_engine()
            result = engine.get_incident(incident_id)
            if not result:
                raise HTTPException(404, {"error": f"Incident {incident_id} not found"})
            return {"status": "success", "incident": result}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"error": str(e)})

    @incident_router.post("/{incident_id}/advance-phase", summary="Advance incident to next NIST phase")
    async def advance_phase(incident_id: str, req: AdvancePhaseRequest):
        try:
            engine  = get_ir_engine()
            ok, res = engine.advance_phase(incident_id, req.actor, req.notes)
            if not ok:
                raise HTTPException(400, res)
            return {"status": "success", **res}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"error": str(e)})

    @incident_router.post("/{incident_id}/evidence", summary="Add evidence with chain of custody")
    async def add_evidence(incident_id: str, req: AddEvidenceRequest):
        try:
            engine  = get_ir_engine()
            ok, ev  = engine.add_evidence(
                incident_id   = incident_id,
                evidence_type = req.evidence_type,
                description   = req.description,
                collected_by  = req.collected_by,
                location      = req.location,
                hash_sha256   = req.hash_sha256,
            )
            if not ok:
                raise HTTPException(404, {"error": f"Incident {incident_id} not found"})
            return {
                "status":      "success",
                "evidence_id": ev.evidence_id,
                "type":        ev.evidence_type.value,
                "collected_at": ev.collected_at,
            }
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"error": str(e)})

    @incident_router.post("/{incident_id}/ioc", summary="Add IOC to incident")
    async def add_ioc(incident_id: str, req: AddIOCRequest):
        try:
            engine = get_ir_engine()
            ok     = engine.add_ioc(incident_id, req.ioc_type, req.value, req.confidence)
            if not ok:
                raise HTTPException(404, {"error": f"Incident {incident_id} not found"})
            return {"status": "success", "message": f"IOC added: {req.ioc_type} = {req.value}"}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"error": str(e)})

    @incident_router.post("/{incident_id}/root-cause", summary="Record root cause and lessons learned")
    async def set_root_cause(incident_id: str, req: RootCauseRequest):
        try:
            engine = get_ir_engine()
            ok     = engine.update_root_cause(incident_id, req.root_cause, req.lessons_learned)
            if not ok:
                raise HTTPException(404, {"error": f"Incident {incident_id} not found"})
            return {"status": "success", "message": "Root cause and lessons learned recorded"}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"error": str(e)})

    @incident_router.get("/{incident_id}/report", summary="Generate post-incident review report")
    async def get_report(incident_id: str):
        try:
            engine = get_ir_engine()
            report = engine.generate_post_incident_report(incident_id)
            if "error" in report:
                raise HTTPException(404, report)
            return {"status": "success", "report": report}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"error": str(e)})

    @incident_router.get("/{incident_id}/stix", summary="Export incident as STIX 2.1 object")
    async def get_stix(incident_id: str):
        try:
            engine = get_ir_engine()
            stix   = engine.generate_stix_incident(incident_id)
            if not stix:
                raise HTTPException(404, {"error": f"Incident {incident_id} not found"})
            return {"status": "success", "stix_object": stix}
        except HTTPException:
            raise
        except Exception as e:
            raise HTTPException(500, {"error": str(e)})

else:
    incident_router = None
