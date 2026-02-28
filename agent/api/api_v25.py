"""
CYBERDUDEBIVASH® SENTINEL APEX v25.0
API Endpoints
=============

FastAPI Router for v25 Features:
- Cyber-Risk Credit Score API
- CVSS v4.0 Calculator API
- CTEM Engine API
- Digital Twin Simulator API

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

from fastapi import APIRouter, HTTPException, Query, Body, Depends
from fastapi.responses import JSONResponse
from pydantic import BaseModel, Field
from typing import Dict, List, Any, Optional
from datetime import datetime
import uuid
import time

# =============================================================================
# PYDANTIC MODELS
# =============================================================================

# Credit Score Models
class VulnerabilityInput(BaseModel):
    cve_id: str = Field(..., description="CVE identifier")
    cvss_score: float = Field(..., ge=0, le=10, description="CVSS score")
    epss_score: float = Field(0.0, ge=0, le=1, description="EPSS probability")
    kev_listed: bool = Field(False, description="CISA KEV listed")
    published_date: Optional[str] = Field(None, description="ISO date string")
    remediation_status: str = Field("open", description="open/in_progress/mitigated/accepted")
    affected_assets: int = Field(1, ge=1, description="Number of affected assets")


class AssetContextInput(BaseModel):
    asset_id: str = Field("default", description="Asset identifier")
    asset_type: str = Field("endpoint", description="Asset type")
    criticality: str = Field("medium", description="Asset criticality")
    data_classification: str = Field("internal", description="Data classification")
    exposure_zone: str = Field("internal", description="Network zone")
    compliance_scope: List[str] = Field(default_factory=list, description="Compliance frameworks")


class CreditScoreRequest(BaseModel):
    entity_id: str = Field(..., description="Entity identifier")
    vulnerabilities: List[VulnerabilityInput] = Field(..., description="Vulnerability list")
    asset_context: Optional[AssetContextInput] = None
    mttr_hours: Optional[float] = Field(None, description="Mean Time to Remediate")
    industry: str = Field("default", description="Industry for benchmarking")


# CVSS Models
class CVSSv4Request(BaseModel):
    attack_vector: str = Field("N", description="AV: N/A/L/P")
    attack_complexity: str = Field("L", description="AC: L/H")
    attack_requirements: str = Field("N", description="AT: N/P")
    privileges_required: str = Field("N", description="PR: N/L/H")
    user_interaction: str = Field("N", description="UI: N/P/A")
    vuln_conf_impact: str = Field("H", description="VC: H/L/N")
    vuln_integ_impact: str = Field("H", description="VI: H/L/N")
    vuln_avail_impact: str = Field("H", description="VA: H/L/N")
    sub_conf_impact: str = Field("N", description="SC: H/L/N")
    sub_integ_impact: str = Field("N", description="SI: H/L/N")
    sub_avail_impact: str = Field("N", description="SA: H/L/N")
    exploit_maturity: str = Field("X", description="E: X/A/P/U")
    conf_requirement: str = Field("X", description="CR: X/H/M/L")
    integ_requirement: str = Field("X", description="IR: X/H/M/L")
    avail_requirement: str = Field("X", description="AR: X/H/M/L")


class CVSSParseRequest(BaseModel):
    vector: str = Field(..., description="CVSS vector string")


class CVSSBatchRequest(BaseModel):
    vectors: List[str] = Field(..., description="List of CVSS vectors")


# CTEM Models
class CTEMScopeRequest(BaseModel):
    name: str = Field(..., description="Scope name")
    asset_types: List[str] = Field(default_factory=list)
    business_units: List[str] = Field(default_factory=list)
    compliance_frameworks: List[str] = Field(default_factory=list)
    exposure_zones: List[str] = Field(default_factory=lambda: ["internet_facing", "dmz"])
    description: str = Field("", description="Scope description")
    owner: str = Field("", description="Scope owner")


class CTEMDiscoveryRequest(BaseModel):
    scope_id: str = Field(..., description="Scope ID")
    vulnerabilities: List[Dict[str, Any]] = Field(..., description="Vulnerability data")


class CTEMValidationRequest(BaseModel):
    result: str = Field(..., description="Validation result")
    notes: str = Field("", description="Validation notes")
    tested_by: str = Field("", description="Tester identifier")


class CTEMRemediationRequest(BaseModel):
    title: str = Field(..., description="Task title")
    task_type: str = Field("patch", description="Task type")
    assignee: str = Field("", description="Assignee")
    team: str = Field("", description="Team")
    estimated_hours: float = Field(0.0, ge=0, description="Effort estimate")


# Simulator Models
class SimulatorBuildRequest(BaseModel):
    endpoints: int = Field(100, ge=0, le=10000)
    servers: int = Field(20, ge=0, le=1000)
    web_apps: int = Field(5, ge=0, le=100)
    databases: int = Field(3, ge=0, le=50)
    domain_controllers: int = Field(2, ge=0, le=10)


class BreachSimulationRequest(BaseModel):
    attack_vector: str = Field("PHISHING", description="Attack vector")
    entry_asset: Optional[str] = Field(None, description="Entry point asset ID")


class MonteCarloRequest(BaseModel):
    iterations: int = Field(100, ge=10, le=500)
    attack_vectors: Optional[List[str]] = Field(None, description="Attack vectors to simulate")


class AttackPathRequest(BaseModel):
    entry_point: str = Field(..., description="Entry point asset ID")
    target: str = Field(..., description="Target asset ID")
    max_paths: int = Field(5, ge=1, le=20)


# =============================================================================
# RESPONSE HELPERS
# =============================================================================

def v25_response(
    data: Any,
    request_id: Optional[str] = None,
    latency_ms: Optional[float] = None
) -> Dict[str, Any]:
    """Standard v25 API response envelope"""
    return {
        "success": True,
        "api_version": "v25.0",
        "request_id": request_id or f"req-{uuid.uuid4().hex[:12]}",
        "timestamp": datetime.utcnow().isoformat(),
        "latency_ms": latency_ms,
        "data": data,
    }


def v25_error(
    message: str,
    code: str = "ERROR",
    status_code: int = 400
) -> JSONResponse:
    """Standard v25 error response"""
    return JSONResponse(
        status_code=status_code,
        content={
            "success": False,
            "api_version": "v25.0",
            "error": {
                "code": code,
                "message": message,
            },
            "timestamp": datetime.utcnow().isoformat(),
        }
    )


# =============================================================================
# API ROUTER
# =============================================================================

router = APIRouter(prefix="/api/v1", tags=["v25"])


# =============================================================================
# HEALTH & STATUS
# =============================================================================

@router.get("/v25/status")
async def v25_status():
    """Get v25 module status"""
    start = time.time()
    
    modules = {
        "cyber_risk_credit": False,
        "cvss_v4": False,
        "ctem": False,
        "digital_twin": False,
    }
    
    try:
        from ..scoring import get_available_modules
        scoring_mods = get_available_modules()
        modules["cyber_risk_credit"] = scoring_mods.get("cyber_risk_credit", False)
        modules["cvss_v4"] = scoring_mods.get("cvss_v4", False)
    except ImportError:
        pass
    
    try:
        from ..ctem import get_ctem_engine
        get_ctem_engine()
        modules["ctem"] = True
    except ImportError:
        pass
    
    try:
        from ..simulator import get_simulator
        get_simulator()
        modules["digital_twin"] = True
    except ImportError:
        pass
    
    latency = (time.time() - start) * 1000
    
    return v25_response({
        "version": "25.0.0",
        "codename": "SENTINEL APEX ULTRA",
        "release_date": "2026-02-28",
        "modules": modules,
        "all_modules_active": all(modules.values()),
    }, latency_ms=round(latency, 2))


# =============================================================================
# CREDIT SCORE ENDPOINTS
# =============================================================================

@router.get("/credit/score")
async def get_credit_score_demo():
    """Get demo credit score calculation"""
    start = time.time()
    
    try:
        from ..scoring.cyber_risk_credit import calculate_credit_score
        
        # Demo data
        demo_vulns = [
            {"cve_id": "CVE-2024-1234", "cvss_score": 9.8, "epss_score": 0.85, "kev_listed": True},
            {"cve_id": "CVE-2024-5678", "cvss_score": 7.5, "epss_score": 0.45, "kev_listed": False},
            {"cve_id": "CVE-2024-9012", "cvss_score": 5.3, "epss_score": 0.12, "kev_listed": False},
        ]
        
        result = calculate_credit_score(
            entity_id="demo-org",
            vulnerabilities=demo_vulns,
            industry="technology",
        )
        
        latency = (time.time() - start) * 1000
        return v25_response(result, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "CREDIT_SCORE_ERROR", 500)


@router.post("/credit/score/custom")
async def calculate_custom_credit_score(request: CreditScoreRequest):
    """Calculate credit score with custom data"""
    start = time.time()
    
    try:
        from ..scoring.cyber_risk_credit import calculate_credit_score
        
        # Convert to dict format
        vulns = [v.dict() for v in request.vulnerabilities]
        asset_ctx = request.asset_context.dict() if request.asset_context else None
        
        result = calculate_credit_score(
            entity_id=request.entity_id,
            vulnerabilities=vulns,
            asset_context=asset_ctx,
            mttr_hours=request.mttr_hours,
            industry=request.industry,
        )
        
        latency = (time.time() - start) * 1000
        return v25_response(result, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "CREDIT_SCORE_ERROR", 500)


@router.get("/credit/history/{entity_id}")
async def get_credit_history(
    entity_id: str,
    days: int = Query(30, ge=1, le=365)
):
    """Get credit score history for an entity"""
    start = time.time()
    
    try:
        from ..scoring.cyber_risk_credit import get_credit_engine
        
        engine = get_credit_engine()
        history = engine.get_history(entity_id, days)
        
        latency = (time.time() - start) * 1000
        return v25_response({
            "entity_id": entity_id,
            "days": days,
            "history": history,
            "data_points": len(history),
        }, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "HISTORY_ERROR", 500)


# =============================================================================
# CVSS v4.0 ENDPOINTS
# =============================================================================

@router.post("/cvss/v4/calculate")
async def calculate_cvss_v4(request: CVSSv4Request):
    """Calculate CVSS v4.0 score from metrics"""
    start = time.time()
    
    try:
        from ..scoring.cvss_v4 import calculate_cvss_v4 as calc
        
        result = calc(
            attack_vector=request.attack_vector,
            attack_complexity=request.attack_complexity,
            attack_requirements=request.attack_requirements,
            privileges_required=request.privileges_required,
            user_interaction=request.user_interaction,
            vuln_conf_impact=request.vuln_conf_impact,
            vuln_integ_impact=request.vuln_integ_impact,
            vuln_avail_impact=request.vuln_avail_impact,
            sub_conf_impact=request.sub_conf_impact,
            sub_integ_impact=request.sub_integ_impact,
            sub_avail_impact=request.sub_avail_impact,
            exploit_maturity=request.exploit_maturity,
            conf_requirement=request.conf_requirement,
            integ_requirement=request.integ_requirement,
            avail_requirement=request.avail_requirement,
        )
        
        latency = (time.time() - start) * 1000
        return v25_response(result, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "CVSS_CALC_ERROR", 500)


@router.post("/cvss/v4/parse")
async def parse_cvss_vector(request: CVSSParseRequest):
    """Parse and calculate CVSS from vector string"""
    start = time.time()
    
    try:
        from ..scoring.cvss_v4 import parse_and_calculate
        
        result = parse_and_calculate(request.vector)
        
        latency = (time.time() - start) * 1000
        return v25_response(result, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "CVSS_PARSE_ERROR", 400)


@router.post("/cvss/v4/batch")
async def batch_cvss_calculation(request: CVSSBatchRequest):
    """Batch calculate multiple CVSS vectors"""
    start = time.time()
    
    try:
        from ..scoring.cvss_v4 import get_cvss_calculator
        
        calculator = get_cvss_calculator()
        results = calculator.batch_calculate(request.vectors)
        
        latency = (time.time() - start) * 1000
        return v25_response({
            "total": len(request.vectors),
            "results": results,
        }, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "CVSS_BATCH_ERROR", 500)


# =============================================================================
# CTEM ENDPOINTS
# =============================================================================

@router.post("/ctem/scope/create")
async def create_ctem_scope(request: CTEMScopeRequest):
    """Create a new CTEM scope"""
    start = time.time()
    
    try:
        from ..ctem import get_ctem_engine
        
        engine = get_ctem_engine()
        scope = engine.create_scope(
            name=request.name,
            asset_types=request.asset_types,
            business_units=request.business_units,
            compliance_frameworks=request.compliance_frameworks,
            exposure_zones=request.exposure_zones,
            description=request.description,
            owner=request.owner,
        )
        
        latency = (time.time() - start) * 1000
        return v25_response(scope.to_dict(), latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "SCOPE_CREATE_ERROR", 500)


@router.get("/ctem/scopes")
async def list_ctem_scopes(active_only: bool = Query(True)):
    """List all CTEM scopes"""
    start = time.time()
    
    try:
        from ..ctem import get_ctem_engine
        
        engine = get_ctem_engine()
        scopes = engine.list_scopes(active_only)
        
        latency = (time.time() - start) * 1000
        return v25_response({
            "scopes": [s.to_dict() for s in scopes],
            "total": len(scopes),
        }, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "SCOPE_LIST_ERROR", 500)


@router.post("/ctem/discover")
async def run_ctem_discovery(request: CTEMDiscoveryRequest):
    """Run CTEM discovery on vulnerabilities"""
    start = time.time()
    
    try:
        from ..ctem import get_ctem_engine
        
        engine = get_ctem_engine()
        exposures = engine.bulk_discover(
            request.scope_id,
            request.vulnerabilities,
        )
        
        latency = (time.time() - start) * 1000
        return v25_response({
            "scope_id": request.scope_id,
            "exposures_created": len(exposures),
            "exposures": [e.to_dict() for e in exposures[:20]],  # Limit response
            "truncated": len(exposures) > 20,
        }, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "DISCOVERY_ERROR", 500)


@router.get("/ctem/exposures")
async def list_exposures(
    scope_id: Optional[str] = Query(None),
    status: Optional[str] = Query(None),
    priority: Optional[str] = Query(None),
    limit: int = Query(50, ge=1, le=500)
):
    """List exposures with filters"""
    start = time.time()
    
    try:
        from ..ctem import get_ctem_engine
        
        engine = get_ctem_engine()
        exposures = engine.list_exposures(
            scope_id=scope_id,
            status=status,
            priority=priority,
            limit=limit,
        )
        
        latency = (time.time() - start) * 1000
        return v25_response({
            "exposures": [e.to_dict() for e in exposures],
            "total": len(exposures),
            "filters": {
                "scope_id": scope_id,
                "status": status,
                "priority": priority,
            },
        }, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "EXPOSURE_LIST_ERROR", 500)


@router.get("/ctem/exposure/{exposure_id}")
async def get_exposure(exposure_id: str):
    """Get single exposure details"""
    start = time.time()
    
    try:
        from ..ctem import get_ctem_engine
        
        engine = get_ctem_engine()
        exposure = engine.get_exposure(exposure_id)
        
        if not exposure:
            return v25_error(f"Exposure not found: {exposure_id}", "NOT_FOUND", 404)
        
        latency = (time.time() - start) * 1000
        return v25_response(exposure.to_dict(), latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "EXPOSURE_GET_ERROR", 500)


@router.post("/ctem/validate/{exposure_id}")
async def validate_exposure(exposure_id: str, request: CTEMValidationRequest):
    """Record validation result for exposure"""
    start = time.time()
    
    try:
        from ..ctem import get_ctem_engine
        
        engine = get_ctem_engine()
        exposure = engine.validate_exposure(
            exposure_id=exposure_id,
            result=request.result,
            notes=request.notes,
            tested_by=request.tested_by,
        )
        
        latency = (time.time() - start) * 1000
        return v25_response(exposure.to_dict(), latency_ms=round(latency, 2))
    
    except ValueError as e:
        return v25_error(str(e), "NOT_FOUND", 404)
    except Exception as e:
        return v25_error(str(e), "VALIDATION_ERROR", 500)


@router.post("/ctem/remediate/{exposure_id}")
async def create_remediation_task(exposure_id: str, request: CTEMRemediationRequest):
    """Create remediation task for exposure"""
    start = time.time()
    
    try:
        from ..ctem import get_ctem_engine
        
        engine = get_ctem_engine()
        task = engine.create_remediation_task(
            exposure_id=exposure_id,
            title=request.title,
            task_type=request.task_type,
            assignee=request.assignee,
            team=request.team,
            estimated_hours=request.estimated_hours,
        )
        
        latency = (time.time() - start) * 1000
        return v25_response(task.to_dict(), latency_ms=round(latency, 2))
    
    except ValueError as e:
        return v25_error(str(e), "NOT_FOUND", 404)
    except Exception as e:
        return v25_error(str(e), "REMEDIATION_ERROR", 500)


@router.get("/ctem/metrics")
async def get_ctem_metrics(scope_id: Optional[str] = Query(None)):
    """Get CTEM performance metrics"""
    start = time.time()
    
    try:
        from ..ctem import get_ctem_engine
        
        engine = get_ctem_engine()
        metrics = engine.calculate_metrics(scope_id)
        
        latency = (time.time() - start) * 1000
        return v25_response(metrics.to_dict(), latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "METRICS_ERROR", 500)


@router.get("/ctem/executive-summary")
async def get_executive_summary(scope_id: Optional[str] = Query(None)):
    """Get executive summary report"""
    start = time.time()
    
    try:
        from ..ctem import get_ctem_engine
        
        engine = get_ctem_engine()
        summary = engine.generate_executive_summary(scope_id)
        
        latency = (time.time() - start) * 1000
        return v25_response(summary, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "SUMMARY_ERROR", 500)


@router.get("/ctem/sla-breaches")
async def get_sla_breaches(
    scope_id: Optional[str] = Query(None),
    include_at_risk: bool = Query(True)
):
    """Get SLA breaches and at-risk exposures"""
    start = time.time()
    
    try:
        from ..ctem import get_ctem_engine
        
        engine = get_ctem_engine()
        breaches = engine.get_sla_breaches(scope_id, include_at_risk)
        
        latency = (time.time() - start) * 1000
        return v25_response({
            "breaches": breaches,
            "total": len(breaches),
            "breached_count": sum(1 for b in breaches if b["status"] == "BREACHED"),
            "at_risk_count": sum(1 for b in breaches if b["status"] == "AT_RISK"),
        }, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "SLA_ERROR", 500)


# =============================================================================
# DIGITAL TWIN SIMULATOR ENDPOINTS
# =============================================================================

@router.post("/simulator/build")
async def build_digital_twin(request: SimulatorBuildRequest):
    """Build digital twin environment"""
    start = time.time()
    
    try:
        from ..simulator import get_simulator
        
        simulator = get_simulator()
        count = simulator.build_default_environment(
            endpoints=request.endpoints,
            servers=request.servers,
            web_apps=request.web_apps,
            databases=request.databases,
            domain_controllers=request.domain_controllers,
        )
        
        summary = simulator.get_attack_surface_summary()
        
        latency = (time.time() - start) * 1000
        return v25_response({
            "assets_created": count,
            "attack_surface": summary,
        }, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "BUILD_ERROR", 500)


@router.post("/simulator/breach")
async def run_breach_simulation(request: BreachSimulationRequest):
    """Run single breach simulation"""
    start = time.time()
    
    try:
        from ..simulator import get_simulator
        
        simulator = get_simulator()
        
        # Ensure environment exists
        if not simulator._assets:
            simulator.build_default_environment()
        
        scenario = simulator.simulate_breach(
            attack_vector=request.attack_vector,
            entry_asset=request.entry_asset,
        )
        
        latency = (time.time() - start) * 1000
        return v25_response(scenario.to_dict(), latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "BREACH_ERROR", 500)


@router.post("/simulator/monte-carlo")
async def run_monte_carlo_simulation(request: MonteCarloRequest):
    """Run Monte Carlo breach simulation"""
    start = time.time()
    
    try:
        from ..simulator import get_simulator
        
        simulator = get_simulator()
        
        # Ensure environment exists
        if not simulator._assets:
            simulator.build_default_environment()
        
        result = simulator.run_monte_carlo(
            iterations=request.iterations,
            attack_vectors=request.attack_vectors,
        )
        
        latency = (time.time() - start) * 1000
        return v25_response(result.to_dict(), latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "MONTE_CARLO_ERROR", 500)


@router.post("/simulator/attack-paths")
async def find_attack_paths(request: AttackPathRequest):
    """Find attack paths between assets"""
    start = time.time()
    
    try:
        from ..simulator import get_simulator
        
        simulator = get_simulator()
        
        if not simulator._assets:
            return v25_error(
                "No environment built. Call /simulator/build first.",
                "NO_ENVIRONMENT",
                400
            )
        
        paths = simulator.find_attack_paths(
            entry_point=request.entry_point,
            target=request.target,
            max_paths=request.max_paths,
        )
        
        latency = (time.time() - start) * 1000
        return v25_response({
            "entry_point": request.entry_point,
            "target": request.target,
            "paths_found": len(paths),
            "paths": [p.to_dict() for p in paths],
        }, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "PATH_ERROR", 500)


@router.get("/simulator/attack-surface")
async def get_attack_surface():
    """Get attack surface summary"""
    start = time.time()
    
    try:
        from ..simulator import get_simulator
        
        simulator = get_simulator()
        
        if not simulator._assets:
            return v25_response({
                "status": "no_environment",
                "message": "No environment built. Call /simulator/build first.",
            })
        
        summary = simulator.get_attack_surface_summary()
        
        latency = (time.time() - start) * 1000
        return v25_response(summary, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "SURFACE_ERROR", 500)


@router.get("/simulator/recommendations")
async def get_security_recommendations():
    """Get security recommendations from latest simulation"""
    start = time.time()
    
    try:
        from ..simulator import get_simulator
        
        simulator = get_simulator()
        
        if not simulator._assets:
            simulator.build_default_environment()
        
        # Run quick Monte Carlo for recommendations
        result = simulator.run_monte_carlo(iterations=50)
        
        latency = (time.time() - start) * 1000
        return v25_response({
            "risk_score": round(result.overall_risk_score, 1),
            "recommendations": result.recommendations,
            "simulation_stats": {
                "breach_success_rate": f"{result.breach_success_rate*100:.1f}%",
                "detection_rate": f"{result.detection_rate*100:.1f}%",
                "crown_jewel_access_rate": f"{result.crown_jewel_access_rate*100:.1f}%",
            },
        }, latency_ms=round(latency, 2))
    
    except Exception as e:
        return v25_error(str(e), "RECOMMENDATIONS_ERROR", 500)


# =============================================================================
# ROUTER REGISTRATION
# =============================================================================

def register_v25_routes(app):
    """Register v25 API routes with FastAPI app"""
    app.include_router(router)
    return router


__all__ = [
    "router",
    "register_v25_routes",
]
