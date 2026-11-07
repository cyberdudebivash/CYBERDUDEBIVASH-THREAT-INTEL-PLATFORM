"""
╔══════════════════════════════════════════════════════════════════════════════╗
║  CYBERDUDEBIVASH® SENTINEL APEX — API SCHEMAS v1.0                        ║
║  Pydantic v2 models for strict request/response validation                 ║
╚══════════════════════════════════════════════════════════════════════════════╝
All API responses follow the standard envelope:
  { "status": "success|error", "data": {...}, "meta": {...} }
"""

from __future__ import annotations

import uuid
import time
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Union
from pydantic import BaseModel, Field, field_validator, model_validator


# ── STANDARD RESPONSE ENVELOPE ────────────────────────────────────────────────

class ResponseMeta(BaseModel):
    request_id: str = Field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    processing_time_ms: float = 0.0
    api_version: str = "v1"
    platform: str = "CYBERDUDEBIVASH® Sentinel APEX"


class StandardResponse(BaseModel):
    status: str = "success"
    data: Any = None
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


class ErrorResponse(BaseModel):
    status: str = "error"
    error: str
    code: int
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


# ── PAGINATION ────────────────────────────────────────────────────────────────

class PaginationMeta(ResponseMeta):
    page: int = 1
    per_page: int = 20
    total: int = 0
    total_pages: int = 1


# ── THREAT INTELLIGENCE SCHEMAS ───────────────────────────────────────────────

class ThreatItem(BaseModel):
    id: Optional[str] = None
    cve_id: Optional[str] = None
    title: str = ""
    severity: str = "MEDIUM"
    risk_score: Optional[float] = None
    cvss: Optional[float] = None
    epss: Optional[float] = None
    kev_confirmed: bool = False
    exploit_status: Optional[str] = None
    mitre_techniques: List[str] = []
    actors: Optional[str] = None
    summary: Optional[str] = None
    source: Optional[str] = None
    timestamp: Optional[str] = None
    tags: List[str] = []

    model_config = {"extra": "allow"}  # Pass-through enrichment fields


class ThreatListResponse(BaseModel):
    status: str = "success"
    data: List[ThreatItem]
    total: int
    page: int = 1
    per_page: int = 20
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


class ThreatDetailResponse(BaseModel):
    status: str = "success"
    data: ThreatItem
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


# ── IOC SCHEMAS ───────────────────────────────────────────────────────────────

class IOCItem(BaseModel):
    ioc_value: str
    ioc_type: str  # ipv4, sha256, md5, url, domain, manifest_ioc
    source_advisory: Optional[str] = None
    severity: str = "MEDIUM"
    confidence: float = 0.5
    kev_linked: bool = False
    dispatch_priority: int = 4
    siem_action: str = "MONITOR"

    @field_validator("confidence")
    @classmethod
    def clamp_confidence(cls, v: float) -> float:
        return max(0.0, min(1.0, v))


class IOCListResponse(BaseModel):
    status: str = "success"
    data: List[IOCItem]
    total: int
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


# ── PREDICTION SCHEMAS ────────────────────────────────────────────────────────

class PredictRequest(BaseModel):
    context: Optional[str] = Field(
        default=None,
        description="Optional context string to filter predictions",
        max_length=500,
    )
    include_supply_chain: bool = True
    include_actor_attribution: bool = True

    @field_validator("context", mode="before")
    @classmethod
    def sanitize_context(cls, v):
        if v is not None:
            v = str(v).strip()[:500]
            # No script injection
            v = v.replace("<", "").replace(">", "").replace(";", "")
        return v


class PredictionItem(BaseModel):
    prediction: str
    confidence: float
    evidence: Optional[str] = None
    recommended_action: Optional[str] = None
    horizon: Optional[str] = None


class PredictResponse(BaseModel):
    status: str = "success"
    data: Dict[str, Any]
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


# ── IDENTITY RISK SCHEMAS ─────────────────────────────────────────────────────

class IdentityRiskSummary(BaseModel):
    overall_risk: str = "UNKNOWN"
    critical_signals: int = 0
    high_signals: int = 0
    total_signals: int = 0
    cve_identity_risks: int = 0
    stealer_families_detected: int = 0
    remediation_actions: int = 0


class IdentityRiskResponse(BaseModel):
    status: str = "success"
    data: Dict[str, Any]
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


# ── DARK WEB SCHEMAS ──────────────────────────────────────────────────────────

class DarkWebSignal(BaseModel):
    advisory_id: Optional[str] = None
    cve_id: Optional[str] = None
    title: str = ""
    dark_web_patterns: List[str] = []
    severity: str = "MEDIUM"
    confidence: float = 0.5


class DarkWebResponse(BaseModel):
    status: str = "success"
    data: Dict[str, Any]
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


# ── RISK SCORE SCHEMAS ────────────────────────────────────────────────────────

class RiskScoreItem(BaseModel):
    cve_id: str
    cvss: float
    sector: str
    exploit_status: str
    kev_confirmed: bool
    epss: float
    annualized_loss_expectancy_usd: float
    ale_formatted: str
    severity_tier: str
    explanation: str


class RiskScoreResponse(BaseModel):
    status: str = "success"
    data: Dict[str, Any]
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


# ── DETECTION RULE SCHEMAS ────────────────────────────────────────────────────

class DetectionRule(BaseModel):
    rule_id: str
    technique: str
    name: str
    tactic: str
    frequency: int
    splunk_query: Optional[str] = None
    kql_query: Optional[str] = None


class DetectionResponse(BaseModel):
    status: str = "success"
    data: Dict[str, Any]
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


# ── SOAR ACTION SCHEMAS ───────────────────────────────────────────────────────

class SOARActionRequest(BaseModel):
    action_type: str = Field(
        ...,
        description="Action type: BLOCK_IP, ENRICH_IOC, CREATE_INCIDENT, GET_PLAYBOOK",
    )
    target: Optional[str] = Field(
        default=None,
        max_length=200,
        description="Target for the action (IP, IOC value, advisory ID)",
    )
    playbook: Optional[str] = Field(
        default=None,
        max_length=100,
        description="Playbook name for GET_PLAYBOOK action",
    )
    dry_run: bool = Field(
        default=True,
        description="Always True in simulation mode; set False for live execution (requires MSSP tier)",
    )

    @field_validator("action_type")
    @classmethod
    def validate_action_type(cls, v: str) -> str:
        allowed = {
            "BLOCK_IP", "ENRICH_IOC", "CREATE_INCIDENT",
            "GET_PLAYBOOK", "LIST_PLAYBOOKS", "GET_DISPATCH_QUEUE",
        }
        v = v.upper().strip()
        if v not in allowed:
            raise ValueError(f"Invalid action_type. Allowed: {', '.join(sorted(allowed))}")
        return v

    @field_validator("target", mode="before")
    @classmethod
    def sanitize_target(cls, v):
        if v is not None:
            v = str(v).strip()[:200]
            v = v.replace(";", "").replace("'", "").replace('"', "")
        return v


class SOARActionResponse(BaseModel):
    status: str = "success"
    data: Dict[str, Any]
    meta: ResponseMeta = Field(default_factory=ResponseMeta)


# ── API KEY VALIDATION ────────────────────────────────────────────────────────

class APIKeyInfo(BaseModel):
    key_id: Optional[str] = None
    tier: str = "FREE"
    scopes: List[str] = []
    requests_today: int = 0
    requests_limit: int = 100
    quota_remaining: int = 100
    valid: bool = True


# ── HEALTH CHECK ──────────────────────────────────────────────────────────────

class EngineStatus(BaseModel):
    name: str
    status: str  # OPERATIONAL, DEGRADED, OFFLINE
    last_run: Optional[str] = None
    outputs_available: bool = False


class HealthResponse(BaseModel):
    status: str = "healthy"
    version: str = "v1"
    engines: List[EngineStatus] = []
    uptime_seconds: float = 0.0
    timestamp: str = Field(default_factory=lambda: datetime.now(timezone.utc).isoformat())


# ── FACTORY HELPERS ───────────────────────────────────────────────────────────

def make_response(data: Any, request_id: str = None,
                  start_time: float = None) -> Dict[str, Any]:
    """Build standardized response envelope."""
    elapsed = (time.monotonic() - start_time) * 1000 if start_time else 0.0
    meta = {
        "request_id": request_id or str(uuid.uuid4()),
        "timestamp": datetime.now(timezone.utc).isoformat(),
        "processing_time_ms": round(elapsed, 2),
        "api_version": "v1",
        "platform": "CYBERDUDEBIVASH® Sentinel APEX",
    }
    return {"status": "success", "data": data, "meta": meta}


def make_error(message: str, code: int, request_id: str = None) -> Dict[str, Any]:
    """Build standardized error response."""
    return {
        "status": "error",
        "error": message,
        "code": code,
        "meta": {
            "request_id": request_id or str(uuid.uuid4()),
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "processing_time_ms": 0.0,
            "api_version": "v1",
        },
    }
