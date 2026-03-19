"""
SENTINEL APEX — API Schemas
Pydantic models for request validation and response serialization
"""
from __future__ import annotations

from datetime import datetime
from enum import Enum
from typing import Any, Optional

from pydantic import BaseModel, EmailStr, Field, field_validator


# ── Enums ─────────────────────────────────────────────────────────────

class TierEnum(str, Enum):
    FREE = "free"
    PRO = "pro"
    ENTERPRISE = "enterprise"
    MSSP = "mssp"


class SeverityEnum(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class RoleEnum(str, Enum):
    ADMIN = "admin"
    ANALYST = "analyst"
    VIEWER = "viewer"


# ── Auth Schemas ──────────────────────────────────────────────────────

class SignUpRequest(BaseModel):
    email: EmailStr
    password: str = Field(..., min_length=8, max_length=128)
    full_name: Optional[str] = Field(None, max_length=200)

    @field_validator("password")
    @classmethod
    def strong_password(cls, v: str) -> str:
        if not any(c.isupper() for c in v):
            raise ValueError("Password must contain at least one uppercase letter")
        if not any(c.isdigit() for c in v):
            raise ValueError("Password must contain at least one digit")
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in v):
            raise ValueError("Password must contain at least one special character")
        return v


class SignInRequest(BaseModel):
    email: EmailStr
    password: str


class RefreshRequest(BaseModel):
    refresh_token: str


class OAuthRequest(BaseModel):
    provider: str = Field(..., pattern="^(google|github)$")
    redirect_to: str = Field(default="https://app.cyberdudebivash.com/auth/callback")


class AuthResponse(BaseModel):
    access_token: str
    refresh_token: Optional[str] = None
    token_type: str = "bearer"
    expires_in: int
    user: UserProfile


class UserProfile(BaseModel):
    id: str
    email: str
    full_name: Optional[str] = None
    role: RoleEnum = RoleEnum.VIEWER
    org_id: str
    org_name: Optional[str] = None
    tier: TierEnum = TierEnum.FREE
    created_at: Optional[datetime] = None


# ── API Key Schemas ───────────────────────────────────────────────────

class APIKeyCreateRequest(BaseModel):
    name: str = Field(default="Default", max_length=100)


class APIKeyResponse(BaseModel):
    id: str
    name: str
    key_prefix: str
    tier: TierEnum
    rate_limit_daily: int
    scopes: list[str]
    status: str
    created_at: datetime
    last_used_at: Optional[datetime] = None


class APIKeyCreatedResponse(APIKeyResponse):
    """Only returned once at creation — contains the full key."""
    api_key: str  # Full key, shown only once


class APIKeyListResponse(BaseModel):
    keys: list[APIKeyResponse]
    count: int


# ── Advisory Schemas ──────────────────────────────────────────────────

class AdvisoryBase(BaseModel):
    id: str
    title: str
    severity: Optional[SeverityEnum] = None
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    cvss: Optional[float] = None
    epss: Optional[float] = None
    kev: bool = False
    cve_id: Optional[str] = None
    source: Optional[str] = None
    published_at: Optional[datetime] = None
    ingested_at: Optional[datetime] = None


class AdvisorySummary(AdvisoryBase):
    """Compact advisory for feed listing."""
    summary_ai: Optional[str] = None
    tags: list[str] = []


class AdvisoryDetail(AdvisoryBase):
    """Full advisory detail."""
    description: Optional[str] = None
    summary_ai: Optional[str] = None
    mitre_techniques: list[Any] = []
    iocs: list[Any] = []
    stix_bundle_url: Optional[str] = None
    defense_kit: dict[str, Any] = {}
    source_url: Optional[str] = None
    tags: list[str] = []
    updated_at: Optional[datetime] = None


class FeedResponse(BaseModel):
    data: list[AdvisorySummary]
    total: int
    page: int
    page_size: int
    has_next: bool


class FeedQueryParams(BaseModel):
    """Query parameters for feed endpoint."""
    page: int = Field(default=1, ge=1)
    page_size: int = Field(default=25, ge=1, le=100)
    severity: Optional[SeverityEnum] = None
    min_risk_score: Optional[float] = Field(None, ge=0, le=100)
    kev_only: bool = False
    source: Optional[str] = None
    cve_id: Optional[str] = None
    search: Optional[str] = Field(None, max_length=500)
    sort_by: str = Field(default="published_at", pattern="^(published_at|risk_score|ingested_at)$")
    sort_order: str = Field(default="desc", pattern="^(asc|desc)$")


# ── Usage Schemas ─────────────────────────────────────────────────────

class UsageStats(BaseModel):
    api_key_id: str
    tier: TierEnum
    daily_limit: int
    calls_today: int
    calls_remaining: int
    period: str  # "2026-03-18"


class UsageDetailResponse(BaseModel):
    current: UsageStats
    endpoints: dict[str, int]  # endpoint -> call count today


# ── Pipeline Ingest Schema ────────────────────────────────────────────

class AdvisoryIngestRequest(BaseModel):
    """Schema for pipeline → API advisory writes."""
    id: str
    title: str
    description: Optional[str] = None
    summary_ai: Optional[str] = None
    risk_score: Optional[float] = None
    confidence: Optional[float] = None
    severity: Optional[SeverityEnum] = None
    cvss: Optional[float] = None
    epss: Optional[float] = None
    kev: bool = False
    cve_id: Optional[str] = None
    mitre_techniques: list[Any] = []
    iocs: list[Any] = []
    stix_bundle_url: Optional[str] = None
    defense_kit: dict[str, Any] = {}
    source: Optional[str] = None
    source_url: Optional[str] = None
    tags: list[str] = []
    published_at: Optional[datetime] = None


class BatchIngestRequest(BaseModel):
    advisories: list[AdvisoryIngestRequest]
    pipeline_secret: str


class IngestResponse(BaseModel):
    ingested: int
    errors: int
    advisory_ids: list[str]


# ── Health / Meta ─────────────────────────────────────────────────────

class HealthResponse(BaseModel):
    status: str
    version: str
    environment: str
    timestamp: datetime
    services: dict[str, str]


class ErrorResponse(BaseModel):
    error: str
    detail: Optional[str] = None
    status_code: int
