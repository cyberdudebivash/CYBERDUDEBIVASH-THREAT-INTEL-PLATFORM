"""
SENTINEL APEX — Core Configuration
CYBERDUDEBIVASH PVT LTD
"""
from __future__ import annotations

import os
from enum import Enum
from functools import lru_cache
from typing import Optional

from pydantic import field_validator
from pydantic_settings import BaseSettings


class Environment(str, Enum):
    DEVELOPMENT = "development"
    STAGING = "staging"
    PRODUCTION = "production"


class Settings(BaseSettings):
    """Application settings loaded from environment variables."""

    # ── App ──────────────────────────────────────────────────────────
    APP_NAME: str = "Sentinel APEX API"
    APP_VERSION: str = "1.0.0"
    ENVIRONMENT: Environment = Environment.PRODUCTION
    DEBUG: bool = False
    LOG_LEVEL: str = "INFO"

    # ── Server ───────────────────────────────────────────────────────
    HOST: str = "0.0.0.0"
    PORT: int = 8000
    WORKERS: int = 2
    CORS_ORIGINS: str = "https://intel.cyberdudebivash.com,https://app.cyberdudebivash.com,http://localhost:3000"

    # ── Supabase ─────────────────────────────────────────────────────
    SUPABASE_URL: str
    SUPABASE_ANON_KEY: str
    SUPABASE_SERVICE_KEY: str
    SUPABASE_JWT_SECRET: str

    # ── Database (Direct PG connection for FastAPI)
    DATABASE_URL: Optional[str] = None  # postgresql://... from Supabase

    # ── Redis (Upstash) ──────────────────────────────────────────────
    UPSTASH_REDIS_URL: Optional[str] = None
    UPSTASH_REDIS_TOKEN: Optional[str] = None

    # ── Stripe ───────────────────────────────────────────────────────
    STRIPE_SECRET_KEY: Optional[str] = None
    STRIPE_WEBHOOK_SECRET: Optional[str] = None
    STRIPE_PRICE_PRO: Optional[str] = None
    STRIPE_PRICE_ENTERPRISE: Optional[str] = None
    STRIPE_PRICE_MSSP: Optional[str] = None

    # ── AI (Claude API for threat summarization)
    ANTHROPIC_API_KEY: Optional[str] = None
    AI_MODEL: str = "claude-sonnet-4-20250514"
    AI_MAX_TOKENS: int = 300

    # ── Security ─────────────────────────────────────────────────────
    API_KEY_PREFIX: str = "cdb_sk_live_"
    JWT_ALGORITHM: str = "HS256"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 60
    REFRESH_TOKEN_EXPIRE_DAYS: int = 30

    # ── Rate Limiting Defaults ───────────────────────────────────────
    RATE_LIMIT_FREE: int = 10
    RATE_LIMIT_PRO: int = 1000
    RATE_LIMIT_ENTERPRISE: int = 100000

    # ── Pipeline Integration ─────────────────────────────────────────
    PIPELINE_SECRET: Optional[str] = None  # Shared secret for pipeline → API writes
    GITHUB_REPO: str = "cyberdudebivash/CYBERDUDEBIVASH-THREAT-INTEL-PLATFORM"

    @field_validator("CORS_ORIGINS")
    @classmethod
    def parse_cors(cls, v: str) -> str:
        return v

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.CORS_ORIGINS.split(",") if o.strip()]

    @property
    def is_production(self) -> bool:
        return self.ENVIRONMENT == Environment.PRODUCTION

    model_config = {"env_file": ".env", "env_file_encoding": "utf-8", "case_sensitive": True}


@lru_cache()
def get_settings() -> Settings:
    return Settings()
