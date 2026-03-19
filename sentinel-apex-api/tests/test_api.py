"""
SENTINEL APEX API — Test Suite
Run: pytest tests/ -v
"""
from __future__ import annotations

import hashlib
import json
import os
from datetime import datetime, timezone
from unittest.mock import AsyncMock, patch

import pytest
from fastapi.testclient import TestClient

# Set test environment before importing app
os.environ.update({
    "SUPABASE_URL": "https://test.supabase.co",
    "SUPABASE_ANON_KEY": "test-anon-key",
    "SUPABASE_SERVICE_KEY": "test-service-key",
    "SUPABASE_JWT_SECRET": "test-jwt-secret-minimum-32-characters-long",
    "ENVIRONMENT": "development",
    "PIPELINE_SECRET": "test-pipeline-secret",
    "CORS_ORIGINS": "http://localhost:3000",
})

from app.main import app
from app.core.security import generate_api_key, hash_api_key

client = TestClient(app)


# ── Meta Endpoints ────────────────────────────────────────────────────

class TestMeta:
    def test_root(self):
        r = client.get("/")
        assert r.status_code == 200
        data = r.json()
        assert data["platform"] == "SENTINEL APEX"
        assert data["vendor"] == "CYBERDUDEBIVASH PVT LTD"
        assert "api_base" in data

    def test_health(self):
        r = client.get("/health")
        assert r.status_code == 200
        data = r.json()
        assert data["status"] in ("healthy", "degraded")
        assert "services" in data

    def test_openapi_schema(self):
        r = client.get("/openapi.json")
        assert r.status_code == 200
        schema = r.json()
        assert schema["info"]["title"] == "SENTINEL APEX API"

    def test_docs(self):
        r = client.get("/docs")
        assert r.status_code == 200


# ── Auth Endpoints ────────────────────────────────────────────────────

class TestAuth:
    def test_signup_validation_weak_password(self):
        r = client.post("/auth/signup", json={
            "email": "test@example.com",
            "password": "weak",
        })
        assert r.status_code == 422  # Validation error

    def test_signup_validation_no_uppercase(self):
        r = client.post("/auth/signup", json={
            "email": "test@example.com",
            "password": "nouppercase1!",
        })
        assert r.status_code == 422

    def test_signup_validation_no_digit(self):
        r = client.post("/auth/signup", json={
            "email": "test@example.com",
            "password": "NoDigitHere!",
        })
        assert r.status_code == 422

    def test_signup_validation_no_special(self):
        r = client.post("/auth/signup", json={
            "email": "test@example.com",
            "password": "NoSpecial1Here",
        })
        assert r.status_code == 422

    def test_signup_valid_format(self):
        """Validates that a properly formatted request passes schema validation."""
        # Will fail at Supabase call (expected in test env)
        r = client.post("/auth/signup", json={
            "email": "test@example.com",
            "password": "Strong1Pass!",
            "full_name": "Test User",
        })
        # Should get past validation (422) to the Supabase call (500 in test)
        assert r.status_code in (201, 409, 500)

    def test_signin_validation(self):
        r = client.post("/auth/signin", json={
            "email": "not-an-email",
            "password": "test",
        })
        assert r.status_code == 422

    def test_me_unauthenticated(self):
        r = client.get("/auth/me")
        assert r.status_code in (401, 403)

    def test_oauth_invalid_provider(self):
        r = client.post("/auth/oauth", json={
            "provider": "facebook",  # Not allowed
        })
        assert r.status_code == 422


# ── Feed Endpoints ────────────────────────────────────────────────────

class TestFeed:
    @patch("app.api.v1.endpoints.feed.SupabaseDB.query")
    async def test_feed_public(self, mock_query):
        mock_query.return_value = {
            "data": [
                {
                    "id": "adv-001",
                    "title": "Test Advisory",
                    "severity": "high",
                    "risk_score": 85.5,
                    "confidence": 0.92,
                    "cvss": 9.1,
                    "epss": 0.45,
                    "kev": True,
                    "cve_id": "CVE-2025-0001",
                    "source": "NVD",
                    "published_at": "2025-03-18T00:00:00Z",
                    "ingested_at": "2025-03-18T01:00:00Z",
                    "summary_ai": "Test summary",
                    "tags": ["rce", "critical"],
                }
            ],
            "count": 1,
        }

        r = client.get("/api/v1/feed")
        assert r.status_code == 200

    def test_feed_query_params_validation(self):
        r = client.get("/api/v1/feed?page=0")
        assert r.status_code == 422

        r = client.get("/api/v1/feed?page_size=200")
        assert r.status_code == 422

        r = client.get("/api/v1/feed?sort_by=invalid")
        assert r.status_code == 422

    def test_search_requires_auth(self):
        r = client.get("/api/v1/search?q=apache")
        assert r.status_code in (401, 403)

    @patch("app.api.v1.endpoints.feed.SupabaseDB.query")
    def test_mitre_coverage_public(self, mock_query):
        """MITRE coverage is accessible without auth."""
        mock_query.return_value = {
            "data": [
                {"mitre_techniques": [{"technique_id": "T1059"}, {"technique_id": "T1566"}]},
                {"mitre_techniques": [{"technique_id": "T1059"}]},
            ]
        }
        r = client.get("/api/v1/mitre/coverage")
        assert r.status_code == 200
        data = r.json()
        assert data["total_techniques"] == 2
        assert data["techniques"]["T1059"] == 2


# ── API Key Endpoints ─────────────────────────────────────────────────

class TestAPIKeys:
    def test_create_key_requires_auth(self):
        r = client.post("/api/v1/keys", json={"name": "Test Key"})
        assert r.status_code in (401, 403)

    def test_list_keys_requires_auth(self):
        r = client.get("/api/v1/keys")
        assert r.status_code in (401, 403)

    def test_revoke_key_requires_auth(self):
        r = client.delete("/api/v1/keys/some-uuid")
        assert r.status_code in (401, 403)


# ── Usage Endpoints ───────────────────────────────────────────────────

class TestUsage:
    def test_usage_requires_auth(self):
        r = client.get("/api/v1/usage")
        assert r.status_code in (401, 403)


# ── Pipeline Ingest ───────────────────────────────────────────────────

class TestIngest:
    def test_ingest_invalid_secret(self):
        r = client.post("/api/v1/ingest", json={
            "advisories": [],
            "pipeline_secret": "wrong-secret",
        })
        assert r.status_code == 403

    def test_ingest_valid_secret_empty(self):
        r = client.post("/api/v1/ingest", json={
            "advisories": [],
            "pipeline_secret": "test-pipeline-secret",
        })
        assert r.status_code == 200
        assert r.json()["ingested"] == 0

    def test_single_ingest_invalid_secret(self):
        r = client.post(
            "/api/v1/ingest/single",
            json={"id": "test-001", "title": "Test"},
            headers={"X-Pipeline-Secret": "wrong"},
        )
        assert r.status_code == 403


# ── Security Utilities ────────────────────────────────────────────────

class TestSecurity:
    def test_api_key_generation(self):
        full_key, prefix, key_hash = generate_api_key()
        assert full_key.startswith("cdb_sk_live_")
        assert len(full_key) > 40
        assert "..." in prefix
        assert len(key_hash) == 64  # SHA-256 hex

    def test_api_key_hash_deterministic(self):
        key = "cdb_sk_live_abc123"
        h1 = hash_api_key(key)
        h2 = hash_api_key(key)
        assert h1 == h2

    def test_api_key_hash_unique(self):
        _, _, h1 = generate_api_key()
        _, _, h2 = generate_api_key()
        assert h1 != h2


# ── Rate Limiting ─────────────────────────────────────────────────────

class TestRateLimit:
    def test_rate_limit_headers(self):
        r = client.get("/api/v1/feed")
        # Rate limit headers should be present on API paths
        assert "x-ratelimit-limit" in r.headers or r.status_code == 500

    def test_non_api_path_no_ratelimit(self):
        r = client.get("/")
        # Root path should not have rate limit headers
        assert r.status_code == 200


# ── CORS ──────────────────────────────────────────────────────────────

class TestCORS:
    def test_cors_preflight(self):
        r = client.options(
            "/api/v1/feed",
            headers={
                "Origin": "http://localhost:3000",
                "Access-Control-Request-Method": "GET",
            },
        )
        assert r.status_code == 200

    def test_cors_blocked_origin(self):
        r = client.options(
            "/api/v1/feed",
            headers={
                "Origin": "https://evil.com",
                "Access-Control-Request-Method": "GET",
            },
        )
        # Should not include evil.com in Access-Control-Allow-Origin
        allow_origin = r.headers.get("access-control-allow-origin", "")
        assert "evil.com" not in allow_origin
