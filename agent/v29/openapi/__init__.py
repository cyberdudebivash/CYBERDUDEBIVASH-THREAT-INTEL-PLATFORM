"""
CYBERDUDEBIVASH® SENTINEL APEX v29.0 — OpenAPI Documentation
==============================================================
Auto-generated API documentation with Swagger UI and ReDoc.

Features:
- OpenAPI 3.1 Specification
- Auto-generated from FastAPI routes
- Swagger UI at /docs
- ReDoc at /redoc
- Downloadable spec at /openapi.json
- Versioned API endpoints (/v1/, /v2/)
- Security scheme documentation

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
from typing import Dict, Any, List, Optional
from dataclasses import dataclass, field
from datetime import datetime
import json
import logging

logger = logging.getLogger(__name__)


# ══════════════════════════════════════════════════════════════════════════════
# OPENAPI SPECIFICATION
# ══════════════════════════════════════════════════════════════════════════════

OPENAPI_SPEC = {
    "openapi": "3.1.0",
    "info": {
        "title": "CYBERDUDEBIVASH® SENTINEL APEX API",
        "description": """
## AI-Powered Threat Intelligence Platform

SENTINEL APEX provides enterprise-grade threat intelligence capabilities:

### Features
- **Real-time Threat Feeds**: Aggregate and analyze threats from multiple sources
- **IOC Extraction**: Automatic extraction of IPs, domains, hashes, URLs
- **STIX 2.1 Export**: Industry-standard threat intelligence format
- **Risk Scoring**: AI-powered threat risk assessment
- **MITRE ATT&CK Mapping**: Technique and tactic correlation
- **SIEM Integration**: Splunk, Sentinel, QRadar connectors

### Authentication
All API endpoints require authentication via:
- **JWT Token**: Bearer token in Authorization header
- **API Key**: X-API-Key header

### Rate Limits
- Free tier: 100 requests/hour
- Pro tier: 1000 requests/hour
- Enterprise: Unlimited

### Support
- Documentation: https://docs.cyberdudebivash.com
- Email: api-support@cyberdudebivash.com
""",
        "version": "29.0.0",
        "termsOfService": "https://cyberdudebivash.com/terms",
        "contact": {
            "name": "SENTINEL APEX API Support",
            "url": "https://cyberdudebivash.com/support",
            "email": "api@cyberdudebivash.com",
        },
        "license": {
            "name": "Commercial License",
            "url": "https://cyberdudebivash.com/license",
        },
    },
    "servers": [
        {
            "url": "https://intel.cyberdudebivash.com/api/v1",
            "description": "Production API",
        },
        {
            "url": "https://staging.cyberdudebivash.com/api/v1",
            "description": "Staging API",
        },
        {
            "url": "http://localhost:8000/api/v1",
            "description": "Local Development",
        },
    ],
    "tags": [
        {"name": "Threats", "description": "Threat intelligence operations"},
        {"name": "IOCs", "description": "Indicator of Compromise operations"},
        {"name": "STIX", "description": "STIX 2.1 bundle operations"},
        {"name": "Enrichment", "description": "Threat enrichment services"},
        {"name": "Reports", "description": "Intelligence reports"},
        {"name": "TAXII", "description": "TAXII 2.1 server endpoints"},
        {"name": "Admin", "description": "Administrative operations"},
        {"name": "Health", "description": "System health and metrics"},
    ],
    "paths": {},
    "components": {
        "securitySchemes": {
            "BearerAuth": {
                "type": "http",
                "scheme": "bearer",
                "bearerFormat": "JWT",
                "description": "JWT token obtained from /auth/login",
            },
            "ApiKeyAuth": {
                "type": "apiKey",
                "in": "header",
                "name": "X-API-Key",
                "description": "API key from dashboard",
            },
        },
        "schemas": {},
        "responses": {
            "UnauthorizedError": {
                "description": "Authentication required",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {"type": "string", "example": "Unauthorized"},
                                "message": {"type": "string"},
                            },
                        },
                    },
                },
            },
            "ForbiddenError": {
                "description": "Insufficient permissions",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {"type": "string", "example": "Forbidden"},
                                "required_permission": {"type": "string"},
                            },
                        },
                    },
                },
            },
            "NotFoundError": {
                "description": "Resource not found",
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "error": {"type": "string", "example": "Not Found"},
                                "resource": {"type": "string"},
                            },
                        },
                    },
                },
            },
        },
    },
    "security": [
        {"BearerAuth": []},
        {"ApiKeyAuth": []},
    ],
}


# ══════════════════════════════════════════════════════════════════════════════
# SCHEMA DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

SCHEMAS = {
    "Threat": {
        "type": "object",
        "properties": {
            "id": {"type": "string", "format": "uuid"},
            "title": {"type": "string"},
            "description": {"type": "string"},
            "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
            "risk_score": {"type": "number", "minimum": 0, "maximum": 10},
            "source": {"type": "string"},
            "published_at": {"type": "string", "format": "date-time"},
            "iocs": {"type": "array", "items": {"$ref": "#/components/schemas/IOC"}},
            "mitre_techniques": {"type": "array", "items": {"type": "string"}},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["id", "title", "severity"],
    },
    "IOC": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "enum": ["ip", "domain", "hash", "url", "email"]},
            "value": {"type": "string"},
            "confidence": {"type": "number", "minimum": 0, "maximum": 100},
            "first_seen": {"type": "string", "format": "date-time"},
            "last_seen": {"type": "string", "format": "date-time"},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "required": ["type", "value"],
    },
    "STIXBundle": {
        "type": "object",
        "properties": {
            "type": {"type": "string", "const": "bundle"},
            "id": {"type": "string", "pattern": "^bundle--"},
            "objects": {"type": "array", "items": {"type": "object"}},
        },
        "required": ["type", "id", "objects"],
    },
    "EnrichmentResult": {
        "type": "object",
        "properties": {
            "ioc": {"type": "string"},
            "sources": {
                "type": "object",
                "additionalProperties": {"type": "object"},
            },
            "risk_score": {"type": "number"},
            "malicious": {"type": "boolean"},
            "enriched_at": {"type": "string", "format": "date-time"},
        },
    },
    "Report": {
        "type": "object",
        "properties": {
            "id": {"type": "string"},
            "title": {"type": "string"},
            "type": {"type": "string", "enum": ["executive", "technical", "tactical"]},
            "content": {"type": "string"},
            "threats": {"type": "array", "items": {"$ref": "#/components/schemas/Threat"}},
            "generated_at": {"type": "string", "format": "date-time"},
        },
    },
    "HealthStatus": {
        "type": "object",
        "properties": {
            "status": {"type": "string", "enum": ["healthy", "degraded", "unhealthy"]},
            "version": {"type": "string"},
            "uptime": {"type": "number"},
            "components": {
                "type": "object",
                "additionalProperties": {
                    "type": "object",
                    "properties": {
                        "status": {"type": "string"},
                        "latency_ms": {"type": "number"},
                    },
                },
            },
        },
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# PATH DEFINITIONS
# ══════════════════════════════════════════════════════════════════════════════

PATHS = {
    "/threats": {
        "get": {
            "tags": ["Threats"],
            "summary": "List threats",
            "description": "Get paginated list of threat intelligence items",
            "operationId": "listThreats",
            "parameters": [
                {"name": "page", "in": "query", "schema": {"type": "integer", "default": 1}},
                {"name": "limit", "in": "query", "schema": {"type": "integer", "default": 50, "maximum": 100}},
                {"name": "severity", "in": "query", "schema": {"type": "string", "enum": ["low", "medium", "high", "critical"]}},
                {"name": "source", "in": "query", "schema": {"type": "string"}},
                {"name": "since", "in": "query", "schema": {"type": "string", "format": "date-time"}},
            ],
            "responses": {
                "200": {
                    "description": "List of threats",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "data": {"type": "array", "items": {"$ref": "#/components/schemas/Threat"}},
                                    "total": {"type": "integer"},
                                    "page": {"type": "integer"},
                                    "pages": {"type": "integer"},
                                },
                            },
                        },
                    },
                },
                "401": {"$ref": "#/components/responses/UnauthorizedError"},
            },
        },
    },
    "/threats/{threat_id}": {
        "get": {
            "tags": ["Threats"],
            "summary": "Get threat by ID",
            "operationId": "getThreat",
            "parameters": [
                {"name": "threat_id", "in": "path", "required": True, "schema": {"type": "string"}},
            ],
            "responses": {
                "200": {
                    "description": "Threat details",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Threat"}}},
                },
                "404": {"$ref": "#/components/responses/NotFoundError"},
            },
        },
    },
    "/iocs/extract": {
        "post": {
            "tags": ["IOCs"],
            "summary": "Extract IOCs from text",
            "operationId": "extractIOCs",
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "text": {"type": "string"},
                                "types": {"type": "array", "items": {"type": "string"}},
                            },
                            "required": ["text"],
                        },
                    },
                },
            },
            "responses": {
                "200": {
                    "description": "Extracted IOCs",
                    "content": {
                        "application/json": {
                            "schema": {
                                "type": "object",
                                "properties": {
                                    "iocs": {"type": "array", "items": {"$ref": "#/components/schemas/IOC"}},
                                    "count": {"type": "integer"},
                                },
                            },
                        },
                    },
                },
            },
        },
    },
    "/stix/export": {
        "get": {
            "tags": ["STIX"],
            "summary": "Export threats as STIX 2.1 bundle",
            "operationId": "exportSTIX",
            "parameters": [
                {"name": "since", "in": "query", "schema": {"type": "string", "format": "date-time"}},
                {"name": "severity", "in": "query", "schema": {"type": "string"}},
            ],
            "responses": {
                "200": {
                    "description": "STIX 2.1 Bundle",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/STIXBundle"}}},
                },
            },
        },
    },
    "/enrich/{ioc}": {
        "get": {
            "tags": ["Enrichment"],
            "summary": "Enrich IOC with threat intelligence",
            "operationId": "enrichIOC",
            "parameters": [
                {"name": "ioc", "in": "path", "required": True, "schema": {"type": "string"}},
                {"name": "sources", "in": "query", "schema": {"type": "array", "items": {"type": "string"}}},
            ],
            "responses": {
                "200": {
                    "description": "Enrichment results",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/EnrichmentResult"}}},
                },
            },
        },
    },
    "/reports/generate": {
        "post": {
            "tags": ["Reports"],
            "summary": "Generate intelligence report",
            "operationId": "generateReport",
            "requestBody": {
                "required": True,
                "content": {
                    "application/json": {
                        "schema": {
                            "type": "object",
                            "properties": {
                                "type": {"type": "string", "enum": ["executive", "technical", "tactical"]},
                                "threats": {"type": "array", "items": {"type": "string"}},
                                "format": {"type": "string", "enum": ["pdf", "html", "markdown"]},
                            },
                        },
                    },
                },
            },
            "responses": {
                "200": {
                    "description": "Generated report",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/Report"}}},
                },
            },
        },
    },
    "/health": {
        "get": {
            "tags": ["Health"],
            "summary": "Health check",
            "operationId": "healthCheck",
            "security": [],
            "responses": {
                "200": {
                    "description": "System health status",
                    "content": {"application/json": {"schema": {"$ref": "#/components/schemas/HealthStatus"}}},
                },
            },
        },
    },
    "/metrics": {
        "get": {
            "tags": ["Health"],
            "summary": "Prometheus metrics",
            "operationId": "getMetrics",
            "security": [],
            "responses": {
                "200": {
                    "description": "Prometheus format metrics",
                    "content": {"text/plain": {"schema": {"type": "string"}}},
                },
            },
        },
    },
}


# ══════════════════════════════════════════════════════════════════════════════
# OPENAPI GENERATOR
# ══════════════════════════════════════════════════════════════════════════════

class OpenAPIGenerator:
    """Generate and serve OpenAPI specification"""
    
    def __init__(self):
        self._spec = OPENAPI_SPEC.copy()
        self._spec["components"]["schemas"] = SCHEMAS
        self._spec["paths"] = PATHS
    
    def get_spec(self) -> Dict[str, Any]:
        """Get complete OpenAPI spec"""
        return self._spec
    
    def get_spec_json(self) -> str:
        """Get spec as JSON string"""
        return json.dumps(self._spec, indent=2)
    
    def add_path(self, path: str, methods: Dict[str, Dict]):
        """Add custom path to spec"""
        self._spec["paths"][path] = methods
    
    def add_schema(self, name: str, schema: Dict):
        """Add custom schema to spec"""
        self._spec["components"]["schemas"][name] = schema
    
    def generate_from_fastapi(self, app):
        """Generate spec from FastAPI app"""
        try:
            from fastapi.openapi.utils import get_openapi
            
            spec = get_openapi(
                title=self._spec["info"]["title"],
                version=self._spec["info"]["version"],
                description=self._spec["info"]["description"],
                routes=app.routes,
            )
            
            # Merge with our custom spec
            spec["info"] = self._spec["info"]
            spec["servers"] = self._spec["servers"]
            spec["tags"] = self._spec["tags"]
            spec["components"]["securitySchemes"] = self._spec["components"]["securitySchemes"]
            spec["security"] = self._spec["security"]
            
            return spec
        except Exception as e:
            logger.error(f"Failed to generate from FastAPI: {e}")
            return self._spec


def create_openapi_routes():
    """Create FastAPI routes for OpenAPI docs"""
    try:
        from fastapi import APIRouter
        from fastapi.responses import JSONResponse, HTMLResponse
        
        router = APIRouter(tags=["Documentation"])
        generator = get_generator()
        
        @router.get("/openapi.json", include_in_schema=False)
        async def openapi_json():
            """Get OpenAPI spec as JSON"""
            return JSONResponse(content=generator.get_spec())
        
        @router.get("/docs", include_in_schema=False)
        async def swagger_ui():
            """Swagger UI"""
            return HTMLResponse(content=f"""
<!DOCTYPE html>
<html>
<head>
    <title>SENTINEL APEX API - Swagger UI</title>
    <link rel="stylesheet" href="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui.css">
</head>
<body>
    <div id="swagger-ui"></div>
    <script src="https://cdn.jsdelivr.net/npm/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
    <script>
        SwaggerUIBundle({{
            url: "/openapi.json",
            dom_id: '#swagger-ui',
            presets: [SwaggerUIBundle.presets.apis, SwaggerUIBundle.SwaggerUIStandalonePreset],
            layout: "StandaloneLayout"
        }});
    </script>
</body>
</html>
            """)
        
        @router.get("/redoc", include_in_schema=False)
        async def redoc():
            """ReDoc documentation"""
            return HTMLResponse(content=f"""
<!DOCTYPE html>
<html>
<head>
    <title>SENTINEL APEX API - ReDoc</title>
    <link href="https://fonts.googleapis.com/css?family=Montserrat:300,400,700|Roboto:300,400,700" rel="stylesheet">
    <style>body {{ margin: 0; padding: 0; }}</style>
</head>
<body>
    <redoc spec-url="/openapi.json"></redoc>
    <script src="https://cdn.jsdelivr.net/npm/redoc@latest/bundles/redoc.standalone.js"></script>
</body>
</html>
            """)
        
        return router
    
    except ImportError:
        logger.warning("FastAPI not installed - OpenAPI routes unavailable")
        return None


# ══════════════════════════════════════════════════════════════════════════════
# SINGLETON
# ══════════════════════════════════════════════════════════════════════════════

_generator_instance: Optional[OpenAPIGenerator] = None


def get_generator() -> OpenAPIGenerator:
    """Get OpenAPI generator singleton"""
    global _generator_instance
    if _generator_instance is None:
        _generator_instance = OpenAPIGenerator()
    return _generator_instance


__all__ = [
    "OPENAPI_SPEC",
    "SCHEMAS",
    "PATHS",
    "OpenAPIGenerator",
    "create_openapi_routes",
    "get_generator",
]
