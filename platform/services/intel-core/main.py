"""
SENTINEL APEX INTEL CORE v2.0
==============================
AI-native Cyber Threat Intelligence microservice:
- Real-time IOC enrichment (VirusTotal, Shodan, AbuseIPDB, OTX)
- AI actor attribution (LLM-powered, MITRE ATT&CK aligned)
- Autonomous threat scoring (10-dimension APEX score)
- STIX 2.1 bundle generation
- Sigma rule auto-generation
- YARA rule generation
- Kafka event streaming (intel events → downstream consumers)
- Vector DB integration (Qdrant) for semantic similarity search
- Graph intelligence (Neo4j threat graph)
- Dark web feed ingestion
- CISA KEV enrichment
- NVD/FIRST.org CVSS/EPSS enrichment
"""
from __future__ import annotations

import asyncio
import json
import uuid
from contextlib import asynccontextmanager
from datetime import datetime, timezone
from typing import Any, Optional

import structlog
from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import JSONResponse
from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
from prometheus_fastapi_instrumentator import Instrumentator

from .config import IntelConfig
from .enrichment.ioc_enricher import IOCEnricher
from .enrichment.ai_enricher import AIEnricher
from .enrichment.cvss_enricher import CVSSEnricher
from .enrichment.kev_enricher import KEVEnricher
from .storage.postgres import PostgresStore
from .storage.qdrant import QdrantStore
from .storage.neo4j import Neo4jGraph
from .streaming.kafka import KafkaProducer
from .intelligence.scorer import APEXScorer
from .intelligence.stix_builder import STIXBuilder
from .intelligence.sigma_generator import SigmaGenerator
from .intelligence.yara_generator import YARAGenerator
from .intelligence.actor_attribution import ActorAttribution
from .routes import build_routes
from .telemetry import setup_telemetry

log = structlog.get_logger("sentinel.intel_core")
config = IntelConfig()

@asynccontextmanager
async def lifespan(app: FastAPI):
    log.info("sentinel.intel_core.startup", version="2.0")
    setup_telemetry(config)
    await PostgresStore.initialize(config.database_url)
    await QdrantStore.initialize(config.qdrant_url, config.qdrant_api_key)
    await Neo4jGraph.initialize(config.neo4j_url, config.neo4j_auth)
    await KafkaProducer.initialize(config.kafka_brokers)
    await IOCEnricher.initialize(config)
    await AIEnricher.initialize(config)
    log.info("sentinel.intel_core.ready")
    yield
    log.info("sentinel.intel_core.shutdown")
    await PostgresStore.close()
    await QdrantStore.close()
    await Neo4jGraph.close()
    await KafkaProducer.close()

app = FastAPI(
    title="SENTINEL APEX Intel Core",
    description="AI-Native CTI Intelligence Processing Engine",
    version="2.0.0",
    lifespan=lifespan,
)

Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)
FastAPIInstrumentor.instrument_app(app)

routes = build_routes(config)
app.include_router(routes)

@app.get("/health", include_in_schema=False)
async def health():
    return {"status": "ok", "service": "intel-core", "version": "2.0.0"}
