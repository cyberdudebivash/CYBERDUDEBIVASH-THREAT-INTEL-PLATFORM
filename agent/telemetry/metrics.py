#!/usr/bin/env python3
"""
agent/telemetry/metrics.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
PROMETHEUS METRICS ENGINE

Wires up the prometheus-client library (already in requirements.txt) to produce
a proper /metrics scrape endpoint and automatic request instrumentation.

Metrics exposed:
  ┌─ API Performance ──────────────────────────────────────────────────────┐
  │ cdb_api_requests_total          Counter   method, endpoint, tier, status
  │ cdb_api_request_duration_secs   Histogram endpoint, tier (p50/p95/p99)
  │ cdb_api_rate_limit_hits_total   Counter   tier, endpoint
  │ cdb_api_active_connections      Gauge     (current in-flight requests)
  ├─ Intelligence Pipeline ────────────────────────────────────────────────┤
  │ cdb_intel_feed_entries_total    Gauge     (current feed size)
  │ cdb_intel_kev_entries_total     Gauge     (KEV count)
  │ cdb_intel_threats_by_severity   Counter   severity (HIGH/MEDIUM/LOW)
  │ cdb_intel_pipeline_run_secs     Histogram (pipeline execution duration)
  │ cdb_intel_feed_sources_active   Gauge     (active RSS feed count)
  ├─ Business / Revenue ───────────────────────────────────────────────────┤
  │ cdb_active_api_keys_total       Gauge     tier
  │ cdb_stripe_events_total         Counter   event_type, outcome
  │ cdb_onboarding_completions      Counter   tier
  ├─ Platform Health ──────────────────────────────────────────────────────┤
  │ cdb_platform_info               Info      version, env
  │ cdb_health_check_status         Gauge     component (0=ok, 1=degraded, 2=error)
  └────────────────────────────────────────────────────────────────────────┘

Feature-flag gated: CDB_METRICS_ENABLED=true (default true — safe, read-only).
The /metrics endpoint should be protected by network policy (not public-facing).
"""

import os
import time
import logging

from fastapi import APIRouter, Request, Response
from prometheus_client import (
    generate_latest,
    CONTENT_TYPE_LATEST,
    Counter,
    Histogram,
    Gauge,
    Info,
    REGISTRY,
)

logger = logging.getLogger("CDB-METRICS")

# ── Metric Definitions ──────────────────────────────────────────────────────
# All metrics prefixed "cdb_" to avoid collision in shared Prometheus instances

_API_REQUESTS = Counter(
    "cdb_api_requests_total",
    "Total API requests processed",
    ["method", "endpoint", "tier", "status_code"],
)

_API_LATENCY = Histogram(
    "cdb_api_request_duration_seconds",
    "API request duration in seconds",
    ["endpoint", "tier"],
    buckets=[0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0],
)

_RATE_LIMIT_HITS = Counter(
    "cdb_api_rate_limit_hits_total",
    "Rate limit enforcement events",
    ["tier", "endpoint"],
)

_ACTIVE_CONNECTIONS = Gauge(
    "cdb_api_active_connections",
    "Currently in-flight API requests",
)

_FEED_ENTRIES = Gauge(
    "cdb_intel_feed_entries_total",
    "Current number of threat intel entries in feed",
)

_KEV_ENTRIES = Gauge(
    "cdb_intel_kev_entries_total",
    "CISA Known Exploited Vulnerabilities currently tracked",
)

_THREATS_BY_SEVERITY = Counter(
    "cdb_intel_threats_by_severity_total",
    "Threat intelligence entries by severity",
    ["severity"],
)

_PIPELINE_DURATION = Histogram(
    "cdb_intel_pipeline_run_seconds",
    "Intelligence pipeline execution duration",
    ["pipeline", "outcome"],
    buckets=[30, 60, 120, 300, 600, 900, 1800],
)

_ACTIVE_FEEDS = Gauge(
    "cdb_intel_feed_sources_active",
    "Number of active RSS intelligence feed sources",
)

_ACTIVE_API_KEYS = Gauge(
    "cdb_active_api_keys_total",
    "Active API keys by tier",
    ["tier"],
)

_STRIPE_EVENTS = Counter(
    "cdb_stripe_events_total",
    "Stripe webhook events processed",
    ["event_type", "outcome"],
)

_ONBOARDING_COMPLETIONS = Counter(
    "cdb_onboarding_completions_total",
    "Customer onboarding completions",
    ["tier"],
)

_PLATFORM_INFO = Info(
    "cdb_platform",
    "Platform version and configuration",
)

_HEALTH_STATUS = Gauge(
    "cdb_health_check_status",
    "Component health status (0=ok, 1=degraded, 2=error)",
    ["component"],
)

# Initialise platform info (run once at module load)
_PLATFORM_INFO.info({
    "version":     os.environ.get("PLATFORM_VERSION", "152.0.0"),
    "env":         os.environ.get("CDB_ENV", "production"),
    "api_version": "v1",
    "platform":    "CYBERDUDEBIVASH-SENTINEL-APEX",
})

# Initialise active feed count from config
try:
    from agent.config import RSS_FEEDS
    _ACTIVE_FEEDS.set(len(RSS_FEEDS))
except Exception:
    pass


# ── FastAPI Router ──────────────────────────────────────────────────────────

metrics_router = APIRouter()

# Metrics endpoint access control
_METRICS_ALLOWED_IPS = set(
    ip.strip()
    for ip in os.environ.get("CDB_METRICS_ALLOWED_IPS", "").split(",")
    if ip.strip()
)


@metrics_router.get("/metrics", include_in_schema=False)
async def prometheus_metrics(request: Request):
    """
    Prometheus scrape endpoint.

    Access control:
      - If CDB_METRICS_ALLOWED_IPS is set: restrict to those IPs (internal network)
      - Default: accessible from any IP (protect via Cloudflare WAF rule or network policy)

    Prometheus scrape config:
      - job_name: cdb-sentinel-apex
        static_configs:
          - targets: ['api.cyberdudebivash.com:8080']
        scheme: https
        metrics_path: /metrics
        scrape_interval: 15s
    """
    client_ip = request.client.host if request.client else ""
    if _METRICS_ALLOWED_IPS and client_ip not in _METRICS_ALLOWED_IPS:
        return Response(content="Forbidden", status_code=403)

    data = generate_latest(REGISTRY)
    return Response(content=data, media_type=CONTENT_TYPE_LATEST)


# ── Middleware ──────────────────────────────────────────────────────────────

# URL path normalisation — prevents cardinality explosion from IDs in paths
_PATH_NORMALISE = {
    # Replace UUID-like segments with {id} placeholder
}

def _normalise_path(path: str) -> str:
    """Reduce high-cardinality URL paths to metric-safe labels."""
    import re
    # Replace UUIDs
    path = re.sub(r'[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}', '{id}', path)
    # Replace numeric IDs
    path = re.sub(r'/\d{4,}', '/{id}', path)
    # Replace STIX bundle IDs (bundle--xxx)
    path = re.sub(r'(bundle|indicator|malware|threat-actor)--[0-9a-f-]+', r'\1--{id}', path)
    return path


async def metrics_middleware(request: Request, call_next):
    """
    Automatic request instrumentation middleware.
    Records: request count, latency histogram, active connection gauge.
    Extracts tier from X-CDB-Tier header (set by auth middleware upstream).
    """
    _ACTIVE_CONNECTIONS.inc()
    endpoint = _normalise_path(request.url.path)
    tier     = request.headers.get("X-CDB-Tier", "unknown")
    t0       = time.monotonic()

    try:
        response = await call_next(request)
    except Exception as e:
        _ACTIVE_CONNECTIONS.dec()
        _API_REQUESTS.labels(
            method=request.method,
            endpoint=endpoint,
            tier=tier,
            status_code="500",
        ).inc()
        raise

    duration = time.monotonic() - t0
    _ACTIVE_CONNECTIONS.dec()

    _API_REQUESTS.labels(
        method=request.method,
        endpoint=endpoint,
        tier=tier,
        status_code=str(response.status_code),
    ).inc()

    _API_LATENCY.labels(endpoint=endpoint, tier=tier).observe(duration)

    # Attach latency to response for debugging
    response.headers["X-Response-Time-Ms"] = str(round(duration * 1000, 1))

    return response


# ── Metric Update Helpers (called from other modules) ───────────────────────

def record_rate_limit_hit(tier: str, endpoint: str) -> None:
    """Record a rate limit enforcement event."""
    _RATE_LIMIT_HITS.labels(tier=tier, endpoint=endpoint).inc()


def update_feed_metrics(entry_count: int, kev_count: int = 0,
                        severity_counts: dict = None) -> None:
    """Update intelligence feed metrics (called after pipeline runs)."""
    _FEED_ENTRIES.set(entry_count)
    _KEV_ENTRIES.set(kev_count)
    if severity_counts:
        for severity, count in severity_counts.items():
            _THREATS_BY_SEVERITY.labels(severity=severity.upper()).inc(count)


def record_pipeline_run(pipeline: str, duration_s: float, success: bool) -> None:
    """Record intelligence pipeline execution metrics."""
    _PIPELINE_DURATION.labels(
        pipeline=pipeline,
        outcome="success" if success else "failure",
    ).observe(duration_s)


def record_stripe_event(event_type: str, success: bool) -> None:
    """Record Stripe webhook event processing."""
    _STRIPE_EVENTS.labels(
        event_type=event_type,
        outcome="success" if success else "failure",
    ).inc()


def record_onboarding_completion(tier: str) -> None:
    """Record customer onboarding completion."""
    _ONBOARDING_COMPLETIONS.labels(tier=tier).inc()


def update_health_metrics(component: str, status: str) -> None:
    """Update component health gauge (0=ok, 1=degraded, 2=error)."""
    status_val = {"ok": 0, "healthy": 0, "degraded": 1, "warning": 1, "error": 2, "unhealthy": 2}
    _HEALTH_STATUS.labels(component=component).set(status_val.get(status.lower(), 2))
