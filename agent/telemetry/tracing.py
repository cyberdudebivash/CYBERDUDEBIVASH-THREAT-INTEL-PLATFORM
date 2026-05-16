#!/usr/bin/env python3
"""
agent/telemetry/tracing.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
OPENTELEMETRY DISTRIBUTED TRACING

Instruments the FastAPI application with OpenTelemetry for distributed tracing.
Exports traces to any OTLP-compatible backend:
  - Grafana Tempo (recommended for Grafana stack)
  - Jaeger (open source)
  - Datadog APM
  - AWS X-Ray (via ADOT collector)
  - Honeycomb

Feature-flag gated: CDB_TRACING_ENABLED=true (default false)
Set OTEL_EXPORTER_OTLP_ENDPOINT to enable trace export.

Additional packages needed when enabling:
  opentelemetry-sdk==1.23.0
  opentelemetry-instrumentation-fastapi==0.44b0
  opentelemetry-instrumentation-requests==0.44b0
  opentelemetry-exporter-otlp-proto-grpc==1.23.0
  (Add to requirements.txt when enabling tracing)
"""

import os
import logging

logger = logging.getLogger("CDB-TRACING")

_TRACING_ENABLED    = os.environ.get("CDB_TRACING_ENABLED", "false").lower() == "true"
_OTLP_ENDPOINT      = os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT", "")
_SERVICE_NAME       = os.environ.get("OTEL_SERVICE_NAME", "cdb-sentinel-apex")
_SERVICE_VERSION    = os.environ.get("PLATFORM_VERSION", "152.0.0")
_DEPLOYMENT_ENV     = os.environ.get("CDB_ENV", "production")


def init_tracing(app) -> bool:
    """
    Initialize OpenTelemetry tracing on the FastAPI app.

    Args:
        app: FastAPI application instance

    Returns:
        True if tracing initialized successfully, False if disabled or unavailable.

    Rollback: set CDB_TRACING_ENABLED=false → tracing silently disabled.
    """
    if not _TRACING_ENABLED:
        logger.debug("[TRACING] Tracing disabled (CDB_TRACING_ENABLED=false)")
        return False

    try:
        from opentelemetry import trace
        from opentelemetry.sdk.trace import TracerProvider
        from opentelemetry.sdk.trace.export import BatchSpanProcessor, ConsoleSpanExporter
        from opentelemetry.sdk.resources import Resource
        from opentelemetry.instrumentation.fastapi import FastAPIInstrumentor
        from opentelemetry.instrumentation.requests import RequestsInstrumentor

    except ImportError as e:
        logger.warning(
            f"[TRACING] OpenTelemetry packages not installed ({e}). "
            "Add opentelemetry-sdk, opentelemetry-instrumentation-fastapi, "
            "opentelemetry-instrumentation-requests to requirements.txt."
        )
        return False

    # Build resource (service metadata)
    resource = Resource.create({
        "service.name":        _SERVICE_NAME,
        "service.version":     _SERVICE_VERSION,
        "deployment.environment": _DEPLOYMENT_ENV,
        "platform":            "cyberdudebivash-sentinel-apex",
    })

    provider = TracerProvider(resource=resource)

    # Configure exporter
    if _OTLP_ENDPOINT:
        try:
            from opentelemetry.exporter.otlp.proto.grpc.trace_exporter import OTLPSpanExporter
            exporter = OTLPSpanExporter(
                endpoint=_OTLP_ENDPOINT,
                insecure=not _OTLP_ENDPOINT.startswith("https"),
            )
            provider.add_span_processor(BatchSpanProcessor(exporter))
            logger.info(f"[TRACING] OTLP export active → {_OTLP_ENDPOINT}")
        except ImportError:
            logger.warning("[TRACING] OTLP gRPC exporter not installed — using console")
            provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
    else:
        # Development: console output
        provider.add_span_processor(BatchSpanProcessor(ConsoleSpanExporter()))
        logger.info("[TRACING] Console span exporter active (set OTEL_EXPORTER_OTLP_ENDPOINT for production)")

    trace.set_tracer_provider(provider)

    # Instrument FastAPI — auto-traces all incoming requests
    FastAPIInstrumentor.instrument_app(
        app,
        tracer_provider=provider,
        excluded_urls="/metrics,/api/v1/health,/api/v1/ready",  # Exclude health/metrics from traces
    )

    # Instrument outgoing HTTP requests (RSS feed fetches, Stripe calls, etc.)
    RequestsInstrumentor().instrument()

    logger.info(f"[TRACING] OpenTelemetry tracing initialized: service={_SERVICE_NAME} env={_DEPLOYMENT_ENV}")
    return True


def get_tracer(name: str = "cdb.sentinel.apex"):
    """Get a named tracer for manual span creation."""
    try:
        from opentelemetry import trace
        return trace.get_tracer(name, _SERVICE_VERSION)
    except ImportError:
        return _NoopTracer()


class _NoopTracer:
    """No-op tracer when OpenTelemetry is not available."""
    def start_as_current_span(self, name, **kwargs):
        from contextlib import contextmanager
        @contextmanager
        def _noop():
            yield None
        return _noop()

    def start_span(self, name, **kwargs):
        return _NoopSpan()


class _NoopSpan:
    def set_attribute(self, *a, **kw): pass
    def set_status(self, *a, **kw): pass
    def end(self, *a, **kw): pass
    def __enter__(self): return self
    def __exit__(self, *a): pass
