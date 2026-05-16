#!/usr/bin/env python3
"""
agent/telemetry/structured_logging.py - CYBERDUDEBIVASH® SENTINEL APEX v47.0
LOKI-COMPATIBLE STRUCTURED JSON LOGGING ENGINE

Replaces Python's default log format with structured JSON output optimised for:
  - Grafana Loki (labels + log line ingestion via Promtail / Grafana Alloy)
  - Elasticsearch / OpenSearch (index-ready JSON)
  - Datadog Logs (dd.trace_id / dd.span_id correlation)
  - Splunk HEC (structured key-value pairs)
  - AWS CloudWatch Logs Insights

JSON schema per log line:
  {
    "ts":          "2025-01-01T00:00:00.000Z",   // ISO 8601 UTC
    "level":       "INFO",                        // DEBUG/INFO/WARNING/ERROR/CRITICAL
    "logger":      "CDB-API",                     // Logger name (maps to Loki label)
    "message":     "...",
    "service":     "cdb-sentinel-apex",
    "env":         "production",
    "version":     "152.0.0",
    "request_id":  "...",                         // Per-request correlation ID
    "trace_id":    "...",                         // OTel trace ID (if tracing active)
    "span_id":     "...",                         // OTel span ID
    "exc_info":    "...",                         // Exception traceback (errors only)
    ...                                           // Any extra fields passed by caller
  }

Loki label strategy:
  - {service="cdb-sentinel-apex", env="production", level="ERROR", logger="CDB-AUTH"}
  - Low-cardinality labels only (no request_id in labels — only in log body)

Usage:
  from agent.telemetry.structured_logging import configure_logging
  configure_logging()  # Call once at app startup (before uvicorn)

  import logging
  logger = logging.getLogger("CDB-MY-MODULE")
  logger.info("User logged in", extra={"user_id": "...", "org_id": "..."})

Feature-flag gated: CDB_STRUCTURED_LOGGING=true (default true — safe)
"""

import os
import sys
import json
import time
import logging
import traceback
import threading
from typing import Any, Dict, Optional
from datetime import datetime, timezone

# ── Configuration ─────────────────────────────────────────────────────────────

_STRUCTURED_LOGGING = os.environ.get("CDB_STRUCTURED_LOGGING", "true").lower() == "true"
_LOG_LEVEL          = os.environ.get("CDB_LOG_LEVEL", "INFO").upper()
_SERVICE_NAME       = os.environ.get("OTEL_SERVICE_NAME", "cdb-sentinel-apex")
_SERVICE_VERSION    = os.environ.get("PLATFORM_VERSION", "152.0.0")
_DEPLOYMENT_ENV     = os.environ.get("CDB_ENV", "production")

# Thread-local storage for per-request context (set by middleware)
_request_context = threading.local()


def set_request_context(request_id: str = "", trace_id: str = "", span_id: str = "", user_id: str = "") -> None:
    """
    Inject per-request context into thread-local storage.
    Called by FastAPI middleware on each incoming request.
    Context is automatically included in all log lines for the request lifetime.
    """
    _request_context.request_id = request_id
    _request_context.trace_id   = trace_id
    _request_context.span_id    = span_id
    _request_context.user_id    = user_id


def clear_request_context() -> None:
    """Clear per-request context (called at response completion)."""
    _request_context.request_id = ""
    _request_context.trace_id   = ""
    _request_context.span_id    = ""
    _request_context.user_id    = ""


def _get_otel_context() -> Dict[str, str]:
    """Extract OpenTelemetry trace/span IDs if tracing is active."""
    try:
        from opentelemetry import trace
        span = trace.get_current_span()
        ctx  = span.get_span_context()
        if ctx and ctx.is_valid:
            return {
                "trace_id": format(ctx.trace_id, "032x"),
                "span_id":  format(ctx.span_id, "016x"),
            }
    except Exception:
        pass
    return {}


# ── JSON Formatter ─────────────────────────────────────────────────────────────

class LokiJSONFormatter(logging.Formatter):
    """
    Formats log records as single-line JSON for Loki/Elasticsearch ingestion.
    Loki labels: service, env, level, logger (low cardinality).
    Log body: all fields including high-cardinality request_id, user_id, etc.
    """

    # Fields to exclude from 'extra' pass-through (standard LogRecord attrs)
    _STANDARD_ATTRS = frozenset({
        "name", "msg", "args", "levelname", "levelno", "pathname", "filename",
        "module", "exc_info", "exc_text", "stack_info", "lineno", "funcName",
        "created", "msecs", "relativeCreated", "thread", "threadName",
        "processName", "process", "message", "taskName",
    })

    def format(self, record: logging.LogRecord) -> str:
        # Render message (handles % formatting, str() of non-strings)
        record.message = record.getMessage()

        ts = datetime.fromtimestamp(record.created, tz=timezone.utc).strftime(
            "%Y-%m-%dT%H:%M:%S.") + f"{int(record.msecs):03d}Z"

        payload: Dict[str, Any] = {
            "ts":      ts,
            "level":   record.levelname,
            "logger":  record.name,
            "message": record.message,
            # Loki label fields (keep low-cardinality)
            "service": _SERVICE_NAME,
            "env":     _DEPLOYMENT_ENV,
            "version": _SERVICE_VERSION,
        }

        # Per-request context from thread-local
        req_id = getattr(_request_context, "request_id", "")
        if req_id:
            payload["request_id"] = req_id
        uid = getattr(_request_context, "user_id", "")
        if uid:
            payload["user_id"] = uid

        # OpenTelemetry trace correlation
        otel = _get_otel_context()
        if otel:
            payload.update(otel)
        else:
            # Fallback: thread-local trace IDs (set by metrics_middleware)
            tid = getattr(_request_context, "trace_id", "")
            sid = getattr(_request_context, "span_id", "")
            if tid:
                payload["trace_id"] = tid
            if sid:
                payload["span_id"] = sid

        # Exception info
        if record.exc_info:
            payload["exc_info"] = self.formatException(record.exc_info)
        if record.stack_info:
            payload["stack_info"] = self.formatStack(record.stack_info)

        # Source location (only for WARNING+)
        if record.levelno >= logging.WARNING:
            payload["src"] = f"{record.filename}:{record.lineno}:{record.funcName}"

        # Extra fields passed via logger.info("msg", extra={"key": "val"})
        for key, value in record.__dict__.items():
            if key not in self._STANDARD_ATTRS and not key.startswith("_"):
                payload[key] = value

        try:
            return json.dumps(payload, default=str, ensure_ascii=False)
        except Exception as e:
            # Fallback: plain text if JSON serialisation fails
            return json.dumps({
                "ts": ts, "level": "ERROR", "logger": "CDB-LOGGING",
                "message": f"Log serialisation failed: {e} — original: {record.message[:200]}",
            })


# ── Plain Formatter (development / non-structured mode) ───────────────────────

_PLAIN_FORMAT = (
    "%(asctime)s [%(levelname)-8s] %(name)-20s | %(message)s"
)


# ── Access Log Filter (suppress noisy health check logs) ──────────────────────

class _HealthCheckFilter(logging.Filter):
    """Suppress access log spam from Prometheus/health check endpoints."""
    _SUPPRESSED = {"/api/v1/health", "/api/v1/ready", "/metrics", "/favicon.ico"}

    def filter(self, record: logging.LogRecord) -> bool:
        msg = record.getMessage()
        return not any(path in msg for path in self._SUPPRESSED)


# ── Sampling Filter (reduce DEBUG volume in production) ───────────────────────

class _SamplingFilter(logging.Filter):
    """
    Probabilistic sampling for DEBUG logs in production.
    Prevents excessive log volume while preserving observability.
    """
    def __init__(self, sample_rate: float = 0.1):
        super().__init__()
        self._rate    = sample_rate
        self._counter = 0
        self._lock    = threading.Lock()

    def filter(self, record: logging.LogRecord) -> bool:
        if record.levelno > logging.DEBUG:
            return True
        with self._lock:
            self._counter += 1
            return (self._counter % max(1, int(1 / self._rate))) == 0


# ── Configure Logging ─────────────────────────────────────────────────────────

def configure_logging(
    level: Optional[str] = None,
    structured: Optional[bool] = None,
    stream=None,
) -> None:
    """
    Configure the root Python logger and all CDB loggers.

    Args:
        level:      Log level override (default: CDB_LOG_LEVEL env, fallback INFO)
        structured: Force structured/plain mode (default: CDB_STRUCTURED_LOGGING env)
        stream:     Output stream (default: sys.stdout — Railway/Docker reads stdout)

    Call once at application startup, before uvicorn is configured.
    Idempotent: safe to call multiple times (reconfigures on each call).
    """
    use_structured = structured if structured is not None else _STRUCTURED_LOGGING
    log_level_str  = level or _LOG_LEVEL
    log_level      = getattr(logging, log_level_str, logging.INFO)
    output_stream  = stream or sys.stdout

    # Choose formatter
    if use_structured:
        formatter = LokiJSONFormatter()
    else:
        formatter = logging.Formatter(_PLAIN_FORMAT, datefmt="%Y-%m-%dT%H:%M:%S")

    # Primary handler: stdout (Docker / Railway captures stdout → log aggregator)
    stdout_handler = logging.StreamHandler(output_stream)
    stdout_handler.setFormatter(formatter)
    stdout_handler.addFilter(_HealthCheckFilter())

    # Apply DEBUG sampling in production to control volume
    if _DEPLOYMENT_ENV == "production" and log_level == logging.DEBUG:
        stdout_handler.addFilter(_SamplingFilter(sample_rate=0.05))

    # Root logger
    root_logger = logging.getLogger()
    root_logger.setLevel(log_level)
    root_logger.handlers.clear()
    root_logger.addHandler(stdout_handler)

    # Silence noisy third-party loggers
    for noisy in ("uvicorn.access", "httpx", "httpcore", "urllib3", "boto3", "botocore"):
        logging.getLogger(noisy).setLevel(logging.WARNING)

    # Uvicorn access logs → our formatter (so access logs are also JSON)
    uvicorn_error = logging.getLogger("uvicorn.error")
    uvicorn_error.handlers.clear()
    uvicorn_error.propagate = True  # Use root handler

    logging.getLogger("CDB-LOGGING").info(
        "Structured logging initialised",
        extra={
            "structured": use_structured,
            "log_level":  log_level_str,
            "service":    _SERVICE_NAME,
            "env":        _DEPLOYMENT_ENV,
        }
    )


# ── Request Context Middleware ─────────────────────────────────────────────────

async def logging_context_middleware(request, call_next):
    """
    FastAPI middleware: injects X-Request-ID into thread-local for log correlation.
    Chain after metrics_middleware (which sets X-CDB-Tier).
    """
    request_id = request.headers.get("X-Request-ID", "")
    if not request_id:
        import uuid
        request_id = str(uuid.uuid4())[:8]

    set_request_context(
        request_id=request_id,
        user_id=request.headers.get("X-CDB-User-ID", ""),
    )

    try:
        response = await call_next(request)
    finally:
        clear_request_context()

    return response


# ── Convenience: get module logger ────────────────────────────────────────────

def get_logger(name: str) -> logging.Logger:
    """Get a CDB-namespaced logger. Prefer over logging.getLogger() directly."""
    return logging.getLogger(name if name.startswith("CDB-") else f"CDB-{name}")
