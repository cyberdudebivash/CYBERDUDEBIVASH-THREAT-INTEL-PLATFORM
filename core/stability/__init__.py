"""
core/stability — CYBERDUDEBIVASH® SENTINEL APEX
Pipeline Stability System: retry, observability, health checks, DLQ
"""
# Import classes and utilities — pipeline_guardian OBJECT is imported as
# `guardian` to avoid shadowing the `pipeline_guardian` SUBMODULE name.
# This ensures `from core.stability.pipeline_guardian import health_router`
# in main.py resolves to the MODULE, not the PipelineGuardian singleton.
from .pipeline_guardian import (
    PipelineGuardian,
    pipeline_guardian as guardian,   # singleton — alias avoids submodule shadow
    retry_with_backoff,
    StructuredLogger,
    HealthChecker,
    DeadLetterQueue,
    PipelineMetrics,
)

# Also expose under the original name so existing call-sites work:
# `from core.stability import pipeline_guardian` still returns the singleton.
pipeline_guardian = guardian

__all__ = [
    "PipelineGuardian",
    "pipeline_guardian",
    "guardian",
    "retry_with_backoff",
    "StructuredLogger",
    "HealthChecker",
    "DeadLetterQueue",
    "PipelineMetrics",
]
