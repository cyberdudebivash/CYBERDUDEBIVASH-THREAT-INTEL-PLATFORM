"""
core/stability — CYBERDUDEBIVASH® SENTINEL APEX
Pipeline Stability System: retry, observability, health checks, DLQ

SHADOWING NOTE:
  Do NOT import the `pipeline_guardian` singleton object under the name
  `pipeline_guardian` here. Python sets core.stability.pipeline_guardian
  to the submodule object AFTER __init__.py runs, but if __init__.py
  assigns the name `pipeline_guardian` to anything, that assignment
  OVERWRITES the submodule reference — causing:
      "No module named 'core.stability.pipeline_guardian'"
  when main.py tries `from core.stability.pipeline_guardian import health_router`.

  Safe approach: import the singleton under a different name (_guardian),
  and expose health_router directly so main.py can import it from the package.
"""
try:
    from .pipeline_guardian import (
        PipelineGuardian,
        retry_with_backoff,
        StructuredLogger,
        HealthChecker,
        DeadLetterQueue,
        PipelineMetrics,
        health_router,
    )
    # Singleton exposed under a distinct name — never as 'pipeline_guardian'
    from .pipeline_guardian import pipeline_guardian as _guardian
    _STABILITY_OK = True
except Exception as _e:
    import logging as _logging
    _logging.getLogger("CDB-STABILITY").warning(
        f"core.stability partial load: {_e}"
    )
    _STABILITY_OK = False
    PipelineGuardian = None   # type: ignore[assignment,misc]
    retry_with_backoff = None # type: ignore[assignment,misc]
    StructuredLogger = None   # type: ignore[assignment,misc]
    HealthChecker = None      # type: ignore[assignment,misc]
    DeadLetterQueue = None    # type: ignore[assignment,misc]
    PipelineMetrics = None    # type: ignore[assignment,misc]
    health_router = None      # type: ignore[assignment,misc]
    _guardian = None

__all__ = [
    "PipelineGuardian",
    "retry_with_backoff",
    "StructuredLogger",
    "HealthChecker",
    "DeadLetterQueue",
    "PipelineMetrics",
    "health_router",
    "_guardian",
    "_STABILITY_OK",
]
