"""
SENTINEL APEX Core Module v47.0 — COMMAND CENTER
═══════════════════════════════════════════════════
Centralized AI-driven cybersecurity intelligence platform.

Architecture:
  - orchestrator: Central pipeline controller (single source of truth)
  - event_bus: Redis-backed event-driven architecture
  - manifest_manager: Hardened manifest with atomic writes
  - pipeline: 7-stage intelligence pipeline (INGEST→PUBLISH)
  - ai_engine: IOC clustering, CVE correlation, campaign detection
  - detection: Sigma, YARA, IOC matching engines
  - storage: PostgreSQL + Redis abstraction layer
"""
from .version import VERSION, CODENAME, VERSION_INFO, get_version

__all__ = [
    "VERSION", "CODENAME", "VERSION_INFO", "get_version",
]
