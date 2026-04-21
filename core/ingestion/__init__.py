"""
core/ingestion — CYBERDUDEBIVASH® SENTINEL APEX v134.0
Threat Intelligence Ingestion Pipeline

Sources: NVD CVE API v2 | CISA KEV | MalwareBazaar | AbuseIPDB
Queue:   Redis Streams (with in-memory fallback)
Pipeline: Fetch → Queue → Dedup → Normalize → Store
"""
from .ingestion_engine import (
    IngestionEngine,
    IngestionQueue,
    IngestionMetrics,
    SourceSchedule,
    get_engine,
    ingestion_router,
)
from .deduplicator import Deduplicator, DedupStats
from .normalizer import Normalizer, IntelItem
from .sources.base import BaseSource, RawIntelItem, FetchResult, FetchStatus, SourceType
from .sources.nvd_source import NVDSource
from .sources.kev_source import KEVSource
from .sources.malwarebazaar_source import MalwareBazaarSource
from .sources.abuseipdb_source import AbuseIPDBSource

__all__ = [
    # Engine
    "IngestionEngine",
    "IngestionQueue",
    "IngestionMetrics",
    "SourceSchedule",
    "get_engine",
    "ingestion_router",
    # Processing
    "Deduplicator",
    "DedupStats",
    "Normalizer",
    "IntelItem",
    # Sources
    "BaseSource",
    "RawIntelItem",
    "FetchResult",
    "FetchStatus",
    "SourceType",
    "NVDSource",
    "KEVSource",
    "MalwareBazaarSource",
    "AbuseIPDBSource",
]
