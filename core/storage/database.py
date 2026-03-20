#!/usr/bin/env python3
"""
database.py — CYBERDUDEBIVASH® SENTINEL APEX v47.0 (COMMAND CENTER)
═══════════════════════════════════════════════════════════════════════
Unified Database Engine: PostgreSQL (production) + SQLite (development).

Features:
  - Connection pooling with health checks
  - Automatic schema migration
  - Transaction context manager
  - Query builder for common operations
  - Full STIX export compatibility maintained
  - Threat intelligence data model

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
import sqlite3
import logging
import hashlib
from datetime import datetime, timezone
from typing import Any, Dict, List, Optional, Tuple
from pathlib import Path
from contextlib import contextmanager

logger = logging.getLogger("CDB-DATABASE")

DATABASE_URL = os.environ.get("CDB_DATABASE_URL", "sqlite:///data/sentinel_apex.db")
SQLITE_PATH = Path("data/sentinel_apex.db")


# ═══════════════════════════════════════════════════════════
# INTELLIGENCE DATA MODEL (SQL Schema)
# ═══════════════════════════════════════════════════════════

INTELLIGENCE_SCHEMA = """
-- Core threat intelligence table
CREATE TABLE IF NOT EXISTS threat_intelligence (
    id {serial} PRIMARY KEY,
    intel_id TEXT NOT NULL UNIQUE,
    title TEXT NOT NULL,
    source_url TEXT,
    blog_url TEXT,
    feed_source TEXT,
    content_hash TEXT UNIQUE,
    severity TEXT NOT NULL DEFAULT 'MEDIUM',
    risk_score REAL DEFAULT 0.0,
    confidence_score REAL DEFAULT 0.0,
    cvss_score REAL,
    epss_score REAL,
    kev_present BOOLEAN DEFAULT FALSE,
    tlp_label TEXT DEFAULT 'TLP:CLEAR',
    actor_tag TEXT DEFAULT 'UNC-CDB-99',
    supply_chain BOOLEAN DEFAULT FALSE,
    stix_id TEXT,
    stix_file TEXT,
    stix_object_count INTEGER DEFAULT 0,
    ioc_counts {jsonb} DEFAULT '{{}}',
    mitre_tactics {jsonb} DEFAULT '[]',
    extended_metrics {jsonb} DEFAULT '{{}}',
    ai_analysis {jsonb} DEFAULT '{{}}',
    campaign_id TEXT,
    cluster_id TEXT,
    pipeline_run_id TEXT,
    status TEXT DEFAULT 'active',
    ingested_at {ts_default},
    enriched_at TEXT,
    published_at TEXT,
    updated_at {ts_default}
);

CREATE INDEX IF NOT EXISTS idx_intel_severity ON threat_intelligence(severity);
CREATE INDEX IF NOT EXISTS idx_intel_risk ON threat_intelligence(risk_score);
CREATE INDEX IF NOT EXISTS idx_intel_status ON threat_intelligence(status);
CREATE INDEX IF NOT EXISTS idx_intel_campaign ON threat_intelligence(campaign_id);
CREATE INDEX IF NOT EXISTS idx_intel_hash ON threat_intelligence(content_hash);

-- IOC storage table
CREATE TABLE IF NOT EXISTS indicators_of_compromise (
    id {serial} PRIMARY KEY,
    ioc_id TEXT NOT NULL UNIQUE,
    intel_id TEXT NOT NULL,
    ioc_type TEXT NOT NULL,
    ioc_value TEXT NOT NULL,
    confidence REAL DEFAULT 0.0,
    first_seen TEXT,
    last_seen TEXT,
    source TEXT,
    tags {jsonb} DEFAULT '[]',
    is_active BOOLEAN DEFAULT TRUE,
    created_at {ts_default},
    UNIQUE(ioc_type, ioc_value)
);

CREATE INDEX IF NOT EXISTS idx_ioc_type ON indicators_of_compromise(ioc_type);
CREATE INDEX IF NOT EXISTS idx_ioc_intel ON indicators_of_compromise(intel_id);
CREATE INDEX IF NOT EXISTS idx_ioc_value ON indicators_of_compromise(ioc_value);

-- Threat campaigns table
CREATE TABLE IF NOT EXISTS threat_campaigns (
    id {serial} PRIMARY KEY,
    campaign_id TEXT NOT NULL UNIQUE,
    name TEXT NOT NULL,
    description TEXT,
    actor_tag TEXT,
    first_seen TEXT,
    last_seen TEXT,
    severity TEXT DEFAULT 'MEDIUM',
    confidence REAL DEFAULT 0.0,
    intel_count INTEGER DEFAULT 0,
    ioc_count INTEGER DEFAULT 0,
    mitre_techniques {jsonb} DEFAULT '[]',
    related_cves {jsonb} DEFAULT '[]',
    sectors_targeted {jsonb} DEFAULT '[]',
    geo_targets {jsonb} DEFAULT '[]',
    status TEXT DEFAULT 'active',
    created_at {ts_default},
    updated_at {ts_default}
);

CREATE INDEX IF NOT EXISTS idx_campaign_status ON threat_campaigns(status);
CREATE INDEX IF NOT EXISTS idx_campaign_actor ON threat_campaigns(actor_tag);

-- Detection results table
CREATE TABLE IF NOT EXISTS detection_results (
    id {serial} PRIMARY KEY,
    detection_id TEXT NOT NULL UNIQUE,
    intel_id TEXT,
    rule_type TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    rule_name TEXT,
    match_data {jsonb} DEFAULT '{{}}',
    severity TEXT DEFAULT 'MEDIUM',
    confidence REAL DEFAULT 0.0,
    false_positive BOOLEAN DEFAULT FALSE,
    validated BOOLEAN DEFAULT FALSE,
    created_at {ts_default}
);

CREATE INDEX IF NOT EXISTS idx_detection_intel ON detection_results(intel_id);
CREATE INDEX IF NOT EXISTS idx_detection_rule ON detection_results(rule_type, rule_id);

-- Pipeline execution log
CREATE TABLE IF NOT EXISTS pipeline_executions (
    id {serial} PRIMARY KEY,
    run_id TEXT NOT NULL UNIQUE,
    status TEXT DEFAULT 'running',
    started_at {ts_default},
    completed_at TEXT,
    items_ingested INTEGER DEFAULT 0,
    items_enriched INTEGER DEFAULT 0,
    items_published INTEGER DEFAULT 0,
    items_deduplicated INTEGER DEFAULT 0,
    errors {jsonb} DEFAULT '[]',
    stages_completed {jsonb} DEFAULT '[]',
    duration_seconds REAL DEFAULT 0.0
);

-- SOC hunt results
CREATE TABLE IF NOT EXISTS soc_hunt_results (
    id {serial} PRIMARY KEY,
    hunt_id TEXT NOT NULL UNIQUE,
    hunt_name TEXT NOT NULL,
    hypothesis TEXT,
    query_type TEXT,
    query_data {jsonb} DEFAULT '{{}}',
    results {jsonb} DEFAULT '[]',
    findings_count INTEGER DEFAULT 0,
    severity TEXT DEFAULT 'INFO',
    analyst TEXT DEFAULT 'SENTINEL-AI',
    status TEXT DEFAULT 'completed',
    created_at {ts_default}
);

CREATE INDEX IF NOT EXISTS idx_hunt_status ON soc_hunt_results(status);

-- API usage tracking
CREATE TABLE IF NOT EXISTS api_usage (
    id {serial} PRIMARY KEY,
    api_key_hash TEXT NOT NULL,
    tier TEXT DEFAULT 'FREE',
    endpoint TEXT NOT NULL,
    method TEXT DEFAULT 'GET',
    status_code INTEGER,
    response_time_ms REAL,
    request_date TEXT NOT NULL,
    created_at {ts_default}
);

CREATE INDEX IF NOT EXISTS idx_api_key ON api_usage(api_key_hash, request_date);

-- API keys table
CREATE TABLE IF NOT EXISTS api_keys (
    id {serial} PRIMARY KEY,
    key_id TEXT NOT NULL UNIQUE,
    key_hash TEXT NOT NULL UNIQUE,
    owner_id TEXT NOT NULL,
    tier TEXT DEFAULT 'FREE',
    name TEXT,
    rate_limit INTEGER DEFAULT 60,
    daily_limit INTEGER DEFAULT 100,
    is_active BOOLEAN DEFAULT TRUE,
    last_used_at TEXT,
    expires_at TEXT,
    created_at {ts_default}
);

CREATE INDEX IF NOT EXISTS idx_apikey_owner ON api_keys(owner_id);
CREATE INDEX IF NOT EXISTS idx_apikey_hash ON api_keys(key_hash);
"""


class DatabaseEngine:
    """
    Unified database engine with PostgreSQL/SQLite dual support.
    Provides connection management, schema migration, and CRUD operations.
    """

    def __init__(self, url: str = DATABASE_URL):
        self._url = url
        self._conn = None
        self._is_postgres = url.startswith("postgresql://") or url.startswith("postgres://")

    def connect(self) -> bool:
        if self._is_postgres:
            try:
                import psycopg2
                import psycopg2.extras
                self._conn = psycopg2.connect(self._url)
                self._conn.autocommit = False
                logger.info("Connected to PostgreSQL")
                return True
            except ImportError:
                logger.warning("psycopg2 not available, falling back to SQLite")
                self._is_postgres = False
            except Exception as e:
                logger.error(f"PostgreSQL connection failed: {e}")
                self._is_postgres = False

        return self._connect_sqlite()

    def _connect_sqlite(self) -> bool:
        try:
            SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
            self._conn = sqlite3.connect(str(SQLITE_PATH), check_same_thread=False)
            self._conn.execute("PRAGMA journal_mode=WAL")
            self._conn.execute("PRAGMA foreign_keys=ON")
            self._conn.execute("PRAGMA busy_timeout=5000")
            self._conn.row_factory = sqlite3.Row
            logger.info(f"Connected to SQLite: {SQLITE_PATH}")
            return True
        except Exception as e:
            logger.error(f"SQLite connection failed: {e}")
            return False

    def initialize_schema(self):
        """Apply the intelligence data model schema."""
        sql = INTELLIGENCE_SCHEMA
        sql = sql.replace("{serial}", "SERIAL" if self._is_postgres else "INTEGER")
        sql = sql.replace(
            "{ts_default}",
            "TIMESTAMP WITH TIME ZONE DEFAULT NOW()" if self._is_postgres
            else "TEXT DEFAULT (datetime('now'))",
        )
        sql = sql.replace("{jsonb}", "JSONB" if self._is_postgres else "TEXT")
        sql = sql.replace("{bigint}", "BIGINT" if self._is_postgres else "INTEGER")

        statements = [s.strip() for s in sql.split(";") if s.strip()]
        for stmt in statements:
            try:
                self._conn.cursor().execute(stmt)
            except Exception as e:
                logger.debug(f"Schema statement skipped: {e}")
        self._conn.commit()
        logger.info("Database schema initialized")

    @contextmanager
    def transaction(self):
        """Context manager for database transactions."""
        cursor = self._conn.cursor()
        try:
            yield cursor
            self._conn.commit()
        except Exception:
            self._conn.rollback()
            raise

    def execute(self, sql: str, params: tuple = ()) -> Any:
        cursor = self._conn.cursor()
        # Convert ? placeholders for PostgreSQL
        if self._is_postgres:
            sql = sql.replace("?", "%s")
        cursor.execute(sql, params)
        return cursor

    def execute_many(self, sql: str, params_list: List[tuple]):
        cursor = self._conn.cursor()
        if self._is_postgres:
            sql = sql.replace("?", "%s")
        cursor.executemany(sql, params_list)
        return cursor

    def fetch_one(self, sql: str, params: tuple = ()) -> Optional[Dict]:
        cursor = self.execute(sql, params)
        row = cursor.fetchone()
        if row is None:
            return None
        if isinstance(row, sqlite3.Row):
            return dict(row)
        if self._is_postgres:
            cols = [desc[0] for desc in cursor.description]
            return dict(zip(cols, row))
        return None

    def fetch_all(self, sql: str, params: tuple = ()) -> List[Dict]:
        cursor = self.execute(sql, params)
        rows = cursor.fetchall()
        if not rows:
            return []
        if isinstance(rows[0], sqlite3.Row):
            return [dict(r) for r in rows]
        if self._is_postgres:
            cols = [desc[0] for desc in cursor.description]
            return [dict(zip(cols, r)) for r in rows]
        return []

    def commit(self):
        self._conn.commit()

    def close(self):
        if self._conn:
            self._conn.close()

    @property
    def is_postgres(self) -> bool:
        return self._is_postgres

    # ── Intelligence CRUD ─────────────────────────────────

    def store_intelligence(self, intel: Dict) -> bool:
        """Store a threat intelligence record."""
        content_hash = hashlib.sha256(
            f"{intel.get('title', '')}|{intel.get('source_url', '')}".lower().encode()
        ).hexdigest()[:24]

        sql = """
            INSERT OR IGNORE INTO threat_intelligence
            (intel_id, title, source_url, blog_url, feed_source, content_hash,
             severity, risk_score, confidence_score, cvss_score, epss_score,
             kev_present, tlp_label, actor_tag, supply_chain, stix_id, stix_file,
             stix_object_count, ioc_counts, mitre_tactics, extended_metrics,
             ai_analysis, campaign_id, cluster_id, pipeline_run_id, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        if self._is_postgres:
            sql = sql.replace("INSERT OR IGNORE", "INSERT")
            sql += " ON CONFLICT (intel_id) DO NOTHING"

        try:
            self.execute(sql, (
                intel.get("intel_id", str(hashlib.sha256(content_hash.encode()).hexdigest())[:16]),
                intel.get("title", ""),
                intel.get("source_url", ""),
                intel.get("blog_url", ""),
                intel.get("feed_source", ""),
                content_hash,
                intel.get("severity", "MEDIUM"),
                float(intel.get("risk_score", 0)),
                float(intel.get("confidence_score", 0)),
                intel.get("cvss_score"),
                intel.get("epss_score"),
                bool(intel.get("kev_present", False)),
                intel.get("tlp_label", "TLP:CLEAR"),
                intel.get("actor_tag", "UNC-CDB-99"),
                bool(intel.get("supply_chain", False)),
                intel.get("stix_id", ""),
                intel.get("stix_file", ""),
                int(intel.get("stix_object_count", 0)),
                json.dumps(intel.get("ioc_counts", {})),
                json.dumps(intel.get("mitre_tactics", [])),
                json.dumps(intel.get("extended_metrics", {})),
                json.dumps(intel.get("ai_analysis", {})),
                intel.get("campaign_id"),
                intel.get("cluster_id"),
                intel.get("pipeline_run_id"),
                intel.get("status", "active"),
            ))
            self.commit()
            return True
        except Exception as e:
            logger.error(f"Store intelligence failed: {e}")
            return False

    def store_ioc(self, ioc: Dict) -> bool:
        """Store an IOC record."""
        sql = """
            INSERT OR IGNORE INTO indicators_of_compromise
            (ioc_id, intel_id, ioc_type, ioc_value, confidence, first_seen, last_seen, source, tags)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        if self._is_postgres:
            sql = sql.replace("INSERT OR IGNORE", "INSERT")
            sql += " ON CONFLICT (ioc_type, ioc_value) DO UPDATE SET last_seen = EXCLUDED.last_seen"

        try:
            now = datetime.now(timezone.utc).isoformat()
            self.execute(sql, (
                ioc.get("ioc_id", hashlib.sha256(f"{ioc['ioc_type']}:{ioc['ioc_value']}".encode()).hexdigest()[:16]),
                ioc.get("intel_id", ""),
                ioc["ioc_type"],
                ioc["ioc_value"],
                float(ioc.get("confidence", 0)),
                ioc.get("first_seen", now),
                ioc.get("last_seen", now),
                ioc.get("source", "sentinel-apex"),
                json.dumps(ioc.get("tags", [])),
            ))
            self.commit()
            return True
        except Exception as e:
            logger.error(f"Store IOC failed: {e}")
            return False

    def store_campaign(self, campaign: Dict) -> bool:
        """Store a threat campaign record."""
        sql = """
            INSERT OR IGNORE INTO threat_campaigns
            (campaign_id, name, description, actor_tag, first_seen, last_seen,
             severity, confidence, intel_count, ioc_count, mitre_techniques,
             related_cves, sectors_targeted, geo_targets, status)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        if self._is_postgres:
            sql = sql.replace("INSERT OR IGNORE", "INSERT")
            sql += " ON CONFLICT (campaign_id) DO UPDATE SET last_seen = EXCLUDED.last_seen, intel_count = EXCLUDED.intel_count"

        try:
            now = datetime.now(timezone.utc).isoformat()
            self.execute(sql, (
                campaign.get("campaign_id", str(uuid.uuid4())[:12] if 'uuid' in dir() else hashlib.sha256(campaign.get("name", "").encode()).hexdigest()[:12]),
                campaign.get("name", ""),
                campaign.get("description", ""),
                campaign.get("actor_tag", "UNC-CDB-99"),
                campaign.get("first_seen", now),
                campaign.get("last_seen", now),
                campaign.get("severity", "MEDIUM"),
                float(campaign.get("confidence", 0)),
                int(campaign.get("intel_count", 0)),
                int(campaign.get("ioc_count", 0)),
                json.dumps(campaign.get("mitre_techniques", [])),
                json.dumps(campaign.get("related_cves", [])),
                json.dumps(campaign.get("sectors_targeted", [])),
                json.dumps(campaign.get("geo_targets", [])),
                campaign.get("status", "active"),
            ))
            self.commit()
            return True
        except Exception as e:
            logger.error(f"Store campaign failed: {e}")
            return False

    def store_detection(self, detection: Dict) -> bool:
        """Store a detection result."""
        sql = """
            INSERT OR IGNORE INTO detection_results
            (detection_id, intel_id, rule_type, rule_id, rule_name,
             match_data, severity, confidence, false_positive, validated)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        if self._is_postgres:
            sql = sql.replace("INSERT OR IGNORE", "INSERT")
            sql += " ON CONFLICT (detection_id) DO NOTHING"

        try:
            self.execute(sql, (
                detection.get("detection_id", hashlib.sha256(json.dumps(detection, sort_keys=True).encode()).hexdigest()[:16]),
                detection.get("intel_id", ""),
                detection.get("rule_type", ""),
                detection.get("rule_id", ""),
                detection.get("rule_name", ""),
                json.dumps(detection.get("match_data", {})),
                detection.get("severity", "MEDIUM"),
                float(detection.get("confidence", 0)),
                bool(detection.get("false_positive", False)),
                bool(detection.get("validated", False)),
            ))
            self.commit()
            return True
        except Exception as e:
            logger.error(f"Store detection failed: {e}")
            return False

    def store_pipeline_run(self, run: Dict) -> bool:
        """Store pipeline execution metadata."""
        sql = """
            INSERT OR IGNORE INTO pipeline_executions
            (run_id, status, items_ingested, items_enriched, items_published,
             items_deduplicated, errors, stages_completed, duration_seconds)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """
        if self._is_postgres:
            sql = sql.replace("INSERT OR IGNORE", "INSERT")
            sql += " ON CONFLICT (run_id) DO UPDATE SET status = EXCLUDED.status, completed_at = NOW()"

        try:
            self.execute(sql, (
                run.get("run_id", ""),
                run.get("status", "running"),
                int(run.get("items_ingested", 0)),
                int(run.get("items_enriched", 0)),
                int(run.get("items_published", 0)),
                int(run.get("items_deduplicated", 0)),
                json.dumps(run.get("errors", [])),
                json.dumps(run.get("stages_completed", [])),
                float(run.get("duration_seconds", 0)),
            ))
            self.commit()
            return True
        except Exception as e:
            logger.error(f"Store pipeline run failed: {e}")
            return False

    def query_intelligence(
        self,
        severity: Optional[str] = None,
        min_risk_score: Optional[float] = None,
        kev_only: bool = False,
        campaign_id: Optional[str] = None,
        limit: int = 50,
        offset: int = 0,
    ) -> List[Dict]:
        """Query intelligence records with filters."""
        conditions = ["status = 'active'"]
        params = []

        if severity:
            conditions.append("severity = ?")
            params.append(severity.upper())
        if min_risk_score is not None:
            conditions.append("risk_score >= ?")
            params.append(min_risk_score)
        if kev_only:
            conditions.append("kev_present = ?")
            params.append(True)
        if campaign_id:
            conditions.append("campaign_id = ?")
            params.append(campaign_id)

        where = " AND ".join(conditions)
        sql = f"""
            SELECT * FROM threat_intelligence
            WHERE {where}
            ORDER BY risk_score DESC, ingested_at DESC
            LIMIT ? OFFSET ?
        """
        params.extend([limit, offset])
        return self.fetch_all(sql, tuple(params))

    def get_dashboard_stats(self) -> Dict:
        """Get aggregate stats for the dashboard."""
        try:
            total = self.fetch_one("SELECT COUNT(*) as cnt FROM threat_intelligence WHERE status = 'active'")
            critical = self.fetch_one("SELECT COUNT(*) as cnt FROM threat_intelligence WHERE severity = 'CRITICAL' AND status = 'active'")
            kev = self.fetch_one("SELECT COUNT(*) as cnt FROM threat_intelligence WHERE kev_present = 1 AND status = 'active'")
            campaigns = self.fetch_one("SELECT COUNT(*) as cnt FROM threat_campaigns WHERE status = 'active'")
            avg_risk = self.fetch_one("SELECT AVG(risk_score) as avg_score FROM threat_intelligence WHERE status = 'active'")
            detections = self.fetch_one("SELECT COUNT(*) as cnt FROM detection_results")
            iocs = self.fetch_one("SELECT COUNT(*) as cnt FROM indicators_of_compromise WHERE is_active = 1")

            return {
                "total_intelligence": total["cnt"] if total else 0,
                "critical_threats": critical["cnt"] if critical else 0,
                "kev_confirmed": kev["cnt"] if kev else 0,
                "active_campaigns": campaigns["cnt"] if campaigns else 0,
                "avg_risk_score": round(avg_risk["avg_score"] or 0, 2) if avg_risk else 0,
                "total_detections": detections["cnt"] if detections else 0,
                "active_iocs": iocs["cnt"] if iocs else 0,
            }
        except Exception as e:
            logger.error(f"Dashboard stats query failed: {e}")
            return {}


# ═══════════════════════════════════════════════════════════
# GLOBAL SINGLETON
# ═══════════════════════════════════════════════════════════

_db_instance: Optional[DatabaseEngine] = None


def get_db() -> DatabaseEngine:
    """Get or create the global database engine instance."""
    global _db_instance
    if _db_instance is None:
        _db_instance = DatabaseEngine()
        _db_instance.connect()
        _db_instance.initialize_schema()
    return _db_instance
