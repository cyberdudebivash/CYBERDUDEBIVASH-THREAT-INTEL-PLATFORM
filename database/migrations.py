#!/usr/bin/env python3
"""
migrations.py — CYBERDUDEBIVASH® SENTINEL APEX v55.0
DATABASE SCHEMA MIGRATIONS

Provides schema creation and migration for:
  - Quota tracking (SQLite / PostgreSQL)
  - B2B webhook subscriptions
  - Sales conversion pipeline
  - Executive risk reports

Supports both SQLite (development) and PostgreSQL (production).

Usage:
    python -m database.migrations migrate        # Apply all migrations
    python -m database.migrations status          # Check migration state
    python -m database.migrations rollback        # Rollback last migration

(c) 2026 CyberDudeBivash Pvt. Ltd. All Rights Reserved.
"""

import os
import json
import sqlite3
import logging
import hashlib
from datetime import datetime, timezone
from typing import Optional, Dict, List, Any
from pathlib import Path

logger = logging.getLogger("CDB-MIGRATIONS")

# ═══════════════════════════════════════════════════════════
# CONFIGURATION
# ═══════════════════════════════════════════════════════════

DATABASE_URL = os.environ.get("CDB_DATABASE_URL", "sqlite:///data/sentinel_apex.db")
SQLITE_PATH = Path("data/sentinel_apex.db")

# ═══════════════════════════════════════════════════════════
# DATABASE ADAPTER
# ═══════════════════════════════════════════════════════════

class DatabaseAdapter:
    """Unified database adapter supporting SQLite and PostgreSQL."""

    def __init__(self, url: str = DATABASE_URL):
        self._url = url
        self._conn = None
        self._is_postgres = url.startswith("postgresql://") or url.startswith("postgres://")

    def connect(self):
        if self._is_postgres:
            try:
                import psycopg2
                self._conn = psycopg2.connect(self._url)
                self._conn.autocommit = False
                logger.info("Connected to PostgreSQL")
            except ImportError:
                logger.warning("psycopg2 not available, falling back to SQLite")
                self._is_postgres = False
                self._connect_sqlite()
            except Exception as e:
                logger.error(f"PostgreSQL connection failed: {e}, falling back to SQLite")
                self._is_postgres = False
                self._connect_sqlite()
        else:
            self._connect_sqlite()

    def _connect_sqlite(self):
        SQLITE_PATH.parent.mkdir(parents=True, exist_ok=True)
        self._conn = sqlite3.connect(str(SQLITE_PATH))
        self._conn.execute("PRAGMA journal_mode=WAL")
        self._conn.execute("PRAGMA foreign_keys=ON")
        logger.info(f"Connected to SQLite: {SQLITE_PATH}")

    def execute(self, sql: str, params: tuple = ()):
        cursor = self._conn.cursor()
        cursor.execute(sql, params)
        return cursor

    def executemany(self, sql: str, params_list: List[tuple]):
        cursor = self._conn.cursor()
        cursor.executemany(sql, params_list)
        return cursor

    def commit(self):
        self._conn.commit()

    def rollback(self):
        self._conn.rollback()

    def close(self):
        if self._conn:
            self._conn.close()

    @property
    def is_postgres(self) -> bool:
        return self._is_postgres

    def serial_type(self) -> str:
        return "SERIAL" if self._is_postgres else "INTEGER"

    def timestamp_default(self) -> str:
        if self._is_postgres:
            return "TIMESTAMP WITH TIME ZONE DEFAULT NOW()"
        return "TEXT DEFAULT (datetime('now'))"

    def jsonb_type(self) -> str:
        return "JSONB" if self._is_postgres else "TEXT"

    def bigint_type(self) -> str:
        return "BIGINT" if self._is_postgres else "INTEGER"


# ═══════════════════════════════════════════════════════════
# MIGRATION DEFINITIONS
# ═══════════════════════════════════════════════════════════

MIGRATIONS: List[Dict] = [
    {
        "version": "v55_001",
        "description": "Create migration tracking table",
        "up": """
            CREATE TABLE IF NOT EXISTS cdb_migrations (
                id {serial} PRIMARY KEY,
                version TEXT NOT NULL UNIQUE,
                description TEXT,
                applied_at {ts_default},
                checksum TEXT
            )
        """,
        "down": "DROP TABLE IF EXISTS cdb_migrations",
    },
    {
        "version": "v55_002",
        "description": "Quota tracking — usage counters and overage log",
        "up": """
            CREATE TABLE IF NOT EXISTS quota_usage (
                id {serial} PRIMARY KEY,
                org_id TEXT NOT NULL,
                metric TEXT NOT NULL,
                period TEXT NOT NULL,
                used_count {bigint} DEFAULT 0,
                limit_count {bigint} DEFAULT 0,
                tier TEXT DEFAULT 'FREE',
                last_updated {ts_default},
                UNIQUE(org_id, metric, period)
            );

            CREATE INDEX IF NOT EXISTS idx_quota_org_period ON quota_usage(org_id, period);

            CREATE TABLE IF NOT EXISTS quota_overage_log (
                id {serial} PRIMARY KEY,
                org_id TEXT NOT NULL,
                metric TEXT NOT NULL,
                overage_units INTEGER NOT NULL,
                tier TEXT NOT NULL,
                endpoint TEXT,
                billed_amount_usd REAL DEFAULT 0.0,
                created_at {ts_default}
            );

            CREATE INDEX IF NOT EXISTS idx_overage_org ON quota_overage_log(org_id);
        """,
        "down": """
            DROP TABLE IF EXISTS quota_overage_log;
            DROP TABLE IF EXISTS quota_usage;
        """,
    },
    {
        "version": "v55_003",
        "description": "B2B webhook subscriptions and delivery tracking",
        "up": """
            CREATE TABLE IF NOT EXISTS b2b_subscriptions (
                id {serial} PRIMARY KEY,
                subscription_id TEXT NOT NULL UNIQUE,
                org_id TEXT NOT NULL,
                webhook_url TEXT NOT NULL,
                tier TEXT DEFAULT 'STANDARD',
                status TEXT DEFAULT 'ACTIVE',
                hmac_secret TEXT NOT NULL,
                mtls_cert_fingerprint TEXT DEFAULT '',
                event_filters {jsonb} DEFAULT '[]',
                rate_limit_per_minute INTEGER DEFAULT 60,
                consecutive_failures INTEGER DEFAULT 0,
                total_deliveries {bigint} DEFAULT 0,
                total_failures {bigint} DEFAULT 0,
                last_delivery_at TEXT,
                metadata {jsonb} DEFAULT '{}',
                created_at {ts_default},
                updated_at {ts_default}
            );

            CREATE INDEX IF NOT EXISTS idx_b2b_org ON b2b_subscriptions(org_id);
            CREATE INDEX IF NOT EXISTS idx_b2b_status ON b2b_subscriptions(status);

            CREATE TABLE IF NOT EXISTS b2b_delivery_log (
                id {serial} PRIMARY KEY,
                subscription_id TEXT NOT NULL,
                pulse_id TEXT NOT NULL,
                status TEXT NOT NULL,
                status_code INTEGER,
                attempt_count INTEGER DEFAULT 1,
                error_message TEXT,
                delivered_at {ts_default}
            );

            CREATE INDEX IF NOT EXISTS idx_delivery_sub ON b2b_delivery_log(subscription_id);
            CREATE INDEX IF NOT EXISTS idx_delivery_pulse ON b2b_delivery_log(pulse_id);
        """,
        "down": """
            DROP TABLE IF EXISTS b2b_delivery_log;
            DROP TABLE IF EXISTS b2b_subscriptions;
        """,
    },
    {
        "version": "v55_004",
        "description": "Executive risk reports and regulatory exposure tracking",
        "up": """
            CREATE TABLE IF NOT EXISTS executive_risk_reports (
                id {serial} PRIMARY KEY,
                report_id TEXT NOT NULL UNIQUE,
                org_id TEXT NOT NULL,
                region TEXT DEFAULT 'GLOBAL',
                sector TEXT DEFAULT 'DEFAULT',
                total_risk_exposure_usd REAL DEFAULT 0.0,
                annualized_loss_exposure_usd REAL DEFAULT 0.0,
                max_regulatory_fine_usd REAL DEFAULT 0.0,
                rosi_percentage REAL DEFAULT 0.0,
                risk_rating TEXT DEFAULT 'INFORMATIONAL',
                finding_count INTEGER DEFAULT 0,
                report_json {jsonb},
                created_at {ts_default}
            );

            CREATE INDEX IF NOT EXISTS idx_risk_org ON executive_risk_reports(org_id);
            CREATE INDEX IF NOT EXISTS idx_risk_rating ON executive_risk_reports(risk_rating);

            CREATE TABLE IF NOT EXISTS regulatory_exposure (
                id {serial} PRIMARY KEY,
                report_id TEXT NOT NULL,
                regulation TEXT NOT NULL,
                projected_fine_usd REAL DEFAULT 0.0,
                max_statutory_fine TEXT,
                region TEXT,
                created_at {ts_default},
                FOREIGN KEY (report_id) REFERENCES executive_risk_reports(report_id)
            );
        """,
        "down": """
            DROP TABLE IF EXISTS regulatory_exposure;
            DROP TABLE IF EXISTS executive_risk_reports;
        """,
    },
    {
        "version": "v55_005",
        "description": "Sales conversion pipeline — leads, advisories, and metrics",
        "up": """
            CREATE TABLE IF NOT EXISTS sales_leads (
                id {serial} PRIMARY KEY,
                lead_id TEXT NOT NULL UNIQUE,
                org_id TEXT NOT NULL,
                org_name TEXT,
                contact_email TEXT,
                contact_name TEXT,
                current_tier TEXT DEFAULT 'FREE',
                target_tier TEXT DEFAULT 'PRO',
                ale_usd REAL DEFAULT 0.0,
                rosi_pct REAL DEFAULT 0.0,
                region TEXT,
                sector TEXT,
                status TEXT DEFAULT 'NEW',
                source TEXT DEFAULT 'AUTO_CONVERSION',
                pipeline_id TEXT,
                advisory_path TEXT,
                follow_up_date TEXT,
                converted_at TEXT,
                created_at {ts_default}
            );

            CREATE INDEX IF NOT EXISTS idx_lead_org ON sales_leads(org_id);
            CREATE INDEX IF NOT EXISTS idx_lead_status ON sales_leads(status);

            CREATE TABLE IF NOT EXISTS conversion_metrics (
                id {serial} PRIMARY KEY,
                metric_date TEXT NOT NULL,
                total_processed INTEGER DEFAULT 0,
                critical_findings INTEGER DEFAULT 0,
                advisories_generated INTEGER DEFAULT 0,
                advisories_dispatched INTEGER DEFAULT 0,
                leads_created INTEGER DEFAULT 0,
                conversions INTEGER DEFAULT 0,
                total_ale_usd REAL DEFAULT 0.0,
                created_at {ts_default},
                UNIQUE(metric_date)
            );
        """,
        "down": """
            DROP TABLE IF EXISTS conversion_metrics;
            DROP TABLE IF EXISTS sales_leads;
        """,
    },
]


# ═══════════════════════════════════════════════════════════
# MIGRATION RUNNER
# ═══════════════════════════════════════════════════════════

class MigrationRunner:
    """Executes database migrations with rollback support."""

    def __init__(self):
        self._db = DatabaseAdapter()

    def migrate(self) -> Dict[str, Any]:
        """Apply all pending migrations."""
        self._db.connect()
        results = {"applied": [], "skipped": [], "errors": []}

        try:
            for migration in MIGRATIONS:
                version = migration["version"]

                # Check if already applied (skip first migration for bootstrapping)
                if version != "v55_001":
                    try:
                        cursor = self._db.execute(
                            "SELECT version FROM cdb_migrations WHERE version = ?", (version,)
                        )
                        if cursor.fetchone():
                            results["skipped"].append(version)
                            continue
                    except Exception:
                        pass  # Table might not exist yet

                # Apply migration
                sql = self._interpolate_sql(migration["up"])
                try:
                    for statement in self._split_statements(sql):
                        if statement.strip():
                            self._db.execute(statement)

                    # Record migration
                    if version != "v55_001":
                        checksum = hashlib.sha256(sql.encode()).hexdigest()[:16]
                        self._db.execute(
                            "INSERT OR IGNORE INTO cdb_migrations (version, description, checksum) "
                            "VALUES (?, ?, ?)",
                            (version, migration["description"], checksum),
                        )

                    self._db.commit()
                    results["applied"].append(version)
                    logger.info(f"Migration applied: {version} — {migration['description']}")

                except Exception as e:
                    self._db.rollback()
                    results["errors"].append({"version": version, "error": str(e)})
                    logger.error(f"Migration failed: {version} — {e}")

        finally:
            self._db.close()

        return results

    def rollback(self, target_version: Optional[str] = None) -> Dict:
        """Rollback the last migration or to a specific version."""
        self._db.connect()
        results = {"rolled_back": [], "errors": []}

        try:
            cursor = self._db.execute(
                "SELECT version FROM cdb_migrations ORDER BY id DESC LIMIT 1"
            )
            row = cursor.fetchone()
            if not row:
                return {"error": "No migrations to rollback"}

            last_version = row[0]

            # Find migration definition
            migration = next((m for m in MIGRATIONS if m["version"] == last_version), None)
            if not migration:
                return {"error": f"Migration definition not found: {last_version}"}

            sql = self._interpolate_sql(migration["down"])
            for statement in self._split_statements(sql):
                if statement.strip():
                    self._db.execute(statement)

            self._db.execute("DELETE FROM cdb_migrations WHERE version = ?", (last_version,))
            self._db.commit()
            results["rolled_back"].append(last_version)
            logger.info(f"Migration rolled back: {last_version}")

        except Exception as e:
            self._db.rollback()
            results["errors"].append(str(e))
        finally:
            self._db.close()

        return results

    def status(self) -> Dict:
        """Check migration status."""
        self._db.connect()
        try:
            cursor = self._db.execute("SELECT version, description, applied_at FROM cdb_migrations ORDER BY id")
            applied = [
                {"version": row[0], "description": row[1], "applied_at": row[2]}
                for row in cursor.fetchall()
            ]
            pending = [
                m["version"] for m in MIGRATIONS
                if m["version"] not in {a["version"] for a in applied}
            ]
            return {"applied": applied, "pending": pending}
        except Exception:
            return {"applied": [], "pending": [m["version"] for m in MIGRATIONS]}
        finally:
            self._db.close()

    def _interpolate_sql(self, sql: str) -> str:
        """Replace type placeholders with database-specific types."""
        result = sql
        result = result.replace("{serial}", self._db.serial_type())
        result = result.replace("{ts_default}", self._db.timestamp_default())
        result = result.replace("{jsonb}", self._db.jsonb_type())
        result = result.replace("{bigint}", self._db.bigint_type())
        return result

    @staticmethod
    def _split_statements(sql: str) -> List[str]:
        """Split SQL into individual statements."""
        return [s.strip() for s in sql.split(";") if s.strip()]


# ═══════════════════════════════════════════════════════════
# CLI
# ═══════════════════════════════════════════════════════════

def main():
    import argparse
    logging.basicConfig(level=logging.INFO, format="%(asctime)s [MIGRATIONS] %(message)s")

    parser = argparse.ArgumentParser(description="CDB SENTINEL APEX — Database Migrations v55")
    parser.add_argument("command", choices=["migrate", "rollback", "status"],
                        help="Migration command")
    args = parser.parse_args()

    runner = MigrationRunner()

    if args.command == "migrate":
        result = runner.migrate()
        print(json.dumps(result, indent=2))
    elif args.command == "rollback":
        result = runner.rollback()
        print(json.dumps(result, indent=2))
    elif args.command == "status":
        result = runner.status()
        print(json.dumps(result, indent=2, default=str))


if __name__ == "__main__":
    main()
