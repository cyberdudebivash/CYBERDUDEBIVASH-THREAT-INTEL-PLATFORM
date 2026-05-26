
-- SENTINEL APEX Telemetry Lake — ClickHouse DDL
-- Production schema for distributed telemetry storage

CREATE TABLE IF NOT EXISTS apex_telemetry.events (
    event_id            UUID,
    tenant_id           LowCardinality(String),
    sensor_id           LowCardinality(String),
    source              LowCardinality(String),
    category            LowCardinality(String),
    severity            LowCardinality(String),
    timestamp_epoch     DateTime64(3, 'UTC'),
    hostname            String,
    src_ip              Nullable(IPv4),
    dst_ip              Nullable(IPv4),
    src_port            Nullable(UInt16),
    dst_port            Nullable(UInt16),
    process_name        LowCardinality(String),
    process_pid         Nullable(UInt32),
    process_hash_sha256 Nullable(FixedString(64)),
    user                Nullable(String),
    domain              Nullable(String),
    dns_query           Nullable(String),
    command_line        Nullable(String),
    file_path           Nullable(String),
    file_hash_sha256    Nullable(FixedString(64)),
    mitre_techniques    Array(String),
    ioc_matches         Array(String),
    sigma_rule_ids      Array(String),
    confidence_score    Float32,
    provenance_hash     FixedString(64),
    dedupe_key          FixedString(16),
    replay_id           Nullable(String),
    enrichment_tags     Array(String),
    raw_payload         String   -- JSON
)
ENGINE = MergeTree()
PARTITION BY toYYYYMMDD(timestamp_epoch)
ORDER BY (tenant_id, timestamp_epoch, event_id)
TTL timestamp_epoch + INTERVAL 90 DAY
SETTINGS index_granularity = 8192;

-- TimescaleDB schema (PostgreSQL)
CREATE TABLE apex_telemetry_ts (
    event_id            UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    tenant_id           TEXT NOT NULL,
    source              TEXT NOT NULL,
    category            TEXT NOT NULL,
    severity            TEXT NOT NULL,
    timestamp_utc       TIMESTAMPTZ NOT NULL,
    hostname            TEXT,
    src_ip              INET,
    dst_ip              INET,
    confidence_score    DOUBLE PRECISION,
    mitre_techniques    TEXT[],
    ioc_matches         TEXT[],
    provenance_hash     TEXT,
    replay_id           TEXT
);
SELECT create_hypertable('apex_telemetry_ts', 'timestamp_utc', chunk_time_interval => INTERVAL '1 day');
CREATE INDEX ON apex_telemetry_ts (tenant_id, timestamp_utc DESC);
CREATE INDEX ON apex_telemetry_ts USING GIN (mitre_techniques);
CREATE INDEX ON apex_telemetry_ts USING GIN (ioc_matches);
