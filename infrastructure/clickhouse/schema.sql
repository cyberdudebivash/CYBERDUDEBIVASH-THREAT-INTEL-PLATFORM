-- =============================================================================
-- CYBERDUDEBIVASH® SENTINEL APEX — ClickHouse Telemetry Lake DDL
-- infrastructure/clickhouse/schema.sql
-- Version: 162.0.0
-- Purpose: Production-grade hyperscale telemetry lake for SOC operations,
--          API analytics, threat intel processing, and MSSP billing metering.
--
-- Deployment: ClickHouse 24.x+ cluster
-- Partitioning: Monthly (toYYYYMM)
-- Replication: ReplicatedMergeTree with 3-replica minimum for HA
-- Retention: 90 days hot / 1 year cold (TTL tiering)
-- =============================================================================

-- Create database
CREATE DATABASE IF NOT EXISTS sentinel_apex ON CLUSTER sentinel_cluster;

USE sentinel_apex;

-- =============================================================================
-- 1. THREAT INTELLIGENCE EVENTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS threat_intel_events ON CLUSTER sentinel_cluster
(
    -- Primary dimensions
    event_id        UUID         DEFAULT generateUUIDv4(),
    ts              DateTime64(3, 'UTC'),
    advisory_id     String,
    stix_id         String,

    -- Severity & scoring
    severity        LowCardinality(String),  -- CRITICAL/HIGH/MEDIUM/LOW/INFO
    risk_score      Float32,
    cvss_score      Float32,
    epss_score      Float32,
    kev_present     UInt8,                   -- 0/1

    -- Classification
    threat_type     LowCardinality(String),
    actor_tag       String,
    scoring_track   LowCardinality(String),  -- CVE_ONLY/THREAT_ACTOR/BLENDED
    feed_source     LowCardinality(String),

    -- IOC metrics
    ioc_count       UInt16,
    ioc_types       Array(String),

    -- ATT&CK coverage
    tactic_count    UInt8,
    technique_ids   Array(String),

    -- Pipeline metrics
    pipeline_stage  LowCardinality(String),
    processing_ms   UInt32,

    -- Tenant
    tenant_id       LowCardinality(String)   DEFAULT 'default',

    -- Partitioning
    _partition_key  Date MATERIALIZED toDate(ts)
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/sentinel_apex/threat_intel_events',
    '{replica}'
)
PARTITION BY toYYYYMM(_partition_key)
ORDER BY (tenant_id, severity, ts)
TTL ts + INTERVAL 90 DAY TO VOLUME 'cold',
    ts + INTERVAL 365 DAY DELETE
SETTINGS
    index_granularity = 8192,
    merge_with_ttl_timeout = 3600;

-- =============================================================================
-- 2. API TELEMETRY (Usage metering, billing, rate limiting)
-- =============================================================================
CREATE TABLE IF NOT EXISTS api_telemetry ON CLUSTER sentinel_cluster
(
    ts              DateTime64(3, 'UTC'),
    request_id      UUID         DEFAULT generateUUIDv4(),

    -- Identity
    tenant_id       LowCardinality(String),
    api_key_id      String,
    tier            LowCardinality(String),  -- free/pro/enterprise/mssp

    -- Request details
    endpoint        String,
    method          LowCardinality(String),
    http_status     UInt16,
    response_ms     UInt32,
    request_bytes   UInt32,
    response_bytes  UInt32,

    -- Rate limiting
    quota_consumed  UInt16,
    quota_remaining UInt32,
    rate_limited    UInt8,

    -- Geography
    client_ip       IPv4,
    country_code    FixedString(2),
    region          LowCardinality(String),

    -- Error tracking
    error_code      LowCardinality(String),
    error_msg       String,

    _partition_key  Date MATERIALIZED toDate(ts)
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/sentinel_apex/api_telemetry',
    '{replica}'
)
PARTITION BY toYYYYMM(_partition_key)
ORDER BY (tenant_id, tier, ts)
TTL ts + INTERVAL 90 DAY TO VOLUME 'cold',
    ts + INTERVAL 365 DAY DELETE
SETTINGS index_granularity = 8192;

-- =============================================================================
-- 3. SOC ALERT EVENTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS soc_alert_events ON CLUSTER sentinel_cluster
(
    ts              DateTime64(3, 'UTC'),
    alert_id        UUID         DEFAULT generateUUIDv4(),
    tenant_id       LowCardinality(String),

    -- Alert classification
    alert_type      LowCardinality(String),
    severity        LowCardinality(String),
    priority        LowCardinality(String),  -- P1/P2/P3/P4

    -- Source intel
    advisory_id     String,
    ioc_value       String,
    ioc_type        LowCardinality(String),
    actor_tag       String,

    -- Workflow state
    status          LowCardinality(String),  -- open/triaged/closed/fp
    assigned_to     String,
    triage_ms       UInt32,                  -- time to first triage
    resolve_ms      UInt32,                  -- time to resolution
    sla_breached    UInt8,

    -- MITRE context
    tactic_id       LowCardinality(String),
    technique_id    LowCardinality(String),

    -- SIEM routing
    siem_target     LowCardinality(String),  -- splunk/sentinel/elastic/chronicle
    siem_event_id   String,
    siem_pushed_at  DateTime64(3, 'UTC'),

    _partition_key  Date MATERIALIZED toDate(ts)
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/sentinel_apex/soc_alert_events',
    '{replica}'
)
PARTITION BY toYYYYMM(_partition_key)
ORDER BY (tenant_id, severity, status, ts)
TTL ts + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192;

-- =============================================================================
-- 4. AI RUNTIME DEFENSE EVENTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS ai_runtime_events ON CLUSTER sentinel_cluster
(
    ts              DateTime64(3, 'UTC'),
    event_id        UUID         DEFAULT generateUUIDv4(),
    tenant_id       LowCardinality(String),
    session_id      String,

    -- Event classification
    event_type      LowCardinality(String),  -- prompt_injection/jailbreak/rag_poison/anomaly
    detection_model LowCardinality(String),
    confidence      Float32,
    blocked         UInt8,

    -- Payload (truncated for privacy)
    payload_hash    String,
    payload_len     UInt32,
    risk_score      Float32,

    -- Model context
    model_id        LowCardinality(String),
    model_provider  LowCardinality(String),
    endpoint_id     String,

    -- Response action
    action_taken    LowCardinality(String),  -- blocked/logged/alerted/sanitized
    latency_ms      UInt16,

    _partition_key  Date MATERIALIZED toDate(ts)
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/sentinel_apex/ai_runtime_events',
    '{replica}'
)
PARTITION BY toYYYYMM(_partition_key)
ORDER BY (tenant_id, event_type, ts)
TTL ts + INTERVAL 90 DAY DELETE
SETTINGS index_granularity = 8192;

-- =============================================================================
-- 5. PIPELINE HEALTH METRICS
-- =============================================================================
CREATE TABLE IF NOT EXISTS pipeline_health ON CLUSTER sentinel_cluster
(
    ts              DateTime64(3, 'UTC'),
    run_id          String,
    workflow_name   LowCardinality(String),

    -- Stage metrics
    stage_name      LowCardinality(String),
    stage_status    LowCardinality(String),  -- success/failed/skipped
    duration_ms     UInt32,
    retry_count     UInt8,

    -- Resource utilization
    disk_used_mb    UInt32,
    disk_free_mb    UInt32,
    mem_used_mb     UInt32,
    cpu_pct         Float32,

    -- Output metrics
    items_processed UInt32,
    items_failed    UInt16,
    artifacts_size_kb UInt32,

    -- Error tracking
    error_class     LowCardinality(String),
    error_msg       String,

    _partition_key  Date MATERIALIZED toDate(ts)
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/sentinel_apex/pipeline_health',
    '{replica}'
)
PARTITION BY toYYYYMM(_partition_key)
ORDER BY (workflow_name, stage_status, ts)
TTL ts + INTERVAL 180 DAY DELETE
SETTINGS index_granularity = 8192;

-- =============================================================================
-- 6. MSSP TENANT BILLING EVENTS
-- =============================================================================
CREATE TABLE IF NOT EXISTS mssp_billing_events ON CLUSTER sentinel_cluster
(
    ts              DateTime64(3, 'UTC'),
    event_id        UUID         DEFAULT generateUUIDv4(),
    tenant_id       LowCardinality(String),
    tenant_name     String,
    billing_period  String,  -- YYYY-MM

    -- Usage
    api_calls       UInt32,
    intel_items     UInt32,
    stix_exports    UInt16,
    siem_pushes     UInt16,
    ai_queries      UInt16,
    users           UInt8,

    -- Tier & pricing
    tier            LowCardinality(String),
    base_price_usd  Float32,
    overage_usd     Float32,
    total_usd       Float32,
    invoice_id      String,
    payment_status  LowCardinality(String),

    _partition_key  Date MATERIALIZED toDate(ts)
)
ENGINE = ReplicatedMergeTree(
    '/clickhouse/tables/{shard}/sentinel_apex/mssp_billing_events',
    '{replica}'
)
PARTITION BY toYYYYMM(_partition_key)
ORDER BY (tenant_id, billing_period, ts)
TTL ts + INTERVAL 730 DAY DELETE  -- 2 years for billing compliance
SETTINGS index_granularity = 8192;

-- =============================================================================
-- MATERIALIZED VIEWS (Aggregations for real-time dashboards)
-- =============================================================================

-- Daily threat severity summary
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_daily_threat_summary
ON CLUSTER sentinel_cluster
ENGINE = ReplicatedSummingMergeTree(
    '/clickhouse/tables/{shard}/sentinel_apex/mv_daily_threat_summary', '{replica}'
)
PARTITION BY toYYYYMM(date)
ORDER BY (tenant_id, date, severity)
AS SELECT
    tenant_id,
    toDate(ts)          AS date,
    severity,
    count()             AS advisory_count,
    sum(kev_present)    AS kev_count,
    avg(risk_score)     AS avg_risk_score,
    max(risk_score)     AS max_risk_score,
    sum(ioc_count)      AS total_iocs
FROM threat_intel_events
GROUP BY tenant_id, date, severity;

-- Hourly API usage summary
CREATE MATERIALIZED VIEW IF NOT EXISTS mv_hourly_api_usage
ON CLUSTER sentinel_cluster
ENGINE = ReplicatedSummingMergeTree(
    '/clickhouse/tables/{shard}/sentinel_apex/mv_hourly_api_usage', '{replica}'
)
PARTITION BY toYYYYMM(hour)
ORDER BY (tenant_id, tier, hour)
AS SELECT
    tenant_id,
    tier,
    toStartOfHour(ts)   AS hour,
    count()             AS request_count,
    sum(rate_limited)   AS rate_limit_hits,
    avg(response_ms)    AS avg_latency_ms,
    sumIf(1, http_status >= 500) AS server_errors,
    sum(response_bytes) AS bytes_out
FROM api_telemetry
GROUP BY tenant_id, tier, hour;

-- =============================================================================
-- 6. AUDIT LOG — Enterprise Trust & Compliance (SOC 2 CC6.2 / CC7.2)
-- =============================================================================
CREATE TABLE IF NOT EXISTS audit_log ON CLUSTER sentinel_cluster
(
    -- Identity
    audit_id        UUID         DEFAULT generateUUIDv4(),
    ts              DateTime64(3, 'UTC'),
    tenant_id       String,
    actor_id        String,       -- user/service/api_key performing action
    actor_type      LowCardinality(String),  -- 'user' | 'api_key' | 'service' | 'system'

    -- Action
    action          LowCardinality(String),  -- 'CREATE' | 'READ' | 'UPDATE' | 'DELETE' | 'AUTH' | 'EXPORT'
    resource_type   LowCardinality(String),  -- 'feed' | 'alert' | 'api_key' | 'tenant' | 'billing'
    resource_id     String,
    outcome         LowCardinality(String),  -- 'SUCCESS' | 'FAILURE' | 'DENIED'

    -- Context
    ip_address      IPv4,
    user_agent      String,
    session_id      String,
    api_key_id      String,
    request_id      String,

    -- Change tracking (for UPDATE/DELETE)
    old_value       String        DEFAULT '',
    new_value       String        DEFAULT '',
    diff_summary    String        DEFAULT '',

    -- Compliance tagging
    compliance_tags Array(String) DEFAULT [],  -- ['SOC2-CC6.2', 'GDPR-Art30', 'PCI-DSS-10']
    retention_days  UInt16        DEFAULT 2555  -- 7 years retention for compliance

) ENGINE = ReplicatedMergeTree(
    '/clickhouse/{cluster}/sentinel_apex/audit_log/{shard}',
    '{replica}'
)
PARTITION BY toYYYYMM(ts)
ORDER BY (tenant_id, ts, audit_id)
TTL ts + INTERVAL retention_days DAY TO DISK 'cold_storage'
SETTINGS index_granularity = 8192;

-- Materialized view: audit events per tenant per day (compliance reporting)
CREATE MATERIALIZED VIEW IF NOT EXISTS audit_daily_summary ON CLUSTER sentinel_cluster
ENGINE = SummingMergeTree()
ORDER BY (tenant_id, action, outcome, day)
AS SELECT
    tenant_id,
    action,
    outcome,
    toDate(ts)  AS day,
    count()     AS event_count,
    uniqExact(actor_id) AS unique_actors
FROM audit_log
GROUP BY tenant_id, action, outcome, day;

-- =============================================================================
-- INDEXES for high-cardinality lookups
-- =============================================================================
ALTER TABLE threat_intel_events ON CLUSTER sentinel_cluster
    ADD INDEX idx_advisory_id advisory_id TYPE bloom_filter(0.01) GRANULARITY 4;

ALTER TABLE api_telemetry ON CLUSTER sentinel_cluster
    ADD INDEX idx_api_key api_key_id TYPE bloom_filter(0.01) GRANULARITY 4;

ALTER TABLE soc_alert_events ON CLUSTER sentinel_cluster
    ADD INDEX idx_ioc_value ioc_value TYPE bloom_filter(0.01) GRANULARITY 4;

-- =============================================================================
-- VERIFICATION QUERIES
-- =============================================================================
-- Run these to confirm schema health post-deployment:

-- SELECT table, engine, total_rows, total_bytes
-- FROM system.tables
-- WHERE database = 'sentinel_apex'
-- ORDER BY total_bytes DESC;

-- SELECT partition, rows, bytes_on_disk, disk_name
-- FROM system.parts
-- WHERE database = 'sentinel_apex' AND table = 'threat_intel_events'
-- ORDER BY modification_time DESC LIMIT 10;
