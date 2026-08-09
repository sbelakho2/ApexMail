-- ApexMail ClickHouse schema — auto-applied by the ClickHouse image on first
-- boot (/docker-entrypoint-initdb.d), and applied manually to existing
-- instances via `clickhouse-client < 001_schema.sql`.
--
-- MUST stay in sync with `ClickHouseEngine::init_schema` in
-- services/mail-server/crates/analytics/src/clickhouse_engine.rs and with the
-- writer in services/mail-server/crates/tracking-service/src/processor.rs.

CREATE DATABASE IF NOT EXISTS apexmail;

-- Main events table — partitioned by month, ordered for tenant+time queries.
CREATE TABLE IF NOT EXISTS apexmail.events (
    id String,
    tenant_id LowCardinality(String),
    message_id String,
    event_type LowCardinality(String),
    timestamp DateTime64(3),
    recipient String,
    recipient_domain LowCardinality(String),
    link_id String,
    user_agent String,
    ip_address String,
    country LowCardinality(String),
    device_type LowCardinality(String),
    campaign_id String,
    metadata String,

    INDEX idx_message_id message_id TYPE bloom_filter GRANULARITY 4,
    INDEX idx_recipient recipient TYPE bloom_filter GRANULARITY 4,
    INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 1
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, event_type)
-- TTL on DateTime64 columns must be cast to DateTime (ClickHouse <= 24.x)
TTL toDateTime(timestamp) + INTERVAL 730 DAY
SETTINGS index_granularity = 8192;

-- Daily aggregates — automatic rollup target (SummingMergeTree).
CREATE TABLE IF NOT EXISTS apexmail.daily_aggregates (
    tenant_id LowCardinality(String),
    date Date,
    event_type LowCardinality(String),
    count UInt64
)
ENGINE = SummingMergeTree()
PARTITION BY toYYYYMM(date)
ORDER BY (tenant_id, date, event_type)
TTL date + INTERVAL 730 DAY;

-- Hourly aggregates — real-time dashboards (SummingMergeTree).
CREATE TABLE IF NOT EXISTS apexmail.hourly_aggregates (
    tenant_id LowCardinality(String),
    hour DateTime,
    event_type LowCardinality(String),
    count UInt64
)
ENGINE = SummingMergeTree()
ORDER BY (tenant_id, hour, event_type)
TTL hour + INTERVAL 90 DAY;

-- Materialized views populating the aggregate tables from the raw events.
CREATE MATERIALIZED VIEW IF NOT EXISTS apexmail.daily_aggregates_mv
TO apexmail.daily_aggregates
AS SELECT
    tenant_id,
    toDate(timestamp) AS date,
    event_type,
    count() AS count
FROM apexmail.events
GROUP BY tenant_id, date, event_type;

CREATE MATERIALIZED VIEW IF NOT EXISTS apexmail.hourly_aggregates_mv
TO apexmail.hourly_aggregates
AS SELECT
    tenant_id,
    toStartOfHour(timestamp) AS hour,
    event_type,
    count() AS count
FROM apexmail.events
GROUP BY tenant_id, hour, event_type;
