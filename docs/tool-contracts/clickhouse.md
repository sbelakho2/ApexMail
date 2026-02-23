# ClickHouse Tool Contract

## Overview

ClickHouse is the OLAP analytics database for ApexMail, providing sub-second queries over billions of email events with 730-day retention.

## Connection Details

| Environment | URL | Database |
|-------------|-----|----------|
| Development | `http://localhost:8123` | `apexmail` |
| Production | `http://clickhouse:8123` | `apexmail` |

## Environment Variables

```bash
# Required
CLICKHOUSE_URL=http://clickhouse:8123
CLICKHOUSE_DATABASE=apexmail

# Optional (with defaults)
CLICKHOUSE_USER=default
CLICKHOUSE_PASSWORD=
CLICKHOUSE_MAX_CONNECTIONS=20
```

## Schema

### Events Table (MergeTree)

```sql
CREATE TABLE events (
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
    INDEX idx_recipient recipient TYPE bloom_filter GRANULARITY 4
)
ENGINE = MergeTree()
PARTITION BY toYYYYMM(timestamp)
ORDER BY (tenant_id, timestamp, event_type)
TTL timestamp + INTERVAL 730 DAY
SETTINGS index_granularity = 8192
```

### Materialized Views

Daily and hourly aggregates are populated automatically via materialized views:

```sql
-- Daily aggregates (SummingMergeTree)
CREATE MATERIALIZED VIEW daily_aggregates_mv
TO daily_aggregates AS
SELECT tenant_id, toDate(timestamp) AS date, event_type, count() AS count
FROM events GROUP BY tenant_id, date, event_type;

-- Hourly aggregates (SummingMergeTree)  
CREATE MATERIALIZED VIEW hourly_aggregates_mv
TO hourly_aggregates AS
SELECT tenant_id, toStartOfHour(timestamp) AS hour, event_type, count() AS count
FROM events GROUP BY tenant_id, hour, event_type;
```

## Query Patterns

### Time-Series (Dashboard)

```sql
SELECT
    toDate(timestamp) AS period,
    count() AS value
FROM events
WHERE tenant_id = 'tenant_123'
  AND timestamp >= toDateTime64('2026-01-01', 3)
  AND timestamp < toDateTime64('2026-02-01', 3)
  AND event_type IN ('delivered', 'opened', 'clicked')
GROUP BY period
ORDER BY period
```

### Funnel Analysis

```sql
SELECT
    event_type,
    uniqExact(message_id) AS unique_messages
FROM events
WHERE tenant_id = 'tenant_123'
  AND timestamp >= toDateTime64('2026-01-01', 3)
  AND timestamp < toDateTime64('2026-02-01', 3)
  AND event_type IN ('sent', 'delivered', 'opened', 'clicked')
GROUP BY event_type
```

### Dimension Aggregation

```sql
SELECT
    recipient_domain AS dimension,
    count() AS count
FROM events
WHERE tenant_id = 'tenant_123'
  AND timestamp >= toDateTime64('2026-01-01', 3)
  AND timestamp < toDateTime64('2026-02-01', 3)
GROUP BY dimension
ORDER BY count DESC
LIMIT 100
```

## Docker Deployment

```yaml
clickhouse:
  image: clickhouse/clickhouse-server:24.8-alpine
  container_name: apexmail-clickhouse
  environment:
    CLICKHOUSE_DB: apexmail
    CLICKHOUSE_USER: default
    CLICKHOUSE_PASSWORD: ""
  volumes:
    - clickhouse_data:/var/lib/clickhouse
    - clickhouse_logs:/var/log/clickhouse-server
  ports:
    - "8123:8123"   # HTTP
    - "9000:9000"   # Native protocol
  healthcheck:
    test: ["CMD-SHELL", "wget -qO- http://localhost:8123/ping || exit 1"]
```

## Performance Characteristics

| Metric | Value |
|--------|-------|
| Insert throughput | 100K+ events/sec (async inserts) |
| Query latency (time-series) | < 100ms on 1B rows |
| Compression ratio | 10-20x vs PostgreSQL |
| Partition pruning | Automatic by `toYYYYMM(timestamp)` |

## Rust Integration

```rust
use analytics::clickhouse_engine::ClickHouseEngine;
use analytics::config::ClickHouseConfig;

let config = ClickHouseConfig::from_env();
let engine = ClickHouseEngine::new(config).await?;

// Time-series query
let series = engine.time_series(
    "tenant_123",
    start_date,
    end_date,
    "day",
    Some(&["delivered", "opened"]),
).await?;

// Deliverability metrics
let metrics = engine.deliverability_metrics(
    "tenant_123",
    start_date,
    end_date,
).await?;
```

## Monitoring

### Key Metrics

- `clickhouse_events_inserted_total` - Total events inserted
- `clickhouse_query_duration_seconds` - Query latency histogram
- `clickhouse_active_parts` - Number of active MergeTree parts

### Health Check

```bash
curl http://localhost:8123/ping
# Should return "Ok.\n"
```

## Backup & Recovery

ClickHouse data is persisted in the `clickhouse_data` Docker volume. For production:

1. Use ClickHouse Keeper for replication (3-node minimum)
2. Enable `clickhouse-backup` for S3 snapshots
3. Set up read replicas for query scaling

## Comparison to Alternatives

| Feature | ClickHouse | DuckDB | PostgreSQL |
|---------|------------|--------|------------|
| **Scale** | Petabytes, horizontal | Single-node, ~100GB | Single-node, ~1TB |
| **Concurrency** | Lock-free reads | Single writer | MVCC, limited |
| **Retention** | 730 days @ billions of rows | Memory-bound | Index bloat |
| **Industry use** | Cloudflare, Uber, Resend | Analytics notebooks | OLTP |

**Conclusion:** ClickHouse is the right choice for ApexMail's enterprise email analytics at scale.
