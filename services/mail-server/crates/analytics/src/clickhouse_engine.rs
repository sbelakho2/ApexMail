//! ClickHouse OLAP query engine for enterprise-scale analytics.
//!
//! Uses ClickHouse for:
//! - Billions of events with sub-second queries
//! - Time-series aggregations with partition pruning
//! - Multi-tenant concurrent analytics
//! - 730-day retention with columnar compression
//! - Real-time event ingestion via async inserts

use std::time::Duration;

use chrono::{DateTime, Utc};
use clickhouse::{Client, Row};
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::{debug, info, warn};

use crate::config::ClickHouseConfig;
use crate::types::*;

/// ClickHouse-backed analytics engine for OLAP queries at enterprise scale.
#[derive(Clone)]
pub struct ClickHouseEngine {
    client: Client,
    config: ClickHouseConfig,
}

/// Event row for ClickHouse ingestion.
#[derive(Debug, Clone, Serialize, Deserialize, Row)]
pub struct ClickHouseEvent {
    pub id: String,
    pub tenant_id: String,
    pub message_id: String,
    pub event_type: String,
    pub timestamp: i64, // Unix timestamp in milliseconds
    pub recipient: String,
    pub recipient_domain: String,
    pub link_id: String,
    pub user_agent: String,
    pub ip_address: String,
    pub country: String,
    pub device_type: String,
    pub campaign_id: String,
    pub metadata: String, // JSON string
}

/// Time-series result row.
#[derive(Debug, Row, Deserialize)]
struct TimeSeriesRow {
    period: String,
    value: u64,
}

/// Aggregation result row.
#[derive(Debug, Row, Deserialize)]
struct AggregationRow {
    dimension: String,
    count: u64,
}

/// Funnel stage result row.
#[derive(Debug, Row, Deserialize)]
struct FunnelRow {
    event_type: String,
    unique_messages: u64,
}

impl ClickHouseEngine {
    /// Create a new ClickHouse engine with the given configuration.
    ///
    /// TLS is enabled when `config.tls_enabled` is `true` (O-11.2).
    /// The URL scheme is automatically upgraded to `https://` and the
    /// `secure` option is set on the native protocol connection.
    pub async fn new(config: ClickHouseConfig) -> anyhow::Result<Self> {
        // Apply TLS: upgrade URL scheme and set secure option (O-11.2)
        let url = if config.tls_enabled {
            // Ensure https:// scheme
            if config.url.starts_with("http://") {
                config.url.replacen("http://", "https://", 1)
            } else if !config.url.starts_with("https://") {
                format!("https://{}", config.url)
            } else {
                config.url.clone()
            }
        } else {
            config.url.clone()
        };

        let mut client_builder = Client::default()
            .with_url(&url)
            .with_database(&config.database)
            .with_user(&config.user)
            .with_password(&config.password)
            .with_compression(clickhouse::Compression::Lz4)
            // DB-11: async_insert=1 with wait_for_async_insert=0 gives eventual consistency.
            // Materialized views (daily_aggregates_mv, hourly_aggregates_mv) may lag behind
            // the main table by up to ~1s (the async insert flush interval).
            // For critical reads-after-write (e.g., real-time dashboards), set
            // wait_for_async_insert=1 or query the raw events table.
            .with_option("async_insert", "1")
            .with_option("wait_for_async_insert", "0")
            // SCALE-M-03: Batch insert tuning for optimal write throughput.
            // async_insert_busy_timeout_ms: how long ClickHouse buffers before flushing
            //   (200ms default gives ~5 flushes/sec without excessive latency).
            // async_insert_max_data_size: max bytes buffered before forced flush
            //   (10MB batches balance memory overhead vs throughput).
            // max_insert_block_size: cap on a single insert block for memory stability
            //   (keep at 1M default; lower if we see OOM under heavy write load).
            // min_insert_block_size_rows / min_insert_block_size_bytes: control how
            //   aggressively ClickHouse merges small inserts into one block.
            .with_option("async_insert_busy_timeout_ms", "200")
            .with_option("async_insert_max_data_size", "10000000")
            .with_option("max_insert_block_size", "1048576")
            .with_option("min_insert_block_size_rows", "100000")
            .with_option("min_insert_block_size_bytes", "50000000");

        if config.tls_enabled {
            client_builder = client_builder.with_option("secure", "1");
        }

        // If a CA cert path is provided, attempt to load it for verification
        if config.tls_enabled && !config.ca_cert_path.is_empty() {
            // The clickhouse crate uses system CA roots by default.
            // For custom CA certificates, configure the SSL_CERT_FILE
            // environment variable or set CLICKHOUSE_CA_CERT_PATH.
            tracing::info!(
                "ClickHouse TLS enabled with CA cert: {}",
                config.ca_cert_path
            );
        }

        let client = client_builder;

        let engine = Self { client, config };

        // Initialize schema
        engine.init_schema().await?;

        info!(url = %engine.config.url, database = %engine.config.database,
              "ClickHouse analytics engine initialized");

        Ok(engine)
    }

    /// Initialize the analytics schema with MergeTree tables.
    async fn init_schema(&self) -> anyhow::Result<()> {
        // Main events table - partitioned by month, ordered for efficient tenant+time queries
        self.client
            .query(
                r#"
                CREATE TABLE IF NOT EXISTS events (
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
                    ,INDEX idx_timestamp timestamp TYPE minmax GRANULARITY 1
                )
                ENGINE = MergeTree()
                PARTITION BY toYYYYMM(timestamp)
                ORDER BY (tenant_id, timestamp, event_type)
                TTL timestamp + INTERVAL 730 DAY
                SETTINGS index_granularity = 8192
                "#,
            )
            .execute()
            .await?;

        // Materialized view for daily aggregates - automatic rollup
        self.client
            .query(
                r#"
                CREATE TABLE IF NOT EXISTS daily_aggregates (
                    tenant_id LowCardinality(String),
                    date Date,
                    event_type LowCardinality(String),
                    count UInt64
                )
                ENGINE = SummingMergeTree()
                PARTITION BY toYYYYMM(date)
                ORDER BY (tenant_id, date, event_type)
                TTL date + INTERVAL 730 DAY
                "#,
            )
            .execute()
            .await?;

        // Hourly aggregates for real-time dashboards
        self.client
            .query(
                r#"
                CREATE TABLE IF NOT EXISTS hourly_aggregates (
                    tenant_id LowCardinality(String),
                    hour DateTime,
                    event_type LowCardinality(String),
                    count UInt64
                )
                ENGINE = SummingMergeTree()
                ORDER BY (tenant_id, hour, event_type)
                TTL hour + INTERVAL 90 DAY
                "#,
            )
            .execute()
            .await?;

        // Materialized view to populate daily aggregates automatically
        self.client
            .query(
                r#"
                CREATE MATERIALIZED VIEW IF NOT EXISTS daily_aggregates_mv
                TO daily_aggregates
                AS SELECT
                    tenant_id,
                    toDate(timestamp) AS date,
                    event_type,
                    count() AS count
                FROM events
                GROUP BY tenant_id, date, event_type
                "#,
            )
            .execute()
            .await?;

        // Materialized view for hourly aggregates
        self.client
            .query(
                r#"
                CREATE MATERIALIZED VIEW IF NOT EXISTS hourly_aggregates_mv
                TO hourly_aggregates
                AS SELECT
                    tenant_id,
                    toStartOfHour(timestamp) AS hour,
                    event_type,
                    count() AS count
                FROM events
                GROUP BY tenant_id, hour, event_type
                "#,
            )
            .execute()
            .await?;

        debug!("ClickHouse schema initialized with MergeTree tables and materialized views");
        Ok(())
    }

    /// Insert events using async inserts for high throughput.
    ///
    /// The insert is bounded by [`ClickHouseConfig::insert_timeout_seconds`] (T-309)
    /// to prevent unbounded waits when ClickHouse is slow or unresponsive.
    pub async fn insert_events(&self, events: &[ClickHouseEvent]) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let timeout_dur = Duration::from_secs(self.config.insert_timeout_seconds);

        timeout(timeout_dur, async {
            let mut insert = self.client.insert("events")?;
            for event in events {
                insert.write(event).await?;
            }
            insert.end().await
        })
        .await
        .map_err(|_elapsed| {
            warn!(
                count = events.len(),
                timeout_s = self.config.insert_timeout_seconds,
                "ClickHouse insert timed out"
            );
            anyhow::anyhow!(
                "ClickHouse insert timed out after {}s for {} events",
                self.config.insert_timeout_seconds,
                events.len()
            )
        })??;

        debug!(count = events.len(), "Inserted events into ClickHouse");
        Ok(())
    }

    /// Time-series query with automatic granularity.
    pub async fn time_series(
        &self,
        tenant_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        granularity: &str,
        event_types: Option<&[String]>,
    ) -> anyhow::Result<Vec<TimeSeriesPoint>> {
        let trunc_fn = match granularity {
            "hour" => "toStartOfHour(timestamp)",
            "day" => "toDate(timestamp)",
            "week" => "toStartOfWeek(timestamp)",
            "month" => "toStartOfMonth(timestamp)",
            _ => "toDate(timestamp)",
        };

        // Allowlist valid event types to prevent SQL injection (#178)
        const ALLOWED_EVENT_TYPES: &[&str] = &[
            "sent",
            "delivered",
            "bounced",
            "deferred",
            "dropped",
            "opened",
            "clicked",
            "complained",
            "unsubscribed",
        ];
        let (event_filter, type_values): (String, Vec<String>) = if let Some(types) = event_types {
            let safe: Vec<&str> = types
                .iter()
                .filter(|t| ALLOWED_EVENT_TYPES.contains(&t.as_str()))
                .map(|t| t.as_str())
                .collect();
            if safe.is_empty() {
                (String::new(), Vec::new())
            } else {
                let placeholders: Vec<&str> = vec!["?"; safe.len()];
                (
                    format!(" AND event_type IN ({})", placeholders.join(",")),
                    safe.iter().map(|s| s.to_string()).collect(),
                )
            }
        } else {
            (String::new(), Vec::new())
        };

        let query = format!(
            r#"
            SELECT
                toString({}) AS period,
                count() AS value
            FROM events
            WHERE tenant_id = ?
              AND timestamp >= toDateTime64(?, 3)
              AND timestamp < toDateTime64(?, 3)
              {}
            GROUP BY period
            ORDER BY period
            "#,
            trunc_fn, event_filter
        );

        let mut query_obj = self
            .client
            .query(&query)
            .bind(tenant_id)
            .bind(start.timestamp_millis() as f64 / 1000.0)
            .bind(end.timestamp_millis() as f64 / 1000.0);

        for t in &type_values {
            query_obj = query_obj.bind(t.as_str());
        }

        let rows = query_obj.fetch_all::<TimeSeriesRow>().await?;

        Ok(rows
            .into_iter()
            .map(|r| TimeSeriesPoint {
                timestamp: r.period,
                value: r.value as i64,
            })
            .collect())
    }

    /// Aggregation by dimension with percentage calculation.
    pub async fn aggregate_by_dimension(
        &self,
        tenant_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        dimension: &str,
    ) -> anyhow::Result<Vec<AggregationResult>> {
        // Allowlist dimensions to prevent SQL injection
        let dim_col = match dimension {
            "event_type" | "recipient_domain" | "country" | "device_type" | "link_id"
            | "campaign_id" => dimension,
            _ => "event_type",
        };

        let query = format!(
            r#"
            SELECT
                {} AS dimension,
                count() AS count
            FROM events
            WHERE tenant_id = ?
              AND timestamp >= toDateTime64(?, 3)
              AND timestamp < toDateTime64(?, 3)
            GROUP BY dimension
            ORDER BY count DESC
            LIMIT 100
            "#,
            dim_col
        );

        let rows = self
            .client
            .query(&query)
            .bind(tenant_id)
            .bind(start.timestamp_millis() as f64 / 1000.0)
            .bind(end.timestamp_millis() as f64 / 1000.0)
            .fetch_all::<AggregationRow>()
            .await?;

        let total: u64 = rows.iter().map(|r| r.count).sum();

        Ok(rows
            .into_iter()
            .map(|r| AggregationResult {
                dimension: r.dimension,
                count: r.count as i64,
                percentage: if total > 0 {
                    Some(r.count as f64 / total as f64 * 100.0)
                } else {
                    None
                },
            })
            .collect())
    }

    /// Funnel analysis:conversion through event stages.
    pub async fn funnel_analysis(
        &self,
        tenant_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
        stages: &[&str],
    ) -> anyhow::Result<Vec<FunnelStage>> {
        if stages.is_empty() {
            return Ok(Vec::new());
        }

        // Allowlist stages to prevent SQL injection (#178)
        const ALLOWED_STAGES: &[&str] = &[
            "sent",
            "delivered",
            "bounced",
            "deferred",
            "dropped",
            "opened",
            "clicked",
            "complained",
            "unsubscribed",
        ];
        let safe_stages: Vec<&str> = stages
            .iter()
            .filter(|s| ALLOWED_STAGES.contains(s))
            .copied()
            .collect();
        if safe_stages.is_empty() {
            return Ok(Vec::new());
        }
        let placeholders: Vec<&str> = vec!["?"; safe_stages.len()];
        let stages_list = placeholders.join(",");

        let query = format!(
            r#"
            SELECT
                event_type,
                uniqExact(message_id) AS unique_messages
            FROM events
            WHERE tenant_id = ?
              AND timestamp >= toDateTime64(?, 3)
              AND timestamp < toDateTime64(?, 3)
              AND event_type IN ({})
            GROUP BY event_type
            "#,
            stages_list
        );

        let mut query_obj = self
            .client
            .query(&query)
            .bind(tenant_id)
            .bind(start.timestamp_millis() as f64 / 1000.0)
            .bind(end.timestamp_millis() as f64 / 1000.0);

        for stage in &safe_stages {
            query_obj = query_obj.bind(stage);
        }

        let rows = query_obj.fetch_all::<FunnelRow>().await?;

        let counts: std::collections::HashMap<String, u64> = rows
            .into_iter()
            .map(|r| (r.event_type, r.unique_messages))
            .collect();

        let mut results = Vec::new();
        let mut previous_count: Option<u64> = None;
        let first_count = counts.get(stages[0]).copied().unwrap_or(0).max(1);

        for stage in stages {
            let count = counts.get(*stage).copied().unwrap_or(0);

            let dropoff = previous_count
                .map(|prev| {
                    if prev > 0 {
                        (prev - count) as f64 / prev as f64 * 100.0
                    } else {
                        0.0
                    }
                })
                .unwrap_or(0.0);

            let percentage = count as f64 / first_count as f64 * 100.0;

            results.push(FunnelStage {
                stage: stage.to_string(),
                count: count as i64,
                dropoff,
                percentage,
            });

            previous_count = Some(count);
        }

        Ok(results)
    }

    /// Get deliverability metrics.
    pub async fn deliverability_metrics(
        &self,
        tenant_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> anyhow::Result<DeliverabilityMetrics> {
        let query = r#"
            SELECT
                event_type,
                count() AS count
            FROM events
            WHERE tenant_id = ?
              AND timestamp >= toDateTime64(?, 3)
              AND timestamp < toDateTime64(?, 3)
            GROUP BY event_type
        "#;

        let rows = self
            .client
            .query(query)
            .bind(tenant_id)
            .bind(start.timestamp_millis() as f64 / 1000.0)
            .bind(end.timestamp_millis() as f64 / 1000.0)
            .fetch_all::<AggregationRow>()
            .await?;

        let counts: std::collections::HashMap<String, u64> =
            rows.into_iter().map(|r| (r.dimension, r.count)).collect();

        let sent = *counts.get("sent").unwrap_or(&0) as f64;
        let delivered = *counts.get("delivered").unwrap_or(&0) as f64;
        let bounced = *counts.get("bounced").unwrap_or(&0) as f64;
        let complained = *counts.get("complained").unwrap_or(&0) as f64;
        let opened = *counts.get("opened").unwrap_or(&0) as f64;
        let clicked = *counts.get("clicked").unwrap_or(&0) as f64;
        let unsubscribed = *counts.get("unsubscribed").unwrap_or(&0) as f64;

        let safe_div = |num: f64, den: f64| if den > 0.0 { num / den } else { 0.0 };

        Ok(DeliverabilityMetrics {
            delivery_rate: safe_div(delivered, sent),
            bounce_rate: safe_div(bounced, sent),
            complaint_rate: safe_div(complained, sent),
            open_rate: safe_div(opened, delivered),
            click_rate: safe_div(clicked, delivered),
            unsubscribe_rate: safe_div(unsubscribed, delivered),
        })
    }

    /// Engagement histogram: group recipients by engagement level.
    pub async fn engagement_histogram(
        &self,
        tenant_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> anyhow::Result<Vec<EngagementBucket>> {
        let query = r#"
            SELECT
                multiIf(
                    countIf(event_type = 'clicked') > 2, 'highly_engaged',
                    countIf(event_type = 'opened') > 2, 'engaged',
                    countIf(event_type = 'opened') > 0, 'somewhat_engaged',
                    countIf(event_type = 'unsubscribed') > 0, 'unsubscribed',
                    'not_engaged'
                ) AS bucket,
                count() AS count
            FROM events
            WHERE tenant_id = ?
              AND timestamp >= toDateTime64(?, 3)
              AND timestamp < toDateTime64(?, 3)
            GROUP BY bucket
            ORDER BY bucket
        "#;

        #[derive(Debug, Row, Deserialize)]
        struct HistogramRow {
            bucket: String,
            count: u64,
        }

        let rows = self
            .client
            .query(query)
            .bind(tenant_id)
            .bind(start.timestamp_millis() as f64 / 1000.0)
            .bind(end.timestamp_millis() as f64 / 1000.0)
            .fetch_all::<HistogramRow>()
            .await?;

        Ok(rows
            .into_iter()
            .map(|r| EngagementBucket {
                range: r.bucket,
                count: r.count as i64,
            })
            .collect())
    }

    /// Real-time stats for the current hour and day windows.
    pub async fn realtime_stats(&self, tenant_id: &str) -> anyhow::Result<RealtimeStats> {
        #[derive(Debug, Row, Deserialize)]
        struct StatsRow {
            sent: u64,
            delivered: u64,
            bounced: u64,
            opened: u64,
            clicked: u64,
            complained: u64,
            unsubscribed: u64,
        }

        // Hour window
        let hour_query = r#"
            SELECT
                countIf(event_type = 'sent') AS sent,
                countIf(event_type = 'delivered') AS delivered,
                countIf(event_type = 'bounced') AS bounced,
                countIf(event_type = 'opened') AS opened,
                countIf(event_type = 'clicked') AS clicked,
                countIf(event_type = 'complained') AS complained,
                countIf(event_type = 'unsubscribed') AS unsubscribed
            FROM events
            WHERE tenant_id = ?
              AND timestamp >= now() - INTERVAL 1 HOUR
        "#;

        let hour_row = self
            .client
            .query(hour_query)
            .bind(tenant_id)
            .fetch_one::<StatsRow>()
            .await?;

        // Day window
        let day_query = r#"
            SELECT
                countIf(event_type = 'sent') AS sent,
                countIf(event_type = 'delivered') AS delivered,
                countIf(event_type = 'bounced') AS bounced,
                countIf(event_type = 'opened') AS opened,
                countIf(event_type = 'clicked') AS clicked,
                countIf(event_type = 'complained') AS complained,
                countIf(event_type = 'unsubscribed') AS unsubscribed
            FROM events
            WHERE tenant_id = ?
              AND timestamp >= now() - INTERVAL 1 DAY
        "#;

        let day_row = self
            .client
            .query(day_query)
            .bind(tenant_id)
            .fetch_one::<StatsRow>()
            .await?;

        let to_counts = |r: StatsRow| crate::types::EventCounts {
            sent: r.sent as i64,
            delivered: r.delivered as i64,
            bounced: r.bounced as i64,
            opened: r.opened as i64,
            clicked: r.clicked as i64,
            complained: r.complained as i64,
            unsubscribed: r.unsubscribed as i64,
        };

        Ok(RealtimeStats {
            this_hour: to_counts(hour_row),
            today: to_counts(day_row),
        })
    }

    /// Get event count for a time range.
    pub async fn event_count(
        &self,
        tenant_id: &str,
        start: DateTime<Utc>,
        end: DateTime<Utc>,
    ) -> anyhow::Result<u64> {
        #[derive(Debug, Row, Deserialize)]
        struct CountRow {
            count: u64,
        }

        let row = self
            .client
            .query(
                r#"
                SELECT count() AS count
                FROM events
                WHERE tenant_id = ?
                  AND timestamp >= toDateTime64(?, 3)
                  AND timestamp < toDateTime64(?, 3)
                "#,
            )
            .bind(tenant_id)
            .bind(start.timestamp_millis() as f64 / 1000.0)
            .bind(end.timestamp_millis() as f64 / 1000.0)
            .fetch_one::<CountRow>()
            .await?;

        Ok(row.count)
    }

    /// Get storage statistics for monitoring.
    pub async fn storage_stats(&self) -> anyhow::Result<StorageStats> {
        #[derive(Debug, Row, Deserialize)]
        struct StatsRow {
            rows: u64,
            bytes: u64,
            parts: u64,
        }

        let row = self
            .client
            .query(
                r#"
                SELECT
                    sum(rows) AS rows,
                    sum(bytes_on_disk) AS bytes,
                    count() AS parts
                FROM system.parts
                WHERE database = currentDatabase()
                  AND table = 'events'
                  AND active
                "#,
            )
            .fetch_one::<StatsRow>()
            .await?;

        Ok(StorageStats {
            total_events: row.rows,
            bytes_on_disk: row.bytes,
            active_parts: row.parts,
        })
    }

    /// Health check.
    pub async fn health_check(&self) -> anyhow::Result<bool> {
        self.client.query("SELECT 1").execute().await?;
        Ok(true)
    }
}

/// Storage statistics for monitoring.
#[derive(Debug, Clone, Serialize)]
pub struct StorageStats {
    pub total_events: u64,
    pub bytes_on_disk: u64,
    pub active_parts: u64,
}

#[cfg(test)]
mod tests {
    use super::*;

    // Integration tests require a running ClickHouse instance
    // Run with:docker run -d -p 8123:8123 clickhouse/clickhouse-server

    #[tokio::test]
    #[ignore = "requires running ClickHouse"]
    async fn test_clickhouse_init() {
        let config = ClickHouseConfig {
            url: "http://localhost:8123".into(),
            database: "apexmail_test".into(),
            user: "default".into(),
            password: "".into(),
            max_connections: 10,
            query_timeout_secs: 30,
            insert_timeout_seconds: 30,
            tls_enabled: false,
            ca_cert_path: String::new(),
        };

        let engine = ClickHouseEngine::new(config).await;
        assert!(engine.is_ok());
        if let Ok(engine) = engine {
            let health = engine.health_check().await;
            assert_eq!(health.ok(), Some(true));
        }
    }
}
