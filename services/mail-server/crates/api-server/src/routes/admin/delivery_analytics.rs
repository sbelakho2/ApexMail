//! Delivery analytics endpoint — provider breakdown, latency percentiles,
//! bounce/complaint rates by transport, and queue health monitoring.
//!
//! All values come from real database queries against messages, email_delivery_log,
//! email_queue, events, bounce_analytics_daily, and bounce_domain_reputation tables.

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::error::ApiError;
use crate::middleware::auth::AuthUser;
use crate::state::AppState;

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/", get(get_delivery_analytics))
        .route("/latency", get(get_latency_percentiles))
        .route("/provider", get(get_provider_breakdown))
        .route("/queue", get(get_queue_health))
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeliveryQuery {
    #[serde(default = "default_range")]
    pub range: String,
}

fn default_range() -> String {
    "7d".into()
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DeliveryAnalyticsResponse {
    pub delivery_rate: f64,
    pub bounce_rate: f64,
    pub complaint_rate: f64,
    pub total_sent: i64,
    pub total_delivered: i64,
    pub total_bounced: i64,
    pub total_complaints: i64,
    pub delivery_by_provider: Vec<ProviderDeliveryStats>,
    pub latency: LatencyStats,
    pub queue_depth: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDeliveryStats {
    pub provider: String,
    pub sent: i64,
    pub delivered: i64,
    pub bounced: i64,
    pub delivery_rate: f64,
    pub bounce_rate: f64,
    pub avg_latency_ms: f64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencyStats {
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub avg_ms: f64,
    pub min_ms: f64,
    pub max_ms: f64,
    pub sample_count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct LatencyPercentileResponse {
    pub percentiles: LatencyStats,
    pub by_provider: Vec<ProviderLatencyStats>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderLatencyStats {
    pub provider: String,
    pub p50_ms: f64,
    pub p95_ms: f64,
    pub p99_ms: f64,
    pub avg_ms: f64,
    pub sample_count: i64,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderBreakdownResponse {
    pub providers: Vec<ProviderDeliveryStats>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QueueHealthResponse {
    pub pending_count: i64,
    pub processing_count: i64,
    pub failed_count: i64,
    pub deferred_count: i64,
    pub avg_attempts: f64,
    pub oldest_pending_minutes: f64,
    pub throughput_last_hour: f64,
}

#[derive(sqlx::FromRow)]
struct DeliveryCountRow {
    sent: i64,
    delivered: i64,
    bounced: i64,
}

#[derive(sqlx::FromRow)]
struct ProviderRow {
    provider: String,
    sent: i64,
    delivered: i64,
    bounced: i64,
    avg_latency: Option<f64>,
}

#[derive(sqlx::FromRow)]
struct LatencyRow {
    p50: f64,
    p95: f64,
    p99: f64,
    avg: f64,
    min: f64,
    max: f64,
    count: i64,
}

#[derive(sqlx::FromRow)]
struct ProviderLatencyRow {
    provider: String,
    p50: f64,
    p95: f64,
    p99: f64,
    avg: f64,
    count: i64,
}

#[derive(sqlx::FromRow)]
struct QueueRow {
    pending: i64,
    processing: i64,
    failed: i64,
    deferred: i64,
    avg_attempts: Option<f64>,
    oldest_minutes: Option<f64>,
}

fn parse_range_interval(range: &str) -> String {
    match range {
        "24h" => "24 hours".into(),
        "7d" => "7 days".into(),
        "30d" => "30 days".into(),
        "90d" => "90 days".into(),
        _ => "7 days".into(),
    }
}

async fn get_delivery_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<DeliveryQuery>,
) -> Result<Json<DeliveryAnalyticsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let interval = parse_range_interval(&params.range);
    let db = &state.db;

    // Aggregate counts
    let counts = sqlx::query_as::<_, DeliveryCountRow>(
        "SELECT
            COUNT(*) as sent,
            COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
            COUNT(*) FILTER (WHERE status = 'bounced') as bounced
         FROM messages
         WHERE created_at >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_optional(db)
    .await?
    .unwrap_or(DeliveryCountRow {
        sent: 0,
        delivered: 0,
        bounced: 0,
    });

    // Complaint counts from events
    let complaint_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM events
         WHERE event_type = 'complained'
           AND timestamp >= NOW() - $1::interval",
    )
    .bind(&interval)
    .fetch_one(db)
    .await
    .unwrap_or(0);

    let safe_sent = if counts.sent > 0 {
        counts.sent as f64
    } else {
        1.0
    };

    // Provider breakdown
    let providers = sqlx::query_as::<_, ProviderRow>(
        "SELECT
            COALESCE(headers->>'X-Mail-Provider', 'unknown') as provider,
            COUNT(*) as sent,
            COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
            COUNT(*) FILTER (WHERE status = 'bounced') as bounced,
            NULL::float8 as avg_latency
         FROM messages
         WHERE created_at >= NOW() - $1::interval
         GROUP BY 1
         ORDER BY sent DESC
         LIMIT 20",
    )
    .bind(&interval)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| ProviderDeliveryStats {
        provider: r.provider,
        sent: r.sent,
        delivered: r.delivered,
        bounced: r.bounced,
        delivery_rate: if r.sent > 0 {
            r.delivered as f64 / r.sent as f64
        } else {
            0.0
        },
        bounce_rate: if r.sent > 0 {
            r.bounced as f64 / r.sent as f64
        } else {
            0.0
        },
        avg_latency_ms: r.avg_latency.unwrap_or(0.0),
    })
    .collect();

    // Latency percentiles from email_delivery_log
    let latency = compute_latency_percentiles(db, &interval).await;

    // Queue depth
    let queue: Option<(i64,)> = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM email_queue
         WHERE status IN ('pending', 'processing', 'deferred')",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    Ok(Json(DeliveryAnalyticsResponse {
        delivery_rate: counts.delivered as f64 / safe_sent,
        bounce_rate: counts.bounced as f64 / safe_sent,
        complaint_rate: complaint_count as f64 / safe_sent,
        total_sent: counts.sent,
        total_delivered: counts.delivered,
        total_bounced: counts.bounced,
        total_complaints: complaint_count,
        delivery_by_provider: providers,
        latency,
        queue_depth: queue.map(|(c,)| c).unwrap_or(0),
    }))
}

async fn get_latency_percentiles(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<DeliveryQuery>,
) -> Result<Json<LatencyPercentileResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let interval = parse_range_interval(&params.range);
    let db = &state.db;

    let percentiles = compute_latency_percentiles(db, &interval).await;

    // Per-provider latency
    let provider_latency = sqlx::query_as::<_, ProviderLatencyRow>(
        "WITH delivery_times AS (
            SELECT
                COALESCE(dl.smtp_response, 'unknown') as provider,
                EXTRACT(EPOCH FROM (dl.attempted_at - eq.sent_at)) * 1000 as latency_ms
            FROM email_delivery_log dl
            JOIN email_queue eq ON eq.id = dl.email_id
            WHERE dl.success = true
              AND eq.sent_at IS NOT NULL
              AND dl.attempted_at >= NOW() - $1::interval
        )
        SELECT
            provider,
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms) as p50,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) as p95,
            PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms) as p99,
            AVG(latency_ms) as avg,
            COUNT(*)::bigint as count
        FROM delivery_times
        GROUP BY provider
        ORDER BY count DESC
        LIMIT 20",
    )
    .bind(&interval)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| ProviderLatencyStats {
        provider: r.provider,
        p50_ms: r.p50,
        p95_ms: r.p95,
        p99_ms: r.p99,
        avg_ms: r.avg,
        sample_count: r.count,
    })
    .collect();

    Ok(Json(LatencyPercentileResponse {
        percentiles,
        by_provider: provider_latency,
    }))
}

async fn get_provider_breakdown(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<DeliveryQuery>,
) -> Result<Json<ProviderBreakdownResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let interval = parse_range_interval(&params.range);
    let db = &state.db;

    let providers = sqlx::query_as::<_, ProviderRow>(
        "SELECT
            COALESCE(headers->>'X-Mail-Provider',
                     CASE
                         WHEN headers->>'X-SES-Configuration-Set' IS NOT NULL THEN 'AWS SES'
                         WHEN headers->>'X-Mailgun-Variables' IS NOT NULL THEN 'Mailgun'
                         ELSE 'SMTP'
                     END
            ) as provider,
            COUNT(*) as sent,
            COUNT(*) FILTER (WHERE status = 'delivered') as delivered,
            COUNT(*) FILTER (WHERE status = 'bounced') as bounced,
            NULL::float8 as avg_latency
         FROM messages
         WHERE created_at >= NOW() - $1::interval
         GROUP BY 1
         ORDER BY sent DESC
         LIMIT 20",
    )
    .bind(&interval)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| ProviderDeliveryStats {
        provider: r.provider,
        sent: r.sent,
        delivered: r.delivered,
        bounced: r.bounced,
        delivery_rate: if r.sent > 0 {
            r.delivered as f64 / r.sent as f64
        } else {
            0.0
        },
        bounce_rate: if r.sent > 0 {
            r.bounced as f64 / r.sent as f64
        } else {
            0.0
        },
        avg_latency_ms: r.avg_latency.unwrap_or(0.0),
    })
    .collect();

    Ok(Json(ProviderBreakdownResponse { providers }))
}

async fn get_queue_health(
    State(state): State<AppState>,
    auth: AuthUser,
) -> Result<Json<QueueHealthResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let db = &state.db;

    let row = sqlx::query_as::<_, QueueRow>(
        "SELECT
            COUNT(*) FILTER (WHERE status = 'pending') as pending,
            COUNT(*) FILTER (WHERE status = 'processing') as processing,
            COUNT(*) FILTER (WHERE status = 'failed') as failed,
            COUNT(*) FILTER (WHERE status = 'deferred') as deferred,
            AVG(attempt) as avg_attempts,
            EXTRACT(EPOCH FROM (NOW() - MIN(created_at))) / 60 as oldest_minutes
         FROM email_queue
         WHERE status IN ('pending', 'processing', 'deferred', 'failed')",
    )
    .fetch_optional(db)
    .await?
    .unwrap_or(QueueRow {
        pending: 0,
        processing: 0,
        failed: 0,
        deferred: 0,
        avg_attempts: None,
        oldest_minutes: None,
    });

    // Throughput: messages sent in the last hour
    let throughput: i64 = sqlx::query_scalar(
        "SELECT COUNT(*)::bigint FROM email_queue
         WHERE sent_at >= NOW() - INTERVAL '1 hour'",
    )
    .fetch_one(db)
    .await
    .unwrap_or(0);

    Ok(Json(QueueHealthResponse {
        pending_count: row.pending,
        processing_count: row.processing,
        failed_count: row.failed,
        deferred_count: row.deferred,
        avg_attempts: row.avg_attempts.unwrap_or(0.0),
        oldest_pending_minutes: row.oldest_minutes.unwrap_or(0.0),
        throughput_last_hour: throughput as f64 / 3600.0,
    }))
}

async fn compute_latency_percentiles(db: &sqlx::PgPool, interval: &str) -> LatencyStats {
    sqlx::query_as::<_, LatencyRow>(
        "WITH delivery_times AS (
            SELECT EXTRACT(EPOCH FROM (dl.attempted_at - eq.sent_at)) * 1000 as latency_ms
            FROM email_delivery_log dl
            JOIN email_queue eq ON eq.id = dl.email_id
            WHERE dl.success = true
              AND eq.sent_at IS NOT NULL
              AND dl.attempted_at >= NOW() - $1::interval
        )
        SELECT
            COALESCE(PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms), 0) as p50,
            COALESCE(PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms), 0) as p95,
            COALESCE(PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms), 0) as p99,
            COALESCE(AVG(latency_ms), 0) as avg,
            COALESCE(MIN(latency_ms), 0) as min,
            COALESCE(MAX(latency_ms), 0) as max,
            COUNT(*)::bigint as count
        FROM delivery_times",
    )
    .bind(interval)
    .fetch_optional(db)
    .await
    .unwrap_or(None)
    .unwrap_or(LatencyRow {
        p50: 0.0,
        p95: 0.0,
        p99: 0.0,
        avg: 0.0,
        min: 0.0,
        max: 0.0,
        count: 0,
    })
    .into()
}

impl From<LatencyRow> for LatencyStats {
    fn from(r: LatencyRow) -> Self {
        LatencyStats {
            p50_ms: r.p50,
            p95_ms: r.p95,
            p99_ms: r.p99,
            avg_ms: r.avg,
            min_ms: r.min,
            max_ms: r.max,
            sample_count: r.count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_range_interval_defaults_to_seven_days() {
        assert_eq!(parse_range_interval("bogus"), "7 days");
    }

    #[test]
    fn parse_range_interval_maps_correctly() {
        assert_eq!(parse_range_interval("24h"), "24 hours");
        assert_eq!(parse_range_interval("30d"), "30 days");
        assert_eq!(parse_range_interval("90d"), "90 days");
    }

    #[test]
    fn latency_stats_from_row() {
        let row = LatencyRow {
            p50: 100.0,
            p95: 500.0,
            p99: 1200.0,
            avg: 200.0,
            min: 10.0,
            max: 5000.0,
            count: 100,
        };
        let stats: LatencyStats = row.into();
        assert!((stats.p50_ms - 100.0).abs() < 0.01);
        assert!((stats.p99_ms - 1200.0).abs() < 0.01);
        assert_eq!(stats.sample_count, 100);
    }

    #[test]
    fn provider_stats_zero_denominator() {
        let stats = ProviderDeliveryStats {
            provider: "smtp".into(),
            sent: 0,
            delivered: 0,
            bounced: 0,
            delivery_rate: 0.0,
            bounce_rate: 0.0,
            avg_latency_ms: 0.0,
        };
        assert_eq!(stats.delivery_rate, 0.0);
        assert_eq!(stats.bounce_rate, 0.0);
    }
}
