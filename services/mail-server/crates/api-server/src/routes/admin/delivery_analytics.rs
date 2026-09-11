//! Delivery analytics endpoint — transport breakdown, latency percentiles,
//! bounce/complaint rates by transport, and queue health monitoring.
//!
//! Metric conventions (single source of truth:
//! [`crate::analytics_metrics`]):
//!
//! * **One cohort/time convention**: event-OCCURRENCE timestamps. `sent`
//!   counts `events.event_type = 'sent'` (written after provider
//!   acceptance), never `messages.created_at`.
//! * **One rate unit**: every rate is a FRACTION in `0.0..=1.0`.
//! * Counts are DISTINCT message ids, so per-recipient copies of one message
//!   cannot inflate a bucket.
//!
//! Latency percentiles come from `email_delivery_log` (attempt-occurrence
//! timestamps); the queue block is an explicit CURRENT snapshot, not a
//! windowed metric — see [`DeliveryAnalyticsResponse::notes`].

use axum::extract::{Query, State};
use axum::routing::get;
use axum::{Json, Router};
use serde::{Deserialize, Serialize};

use crate::analytics_metrics::{detect_event_columns, distinct_message_counts, EventColumns};
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
    /// Fraction in `0.0..=1.0` (distinct delivered messages / distinct sent
    /// messages), over event-occurrence timestamps.
    pub delivery_rate: f64,
    /// Fraction in `0.0..=1.0`.
    pub bounce_rate: f64,
    /// Fraction in `0.0..=1.0`.
    pub complaint_rate: f64,
    /// DISTINCT messages with a successful `sent` event in the window.
    pub total_sent: i64,
    /// DISTINCT messages with a `delivered` event in the window.
    pub total_delivered: i64,
    /// DISTINCT messages with a `bounced` event in the window.
    pub total_bounced: i64,
    /// DISTINCT messages with a `complained` event in the window.
    pub total_complaints: i64,
    pub delivery_by_provider: Vec<ProviderDeliveryStats>,
    pub latency: LatencyStats,
    /// CURRENT queue backlog (snapshot), not restricted to the window.
    pub queue_depth: i64,
    /// Interpretation notes (cohort/rate conventions and the snapshot-only
    /// queue fields) so the UI can label the numbers honestly.
    pub notes: Vec<String>,
}

#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderDeliveryStats {
    /// Sending transport dimension (`ses` / `smtp` / `unknown`), read from
    /// `messages.transport` (migration 021/056). This is the outbound
    /// transport, not the recipient mailbox provider.
    pub provider: String,
    pub sent: i64,
    pub delivered: i64,
    pub bounced: i64,
    /// Fraction in `0.0..=1.0`.
    pub delivery_rate: f64,
    /// Fraction in `0.0..=1.0`.
    pub bounce_rate: f64,
    /// `None` — per-provider/transport latency is not derivable from the
    /// event-based breakdown. Real percentiles are served by `/latency`
    /// (from `email_delivery_log`), so this is explicitly absent instead of
    /// a placeholder zero.
    pub avg_latency_ms: Option<f64>,
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
    pub by_provider: Vec<TransportLatencyStats>,
}

/// Latency percentiles by SENDING TRANSPORT (`messages.transport`), the real
/// dimension recorded for each delivery attempt. (The previous code grouped
/// by `email_delivery_log.smtp_response` — the SMTP reply text, e.g.
/// "250 OK" — which is not a provider at all.)
#[derive(Debug, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct TransportLatencyStats {
    pub transport: String,
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
    pub notes: Vec<String>,
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
    /// Sends accepted in the last hour, expressed per second.
    pub throughput_per_second: f64,
}

#[derive(sqlx::FromRow)]
struct ProviderRow {
    provider: String,
    sent: i64,
    delivered: i64,
    bounced: i64,
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
    transport: String,
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

/// Interpretation notes shared by the delivery endpoints.
fn delivery_notes() -> Vec<String> {
    vec![
        "All rates are fractions in 0.0-1.0. Counts are DISTINCT messages bucketed by event-occurrence timestamps; 'sent' means a successful send event, not message creation."
            .to_string(),
        "Queue fields (queueDepth / /queue) are CURRENT snapshots, not windowed metrics.".to_string(),
    ]
}

/// Distinct-message sent/delivered/bounced per SENDING TRANSPORT, over
/// event-occurrence timestamps. `messages.transport` is the real transport
/// recorded at send time (migration 021:250-259); events are joined to the
/// message row by id.
async fn transport_breakdown(
    db: &sqlx::PgPool,
    interval: &str,
    columns: EventColumns,
) -> Result<Vec<ProviderDeliveryStats>, ApiError> {
    let type_col = columns.type_col.as_sql();
    let time_col = columns.time_col.as_sql();

    let rows = sqlx::query_as::<_, ProviderRow>(&format!(
        "SELECT
            COALESCE(NULLIF(m.transport, ''), 'unknown') as provider,
            COUNT(DISTINCT e.message_id) FILTER (WHERE e.{type_col} = 'sent')::bigint as sent,
            COUNT(DISTINCT e.message_id) FILTER (WHERE e.{type_col} = 'delivered')::bigint as delivered,
            COUNT(DISTINCT e.message_id) FILTER (WHERE e.{type_col} = 'bounced')::bigint as bounced
         FROM events e
         LEFT JOIN messages m ON m.id::text = e.message_id
         WHERE e.{time_col} >= NOW() - $1::interval
         GROUP BY 1
         ORDER BY sent DESC
         LIMIT 20"
    ))
    .bind(interval)
    .fetch_all(db)
    .await?;

    Ok(rows
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
            avg_latency_ms: None,
        })
        .collect())
}

async fn get_delivery_analytics(
    State(state): State<AppState>,
    auth: AuthUser,
    Query(params): Query<DeliveryQuery>,
) -> Result<Json<DeliveryAnalyticsResponse>, ApiError> {
    crate::middleware::auth::require_scopes(&auth, &["*"])?;

    let interval = parse_range_interval(&params.range);
    let db = &state.db;

    // One cohort convention: event occurrence. `sent` is a successful send
    // event and every count is DISTINCT messages.
    let columns = detect_event_columns(&state).await;
    let counts = distinct_message_counts(db, None, &interval, columns).await?;

    let delivery_by_provider = transport_breakdown(db, &interval, columns).await?;

    // Latency percentiles from email_delivery_log (attempt occurrence).
    let latency = compute_latency_percentiles(db, &interval).await;

    // Queue depth — CURRENT snapshot (documented in the response notes).
    let queue: Option<(i64,)> = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM email_queue
         WHERE status IN ('pending', 'processing', 'deferred')",
    )
    .fetch_optional(db)
    .await
    .ok()
    .flatten();

    Ok(Json(DeliveryAnalyticsResponse {
        delivery_rate: counts.delivery_rate(),
        bounce_rate: counts.bounce_rate(),
        complaint_rate: counts.complaint_rate(),
        total_sent: counts.sent,
        total_delivered: counts.delivered,
        total_bounced: counts.bounced,
        total_complaints: counts.complained,
        delivery_by_provider,
        latency,
        queue_depth: queue.map(|(c,)| c).unwrap_or(0),
        notes: delivery_notes(),
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

    // Per-transport latency: the dimension recorded at send time is
    // `messages.transport`, resolved through email_queue.message_id.
    let provider_latency = sqlx::query_as::<_, ProviderLatencyRow>(
        "WITH delivery_times AS (
            SELECT
                COALESCE(NULLIF(m.transport, ''), 'unknown') as transport,
                EXTRACT(EPOCH FROM (dl.attempted_at - eq.sent_at)) * 1000 as latency_ms
            FROM email_delivery_log dl
            JOIN email_queue eq ON eq.id = dl.email_id
            LEFT JOIN messages m ON m.id = eq.message_id
            WHERE dl.success = true
              AND eq.sent_at IS NOT NULL
              AND dl.attempted_at >= NOW() - $1::interval
        )
        SELECT
            transport,
            PERCENTILE_CONT(0.50) WITHIN GROUP (ORDER BY latency_ms) as p50,
            PERCENTILE_CONT(0.95) WITHIN GROUP (ORDER BY latency_ms) as p95,
            PERCENTILE_CONT(0.99) WITHIN GROUP (ORDER BY latency_ms) as p99,
            AVG(latency_ms) as avg,
            COUNT(*)::bigint as count
        FROM delivery_times
        GROUP BY transport
        ORDER BY count DESC
        LIMIT 20",
    )
    .bind(&interval)
    .fetch_all(db)
    .await
    .unwrap_or_default()
    .into_iter()
    .map(|r| TransportLatencyStats {
        transport: r.transport,
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
    let columns = detect_event_columns(&state).await;

    let providers = transport_breakdown(db, &interval, columns).await?;

    Ok(Json(ProviderBreakdownResponse {
        providers,
        notes: delivery_notes(),
    }))
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

    // Throughput: sends accepted in the last hour, expressed per second.
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
        throughput_per_second: throughput as f64 / 3600.0,
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
            avg_latency_ms: None,
        };
        assert_eq!(stats.delivery_rate, 0.0);
        assert_eq!(stats.bounce_rate, 0.0);
        // Per-transport latency is absent, never a placeholder zero.
        assert!(stats.avg_latency_ms.is_none());
    }

    #[test]
    fn rates_documented_as_fractions() {
        let notes = delivery_notes();
        assert!(
            notes.iter().any(|n| n.contains("fractions in 0.0-1.0")),
            "the response must document the rate unit: {notes:?}"
        );
    }

    /// Executes the real event-based transport breakdown against the
    /// canonical schema: two send copies of ONE message and one bounced
    /// event count once (distinct message), proving the SQL is valid and the
    /// cardinality convention holds. Gated on TEST_DATABASE_URL.
    #[tokio::test]
    async fn transport_breakdown_counts_distinct_messages_per_transport() {
        let Some(pool) = crate::test_db::canonical_pool("delivery_transport_distinct").await else {
            eprintln!(
                "skipping transport_breakdown_counts_distinct_messages_per_transport: no TEST_DATABASE_URL"
            );
            return;
        };

        let suffix = uuid::Uuid::new_v4().simple().to_string();
        let tenant = format!("t{}", &suffix[..25]);
        let message_id = uuid::Uuid::new_v4();

        // messages.tenant_id has an FK to tenants.
        sqlx::query("INSERT INTO tenants (id, name) VALUES ($1, 'delivery-transport-test')")
            .bind(&tenant)
            .execute(&pool)
            .await
            .expect("seed tenant");

        sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, status, transport)
             VALUES ($1, $2, 'a@apex.example', '[]'::jsonb, 's', 'sent', 'ses')",
        )
        .bind(message_id)
        .bind(&tenant)
        .execute(&pool)
        .await
        .expect("seed message");

        // Two per-recipient send copies + one delivered + two bounces, all
        // for the SAME message.
        for (event_type, occurrences) in [("sent", 2), ("delivered", 1), ("bounced", 2)] {
            for _ in 0..occurrences {
                sqlx::query(
                    "INSERT INTO events (id, tenant_id, message_id, event_type, timestamp)
                     VALUES ($1, $2, $3, $4, NOW())",
                )
                .bind(format!("evt-{}", uuid::Uuid::new_v4().simple()))
                .bind(&tenant)
                .bind(message_id.to_string())
                .bind(event_type)
                .execute(&pool)
                .await
                .expect("seed event");
            }
        }

        let rows = transport_breakdown(&pool, "30 days", EventColumns::default())
            .await
            .expect("transport breakdown query must execute");

        let ses = rows
            .iter()
            .find(|r| r.provider == "ses")
            .expect("transport dimension must be the message's transport");
        assert_eq!(ses.sent, 1, "two send copies of one message count once");
        assert_eq!(ses.delivered, 1);
        assert_eq!(
            ses.bounced, 1,
            "two bounce events on one message count once"
        );
        assert!(ses.delivery_rate <= 1.0);
        assert!(ses.bounce_rate <= 1.0);
        assert!(ses.avg_latency_ms.is_none(), "no placeholder latency");

        pool.close().await;
    }
}
