//! Axum HTTP routes for the observability service.
//!
//! Exposes metrics summaries, traces, logs, alerts, SLOs, and a health
//! endpoint via a shared [`AppState`].

use std::collections::HashMap;
use std::sync::Arc;
use std::time::Duration;

use axum::{
    extract::{DefaultBodyLimit, Query, State},
    http::{header, header::AUTHORIZATION, HeaderValue, StatusCode},
    middleware::{self, Next},
    response::{IntoResponse, Response},
    routing::get,
    Json, Router,
};
use chrono::{DateTime, Utc};
use deadpool_redis::Pool as RedisPool;
use metrics_exporter_prometheus::PrometheusHandle;
use serde::{Deserialize, Serialize};
use tower_http::timeout::TimeoutLayer;
use uuid::Uuid;

use crate::alerting::AlertManager;
use crate::log_aggregator::LogAggregator;
use crate::metrics_collector::MetricsCollector;
use crate::slo::SloMonitor;
use crate::trace_collector::TraceCollector;
use crate::types::{Alert, LogLevel};

// ---------------------------------------------------------------------------
// Shared application state
// ---------------------------------------------------------------------------

/// Shared state injected into all route handlers.
#[derive(Clone)]
pub struct AppState {
    pub metrics: Arc<MetricsCollector>,
    pub traces: Arc<TraceCollector>,
    pub logs: Arc<LogAggregator>,
    pub alerts: Arc<AlertManager>,
    pub slos: Arc<SloMonitor>,
    pub service_token: String,
    pub redis_pool: Option<Arc<RedisPool>>,
    pub metrics_handle: Option<PrometheusHandle>,
    /// Optional Postgres pool. When attached, ingested alertmanager alerts
    /// are ALSO persisted into the `system_alerts` table so the control
    /// plane's SSE alert stream, dashboard risk counts, and system-health
    /// surfaces see them (previously nothing ever wrote that table).
    pub db_pool: Option<sqlx::PgPool>,
}

impl AppState {
    pub fn new(
        metrics: Arc<MetricsCollector>,
        traces: Arc<TraceCollector>,
        logs: Arc<LogAggregator>,
        alerts: Arc<AlertManager>,
        slos: Arc<SloMonitor>,
        service_token: String,
    ) -> Self {
        Self {
            metrics,
            traces,
            logs,
            alerts,
            slos,
            service_token,
            redis_pool: None,
            metrics_handle: None,
            db_pool: None,
        }
    }

    /// Attach the Redis connection pool used for dependency health checks.
    pub fn with_redis_pool(mut self, pool: Arc<RedisPool>) -> Self {
        self.redis_pool = Some(pool);
        self
    }

    /// Attach the Prometheus recorder handle for the `/metrics` endpoint.
    pub fn with_metrics_handle(mut self, handle: PrometheusHandle) -> Self {
        self.metrics_handle = Some(handle);
        self
    }

    /// Attach the Postgres pool used to persist alerts into `system_alerts`.
    pub fn with_db_pool(mut self, pool: sqlx::PgPool) -> Self {
        self.db_pool = Some(pool);
        self
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the observability HTTP router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/health", get(health))
        .route("/health/details", get(health_details))
        .route("/metrics", get(metrics))
        .route("/metrics/summary", get(metrics_summary))
        .route("/traces", get(traces_list))
        .route("/logs", get(logs_query).post(logs_ingest))
        .route("/alerts", get(alerts_list).post(alerts_ingest))
        .route("/slos", get(slos_list))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_service_token,
        ))
        .with_state(state)
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024)) // 2 MB
        .layer(TimeoutLayer::new(Duration::from_secs(30)))
}

// ---------------------------------------------------------------------------
// Auth middleware
// ---------------------------------------------------------------------------

async fn require_service_token(
    State(state): State<AppState>,
    req: axum::http::Request<axum::body::Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Liveness probe and Prometheus scrape endpoints are intentionally
    // unauthenticated: the service is only reachable on the internal Docker
    // networks, and Prometheus does not carry a service token.
    let path = req.uri().path();
    if path == "/health" || path == "/metrics" {
        return Ok(next.run(req).await);
    }
    if state.service_token.is_empty() {
        return Err(StatusCode::UNAUTHORIZED);
    }
    let provided = req
        .headers()
        .get("x-api-key")
        .and_then(|v| v.to_str().ok().map(String::from))
        .or_else(|| {
            req.headers()
                .get(AUTHORIZATION)
                .and_then(|v| v.to_str().ok())
                .and_then(|raw| raw.trim().strip_prefix("Bearer ").map(String::from))
        });
    if provided
        .as_deref()
        .is_some_and(|p| apexmail_lib::timing_safe_compare(p, &state.service_token))
    {
        Ok(next.run(req).await)
    } else {
        Err(StatusCode::UNAUTHORIZED)
    }
}

// ---------------------------------------------------------------------------
// Query parameter structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct TracesQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct LogsQuery {
    level: Option<String>,
    service: Option<String>,
    limit: Option<usize>,
}

/// Alertmanager webhook envelope.
///
/// No `deny_unknown_fields`: real Alertmanager payloads carry additional
/// envelope fields (receiver, groupLabels, commonLabels, commonAnnotations,
/// externalURL, version, truncatedAlerts, …) that must not 422 the ingest.
#[derive(Debug, Deserialize)]
struct AlertmanagerWebhook {
    #[serde(default)]
    alerts: Vec<AlertmanagerAlert>,
}

/// A single Alertmanager alert.
///
/// No `deny_unknown_fields`: beyond the fields we consume, alerts carry
/// generatorURL, valueString and future Alertmanager additions. Unknown
/// fields are ignored so upgrades of Alertmanager never break ingestion.
#[derive(Debug, Deserialize)]
struct AlertmanagerAlert {
    #[serde(default = "default_alert_status")]
    status: String,
    #[serde(default)]
    labels: HashMap<String, String>,
    #[serde(default)]
    annotations: HashMap<String, String>,
    #[serde(rename = "startsAt")]
    starts_at: Option<DateTime<Utc>>,
    #[serde(rename = "endsAt")]
    ends_at: Option<DateTime<Utc>>,
    fingerprint: Option<String>,
    // Commonly-present Alertmanager fields we accept but do not consume;
    // declared so the accepted schema is documented and stays deserializable.
    #[serde(rename = "generatorURL", default)]
    #[allow(dead_code)]
    generator_url: Option<String>,
    #[serde(rename = "valueString", default)]
    #[allow(dead_code)]
    value_string: Option<String>,
}

fn default_alert_status() -> String {
    "firing".to_string()
}

/// Maximum log entries accepted by one POST /logs ingest call.
const MAX_LOG_INGEST_BATCH: usize = 1_000;

/// Maximum stored characters per ingested log message (mirrors the default
/// `logging.max_message_length`; longer messages arrive truncated).
const MAX_LOG_INGEST_MESSAGE_CHARS: usize = 10_000;

/// A single structured log line submitted to POST /logs by an internal
/// service.
///
/// No `deny_unknown_fields`: internal producers may carry extra fields;
/// unknown ones are ignored so producer evolution never breaks ingestion.
/// The level vocabulary is validated server-side — an unknown level rejects
/// the whole batch rather than silently dropping entries.
#[derive(Debug, Deserialize)]
struct LogIngestEntry {
    level: String,
    message: String,
    #[serde(default)]
    service: Option<String>,
    #[serde(default)]
    trace_id: Option<String>,
    #[serde(default)]
    span_id: Option<String>,
    #[serde(default)]
    context: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    metadata: Option<HashMap<String, serde_json::Value>>,
    #[serde(default)]
    duration_ms: Option<i64>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
}

#[derive(Debug, Serialize)]
struct DetailedHealthResponse {
    status: String,
    uptime_secs: u64,
    metrics_count: usize,
    traces_count: usize,
    logs_count: usize,
    active_alerts: usize,
    slos_defined: usize,
    redis_connected: bool,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Prometheus text exposition endpoint.
///
/// Renders the global `metrics` crate registry (Redis monitor gauges) plus
/// the in-memory [`MetricsCollector`] (self-monitoring gauges, counters,
/// histograms). Unauthenticated — Prometheus scrapes it on the internal
/// monitoring network.
async fn metrics(State(state): State<AppState>) -> impl IntoResponse {
    let mut body = String::new();
    if let Some(handle) = &state.metrics_handle {
        body.push_str(&handle.render());
        body.push('\n');
    }
    body.push_str(&state.metrics.export_prometheus());

    (
        StatusCode::OK,
        [(
            header::CONTENT_TYPE,
            HeaderValue::from_static("text/plain; version=0.0.4; charset=utf-8"),
        )],
        body,
    )
}

async fn metrics_summary(
    State(state): State<AppState>,
) -> Json<Vec<crate::metrics_collector::MetricSummary>> {
    Json(state.metrics.get_summary())
}

async fn traces_list(
    State(state): State<AppState>,
    Query(params): Query<TracesQuery>,
) -> Json<Vec<crate::types::TraceSpan>> {
    let limit = clamp_limit(params.limit.unwrap_or(100), 1000);
    Json(state.traces.list_recent(limit))
}

async fn logs_query(
    State(state): State<AppState>,
    Query(params): Query<LogsQuery>,
) -> Json<Vec<crate::types::LogEntry>> {
    let level_filter = params.level.as_deref().and_then(parse_log_level);
    let limit = clamp_limit(params.limit.unwrap_or(200), 1000);
    Json(
        state
            .logs
            .query(level_filter, params.service.as_deref(), limit),
    )
}

/// POST /logs — ingest structured log lines from internal services.
///
/// This is the producer for the `observability_log_error_rate` metric and
/// therefore for the `high_log_error_rate` Critical alert rule: without an
/// ingest path the aggregator stays empty, the gauge is permanently 0.0,
/// and the rule can never fire. Token-authenticated like every other
/// protected route (the same internal-service-token callers already use
/// for POST /alerts).
async fn logs_ingest(
    State(state): State<AppState>,
    Json(entries): Json<Vec<LogIngestEntry>>,
) -> Response {
    if entries.is_empty() {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({ "error": "log batch must not be empty" })),
        )
            .into_response();
    }
    if entries.len() > MAX_LOG_INGEST_BATCH {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({
                "error": format!("log batch exceeds {MAX_LOG_INGEST_BATCH} entries")
            })),
        )
            .into_response();
    }

    let mut parsed = Vec::with_capacity(entries.len());
    for entry in entries {
        let level = match parse_log_level(&entry.level) {
            Some(level) => level,
            None => {
                return (
                    StatusCode::BAD_REQUEST,
                    Json(serde_json::json!({
                        "error": format!("unknown log level: {:?}", entry.level)
                    })),
                )
                    .into_response()
            }
        };
        let service = entry
            .service
            .unwrap_or_else(|| "unknown".to_string());
        let message = truncate_chars(&entry.message, MAX_LOG_INGEST_MESSAGE_CHARS);
        parsed.push(crate::types::LogEntry {
            id: Uuid::new_v4(),
            timestamp: Utc::now(),
            level,
            message,
            service,
            trace_id: entry.trace_id,
            span_id: entry.span_id,
            context: entry.context,
            error_info: None,
            duration_ms: entry.duration_ms,
            metadata: entry.metadata,
        });
    }

    let count = parsed.len();
    for entry in parsed {
        state.logs.ingest(entry);
    }
    (
        StatusCode::ACCEPTED,
        Json(serde_json::json!({ "accepted": count })),
    )
        .into_response()
}

/// Truncate `text` to at most `max_chars` characters (char-boundary safe).
fn truncate_chars(text: &str, max_chars: usize) -> String {
    if text.chars().count() <= max_chars {
        text.to_string()
    } else {
        text.chars().take(max_chars).collect()
    }
}

async fn alerts_list(State(state): State<AppState>) -> Json<Vec<Alert>> {
    Json(state.alerts.list_active_alerts())
}

async fn alerts_ingest(
    State(state): State<AppState>,
    Json(payload): Json<AlertmanagerWebhook>,
) -> StatusCode {
    // Persist firing/resolved alerts into system_alerts so the control
    // plane surfaces (CP SSE alert stream, dashboard risk counts,
    // system-health alerts) observe alertmanager traffic. Best-effort: a
    // persistence failure never breaks the in-memory ingest.
    persist_alerts_to_system_alerts(&state.db_pool, &payload.alerts).await;

    let alerts = payload
        .alerts
        .into_iter()
        .map(alertmanager_alert_to_domain_alert)
        .collect();
    state.alerts.ingest_external_alerts(alerts);
    StatusCode::ACCEPTED
}

/// Map an alertmanager severity label onto system_alerts' CHECK-constrained
/// values ('info' | 'warning' | 'critical'). Unknown labels degrade to
/// 'info' rather than violating the constraint.
fn system_alerts_severity(labels: &HashMap<String, String>) -> &'static str {
    match labels.get("severity").map(String::as_str) {
        Some("critical") => "critical",
        Some("warning") | Some("page") => "warning",
        _ => "info",
    }
}

/// Persist ingested alertmanager alerts into the shared `system_alerts`
/// table (columns added in migration 108: component / source /
/// fingerprint). Firing alerts are inserted idempotently (unique on
/// (source, fingerprint)); resolved alerts acknowledge their row so they
/// stop counting toward unacknowledged risk in the CP dashboard.
async fn persist_alerts_to_system_alerts(
    pool: &Option<sqlx::PgPool>,
    alerts: &[AlertmanagerAlert],
) {
    let Some(db) = pool else {
        // No pool configured — the CP surfaces stay empty, logged once per
        // ingest so operators notice the missing DATABASE_URL wiring.
        tracing::debug!("no database pool attached — skipping system_alerts persistence");
        return;
    };

    for alert in alerts {
        let rule_name = alert
            .labels
            .get("alertname")
            .cloned()
            .unwrap_or_else(|| "alertmanager".to_string());
        let message = alert
            .annotations
            .get("summary")
            .or_else(|| alert.annotations.get("description"))
            .cloned()
            .unwrap_or_else(|| rule_name.clone());
        let component = alert
            .labels
            .get("component")
            .or_else(|| alert.labels.get("job"))
            .cloned();
        let severity = system_alerts_severity(&alert.labels);
        // The unique index requires a non-NULL fingerprint for external
        // sources; fall back to a hash-free stable value when Alertmanager
        // omitted one (rare, but the column must not be NULL for dedup).
        let fingerprint = alert
            .fingerprint
            .clone()
            .unwrap_or_else(|| format!("{rule_name}:{}", component.clone().unwrap_or_default()));

        let result = if alert.status == "resolved" {
            sqlx::query(
                "UPDATE system_alerts
                 SET acknowledged = true, acknowledged_at = NOW()
                 WHERE source = 'alertmanager' AND fingerprint = $1 AND acknowledged = false",
            )
            .bind(&fingerprint)
            .execute(db)
            .await
        } else {
            sqlx::query(
                "INSERT INTO system_alerts
                    (alert_type, message, severity, component, source, fingerprint)
                 VALUES ($1, $2, $3, $4, 'alertmanager', $5)
                 ON CONFLICT DO NOTHING",
            )
            .bind(&rule_name)
            .bind(&message)
            .bind(severity)
            .bind(&component)
            .bind(&fingerprint)
            .execute(db)
            .await
        };

        if let Err(error) = result {
            tracing::warn!(
                error = %error,
                alert = %rule_name,
                "failed to persist alert into system_alerts"
            );
        }
    }
}

async fn slos_list(State(state): State<AppState>) -> Json<Vec<crate::slo::SloComplianceResult>> {
    // Return targets as-is (compliance requires request counts, so here we
    // just list defined SLOs as zero-traffic compliance snapshots).
    let targets = state.slos.list_slos();
    let results: Vec<_> = targets
        .iter()
        .filter_map(|t| state.slos.check_compliance(&t.name, 0, 0))
        .collect();
    Json(results)
}

async fn health() -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
    })
}

async fn health_details(State(state): State<AppState>) -> Json<DetailedHealthResponse> {
    let redis_connected = match &state.redis_pool {
        Some(pool) => check_redis(pool).await,
        None => false,
    };

    let (status, redis_connected) = match &state.redis_pool {
        Some(_) if !redis_connected => ("degraded".to_string(), false),
        _ => ("ok".to_string(), redis_connected),
    };

    Json(DetailedHealthResponse {
        status,
        uptime_secs: state.metrics.uptime_secs(),
        metrics_count: state.metrics.get_summary().len(),
        traces_count: state.traces.len(),
        logs_count: state.logs.len(),
        active_alerts: state.alerts.list_active_alerts().len(),
        slos_defined: state.slos.list_slos().len(),
        redis_connected,
    })
}

/// Probe the Redis pool with a `PING`, bounded by a 2s timeout.
async fn check_redis(pool: &RedisPool) -> bool {
    let result = tokio::time::timeout(Duration::from_secs(2), async {
        match pool.get().await {
            Ok(mut conn) => {
                let pong: String = redis::cmd("PING")
                    .query_async(&mut conn)
                    .await
                    .unwrap_or_default();
                pong
            }
            Err(err) => {
                tracing::warn!(error = %err, "redis health check: pool acquire failed");
                String::new()
            }
        }
    })
    .await;

    match result {
        Ok(pong) => pong == "PONG",
        Err(_) => {
            tracing::warn!("redis health check timed out");
            false
        }
    }
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

fn clamp_limit(limit: usize, max: usize) -> usize {
    limit.clamp(1, max)
}

fn parse_log_level(s: &str) -> Option<LogLevel> {
    match s.to_lowercase().as_str() {
        "trace" => Some(LogLevel::Trace),
        "debug" => Some(LogLevel::Debug),
        "info" => Some(LogLevel::Info),
        "warn" | "warning" => Some(LogLevel::Warn),
        "error" => Some(LogLevel::Error),
        "fatal" => Some(LogLevel::Fatal),
        _ => None,
    }
}

fn alertmanager_alert_to_domain_alert(alert: AlertmanagerAlert) -> Alert {
    let status = parse_alert_status(&alert.status);
    let fingerprint = alert
        .fingerprint
        .unwrap_or_else(|| Uuid::new_v4().to_string());
    let rule_name = alert
        .labels
        .get("alertname")
        .cloned()
        .unwrap_or_else(|| "alertmanager".to_string());
    let summary = alert
        .annotations
        .get("summary")
        .cloned()
        .unwrap_or_else(|| rule_name.clone());
    let description = alert
        .annotations
        .get("description")
        .cloned()
        .unwrap_or_else(|| summary.clone());
    let fired_at = alert.starts_at.unwrap_or_else(Utc::now);
    let resolved_at = if status == crate::types::AlertStatus::Resolved {
        Some(alert.ends_at.unwrap_or_else(Utc::now))
    } else {
        None
    };

    Alert {
        id: fingerprint.clone(),
        rule_id: fingerprint,
        rule_name,
        status,
        severity: parse_alert_severity(alert.labels.get("severity").map(String::as_str)),
        summary,
        description,
        labels: alert.labels,
        annotations: alert.annotations,
        value: 0.0,
        threshold: 0.0,
        fired_at,
        resolved_at,
        acknowledged_at: None,
        acknowledged_by: None,
        silenced_until: None,
        notifications_sent: 1,
        last_notification_at: Some(Utc::now()),
    }
}

fn parse_alert_status(status: &str) -> crate::types::AlertStatus {
    match status.to_ascii_lowercase().as_str() {
        "resolved" => crate::types::AlertStatus::Resolved,
        "pending" => crate::types::AlertStatus::Pending,
        "acknowledged" => crate::types::AlertStatus::Acknowledged,
        "silenced" => crate::types::AlertStatus::Silenced,
        _ => crate::types::AlertStatus::Firing,
    }
}

fn parse_alert_severity(severity: Option<&str>) -> crate::types::AlertSeverity {
    match severity.unwrap_or("warning").to_ascii_lowercase().as_str() {
        "info" => crate::types::AlertSeverity::Info,
        "critical" => crate::types::AlertSeverity::Critical,
        "emergency" => crate::types::AlertSeverity::Emergency,
        _ => crate::types::AlertSeverity::Warning,
    }
}

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use serde_json::json;
    use tower::ServiceExt; // for `oneshot`

    fn test_state() -> AppState {
        AppState::new(
            Arc::new(MetricsCollector::new(vec![0.1, 0.5, 1.0])),
            Arc::new(TraceCollector::new()),
            Arc::new(LogAggregator::new()),
            Arc::new(AlertManager::new()),
            Arc::new(SloMonitor::new()),
            "test-token".to_string(),
        )
    }

    #[tokio::test]
    async fn test_health_endpoint() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/health")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert!(json.get("uptime_secs").is_none());
    }

    #[tokio::test]
    async fn test_health_details_endpoint_requires_service_token() {
        let app = router(test_state());
        let req = Request::builder()
            .uri("/health/details")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_health_details_endpoint() {
        let state = test_state();
        let app = router(state);
        let req = Request::builder()
            .uri("/health/details")
            .header("x-api-key", "test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert_eq!(json["status"], "ok");
        assert!(json["uptime_secs"].is_number());
    }

    #[tokio::test]
    async fn test_metrics_endpoint_is_public_and_text_exposition() {
        let state = test_state();
        state
            .metrics
            .record_counter("http_total", 10.0, "HTTP total");
        state
            .metrics
            .record_gauge("active_conns", 5.0, "Active connections");

        let app = router(state);
        let req = Request::builder()
            .uri("/metrics")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        assert_eq!(
            resp.headers()["content-type"],
            "text/plain; version=0.0.4; charset=utf-8"
        );

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let text = String::from_utf8(body.to_vec()).unwrap();
        assert!(text.contains("# TYPE http_total counter"));
        assert!(text.contains("http_total 10"));
        assert!(text.contains("# TYPE active_conns gauge"));
        assert!(text.contains("active_conns 5"));
    }

    #[tokio::test]
    async fn test_metrics_summary_endpoint() {
        let state = test_state();
        state
            .metrics
            .record_counter("req_total", 5.0, "total requests");

        let app = router(state);
        let req = Request::builder()
            .uri("/metrics/summary")
            .header("x-api-key", "test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["name"], "req_total");
    }

    #[tokio::test]
    async fn test_slos_endpoint() {
        let state = test_state();
        state.slos.define_slo("uptime", 99.9, 30);

        let app = router(state);
        let req = Request::builder()
            .uri("/slos")
            .header("x-api-key", "test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["name"], "uptime");
        assert!(json[0]["compliant"].as_bool().unwrap());
        // Zero observed traffic → compliance percentage is unknown (null),
        // never an implied 100%.
        assert!(json[0]["current_pct"].is_null());
    }

    #[tokio::test]
    async fn test_alertmanager_webhook_ingest_endpoint() {
        let app = router(test_state());
        let payload = json!({
            "alerts": [
                {
                    "status": "firing",
                    "labels": {
                        "alertname": "TrackingServiceDown",
                        "severity": "critical"
                    },
                    "annotations": {
                        "summary": "Tracking service is down",
                        "description": "Tracking service has been unreachable for more than 1 minute"
                    },
                    "startsAt": "2026-04-27T10:00:00Z",
                    "fingerprint": "tracking-service-down"
                }
            ]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/alerts")
            .header("x-api-key", "test-token")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let req = Request::builder()
            .uri("/alerts")
            .header("x-api-key", "test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["rule_name"], "TrackingServiceDown");
        assert_eq!(json[0]["severity"], "critical");
    }

    #[tokio::test]
    async fn test_alertmanager_webhook_requires_service_token() {
        let app = router(test_state());
        let payload = json!({
            "alerts": [
                {
                    "status": "firing",
                    "labels": { "alertname": "UnauthorizedAlert" },
                    "annotations": { "summary": "Unauthorized" }
                }
            ]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/alerts")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_alertmanager_webhook_accepts_unknown_fields() {
        // Real Alertmanager payloads include envelope fields (receiver,
        // version, externalURL, groupLabels, …) and per-alert fields we do
        // not consume (generatorURL, valueString, unexpected). Ingestion
        // must accept them instead of answering 422.
        let state = test_state();
        let app = router(state.clone());
        let payload = json!({
            "receiver": "apexmail-observability",
            "status": "firing",
            "externalURL": "https://alertmanager.example",
            "version": "0.27.0",
            "groupLabels": { "alertname": "SchemaAlert", "service": "tracking" },
            "commonLabels": { "alertname": "SchemaAlert" },
            "commonAnnotations": { "summary": "Schema validation" },
            "truncatedAlerts": 0,
            "alerts": [
                {
                    "status": "firing",
                    "labels": { "alertname": "SchemaAlert" },
                    "annotations": { "summary": "Schema validation" },
                    "startsAt": "2026-04-27T10:00:00.123456789Z",
                    "endsAt": "0001-01-01T00:00:00Z",
                    "generatorURL": "https://prometheus.example/graph",
                    "valueString": "42.5",
                    "fingerprint": "schema-alert-1",
                    "unexpected": "value"
                }
            ]
        });

        let req = Request::builder()
            .method("POST")
            .uri("/alerts")
            .header("x-api-key", "test-token")
            .header("content-type", "application/json")
            .body(Body::from(payload.to_string()))
            .unwrap();

        let resp = app.clone().oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        let req = Request::builder()
            .uri("/alerts")
            .header("x-api-key", "test-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["rule_name"], "SchemaAlert");
    }
    #[test]
    fn system_alerts_severity_maps_to_check_constraint_values() {
        let mut labels = HashMap::new();
        labels.insert("severity".to_string(), "critical".to_string());
        assert_eq!(system_alerts_severity(&labels), "critical");

        labels.insert("severity".to_string(), "warning".to_string());
        assert_eq!(system_alerts_severity(&labels), "warning");

        // Unknown labels degrade to 'info' — the column CHECK only allows
        // info/warning/critical.
        labels.insert("severity".to_string(), "catastrophic".to_string());
        assert_eq!(system_alerts_severity(&labels), "info");

        let empty: HashMap<String, String> = HashMap::new();
        assert_eq!(system_alerts_severity(&empty), "info");
    }

    #[tokio::test]
    async fn persist_alerts_without_pool_is_a_no_op_not_an_error() {
        // No DB pool attached (deployment without DATABASE wiring) — the
        // ingest path must still succeed for every alert.
        let alert = AlertmanagerAlert {
            status: "firing".into(),
            labels: HashMap::from([
                ("alertname".to_string(), "NoPool".to_string()),
                ("severity".to_string(), "critical".to_string()),
            ]),
            annotations: HashMap::from([("summary".to_string(), "no pool".to_string())]),
            starts_at: None,
            ends_at: None,
            fingerprint: Some("no-pool-1".into()),
            generator_url: None,
            value_string: None,
        };

        persist_alerts_to_system_alerts(&None, &[alert]).await;
    }

    // ── POST /logs ingest (producer for high_log_error_rate) ──────────

    fn log_ingest_request(body: serde_json::Value, token: bool) -> Request<Body> {
        let mut builder = Request::builder()
            .method("POST")
            .uri("/logs")
            .header("content-type", "application/json");
        if token {
            builder = builder.header("x-api-key", "test-token");
        }
        builder.body(Body::from(body.to_string())).unwrap()
    }

    #[tokio::test]
    async fn log_ingest_feeds_the_aggregator_and_the_error_rate_metric() {
        // Regression: nothing ever called LogAggregator::ingest, so the
        // observability_log_error_rate gauge was permanently 0.0 and the
        // high_log_error_rate Critical rule could never fire.
        let state = test_state();
        let app = router(state.clone());
        let payload = json!([
            { "level": "info", "service": "api", "message": "request handled" },
            { "level": "info", "service": "api", "message": "request handled" },
            { "level": "error", "service": "api", "message": "db timeout" },
            { "level": "warn", "service": "worker", "message": "slow job",
              "trace_id": "abc", "duration_ms": 1200, "unexpected": "ignored" }
        ]);

        let resp = app
            .clone()
            .oneshot(log_ingest_request(payload, true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::ACCEPTED);

        // The stored entries feed the error-rate window the alert metric
        // reads: one Error entry among four ⇒ 0.25.
        let rate = state.logs.get_error_rate(60);
        assert!(
            (rate - 0.25).abs() < 1e-9,
            "one error among four entries ⇒ 0.25, got {rate}"
        );

        // And the query surface sees them.
        let req = Request::builder()
            .uri("/logs?level=error")
            .header("x-api-key", "test-token")
            .body(Body::empty())
            .unwrap();
        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
        let body = axum::body::to_bytes(resp.into_body(), usize::MAX)
            .await
            .unwrap();
        let json: Vec<serde_json::Value> = serde_json::from_slice(&body).unwrap();
        assert_eq!(json.len(), 1);
        assert_eq!(json[0]["message"], "db timeout");
    }

    #[tokio::test]
    async fn log_ingest_requires_the_service_token() {
        let app = router(test_state());
        let resp = app
            .oneshot(log_ingest_request(json!([{ "level": "info", "message": "x" }]), false))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn log_ingest_rejects_empty_oversized_and_unknown_level_batches() {
        let app = router(test_state());

        let resp = app
            .clone()
            .oneshot(log_ingest_request(json!([]), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let oversize: Vec<serde_json::Value> = (0..=MAX_LOG_INGEST_BATCH)
            .map(|i| json!({ "level": "info", "message": format!("entry {i}") }))
            .collect();
        let resp = app
            .clone()
            .oneshot(log_ingest_request(json!(oversize), true))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);

        let resp = app
            .oneshot(log_ingest_request(
                json!([{ "level": "loud", "message": "x" }]),
                true,
            ))
            .await
            .unwrap();
        assert_eq!(resp.status(), StatusCode::BAD_REQUEST);
    }

    #[test]
    fn truncate_chars_is_char_boundary_safe() {
        assert_eq!(truncate_chars("hello", 10), "hello");
        let cjk = "你好世界";
        assert_eq!(truncate_chars(cjk, 2), "你好");
        assert_eq!(truncate_chars("é€", 1), "é");
    }
}
