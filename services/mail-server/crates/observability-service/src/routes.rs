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
        .route("/logs", get(logs_query))
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

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertmanagerWebhook {
    alerts: Vec<AlertmanagerAlert>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct AlertmanagerAlert {
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
        [(header::CONTENT_TYPE, HeaderValue::from_static(
            "text/plain; version=0.0.4; charset=utf-8",
        ))],
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

async fn alerts_list(State(state): State<AppState>) -> Json<Vec<Alert>> {
    Json(state.alerts.list_active_alerts())
}

async fn alerts_ingest(
    State(state): State<AppState>,
    Json(payload): Json<AlertmanagerWebhook>,
) -> StatusCode {
    let alerts = payload
        .alerts
        .into_iter()
        .map(alertmanager_alert_to_domain_alert)
        .collect();
    state.alerts.ingest_external_alerts(alerts);
    StatusCode::ACCEPTED
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
                let pong: String =
                    redis::cmd("PING").query_async(&mut conn).await.unwrap_or_default();
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
        state.metrics.record_counter("http_total", 10.0, "HTTP total");
        state.metrics.record_gauge("active_conns", 5.0, "Active connections");

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
    async fn test_alertmanager_webhook_rejects_unknown_fields() {
        let app = router(test_state());
        let payload = json!({
            "alerts": [
                {
                    "status": "firing",
                    "labels": { "alertname": "SchemaAlert" },
                    "annotations": { "summary": "Schema validation" },
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

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNPROCESSABLE_ENTITY);
    }
}
