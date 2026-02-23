//! Axum HTTP routes for the observability service.
//!
//! Exposes metrics summaries, traces, logs, alerts, SLOs, and a health
//! endpoint via a shared [`AppState`].

use std::sync::Arc;

use axum::{
    extract::{Query, State},
    routing::get,
    Json, Router,
};
use serde::{Deserialize, Serialize};

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
}

impl AppState {
    pub fn new(
        metrics: Arc<MetricsCollector>,
        traces: Arc<TraceCollector>,
        logs: Arc<LogAggregator>,
        alerts: Arc<AlertManager>,
        slos: Arc<SloMonitor>,
    ) -> Self {
        Self {
            metrics,
            traces,
            logs,
            alerts,
            slos,
        }
    }
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the observability HTTP router.
pub fn router(state: AppState) -> Router {
    Router::new()
        .route("/metrics/summary", get(metrics_summary))
        .route("/traces", get(traces_list))
        .route("/logs", get(logs_query))
        .route("/alerts", get(alerts_list))
        .route("/slos", get(slos_list))
        .route("/health", get(health))
        .with_state(state)
}

// ---------------------------------------------------------------------------
// Query parameter structs
// ---------------------------------------------------------------------------

#[derive(Debug, Deserialize)]
struct TracesQuery {
    limit: Option<usize>,
}

#[derive(Debug, Deserialize)]
struct LogsQuery {
    level: Option<String>,
    service: Option<String>,
    limit: Option<usize>,
}

// ---------------------------------------------------------------------------
// Response types
// ---------------------------------------------------------------------------

#[derive(Debug, Serialize)]
struct HealthResponse {
    status: String,
    uptime_secs: u64,
    metrics_count: usize,
    traces_count: usize,
    logs_count: usize,
    active_alerts: usize,
    slos_defined: usize,
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

async fn metrics_summary(
    State(state): State<AppState>,
) -> Json<Vec<crate::metrics_collector::MetricSummary>> {
    Json(state.metrics.get_summary())
}

async fn traces_list(
    State(state): State<AppState>,
    Query(params): Query<TracesQuery>,
) -> Json<Vec<crate::types::TraceSpan>> {
    let limit = params.limit.unwrap_or(100);
    Json(state.traces.list_recent(limit))
}

async fn logs_query(
    State(state): State<AppState>,
    Query(params): Query<LogsQuery>,
) -> Json<Vec<crate::types::LogEntry>> {
    let level_filter = params.level.as_deref().and_then(parse_log_level);
    let limit = params.limit.unwrap_or(200);
    Json(state.logs.query(level_filter, params.service.as_deref(), limit))
}

async fn alerts_list(State(state): State<AppState>) -> Json<Vec<Alert>> {
    Json(state.alerts.list_active_alerts())
}

async fn slos_list(
    State(state): State<AppState>,
) -> Json<Vec<crate::slo::SloComplianceResult>> {
    // Return targets as-is (compliance requires request counts, so here we
    // just list defined SLOs as zero-traffic compliance snapshots).
    let targets = state.slos.list_slos();
    let results: Vec<_> = targets
        .iter()
        .filter_map(|t| state.slos.check_compliance(&t.name, 0, 0))
        .collect();
    Json(results)
}

async fn health(State(state): State<AppState>) -> Json<HealthResponse> {
    Json(HealthResponse {
        status: "ok".to_string(),
        uptime_secs: state.metrics.uptime_secs(),
        metrics_count: state.metrics.get_summary().len(),
        traces_count: state.traces.len(),
        logs_count: state.logs.len(),
        active_alerts: state.alerts.list_active_alerts().len(),
        slos_defined: state.slos.list_slos().len(),
    })
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

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

// ===========================================================================
// Tests
// ===========================================================================

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt; // for `oneshot`

    fn test_state() -> AppState {
        AppState::new(
            Arc::new(MetricsCollector::new(vec![0.1, 0.5, 1.0])),
            Arc::new(TraceCollector::new()),
            Arc::new(LogAggregator::new()),
            Arc::new(AlertManager::new()),
            Arc::new(SloMonitor::new()),
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
        assert!(json["uptime_secs"].is_number());
    }

    #[tokio::test]
    async fn test_metrics_summary_endpoint() {
        let state = test_state();
        state.metrics.record_counter("req_total", 5.0, "total requests");

        let app = router(state);
        let req = Request::builder()
            .uri("/metrics/summary")
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
}
