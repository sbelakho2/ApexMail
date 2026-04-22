//! Prometheus metrics middleware for the API server.
//!
//! Records per-request latency and counts using the `metrics` crate,
//! which are exported via `metrics-exporter-prometheus` (installed in
//! `server.rs` at startup).
//!
//! ## Metrics Emitted
//!
//! | Metric | Type | Labels |
//! |---------------------------------------|-----------|-------------------------------|
//! | `apexmail_http_request_duration_seconds` | Histogram | method, path_pattern, status |
//! | `apexmail_http_requests_total` | Counter | method, path_pattern, status |
//! | `apexmail_http_requests_in_flight` | Gauge | method |

use axum::extract::MatchedPath;
use axum::http::Request;
use axum::middleware::Next;
use axum::response::Response;
use std::time::Instant;

/// Axum middleware:records request duration and counts as Prometheus metrics.
/// Must be placed *after* the router so that `MatchedPath` is available in
/// request extensions (axum populates it when a route matches).
/// Injects via `axum::middleware::from_fn(metrics_middleware)`.
pub async fn metrics_middleware(
    req: Request<axum::body::Body>,
    next: Next,
) -> Response {
    let method = req.method().clone().to_string();

// Prefer the matched pattern ("/v1/messages/:id") over the raw URI
// to avoid high-cardinality label explosion.
    let path_pattern = req
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| req.uri().path().to_owned());

// In-flight gauge
    metrics::gauge!("apexmail_http_requests_in_flight", "method" => method.clone())
        .increment(1.0);

    let start = Instant::now();
    let response = next.run(req).await;
    let duration = start.elapsed();

    let status = response.status().as_u16().to_string();

// Decrement in-flight
    metrics::gauge!("apexmail_http_requests_in_flight", "method" => method.clone())
        .decrement(1.0);

// Request count
    metrics::counter!(
        "apexmail_http_requests_total",
        "method" => method.clone(),
        "path_pattern" => path_pattern.clone(),
        "status" => status.clone(),
    )
    .increment(1);

// Duration histogram
    metrics::histogram!(
        "apexmail_http_request_duration_seconds",
        "method" => method,
        "path_pattern" => path_pattern,
        "status" => status,
    )
    .record(duration.as_secs_f64());

    response
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    async fn ok_handler() -> &'static str {
        "ok"
    }

    #[tokio::test]
    async fn metrics_middleware_records_without_panic() {
// Install a noop recorder so metrics macros don't panic in tests
        let _ = metrics_exporter_prometheus::PrometheusBuilder::new()
            .install_recorder();

        let app = Router::new()
            .route("/test", get(ok_handler))
            .layer(middleware::from_fn(metrics_middleware));

        let request = Request::builder()
            .uri("/test")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn metrics_middleware_handles_unmatched_paths() {
// Ensure 404s don't blow up the middleware
        let app = Router::new()
            .route("/test", get(ok_handler))
            .layer(middleware::from_fn(metrics_middleware));

        let request = Request::builder()
            .uri("/nonexistent")
            .body(Body::empty())
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }
}
