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
use metrics_exporter_prometheus::{Matcher, PrometheusBuilder};
use std::time::Instant;

/// Histogram buckets (seconds) for the request-duration series.
///
/// `metrics-exporter-prometheus` renders histograms as Prometheus SUMMARIES
/// unless an explicit bucket distribution is configured: without this, the
/// exported series had no `_bucket` samples while `deploy/alerting-rules.yml`
/// and every `deploy/grafana/dashboards/api-performance.json` latency panel
/// query `..._bucket` with `histogram_quantile()` — all of them were
/// mathematically dead (empty result, no alert could fire; dogfood
/// 2026-10-08). The rack spans sub-millisecond health probes up to the
/// 30s query timeout.
pub const REQUEST_DURATION_BUCKETS: &[f64] = &[
    0.001, 0.0025, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0, 30.0,
];

/// Apply the histogram bucket configuration to a Prometheus recorder
/// builder. `bin/server.rs` must route its builder through this so the
/// live process exports `apexmail_http_request_duration_seconds_bucket`
/// (pinned by a test that reads `bin/server.rs`).
pub fn configure_request_duration_buckets(builder: PrometheusBuilder) -> PrometheusBuilder {
    builder
        .set_buckets_for_metric(
            Matcher::Full("apexmail_http_request_duration_seconds".to_string()),
            REQUEST_DURATION_BUCKETS,
        )
        .expect("static request-duration buckets are a valid, non-empty distribution")
}

/// Axum middleware:records request duration and counts as Prometheus metrics.
/// Must be placed *after* the router so that `MatchedPath` is available in
/// request extensions (axum populates it when a route matches).
/// Injects via `axum::middleware::from_fn(metrics_middleware)`.
pub async fn metrics_middleware(req: Request<axum::body::Body>, next: Next) -> Response {
    let method = req.method().clone().to_string();

    // Prefer the matched pattern ("/v1/messages/:id") over the raw URI
    // to avoid high-cardinality label explosion. When no route matched
    // (404s, odd probes) fall back to a single literal label instead of
    // the raw request path, which is attacker-controlled cardinality.
    let path_pattern = req
        .extensions()
        .get::<MatchedPath>()
        .map(|mp| mp.as_str().to_owned())
        .unwrap_or_else(|| "unmatched".to_owned());

    // In-flight gauge
    metrics::gauge!("apexmail_http_requests_in_flight", "method" => method.clone()).increment(1.0);

    let start = Instant::now();
    let response = next.run(req).await;
    let duration = start.elapsed();

    let status = response.status().as_u16().to_string();

    // Decrement in-flight
    metrics::gauge!("apexmail_http_requests_in_flight", "method" => method.clone()).decrement(1.0);

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
        let _ = metrics_exporter_prometheus::PrometheusBuilder::new().install_recorder();

        let app = Router::new()
            .route("/test", get(ok_handler))
            .layer(middleware::from_fn(metrics_middleware));

        let request = Request::builder().uri("/test").body(Body::empty()).unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::OK);
    }

    /// The exported series must be a Prometheus HISTOGRAM (with `_bucket`
    /// samples), not the exporter's default summary. Every latency alert and
    /// Grafana panel uses `histogram_quantile(..._bucket)`; a summary makes
    /// them silently dead.
    #[test]
    fn request_duration_is_exported_as_a_histogram_with_buckets() {
        let recorder =
            configure_request_duration_buckets(PrometheusBuilder::new()).build_recorder();
        let handle = recorder.handle();
        metrics::with_local_recorder(&recorder, || {
            metrics::histogram!(
                "apexmail_http_request_duration_seconds",
                "method" => "GET",
                "path_pattern" => "/v1/messages",
                "status" => "200",
            )
            .record(0.05);
        });
        let rendered = handle.render();
        assert!(
            rendered.contains("# TYPE apexmail_http_request_duration_seconds histogram"),
            "duration series must be a histogram, rendered:\n{rendered}"
        );
        assert!(
            rendered.contains("apexmail_http_request_duration_seconds_bucket"),
            "histogram_quantile() needs `_bucket` samples; none were rendered:\n{rendered}"
        );
        assert!(
            rendered.contains("le=\"0.05\""),
            "the configured buckets must be exported (le labels):\n{rendered}"
        );
    }

    /// Production wiring pin: `bin/server.rs` must install the recorder
    /// through [`configure_request_duration_buckets`]. Reading the source is
    /// deliberate — the defect was exactly "the test exercised the metric
    /// facade while the binary installed an unconfigured recorder".
    #[test]
    fn server_binary_configures_the_request_duration_buckets() {
        let source = include_str!("../bin/server.rs");
        assert!(
            source.contains("configure_request_duration_buckets"),
            "bin/server.rs must route PrometheusBuilder through \
             configure_request_duration_buckets (otherwise the latency series \
             degrades to a summary and every _bucket alert dies)"
        );
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
