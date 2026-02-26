//! Observability service binary entry-point.

use std::net::SocketAddr;
use std::sync::Arc;

use observability_service::alerting::AlertManager;
use observability_service::config::ObservabilityConfig;
use observability_service::log_aggregator::LogAggregator;
use observability_service::metrics_collector::MetricsCollector;
use observability_service::routes::{self, AppState};
use observability_service::slo::SloMonitor;
use observability_service::trace_collector::TraceCollector;

#[tokio::main]
async fn main() {
    // Initialise tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "info".into()),
        )
        .json()
        .init();

    let config = match ObservabilityConfig::from_env() {
        Ok(config) => config,
        Err(err) => {
            tracing::error!(error = %err, "Invalid observability configuration");
            return;
        }
    };

    tracing::info!(
        port = config.port,
        env = %config.environment,
        "Starting observability service"
    );

    let default_buckets = config.metrics.histogram_buckets.clone();

    let state = AppState::new(
        Arc::new(MetricsCollector::new(default_buckets)),
        Arc::new(TraceCollector::new()),
        Arc::new(LogAggregator::new()),
        Arc::new(AlertManager::new()),
        Arc::new(SloMonitor::new()),
    );

    let app = routes::router(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    tracing::info!(%addr, "Listening");

    let listener = match tokio::net::TcpListener::bind(addr).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, %addr, "failed to bind listener");
            return;
        }
    };

    if let Err(err) = axum::serve(listener, app).await {
        tracing::error!(error = %err, "server error");
    }
}
