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
            tracing_subscriber::EnvFilter::try_from_default_env().unwrap_or_else(|_| "info".into()),
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
        config.internal_service_token.clone(),
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

    let shutdown = async {
        let ctrl_c = async {
            let _ = tokio::signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let terminate = async {
            tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
                .expect("failed to install SIGTERM handler")
                .recv()
                .await;
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::select! {
            _ = ctrl_c => tracing::info!("received Ctrl+C — shutting down"),
            _ = terminate => tracing::info!("received SIGTERM — shutting down"),
        }
    };
    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        tracing::error!(error = %err, "server error");
    }
}
