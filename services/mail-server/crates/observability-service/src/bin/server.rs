//! Observability service binary entry-point.

use std::net::SocketAddr;
use std::sync::atomic::{AtomicBool, Ordering};
use std::sync::Arc;
use std::time::Duration;

use deadpool_redis::{Config as RedisConfig, Runtime};
use observability_service::alerting::AlertManager;
use observability_service::config::ObservabilityConfig;
use observability_service::log_aggregator::LogAggregator;
use observability_service::metrics_collector::MetricsCollector;
use observability_service::redis_monitor::{RedisKeyMonitor, DEFAULT_POLL_INTERVAL_SECS};
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
        redis_host = %config.redis_host,
        redis_port = config.redis_port,
        "Starting observability service"
    );

    // ── Redis connection pool ──────────────────────────────────────────

    let redis_url = format!("redis://{}:{}", config.redis_host, config.redis_port);
    let redis_cfg = RedisConfig::from_url(&redis_url);
    let redis_pool = match redis_cfg.create_pool(Some(Runtime::Tokio1)) {
        Ok(pool) => Arc::new(pool),
        Err(err) => {
            tracing::error!(error = %err, redis_url = %redis_url, "failed to create Redis pool");
            return;
        }
    };

    // ── Redis key eviction monitor ─────────────────────────────────────

    let eviction_monitor = Arc::new(RedisKeyMonitor::new(None)); // uses default threshold of 100 keys/min
    let shutdown_flag = Arc::new(AtomicBool::new(false));

    // Spawn periodic Redis eviction check task
    let monitor_pool = redis_pool.clone();
    let monitor_clone = eviction_monitor.clone();
    let flag_clone = shutdown_flag.clone();
    tokio::spawn(async move {
        tracing::info!(
            poll_interval_secs = DEFAULT_POLL_INTERVAL_SECS,
            eviction_threshold = monitor_clone.eviction_rate_threshold(),
            "Redis key eviction monitor task started",
        );

        while !flag_clone.load(Ordering::Acquire) {
            tokio::select! {
                _ = tokio::time::sleep(Duration::from_secs(DEFAULT_POLL_INTERVAL_SECS)) => {
                    if flag_clone.load(Ordering::Acquire) {
                        break;
                    }
                    monitor_clone.check_evictions(&monitor_pool).await;
                }
            }
        }

        tracing::info!("Redis key eviction monitor task shut down");
    });

    // ── Core state ─────────────────────────────────────────────────────

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

    let shutdown = {
        let flag = shutdown_flag.clone();
        async move {
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
                _ = ctrl_c => {
                    tracing::info!("received Ctrl+C — shutting down");
                    flag.store(true, Ordering::Release);
                }
                _ = terminate => {
                    tracing::info!("received SIGTERM — shutting down");
                    flag.store(true, Ordering::Release);
                }
            }
        }
    };
    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        tracing::error!(error = %err, "server error");
    }
}
