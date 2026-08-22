use metrics_exporter_prometheus::PrometheusBuilder;
use std::sync::Arc;
use tokio::signal;
use tracing::info;

use enterprise::config::Config;
use enterprise::routes::{router, AppState};
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present
    dotenvy::dotenv().ok();

    // Initialize tracing (with OTLP support)
    let _tracing_guard = init_tracing();

    // Load configuration
    let config =
        Config::from_env().map_err(|err| anyhow::anyhow!("Invalid enterprise config: {err}"))?;
    if let Err(err) = config.validate() {
        return Err(anyhow::anyhow!("Invalid enterprise config: {err}"));
    }
    let bind_addr = format!("{}:{}", config.host, config.port);
    info!(host = %config.host, port = config.port, "Starting enterprise service");

    // Connect to PostgreSQL
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(config.db.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect_lazy(&config.db.url())
        .map_err(|e| anyhow::anyhow!("Database pool: {e}"))?;

    // Install an in-process Prometheus recorder. The router renders the
    // resulting handle at `/metrics` on the existing enterprise HTTP port.
    let metrics_recorder = PrometheusBuilder::new().build_recorder();
    let metrics_handle = metrics_recorder.handle();
    if let Err(error) = metrics::set_global_recorder(Box::new(metrics_recorder)) {
        tracing::warn!(error = %error, "Prometheus recorder already installed");
    }
    metrics::gauge!("apexmail_enterprise_info").set(1.0);

    // Build app state
    let state = Arc::new(AppState::new(db.clone(), config, metrics_handle));

    // Build router
    let app = router(state.clone());

    // Spawn background jobs
    spawn_background_jobs(state.clone(), db.clone());

    // Start server
    let listener = tokio::net::TcpListener::bind(&bind_addr).await?;
    info!(addr = %bind_addr, "Enterprise server listening");

    // ConnectInfo is required by the audit-log identity derivation (fix C:
    // peer IP) and the /metrics loopback check (fix H-3).
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<std::net::SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    info!("Enterprise server shutdown complete");
    Ok(())
}

/// Spawn background jobs for enterprise features
fn spawn_background_jobs(state: Arc<AppState>, db: sqlx::PgPool) {
    // Job 0:QBR sending-metrics rollup — aggregates yesterday's events into
    // ent_sending_metrics daily so generated QBRs carry real numbers (the
    // hourly cadence catches up after downtime; the rollup is idempotent).
    let qbr_db = db.clone();
    tokio::spawn(async move {
        let service = enterprise::qbr::QBRService::new(qbr_db);
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            let yesterday = chrono::Utc::now().date_naive() - chrono::Duration::days(1);
            if let Err(e) = service.rollup_daily_sending_metrics(yesterday).await {
                tracing::error!(error = %e, day = %yesterday, "QBR metrics rollup failed");
            }
        }
    });

    // Job 1:Check SLA breaches every 60 seconds
    let sla_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(60));
        loop {
            interval.tick().await;
            match sla_state.support.check_sla_breaches().await {
                Ok(breaches) if !breaches.is_empty() => {
                    info!(count = breaches.len(), "SLA breaches detected");
                }
                Err(e) => tracing::error!(error = %e, "SLA breach check failed"),
                _ => {}
            }
        }
    });

    // Job 2:Auto-escalate tickets every 5 minutes
    let escalate_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(300));
        loop {
            interval.tick().await;
            match escalate_state.support.auto_escalate().await {
                Ok(count) if count > 0 => {
                    info!(escalated = count, "Auto-escalated tickets");
                }
                Err(e) => tracing::error!(error = %e, "Auto-escalation failed"),
                _ => {}
            }
        }
    });

    // Job 3:Cleanup expired SSO sessions every hour
    let session_state = state.clone();
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(tokio::time::Duration::from_secs(3600));
        loop {
            interval.tick().await;
            match session_state.sso.cleanup_expired_sessions().await {
                Ok(count) if count > 0 => {
                    info!(cleaned = count, "Expired SSO sessions cleaned");
                }
                Err(e) => tracing::error!(error = %e, "Session cleanup failed"),
                _ => {}
            }
        }
    });

    // Job 4:Log-stream delivery loop (fix H-1). Periodically pulls the
    // active streams and delivers a bounded heartbeat batch to each
    // verified destination via the SSRF-guarded, address-pinned client.
    // Best-effort: failures are recorded per stream and retried next cycle.
    let delivery_state = state.clone();
    let flush_interval = std::time::Duration::from_millis(
        delivery_state.config.log_stream.flush_interval_ms.max(1_000),
    );
    tokio::spawn(async move {
        let mut interval = tokio::time::interval(flush_interval);
        loop {
            interval.tick().await;
            match delivery_state.log_streaming.run_delivery_cycle().await {
                Ok(delivered) if delivered > 0 => {
                    info!(delivered = delivered, "Log-stream heartbeat deliveries completed");
                }
                Ok(_) => {}
                Err(e) => tracing::error!(error = %e, "Log-stream delivery cycle failed"),
            }
        }
    });

    info!("Background jobs started: SLA check (60s), auto-escalation (5m), session cleanup (1h), log-stream delivery (flush interval)");
}

/// Wait for Ctrl+C or SIGTERM for graceful shutdown
async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            tracing::error!(?error, "Failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                tracing::error!(?error, "Failed to install signal handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => { info!("Received Ctrl+C, shutting down"); }
        _ = terminate => { info!("Received SIGTERM, shutting down"); }
    }
}

/// Initialize tracing subscriber with OTLP support.
/// Falls back to JSON logging when OTLP is not configured.
fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "enterprise-server".into(),
            service_version: option_env!("CARGO_PKG_VERSION").map(str::to_string),
            environment: std::env::var("APP_ENV").ok(),
            ..Default::default()
        };

        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(error) => tracing::error!("failed to initialize OTLP tracing: {error}"),
        }
    }

    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info")),
        )
        .json()
        .init();
    None
}
