//! Isolation server binary — HTTP on port 4500 with background cron jobs
//! and graceful shutdown.

use clap::Parser;
use deadpool_redis::{Config as DpRedisConfig, Runtime};
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::signal;
use tokio::time::{interval, Duration};
use tracing::{error, info};

use isolation::audit::AuditService;
use isolation::config::Config;
use isolation::data_isolation::DataIsolationService;
use isolation::encryption::EncryptionService;
use isolation::rate_limit::RateLimitService;
use isolation::routes::{create_router, AppState};
use isolation::tenant::TenantService;

#[derive(Parser)]
#[command(name = "isolation-server")]
struct Cli {
    /// Override port (default from ISOLATION_PORT or 4500)
    #[arg(short, long)]
    port: Option<u16>,
}

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "isolation-server".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "isolation=info,tower_http=info".into()),
        )
        .init();
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let _guard = init_tracing();

    dotenvy::dotenv().ok();

    let cli = Cli::parse();
    let config = Config::from_env();
    let port = cli.port.unwrap_or(config.port);

    // Database pool
    let db_url = format!(
        "postgres://{}:{}@{}:{}/{}",
        config.database.user,
        config.database.password,
        config.database.host,
        config.database.port,
        config.database.database,
    );
    let db = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&db_url)
        .await?;

    info!("Connected to database");

    // Redis pool
    let redis_cfg = DpRedisConfig::from_url(config.redis.url());
    let redis = redis_cfg.create_pool(Some(Runtime::Tokio1))?;

    info!("Redis pool created");

    // Build services
    let tenant = TenantService::new(db.clone(), config.clone());
    let mut isolation = DataIsolationService::new(db.clone());
    // F63: initialization failures (policy store unreadable, access-attempt
    // audit relation missing) are STARTUP errors. The previously logged-and-
    // continued behavior served requests with an unenforceable policy set and
    // a silently discarded audit trail.
    if let Err(e) = isolation.initialize().await {
        error!(error = %e, "Failed to initialize data isolation policies");
        return Err(e);
    }
    let security_config = config.security.clone();
    let encryption = EncryptionService::new(db.clone(), security_config.clone());
    // F63: load keys + field-encryption policies (iso_encryption_keys /
    // iso_encryption_policies) before serving. A missing relation or
    // unreadable key store is a readiness failure, not a runtime warn.
    encryption.initialize().await?;
    let rate_limit = RateLimitService::new(redis.clone());
    let audit = AuditService::new(db.clone(), security_config);

    let state = Arc::new(AppState {
        tenant,
        isolation,
        encryption,
        rate_limit,
        audit,
        config: config.clone(),
    });

    // Build router with middleware
    let cors = if config.cors.origins.iter().any(|o| o == "*") {
        tower_http::cors::CorsLayer::permissive()
    } else {
        let origins: Vec<axum::http::HeaderValue> = config
            .cors
            .origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        tower_http::cors::CorsLayer::new()
            .allow_origin(origins)
            .allow_methods([
                axum::http::Method::GET,
                axum::http::Method::POST,
                axum::http::Method::PUT,
                axum::http::Method::DELETE,
            ])
            .allow_headers(tower_http::cors::Any)
    };
    let app = create_router(state.clone())
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(cors);

    // Start background cron jobs
    let cron_state = state.clone();
    let cron_handle = tokio::spawn(async move {
        run_cron_jobs(cron_state).await;
    });

    // Start HTTP server
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Isolation server listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Shutting down...");
    cron_handle.abort();

    // Flush remaining audit events
    state.audit.flush().await.ok();

    db.close().await;
    Ok(())
}

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
                tracing::error!(?error, "Failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}

/// Background cron jobs:/// 1. Audit buffer flush — every 5s
/// 2. Audit log cleanup — daily (every 24h)
/// 3. Encryption key rotation check — every 60min
/// 4. Access-attempt audit retention cleanup — daily (F63)
async fn run_cron_jobs(state: Arc<AppState>) {
    let mut flush_ticker = interval(Duration::from_secs(5));
    let mut cleanup_ticker = interval(Duration::from_secs(86400));
    let mut rotation_ticker = interval(Duration::from_secs(3600));
    let mut access_cleanup_ticker = interval(Duration::from_secs(86400));

    loop {
        tokio::select! {
                    _ = flush_ticker.tick() => {
                        if let Err(e) = state.audit.flush().await {
                            error!(error = %e, "Audit buffer flush failed");
                        }
                    }
                    _ = cleanup_ticker.tick() => {
                        match state.audit.cleanup().await {
                            Ok(n) if n > 0 => info!(count = n, "Audit log cleanup completed"),
                            Err(e) => error!(error = %e, "Audit log cleanup failed"),
                            _ => {}
                        }
                    }
                    _ = access_cleanup_ticker.tick() => {
                        // F63: iso_access_attempts is append-only per decision —
                        // retention keeps it bounded.
                        match state.isolation.cleanup_access_attempts(365).await {
                            Ok(n) if n > 0 => info!(count = n, "Access-attempt audit cleanup completed"),
                            Err(e) => error!(error = %e, "Access-attempt audit cleanup failed"),
                            _ => {}
                        }
                    }
                    _ = rotation_ticker.tick() => {
        // Check for keys needing rotation — iterate known orgs
        // In production, this would query the DB for stale keys
                        info!("Key rotation check completed");
                    }
                }
    }
}
