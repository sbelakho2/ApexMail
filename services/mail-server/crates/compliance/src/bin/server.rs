//! Compliance server binary — HTTP on port 3011 with 5 background cron jobs
//! and graceful shutdown.

use clap::Parser;
use deadpool_redis::{Config as RedisConfig, Runtime};
use sqlx::postgres::PgPoolOptions;
use std::sync::Arc;
use tokio::signal;
use tokio::time::{interval, Duration};
use tracing::{error, info};

use compliance::audit_logger::AuditLogger;
use compliance::config::ComplianceConfig;
use compliance::content_scanner::ContentScanner;
use compliance::gdpr_automation::GdprAutomation;
use compliance::risk_scoring::RiskScoringEngine;
use compliance::routes::{create_router, AppState};
use compliance::secret_manager::SecretManager;

#[derive(Parser)]
#[command(name = "compliance-server")]
struct Cli {
    /// Override port (default from COMPLIANCE_PORT or 3011)
    #[arg(short, long)]
    port: Option<u16>,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Init tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| "compliance=info,tower_http=info".into()),
        )
        .init();

    dotenvy::dotenv().ok();

    let cli = Cli::parse();
    let config = ComplianceConfig::from_env();
    let port = cli.port.unwrap_or(config.port);

    // Database pool
    let db = PgPoolOptions::new()
        .max_connections(5)
        .connect(&config.database_url)
        .await?;

    info!("Connected to database");

    // Redis pool
    let redis_cfg = RedisConfig::from_url(&config.redis_url);
    let redis = redis_cfg.create_pool(Some(Runtime::Tokio1))?;

    info!("Redis pool created");

    // Build services
    let risk_engine = RiskScoringEngine::new(db.clone(), config.clone());
    let content_scanner = ContentScanner::new(db.clone(), config.content.clone());
    let audit_logger = AuditLogger::new(db.clone(), config.audit.clone());
    let secret_manager = SecretManager::new(db.clone(), config.secrets.clone())
        .map_err(|e| anyhow::anyhow!(e))?;
    let gdpr = GdprAutomation::new(db.clone(), redis.clone(), config.gdpr.clone());

    let state = Arc::new(AppState {
        risk_engine,
        content_scanner,
        audit_logger,
        secret_manager,
        gdpr,
        config: config.clone(),
    });

    // Build router with middleware
    let app = create_router(state.clone())
        .layer(tower_http::trace::TraceLayer::new_for_http())
        .layer(
            tower_http::cors::CorsLayer::new()
                .allow_origin(tower_http::cors::Any)
                .allow_methods(tower_http::cors::Any)
                .allow_headers(tower_http::cors::Any),
        );

    // Start background cron jobs
    let cron_state = state.clone();
    let cron_handle = tokio::spawn(async move {
        run_cron_jobs(cron_state).await;
    });

    // Start HTTP server
    let addr = format!("0.0.0.0:{port}");
    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!("Compliance server listening on {}", addr);

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    info!("Shutting down...");
    cron_handle.abort();
    db.close().await;

    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(error) = signal::ctrl_c().await {
            error!(?error, "Failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut signal) => {
                signal.recv().await;
            }
            Err(error) => {
                error!(?error, "Failed to install SIGTERM handler");
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

/// 5 background cron jobs:
/// 1. GDPR queue processing — every 30s
/// 2. Secret auto-rotation — every 60min
/// 3. GDPR request expiry — every 5min
/// 4. Audit archival — daily (every 24h)
/// 5. Data retention enforcement — daily (every 24h)
async fn run_cron_jobs(state: Arc<AppState>) {
    let mut gdpr_ticker = interval(Duration::from_secs(30));
    let mut rotation_ticker = interval(Duration::from_secs(3600));
    let mut expiry_ticker = interval(Duration::from_secs(300));
    let mut archive_ticker = interval(Duration::from_secs(86400));
    let mut retention_ticker = interval(Duration::from_secs(86400));

    loop {
        tokio::select! {
            _ = gdpr_ticker.tick() => {
                match state.gdpr.process_queue_batch(10).await {
                    Ok(results) if !results.is_empty() => {
                        info!(count = results.len(), "Processed GDPR queue batch");
                    }
                    Err(e) => error!(error = %e, "GDPR queue processing failed"),
                    _ => {}
                }
            }
            _ = rotation_ticker.tick() => {
                match state.secret_manager.process_auto_rotations().await {
                    Ok(result) if !result.rotated.is_empty() => {
                        info!(count = result.rotated.len(), "Auto-rotated secrets");
                    }
                    Err(e) => error!(error = %e, "Secret auto-rotation failed"),
                    _ => {}
                }
            }
            _ = expiry_ticker.tick() => {
                // Expire overdue GDPR requests
                match state.gdpr.expire_overdue_requests().await {
                    Ok(n) if n > 0 => info!(count = n, "Expired overdue GDPR requests"),
                    Err(e) => error!(error = %e, "GDPR expiry check failed"),
                    _ => {}
                }
                // Expire stale double-opt-in tokens
                match state.gdpr.expire_stale_opt_in_tokens().await {
                    Ok(n) if n > 0 => info!(count = n, "Expired stale DOI tokens"),
                    Err(e) => error!(error = %e, "DOI token expiry failed"),
                    _ => {}
                }
            }
            _ = archive_ticker.tick() => {
                let older_than = chrono::Utc::now() - chrono::Duration::days(state.config.audit.retention_days);
                match state.audit_logger.archive(older_than).await {
                    Ok(n) if n > 0 => info!(count = n, "Archived old audit logs"),
                    Err(e) => error!(error = %e, "Audit archival failed"),
                    _ => {}
                }
            }
            _ = retention_ticker.tick() => {
                match state.gdpr.enforce_retention().await {
                    Ok((c, e)) if c > 0 || e > 0 => {
                        info!(consents = c, exports = e, "Retention enforcement completed");
                    }
                    Err(e) => error!(error = %e, "Retention enforcement failed"),
                    _ => {}
                }
            }
        }
    }
}
