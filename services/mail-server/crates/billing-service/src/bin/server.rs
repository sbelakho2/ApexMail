//! Billing service entry point.
//!
//! Reads configuration from environment variables (or `.env`), sets up the
//! database pool, Redis pool and HTTP server, then serves billing routes.

use clap::Parser;
use deadpool_redis::Runtime;
use sqlx::postgres::PgPoolOptions;
use tracing_subscriber::{fmt, EnvFilter};

use billing_service::{config::BillingConfig, maintenance, routes, AppState};

#[derive(Parser, Debug)]
#[command(name = "billing-service", about = "ApexMail billing service")]
struct Cli {
/// Listen address (overrides BILLING_LISTEN_ADDR).
    #[arg(long, env = "BILLING_LISTEN_ADDR", default_value = "0.0.0.0:4100")]
    listen: String,

/// Database URL.
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

/// Redis URL.
    #[arg(long, env = "REDIS_URL")]
    redis_url: String,

/// Service auth token.
    #[arg(long, env = "SERVICE_AUTH_TOKEN", default_value = "")]
    service_auth_token: String,

/// Stripe webhook signing secret.
    #[arg(long, env = "STRIPE_WEBHOOK_SECRET", default_value = "")]
    stripe_webhook_secret: String,

/// Internal API base URL.
    #[arg(long, env = "API_BASE_URL", default_value = "http://localhost:3001")]
    api_base_url: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
// Load .env if present (ignore errors).
    let _ = dotenvy::dotenv();

// Logging.
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let cli = Cli::parse();

    tracing::info!(listen = %cli.listen, "starting billing-service");

// Database pool.
    let db = PgPoolOptions::new()
        .max_connections(20)
        .min_connections(2)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&cli.database_url)
        .await?;

// Migrations are managed externally (apexmail-db crate or deploy tooling).
// If you need auto-migration, point sqlx::migrate! at the correct path.

// Redis pool.
    let redis_cfg = deadpool_redis::Config::from_url(&cli.redis_url);
    let redis = redis_cfg.create_pool(Some(Runtime::Tokio1))?;

// App state.
    let config = BillingConfig {
        database_url: cli.database_url,
        redis_url: cli.redis_url,
        listen_addr: cli.listen.clone(),
        service_auth_token: cli.service_auth_token,
        stripe_webhook_secret: cli.stripe_webhook_secret,
        api_base_url: cli.api_base_url,
        ..BillingConfig::default()
    };

    let state = AppState::new(db, redis, config);
    let app = routes::router(state.clone());
    maintenance::start_periodic_jobs(state.clone());

// Bind & serve.
    let listener = tokio::net::TcpListener::bind(&cli.listen).await?;
    tracing::info!("billing-service listening on {}", cli.listen);

    let shutdown = async {
        let ctrl_c = async {
            match tokio::signal::ctrl_c().await {
                Ok(()) => tracing::info!("received Ctrl+C — shutting down"),
                Err(e) => {
                    tracing::error!("failed to install Ctrl+C handler: {e}");
                    std::future::pending::<()>().await;
                }
            }
        };
        #[cfg(unix)]
        {
            match tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate()) {
                Ok(mut terminate) => tokio::select! {
                    _ = ctrl_c => {}
                    _ = terminate.recv() => tracing::info!("received SIGTERM — shutting down"),
                },
                Err(e) => {
                    tracing::error!(
                        "failed to install SIGTERM handler: {e}; falling back to Ctrl+C only"
                    );
                    ctrl_c.await;
                }
            }
        }
        #[cfg(not(unix))]
        {
            ctrl_c.await;
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}
