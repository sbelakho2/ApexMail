//! Billing service entry point.
//!
//! Reads configuration from environment variables (or `.env`), sets up the
//! database pool, Redis pool and HTTP server, then serves billing routes.

use clap::Parser;
use deadpool_redis::Runtime;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
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

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "billing-service".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    None
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // Load .env if present (ignore errors).
    let _ = dotenvy::dotenv();

    let _guard = init_tracing();

    let cli = Cli::parse();

    // BS-001: Fail-fast if Stripe webhook secret is not configured.
    // The /webhooks/stripe endpoint is exempt from service auth and relies
    // entirely on HMAC-SHA256 signature verification. An empty secret would
    // cause all webhook requests to be rejected, but it's better to fail at
    // startup than silently drop webhook events in production.
    if cli.stripe_webhook_secret.trim().is_empty() {
        tracing::error!(
            "STRIPE_WEBHOOK_SECRET is not configured. Stripe webhook signature \
             verification requires this secret. Set the environment variable or \
             pass --stripe-webhook-secret."
        );
        anyhow::bail!("STRIPE_WEBHOOK_SECRET is required");
    }

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

    // BS-002: Validate that the dunning_config table exists at startup.
    // Previously the table was created on-demand at runtime (with a CREATE TABLE
    // IF NOT EXISTS in the webhook handler), which could cause race conditions
    // and obscures schema management.  Warn early if the migration is missing.
    {
        let table_exists: bool = sqlx::query_scalar(
            "SELECT EXISTS (
                SELECT FROM information_schema.tables
                WHERE table_name = 'dunning_config'
            )",
        )
        .fetch_one(&db)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to check dunning_config table existence: {e}"))?;

        if !table_exists {
            tracing::warn!(
                "dunning_config table does not exist — dunning features will use \
                 hardcoded defaults. Run the database migrations to create this table."
            );
        } else {
            tracing::info!("dunning_config table found — dunning schema is up-to-date");
        }
    }

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
    billing_service::stripe_webhooks::spawn_deadletter_retry_worker(state.clone());

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
