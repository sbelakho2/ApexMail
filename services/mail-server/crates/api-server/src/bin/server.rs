//! API server binary — entry point.
//!
//! Loads configuration, creates connection pools, builds the Axum app,
//! and serves with graceful shutdown on SIGTERM / SIGINT.

use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::EnvFilter;
use reqwest::Client;

use api_server::app::build_app;
use api_server::config::Config;
use api_server::ip_provider::DedicatedIpProvider;
use api_server::ses_provider::SesIpProvider;
use api_server::state::AppStateInner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Logging ─────────────────────────────────────────────
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    // ── Config ──────────────────────────────────────────────
    let config = Config::from_env()?;
    tracing::info!(
        port = config.port,
        host = %config.host,
        environment = ?config.environment,
        "loaded configuration"
    );

    // ── Database pool ───────────────────────────────────────
    let db = apexmail_db::pool::create_pool_from_config(
        &config.db_host,
        config.db_port,
        &config.db_name,
        &config.db_user,
        &config.db_password,
        config.db_max_connections,
    )
    .await?;
    tracing::info!("database pool created");

    // ── Redis pool ──────────────────────────────────────────
    let redis_cfg = deadpool_redis::Config::from_url(&config.redis_url());
    let redis = redis_cfg
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .map_err(|e| anyhow::anyhow!("failed to create Redis pool: {e}"))?;
    tracing::info!("redis pool created");

    // ── AWS SES client ──────────────────────────────────────
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_sesv2::config::Region::new(config.aws_region.clone()))
        .load()
        .await;
    let ses_client = aws_sdk_sesv2::Client::new(&aws_config);
    let ses_provider = SesIpProvider::new(
        ses_client,
        db.clone(),
        config.ses_ip_pool_prefix.clone(),
        config.aws_region.clone(),
    );
    tracing::info!(region = %config.aws_region, "AWS SES client initialized (shared-pool sending only)");

    // ── Hetzner dedicated IP provider ───────────────────────
    let ip_provider = DedicatedIpProvider::from_env(db.clone());
    if ip_provider.is_some() {
        tracing::info!("Hetzner dedicated IP provider initialized");
    } else {
        tracing::warn!("HETZNER_API_TOKEN not set — dedicated IP provisioning disabled");
    }

    // ── App state ───────────────────────────────────────────
    let http_client = Client::builder()
        .timeout(std::time::Duration::from_secs(30))
        .build()?;

    let state = AppStateInner::new(db, redis, config.clone(), http_client, ses_provider, ip_provider);

    // ── Prometheus metrics recorder ─────────────────────────
    if config.metrics_port > 0 {
        let metrics_addr: std::net::SocketAddr =
            format!("0.0.0.0:{}", config.metrics_port).parse()?;
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(metrics_addr)
            .install_recorder()
            .map_err(|e| anyhow::anyhow!("failed to install Prometheus recorder: {e}"))?;
        tracing::info!(port = config.metrics_port, "Prometheus metrics server ready");
    }

    // ── Build & serve ───────────────────────────────────────
    let app = build_app(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");

    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown_signal())
        .await?;

    tracing::info!("server shut down gracefully");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(e) = signal::ctrl_c().await {
            tracing::error!(error = %e, "failed to listen for Ctrl+C — shutdown may require SIGKILL");
            // Fall back to pending so the other branch (SIGTERM) can still work.
            std::future::pending::<()>().await;
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut sig) => { sig.recv().await; }
            Err(e) => {
                tracing::error!(error = %e, "failed to install SIGTERM handler");
                std::future::pending::<()>().await;
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => tracing::info!("received Ctrl+C"),
        _ = terminate => tracing::info!("received SIGTERM"),
    }
}
