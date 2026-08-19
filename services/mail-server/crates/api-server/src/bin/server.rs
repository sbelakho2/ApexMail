//! API server binary — entry point.
//!
//! Loads configuration, creates connection pools, builds the Axum app,
//! and serves with graceful shutdown on SIGTERM / SIGINT.

use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use reqwest::Client;
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio::signal;
use tracing_subscriber::EnvFilter;

use apexmail_db::pool::set_query_timeout;
use api_server::app::build_app;
use api_server::config::Config;
use api_server::ip_provider::DedicatedIpProvider;
use api_server::routes::domains::bootstrap_system_sender;
use api_server::ses_provider::SesIpProvider;
use api_server::state::AppStateInner;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    // ── Logging ─────────────────────────────────────────────
    let _tracing_guard = init_tracing();

    // ── Config ──────────────────────────────────────────────
    let config = Config::from_env()?;
    tracing::info!(
        port = config.port,
        host = %config.host,
        environment = ?config.environment,
        "loaded configuration"
    );

    // ── Query timeout ────────────────────────────────────────
    set_query_timeout(config.query_timeout_seconds);
    tracing::info!(
        timeout_secs = config.query_timeout_seconds,
        "global query timeout configured"
    );

    // ── Database pool ───────────────────────────────────────
    let db = apexmail_db::pool::create_pool_from_config(
        &config.db_host,
        config.db_port,
        &config.db_name,
        &config.db_user,
        &config.db_password,
        config.db_max_connections,
        config.statement_cache_capacity,
    )
    .await?;
    tracing::info!("database pool created");

    // ── Pool pair (primary + replica) ───────────────────────
    let pools = apexmail_db::pool::create_pool_pair(
        &config.database_url(),
        config.database_replica_url.as_deref(),
        config.db_max_connections,
        config.statement_cache_capacity,
    )
    .await?;
    tracing::info!(
        replica_configured = config.database_replica_url.is_some(),
        "database pool pair created"
    );

    // ── Redis pool ──────────────────────────────────────────
    // PP-002: Configure pool timeouts so Redis outages don't hang indefinitely.
    // `create_timeout` limits TCP connect to Redis; `wait_timeout` limits
    // waiting for a pooled connection (acquire).
    let redis_cfg = deadpool_redis::Config::from_url(config.redis_url());
    let mut pool_cfg = deadpool_redis::PoolConfig::new(config.redis_pool_max_size);
    pool_cfg.timeouts = deadpool_redis::Timeouts {
        wait: Some(std::time::Duration::from_secs(5)),
        create: Some(std::time::Duration::from_secs(10)),
        recycle: None,
    };
    let redis = deadpool_redis::Config {
        pool: Some(pool_cfg),
        ..redis_cfg
    }
    .create_pool(Some(deadpool_redis::Runtime::Tokio1))
    .map_err(|e| anyhow::anyhow!("failed to create Redis pool: {e}"))?;
    tracing::info!(max_size = config.redis_pool_max_size, "redis pool created");

    // ── AWS SES client ──────────────────────────────────────
    let aws_config = aws_config::defaults(aws_config::BehaviorVersion::latest())
        .region(aws_sdk_sesv2::config::Region::new(
            config.aws_region.clone(),
        ))
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
        .timeout(std::time::Duration::from_secs(config.http_client_timeout_secs))
        .build()?;
    tracing::info!(
        timeout_secs = config.http_client_timeout_secs,
        "HTTP client timeout configured"
    );

    let state = AppStateInner::new(
        db,
        pools,
        redis,
        config.clone(),
        http_client,
        ses_provider,
        ip_provider,
    )
    .await
    .map_err(|e| anyhow::anyhow!("failed to initialize DDoS protector: {e}"))?;
    tracing::info!(
        "resilience layer initialised — circuit breakers (db, redis, clickhouse) and bulkheads active"
    );

    // The migration only creates a pending platform domain. Provisioning is
    // opt-in so a deployment never invents DNS state, but operators can safely
    // request encrypted per-domain key material during a controlled rollout.
    if system_sender_bootstrap_requested()? {
        let status = bootstrap_system_sender(&state)
            .await
            .map_err(|error| anyhow::anyhow!("system sender bootstrap failed: {error}"))?;
        tracing::info!(
            domain = %status.domain,
            status = %status.status,
            ready = status.ready,
            dns_record_count = status.records.len(),
            "system sender bootstrap completed; publish the returned records and verify explicitly"
        );
    }

    let shutdown_state = state.clone();

    // ── Inbox-placement scheduler ───────────────────────────
    // Spawn the background loop that picks up `Pending` placement tests and
    // executes them, plus the periodic seed-account health checker. The
    // scheduler is held in `placement_scheduler` so we can signal a graceful
    // shutdown alongside the HTTP server.
    let placement_scheduler = if let Some(ref placement_state) = state.placement_state {
        let scheduler = std::sync::Arc::new(inbox_placement::PlacementScheduler::new(
            placement_state.engine.clone(),
        ));
        scheduler.clone().start().await;
        tracing::info!(
            polling_interval_secs = config.placement_polling_interval_secs,
            "inbox-placement scheduler started"
        );
        Some(scheduler)
    } else {
        tracing::info!("inbox-placement disabled (PLACEMENT_ENABLED=false)");
        None
    };

    // ── Prometheus metrics recorder ─────────────────────────
    if config.metrics_port > 0 {
        let metrics_addr: std::net::SocketAddr =
            format!("0.0.0.0:{}", config.metrics_port).parse()?;
        metrics_exporter_prometheus::PrometheusBuilder::new()
            .with_http_listener(metrics_addr)
            .install_recorder()
            .map_err(|e| anyhow::anyhow!("failed to install Prometheus recorder: {e}"))?;
        tracing::info!(
            port = config.metrics_port,
            "Prometheus metrics server ready"
        );
    }

    // ── Build & serve ───────────────────────────────────────
    let app = build_app(state);

    let addr: SocketAddr = format!("{}:{}", config.host, config.port).parse()?;
    let listener = TcpListener::bind(addr).await?;
    tracing::info!(%addr, "listening");

    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .with_graceful_shutdown(shutdown_signal())
    .await?;

    if let Some(scheduler) = placement_scheduler {
        scheduler.shutdown().await;
        tracing::info!("inbox-placement scheduler shut down");
    }

    shutdown_state.db.close().await;
    tracing::info!("database pool closed");

    tracing::info!("server shut down gracefully");
    Ok(())
}

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "api-server".into(),
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
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    None
}

fn system_sender_bootstrap_requested() -> anyhow::Result<bool> {
    match std::env::var("SYSTEM_SENDER_BOOTSTRAP_ON_STARTUP") {
        Ok(value) if value.eq_ignore_ascii_case("true") || value == "1" => Ok(true),
        Ok(value) if value.eq_ignore_ascii_case("false") || value == "0" || value.is_empty() => {
            Ok(false)
        }
        Ok(_) => Err(anyhow::anyhow!(
            "SYSTEM_SENDER_BOOTSTRAP_ON_STARTUP must be true, false, 1, or 0"
        )),
        Err(std::env::VarError::NotPresent) => Ok(false),
        Err(error) => Err(anyhow::anyhow!(
            "failed to read SYSTEM_SENDER_BOOTSTRAP_ON_STARTUP: {error}"
        )),
    }
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
            Ok(mut sig) => {
                sig.recv().await;
            }
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
