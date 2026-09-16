//! Worker entry point — runs all processors.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::{http::header::CONTENT_TYPE, response::IntoResponse, routing::get, Router};
use deadpool_redis::{Config as RedisConfig, Runtime};
use metrics_exporter_prometheus::PrometheusBuilder;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use sqlx::postgres::PgPoolOptions;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use worker_processors::{
    common::{
        AnalyticsConfig, DkimConfig, EmailConfig, ProcessorConfig, ReplyHandlerConfig, SesConfig,
        SmtpConfig, TrackingConfig, TransportType, WebhookConfig,
    },
    AnalyticsProcessor, EmailProcessor, ReplyHandler, WebhookProcessor,
};

/// Supervise a processor: restart it with capped exponential backoff whenever
/// `start()` returns an error. A transient failure at startup (transport
/// down, DB/Redis hiccup) previously disabled the processor — and with it,
/// email delivery — until the container was manually restarted. `Ok(())` is
/// a clean shutdown (Ctrl+C path) and ends supervision.
async fn supervise<F, Fut>(name: &'static str, mut start: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = worker_processors::ProcessorResult<()>>,
{
    let mut backoff_secs: u64 = 5;
    loop {
        match start().await {
            Ok(()) => {
                info!(processor = name, "processor shut down cleanly");
                return;
            }
            Err(e) => {
                error!(
                    processor = name,
                    error = %e,
                    backoff_secs,
                    "processor failed; restarting under supervision"
                );
                tokio::time::sleep(Duration::from_secs(backoff_secs)).await;
                backoff_secs = (backoff_secs * 2).min(60);
            }
        }
    }
}

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "worker".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    tracing_subscriber::fmt()
        .json()
        .with_target(true)
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();
    None
}

/// Environment-resolved startup settings (concurrency, poll cadence, which
/// processors run). Extracted from `main` so every parse arm is testable.
#[derive(Debug, Clone, Copy)]
struct WorkerSettings {
    concurrency: usize,
    poll_interval: Duration,
    run_analytics: bool,
    run_email: bool,
    run_reply_handler: bool,
    run_webhook: bool,
}

fn env_flag(name: &str) -> bool {
    env::var(name)
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true)
}

fn load_worker_settings() -> WorkerSettings {
    let concurrency: usize = env::var("WORKER_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10)
        .max(1);

    let poll_interval = Duration::from_secs(
        env::var("WORKER_POLL_INTERVAL")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(5),
    );

    WorkerSettings {
        concurrency,
        poll_interval,
        run_analytics: env_flag("WORKER_RUN_ANALYTICS"),
        run_email: env_flag("WORKER_RUN_EMAIL"),
        run_reply_handler: env_flag("WORKER_RUN_REPLY_HANDLER"),
        run_webhook: env_flag("WORKER_RUN_WEBHOOK"),
    }
}

/// Capabilities advertised on the worker heartbeat: the infrastructure
/// always present plus one entry per enabled processor.
fn capability_list(settings: &WorkerSettings) -> Vec<String> {
    let mut capabilities = vec!["postgres".to_string(), "redis".to_string()];
    if settings.run_analytics {
        capabilities.push("analytics".to_string());
    }
    if settings.run_email {
        capabilities.push("email".to_string());
    }
    if settings.run_reply_handler {
        capabilities.push("reply-handler".to_string());
    }
    if settings.run_webhook {
        capabilities.push("webhook".to_string());
    }
    capabilities
}

/// VERP v2 secret requirement (mirrors the MTA's production gate): outbound
/// mail may only carry an AUTHENTICATED bounce Return-Path. Without the
/// shared secret the worker emits NO VERP at all — it never falls back to
/// the unsigned v1 grammar — and production startup refuses the
/// configuration when the email processor is enabled.
fn verp_secret_gate(run_email: bool) -> Result<()> {
    let verp_domain_enabled = env::var("VERP_DOMAIN")
        .map(|v| !v.trim().is_empty())
        .unwrap_or(true);
    let verp_secret_ok = env::var("VERP_HMAC_SECRET")
        .map(|v| v.trim().len() >= apexmail_lib::verp::VERP_V2_MIN_SECRET_LEN)
        .unwrap_or(false);
    if verp_domain_enabled && !verp_secret_ok {
        let production = env::var("NODE_ENV")
            .map(|v| {
                matches!(
                    v.trim().to_ascii_lowercase().as_str(),
                    "production" | "prod"
                )
            })
            .unwrap_or(false);
        if production && run_email {
            anyhow::bail!(
                "VERP_HMAC_SECRET must be set (>= {} bytes) when running the email processor in \
                 production: unsigned v1 VERP is no longer emitted and bounces cannot be \
                 authenticated without the shared secret",
                apexmail_lib::verp::VERP_V2_MIN_SECRET_LEN
            );
        }
        warn!(
            "VERP_HMAC_SECRET is unset or shorter than {} bytes: outbound mail will carry NO \
             VERP Return-Path (unsigned v1 is not emitted); set the shared secret to enable \
             authenticated bounce routing",
            apexmail_lib::verp::VERP_V2_MIN_SECRET_LEN
        );
    }
    Ok(())
}

/// Create the Postgres pool with the production tunings (PERF-116: 60s
/// acquire timeout, statement cache capacity 100).
async fn connect_db(database_url: &str) -> Result<sqlx::PgPool> {
    let connect_opts = database_url
        .parse::<sqlx::postgres::PgConnectOptions>()?
        .statement_cache_capacity(100);
    let db = PgPoolOptions::new()
        .max_connections(30)
        .acquire_timeout(Duration::from_secs(60))
        .idle_timeout(Duration::from_secs(300))
        .max_lifetime(Duration::from_secs(1800))
        .connect_with(connect_opts)
        .await?;
    Ok(db)
}

/// Create the Redis pool from a URL.
fn connect_redis(redis_url: &str) -> Result<deadpool_redis::Pool> {
    let redis_cfg = RedisConfig::from_url(redis_url);
    Ok(redis_cfg.create_pool(Some(Runtime::Tokio1))?)
}

/// Resolve the SMTP relay host. Only `smtp` selects SMTP; SES is the default
/// for every other value. An empty/missing SMTP_HOST is fatal ONLY for the
/// SMTP transport — with SES the deliberately invalid sentinel host stays in
/// place so the hybrid dispatcher knows the relay is NOT configured and
/// dedicated-route sends defer before DATA instead of routing at localhost.
fn smtp_host_for(transport_type: &TransportType) -> Result<String> {
    match env::var("SMTP_HOST") {
        Ok(h) if !h.is_empty() => Ok(h),
        Ok(_) | Err(_) => {
            if *transport_type == TransportType::Smtp {
                anyhow::bail!(
                    "SMTP_HOST environment variable must be set when EMAIL_TRANSPORT_TYPE=smtp"
                );
            }
            warn!(
                "SMTP_HOST not set; SES shared-pool transport selected — dedicated \
                 delivery routes (dedicated_ips rows) will defer until a relay is configured"
            );
            Ok(SmtpConfig::default().host)
        }
    }
}

/// Build the email processor configuration from the environment.
fn build_email_config(concurrency: usize, poll_interval: Duration) -> Result<EmailConfig> {
    // Choose transport backend via EMAIL_TRANSPORT_TYPE env var.
    let transport_type = env::var("EMAIL_TRANSPORT_TYPE")
        .map(|v| TransportType::from_env(&v))
        .unwrap_or_default();

    let smtp_host = smtp_host_for(&transport_type)?;

    let smtp_config = SmtpConfig {
        host: smtp_host,
        port: env::var("SMTP_PORT")
            .ok()
            .and_then(|s| s.parse().ok())
            .unwrap_or(587),
        secure: env::var("SMTP_TLS")
            .map(|v| v == "true" || v == "1")
            .unwrap_or(true),
        username: env::var("SMTP_USERNAME").ok().filter(|s| !s.is_empty()),
        password: env::var("SMTP_PASSWORD")
            .ok()
            .filter(|s| !s.is_empty())
            .map(zeroize::Zeroizing::new),
        ..Default::default()
    };
    let ses_config = SesConfig {
        // Keep this default aligned with api-server's Config::from_env.
        // Production compose passes AWS_REGION explicitly to both
        // services; this fallback only protects local/test deployments.
        region: env::var("AWS_REGION")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .unwrap_or_else(|| "us-east-1".to_string()),
        configuration_set: env::var("SES_CONFIGURATION_SET")
            .ok()
            .filter(|value| !value.trim().is_empty()),
        ..Default::default()
    };

    Ok(EmailConfig {
        base: ProcessorConfig {
            name: "email".to_string(),
            concurrency,
            poll_interval,
            ..Default::default()
        },
        transport_type,
        smtp: smtp_config,
        ses: ses_config,
        dkim: DkimConfig {
            enabled: env::var("DKIM_ENABLED")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(false),
            // Customer-domain selectors and keys are retrieved from the
            // encrypted domains table per job. Do not load one global key
            // that could sign another tenant's domain.
            ..Default::default()
        },
        // Tracking enablement is env-driven (TRACKING_ENABLED +
        // TRACKING_SECRET_KEY): previously the ..Default::default() here
        // always left `enabled: false`, so pixels/links were never
        // rewritten and engagement accounting was dead.
        tracking: TrackingConfig::from_env(),
        ..Default::default()
    })
}

/// A base `ProcessorConfig` for a named processor.
fn base_config(name: &str, settings: &WorkerSettings) -> ProcessorConfig {
    ProcessorConfig {
        name: name.to_string(),
        concurrency: settings.concurrency,
        poll_interval: settings.poll_interval,
        ..Default::default()
    }
}

/// Everything `run_worker` starts, so tests (and the shutdown path) can stop
/// it deterministically.
struct WorkerProcesses {
    handles: Vec<tokio::task::JoinHandle<()>>,
    analytics: Option<Arc<AnalyticsProcessor>>,
    email: Option<Arc<EmailProcessor>>,
    reply: Option<Arc<ReplyHandler>>,
    webhook: Option<Arc<WebhookProcessor>>,
    heartbeat: tokio::task::JoinHandle<()>,
}

/// Start every enabled processor against INJECTED pools plus the heartbeat
/// emitter. Supervised: each processor restarts with capped backoff on error.
async fn run_worker(
    db: sqlx::PgPool,
    redis: deadpool_redis::Pool,
    settings: &WorkerSettings,
) -> Result<WorkerProcesses> {
    // ── Process heartbeat (real liveness for the control plane) ──
    // system_health reads service_heartbeats; queue activity is NOT a
    // liveness signal. Capabilities list the processors this process runs.
    // Beats start immediately; failures are logged, never fatal.
    let heartbeat_config =
        apexmail_lib::heartbeat::HeartbeatConfig::new("worker", env!("CARGO_PKG_VERSION"))
            .with_capabilities(capability_list(settings))
            .with_interval_from_env()
            .with_region_from_env();
    info!(
        instance_id = %heartbeat_config.instance_id,
        "worker heartbeat emitter started"
    );
    let heartbeat = apexmail_lib::heartbeat::spawn_service_heartbeat(db.clone(), heartbeat_config);

    verp_secret_gate(settings.run_email)?;

    let mut handles = vec![];
    let mut analytics_processor: Option<Arc<AnalyticsProcessor>> = None;
    let mut email_processor: Option<Arc<EmailProcessor>> = None;
    let mut reply_processor: Option<Arc<ReplyHandler>> = None;
    let mut webhook_processor: Option<Arc<WebhookProcessor>> = None;

    // Start analytics processor
    if settings.run_analytics {
        let config = AnalyticsConfig {
            base: base_config("analytics", settings),
            ..Default::default()
        };

        let processor = Arc::new(AnalyticsProcessor::new(db.clone(), redis.clone(), config));
        let p = Arc::clone(&processor);
        handles.push(tokio::spawn(async move {
            supervise("analytics", move || {
                let p = Arc::clone(&p);
                async move { p.start().await }
            })
            .await;
        }));
        analytics_processor = Some(processor);
        info!("Analytics processor started");
    }

    // Start email processor
    if settings.run_email {
        let config = build_email_config(settings.concurrency, settings.poll_interval)?;
        info!(transport = ?config.transport_type, "Email transport backend selected");

        match EmailProcessor::new(db.clone(), redis.clone(), config).await {
            Ok(processor) => {
                let processor = Arc::new(processor);
                let p = Arc::clone(&processor);
                handles.push(tokio::spawn(async move {
                    supervise("email", move || {
                        let p = Arc::clone(&p);
                        async move { p.start().await }
                    })
                    .await;
                }));
                email_processor = Some(processor);
                info!("Email processor started");
            }
            Err(e) => {
                error!(error = %e, "Failed to create email processor");
            }
        }
    }

    // Start reply handler
    if settings.run_reply_handler {
        let config = ReplyHandlerConfig {
            base: base_config("reply-handler", settings),
            ..Default::default()
        };

        let processor = Arc::new(ReplyHandler::new(db.clone(), config));
        let p = Arc::clone(&processor);
        handles.push(tokio::spawn(async move {
            supervise("reply-handler", move || {
                let p = Arc::clone(&p);
                async move { p.start().await }
            })
            .await;
        }));
        reply_processor = Some(processor);
        info!("Reply handler started");
    }

    // Start webhook processor
    if settings.run_webhook {
        let config = WebhookConfig {
            base: base_config("webhook", settings),
            ..Default::default()
        };

        match WebhookProcessor::new(db.clone(), redis.clone(), config) {
            Ok(processor) => {
                let processor = Arc::new(processor);
                let p = Arc::clone(&processor);
                handles.push(tokio::spawn(async move {
                    supervise("webhook", move || {
                        let p = Arc::clone(&p);
                        async move { p.start().await }
                    })
                    .await;
                }));
                webhook_processor = Some(processor);
                info!("Webhook processor started");
            }
            Err(e) => {
                error!(error = %e, "Failed to create webhook processor");
            }
        }
    }

    info!("All processors running. Press Ctrl+C to stop.");

    Ok(WorkerProcesses {
        handles,
        analytics: analytics_processor,
        email: email_processor,
        reply: reply_processor,
        webhook: webhook_processor,
        heartbeat,
    })
}

/// Serve /health and /metrics on an INJECTED listener. Runs until the task
/// is aborted; extraction keeps the bind out of the tested body.
async fn run_health_server(
    listener: tokio::net::TcpListener,
    metrics_handler: metrics_exporter_prometheus::PrometheusHandle,
) {
    let metrics_handler = std::sync::Arc::new(metrics_handler);
    let health_app = Router::new()
        .route("/health", get(|| async { "OK" }))
        .route(
            "/metrics",
            get(move || {
                let metrics_handle = metrics_handler.clone();
                async move {
                    (
                        [(CONTENT_TYPE, "text/plain; version=0.0.4; charset=utf-8")],
                        metrics_handle.render(),
                    )
                        .into_response()
                }
            }),
        );
    if let Err(e) = axum::serve(listener, health_app).await {
        error!(error = %e, "Health check server failed");
    }
}

/// Resolve the health port: HEALTH_PORT wins, then METRICS_PORT (the compose
/// file configures 9093), then 9090.
fn health_port() -> u16 {
    env::var("HEALTH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| env::var("METRICS_PORT").ok().and_then(|s| s.parse().ok()))
        .unwrap_or(9090)
}

/// Stop every processor, then join their tasks with a bounded wait. A
/// shutdown that exceeds `timeout` logs and returns (the process exits).
async fn shutdown_worker(processes: WorkerProcesses, shutdown_timeout: Duration) {
    if let Some(processor) = &processes.analytics {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop analytics processor");
        }
    }
    if let Some(processor) = &processes.email {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop email processor");
        }
    }
    if let Some(processor) = &processes.reply {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop reply handler");
        }
    }
    if let Some(processor) = &processes.webhook {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop webhook processor");
        }
    }

    let join_all = async {
        for handle in processes.handles {
            if let Err(error) = handle.await {
                warn!(error = %error, "Processor task join failed during shutdown");
            }
        }
    };

    if tokio::time::timeout(shutdown_timeout, join_all)
        .await
        .is_err()
    {
        warn!("Shutdown timed out; some processor tasks may still be running");
    }

    // Stop beating; the control plane sees the lease go stale on its own.
    processes.heartbeat.abort();
}

#[tokio::main]
async fn main() -> Result<()> {
    // Install the ring CryptoProvider for rustls before any TLS-capable code
    // runs. The workspace enables both `ring` (workspace rustls) and
    // aws-lc-rs (via reqwest's `rustls-tls`, sqlx, mail-send), so rustls
    // cannot pick a default provider on its own and would panic on the first
    // TLS handshake (email SMTP TLS verify, webhook HTTPS delivery, SES).
    // Installing explicitly keeps the provider deterministic across builds.
    if rustls::crypto::CryptoProvider::get_default().is_none() {
        let _ = rustls::crypto::ring::default_provider().install_default();
    }

    let _guard = init_tracing();

    // Keep health and Prometheus metrics on the worker's probe port. The
    // service previously accepted TCP connections there but returned no
    // scrapeable metrics, which made the configured monitoring target fail.
    let metrics_recorder = PrometheusBuilder::new().build_recorder();
    let metrics_handle = metrics_recorder.handle();
    if let Err(error) = metrics::set_global_recorder(Box::new(metrics_recorder)) {
        warn!(error = %error, "Prometheus recorder already installed");
    }
    metrics::gauge!("apexmail_worker_info").set(1.0);

    info!("Starting ApexMail Worker (Rust)");

    // Load configuration from environment
    let database_url = env::var("DATABASE_URL")
        .map_err(|_| anyhow::anyhow!("DATABASE_URL environment variable must be set"))?;
    let redis_url = env::var("REDIS_URL")
        .map_err(|_| anyhow::anyhow!("REDIS_URL environment variable must be set"))?;

    let db = connect_db(&database_url).await?;
    info!("Connected to PostgreSQL");

    let redis = connect_redis(&redis_url)?;
    info!("Connected to Redis");

    let settings = load_worker_settings();
    let processes = run_worker(db, redis, &settings).await?;

    // Start health check server for Kubernetes probes. Honors HEALTH_PORT and
    // falls back to METRICS_PORT so the container healthcheck and the
    // listener always agree.
    let health_addr = SocketAddr::from(([0, 0, 0, 0], health_port()));
    let health_listener = tokio::net::TcpListener::bind(health_addr).await?;
    info!(port = health_port(), "Health check server listening");
    tokio::spawn(run_health_server(health_listener, metrics_handle));

    // Wait for shutdown signal (SIGINT or SIGTERM)
    {
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
            _ = ctrl_c => info!("received Ctrl+C"),
            _ = terminate => info!("received SIGTERM"),
        }
    }

    info!("Shutting down...");
    shutdown_worker(processes, Duration::from_secs(10)).await;
    info!("Worker stopped");
    Ok(())
}

#[cfg(test)]
mod tests {
    //! The supervisor is the only piece of the worker binary that can be
    //! exercised without a live broker: a clean shutdown must end supervision,
    //! and a failing processor must be restarted under a capped backoff.

    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    /// Single crate-wide lock serializing env-mutating tests (each nextest
    /// test is its own process, but `cargo test` runs them on shared threads).
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    /// Same deterministic AWS environment the lib's test fixtures install
    /// (metadata probing off, file-based rustls roots) — `run_worker` builds
    /// the SES transport via `EmailProcessor::new`.
    fn ensure_aws_test_env() {
        static INSTALL: std::sync::Once = std::sync::Once::new();
        INSTALL.call_once(|| {
            std::env::set_var("AWS_EC2_METADATA_DISABLED", "true");
            std::env::set_var("AWS_ACCESS_KEY_ID", "test");
            std::env::set_var("AWS_SECRET_ACCESS_KEY", "test");
            for var in ["SSL_CERT_FILE", "AWS_CA_BUNDLE"] {
                if std::env::var_os(var).is_none() {
                    for candidate in [
                        "/etc/ssl/cert.pem",
                        "/etc/ssl/certs/ca-certificates.crt",
                        "/etc/pki/tls/certs/ca-bundle.crt",
                    ] {
                        if std::path::Path::new(candidate).is_file() {
                            std::env::set_var(var, candidate);
                            break;
                        }
                    }
                }
            }
        });
    }

    /// Run `body` with the listed env vars forced to values, restoring the
    /// previous state afterwards (unset stays unset).
    fn with_env(vars: &[(&str, Option<&str>)], body: impl FnOnce()) {
        let _guard = ENV_LOCK.lock().expect("env lock");
        let saved: Vec<(&str, Option<std::ffi::OsString>)> = vars
            .iter()
            .map(|(k, _)| (*k, std::env::var_os(k)))
            .collect();
        for (k, v) in vars {
            match v {
                Some(value) => std::env::set_var(k, value),
                None => std::env::remove_var(k),
            }
        }
        body();
        for (k, v) in saved {
            match v {
                Some(previous) => std::env::set_var(k, previous),
                None => std::env::remove_var(k),
            }
        }
    }

    #[tokio::test(start_paused = true)]
    async fn supervise_returns_on_a_clean_shutdown_without_restarting() {
        let calls = AtomicUsize::new(0);
        supervise("clean", || {
            calls.fetch_add(1, Ordering::SeqCst);
            async { Ok(()) }
        })
        .await;
        assert_eq!(calls.load(Ordering::SeqCst), 1, "Ok(()) ends supervision");
    }

    #[tokio::test(start_paused = true)]
    async fn supervise_restarts_a_failed_processor_with_backoff() {
        let calls = AtomicUsize::new(0);
        supervise("flaky", || {
            let attempt = calls.fetch_add(1, Ordering::SeqCst);
            async move {
                if attempt < 2 {
                    Err(worker_processors::ProcessorError::Job(format!(
                        "transient failure {attempt}"
                    )))
                } else {
                    Ok(())
                }
            }
        })
        .await;
        assert_eq!(
            calls.load(Ordering::SeqCst),
            3,
            "each failure must restart the processor until it shuts down cleanly"
        );
    }

    #[test]
    fn worker_settings_parse_every_env_arm() {
        with_env(
            &[
                ("WORKER_CONCURRENCY", Some("0")),
                ("WORKER_POLL_INTERVAL", Some("not-a-number")),
                ("WORKER_RUN_ANALYTICS", Some("false")),
                ("WORKER_RUN_EMAIL", Some("0")),
                ("WORKER_RUN_REPLY_HANDLER", Some("1")),
                ("WORKER_RUN_WEBHOOK", Some("true")),
            ],
            || {
                let s = load_worker_settings();
                assert_eq!(s.concurrency, 1, "a zero concurrency is clamped up to 1");
                assert_eq!(
                    s.poll_interval,
                    Duration::from_secs(5),
                    "invalid interval falls back to 5s"
                );
                assert!(!s.run_analytics, "false disables");
                assert!(!s.run_email, "0 disables");
                assert!(s.run_reply_handler, "1 enables");
                assert!(s.run_webhook, "true enables");
            },
        );
        with_env(
            &[
                ("WORKER_CONCURRENCY", Some("32")),
                ("WORKER_POLL_INTERVAL", Some("2")),
                ("WORKER_RUN_ANALYTICS", Some("garbage")),
            ],
            || {
                let s = load_worker_settings();
                assert_eq!(s.concurrency, 32);
                assert_eq!(s.poll_interval, Duration::from_secs(2));
                // Any explicit value other than true/1 DISABLES the processor.
                assert!(!s.run_analytics, "unknown flag value disables");
                assert!(s.run_email && s.run_reply_handler && s.run_webhook);
            },
        );
    }

    #[test]
    fn capabilities_reflect_enabled_processors() {
        let base = WorkerSettings {
            concurrency: 4,
            poll_interval: Duration::from_secs(1),
            run_analytics: false,
            run_email: false,
            run_reply_handler: false,
            run_webhook: false,
        };
        assert_eq!(capability_list(&base), ["postgres", "redis"]);
        let all = WorkerSettings {
            run_analytics: true,
            run_email: true,
            run_reply_handler: true,
            run_webhook: true,
            ..base
        };
        assert_eq!(
            capability_list(&all),
            [
                "postgres",
                "redis",
                "analytics",
                "email",
                "reply-handler",
                "webhook"
            ]
        );
    }

    #[test]
    fn verp_gate_refuses_production_email_without_the_shared_secret() {
        // Production + email + missing secret: hard error.
        with_env(
            &[
                ("NODE_ENV", Some("production")),
                ("VERP_HMAC_SECRET", None),
                ("VERP_DOMAIN", None),
            ],
            || {
                let err = verp_secret_gate(true).expect_err("production must refuse");
                assert!(
                    format!("{err:#}").contains("VERP_HMAC_SECRET must be set"),
                    "{err:#}"
                );
            },
        );
        // "prod" is accepted as production too (with an empty VERP_DOMAIN
        // explicitly given).
        with_env(
            &[
                ("NODE_ENV", Some(" prod ")),
                ("VERP_HMAC_SECRET", Some("short")),
                ("VERP_DOMAIN", Some("bounces.example.test")),
            ],
            || {
                assert!(
                    verp_secret_gate(true).is_err(),
                    "a too-short secret still refuses"
                );
            },
        );
        // Production but the email processor is off: warn-only.
        with_env(
            &[
                ("NODE_ENV", Some("production")),
                ("VERP_HMAC_SECRET", None),
                ("VERP_DOMAIN", None),
            ],
            || {
                assert!(
                    verp_secret_gate(false).is_ok(),
                    "no email processor => warn only"
                );
            },
        );
        // VERP explicitly disabled by an empty domain: never fatal.
        with_env(
            &[
                ("NODE_ENV", Some("production")),
                ("VERP_HMAC_SECRET", None),
                ("VERP_DOMAIN", Some("   ")),
            ],
            || {
                assert!(
                    verp_secret_gate(true).is_ok(),
                    "disabled VERP domain => warn only"
                );
            },
        );
        // A long-enough secret in production passes cleanly.
        with_env(
            &[
                ("NODE_ENV", Some("production")),
                ("VERP_HMAC_SECRET", Some("0123456789abcdef0123456789abcdef")),
                ("VERP_DOMAIN", None),
            ],
            || {
                assert!(verp_secret_gate(true).is_ok(), "valid secret passes");
            },
        );
        // Development without a secret: warn-only.
        with_env(
            &[
                ("NODE_ENV", Some("development")),
                ("VERP_HMAC_SECRET", None),
            ],
            || {
                assert!(
                    verp_secret_gate(true).is_ok(),
                    "development degrades to a warning"
                );
            },
        );
    }

    #[test]
    fn smtp_host_resolution_arms() {
        use worker_processors::common::SmtpConfig;
        // SMTP transport without a host: hard error.
        with_env(&[("SMTP_HOST", None)], || {
            let err = smtp_host_for(&TransportType::Smtp).expect_err("smtp needs SMTP_HOST");
            assert!(
                format!("{err:#}").contains("SMTP_HOST environment variable must be set"),
                "{err:#}"
            );
        });
        // Empty SMTP_HOST is treated as missing for smtp, and as "not
        // configured" for ses (sentinel host).
        with_env(&[("SMTP_HOST", Some(""))], || {
            assert!(smtp_host_for(&TransportType::Smtp).is_err());
            let host = smtp_host_for(&TransportType::Ses).expect("ses tolerates no relay");
            assert_eq!(
                host,
                SmtpConfig::default().host,
                "ses keeps the sentinel host"
            );
        });
        // An explicit host wins for both transports.
        with_env(&[("SMTP_HOST", Some("relay.example.test"))], || {
            assert_eq!(
                smtp_host_for(&TransportType::Smtp).unwrap(),
                "relay.example.test"
            );
            assert_eq!(
                smtp_host_for(&TransportType::Ses).unwrap(),
                "relay.example.test"
            );
        });
    }

    #[test]
    fn email_config_assembles_env_settings() {
        ensure_aws_test_env();
        with_env(
            &[
                ("EMAIL_TRANSPORT_TYPE", Some("smtp")),
                ("SMTP_HOST", Some("relay.example.test")),
                ("SMTP_PORT", Some("2525")),
                ("SMTP_TLS", Some("false")),
                ("SMTP_USERNAME", Some("user")),
                ("SMTP_PASSWORD", Some("pass")),
                ("AWS_REGION", Some("eu-west-1")),
                ("SES_CONFIGURATION_SET", Some("cs-1")),
                ("DKIM_ENABLED", Some("1")),
                ("TRACKING_ENABLED", Some("true")),
                (
                    "TRACKING_SECRET_KEY",
                    Some("0123456789abcdef0123456789abcdef"),
                ),
            ],
            || {
                let cfg = build_email_config(7, Duration::from_secs(3)).expect("config builds");
                assert_eq!(cfg.transport_type, TransportType::Smtp);
                assert_eq!(cfg.smtp.host, "relay.example.test");
                assert_eq!(cfg.smtp.port, 2525);
                assert!(!cfg.smtp.secure);
                assert_eq!(cfg.smtp.username.as_deref(), Some("user"));
                assert_eq!(
                    cfg.smtp.password.as_ref().map(|p| p.as_str().to_string()),
                    Some("pass".to_string())
                );
                assert_eq!(cfg.ses.region, "eu-west-1");
                assert_eq!(cfg.ses.configuration_set.as_deref(), Some("cs-1"));
                assert!(cfg.dkim.enabled);
                assert!(
                    cfg.tracking.enabled,
                    "tracking must follow TRACKING_ENABLED"
                );
                assert_eq!(cfg.base.concurrency, 7);
                assert_eq!(cfg.base.poll_interval, Duration::from_secs(3));
            },
        );
        // SES default transport: no SMTP_HOST needed.
        with_env(
            &[
                ("EMAIL_TRANSPORT_TYPE", None),
                ("SMTP_HOST", None),
                ("SMTP_PORT", Some("nope")),
                ("DKIM_ENABLED", None),
                ("AWS_REGION", Some("  ")),
            ],
            || {
                let cfg = build_email_config(1, Duration::from_secs(1)).expect("ses config builds");
                assert_eq!(cfg.transport_type, TransportType::Ses);
                assert_eq!(cfg.smtp.port, 587, "invalid SMTP_PORT falls back to 587");
                assert!(!cfg.dkim.enabled);
                assert_eq!(cfg.ses.region, "us-east-1", "blank AWS_REGION falls back");
            },
        );
    }

    #[test]
    fn health_port_prefers_health_then_metrics_then_default() {
        with_env(&[("HEALTH_PORT", None), ("METRICS_PORT", None)], || {
            assert_eq!(health_port(), 9090);
        });
        with_env(
            &[("HEALTH_PORT", None), ("METRICS_PORT", Some("9093"))],
            || {
                assert_eq!(health_port(), 9093);
            },
        );
        with_env(
            &[
                ("HEALTH_PORT", Some("18080")),
                ("METRICS_PORT", Some("9093")),
            ],
            || {
                assert_eq!(health_port(), 18080, "HEALTH_PORT wins");
            },
        );
        with_env(
            &[("HEALTH_PORT", Some("bad")), ("METRICS_PORT", None)],
            || {
                assert_eq!(health_port(), 9090, "invalid HEALTH_PORT falls through");
            },
        );
    }

    #[tokio::test]
    async fn connect_db_rejects_a_malformed_url_immediately() {
        let err = connect_db("totally not a url")
            .await
            .expect_err("parse failure");
        assert!(
            format!("{err:#}").to_lowercase().contains("url"),
            "unexpected error: {err:#}"
        );
    }

    #[test]
    fn connect_redis_rejects_a_malformed_url() {
        assert!(
            connect_redis("not a redis url at all").is_err(),
            "deadpool must refuse an unparseable URL"
        );
    }

    /// The real health server on a loopback ephemeral port: /health answers
    /// OK and /metrics renders scrapeable Prometheus text.
    #[tokio::test]
    async fn health_server_serves_health_and_prometheus_metrics() {
        // Build a recorder without installing it globally (tests share a process).
        let recorder = PrometheusBuilder::new().build_recorder();
        let handle = recorder.handle();
        // Record one counter through the LOCAL recorder (the global one is not
        // installed in the test process) so the render is non-empty.
        {
            // Scope a real macro-driven counter through the LOCAL recorder so
            // the rendered output is non-empty.
            metrics::with_local_recorder(&recorder, || {
                metrics::counter!("apexmail_worker_test_up").increment(1);
            });
        }

        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind ephemeral health port");
        let port = listener.local_addr().expect("addr").port();
        let server = tokio::spawn(run_health_server(listener, handle));

        let client = reqwest::Client::builder()
            .timeout(Duration::from_secs(10))
            .build()
            .expect("client");
        let health = client
            .get(format!("http://127.0.0.1:{port}/health"))
            .send()
            .await
            .expect("GET /health");
        assert_eq!(health.status(), 200);
        assert_eq!(health.text().await.expect("body"), "OK");

        let metrics = client
            .get(format!("http://127.0.0.1:{port}/metrics"))
            .send()
            .await
            .expect("GET /metrics");
        assert_eq!(metrics.status(), 200);
        let headers = metrics.headers().clone();
        let content_type = headers
            .get(reqwest::header::CONTENT_TYPE)
            .and_then(|v| v.to_str().ok())
            .unwrap_or_default()
            .to_string();
        assert!(content_type.starts_with("text/plain"), "{content_type}");
        let body = metrics.text().await.expect("metrics body");
        assert!(body.contains("apexmail_worker_test_up"), "{body}");

        server.abort();
    }

    /// `run_worker` against a fresh canonical DB + real Redis starts every
    /// enabled processor; `shutdown_worker` stops and joins them.
    #[tokio::test]
    async fn run_worker_starts_all_processors_and_shutdown_joins_them() {
        ensure_aws_test_env();
        let db = match migrator::test_support::fresh_canonical_pool(
            "worker_bin_run_worker",
            "bin_run_worker",
        )
        .await
        {
            Ok(Some(pool)) => pool,
            Ok(None) => {
                eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
                return;
            }
            Err(e) => panic!("provision failed: {e}"),
        };
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let redis = connect_redis(&redis_url).expect("test redis pool");

        let settings = WorkerSettings {
            concurrency: 2,
            poll_interval: Duration::from_secs(60),
            run_analytics: true,
            run_email: true,
            run_reply_handler: true,
            run_webhook: true,
        };
        let processes = run_worker(db.clone(), redis.clone(), &settings)
            .await
            .expect("all processors start");
        assert!(processes.analytics.is_some(), "analytics started");
        assert!(processes.email.is_some(), "email started");
        assert!(processes.reply.is_some(), "reply handler started");
        assert!(processes.webhook.is_some(), "webhook started");
        assert_eq!(processes.handles.len(), 4, "one supervised task each");

        shutdown_worker(processes, Duration::from_secs(10)).await;
        db.close().await;
    }

    /// A disabled processor is neither built nor supervised; the VERP gate
    /// failure aborts startup with an error.
    #[tokio::test]
    async fn run_worker_selective_flags_and_verp_refusal() {
        ensure_aws_test_env();
        let db = match migrator::test_support::fresh_canonical_pool(
            "worker_bin_verp_gate",
            "bin_verp_gate",
        )
        .await
        {
            Ok(Some(pool)) => pool,
            Ok(None) => {
                eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
                return;
            }
            Err(e) => panic!("provision failed: {e}"),
        };
        let redis_url =
            std::env::var("TEST_REDIS_URL").unwrap_or_else(|_| "redis://127.0.0.1:6379".into());
        let redis = connect_redis(&redis_url).expect("test redis pool");

        let settings = WorkerSettings {
            concurrency: 1,
            poll_interval: Duration::from_secs(60),
            run_analytics: false,
            run_email: false,
            run_reply_handler: true,
            run_webhook: false,
        };
        let processes = run_worker(db.clone(), redis.clone(), &settings)
            .await
            .expect("only the reply handler runs");
        assert!(processes.analytics.is_none());
        assert!(processes.email.is_none());
        assert!(processes.reply.is_some());
        assert!(processes.webhook.is_none());
        assert_eq!(processes.handles.len(), 1);
        shutdown_worker(processes, Duration::from_secs(10)).await;

        // Production VERP refusal: email enabled without the secret aborts
        // run_worker AFTER the heartbeat started (matching production's
        // ordering) and before the email processor is created.
        let saved = (
            std::env::var_os("NODE_ENV"),
            std::env::var_os("VERP_HMAC_SECRET"),
        );
        {
            let _guard = ENV_LOCK.lock().expect("env lock");
            std::env::set_var("NODE_ENV", "production");
            std::env::remove_var("VERP_HMAC_SECRET");
        }
        let settings = WorkerSettings {
            run_analytics: false,
            run_email: true,
            run_reply_handler: false,
            run_webhook: false,
            ..settings
        };
        let result = run_worker(db.clone(), redis.clone(), &settings).await;
        match saved {
            (Some(env), _) => std::env::set_var("NODE_ENV", env),
            (None, _) => std::env::remove_var("NODE_ENV"),
        }
        match saved.1 {
            Some(secret) => std::env::set_var("VERP_HMAC_SECRET", secret),
            None => std::env::remove_var("VERP_HMAC_SECRET"),
        }
        let err = match result {
            Err(e) => e,
            Ok(_) => panic!("production VERP gate must refuse, but run_worker succeeded"),
        };
        assert!(
            format!("{err:#}").contains("VERP_HMAC_SECRET must be set"),
            "{err:#}"
        );
        db.close().await;
    }
}
