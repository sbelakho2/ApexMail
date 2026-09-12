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

    // Create database pool
    // PERF-116: Acquire timeout increased to 60s (from 10s) and statement
    // caching enabled (capacity 100) to avoid re-preparation roundtrips.
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

    info!("Connected to PostgreSQL");

    // Create Redis pool
    let redis_cfg = RedisConfig::from_url(&redis_url);
    let redis = redis_cfg.create_pool(Some(Runtime::Tokio1))?;

    info!("Connected to Redis");

    // Load concurrency from env
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

    // Determine which processors to run
    let run_analytics = env::var("WORKER_RUN_ANALYTICS")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);
    let run_email = env::var("WORKER_RUN_EMAIL")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);
    let run_reply_handler = env::var("WORKER_RUN_REPLY_HANDLER")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);
    let run_webhook = env::var("WORKER_RUN_WEBHOOK")
        .map(|v| v == "true" || v == "1")
        .unwrap_or(true);

    // ── Process heartbeat (real liveness for the control plane) ──
    // system_health reads service_heartbeats; queue activity is NOT a
    // liveness signal. Capabilities list the processors this process runs.
    // Beats start immediately; failures are logged, never fatal.
    let mut capabilities = vec!["postgres".to_string(), "redis".to_string()];
    if run_analytics {
        capabilities.push("analytics".to_string());
    }
    if run_email {
        capabilities.push("email".to_string());
    }
    if run_reply_handler {
        capabilities.push("reply-handler".to_string());
    }
    if run_webhook {
        capabilities.push("webhook".to_string());
    }
    let heartbeat_config =
        apexmail_lib::heartbeat::HeartbeatConfig::new("worker", env!("CARGO_PKG_VERSION"))
            .with_capabilities(capabilities)
            .with_interval_from_env()
            .with_region_from_env();
    info!(
        instance_id = %heartbeat_config.instance_id,
        "worker heartbeat emitter started"
    );
    let heartbeat = apexmail_lib::heartbeat::spawn_service_heartbeat(db.clone(), heartbeat_config);

    // VERP v2 secret requirement (mirrors the MTA's production gate):
    // outbound mail may only carry an AUTHENTICATED bounce Return-Path.
    // Without the shared secret the worker emits NO VERP at all — it never
    // falls back to the unsigned v1 grammar — and production startup refuses
    // the configuration when the email processor is enabled.
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

    let mut handles = vec![];
    let mut analytics_processor: Option<Arc<AnalyticsProcessor>> = None;
    let mut email_processor: Option<Arc<EmailProcessor>> = None;
    let mut reply_processor: Option<Arc<ReplyHandler>> = None;
    let mut webhook_processor: Option<Arc<WebhookProcessor>> = None;

    // Start analytics processor
    if run_analytics {
        let config = AnalyticsConfig {
            base: ProcessorConfig {
                name: "analytics".to_string(),
                concurrency,
                poll_interval,
                ..Default::default()
            },
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
    if run_email {
        // Choose transport backend via EMAIL_TRANSPORT_TYPE env var.
        // Only `smtp` selects SMTP; SES is the default for every other value.
        let transport_type = env::var("EMAIL_TRANSPORT_TYPE")
            .map(|v| TransportType::from_env(&v))
            .unwrap_or_default();

        info!(transport = ?transport_type, "Email transport backend selected");

        // Only require SMTP_HOST when the SMTP transport is actually in use.
        // With the SES transport the SMTP settings are never exercised, so we
        // fall back to a harmless local default instead of crash-looping the
        // whole worker binary at startup.
        let smtp_host = match env::var("SMTP_HOST") {
            Ok(h) if !h.is_empty() => h,
            Ok(_) | Err(_) => {
                if transport_type == TransportType::Smtp {
                    return Err(anyhow::anyhow!(
                        "SMTP_HOST environment variable must be set when EMAIL_TRANSPORT_TYPE=smtp"
                    ));
                }
                // Leave the deliberately invalid sentinel host in place: the
                // hybrid dispatcher must know the relay is NOT configured, so
                // dedicated-route sends defer before DATA instead of being
                // routed at a defaulted/localhost address.
                warn!(
                    "SMTP_HOST not set; SES shared-pool transport selected — dedicated \
                     delivery routes (dedicated_ips rows) will defer until a relay is configured"
                );
                SmtpConfig::default().host
            }
        };

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

        let config = EmailConfig {
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
        };

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
    if run_reply_handler {
        let config = ReplyHandlerConfig {
            base: ProcessorConfig {
                name: "reply-handler".to_string(),
                concurrency,
                poll_interval,
                ..Default::default()
            },
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
    if run_webhook {
        let config = WebhookConfig {
            base: ProcessorConfig {
                name: "webhook".to_string(),
                concurrency,
                poll_interval,
                ..Default::default()
            },
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

    // Start health check server for Kubernetes probes. Honors HEALTH_PORT and
    // falls back to METRICS_PORT (the compose file configures 9093) so the
    // container healthcheck and the listener always agree.
    let health_port: u16 = env::var("HEALTH_PORT")
        .ok()
        .and_then(|s| s.parse().ok())
        .or_else(|| env::var("METRICS_PORT").ok().and_then(|s| s.parse().ok()))
        .unwrap_or(9090);

    let metrics_handler = metrics_handle.clone();
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
    let health_addr = SocketAddr::from(([0, 0, 0, 0], health_port));
    let health_listener = tokio::net::TcpListener::bind(health_addr).await?;
    info!(port = health_port, "Health check server listening");
    tokio::spawn(async move {
        if let Err(e) = axum::serve(health_listener, health_app).await {
            error!(error = %e, "Health check server failed");
        }
    });

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

    if let Some(processor) = &analytics_processor {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop analytics processor");
        }
    }
    if let Some(processor) = &email_processor {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop email processor");
        }
    }
    if let Some(processor) = &reply_processor {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop reply handler");
        }
    }
    if let Some(processor) = &webhook_processor {
        if let Err(e) = processor.stop().await {
            warn!(error = %e, "Failed to stop webhook processor");
        }
    }

    let shutdown_timeout = Duration::from_secs(10);
    let join_all = async {
        for handle in handles {
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
    heartbeat.abort();

    info!("Worker stopped");
    Ok(())
}
