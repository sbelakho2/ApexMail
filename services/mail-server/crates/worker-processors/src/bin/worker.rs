//! Worker entry point — runs all processors.

use std::env;
use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use axum::{routing::get, Router};
use deadpool_redis::{Config as RedisConfig, Runtime};
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use sqlx::postgres::PgPoolOptions;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

use worker_processors::{
    common::{
        AnalyticsConfig, DkimConfig, EmailConfig, ProcessorConfig, ReplyHandlerConfig,
        SmtpConfig, TransportType, WebhookConfig,
    },
    AnalyticsProcessor, EmailProcessor, ReplyHandler, WebhookProcessor,
};

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

    // Install the ring crypto provider for rustls BEFORE any TLS use.
    // The workspace enables rustls with the `ring` feature, but other
    // dependencies (reqwest/rustls-tls, redis/tokio-rustls-comp) can pull
    // rustls in with aws-lc-rs too, leaving no unambiguous process-level
    // default. Without an explicit install, the first TLS connection
    // panics with "Could not automatically determine the process-level
    // CryptoProvider" and kills the email processor task.
    let _ = rustls::crypto::ring::default_provider().install_default();

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
            if let Err(e) = p.start().await {
                error!(error = %e, "Analytics processor failed");
            }
        }));
        analytics_processor = Some(processor);
        info!("Analytics processor started");
    }

    // Start email processor
    if run_email {
        let smtp_config = SmtpConfig {
            host: env::var("SMTP_HOST").map_err(|_| {
                anyhow::anyhow!("SMTP_HOST environment variable must be set for email processing")
            })?,
            port: env::var("SMTP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(587),
            secure: env::var("SMTP_TLS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
            username: env::var("SMTP_USERNAME")
                .ok()
                .filter(|s| !s.is_empty()),
            password: env::var("SMTP_PASSWORD")
                .ok()
                .filter(|s| !s.is_empty())
                .map(zeroize::Zeroizing::new),
            ..Default::default()
        };

        // Choose transport backend via EMAIL_TRANSPORT_TYPE env var.
        // Values:"ses" (default), "smtp" / "self-hosted" / "direct".
        let transport_type = env::var("EMAIL_TRANSPORT_TYPE")
            .map(|v| TransportType::from_env(&v))
            .unwrap_or_default();

        info!(transport = ?transport_type, "Email transport backend selected");

        let config = EmailConfig {
            base: ProcessorConfig {
                name: "email".to_string(),
                concurrency,
                poll_interval,
                ..Default::default()
            },
            transport_type,
            smtp: smtp_config,
            dkim: DkimConfig {
                enabled: env::var("DKIM_ENABLED")
                    .map(|v| v == "true" || v == "1")
                    .unwrap_or(false),
                selector: env::var("DKIM_SELECTOR").unwrap_or_else(|_| "apexmail2026".into()),
                key_path: env::var("DKIM_KEY_PATH").ok().filter(|s| !s.is_empty()),
                domain: env::var("DKIM_DOMAIN").ok().filter(|s| !s.is_empty()),
            },
            ..Default::default()
        };

        match EmailProcessor::new(db.clone(), redis.clone(), config).await {
            Ok(processor) => {
                let processor = Arc::new(processor);
                let p = Arc::clone(&processor);
                handles.push(tokio::spawn(async move {
                    if let Err(e) = p.start().await {
                        error!(error = %e, "Email processor failed");
                    }
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
            if let Err(e) = p.start().await {
                error!(error = %e, "Reply handler failed");
            }
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
                    if let Err(e) = p.start().await {
                        error!(error = %e, "Webhook processor failed");
                    }
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

    let health_app = Router::new().route("/health", get(|| async { "OK" }));
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

    info!("Worker stopped");
    Ok(())
}
