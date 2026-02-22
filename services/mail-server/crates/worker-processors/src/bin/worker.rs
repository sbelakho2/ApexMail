//! Worker entry point — runs all processors.

use std::env;
use std::sync::Arc;
use std::time::Duration;

use anyhow::Result;
use deadpool_redis::{Config as RedisConfig, Runtime};
use sqlx::postgres::PgPoolOptions;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use worker_processors::{
    common::{
        AnalyticsConfig, EmailConfig, ProcessorConfig, ReplyHandlerConfig, SmtpConfig,
        WebhookConfig,
    },
    AnalyticsProcessor, EmailProcessor, ReplyHandler, WebhookProcessor,
};

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .init();

    info!("Starting ApexMail Worker (Rust)");

    // Load configuration from environment
    let database_url = env::var("DATABASE_URL").expect("DATABASE_URL must be set");
    let redis_url = env::var("REDIS_URL").unwrap_or_else(|_| "redis://localhost:6379".to_string());

    // Create database pool
    let db = PgPoolOptions::new()
        .max_connections(30)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&database_url)
        .await?;

    info!("Connected to PostgreSQL");

    // Create Redis pool
    let redis_cfg = RedisConfig::from_url(&redis_url);
    let redis = redis_cfg.create_pool(Some(Runtime::Tokio1))?;

    info!("Connected to Redis");

    // Load concurrency from env
    let concurrency = env::var("WORKER_CONCURRENCY")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(10);

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
        info!("Analytics processor started");
    }

    // Start email processor
    if run_email {
        let smtp_config = SmtpConfig {
            host: env::var("SMTP_HOST").unwrap_or_else(|_| "localhost".to_string()),
            port: env::var("SMTP_PORT")
                .ok()
                .and_then(|s| s.parse().ok())
                .unwrap_or(587),
            secure: env::var("SMTP_TLS")
                .map(|v| v == "true" || v == "1")
                .unwrap_or(true),
            username: env::var("SMTP_USERNAME").ok(),
            password: env::var("SMTP_PASSWORD").ok(),
            ..Default::default()
        };

        let config = EmailConfig {
            base: ProcessorConfig {
                name: "email".to_string(),
                concurrency,
                poll_interval,
                ..Default::default()
            },
            smtp: smtp_config,
            ..Default::default()
        };

        match EmailProcessor::new(db.clone(), redis.clone(), config) {
            Ok(processor) => {
                let processor = Arc::new(processor);
                let p = Arc::clone(&processor);
                handles.push(tokio::spawn(async move {
                    if let Err(e) = p.start().await {
                        error!(error = %e, "Email processor failed");
                    }
                }));
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
                info!("Webhook processor started");
            }
            Err(e) => {
                error!(error = %e, "Failed to create webhook processor");
            }
        }
    }

    info!("All processors running. Press Ctrl+C to stop.");

    // Wait for shutdown signal
    tokio::signal::ctrl_c().await?;

    info!("Shutting down...");

    // All processors will exit gracefully when their tasks are cancelled
    for handle in handles {
        handle.abort();
    }

    info!("Worker stopped");
    Ok(())
}
