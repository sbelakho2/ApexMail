//! MTA binary – starts inbound, bounce, and feedback‑loop servers with health endpoint.

use std::sync::Arc;

use axum::{routing::get, Router};
use clap::Parser;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use sqlx::postgres::PgPoolOptions;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use mta::auth::EmailAuthenticator;
use mta::config::MtaConfig;
use mta::servers::{BounceServer, FeedbackLoopServer, InboundServer, SubmissionServer};

#[derive(Parser)]
#[command(name = "mta-server", about = "ApexMail MTA Server")]
struct Cli {
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    // Initialize tracing (with OTLP support)
    let _tracing_guard = init_tracing(&cli.log_level);

    let config = MtaConfig::from_env()?;
    info!(mta_id = %config.mta_id, "Starting MTA server");

    // Database pool
    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&config.database.connection_string)
        .await?;

    // Redis pool
    let redis_cfg = deadpool_redis::Config::from_url(&config.redis.url);
    let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    // TLS acceptor (optional)
    let tls_acceptor = if config.inbound.tls.enabled {
        let cert_path = config
            .inbound
            .tls
            .cert_path
            .as_deref()
            .unwrap_or("cert.pem");
        let key_path = config.inbound.tls.key_path.as_deref().unwrap_or("key.pem");
        Some(load_tls_acceptor(cert_path, key_path)?)
    } else {
        None
    };

    // Email authenticator
    let authenticator = Arc::new(
        EmailAuthenticator::new(config.email_auth.clone(), config.inbound.hostname.clone()).await?,
    );

    // Health server
    let health_pool = pool.clone();
    let health_redis = redis_pool.clone();
    let health_port = config.health_port;
    // #152:Store health server handle for proper shutdown
    let health_handle = tokio::spawn(async move {
        let app = Router::new()
            .route("/health", get(|| async { "OK" }))
            .route(
                "/ready",
                get(move || {
                    let p = health_pool.clone();
                    let r = health_redis.clone();
                    async move {
                        let db_ok = sqlx::query("SELECT 1").execute(&p).await.is_ok();
                        let redis_ok = r.get().await.is_ok();
                        if db_ok && redis_ok {
                            (axum::http::StatusCode::OK, "ready")
                        } else {
                            (axum::http::StatusCode::SERVICE_UNAVAILABLE, "not ready")
                        }
                    }
                }),
            );
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{health_port}")).await;
        let listener = match listener {
            Ok(listener) => listener,
            Err(error) => {
                error!(error = %error, port = health_port, "Failed to bind health listener");
                return;
            }
        };
        info!(port = health_port, "Health server listening");
        axum::serve(listener, app).await.ok();
    });

    // Inbound server
    // #151:Keep server references for graceful stop calls
    let (inbound_srv, inbound_handle) = if config.inbound.enabled {
        let srv = Arc::new(InboundServer::new(
            config.inbound.clone(),
            config.rate_limit.clone(),
            pool.clone(),
            redis_pool.clone(),
            authenticator.clone(),
            config.inbound.hostname.clone(),
        ));
        let s = srv.clone();
        let tls = tls_acceptor.clone();
        (
            Some(srv),
            Some(tokio::spawn(async move {
                if let Err(e) = s.start(tls).await {
                    error!(error = %e, "Inbound server failed");
                }
            })),
        )
    } else {
        (None, None)
    };

    // Bounce server
    let (bounce_srv, bounce_handle) = if config.bounce.enabled {
        let srv = Arc::new(BounceServer::new(
            config.bounce.clone(),
            pool.clone(),
            redis_pool.clone(),
            config.bounce.hostname.clone(),
        ));
        let s = srv.clone();
        (
            Some(srv),
            Some(tokio::spawn(async move {
                if let Err(e) = s.start().await {
                    error!(error = %e, "Bounce server failed");
                }
            })),
        )
    } else {
        (None, None)
    };

    // Feedback loop server
    let (fbl_srv, fbl_handle) = if config.feedback.enabled {
        let srv = Arc::new(FeedbackLoopServer::new(
            config.feedback.clone(),
            pool.clone(),
            redis_pool.clone(),
            config.feedback.hostname.clone(),
            &[],
        ));
        let s = srv.clone();
        (
            Some(srv),
            Some(tokio::spawn(async move {
                if let Err(e) = s.start().await {
                    error!(error = %e, "FBL server failed");
                }
            })),
        )
    } else {
        (None, None)
    };

    // Submission server (authenticated SMTP on port 587)
    let (submission_srv, submission_handle) = if config.submission.enabled {
        let srv = Arc::new(SubmissionServer::new(
            config.submission.clone(),
            pool.clone(),
        ));
        let s = srv.clone();
        (
            Some(srv),
            Some(tokio::spawn(async move {
                if let Err(e) = s.start().await {
                    error!(error = %e, "Submission server failed");
                }
            })),
        )
    } else {
        (None, None)
    };

    // Postmaster Tools / SNDS reputation poller (background, never aborts startup).
    let postmaster_pool = pool.clone();
    let postmaster_redis = redis_pool.clone();
    let _postmaster_handle = tokio::spawn(async move {
        // The resolver pulls plaintext secrets from the compliance secret_manager
        // via Redis pub/sub if available, falling back to the raw value of the
        // referenced env var. Failure here is logged but does not stop the poll.
        let resolver: mta::postmaster::scheduler::SecretResolver =
            std::sync::Arc::new(move |secret_ref: String| {
                let r = postmaster_redis.clone();
                Box::pin(async move {
                    if let Ok(mut conn) = r.get().await {
                        let key = format!("compliance:secrets:{}:plaintext", secret_ref);
                        let v: Result<Option<String>, _> =
                            redis::cmd("GET").arg(&key).query_async(&mut *conn).await;
                        if let Ok(Some(val)) = v {
                            return Ok(val);
                        }
                    }
                    // Last-resort fallback: env var with the secret_ref name.
                    std::env::var(&secret_ref).map_err(|_| {
                        format!("secret_ref '{secret_ref}' not found in Redis or env",)
                    })
                })
            });
        let cfg = mta::postmaster::scheduler::ScheduleConfig::default();
        info!(
            "Postmaster reputation poller starting (interval = {:?})",
            cfg.interval
        );
        let handle = mta::postmaster::scheduler::spawn(postmaster_pool, cfg, resolver);
        if let Err(e) = handle.await {
            error!(error = %e, "Postmaster scheduler exited");
        }
    });

    // Wait for shutdown signal (SIGINT or SIGTERM)
    info!("MTA server running. Waiting for shutdown signal.");
    {
        let ctrl_c = async {
            let _ = signal::ctrl_c().await;
        };
        #[cfg(unix)]
        let terminate = async {
            match signal::unix::signal(signal::unix::SignalKind::terminate()) {
                Ok(mut sig) => sig.recv().await,
                Err(e) => {
                    tracing::error!(error = %e, "failed to install SIGTERM handler, waiting indefinitely");
                    std::future::pending().await
                }
            }
        };
        #[cfg(not(unix))]
        let terminate = std::future::pending::<()>();
        tokio::select! {
            _ = ctrl_c => info!("received Ctrl+C"),
            _ = terminate => info!("received SIGTERM"),
        }
    }
    info!("Shutting down...");

    // #151:Signal graceful shutdown on all servers before aborting
    if let Some(ref srv) = inbound_srv {
        srv.stop();
    }
    if let Some(ref srv) = bounce_srv {
        srv.stop();
    }
    if let Some(ref srv) = fbl_srv {
        srv.stop();
    }
    if let Some(ref srv) = submission_srv {
        srv.stop();
    }

    // #150:Use .max(5) so grace period is AT LEAST 5s (was .min(5) = at most 5s)
    let grace = std::time::Duration::from_secs(config.graceful_shutdown_timeout.max(5));
    let _ = tokio::time::timeout(grace, async {
        if let Some(h) = inbound_handle {
            let _ = h.await;
        }
        if let Some(h) = bounce_handle {
            let _ = h.await;
        }
        if let Some(h) = fbl_handle {
            let _ = h.await;
        }
        if let Some(h) = submission_handle {
            let _ = h.await;
        }
    })
    .await;

    // #152:Abort health server last
    health_handle.abort();

    pool.close().await;
    info!("MTA server stopped");
    Ok(())
}

fn load_tls_acceptor(cert_path: &str, key_path: &str) -> anyhow::Result<tokio_rustls::TlsAcceptor> {
    use rustls_pemfile::{certs, private_key};
    use std::fs::File;
    use std::io::BufReader;
    use tokio_rustls::rustls;

    let cert_file = File::open(cert_path)?;
    let key_file = File::open(key_path)?;

    let certs: Vec<_> = certs(&mut BufReader::new(cert_file))
        .filter_map(|c| c.ok())
        .collect();
    let key = private_key(&mut BufReader::new(key_file))?
        .ok_or_else(|| anyhow::anyhow!("No private key found in {key_path}"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)?;

    Ok(tokio_rustls::TlsAcceptor::from(Arc::new(config)))
}

/// Initialize tracing subscriber with OTLP support.
/// Falls back to JSON logging when OTLP is not configured.
fn init_tracing(log_level: &str) -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "mta-server".into(),
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
        .json()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level)),
        )
        .init();
    None
}
