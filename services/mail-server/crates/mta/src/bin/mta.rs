//! MTA binary – starts inbound, bounce, and feedback‑loop servers with health endpoint.

use std::sync::Arc;

use axum::{routing::get, Router};
use clap::Parser;
use sqlx::postgres::PgPoolOptions;
use tokio::signal;
use tracing::{error, info};
use tracing_subscriber::EnvFilter;

use mta::config::MtaConfig;
use mta::auth::EmailAuthenticator;
use mta::servers::{BounceServer, FeedbackLoopServer, InboundServer};

#[derive(Parser)]
#[command(name = "mta-server", about = "ApexMail MTA Server")]
struct Cli {
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let cli = Cli::parse();

    tracing_subscriber::fmt()
        .json()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            EnvFilter::new(&cli.log_level)
        }))
        .init();

    let config = MtaConfig::from_env()?;
    info!(mta_id = %config.mta_id, "Starting MTA server");

    // Database pool
    let pool = PgPoolOptions::new()
        .max_connections(config.database.max_connections)
        .connect(&config.database.connection_string)
        .await?;

    // Redis pool
    let redis_cfg = deadpool_redis::Config::from_url(&config.redis.url);
    let redis_pool = redis_cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))?;

    // TLS acceptor (optional)
    let tls_acceptor = if config.inbound.tls.enabled {
        let cert_path = config.inbound.tls.cert_path.as_deref().unwrap_or("cert.pem");
        let key_path = config.inbound.tls.key_path.as_deref().unwrap_or("key.pem");
        Some(load_tls_acceptor(cert_path, key_path)?)
    } else {
        None
    };

    // Email authenticator
    let authenticator = Arc::new(
        EmailAuthenticator::new(config.email_auth.clone(), config.inbound.hostname.clone())
            .await?,
    );

    // Health server
    let health_pool = pool.clone();
    let health_redis = redis_pool.clone();
    let health_port = config.health_port;
    // #152: Store health server handle for proper shutdown
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
        let listener = tokio::net::TcpListener::bind(format!("0.0.0.0:{health_port}"))
            .await
            .expect("health listener");
        info!(port = health_port, "Health server listening");
        axum::serve(listener, app).await.ok();
    });

    // Inbound server
    // #151: Keep server references for graceful stop() calls
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
        (Some(srv), Some(tokio::spawn(async move {
            if let Err(e) = s.start(tls).await {
                error!(error = %e, "Inbound server failed");
            }
        })))
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
        (Some(srv), Some(tokio::spawn(async move {
            if let Err(e) = s.start().await {
                error!(error = %e, "Bounce server failed");
            }
        })))
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
        (Some(srv), Some(tokio::spawn(async move {
            if let Err(e) = s.start().await {
                error!(error = %e, "FBL server failed");
            }
        })))
    } else {
        (None, None)
    };

    // Wait for shutdown signal
    info!("MTA server running. Press Ctrl+C to stop.");
    signal::ctrl_c().await?;
    info!("Shutting down...");

    // #151: Signal graceful shutdown on all servers before aborting
    if let Some(ref srv) = inbound_srv { srv.stop(); }
    if let Some(ref srv) = bounce_srv { srv.stop(); }
    if let Some(ref srv) = fbl_srv { srv.stop(); }

    // #150: Use .max(5) so grace period is AT LEAST 5s (was .min(5) = at most 5s)
    let grace = std::time::Duration::from_secs(config.graceful_shutdown_timeout.max(5));
    let _ = tokio::time::timeout(grace, async {
        if let Some(h) = inbound_handle { let _ = h.await; }
        if let Some(h) = bounce_handle { let _ = h.await; }
        if let Some(h) = fbl_handle { let _ = h.await; }
    }).await;

    // #152: Abort health server last
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
