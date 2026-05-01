//! DevEx service entry point.

use anyhow::{Context, Result};
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use devex_service::config::DevExConfig;
use devex_service::routes::{build_router, AppState};

#[tokio::main]
async fn main() -> Result<()> {
    // ── Structured logging ────────────────────────────────────────────
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_default_env().add_directive("devex_service=info".parse()?))
        .init();

    info!("ApexMail DevEx Service starting");

    // ── Config ────────────────────────────────────────────────────────
    let _ = dotenvy::dotenv(); // ignore missing .env
    let cfg = DevExConfig::from_env().context("Failed to load DevEx configuration")?;
    let addr = format!("{}:{}", cfg.host, cfg.port);

    info!(
        host = %cfg.host,
        port = cfg.port,
        api_version = %cfg.current_api_version,
        "Configuration loaded"
    );

    // ── App state + router ────────────────────────────────────────────
    let state = AppState::from_config(cfg).context("Failed to build DevEx app state")?;
    let router = build_router(state);

    // ── Bind & serve ──────────────────────────────────────────────────
    let listener = tokio::net::TcpListener::bind(&addr)
        .await
        .context(format!("Failed to bind to {addr}"))?;

    info!(%addr, "DevEx service listening");

    axum::serve(listener, router)
        .with_graceful_shutdown(shutdown_signal())
        .await
        .context("Server error")?;

    info!("DevEx service stopped");
    Ok(())
}

async fn shutdown_signal() {
    let ctrl_c = async {
        if let Err(err) = signal::ctrl_c().await {
            warn!(error = %err, "Failed to install Ctrl+C handler");
        }
    };

    #[cfg(unix)]
    let terminate = async {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut term) => {
                term.recv().await;
            }
            Err(err) => {
                warn!(error = %err, "Failed to install SIGTERM handler");
            }
        }
    };

    #[cfg(not(unix))]
    let terminate = std::future::pending::<()>();

    tokio::select! {
        _ = ctrl_c => {},
        _ = terminate => {},
    }

    info!("Shutdown signal received");
}
