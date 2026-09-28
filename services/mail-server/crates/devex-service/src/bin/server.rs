//! DevEx service entry point.

use anyhow::{Context, Result};
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use tokio::signal;
use tracing::{info, warn};
use tracing_subscriber::{fmt, prelude::*, EnvFilter};

use devex_service::auth::ServiceAuth;
use devex_service::config::DevExConfig;
use devex_service::routes::{build_router, AppState};

fn init_tracing() -> Result<Option<TracingGuard>> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "devex-service".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Ok(Some(guard)),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    tracing_subscriber::registry()
        .with(fmt::layer().json())
        .with(EnvFilter::from_default_env().add_directive("devex_service=info".parse()?))
        .init();
    Ok(None)
}

#[tokio::main]
async fn main() -> Result<()> {
    let _guard = init_tracing()?;

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
    // P1 #6: per-workload credentials. When DEVEX_AUTH_TOKEN is set it is
    // the ONLY accepted secret; when it is unset production boots REFUSE
    // (the per-workload pattern is complete for this service) and
    // non-production boots fall back to the universal token with a
    // required-soon warning. `from_env` is the strict boot check; the
    // identical (lenient) resolution inside `from_config` becomes the
    // state's credential.
    let service_auth = ServiceAuth::from_env()
        .map_err(|reason| anyhow::anyhow!("refusing to start: {reason}"))?;
    if service_auth.dedicated_configured() {
        info!(
            "per-workload auth active: {} is the only accepted credential",
            devex_service::auth::DEDICATED_TOKEN_ENV
        );
    }
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
