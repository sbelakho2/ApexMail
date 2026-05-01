//! AI service binary entry-point.

use std::sync::Arc;
use tracing_subscriber::EnvFilter;

use ai_service::{config::AiConfig, routes};

#[tokio::main]
async fn main() {
    // Initialise structured logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();

    let config = match AiConfig::from_env() {
        Ok(cfg) => cfg,
        Err(err) => {
            tracing::error!(error = %err, "invalid AI configuration");
            return;
        }
    };
    tracing::info!(
        endpoint = %config.model_endpoint,
        embedding_dim = config.embedding_dim,
        "starting AI service"
    );

    let state = match routes::AppState::new(config) {
        Ok(state) => Arc::new(state),
        Err(err) => {
            tracing::error!(error = %err, "failed to initialize AI service state");
            return;
        }
    };
    let app = routes::build_router(state);

    let bind = std::env::var("AI_BIND").unwrap_or_else(|_| "0.0.0.0:3012".into());
    let listener = match tokio::net::TcpListener::bind(&bind).await {
        Ok(listener) => listener,
        Err(err) => {
            tracing::error!(error = %err, %bind, "failed to bind TCP listener");
            return;
        }
    };
    tracing::info!(%bind, "AI service listening");

    let shutdown = async {
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
            _ = ctrl_c => tracing::info!("received Ctrl+C — shutting down"),
            _ = terminate => tracing::info!("received SIGTERM — shutting down"),
        }
    };
    if let Err(err) = axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await
    {
        tracing::error!(error = %err, "AI service failed");
    }
}
