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

    let config = AiConfig::from_env();
    tracing::info!(
        endpoint = %config.model_endpoint,
        embedding_dim = config.embedding_dim,
        "starting AI service"
    );

    let state = Arc::new(routes::AppState::new(config));
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

    if let Err(err) = axum::serve(listener, app).await {
        tracing::error!(error = %err, "AI service failed");
    }
}
