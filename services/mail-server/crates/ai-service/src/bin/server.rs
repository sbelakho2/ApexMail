//! AI service binary entry-point.

use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use tracing_subscriber::EnvFilter;

use ai_service::routes;

fn init_tracing() -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "ai-service".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new("info")),
        )
        .json()
        .init();
    None
}

#[tokio::main]
async fn main() {
    let _guard = init_tracing();

    tracing::info!("starting AI intelligence service");

    let state = match routes::default_app_state().await {
        Ok(state) => state,
        Err(error) => {
            tracing::error!(%error, "invalid AI service configuration");
            return;
        }
    };
    // Mailbot runtime (SalesCloser plan §5.3): the DRAFT-ONLY email agent
    // runs in THIS process, over the same pool, model client and inference
    // governor the HTTP surfaces use. Opt-in (AI_EMAIL_AGENT_ENABLED); it
    // refuses to start without mandatory human approval — every generated
    // reply is stored as a pending draft for the review queue, never sent.
    match ai_service::email_agent::EmailAnswerer::from_env_with_runtime(
        state.docs_pool.clone(),
        state.llm.clone(),
        state.rate_governor.clone(),
    ) {
        Ok(Some(answerer)) => {
            let answerer = std::sync::Arc::new(answerer);
            if answerer.clone().start() {
                tracing::info!("email answering agent started (draft-only, approval required)");
            }
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, "email answering agent not started");
        }
    }

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
