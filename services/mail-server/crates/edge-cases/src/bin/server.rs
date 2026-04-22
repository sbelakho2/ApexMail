//! Binary entry-point for the edge-cases server.

use std::net::SocketAddr;
use std::sync::Arc;

use axum::http::header;
use tower_http::cors::{Any, CorsLayer};
use tracing::info;

use edge_cases::config::EdgeCasesConfig;
use edge_cases::routes::{self, AppState};
use edge_cases::services::{
    attachment::AttachmentService,
    calendar::CalendarService,
    delivery::DeliveryService,
    eai::EAIService,
};

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    let config = EdgeCasesConfig::from_env()?;
    info!(port = config.port, "Starting edge-cases server");

// Database pool
    let pool = sqlx::postgres::PgPoolOptions::new()
        .max_connections(20)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&config.database_url)
        .await?;

// Redis pool
    let redis_cfg = deadpool_redis::Config::from_url(&config.redis_url);
    let redis_pool = redis_cfg
        .create_pool(Some(deadpool_redis::Runtime::Tokio1))
        .expect("Failed to create redis pool");

// Build services
    let eai = EAIService::new(pool.clone(), redis_pool.clone());
    let attachment = AttachmentService::new(
        pool.clone(),
        config.attachments.clone(),
        config.clamav.clone(),
    );
    let calendar = CalendarService::new(pool.clone());
    let delivery = DeliveryService::new(
        pool.clone(),
        redis_pool.clone(),
        config.retry.clone(),
        config.loop_detection.clone(),
        &config.auto_responder.subject_patterns,
    );

    let state = Arc::new(AppState {
        eai,
        attachment,
        calendar,
        delivery,
        api_key: config.api_key.clone(),
    });

    let mut cors = CorsLayer::new()
        .allow_methods(Any)
        .allow_headers(vec![
            header::CONTENT_TYPE,
            header::AUTHORIZATION,
        ]);
    if config.node_env == "development" {
        cors = cors.allow_origin(Any);
    }

    let app = routes::router(state).layer(cors);

    let addr = SocketAddr::from(([0, 0, 0, 0], config.port));
    info!(%addr, "Listening");

    let listener = tokio::net::TcpListener::bind(addr).await?;

    let shutdown = async {
        let ctrl_c = async { let _ = tokio::signal::ctrl_c().await; };
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
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}
