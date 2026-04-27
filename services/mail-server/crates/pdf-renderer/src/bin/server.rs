//! PDF Renderer standalone service binary.
//!
//! Starts an Axum HTTP server for PDF generation.
//!
//! Usage://! pdf-renderer --port 3004
//! PDF_PORT=3004 pdf-renderer

use clap::Parser;
use tracing::{info, warn};
use tracing_subscriber::EnvFilter;

use pdf_renderer::pdf_router;

#[derive(Parser, Debug)]
#[command(name = "pdf-renderer", about = "ApexMail PDF generation service")]
struct Args {
/// Host to bind to
    #[arg(long, env = "PDF_HOST", default_value = "0.0.0.0")]
    host: String,

/// Port to listen on
    #[arg(long, short, env = "PDF_PORT", default_value_t = 3004)]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

// Initialize tracing
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("info,pdf_renderer=debug")),
        )
        .json()
        .init();

    let args = Args::parse();
    let addr = format!("{}:{}", args.host, args.port);

    info!(addr = %addr, "Starting PDF renderer service");

    let service_token = std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default();
    if service_token.is_empty() {
        warn!("INTERNAL_SERVICE_TOKEN is not set — internal auth is effectively disabled");
    }

    let app = pdf_router(service_token);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    info!(addr = %addr, "PDF renderer service listening");

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
            _ = ctrl_c => info!("received Ctrl+C — shutting down"),
            _ = terminate => info!("received SIGTERM — shutting down"),
        }
    };
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}
