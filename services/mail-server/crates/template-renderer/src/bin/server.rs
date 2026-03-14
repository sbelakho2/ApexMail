use std::sync::Arc;
use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

use template_renderer::config::*;
use template_renderer::sandbox::Sandbox;
use template_renderer::cache::TemplateCache;
use template_renderer::routes::{self, AppState};

#[derive(Parser)]
#[command(name = "template-renderer", about = "Email template rendering service")]
struct Cli {
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,

    #[arg(long, env = "HOST", default_value = "0.0.0.0")]
    host: String,

    #[arg(long, env = "PORT", default_value = "9080")]
    port: u16,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();

    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let cli = Cli::parse();

    tracing::info!("Connecting to database...");
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(10)
        .acquire_timeout(std::time::Duration::from_secs(10))
        .idle_timeout(std::time::Duration::from_secs(300))
        .max_lifetime(std::time::Duration::from_secs(1800))
        .connect(&cli.database_url)
        .await?;

    let config = RendererConfig {
        db: DatabaseConfig {
            url: cli.database_url,
            max_connections: 10,
        },
        server: ServerConfig {
            host: cli.host.clone(),
            port: cli.port,
        },
        sandbox: SandboxConfig {
            timeout_ms: 5000,
            max_memory_bytes: 64 * 1024 * 1024,
            max_source_length: 512 * 1024,
            max_output_length: 2 * 1024 * 1024,
        },
        cache: CacheConfig {
            max_entries: 1000,
            ttl_secs: 3600,
        },
    };

    if let Err(err) = config.validate() {
        anyhow::bail!("Invalid renderer config: {err}");
    }

    let state = Arc::new(AppState {
        db,
        sandbox: Sandbox::new(config.sandbox.clone()),
        cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
        config,
        service_token: {
            let token = std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default();
            if token.is_empty() {
                tracing::warn!("INTERNAL_SERVICE_TOKEN is not set — internal auth is effectively disabled");
            }
            token
        },
    });

    let app = routes::router(state);
    let addr = format!("{}:{}", cli.host, cli.port);
    tracing::info!("Template renderer listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

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
