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
    let db = sqlx::PgPool::connect(&cli.database_url).await?;

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

    let state = Arc::new(AppState {
        db,
        sandbox: Sandbox::new(config.sandbox.clone()),
        cache: TemplateCache::new(config.cache.max_entries, config.cache.ttl_secs),
        config,
    });

    let app = routes::router(state);
    let addr = format!("{}:{}", cli.host, cli.port);
    tracing::info!("Template renderer listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
