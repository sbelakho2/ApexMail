use std::sync::Arc;
use clap::Parser;
use tracing_subscriber::{fmt, EnvFilter};

use ai_embeddings::config::*;
use ai_embeddings::embeddings::EmbeddingService;
use ai_embeddings::vector_store::VectorStore;
use ai_embeddings::routes::{self, AppState};

#[derive(Parser)]
#[command(name = "ai-embeddings", about = "AI embedding and vector search service")]
struct Cli {
    #[arg(long, env = "INFERENCE_URL", default_value = "http://localhost:8080")]
    inference_url: String,

    #[arg(long, env = "HOST", default_value = "0.0.0.0")]
    host: String,

    #[arg(long, env = "PORT", default_value = "9090")]
    port: u16,

    #[arg(long, env = "DIMENSION", default_value = "384")]
    dimension: usize,

    #[arg(long, env = "MAX_VECTORS", default_value = "100000")]
    max_vectors: usize,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    fmt().with_env_filter(EnvFilter::from_default_env()).json().init();

    let cli = Cli::parse();

    let config = EmbeddingsConfig {
        server: ServerConfig {
            host: cli.host.clone(),
            port: cli.port,
        },
        inference: InferenceConfig {
            url: cli.inference_url,
            model: "all-MiniLM-L6-v2".to_string(),
            dimension: cli.dimension,
            max_concurrency: 8,
            timeout_ms: 30_000,
            pooling: PoolingStrategy::Mean,
        },
        store: StoreConfig {
            max_vectors: cli.max_vectors,
            eviction_threshold: (cli.max_vectors as f64 * 0.9) as usize,
        },
    };

    if let Err(err) = config.validate() {
        anyhow::bail!("Invalid embeddings config: {err}");
    }

    let embedding_service = EmbeddingService::new(config.inference.clone())?;
    let state = Arc::new(AppState {
        embedding_service,
        vector_store: VectorStore::new(
            config.inference.dimension,
            config.store.max_vectors,
            config.store.eviction_threshold,
        ),
        config,
    });

    let app = routes::router(state);
    let addr = format!("{}:{}", cli.host, cli.port);
    tracing::info!("AI embeddings service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}
