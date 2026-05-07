use clap::Parser;
use std::sync::Arc;
use tracing_subscriber::{fmt, EnvFilter};

use ai_embeddings::config::*;
use ai_embeddings::embeddings::EmbeddingService;
use ai_embeddings::routes::{self, AppState};
use ai_embeddings::vector_store::VectorStore;

#[derive(Parser)]
#[command(
    name = "ai-embeddings",
    about = "AI embedding and vector search service"
)]
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

    /// HMAC-SHA256 key for NDJSON persistence integrity (hex-encoded 32 bytes)
    #[arg(long, env = "PERSISTENCE_HMAC_KEY", default_value = "")]
    persistence_hmac_key: String,

    /// Enable TLS verification for inference sidecar. Auto-enabled when
    /// INFERENCE_URL uses https://; auto-disabled for http://. Override
    /// explicitly with SIDECAR_TLS_ENABLED=true|false.
    #[arg(long, env = "SIDECAR_TLS_ENABLED")]
    sidecar_tls_enabled: Option<bool>,

    /// Optional path to a custom CA certificate (PEM) for sidecar TLS.
    #[arg(long, env = "SIDECAR_TLS_CA_PATH", default_value = "")]
    sidecar_tls_ca_path: String,
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    dotenvy::dotenv().ok();
    fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .json()
        .init();

    let cli = Cli::parse();

    // Decode hex-encoded HMAC key
    let hmac_key_bytes = if cli.persistence_hmac_key.is_empty() {
        Vec::new()
    } else {
        hex::decode(&cli.persistence_hmac_key)
            .map_err(|e| anyhow::anyhow!("PERSISTENCE_HMAC_KEY must be a valid hex string: {e}"))?
    };

    let config = EmbeddingsConfig {
        server: ServerConfig {
            host: cli.host.clone(),
            port: cli.port,
        },
        inference: InferenceConfig {
            url: cli.inference_url.clone(),
            model: "all-MiniLM-L6-v2".to_string(),
            dimension: cli.dimension,
            max_concurrency: 8,
            timeout_ms: 30_000,
            pooling: PoolingStrategy::Mean,
            sidecar_tls_enabled: cli
                .sidecar_tls_enabled
                .unwrap_or_else(|| cli.inference_url.starts_with("https://")),
            sidecar_tls_ca_path: cli.sidecar_tls_ca_path,
        },
        store: StoreConfig {
            max_vectors: cli.max_vectors,
            eviction_threshold: (cli.max_vectors as f64 * 0.9) as usize,
            persistence_hmac_key: cli.persistence_hmac_key,
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
            hmac_key_bytes,
        ),
        config,
        service_token: {
            let token = std::env::var("INTERNAL_SERVICE_TOKEN").unwrap_or_default();
            if token.is_empty() {
                tracing::warn!(
                    "INTERNAL_SERVICE_TOKEN is not set — internal auth is effectively disabled"
                );
            }
            token
        },
    });

    let app = routes::router(state);
    let addr = format!("{}:{}", cli.host, cli.port);
    tracing::info!("AI embeddings service listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(&addr).await?;

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
    axum::serve(listener, app)
        .with_graceful_shutdown(shutdown)
        .await?;

    Ok(())
}
