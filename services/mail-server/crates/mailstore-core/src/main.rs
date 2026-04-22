//! Mailstore Service
//!
//! Provides message storage and retrieval functionality.

use std::sync::Arc;
use anyhow::Result;
use clap::Parser;
use tonic::transport::Server;
use tracing::info;
use tracing_subscriber::EnvFilter;

use mail_proto::MailstoreServiceServer;
use mailstore_core::{MessageStorage, MailstoreServiceImpl};

#[derive(Parser)]
#[command(name = "mailstore")]
#[command(about = "Mailstore Service - Message storage and retrieval")]
struct Cli {
/// gRPC listen address
    #[arg(short, long, default_value = "0.0.0.0:50051")]
    listen: String,
    
/// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    
/// Log level
    #[arg(long, default_value = "info")]
    log_level: String,
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();
    
// Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cli.log_level));
    
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
    
    info!("Starting Mailstore Service");
    info!("Listen address: {}", cli.listen);
    
// Connect to database
    let pool = sqlx::PgPool::connect(&cli.database_url).await?;
    info!("Connected to database");
    
// Create storage
    let storage = Arc::new(MessageStorage::new(pool));
    storage.initialize().await?;
    
// Create gRPC service
    let service = MailstoreServiceImpl::new(storage);
    
// Start gRPC server
    let addr = cli.listen.parse()?;
    info!("Starting gRPC server on {}", addr);
    
    Server::builder()
        .add_service(MailstoreServiceServer::new(service))
        .serve_with_shutdown(addr, async {
            tokio::signal::ctrl_c().await.ok();
            info!("Shutdown signal received");
        })
        .await?;
    
    info!("Mailstore Service stopped");
    Ok(())
}
