//! Submission Server
//!
//! Authenticated SMTP submission server on port 587 for sending emails.
//! This is the entry point for users/applications to submit emails for delivery.

use anyhow::Result;
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::{TcpListener, TcpStream};
use tracing::{debug, error, info, warn};

mod auth;
mod session;

use session::SubmissionSession;

#[derive(Parser, Debug)]
#[command(name = "submission-server")]
#[command(about = "Authenticated SMTP Submission Server")]
struct Args {
    /// Listen address
    #[arg(long, default_value = "0.0.0.0:587")]
    listen: String,
    
    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    
    /// Outbound queue gRPC address
    #[arg(long, default_value = "http://localhost:50052")]
    outbound_url: String,
    
    /// Server hostname
    #[arg(long, default_value = "mail.apexmail.ee")]
    hostname: String,
    
    /// Require authentication
    #[arg(long, default_value = "true")]
    require_auth: bool,
    
    /// Enable STARTTLS
    #[arg(long, default_value = "true")]
    enable_starttls: bool,
}

/// Server state shared across connections
pub struct ServerState {
    pub hostname: String,
    pub require_auth: bool,
    pub enable_starttls: bool,
    pub outbound_url: String,
    pub db_pool: sqlx::PgPool,
}

#[tokio::main]
async fn main() -> Result<()> {
    // Initialize logging
    tracing_subscriber::fmt()
        .with_env_filter(
            tracing_subscriber::EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| tracing_subscriber::EnvFilter::new("info"))
        )
        .json()
        .init();
    
    let args = Args::parse();
    
    info!(
        listen = %args.listen,
        hostname = %args.hostname,
        require_auth = args.require_auth,
        "Starting Submission Server"
    );
    
    // Connect to database
    let db_pool = sqlx::PgPool::connect(&args.database_url).await?;
    info!("Connected to database");
    
    // Create server state
    let state = Arc::new(ServerState {
        hostname: args.hostname,
        require_auth: args.require_auth,
        enable_starttls: args.enable_starttls,
        outbound_url: args.outbound_url,
        db_pool,
    });
    
    // Bind to address
    let addr: SocketAddr = args.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(address = %addr, "Submission server listening");
    
    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer_addr, state).await {
                        error!(peer = %peer_addr, error = %e, "Connection error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "Failed to accept connection");
            }
        }
    }
}

/// Handle a single SMTP connection
async fn handle_connection(
    stream: TcpStream,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,
) -> Result<()> {
    info!(peer = %peer_addr, "New submission connection");
    
    let mut session = SubmissionSession::new(stream, peer_addr, state);
    session.run().await?;
    
    info!(peer = %peer_addr, "Connection closed");
    Ok(())
}
