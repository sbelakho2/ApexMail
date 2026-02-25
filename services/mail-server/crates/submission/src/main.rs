//! Submission Server
//!
//! Authenticated SMTP submission server on port 587 for sending emails.
//! This is the entry point for users/applications to submit emails for delivery.

use anyhow::{anyhow, Result};
use clap::Parser;
use std::net::SocketAddr;
use std::sync::Arc;
use std::fs::File;
use std::io::BufReader as StdBufReader;
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Semaphore;
use tracing::{error, info, warn};
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, pki_types::PrivateKeyDer};
use rustls_pemfile::{certs, private_key};

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
    
    /// #176: Enable STARTTLS — auto-detected from cert/key presence when not explicit
    #[arg(long)]
    enable_starttls: Option<bool>,

    /// TLS certificate path (PEM)
    #[arg(long, env = "TLS_CERT_PATH")]
    tls_cert_path: Option<String>,

    /// TLS private key path (PEM)
    #[arg(long, env = "TLS_KEY_PATH")]
    tls_key_path: Option<String>,

    /// #175: Maximum concurrent connections
    #[arg(long, env = "MAX_CONNECTIONS", default_value = "512")]
    max_connections: usize,
}

/// Server state shared across connections
pub struct ServerState {
    pub hostname: String,
    pub require_auth: bool,
    pub enable_starttls: bool,
    pub outbound_url: String,
    pub db_pool: sqlx::PgPool,
    pub tls_acceptor: Option<TlsAcceptor>,
}

fn load_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_file = File::open(cert_path)
        .map_err(|e| anyhow!("Failed to open TLS cert file: {}", e))?;
    let mut cert_reader = StdBufReader::new(cert_file);
    let certs = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("Failed to read TLS certs: {}", e))?;
    if certs.is_empty() {
        return Err(anyhow!("No TLS certificates found"));
    }

    let key_file = File::open(key_path)
        .map_err(|e| anyhow!("Failed to open TLS key file: {}", e))?;
    let mut key_reader = StdBufReader::new(key_file);
    let key: PrivateKeyDer<'static> = private_key(&mut key_reader)
        .map_err(|e| anyhow!("Failed to read TLS private key: {}", e))?
        .ok_or_else(|| anyhow!("No TLS private key found"))?;

    let config = rustls::ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| anyhow!("Invalid TLS config: {}", e))?;

    Ok(TlsAcceptor::from(Arc::new(config)))
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

    // #176: Auto-detect STARTTLS from cert/key presence if not explicitly set
    let enable_starttls = args.enable_starttls.unwrap_or_else(|| {
        args.tls_cert_path.is_some() && args.tls_key_path.is_some()
    });

    let tls_acceptor = if enable_starttls {
        let cert_path = args.tls_cert_path.clone().ok_or_else(|| {
            anyhow!("TLS_CERT_PATH is required when STARTTLS is enabled")
        })?;
        let key_path = args.tls_key_path.clone().ok_or_else(|| {
            anyhow!("TLS_KEY_PATH is required when STARTTLS is enabled")
        })?;
        Some(load_tls_acceptor(&cert_path, &key_path)?)
    } else {
        if args.tls_cert_path.is_some() || args.tls_key_path.is_some() {
            warn!("Both --tls-cert-path and --tls-key-path needed for STARTTLS; TLS disabled");
        }
        None
    };
    
    // Create server state
    let state = Arc::new(ServerState {
        hostname: args.hostname,
        require_auth: args.require_auth,
        enable_starttls,
        outbound_url: args.outbound_url,
        db_pool,
        tls_acceptor,
    });
    
    // #175: Connection limiter
    let conn_semaphore = Arc::new(Semaphore::new(args.max_connections));

    // Bind to address
    let addr: SocketAddr = args.listen.parse()?;
    let listener = TcpListener::bind(addr).await?;
    info!(address = %addr, max_connections = args.max_connections, "Submission server listening");
    
    // Accept connections
    loop {
        match listener.accept().await {
            Ok((stream, peer_addr)) => {
                let permit = match conn_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(peer = %peer_addr, "Connection rejected: max connections reached");
                        drop(stream);
                        continue;
                    }
                };
                let state = Arc::clone(&state);
                tokio::spawn(async move {
                    if let Err(e) = handle_connection(stream, peer_addr, state).await {
                        error!(peer = %peer_addr, error = %e, "Connection error");
                    }
                    drop(permit);
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
