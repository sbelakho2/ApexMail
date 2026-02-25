//! SMTP Edge Service
//!
//! Inbound SMTP server handling mail from the internet (port 25).

mod session;
// #165: Removed dead `parser` module — all parsing is handled in session.rs.

use anyhow::{anyhow, Result};
use clap::Parser;
use std::sync::Arc;
use std::fs::File;
use std::io::BufReader as StdBufReader;
use tokio::net::TcpListener;
use tokio::sync::Semaphore;
use tracing::{info, warn, error};
use tracing_subscriber::EnvFilter;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, pki_types::PrivateKeyDer};
use rustls_pemfile::{certs, private_key};

/// Default maximum concurrent connections.
const DEFAULT_MAX_CONNECTIONS: usize = 1024;

#[derive(Parser)]
#[command(name = "smtp-edge")]
#[command(about = "SMTP Edge - Inbound mail server")]
struct Cli {
    /// Listen address
    #[arg(short, long, default_value = "0.0.0.0:25")]
    listen: String,
    
    /// Hostname to announce
    #[arg(long, default_value = "mail.apexmail.ee")]
    hostname: String,
    
    /// Mailstore gRPC address
    #[arg(long, default_value = "127.0.0.1:50051")]
    mailstore_addr: String,
    
    /// TLS certificate path
    #[arg(long)]
    cert: Option<String>,
    
    /// TLS key path
    #[arg(long)]
    key: Option<String>,
    
    /// Log level
    #[arg(long, default_value = "info")]
    log_level: String,

    /// #162: Comma-separated list of local domains to accept mail for
    #[arg(long, env = "LOCAL_DOMAINS", value_delimiter = ',')]
    local_domains: Vec<String>,

    /// #163: Maximum concurrent connections
    #[arg(long, env = "MAX_CONNECTIONS", default_value_t = DEFAULT_MAX_CONNECTIONS)]
    max_connections: usize,
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
    let cli = Cli::parse();
    
    // Initialize logging
    let filter = EnvFilter::try_from_default_env()
        .unwrap_or_else(|_| EnvFilter::new(&cli.log_level));
    
    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
    
    info!("Starting SMTP Edge on {}", cli.listen);
    
    // #164: Both cert AND key must be present to enable STARTTLS (was || — wrong)
    let enable_starttls = cli.cert.is_some() && cli.key.is_some();
    let tls_acceptor = if enable_starttls {
        let cert_path = cli.cert.clone().unwrap(); // safe: checked above
        let key_path = cli.key.clone().unwrap(); // safe: checked above
        Some(load_tls_acceptor(&cert_path, &key_path)?)
    } else {
        if cli.cert.is_some() || cli.key.is_some() {
            warn!("Both --cert and --key must be provided to enable STARTTLS; TLS disabled");
        }
        None
    };

    // #162: local_domains from CLI/env; warn if empty
    if cli.local_domains.is_empty() {
        warn!("No --local-domains configured; all inbound mail will be rejected as non-local");
    }

    let config = Arc::new(session::SmtpConfig::new(
        cli.hostname,
        cli.mailstore_addr,
        25 * 1024 * 1024, // 25MB
        100,
        enable_starttls,
        tls_acceptor,
        cli.local_domains,
    ));

    // #163: Semaphore limits concurrent connections
    let conn_semaphore = Arc::new(Semaphore::new(cli.max_connections));
    
    let listener = TcpListener::bind(&cli.listen).await?;
    info!("SMTP listening on {} (max_connections={})", cli.listen, cli.max_connections);
    
    loop {
        match listener.accept().await {
            Ok((mut socket, addr)) => {
                // #163: Acquire permit before spawning — rejects when at capacity
                let permit = match conn_semaphore.clone().try_acquire_owned() {
                    Ok(p) => p,
                    Err(_) => {
                        warn!(peer = %addr, "Connection rejected: max connections reached");
                        // Try to send a 421 before dropping
                        let _ = tokio::io::AsyncWriteExt::write_all(
                            &mut socket,
                            b"421 4.7.0 Too many connections, try again later\r\n",
                        ).await;
                        drop(socket);
                        continue;
                    }
                };

                let config = config.clone();
                tokio::spawn(async move {
                    let peer = addr;
                    info!(peer = %peer, "New SMTP connection");
                    
                    if let Err(e) = session::handle_connection(socket, config, peer).await {
                        warn!(peer = %peer, error = %e, "SMTP session error");
                    }

                    // Permit is dropped here, releasing the semaphore slot
                    drop(permit);
                });
            }
            Err(e) => {
                error!(error = %e, "Accept error");
            }
        }
    }
}
