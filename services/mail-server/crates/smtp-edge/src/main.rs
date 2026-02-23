//! SMTP Edge Service
//!
//! Inbound SMTP server handling mail from the internet (port 25).

mod session;
mod parser;

use anyhow::{anyhow, Result};
use clap::Parser;
use std::sync::Arc;
use std::fs::File;
use std::io::BufReader as StdBufReader;
use tokio::net::TcpListener;
use tracing::{info, warn, error};
use tracing_subscriber::EnvFilter;
use tokio_rustls::TlsAcceptor;
use tokio_rustls::rustls::{self, pki_types::PrivateKeyDer};
use rustls_pemfile::{certs, private_key};

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
    
    let enable_starttls = cli.cert.is_some() || cli.key.is_some();
    let tls_acceptor = if enable_starttls {
        let cert_path = cli.cert.clone().ok_or_else(|| anyhow!("--cert is required when STARTTLS is enabled"))?;
        let key_path = cli.key.clone().ok_or_else(|| anyhow!("--key is required when STARTTLS is enabled"))?;
        Some(load_tls_acceptor(&cert_path, &key_path)?)
    } else {
        None
    };

    let config = Arc::new(session::SmtpConfig {
        hostname: cli.hostname,
        mailstore_addr: cli.mailstore_addr,
        max_message_size: 25 * 1024 * 1024, // 25MB
        max_recipients: 100,
        enable_starttls,
        tls_acceptor,
        local_domains: vec![],
    });
    
    let listener = TcpListener::bind(&cli.listen).await?;
    info!("SMTP listening on {}", cli.listen);
    
    loop {
        match listener.accept().await {
            Ok((socket, addr)) => {
                let config = config.clone();
                tokio::spawn(async move {
                    let peer = addr.to_string();
                    info!(peer = %peer, "New SMTP connection");
                    
                    if let Err(e) = session::handle_connection(socket, config, peer.clone()).await {
                        warn!(peer = %peer, error = %e, "SMTP session error");
                    }
                });
            }
            Err(e) => {
                error!(error = %e, "Accept error");
            }
        }
    }
}
