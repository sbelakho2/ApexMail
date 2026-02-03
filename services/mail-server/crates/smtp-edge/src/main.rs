//! SMTP Edge Service
//!
//! Inbound SMTP server handling mail from the internet (port 25).

mod session;
mod parser;

use anyhow::Result;
use clap::Parser;
use std::sync::Arc;
use tokio::net::TcpListener;
use tracing::{info, warn, error};
use tracing_subscriber::EnvFilter;

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
    
    let config = Arc::new(session::SmtpConfig {
        hostname: cli.hostname,
        mailstore_addr: cli.mailstore_addr,
        max_message_size: 25 * 1024 * 1024, // 25MB
        max_recipients: 100,
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
