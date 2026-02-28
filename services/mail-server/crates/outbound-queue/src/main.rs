//! Outbound Queue Service
//!
//! Handles outbound email delivery with retry logic and direct SMTP sending.
//! Uses purpose-built infrastructure - sends directly via SMTP with DKIM signing.

pub mod smtp_sender;
pub mod queue;
pub mod dkim;
pub mod service;
pub mod ip_rotation;
pub mod dnsbl;

use std::sync::Arc;
use anyhow::Result;
use clap::Parser;
use tokio::sync::mpsc;
use tonic::transport::Server;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

use mail_proto::generated::outbound_service_server::OutboundServiceServer;
use crate::dkim::DkimSigner;
use crate::dnsbl::DnsblChecker;
use crate::ip_rotation::IpPool;
use crate::queue::{EmailQueue, QueueConfig};
use crate::service::OutboundServiceImpl;
use crate::smtp_sender::SmtpSender;

#[derive(Parser)]
#[command(name = "outbound-queue")]
#[command(about = "Outbound Queue - High-performance email delivery service")]
struct Cli {
    /// gRPC listen address
    #[arg(short, long, default_value = "0.0.0.0:50052")]
    listen: String,
    
    /// Database URL
    #[arg(long, env = "DATABASE_URL")]
    database_url: String,
    
    /// Default from domain
    #[arg(long, default_value = "apexmail.ee")]
    from_domain: String,
    
    /// DKIM selector
    #[arg(long, default_value = "apexmail2026")]
    dkim_selector: String,
    
    /// DKIM private key path
    #[arg(long)]
    dkim_key_path: Option<String>,
    
    /// Number of worker threads for queue processing
    #[arg(long, default_value = "4")]
    workers: usize,
    
    /// Batch size for queue processing
    #[arg(long, default_value = "100")]
    batch_size: usize,
    
    /// Outbound IP addresses for self-hosted sending (comma-separated).
    /// When provided, these IPs are added to the IP pool for source-binding
    /// and round-robin rotation.
    #[arg(long, env = "OUTBOUND_IPS", value_delimiter = ',')]
    outbound_ips: Vec<String>,

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
    
    info!("Starting Outbound Queue Service");
    info!("Listen address: {}", cli.listen);
    info!("From domain: {}", cli.from_domain);
    info!("DKIM selector: {}", cli.dkim_selector);
    
    // Connect to database
    let pool = sqlx::PgPool::connect(&cli.database_url).await?;
    info!("Connected to database");
    
    // Create SMTP sender
    let mut smtp_sender = SmtpSender::new(cli.from_domain.clone());

    // Wire IP pool if outbound IPs are configured (self-hosted path)
    if !cli.outbound_ips.is_empty() {
        let mut pool = IpPool::new();
        for ip_str in &cli.outbound_ips {
            match ip_str.trim().parse::<std::net::IpAddr>() {
                Ok(ip) => {
                    pool.add_ip(ip_rotation::OutboundIp::new_healthy(ip, None));
                    info!(ip = %ip, "Added outbound IP to pool");
                }
                Err(e) => {
                    warn!(ip = %ip_str, error = %e, "Skipping invalid outbound IP");
                }
            }
        }
        let pool = Arc::new(tokio::sync::RwLock::new(pool));
        smtp_sender.set_ip_pool(pool);
        info!(count = cli.outbound_ips.len(), "IP pool initialised for source-bound sending");

        // Start background DNSBL monitoring for our outbound IPs
        let dnsbl_ips: Vec<std::net::IpAddr> = cli.outbound_ips.iter()
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        if !dnsbl_ips.is_empty() {
            tokio::spawn(async move {
                let checker = DnsblChecker::new();
                loop {
                    for ip in &dnsbl_ips {
                        let report = checker.check_all(*ip).await;
                        if report.listing_count() > 0 {
                            warn!(
                                ip = %ip,
                                listings = report.listing_count(),
                                severity = ?report.max_severity(),
                                "IP listed on DNSBL(s) — review needed"
                            );
                        } else {
                            debug!(ip = %ip, "DNSBL check clean");
                        }
                    }
                    // Check every 15 minutes
                    tokio::time::sleep(std::time::Duration::from_secs(900)).await;
                }
            });
            info!("Background DNSBL monitor started (15-minute interval)");
        }
    }
    
    // Create queue
    let queue_config = QueueConfig {
        worker_count: cli.workers,
        batch_size: cli.batch_size,
        ..Default::default()
    };
    let mut queue = EmailQueue::new(pool.clone(), queue_config, smtp_sender);
    
    // Load DKIM signer if configured
    if let Some(ref key_path) = cli.dkim_key_path {
        match DkimSigner::from_file(&cli.from_domain, &cli.dkim_selector, key_path).await {
            Ok(signer) => {
                info!("DKIM signer loaded from {}", key_path);
                queue = queue.with_dkim_signer(signer);
            }
            Err(e) => {
                tracing::warn!("Failed to load DKIM key: {}. Sending without DKIM.", e);
            }
        }
    }
    
    // Initialize queue tables
    queue.initialize().await?;
    
    let queue = Arc::new(queue);
    
    // Start queue processor
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
    let processor_queue = Arc::clone(&queue);
    let processor_handle = tokio::spawn(async move {
        processor_queue.start_processing(shutdown_rx).await;
    });
    
    // Create gRPC service
    let service = OutboundServiceImpl::new(Arc::clone(&queue));
    
    // Start gRPC server
    let addr = cli.listen.parse()?;
    info!("Starting gRPC server on {}", addr);
    
    Server::builder()
        .add_service(OutboundServiceServer::new(service))
        .serve_with_shutdown(addr, async {
            tokio::signal::ctrl_c().await.ok();
            info!("Shutdown signal received");
            if let Err(error) = shutdown_tx.send(()).await {
                warn!(error = %error, "Failed to send shutdown signal to queue processor");
            }
        })
        .await?;
    
    // #119: Graceful drain — wait for processor to finish in-flight emails with a timeout
    info!("Waiting for in-flight emails to drain (up to 30s)...");
    match tokio::time::timeout(
        std::time::Duration::from_secs(30),
        processor_handle,
    ).await {
        Ok(Ok(())) => info!("Queue processor drained cleanly"),
        Ok(Err(e)) => tracing::warn!("Queue processor task panicked: {}", e),
        Err(_) => tracing::warn!("Queue processor drain timed out after 30s; some emails may still be in-flight"),
    }
    
    // Close database pool gracefully
    pool.close().await;
    
    info!("Outbound Queue Service stopped");
    Ok(())
}
