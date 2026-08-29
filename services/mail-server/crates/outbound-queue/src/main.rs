//! Outbound Queue Service
//!
//! Handles outbound email delivery with retry logic and direct SMTP sending.
//! Uses purpose-built infrastructure - sends directly via SMTP with DKIM signing.

pub mod dkim;
pub mod dnsbl;
pub mod ip_rotation;
pub mod provider_throttle;
pub mod queue;
pub mod service;
pub mod smtp_sender;

use anyhow::{anyhow, bail, Result};
use clap::Parser;
use mail_proto::{InternalServiceToken, OutboundServiceServer};
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use std::sync::Arc;
use tokio::sync::mpsc;
use tonic::transport::Server;
use tracing::{debug, info, warn};
use tracing_subscriber::EnvFilter;

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
    /// gRPC listen address. Defaults to loopback so the service is not
    /// exposed without authentication; container deployments override this
    /// with OUTBOUND_BIND_ADDR=0.0.0.0:50052 and MUST also set
    /// INTERNAL_SERVICE_TOKEN (startup refuses a non-loopback tokenless bind).
    #[arg(
        short,
        long,
        env = "OUTBOUND_BIND_ADDR",
        default_value = "127.0.0.1:50052"
    )]
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

    /// DKIM private key path (alternative to DKIM_PRIVATE_KEY env var).
    /// If set, loads DKIM key from this file path.
    /// If absent, falls back to the DKIM_PRIVATE_KEY environment variable.
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

fn init_tracing(log_level: &str) -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "outbound-queue".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    let filter = EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
    None
}

/// Shared-token gRPC authentication (same contract as mailstore-core).
///
/// When `INTERNAL_SERVICE_TOKEN` is set, every request must present
/// `authorization: Bearer <INTERNAL_SERVICE_TOKEN>` or it is rejected with
/// PERMISSION_DENIED. The token may only be omitted for loopback local
/// development; startup rejects an externally reachable tokenless server, so
/// the service can never be an unauthenticated open relay.
#[derive(Clone)]
struct SharedTokenInterceptor {
    expected: Option<InternalServiceToken>,
}

impl SharedTokenInterceptor {
    fn from_env() -> Result<Self> {
        Ok(Self {
            expected: InternalServiceToken::from_env().map_err(|error| anyhow!(error))?,
        })
    }

    fn is_enabled(&self) -> bool {
        self.expected.is_some()
    }

    #[cfg(test)]
    fn with_token(token: &str) -> Self {
        Self {
            expected: Some(
                InternalServiceToken::new(token.to_owned())
                    .expect("test token must satisfy production validation"),
            ),
        }
    }

    #[cfg(test)]
    fn without_token() -> Self {
        Self { expected: None }
    }
}

impl tonic::service::Interceptor for SharedTokenInterceptor {
    fn call(&mut self, request: tonic::Request<()>) -> Result<tonic::Request<()>, tonic::Status> {
        if !self.is_enabled() {
            // Loopback-only development mode: bind validation above already
            // refuses non-loopback tokenless listeners.
            return Ok(request);
        }
        let authorized = request
            .metadata()
            .get("authorization")
            .and_then(|value| value.to_str().ok())
            .and_then(|value| value.trim().strip_prefix("Bearer "))
            .zip(self.expected.as_ref())
            .is_some_and(|(provided, expected)| {
                constant_time_eq(provided.as_bytes(), expected.as_str().as_bytes())
            });
        if authorized {
            Ok(request)
        } else {
            Err(tonic::Status::permission_denied(
                "missing or invalid internal service token",
            ))
        }
    }
}

/// Length-safe constant-time byte comparison (avoids a new dependency on
/// `subtle`; the length check itself leaks only the token length).
fn constant_time_eq(a: &[u8], b: &[u8]) -> bool {
    if a.len() != b.len() {
        return false;
    }
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Only loopback binds may opt out of internal service authentication. Docker
/// bridge and wildcard addresses are network-reachable and must always carry
/// a validated token — a tokenless wildcard bind would be an open relay.
fn validate_bind_security(
    address: std::net::SocketAddr,
    interceptor: &SharedTokenInterceptor,
) -> Result<()> {
    if !address.ip().is_loopback() && !interceptor.is_enabled() {
        bail!(
            "INTERNAL_SERVICE_TOKEN is required when OUTBOUND_BIND_ADDR ({address}) is not loopback"
        );
    }
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let _guard = init_tracing(&cli.log_level);

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
        info!(
            count = cli.outbound_ips.len(),
            "IP pool initialised for source-bound sending"
        );

        // Start background DNSBL monitoring for our outbound IPs
        let dnsbl_ips: Vec<std::net::IpAddr> = cli
            .outbound_ips
            .iter()
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        if !dnsbl_ips.is_empty() {
            let check_interval = DnsblChecker::check_interval();
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
                    tokio::time::sleep(check_interval).await;
                }
            });
            info!(
                interval_secs = check_interval.as_secs(),
                "Background DNSBL monitor started"
            );
        }
    }

    // Create queue
    let queue_config = QueueConfig {
        worker_count: cli.workers,
        batch_size: cli.batch_size,
        ..Default::default()
    };
    let mut queue = EmailQueue::new(pool.clone(), queue_config, smtp_sender);

    // Load DKIM signer (MI-002): prefer env var DKIM_PRIVATE_KEY over file,
    // so the secret is never stored at rest in a config file.
    let dkim_result = if let Some(ref key_path) = cli.dkim_key_path {
        // Load from file path (legacy/development path)
        DkimSigner::from_file(&cli.from_domain, &cli.dkim_selector, key_path)
            .await
            .map(|s| (s, format!("file: {}", key_path)))
    } else {
        // Load from DKIM_PRIVATE_KEY environment variable (production path)
        // This avoids writing the private key to disk entirely.
        match DkimSigner::from_env(&cli.from_domain, &cli.dkim_selector) {
            Ok(signer) => Ok((signer, "DKIM_PRIVATE_KEY env var".to_string())),
            Err(env_err) => {
                // Env var not set — check if we should also try the file
                info!(
                    "DKIM_PRIVATE_KEY not set ({}). Trying default key path...",
                    env_err
                );
                // Try default path as last resort
                let default_path = format!("/etc/apexmail/dkim/{}.pem", cli.from_domain);
                DkimSigner::from_file(&cli.from_domain, &cli.dkim_selector, &default_path)
                    .await
                    .map(|s| (s, format!("default path: {}", default_path)))
            }
        }
    };

    match dkim_result {
        Ok((signer, source)) => {
            info!("DKIM signer loaded from {}", source);
            queue = queue.with_dkim_signer(signer);
        }
        Err(e) => {
            tracing::warn!(
                "Failed to load DKIM key ({}). Sending without DKIM signature.",
                e
            );
        }
    }

    // Per-provider reputation throttle: gates outbound to Gmail / Outlook /
    // Yahoo / iCloud based on signals from the postmaster scheduler. Always
    // enabled — when no reputation summary exists yet, the throttle is 0%.
    queue = queue.with_provider_throttle(crate::provider_throttle::ProviderThrottle::new(
        pool.clone(),
    ));
    info!("Per-provider reputation throttle enabled");

    // Initialize queue tables
    queue.initialize().await?;

    let queue = Arc::new(queue);

    // Lease reaper: flip rows orphaned in 'processing' (worker crash between
    // claim and send) back to 'pending' so they are retried. Runs on a 60s
    // interval as a safety net alongside fetch_pending's inline reclaim.
    {
        let reaper_pool = pool.clone();
        tokio::spawn(async move {
            let mut interval = tokio::time::interval(std::time::Duration::from_secs(60));
            interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
            loop {
                interval.tick().await;
                crate::queue::reap_expired_processing(&reaper_pool).await;
            }
        });
        info!("Expired-processing lease reaper started (60s interval)");
    }

    // Start queue processor
    let (shutdown_tx, shutdown_rx) = mpsc::channel::<()>(1);
    let processor_queue = Arc::clone(&queue);
    let processor_handle = tokio::spawn(async move {
        processor_queue.start_processing(shutdown_rx).await;
    });

    // Create gRPC service
    let service = OutboundServiceImpl::new(Arc::clone(&queue));

    // Start gRPC server — every RPC passes the shared-token check first.
    let addr = cli.listen.parse()?;
    let interceptor = SharedTokenInterceptor::from_env()?;
    validate_bind_security(addr, &interceptor)?;
    info!("Starting gRPC server on {}", addr);
    if interceptor.is_enabled() {
        info!("gRPC shared-token authentication enabled (INTERNAL_SERVICE_TOKEN)");
    } else {
        warn!(
            bind = %addr,
            "gRPC authentication DISABLED (no INTERNAL_SERVICE_TOKEN); loopback-only bind permitted for local development"
        );
    }

    Server::builder()
        .layer(tonic::service::interceptor(interceptor))
        .add_service(OutboundServiceServer::new(service))
        .serve_with_shutdown(addr, async {
            tokio::signal::ctrl_c().await.ok();
            info!("Shutdown signal received");
            if let Err(error) = shutdown_tx.send(()).await {
                warn!(error = %error, "Failed to send shutdown signal to queue processor");
            }
        })
        .await?;

    // #119:Graceful drain — wait for processor to finish in-flight emails with a timeout
    info!("Waiting for in-flight emails to drain (up to 30s)...");
    match tokio::time::timeout(std::time::Duration::from_secs(30), processor_handle).await {
        Ok(Ok(())) => info!("Queue processor drained cleanly"),
        Ok(Err(e)) => tracing::warn!("Queue processor task panicked: {}", e),
        Err(_) => tracing::warn!(
            "Queue processor drain timed out after 30s; some emails may still be in-flight"
        ),
    }

    // Close database pool gracefully
    pool.close().await;

    info!("Outbound Queue Service stopped");
    Ok(())
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use mail_proto::MIN_INTERNAL_SERVICE_TOKEN_LENGTH;
    use tonic::service::Interceptor;

    const TEST_TOKEN: &str = "aabbccddeeff00112233445566778899aabbccdd";

    fn bearer(value: &str) -> tonic::Request<()> {
        let mut request = tonic::Request::new(());
        request.metadata_mut().insert(
            "authorization",
            format!("Bearer {value}")
                .parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>()
                .expect("test header must be valid ASCII"),
        );
        request
    }

    #[test]
    fn rpc_without_token_is_permission_denied() {
        let mut interceptor = SharedTokenInterceptor::with_token(TEST_TOKEN);
        let err = interceptor
            .call(tonic::Request::new(()))
            .expect_err("tokenless RPC must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn rpc_with_wrong_token_is_permission_denied() {
        let mut interceptor = SharedTokenInterceptor::with_token(TEST_TOKEN);
        let wrong = "0123456789abcdef0123456789abcdef01234567";
        let err = interceptor
            .call(bearer(wrong))
            .expect_err("wrong-token RPC must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn rpc_with_correct_token_is_authorized() {
        let mut interceptor = SharedTokenInterceptor::with_token(TEST_TOKEN);
        interceptor
            .call(bearer(TEST_TOKEN))
            .expect("correct token must authorize the RPC");
    }

    #[test]
    fn rpc_with_malformed_authorization_header_is_permission_denied() {
        let mut interceptor = SharedTokenInterceptor::with_token(TEST_TOKEN);
        let mut request = tonic::Request::new(());
        request.metadata_mut().insert(
            "authorization",
            "Basic something-else"
                .parse::<tonic::metadata::MetadataValue<tonic::metadata::Ascii>>()
                .unwrap(),
        );
        let err = interceptor
            .call(request)
            .expect_err("non-Bearer authorization must be rejected");
        assert_eq!(err.code(), tonic::Code::PermissionDenied);
    }

    #[test]
    fn tokenless_interceptor_passes_only_for_loopback_development() {
        let mut interceptor = SharedTokenInterceptor::without_token();
        interceptor
            .call(tonic::Request::new(()))
            .expect("loopback dev mode has no token to check");
        // But a non-loopback tokenless bind must refuse to start.
        let addr: std::net::SocketAddr = "0.0.0.0:50052".parse().unwrap();
        assert!(validate_bind_security(addr, &interceptor).is_err());
    }

    #[test]
    fn non_loopback_bind_requires_token() {
        let interceptor = SharedTokenInterceptor::with_token(TEST_TOKEN);
        let wildcard: std::net::SocketAddr = "0.0.0.0:50052".parse().unwrap();
        assert!(validate_bind_security(wildcard, &interceptor).is_ok());
        let loopback: std::net::SocketAddr = "127.0.0.1:50052".parse().unwrap();
        assert!(validate_bind_security(loopback, &interceptor).is_ok());
        assert!(validate_bind_security(loopback, &SharedTokenInterceptor::without_token()).is_ok());
    }

    #[test]
    fn test_token_length_is_enforced_by_shared_type() {
        // The shared InternalServiceToken type rejects weak secrets, so the
        // interceptor can never be built around a short/guessable token.
        assert!(InternalServiceToken::new("short").is_err());
        assert!(InternalServiceToken::new(TEST_TOKEN).is_ok());
        assert!(TEST_TOKEN.len() >= MIN_INTERNAL_SERVICE_TOKEN_LENGTH);
    }
}
