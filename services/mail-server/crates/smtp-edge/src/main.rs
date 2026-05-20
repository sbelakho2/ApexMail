//! SMTP Edge Service
//!
//! Inbound SMTP server handling mail from the internet (port 25).

mod session;
// #165:Removed dead `parser` module — all parsing is handled in session.rs.

use anyhow::{anyhow, Result};
use axum::http::{HeaderValue, StatusCode};
use axum::response::IntoResponse;
use axum::{extract::State, routing::get, Router};
use clap::Parser;
use observability_service::otlp_exporter::{
    init_otlp_tracing, is_otlp_enabled, OtlpConfig, TracingGuard,
};
use rustls_pemfile::{certs, private_key};
use std::fs::File;
use std::io::BufReader as StdBufReader;
use std::sync::Arc;
use tokio::net::TcpListener;
use tokio::signal;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tokio::time::{timeout, Duration};
use tokio_rustls::rustls::{self, pki_types::PrivateKeyDer};
use tokio_rustls::TlsAcceptor;
use tracing::{error, info, warn};
use tracing_subscriber::EnvFilter;

/// Default maximum concurrent connections.
const DEFAULT_HTTP_LISTEN: &str = "127.0.0.1:8080";

fn default_max_connections() -> usize {
    1024
}
fn default_connection_queue_timeout_secs() -> u64 {
    5
}
fn default_max_line_length() -> usize {
    1000
}
fn default_command_timeout_secs() -> u64 {
    30
}
fn default_session_timeout_secs() -> u64 {
    300
}
fn default_max_message_bytes() -> usize {
    25 * 1024 * 1024
}
fn default_max_recipients() -> usize {
    100
}

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

    /// #162:Comma-separated list of local domains to accept mail for
    #[arg(long, env = "LOCAL_DOMAINS", value_delimiter = ',')]
    local_domains: Vec<String>,

    /// #163:Maximum concurrent connections
    #[arg(long, env = "MAX_CONNECTIONS", default_value_t = default_max_connections())]
    max_connections: usize,

    /// Max wait in seconds for a connection slot before sending 421
    #[arg(long, env = "SMTP_CONNECTION_QUEUE_TIMEOUT_SECS", default_value_t = default_connection_queue_timeout_secs())]
    connection_queue_timeout_secs: u64,

    /// Maximum accepted SMTP line length (including CRLF)
    #[arg(long, env = "SMTP_MAX_LINE_LENGTH", default_value_t = default_max_line_length())]
    max_line_length: usize,

    /// Maximum wait time for one SMTP command/data line (seconds)
    #[arg(long, env = "SMTP_COMMAND_TIMEOUT_SECS", default_value_t = default_command_timeout_secs())]
    command_timeout_secs: u64,

    /// Maximum total SMTP session duration (seconds)
    #[arg(long, env = "SMTP_SESSION_TIMEOUT_SECS", default_value_t = default_session_timeout_secs())]
    session_timeout_secs: u64,

    /// Maximum SMTP message size in bytes
    #[arg(long, env = "SMTP_MAX_MESSAGE_BYTES", default_value_t = default_max_message_bytes())]
    max_message_bytes: usize,

    /// Maximum recipients per message
    #[arg(long, env = "SMTP_MAX_RECIPIENTS", default_value_t = default_max_recipients())]
    max_recipients: usize,

    /// HTTP listen address for health/metrics
    #[arg(long, env = "SMTP_EDGE_HTTP_LISTEN", default_value = DEFAULT_HTTP_LISTEN)]
    http_listen: String,
}

fn load_tls_acceptor(cert_path: &str, key_path: &str) -> Result<TlsAcceptor> {
    let cert_file =
        File::open(cert_path).map_err(|e| anyhow!("Failed to open TLS cert file: {}", e))?;
    let mut cert_reader = StdBufReader::new(cert_file);
    let certs = certs(&mut cert_reader)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow!("Failed to read TLS certs: {}", e))?;
    if certs.is_empty() {
        return Err(anyhow!("No TLS certificates found"));
    }

    let key_file =
        File::open(key_path).map_err(|e| anyhow!("Failed to open TLS key file: {}", e))?;
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

fn init_tracing(log_level: &str) -> Option<TracingGuard> {
    if is_otlp_enabled() {
        let config = OtlpConfig {
            service_name: "smtp-edge".to_string(),
            ..OtlpConfig::default()
        };
        match init_otlp_tracing(config) {
            Ok(guard) => return Some(guard),
            Err(e) => tracing::warn!("OTLP tracing disabled: {e}"),
        }
    }
    // Fallback: structured JSON logging
    let filter =
        EnvFilter::try_from_default_env().unwrap_or_else(|_| EnvFilter::new(log_level));

    tracing_subscriber::fmt()
        .with_env_filter(filter)
        .json()
        .init();
    None
}

#[tokio::main]
async fn main() -> Result<()> {
    let cli = Cli::parse();

    let _guard = init_tracing(&cli.log_level);

    info!("Starting SMTP Edge on {}", cli.listen);

    // #164:Both cert AND key must be present to enable STARTTLS (was || — wrong)
    let enable_starttls = cli.cert.is_some() && cli.key.is_some();
    let tls_acceptor = if enable_starttls {
        let (Some(cert_path), Some(key_path)) = (cli.cert.as_deref(), cli.key.as_deref()) else {
            return Err(anyhow!("TLS enabled but cert/key missing"));
        };
        Some(load_tls_acceptor(cert_path, key_path)?)
    } else {
        if cli.cert.is_some() || cli.key.is_some() {
            warn!("Both --cert and --key must be provided to enable STARTTLS; TLS disabled");
        }
        None
    };

    // #162:local_domains from CLI/env; fail fast if empty
    if cli.local_domains.is_empty() {
        return Err(anyhow!(
            "No --local-domains configured; refusing to start because all inbound mail would be rejected"
        ));
    }

    let metrics = Arc::new(session::SmtpMetrics::new());
    let config = Arc::new(session::SmtpConfig::new(
        cli.hostname,
        cli.mailstore_addr,
        cli.max_message_bytes,
        cli.max_recipients,
        enable_starttls,
        tls_acceptor,
        cli.local_domains,
        cli.max_line_length,
        std::time::Duration::from_secs(cli.command_timeout_secs),
        std::time::Duration::from_secs(cli.session_timeout_secs),
        metrics.clone(),
    ));

    let http_metrics = metrics.clone();
    let http_listen = cli.http_listen.clone();
    tokio::spawn(async move {
        if let Err(e) = run_http_server(&http_listen, http_metrics).await {
            warn!(error = %e, "SMTP HTTP server exited");
        }
    });

    // #163:Semaphore limits concurrent connections
    let conn_semaphore = Arc::new(Semaphore::new(cli.max_connections));

    let listener = TcpListener::bind(&cli.listen).await?;
    info!(
        "SMTP listening on {} (max_connections={})",
        cli.listen, cli.max_connections
    );

    let shutdown = shutdown_signal();
    tokio::pin!(shutdown);
    let mut join_set = JoinSet::new();

    loop {
        let accept_result = tokio::select! {
            result = listener.accept() => Some(result),
            _ = &mut shutdown => {
                info!("Shutdown signal received, stopping SMTP accept loop");
                None
            }
            result = join_set.join_next(), if !join_set.is_empty() => {
                if let Some(Err(err)) = result {
                    warn!(error = %err, "SMTP session task failed");
                }
                continue;
            }
        };

        let Some(accept_result) = accept_result else {
            break;
        };

        match accept_result {
            Ok((mut socket, addr)) => {
                // #E-034:Allow bounded queueing for a slot instead of immediate rejection
                let permit = match timeout(
                    Duration::from_secs(cli.connection_queue_timeout_secs),
                    conn_semaphore.clone().acquire_owned(),
                )
                .await
                {
                    Ok(Ok(p)) => p,
                    Ok(Err(_)) | Err(_) => {
                        warn!(peer = %addr, "Connection rejected: max connections/queue timeout reached");
                        if let Err(error) = tokio::io::AsyncWriteExt::write_all(
                            &mut socket,
                            b"421 4.7.0 Too many connections, try again later\r\n",
                        )
                        .await
                        {
                            warn!(peer = %addr, error = %error, "Failed to write SMTP overload response");
                        }
                        drop(socket);
                        continue;
                    }
                };

                let config = config.clone();
                join_set.spawn(async move {
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

    // Graceful drain:wait for active sessions to release semaphore permits.
    let drain_timeout = Duration::from_secs(30);
    let start = tokio::time::Instant::now();
    while conn_semaphore.available_permits() < cli.max_connections {
        if start.elapsed() >= drain_timeout {
            warn!("Shutdown drain timed out; exiting with active sessions");
            break;
        }
        tokio::time::sleep(Duration::from_millis(200)).await;
    }

    let drain_deadline = tokio::time::Instant::now() + drain_timeout;
    while !join_set.is_empty() {
        let now = tokio::time::Instant::now();
        if now >= drain_deadline {
            warn!("Shutdown task drain timed out; exiting with active tasks");
            break;
        }
        let remaining = drain_deadline - now;
        match timeout(remaining, join_set.join_next()).await {
            Ok(Some(Err(err))) => {
                warn!(error = %err, "SMTP session task failed during shutdown");
            }
            Ok(Some(Ok(_))) => {}
            Ok(None) => break,
            Err(_) => break,
        }
    }

    info!("SMTP edge shutdown complete");
    Ok(())
}

async fn shutdown_signal() {
    #[cfg(unix)]
    {
        match signal::unix::signal(signal::unix::SignalKind::terminate()) {
            Ok(mut terminate) => {
                tokio::select! {
                    _ = signal::ctrl_c() => {},
                    _ = terminate.recv() => {},
                }
            }
            Err(e) => {
                warn!(error = %e, "Failed to install SIGTERM handler; falling back to Ctrl+C");
                if let Err(error) = signal::ctrl_c().await {
                    warn!(error = %error, "Ctrl+C signal handler failed");
                }
            }
        }
    }

    #[cfg(not(unix))]
    {
        if let Err(error) = signal::ctrl_c().await {
            warn!(error = %error, "Ctrl+C signal handler failed");
        }
    }
}

async fn run_http_server(listen: &str, metrics: Arc<session::SmtpMetrics>) -> Result<()> {
    let app = Router::new()
        .route("/healthz", get(healthz))
        .route("/metrics", get(metrics_handler))
        .with_state(metrics);

    let listener = tokio::net::TcpListener::bind(listen).await?;
    info!("SMTP HTTP listening on {}", listen);
    axum::serve(listener, app).await.map_err(|e| anyhow!(e))
}

async fn healthz() -> impl IntoResponse {
    (StatusCode::OK, "ok")
}

async fn metrics_handler(State(metrics): State<Arc<session::SmtpMetrics>>) -> impl IntoResponse {
    let snapshot = metrics.snapshot();
    let body = render_metrics(&snapshot);
    let mut response = body.into_response();
    response.headers_mut().insert(
        axum::http::header::CONTENT_TYPE,
        HeaderValue::from_static("text/plain; version=0.0.4"),
    );
    response
}

fn render_metrics(snapshot: &session::SmtpMetricsSnapshot) -> String {
    format!(
        "smtp_edge_sessions_started {}\n\
smtp_edge_sessions_ended {}\n\
smtp_edge_deliveries_ok {}\n\
smtp_edge_deliveries_rejected {}\n\
smtp_edge_deliveries_oversized {}\n",
        snapshot.sessions_started,
        snapshot.sessions_ended,
        snapshot.deliveries_ok,
        snapshot.deliveries_rejected,
        snapshot.deliveries_oversized,
    )
}
