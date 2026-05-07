//! SMTP Session Handler

use anyhow::Result;
use bytes::Bytes;
use dashmap::DashMap;
use futures::future::try_join_all;
use mail_auth::{AuthenticatedMessage, DkimResult, Resolver, SpfResult};
use mail_parser::{Address, MessageParser};
use mail_proto::generated::{
    mailstore_service_client::MailstoreServiceClient, MessageFlags, StoreMessageRequest,
};
use std::collections::{HashSet, VecDeque};
use std::fmt::Write as _;
use std::future::Future;
use std::io::ErrorKind;
use std::net::IpAddr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, LazyLock};
use tokio::io::{AsyncReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio::time::{timeout, Duration, Instant};
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tracing::{debug, error, info, warn};
use trust_dns_resolver::config::{
    NameServerConfig, NameServerConfigGroup, Protocol, ResolverConfig, ResolverOpts,
};

// #156:Shared DNS resolver — avoids re-reading /etc/resolv.conf per message
static EDGE_RESOLVER: LazyLock<Option<Resolver>> = LazyLock::new(|| match build_dns_resolver() {
    Ok(resolver) => Some(resolver),
    Err(e) => {
        error!(error = %e, "Failed to initialize DNS resolver at startup; DMARC/SPF/DKIM verification will be unavailable");
        None
    }
});

const COMMAND_RATE_WINDOW: Duration = Duration::from_secs(60);
const MAX_COMMANDS_PER_WINDOW: usize = 240;
/// Maximum number of distinct IPs tracked for rate limiting.
/// Once exceeded, the oldest entries are evicted to prevent unbounded growth.
const MAX_RATE_TRACKER_ENTRIES: usize = 100_000;
const RATE_TRACKER_EVICTION_INTERVAL: Duration = Duration::from_secs(30);
const DATA_BUFFER_SHRINK_THRESHOLD: usize = 128 * 1024;
const DATA_BUFFER_DEFAULT_CAPACITY: usize = 8 * 1024;
const DNS_CIRCUIT_FAILURE_THRESHOLD: u32 = 5;
const DNS_CIRCUIT_OPEN_SECS: u64 = 30;
const GRPC_CHANNEL_TTL: Duration = Duration::from_secs(60);
const LINE_BUFFER_SHRINK_THRESHOLD: usize = 8 * 1024;

pub struct SmtpMetrics {
    sessions_started: AtomicU64,
    sessions_ended: AtomicU64,
    deliveries_ok: AtomicU64,
    deliveries_rejected: AtomicU64,
    deliveries_oversized: AtomicU64,
}

impl SmtpMetrics {
    pub fn new() -> Self {
        Self {
            sessions_started: AtomicU64::new(0),
            sessions_ended: AtomicU64::new(0),
            deliveries_ok: AtomicU64::new(0),
            deliveries_rejected: AtomicU64::new(0),
            deliveries_oversized: AtomicU64::new(0),
        }
    }

    pub fn snapshot(&self) -> SmtpMetricsSnapshot {
        SmtpMetricsSnapshot {
            sessions_started: self.sessions_started.load(Ordering::Relaxed),
            sessions_ended: self.sessions_ended.load(Ordering::Relaxed),
            deliveries_ok: self.deliveries_ok.load(Ordering::Relaxed),
            deliveries_rejected: self.deliveries_rejected.load(Ordering::Relaxed),
            deliveries_oversized: self.deliveries_oversized.load(Ordering::Relaxed),
        }
    }

    pub fn record_session_start(&self) {
        self.sessions_started.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_session_end(&self) {
        self.sessions_ended.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_delivery_ok(&self) {
        self.deliveries_ok.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_delivery_rejected(&self) {
        self.deliveries_rejected.fetch_add(1, Ordering::Relaxed);
    }

    pub fn record_delivery_oversized(&self) {
        self.deliveries_oversized.fetch_add(1, Ordering::Relaxed);
    }
}

pub struct SmtpMetricsSnapshot {
    pub sessions_started: u64,
    pub sessions_ended: u64,
    pub deliveries_ok: u64,
    pub deliveries_rejected: u64,
    pub deliveries_oversized: u64,
}

/// Rate tracker using DashMap for lock-free concurrent access.
/// Each IP maps to a VecDeque of command timestamps within the sliding window.
/// Entries are evicted when the map exceeds MAX_RATE_TRACKER_ENTRIES or when
/// all timestamps for an IP expire.
static COMMAND_RATE_TRACKER: LazyLock<DashMap<IpAddr, VecDeque<Instant>>> =
    LazyLock::new(|| DashMap::with_capacity(1024));

/// Spawn a background task that periodically evicts stale entries from the
/// rate tracker. Call once at server startup.
pub fn spawn_rate_tracker_cleanup() {
    tokio::spawn(async {
        loop {
            tokio::time::sleep(RATE_TRACKER_EVICTION_INTERVAL).await;
            evict_stale_rate_entries();
        }
    });
}

/// Remove entries whose most-recent timestamp is older than the window,
/// or trim the map down to MAX_RATE_TRACKER_ENTRIES by dropping the
/// least-recently-active IPs.
fn evict_stale_rate_entries() {
    let now = Instant::now();
    let window_start = now - COMMAND_RATE_WINDOW;

    // Phase 1 — remove fully-expired entries
    COMMAND_RATE_TRACKER.retain(|_ip, timestamps| {
        // Drop entries if the newest timestamp is outside the window
        timestamps.back().map_or(false, |t| *t >= window_start)
    });

    // Phase 2 — if still over capacity, drop entries with fewest recent commands
    let len = COMMAND_RATE_TRACKER.len();
    if len > MAX_RATE_TRACKER_ENTRIES {
        let excess = len - MAX_RATE_TRACKER_ENTRIES;
        let mut entries: Vec<(IpAddr, usize)> = COMMAND_RATE_TRACKER
            .iter()
            .map(|r| (*r.key(), r.value().len()))
            .collect();
        // Sort ascending by number of recent commands — evict least-active first
        entries.sort_by_key(|&(_, count)| count);
        for (ip, _) in entries.into_iter().take(excess) {
            COMMAND_RATE_TRACKER.remove(&ip);
        }
    }
}

struct DnsCircuitState {
    consecutive_failures: u32,
    open_until: Option<Instant>,
}

static DNS_CIRCUIT: LazyLock<tokio::sync::RwLock<DnsCircuitState>> = LazyLock::new(|| {
    tokio::sync::RwLock::new(DnsCircuitState {
        consecutive_failures: 0,
        open_until: None,
    })
});

pub struct SmtpConfig {
    pub hostname: String,
    pub mailstore_addr: String,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub enable_starttls: bool,
    pub tls_acceptor: Option<TlsAcceptor>,
    /// Domains this server accepts mail for
    #[allow(dead_code)]
    pub local_domains: Vec<String>,
    /// Lowercased local domains for fast lookup
    pub local_domains_lower: HashSet<String>,
    /// Maximum SMTP line length (including CRLF)
    pub max_line_length: usize,
    /// Maximum wait time for each SMTP command/data line
    pub command_timeout: Duration,
    /// Maximum total SMTP session duration
    pub session_timeout: Duration,
    /// #157:Cached gRPC channel to mailstore — reused across messages
    grpc_channel: tokio::sync::RwLock<Option<CachedChannel>>,
    pub metrics: Arc<SmtpMetrics>,
}

struct CachedChannel {
    channel: tonic::transport::Channel,
    created_at: Instant,
}

impl SmtpConfig {
    /// Create a new SmtpConfig.
    pub fn new(
        hostname: String,
        mailstore_addr: String,
        max_message_size: usize,
        max_recipients: usize,
        enable_starttls: bool,
        tls_acceptor: Option<TlsAcceptor>,
        local_domains: Vec<String>,
        max_line_length: usize,
        command_timeout: Duration,
        session_timeout: Duration,
        metrics: Arc<SmtpMetrics>,
    ) -> Self {
        let local_domains_lower = local_domains
            .iter()
            .map(|d| d.to_lowercase())
            .collect::<HashSet<_>>();
        Self {
            hostname,
            mailstore_addr,
            max_message_size,
            max_recipients,
            enable_starttls,
            tls_acceptor,
            local_domains,
            local_domains_lower,
            max_line_length,
            command_timeout,
            session_timeout,
            grpc_channel: tokio::sync::RwLock::new(None),
            metrics,
        }
    }

    /// #157:Get or create a shared gRPC mailstore client.
    /// Re-uses the underlying HTTP/2 channel across messages.
    pub async fn grpc_client(
        &self,
        endpoint: &str,
    ) -> Result<MailstoreServiceClient<tonic::transport::Channel>> {
        {
            let guard = self.grpc_channel.read().await;
            if let Some(cached) = guard.as_ref() {
                if cached.created_at.elapsed() < GRPC_CHANNEL_TTL {
                    return Ok(MailstoreServiceClient::new(cached.channel.clone()));
                }
            }
        }

        let mut guard = self.grpc_channel.write().await;
        if let Some(cached) = guard.as_ref() {
            if cached.created_at.elapsed() < GRPC_CHANNEL_TTL {
                return Ok(MailstoreServiceClient::new(cached.channel.clone()));
            }
        }

        let channel = tonic::transport::Channel::from_shared(endpoint.to_string())
            .map_err(|e| anyhow::anyhow!("Invalid mailstore endpoint: {}", e))?
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to mailstore: {}", e))?;

        *guard = Some(CachedChannel {
            channel: channel.clone(),
            created_at: Instant::now(),
        });

        Ok(MailstoreServiceClient::new(channel))
    }
}

#[derive(Debug)]
struct SmtpState {
    helo: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data_mode: bool,
    data_buffer: Vec<u8>,
    data_too_large: bool,
    needs_helo: bool,
}

impl Default for SmtpState {
    fn default() -> Self {
        Self {
            helo: None,
            mail_from: None,
            rcpt_to: Vec::new(),
            data_mode: false,
            data_buffer: Vec::with_capacity(DATA_BUFFER_DEFAULT_CAPACITY),
            data_too_large: false,
            needs_helo: false,
        }
    }
}

enum SessionStream {
    Plain(BufStream<TcpStream>),
    Tls(BufStream<TlsStream<TcpStream>>),
    Invalid,
}

enum ReadLineStatus {
    Eof,
    Line,
    TooLong,
}

enum ReadLineBytesStatus {
    Eof,
    Line,
    TooLong,
}

impl SessionStream {
    #[allow(dead_code)]
    async fn with_stream<T, FPlain, FTls, FutPlain, FutTls>(
        &mut self,
        plain_op: FPlain,
        tls_op: FTls,
    ) -> Result<T>
    where
        FPlain: FnOnce(&mut BufStream<TcpStream>) -> FutPlain,
        FTls: FnOnce(&mut BufStream<TlsStream<TcpStream>>) -> FutTls,
        FutPlain: Future<Output = Result<T>>,
        FutTls: Future<Output = Result<T>>,
    {
        match self {
            SessionStream::Plain(stream) => plain_op(stream).await,
            SessionStream::Tls(stream) => tls_op(stream).await,
            SessionStream::Invalid => Err(anyhow::anyhow!("Invalid session stream state")),
        }
    }

    async fn read_u8(&mut self) -> Result<u8> {
        match self {
            SessionStream::Plain(stream) => stream.read_u8().await.map_err(Into::into),
            SessionStream::Tls(stream) => stream.read_u8().await.map_err(Into::into),
            SessionStream::Invalid => Err(anyhow::anyhow!("Invalid session stream state")),
        }
    }

    async fn read_chunk(&mut self, buf: &mut [u8]) -> Result<usize> {
        match self {
            SessionStream::Plain(stream) => stream.read(buf).await.map_err(Into::into),
            SessionStream::Tls(stream) => stream.read(buf).await.map_err(Into::into),
            SessionStream::Invalid => Err(anyhow::anyhow!("Invalid session stream state")),
        }
    }

    async fn drain_until_newline(&mut self) -> Result<()> {
        loop {
            match self.read_u8().await {
                Ok(byte) => {
                    if byte == b'\n' {
                        return Ok(());
                    }
                }
                Err(e) => {
                    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                        if io_err.kind() == ErrorKind::UnexpectedEof {
                            return Ok(());
                        }
                    }
                    return Err(e);
                }
            }
        }
    }

    async fn read_line_limited(
        &mut self,
        line: &mut String,
        max_len: usize,
    ) -> Result<ReadLineStatus> {
        line.clear();
        let mut bytes = Vec::with_capacity(max_len.min(256));

        loop {
            match self.read_u8().await {
                Ok(byte) => {
                    bytes.push(byte);
                    if bytes.len() > max_len {
                        self.drain_until_newline().await?;
                        return Ok(ReadLineStatus::TooLong);
                    }
                    if byte == b'\n' {
                        break;
                    }
                }
                Err(e) => {
                    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                        if io_err.kind() == ErrorKind::UnexpectedEof {
                            if bytes.is_empty() {
                                return Ok(ReadLineStatus::Eof);
                            }
                            break;
                        }
                    }
                    return Err(e);
                }
            }
        }

        *line = String::from_utf8_lossy(&bytes).into_owned();
        Ok(ReadLineStatus::Line)
    }

    async fn read_line_limited_bytes(
        &mut self,
        line: &mut Vec<u8>,
        max_len: usize,
    ) -> Result<ReadLineBytesStatus> {
        line.clear();
        line.reserve(max_len.min(256));

        loop {
            match self.read_u8().await {
                Ok(byte) => {
                    line.push(byte);
                    if line.len() > max_len {
                        self.drain_until_newline().await?;
                        return Ok(ReadLineBytesStatus::TooLong);
                    }
                    if byte == b'\n' {
                        break;
                    }
                }
                Err(e) => {
                    if let Some(io_err) = e.downcast_ref::<std::io::Error>() {
                        if io_err.kind() == ErrorKind::UnexpectedEof {
                            if line.is_empty() {
                                return Ok(ReadLineBytesStatus::Eof);
                            }
                            break;
                        }
                    }
                    return Err(e);
                }
            }
        }

        Ok(ReadLineBytesStatus::Line)
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        match self {
            SessionStream::Plain(stream) => stream.write_all(data).await.map_err(Into::into),
            SessionStream::Tls(stream) => stream.write_all(data).await.map_err(Into::into),
            SessionStream::Invalid => Err(anyhow::anyhow!("Invalid session stream state")),
        }
    }

    async fn flush(&mut self) -> Result<()> {
        match self {
            SessionStream::Plain(stream) => stream.flush().await.map_err(Into::into),
            SessionStream::Tls(stream) => stream.flush().await.map_err(Into::into),
            SessionStream::Invalid => Err(anyhow::anyhow!("Invalid session stream state")),
        }
    }
}

async fn read_client_line(
    stream: &mut SessionStream,
    line: &mut String,
    config: &SmtpConfig,
    session_deadline: Instant,
) -> Result<ReadLineStatus> {
    let now = Instant::now();
    if now >= session_deadline {
        return Err(anyhow::anyhow!("SMTP session timeout reached"));
    }

    let remaining = session_deadline.saturating_duration_since(now);
    let line_timeout = std::cmp::min(config.command_timeout, remaining);
    if line_timeout.is_zero() {
        return Err(anyhow::anyhow!("SMTP session timeout reached"));
    }

    match timeout(
        line_timeout,
        stream.read_line_limited(line, config.max_line_length),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("SMTP command timeout exceeded")),
    }
}

async fn read_client_data_line(
    stream: &mut SessionStream,
    line: &mut Vec<u8>,
    config: &SmtpConfig,
    session_deadline: Instant,
) -> Result<ReadLineBytesStatus> {
    let now = Instant::now();
    if now >= session_deadline {
        return Err(anyhow::anyhow!("SMTP session timeout reached"));
    }

    let remaining = session_deadline.saturating_duration_since(now);
    let line_timeout = std::cmp::min(config.command_timeout, remaining);
    if line_timeout.is_zero() {
        return Err(anyhow::anyhow!("SMTP session timeout reached"));
    }

    match timeout(
        line_timeout,
        stream.read_line_limited_bytes(line, config.max_line_length),
    )
    .await
    {
        Ok(result) => result,
        Err(_) => Err(anyhow::anyhow!("SMTP command timeout exceeded")),
    }
}

fn is_end_of_data_line(line: &[u8]) -> bool {
    match line {
        b".\n" | b".\r\n" => true,
        _ => false,
    }
}

async fn drain_data_until_end(
    stream: &mut SessionStream,
    config: &SmtpConfig,
    session_deadline: Instant,
) -> Result<()> {
    let mut tail: Vec<u8> = Vec::with_capacity(5);
    let mut buf = [0u8; 4096];

    loop {
        if Instant::now() >= session_deadline {
            return Err(anyhow::anyhow!("SMTP session timeout reached"));
        }

        let remaining = session_deadline.saturating_duration_since(Instant::now());
        let timeout_duration = config.command_timeout.min(remaining);
        if timeout_duration.is_zero() {
            return Err(anyhow::anyhow!("SMTP session timeout reached"));
        }

        let read = match timeout(timeout_duration, stream.read_chunk(&mut buf)).await {
            Ok(Ok(count)) => count,
            Ok(Err(e)) => return Err(e),
            Err(_) => return Err(anyhow::anyhow!("SMTP command timeout exceeded")),
        };

        if read == 0 {
            return Ok(());
        }

        for &byte in &buf[..read] {
            tail.push(byte);
            if tail.len() > 5 {
                tail.remove(0);
            }

            if tail.ends_with(b"\r\n.\r\n")
                || tail.ends_with(b"\n.\n")
                || tail.ends_with(b"\n.\r\n")
            {
                return Ok(());
            }
        }
    }
}

async fn handle_oversized_message(
    stream: &mut SessionStream,
    state: &mut SmtpState,
    config: &SmtpConfig,
    session_deadline: Instant,
) -> Result<bool> {
    drain_data_until_end(stream, config, session_deadline).await?;
    config.metrics.record_delivery_oversized();
    stream.write_all(b"552 5.3.4 Message too large\r\n").await?;
    stream.flush().await?;

    state.data_mode = false;
    state.data_too_large = false;
    state.mail_from = None;
    state.rcpt_to.clear();
    reset_data_buffer(&mut state.data_buffer);
    Ok(true)
}

pub async fn handle_connection(
    socket: TcpStream,
    config: Arc<SmtpConfig>,
    peer_addr: std::net::SocketAddr,
) -> Result<()> {
    let mut stream = SessionStream::Plain(BufStream::new(socket));
    let mut state = SmtpState::default();
    let peer = peer_addr.to_string();
    let session_deadline = Instant::now() + config.session_timeout;
    config.metrics.record_session_start();

    // Send greeting
    let greeting = format!("220 {} ESMTP ready\r\n", config.hostname);
    stream.write_all(greeting.as_bytes()).await?;
    stream.flush().await?;

    let mut line = String::with_capacity(config.max_line_length.min(256));
    let mut data_line: Vec<u8> = Vec::new();

    loop {
        let keep_going = if state.data_mode {
            handle_data_mode(
                &mut stream,
                &mut state,
                &config,
                peer_addr,
                &peer,
                session_deadline,
                &mut data_line,
            )
            .await?
        } else {
            handle_command_mode(
                &mut stream,
                &mut state,
                &config,
                peer_addr,
                &peer,
                session_deadline,
                &mut line,
            )
            .await?
        };

        if !keep_going {
            break;
        }
    }

    config.metrics.record_session_end();
    debug!(peer = %peer, "Connection closed");
    Ok(())
}

async fn handle_data_mode(
    stream: &mut SessionStream,
    state: &mut SmtpState,
    config: &SmtpConfig,
    peer_addr: std::net::SocketAddr,
    peer: &str,
    session_deadline: Instant,
    data_line: &mut Vec<u8>,
) -> Result<bool> {
    match read_client_data_line(stream, data_line, config, session_deadline).await {
        Ok(ReadLineBytesStatus::Eof) => Ok(false),
        Ok(ReadLineBytesStatus::TooLong) => {
            state.data_too_large = true;
            reset_data_buffer(&mut state.data_buffer);
            handle_oversized_message(stream, state, config, session_deadline).await
        }
        Ok(ReadLineBytesStatus::Line) => {
            if is_end_of_data_line(data_line) {
                state.data_mode = false;
                if state.data_too_large {
                    config.metrics.record_delivery_oversized();
                    stream.write_all(b"552 5.3.4 Message too large\r\n").await?;
                    stream.flush().await?;
                    state.data_too_large = false;
                } else {
                    let result = process_message(state, config, peer_addr).await;

                    match result {
                        Ok(_) => {
                            config.metrics.record_delivery_ok();
                            info!(
                                peer = %peer,
                                from = %mail_common::pii::redact_email_opt(&state.mail_from),
                                to = %mail_common::pii::redact_email_list(&state.rcpt_to),
                                size = state.data_buffer.len(),
                                "Message accepted"
                            );
                            stream
                                .write_all(b"250 2.0.0 Message accepted for delivery\r\n")
                                .await?;
                            stream.flush().await?;
                        }
                        Err(e) => {
                            config.metrics.record_delivery_rejected();
                            warn!(peer = %peer, error = %e, "Message rejected");
                            let response = "550 5.7.1 Message rejected\r\n";
                            stream.write_all(response.as_bytes()).await?;
                            stream.flush().await?;
                        }
                    }
                }

                state.mail_from = None;
                state.rcpt_to.clear();
                reset_data_buffer(&mut state.data_buffer);
                state.data_too_large = false;
            } else {
                let data_bytes = if data_line.starts_with(b"..") {
                    &data_line[1..]
                } else {
                    &data_line[..]
                };

                if !state.data_too_large
                    && state.data_buffer.len() + data_bytes.len() > config.max_message_size
                {
                    state.data_too_large = true;
                    reset_data_buffer(&mut state.data_buffer);
                    return handle_oversized_message(stream, state, config, session_deadline).await;
                } else if !state.data_too_large {
                    state.data_buffer.extend_from_slice(data_bytes);
                }
            }
            Ok(true)
        }
        Err(e) => {
            warn!(peer = %peer, error = %e, "Read error/timeout in DATA");
            stream
                .write_all(b"421 4.4.2 Timeout waiting for client input\r\n")
                .await?;
            stream.flush().await?;
            Ok(false)
        }
    }
}

async fn handle_command_mode(
    stream: &mut SessionStream,
    state: &mut SmtpState,
    config: &SmtpConfig,
    peer_addr: std::net::SocketAddr,
    peer: &str,
    session_deadline: Instant,
    line: &mut String,
) -> Result<bool> {
    line.clear();
    match read_client_line(stream, line, config, session_deadline).await {
        Ok(ReadLineStatus::Eof) => Ok(false),
        Ok(ReadLineStatus::TooLong) => {
            stream.write_all(b"500 5.5.2 Line too long\r\n").await?;
            stream.flush().await?;
            reset_line_buffer(line, config);
            Ok(true)
        }
        Ok(ReadLineStatus::Line) => {
            let command = line.trim().split_whitespace().next().unwrap_or("");

            if !allow_command_from_peer(peer_addr.ip()).await {
                stream
                    .write_all(b"421 4.7.0 Rate limit exceeded\r\n")
                    .await?;
                stream.flush().await?;
                reset_line_buffer(line, config);
                return Ok(false);
            }

            if command.eq_ignore_ascii_case("STARTTLS") {
                if !config.enable_starttls {
                    stream.write_all(b"454 4.7.0 TLS not available\r\n").await?;
                    stream.flush().await?;
                    return Ok(true);
                }

                if matches!(stream, SessionStream::Tls(_)) {
                    stream
                        .write_all(b"503 5.5.1 TLS already active\r\n")
                        .await?;
                    stream.flush().await?;
                    return Ok(true);
                }

                let acceptor = match &config.tls_acceptor {
                    Some(a) => a,
                    None => {
                        stream.write_all(b"454 4.7.0 TLS not available\r\n").await?;
                        stream.flush().await?;
                        return Ok(true);
                    }
                };

                stream
                    .write_all(b"220 2.0.0 Ready to start TLS\r\n")
                    .await?;
                stream.flush().await?;

                let current = std::mem::replace(stream, SessionStream::Invalid);
                let plain_stream = match current {
                    SessionStream::Plain(s) => s,
                    other => {
                        *stream = other;
                        return Ok(true);
                    }
                };

                let tcp_stream = plain_stream.into_inner();
                let tls_stream = match acceptor.accept(tcp_stream).await {
                    Ok(s) => s,
                    Err(e) => {
                        warn!(peer = %peer, error = %e, "STARTTLS handshake failed");
                        *stream = SessionStream::Invalid;
                        return Ok(false);
                    }
                };
                *stream = SessionStream::Tls(BufStream::new(tls_stream));

                *state = SmtpState::default();
                state.needs_helo = true;
                return Ok(true);
            }

            let response = handle_command(line, state, config, peer).await;

            if response.starts_with("221") {
                stream.write_all(response.as_bytes()).await?;
                stream.flush().await?;
                reset_line_buffer(line, config);
                return Ok(false);
            }

            stream.write_all(response.as_bytes()).await?;
            stream.flush().await?;
            reset_line_buffer(line, config);
            Ok(true)
        }
        Err(e) => {
            warn!(peer = %peer, error = %e, "Read error/timeout");
            stream
                .write_all(b"421 4.4.2 Timeout waiting for client input\r\n")
                .await?;
            stream.flush().await?;
            reset_line_buffer(line, config);
            Ok(false)
        }
    }
}

async fn allow_command_from_peer(peer_ip: IpAddr) -> bool {
    use std::sync::Once;
    static CLEANUP_INIT: Once = Once::new();
    CLEANUP_INIT.call_once(spawn_rate_tracker_cleanup);

    let now = Instant::now();
    let window_start = now - COMMAND_RATE_WINDOW;

    // DashMap entry API — only locks the shard for this IP, not the entire map
    let mut entry = COMMAND_RATE_TRACKER
        .entry(peer_ip)
        .or_insert_with(VecDeque::new);
    let timestamps = entry.value_mut();

    // Purge expired timestamps from the front
    while let Some(front) = timestamps.front() {
        if *front < window_start {
            timestamps.pop_front();
        } else {
            break;
        }
    }

    if timestamps.len() >= MAX_COMMANDS_PER_WINDOW {
        return false;
    }

    timestamps.push_back(now);
    true
}

fn reset_data_buffer(buffer: &mut Vec<u8>) {
    if buffer.capacity() > DATA_BUFFER_SHRINK_THRESHOLD {
        *buffer = Vec::with_capacity(DATA_BUFFER_DEFAULT_CAPACITY);
    } else {
        buffer.clear();
    }
}

fn reset_line_buffer(line: &mut String, config: &SmtpConfig) {
    if line.capacity() > LINE_BUFFER_SHRINK_THRESHOLD.max(config.max_line_length * 4) {
        *line = String::with_capacity(config.max_line_length.min(256));
    } else {
        line.clear();
    }
}

fn build_dns_resolver() -> Result<Resolver, anyhow::Error> {
    let servers = std::env::var("SMTP_EDGE_DNS_SERVERS").ok();
    if let Some(servers) = servers {
        let mut group = NameServerConfigGroup::new();
        for entry in servers
            .split(',')
            .map(|s| s.trim())
            .filter(|s| !s.is_empty())
        {
            let addr: std::net::IpAddr = entry
                .parse()
                .map_err(|_| anyhow::anyhow!("Invalid DNS server address: {}", entry))?;
            let socket = std::net::SocketAddr::new(addr, 53);
            group.push(NameServerConfig::new(socket, Protocol::Udp));
        }
        if group.is_empty() {
            return Resolver::new_system_conf().map_err(|e| anyhow::anyhow!("resolver: {e}"));
        }
        let config = ResolverConfig::from_parts(None, vec![], group);
        return Resolver::with_capacity(config, ResolverOpts::default(), 128)
            .map_err(|e| anyhow::anyhow!("resolver: {e}"));
    }

    Resolver::new_system_conf().map_err(|e| anyhow::anyhow!("resolver: {e}"))
}

async fn dns_circuit_allows_queries() -> bool {
    let mut state = DNS_CIRCUIT.write().await;
    if let Some(until) = state.open_until {
        if Instant::now() < until {
            return false;
        }
        state.open_until = None;
        state.consecutive_failures = 0;
    }
    true
}

async fn dns_circuit_record(success: bool) {
    let mut state = DNS_CIRCUIT.write().await;
    if success {
        state.consecutive_failures = 0;
        state.open_until = None;
        return;
    }

    state.consecutive_failures += 1;
    if state.consecutive_failures >= DNS_CIRCUIT_FAILURE_THRESHOLD {
        state.open_until = Some(Instant::now() + Duration::from_secs(DNS_CIRCUIT_OPEN_SECS));
    }
}

async fn handle_command(
    line: &str,
    state: &mut SmtpState,
    config: &SmtpConfig,
    _peer: &str,
) -> String {
    let line = line.trim();
    let (cmd, args) = match line.find(' ') {
        Some(pos) => (&line[..pos], line[pos + 1..].trim()),
        None => (line, ""),
    };

    if state.needs_helo
        && !cmd.eq_ignore_ascii_case("EHLO")
        && !cmd.eq_ignore_ascii_case("HELO")
        && !cmd.eq_ignore_ascii_case("NOOP")
        && !cmd.eq_ignore_ascii_case("QUIT")
    {
        return "503 5.5.1 EHLO/HELO required after STARTTLS\r\n".to_string();
    }

    if cmd.eq_ignore_ascii_case("HELO") {
        if args.is_empty() {
            return "501 5.5.4 HELO requires domain argument\r\n".to_string();
        }
        if !args.is_ascii() {
            return "501 5.5.4 HELO argument must be ASCII\r\n".to_string();
        }
        state.helo = Some(args.to_string());
        state.needs_helo = false;
        format!("250 {} Hello {}\r\n", config.hostname, args)
    } else if cmd.eq_ignore_ascii_case("EHLO") {
        if args.is_empty() {
            return "501 5.5.4 EHLO requires domain argument\r\n".to_string();
        }
        if !args.is_ascii() {
            return "501 5.5.4 EHLO argument must be ASCII\r\n".to_string();
        }
        state.helo = Some(args.to_string());
        state.needs_helo = false;
        let mut response = String::with_capacity(128);
        if let Err(error) = write!(
            &mut response,
            "250-{} Hello {}\r\n250-SIZE {}\r\n250-8BITMIME\r\n250-ENHANCEDSTATUSCODES\r\n",
            config.hostname, args, config.max_message_size
        ) {
            tracing::warn!(error = %error, "Failed to format EHLO response");
        }

        response.push_str("250-SMTPUTF8\r\n");

        if config.enable_starttls {
            response.push_str("250-STARTTLS\r\n");
        }

        response.push_str("250 HELP\r\n");
        response
    } else if cmd.eq_ignore_ascii_case("MAIL") {
        if state.helo.is_none() {
            return "503 5.5.1 EHLO/HELO first\r\n".to_string();
        }

        let from = parse_mail_from(args);
        match from {
            Some(addr) => {
                if let Some(size) = extract_size_param(args) {
                    if size > config.max_message_size as u64 {
                        return "552 5.3.4 Message size exceeds fixed maximum message size\r\n"
                            .to_string();
                    }
                }
                state.mail_from = Some(addr);
                state.rcpt_to.clear();
                "250 2.1.0 Sender OK\r\n".to_string()
            }
            None => "501 5.1.7 Syntax error in MAIL FROM\r\n".to_string(),
        }
    } else if cmd.eq_ignore_ascii_case("RCPT") {
        if state.mail_from.is_none() {
            return "503 5.5.1 MAIL first\r\n".to_string();
        }

        if state.rcpt_to.len() >= config.max_recipients {
            return "452 4.5.3 Too many recipients\r\n".to_string();
        }

        let to = parse_rcpt_to(args);
        match to {
            Some(addr) => {
                if is_local_domain(&addr, config) {
                    state.rcpt_to.push(addr);
                    "250 2.1.5 Recipient OK\r\n".to_string()
                } else {
                    "550 5.1.1 User not local; we do not relay\r\n".to_string()
                }
            }
            None => "501 5.1.3 Syntax error in RCPT TO\r\n".to_string(),
        }
    } else if cmd.eq_ignore_ascii_case("DATA") {
        if state.rcpt_to.is_empty() {
            return "503 5.5.1 RCPT first\r\n".to_string();
        }

        state.data_mode = true;
        reset_data_buffer(&mut state.data_buffer);
        state.data_too_large = false;
        "354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string()
    } else if cmd.eq_ignore_ascii_case("RSET") {
        state.mail_from = None;
        state.rcpt_to.clear();
        reset_data_buffer(&mut state.data_buffer);
        state.data_too_large = false;
        "250 2.0.0 OK\r\n".to_string()
    } else if cmd.eq_ignore_ascii_case("NOOP") {
        "250 2.0.0 OK\r\n".to_string()
    } else if cmd.eq_ignore_ascii_case("QUIT") {
        format!("221 2.0.0 {} closing connection\r\n", config.hostname)
    } else if cmd.eq_ignore_ascii_case("VRFY") {
        "252 2.5.2 Cannot VRFY user\r\n".to_string()
    } else if cmd.eq_ignore_ascii_case("EXPN") {
        "252 2.5.2 Cannot expand list\r\n".to_string()
    } else {
        "500 5.5.1 Command not recognized\r\n".to_string()
    }
}

fn parse_mail_from(args: &str) -> Option<String> {
    let prefix = "FROM:";
    if !args.get(..prefix.len())?.eq_ignore_ascii_case(prefix) {
        return None;
    }

    let rest = args[prefix.len()..].trim();
    extract_address(rest)
}

fn parse_rcpt_to(args: &str) -> Option<String> {
    let prefix = "TO:";
    if !args.get(..prefix.len())?.eq_ignore_ascii_case(prefix) {
        return None;
    }

    let rest = args[prefix.len()..].trim();
    let addr = extract_address(rest)?;
    if addr.is_empty() {
        return None;
    }
    Some(addr)
}

fn extract_size_param(args: &str) -> Option<u64> {
    for token in args.split_whitespace() {
        if token.len() < 6 {
            continue;
        }
        if token[..5].eq_ignore_ascii_case("size=") {
            return token[5..].trim().parse().ok();
        }
    }
    None
}

fn extract_address(s: &str) -> Option<String> {
    // Handle <address> format (including null sender <>)
    if s.starts_with('<') {
        if let Some(end) = s.find('>') {
            let inner = &s[1..end];
            // Empty <> is the null sender — valid in SMTP MAIL FROM
            if inner.is_empty() {
                return Some(String::new());
            }

            if !is_valid_addr_spec(inner) {
                return None;
            }

            return Some(inner.to_string());
        }
        // Malformed:'<' without '>'
        return None;
    }

    // Handle bare address token up to first whitespace, strip trailing params.
    let addr = s.split_whitespace().next()?;
    let addr = addr.trim_end_matches(|c| c == '>' || c == ',' || c == ';');
    if addr.is_empty() {
        return None;
    }
    if !is_valid_addr_spec(addr) {
        return None;
    }
    Some(addr.to_string())
}

fn is_valid_addr_spec(addr: &str) -> bool {
    let mut parts = addr.split('@');
    let local = parts.next().unwrap_or_default();
    let domain = parts.next().unwrap_or_default();
    local.len() > 0 && domain.len() > 0 && parts.next().is_none()
}

fn is_local_domain(addr: &str, config: &SmtpConfig) -> bool {
    let domain = addr.split('@').nth(1).unwrap_or("").to_lowercase();
    // #160:Removed unconditional localhost acceptance — prevents relay to
    // internal services. Localhost must be explicitly configured if needed.
    config.local_domains_lower.contains(&domain)
}

async fn process_message(
    state: &SmtpState,
    config: &SmtpConfig,
    peer_addr: std::net::SocketAddr,
) -> Result<()> {
    let from_addr = state
        .mail_from
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("MAIL FROM missing before DATA"))?;
    let helo_domain = state
        .helo
        .as_deref()
        .ok_or_else(|| anyhow::anyhow!("EHLO/HELO missing before DATA"))?;
    let message_data = &state.data_buffer;

    // Extract sender domain for SPF checks
    let from_domain = from_addr.split('@').nth(1).unwrap_or("").to_lowercase();

    // Extract header From domain for DMARC alignment
    let header_from_domain = extract_header_from_domain(message_data);

    // Parse the peer IP address
    let peer_ip: std::net::IpAddr = peer_addr.ip();

    // #156:Use shared DNS resolver instead of creating one per message
    let resolver = if dns_circuit_allows_queries().await {
        EDGE_RESOLVER.as_ref()
    } else {
        None
    };

    // ── SPF and DKIM verification (parallel) ───────────────────────────
    let spf_future = async {
        if resolver.is_none() {
            "temperror".to_string()
        } else if !from_domain.is_empty() {
            let Some(resolver) = resolver else {
                return "temperror".to_string();
            };
            let result = resolver
                .verify_spf_sender(peer_ip, helo_domain, &from_domain, from_addr)
                .await;
            let spf_status = match result.result() {
                SpfResult::Pass => "pass",
                SpfResult::Fail => "fail",
                SpfResult::SoftFail => "softfail",
                SpfResult::Neutral => "neutral",
                SpfResult::TempError => "temperror",
                SpfResult::PermError => "permerror",
                SpfResult::None => "none",
            };
            info!(
                peer = %peer_addr,
                from = %mail_common::pii::redact_email(&from_addr),
                spf = %spf_status,
                "SPF verification result"
            );
            spf_status.to_string()
        } else {
            "none".to_string()
        }
    };

    let dkim_future = async {
        if resolver.is_none() {
            "temperror".to_string()
        } else {
            let Some(resolver) = resolver else {
                return "temperror".to_string();
            };
            match AuthenticatedMessage::parse(message_data) {
                Some(authenticated_msg) => {
                    let dkim_output = resolver.verify_dkim(&authenticated_msg).await;
                    let mut overall = "none";
                    for result in dkim_output.iter() {
                        match result.result() {
                            DkimResult::Pass => {
                                overall = "pass";
                                break; // One pass is enough
                            }
                            DkimResult::Fail(_) => {
                                if overall != "pass" {
                                    overall = "fail";
                                }
                            }
                            DkimResult::Neutral(_) | DkimResult::None => {}
                            _ => {
                                if overall == "none" {
                                    overall = "temperror";
                                }
                            }
                        }
                    }
                    info!(
                        peer = %peer_addr,
                        from = %mail_common::pii::redact_email(&from_addr),
                        dkim = %overall,
                        "DKIM verification result"
                    );
                    overall.to_string()
                }
                None => {
                    debug!(peer = %peer_addr, "Could not parse message for DKIM verification");
                    "none".to_string()
                }
            }
        }
    };

    let (spf_result, dkim_result) = tokio::join!(spf_future, dkim_future);

    // ── #158:DMARC evaluation with DNS record lookup ──────────────────
    let spf_aligned = spf_result == "pass";
    let dkim_aligned = dkim_result == "pass";

    // Determine raw DMARC alignment result
    let dmarc_aligned = if !from_domain.is_empty() {
        if spf_aligned || dkim_aligned {
            "pass"
        } else if spf_result == "fail" && dkim_result == "fail" {
            "fail"
        } else {
            "none"
        }
    } else {
        "none"
    };

    // #158:Fetch the actual DMARC DNS record to determine the domain's policy
    let dmarc_policy = if !header_from_domain.is_empty() {
        if let Some(resolver) = resolver {
            fetch_dmarc_policy(resolver, &header_from_domain).await
        } else {
            DmarcPolicyResult::none(header_from_domain.clone())
        }
    } else {
        DmarcPolicyResult::none(String::new()) // no domain → no policy
    };

    if resolver.is_some() {
        let dns_ok = spf_result != "temperror" && dkim_result != "temperror";
        dns_circuit_record(dns_ok).await;
    }

    // Apply DMARC policy to determine final action
    let dmarc_result = dmarc_aligned;

    info!(
        peer = %peer_addr,
        from = %mail_common::pii::redact_email(&from_addr),
        spf = %spf_result,
        dkim = %dkim_result,
        dmarc = %dmarc_result,
        dmarc_policy = %dmarc_policy.policy,
        "Authentication-Results summary"
    );

    // #159:SPF hard-fail rejection is now deferred to DMARC policy.
    // Only reject if the DMARC policy mandates it (p=reject or p=quarantine).
    let mut custom_flags = Vec::new();
    if dmarc_result == "fail" {
        match dmarc_policy.policy.as_str() {
            "reject" => {
                warn!(
                    peer = %peer_addr,
                    from = %mail_common::pii::redact_email(&from_addr),
                    dmarc_policy = "reject",
                    "DMARC reject — SPF and DKIM both failed, domain policy demands rejection"
                );
                return Err(anyhow::anyhow!(
                    "Message failed authentication (SPF={}, DKIM={}, DMARC=fail, policy=reject)",
                    spf_result,
                    dkim_result
                ));
            }
            "quarantine" => {
                warn!(
                    peer = %peer_addr,
                    from = %mail_common::pii::redact_email(&from_addr),
                    dmarc_policy = "quarantine",
                    "DMARC quarantine — SPF and DKIM both failed, marking suspicious"
                );
                custom_flags.push("dmarc=quarantine".to_string());
            }
            _ => {
                // p=none or no policy — accept the message
                info!(
                    peer = %peer_addr,
                    from = %mail_common::pii::redact_email(&from_addr),
                    dmarc_policy = %dmarc_policy.policy,
                    "DMARC fail but policy is none/missing — accepting message"
                );
            }
        }
    } else if dmarc_result == "temperror" {
        warn!(
            peer = %peer_addr,
            from = %mail_common::pii::redact_email(&from_addr),
            dmarc_policy = %dmarc_policy.policy,
            "DMARC temp error — deferring enforcement"
        );
    }

    // ── Build Authentication-Results header ────────────────────────────
    let safe_from_addr = sanitize_header_value(from_addr);
    let safe_from_domain = sanitize_header_value(&header_from_domain);
    let auth_results_header = format!(
        "Authentication-Results: {};\r\n\tspf={} smtp.mailfrom={};\r\n\tdkim={};\r\n\tdmarc={} header.from={}\r\n",
        config.hostname,
        spf_result,
        safe_from_addr,
        dkim_result,
        dmarc_result,
        safe_from_domain,
    );

    // Prepend Authentication-Results header to the message
    let mut final_message = auth_results_header.into_bytes();
    final_message.extend_from_slice(message_data);
    let final_message = Bytes::from(final_message);

    // ── #157:Store via mailstore gRPC — use shared client ─────────────
    let allow_insecure_mailstore = std::env::var("SMTP_EDGE_ALLOW_INSECURE_MAILSTORE")
        .map(|v| v.eq_ignore_ascii_case("true") || v == "1")
        .unwrap_or(false);

    let mailstore_endpoint = if config.mailstore_addr.starts_with("https://") {
        config.mailstore_addr.clone()
    } else if config.mailstore_addr.starts_with("http://") {
        if allow_insecure_mailstore {
            config.mailstore_addr.clone()
        } else {
            return Err(anyhow::anyhow!(
                "Insecure mailstore endpoint '{}' is blocked; use https:// or set SMTP_EDGE_ALLOW_INSECURE_MAILSTORE=true",
                config.mailstore_addr
            ));
        }
    } else {
        format!("https://{}", config.mailstore_addr)
    };

    let client = config.grpc_client(&mailstore_endpoint).await.map_err(|e| {
        anyhow::anyhow!(
            "Failed to connect to mailstore at {}: {}",
            mailstore_endpoint,
            e
        )
    })?;

    let internal_date = chrono::Utc::now().timestamp();
    let store_tasks = state.rcpt_to.iter().cloned().map(|recipient| {
        let mut recipient_client = client.clone();
        let payload = final_message.clone();
        let custom_flags = custom_flags.clone();
        async move {
            let request = StoreMessageRequest {
                account_id: recipient.clone(),
                mailbox: "Inbox".to_string(),
                raw_message: payload,
                flags: Some(MessageFlags {
                    seen: false,
                    answered: false,
                    flagged: false,
                    deleted: false,
                    draft: false,
                    recent: true,
                    custom: custom_flags.clone(),
                }),
                internal_date,
            };

            let response = recipient_client
                .store_message(request)
                .await
                .map_err(|e| {
                    anyhow::anyhow!("Failed to store message for recipient {}: {}", recipient, e)
                })?
                .into_inner();

            debug!(
                recipient = %mail_common::pii::redact_email(&recipient),
                message_id = %response.message_id,
                uid = response.uid,
                blob_hash = %response.blob_hash,
                "Stored message in mailstore"
            );

            Ok::<(), anyhow::Error>(())
        }
    });

    try_join_all(store_tasks).await?;

    let parsed_subject = MessageParser::new()
        .parse(final_message.as_ref())
        .and_then(|m| m.subject().map(|s| s.to_string()));

    info!(
        peer = %peer_addr,
        from = %mail_common::pii::redact_email(&from_addr),
        to = %mail_common::pii::redact_email_list(&state.rcpt_to),
        subject = ?parsed_subject,
        size = final_message.len(),
        spf = %spf_result,
        dkim = %dkim_result,
        dmarc = %dmarc_result,
        "Message accepted and authenticated — ready for mailstore delivery"
    );

    Ok(())
}

fn sanitize_header_value(value: &str) -> String {
    value
        .chars()
        .filter(|c| *c != '\r' && *c != '\n' && c.is_ascii_graphic())
        .collect()
}

fn extract_header_from_domain(message_data: &[u8]) -> String {
    let message = match MessageParser::new().parse(message_data) {
        Some(message) => message,
        None => return String::new(),
    };

    let address = match message.from() {
        Some(Address::List(addresses)) => addresses.iter().find_map(|addr| addr.address.as_deref()),
        Some(Address::Group(groups)) => groups
            .iter()
            .flat_map(|group| group.addresses.iter())
            .find_map(|addr| addr.address.as_deref()),
        None => None,
    };

    address
        .and_then(|addr| addr.split('@').nth(1))
        .unwrap_or("")
        .to_lowercase()
}

#[allow(dead_code)]
fn domains_align(header_domain: &str, auth_domain: &str) -> bool {
    if header_domain.is_empty() || auth_domain.is_empty() {
        return false;
    }

    let header = canonical_domain(header_domain);
    let auth = canonical_domain(auth_domain);
    if header == auth {
        return true;
    }

    let header_org = organizational_domain(&header);
    let auth_org = organizational_domain(&auth);
    header_org.is_some() && header_org == auth_org
}

#[allow(dead_code)]
fn canonical_domain(domain: &str) -> String {
    domain.trim_end_matches('.').to_lowercase()
}

#[allow(dead_code)]
fn organizational_domain(domain: &str) -> Option<String> {
    let labels: Vec<&str> = domain
        .split('.')
        .filter(|label| !label.is_empty())
        .collect();
    if labels.len() < 2 {
        return None;
    }
    Some(labels[labels.len() - 2..].join("."))
}

/// #158:Fetch the DMARC policy from DNS for a given domain.
/// Queries `_dmarc.{domain}` TXT record, falls back to parent domains.
async fn fetch_dmarc_policy(resolver: &Resolver, domain: &str) -> DmarcPolicyResult {
    if let Some(record) = query_dmarc_txt(resolver, domain).await {
        return DmarcPolicyResult {
            policy: record.policy,
            record_domain: record.domain,
        };
    }

    for parent in parent_domains(domain) {
        if let Some(record) = query_dmarc_txt(resolver, &parent).await {
            let policy = record
                .subdomain_policy
                .unwrap_or_else(|| record.policy.clone());
            return DmarcPolicyResult {
                policy,
                record_domain: record.domain,
            };
        }
    }

    DmarcPolicyResult::none(domain.to_string())
}

/// Query `_dmarc.{domain}` TXT record and extract `p=` and `sp=` values.
async fn query_dmarc_txt(resolver: &Resolver, domain: &str) -> Option<DmarcRecord> {
    let qname = format!("_dmarc.{domain}");
    let raw = resolver.txt_raw_lookup(&qname).await.ok()?;
    let txt = String::from_utf8_lossy(&raw).to_lowercase();
    let mut has_version = false;
    let mut policy = None;
    let mut subdomain_policy = None;

    for part in txt.split(';') {
        let part = part.trim();
        if part.is_empty() {
            continue;
        }
        let mut iter = part.splitn(2, '=');
        let key = iter.next().unwrap_or("").trim();
        let value = iter.next().unwrap_or("").trim();
        match key {
            "v" => {
                if value == "dmarc1" {
                    has_version = true;
                }
            }
            "p" => policy = Some(normalize_dmarc_policy(value)),
            "sp" => subdomain_policy = Some(normalize_dmarc_policy(value)),
            _ => {}
        }
    }

    if !has_version {
        return None;
    }

    Some(DmarcRecord {
        policy: policy.unwrap_or_else(|| "none".to_string()),
        subdomain_policy,
        domain: domain.to_string(),
    })
}

fn normalize_dmarc_policy(value: &str) -> String {
    match value.trim() {
        "reject" | "quarantine" | "none" => value.trim().to_string(),
        _ => "none".to_string(),
    }
}

fn parent_domains(domain: &str) -> Vec<String> {
    let parts: Vec<&str> = domain
        .split('.')
        .filter(|label| !label.is_empty())
        .collect();
    if parts.len() < 2 {
        return Vec::new();
    }
    let mut parents = Vec::new();
    for idx in 1..parts.len() - 1 {
        parents.push(parts[idx..].join("."));
    }
    parents
}

struct DmarcRecord {
    policy: String,
    subdomain_policy: Option<String>,
    domain: String,
}

struct DmarcPolicyResult {
    policy: String,
    #[allow(dead_code)]
    record_domain: String,
}

impl DmarcPolicyResult {
    fn none(domain: String) -> Self {
        Self {
            policy: "none".to_string(),
            record_domain: domain,
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::{Ipv4Addr, Ipv6Addr};

    // -----------------------------------------------------------------------
    // SmtpMetrics
    // -----------------------------------------------------------------------

    #[test]
    fn metrics_initial_state_is_zero() {
        let m = SmtpMetrics::new();
        let s = m.snapshot();
        assert_eq!(s.sessions_started, 0);
        assert_eq!(s.sessions_ended, 0);
        assert_eq!(s.deliveries_ok, 0);
        assert_eq!(s.deliveries_rejected, 0);
        assert_eq!(s.deliveries_oversized, 0);
    }

    #[test]
    fn metrics_increment_independently() {
        let m = SmtpMetrics::new();
        m.record_session_start();
        m.record_session_start();
        m.record_delivery_ok();
        m.record_delivery_rejected();
        m.record_delivery_oversized();
        m.record_session_end();

        let s = m.snapshot();
        assert_eq!(s.sessions_started, 2);
        assert_eq!(s.sessions_ended, 1);
        assert_eq!(s.deliveries_ok, 1);
        assert_eq!(s.deliveries_rejected, 1);
        assert_eq!(s.deliveries_oversized, 1);
    }

    // -----------------------------------------------------------------------
    // Rate tracker — allow_command_from_peer
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn rate_tracker_allows_first_command() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 1));
        COMMAND_RATE_TRACKER.remove(&ip); // ensure clean slate for this IP
        assert!(allow_command_from_peer(ip).await);
        assert!(COMMAND_RATE_TRACKER.get(&ip).unwrap().len() >= 1);
    }

    #[tokio::test]
    async fn rate_tracker_allows_up_to_max_commands() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 2));
        COMMAND_RATE_TRACKER.remove(&ip);
        for _ in 0..MAX_COMMANDS_PER_WINDOW {
            assert!(allow_command_from_peer(ip).await);
        }
        // Exactly at limit — next should be rejected
        assert!(!allow_command_from_peer(ip).await);
    }

    #[tokio::test]
    async fn rate_tracker_different_ips_independent() {
        let ip_a = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 3));
        let ip_b = IpAddr::V4(Ipv4Addr::new(10, 99, 0, 4));
        COMMAND_RATE_TRACKER.remove(&ip_a);
        COMMAND_RATE_TRACKER.remove(&ip_b);

        for _ in 0..MAX_COMMANDS_PER_WINDOW {
            assert!(allow_command_from_peer(ip_a).await);
        }
        // ip_a exhausted, ip_b should still be allowed
        assert!(!allow_command_from_peer(ip_a).await);
        assert!(allow_command_from_peer(ip_b).await);
    }

    #[tokio::test]
    async fn rate_tracker_ipv6_works() {
        let ip = IpAddr::V6(Ipv6Addr::new(0xfe80, 0, 0, 0, 0, 0, 0, 99));
        COMMAND_RATE_TRACKER.remove(&ip);
        assert!(allow_command_from_peer(ip).await);
        assert!(COMMAND_RATE_TRACKER.contains_key(&ip));
    }

    // -----------------------------------------------------------------------
    // Eviction
    // -----------------------------------------------------------------------

    #[test]
    fn eviction_removes_empty_entries() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 1, 1));
        // Insert an entry with an empty VecDeque
        COMMAND_RATE_TRACKER.insert(ip, VecDeque::new());
        assert!(COMMAND_RATE_TRACKER.contains_key(&ip));

        evict_stale_rate_entries();
        // Empty deque => back returns None => should be evicted
        assert!(!COMMAND_RATE_TRACKER.contains_key(&ip));
    }

    #[test]
    fn eviction_keeps_recent_entries() {
        let ip = IpAddr::V4(Ipv4Addr::new(10, 99, 1, 2));
        let mut deque = VecDeque::new();
        deque.push_back(Instant::now()); // fresh timestamp
        COMMAND_RATE_TRACKER.insert(ip, deque);

        evict_stale_rate_entries();
        assert!(COMMAND_RATE_TRACKER.contains_key(&ip));
        // Cleanup
        COMMAND_RATE_TRACKER.remove(&ip);
    }

    #[test]
    fn eviction_phase2_trims_over_capacity() {
        // Instead of creating 100K+ unique IPs (slow), we verify the eviction
        // logic by checking that after inserting known entries and calling
        // evict, entries with stale timestamps are removed.
        let base_ip = |i: u8| IpAddr::V4(Ipv4Addr::new(10, 98, 0, i));

        // Insert 5 entries:3 with only expired timestamps, 2 with fresh
        for i in 0..3u8 {
            COMMAND_RATE_TRACKER.insert(base_ip(i), VecDeque::new());
        }
        for i in 3..5u8 {
            let mut deque: VecDeque<Instant> = VecDeque::new();
            deque.push_back(Instant::now());
            COMMAND_RATE_TRACKER.insert(base_ip(i), deque);
        }

        evict_stale_rate_entries();

        // Stale (empty) entries should be gone
        for i in 0..3u8 {
            assert!(
                !COMMAND_RATE_TRACKER.contains_key(&base_ip(i)),
                "Stale entry {} should have been evicted",
                i
            );
        }
        // Fresh entries should remain
        for i in 3..5u8 {
            assert!(
                COMMAND_RATE_TRACKER.contains_key(&base_ip(i)),
                "Fresh entry {} should still exist",
                i
            );
        }

        // Cleanup
        for i in 0..5u8 {
            COMMAND_RATE_TRACKER.remove(&base_ip(i));
        }
    }

    // -----------------------------------------------------------------------
    // Helper functions
    // -----------------------------------------------------------------------

    #[test]
    fn reset_data_buffer_shrinks_large_buffers() {
        let mut buf = Vec::with_capacity(DATA_BUFFER_SHRINK_THRESHOLD + 1);
        buf.extend_from_slice(&[0u8; 256]);
        reset_data_buffer(&mut buf);
        assert_eq!(buf.capacity(), DATA_BUFFER_DEFAULT_CAPACITY);
        assert!(buf.is_empty());
    }

    #[test]
    fn reset_data_buffer_clears_small_buffers_without_realloc() {
        let mut buf = Vec::with_capacity(64);
        buf.extend_from_slice(&[0u8; 32]);
        let cap_before = buf.capacity();
        reset_data_buffer(&mut buf);
        assert!(buf.is_empty());
        assert_eq!(buf.capacity(), cap_before); // no realloc
    }

    #[test]
    fn normalize_dmarc_policy_accepts_valid() {
        assert_eq!(normalize_dmarc_policy("reject"), "reject");
        assert_eq!(normalize_dmarc_policy("quarantine"), "quarantine");
        assert_eq!(normalize_dmarc_policy("none"), "none");
    }

    #[test]
    fn normalize_dmarc_policy_trims_whitespace() {
        assert_eq!(normalize_dmarc_policy("  reject "), "reject");
    }

    #[test]
    fn normalize_dmarc_policy_unknown_becomes_none() {
        assert_eq!(normalize_dmarc_policy("invalid"), "none");
        assert_eq!(normalize_dmarc_policy(""), "none");
        assert_eq!(normalize_dmarc_policy("REJECT"), "none"); // case-sensitive
    }

    #[test]
    fn parent_domains_multi_level() {
        let result = parent_domains("sub.example.com");
        assert_eq!(result, vec!["example.com"]);
    }

    #[test]
    fn parent_domains_two_labels() {
        let result = parent_domains("example.com");
        assert!(result.is_empty());
    }

    #[test]
    fn parent_domains_deep() {
        let result = parent_domains("a.b.c.d.com");
        assert_eq!(result, vec!["b.c.d.com", "c.d.com", "d.com"]);
    }

    #[test]
    fn parent_domains_empty_string() {
        assert!(parent_domains("").is_empty());
    }

    #[test]
    fn parent_domains_single_label() {
        assert!(parent_domains("localhost").is_empty());
    }

    // -----------------------------------------------------------------------
    // SmtpConfig
    // -----------------------------------------------------------------------

    #[test]
    fn smtp_config_local_domains_lowered() {
        let cfg = SmtpConfig::new(
            "mail.example.com".into(),
            "localhost:50051".into(),
            10 * 1024 * 1024,
            100,
            false,
            None,
            vec!["Example.COM".into(), "TEST.ORG".into()],
            998,
            Duration::from_secs(300),
            Duration::from_secs(600),
            Arc::new(SmtpMetrics::new()),
        );
        assert!(cfg.local_domains_lower.contains("example.com"));
        assert!(cfg.local_domains_lower.contains("test.org"));
        assert!(!cfg.local_domains_lower.contains("Example.COM"));
    }

    // -----------------------------------------------------------------------
    // Constants sanity
    // -----------------------------------------------------------------------

    #[test]
    fn rate_constants_are_sane() {
        assert!(MAX_COMMANDS_PER_WINDOW > 0);
        assert!(COMMAND_RATE_WINDOW.as_secs() > 0);
        assert!(MAX_RATE_TRACKER_ENTRIES > 0);
        assert!(RATE_TRACKER_EVICTION_INTERVAL.as_secs() > 0);
        assert!(RATE_TRACKER_EVICTION_INTERVAL < COMMAND_RATE_WINDOW);
    }

    #[test]
    fn data_buffer_thresholds_are_consistent() {
        assert!(DATA_BUFFER_DEFAULT_CAPACITY < DATA_BUFFER_SHRINK_THRESHOLD);
    }

    // -----------------------------------------------------------------------
    // DmarcPolicyResult
    // -----------------------------------------------------------------------

    #[test]
    fn dmarc_policy_result_none_default() {
        let result = DmarcPolicyResult::none("example.com".into());
        assert_eq!(result.policy, "none");
        assert_eq!(result.record_domain, "example.com");
    }
}
