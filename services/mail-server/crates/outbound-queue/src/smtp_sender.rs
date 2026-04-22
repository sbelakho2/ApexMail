//! Direct SMTP Sender
//!
//! Sends emails directly via SMTP with enterprise-grade infrastructure.
//! Includes DKIM signing, proper MX lookup, and retry logic.

use anyhow::{anyhow, Result};
use futures::stream::{FuturesUnordered, StreamExt};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::LazyLock;
use std::env;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;
use moka::future::Cache;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio::sync::RwLock;
use tokio::time::timeout;
use tracing::{debug, error, info, warn};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::error::ResolveErrorKind;
use trust_dns_resolver::proto::op::ResponseCode;

use crate::dkim::DkimSigner;
use crate::ip_rotation::IpPool;

/// SMTP Send Result
#[derive(Debug, Clone)]
pub struct SmtpSendResult {
    pub success: bool,
    pub message_id: String,
    pub response: String,
    pub accepted: Vec<String>,
    pub rejected: Vec<String>,
}

/// Configuration for SMTP sending
#[derive(Debug, Clone)]
pub struct SmtpSenderConfig {
    pub hostname: String,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub retry_delay_seconds: u64,
    pub require_starttls: bool,
    pub connection_pool_size: usize,
    pub mx_cache_ttl_secs: u64,
}

impl Default for SmtpSenderConfig {
    fn default() -> Self {
        Self {
            hostname: default_sender_hostname(),
            timeout_seconds: 60,
            max_retries: 3,
            retry_delay_seconds: 30,
            require_starttls: false,
            connection_pool_size: 2,
            mx_cache_ttl_secs: default_mx_cache_ttl_secs(),
        }
    }
}

/// Maximum entries in the MX cache
const MX_CACHE_MAX: u64 = 10_000;
static MAX_SMTP_RESPONSE_LINE: LazyLock<usize> = LazyLock::new(|| {
    env::var("SMTP_MAX_RESPONSE_LINE")
        .ok()
        .and_then(|val| val.parse::<usize>().ok())
        .filter(|val| *val > 0)
        .unwrap_or(1000)
});
const MAX_EHLO_LINES: usize = 64;
const MAX_CONNECTION_POOL_DOMAINS: usize = 2048;

fn default_sender_hostname() -> String {
    env::var("SMTP_SENDER_HOSTNAME")
        .or_else(|_| env::var("HOSTNAME"))
        .unwrap_or_else(|_| "localhost".to_string())
}

fn default_mx_cache_ttl_secs() -> u64 {
    env::var("SMTP_MX_CACHE_TTL_SECS")
        .ok()
        .and_then(|val| val.parse::<u64>().ok())
        .filter(|val| *val > 0)
        .unwrap_or(300)
}

/// Direct SMTP Sender - Enterprise-Grade Infrastructure
pub struct SmtpSender {
    config: SmtpSenderConfig,
    #[allow(unused)]
    from_domain: String,
    resolver: TokioAsyncResolver,
    dkim_signer: Option<DkimSigner>,
/// MX cache with TTL and bounded size (#106/#107)
    mx_cache: Cache<String, Vec<String>>,
/// Per-MX SMTP connection pool to reduce TCP/TLS handshakes
    connection_pool: RwLock<HashMap<String, Vec<PooledStream>>>,
/// Optional IP pool for source-binding and rotation (self-hosted path).
    ip_pool: Option<Arc<tokio::sync::RwLock<IpPool>>>,
}

struct OutboundMetrics {
    deliveries_ok: AtomicU64,
    deliveries_failed: AtomicU64,
    recipients_accepted: AtomicU64,
    recipients_rejected: AtomicU64,
}

impl OutboundMetrics {
    fn new() -> Self {
        Self {
            deliveries_ok: AtomicU64::new(0),
            deliveries_failed: AtomicU64::new(0),
            recipients_accepted: AtomicU64::new(0),
            recipients_rejected: AtomicU64::new(0),
        }
    }

    fn record_send_result(&self, success: bool, accepted: usize, rejected: usize) {
        if success {
            self.deliveries_ok.fetch_add(1, Ordering::Relaxed);
        } else {
            self.deliveries_failed.fetch_add(1, Ordering::Relaxed);
        }
        self.recipients_accepted
            .fetch_add(accepted as u64, Ordering::Relaxed);
        self.recipients_rejected
            .fetch_add(rejected as u64, Ordering::Relaxed);
    }

    fn snapshot(&self) -> OutboundMetricsSnapshot {
        OutboundMetricsSnapshot {
            deliveries_ok: self.deliveries_ok.load(Ordering::Relaxed),
            deliveries_failed: self.deliveries_failed.load(Ordering::Relaxed),
            recipients_accepted: self.recipients_accepted.load(Ordering::Relaxed),
            recipients_rejected: self.recipients_rejected.load(Ordering::Relaxed),
        }
    }
}

#[derive(Debug, Clone)]
pub struct OutboundMetricsSnapshot {
    pub deliveries_ok: u64,
    pub deliveries_failed: u64,
    pub recipients_accepted: u64,
    pub recipients_rejected: u64,
}

static OUTBOUND_METRICS: LazyLock<OutboundMetrics> = LazyLock::new(OutboundMetrics::new);

enum PooledStream {
    Plain(TcpStream),
    Tls(tokio_rustls::client::TlsStream<TcpStream>),
}

impl SmtpSender {
/// Create a new SMTP sender with just the from domain
    pub fn new(from_domain: String) -> Self {
        Self::build_sender(from_domain, SmtpSenderConfig::default(), None)
    }
    
/// Create with custom config
    pub fn with_config(from_domain: String, config: SmtpSenderConfig) -> Self {
        Self::build_sender(from_domain, config, None)
    }
    
/// Create with DKIM signer
    pub fn with_dkim(from_domain: String, config: SmtpSenderConfig, dkim_signer: DkimSigner) -> Self {
        Self::build_sender(from_domain, config, Some(dkim_signer))
    }

    fn build_sender(
        from_domain: String,
        config: SmtpSenderConfig,
        dkim_signer: Option<DkimSigner>,
    ) -> Self {
        let resolver = TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        let mx_cache_ttl_secs = config.mx_cache_ttl_secs;

        Self {
            config,
            from_domain,
            resolver,
            dkim_signer,
            mx_cache: Cache::builder()
                .max_capacity(MX_CACHE_MAX)
                .time_to_live(Duration::from_secs(mx_cache_ttl_secs))
                .build(),
            connection_pool: RwLock::new(HashMap::new()),
            ip_pool: None,
        }
    }
    
/// Attach an IP pool for source-binding and rotation.
    pub fn set_ip_pool(&mut self, pool: Arc<tokio::sync::RwLock<IpPool>>) {
        self.ip_pool = Some(pool);
    }
    
/// Set DKIM signer
    pub fn set_dkim_signer(&mut self, signer: DkimSigner) {
        self.dkim_signer = Some(signer);
    }
    
/// Send an email directly via SMTP
    pub async fn send(
        &self,
        from: &str,
        to: &[String],
        subject: &str,
        text_body: Option<&str>,
        html_body: Option<&str>,
        headers: Option<HashMap<String, String>>,
    ) -> Result<SmtpSendResult> {
// Group recipients by domain
        let mut by_domain: HashMap<String, Vec<String>> = HashMap::new();
        for recipient in to {
            let domain = recipient.split('@').nth(1)
                .ok_or_else(|| anyhow!("Invalid recipient: {}", recipient))?;
            by_domain.entry(domain.to_string())
                .or_default()
                .push(recipient.clone());
        }
        
        let mut all_accepted = Vec::with_capacity(to.len());
        let mut all_rejected = Vec::with_capacity(to.len());
        let mut last_response: Option<String> = None;
        
// Generate a single Message-ID for the email (#103:avoid dual generation)
        let message_id = format!("<{}@{}>", uuid::Uuid::new_v4(), self.config.hostname);
        
        let mut domain_payloads = Vec::with_capacity(by_domain.len());
        for (domain, recipients) in by_domain {
            let message = self.build_message(
                from,
                &recipients,
                subject,
                text_body,
                html_body,
                &headers,
                &message_id,
            )?;
            domain_payloads.push((domain, recipients, message));
        }

        let mut deliveries = FuturesUnordered::new();
        for (domain, recipients, message) in domain_payloads {
            let message_id = message_id.clone();
            deliveries.push(async move {
                let mx_servers = self.lookup_mx(&domain).await?;
                if mx_servers.is_empty() {
                    warn!(domain = %domain, "No MX records found");
                    return Ok::<(Vec<String>, Vec<String>, String), anyhow::Error>((
                        Vec::new(),
                        recipients,
                        String::new(),
                    ));
                }

                let mut sent = false;
                let mut accepted = Vec::with_capacity(recipients.len());
                let mut rejected = Vec::with_capacity(recipients.len());
                let mut response = String::new();
                for mx_host in &mx_servers {
                    match self
                        .send_to_mx(mx_host, from, &recipients, &message, &message_id)
                        .await
                    {
                        Ok(result) => {
                            accepted.extend(result.accepted);
                            rejected.extend(result.rejected);
                            response = result.response;
                            sent = true;
                            break;
                        }
                        Err(e) => {
                            warn!(mx = %mx_host, error = %e, "MX delivery failed, trying next");
                        }
                    }
                }

                if !sent {
                    rejected.extend(recipients);
                }

                Ok::<(Vec<String>, Vec<String>, String), anyhow::Error>((
                    accepted,
                    rejected,
                    response,
                ))
            });
        }

        while let Some(result) = deliveries.next().await {
            let (accepted, rejected, response) = result?;
            all_accepted.extend(accepted);
            all_rejected.extend(rejected);
            if !response.is_empty() {
                last_response = Some(response);
            }
        }
        
        let success = !all_accepted.is_empty();
        
        OUTBOUND_METRICS.record_send_result(success, all_accepted.len(), all_rejected.len());

        Ok(SmtpSendResult {
            success,
            message_id,
            response: last_response.unwrap_or_default(),
            accepted: all_accepted,
            rejected: all_rejected,
        })
    }

    pub fn metrics_snapshot(&self) -> OutboundMetricsSnapshot {
        OUTBOUND_METRICS.snapshot()
    }
    
/// Look up MX records for a domain
    async fn lookup_mx(&self, domain: &str) -> Result<Vec<String>> {
// Check cache first (moka handles TTL and eviction)
        if let Some(cached) = self.mx_cache.get(domain).await {
            return Ok(cached);
        }
        
        debug!(domain = %domain, "Looking up MX records");
        
        let lookup = self.resolver.mx_lookup(domain).await;
        
        let mx_servers: Vec<String> = match lookup {
            Ok(mx) => {
                let mut servers: Vec<(u16, String)> = mx.iter()
                    .map(|r| (r.preference(), r.exchange().to_string().trim_end_matches('.').to_string()))
                    .collect();
                servers.sort_by_key(|(pref, _)| *pref);
                servers.into_iter().map(|(_, host)| host).collect()
            }
            Err(err) => match err.kind() {
                ResolveErrorKind::NoRecordsFound { response_code, .. }
                    if *response_code == ResponseCode::NoError
                        || *response_code == ResponseCode::NXDomain =>
                {
// Fall back to A record (implicit MX)
                    vec![domain.to_string()]
                }
                _ => return Err(err.into()),
            },
        };
        
// Cache the result (moka enforces TTL + max capacity)
        self.mx_cache.insert(domain.to_string(), mx_servers).await;

        self.mx_cache
            .get(domain)
            .await
            .ok_or_else(|| anyhow!("MX cache insert/read inconsistency for {}", domain))
    }
    
/// Send to a specific MX server
    async fn send_to_mx(
        &self,
        mx_host: &str,
        from: &str,
        recipients: &[String],
        message: &[u8],
        message_id: &str,
    ) -> Result<SmtpSendResult> {
        let timeout_duration = Duration::from_secs(self.config.timeout_seconds);
        let session_timeout = timeout_duration.saturating_mul(4);

        if let Some(stream) = self.take_pooled_connection(mx_host).await {
            let (result, pooled) = timeout(
                session_timeout,
                self.smtp_session_from_pool(stream, mx_host, from, recipients, message, message_id),
            )
            .await
            .map_err(|_| anyhow!("Timed out reusing pooled SMTP session for {}", mx_host))??;
            if let Some(returned) = pooled {
                self.return_pooled_connection(mx_host, returned).await;
            }
            return Ok(result);
        }

// Resolve MX host to IP
        let addrs = self.resolver.lookup_ip(mx_host).await?;
        let addr = addrs
            .iter()
            .next()
            .ok_or_else(|| anyhow!("No IP addresses for MX host: {}", mx_host))?;

        let socket_addr = SocketAddr::new(addr, 25);

        debug!(mx = %mx_host, addr = %socket_addr, "Connecting to MX server");

// Connect with timeout — use source-bound socket when IP pool is available
        let stream = if let Some(ref ip_pool) = self.ip_pool {
            let pool = ip_pool.read().await;
            let (stream, source_ip) = timeout(
                timeout_duration,
                pool.connect_with_source(socket_addr, None),
            )
            .await
            .map_err(|_| anyhow!("Timed out connecting to {}", mx_host))??;
            debug!(source = %source_ip, mx = %mx_host, "Connected with source-bound IP");
            stream
        } else {
            timeout(timeout_duration, TcpStream::connect(socket_addr)).await??
        };
        let (result, pooled) = timeout(
            session_timeout,
            self.smtp_session_plain(stream, mx_host, from, recipients, message, message_id, true),
        )
        .await
        .map_err(|_| anyhow!("Timed out SMTP session for {}", mx_host))??;
        if let Some(returned) = pooled {
            self.return_pooled_connection(mx_host, returned).await;
        }
        Ok(result)
    }
    
/// Continue SMTP conversation over a TLS stream
    async fn smtp_conversation_over_tls(
        &self,
        tls_stream: tokio_rustls::client::TlsStream<TcpStream>,
        mx_host: &str,
        from: &str,
        recipients: &[String],
        message: &[u8],
        message_id: &str,
    ) -> Result<(SmtpSendResult, Option<PooledStream>)> {
        let mut stream = BufStream::new(tls_stream);
        let timeout_duration = Duration::from_secs(self.config.timeout_seconds);
        
// Re-EHLO after TLS upgrade (RFC 3207 §4.2)
        let ehlo_cmd = format!("EHLO {}\r\n", self.config.hostname);
        stream.write_all(ehlo_cmd.as_bytes()).await?;
        
        read_ehlo_response(&mut stream, timeout_duration).await?;
        
// Proceed with MAIL FROM / RCPT TO / DATA over TLS
        let result = self
            .smtp_mail_transaction(&mut stream, from, recipients, message, mx_host, message_id)
            .await?;

        let pooled = self.maybe_pool_connection_tls(stream).await?;
        Ok((result, pooled))
    }
    
/// Execute the MAIL FROM → RCPT TO → DATA → message sequence
    async fn smtp_mail_transaction<S>(
        &self,
        stream: &mut S,
        from: &str,
        recipients: &[String],
        message: &[u8],
        mx_host: &str,
        message_id: &str,
    ) -> Result<SmtpSendResult>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut response = String::new();
        let timeout_duration = Duration::from_secs(self.config.timeout_seconds);
        let mail_from = format!("MAIL FROM:<{}>\r\n", from);
        stream.write_all(mail_from.as_bytes()).await?;
        response.clear();
        read_smtp_line_timeout(stream, &mut response, timeout_duration).await?;
        if !response.starts_with("250") {
            return Err(anyhow!("MAIL FROM failed: {}", response.trim()));
        }
        
// RCPT TO for each recipient
        let mut accepted = Vec::with_capacity(recipients.len());
        let mut rejected = Vec::with_capacity(recipients.len());
        
        for recipient in recipients {
            let rcpt_to = format!("RCPT TO:<{}>\r\n", recipient);
            stream.write_all(rcpt_to.as_bytes()).await?;
            response.clear();
            read_smtp_line_timeout(stream, &mut response, timeout_duration).await?;
            if response.starts_with("250") {
                accepted.push(recipient.clone());
            } else {
                rejected.push(recipient.clone());
                warn!(recipient = %mail_common::pii::redact_email(&recipient), response = %response.trim(), "Recipient rejected");
            }
        }
        
        if accepted.is_empty() {
// RSET and read response (#104:avoid stream desync)
            stream.write_all(b"RSET\r\n").await?;
            response.clear();
            if let Err(error) = read_smtp_line_timeout(stream, &mut response, timeout_duration).await {
                warn!(error = %error, "Failed to read SMTP response after RSET");
            }
            return Ok(SmtpSendResult {
                success: false,
                message_id: message_id.to_string(),
                response: response.trim().to_string(),
                accepted,
                rejected,
            });
        }
        
// DATA
        stream.write_all(b"DATA\r\n").await?;
        response.clear();
        read_smtp_line_timeout(stream, &mut response, timeout_duration).await?;
        if !response.starts_with("354") {
            return Err(anyhow!("DATA failed: {}", response.trim()));
        }
        
// Send message with dot-stuffing (RFC 5321 §4.5.2) (#100)
// Any line starting with '.' must have it doubled to prevent SMTP smuggling
        let stuffed = dot_stuff_message(message);
        stream.write_all(&stuffed).await?;
        
// End of message
        stream.write_all(b"\r\n.\r\n").await?;
        response.clear();
        read_smtp_line_timeout(stream, &mut response, timeout_duration).await?;
        if !response.starts_with("250") {
            return Err(anyhow!("Message rejected: {}", response.trim()));
        }
        
        let final_response = response.trim().to_string();
        let extracted_id = extract_queue_id(&final_response)
            .unwrap_or_else(|| message_id.to_string());
        
        info!(mx = %mx_host, accepted = ?accepted, "Message delivered successfully");
        
        Ok(SmtpSendResult {
            success: true,
            message_id: extracted_id,
            response: final_response,
            accepted,
            rejected,
        })
    }
    
/// Sanitize a header value to prevent header injection (#101)
/// Strips CR, LF, and NUL bytes that could inject additional headers
    fn sanitize_header(value: &str) -> String {
        value.chars().filter(|c| *c != '\r' && *c != '\n' && *c != '\0').collect()
    }
    
/// Build an RFC 5322 compliant email message
    fn build_message(
        &self,
        from: &str,
        to: &[String],
        subject: &str,
        text_body: Option<&str>,
        html_body: Option<&str>,
        headers: &Option<HashMap<String, String>>,
        message_id: &str,
    ) -> Result<Vec<u8>> {
        use chrono::Utc;
        
        let date = Utc::now().to_rfc2822();
        
        let mut msg = Vec::with_capacity(1024);
        
// Required headers — sanitize all user-supplied values (#101)
        let safe_from = Self::sanitize_header(from);
        let safe_to: Vec<String> = to.iter().map(|t| Self::sanitize_header(t)).collect();
        let safe_subject = Self::sanitize_header(subject);
        
        msg.extend_from_slice(format!("From: {}\r\n", safe_from).as_bytes());
        msg.extend_from_slice(format!("To: {}\r\n", safe_to.join(", ")).as_bytes());
        msg.extend_from_slice(format!("Subject: {}\r\n", safe_subject).as_bytes());
        msg.extend_from_slice(format!("Date: {}\r\n", date).as_bytes());
        msg.extend_from_slice(format!("Message-ID: {}\r\n", message_id).as_bytes());
        msg.extend_from_slice(b"MIME-Version: 1.0\r\n");
        
// Custom headers — sanitize keys and values (#101)
        if let Some(hdrs) = headers {
            for (key, value) in hdrs {
                let safe_key = Self::sanitize_header(key);
                let safe_value = Self::sanitize_header(value);
                msg.extend_from_slice(format!("{}: {}\r\n", safe_key, safe_value).as_bytes());
            }
        }
        
// Body
// #102:Use 8bit transfer encoding (honest about the encoding we actually use)
        match (text_body, html_body) {
            (Some(text), Some(html)) => {
// Multipart alternative
                let boundary = format!("----=_Part_{}", uuid::Uuid::new_v4().to_string().replace('-', ""));
                msg.extend_from_slice(format!("Content-Type: multipart/alternative; boundary=\"{}\"\r\n", boundary).as_bytes());
                msg.extend_from_slice(b"\r\n");
                
// Text part
                msg.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
                msg.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
                msg.extend_from_slice(b"Content-Transfer-Encoding: 8bit\r\n");
                msg.extend_from_slice(b"\r\n");
                msg.extend_from_slice(text.as_bytes());
                msg.extend_from_slice(b"\r\n");
                
// HTML part
                msg.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
                msg.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
                msg.extend_from_slice(b"Content-Transfer-Encoding: 8bit\r\n");
                msg.extend_from_slice(b"\r\n");
                msg.extend_from_slice(html.as_bytes());
                msg.extend_from_slice(b"\r\n");
                
// End boundary
                msg.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
            }
            (Some(text), None) => {
                msg.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
                msg.extend_from_slice(b"\r\n");
                msg.extend_from_slice(text.as_bytes());
            }
            (None, Some(html)) => {
                msg.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
                msg.extend_from_slice(b"\r\n");
                msg.extend_from_slice(html.as_bytes());
            }
            (None, None) => {
                msg.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
                msg.extend_from_slice(b"\r\n");
            }
        }
        
// Sign with DKIM if configured
        if let Some(ref signer) = self.dkim_signer {
            let signature = signer.sign(&msg)?;
            let mut signed_msg = signature.into_bytes();
            signed_msg.extend_from_slice(b"\r\n");
            signed_msg.extend_from_slice(&msg);
            return Ok(signed_msg);
        }
        
        Ok(msg)
    }
}

impl SmtpSender {
    async fn take_pooled_connection(&self, mx_host: &str) -> Option<PooledStream> {
        let mut pool = self.connection_pool.write().await;
        pool.get_mut(mx_host).and_then(|connections| connections.pop())
    }

    async fn return_pooled_connection(&self, mx_host: &str, stream: PooledStream) {
        let mut pool = self.connection_pool.write().await;
        if !pool.contains_key(mx_host) && pool.len() >= MAX_CONNECTION_POOL_DOMAINS {
            drop(pool);
            self.close_pooled_connection(stream).await;
            return;
        }
        let entry = pool.entry(mx_host.to_string()).or_default();
        if entry.len() < self.config.connection_pool_size {
            entry.push(stream);
        } else {
            drop(pool);
            self.close_pooled_connection(stream).await;
        }
    }

    async fn close_pooled_connection(&self, stream: PooledStream) {
        match stream {
            PooledStream::Plain(tcp_stream) => {
                let mut stream = BufStream::new(tcp_stream);
                if let Err(error) = self.send_quit(&mut stream).await {
                    warn!(error = %error, "Failed to close pooled plaintext SMTP stream cleanly");
                }
            }
            PooledStream::Tls(tls_stream) => {
                let mut stream = BufStream::new(tls_stream);
                if let Err(error) = self.send_quit(&mut stream).await {
                    warn!(error = %error, "Failed to close pooled TLS SMTP stream cleanly");
                }
            }
        }
    }

    async fn smtp_session_from_pool(
        &self,
        stream: PooledStream,
        mx_host: &str,
        from: &str,
        recipients: &[String],
        message: &[u8],
        message_id: &str,
    ) -> Result<(SmtpSendResult, Option<PooledStream>)> {
        match stream {
            PooledStream::Plain(tcp_stream) => {
                self.smtp_session_plain(
                    tcp_stream,
                    mx_host,
                    from,
                    recipients,
                    message,
                    message_id,
                    false,
                )
                    .await
            }
            PooledStream::Tls(tls_stream) => {
                self.smtp_conversation_over_tls(
                    tls_stream,
                    mx_host,
                    from,
                    recipients,
                    message,
                    message_id,
                )
                    .await
            }
        }
    }

    async fn smtp_session_plain(
        &self,
        stream: TcpStream,
        mx_host: &str,
        from: &str,
        recipients: &[String],
        message: &[u8],
        message_id: &str,
        expect_greeting: bool,
    ) -> Result<(SmtpSendResult, Option<PooledStream>)> {
        let mut stream = BufStream::new(stream);
        let mut response = String::new();
        let timeout_duration = Duration::from_secs(self.config.timeout_seconds);

        if expect_greeting {
            response.clear();
            read_smtp_line_timeout(&mut stream, &mut response, timeout_duration).await?;
            if !response.starts_with("220") {
                return Err(anyhow!("Bad greeting: {}", response.trim()));
            }
        }

// EHLO
        let ehlo_cmd = format!("EHLO {}\r\n", self.config.hostname);
        stream.write_all(ehlo_cmd.as_bytes()).await?;

// Read EHLO response (may be multi-line), collect capabilities
        let ehlo_lines = read_ehlo_response(&mut stream, timeout_duration).await?;

// Check if remote server advertises STARTTLS
        let supports_starttls = ehlo_lines.iter().any(|l| {
            l.len() >= 4 && l[4..].trim().eq_ignore_ascii_case("STARTTLS")
        });

// Attempt STARTTLS upgrade if supported
        if supports_starttls {
            debug!(mx = %mx_host, "Server supports STARTTLS, upgrading connection");

            stream.write_all(b"STARTTLS\r\n").await?;
            response.clear();
            read_smtp_line_timeout(&mut stream, &mut response, timeout_duration).await?;
            if !response.starts_with("220") {
                error!(mx = %mx_host, response = %response.trim(), "STARTTLS rejected by server that advertised it; aborting to prevent security downgrade");
                return Err(anyhow!("STARTTLS rejected by {}: {}; refusing plaintext downgrade", mx_host, response.trim()));
            }

            stream.flush().await?;
            let tcp_stream = stream.into_inner();

            let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
            root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());

            let tls_config = tokio_rustls::rustls::ClientConfig::builder()
                .with_root_certificates(root_store)
                .with_no_client_auth();
            let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));

            let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(mx_host.to_string())
                .map_err(|e| anyhow!("Invalid server name for TLS: {}", e))?;

            let tls_stream = connector.connect(server_name, tcp_stream).await
                .map_err(|e| anyhow!("TLS handshake failed with {}: {}", mx_host, e))?;

            info!(mx = %mx_host, "STARTTLS upgrade successful");

            return self
                .smtp_conversation_over_tls(
                    tls_stream,
                    mx_host,
                    from,
                    recipients,
                    message,
                    message_id,
                )
                .await;
        }

        if self.config.require_starttls {
            return Err(anyhow!("STARTTLS required but not advertised by {}", mx_host));
        }

        debug!(mx = %mx_host, "Server does not support STARTTLS, sending in plaintext");
        let result = self
            .smtp_mail_transaction(&mut stream, from, recipients, message, mx_host, message_id)
            .await?;

        let pooled = self.maybe_pool_connection_plain(stream).await?;
        Ok((result, pooled))
    }

    async fn maybe_pool_connection_plain(
        &self,
        mut stream: BufStream<TcpStream>,
    ) -> Result<Option<PooledStream>> {
        if self.config.connection_pool_size == 0 {
            self.send_quit(&mut stream).await?;
            return Ok(None);
        }

        if !self.reset_session(&mut stream).await? {
            self.send_quit(&mut stream).await?;
            return Ok(None);
        }

        let tcp = stream.into_inner();
        Ok(Some(PooledStream::Plain(tcp)))
    }

    async fn maybe_pool_connection_tls(
        &self,
        mut stream: BufStream<tokio_rustls::client::TlsStream<TcpStream>>,
    ) -> Result<Option<PooledStream>> {
        if self.config.connection_pool_size == 0 {
            self.send_quit(&mut stream).await?;
            return Ok(None);
        }

        if !self.reset_session(&mut stream).await? {
            self.send_quit(&mut stream).await?;
            return Ok(None);
        }

        let tls_stream = stream.into_inner();
        Ok(Some(PooledStream::Tls(tls_stream)))
    }

    async fn reset_session<S>(&self, stream: &mut S) -> Result<bool>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Duration::from_secs(self.config.timeout_seconds);
        stream.write_all(b"RSET\r\n").await?;
        let mut response = String::new();
        read_smtp_line_timeout(stream, &mut response, timeout_duration).await?;
        Ok(response.starts_with("250"))
    }

    async fn send_quit<S>(&self, stream: &mut S) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let timeout_duration = Duration::from_secs(self.config.timeout_seconds);
        stream.write_all(b"QUIT\r\n").await?;
        let mut response = String::new();
        if let Err(error) = read_smtp_line_timeout(stream, &mut response, timeout_duration).await {
            warn!(error = %error, "No SMTP response received after QUIT");
        }
        if let Err(error) = stream.shutdown().await {
            warn!(error = %error, "Failed to shutdown SMTP stream after QUIT");
        }
        Ok(())
    }
}

async fn read_smtp_line_limited<R>(reader: &mut R, response: &mut String) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    response.clear();
    let mut bytes = Vec::with_capacity(128);

    loop {
        let byte = match reader.read_u8().await {
            Ok(b) => b,
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                if bytes.is_empty() {
                    return Ok(0);
                }
                break;
            }
            Err(e) => return Err(e.into()),
        };

        bytes.push(byte);
        if bytes.len() > *MAX_SMTP_RESPONSE_LINE {
            while let Ok(next) = reader.read_u8().await {
                if next == b'\n' {
                    break;
                }
            }
            return Err(anyhow!("SMTP response line too long"));
        }

        if byte == b'\n' {
            break;
        }
    }

    *response = String::from_utf8_lossy(&bytes).into_owned();
    Ok(bytes.len())
}

async fn read_smtp_line_timeout<R>(
    reader: &mut R,
    response: &mut String,
    timeout_duration: Duration,
) -> Result<usize>
where
    R: AsyncRead + Unpin,
{
    match timeout(timeout_duration, read_smtp_line_limited(reader, response)).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("SMTP response timeout")),
    }
}

async fn read_ehlo_response<S>(
    stream: &mut S,
    timeout_duration: Duration,
) -> Result<Vec<String>>
where
    S: AsyncRead + Unpin,
{
    let mut lines = Vec::with_capacity(MAX_EHLO_LINES);
    let mut response = String::new();

    for _ in 0..MAX_EHLO_LINES {
        response.clear();
        read_smtp_line_timeout(stream, &mut response, timeout_duration).await?;
        if response.len() < 4 {
            return Err(anyhow!("Invalid EHLO response"));
        }

        if !response.starts_with("250") {
            return Err(anyhow!("EHLO failed: {}", response.trim()));
        }

        let separator = response.chars().nth(3).unwrap_or(' ');
        if separator != '-' && separator != ' ' {
            return Err(anyhow!("Malformed EHLO response: {}", response.trim()));
        }

        lines.push(response.clone());
        if separator == ' ' {
            return Ok(lines);
        }
    }

    Err(anyhow!("EHLO response too long"))
}

fn dot_stuff_message(message: &[u8]) -> Vec<u8> {
    let mut stuffed = Vec::with_capacity(message.len() + 16);
    let mut start_of_line = true;

    for &byte in message {
        if start_of_line && byte == b'.' {
            stuffed.push(b'.');
        }
        stuffed.push(byte);
        start_of_line = byte == b'\n';
    }

    stuffed
}

fn extract_queue_id(response: &str) -> Option<String> {
    let normalized = response.to_ascii_lowercase();
    for marker in ["queued as", "queue id", "queued id"] {
        if let Some(pos) = normalized.find(marker) {
            let tail = response[pos + marker.len()..].trim();
            let token = tail.split_whitespace().next().unwrap_or("");
            let cleaned = token.trim_matches(&['<', '>', ':', ';', '.', ','][..]);
            if !cleaned.is_empty() {
                return Some(cleaned.to_string());
            }
        }
    }
    None
}

/// Send a simple email (convenience function)
pub async fn send_email(
    from: &str,
    to: &[String],
    subject: &str,
    text_body: Option<&str>,
    html_body: Option<&str>,
    dkim_signer: Option<DkimSigner>,
) -> Result<SmtpSendResult> {
    let config = SmtpSenderConfig::default();
    let from_domain = from.split('@').nth(1).unwrap_or("apexmail.ee").to_string();
    
    let sender = if let Some(signer) = dkim_signer {
        SmtpSender::with_dkim(from_domain, config, signer)
    } else {
        SmtpSender::with_config(from_domain, config)
    };
    
    sender.send(from, to, subject, text_body, html_body, None).await
}
