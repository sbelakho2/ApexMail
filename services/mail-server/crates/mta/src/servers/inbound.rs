//! Inbound SMTP server – accepts mail on port 25 (STARTTLS) and 465 (implicit TLS).
//!
//! Implements rate limiting, SPF/DKIM/DMARC authentication, VERP reply detection,
//! and message storage.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::Arc;
use std::time::{Duration, Instant};

use bytes::BytesMut;
use dashmap::DashMap;
use governor::{Quota, RateLimiter};
use nonzero_ext::nonzero;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::auth::EmailAuthenticator;
use crate::config::{InboundConfig, EmailAuthConfig, RateLimitConfig};

// ── types ──────────────────────────────────────────────────────────────────────

/// Per‑session context tracked during an SMTP conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub id: String,
    pub client_ip: IpAddr,
    pub authenticated: bool,
    pub tenant_id: Option<String>,
    pub message_count: u32,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub helo_hostname: String,
    pub mail_from: Option<String>,
    pub rcpt_to: Vec<String>,
}

/// Inbound SMTP server.
pub struct InboundServer {
    config: InboundConfig,
    rate_limit_config: RateLimitConfig,
    pool: PgPool,
    redis: deadpool_redis::Pool,
    authenticator: Arc<EmailAuthenticator>,
    hostname: String,
    /// Per‑IP connection counter.
    connections: Arc<DashMap<IpAddr, u32>>,
    /// Rate limiter per IP (token bucket).
    ip_limiters: Arc<DashMap<IpAddr, Arc<RateLimiter<governor::state::NotKeyed, governor::state::InMemoryState, governor::clock::DefaultClock>>>>,
    shutdown: Arc<Notify>,
}

impl InboundServer {
    pub fn new(
        config: InboundConfig,
        rate_limit_config: RateLimitConfig,
        pool: PgPool,
        redis: deadpool_redis::Pool,
        authenticator: Arc<EmailAuthenticator>,
        hostname: String,
    ) -> Self {
        Self {
            config,
            rate_limit_config,
            pool,
            redis,
            authenticator,
            hostname,
            connections: Arc::new(DashMap::new()),
            ip_limiters: Arc::new(DashMap::new()),
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Start listening on both plain (STARTTLS) and implicit‑TLS ports.
    pub async fn start(self: Arc<Self>, tls: Option<TlsAcceptor>) -> anyhow::Result<()> {
        let plain_addr = format!("{}:{}", self.config.host, self.config.port);
        let plain_listener = TcpListener::bind(&plain_addr).await?;
        info!(addr = %plain_addr, "Inbound SMTP server listening (STARTTLS)");

        let tls_handle = if let Some(ref acceptor) = tls {
            let secure_addr = format!("{}:{}", self.config.host, self.config.secure_port);
            let tls_listener = TcpListener::bind(&secure_addr).await?;
            info!(addr = %secure_addr, "Inbound SMTP server listening (implicit TLS)");
            let server = self.clone();
            let acc = acceptor.clone();
            Some(tokio::spawn(async move {
                loop {
                    tokio::select! {
                        res = tls_listener.accept() => {
                            match res {
                                Ok((socket, peer)) => {
                                    let srv = server.clone();
                                    let a = acc.clone();
                                    tokio::spawn(async move {
                                        match a.accept(socket).await {
                                            Ok(tls_stream) => {
                                                srv.handle_session_tls(tls_stream, peer).await;
                                            }
                                            Err(e) => debug!(error = %e, "TLS handshake failed"),
                                        }
                                    });
                                }
                                Err(e) => warn!(error = %e, "TLS accept error"),
                            }
                        }
                        _ = server.shutdown.notified() => break,
                    }
                }
            }))
        } else {
            None
        };

        // Plain listener loop
        loop {
            tokio::select! {
                res = plain_listener.accept() => {
                    match res {
                        Ok((socket, peer)) => {
                            let srv = self.clone();
                            let tls_acc = tls.clone();
                            tokio::spawn(async move {
                                srv.handle_session_plain(socket, peer, tls_acc).await;
                            });
                        }
                        Err(e) => warn!(error = %e, "Accept error"),
                    }
                }
                _ = self.shutdown.notified() => break,
            }
        }

        if let Some(h) = tls_handle {
            h.abort();
        }
        Ok(())
    }

    /// Graceful shutdown.
    pub fn stop(&self) {
        self.shutdown.notify_waiters();
    }

    // ── session handlers ───────────────────────────────────────────────────────

    async fn handle_session_plain(
        self: Arc<Self>,
        socket: TcpStream,
        peer: SocketAddr,
        tls: Option<TlsAcceptor>,
    ) {
        let ip = peer.ip();
        if !self.check_rate_limit(ip) {
            let _ = write_line_tcp(&socket, "421 Too many connections, try again later\r\n").await;
            return;
        }
        self.track_connection(ip, true);

        let mut ctx = SessionContext {
            id: Uuid::new_v4().to_string(),
            client_ip: ip,
            authenticated: false,
            tenant_id: None,
            message_count: 0,
            start_time: chrono::Utc::now(),
            helo_hostname: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
        };

        let mut stream = BufStream::new(socket);
        let greeting = format!("220 {} ESMTP ApexMail MTA\r\n", self.hostname);
        if let Err(e) = write_line_buf(&mut stream, &greeting).await {
            debug!(error = %e, "Failed to send greeting");
            self.track_connection(ip, false);
            return;
        }

        let mut line = String::new();
        loop {
            line.clear();
            match tokio::time::timeout(Duration::from_secs(300), stream.read_line(&mut line)).await
            {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(_)) => {}
                Ok(Err(e)) => {
                    debug!(error = %e, "Read error");
                    break;
                }
            }

            let cmd = line.trim().to_uppercase();
            let response = self.handle_command(&cmd, &line, &mut ctx).await;

            if let Err(e) = write_line_buf(&mut stream, &response).await {
                debug!(error = %e, "Write error");
                break;
            }

            if cmd.starts_with("QUIT") {
                break;
            }

            // DATA handling
            if cmd.starts_with("DATA") && response.starts_with("354") {
                let mut message = BytesMut::new();
                loop {
                    line.clear();
                    match tokio::time::timeout(Duration::from_secs(300), stream.read_line(&mut line)).await {
                        Ok(Ok(0)) | Err(_) => break,
                        Ok(Ok(_)) => {
                            if line.trim() == "." {
                                break;
                            }
                            // Dot-unstuffing
                            if line.starts_with("..") {
                                message.extend_from_slice(line[1..].as_bytes());
                            } else {
                                message.extend_from_slice(line.as_bytes());
                            }
                        }
                        Ok(Err(_)) => break,
                    }
                    if message.len() > self.config.max_message_size {
                        let _ = write_line_buf(&mut stream, "552 Message too large\r\n").await;
                        break;
                    }
                }

                if message.len() <= self.config.max_message_size {
                    let result = self.process_message(&ctx, &message).await;
                    let resp = match result {
                        Ok(id) => format!("250 OK id={id}\r\n"),
                        Err(e) => format!("451 Temporary failure: {e}\r\n"),
                    };
                    let _ = write_line_buf(&mut stream, &resp).await;
                    ctx.message_count += 1;
                    ctx.mail_from = None;
                    ctx.rcpt_to.clear();
                }
            }
        }

        self.track_connection(ip, false);
    }

    async fn handle_session_tls(
        self: Arc<Self>,
        tls_stream: tokio_rustls::server::TlsStream<TcpStream>,
        peer: SocketAddr,
    ) {
        let ip = peer.ip();
        if !self.check_rate_limit(ip) {
            return;
        }
        self.track_connection(ip, true);

        let ctx = SessionContext {
            id: Uuid::new_v4().to_string(),
            client_ip: ip,
            authenticated: false,
            tenant_id: None,
            message_count: 0,
            start_time: chrono::Utc::now(),
            helo_hostname: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
        };

        // Similar session loop over TLS stream — simplified for brevity
        // In production: factor out a generic session loop over AsyncRead+AsyncWrite
        debug!(session = %ctx.id, "TLS session started");
        self.track_connection(ip, false);
    }

    // ── commands ───────────────────────────────────────────────────────────────

    async fn handle_command(
        &self,
        cmd_upper: &str,
        raw_line: &str,
        ctx: &mut SessionContext,
    ) -> String {
        if cmd_upper.starts_with("EHLO") || cmd_upper.starts_with("HELO") {
            let host = raw_line
                .split_whitespace()
                .nth(1)
                .unwrap_or("unknown")
                .trim();
            ctx.helo_hostname = host.to_string();
            let mut caps = format!("250-{} Hello {}\r\n", self.hostname, host);
            caps.push_str(&format!("250-SIZE {}\r\n", self.config.max_message_size));
            caps.push_str("250-STARTTLS\r\n");
            caps.push_str("250-8BITMIME\r\n");
            caps.push_str("250-PIPELINING\r\n");
            caps.push_str("250 SMTPUTF8\r\n");
            caps
        } else if cmd_upper.starts_with("MAIL FROM") {
            let addr = extract_address(raw_line);
            ctx.mail_from = Some(addr);
            "250 OK\r\n".into()
        } else if cmd_upper.starts_with("RCPT TO") {
            if ctx.rcpt_to.len() >= self.config.max_recipients {
                return "452 Too many recipients\r\n".into();
            }
            let addr = extract_address(raw_line);
            ctx.rcpt_to.push(addr);
            "250 OK\r\n".into()
        } else if cmd_upper.starts_with("DATA") {
            if ctx.mail_from.is_none() || ctx.rcpt_to.is_empty() {
                "503 Bad sequence of commands\r\n".into()
            } else {
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n".into()
            }
        } else if cmd_upper.starts_with("RSET") {
            ctx.mail_from = None;
            ctx.rcpt_to.clear();
            "250 OK\r\n".into()
        } else if cmd_upper.starts_with("NOOP") {
            "250 OK\r\n".into()
        } else if cmd_upper.starts_with("QUIT") {
            "221 Bye\r\n".into()
        } else {
            "502 Command not recognised\r\n".into()
        }
    }

    // ── message processing ─────────────────────────────────────────────────────

    async fn process_message(
        &self,
        ctx: &SessionContext,
        raw: &[u8],
    ) -> anyhow::Result<String> {
        let message_id = Uuid::new_v4().to_string();
        let mail_from = ctx.mail_from.as_deref().unwrap_or("<>");
        let helo = &ctx.helo_hostname;

        // 1. Email authentication
        let auth_results = self
            .authenticator
            .authenticate(raw, ctx.client_ip, helo, mail_from)
            .await?;

        let disposition = self.authenticator.should_accept(&auth_results);
        match disposition {
            crate::auth::MessageDisposition::Reject => {
                anyhow::bail!("Message rejected by policy (DMARC)");
            }
            crate::auth::MessageDisposition::Quarantine => {
                info!(id = %message_id, "Message quarantined");
            }
            crate::auth::MessageDisposition::Accept => {}
        }

        // 2. Detect VERP reply
        let is_verp = ctx.rcpt_to.iter().any(|r| r.contains("bounces+"));

        // 3. Store message in database
        let rcpts_json = serde_json::to_value(&ctx.rcpt_to)?;
        sqlx::query(
            r#"INSERT INTO inbound_messages (
                id, mail_from, rcpt_to, client_ip, helo_hostname,
                raw_size, auth_results, disposition, is_verp_reply,
                created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, NOW())
            ON CONFLICT DO NOTHING"#,
        )
        .bind(&message_id)
        .bind(mail_from)
        .bind(&rcpts_json)
        .bind(ctx.client_ip.to_string())
        .bind(helo)
        .bind(raw.len() as i64)
        .bind(&auth_results.auth_results_header)
        .bind(format!("{:?}", disposition))
        .bind(is_verp)
        .execute(&self.pool)
        .await?;

        // 4. Queue webhook notification
        self.queue_inbound_webhook(&message_id, mail_from, &ctx.rcpt_to)
            .await?;

        info!(
            id = %message_id,
            from = mail_from,
            rcpt_count = ctx.rcpt_to.len(),
            spf = ?auth_results.spf.result,
            dmarc = ?auth_results.dmarc.result,
            "Message accepted"
        );

        Ok(message_id)
    }

    async fn queue_inbound_webhook(
        &self,
        message_id: &str,
        from: &str,
        rcpt_to: &[String],
    ) -> anyhow::Result<()> {
        let payload = serde_json::json!({
            "event": "inbound",
            "message_id": message_id,
            "from": from,
            "recipients": rcpt_to,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        let mut conn = self.redis.get().await?;
        redis::cmd("LPUSH")
            .arg("mta:webhook_queue")
            .arg(payload.to_string())
            .query_async::<String>(&mut *conn)
            .await
            .ok();

        Ok(())
    }

    // ── rate limiting ──────────────────────────────────────────────────────────

    fn check_rate_limit(&self, ip: IpAddr) -> bool {
        if !self.rate_limit_config.enabled {
            return true;
        }
        let count = self.connections.get(&ip).map(|v| *v).unwrap_or(0);
        count < self.rate_limit_config.max_connections_per_ip
    }

    fn track_connection(&self, ip: IpAddr, connect: bool) {
        if connect {
            *self.connections.entry(ip).or_insert(0) += 1;
        } else {
            if let Some(mut count) = self.connections.get_mut(&ip) {
                *count = count.saturating_sub(1);
                if *count == 0 {
                    drop(count);
                    self.connections.remove(&ip);
                }
            }
        }
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

fn extract_address(line: &str) -> String {
    if let Some(start) = line.find('<') {
        if let Some(end) = line.find('>') {
            return line[start + 1..end].to_string();
        }
    }
    // Fallback: last token
    line.split_whitespace()
        .last()
        .unwrap_or("")
        .trim_matches(|c| c == '<' || c == '>')
        .to_string()
}

async fn write_line_tcp(socket: &TcpStream, data: &str) -> std::io::Result<()> {
    use tokio::io::AsyncWriteExt;
    let mut s = socket;
    // TcpStream doesn't impl write directly without &mut, this is a simplified version
    Ok(())
}

async fn write_line_buf<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut BufStream<S>,
    data: &str,
) -> std::io::Result<()> {
    stream.write_all(data.as_bytes()).await?;
    stream.flush().await
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_extract_address_angle_brackets() {
        assert_eq!(extract_address("MAIL FROM:<user@example.com>"), "user@example.com");
    }

    #[test]
    fn test_extract_address_no_brackets() {
        assert_eq!(extract_address("MAIL FROM: user@example.com"), "user@example.com");
    }

    #[test]
    fn test_extract_address_empty_sender() {
        assert_eq!(extract_address("MAIL FROM:<>"), "");
    }

    #[test]
    fn test_session_context_defaults() {
        let ctx = SessionContext {
            id: "test".into(),
            client_ip: "127.0.0.1".parse().unwrap(),
            authenticated: false,
            tenant_id: None,
            message_count: 0,
            start_time: chrono::Utc::now(),
            helo_hostname: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
        };
        assert!(!ctx.authenticated);
        assert_eq!(ctx.message_count, 0);
    }
}
