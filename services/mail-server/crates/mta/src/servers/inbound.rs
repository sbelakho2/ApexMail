//! Inbound SMTP server – accepts mail on port 25 (STARTTLS) and 465 (implicit TLS).
//!
//! Implements rate limiting, SPF/DKIM/DMARC authentication, VERP reply detection,
//! and message storage.

use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::BytesMut;
use dashmap::DashMap;
use governor::RateLimiter;
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use uuid::Uuid;

use crate::auth::{EmailAuthenticator, SpfStatus};
use crate::config::{InboundConfig, RateLimitConfig};

// Shared resolver to avoid allocating a new DNS client per PTR verification.
static INBOUND_RDNS_RESOLVER: LazyLock<TokioAsyncResolver> =
    LazyLock::new(|| TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()));

// ── types ──────────────────────────────────────────────────────────────────────

/// Per‑session context tracked during an SMTP conversation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionContext {
    pub id: String,
    pub client_ip: IpAddr,
    pub authenticated: bool,
    #[serde(default)]
    pub tls_active: bool,
    pub tenant_id: Option<String>,
    pub message_count: u32,
    pub start_time: chrono::DateTime<chrono::Utc>,
    pub helo_hostname: String,
    pub mail_from: Option<String>,
    pub rcpt_to: Vec<String>,
    /// Whether SPF result was served from cache or freshly evaluated.
    pub spf_status: Option<SpfStatus>,
    /// AUTH LOGIN state machine: None = not in auth login, Some(email) = waiting for password.
    pub auth_login_user: Option<String>,
    /// AUTH PLAIN two-step: true when waiting for the base64 response after sending 334.
    pub auth_plain_pending: bool,
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
    #[expect(
        dead_code,
        reason = "rate limiters are initialized for connection admission wiring in the inbound server"
    )]
    #[allow(clippy::type_complexity)]
    ip_limiters: Arc<
        DashMap<
            IpAddr,
            Arc<
                RateLimiter<
                    governor::state::NotKeyed,
                    governor::state::InMemoryState,
                    governor::clock::DefaultClock,
                >,
            >,
        >,
    >,
    /// Bounded PTR/FCrDNS cache to avoid repeated DNS lookups per source IP.
    rdns_cache: Cache<IpAddr, bool>,
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
            rdns_cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(600))
                .build(),
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
        tls: Option<TlsAcceptor>, // #136:renamed from _tls, now used for STARTTLS
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
            tls_active: false,
            tenant_id: None,
            message_count: 0,
            start_time: chrono::Utc::now(),
            helo_hostname: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
            spf_status: None,
            auth_login_user: None,
            auth_plain_pending: false,
        };

        let allow_starttls = tls.is_some();
        let mut stream = BufStream::new(socket);
        let starttls_requested = self
            .run_session_loop(&mut stream, &mut ctx, allow_starttls)
            .await;

        // #136:Handle STARTTLS upgrade if requested
        if starttls_requested {
            if let Some(acceptor) = tls {
                let inner = stream.into_inner();
                match acceptor.accept(inner).await {
                    Ok(tls_stream) => {
                        ctx.tls_active = true;
                        ctx.helo_hostname.clear();
                        ctx.mail_from = None;
                        ctx.rcpt_to.clear();
                        let mut tls_buf = BufStream::new(tls_stream);
                        self.run_session_loop(&mut tls_buf, &mut ctx, false).await;
                    }
                    Err(e) => {
                        debug!(error = %e, "STARTTLS handshake failed");
                    }
                }
            }
        }

        self.track_connection(ip, false);
    }

    /// Generic session loop over any AsyncRead+AsyncWrite stream (plain or TLS).
    /// Returns true if client requested STARTTLS (caller should upgrade and re-enter).
    async fn run_session_loop<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        self: &Arc<Self>,
        stream: &mut BufStream<S>,
        ctx: &mut SessionContext,
        allow_starttls: bool, // #136:whether STARTTLS upgrade is available
    ) -> bool {
        let greeting = format!("220 {} ESMTP ApexMail MTA\r\n", self.hostname);
        if let Err(e) = write_line_buf(stream, &greeting).await {
            debug!(error = %e, "Failed to send greeting");
            return false;
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

            // #136:Handle STARTTLS before generic command dispatch
            if cmd == "STARTTLS" {
                if starttls_is_available(allow_starttls, ctx) {
                    let _ = write_line_buf(stream, "220 Ready to start TLS\r\n").await;
                    return true; // Signal caller to upgrade
                } else {
                    let _ = write_line_buf(stream, "454 TLS not available\r\n").await;
                    continue;
                }
            } else if cmd.starts_with("STARTTLS") {
                let _ = write_line_buf(stream, "501 Syntax: STARTTLS\r\n").await;
                continue;
            }

            let response = self.handle_command(&cmd, &line, ctx, allow_starttls).await;

            if let Err(e) = write_line_buf(stream, &response).await {
                debug!(error = %e, "Write error");
                break;
            }

            if cmd.starts_with("QUIT") {
                break;
            }

            // DATA handling
            if cmd.starts_with("DATA") && response.starts_with("354") {
                let mut message = BytesMut::new();
                let mut too_large = false;
                // #137:Track total DATA deadline (10 min) to prevent slow-loris attacks
                let data_deadline = tokio::time::Instant::now() + Duration::from_secs(600);
                let mut data_timed_out = false;
                loop {
                    line.clear();
                    let remaining = data_deadline
                        .checked_duration_since(tokio::time::Instant::now())
                        .unwrap_or(Duration::ZERO);
                    if remaining.is_zero() {
                        data_timed_out = true;
                        break;
                    }
                    let per_line_timeout = remaining.min(Duration::from_secs(300));
                    match tokio::time::timeout(per_line_timeout, stream.read_line(&mut line)).await
                    {
                        Err(_) => {
                            data_timed_out = true;
                            break;
                        }
                        Ok(Ok(0)) => break,
                        Ok(Ok(_)) => {
                            if line.trim() == "." {
                                break;
                            }
                            // #141:Check size BEFORE extending to prevent temporary overallocation
                            if !too_large {
                                let data_slice = if line.starts_with("..") {
                                    &line[1..]
                                } else {
                                    &line[..]
                                };
                                if message.len() + data_slice.len() > self.config.max_message_size {
                                    too_large = true;
                                    message.clear();
                                } else {
                                    message.extend_from_slice(data_slice.as_bytes());
                                }
                            }
                        }
                        Ok(Err(_)) => break,
                    }
                }

                if data_timed_out {
                    // #137:Total DATA timeout exceeded
                    let _ = write_line_buf(stream, "421 Data timeout exceeded\r\n").await;
                    break;
                }

                if too_large {
                    let _ = write_line_buf(stream, "552 Message too large\r\n").await;
                    ctx.mail_from = None;
                    ctx.rcpt_to.clear();
                } else if message.len() <= self.config.max_message_size {
                    let result = self.process_message(ctx, &message).await;
                    let resp = match result {
                        Ok(id) => format!("250 OK id={id}\r\n"),
                        Err(e) => format!("451 Temporary failure: {e}\r\n"),
                    };
                    let _ = write_line_buf(stream, &resp).await;
                    ctx.message_count += 1;
                    ctx.mail_from = None;
                    ctx.rcpt_to.clear();
                }
            }
        }
        false
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

        let mut ctx = SessionContext {
            id: Uuid::new_v4().to_string(),
            client_ip: ip,
            authenticated: false,
            tls_active: true,
            tenant_id: None,
            message_count: 0,
            start_time: chrono::Utc::now(),
            helo_hostname: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
            spf_status: None,
            auth_login_user: None,
            auth_plain_pending: false,
        };

        let mut stream = BufStream::new(tls_stream);
        self.run_session_loop(&mut stream, &mut ctx, false).await; // #136:already on TLS
        self.track_connection(ip, false);
    }

    // ── commands ───────────────────────────────────────────────────────────────

    async fn handle_command(
        &self,
        cmd_upper: &str,
        raw_line: &str,
        ctx: &mut SessionContext,
        allow_starttls: bool,
    ) -> String {
        if cmd_upper.starts_with("EHLO") || cmd_upper.starts_with("HELO") {
            let Some(host) = parse_helo_hostname(raw_line) else {
                return "501 Invalid HELO/EHLO hostname\r\n".into();
            };
            ctx.helo_hostname = host.to_string();
            let mut caps = format!("250-{} Hello {}\r\n", self.hostname, host);
            caps.push_str(&format!("250-SIZE {}\r\n", self.config.max_message_size));
            if should_advertise_starttls(self.config.tls.enabled, allow_starttls, ctx) {
                caps.push_str("250-STARTTLS\r\n");
            }
            // Advertise AUTH on TLS connections so email clients (Thunderbird,
            // Apple Mail, etc.) can authenticate for submission over port 465.
            // This is critical: without AUTH in the EHLO response, clients that
            // auto-detect port 465 will hang indefinitely waiting for AUTH.
            if ctx.tls_active {
                caps.push_str("250-AUTH PLAIN LOGIN\r\n");
            }
            caps.push_str("250-8BITMIME\r\n");
            caps.push_str("250-PIPELINING\r\n");
            caps.push_str("250 SMTPUTF8\r\n");
            caps
        } else if cmd_upper.starts_with("STARTTLS") {
            "454 TLS not available\r\n".into()
        } else if cmd_upper.starts_with("AUTH PLAIN") && ctx.tls_active {
            // Handle AUTH PLAIN on TLS connections (port 465 submission).
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            let inline = raw_line.trim().strip_prefix("AUTH PLAIN").unwrap_or("").trim();
            let auth_b64 = if !inline.is_empty() {
                inline.to_string()
            } else {
                // Two-step: send 334 challenge, set pending flag
                ctx.auth_plain_pending = true;
                return "334 \r\n".into();
            };
            return self.do_auth_plain(&auth_b64, ctx).await;
        } else if ctx.auth_plain_pending && ctx.tls_active {
            // AUTH PLAIN two-step: client sent the base64 response after our 334
            ctx.auth_plain_pending = false;
            return self.do_auth_plain(raw_line.trim(), ctx).await;
        } else if cmd_upper.starts_with("AUTH LOGIN") && ctx.tls_active {
            // AUTH LOGIN multi-step: prompt for username (base64 "VXNlcm5hbWU6")
            ctx.auth_login_user = Some(String::new()); // marker: waiting for username
            return "334 VXNlcm5hbWU6\r\n".into();
        } else if ctx.auth_login_user.is_some() && ctx.tls_active {
            // AUTH LOGIN state machine: we're waiting for username or password
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            let decoded = BASE64.decode(raw_line.trim()).unwrap_or_default();
            let value = String::from_utf8_lossy(&decoded).to_string();

            if ctx.auth_login_user.as_deref() == Some("") {
                // Username received, now prompt for password
                ctx.auth_login_user = Some(value);
                return "334 UGFzc3dvcmQ6\r\n".into();
            } else {
                // Password received, attempt authentication
                let user = ctx.auth_login_user.take().unwrap_or_default();
                match self.authenticate_user(&user, &value, ctx.client_ip).await {
                    Ok(_) => {
                        ctx.authenticated = true;
                        "235 2.7.0 Authentication successful\r\n".into()
                    }
                    Err(_) => "535 5.7.8 Authentication failed\r\n".into(),
                }
            }
        } else if cmd_upper.starts_with("AUTH PLAIN") && !ctx.tls_active {
            // AUTH PLAIN before TLS — reject for security
            "538 5.7.11 Encryption required for requested authentication\r\n".into()
        } else if cmd_upper.starts_with("MAIL FROM") {
            if self.config.auth_required && !ctx.authenticated {
                return "530 Authentication required\r\n".into();
            }
            if !self.verify_inbound_source(ctx.client_ip).await {
                warn!(client_ip = %ctx.client_ip, "Rejected inbound sender without forward-confirmed PTR record");
                return "550 Reverse DNS lookup required\r\n".into();
            }
            let addr = extract_address(raw_line);
            ctx.mail_from = Some(addr);
            "250 OK\r\n".into()
        } else if cmd_upper.starts_with("RCPT TO") {
            if self.config.auth_required && !ctx.authenticated {
                return "530 Authentication required\r\n".into();
            }
            if ctx.rcpt_to.len() >= self.config.max_recipients {
                return "452 Too many recipients\r\n".into();
            }
            let addr = extract_address(raw_line);
            if recipient_domain(&addr).is_none() {
                return "550 Invalid recipient\r\n".into();
            }
            match self.is_managed_recipient(&addr).await {
                Ok(true) => {}
                Ok(false) => return "550 No such user here\r\n".into(),
                Err(error) => {
                    warn!(recipient = %addr, %error, "Failed to validate inbound recipient domain");
                    return "451 Temporary local problem\r\n".into();
                }
            }
            ctx.rcpt_to.push(addr);
            "250 OK\r\n".into()
        } else if cmd_upper.starts_with("DATA") {
            if self.config.auth_required && !ctx.authenticated {
                return "530 Authentication required\r\n".into();
            }
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

    async fn process_message(&self, ctx: &SessionContext, raw: &[u8]) -> anyhow::Result<String> {
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
        // #139:LPUSH returns list length (i64), not String
        if let Err(e) = redis::cmd("LPUSH")
            .arg("mta:webhook_queue")
            .arg(payload.to_string())
            .query_async::<i64>(&mut *conn)
            .await
        {
            tracing::error!(message_id = %message_id, error = %e, "Failed to push inbound webhook to Redis queue");
        }

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
            // #140:Atomic decrement then conditional removal – avoids race
            // between count reaching zero and another thread incrementing
            self.connections
                .entry(ip)
                .and_modify(|c| *c = c.saturating_sub(1));
            self.connections.remove_if(&ip, |_, c| *c == 0);
        }
    }

    async fn is_managed_recipient(&self, recipient: &str) -> anyhow::Result<bool> {
        let Some(domain) = recipient_domain(recipient) else {
            return Ok(false);
        };

        let exists = sqlx::query_scalar::<_, bool>(
            "SELECT EXISTS(SELECT 1 FROM domains WHERE LOWER(name) = LOWER($1) AND status = 'verified')",
        )
        .bind(domain)
        .fetch_one(&self.pool)
        .await?;

        Ok(exists)
    }

    async fn verify_inbound_source(&self, ip: IpAddr) -> bool {
        if ptr_verification_exempt(ip) {
            return true;
        }

        if let Some(cached) = self.rdns_cache.get(&ip) {
            return cached;
        }

        let resolver = &*INBOUND_RDNS_RESOLVER;
        let result = match resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                let hostnames: Vec<String> = lookup
                    .iter()
                    .map(|name| name.to_string().trim_end_matches('.').to_ascii_lowercase())
                    .filter(|hostname| !hostname.is_empty())
                    .collect();

                if hostnames.is_empty() {
                    debug!(ip = %ip, "Inbound PTR lookup returned no hostnames");
                    false
                } else {
                    let mut confirmed = false;
                    for hostname in hostnames {
                        match resolver.lookup_ip(hostname.as_str()).await {
                            Ok(forward) => {
                                if forward.iter().any(|addr| addr == ip) {
                                    confirmed = true;
                                    break;
                                }
                                debug!(ip = %ip, hostname = %hostname, "Inbound FCrDNS failed: forward lookup doesn't match IP");
                            }
                            Err(error) => {
                                debug!(ip = %ip, hostname = %hostname, error = %error, "Inbound FCrDNS forward lookup failed");
                            }
                        }
                    }
                    confirmed
                }
            }
            Err(error) => {
                debug!(ip = %ip, error = %error, "Inbound PTR lookup failed");
                false
            }
        };

        self.rdns_cache.insert(ip, result);
        result
    }

    /// Process AUTH PLAIN base64 credentials.
    async fn do_auth_plain(&self, auth_b64: &str, ctx: &mut SessionContext) -> String {
        use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
        match BASE64.decode(auth_b64.trim()) {
            Ok(creds) => {
                let s = String::from_utf8_lossy(&creds);
                let parts: Vec<&str> = s.splitn(3, '\0').collect();
                if parts.len() >= 3 {
                    match self.authenticate_user(parts[1], parts[2], ctx.client_ip).await {
                        Ok(_) => {
                            ctx.authenticated = true;
                            "235 2.7.0 Authentication successful\r\n".into()
                        }
                        Err(_) => "535 5.7.8 Authentication failed\r\n".into(),
                    }
                } else {
                    "535 5.7.8 Authentication failed\r\n".into()
                }
            }
            Err(_) => "501 Invalid base64\r\n".into(),
        }
    }

    /// Authenticate a user against the users table (same logic as submission server).
    async fn authenticate_user(
        &self,
        email: &str,
        password: &str,
        _ip: IpAddr,
    ) -> Result<String, ()> {
        let user = sqlx::query_as::<_, (String, String, String)>(
            "SELECT email, password_hash, status FROM users WHERE LOWER(email) = LOWER($1)",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ())?;

        let (user_email, password_hash, status) = match user {
            Some(u) => u,
            None => return Err(()),
        };

        if status != "active" {
            return Err(());
        }

        match apexmail_lib::crypto::verify_password(password, &password_hash) {
            Ok(true) => Ok(user_email),
            _ => Err(()),
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
    // Fallback:last token
    line.split_whitespace()
        .last()
        .unwrap_or("")
        .trim_matches(|c| c == '<' || c == '>')
        .to_string()
}

fn recipient_domain(recipient: &str) -> Option<&str> {
    let (_, domain) = recipient.rsplit_once('@')?;
    let domain = domain.trim();
    if domain.is_empty() {
        None
    } else {
        Some(domain)
    }
}

fn parse_helo_hostname(raw_line: &str) -> Option<&str> {
    let mut parts = raw_line.split_whitespace();
    let _command = parts.next()?;
    let host = parts.next()?.trim();
    if parts.next().is_some() {
        return None;
    }
    if is_valid_helo_hostname(host) {
        Some(host)
    } else {
        None
    }
}

fn is_valid_helo_hostname(host: &str) -> bool {
    if host.is_empty() || host.len() > 255 || !host.is_ascii() {
        return false;
    }

    if let Some(literal) = host
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
    {
        return literal
            .strip_prefix("IPv6:")
            .unwrap_or(literal)
            .parse::<IpAddr>()
            .is_ok();
    }

    host.split('.').all(is_valid_helo_label)
}

fn is_valid_helo_label(label: &str) -> bool {
    !label.is_empty()
        && label.len() <= 63
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-')
}

fn ptr_verification_exempt(ip: IpAddr) -> bool {
    match ip {
        IpAddr::V4(v4) => {
            v4.is_private()
                || v4.is_loopback()
                || v4.is_link_local()
                || v4.is_multicast()
                || v4.is_unspecified()
                || v4 == Ipv4Addr::BROADCAST
        }
        IpAddr::V6(v6) => {
            v6.is_loopback()
                || v6.is_unspecified()
                || v6.is_multicast()
                || v6.is_unique_local()
                || v6.is_unicast_link_local()
        }
    }
}

fn starttls_is_available(allow_starttls: bool, ctx: &SessionContext) -> bool {
    allow_starttls && !ctx.tls_active
}

fn should_advertise_starttls(
    tls_enabled: bool,
    allow_starttls: bool,
    ctx: &SessionContext,
) -> bool {
    tls_enabled && starttls_is_available(allow_starttls, ctx)
}

/// #138:Write all bytes to a raw TcpStream, handling partial writes.
async fn write_line_tcp(socket: &TcpStream, data: &str) -> std::io::Result<()> {
    let bytes = data.as_bytes();
    let mut written = 0;
    while written < bytes.len() {
        socket.writable().await?;
        match socket.try_write(&bytes[written..]) {
            Ok(n) => written += n,
            Err(ref e) if e.kind() == std::io::ErrorKind::WouldBlock => continue,
            Err(e) => return Err(e),
        }
    }
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
        assert_eq!(
            extract_address("MAIL FROM:<user@example.com>"),
            "user@example.com"
        );
    }

    #[test]
    fn test_extract_address_no_brackets() {
        assert_eq!(
            extract_address("MAIL FROM: user@example.com"),
            "user@example.com"
        );
    }

    #[test]
    fn test_extract_address_empty_sender() {
        assert_eq!(extract_address("MAIL FROM:<>"), "");
    }

    #[test]
    fn test_recipient_domain_extracts_domain() {
        assert_eq!(recipient_domain("user@example.com"), Some("example.com"));
    }

    #[test]
    fn test_recipient_domain_rejects_missing_domain() {
        assert_eq!(recipient_domain("invalid-recipient"), None);
        assert_eq!(recipient_domain("user@"), None);
    }

    #[test]
    fn test_parse_helo_hostname_accepts_domain_and_address_literals() {
        assert_eq!(
            parse_helo_hostname("EHLO mail.example.com\r\n"),
            Some("mail.example.com")
        );
        assert_eq!(
            parse_helo_hostname("HELO [127.0.0.1]\r\n"),
            Some("[127.0.0.1]")
        );
        assert_eq!(
            parse_helo_hostname("EHLO [IPv6:2001:db8::1]\r\n"),
            Some("[IPv6:2001:db8::1]")
        );
    }

    #[test]
    fn test_parse_helo_hostname_rejects_invalid_hosts() {
        assert_eq!(parse_helo_hostname("EHLO bad host\r\n"), None);
        assert_eq!(parse_helo_hostname("EHLO -bad.example\r\n"), None);
        assert_eq!(parse_helo_hostname("EHLO mail_.example.com\r\n"), None);
        assert_eq!(parse_helo_hostname("EHLO \r\n"), None);
    }

    #[test]
    fn test_session_context_defaults() {
        let ctx = SessionContext {
            id: "test".into(),
            client_ip: std::net::IpAddr::from([127, 0, 0, 1]),
            authenticated: false,
            tls_active: false,
            tenant_id: None,
            message_count: 0,
            start_time: chrono::Utc::now(),
            helo_hostname: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
            spf_status: None,
            auth_login_user: None,
            auth_plain_pending: false,
        };
        assert!(!ctx.authenticated);
        assert_eq!(ctx.message_count, 0);
    }

    #[test]
    fn test_starttls_available_only_before_tls_activation() {
        let mut ctx = SessionContext {
            id: "test".into(),
            client_ip: std::net::IpAddr::from([127, 0, 0, 1]),
            authenticated: false,
            tls_active: false,
            tenant_id: None,
            message_count: 0,
            start_time: chrono::Utc::now(),
            helo_hostname: String::new(),
            mail_from: None,
            rcpt_to: Vec::new(),
            spf_status: None,
            auth_login_user: None,
            auth_plain_pending: false,
        };

        assert!(starttls_is_available(true, &ctx));
        assert!(should_advertise_starttls(true, true, &ctx));
        assert!(!should_advertise_starttls(false, true, &ctx));
        assert!(!should_advertise_starttls(true, false, &ctx));

        ctx.tls_active = true;
        assert!(!starttls_is_available(true, &ctx));
        assert!(!should_advertise_starttls(true, true, &ctx));
    }

    #[test]
    fn test_ptr_verification_exempt_for_local_and_private_ips() {
        assert!(ptr_verification_exempt(IpAddr::V4(Ipv4Addr::LOCALHOST)));
        assert!(ptr_verification_exempt(IpAddr::V4(Ipv4Addr::new(
            10, 0, 0, 1
        ))));
        assert!(ptr_verification_exempt(IpAddr::V6(
            std::net::Ipv6Addr::LOCALHOST
        )));
    }

    #[test]
    fn test_ptr_verification_required_for_public_ips() {
        assert!(!ptr_verification_exempt(IpAddr::V4(Ipv4Addr::new(
            8, 8, 8, 8
        ))));
        assert!(!ptr_verification_exempt(IpAddr::V6(
            "2606:4700:4700::1111".parse().unwrap()
        )));
    }
}
