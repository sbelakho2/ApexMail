//! Inbound SMTP server – accepts mail on port 25 (STARTTLS) and 465 (implicit TLS).
//!
//! Implements rate limiting, SPF/DKIM/DMARC authentication, VERP reply detection,
//! and message storage.

use std::future::Future;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::BytesMut;
use dashmap::DashMap;
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::io::{AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::TlsAcceptor;
use tracing::{debug, info, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use uuid::Uuid;

use crate::auth::{
    verify_against_dummy, AuthError, AuthFailTracker, EmailAuthenticator, SpfStatus,
};
use crate::config::{InboundConfig, RateLimitConfig};
use mail_proto::mailstore_service_client::MailstoreServiceClient;
use mail_proto::{
    GetAccountRequest, InternalServiceAuthInterceptor, MessageFlags, StoreMessageRequest,
};
use tonic::transport::Channel;

use super::util::{read_line_capped, LineRead, MAX_COMMAND_LINE, MAX_DATA_LINE};

// Shared resolver to avoid allocating a new DNS client per PTR verification.
static INBOUND_RDNS_RESOLVER: LazyLock<TokioAsyncResolver> =
    LazyLock::new(|| TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()));

/// M26: maximum time a TLS handshake may take before the connection is
/// dropped and the per-IP connection slot released.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// M28: bounded deadlines for mailstore gRPC calls — a hung mailstore must
/// never stall the SMTP session task indefinitely.
const MAILSTORE_CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);
const MAILSTORE_RPC_TIMEOUT: Duration = Duration::from_secs(10);

type MailstoreClient = MailstoreServiceClient<
    tonic::service::interceptor::InterceptedService<Channel, InternalServiceAuthInterceptor>,
>;

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
    /// Per‑IP connection counter (admission control).
    connections: Arc<DashMap<IpAddr, u32>>,
    /// Bounded PTR/FCrDNS cache to avoid repeated DNS lookups per source IP.
    rdns_cache: Cache<IpAddr, bool>,
    /// Failed-AUTH lockout tracking (per-IP + per-account), shared with
    /// the submission server.
    auth_fail_tracker: AuthFailTracker,
    shutdown: Arc<Notify>,
    /// gRPC client for mailbox delivery to the mailstore service.
    mailstore: MailstoreClient,
}

impl InboundServer {
    pub fn new(
        config: InboundConfig,
        rate_limit_config: RateLimitConfig,
        pool: PgPool,
        redis: deadpool_redis::Pool,
        authenticator: Arc<EmailAuthenticator>,
        hostname: String,
        mailstore_addr: String,
    ) -> anyhow::Result<Self> {
        let channel = Channel::from_shared(mailstore_addr)
            .map_err(|error| anyhow::anyhow!("invalid MAILSTORE_GRPC_ADDR: {error}"))?
            .timeout(MAILSTORE_CHANNEL_TIMEOUT)
            .connect_lazy();
        let interceptor = InternalServiceAuthInterceptor::from_env()
            .map_err(|error| anyhow::anyhow!("invalid internal mailstore authentication: {error}"))?;

        Ok(Self {
            config,
            rate_limit_config,
            pool,
            redis,
            authenticator,
            hostname,
            connections: Arc::new(DashMap::new()),
            rdns_cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(600))
                .build(),
            auth_fail_tracker: AuthFailTracker::new(),
            shutdown: Arc::new(Notify::new()),
            mailstore: MailstoreServiceClient::with_interceptor(channel, interceptor),
        })
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
                                        match tls_handshake_with_timeout(
                                            a.accept(socket),
                                            TLS_HANDSHAKE_TIMEOUT,
                                        )
                                        .await
                                        {
                                            Ok(tls_stream) => {
                                                srv.handle_session_tls(tls_stream, peer).await;
                                            }
                                            Err(()) => {
                                                debug!("TLS handshake failed or timed out");
                                            }
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
                match tls_handshake_with_timeout(acceptor.accept(inner), TLS_HANDSHAKE_TIMEOUT)
                    .await
                {
                    Ok(tls_stream) => {
                        ctx.tls_active = true;
                        ctx.helo_hostname.clear();
                        ctx.mail_from = None;
                        ctx.rcpt_to.clear();
                        let mut tls_buf = BufStream::new(tls_stream);
                        self.run_session_loop(&mut tls_buf, &mut ctx, false).await;
                    }
                    Err(()) => {
                        // M26: on timeout/failure the socket is dropped and the
                        // per-IP connection slot released below.
                        debug!("STARTTLS handshake failed or timed out");
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
            match tokio::time::timeout(
                Duration::from_secs(300),
                read_line_capped(stream, MAX_COMMAND_LINE),
            )
            .await
            {
                Ok(Ok(LineRead::Eof)) | Err(_) => break,
                Ok(Ok(LineRead::TooLong)) => {
                    let _ = write_line_buf(stream, "500 5.5.2 Line too long\r\n").await;
                    continue;
                }
                Ok(Ok(LineRead::Line(l))) => line = l,
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
                // A message is only complete when the client sent <CRLF>.<CRLF>.
                // Anything else (EOF, read error mid-DATA) is a truncated
                // message that must be discarded, never processed.
                let mut terminated = false;
                let mut aborted = false;
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
                    match tokio::time::timeout(
                        per_line_timeout,
                        read_line_capped(stream, MAX_DATA_LINE),
                    )
                    .await
                    {
                        Err(_) => {
                            data_timed_out = true;
                            break;
                        }
                        Ok(Ok(LineRead::Eof)) | Ok(Err(_)) => {
                            // Client disconnected / stream failed mid-DATA.
                            aborted = true;
                            break;
                        }
                        Ok(Ok(LineRead::TooLong)) => {
                            // A single line over the per-line cap cannot be
                            // part of a message we are willing to store.
                            too_large = true;
                            message.clear();
                        }
                        Ok(Ok(LineRead::Line(l))) => {
                            line = l;
                            if line.trim() == "." {
                                terminated = true;
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
                    }
                }

                if data_timed_out {
                    // #137:Total DATA timeout exceeded
                    let _ = write_line_buf(stream, "421 Data timeout exceeded\r\n").await;
                    break;
                }

                if aborted {
                    // Truncated message: discard the whole transaction and
                    // tell the client to retry rather than accepting (and
                    // relaying) a partial message.
                    let _ = write_line_buf(stream, "451 4.3.0 Temporary failure\r\n").await;
                    ctx.mail_from = None;
                    ctx.rcpt_to.clear();
                    continue;
                }

                if too_large {
                    let _ = write_line_buf(stream, "552 Message too large\r\n").await;
                    ctx.mail_from = None;
                    ctx.rcpt_to.clear();
                } else if terminated {
                    let result = self.process_message(ctx, &message).await;
                    let resp = format_data_response(&result);
                    let _ = write_line_buf(stream, &resp).await;
                    ctx.message_count += 1;
                    ctx.mail_from = None;
                    ctx.rcpt_to.clear();
                    // Enforce the per-connection message budget: once the
                    // client reached max_messages_per_connection, close the
                    // session instead of accepting unbounded mail.
                    if ctx.message_count >= self.rate_limit_config.max_messages_per_connection {
                        let _ = write_line_buf(
                            stream,
                            "421 4.7.0 Too many messages, closing connection\r\n",
                        )
                        .await;
                        break;
                    }
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
            let inline = raw_line
                .trim()
                .strip_prefix("AUTH PLAIN")
                .unwrap_or("")
                .trim();
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
                    Err(AuthError::LockedOut) => {
                        "454 4.7.0 Too many failed authentication attempts\r\n".into()
                    }
                    Err(AuthError::Failed) => "535 5.7.8 Authentication failed\r\n".into(),
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
            // RFC 5321 §4.1.4: a MAIL FROM implicitly resets any prior
            // transaction's recipients — a new reverse-path starts a new
            // transaction.
            ctx.rcpt_to.clear();
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
        // inbound_messages.id is VARCHAR(26): "inb_" + 22 hex chars fits
        // exactly (a 36-char UUID string would overflow the column).
        let message_id = format!("inb_{}", &Uuid::new_v4().simple().to_string()[..22]);
        let mail_from = ctx.mail_from.as_deref().unwrap_or("<>");
        let helo = &ctx.helo_hostname;

        // 1. Email authentication (SPF/DKIM/DMARC policy gate)
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

        // 2. Detect VERP reply. Exact local-part prefix match: a substring
        //    match would also flag innocent addresses that merely contain
        //    "bounces+" anywhere (e.g. "user+bounces+tag@dom").
        let is_verp = ctx.rcpt_to.iter().any(|r| r.starts_with("bounces+"));

        // 3. Resolve the tenant that owns the first recipient's domain
        //    (nullable: rows with an unknown/local-only recipient stay untagged).
        let tenant_id: Option<String> = match ctx.rcpt_to.iter().find_map(|r| recipient_domain(r)) {
            Some(domain) => sqlx::query_scalar(
                "SELECT tenant_id FROM domains WHERE LOWER(name) = LOWER($1) LIMIT 1",
            )
            .bind(domain)
            .fetch_optional(&self.pool)
            .await
            .ok()
            .flatten(),
            None => None,
        };

        // 4. Persist the message using ONLY the columns migration 088
        //    guarantees on inbound_messages (tenant_id, mail_from, rcpt_to,
        //    client_ip, helo_hostname, raw_message, raw_size, auth_results,
        //    spf_result, disposition, is_verp_reply). The previously written
        //    from_email/to_email/subject/body_text/body_html/headers/
        //    created_at family exists in NO deployed migration — that INSERT
        //    failed with "column does not exist" and 451-rejected every
        //    inbound message. The full raw MIME is preserved in raw_message
        //    for downstream consumers.
        let sender = if mail_from == "<>" { "" } else { mail_from };

        // 5. Store the message (full raw MIME preserved in raw_message)
        sqlx::query(
            r#"INSERT INTO inbound_messages (
                id, tenant_id, mail_from, rcpt_to, client_ip, helo_hostname,
                raw_message, raw_size, auth_results, spf_result, disposition,
                is_verp_reply
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
            ON CONFLICT (id) DO NOTHING"#,
        )
        .bind(&message_id)
        .bind(tenant_id)
        .bind(sender)
        .bind(&ctx.rcpt_to)
        .bind(ctx.client_ip.to_string())
        .bind(helo)
        .bind(raw)
        .bind(raw.len() as i64)
        .bind(&auth_results.auth_results_header)
        .bind(format!("{:?}", auth_results.spf.result).to_lowercase())
        .bind(format!("{:?}", disposition).to_lowercase())
        .bind(is_verp)
        .execute(&self.pool)
        .await?;

        // 6. Queue webhook notification
        self.queue_inbound_webhook(&message_id, mail_from, &ctx.rcpt_to)
            .await?;

        // 7. Deliver to the mailstore mailbox (best-effort). inbound_messages
        //    is the durable record; a mailstore outage must not fail the SMTP
        //    transaction, and unknown recipients are simply skipped.
        if !ctx.rcpt_to.is_empty() {
            self.deliver_to_mailstore(ctx, raw, &auth_results.auth_results_header)
                .await;
        }

        info!(
            id = %message_id,
            from = mail_from,
            rcpt_count = ctx.rcpt_to.len(),
            spf = ?auth_results.spf.result,
            dmarc = ?auth_results.dmarc.result,
            is_verp = is_verp,
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

        // Best-effort: the message is already persisted; a webhook notification
        // failure must never reject the mail or fail the session.
        let push_result: Result<(), ()> = async {
            let mut conn = self.redis.get().await.map_err(|e| {
                tracing::error!(message_id = %message_id, error = %e, "Failed to get Redis connection for inbound webhook");
            })?;
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
        .await;
        let _ = push_result;

        Ok(())
    }

    /// Deliver an accepted message into the recipient's mailstore mailbox.
    ///
    /// The raw RFC5322 message (with the Authentication-Results header) is
    /// stored into the recipient's Inbox via the mailstore gRPC service so the
    /// message is visible over IMAP. Best-effort: failures are logged, never
    /// propagated to the SMTP session.
    async fn deliver_to_mailstore(
        &self,
        ctx: &SessionContext,
        raw: &[u8],
        auth_results_header: &str,
    ) {
        let mut client = self.mailstore.clone();
        let mut final_message = Vec::with_capacity(auth_results_header.len() + raw.len() + 2);
        // The Authentication-Results header has no trailing CRLF of its own;
        // without one it would fuse with the message's first header line and
        // corrupt the stored MIME (e.g. "…dmarc=passFrom: a@b.com").
        final_message.extend_from_slice(auth_results_header.as_bytes());
        final_message.extend_from_slice(b"\r\n");
        final_message.extend_from_slice(raw);

        for recipient in &ctx.rcpt_to {
            let lookup = GetAccountRequest {
                account_id: String::new(),
                email: recipient.clone(),
            };
            // M28: bounded RPC — a hung mailstore must not stall the session.
            let account_id = match rpc_with_deadline(client.get_account(lookup), MAILSTORE_RPC_TIMEOUT)
                .await
            {
                Some(Ok(resp)) => {
                    let r = resp.into_inner();
                    if r.account_id.is_empty() {
                        continue;
                    }
                    r.account_id
                }
                Some(Err(e)) => {
                    debug!(
                        recipient = %mail_common::pii::redact_email(recipient),
                        error = %e,
                        "No mailstore account for recipient; skipping mailbox delivery"
                    );
                    continue;
                }
                None => {
                    debug!(
                        recipient = %mail_common::pii::redact_email(recipient),
                        "Mailstore account lookup timed out; skipping mailbox delivery"
                    );
                    continue;
                }
            };

            let req = StoreMessageRequest {
                account_id,
                mailbox: "Inbox".to_string(),
                raw_message: final_message.clone().into(),
                flags: Some(MessageFlags {
                    recent: true,
                    ..Default::default()
                }),
                internal_date: chrono::Utc::now().timestamp(),
            };
            match rpc_with_deadline(client.store_message(req), MAILSTORE_RPC_TIMEOUT).await {
                Some(Ok(resp)) => {
                    info!(
                        recipient = %mail_common::pii::redact_email(recipient),
                        uid = resp.into_inner().uid,
                        "Message delivered to mailstore mailbox"
                    );
                }
                Some(Err(e)) => {
                    warn!(
                        recipient = %mail_common::pii::redact_email(recipient),
                        error = %e,
                        "Failed to deliver message to mailstore mailbox"
                    );
                }
                None => {
                    warn!(
                        recipient = %mail_common::pii::redact_email(recipient),
                        "Mailstore store_message timed out; mailbox delivery skipped"
                    );
                }
            }
        }
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
                    match self
                        .authenticate_user(parts[1], parts[2], ctx.client_ip)
                        .await
                    {
                        Ok(_) => {
                            ctx.authenticated = true;
                            "235 2.7.0 Authentication successful\r\n".into()
                        }
                        Err(AuthError::LockedOut) => {
                            "454 4.7.0 Too many failed authentication attempts\r\n".into()
                        }
                        Err(AuthError::Failed) => "535 5.7.8 Authentication failed\r\n".into(),
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
        ip: IpAddr,
    ) -> Result<String, AuthError> {
        // FIX-4: lockout short-circuit BEFORE any work, identical to the
        // submission server (shared tracker). Per-IP + per-account keys;
        // counters decay after the tracker's TTL (the lockout window).
        if self.auth_fail_tracker.is_locked(ip, email) {
            return Err(AuthError::LockedOut);
        }

        let user = sqlx::query_as::<_, (String, String, String)>(
            "SELECT email, password_hash, status FROM users WHERE LOWER(email) = LOWER($1)",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::Failed)?;

        let (user_email, password_hash, status) = match user {
            Some(u) => u,
            None => {
                // FIX-4: unknown-account attempts count toward the
                // lockout (no brute-force bypass via nonexistent users).
                self.auth_fail_tracker.record_failure(ip, email);
                // FIX-5: spend the same verification time as a real
                // account so the response cannot reveal whether the
                // account exists (user-enumeration side channel).
                let _ = verify_against_dummy(password);
                return Err(AuthError::Failed);
            }
        };

        if status != "active" {
            self.auth_fail_tracker.record_failure(ip, email);
            let _ = verify_against_dummy(password);
            return Err(AuthError::Failed);
        }

        // Same scheme handling as the submission server: accept Argon2id and
        // legacy bcrypt hashes, and migrate bcrypt rows to Argon2id on success.
        match apexmail_lib::crypto::verify_password_for_login(password, &password_hash) {
            Ok(verification) if verification.valid => {
                self.auth_fail_tracker.reset(ip, email);
                if let Some(new_hash) = verification.migrated_hash {
                    let _ = sqlx::query(
                        "UPDATE users SET password_hash = $1 WHERE LOWER(email) = LOWER($2)",
                    )
                    .bind(new_hash)
                    .bind(&user_email)
                    .execute(&self.pool)
                    .await;
                }
                Ok(user_email)
            }
            _ => {
                self.auth_fail_tracker.record_failure(ip, email);
                Err(AuthError::Failed)
            }
        }
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

fn extract_address(line: &str) -> String {
    // Shared panic-safe helper: the closing '>' is always searched after
    // the opening '<' — a '>' earlier in the line used to slice out of
    // bounds and kill the session task (remote panic).
    if let Some(addr) = super::util::extract_addr_safe(line) {
        return addr.to_string();
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

/// M23: format the SMTP response for a DATA result. The client only ever sees
/// a generic temporary-failure message; internal error details are logged
/// server-side and never echoed to the remote peer.
fn format_data_response(result: &anyhow::Result<String>) -> String {
    match result {
        Ok(id) => format!("250 OK id={id}\r\n"),
        Err(e) => {
            warn!(error = %e, "Message processing failed; sending generic 451");
            "451 4.3.0 Temporary failure\r\n".into()
        }
    }
}

/// M26: run a TLS handshake under a bounded timeout. On timeout or error the
/// connection is dead; callers must drop the socket and release the
/// per-IP connection slot.
pub(crate) async fn tls_handshake_with_timeout<F>(
    handshake: F,
    timeout_dur: Duration,
) -> Result<tokio_rustls::server::TlsStream<TcpStream>, ()>
where
    F: Future<Output = std::io::Result<tokio_rustls::server::TlsStream<TcpStream>>>,
{
    match tokio::time::timeout(timeout_dur, handshake).await {
        Ok(Ok(stream)) => Ok(stream),
        Ok(Err(e)) => {
            debug!(error = %e, "TLS handshake failed");
            Err(())
        }
        Err(_) => {
            warn!("TLS handshake timed out; closing connection");
            Err(())
        }
    }
}

/// M28: run a mailstore RPC under a bounded deadline. Returns None on timeout
/// so the caller can degrade gracefully (best-effort delivery semantics).
async fn rpc_with_deadline<T>(fut: impl Future<Output = T>, dur: Duration) -> Option<T> {
    match tokio::time::timeout(dur, fut).await {
        Ok(value) => Some(value),
        Err(_) => {
            warn!(timeout = %dur.as_secs(), "mailstore RPC timed out");
            None
        }
    }
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

    // ── FIX-4/FIX-5: lockout + timing parity on the 465 AUTH path ───────────

    use base64::Engine as _;

    async fn test_inbound(ip: IpAddr) -> (InboundServer, SessionContext) {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .expect("lazy pool construction cannot fail with a well-formed URL");
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool construction");
        let config = InboundConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 25,
            secure_port: 465,
            hostname: "mail.test".into(),
            max_message_size: 10 * 1024 * 1024,
            max_recipients: 100,
            auth_required: false,
            tls: Default::default(),
        };
        let rate_limit = RateLimitConfig {
            enabled: true,
            max_connections_per_ip: 10,
            max_messages_per_connection: 100,
            max_recipients_per_message: 100,
        };
        let authenticator = Arc::new(
            crate::auth::EmailAuthenticator::new(
                crate::config::EmailAuthConfig {
                    require_spf: false,
                    require_dkim: false,
                    enforce_dmarc: false,
                    allow_soft_fail: true,
                    trusted_relays: Vec::new(),
                    spf_cache_max_entries: 10_000,
                },
                "mail.test".into(),
            )
            .await
            .expect("authenticator construction"),
        );
        let ctx = SessionContext {
            id: "test".into(),
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
        let server = InboundServer::new(
            config,
            rate_limit,
            pool,
            redis,
            authenticator,
            "mail.test".into(),
            "http://127.0.0.1:1".into(),
        )
        .expect("test mailstore configuration must be valid");
        (server, ctx)
    }

    #[tokio::test]
    async fn test_inbound_auth_plain_locked_returns_454() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ctx.client_ip, "alice@example.com");
        }
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(b"\0alice@example.com\0correct-password");
        let resp = server
            .handle_command("AUTH PLAIN", &format!("AUTH PLAIN {b64}"), &mut ctx, false)
            .await;
        assert!(
            resp.contains("454"),
            "locked account must get 454, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn test_inbound_auth_plain_two_step_locked_returns_454() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ctx.client_ip, "alice@example.com");
        }
        let first = server
            .handle_command("AUTH PLAIN", "AUTH PLAIN", &mut ctx, false)
            .await;
        assert!(first.contains("334"), "two-step challenge: {first:?}");
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(b"\0alice@example.com\0correct-password");
        let resp = server.handle_command("", &b64, &mut ctx, false).await;
        assert!(
            resp.contains("454"),
            "locked account must get 454, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn test_inbound_auth_login_locked_returns_454() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ctx.client_ip, "alice@example.com");
        }
        let step1 = server
            .handle_command("AUTH LOGIN", "AUTH LOGIN", &mut ctx, false)
            .await;
        assert!(step1.contains("334"), "username challenge: {step1:?}");
        let step2 = server
            .handle_command("", "YWxpY2VAZXhhbXBsZS5jb20=", &mut ctx, false)
            .await;
        assert!(step2.contains("334"), "password challenge: {step2:?}");
        let step3 = server
            .handle_command("", "Y29ycmVjdC1wYXNzd29yZA==", &mut ctx, false)
            .await;
        assert!(
            step3.contains("454"),
            "locked account must get 454, got {step3:?}"
        );
    }

    #[tokio::test]
    async fn test_inbound_lockout_is_per_account() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ctx.client_ip, "bob@example.com");
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"\0alice@example.com\0secret");
        let resp = server
            .handle_command("AUTH PLAIN", &format!("AUTH PLAIN {b64}"), &mut ctx, false)
            .await;
        assert!(
            !resp.contains("454"),
            "account A must not be locked by account B failures, got {resp:?}"
        );
        assert!(resp.contains("535"), "expected auth failure, got {resp:?}");
    }

    #[tokio::test]
    async fn test_inbound_lockout_is_per_ip() {
        let locked_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let other_ip = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        let (server, mut ctx) = test_inbound(other_ip).await;
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(locked_ip, "alice@example.com");
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"\0alice@example.com\0secret");
        let resp = server
            .handle_command("AUTH PLAIN", &format!("AUTH PLAIN {b64}"), &mut ctx, false)
            .await;
        assert!(
            !resp.contains("454"),
            "IP Y must not be locked by failures from IP X, got {resp:?}"
        );
        assert!(resp.contains("535"), "expected auth failure, got {resp:?}");
    }

    #[tokio::test]
    async fn test_inbound_unknown_email_counts_toward_lockout() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ctx.client_ip, "ghost@example.com");
        }
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(b"\0ghost@example.com\0anything");
        let resp = server
            .handle_command("AUTH PLAIN", &format!("AUTH PLAIN {b64}"), &mut ctx, false)
            .await;
        assert!(
            resp.contains("454"),
            "unknown-account attempts must count toward lockout, got {resp:?}"
        );
    }

    #[tokio::test]
    async fn test_inbound_authenticate_user_returns_locked_out() {
        let (server, ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ctx.client_ip, "alice@example.com");
        }
        let result = server
            .authenticate_user("alice@example.com", "correct-password", ctx.client_ip)
            .await;
        assert_eq!(result, Err(crate::auth::AuthError::LockedOut));
    }

    #[tokio::test]
    async fn test_inbound_authenticate_user_not_locked_is_failed_not_locked_out() {
        let (server, ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        // No prior failures: the attempt reaches the (unreachable) DB and
        // must surface as a plain failure, never as a lockout.
        let result = server
            .authenticate_user("alice@example.com", "secret", ctx.client_ip)
            .await;
        assert_eq!(result, Err(crate::auth::AuthError::Failed));
    }

    // ── FIX-F (M23): never echo internal error details to the client ──────

    #[test]
    fn test_format_data_response_error_is_generic() {
        let resp = format_data_response(&Err(anyhow::anyhow!(
            "postgres: connection refused at 10.0.0.5:5432"
        )));
        assert_eq!(
            resp, "451 4.3.0 Temporary failure\r\n",
            "internal error details must never be echoed to the remote client"
        );
    }

    #[test]
    fn test_format_data_response_ok_includes_id() {
        let resp = format_data_response(&Ok("abc-123".into()));
        assert_eq!(resp, "250 OK id=abc-123\r\n");
    }

    // ── FIX-H (M28): bounded mailstore RPCs ───────────────────────────────

    #[tokio::test]
    async fn test_rpc_with_deadline_never_resolving_future_returns_none() {
        // A hung mailstore RPC must never stall the session: the deadline
        // helper must return None long before the outer test deadline.
        let result = tokio::time::timeout(
            Duration::from_millis(500),
            rpc_with_deadline(std::future::pending::<()>(), Duration::from_millis(50)),
        )
        .await;
        assert!(
            result.is_ok(),
            "rpc_with_deadline must return before the outer deadline"
        );
        assert_eq!(result.unwrap(), None);
    }

    #[tokio::test]
    async fn test_rpc_with_deadline_returns_value_when_resolves() {
        let result = rpc_with_deadline(async { 42 }, Duration::from_millis(50)).await;
        assert_eq!(result, Some(42));
    }

    // ── FIX-G (M26): bounded TLS handshakes ───────────────────────────────

    fn test_tls_acceptor() -> tokio_rustls::TlsAcceptor {
        use rustls_pemfile::{certs, private_key};
        let fixture_dir =
            std::path::PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
        let certs: Vec<_> = certs(&mut std::io::BufReader::new(
            std::fs::File::open(fixture_dir.join("cert.pem")).unwrap(),
        ))
        .collect::<Result<_, _>>()
        .unwrap();
        let key = private_key(&mut std::io::BufReader::new(
            std::fs::File::open(fixture_dir.join("key.pem")).unwrap(),
        ))
        .unwrap()
        .unwrap();
        let config = rustls::ServerConfig::builder_with_provider(Arc::new(
            rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .unwrap();
        tokio_rustls::TlsAcceptor::from(Arc::new(config))
    }

    #[tokio::test]
    async fn test_tls_handshake_timeout_fires_on_never_completing_handshake() {
        // A client that connects but never sends a ClientHello must be cut off
        // by the handshake timeout — never held forever.
        let never: std::future::Pending<
            std::io::Result<tokio_rustls::server::TlsStream<TcpStream>>,
        > = std::future::pending();

        let result = tokio::time::timeout(
            Duration::from_millis(500),
            tls_handshake_with_timeout(never, Duration::from_millis(50)),
        )
        .await;
        assert!(
            result.is_ok(),
            "tls_handshake_with_timeout must return before the outer deadline"
        );
        assert!(result.unwrap().is_err());
    }

    #[tokio::test]
    async fn test_starttls_handshake_timeout_releases_connection_slot() {
        tokio::time::pause();
        let (server, _ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        let server = Arc::new(server);
        let acceptor = test_tls_acceptor();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let ip = addr.ip();

        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session_plain(socket, peer, Some(acceptor)).await;
        });

        use tokio::io::AsyncReadExt;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let mut buf = [0u8; 2048];

        // Greeting
        let n = client.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("220"));
        // EHLO
        client.write_all(b"EHLO test.local\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("250"));
        // STARTTLS — server replies 220 and then waits for the handshake.
        client.write_all(b"STARTTLS\r\n").await.unwrap();
        let n = client.read(&mut buf).await.unwrap();
        assert!(String::from_utf8_lossy(&buf[..n]).starts_with("220"));

        // The client sends no ClientHello: the 30s handshake timeout must
        // fire and the session must end, releasing the per-IP slot.
        tokio::time::advance(TLS_HANDSHAKE_TIMEOUT + Duration::from_secs(1)).await;
        tokio::time::resume();

        let completed = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert!(
            completed.is_ok(),
            "session must terminate after the TLS handshake timeout"
        );

        let slot = server.connections.get(&ip).map(|v| *v).unwrap_or(0);
        assert_eq!(
            slot, 0,
            "the per-IP connection slot must be released after a timed-out handshake"
        );
    }

    #[tokio::test]
    async fn test_implicit_tls_handshake_timeout_does_not_hang_task() {
        tokio::time::pause();
        let (server, _ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        let server = Arc::new(server);
        let acceptor = test_tls_acceptor();

        // Simulate the implicit-TLS accept loop: a client that connects to the
        // 465 listener but never completes the handshake must be dropped by
        // the bounded wrapper instead of hanging the spawned task.
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();

        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            match tls_handshake_with_timeout(acceptor.accept(socket), TLS_HANDSHAKE_TIMEOUT).await
            {
                Ok(_tls_stream) => unreachable!("handshake cannot succeed without a client"),
                Err(()) => {}
            }
            let _ = peer;
            let _ = server;
        });

        let _client = TcpStream::connect(addr).await.unwrap();
        // Let the accepting task reach the handshake wrapper before advancing.
        tokio::task::yield_now().await;
        tokio::task::yield_now().await;
        tokio::time::advance(TLS_HANDSHAKE_TIMEOUT + Duration::from_secs(1)).await;
        tokio::task::yield_now().await;
        tokio::time::resume();

        let completed = tokio::time::timeout(Duration::from_secs(5), task).await;
        assert!(
            completed.is_ok(),
            "implicit-TLS handshake task must end after the timeout"
        );
    }
}
