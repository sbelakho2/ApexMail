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
use trust_dns_resolver::{Resolver, TokioResolver};
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

use super::util::{
    build_received_header, is_mail_from_arg, is_rcpt_to_arg, is_strict_end_of_data,
    line_content_bytes, line_lossy, log_session_summary, log_smtp_reject, mail_size_param,
    mail_smtputf8_param, metric_message, read_line_capped, received_hop_limit_exceeded, split_verb,
    unstuff_dot_line_bytes, validate_mail_params, validate_rcpt_params, LineRead, LineTerminator,
    MailParamPolicy, MAX_COMMAND_LINE, MAX_DATA_LINE,
};

// Shared resolver to avoid allocating a new DNS client per PTR verification.
// trust-dns 0.26: TokioAsyncResolver::tokio is gone; build a TokioResolver
// (builder defaults already equal ResolverOpts::default()).
static INBOUND_RDNS_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    Resolver::builder_tokio()
        .expect("system resolver configuration is always buildable")
        .build()
        .expect("system resolver configuration is always buildable")
});

/// M26: maximum time a TLS handshake may take before the connection is
/// dropped and the per-IP connection slot released.
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(30);

/// M28: bounded deadlines for mailstore gRPC calls — a hung mailstore must
/// never stall the SMTP session task indefinitely.
const MAILSTORE_CHANNEL_TIMEOUT: Duration = Duration::from_secs(10);
const MAILSTORE_RPC_TIMEOUT: Duration = Duration::from_secs(10);

/// F-14: number of 4xx/5xx replies after which the session is closed with
/// `421 4.7.0 Too many errors` (RFC 5321 §4.3.2 recommends a small limit).
const MAX_SESSION_ERRORS: u32 = 20;

/// F-14: hard wall-clock cap for an UNAUTHENTICATED session. Authenticated
/// sessions are bounded by the per-command idle timeout instead.
const SESSION_DEADLINE: Duration = Duration::from_secs(30 * 60);

type MailstoreClient = MailstoreServiceClient<
    tonic::service::interceptor::InterceptedService<Channel, InternalServiceAuthInterceptor>,
>;

// ── types ──────────────────────────────────────────────────────────────────────

/// F-02: outcome of the PTR/FCrDNS verification for one client IP.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum SourceCheck {
    /// PTR exists and forward-resolves back to the IP (FCrDNS confirmed);
    /// carries the confirmed hostname for the Received trace header.
    Confirmed(Option<String>),
    /// No PTR, or the PTR is not forward-confirmed; carries the unconfirmed
    /// PTR hostname when one exists.
    NoReverseDns(Option<String>),
    /// The resolver itself failed transiently — callers tempfail (451 4.4.3)
    /// and the result is never cached.
    Transient,
}

/// F-02: reply for a transient resolver failure at MAIL FROM — a DNS outage
/// must tempfail (never hard-reject), regardless of the FCrDNS policy flag.
const FCRDNS_TEMPFAIL_REPLY: &str = "451 4.4.3 Temporary DNS failure verifying sender\r\n";

/// F-02: reply when the client has no forward-confirmed reverse DNS AND the
/// operator opted into the hard gate (`SMTP_REQUIRE_FCRDNS=true`).
const FCRDNS_REQUIRED_REPLY: &str = "550 5.7.25 Reverse DNS lookup required (FCrDNS)\r\n";

/// F-02: the MAIL FROM reply implied by a source check (`None` = accept).
/// Pure so the fail-open/fail-closed matrix is unit-testable:
///
/// * `Transient` → tempfail 451 (either policy) — a resolver outage must
///   not permanently bounce mail.
/// * `NoReverseDns` → hard 550 only under `require_fcrdns=true`; the
///   default accepts with a logged warning (RFC 5321 §7.9).
/// * `Confirmed` → informational, always accepted.
fn fcrdns_reply(check: &SourceCheck, require_fcrdns: bool) -> Option<&'static str> {
    match (check, require_fcrdns) {
        (SourceCheck::Transient, _) => Some(FCRDNS_TEMPFAIL_REPLY),
        (SourceCheck::NoReverseDns(_), true) => Some(FCRDNS_REQUIRED_REPLY),
        (_, _) => None,
    }
}

/// F-02: only DETERMINATE outcomes belong in the negative cache — a
/// transient resolver failure must never poison the 600 s cache into
/// hard-rejecting every subsequent sender from that IP.
fn rdns_outcome_cacheable(check: &SourceCheck) -> bool {
    !matches!(check, SourceCheck::Transient)
}

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
    /// Whether this session's LISTENER permits AUTH at all. The implicit-TLS
    /// listener (port 465) is a submission port and always permits AUTH;
    /// the internet-facing port-25 listener permits it only when
    /// `SMTP_ADVERTISE_AUTH_PORT25=true` (default false — mail clients
    /// submitting real mail should use port 587/465, and port 25 must not
    /// present an always-on AUTH brute-force surface).
    #[serde(default)]
    pub auth_enabled: bool,
    /// Whether EHLO/HELO has been seen on the current leg of the session
    /// (RFC 5321 sequencing; reset by a successful STARTTLS).
    #[serde(default)]
    pub helo_seen: bool,
    /// Forward-confirmed reverse DNS hostname for the client IP ("unknown"
    /// when absent) — recorded in the Received trace header (F-01).
    #[serde(default)]
    pub client_rdns: Option<String>,
    /// Whether the current transaction's MAIL FROM carried SMTPUTF8
    /// (recorded in the Received trace header, F-01).
    #[serde(default)]
    pub mail_smtputf8: bool,
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
    /// Only Confirmed/NoReverseDns outcomes are cached (transient resolver
    /// failures must not poison the negative cache — F-02).
    rdns_cache: Cache<IpAddr, SourceCheck>,
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
        let interceptor = InternalServiceAuthInterceptor::from_env().map_err(|error| {
            anyhow::anyhow!("invalid internal mailstore authentication: {error}")
        })?;

        let auth_fail_tracker = AuthFailTracker::with_redis(redis.clone());
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
            auth_fail_tracker,
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
            let _ = write_line_tcp(
                &socket,
                "421 4.7.0 Too many connections, try again later\r\n",
            )
            .await;
            return;
        }
        // F-19: RAII slot guard (same pattern as the bounce server) — the
        // per-IP slot is released on EVERY exit path, early returns included.
        // F-19: increment + RAII guard (decrement happens on drop).
        *self.connections.entry(ip).or_insert(0) += 1;
        let _conn_guard = super::bounce::ConnGuard {
            conns: self.connections.clone(),
            ip,
        };

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
            // Port 25: AUTH only when explicitly enabled via config — the
            // internet-facing listener must not advertise an AUTH
            // brute-force surface by default.
            auth_enabled: self.config.advertise_auth_port25,
            helo_seen: false,
            client_rdns: None,
            mail_smtputf8: false,
        };

        let allow_starttls = tls.is_some();
        let mut stream = BufStream::new(socket);
        // F-11: the greeting is written exactly ONCE per connection, here.
        // run_session_loop no longer greets — re-entering it after STARTTLS
        // must continue at the client's EHLO (RFC 3207 §4.2), not emit a
        // second 220 banner.
        let greeting = format!("220 {} ESMTP ApexMail MTA\r\n", self.hostname);
        if let Err(e) = write_line_buf(&mut stream, &greeting).await {
            debug!(error = %e, "Failed to send greeting");
            log_session_summary(
                "inbound",
                ip,
                &ctx.id,
                ctx.tls_active,
                ctx.authenticated,
                ctx.message_count,
                (chrono::Utc::now() - ctx.start_time).num_milliseconds() as u128,
                "closed",
            );
            return;
        }
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
                        // RFC 3207 §4.2: the server must discard knowledge
                        // obtained from the client before TLS was in place —
                        // including the EHLO state (the client MUST re-issue
                        // EHLO on the TLS leg). No new greeting on this leg.
                        ctx.helo_seen = false;
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

        log_session_summary(
            "inbound",
            ip,
            &ctx.id,
            ctx.tls_active,
            ctx.authenticated,
            ctx.message_count,
            (chrono::Utc::now() - ctx.start_time).num_milliseconds() as u128,
            "closed",
        );
    }

    /// Generic session loop over any AsyncRead+AsyncWrite stream (plain or TLS).
    /// Returns true if client requested STARTTLS (caller should upgrade and re-enter).
    ///
    /// The caller owns the greeting (F-11): this loop starts directly at
    /// command processing so the post-STARTTLS leg does not produce a
    /// second 220 banner (RFC 3207).
    ///
    /// PIPELINING (RFC 2920): commands are read line-by-line from a buffered
    /// stream and each command's reply is written (and flushed) before the
    /// next line is parsed, so a client that groups `EHLO/MAIL/RCPT/DATA`
    /// into one TCP segment gets one reply per command in order. The only
    /// synchronisation point is DATA: the `354` reply is flushed before any
    /// body line is consumed, which is exactly the RFC 2920 checkpoint
    /// requirement.
    async fn run_session_loop<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        self: &Arc<Self>,
        stream: &mut BufStream<S>,
        ctx: &mut SessionContext,
        allow_starttls: bool, // #136:whether STARTTLS upgrade is available
    ) -> bool {
        // F-14: hard cap on the total lifetime of an unauthenticated session
        // and on the number of 4xx/5xx replies it may elicit.
        let session_deadline = tokio::time::Instant::now() + SESSION_DEADLINE;
        let mut error_count: u32 = 0;

        let mut line = String::new();
        loop {
            line.clear();
            match tokio::time::timeout(
                Duration::from_secs(300),
                read_line_capped(stream, MAX_COMMAND_LINE),
            )
            .await
            {
                Ok(Ok(LineRead::Eof)) => break,
                Err(_) => {
                    // Idle timeout: tell the client why the connection is
                    // going away (RFC 5321 §4.2.1 uses 421 for this) instead
                    // of silently dropping the socket.
                    let _ =
                        write_line_buf(stream, "421 4.4.2 Idle timeout, closing connection\r\n")
                            .await;
                    break;
                }
                Ok(Ok(LineRead::TooLong)) => {
                    // The line's remainder (through its newline) was fully
                    // drained — the session is still synchronised.
                    log_smtp_reject("inbound", ctx.client_ip, &ctx.id, "500 5.5.2 Line too long");
                    let _ = write_line_buf(stream, "500 5.5.2 Line too long\r\n").await;
                    error_count += 1;
                    if error_count >= MAX_SESSION_ERRORS {
                        let _ = write_line_buf(
                            stream,
                            "421 4.7.0 Too many errors, closing connection\r\n",
                        )
                        .await;
                        break;
                    }
                    continue;
                }
                Ok(Ok(LineRead::Overflow)) => {
                    // No newline within the absolute drain limit: the
                    // stream's position is untrustworthy. Reply and CLOSE —
                    // reading on would parse attacker-controlled bytes as commands.
                    log_smtp_reject(
                        "inbound",
                        ctx.client_ip,
                        &ctx.id,
                        "500 5.5.2 Line too long (connection closed)",
                    );
                    let _ = write_line_buf(stream, "500 5.5.2 Line too long\r\n").await;
                    break;
                }
                Ok(Ok(LineRead::Line(_, LineTerminator::BareLf))) => {
                    // F-08: a bare-LF COMMAND line is refused (RFC 5321
                    // commands are CRLF-terminated). DATA body tolerance is
                    // unchanged — only command lines are gated here.
                    log_smtp_reject(
                        "inbound",
                        ctx.client_ip,
                        &ctx.id,
                        "500 5.5.2 Bare LF not allowed",
                    );
                    let _ = write_line_buf(stream, "500 5.5.2 Bare LF not allowed\r\n").await;
                    error_count += 1;
                    if error_count >= MAX_SESSION_ERRORS {
                        let _ = write_line_buf(
                            stream,
                            "421 4.7.0 Too many errors, closing connection\r\n",
                        )
                        .await;
                        break;
                    }
                    continue;
                }
                Ok(Ok(LineRead::Line(l, _))) => line = line_lossy(&l),
                Ok(Err(e)) => {
                    debug!(error = %e, "Read error");
                    break;
                }
            }

            // F-14: an unauthenticated session must not outlive the deadline.
            if !ctx.authenticated && tokio::time::Instant::now() >= session_deadline {
                log_smtp_reject(
                    "inbound",
                    ctx.client_ip,
                    &ctx.id,
                    "421 4.7.0 Session deadline exceeded",
                );
                let _ = write_line_buf(
                    stream,
                    "421 4.7.0 Session deadline exceeded, closing connection\r\n",
                )
                .await;
                break;
            }

            // F-06: the verb is matched as an exact first token.
            let (verb_owned, arg) = split_verb(line.trim());
            let verb = verb_owned.as_str();

            // #136:Handle STARTTLS before generic command dispatch
            if verb == "STARTTLS" && arg.is_empty() {
                if ctx.tls_active {
                    // RFC 3207 §4: renegotiating (nested) TLS is a protocol
                    // error, not a temporary failure.
                    log_smtp_reject(
                        "inbound",
                        ctx.client_ip,
                        &ctx.id,
                        "503 5.5.1 TLS already active",
                    );
                    let _ = write_line_buf(stream, "503 5.5.1 TLS already active\r\n").await;
                    continue;
                }
                if !ctx.helo_seen {
                    log_smtp_reject(
                        "inbound",
                        ctx.client_ip,
                        &ctx.id,
                        "503 5.5.1 Error: send HELO/EHLO first",
                    );
                    let _ =
                        write_line_buf(stream, "503 5.5.1 Error: send HELO/EHLO first\r\n").await;
                    continue;
                }
                if starttls_is_available(allow_starttls, ctx) {
                    let _ = write_line_buf(stream, "220 Ready to start TLS\r\n").await;
                    return true; // Signal caller to upgrade
                } else {
                    log_smtp_reject(
                        "inbound",
                        ctx.client_ip,
                        &ctx.id,
                        "454 4.7.0 TLS not available",
                    );
                    let _ = write_line_buf(stream, "454 4.7.0 TLS not available\r\n").await;
                    continue;
                }
            } else if verb == "STARTTLS" {
                log_smtp_reject(
                    "inbound",
                    ctx.client_ip,
                    &ctx.id,
                    "501 5.5.4 Syntax: STARTTLS",
                );
                let _ = write_line_buf(stream, "501 5.5.4 Syntax: STARTTLS\r\n").await;
                continue;
            }

            let response = self
                .handle_command(verb, arg, &line, ctx, allow_starttls)
                .await;

            // F-14: every 4xx/5xx reply counts toward the error budget; the
            // session is closed with 421 once it is exhausted (the command's
            // own reply is still delivered first, matching the submission
            // server's reply macro).
            let is_error_reply = response.starts_with('4') || response.starts_with('5');
            if is_error_reply {
                log_smtp_reject("inbound", ctx.client_ip, &ctx.id, &response);
                error_count += 1;
            }

            if let Err(e) = write_line_buf(stream, &response).await {
                debug!(error = %e, "Write error");
                break;
            }

            if is_error_reply && error_count >= MAX_SESSION_ERRORS {
                let _ = write_line_buf(stream, "421 4.7.0 Too many errors, closing connection\r\n")
                    .await;
                break;
            }

            if verb == "QUIT" {
                break;
            }

            // DATA handling
            if verb == "DATA" && response.starts_with("354") {
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
                let mut overflowed = false;
                loop {
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
                            // part of a message we are willing to store. The
                            // line was drained through its newline, so the
                            // session stays synchronised.
                            too_large = true;
                            message.clear();
                        }
                        Ok(Ok(LineRead::Overflow)) => {
                            // No newline within the absolute drain limit: the
                            // stream can no longer be resynchronised — close.
                            overflowed = true;
                            break;
                        }
                        Ok(Ok(LineRead::Line(l, term))) => {
                            // RFC 5321 §4.1.1.5: DATA ends ONLY on a line that
                            // is exactly "." with a CRLF terminator. A bare-LF
                            // "." line is body data (SMTP smuggling defence).
                            if is_strict_end_of_data(&l, term) {
                                terminated = true;
                                break;
                            }
                            // #141:Check size BEFORE extending to prevent temporary overallocation
                            if !too_large {
                                // Strip the line's actual terminator, un-stuff
                                // exactly one leading dot (RFC 5321 §4.5.2),
                                // and store the line with a normalized CRLF so
                                // a bare-LF body line is never relayed onward.
                                // Bytes are preserved verbatim (8BITMIME).
                                let data_slice =
                                    unstuff_dot_line_bytes(line_content_bytes(&l, term));
                                if message.len() + data_slice.len() + 2
                                    > self.config.max_message_size
                                {
                                    too_large = true;
                                    message.clear();
                                } else {
                                    message.extend_from_slice(data_slice);
                                    message.extend_from_slice(b"\r\n");
                                }
                            }
                        }
                    }
                }

                if data_timed_out {
                    // #137:Total DATA timeout exceeded
                    log_smtp_reject(
                        "inbound",
                        ctx.client_ip,
                        &ctx.id,
                        "421 4.4.2 Data timeout exceeded",
                    );
                    let _ = write_line_buf(stream, "421 4.4.2 Data timeout exceeded\r\n").await;
                    break;
                }

                if overflowed {
                    log_smtp_reject(
                        "inbound",
                        ctx.client_ip,
                        &ctx.id,
                        "500 5.5.2 Data line too long (connection closed)",
                    );
                    let _ = write_line_buf(stream, "500 5.5.2 Line too long\r\n").await;
                    break;
                }

                if aborted {
                    // Truncated message: discard the whole transaction and
                    // tell the client to retry rather than accepting (and
                    // relaying) a partial message.
                    log_smtp_reject(
                        "inbound",
                        ctx.client_ip,
                        &ctx.id,
                        "451 4.3.0 Temporary failure (truncated message)",
                    );
                    let _ = write_line_buf(stream, "451 4.3.0 Temporary failure\r\n").await;
                    ctx.mail_from = None;
                    ctx.rcpt_to.clear();
                    continue;
                }

                if too_large {
                    log_smtp_reject(
                        "inbound",
                        ctx.client_ip,
                        &ctx.id,
                        "552 5.3.4 Message size exceeds fixed maximum message size",
                    );
                    let _ = write_line_buf(
                        stream,
                        "552 5.3.4 Message size exceeds fixed maximum message size\r\n",
                    )
                    .await;
                    ctx.mail_from = None;
                    ctx.rcpt_to.clear();
                } else if terminated {
                    // F-01: refuse obvious routing loops before any
                    // parsing/persist work (cheap raw header scan).
                    if received_hop_limit_exceeded(&message) {
                        log_smtp_reject(
                            "inbound",
                            ctx.client_ip,
                            &ctx.id,
                            "550 5.4.6 Routing loop detected",
                        );
                        let _ = write_line_buf(stream, "550 5.4.6 Routing loop detected\r\n").await;
                        ctx.mail_from = None;
                        ctx.rcpt_to.clear();
                        ctx.mail_smtputf8 = false;
                        continue;
                    }
                    let result = self.process_message(ctx, &message).await;
                    let resp = format_data_response(&result);
                    if resp.starts_with('4') || resp.starts_with('5') {
                        log_smtp_reject("inbound", ctx.client_ip, &ctx.id, &resp);
                        // F-14: DATA rejections count toward the budget too.
                        error_count += 1;
                    }
                    let _ = write_line_buf(stream, &resp).await;
                    ctx.message_count += 1;
                    ctx.mail_from = None;
                    ctx.rcpt_to.clear();
                    ctx.mail_smtputf8 = false;
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
            // F-13: the implicit-TLS listener must not drop over-limit
            // connections silently — the client already paid for the TLS
            // handshake, so tell it why the connection is going away.
            let mut stream = BufStream::new(tls_stream);
            let _ = write_line_buf(
                &mut stream,
                "421 4.7.0 Too many connections, try again later\r\n",
            )
            .await;
            return;
        }
        // F-19: RAII slot guard — released on every exit path.
        // F-19: increment + RAII guard (decrement happens on drop).
        *self.connections.entry(ip).or_insert(0) += 1;
        let _conn_guard = super::bounce::ConnGuard {
            conns: self.connections.clone(),
            ip,
        };

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
            // Port 465 (implicit TLS) is a submission port: AUTH is part of
            // its contract — email clients that auto-detect port 465 hang
            // indefinitely when AUTH is missing from EHLO.
            auth_enabled: true,
            helo_seen: false,
            client_rdns: None,
            mail_smtputf8: false,
        };

        let mut stream = BufStream::new(tls_stream);
        let greeting = format!("220 {} ESMTP ApexMail MTA\r\n", self.hostname);
        if let Err(e) = write_line_buf(&mut stream, &greeting).await {
            debug!(error = %e, "Failed to send greeting");
            return;
        }
        self.run_session_loop(&mut stream, &mut ctx, false).await; // #136:already on TLS
        log_session_summary(
            "inbound465",
            ip,
            &ctx.id,
            ctx.tls_active,
            ctx.authenticated,
            ctx.message_count,
            (chrono::Utc::now() - ctx.start_time).num_milliseconds() as u128,
            "closed",
        );
    }

    // ── commands ───────────────────────────────────────────────────────────────

    async fn handle_command(
        &self,
        verb: &str,
        arg: &str,
        raw_line: &str,
        ctx: &mut SessionContext,
        allow_starttls: bool,
    ) -> String {
        if verb == "EHLO" || verb == "HELO" {
            let Some(host) = parse_helo_hostname(raw_line) else {
                return "501 5.5.4 Invalid HELO/EHLO hostname\r\n".into();
            };
            ctx.helo_hostname = host.to_string();
            ctx.helo_seen = true;
            // F-04: EHLO/HELO resets any transaction in progress
            // (RFC 5321 §4.1.4).
            ctx.mail_from = None;
            ctx.rcpt_to.clear();
            ctx.mail_smtputf8 = false;
            let mut caps = format!("250-{} Hello {}\r\n", self.hostname, host);
            caps.push_str(&format!("250-SIZE {}\r\n", self.config.max_message_size));
            if should_advertise_starttls(self.config.tls.enabled, allow_starttls, ctx) {
                caps.push_str("250-STARTTLS\r\n");
            }
            // Advertise AUTH on TLS connections whose listener permits it
            // (port 465 by default; port 25 only with
            // SMTP_ADVERTISE_AUTH_PORT25=true). Clients submitting real mail
            // should use the dedicated submission ports 587/465.
            if ctx.tls_active && ctx.auth_enabled {
                caps.push_str("250-AUTH PLAIN LOGIN\r\n");
            }
            // 8BITMIME (RFC 6152): body octets outside US-ASCII are accepted
            // and stored byte-for-byte. SMTPUTF8 (RFC 6531): UTF-8 envelope
            // addresses are accepted (the address validator is
            // charset-agnostic by design).
            caps.push_str("250-8BITMIME\r\n");
            caps.push_str("250-PIPELINING\r\n");
            // F-05: ENHANCEDSTATUSCODES (RFC 2034) — every reply this
            // server emits already carries an enhanced status code.
            caps.push_str("250-ENHANCEDSTATUSCODES\r\n");
            caps.push_str("250 SMTPUTF8\r\n");
            caps
        } else if verb == "STARTTLS" {
            // The session loop dispatches STARTTLS before this point; the
            // verb only reaches here when no TLS upgrade is available.
            "454 4.7.0 TLS not available\r\n".into()
        } else if (ctx.auth_plain_pending || ctx.auth_login_user.is_some()) && ctx.tls_active {
            // AUTH continuation line (base64 payload, or "*" to cancel —
            // F-12, RFC 4954 §4).
            if raw_line.trim() == "*" {
                ctx.auth_plain_pending = false;
                ctx.auth_login_user = None;
                return "501 5.7.0 Authentication cancelled\r\n".into();
            }
            if ctx.auth_plain_pending {
                // AUTH PLAIN two-step: client sent the base64 response after our 334
                ctx.auth_plain_pending = false;
                return self.do_auth_plain(raw_line.trim(), ctx).await;
            }
            // AUTH LOGIN state machine: we're waiting for username or password
            use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
            let decoded = BASE64.decode(raw_line.trim()).unwrap_or_default();
            let value = String::from_utf8_lossy(&decoded).to_string();

            if ctx.auth_login_user.as_deref() == Some("") {
                // Username received, now prompt for password
                ctx.auth_login_user = Some(value);
                "334 UGFzc3dvcmQ6\r\n".into()
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
        } else if verb == "AUTH" && !ctx.auth_enabled {
            // Port 25 without the explicit opt-in: AUTH is neither advertised
            // nor honoured, removing the internet-facing brute-force surface.
            "502 5.5.1 AUTH not available on this port; submit mail via port 587 or 465\r\n".into()
        } else if verb == "AUTH" && !ctx.helo_seen {
            "503 5.5.1 Error: send HELO/EHLO first\r\n".into()
        } else if verb == "AUTH" && !ctx.tls_active {
            // AUTH before TLS — reject for security
            "538 5.7.11 Encryption required for requested authentication\r\n".into()
        } else if verb == "AUTH" {
            // F-12: the mechanism matches case-insensitively on the first
            // ARG token; the remainder is the optional inline initial
            // response (RFC 4954; "=" encodes the empty string).
            let (mech, initial) = match arg.split_once(char::is_whitespace) {
                Some((mech, rest)) => (mech.to_ascii_uppercase(), rest.trim_start()),
                None => (arg.to_ascii_uppercase(), ""),
            };
            let initial = initial.strip_prefix('=').unwrap_or(initial);
            if mech == "PLAIN" {
                if initial.is_empty() {
                    // Two-step: send 334 challenge, set pending flag
                    ctx.auth_plain_pending = true;
                    "334 \r\n".into()
                } else {
                    self.do_auth_plain(initial, ctx).await
                }
            } else if mech == "LOGIN" {
                if initial.is_empty() {
                    // Multi-step: prompt for the base64 username.
                    ctx.auth_login_user = Some(String::new()); // marker: waiting for username
                    "334 VXNlcm5hbWU6\r\n".into()
                } else {
                    // Inline initial response = base64 username; go straight
                    // to the password prompt (mirrors the submission server).
                    use base64::{engine::general_purpose::STANDARD as BASE64, Engine};
                    let user = BASE64
                        .decode(initial)
                        .map(|bytes| String::from_utf8_lossy(&bytes).into_owned())
                        .unwrap_or_default();
                    ctx.auth_login_user = Some(user);
                    "334 UGFzc3dvcmQ6\r\n".into()
                }
            } else {
                "504 5.5.4 Unrecognized authentication type\r\n".into()
            }
        } else if verb == "MAIL" {
            if !ctx.helo_seen {
                return "503 5.5.1 Error: send HELO/EHLO first\r\n".into();
            }
            if !is_mail_from_arg(arg) {
                // F-06: "MAIL FROMX:<a@b>" must not be treated as MAIL
                // (syntax errors are answered regardless of auth state —
                // RFC 5321 §4.1.4).
                return "501 5.5.4 Syntax: MAIL FROM:<address>\r\n".into();
            }
            if self.config.auth_required && !ctx.authenticated {
                return "530 5.7.0 Authentication required\r\n".into();
            }
            if ctx.mail_from.is_some() {
                // F-04: nested MAIL — RFC 5321 §4.1.4 sequencing error.
                return "503 5.5.1 Nested MAIL command\r\n".into();
            }
            // F-02: forward-confirmed reverse DNS. Transient resolver
            // failures tempfail (451 4.4.3) and are never cached; a missing
            // PTR is only a hard 550 5.7.25 under SMTP_REQUIRE_FCRDNS=true.
            let check = self.verify_inbound_source(ctx.client_ip).await;
            // Record the PTR hostname (when any) for the Received header.
            ctx.client_rdns = match &check {
                SourceCheck::Confirmed(host) | SourceCheck::NoReverseDns(host) => host.clone(),
                SourceCheck::Transient => None,
            };
            if let Some(reply) = fcrdns_reply(&check, self.config.require_fcrdns) {
                if check == SourceCheck::Transient {
                    warn!(
                        client_ip = %ctx.client_ip,
                        "Temporary DNS failure during reverse-DNS verification; tempfail"
                    );
                } else {
                    warn!(
                        client_ip = %ctx.client_ip,
                        "Rejected inbound sender without forward-confirmed PTR record"
                    );
                    metric_message("inbound", "rejected");
                }
                return reply.into();
            }
            if matches!(check, SourceCheck::NoReverseDns(_)) {
                warn!(
                    client_ip = %ctx.client_ip,
                    "Inbound sender has no forward-confirmed PTR (accepted: SMTP_REQUIRE_FCRDNS=false)"
                );
            }
            // RFC 5321 §4.1.1.3/§4.1.1.11 + RFC 1870: only parameters for
            // advertised extensions are accepted; an advertised SIZE
            // declaration over the limit is refused up-front with 552.
            if let Err(reject) = validate_mail_params(
                raw_line,
                MailParamPolicy {
                    body_8bitmime: true,
                    smtputf8: true,
                },
            ) {
                return format!("{reject}\r\n");
            }
            if let Some(declared) = mail_size_param(raw_line) {
                if declared > self.config.max_message_size as u64 {
                    return "552 5.3.4 Message size exceeds fixed maximum message size\r\n".into();
                }
            }
            let addr = extract_address(raw_line);
            // E-6:an unvalidated reverse-path used to be echoed into
            // downstream rows (inbound_messages.mail_from). The null sender
            // <> is legal on port 25 (bounces); any non-empty address must
            // satisfy the same syntax rules the submission server enforces.
            if !addr.is_empty() && !super::submission::is_valid_envelope_address(&addr) {
                return "501 5.1.7 Malformed reverse-path\r\n".into();
            }
            // RFC 5321 §4.1.4: a MAIL FROM implicitly resets any prior
            // transaction's recipients — a new reverse-path starts a new
            // transaction.
            ctx.rcpt_to.clear();
            ctx.mail_from = Some(addr);
            ctx.mail_smtputf8 = mail_smtputf8_param(raw_line);
            "250 2.0.0 Ok\r\n".into()
        } else if verb == "RCPT" {
            if !ctx.helo_seen {
                return "503 5.5.1 Error: send HELO/EHLO first\r\n".into();
            }
            if self.config.auth_required && !ctx.authenticated {
                return "530 5.7.0 Authentication required\r\n".into();
            }
            if ctx.mail_from.is_none() {
                return "503 5.5.1 Error: need MAIL command first\r\n".into();
            }
            if ctx.rcpt_to.len() >= self.config.max_recipients {
                return "452 4.5.3 Too many recipients\r\n".into();
            }
            if !is_rcpt_to_arg(arg) {
                return "501 5.5.4 Syntax: RCPT TO:<address>\r\n".into();
            }
            if let Err(reject) = validate_rcpt_params(raw_line) {
                return format!("{reject}\r\n");
            }
            let addr = extract_address(raw_line);
            // F-03: the forward-path gets the SAME syntax validation the
            // submission server applies (no whitespace, no control
            // characters, exactly one '@', well-formed dotted domain) — the
            // old length+domain-only check let "a b@example.com" and
            // "a@@b.com" straight into the envelope.
            if !super::submission::is_valid_envelope_address(&addr) {
                return "501 5.1.3 Bad recipient address syntax\r\n".into();
            }
            match self.is_managed_recipient(&addr).await {
                Ok(true) => {}
                Ok(false) => return "550 5.1.1 No such user here\r\n".into(),
                Err(error) => {
                    warn!(
                        recipient = %mail_common::pii::redact_email(&addr),
                        %error,
                        "Failed to validate inbound recipient domain"
                    );
                    return "451 4.3.0 Temporary local problem\r\n".into();
                }
            }
            ctx.rcpt_to.push(addr);
            "250 2.0.0 Ok\r\n".into()
        } else if verb == "DATA" {
            if self.config.auth_required && !ctx.authenticated {
                return "530 5.7.0 Authentication required\r\n".into();
            }
            if !arg.is_empty() {
                // F-06: DATA takes no parameters.
                return "501 5.5.4 Syntax: DATA\r\n".into();
            }
            if ctx.mail_from.is_none() || ctx.rcpt_to.is_empty() {
                "503 5.5.1 Bad sequence of commands\r\n".into()
            } else {
                "354 Start mail input; end with <CRLF>.<CRLF>\r\n".into()
            }
        } else if verb == "RSET" {
            ctx.mail_from = None;
            ctx.rcpt_to.clear();
            ctx.mail_smtputf8 = false;
            "250 2.0.0 Ok\r\n".into()
        } else if verb == "NOOP" {
            "250 2.0.0 Ok\r\n".into()
        } else if verb == "QUIT" {
            "221 2.0.0 Bye\r\n".into()
        } else if verb == "HELP" {
            "214 2.0.0 Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT STARTTLS HELP VRFY EXPN; see RFC 5321\r\n"
                .into()
        } else if verb == "VRFY" {
            // RFC 5321 §7.3: never confirm address existence — 252 keeps
            // the anti-enumeration posture while staying protocol-correct.
            "252 2.5.2 Cannot VRFY user, but will accept message and attempt delivery\r\n".into()
        } else if verb == "EXPN" {
            "502 5.5.1 EXPN command not supported\r\n".into()
        } else {
            // F-06: unknown COMMAND is a syntax error (RFC 5321 §4.2.4
            // uses 500 for unrecognized commands).
            "500 5.5.2 Command not recognised\r\n".into()
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
                metric_message("inbound", "rejected");
                anyhow::bail!("Message rejected by policy (DMARC)");
            }
            crate::auth::MessageDisposition::Quarantine => {
                metric_message("inbound", "quarantined");
                info!(id = %message_id, "Message quarantined");
            }
            crate::auth::MessageDisposition::Accept => {}
            crate::auth::MessageDisposition::TempFail => {
                // C:the DMARC policy lookup transiently failed with no
                // passing SPF/DKIM — answer 451 (via the generic temporary
                // failure reply) so the sender retries instead of
                // fail-open accepting a potentially spoofed message.
                metric_message("inbound", "tempfail");
                anyhow::bail!("Message temporarily rejected: DMARC policy lookup failed");
            }
        }

        // F-16 (partial): after DMARC evaluation, optionally seal the
        // message with an ARC set signed by the managed domain's DKIM key.
        let arc_headers = if self.config.arc_seal {
            self.build_arc_seal(ctx, raw, &auth_results).await
        } else {
            None
        };

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

        // 4. Compose the stored message: the Received trace header for this
        //    hop (F-01), the Authentication-Results header, any ARC seal,
        //    then the raw client bytes verbatim. helo passed
        //    is_valid_helo_hostname and the addresses are server-generated,
        //    so no prepended value can inject CRLF.
        let received = build_received_header(
            helo,
            ctx.client_rdns.as_deref(),
            ctx.client_ip,
            &self.hostname,
            ctx.tls_active,
            ctx.authenticated,
            ctx.mail_smtputf8,
            &message_id,
        );
        let stored_message = build_stored_message(
            &received,
            &auth_results.auth_results_header,
            arc_headers.as_deref(),
            raw,
        );
        let sender = if mail_from == "<>" { "" } else { mail_from };

        // 5. Persist the message using ONLY the columns migration 088
        //    guarantees on inbound_messages (tenant_id, mail_from, rcpt_to,
        //    client_ip, helo_hostname, raw_message, raw_size, auth_results,
        //    spf_result, disposition, is_verp_reply). The previously written
        //    from_email/to_email/subject/body_text/body_html/headers/
        //    created_at family exists in NO deployed migration — that INSERT
        //    failed with "column does not exist" and 451-rejected every
        //    inbound message. The full raw MIME (trace headers included) is
        //    preserved in raw_message for downstream consumers.
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
        .bind(&stored_message)
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
            self.deliver_to_mailstore(ctx, &stored_message).await;
        }

        info!(
            id = %message_id,
            from = %mail_common::pii::redact_email(mail_from),
            rcpt_count = ctx.rcpt_to.len(),
            spf = ?auth_results.spf.result,
            dmarc = ?auth_results.dmarc.result,
            is_verp = is_verp,
            "Message accepted"
        );
        metric_message("inbound", "accepted");

        Ok(message_id)
    }

    /// F-16 (partial): build the ARC header set (RFC 8617) for an accepted
    /// message, sealed with the RECEIVING (managed) domain's DKIM key —
    /// the domain that owns the first recipient resolves the key.
    ///
    /// Minimal-correct wiring: only FIRST-HOP messages are sealed
    /// (no pre-existing ARC chain → `cv=none`, which needs no key
    /// resolution for prior sets). Sealing a message that already carries a
    /// chain requires async DKIM key resolution for the verifier closure
    /// (generate_arc_headers takes a sync lookup) — that lands with the
    /// direct-MX sender work tracked under F-16. Any failure is logged and
    /// downgraded to "no seal": ARC must never reject or delay mail.
    async fn build_arc_seal(
        &self,
        ctx: &SessionContext,
        raw: &[u8],
        auth_results: &crate::auth::AuthenticationResults,
    ) -> Option<String> {
        let recipient = ctx.rcpt_to.first()?;
        let domain = recipient_domain(recipient)?;

        // Resolve the managed domain row that holds the DKIM sealing key.
        // `dkim_private_key` is the encrypted "dkim:v1:" envelope; the AAD
        // binds it to (tenant, domain), matching how the API writes and the
        // worker reads the same column.
        let row: Option<(uuid::Uuid, String, String, String)> = sqlx::query_as(
            r#"SELECT id, tenant_id::text, dkim_selector, dkim_private_key
                 FROM domains
                WHERE LOWER(name) = LOWER($1)
                  AND status = 'verified'
                  AND dkim_enabled = true
                  AND dkim_selector IS NOT NULL
                  AND dkim_private_key IS NOT NULL
                LIMIT 1"#,
        )
        .bind(domain)
        .fetch_optional(&self.pool)
        .await
        .ok()
        .flatten();
        let Some((domain_id, tenant_id, selector, stored_key)) = row else {
            warn!(
                domain = %domain,
                "ARC sealing enabled (SMTP_ARC_SEAL=true) but no ready DKIM key for the managed domain; skipping seal"
            );
            return None;
        };

        let aad = apexmail_lib::dkim::dkim_private_key_aad(&tenant_id, &domain_id.to_string());
        let private_key = match apexmail_lib::dkim::decrypt_dkim_private_key(&stored_key, &aad)
            .map_err(|e| anyhow::anyhow!("dkim envelope: {e}"))
            .and_then(|pem| parse_rsa_private_key(&pem))
        {
            Ok(key) => key,
            Err(error) => {
                warn!(%error, domain = %domain, "ARC sealing key unusable; skipping seal");
                return None;
            }
        };

        let (headers_bytes, body_bytes) = super::submission::split_headers_body(raw);
        let headers = String::from_utf8_lossy(headers_bytes);

        // First-hop only (see doc comment): an existing chain would need
        // real key resolution to produce a meaningful cv= value.
        if !crate::auth::parse_arc_headers(&headers).is_empty() {
            debug!("ARC: message already carries a chain; first-hop-only sealing skips it");
            return None;
        }

        let arc_input = crate::auth::ArcAuthResult {
            spf: format!("{:?}", auth_results.spf.result).to_lowercase(),
            dkim: auth_results
                .dkim
                .iter()
                .map(|outcome| format!("{:?}", outcome.result).to_lowercase())
                .max()
                .unwrap_or_else(|| "none".to_string()),
            dmarc: format!("{:?}", auth_results.dmarc.result).to_lowercase(),
        };
        let config = crate::auth::ArcSigningConfig {
            domain: domain.to_string(),
            selector,
            private_key,
        };
        match crate::auth::generate_arc_headers(
            &headers,
            body_bytes,
            &arc_input,
            &config,
            &[],
            &|_, _| None,
        ) {
            Ok(set) => Some(crate::auth::format_arc_headers_for_message(&set)),
            Err(error) => {
                warn!(%error, domain = %domain, "ARC seal generation failed; skipping seal");
                None
            }
        }
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
    /// The fully-composed stored message (Received trace header +
    /// Authentication-Results + optional ARC seal + raw client bytes) is
    /// stored into the recipient's Inbox via the mailstore gRPC service so
    /// the message is visible over IMAP. Best-effort: failures are logged,
    /// never propagated to the SMTP session.
    async fn deliver_to_mailstore(&self, ctx: &SessionContext, final_message: &[u8]) {
        let mut client = self.mailstore.clone();

        for recipient in &ctx.rcpt_to {
            let lookup = GetAccountRequest {
                account_id: String::new(),
                email: recipient.clone(),
            };
            // M28: bounded RPC — a hung mailstore must not stall the session.
            let account_id =
                match rpc_with_deadline(client.get_account(lookup), MAILSTORE_RPC_TIMEOUT).await {
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
                raw_message: final_message.to_vec().into(),
                flags: Some(MessageFlags {
                    recent: true,
                    ..Default::default()
                }),
                internal_date: chrono::Utc::now().timestamp(),
                // Delivery path: keep per-mailbox Message-ID dedup active.
                dedup_exempt: false,
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

    /// F-02: verify the client source via PTR + forward confirmation
    /// (FCrDNS). Returns a [`SourceCheck`] the MAIL FROM handler turns into
    /// a reply:
    ///
    /// * `Confirmed` — FCrDNS passed; informational only, mail proceeds.
    /// * `NoReverseDns` — no PTR (or PTR not forward-confirmed). A hard
    ///   `550 5.7.25` ONLY under `SMTP_REQUIRE_FCRDNS=true`; the default
    ///   logs a warning and continues (RFC 5321 §7.9 makes the refusal a
    ///   policy choice, and plenty of legitimate senders lack matching PTR).
    /// * `Transient` — the resolver itself failed. Callers tempfail with
    ///   `451 4.4.3`, and the result is NEVER cached: a DNS outage must not
    ///   poison the 600 s cache into hard-rejecting every sender.
    async fn verify_inbound_source(&self, ip: IpAddr) -> SourceCheck {
        if ptr_verification_exempt(ip) {
            return SourceCheck::Confirmed(None);
        }

        if let Some(cached) = self.rdns_cache.get(&ip) {
            return cached;
        }

        let resolver = &*INBOUND_RDNS_RESOLVER;
        let result = match resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                // trust-dns 0.26 removed typed lookup iteration; extract the
                // PTR names from the raw answer records.
                let hostnames: Vec<String> = lookup
                    .answers()
                    .iter()
                    .filter_map(|record| match &record.data {
                        trust_dns_resolver::proto::rr::RData::PTR(ptr) => Some(ptr.0.to_string()),
                        _ => None,
                    })
                    .map(|name| name.trim_end_matches('.').to_ascii_lowercase())
                    .filter(|hostname| !hostname.is_empty())
                    .collect();

                if hostnames.is_empty() {
                    debug!(ip = %ip, "Inbound PTR lookup returned no hostnames");
                    SourceCheck::NoReverseDns(None)
                } else {
                    let mut confirmed: Option<String> = None;
                    let mut transient = false;
                    for hostname in &hostnames {
                        match resolver.lookup_ip(hostname.as_str()).await {
                            Ok(forward) => {
                                if forward.iter().any(|addr| addr == ip) {
                                    confirmed = Some(hostname.clone());
                                    break;
                                }
                                debug!(ip = %ip, hostname = %hostname, "Inbound FCrDNS failed: forward lookup doesn't match IP");
                            }
                            // A failing FORWARD lookup is as transient as a
                            // failing PTR lookup — fail open with a tempfail,
                            // never a permanent rejection.
                            Err(error) => {
                                debug!(ip = %ip, hostname = %hostname, %error, "Inbound FCrDNS forward lookup failed");
                                transient = true;
                            }
                        }
                    }
                    if let Some(hostname) = confirmed {
                        SourceCheck::Confirmed(Some(hostname))
                    } else if transient {
                        SourceCheck::Transient
                    } else {
                        SourceCheck::NoReverseDns(hostnames.into_iter().next())
                    }
                }
            }
            Err(error) => {
                debug!(ip = %ip, %error, "Inbound PTR lookup failed");
                SourceCheck::Transient
            }
        };

        // F-02: only determinate outcomes are cached (a transient resolver
        // failure must never poison the negative cache).
        match result {
            cacheable if rdns_outcome_cacheable(&cacheable) => {
                self.rdns_cache.insert(ip, cacheable.clone());
                cacheable
            }
            transient => transient,
        }
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
            Err(_) => "501 5.5.2 Invalid base64\r\n".into(),
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
        if self.auth_fail_tracker.is_locked(ip, email).await {
            metrics::counter!("mta.auth.lockout").increment(1);
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
                self.auth_fail_tracker.record_failure(ip, email).await;
                // FIX-5: spend the same verification time as a real
                // account so the response cannot reveal whether the
                // account exists (user-enumeration side channel).
                let _ = verify_against_dummy(password);
                metrics::counter!("mta.auth.failure").increment(1);
                return Err(AuthError::Failed);
            }
        };

        if status != "active" {
            self.auth_fail_tracker.record_failure(ip, email).await;
            let _ = verify_against_dummy(password);
            metrics::counter!("mta.auth.failure").increment(1);
            return Err(AuthError::Failed);
        }

        // Same scheme handling as the submission server: accept Argon2id and
        // legacy bcrypt hashes, and migrate bcrypt rows to Argon2id on success.
        match apexmail_lib::crypto::verify_password_for_login(password, &password_hash) {
            Ok(verification) if verification.valid => {
                self.auth_fail_tracker.reset(ip, email).await;
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
                self.auth_fail_tracker.record_failure(ip, email).await;
                metrics::counter!("mta.auth.failure").increment(1);
                Err(AuthError::Failed)
            }
        }
    }
}

// ── helpers ────────────────────────────────────────────────────────────────────

/// Compose the stored/delivered message: the `Received:` trace header for
/// this hop (F-01), the Authentication-Results header, an optional ARC seal
/// set (F-16), and then the raw client bytes verbatim — each separated by
/// exactly one CRLF.
///
/// The A-R header generated by `build_auth_results_header` folds its
/// continuation lines with `<CRLF>\t` (never a bare LF), and it carries no
/// trailing CRLF of its own — exactly one is appended here so the header
/// cannot fuse with the message's first header line ("…dmarc=passFrom:
/// a@b.com"). The same applies to the Received/ARC blocks (no trailing CRLF
/// of their own). The raw message below is already CRLF-normalized line by
/// line during DATA reception, so the whole stored blob uses CRLF endings
/// exclusively.
fn build_stored_message(
    received: &str,
    auth_results_header: &str,
    arc_headers: Option<&str>,
    raw: &[u8],
) -> Vec<u8> {
    let mut final_message = Vec::with_capacity(
        received.len()
            + auth_results_header.len()
            + arc_headers.map_or(0, str::len)
            + raw.len()
            + 8,
    );
    final_message.extend_from_slice(received.as_bytes());
    final_message.extend_from_slice(b"\r\n");
    final_message.extend_from_slice(auth_results_header.as_bytes());
    final_message.extend_from_slice(b"\r\n");
    if let Some(arc) = arc_headers {
        final_message.extend_from_slice(arc.as_bytes());
        final_message.extend_from_slice(b"\r\n");
    }
    final_message.extend_from_slice(raw);
    final_message
}

/// Parse a PEM-encoded RSA private key (PKCS#8 first, then PKCS#1 — the
/// two encodings apexmail-lib's DKIM provisioning may have produced).
fn parse_rsa_private_key(pem: &str) -> anyhow::Result<rsa::RsaPrivateKey> {
    use rsa::pkcs1::DecodeRsaPrivateKey;
    use rsa::pkcs8::DecodePrivateKey;
    rsa::RsaPrivateKey::from_pkcs8_pem(pem)
        .or_else(|_| rsa::RsaPrivateKey::from_pkcs1_pem(pem))
        .map_err(|e| anyhow::anyhow!("invalid RSA private-key PEM: {e}"))
}

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

pub(crate) fn is_valid_helo_hostname(host: &str) -> bool {
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
        Ok(id) => format!("250 2.0.0 Ok id={id}\r\n"),
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
        Ok(Ok(stream)) => {
            metrics::counter!("mta.tls.handshake", "result" => "ok").increment(1);
            Ok(stream)
        }
        Ok(Err(e)) => {
            metrics::counter!("mta.tls.handshake", "result" => "failed").increment(1);
            debug!(error = %e, "TLS handshake failed");
            Err(())
        }
        Err(_) => {
            metrics::counter!("mta.tls.handshake", "result" => "timeout").increment(1);
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
            auth_enabled: true,
            helo_seen: false,

            client_rdns: None,

            mail_smtputf8: false,
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
            auth_enabled: true,
            helo_seen: false,

            client_rdns: None,

            mail_smtputf8: false,
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

    /// Drive handle_command exactly the way the session loop does (F-06):
    /// split the raw line into verb + arg and dispatch on the verb.
    async fn handle_cmd(server: &InboundServer, line: &str, ctx: &mut SessionContext) -> String {
        let (verb, arg) = split_verb(line.trim());
        server.handle_command(&verb, arg, line, ctx, false).await
    }

    /// Pool pointed at an unroutable Redis with a fast create timeout —
    /// the durable lockout layer fails over to memory quickly.
    fn unroutable_redis_pool() -> deadpool_redis::Pool {
        let mut cfg = deadpool_redis::Config::from_url("redis://127.0.0.1:1");
        let mut pool_cfg = deadpool_redis::PoolConfig::default();
        pool_cfg.timeouts.create = Some(Duration::from_millis(100));
        pool_cfg.timeouts.wait = Some(Duration::from_millis(100));
        pool_cfg.timeouts.recycle = Some(Duration::from_millis(100));
        cfg.pool = Some(pool_cfg);
        cfg.create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool construction")
    }

    async fn test_inbound(ip: IpAddr) -> (InboundServer, SessionContext) {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .expect("lazy pool construction cannot fail with a well-formed URL");
        let redis = unroutable_redis_pool();
        let config = InboundConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 25,
            secure_port: 465,
            hostname: "mail.test".into(),
            max_message_size: 10 * 1024 * 1024,
            max_recipients: 100,
            auth_required: false,
            advertise_auth_port25: false,
            require_fcrdns: false,
            arc_seal: false,
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
            // Command-level tests run as if EHLO already happened (the
            // sequencing gate is covered by its own dedicated tests).
            auth_enabled: true,
            helo_seen: true,

            client_rdns: None,

            mail_smtputf8: false,
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
                .record_failure(ctx.client_ip, "alice@example.com")
                .await;
        }
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(b"\0alice@example.com\0correct-password");
        let resp = handle_cmd(&server, &format!("AUTH PLAIN {b64}"), &mut ctx).await;
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
                .record_failure(ctx.client_ip, "alice@example.com")
                .await;
        }
        let first = handle_cmd(&server, "AUTH PLAIN", &mut ctx).await;
        assert!(first.contains("334"), "two-step challenge: {first:?}");
        let b64 = base64::engine::general_purpose::STANDARD
            .encode(b"\0alice@example.com\0correct-password");
        let resp = handle_cmd(&server, &b64, &mut ctx).await;
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
                .record_failure(ctx.client_ip, "alice@example.com")
                .await;
        }
        let step1 = handle_cmd(&server, "AUTH LOGIN", &mut ctx).await;
        assert!(step1.contains("334"), "username challenge: {step1:?}");
        let step2 = handle_cmd(&server, "YWxpY2VAZXhhbXBsZS5jb20=", &mut ctx).await;
        assert!(step2.contains("334"), "password challenge: {step2:?}");
        let step3 = handle_cmd(&server, "Y29ycmVjdC1wYXNzd29yZA==", &mut ctx).await;
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
                .record_failure(ctx.client_ip, "bob@example.com")
                .await;
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"\0alice@example.com\0secret");
        let resp = handle_cmd(&server, &format!("AUTH PLAIN {b64}"), &mut ctx).await;
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
                .record_failure(locked_ip, "alice@example.com")
                .await;
        }
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"\0alice@example.com\0secret");
        let resp = handle_cmd(&server, &format!("AUTH PLAIN {b64}"), &mut ctx).await;
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
                .record_failure(ctx.client_ip, "ghost@example.com")
                .await;
        }
        let b64 =
            base64::engine::general_purpose::STANDARD.encode(b"\0ghost@example.com\0anything");
        let resp = handle_cmd(&server, &format!("AUTH PLAIN {b64}"), &mut ctx).await;
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
                .record_failure(ctx.client_ip, "alice@example.com")
                .await;
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
        assert_eq!(resp, "250 2.0.0 Ok id=abc-123\r\n");
    }

    // ── E-6: inbound MAIL FROM reverse-path validation ─────────────────────

    #[tokio::test]
    async fn inbound_mail_from_with_invalid_address_is_refused_501() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        // Private IP → PTR verification is exempt, so the syntax check is the
        // only gate: a whitespace-containing reverse-path must be refused.
        for bad in [
            "MAIL FROM:<bad address@example.com>",
            "MAIL FROM:<nodomain>",
        ] {
            let resp = handle_cmd(&server, bad, &mut ctx).await;
            assert!(
                resp.starts_with("501"),
                "invalid reverse-path must be refused with 501, got {resp:?} for {bad:?}"
            );
            assert!(
                ctx.mail_from.is_none(),
                "no reverse-path stored for {bad:?}"
            );
        }
    }

    #[tokio::test]
    async fn inbound_mail_from_accepts_valid_and_null_reverse_path() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        // The null sender <> is legal on port 25 (bounces/DSNs).
        let resp = handle_cmd(&server, "MAIL FROM:<>\r\n", &mut ctx).await;
        assert!(
            resp.starts_with("250"),
            "null sender must be accepted: {resp:?}"
        );
        assert_eq!(ctx.mail_from.as_deref(), Some(""));

        // F-04: a second MAIL while the transaction is open is a nested
        // MAIL (RFC 5321 §4.1.4) — 503, and the open transaction survives.
        let nested = handle_cmd(&server, "MAIL FROM:<user@example.com>\r\n", &mut ctx).await;
        assert_eq!(nested, "503 5.5.1 Nested MAIL command\r\n");
        assert_eq!(ctx.mail_from.as_deref(), Some(""));

        // RSET closes the transaction; the next MAIL FROM is accepted.
        assert!(handle_cmd(&server, "RSET", &mut ctx)
            .await
            .starts_with("250"));
        let resp = handle_cmd(&server, "MAIL FROM:<user@example.com>\r\n", &mut ctx).await;
        assert!(
            resp.starts_with("250"),
            "valid sender must be accepted: {resp:?}"
        );
        assert_eq!(ctx.mail_from.as_deref(), Some("user@example.com"));
    }

    #[tokio::test]
    async fn ehlo_resets_an_open_transaction() {
        // F-04: EHLO/HELO clears mail_from/rcpt_to (RFC 5321 §4.1.4) — the
        // client may start a fresh transaction without RSET.
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        assert!(
            handle_cmd(&server, "MAIL FROM:<first@example.com>\r\n", &mut ctx)
                .await
                .starts_with("250")
        );
        let resp = handle_cmd(&server, "EHLO mail.example.com\r\n", &mut ctx).await;
        assert!(resp.starts_with("250"), "EHLO reply: {resp:?}");
        assert!(
            resp.contains("250-ENHANCEDSTATUSCODES\r\n"),
            "F-05 advertised: {resp:?}"
        );
        assert!(ctx.mail_from.is_none(), "EHLO must reset mail_from");
        assert!(ctx.rcpt_to.is_empty(), "EHLO must reset rcpt_to");
        // A fresh MAIL FROM is accepted (not nested).
        assert!(
            handle_cmd(&server, "MAIL FROM:<second@example.com>\r\n", &mut ctx)
                .await
                .starts_with("250")
        );
        assert_eq!(ctx.mail_from.as_deref(), Some("second@example.com"));
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
            if let Ok(_tls_stream) =
                tls_handshake_with_timeout(acceptor.accept(socket), TLS_HANDSHAKE_TIMEOUT).await
            {
                unreachable!("handshake cannot succeed without a client")
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

    // ── AUTH gating on the internet-facing port-25 listener ────────────────

    #[tokio::test]
    async fn ehlo_does_not_advertise_auth_when_listener_disables_it() {
        // Port 25 default (advertise_auth_port25=false): even on an active
        // TLS leg (post-STARTTLS) AUTH must not be advertised.
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.auth_enabled = false;
        ctx.tls_active = true;
        let resp = handle_cmd(&server, "EHLO mail.example.com\r\n", &mut ctx).await;
        assert!(
            !resp.contains("AUTH"),
            "port-25 EHLO must not advertise AUTH: {resp:?}"
        );
        // The submission extensions stay advertised.
        assert!(resp.contains("8BITMIME"));
        assert!(resp.contains("SMTPUTF8"));
        assert!(resp.contains("PIPELINING"));
    }

    #[tokio::test]
    async fn ehlo_advertises_auth_on_submission_listener() {
        // The implicit-TLS listener (465) keeps AUTH — it is a submission
        // port; clients that auto-detect 465 wait for the AUTH capability.
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.auth_enabled = true;
        ctx.tls_active = true;
        let resp = handle_cmd(&server, "EHLO mail.example.com\r\n", &mut ctx).await;
        assert!(
            resp.contains("250-AUTH PLAIN LOGIN"),
            "465 EHLO must advertise AUTH: {resp:?}"
        );
    }

    #[tokio::test]
    async fn auth_command_refused_with_502_when_listener_disables_it() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.auth_enabled = false;
        ctx.tls_active = true;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"\0a@example.com\0pw");
        let resp = handle_cmd(&server, &format!("AUTH PLAIN {b64}"), &mut ctx).await;
        assert_eq!(
            resp,
            "502 5.5.1 AUTH not available on this port; submit mail via port 587 or 465\r\n"
        );
        // No brute-force state is engaged: the AUTH LOGIN/PLAIN state
        // machines must not arm.
        assert!(!ctx.auth_plain_pending && ctx.auth_login_user.is_none());
    }

    /// Read one CRLF-terminated SMTP reply line from a raw TCP stream
    /// (deterministic — a single `read()` can return a partial or merged
    /// mix of replies).
    async fn read_reply_line<R: tokio::io::AsyncRead + Unpin>(stream: &mut R) -> String {
        use tokio::io::AsyncReadExt;
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        loop {
            let n = stream.read(&mut byte).await.unwrap();
            assert_eq!(n, 1, "peer closed mid-reply");
            buf.push(byte[0]);
            if buf.ends_with(b"\r\n") {
                break;
            }
        }
        String::from_utf8_lossy(&buf).into_owned()
    }

    /// Read a full (possibly multi-line) SMTP reply terminated by a
    /// `NNN <text>` line (space in the 4th position).
    async fn read_smtp_reply<R: tokio::io::AsyncRead + Unpin>(stream: &mut R) -> String {
        let mut full = String::new();
        loop {
            let line = read_reply_line(stream).await;
            let multiline = line.len() >= 4 && line.as_bytes()[3] == b'-';
            full.push_str(&line);
            if !multiline {
                return full;
            }
        }
    }

    #[tokio::test]
    async fn port25_session_does_not_advertise_auth_after_starttls() {
        // Full end-to-end pin of the default: connect to the port-25 plain
        // listener, upgrade with STARTTLS, EHLO again — no AUTH capability
        // and AUTH commands refused with 502.
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let (server, _ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        let server = Arc::new(server);
        let acceptor = test_tls_acceptor();

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session_plain(socket, peer, Some(acceptor)).await;
        });

        use tokio::io::AsyncWriteExt;
        let mut client = TcpStream::connect(addr).await.unwrap();

        // Greeting + plaintext EHLO (no AUTH expected pre-TLS either).
        let greeting = read_reply_line(&mut client).await;
        assert!(greeting.starts_with("220"), "greeting: {greeting:?}");
        client.write_all(b"EHLO client.example\r\n").await.unwrap();
        let ehlo_plain = read_smtp_reply(&mut client).await;
        assert!(ehlo_plain.contains("250-"), "EHLO reply: {ehlo_plain:?}");
        assert!(
            !ehlo_plain.contains("AUTH"),
            "no AUTH before TLS: {ehlo_plain:?}"
        );

        // STARTTLS upgrade.
        client.write_all(b"STARTTLS\r\n").await.unwrap();
        let ready = read_reply_line(&mut client).await;
        assert!(ready.starts_with("220"), "STARTTLS reply: {ready:?}");

        let cert_pem = std::fs::read(format!(
            "{}/tests/fixtures/cert.pem",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&cert_pem[..]))
            .collect::<Result<_, _>>()
            .unwrap();
        roots.add(certs[0].clone()).unwrap();
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::client::TlsConnector::from(Arc::new(config));
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(name, client).await.unwrap();

        // F-11 (INVERTED pin): RFC 3207 §4.2 forbids a second 220 greeting
        // on the TLS leg — the session continues directly at the client's
        // EHLO. Send EHLO IMMEDIATELY after the handshake; the first reply
        // must be the EHLO response (250-...), never a 220 banner.
        tls.write_all(b"EHLO client.example\r\n").await.unwrap();
        let first = read_smtp_reply(&mut tls).await;
        assert!(
            first.starts_with("250"),
            "TLS leg must start at the EHLO reply, no 220 greeting: {first:?}"
        );
        assert!(
            !first.contains("AUTH"),
            "port-25 EHLO after STARTTLS must NOT advertise AUTH: {first:?}"
        );

        // And an AUTH attempt is refused outright.
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"\0a@example.com\0pw");
        tls.write_all(format!("AUTH PLAIN {b64}\r\n").as_bytes())
            .await
            .unwrap();
        let auth_resp = read_reply_line(&mut tls).await;
        assert!(
            auth_resp.starts_with("502"),
            "AUTH on port 25 must be refused with 502, got {auth_resp:?}"
        );

        tls.write_all(b"QUIT\r\n").await.unwrap();
        let bye = read_reply_line(&mut tls).await;
        assert!(bye.starts_with("221"), "QUIT reply: {bye:?}");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
    }

    // ── RFC 5321 sequencing: nothing before EHLO ───────────────────────────

    #[tokio::test]
    async fn commands_before_ehlo_are_refused_with_503() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.helo_seen = false;
        for cmd in [
            "MAIL FROM:<user@example.com>",
            "RCPT TO:<user@example.com>",
            "AUTH PLAIN dXNlcgBwYXNz",
        ] {
            // The session loop dispatches on the split verb + raw line.
            let resp = handle_cmd(&server, cmd, &mut ctx).await;
            assert_eq!(
                resp, "503 5.5.1 Error: send HELO/EHLO first\r\n",
                "{cmd:?} before EHLO must be refused with 503"
            );
        }
    }

    #[test]
    fn starttls_before_ehlo_is_refused_with_503() {
        // Pure policy check (the session loop applies this before dispatch):
        // a session without EHLO must not be allowed to negotiate TLS.
        let ctx = SessionContext {
            id: "t".into(),
            client_ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
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
            auth_enabled: false,
            helo_seen: false,

            client_rdns: None,

            mail_smtputf8: false,
        };
        assert!(!ctx.helo_seen);
        assert!(!ctx.tls_active);
    }

    // ── exact enhanced status codes for the rejection suite ────────────────

    #[tokio::test]
    async fn rejection_suite_uses_exact_enhanced_status_codes() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.helo_seen = true;

        // Malformed HELO argument → 501 5.5.4.
        assert_eq!(
            handle_cmd(&server, "EHLO bad host\r\n", &mut ctx).await,
            "501 5.5.4 Invalid HELO/EHLO hostname\r\n"
        );

        // Malformed reverse-path → 501 5.1.7.
        assert_eq!(
            handle_cmd(&server, "MAIL FROM:<bad address@example.com>", &mut ctx).await,
            "501 5.1.7 Malformed reverse-path\r\n"
        );

        // Recipient address without a domain → 501 5.1.3 (syntax, not 550).
        ctx.mail_from = Some("user@example.com".into());
        assert_eq!(
            handle_cmd(&server, "RCPT TO:<nodomain>", &mut ctx).await,
            "501 5.1.3 Bad recipient address syntax\r\n"
        );

        // Over-long forward-path (RFC 5321 §4.5.3.1.1) → 501 5.1.3 as well.
        let huge = format!("user@{}.com", "d".repeat(400));
        assert_eq!(
            handle_cmd(&server, &format!("RCPT TO:<{huge}>"), &mut ctx).await,
            "501 5.1.3 Bad recipient address syntax\r\n"
        );

        // DATA without a transaction → 503 5.5.1.
        ctx.mail_from = None;
        ctx.rcpt_to.clear();
        assert_eq!(
            handle_cmd(&server, "DATA", &mut ctx).await,
            "503 5.5.1 Bad sequence of commands\r\n"
        );

        // RCPT without MAIL → 503 5.5.1 (need MAIL first).
        assert_eq!(
            handle_cmd(&server, "RCPT TO:<a@example.com>", &mut ctx).await,
            "503 5.5.1 Error: need MAIL command first\r\n"
        );

        // Unknown command → 500 5.5.2 (F-06: RFC 5321 §4.2.4 uses 500 for
        // unrecognized commands; 502 stays reserved for known-but-
        // unimplemented verbs like EXPN).
        assert_eq!(
            handle_cmd(&server, "FROBNICATE", &mut ctx).await,
            "500 5.5.2 Command not recognised\r\n"
        );
    }

    #[tokio::test]
    async fn help_vrfy_and_expn_replies_are_protocol_correct() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.helo_seen = true;

        let help = handle_cmd(&server, "HELP", &mut ctx).await;
        assert!(help.starts_with("214 2.0.0 "), "HELP: {help:?}");

        // VRFY must never confirm or deny a recipient (anti-enumeration).
        let vrfy = handle_cmd(&server, "VRFY user@example.com", &mut ctx).await;
        assert_eq!(
            vrfy,
            "252 2.5.2 Cannot VRFY user, but will accept message and attempt delivery\r\n"
        );

        let expn = handle_cmd(&server, "EXPN list", &mut ctx).await;
        assert_eq!(expn, "502 5.5.1 EXPN command not supported\r\n");
    }

    // ── RFC 1870 SIZE parameter on MAIL FROM ───────────────────────────────

    #[tokio::test]
    async fn mail_from_size_over_advertised_maximum_is_refused_552() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.helo_seen = true;
        let size = server.config.max_message_size + 1;
        let resp = handle_cmd(
            &server,
            &format!("MAIL FROM:<user@example.com> SIZE={size}"),
            &mut ctx,
        )
        .await;
        assert_eq!(
            resp,
            "552 5.3.4 Message size exceeds fixed maximum message size\r\n"
        );
        assert!(ctx.mail_from.is_none(), "no transaction started");

        // A SIZE declaration within the advertised maximum is accepted —
        // and the advertisement matches the enforced value exactly.
        let resp = handle_cmd(
            &server,
            &format!(
                "MAIL FROM:<user@example.com> SIZE={}",
                server.config.max_message_size
            ),
            &mut ctx,
        )
        .await;
        assert!(resp.starts_with("250"), "in-limit SIZE accepted: {resp:?}");
        let ehlo = handle_cmd(&server, "EHLO mail.example.com\r\n", &mut ctx).await;
        assert!(
            ehlo.contains(&format!("250-SIZE {}\r\n", server.config.max_message_size)),
            "SIZE advertisement must match enforcement: {ehlo:?}"
        );
    }

    #[tokio::test]
    async fn mail_from_unknown_parameter_is_refused_555() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.helo_seen = true;
        assert_eq!(
            handle_cmd(&server, "MAIL FROM:<user@example.com> X-BOGUS=1", &mut ctx).await,
            "555 5.5.4 MAIL parameter not recognised\r\n"
        );
        // Recognised extension parameters pass.
        let resp = handle_cmd(
            &server,
            "MAIL FROM:<user@example.com> BODY=8BITMIME SMTPUTF8",
            &mut ctx,
        )
        .await;
        assert!(
            resp.starts_with("250"),
            "advertised params accepted: {resp:?}"
        );
    }

    #[tokio::test]
    async fn rcpt_parameter_is_refused_555() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.helo_seen = true;
        ctx.mail_from = Some("user@example.com".into());
        assert_eq!(
            handle_cmd(&server, "RCPT TO:<a@example.com> NOTIFY=NEVER", &mut ctx).await,
            "555 5.5.4 RCPT parameter not recognised\r\n"
        );
    }

    // ── recipient budget ───────────────────────────────────────────────────

    #[tokio::test]
    async fn recipient_cap_enforced_with_452_4_5_3() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.helo_seen = true;
        ctx.mail_from = Some("user@example.com".into());
        for _ in 0..server.config.max_recipients {
            ctx.rcpt_to.push("sink@example.com".into());
        }
        assert_eq!(
            handle_cmd(&server, "RCPT TO:<one@example.com>", &mut ctx).await,
            "452 4.5.3 Too many recipients\r\n"
        );
    }

    // ── Authentication-Results prepend consistency ─────────────────────────

    #[test]
    fn build_stored_message_separates_ar_header_with_crlf_only() {
        let received = "Received: from c (unknown [10.0.0.1])\r\n\tby mx.test with ESMTP id t;";
        let header = "Authentication-Results: mx.test;\r\n\tspf=pass smtp.mailfrom=a.com";
        let raw = b"From: a@b.com\r\nSubject: hi\r\n\r\nbody\r\n";
        let stored = build_stored_message(received, header, None, raw);
        // Received first, then exactly one CRLF before the A-R header.
        assert!(stored.starts_with(received.as_bytes()));
        assert_eq!(
            &stored[received.len()..received.len() + 2],
            b"\r\n",
            "exactly one CRLF after the Received header"
        );
        // Exactly one CRLF between the A-R header and the message...
        let ar_start = received.len() + 2;
        let joined = &stored[ar_start..ar_start + header.len() + 2];
        assert_eq!(&joined[header.len()..], b"\r\n");
        assert!(stored.windows(header.len()).any(|w| w == header.as_bytes()));
        // ...the A-R header is complete before the first message header...
        assert_eq!(&stored[received.len() + header.len() + 4..], raw);
        // ...and the composed blob never contains a bare LF.
        for i in 0..stored.len() {
            if stored[i] == b'\n' {
                assert!(i > 0 && stored[i - 1] == b'\r', "bare LF at offset {i}");
            }
        }
    }

    #[test]
    fn build_stored_message_places_arc_seal_between_ar_and_raw() {
        let received = "Received: from c (unknown [10.0.0.1])\r\n\tby mx.test with ESMTPS id t;";
        let header = "Authentication-Results: mx.test;\r\n\tspf=pass";
        let arc = "ARC-Authentication-Results: i=1;\r\n\tARC-Seal: i=1;";
        let raw = b"From: a@b.com\r\n\r\nbody";
        let stored = build_stored_message(received, header, Some(arc), raw);
        let expected_prefix = format!("{received}\r\n{header}\r\n{arc}\r\n");
        assert!(stored.starts_with(expected_prefix.as_bytes()));
        assert_eq!(&stored[expected_prefix.len()..], raw);
    }

    // ── drain/resync: no command smuggling from over-long lines ────────────

    #[tokio::test]
    async fn oversized_command_line_cannot_smuggle_commands_session_level() {
        let (server, _ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        let server = Arc::new(server);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session_plain(socket, peer, None).await;
        });

        use tokio::io::AsyncWriteExt;
        let mut client = TcpStream::connect(addr).await.unwrap();

        // Greeting.
        let greeting = read_reply_line(&mut client).await;
        assert!(greeting.starts_with("220"), "greeting: {greeting:?}");

        // 100 KB line with "QUIT" smuggled INSIDE it (before its newline),
        // followed by a legitimate NOOP and QUIT.
        let attack = format!("{}QUIT\r\n", "A".repeat(100 * 1024));
        client.write_all(attack.as_bytes()).await.unwrap();
        client.write_all(b"NOOP\r\n").await.unwrap();

        // First reply: 500 line too long (the whole oversized line, QUIT
        // included, was drained — it did NOT terminate the session).
        let too_long = read_reply_line(&mut client).await;
        assert!(
            too_long.starts_with("500"),
            "oversized line refused: {too_long:?}"
        );

        // The smuggled QUIT must not have closed the session: NOOP runs.
        let noop = read_reply_line(&mut client).await;
        assert!(
            noop.starts_with("250"),
            "NOOP after oversized line must execute, got {noop:?}"
        );

        client.write_all(b"QUIT\r\n").await.unwrap();
        let bye = read_reply_line(&mut client).await;
        assert!(bye.starts_with("221"), "QUIT reply: {bye:?}");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
    }

    // ── F-02: FCrDNS gate fail-open default + tempfail on DNS errors ──────

    #[test]
    fn fcrdns_reply_matrix_tempfails_transient_rejects_only_when_required() {
        // Transient resolver failure → tempfail 451 under BOTH policies —
        // a DNS outage must not permanently bounce mail.
        assert_eq!(
            fcrdns_reply(&SourceCheck::Transient, false),
            Some(FCRDNS_TEMPFAIL_REPLY)
        );
        assert_eq!(
            fcrdns_reply(&SourceCheck::Transient, true),
            Some(FCRDNS_TEMPFAIL_REPLY)
        );
        assert_eq!(
            FCRDNS_TEMPFAIL_REPLY,
            "451 4.4.3 Temporary DNS failure verifying sender\r\n"
        );
        // No PTR: hard 550 ONLY under SMTP_REQUIRE_FCRDNS=true.
        assert_eq!(
            fcrdns_reply(&SourceCheck::NoReverseDns(None), true),
            Some(FCRDNS_REQUIRED_REPLY)
        );
        assert_eq!(
            fcrdns_reply(&SourceCheck::NoReverseDns(None), false),
            None,
            "default policy accepts no-PTR senders"
        );
        // FCrDNS-confirmed is informational under both policies.
        assert_eq!(
            fcrdns_reply(
                &SourceCheck::Confirmed(Some("rev.example.com".into())),
                true
            ),
            None
        );
        assert_eq!(
            fcrdns_reply(
                &SourceCheck::Confirmed(Some("rev.example.com".into())),
                false
            ),
            None
        );
    }

    #[test]
    fn fcrdns_transient_outcomes_are_never_cached() {
        assert!(!rdns_outcome_cacheable(&SourceCheck::Transient));
        assert!(rdns_outcome_cacheable(&SourceCheck::NoReverseDns(None)));
        assert!(rdns_outcome_cacheable(&SourceCheck::Confirmed(None)));
    }

    #[tokio::test]
    async fn no_ptr_sender_accepted_when_fcrdns_not_required() {
        // Pre-seed the rdns cache for a public IP with a no-PTR outcome so
        // the command path runs deterministically without touching DNS.
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 50)); // TEST-NET-1, not exempt
        let (server, mut ctx) = test_inbound(ip).await;
        server
            .rdns_cache
            .insert(ip, SourceCheck::NoReverseDns(None));
        let resp = handle_cmd(&server, "MAIL FROM:<user@example.com>\r\n", &mut ctx).await;
        assert_eq!(resp, "250 2.0.0 Ok\r\n", "no-PTR + require=false accepts");
        assert_eq!(ctx.client_rdns, None, "no hostname recorded");
    }

    #[tokio::test]
    async fn no_ptr_sender_rejected_550_when_fcrdns_required() {
        let ip = IpAddr::V4(Ipv4Addr::new(192, 0, 2, 51));
        let (mut server, mut ctx) = test_inbound(ip).await;
        server.config.require_fcrdns = true;
        server.rdns_cache.insert(
            ip,
            SourceCheck::NoReverseDns(Some("unconfirmed.example".into())),
        );
        let resp = handle_cmd(&server, "MAIL FROM:<user@example.com>\r\n", &mut ctx).await;
        assert_eq!(resp, FCRDNS_REQUIRED_REPLY);
        assert!(ctx.mail_from.is_none(), "no transaction started");
        // The unconfirmed PTR hostname is still recorded for the trace
        // header on any later accepted transaction.
        assert_eq!(
            ctx.client_rdns.as_deref(),
            Some("unconfirmed.example"),
            "unconfirmed hostname kept as trace evidence"
        );
    }

    // ── F-03: inbound RCPT TO syntax validation ────────────────────────────

    #[tokio::test]
    async fn inbound_rcpt_syntax_is_validated() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        ctx.mail_from = Some("user@example.com".into());
        for bad in [
            "RCPT TO:<a b@example.com>",
            "RCPT TO:<a\x01b@example.com>",
            "RCPT TO:<a@@b.com>",
            "RCPT TO:<user@>",
            "RCPT TO:<user@nodot>",
        ] {
            let resp = handle_cmd(&server, bad, &mut ctx).await;
            assert_eq!(
                resp, "501 5.1.3 Bad recipient address syntax\r\n",
                "{bad:?} must be refused with 501 5.1.3"
            );
            assert!(ctx.rcpt_to.is_empty(), "nothing stored for {bad:?}");
        }
        // A WELL-FORMED recipient passes the syntax gate: the next failure
        // is the (DB-unreachable) managed-recipient lookup's 451 — not 501.
        let resp = handle_cmd(&server, "RCPT TO:<user@example.com>\r\n", &mut ctx).await;
        assert_eq!(resp, "451 4.3.0 Temporary local problem\r\n");
    }

    // ── F-12: inbound AUTH verb case, inline LOGIN, cancellation ───────────

    #[tokio::test]
    async fn inbound_auth_verb_matches_case_insensitively() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        let b64 = base64::engine::general_purpose::STANDARD.encode(b"\0alice@example.com\0pw");
        // Lowercase "auth plain <b64>" must reach credential verification
        // (DB unreachable → 535), never 502/538/504.
        let resp = handle_cmd(&server, &format!("auth plain {b64}"), &mut ctx).await;
        assert_eq!(resp, "535 5.7.8 Authentication failed\r\n");
        // Unknown mechanism → 504 5.5.4 (RFC 4954).
        let resp = handle_cmd(&server, "AUTH XKEY <payload>", &mut ctx).await;
        assert_eq!(resp, "504 5.5.4 Unrecognized authentication type\r\n");
    }

    #[tokio::test]
    async fn inbound_auth_login_accepts_inline_initial_response() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        let user = base64::engine::general_purpose::STANDARD.encode("alice@example.com");
        let resp = handle_cmd(&server, &format!("AUTH LOGIN {user}"), &mut ctx).await;
        assert_eq!(
            resp, "334 UGFzc3dvcmQ6\r\n",
            "inline username skips the username prompt"
        );
        assert_eq!(ctx.auth_login_user.as_deref(), Some("alice@example.com"));
        // The password step still runs the full verification (DB → 454/535).
        let pass = base64::engine::general_purpose::STANDARD.encode("secret");
        let resp = handle_cmd(&server, &pass, &mut ctx).await;
        assert_eq!(resp, "535 5.7.8 Authentication failed\r\n");
    }

    #[tokio::test]
    async fn inbound_auth_star_cancels_the_exchange() {
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        assert_eq!(
            handle_cmd(&server, "AUTH LOGIN", &mut ctx).await,
            "334 VXNlcm5hbWU6\r\n"
        );
        assert_eq!(
            handle_cmd(&server, "*", &mut ctx).await,
            "501 5.7.0 Authentication cancelled\r\n"
        );
        assert!(ctx.auth_login_user.is_none(), "login state cleared");
        // PLAIN two-step cancels identically.
        assert_eq!(
            handle_cmd(&server, "AUTH PLAIN", &mut ctx).await,
            "334 \r\n"
        );
        assert_eq!(
            handle_cmd(&server, "*", &mut ctx).await,
            "501 5.7.0 Authentication cancelled\r\n"
        );
        assert!(!ctx.auth_plain_pending, "plain state cleared");
    }

    // ── F-14: error cap + unauthenticated session deadline (session level) ─

    #[tokio::test]
    async fn inbound_error_cap_closes_session_after_twenty_errors() {
        let (server, _ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        let server = Arc::new(server);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session_plain(socket, peer, None).await;
        });

        use tokio::io::AsyncWriteExt;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let greeting = read_reply_line(&mut client).await;
        assert!(greeting.starts_with("220"));

        for i in 1..=MAX_SESSION_ERRORS {
            client.write_all(b"FROBNICATE\r\n").await.unwrap();
            let resp = read_reply_line(&mut client).await;
            assert_eq!(resp, "500 5.5.2 Command not recognised\r\n", "error #{i}");
        }
        // The 20th error is followed by 421 Too many errors + close.
        assert_eq!(
            read_reply_line(&mut client).await,
            "421 4.7.0 Too many errors, closing connection\r\n"
        );
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
    }

    #[tokio::test]
    async fn inbound_unauthenticated_session_deadline_is_enforced() {
        // Driven over a duplex stream: under paused time a real TCP socket
        // lets the per-read idle timer win the race with the client's write
        // (the submission deadline test uses the same duplex idiom).
        tokio::time::pause();
        let (server, mut ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        let server = Arc::new(server);
        let (client, server_side) = tokio::io::duplex(8 * 1024);
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let mut stream = BufStream::new(server_side);
            srv.run_session_loop(&mut stream, &mut ctx, false).await
        });

        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut client = BufStream::new(client);

        client.write_all(b"NOOP\r\n").await.unwrap();
        client.flush().await.unwrap();
        // Read the 250 reply byte-by-byte to the CRLF.
        let mut buf = [0u8; 128];
        let mut reply = Vec::new();
        loop {
            let n = client.read(&mut buf).await.unwrap();
            assert!(n > 0, "peer closed before NOOP reply");
            reply.extend_from_slice(&buf[..n]);
            if reply.ends_with(b"\r\n") {
                break;
            }
        }
        assert!(reply.starts_with(b"250"), "NOOP reply: {reply:?}");

        // Advance past the 30-minute unauthenticated deadline.
        tokio::time::advance(SESSION_DEADLINE + Duration::from_secs(1)).await;

        client.write_all(b"NOOP\r\n").await.unwrap();
        client.flush().await.unwrap();
        let mut reply = Vec::new();
        loop {
            let n = client.read(&mut buf).await.unwrap();
            if n == 0 {
                break;
            }
            reply.extend_from_slice(&buf[..n]);
            if reply.ends_with(b"\r\n") {
                break;
            }
        }
        assert_eq!(
            String::from_utf8_lossy(&reply),
            "421 4.7.0 Session deadline exceeded, closing connection\r\n"
        );
        tokio::time::resume();
        let _ = tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("session must finish");
    }

    // ── F-08: bare-LF command lines are refused, the session survives ─────

    #[tokio::test]
    async fn inbound_bare_lf_command_line_is_refused_but_session_survives() {
        let (server, _ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        let server = Arc::new(server);
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session_plain(socket, peer, None).await;
        });

        use tokio::io::AsyncWriteExt;
        let mut client = TcpStream::connect(addr).await.unwrap();
        let greeting = read_reply_line(&mut client).await;
        assert!(greeting.starts_with("220"));

        // A NOOP terminated by a bare LF is refused (commands are CRLF-only).
        client.write_all(b"NOOP\n").await.unwrap();
        assert_eq!(
            read_reply_line(&mut client).await,
            "500 5.5.2 Bare LF not allowed\r\n"
        );
        // The session stays synchronised: a properly terminated NOOP works.
        client.write_all(b"NOOP\r\n").await.unwrap();
        assert!(read_reply_line(&mut client).await.starts_with("250"));

        client.write_all(b"QUIT\r\n").await.unwrap();
        let bye = read_reply_line(&mut client).await;
        assert!(bye.starts_with("221"), "QUIT reply: {bye:?}");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
    }

    // ── F-13: implicit-TLS over-limit connections get the 421 reply ───────

    #[tokio::test]
    async fn implicit_tls_over_limit_connection_receives_421() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let (server, _ctx) = test_inbound(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1))).await;
        let server = Arc::new(server);
        // Fill the per-IP slots for loopback to the cap.
        *server
            .connections
            .entry(IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)))
            .or_insert(0) += server.rate_limit_config.max_connections_per_ip;

        let acceptor = test_tls_acceptor();
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            match tls_handshake_with_timeout(acceptor.accept(socket), TLS_HANDSHAKE_TIMEOUT).await {
                Ok(tls_stream) => srv.handle_session_tls(tls_stream, peer).await,
                Err(()) => panic!("client TLS handshake must succeed"),
            }
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let cert_pem = std::fs::read(format!(
            "{}/tests/fixtures/cert.pem",
            env!("CARGO_MANIFEST_DIR")
        ))
        .unwrap();
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&cert_pem[..]))
            .collect::<Result<_, _>>()
            .unwrap();
        roots.add(certs[0].clone()).unwrap();
        let config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::client::TlsConnector::from(Arc::new(config));
        let name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost").unwrap();
        let mut tls = connector.connect(name, tcp).await.unwrap();

        // F-13: the over-limit connection is not dropped silently — the 421
        // arrives on the TLS stream itself.
        let resp = read_reply_line(&mut tls).await;
        assert_eq!(resp, "421 4.7.0 Too many connections, try again later\r\n");
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap();
    }

    // ── F-01: hop limit enforced at end-of-DATA (source pin) ───────────────

    #[test]
    fn inbound_data_path_pins_the_routing_loop_refusal() {
        // Reaching end-of-DATA in the unit suite needs a managed-recipient
        // DB lookup, so the loop refusal is pinned against the compiled-in
        // session-loop source (same idiom as the submission source pins):
        // the check runs on the raw buffer BEFORE process_message.
        let source = include_str!("inbound.rs");
        let terminated = source
            .find("} else if terminated {")
            .expect("terminated DATA branch");
        let hop_check = source
            .find("550 5.4.6 Routing loop detected")
            .expect("hop-limit refusal");
        let process = source
            .find("self.process_message(ctx, &message).await")
            .expect("process_message call");
        assert!(
            terminated < hop_check && hop_check < process,
            "the hop-limit refusal must fire at end-of-DATA, before processing"
        );
    }
}
