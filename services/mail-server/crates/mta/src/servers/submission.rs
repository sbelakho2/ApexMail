//! SMTP Submission server – accepts authenticated mail on port 587 for relaying.
//!
//! Supports AUTH PLAIN and AUTH LOGIN against the `users` table.
//! Supports STARTTLS when a TLS acceptor is provided.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dashmap::DashMap;
use mail_parser::{ContentType, HeaderName, HeaderValue};
use sqlx::PgPool;
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::{TlsAcceptor, TlsStream};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::auth::{verify_against_dummy, AuthError, AuthFailTracker};
use crate::config::{RateLimitConfig, SubmissionConfig};

use super::util::{
    build_received_header, is_mail_from_arg, is_rcpt_to_arg, is_strict_end_of_data,
    line_content_bytes, line_lossy, log_session_summary, log_smtp_reject, mail_size_param,
    mail_smtputf8_param, metric_message, read_line_capped, received_hop_limit_exceeded, split_verb,
    unstuff_dot_line_bytes, validate_mail_params, validate_rcpt_params, LineRead, LineTerminator,
    MailParamPolicy, MAX_COMMAND_LINE, MAX_DATA_LINE,
};

/// Per-read timeout for AUTH challenge/response lines (a silent client must
/// not hold the session forever).
const AUTH_LINE_TIMEOUT: Duration = Duration::from_secs(120);

/// Total deadline for receiving message DATA.
const DATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// Per-line timeout while receiving message DATA.
const DATA_LINE_TIMEOUT: Duration = Duration::from_secs(300);

/// F-14: number of 4xx/5xx replies after which the session is closed with
/// `421 4.7.0 Too many errors` (RFC 5321 §4.3.2 recommends a small limit).
const MAX_SESSION_ERRORS: u32 = 20;

/// F-14: hard wall-clock cap for an UNAUTHENTICATED session. Authenticated
/// sessions are bounded by the per-command idle timeout instead.
const SESSION_DEADLINE: Duration = Duration::from_secs(30 * 60);

/// Outcome of reading one DATA payload (see
/// [`SubmissionServer::read_data_message`]).
#[derive(Debug)]
enum ReadDataOutcome {
    /// A complete message terminated by strict `<CRLF>.<CRLF>`; body lines
    /// are dot-unstuffed and CRLF-normalized. The final line's CRLF belongs
    /// to the terminator and is not part of the payload.
    Message(Vec<u8>),
    /// A line exceeded the per-line cap or the message exceeded the size cap.
    TooLarge,
    /// The absolute line-drain limit was exceeded without a newline: the
    /// stream cannot be resynchronised — the connection must close.
    Overflow,
    /// Total or per-line deadline exceeded.
    TimedOut,
    /// Client disconnected / stream failed mid-DATA: partial payload discarded.
    Aborted,
}

/// Outcome of persisting a submitted message.
enum QueueOutcome {
    /// The message was inserted into `email_queue`.
    Queued,
    /// The MAIL FROM domain is not owned by the authenticated user's
    /// tenant — the message must be refused with `550 5.7.1`.
    SenderNotOwned,
    /// The sender belongs to the tenant but does not satisfy the unified
    /// current-domain readiness contract for the selected transport.
    SenderNotReady,
    /// Every recipient is on the tenant suppression list — refused with
    /// `550 5.1.1` (CAN-SPAM: the SMTP path must not bypass the list the
    /// REST send path enforces).
    RecipientSuppressed,
}

/// Why the queue write itself failed. Every constructor logs the CAUSE at
/// ERROR level before returning — the previously swallowed
/// `.map_err(|_| ())` sites answered 451 without leaving any trace of
/// WHICH statement failed, turning every queue outage into an
/// undiagnosable "Requested action aborted". The variant decides the
/// WHY the queue write failed matters: infrastructure failures are
/// transient (451, client retries); a malformed internally-generated id is
/// permanent (554).
enum QueueWriteFailure {
    /// Infrastructure failure (DB/pool/task): answer 451 so the client
    /// retries the message.
    Transient,
    /// This message can never be queued (internal invariant broken):
    /// answer 554 so the client does not retry.
    Permanent,
}

impl QueueWriteFailure {
    /// Log `cause` at ERROR and classify the failure as retryable
    /// infrastructure (451).
    fn transient(cause: impl std::fmt::Display, stage: &str) -> Self {
        tracing::error!(error = %cause, stage = stage, "Submission queue write failed (transient)");
        Self::Transient
    }

    /// Log `cause` at ERROR and classify the failure as permanent (554).
    fn permanent(cause: impl std::fmt::Display, stage: &str) -> Self {
        tracing::error!(error = %cause, stage = stage, "Submission queue write failed (permanent)");
        Self::Permanent
    }
}

/// Terminal outcome of one AUTH exchange (RFC 4954). Failing replies are
/// RETURNED, not written: the session loop emits them through `reply!` so
/// every 4xx/5xx counts toward the session error budget and is logged via
/// `log_smtp_reject` — a brute-forcer hammering AUTH disconnects after
/// MAX_SESSION_ERRORS attempts exactly like any other error source.
enum AuthOutcome {
    Success(String, Uuid),
    /// Terminal reply (already CRLF-terminated), to be emitted via `reply!`.
    Reply(&'static str),
    /// The transport died mid-exchange; no reply can be delivered.
    Silent,
}

/// One AUTH continuation line (see [`SubmissionServer::read_auth_line`]).
enum AuthLine {
    Payload(String),
    /// RFC 4954 §4: a lone `*` cancels the exchange.
    Cancelled,
    /// The continuation line exceeded the command-line cap (drained; the
    /// session stays synchronised).
    TooLong,
}

/// Terminal AUTH replies shared by both mechanisms. `&'static str` so they
/// can ride in [`AuthOutcome::Reply`] without allocation.
const AUTH_FAILED: &str = "535 5.7.8 Authentication failed\r\n";
const AUTH_LOCKED_OUT: &str = "454 4.7.0 Too many failed authentication attempts\r\n";
const AUTH_BAD_BASE64: &str = "501 5.5.2 Invalid base64\r\n";
const AUTH_CANCELLED: &str = "501 5.7.0 Authentication cancelled\r\n";
const AUTH_LINE_TOO_LONG: &str = "500 5.5.2 Line too long\r\n";

pub struct SubmissionServer {
    config: SubmissionConfig,
    rate_limit: RateLimitConfig,
    pool: PgPool,
    shutdown: Arc<Notify>,
    connections: Arc<DashMap<std::net::IpAddr, u32>>,
    /// Failed-AUTH lockout tracking. Backed by Redis when a pool is
    /// supplied (`with_redis`) so lockouts survive restarts and are shared
    /// across replicas; otherwise in-memory only.
    auth_fail_tracker: AuthFailTracker,
    tls_acceptor: Option<TlsAcceptor>,
}

impl SubmissionServer {
    pub fn new(
        config: SubmissionConfig,
        rate_limit: RateLimitConfig,
        pool: PgPool,
        redis: deadpool_redis::Pool,
        tls_acceptor: Option<TlsAcceptor>,
    ) -> Self {
        Self {
            config,
            rate_limit,
            pool,
            shutdown: Arc::new(Notify::new()),
            connections: Arc::new(DashMap::new()),
            auth_fail_tracker: AuthFailTracker::with_redis(redis),
            tls_acceptor,
        }
    }

    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await?;
        info!(addr = %addr, "Submission SMTP server listening (AUTH required, STARTTLS available)");

        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((socket, peer)) => {
                            let srv = self.clone();
                            tokio::spawn(async move {
                                srv.handle_session(socket, peer).await;
                            });
                        }
                        Err(e) => warn!(error = %e, "Submission accept error"),
                    }
                }
                _ = self.shutdown.notified() => break,
            }
        }
        Ok(())
    }

    pub fn stop(&self) {
        self.shutdown.notify_waiters();
    }

    // ── Session entry point (TCP → possibly upgrade to TLS) ──────────────

    async fn handle_session(self: Arc<Self>, socket: TcpStream, peer: SocketAddr) {
        let ip = peer.ip();

        // Admission control: per-IP connection cap (mirrors the inbound
        // server's gate; without it `connections` is tracked but never
        // enforced, so one IP may hold unlimited concurrent sessions). The
        // check and the slot increment are one atomic step — concurrent
        // connects cannot overshoot the cap.
        if self.rate_limit.enabled
            && !super::bounce::try_admit_connection(
                &self.connections,
                ip,
                self.rate_limit.max_connections_per_ip,
            )
        {
            let mut stream = BufStream::new(socket);
            let _ = write_line(
                &mut stream,
                "421 4.7.0 Too many connections from your IP\r\n",
            )
            .await;
            return;
        }

        // F-19: RAII slot guard (same pattern as the bounce server) — the
        // per-IP slot is released on EVERY exit path, early returns included.
        let _conn_guard = super::bounce::ConnGuard {
            conns: self.connections.clone(),
            ip,
        };

        let greeting = format!("220 {} ESMTP ApexMail Submission\r\n", self.config.hostname);
        let mut stream = BufStream::new(socket);
        if let Err(e) = write_line(&mut stream, &greeting).await {
            debug!(error = %e, peer = %peer, "Failed to send greeting");
            return;
        }

        let allow_starttls = self.tls_acceptor.is_some();
        let (starttls_requested, _msg_count) = self
            .run_session_loop(&mut stream, peer, allow_starttls, false)
            .await;

        if starttls_requested {
            if let Some(ref acceptor) = self.tls_acceptor {
                let _ = write_line(&mut stream, "220 Go ahead\r\n").await;
                let _ = stream.flush().await;
                let inner = stream.into_inner();
                match super::inbound::tls_handshake_with_timeout(
                    acceptor.accept(inner),
                    Duration::from_secs(30),
                )
                .await
                {
                    Ok(tls_stream) => {
                        let mut tls_buf = BufStream::new(TlsStream::from(tls_stream));
                        self.run_session_loop(&mut tls_buf, peer, false, true).await;
                    }
                    Err(()) => {
                        // M26: timed-out/failed handshake — socket is dropped
                        // and the connection slot released below.
                        debug!("STARTTLS handshake failed or timed out");
                    }
                }
            }
        }
    }

    // ── Generic session loop (works over TCP or TLS) ─────────────────────
    // Returns (starttls_requested, message_count).

    ///
    /// PIPELINING (RFC 2920): commands are read line-by-line from a buffered
    /// stream and each command's reply is flushed before the next line is
    /// parsed, so grouped commands get one reply each in order; the DATA
    /// `354` reply is flushed before body lines are consumed.
    async fn run_session_loop<S: AsyncRead + AsyncWrite + Unpin>(
        self: &Arc<Self>,
        stream: &mut BufStream<S>,
        peer: SocketAddr,
        allow_starttls: bool,
        already_tls: bool,
    ) -> (bool, u32) {
        let mut authenticated = false;
        let mut auth_email = String::new();
        let mut helo_seen = false;
        // Validated EHLO/HELO argument ("unknown" when it failed validation) —
        // used for the Received trace header (F-01).
        let mut helo_hostname = String::new();
        let mut mail_from: Option<String> = None;
        let mut rcpt_to: Vec<String> = Vec::new();
        // Whether the current transaction's MAIL FROM carried SMTPUTF8
        // (recorded in the Received trace header, F-01).
        let mut smtputf8 = false;
        let mut message_count: u32 = 0;
        let mut line = String::new();
        let ip = peer.ip();
        let session_id = Uuid::new_v4().to_string();
        let started = Instant::now();
        // F-14: hard wall-clock cap for the unauthenticated phase.
        let session_deadline = tokio::time::Instant::now() + SESSION_DEADLINE;
        // F-14: count of 4xx/5xx replies this session has emitted.
        let mut error_count: u32 = 0;

        // Single write point for command replies: 4xx/5xx replies count
        // toward the error budget; at MAX_SESSION_ERRORS the session is
        // closed with 421 (RFC 5321 §4.3.2 "too many errors").
        // NOTE: the plain `break` below exits the dispatch loop — the only
        // loop enclosing every `reply!` invocation.
        macro_rules! reply {
            ($($arg:tt)*) => {{
                let response: String = format!($($arg)*);
                let is_error = response.starts_with('4') || response.starts_with('5');
                if let Err(e) = write_line(stream, &response).await {
                    debug!(error = %e, peer = %peer, "Write error");
                }
                if is_error {
                    error_count += 1;
                    if error_count >= MAX_SESSION_ERRORS {
                        let _ = write_line(
                            stream,
                            "421 4.7.0 Too many errors, closing connection\r\n",
                        )
                        .await;
                        break;
                    }
                }
            }};
        }

        loop {
            line.clear();
            let read = async { read_line_capped(stream, MAX_COMMAND_LINE).await };
            match tokio::time::timeout(Duration::from_secs(300), read).await {
                Err(_) => {
                    // Idle timeout: 421 with the reason instead of a bare drop.
                    log_smtp_reject(
                        "submission",
                        ip,
                        &session_id,
                        "421 4.4.2 Idle timeout, closing connection",
                    );
                    reply!("421 4.4.2 Idle timeout, closing connection\r\n");
                    break;
                }
                Ok(Ok(LineRead::Eof)) => break,
                Ok(Ok(LineRead::TooLong)) => {
                    // Remainder drained through its newline: session stays
                    // synchronised.
                    log_smtp_reject("submission", ip, &session_id, "500 5.5.2 Line too long");
                    reply!("500 5.5.2 Line too long\r\n");
                    continue;
                }
                Ok(Ok(LineRead::Overflow)) => {
                    // No newline within the absolute drain limit: close —
                    // reading on would parse attacker bytes as commands.
                    log_smtp_reject(
                        "submission",
                        ip,
                        &session_id,
                        "500 5.5.2 Line too long (connection closed)",
                    );
                    reply!("500 5.5.2 Line too long\r\n");
                    break;
                }
                Ok(Ok(LineRead::Line(_, LineTerminator::BareLf))) => {
                    // F-08: a bare-LF COMMAND line is refused (RFC 5321
                    // commands are CRLF-terminated). DATA body tolerance is
                    // unchanged — only command lines are gated here.
                    log_smtp_reject(
                        "submission",
                        ip,
                        &session_id,
                        "500 5.5.2 Bare LF not allowed",
                    );
                    reply!("500 5.5.2 Bare LF not allowed\r\n");
                    continue;
                }
                Ok(Ok(LineRead::Line(l, _))) => line = line_lossy(&l),
                Ok(Err(e)) => {
                    debug!(error = %e, peer = %peer, "Read error");
                    break;
                }
            }

            // F-14: an unauthenticated session must not outlive the deadline.
            if !authenticated && tokio::time::Instant::now() >= session_deadline {
                log_smtp_reject(
                    "submission",
                    ip,
                    &session_id,
                    "421 4.7.0 Session deadline exceeded",
                );
                reply!("421 4.7.0 Session deadline exceeded, closing connection\r\n");
                break;
            }

            // F-06: the verb is matched as an exact first token —
            // `starts_with("DATA")`-style prefix tests accepted `DATABASE`
            // and `MAIL FROMX:<a@b>` as real commands.
            // IMPORTANT: only the verb is uppercased, never the arguments
            // (base64 payloads in AUTH PLAIN are case-sensitive).
            let trimmed = line.trim();
            let (verb_owned, arg) = split_verb(trimmed);
            let verb = verb_owned.as_str();

            if verb == "EHLO" || verb == "HELO" {
                // E-3:validate the EHLO argument before echoing it back —
                // an unvalidated argument used to be reflected verbatim into
                // the greeting (CRLF/control payloads included). An invalid
                // or missing argument is rejected with 501 5.5.4, matching
                // the inbound server (RFC 5321 §4.1.1.1) instead of being
                // silently accepted as "unknown".
                let host = match trimmed
                    .split_whitespace()
                    .nth(1)
                    .filter(|host| super::inbound::is_valid_helo_hostname(host))
                {
                    Some(host) => host,
                    None => {
                        log_smtp_reject(
                            "submission",
                            ip,
                            &session_id,
                            "501 5.5.4 Invalid HELO/EHLO hostname",
                        );
                        reply!("501 5.5.4 Invalid HELO/EHLO hostname\r\n");
                        continue;
                    }
                };
                helo_seen = true;
                helo_hostname = host.to_string();
                // F-04: EHLO/HELO resets any transaction in progress
                // (RFC 5321 §4.1.4).
                mail_from = None;
                rcpt_to.clear();
                smtputf8 = false;
                let mut caps = format!("250-{} Hello {}\r\n", self.config.hostname, host);
                caps.push_str(&format!("250-SIZE {}\r\n", self.config.max_message_size));
                if allow_starttls && !already_tls {
                    caps.push_str("250-STARTTLS\r\n");
                }
                // FIX-2: only advertise AUTH once the session is on TLS;
                // advertising it on a plaintext session invites clients
                // to send credentials in cleartext.
                if already_tls && !authenticated {
                    caps.push_str("250-AUTH PLAIN LOGIN\r\n");
                }
                caps.push_str("250-8BITMIME\r\n");
                caps.push_str("250-PIPELINING\r\n");
                // F-05: ENHANCEDSTATUSCODES (RFC 2034) — every reply this
                // server emits already carries an enhanced status code.
                caps.push_str("250-ENHANCEDSTATUSCODES\r\n");
                caps.push_str("250 SMTPUTF8\r\n");
                let _ = write_line(stream, &caps).await;
            } else if verb == "STARTTLS" {
                if !helo_seen {
                    log_smtp_reject(
                        "submission",
                        ip,
                        &session_id,
                        "503 5.5.1 Error: send HELO/EHLO first",
                    );
                    reply!("503 5.5.1 Error: send HELO/EHLO first\r\n");
                } else if already_tls {
                    // RFC 3207 §4: nested STARTTLS is a sequencing error.
                    log_smtp_reject(
                        "submission",
                        ip,
                        &session_id,
                        "503 5.5.1 TLS already active",
                    );
                    reply!("503 5.5.1 TLS already active\r\n");
                } else if !arg.is_empty() {
                    log_smtp_reject("submission", ip, &session_id, "501 5.5.4 Syntax: STARTTLS");
                    reply!("501 5.5.4 Syntax: STARTTLS\r\n");
                } else if allow_starttls {
                    return (true, message_count);
                } else {
                    log_smtp_reject("submission", ip, &session_id, "454 4.7.0 TLS not available");
                    reply!("454 4.7.0 TLS not available\r\n");
                }
            } else if verb == "AUTH" {
                // F-12: the mechanism is the first ARG token (any case) and
                // the remainder is the optional inline initial response.
                let (mech, initial_response) = match arg.split_once(char::is_whitespace) {
                    Some((mech, rest)) => (mech.to_ascii_uppercase(), rest.trim_start()),
                    None => (arg.to_ascii_uppercase(), ""),
                };
                if !helo_seen {
                    // RFC 4954 §4: AUTH must not be used before EHLO.
                    reply!("503 5.5.1 Send EHLO first\r\n");
                } else if !already_tls {
                    // FIX-2: refuse AUTH on a plaintext session — the
                    // credentials would traverse the network in cleartext.
                    reply!("530 5.7.0 Must issue STARTTLS first\r\n");
                } else if authenticated {
                    reply!("503 5.5.1 Already authenticated\r\n");
                } else if mail_from.is_some() {
                    // RFC 4954 §4: AUTH is not permitted during a mail
                    // transaction (mirror of the inbound server's guard).
                    reply!("503 5.5.1 AUTH not permitted during a mail transaction\r\n");
                } else if mech == "LOGIN" {
                    match self.handle_auth_login(stream, initial_response, ip).await {
                        AuthOutcome::Success(email, _account_id) => {
                            authenticated = true;
                            auth_email = email;
                        }
                        AuthOutcome::Reply(reply) => {
                            log_smtp_reject("submission", ip, &session_id, reply.trim_end());
                            reply!("{reply}");
                        }
                        AuthOutcome::Silent => {}
                    }
                } else if mech == "PLAIN" {
                    match self.handle_auth_plain(stream, initial_response, ip).await {
                        AuthOutcome::Success(email, _account_id) => {
                            authenticated = true;
                            auth_email = email;
                        }
                        AuthOutcome::Reply(reply) => {
                            log_smtp_reject("submission", ip, &session_id, reply.trim_end());
                            reply!("{reply}");
                        }
                        AuthOutcome::Silent => {}
                    }
                } else {
                    reply!("504 5.5.4 Unrecognized authentication type\r\n");
                }
            } else if verb == "MAIL" {
                if !helo_seen {
                    reply!("503 5.5.1 Send EHLO first\r\n");
                } else if !is_mail_from_arg(arg) {
                    // F-06: "MAIL FROMX:<a@b>" must not be treated as MAIL.
                    // (Syntax errors are answered regardless of auth state —
                    // RFC 5321 §4.1.4.)
                    log_smtp_reject(
                        "submission",
                        ip,
                        &session_id,
                        "501 5.5.4 Syntax: MAIL FROM:<address>",
                    );
                    reply!("501 5.5.4 Syntax: MAIL FROM:<address>\r\n");
                } else if !authenticated {
                    reply!("530 5.7.0 Authentication required\r\n");
                } else if mail_from.is_some() {
                    // F-04: nested MAIL — RFC 5321 §4.1.4 sequencing error.
                    log_smtp_reject(
                        "submission",
                        ip,
                        &session_id,
                        "503 5.5.1 Nested MAIL command",
                    );
                    reply!("503 5.5.1 Nested MAIL command\r\n");
                } else if let Err(reject) = validate_mail_params(
                    trimmed,
                    MailParamPolicy {
                        body_8bitmime: true,
                        smtputf8: true,
                    },
                ) {
                    log_smtp_reject("submission", ip, &session_id, reject);
                    reply!("{reject}\r\n");
                } else if mail_size_param(trimmed)
                    .is_some_and(|size| size > self.config.max_message_size as u64)
                {
                    // RFC 1870 §6.2: a SIZE declaration above the advertised
                    // maximum is refused immediately (552), before any DATA
                    // is transferred.
                    log_smtp_reject(
                        "submission",
                        ip,
                        &session_id,
                        "552 5.3.4 Message size exceeds fixed maximum message size",
                    );
                    reply!("552 5.3.4 Message size exceeds fixed maximum message size\r\n");
                } else {
                    // Store only the envelope address, not the full command line.
                    let addr = extract_address(trimmed);
                    if !is_valid_envelope_address(&addr) {
                        // RFC 6409: a submission server must reject messages with a
                        // null/invalid reverse-path; email_queue.from_address also
                        // enforces a valid-address CHECK constraint.
                        reply!("553 5.1.7 Sender address required\r\n");
                    } else {
                        mail_from = Some(addr);
                        smtputf8 = mail_smtputf8_param(trimmed);
                        let _ = write_line(stream, "250 2.0.0 Ok\r\n").await;
                    }
                }
            } else if verb == "RCPT" {
                if !helo_seen {
                    reply!("503 5.5.1 Send EHLO first\r\n");
                } else if !authenticated {
                    reply!("530 5.7.0 Authentication required\r\n");
                } else if !is_rcpt_to_arg(arg) {
                    // F-06: "RCPT TOX:<a@b>" must not be treated as RCPT.
                    log_smtp_reject(
                        "submission",
                        ip,
                        &session_id,
                        "501 5.5.4 Syntax: RCPT TO:<address>",
                    );
                    reply!("501 5.5.4 Syntax: RCPT TO:<address>\r\n");
                } else if rcpt_to.len()
                    >= super::util::effective_max_recipients(
                        self.config.max_recipients,
                        self.rate_limit.max_recipients_per_message,
                    )
                {
                    reply!("452 4.5.3 Too many recipients\r\n");
                } else if let Err(reject) = validate_rcpt_params(trimmed) {
                    log_smtp_reject("submission", ip, &session_id, reject);
                    reply!("{reject}\r\n");
                } else {
                    // Store only the recipient address, not the full command line.
                    let addr = extract_address(trimmed);
                    if !is_valid_envelope_address(&addr) {
                        reply!("501 5.1.3 Bad recipient address syntax\r\n");
                    } else {
                        rcpt_to.push(addr);
                        let _ = write_line(stream, "250 2.0.0 Ok\r\n").await;
                    }
                }
            } else if verb == "DATA" {
                if !helo_seen {
                    reply!("503 5.5.1 Send EHLO first\r\n");
                } else if !authenticated {
                    reply!("530 5.7.0 Authentication required\r\n");
                } else if !arg.is_empty() {
                    log_smtp_reject("submission", ip, &session_id, "501 5.5.4 Syntax: DATA");
                    reply!("501 5.5.4 Syntax: DATA\r\n");
                } else if mail_from.is_none() || rcpt_to.is_empty() {
                    reply!("503 5.5.1 Need MAIL and RCPT first\r\n");
                } else {
                    let _ = write_line(stream, "354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                        .await;

                    match self.read_data_message(stream).await {
                        ReadDataOutcome::TimedOut => {
                            log_smtp_reject(
                                "submission",
                                ip,
                                &session_id,
                                "421 4.4.2 Data timeout exceeded",
                            );
                            reply!("421 4.4.2 Data timeout exceeded\r\n");
                            break;
                        }
                        ReadDataOutcome::Overflow => {
                            log_smtp_reject(
                                "submission",
                                ip,
                                &session_id,
                                "500 5.5.2 Data line too long (connection closed)",
                            );
                            reply!("500 5.5.2 Line too long\r\n");
                            break;
                        }
                        ReadDataOutcome::Aborted => {
                            // Client disconnected / stream failed mid-DATA: the
                            // partial payload is discarded and never queued.
                            break;
                        }
                        ReadDataOutcome::TooLarge => {
                            // RFC 5321 §4.5.3.2: message exceeds the SIZE limit.
                            log_smtp_reject(
                                "submission",
                                ip,
                                &session_id,
                                "552 5.3.4 Message size exceeds fixed maximum message size",
                            );
                            reply!("552 5.3.4 Message size exceeds fixed maximum message size\r\n");
                            mail_from = None;
                            rcpt_to.clear();
                            continue;
                        }
                        ReadDataOutcome::Message(data) => {
                            // F-01: refuse obvious routing loops before any
                            // parsing/persist work (cheap raw header scan).
                            if received_hop_limit_exceeded(&data) {
                                log_smtp_reject(
                                    "submission",
                                    ip,
                                    &session_id,
                                    "550 5.4.6 Routing loop detected",
                                );
                                reply!("550 5.4.6 Routing loop detected\r\n");
                                mail_from = None;
                                rcpt_to.clear();
                                continue;
                            }
                            // F-01: prepend the trace header for this hop
                            // before the queue write. helo_hostname passed
                            // is_valid_helo_hostname (or is the literal
                            // "unknown"), so no CRLF injection is possible.
                            let msg_id = Uuid::new_v4().to_string();
                            let received = build_received_header(
                                &helo_hostname,
                                None,
                                ip,
                                &self.config.hostname,
                                already_tls,
                                true,
                                smtputf8,
                                &msg_id,
                            );
                            let message = compose_stored_message(&received, &data);
                            match self
                                .queue_message(
                                    &auth_email,
                                    mail_from.as_deref().unwrap_or(""),
                                    &rcpt_to,
                                    &message,
                                    &msg_id,
                                )
                                .await
                            {
                                Ok(QueueOutcome::Queued) => {
                                    message_count += 1;
                                    let _ = write_line(
                                        stream,
                                        &format!("250 2.0.0 Ok id={}\r\n", msg_id),
                                    )
                                    .await;
                                    if message_count >= self.rate_limit.max_messages_per_connection
                                    {
                                        let _ = write_line(
                                            stream,
                                            "421 4.7.0 Too many messages, closing connection\r\n",
                                        )
                                        .await;
                                        break;
                                    }
                                }
                                Ok(QueueOutcome::SenderNotOwned) => {
                                    // MAIL FROM domain is not owned by the
                                    // authenticated account's tenant.
                                    reply!("550 5.7.1 sender address not owned by account\r\n");
                                }
                                Ok(QueueOutcome::SenderNotReady) => {
                                    reply!("550 5.7.1 sender domain is not verified and ready for delivery\r\n");
                                }
                                Ok(QueueOutcome::RecipientSuppressed) => {
                                    reply!("550 5.1.1 recipient address suppressed\r\n");
                                }
                                Err(QueueWriteFailure::Transient) => {
                                    // Infrastructure failure — already
                                    // ERROR-logged with its cause inside
                                    // queue_message; the client retries.
                                    reply!("451 4.3.0 Requested action aborted\r\n");
                                }
                                Err(QueueWriteFailure::Permanent) => {
                                    // Internal invariant broken for THIS
                                    // message — retrying cannot fix it.
                                    reply!("554 5.6.0 Message could not be queued\r\n");
                                }
                            }
                            mail_from = None;
                            rcpt_to.clear();
                            smtputf8 = false;
                        }
                    }
                }
            } else if verb == "RSET" {
                mail_from = None;
                rcpt_to.clear();
                smtputf8 = false;
                let _ = write_line(stream, "250 2.0.0 Ok\r\n").await;
            } else if verb == "NOOP" {
                let _ = write_line(stream, "250 2.0.0 Ok\r\n").await;
            } else if verb == "QUIT" {
                let _ = write_line(stream, "221 2.0.0 Bye\r\n").await;
                break;
            } else if verb == "HELP" {
                let _ = write_line(
                    stream,
                    "214 2.0.0 Commands: EHLO HELO AUTH MAIL RCPT DATA RSET NOOP QUIT STARTTLS HELP VRFY EXPN; see RFC 5321\r\n",
                )
                .await;
            } else if verb == "VRFY" {
                // RFC 5321 §7.3: never confirm address existence.
                let _ = write_line(
                    stream,
                    "252 2.5.2 Cannot VRFY user, but will accept message and attempt delivery\r\n",
                )
                .await;
            } else if verb == "EXPN" {
                reply!("502 5.5.1 EXPN command not supported\r\n");
            } else {
                // F-06: unknown COMMAND is a syntax error (RFC 5321 §4.2.4
                // uses 500 for unrecognized commands).
                log_smtp_reject(
                    "submission",
                    ip,
                    &session_id,
                    "500 5.5.2 Command not recognised",
                );
                reply!("500 5.5.2 Command not recognised\r\n");
            }
        }

        log_session_summary(
            "submission",
            ip,
            &session_id,
            already_tls,
            authenticated,
            message_count,
            started.elapsed().as_millis(),
            "closed",
        );
        (false, message_count)
    }

    /// Read one DATA payload. Protections applied while reading:
    ///
    ///  - a total deadline (slow-loris protection) plus a per-line timeout
    ///    and a per-line length cap,
    ///  - the overall size cap is enforced BEFORE buffering (552),
    ///  - end-of-data is ONLY a line that is exactly `.` terminated by CRLF
    ///    (RFC 5321 §4.1.1.5 strict — a bare-LF `".\n"` line is body data,
    ///    closing the SMTP-smuggling window),
    ///  - RFC 5321 §4.5.2 dot-unstuffing removes exactly ONE leading dot,
    ///  - every stored body line is CRLF-normalized (a bare-LF body line is
    ///    never relayed), and
    ///  - a truncated payload (client disconnect mid-DATA) is discarded.
    async fn read_data_message<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut BufStream<S>,
    ) -> ReadDataOutcome {
        let mut data = Vec::new();
        let mut too_large = false;
        let deadline = Instant::now() + DATA_TOTAL_TIMEOUT;
        loop {
            let remaining = deadline
                .checked_duration_since(Instant::now())
                .unwrap_or(Duration::ZERO);
            if remaining.is_zero() {
                return ReadDataOutcome::TimedOut;
            }
            let per_line = remaining.min(DATA_LINE_TIMEOUT);
            match tokio::time::timeout(per_line, read_line_capped(stream, MAX_DATA_LINE)).await {
                Err(_) => return ReadDataOutcome::TimedOut,
                Ok(Ok(LineRead::Eof)) | Ok(Err(_)) => return ReadDataOutcome::Aborted,
                Ok(Ok(LineRead::TooLong)) => {
                    // A single line over the per-line cap cannot be part of a
                    // message we are willing to store; the line itself was
                    // drained through its newline, keep reading (without
                    // buffering) until the terminator so the session stays
                    // synchronised and can be refused with 552.
                    too_large = true;
                    data.clear();
                }
                Ok(Ok(LineRead::Overflow)) => {
                    // No newline within the absolute drain limit: the stream
                    // cannot be resynchronised — treat as fatal for the DATA
                    // transfer (the caller closes after the 552/500 reply).
                    return ReadDataOutcome::Overflow;
                }
                Ok(Ok(LineRead::Line(l, term))) => {
                    if is_strict_end_of_data(&l, term) {
                        if too_large {
                            return ReadDataOutcome::TooLarge;
                        }
                        // The final CRLF belongs to the <CRLF>.<CRLF>
                        // terminator, not to the message content.
                        if data.last() == Some(&b'\n') {
                            data.pop();
                            if data.last() == Some(&b'\r') {
                                data.pop();
                            }
                        }
                        return ReadDataOutcome::Message(data);
                    }
                    if too_large {
                        // Drain the rest without buffering.
                        continue;
                    }
                    // Bytes preserved verbatim (8BITMIME): strip the line's
                    // actual terminator, un-stuff exactly one leading dot
                    // (RFC 5321 §4.5.2), and normalize the stored line to
                    // CRLF so a bare-LF body line is never relayed.
                    let data_slice = unstuff_dot_line_bytes(line_content_bytes(&l, term));
                    if data.len() + data_slice.len() + 2 > self.config.max_message_size {
                        too_large = true;
                        data.clear();
                    } else {
                        data.extend_from_slice(data_slice);
                        data.extend_from_slice(b"\r\n");
                    }
                }
            }
        }
    }

    /// `AUTH LOGIN` two-step (plus optional inline username): prompt for
    /// base64 username then password, verify, and always produce a
    /// terminating reply (never leave the client hanging). 334 challenges
    /// are written directly (they are not error replies); every terminal
    /// reply is returned as [`AuthOutcome::Reply`] so the session loop can
    /// emit it through `reply!` — AUTH failures must count toward the
    /// session error budget like any other 4xx/5xx.
    async fn handle_auth_login<S: AsyncRead + AsyncWrite + Unpin>(
        self: &Arc<Self>,
        stream: &mut BufStream<S>,
        initial_response: &str,
        ip: std::net::IpAddr,
    ) -> AuthOutcome {
        // F-12: "AUTH LOGIN <base64-username>" carries the username inline
        // (RFC 4954 initial-response); "=" encodes the empty string.
        let user_b64: String = if !initial_response.is_empty() {
            initial_response
                .strip_prefix('=')
                .unwrap_or(initial_response)
                .to_string()
        } else {
            let _ = write_line(stream, "334 VXNlcm5lbWU6\r\n").await;
            match self.read_auth_line(stream).await {
                Some(AuthLine::Payload(line)) => line,
                Some(AuthLine::Cancelled) => return AuthOutcome::Reply(AUTH_CANCELLED),
                Some(AuthLine::TooLong) => return AuthOutcome::Reply(AUTH_LINE_TOO_LONG),
                None => return AuthOutcome::Silent,
            }
        };

        let _ = write_line(stream, "334 UGFzc3dvcmQ6\r\n").await;
        let pass_b64 = match self.read_auth_line(stream).await {
            Some(AuthLine::Payload(line)) => line,
            Some(AuthLine::Cancelled) => return AuthOutcome::Reply(AUTH_CANCELLED),
            Some(AuthLine::TooLong) => return AuthOutcome::Reply(AUTH_LINE_TOO_LONG),
            None => return AuthOutcome::Silent,
        };

        match (
            BASE64.decode(user_b64.trim()),
            BASE64.decode(pass_b64.trim()),
        ) {
            (Ok(user), Ok(pass)) => {
                let user_str = String::from_utf8_lossy(&user);
                let pass_str = String::from_utf8_lossy(&pass);
                match self.authenticate_user(&user_str, &pass_str, ip).await {
                    Ok((email, account_id)) => {
                        let _ = write_line(stream, "235 2.7.0 Authentication successful\r\n").await;
                        AuthOutcome::Success(email, account_id)
                    }
                    Err(AuthError::LockedOut) => AuthOutcome::Reply(AUTH_LOCKED_OUT),
                    Err(AuthError::Failed) => AuthOutcome::Reply(AUTH_FAILED),
                }
            }
            _ => AuthOutcome::Reply(AUTH_BAD_BASE64),
        }
    }

    /// `AUTH PLAIN` inline or two-step. Always produces a terminating reply,
    /// including for payloads that decode to fewer than three NUL-separated
    /// fields (previously the client hung forever in that case). Terminal
    /// replies are returned (not written) so failures flow through `reply!`
    /// and the session error budget.
    async fn handle_auth_plain<S: AsyncRead + AsyncWrite + Unpin>(
        self: &Arc<Self>,
        stream: &mut BufStream<S>,
        initial_response: &str,
        ip: std::net::IpAddr,
    ) -> AuthOutcome {
        // F-12: the base64 payload arrives verbatim (any command case); "="
        // encodes the empty initial response (RFC 4954).
        let auth_b64: String = if !initial_response.is_empty() {
            initial_response
                .strip_prefix('=')
                .unwrap_or(initial_response)
                .to_string()
        } else {
            let _ = write_line(stream, "334 \r\n").await;
            match self.read_auth_line(stream).await {
                Some(AuthLine::Payload(line)) => line,
                Some(AuthLine::Cancelled) => return AuthOutcome::Reply(AUTH_CANCELLED),
                Some(AuthLine::TooLong) => return AuthOutcome::Reply(AUTH_LINE_TOO_LONG),
                None => return AuthOutcome::Silent,
            }
        };
        match BASE64.decode(auth_b64.trim()) {
            Ok(creds) => {
                let s = String::from_utf8_lossy(&creds);
                let parts: Vec<&str> = s.splitn(3, '\0').collect();
                if parts.len() >= 3 {
                    match self.authenticate_user(parts[1], parts[2], ip).await {
                        Ok((email, account_id)) => {
                            let _ =
                                write_line(stream, "235 2.7.0 Authentication successful\r\n").await;
                            AuthOutcome::Success(email, account_id)
                        }
                        Err(AuthError::LockedOut) => AuthOutcome::Reply(AUTH_LOCKED_OUT),
                        Err(AuthError::Failed) => AuthOutcome::Reply(AUTH_FAILED),
                    }
                } else {
                    // Malformed authcid (fewer than three NUL fields).
                    AuthOutcome::Reply(AUTH_FAILED)
                }
            }
            _ => AuthOutcome::Reply(AUTH_BAD_BASE64),
        }
    }

    /// Read one AUTH response line with a timeout and a line-length cap.
    /// A line consisting of the single `*` cancels the authentication
    /// exchange (RFC 4954 §4) — the caller answers with 501. Over-long
    /// continuation lines are reported so the caller can answer 500 (the
    /// remainder was drained, the session stays synchronised). `None` means
    /// the transport died: no reply can be delivered.
    async fn read_auth_line<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut BufStream<S>,
    ) -> Option<AuthLine> {
        match tokio::time::timeout(
            AUTH_LINE_TIMEOUT,
            read_line_capped(stream, MAX_COMMAND_LINE),
        )
        .await
        {
            Ok(Ok(LineRead::Line(l, _))) => {
                let line = line_lossy(&l);
                if line.trim() == "*" {
                    Some(AuthLine::Cancelled)
                } else {
                    Some(AuthLine::Payload(line))
                }
            }
            Ok(Ok(LineRead::TooLong)) => Some(AuthLine::TooLong),
            _ => None,
        }
    }

    // ── Auth helper ──────────────────────────────────────────────────────

    async fn authenticate_user(
        &self,
        email: &str,
        password: &str,
        ip: std::net::IpAddr,
    ) -> Result<(String, Uuid), AuthError> {
        // FIX-3: lockout short-circuit BEFORE any work. Once an (IP,
        // account) pair — or an IP across all accounts — has accumulated
        // enough recent failures, further attempts are rejected without
        // touching the database or verifying the presented password.
        // Counters decay after the tracker's TTL, which is the lockout
        // window after which legitimate users can authenticate again.
        if self.auth_fail_tracker.is_locked(ip, email).await {
            metrics::counter!("mta.auth.lockout").increment(1);
            return Err(AuthError::LockedOut);
        }

        // NOTE: `users` has no `username` column (only smtp_credentials does),
        // so the lookup is by email only — identical to the api-server login
        // path. The tenant join enforces tenants.status here too (F18): a
        // suspended tenant's SMTP credentials must stop accepting
        // submission, same as the API/SSR gates in api-server.
        let user = sqlx::query_as::<_, (String, Uuid, String, String, String)>(
            "SELECT u.email, u.id, u.password_hash, u.status, t.status \
             FROM users u JOIN tenants t ON t.id = u.tenant_id \
             WHERE LOWER(u.email) = LOWER($1)",
        )
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::Failed)?;

        let (user_email, user_id, password_hash, status, tenant_status) = match user {
            Some(u) => u,
            None => {
                // FIX-3: unknown-account attempts count toward the
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

        // The failure shape stays identical for user- and tenant-level
        // refusals so the SMTP dialogue cannot distinguish them.
        if status != "active" || tenant_status != "active" {
            self.auth_fail_tracker.record_failure(ip, email).await;
            let _ = verify_against_dummy(password);
            metrics::counter!("mta.auth.failure").increment(1);
            return Err(AuthError::Failed);
        }

        // verify_password_for_login accepts both Argon2id and legacy bcrypt
        // hashes (the users table contains bcrypt rows created before the
        // Argon2id migration). On successful bcrypt login it returns an
        // Argon2id replacement hash, which we persist so the row migrates.
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
                Ok((user_email, user_id))
            }
            _ => {
                self.auth_fail_tracker.record_failure(ip, email).await;
                metrics::counter!("mta.auth.failure").increment(1);
                Err(AuthError::Failed)
            }
        }
    }

    // ── Queue helper ─────────────────────────────────────────────────────

    /// Persist a submitted message into `email_queue` using the deployed
    /// (production) schema: `id`/`message_id`/`domain_id` are UUIDs, `tenant_id`
    /// is VARCHAR(26) referencing `tenants(id)`, and `from_address`/`to_addresses`/
    /// `subject` are the NOT NULL columns the queue worker relies on. Both the
    /// new column group (`from_address`, `to_addresses`, `text_body`, ...) and the
    /// legacy worker columns (`"from"`, `"to"`, `html`, `text`, `tenant_id`,
    /// `domain_id`, `message_id`) are populated so `EmailProcessor::fetch_jobs`
    /// can decode the row.
    ///
    /// F-10: `data` is the raw BYTES of the message (Received header already
    /// prepended by the caller). 8BITMIME is advertised, so the payload may
    /// contain octets outside US-ASCII — the header/body split and the MIME
    /// parsing both run on the original bytes (see [`prepare_queue_payload`]);
    /// a lossy UTF-8 decode is applied ONLY to values destined for the TEXT
    /// columns, never to the parser input.
    async fn queue_message(
        &self,
        auth_email: &str,
        mail_from: &str,
        rcpt_to: &[String],
        data: &[u8],
        msg_id: &str,
    ) -> Result<QueueOutcome, QueueWriteFailure> {
        // The MIME parse is pure CPU over up to max_message_size (10 MB) of
        // bytes: it must run on the blocking pool, never on the async
        // worker the session loop shares with every other connection. The
        // payload needs to be owned ('static) for the dispatch — one copy
        // is the price of not stalling the runtime.
        let payload = {
            let data = data.to_vec();
            tokio::task::spawn_blocking(move || prepare_queue_payload(&data))
                .await
                .map_err(|e| {
                    QueueWriteFailure::transient(
                        e,
                        "submission queue: payload preparation task failed",
                    )
                })?
        };

        let mut tx = self.pool.begin().await.map_err(|e| {
            QueueWriteFailure::transient(e, "submission queue: begin transaction failed")
        })?;

        // Queue-insert durability: a submission must not be acknowledged
        // before its queue row is recoverable. PostgreSQL defaults to
        // synchronous_commit=on, but that is a session/server-level default
        // that a pool configuration or operator could relax; SET LOCAL pins
        // the WAL-flush-before-commit guarantee for exactly this
        // transaction, so the 250 implies the row survived a crash.
        sqlx::query("SET LOCAL synchronous_commit = on")
            .execute(&mut *tx)
            .await
            .map_err(|e| {
                QueueWriteFailure::transient(
                    e,
                    "submission queue: SET LOCAL synchronous_commit failed",
                )
            })?;

        // tenant_id is VARCHAR(26) referencing tenants(id) — never the user's
        // account UUID. Look up the authenticated user's actual tenant (by
        // email only: `users` has no `username` column).
        let tenant_id: Option<String> =
            sqlx::query_scalar("SELECT tenant_id FROM users WHERE LOWER(email) = LOWER($1)")
                .bind(auth_email)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|e| {
                    QueueWriteFailure::transient(e, "submission queue: tenant lookup failed")
                })?
                .flatten();

        // CAN-SPAM (F): the REST send path refuses suppressed recipients
        // before queueing; the SMTP submission path must not be a bypass.
        // Canonicalize (trim + lowercase) exactly like the api-server check
        // and drop suppressed recipients from the queued row. A lookup
        // failure surfaces as Transient → 451 so the client retries rather
        // than silently delivering to a suppressed address.
        let rcpt_to: Vec<String> = match tenant_id.as_deref() {
            Some(tenant) => {
                let canonical = canonical_recipients(rcpt_to);
                let suppressed: Vec<String> =
                    sqlx::query_scalar(
                        "SELECT LOWER(email) FROM suppressions WHERE tenant_id = $1 AND LOWER(email) = ANY($2)",
                    )
                    .bind(tenant)
                    .bind(&canonical)
                    .fetch_all(&mut *tx)
                    .await
                    .map_err(|e| {
                        QueueWriteFailure::transient(
                            e,
                            "submission queue: suppression lookup failed",
                        )
                    })?;
                if !suppressed.is_empty() {
                    for dropped in &suppressed {
                        warn!(
                            recipient = %mail_common::pii::redact_email(dropped),
                            "Submission recipient is suppressed; dropping from queue"
                        );
                    }
                }
                let allowed = filter_suppressed_recipients(rcpt_to, &suppressed);
                if allowed.is_empty() {
                    metric_message("submission", "rejected");
                    return Ok(QueueOutcome::RecipientSuppressed);
                }
                allowed
            }
            None => rcpt_to.to_vec(),
        };

        // Resolve the sender's domain while holding a share lock through queue
        // insertion. This matches the API's authorization predicate and
        // prevents acknowledging a message from a domain already being
        // revoked/deleted at the same instant.
        let requires_ses = apexmail_lib::transport::email_transport_is_ses(
            std::env::var("EMAIL_TRANSPORT_TYPE").ok().as_deref(),
        );
        let domain: Option<(Uuid, bool)> = match tenant_id.as_deref() {
            Some(tenant) => {
                let domain_name = mail_from
                    .rsplit_once('@')
                    .map(|(_, d)| d.trim().trim_end_matches('.'))
                    .unwrap_or_default();
                if domain_name.is_empty() {
                    None
                } else {
                    sqlx::query_as(
                        "SELECT id, status = 'verified'
                                AND dkim_enabled = true
                                AND dkim_selector IS NOT NULL
                                AND dkim_public_key IS NOT NULL
                                AND dkim_private_key IS NOT NULL
                                AND COALESCE(dkim_private_key LIKE 'dkim:v1:%', false)
                                AND ($3::boolean = false OR ses_verified = true)
                           FROM domains
                          WHERE LOWER(name) = LOWER($1) AND tenant_id = $2
                          LIMIT 1 FOR SHARE",
                    )
                    .bind(domain_name)
                    .bind(tenant)
                    .bind(requires_ses)
                    .fetch_optional(&mut *tx)
                    .await
                    .map_err(|e| {
                        QueueWriteFailure::transient(
                            e,
                            "submission queue: sender domain lookup failed",
                        )
                    })?
                }
            }
            None => None,
        };

        let domain_id = match domain {
            None => {
                warn!(
                    from = %mail_common::pii::redact_email(mail_from),
                    "Submission MAIL FROM domain not owned by account's tenant; rejecting"
                );
                metric_message("submission", "rejected");
                return Ok(QueueOutcome::SenderNotOwned);
            }
            Some((_, false)) => {
                warn!(
                    from = %mail_common::pii::redact_email(mail_from),
                    requires_ses,
                    "Submission MAIL FROM domain is not ready; rejecting"
                );
                metric_message("submission", "rejected");
                return Ok(QueueOutcome::SenderNotReady);
            }
            Some((domain_id, true)) => domain_id,
        };

        // The queue row's id/message_id are UUID columns: a non-UUID msg_id
        // is an internal invariant violation (this server minted it), not a
        // client error and not a transient condition — 554, never retried
        // by a well-behaved client.
        let message_uuid = Uuid::parse_str(msg_id).map_err(|e| {
            QueueWriteFailure::permanent(e, "submission queue: generated message id is not a UUID")
        })?;
        let to_first = rcpt_to.first().cloned().unwrap_or_default();

        sqlx::query(
            r#"INSERT INTO email_queue (
                id, from_address, to_addresses, subject, raw_headers, text_body,
                "from", "to", html, text, headers, attachments,
                status, priority, tenant_id, message_id,
                domain_id, metadata, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $15, $16, 'pending', 5,
                      $11, $12, $13, $14, NOW(), NOW())"#,
        )
        .bind(message_uuid)
        .bind(mail_from)
        .bind(&rcpt_to)
        .bind(&payload.subject)
        .bind(&payload.headers)
        .bind(&payload.text_body)
        .bind(mail_from)
        .bind(&to_first)
        .bind(&payload.html_body)
        .bind(&payload.text_body)
        .bind(&tenant_id)
        .bind(message_uuid)
        .bind(domain_id)
        .bind(Option::<serde_json::Value>::None)
        .bind(&payload.custom_headers)
        .bind(&payload.attachments)
        .execute(&mut *tx)
        .await
        .map_err(|e| {
            QueueWriteFailure::transient(e, "submission queue: email_queue INSERT failed")
        })?;

        tx.commit().await.map_err(|e| {
            QueueWriteFailure::transient(e, "submission queue: transaction commit failed")
        })?;

        info!(
            message_id = %msg_id,
            from = %mail_common::pii::redact_email(mail_from),
            to = ?rcpt_to,
            size = data.len(),
            "Message queued via submission"
        );
        metric_message("submission", "queued");
        Ok(QueueOutcome::Queued)
    }
}

// ── I/O helpers ─────────────────────────────────────────────────────────

/// Extract the bare address from an SMTP command line such as
/// `RCPT TO:<user@example.com>` or `MAIL FROM: user@example.com`.
/// Only the address path is returned — trailing parameters such as
/// `SIZE=1000` are never part of the address.
fn extract_address(line: &str) -> String {
    // Prefer the explicit angle-bracketed path (shared panic-safe helper:
    // the closing '>' is always searched after the opening '<').
    if let Some(addr) = super::util::extract_addr_safe(line) {
        return addr.to_string();
    }
    // Fall back to the token directly after the MAIL FROM:/RCPT TO: verb
    // (never the last token — that could be a command parameter).
    let rest = line
        .split_once("MAIL FROM")
        .or_else(|| line.split_once("RCPT TO"))
        .or_else(|| line.split_once("mail from"))
        .or_else(|| line.split_once("rcpt to"))
        .map(|(_, r)| r)
        .unwrap_or(line)
        .trim_start_matches(':')
        .trim();
    rest.split_whitespace()
        .next()
        .unwrap_or("")
        .trim_matches(|c| c == '<' || c == '>')
        .to_string()
}

/// Hard cap on envelope address length. RFC 5321 §4.5.3.1.1 caps the
/// reverse/forward path; 320 octets is the generous local(64)+domain(255)
/// budget also used by the bounce server's validator, and bounds how much
/// of an over-long command line can end up stored in the envelope.
pub(crate) const MAX_ENVELOPE_ADDR_LEN: usize = 320;

/// Validate an envelope address against the same rules `email_queue` enforces
/// (`chk_email_queue_from_address`): no whitespace, no control characters,
/// exactly one `@`, a non-empty local part, and a non-empty domain containing
/// at least one dot. Charset-agnostic by design (SMTPUTF8).
pub(crate) fn is_valid_envelope_address(addr: &str) -> bool {
    if addr.is_empty()
        || addr.len() > MAX_ENVELOPE_ADDR_LEN
        || addr.chars().any(|c| c.is_whitespace() || c.is_control())
        // Exactly one '@' (F-03): rsplit_once alone accepted "a@@b.com",
        // which the queue's DB CHECK refuses.
        || addr.matches('@').count() != 1
    {
        return false;
    }
    match addr.rsplit_once('@') {
        Some((local, domain)) => {
            !local.is_empty()
                && !domain.is_empty()
                && domain.contains('.')
                && !domain.starts_with('.')
                && !domain.ends_with('.')
        }
        None => false,
    }
}

/// Split a raw message into (headers, body) at the first blank line.
///
/// F-10: byte-oriented — the raw payload may contain 8-bit octets
/// (8BITMIME) that are NOT valid UTF-8, so the split must never go through
/// a lossy String decode first (that would both corrupt the boundary search
/// and replace body octets with U+FFFD). Shared with the inbound server's
/// ARC sealing path.
pub(crate) fn split_headers_body(raw: &[u8]) -> (&[u8], &[u8]) {
    // Earliest separator wins, whatever its flavour: a message with LF-only
    // headers followed by a CRLF body must split at the LF blank line.
    let crlf = raw.windows(4).position(|w| w == b"\r\n\r\n");
    let lf = raw.windows(2).position(|w| w == b"\n\n");
    match (crlf, lf) {
        (Some(a), Some(b)) if a < b => (&raw[..a], &raw[a + 4..]),
        (Some(a), None) => (&raw[..a], &raw[a + 4..]),
        (_, Some(b)) => (&raw[..b], &raw[b + 2..]),
        (None, None) => (raw, b""),
    }
}

/// Compose the message handed to the queue: the `Received:` trace header for
/// this hop followed by the client's RAW bytes, verbatim (F-10 — the bytes
/// are never decoded on this path).
fn compose_stored_message(received: &str, data: &[u8]) -> Vec<u8> {
    let mut message = Vec::with_capacity(received.len() + 2 + data.len());
    message.extend_from_slice(received.as_bytes());
    message.extend_from_slice(b"\r\n");
    message.extend_from_slice(data);
    message
}

/// Derived values `email_queue` needs from the raw message bytes (F-10).
struct PreparedQueuePayload {
    /// Header block as text for the `raw_headers` TEXT column (lossy decode
    /// is acceptable ONLY here — it is a display/inspection column, not the
    /// parsing input).
    headers: String,
    subject: String,
    text_body: String,
    html_body: Option<String>,
    /// Customer-supplied headers (Reply-To, List-Unsubscribe, X-*) for the
    /// `headers` JSONB column. The delivery worker re-applies these when it
    /// rebuilds the outgoing MIME; protected transport headers are excluded
    /// (the worker filters them again on read).
    custom_headers: serde_json::Value,
    /// Attachments for the `attachments` JSONB column, in the worker's
    /// contract shape: `[{filename, content: base64, contentType}]`.
    /// Without this, submitted mail with attachments is delivered with the
    /// attachments silently deleted.
    attachments: serde_json::Value,
}

/// Headers the queue must never carry as "custom": they are either rebuilt
/// by the delivery worker or belong to the transport layer. Mirrors the
/// worker's PROTECTED_HEADERS list (worker-processors/email/processor.rs).
const QUEUE_PROTECTED_HEADERS: &[&str] = &[
    "from",
    "to",
    "cc",
    "bcc",
    "subject",
    "date",
    "message-id",
    "dkim-signature",
    "arc-seal",
    "arc-message-signature",
    "arc-authentication-results",
    "return-path",
    "received",
    "received-spf",
    "authentication-results",
    "x-apexmail-message-id",
    "x-apexmail-tenant-id",
    "x-apexmail-campaign-id",
    "x-originating-ip",
    "x-mailer",
    "mime-version",
    "content-type",
    "content-transfer-encoding",
];

/// Fold RFC 5322 continuation lines and collect non-protected headers as a
/// JSON object keyed by lowercased name. Operates on the decoded header
/// block text so folded values (long List-Unsubscribe URLs) survive intact.
fn extract_custom_headers(headers: &str) -> serde_json::Value {
    let mut map = serde_json::Map::new();
    let mut current: Option<(String, String)> = None;

    fn flush(
        current: &mut Option<(String, String)>,
        map: &mut serde_json::Map<String, serde_json::Value>,
    ) {
        if let Some((name, value)) = current.take() {
            let key = name.trim().to_ascii_lowercase();
            if !key.is_empty() && !QUEUE_PROTECTED_HEADERS.contains(&key.as_str()) {
                map.insert(key, serde_json::Value::String(value.trim().to_string()));
            }
        }
    }

    for line in headers.lines() {
        if line.starts_with(' ') || line.starts_with('\t') {
            if let Some((_, value)) = current.as_mut() {
                value.push(' ');
                value.push_str(line.trim());
            }
            continue;
        }
        flush(&mut current, &mut map);
        if let Some((name, value)) = line.split_once(':') {
            current = Some((name.trim().to_string(), value.trim().to_string()));
        }
    }
    flush(&mut current, &mut map);

    serde_json::Value::Object(map)
}

/// Extract attachments from the parsed MIME in the worker's JSONB contract
/// shape (`filename`, base64 `content`, `contentType`).
fn extract_attachments(message: &mail_parser::Message<'_>) -> serde_json::Value {
    use base64::Engine as _;

    let mut items = Vec::new();
    for (index, part) in message.attachments().enumerate() {
        let contents = part.contents();
        if contents.is_empty() {
            continue;
        }
        let part_headers = part.headers();
        let header_ct = |name: &HeaderName<'_>| -> Option<&ContentType<'_>> {
            part_headers
                .iter()
                .rev()
                .find(|h| &h.name == name)
                .and_then(|h| match &h.value {
                    HeaderValue::ContentType(ct) => Some(ct),
                    _ => None,
                })
        };
        // Filename: Content-Disposition filename attribute, else the
        // Content-Type name attribute (mirrors GetHeader::attachment_name).
        let filename = header_ct(&HeaderName::ContentDisposition)
            .and_then(|cd| cd.attribute("filename"))
            .or_else(|| header_ct(&HeaderName::ContentType).and_then(|ct| ct.attribute("name")))
            .map(|n| n.to_string())
            .unwrap_or_else(|| format!("attachment-{}", index + 1));

        let content_type = header_ct(&HeaderName::ContentType)
            .map(|ct| match &ct.c_subtype {
                Some(subtype) => format!("{}/{}", ct.c_type, subtype),
                None => ct.c_type.to_string(),
            })
            .unwrap_or_else(|| "application/octet-stream".to_string());

        items.push(serde_json::json!({
            "filename": filename,
            "content": base64::engine::general_purpose::STANDARD.encode(contents),
            "contentType": content_type,
        }));
    }
    serde_json::Value::Array(items)
}

/// Split and MIME-parse the RAW message bytes.
///
/// The MIME parser handles charset-labelled 8-bit bodies (e.g.
/// `charset=iso-8859-1`) correctly when fed the ORIGINAL octets — decoding
/// to text with the declared charset. The previous implementation ran
/// `String::from_utf8_lossy` over the whole payload first, which replaced
/// every non-UTF-8 octet with U+FFFD BEFORE parsing and corrupted every
/// 8BITMIME submission. The parser input stays raw bytes; `from_utf8_lossy`
/// is applied only to the TEXT-column fallbacks.
fn prepare_queue_payload(data: &[u8]) -> PreparedQueuePayload {
    let (headers_bytes, body_bytes) = split_headers_body(data);

    // Parse the MIME content so the worker's html/text columns are
    // populated (the worker builds the outgoing message from them).
    let parsed = mail_parser::MessageParser::default().parse(data);
    let headers = String::from_utf8_lossy(headers_bytes).into_owned();
    let subject = parsed
        .as_ref()
        .and_then(|m| m.subject())
        .map(|s| s.to_string())
        .unwrap_or_else(|| extract_subject(&headers));
    let html_body = parsed
        .as_ref()
        .and_then(|m| m.body_html(0))
        .map(|b| b.into_owned());
    let text_body = parsed
        .as_ref()
        .and_then(|m| m.body_text(0))
        .map(|b| b.into_owned())
        .filter(|b| !b.is_empty())
        .unwrap_or_else(|| String::from_utf8_lossy(body_bytes).into_owned());

    // subject is NOT NULL in email_queue (max length 998 per CHECK).
    // E-4:the mail_parser value is NOT pre-truncated (only the header
    // fallback is), so a >998-char subject failed the INSERT with a
    // permanent 451. Truncate char-safely on every path.
    let subject = if subject.is_empty() {
        "(no subject)".to_string()
    } else {
        truncate_subject_chars(&subject, MAX_SUBJECT_CHARS)
    };

    let custom_headers = extract_custom_headers(&headers);
    let attachments = parsed
        .as_ref()
        .map(extract_attachments)
        .unwrap_or(serde_json::Value::Array(Vec::new()));

    PreparedQueuePayload {
        headers,
        subject,
        text_body,
        html_body,
        custom_headers,
        attachments,
    }
}

/// Extract the Subject header value; `email_queue.subject` is NOT NULL.
fn extract_subject(headers: &str) -> String {
    let subject = headers
        .lines()
        .find(|l| l.to_ascii_lowercase().starts_with("subject:"))
        .map(|l| {
            l.split_once(':')
                .map(|(_, v)| v.trim())
                .unwrap_or("")
                .to_string()
        })
        .unwrap_or_else(|| "(no subject)".to_string());
    if subject.is_empty() {
        "(no subject)".to_string()
    } else {
        // chk_email_queue_subject_length: char_length(subject) <= 998
        truncate_subject_chars(&subject, MAX_SUBJECT_CHARS)
    }
}

/// `email_queue` CHECK constraint: char_length(subject) <= 998.
const MAX_SUBJECT_CHARS: usize = 998;

/// Truncate to at most `max_chars` CHARACTERS (never splitting a multi-byte
/// character). The DB CHECK is char_length-based; a byte-oriented slice on a
/// multibyte subject would panic at the char boundary.
fn truncate_subject_chars(subject: &str, max_chars: usize) -> String {
    if subject.chars().count() <= max_chars {
        subject.to_string()
    } else {
        subject.chars().take(max_chars).collect()
    }
}

/// Canonicalize recipient addresses for the suppression lookup (same shape
/// as the api-server's `canonical_email`: trim + lowercase).
fn canonical_recipients(rcpt_to: &[String]) -> Vec<String> {
    rcpt_to
        .iter()
        .map(|r| r.trim().to_ascii_lowercase())
        .collect()
}

/// Keep only recipients NOT present in the (lowercased) suppressed set.
fn filter_suppressed_recipients(rcpt_to: &[String], suppressed: &[String]) -> Vec<String> {
    let suppressed: std::collections::HashSet<&str> =
        suppressed.iter().map(|s| s.as_str()).collect();
    rcpt_to
        .iter()
        .filter(|r| !suppressed.contains(r.trim().to_ascii_lowercase().as_str()))
        .cloned()
        .collect()
}

async fn write_line<S: AsyncWrite + Unpin>(sink: &mut S, line: &str) -> std::io::Result<()> {
    sink.write_all(line.as_bytes()).await?;
    sink.flush().await
}

// ── tests ─────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};

    fn fixture_dir() -> String {
        format!("{}/tests/fixtures", env!("CARGO_MANIFEST_DIR"))
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

    fn test_peer(octet: u8) -> SocketAddr {
        format!("10.0.0.{octet}:2525").parse().unwrap()
    }

    fn test_server(tls_acceptor: Option<TlsAcceptor>) -> SubmissionServer {
        // connect_lazy: the URL is never actually connected in tests;
        // any real query fails and maps to AuthError::Failed (535). The
        // short acquire timeout keeps DB-touching tests fast.
        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .expect("lazy pool construction cannot fail with a well-formed URL");
        // Unroutable Redis: the durable lockout store degrades to the
        // in-memory fallback, which is what the lockout tests exercise.
        // A short create timeout keeps the failure fast (an OS-level TCP
        // timeout would otherwise stall every auth attempt by minutes).
        let redis = unroutable_redis_pool();
        let config = SubmissionConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 587,
            hostname: "submission.test".into(),
            max_message_size: 10 * 1024 * 1024,
            max_recipients: 100,
            auth_required: true,
        };
        let rate_limit = RateLimitConfig {
            enabled: true,
            max_connections_per_ip: 10,
            max_messages_per_connection: 100,
            max_recipients_per_message: 100,
        };
        SubmissionServer::new(config, rate_limit, pool, redis, tls_acceptor)
    }

    fn fixture_acceptor() -> TlsAcceptor {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let cert_pem = std::fs::read(format!("{}/cert.pem", fixture_dir())).unwrap();
        let key_pem = std::fs::read(format!("{}/key.pem", fixture_dir())).unwrap();
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&cert_pem[..]))
            .collect::<Result<_, _>>()
            .unwrap();
        let key = rustls_pemfile::private_key(&mut std::io::BufReader::new(&key_pem[..]))
            .unwrap()
            .unwrap();
        let config = tokio_rustls::rustls::ServerConfig::builder()
            .with_no_client_auth()
            .with_single_cert(certs, key)
            .unwrap();
        TlsAcceptor::from(Arc::new(config))
    }

    fn auth_plain_b64(user: &str, pass: &str) -> String {
        let payload = format!("\0{user}\0{pass}");
        BASE64.encode(payload.as_bytes())
    }

    async fn read_smtp_response<S: AsyncRead + AsyncWrite + Unpin>(
        stream: &mut BufStream<S>,
    ) -> String {
        let mut resp = String::new();
        loop {
            let mut line = String::new();
            if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
                break;
            }
            let multiline = line.len() >= 4 && line.as_bytes()[3] == b'-';
            resp.push_str(&line);
            if !multiline {
                break;
            }
        }
        resp
    }

    /// Drive one submission session: send each command, read the full
    /// (possibly multi-line) response, and assert it contains the
    /// expected substring. Ends with QUIT. Returns the transcript.
    async fn run_session(
        server: Arc<SubmissionServer>,
        peer: SocketAddr,
        allow_starttls: bool,
        already_tls: bool,
        steps: &[(&str, &str)],
    ) -> String {
        let (client, server_side) = tokio::io::duplex(32 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, peer, allow_starttls, already_tls)
                .await
        });
        let mut client_buf = BufStream::new(client);
        let mut transcript = String::new();
        for (cmd, expected) in steps {
            client_buf.write_all(cmd.as_bytes()).await.unwrap();
            client_buf.write_all(b"\r\n").await.unwrap();
            client_buf.flush().await.unwrap();
            let resp = read_smtp_response(&mut client_buf).await;
            transcript.push_str(&resp);
            assert!(
                resp.contains(expected),
                "expected {expected:?} in response, got {resp:?} (transcript: {transcript:?})"
            );
        }
        client_buf.write_all(b"QUIT\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        let _ = read_smtp_response(&mut client_buf).await;
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("session loop must finish")
            .expect("session loop must not panic");
        transcript
    }

    // ── FIX-2: AUTH must require TLS (port 587 STARTTLS gate) ────────────────

    #[tokio::test]
    async fn test_plaintext_ehlo_does_not_advertise_auth() {
        let server = Arc::new(test_server(None));
        let transcript = run_session(
            server,
            test_peer(1),
            true,
            false,
            &[("EHLO client.example", "250-")],
        )
        .await;
        assert!(
            !transcript.contains("AUTH"),
            "plaintext EHLO must not advertise AUTH: {transcript:?}"
        );
        assert!(
            transcript.contains("STARTTLS"),
            "plaintext EHLO must still advertise STARTTLS: {transcript:?}"
        );
    }

    #[tokio::test]
    async fn test_plaintext_auth_plain_refused_with_530() {
        let server = Arc::new(test_server(None));
        let b64 = auth_plain_b64("alice@example.com", "secret");
        run_session(
            server,
            test_peer(1),
            true,
            false,
            &[
                ("EHLO client.example", "250-"),
                (
                    &format!("AUTH PLAIN {b64}"),
                    "530 5.7.0 Must issue STARTTLS first",
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_plaintext_auth_login_refused_with_530() {
        let server = Arc::new(test_server(None));
        let user = BASE64.encode("alice@example.com");
        run_session(
            server,
            test_peer(1),
            true,
            false,
            &[
                ("EHLO client.example", "250-"),
                (
                    &format!("AUTH LOGIN {user}"),
                    "530 5.7.0 Must issue STARTTLS first",
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_tls_session_ehlo_advertises_auth_and_not_starttls() {
        let server = Arc::new(test_server(None));
        let transcript = run_session(
            server,
            test_peer(1),
            false,
            true,
            &[("EHLO client.example", "250-")],
        )
        .await;
        assert!(
            transcript.contains("AUTH PLAIN LOGIN"),
            "post-TLS EHLO must advertise AUTH: {transcript:?}"
        );
        assert!(
            !transcript.contains("STARTTLS"),
            "post-TLS EHLO must not advertise STARTTLS: {transcript:?}"
        );
    }

    #[tokio::test]
    async fn test_tls_session_auth_is_processed_not_gated() {
        // With TLS active the AUTH command must reach credential
        // verification (here the unreachable DB yields 535) instead of
        // being refused by the pre-TLS gate.
        let server = Arc::new(test_server(None));
        let b64 = auth_plain_b64("alice@example.com", "secret");
        run_session(
            server,
            test_peer(1),
            false,
            true,
            &[
                ("EHLO client.example", "250-"),
                (&format!("AUTH PLAIN {b64}"), "535"),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_mail_before_auth_still_refused_530() {
        // No regression: MAIL FROM before authentication keeps the
        // existing 530/503 behavior.
        let server = Arc::new(test_server(None));
        run_session(
            server,
            test_peer(1),
            false,
            true,
            &[
                ("EHLO client.example", "250-"),
                (
                    "MAIL FROM:<a@example.com>",
                    "530 5.7.0 Authentication required",
                ),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_full_starttls_upgrade_handshake_gates_auth() {
        let _ = tokio_rustls::rustls::crypto::ring::default_provider().install_default();
        let server = Arc::new(test_server(Some(fixture_acceptor())));
        let (client, server_side) = tokio::io::duplex(32 * 1024);

        let server_task = tokio::spawn({
            let server = server.clone();
            async move {
                let mut stream = BufStream::new(server_side);
                let _ = write_line(
                    &mut stream,
                    &format!(
                        "220 {} ESMTP ApexMail Submission\r\n",
                        server.config.hostname
                    ),
                )
                .await;
                let (starttls_requested, _) = server
                    .run_session_loop(&mut stream, test_peer(1), true, false)
                    .await;
                assert!(starttls_requested);
                let _ = write_line(&mut stream, "220 Go ahead\r\n").await;
                let _ = stream.flush().await;
                let inner = stream.into_inner();
                match server.tls_acceptor.as_ref().unwrap().accept(inner).await {
                    Ok(tls_stream) => {
                        let mut tls_buf = BufStream::new(TlsStream::from(tls_stream));
                        server
                            .run_session_loop(&mut tls_buf, test_peer(1), false, true)
                            .await;
                    }
                    Err(e) => panic!("STARTTLS handshake failed: {e}"),
                }
            }
        });

        let mut client_buf = BufStream::new(client);
        let greeting = read_smtp_response(&mut client_buf).await;
        assert!(greeting.contains("220"), "greeting: {greeting:?}");

        client_buf
            .write_all(b"EHLO client.example\r\n")
            .await
            .unwrap();
        client_buf.flush().await.unwrap();
        let ehlo_plain = read_smtp_response(&mut client_buf).await;
        assert!(ehlo_plain.contains("STARTTLS"));
        assert!(!ehlo_plain.contains("AUTH"));

        client_buf.write_all(b"STARTTLS\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        let starttls = read_smtp_response(&mut client_buf).await;
        assert!(starttls.contains("220 Go ahead"));

        let cert_pem = std::fs::read(format!("{}/cert.pem", fixture_dir())).unwrap();
        let mut roots = tokio_rustls::rustls::RootCertStore::empty();
        let certs: Vec<_> = rustls_pemfile::certs(&mut std::io::BufReader::new(&cert_pem[..]))
            .collect::<Result<_, _>>()
            .unwrap();
        roots.add(certs[0].clone()).unwrap();
        let client_config = tokio_rustls::rustls::ClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth();
        let connector = tokio_rustls::client::TlsConnector::from(Arc::new(client_config));
        let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from("localhost")
            .expect("localhost is a valid server name");
        let tls_client = connector
            .connect(server_name, client_buf.into_inner())
            .await
            .expect("client TLS handshake must succeed");
        let mut tls_buf = BufStream::new(tls_client);

        tls_buf.write_all(b"EHLO client.example\r\n").await.unwrap();
        tls_buf.flush().await.unwrap();
        let ehlo_tls = read_smtp_response(&mut tls_buf).await;
        assert!(
            ehlo_tls.contains("250-AUTH PLAIN LOGIN"),
            "post-STARTTLS EHLO must advertise AUTH: {ehlo_tls:?}"
        );
        assert!(!ehlo_tls.contains("STARTTLS"));

        let b64 = auth_plain_b64("alice@example.com", "secret");
        tls_buf
            .write_all(format!("AUTH PLAIN {b64}\r\n").as_bytes())
            .await
            .unwrap();
        tls_buf.flush().await.unwrap();
        let auth = read_smtp_response(&mut tls_buf).await;
        assert!(
            auth.contains("535"),
            "AUTH after STARTTLS must be processed (DB unreachable -> 535), got {auth:?}"
        );

        tls_buf.write_all(b"QUIT\r\n").await.unwrap();
        tls_buf.flush().await.unwrap();
        let _ = read_smtp_response(&mut tls_buf).await;
        tokio::time::timeout(Duration::from_secs(10), server_task)
            .await
            .expect("server task must finish")
            .expect("server task must not panic");
    }

    // ── FIX-3: lockout after repeated failures ───────────────────────────────

    #[tokio::test]
    async fn test_locked_account_rejected_with_454_even_with_credentials() {
        // 5 wrong passwords -> lockout; the 6th attempt (even with the
        // correct password) is rejected with 454 until the window passes.
        let server = Arc::new(test_server(None));
        let ip = test_peer(1).ip();
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ip, "alice@example.com")
                .await;
        }
        let b64 = auth_plain_b64("alice@example.com", "correct-password");
        run_session(
            server,
            test_peer(1),
            false,
            true,
            &[
                ("EHLO client.example", "250-"),
                (&format!("AUTH PLAIN {b64}"), "454"),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn repeated_failed_auth_attempts_hit_the_session_error_budget() {
        // AUTH failures are 4xx/5xx replies like any other: each increments
        // the session error budget, so MAX_SESSION_ERRORS bad attempts must
        // disconnect with 421 — a brute-forcer cannot hammer AUTH forever on
        // one connection. (After the lockout kicks in the reply becomes 454;
        // either way it counts toward the budget.)
        let server = Arc::new(test_server(None));
        let (client, server_side) = tokio::io::duplex(32 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, test_peer(8), false, true)
                .await
        });
        let mut client_buf = BufStream::new(client);

        client_buf
            .write_all(b"EHLO client.example\r\n")
            .await
            .unwrap();
        client_buf.flush().await.unwrap();
        assert!(read_smtp_response(&mut client_buf).await.starts_with("250"));

        let b64 = auth_plain_b64("alice@example.com", "wrong-password");
        for _ in 1..MAX_SESSION_ERRORS {
            client_buf
                .write_all(format!("AUTH PLAIN {b64}\r\n").as_bytes())
                .await
                .unwrap();
            client_buf.flush().await.unwrap();
            let resp = read_smtp_response(&mut client_buf).await;
            assert!(
                resp.starts_with("535") || resp.starts_with("454"),
                "each failed AUTH attempt must be an error reply, got {resp:?}"
            );
            assert_eq!(
                resp.lines().count(),
                1,
                "no 421 may arrive before the budget is exhausted: {resp:?}"
            );
        }

        // The MAX_SESSION_ERRORS-th failure still gets its own reply, then
        // the session closes with 421.
        client_buf
            .write_all(format!("AUTH PLAIN {b64}\r\n").as_bytes())
            .await
            .unwrap();
        client_buf.flush().await.unwrap();
        let resp = read_smtp_response(&mut client_buf).await;
        assert!(
            resp.starts_with("535") || resp.starts_with("454"),
            "final failed AUTH reply: {resp:?}"
        );
        let closing = read_smtp_response(&mut client_buf).await;
        assert_eq!(
            closing, "421 4.7.0 Too many errors, closing connection\r\n",
            "the session must close once the error budget is exhausted"
        );
        tokio::time::timeout(Duration::from_secs(30), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");
    }

    #[tokio::test]
    async fn test_lockout_is_per_account() {
        let server = Arc::new(test_server(None));
        let ip = test_peer(1).ip();
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ip, "bob@example.com")
                .await;
        }
        let b64 = auth_plain_b64("alice@example.com", "secret");
        run_session(
            server,
            test_peer(1),
            false,
            true,
            &[
                ("EHLO client.example", "250-"),
                (&format!("AUTH PLAIN {b64}"), "535"),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_lockout_is_per_ip() {
        let server = Arc::new(test_server(None));
        let locked_ip = test_peer(1).ip();
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(locked_ip, "alice@example.com")
                .await;
        }
        // The same account authenticating from a different IP is not locked.
        let b64 = auth_plain_b64("alice@example.com", "secret");
        run_session(
            server,
            test_peer(2),
            false,
            true,
            &[
                ("EHLO client.example", "250-"),
                (&format!("AUTH PLAIN {b64}"), "535"),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_unknown_email_attempts_count_toward_lockout() {
        // An unknown account is recorded under its own key, so brute
        // forcing nonexistent users cannot bypass the lockout.
        let server = Arc::new(test_server(None));
        let ip = test_peer(1).ip();
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ip, "ghost@example.com")
                .await;
        }
        let b64 = auth_plain_b64("ghost@example.com", "anything");
        run_session(
            server,
            test_peer(1),
            false,
            true,
            &[
                ("EHLO client.example", "250-"),
                (&format!("AUTH PLAIN {b64}"), "454"),
            ],
        )
        .await;
    }

    #[tokio::test]
    async fn test_auth_login_locked_account_rejected_with_454() {
        let server = Arc::new(test_server(None));
        let ip = test_peer(1).ip();
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ip, "alice@example.com")
                .await;
        }
        let user = BASE64.encode("alice@example.com");
        let pass = BASE64.encode("correct-password");
        run_session(
            server,
            test_peer(1),
            false,
            true,
            &[
                ("EHLO client.example", "250-"),
                (&format!("AUTH LOGIN {user}"), "334"),
                (&pass, "454"),
            ],
        )
        .await;
    }

    // ── B / E-3 / E-4 / F: smuggling, EHLO echo, subject cap, suppression ───

    /// Drive read_data_message over a duplex stream by writing the given raw
    /// bytes; the client half stays open so a premature EOF cannot truncate
    /// DATA before the payload's own terminator arrives.
    async fn drive_data(server: &SubmissionServer, payload: &[u8]) -> ReadDataOutcome {
        let (client, server_side) = tokio::io::duplex(64 * 1024);
        let mut writer = client;
        writer.write_all(payload).await.unwrap();
        writer.flush().await.unwrap();
        let mut stream = BufStream::new(server_side);
        let outcome = tokio::time::timeout(
            Duration::from_secs(10),
            server.read_data_message(&mut stream),
        )
        .await
        .expect("read_data_message must terminate");
        drop(writer);
        outcome
    }

    #[tokio::test]
    async fn bare_lf_dot_does_not_terminate_data() {
        let server = test_server(None);
        // A bare-LF "." line must be stored as body data (un-stuffed to an
        // empty line per RFC 5321 §4.5.2); only <CRLF>.<CRLF> terminates. A
        // smuggled QUIT line after it stays body data too.
        let payload = b"Subject: t\r\n\
                        .\n\
                        QUIT\r\n\
                        tail\r\n\
                        .\r\n";
        match drive_data(&server, payload).await {
            ReadDataOutcome::Message(data) => {
                let text = String::from_utf8_lossy(&data);
                // The bare-LF dot became an empty body line (dot stripped) —
                // it did NOT terminate DATA.
                assert!(
                    text.starts_with("Subject: t\r\n\r\n"),
                    "bare-LF dot line is body data (unstuffed to empty): {text:?}"
                );
                assert!(
                    text.contains("QUIT\r\n"),
                    "line after the bare-LF dot stays body data: {text:?}"
                );
                assert!(
                    text.ends_with("tail"),
                    "final CRLF belongs to terminator: {text:?}"
                );
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn space_padded_dot_lines_stay_body_data() {
        let server = test_server(None);
        // " ." / ". " / " . " must NOT terminate DATA (the old trim() check did).
        let payload = b"Subject: t\r\n .\r\n. \r\n . \r\n..\r\n.\r\n";
        match drive_data(&server, payload).await {
            ReadDataOutcome::Message(data) => {
                let text = String::from_utf8_lossy(&data);
                assert!(text.contains(" .\r\n"), "leading-space dot kept: {text:?}");
                assert!(text.contains(" . \r\n"), "padded dot kept: {text:?}");
                // ". " unstuffs to " " (exactly one dot removed); ".." (a
                // stuffed single dot) unstuffs to "." and stays body.
                assert!(
                    text.contains(" \r\n."),
                    "dot-space and stuffed-dot semantics: {text:?}"
                );
                assert!(
                    text.ends_with('.'),
                    "last body line is the unstuffed '..': {text:?}"
                );
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn dot_stuffing_round_trip_is_exact() {
        let server = test_server(None);
        // Sender-stuffed "..foo" → stored ".foo"; stuffed ".." → stored ".".
        // The final CRLF belongs to the <CRLF>.<CRLF> terminator, so the last
        // stored line has no trailing CRLF (re-sending adds it back).
        let payload = b"..foo\r\n..\r\n.\r\n";
        match drive_data(&server, payload).await {
            ReadDataOutcome::Message(data) => {
                assert_eq!(data.as_slice(), b".foo\r\n.".as_slice());
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn lf_only_body_lines_are_stored_with_crlf() {
        let server = test_server(None);
        // LF-only client line endings must be normalized to CRLF so the
        // relayed message cannot re-open the smuggling window downstream.
        let payload = b"Subject: t\nfirst\nsecond\n.\r\n";
        match drive_data(&server, payload).await {
            ReadDataOutcome::Message(data) => {
                assert_eq!(data.as_slice(), b"Subject: t\r\nfirst\r\nsecond".as_slice());
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn truncated_data_payload_is_aborted_not_queued() {
        let server = test_server(None);
        // Client disconnects mid-DATA without the terminator: the partial
        // payload must be discarded (Aborted), never queued.
        let (client, server_side) = tokio::io::duplex(4096);
        let mut writer = client;
        writer
            .write_all(b"Subject: half\r\nbody-so-far\r\n")
            .await
            .unwrap();
        writer.flush().await.unwrap();
        drop(writer);
        let mut stream = BufStream::new(server_side);
        let outcome = server.read_data_message(&mut stream).await;
        assert!(matches!(outcome, ReadDataOutcome::Aborted));
    }

    #[tokio::test]
    async fn oversized_message_is_refused_with_toolarge() {
        // max_message_size of 64 bytes: exceeding it must come back TooLarge
        // (never buffered wholesale), with the payload still drained.
        let pool = PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .unwrap();
        let config = SubmissionConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 587,
            hostname: "submission.test".into(),
            max_message_size: 64,
            max_recipients: 100,
            auth_required: true,
        };
        let rate_limit = RateLimitConfig {
            enabled: true,
            max_connections_per_ip: 10,
            max_messages_per_connection: 100,
            max_recipients_per_message: 100,
        };
        let redis = unroutable_redis_pool();
        let small = SubmissionServer::new(config, rate_limit, pool, redis, None);
        let big_line = "x".repeat(80);
        let payload = format!("{big_line}\r\n.\r\n").into_bytes();
        let outcome = drive_data(&small, &payload).await;
        assert!(
            matches!(outcome, ReadDataOutcome::TooLarge),
            "expected TooLarge, got {outcome:?}"
        );
    }

    #[tokio::test]
    async fn ehlo_argument_is_validated_before_echoing() {
        // E-3: an invalid EHLO argument must not be reflected verbatim.
        let server = Arc::new(test_server(None));
        let (client, server_side) = tokio::io::duplex(8 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, test_peer(3), false, true)
                .await
        });
        let mut client_buf = BufStream::new(client);
        client_buf
            .write_all(b"EHLO bad\x01host and junk\r\n")
            .await
            .unwrap();
        client_buf.flush().await.unwrap();
        let resp = read_smtp_response(&mut client_buf).await;
        assert!(
            resp.starts_with("501 5.5.4") && !resp.contains("bad\x01host"),
            "invalid EHLO arg must be rejected with 501 5.5.4, not echoed: {resp:?}"
        );
        // A valid hostname is still echoed.
        client_buf
            .write_all(b"EHLO client.example\r\n")
            .await
            .unwrap();
        client_buf.flush().await.unwrap();
        let resp = read_smtp_response(&mut client_buf).await;
        assert!(
            resp.contains("client.example"),
            "valid host echoed: {resp:?}"
        );
        client_buf.write_all(b"QUIT\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        let _ = read_smtp_response(&mut client_buf).await;
        drop(client_buf);
        let _ = tokio::time::timeout(Duration::from_secs(5), task).await;
    }

    // ── E-4: subject char cap ───────────────────────────────────────────────

    #[test]
    fn subject_truncation_is_char_safe_and_caps_at_998() {
        let ascii = "a".repeat(1200);
        assert_eq!(
            truncate_subject_chars(&ascii, MAX_SUBJECT_CHARS)
                .chars()
                .count(),
            998
        );

        // Multibyte: never splits a character.
        let multibyte = "\u{f6}".repeat(600); // 1200 bytes, 600 chars
        let truncated = truncate_subject_chars(&multibyte, MAX_SUBJECT_CHARS);
        assert!(truncated.chars().count() <= 998);
        assert!(truncated.chars().all(|c| c == '\u{f6}'));

        // Short subjects pass through unchanged.
        assert_eq!(truncate_subject_chars("hello", MAX_SUBJECT_CHARS), "hello");
    }

    #[test]
    fn extract_subject_truncates_to_998_chars() {
        let headers = format!("Subject: {}\r\n", "s".repeat(1500));
        assert_eq!(extract_subject(&headers).chars().count(), 998);
    }

    // ── F: suppression filtering (pure logic; the query mirrors api-server) ──

    #[test]
    fn canonical_recipients_trims_and_lowercases() {
        let rcpt = vec!["  Alice@Example.COM ".to_string(), "bob@example.com".into()];
        assert_eq!(
            canonical_recipients(&rcpt),
            vec!["alice@example.com", "bob@example.com"]
        );
    }

    #[test]
    fn filter_suppressed_recipients_drops_only_suppressed() {
        let rcpt = vec![
            "alice@example.com".to_string(),
            "BOB@example.com".to_string(),
            "carol@example.com".to_string(),
        ];
        let suppressed = vec!["bob@example.com".to_string()];
        let allowed = filter_suppressed_recipients(&rcpt, &suppressed);
        assert_eq!(allowed, vec!["alice@example.com", "carol@example.com"]);
        // All suppressed → empty queue payload (caller returns 550 5.1.1).
        let all = filter_suppressed_recipients(&rcpt[..1], &["alice@example.com".to_string()]);
        assert!(all.is_empty());
        // Empty suppression list keeps everything.
        assert_eq!(filter_suppressed_recipients(&rcpt, &[]), rcpt);
    }

    // ── RFC 2920 pipelining ────────────────────────────────────────────────

    #[tokio::test]
    async fn pipelined_commands_receive_ordered_replies() {
        // PIPELINING is advertised: a client that groups EHLO+NOOP+QUIT in
        // one TCP segment must get one reply per command, in order.
        let server = Arc::new(test_server(None));
        let (client, server_side) = tokio::io::duplex(32 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, test_peer(5), false, true)
                .await
        });
        let mut client_buf = BufStream::new(client);
        client_buf
            .write_all(b"EHLO client.example\r\nNOOP\r\nQUIT\r\n")
            .await
            .unwrap();
        client_buf.flush().await.unwrap();

        let ehlo = read_smtp_response(&mut client_buf).await;
        assert!(ehlo.contains("250-"), "EHLO reply: {ehlo:?}");
        assert!(
            ehlo.ends_with("250 SMTPUTF8\r\n"),
            "last capability line: {ehlo:?}"
        );

        let noop = read_smtp_response(&mut client_buf).await;
        assert_eq!(noop, "250 2.0.0 Ok\r\n", "NOOP reply must come second");

        let quit = read_smtp_response(&mut client_buf).await;
        assert_eq!(quit, "221 2.0.0 Bye\r\n", "QUIT reply must come third");

        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");
    }

    #[tokio::test]
    async fn starttls_before_ehlo_is_refused_with_503() {
        let server = Arc::new(test_server(Some(fixture_acceptor())));
        run_session(
            server,
            test_peer(6),
            true,
            false,
            &[("STARTTLS", "503 5.5.1 Error: send HELO/EHLO first")],
        )
        .await;
    }

    #[tokio::test]
    async fn oversized_command_line_cannot_smuggle_commands() {
        // A 100 KB line with QUIT smuggled inside it, then a valid NOOP +
        // QUIT: the drain must consume through the oversized line's newline
        // so the session survives and executes exactly the real commands.
        let server = Arc::new(test_server(None));
        let (client, server_side) = tokio::io::duplex(256 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, test_peer(7), false, true)
                .await
        });
        let mut client_buf = BufStream::new(client);
        let attack = format!("{}QUIT\r\n", "A".repeat(100 * 1024));
        client_buf.write_all(attack.as_bytes()).await.unwrap();
        client_buf.write_all(b"NOOP\r\n").await.unwrap();
        client_buf.flush().await.unwrap();

        let too_long = read_smtp_response(&mut client_buf).await;
        assert!(
            too_long.starts_with("500"),
            "oversized line refused: {too_long:?}"
        );
        let noop = read_smtp_response(&mut client_buf).await;
        assert!(
            noop.starts_with("250"),
            "NOOP after the oversized line must execute: {noop:?}"
        );

        client_buf.write_all(b"QUIT\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        let _ = read_smtp_response(&mut client_buf).await;
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");
    }

    // ── 8BITMIME / SMTPUTF8 advertisement-vs-enforcement consistency ──────

    #[tokio::test]
    async fn eight_bit_body_bytes_are_preserved_verbatim() {
        // DECISION (pinned): 8BITMIME stays advertised and is honoured —
        // body octets outside US-ASCII are stored byte-for-byte, never
        // mangled through a lossy UTF-8 decode.
        let server = test_server(None);
        let payload = b"Subject: 8bit\r\ncaf\xe9 na\xefve \xf6\r\n.\r\n";
        match drive_data(&server, payload).await {
            ReadDataOutcome::Message(data) => {
                assert_eq!(
                    &data[..],
                    b"Subject: 8bit\r\ncaf\xe9 na\xefve \xf6".as_slice(),
                    "8-bit body bytes must round-trip unchanged"
                );
            }
            other => panic!("expected Message, got {other:?}"),
        }
    }

    #[test]
    fn smtputf8_envelope_addresses_are_accepted() {
        // DECISION (pinned): SMTPUTF8 stays advertised and is honoured —
        // the envelope validator is charset-agnostic, so UTF-8 addresses
        // (RFC 6531) are accepted end-to-end.
        assert!(is_valid_envelope_address("p\u{f8}\u{fc}ser@example.com"));
        assert!(is_valid_envelope_address("user@\u{e4}example.com"));
        // ASCII addresses keep working, and structurally broken ones are
        // still refused regardless of charset.
        assert!(is_valid_envelope_address("plain@example.com"));
        assert!(!is_valid_envelope_address("p\u{f8}@nodot"));
        assert!(!is_valid_envelope_address("spaces in@example.com"));
    }

    #[test]
    fn envelope_addresses_over_320_octets_are_refused() {
        // RFC 5321 §4.5.3.1.1 caps the path; 320 octets is the generous
        // local(64)+domain(255) budget used across the codebase.
        let local = "a".repeat(320);
        assert!(!is_valid_envelope_address(&format!("{local}@example.com")));
        let fits = "a".repeat(300);
        assert!(is_valid_envelope_address(&format!("{fits}@example.com")));
    }

    // ── header/body split tolerance ────────────────────────────────────────

    #[test]
    fn split_headers_body_tolerates_double_blank_lines() {
        // Some clients emit an extra CRLF before the body; the split must
        // still find the header block and not treat headers as body.
        let raw = b"Subject: t\r\nFrom: a@b.com\r\n\r\n\r\nbody";
        let (headers, body) = split_headers_body(raw);
        assert!(String::from_utf8_lossy(headers).contains("Subject: t"));
        assert_eq!(body, b"\r\nbody");
        // LF-only variant is tolerated identically.
        let (headers, body) = split_headers_body(b"Subject: t\n\nbody");
        assert!(String::from_utf8_lossy(headers).contains("Subject: t"));
        assert_eq!(body, b"body");
        // No blank line at all: everything is headers, body empty.
        let (headers, body) = split_headers_body(b"Subject: only-headers");
        assert!(String::from_utf8_lossy(headers).contains("Subject:"));
        assert_eq!(body, b"");
        // Mixed flavours: the EARLIEST blank line wins (LF-only headers
        // followed by a CRLF body must not swallow body bytes into headers).
        let (headers, body) = split_headers_body(b"Subject: t\nX: 1\n\nbody\r\n\r\nrest");
        assert_eq!(headers, b"Subject: t\nX: 1");
        assert_eq!(body, b"body\r\n\r\nrest");
    }

    // ── F-10: 8-bit payloads survive the queue preparation ────────────────

    #[test]
    fn prepare_queue_payload_preserves_iso_8859_1_bytes() {
        // 8BITMIME is advertised: an ISO-8859-1 body (0xE9 = é, 0xEF = ï)
        // must reach the MIME parser as RAW BYTES so the parser decodes it
        // with the declared charset — never through a lossy UTF-8 decode
        // that would replace every high octet with U+FFFD. (The subject
        // uses legal RFC 6532 UTF-8, which also round-trips exactly.)
        let mut msg = Vec::new();
        msg.extend_from_slice(b"From: a@b.com\r\n");
        msg.extend_from_slice("Subject: caf\u{e9}\r\n".as_bytes()); // UTF-8 8-bit header
        msg.extend_from_slice(b"Content-Type: text/plain; charset=iso-8859-1\r\n");
        msg.extend_from_slice(b"\r\n");
        msg.extend_from_slice(b"caf\xe9 na\xefve\r\n");
        let payload = prepare_queue_payload(&msg);
        assert!(
            !payload.text_body.contains('\u{fffd}'),
            "8-bit body must not be mangled: {:?}",
            payload.text_body
        );
        assert!(
            payload.text_body.contains("caf\u{e9} na\u{ef}ve"),
            "parser decodes the declared charset: {:?}",
            payload.text_body
        );
        assert!(
            payload.subject.contains("caf\u{e9}"),
            "UTF-8 8-bit subject round-trips: {:?}",
            payload.subject
        );
        // The header/body split is byte-exact even with high octets in both.
        assert!(payload.headers.starts_with("From: a@b.com"));
    }

    #[test]
    fn prepare_queue_payload_falls_back_lossy_only_for_text_columns() {
        // Unparseable body (no Content-Type, invalid UTF-8): the fallback for
        // the TEXT column is lossy — but the mangling is confined to the
        // derived text, and the parser still saw the original bytes.
        let msg = b"Subject: t\r\n\r\nraw \xe9 bytes";
        let payload = prepare_queue_payload(msg);
        assert_eq!(payload.subject, "t");
        assert!(payload.text_body.contains("raw"));
        // A charset-less 8-bit SUBJECT header is not valid UTF-8: it decodes
        // best-effort (replacement chars). The DB column is TEXT, so this is
        // the ceiling for undeclared-charset headers; the body above shows
        // the charset-declared path is exact.
        let latin1_subject = b"Subject: caf\xe9\r\n\r\nbody";
        let payload = prepare_queue_payload(latin1_subject);
        assert!(payload.subject.contains("caf"), "{}", payload.subject);
    }

    #[test]
    fn eight_bit_submission_session_passes_bytes_to_queue_untouched() {
        // E2E byte-pipeline pin (the full session cannot authenticate against
        // the unreachable test DB, so the pipeline is composed from its two
        // real stages): DATA bytes as delivered by read_data_message (pinned
        // verbatim by eight_bit_body_bytes_are_preserved_verbatim) →
        // compose_stored_message (Received prepend) → prepare_queue_payload
        // (split + MIME parse feeding the queue columns). Every 0xE9/0xEF
        // octet must survive to the parsed columns — the old
        // String::from_utf8_lossy over the whole body replaced them with
        // U+FFFD here.
        let mut data = Vec::new();
        data.extend_from_slice(b"From: a@b.com\r\n");
        data.extend_from_slice("Subject: caf\u{e9}\r\n".as_bytes()); // UTF-8 8-bit header
        data.extend_from_slice(b"Content-Type: text/plain; charset=iso-8859-1\r\n");
        data.extend_from_slice(b"\r\n");
        data.extend_from_slice(b"caf\xe9 na\xefve\r\n");

        let received = build_received_header(
            "client.example",
            None,
            "10.0.0.9".parse().unwrap(),
            "submission.test",
            true,
            true,
            true,
            "0192f0a4-e2e",
        );
        let composed = compose_stored_message(&received, &data);
        assert!(composed.starts_with(b"Received: from client.example"));
        // The raw client bytes follow the trace header byte-for-byte.
        assert_eq!(&composed[composed.len() - data.len()..], &data[..]);

        let payload = prepare_queue_payload(&composed);
        // The trace header (and only it) lands in the headers column...
        assert!(payload
            .headers
            .starts_with("Received: from client.example (unknown [10.0.0.9])"));
        assert!(payload.headers.contains("with UTF8ESMTPSA id 0192f0a4-e2e"));
        // ...and the ISO-8859-1 body/subject decode via the declared charset
        // with zero U+FFFD replacement octets.
        assert!(
            !payload.text_body.contains('\u{fffd}'),
            "{:?}",
            payload.text_body
        );
        assert!(payload.text_body.contains("caf\u{e9} na\u{ef}ve"));
        assert!(payload.subject.contains("caf\u{e9}"));
    }

    #[test]
    fn prepare_queue_payload_extracts_attachments_and_custom_headers() {
        // Attachments and custom headers (List-Unsubscribe, X-Custom, folded
        // values) must reach the queue row — the worker rebuilds the outgoing
        // MIME exclusively from `headers`/`attachments`; losing them silently
        // deleted customer attachments on delivery.
        use base64::Engine as _;
        let png = base64::engine::general_purpose::STANDARD
            .decode("iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==")
            .unwrap();
        let mut msg = Vec::new();
        msg.extend_from_slice(b"From: a@b.com\r\n");
        msg.extend_from_slice(b"To: c@d.com\r\n");
        msg.extend_from_slice(b"Subject: with attachment\r\n");
        msg.extend_from_slice(b"Message-ID: <m1@b.com>\r\n");
        msg.extend_from_slice(
            b"List-Unsubscribe: <https://apexmail.ee/u/1>,\r\n\t<mailto:un@b.com>\r\n",
        );
        msg.extend_from_slice(b"X-Campaign: spring-launch\r\n");
        msg.extend_from_slice(b"MIME-Version: 1.0\r\n");
        msg.extend_from_slice(b"Content-Type: multipart/mixed; boundary=\"mix\"\r\n\r\n");
        msg.extend_from_slice(b"--mix\r\n");
        msg.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n\r\n");
        msg.extend_from_slice(b"hello\r\n");
        msg.extend_from_slice(b"--mix\r\n");
        msg.extend_from_slice(b"Content-Type: image/png; name=\"pixel.png\"\r\n");
        msg.extend_from_slice(b"Content-Disposition: attachment; filename=\"pixel.png\"\r\n");
        msg.extend_from_slice(b"Content-Transfer-Encoding: base64\r\n\r\n");
        msg.extend_from_slice(b"iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg==\r\n");
        msg.extend_from_slice(b"--mix--\r\n");

        let payload = prepare_queue_payload(&msg);

        let headers = payload.custom_headers.as_object().expect("object");
        assert_eq!(
            headers.get("list-unsubscribe").and_then(|v| v.as_str()),
            Some("<https://apexmail.ee/u/1>, <mailto:un@b.com>"),
            "folded header must be unfolded and preserved"
        );
        assert_eq!(
            headers.get("x-campaign").and_then(|v| v.as_str()),
            Some("spring-launch")
        );
        for protected in [
            "from",
            "to",
            "subject",
            "message-id",
            "mime-version",
            "content-type",
        ] {
            assert!(
                !headers.contains_key(protected),
                "{protected} must not be a custom header"
            );
        }

        let attachments = payload.attachments.as_array().expect("array");
        assert_eq!(attachments.len(), 1, "one attachment: {attachments:?}");
        let att = &attachments[0];
        assert_eq!(att["filename"], "pixel.png");
        assert_eq!(att["contentType"], "image/png");
        let decoded = base64::engine::general_purpose::STANDARD
            .decode(att["content"].as_str().unwrap())
            .unwrap();
        assert_eq!(decoded, png, "attachment bytes must round-trip exactly");
    }

    // ── queue-insert durability (item h) ───────────────────────────────────

    #[test]
    fn queue_insert_tx_pins_synchronous_commit_before_the_email_queue_insert() {
        // The 250 acknowledgement for a submitted message must not precede
        // the WAL flush of its email_queue row. The queue transaction pins
        // `SET LOCAL synchronous_commit = on` — immune to a relaxed
        // session/pool/server default — and does so BEFORE the
        // INSERT INTO email_queue. The unit suite has no live Postgres, so
        // the invariant is pinned against the compiled-in source itself.
        let source = include_str!("submission.rs");
        let begin_pos = source
            .find("self.pool.begin()")
            .expect("the queue path must run inside an explicit transaction");
        let set_pos = source
            .find("SET LOCAL synchronous_commit = on")
            .expect("the queue tx must pin synchronous_commit for the insert");
        let insert_pos = source
            .find("INSERT INTO email_queue (")
            .expect("the queue tx must insert into email_queue");
        assert!(
            begin_pos < set_pos,
            "SET LOCAL only applies inside a transaction — it must follow BEGIN"
        );
        assert!(
            set_pos < insert_pos,
            "synchronous_commit must be pinned before the email_queue insert"
        );
    }

    #[test]
    fn mime_parse_for_queue_payload_runs_on_the_blocking_pool() {
        // The MIME parse in prepare_queue_payload churns up to
        // max_message_size (10 MB) of bytes; running it on the session task
        // blocks an async worker thread and stalls every concurrent SMTP
        // session. The parse must be dispatched to the blocking pool
        // (pinned against the compiled-in source, same convention as the
        // synchronous_commit pin above). Needles are built with concat! so
        // this test never matches its own source text.
        let source = include_str!("submission.rs");
        let call_needle = std::concat!("prepare_queue_payload", "(&", "data", ")");
        let blocking_needle = std::concat!("spawn", "_blocking");
        let parse_pos = source
            .find(call_needle)
            .expect("the queue path must derive its payload via prepare_queue_payload");
        assert!(
            source[..parse_pos].contains(blocking_needle),
            "the blocking-pool dispatch must enclose the prepare_queue_payload call"
        );
    }

    // ── F-06: exact verb matching ──────────────────────────────────────────

    #[tokio::test]
    async fn database_and_mail_fromx_are_not_real_commands() {
        let server = Arc::new(test_server(None));
        let (client, server_side) = tokio::io::duplex(32 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, test_peer(11), false, true)
                .await
        });
        let mut client_buf = BufStream::new(client);

        client_buf
            .write_all(b"EHLO client.example\r\n")
            .await
            .unwrap();
        client_buf.flush().await.unwrap();
        assert!(read_smtp_response(&mut client_buf).await.starts_with("250"));

        client_buf.write_all(b"DATABASE\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        let resp = read_smtp_response(&mut client_buf).await;
        assert_eq!(
            resp, "500 5.5.2 Command not recognised\r\n",
            "DATABASE must not be treated as DATA"
        );

        // MAIL FROMX must not start a transaction (the old prefix match
        // accepted it): with EHLO seen, the syntax guard fires 501.
        client_buf
            .write_all(b"MAIL FROMX:<a@b.com>\r\n")
            .await
            .unwrap();
        client_buf.flush().await.unwrap();
        let resp = read_smtp_response(&mut client_buf).await;
        assert_eq!(
            resp, "501 5.5.4 Syntax: MAIL FROM:<address>\r\n",
            "MAIL FROMX must be a syntax error, got {resp:?}"
        );

        client_buf.write_all(b"QUIT\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        let _ = read_smtp_response(&mut client_buf).await;
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");
    }

    #[test]
    fn envelope_validator_rejects_double_at_and_control_chars() {
        // F-03: "a@@b.com" must fail the same validator inbound reuses.
        assert!(!is_valid_envelope_address("a@@b.com"));
        assert!(!is_valid_envelope_address("a\x01b@example.com"));
        assert!(!is_valid_envelope_address("a b@example.com"));
        assert!(is_valid_envelope_address("plain@example.com"));
        assert!(is_valid_envelope_address("p\u{f8}ser@example.com"));
    }

    // ── F-04/F-05: EHLO capability list and transaction reset ──────────────

    #[tokio::test]
    async fn ehlo_advertises_enhancedstatuscodes_and_keeps_sequencing() {
        // The transaction gates run before authentication in the loop, so
        // the behavioral nested-MAIL pin lives in the inbound command-level
        // suite (both servers share the rule); the EHLO capability list and
        // command sequencing are observable here pre-auth.
        let server = Arc::new(test_server(None));
        let (client, server_side) = tokio::io::duplex(32 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, test_peer(12), false, true)
                .await
        });
        let mut client_buf = BufStream::new(client);

        // EHLO works pre-auth.
        client_buf
            .write_all(b"EHLO client.example\r\n")
            .await
            .unwrap();
        client_buf.flush().await.unwrap();
        let caps = read_smtp_response(&mut client_buf).await;
        assert!(
            caps.contains("250-ENHANCEDSTATUSCODES\r\n"),
            "F-05: {caps:?}"
        );
        assert!(
            caps.ends_with("250 SMTPUTF8\r\n"),
            "last capability: {caps:?}"
        );

        // DATA without a transaction, pre-auth: the authentication gate
        // fires first (530), same ordering as before the verb rework.
        client_buf.write_all(b"DATA\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        assert!(read_smtp_response(&mut client_buf).await.starts_with("530"));

        // MAIL pre-auth: 530 (gate order kept).
        client_buf
            .write_all(b"MAIL FROM:<a@b.com>\r\n")
            .await
            .unwrap();
        client_buf.flush().await.unwrap();
        assert!(read_smtp_response(&mut client_buf).await.starts_with("530"));

        client_buf.write_all(b"QUIT\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        let _ = read_smtp_response(&mut client_buf).await;
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");
    }

    #[test]
    fn submission_source_pins_ehlo_reset_and_nested_mail_guard() {
        // The authenticated-path rules (EHLO resets the transaction; nested
        // MAIL → 503) are not reachable in the unit suite (no live DB to
        // authenticate against), so they are pinned against the compiled-in
        // source — same idiom as the synchronous_commit pin above.
        let source = include_str!("submission.rs");
        let ehlo_branch = source
            .find("if verb == \"EHLO\" || verb == \"HELO\"")
            .expect("EHLO branch");
        let mail_branch = source
            .find("} else if verb == \"MAIL\" {")
            .expect("MAIL branch");
        let nested_guard = source
            .find("503 5.5.1 Nested MAIL command")
            .expect("nested MAIL guard");
        assert!(
            ehlo_branch < mail_branch,
            "both branches live in the dispatch chain"
        );
        // The EHLO branch clears the transaction BEFORE the next branch starts.
        let reset = source[ehlo_branch..mail_branch]
            .find("mail_from = None;")
            .expect("EHLO must reset mail_from");
        assert!(reset > 0);
        // The nested guard sits inside the MAIL branch, before storing.
        assert!(nested_guard > mail_branch);
    }

    // ── F-08: bare-LF command lines ────────────────────────────────────────

    #[tokio::test]
    async fn bare_lf_command_line_is_refused_but_session_survives() {
        let server = Arc::new(test_server(None));
        let (client, server_side) = tokio::io::duplex(32 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, test_peer(13), false, true)
                .await
        });
        let mut client_buf = BufStream::new(client);

        client_buf.write_all(b"NOOP\n").await.unwrap();
        client_buf.flush().await.unwrap();
        assert_eq!(
            read_smtp_response(&mut client_buf).await,
            "500 5.5.2 Bare LF not allowed\r\n"
        );

        // The session continues; a properly terminated command works.
        client_buf.write_all(b"NOOP\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        assert_eq!(
            read_smtp_response(&mut client_buf).await,
            "250 2.0.0 Ok\r\n"
        );

        client_buf.write_all(b"QUIT\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        let _ = read_smtp_response(&mut client_buf).await;
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");
    }

    // ── F-14: error cap and unauthenticated session deadline ───────────────

    #[tokio::test]
    async fn twenty_error_replies_close_the_session() {
        let server = Arc::new(test_server(None));
        let (client, server_side) = tokio::io::duplex(32 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, test_peer(14), false, true)
                .await
        });
        let mut client_buf = BufStream::new(client);

        for i in 1..=MAX_SESSION_ERRORS {
            client_buf.write_all(b"FROBNICATE\r\n").await.unwrap();
            client_buf.flush().await.unwrap();
            let resp = read_smtp_response(&mut client_buf).await;
            assert_eq!(resp, "500 5.5.2 Command not recognised\r\n", "error #{i}");
        }
        // The 20th error is followed by 421 Too many errors and a close.
        assert_eq!(
            read_smtp_response(&mut client_buf).await,
            "421 4.7.0 Too many errors, closing connection\r\n"
        );
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");
    }

    #[tokio::test]
    async fn unauthenticated_session_deadline_is_enforced() {
        tokio::time::pause();
        let server = Arc::new(test_server(None));
        let (client, server_side) = tokio::io::duplex(32 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, test_peer(15), false, true)
                .await
        });
        let mut client_buf = BufStream::new(client);

        client_buf.write_all(b"NOOP\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        assert_eq!(
            read_smtp_response(&mut client_buf).await,
            "250 2.0.0 Ok\r\n"
        );

        // Advance past the 30-minute unauthenticated deadline.
        tokio::time::advance(SESSION_DEADLINE + Duration::from_secs(1)).await;

        client_buf.write_all(b"NOOP\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        assert_eq!(
            read_smtp_response(&mut client_buf).await,
            "421 4.7.0 Session deadline exceeded, closing connection\r\n"
        );
        tokio::time::resume();
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");
    }

    // ── F-12: "*" cancels the AUTH exchange ────────────────────────────────

    #[tokio::test]
    async fn auth_login_cancelled_with_star_replies_501() {
        let server = Arc::new(test_server(None));
        let (client, server_side) = tokio::io::duplex(32 * 1024);
        let task = tokio::spawn(async move {
            let mut server_buf = BufStream::new(server_side);
            server
                .run_session_loop(&mut server_buf, test_peer(16), false, true)
                .await
        });
        let mut client_buf = BufStream::new(client);
        client_buf
            .write_all(b"EHLO client.example\r\n")
            .await
            .unwrap();
        client_buf.flush().await.unwrap();
        let _ = read_smtp_response(&mut client_buf).await;

        client_buf.write_all(b"AUTH LOGIN\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        assert!(
            read_smtp_response(&mut client_buf).await.starts_with("334"),
            "username challenge"
        );
        client_buf.write_all(b"*\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        assert_eq!(
            read_smtp_response(&mut client_buf).await,
            "501 5.7.0 Authentication cancelled\r\n"
        );

        client_buf.write_all(b"QUIT\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        let _ = read_smtp_response(&mut client_buf).await;
        tokio::time::timeout(Duration::from_secs(10), task)
            .await
            .expect("session must finish")
            .expect("session must not panic");
    }

    // ── F-01: hop limit end-of-DATA refusal ────────────────────────────────

    #[test]
    fn data_with_forty_received_headers_exceeds_hop_limit() {
        // The session-level 550 5.4.6 reply is emitted between end-of-DATA
        // and the queue write; reaching it in the unit suite needs a live DB
        // (authentication), so the boundary is pinned on the exact payload
        // shape the loop feeds this helper (terminator included).
        let mut msg = Vec::new();
        for _ in 0..40 {
            msg.extend_from_slice(b"Received: hop\r\n");
        }
        msg.extend_from_slice(b"\r\nbody\r\n.\r\n");
        assert!(received_hop_limit_exceeded(&msg));

        let mut under = Vec::new();
        for _ in 0..39 {
            under.extend_from_slice(b"Received: hop\r\n");
        }
        under.extend_from_slice(b"\r\nbody\r\n.\r\n");
        assert!(!received_hop_limit_exceeded(&under));
    }

    #[test]
    fn received_trace_header_clauses_are_correct() {
        // Plain ESMTP hop (inbound shape, no TLS).
        let h = build_received_header(
            "mail.sender.example",
            Some("rev.example.com"),
            "192.0.2.10".parse().unwrap(),
            "mx.apexmail.ee",
            false,
            false,
            false,
            "inb_abc123",
        );
        assert!(h.starts_with("Received: from mail.sender.example (rev.example.com [192.0.2.10])"));
        assert!(h.contains("by mx.apexmail.ee with ESMTP id inb_abc123;"));
        // Exactly three physical lines (two folds).
        assert_eq!(h.matches("\r\n").count(), 2);

        // TLS leg → ESMTPS; unknown rDNS → "unknown".
        let tls = build_received_header(
            "mail.sender.example",
            None,
            "192.0.2.10".parse().unwrap(),
            "mx.apexmail.ee",
            true,
            false,
            false,
            "inb_abc124",
        );
        assert!(tls.contains("with ESMTPS id"));
        assert!(tls.contains("(unknown [192.0.2.10])"));

        // SMTPUTF8 + TLS + auth → UTF8-prefixed ESMTPSA.
        let utf8 = build_received_header(
            "mail.sender.example",
            None,
            "192.0.2.10".parse().unwrap(),
            "mx.apexmail.ee",
            true,
            true,
            true,
            "q-1",
        );
        assert!(utf8.contains("with UTF8ESMTPSA id"));
    }

    #[test]
    fn received_trace_header_rejects_crlf_injection_from_rdns() {
        // The rDNS value is DNS-derived; a hostile/odd PTR string with CR/LF
        // must collapse to "unknown" rather than split the header.
        let h = build_received_header(
            "mail.sender.example",
            Some("evil\r\nX-Injected: 1"),
            "192.0.2.10".parse().unwrap(),
            "mx.apexmail.ee",
            false,
            false,
            false,
            "inb_abc125",
        );
        assert!(!h.contains("X-Injected"));
        assert!(h.contains("(unknown [192.0.2.10])"));
        assert_eq!(h.matches("\r\n").count(), 2, "still exactly three lines");
    }

    #[test]
    fn validated_helo_hostname_can_never_inject_crlf() {
        // Pin the invariant the Received header relies on: any HELO argument
        // that passes is_valid_helo_hostname is free of CR/LF/controls.
        for junk in [
            "evil\r\nX-Injected: 1",
            "evil\nX-Injected: 1",
            "evil\rX: 1",
            "evil\x01junk",
            "evil junk",
        ] {
            assert!(
                !super::super::inbound::is_valid_helo_hostname(junk),
                "{junk:?} must never pass HELO validation"
            );
        }
        // And the shapes that DO pass are injection-free by construction.
        assert!(super::super::inbound::is_valid_helo_hostname(
            "mail.example.com"
        ));
        assert!(super::super::inbound::is_valid_helo_hostname("[127.0.0.1]"));
    }
}
