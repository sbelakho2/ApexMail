//! SMTP Submission server – accepts authenticated mail on port 587 for relaying.
//!
//! Supports AUTH PLAIN and AUTH LOGIN against the `users` table.
//! Supports STARTTLS when a TLS acceptor is provided.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dashmap::DashMap;
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::{TlsAcceptor, TlsStream};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::auth::{verify_against_dummy, AuthError, AuthFailTracker};
use crate::config::{RateLimitConfig, SubmissionConfig};

/// Maximum length of a single SMTP command line (RFC 5321 §4.5.3.1.4 limits
/// commands to 512 octets and lines to 1000; 4096 gives headroom for the
/// inline `AUTH PLAIN <base64>` payload while still bounding memory).
const MAX_COMMAND_LINE: usize = 4096;

/// After an over-long line, keep draining this many bytes looking for the
/// terminator so the session can resynchronise instead of closing.
const MAX_LINE_DRAIN: usize = 64 * 1024;

/// Per-read timeout for AUTH challenge/response lines (a silent client must
/// not hold the session forever).
const AUTH_LINE_TIMEOUT: Duration = Duration::from_secs(120);

/// Total deadline for receiving message DATA.
const DATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// Per-line timeout while receiving message DATA.
const DATA_LINE_TIMEOUT: Duration = Duration::from_secs(300);

/// Result of a capped line read.
enum LineRead {
    /// A full line (including trailing `\r\n`).
    Line(String),
    /// The line exceeded the cap; the terminator was still drained.
    TooLong,
    /// End of stream.
    Eof,
}

pub struct SubmissionServer {
    config: SubmissionConfig,
    rate_limit: RateLimitConfig,
    pool: PgPool,
    shutdown: Arc<Notify>,
    connections: Arc<DashMap<std::net::IpAddr, u32>>,
    auth_fail_tracker: AuthFailTracker,
    tls_acceptor: Option<TlsAcceptor>,
}

impl SubmissionServer {
    pub fn new(
        config: SubmissionConfig,
        rate_limit: RateLimitConfig,
        pool: PgPool,
        tls_acceptor: Option<TlsAcceptor>,
    ) -> Self {
        Self {
            config,
            rate_limit,
            pool,
            shutdown: Arc::new(Notify::new()),
            connections: Arc::new(DashMap::new()),
            auth_fail_tracker: AuthFailTracker::new(),
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
        self.track_connection(ip, true);

        let greeting = format!("220 {} ESMTP ApexMail Submission\r\n", self.config.hostname);
        let mut stream = BufStream::new(socket);
        if let Err(e) = write_line(&mut stream, &greeting).await {
            debug!(error = %e, peer = %peer, "Failed to send greeting");
            self.track_connection(ip, false);
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
                match acceptor.accept(inner).await {
                    Ok(tls_stream) => {
                        let mut tls_buf = BufStream::new(TlsStream::from(tls_stream));
                        self.run_session_loop(&mut tls_buf, peer, false, true).await;
                    }
                    Err(e) => debug!(error = %e, "STARTTLS handshake failed"),
                }
            }
        }

        self.track_connection(ip, false);
    }

    // ── Generic session loop (works over TCP or TLS) ─────────────────────
    // Returns (starttls_requested, message_count).

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
        let mut mail_from: Option<String> = None;
        let mut rcpt_to: Vec<String> = Vec::new();
        let mut message_count: u32 = 0;
        let mut line = String::new();
        let ip = peer.ip();

        loop {
            line.clear();
            let read = async { read_line_capped(stream, MAX_COMMAND_LINE).await };
            match tokio::time::timeout(Duration::from_secs(300), read).await {
                Err(_) => break,
                Ok(Ok(LineRead::Eof)) => break,
                Ok(Ok(LineRead::TooLong)) => {
                    let _ = write_line(stream, "500 5.5.2 Line too long\r\n").await;
                    continue;
                }
                Ok(Ok(LineRead::Line(l))) => line = l,
                Ok(Err(e)) => {
                    debug!(error = %e, peer = %peer, "Read error");
                    break;
                }
            }

            // IMPORTANT: Only uppercase the command verb, NOT the arguments.
            // Base64 payloads in AUTH PLAIN are case-sensitive — uppercasing
            // the entire line corrupts the credentials.
            let trimmed = line.trim();
            let cmd_upper = trimmed.to_uppercase();
            let cmd = cmd_upper.as_str();

            if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                helo_seen = true;
                let host = line.split_whitespace().nth(1).unwrap_or("unknown");
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
                caps.push_str("250 SMTPUTF8\r\n");
                let _ = write_line(stream, &caps).await;
            } else if cmd == "STARTTLS" && allow_starttls && !already_tls {
                return (true, message_count);
            } else if cmd == "STARTTLS" {
                let _ = write_line(stream, "454 TLS not available\r\n").await;
            } else if cmd.starts_with("AUTH LOGIN") || cmd.starts_with("AUTH PLAIN") {
                if !helo_seen {
                    // RFC 4954 §4: AUTH must not be used before EHLO.
                    let _ = write_line(stream, "503 5.5.1 Send EHLO first\r\n").await;
                } else if !already_tls {
                    // FIX-2: refuse AUTH on a plaintext session — the
                    // credentials would traverse the network in cleartext.
                    let _ = write_line(stream, "530 5.7.0 Must issue STARTTLS first\r\n").await;
                } else if authenticated {
                    let _ = write_line(stream, "503 5.5.1 Already authenticated\r\n").await;
                } else if cmd.starts_with("AUTH LOGIN") {
                    if let Some((email, _account_id)) =
                        self.handle_auth_login(stream, trimmed, ip).await
                    {
                        authenticated = true;
                        auth_email = email;
                    }
                } else if let Some((email, _account_id)) =
                    self.handle_auth_plain(stream, trimmed, ip).await
                {
                    authenticated = true;
                    auth_email = email;
                }
            } else if cmd.starts_with("MAIL FROM") {
                if !helo_seen {
                    let _ = write_line(stream, "503 5.5.1 Send EHLO first\r\n").await;
                } else if !authenticated {
                    let _ = write_line(stream, "530 5.7.0 Authentication required\r\n").await;
                } else {
                    // Store only the envelope address, not the full command line.
                    let addr = extract_address(trimmed);
                    if !is_valid_envelope_address(&addr) {
                        // RFC 6409: a submission server must reject messages with a
                        // null/invalid reverse-path; email_queue.from_address also
                        // enforces a valid-address CHECK constraint.
                        let _ = write_line(stream, "553 5.1.7 Sender address required\r\n").await;
                    } else {
                        mail_from = Some(addr);
                        let _ = write_line(stream, "250 OK\r\n").await;
                    }
                }
            } else if cmd.starts_with("RCPT TO") {
                if !helo_seen {
                    let _ = write_line(stream, "503 5.5.1 Send EHLO first\r\n").await;
                } else if !authenticated {
                    let _ = write_line(stream, "530 5.7.0 Authentication required\r\n").await;
                } else if rcpt_to.len() >= self.config.max_recipients {
                    let _ = write_line(stream, "452 4.5.3 Too many recipients\r\n").await;
                } else {
                    // Store only the recipient address, not the full command line.
                    let addr = extract_address(trimmed);
                    if !is_valid_envelope_address(&addr) {
                        let _ =
                            write_line(stream, "501 5.1.3 Bad recipient address syntax\r\n").await;
                    } else {
                        rcpt_to.push(addr);
                        let _ = write_line(stream, "250 OK\r\n").await;
                    }
                }
            } else if cmd.starts_with("DATA") {
                if !helo_seen {
                    let _ = write_line(stream, "503 5.5.1 Send EHLO first\r\n").await;
                } else if !authenticated {
                    let _ = write_line(stream, "530 5.7.0 Authentication required\r\n").await;
                } else if mail_from.is_none() || rcpt_to.is_empty() {
                    let _ = write_line(stream, "503 5.5.1 Need MAIL and RCPT first\r\n").await;
                } else {
                    let _ = write_line(stream, "354 Start mail input; end with <CRLF>.<CRLF>\r\n")
                        .await;

                    // Receive the message body with:
                    //  - a total deadline (slow-loris protection),
                    //  - a per-line timeout,
                    //  - an overall size cap enforced BEFORE buffering (552),
                    //  - dot-unstuffing, and no queueing of partial DATA on
                    //    client disconnect.
                    let mut data = Vec::new();
                    let mut buf = String::new();
                    let mut too_large = false;
                    let mut timed_out = false;
                    let mut terminated = false;
                    let deadline = Instant::now() + DATA_TOTAL_TIMEOUT;
                    loop {
                        buf.clear();
                        let remaining = deadline
                            .checked_duration_since(Instant::now())
                            .unwrap_or(Duration::ZERO);
                        if remaining.is_zero() {
                            timed_out = true;
                            break;
                        }
                        let per_line = remaining.min(DATA_LINE_TIMEOUT);
                        match tokio::time::timeout(per_line, stream.read_line(&mut buf)).await {
                            Err(_) => {
                                timed_out = true;
                                break;
                            }
                            Ok(Ok(0)) => break, // client disconnected mid-DATA
                            Ok(Ok(_)) => {
                                if buf.trim_end_matches(['\r', '\n']) == "." {
                                    terminated = true;
                                    break;
                                }
                                if too_large {
                                    // Drain the rest without buffering.
                                    continue;
                                }
                                // RFC 5321 §4.5.2: un-stuff transparently-doubled dots.
                                let data_slice = if let Some(rest) = buf.strip_prefix("..") {
                                    rest
                                } else {
                                    &buf[..]
                                };
                                if data.len() + data_slice.len() > self.config.max_message_size {
                                    too_large = true;
                                    data.clear();
                                } else {
                                    data.extend_from_slice(data_slice.as_bytes());
                                }
                            }
                            Ok(Err(_)) => break,
                        }
                    }

                    if timed_out {
                        let _ = write_line(stream, "421 4.4.2 Data timeout exceeded\r\n").await;
                        break;
                    }

                    if too_large {
                        // RFC 5321 §4.5.3.2: message exceeds the SIZE limit.
                        let _ = write_line(stream, "552 5.3.4 Message too large\r\n").await;
                        mail_from = None;
                        rcpt_to.clear();
                        continue;
                    }

                    if terminated {
                        if data.last() == Some(&b'\n') {
                            data.pop();
                            if data.last() == Some(&b'\r') {
                                data.pop();
                            }
                        }
                        let data_str = String::from_utf8_lossy(&data);
                        let msg_id = Uuid::new_v4().to_string();
                        match self
                            .queue_message(
                                &auth_email,
                                mail_from.as_deref().unwrap_or(""),
                                &rcpt_to,
                                &data_str,
                                &msg_id,
                            )
                            .await
                        {
                            Ok(_) => {
                                message_count += 1;
                                let _ =
                                    write_line(stream, &format!("250 OK id={}\r\n", msg_id)).await;
                                if message_count >= self.rate_limit.max_messages_per_connection {
                                    let _ = write_line(
                                        stream,
                                        "421 4.7.0 Too many messages, closing connection\r\n",
                                    )
                                    .await;
                                    break;
                                }
                            }
                            Err(_) => {
                                let _ =
                                    write_line(stream, "451 4.3.0 Requested action aborted\r\n")
                                        .await;
                            }
                        }
                        mail_from = None;
                        rcpt_to.clear();
                    }
                }
            } else if cmd.starts_with("RSET") {
                mail_from = None;
                rcpt_to.clear();
                let _ = write_line(stream, "250 OK\r\n").await;
            } else if cmd.starts_with("NOOP") {
                let _ = write_line(stream, "250 OK\r\n").await;
            } else if cmd.starts_with("QUIT") {
                let _ = write_line(stream, "221 Bye\r\n").await;
                break;
            } else if cmd.starts_with("HELP") {
                let _ = write_line(
                    stream,
                    "214 Supported: EHLO HELO AUTH MAIL RCPT DATA RSET NOOP QUIT\r\n",
                )
                .await;
            } else {
                let _ = write_line(stream, "502 5.5.1 Command not recognised\r\n").await;
            }
        }

        debug!(
            peer = %peer,
            authenticated = authenticated,
            messages = message_count,
            "Submission session ended"
        );
        (false, message_count)
    }

    /// `AUTH LOGIN` two-step (plus optional inline username): prompt for
    /// base64 username then password, verify, and always send a terminating
    /// reply (never leave the client hanging). Returns the authenticated
    /// email on success.
    async fn handle_auth_login<S: AsyncRead + AsyncWrite + Unpin>(
        self: &Arc<Self>,
        stream: &mut BufStream<S>,
        trimmed: &str,
        ip: std::net::IpAddr,
    ) -> Option<(String, Uuid)> {
        // Optional inline initial response: "AUTH LOGIN <base64-username>".
        let inline_user = trimmed
            .strip_prefix("AUTH LOGIN")
            .or_else(|| trimmed.strip_prefix("auth login"))
            .unwrap_or(trimmed)
            .trim();
        let user_b64: String = if !inline_user.is_empty() {
            inline_user.to_string()
        } else {
            let _ = write_line(stream, "334 VXNlcm5hbWU6\r\n").await;
            self.read_auth_line(stream).await?
        };

        let _ = write_line(stream, "334 UGFzc3dvcmQ6\r\n").await;
        let pass_b64 = self.read_auth_line(stream).await?;

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
                        Some((email, account_id))
                    }
                    Err(AuthError::LockedOut) => {
                        let _ = write_line(
                            stream,
                            "454 4.7.0 Too many failed authentication attempts\r\n",
                        )
                        .await;
                        None
                    }
                    Err(AuthError::Failed) => {
                        let _ = write_line(stream, "535 5.7.8 Authentication failed\r\n").await;
                        None
                    }
                }
            }
            _ => {
                let _ = write_line(stream, "501 5.5.2 Invalid base64\r\n").await;
                None
            }
        }
    }

    /// `AUTH PLAIN` inline or two-step. Always sends a terminating reply,
    /// including for payloads that decode to fewer than three NUL-separated
    /// fields (previously the client hung forever in that case). Returns the
    /// authenticated email on success.
    async fn handle_auth_plain<S: AsyncRead + AsyncWrite + Unpin>(
        self: &Arc<Self>,
        stream: &mut BufStream<S>,
        trimmed: &str,
        ip: std::net::IpAddr,
    ) -> Option<(String, Uuid)> {
        // Use the ORIGINAL line (not uppercased) to preserve base64 case.
        let inline_b64 = trimmed
            .strip_prefix("AUTH PLAIN")
            .or_else(|| trimmed.strip_prefix("auth plain"))
            .unwrap_or(trimmed)
            .trim();
        let auth_b64: String = if !inline_b64.is_empty() {
            inline_b64.to_string()
        } else {
            let _ = write_line(stream, "334 \r\n").await;
            self.read_auth_line(stream).await?
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
                            Some((email, account_id))
                        }
                        Err(AuthError::LockedOut) => {
                            let _ = write_line(
                                stream,
                                "454 4.7.0 Too many failed authentication attempts\r\n",
                            )
                            .await;
                            None
                        }
                        Err(AuthError::Failed) => {
                            let _ = write_line(stream, "535 5.7.8 Authentication failed\r\n").await;
                            None
                        }
                    }
                } else {
                    // Malformed authcid (fewer than three NUL fields).
                    let _ = write_line(stream, "535 5.7.8 Authentication failed\r\n").await;
                    None
                }
            }
            _ => {
                let _ = write_line(stream, "501 5.5.2 Invalid base64\r\n").await;
                None
            }
        }
    }

    /// Read one AUTH response line with a timeout and a line-length cap.
    async fn read_auth_line<S: AsyncRead + AsyncWrite + Unpin>(
        &self,
        stream: &mut BufStream<S>,
    ) -> Option<String> {
        match tokio::time::timeout(
            AUTH_LINE_TIMEOUT,
            read_line_capped(stream, MAX_COMMAND_LINE),
        )
        .await
        {
            Ok(Ok(LineRead::Line(l))) => Some(l),
            Ok(Ok(LineRead::TooLong)) => {
                let _ = write_line(stream, "500 5.5.2 Line too long\r\n").await;
                None
            }
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
        if self.auth_fail_tracker.is_locked(ip, email) {
            return Err(AuthError::LockedOut);
        }

        let user = sqlx::query_as::<_, (String, Uuid, String, String)>(
            "SELECT email, id, password_hash, status FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)",
        )
        .bind(email)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| AuthError::Failed)?;

        let (user_email, user_id, password_hash, status) = match user {
            Some(u) => u,
            None => {
                // FIX-3: unknown-account attempts count toward the
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

        // verify_password_for_login accepts both Argon2id and legacy bcrypt
        // hashes (the users table contains bcrypt rows created before the
        // Argon2id migration). On successful bcrypt login it returns an
        // Argon2id replacement hash, which we persist so the row migrates.
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
                Ok((user_email, user_id))
            }
            _ => {
                self.auth_fail_tracker.record_failure(ip, email);
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
    async fn queue_message(
        &self,
        auth_email: &str,
        mail_from: &str,
        rcpt_to: &[String],
        data: &str,
        msg_id: &str,
    ) -> Result<(), ()> {
        // Split the raw message into headers and body so the queue stores them
        // separately (the queue has no raw_mime column).
        let (headers_part, body_part) = split_headers_body(data);

        // Parse the MIME content so the worker's html/text columns are
        // populated (the worker builds the outgoing message from them).
        let parsed = mail_parser::MessageParser::default().parse(data.as_bytes());
        let subject = parsed
            .as_ref()
            .and_then(|m| m.subject())
            .map(|s| s.to_string())
            .unwrap_or_else(|| extract_subject(headers_part));
        let html_body = parsed
            .as_ref()
            .and_then(|m| m.body_html(0))
            .map(|b| b.into_owned());
        let text_body = parsed
            .as_ref()
            .and_then(|m| m.body_text(0))
            .map(|b| b.into_owned())
            .filter(|b| !b.is_empty())
            .unwrap_or_else(|| body_part.to_string());

        // subject is NOT NULL in email_queue (max length 998 per CHECK).
        let subject = if subject.is_empty() {
            "(no subject)".to_string()
        } else {
            subject
        };

        // tenant_id is VARCHAR(26) referencing tenants(id) — never the user's
        // account UUID. Look up the authenticated user's actual tenant.
        let tenant_id: Option<String> = sqlx::query_scalar(
            "SELECT tenant_id FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)",
        )
        .bind(auth_email)
        .bind(auth_email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ())?
        .flatten();

        // domain_id is UUID referencing domains(id); resolve the sender's
        // domain owned by the user's tenant so the worker can route/DKIM-sign.
        let domain_id: Option<Uuid> = match tenant_id.as_deref() {
            Some(tenant) => {
                let domain_name = mail_from
                    .rsplit_once('@')
                    .map(|(_, d)| d)
                    .unwrap_or_default();
                if domain_name.is_empty() {
                    None
                } else {
                    sqlx::query_scalar(
                        "SELECT id FROM domains WHERE LOWER(name) = LOWER($1) AND tenant_id = $2 LIMIT 1",
                    )
                    .bind(domain_name)
                    .bind(tenant)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(|_| ())?
                }
            }
            None => None,
        };

        let message_uuid = Uuid::parse_str(msg_id).map_err(|_| ())?;
        let to_first = rcpt_to.first().cloned().unwrap_or_default();

        sqlx::query(
            r#"INSERT INTO email_queue (
                id, from_address, to_addresses, subject, raw_headers, text_body,
                "from", "to", html, text, status, priority, tenant_id, message_id,
                domain_id, metadata, created_at, updated_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending', 5,
                      $11, $12, $13, $14, NOW(), NOW())"#,
        )
        .bind(message_uuid)
        .bind(mail_from)
        .bind(rcpt_to)
        .bind(&subject)
        .bind(headers_part)
        .bind(&text_body)
        .bind(mail_from)
        .bind(&to_first)
        .bind(&html_body)
        .bind(&text_body)
        .bind(tenant_id)
        .bind(message_uuid)
        .bind(domain_id)
        .bind(Option::<serde_json::Value>::None)
        .execute(&self.pool)
        .await
        .map_err(|_| ())?;

        info!(
            message_id = %msg_id,
            from = %mail_common::pii::redact_email(mail_from),
            to = ?rcpt_to,
            size = data.len(),
            "Message queued via submission"
        );
        Ok(())
    }

    fn track_connection(&self, ip: std::net::IpAddr, incr: bool) {
        if incr {
            self.connections
                .entry(ip)
                .and_modify(|c| *c += 1)
                .or_insert(1);
        } else {
            self.connections.entry(ip).and_modify(|c| {
                if *c > 0 {
                    *c -= 1;
                }
            });
        }
    }
}

// ── I/O helpers ─────────────────────────────────────────────────────────

/// Read one line with a hard cap on its length. When the cap is exceeded,
/// the remainder of the line is drained (up to `MAX_LINE_DRAIN` bytes) so
/// the session can stay synchronised, then `LineRead::TooLong` is returned.
async fn read_line_capped<S: AsyncRead + AsyncWrite + Unpin>(
    stream: &mut BufStream<S>,
    cap: usize,
) -> std::io::Result<LineRead> {
    use tokio::io::AsyncBufReadExt;
    let mut line = Vec::with_capacity(128);
    let mut too_long = false;
    let mut drained = 0usize;
    loop {
        // Scope the borrow so `buf` is dropped before `stream.consume`.
        let action = {
            let buf = stream.fill_buf().await?;
            if buf.is_empty() {
                if line.is_empty() && !too_long {
                    return Ok(LineRead::Eof);
                }
                // EOF mid-line: return what we have.
                Action::Done
            } else if let Some(pos) = buf.iter().position(|&b| b == b'\n') {
                let take = pos + 1;
                if line.len() + take > cap {
                    too_long = true;
                    line.clear();
                } else if !too_long {
                    line.extend_from_slice(&buf[..take]);
                }
                // A newline-terminated line is complete — return now.
                // (Action::Return breaks after consuming; looping back to
                // fill_buf() would block until MORE data arrives, hanging
                // the session while the client waits for a reply.)
                Action::Return(take)
            } else if too_long {
                drained += buf.len();
                if drained > MAX_LINE_DRAIN {
                    Action::GiveUp
                } else {
                    Action::Consume(buf.len())
                }
            } else if line.len() + buf.len() > cap {
                too_long = true;
                line.clear();
                Action::Consume(buf.len())
            } else {
                line.extend_from_slice(buf);
                Action::Consume(buf.len())
            }
        };
        match action {
            Action::Done => break,
            Action::Return(n) => {
                stream.consume(n);
                break;
            }
            Action::GiveUp => return Ok(LineRead::TooLong),
            Action::Consume(n) => stream.consume(n),
        }
    }
    if too_long {
        Ok(LineRead::TooLong)
    } else {
        Ok(LineRead::Line(String::from_utf8_lossy(&line).into_owned()))
    }
}

enum Action {
    Done,
    Return(usize),
    Consume(usize),
    GiveUp,
}

/// Extract the bare address from an SMTP command line such as
/// `RCPT TO:<user@example.com>` or `MAIL FROM: user@example.com`.
/// Only the address path is returned — trailing parameters such as
/// `SIZE=1000` are never part of the address.
fn extract_address(line: &str) -> String {
    // Prefer the explicit angle-bracketed path.
    if let Some(start) = line.find('<') {
        if let Some(end) = line[start + 1..].find('>') {
            return line[start + 1..start + 1 + end].to_string();
        }
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

/// Validate an envelope address against the same rules `email_queue` enforces
/// (`chk_email_queue_from_address`): no whitespace, one `@`, a non-empty local
/// part, and a non-empty domain containing at least one dot.
fn is_valid_envelope_address(addr: &str) -> bool {
    if addr.is_empty() || addr.chars().any(char::is_whitespace) {
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
fn split_headers_body(raw: &str) -> (&str, &str) {
    if let Some(sep) = raw.find("\r\n\r\n") {
        (&raw[..sep], &raw[sep + 4..])
    } else if let Some(sep) = raw.find("\n\n") {
        (&raw[..sep], &raw[sep + 2..])
    } else {
        (raw, "")
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
        subject.chars().take(998).collect()
    }
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
        SubmissionServer::new(config, rate_limit, pool, tls_acceptor)
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
                .record_failure(ip, "alice@example.com");
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
    async fn test_lockout_is_per_account() {
        let server = Arc::new(test_server(None));
        let ip = test_peer(1).ip();
        for _ in 0..5 {
            server
                .auth_fail_tracker
                .record_failure(ip, "bob@example.com");
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
                .record_failure(locked_ip, "alice@example.com");
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
                .record_failure(ip, "ghost@example.com");
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
                .record_failure(ip, "alice@example.com");
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
}
