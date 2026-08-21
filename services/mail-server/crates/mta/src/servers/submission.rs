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
use tokio::io::{AsyncRead, AsyncWrite, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::{TlsAcceptor, TlsStream};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::auth::{verify_against_dummy, AuthError, AuthFailTracker};
use crate::config::{RateLimitConfig, SubmissionConfig};

use super::util::{
    is_strict_end_of_data, line_content, read_line_capped, unstuff_dot_line, LineRead,
    MAX_COMMAND_LINE, MAX_DATA_LINE,
};

/// Per-read timeout for AUTH challenge/response lines (a silent client must
/// not hold the session forever).
const AUTH_LINE_TIMEOUT: Duration = Duration::from_secs(120);

/// Total deadline for receiving message DATA.
const DATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// Per-line timeout while receiving message DATA.
const DATA_LINE_TIMEOUT: Duration = Duration::from_secs(300);

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

        // Admission control: per-IP connection cap (mirrors the inbound
        // server's gate; without it `connections` is tracked but never
        // enforced, so one IP may hold unlimited concurrent sessions).
        let active = self.connections.get(&ip).map(|c| *c).unwrap_or(0);
        if self.rate_limit.enabled && active >= self.rate_limit.max_connections_per_ip {
            let mut stream = BufStream::new(socket);
            let _ = write_line(
                &mut stream,
                "421 4.7.0 Too many connections from your IP\r\n",
            )
            .await;
            return;
        }

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
                Ok(Ok(LineRead::Line(l, _))) => line = l,
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
                // E-3:validate the EHLO argument before echoing it back —
                // an unvalidated argument used to be reflected verbatim into
                // the greeting (CRLF/control payloads included).
                let host = line
                    .split_whitespace()
                    .nth(1)
                    .filter(|host| super::inbound::is_valid_helo_hostname(host))
                    .unwrap_or("unknown");
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

                    match self.read_data_message(stream).await {
                        ReadDataOutcome::TimedOut => {
                            let _ =
                                write_line(stream, "421 4.4.2 Data timeout exceeded\r\n").await;
                            break;
                        }
                        ReadDataOutcome::Aborted => {
                            // Client disconnected / stream failed mid-DATA: the
                            // partial payload is discarded and never queued.
                            break;
                        }
                        ReadDataOutcome::TooLarge => {
                            // RFC 5321 §4.5.3.2: message exceeds the SIZE limit.
                            let _ = write_line(stream, "552 5.3.4 Message too large\r\n").await;
                            mail_from = None;
                            rcpt_to.clear();
                            continue;
                        }
                        ReadDataOutcome::Message(data) => {
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
                                Ok(QueueOutcome::Queued) => {
                                    message_count += 1;
                                    let _ = write_line(
                                        stream,
                                        &format!("250 OK id={}\r\n", msg_id),
                                    )
                                    .await;
                                    if message_count
                                        >= self.rate_limit.max_messages_per_connection
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
                                    let _ = write_line(
                                        stream,
                                        "550 5.7.1 sender address not owned by account\r\n",
                                    )
                                    .await;
                                }
                                Ok(QueueOutcome::SenderNotReady) => {
                                    let _ = write_line(
                                        stream,
                                        "550 5.7.1 sender domain is not verified and ready for delivery\r\n",
                                    )
                                    .await;
                                }
                                Ok(QueueOutcome::RecipientSuppressed) => {
                                    let _ = write_line(
                                        stream,
                                        "550 5.1.1 recipient address suppressed\r\n",
                                    )
                                    .await;
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
        let mut line = String::new();
        let mut too_large = false;
        let deadline = Instant::now() + DATA_TOTAL_TIMEOUT;
        loop {
            line.clear();
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
                    // drained, keep reading (without buffering) until the
                    // terminator so the session stays synchronised and can be
                    // refused with 552.
                    too_large = true;
                    data.clear();
                }
                Ok(Ok(LineRead::Line(l, term))) => {
                    line = l;
                    if is_strict_end_of_data(&line, term) {
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
                    let data_slice = unstuff_dot_line(line_content(&line, term));
                    if data.len() + data_slice.len() + 2 > self.config.max_message_size {
                        too_large = true;
                        data.clear();
                    } else {
                        data.extend_from_slice(data_slice.as_bytes());
                        data.extend_from_slice(b"\r\n");
                    }
                }
            }
        }
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
            Ok(Ok(LineRead::Line(l, _))) => Some(l),
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

        // NOTE: `users` has no `username` column (only smtp_credentials does),
        // so the lookup is by email only — identical to the api-server login
        // path.
        let user = sqlx::query_as::<_, (String, Uuid, String, String)>(
            "SELECT email, id, password_hash, status FROM users WHERE LOWER(email) = LOWER($1)",
        )
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
    ) -> Result<QueueOutcome, ()> {
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
        // E-4:the mail_parser value is NOT pre-truncated (only the header
        // fallback is), so a >998-char subject failed the INSERT with a
        // permanent 451. Truncate char-safely on every path.
        let subject = if subject.is_empty() {
            "(no subject)".to_string()
        } else {
            truncate_subject_chars(&subject, MAX_SUBJECT_CHARS)
        };

        let mut tx = self.pool.begin().await.map_err(|_| ())?;

        // tenant_id is VARCHAR(26) referencing tenants(id) — never the user's
        // account UUID. Look up the authenticated user's actual tenant (by
        // email only: `users` has no `username` column).
        let tenant_id: Option<String> =
            sqlx::query_scalar("SELECT tenant_id FROM users WHERE LOWER(email) = LOWER($1)")
                .bind(auth_email)
                .fetch_optional(&mut *tx)
                .await
                .map_err(|_| ())?
                .flatten();

        // CAN-SPAM (F): the REST send path refuses suppressed recipients
        // before queueing; the SMTP submission path must not be a bypass.
        // Canonicalize (trim + lowercase) exactly like the api-server check
        // and drop suppressed recipients from the queued row. A lookup
        // failure surfaces as Err(()) → 451 so the client retries rather
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
                    .map_err(|_| ())?;
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
                    .map_err(|_| ())?
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
                return Ok(QueueOutcome::SenderNotOwned);
            }
            Some((_, false)) => {
                warn!(
                    from = %mail_common::pii::redact_email(mail_from),
                    requires_ses,
                    "Submission MAIL FROM domain is not ready; rejecting"
                );
                return Ok(QueueOutcome::SenderNotReady);
            }
            Some((domain_id, true)) => domain_id,
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
        .bind(&rcpt_to)
        .bind(&subject)
        .bind(headers_part)
        .bind(&text_body)
        .bind(mail_from)
        .bind(&to_first)
        .bind(&html_body)
        .bind(&text_body)
        .bind(&tenant_id)
        .bind(message_uuid)
        .bind(domain_id)
        .bind(Option::<serde_json::Value>::None)
        .execute(&mut *tx)
        .await
        .map_err(|_| ())?;

        tx.commit().await.map_err(|_| ())?;

        info!(
            message_id = %msg_id,
            from = %mail_common::pii::redact_email(mail_from),
            to = ?rcpt_to,
            size = data.len(),
            "Message queued via submission"
        );
        Ok(QueueOutcome::Queued)
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

/// Validate an envelope address against the same rules `email_queue` enforces
/// (`chk_email_queue_from_address`): no whitespace, one `@`, a non-empty local
/// part, and a non-empty domain containing at least one dot.
pub(crate) fn is_valid_envelope_address(addr: &str) -> bool {
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
                assert!(text.ends_with("tail"), "final CRLF belongs to terminator: {text:?}");
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
                assert!(text.contains(" \r\n."), "dot-space and stuffed-dot semantics: {text:?}");
                assert!(text.ends_with('.'), "last body line is the unstuffed '..': {text:?}");
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
        writer.write_all(b"Subject: half\r\nbody-so-far\r\n").await.unwrap();
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
        let small = SubmissionServer::new(config, rate_limit, pool, None);
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
            resp.contains("unknown") && !resp.contains("bad\x01host"),
            "invalid EHLO arg must be replaced with 'unknown': {resp:?}"
        );
        // A valid hostname is still echoed.
        client_buf.write_all(b"EHLO client.example\r\n").await.unwrap();
        client_buf.flush().await.unwrap();
        let resp = read_smtp_response(&mut client_buf).await;
        assert!(resp.contains("client.example"), "valid host echoed: {resp:?}");
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
        assert_eq!(truncate_subject_chars(&ascii, MAX_SUBJECT_CHARS).chars().count(), 998);

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
}
