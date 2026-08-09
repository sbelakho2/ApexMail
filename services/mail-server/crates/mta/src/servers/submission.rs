//! SMTP Submission server – accepts authenticated mail on port 587 for relaying.
//!
//! Supports AUTH PLAIN and AUTH LOGIN against the `users` table.
//! Supports STARTTLS when a TLS acceptor is provided.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use dashmap::DashMap;
use moka::sync::Cache;
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tokio_rustls::{TlsAcceptor, TlsStream};
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::SubmissionConfig;

pub struct SubmissionServer {
    config: SubmissionConfig,
    pool: PgPool,
    shutdown: Arc<Notify>,
    connections: Arc<DashMap<std::net::IpAddr, u32>>,
    auth_fail_cache: Cache<std::net::IpAddr, u64>,
    tls_acceptor: Option<TlsAcceptor>,
}

impl SubmissionServer {
    pub fn new(
        config: SubmissionConfig,
        pool: PgPool,
        tls_acceptor: Option<TlsAcceptor>,
    ) -> Self {
        Self {
            config,
            pool,
            shutdown: Arc::new(Notify::new()),
            connections: Arc::new(DashMap::new()),
            auth_fail_cache: Cache::builder()
                .max_capacity(50_000)
                .time_to_live(Duration::from_secs(300))
                .build(),
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
        let (starttls_requested, _msg_count) =
            self.run_session_loop(&mut stream, peer, allow_starttls, false).await;

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
        let mut mail_from: Option<String> = None;
        let mut rcpt_to: Vec<String> = Vec::new();
        let mut message_count: u32 = 0;
        let mut line = String::new();
        let ip = peer.ip();

        loop {
            line.clear();
            match tokio::time::timeout(Duration::from_secs(300), stream.read_line(&mut line)).await {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(_)) => {}
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
                let host = line.split_whitespace().nth(1).unwrap_or("unknown");
                let mut caps = format!("250-{} Hello {}\r\n", self.config.hostname, host);
                caps.push_str(&format!("250-SIZE {}\r\n", self.config.max_message_size));
                if allow_starttls && !already_tls {
                    caps.push_str("250-STARTTLS\r\n");
                }
                if !authenticated {
                    caps.push_str("250-AUTH PLAIN LOGIN\r\n");
                }
                caps.push_str("250-8BITMIME\r\n");
                caps.push_str("250-PIPELINING\r\n");
                caps.push_str("250 SMTPUTF8\r\n");
                let _ = write_line(stream, &caps).await;
            } else if cmd == "STARTTLS" && allow_starttls && !already_tls {
                return (true, message_count);
            } else if cmd.starts_with("AUTH LOGIN") {
                let _ = write_line(stream, "334 VXNlcm5hbWU6\r\n").await;
                let mut user_b64 = String::new();
                match stream.read_line(&mut user_b64).await {
                    Ok(_) => {}
                    _ => break,
                }
                let _ = write_line(stream, "334 UGFzc3dvcmQ6\r\n").await;
                let mut pass_b64 = String::new();
                match stream.read_line(&mut pass_b64).await {
                    Ok(_) => {}
                    _ => break,
                }
                match (
                    BASE64.decode(user_b64.trim()),
                    BASE64.decode(pass_b64.trim()),
                ) {
                    (Ok(user), Ok(pass)) => {
                        let user_str = String::from_utf8_lossy(&user);
                        let pass_str = String::from_utf8_lossy(&pass);
                        match self
                            .authenticate_user(&user_str, &pass_str, ip)
                            .await
                        {
                            Ok((email, _account_id)) => {
                                authenticated = true;
                                auth_email = email;
                                // Reset the per-IP auth-failure counter so a user who
                                // previously hit the lockout threshold (possibly via a
                                // shared/NAT IP) is not locked out after a correct login.
                                self.auth_fail_cache.remove(&ip);
                                let _ = write_line(stream, "235 2.7.0 Authentication successful\r\n").await;
                            }
                            Err(_) => {
                                let _ =
                                    write_line(stream, "535 5.7.8 Authentication failed\r\n").await;
                            }
                        }
                    }
                    _ => {
                        let _ = write_line(stream, "501 Invalid base64\r\n").await;
                    }
                }
            } else if cmd.starts_with("AUTH PLAIN") {
                // RFC 4954: AUTH PLAIN can include the initial response inline:
                //   "AUTH PLAIN <base64>"  — one-line form (what most clients use)
                //   "AUTH PLAIN"           — two-step form (server sends 334, client responds)
                // IMPORTANT: use the ORIGINAL line (not uppercased cmd) to preserve base64 case.
                let inline_b64 = trimmed.strip_prefix("AUTH PLAIN").or_else(|| trimmed.strip_prefix("auth plain")).unwrap_or("").trim();
                let auth_b64 = if !inline_b64.is_empty() {
                    // One-line form: use the inline base64 directly
                    inline_b64.to_string()
                } else {
                    // Two-step form: send challenge, wait for response
                    let _ = write_line(stream, "334 \r\n").await;
                    let mut b64 = String::new();
                    match stream.read_line(&mut b64).await {
                        Ok(_) => b64,
                        _ => break,
                    }
                };
                match BASE64.decode(auth_b64.trim()) {
                    Ok(creds) => {
                        let s = String::from_utf8_lossy(&creds);
                        let parts: Vec<&str> = s.splitn(3, '\0').collect();
                        if parts.len() >= 3 {
                            match self.authenticate_user(parts[1], parts[2], ip).await {
                                Ok((email, _account_id)) => {
                                    authenticated = true;
                                    auth_email = email;
                                    self.auth_fail_cache.remove(&ip);
                                    let _ = write_line(
                                        stream,
                                        "235 2.7.0 Authentication successful\r\n",
                                    )
                                    .await;
                                }
                                Err(_) => {
                                    let _ = write_line(
                                        stream,
                                        "535 5.7.8 Authentication failed\r\n",
                                    )
                                    .await;
                                }
                            }
                        }
                    }
                    _ => {
                        let _ = write_line(stream, "501 Invalid base64\r\n").await;
                    }
                }
            } else if cmd.starts_with("MAIL FROM:") {
                if !authenticated {
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
            } else if cmd.starts_with("RCPT TO:") {
                if !authenticated {
                    let _ = write_line(stream, "530 5.7.0 Authentication required\r\n").await;
                } else if rcpt_to.len() >= self.config.max_recipients {
                    let _ = write_line(stream, "452 Too many recipients\r\n").await;
                } else {
                    // Store only the recipient address, not the full command line.
                    let addr = extract_address(trimmed);
                    if !is_valid_envelope_address(&addr) {
                        let _ = write_line(stream, "501 5.1.3 Bad recipient address syntax\r\n").await;
                    } else {
                        rcpt_to.push(addr);
                        let _ = write_line(stream, "250 OK\r\n").await;
                    }
                }
            } else if cmd == "DATA" {
                if !authenticated {
                    let _ = write_line(stream, "530 5.7.0 Authentication required\r\n").await;
                } else if mail_from.is_none() || rcpt_to.is_empty() {
                    let _ = write_line(stream, "503 Need MAIL and RCPT first\r\n").await;
                } else {
                    let _ = write_line(
                        stream,
                        "354 Start mail input; end with <CRLF>.<CRLF>\r\n",
                    )
                    .await;
                    let mut data = Vec::new();
                    let mut buf = String::new();
                    loop {
                        buf.clear();
                        match stream.read_line(&mut buf).await {
                            Ok(0) => break,
                            Ok(_) => {
                                if buf.trim_end_matches(['\r', '\n']) == "." {
                                    break;
                                }
                                // RFC 5321 §4.5.2: un-stuff transparently-doubled dots.
                                if let Some(rest) = buf.strip_prefix("..") {
                                    data.extend_from_slice(rest.as_bytes());
                                } else {
                                    data.extend_from_slice(buf.as_bytes());
                                }
                            }
                            Err(_) => break,
                        }
                    }
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
                            let _ = write_line(
                                stream,
                                &format!("250 OK id={}\r\n", msg_id),
                            )
                            .await;
                        }
                        Err(_) => {
                            let _ = write_line(stream, "451 Requested action aborted\r\n").await;
                        }
                    }
                    mail_from = None;
                    rcpt_to.clear();
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
            } else {
                let _ = write_line(stream, "502 Command not recognised\r\n").await;
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

    // ── Auth helper ──────────────────────────────────────────────────────

    async fn authenticate_user(
        &self,
        email: &str,
        password: &str,
        ip: std::net::IpAddr,
    ) -> Result<(String, Uuid), ()> {
        // NOTE: no early-return lockout short-circuit. When an IP has >=5
        // recent failures we STILL verify the presented credentials: a
        // legitimate user behind a shared (NAT) IP must be able to log in
        // with the correct password, which resets the counter below.
        // Incorrect credentials simply keep the lockout in place (and the
        // counter entry expires after the cache TTL anyway).
        let user = sqlx::query_as::<_, (String, Uuid, String, String)>(
            "SELECT email, id, password_hash, status FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2)",
        )
        .bind(email)
        .bind(email)
        .fetch_optional(&self.pool)
        .await
        .map_err(|_| ())?;

        let (user_email, user_id, password_hash, status) = match user {
            Some(u) => u,
            None => {
                self.auth_fail_cache.insert(ip, 1 + self.auth_fail_cache.get(&ip).unwrap_or(0));
                return Err(());
            }
        };

        if status != "active" {
            return Err(());
        }

        // verify_password_for_login accepts both Argon2id and legacy bcrypt
        // hashes (the users table contains bcrypt rows created before the
        // Argon2id migration). On successful bcrypt login it returns an
        // Argon2id replacement hash, which we persist so the row migrates.
        match apexmail_lib::crypto::verify_password_for_login(password, &password_hash) {
            Ok(verification) if verification.valid => {
                self.auth_fail_cache.remove(&ip);
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
                self.auth_fail_cache
                    .insert(ip, 1 + self.auth_fail_cache.get(&ip).unwrap_or(0));
                Err(())
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
        let html_body = parsed.as_ref().and_then(|m| m.body_html(0)).map(|b| b.into_owned());
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

/// Extract the bare address from an SMTP command line such as
/// `RCPT TO:<user@example.com>` or `MAIL FROM: user@example.com`.
fn extract_address(line: &str) -> String {
    if let Some(start) = line.find('<') {
        if let Some(end) = line.find('>') {
            return line[start + 1..end].to_string();
        }
    }
    line.split_whitespace()
        .last()
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
