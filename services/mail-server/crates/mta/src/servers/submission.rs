//! SMTP Submission server – accepts authenticated mail on port 587 for relaying.
//!
//! Supports AUTH PLAIN and AUTH LOGIN mechanisms against the `users` table,
//! using the same password verification as the API server.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::BytesMut;
use dashmap::DashMap;
use moka::sync::Cache;
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::SubmissionConfig;

pub struct SubmissionServer {
    config: SubmissionConfig,
    pool: PgPool,
    shutdown: Arc<Notify>,
    connections: Arc<DashMap<std::net::IpAddr, u32>>,
    auth_fail_cache: Cache<std::net::IpAddr, u64>,
}

impl SubmissionServer {
    pub fn new(config: SubmissionConfig, pool: PgPool) -> Self {
        Self {
            config,
            pool,
            shutdown: Arc::new(Notify::new()),
            connections: Arc::new(DashMap::new()),
            auth_fail_cache: Cache::builder()
                .max_capacity(50_000)
                .time_to_live(Duration::from_secs(300))
                .build(),
        }
    }

    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await?;
        info!(addr = %addr, "Submission SMTP server listening (AUTH required)");

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

        let mut authenticated = false;
        let mut auth_email = String::new();
        let mut auth_account_id: Option<Uuid> = None;
        let mut mail_from: Option<String> = None;
        let mut rcpt_to: Vec<String> = Vec::new();
        let mut message_count: u32 = 0;
        let mut line = String::new();

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

            let cmd = line.trim().to_uppercase();

            if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                let host = line.split_whitespace().nth(1).unwrap_or("unknown");
                let mut caps = format!("250-{} Hello {}\r\n", self.config.hostname, host);
                caps.push_str(&format!("250-SIZE {}\r\n", self.config.max_message_size));
                if !authenticated {
                    caps.push_str("250-AUTH PLAIN LOGIN\r\n");
                }
                caps.push_str("250-8BITMIME\r\n");
                caps.push_str("250-PIPELINING\r\n");
                caps.push_str("250 SMTPUTF8\r\n");
                if let Err(e) = write_line(&mut stream, &caps).await {
                    debug!(error = %e, "Write error");
                    break;
                }
            } else if cmd.starts_with("AUTH PLAIN") || cmd.starts_with("AUTH PLAIN") {
                let remainder = line["AUTH PLAIN".len()..].trim().to_string();
                match self.auth_plain(&remainder, peer, &mut stream).await {
                    Ok(result) => {
                        authenticated = result.success;
                        auth_email = result.email.unwrap_or_default();
                        auth_account_id = result.account_id;
                    }
                    Err(e) => {
                        warn!(error = %e, peer = %peer, "Auth PLAIN error");
                        break;
                    }
                }
            } else if cmd.starts_with("AUTH LOGIN") {
                match self.auth_login(peer, &mut stream).await {
                    Ok(result) => {
                        authenticated = result.success;
                        auth_email = result.email.unwrap_or_default();
                        auth_account_id = result.account_id;
                    }
                    Err(e) => {
                        warn!(error = %e, peer = %peer, "Auth LOGIN error");
                        break;
                    }
                }
            } else if cmd.starts_with("AUTH") {
                let _ = write_line(&mut stream, "504 Unrecognized authentication mechanism\r\n").await;
            } else if cmd.starts_with("MAIL FROM") {
                if !authenticated {
                    self.require_auth(&mut stream).await;
                    continue;
                }
                let addr = extract_address(&line);
                mail_from = Some(addr);
                let _ = write_line(&mut stream, "250 OK\r\n").await;
            } else if cmd.starts_with("RCPT TO") {
                if !authenticated {
                    self.require_auth(&mut stream).await;
                    continue;
                }
                if rcpt_to.len() >= self.config.max_recipients {
                    let _ = write_line(&mut stream, "452 Too many recipients\r\n").await;
                    continue;
                }
                let addr = extract_address(&line);
                if !addr.contains('@') {
                    let _ = write_line(&mut stream, "550 Invalid recipient\r\n").await;
                    continue;
                }
                rcpt_to.push(addr);
                let _ = write_line(&mut stream, "250 OK\r\n").await;
            } else if cmd.starts_with("DATA") {
                if !authenticated {
                    self.require_auth(&mut stream).await;
                    continue;
                }
                if mail_from.is_none() || rcpt_to.is_empty() {
                    let _ = write_line(&mut stream, "503 Bad sequence of commands\r\n").await;
                    continue;
                }
                let _ = write_line(&mut stream, "354 Start mail input; end with <CRLF>.<CRLF>\r\n").await;

                let mut message = BytesMut::new();
                let mut too_large = false;
                let deadline = tokio::time::Instant::now() + Duration::from_secs(600);

                loop {
                    line.clear();
                    let remaining = deadline
                        .checked_duration_since(tokio::time::Instant::now())
                        .unwrap_or(Duration::ZERO);
                    if remaining.is_zero() {
                        let _ = write_line(&mut stream, "421 Data timeout exceeded\r\n").await;
                        break;
                    }
                    let per_line = remaining.min(Duration::from_secs(300));
                    match tokio::time::timeout(per_line, stream.read_line(&mut line)).await {
                        Err(_) => {
                            let _ = write_line(&mut stream, "421 Data timeout exceeded\r\n").await;
                            break;
                        }
                        Ok(Ok(0)) => break,
                        Ok(Ok(_)) => {
                            if line.trim() == "." {
                                break;
                            }
                            if !too_large {
                                let data_slice = if line.starts_with("..") {
                                    &line[1..]
                                } else {
                                    &line[..]
                                };
                                if message.len() + data_slice.len()
                                    > self.config.max_message_size
                                {
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

                if too_large {
                    let _ = write_line(&mut stream, "552 Message too large\r\n").await;
                } else if !message.is_empty() {
                    let result = self
                        .submit_message(
                            &auth_email,
                            auth_account_id,
                            &mail_from,
                            &rcpt_to,
                            &message,
                        )
                        .await;
                    match result {
                        Ok(id) => {
                            let _ = write_line(
                                &mut stream,
                                &format!("250 OK id={}\r\n", id),
                            ).await;
                            message_count += 1;
                        }
                        Err(e) => {
                            warn!(error = %e, peer = %peer, "Message submission failed");
                            let _ = write_line(
                                &mut stream,
                                "451 Temporary local error\r\n",
                            ).await;
                        }
                    }
                }
                mail_from = None;
                rcpt_to.clear();
            } else if cmd.starts_with("RSET") {
                mail_from = None;
                rcpt_to.clear();
                let _ = write_line(&mut stream, "250 OK\r\n").await;
            } else if cmd.starts_with("NOOP") {
                let _ = write_line(&mut stream, "250 OK\r\n").await;
            } else if cmd.starts_with("QUIT") {
                let _ = write_line(&mut stream, "221 Bye\r\n").await;
                break;
            } else if cmd.starts_with("STARTTLS") {
                let _ = write_line(&mut stream, "454 TLS not available\r\n").await;
            } else {
                let _ = write_line(&mut stream, "502 Command not recognised\r\n").await;
            }
        }

        debug!(
            peer = %peer,
            authenticated = authenticated,
            messages = message_count,
            "Submission session ended"
        );
        self.track_connection(ip, false);
    }

    async fn require_auth<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &self,
        stream: &mut BufStream<S>,
    ) {
        let _ = write_line(
            stream,
            "530 5.7.0 Authentication required; use AUTH PLAIN or AUTH LOGIN first\r\n",
        )
        .await;
    }

    async fn auth_plain<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &self,
        initial: &str,
        peer: SocketAddr,
        stream: &mut BufStream<S>,
    ) -> anyhow::Result<AuthResult> {
        let ip = peer.ip();
        let credentials = if initial.is_empty() {
            let _ = write_line(stream, "334 \r\n").await;
            let mut creds = String::new();
            tokio::time::timeout(Duration::from_secs(60), stream.read_line(&mut creds))
                .await
                .map_err(|_| anyhow::anyhow!("AUTH PLAIN timeout"))??;
            creds.trim().to_string()
        } else {
            initial.to_string()
        };

        if self.is_auth_rate_limited(ip) {
            let _ = write_line(stream, "454 Too many authentication failures\r\n").await;
            return Ok(AuthResult::failed("rate-limited"));
        }

        let decoded = BASE64
            .decode(&credentials)
            .map_err(|e| anyhow::anyhow!("Invalid base64: {}", e))?;

        let decoded_str = String::from_utf8_lossy(&decoded).into_owned();
        let parts: Vec<&str> = decoded_str.split('\0').collect();

        let (username, password) = match parts.as_slice() {
            [_, user, pass] => (*user, *pass),
            [user, pass] => (*user, *pass),
            _ => {
                let _ = write_line(stream, "535 Invalid PLAIN credentials format\r\n").await;
                return Ok(AuthResult::failed("bad-format"));
            }
        };

        let result = self.verify_credentials(username, password).await?;
        if result.success {
            self.auth_fail_cache.invalidate(&ip);
            let _ = write_line(stream, "235 2.7.0 Authentication successful\r\n").await;
        } else {
            self.record_auth_failure(ip);
            let _ = write_line(stream, "535 5.7.8 Authentication failed\r\n").await;
        }
        Ok(result)
    }

    async fn auth_login<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
        &self,
        peer: SocketAddr,
        stream: &mut BufStream<S>,
    ) -> anyhow::Result<AuthResult> {
        let ip = peer.ip();

        if self.is_auth_rate_limited(ip) {
            let _ = write_line(stream, "454 Too many authentication failures\r\n").await;
            return Ok(AuthResult::failed("rate-limited"));
        }

        let _ = write_line(stream, "334 VXNlcm5hbWU6\r\n").await;
        let mut user_line = String::new();
        tokio::time::timeout(Duration::from_secs(60), stream.read_line(&mut user_line))
            .await
            .map_err(|_| anyhow::anyhow!("AUTH LOGIN username timeout"))??;
        let username_b64 = user_line.trim();

        let _ = write_line(stream, "334 UGFzc3dvcmQ6\r\n").await;
        let mut pass_line = String::new();
        tokio::time::timeout(Duration::from_secs(60), stream.read_line(&mut pass_line))
            .await
            .map_err(|_| anyhow::anyhow!("AUTH LOGIN password timeout"))??;
        let password_b64 = pass_line.trim();

        let username = String::from_utf8(
            BASE64
                .decode(username_b64)
                .map_err(|e| anyhow::anyhow!("Invalid base64 username: {}", e))?,
        )
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 username: {}", e))?;

        let password = String::from_utf8(
            BASE64
                .decode(password_b64)
                .map_err(|e| anyhow::anyhow!("Invalid base64 password: {}", e))?,
        )
        .map_err(|e| anyhow::anyhow!("Invalid UTF-8 password: {}", e))?;

        let result = self.verify_credentials(&username, &password).await?;
        if result.success {
            self.auth_fail_cache.invalidate(&ip);
            let _ = write_line(stream, "235 2.7.0 Authentication successful\r\n").await;
        } else {
            self.record_auth_failure(ip);
            let _ = write_line(stream, "535 5.7.8 Authentication failed\r\n").await;
        }
        Ok(result)
    }

    async fn verify_credentials(&self, username: &str, password: &str) -> anyhow::Result<AuthResult> {
        let row = sqlx::query(
            "SELECT id, email, password_hash, status FROM users WHERE LOWER(email) = LOWER($1) OR LOWER(username) = LOWER($2) LIMIT 1",
        )
        .bind(username)
        .bind(username)
        .fetch_optional(&self.pool)
        .await?;

        let row = match row {
            Some(r) => r,
            None => {
                debug!(username = %username, "User not found");
                return Ok(AuthResult::failed("not-found"));
            }
        };

        let status: String = sqlx::Row::get(&row, "status");
        if status != "active" {
            debug!(username = %username, status = %status, "Account not active");
            return Ok(AuthResult::failed("inactive"));
        }

        let password_hash: String = sqlx::Row::get(&row, "password_hash");
        let verification =
            apexmail_lib::crypto::verify_password_for_login(password, &password_hash)
                .map_err(|e| anyhow::anyhow!("Password verification error: {}", e))?;

        if verification.valid {
            let account_id: Uuid = sqlx::Row::get(&row, "id");
            let email: String = sqlx::Row::get(&row, "email");

            if let Some(migrated_hash) = verification.migrated_hash {
                let result = sqlx::query(
                    "UPDATE users SET password_hash = $1, updated_at = NOW() WHERE id = $2 AND password_hash = $3",
                )
                .bind(&migrated_hash)
                .bind(account_id)
                .bind(&password_hash)
                .execute(&self.pool)
                .await;
                if let Err(e) = result {
                    warn!(username = %username, error = %e, "Failed to migrate bcrypt hash to Argon2id");
                }
            }

            debug!(username = %username, "Submission authentication successful");
            Ok(AuthResult {
                success: true,
                account_id: Some(account_id),
                email: Some(email),
            })
        } else {
            debug!(username = %username, "Invalid password");
            Ok(AuthResult::failed("invalid-password"))
        }
    }

    async fn submit_message(
        &self,
        auth_email: &str,
        auth_account_id: Option<Uuid>,
        mail_from: &Option<String>,
        rcpt_to: &[String],
        raw: &[u8],
    ) -> anyhow::Result<String> {
        let message_id = Uuid::new_v4();
        let from = mail_from.as_deref().unwrap_or("<>");
        let raw_str = String::from_utf8_lossy(raw);

        let (headers_part, body_part) = if let Some(sep) = raw_str.find("\r\n\r\n") {
            (&raw_str[..sep], &raw_str[sep + 4..])
        } else if let Some(sep) = raw_str.find("\n\n") {
            (&raw_str[..sep], &raw_str[sep + 2..])
        } else {
            ("", raw_str.as_ref())
        };

        let subject = headers_part
            .lines()
            .find(|l| l.to_lowercase().starts_with("subject:"))
            .map(|l| l[8..].trim().to_string())
            .unwrap_or_else(|| "(no subject)".to_string());

        let from_addr = if from == "<>" { auth_email.to_string() } else { from.to_string() };

        sqlx::query(
            r#"
            INSERT INTO email_queue (
                id, from_address, to_addresses, subject,
                raw_headers, text_body, status, priority
            )
            VALUES ($1, $2, $3, $4, $5, $6, 'pending', 50)
            "#,
        )
        .bind(message_id)
        .bind(&from_addr)
        .bind(rcpt_to)
        .bind(&subject)
        .bind(headers_part)
        .bind(body_part)
        .execute(&self.pool)
        .await?;

        info!(
            message_id = %message_id,
            from = %mail_common::pii::redact_email(&from_addr),
            to = %mail_common::pii::redact_email_list(rcpt_to),
            size = raw.len(),
            "Message queued via submission"
        );

        let _ = auth_account_id;
        Ok(message_id.to_string())
    }

    fn track_connection(&self, ip: std::net::IpAddr, connect: bool) {
        if connect {
            *self.connections.entry(ip).or_insert(0) += 1;
        } else {
            self.connections
                .entry(ip)
                .and_modify(|c| *c = c.saturating_sub(1));
            self.connections.remove_if(&ip, |_, c| *c == 0);
        }
    }

    fn is_auth_rate_limited(&self, ip: std::net::IpAddr) -> bool {
        self.auth_fail_cache.get(&ip).unwrap_or(0) >= 5
    }

    fn record_auth_failure(&self, ip: std::net::IpAddr) {
        let count = self.auth_fail_cache.get(&ip).unwrap_or(0);
        self.auth_fail_cache.insert(ip, count.saturating_add(1));
    }
}

#[derive(Debug, Clone)]
struct AuthResult {
    success: bool,
    account_id: Option<Uuid>,
    email: Option<String>,
}

impl AuthResult {
    fn failed(_reason: &str) -> Self {
        Self {
            success: false,
            account_id: None,
            email: None,
        }
    }
}

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

async fn write_line<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut BufStream<S>,
    data: &str,
) -> std::io::Result<()> {
    stream.write_all(data.as_bytes()).await?;
    stream.flush().await
}
