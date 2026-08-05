//! SMTP Submission server – accepts authenticated mail on port 587 for relaying.
//!
//! Supports AUTH PLAIN and AUTH LOGIN against the `users` table.
//! Supports STARTTLS when a TLS acceptor is provided.

use std::net::SocketAddr;
use std::sync::Arc;
use std::time::Duration;

use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use bytes::BytesMut;
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
        let mut auth_account_id: Option<Uuid> = None;
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

            let cmd = line.trim().to_uppercase();

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
                            Ok((email, account_id)) => {
                                authenticated = true;
                                auth_email = email;
                                auth_account_id = Some(account_id);
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
                let inline_b64 = cmd.strip_prefix("AUTH PLAIN").unwrap_or("").trim();
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
                                Ok((email, account_id)) => {
                                    authenticated = true;
                                    auth_email = email;
                                    auth_account_id = Some(account_id);
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
                    mail_from = Some(line.trim().to_string());
                    let _ = write_line(stream, "250 OK\r\n").await;
                }
            } else if cmd.starts_with("RCPT TO:") {
                if !authenticated {
                    let _ = write_line(stream, "530 5.7.0 Authentication required\r\n").await;
                } else {
                    rcpt_to.push(line.trim().to_string());
                    let _ = write_line(stream, "250 OK\r\n").await;
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
                                if buf == ".\r\n" {
                                    break;
                                }
                                data.extend_from_slice(buf.as_bytes());
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
                            &auth_account_id.unwrap_or_default(),
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
        let key = ip;
        if let Some(failures) = self.auth_fail_cache.get(&key) {
            if failures >= 5 {
                return Err(());
            }
        }

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

        match apexmail_lib::crypto::verify_password(password, &password_hash) {
            Ok(true) => Ok((user_email, user_id)),
            _ => {
                self.auth_fail_cache.insert(ip, 1 + self.auth_fail_cache.get(&ip).unwrap_or(0));
                Err(())
            }
        }
    }

    // ── Queue helper ─────────────────────────────────────────────────────

    async fn queue_message(
        &self,
        account_id: &Uuid,
        from_email: &str,
        mail_from: &str,
        rcpt_to: &[String],
        data: &str,
        msg_id: &str,
    ) -> Result<(), ()> {
        let to_json = serde_json::to_string(rcpt_to).map_err(|_| ())?;
        sqlx::query(
            "INSERT INTO email_queue (id, tenant_id, from_address, to_addresses, raw_mime, status, priority, created_at)
             VALUES ($1, $2, $3, $4::jsonb, $5, 'pending', 5, NOW())",
        )
        .bind(msg_id)
        .bind(account_id.to_string())
        .bind(from_email)
        .bind(&to_json)
        .bind(data)
        .execute(&self.pool)
        .await
        .map_err(|_| ())?;

        info!(
            message_id = %msg_id,
            from = %mail_common::pii::redact_email(from_email),
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

async fn write_line<S: AsyncWrite + Unpin>(sink: &mut S, line: &str) -> std::io::Result<()> {
    sink.write_all(line.as_bytes()).await?;
    sink.flush().await
}
