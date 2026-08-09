//! SMTP Submission Session
//!
//! Handles an authenticated SMTP session for email submission.

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use std::sync::LazyLock;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio_rustls::{server::TlsStream, TlsAcceptor};
use tracing::{debug, error, info, warn};
use uuid::Uuid;

use crate::auth::{auth_login, auth_plain, AuthResult};
use crate::ServerState;

/// SMTP submission session state
pub struct SubmissionSession {
    stream: SessionStream,
    peer_addr: SocketAddr,
    state: Arc<ServerState>,

    // Session state
    authenticated: bool,
    auth_account_id: Option<Uuid>,
    auth_email: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data_buffer: Vec<u8>,
}

const MAX_MESSAGE_SIZE: usize = 25 * 1024 * 1024; // 25 MB
/// #171:Maximum recipients per message
static MAX_RECIPIENTS: LazyLock<usize> = LazyLock::new(|| {
    std::env::var("SUBMISSION_MAX_RECIPIENTS")
        .ok()
        .and_then(|value| value.parse::<usize>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(100)
});

#[allow(clippy::large_enum_variant)]
enum SessionStream {
    Plain(BufStream<TcpStream>),
    Tls(BufStream<TlsStream<TcpStream>>),
    Invalid,
}

impl SessionStream {
    async fn read_line(&mut self, line: &mut String) -> Result<usize> {
        match self {
            SessionStream::Plain(stream) => Ok(stream.read_line(line).await?),
            SessionStream::Tls(stream) => Ok(stream.read_line(line).await?),
            SessionStream::Invalid => Err(anyhow!("Invalid session stream state")),
        }
    }

    async fn write_all(&mut self, data: &[u8]) -> Result<()> {
        match self {
            SessionStream::Plain(stream) => {
                stream.write_all(data).await?;
                Ok(())
            }
            SessionStream::Tls(stream) => {
                stream.write_all(data).await?;
                Ok(())
            }
            SessionStream::Invalid => Err(anyhow!("Invalid session stream state")),
        }
    }

    async fn flush(&mut self) -> Result<()> {
        match self {
            SessionStream::Plain(stream) => {
                stream.flush().await?;
                Ok(())
            }
            SessionStream::Tls(stream) => {
                stream.flush().await?;
                Ok(())
            }
            SessionStream::Invalid => Err(anyhow!("Invalid session stream state")),
        }
    }
}

impl SubmissionSession {
    pub fn new(stream: TcpStream, peer_addr: SocketAddr, state: Arc<ServerState>) -> Self {
        Self {
            stream: SessionStream::Plain(BufStream::new(stream)),
            peer_addr,
            state,
            authenticated: false,
            auth_account_id: None,
            auth_email: None,
            mail_from: None,
            rcpt_to: Vec::new(),
            data_buffer: Vec::new(),
        }
    }

    /// Run the SMTP session
    pub async fn run(&mut self) -> Result<()> {
        // Send greeting
        self.send_response(
            220,
            &format!("{} ESMTP ApexMail Submission", self.state.hostname),
        )
        .await?;

        // Command loop
        let mut line = String::new();
        loop {
            line.clear();
            match self.stream.read_line(&mut line).await {
                Ok(0) => {
                    debug!(peer = %self.peer_addr, "Client disconnected");
                    break;
                }
                Ok(_) => {
                    let line = line.trim().to_string();
                    debug!(peer = %self.peer_addr, command = %line, "Received command");

                    // #166:handle_command returns Ok(true) for QUIT to avoid
                    // the error handler sending a spurious "500 Internal error".
                    match self.handle_command(&line).await {
                        Ok(true) => break, // QUIT
                        Ok(false) => {}
                        Err(e) => {
                            error!(peer = %self.peer_addr, error = %e, "Command error");
                            self.send_response(500, "Internal error").await?;
                        }
                    }
                }
                Err(e) => {
                    error!(peer = %self.peer_addr, error = %e, "Read error");
                    break;
                }
            }
        }

        Ok(())
    }

    /// Handle an SMTP command. Returns Ok(true) when session should end (QUIT).
    async fn handle_command(&mut self, line: &str) -> Result<bool> {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        let command = parts[0].to_uppercase();
        let args = parts.get(1).copied().unwrap_or("");

        match command.as_str() {
            "EHLO" | "HELO" => {
                self.handle_ehlo(args).await?;
                Ok(false)
            }
            "AUTH" => {
                self.handle_auth(args).await?;
                Ok(false)
            }
            "MAIL" => {
                self.handle_mail(args).await?;
                Ok(false)
            }
            "RCPT" => {
                self.handle_rcpt(args).await?;
                Ok(false)
            }
            "DATA" => {
                self.handle_data().await?;
                Ok(false)
            }
            "RSET" => {
                self.handle_rset().await?;
                Ok(false)
            }
            "NOOP" => {
                self.handle_noop().await?;
                Ok(false)
            }
            "QUIT" => {
                self.handle_quit().await?;
                Ok(true)
            }
            "STARTTLS" => {
                self.handle_starttls().await?;
                Ok(false)
            }
            _ => {
                self.send_response(500, "Unknown command").await?;
                Ok(false)
            }
        }
    }

    /// Handle EHLO/HELO
    async fn handle_ehlo(&mut self, _domain: &str) -> Result<()> {
        // #167:SIZE must match MAX_MESSAGE_SIZE (25 MB), was advertising 50 MB
        let mut extensions = vec![
            format!("{}", self.state.hostname),
            format!("SIZE {}", MAX_MESSAGE_SIZE),
            "8BITMIME".to_string(),
            "SMTPUTF8".to_string(),
            "PIPELINING".to_string(),
        ];

        // Add AUTH if not authenticated
        if !self.authenticated {
            extensions.push("AUTH PLAIN LOGIN".to_string());
        }

        // Add STARTTLS
        if self.state.enable_starttls {
            extensions.push("STARTTLS".to_string());
        }

        // Send multi-line response
        for (i, ext) in extensions.iter().enumerate() {
            let prefix = if i == extensions.len() - 1 {
                "250 "
            } else {
                "250-"
            };
            self.send_line(&format!("{}{}", prefix, ext)).await?;
        }

        Ok(())
    }

    /// Handle AUTH
    async fn handle_auth(&mut self, args: &str) -> Result<()> {
        if self.authenticated {
            self.send_response(503, "Already authenticated").await?;
            return Ok(());
        }

        let parts: Vec<&str> = args.splitn(2, ' ').collect();
        let mechanism = parts[0].to_uppercase();
        let initial_response = parts.get(1).copied();

        match mechanism.as_str() {
            "PLAIN" => {
                let credentials = match initial_response {
                    Some(creds) if !creds.is_empty() => creds.to_string(),
                    _ => {
                        // Request credentials
                        self.send_response(334, "").await?;
                        let mut creds = String::new();
                        self.stream.read_line(&mut creds).await?;
                        creds.trim().to_string()
                    }
                };

                let result =
                    auth_plain(&credentials, &self.state.db_pool, self.peer_addr.ip()).await?;
                self.complete_auth(result).await
            }
            "LOGIN" => {
                // Request username
                self.send_response(334, "VXNlcm5hbWU6").await?; // "Username:" in base64
                let mut username = String::new();
                self.stream.read_line(&mut username).await?;
                let username = username.trim().to_string();

                // Request password                 self.send_response(334, "UGFzc3dvcmQ6").await?; // "Password:" in base64
                let mut password = String::new();
                self.stream.read_line(&mut password).await?;
                let password = password.trim().to_string();

                let result = auth_login(
                    &username,
                    &password,
                    &self.state.db_pool,
                    self.peer_addr.ip(),
                )
                .await?;
                self.complete_auth(result).await
            }
            _ => {
                self.send_response(504, "Unrecognized authentication mechanism")
                    .await?;
                Ok(())
            }
        }
    }

    /// Complete authentication
    async fn complete_auth(&mut self, result: AuthResult) -> Result<()> {
        if result.success {
            self.authenticated = true;
            self.auth_account_id = result.account_id;
            self.auth_email = result.email.clone();
            info!(
                peer = %self.peer_addr,
                email = %mail_common::pii::redact_email(result.email.as_deref().unwrap_or("")),
                "Authentication successful"
            );
            self.send_response(235, "Authentication successful").await
        } else {
            warn!(
                peer = %self.peer_addr,
                error = ?result.error,
                "Authentication failed"
            );
            self.send_response(535, "Authentication failed").await
        }
    }

    /// Handle MAIL FROM
    async fn handle_mail(&mut self, args: &str) -> Result<()> {
        // Check authentication if required
        if self.state.require_auth && !self.authenticated {
            self.send_response(530, "Authentication required").await?;
            return Ok(());
        }

        // Parse MAIL FROM:<address>
        let args_upper = args.to_uppercase();
        if !args_upper.starts_with("FROM:") {
            self.send_response(501, "Syntax error").await?;
            return Ok(());
        }

        // #169:Extract address properly, handling ESMTP parameters after '>'
        let rest = args[5..].trim();
        let from = extract_address(rest).unwrap_or_default();
        if from.is_empty() {
            self.send_response(501, "Syntax error in sender address")
                .await?;
            return Ok(());
        }

        // Verify sender matches authenticated user (optional)
        if self.authenticated {
            if let Some(ref auth_email) = self.auth_email {
                if from != auth_email.as_str()
                    && !from.ends_with(&format!("@{}", self.state.hostname))
                {
                    warn!(
                        peer = %self.peer_addr,
                        from = %mail_common::pii::redact_email(&from),
                        auth_email = %mail_common::pii::redact_email(auth_email),
                        "Sender mismatch"
                    );
                    // Allow it but log - could be sending on behalf of
                }
            }
        }

        self.mail_from = Some(from.to_string());
        self.rcpt_to.clear();
        self.send_response(250, "OK").await
    }

    /// Handle RCPT TO
    async fn handle_rcpt(&mut self, args: &str) -> Result<()> {
        if self.mail_from.is_none() {
            self.send_response(503, "MAIL first").await?;
            return Ok(());
        }

        // #171:Enforce maximum recipient limit
        if self.rcpt_to.len() >= *MAX_RECIPIENTS {
            self.send_response(452, "Too many recipients").await?;
            return Ok(());
        }

        // Parse RCPT TO:<address>
        let args_upper = args.to_uppercase();
        if !args_upper.starts_with("TO:") {
            self.send_response(501, "Syntax error").await?;
            return Ok(());
        }

        // #172:Extract address properly, handling ESMTP parameters after '>'
        let rest = args[3..].trim();
        let to = extract_address(rest).unwrap_or_default();

        if to.is_empty() || !to.contains('@') {
            self.send_response(550, "Invalid recipient").await?;
            return Ok(());
        }

        self.rcpt_to.push(to);
        self.send_response(250, "OK").await
    }

    /// Handle DATA
    async fn handle_data(&mut self) -> Result<()> {
        if self.mail_from.is_none() {
            self.send_response(503, "MAIL first").await?;
            return Ok(());
        }

        if self.rcpt_to.is_empty() {
            self.send_response(503, "RCPT first").await?;
            return Ok(());
        }

        self.send_response(354, "Start mail input; end with <CRLF>.<CRLF>")
            .await?;

        // Read message data
        self.data_buffer.clear();
        let mut line = String::new();
        let mut too_large = false;

        // #170:Total 10-minute deadline for DATA phase to prevent slow-loris
        let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(600);

        loop {
            line.clear();
            let remaining = deadline.duration_since(tokio::time::Instant::now());
            if remaining.is_zero() {
                self.send_response(451, "Timeout waiting for message data")
                    .await?;
                self.mail_from = None;
                self.rcpt_to.clear();
                return Ok(());
            }
            let per_line = remaining.min(std::time::Duration::from_secs(300));
            match tokio::time::timeout(per_line, self.stream.read_line(&mut line)).await {
                Err(_) => {
                    self.send_response(451, "Timeout waiting for message data")
                        .await?;
                    self.mail_from = None;
                    self.rcpt_to.clear();
                    return Ok(());
                }
                Ok(result) => match result {
                    Ok(0) => {
                        return Err(anyhow!("Client disconnected during DATA"));
                    }
                    Ok(_) => {
                        if line.trim() == "." {
                            break;
                        }
                        // Handle dot-stuffing
                        let data = if line.starts_with("..") {
                            &line[1..]
                        } else {
                            &line
                        };
                        if !too_large {
                            if self.data_buffer.len() + data.len() > MAX_MESSAGE_SIZE {
                                too_large = true;
                                self.data_buffer.clear();
                            } else {
                                self.data_buffer.extend_from_slice(data.as_bytes());
                            }
                        }
                    }
                    Err(e) => return Err(e),
                }, // Ok(result)
            } // match timeout
        } // loop

        if too_large {
            self.send_response(552, "Message too large").await?;
            self.mail_from = None;
            self.rcpt_to.clear();
            return Ok(());
        }

        // Submit message to outbound queue
        self.submit_message().await
    }

    /// #168:Split raw message into headers + body so outbound doesn't duplicate headers.
    /// Submit message to outbound queue
    async fn submit_message(&mut self) -> Result<()> {
        let from = self
            .mail_from
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("No MAIL FROM set before submitting message"))?
            .clone();
        let to = self.rcpt_to.clone();
        let raw = String::from_utf8_lossy(&self.data_buffer).to_string();

        // #168:Separate headers from body to avoid outbound re-prepending them.
        // The raw message has headers separated from body by a blank line.
        let (headers_part, body_part) = if let Some(sep) = raw.find("\r\n\r\n") {
            (&raw[..sep], &raw[sep + 4..])
        } else if let Some(sep) = raw.find("\n\n") {
            (&raw[..sep], &raw[sep + 2..])
        } else {
            ("", raw.as_str())
        };

        info!(
            peer = %self.peer_addr,
            from = %mail_common::pii::redact_email(&from),
            to = %mail_common::pii::redact_email_list(&to),
            size = self.data_buffer.len(),
            "Submitting message"
        );

        let message_id = Uuid::new_v4();

        // Parse subject from headers
        let subject = headers_part
            .lines()
            .find(|l| l.to_lowercase().starts_with("subject:"))
            .map(|l| l[8..].trim().to_string())
            .unwrap_or_else(|| "(no subject)".to_string());

        // Store headers separately and body as text_body so outbound
        // can reconstruct without duplicating headers. Both schema families
        // are populated so the queue worker (fetch_jobs) can decode the row:
        // base family (from_address/to_addresses/text_body) plus the worker
        // columns (message_id/"from"/"to"/text).
        let to_first = to.first().cloned().unwrap_or_default();
        sqlx::query(
            r#"
            INSERT INTO email_queue (
                id, message_id, from_address, to_addresses, subject,
                raw_headers, text_body, "from", "to", text, status, priority
            )
            VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, 'pending', 50)
        "#,
        )
        .bind(message_id)
        .bind(message_id)
        .bind(&from)
        .bind(&to)
        .bind(&subject)
        .bind(headers_part)
        .bind(body_part)
        .bind(&from)
        .bind(&to_first)
        .bind(body_part)
        .execute(&self.state.db_pool)
        .await?;

        info!(
            message_id = %message_id,
            from = %mail_common::pii::redact_email(&from),
            to = %mail_common::pii::redact_email_list(&to),
            "Message queued"
        );

        self.send_response(250, &format!("OK, message queued as {}", message_id))
            .await?;

        // Reset session state
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data_buffer.clear();

        Ok(())
    }

    /// Handle RSET
    async fn handle_rset(&mut self) -> Result<()> {
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data_buffer.clear();
        self.send_response(250, "OK").await
    }

    /// Handle NOOP
    async fn handle_noop(&mut self) -> Result<()> {
        self.send_response(250, "OK").await
    }

    /// Handle QUIT — #166:Returns Ok() instead of Err("QUIT") to avoid
    /// the error handler sending a spurious "500 Internal error" after "221 Bye".
    async fn handle_quit(&mut self) -> Result<()> {
        self.send_response(221, &format!("{} Bye", self.state.hostname))
            .await?;
        Ok(())
    }

    /// Handle STARTTLS
    async fn handle_starttls(&mut self) -> Result<()> {
        if !self.state.enable_starttls {
            self.send_response(502, "STARTTLS not available").await?;
            return Ok(());
        }

        if matches!(self.stream, SessionStream::Tls(_)) {
            self.send_response(503, "TLS already active").await?;
            return Ok(());
        }

        let acceptor: &TlsAcceptor = self
            .state
            .tls_acceptor
            .as_ref()
            .ok_or_else(|| anyhow!("TLS acceptor not configured"))?;
        let acceptor = acceptor.clone();

        self.send_response(220, "Ready to start TLS").await?;

        let current = std::mem::replace(&mut self.stream, SessionStream::Invalid);
        let plain_stream = match current {
            SessionStream::Plain(stream) => stream,
            other => {
                self.stream = other;
                return Err(anyhow!("Invalid stream state during STARTTLS"));
            }
        };

        let tcp_stream = plain_stream.into_inner();
        let tls_stream = acceptor.accept(tcp_stream).await?;
        self.stream = SessionStream::Tls(BufStream::new(tls_stream));

        // Reset session state per RFC after TLS negotiation
        self.authenticated = false;
        self.auth_account_id = None;
        self.auth_email = None;
        self.mail_from = None;
        self.rcpt_to.clear();
        self.data_buffer.clear();

        Ok(())
    }

    /// Send an SMTP response
    async fn send_response(&mut self, code: u16, message: &str) -> Result<()> {
        self.send_line(&format!("{} {}", code, message)).await
    }

    /// Send a line
    async fn send_line(&mut self, line: &str) -> Result<()> {
        self.stream.write_all(line.as_bytes()).await?;
        self.stream.write_all(b"\r\n").await?;
        self.stream.flush().await?;
        Ok(())
    }
}

/// #169/#172:Extract email address from SMTP command argument,
/// properly handling angle brackets and ESMTP parameters after '>'.
fn extract_address(s: &str) -> Option<String> {
    let s = s.trim();
    if s.starts_with('<') {
        if let Some(end) = s.find('>') {
            let addr = &s[1..end];
            return Some(addr.to_string());
        }
        return None; // malformed
    }
    // Bare address:take up to first whitespace
    let addr = s.split_whitespace().next()?;
    if addr.is_empty() {
        return None;
    }
    Some(addr.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use tokio::io::AsyncReadExt;
    use tokio::net::TcpListener;

    async fn connected_streams() -> (TcpStream, TcpStream) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let client = TcpStream::connect(addr).await.unwrap();
        let (server, _) = listener.accept().await.unwrap();
        (server, client)
    }

    fn test_state() -> Arc<ServerState> {
        Arc::new(ServerState {
            hostname: "apexmail.test".into(),
            require_auth: true,
            enable_starttls: false,
            outbound_url: "http://127.0.0.1:0".into(),
            db_pool: PgPoolOptions::new()
                .connect_lazy("postgres://localhost/unused")
                .unwrap(),
            tls_acceptor: None,
        })
    }

    #[tokio::test]
    async fn handle_mail_allows_authenticated_sender_mismatch() {
        let (server_stream, mut client_stream) = connected_streams().await;
        let peer_addr = "127.0.0.1:2525".parse().unwrap();
        let mut session = SubmissionSession::new(server_stream, peer_addr, test_state());
        session.authenticated = true;
        session.auth_email = Some("auth@apexmail.test".into());

        session
            .handle_mail("FROM:<external@example.com>")
            .await
            .unwrap();

        assert_eq!(session.mail_from.as_deref(), Some("external@example.com"));

        let mut buf = [0u8; 128];
        let n = client_stream.read(&mut buf).await.unwrap();
        let response = String::from_utf8_lossy(&buf[..n]);
        assert!(response.contains("250 OK"));
    }
}
