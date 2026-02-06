//! SMTP Submission Session
//!
//! Handles an authenticated SMTP session for email submission.

use anyhow::{anyhow, Result};
use std::net::SocketAddr;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, server::TlsStream};
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
        self.send_response(220, &format!("{} ESMTP ApexMail Submission", self.state.hostname)).await?;
        
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
                    
                    if let Err(e) = self.handle_command(&line).await {
                        error!(peer = %self.peer_addr, error = %e, "Command error");
                        self.send_response(500, "Internal error").await?;
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
    
    /// Handle an SMTP command
    async fn handle_command(&mut self, line: &str) -> Result<()> {
        let parts: Vec<&str> = line.splitn(2, ' ').collect();
        let command = parts[0].to_uppercase();
        let args = parts.get(1).copied().unwrap_or("");
        
        match command.as_str() {
            "EHLO" | "HELO" => self.handle_ehlo(args).await,
            "AUTH" => self.handle_auth(args).await,
            "MAIL" => self.handle_mail(args).await,
            "RCPT" => self.handle_rcpt(args).await,
            "DATA" => self.handle_data().await,
            "RSET" => self.handle_rset().await,
            "NOOP" => self.handle_noop().await,
            "QUIT" => self.handle_quit().await,
            "STARTTLS" => self.handle_starttls().await,
            _ => {
                self.send_response(500, "Unknown command").await?;
                Ok(())
            }
        }
    }
    
    /// Handle EHLO/HELO
    async fn handle_ehlo(&mut self, _domain: &str) -> Result<()> {
        let mut extensions = vec![
            format!("{}", self.state.hostname),
            "SIZE 52428800".to_string(), // 50MB
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
            let prefix = if i == extensions.len() - 1 { "250 " } else { "250-" };
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
                
                let result = auth_plain(&credentials, &self.state.db_pool).await?;
                self.complete_auth(result).await
            }
            "LOGIN" => {
                // Request username
                self.send_response(334, "VXNlcm5hbWU6").await?; // "Username:" in base64
                let mut username = String::new();
                self.stream.read_line(&mut username).await?;
                let username = username.trim().to_string();
                
                // Request password  
                self.send_response(334, "UGFzc3dvcmQ6").await?; // "Password:" in base64
                let mut password = String::new();
                self.stream.read_line(&mut password).await?;
                let password = password.trim().to_string();
                
                let result = auth_login(&username, &password, &self.state.db_pool).await?;
                self.complete_auth(result).await
            }
            _ => {
                self.send_response(504, "Unrecognized authentication mechanism").await?;
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
                email = ?result.email,
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
        
        let from = args[5..].trim();
        let from = from.trim_start_matches('<').trim_end_matches('>').trim();
        
        // Verify sender matches authenticated user (optional)
        if self.authenticated {
            if let Some(ref auth_email) = self.auth_email {
                if from != auth_email && !from.ends_with(&format!("@{}", self.state.hostname)) {
                    warn!(
                        peer = %self.peer_addr,
                        from = %from,
                        auth_email = %auth_email,
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
        
        // Parse RCPT TO:<address>
        let args_upper = args.to_uppercase();
        if !args_upper.starts_with("TO:") {
            self.send_response(501, "Syntax error").await?;
            return Ok(());
        }
        
        let to = args[3..].trim();
        let to = to.trim_start_matches('<').trim_end_matches('>').trim();
        
        if to.is_empty() || !to.contains('@') {
            self.send_response(550, "Invalid recipient").await?;
            return Ok(());
        }
        
        self.rcpt_to.push(to.to_string());
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
        
        self.send_response(354, "Start mail input; end with <CRLF>.<CRLF>").await?;
        
        // Read message data
        self.data_buffer.clear();
        let mut line = String::new();
        
        loop {
            line.clear();
            match self.stream.read_line(&mut line).await {
                Ok(0) => {
                    return Err(anyhow!("Client disconnected during DATA"));
                }
                Ok(_) => {
                    if line.trim() == "." {
                        break;
                    }
                    // Handle dot-stuffing
                    let data = if line.starts_with("..") { &line[1..] } else { &line };
                    self.data_buffer.extend_from_slice(data.as_bytes());
                }
                Err(e) => return Err(e.into()),
            }
        }
        
        // Submit message to outbound queue
        self.submit_message().await
    }
    
    /// Submit message to outbound queue
    async fn submit_message(&mut self) -> Result<()> {
        let from = self.mail_from.as_ref().unwrap().clone();
        let to = self.rcpt_to.clone();
        let data = String::from_utf8_lossy(&self.data_buffer).to_string();
        
        info!(
            peer = %self.peer_addr,
            from = %from,
            to = ?to,
            size = self.data_buffer.len(),
            "Submitting message"
        );
        
        // Connect to outbound queue and submit
        // For now, we'll use a direct database insert
        let message_id = Uuid::new_v4();
        
        // Parse subject from headers
        let subject = data.lines()
            .find(|l| l.to_lowercase().starts_with("subject:"))
            .map(|l| l[8..].trim().to_string())
            .unwrap_or_else(|| "(no subject)".to_string());
        
        // Insert into queue
        sqlx::query(r#"
            INSERT INTO email_queue (
                id, from_address, to_addresses, subject, 
                text_body, status, priority
            )
            VALUES ($1, $2, $3, $4, $5, 'pending', 50)
        "#)
        .bind(&message_id)
        .bind(&from)
        .bind(&to)
        .bind(&subject)
        .bind(&data)
        .execute(&self.state.db_pool)
        .await?;
        
        info!(
            message_id = %message_id,
            from = %from,
            to = ?to,
            "Message queued"
        );
        
        self.send_response(250, &format!("OK, message queued as {}", message_id)).await?;
        
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
    
    /// Handle QUIT
    async fn handle_quit(&mut self) -> Result<()> {
        self.send_response(221, &format!("{} Bye", self.state.hostname)).await?;
        Err(anyhow!("QUIT"))
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
