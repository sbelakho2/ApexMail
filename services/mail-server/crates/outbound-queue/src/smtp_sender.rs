//! Direct SMTP Sender
//!
//! Sends emails directly via SMTP without any third-party services.
//! Includes DKIM signing, proper MX lookup, and retry logic.

use anyhow::{anyhow, Result};
use std::collections::HashMap;
use std::net::SocketAddr;
use std::time::Duration;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tokio::time::timeout;
use tracing::{debug, info, warn};
use trust_dns_resolver::TokioAsyncResolver;
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};

use crate::dkim::DkimSigner;

/// SMTP Send Result
#[derive(Debug, Clone)]
pub struct SmtpSendResult {
    pub success: bool,
    pub message_id: String,
    pub response: String,
    pub accepted: Vec<String>,
    pub rejected: Vec<String>,
}

/// Configuration for SMTP sending
#[derive(Debug, Clone)]
pub struct SmtpSenderConfig {
    pub hostname: String,
    pub timeout_seconds: u64,
    pub max_retries: u32,
    pub retry_delay_seconds: u64,
}

impl Default for SmtpSenderConfig {
    fn default() -> Self {
        Self {
            hostname: "mail.apexmail.ee".to_string(),
            timeout_seconds: 60,
            max_retries: 3,
            retry_delay_seconds: 30,
        }
    }
}

/// Direct SMTP Sender - NO THIRD-PARTY SERVICES
pub struct SmtpSender {
    config: SmtpSenderConfig,
    from_domain: String,
    resolver: TokioAsyncResolver,
    dkim_signer: Option<DkimSigner>,
    mx_cache: HashMap<String, Vec<String>>,
}

impl SmtpSender {
    /// Create a new SMTP sender with just the from domain
    pub fn new(from_domain: String) -> Self {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        
        Self {
            config: SmtpSenderConfig::default(),
            from_domain,
            resolver,
            dkim_signer: None,
            mx_cache: HashMap::new(),
        }
    }
    
    /// Create with custom config
    pub fn with_config(from_domain: String, config: SmtpSenderConfig) -> Self {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        
        Self {
            config,
            from_domain,
            resolver,
            dkim_signer: None,
            mx_cache: HashMap::new(),
        }
    }
    
    /// Create with DKIM signer
    pub fn with_dkim(from_domain: String, config: SmtpSenderConfig, dkim_signer: DkimSigner) -> Self {
        let resolver = TokioAsyncResolver::tokio(
            ResolverConfig::default(),
            ResolverOpts::default(),
        );
        
        Self {
            config,
            from_domain,
            resolver,
            dkim_signer: Some(dkim_signer),
            mx_cache: HashMap::new(),
        }
    }
    
    /// Set DKIM signer
    pub fn set_dkim_signer(&mut self, signer: DkimSigner) {
        self.dkim_signer = Some(signer);
    }
    
    /// Send an email directly via SMTP
    pub async fn send(
        &mut self,
        from: &str,
        to: &[String],
        subject: &str,
        text_body: Option<&str>,
        html_body: Option<&str>,
        headers: Option<HashMap<String, String>>,
    ) -> Result<SmtpSendResult> {
        // Group recipients by domain
        let mut by_domain: HashMap<String, Vec<String>> = HashMap::new();
        for recipient in to {
            let domain = recipient.split('@').nth(1)
                .ok_or_else(|| anyhow!("Invalid recipient: {}", recipient))?;
            by_domain.entry(domain.to_string())
                .or_default()
                .push(recipient.clone());
        }
        
        let mut all_accepted = Vec::new();
        let mut all_rejected = Vec::new();
        let mut last_response = String::new();
        
        // Send to each domain
        for (domain, recipients) in by_domain {
            // Build message
            let message = self.build_message(from, &recipients, subject, text_body, html_body, &headers)?;
            
            // Get MX servers for domain
            let mx_servers = self.lookup_mx(&domain).await?;
            
            if mx_servers.is_empty() {
                warn!(domain = %domain, "No MX records found");
                all_rejected.extend(recipients);
                continue;
            }
            
            // Try each MX server
            let mut sent = false;
            for mx_host in &mx_servers {
                match self.send_to_mx(mx_host, from, &recipients, &message).await {
                    Ok(result) => {
                        all_accepted.extend(result.accepted);
                        all_rejected.extend(result.rejected);
                        last_response = result.response;
                        sent = true;
                        break;
                    }
                    Err(e) => {
                        warn!(mx = %mx_host, error = %e, "MX delivery failed, trying next");
                    }
                }
            }
            
            if !sent {
                all_rejected.extend(recipients);
            }
        }
        
        let success = !all_accepted.is_empty();
        let message_id = format!("<{}@{}>", uuid::Uuid::new_v4(), self.config.hostname);
        
        Ok(SmtpSendResult {
            success,
            message_id,
            response: last_response,
            accepted: all_accepted,
            rejected: all_rejected,
        })
    }
    
    /// Look up MX records for a domain
    async fn lookup_mx(&mut self, domain: &str) -> Result<Vec<String>> {
        // Check cache first
        if let Some(cached) = self.mx_cache.get(domain) {
            return Ok(cached.clone());
        }
        
        debug!(domain = %domain, "Looking up MX records");
        
        let lookup = self.resolver.mx_lookup(domain).await;
        
        let mx_servers: Vec<String> = match lookup {
            Ok(mx) => {
                let mut servers: Vec<(u16, String)> = mx.iter()
                    .map(|r| (r.preference(), r.exchange().to_string().trim_end_matches('.').to_string()))
                    .collect();
                servers.sort_by_key(|(pref, _)| *pref);
                servers.into_iter().map(|(_, host)| host).collect()
            }
            Err(_) => {
                // Fall back to A record (implicit MX)
                vec![domain.to_string()]
            }
        };
        
        // Cache the result
        self.mx_cache.insert(domain.to_string(), mx_servers.clone());
        
        Ok(mx_servers)
    }
    
    /// Send to a specific MX server
    async fn send_to_mx(
        &self,
        mx_host: &str,
        from: &str,
        recipients: &[String],
        message: &[u8],
    ) -> Result<SmtpSendResult> {
        let timeout_duration = Duration::from_secs(self.config.timeout_seconds);
        
        // Resolve MX host to IP
        let addrs = self.resolver.lookup_ip(mx_host).await?;
        let addr = addrs.iter().next()
            .ok_or_else(|| anyhow!("No IP addresses for MX host: {}", mx_host))?;
        
        let socket_addr = SocketAddr::new(addr, 25);
        
        debug!(mx = %mx_host, addr = %socket_addr, "Connecting to MX server");
        
        // Connect with timeout
        let stream = timeout(timeout_duration, TcpStream::connect(socket_addr)).await??;
        let (reader, mut writer) = stream.into_split();
        let mut reader = BufReader::new(reader);
        let mut response = String::new();
        
        // Read greeting
        response.clear();
        reader.read_line(&mut response).await?;
        if !response.starts_with("220") {
            return Err(anyhow!("Bad greeting: {}", response.trim()));
        }
        
        // EHLO
        let ehlo_cmd = format!("EHLO {}\r\n", self.config.hostname);
        writer.write_all(ehlo_cmd.as_bytes()).await?;
        
        // Read EHLO response (may be multi-line), collect capabilities
        let mut ehlo_lines = Vec::new();
        loop {
            response.clear();
            reader.read_line(&mut response).await?;
            if response.len() < 4 {
                return Err(anyhow!("Invalid EHLO response"));
            }
            ehlo_lines.push(response.clone());
            if response.chars().nth(3) == Some(' ') {
                break;
            }
        }
        if !response.starts_with("250") {
            return Err(anyhow!("EHLO failed: {}", response.trim()));
        }
        
        // Check if remote server advertises STARTTLS
        let supports_starttls = ehlo_lines.iter().any(|l| {
            l.len() >= 4 && l[4..].trim().eq_ignore_ascii_case("STARTTLS")
        });
        
        // Attempt STARTTLS upgrade if supported
        if supports_starttls {
            debug!(mx = %mx_host, "Server supports STARTTLS, upgrading connection");
            
            writer.write_all(b"STARTTLS\r\n").await?;
            response.clear();
            reader.read_line(&mut response).await?;
            if !response.starts_with("220") {
                warn!(mx = %mx_host, response = %response.trim(), "STARTTLS rejected, continuing in plaintext");
            } else {
                // Reunite reader/writer back into the TcpStream
                let tcp_stream = reader.into_inner().reunite(writer)?;
                
                // Build TLS config with system root certificates
                let mut root_store = tokio_rustls::rustls::RootCertStore::empty();
                root_store.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
                
                let tls_config = tokio_rustls::rustls::ClientConfig::builder()
                    .with_root_certificates(root_store)
                    .with_no_client_auth();
                let connector = tokio_rustls::TlsConnector::from(std::sync::Arc::new(tls_config));
                
                let server_name = tokio_rustls::rustls::pki_types::ServerName::try_from(mx_host.to_string())
                    .map_err(|e| anyhow!("Invalid server name for TLS: {}", e))?;
                
                let tls_stream = connector.connect(server_name, tcp_stream).await
                    .map_err(|e| anyhow!("TLS handshake failed with {}: {}", mx_host, e))?;
                
                info!(mx = %mx_host, "STARTTLS upgrade successful");
                
                // Continue the SMTP conversation over TLS
                return self.smtp_conversation_over_tls(tls_stream, mx_host, from, recipients, message).await;
            }
        } else {
            debug!(mx = %mx_host, "Server does not support STARTTLS, sending in plaintext");
        }
        
        // Continue plaintext SMTP conversation (no STARTTLS or STARTTLS rejected)
        self.smtp_mail_transaction(&mut reader, &mut writer, from, recipients, message, mx_host).await
    }
    
    /// Continue SMTP conversation over a TLS stream
    async fn smtp_conversation_over_tls(
        &self,
        tls_stream: tokio_rustls::client::TlsStream<TcpStream>,
        mx_host: &str,
        from: &str,
        recipients: &[String],
        message: &[u8],
    ) -> Result<SmtpSendResult> {
        let (tls_reader, tls_writer) = tokio::io::split(tls_stream);
        let mut reader = BufReader::new(tls_reader);
        let mut writer = tls_writer;
        let mut response = String::new();
        
        // Re-EHLO after TLS upgrade (RFC 3207 §4.2)
        let ehlo_cmd = format!("EHLO {}\r\n", self.config.hostname);
        writer.write_all(ehlo_cmd.as_bytes()).await?;
        
        loop {
            response.clear();
            reader.read_line(&mut response).await?;
            if response.len() < 4 {
                return Err(anyhow!("Invalid EHLO response after STARTTLS"));
            }
            if response.chars().nth(3) == Some(' ') {
                break;
            }
        }
        if !response.starts_with("250") {
            return Err(anyhow!("EHLO after STARTTLS failed: {}", response.trim()));
        }
        
        // Proceed with MAIL FROM / RCPT TO / DATA over TLS
        self.smtp_mail_transaction(&mut reader, &mut writer, from, recipients, message, mx_host).await
    }
    
    /// Execute the MAIL FROM → RCPT TO → DATA → message sequence
    async fn smtp_mail_transaction<R, W>(
        &self,
        reader: &mut BufReader<R>,
        writer: &mut W,
        from: &str,
        recipients: &[String],
        message: &[u8],
        mx_host: &str,
    ) -> Result<SmtpSendResult>
    where
        R: tokio::io::AsyncRead + Unpin,
        W: tokio::io::AsyncWrite + Unpin,
    {
        let mut response = String::new();
        let mail_from = format!("MAIL FROM:<{}>\r\n", from);
        writer.write_all(mail_from.as_bytes()).await?;
        response.clear();
        reader.read_line(&mut response).await?;
        if !response.starts_with("250") {
            return Err(anyhow!("MAIL FROM failed: {}", response.trim()));
        }
        
        // RCPT TO for each recipient
        let mut accepted = Vec::new();
        let mut rejected = Vec::new();
        
        for recipient in recipients {
            let rcpt_to = format!("RCPT TO:<{}>\r\n", recipient);
            writer.write_all(rcpt_to.as_bytes()).await?;
            response.clear();
            reader.read_line(&mut response).await?;
            if response.starts_with("250") {
                accepted.push(recipient.clone());
            } else {
                rejected.push(recipient.clone());
                warn!(recipient = %recipient, response = %response.trim(), "Recipient rejected");
            }
        }
        
        if accepted.is_empty() {
            // RSET and return
            writer.write_all(b"RSET\r\n").await?;
            return Ok(SmtpSendResult {
                success: false,
                message_id: String::new(),
                response: response.trim().to_string(),
                accepted,
                rejected,
            });
        }
        
        // DATA
        writer.write_all(b"DATA\r\n").await?;
        response.clear();
        reader.read_line(&mut response).await?;
        if !response.starts_with("354") {
            return Err(anyhow!("DATA failed: {}", response.trim()));
        }
        
        // Send message
        writer.write_all(message).await?;
        
        // End of message
        writer.write_all(b"\r\n.\r\n").await?;
        response.clear();
        reader.read_line(&mut response).await?;
        if !response.starts_with("250") {
            return Err(anyhow!("Message rejected: {}", response.trim()));
        }
        
        let final_response = response.trim().to_string();
        
        // QUIT
        writer.write_all(b"QUIT\r\n").await?;
        
        info!(mx = %mx_host, accepted = ?accepted, "Message delivered successfully");
        
        Ok(SmtpSendResult {
            success: true,
            message_id: String::new(), // Would parse from response
            response: final_response,
            accepted,
            rejected,
        })
    }
    
    /// Build an RFC 5322 compliant email message
    fn build_message(
        &self,
        from: &str,
        to: &[String],
        subject: &str,
        text_body: Option<&str>,
        html_body: Option<&str>,
        headers: &Option<HashMap<String, String>>,
    ) -> Result<Vec<u8>> {
        use chrono::Utc;
        
        let message_id = format!("<{}@{}>", uuid::Uuid::new_v4(), self.config.hostname);
        let date = Utc::now().format("%a, %d %b %Y %H:%M:%S %z").to_string();
        
        let mut msg = Vec::new();
        
        // Required headers
        msg.extend_from_slice(format!("From: {}\r\n", from).as_bytes());
        msg.extend_from_slice(format!("To: {}\r\n", to.join(", ")).as_bytes());
        msg.extend_from_slice(format!("Subject: {}\r\n", subject).as_bytes());
        msg.extend_from_slice(format!("Date: {}\r\n", date).as_bytes());
        msg.extend_from_slice(format!("Message-ID: {}\r\n", message_id).as_bytes());
        msg.extend_from_slice(b"MIME-Version: 1.0\r\n");
        
        // Custom headers
        if let Some(hdrs) = headers {
            for (key, value) in hdrs {
                msg.extend_from_slice(format!("{}: {}\r\n", key, value).as_bytes());
            }
        }
        
        // Body
        match (text_body, html_body) {
            (Some(text), Some(html)) => {
                // Multipart alternative
                let boundary = format!("----=_Part_{}", uuid::Uuid::new_v4().to_string().replace("-", ""));
                msg.extend_from_slice(format!("Content-Type: multipart/alternative; boundary=\"{}\"\r\n", boundary).as_bytes());
                msg.extend_from_slice(b"\r\n");
                
                // Text part
                msg.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
                msg.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
                msg.extend_from_slice(b"Content-Transfer-Encoding: quoted-printable\r\n");
                msg.extend_from_slice(b"\r\n");
                msg.extend_from_slice(text.as_bytes());
                msg.extend_from_slice(b"\r\n");
                
                // HTML part
                msg.extend_from_slice(format!("--{}\r\n", boundary).as_bytes());
                msg.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
                msg.extend_from_slice(b"Content-Transfer-Encoding: quoted-printable\r\n");
                msg.extend_from_slice(b"\r\n");
                msg.extend_from_slice(html.as_bytes());
                msg.extend_from_slice(b"\r\n");
                
                // End boundary
                msg.extend_from_slice(format!("--{}--\r\n", boundary).as_bytes());
            }
            (Some(text), None) => {
                msg.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
                msg.extend_from_slice(b"\r\n");
                msg.extend_from_slice(text.as_bytes());
            }
            (None, Some(html)) => {
                msg.extend_from_slice(b"Content-Type: text/html; charset=utf-8\r\n");
                msg.extend_from_slice(b"\r\n");
                msg.extend_from_slice(html.as_bytes());
            }
            (None, None) => {
                msg.extend_from_slice(b"Content-Type: text/plain; charset=utf-8\r\n");
                msg.extend_from_slice(b"\r\n");
            }
        }
        
        // Sign with DKIM if configured
        if let Some(ref signer) = self.dkim_signer {
            let signature = signer.sign(&msg)?;
            let mut signed_msg = signature.into_bytes();
            signed_msg.extend_from_slice(b"\r\n");
            signed_msg.extend_from_slice(&msg);
            return Ok(signed_msg);
        }
        
        Ok(msg)
    }
}

/// Send a simple email (convenience function)
pub async fn send_email(
    from: &str,
    to: &[String],
    subject: &str,
    text_body: Option<&str>,
    html_body: Option<&str>,
    dkim_signer: Option<DkimSigner>,
) -> Result<SmtpSendResult> {
    let config = SmtpSenderConfig::default();
    let from_domain = from.split('@').nth(1).unwrap_or("apexmail.ee").to_string();
    
    let mut sender = if let Some(signer) = dkim_signer {
        SmtpSender::with_dkim(from_domain, config, signer)
    } else {
        SmtpSender::with_config(from_domain, config)
    };
    
    sender.send(from, to, subject, text_body, html_body, None).await
}
