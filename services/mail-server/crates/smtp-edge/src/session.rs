//! SMTP Session Handler

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::TcpStream;
use tokio_rustls::{TlsAcceptor, server::TlsStream};
use tracing::{debug, info, warn};
use mail_auth::{AuthenticatedMessage, DkimResult, Resolver, SpfResult};
use mail_parser::MessageParser;
use mail_proto::generated::{
    mailstore_service_client::MailstoreServiceClient,
    MessageFlags,
    StoreMessageRequest,
};

pub struct SmtpConfig {
    pub hostname: String,
    pub mailstore_addr: String,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub enable_starttls: bool,
    pub tls_acceptor: Option<TlsAcceptor>,
    /// Domains this server accepts mail for
    pub local_domains: Vec<String>,
}

#[derive(Debug, Default)]
struct SmtpState {
    helo: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data_mode: bool,
    data_buffer: Vec<u8>,
    authenticated: bool,
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
            SessionStream::Invalid => Err(anyhow::anyhow!("Invalid session stream state")),
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
            SessionStream::Invalid => Err(anyhow::anyhow!("Invalid session stream state")),
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
            SessionStream::Invalid => Err(anyhow::anyhow!("Invalid session stream state")),
        }
    }
}

pub async fn handle_connection(
    socket: TcpStream,
    config: Arc<SmtpConfig>,
    peer: String,
) -> Result<()> {
    let mut stream = SessionStream::Plain(BufStream::new(socket));
    let mut state = SmtpState::default();
    
    // Send greeting
    let greeting = format!("220 {} ESMTP ApexMail ready\r\n", config.hostname);
    stream.write_all(greeting.as_bytes()).await?;
    stream.flush().await?;
    
    let mut line = String::new();
    
    loop {
        line.clear();
        
        if state.data_mode {
            // Reading message data
            match stream.read_line(&mut line).await {
                Ok(0) => break, // Connection closed
                Ok(_) => {
                    if line.trim() == "." {
                        // End of data
                        state.data_mode = false;
                        
                        // Process message
                        let result = process_message(&state, &config, &peer).await;
                        
                        match result {
                            Ok(_) => {
                                info!(
                                    peer = %peer,
                                    from = ?state.mail_from,
                                    to = ?state.rcpt_to,
                                    size = state.data_buffer.len(),
                                    "Message accepted"
                                );
                                stream.write_all(b"250 2.0.0 Message accepted for delivery\r\n").await?;
                                stream.flush().await?;
                            }
                            Err(e) => {
                                warn!(peer = %peer, error = %e, "Message rejected");
                                let response = format!("550 5.7.1 Message rejected: {}\r\n", e);
                                stream.write_all(response.as_bytes()).await?;
                                stream.flush().await?;
                            }
                        }
                        
                        // Reset state for next message
                        state.mail_from = None;
                        state.rcpt_to.clear();
                        state.data_buffer.clear();
                    } else {
                        // Handle dot-stuffing
                        let data_line = if line.starts_with("..") {
                            &line[1..]
                        } else {
                            &line
                        };
                        
                        if state.data_buffer.len() + data_line.len() > config.max_message_size {
                            state.data_mode = false;
                            stream.write_all(b"552 5.3.4 Message too large\r\n").await?;
                            stream.flush().await?;
                            state.data_buffer.clear();
                        } else {
                            state.data_buffer.extend_from_slice(data_line.as_bytes());
                        }
                    }
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "Read error in DATA");
                    break;
                }
            }
        } else {
            // Reading commands
            match stream.read_line(&mut line).await {
                Ok(0) => break, // Connection closed
                Ok(_) => {
                    let command = line.trim().split_whitespace().next().unwrap_or("").to_uppercase();

                    if command == "STARTTLS" {
                        if !config.enable_starttls {
                            stream.write_all(b"454 4.7.0 TLS not available\r\n").await?;
                            stream.flush().await?;
                            continue;
                        }

                        if matches!(stream, SessionStream::Tls(_)) {
                            stream.write_all(b"503 5.5.1 TLS already active\r\n").await?;
                            stream.flush().await?;
                            continue;
                        }

                        let acceptor = match &config.tls_acceptor {
                            Some(a) => a,
                            None => {
                                stream.write_all(b"454 4.7.0 TLS not available\r\n").await?;
                                stream.flush().await?;
                                continue;
                            }
                        };

                        stream.write_all(b"220 2.0.0 Ready to start TLS\r\n").await?;
                        stream.flush().await?;

                        let current = std::mem::replace(&mut stream, SessionStream::Invalid);
                        let plain_stream = match current {
                            SessionStream::Plain(s) => s,
                            other => {
                                stream = other;
                                continue;
                            }
                        };

                        let tcp_stream = plain_stream.into_inner();
                        let tls_stream = acceptor.accept(tcp_stream).await?;
                        stream = SessionStream::Tls(BufStream::new(tls_stream));

                        // Reset session state after TLS negotiation
                        state = SmtpState::default();
                        continue;
                    }

                    let response = handle_command(&line, &mut state, &config, &peer).await;

                    if response.starts_with("221") {
                        stream.write_all(response.as_bytes()).await?;
                        stream.flush().await?;
                        break;
                    }

                    stream.write_all(response.as_bytes()).await?;
                    stream.flush().await?;
                }
                Err(e) => {
                    warn!(peer = %peer, error = %e, "Read error");
                    break;
                }
            }
        }
    }
    
    debug!(peer = %peer, "Connection closed");
    Ok(())
}

async fn handle_command(
    line: &str,
    state: &mut SmtpState,
    config: &SmtpConfig,
    _peer: &str,
) -> String {
    let line = line.trim();
    let (cmd, args) = match line.find(' ') {
        Some(pos) => (&line[..pos], line[pos + 1..].trim()),
        None => (line, ""),
    };
    
    let cmd_upper = cmd.to_uppercase();
    
    match cmd_upper.as_str() {
        "HELO" => {
            if args.is_empty() {
                return "501 5.5.4 HELO requires domain argument\r\n".to_string();
            }
            state.helo = Some(args.to_string());
            format!("250 {} Hello {}\r\n", config.hostname, args)
        }
        
        "EHLO" => {
            if args.is_empty() {
                return "501 5.5.4 EHLO requires domain argument\r\n".to_string();
            }
            state.helo = Some(args.to_string());
            let mut response = format!(
                "250-{} Hello {}\r\n\
                 250-SIZE {}\r\n\
                 250-8BITMIME\r\n\
                 250-ENHANCEDSTATUSCODES\r\n\
                 250-PIPELINING\r\n",
                config.hostname, args, config.max_message_size
            );

            if config.enable_starttls {
                response.push_str("250-STARTTLS\r\n");
            }

            response.push_str("250 HELP\r\n");
            response
        }
        
        "MAIL" => {
            if state.helo.is_none() {
                return "503 5.5.1 EHLO/HELO first\r\n".to_string();
            }
            
            // Parse MAIL FROM:<address>
            let from = parse_mail_from(args);
            match from {
                Some(addr) => {
                    state.mail_from = Some(addr);
                    state.rcpt_to.clear();
                    "250 2.1.0 Sender OK\r\n".to_string()
                }
                None => "501 5.1.7 Syntax error in MAIL FROM\r\n".to_string(),
            }
        }
        
        "RCPT" => {
            if state.mail_from.is_none() {
                return "503 5.5.1 MAIL first\r\n".to_string();
            }
            
            if state.rcpt_to.len() >= config.max_recipients {
                return "452 4.5.3 Too many recipients\r\n".to_string();
            }
            
            // Parse RCPT TO:<address>
            let to = parse_rcpt_to(args);
            match to {
                Some(addr) => {
                    // Check if we accept mail for this domain
                    if is_local_domain(&addr, config) {
                        state.rcpt_to.push(addr);
                        "250 2.1.5 Recipient OK\r\n".to_string()
                    } else {
                        "550 5.1.1 User not local; we do not relay\r\n".to_string()
                    }
                }
                None => "501 5.1.3 Syntax error in RCPT TO\r\n".to_string(),
            }
        }
        
        "DATA" => {
            if state.rcpt_to.is_empty() {
                return "503 5.5.1 RCPT first\r\n".to_string();
            }
            
            state.data_mode = true;
            state.data_buffer.clear();
            "354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string()
        }
        
        "RSET" => {
            state.mail_from = None;
            state.rcpt_to.clear();
            state.data_buffer.clear();
            "250 2.0.0 OK\r\n".to_string()
        }
        
        "NOOP" => "250 2.0.0 OK\r\n".to_string(),
        
        "QUIT" => format!("221 2.0.0 {} closing connection\r\n", config.hostname),
        
        "VRFY" => "252 2.5.2 Cannot VRFY user\r\n".to_string(),
        
        "EXPN" => "252 2.5.2 Cannot expand list\r\n".to_string(),
        
        _ => "500 5.5.1 Command not recognized\r\n".to_string(),
    }
}

fn parse_mail_from(args: &str) -> Option<String> {
    let args_upper = args.to_uppercase();
    if !args_upper.starts_with("FROM:") {
        return None;
    }
    
    let rest = args[5..].trim();
    extract_address(rest)
}

fn parse_rcpt_to(args: &str) -> Option<String> {
    let args_upper = args.to_uppercase();
    if !args_upper.starts_with("TO:") {
        return None;
    }
    
    let rest = args[3..].trim();
    extract_address(rest)
}

fn extract_address(s: &str) -> Option<String> {
    // Handle <address> format
    if s.starts_with('<') {
        if let Some(end) = s.find('>') {
            return Some(s[1..end].to_string());
        }
    }
    
    // Handle bare address
    let addr = s.split_whitespace().next()?;
    if addr.contains('@') {
        return Some(addr.to_string());
    }
    
    None
}

fn is_local_domain(addr: &str, config: &SmtpConfig) -> bool {
    let domain = addr.split('@').nth(1).unwrap_or("").to_lowercase();
    // Always accept localhost for development
    if domain == "localhost" {
        return true;
    }
    // Check against configured local domains
    config.local_domains.iter().any(|d| d.to_lowercase() == domain)
}

async fn process_message(
    state: &SmtpState,
    config: &SmtpConfig,
    peer: &str,
) -> Result<()> {
    let from_addr = state.mail_from.as_deref().unwrap_or("<>");
    let helo_domain = state.helo.as_deref().unwrap_or("unknown");
    let message_data = &state.data_buffer;
    
    // Extract sender domain for SPF/DMARC checks
    let from_domain = from_addr
        .split('@')
        .nth(1)
        .unwrap_or("")
        .to_lowercase();
    
    // Parse the peer IP address
    let peer_ip: std::net::IpAddr = peer
        .split(':')
        .next()
        .unwrap_or(peer)
        .parse()
        .unwrap_or(std::net::IpAddr::V4(std::net::Ipv4Addr::UNSPECIFIED));
    
    // Create DNS resolver for authentication checks
    let resolver = Resolver::new_system_conf()
        .map_err(|e| anyhow::anyhow!("Failed to create DNS resolver: {}", e))?;
    
    // ── SPF verification ───────────────────────────────────────────────
    let spf_result = if !from_domain.is_empty() {
        match resolver
            .verify_spf_sender(peer_ip, helo_domain, &from_domain, from_addr)
            .await
        {
            result => {
                let spf_status = match result.result() {
                    SpfResult::Pass => "pass",
                    SpfResult::Fail => "fail",
                    SpfResult::SoftFail => "softfail",
                    SpfResult::Neutral => "neutral",
                    SpfResult::TempError => "temperror",
                    SpfResult::PermError => "permerror",
                    SpfResult::None => "none",
                };
                info!(
                    peer = %peer,
                    from = %from_addr,
                    spf = %spf_status,
                    "SPF verification result"
                );
                spf_status.to_string()
            }
        }
    } else {
        "none".to_string()
    };
    
    // Hard fail SPF = reject
    if spf_result == "fail" {
        warn!(peer = %peer, from = %from_addr, "SPF hard fail — rejecting message");
        return Err(anyhow::anyhow!("SPF check failed: mail from {} not authorized by {}", peer, from_domain));
    }
    
    // ── DKIM verification ──────────────────────────────────────────────
    let dkim_result = match AuthenticatedMessage::parse(message_data) {
        Some(authenticated_msg) => {
            let dkim_output = resolver.verify_dkim(&authenticated_msg).await;
            let mut overall = "none";
            for result in dkim_output.iter() {
                match result.result() {
                    DkimResult::Pass => {
                        overall = "pass";
                        break; // One pass is enough
                    }
                    DkimResult::Fail(_) => {
                        if overall != "pass" {
                            overall = "fail";
                        }
                    }
                    DkimResult::Neutral(_) | DkimResult::None => {}
                    _ => {
                        if overall == "none" {
                            overall = "temperror";
                        }
                    }
                }
            }
            info!(
                peer = %peer,
                from = %from_addr,
                dkim = %overall,
                "DKIM verification result"
            );
            overall.to_string()
        }
        None => {
            debug!(peer = %peer, "Could not parse message for DKIM verification");
            "none".to_string()
        }
    };
    
    // ── DMARC evaluation ───────────────────────────────────────────────
    // DMARC passes if either SPF or DKIM passes AND aligns with From domain
    let dmarc_result = if !from_domain.is_empty() {
        let spf_aligned = spf_result == "pass";
        let dkim_aligned = dkim_result == "pass";
        
        if spf_aligned || dkim_aligned {
            "pass"
        } else if spf_result == "fail" && dkim_result == "fail" {
            "fail"
        } else {
            "none"
        }
    } else {
        "none"
    };
    
    info!(
        peer = %peer,
        from = %from_addr,
        spf = %spf_result,
        dkim = %dkim_result,
        dmarc = %dmarc_result,
        "Authentication-Results summary"
    );
    
    // Reject on DMARC fail (SPF fail + DKIM fail)
    if dmarc_result == "fail" {
        warn!(
            peer = %peer,
            from = %from_addr,
            "DMARC fail — both SPF and DKIM failed, rejecting"
        );
        return Err(anyhow::anyhow!(
            "Message failed authentication checks (SPF={}, DKIM={}, DMARC=fail)",
            spf_result,
            dkim_result
        ));
    }
    
    // ── Build Authentication-Results header ────────────────────────────
    let auth_results_header = format!(
        "Authentication-Results: {};\r\n\tspf={} smtp.mailfrom={};\r\n\tdkim={};\r\n\tdmarc={} header.from={}\r\n",
        config.hostname,
        spf_result,
        from_addr,
        dkim_result,
        dmarc_result,
        from_domain,
    );
    
    // Prepend Authentication-Results header to the message
    let mut final_message = auth_results_header.into_bytes();
    final_message.extend_from_slice(message_data);
    
    // ── Store via mailstore gRPC ───────────────────────────────────────
    let mailstore_endpoint = if config.mailstore_addr.starts_with("http://") || config.mailstore_addr.starts_with("https://") {
        config.mailstore_addr.clone()
    } else {
        format!("http://{}", config.mailstore_addr)
    };

    let mut client = MailstoreServiceClient::connect(mailstore_endpoint.clone())
        .await
        .map_err(|e| anyhow::anyhow!("Failed to connect to mailstore at {}: {}", mailstore_endpoint, e))?;

    let internal_date = chrono::Utc::now().timestamp();
    for recipient in &state.rcpt_to {
        let request = StoreMessageRequest {
            account_id: recipient.clone(),
            mailbox: "Inbox".to_string(),
            raw_message: final_message.clone(),
            flags: Some(MessageFlags {
                seen: false,
                answered: false,
                flagged: false,
                deleted: false,
                draft: false,
                recent: true,
                custom: vec![],
            }),
            internal_date,
        };

        let response = client
            .store_message(request)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to store message for recipient {}: {}", recipient, e))?
            .into_inner();

        debug!(
            recipient = %recipient,
            message_id = %response.message_id,
            uid = response.uid,
            blob_hash = %response.blob_hash,
            "Stored message in mailstore"
        );
    }

    let parsed_subject = MessageParser::new()
        .parse(&final_message)
        .and_then(|m| m.subject().map(|s| s.to_string()));
    
    info!(
        peer = %peer,
        from = %from_addr,
        to = ?state.rcpt_to,
        subject = ?parsed_subject,
        size = final_message.len(),
        spf = %spf_result,
        dkim = %dkim_result,
        dmarc = %dmarc_result,
        "Message accepted and authenticated — ready for mailstore delivery"
    );
    
    Ok(())
}
