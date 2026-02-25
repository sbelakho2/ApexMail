//! SMTP Session Handler

use anyhow::Result;
use std::sync::{Arc, LazyLock};
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

// #156: Shared DNS resolver — avoids re-reading /etc/resolv.conf per message
static EDGE_RESOLVER: LazyLock<Resolver> = LazyLock::new(|| {
    Resolver::new_system_conf()
        .expect("Failed to create system DNS resolver at startup")
});

pub struct SmtpConfig {
    pub hostname: String,
    pub mailstore_addr: String,
    pub max_message_size: usize,
    pub max_recipients: usize,
    pub enable_starttls: bool,
    pub tls_acceptor: Option<TlsAcceptor>,
    /// Domains this server accepts mail for
    pub local_domains: Vec<String>,
    /// #157: Cached gRPC channel to mailstore — reused across messages
    grpc_channel: tokio::sync::Mutex<Option<tonic::transport::Channel>>,
}

impl SmtpConfig {
    /// Create a new SmtpConfig.
    pub fn new(
        hostname: String,
        mailstore_addr: String,
        max_message_size: usize,
        max_recipients: usize,
        enable_starttls: bool,
        tls_acceptor: Option<TlsAcceptor>,
        local_domains: Vec<String>,
    ) -> Self {
        Self {
            hostname,
            mailstore_addr,
            max_message_size,
            max_recipients,
            enable_starttls,
            tls_acceptor,
            local_domains,
            grpc_channel: tokio::sync::Mutex::new(None),
        }
    }

    /// #157: Get or create a shared gRPC mailstore client.
    /// Re-uses the underlying HTTP/2 channel across messages.
    pub async fn grpc_client(
        &self,
        endpoint: &str,
    ) -> Result<MailstoreServiceClient<tonic::transport::Channel>> {
        let mut guard = self.grpc_channel.lock().await;
        if let Some(ref channel) = *guard {
            return Ok(MailstoreServiceClient::new(channel.clone()));
        }
        let channel = tonic::transport::Channel::from_shared(endpoint.to_string())
            .map_err(|e| anyhow::anyhow!("Invalid mailstore endpoint: {}", e))?
            .connect()
            .await
            .map_err(|e| anyhow::anyhow!("Failed to connect to mailstore: {}", e))?;
        *guard = Some(channel.clone());
        Ok(MailstoreServiceClient::new(channel))
    }
}

#[derive(Debug, Default)]
struct SmtpState {
    helo: Option<String>,
    mail_from: Option<String>,
    rcpt_to: Vec<String>,
    data_mode: bool,
    data_buffer: Vec<u8>,
    data_too_large: bool,
    #[allow(dead_code)]
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
    peer_addr: std::net::SocketAddr,
) -> Result<()> {
    let mut stream = SessionStream::Plain(BufStream::new(socket));
    let mut state = SmtpState::default();
    let peer = peer_addr.to_string();
    
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
                        if state.data_too_large {
                            stream.write_all(b"552 5.3.4 Message too large\r\n").await?;
                            stream.flush().await?;
                            state.data_too_large = false;
                        } else {
                            // Process message
                            let result = process_message(&state, &config, peer_addr).await;

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
                        }

                        // Reset state for next message
                        state.mail_from = None;
                        state.rcpt_to.clear();
                        state.data_buffer.clear();
                        state.data_too_large = false;
                    } else {
                        // Handle dot-stuffing
                        let data_line = if line.starts_with("..") {
                            &line[1..]
                        } else {
                            &line
                        };

                        if !state.data_too_large && state.data_buffer.len() + data_line.len() > config.max_message_size {
                            // Keep draining until end-of-data to avoid desync
                            state.data_too_large = true;
                            state.data_buffer.clear();
                        } else if !state.data_too_large {
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
            state.data_too_large = false;
            "354 Start mail input; end with <CRLF>.<CRLF>\r\n".to_string()
        }
        
        "RSET" => {
            state.mail_from = None;
            state.rcpt_to.clear();
            state.data_buffer.clear();
            state.data_too_large = false;
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
    // Handle <address> format (including null sender <>)
    if s.starts_with('<') {
        if let Some(end) = s.find('>') {
            let inner = &s[1..end];
            // Empty <> is the null sender — valid in SMTP
            return Some(inner.to_string());
        }
        // Malformed: '<' without '>'
        return None;
    }
    
    // #161: Handle bare address — take token up to first whitespace.
    // Bare addresses are valid in SMTP (RFC 5321 §4.1.1.2 allows local-part only).
    let addr = s.split_whitespace().next()?;
    if addr.is_empty() {
        return None;
    }
    Some(addr.to_string())
}

fn is_local_domain(addr: &str, config: &SmtpConfig) -> bool {
    let domain = addr.split('@').nth(1).unwrap_or("").to_lowercase();
    // #160: Removed unconditional localhost acceptance — prevents relay to
    // internal services. Localhost must be explicitly configured if needed.
    config.local_domains.iter().any(|d| d.to_lowercase() == domain)
}

async fn process_message(
    state: &SmtpState,
    config: &SmtpConfig,
    peer_addr: std::net::SocketAddr,
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
    let peer_ip: std::net::IpAddr = peer_addr.ip();
    
    // #156: Use shared DNS resolver instead of creating one per message
    let resolver = &*EDGE_RESOLVER;
    
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
                    peer = %peer_addr,
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
                peer = %peer_addr,
                from = %from_addr,
                dkim = %overall,
                "DKIM verification result"
            );
            overall.to_string()
        }
        None => {
            debug!(peer = %peer_addr, "Could not parse message for DKIM verification");
            "none".to_string()
        }
    };
    
    // ── #158: DMARC evaluation with DNS record lookup ──────────────────
    let spf_aligned = spf_result == "pass";
    let dkim_aligned = dkim_result == "pass";

    // Determine raw DMARC alignment result
    let dmarc_aligned = if !from_domain.is_empty() {
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

    // #158: Fetch the actual DMARC DNS record to determine the domain's policy
    let dmarc_policy = if !from_domain.is_empty() {
        fetch_dmarc_policy(resolver, &from_domain).await
    } else {
        "none".to_string() // no domain → no policy
    };

    // Apply DMARC policy to determine final action
    let dmarc_result = dmarc_aligned;

    info!(
        peer = %peer_addr,
        from = %from_addr,
        spf = %spf_result,
        dkim = %dkim_result,
        dmarc = %dmarc_result,
        dmarc_policy = %dmarc_policy,
        "Authentication-Results summary"
    );

    // #159: SPF hard-fail rejection is now deferred to DMARC policy.
    // Only reject if the DMARC policy mandates it (p=reject or p=quarantine).
    if dmarc_result == "fail" {
        match dmarc_policy.as_str() {
            "reject" => {
                warn!(
                    peer = %peer_addr,
                    from = %from_addr,
                    dmarc_policy = "reject",
                    "DMARC reject — SPF and DKIM both failed, domain policy demands rejection"
                );
                return Err(anyhow::anyhow!(
                    "Message failed authentication (SPF={}, DKIM={}, DMARC=fail, policy=reject)",
                    spf_result, dkim_result
                ));
            }
            "quarantine" => {
                warn!(
                    peer = %peer_addr,
                    from = %from_addr,
                    dmarc_policy = "quarantine",
                    "DMARC quarantine — SPF and DKIM both failed, marking suspicious"
                );
                // We still accept but could flag — for now, log and continue
            }
            _ => {
                // p=none or no policy — accept the message
                info!(
                    peer = %peer_addr,
                    from = %from_addr,
                    dmarc_policy = %dmarc_policy,
                    "DMARC fail but policy is none/missing — accepting message"
                );
            }
        }
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
    
    // ── #157: Store via mailstore gRPC — use shared client ─────────────
    let mailstore_endpoint = if config.mailstore_addr.starts_with("http://") || config.mailstore_addr.starts_with("https://") {
        config.mailstore_addr.clone()
    } else {
        format!("http://{}", config.mailstore_addr)
    };

    let mut client = config.grpc_client(&mailstore_endpoint).await
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
        peer = %peer_addr,
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

/// #158: Fetch the DMARC policy from DNS for a given domain.
/// Queries `_dmarc.{domain}` TXT record, falls back to parent domain.
/// Returns the policy value: "reject", "quarantine", "none", or "none" if not found.
async fn fetch_dmarc_policy(resolver: &Resolver, domain: &str) -> String {
    // Try exact domain first
    if let Some(policy) = query_dmarc_txt(resolver, domain).await {
        return policy;
    }
    // Fallback to organizational domain (parent): e.g. sub.example.com → example.com
    if let Some(dot_pos) = domain.find('.') {
        let parent = &domain[dot_pos + 1..];
        if parent.contains('.') {
            if let Some(policy) = query_dmarc_txt(resolver, parent).await {
                return policy;
            }
        }
    }
    "none".to_string()
}

/// Query `_dmarc.{domain}` TXT record and extract `p=` value.
async fn query_dmarc_txt(resolver: &Resolver, domain: &str) -> Option<String> {
    let qname = format!("_dmarc.{domain}");
    let raw = resolver.txt_raw_lookup(&qname).await.ok()?;
    let txt = String::from_utf8_lossy(&raw).to_lowercase();
    if txt.starts_with("v=dmarc1") {
        // Extract p= tag
        for part in txt.split(';') {
            let part = part.trim();
            if part.starts_with("p=") {
                let value = part[2..].trim();
                match value {
                    "reject" | "quarantine" | "none" => return Some(value.to_string()),
                    _ => return Some("none".to_string()),
                }
            }
        }
    }
    None
}
