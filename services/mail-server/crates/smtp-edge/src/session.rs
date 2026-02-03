//! SMTP Session Handler

use anyhow::Result;
use std::sync::Arc;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};
use tokio::net::TcpStream;
use tracing::{debug, info, warn};

pub struct SmtpConfig {
    pub hostname: String,
    pub mailstore_addr: String,
    pub max_message_size: usize,
    pub max_recipients: usize,
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

pub async fn handle_connection(
    socket: TcpStream,
    config: Arc<SmtpConfig>,
    peer: String,
) -> Result<()> {
    let (reader, mut writer) = socket.into_split();
    let mut reader = BufReader::new(reader);
    let mut state = SmtpState::default();
    
    // Send greeting
    let greeting = format!("220 {} ESMTP ApexMail ready\r\n", config.hostname);
    writer.write_all(greeting.as_bytes()).await?;
    
    let mut line = String::new();
    
    loop {
        line.clear();
        
        if state.data_mode {
            // Reading message data
            match reader.read_line(&mut line).await {
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
                                writer.write_all(b"250 2.0.0 Message accepted for delivery\r\n").await?;
                            }
                            Err(e) => {
                                warn!(peer = %peer, error = %e, "Message rejected");
                                let response = format!("550 5.7.1 Message rejected: {}\r\n", e);
                                writer.write_all(response.as_bytes()).await?;
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
                            writer.write_all(b"552 5.3.4 Message too large\r\n").await?;
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
            match reader.read_line(&mut line).await {
                Ok(0) => break, // Connection closed
                Ok(_) => {
                    let response = handle_command(&line, &mut state, &config, &peer).await;
                    
                    if response.starts_with("221") {
                        writer.write_all(response.as_bytes()).await?;
                        break;
                    }
                    
                    writer.write_all(response.as_bytes()).await?;
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
            format!(
                "250-{} Hello {}\r\n\
                 250-SIZE {}\r\n\
                 250-8BITMIME\r\n\
                 250-ENHANCEDSTATUSCODES\r\n\
                 250-PIPELINING\r\n\
                 250 STARTTLS\r\n",
                config.hostname, args, config.max_message_size
            )
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
                    if is_local_domain(&addr) {
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
        
        "STARTTLS" => {
            // In production, this would upgrade to TLS
            "454 4.7.0 TLS not available\r\n".to_string()
        }
        
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

fn is_local_domain(addr: &str) -> bool {
    let domain = addr.split('@').nth(1).unwrap_or("");
    matches!(
        domain.to_lowercase().as_str(),
        "apexmail.ee" | "mail.apexmail.ee" | "localhost"
    )
}

async fn process_message(
    state: &SmtpState,
    _config: &SmtpConfig,
    _peer: &str,
) -> Result<()> {
    // In production, this would:
    // 1. Call spam gateway for scanning
    // 2. Store message via mailstore gRPC
    // For now, just log and accept
    
    debug!(
        from = ?state.mail_from,
        to = ?state.rcpt_to,
        size = state.data_buffer.len(),
        "Processing inbound message"
    );
    
    Ok(())
}
