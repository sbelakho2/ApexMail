//! Bounce processing server – accepts DSN bounces and maps them to original messages.
//!
//! Listens on a dedicated port, enforces RFC 5321 null‑sender, classifies bounces per
//! RFC 3463 enhanced status codes, and manages the suppression list.

use std::net::SocketAddr;
use std::sync::{Arc, LazyLock};

use bytes::BytesMut;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::BounceConfig;

// #142:Pre-compiled regex for RFC 3463 enhanced status codes
static BOUNCE_STATUS_RE: LazyLock<Option<regex::Regex>> =
    LazyLock::new(|| regex::Regex::new(r"[45]\.[0-9]{1,3}\.[0-9]{1,3}").ok());

// ── types ──────────────────────────────────────────────────────────────────────

/// Classification of a bounce.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BounceInfo {
    pub original_message_id: Option<String>,
    pub original_recipient: Option<String>,
    pub bounce_type: BounceType,
    pub bounce_subtype: String,
    pub diagnostic_code: Option<String>,
    pub action: String,
    pub status: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum BounceType {
    Hard,
    Soft,
    Transient,
}

/// Bounce processing server.
pub struct BounceServer {
    config: BounceConfig,
    pool: PgPool,
    redis: deadpool_redis::Pool,
    hostname: String,
    shutdown: Arc<Notify>,
}

impl BounceServer {
    pub fn new(
        config: BounceConfig,
        pool: PgPool,
        redis: deadpool_redis::Pool,
        hostname: String,
    ) -> Self {
        Self {
            config,
            pool,
            redis,
            hostname,
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Start listening.
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await?;
        info!(addr = %addr, "Bounce server listening");

        loop {
            tokio::select! {
                res = listener.accept() => {
                    match res {
                        Ok((socket, peer)) => {
                            let srv = self.clone();
                            tokio::spawn(async move { srv.handle_session(socket, peer).await });
                        }
                        Err(e) => warn!(error = %e, "Accept error"),
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

    async fn handle_session(self: Arc<Self>, socket: TcpStream, _peer: SocketAddr) {
        let mut stream = BufStream::new(socket);
        let greeting = format!("220 {} Bounce Processor\r\n", self.hostname);
        if let Err(_e) = write_line(&mut stream, &greeting).await {
            return;
        }

        let mut rcpt_to = Vec::<String>::new();
        let mut line = String::new();

        loop {
            line.clear();
            match tokio::time::timeout(
                std::time::Duration::from_secs(120),
                stream.read_line(&mut line),
            )
            .await
            {
                Ok(Ok(0)) | Err(_) => break,
                Ok(Ok(_)) => {}
                Ok(Err(_)) => break,
            }

            let cmd = line.trim().to_uppercase();

            if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                let _host = line.split_whitespace().nth(1).unwrap_or("");
                let _ = write_line(&mut stream, &format!("250 {} Hello\r\n", self.hostname)).await;
            } else if cmd.starts_with("MAIL FROM") {
                let addr = extract_addr(&line);
                // RFC 5321:bounces (DSNs) must have null sender
                if !addr.is_empty() && addr != "<>" {
                    let _ =
                        write_line(&mut stream, "550 Bounce MAIL FROM must be null (<>)\r\n").await;
                } else {
                    // #145:mail_from validated but not stored (always <> for bounces)
                    let _ = write_line(&mut stream, "250 OK\r\n").await;
                }
            } else if cmd.starts_with("RCPT TO") {
                let addr = extract_addr(&line);
                // Accept VERP addresses and standard bounce addresses
                let accepted = addr.contains("bounces+")
                    || addr.starts_with("bounce@")
                    || addr.starts_with("bounces@")
                    || addr.starts_with("mailer-daemon@");
                if accepted {
                    rcpt_to.push(addr);
                    let _ = write_line(&mut stream, "250 OK\r\n").await;
                } else {
                    let _ = write_line(&mut stream, "550 Invalid bounce recipient\r\n").await;
                }
            } else if cmd.starts_with("DATA") {
                if rcpt_to.is_empty() {
                    let _ = write_line(&mut stream, "503 Bad sequence\r\n").await;
                    continue;
                }
                let _ = write_line(&mut stream, "354 Go ahead\r\n").await;
                let mut message = BytesMut::new();
                loop {
                    line.clear();
                    match stream.read_line(&mut line).await {
                        Ok(0) => break,
                        Ok(_) => {
                            if line.trim() == "." {
                                break;
                            }
                            if line.starts_with("..") {
                                message.extend_from_slice(&line.as_bytes()[1..]);
                            } else {
                                message.extend_from_slice(line.as_bytes());
                            }
                        }
                        Err(_) => break,
                    }
                }

                match self.process_bounce(&rcpt_to, &message).await {
                    Ok(id) => {
                        let _ = write_line(&mut stream, &format!("250 OK id={id}\r\n")).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Bounce processing failed");
                        let _ = write_line(&mut stream, "451 Temporary failure\r\n").await;
                    }
                }
                rcpt_to.clear();
            } else if cmd.starts_with("RSET") {
                // #145:only clear rcpt_to (mail_from no longer tracked)
                rcpt_to.clear();
                let _ = write_line(&mut stream, "250 OK\r\n").await;
            } else if cmd.starts_with("QUIT") {
                let _ = write_line(&mut stream, "221 Bye\r\n").await;
                break;
            } else if cmd.starts_with("NOOP") {
                let _ = write_line(&mut stream, "250 OK\r\n").await;
            } else if cmd.starts_with("VRFY") || cmd.starts_with("EXPN") {
                // We intentionally do not reveal recipient validity to avoid directory harvests.
                let _ = write_line(
                    &mut stream,
                    "252 Cannot VRFY user, but will accept message and attempt delivery\r\n",
                )
                .await;
            } else if cmd.starts_with("HELP") {
                let _ = write_line(
                    &mut stream,
                    "214 Supported: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT\r\n",
                )
                .await;
            } else if cmd.starts_with("STARTTLS") {
                let _ = write_line(&mut stream, "454 TLS not available on this endpoint\r\n").await;
            } else {
                let _ = write_line(&mut stream, "500 Syntax error, command unrecognized\r\n").await;
            }
        }
    }

    // ── bounce processing ──────────────────────────────────────────────────────

    async fn process_bounce(&self, rcpt_to: &[String], raw: &[u8]) -> anyhow::Result<String> {
        let bounce_id = Uuid::new_v4().to_string();
        let message = String::from_utf8_lossy(raw);

        // 1. Try to match via VERP address
        let mut original_message_id = None;
        let mut original_recipient = None;
        for addr in rcpt_to {
            if let Some((oid, recip)) = parse_verp_address(addr, &self.config.verp_domain) {
                original_message_id = Some(oid);
                original_recipient = Some(recip);
                break;
            }
        }

        // O-1.7:Sanitize VERP-derived recipient data in logs and error messages
        let log_recipient = original_recipient.as_ref().map(|r| {
            if self.config.verp_sanitize {
                mail_common::pii::redact_email(r).to_string()
            } else {
                r.clone()
            }
        });

        // 2. If no VERP match, try to parse DSN
        if original_message_id.is_none() {
            if let Some(mid) = extract_original_message_id(&message) {
                original_message_id = Some(mid);
            }
        }

        // 3. Classify bounce
        let bounce_info = classify_bounce(&message);

        // 4. Record bounce event
        sqlx::query(
            r#"INSERT INTO bounce_events (
                id, original_message_id, original_recipient,
                bounce_type, bounce_subtype, diagnostic_code,
                status_code, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())"#,
        )
        .bind(&bounce_id)
        .bind(&original_message_id)
        .bind(&original_recipient)
        .bind(format!("{:?}", bounce_info.bounce_type))
        .bind(&bounce_info.bounce_subtype)
        .bind(&bounce_info.diagnostic_code)
        .bind(&bounce_info.status)
        .execute(&self.pool)
        .await?;

        // 5. Hard bounces → suppression list
        if bounce_info.bounce_type == BounceType::Hard {
            if let Some(ref recip) = original_recipient {
                sqlx::query(
                    "INSERT INTO suppression_list (email, reason, source, created_at) VALUES ($1, 'hard_bounce', 'mta', NOW()) ON CONFLICT DO NOTHING"
                )
                .bind(recip)
                .execute(&self.pool)
                .await?;
                // O-1.7:Use sanitized recipient in logs when verp_sanitize is enabled
                let log_recip = log_recipient.as_deref().unwrap_or("redacted");
                info!(email = %log_recip, "Added to suppression list (hard bounce)");
            }
        }

        // 6. Queue webhook
        // O-1.7:Use sanitized recipient in webhook when verp_sanitize is enabled
        let webhook_recipient = if self.config.verp_sanitize {
            log_recipient.clone()
        } else {
            original_recipient.clone()
        };
        let payload = serde_json::json!({
            "event": "bounce",
            "bounce_id": bounce_id,
            "original_message_id": original_message_id,
            "original_recipient": webhook_recipient,
            "bounce_type": format!("{:?}", bounce_info.bounce_type),
            "subtype": bounce_info.bounce_subtype,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        if let Ok(mut conn) = self.redis.get().await {
            redis::cmd("LPUSH")
                .arg("mta:webhook_queue")
                .arg(payload.to_string())
                .query_async::<i64>(&mut *conn) // LPUSH returns list length (i64)
                .await
                .ok();
        }

        info!(
            bounce_id = %bounce_id,
            msg_id = ?original_message_id,
            bounce_type = ?bounce_info.bounce_type,
            "Bounce processed"
        );

        Ok(bounce_id)
    }

    /// Clean up old unmatched bounces.
    pub async fn cleanup_unmatched_bounces(
        &self,
        retention_days: i32,
        batch_size: i32,
    ) -> anyhow::Result<u64> {
        let result = sqlx::query(
            r#"DELETE FROM bounce_events
               WHERE original_message_id IS NULL
               AND created_at < NOW() - make_interval(days => $1)
               AND id IN (
                   SELECT id FROM bounce_events
                   WHERE original_message_id IS NULL
                   AND created_at < NOW() - make_interval(days => $1)
                   LIMIT $2
               )"#,
        )
        .bind(retention_days)
        .bind(batch_size)
        .execute(&self.pool)
        .await?;

        Ok(result.rows_affected())
    }
}

// ── bounce classification (RFC 3463) ───────────────────────────────────────────

/// Classify a bounce message by its DSN status code.
pub fn classify_bounce(message: &str) -> BounceInfo {
    let status_code = extract_status_code(message);
    let diagnostic = extract_diagnostic_code(message);

    let (bounce_type, subtype) = match status_code.as_str() {
        s if s.starts_with("5.1.") => (
            BounceType::Hard,
            match s {
                "5.1.0" => "address-rejected",
                "5.1.1" => "no-mailbox",
                "5.1.2" => "no-such-domain",
                "5.1.3" => "bad-syntax",
                "5.1.4" => "ambiguous-address",
                "5.1.6" => "moved",
                _ => "address-error",
            },
        ),
        s if s.starts_with("5.2.") => (
            BounceType::Hard,
            match s {
                "5.2.1" => "disabled",
                "5.2.2" => "mailbox-full",
                "5.2.3" => "message-too-large",
                _ => "mailbox-error",
            },
        ),
        s if s.starts_with("5.3.") => (BounceType::Hard, "system-error"),
        s if s.starts_with("5.4.") => (BounceType::Hard, "network-error"),
        s if s.starts_with("5.5.") => (BounceType::Hard, "protocol-error"),
        s if s.starts_with("5.6.") => (BounceType::Hard, "content-error"),
        s if s.starts_with("5.7.") => (
            BounceType::Hard,
            match s {
                "5.7.1" => "policy",
                "5.7.13" => "account-disabled",
                "5.7.23" => "spf-failed",
                "5.7.25" => "ip-blacklisted",
                "5.7.26" => "dmarc-failed",
                _ => "security-error",
            },
        ),
        s if s.starts_with("4.2.") => (
            BounceType::Soft,
            match s {
                "4.2.1" => "disabled-temp",
                "4.2.2" => "mailbox-full",
                _ => "mailbox-temp",
            },
        ),
        s if s.starts_with("4.4.") => (BounceType::Soft, "network-error"),
        s if s.starts_with("4.7.") => (BounceType::Soft, "security-temp"),
        s if s.starts_with("4.") => (BounceType::Transient, "transient"),
        _ => {
            // Heuristic:look for keywords
            let lower = message.to_lowercase();
            if lower.contains("does not exist")
                || lower.contains("no such user")
                || lower.contains("unknown recipient")
                || lower.contains("unknown user")
            {
                (BounceType::Hard, "no-mailbox")
            } else if lower.contains("mailbox full")
                || lower.contains("over quota")
                || lower.contains("quota exceeded")
            {
                (BounceType::Soft, "mailbox-full")
            } else if lower.contains("temporarily") || lower.contains("try again") {
                (BounceType::Transient, "transient")
            } else {
                (BounceType::Hard, "unknown")
            }
        }
    };

    BounceInfo {
        original_message_id: extract_original_message_id(message),
        original_recipient: None,
        bounce_type,
        bounce_subtype: subtype.to_string(),
        diagnostic_code: diagnostic,
        action: if bounce_type == BounceType::Hard {
            "failed".into()
        } else {
            "delayed".into()
        },
        status: status_code,
    }
}

// ── parsing helpers ────────────────────────────────────────────────────────────

fn parse_verp_address(addr: &str, verp_domain: &str) -> Option<(String, String)> {
    // VERP format:bounces+{message_id}={recipient_domain}={recipient_local}@{verp_domain}
    let addr = addr.trim_matches(|c| c == '<' || c == '>');
    if !addr.ends_with(&format!("@{verp_domain}")) {
        return None;
    }
    let local = addr.split('@').next()?;
    let rest = local.strip_prefix("bounces+")?;

    // Split:message_id=domain=local
    let parts: Vec<&str> = rest.splitn(3, '=').collect();
    if parts.len() >= 3 {
        let message_id = parts[0].to_string();
        let recip = format!("{}@{}", parts[2], parts[1]);
        Some((message_id, recip))
    } else {
        None
    }
}

fn extract_status_code(message: &str) -> String {
    // #142:Use pre-compiled regex (LazyLock)
    // #143:Only search in DSN header lines (Status:, Diagnostic-Code:) to avoid
    // matching codes from the attached original message
    let mut saw_dsn_header = false;
    for line in message.lines() {
        let trimmed = line.trim().to_lowercase();
        if is_dsn_header_line(&trimmed) {
            saw_dsn_header = true;
        }
        if trimmed.starts_with("status:") || trimmed.starts_with("diagnostic-code:") {
            if let Some(re) = &*BOUNCE_STATUS_RE {
                if let Some(m) = re.find(line) {
                    return m.as_str().to_string();
                }
            }
        }
    }
    if saw_dsn_header {
        return String::new();
    }
    // Fallback:check lines starting with 3-digit SMTP reply codes
    if let Some(re) = &*BOUNCE_STATUS_RE {
        for line in message.lines() {
            let trimmed = line.trim();
            if let Some(m) = re.find(trimmed) {
                if m.start() == 0 {
                    return m.as_str().to_string();
                }
            }
        }
    }
    String::new()
}

fn is_dsn_header_line(trimmed_lower: &str) -> bool {
    matches!(
        trimmed_lower.split_once(':').map(|(name, _)| name),
        Some(
            "action"
                | "diagnostic-code"
                | "final-recipient"
                | "last-attempt-date"
                | "original-recipient"
                | "remote-mta"
                | "reporting-mta"
                | "status"
                | "will-retry-until"
        )
    )
}

fn extract_diagnostic_code(message: &str) -> Option<String> {
    for line in message.lines() {
        let trimmed = line.trim().to_lowercase();
        if trimmed.starts_with("diagnostic-code:") {
            return Some(line.trim().to_string());
        }
    }
    None
}

fn extract_original_message_id(message: &str) -> Option<String> {
    for line in message.lines() {
        let trimmed = line.trim().to_lowercase();
        if trimmed.starts_with("original-message-id:")
            || trimmed.starts_with("x-original-message-id:")
        {
            let value = line
                .split(':')
                .skip(1)
                .collect::<Vec<_>>()
                .join(":")
                .trim()
                .to_string();
            let cleaned = value.trim_matches(|c| c == '<' || c == '>').to_string();
            if !cleaned.is_empty() {
                return Some(cleaned);
            }
        }
    }
    // #144:Removed generic Message-ID fallback that could match the bounce's own ID.
    // Only Original-Message-ID / X-Original-Message-ID are reliable for matching.
    None
}

fn extract_addr(line: &str) -> String {
    if let Some(start) = line.find('<') {
        if let Some(end) = line.find('>') {
            return line[start + 1..end].to_string();
        }
    }
    line.split_whitespace().last().unwrap_or("").to_string()
}

async fn write_line<S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin>(
    stream: &mut BufStream<S>,
    data: &str,
) -> std::io::Result<()> {
    stream.write_all(data.as_bytes()).await?;
    stream.flush().await
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_classify_hard_bounce_no_mailbox() {
        let msg = "Status: 5.1.1\r\nDiagnostic-Code: smtp; 550 User unknown";
        let info = classify_bounce(msg);
        assert_eq!(info.bounce_type, BounceType::Hard);
        assert_eq!(info.bounce_subtype, "no-mailbox");
    }

    #[test]
    fn test_classify_soft_bounce_mailbox_full() {
        let msg = "Status: 4.2.2\r\nDiagnostic-Code: smtp; 452 Mailbox full";
        let info = classify_bounce(msg);
        assert_eq!(info.bounce_type, BounceType::Soft);
        assert_eq!(info.bounce_subtype, "mailbox-full");
    }

    #[test]
    fn test_classify_hard_bounce_policy() {
        let msg = "Status: 5.7.1\r\nPolicy rejection";
        let info = classify_bounce(msg);
        assert_eq!(info.bounce_type, BounceType::Hard);
        assert_eq!(info.bounce_subtype, "policy");
    }

    #[test]
    fn test_classify_transient_bounce() {
        let msg = "Status: 4.0.0\r\nTemporary issue";
        let info = classify_bounce(msg);
        assert_eq!(info.bounce_type, BounceType::Transient);
    }

    #[test]
    fn test_classify_heuristic_no_such_user() {
        let msg = "Sorry, no such user at this domain";
        let info = classify_bounce(msg);
        assert_eq!(info.bounce_type, BounceType::Hard);
        assert_eq!(info.bounce_subtype, "no-mailbox");
    }

    #[test]
    fn test_classify_heuristic_over_quota() {
        let msg = "User mailbox is over quota, please try again later";
        let info = classify_bounce(msg);
        assert_eq!(info.bounce_type, BounceType::Soft);
        assert_eq!(info.bounce_subtype, "mailbox-full");
    }

    #[test]
    fn test_parse_verp_address() {
        let result = parse_verp_address(
            "bounces+msg123=example.com=user@bounces.apexmail.ee",
            "bounces.apexmail.ee",
        );
        let (mid, recip) = result.expect("expected valid VERP address");
        assert_eq!(mid, "msg123");
        assert_eq!(recip, "user@example.com");
    }

    #[test]
    fn test_parse_verp_address_wrong_domain() {
        let result = parse_verp_address(
            "bounces+msg123=example.com=user@wrong.domain",
            "bounces.apexmail.ee",
        );
        assert!(result.is_none());
    }

    #[test]
    fn test_extract_status_code() {
        assert_eq!(extract_status_code("Status: 5.1.1 User unknown"), "5.1.1");
        assert_eq!(extract_status_code("4.7.1 rejected"), "4.7.1");
        assert_eq!(extract_status_code("No code here"), "");
    }

    #[test]
    fn test_extract_status_code_skips_fallback_when_dsn_headers_exist() {
        let msg = concat!(
            "Final-Recipient: rfc822; user@example.com\r\n",
            "Action: failed\r\n",
            "\r\n",
            "Original message follows\r\n",
            "5.1.1 this line belongs to the attached original message\r\n"
        );

        assert_eq!(extract_status_code(msg), "");
    }

    #[test]
    fn test_extract_status_code_keeps_fallback_without_dsn_headers() {
        let msg = "Original message follows\r\n5.1.1 recipient rejected\r\n";
        assert_eq!(extract_status_code(msg), "5.1.1");
    }

    #[test]
    fn test_extract_original_message_id() {
        let msg = "Subject: test\r\nOriginal-Message-ID: <abc123@example.com>\r\n";
        assert_eq!(
            extract_original_message_id(msg),
            Some("abc123@example.com".into())
        );
    }
}
