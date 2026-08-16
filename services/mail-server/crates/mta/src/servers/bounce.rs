//! Bounce processing server – accepts DSN bounces and maps them to original messages.
//!
//! Listens on a dedicated port, enforces RFC 5321 null‑sender, classifies bounces per
//! RFC 3463 enhanced status codes, and manages the suppression list.

use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::BytesMut;
use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use tokio::io::{AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tracing::{debug, info, warn};
use uuid::Uuid;

use crate::config::BounceConfig;

use super::util::{read_line_capped, LineRead, MAX_COMMAND_LINE, MAX_DATA_LINE};

/// Per-line timeout while receiving bounce DATA.
const DATA_LINE_TIMEOUT: Duration = Duration::from_secs(300);

// #142:Pre-compiled regex for RFC 3463 enhanced status codes
static BOUNCE_STATUS_RE: LazyLock<Option<regex::Regex>> =
    LazyLock::new(|| regex::Regex::new(r"[45]\.[0-9]{1,3}\.[0-9]{1,3}").ok());

/// Per-IP message rate-limit window.
const PER_IP_RATE_WINDOW_SECS: u64 = 3600;

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
    /// Active connections per IP — enforces `max_connections_per_ip`.
    connections: Arc<DashMap<IpAddr, u32>>,
    /// Rolling per-IP message counter — enforces `max_messages_per_ip_per_hour`.
    per_ip_msgs: moka::sync::Cache<IpAddr, u64>,
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
            connections: Arc::new(DashMap::new()),
            per_ip_msgs: moka::sync::Cache::builder()
                .max_capacity(100_000)
                .time_to_live(Duration::from_secs(PER_IP_RATE_WINDOW_SECS))
                .build(),
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

    async fn handle_session(self: Arc<Self>, socket: TcpStream, peer: SocketAddr) {
        let peer_ip = peer.ip();

        // Enforce the per-IP connection cap (C3/H10 hardening).
        let active = self.connections.get(&peer_ip).map(|e| *e).unwrap_or(0);
        if !connection_allowed(active, self.config.max_connections_per_ip) {
            let mut s = BufStream::new(socket);
            let _ = write_line(&mut s, "421 Too many connections from your IP\r\n").await;
            return;
        }
        *self.connections.entry(peer_ip).or_insert(0) += 1;
        let _conn_guard = ConnGuard {
            conns: self.connections.clone(),
            ip: peer_ip,
        };

        let mut stream = BufStream::new(socket);
        let greeting = format!("220 {} Bounce Processor\r\n", self.hostname);
        if let Err(_e) = write_line(&mut stream, &greeting).await {
            return;
        }

        let mut rcpt_to = Vec::<String>::new();
        let mut mail_from_seen = false;
        let mut msgs_this_conn: u32 = 0;
        let mut line = String::new();

        loop {
            line.clear();
            match tokio::time::timeout(
                std::time::Duration::from_secs(120),
                read_line_capped(&mut stream, MAX_COMMAND_LINE),
            )
            .await
            {
                Ok(Ok(LineRead::Eof)) | Err(_) | Ok(Err(_)) => break,
                Ok(Ok(LineRead::TooLong)) => {
                    let _ = write_line(&mut stream, "500 5.5.2 Line too long\r\n").await;
                    continue;
                }
                Ok(Ok(LineRead::Line(l))) => line = l,
            }

            let cmd = line.trim().to_uppercase();

            if cmd.starts_with("EHLO") || cmd.starts_with("HELO") {
                let _host = line.split_whitespace().nth(1).unwrap_or("");
                let _ = write_line(&mut stream, &format!("250 {} Hello\r\n", self.hostname)).await;
            } else if cmd.starts_with("MAIL FROM") {
                let addr = extract_addr(&line);
                // RFC 5321:bounces (DSNs) must have exactly the null sender.
                // `extract_addr("MAIL FROM:<>")` yields the EMPTY string (the
                // angle brackets are stripped), so the null sender check must
                // accept "" — anything non-empty is a real sender and rejected.
                if !null_sender_ok(&addr) {
                    let _ =
                        write_line(&mut stream, "550 Bounce MAIL FROM must be null (<>)\r\n").await;
                } else {
                    mail_from_seen = true;
                    rcpt_to.clear();
                    let _ = write_line(&mut stream, "250 OK\r\n").await;
                }
            } else if cmd.starts_with("RCPT TO") {
                let addr = extract_addr(&line);
                if !mail_from_seen {
                    let _ = write_line(&mut stream, "503 Bad sequence (send MAIL FROM first)\r\n").await;
                } else if !bounce_rcpt_ok(&addr, &self.config.verp_domain) {
                    let _ = write_line(&mut stream, "550 Invalid bounce recipient\r\n").await;
                } else {
                    rcpt_to.push(addr);
                    let _ = write_line(&mut stream, "250 OK\r\n").await;
                }
            } else if cmd.starts_with("DATA") {
                if !mail_from_seen || rcpt_to.is_empty() {
                    let _ = write_line(&mut stream, "503 Bad sequence\r\n").await;
                    continue;
                }
                // Per-connection and per-IP message budgets (C3/H10 hardening).
                if msgs_this_conn >= self.config.max_messages_per_connection {
                    let _ = write_line(&mut stream, "452 Too many messages from this connection\r\n").await;
                    continue;
                }
                let ip_msgs = self.per_ip_msgs.get(&peer_ip).unwrap_or(0) + 1;
                self.per_ip_msgs.insert(peer_ip, ip_msgs);
                if ip_msgs > u64::from(self.config.max_messages_per_ip_per_hour) {
                    let _ = write_line(&mut stream, "452 Rate limit exceeded for your IP\r\n").await;
                    continue;
                }

                let _ = write_line(&mut stream, "354 Go ahead\r\n").await;
                let mut message = BytesMut::new();
                let mut too_large = false;
                // A bounce is only complete when the client sent the
                // <CRLF>.<CRLF> terminator; EOF/read-error mid-DATA yields a
                // truncated payload that must never be processed.
                let mut terminated = false;
                let mut timed_out = false;
                loop {
                    line.clear();
                    match tokio::time::timeout(
                        DATA_LINE_TIMEOUT,
                        read_line_capped(&mut stream, MAX_DATA_LINE),
                    )
                    .await
                    {
                        Err(_) => {
                            timed_out = true;
                            break;
                        }
                        Ok(Ok(LineRead::Eof)) | Ok(Err(_)) => break,
                        Ok(Ok(LineRead::TooLong)) => {
                            // A single line over the per-line cap cannot be
                            // part of a payload we are willing to store.
                            too_large = true;
                        }
                        Ok(Ok(LineRead::Line(l))) => {
                            line = l;
                            if line.trim() == "." {
                                terminated = true;
                                break;
                            }
                            if !too_large
                                && !append_data_line(&mut message, &line, self.config.max_message_size)
                            {
                                too_large = true;
                                // Drain the remainder without buffering it.
                                loop {
                                    line.clear();
                                    match tokio::time::timeout(
                                        DATA_LINE_TIMEOUT,
                                        read_line_capped(&mut stream, MAX_DATA_LINE),
                                    )
                                    .await
                                    {
                                        Err(_) => {
                                            timed_out = true;
                                            break;
                                        }
                                        Ok(Ok(LineRead::Eof)) | Ok(Err(_)) => break,
                                        Ok(Ok(LineRead::TooLong)) => {}
                                        Ok(Ok(LineRead::Line(dl))) => {
                                            if dl.trim() == "." {
                                                break;
                                            }
                                        }
                                    }
                                }
                                break;
                            }
                        }
                    }
                }

                if timed_out {
                    // Slow/stalled client mid-DATA: refuse rather than wait
                    // forever (and never accept the partial payload).
                    let _ = write_line(&mut stream, "421 4.4.2 Data timeout exceeded\r\n").await;
                } else if too_large {
                    let _ = write_line(&mut stream, "552 5.3.4 Message size exceeds fixed limit\r\n").await;
                } else if terminated {
                    match self.process_bounce(&rcpt_to, &message).await {
                        Ok(id) => {
                            let _ = write_line(&mut stream, &format!("250 OK id={id}\r\n")).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "Bounce processing failed");
                            let _ = write_line(&mut stream, "451 Temporary failure\r\n").await;
                        }
                    }
                }
                msgs_this_conn += 1;
                rcpt_to.clear();
            } else if cmd.starts_with("RSET") {
                rcpt_to.clear();
                mail_from_seen = false;
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
        // bounce_events.id is a UUID column (migration 093) — bind the Uuid
        // itself, not its String form.
        let bounce_id = Uuid::new_v4();
        let message = String::from_utf8_lossy(raw);

        // 1. Try to match via VERP address
        let mut original_message_id = None;
        let mut original_recipient = None;
        for addr in rcpt_to {
            if let Some((oid, recip)) = parse_verp_address(addr, &self.config.verp_domain) {
                // C3: never trust an unvalidated VERP payload — a malformed
                // recipient (header injection, control chars) is dropped.
                if is_valid_email_addr(&recip) {
                    original_message_id = Some(oid);
                    original_recipient = Some(recip);
                }
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

        // 4. Record bounce event — dedupe on (original_message_id, original_recipient).
        //    A retry that already produced a row must not run side effects again.
        let inserted = sqlx::query(
            r#"INSERT INTO bounce_events (
                id, original_message_id, original_recipient,
                bounce_type, bounce_subtype, diagnostic_code,
                status_code, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, NOW())
            ON CONFLICT (original_message_id, original_recipient)
            WHERE original_message_id IS NOT NULL AND original_recipient IS NOT NULL
            DO NOTHING"#,
        )
        .bind(bounce_id)
        .bind(&original_message_id)
        .bind(&original_recipient)
        .bind(format!("{:?}", bounce_info.bounce_type))
        .bind(&bounce_info.bounce_subtype)
        .bind(&bounce_info.diagnostic_code)
        .bind(&bounce_info.status)
        .execute(&self.pool)
        .await?
        .rows_affected()
            > 0;

        if !inserted {
            debug!(msg_id = ?original_message_id, "Duplicate bounce event, skipping side effects");
            return Ok(bounce_id.to_string());
        }

        // 5. C3: only act on bounces that reference a message this system sent.
        //    Resolve the tenant from email_queue and cross-check the VERP
        //    recipient against the queued recipient — a mismatch means the
        //    VERP address was forged and must not poison suppression.
        let (tenant_id, queued_recipient) = match original_message_id.as_deref() {
            Some(mid) => match self.lookup_sent_message(mid).await? {
                Some(v) => v,
                None => {
                    warn!(msg_id = %mid, "Bounce references unknown message — skipping suppression and webhook");
                    return Ok(bounce_id.to_string());
                }
            },
            None => {
                warn!("Bounce carries no original message id — skipping suppression and webhook");
                return Ok(bounce_id.to_string());
            }
        };

        let suppression_recipient = match (&original_recipient, queued_recipient) {
            (Some(verp_recip), queued_recip) if *verp_recip == queued_recip => Some(verp_recip.clone()),
            (Some(verp_recip), queued_recip) => {
                warn!(
                    verp_recipient = %verp_recip,
                    queued_recipient = %queued_recip,
                    msg_id = ?original_message_id,
                    "VERP recipient does not match queued recipient — dropping forged bounce"
                );
                None
            }
            (None, queued_recip) => Some(queued_recip),
        };

        // 6. Hard bounces → suppression list (canonical `suppressions` table).
        if bounce_info.bounce_type == BounceType::Hard {
            if let Some(ref recip) = suppression_recipient {
                let log_recip = log_recipient.as_deref().unwrap_or("redacted");
                let res = sqlx::query(
                    r#"INSERT INTO suppressions
                       (id, tenant_id, email, reason, subtype, source, created_at)
                       VALUES ($1, $2, $3, 'hard_bounce', 'mta', 'mta', NOW())
                       ON CONFLICT (tenant_id, email) DO NOTHING"#,
                )
                .bind(suppression_row_id())
                .bind(&tenant_id)
                .bind(recip)
                .execute(&self.pool)
                .await;
                match res {
                    Ok(_) => info!(email = %log_recip, "Added to suppression list (hard bounce)"),
                    Err(e) => {
                        // C4: a suppression write failure must never abort bounce
                        // processing (that used to trigger endless retry loops).
                        warn!(error = %e, "Suppression write failed; continuing bounce processing")
                    }
                }
            }
        }

        // 7. Queue webhook (only for verified messages)
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

        Ok(bounce_id.to_string())
    }

    /// Resolve the tenant and recipient of a message this system sent.
    ///
    /// Looks up `email_queue` by its id or message_id. Returns `None` when the
    /// message is unknown to this system (attacker-forged reference).
    async fn lookup_sent_message(
        &self,
        message_id: &str,
    ) -> anyhow::Result<Option<(String, String)>> {
        let row: Option<(String, String)> = sqlx::query_as(
            r#"SELECT COALESCE(tenant_id, '') AS tenant_id,
                      COALESCE(to_addresses[1], "to", '') AS recipient
               FROM email_queue
               WHERE id::text = $1 OR message_id::text = $1
               LIMIT 1"#,
        )
        .bind(message_id)
        .fetch_optional(&self.pool)
        .await?;

        Ok(row.filter(|(tenant, recipient)| !tenant.is_empty() && !recipient.is_empty()))
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
                // RFC 3463/3464: the absence of a 5.x status code must not
                // imply permanent failure. Unrecognised bounces are treated as
                // transient so a legitimate temporary failure is never
                // permanently suppressed.
                (BounceType::Transient, "unknown")
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

/// RAII guard that releases a per-IP connection slot when the session ends.
pub(crate) struct ConnGuard {
    pub(crate) conns: Arc<DashMap<IpAddr, u32>>,
    pub(crate) ip: IpAddr,
}

impl Drop for ConnGuard {
    fn drop(&mut self) {
        if let Some(mut entry) = self.conns.get_mut(&self.ip) {
            let count = *entry;
            if count <= 1 {
                drop(entry);
                self.conns.remove(&self.ip);
            } else {
                *entry = count - 1;
            }
        }
    }
}

/// A new session is only admitted while the per-IP count stays under the cap.
pub(crate) fn connection_allowed(current: u32, max: u32) -> bool {
    current < max
}

/// RFC 5321:bounce sessions require exactly the null sender `<>`.
///
/// `extract_addr` returns the address BETWEEN the angle brackets, so the null
/// sender arrives here as the empty string — requiring the literal `<>` used
/// to reject every legitimate bounce and killed the whole bounce pipeline.
pub(crate) fn null_sender_ok(addr: &str) -> bool {
    addr.is_empty()
}

/// Whether a `RCPT TO` address is an acceptable bounce recipient for this
/// server: a VERP address for the configured domain, or a legacy
/// `bounce@`/`bounces@`/`mailer-daemon@` address on the same domain.
///
/// C3: previously any address merely *containing* `bounces+` was accepted;
/// the VERP payload is now fully parsed and validated against `verp_domain`,
/// and legacy addresses must be on the VERP domain itself.
fn bounce_rcpt_ok(addr: &str, verp_domain: &str) -> bool {
    let inner = addr.trim_matches(|c| c == '<' || c == '>');
    if inner.is_empty() {
        return false;
    }
    if let Some((_, recipient)) = parse_verp_address(inner, verp_domain) {
        return is_valid_email_addr(&recipient);
    }
    for prefix in ["bounce@", "bounces@", "mailer-daemon@"] {
        if inner.starts_with(prefix) && inner.ends_with(&format!("@{verp_domain}")) {
            return true;
        }
    }
    false
}

/// Conservative addr-spec validation that blocks header injection and other
/// malformed payloads from reaching the suppression table (C3).
fn is_valid_email_addr(addr: &str) -> bool {
    if addr.len() > 320 || addr.is_empty() {
        return false;
    }
    if addr.bytes().any(|b| b.is_ascii_control() || b.is_ascii_whitespace()) {
        return false;
    }
    // Exactly one '@' with a non-empty local part and domain part.
    let (local, domain) = match addr.rsplit_once('@') {
        Some(parts) => parts,
        None => return false,
    };
    !local.is_empty() && !domain.is_empty() && !domain.starts_with('.') && !domain.ends_with('.')
}

/// Append one DATA line to the message buffer, honoring dot-unstuffing.
///
/// Returns `false` (leaving the buffer untouched) when the line would push
/// the message past `max_size` — the caller must then reject with `552` and
/// drain the remainder (H10).
pub(crate) fn append_data_line(message: &mut BytesMut, line: &str, max_size: usize) -> bool {
    let body = if line.starts_with("..") { &line[1..] } else { line };
    if message.len().saturating_add(body.len()) > max_size {
        return false;
    }
    message.extend_from_slice(body.as_bytes());
    true
}

/// New suppression row id (`sup_` + 18 hex chars = 22 chars, matching the
/// `suppressions.id VARCHAR(26)` column).
pub(crate) fn suppression_row_id() -> String {
    format!("sup_{}", &uuid::Uuid::new_v4().simple().to_string()[..18])
}

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
        // M54: stop at the attached original message — the MIME boundary is
        // where attacker-controlled (or merely stale) headers begin.
        if is_attached_original_boundary(&trimmed) {
            break;
        }
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
            if is_attached_original_boundary(&trimmed.to_lowercase()) {
                break;
            }
            if let Some(m) = re.find(trimmed) {
                if m.start() == 0 {
                    return m.as_str().to_string();
                }
            }
        }
    }
    String::new()
}

/// True when a (lower-cased, trimmed) header line marks the start of the
/// attached original message, i.e. the DSN part is over (M54).
fn is_attached_original_boundary(trimmed_lower: &str) -> bool {
    trimmed_lower.starts_with("content-type: message/rfc822")
        || trimmed_lower.starts_with("content-type: message/delivery-status")
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
    // Shared panic-safe helper: search for '>' only AFTER the '<'. Searching
    // the whole line could find a '>' before the '<' and slice out of bounds
    // (remote panic on malformed commands like "RCPT TO:x> <a@b>").
    if let Some(addr) = super::util::extract_addr_safe(line) {
        return addr.to_string();
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

    #[test]
    fn test_null_sender_ok() {
        // extract_addr("MAIL FROM:<>") yields the empty string — the null
        // sender must be accepted in that form or every bounce is rejected.
        assert!(null_sender_ok(""));
        assert!(!null_sender_ok("attacker@evil.com"));
        assert!(!null_sender_ok(" "));
    }

    #[test]
    fn test_extract_addr_null_sender_yields_empty() {
        assert_eq!(extract_addr("MAIL FROM:<>\r\n"), "");
        assert_eq!(extract_addr("MAIL FROM:<user@bounces.apexmail.ee>\r\n"), "user@bounces.apexmail.ee");
    }

    #[test]
    fn test_extract_addr_closing_bracket_before_opening_does_not_panic() {
        // '>' before '<' used to slice out of bounds and panic the session.
        assert_eq!(extract_addr("MAIL FROM:x> <user@example.com>\r\n"), "user@example.com");
        // Unterminated path: falls back to the last whitespace token
        // (trailing CRLF is split off as whitespace, the '<' stays attached).
        assert_eq!(
            extract_addr("MAIL FROM:unterminated <user@example.com\r\n"),
            "<user@example.com"
        );
    }

    #[test]
    fn test_bounce_rcpt_ok_accepts_verp_address() {
        assert!(bounce_rcpt_ok(
            "<bounces+msg123=example.com=user@bounces.apexmail.ee>",
            "bounces.apexmail.ee"
        ));
    }

    #[test]
    fn test_bounce_rcpt_ok_rejects_verp_wrong_domain() {
        assert!(!bounce_rcpt_ok(
            "<bounces+msg123=example.com=user@evil.com>",
            "bounces.apexmail.ee"
        ));
        assert!(!bounce_rcpt_ok(
            "bounces+msg123=example.com=user@bounces.apexmail.ee.evil.com",
            "bounces.apexmail.ee"
        ));
    }

    #[test]
    fn test_bounce_rcpt_ok_legacy_addresses() {
        assert!(bounce_rcpt_ok(
            "<bounce@bounces.apexmail.ee>",
            "bounces.apexmail.ee"
        ));
        assert!(bounce_rcpt_ok(
            "<bounces@bounces.apexmail.ee>",
            "bounces.apexmail.ee"
        ));
        assert!(bounce_rcpt_ok(
            "<mailer-daemon@bounces.apexmail.ee>",
            "bounces.apexmail.ee"
        ));
        assert!(!bounce_rcpt_ok(
            "<bounce@evil.com>",
            "bounces.apexmail.ee"
        ));
        assert!(!bounce_rcpt_ok(
            "<mailer-daemon@evil.com>",
            "bounces.apexmail.ee"
        ));
    }

    #[test]
    fn test_bounce_rcpt_ok_rejects_malformed_verp() {
        assert!(!bounce_rcpt_ok(
            "bounces+msg123@bounces.apexmail.ee",
            "bounces.apexmail.ee"
        ));
        assert!(!bounce_rcpt_ok(
            "bounces+id=domain=local with spaces@bounces.apexmail.ee",
            "bounces.apexmail.ee"
        ));
        assert!(!bounce_rcpt_ok(
            "bounces+id=domain=local\r\nX-Evil: 1@bounces.apexmail.ee",
            "bounces.apexmail.ee"
        ));
        assert!(!bounce_rcpt_ok("", "bounces.apexmail.ee"));
    }

    #[test]
    fn test_is_valid_email_addr() {
        assert!(is_valid_email_addr("user@example.com"));
        assert!(is_valid_email_addr("first.last+tag@sub.example.co.uk"));
        assert!(!is_valid_email_addr(""));
        assert!(!is_valid_email_addr("not-an-email"));
        assert!(!is_valid_email_addr("a b@example.com"));
        assert!(!is_valid_email_addr("user@example.com\r\nBcc: victim@evil.com"));
        assert!(!is_valid_email_addr("user@example.com\nBcc: victim@evil.com"));
        assert!(!is_valid_email_addr("@example.com"));
        assert!(!is_valid_email_addr("user@"));
    }

    #[test]
    fn test_append_data_line_caps_size() {
        let mut message = BytesMut::new();
        assert!(append_data_line(&mut message, "line one\r\n", 24));
        assert!(append_data_line(&mut message, "..unstuff me\r\n", 24));
        assert_eq!(message.as_ref(), b"line one\r\n.unstuff me\r\n");
        // Appending exactly up to the cap is allowed.
        assert!(append_data_line(&mut message, "x", 24));
        assert_eq!(message.as_ref(), b"line one\r\n.unstuff me\r\nx");
        // A line that would exceed the cap is rejected wholesale (message unchanged).
        assert!(!append_data_line(&mut message, "y", 24));
        assert_eq!(message.as_ref(), b"line one\r\n.unstuff me\r\nx");
        // A single line larger than the whole budget is rejected too.
        let mut m2 = BytesMut::new();
        assert!(!append_data_line(&mut m2, "y".repeat(25).as_str(), 24));
        assert!(m2.is_empty());
    }

    #[test]
    fn test_classify_unknown_defaults_to_transient() {
        let msg = "This is an opaque delivery failure with no recognizable code or keyword";
        let info = classify_bounce(msg);
        assert_eq!(
            info.bounce_type,
            BounceType::Transient,
            "RFC 3463: absence of a 5.x code must not imply permanent failure"
        );
    }

    #[test]
    fn test_extract_status_code_stops_at_attached_original() {
        let msg = concat!(
            "Content-Type: multipart/report; report-type=delivery-status; boundary=BB\r\n",
            "\r\n",
            "--BB\r\n",
            "Content-Type: message/delivery-status\r\n",
            "\r\n",
            "Final-Recipient: rfc822; user@example.com\r\n",
            "Action: failed\r\n",
            "Diagnostic-Code: smtp; 550 user unknown\r\n",
            "\r\n",
            "--BB\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "Subject: the original message\r\n",
            "Status: 5.1.1 no such user\r\n",
            "--BB--\r\n",
        );
        // The DSN part carries no Status header, so the 5.1.1 inside the
        // attached original must NOT be picked up.
        assert_eq!(extract_status_code(msg), "");
    }

    #[test]
    fn test_extract_status_code_ignores_attached_original_when_no_dsn() {
        let msg = concat!(
            "Content-Type: multipart/report; boundary=BB\r\n",
            "--BB\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "Status: 5.1.1 no such user\r\n",
            "--BB--\r\n",
        );
        assert_eq!(extract_status_code(msg), "");
    }

    #[test]
    fn test_suppression_row_id_format() {
        let id = suppression_row_id();
        assert!(id.starts_with("sup_"));
        assert_eq!(id.len(), 22);
    }

    #[test]
    fn test_connection_allowed() {
        assert!(connection_allowed(0, 10));
        assert!(connection_allowed(9, 10));
        assert!(!connection_allowed(10, 10));
        assert!(!connection_allowed(11, 10));
    }
}
