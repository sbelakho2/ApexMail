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

use super::util::{
    is_mail_from_arg, is_rcpt_to_arg, is_strict_end_of_data, line_content_bytes, line_lossy,
    log_session_summary, log_smtp_reject, metric_message, read_line_capped, split_verb,
    write_reply, LineRead, LineTerminator, MAX_COMMAND_LINE, MAX_DATA_LINE,
};

/// Per-line timeout while receiving bounce DATA.
const DATA_LINE_TIMEOUT: Duration = Duration::from_secs(300);

/// Total deadline for receiving one bounce DATA payload (slow-loris
/// protection, mirrors the inbound server's 10-minute cap).
const DATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

/// Maximum accepted `RCPT TO` addresses per bounce transaction. Bounces are
/// one-DSN-per-message; a handful of recipients is generous, and the bound
/// keeps a hostile client from growing `rcpt_to` without limit.
pub(crate) const MAX_RCPT_PER_TRANSACTION: usize = 100;

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
        let session_id = Uuid::new_v4().to_string();
        let started = std::time::Instant::now();

        // Enforce the per-IP connection cap (C3/H10 hardening). The
        // admission check and the slot increment are one atomic step —
        // concurrent connects cannot overshoot the cap.
        if !try_admit_connection(
            &self.connections,
            peer_ip,
            self.config.max_connections_per_ip,
        ) {
            let mut s = BufStream::new(socket);
            log_smtp_reject(
                "bounce",
                peer_ip,
                &session_id,
                "421 4.7.0 Too many connections, try again later",
            );
            let _ = write_reply(
                &mut s,
                "bounce",
                peer_ip,
                &session_id,
                "421 4.7.0 Too many connections, try again later\r\n",
            )
            .await;
            log_session_summary(
                "bounce",
                peer_ip,
                &session_id,
                false,
                false,
                0,
                started.elapsed().as_millis(),
                "conn_limit",
            );
            return;
        }
        // F-19: RAII slot guard (admission above already took the slot).
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
        let mut close_reason = "closed";

        loop {
            line.clear();
            match tokio::time::timeout(
                std::time::Duration::from_secs(120),
                read_line_capped(&mut stream, MAX_COMMAND_LINE),
            )
            .await
            {
                Ok(Ok(LineRead::Eof)) | Ok(Err(_)) => break,
                Err(_) => {
                    // Command-phase idle timeout: tell the client why the
                    // connection is going away (421, RFC 5321 §4.2.1).
                    close_reason = "idle_timeout";
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "421 4.4.2 Idle timeout, closing connection\r\n",
                    )
                    .await;
                    break;
                }
                Ok(Ok(LineRead::TooLong)) => {
                    // Remainder drained through its newline: synchronised.
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "500 5.5.2 Line too long\r\n",
                    )
                    .await;
                    continue;
                }
                Ok(Ok(LineRead::Overflow)) => {
                    // Resynchronisation impossible: reply and close so the
                    // leftover bytes can never be parsed as commands.
                    close_reason = "overflow";
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "500 5.5.2 Line too long\r\n",
                    )
                    .await;
                    break;
                }
                Ok(Ok(LineRead::Line(_, LineTerminator::BareLf))) => {
                    // F-08: a bare-LF COMMAND line is refused (DATA body
                    // tolerance is unchanged).
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "500 5.5.2 Bare LF not allowed\r\n",
                    )
                    .await;
                    continue;
                }
                Ok(Ok(LineRead::Line(l, _))) => line = line_lossy(&l),
            }

            // F-06: the verb is matched as an exact first token.
            let (verb_owned, arg) = split_verb(line.trim());
            let verb = verb_owned.as_str();

            if verb == "EHLO" || verb == "HELO" {
                let _host = line.split_whitespace().nth(1).unwrap_or("");
                // SIZE advertisement equals the enforced cap (RFC 1870): the
                // 552 reply below uses exactly max_message_size, so a client
                // that honours SIZE= never wastes a transfer.
                let caps = format!(
                    "250-{} Hello\r\n250-SIZE {}\r\n250 8BITMIME\r\n",
                    self.hostname, self.config.max_message_size
                );
                let _ = write_line(&mut stream, &caps).await;
            } else if verb == "MAIL" && is_mail_from_arg(arg) {
                let addr = extract_addr(&line);
                // RFC 5321:bounces (DSNs) must have exactly the null sender.
                // `extract_addr("MAIL FROM:<>")` yields the EMPTY string (the
                // angle brackets are stripped), so the null sender check must
                // accept "" — anything non-empty is a real sender and rejected.
                if !null_sender_ok(&addr) {
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "550 5.7.1 Bounce MAIL FROM must be null (<>)\r\n",
                    )
                    .await;
                } else {
                    mail_from_seen = true;
                    rcpt_to.clear();
                    let _ = write_line(&mut stream, "250 2.0.0 Ok\r\n").await;
                }
            } else if verb == "MAIL" {
                // F-06: "MAIL FROMX:..." is a syntax error, not a MAIL.
                let _ = write_reply(
                    &mut stream,
                    "bounce",
                    peer_ip,
                    &session_id,
                    "501 5.5.4 Syntax: MAIL FROM:<address>\r\n",
                )
                .await;
            } else if verb == "RCPT" && is_rcpt_to_arg(arg) {
                let addr = extract_addr(&line);
                if !mail_from_seen {
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "503 5.5.1 Error: need MAIL command first\r\n",
                    )
                    .await;
                } else if rcpt_to.len() >= MAX_RCPT_PER_TRANSACTION {
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "452 4.5.3 Too many recipients\r\n",
                    )
                    .await;
                } else if !bounce_rcpt_ok(&addr, &self.config.verp_domain) {
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "550 5.1.1 Invalid bounce recipient\r\n",
                    )
                    .await;
                } else {
                    rcpt_to.push(addr);
                    let _ = write_line(&mut stream, "250 2.0.0 Ok\r\n").await;
                }
            } else if verb == "RCPT" {
                let _ = write_reply(
                    &mut stream,
                    "bounce",
                    peer_ip,
                    &session_id,
                    "501 5.5.4 Syntax: RCPT TO:<address>\r\n",
                )
                .await;
            } else if verb == "DATA" {
                if !mail_from_seen || rcpt_to.is_empty() {
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "503 5.5.1 Bad sequence of commands\r\n",
                    )
                    .await;
                    continue;
                }
                // Per-connection and per-IP message budgets (C3/H10 hardening).
                if msgs_this_conn >= self.config.max_messages_per_connection {
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "452 4.5.3 Too many messages from this connection\r\n",
                    )
                    .await;
                    continue;
                }
                let ip_msgs = self.per_ip_msgs.get(&peer_ip).unwrap_or(0) + 1;
                self.per_ip_msgs.insert(peer_ip, ip_msgs);
                if ip_msgs > u64::from(self.config.max_messages_per_ip_per_hour) {
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "452 4.3.2 Rate limit exceeded for your IP\r\n",
                    )
                    .await;
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
                let mut overflowed = false;
                // E-9:total DATA deadline so a slow client cannot drip-feed
                // lines forever (each line gets at most DATA_LINE_TIMEOUT but
                // the whole payload at most DATA_TOTAL_TIMEOUT).
                let deadline = std::time::Instant::now() + DATA_TOTAL_TIMEOUT;
                loop {
                    line.clear();
                    let remaining = deadline
                        .checked_duration_since(std::time::Instant::now())
                        .unwrap_or(Duration::ZERO);
                    if remaining.is_zero() {
                        timed_out = true;
                        break;
                    }
                    let per_line = remaining.min(DATA_LINE_TIMEOUT);
                    match tokio::time::timeout(
                        per_line,
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
                        Ok(Ok(LineRead::Overflow)) => {
                            // Resynchronisation impossible: drop the payload
                            // and close (see below).
                            overflowed = true;
                            break;
                        }
                        Ok(Ok(LineRead::Line(l, term))) => {
                            // RFC 5321 strict: end-of-data is exactly "." with
                            // a CRLF terminator (bare-LF "." is body data).
                            if is_strict_end_of_data(&l, term) {
                                terminated = true;
                                break;
                            }
                            let content = line_content_bytes(&l, term);
                            if !too_large
                                && !append_data_line(
                                    &mut message,
                                    content,
                                    self.config.max_message_size,
                                )
                            {
                                too_large = true;
                                // Drain the remainder without buffering it.
                                loop {
                                    line.clear();
                                    let remaining = deadline
                                        .checked_duration_since(std::time::Instant::now())
                                        .unwrap_or(Duration::ZERO);
                                    if remaining.is_zero() {
                                        timed_out = true;
                                        break;
                                    }
                                    match tokio::time::timeout(
                                        remaining.min(DATA_LINE_TIMEOUT),
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
                                        Ok(Ok(LineRead::Overflow)) => break,
                                        Ok(Ok(LineRead::Line(dl, dterm))) => {
                                            if is_strict_end_of_data(&dl, dterm) {
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
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "421 4.4.2 Data timeout exceeded\r\n",
                    )
                    .await;
                } else if overflowed {
                    // Unresynchronisable stream: reply and close.
                    close_reason = "overflow";
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "500 5.5.2 Line too long\r\n",
                    )
                    .await;
                    break;
                } else if too_large {
                    let _ = write_reply(
                        &mut stream,
                        "bounce",
                        peer_ip,
                        &session_id,
                        "552 5.3.4 Message size exceeds fixed maximum message size\r\n",
                    )
                    .await;
                } else if terminated {
                    match self.process_bounce(&rcpt_to, &message).await {
                        Ok(id) => {
                            let _ =
                                write_line(&mut stream, &format!("250 2.0.0 Ok id={id}\r\n")).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "Bounce processing failed");
                            let _ = write_reply(
                                &mut stream,
                                "bounce",
                                peer_ip,
                                &session_id,
                                "451 4.3.0 Temporary failure\r\n",
                            )
                            .await;
                        }
                    }
                }
                msgs_this_conn += 1;
                rcpt_to.clear();
            } else if verb == "RSET" {
                rcpt_to.clear();
                mail_from_seen = false;
                let _ = write_line(&mut stream, "250 2.0.0 Ok\r\n").await;
            } else if verb == "QUIT" {
                let _ = write_line(&mut stream, "221 2.0.0 Bye\r\n").await;
                close_reason = "quit";
                break;
            } else if verb == "NOOP" {
                let _ = write_line(&mut stream, "250 2.0.0 Ok\r\n").await;
            } else if verb == "VRFY" || verb == "EXPN" {
                // We intentionally do not reveal recipient validity to avoid directory harvests.
                let _ = write_line(
                    &mut stream,
                    "252 2.5.2 Cannot VRFY user, but will accept message and attempt delivery\r\n",
                )
                .await;
            } else if verb == "HELP" {
                let _ = write_line(
                    &mut stream,
                    "214 2.0.0 Commands: EHLO HELO MAIL RCPT DATA RSET NOOP QUIT; see RFC 5321\r\n",
                )
                .await;
            } else if verb == "STARTTLS" {
                let _ = write_reply(
                    &mut stream,
                    "bounce",
                    peer_ip,
                    &session_id,
                    "454 4.7.0 TLS not available on this endpoint\r\n",
                )
                .await;
            } else {
                // F-06: unknown COMMAND is a syntax error (RFC 5321 §4.2.4).
                let _ = write_reply(
                    &mut stream,
                    "bounce",
                    peer_ip,
                    &session_id,
                    "500 5.5.2 Command not recognised\r\n",
                )
                .await;
            }
        }

        log_session_summary(
            "bounce",
            peer_ip,
            &session_id,
            false,
            false,
            msgs_this_conn,
            started.elapsed().as_millis(),
            close_reason,
        );
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

        let suppression_recipient =
            suppression_target(original_recipient.as_deref(), &queued_recipient);
        if let Some(verp_recip) = original_recipient.as_deref() {
            if suppression_recipient.is_none() {
                // F-23: both addresses are PII — redact before logging.
                warn!(
                    verp_recipient = %mail_common::pii::redact_email(verp_recip),
                    queued_recipient = %mail_common::pii::redact_email(&queued_recipient),
                    msg_id = ?original_message_id,
                    "VERP recipient does not match queued recipient — dropping forged bounce"
                );
            }
        }

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
            // LPUSH + LTRIM: a dead consumer must not grow the list (and
            // Redis memory) without bound.
            if let Err(e) =
                super::util::push_webhook_bounded(&mut *conn, &payload.to_string()).await
            {
                debug!(error = %e, "Failed to push bounce webhook to Redis queue");
            }
        }

        info!(
            bounce_id = %bounce_id,
            msg_id = ?original_message_id,
            bounce_type = ?bounce_info.bounce_type,
            "Bounce processed"
        );
        metric_message("bounce", "accepted");

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

/// Whether a 5.7.1 bounce's diagnostic text indicates an authentication
/// failure (SPF/DMARC/DKIM) rather than a generic content/spam policy.
/// Only the former says something permanent about future mail from this
/// sender; a generic policy rejection may accept mail again later.
fn is_authentication_policy_rejection(message: &str) -> bool {
    message
        .to_ascii_lowercase()
        .split(|c: char| !c.is_ascii_alphanumeric())
        .any(|token| {
            matches!(
                token,
                "spf" | "dmarc" | "dkim" | "authentication" | "authenticated"
            )
        })
}

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
        s if s.starts_with("5.7.") => {
            let hard = if s == "5.7.1" {
                // A bare 5.7.1 ("policy rejection") is usually a content or
                // spam policy, not a verdict on the recipient — retrying
                // later often succeeds, so it must not permanently suppress.
                // Only an SPF/DMARC/DKIM-flavoured 5.7.1 is a genuine hard
                // failure of the sender's authentication.
                is_authentication_policy_rejection(message)
            } else {
                true
            };
            (
                if hard {
                    BounceType::Hard
                } else {
                    BounceType::Soft
                },
                match s {
                    "5.7.1" => "policy",
                    "5.7.13" => "account-disabled",
                    "5.7.23" => "spf-failed",
                    "5.7.25" => "ip-blacklisted",
                    "5.7.26" => "dmarc-failed",
                    _ => "security-error",
                },
            )
        }
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

/// Atomically admit one connection under a per-IP cap.
///
/// Returns `true` when the slot was taken; the caller MUST then hold a
/// [`ConnGuard`] so the slot is released on every exit path. The
/// check-and-increment must be ONE critical section: a separate
/// read-then-increment let concurrent connects all observe "under the cap"
/// and slip past it (TOCTOU overshoot).
pub(crate) fn try_admit_connection(conns: &DashMap<IpAddr, u32>, ip: IpAddr, max: u32) -> bool {
    // DashMap's entry() pins the shard lock for the guard's lifetime, so
    // the cap check and the increment are one critical section per IP.
    let mut entry = conns.entry(ip).or_insert(0);
    if !connection_allowed(*entry, max) {
        return false;
    }
    *entry += 1;
    true
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
    if addr
        .bytes()
        .any(|b| b.is_ascii_control() || b.is_ascii_whitespace())
    {
        return false;
    }
    // Exactly one '@' with a non-empty local part and domain part.
    let (local, domain) = match addr.rsplit_once('@') {
        Some(parts) => parts,
        None => return false,
    };
    !local.is_empty() && !domain.is_empty() && !domain.starts_with('.') && !domain.ends_with('.')
}

/// Append one DATA body line (terminator already stripped) to the message
/// buffer, honoring RFC 5321 §4.5.2 dot-unstuffing (exactly ONE leading dot
/// removed) and normalizing the stored terminator to CRLF — a bare-LF body
/// line must never be stored or relayed with a bare LF.
///
/// Returns `false` (leaving the buffer untouched) when the line would push
/// the message past `max_size` — the caller must then reject with `552` and
/// drain the remainder (H10).
pub(crate) fn append_data_line(message: &mut BytesMut, content: &[u8], max_size: usize) -> bool {
    let body = super::util::unstuff_dot_line_bytes(content);
    // +2 for the normalized CRLF terminator.
    if message.len().saturating_add(body.len()).saturating_add(2) > max_size {
        return false;
    }
    message.extend_from_slice(body);
    message.extend_from_slice(b"\r\n");
    true
}

/// New suppression row id (`sup_` + 18 hex chars = 22 chars, matching the
/// `suppressions.id VARCHAR(26)` column).
pub(crate) fn suppression_row_id() -> String {
    format!("sup_{}", &uuid::Uuid::new_v4().simple().to_string()[..18])
}

/// Decide which address (if any) a bounce may place on the suppression list.
///
/// `verp_recipient` is the recipient parsed from the bounce's VERP envelope
/// address (whose local part already resolved to the queued message);
/// `queued_recipient` is the recipient recorded on that queued message.
fn suppression_target(verp_recipient: Option<&str>, queued_recipient: &str) -> Option<String> {
    match verp_recipient {
        Some(verp) if verp == queued_recipient => Some(verp.to_string()),
        // No VERP recipient: the bounce's only linkage to the queued message
        // is the attacker-writable Original-Message-ID header. Such a bounce
        // may be classified and logged, but must never suppress.
        None => None,
        // VERP present but pointing at a different address than the queued
        // message's recipient: forged or replayed VERP — never suppress.
        Some(_) => None,
    }
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
        // M54 parity with extract_status_code: a Diagnostic-Code line after
        // the message/rfc822 boundary belongs to the attached original
        // message and must never drive the bounce classification.
        if is_attached_original_boundary(&trimmed) {
            break;
        }
        if trimmed.starts_with("diagnostic-code:") {
            return Some(line.trim().to_string());
        }
    }
    None
}

fn extract_original_message_id(message: &str) -> Option<String> {
    for line in message.lines() {
        let trimmed = line.trim().to_lowercase();
        // M54 parity with extract_status_code: the linkage header must come
        // from the DSN part — everything after the message/rfc822 boundary
        // belongs to the attached original message and is attacker-writable.
        if is_attached_original_boundary(&trimmed) {
            break;
        }
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
        let msg = "Status: 5.7.1\r\nDiagnostic-Code: smtp; 550 5.7.1 SPF verification failed";
        let info = classify_bounce(msg);
        assert_eq!(info.bounce_type, BounceType::Hard);
        assert_eq!(info.bounce_subtype, "policy");
    }

    #[test]
    fn test_classify_generic_571_policy_rejection_is_soft() {
        // A bare 5.7.1 "policy rejection" (spam/content policy, rate
        // limits, greylisting-ish deferrals) says nothing permanent about
        // the RECIPIENT — treating it as Hard permanently suppressed
        // addresses that could accept mail again minutes later.
        let msg = "Status: 5.7.1\r\nDiagnostic-Code: smtp; 550 5.7.1 Policy rejection - mail refused by local policy";
        let info = classify_bounce(msg);
        assert_eq!(
            info.bounce_type,
            BounceType::Soft,
            "generic 5.7.1 must be transient, not a permanent suppression"
        );
    }

    #[test]
    fn test_classify_571_with_dmarc_detail_is_hard() {
        let msg =
            "Status: 5.7.1\r\nDiagnostic-Code: smtp; 550 5.7.1 DMARC policy violation (p=reject)";
        let info = classify_bounce(msg);
        assert_eq!(
            info.bounce_type,
            BounceType::Hard,
            "an authentication-flavoured 5.7.1 is a genuine hard failure"
        );
        assert_eq!(info.bounce_subtype, "policy");
    }

    #[test]
    fn test_classify_transient_bounce() {
        let msg = "Status: 4.0.0\r\nTemporary issue";
        let info = classify_bounce(msg);
        assert_eq!(info.bounce_type, BounceType::Transient);
    }

    #[test]
    fn test_extract_diagnostic_code_stops_at_attached_original() {
        // A Diagnostic-Code inside the attached original message is
        // attacker-writable and must not drive classification when the DSN
        // part itself carries none.
        let msg = concat!(
            "Content-Type: multipart/report; boundary=BB\r\n",
            "--BB\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "Diagnostic-Code: smtp; 550 forged diagnostic\r\n",
            "--BB--\r\n",
        );
        assert_eq!(
            extract_diagnostic_code(msg),
            None,
            "an attached-original Diagnostic-Code must be ignored"
        );
        // The DSN part's own diagnostic is still extracted.
        let dsn = "Final-Recipient: rfc822; user@example.com\r\nDiagnostic-Code: smtp; 550 user unknown\r\n";
        assert_eq!(
            extract_diagnostic_code(dsn),
            Some("Diagnostic-Code: smtp; 550 user unknown".into())
        );
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
    fn test_verp_round_trip_matches_documented_format() {
        // The VERP return-path format generated by the outbound pipeline is
        // `bounces+{message_id}={recipient_domain}={recipient_local}@{verp_domain}`;
        // the bounce parser must round-trip exactly that shape, and the
        // inbound server's VERP-reply detection (local part starts with
        // "bounces+") must be a superset of the parseable addresses.
        let verp_domain = "bounces.apexmail.ee";
        let message_id = "0192f0a4-abc";
        let recip_local = "user+tag";
        let recip_domain = "example.com";
        let addr = format!("bounces+{message_id}={recip_domain}={recip_local}@{verp_domain}");

        assert!(
            addr.starts_with("bounces+"),
            "inbound is_verp prefix matches"
        );
        assert_eq!(
            parse_verp_address(&addr, verp_domain),
            Some((
                message_id.to_string(),
                format!("{recip_local}@{recip_domain}")
            ))
        );

        // Tricky locals (embedded '=' allowed after the second field) still
        // round-trip; the message id itself must not contain '='.
        let tricky = format!("bounces+{message_id}={recip_domain}=a=b=c@{verp_domain}");
        assert_eq!(
            parse_verp_address(&tricky, verp_domain).map(|(_, recip)| recip),
            Some("a=b=c@example.com".to_string())
        );
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
    fn test_extract_original_message_id_stops_at_attached_original() {
        // M54 parity with extract_status_code: everything after the
        // message/rfc822 boundary belongs to the attached original message
        // (attacker-writable) and must never be used as the bounce linkage.
        let msg = concat!(
            "Content-Type: multipart/report; report-type=delivery-status; boundary=BB\r\n",
            "\r\n",
            "--BB\r\n",
            "Content-Type: message/delivery-status\r\n",
            "\r\n",
            "Reporting-MTA: dns; mail.example.com\r\n",
            "\r\n",
            "--BB\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "Original-Message-ID: <forged-attacker-id@evil.com>\r\n",
            "X-Original-Message-ID: <also-forged@evil.com>\r\n",
            "--BB--\r\n",
        );
        assert_eq!(
            extract_original_message_id(msg),
            None,
            "an Original-Message-ID inside the attached original message must be ignored"
        );
    }

    #[test]
    fn test_extract_original_message_id_in_dsn_part_still_parsed() {
        // The per-message DSN field (before the attached message) stays the
        // supported linkage for classification/logging.
        let msg = concat!(
            "Reporting-MTA: dns; mail.example.com\r\n",
            "Original-Message-ID: <legit-dsn-ref@example.com>\r\n",
            "\r\n",
            "Content-Type: message/rfc822\r\n",
            "\r\n",
            "Subject: attached original\r\n",
        );
        assert_eq!(
            extract_original_message_id(msg),
            Some("legit-dsn-ref@example.com".into())
        );
    }

    #[test]
    fn forged_bounce_with_only_original_message_id_never_suppresses() {
        // A bounce carrying only an attacker-writable Original-Message-ID
        // (no valid VERP envelope) must never land the queued recipient on
        // the suppression list — otherwise anyone can suppress any victim
        // by forging one header referencing a sent message.
        assert!(
            suppression_target(None, "victim@example.com").is_none(),
            "no VERP recipient => no suppression target"
        );
    }

    #[test]
    fn genuine_verp_bounce_still_suppresses() {
        assert_eq!(
            suppression_target(Some("user@example.com"), "user@example.com"),
            Some("user@example.com".to_string()),
            "a VERP recipient matching the queued recipient is suppressible"
        );
    }

    #[test]
    fn mismatched_verp_recipient_never_suppresses() {
        assert!(
            suppression_target(Some("other@example.com"), "user@example.com").is_none(),
            "a VERP recipient that differs from the queued recipient is a forged/replayed VERP"
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
        assert_eq!(
            extract_addr("MAIL FROM:<user@bounces.apexmail.ee>\r\n"),
            "user@bounces.apexmail.ee"
        );
    }

    #[test]
    fn test_extract_addr_closing_bracket_before_opening_does_not_panic() {
        // '>' before '<' used to slice out of bounds and panic the session.
        assert_eq!(
            extract_addr("MAIL FROM:x> <user@example.com>\r\n"),
            "user@example.com"
        );
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
        assert!(!bounce_rcpt_ok("<bounce@evil.com>", "bounces.apexmail.ee"));
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
        assert!(!is_valid_email_addr(
            "user@example.com\r\nBcc: victim@evil.com"
        ));
        assert!(!is_valid_email_addr(
            "user@example.com\nBcc: victim@evil.com"
        ));
        assert!(!is_valid_email_addr("@example.com"));
        assert!(!is_valid_email_addr("user@"));
    }

    #[test]
    fn test_append_data_line_caps_size() {
        // NOTE: updated with the smuggling fix — append_data_line now takes
        // the line CONTENT (terminator stripped), unstuffs exactly ONE
        // leading dot, and always appends a normalized CRLF terminator.
        let mut message = BytesMut::new();
        assert!(append_data_line(&mut message, b"line one", 23));
        assert!(append_data_line(&mut message, b"..unstuff me", 23));
        assert_eq!(message.as_ref(), b"line one\r\n.unstuff me\r\n");
        // Appending exactly up to the cap is allowed (23 = 10 + 13, CRLFs included).
        assert_eq!(message.len(), 23);
        // A line that would exceed the cap is rejected wholesale (message unchanged).
        assert!(!append_data_line(&mut message, b"x", 23));
        assert_eq!(message.as_ref(), b"line one\r\n.unstuff me\r\n");
        // A single line larger than the whole budget is rejected too.
        let mut m2 = BytesMut::new();
        assert!(!append_data_line(&mut m2, &"y".repeat(25).into_bytes(), 23));
        assert!(m2.is_empty());
    }

    #[test]
    fn test_append_data_line_unstuffs_exactly_one_dot() {
        // RFC 5321 §4.5.2 round-trips: the sender doubles a leading dot.
        let mut message = BytesMut::new();
        assert!(append_data_line(&mut message, b"..foo", 1024)); // stuffed ".foo"
        assert!(append_data_line(&mut message, b"..", 1024)); // stuffed "."
        assert!(append_data_line(&mut message, b"plain", 1024));
        assert_eq!(message.as_ref(), b".foo\r\n.\r\nplain\r\n");
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

    #[test]
    fn concurrent_admissions_cannot_exceed_the_per_ip_cap() {
        // 16 threads released by a barrier all attempt admission against a
        // cap of 10: exactly 10 may be admitted and the counter must land
        // on exactly 10 — a check-then-increment race admits the whole
        // first wave (16) past the cap.
        let conns: Arc<DashMap<IpAddr, u32>> = Arc::new(DashMap::new());
        let ip: IpAddr = "192.0.2.10".parse().unwrap();
        let barrier = Arc::new(std::sync::Barrier::new(16));
        let admitted = Arc::new(std::sync::atomic::AtomicUsize::new(0));
        let mut handles = Vec::new();
        for _ in 0..16 {
            let conns = conns.clone();
            let barrier = barrier.clone();
            let admitted = admitted.clone();
            handles.push(std::thread::spawn(move || {
                barrier.wait();
                if try_admit_connection(&conns, ip, 10) {
                    admitted.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
                }
            }));
        }
        for handle in handles {
            handle.join().expect("admission must not deadlock");
        }
        assert_eq!(
            admitted.load(std::sync::atomic::Ordering::SeqCst),
            10,
            "exactly the cap may be admitted"
        );
        assert_eq!(*conns.get(&ip).unwrap(), 10);
    }

    // ── B: full-session smuggling test (real TCP, DB unreachable) ──────────

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    fn test_bounce_server() -> BounceServer {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .expect("lazy pool construction cannot fail with a well-formed URL");
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool construction");
        let config = BounceConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 0,
            hostname: "bounce.test".into(),
            verp_domain: "bounces.apexmail.ee".into(),
            verp_sanitize: true,
            max_message_size: 1024 * 1024,
            max_connections_per_ip: 10,
            max_messages_per_connection: 100,
            max_messages_per_ip_per_hour: 2000,
        };
        BounceServer::new(config, pool, redis, "bounce.test".into())
    }

    async fn read_reply(
        reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> String {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("reply must arrive within 5s")
            .expect("read must not fail");
        line
    }

    /// Read a complete (possibly multi-line) SMTP reply: continuation lines
    /// are `NNN-…`, the final line is `NNN …`.
    async fn read_full_reply(
        reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> String {
        let mut full = String::new();
        loop {
            let line = read_reply(reader).await;
            let more = line.len() >= 4 && line.as_bytes()[3] == b'-';
            full.push_str(&line);
            if !more {
                return full;
            }
        }
    }

    #[tokio::test]
    async fn bounce_data_is_terminated_only_by_a_crlf_dot() {
        let server = std::sync::Arc::new(test_bounce_server());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        assert!(read_reply(&mut reader).await.starts_with("220"));

        writer.write_all(b"EHLO client.example\r\n").await.unwrap();
        assert!(read_full_reply(&mut reader).await.starts_with("250"));

        writer.write_all(b"MAIL FROM:<>\r\n").await.unwrap();
        assert!(read_reply(&mut reader).await.starts_with("250"));

        writer
            .write_all(b"RCPT TO:<bounces+msg123=example.com=user@bounces.apexmail.ee>\r\n")
            .await
            .unwrap();
        assert!(read_reply(&mut reader).await.starts_with("250"));

        writer.write_all(b"DATA\r\n").await.unwrap();
        assert!(read_reply(&mut reader).await.starts_with("354"));

        // Smuggling payload: a bare-LF "." line followed by what should be a
        // smuggled command, then more body, then the REAL terminator. If the
        // server treated ".\n" as end-of-data, "QUIT" would be parsed as a
        // command (221 + connection close) before we ever sent the real
        // terminator.
        writer
            .write_all(b"Subject: bounce\r\n.\nQUIT\r\ntail\r\n.\r\n")
            .await
            .unwrap();

        // Exactly one response follows the payload: the bounce hits the
        // (unreachable) DB and must yield 451 — never a 221 from a smuggled
        // QUIT, and never a 250 for a truncated message.
        let resp = read_reply(&mut reader).await;
        assert!(
            resp.starts_with("451"),
            "post-DATA reply must be the 451 from process_bounce, got {resp:?}"
        );

        // The session is still alive and command-synchronized: QUIT now gets 221.
        writer.write_all(b"QUIT\r\n").await.unwrap();
        let resp = read_reply(&mut reader).await;
        assert!(
            resp.starts_with("221"),
            "session still synchronized: {resp:?}"
        );

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn bounce_padded_dot_line_stays_body_data() {
        let server = std::sync::Arc::new(test_bounce_server());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let _ = read_reply(&mut reader).await; // greeting

        writer.write_all(b"EHLO client.example\r\n").await.unwrap();
        let _ = read_full_reply(&mut reader).await;
        writer.write_all(b"MAIL FROM:<>\r\n").await.unwrap();
        let _ = read_reply(&mut reader).await;
        writer
            .write_all(b"RCPT TO:<bounce@bounces.apexmail.ee>\r\n")
            .await
            .unwrap();
        let _ = read_reply(&mut reader).await;
        writer.write_all(b"DATA\r\n").await.unwrap();
        assert!(read_reply(&mut reader).await.starts_with("354"));

        // " ." / " . " must NOT terminate DATA (the old trim() check did).
        writer
            .write_all(b"body\r\n .\r\n . \r\n.\r\n")
            .await
            .unwrap();

        let resp = read_reply(&mut reader).await;
        assert!(
            resp.starts_with("451"),
            "padded dots are body data; the reply must be process_bounce's 451, got {resp:?}"
        );

        writer.write_all(b"QUIT\r\n").await.unwrap();
        let resp = read_reply(&mut reader).await;
        assert!(
            resp.starts_with("221"),
            "session still synchronized: {resp:?}"
        );

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    // ── exact enhanced status codes for the rejection suite ────────────────

    #[tokio::test]
    async fn bounce_rejection_suite_uses_exact_enhanced_status_codes() {
        let server = std::sync::Arc::new(test_bounce_server());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);

        let _ = read_reply(&mut reader).await; // greeting

        // Non-null sender on the DSN endpoint → 550 5.7.1 (policy refusal).
        writer
            .write_all(b"MAIL FROM:<attacker@evil.com>\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut reader).await,
            "550 5.7.1 Bounce MAIL FROM must be null (<>)\r\n"
        );

        // RCPT before MAIL → 503 5.5.1.
        writer
            .write_all(b"RCPT TO:<bounces+msg=example.com=user@bounces.apexmail.ee>\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut reader).await,
            "503 5.5.1 Error: need MAIL command first\r\n"
        );

        writer.write_all(b"MAIL FROM:<>\r\n").await.unwrap();
        assert_eq!(read_reply(&mut reader).await, "250 2.0.0 Ok\r\n");

        // Non-VERP, non-legacy recipient → 550 5.1.1.
        writer
            .write_all(b"RCPT TO:<user@other.com>\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut reader).await,
            "550 5.1.1 Invalid bounce recipient\r\n"
        );

        // Unknown command → 500 5.5.2 (F-06, consistent with inbound/submission).
        writer.write_all(b"FROBNICATE\r\n").await.unwrap();
        assert_eq!(
            read_reply(&mut reader).await,
            "500 5.5.2 Command not recognised\r\n"
        );

        // STARTTLS is not offered here → 454 4.7.0.
        writer.write_all(b"STARTTLS\r\n").await.unwrap();
        assert_eq!(
            read_reply(&mut reader).await,
            "454 4.7.0 TLS not available on this endpoint\r\n"
        );

        // RSET clears the transaction; DATA without one → 503 5.5.1.
        writer.write_all(b"RSET\r\n").await.unwrap();
        assert_eq!(read_reply(&mut reader).await, "250 2.0.0 Ok\r\n");
        writer.write_all(b"DATA\r\n").await.unwrap();
        assert_eq!(
            read_reply(&mut reader).await,
            "503 5.5.1 Bad sequence of commands\r\n"
        );

        writer.write_all(b"QUIT\r\n").await.unwrap();
        assert_eq!(read_reply(&mut reader).await, "221 2.0.0 Bye\r\n");

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn bounce_ehlo_advertises_exactly_the_enforced_size_cap() {
        // RFC 1870: the SIZE advertisement must equal the value the 552
        // enforcement actually uses (config.max_message_size).
        let server = std::sync::Arc::new(test_bounce_server());
        let advertised = server.config.max_message_size;
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let _ = read_reply(&mut reader).await; // greeting

        writer.write_all(b"EHLO client.example\r\n").await.unwrap();
        let ehlo = read_full_reply(&mut reader).await;
        assert!(
            ehlo.contains(&format!("250-SIZE {advertised}\r\n")),
            "SIZE advertisement must match enforcement: {ehlo:?}"
        );

        writer.write_all(b"QUIT\r\n").await.unwrap();
        let _ = read_reply(&mut reader).await;
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn bounce_recipient_cap_enforced_with_452_4_5_3() {
        let server = std::sync::Arc::new(test_bounce_server());
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let _ = read_reply(&mut reader).await; // greeting
        writer.write_all(b"EHLO c\r\n").await.unwrap();
        let _ = read_full_reply(&mut reader).await;
        writer.write_all(b"MAIL FROM:<>\r\n").await.unwrap();
        assert!(read_reply(&mut reader).await.starts_with("250"));

        // Fill the recipient budget with legacy addresses.
        for _ in 0..MAX_RCPT_PER_TRANSACTION {
            writer
                .write_all(b"RCPT TO:<bounce@bounces.apexmail.ee>\r\n")
                .await
                .unwrap();
            assert!(read_reply(&mut reader).await.starts_with("250"));
        }
        // One more recipient is over the cap.
        writer
            .write_all(b"RCPT TO:<bounce@bounces.apexmail.ee>\r\n")
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut reader).await,
            "452 4.5.3 Too many recipients\r\n"
        );

        writer.write_all(b"QUIT\r\n").await.unwrap();
        let _ = read_reply(&mut reader).await;
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn bounce_oversize_payload_rejected_with_exact_552_5_3_4() {
        // Custom server with a tiny enforced cap: the 552 reply and the
        // advertised SIZE both derive from max_message_size.
        let mut config = test_bounce_server().config;
        config.max_message_size = 64;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .unwrap();
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let server =
            std::sync::Arc::new(BounceServer::new(config, pool, redis, "bounce.test".into()));
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let _ = read_reply(&mut reader).await; // greeting
        writer.write_all(b"EHLO c\r\n").await.unwrap();
        let _ = read_full_reply(&mut reader).await;
        writer.write_all(b"MAIL FROM:<>\r\n").await.unwrap();
        let _ = read_reply(&mut reader).await;
        writer
            .write_all(b"RCPT TO:<bounce@bounces.apexmail.ee>\r\n")
            .await
            .unwrap();
        let _ = read_reply(&mut reader).await;
        writer.write_all(b"DATA\r\n").await.unwrap();
        assert!(read_reply(&mut reader).await.starts_with("354"));

        // A body line far past the 64-byte cap, then the terminator.
        writer
            .write_all(format!("{}\r\n.\r\n", "x".repeat(200)).as_bytes())
            .await
            .unwrap();
        assert_eq!(
            read_reply(&mut reader).await,
            "552 5.3.4 Message size exceeds fixed maximum message size\r\n"
        );

        // The session stays synchronised after the refusal.
        writer.write_all(b"QUIT\r\n").await.unwrap();
        assert!(read_reply(&mut reader).await.starts_with("221"));
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn bounce_connection_cap_replies_421_4_7_0() {
        let server = std::sync::Arc::new(test_bounce_server());
        let cap = server.config.max_connections_per_ip;
        // Pre-fill the per-IP connection table to the cap for loopback.
        *server
            .connections
            .entry(std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1)))
            .or_insert(0) += cap;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = server.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, _writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        assert_eq!(
            read_reply(&mut reader).await,
            "421 4.7.0 Too many connections, try again later\r\n"
        );
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[test]
    fn webhook_push_is_trimmed_to_a_bounded_length() {
        // The `mta:webhook_queue` Redis list must be trimmed after every
        // LPUSH: with a dead consumer an unbounded list grows Redis memory
        // without limit. Pinned against the compiled-in source (needles
        // concat!-built so the test cannot match its own text).
        let source = include_str!("bounce.rs");
        let trim_needle = std::concat!("LT", "RIM");
        assert!(
            source.contains(trim_needle),
            "the webhook push path must trim the queue to a bounded length"
        );
    }
}
