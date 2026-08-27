//! Feedback Loop (FBL) server – processes ARF complaint reports from ISPs.
//!
//! Verifies the source IP via reverse DNS against a known list of ISP FBL senders,
//! parses ARF feedback reports, updates sender reputation, and manages suppression.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::BytesMut;
use dashmap::DashMap;
use hmac::{Hmac, Mac};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use tokio::io::{AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};
use trust_dns_resolver::{Resolver, TokioResolver};
use uuid::Uuid;

use super::bounce::{append_data_line, connection_allowed, ConnGuard, MAX_RCPT_PER_TRANSACTION};
use super::util::{
    is_mail_from_arg, is_rcpt_to_arg, is_strict_end_of_data, line_content_bytes, line_lossy,
    log_session_summary, log_smtp_reject, metric_message, read_line_capped, split_verb,
    write_reply, LineRead, LineTerminator, MAX_COMMAND_LINE, MAX_DATA_LINE,
};
use crate::config::FeedbackConfig;

/// Per-line timeout while receiving ARF complaint DATA.
const DATA_LINE_TIMEOUT: Duration = Duration::from_secs(300);

/// Total deadline for receiving one ARF complaint payload (slow-loris
/// protection, mirrors the inbound server's 10-minute cap).
const DATA_TOTAL_TIMEOUT: Duration = Duration::from_secs(600);

// #148:Shared DNS resolver – avoids creating a new one per rDNS verification call.
// trust-dns 0.26: TokioAsyncResolver::tokio is gone; build a TokioResolver
// (builder defaults already equal ResolverOpts::default()).
static FBL_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    Resolver::builder_tokio()
        .expect("system resolver configuration is always buildable")
        .build()
        .expect("system resolver configuration is always buildable")
});

// #147:Shared HTTP client with timeout – avoids Client::new fallback without timeout
static FBL_CLIENT: LazyLock<Option<reqwest::Client>> = LazyLock::new(|| {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .ok()
});

// ── types ──────────────────────────────────────────────────────────────────────

/// Parsed ARF complaint info.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplaintInfo {
    pub feedback_type: String,
    pub user_agent: Option<String>,
    pub version: Option<String>,
    pub original_message_id: Option<String>,
    pub original_recipient: Option<String>,
    pub reporting_mta: Option<String>,
    pub source_ip: Option<String>,
    pub arrival_date: Option<String>,
    pub reported_domain: Option<String>,
    pub reported_uris: Vec<String>,
    pub authentication_results: Option<String>,
}

/// Well‑known FBL sender domains (Google, Yahoo, Microsoft, AOL, etc.).
const TRUSTED_FBL_SENDERS: &[&str] = &[
    "google.com",
    "gmail.com",
    "yahoo.com",
    "yahoo.net",
    "yahoodns.net",
    "microsoft.com",
    "outlook.com",
    "hotmail.com",
    "aol.com",
    "comcast.net",
    "cox.net",
    "att.net",
    "verizon.net",
    "mail.ru",
    "yandex.net",
    "returnpath.net",
    "validity.com",
];

/// FBL processing server.
pub struct FeedbackLoopServer {
    config: FeedbackConfig,
    pool: PgPool,
    redis: deadpool_redis::Pool,
    hostname: String,
    trusted_domains: HashSet<String>,
    /// #149:Bounded rDNS cache with 10-minute TTL (replaces unbounded DashMap).
    rdns_cache: Cache<IpAddr, bool>,
    /// Active connections per IP — enforces `max_connections_per_ip`.
    connections: Arc<DashMap<IpAddr, u32>>,
    shutdown: Arc<Notify>,
}

impl FeedbackLoopServer {
    pub fn new(
        config: FeedbackConfig,
        pool: PgPool,
        redis: deadpool_redis::Pool,
        hostname: String,
        extra_trusted: &[String],
    ) -> Self {
        let mut trusted: HashSet<String> =
            TRUSTED_FBL_SENDERS.iter().map(|s| s.to_string()).collect();
        for d in extra_trusted {
            trusted.insert(d.clone());
        }
        Self {
            config,
            pool,
            redis,
            hostname,
            trusted_domains: trusted,
            // #149:Bounded cache with TTL prevents unbounded memory growth
            rdns_cache: Cache::builder()
                .max_capacity(10_000)
                .time_to_live(Duration::from_secs(600))
                .build(),
            connections: Arc::new(DashMap::new()),
            shutdown: Arc::new(Notify::new()),
        }
    }

    /// Start listening.
    pub async fn start(self: Arc<Self>) -> anyhow::Result<()> {
        let addr = format!("{}:{}", self.config.host, self.config.port);
        let listener = TcpListener::bind(&addr).await?;
        info!(addr = %addr, "FBL server listening");

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
        let ip = peer.ip();
        let session_id = Uuid::new_v4().to_string();
        let started = std::time::Instant::now();

        // Verify source via rDNS
        if !self.verify_fbl_source(ip).await {
            let mut s = BufStream::new(socket);
            log_smtp_reject("fbl", ip, &session_id, "554 5.7.1 Unverified FBL source");
            let _ = write_reply(
                &mut s,
                "fbl",
                ip,
                &session_id,
                "554 5.7.1 Unverified FBL source\r\n",
            )
            .await;
            log_session_summary(
                "fbl",
                ip,
                &session_id,
                false,
                false,
                0,
                started.elapsed().as_millis(),
                "unverified_source",
            );
            return;
        }

        // Enforce the per-IP connection cap.
        let active = self.connections.get(&ip).map(|e| *e).unwrap_or(0);
        if !connection_allowed(active, self.config.max_connections_per_ip) {
            let mut s = BufStream::new(socket);
            log_smtp_reject(
                "fbl",
                ip,
                &session_id,
                "421 4.7.0 Too many connections, try again later",
            );
            let _ = write_reply(
                &mut s,
                "fbl",
                ip,
                &session_id,
                "421 4.7.0 Too many connections, try again later\r\n",
            )
            .await;
            log_session_summary(
                "fbl",
                ip,
                &session_id,
                false,
                false,
                0,
                started.elapsed().as_millis(),
                "conn_limit",
            );
            return;
        }
        *self.connections.entry(ip).or_insert(0) += 1;
        let _conn_guard = ConnGuard {
            conns: self.connections.clone(),
            ip,
        };

        let mut stream = BufStream::new(socket);
        let greeting = format!("220 {} FBL Processor\r\n", self.hostname);
        if write_line(&mut stream, &greeting).await.is_err() {
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
                        "fbl",
                        ip,
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
                        "fbl",
                        ip,
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
                        "fbl",
                        ip,
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
                        "fbl",
                        ip,
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
                // SIZE advertisement equals the enforced cap (RFC 1870): the
                // 552 enforcement below uses exactly max_arf_size.
                let caps = format!(
                    "250-{}\r\n250-SIZE {}\r\n250 8BITMIME\r\n",
                    self.hostname, self.config.max_arf_size
                );
                let _ = write_line(&mut stream, &caps).await;
            } else if verb == "MAIL" && is_mail_from_arg(arg) {
                // ARF reports from ISP FBL sources are regular mail with a
                // real envelope sender — the rDNS/FCrDNS verification is the
                // source of trust here, not a null sender. We only enforce
                // the MAIL → RCPT ordering.
                mail_from_seen = true;
                rcpt_to.clear();
                let _ = write_line(&mut stream, "250 2.0.0 Ok\r\n").await;
            } else if verb == "MAIL" {
                // F-06: "MAIL FROMX:..." is a syntax error, not a MAIL.
                let _ = write_reply(
                    &mut stream,
                    "fbl",
                    ip,
                    &session_id,
                    "501 5.5.4 Syntax: MAIL FROM:<address>\r\n",
                )
                .await;
            } else if verb == "RCPT" && is_rcpt_to_arg(arg) {
                let addr = extract_addr(&line);
                if !mail_from_seen {
                    let _ = write_reply(
                        &mut stream,
                        "fbl",
                        ip,
                        &session_id,
                        "503 5.5.1 Error: need MAIL command first\r\n",
                    )
                    .await;
                    continue;
                }
                if rcpt_to.len() >= MAX_RCPT_PER_TRANSACTION {
                    let _ = write_reply(
                        &mut stream,
                        "fbl",
                        ip,
                        &session_id,
                        "452 4.5.3 Too many recipients\r\n",
                    )
                    .await;
                    continue;
                }
                if addr.len() > super::submission::MAX_ENVELOPE_ADDR_LEN {
                    // RFC 5321 §4.5.3.1.1: bound the forward-path length so
                    // an over-long command line cannot be parked in the
                    // envelope (the per-line cap alone still allows ~4 KB).
                    let _ = write_reply(
                        &mut stream,
                        "fbl",
                        ip,
                        &session_id,
                        "501 5.1.3 Bad recipient address syntax\r\n",
                    )
                    .await;
                    continue;
                }
                // Accept abuse@, complaints@, fbl@, feedback@, postmaster@
                let local = addr.split('@').next().unwrap_or("").to_lowercase();
                let accepted = local == "abuse"
                    || local == "complaints"
                    || local == "fbl"
                    || local == "feedback"
                    || local == "postmaster";
                if accepted {
                    rcpt_to.push(addr);
                    let _ = write_line(&mut stream, "250 2.0.0 Ok\r\n").await;
                } else {
                    let _ = write_reply(
                        &mut stream,
                        "fbl",
                        ip,
                        &session_id,
                        "550 5.1.1 Invalid FBL recipient\r\n",
                    )
                    .await;
                }
            } else if verb == "DATA" {
                if !mail_from_seen || rcpt_to.is_empty() {
                    let _ = write_reply(
                        &mut stream,
                        "fbl",
                        ip,
                        &session_id,
                        "503 5.5.1 Bad sequence of commands\r\n",
                    )
                    .await;
                    continue;
                }
                if msgs_this_conn >= self.config.max_messages_per_connection {
                    let _ = write_reply(
                        &mut stream,
                        "fbl",
                        ip,
                        &session_id,
                        "452 4.5.3 Too many messages from this connection\r\n",
                    )
                    .await;
                    continue;
                }
                let _ = write_line(&mut stream, "354 Go ahead\r\n").await;
                let mut message = BytesMut::new();
                let mut too_large = false;
                // A report is only complete when the client sent the
                // <CRLF>.<CRLF> terminator; EOF/read-error mid-DATA yields a
                // truncated payload that must never be processed.
                let mut terminated = false;
                let mut timed_out = false;
                let mut overflowed = false;
                // E-9:total DATA deadline so a slow client cannot drip-feed
                // lines forever.
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
                            // M57: enforce max_arf_size *while* reading so the
                            // payload is never fully buffered before rejection.
                            if !too_large
                                && !append_data_line(
                                    &mut message,
                                    content,
                                    self.config.max_arf_size,
                                )
                            {
                                too_large = true;
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
                        "fbl",
                        ip,
                        &session_id,
                        "421 4.4.2 Data timeout exceeded\r\n",
                    )
                    .await;
                } else if overflowed {
                    // Unresynchronisable stream: reply and close.
                    close_reason = "overflow";
                    let _ = write_reply(
                        &mut stream,
                        "fbl",
                        ip,
                        &session_id,
                        "500 5.5.2 Line too long\r\n",
                    )
                    .await;
                    break;
                } else if too_large {
                    let _ = write_reply(
                        &mut stream,
                        "fbl",
                        ip,
                        &session_id,
                        "552 5.3.4 Message size exceeds fixed maximum message size\r\n",
                    )
                    .await;
                } else if terminated {
                    match self.process_complaint(ip, &message).await {
                        Ok(id) => {
                            let _ =
                                write_line(&mut stream, &format!("250 2.0.0 Ok id={id}\r\n")).await;
                        }
                        Err(e) => {
                            warn!(error = %e, "Complaint processing failed");
                            let _ = write_reply(
                                &mut stream,
                                "fbl",
                                ip,
                                &session_id,
                                "451 4.3.0 Temporary failure\r\n",
                            )
                            .await;
                        }
                    }
                }
                msgs_this_conn += 1;
                rcpt_to.clear();
            } else if verb == "QUIT" {
                let _ = write_line(&mut stream, "221 2.0.0 Bye\r\n").await;
                close_reason = "quit";
                break;
            } else if verb == "RSET" || verb == "NOOP" {
                if verb == "RSET" {
                    rcpt_to.clear();
                    mail_from_seen = false;
                }
                let _ = write_line(&mut stream, "250 2.0.0 Ok\r\n").await;
            } else if verb == "VRFY" || verb == "EXPN" {
                // Avoid leaking recipient validity.
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
                    "fbl",
                    ip,
                    &session_id,
                    "454 4.7.0 TLS not available on this endpoint\r\n",
                )
                .await;
            } else {
                let _ = write_reply(
                    &mut stream,
                    "fbl",
                    ip,
                    &session_id,
                    "500 5.5.2 Command not recognised\r\n",
                )
                .await;
            }
        }

        log_session_summary(
            "fbl",
            ip,
            &session_id,
            false,
            false,
            msgs_this_conn,
            started.elapsed().as_millis(),
            close_reason,
        );
    }

    // ── rDNS verification ──────────────────────────────────────────────────────

    async fn verify_fbl_source(&self, ip: IpAddr) -> bool {
        // Check cache
        if let Some(cached) = self.rdns_cache.get(&ip) {
            return cached;
        }

        // #148:Use shared resolver instead of creating a new one per call
        let resolver = &*FBL_RESOLVER;

        // Reverse DNS lookup
        let result = match resolver.reverse_lookup(ip).await {
            Ok(lookup) => {
                let mut matched_hostname: Option<String> = None;
                // trust-dns 0.26 removed typed lookup iteration; extract the
                // PTR names from the raw answer records.
                for hostname_str in
                    lookup
                        .answers()
                        .iter()
                        .filter_map(|record| match &record.data {
                            trust_dns_resolver::proto::rr::RData::PTR(ptr) => {
                                Some(ptr.0.to_string())
                            }
                            _ => None,
                        })
                {
                    let hostname = hostname_str.trim_end_matches('.').to_lowercase();
                    if self
                        .trusted_domains
                        .iter()
                        .any(|domain| hostname_matches_trusted(&hostname, domain))
                    {
                        matched_hostname = Some(hostname);
                        break;
                    }
                }

                // #146:Forward-Confirmed reverse DNS (FCrDNS) – verify the PTR
                // hostname resolves back to the original IP to prevent PTR spoofing
                if let Some(ref hostname) = matched_hostname {
                    match resolver.lookup_ip(hostname.as_str()).await {
                        Ok(forward) => {
                            let confirmed = forward.iter().any(|addr| addr == ip);
                            if !confirmed {
                                debug!(ip = %ip, hostname = %hostname, "FCrDNS failed: forward lookup doesn't match IP");
                            }
                            confirmed
                        }
                        Err(e) => {
                            debug!(ip = %ip, hostname = %hostname, error = %e, "FCrDNS forward lookup failed");
                            false
                        }
                    }
                } else {
                    debug!(ip = %ip, "rDNS lookup didn't match trusted FBL senders");
                    false
                }
            }
            Err(e) => {
                debug!(ip = %ip, error = %e, "rDNS lookup failed");
                false
            }
        };

        self.rdns_cache.insert(ip, result);
        result
    }

    // ── complaint processing ───────────────────────────────────────────────────

    async fn process_complaint(&self, source_ip: IpAddr, raw: &[u8]) -> anyhow::Result<String> {
        // complaint_events.id is a UUID column (migration 093) — bind the
        // Uuid itself, not its String form.
        let complaint_id = Uuid::new_v4();

        // O-1.5:Reject oversized ARF payloads (also enforced while reading).
        if raw.len() > self.config.max_arf_size {
            warn!(
                size = raw.len(),
                max = self.config.max_arf_size,
                "Complaint payload exceeds max_arf_size, rejecting"
            );
            return Err(anyhow::anyhow!(
                "Complaint payload too large: {} bytes exceeds limit of {} bytes",
                raw.len(),
                self.config.max_arf_size,
            ));
        }

        let message = String::from_utf8_lossy(raw);

        // Parse ARF report
        let complaint = parse_arf_report(&message);

        // Match to original message
        let original_id = complaint.original_message_id.clone();

        // complaint_events.arrival_date is TIMESTAMPTZ (migration 093) — the
        // raw ARF header string (RFC 5322 date) must be parsed before binding.
        // Unparseable dates are stored as NULL rather than failing the insert.
        let arrival_date: Option<chrono::DateTime<chrono::Utc>> = complaint
            .arrival_date
            .as_deref()
            .and_then(|s| {
                chrono::DateTime::parse_from_rfc2822(s)
                    .or_else(|_| chrono::DateTime::parse_from_rfc3339(s))
                    .ok()
            })
            .map(|dt| dt.with_timezone(&chrono::Utc));

        // Record complaint event. The unique index on
        // (source_ip, original_message_id, original_recipient) makes retries
        // and replays idempotent: only a freshly inserted row may run side
        // effects (M55).
        let inserted = sqlx::query(
            r#"INSERT INTO complaint_events (
                id, original_message_id, original_recipient,
                feedback_type, source_ip, reporting_mta,
                user_agent, arrival_date, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())
            ON CONFLICT (source_ip, original_message_id, original_recipient)
            WHERE original_message_id IS NOT NULL AND original_recipient IS NOT NULL
            DO NOTHING"#,
        )
        .bind(complaint_id)
        .bind(&original_id)
        .bind(&complaint.original_recipient)
        .bind(&complaint.feedback_type)
        .bind(source_ip.to_string())
        .bind(&complaint.reporting_mta)
        .bind(&complaint.user_agent)
        .bind(arrival_date)
        .execute(&self.pool)
        .await?
        .rows_affected()
            > 0;

        if !inserted {
            debug!(
                msg_id = ?original_id,
                dedup_key = ?complaint_dedup_key(&complaint, source_ip),
                "Duplicate complaint event, skipping side effects"
            );
            return Ok(complaint_id.to_string());
        }

        // Only act on complaints referencing a message this system sent:
        // resolve the tenant before touching suppression. The FBL source is
        // rDNS-verified, so reputation counting and webhooks still run for
        // unknown messages (e.g. pruned from email_queue) — only the
        // suppression is gated on verification.
        let suppression_target: Option<(String, String)> = match original_id.as_deref() {
            Some(mid) => match self.lookup_sent_message(mid).await? {
                None => {
                    warn!(msg_id = %mid, "Complaint references unknown message — skipping suppression");
                    None
                }
                Some((tenant_id, queued_recipient)) => match &complaint.original_recipient {
                    Some(reported) if *reported == queued_recipient => {
                        Some((tenant_id, reported.clone()))
                    }
                    Some(reported) => {
                        warn!(
                            reported_recipient = %reported,
                            queued_recipient = %queued_recipient,
                            msg_id = %mid,
                            "Complaint recipient does not match queued recipient — dropping forged complaint"
                        );
                        None
                    }
                    None => Some((tenant_id, queued_recipient)),
                },
            },
            None => {
                warn!("Complaint carries no original message id — skipping suppression");
                None
            }
        };

        if let Some((tenant_id, recipient)) = suppression_target {
            if let Err(e) = self
                .insert_suppression(&tenant_id, &recipient, "complaint")
                .await
            {
                warn!(error = %e, "Suppression write failed; continuing complaint processing");
            }
        }

        // Update sender reputation (only for freshly inserted complaints)
        self.update_sender_reputation(&complaint).await?;

        // Queue webhook
        let payload = serde_json::json!({
            "event": "complaint",
            "complaint_id": complaint_id,
            "original_message_id": original_id,
            "feedback_type": complaint.feedback_type,
            "recipient": complaint.original_recipient,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        if let Ok(mut conn) = self.redis.get().await {
            redis::cmd("LPUSH")
                .arg("mta:webhook_queue")
                .arg(payload.to_string())
                .query_async::<i64>(&mut *conn) // LPUSH returns list length
                .await
                .ok();
        }

        info!(
            complaint_id = %complaint_id,
            msg_id = ?original_id,
            feedback_type = %complaint.feedback_type,
            "Complaint processed"
        );
        metric_message("fbl", "accepted");

        Ok(complaint_id.to_string())
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

    /// Insert into the canonical `suppressions` table (C4). FBL-triggered
    /// rows are always complaints and never removable by the API.
    async fn insert_suppression(
        &self,
        tenant_id: &str,
        email: &str,
        reason: &str,
    ) -> anyhow::Result<()> {
        sqlx::query(
            r#"INSERT INTO suppressions
               (id, tenant_id, email, reason, subtype, source, created_at)
               VALUES ($1, $2, $3, $4, 'fbl', 'fbl', NOW())
               ON CONFLICT (tenant_id, email) DO NOTHING"#,
        )
        .bind(super::bounce::suppression_row_id())
        .bind(tenant_id)
        .bind(email)
        .bind(reason)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn update_sender_reputation(&self, complaint: &ComplaintInfo) -> anyhow::Result<()> {
        // Extract domain from original message or reported domain
        let domain = complaint.reported_domain.as_deref().unwrap_or("unknown");

        let today = chrono::Utc::now().format("%Y-%m-%d").to_string();

        // Increment complaint count in Redis with 7-day TTL
        if let Ok(mut conn) = self.redis.get().await {
            let key = format!("mta:reputation:{}:{}", domain, today);
            redis::cmd("HINCRBY")
                .arg(&key)
                .arg("complaints")
                .arg(1i64)
                .query_async::<i64>(&mut *conn)
                .await
                .ok();
            redis::cmd("EXPIRE")
                .arg(&key)
                .arg(7 * 86400i64)
                .query_async::<bool>(&mut *conn)
                .await
                .ok();

            // Check complaint rate (if we have sent count)
            let sent: i64 = redis::cmd("HGET")
                .arg(&key)
                .arg("sent")
                .query_async::<i64>(&mut *conn)
                .await
                .unwrap_or(0);
            let complaints: i64 = redis::cmd("HGET")
                .arg(&key)
                .arg("complaints")
                .query_async::<i64>(&mut *conn)
                .await
                .unwrap_or(0);

            if sent > 100 {
                let rate = complaints as f64 / sent as f64;
                if rate > 0.001 {
                    // 0.1% threshold
                    warn!(
                        domain = domain,
                        rate = rate,
                        sent = sent,
                        complaints = complaints,
                        "High complaint rate detected"
                    );
                    // Trigger alert webhook
                    self.trigger_alert_webhook(domain, rate, sent, complaints)
                        .await;
                }
            }
        }

        // Record in DB for long-term tracking
        sqlx::query(
            r#"INSERT INTO sender_reputation (domain, date, complaints, updated_at)
               VALUES ($1, CURRENT_DATE, 1, NOW())
               ON CONFLICT (domain, date)
               DO UPDATE SET complaints = sender_reputation.complaints + 1, updated_at = NOW()"#,
        )
        .bind(domain)
        .execute(&self.pool)
        .await?;

        Ok(())
    }

    /// Trigger alert webhooks for high complaint rate
    async fn trigger_alert_webhook(&self, domain: &str, rate: f64, sent: i64, complaints: i64) {
        // Query all active webhooks for this type of alert
        let webhooks: Vec<(Uuid, String, String)> = match sqlx::query_as(
            "SELECT id, url, secret FROM alert_webhooks
             WHERE enabled = true AND alert_types @> $1::jsonb",
        )
        .bind(serde_json::json!(["complaint_rate"]))
        .fetch_all(&self.pool)
        .await
        {
            Ok(rows) => rows,
            Err(e) => {
                error!(error = %e, "Failed to query alert webhooks");
                return;
            }
        };

        if webhooks.is_empty() {
            return;
        }

        let payload = serde_json::json!({
            "alert_type": "complaint_rate",
            "severity": if rate > 0.005 { "critical" } else { "warning" },
            "domain": domain,
            "complaint_rate": rate,
            "sent_count": sent,
            "complaint_count": complaints,
            "threshold": 0.001,
            "timestamp": chrono::Utc::now().to_rfc3339(),
        });

        // #147:Use shared client with guaranteed timeout
        let Some(client) = FBL_CLIENT.as_ref() else {
            error!("FBL HTTP client unavailable; skipping complaint rate webhooks");
            return;
        };

        for (webhook_id, url, secret) in webhooks {
            // Compute HMAC signature
            type HmacSha256 = Hmac<Sha256>;
            let payload_str = serde_json::to_string(&payload).unwrap_or_default();
            let signature = if !secret.is_empty() {
                match HmacSha256::new_from_slice(secret.as_bytes()) {
                    Ok(mut mac) => {
                        mac.update(payload_str.as_bytes());
                        let result = mac.finalize();
                        hex::encode(result.into_bytes())
                    }
                    Err(e) => {
                        error!(error = %e, webhook_id = %webhook_id, "Invalid webhook secret for HMAC; sending unsigned alert");
                        String::new()
                    }
                }
            } else {
                String::new()
            };

            let response = client
                .post(&url)
                .header("Content-Type", "application/json")
                .header("X-ApexMail-Signature", &signature)
                .header("X-ApexMail-Event", "complaint_rate_alert")
                .body(payload_str.clone())
                .send()
                .await;

            // Record delivery attempt
            let (success, status_code, error_msg) = match response {
                Ok(resp) => {
                    let status = resp.status().as_u16() as i32;
                    let success = resp.status().is_success();
                    (success, Some(status), None)
                }
                Err(e) => (false, None, Some(e.to_string())),
            };

            if let Err(e) = sqlx::query(
                "INSERT INTO alert_webhook_deliveries (webhook_id, alert_type, payload, success, status_code, error_message, delivered_at)
                 VALUES ($1, 'complaint_rate', $2, $3, $4, $5, NOW())"
            )
                // alert_webhook_deliveries.webhook_id is TEXT (migration 093);
                // bind the UUID's string form, not the Uuid itself.
                .bind(webhook_id.to_string())
                .bind(&payload)
                .bind(success)
                .bind(status_code)
                .bind(error_msg)
                .execute(&self.pool)
                .await
            {
                warn!(webhook_id = %webhook_id, error = %e, "Failed to record webhook delivery");
            }

            if success {
                debug!(webhook_id = %webhook_id, url = %url, "Alert webhook delivered");
            } else {
                warn!(webhook_id = %webhook_id, url = %url, "Alert webhook delivery failed");
            }
        }
    }
}

// ── ARF parsing ────────────────────────────────────────────────────────────────

/// Strict trusted-domain match for FBL sources (H16).
///
/// A PTR hostname is only trusted when it equals the domain or lives in a
/// real subdomain of it. A bare suffix match (`evil-google.com` ending in
/// `google.com`) is rejected — an attacker can register such names and
/// control their own PTR + A records.
fn hostname_matches_trusted(hostname: &str, domain: &str) -> bool {
    hostname == domain || hostname.ends_with(&format!(".{domain}"))
}

/// Natural key used to deduplicate complaint reports (M55).
///
/// Only reports carrying both an original message id and an original
/// recipient can be deduplicated; everything else is recorded but never
/// counted toward reputation or suppression.
fn complaint_dedup_key(info: &ComplaintInfo, source_ip: IpAddr) -> Option<String> {
    let mid = info.original_message_id.as_deref()?;
    let recipient = info.original_recipient.as_deref()?;
    Some(format!("{}|{}|{}", source_ip, mid, recipient))
}

/// Parse an ARF (Abuse Reporting Format) feedback report.
pub fn parse_arf_report(message: &str) -> ComplaintInfo {
    let mut info = ComplaintInfo {
        feedback_type: "abuse".into(),
        user_agent: None,
        version: None,
        original_message_id: None,
        original_recipient: None,
        reporting_mta: None,
        source_ip: None,
        arrival_date: None,
        reported_domain: None,
        reported_uris: Vec::new(),
        authentication_results: None,
    };

    for line in message.lines() {
        let trimmed = line.trim();
        let lower = trimmed.to_lowercase();

        if lower.starts_with("feedback-type:") {
            info.feedback_type = extract_value(trimmed);
        } else if lower.starts_with("user-agent:") {
            info.user_agent = Some(extract_value(trimmed));
        } else if lower.starts_with("version:") {
            info.version = Some(extract_value(trimmed));
        } else if lower.starts_with("original-rcpt-to:") {
            info.original_recipient = Some(extract_value(trimmed));
        } else if lower.starts_with("original-mail-from:") {
            let from = extract_value(trimmed);
            if info.reported_domain.is_none() {
                info.reported_domain = from.rsplit_once('@').map(|(_, d)| d.to_string());
            }
        } else if lower.starts_with("arrival-date:") {
            info.arrival_date = Some(extract_value(trimmed));
        } else if lower.starts_with("reporting-mta:") {
            info.reporting_mta = Some(extract_value(trimmed));
        } else if lower.starts_with("source-ip:") {
            info.source_ip = Some(extract_value(trimmed));
        } else if lower.starts_with("reported-uri:") {
            info.reported_uris.push(extract_value(trimmed));
        } else if lower.starts_with("authentication-results:") {
            info.authentication_results = Some(extract_value(trimmed));
        } else if lower.starts_with("original-message-id:") && info.original_message_id.is_none() {
            let mid = extract_value(trimmed);
            info.original_message_id = Some(mid.trim_matches(|c| c == '<' || c == '>').to_string());
        }
    }

    info
}

fn extract_value(line: &str) -> String {
    line.split_once(':')
        .map(|(_, v)| v.trim().to_string())
        .unwrap_or_default()
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
    fn test_parse_arf_report_basic() {
        let report = "\
Feedback-Type: abuse\r\n\
User-Agent: FBL/1.0\r\n\
Version: 1\r\n\
Original-Rcpt-To: victim@example.com\r\n\
Original-Mail-From: spammer@bad.com\r\n\
Arrival-Date: Thu, 01 Jan 2025 00:00:00 +0000\r\n\
Reporting-MTA: dns; mx.example.com\r\n\
Source-IP: 192.168.1.1\r\n\
Original-Message-ID: <msg123@bad.com>\r\n";

        let info = parse_arf_report(report);
        assert_eq!(info.feedback_type, "abuse");
        assert_eq!(info.user_agent, Some("FBL/1.0".into()));
        assert_eq!(info.original_recipient, Some("victim@example.com".into()));
        assert_eq!(info.reported_domain, Some("bad.com".into()));
        assert_eq!(info.original_message_id, Some("msg123@bad.com".into()));
        assert_eq!(info.source_ip, Some("192.168.1.1".into()));
    }

    #[test]
    fn test_parse_arf_report_minimal() {
        let report = "Feedback-Type: fraud\r\n";
        let info = parse_arf_report(report);
        assert_eq!(info.feedback_type, "fraud");
        assert!(info.original_recipient.is_none());
    }

    #[test]
    fn test_parse_arf_report_with_uris() {
        let report = "\
Feedback-Type: abuse\r\n\
Reported-URI: http://bad.com/phish\r\n\
Reported-URI: http://bad.com/malware\r\n";

        let info = parse_arf_report(report);
        assert_eq!(info.reported_uris.len(), 2);
        assert_eq!(info.reported_uris[0], "http://bad.com/phish");
    }

    #[test]
    fn test_parse_arf_report_ignores_generic_message_id_linkage() {
        let report = "\
Feedback-Type: abuse\r\n\
Message-ID: <bounce-report@example.net>\r\n";

        let info = parse_arf_report(report);
        assert!(info.original_message_id.is_none());
    }

    #[test]
    fn test_parse_arf_report_keeps_explicit_original_message_id() {
        let report = "\
Feedback-Type: abuse\r\n\
Message-ID: <bounce-report@example.net>\r\n\
Original-Message-ID: <original@example.com>\r\n";

        let info = parse_arf_report(report);
        assert_eq!(
            info.original_message_id,
            Some("original@example.com".into())
        );
    }

    #[test]
    fn test_trusted_fbl_senders() {
        assert!(TRUSTED_FBL_SENDERS.contains(&"google.com"));
        assert!(TRUSTED_FBL_SENDERS.contains(&"microsoft.com"));
        assert!(TRUSTED_FBL_SENDERS.contains(&"yahoo.com"));
    }

    #[test]
    fn test_hostname_matches_trusted_domain_exact() {
        assert!(hostname_matches_trusted("google.com", "google.com"));
    }

    #[test]
    fn test_hostname_matches_trusted_subdomain() {
        assert!(hostname_matches_trusted("mx.google.com", "google.com"));
        assert!(hostname_matches_trusted(
            "outbound.mail.microsoft.com",
            "microsoft.com"
        ));
    }

    #[test]
    fn test_hostname_matches_trusted_rejects_suffix_spoof() {
        assert!(!hostname_matches_trusted("evil-google.com", "google.com"));
        assert!(!hostname_matches_trusted("notgoogle.com", "google.com"));
        assert!(!hostname_matches_trusted(
            "google.com.evil.com",
            "google.com"
        ));
        assert!(!hostname_matches_trusted("google.com.", "google.com"));
        assert!(!hostname_matches_trusted("", "google.com"));
    }

    #[test]
    fn test_complaint_dedup_key() {
        let info = ComplaintInfo {
            feedback_type: "abuse".into(),
            user_agent: None,
            version: None,
            original_message_id: Some("msg123@example.com".into()),
            original_recipient: Some("victim@example.com".into()),
            reporting_mta: None,
            source_ip: Some("192.168.1.1".into()),
            arrival_date: None,
            reported_domain: None,
            reported_uris: vec![],
            authentication_results: None,
        };
        let key = complaint_dedup_key(&info, std::net::IpAddr::from([192, 168, 1, 1]));
        assert_eq!(
            key.as_deref(),
            Some("192.168.1.1|msg123@example.com|victim@example.com")
        );
    }

    #[test]
    fn test_complaint_dedup_key_requires_identity() {
        let info = ComplaintInfo {
            feedback_type: "abuse".into(),
            user_agent: None,
            version: None,
            original_message_id: None,
            original_recipient: Some("victim@example.com".into()),
            reporting_mta: None,
            source_ip: None,
            arrival_date: None,
            reported_domain: None,
            reported_uris: vec![],
            authentication_results: None,
        };
        // Without a verifiable original message id we cannot dedupe —
        // the event is recorded but never counted toward reputation.
        assert!(complaint_dedup_key(&info, std::net::IpAddr::from([192, 168, 1, 1])).is_none());
    }

    // ── full-session tests (rDNS bypassed via a cached verdict) ────────────

    use tokio::io::{AsyncBufReadExt, AsyncWriteExt};
    use tokio::net::{TcpListener, TcpStream};

    const LOOPBACK: std::net::IpAddr = std::net::IpAddr::V4(std::net::Ipv4Addr::new(127, 0, 0, 1));

    /// Test server whose rDNS verdict for loopback is seeded in the cache, so
    /// full sessions run deterministically without touching real DNS.
    fn test_fbl_server(rdns_ok: bool) -> std::sync::Arc<FeedbackLoopServer> {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .expect("lazy pool construction");
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .expect("lazy redis pool construction");
        let config = FeedbackConfig {
            enabled: true,
            host: "127.0.0.1".into(),
            port: 0,
            hostname: "fbl.test".into(),
            max_arf_size: 1024 * 1024,
            max_connections_per_ip: 10,
            max_messages_per_connection: 100,
        };
        let server = std::sync::Arc::new(FeedbackLoopServer::new(
            config,
            pool,
            redis,
            "fbl.test".into(),
            &[],
        ));
        server.rdns_cache.insert(LOOPBACK, rdns_ok);
        server
    }

    async fn fbl_read_reply(
        reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> String {
        let mut line = String::new();
        tokio::time::timeout(Duration::from_secs(5), reader.read_line(&mut line))
            .await
            .expect("reply must arrive within 5s")
            .expect("read must not fail");
        line
    }

    /// Read a complete (possibly multi-line) SMTP reply.
    async fn fbl_read_full_reply(
        reader: &mut tokio::io::BufReader<tokio::net::tcp::OwnedReadHalf>,
    ) -> String {
        let mut full = String::new();
        loop {
            let line = fbl_read_reply(reader).await;
            let more = line.len() >= 4 && line.as_bytes()[3] == b'-';
            full.push_str(&line);
            if !more {
                return full;
            }
        }
    }

    #[tokio::test]
    async fn fbl_unverified_source_replies_554_5_7_1() {
        // Cached rDNS verdict = false: the greeting rejection is immediate
        // and deterministic (no live DNS in unit tests).
        let server = test_fbl_server(false);
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
            fbl_read_reply(&mut reader).await,
            "554 5.7.1 Unverified FBL source\r\n"
        );
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn fbl_rejection_suite_uses_exact_enhanced_status_codes() {
        let server = test_fbl_server(true);
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

        let _ = fbl_read_reply(&mut reader).await; // greeting

        // RCPT before MAIL → 503 5.5.1.
        writer
            .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
            .await
            .unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "503 5.5.1 Error: need MAIL command first\r\n"
        );

        // ARF senders are real senders: MAIL FROM with an address is fine.
        writer
            .write_all(b"MAIL FROM:<fbl@google.com>\r\n")
            .await
            .unwrap();
        assert_eq!(fbl_read_reply(&mut reader).await, "250 2.0.0 Ok\r\n");

        // Not an FBL role mailbox → 550 5.1.1.
        writer
            .write_all(b"RCPT TO:<nobody@fbl.test>\r\n")
            .await
            .unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "550 5.1.1 Invalid FBL recipient\r\n"
        );

        // Over-long forward-path (RFC 5321 §4.5.3.1.1) → 501 5.1.3.
        let huge = format!("abuse@{}.com", "d".repeat(400));
        writer
            .write_all(format!("RCPT TO:<{huge}>\r\n").as_bytes())
            .await
            .unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "501 5.1.3 Bad recipient address syntax\r\n"
        );

        // Unknown command → 500 5.5.2 (F-06, consistent with inbound/submission).
        writer.write_all(b"FROBNICATE\r\n").await.unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "500 5.5.2 Command not recognised\r\n"
        );

        // STARTTLS is not offered here → 454 4.7.0.
        writer.write_all(b"STARTTLS\r\n").await.unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "454 4.7.0 TLS not available on this endpoint\r\n"
        );

        // RSET clears the transaction; DATA without one → 503 5.5.1.
        writer.write_all(b"RSET\r\n").await.unwrap();
        assert_eq!(fbl_read_reply(&mut reader).await, "250 2.0.0 Ok\r\n");
        writer.write_all(b"DATA\r\n").await.unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "503 5.5.1 Bad sequence of commands\r\n"
        );

        writer.write_all(b"QUIT\r\n").await.unwrap();
        assert_eq!(fbl_read_reply(&mut reader).await, "221 2.0.0 Bye\r\n");

        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn fbl_ehlo_advertises_exactly_the_enforced_size_cap() {
        // RFC 1870: the SIZE advertisement must equal the value the 552
        // enforcement actually uses (config.max_arf_size).
        let server = test_fbl_server(true);
        let advertised = server.config.max_arf_size;
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
        let _ = fbl_read_reply(&mut reader).await; // greeting

        writer.write_all(b"EHLO client.example\r\n").await.unwrap();
        let ehlo = fbl_read_full_reply(&mut reader).await;
        assert!(
            ehlo.contains(&format!("250-SIZE {advertised}\r\n")),
            "SIZE advertisement must match enforcement: {ehlo:?}"
        );

        writer.write_all(b"QUIT\r\n").await.unwrap();
        let _ = fbl_read_reply(&mut reader).await;
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn fbl_recipient_cap_enforced_with_452_4_5_3() {
        let server = test_fbl_server(true);
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
        let _ = fbl_read_reply(&mut reader).await; // greeting
        writer.write_all(b"EHLO c\r\n").await.unwrap();
        let _ = fbl_read_full_reply(&mut reader).await;
        writer
            .write_all(b"MAIL FROM:<fbl@google.com>\r\n")
            .await
            .unwrap();
        assert!(fbl_read_reply(&mut reader).await.starts_with("250"));

        for _ in 0..MAX_RCPT_PER_TRANSACTION {
            writer
                .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
                .await
                .unwrap();
            assert!(fbl_read_reply(&mut reader).await.starts_with("250"));
        }
        writer
            .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
            .await
            .unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "452 4.5.3 Too many recipients\r\n"
        );

        writer.write_all(b"QUIT\r\n").await.unwrap();
        let _ = fbl_read_reply(&mut reader).await;
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }

    #[tokio::test]
    async fn fbl_oversize_payload_rejected_with_exact_552_5_3_4() {
        // Custom server with a tiny enforced cap: the 552 reply and the
        // advertised SIZE both derive from max_arf_size.
        let server = test_fbl_server(true);
        let mut config = server.config.clone();
        config.max_arf_size = 64;
        let pool = sqlx::postgres::PgPoolOptions::new()
            .acquire_timeout(Duration::from_secs(1))
            .connect_lazy("postgres://127.0.0.1:1/mta_test")
            .unwrap();
        let redis = deadpool_redis::Config::from_url("redis://127.0.0.1:1")
            .create_pool(Some(deadpool_redis::Runtime::Tokio1))
            .unwrap();
        let small = std::sync::Arc::new(FeedbackLoopServer::new(
            config,
            pool,
            redis,
            "fbl.test".into(),
            &[],
        ));
        small.rdns_cache.insert(LOOPBACK, true);

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let srv = small.clone();
        let task = tokio::spawn(async move {
            let (socket, peer) = listener.accept().await.unwrap();
            srv.handle_session(socket, peer).await;
        });

        let tcp = TcpStream::connect(addr).await.unwrap();
        let (reader, mut writer) = tcp.into_split();
        let mut reader = tokio::io::BufReader::new(reader);
        let _ = fbl_read_reply(&mut reader).await; // greeting
        writer.write_all(b"EHLO c\r\n").await.unwrap();
        let _ = fbl_read_full_reply(&mut reader).await;
        writer
            .write_all(b"MAIL FROM:<fbl@google.com>\r\n")
            .await
            .unwrap();
        let _ = fbl_read_reply(&mut reader).await;
        writer
            .write_all(b"RCPT TO:<abuse@fbl.test>\r\n")
            .await
            .unwrap();
        let _ = fbl_read_reply(&mut reader).await;
        writer.write_all(b"DATA\r\n").await.unwrap();
        assert!(fbl_read_reply(&mut reader).await.starts_with("354"));

        writer
            .write_all(format!("{}\r\n.\r\n", "x".repeat(200)).as_bytes())
            .await
            .unwrap();
        assert_eq!(
            fbl_read_reply(&mut reader).await,
            "552 5.3.4 Message size exceeds fixed maximum message size\r\n"
        );

        // The session stays synchronised after the refusal.
        writer.write_all(b"QUIT\r\n").await.unwrap();
        assert!(fbl_read_reply(&mut reader).await.starts_with("221"));
        tokio::time::timeout(Duration::from_secs(5), task)
            .await
            .expect("session task must finish")
            .expect("session task must not panic");
    }
}
