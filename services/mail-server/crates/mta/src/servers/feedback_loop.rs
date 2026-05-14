//! Feedback Loop (FBL) server – processes ARF complaint reports from ISPs.
//!
//! Verifies the source IP via reverse DNS against a known list of ISP FBL senders,
//! parses ARF feedback reports, updates sender reputation, and manages suppression.

use std::collections::HashSet;
use std::net::{IpAddr, SocketAddr};
use std::sync::{Arc, LazyLock};
use std::time::Duration;

use bytes::BytesMut;
use hmac::{Hmac, Mac};
use moka::sync::Cache;
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use sqlx::PgPool;
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufStream};
use tokio::net::{TcpListener, TcpStream};
use tokio::sync::Notify;
use tracing::{debug, error, info, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;
use uuid::Uuid;

use crate::config::FeedbackConfig;

// #148:Shared DNS resolver – avoids creating a new one per rDNS verification call
static FBL_RESOLVER: LazyLock<TokioAsyncResolver> =
    LazyLock::new(|| TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default()));

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

        // Verify source via rDNS
        if !self.verify_fbl_source(ip).await {
            let mut s = BufStream::new(socket);
            let _ = write_line(&mut s, "554 Unverified FBL source\r\n").await;
            return;
        }

        let mut stream = BufStream::new(socket);
        let greeting = format!("220 {} FBL Processor\r\n", self.hostname);
        if write_line(&mut stream, &greeting).await.is_err() {
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
                let _ = write_line(&mut stream, &format!("250 {}\r\n", self.hostname)).await;
            } else if cmd.starts_with("MAIL FROM") {
                let _ = write_line(&mut stream, "250 OK\r\n").await;
            } else if cmd.starts_with("RCPT TO") {
                let addr = extract_addr(&line);
                // Accept abuse@, complaints@, fbl@, feedback@, postmaster@
                let local = addr.split('@').next().unwrap_or("").to_lowercase();
                let accepted = local == "abuse"
                    || local == "complaints"
                    || local == "fbl"
                    || local == "feedback"
                    || local == "postmaster";
                if accepted {
                    rcpt_to.push(addr);
                    let _ = write_line(&mut stream, "250 OK\r\n").await;
                } else {
                    let _ = write_line(&mut stream, "550 Invalid FBL recipient\r\n").await;
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

                match self.process_complaint(ip, &message).await {
                    Ok(id) => {
                        let _ = write_line(&mut stream, &format!("250 OK id={id}\r\n")).await;
                    }
                    Err(e) => {
                        warn!(error = %e, "Complaint processing failed");
                        let _ = write_line(&mut stream, "451 Temporary failure\r\n").await;
                    }
                }
                rcpt_to.clear();
            } else if cmd.starts_with("QUIT") {
                let _ = write_line(&mut stream, "221 Bye\r\n").await;
                break;
            } else if cmd.starts_with("RSET") || cmd.starts_with("NOOP") {
                let _ = write_line(&mut stream, "250 OK\r\n").await;
            } else if cmd.starts_with("VRFY") || cmd.starts_with("EXPN") {
                // Avoid leaking recipient validity.
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
                for name in lookup.iter() {
                    let hostname_str = name.to_string();
                    let hostname = hostname_str.trim_end_matches('.').to_lowercase();
                    if self
                        .trusted_domains
                        .iter()
                        .any(|domain| hostname.ends_with(domain.as_str()))
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
        let complaint_id = Uuid::new_v4().to_string();

        // O-1.5:Reject oversized ARF payloads before parsing
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

        // Record complaint event
        sqlx::query(
            r#"INSERT INTO complaint_events (
                id, original_message_id, original_recipient,
                feedback_type, source_ip, reporting_mta,
                user_agent, arrival_date, created_at
            ) VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW())"#,
        )
        .bind(&complaint_id)
        .bind(&original_id)
        .bind(&complaint.original_recipient)
        .bind(&complaint.feedback_type)
        .bind(source_ip.to_string())
        .bind(&complaint.reporting_mta)
        .bind(&complaint.user_agent)
        .bind(&complaint.arrival_date)
        .execute(&self.pool)
        .await?;

        // Add recipient to suppression list (complaints → always suppress)
        if let Some(ref recipient) = complaint.original_recipient {
            sqlx::query(
                "INSERT INTO suppression_list (email, reason, source, created_at) VALUES ($1, 'complaint', 'fbl', NOW()) ON CONFLICT DO NOTHING"
            )
            .bind(recipient)
            .execute(&self.pool)
            .await?;
        }

        // Update sender reputation
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

        Ok(complaint_id)
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
                .bind(webhook_id)
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
}
