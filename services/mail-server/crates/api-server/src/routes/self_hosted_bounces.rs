//! Self-hosted bounce and feedback handler.
//!
//! When using the self-hosted SMTP path (Hetzner IPs), we don't get automatic
//! bounce/complaint notifications from SES. Instead, we need to://!
//! 1. Run an inbound SMTP server to receive bounces (Return-Path)
//! 2. Parse SMTP bounce responses during delivery
//! 3. Handle FBL (Feedback Loop) reports from ISPs
//!
//! This module processes these events and updates suppressions accordingly.

use chrono::{DateTime, Utc};
use regex::{Regex, RegexBuilder};
use serde::{Deserialize, Serialize};
use sqlx::PgPool;
use std::sync::LazyLock;
use tracing::{debug, info, warn};

// ─── Bounce Types ──────────────────────────────────────────────

/// Type of bounce.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BounceType {
    /// Permanent failure — email should never be retried.
    Hard,
    /// Temporary failure — may succeed on retry.
    Soft,
    /// Unknown bounce type.
    Unknown,
}

/// Categorization of bounce reason.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum BounceCategory {
    /// Invalid recipient address.
    InvalidRecipient,
    /// Mailbox full.
    MailboxFull,
    /// Domain doesn't exist.
    InvalidDomain,
    /// Blocked by recipient server.
    Blocked,
    /// Content rejected (spam filter).
    ContentRejected,
    /// Policy rejection (SPF, DKIM, DMARC).
    PolicyRejection,
    /// Technical issue.
    Technical,
    /// Unknown category.
    Unknown,
}

/// A parsed bounce event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BounceEvent {
    pub id: String,
    pub tenant_id: String,
    pub message_id: String,
    pub recipient: String,
    pub bounce_type: BounceType,
    pub category: BounceCategory,
    pub diagnostic_code: Option<String>,
    pub smtp_response: Option<String>,
    pub source_ip: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

/// A complaint/FBL event.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ComplaintEvent {
    pub id: String,
    pub tenant_id: String,
    pub message_id: String,
    pub recipient: String,
    pub feedback_type: String, // "abuse", "fraud", "other"
    pub user_agent: Option<String>,
    pub occurred_at: DateTime<Utc>,
}

// ─── SMTP Response Parser ──────────────────────────────────────

/// Parse SMTP response code and determine bounce type/category.
pub fn parse_smtp_response(
    code: u16,
    enhanced_code: Option<&str>,
    text: &str,
) -> (BounceType, BounceCategory) {
    // Parse enhanced status code (e.g., "5.1.1")
    let category = if let Some(enhanced) = enhanced_code {
        parse_enhanced_status_code(enhanced)
    } else {
        parse_from_code_and_text(code, text)
    };

    let bounce_type = if (500..600).contains(&code) {
        BounceType::Hard
    } else if (400..500).contains(&code) {
        BounceType::Soft
    } else {
        BounceType::Unknown
    };

    (bounce_type, category)
}

/// Parse RFC 3463 enhanced status code.
fn parse_enhanced_status_code(code: &str) -> BounceCategory {
    let parts: Vec<&str> = code.split('.').collect();
    if parts.len() < 2 {
        return BounceCategory::Unknown;
    }

    let class = parts[0];
    let subject = parts.get(1).copied().unwrap_or("0");
    let detail = parts.get(2).copied().unwrap_or("0");

    match subject {
        // x.1.x - Address status
        "1" => {
            match parts.get(2).copied().unwrap_or("0") {
                "1" => BounceCategory::InvalidRecipient, // Bad destination mailbox
                "2" => BounceCategory::InvalidDomain,    // Bad destination system
                "3" => BounceCategory::InvalidRecipient, // Bad destination mailbox syntax
                "4" => BounceCategory::InvalidRecipient, // Ambiguous address
                "5" => BounceCategory::InvalidRecipient, // Valid address but no route
                "6" => BounceCategory::InvalidRecipient, // Mailbox moved
                "7" => BounceCategory::InvalidRecipient, // Bad sender mailbox syntax
                "8" => BounceCategory::InvalidDomain,    // Bad sender system
                _ => BounceCategory::InvalidRecipient,
            }
        }
        // x.2.x - Mailbox status
        "2" => {
            match detail {
                "1" => BounceCategory::InvalidRecipient, // Mailbox disabled
                "2" => BounceCategory::MailboxFull,      // Mailbox full
                "3" => BounceCategory::Technical,        // Message length exceeds limit
                "4" => BounceCategory::Technical,        // Mailing list expansion problem
                _ => BounceCategory::Technical,
            }
        }
        // x.3.x - Mail system status
        "3" => BounceCategory::Technical,
        // x.4.x - Network and routing
        "4" => BounceCategory::Technical,
        // x.5.x - Protocol status
        "5" => BounceCategory::Technical,
        // x.6.x - Message content/media
        "6" => BounceCategory::ContentRejected,
        // x.7.x - Security/policy
        "7" => {
            match detail {
                "0" | "1" => BounceCategory::PolicyRejection, // Delivery not authorized
                "2" | "3" => BounceCategory::PolicyRejection, // Mailing list expansion prohibited
                "4" | "5" | "6" => BounceCategory::PolicyRejection, // Security/encryption issue
                "7" => BounceCategory::ContentRejected,       // Content too large
                "8" | "9" => BounceCategory::PolicyRejection, // Auth required
                "13" | "14" => BounceCategory::PolicyRejection, // Sender/recipient verification failed
                "15" | "16" | "17" => BounceCategory::PolicyRejection, // Priority issues
                "18" | "19" | "20" => BounceCategory::PolicyRejection, // TLS/Auth issues
                "21" | "22" | "23" | "24" | "25" | "26" | "27" => BounceCategory::Blocked, // SPF/DKIM/DMARC
                _ => BounceCategory::PolicyRejection,
            }
        }
        _ => match class {
            "4" | "5" => BounceCategory::Technical,
            _ => BounceCategory::Unknown,
        },
    }
}

/// Fallback parsing from code and text.
///
/// # Security (L-08)
/// Uses word-boundary regex patterns instead of raw `.contains()` substring
/// matching to prevent false positives (e.g., "mailbox full" matching unrelated
/// text like "your mailbox is not full, please try again"). The regex patterns
/// ensure the keywords are matched as whole words, not as substrings of larger
/// words or phrases.
fn parse_from_code_and_text(code: u16, text: &str) -> BounceCategory {
    let text_lower = text.to_lowercase();

    // L-08: Use word-boundary patterns to prevent false positives from substring matching.
    // Each pattern is compiled once and cached via `std::sync::LazyLock` for performance.
    static RE_INVALID_RECIPIENT: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new(
            r"\b(?:user unknown|no such user|recipient rejected|mailbox not found|invalid recipient|no such mailbox|address rejected|mailbox unavailable|user does not have)\b",
        )
        .case_insensitive(true)
        .build()
        .expect("Invalid regex")
    });

    static RE_MAILBOX_FULL: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new(
            r"\b(?:mailbox full|quota exceeded|over quota|mailbox storage|exceeded storage|mailbox quota)\b",
        )
        .case_insensitive(true)
        .build()
        .expect("Invalid regex")
    });

    static RE_INVALID_DOMAIN: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new(
            r"\b(?:domain not found|no mx record|bad domain|unknown domain|domain does not exist|invalid domain)\b",
        )
        .case_insensitive(true)
        .build()
        .expect("Invalid regex")
    });

    static RE_BLOCKED: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new(
            r"\b(?:blocked|blacklist(?:ed)?|listed|denied|recipient rejected|sender rejected|access denied)\b",
        )
        .case_insensitive(true)
        .build()
        .expect("Invalid regex")
    });

    static RE_CONTENT_REJECTED: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new(
            r"\b(?:spam|content rejected|message rejected|message content|attachment rejected|virus detected|suspicious attachment)\b",
        )
        .case_insensitive(true)
        .build()
        .expect("Invalid regex")
    });

    static RE_POLICY_REJECTION: LazyLock<Regex> = LazyLock::new(|| {
        RegexBuilder::new(
            r"\b(?:spf|dkim|dmarc|authentication(?: required)?|policy rejection|not authorized|not permitted|sender verify|recipient verify)\b",
        )
        .case_insensitive(true)
        .build()
        .expect("Invalid regex")
    });

    // Check for common patterns with word-boundary matching (L-08)
    if RE_INVALID_RECIPIENT.is_match(&text_lower) {
        return BounceCategory::InvalidRecipient;
    }

    if RE_MAILBOX_FULL.is_match(&text_lower) {
        return BounceCategory::MailboxFull;
    }

    if RE_INVALID_DOMAIN.is_match(&text_lower) {
        return BounceCategory::InvalidDomain;
    }

    if RE_BLOCKED.is_match(&text_lower) {
        return BounceCategory::Blocked;
    }

    if RE_CONTENT_REJECTED.is_match(&text_lower) {
        return BounceCategory::ContentRejected;
    }

    if RE_POLICY_REJECTION.is_match(&text_lower) {
        return BounceCategory::PolicyRejection;
    }

    match code {
        550 | 551 | 553 => BounceCategory::InvalidRecipient,
        552 | 452 => BounceCategory::MailboxFull,
        450 | 451 | 554 => BounceCategory::Technical,
        _ => BounceCategory::Unknown,
    }
}

// ─── Bounce Handler ────────────────────────────────────────────

/// M-3 decision for a VERP-parsed bounce address: whether the bounce may be
/// processed at all, and which recipient may be suppressed.
#[derive(Debug, Clone, PartialEq, Eq)]
enum VerpBounceDisposition {
    /// The message id resolved to a queue row owned by the VERP tenant —
    /// process the bounce and suppress this validated recipient.
    Process(String),
    /// Unknown message id, empty queue row, or tenant mismatch (forged
    /// bounce): record and suppress nothing.
    Reject,
}

/// Pure M-3 decision: a bounce is only actionable when its VERP message id
/// resolves to a queued message whose tenant matches the tenant encoded in
/// the VERP address.
fn verp_bounce_disposition(
    queued: Option<(&str, &str)>,
    verp_tenant: &str,
) -> VerpBounceDisposition {
    match queued {
        Some((tenant, recipient))
            if !tenant.is_empty()
                && !recipient.is_empty()
                && tenant.eq_ignore_ascii_case(verp_tenant) =>
        {
            VerpBounceDisposition::Process(recipient.to_string())
        }
        _ => VerpBounceDisposition::Reject,
    }
}

/// Handler for processing bounces from the self-hosted path.
pub struct SelfHostedBounceHandler {
    db: PgPool,
    /// Regex for extracting message ID from Return-Path.
    return_path_regex: Regex,
}

/// VERP Return-Path pattern, anchored to the platform's bounce domain.
///
/// Return-Path format: bounce+{tenant_id}+{message_id}@returns.{SYSTEM_DOMAIN}
/// The domain is anchored to the platform's product domain (audit M-4: the
/// pattern previously tolerated — and tests hardcoded — a drifted
/// `returns.apexmail.io`, while the platform operates `apexmail.ee`).
fn return_path_regex_pattern() -> String {
    format!(
        r"bounce\+([^+]+)\+([^@]+)@returns\.{}\b",
        regex::escape(crate::routes::system_sender::SYSTEM_DOMAIN)
    )
}

impl SelfHostedBounceHandler {
    /// Create a new bounce handler.
    pub fn new(db: PgPool) -> Self {
        let return_path_regex = Regex::new(&return_path_regex_pattern()).expect("Invalid regex");

        Self {
            db,
            return_path_regex,
        }
    }

    /// Process an SMTP bounce response (called during delivery).
    pub async fn process_smtp_bounce(
        &self,
        tenant_id: &str,
        message_id: &str,
        recipient: &str,
        code: u16,
        enhanced_code: Option<&str>,
        response_text: &str,
        source_ip: Option<&str>,
    ) -> Result<(), BounceError> {
        let (bounce_type, category) = parse_smtp_response(code, enhanced_code, response_text);

        let event = BounceEvent {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            message_id: message_id.to_string(),
            recipient: recipient.to_string(),
            bounce_type,
            category,
            diagnostic_code: enhanced_code.map(|s| s.to_string()),
            smtp_response: Some(format!("{} {}", code, response_text)),
            source_ip: source_ip.map(|s| s.to_string()),
            occurred_at: Utc::now(),
        };

        self.record_bounce(&event).await?;

        // Add to suppressions if hard bounce
        if bounce_type == BounceType::Hard {
            self.add_suppression(tenant_id, recipient, &format!("hard_bounce:{:?}", category))
                .await?;
        }

        Ok(())
    }

    /// Process an inbound bounce email (DSN).
    pub async fn process_bounce_email(
        &self,
        _from: &str,
        to: &str,
        raw_email: &[u8],
    ) -> Result<(), BounceError> {
        // Parse Return-Path to get tenant_id and message_id
        let captures = self
            .return_path_regex
            .captures(to)
            .ok_or(BounceError::InvalidReturnPath)?;

        let tenant_id = captures
            .get(1)
            .ok_or(BounceError::InvalidReturnPath)?
            .as_str();
        let message_id = captures
            .get(2)
            .ok_or(BounceError::InvalidReturnPath)?
            .as_str();

        // M-3: never trust the VERP payload alone. Resolve the queued message
        // and cross-check the tenant, mirroring the reference implementation
        // in crates/mta/src/servers/bounce.rs (`lookup_sent_message`): a
        // bounce for a message this system never sent (or one whose VERP
        // tenant does not match the queue row) must not record events, bump
        // deliverability metrics, or poison the suppression list.
        let queued = self.lookup_queued_message(message_id).await?;
        let suppression_recipient = match verp_bounce_disposition(
            queued
                .as_ref()
                .map(|(tenant, recipient)| (tenant.as_str(), recipient.as_str())),
            tenant_id,
        ) {
            VerpBounceDisposition::Process(validated_recipient) => validated_recipient,
            VerpBounceDisposition::Reject => {
                warn!(
                    tenant_id = %tenant_id,
                    message_id = %message_id,
                    "Bounce references an unknown or mismatched message — skipping processing"
                );
                return Ok(());
            }
        };

        // Parse the DSN email to extract bounce details
        let (recipient, bounce_type, category, diagnostic) = parse_dsn_email(raw_email)?;

        let event = BounceEvent {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            message_id: message_id.to_string(),
            recipient,
            bounce_type,
            category,
            diagnostic_code: diagnostic,
            smtp_response: None,
            source_ip: None,
            occurred_at: Utc::now(),
        };

        self.record_bounce(&event).await?;

        // Add to suppressions if hard bounce. The suppression targets the
        // recipient from the validated queue row — the address this system
        // actually sent to — not the DSN-claimed Final-Recipient, which is
        // attacker-influenceable content (M-12).
        if bounce_type == BounceType::Hard {
            self.add_suppression(
                tenant_id,
                &suppression_recipient,
                &format!("hard_bounce:{:?}", category),
            )
            .await?;
        }

        info!(
            tenant_id = %tenant_id,
            message_id = %message_id,
            recipient = %apexmail_lib::pii::redact_email(&event.recipient),
            bounce_type = ?bounce_type,
            "Processed inbound bounce"
        );

        Ok(())
    }

    /// Resolve the tenant and recipient of a message this system sent
    /// (M-3, mirrors `mta::servers::bounce::lookup_sent_message`).
    async fn lookup_queued_message(
        &self,
        message_id: &str,
    ) -> Result<Option<(String, String)>, BounceError> {
        let row: Option<(String, String)> = sqlx::query_as(
            r#"SELECT COALESCE(tenant_id::text, '') AS tenant_id,
                      COALESCE(to_addresses[1], '') AS recipient
               FROM email_queue
               WHERE id::text = $1 OR message_id::text = $1
               LIMIT 1"#,
        )
        .bind(message_id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| BounceError::Database(e.to_string()))?;

        Ok(row.filter(|(tenant, recipient)| !tenant.is_empty() && !recipient.is_empty()))
    }

    /// Process an FBL (Feedback Loop) complaint.
    pub async fn process_fbl_complaint(
        &self,
        tenant_id: &str,
        message_id: &str,
        recipient: &str,
        feedback_type: &str,
        user_agent: Option<&str>,
    ) -> Result<(), BounceError> {
        let event = ComplaintEvent {
            id: uuid::Uuid::new_v4().to_string(),
            tenant_id: tenant_id.to_string(),
            message_id: message_id.to_string(),
            recipient: recipient.to_string(),
            feedback_type: feedback_type.to_string(),
            user_agent: user_agent.map(|s| s.to_string()),
            occurred_at: Utc::now(),
        };

        // Record complaint
        sqlx::query(
            r#"
            INSERT INTO complaints (id, tenant_id, recipient, feedback_type, user_agent, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            "#,
        )
        .bind(&event.id)
        .bind(&event.tenant_id)
        .bind(&event.recipient)
        .bind(&event.feedback_type)
        .bind(&event.user_agent)
        .execute(&self.db)
        .await
        .map_err(|e| BounceError::Database(e.to_string()))?;

        // Always suppress on complaint
        self.add_suppression(tenant_id, recipient, "complaint")
            .await?;

        // Update tenant metrics
        sqlx::query(
            r#"
            INSERT INTO tenant_deliverability_metrics (tenant_id, period_start, emails_complained)
            VALUES ($1, DATE_TRUNC('day', NOW()), 1)
            ON CONFLICT (tenant_id, period_start)
            DO UPDATE SET emails_complained = tenant_deliverability_metrics.emails_complained + 1
            "#,
        )
        .bind(tenant_id)
        .execute(&self.db)
        .await
        .map_err(|e| BounceError::Database(e.to_string()))?;

        warn!(
            tenant_id = %tenant_id,
            recipient = %apexmail_lib::pii::redact_email(recipient),
            feedback_type = %feedback_type,
            "Processed FBL complaint"
        );

        Ok(())
    }

    /// Record a bounce event to the database.
    async fn record_bounce(&self, event: &BounceEvent) -> Result<(), BounceError> {
        sqlx::query(
            r#"
            INSERT INTO bounces (id, tenant_id, recipient, bounce_type, diagnostic_code, created_at)
            VALUES ($1, $2, $3, $4, $5, NOW())
            "#,
        )
        .bind(&event.id)
        .bind(&event.tenant_id)
        .bind(&event.recipient)
        .bind(format!("{:?}", event.bounce_type).to_lowercase())
        .bind(&event.diagnostic_code)
        .execute(&self.db)
        .await
        .map_err(|e| BounceError::Database(e.to_string()))?;

        // Update tenant metrics
        let metric_column = "emails_bounced";

        sqlx::query(&format!(
            r#"
            INSERT INTO tenant_deliverability_metrics (tenant_id, period_start, {})
            VALUES ($1, DATE_TRUNC('day', NOW()), 1)
            ON CONFLICT (tenant_id, period_start)
            DO UPDATE SET {} = tenant_deliverability_metrics.{} + 1
            "#,
            metric_column, metric_column, metric_column
        ))
        .bind(&event.tenant_id)
        .execute(&self.db)
        .await
        .map_err(|e| BounceError::Database(e.to_string()))?;

        debug!(
            tenant_id = %event.tenant_id,
            message_id = %event.message_id,
            recipient = %apexmail_lib::pii::redact_email(&event.recipient),
            bounce_type = ?event.bounce_type,
            category = ?event.category,
            "Recorded bounce event"
        );

        Ok(())
    }

    /// Add an email to the suppression list.
    async fn add_suppression(
        &self,
        tenant_id: &str,
        email: &str,
        reason: &str,
    ) -> Result<(), BounceError> {
        // `suppressions.id VARCHAR(26)` is NOT NULL without a default
        // (migration 088) — supply one (`sup_` + 18 hex = 22 chars, matching
        // the mta crate's suppression row ids).
        let suppression_id = format!("sup_{}", &uuid::Uuid::new_v4().simple().to_string()[..18]);

        sqlx::query(
            r#"
            INSERT INTO suppressions (id, tenant_id, email, reason, created_at)
            VALUES ($1, $2, $3, $4, NOW())
            ON CONFLICT (tenant_id, email) DO UPDATE SET reason = $4
            "#,
        )
        .bind(suppression_id)
        .bind(tenant_id)
        .bind(email)
        .bind(reason)
        .execute(&self.db)
        .await
        .map_err(|e| BounceError::Database(e.to_string()))?;

        info!(tenant_id = %tenant_id, email = %apexmail_lib::pii::redact_email(email), reason = %reason, "Added to suppression list");

        Ok(())
    }
}

/// Parse a DSN (Delivery Status Notification) email.
///
/// Pure function (no handler state): all field lookups go through the
/// region-limited [`extract_dsn_header`] (M-12).
fn parse_dsn_email(
    raw_email: &[u8],
) -> Result<(String, BounceType, BounceCategory, Option<String>), BounceError> {
    // Basic DSN parsing - in production, use a proper MIME parser
    let email_str = String::from_utf8_lossy(raw_email);

    // M-12: look up DSN fields ONLY within trusted header regions — a
    // "Final-Recipient:" line planted inside the bounced message's original
    // content must not win the lookup.
    let recipient = extract_dsn_header(&email_str, "Final-Recipient")
        .or_else(|| extract_dsn_header(&email_str, "Original-Recipient"))
        .unwrap_or_else(|| "unknown@unknown.com".to_string());

    // Clean up recipient (remove "rfc822;" prefix)
    let recipient = recipient
        .replace("rfc822;", "")
        .replace("RFC822;", "")
        .trim()
        .to_string();

    // Look for Status header (e.g., "5.1.1")
    let status = extract_dsn_header(&email_str, "Status");
    let diagnostic = extract_dsn_header(&email_str, "Diagnostic-Code");

    let (bounce_type, category) = if let Some(ref status) = status {
        (
            if status.starts_with('5') {
                BounceType::Hard
            } else if status.starts_with('4') {
                BounceType::Soft
            } else {
                BounceType::Unknown
            },
            parse_enhanced_status_code(status),
        )
    } else {
        // Try to determine from diagnostic
        let (bt, cat) = if let Some(ref diag) = diagnostic {
            let code = if diag.contains("550") {
                550
            } else if diag.contains("551") {
                551
            } else {
                0
            };
            parse_smtp_response(code, None, diag)
        } else {
            (BounceType::Unknown, BounceCategory::Unknown)
        };
        (bt, cat)
    };

    Ok((recipient, bounce_type, category, diagnostic))
}

// ─── DSN header-region extraction (M-12) ───────────────────────

/// Split a block at the first blank line into `(headers, Some(body))`; a
/// block with no blank line is all headers.
fn split_header_body(block: &str) -> (&str, Option<&str>) {
    if let Some(pos) = block.find("\r\n\r\n") {
        (&block[..pos], Some(&block[pos + 4..]))
    } else if let Some(pos) = block.find("\n\n") {
        (&block[..pos], Some(&block[pos + 2..]))
    } else {
        (block, None)
    }
}

/// Extract a header value from a bounded header region (line-start match on
/// the header name, case-insensitive — same matching rule the previous
/// whole-message scanner used, now scope-limited).
fn extract_header_in_region(region: &str, header_name: &str) -> Option<String> {
    let pattern = format!("{}:", header_name);
    for line in region.lines() {
        if line.to_lowercase().starts_with(&pattern.to_lowercase()) {
            return Some(line[pattern.len()..].trim().to_string());
        }
    }
    None
}

/// Parse the `boundary` parameter out of a Content-Type header value.
fn mime_boundary(content_type: &str) -> Option<String> {
    let lower = content_type.to_ascii_lowercase();
    let idx = lower.find("boundary=")?;
    let rest = content_type[idx + "boundary=".len()..].trim_start();
    if let Some(stripped) = rest.strip_prefix('"') {
        let end = stripped.find('"')?;
        Some(stripped[..end].to_string())
    } else {
        let end = rest.find(';').unwrap_or(rest.len());
        Some(rest[..end].trim().to_string())
    }
}

/// Split a multipart body into its parts at the MIME boundary delimiter
/// lines (preamble ignored, closing delimiter terminates).
fn split_mime_parts(body: &str, boundary: &str) -> Vec<String> {
    let delimiter = format!("--{boundary}");
    let closing = format!("{delimiter}--");
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut inside = false;
    for line in body.lines() {
        let line = line.trim_end_matches('\r');
        let trimmed = line.trim_start();
        if trimmed == delimiter || trimmed == closing {
            if inside {
                parts.push(std::mem::take(&mut current));
            }
            inside = true;
            if trimmed == closing {
                break;
            }
            continue;
        }
        if inside {
            current.push_str(line);
            current.push('\n');
        }
    }
    if inside && !current.is_empty() {
        parts.push(current);
    }
    parts
}

/// Whether a Content-Type header value denotes `message/delivery-status`
/// content — the MIME part whose entire payload is header-format DSN fields.
///
/// Note: a top-level `multipart/report; report-type=delivery-status` is NOT
/// delivery-status content itself (only its dedicated part is), so it must
/// not trigger the whole-message shortcut.
fn is_delivery_status_content(content_type: &str) -> bool {
    content_type
        .to_ascii_lowercase()
        .contains("message/delivery-status")
}

/// The header regions a DSN field may legitimately appear in, in priority
/// order (M-12):
///
/// 1. the `message/delivery-status` part — its content is header-format
///    per-message/per-recipient fields (`Final-Recipient`, `Status`,
///    `Diagnostic-Code`, ...), which is where RFC 3464 puts them;
/// 2. the top-level header block (a bare `message/delivery-status` message
///    is entirely header-format, headers included);
/// 3. the header block of every other MIME part (part headers over body
///    hits).
///
/// The body of the `message/rfc822` part — the original bounced message,
/// whose content the sender's correspondent controls — is never a region.
fn dsn_header_regions(email: &str) -> Vec<String> {
    let (top_headers, body) = split_header_body(email);
    let top_content_type =
        extract_header_in_region(top_headers, "Content-Type").unwrap_or_default();

    // A bare message/delivery-status (non-multipart) is all header-format.
    if is_delivery_status_content(&top_content_type) {
        return vec![email.to_string()];
    }

    let mut delivery_status_regions = Vec::new();
    let mut part_header_regions = Vec::new();

    if let (Some(boundary), Some(body)) = (mime_boundary(&top_content_type), body) {
        for part in split_mime_parts(body, &boundary) {
            let (part_headers, _part_body) = split_header_body(&part);
            let part_content_type =
                extract_header_in_region(part_headers, "Content-Type").unwrap_or_default();
            if is_delivery_status_content(&part_content_type) {
                // The whole delivery-status part is header-format fields.
                delivery_status_regions.push(part);
            } else {
                part_header_regions.push(part_headers.to_string());
            }
        }
    }

    let mut regions = delivery_status_regions;
    regions.push(top_headers.to_string());
    regions.extend(part_header_regions);
    regions
}

/// Extract a DSN header field, searching ONLY the trusted [`dsn_header_regions`]
/// (M-12): the `message/delivery-status` part of a multipart/report, the
/// top-level header block, and the header blocks of the other MIME parts —
/// never the body of the `message/rfc822` part that carries the
/// (attacker-influenceable) original bounced message.
fn extract_dsn_header(email: &str, header_name: &str) -> Option<String> {
    for region in dsn_header_regions(email) {
        if let Some(value) = extract_header_in_region(&region, header_name) {
            return Some(value);
        }
    }
    None
}

// ─── Errors ────────────────────────────────────────────────────

#[derive(Debug, thiserror::Error)]
pub enum BounceError {
    #[error("Database error: {0}")]
    Database(String),

    #[error("Invalid Return-Path format")]
    InvalidReturnPath,

    #[error("Parse error: {0}")]
    ParseError(String),
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_smtp_response_hard_bounce() {
        let (bt, cat) = parse_smtp_response(550, Some("5.1.1"), "User unknown");
        assert_eq!(bt, BounceType::Hard);
        assert_eq!(cat, BounceCategory::InvalidRecipient);
    }

    #[test]
    fn test_parse_smtp_response_soft_bounce() {
        let (bt, cat) = parse_smtp_response(452, Some("4.2.2"), "Mailbox full");
        assert_eq!(bt, BounceType::Soft);
        assert_eq!(cat, BounceCategory::MailboxFull);
    }

    #[test]
    fn test_parse_smtp_response_blocked() {
        let (bt, cat) = parse_smtp_response(554, Some("5.7.1"), "Blocked by policy");
        assert_eq!(bt, BounceType::Hard);
        assert_eq!(cat, BounceCategory::PolicyRejection);
    }

    #[test]
    fn test_parse_from_text() {
        let (bt, cat) = parse_smtp_response(550, None, "User unknown or mailbox unavailable");
        assert_eq!(bt, BounceType::Hard);
        assert_eq!(cat, BounceCategory::InvalidRecipient);

        let (bt2, cat2) = parse_smtp_response(452, None, "Mailbox is full");
        assert_eq!(bt2, BounceType::Soft);
        assert_eq!(cat2, BounceCategory::MailboxFull);
    }

    #[test]
    fn test_enhanced_status_codes() {
        assert_eq!(
            parse_enhanced_status_code("5.1.1"),
            BounceCategory::InvalidRecipient
        );
        assert_eq!(
            parse_enhanced_status_code("5.2.2"),
            BounceCategory::MailboxFull
        );
        assert_eq!(
            parse_enhanced_status_code("5.7.1"),
            BounceCategory::PolicyRejection
        );
        assert_eq!(
            parse_enhanced_status_code("5.6.1"),
            BounceCategory::ContentRejected
        );
        assert_eq!(
            parse_enhanced_status_code("5.7.23"),
            BounceCategory::Blocked
        ); // DKIM
    }

    // ── M-12: header-region extraction ───────────────────────────

    /// A realistic multipart/report DSN whose message/rfc822 part carries a
    /// planted `Final-Recipient`/`Status` inside the ORIGINAL message body.
    fn dsn_with_planted_headers() -> String {
        [
            "From: MAILER-DAEMON@mail.example.net",
            "To: bounce+11111111-1111-1111-1111-111111111111+victim@example.com",
            "Subject: Undelivered Mail",
            "MIME-Version: 1.0",
            "Content-Type: multipart/report; report-type=delivery-status; boundary=\"BOUND\"",
            "",
            "This is a MIME-encapsulated message.",
            "",
            "--BOUND",
            "Content-Type: text/plain; charset=us-ascii",
            "",
            "The mail could not be delivered.",
            "",
            "--BOUND",
            "Content-Type: message/delivery-status",
            "",
            "Reporting-MTA: dns; mail.example.net",
            "",
            "Final-Recipient: rfc822; real-recipient@example.com",
            "Original-Recipient: rfc822; real-recipient@example.com",
            "Action: failed",
            "Status: 5.1.1",
            "Diagnostic-Code: smtp; 550 5.1.1 User unknown",
            "",
            "--BOUND",
            "Content-Type: message/rfc822",
            "",
            "Return-Path: <bounce+11111111-1111-1111-1111-111111111111+victim@example.com>",
            "From: Sender <sender@example.com>",
            "Subject: original message",
            "",
            "Final-Recipient: rfc822; planted-victim@attacker.tld",
            "Status: 5.1.1",
            "Someone wrote about Final-Recipient: rfc822; body-planted@attacker.tld",
            "in the body of the original message.",
            "",
            "--BOUND--",
            "",
        ]
        .join("\r\n")
    }

    #[test]
    fn dsn_fields_come_from_delivery_status_part_not_planted_body_lines() {
        let raw = dsn_with_planted_headers();

        let (recipient, bounce_type, _category, diagnostic) =
            parse_dsn_email(raw.as_bytes()).unwrap();

        assert_eq!(
            recipient, "real-recipient@example.com",
            "the delivery-status part must win over planted body lines"
        );
        assert_eq!(bounce_type, BounceType::Hard);
        assert_eq!(diagnostic.as_deref(), Some("smtp; 550 5.1.1 User unknown"));
    }

    #[test]
    fn header_regions_never_include_the_original_message_body() {
        let raw = dsn_with_planted_headers();
        let regions = dsn_header_regions(&raw);

        assert!(
            regions.iter().any(|r| r.contains("message/delivery-status")
                && r.contains("Final-Recipient: rfc822; real-recipient@example.com")),
            "the delivery-status part must be a search region"
        );
        for region in &regions {
            assert!(
                !region.contains("body-planted@attacker.tld"),
                "original-message body content leaked into a header region: {region:?}"
            );
        }
    }

    #[test]
    fn non_mime_bounces_only_consider_top_level_headers() {
        // A non-MIME bounce: a Status line planted in the body must not
        // classify the bounce (and a body Final-Recipient must not win).
        let raw = "From: MAILER-DAEMON@example.net\r\n\
                   To: bounce+t+msg@returns.apexmail.ee\r\n\
                   Subject: failure\r\n\
                   \r\n\
                   Final-Recipient: rfc822; body-planted@attacker.tld\r\n\
                   Status: 5.1.1\r\n\
                   your message could not be delivered\r\n";

        let regions = dsn_header_regions(raw);
        assert_eq!(regions.len(), 1, "only the top-level header block");
        assert!(regions[0].starts_with("From: MAILER-DAEMON"));

        let (recipient, bounce_type, _category, diagnostic) =
            parse_dsn_email(raw.as_bytes()).unwrap();
        assert_eq!(
            recipient, "unknown@unknown.com",
            "no trusted Final-Recipient"
        );
        assert_eq!(bounce_type, BounceType::Unknown, "planted Status ignored");
        assert_eq!(diagnostic, None, "planted Diagnostic-Code ignored");
    }

    // ── M-3: VERP validation decision ────────────────────────────

    #[test]
    fn verp_return_path_regex_anchors_to_the_platform_domain() {
        let re = Regex::new(&return_path_regex_pattern()).expect("valid pattern");

        // The platform domain parses and extracts tenant + message id.
        let caps = re
            .captures("bounce+tenant-a+00000000-0000-0000-0000-000000000000@returns.apexmail.ee")
            .expect("platform-domain VERP address must match");
        assert_eq!(caps.get(1).unwrap().as_str(), "tenant-a");
        assert_eq!(
            caps.get(2).unwrap().as_str(),
            "00000000-0000-0000-0000-000000000000"
        );

        // M-4 regression: the drifted `apexmail.io` domain must NOT parse.
        assert!(
            re.captures("bounce+tenant-a+00000000-0000-0000-0000-000000000000@returns.apexmail.io")
                .is_none(),
            "VERP addresses on a domain the platform does not operate must be rejected"
        );

        // Arbitrary attacker domains must not parse either.
        assert!(
            re.captures("bounce+tenant-a+msg@returns.attacker.tld")
                .is_none(),
            "foreign VERP domains must be rejected"
        );
    }

    #[test]
    fn verp_bounce_disposition_rejects_unknown_and_mismatched_messages() {
        // Unknown message id (nothing queued): forged bounce.
        assert_eq!(
            verp_bounce_disposition(None, "tenant-a"),
            VerpBounceDisposition::Reject
        );
        // Queue row with empty tenant/recipient is unusable.
        assert_eq!(
            verp_bounce_disposition(Some(("", "user@example.com")), "tenant-a"),
            VerpBounceDisposition::Reject
        );
        assert_eq!(
            verp_bounce_disposition(Some(("tenant-a", "")), "tenant-a"),
            VerpBounceDisposition::Reject
        );
        // VERP tenant does not match the queue row's tenant: forged.
        assert_eq!(
            verp_bounce_disposition(Some(("tenant-b", "user@example.com")), "tenant-a"),
            VerpBounceDisposition::Reject
        );
        // Valid: matching tenant, resolvable recipient.
        assert_eq!(
            verp_bounce_disposition(Some(("tenant-a", "user@example.com")), "tenant-a"),
            VerpBounceDisposition::Process("user@example.com".to_string())
        );
        // Tenant comparison is case-insensitive (UUID casing varies by source).
        assert_eq!(
            verp_bounce_disposition(Some(("Tenant-A", "user@example.com")), "tenant-a"),
            VerpBounceDisposition::Process("user@example.com".to_string())
        );
    }

    // ── M-3 + M-12 end-to-end (DB-gated) ─────────────────────────

    /// Minimal schema for the handler's queries, in a dedicated per-test
    /// database (avoids the tools/migrations shape divergence in `<db>_api`).
    async fn bounce_test_pool(db_suffix: &str) -> Option<sqlx::PgPool> {
        use sqlx::postgres::PgPoolOptions;
        use std::time::Duration;

        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api_bounces_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;
        sqlx::query(
            r#"
            CREATE TABLE email_queue (
                id           UUID PRIMARY KEY,
                tenant_id    TEXT,
                to_addresses TEXT[] NOT NULL DEFAULT '{}',
                message_id   UUID
            );
            CREATE TABLE bounces (
                id              UUID PRIMARY KEY,
                tenant_id       VARCHAR(26) NOT NULL,
                recipient       VARCHAR(320) NOT NULL,
                bounce_type     VARCHAR(20)  NOT NULL,
                diagnostic_code TEXT,
                created_at      TIMESTAMPTZ  NOT NULL DEFAULT NOW()
            );
            CREATE TABLE suppressions (
                id         VARCHAR(26) PRIMARY KEY,
                tenant_id  VARCHAR(26) NOT NULL,
                email      VARCHAR(255) NOT NULL,
                reason     VARCHAR(50)  NOT NULL,
                subtype    VARCHAR(100),
                source     VARCHAR(100),
                created_at TIMESTAMPTZ  NOT NULL DEFAULT NOW(),
                updated_at TIMESTAMPTZ,
                UNIQUE (tenant_id, email)
            );
            CREATE TABLE tenant_deliverability_metrics (
                tenant_id         TEXT NOT NULL,
                period_start      TIMESTAMPTZ NOT NULL,
                emails_bounced    BIGINT NOT NULL DEFAULT 0,
                emails_complained BIGINT NOT NULL DEFAULT 0,
                PRIMARY KEY (tenant_id, period_start)
            );
            "#,
        )
        .execute(&pool)
        .await
        .ok()?;
        Some(pool)
    }

    async fn suppression_count(pool: &sqlx::PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM suppressions")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    async fn bounce_count(pool: &sqlx::PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM bounces")
            .fetch_one(pool)
            .await
            .unwrap()
    }

    #[tokio::test]
    async fn forged_bounce_for_unknown_message_does_not_suppress() {
        let Some(pool) = bounce_test_pool("forged").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        // NOTHING is queued: the VERP address is entirely forged.
        let handler = SelfHostedBounceHandler::new(pool.clone());
        handler
            .process_bounce_email(
                "mailer-daemon@evil.example",
                "bounce+tenant-a+00000000-0000-0000-0000-000000000000@returns.apexmail.ee",
                dsn_with_planted_headers().as_bytes(),
            )
            .await
            .expect("forged bounce is dropped without error");

        assert_eq!(suppression_count(&pool).await, 0, "no suppression");
        assert_eq!(bounce_count(&pool).await, 0, "no bounce recorded");
        pool.close().await;
    }

    #[tokio::test]
    async fn forged_bounce_with_mismatched_verp_tenant_does_not_suppress() {
        let Some(pool) = bounce_test_pool("mismatch").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        // A real queued message — but owned by tenant-b, while the VERP
        // address claims tenant-a.
        let message_id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO email_queue (id, tenant_id, to_addresses) VALUES ($1, 'tenant-b', ARRAY['real-recipient@example.com'])")
            .bind(message_id)
            .execute(&pool)
            .await
            .unwrap();

        let handler = SelfHostedBounceHandler::new(pool.clone());
        handler
            .process_bounce_email(
                "mailer-daemon@evil.example",
                &format!("bounce+tenant-a+{message_id}@returns.apexmail.ee"),
                dsn_with_planted_headers().as_bytes(),
            )
            .await
            .expect("forged bounce is dropped without error");

        assert_eq!(suppression_count(&pool).await, 0, "no suppression");
        assert_eq!(bounce_count(&pool).await, 0, "no bounce recorded");
        pool.close().await;
    }

    #[tokio::test]
    async fn legitimate_dsn_suppresses_the_queued_recipient_not_planted_one() {
        let Some(pool) = bounce_test_pool("legit").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        let message_id = uuid::Uuid::new_v4();
        sqlx::query("INSERT INTO email_queue (id, tenant_id, to_addresses) VALUES ($1, 'tenant-a', ARRAY['real-recipient@example.com'])")
            .bind(message_id)
            .execute(&pool)
            .await
            .unwrap();

        let handler = SelfHostedBounceHandler::new(pool.clone());
        handler
            .process_bounce_email(
                "mailer-daemon@mail.example.net",
                &format!("bounce+tenant-a+{message_id}@returns.apexmail.ee"),
                dsn_with_planted_headers().as_bytes(),
            )
            .await
            .expect("legitimate bounce processes");

        assert_eq!(bounce_count(&pool).await, 1, "bounce recorded");
        let suppressed: Option<(String, String)> =
            sqlx::query_as("SELECT email, reason FROM suppressions WHERE tenant_id = 'tenant-a'")
                .fetch_optional(&pool)
                .await
                .unwrap();
        let (suppressed_email, suppressed_reason) = suppressed.expect("hard bounce suppresses");
        // The VALIDATED queued recipient is suppressed — never the address
        // planted in the original message body.
        assert_eq!(suppressed_email, "real-recipient@example.com");
        assert!(
            suppressed_reason.starts_with("hard_bounce:"),
            "reason: {suppressed_reason}"
        );
        assert!(
            !suppressed_email.contains("attacker.tld"),
            "planted recipient must never be suppressed"
        );
        pool.close().await;
    }
}
