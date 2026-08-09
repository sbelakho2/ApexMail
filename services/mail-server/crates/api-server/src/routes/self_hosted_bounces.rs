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

/// Handler for processing bounces from the self-hosted path.
pub struct SelfHostedBounceHandler {
    db: PgPool,
    /// Regex for extracting message ID from Return-Path.
    return_path_regex: Regex,
}

impl SelfHostedBounceHandler {
    /// Create a new bounce handler.
    pub fn new(db: PgPool) -> Self {
        // Return-Path format:bounce+{tenant_id}+{message_id}@returns.apexmail.io
        let return_path_regex = Regex::new(r"bounce\+([^+]+)\+([^@]+)@").expect("Invalid regex");

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

        // Parse the DSN email to extract bounce details
        let (recipient, bounce_type, category, diagnostic) = self.parse_dsn_email(raw_email)?;

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

        // Add to suppressions if hard bounce
        if bounce_type == BounceType::Hard {
            self.add_suppression(
                tenant_id,
                &event.recipient,
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
        sqlx::query(
            r#"
            INSERT INTO suppressions (tenant_id, email, reason, created_at)
            VALUES ($1, $2, $3, NOW())
            ON CONFLICT (tenant_id, email) DO UPDATE SET reason = $3
            "#,
        )
        .bind(tenant_id)
        .bind(email)
        .bind(reason)
        .execute(&self.db)
        .await
        .map_err(|e| BounceError::Database(e.to_string()))?;

        info!(tenant_id = %tenant_id, email = %apexmail_lib::pii::redact_email(email), reason = %reason, "Added to suppression list");

        Ok(())
    }

    /// Parse a DSN (Delivery Status Notification) email.
    fn parse_dsn_email(
        &self,
        raw_email: &[u8],
    ) -> Result<(String, BounceType, BounceCategory, Option<String>), BounceError> {
        // Basic DSN parsing - in production, use a proper MIME parser
        let email_str = String::from_utf8_lossy(raw_email);

        // Look for Final-Recipient header
        let recipient = self
            .extract_header(&email_str, "Final-Recipient")
            .or_else(|| self.extract_header(&email_str, "Original-Recipient"))
            .unwrap_or_else(|| "unknown@unknown.com".to_string());

        // Clean up recipient (remove "rfc822;" prefix)
        let recipient = recipient
            .replace("rfc822;", "")
            .replace("RFC822;", "")
            .trim()
            .to_string();

        // Look for Status header (e.g., "5.1.1")
        let status = self.extract_header(&email_str, "Status");
        let diagnostic = self.extract_header(&email_str, "Diagnostic-Code");

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

    /// Extract a header value from an email.
    fn extract_header(&self, email: &str, header_name: &str) -> Option<String> {
        let pattern = format!("{}:", header_name);
        for line in email.lines() {
            if line.to_lowercase().starts_with(&pattern.to_lowercase()) {
                return Some(line[pattern.len()..].trim().to_string());
            }
        }
        None
    }
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
}
