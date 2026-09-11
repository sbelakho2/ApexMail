//! Email processor types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use zeroize::Zeroizing;

/// An email job from the queue.
#[derive(Debug, Clone, FromRow, Serialize, Deserialize)]
pub struct EmailJob {
    pub id: String,
    #[sqlx(rename = "messageId")]
    pub message_id: String,
    #[sqlx(rename = "tenantId")]
    pub tenant_id: String,
    #[sqlx(rename = "domainId")]
    pub domain_id: String,
    pub from: String,
    pub to: String,
    pub subject: String,
    pub html: Option<String>,
    pub text: Option<String>,
    pub headers: Option<JsonValue>,
    pub attachments: Option<JsonValue>,
    #[sqlx(rename = "campaignId")]
    pub campaign_id: Option<String>,
    /// F55: the validated server-owned send category (migration 187,
    /// default 'marketing'), enforced at dispatch against
    /// subscription_preferences.
    pub message_category: String,
    pub tags: Option<Vec<String>>,
    pub metadata: Option<JsonValue>,
    #[sqlx(rename = "scheduledAt")]
    pub scheduled_at: Option<DateTime<Utc>>,
    pub attempt: i32,
    #[sqlx(rename = "createdAt")]
    pub created_at: DateTime<Utc>,
}

/// F26: one structured RFC 5322 mailbox (`Name <local@domain>`). Visible
/// To/Cc lists and Reply-To are carried as ARRAYS of these end-to-end
/// (queue JSONB → `EmailJob` → `PreparedEmail` → MIME) — never as one
/// comma-joined string, which mail-builder 0.3.2's `From<&str>` would wrap
/// into a single angle-bracket mailbox (`<a@x, b@y>`).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Mailbox {
    /// Display name (already RFC 2047-encoded by the transport when set).
    pub name: Option<String>,
    /// Bare address (`local@domain`).
    pub email: String,
}

impl Mailbox {
    /// Parse ONE mailbox from its header string form. Accepts
    /// `local@domain` and `Name <local@domain>` (quoted or unquoted name);
    /// returns `None` when no `@` survives the trim or the value contains
    /// line breaks (header-injection defence).
    pub fn parse(value: &str) -> Option<Self> {
        if value.contains(['\r', '\n']) {
            return None;
        }
        let trimmed = value.trim();
        if let Some((name, addr)) = split_display_name(trimmed) {
            let addr = addr.trim().trim_matches(|c| c == '<' || c == '>').trim();
            if addr.contains('@') && !addr.is_empty() {
                let name = name.trim().trim_matches('"').trim();
                return Some(Self {
                    name: (!name.is_empty()).then(|| name.to_string()),
                    email: addr.to_string(),
                });
            }
            return None;
        }
        if trimmed.contains('@') && !trimmed.is_empty() {
            return Some(Self {
                name: None,
                email: trimmed.to_string(),
            });
        }
        None
    }

    /// Parse a header VALUE that may hold several comma-separated
    /// mailboxes — the LEGACY comma-joined representation stored by older
    /// writers (F26 backfill path: parse, do not re-serialize). Splitting
    /// is QUOTE-AWARE so a display name like `"Doe, Jane"` survives as one
    /// mailbox. Empty segments are skipped; unparsable segments are
    /// dropped (the send-time validation already rejected malformed
    /// recipients, so this is defense in depth for queue rows persisted
    /// before then).
    pub fn parse_list(value: &str) -> Vec<Self> {
        split_mailbox_list(value)
            .into_iter()
            .filter_map(|segment| Mailbox::parse(&segment))
            .filter(|mailbox| !mailbox.email.is_empty())
            .collect()
    }
}

/// Split a comma-separated mailbox list on the commas that are NOT inside
/// a double-quoted display name (RFC 5322 quoted strings may contain
/// commas).
fn split_mailbox_list(value: &str) -> Vec<String> {
    let mut segments = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut escaped = false;
    for ch in value.chars() {
        match ch {
            '\\' if in_quotes => {
                escaped = !escaped;
                current.push(ch);
            }
            '"' if !escaped => {
                in_quotes = !in_quotes;
                current.push(ch);
            }
            ',' if !in_quotes => {
                segments.push(std::mem::take(&mut current));
            }
            _ => {
                escaped = false;
                current.push(ch);
            }
        }
    }
    segments.push(current);
    segments
}

/// Split `Name <addr>` into `(name, <addr>)`, tolerating quoted display
/// names containing commas/angles. Returns `None` for bare addresses.
fn split_display_name(value: &str) -> Option<(String, &str)> {
    let open = value.rfind('<')?;
    let close = value.rfind('>')?;
    if close <= open || !value.ends_with('>') {
        return None;
    }
    let name = value.get(..open)?.trim().to_string();
    let addr = value.get(open..=close)?;
    if addr.contains(['\r', '\n']) || name.contains(['\r', '\n']) {
        return None;
    }
    Some((name, addr))
}

/// Domain configuration for sending.
#[derive(Debug, Clone, FromRow)]
pub struct Domain {
    pub id: String,
    pub tenant_id: String,
    pub domain: String,
    pub dkim_selector: Option<String>,
    /// Canonical DNS `p=` value used to validate the decrypted private key.
    pub dkim_public_key: Option<String>,
    /// Encrypted-at-rest private-key envelope; it is decrypted only while an
    /// SMTP message is being prepared.
    pub dkim_private_key: Option<String>,
    pub warmup_enabled: bool,
    pub warmup_day: i32,
    /// The dedicated source IP whose reputation bounds warmup admission for
    /// this send (the tenant's least-warmed `dedicated_ips` row). `None` when
    /// warmup is disabled (shared pool) — see `WarmupIpIdentity`.
    pub warmup_ip: Option<WarmupIpIdentity>,
    pub return_path: Option<String>,
}

/// The canonical identity of the dedicated IP that carries the warmup
/// reputation boundary for a tenant send. Warmup admission is keyed on the
/// `ip_address` (the reputation boundary is the IP, not the domain).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct WarmupIpIdentity {
    /// `dedicated_ips.id` — the row that owns the warmup state.
    pub dedicated_ip_id: String,
    /// Source IP address (`dedicated_ips.ip_address`).
    pub ip_address: String,
    /// Canonical warmup start (`dedicated_ips.warmup_started_at`).
    pub warmup_started_at: DateTime<Utc>,
}

/// Suppression entry.
#[derive(Debug, Clone)]
pub struct Suppression {
    pub email: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

/// Prepared email ready for sending.
#[derive(Debug, Clone)]
pub struct PreparedEmail {
    pub from: String,
    /// Envelope destination: exactly ONE recipient (the send unit).
    pub to: String,
    /// F26: the ORIGINAL visible MIME `To` mailbox list. Empty falls back to
    /// `to` (legacy single-recipient rows).
    pub mime_to: Vec<Mailbox>,
    /// F26: the ORIGINAL visible MIME `Cc` mailbox list. Bcc intentionally
    /// has no representation here — it lives only in the delivery data.
    pub mime_cc: Vec<Mailbox>,
    /// F26: structured Reply-To mailbox (display-name capable).
    pub reply_to: Option<Mailbox>,
    pub subject: String,
    pub html: Option<String>,
    pub text: Option<String>,
    pub headers: Vec<(String, String)>,
    pub attachments: Vec<Attachment>,
    pub dkim: Option<DkimConfig>,
}

/// Email attachment.
#[derive(Debug, Clone)]
pub struct Attachment {
    pub filename: String,
    pub content: Vec<u8>,
    pub content_type: String,
}

/// DKIM signing configuration.
#[derive(Debug, Clone)]
pub struct DkimConfig {
    pub selector: String,
    pub domain: String,
    pub private_key: Zeroizing<String>,
}

/// Email send result.
#[derive(Debug, Clone)]
pub struct SendResult {
    pub smtp_message_id: Option<String>,
    pub accepted: bool,
    pub response: String,
}

/// Send outcome for error rate tracking.
#[derive(Debug, Clone, Copy)]
pub enum SendOutcome {
    Success,
    SoftBounce,
    HardBounce,
    RateLimit,
    Suppressed,
    /// A locally rejected job, such as a missing or mismatched authorized
    /// domain. These are not transport failures and must not open the SMTP
    /// circuit breaker.
    Rejected,
    TransportError,
}

/// Cached suppression check result.
#[derive(Debug, Clone)]
pub struct CachedSuppression {
    pub suppressed: bool,
    pub reason: Option<String>,
    pub expires_at: std::time::Instant,
}

/// IP rate limit check result.
#[derive(Debug, Clone)]
pub struct RateLimitResult {
    pub allowed: bool,
    pub reason: Option<String>,
    pub current_count: i64,
    pub limit: i64,
    pub retry_after_ms: Option<u64>,
    pub isp: Option<String>,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn mailbox_parses_bare_address() {
        let m = Mailbox::parse("user@example.com").unwrap();
        assert_eq!(m.email, "user@example.com");
        assert!(m.name.is_none());
    }

    #[test]
    fn mailbox_parses_display_name_forms() {
        let m = Mailbox::parse("Jane Doe <jane@example.com>").unwrap();
        assert_eq!(m.email, "jane@example.com");
        assert_eq!(m.name.as_deref(), Some("Jane Doe"));

        let m = Mailbox::parse("\"Doe, Jane\" <jane@example.com>").unwrap();
        assert_eq!(m.email, "jane@example.com");
        assert_eq!(m.name.as_deref(), Some("Doe, Jane"));
    }

    #[test]
    fn mailbox_rejects_malformed() {
        assert!(Mailbox::parse("no-at-sign").is_none());
        assert!(Mailbox::parse("  ").is_none());
        // Header injection attempts are rejected outright.
        assert!(Mailbox::parse("a@b.com\r\nBcc: x@y.z").is_none());
        assert!(Mailbox::parse("Name <a@b.com>\r\nBcc: x@y.z").is_none());
    }

    #[test]
    fn mailbox_list_parses_legacy_comma_joined() {
        let list = Mailbox::parse_list("a@example.com, B <b@example.com>, , c@example.com");
        assert_eq!(list.len(), 3);
        assert_eq!(list[0].email, "a@example.com");
        assert_eq!(list[1].name.as_deref(), Some("B"));
        assert_eq!(list[2].email, "c@example.com");
    }

    #[test]
    fn mailbox_list_parses_quoted_comma_name() {
        let list = Mailbox::parse_list("\"Doe, Jane\" <jane@example.com>, bob@example.com");
        assert_eq!(list.len(), 2);
        assert_eq!(list[0].name.as_deref(), Some("Doe, Jane"));
        assert_eq!(list[1].email, "bob@example.com");
    }
}
