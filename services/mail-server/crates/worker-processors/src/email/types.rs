//! Email processor types.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value as JsonValue;
use sqlx::FromRow;
use zeroize::Zeroizing;

use crate::common::TransportType;

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
    /// The stable logical send identity the SALES queue uses
    /// (`messages.idempotency_key = 'sa-send:{step_execution_id}'`, migration
    /// 200 / `sales_step_executions.id`). `email_queue.sales_step_execution_id`
    /// (migration 202) is the typed provenance column; when present the
    /// acceptance ledger's `send_unit` is `sa-send:{id}`, so a retry of the
    /// same logical send can never submit twice. Non-sales rows fall back to
    /// the queue row id plus recipient (`email_queue:{id}:{recipient}`).
    ///
    /// `serde(default)` keeps deserialization of pre-migration payloads
    /// working (the field is only ever read from a queue row).
    #[serde(default)]
    #[sqlx(rename = "salesStepExecutionId")]
    pub sales_step_execution_id: Option<String>,
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
    /// `domains.ses_verified` — required for a [`DeliveryRoute::SesShared`]
    /// send (SES refuses unverified senders) and deliberately NOT required
    /// for a dedicated relay route, which binds a tenant IP and does not
    /// traverse SES.
    pub ses_verified: bool,
    /// The tenant's dedicated-IP routing candidates, ordered by preference
    /// (warming first, least-warmed first; active/graduated after). `empty`
    /// means the domain rides the shared pool — see `DedicatedIp`.
    pub dedicated_ips: Vec<DedicatedIp>,
    pub return_path: Option<String>,
}

/// One dedicated-IP row eligible for routing: `dedicated_ips.status` in
/// (`warming`, `active`). The routing decision (and the warmup quota) is
/// keyed on the IP, not the sending domain.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct DedicatedIp {
    /// `dedicated_ips.id` — the row that owns the warmup state.
    pub id: String,
    /// Source IP address (`dedicated_ips.ip_address`).
    pub ip_address: String,
    /// True while the row is still warming (`dedicated_ips.status =
    /// 'warming'`): the canonical daily cap is derived from
    /// `warmup_started_at` and `mail_common::warmup`. False for a graduated
    /// (`active`) row — it keeps being routed as dedicated WITHOUT warmup
    /// throttling.
    pub warming: bool,
    /// Canonical warmup start (`dedicated_ips.warmup_started_at`).
    pub warmup_started_at: Option<DateTime<Utc>>,
}

/// Suppression entry.
#[derive(Debug, Clone)]
pub struct Suppression {
    pub email: String,
    pub reason: String,
    pub created_at: DateTime<Utc>,
}

/// VERP v2 binding material for one send unit.
///
/// The v2 token is HMAC-bound to (queue/send id, tenant, recipient, expiry);
/// the recipient is the envelope destination (`PreparedEmail::to`) and this
/// struct carries the two identities only the authenticated job context
/// knows. It is populated from the persisted `EmailJob`, never from caller
/// input, so a caller cannot mint a bounce address for another tenant's
/// message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerpBinding {
    /// `email_queue.id` — the queue row the bounce is attributed to.
    pub queue_id: String,
    /// `email_queue.tenant_id` — the owning tenant.
    pub tenant_id: String,
}

/// Prepared email ready for sending.
#[derive(Debug, Clone)]
pub struct PreparedEmail {
    /// Stable logical send identity for this per-recipient copy — EXACTLY the
    /// `send_unit` the processor reserves on `sales_delivery_acceptances`
    /// (`send_unit_of`: `sa-send:{step_execution_id}` or
    /// `email_queue:{queue row id}:{canonical recipient}`). The outbound MTA
    /// passes it through to `outbound_relay_ledger` (migration 212), whose
    /// PRIMARY KEY is the same value, so a retried submission returns the
    /// stored acceptance instead of delivering a second copy.
    pub send_unit: String,
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
    /// VERP v2 binding (see [`VerpBinding`]); `None` for legacy/prepared
    /// emails without authenticated queue context, which get no VERP
    /// Return-Path (never the unsigned v1 grammar).
    pub verp: Option<VerpBinding>,
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

/// The delivery route selected for ONE send unit — the decision the
/// transport layer must actually execute.
///
/// This is derived by the processor from state it already relies on:
/// * [`Domain::warmup_ip`] — the dedicated-IP identity selected per tenant
///   (its `ip_address` is the reputation boundary the warmup admission
///   reserves capacity on) → [`DeliveryRoute::Dedicated`];
/// * no warming dedicated IP → [`DeliveryRoute::SesShared`] (the shared
///   pool rides platform reputation; there is no per-IP binding to honour).
///
/// The route is NOT a replacement for `EmailJob.metadata` / `Domain::warmup_ip`
/// — it is the derived, per-send value that travels with the send so the
/// admission decision and the network path cannot disagree.
#[derive(Debug, Clone)]
pub enum DeliveryRoute {
    /// AWS SES shared IP pool — no dedicated source IP to bind. The
    /// dedicated-source-IP verification deliberately does NOT apply.
    SesShared,
    /// Self-hosted relay MTA must send from the tenant's dedicated source
    /// IP: `dedicated_ip_id` is `dedicated_ips.id` and `source_ip` is the
    /// parsed `dedicated_ips.ip_address` that warmup admission reserved
    /// capacity against.
    Dedicated {
        dedicated_ip_id: String,
        source_ip: std::net::IpAddr,
    },
}

impl DeliveryRoute {
    /// True for the dedicated-IP route — the only route whose source IP must
    /// be confirmed by the transport before warmup capacity counts as spent.
    pub fn is_dedicated(&self) -> bool {
        matches!(self, Self::Dedicated { .. })
    }

    /// `Some(source_ip)` for [`DeliveryRoute::Dedicated`], `None` for the
    /// shared route.
    pub fn dedicated_source_ip(&self) -> Option<std::net::IpAddr> {
        match self {
            Self::Dedicated { source_ip, .. } => Some(*source_ip),
            Self::SesShared => None,
        }
    }
}

impl std::fmt::Display for DeliveryRoute {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::SesShared => write!(f, "ses-shared"),
            Self::Dedicated {
                dedicated_ip_id,
                source_ip,
            } => write!(f, "dedicated({dedicated_ip_id} @ {source_ip})"),
        }
    }
}

/// What a transport actually did for one [`DeliveryRoute`].
///
/// `actual_source_ip` is the ONLY evidence that a dedicated route was
/// really used: the transport must report the source address the recipient
/// would observe. `None` means "not reported".
///
/// The processor refuses to SUBMIT a dedicated route on a transport that does
/// not declare `supports_source_binding()` (pre-DATA refusal), so by the time
/// a receipt exists the transport contractually knows the bound source IP.
/// A receipt that disagrees with the route is recorded on the acceptance
/// ledger as a contract violation (with a loud alarm) but NEVER turned into a
/// retry: the message may already be externally accepted, and retrying after
/// acceptance is the duplicate risk this contract exists to remove.
#[derive(Debug, Clone)]
pub struct DeliveryReceipt {
    /// Which transport carried the message.
    pub transport: TransportType,
    /// Opaque per-message id when the transport exposes one (SES
    /// `MessageId`; `None` on the SMTP relay path).
    pub transport_message_id: Option<String>,
    /// The recipient-facing source IP the transport actually used, when it
    /// can report it. `None` = not reported (see type docs).
    pub actual_source_ip: Option<std::net::IpAddr>,
    /// Normalized recipient mailbox provider as resolved at delivery time
    /// (e.g. `google_workspace` from the recipient domain's MX records),
    /// when the transport's delivery path actually resolved it.
    ///
    /// `None` = NOT KNOWN on this path. It must never be guessed from the
    /// visible recipient domain here: a custom domain hosted by Google
    /// Workspace is indistinguishable from a self-hosted one without the MX
    /// record (migration 202's rationale). The value is persisted on the
    /// `sent`/`bounced` events rows together with `provider_source`.
    pub recipient_provider: Option<String>,
    /// How `recipient_provider` was obtained — one of `mx_resolved`,
    /// `provider_callback`, or `inferred` (the `events.provider_source`
    /// CHECK constraint, migration
    /// `202_sales_feedback_delivery_binding.sql:154-163`). `None` whenever
    /// `recipient_provider` is `None`.
    pub provider_source: Option<String>,
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
