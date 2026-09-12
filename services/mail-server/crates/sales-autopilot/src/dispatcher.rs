//! Production campaign email dispatcher.
//!
//! # Architecture
//!
//! Campaigns send through the platform's OWN pipeline, not a side channel:
//! this dispatcher enqueues into `messages` + `email_queue` with the exact
//! same statements the REST send path uses
//! (`crates/api-server/src/routes/messages.rs`):
//!
//! * sender-domain resolution (`FOR SHARE` row lock, DKIM-ready + SES/SMTP
//!   transport gate),
//! * quota reservation via `billing_service::usage::record_with_quota_check`
//!   (behind the [`QuotaGateway`] trait so tests can fake it),
//! * `messages` insert with `ON CONFLICT (tenant_id, idempotency_key) DO
//!   NOTHING` and a deterministic key `sacmp:{campaign_id}:{recipient}` —
//!   a crash/restart can never double-send,
//! * `email_queue` insert per recipient (`status='pending'`, `priority=5`),
//!   plus `List-Unsubscribe` / `List-Unsubscribe-Post` custom headers that
//!   the delivery worker passes through to the outgoing message.
//!
//! Rejected alternative (documented in the crate README): a direct SMTP
//! client to the MTA would duplicate DKIM signing, retries, bounce handling
//! and tracking, and would bypass billing quota and ops dashboards.
//!
//! # Bounce / complaint handling
//!
//! The delivery worker writes hard bounces and unsubscribe-reply
//! classifications into the platform `suppressions` table. This dispatcher
//! POLLS: the due-recipient query (see `CampaignManager`) re-checks
//! `suppressions` and `sales_unsubscribes` immediately before every batch,
//! and [`ProductionCampaignDispatcher::enqueue_recipient`] re-checks inside
//! the per-recipient transaction (closing the select→enqueue race). A push
//! mechanism (LISTEN/NOTIFY on `suppressions`) is a future enhancement.

use std::sync::Arc;

use chrono::{DateTime, Utc};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

use crate::campaigns::DispatchRecipient;
use crate::config::DispatchConfig;
use crate::types::SalesError;

// ---------------------------------------------------------------------------
// Quota gateway — thin seam over billing_service::usage
// ---------------------------------------------------------------------------

/// A reserved unit of email quota that can be released again.
#[derive(Debug, Clone)]
pub struct QuotaReservation {
    pub event_id: Uuid,
    pub recorded_at: DateTime<Utc>,
}

/// Reserve/release one unit of email quota for a tenant.
///
/// The production implementation ([`BillingQuotaGateway`]) calls the very
/// same billing functions the REST send path calls; the trait exists so
/// tests (and un-billed deployments) can substitute deterministic fakes.
pub trait QuotaGateway: Send + Sync + std::fmt::Debug {
    fn reserve(&self, tenant_id: &str) -> QuotaFuture<'_, Result<QuotaReservation, SalesError>>;
    fn rollback(
        &self,
        tenant_id: &str,
        reservation: &QuotaReservation,
    ) -> QuotaFuture<'_, Result<(), SalesError>>;
}

/// Boxed future type for [`QuotaGateway`] (keeps the trait object-safe).
pub type QuotaFuture<'a, T> = std::pin::Pin<Box<dyn std::future::Future<Output = T> + Send + 'a>>;

/// Production quota gateway.
///
/// Calls the REAL billing gate — `billing_service::usage::
/// record_with_quota_check` / `rollback_usage_record` — the exact functions
/// api-server's REST send path (crates/api-server/src/routes/messages.rs)
/// uses. (This block used to be a local mirror of those functions, kept
/// only while billing-service did not compile; the mirror's UTC
/// calendar-month counter key diverged from the billing gate's
/// billing-cycle-anchored key, silently doubling the effective email limit
/// for subscribed tenants — audit F1. Depending on the real implementation
/// means one quota gate for the whole platform: anchored counter keys,
/// override-aware plan limits with per-plan builtin fallbacks,
/// `metering_events` persistence, the per-event audit-log append and
/// reservation compensation on failure.)
#[derive(Debug, Clone)]
pub struct BillingQuotaGateway {
    db: PgPool,
    redis: deadpool_redis::Pool,
}

impl BillingQuotaGateway {
    pub fn new(db: PgPool, redis: deadpool_redis::Pool) -> Self {
        Self { db, redis }
    }
}

impl QuotaGateway for BillingQuotaGateway {
    fn reserve(&self, tenant_id: &str) -> QuotaFuture<'_, Result<QuotaReservation, SalesError>> {
        let tenant_id = tenant_id.to_string();
        Box::pin(async move {
            let event_id = Uuid::new_v4();
            let recorded_at = Utc::now();

            // The real billing gate: billing-cycle-anchored counter key,
            // override-aware plan limits (NULL limits fall back to the
            // per-plan builtin seeds — billing_service::usage::
            // resolve_plan_limits / plans::builtin_quota_limits, replacing
            // this crate's old hard-coded 30 000 fallback), atomic
            // check-and-increment reservation, `metering_events` persistence
            // WITH the per-event audit-log append, and compensation when
            // persistence fails. Unknown tenants are denied (limit 0).
            let result = billing_service::usage::record_with_quota_check(
                &self.db,
                &self.redis,
                &tenant_id,
                billing_service::types::MeterEventType::EmailsSent,
                1,
                Some(event_id),
                Some(serde_json::json!({ "source": "sales-autopilot" })),
            )
            .await
            .map_err(|e| {
                tracing::error!(error = %e, tenant_id = %tenant_id, "quota reservation failed");
                SalesError::ServiceUnavailable(
                    "billing quota enforcement is temporarily unavailable".into(),
                )
            })?;

            if !result.allowed {
                // Counter NOT incremented on denial (billing's Lua gate).
                return Err(SalesError::QuotaExhausted(tenant_id));
            }

            Ok(QuotaReservation {
                event_id,
                recorded_at,
            })
        })
    }

    fn rollback(
        &self,
        tenant_id: &str,
        reservation: &QuotaReservation,
    ) -> QuotaFuture<'_, Result<(), SalesError>> {
        let tenant_id = tenant_id.to_string();
        let reservation = reservation.clone();
        Box::pin(async move {
            // The real billing rollback: deletes the metering event, appends
            // the rollback audit record, decrements the anchored counter and
            // drops the dedup key.
            billing_service::usage::rollback_usage_record(
                &self.db,
                &self.redis,
                &tenant_id,
                billing_service::types::MeterEventType::EmailsSent,
                1,
                reservation.event_id,
                reservation.recorded_at,
            )
            .await
            .map_err(|e| {
                SalesError::ServiceUnavailable(format!("failed to release quota reservation: {e}"))
            })
        })
    }
}

// ---------------------------------------------------------------------------
// Unsubscribe tokens
//
// Two generations exist:
//
// * **v2 (current)** — an opaque 32-byte random token, URL-safe base64. Only
//   its SHA-256 hash is persisted (`sales_unsubscribe_tokens`, migration
//   203), so a database/backup leak does not disclose recipient addresses
//   and the URL itself carries no tenant id, no email, and no reversible
//   encoding of either.
// * **v1 (legacy, read-only)** — `v1.{tenant_hex}.{email_hex}.{expiry}.{sig}`.
//   Hex is reversible, so every v1 URL is a portable copy of the recipient
//   address. No new token may be minted with it; the verifier is retained
//   only so links in already-delivered mail keep working for ONE expiry
//   cycle ([`UNSUB_TOKEN_TTL_SECS`], 365 days) after the v2 rollout. Delete
//   the legacy block (and the handler fallback in `routes.rs`) once
//   `Utc::now() > rollout + 365 days` and no v1 signer callers remain —
//   grep for `sign_unsubscribe_token` / `verify_unsubscribe_token` first.
// ---------------------------------------------------------------------------

/// Default token lifetime: 365 days (recipients keep emails a long time).
const UNSUB_TOKEN_TTL_SECS: i64 = 365 * 24 * 3600;

/// Entropy per v2 token. 32 bytes = 256 bits; brute-forcing the hash
/// preimage is not feasible.
const UNSUB_TOKEN_V2_BYTES: usize = 32;

/// URL-safe unpadded base64 length of [`UNSUB_TOKEN_V2_BYTES`].
const UNSUB_TOKEN_V2_LEN: usize = 43;

/// Create an opaque v2 unsubscribe token for (tenant, recipient) and persist
/// ONLY its SHA-256 hash. Returns the public token (the only form that ever
/// leaves this process); the raw token is never written to the database, a
/// log, or an error.
///
/// The recipient address is canonicalized (trim + lowercase) exactly like
/// the suppression stores' canonical form, so a click resolves to the same
/// (tenant, email) pair that would be suppressed.
pub async fn create_unsubscribe_token(
    db: &PgPool,
    tenant_id: &str,
    email: &str,
) -> Result<String, SalesError> {
    use base64::Engine as _;
    use rand::TryRngCore as _;

    let mut raw = [0u8; UNSUB_TOKEN_V2_BYTES];
    rand::rngs::OsRng.try_fill_bytes(&mut raw).map_err(|e| {
        tracing::error!(error = %e, "OsRng failed while generating an unsubscribe token");
        SalesError::ServiceUnavailable("secure randomness unavailable".into())
    })?;

    let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
    let hash = Sha256::digest(raw);
    let expires_at = Utc::now() + chrono::Duration::seconds(UNSUB_TOKEN_TTL_SECS);

    sqlx::query(
        "INSERT INTO sales_unsubscribe_tokens (token_hash, tenant_id, email, expires_at) \
         VALUES ($1, $2, $3, $4) \
         ON CONFLICT (token_hash) DO NOTHING",
    )
    .bind(hash.as_slice())
    .bind(tenant_id.trim())
    .bind(email.trim().to_ascii_lowercase())
    .bind(expires_at)
    .execute(db)
    .await
    .map_err(|e| {
        // The message contains no token material.
        tracing::error!(error = %e, "failed to persist an unsubscribe token");
        SalesError::Database(e.to_string())
    })?;

    Ok(token)
}

/// Decode the URL-safe base64 shape of a v2 token into its raw bytes.
/// `None` for anything that is not exactly a 43-character URL-safe base64
/// string (lengths, padding, and invalid characters are all rejected before
/// any database work).
fn decode_v2_token(token: &str) -> Option<[u8; UNSUB_TOKEN_V2_BYTES]> {
    use base64::Engine as _;

    let token = token.trim();
    if token.len() != UNSUB_TOKEN_V2_LEN {
        return None;
    }
    let decoded = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(token)
        .ok()?;
    decoded.try_into().ok()
}

/// Resolve an opaque v2 token: decode → SHA-256 → look up the persisted hash
/// `WHERE expires_at > now()`. Returns `Ok(None)` for a malformed, unknown,
/// or expired token; a database failure is an `Err` (the caller must not
/// treat it as "no such token" and fall through to the legacy verifier on a
/// transient outage).
///
/// # `used_at` semantics (documented choice)
///
/// The first successful redemption stamps `used_at = NOW()`; later
/// redemptions keep the original timestamp and still resolve. Single-use
/// enforcement is deliberately NOT applied: mail clients and security
/// scanners prefetch `List-Unsubscribe` URLs, and RFC 8058 clients retry,
/// so burning the link on first read would break the actual recipient's
/// click. Suppression itself is idempotent on both stores, so replaying a
/// redeemed token has no additional effect.
pub async fn resolve_unsubscribe_token(
    db: &PgPool,
    token: &str,
) -> Result<Option<UnsubscribeTokenData>, SalesError> {
    let Some(raw) = decode_v2_token(token) else {
        return Ok(None);
    };
    let hash = Sha256::digest(raw);

    // One statement: the UPDATE both marks first use and selects the row.
    let row: Option<(String, String, DateTime<Utc>)> = sqlx::query_as(
        "UPDATE sales_unsubscribe_tokens \
         SET used_at = COALESCE(used_at, NOW()) \
         WHERE token_hash = $1 AND expires_at > NOW() \
         RETURNING tenant_id, email, expires_at",
    )
    .bind(hash.as_slice())
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    Ok(
        row.map(|(tenant_id, email, expires_at)| UnsubscribeTokenData {
            tenant_id,
            email,
            expires_at: expires_at.timestamp(),
        }),
    )
}

/// A verified unsubscribe token's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubscribeTokenData {
    pub tenant_id: String,
    pub email: String,
    pub expires_at: i64,
}

// ── Legacy v1 tokens (read-only compatibility; do not mint) ────────────────

/// Token version prefix; embedded in the signed payload.
const UNSUB_TOKEN_VERSION: &str = "v1";

fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0f) as usize] as char);
    }
    out
}

fn hex_decode(s: &str) -> Option<Vec<u8>> {
    if !s.len().is_multiple_of(2) {
        return None;
    }
    let bytes = s.as_bytes();
    let mut out = Vec::with_capacity(s.len() / 2);
    for pair in bytes.as_chunks::<2>().0 {
        let hi = (pair[0] as char).to_digit(16)?;
        let lo = (pair[1] as char).to_digit(16)?;
        out.push((hi * 16 + lo) as u8);
    }
    Some(out)
}

/// Signed payload: `v1.{tenant_hex}.{email_hex}.{expiry_unix}`.
fn unsub_signed_payload(tenant_hex: &str, email_hex: &str, expires_at: i64) -> String {
    format!("{UNSUB_TOKEN_VERSION}.{tenant_hex}.{email_hex}.{expires_at}")
}

/// **Deprecated (v1)** — the payload hex-encodes the tenant id and recipient
/// address, so the token is a reversible copy of the address. Kept ONLY for
/// the legacy dry-run preview path (`campaigns::legacy_unsubscribe_link`),
/// which never enqueues, and for v1 verification tests. Never call this from
/// a send path: use [`create_unsubscribe_token`] instead.
pub fn sign_unsubscribe_token(
    secret: &str,
    tenant_id: &str,
    email: &str,
    expires_at: i64,
) -> String {
    let payload = unsub_signed_payload(
        &hex_encode(tenant_id.as_bytes()),
        &hex_encode(email.as_bytes()),
        expires_at,
    );
    let sig = apexmail_lib::crypto::create_hmac_signature(secret.as_bytes(), payload.as_bytes());
    format!("{payload}.{sig}")
}

/// **Deprecated (v1, read-only compatibility)** — verifies tokens that were
/// already delivered in email before the v2 rollout. Returns `None` for
/// malformed input, a bad signature (constant-time compare), or an expired
/// token.
///
/// Wire format: `v1.{tenant_hex}.{email_hex}.{expiry_unix}.{sig_hex}` —
/// five dot-separated segments. Remove together with the handler fallback
/// once every v1 token is past its 365-day TTL (see the section comment).
pub fn verify_unsubscribe_token(secret: &str, token: &str) -> Option<UnsubscribeTokenData> {
    let token = token.trim();
    if token.len() < 16 || token.len() > 2048 {
        return None;
    }
    let mut parts = token.split('.');
    let version = parts.next()?;
    let tenant_hex = parts.next()?;
    let email_hex = parts.next()?;
    let expiry_raw = parts.next()?;
    let sig = parts.next()?;
    if parts.next().is_some() || version != UNSUB_TOKEN_VERSION {
        return None;
    }
    if tenant_hex.is_empty() || !(2..=1024).contains(&email_hex.len()) {
        return None;
    }
    let expires_at: i64 = expiry_raw.parse().ok()?;
    if expiry_raw.len() > 12 {
        return None;
    }

    let expected = apexmail_lib::crypto::create_hmac_signature(
        secret.as_bytes(),
        unsub_signed_payload(tenant_hex, email_hex, expires_at).as_bytes(),
    );
    if !apexmail_lib::timing_safe_compare(sig, &expected) {
        return None;
    }
    if Utc::now().timestamp() >= expires_at {
        return None;
    }
    let tenant_id = String::from_utf8(hex_decode(tenant_hex)?).ok()?;
    let email = String::from_utf8(hex_decode(email_hex)?).ok()?;
    if tenant_id.is_empty() || email.is_empty() {
        return None;
    }
    Some(UnsubscribeTokenData {
        tenant_id,
        email,
        expires_at,
    })
}

/// **Deprecated (v1)** — convenience signer expiring
/// [`UNSUB_TOKEN_TTL_SECS`] from now, used only by the legacy dry-run
/// preview path. New sends must use [`create_unsubscribe_token`].
pub fn sign_unsubscribe_token_default_ttl(secret: &str, tenant_id: &str, email: &str) -> String {
    let expires_at = Utc::now().timestamp() + UNSUB_TOKEN_TTL_SECS;
    sign_unsubscribe_token(
        secret,
        tenant_id.trim(),
        &email.trim().to_ascii_lowercase(),
        expires_at,
    )
}

// ---------------------------------------------------------------------------
// Personalization
// ---------------------------------------------------------------------------

/// Lead profile fields interpolated into campaign templates.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct LeadProfile {
    pub name: String,
    pub company: String,
    pub title: String,
}

/// HTML-escape a personalization value before it is interpolated into the
/// subject or HTML body. A lead named `<script>` must never inject markup.
pub fn escape_html(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for ch in value.chars() {
        match ch {
            '&' => out.push_str("&amp;"),
            '<' => out.push_str("&lt;"),
            '>' => out.push_str("&gt;"),
            '"' => out.push_str("&quot;"),
            '\'' => out.push_str("&#39;"),
            _ => out.push(ch),
        }
    }
    out
}

/// Replace `{{placeholder}}` tokens (whitespace-tolerant) with the
/// HTML-escaped value. Unknown placeholders are left untouched so operators
/// can see them in dry-run output.
fn interpolate(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (key, value) in vars {
        let escaped = escape_html(value);
        for pattern in [format!("{{{{{key}}}}}"), format!("{{{{ {key} }}}}")] {
            if out.contains(&pattern) {
                out = out.replace(&pattern, &escaped);
            }
        }
    }
    out
}

/// Interpolate for plain-text parts: no escaping, raw values.
fn interpolate_text(template: &str, vars: &[(&str, &str)]) -> String {
    let mut out = template.to_string();
    for (key, value) in vars {
        for pattern in [format!("{{{{{key}}}}}"), format!("{{{{ {key} }}}}")] {
            if out.contains(&pattern) {
                out = out.replace(&pattern, value);
            }
        }
    }
    out
}

/// Truncate a subject on a char boundary so it always fits the
/// `VARCHAR(255)` subject columns on both schema lineages.
fn truncate_subject(subject: &str) -> String {
    if subject.chars().count() <= 255 {
        return subject.to_string();
    }
    subject.chars().take(255).collect()
}

/// A fully rendered, personalized message ready for enqueue.
#[derive(Debug, Clone)]
pub struct RenderedMessage {
    pub subject: String,
    pub html: Option<String>,
    pub text: Option<String>,
}

/// Why a recipient is receiving this message.
///
/// This exists because the previous footer hardcoded "You are receiving this
/// email because you signed up at ApexMail", which is simply false for cold
/// discovered prospects. Manufacturing consent in a footer is both a
/// deliverability and a legal defect, so the reason is now an explicit input
/// the caller must choose.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FooterReason<'a> {
    /// Cold/business outreach to someone who never signed up. Carries the
    /// lawful-basis description the jurisdiction policy resolved.
    BusinessContact { basis: &'a str },
    /// The recipient opted in or is an existing customer.
    ConsentedRelationship,
    /// A product/account notification to a customer.
    AccountNotification,
}

/// Everything the footer must disclose (CAN-SPAM + ePrivacy Art. 13 style).
#[derive(Debug, Clone)]
pub struct OutreachFooter<'a> {
    /// Who is actually sending: a legal identity, not just a product name.
    pub sender_identity: &'a str,
    pub reason: FooterReason<'a>,
    pub unsubscribe_link: &'a str,
    pub postal_address: Option<&'a str>,
    pub privacy_url: Option<&'a str>,
}

/// Render the truthfulness-aware footer for one outbound sales message.
///
/// Returns `(html, text)`. The caller supplies the reason, and the wording
/// follows from it — the footer can never claim a signup that did not happen.
pub fn render_outreach_footer(footer: &OutreachFooter<'_>) -> (String, String) {
    let mut disclosure = String::new();
    if let Some(address) = footer.postal_address {
        disclosure.push_str(escape_html(address).as_str());
    }
    if let Some(privacy) = footer.privacy_url {
        if !disclosure.is_empty() {
            disclosure.push_str(" &middot; ");
        }
        disclosure.push_str(&format!(
            "<a href=\"{}\" style=\"color:#666\">Privacy</a>",
            escape_html(privacy)
        ));
    }

    let reason_html = match &footer.reason {
        FooterReason::BusinessContact { basis } => format!(
            "We are contacting you as a business contact because {} \
             We are not claiming that you signed up or consented to marketing.",
            escape_html(basis)
        ),
        FooterReason::ConsentedRelationship => {
            "You are receiving this email because you opted in to ApexMail communications."
                .to_string()
        }
        FooterReason::AccountNotification => {
            "You are receiving this email as part of your ApexMail account.".to_string()
        }
    };

    let html = format!(
        "\n<div class=\"apexmail-unsubscribe-footer\" style=\"margin-top:24px;padding-top:12px;border-top:1px solid #eee;font-size:12px;color:#666\">\n  \
         <p>{}<br>{}</p>\n  <p>{} <a href=\"{}\" style=\"color:#666\">Unsubscribe</a></p>\n</div>\n",
        escape_html(footer.sender_identity),
        reason_html,
        if disclosure.is_empty() { String::new() } else { disclosure },
        escape_html(footer.unsubscribe_link),
    );

    let reason_text = match &footer.reason {
        FooterReason::BusinessContact { basis } => format!(
            "We are contacting you as a business contact because {basis} \
             We are not claiming that you signed up or consented to marketing."
        ),
        FooterReason::ConsentedRelationship => {
            "You are receiving this email because you opted in to ApexMail communications."
                .to_string()
        }
        FooterReason::AccountNotification => {
            "You are receiving this email as part of your ApexMail account.".to_string()
        }
    };

    let mut text = format!(
        "\n\n--\n{reason_text}\nUnsubscribe: {}",
        footer.unsubscribe_link
    );
    if let Some(address) = footer.postal_address {
        text.push_str(&format!("\n{address}"));
    }
    if let Some(privacy) = footer.privacy_url {
        text.push_str(&format!("\nPrivacy: {privacy}"));
    }
    text.push('\n');

    (html, text)
}

/// The truthful default footer used when a caller has no policy context yet.
///
/// It describes a business contact rather than claiming a signup, so the
/// mis-statement cannot recur by default.
fn default_footer<'a>(
    recipient: &'a DispatchRecipient,
    sender_name: &'a str,
) -> OutreachFooter<'a> {
    OutreachFooter {
        sender_identity: sender_name,
        reason: FooterReason::BusinessContact {
            basis: "your organisation appears to be a potential fit for ApexMail's email delivery platform.",
        },
        unsubscribe_link: &recipient.unsubscribe_link,
        postal_address: None,
        privacy_url: None,
    }
}

/// Render a template for one recipient: personalization (HTML-escaped) + a
/// truthful CAN-SPAM footer with the unsubscribe link.
///
/// Uses the neutral business-contact footer. Callers with jurisdiction context
/// should use [`render_for_recipient_with_footer`] and pass the disclosure the
/// policy resolved.
pub fn render_for_recipient(
    template: &TemplateContent,
    recipient: &DispatchRecipient,
    sender_name: &str,
) -> Result<RenderedMessage, SalesError> {
    render_for_recipient_with_footer(template, recipient, default_footer(recipient, sender_name))
}

/// Render a template with an explicit, policy-resolved footer.
pub fn render_for_recipient_with_footer(
    template: &TemplateContent,
    recipient: &DispatchRecipient,
    footer: OutreachFooter<'_>,
) -> Result<RenderedMessage, SalesError> {
    let sender_name = footer.sender_identity.to_string();
    let (footer_html, footer_text) = render_outreach_footer(&footer);
    render_with_footer_text(
        template,
        recipient,
        &sender_name,
        &footer_html,
        &footer_text,
    )
}

/// Shared rendering core once the footer bodies are known.
fn render_with_footer_text(
    template: &TemplateContent,
    recipient: &DispatchRecipient,
    sender_name: &str,
    footer_html: &str,
    footer_text: &str,
) -> Result<RenderedMessage, SalesError> {
    let lead = recipient.lead.clone().unwrap_or_default();
    let first_name = lead
        .name
        .split_whitespace()
        .next()
        .unwrap_or_default()
        .to_string();
    let last_name: String = {
        let mut parts = lead.name.split_whitespace();
        parts.next();
        parts.collect::<Vec<_>>().join(" ")
    };
    let vars: Vec<(&str, &str)> = vec![
        ("first_name", first_name.as_str()),
        ("last_name", last_name.as_str()),
        ("name", lead.name.as_str()),
        ("company", lead.company.as_str()),
        ("title", lead.title.as_str()),
        ("email", recipient.email.as_str()),
        ("sender_name", sender_name),
    ];

    if template.html_body.is_none() && template.text_body.is_none() {
        return Err(SalesError::InvalidInput(
            "campaign template has neither an HTML nor a text body".into(),
        ));
    }

    let html = template.html_body.as_deref().map(|body| {
        let rendered = interpolate(body, &vars);
        // Insert before </body> when present; otherwise append.
        match rendered.rfind("</body>") {
            Some(pos) => format!("{}{}{}", &rendered[..pos], footer_html, &rendered[pos..]),
            None => format!("{rendered}{footer_html}"),
        }
    });
    let text = template
        .text_body
        .as_deref()
        .map(|body| format!("{}{}", interpolate_text(body, &vars), footer_text));

    Ok(RenderedMessage {
        subject: truncate_subject(&interpolate(&template.subject, &vars)),
        html,
        text,
    })
}

// ---------------------------------------------------------------------------
// Template fetch
// ---------------------------------------------------------------------------

/// Raw template content fetched from the platform `templates` table.
#[derive(Debug, Clone)]
pub struct TemplateContent {
    pub subject: String,
    pub html_body: Option<String>,
    pub text_body: Option<String>,
}

/// Fetch a template by id or slug for a tenant (canonical templates shape:
/// VARCHAR(26) ids, versioned subject/html_body/text_body).
pub async fn fetch_template(
    db: &PgPool,
    tenant_id: &str,
    template_id: &str,
) -> Result<TemplateContent, SalesError> {
    let row: Option<(String, Option<String>, Option<String>)> = sqlx::query_as(
        "SELECT subject, html_body, text_body FROM templates \
         WHERE tenant_id = $1 AND (id = $2 OR slug = $2) \
         ORDER BY version DESC LIMIT 1",
    )
    .bind(tenant_id)
    .bind(template_id)
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;

    match row {
        Some((subject, html_body, text_body)) => Ok(TemplateContent {
            subject,
            html_body,
            text_body,
        }),
        None => Err(SalesError::InvalidInput(format!(
            "campaign template '{template_id}' not found for tenant"
        ))),
    }
}

// ---------------------------------------------------------------------------
// Sender-domain resolution (mirrors api-server messages.rs)
// ---------------------------------------------------------------------------

/// SES/SMTP transport gate — identical semantics to
/// `api-server::config::Config::ses_transport_enabled` (read at call time so
/// deployments behave the same as the REST path).
fn ses_transport_enabled() -> bool {
    apexmail_lib::transport::email_transport_is_ses(
        std::env::var("EMAIL_TRANSPORT_TYPE").ok().as_deref(),
    )
}

fn sender_domain(from: &str) -> Option<String> {
    from.rsplit_once('@')
        .map(|(_, domain)| domain.trim().trim_end_matches('.').to_ascii_lowercase())
        .filter(|domain| !domain.is_empty())
}

/// Resolve the ready `domains.id` for the sender domain while holding a row
/// lock through queue insertion — the exact SQL from api-server's
/// `resolve_sender_domain_id` (closes the check-then-enqueue race where a
/// domain could be disabled between validation and enqueue).
async fn resolve_sender_domain_id(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: &str,
    from: &str,
) -> Result<Option<String>, sqlx::Error> {
    let Some(sender_domain) = sender_domain(from) else {
        return Ok(None);
    };
    sqlx::query_scalar(
        "SELECT id::text FROM domains
                 WHERE tenant_id = $1 AND name = $2 AND status = 'verified'
                     AND dkim_enabled = true
                     AND dkim_selector IS NOT NULL AND dkim_public_key IS NOT NULL AND dkim_private_key IS NOT NULL
                           AND dkim_private_key LIKE 'dkim:v1:%'
                     AND ($3::boolean = false OR ses_verified = true)
                 LIMIT 1 FOR SHARE",
    )
    .bind(tenant_id)
    .bind(&sender_domain)
    .bind(ses_transport_enabled())
    .fetch_optional(&mut **tx)
    .await
}

/// Lock-free variant for validation/dry-run (no enqueue follows).
pub async fn sender_domain_ready(
    db: &PgPool,
    tenant_id: &str,
    from: &str,
) -> Result<bool, SalesError> {
    let Some(sender_domain) = sender_domain(from) else {
        return Ok(false);
    };
    let exists: Option<String> = sqlx::query_scalar(
        "SELECT id::text FROM domains
                 WHERE tenant_id = $1 AND name = $2 AND status = 'verified'
                     AND dkim_enabled = true
                     AND dkim_selector IS NOT NULL AND dkim_public_key IS NOT NULL AND dkim_private_key IS NOT NULL
                       AND dkim_private_key LIKE 'dkim:v1:%'
                     AND ($3::boolean = false OR ses_verified = true)
                 LIMIT 1",
    )
    .bind(tenant_id)
    .bind(&sender_domain)
    .bind(ses_transport_enabled())
    .fetch_optional(db)
    .await
    .map_err(|e| SalesError::Database(e.to_string()))?;
    Ok(exists.is_some())
}

// ---------------------------------------------------------------------------
// Production dispatcher
// ---------------------------------------------------------------------------

/// The identity of one logical outbound send.
///
/// The old key was `campaign_idempotency_key(campaign_id, recipient_email)`
/// → `sacmp:{campaign}:{recipient}`. That is a *dedupe* key, not an identity:
/// as soon as a campaign (or a sequence) legitimately sends a second email to
/// the same recipient, the second send collides with the first and is silently
/// dropped. The unit of idempotency has to be the logical step execution.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SendIdentity<'a> {
    /// One send of one step of one enrollment. This is the canonical identity
    /// for sequence mail: `sa:{enrollment}:{version}:{step}:{attempt_kind}:{variant}`.
    StepExecution {
        enrollment_id: Uuid,
        sequence_version_id: Uuid,
        step_id: Uuid,
        attempt_kind: &'a str,
        variant: &'a str,
    },
    /// One send per recipient per campaign. Correct ONLY for a single-touch
    /// campaign; a multi-touch campaign must use [`SendIdentity::StepExecution`]
    /// or its later touches will be deduped away.
    CampaignRecipient {
        campaign_id: Uuid,
        recipient_email: &'a str,
    },
}

/// Compute the idempotency key for one logical send.
///
/// Resolution order matters: a step execution always wins, because that is the
/// identity that makes a second legitimate touch representable.
pub fn send_idempotency_key(identity: SendIdentity<'_>) -> String {
    match identity {
        SendIdentity::StepExecution {
            enrollment_id,
            sequence_version_id,
            step_id,
            attempt_kind,
            variant,
        } => crate::sequences::sales_step_idempotency_key(
            enrollment_id,
            sequence_version_id,
            step_id,
            attempt_kind,
            variant,
        ),
        SendIdentity::CampaignRecipient {
            campaign_id,
            recipient_email,
        } => {
            // Bound the key length: messages.idempotency_key is VARCHAR(255).
            // The fixed prefix + campaign uuid leave ~200 chars for the
            // recipient.
            let recipient = truncate_bytes(recipient_email.trim().to_ascii_lowercase(), 200);
            format!("sacmp:{campaign_id}:{recipient}")
        }
    }
}

/// Legacy (campaign, recipient) key.
///
/// Retained for the single-touch campaign path only. New multi-touch work must
/// build its key from [`SendIdentity::StepExecution`], otherwise the second
/// email to a recipient inside the same campaign is silently suppressed.
pub fn campaign_idempotency_key(campaign_id: Uuid, recipient_email: &str) -> String {
    send_idempotency_key(SendIdentity::CampaignRecipient {
        campaign_id,
        recipient_email,
    })
}

fn truncate_bytes(s: String, max: usize) -> String {
    if s.len() <= max {
        return s;
    }
    let mut end = max;
    while end > 0 && !s.is_char_boundary(end) {
        end -= 1;
    }
    s[..end].to_string()
}

/// Outcome of enqueueing one recipient.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EnqueueOutcome {
    /// Rows inserted into `messages` + `email_queue`; ledger stamped.
    Enqueued,
    /// Another dispatcher claimed the ledger row concurrently — skipped.
    AlreadyClaimed,
    /// The (campaign, recipient) idempotency key already existed — a prior
    /// attempt (or an older code path that stamped the ledger first) already
    /// enqueued this recipient; nothing sent again.
    DuplicateIdempotency,
    /// The worker no longer holds the action lease (recovered by another
    /// process, expired, or the action left `executing`). This is the
    /// ANTI-DUPLICATE GUARD: the stale worker produced NO external effect —
    /// nothing was inserted into `messages` or `email_queue` — and the
    /// recovered worker owns the retry.
    LeaseLost,
}

/// `email_queue` insert for campaign mail. `campaign_id` is set on the COLUMN
/// (not just metadata) so the delivery worker attributes every event it
/// records (sent/bounced) back to the campaign — see D.
const CAMPAIGN_EMAIL_QUEUE_INSERT_SQL: &str = r#"
            INSERT INTO email_queue (
                id, message_id, tenant_id, domain_id, campaign_id, from_address, to_addresses, subject,
                "from", "to", html, text, tags, metadata, headers, scheduled_at, priority, status, created_at, updated_at
             ) VALUES (
                $1::uuid, $2::uuid, $3, $4::uuid, $5::uuid, $6, ARRAY[$7], $8,
                $6, $7, $9, $10, $11, $12, $13, $14, 5, 'pending', $15, $15
             )
        "#;

/// `messages` insert for a sequenced (autonomous/worker) send.
///
/// The four typed provenance columns added by migration 202
/// (`sales_decision_id`, `sales_sender_identity_id`, `sales_step_execution_id`,
/// `sales_enrollment_id`) are written on the ROW itself, so a feedback
/// consumer can attribute a bounce/complaint/reply without parsing JSON
/// metadata at delivery speed. Parameterized (`$16`..`$19`), never
/// interpolated. Idempotency is unchanged: `ON CONFLICT (tenant_id,
/// idempotency_key) DO NOTHING` still collapses a duplicate logical send.
const SEQUENCE_MESSAGES_INSERT_SQL: &str = r#"
            INSERT INTO messages (
                id, tenant_id, from_email, to_emails, cc_emails, bcc_emails,
                subject, html_body, text_body, status, tags, metadata,
                scheduled_at, created_at, idempotency_key,
                sales_decision_id, sales_sender_identity_id,
                sales_step_execution_id, sales_enrollment_id
             ) VALUES (
                $1::uuid, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12,
                $13, $14, $15,
                $16::uuid, $17::uuid, $18::uuid, $19::uuid
             )
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING
        "#;

/// `email_queue` insert for a sequenced send: the same four typed provenance
/// columns as [`SEQUENCE_MESSAGES_INSERT_SQL`], so delivery events are
/// attributable at the queue row too. `campaign_id` stays NULL — sequence mail
/// is attributed to a step execution, not a campaign.
const SEQUENCE_EMAIL_QUEUE_INSERT_SQL: &str = r#"
            INSERT INTO email_queue (
                id, message_id, tenant_id, domain_id, campaign_id, from_address, to_addresses, subject,
                "from", "to", html, text, tags, metadata, headers, scheduled_at, priority, status, created_at, updated_at,
                sales_decision_id, sales_sender_identity_id,
                sales_step_execution_id, sales_enrollment_id
             ) VALUES (
                $1::uuid, $2::uuid, $3, $4::uuid, NULL, $5, ARRAY[$6], $7,
                $5, $6, $8, $9, $10, $11, $12, $13, 5, 'pending', $13, $13,
                $14::uuid, $15::uuid, $16::uuid, $17::uuid
             )
        "#;

/// Statement order inside the sequenced-send transaction: the lease fence is
/// deliberately FIRST — before either insert — so a stale worker aborts with
/// no external effect. Test-only data so the ordering is asserted in tests;
/// the implementation below follows it literally.
#[cfg(test)]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SequencedTxStep {
    VerifyActionLeaseFence,
    InsertMessages,
    InsertEmailQueue,
}

#[cfg(test)]
const SEQUENCED_TX_ORDER: [SequencedTxStep; 3] = [
    SequencedTxStep::VerifyActionLeaseFence,
    SequencedTxStep::InsertMessages,
    SequencedTxStep::InsertEmailQueue,
];

/// The envelope identity of one sequenced send.
#[derive(Debug, Clone, PartialEq, Eq)]
struct SequencedEnvelope {
    from_email: String,
    from_name: String,
}

/// Derive the envelope identity for a sequenced send.
///
/// The sender is ALWAYS the resolved identity (`sender.from_email`). The
/// deployment-wide `DispatchConfig::from_email`
/// (`SALES_CAMPAIGN_FROM_EMAIL`) is deliberately not consulted here: it is the
/// legacy campaign/manual-reply default, and using it for autonomous sequence
/// mail is exactly the defect this path exists to fix. The config only
/// supplies a display-name fallback when the identity sets no `from_name`.
///
/// Pure so the "send from the resolved identity, never the config" rule is
/// unit-testable without a database.
fn sequenced_envelope(
    sender: &crate::types::SenderIdentity,
    cfg: &DispatchConfig,
) -> SequencedEnvelope {
    SequencedEnvelope {
        from_email: sender.from_email.clone(),
        from_name: sender.display_name(&cfg.from_name),
    }
}

/// Refuse a sequenced send whose sender is not a real sales identity for the
/// requesting tenant.
///
/// The pool-isolation resolver (`crate::sender_pool`) already enforces both
/// rules; this is a second, cheap gate at the send site so a caller cannot
/// hand the dispatcher a transactional-pool or cross-tenant identity.
fn ensure_sequenced_sender(
    sender: &crate::types::SenderIdentity,
    tenant_id: &str,
) -> Result<(), SalesError> {
    crate::sender_pool::ensure_sales_pool(sender.pool)?;
    if sender.tenant_id != tenant_id {
        return Err(SalesError::PolicyDenied(format!(
            "sender identity {} belongs to tenant '{}', not '{tenant_id}'; refusing to send",
            sender.id, sender.tenant_id
        )));
    }
    Ok(())
}

/// The production dispatcher: enqueues campaign mail through the platform's
/// own pipeline (messages + email_queue), mirroring api-server's REST send.
#[derive(Debug, Clone)]
pub struct ProductionCampaignDispatcher {
    db: PgPool,
    quota: Arc<dyn QuotaGateway>,
    cfg: DispatchConfig,
}

impl ProductionCampaignDispatcher {
    /// Construct the production dispatcher. Fails unless the mandatory
    /// configuration is present — an unconfigured deployment must NOT get a
    /// half-working dispatcher (campaign start stays 503).
    pub fn new(
        cfg: DispatchConfig,
        db: PgPool,
        quota: Arc<dyn QuotaGateway>,
    ) -> anyhow::Result<Self> {
        if !cfg.is_configured() {
            anyhow::bail!(
                "production campaign dispatcher requires SALES_CAMPAIGN_FROM_EMAIL (valid \
                 address) and SALES_UNSUBSCRIBE_SECRET (>= 32 chars)"
            );
        }
        Ok(Self {
            db,
            quota,
            cfg: DispatchConfig {
                from_email: cfg.from_email.trim().to_string(),
                ..cfg
            },
        })
    }

    pub fn config(&self) -> &DispatchConfig {
        &self.cfg
    }

    /// Suppress (tenant, recipient) in both suppression stores. Used by the
    /// unsubscribe endpoint; also the bounce/complaint mechanism mirror.
    pub async fn suppress(
        db: &PgPool,
        tenant_id: &str,
        email: &str,
        source: &str,
    ) -> Result<(), SalesError> {
        let normalized = email.trim().to_ascii_lowercase();
        sqlx::query(
            "INSERT INTO sales_unsubscribes (tenant_id, email, created_at) \
             VALUES ($1, $2, NOW()) ON CONFLICT (tenant_id, email) DO NOTHING",
        )
        .bind(tenant_id)
        .bind(&normalized)
        .execute(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        // Mirror into the platform-wide suppression table so the REST send
        // path excludes this recipient too. Best-effort: the platform table
        // has an FK on tenant_id; a tenant unknown to the platform keeps at
        // least the sales-side suppression.
        let inserted = sqlx::query(
            "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at) \
             VALUES ($1, $2, $3, 'unsubscribe', $4, NOW()) \
             ON CONFLICT (tenant_id, email) DO NOTHING",
        )
        .bind(apexmail_lib::id::generate_id("sup", 22))
        .bind(tenant_id)
        .bind(&normalized)
        .bind(source)
        .execute(db)
        .await;

        match inserted {
            Ok(_) => Ok(()),
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    tenant_id = %tenant_id,
                    email = %normalized,
                    "platform suppression mirror failed (sales-side suppression still active)"
                );
                Ok(())
            }
        }
    }

    /// Enqueue ONE recipient. Steps 2–5 of the README pipeline run in a
    /// single transaction; the quota reservation is released on any failure
    /// path that does not enqueue.
    #[allow(clippy::too_many_arguments)]
    pub async fn enqueue_recipient(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        rendered: &RenderedMessage,
        recipient_email: &str,
        unsubscribe_link: &str,
    ) -> Result<EnqueueOutcome, SalesError> {
        // 1. Quota reservation (outside the enqueue transaction, exactly like
        //    the REST path — rolled back on every non-enqueue exit).
        let reservation = self.quota.reserve(tenant_id).await?;

        let outcome = self
            .enqueue_recipient_tx(
                tenant_id,
                campaign_id,
                rendered,
                recipient_email,
                unsubscribe_link,
                &reservation,
            )
            .await;

        match &outcome {
            Ok(EnqueueOutcome::Enqueued) => {}
            // `LeaseLost` is unreachable on the campaign path (no action lease
            // is involved) but is handled as a no-send so the reservation is
            // always released when nothing was enqueued.
            Ok(EnqueueOutcome::AlreadyClaimed)
            | Ok(EnqueueOutcome::DuplicateIdempotency)
            | Ok(EnqueueOutcome::LeaseLost) => {
                // Nothing will be delivered for this reservation — release it.
                if let Err(e) = self.quota.rollback(tenant_id, &reservation).await {
                    tracing::error!(error = %e, tenant_id = %tenant_id, "failed to release quota for skipped recipient");
                }
            }
            Err(_) => {
                if let Err(e) = self.quota.rollback(tenant_id, &reservation).await {
                    tracing::error!(error = %e, tenant_id = %tenant_id, "failed to roll back quota after enqueue failure");
                }
            }
        }

        outcome
    }

    #[allow(clippy::too_many_arguments)]
    async fn enqueue_recipient_tx(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        rendered: &RenderedMessage,
        recipient_email: &str,
        unsubscribe_link: &str,
        reservation: &QuotaReservation,
    ) -> Result<EnqueueOutcome, SalesError> {
        let message_id = Uuid::new_v4();
        let created_at = Utc::now();
        // LEGACY PATH (the audit intends to retire it): campaign mail still
        // sends from the deployment-wide SALES_CAMPAIGN_FROM_EMAIL. New
        // autonomous/sequence mail must name the resolved sender identity
        // instead — see `enqueue_sequenced`.
        let from = self.cfg.from_email.clone();
        let idempotency_key = campaign_idempotency_key(campaign_id, recipient_email);

        let metadata = serde_json::json!({
            "source": "sales-autopilot",
            "campaign_id": campaign_id.to_string(),
            "sales_tenant_id": tenant_id,
            "from_name": self.cfg.from_name,
            "quota_event_id": reservation.event_id.to_string(),
        });
        let headers = serde_json::json!({
            // RFC 2369 angle-bracket form; the delivery worker forwards
            // non-protected custom headers to the outgoing message.
            "List-Unsubscribe": format!("<{unsubscribe_link}>"),
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        });
        let tags = vec!["sales-campaign".to_string()];

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        // Pre-recipient suppression re-check inside the transaction: a
        // bounce/complaint that landed between the batch select and now is
        // still honoured (mission: re-check suppressions before each send).
        let still_eligible: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (\
                SELECT 1 FROM sales_unsubscribes u \
                WHERE u.tenant_id = $1 AND u.email = LOWER($2)\
             ) AND NOT EXISTS (\
                SELECT 1 FROM suppressions s \
                WHERE s.tenant_id = $1 AND LOWER(s.email) = LOWER($2)\
             )",
        )
        .bind(tenant_id)
        .bind(recipient_email)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if !still_eligible {
            return Ok(EnqueueOutcome::AlreadyClaimed);
        }

        // Sender-domain resolution with a row lock held through the queue
        // insert (mirrors messages.rs resolve_sender_domain_id).
        let domain_id = resolve_sender_domain_id(&mut tx, tenant_id, &from)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?
            .ok_or_else(|| {
                SalesError::InvalidInput(format!(
                    "sender domain '{}' is not ready for the configured delivery transport",
                    from.rsplit_once('@').map(|(_, d)| d).unwrap_or(&from)
                ))
            })?;

        // 2. Send-ledger claim: atomic against concurrent dispatchers.
        let claimed: Option<(String,)> = sqlx::query_as(
            "UPDATE sales_campaign_recipients \
             SET sent_at = NOW(), message_id = $3 \
             WHERE campaign_id = $1 AND email = $2 AND sent_at IS NULL \
             RETURNING email",
        )
        .bind(campaign_id)
        .bind(recipient_email)
        .bind(message_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        if claimed.is_none() {
            return Ok(EnqueueOutcome::AlreadyClaimed);
        }

        // 3. `messages` insert with idempotency (same statement as the REST
        //    path, key = sacmp:{campaign}:{recipient}).
        let result = sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails,
             subject, html_body, text_body, status, tags, metadata, scheduled_at, created_at, idempotency_key)
             VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
        )
        .bind(message_id)
        .bind(tenant_id)
        .bind(&from)
        .bind(serde_json::json!([recipient_email]))
        .bind(None::<serde_json::Value>)
        .bind(None::<serde_json::Value>)
        .bind(&rendered.subject)
        .bind(&rendered.html)
        .bind(&rendered.text)
        .bind("queued")
        .bind(serde_json::json!(tags))
        .bind(&metadata)
        .bind(None::<DateTime<Utc>>)
        .bind(created_at)
        .bind(&idempotency_key)
        .execute(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            // Idempotent duplicate: this (campaign, recipient) was already
            // enqueued by a prior attempt — never double-send. Commit the
            // ledger claim so the recipient is not retried forever (the
            // `sent` counter was already incremented by the original attempt).
            tracing::warn!(
                tenant_id = %tenant_id,
                campaign_id = %campaign_id,
                recipient = %recipient_email,
                "campaign send skipped: idempotency key already enqueued"
            );
            tx.commit()
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
            return Ok(EnqueueOutcome::DuplicateIdempotency);
        }

        // 4. `email_queue` insert (single-recipient row, mirrors the REST
        //    per-recipient loop). `campaign_id` is set on the COLUMN (not
        //    just metadata): the delivery worker reads
        //    email_queue.campaign_id into every events row it records
        //    (sent/bounced), which is what attributes engagement and bounce
        //    side effects back to this campaign.
        sqlx::query(CAMPAIGN_EMAIL_QUEUE_INSERT_SQL)
            .bind(Uuid::new_v4())
            .bind(message_id)
            .bind(tenant_id)
            .bind(&domain_id)
            .bind(campaign_id)
            .bind(&from)
            .bind(recipient_email)
            .bind(&rendered.subject)
            .bind(&rendered.html)
            .bind(&rendered.text)
            .bind(&tags)
            .bind(&metadata)
            .bind(&headers)
            .bind(None::<DateTime<Utc>>)
            .bind(created_at)
            .execute(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        // 5. Campaign send counter — same transaction.
        sqlx::query("UPDATE sales_campaigns SET sent = sent + 1 WHERE id = $1")
            .bind(campaign_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        metrics::counter!("sales_campaign_dispatch_enqueued_total").increment(1);
        Ok(EnqueueOutcome::Enqueued)
    }

    /// Enqueue ONE sequence step execution.
    ///
    /// This is the canonical send path for sequence mail. It differs from
    /// [`Self::enqueue_recipient`] in three ways that matter:
    ///
    /// 1. **The envelope sender is the RESOLVED `sender` identity**
    ///    (`sender.from_email`), never the deployment-wide
    ///    `SALES_CAMPAIGN_FROM_EMAIL` (`DispatchConfig::from_email`).
    ///    `SALES_CAMPAIGN_FROM_EMAIL` remains only for the legacy campaign and
    ///    manual-reply paths; a sequenced/autonomous send must name the
    ///    identity it sends from, or the message's domain/DKIM/health
    ///    attribution is a lie.
    /// 2. The send identity is the caller's logical step execution (see
    ///    [`SendIdentity::StepExecution`]), not `(campaign, recipient)`, so a
    ///    later legitimate touch to the same person is a different message
    ///    rather than a suppressed duplicate.
    /// 3. It is fenced: the caller passes the [`crate::actions::ActionFence`]
    ///    of the claimed action, and the fence is verified inside the enqueue
    ///    transaction BEFORE any insert. A worker whose lease was recovered
    ///    returns [`EnqueueOutcome::LeaseLost`] and enqueues nothing.
    ///
    /// The caller (the action worker) has already claimed the
    /// `sales_step_executions` row, so that row — not a campaign ledger — is
    /// the send ledger. Suppression is still re-checked inside the transaction,
    /// because an unsubscribe that landed between the decision and this send
    /// must win.
    #[allow(clippy::too_many_arguments)]
    pub async fn enqueue_sequenced(
        &self,
        tenant_id: &str,
        idempotency_key: &str,
        rendered: &RenderedMessage,
        recipient_email: &str,
        unsubscribe_link: &str,
        sender: &crate::types::SenderIdentity,
        decision_id: Uuid,
        step_execution_id: Uuid,
        enrollment_id: Uuid,
        action_fence: &crate::actions::ActionFence,
        metadata_extra: serde_json::Value,
    ) -> Result<EnqueueOutcome, SalesError> {
        // The sender must be a real sales identity for THIS tenant: the
        // resolver (`sender_pool`) already enforces this, but the dispatcher
        // refuses again rather than trusting an arbitrary caller.
        ensure_sequenced_sender(sender, tenant_id)?;

        let reservation = self.quota.reserve(tenant_id).await?;

        let outcome = self
            .enqueue_sequenced_tx(
                tenant_id,
                idempotency_key,
                rendered,
                recipient_email,
                unsubscribe_link,
                sender,
                decision_id,
                step_execution_id,
                enrollment_id,
                action_fence,
                metadata_extra,
                &reservation,
            )
            .await;

        match &outcome {
            Ok(EnqueueOutcome::Enqueued) => {}
            Ok(EnqueueOutcome::AlreadyClaimed)
            | Ok(EnqueueOutcome::DuplicateIdempotency)
            | Ok(EnqueueOutcome::LeaseLost) => {
                // Nothing will be delivered for this reservation — release it.
                // LeaseLost in particular aborts before any insert, so the
                // reservation bought nothing.
                if let Err(e) = self.quota.rollback(tenant_id, &reservation).await {
                    tracing::error!(error = %e, tenant_id = %tenant_id, "failed to release quota for skipped step send");
                }
            }
            Err(_) => {
                if let Err(e) = self.quota.rollback(tenant_id, &reservation).await {
                    tracing::error!(error = %e, tenant_id = %tenant_id, "failed to roll back quota after step send failure");
                }
            }
        }

        outcome
    }

    #[allow(clippy::too_many_arguments)]
    async fn enqueue_sequenced_tx(
        &self,
        tenant_id: &str,
        idempotency_key: &str,
        rendered: &RenderedMessage,
        recipient_email: &str,
        unsubscribe_link: &str,
        sender: &crate::types::SenderIdentity,
        decision_id: Uuid,
        step_execution_id: Uuid,
        enrollment_id: Uuid,
        action_fence: &crate::actions::ActionFence,
        metadata_extra: serde_json::Value,
        reservation: &QuotaReservation,
    ) -> Result<EnqueueOutcome, SalesError> {
        let message_id = Uuid::new_v4();
        let created_at = Utc::now();
        // The envelope identity is the resolved sender, never the legacy
        // deployment-wide default (see the method doc comment).
        let envelope = sequenced_envelope(sender, &self.cfg);
        let from = envelope.from_email.clone();

        let mut metadata = serde_json::json!({
            "source": "sales-autopilot",
            "sales_tenant_id": tenant_id,
            "from_name": envelope.from_name,
            "quota_event_id": reservation.event_id.to_string(),
            // Belt and braces: the typed columns below are authoritative, but
            // the same provenance is also visible in metadata for consumers
            // that only read JSON.
            "sales_decision_id": decision_id.to_string(),
            "sales_sender_identity_id": sender.id.to_string(),
            "sales_sender_pool": sender.pool.as_str(),
            "sales_sender_source_ip": sender.source_ip.map(|ip| ip.to_string()),
        });
        if let (Some(base), Some(extra)) = (metadata.as_object_mut(), metadata_extra.as_object()) {
            for (key, value) in extra {
                base.insert(key.clone(), value.clone());
            }
        }
        let headers = serde_json::json!({
            "List-Unsubscribe": format!("<{unsubscribe_link}>"),
            "List-Unsubscribe-Post": "List-Unsubscribe=One-Click",
        });
        let tags = vec!["sales-sequence".to_string()];

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        // STEP 1: execution fence, BEFORE any insert.
        // `verify_fence_in_tx` takes `FOR SHARE` on the sales_actions row, so
        // the lease cannot be recovered by another worker while this
        // transaction (and therefore the external effect) is being produced.
        // No row → the worker no longer owns the action: abort with NO
        // external effect. Dropping `tx` rolls back; nothing was written.
        if !crate::actions::verify_fence_in_tx(&mut tx, action_fence).await? {
            tracing::warn!(
                action_id = %action_fence.action_id,
                tenant_id = %tenant_id,
                recipient = %recipient_email,
                "sequence step send refused: action lease fence is stale (work recovered by another worker)"
            );
            metrics::counter!("sales_sequence_send_lease_lost_total").increment(1);
            return Ok(EnqueueOutcome::LeaseLost);
        }

        // Re-check suppression inside the transaction: a bounce, complaint or
        // unsubscribe that arrived between the decision and now is honored.
        let still_eligible: bool = sqlx::query_scalar(
            "SELECT NOT EXISTS (\
                SELECT 1 FROM sales_unsubscribes u \
                WHERE u.tenant_id = $1 AND u.email = LOWER($2)\
             ) AND NOT EXISTS (\
                SELECT 1 FROM suppressions s \
                WHERE s.tenant_id = $1 AND LOWER(s.email) = LOWER($2)\
             )",
        )
        .bind(tenant_id)
        .bind(recipient_email)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if !still_eligible {
            return Ok(EnqueueOutcome::AlreadyClaimed);
        }

        let domain_id = resolve_sender_domain_id(&mut tx, tenant_id, &from)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?
            .ok_or_else(|| {
                SalesError::InvalidInput(format!(
                    "sender domain '{}' is not ready for the configured delivery transport",
                    from.rsplit_once('@').map(|(_, d)| d).unwrap_or(&from)
                ))
            })?;

        // STEP 2: `messages` insert with the typed sales provenance columns
        // and idempotency preserved.
        let result = sqlx::query(SEQUENCE_MESSAGES_INSERT_SQL)
            .bind(message_id)
            .bind(tenant_id)
            .bind(&from)
            .bind(serde_json::json!([recipient_email]))
            .bind(None::<serde_json::Value>)
            .bind(None::<serde_json::Value>)
            .bind(&rendered.subject)
            .bind(&rendered.html)
            .bind(&rendered.text)
            .bind("queued")
            .bind(serde_json::json!(tags))
            .bind(&metadata)
            .bind(None::<DateTime<Utc>>)
            .bind(created_at)
            .bind(idempotency_key)
            .bind(decision_id)
            .bind(sender.id)
            .bind(step_execution_id)
            .bind(enrollment_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            // This logical step execution was already enqueued. Never send it
            // twice; a replay of the action is a no-op.
            tracing::warn!(
                tenant_id = %tenant_id,
                recipient = %recipient_email,
                idempotency_key = %idempotency_key,
                "sequence step send skipped: idempotency key already enqueued"
            );
            tx.commit()
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
            return Ok(EnqueueOutcome::DuplicateIdempotency);
        }

        // STEP 3: `email_queue` insert, same four typed provenance columns.
        // campaign_id is NULL: sequence mail is attributed to a step
        // execution, not to a campaign.
        sqlx::query(SEQUENCE_EMAIL_QUEUE_INSERT_SQL)
            .bind(Uuid::new_v4())
            .bind(message_id)
            .bind(tenant_id)
            .bind(&domain_id)
            .bind(&from)
            .bind(recipient_email)
            .bind(&rendered.subject)
            .bind(&rendered.html)
            .bind(&rendered.text)
            .bind(&tags)
            .bind(&metadata)
            .bind(&headers)
            .bind(created_at)
            .bind(decision_id)
            .bind(sender.id)
            .bind(step_execution_id)
            .bind(enrollment_id)
            .execute(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        metrics::counter!("sales_sequence_send_enqueued_total").increment(1);
        Ok(EnqueueOutcome::Enqueued)
    }

    /// Core batch dispatch shared by the trait method and the scheduler.
    pub async fn dispatch_batch(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        template_id: &str,
        recipients: &[DispatchRecipient],
    ) -> Result<usize, SalesError> {
        if recipients.is_empty() {
            return Ok(0);
        }

        // Sender-domain readiness (lock-free pre-check for a fast, clear
        // error; the authoritative FOR SHARE check runs per recipient inside
        // the enqueue transaction).
        if !sender_domain_ready(&self.db, tenant_id, &self.cfg.from_email).await? {
            return Err(SalesError::InvalidInput(format!(
                "sender domain of '{}' is not verified/DKIM-ready for tenant — campaign paused",
                self.cfg.from_email
            )));
        }

        let template = fetch_template(&self.db, tenant_id, template_id).await?;

        let mut enqueued = 0usize;
        for recipient in recipients {
            let rendered = render_for_recipient(&template, recipient, &self.cfg.from_name)?;
            match self
                .enqueue_recipient(
                    tenant_id,
                    campaign_id,
                    &rendered,
                    &recipient.email,
                    &recipient.unsubscribe_link,
                )
                .await
            {
                Ok(EnqueueOutcome::Enqueued) => enqueued += 1,
                Ok(EnqueueOutcome::AlreadyClaimed) => {
                    metrics::counter!("sales_campaign_dispatch_skipped_total", "reason" => "claimed_or_suppressed")
                        .increment(1);
                }
                Ok(EnqueueOutcome::DuplicateIdempotency) => {
                    metrics::counter!("sales_campaign_dispatch_skipped_total", "reason" => "duplicate")
                        .increment(1);
                }
                // Unreachable on the campaign path (no action lease is
                // involved), but handled honestly rather than panicking: a
                // lease loss never enqueued anything, so the batch continues.
                Ok(EnqueueOutcome::LeaseLost) => {
                    metrics::counter!("sales_campaign_dispatch_skipped_total", "reason" => "lease_lost")
                        .increment(1);
                }
                // Quota exhaustion and hard configuration errors abort the
                // batch — the campaign is paused with an error state by the
                // caller; transient DB errors are retried on the next tick.
                Err(e) => return Err(e),
            }
        }
        Ok(enqueued)
    }

    /// Opaque v2 unsubscribe link on this service's public endpoint. The
    /// campaign id is intentionally not embedded: suppression is tenant-level
    /// (a recipient opting out of one campaign opts out of all).
    ///
    /// Persists only the token hash (see [`create_unsubscribe_token`]), so
    /// the emitted URL carries no recipient/tenant material. Fails rather
    /// than falling back to a v1 link when persistence fails — a token that
    /// cannot be resolved is worse than no link.
    ///
    /// Inherent (not trait) method since the legacy `CampaignEmailDispatcher`
    /// trait was retired by the campaigns refactor: the legacy campaign path
    /// must not enqueue directly. Kept public for the manual/legacy callers
    /// that still compose an unsubscribe link.
    pub async fn unsubscribe_link(
        &self,
        tenant_id: &str,
        _campaign_id: Uuid,
        recipient_email: &str,
    ) -> Result<String, SalesError> {
        let token = create_unsubscribe_token(&self.db, tenant_id, recipient_email).await?;
        Ok(format!("{}/u/{}", self.cfg.public_base_url, token))
    }
}

// ---------------------------------------------------------------------------
// Inbox replies (same pipeline, no campaign ledger)
// ---------------------------------------------------------------------------

/// Idempotency key namespace for inbox replies — one enqueued reply per
/// inbox message; a double-click can never double-send.
pub fn reply_idempotency_key(inbox_message_id: Uuid) -> String {
    format!("sareply:{inbox_message_id}")
}

/// Compose a reply subject from the original: `Re: `-prefixed unless the
/// original already carries the prefix (case-insensitive), truncated to fit
/// the `VARCHAR(255)` subject columns.
pub fn compose_reply_subject(original: &str) -> String {
    let trimmed = original.trim();
    let prefixed = if trimmed
        .split_once(':')
        .is_some_and(|(tag, _)| tag.trim().eq_ignore_ascii_case("re"))
    {
        trimmed.to_string()
    } else {
        format!("Re: {trimmed}")
    };
    truncate_subject(&prefixed)
}

/// Compose the HTML part of a reply from the operator's plain-text body:
/// blank-line-separated paragraphs, every value HTML-escaped (a lead's
/// hostile `<script>` text must never inject markup into the reply).
pub fn compose_reply_html(body: &str) -> String {
    let mut html = String::from("<div class=\"apexmail-reply\">\n");
    for paragraph in body.trim().split("\n\n") {
        let escaped = escape_html(paragraph.trim());
        if escaped.is_empty() {
            continue;
        }
        html.push_str("  <p>");
        html.push_str(&escaped);
        html.push_str("</p>\n");
    }
    html.push_str("</div>\n");
    html
}

/// Outcome of enqueueing an inbox reply.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ReplyOutcome {
    /// Rows inserted into `messages` + `email_queue`; the inbox `replied`
    /// flag was stamped in the same transaction.
    Enqueued { message_id: Uuid },
    /// This inbox message was already replied to (idempotent replay of the
    /// deterministic key, or the flag was set by another path). Nothing new
    /// is sent. `message_id` is the existing `messages` row when found.
    AlreadyReplied { message_id: Option<Uuid> },
}

impl ProductionCampaignDispatcher {
    /// Enqueue a reply to an inbound inbox message through the platform
    /// pipeline (`messages` + `email_queue`) — the same statements the
    /// campaign enqueue path and api-server's REST send use, minus the
    /// campaign ledger. The `replied` flag on `sales_inbox_messages` is
    /// stamped in the SAME transaction, so the flag can never claim
    /// "replied" while no reply was enqueued (and a failed enqueue leaves
    /// the message visibly unanswered for retry).
    ///
    /// # Suppression semantics (deliberate, documented decision)
    ///
    /// A reply is 1:1 transactional correspondence, not bulk commercial
    /// mail. Exactly like api-server's REST send path we check ONLY the
    /// platform-wide `suppressions` table (hard bounces, spam complaints,
    /// platform-level unsubscribes). A campaign opt-out recorded in
    /// `sales_unsubscribes` does NOT block a personal reply — a lead who
    /// opted out of marketing may still legitimately receive a direct
    /// answer to their own inbound question.
    #[allow(clippy::too_many_arguments)]
    pub async fn enqueue_reply(
        &self,
        tenant_id: &str,
        inbox_message_id: Uuid,
        to_email: &str,
        subject: &str,
        html: Option<&str>,
        text: &str,
    ) -> Result<ReplyOutcome, SalesError> {
        // Quota reservation outside the enqueue transaction (same as the
        // campaign path); released on every non-enqueue exit.
        let reservation = self.quota.reserve(tenant_id).await?;

        let outcome = self
            .enqueue_reply_tx(
                tenant_id,
                inbox_message_id,
                to_email,
                subject,
                html,
                text,
                &reservation,
            )
            .await;

        match &outcome {
            Ok(ReplyOutcome::Enqueued { .. }) => {}
            Ok(ReplyOutcome::AlreadyReplied { .. }) | Err(_) => {
                // Nothing will be delivered for this reservation — release it.
                if let Err(e) = self.quota.rollback(tenant_id, &reservation).await {
                    tracing::error!(
                        error = %e,
                        tenant_id = %tenant_id,
                        inbox_message_id = %inbox_message_id,
                        "failed to release quota for skipped inbox reply"
                    );
                }
            }
        }

        outcome
    }

    #[allow(clippy::too_many_arguments)]
    async fn enqueue_reply_tx(
        &self,
        tenant_id: &str,
        inbox_message_id: Uuid,
        to_email: &str,
        subject: &str,
        html: Option<&str>,
        text: &str,
        reservation: &QuotaReservation,
    ) -> Result<ReplyOutcome, SalesError> {
        let message_id = Uuid::new_v4();
        let created_at = Utc::now();
        // LEGACY PATH (retained for 1:1 correspondence): replies to an
        // inbound inbox message still use the deployment-wide
        // SALES_CAMPAIGN_FROM_EMAIL. Autonomous sequence mail must send from
        // the resolved sender identity — see `enqueue_sequenced`.
        let from = self.cfg.from_email.clone();
        let idempotency_key = reply_idempotency_key(inbox_message_id);

        let metadata = serde_json::json!({
            "source": "sales-autopilot",
            "kind": "inbox-reply",
            "inbox_message_id": inbox_message_id.to_string(),
            "sales_tenant_id": tenant_id,
            "from_name": self.cfg.from_name,
            "quota_event_id": reservation.event_id.to_string(),
        });
        let tags = vec!["sales-inbox-reply".to_string()];

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        // Platform-suppression re-check inside the transaction (mirror of
        // the REST path's `suppressed_recipients` gate): a correspondent
        // who hard-bounced never gets another send through this pipeline.
        let suppressed: bool = sqlx::query_scalar(
            "SELECT EXISTS (\
                SELECT 1 FROM suppressions s \
                WHERE s.tenant_id = $1 AND LOWER(s.email) = LOWER($2)\
             )",
        )
        .bind(tenant_id)
        .bind(to_email)
        .fetch_one(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        if suppressed {
            return Err(SalesError::InvalidInput(format!(
                "recipient is suppressed: {}",
                to_email.trim().to_ascii_lowercase()
            )));
        }

        // Sender-domain resolution with the row lock held through the queue
        // insert (identical gate to campaigns and the REST send path).
        let domain_id = resolve_sender_domain_id(&mut tx, tenant_id, &from)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?
            .ok_or_else(|| {
                SalesError::InvalidInput(format!(
                    "sender domain '{}' is not ready for the configured delivery transport",
                    from.rsplit_once('@').map(|(_, d)| d).unwrap_or(&from)
                ))
            })?;

        // Atomic "replied" claim: exactly one reply per inbox message is
        // ever enqueued (the flag and the enqueue commit together).
        let claimed: Option<Uuid> = sqlx::query_scalar(
            "UPDATE sales_inbox_messages SET replied = true \
             WHERE id = $1 AND tenant_id = $2 AND replied = false \
             RETURNING id",
        )
        .bind(inbox_message_id)
        .bind(tenant_id)
        .fetch_optional(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;
        if claimed.is_none() {
            // Already replied (or the flag was set by another path): resolve
            // the existing message id for an honest response, commit nothing
            // new, and release the reservation in the caller.
            let existing: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM messages \
                 WHERE tenant_id = $1 AND idempotency_key = $2 LIMIT 1",
            )
            .bind(tenant_id)
            .bind(&idempotency_key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
            // Nothing was written; dropping the tx rolls back.
            return Ok(ReplyOutcome::AlreadyReplied {
                message_id: existing,
            });
        }

        // `messages` insert with the deterministic reply key
        // (ON CONFLICT DO NOTHING — same statement as the REST path).
        let result = sqlx::query(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails,
             subject, html_body, text_body, status, tags, metadata, scheduled_at, created_at, idempotency_key)
             VALUES ($1::uuid,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15)
             ON CONFLICT (tenant_id, idempotency_key) DO NOTHING",
        )
        .bind(message_id)
        .bind(tenant_id)
        .bind(&from)
        .bind(serde_json::json!([to_email]))
        .bind(None::<serde_json::Value>)
        .bind(None::<serde_json::Value>)
        .bind(subject)
        .bind(html)
        .bind(text)
        .bind("queued")
        .bind(serde_json::json!(tags))
        .bind(&metadata)
        .bind(None::<DateTime<Utc>>)
        .bind(created_at)
        .bind(&idempotency_key)
        .execute(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        if result.rows_affected() == 0 {
            // Idempotent duplicate: this inbox message was already replied
            // to by a prior attempt whose flag stamp was lost (crash
            // between enqueue and a legacy flag path). Commit the flag
            // claim so it is not retried forever; never double-send.
            let existing: Option<Uuid> = sqlx::query_scalar(
                "SELECT id FROM messages \
                 WHERE tenant_id = $1 AND idempotency_key = $2 LIMIT 1",
            )
            .bind(tenant_id)
            .bind(&idempotency_key)
            .fetch_optional(&mut *tx)
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;
            tx.commit()
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
            tracing::warn!(
                tenant_id = %tenant_id,
                inbox_message_id = %inbox_message_id,
                "inbox reply skipped: idempotency key already enqueued"
            );
            return Ok(ReplyOutcome::AlreadyReplied {
                message_id: existing,
            });
        }

        // `email_queue` insert (single-recipient row, mirrors the REST path;
        // no List-Unsubscribe headers — this is 1:1 correspondence, not
        // bulk mail).
        sqlx::query(
            "INSERT INTO email_queue (
                id, message_id, tenant_id, domain_id, from_address, to_addresses, subject,
                \"from\", \"to\", html, text, tags, metadata, headers, scheduled_at, priority, status, created_at, updated_at
             ) VALUES (
                $1::uuid, $2::uuid, $3, $4::uuid, $5, ARRAY[$6], $7,
                $5, $6, $8, $9, $10, $11, $12, $13, 5, 'pending', $14, $14
             )",
        )
        .bind(Uuid::new_v4())
        .bind(message_id)
        .bind(tenant_id)
        .bind(&domain_id)
        .bind(&from)
        .bind(to_email)
        .bind(subject)
        .bind(html)
        .bind(text)
        .bind(&tags)
        .bind(&metadata)
        .bind(None::<serde_json::Value>)
        .bind(None::<DateTime<Utc>>)
        .bind(created_at)
        .execute(&mut *tx)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

        tx.commit()
            .await
            .map_err(|e| SalesError::Database(e.to_string()))?;

        metrics::counter!("sales_inbox_replies_enqueued_total").increment(1);
        Ok(ReplyOutcome::Enqueued { message_id })
    }
}

// ---------------------------------------------------------------------------
// Tests (unit, no database)
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    const SECRET: &str = "test-unsub-secret-0123456789abcdef";

    #[test]
    fn token_roundtrip() {
        // Canonicalization: mixed-case/whitespace input signs to the
        // lowercased form actually used by the suppression stores.
        let token = sign_unsubscribe_token_default_ttl(SECRET, "ten_a", " User@Example.COM ");
        let data = verify_unsubscribe_token(SECRET, &token).expect("valid token must verify");
        assert_eq!(data.tenant_id, "ten_a");
        assert_eq!(data.email, "user@example.com");
    }

    #[test]
    fn token_is_opaque_no_plaintext_pii() {
        let token = sign_unsubscribe_token_default_ttl(SECRET, "ten_a", "secret@corp.example");
        assert!(!token.contains("ten_a"));
        assert!(!token.contains("secret"));
        assert!(!token.contains("corp.example"));
    }

    #[test]
    fn token_tampering_is_rejected() {
        let token = sign_unsubscribe_token_default_ttl(SECRET, "ten_a", "a@b.c");
        // Flip one hex char of the tenant segment.
        let mut chars: Vec<char> = token.chars().collect();
        let idx = token.find('.').map(|i| i + 1).unwrap();
        chars[idx] = if chars[idx] == 'a' { 'b' } else { 'a' };
        let tampered: String = chars.into_iter().collect();
        assert!(verify_unsubscribe_token(SECRET, &tampered).is_none());
    }

    #[test]
    fn token_wrong_secret_is_rejected() {
        let token = sign_unsubscribe_token_default_ttl(SECRET, "ten_a", "a@b.c");
        assert!(verify_unsubscribe_token("another-secret-0123456789abcdef!!", &token).is_none());
    }

    #[test]
    fn token_expired_is_rejected() {
        let past = Utc::now().timestamp() - 1;
        let token = sign_unsubscribe_token(SECRET, "ten_a", "a@b.c", past);
        assert!(verify_unsubscribe_token(SECRET, &token).is_none());
    }

    #[test]
    fn token_malformed_shapes_are_rejected() {
        for bad in [
            "",
            "v1",
            "v1.1234",
            "v1.1234.5678",
            "v1.1234.5678.9999.extra",
            "v2.74656e5f61.614062632e63.9999999999.deadbeef",
            "v1..614062632e63.9999999999.deadbeef",
            "v1.74656e5f61.614062632e63.9999999999.not-a-real-signature",
            "v1.74656e5f61.614062632e63.not-a-number.deadbeef",
        ] {
            assert!(
                verify_unsubscribe_token(SECRET, bad).is_none(),
                "malformed token must be rejected: {bad}"
            );
        }
    }

    #[test]
    fn token_expiry_boundary_accepts_future() {
        let future = Utc::now().timestamp() + 60;
        let token = sign_unsubscribe_token(SECRET, "ten_a", "a@b.c", future);
        assert!(verify_unsubscribe_token(SECRET, &token).is_some());
    }

    // ── v2 opaque unsubscribe tokens (item 25) ─────────────────────────
    //
    // The whole point of v2 is that the URL carries no recipient/tenant
    // material and that only a hash is persisted. These tests run against
    // the canonical migrated database and soft-skip when it is unconfigured
    // (same contract as the rest of the crate's DB tests).

    /// Adversarial 1: the delivered URL contains neither the recipient nor
    /// the tenant id, nor any hex encoding of either (the v1 payload is
    /// reversible; v2 must not embed it at all).
    #[tokio::test]
    async fn v2_token_url_carries_no_recipient_tenant_or_hex_payload() {
        let Some(db) = crate::test_db::canonical_test_pool("dispatcher_v2_opacity").await else {
            return;
        };
        let tenant_id = "ten_v2opaque";
        let email = "opaque.recipient@corp.example";

        let token = create_unsubscribe_token(&db, tenant_id, email)
            .await
            .expect("v2 token creation");
        let url = format!("https://sales.example/u/{token}");

        // Shape: URL-safe base64, 43 chars, no dots (not a v1 payload).
        assert_eq!(token.len(), UNSUB_TOKEN_V2_LEN);
        assert!(!token.contains('.'));
        assert!(token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));

        // No plaintext and no reversible encoding of either identity.
        assert!(!url.contains(email), "URL must not embed the recipient");
        assert!(!url.contains("opaque.recipient"));
        assert!(!url.contains("corp.example"));
        assert!(!url.contains(tenant_id), "URL must not embed the tenant id");
        assert!(
            !url.contains(&hex_encode(tenant_id.as_bytes())),
            "the v1 hex tenant payload must not appear"
        );
        assert!(
            !url.contains(&hex_encode(email.as_bytes())),
            "the v1 hex recipient payload must not appear"
        );

        let _ = sqlx::query("DELETE FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&db)
            .await;
    }

    /// Adversarial 2: one flipped byte (first base64 character ⇒ a different
    /// decoded hash preimage) resolves to nothing.
    #[tokio::test]
    async fn tampered_v2_token_does_not_resolve() {
        let Some(db) = crate::test_db::canonical_test_pool("dispatcher_v2_tamper").await else {
            return;
        };
        let tenant_id = "ten_v2tamper";
        let token = create_unsubscribe_token(&db, tenant_id, "tamper@corp.example")
            .await
            .expect("v2 token creation");

        // Sanity: the untampered token resolves.
        assert!(
            resolve_unsubscribe_token(&db, &token)
                .await
                .expect("lookup")
                .is_some(),
            "the untampered token must resolve"
        );

        let mut chars: Vec<char> = token.chars().collect();
        chars[0] = if chars[0] == 'A' { 'B' } else { 'A' };
        let tampered: String = chars.into_iter().collect();
        assert_ne!(tampered, token);

        assert!(
            resolve_unsubscribe_token(&db, &tampered)
                .await
                .expect("lookup")
                .is_none(),
            "a tampered token must not resolve"
        );

        let _ = sqlx::query("DELETE FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&db)
            .await;
    }

    /// Adversarial 3: an expired v2 row does not resolve.
    #[tokio::test]
    async fn expired_v2_token_does_not_resolve() {
        use base64::Engine as _;

        let Some(db) = crate::test_db::canonical_test_pool("dispatcher_v2_expired").await else {
            return;
        };
        let tenant_id = "ten_v2expired";
        let raw = [0x42u8; UNSUB_TOKEN_V2_BYTES];
        let token = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(raw);
        let hash = Sha256::digest(raw);
        sqlx::query(
            "INSERT INTO sales_unsubscribe_tokens (token_hash, tenant_id, email, expires_at) \
             VALUES ($1, $2, $3, NOW() - INTERVAL '1 second')",
        )
        .bind(hash.as_slice())
        .bind(tenant_id)
        .bind("expired@corp.example")
        .execute(&db)
        .await
        .expect("seed an expired token");

        assert!(
            resolve_unsubscribe_token(&db, &token)
                .await
                .expect("lookup")
                .is_none(),
            "an expired token must not resolve"
        );

        let _ = sqlx::query("DELETE FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&db)
            .await;
    }

    /// Adversarial 4: the legacy v1 verifier still accepts an already-sent
    /// v1 token, while every NEW send mints a v2 token that the v1 verifier
    /// rejects.
    #[tokio::test]
    async fn legacy_v1_resolves_and_new_sends_are_v2() {
        // Compatibility half: an old v1 link still resolves.
        let v1 = sign_unsubscribe_token_default_ttl(SECRET, "ten_legacy", "old.link@corp.example");
        let data = verify_unsubscribe_token(SECRET, &v1).expect("v1 compatibility verifier");
        assert_eq!(data.tenant_id, "ten_legacy");
        assert_eq!(data.email, "old.link@corp.example");

        // New-send half.
        let Some(db) = crate::test_db::canonical_test_pool("dispatcher_v2_new_send").await else {
            return;
        };
        let tenant_id = "ten_v2newsend";
        let token = create_unsubscribe_token(&db, tenant_id, "new.send@corp.example")
            .await
            .expect("v2 token creation");

        assert_eq!(token.len(), UNSUB_TOKEN_V2_LEN);
        assert!(
            verify_unsubscribe_token(SECRET, &token).is_none(),
            "a v2 opaque token is not a v1 payload and must not verify as one"
        );
        let resolved = resolve_unsubscribe_token(&db, &token)
            .await
            .expect("lookup")
            .expect("new send's v2 token resolves");
        assert_eq!(resolved.tenant_id, tenant_id);
        assert_eq!(resolved.email, "new.send@corp.example");

        // The whole token is not persisted anywhere: the row's key is the hash.
        let stored_hash: Vec<u8> = sqlx::query_scalar(
            "SELECT token_hash FROM sales_unsubscribe_tokens WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_one(&db)
        .await
        .expect("read stored hash");
        assert_ne!(
            stored_hash,
            token.as_bytes(),
            "the raw token must never be stored"
        );

        let _ = sqlx::query("DELETE FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&db)
            .await;
    }

    /// Adversarial 5 (documented `used_at` semantics): the FIRST redemption
    /// stamps `used_at`; a replay still resolves and never rewrites the
    /// original timestamp (idempotent suppression, not single-use — mail
    /// scanners prefetch links).
    #[tokio::test]
    async fn used_at_is_stamped_on_first_redemption_and_replay_still_resolves() {
        let Some(db) = crate::test_db::canonical_test_pool("dispatcher_v2_used_at").await else {
            return;
        };
        let tenant_id = "ten_v2usedat";
        let token = create_unsubscribe_token(&db, tenant_id, "used.at@corp.example")
            .await
            .expect("v2 token creation");

        let used_before: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT used_at FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&db)
                .await
                .expect("read used_at before redemption");
        assert!(used_before.is_none(), "a fresh token is unused");

        assert!(resolve_unsubscribe_token(&db, &token)
            .await
            .expect("first redemption")
            .is_some());
        let used_after: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT used_at FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&db)
                .await
                .expect("read used_at after redemption");
        assert!(used_after.is_some(), "first redemption stamps used_at");

        // Replay: still resolves, and COALESCE keeps the first timestamp.
        assert!(resolve_unsubscribe_token(&db, &token)
            .await
            .expect("replay")
            .is_some());
        let used_replay: Option<DateTime<Utc>> =
            sqlx::query_scalar("SELECT used_at FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
                .bind(tenant_id)
                .fetch_one(&db)
                .await
                .expect("read used_at after replay");
        assert_eq!(
            used_replay, used_after,
            "a replay must not rewrite the first-redemption timestamp"
        );

        let _ = sqlx::query("DELETE FROM sales_unsubscribe_tokens WHERE tenant_id = $1")
            .bind(tenant_id)
            .execute(&db)
            .await;
    }

    #[test]
    fn personalization_escapes_html() {
        let template = TemplateContent {
            subject: "Hi {{first_name}} — {{company}}".into(),
            html_body: Some("<p>Hello {{name}} at {{company}}</p>".into()),
            text_body: Some("Hello {{name}}".into()),
        };
        let recipient = DispatchRecipient {
            email: "x@y.z".into(),
            unsubscribe_link: "https://sales.example/u/token".into(),
            lead: Some(LeadProfile {
                name: "<script>alert(1)</script>".into(),
                company: "ACME & Sons <b>LLC</b>".into(),
                title: String::new(),
            }),
        };
        let rendered = render_for_recipient(&template, &recipient, "ApexMail").unwrap();
        // The lead name has no whitespace, so first_name is the whole
        // (escaped) script tag; the subject interpolates it safely.
        assert_eq!(
            rendered.subject,
            "Hi &lt;script&gt;alert(1)&lt;/script&gt; — ACME &amp; Sons &lt;b&gt;LLC&lt;/b&gt;"
        );
        assert!(rendered
            .html
            .as_ref()
            .unwrap()
            .contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!rendered.html.as_ref().unwrap().contains("<script>"));
        // Text body keeps raw values (no double-escaping).
        assert!(rendered
            .text
            .as_ref()
            .unwrap()
            .contains("Hello <script>alert(1)</script>"));
        // CAN-SPAM footer link present in both bodies.
        assert!(rendered
            .html
            .as_ref()
            .unwrap()
            .contains("https://sales.example/u/token"));
        assert!(rendered
            .text
            .as_ref()
            .unwrap()
            .contains("https://sales.example/u/token"));
    }

    #[test]
    fn personalization_handles_first_last_name_split() {
        let template = TemplateContent {
            subject: "{{first_name}}|{{last_name}}".into(),
            html_body: None,
            text_body: Some("x".into()),
        };
        let recipient = DispatchRecipient {
            email: "x@y.z".into(),
            unsubscribe_link: "https://u".into(),
            lead: Some(LeadProfile {
                name: "Ada Lovelace Byron".into(),
                company: String::new(),
                title: String::new(),
            }),
        };
        let rendered = render_for_recipient(&template, &recipient, "S").unwrap();
        assert_eq!(rendered.subject, "Ada|Lovelace Byron");
    }

    #[test]
    fn personalization_whitespace_tolerant_placeholders() {
        let template = TemplateContent {
            subject: "Hi {{ first_name }}".into(),
            html_body: None,
            text_body: Some("t".into()),
        };
        let recipient = DispatchRecipient {
            email: "x@y.z".into(),
            unsubscribe_link: "https://u".into(),
            lead: Some(LeadProfile {
                name: "Ada".into(),
                company: String::new(),
                title: String::new(),
            }),
        };
        assert_eq!(
            render_for_recipient(&template, &recipient, "S")
                .unwrap()
                .subject,
            "Hi Ada"
        );
    }

    #[test]
    fn personalization_unknown_placeholder_left_intact() {
        let template = TemplateContent {
            subject: "Hi {{not_a_var}}".into(),
            html_body: None,
            text_body: Some("t".into()),
        };
        let recipient = DispatchRecipient {
            email: "x@y.z".into(),
            unsubscribe_link: "https://u".into(),
            lead: None,
        };
        assert_eq!(
            render_for_recipient(&template, &recipient, "S")
                .unwrap()
                .subject,
            "Hi {{not_a_var}}"
        );
    }

    #[test]
    fn render_without_lead_uses_empty_values() {
        let template = TemplateContent {
            subject: "Hello {{first_name}}".into(),
            html_body: Some("<p>{{company}}</p>".into()),
            text_body: None,
        };
        let recipient = DispatchRecipient {
            email: "x@y.z".into(),
            unsubscribe_link: "https://u".into(),
            lead: None,
        };
        let rendered = render_for_recipient(&template, &recipient, "S").unwrap();
        assert_eq!(rendered.subject, "Hello ");
        assert!(rendered.html.unwrap().contains("<p></p>"));
    }

    #[test]
    fn render_rejects_template_without_any_body() {
        let template = TemplateContent {
            subject: "s".into(),
            html_body: None,
            text_body: None,
        };
        let recipient = DispatchRecipient {
            email: "x@y.z".into(),
            unsubscribe_link: "https://u".into(),
            lead: None,
        };
        assert!(render_for_recipient(&template, &recipient, "S").is_err());
    }

    #[test]
    fn subject_is_truncated_to_255_chars() {
        let template = TemplateContent {
            subject: "x".repeat(300),
            html_body: None,
            text_body: Some("t".into()),
        };
        let recipient = DispatchRecipient {
            email: "x@y.z".into(),
            unsubscribe_link: "https://u".into(),
            lead: None,
        };
        let rendered = render_for_recipient(&template, &recipient, "S").unwrap();
        assert_eq!(rendered.subject.chars().count(), 255);
    }

    #[test]
    fn footer_inserted_before_closing_body_tag() {
        let template = TemplateContent {
            subject: "s".into(),
            html_body: Some("<html><body><p>x</p></body></html>".into()),
            text_body: None,
        };
        let recipient = DispatchRecipient {
            email: "x@y.z".into(),
            unsubscribe_link: "https://u".into(),
            lead: None,
        };
        let html = render_for_recipient(&template, &recipient, "S")
            .unwrap()
            .html
            .unwrap();
        let footer = html.find("apexmail-unsubscribe-footer").unwrap();
        let body_close = html.rfind("</body>").unwrap();
        assert!(footer < body_close, "footer must render before </body>");
        assert!(html.ends_with("</body></html>"));
    }

    #[test]
    fn idempotency_key_is_stable_and_bounded() {
        let campaign = Uuid::new_v4();
        let a = campaign_idempotency_key(campaign, "User@Example.COM ");
        let b = campaign_idempotency_key(campaign, "user@example.com");
        assert_eq!(a, b, "key is canonical over case/whitespace");
        assert!(a.starts_with(&format!("sacmp:{campaign}:")));

        // Very long recipients must not blow past VARCHAR(255).
        let long = format!("{}@example.com", "a".repeat(400));
        let key = campaign_idempotency_key(campaign, &long);
        assert!(key.len() <= 255, "key length {} > 255", key.len());
    }

    /// The footer must never manufacture consent. The previous implementation
    /// hardcoded "you signed up at ApexMail" for cold discovered prospects.
    #[test]
    fn footer_never_claims_a_signup_that_did_not_happen() {
        let recipient = DispatchRecipient::new("prospect@example.com", "https://x/u/1");
        let template = TemplateContent {
            subject: "Hello".into(),
            html_body: Some("<html><body><p>Hi</p></body></html>".into()),
            text_body: Some("Hi".into()),
        };

        let rendered = render_for_recipient(&template, &recipient, "ApexMail OÜ").unwrap();
        let html = rendered.html.unwrap();
        let text = rendered.text.unwrap();

        // The false claim is gone in both bodies.
        for body in [&html, &text] {
            assert!(
                !body.contains("because you signed up"),
                "footer must not claim a signup for cold outreach"
            );
            assert!(
                body.contains("not claiming that you signed up"),
                "footer must explicitly disclaim consent for a business contact"
            );
            // The opt-out mechanism is still present (CAN-SPAM).
            assert!(
                body.contains("https://x/u/1"),
                "opt-out link must be present"
            );
        }
        assert!(html.contains("apexmail-unsubscribe-footer"));
    }

    /// An opted-in relationship may say so — the wording follows the reason.
    #[test]
    fn consented_relationship_footer_states_the_opt_in() {
        let recipient = DispatchRecipient::new("customer@example.com", "https://x/u/2");
        let template = TemplateContent {
            subject: "Hello".into(),
            html_body: Some("<p>Hi</p>".into()),
            text_body: None,
        };
        let (html, text) = render_outreach_footer(&OutreachFooter {
            sender_identity: "ApexMail OÜ",
            reason: FooterReason::ConsentedRelationship,
            unsubscribe_link: "https://x/u/2",
            postal_address: Some("Tallinn, Estonia"),
            privacy_url: Some("https://apexmail.ee/privacy"),
        });
        assert!(html.contains("opted in"));
        assert!(html.contains("Tallinn, Estonia"));
        assert!(html.contains("https://apexmail.ee/privacy"));
        assert!(text.contains("opted in"));
        assert!(text.contains("Privacy: https://apexmail.ee/privacy"));

        let rendered = render_for_recipient_with_footer(
            &template,
            &recipient,
            OutreachFooter {
                sender_identity: "ApexMail OÜ",
                reason: FooterReason::ConsentedRelationship,
                unsubscribe_link: "https://x/u/2",
                postal_address: None,
                privacy_url: None,
            },
        )
        .unwrap();
        assert!(rendered.html.unwrap().contains("opted in"));
    }

    /// Release gate (§103¹ / CAN-SPAM): the central footer renderer must
    /// carry the unsubscribe link and a truthful disclosure for EVERY
    /// [`FooterReason`] — a reason that renders without them is a bypass of
    /// the compliant footer.
    #[test]
    fn every_footer_reason_carries_the_unsubscribe_link_and_disclosure() {
        let link = "https://apexmail.example/u/token-123";
        let reasons = [
            (
                FooterReason::BusinessContact {
                    basis: "your organisation appears to be a potential fit for ApexMail's \
                            email delivery platform.",
                },
                "not claiming that you signed up",
            ),
            (FooterReason::ConsentedRelationship, "opted in"),
            (
                FooterReason::AccountNotification,
                "part of your ApexMail account",
            ),
        ];

        for (reason, disclosure) in reasons {
            let (html, text) = render_outreach_footer(&OutreachFooter {
                sender_identity: "ApexMail OÜ",
                reason,
                unsubscribe_link: link,
                postal_address: Some("Tallinn, Estonia"),
                privacy_url: Some("https://apexmail.ee/privacy"),
            });
            for body in [&html, &text] {
                assert!(
                    body.contains(link),
                    "every footer reason must carry the unsubscribe link"
                );
                assert!(
                    body.to_ascii_lowercase().contains("unsubscribe"),
                    "every footer reason must name the unsubscribe mechanism"
                );
                assert!(
                    body.contains(disclosure),
                    "the footer must disclose its reason: expected {disclosure:?}"
                );
            }
        }
    }

    /// The sequenced send path's template arm goes through
    /// [`render_for_recipient_with_footer`]; both bodies it produces must
    /// already contain the footer, so the worker can never enqueue a bare
    /// template body.
    #[test]
    fn sequenced_template_render_contains_the_footer_in_both_bodies() {
        let template = TemplateContent {
            subject: "Hello".into(),
            html_body: Some("<html><body><p>Hi {{first_name}}</p></body></html>".into()),
            text_body: Some("Hi {{first_name}}".into()),
        };
        let recipient = DispatchRecipient::new(
            "prospect@example.com",
            "https://apexmail.example/u/token-sequenced",
        );
        let reasons = [
            FooterReason::BusinessContact {
                basis: "your organisation appears to be a potential fit.",
            },
            FooterReason::ConsentedRelationship,
            FooterReason::AccountNotification,
        ];

        for reason in reasons {
            let rendered = render_for_recipient_with_footer(
                &template,
                &recipient,
                OutreachFooter {
                    sender_identity: "ApexMail OÜ",
                    reason,
                    unsubscribe_link: &recipient.unsubscribe_link,
                    postal_address: None,
                    privacy_url: None,
                },
            )
            .expect("a template with both bodies renders");

            let html = rendered.html.expect("html body rendered");
            let text = rendered.text.expect("text body rendered");
            assert!(html.contains("apexmail-unsubscribe-footer"));
            assert!(html.contains(&recipient.unsubscribe_link));
            assert!(text.contains(&recipient.unsubscribe_link));
            assert!(html.contains("Unsubscribe</a>"));
            assert!(text.contains("Unsubscribe:"));
        }
    }

    /// The regression the identity fix exists for: two different steps of the
    /// same enrollment to the same recipient must NOT collide.
    #[test]
    fn different_steps_of_one_enrollment_do_not_collide() {
        let enrollment = Uuid::new_v4();
        let version = Uuid::new_v4();
        let step_one = Uuid::new_v4();
        let step_two = Uuid::new_v4();

        let first = send_idempotency_key(SendIdentity::StepExecution {
            enrollment_id: enrollment,
            sequence_version_id: version,
            step_id: step_one,
            attempt_kind: "primary",
            variant: "default",
        });
        let second = send_idempotency_key(SendIdentity::StepExecution {
            enrollment_id: enrollment,
            sequence_version_id: version,
            step_id: step_two,
            attempt_kind: "primary",
            variant: "default",
        });
        assert_ne!(
            first, second,
            "a second legitimate email in one sequence must be representable"
        );

        // Variant divergence: an A/B arm is its own logical send.
        let variant_b = send_idempotency_key(SendIdentity::StepExecution {
            enrollment_id: enrollment,
            sequence_version_id: version,
            step_id: step_one,
            attempt_kind: "primary",
            variant: "arm-b",
        });
        assert_ne!(first, variant_b);

        // Stable for identical inputs (replay collapses to one row).
        let repeat = send_idempotency_key(SendIdentity::StepExecution {
            enrollment_id: enrollment,
            sequence_version_id: version,
            step_id: step_one,
            attempt_kind: "primary",
            variant: "default",
        });
        assert_eq!(first, repeat);

        assert!(first.starts_with("sa:"), "step keys use the sa: namespace");
        assert!(first.len() <= 255, "key length {} > 255", first.len());
    }

    /// The legacy campaign key keeps its documented behaviour so the
    /// single-touch campaign path is unchanged by the identity refactor.
    #[test]
    fn legacy_campaign_key_unchanged() {
        let campaign = Uuid::new_v4();
        let key = send_idempotency_key(SendIdentity::CampaignRecipient {
            campaign_id: campaign,
            recipient_email: "User@Example.COM ",
        });
        assert_eq!(key, campaign_idempotency_key(campaign, "user@example.com"));
        assert!(key.starts_with(&format!("sacmp:{campaign}:")));
    }

    #[test]
    fn hex_helpers_roundtrip_and_reject_garbage() {
        assert_eq!(hex_encode(b"ten_a"), "74656e5f61");
        assert_eq!(hex_decode("74656e5f61").unwrap(), b"ten_a");
        assert!(hex_decode("zz").is_none());
        assert!(hex_decode("abc").is_none());
    }

    #[test]
    fn escape_html_covers_all_five_characters() {
        assert_eq!(escape_html("&<>\"'"), "&amp;&lt;&gt;&quot;&#39;");
        assert_eq!(escape_html("plain"), "plain");
    }

    // ── Inbox reply composition ─────────────────────────────────────────

    #[test]
    fn reply_subject_prefixes_and_does_not_double_prefix() {
        assert_eq!(
            compose_reply_subject("Pricing question"),
            "Re: Pricing question"
        );
        assert_eq!(
            compose_reply_subject("RE: Pricing question"),
            "RE: Pricing question"
        );
        assert_eq!(
            compose_reply_subject("re: already replied"),
            "re: already replied"
        );
        assert_eq!(compose_reply_subject("  Trims me  "), "Re: Trims me");
        // Not a Re: prefix — the colon belongs to the subject text.
        assert_eq!(
            compose_reply_subject("Note: something"),
            "Re: Note: something"
        );
    }

    #[test]
    fn reply_subject_is_truncated_to_255_chars() {
        let subject = compose_reply_subject(&"x".repeat(300));
        assert_eq!(subject.chars().count(), 255);
        assert!(subject.starts_with("Re: "));
    }

    #[test]
    fn reply_html_escapes_and_splits_paragraphs() {
        let html =
            compose_reply_html("Thanks for the demo request!\n\n<script>alert(1)</script> & more");
        assert!(html.contains("<p>Thanks for the demo request!</p>"));
        assert!(
            html.contains("&lt;script&gt;alert(1)&lt;/script&gt; &amp; more"),
            "hostile body text must be escaped: {html}"
        );
        assert!(!html.contains("<script>"));
    }

    #[test]
    fn reply_html_skips_blank_paragraphs() {
        let html = compose_reply_html("first\n\n\n\n  \n\nsecond");
        assert_eq!(html.matches("<p>").count(), 2);
    }

    #[test]
    fn reply_idempotency_key_is_deterministic_and_short() {
        let id = Uuid::new_v4();
        assert_eq!(reply_idempotency_key(id), format!("sareply:{id}"));
        assert!(reply_idempotency_key(id).len() <= 255);
        // Distinct inbox messages never share a key.
        assert_ne!(
            reply_idempotency_key(id),
            reply_idempotency_key(Uuid::new_v4())
        );
    }

    /// D: campaign attribution — the email_queue insert must set the
    /// campaign_id COLUMN (bound as a UUID, position $5), because the
    /// delivery worker reads email_queue.campaign_id into every events row
    /// it records. Metadata-only attribution left worker events unattributed.
    #[test]
    fn campaign_queue_insert_sets_campaign_id_column() {
        let sql = CAMPAIGN_EMAIL_QUEUE_INSERT_SQL;
        assert!(
            sql.contains("campaign_id"),
            "the campaign_id column must be written"
        );
        assert!(
            sql.contains("$5::uuid"),
            "campaign_id is bound as a UUID in positional slot 5"
        );
        // The statement still mirrors the REST send path shape.
        assert!(sql.contains("'pending'"));
        assert!(sql.contains("ARRAY[$7]"));
    }

    // -----------------------------------------------------------------------
    // Sequenced send: identity sender, execution fence, typed provenance
    // -----------------------------------------------------------------------

    fn test_dispatch_config() -> DispatchConfig {
        DispatchConfig {
            from_email: "legacy-global@apexmail.example".into(),
            from_name: "Legacy Deployment Default".into(),
            unsubscribe_secret: "test-unsubscribe-secret-0123456789abcdef".into(),
            public_base_url: "http://127.0.0.1:3010".into(),
            unsubscribe_redirect_url: None,
            dispatch_interval_secs: 30,
            dispatch_batch_size: 100,
            dispatch_concurrency: 1,
        }
    }

    fn sample_sender(from_email: &str, tenant_id: &str) -> crate::types::SenderIdentity {
        crate::types::SenderIdentity {
            id: Uuid::new_v4(),
            tenant_id: tenant_id.into(),
            pool: crate::types::SenderPool::SalesOutbound,
            from_email: from_email.into(),
            from_name: Some("Resolved Sales Sender".into()),
            domain: from_email
                .rsplit_once('@')
                .map(|(_, domain)| domain)
                .unwrap_or_default()
                .to_string(),
            status: "active".into(),
            daily_limit: Some(100),
            source_ip: Some("203.0.113.9".parse().expect("valid test IP")),
            provider: Some("ses".into()),
        }
    }

    /// The defect this test exists for: the sequenced send must name the
    /// resolved identity, never the deployment-wide
    /// `SALES_CAMPAIGN_FROM_EMAIL` (`DispatchConfig::from_email`).
    #[test]
    fn sequenced_envelope_sender_is_the_resolved_identity_never_the_config() {
        let cfg = test_dispatch_config();
        let sender = sample_sender("identity@outbound.example", "tenant-a");

        let envelope = sequenced_envelope(&sender, &cfg);

        assert_eq!(envelope.from_email, "identity@outbound.example");
        // Two DIFFERENT values: the config one must not win.
        assert_ne!(sender.from_email, cfg.from_email);
        assert_ne!(envelope.from_email, cfg.from_email);

        // The display name follows the identity; config is only the fallback
        // when the identity sets none.
        assert_eq!(envelope.from_name, "Resolved Sales Sender");
        let mut unnamed = sender.clone();
        unnamed.from_name = None;
        assert_eq!(sequenced_envelope(&unnamed, &cfg).from_name, cfg.from_name);
    }

    /// A caller cannot hand the dispatcher a transactional-pool or
    /// cross-tenant identity, even if it bypassed the pool resolver.
    #[test]
    fn sequenced_send_refuses_a_non_sales_or_cross_tenant_sender() {
        let mut wrong_pool = sample_sender("identity@outbound.example", "tenant-a");
        wrong_pool.pool = crate::types::SenderPool::TransactionalCustomer;
        let err = ensure_sequenced_sender(&wrong_pool, "tenant-a").unwrap_err();
        assert!(matches!(err, SalesError::PolicyDenied(_)));
        assert!(err.to_string().contains("not a sales pool"));

        let cross_tenant = sample_sender("identity@outbound.example", "tenant-b");
        let err = ensure_sequenced_sender(&cross_tenant, "tenant-a").unwrap_err();
        assert!(matches!(err, SalesError::PolicyDenied(_)));
        assert!(err.to_string().contains("tenant-b"));
    }

    /// The fence is the anti-duplicate guard: a stale claim is not authorized,
    /// so the transaction returns `LeaseLost` BEFORE either insert, and the
    /// statement order encodes exactly that.
    #[test]
    fn lease_lost_is_the_no_insert_guard_and_the_fence_precedes_the_inserts() {
        // No other outcome may be mistaken for "sent".
        assert_ne!(EnqueueOutcome::LeaseLost, EnqueueOutcome::Enqueued);
        assert_ne!(EnqueueOutcome::LeaseLost, EnqueueOutcome::AlreadyClaimed);
        assert_ne!(
            EnqueueOutcome::LeaseLost,
            EnqueueOutcome::DuplicateIdempotency
        );

        // The pure predicate behind `verify_fence_in_tx`: an expired lease (or
        // another owner/token) does not authorize, which is what makes the
        // transaction abort with no external effect.
        let now = Utc::now();
        let fence = crate::actions::ActionFence {
            action_id: Uuid::new_v4(),
            lease_owner: "worker-a".into(),
            lease_token: Uuid::new_v4(),
        };
        assert!(
            !fence.authorizes(
                Some("worker-a"),
                Some(fence.lease_token),
                Some(now - chrono::Duration::seconds(1)),
                "executing",
                now,
            ),
            "an expired lease must not authorize a send"
        );
        assert!(
            !fence.authorizes(
                Some("worker-b"),
                Some(fence.lease_token),
                Some(now + chrono::Duration::seconds(30)),
                "executing",
                now,
            ),
            "a recovered claim (different owner) must not authorize a send"
        );

        // Fence first, then messages, then email_queue.
        assert_eq!(
            SEQUENCED_TX_ORDER,
            [
                SequencedTxStep::VerifyActionLeaseFence,
                SequencedTxStep::InsertMessages,
                SequencedTxStep::InsertEmailQueue,
            ]
        );
    }

    /// Typed provenance (migration 202): all four columns on BOTH inserts,
    /// parameterized as UUIDs — a feedback consumer must not have to parse
    /// JSON metadata. Idempotency and the envelope columns are preserved.
    #[test]
    fn sequenced_inserts_write_all_four_typed_provenance_columns() {
        let typed = [
            "sales_decision_id",
            "sales_sender_identity_id",
            "sales_step_execution_id",
            "sales_enrollment_id",
        ];
        for sql in [
            SEQUENCE_MESSAGES_INSERT_SQL,
            SEQUENCE_EMAIL_QUEUE_INSERT_SQL,
        ] {
            for column in typed {
                assert!(
                    sql.contains(column),
                    "typed provenance column {column} missing from: {sql}"
                );
            }
            assert!(
                sql.contains("::uuid"),
                "typed ids must be bound as UUID params, not interpolated: {sql}"
            );
        }
        for placeholder in ["$16::uuid", "$17::uuid", "$18::uuid", "$19::uuid"] {
            assert!(SEQUENCE_MESSAGES_INSERT_SQL.contains(placeholder));
        }
        for placeholder in ["$14::uuid", "$15::uuid", "$16::uuid", "$17::uuid"] {
            assert!(SEQUENCE_EMAIL_QUEUE_INSERT_SQL.contains(placeholder));
        }
        // Envelope columns are present (bound from the resolved sender).
        assert!(SEQUENCE_MESSAGES_INSERT_SQL.contains("from_email"));
        assert!(SEQUENCE_EMAIL_QUEUE_INSERT_SQL.contains("from_address"));
        // A duplicate logical send still collapses.
        assert!(SEQUENCE_MESSAGES_INSERT_SQL
            .contains("ON CONFLICT (tenant_id, idempotency_key) DO NOTHING"));
    }

    // -----------------------------------------------------------------------
    // Live-DB proofs (ignored by default)
    // -----------------------------------------------------------------------

    /// Deterministic quota gateway: records reserve/release without billing.
    #[derive(Debug, Default)]
    struct FakeQuota {
        reserved: std::sync::atomic::AtomicUsize,
        released: std::sync::atomic::AtomicUsize,
    }

    impl QuotaGateway for FakeQuota {
        fn reserve(
            &self,
            _tenant_id: &str,
        ) -> QuotaFuture<'_, Result<QuotaReservation, SalesError>> {
            self.reserved
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async move {
                Ok(QuotaReservation {
                    event_id: Uuid::new_v4(),
                    recorded_at: Utc::now(),
                })
            })
        }

        fn rollback(
            &self,
            _tenant_id: &str,
            _reservation: &QuotaReservation,
        ) -> QuotaFuture<'_, Result<(), SalesError>> {
            self.released
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            Box::pin(async { Ok(()) })
        }
    }

    fn test_rendered() -> RenderedMessage {
        RenderedMessage {
            subject: "Sequenced binding test".into(),
            html: Some("<p>Hello</p>".into()),
            text: Some("Hello".into()),
        }
    }

    struct SequencedFixture {
        tenant: String,
        sender: crate::types::SenderIdentity,
        decision_id: Uuid,
        step_execution_id: Uuid,
        enrollment_id: Uuid,
        fence: crate::actions::ActionFence,
        key: String,
    }

    /// Seed every row the sequenced send path needs: tenant, verified/DKIM
    /// sender domain, sales sender identity, decision packet, sequence +
    /// enrollment + step execution, and a claimed (`executing`) action whose
    /// lease is live or expired.
    ///
    /// Every id/name is unique per run (the canonical database is shared and
    /// reused), so leftovers from a failed assertion cannot make a later run
    /// flaky.
    async fn seed_sequenced_fixture(
        pool: &PgPool,
        label: &str,
        lease_live: bool,
    ) -> SequencedFixture {
        let tenant = crate::test_db::unique_test_tenant(label);
        sqlx::query(
            "INSERT INTO tenants (id, name, slug, plan, status) \
             VALUES ($1, $2, $3, 'starter', 'active') ON CONFLICT (id) DO NOTHING",
        )
        .bind(&tenant)
        .bind(format!("test {tenant}"))
        .bind(format!("slug-{tenant}"))
        .execute(pool)
        .await
        .expect("seeding a tenant must succeed");

        // Verified + DKIM-ready domain for the RESOLVED sender identity (the
        // legacy config address deliberately has no domain).
        let domain = format!(
            "mail-{}.example.com",
            &Uuid::new_v4().simple().to_string()[..12]
        );
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, verified, dkim_enabled, ses_verified, \
             dkim_selector, dkim_public_key, dkim_private_key) \
             VALUES ($1, $2, $3, 'verified', true, true, true, 'test-selector', 'test-public-key', 'dkim:v1:test')",
        )
        .bind(Uuid::new_v4())
        .bind(&tenant)
        .bind(&domain)
        .execute(pool)
        .await
        .expect("inserting a verified domain must succeed");

        let sender_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sender_identities \
             (id, tenant_id, pool, from_email, from_name, domain, source_ip, provider, status, daily_limit) \
             VALUES ($1, $2, 'sales_outbound', $3, 'Resolved Sales Sender', $4, \
                     '203.0.113.7'::inet, 'test-provider', 'active', 100)",
        )
        .bind(sender_id)
        .bind(&tenant)
        .bind(format!("sender@{domain}"))
        .bind(&domain)
        .execute(pool)
        .await
        .expect("inserting a sender identity must succeed");

        // Reload through the resolver: proves `host(source_ip)` decodes into
        // `IpAddr` and the sales-pool gate passes on the new fields.
        let sender = crate::sender_pool::load_sales_sender(pool, &tenant, sender_id)
            .await
            .expect("the seeded sender must resolve as a sales identity");
        assert_eq!(
            sender.source_ip,
            Some("203.0.113.7".parse().expect("valid test IP")),
            "host(source_ip) must decode INET into IpAddr"
        );
        assert_eq!(sender.provider.as_deref(), Some("test-provider"));

        let account_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_accounts (id, tenant_id, company, domain) \
             VALUES ($1, $2, 'Prospect Co', $3)",
        )
        .bind(account_id)
        .bind(&tenant)
        .bind(format!(
            "prospect-{}.example",
            &Uuid::new_v4().simple().to_string()[..8]
        ))
        .execute(pool)
        .await
        .expect("inserting an account must succeed");

        let contact_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_contacts (id, tenant_id, account_id, full_name) \
             VALUES ($1, $2, $3, 'Ada Prospect')",
        )
        .bind(contact_id)
        .bind(&tenant)
        .bind(account_id)
        .execute(pool)
        .await
        .expect("inserting a contact must succeed");

        let sequence_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sequences (id, tenant_id, name, status) \
             VALUES ($1, $2, 'Binding Test', 'active')",
        )
        .bind(sequence_id)
        .bind(&tenant)
        .execute(pool)
        .await
        .expect("inserting a sequence must succeed");

        let version_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sequence_versions (id, tenant_id, sequence_id, version, status) \
             VALUES ($1, $2, $3, 1, 'active')",
        )
        .bind(version_id)
        .bind(&tenant)
        .bind(sequence_id)
        .execute(pool)
        .await
        .expect("inserting a sequence version must succeed");

        let step_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sequence_steps (id, tenant_id, version_id, step_index, kind, template_id) \
             VALUES ($1, $2, $3, 0, 'email', 'tpl-binding-test')",
        )
        .bind(step_id)
        .bind(&tenant)
        .bind(version_id)
        .execute(pool)
        .await
        .expect("inserting a sequence step must succeed");

        let enrollment_id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_enrollments (id, tenant_id, sequence_version_id, contact_id, state) \
             VALUES ($1, $2, $3, $4, 'active')",
        )
        .bind(enrollment_id)
        .bind(&tenant)
        .bind(version_id)
        .bind(contact_id)
        .execute(pool)
        .await
        .expect("inserting an enrollment must succeed");

        let step_execution_id = Uuid::new_v4();
        let key = format!(
            "sa:test:{}:{}",
            tenant,
            &Uuid::new_v4().simple().to_string()[..12]
        );
        sqlx::query(
            "INSERT INTO sales_step_executions \
             (id, tenant_id, enrollment_id, sequence_version_id, sequence_step_id, step_index, state, idempotency_key) \
             VALUES ($1, $2, $3, $4, $5, 0, 'executing', $6)",
        )
        .bind(step_execution_id)
        .bind(&tenant)
        .bind(enrollment_id)
        .bind(version_id)
        .bind(step_id)
        .bind(&key)
        .execute(pool)
        .await
        .expect("inserting a step execution must succeed");

        let decision_id = Uuid::new_v4();
        // `enforcement`/`review_status` are NOT NULL as of migration 204 (the
        // Decision Packet must carry a verdict); a fixture that omits them is
        // not a valid packet.
        sqlx::query(
            "INSERT INTO sales_decisions \
                 (id, tenant_id, action, autonomy_mode, enforcement, review_status, rationale) \
             VALUES ($1, $2, 'contact', 'autonomous_guarded', 'execute', 'not_required', 'binding test')",
        )
        .bind(decision_id)
        .bind(&tenant)
        .execute(pool)
        .await
        .expect("inserting a decision must succeed");

        let action_id = Uuid::new_v4();
        let lease_owner = format!(
            "worker-{label}-{}",
            &Uuid::new_v4().simple().to_string()[..8]
        );
        let lease_token = Uuid::new_v4();
        let action_sql = if lease_live {
            "INSERT INTO sales_actions \
             (id, tenant_id, action_type, entity_type, entity_id, due_at, priority, state, attempt, \
              max_attempts, lease_owner, lease_token, lease_expires_at, idempotency_key, payload, decision_id) \
             VALUES ($1, $2, 'send_step', 'enrollment', $3, NOW(), 100, 'executing', 1, 5, $4, $5, \
                     NOW() + INTERVAL '10 minutes', $6, '{}'::jsonb, $7)"
        } else {
            "INSERT INTO sales_actions \
             (id, tenant_id, action_type, entity_type, entity_id, due_at, priority, state, attempt, \
              max_attempts, lease_owner, lease_token, lease_expires_at, idempotency_key, payload, decision_id) \
             VALUES ($1, $2, 'send_step', 'enrollment', $3, NOW(), 100, 'executing', 1, 5, $4, $5, \
                     NOW() - INTERVAL '1 minute', $6, '{}'::jsonb, $7)"
        };
        sqlx::query(action_sql)
            .bind(action_id)
            .bind(&tenant)
            .bind(enrollment_id)
            .bind(&lease_owner)
            .bind(lease_token)
            .bind(format!("action:{key}"))
            .bind(decision_id)
            .execute(pool)
            .await
            .expect("inserting a claimed action must succeed");

        SequencedFixture {
            tenant,
            sender,
            decision_id,
            step_execution_id,
            enrollment_id,
            fence: crate::actions::ActionFence {
                action_id,
                lease_owner,
                lease_token,
            },
            key,
        }
    }

    async fn cleanup_sequenced_fixture(pool: &PgPool, tenant: &str) {
        for sql in [
            "DELETE FROM email_queue WHERE tenant_id = $1",
            "DELETE FROM messages WHERE tenant_id = $1",
            "DELETE FROM sales_actions WHERE tenant_id = $1",
            "DELETE FROM sales_step_executions WHERE tenant_id = $1",
            "DELETE FROM sales_enrollments WHERE tenant_id = $1",
            "DELETE FROM sales_sequence_steps WHERE tenant_id = $1",
            "DELETE FROM sales_sequence_versions WHERE tenant_id = $1",
            "DELETE FROM sales_sequences WHERE tenant_id = $1",
            "DELETE FROM sales_decisions WHERE tenant_id = $1",
            "DELETE FROM sales_contacts WHERE tenant_id = $1",
            "DELETE FROM sales_accounts WHERE tenant_id = $1",
            "DELETE FROM sales_sender_identities WHERE tenant_id = $1",
            "DELETE FROM domains WHERE tenant_id = $1",
            "DELETE FROM tenants WHERE id = $1",
        ] {
            sqlx::query(sql)
                .bind(tenant)
                .execute(pool)
                .await
                .expect("fixture cleanup must succeed");
        }
    }

    /// Live proof for defects 1+2: the sequenced send writes the four typed
    /// provenance columns on BOTH `messages` and `email_queue`, and the
    /// envelope sender is the resolved identity (never
    /// `SALES_CAMPAIGN_FROM_EMAIL`).
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn sequenced_send_binds_typed_provenance_and_the_resolved_sender() {
        let Some(pool) = crate::test_db::canonical_test_pool("sequenced_binding").await else {
            return;
        };
        let fx = seed_sequenced_fixture(&pool, "seqbind", true).await;
        let quota = Arc::new(FakeQuota::default());
        let dispatcher =
            ProductionCampaignDispatcher::new(test_dispatch_config(), pool.clone(), quota.clone())
                .expect("the test dispatch config is configured");

        let outcome = dispatcher
            .enqueue_sequenced(
                &fx.tenant,
                &fx.key,
                &test_rendered(),
                "prospect@example.com",
                "https://sales.example/u/token",
                &fx.sender,
                fx.decision_id,
                fx.step_execution_id,
                fx.enrollment_id,
                &fx.fence,
                serde_json::json!({ "test": "binding" }),
            )
            .await
            .expect("a fenced sequenced send must succeed");
        assert_eq!(outcome, EnqueueOutcome::Enqueued);

        let (decision, sender_id, step_id, enrollment, from_email, metadata): (
            Option<Uuid>,
            Option<Uuid>,
            Option<Uuid>,
            Option<Uuid>,
            String,
            serde_json::Value,
        ) = sqlx::query_as(
            "SELECT sales_decision_id, sales_sender_identity_id, sales_step_execution_id, \
                    sales_enrollment_id, from_email, metadata \
             FROM messages WHERE tenant_id = $1 AND idempotency_key = $2",
        )
        .bind(&fx.tenant)
        .bind(&fx.key)
        .fetch_one(&pool)
        .await
        .expect("the messages row must exist");

        assert_eq!(decision, Some(fx.decision_id), "typed decision id");
        assert_eq!(sender_id, Some(fx.sender.id), "typed sender identity id");
        assert_eq!(
            step_id,
            Some(fx.step_execution_id),
            "typed step execution id"
        );
        assert_eq!(enrollment, Some(fx.enrollment_id), "typed enrollment id");
        assert_eq!(
            from_email, fx.sender.from_email,
            "the envelope sender must be the resolved identity"
        );
        assert_ne!(
            from_email,
            dispatcher.config().from_email,
            "SALES_CAMPAIGN_FROM_EMAIL must never be used for a sequenced send"
        );

        // Belt and braces: the same provenance in metadata.
        assert_eq!(
            metadata["sales_decision_id"],
            serde_json::json!(fx.decision_id.to_string())
        );
        assert_eq!(
            metadata["sales_sender_identity_id"],
            serde_json::json!(fx.sender.id.to_string())
        );
        assert_eq!(metadata["sales_sender_pool"], "sales_outbound");
        assert_eq!(metadata["sales_sender_source_ip"], "203.0.113.7");

        // The queue row carries the same typed provenance, and its
        // from_address is the identity's address.
        let (q_decision, q_sender, q_step, q_enrollment, q_from): (
            Option<Uuid>,
            Option<Uuid>,
            Option<Uuid>,
            Option<Uuid>,
            String,
        ) = sqlx::query_as(
            "SELECT sales_decision_id, sales_sender_identity_id, sales_step_execution_id, \
                    sales_enrollment_id, from_address \
             FROM email_queue WHERE tenant_id = $1 AND message_id = \
                 (SELECT id FROM messages WHERE tenant_id = $1 AND idempotency_key = $2)",
        )
        .bind(&fx.tenant)
        .bind(&fx.key)
        .fetch_one(&pool)
        .await
        .expect("the email_queue row must exist");

        assert_eq!(q_decision, Some(fx.decision_id));
        assert_eq!(q_sender, Some(fx.sender.id));
        assert_eq!(q_step, Some(fx.step_execution_id));
        assert_eq!(q_enrollment, Some(fx.enrollment_id));
        assert_eq!(q_from, fx.sender.from_email);

        assert_eq!(
            quota.reserved.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the send reserves quota exactly once"
        );
        assert_eq!(
            quota.released.load(std::sync::atomic::Ordering::SeqCst),
            0,
            "an enqueued send keeps its reservation"
        );

        cleanup_sequenced_fixture(&pool, &fx.tenant).await;
    }

    /// Live proof for defect 3: a worker whose lease was recovered (here:
    /// expired) gets `LeaseLost` and produces NO external effect — zero new
    /// rows in `messages` and `email_queue` — and its quota reservation is
    /// released.
    #[ignore = "requires local PostgreSQL with the canonical sales schema"]
    #[tokio::test]
    async fn stale_fence_returns_lease_lost_and_writes_nothing() {
        let Some(pool) = crate::test_db::canonical_test_pool("stale_send_fence").await else {
            return;
        };
        let fx = seed_sequenced_fixture(&pool, "stalefence", false).await;
        let quota = Arc::new(FakeQuota::default());
        let dispatcher =
            ProductionCampaignDispatcher::new(test_dispatch_config(), pool.clone(), quota.clone())
                .expect("the test dispatch config is configured");

        let outcome = dispatcher
            .enqueue_sequenced(
                &fx.tenant,
                &fx.key,
                &test_rendered(),
                "prospect@example.com",
                "https://sales.example/u/token",
                &fx.sender,
                fx.decision_id,
                fx.step_execution_id,
                fx.enrollment_id,
                &fx.fence,
                serde_json::json!({ "test": "stale-fence" }),
            )
            .await
            .expect("a stale fence is a refusal, not a database error");
        assert_eq!(
            outcome,
            EnqueueOutcome::LeaseLost,
            "the anti-duplicate guard must fire for a stale lease"
        );

        let messages: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM messages WHERE tenant_id = $1")
                .bind(&fx.tenant)
                .fetch_one(&pool)
                .await
                .expect("counting messages must succeed");
        assert_eq!(messages, 0, "a stale worker must not insert into messages");

        let queued: i64 =
            sqlx::query_scalar("SELECT COUNT(*)::bigint FROM email_queue WHERE tenant_id = $1")
                .bind(&fx.tenant)
                .fetch_one(&pool)
                .await
                .expect("counting email_queue must succeed");
        assert_eq!(queued, 0, "a stale worker must not insert into email_queue");

        assert_eq!(
            quota.reserved.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "the reservation is taken before the fence check"
        );
        assert_eq!(
            quota.released.load(std::sync::atomic::Ordering::SeqCst),
            1,
            "a refused send must release its quota reservation"
        );

        cleanup_sequenced_fixture(&pool, &fx.tenant).await;
    }
}
