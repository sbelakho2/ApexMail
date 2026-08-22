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
use sqlx::PgPool;
use uuid::Uuid;

use crate::campaigns::{CampaignEmailDispatcher, DispatchRecipient};
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
/// # Integration point (precise)
///
/// This is a faithful LOCAL mirror of `billing_service::usage::
/// record_with_quota_check` / `rollback_usage_record`
/// (crates/billing-service/src/usage.rs): same Redis counter keys
/// (`meter:rt:{tenant}:emails_sent:{Y}-{M}`), same dedup keys
/// (`meter:dedup:{event_id}`), same check-and-increment Lua semantics, same
/// `metering_events` persistence, same plan-limit resolution SQL. It exists
/// because the billing-service crate currently does not compile in this
/// working tree (uncommitted WIP in an untracked `usage_ingest.rs` wired
/// through a modified `lib.rs`) and this crate must not edit sibling crates.
///
/// **When billing-service compiles again**, replace the bodies of
/// [`QuotaGateway::reserve`] and [`QuotaGateway::rollback`] below with direct
/// calls to `billing_service::usage::record_with_quota_check(...)` /
/// `rollback_usage_record(...)` (exactly what api-server's messages.rs does)
/// and delete the private helpers in this block — the keys and persisted
/// rows are already identical, so the swap is seamless.
#[derive(Debug, Clone)]
pub struct BillingQuotaGateway {
    db: PgPool,
    redis: deadpool_redis::Pool,
}

/// Email quota fallback when the plan row exists but has a NULL email
/// limit — matches the billing service's builtin free-plan seed
/// (`builtin_quota_limits` in billing-service/src/plans.rs).
const FALLBACK_EMAIL_LIMIT: i64 = 30_000;

/// Same check-and-increment Lua as billing-service `QUOTA_CHECK_AND_INCR_LUA`.
const QUOTA_CHECK_AND_INCR_LUA: &str = r#"
local current = tonumber(redis.call('GET', KEYS[1]) or '0')
local lim     = tonumber(ARGV[1])
local qty     = tonumber(ARGV[2])
local ttl     = tonumber(ARGV[3])
if lim >= 0 and current + qty > lim then
    return -1
end
local new_val = redis.call('INCRBY', KEYS[1], qty)
redis.call('EXPIRE', KEYS[1], ttl)
return new_val
"#;

/// Billing keeps counters for 40 days.
const METER_TTL_SECS: i64 = 40 * 86_400;

/// Mirror of billing-service `usage_counter_key` (calendar-month window).
fn usage_counter_key(tenant_id: &str, at: chrono::DateTime<Utc>) -> String {
    use chrono::Datelike;
    format!(
        "meter:rt:{}:emails_sent:{}-{:02}",
        tenant_id,
        at.year(),
        at.month()
    )
}

/// Mirror of billing-service `usage_dedup_key`.
fn usage_dedup_key(event_id: Uuid) -> String {
    format!("meter:dedup:{event_id}")
}

/// Mirror of billing-service `TENANT_PLAN_LIMITS_SQL` (override-aware).
const TENANT_PLAN_LIMITS_SQL: &str = r#"
        SELECT t.plan as plan_name,
               p.email_limit
        FROM tenants t
        LEFT JOIN plan_overrides po
          ON po.tenant_id = t.id
         AND po.active = true
         AND (po.expires_at IS NULL OR po.expires_at > NOW())
        LEFT JOIN plans p ON p.name = COALESCE(po.plan, t.plan)
        WHERE t.id = $1
        "#;

impl BillingQuotaGateway {
    pub fn new(db: PgPool, redis: deadpool_redis::Pool) -> Self {
        Self { db, redis }
    }

    /// Mirror of billing-service `rollback_quota_reservation`: atomically
    /// decrement the counter and drop the dedup key.
    async fn rollback_reservation(
        &self,
        tenant_id: &str,
        event_id: Uuid,
        recorded_at: DateTime<Utc>,
    ) -> Result<(), SalesError> {
        let mut conn = self
            .redis
            .get()
            .await
            .map_err(|e| SalesError::ServiceUnavailable(format!("quota redis unavailable: {e}")))?;
        let counter_key = usage_counter_key(tenant_id, recorded_at);
        let dedup_key = usage_dedup_key(event_id);
        let _: () = redis::pipe()
            .atomic()
            .cmd("INCRBY")
            .arg(&counter_key)
            .arg(-1i64)
            .ignore()
            .cmd("DEL")
            .arg(&dedup_key)
            .ignore()
            .query_async(&mut *conn)
            .await
            .map_err(|e| {
                SalesError::Internal(anyhow::anyhow!("quota rollback redis error: {e}"))
            })?;
        Ok(())
    }
}

impl QuotaGateway for BillingQuotaGateway {
    fn reserve(&self, tenant_id: &str) -> QuotaFuture<'_, Result<QuotaReservation, SalesError>> {
        let tenant_id = tenant_id.to_string();
        Box::pin(async move {
            let event_id = Uuid::new_v4();
            let recorded_at = Utc::now();

            // Plan limit resolution (mirror of resolve_plan_limits):
            // unknown tenant ⇒ limit 0 (deny), like the billing service.
            let row: Option<(String, Option<i64>)> =
                sqlx::query_as(TENANT_PLAN_LIMITS_SQL)
                    .bind(&tenant_id)
                    .fetch_optional(&self.db)
                    .await
                    .map_err(|e| {
                        tracing::error!(error = %e, tenant_id = %tenant_id, "quota plan lookup failed");
                        SalesError::ServiceUnavailable(
                            "billing quota enforcement is temporarily unavailable".into(),
                        )
                    })?;
            let limit = match row {
                Some((_, email_limit)) => email_limit.unwrap_or(FALLBACK_EMAIL_LIMIT),
                None => 0,
            };

            let mut conn = self
                .redis
                .get()
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, tenant_id = %tenant_id, "quota redis unavailable");
                    SalesError::ServiceUnavailable(
                        "billing quota enforcement is temporarily unavailable".into(),
                    )
                })?;

            // Atomic check-and-increment reservation.
            let new_val: i64 = redis::Script::new(QUOTA_CHECK_AND_INCR_LUA)
                .key(usage_counter_key(&tenant_id, recorded_at))
                .arg(limit)
                .arg(1i64)
                .arg(METER_TTL_SECS)
                .invoke_async(&mut *conn)
                .await
                .map_err(|e| {
                    tracing::error!(error = %e, tenant_id = %tenant_id, "quota redis EVAL failed");
                    SalesError::ServiceUnavailable(
                        "billing quota enforcement is temporarily unavailable".into(),
                    )
                })?;

            if new_val < 0 {
                // Counter NOT incremented on denial (see the Lua script).
                return Err(SalesError::QuotaExhausted(tenant_id));
            }

            // Persist the metering event (source of truth for invoices).
            // On failure the reservation is compensated, exactly like
            // billing-service's persist step.
            let persisted = sqlx::query(
                "INSERT INTO metering_events (id, tenant_id, event_type, quantity, timestamp, metadata) \
                 VALUES ($1, $2, 'emails_sent', 1, $3, $4) \
                 ON CONFLICT (id) DO NOTHING",
            )
            .bind(event_id)
            .bind(&tenant_id)
            .bind(recorded_at)
            .bind(serde_json::json!({"source": "sales-autopilot"}))
            .execute(&self.db)
            .await;

            if let Err(e) = persisted {
                if let Err(rollback_err) =
                    self.rollback_reservation(&tenant_id, event_id, recorded_at).await
                {
                    tracing::error!(error = %rollback_err, "quota reservation leak after metering persist failure");
                }
                return Err(SalesError::Database(e.to_string()));
            }

            // Mark the event as durably persisted (dedup key), mirroring
            // billing-service's post-persist SET.
            let _: Result<(), _> = redis::cmd("SET")
                .arg(usage_dedup_key(event_id))
                .arg("1")
                .arg("EX")
                .arg(METER_TTL_SECS)
                .query_async(&mut *conn)
                .await;

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
            sqlx::query("DELETE FROM metering_events WHERE id = $1")
                .bind(reservation.event_id)
                .execute(&self.db)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;

            self.rollback_reservation(&tenant_id, reservation.event_id, reservation.recorded_at)
                .await
        })
    }
}

// ---------------------------------------------------------------------------
// Unsubscribe tokens (HMAC-SHA256, no plaintext PII)
// ---------------------------------------------------------------------------

/// Token version prefix; embedded in the signed payload.
const UNSUB_TOKEN_VERSION: &str = "v1";
/// Default token lifetime: 365 days (recipients keep emails a long time).
const UNSUB_TOKEN_TTL_SECS: i64 = 365 * 24 * 3600;

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
    for pair in bytes.chunks_exact(2) {
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

/// Sign an unsubscribe token for (tenant, recipient). Deterministic for a
/// given expiry, carries no plaintext PII, and is safe to embed in a URL.
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

/// A verified unsubscribe token's contents.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnsubscribeTokenData {
    pub tenant_id: String,
    pub email: String,
    pub expires_at: i64,
}

/// Verify + decode an unsubscribe token. Returns `None` for malformed
/// input, a bad signature (constant-time compare), or an expired token.
///
/// Wire format: `v1.{tenant_hex}.{email_hex}.{expiry_unix}.{sig_hex}` —
/// five dot-separated segments.
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

/// Convenience: sign a token expiring [`UNSUB_TOKEN_TTL_SECS`] from now. The
/// recipient address is canonicalized (trim + lowercase) so the token always
/// matches the suppression stores' canonical form.
pub fn sign_unsubscribe_token_default_ttl(
    secret: &str,
    tenant_id: &str,
    email: &str,
) -> String {
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

/// Render a template for one recipient: personalization (HTML-escaped) +
/// CAN-SPAM footer with the unsubscribe link.
pub fn render_for_recipient(
    template: &TemplateContent,
    recipient: &DispatchRecipient,
    sender_name: &str,
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

    let footer_html = format!(
        "\n<div class=\"apexmail-unsubscribe-footer\" style=\"margin-top:24px;padding-top:12px;border-top:1px solid #eee;font-size:12px;color:#666\">\n  <p>You are receiving this email because you signed up at ApexMail. <a href=\"{}\" style=\"color:#666\">Unsubscribe</a></p>\n</div>\n",
        recipient.unsubscribe_link
    );
    let footer_text = format!("\n\n--\nUnsubscribe: {}\n", recipient.unsubscribe_link);

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

/// Fetch a template by id or slug for a tenant. Column set restricted to
/// columns present on BOTH schema lineages (tools/migrations and
/// services/mail-server/migrations).
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

/// Idempotency key namespace for campaign sends.
pub fn campaign_idempotency_key(campaign_id: Uuid, recipient_email: &str) -> String {
    // Bound the key length: messages.idempotency_key is VARCHAR(255). The
    // fixed prefix + campaign uuid leave ~200 chars for the recipient.
    let recipient = truncate_bytes(recipient_email.trim().to_ascii_lowercase(), 200);
    format!("sacmp:{campaign_id}:{recipient}")
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
    pub fn new(cfg: DispatchConfig, db: PgPool, quota: Arc<dyn QuotaGateway>) -> anyhow::Result<Self> {
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
            .enqueue_recipient_tx(tenant_id, campaign_id, rendered, recipient_email, unsubscribe_link, &reservation)
            .await;

        match &outcome {
            Ok(EnqueueOutcome::Enqueued) => {}
            Ok(EnqueueOutcome::AlreadyClaimed) | Ok(EnqueueOutcome::DuplicateIdempotency) => {
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
                // Quota exhaustion and hard configuration errors abort the
                // batch — the campaign is paused with an error state by the
                // caller; transient DB errors are retried on the next tick.
                Err(e) => return Err(e),
            }
        }
        Ok(enqueued)
    }
}

impl CampaignEmailDispatcher for ProductionCampaignDispatcher {
    fn dispatch(
        &self,
        tenant_id: &str,
        campaign_id: Uuid,
        template_id: &str,
        recipients: &[DispatchRecipient],
    ) -> std::pin::Pin<Box<dyn std::future::Future<Output = Result<usize, SalesError>> + Send>>
    {
        let tenant_id = tenant_id.to_string();
        let template_id = template_id.to_string();
        let recipients = recipients.to_vec();
        let this = self.clone();
        Box::pin(async move {
            this.dispatch_batch(&tenant_id, campaign_id, &template_id, &recipients)
                .await
        })
    }

    /// HMAC-signed unsubscribe link on this service's public endpoint. The
    /// campaign id is intentionally not embedded: suppression is
    /// tenant-level (a recipient opting out of one campaign opts out of all).
    fn unsubscribe_link(&self, tenant_id: &str, _campaign_id: Uuid, recipient_email: &str) -> String {
        let token = sign_unsubscribe_token_default_ttl(
            &self.cfg.unsubscribe_secret,
            tenant_id,
            &recipient_email.trim().to_ascii_lowercase(),
        );
        format!("{}/u/{}", self.cfg.public_base_url, token)
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
        assert!(rendered.html.as_ref().unwrap().contains("&lt;script&gt;alert(1)&lt;/script&gt;"));
        assert!(!rendered.html.as_ref().unwrap().contains("<script>"));
        // Text body keeps raw values (no double-escaping).
        assert!(rendered.text.as_ref().unwrap().contains("Hello <script>alert(1)</script>"));
        // CAN-SPAM footer link present in both bodies.
        assert!(rendered.html.as_ref().unwrap().contains("https://sales.example/u/token"));
        assert!(rendered.text.as_ref().unwrap().contains("https://sales.example/u/token"));
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
            render_for_recipient(&template, &recipient, "S").unwrap().subject,
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
            render_for_recipient(&template, &recipient, "S").unwrap().subject,
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
        assert_eq!(compose_reply_subject("Pricing question"), "Re: Pricing question");
        assert_eq!(compose_reply_subject("RE: Pricing question"), "RE: Pricing question");
        assert_eq!(compose_reply_subject("re: already replied"), "re: already replied");
        assert_eq!(compose_reply_subject("  Trims me  "), "Re: Trims me");
        // Not a Re: prefix — the colon belongs to the subject text.
        assert_eq!(compose_reply_subject("Note: something"), "Re: Note: something");
    }

    #[test]
    fn reply_subject_is_truncated_to_255_chars() {
        let subject = compose_reply_subject(&"x".repeat(300));
        assert_eq!(subject.chars().count(), 255);
        assert!(subject.starts_with("Re: "));
    }

    #[test]
    fn reply_html_escapes_and_splits_paragraphs() {
        let html = compose_reply_html("Thanks for the demo request!\n\n<script>alert(1)</script> & more");
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
        assert_ne!(reply_idempotency_key(id), reply_idempotency_key(Uuid::new_v4()));
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
}
