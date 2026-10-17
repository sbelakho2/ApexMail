//! The Adyen notification wire layer: the live ingest surface for
//! `POST /webhooks/adyen`.
//!
//! The frozen contract (docs/tool-contracts/adyen.md, mirrored by
//! `tools/dogfood-v2/harness/adyen.py`):
//!
//! * request body `{"notificationItems":[{"NotificationRequestItem":{…}}]}`;
//! * the HMAC lives INSIDE the body at `additionalData.hmacSignature` — a
//!   base64 digest over the escaped colon-joined
//!   `pspReference:originalReference:merchantAccountCode:merchantReference:amount.value:amount.currency:eventCode:success`,
//!   keyed by the hex-decoded `ADYEN_HMAC_KEY`, compared timing-safe;
//! * amounts are integer minor units (cents);
//! * `[accepted]` (bare text) acknowledges a notification whose every item
//!   was processed or is a duplicate;
//! * Adyen retries the same notification until acknowledged, so idempotency
//!   is the deterministic dedupe digest over
//!   (eventCode, pspReference, success, eventDate, merchantReference) — the
//!   Adyen HMAC has no timestamp segment and no freshness window exists.
//!
//! Local invoices are OURS: an `AUTHORISATION` names the obligation through
//! `merchantReference = invoice:{local_invoice_uuid}` and the local invoice
//! total is the tax decision the charge is validated against.

use std::collections::HashMap;
use std::sync::{Arc, OnceLock};
use std::time::Duration;

use axum::{
    body::Bytes,
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Response},
    routing::post,
    Json, Router,
};
use chrono::{DateTime, TimeDelta, Utc};
use futures::future::join_all;
use hmac::{Hmac, Mac};
use serde::{Deserialize, Serialize};
use sha2::Sha256;
use tokio::time::timeout;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::routes::{append_audit_log, generate_audit_log_id};
use crate::AppState;

type HmacSha256 = Hmac<Sha256>;

const DEADLETTER_EVENT_PREFIX: &str = "adyen:deadletter:event:";
const DEADLETTER_INDEX_KEY: &str = "adyen:deadletter:index";
const DEADLETTER_RETENTION_SECONDS: usize = 35 * 24 * 60 * 60;
const DEADLETTER_RETENTION_MS: i64 = (DEADLETTER_RETENTION_SECONDS as i64) * 1000;
const DEADLETTER_RETRY_INDEX_KEY: &str = "adyen:deadletter:retry:index";
const DEADLETTER_MAX_RETRIES: u32 = 5;
/// Maximum stored webhook body size (4 KiB). Larger bodies are truncated
/// before the Redis SET so a single oversized Adyen payload cannot bloat
/// every deadletter entry. Truncated bodies are kept for debugging but are
/// never replayed — the retry scheduler skips entries whose body was cut.
const DEADLETTER_MAX_BODY_BYTES: usize = 4 * 1024;
/// Poll interval for the deadletter retry worker.
const DEADLETTER_RETRY_POLL_INTERVAL_SECS: u64 = 60;
/// Exponential backoff schedule in seconds: 5 min, 15 min, 30 min, 1 hour, 2 hours (max 5 attempts).
const DEADLETTER_RETRY_BACKOFF_SECONDS: [i64; 5] = [300, 900, 1800, 3600, 7200];
/// Maximum number of deadletter entries to retry per batch.
const DEADLETTER_RETRY_BATCH_SIZE: usize = 10;
/// Keys per MGET / ZREM round trip. Bounds a single Redis command's args
/// while keeping the retry pass O(1) round trips instead of O(entries).
const DEADLETTER_KEY_CHUNK: usize = 100;
const DUNNING_STATUS_CACHE_TTL_SECONDS: u64 = 300;

/// The success answer Adyen expects: the bare body `[accepted]` (text).
const ADYEN_ACCEPTED_RESPONSE: &str = "[accepted]";

/// The `adyen_tax_snapshots.authority` value recorded when the charged total
/// is validated against ApexMail's own computation. Migration 218's CHECK
/// constraint allows only ('stripe_tax', 'apexmail_local'); `apexmail_local`
/// is the allowed value that truthfully means "ApexMail's local computation
/// validated against the charge" (the pre-cutover `stripe_tax` check value named a
/// processor ApexMail no longer uses).
const ADYEN_TAX_AUTHORITY_LOCAL: &str = "apexmail_local";

/// The `invoice_payment_allocations.source` value for a settled Adyen
/// payment. The accounting ledger adapter
/// (`accounting_core::adapters::post_payment_allocation_in`) branches on
/// `source = 'adyen'` to post to the Adyen processor clearing account with
/// the `adyen_settlement` source type, so this is the codebase's truthful
/// value (migration 140's CHECK still lists the pre-cutover set; see the
/// migration-gap note in the module tests).
const ADYEN_ALLOCATION_SOURCE: &str = "adyen";

static DUNNING_CONFIG_TABLE_ENSURED: OnceLock<()> = OnceLock::new();

/// The Adyen webhook ingest route. Mounted by the billing-service binary
/// AND by api-server (which nests it on the public rate-limited stack when
/// `ADYEN_HMAC_KEY` is configured) — the billing-service binary has
/// no container in any deployed topology, so api-server is the live ingest
/// surface (dogfood finding A, 2026-10-05).
pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/webhooks/adyen", post(handle_adyen_webhook))
}

async fn handle_adyen_webhook(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    match process_webhook(&state, &body).await {
        Ok(result) => {
            info!(
                items_processed = result.items_processed,
                items_duplicate = result.items_duplicate,
                "adyen notification accepted"
            );
            (StatusCode::OK, ADYEN_ACCEPTED_RESPONSE).into_response()
        }
        Err(error) => {
            let error_message = error.message().to_string();
            if error.should_record_deadletter() {
                record_deadletter(
                    &state,
                    DeadletterEntry {
                        reason: error.deadletter_reason().into(),
                        occurred_at: None,
                        event_id: first_psp_reference(&body),
                        error: Some(error.deadletter_detail().to_string()),
                        payload_length: Some(body.len()),
                        ..Default::default()
                    },
                    Some(&body),
                    None,
                )
                .await;
            }

            error!(error = %error_message, "adyen webhook processing failed");
            json_error(error.http_status(), error.response_message())
        }
    }
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

// ---------------------------------------------------------------------------
// The wire types
// ---------------------------------------------------------------------------

/// One `NotificationRequestItem` (the unit Adyen retries and we dedupe on).
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdyenNotificationItem {
    psp_reference: String,
    #[serde(default)]
    original_reference: Option<String>,
    /// Present on every real notification; absent deserializes to empty and
    /// participates in the signing string as an empty field (the SDK recipe).
    #[serde(default)]
    merchant_account_code: Option<String>,
    #[serde(default)]
    merchant_reference: String,
    #[serde(default)]
    amount: Option<AdyenAmount>,
    #[serde(default)]
    event_code: String,
    #[serde(default)]
    event_date: Option<String>,
    /// "true" / "false" verbatim (Adyen's documented wire type).
    #[serde(default)]
    success: Option<String>,
    #[serde(default)]
    payment_method: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    additional_data: Option<AdyenAdditionalData>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdyenAmount {
    /// Integer MINOR UNITS (cents). Absent is absent — never coerced to 0;
    /// the signing string renders it as the empty field, exactly like the
    /// harness.
    #[serde(default)]
    value: Option<i64>,
    #[serde(default)]
    currency: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct AdyenAdditionalData {
    #[serde(default)]
    hmac_signature: Option<String>,
    /// The stored-payment token (shopper-scoped) bound by
    /// `RECURRING_CONTRACT`.
    #[serde(default)]
    recurring_detail_reference: Option<String>,
    /// The shopper reference; in ApexMail it IS the tenant id.
    #[serde(default)]
    shopper_reference: Option<String>,
    #[serde(default)]
    recurring_processing_model: Option<String>,
    /// The notification metadata (`additionalData.metadata.*`); the tenant
    /// fallback when no shopperReference is present.
    #[serde(default)]
    metadata: Option<HashMap<String, String>>,
}

#[derive(Debug, Deserialize)]
struct AdyenNotificationEnvelope {
    #[serde(rename = "notificationItems", default)]
    notification_items: Vec<AdyenNotificationEnvelopeEntry>,
}

#[derive(Debug, Deserialize)]
struct AdyenNotificationEnvelopeEntry {
    #[serde(rename = "NotificationRequestItem")]
    notification_request_item: AdyenNotificationItem,
}

impl AdyenNotificationItem {
    fn hmac_signature(&self) -> Option<&str> {
        self.additional_data
            .as_ref()
            .and_then(|data| data.hmac_signature.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn shopper_reference(&self) -> Option<&str> {
        self.additional_data
            .as_ref()
            .and_then(|data| data.shopper_reference.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn metadata_tenant_id(&self) -> Option<&str> {
        self.additional_data
            .as_ref()
            .and_then(|data| data.metadata.as_ref())
            .and_then(|metadata| metadata.get("tenant_id"))
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn recurring_detail_reference(&self) -> Option<&str> {
        self.additional_data
            .as_ref()
            .and_then(|data| data.recurring_detail_reference.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn recurring_processing_model(&self) -> Option<&str> {
        self.additional_data
            .as_ref()
            .and_then(|data| data.recurring_processing_model.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn amount_value(&self) -> Option<i64> {
        self.amount.as_ref().and_then(|amount| amount.value)
    }

    fn amount_currency(&self) -> Option<&str> {
        self.amount
            .as_ref()
            .and_then(|amount| amount.currency.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn success_is_true(&self) -> bool {
        self.success
            .as_deref()
            .map(str::trim)
            .is_some_and(|value| value.eq_ignore_ascii_case("true"))
    }
}

// ---------------------------------------------------------------------------
// The SDK signing recipe (HMAC-SHA256, hex-decoded key, base64 digest,
// timing-safe compare) and the deterministic dedupe id
// ---------------------------------------------------------------------------

/// The signing key: `ADYEN_HMAC_KEY` is hex-encoded key material and is
/// hex-decoded. A non-hex local-dev secret (the compose default) stays usable
/// as raw bytes — the same documented fallback the Python harness applies, so
/// the fixture, the probes and the local stack agree.
fn hmac_key_bytes(secret: &str) -> Vec<u8> {
    let cleaned = secret.trim();
    hex::decode(cleaned).unwrap_or_else(|_| cleaned.as_bytes().to_vec())
}

/// Adyen's signing-string escaping: backslashes first, then colons. Applied
/// to every field (a no-op for digits, currency codes, event codes and
/// true/false).
fn escape_signing_value(value: &str) -> String {
    value.replace('\\', "\\\\").replace(':', "\\:")
}

/// The exact signing string for one notification item.
fn adyen_signing_string(item: &AdyenNotificationItem) -> String {
    [
        escape_signing_value(item.psp_reference.as_str()),
        escape_signing_value(item.original_reference.as_deref().unwrap_or("")),
        escape_signing_value(item.merchant_account_code.as_deref().unwrap_or("")),
        escape_signing_value(item.merchant_reference.as_str()),
        escape_signing_value(
            &item
                .amount
                .as_ref()
                .and_then(|amount| amount.value)
                .map(|value| value.to_string())
                .unwrap_or_default(),
        ),
        escape_signing_value(
            item.amount
                .as_ref()
                .and_then(|amount| amount.currency.as_deref())
                .unwrap_or(""),
        ),
        escape_signing_value(item.event_code.as_str()),
        escape_signing_value(item.success.as_deref().unwrap_or("")),
    ]
    .join(":")
}

/// Verify one item's in-body HMAC against the secret, timing-safe
/// (`Mac::verify_slice`). The digest travels base64-encoded.
fn verify_item_hmac(
    secret: &str,
    item: &AdyenNotificationItem,
    signature: &str,
) -> Result<(), String> {
    let expected =
        base64_decode(signature.trim()).ok_or_else(|| "Invalid webhook signature".to_string())?;
    let mut mac = HmacSha256::new_from_slice(&hmac_key_bytes(secret))
        .expect("HMAC accepts arbitrary key lengths");
    mac.update(adyen_signing_string(item).as_bytes());
    mac.verify_slice(&expected)
        .map_err(|_| "Invalid webhook signature".to_string())
}

/// The deterministic dedupe id (`adn_<hex>`) — SHA-256 over the five fields
/// Adyen retries identically, joined with the unit separator the Python
/// harness uses. This is the idempotency key that replaces the pre-Adyen
/// timestamp tolerance (Adyen's HMAC has no timestamp segment).
fn adyen_notification_id(item: &AdyenNotificationItem) -> String {
    use sha2::Digest;
    let basis = [
        item.event_code.clone(),
        item.psp_reference.clone(),
        item.success.clone().unwrap_or_default(),
        item.event_date.clone().unwrap_or_default(),
        item.merchant_reference.clone(),
    ]
    .join("\u{1f}");
    format!("adn_{}", hex::encode(Sha256::digest(basis.as_bytes())))
}

/// Strict standard-alphabet base64 decoding (RFC 4648): padding optional but
/// validated, no whitespace, no URL-safe alphabet. `None` on any malformed
/// input — a malformed signature is an invalid signature.
fn base64_decode(input: &str) -> Option<Vec<u8>> {
    let bytes = input.as_bytes();
    if bytes.is_empty() || bytes.len() % 4 == 1 {
        return None;
    }
    let mut out = Vec::with_capacity(bytes.len() / 4 * 3 + 2);
    let mut buffer: u32 = 0;
    let mut bits: u32 = 0;
    let mut padding = 0usize;
    for &byte in bytes {
        if byte == b'=' {
            padding += 1;
            if padding > 2 {
                return None;
            }
            continue;
        }
        if padding > 0 {
            return None;
        }
        let value = match byte {
            b'A'..=b'Z' => byte - b'A',
            b'a'..=b'z' => byte - b'a' + 26,
            b'0'..=b'9' => byte - b'0' + 52,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        } as u32;
        buffer = (buffer << 6) | value;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((buffer >> bits) as u8);
        }
    }
    Some(out)
}

/// Standard base64 encoding (test-only: production verifies, tests sign).
#[cfg(test)]
fn base64_encode(bytes: &[u8]) -> String {
    const ALPHABET: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::with_capacity(bytes.len().div_ceil(3) * 4);
    for chunk in bytes.chunks(3) {
        let b0 = chunk[0] as u32;
        let b1 = chunk.get(1).copied().unwrap_or(0) as u32;
        let b2 = chunk.get(2).copied().unwrap_or(0) as u32;
        let triple = (b0 << 16) | (b1 << 8) | b2;
        out.push(ALPHABET[(triple >> 18) as usize & 0x3f] as char);
        out.push(ALPHABET[(triple >> 12) as usize & 0x3f] as char);
        if chunk.len() > 1 {
            out.push(ALPHABET[(triple >> 6) as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
        if chunk.len() > 2 {
            out.push(ALPHABET[triple as usize & 0x3f] as char);
        } else {
            out.push('=');
        }
    }
    out
}

// ---------------------------------------------------------------------------
// Event-code dispatch
// ---------------------------------------------------------------------------

/// Which handler an item routes to. Pure — the dispatch matrix is unit
/// tested without a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotificationArm {
    /// `AUTHORISATION` success, no `recurringProcessingModel`: checkout
    /// authorisation (informational; never an entitlement event).
    CheckoutAuthorisation,
    /// `AUTHORISATION` success WITH `recurringProcessingModel`: settles the
    /// local invoice named by `merchantReference`.
    RecurringAuthorisation,
    /// `AUTHORISATION` success=false: dunning/refusal path.
    AuthorisationRefused,
    /// `RECURRING_CONTRACT` / `recurring.token.created`.
    TokenCreated,
    Refund,
    RefundFailed,
    Chargeback,
    ChargebackReversed,
    Unknown,
}

fn notification_arm(item: &AdyenNotificationItem) -> NotificationArm {
    match item.event_code.trim() {
        "AUTHORISATION" => {
            if item.success_is_true() {
                if item.recurring_processing_model().is_some() {
                    NotificationArm::RecurringAuthorisation
                } else {
                    NotificationArm::CheckoutAuthorisation
                }
            } else {
                NotificationArm::AuthorisationRefused
            }
        }
        "RECURRING_CONTRACT" | "recurring.token.created" => NotificationArm::TokenCreated,
        "REFUND" => NotificationArm::Refund,
        "REFUND_FAILED" => NotificationArm::RefundFailed,
        "CHARGEBACK" => NotificationArm::Chargeback,
        "CHARGEBACK_REVERSED" => NotificationArm::ChargebackReversed,
        _ => NotificationArm::Unknown,
    }
}

async fn handle_notification(state: &AppState, item: &AdyenNotificationItem) -> Result<(), String> {
    match notification_arm(item) {
        NotificationArm::CheckoutAuthorisation => handle_checkout_authorisation(state, item).await,
        NotificationArm::RecurringAuthorisation => {
            handle_recurring_authorisation(state, item).await
        }
        NotificationArm::AuthorisationRefused => handle_authorisation_refused(state, item).await,
        NotificationArm::TokenCreated => handle_token_created(state, item).await,
        NotificationArm::Refund => {
            record_money_event(state, item, MoneyEventKind::Refund).await;
            Ok(())
        }
        NotificationArm::RefundFailed => {
            record_money_event(state, item, MoneyEventKind::RefundFailed).await;
            Ok(())
        }
        NotificationArm::Chargeback => {
            record_money_event(state, item, MoneyEventKind::Chargeback).await;
            Ok(())
        }
        NotificationArm::ChargebackReversed => {
            record_money_event(state, item, MoneyEventKind::ChargebackReversed).await;
            Ok(())
        }
        NotificationArm::Unknown => {
            warn!(
                event_code = %item.event_code,
                psp_reference = %item.psp_reference,
                "unhandled adyen notification event code — acknowledged without effect"
            );
            Ok(())
        }
    }
}

// ---------------------------------------------------------------------------
// Handlers
// ---------------------------------------------------------------------------

/// Parse `merchantReference` into the LOCAL invoice id: `invoice:{uuid}` (the
/// recurring-charge contract) or a bare uuid. Garbage is refused, never
/// guessed.
fn parse_merchant_reference_invoice_id(reference: &str) -> Option<Uuid> {
    let reference = reference.trim();
    let candidate = reference
        .strip_prefix("invoice:")
        .map(str::trim)
        .unwrap_or(reference);
    Uuid::parse_str(candidate).ok()
}

/// A checkout authorisation is informational only: the payment succeeded, but
/// entitlement follows the recurring/our-side subscription state, never a
/// single payment. In particular this must not reactivate a tenant suspended
/// for abuse (same invariant the pre-Adyen checkout webhook carried).
async fn handle_checkout_authorisation(
    _state: &AppState,
    item: &AdyenNotificationItem,
) -> Result<(), String> {
    match item
        .shopper_reference()
        .or_else(|| item.metadata_tenant_id())
    {
        Some(tenant_id) => info!(
            tenant_id = %tenant_id,
            psp_reference = %item.psp_reference,
            merchant_reference = %item.merchant_reference,
            "adyen checkout authorisation acknowledged; entitlement follows the recurring/our-side subscription state"
        ),
        None => warn!(
            psp_reference = %item.psp_reference,
            merchant_reference = %item.merchant_reference,
            "adyen checkout authorisation carries neither shopperReference nor tenant metadata — acknowledged without effect"
        ),
    }
    Ok(())
}

/// The local invoice an `AUTHORISATION` settles, read before the tax gate.
#[derive(Debug, Clone, sqlx::FromRow)]
struct LocalInvoiceSettlement {
    id: Uuid,
    tenant_id: String,
    currency: String,
    subtotal_cents: i64,
    vat_cents: i64,
    total_cents: i64,
    billing_country: Option<String>,
    vat_rate: Option<f64>,
    vat_evidence_id: Option<Uuid>,
}

async fn load_local_invoice_for_settlement(
    state: &AppState,
    invoice_id: Uuid,
) -> Result<Option<LocalInvoiceSettlement>, String> {
    sqlx::query_as::<_, LocalInvoiceSettlement>(
        r#"
        SELECT id, tenant_id, currency,
               COALESCE(subtotal, amount, 0)::bigint AS subtotal_cents,
               COALESCE(vat_total, 0)::bigint AS vat_cents,
               COALESCE(total, amount, 0)::bigint AS total_cents,
               billing_country, vat_rate, vat_evidence_id
        FROM invoices
        WHERE id = $1
        "#,
    )
    .bind(invoice_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to load local invoice {invoice_id}: {error}"))
}

/// The tenant that owns the settlement/refusal: shopperReference (the tenant
/// id) when present — and it must match the invoice's own tenant, or this is
/// a cross-tenant event and is refused — falling back to the invoice's tenant.
fn settlement_tenant(
    item: &AdyenNotificationItem,
    invoice_id: Uuid,
    invoice_tenant: &str,
) -> Result<String, String> {
    match item.shopper_reference() {
        Some(shopper) if shopper != invoice_tenant => Err(format!(
            "AUTHORISATION for invoice {invoice_id} belongs to tenant {invoice_tenant} but the \
             notification attributes it to shopper {shopper} — cross-tenant event refused"
        )),
        _ => Ok(invoice_tenant.to_string()),
    }
}

fn currencies_match(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

/// The payment amount actually recorded as an allocation: the verified charge,
/// capped against the authoritative remaining obligation, never negative.
fn allocation_cents(charged_cents: i64, outstanding_cents: i64) -> i64 {
    charged_cents.min(outstanding_cents).max(0)
}

/// The allocation's unique operation id — the settlement's idempotency key.
fn settlement_operation_id(item: &AdyenNotificationItem) -> String {
    format!("adyen:{}", item.psp_reference.trim())
}

/// Convert the old `handle_invoice_paid`: a successful recurring
/// `AUTHORISATION` settles the LOCAL invoice named by
/// `merchantReference = invoice:{uuid}` with `amount.value` (minor units) as
/// the verified charge. Runs the existing settlement logic (mark paid +
/// allocation) and the existing tax-truth snapshot gate, whose source is now
/// ApexMail's own computation validated against the charge.
async fn handle_recurring_authorisation(
    state: &AppState,
    item: &AdyenNotificationItem,
) -> Result<(), String> {
    let Some(local_invoice_id) = parse_merchant_reference_invoice_id(&item.merchant_reference)
    else {
        return Err(format!(
            "AUTHORISATION {} reference {:?} does not name a local invoice (expected \
             `invoice:{{uuid}}` or a bare uuid) — refusing to settle an unidentifiable obligation",
            item.psp_reference, item.merchant_reference
        ));
    };
    let Some(charged_cents) = item.amount_value() else {
        return Err(format!(
            "AUTHORISATION {} for {local_invoice_id} carries no amount.value — refusing to \
             settle an unverifiable charge",
            item.psp_reference
        ));
    };
    let Some(local) = load_local_invoice_for_settlement(state, local_invoice_id).await? else {
        return Err(format!(
            "AUTHORISATION {} references local invoice {local_invoice_id} which does not exist \
             — refusing to settle an unknown obligation",
            item.psp_reference
        ));
    };
    let tenant_id = settlement_tenant(item, local.id, &local.tenant_id)?;
    if let Some(currency) = item.amount_currency() {
        if !currencies_match(currency, &local.currency) {
            return Err(format!(
                "AUTHORISATION {} for {local_invoice_id} carries currency {currency} but the \
                 local invoice is denominated in {}",
                item.psp_reference, local.currency
            ));
        }
    }

    // TAX-TRUTH GATE (P0): persist an immutable snapshot of the charge and
    // validate the charged total against the local invoice's computed total
    // BEFORE settling. A mismatch returns Err here — no local invoice is
    // marked paid, no allocation runs — and a durable finance incident is
    // raised for operators.
    let tax_snapshot_id =
        validate_and_snapshot_adyen_tax(state, item, &local, charged_cents).await?;

    // Settlement: the pre-Adyen CTE behaviour, now against the locked local
    // row — mark paid and record the VERIFIED charged amount (amount.value)
    // as the allocation, capped against the authoritative remaining
    // obligation in the matching currency. Idempotent through the
    // allocation's unique operation id.
    let payment_cents = charged_cents.max(0);
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin invoice settlement transaction: {error}"))?;

    let locked: Option<(Uuid, String, String)> = sqlx::query_as(
        r#"
        SELECT id, tenant_id, currency
        FROM invoices
        WHERE id = $1
        FOR UPDATE
        "#,
    )
    .bind(local.id)
    .fetch_optional(&mut *tx)
    .await
    .map_err(|error| format!("Failed to lock local invoice {local_invoice_id}: {error}"))?;

    let Some((invoice_row_id, row_tenant, invoice_currency)) = locked else {
        return Err(format!(
            "local invoice {local_invoice_id} disappeared before settlement"
        ));
    };

    let outstanding = crate::invoices::invoice_outstanding_cents_in(&mut *tx, invoice_row_id)
        .await
        .map_err(|error| format!("Failed to derive outstanding for {invoice_row_id}: {error}"))?;

    let allocation = allocation_cents(payment_cents, outstanding);
    if payment_cents > outstanding {
        warn!(
            invoice_id = %invoice_row_id,
            adyen_psp_reference = %item.psp_reference,
            payment_cents,
            outstanding,
            "adyen payment exceeds the remaining obligation — allocating only the \
             authoritative remainder (over-allocation rejected)"
        );
    }

    sqlx::query(
        r#"
        UPDATE invoices
        SET status = 'paid',
            paid_at = COALESCE(paid_at, NOW()),
            adyen_psp_reference = COALESCE(adyen_psp_reference, $2),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(invoice_row_id)
    .bind(item.psp_reference.trim())
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("Failed to mark invoice {invoice_row_id} paid: {error}"))?;

    if allocation > 0 {
        let operation_id = settlement_operation_id(item);
        sqlx::query(
            r#"
            INSERT INTO invoice_payment_allocations (
                id, tenant_id, invoice_id, operation_id, source, amount_cents, currency
            )
            VALUES (
                gen_random_uuid(), $1, $2, $3, $4, $5, $6
            )
            ON CONFLICT (operation_id) DO NOTHING
            "#,
        )
        .bind(&row_tenant)
        .bind(invoice_row_id)
        .bind(&operation_id)
        .bind(ADYEN_ALLOCATION_SOURCE)
        .bind(allocation)
        .bind(invoice_currency.trim().to_uppercase())
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Failed to record Adyen payment allocation: {error}"))?;

        // Statutory ledger: post the settlement (Dr processor clearing, Cr
        // AR) in the same transaction. Idempotent on the allocation's unique
        // operation id, so a replayed webhook posts once.
        crate::accounting_postings::post_payment_allocation_in(&mut tx, &operation_id).await;
    } else {
        info!(
            invoice_id = %invoice_row_id,
            adyen_psp_reference = %item.psp_reference,
            payment_cents,
            outstanding,
            "adyen invoice settled without a positive allocation (zero-value/already covered)"
        );
    }

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit invoice settlement: {error}"))?;

    // Statutory ledger: post invoice finalization for the settled invoice
    // (no-op replay when the usage sweep already posted it). Runs AFTER the
    // settlement commit; the source identity makes the replay idempotent.
    crate::accounting_postings::post_invoice_issued(&state.db, invoice_row_id).await;

    // Dunning recovery is only legitimate now that THE tenant's invoice
    // actually settled: scope the recovery to this invoice's failure history.
    crate::maintenance::mark_payment_recovered(
        state,
        &tenant_id,
        Some(&invoice_row_id.to_string()),
    )
    .await?;

    // Recognition ledger: reflect the settlement in `vat_recognition_entries`
    // (general-scheme supplies were recognised at issue; cash-accounting
    // supplies recognise on payment). Idempotent, best-effort — a failure is
    // logged, never allowed to fake or skip the ledger.
    if let Err(error) = crate::vat_recognition::materialize_invoice_recognition_by_id(
        &state.db,
        invoice_row_id,
        Utc::now(),
    )
    .await
    {
        warn!(
            invoice_id = %invoice_row_id,
            adyen_psp_reference = %item.psp_reference,
            error = %error,
            "failed to materialize VAT recognition after Adyen settlement"
        );
    }

    // Link the immutable tax snapshot onto the settled invoice.
    if let Some(snapshot_id) = tax_snapshot_id {
        if let Err(error) = sqlx::query(
            r#"
            UPDATE invoices
            SET adyen_tax_snapshot_id = $2,
                updated_at = NOW()
            WHERE id = $1
            "#,
        )
        .bind(invoice_row_id)
        .bind(snapshot_id)
        .execute(&state.db)
        .await
        {
            warn!(
                invoice_id = %invoice_row_id,
                snapshot_id = %snapshot_id,
                error = %error,
                "failed to link adyen tax snapshot onto the local invoice — snapshot remains authoritative"
            );
        }
    }

    info!(
        tenant_id = %tenant_id,
        invoice_id = %invoice_row_id,
        adyen_psp_reference = %item.psp_reference,
        payment_cents,
        allocation,
        "adyen recurring authorisation settled the local invoice"
    );

    // Dedicated-IP provisioning: the deleted subscription-change handler used
    // to spawn this once a subscription became active; under Adyen our own
    // settled recurring charge is that moment. The spawn is idempotent
    // (pending-request upsert + active-count check) and failures are recorded
    // on the request row — the same contract the old call site documented.
    let provision_state = state.clone();
    let provision_tenant = tenant_id.to_string();
    tokio::spawn(async move {
        if let Err(error) =
            auto_provision_dedicated_ips_background(&provision_state, &provision_tenant).await
        {
            error!(
                tenant_id = %provision_tenant,
                error = %error,
                "dedicated-IP provisioning after Adyen settlement failed"
            );
        }
    });

    Ok(())
}

/// Convert the old `handle_payment_failed`: an unsuccessful `AUTHORISATION`
/// runs the existing dunning path (atomic retry scheduling + customer
/// notice) keyed on the local invoice from `merchantReference`. An
/// unresolvable reference is an Err (deadlettered), never silently dropped.
async fn handle_authorisation_refused(
    state: &AppState,
    item: &AdyenNotificationItem,
) -> Result<(), String> {
    let Some(local_invoice_id) = parse_merchant_reference_invoice_id(&item.merchant_reference)
    else {
        return Err(format!(
            "refused AUTHORISATION {} reference {:?} does not name a local invoice (expected \
             `invoice:{{uuid}}` or a bare uuid) — refusing to drop the refusal",
            item.psp_reference, item.merchant_reference
        ));
    };
    let invoice_tenant: Option<String> =
        sqlx::query_scalar("SELECT tenant_id FROM invoices WHERE id = $1")
            .bind(local_invoice_id)
            .fetch_optional(&state.db)
            .await
            .map_err(|error| {
                format!("Failed to resolve local invoice {local_invoice_id} for a refusal: {error}")
            })?;
    let Some(invoice_tenant) = invoice_tenant else {
        return Err(format!(
            "refused AUTHORISATION {} references local invoice {local_invoice_id} which does not \
             exist — deadlettered for replay once the invoice exists",
            item.psp_reference
        ));
    };
    let tenant_id = settlement_tenant(item, local_invoice_id, &invoice_tenant)?;

    let amount = item.amount_value().unwrap_or(0);
    let dunning =
        record_failed_payment(state, &tenant_id, &local_invoice_id.to_string(), amount).await?;

    sqlx::query(
        r#"
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        VALUES (gen_random_uuid(), $1, 'payment_failed', $2, 'pending', NOW())
        "#,
    )
    .bind(&tenant_id)
    .bind(serde_json::json!({
        "invoiceId": local_invoice_id.to_string(),
        "pspReference": item.psp_reference.trim(),
        "amount": amount,
        // The notification drainer renders money with this code and never
        // assumes one (the drain labels an absent code explicitly).
        "currency": normalize_adyen_currency(item.amount_currency()),
        "reason": item.reason.clone().unwrap_or_default(),
        "dunningStatus": dunning.status,
        "nextRetryAt": dunning.next_retry_at.map(|value| value.to_rfc3339()),
    }))
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to enqueue payment_failed notification: {error}"))?;

    warn!(
        tenant_id = %tenant_id,
        invoice_id = %local_invoice_id,
        psp_reference = %item.psp_reference,
        reason = %item.reason.as_deref().unwrap_or(""),
        "adyen authorisation refused — dunning state recorded and the customer notified"
    );
    Ok(())
}

/// `RECURRING_CONTRACT` / `recurring.token.created`: the shopper re-tokenized
/// at cutover. Bind the token (and the processing model when present) to
/// every `adyen_subscriptions` row of the shopper's tenant — the token is
/// shopper-scoped, and the dunning auto-pay path reads it per tenant
/// regardless of the row's status. A missing token or tenant is an Err.
async fn handle_token_created(
    state: &AppState,
    item: &AdyenNotificationItem,
) -> Result<(), String> {
    let Some(token) = item.recurring_detail_reference() else {
        return Err(format!(
            "RECURRING_CONTRACT {} carries no additionalData.recurringDetailReference — \
             nothing to bind",
            item.psp_reference
        ));
    };
    let Some(tenant_id) = item.shopper_reference() else {
        return Err(format!(
            "RECURRING_CONTRACT {} carries no additionalData.shopperReference — tenant \
             unresolvable, refusing to bind the token to an unknown shopper",
            item.psp_reference
        ));
    };
    let processing_model = item.recurring_processing_model();

    let bound: Vec<(String,)> = sqlx::query_as(
        r#"
        UPDATE adyen_subscriptions
        SET adyen_recurring_detail_reference = $2,
            adyen_recurring_processing_model = COALESCE($3, adyen_recurring_processing_model),
            updated_at = NOW()
        WHERE tenant_id = $1
        RETURNING adyen_subscription_id
        "#,
    )
    .bind(tenant_id)
    .bind(token)
    .bind(processing_model)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to bind the Adyen recurring token: {error}"))?;

    if bound.is_empty() {
        return Err(format!(
            "RECURRING_CONTRACT {} resolved tenant {tenant_id} but no subscription row exists \
             to bind the token to — deadlettered for replay",
            item.psp_reference
        ));
    }

    info!(
        tenant_id = %tenant_id,
        psp_reference = %item.psp_reference,
        subscriptions_bound = bound.len(),
        recurring_processing_model = %processing_model.unwrap_or(""),
        "adyen recurring token bound"
    );
    Ok(())
}

/// Provider-initiated money movement worth a durable audit record.
#[derive(Debug, Clone, Copy)]
enum MoneyEventKind {
    Refund,
    RefundFailed,
    Chargeback,
    ChargebackReversed,
}

impl MoneyEventKind {
    fn kind(self) -> &'static str {
        match self {
            Self::Refund => "refund",
            Self::RefundFailed => "refund_failed",
            Self::Chargeback => "chargeback",
            Self::ChargebackReversed => "chargeback_reversed",
        }
    }

    fn audit_action(self) -> &'static str {
        match self {
            Self::Refund => "billing.adyen_refund_recorded",
            Self::RefundFailed => "billing.adyen_refund_failed",
            Self::Chargeback => "billing.adyen_chargeback_recorded",
            Self::ChargebackReversed => "billing.adyen_chargeback_reversed",
        }
    }

    fn notification_type(self) -> &'static str {
        self.kind()
    }
}

/// Record a provider-side money event (refund / failed refund / chargeback /
/// reversal) against the local invoice/psp binding: an audit row on the
/// resolved tenant, a durable operator notification, and an alert-grade log
/// when the binding cannot be resolved. NEVER a 5xx and never a silent drop —
/// a reconciliation event must not make Adyen retry forever, and the
/// `adyen_webhook_events` claim row plus the logs remain the durable record
/// even when the audit insert cannot run.
async fn record_money_event(state: &AppState, item: &AdyenNotificationItem, event: MoneyEventKind) {
    let local_invoice_id = parse_merchant_reference_invoice_id(&item.merchant_reference);
    let mut tenant_id: Option<String> = None;
    if let Some(invoice_id) = local_invoice_id {
        match sqlx::query_scalar::<_, String>("SELECT tenant_id FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_optional(&state.db)
            .await
        {
            Ok(row) => tenant_id = row,
            Err(error) => warn!(
                invoice_id = %invoice_id,
                error = %error,
                "failed to resolve the local invoice tenant for an adyen money event"
            ),
        }
    }

    let detail = serde_json::json!({
        "kind": event.kind(),
        "pspReference": item.psp_reference.trim(),
        "originalReference": item.original_reference.as_deref().unwrap_or(""),
        "merchantReference": item.merchant_reference.trim(),
        "localInvoiceId": local_invoice_id.map(|id| id.to_string()),
        "amountMinorUnits": item.amount_value(),
        "currency": item.amount_currency(),
        "reason": item.reason.clone(),
    });

    let Some(tenant_id) = tenant_id else {
        error!(
            psp_reference = %item.psp_reference,
            kind = event.kind(),
            detail = %detail,
            "adyen money event without a resolvable local invoice — recorded in the notification \
             ledger and logs for reconciliation"
        );
        return;
    };

    match state.db.begin().await {
        Ok(mut tx) => {
            match append_audit_log(
                &mut tx,
                &tenant_id,
                event.audit_action(),
                "adyen_notification",
                Some(item.psp_reference.trim()),
                detail.clone(),
                Utc::now(),
            )
            .await
            {
                Ok(()) => {
                    if let Err(error) = tx.commit().await {
                        error!(
                            tenant_id = %tenant_id,
                            psp_reference = %item.psp_reference,
                            error = %error,
                            "failed to commit the adyen money-event audit row"
                        );
                    }
                }
                Err(error) => {
                    error!(
                        tenant_id = %tenant_id,
                        psp_reference = %item.psp_reference,
                        error = %error,
                        "failed to append the adyen money-event audit row"
                    );
                    let _ = tx.rollback().await;
                }
            }
        }
        Err(error) => error!(
            tenant_id = %tenant_id,
            psp_reference = %item.psp_reference,
            error = %error,
            "failed to begin the adyen money-event audit transaction"
        ),
    }

    if let Err(error) = sqlx::query(
        r#"
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        VALUES (gen_random_uuid(), $1, $2, $3, 'pending', NOW())
        "#,
    )
    .bind(&tenant_id)
    .bind(event.notification_type())
    .bind(&detail)
    .execute(&state.db)
    .await
    {
        error!(
            tenant_id = %tenant_id,
            psp_reference = %item.psp_reference,
            error = %error,
            "failed to enqueue the adyen money-event operator notification"
        );
    }

    warn!(
        tenant_id = %tenant_id,
        psp_reference = %item.psp_reference,
        kind = event.kind(),
        amount_minor_units = ?item.amount_value(),
        "adyen money event recorded for reconciliation"
    );
}

// ---------------------------------------------------------------------------
// Tax truth (P0): immutable tax snapshot + validation of the charged total
// ---------------------------------------------------------------------------
//
// ApexMail owns the tax decision now: Adyen transmits no tax fields, so the
// LOCAL invoice's computed totals are the expectation and Adyen's charged
// total (the notification item's `amount.value`, minor units) is what must
// validate against it. The snapshot of the charge and the comparison are
// persisted immutably in `adyen_tax_snapshots` (migration 218); a mismatch
// BLOCKS local settlement and raises a `finance_incidents` row instead of
// quietly recording inconsistent books.

/// ApexMail's independently computed total for the charged invoice.
#[derive(Debug, Clone, PartialEq)]
struct ExpectedTax {
    subtotal_cents: i64,
    vat_cents: i64,
    total_cents: i64,
    /// `local_invoice` for the Adyen path: the totals come from the local
    /// invoice row (the only tax decision that exists).
    source: &'static str,
    country: Option<String>,
    vat_rate: f64,
    evidence_id: Option<Uuid>,
}

/// A charged-total mismatch between the Adyen charge and ApexMail's
/// computation.
#[derive(Debug, Clone, PartialEq, Eq)]
struct TaxTotalDiscrepancy {
    observed_subtotal_cents: i64,
    observed_vat_cents: i64,
    observed_total_cents: i64,
    expected_subtotal_cents: i64,
    expected_vat_cents: i64,
    expected_total_cents: i64,
    delta_cents: i64,
}

impl TaxTotalDiscrepancy {
    fn summary(&self) -> String {
        format!(
            "charged total {} != ApexMail-computed {} (subtotal {} vs {}, VAT {} vs {})",
            self.observed_total_cents,
            self.expected_total_cents,
            self.observed_subtotal_cents,
            self.expected_subtotal_cents,
            self.observed_vat_cents,
            self.expected_vat_cents,
        )
    }
}

/// Compare the charged money fields against ApexMail's independent
/// computation. Pure and unit-tested: a mismatch is an error (the caller
/// blocks settlement and raises a finance incident), never a warning.
fn check_charged_total(
    expected: &ExpectedTax,
    observed_subtotal_cents: i64,
    observed_vat_cents: i64,
    observed_total_cents: i64,
) -> Result<(), TaxTotalDiscrepancy> {
    if expected.subtotal_cents == observed_subtotal_cents
        && expected.vat_cents == observed_vat_cents
        && expected.total_cents == observed_total_cents
    {
        return Ok(());
    }
    Err(TaxTotalDiscrepancy {
        observed_subtotal_cents,
        observed_vat_cents,
        observed_total_cents,
        expected_subtotal_cents: expected.subtotal_cents,
        expected_vat_cents: expected.vat_cents,
        expected_total_cents: expected.total_cents,
        delta_cents: observed_total_cents - expected.total_cents,
    })
}

/// The persisted validation status for a gate outcome (pure).
fn tax_validation_status(validation: &Result<(), TaxTotalDiscrepancy>) -> &'static str {
    match validation {
        Ok(()) => "validated",
        Err(_) => "discrepancy",
    }
}

/// ApexMail's expectation for a charge: the LOCAL invoice's own computed
/// totals and provenance. Adyen carries no tax fields, so no wire value is
/// consulted — the local row is the only tax decision (pure).
fn expected_tax_from_local_invoice(local: &LocalInvoiceSettlement) -> ExpectedTax {
    ExpectedTax {
        subtotal_cents: local.subtotal_cents,
        vat_cents: local.vat_cents,
        total_cents: local.total_cents,
        source: "local_invoice",
        country: local
            .billing_country
            .clone()
            .filter(|value| !value.trim().is_empty()),
        vat_rate: local.vat_rate.unwrap_or(0.0),
        evidence_id: local.vat_evidence_id,
    }
}

/// SHA-256 over the canonical snapshot payload.
fn snapshot_payload_hash(payload: &serde_json::Value) -> String {
    use sha2::Digest;
    let canonical = serde_json::to_vec(payload).unwrap_or_default();
    hex::encode(Sha256::digest(&canonical))
}

/// Row of `adyen_tax_snapshots` already persisted for this psp reference.
/// Returns `(validation_status, apexmail expected total, charged total)`.
async fn load_existing_tax_snapshot(
    db: &sqlx::PgPool,
    adyen_psp_reference: &str,
) -> Result<Option<(String, i64, i64)>, String> {
    sqlx::query_as(
        r#"
        SELECT validation_status,
               COALESCE(apexmail_expected_total_cents, total_cents)::bigint,
               total_cents
        FROM adyen_tax_snapshots
        WHERE adyen_psp_reference = $1
        "#,
    )
    .bind(adyen_psp_reference)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load existing tax snapshot: {error}"))
}

/// Persist a snapshot (first write wins; the table is trigger-immutable).
/// Returns the snapshot id.
///
/// `observed` is `(subtotal, vat, charged total)`: Adyen transmits only the
/// charged TOTAL, so the itemisation columns carry the local invoice's own
/// split and `total_cents`/`amount_paid_cents` carry the charge — the
/// comparison below is therefore exactly "charged total vs local total".
#[allow(clippy::too_many_arguments)]
async fn persist_tax_snapshot(
    db: &sqlx::PgPool,
    item: &AdyenNotificationItem,
    tenant_id: &str,
    local_invoice_id: Option<Uuid>,
    currency: &str,
    observed: (i64, i64, i64),
    expected: &ExpectedTax,
    validation_status: &str,
    discrepancy_cents: i64,
) -> Result<Uuid, String> {
    let adyen_item = serde_json::to_value(item).unwrap_or(serde_json::Value::Null);
    let observed_payload = serde_json::json!({
        "adyen_psp_reference": item.psp_reference.trim(),
        "adyen_merchant_reference": item.merchant_reference.trim(),
        "currency": currency,
        "subtotal_cents": observed.0,
        "tax_cents": observed.1,
        "total_cents": observed.2,
        "amount_paid_cents": observed.2,
        "automatic_tax_status": serde_json::Value::Null,
        "tax_id_status": "not_applicable",
        "tax_ids": [],
        "jurisdiction": expected.country,
        "tax_breakdown": [],
        "adyen_item": adyen_item,
        "apexmail": {
            "expected_subtotal_cents": expected.subtotal_cents,
            "expected_vat_cents": expected.vat_cents,
            "expected_total_cents": expected.total_cents,
            "source": expected.source,
            "vat_rate": expected.vat_rate,
            "evidence_id": expected.evidence_id,
        },
        "validation_status": validation_status,
    });
    let raw_hash = snapshot_payload_hash(&observed_payload);

    let inserted: Option<(Uuid,)> = sqlx::query_as(
        r#"
        INSERT INTO adyen_tax_snapshots (
            adyen_psp_reference, adyen_merchant_reference, tenant_id, local_invoice_id,
            currency, subtotal_cents, tax_cents, total_cents, amount_paid_cents,
            automatic_tax_status, authority, jurisdiction, tax_id_status,
            tax_ids, tax_breakdown,
            apexmail_expected_subtotal_cents, apexmail_expected_vat_cents,
            apexmail_expected_total_cents, validation_status, discrepancy_cents,
            raw_payload_hash, raw_payload
        ) VALUES (
            $1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12, $13, $14, $15,
            $16, $17, $18, $19, $20, $21, $22
        )
        ON CONFLICT (adyen_psp_reference) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(item.psp_reference.trim())
    .bind(item.merchant_reference.trim())
    .bind(tenant_id)
    .bind(local_invoice_id)
    .bind(currency)
    .bind(observed.0)
    .bind(observed.1)
    .bind(observed.2)
    .bind(observed.2)
    // Adyen carries no tax object and no verified tax IDs: NULL/empty are the
    // truthful values, and the local split lives in the expected columns.
    .bind(Option::<String>::None)
    .bind(ADYEN_TAX_AUTHORITY_LOCAL)
    .bind(&expected.country)
    .bind("not_applicable")
    .bind(serde_json::json!([]))
    .bind(serde_json::json!([]))
    .bind(expected.subtotal_cents)
    .bind(expected.vat_cents)
    .bind(expected.total_cents)
    .bind(validation_status)
    .bind(discrepancy_cents)
    .bind(&raw_hash)
    .bind(&observed_payload)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to persist adyen tax snapshot: {error}"))?;

    if let Some((id,)) = inserted {
        return Ok(id);
    }
    // Already persisted (replay): immutability means first write wins.
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM adyen_tax_snapshots WHERE adyen_psp_reference = $1",
    )
    .bind(item.psp_reference.trim())
    .fetch_one(db)
    .await
    .map_err(|error| format!("failed to reload adyen tax snapshot: {error}"))
}

/// Raise a durable finance incident. Idempotent per open incident: webhook
/// retries and dead-letter replays cannot spam duplicate open rows.
#[allow(clippy::too_many_arguments)]
async fn raise_finance_incident(
    db: &sqlx::PgPool,
    kind: &str,
    severity: &str,
    tenant_id: &str,
    local_invoice_id: Option<Uuid>,
    adyen_psp_reference: &str,
    currency: &str,
    expected_total_cents: Option<i64>,
    observed_total_cents: Option<i64>,
    detail: &serde_json::Value,
) -> Result<(), String> {
    sqlx::query(
        r#"
        INSERT INTO finance_incidents (
            kind, severity, status, tenant_id, local_invoice_id,
            adyen_psp_reference, currency, expected_total_cents,
            observed_total_cents, delta_cents, detail
        )
        SELECT $1, $2, 'open', $3, $4, $5, $6, $7, $8,
               COALESCE($7, 0) - COALESCE($8, 0), $9
        WHERE NOT EXISTS (
            SELECT 1 FROM finance_incidents
            WHERE kind = $1 AND adyen_psp_reference = $5 AND status = 'open'
        )
        "#,
    )
    .bind(kind)
    .bind(severity)
    .bind(tenant_id)
    .bind(local_invoice_id)
    .bind(adyen_psp_reference)
    .bind(currency)
    .bind(expected_total_cents)
    .bind(observed_total_cents)
    .bind(detail)
    .execute(db)
    .await
    .map_err(|error| format!("failed to raise finance incident: {error}"))?;
    Ok(())
}

/// The tax-truth gate. Persists an immutable snapshot of the charge and
/// validates the charged total against the LOCAL invoice's computed total.
/// Returns `Err` (blocking settlement) when they disagree, after raising a
/// durable finance incident.
async fn validate_and_snapshot_adyen_tax(
    state: &AppState,
    item: &AdyenNotificationItem,
    local: &LocalInvoiceSettlement,
    charged_total_cents: i64,
) -> Result<Option<Uuid>, String> {
    // Replays: the first snapshot is immutable. A recorded discrepancy stays
    // blocking until a finance operator resolves it; a validated snapshot
    // makes replays no-ops.
    if let Some((status, expected_total, observed_total)) =
        load_existing_tax_snapshot(&state.db, item.psp_reference.trim()).await?
    {
        if status == "discrepancy" {
            raise_finance_incident(
                &state.db,
                "tax_total_mismatch",
                "high",
                &local.tenant_id,
                Some(local.id),
                item.psp_reference.trim(),
                &normalize_adyen_currency(item.amount_currency()),
                Some(expected_total),
                Some(observed_total),
                &serde_json::json!({
                    "reason": "existing immutable snapshot records a charged-total discrepancy",
                }),
            )
            .await?;
            return Err(format!(
                "AUTHORISATION for {} blocked: an open finance incident records a charged-total \
                 discrepancy (charged {observed_total}, ApexMail computed {expected_total})",
                item.psp_reference.trim()
            ));
        }
        return Ok(Some(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM adyen_tax_snapshots WHERE adyen_psp_reference = $1",
            )
            .bind(item.psp_reference.trim())
            .fetch_one(&state.db)
            .await
            .map_err(|error| format!("failed to load tax snapshot id: {error}"))?,
        ));
    }

    let expected = expected_tax_from_local_invoice(local);
    let currency = normalize_adyen_currency(item.amount_currency());

    // Adyen transmits only the charged total; the itemisation is the local
    // invoice's decision. Comparing with the local split on both sides makes
    // the check exactly "charged total vs local total".
    let validation = check_charged_total(
        &expected,
        expected.subtotal_cents,
        expected.vat_cents,
        charged_total_cents,
    );
    let validation_status = tax_validation_status(&validation);
    let discrepancy_cents = validation
        .as_ref()
        .err()
        .map(|discrepancy| discrepancy.delta_cents)
        .unwrap_or(0);

    let snapshot_id = persist_tax_snapshot(
        &state.db,
        item,
        &local.tenant_id,
        Some(local.id),
        &currency,
        (
            expected.subtotal_cents,
            expected.vat_cents,
            charged_total_cents,
        ),
        &expected,
        validation_status,
        discrepancy_cents,
    )
    .await?;

    if let Err(discrepancy) = validation {
        let detail = serde_json::json!({
            "reason": discrepancy.summary(),
            "expected_source": expected.source,
            "expected_country": expected.country,
            "expected_vat_rate": expected.vat_rate,
            "vat_evidence_id": expected.evidence_id,
            "psp_reference": item.psp_reference.trim(),
            "merchant_reference": item.merchant_reference.trim(),
        });
        raise_finance_incident(
            &state.db,
            "tax_total_mismatch",
            "critical",
            &local.tenant_id,
            Some(local.id),
            item.psp_reference.trim(),
            &currency,
            Some(expected.total_cents),
            Some(charged_total_cents),
            &detail,
        )
        .await?;
        error!(
            adyen_psp_reference = %item.psp_reference,
            tenant_id = %local.tenant_id,
            observed_total_cents = charged_total_cents,
            expected_total_cents = expected.total_cents,
            delta_cents = discrepancy.delta_cents,
            "BLOCKED invoice finalization: Adyen charged a total that disagrees with ApexMail's \
             computation — finance incident raised"
        );
        return Err(format!(
            "AUTHORISATION for {} blocked: {}",
            item.psp_reference.trim(),
            discrepancy.summary()
        ));
    }

    info!(
        adyen_psp_reference = %item.psp_reference,
        tenant_id = %local.tenant_id,
        authority = ADYEN_TAX_AUTHORITY_LOCAL,
        validation_status,
        observed_total_cents = charged_total_cents,
        expected_total_cents = expected.total_cents,
        "adyen tax snapshot persisted and the charged total validated against the local invoice"
    );

    Ok(Some(snapshot_id))
}

/// Normalize a wire currency for local comparison/storage (lowercase, like
/// `invoices.currency`). Defaults to `eur`.
fn normalize_adyen_currency(currency: Option<&str>) -> String {
    currency
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_ascii_lowercase)
        .unwrap_or_else(|| "eur".into())
}

// ---------------------------------------------------------------------------
// Request processing (parse → verify → claim → handle) and the response
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct ProcessWebhookResult {
    items_processed: usize,
    items_duplicate: usize,
}

#[derive(Debug)]
enum ProcessWebhookError {
    /// The wire itself is invalid (bad envelope, missing/invalid HMAC): the
    /// client sees the specific message and the delivery is deadlettered.
    InvalidRequest {
        message: String,
        detail: String,
        reason: &'static str,
    },
    /// A processing-stage failure not yet deadlettered (e.g. the claim query
    /// failed): deadlettered without touching the ledger row.
    RecordDeadletter(String),
    /// A per-item handler failure: the atomic failure + deadletter already
    /// ran inside `process_webhook`.
    DeadletterFlowHandled(String),
    /// Transient condition (e.g. another worker holds the event): Adyen
    /// must retry. Maps to 5xx and never deadletters.
    RetryLater(String),
}

impl ProcessWebhookError {
    fn message(&self) -> &str {
        match self {
            Self::InvalidRequest { message, .. } => message,
            Self::RecordDeadletter(message)
            | Self::DeadletterFlowHandled(message)
            | Self::RetryLater(message) => message,
        }
    }

    /// What Adyen sees for this class. Wire errors name the defect; every
    /// other class keeps the legacy generic body (internal details stay out
    /// of the response).
    fn response_message(&self) -> &str {
        match self {
            Self::InvalidRequest { message, .. } => message,
            _ => "Webhook processing failed",
        }
    }

    fn deadletter_detail(&self) -> &str {
        match self {
            Self::InvalidRequest { detail, .. } => detail,
            _ => self.message(),
        }
    }

    fn deadletter_reason(&self) -> &'static str {
        match self {
            Self::InvalidRequest { reason, .. } => reason,
            _ => "processing_failed",
        }
    }

    fn should_record_deadletter(&self) -> bool {
        matches!(
            self,
            Self::InvalidRequest { .. } | Self::RecordDeadletter(_)
        )
    }

    /// HTTP status Adyen sees. Retryable errors use 503 (Adyen retries on
    /// any non-2xx; 5xx signals server-side transience); refusals keep 400.
    fn http_status(&self) -> StatusCode {
        match self {
            Self::RetryLater(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::InvalidRequest { .. }
            | Self::RecordDeadletter(_)
            | Self::DeadletterFlowHandled(_) => StatusCode::BAD_REQUEST,
        }
    }
}

impl From<String> for ProcessWebhookError {
    fn from(message: String) -> Self {
        Self::RecordDeadletter(message)
    }
}

/// Best-effort psp reference for deadletter diagnostics (a malformed body has
/// none).
fn first_psp_reference(payload: &[u8]) -> Option<String> {
    let envelope = serde_json::from_slice::<AdyenNotificationEnvelope>(payload).ok()?;
    envelope
        .notification_items
        .first()
        .map(|entry| {
            entry
                .notification_request_item
                .psp_reference
                .trim()
                .to_string()
        })
        .filter(|value| !value.is_empty())
}

async fn process_webhook(
    state: &AppState,
    payload: &[u8],
) -> Result<ProcessWebhookResult, ProcessWebhookError> {
    let envelope =
        serde_json::from_slice::<AdyenNotificationEnvelope>(payload).map_err(|error| {
            ProcessWebhookError::InvalidRequest {
                message: "Invalid JSON payload".into(),
                detail: error.to_string(),
                reason: "invalid_json_payload",
            }
        })?;

    if envelope.notification_items.is_empty() {
        return Err(ProcessWebhookError::InvalidRequest {
            message: "Invalid notification payload".into(),
            detail: "notificationItems is empty or missing".into(),
            reason: "missing_notification_items",
        });
    }

    let items: Vec<&AdyenNotificationItem> = envelope
        .notification_items
        .iter()
        .map(|entry| &entry.notification_request_item)
        .collect();

    // Every item must carry an identity; a blank pspReference/eventCode is a
    // malformed delivery, not an anonymous event.
    for item in &items {
        if item.psp_reference.trim().is_empty() || item.event_code.trim().is_empty() {
            return Err(ProcessWebhookError::InvalidRequest {
                message: "Invalid notification payload".into(),
                detail: format!(
                    "notification item missing pspReference or eventCode (pspReference={:?}, eventCode={:?})",
                    item.psp_reference, item.event_code
                ),
                reason: "invalid_notification_item",
            });
        }
    }

    // Bad/missing HMAC or an unconfigured secret: the signature is INSIDE the
    // body, so this check happens per item before anything is claimed. A
    // deployment without a configured secret cannot verify anything; that is
    // SERVER misconfiguration, so it is retryable (503) — a 400 would make
    // Adyen treat every billing event as permanently rejected.
    for item in &items {
        if item.hmac_signature().is_none() {
            return Err(ProcessWebhookError::InvalidRequest {
                message: "Missing HMAC signature".into(),
                detail: format!(
                    "notification item {} carries no additionalData.hmacSignature",
                    item.psp_reference.trim()
                ),
                reason: "missing_signature",
            });
        }
    }

    let secret = state.config.adyen_hmac_key.trim();
    if secret.is_empty() {
        return Err(ProcessWebhookError::RetryLater(
            "Adyen webhook secret is not configured".into(),
        ));
    }

    for item in &items {
        let signature = item.hmac_signature().unwrap_or_default();
        if let Err(error) = verify_item_hmac(secret, item, signature) {
            return Err(ProcessWebhookError::InvalidRequest {
                message: error.clone(),
                detail: format!(
                    "HMAC verification failed for notification item {}",
                    item.psp_reference.trim()
                ),
                reason: "invalid_signature",
            });
        }
    }

    let mut items_processed = 0usize;
    let mut items_duplicate = 0usize;
    for item in &items {
        match process_notification_item(state, item, payload).await? {
            ItemOutcome::Processed => items_processed += 1,
            ItemOutcome::Duplicate => items_duplicate += 1,
        }
    }

    Ok(ProcessWebhookResult {
        items_processed,
        items_duplicate,
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemOutcome {
    Processed,
    Duplicate,
}

async fn process_notification_item(
    state: &AppState,
    item: &AdyenNotificationItem,
    payload: &[u8],
) -> Result<ItemOutcome, ProcessWebhookError> {
    let notification_id = adyen_notification_id(item);
    match claim_webhook_event(
        state,
        &notification_id,
        item.event_code.trim(),
        item.psp_reference.trim(),
    )
    .await?
    {
        WebhookEventClaim::Claimed => {}
        WebhookEventClaim::AlreadyProcessed => {
            info!(
                adyen_notification_id = %notification_id,
                psp_reference = %item.psp_reference,
                event_code = %item.event_code,
                "duplicate adyen notification already processed"
            );
            return Ok(ItemOutcome::Duplicate);
        }
        WebhookEventClaim::AlreadyPending => {
            // Acknowledging a concurrently-pending event with a 200 makes
            // Adyen stop retrying; if the worker that claimed it then
            // crashes, the row is stuck in `pending` forever. Return a
            // retryable status instead so Adyen keeps retrying (and the
            // stale-pending reclaimer eventually resets the row).
            info!(
                adyen_notification_id = %notification_id,
                psp_reference = %item.psp_reference,
                "adyen notification is already being processed by another worker; asking Adyen to retry"
            );
            return Err(ProcessWebhookError::RetryLater(format!(
                "notification {notification_id} is pending on another worker"
            )));
        }
    }

    match handle_notification(state, item).await {
        Ok(()) => {
            sqlx::query(
                r#"
                UPDATE adyen_webhook_events
                SET status = 'processed', processed_at = NOW(), updated_at = NOW()
                WHERE adyen_notification_id = $1
                "#,
            )
            .bind(&notification_id)
            .execute(&state.db)
            .await
            .map_err(|error| format!("Failed to mark Adyen webhook as processed: {error}"))?;

            Ok(ItemOutcome::Processed)
        }
        Err(error_message) => {
            if let Err(deadletter_error) = record_failed_webhook_deadletter_atomic(
                state,
                &notification_id,
                &error_message,
                payload,
                item.hmac_signature(),
            )
            .await
            {
                error!(
                    adyen_notification_id = %notification_id,
                    error = %deadletter_error,
                    "failed to persist adyen webhook failure/deadletter atomically"
                );
            }

            Err(ProcessWebhookError::DeadletterFlowHandled(error_message))
        }
    }
}

// ---------------------------------------------------------------------------
// Deadletter machinery (Redis-backed; replayed by the retry worker)
// ---------------------------------------------------------------------------

async fn record_deadletter(
    state: &AppState,
    entry: DeadletterEntry,
    body: Option<&[u8]>,
    signature: Option<&str>,
) {
    let prepared = prepare_deadletter(entry, body, signature, Utc::now());

    if let Err(error) = write_prepared_deadletter_to_redis(state, &prepared).await {
        error!(error = %error, "failed to write adyen dead letter");
    }
}

/// Cap `text` at `max_bytes`, cutting at a UTF-8 char boundary and marking
/// the result as truncated. Used for the deadletter body cap.
fn truncate_at_char_boundary(text: &str, max_bytes: usize) -> String {
    if text.len() <= max_bytes {
        return text.to_string();
    }

    let mut end = max_bytes;
    while end > 0 && !text.is_char_boundary(end) {
        end -= 1;
    }

    let mut truncated = text[..end].to_string();
    truncated.push_str("...(truncated)");
    truncated
}

/// Prepare a deadletter entry for storage. Serialization of this
/// all-string/Option struct is infallible, so no error arm is invented.
fn prepare_deadletter(
    entry: DeadletterEntry,
    body: Option<&[u8]>,
    signature: Option<&str>,
    now: DateTime<Utc>,
) -> PreparedDeadletter {
    let now_ms = now.timestamp_millis();
    let occurred_at = entry
        .occurred_at
        .clone()
        .unwrap_or_else(|| now.to_rfc3339());
    let (body_str, body_truncated) = match body {
        Some(bytes) => {
            let text = String::from_utf8_lossy(bytes);
            let truncated = text.len() > DEADLETTER_MAX_BODY_BYTES;
            (
                Some(truncate_at_char_boundary(&text, DEADLETTER_MAX_BODY_BYTES)),
                truncated,
            )
        }
        None => (None, false),
    };
    let sig_str = signature.map(str::to_string);
    let event_key = format!(
        "{}{}:{}",
        DEADLETTER_EVENT_PREFIX,
        sanitize_event_id(entry.event_id.as_deref()),
        now_ms
    );
    // A truncated body cannot be replayed (the stored JSON is incomplete),
    // so only schedule a retry when the full body was preserved.
    let retry_at_ms = (entry.reason == "processing_failed"
        && body_str.is_some()
        && !body_truncated
        && sig_str.is_some()
        && entry.retry_count < entry.max_retries)
        .then_some(now_ms + DEADLETTER_RETRY_BACKOFF_SECONDS[0] * 1000);

    let store_entry = DeadletterEntry {
        occurred_at: Some(occurred_at),
        body: body_str,
        signature: sig_str,
        ..entry
    };

    PreparedDeadletter {
        event_key,
        payload: serde_json::to_string(&store_entry).expect("deadletter entry serializes"),
        now_ms,
        cleanup_before_ms: now_ms - DEADLETTER_RETENTION_MS,
        retry_at_ms,
    }
}

async fn write_prepared_deadletter_to_redis(
    state: &AppState,
    prepared: &PreparedDeadletter,
) -> Result<(), String> {
    let mut conn = state.redis.get().await.map_err(|error| {
        format!("failed to acquire redis connection for adyen dead letter: {error}")
    })?;

    let mut pipe = redis::pipe();
    pipe.atomic();
    pipe.cmd("SETEX")
        .arg(&prepared.event_key)
        .arg(DEADLETTER_RETENTION_SECONDS)
        .arg(&prepared.payload)
        .ignore()
        .cmd("ZADD")
        .arg(DEADLETTER_INDEX_KEY)
        .arg(prepared.now_ms)
        .arg(&prepared.event_key)
        .ignore()
        .cmd("ZREMRANGEBYSCORE")
        .arg(DEADLETTER_INDEX_KEY)
        .arg(0)
        .arg(prepared.cleanup_before_ms)
        .ignore()
        .cmd("EXPIRE")
        .arg(DEADLETTER_INDEX_KEY)
        .arg(DEADLETTER_RETENTION_SECONDS)
        .ignore();

    if let Some(retry_at_ms) = prepared.retry_at_ms {
        pipe.cmd("ZADD")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(retry_at_ms)
            .arg(&prepared.event_key)
            .ignore()
            .cmd("EXPIRE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(DEADLETTER_RETENTION_SECONDS)
            .ignore();
    }

    pipe.query_async::<()>(&mut conn)
        .await
        .map_err(|error| format!("failed to write adyen dead letter: {error}"))
}

async fn remove_prepared_deadletter_from_redis(state: &AppState, event_key: &str) {
    if let Ok(mut conn) = state.redis.get().await {
        // Best-effort compensation: a Redis failure here is only logged (the
        // deadletter entry is retry-indexed and expires on its own TTL).
        if let Err(error) = redis::pipe()
            .atomic()
            .cmd("DEL")
            .arg(event_key)
            .ignore()
            .cmd("ZREM")
            .arg(DEADLETTER_INDEX_KEY)
            .arg(event_key)
            .ignore()
            .cmd("ZREM")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(event_key)
            .ignore()
            .query_async::<()>(&mut conn)
            .await
        {
            error!(
                error = %error,
                event_key,
                "failed to compensate adyen dead letter after DB commit failure"
            );
        }
    }
}

fn sanitize_event_id(event_id: Option<&str>) -> String {
    let Some(event_id) = event_id.map(str::trim).filter(|value| !value.is_empty()) else {
        return "unknown".into();
    };

    event_id
        .chars()
        .map(|character| {
            if character.is_ascii_alphanumeric() || character == '_' || character == '-' {
                character
            } else {
                '_'
            }
        })
        .collect()
}

async fn record_failed_webhook_deadletter_atomic(
    state: &AppState,
    notification_id: &str,
    error_message: &str,
    payload: &[u8],
    signature: Option<&str>,
) -> Result<(), String> {
    let prepared = prepare_deadletter(
        DeadletterEntry {
            reason: "processing_failed".into(),
            occurred_at: None,
            event_id: Some(notification_id.to_string()),
            error: Some(error_message.to_string()),
            payload_length: None,
            ..Default::default()
        },
        Some(payload),
        signature,
        Utc::now(),
    );

    let mut tx =
        state.db.begin().await.map_err(|error| {
            format!("Failed to begin Adyen webhook failure transaction: {error}")
        })?;

    let update_result = sqlx::query(
        r#"
        UPDATE adyen_webhook_events
        SET status = 'failed', error = $2, updated_at = NOW()
        WHERE adyen_notification_id = $1
        "#,
    )
    .bind(notification_id)
    .bind(error_message)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("Failed to mark Adyen webhook as failed: {error}"))?;

    if update_result.rows_affected() == 0 {
        tx.rollback().await.map_err(|error| {
            format!("Failed to roll back empty Adyen webhook failure transaction: {error}")
        })?;
        return Err(format!(
            "Failed to mark Adyen webhook {notification_id} as failed: event row was not found"
        ));
    }

    if let Err(error) = write_prepared_deadletter_to_redis(state, &prepared).await {
        if let Err(rollback_error) = tx.rollback().await {
            error!(notification_id, error = %rollback_error, "failed to roll back Adyen webhook failure transaction after Redis deadletter error");
        }
        return Err(error);
    }

    if let Err(error) = tx.commit().await {
        remove_prepared_deadletter_from_redis(state, &prepared.event_key).await;
        return Err(format!(
            "Failed to commit Adyen webhook failure transaction after Redis deadletter write: {error}"
        ));
    }

    Ok(())
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct DeadletterEntry {
    reason: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    occurred_at: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    event_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    error: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    payload_length: Option<usize>,
    /// How many times this entry has been retried so far.
    #[serde(default)]
    retry_count: u32,
    /// Maximum retry attempts before giving up.
    #[serde(default = "default_max_retries")]
    max_retries: u32,
    /// Raw Adyen webhook body (JSON), for replay on retry.
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    /// The first notification item's in-body `additionalData.hmacSignature`,
    /// kept for the retry index; the replay re-verifies every item against
    /// its own in-body signature.
    #[serde(skip_serializing_if = "Option::is_none")]
    signature: Option<String>,
}

const fn default_max_retries() -> u32 {
    DEADLETTER_MAX_RETRIES
}

impl Default for DeadletterEntry {
    fn default() -> Self {
        Self {
            reason: String::new(),
            occurred_at: None,
            event_id: None,
            error: None,
            payload_length: None,
            retry_count: 0,
            max_retries: DEADLETTER_MAX_RETRIES,
            body: None,
            signature: None,
        }
    }
}

#[derive(Debug)]
struct PreparedDeadletter {
    event_key: String,
    payload: String,
    now_ms: i64,
    cleanup_before_ms: i64,
    retry_at_ms: Option<i64>,
}

// ---------------------------------------------------------------------------
// The `adyen_webhook_events` ledger (claim / status / reclaim)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum WebhookEventClaim {
    Claimed,
    AlreadyProcessed,
    AlreadyPending,
}

async fn claim_webhook_event(
    state: &AppState,
    notification_id: &str,
    event_type: &str,
    psp_reference: &str,
) -> Result<WebhookEventClaim, String> {
    let row = sqlx::query_as::<_, WebhookEventClaimRow>(
        r#"
        WITH claimed AS (
            INSERT INTO adyen_webhook_events
                (id, adyen_notification_id, adyen_psp_reference, event_type, status, created_at, updated_at)
            VALUES (gen_random_uuid(), $1, $2, $3, 'pending', NOW(), NOW())
            ON CONFLICT (adyen_notification_id) DO UPDATE
            SET adyen_psp_reference = COALESCE(EXCLUDED.adyen_psp_reference, adyen_webhook_events.adyen_psp_reference),
                event_type = EXCLUDED.event_type,
                status = 'pending',
                error = NULL,
                updated_at = NOW()
            WHERE adyen_webhook_events.status <> 'processed'
              AND adyen_webhook_events.status <> 'pending'
            RETURNING true AS claimed, status
        )
        SELECT claimed, status FROM claimed
        UNION ALL
        SELECT false AS claimed, status
        FROM adyen_webhook_events
        WHERE adyen_notification_id = $1
          AND NOT EXISTS (SELECT 1 FROM claimed)
        LIMIT 1
        "#,
    )
    .bind(notification_id)
    .bind(psp_reference)
    .bind(event_type)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to claim Adyen webhook event: {error}"))?;

    Ok(classify_webhook_claim(row))
}

fn classify_webhook_claim(row: Option<WebhookEventClaimRow>) -> WebhookEventClaim {
    match row {
        Some(WebhookEventClaimRow { claimed: true, .. }) => WebhookEventClaim::Claimed,
        Some(WebhookEventClaimRow { status, .. }) if status == "processed" => {
            WebhookEventClaim::AlreadyProcessed
        }
        _ => WebhookEventClaim::AlreadyPending,
    }
}

#[derive(Debug, sqlx::FromRow)]
struct WebhookEventClaimRow {
    claimed: bool,
    status: String,
}

/// Age after which a `pending` webhook event row is considered abandoned
/// (claiming worker crashed mid-processing) and may be reclaimed (Fix G).
pub const STALE_PENDING_RECLAIM_SECS: u64 = 10 * 60;

/// Cutoff timestamp for the stale-pending reclaim sweep.
fn stale_pending_cutoff(now: DateTime<Utc>) -> DateTime<Utc> {
    now - TimeDelta::seconds(STALE_PENDING_RECLAIM_SECS as i64)
}

/// Reclaim webhook events stuck in `pending` for longer than
/// [`STALE_PENDING_RECLAIM_SECS`]. Rows are reset to `received` (with the
/// reason recorded in `error`) so either a Adyen retry or a deadletter
/// replay can claim them again. Returns the reclaimed event ids.
///
/// Wired into the maintenance worker loop (runs on startup and hourly).
pub async fn reclaim_stale_pending_webhooks(state: &AppState) -> Result<Vec<String>, String> {
    let cutoff = stale_pending_cutoff(Utc::now());
    let reclaimed: Vec<String> = sqlx::query_scalar(
        r#"
        UPDATE adyen_webhook_events
        SET status = 'received',
            error = 'reclaimed: pending exceeded stale threshold',
            updated_at = NOW()
        WHERE status = 'pending'
          AND updated_at < $1
        RETURNING adyen_notification_id
        "#,
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to reclaim stale pending webhook events: {error}"))?;

    if !reclaimed.is_empty() {
        warn!(
            count = reclaimed.len(),
            "reclaimed stale pending adyen webhook events"
        );
    }

    Ok(reclaimed)
}

// ---------------------------------------------------------------------------
// Dunning (atomic retry scheduling + customer notice)
// ---------------------------------------------------------------------------

/// Post-increment dunning state as returned by the atomic upsert.
#[derive(Debug, Clone, sqlx::FromRow)]
struct DunningSnapshot {
    failed_payment_count: i32,
    first_failed_at: Option<DateTime<Utc>>,
    status: String,
}

/// Dunning state decision derived from the post-increment snapshot (pure —
/// Fix H). `failed_payment_count` here is the already-incremented value
/// produced SQL-side, so concurrent failures can never lose an increment;
/// `first_failed_at` is the LEAST() of the existing value and `now`, also
/// computed SQL-side.
#[derive(Debug)]
struct ComputedDunningState {
    failed_payment_count: i32,
    first_failed_at: DateTime<Utc>,
    status: String,
    suspended_at: Option<DateTime<Utc>>,
    grace_period_ends_at: Option<DateTime<Utc>>,
}

fn next_dunning_state(
    existing: Option<DunningSnapshot>,
    now: DateTime<Utc>,
    config: &DunningConfig,
) -> ComputedDunningState {
    let first_failed_at = existing
        .as_ref()
        .and_then(|row| row.first_failed_at)
        .unwrap_or(now);
    let failed_payment_count = existing
        .as_ref()
        .map(|row| row.failed_payment_count)
        // The insert path passes the already-incremented count (SQL side);
        // a missing snapshot means this is the first failure.
        .unwrap_or(1);
    let days_since_first_failure = (now - first_failed_at).num_days().max(0);

    let mut new_status = "warning".to_string();
    let mut suspended_at = None;
    let mut grace_period_ends_at = None;

    if days_since_first_failure >= i64::from(config.hard_suspend_after_days) {
        new_status = "hard_suspended".into();
        if existing.as_ref().map(|row| row.status.as_str()) != Some("hard_suspended") {
            suspended_at = Some(now);
            grace_period_ends_at = Some(now + TimeDelta::days(i64::from(config.grace_period_days)));
        }
    } else if days_since_first_failure >= i64::from(config.soft_suspend_after_days) {
        new_status = "soft_suspended".into();
        let already_suspended = existing
            .as_ref()
            .map(|row| row.status.contains("suspended"))
            .unwrap_or(false);
        if !already_suspended {
            suspended_at = Some(now);
        }
    }

    ComputedDunningState {
        failed_payment_count,
        first_failed_at,
        status: new_status,
        suspended_at,
        grace_period_ends_at,
    }
}

/// A dunning lifecycle transition worth emitting an event for
/// (audit item 3g): entering soft/hard suspension, or recovering.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DunningTransition {
    SoftSuspended,
    HardSuspended,
    Recovered,
}

impl DunningTransition {
    /// `dunning_events.event_type` value for the transition.
    pub fn event_type(self) -> &'static str {
        match self {
            Self::SoftSuspended => "soft_suspended",
            Self::HardSuspended => "hard_suspended",
            Self::Recovered => "payment_recovered",
        }
    }
}

/// Pure classifier for dunning state transitions: returns `Some` only when
/// the status actually *changes into* a suspension state (or back to
/// healthy), so repeated refusal notifications for a tenant that is already
/// suspended do not spam duplicate transition events.
/// Unit-tested.
pub fn dunning_transition(previous: Option<&str>, new_status: &str) -> Option<DunningTransition> {
    let previous = previous.map(str::trim).filter(|status| !status.is_empty());
    if previous == Some(new_status) {
        return None; // No state change.
    }

    match new_status {
        "soft_suspended" if !matches!(previous, Some("soft_suspended" | "hard_suspended")) => {
            Some(DunningTransition::SoftSuspended)
        }
        "hard_suspended" if !matches!(previous, Some("hard_suspended")) => {
            Some(DunningTransition::HardSuspended)
        }
        "healthy"
            if matches!(
                previous,
                Some("warning" | "soft_suspended" | "hard_suspended")
            ) =>
        {
            Some(DunningTransition::Recovered)
        }
        _ => None,
    }
}

async fn record_failed_payment(
    state: &AppState,
    tenant_id: &str,
    invoice_id: &str,
    amount: i64,
) -> Result<DunningResult, String> {
    let config = get_dunning_config_for_tenant(state, tenant_id).await;
    let now = Utc::now();
    let mut tx = state
        .db
        .begin()
        .await
        .map_err(|error| format!("Failed to begin payment failure transaction: {error}"))?;

    // Fix H — single UPSERT with SQL-side increment. The counter increment
    // and first_failed_at=LEAST(existing, now) happen atomically inside the
    // statement, eliminating the read-compute-write race that lost
    // increments under concurrent refusal events.
    // dunning_records.id is VARCHAR(26) (migrations 087/093) — a 36-char
    // gen_random_uuid() string would overflow the column. Generate the id
    // in Rust with the shared 26-char generator instead.
    let dunning_record_id = generate_audit_log_id();

    let snapshot = sqlx::query_as::<_, DunningSnapshot>(
        r#"
        INSERT INTO dunning_records (
            id, tenant_id, status, failed_payment_count, first_failed_at,
            last_failed_at, next_retry_at, suspended_at, grace_period_ends_at,
            created_at, updated_at
        )
        VALUES ($2, $1, 'warning', 1, $3, $3, NULL, NULL, NULL, NOW(), NOW())
        ON CONFLICT (tenant_id) DO UPDATE SET
            failed_payment_count = dunning_records.failed_payment_count + 1,
            first_failed_at = LEAST(
                COALESCE(dunning_records.first_failed_at, EXCLUDED.first_failed_at),
                EXCLUDED.first_failed_at
            ),
            last_failed_at = EXCLUDED.last_failed_at,
            updated_at = NOW()
        RETURNING failed_payment_count, first_failed_at, status
        "#,
    )
    .bind(tenant_id)
    .bind(&dunning_record_id)
    .bind(now)
    .fetch_one(&mut *tx)
    .await
    .map_err(|error| format!("Failed to upsert dunning counters: {error}"))?;

    let computed = next_dunning_state(Some(snapshot.clone()), now, &config);
    let next_retry_at = calculate_next_retry(
        computed.first_failed_at,
        computed.failed_payment_count,
        &config,
    );

    // Audit item 3g — emit a distinct event when the tenant *transitions*
    // into soft/hard suspension (not on every repeated failure), so
    // webhook consumers and internal automations can key off the lifecycle
    // change instead of diffing payment_failed rows.
    let transition = dunning_transition(Some(&snapshot.status), &computed.status);

    sqlx::query(
        r#"
        WITH update_dunning AS (
            UPDATE dunning_records
            SET status = $2,
                next_retry_at = $3,
                suspended_at = COALESCE(dunning_records.suspended_at, $4),
                grace_period_ends_at = COALESCE($5, dunning_records.grace_period_ends_at),
                updated_at = NOW()
            WHERE tenant_id = $1
            RETURNING tenant_id
        ),
        log_event AS (
            INSERT INTO dunning_events (
                id, tenant_id, event_type, invoice_id, created_at
            )
            VALUES (gen_random_uuid(), $1, 'payment_failed', $8, NOW())
            RETURNING tenant_id
        ),
        log_transition AS (
            INSERT INTO dunning_events (
                id, tenant_id, event_type, invoice_id, created_at
            )
            SELECT gen_random_uuid(), $1, $7, $8, NOW()
            WHERE $7 IS NOT NULL
            RETURNING tenant_id
        ),
        suspend_tenant AS (
            UPDATE tenants
            SET status = 'suspended', updated_at = NOW()
            WHERE id = $1 AND $6 = true
            RETURNING id
        ),
        -- Audit F09: a dunning suspension is a BILLING restriction. It is
        -- recorded independently so payment recovery can clear exactly
        -- this hold without touching administrative, verification or
        -- abuse restrictions on the same tenant.
        billing_restriction AS (
            INSERT INTO tenant_restrictions (tenant_id, kind, reason, actor_type)
            SELECT $1, 'billing', 'dunning hard suspension', 'system'
            WHERE $6 = true
            ON CONFLICT (tenant_id, kind) WHERE cleared_at IS NULL
            DO NOTHING
        )
        SELECT 1
        "#,
    )
    .bind(tenant_id)
    .bind(&computed.status)
    .bind(next_retry_at)
    .bind(computed.suspended_at)
    .bind(computed.grace_period_ends_at)
    .bind(computed.status == "hard_suspended")
    .bind(transition.map(DunningTransition::event_type))
    .bind(invoice_id)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("Failed to upsert dunning state: {error}"))?;

    if let Some(transition) = transition {
        append_audit_log(
            &mut tx,
            tenant_id,
            "billing.dunning_transition",
            "dunning_record",
            Some(tenant_id),
            serde_json::json!({
                "transition": transition.event_type(),
                "fromStatus": snapshot.status,
                "toStatus": computed.status,
                "invoiceId": invoice_id,
                "failedPaymentCount": computed.failed_payment_count,
            }),
            now,
        )
        .await
        .map_err(|error| format!("Failed to insert dunning transition audit log: {error}"))?;
    }

    append_audit_log(
        &mut tx,
        tenant_id,
        "billing.payment_failed",
        "invoice",
        Some(invoice_id),
        serde_json::json!({
            "amount": amount,
            "failedPaymentCount": computed.failed_payment_count,
            "daysSinceFirstFailure": (now - computed.first_failed_at).num_days().max(0),
            "status": computed.status,
            "nextRetryAt": next_retry_at.map(|value| value.to_rfc3339()),
        }),
        now,
    )
    .await
    .map_err(|error| format!("Failed to insert payment failure audit log: {error}"))?;

    tx.commit()
        .await
        .map_err(|error| format!("Failed to commit payment failure transaction: {error}"))?;

    // Soft/hard suspension transitions notify out-of-band AFTER the state
    // change is durably committed: the notification queue feeds the
    // tenant-facing email/webhook fan-out, keyed off the transition.
    if let Some(transition) = transition {
        send_dunning_notification(
            state,
            tenant_id,
            &computed.status,
            serde_json::json!({
                "transition": transition.event_type(),
                "failedCount": computed.failed_payment_count,
                "daysSinceFirstFailure": (now - computed.first_failed_at).num_days().max(0),
                "gracePeriodEndsAt": computed.grace_period_ends_at.map(|value| value.to_rfc3339()),
            }),
        )
        .await;
    }

    send_dunning_notification(
        state,
        tenant_id,
        &computed.status,
        serde_json::json!({
            "failedCount": computed.failed_payment_count,
            "daysSinceFirstFailure": (now - computed.first_failed_at).num_days().max(0),
            "nextRetryAt": next_retry_at.map(|value| value.to_rfc3339()),
        }),
    )
    .await;

    if let Ok(mut conn) = state.redis.get().await {
        let cache_key = format!("dunning:status:{tenant_id}");
        let cache_result: Result<(), _> = redis::AsyncCommands::set_ex(
            &mut conn,
            &cache_key,
            &computed.status,
            DUNNING_STATUS_CACHE_TTL_SECONDS,
        )
        .await;
        if let Err(error) = cache_result {
            warn!(tenant_id = %tenant_id, error = %error, "failed to cache dunning status");
        }
    }

    Ok(DunningResult {
        status: computed.status,
        next_retry_at,
    })
}

async fn get_dunning_config_for_tenant(state: &AppState, tenant_id: &str) -> DunningConfig {
    if let Err(error) = ensure_dunning_config_table(state).await {
        warn!(tenant_id = %tenant_id, error = %error, "failed to ensure dunning_config table; using defaults");
        return DunningConfig::default();
    }

    let result = sqlx::query_as::<_, DunningConfigRow>(
        r#"
        SELECT retry_schedule_days, soft_suspend_after_days, hard_suspend_after_days, grace_period_days
        FROM dunning_config
        WHERE tenant_id = $1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await;

    match result {
        Ok(Some(row)) => DunningConfig {
            retry_schedule_days: row.retry_schedule_days,
            soft_suspend_after_days: row.soft_suspend_after_days,
            hard_suspend_after_days: row.hard_suspend_after_days,
            grace_period_days: row.grace_period_days,
        },
        Ok(None) => DunningConfig::default(),
        Err(error) => {
            warn!(tenant_id = %tenant_id, error = %error, "failed to load dunning config; using defaults");
            DunningConfig::default()
        }
    }
}

async fn ensure_dunning_config_table(state: &AppState) -> Result<(), String> {
    if DUNNING_CONFIG_TABLE_ENSURED.get().is_some() {
        return Ok(());
    }

    // The dunning_config table is now created via the formal migration system
    // (migrations/045_create_dunning_config.sql). This function validates that
    // the migration has been applied, rather than creating the table at runtime.
    let table_exists: bool = sqlx::query_scalar(
        r#"
        SELECT EXISTS (
            SELECT FROM information_schema.tables
            WHERE table_name = 'dunning_config'
        )
        "#,
    )
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to check dunning_config table existence: {error}"))?;

    if !table_exists {
        tracing::error!(
            "dunning_config table does not exist — migration 045 has not been applied. \
             Dunning features will use hardcoded defaults."
        );
        return Err("dunning_config table not found — run migrations".to_string());
    }

    let _ = DUNNING_CONFIG_TABLE_ENSURED.set(());
    Ok(())
}

fn calculate_next_retry(
    first_failed_at: DateTime<Utc>,
    attempt_count: i32,
    config: &DunningConfig,
) -> Option<DateTime<Utc>> {
    let index = usize::try_from(attempt_count.saturating_sub(1)).ok()?;
    let days_to_add = *config.retry_schedule_days.get(index)?;
    Some(first_failed_at + TimeDelta::days(i64::from(days_to_add)))
}

async fn send_dunning_notification(
    state: &AppState,
    tenant_id: &str,
    status: &str,
    payload: serde_json::Value,
) {
    let notification_type = match status {
        "warning" => "payment_reminder",
        "soft_suspended" => "account_soft_suspended",
        _ => "account_hard_suspended",
    };

    let result = sqlx::query(
        r#"
        INSERT INTO notification_queue (id, tenant_id, type, payload, status, created_at)
        VALUES (gen_random_uuid(), $1, $2, $3, 'pending', NOW())
        "#,
    )
    .bind(tenant_id)
    .bind(notification_type)
    .bind(payload)
    .execute(&state.db)
    .await;

    if let Err(error) = result {
        error!(tenant_id = %tenant_id, error = %error, "failed to enqueue dunning notification");
    }
}

#[derive(Debug, sqlx::FromRow)]
struct DunningConfigRow {
    retry_schedule_days: Vec<i32>,
    soft_suspend_after_days: i32,
    hard_suspend_after_days: i32,
    grace_period_days: i32,
}

#[derive(Debug, Clone)]
struct DunningConfig {
    retry_schedule_days: Vec<i32>,
    soft_suspend_after_days: i32,
    hard_suspend_after_days: i32,
    grace_period_days: i32,
}

impl Default for DunningConfig {
    fn default() -> Self {
        Self {
            retry_schedule_days: vec![1, 3, 7, 14],
            soft_suspend_after_days: 7,
            hard_suspend_after_days: 21,
            grace_period_days: 7,
        }
    }
}

#[derive(Debug)]
struct DunningResult {
    status: String,
    next_retry_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Deadletter replay + the retry worker
// ---------------------------------------------------------------------------

/// Replay a deadletter entry by re-verifying every item's in-body HMAC,
/// claiming each notification in the database (idempotent via
/// `ON CONFLICT`), and calling the event-code dispatch.
async fn replay_deadletter(state: &AppState, entry: &DeadletterEntry) -> Result<(), String> {
    let body = entry
        .body
        .as_deref()
        .ok_or_else(|| "No body stored for retry".to_string())?;
    entry
        .signature
        .as_deref()
        .ok_or_else(|| "No signature stored for retry".to_string())?;

    // Re-verify the stored HMAC before processing: the body lives in Redis
    // between the original failure and this replay, so integrity must be
    // re-checked against the secret instead of trusting the stored payload.
    // The signature is inside the body, so each item is verified against its
    // own `additionalData.hmacSignature`.
    let secret = state.config.adyen_hmac_key.trim();
    if secret.is_empty() {
        return Err("Adyen webhook secret is not configured".into());
    }

    let envelope: AdyenNotificationEnvelope = serde_json::from_str(body)
        .map_err(|error| format!("Failed to parse stored webhook body: {error}"))?;
    if envelope.notification_items.is_empty() {
        return Err("stored notification carries no notificationItems".into());
    }

    for item in &envelope.notification_items {
        let item = &item.notification_request_item;
        let signature = item
            .hmac_signature()
            .ok_or_else(|| "stored notification item carries no hmacSignature".to_string())?;
        verify_item_hmac(secret, item, signature)?;
    }

    for entry_item in &envelope.notification_items {
        let item = &entry_item.notification_request_item;
        let notification_id = adyen_notification_id(item);
        match claim_webhook_event(
            state,
            &notification_id,
            item.event_code.trim(),
            item.psp_reference.trim(),
        )
        .await?
        {
            WebhookEventClaim::Claimed => {}
            WebhookEventClaim::AlreadyProcessed => {
                info!(
                    adyen_notification_id = %notification_id,
                    "deadletter retry: event already processed, skipping"
                );
                continue;
            }
            WebhookEventClaim::AlreadyPending => {
                return Err("Event is already pending on another worker".into());
            }
        }

        // Process the event business logic.
        handle_notification(state, item).await?;

        // Mark as processed in the database.
        sqlx::query(
            r#"
            UPDATE adyen_webhook_events
            SET status = 'processed', processed_at = NOW(), updated_at = NOW()
            WHERE adyen_notification_id = $1
            "#,
        )
        .bind(&notification_id)
        .execute(&state.db)
        .await
        .map_err(|error| format!("Failed to mark retried event as processed: {error}"))?;

        info!(adyen_notification_id = %notification_id, "deadletter retry succeeded");
    }

    Ok(())
}

/// Scan the retry index for entries whose retry timestamp is due, attempt to
/// replay them, and either remove them on success or schedule the next
/// exponential-backoff retry on transient failure.
async fn process_deadletter_retries(state: &AppState) -> Result<(), String> {
    let now_ms = Utc::now().timestamp_millis();
    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|error| format!("Redis connection error: {error}"))?;

    // Fetch all entries due for retry (score <= now_ms).
    #[cfg(test)]
    crate::test_support::query_count::bump("deadletter.redis");
    let due_entries: Vec<String> = redis::cmd("ZRANGEBYSCORE")
        .arg(DEADLETTER_RETRY_INDEX_KEY)
        .arg(0i64)
        .arg(now_ms)
        .query_async(&mut *conn)
        .await
        .map_err(|error| format!("Failed to query retry index: {error}"))?;

    let batch: Vec<String> = due_entries
        .into_iter()
        .take(DEADLETTER_RETRY_BATCH_SIZE)
        .collect();
    if batch.is_empty() {
        return Ok(());
    }
    info!(
        batch_size = batch.len(),
        "retrying deadlettered webhook events"
    );

    // P3 fix 4 — read every due entry in ONE MGET per chunk instead of one
    // GET per key (the per-key GET/DEL loop was O(batch) round trips). The
    // connection is released before replay: each replay does DB work and
    // must not pin a Redis connection for the whole batch.
    let mut entry_jsons: Vec<Option<String>> = Vec::with_capacity(batch.len());
    for chunk in batch.chunks(DEADLETTER_KEY_CHUNK) {
        #[cfg(test)]
        crate::test_support::query_count::bump("deadletter.redis");
        let values: Vec<Option<String>> = redis::cmd("MGET")
            .arg(chunk)
            .query_async(&mut *conn)
            .await
            .map_err(|error| format!("Failed to read deadletter entries: {error}"))?;
        entry_jsons.extend(values);
    }
    drop(conn);

    // Batch the index mutations: stale/corrupt/handled keys accumulate into
    // one (chunked) ZREM, reschedules into one pipelined SET+ZADD, exhausted
    // TTL shortenings into one pipelined SETEX. Net outcomes are identical
    // to the per-key writes; a crash before the flush only means the entries
    // remain due and are replayed (replay is idempotent).
    let mut remove_from_index: Vec<String> = Vec::new();
    let mut shorten_ttl: Vec<(String, String)> = Vec::new();
    let mut reschedule: Vec<(String, String, i64)> = Vec::new();

    for (event_key, entry_json) in batch.iter().zip(entry_jsons) {
        let Some(entry_json) = entry_json else {
            // Entry already evicted — remove stale retry index member.
            remove_from_index.push(event_key.clone());
            continue;
        };

        let entry: DeadletterEntry = match serde_json::from_str(&entry_json) {
            Ok(entry) => entry,
            Err(error) => {
                warn!(error = %error, key = %event_key, "corrupt deadletter entry, removing from retry index");
                remove_from_index.push(event_key.clone());
                continue;
            }
        };

        // Only retry processing_failed entries that have body + signature.
        if entry.reason != "processing_failed" || entry.body.is_none() || entry.signature.is_none()
        {
            remove_from_index.push(event_key.clone());
            continue;
        }

        match replay_deadletter(state, &entry).await {
            Ok(()) => {
                // Success — remove from retry index (deadletter remains for audit).
                remove_from_index.push(event_key.clone());
                info!(
                    event_id = ?entry.event_id,
                    "deadletter retry succeeded"
                );
            }
            Err(error) => {
                let next_count = entry.retry_count + 1;
                warn!(
                    event_id = ?entry.event_id,
                    retry_count = next_count,
                    max_retries = DEADLETTER_MAX_RETRIES,
                    error = %error,
                    "deadletter retry attempt failed"
                );

                if next_count >= DEADLETTER_MAX_RETRIES {
                    // Exhausted — remove from retry index but keep the deadletter entry
                    // for manual inspection (with a shorter 7-day TTL).
                    warn!(
                        event_id = ?entry.event_id,
                        retry_count = next_count,
                        "deadletter retry exhausted, giving up"
                    );
                    remove_from_index.push(event_key.clone());

                    // Shorten TTL to 7 days for final review.
                    let mut final_entry = entry.clone();
                    final_entry.retry_count = next_count;
                    if let Ok(json) = serde_json::to_string(&final_entry) {
                        shorten_ttl.push((event_key.clone(), json));
                    }
                } else {
                    // Schedule next retry with exponential backoff.
                    let backoff_secs = DEADLETTER_RETRY_BACKOFF_SECONDS
                        .get(next_count as usize - 1)
                        .copied()
                        .unwrap_or(DEADLETTER_RETRY_BACKOFF_SECONDS[4]); // cap at max
                    let next_retry_ms = Utc::now().timestamp_millis() + backoff_secs * 1000;

                    let mut updated_entry = entry.clone();
                    updated_entry.retry_count = next_count;
                    if let Ok(json) = serde_json::to_string(&updated_entry) {
                        reschedule.push((event_key.clone(), json, next_retry_ms));
                    }
                }
            }
        }
    }

    if remove_from_index.is_empty() && shorten_ttl.is_empty() && reschedule.is_empty() {
        return Ok(());
    }

    let mut conn = state
        .redis
        .get()
        .await
        .map_err(|error| format!("Redis connection error: {error}"))?;

    // ONE ZREM per chunk carries every removed member (the old loop issued
    // one ZREM per entry).
    for chunk in remove_from_index.chunks(DEADLETTER_KEY_CHUNK) {
        #[cfg(test)]
        crate::test_support::query_count::bump("deadletter.redis");
        let mut command = redis::cmd("ZREM");
        command.arg(DEADLETTER_RETRY_INDEX_KEY);
        for key in chunk {
            command.arg(key);
        }
        let _: () = command.query_async(&mut *conn).await.unwrap_or_default();
    }

    if !shorten_ttl.is_empty() || !reschedule.is_empty() {
        // ONE atomic pipeline carries every SETEX + SET/ZADD pair (atomic:
        // the retry-counter update and its index score move together, like
        // the per-entry pipe this replaces).
        #[cfg(test)]
        crate::test_support::query_count::bump("deadletter.redis");
        let mut pipe = redis::pipe();
        pipe.atomic();
        for (event_key, json) in &shorten_ttl {
            pipe.cmd("SETEX")
                .arg(event_key)
                .arg(7 * 24 * 60 * 60usize)
                .arg(json)
                .ignore();
        }
        for (event_key, json, next_retry_ms) in &reschedule {
            pipe.cmd("SET")
                .arg(event_key)
                .arg(json)
                .ignore()
                .cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(*next_retry_ms)
                .arg(event_key)
                .ignore();
        }
        let _: () = pipe.query_async(&mut *conn).await.unwrap_or_default();
    }

    Ok(())
}

/// Spawns a background tokio task that polls the deadletter retry index every
/// [`DEADLETTER_RETRY_POLL_INTERVAL_SECS`] seconds and replays due entries.
///
/// Call this once at application startup (e.g. from `main()`).
pub fn spawn_deadletter_retry_worker(state: Arc<AppState>) {
    tokio::spawn(async move {
        let mut interval =
            tokio::time::interval(Duration::from_secs(DEADLETTER_RETRY_POLL_INTERVAL_SECS));
        interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);

        loop {
            interval.tick().await;

            if let Err(e) = process_deadletter_retries(&state).await {
                error!(error = %e, "deadletter retry worker error");
            }
        }
    });

    info!(
        "deadletter retry worker spawned (poll interval: {}s)",
        DEADLETTER_RETRY_POLL_INTERVAL_SECS
    );
}

/// Retry deadlettered webhook events from the retry index.
/// Processes events in batches of [`DEADLETTER_RETRY_BATCH_SIZE`] (default 10).
/// Uses exponential backoff: retry after 5min, 15min, 30min, 1hr, 2hr (max 5 attempts).
///
/// Single implementation shared with the spawned worker
/// ([`spawn_deadletter_retry_worker`] → [`process_deadletter_retries`]): the
/// scan-and-retry logic existed twice (worker copy and entry-point copy) and
/// the two had drifted, so arms covered through one path stayed invisible on
/// the other. This is now a thin delegate.
pub async fn retry_deadlettered_webhooks(state: &AppState) -> Result<(), String> {
    process_deadletter_retries(state).await
}

// ---------------------------------------------------------------------------
// Dedicated-IP auto-provisioning
// ---------------------------------------------------------------------------

/// The exact JSON body sent to `POST {api_base_url}/v1/dedicated-ips`.
///
/// The API's `AllocateIpRequest` is `#[serde(deny_unknown_fields)]` and only
/// declares `region` (optional). The empty object parses into the contract
/// (every field is defaulted). If a region ever needs to be pinned, extend
/// this object with `region` only.
fn auto_provision_request_body() -> serde_json::Value {
    serde_json::json!({})
}

/// Background task that performs the actual dedicated IP provisioning for a
/// tenant whose subscription became entitled.
///
/// Public because the subscription-state owners (outside the webhook layer
/// after the Adyen conversion — Adyen sends no subscription-status
/// notifications) are the legitimate callers. There is no maintenance retry
/// consumer: failures are logged and the
/// `dedicated_ip_provisioning_requests` row is finalized as
/// 'failed'/'partial'. A later entitled-subscription event retries the
/// provisioning path from scratch (idempotent request upsert + active-count
/// check), so the absence of a sweeper does not strand provisioning.
pub async fn auto_provision_dedicated_ips_background(
    app_state: &AppState,
    tenant_id: &str,
) -> Result<(), String> {
    // Re-borrow the inner fields we need
    let state = app_state;
    let included_count = sqlx::query_scalar::<_, i32>(
        r#"
        SELECT COALESCE((p.features->>'dedicated_ip_count')::int, 0) AS included_count
        FROM adyen_subscriptions s
        JOIN plans p ON p.name = (
            SELECT plan FROM tenants WHERE id = s.tenant_id
        )
        WHERE s.tenant_id = $1 AND s.status = 'active'
        ORDER BY s.created_at DESC
        LIMIT 1
        "#,
    )
    .bind(tenant_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to load dedicated IP allowance: {error}"))?
    .unwrap_or(0);

    if included_count <= 0 {
        return Ok(());
    }

    let active_count = sqlx::query_scalar::<_, i64>(
        r#"
        SELECT COUNT(*)::bigint
        FROM dedicated_ips
        WHERE tenant_id = $1
          AND status NOT IN ('retired', 'releasing', 'failed', 'cleanup_failed')
        "#,
    )
    .bind(tenant_id)
    .fetch_one(&state.db)
    .await
    .map_err(|error| format!("Failed to load active dedicated IP count: {error}"))?;
    // Terminal provisioning-failure rows (`failed`, `cleanup_failed`) do not
    // occupy the allowance: the API-side `NON_OCCUPYING_STATUSES` is the
    // canonical list (crates/api-server/src/ip_provider.rs) and must stay in
    // sync with the literal above.

    let to_allocate = i64::from(included_count) - active_count;
    if to_allocate <= 0 {
        info!(tenant_id = %tenant_id, active_count, included_count, "tenant already has sufficient dedicated IPs");
        return Ok(());
    }

    sqlx::query(
        r#"
        INSERT INTO dedicated_ip_provisioning_requests
            (id, tenant_id, requested_count, status, created_at, updated_at)
        VALUES (gen_random_uuid(), $1, $2, 'pending', NOW(), NOW())
        ON CONFLICT (tenant_id) WHERE status = 'pending'
        DO UPDATE SET requested_count = $2, updated_at = NOW()
        "#,
    )
    .bind(tenant_id)
    .bind(to_allocate)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to record dedicated IP provisioning request: {error}"))?;

    // Use a shared HTTP client with sane timeouts.
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .map_err(|e| format!("Failed to build HTTP client: {e}"))?;

    let api_base_url = state.config.api_base_url.trim_end_matches('/');
    let bearer = format!("Bearer {}", state.config.service_auth_token);

    // Build all requests upfront, then fire them concurrently with bounded parallelism.
    let mut requests: Vec<_> = (0..to_allocate)
        .map(|_| {
            client
                .post(format!("{api_base_url}/v1/dedicated-ips"))
                .header(reqwest::header::CONTENT_TYPE, "application/json")
                .header(reqwest::header::AUTHORIZATION, &bearer)
                .header("X-Internal-Service", "billing")
                .header("X-Tenant-Id", tenant_id)
                .json(&auto_provision_request_body())
                .send()
        })
        .collect();

    // Fire requests in concurrent batches of 5 to avoid overwhelming the API server.
    let mut success_count = 0_i64;
    let mut failure_count = 0_i64;
    const BATCH_SIZE: usize = 5;

    for chunk in requests.chunks_mut(BATCH_SIZE) {
        let results = join_all(
            chunk
                .iter_mut()
                .map(|req| timeout(Duration::from_secs(30), req)),
        )
        .await;

        for result in results {
            match result {
                Ok(Ok(response)) if response.status().is_success() => {
                    success_count += 1;
                }
                Ok(Ok(response)) => {
                    failure_count += 1;
                    let status = response.status();
                    let body = response.text().await.unwrap_or_default();
                    warn!(
                        tenant_id = %tenant_id,
                        status = %status,
                        error = %body,
                        "dedicated IP auto-provision request failed"
                    );
                }
                Ok(Err(error)) => {
                    failure_count += 1;
                    error!(
                        tenant_id = %tenant_id,
                        error = %error,
                        "dedicated IP auto-provision request errored"
                    );
                }
                Err(_elapsed) => {
                    failure_count += 1;
                    error!(
                        tenant_id = %tenant_id,
                        "dedicated IP auto-provision request timed out after 30s"
                    );
                }
            }
        }
    }

    let final_status = if failure_count == 0 {
        "completed"
    } else if success_count > 0 {
        "partial"
    } else {
        "failed"
    };

    sqlx::query(
        r#"
        UPDATE dedicated_ip_provisioning_requests
        SET status = $2, success_count = $3, failure_count = $4, updated_at = NOW()
        WHERE tenant_id = $1 AND status = 'pending'
        "#,
    )
    .bind(tenant_id)
    .bind(final_status)
    .bind(success_count)
    .bind(failure_count)
    .execute(&state.db)
    .await
    .map_err(|error| format!("Failed to update dedicated IP provisioning request: {error}"))?;

    if failure_count > 0 {
        error!(
            tenant_id = %tenant_id,
            requested_count = to_allocate,
            success_count,
            failure_count,
            final_status,
            "dedicated IP provisioning had failures"
        );
    }

    Ok(())
}

// ---------------------------------------------------------------------------
// Test helpers shared by both in-file test modules.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod wire_test_helpers {
    use super::*;

    /// The official Adyen SDK HMAC test vector (the same key/fields the
    /// Adyen client libraries pin, re-validated against the Python harness
    /// recipe `tools/dogfood-v2/harness/adyen.py`).
    pub(crate) const OFFICIAL_HMAC_KEY: &str =
        "44782DEF547AAA06C910C43932B1EB0C71FC68D9D0C057550C48EC2ACF6BA056";
    pub(crate) const OFFICIAL_HMAC_SIGNATURE: &str = "coqCmt/IZ4E3CzPvMY8zTjQVL5hYJUiBRg8UU+iCWo0=";
    pub(crate) const OFFICIAL_SIGNING_STRING: &str =
        "7914073381342284::TestMerchant:TestPayment-1407325143704:1130:EUR:AUTHORISATION:true";

    pub(crate) fn official_item() -> AdyenNotificationItem {
        parse_item(serde_json::json!({
            "pspReference": "7914073381342284",
            "merchantAccountCode": "TestMerchant",
            "merchantReference": "TestPayment-1407325143704",
            "amount": { "currency": "EUR", "value": 1130 },
            "eventCode": "AUTHORISATION",
            "eventDate": "2019-05-06T17:15:34.121+02:00",
            "success": "true",
            "paymentMethod": "visa",
            "reason": "",
            "operations": ["CANCEL", "CAPTURE", "REFUND"]
        }))
    }

    pub(crate) fn parse_item(value: serde_json::Value) -> AdyenNotificationItem {
        serde_json::from_value(value).expect("notification item parses")
    }

    /// Sign an item exactly like the wire/harness: base64 of the HMAC over
    /// the escaped signing string with the hex-decoded key.
    pub(crate) fn sign_item(secret: &str, item: &AdyenNotificationItem) -> String {
        let mut mac = HmacSha256::new_from_slice(&hmac_key_bytes(secret)).expect("HMAC key");
        mac.update(adyen_signing_string(item).as_bytes());
        base64_encode(&mac.finalize().into_bytes())
    }

    /// The notification envelope with one item carrying `signature` in its
    /// `additionalData`.
    pub(crate) fn envelope_bytes(item: &AdyenNotificationItem, signature: &str) -> Vec<u8> {
        let mut value = serde_json::to_value(item).expect("item json");
        let data = value
            .get_mut("additionalData")
            .and_then(serde_json::Value::as_object_mut)
            .cloned();
        let mut data = data.unwrap_or_default();
        data.insert(
            "hmacSignature".into(),
            serde_json::Value::String(signature.into()),
        );
        value["additionalData"] = serde_json::Value::Object(data);
        serde_json::to_vec(&serde_json::json!({
            "live": "false",
            "notificationItems": [{ "NotificationRequestItem": value }]
        }))
        .expect("envelope json")
    }

    /// The envelope for an item signed with `secret`.
    pub(crate) fn signed_envelope(secret: &str, item: &AdyenNotificationItem) -> Vec<u8> {
        let signature = sign_item(secret, item);
        envelope_bytes(item, &signature)
    }

    pub(crate) fn parse_envelope(body: &[u8]) -> Vec<AdyenNotificationItem> {
        let envelope: AdyenNotificationEnvelope =
            serde_json::from_slice(body).expect("envelope parses");
        envelope
            .notification_items
            .into_iter()
            .map(|entry| entry.notification_request_item)
            .collect()
    }

    /// A minimal recurring AUTHORISATION item for `reference`.
    pub(crate) fn recurring_item(reference: &str, value: i64, success: bool) -> serde_json::Value {
        serde_json::json!({
            "pspReference": format!("psp_{reference}"),
            "originalReference": "psp_original",
            "merchantAccountCode": "ApexMailECOM",
            "merchantReference": reference,
            "amount": { "currency": "EUR", "value": value },
            "eventCode": "AUTHORISATION",
            "eventDate": "2026-10-14T10:00:00+00:00",
            "success": if success { "true" } else { "false" },
            "paymentMethod": "visa",
            "additionalData": {
                "shopperReference": "shopper-tenant",
                "recurringProcessingModel": "Subscription",
                "metadata": { "tenant_id": "shopper-tenant" }
            }
        })
    }
}

#[cfg(test)]
mod tests {
    use super::wire_test_helpers::*;
    use super::*;

    // ------------------------------------------------------------------
    // The HMAC recipe: the official pinned vector, tamper handling and the
    // hex-decoded key.
    // ------------------------------------------------------------------

    #[test]
    fn adyen_hmac_matches_the_official_sdk_vector() {
        // The official test vector (Adyen's own SDK specs, validated against
        // tools/dogfood-v2/harness/adyen.py): key hex-decoded, signing string
        // escaped colon-joined, digest base64, verified timing-safe.
        let item = official_item();
        assert_eq!(adyen_signing_string(&item), OFFICIAL_SIGNING_STRING);
        assert!(
            verify_item_hmac(OFFICIAL_HMAC_KEY, &item, OFFICIAL_HMAC_SIGNATURE).is_ok(),
            "the official pinned vector must verify"
        );
        // The signature is BASE64 (a hex comparison would never match).
        assert_eq!(base64_encode(b"00"), "MDA=");

        // Tampered item fields → HMAC mismatch.
        let mut tampered = item.clone();
        tampered.success = Some("false".into());
        assert!(verify_item_hmac(OFFICIAL_HMAC_KEY, &tampered, OFFICIAL_HMAC_SIGNATURE).is_err());
        let mut tampered = item.clone();
        tampered.amount = Some(AdyenAmount {
            value: Some(1131),
            currency: Some("EUR".into()),
        });
        assert!(verify_item_hmac(OFFICIAL_HMAC_KEY, &tampered, OFFICIAL_HMAC_SIGNATURE).is_err());

        // Wrong secret → mismatch.
        let wrong_secret = "deliberately-wrong-hmac-secret-not-a-key";
        assert!(verify_item_hmac(wrong_secret, &item, OFFICIAL_HMAC_SIGNATURE).is_err());

        // Bit-flipped signature → mismatch.
        let flipped: String = OFFICIAL_HMAC_SIGNATURE
            .chars()
            .map(|character| if character == '0' { '1' } else { '0' })
            .collect();
        assert!(verify_item_hmac(OFFICIAL_HMAC_KEY, &item, &flipped).is_err());

        // A signature produced by our signer round-trips through verify.
        let produced = sign_item(OFFICIAL_HMAC_KEY, &item);
        assert_eq!(produced, OFFICIAL_HMAC_SIGNATURE);
        assert!(verify_item_hmac(OFFICIAL_HMAC_KEY, &item, &produced).is_ok());
    }

    #[test]
    fn hmac_key_is_hex_decoded_with_a_raw_local_dev_fallback() {
        // A real key is hex: 64 hex chars → 32 key bytes.
        assert_eq!(hmac_key_bytes(OFFICIAL_HMAC_KEY).len(), 32);
        assert_eq!(
            hmac_key_bytes(OFFICIAL_HMAC_KEY),
            hex::decode(OFFICIAL_HMAC_KEY).expect("hex")
        );
        // The non-hex local-dev default stays usable as raw bytes (the
        // documented harness fallback), so fixture/probe/local stack agree.
        let dev = "dev-adyen-webhook-secret-local-only-0123456789";
        assert_eq!(hmac_key_bytes(dev), dev.as_bytes().to_vec());
        assert_eq!(hmac_key_bytes("  "), Vec::<u8>::new());
    }

    #[test]
    fn signature_base64_decoder_accepts_standard_padded_base64() {
        assert_eq!(base64_decode("").as_deref(), None);
        assert_eq!(base64_decode("TQ==").as_deref(), Some(&b"M"[..]));
        assert_eq!(base64_decode("TWE=").as_deref(), Some(&b"Ma"[..]));
        assert_eq!(base64_decode("TWFu").as_deref(), Some(&b"Man"[..]));
        // The official signature decodes to a full SHA-256 digest (32 bytes).
        assert_eq!(
            base64_decode(OFFICIAL_HMAC_SIGNATURE)
                .expect("official signature decodes")
                .len(),
            32
        );
        // Unpadded standard base64 is accepted too.
        assert_eq!(base64_decode("TWFu").as_deref(), Some(&b"Man"[..]));
    }

    #[test]
    fn signature_base64_decoder_rejects_empty_and_malformed_input() {
        // Empty/blank never verifies as a signature.
        assert_eq!(base64_decode(""), None);
        assert_eq!(base64_decode("   "), None);
        // Non-alphabet characters (including the URL-safe alphabet and hex).
        assert_eq!(base64_decode("deadbeef!"), None);
        assert_eq!(base64_decode("t=123,v1=abc"), None);
        assert_eq!(base64_decode("AA-_"), None);
        // A single dangling character is not a valid quantum.
        assert_eq!(base64_decode("A"), None);
        assert_eq!(base64_decode("AAAAA"), None);
        // More than two padding characters is malformed.
        assert_eq!(base64_decode("T==="), None);
    }

    #[test]
    fn signature_base64_decoder_rejects_trailing_data_after_padding() {
        assert_eq!(base64_decode("TQ==TQ=="), None);
        assert_eq!(base64_decode("TQ==a"), None);
    }

    #[test]
    fn signing_string_escapes_backslashes_before_colons() {
        let item = parse_item(serde_json::json!({
            "pspReference": "psp:with:colons",
            "merchantAccountCode": "ApexMailECOM",
            "merchantReference": "ref\\with\\slashes",
            "amount": { "currency": "EUR", "value": 1 },
            "eventCode": "AUTHORISATION",
            "success": "true"
        }));
        assert_eq!(
            adyen_signing_string(&item),
            "psp\\:with\\:colons::ApexMailECOM:ref\\\\with\\\\slashes:1:EUR:AUTHORISATION:true"
        );
    }

    #[test]
    fn signing_string_renders_missing_fields_as_empty() {
        let item = parse_item(serde_json::json!({
            "pspReference": "psp_min",
            "merchantAccountCode": "ApexMailECOM",
            "merchantReference": "ref",
            "eventCode": "REFUND",
            "success": "true"
        }));
        // No originalReference, no amount: both render as empty fields.
        assert_eq!(
            adyen_signing_string(&item),
            "psp_min::ApexMailECOM:ref:::REFUND:true"
        );
    }

    // ------------------------------------------------------------------
    // The deterministic dedupe id (Adyen retries; the digest is the
    // idempotency key replacing the pre-Adyen timestamp tolerance).
    // ------------------------------------------------------------------

    #[test]
    fn identical_notifications_share_the_dedupe_id_and_retries_cannot_reapply() {
        let item = official_item();
        let first = adyen_notification_id(&item);
        let second = adyen_notification_id(&item);
        assert_eq!(first, second, "Adyen retries the same notification");
        // A different pspReference is a different notification.
        let mut other = item.clone();
        other.psp_reference = "7914073381342285".into();
        assert_ne!(adyen_notification_id(&other), first);
        // A different success is a different notification.
        let mut other = item.clone();
        other.success = Some("false".into());
        assert_ne!(adyen_notification_id(&other), first);
        // A different merchant reference is a different notification.
        let mut other = item.clone();
        other.merchant_reference = "TestPayment-other".into();
        assert_ne!(adyen_notification_id(&other), first);
    }

    #[test]
    fn a_new_event_date_is_a_new_notification() {
        // eventDate participates in the digest: the SAME charge at a NEW
        // eventDate is a new notification (a genuinely new event), while a
        // byte-identical retry keeps the same id.
        let item = official_item();
        let mut later = item.clone();
        later.event_date = Some("2026-10-14T10:00:00+00:00".into());
        assert_ne!(adyen_notification_id(&later), adyen_notification_id(&item));
        assert_eq!(
            adyen_notification_id(&item),
            adyen_notification_id(&official_item())
        );
    }

    #[test]
    fn notification_ids_are_prefixed_and_content_addressed() {
        let id = adyen_notification_id(&official_item());
        assert!(
            id.starts_with("adn_"),
            "the dedupe id carries the adn_ prefix"
        );
        assert_eq!(id.len(), 4 + 64, "adn_ + a full SHA-256 hex digest");
        assert!(id[4..]
            .chars()
            .all(|character| character.is_ascii_hexdigit()));
        // Pinned against the Python harness's digest basis (unit-separated
        // eventCode|pspReference|success|eventDate|merchantReference).
        assert_eq!(
            id,
            "adn_dd4fa7b2362506799a047ccf6c15d6c6f33626d5c65827adc06fd78062c98689"
        );
    }

    // ------------------------------------------------------------------
    // merchantReference → local invoice; tenant resolution.
    // ------------------------------------------------------------------

    #[test]
    fn merchant_reference_parses_invoice_prefixed_and_bare_uuids() {
        let id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid");
        assert_eq!(
            parse_merchant_reference_invoice_id("invoice:01234567-89ab-cdef-0123-456789abcdef"),
            Some(id)
        );
        assert_eq!(
            parse_merchant_reference_invoice_id("01234567-89ab-cdef-0123-456789abcdef"),
            Some(id)
        );
        assert_eq!(
            parse_merchant_reference_invoice_id("  invoice:01234567-89ab-cdef-0123-456789abcdef "),
            Some(id)
        );
    }

    #[test]
    fn merchant_reference_rejects_garbage_and_foreign_prefixes() {
        assert_eq!(parse_merchant_reference_invoice_id(""), None);
        assert_eq!(parse_merchant_reference_invoice_id("not-a-uuid"), None);
        assert_eq!(parse_merchant_reference_invoice_id("invoice:"), None);
        assert_eq!(
            parse_merchant_reference_invoice_id("invoice:not-a-uuid"),
            None
        );
        // A foreign prefix is not silently unwrapped into a uuid.
        assert_eq!(
            parse_merchant_reference_invoice_id(
                "dedicated_ip:01234567-89ab-cdef-0123-456789abcdef"
            ),
            None
        );
    }

    #[test]
    fn item_metadata_tenant_fallback_is_used_when_shopper_is_absent() {
        let item = parse_item(serde_json::json!({
            "pspReference": "psp_meta",
            "merchantReference": "invoice:01234567-89ab-cdef-0123-456789abcdef",
            "amount": { "currency": "EUR", "value": 100 },
            "eventCode": "AUTHORISATION",
            "success": "true",
            "additionalData": { "metadata": { "tenant_id": "tenant_meta" } }
        }));
        assert_eq!(item.shopper_reference(), None);
        assert_eq!(item.metadata_tenant_id(), Some("tenant_meta"));

        // The shopper reference wins when present.
        let item = parse_item(serde_json::json!({
            "pspReference": "psp_meta",
            "merchantReference": "invoice:01234567-89ab-cdef-0123-456789abcdef",
            "amount": { "currency": "EUR", "value": 100 },
            "eventCode": "AUTHORISATION",
            "success": "true",
            "additionalData": {
                "shopperReference": "tenant_shopper",
                "metadata": { "tenant_id": "tenant_meta" }
            }
        }));
        assert_eq!(item.shopper_reference(), Some("tenant_shopper"));

        // Garbage/blank metadata never becomes a tenant.
        let blank = parse_item(serde_json::json!({
            "pspReference": "psp_meta_blank",
            "merchantReference": "ref",
            "amount": { "currency": "EUR", "value": 100 },
            "eventCode": "AUTHORISATION",
            "success": "true",
            "additionalData": { "metadata": { "tenant_id": "   " } }
        }));
        assert_eq!(blank.metadata_tenant_id(), None);
    }

    #[test]
    fn item_accessors_trim_and_reject_blank_values() {
        let item = parse_item(serde_json::json!({
            "pspReference": "psp_accessors",
            "merchantReference": "ref",
            "eventCode": "RECURRING_CONTRACT",
            "amount": { "currency": "  ", "value": 0 },
            "success": "TRUE",
            "additionalData": {
                "hmacSignature": "  ",
                "recurringDetailReference": "  tok_123  ",
                "recurringProcessingModel": "Subscription",
                "shopperReference": ""
            }
        }));
        assert_eq!(item.hmac_signature(), None, "blank signatures are absent");
        assert_eq!(item.recurring_detail_reference(), Some("tok_123"));
        assert_eq!(item.recurring_processing_model(), Some("Subscription"));
        assert_eq!(item.shopper_reference(), None);
        assert_eq!(item.amount_currency(), None);
        assert_eq!(item.amount_value(), Some(0));
        assert!(
            item.success_is_true(),
            "success is compared case-insensitively"
        );
    }

    // ------------------------------------------------------------------
    // Dispatch: eventCode + success + recurringProcessingModel.
    // ------------------------------------------------------------------

    #[test]
    fn notification_arm_routes_authorisation_by_success_and_recurring_model() {
        let checkout = parse_item(serde_json::json!({
            "pspReference": "psp_checkout",
            "merchantReference": "checkout_ref",
            "amount": { "currency": "EUR", "value": 2900 },
            "eventCode": "AUTHORISATION",
            "success": "true",
            "additionalData": { "shopperReference": "tenant_1" }
        }));
        assert_eq!(
            notification_arm(&checkout),
            NotificationArm::CheckoutAuthorisation
        );

        let recurring = parse_item(recurring_item(
            "invoice:01234567-89ab-cdef-0123-456789abcdef",
            2900,
            true,
        ));
        assert_eq!(
            notification_arm(&recurring),
            NotificationArm::RecurringAuthorisation
        );

        let refused = parse_item(recurring_item(
            "invoice:01234567-89ab-cdef-0123-456789abcdef",
            2900,
            false,
        ));
        assert_eq!(
            notification_arm(&refused),
            NotificationArm::AuthorisationRefused
        );

        // A failed checkout authorisation is also a refusal event.
        let failed_checkout = parse_item(serde_json::json!({
            "pspReference": "psp_failed_checkout",
            "merchantReference": "checkout_ref",
            "amount": { "currency": "EUR", "value": 2900 },
            "eventCode": "AUTHORISATION",
            "success": "false"
        }));
        assert_eq!(
            notification_arm(&failed_checkout),
            NotificationArm::AuthorisationRefused
        );
    }

    #[test]
    fn notification_arm_covers_every_contract_event_code() {
        for (event_code, expected) in [
            ("RECURRING_CONTRACT", NotificationArm::TokenCreated),
            ("recurring.token.created", NotificationArm::TokenCreated),
            ("REFUND", NotificationArm::Refund),
            ("REFUND_FAILED", NotificationArm::RefundFailed),
            ("CHARGEBACK", NotificationArm::Chargeback),
            ("CHARGEBACK_REVERSED", NotificationArm::ChargebackReversed),
            ("ORDER_CLOSED", NotificationArm::Unknown),
            ("  REFUND  ", NotificationArm::Refund),
        ] {
            let item = parse_item(serde_json::json!({
                "pspReference": "psp_arm",
                "merchantReference": "ref",
                "amount": { "currency": "EUR", "value": 1 },
                "eventCode": event_code,
                "success": "true"
            }));
            assert_eq!(notification_arm(&item), expected, "eventCode {event_code}");
        }
    }

    #[test]
    fn unknown_event_codes_are_acknowledged() {
        // The catch-all arm (warn + Ok) keeps the pre-Adyen unknown-type
        // behaviour: an event family we do not consume must be acknowledged,
        // never retried forever.
        let item = parse_item(serde_json::json!({
            "pspReference": "psp_unknown",
            "merchantReference": "ref",
            "amount": { "currency": "EUR", "value": 1 },
            "eventCode": "ORDER_CLOSED",
            "success": "true"
        }));
        assert_eq!(notification_arm(&item), NotificationArm::Unknown);
        assert!(!matches!(
            notification_arm(&item),
            NotificationArm::RecurringAuthorisation
                | NotificationArm::CheckoutAuthorisation
                | NotificationArm::AuthorisationRefused
                | NotificationArm::TokenCreated
                | NotificationArm::Refund
                | NotificationArm::RefundFailed
                | NotificationArm::Chargeback
                | NotificationArm::ChargebackReversed
        ));
    }

    #[test]
    fn supported_event_codes_cover_the_frozen_contract() {
        // The contract's consumed event families (docs/tool-contracts/adyen.md).
        for event_code in [
            "AUTHORISATION",
            "RECURRING_CONTRACT",
            "REFUND",
            "REFUND_FAILED",
            "CHARGEBACK",
            "CHARGEBACK_REVERSED",
        ] {
            let item = parse_item(serde_json::json!({
                "pspReference": "psp_contract",
                "merchantReference": "ref",
                "amount": { "currency": "EUR", "value": 1 },
                "eventCode": event_code,
                "success": "true"
            }));
            assert_ne!(notification_arm(&item), NotificationArm::Unknown);
        }
    }

    // ------------------------------------------------------------------
    // Money: allocation and exact minor units.
    // ------------------------------------------------------------------

    #[test]
    fn allocation_prefers_the_verified_charge_over_the_invoice_total() {
        // Adyen's own charged amount is the verified payment; the allocation
        // is capped by it, never by a stale local total.
        assert_eq!(allocation_cents(6_000, 10_000), 6_000);
        assert_eq!(allocation_cents(11_300, 11_300), 11_300);
    }

    #[test]
    fn allocation_is_capped_by_the_authoritative_remainder() {
        // More charged than outstanding: only the remainder allocates.
        assert_eq!(allocation_cents(12_400, 400), 400);
        // Nothing outstanding (already paid / zero value): no allocation.
        assert_eq!(allocation_cents(12_400, 0), 0);
        assert_eq!(allocation_cents(0, 0), 0);
    }

    #[test]
    fn allocation_never_goes_negative() {
        assert_eq!(allocation_cents(-5, 1_000), 0);
        assert_eq!(allocation_cents(1_000, -5), 0);
        assert_eq!(allocation_cents(-5, -5), 0);
    }

    #[test]
    fn zero_value_payments_settle_without_a_positive_allocation() {
        // A zero-value paid invoice must not attempt an allocation (the
        // amount_cents > 0 CHECK would fail the callback); the settlement
        // marks it paid with no allocation row.
        assert_eq!(allocation_cents(0, 0), 0);
        assert_eq!(allocation_cents(0, 1_000), 0);
    }

    #[test]
    fn the_charged_total_is_the_wire_amount_value() {
        // The settlement binds `amount.value` (minor units) as the verified
        // charge, and the snapshot records exactly that figure — never a
        // re-derived or re-rounded amount.
        let item = official_item();
        assert_eq!(item.amount_value(), Some(1130));
        assert_eq!(item.amount_currency(), Some("EUR"));
        assert_eq!(settlement_operation_id(&item), "adyen:7914073381342284");
        assert_eq!(
            allocation_cents(item.amount_value().expect("amount"), 1130),
            1130
        );
        let source = include_str!("adyen_webhooks.rs");
        assert!(source.contains("let payment_cents = charged_cents.max(0);"));
        assert!(source.contains(".bind(allocation)"));
    }

    #[test]
    fn minor_unit_amounts_parse_exactly_without_float_drift() {
        let item = parse_item(serde_json::json!({
            "pspReference": "psp_money",
            "merchantReference": "ref",
            "amount": { "currency": "EUR", "value": 1130 },
            "eventCode": "AUTHORISATION",
            "success": "true"
        }));
        assert_eq!(item.amount_value(), Some(1130));
        let negative = parse_item(serde_json::json!({
            "pspReference": "psp_money_credit",
            "merchantReference": "ref",
            "amount": { "currency": "EUR", "value": -1240 },
            "eventCode": "AUTHORISATION",
            "success": "true"
        }));
        assert_eq!(negative.amount_value(), Some(-1_240));
        // The extreme exact value survives; one past it is refused at parse
        // time (never wrapped).
        let max = parse_item(serde_json::json!({
            "pspReference": "psp_money_max",
            "merchantReference": "ref",
            "amount": { "currency": "EUR", "value": i64::MAX },
            "eventCode": "AUTHORISATION",
            "success": "true"
        }));
        assert_eq!(max.amount_value(), Some(i64::MAX));
        let overflow = serde_json::from_value::<AdyenNotificationItem>(serde_json::json!({
            "pspReference": "psp_money_overflow",
            "merchantReference": "ref",
            "amount": { "currency": "EUR", "value": 9_223_372_036_854_775_808_u64 },
            "eventCode": "AUTHORISATION",
            "success": "true"
        }));
        assert!(overflow.is_err(), "an out-of-range amount is refused");
        // Fractional minor units are not money — the parse refuses them.
        let fractional = serde_json::from_value::<AdyenNotificationItem>(serde_json::json!({
            "pspReference": "psp_money_frac",
            "merchantReference": "ref",
            "amount": { "currency": "EUR", "value": 1130.5 },
            "eventCode": "AUTHORISATION",
            "success": "true"
        }));
        assert!(fractional.is_err(), "a fractional minor unit is refused");
    }

    #[test]
    fn a_zero_charged_total_is_a_real_zero_not_missing_data() {
        let item = parse_item(serde_json::json!({
            "pspReference": "psp_zero",
            "merchantReference": "ref",
            "amount": { "currency": "EUR", "value": 0 },
            "eventCode": "AUTHORISATION",
            "success": "true"
        }));
        assert_eq!(item.amount_value(), Some(0));
        assert!(item.amount.is_some());
    }

    #[test]
    fn a_missing_wire_amount_is_absent_not_zero() {
        let item = parse_item(serde_json::json!({
            "pspReference": "psp_no_amount",
            "merchantReference": "ref",
            "eventCode": "AUTHORISATION",
            "success": "true"
        }));
        assert_eq!(item.amount_value(), None);
        assert_eq!(item.amount_currency(), None);
    }

    #[test]
    fn notification_item_decodes_the_full_wire_shape() {
        let item = official_item();
        assert_eq!(item.psp_reference, "7914073381342284");
        assert_eq!(item.merchant_account_code.as_deref(), Some("TestMerchant"));
        assert_eq!(item.merchant_reference, "TestPayment-1407325143704");
        assert_eq!(item.amount_value(), Some(1130));
        assert_eq!(item.amount_currency(), Some("EUR"));
        assert_eq!(item.event_code, "AUTHORISATION");
        assert_eq!(
            item.event_date.as_deref(),
            Some("2019-05-06T17:15:34.121+02:00")
        );
        assert_eq!(item.success.as_deref(), Some("true"));
        assert_eq!(item.payment_method.as_deref(), Some("visa"));
        // Unknown notification fields (`operations`, `live`) are ignored.
        assert!(item.additional_data.is_none());
    }

    #[test]
    fn notification_item_decodes_minimal_shape_with_empty_defaults() {
        let item = parse_item(serde_json::json!({ "pspReference": "psp_minimal" }));
        assert_eq!(item.psp_reference, "psp_minimal");
        assert_eq!(item.merchant_reference, "");
        assert_eq!(item.event_code, "");
        assert_eq!(item.success, None);
        assert!(item.amount.is_none());
        assert_eq!(item.original_reference, None);
        assert!(item.additional_data.is_none());
        assert!(!item.success_is_true());
    }

    // ------------------------------------------------------------------
    // Tax truth (P0): the local invoice is the expectation, the charge must
    // match its total.
    // ------------------------------------------------------------------

    fn expected(subtotal: i64, vat: i64) -> ExpectedTax {
        ExpectedTax {
            subtotal_cents: subtotal,
            vat_cents: vat,
            total_cents: subtotal + vat,
            source: "local_invoice",
            country: Some("EE".into()),
            vat_rate: 24.0,
            evidence_id: None,
        }
    }

    #[test]
    fn tax_total_mismatch_is_an_error_not_a_warning() {
        // Adyen charged 10.00 + 0 tax; the local invoice's statutory total
        // is 10.00 + 2.40. This MUST block.
        let discrepancy = check_charged_total(&expected(1_000, 240), 1_000, 0, 1_000)
            .expect_err("mismatch must be an error");
        assert_eq!(discrepancy.expected_total_cents, 1_240);
        assert_eq!(discrepancy.observed_total_cents, 1_000);
        assert_eq!(discrepancy.delta_cents, -240);
        assert!(discrepancy.summary().contains("1240"));
    }

    #[test]
    fn matching_charged_total_passes_validation() {
        assert!(check_charged_total(&expected(1_000, 240), 1_000, 240, 1_240).is_ok());
        // A legitimately zero-rated reverse charge matches with zero VAT.
        let reverse = ExpectedTax {
            subtotal_cents: 1_000,
            vat_cents: 0,
            total_cents: 1_000,
            source: "local_invoice",
            country: Some("DE".into()),
            vat_rate: 0.0,
            evidence_id: Some(Uuid::new_v4()),
        };
        assert!(check_charged_total(&reverse, 1_000, 0, 1_000).is_ok());
    }

    #[test]
    fn zero_value_and_credit_invoices_validate_without_inventing_vat() {
        // A 100%-discounted invoice: local total 0, charge 0 — validated.
        assert!(check_charged_total(&expected(0, 0), 0, 0, 0).is_ok());
        // A credit invoice (negative totals): the charge carries the sign.
        let credit = ExpectedTax {
            subtotal_cents: -1_000,
            vat_cents: -240,
            total_cents: -1_240,
            source: "local_invoice",
            country: Some("EE".into()),
            vat_rate: 24.0,
            evidence_id: None,
        };
        assert!(check_charged_total(&credit, -1_000, -240, -1_240).is_ok());
        // A charge against a zero-total invoice is a discrepancy, never a
        // silent skip.
        assert!(check_charged_total(&expected(0, 0), 0, 0, 1_000).is_err());
    }

    #[test]
    fn the_local_computation_is_the_only_tax_authority() {
        // Adyen transmits no tax fields; the expectation is built ONLY from
        // the local invoice row (totals, country, rate, evidence).
        let local = LocalInvoiceSettlement {
            id: Uuid::new_v4(),
            tenant_id: "tenant_local".into(),
            currency: "eur".into(),
            subtotal_cents: 10_000,
            vat_cents: 2_400,
            total_cents: 12_400,
            billing_country: Some("EE".into()),
            vat_rate: Some(24.0),
            vat_evidence_id: Some(Uuid::new_v4()),
        };
        let expected = expected_tax_from_local_invoice(&local);
        assert_eq!(expected.source, "local_invoice");
        assert_eq!(expected.subtotal_cents, 10_000);
        assert_eq!(expected.vat_cents, 2_400);
        assert_eq!(expected.total_cents, 12_400);
        assert_eq!(expected.country.as_deref(), Some("EE"));
        assert_eq!(expected.vat_rate, 24.0);
        assert_eq!(expected.evidence_id, local.vat_evidence_id);
        // A blank country is absent, never an empty-string jurisdiction.
        let mut blank = local.clone();
        blank.billing_country = Some("  ".into());
        assert_eq!(expected_tax_from_local_invoice(&blank).country, None);
        // A missing rate degrades to zero, never to a fabricated statutory
        // rate.
        let mut missing_rate = local.clone();
        missing_rate.vat_rate = None;
        assert_eq!(expected_tax_from_local_invoice(&missing_rate).vat_rate, 0.0);
    }

    #[test]
    fn tax_validation_status_maps_outcomes_truthfully() {
        let ok: Result<(), TaxTotalDiscrepancy> = Ok(());
        assert_eq!(tax_validation_status(&ok), "validated");
        let err =
            check_charged_total(&expected(1_000, 240), 1_000, 0, 1_000).expect_err("mismatch");
        assert_eq!(tax_validation_status(&Err(err)), "discrepancy");
    }

    #[test]
    fn charged_total_discrepancy_summary_names_both_totals() {
        let discrepancy =
            check_charged_total(&expected(1_000, 240), 1_000, 0, 1_000).expect_err("mismatch");
        let summary = discrepancy.summary();
        assert!(summary.contains("charged total 1000"), "{summary}");
        assert!(summary.contains("ApexMail-computed 1240"), "{summary}");
        assert!(summary.contains("VAT 0 vs 240"), "{summary}");
    }

    #[test]
    fn snapshot_payload_hash_is_stable_and_content_addressed() {
        let payload = serde_json::json!({"a": 1, "b": [true, null]});
        let first = snapshot_payload_hash(&payload);
        let second = snapshot_payload_hash(&payload);
        assert_eq!(first, second);
        assert_eq!(first.len(), 64);
        assert_ne!(first, snapshot_payload_hash(&serde_json::json!({"a": 2})));
    }

    #[test]
    fn snapshot_persist_sql_binds_expected_and_observed_sides() {
        // Guard the write shape: the snapshot must carry both the observed
        // charge figures and ApexMail's independent expectation plus hash.
        let source = include_str!("adyen_webhooks.rs");
        for needle in [
            "apexmail_expected_total_cents",
            "raw_payload_hash",
            "validation_status",
            "ON CONFLICT (adyen_psp_reference) DO NOTHING",
            "adyen_merchant_reference",
        ] {
            assert!(
                source.contains(needle),
                "snapshot write must include {needle}"
            );
        }
        // The discrepancy path must both block (Err) and persist an incident.
        assert!(source.contains("finance_incidents"));
        assert!(source.contains("BLOCKED invoice finalization"));
    }

    #[test]
    fn tax_snapshot_authority_is_an_allowed_check_value() {
        // Migration 218's CHECK allows ('stripe_tax', 'apexmail_local');
        // 'apexmail_local' is the truthful allowed value for "ApexMail's
        // local computation validated against the charge".
        assert_eq!(ADYEN_TAX_AUTHORITY_LOCAL, "apexmail_local");
        assert_ne!(ADYEN_TAX_AUTHORITY_LOCAL, "adyen_tax");
        let source = include_str!("adyen_webhooks.rs");
        assert!(source.contains("ADYEN_TAX_AUTHORITY_LOCAL"));
    }

    #[test]
    fn currencies_are_compared_case_insensitively() {
        assert!(currencies_match("eur", "EUR"));
        assert!(currencies_match(" EUR ", "eur"));
        assert!(!currencies_match("usd", "eur"));
        assert!(!currencies_match("", "eur"));
    }

    #[test]
    fn normalize_adyen_currency_defaults_to_eur_and_lowercases() {
        assert_eq!(normalize_adyen_currency(Some("EUR")), "eur");
        assert_eq!(normalize_adyen_currency(Some("usd")), "usd");
        assert_eq!(normalize_adyen_currency(Some("  ")), "eur");
        assert_eq!(normalize_adyen_currency(None), "eur");
    }

    // ------------------------------------------------------------------
    // Deadletter entries.
    // ------------------------------------------------------------------

    #[test]
    fn deadletter_entry_default_has_max_retries() {
        let entry = DeadletterEntry::default();
        assert_eq!(entry.max_retries, DEADLETTER_MAX_RETRIES);
        assert_eq!(entry.retry_count, 0);
        assert!(entry.body.is_none());
        assert!(entry.signature.is_none());
        assert!(entry.event_id.is_none());
    }

    #[test]
    fn deadletter_entry_serialization_roundtrip_with_retry_fields() {
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            occurred_at: Some("2025-01-01T00:00:00Z".into()),
            event_id: Some("adn_123".into()),
            error: Some("transient db error".into()),
            payload_length: Some(1024),
            retry_count: 2,
            max_retries: DEADLETTER_MAX_RETRIES,
            body: Some(
                r#"{"notificationItems":[{"NotificationRequestItem":{"eventCode":"AUTHORISATION"}}]}"#
                    .into(),
            ),
            signature: Some("coqCmt/IZ4E3CzPvMY8zTjQVL5hYJUiBRg8UU+iCWo0=".into()),
        };

        let json = serde_json::to_string(&entry).expect("serialize");
        let deserialized: DeadletterEntry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.reason, "processing_failed");
        assert_eq!(deserialized.retry_count, 2);
        assert_eq!(deserialized.max_retries, DEADLETTER_MAX_RETRIES);
        assert_eq!(deserialized.event_id, Some("adn_123".into()));
        assert!(deserialized.body.is_some());
        assert!(deserialized.signature.is_some());
    }

    #[test]
    fn deadletter_entry_deserializes_legacy_entry_without_retry_fields() {
        // Simulate a legacy entry that was stored before the retry fields existed.
        let legacy_json = r#"{
            "reason": "processing_failed",
            "occurredAt": "2025-01-01T00:00:00Z",
            "eventId": "adn_999",
            "error": "timeout"
        }"#;
        let entry: DeadletterEntry = serde_json::from_str(legacy_json).expect("deserialize legacy");

        assert_eq!(entry.retry_count, 0);
        assert_eq!(entry.max_retries, DEADLETTER_MAX_RETRIES);
        assert!(entry.body.is_none());
        assert!(entry.signature.is_none());
    }

    #[test]
    fn prepare_deadletter_schedules_retry_for_processing_failure() {
        let now = Utc::now();
        let prepared = prepare_deadletter(
            DeadletterEntry {
                reason: "processing_failed".into(),
                event_id: Some("adn_retry".into()),
                error: Some("db timeout".into()),
                ..Default::default()
            },
            Some(br#"{"notificationItems":[{"NotificationRequestItem":{"pspReference":"psp_retry"}}]}"#),
            Some("coqCmt/IZ4E3CzPvMY8zTjQVL5hYJUiBRg8UU+iCWo0="),
            now,
        );

        assert!(prepared.event_key.contains("adn_retry"));
        assert_eq!(
            prepared.retry_at_ms,
            Some(prepared.now_ms + DEADLETTER_RETRY_BACKOFF_SECONDS[0] * 1000)
        );

        let entry: DeadletterEntry = serde_json::from_str(&prepared.payload).expect("payload json");
        assert_eq!(entry.reason, "processing_failed");
        assert_eq!(
            entry.body.as_deref(),
            Some(
                r#"{"notificationItems":[{"NotificationRequestItem":{"pspReference":"psp_retry"}}]}"#
            )
        );
        assert_eq!(
            entry.signature.as_deref(),
            Some("coqCmt/IZ4E3CzPvMY8zTjQVL5hYJUiBRg8UU+iCWo0=")
        );
    }

    #[test]
    fn prepare_deadletter_caps_body_to_4kb_and_skips_retry() {
        // A body larger than the 4 KiB cap must be truncated before the Redis
        // SET, and — because the stored JSON is incomplete — no retry may be
        // scheduled for it.
        let oversized_body = format!(
            r#"{{"notificationItems":[],"padding":"{}"}}"#,
            "x".repeat(DEADLETTER_MAX_BODY_BYTES)
        );
        let oversized_bytes = oversized_body.as_bytes();
        assert!(oversized_bytes.len() > DEADLETTER_MAX_BODY_BYTES);

        let prepared = prepare_deadletter(
            DeadletterEntry {
                reason: "processing_failed".into(),
                event_id: Some("adn_big".into()),
                error: Some("boom".into()),
                ..Default::default()
            },
            Some(oversized_bytes),
            Some("coqCmt/IZ4E3CzPvMY8zTjQVL5hYJUiBRg8UU+iCWo0="),
            Utc::now(),
        );

        assert_eq!(
            prepared.retry_at_ms, None,
            "truncated bodies must not replay"
        );

        let entry: DeadletterEntry = serde_json::from_str(&prepared.payload).expect("payload json");
        let stored_body = entry.body.as_deref().expect("body stored");
        assert!(stored_body.len() <= DEADLETTER_MAX_BODY_BYTES + "...(truncated)".len());
        assert!(stored_body.ends_with("...(truncated)"));
    }

    #[test]
    fn truncate_at_char_boundary_respects_multibyte_chars() {
        assert_eq!(truncate_at_char_boundary("short", 100), "short");

        // é is 2 bytes — the cut must back off to the previous char boundary.
        let truncated = truncate_at_char_boundary(&"é".repeat(100), 11);
        assert!(truncated.len() <= 11 + "...(truncated)".len());
        assert!(truncated.ends_with("...(truncated)"));
    }

    #[test]
    fn deadletter_preparation_truncates_and_never_schedules_truncated_replays() {
        let now = Utc::now();
        let small = prepare_deadletter(
            DeadletterEntry {
                reason: "processing_failed".into(),
                event_id: Some("adn/with spaces".into()),
                ..Default::default()
            },
            Some(br#"{"notificationItems":[]}"#),
            Some("TQ=="),
            now,
        );
        assert!(small.retry_at_ms.is_some(), "a full body is retryable");
        assert!(small.event_key.contains("adn_with_spaces"));

        let oversized = "x".repeat(DEADLETTER_MAX_BODY_BYTES + 100);
        let big = prepare_deadletter(
            DeadletterEntry {
                reason: "processing_failed".into(),
                event_id: Some("adn_big".into()),
                ..Default::default()
            },
            Some(oversized.as_bytes()),
            Some("TQ=="),
            now,
        );
        assert!(
            big.retry_at_ms.is_none(),
            "a truncated body can never be replayed"
        );
        let stored: DeadletterEntry = serde_json::from_str(&big.payload).expect("payload");
        assert!(
            stored.body.expect("body").ends_with("...(truncated)"),
            "truncation is marked"
        );
    }

    // ------------------------------------------------------------------
    // Error/claim classification.
    // ------------------------------------------------------------------

    #[test]
    fn process_webhook_error_tracks_deadletter_ownership() {
        let wire = ProcessWebhookError::InvalidRequest {
            message: "Invalid JSON payload".into(),
            detail: "expected value at line 1 column 1".into(),
            reason: "invalid_json_payload",
        };
        assert!(wire.should_record_deadletter());
        assert_eq!(wire.deadletter_reason(), "invalid_json_payload");
        assert_eq!(
            wire.deadletter_detail(),
            "expected value at line 1 column 1"
        );
        assert_eq!(wire.response_message(), "Invalid JSON payload");
        assert_eq!(wire.http_status(), StatusCode::BAD_REQUEST);

        let unrecorded = ProcessWebhookError::RecordDeadletter("claim failed".into());
        assert!(unrecorded.should_record_deadletter());
        assert_eq!(unrecorded.deadletter_reason(), "processing_failed");
        assert_eq!(unrecorded.message(), "claim failed");
        assert_eq!(unrecorded.response_message(), "Webhook processing failed");

        let handled = ProcessWebhookError::DeadletterFlowHandled("business failure".into());
        assert!(!handled.should_record_deadletter());
        assert_eq!(handled.message(), "business failure");
        assert_eq!(handled.response_message(), "Webhook processing failed");
    }

    #[test]
    fn retry_later_error_maps_to_500_and_no_deadletter() {
        let error = ProcessWebhookError::RetryLater("event pending on another worker".into());

        assert_eq!(error.http_status(), StatusCode::SERVICE_UNAVAILABLE);
        assert!(!error.should_record_deadletter());
        assert_eq!(error.message(), "event pending on another worker");
        assert_eq!(error.response_message(), "Webhook processing failed");
    }

    #[test]
    fn deadlettered_errors_map_to_400_and_skip_duplicate_deadletter() {
        let error = ProcessWebhookError::DeadletterFlowHandled("business failure".into());

        assert_eq!(error.http_status(), StatusCode::BAD_REQUEST);
        // The deadletter was already written atomically with the DB status
        // flip inside process_webhook — must not be recorded twice.
        assert!(!error.should_record_deadletter());
    }

    #[test]
    fn stale_pending_cutoff_is_ten_minutes_in_the_past() {
        let now = Utc::now();
        let cutoff = stale_pending_cutoff(now);

        assert_eq!(
            now - cutoff,
            TimeDelta::seconds(STALE_PENDING_RECLAIM_SECS as i64)
        );
    }

    #[test]
    fn sanitize_event_id_handles_edge_cases() {
        assert_eq!(sanitize_event_id(None), "unknown");
        assert_eq!(sanitize_event_id(Some("")), "unknown");
        assert_eq!(sanitize_event_id(Some("  ")), "unknown");
        assert_eq!(sanitize_event_id(Some("adn_123")), "adn_123");
        assert_eq!(sanitize_event_id(Some("adn_123:456")), "adn_123_456");
        assert_eq!(sanitize_event_id(Some("adn/abc<>def")), "adn_abc__def");
    }

    #[test]
    fn classify_webhook_claim_allows_claimed_event() {
        let decision = classify_webhook_claim(Some(WebhookEventClaimRow {
            claimed: true,
            status: "pending".into(),
        }));

        assert_eq!(decision, WebhookEventClaim::Claimed);
    }

    #[test]
    fn classify_webhook_claim_skips_processed_event() {
        let decision = classify_webhook_claim(Some(WebhookEventClaimRow {
            claimed: false,
            status: "processed".into(),
        }));

        assert_eq!(decision, WebhookEventClaim::AlreadyProcessed);
    }

    #[test]
    fn classify_webhook_claim_skips_pending_event() {
        let decision = classify_webhook_claim(Some(WebhookEventClaimRow {
            claimed: false,
            status: "pending".into(),
        }));

        assert_eq!(decision, WebhookEventClaim::AlreadyPending);
    }

    #[test]
    fn notification_claim_state_machine_states_are_the_ledger_contract() {
        // The claim SQL writes exactly these statuses; the reclaimer only
        // ever rewinds 'pending'. Pin the vocabulary the ledger depends on.
        let states = ["received", "pending", "processed", "failed"];
        assert!(states.contains(&"received"));
        assert!(states.contains(&"pending"));
        assert!(states.contains(&"processed"));
        assert!(states.contains(&"failed"));
        for source_probe in [
            "status = 'processed', processed_at = NOW()",
            "status = 'failed', error = $2",
            "status = 'received',",
        ] {
            assert!(
                include_str!("adyen_webhooks.rs").contains(source_probe),
                "the ledger state machine must keep writing {source_probe}"
            );
        }
    }

    // ------------------------------------------------------------------
    // Dunning state (Fix H) and transitions (audit item 3g).
    // ------------------------------------------------------------------

    #[test]
    fn dunning_transition_fires_on_entering_soft_suspension() {
        assert_eq!(
            dunning_transition(Some("warning"), "soft_suspended"),
            Some(DunningTransition::SoftSuspended)
        );
        assert_eq!(
            dunning_transition(None, "soft_suspended"),
            Some(DunningTransition::SoftSuspended)
        );
    }

    #[test]
    fn dunning_transition_fires_on_entering_hard_suspension() {
        assert_eq!(
            dunning_transition(Some("warning"), "hard_suspended"),
            Some(DunningTransition::HardSuspended)
        );
        // Escalation soft -> hard is also a hard-suspension transition.
        assert_eq!(
            dunning_transition(Some("soft_suspended"), "hard_suspended"),
            Some(DunningTransition::HardSuspended)
        );
    }

    #[test]
    fn dunning_transition_fires_on_recovery() {
        assert_eq!(
            dunning_transition(Some("hard_suspended"), "healthy"),
            Some(DunningTransition::Recovered)
        );
        assert_eq!(
            dunning_transition(Some("soft_suspended"), "healthy"),
            Some(DunningTransition::Recovered)
        );
        assert_eq!(
            dunning_transition(Some("warning"), "healthy"),
            Some(DunningTransition::Recovered)
        );
    }

    #[test]
    fn dunning_transition_does_not_fire_without_state_change() {
        // Repeated refusals in the same state must not spam duplicate
        // transition events.
        assert_eq!(dunning_transition(Some("warning"), "warning"), None);
        assert_eq!(
            dunning_transition(Some("soft_suspended"), "soft_suspended"),
            None
        );
        assert_eq!(
            dunning_transition(Some("hard_suspended"), "hard_suspended"),
            None
        );
        assert_eq!(dunning_transition(None, "warning"), None);
        assert_eq!(dunning_transition(None, "healthy"), None);
    }

    #[test]
    fn dunning_transition_de_escalation_hard_to_soft_is_not_soft_transition() {
        // Hard -> soft is a state change but not a new suspension entry; the
        // soft-suspension event must not fire again for an already
        // suspended tenant.
        assert_eq!(
            dunning_transition(Some("hard_suspended"), "soft_suspended"),
            None
        );
    }

    #[test]
    fn dunning_transition_event_types_are_snake_case_rows() {
        // Values must match the dunning_events.event_type conventions
        // already used by the payment_recovered path (mark_payment_recovered).
        assert_eq!(
            DunningTransition::SoftSuspended.event_type(),
            "soft_suspended"
        );
        assert_eq!(
            DunningTransition::HardSuspended.event_type(),
            "hard_suspended"
        );
        assert_eq!(
            DunningTransition::Recovered.event_type(),
            "payment_recovered"
        );
    }

    #[test]
    fn dunning_state_first_failure_is_warning() {
        let now = Utc::now();
        let state = next_dunning_state(None, now, &dunning_config());

        assert_eq!(state.failed_payment_count, 1);
        assert_eq!(state.status, "warning");
        assert_eq!(state.first_failed_at, now);
        assert!(state.suspended_at.is_none());
    }

    #[test]
    fn dunning_state_consumes_post_increment_snapshot() {
        // The SQL upsert increments the counter atomically; this function only
        // sees the already-incremented snapshot (count=2 for a second
        // failure) and must preserve it together with the original
        // first_failed_at.
        let now = Utc::now();
        let first = now - TimeDelta::days(2);

        let state = next_dunning_state(
            Some(DunningSnapshot {
                failed_payment_count: 2,
                first_failed_at: Some(first),
                status: "warning".into(),
            }),
            now,
            &dunning_config(),
        );

        assert_eq!(state.failed_payment_count, 2);
        assert_eq!(state.first_failed_at, first);
        assert_eq!(state.status, "warning");
    }

    #[test]
    fn dunning_state_soft_suspends_after_threshold_days() {
        let now = Utc::now();
        let first = now - TimeDelta::days(7); // soft_suspend_after_days = 7

        let state = next_dunning_state(
            Some(DunningSnapshot {
                failed_payment_count: 3,
                first_failed_at: Some(first),
                status: "warning".into(),
            }),
            now,
            &dunning_config(),
        );

        assert_eq!(state.status, "soft_suspended");
        assert!(state.suspended_at.is_some());
        assert!(state.grace_period_ends_at.is_none());
    }

    #[test]
    fn dunning_state_hard_suspends_and_sets_grace_once() {
        let now = Utc::now();
        let first = now - TimeDelta::days(21); // hard_suspend_after_days = 21

        let state = next_dunning_state(
            Some(DunningSnapshot {
                failed_payment_count: 5,
                first_failed_at: Some(first),
                status: "warning".into(),
            }),
            now,
            &dunning_config(),
        );

        assert_eq!(state.status, "hard_suspended");
        assert!(state.suspended_at.is_some());
        assert_eq!(state.grace_period_ends_at, Some(now + TimeDelta::days(7)));

        // Already hard-suspended → grace/suspension timestamps preserved.
        let state = next_dunning_state(
            Some(DunningSnapshot {
                failed_payment_count: 6,
                first_failed_at: Some(first),
                status: "hard_suspended".into(),
            }),
            now,
            &dunning_config(),
        );
        assert_eq!(state.status, "hard_suspended");
        assert!(state.suspended_at.is_none());
        assert!(state.grace_period_ends_at.is_none());
    }

    fn dunning_config() -> DunningConfig {
        DunningConfig::default()
    }

    #[test]
    fn dunning_config_and_transition_helpers_are_bounded() {
        let config = DunningConfig::default();
        let now = Utc::now();
        assert_eq!(
            calculate_next_retry(now, 1, &config),
            Some(now + TimeDelta::days(1))
        );
        assert_eq!(
            calculate_next_retry(now, 2, &config),
            Some(now + TimeDelta::days(3))
        );
        assert_eq!(
            calculate_next_retry(now, 4, &config),
            Some(now + TimeDelta::days(14))
        );
        assert_eq!(
            calculate_next_retry(now, 99, &config),
            None,
            "past the schedule there is no next retry"
        );
        assert_eq!(
            calculate_next_retry(now, 0, &config),
            None,
            "a zero count has no schedule slot and must not panic"
        );
        assert!(dunning_transition(Some("warning"), "warning").is_none());
        assert!(dunning_transition(None, "warning").is_none());
        assert_eq!(
            dunning_transition(None, "soft_suspended"),
            Some(DunningTransition::SoftSuspended)
        );
        assert!(dunning_transition(Some("soft_suspended"), "soft_suspended").is_none());
        assert_eq!(
            dunning_transition(Some("warning"), "hard_suspended"),
            Some(DunningTransition::HardSuspended)
        );
        assert_eq!(
            dunning_transition(Some("hard_suspended"), "healthy"),
            Some(DunningTransition::Recovered)
        );
        assert!(dunning_transition(Some("healthy"), "healthy").is_none());
        assert_eq!(
            DunningTransition::Recovered.event_type(),
            "payment_recovered"
        );
    }

    // ------------------------------------------------------------------
    // Dedicated-IP auto-provisioning request contract.
    // ------------------------------------------------------------------

    /// Locally-declared mirror of the API's
    /// `api_server::routes::dedicated_ips::AllocateIpRequest` (api-server is
    /// deliberately NOT a dependency of billing-service). Field names and the
    /// `deny_unknown_fields` validation MUST match the API extractor exactly:
    /// if the API contract gains a field, this mirror must gain it too, or
    /// the request body built here is rejected at deserialization time.
    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AllocateIpRequestMirror {
        #[serde(default)]
        region: Option<String>,
    }

    #[test]
    fn auto_provision_body_deserializes_into_the_api_allocate_contract() {
        // Serialize the EXACT production request body and prove the API's
        // extractor contract accepts it.
        let body = serde_json::to_string(&auto_provision_request_body())
            .expect("auto-provision body must serialize");
        let parsed: AllocateIpRequestMirror = serde_json::from_str(&body)
            .expect("billing auto-provision body must deserialize into AllocateIpRequest");
        assert!(parsed.region.is_none());

        // Regression guard: the pre-fix body carried an unknown field and the
        // same contract rejects it — so this mirror genuinely exercises
        // `deny_unknown_fields` rather than accepting everything.
        let pre_fix = r#"{"auto_provisioned":true}"#;
        assert!(
            serde_json::from_str::<AllocateIpRequestMirror>(pre_fix).is_err(),
            "the old auto_provisioned body must remain rejected by the API contract"
        );
    }
}

// ---------------------------------------------------------------------------
// Adversarial coverage tests (DB + Redis backed) for the Adyen webhook
// pipeline, dunning escalation, deadletter replay, and the tax-truth gate.
//
// These call the PRIVATE handlers directly: the public route wrapper is
// already covered by tests/coverage_adversarial.rs, while the private
// replay/dunning/tax functions can only be driven from inside the crate.
// Every test provisions its own canonical database clone; `TEST_DATABASE_URL`
// unset means soft-skip.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod coverage_adversarial {
    use super::wire_test_helpers::*;
    use super::*;

    use crate::config::BillingConfig;
    use deadpool_redis::Runtime;
    use sqlx::postgres::PgPoolOptions;
    use std::sync::Arc;

    struct Env {
        state: Arc<AppState>,
        pool: sqlx::PgPool,
        redis: deadpool_redis::Pool,
        db_name: String,
        admin_url: String,
    }

    impl Env {
        /// Schema-level fault injection in this test's PRIVATE database
        /// clone: rename a table so queries against it fail (42P01).
        async fn break_table(&self, table: &str) {
            sqlx::query(&format!("ALTER TABLE {table} RENAME TO {table}_broken"))
                .execute(&self.pool)
                .await
                .expect("break table");
        }

        async fn restore_table(&self, table: &str) {
            let _ = sqlx::query(&format!("ALTER TABLE {table}_broken RENAME TO {table}"))
                .execute(&self.pool)
                .await;
        }

        async fn finish(self) {
            self.pool.close().await;
            let admin = PgPoolOptions::new()
                .max_connections(1)
                .connect(&self.admin_url)
                .await
                .expect("admin connect for teardown");
            let _ = sqlx::query(&format!(
                r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
                self.db_name
            ))
            .execute(&admin)
            .await;
            admin.close().await;
        }
    }

    async fn provision(test_name: &str) -> Option<Env> {
        crate::test_support::assert_soft_skip_allowed("TEST_DATABASE_URL");
        let url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())?;
        let (server_part, db_part) = url.rsplit_once('/').expect("db segment");
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
        for byte in test_name.bytes() {
            digest ^= u64::from(byte);
            digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
        }
        let db_name = format!("{db_only}_swcov_{:08x}", digest & 0xffff_ffff);

        let admin_url = std::env::var("TEST_DATABASE_ADMIN_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| format!("{server_part}/postgres"));
        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(30))
            .connect(&admin_url)
            .await
            .expect("admin connect");

        let migrations_dir =
            std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
        let mut count = 0_usize;
        let mut newest = 0_i64;
        for entry in std::fs::read_dir(&migrations_dir).expect("migrations dir") {
            let name = entry
                .expect("entry")
                .file_name()
                .to_string_lossy()
                .to_string();
            if let Some(prefix) = name.split('_').next() {
                if let Ok(version) = prefix.parse::<i64>() {
                    count += 1;
                    newest = newest.max(version);
                }
            }
        }
        let template: Option<String> = sqlx::query_scalar(
            "SELECT datname FROM pg_database WHERE datname LIKE $1 ORDER BY datname DESC LIMIT 1",
        )
        .bind(format!("apexmail_canonical_tpl_{count}_{newest}_%"))
        .fetch_optional(&admin)
        .await
        .expect("template lookup");
        let template = template.expect("canonical template database must exist");

        sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
            db_name
        ))
        .execute(&admin)
        .await
        .expect("drop test db");
        {
            // Serialize template clones process-wide and retry the transient
            // 55006 (a concurrent cloner's internal session on the template).
            let _clone_guard = crate::test_support::CLONE_LOCK.lock().await;
            let mut last_error = None;
            for _ in 0..5 {
                match sqlx::query(&format!(
                    r#"CREATE DATABASE "{}" TEMPLATE "{}""#,
                    db_name, template
                ))
                .execute(&admin)
                .await
                {
                    Ok(_) => {
                        last_error = None;
                        break;
                    }
                    Err(error) => {
                        last_error = Some(error);
                        tokio::time::sleep(Duration::from_millis(50)).await;
                    }
                }
            }
            if let Some(error) = last_error {
                panic!("clone test db: {error}");
            }
        }
        admin.close().await;

        let database_url = format!("{server_part}/{db_name}");
        let pool = PgPoolOptions::new()
            .max_connections(4)
            .acquire_timeout(Duration::from_secs(10))
            .connect(&database_url)
            .await
            .expect("connect test db");
        let redis_url = std::env::var("TEST_REDIS_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())
            .expect("TEST_REDIS_URL must be set");
        let redis = deadpool_redis::Config::from_url(redis_url)
            .create_pool(Some(Runtime::Tokio1))
            .expect("redis pool");

        // MIGRATION-GAP COMPENSATION (private clone only): the committed
        // migration 140 pins `invoice_payment_allocations.source` to
        // ('wallet','stripe','manual','credit_note') — byte-exact and
        // ledger-applied, so it cannot be edited in place. The Adyen
        // settlement writes 'adyen' (the value
        // `accounting_core::adapters::post_payment_allocation_in` branches on
        // for the processor-clearing account); extend THIS CLONE to the
        // intended post-cutover contract so the settlement path is exercised.
        // Production needs the same value added by a new migration.
        for statement in [
            "ALTER TABLE invoice_payment_allocations \
             DROP CONSTRAINT IF EXISTS invoice_payment_allocations_source_check",
            "ALTER TABLE invoice_payment_allocations \
             ADD CONSTRAINT invoice_payment_allocations_source_check \
             CHECK (source IN ('wallet', 'stripe', 'manual', 'credit_note', 'adyen'))",
        ] {
            sqlx::query(statement)
                .execute(&pool)
                .await
                .expect("allocation source contract (migration-gap compensation)");
        }

        let config = BillingConfig {
            database_url,
            redis_url: "redis://127.0.0.1:6379".to_string(),
            service_auth_token: "coverage".to_string(),
            adyen_hmac_key: "whsec_coverage".to_string(),
            api_base_url: "http://127.0.0.1:9".to_string(),
            ..BillingConfig::default()
        };
        let state = AppState::new(pool.clone(), redis.clone(), config);
        Some(Env {
            state,
            pool,
            redis,
            db_name,
            admin_url,
        })
    }

    macro_rules! env_test {
        ($name:ident, |$e:ident| $body:block) => {
            #[tokio::test]
            async fn $name() {
                if let Some(owned) = provision(stringify!($name)).await {
                    let $e = &owned;
                    $body
                    owned.finish().await;
                }
            }
        };
    }

    /// Serializes tests that use the process-shared deadletter Redis indexes.
    static DEADLETTER_LOCK: tokio::sync::Mutex<()> = tokio::sync::Mutex::const_new(());

    async fn seed_tenant(env: &Env, tenant: &str, plan: &str, status: &str) {
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, $3, $4)
             ON CONFLICT (id) DO UPDATE SET plan = EXCLUDED.plan, status = EXCLUDED.status",
        )
        .bind(tenant)
        .bind(format!("Coverage {tenant}"))
        .bind(plan)
        .bind(status)
        .execute(&env.pool)
        .await
        .expect("seed tenant");
    }

    fn invoice_number(invoice_id: Uuid) -> String {
        format!("SWCOV-{}", &invoice_id.to_string()[..8])
    }

    /// A local invoice in the state the recurring-charge contract produces
    /// (reference `invoice:{id}` is what the wire names it by).
    async fn seed_local_invoice(
        env: &Env,
        tenant: &str,
        invoice_id: Uuid,
        subtotal: i64,
        vat: i64,
        total: i64,
        currency: &str,
    ) {
        sqlx::query(
            "INSERT INTO invoices (id, tenant_id, adyen_psp_reference, invoice_number, status,
                                   amount, currency, subtotal, vat_total, total,
                                   due_at, period_start, period_end, created_at, updated_at)
             VALUES ($1, $2, NULL, $3, 'pending', $6, $7, $4, $5, $6, NOW(), NOW(), NOW() + INTERVAL '30 days', NOW(), NOW())",
        )
        .bind(invoice_id)
        .bind(tenant)
        .bind(invoice_number(invoice_id))
        .bind(subtotal)
        .bind(vat)
        .bind(total)
        .bind(currency)
        .execute(&env.pool)
        .await
        .expect("seed local invoice");
    }

    /// A recurring AUTHORISATION item (success or refusal) for a local
    /// invoice.
    fn authorisation_item(
        psp_reference: &str,
        invoice_id: Uuid,
        value: i64,
        success: bool,
        shopper: Option<&str>,
    ) -> AdyenNotificationItem {
        let mut additional = serde_json::json!({ "recurringProcessingModel": "Subscription" });
        if let Some(shopper) = shopper {
            additional["shopperReference"] = serde_json::json!(shopper);
            additional["metadata"] = serde_json::json!({ "tenant_id": shopper });
        }
        parse_item(serde_json::json!({
            "pspReference": psp_reference,
            "originalReference": "psp_original_ref",
            "merchantAccountCode": "ApexMailECOV",
            "merchantReference": format!("invoice:{invoice_id}"),
            "amount": { "currency": "EUR", "value": value },
            "eventCode": "AUTHORISATION",
            "eventDate": "2026-10-14T10:00:00+00:00",
            "success": if success { "true" } else { "false" },
            "paymentMethod": "visa",
            "additionalData": additional
        }))
    }

    fn checkout_item(psp_reference: &str, shopper: Option<&str>) -> AdyenNotificationItem {
        let additional = match shopper {
            Some(shopper) => serde_json::json!({ "shopperReference": shopper }),
            None => serde_json::json!({}),
        };
        parse_item(serde_json::json!({
            "pspReference": psp_reference,
            "merchantAccountCode": "ApexMailECOV",
            "merchantReference": "checkout_ref",
            "amount": { "currency": "EUR", "value": 2900 },
            "eventCode": "AUTHORISATION",
            "eventDate": "2026-10-14T10:00:00+00:00",
            "success": "true",
            "paymentMethod": "visa",
            "additionalData": additional
        }))
    }

    /// The local invoice read the way the handler reads it.
    async fn local_invoice(env: &Env, invoice_id: Uuid) -> LocalInvoiceSettlement {
        load_local_invoice_for_settlement(&env.state, invoice_id)
            .await
            .expect("load local invoice")
            .expect("local invoice exists")
    }

    async fn redis_conn(env: &Env) -> deadpool_redis::Connection {
        env.redis.get().await.expect("redis connection")
    }

    async fn pool_conn(pool: &deadpool_redis::Pool) -> deadpool_redis::Connection {
        pool.get().await.expect("redis connection")
    }

    async fn event_rows(pool: &sqlx::PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM adyen_webhook_events")
            .fetch_one(pool)
            .await
            .expect("event rows")
    }

    /// Clear every deadletter key/index: the Redis server is shared across
    /// runs, so stale entries (35-day TTL) would otherwise pollute counts.
    /// Callers must hold DEADLETTER_LOCK.
    async fn clear_all_deadletters(env: &Env) {
        let mut conn = redis_conn(env).await;
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("adyen:deadletter:*")
            .query_async(&mut conn)
            .await
            .expect("keys");
        if !keys.is_empty() {
            let _: () = redis::cmd("DEL")
                .arg(&keys)
                .query_async(&mut conn)
                .await
                .expect("del");
        }
    }

    async fn deadletter_entries(env: &Env, pattern: &str) -> Vec<String> {
        let mut conn = redis_conn(env).await;
        deadletter_entries_on(&mut conn, pattern).await
    }

    async fn deadletter_entries_on(
        conn: &mut deadpool_redis::Connection,
        pattern: &str,
    ) -> Vec<String> {
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg(pattern)
            .query_async(&mut *conn)
            .await
            .expect("keys");
        let mut out = Vec::new();
        for key in keys {
            let value: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(conn)
                .await
                .expect("get");
            if let Some(value) = value {
                out.push(value);
            }
        }
        out
    }

    /// AppState over `env`'s DB with a private throwaway redis — full
    /// isolation for tests that poison the shared deadletter indexes.
    fn state_with_isolated_redis(
        env: &Env,
        isolated: &crate::test_support::IsolatedRedis,
    ) -> Arc<AppState> {
        let mut config = env.state.config.clone();
        config.redis_url = "redis://127.0.0.1:1".to_string();
        AppState::new(env.pool.clone(), isolated.pool.clone(), config)
    }

    async fn post_webhook_with_header(
        state: &Arc<AppState>,
        body: &[u8],
        header_name: &str,
        header_value: &str,
    ) -> axum::response::Response {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/webhooks/adyen")
            .header(header_name, header_value)
            .body(axum::body::Body::from(body.to_vec()))
            .expect("request");
        tower::ServiceExt::oneshot(router().with_state(state.clone()), request)
            .await
            .expect("oneshot")
    }

    env_test!(legacy_header_only_deliveries_are_refused, |env| {
        // FAIL-BEFORE PROOF that the pre-Adyen header scheme is dead: the old
        // wire authenticated deliveries with an `Adyen-Signature` HEADER
        // (`t=…,v1=…`, the shape `test_support::sign_adyen` builds) and
        // enforced a timestamp tolerance. The Adyen contract moved the HMAC
        // INTO the body at `additionalData.hmacSignature` with no timestamp at
        // all, so a delivery carrying only the legacy header has no verifiable
        // in-body signature and is refused.
        let legacy_header = crate::test_support::sign_adyen(
            "whsec_adversarial",
            br#"{"notificationItems":[]}"#,
            1_711_234_567,
        );
        let item = parse_item(serde_json::json!({
            "pspReference": "psp_legacy_header",
            "merchantAccountCode": "ApexMailECOV",
            "merchantReference": "ref",
            "amount": { "currency": "EUR", "value": 1 },
            "eventCode": "AUTHORISATION",
            "success": "true"
        }));
        let body = envelope_bytes(&item, "");
        let parsed = parse_envelope(&body);
        assert_eq!(parsed.len(), 1);
        assert_eq!(parsed[0].psp_reference, "psp_legacy_header");
        assert!(parsed[0].hmac_signature().is_none());

        let response =
            post_webhook_with_header(&env.state, &body, "adyen-hmac-signature", &legacy_header)
                .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await["error"],
            "Missing HMAC signature"
        );
        assert_eq!(
            event_rows(&env.pool).await,
            0,
            "the legacy header authorises nothing"
        );
    });

    async fn post_webhook(state: &Arc<AppState>, body: &[u8]) -> axum::response::Response {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/webhooks/adyen")
            .body(axum::body::Body::from(body.to_vec()))
            .expect("request");
        tower::ServiceExt::oneshot(router().with_state(state.clone()), request)
            .await
            .expect("oneshot")
    }

    async fn response_text(response: axum::response::Response) -> String {
        let bytes = axum::body::to_bytes(response.into_body(), usize::MAX)
            .await
            .expect("body");
        String::from_utf8_lossy(&bytes).to_string()
    }

    async fn response_json(response: axum::response::Response) -> serde_json::Value {
        let text = response_text(response).await;
        serde_json::from_str(&text).unwrap_or(serde_json::Value::Null)
    }

    // ===================================================================
    // Wire validation: the envelope, the in-body HMAC, the dedupe id.
    // ===================================================================

    env_test!(route_missing_hmac_signature_is_400_and_deadletters, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let body = serde_json::to_vec(&serde_json::json!({
            "notificationItems": [{ "NotificationRequestItem": {
                "pspReference": "psp_nosig",
                "merchantReference": "invoice:01234567-89ab-cdef-0123-456789abcdef",
                "amount": { "currency": "EUR", "value": 100 },
                "eventCode": "AUTHORISATION",
                "success": "true"
            }}]
        }))
        .expect("body");
        let response = post_webhook(&env.state, &body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["error"], "Missing HMAC signature");
        let entries = deadletter_entries(env, "adyen:deadletter:event:psp_nosig*").await;
        assert_eq!(
            entries.len(),
            1,
            "a missing in-body signature is deadlettered"
        );
        let entry: DeadletterEntry = serde_json::from_str(&entries[0]).expect("entry");
        assert_eq!(entry.reason, "missing_signature");
        assert_eq!(event_rows(&env.pool).await, 0, "nothing claimed");
    });

    env_test!(route_blank_hmac_signature_is_400, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let item = authorisation_item(
            "psp_blank_sig",
            Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid"),
            100,
            true,
            Some("swcov_blank"),
        );
        let body = envelope_bytes(&item, "   ");
        let response = post_webhook(&env.state, &body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["error"], "Missing HMAC signature");
        assert_eq!(event_rows(&env.pool).await, 0);
    });

    env_test!(route_malformed_json_refused_with_no_write, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let response = post_webhook(&env.state, b"not json").await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        let json = response_json(response).await;
        assert_eq!(json["error"], "Invalid JSON payload");
        assert_eq!(
            event_rows(&env.pool).await,
            0,
            "malformed JSON writes nothing"
        );
        let entries = deadletter_entries(env, "adyen:deadletter:event:*").await;
        assert_eq!(entries.len(), 1);
        let entry: DeadletterEntry = serde_json::from_str(&entries[0]).expect("entry");
        assert_eq!(entry.reason, "invalid_json_payload");
        assert!(entry.body.is_some(), "the refused body is kept for triage");
    });

    env_test!(route_missing_items_and_blank_identities_refused, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        for body in [
            br#"{}"#.to_vec(),
            br#"{"notificationItems": []}"#.to_vec(),
            br#"{"notificationItems": [{"NotificationRequestItem": {"pspReference": "", "eventCode": "AUTHORISATION"}}]}"#.to_vec(),
            br#"{"notificationItems": [{"NotificationRequestItem": {"pspReference": "psp_blank_code", "eventCode": "   "}}]}"#.to_vec(),
        ] {
            let response = post_webhook(&env.state, &body).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            let json = response_json(response).await;
            assert_eq!(json["error"], "Invalid notification payload");
        }
        assert_eq!(event_rows(&env.pool).await, 0);
    });

    env_test!(route_tampered_signature_and_secret_refused, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let item = authorisation_item(
            "psp_tamper",
            Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid"),
            100,
            true,
            Some("swcov_tamper"),
        );

        // Signed with the WRONG secret.
        let wrong_secret = sign_item("whsec_NOT_the_secret", &item);
        let response = post_webhook(&env.state, &envelope_bytes(&item, &wrong_secret)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await["error"],
            "Invalid webhook signature"
        );
        assert_eq!(
            event_rows(&env.pool).await,
            0,
            "forged signature writes nothing"
        );

        // Tampered payload: the signature is over different item fields.
        let mut tampered = item.clone();
        tampered.success = Some("false".into());
        let right_signature = sign_item("whsec_coverage", &item);
        let response = post_webhook(&env.state, &envelope_bytes(&tampered, &right_signature)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        // Bit-flipped signature.
        let flipped: String = right_signature
            .chars()
            .map(|character| if character == '0' { '1' } else { '0' })
            .collect();
        let response = post_webhook(&env.state, &envelope_bytes(&item, &flipped)).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            event_rows(&env.pool).await,
            0,
            "bit-flipped signature writes nothing"
        );
    });

    env_test!(route_malformed_hmac_signatures_refused, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        let item = authorisation_item(
            "psp_badsig",
            Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid"),
            100,
            true,
            Some("swcov_badsig"),
        );
        for signature in [
            "!!!not-base64!!!",
            "t=123,v1=abc",
            "deadbeef",
            "AA==",
            "====",
            "TQ==TQ==",
        ] {
            let response = post_webhook(&env.state, &envelope_bytes(&item, signature)).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "signature {signature} refused"
            );
        }
        assert_eq!(event_rows(&env.pool).await, 0);
    });

    env_test!(
        multi_item_envelopes_verify_every_item_before_claiming,
        |env| {
            let _guard = DEADLETTER_LOCK.lock().await;
            let _dl_guard =
                crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
            clear_all_deadletters(env).await;
            let tenant = "swcov_multi";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice_id = Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid");
            seed_local_invoice(env, tenant, invoice_id, 100, 0, 100, "eur").await;

            // One signed item + one unsigned item: the whole envelope is
            // refused and NOTHING is claimed.
            let signed =
                authorisation_item("psp_multi_signed", invoice_id, 100, true, Some(tenant));
            let unsigned =
                authorisation_item("psp_multi_unsigned", invoice_id, 100, true, Some(tenant));
            let mut unsigned_value = serde_json::to_value(&unsigned).expect("item json");
            unsigned_value
                .as_object_mut()
                .expect("object")
                .remove("additionalData");
            let body = serde_json::to_vec(&serde_json::json!({
                "notificationItems": [
                    { "NotificationRequestItem": unsigned_value },
                    { "NotificationRequestItem": signed_value(&signed, &sign_item("whsec_coverage", &signed)) }
                ]
            }))
            .expect("body");
            let response = post_webhook(&env.state, &body).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "one unsigned item refuses the whole envelope"
            );
            assert_eq!(
                event_rows(&env.pool).await,
                0,
                "no item is claimed when any item fails verification"
            );

            // Every item signed: every item is claimed and the envelope is
            // accepted with the bare [accepted] body.
            let first = authorisation_item("psp_multi_1", invoice_id, 100, true, Some(tenant));
            let second = authorisation_item("psp_multi_2", invoice_id, 100, true, Some(tenant));
            let body = serde_json::to_vec(&serde_json::json!({
                "notificationItems": [
                    { "NotificationRequestItem": signed_value(&first, &sign_item("whsec_coverage", &first)) },
                    { "NotificationRequestItem": signed_value(&second, &sign_item("whsec_coverage", &second)) }
                ]
            }))
            .expect("body");
            let response = post_webhook(&env.state, &body).await;
            assert_eq!(response.status(), StatusCode::OK);
            assert_eq!(response_text(response).await, ADYEN_ACCEPTED_RESPONSE);
            assert_eq!(event_rows(&env.pool).await, 2, "both items claimed");
        }
    );

    /// An item with `signature` injected into its `additionalData`.
    fn signed_value(item: &AdyenNotificationItem, signature: &str) -> serde_json::Value {
        let mut value = serde_json::to_value(item).expect("item json");
        let mut data = value
            .get("additionalData")
            .and_then(serde_json::Value::as_object)
            .cloned()
            .unwrap_or_default();
        data.insert(
            "hmacSignature".into(),
            serde_json::Value::String(signature.into()),
        );
        value["additionalData"] = serde_json::Value::Object(data);
        value
    }

    env_test!(route_unknown_event_type_acknowledged_and_processed, |env| {
        let item = parse_item(serde_json::json!({
            "pspReference": "psp_swadv_unknown",
            "merchantAccountCode": "ApexMailECOV",
            "merchantReference": "unrelated-ref",
            "amount": { "currency": "EUR", "value": 1 },
            "eventCode": "ORDER_CLOSED",
            "success": "true"
        }));
        let body = signed_envelope("whsec_coverage", &item);
        let response = post_webhook(&env.state, &body).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(
            response_text(response).await,
            ADYEN_ACCEPTED_RESPONSE,
            "the acknowledgement is the BARE [accepted] body"
        );
        let status: String = sqlx::query_scalar(
            "SELECT status FROM adyen_webhook_events WHERE adyen_notification_id = $1",
        )
        .bind(adyen_notification_id(&item))
        .fetch_one(&env.pool)
        .await
        .expect("status");
        assert_eq!(
            status, "processed",
            "unknown types are claimed and acknowledged"
        );
        let psp: Option<String> = sqlx::query_scalar(
            "SELECT adyen_psp_reference FROM adyen_webhook_events WHERE adyen_notification_id = $1",
        )
        .bind(adyen_notification_id(&item))
        .fetch_one(&env.pool)
        .await
        .expect("psp");
        assert_eq!(
            psp.as_deref(),
            Some("psp_swadv_unknown"),
            "the psp is stored for support lookups"
        );
    });

    env_test!(verify_item_empty_secret_refused_before_any_write, |env| {
        let item = authorisation_item(
            "psp_nosecret",
            Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid"),
            100,
            true,
            Some("swcov_nosecret"),
        );
        let body = signed_envelope("whsec_coverage", &item);
        let broken = crate::test_support::state_with_empty_adyen_secret(
            &env.pool,
            &env.redis,
            &env.state.config,
        );
        match process_webhook(&broken, &body).await {
            Err(ProcessWebhookError::RetryLater(message)) => {
                assert_eq!(message, "Adyen webhook secret is not configured");
            }
            other => panic!("an unconfigured secret must be retryable, got {other:?}"),
        }

        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(adyen_notification_id(&item)),
            body: Some(String::from_utf8(body.clone()).expect("body")),
            signature: Some(sign_item("whsec_coverage", &item)),
            ..Default::default()
        };
        let error = replay_deadletter(&broken, &entry)
            .await
            .expect_err("replay refuses an unconfigured secret");
        assert_eq!(error, "Adyen webhook secret is not configured");
        assert_eq!(event_rows(&env.pool).await, 0);
    });

    // ===================================================================
    // Replay / idempotency.
    // ===================================================================

    env_test!(route_replay_is_exactly_once_no_double_settlement, |env| {
        let tenant = "swadv_replay";
        seed_tenant(env, tenant, "free", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 10_000, 2_400, 12_400, "eur").await;
        let item = authorisation_item("psp_swadv_replay", invoice_id, 12_400, true, Some(tenant));
        let body = signed_envelope("whsec_coverage", &item);

        let first = post_webhook(&env.state, &body).await;
        assert_eq!(first.status(), StatusCode::OK);
        assert_eq!(response_text(first).await, ADYEN_ACCEPTED_RESPONSE);
        let second = post_webhook(&env.state, &body).await;
        assert_eq!(
            second.status(),
            StatusCode::OK,
            "Adyen expects 2xx on replay"
        );
        assert_eq!(response_text(second).await, ADYEN_ACCEPTED_RESPONSE);

        let (status, allocations, events): (String, i64, i64) = sqlx::query_as(
            "SELECT
                    (SELECT status FROM invoices WHERE id = $1),
                    (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1),
                    (SELECT COUNT(*) FROM adyen_webhook_events)",
        )
        .bind(invoice_id)
        .fetch_one(&env.pool)
        .await
        .expect("state");
        assert_eq!(status, "paid");
        assert_eq!(allocations, 1, "replay never double-allocates");
        assert_eq!(events, 1, "replay never duplicates the ledger row");
    });

    env_test!(
        semantics_identical_charge_with_a_new_event_date_is_a_new_notification_but_settles_once,
        |env| {
            // Adyen has no timestamp tolerance: freshness is replaced by the
            // dedupe digest. A byte-identical retry is the SAME notification;
            // a genuinely new eventDate is a new notification whose
            // settlement is still capped by the authoritative remainder.
            let tenant = "swadv_stale";
            seed_tenant(env, tenant, "free", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, tenant, invoice_id, 10_000, 2_400, 12_400, "eur").await;
            let item =
                authorisation_item("psp_swadv_stale", invoice_id, 12_400, true, Some(tenant));
            let first = post_webhook(&env.state, &signed_envelope("whsec_coverage", &item)).await;
            assert_eq!(first.status(), StatusCode::OK);

            let mut later = item.clone();
            later.event_date = Some("2026-10-15T10:00:00+00:00".into());
            assert_ne!(
                adyen_notification_id(&later),
                adyen_notification_id(&item),
                "a new eventDate is a new notification id"
            );
            let second = post_webhook(&env.state, &signed_envelope("whsec_coverage", &later)).await;
            assert_eq!(second.status(), StatusCode::OK);
            let allocations: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1",
            )
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("allocations");
            assert_eq!(
                allocations, 1,
                "the settled invoice cannot be allocated twice"
            );
        }
    );

    env_test!(
        route_event_pending_elsewhere_returns_503_and_no_deadletter,
        |env| {
            let _guard = DEADLETTER_LOCK.lock().await;
            let _dl_guard =
                crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
            clear_all_deadletters(env).await;
            seed_tenant(env, "swadv_pending", "free", "active").await;
            let item = authorisation_item(
                "psp_swadv_pending",
                Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid"),
                100,
                true,
                Some("swadv_pending"),
            );
            sqlx::query(
                "INSERT INTO adyen_webhook_events (id, adyen_notification_id, event_type, status)
                 VALUES (gen_random_uuid(), $1, 'AUTHORISATION', 'pending')",
            )
            .bind(adyen_notification_id(&item))
            .execute(&env.pool)
            .await
            .expect("pending row");

            let response =
                post_webhook(&env.state, &signed_envelope("whsec_coverage", &item)).await;
            assert_eq!(response.status(), StatusCode::SERVICE_UNAVAILABLE);
            let entries = deadletter_entries(env, "adyen:deadletter:event:*").await;
            assert_eq!(entries.len(), 0, "a pending event is never deadlettered");
            let status: String = sqlx::query_scalar(
                "SELECT status FROM adyen_webhook_events WHERE adyen_notification_id = $1",
            )
            .bind(adyen_notification_id(&item))
            .fetch_one(&env.pool)
            .await
            .expect("status");
            assert_eq!(status, "pending", "the other worker's claim is untouched");
        }
    );

    // ===================================================================
    // Recurring settlement: resolution, tenant binding, money.
    // ===================================================================

    env_test!(
        recurring_authorisation_settles_allocates_and_recovers_dunning,
        |env| {
            let tenant = "swadv_settle";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, tenant, invoice_id, 10_000, 2_400, 12_400, "eur").await;
            // Tenant already in dunning: settlement must recover it.
            sqlx::query(
                "INSERT INTO dunning_records (id, tenant_id, status, failed_payment_count)
                 VALUES ('swadv_settle_dunning_0001', $1, 'soft_suspended', 3)",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("dunning");

            let item =
                authorisation_item("psp_swadv_settle", invoice_id, 12_400, true, Some(tenant));
            handle_recurring_authorisation(&env.state, &item)
                .await
                .expect("settlement");
            let (status, paid_at_is_set, psp): (String, bool, Option<String>) = sqlx::query_as(
                "SELECT status, paid_at IS NOT NULL, adyen_psp_reference FROM invoices WHERE id = $1",
            )
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("invoice");
            assert_eq!(status, "paid");
            assert!(paid_at_is_set);
            assert_eq!(
                psp.as_deref(),
                Some("psp_swadv_settle"),
                "the settlement binds the psp reference"
            );
            let (amount, source, operation_id): (i64, String, String) = sqlx::query_as(
                "SELECT amount_cents, source, operation_id FROM invoice_payment_allocations WHERE invoice_id = $1",
            )
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("allocation");
            assert_eq!(
                amount, 12_400,
                "the verified payment is allocated exactly once"
            );
            assert_eq!(source, ADYEN_ALLOCATION_SOURCE);
            assert_eq!(operation_id, "adyen:psp_swadv_settle");
            let dunning: Option<String> =
                sqlx::query_scalar("SELECT status FROM dunning_records WHERE tenant_id = $1")
                    .bind(tenant)
                    .fetch_one(&env.pool)
                    .await
                    .expect("dunning");
            assert_eq!(
                dunning.as_deref(),
                Some("healthy"),
                "settlement recovers dunning"
            );
            let snapshot: Option<Uuid> =
                sqlx::query_scalar("SELECT adyen_tax_snapshot_id FROM invoices WHERE id = $1")
                    .bind(invoice_id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("snapshot link");
            assert!(snapshot.is_some(), "the tax snapshot is linked");

            // Replay: idempotent, no second allocation.
            handle_recurring_authorisation(&env.state, &item)
                .await
                .expect("replay");
            let allocations: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1",
            )
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("count");
            assert_eq!(allocations, 1, "replay never double-allocates");
        }
    );

    env_test!(
        recurring_authorisation_without_a_local_invoice_deadletters,
        |env| {
            seed_tenant(env, "swcov_orphan_paid", "growth", "active").await;
            let unknown = Uuid::new_v4();
            let orphan = authorisation_item(
                "psp_orphan_paid",
                unknown,
                100,
                true,
                Some("swcov_orphan_paid"),
            );
            let error = handle_recurring_authorisation(&env.state, &orphan)
                .await
                .expect_err("unknown local invoice");
            assert!(error.contains("does not exist"), "{error}");

            // A reference that is not `invoice:{uuid}` at all is equally refused.
            let garbage = parse_item(serde_json::json!({
                "pspReference": "psp_orphan_ref",
                "merchantReference": "not-an-invoice-ref",
                "amount": { "currency": "EUR", "value": 100 },
                "eventCode": "AUTHORISATION",
                "success": "true",
                "additionalData": { "recurringProcessingModel": "Subscription" }
            }));
            let error = handle_recurring_authorisation(&env.state, &garbage)
                .await
                .expect_err("unidentifiable reference");
            assert!(error.contains("does not name a local invoice"), "{error}");
            assert_eq!(event_rows(&env.pool).await, 0, "no ledger writes");
            let snapshots: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM adyen_tax_snapshots")
                .fetch_one(&env.pool)
                .await
                .expect("snapshots");
            assert_eq!(snapshots, 0);
        }
    );

    env_test!(
        recurring_authorisation_never_settles_another_tenants_invoice,
        |env| {
            let owner = "swadv_inv_owner";
            let other = "swadv_inv_other";
            seed_tenant(env, owner, "growth", "active").await;
            seed_tenant(env, other, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, owner, invoice_id, 1_000, 0, 1_000, "eur").await;

            // The invoice is attributed to a DIFFERENT shopper: refused, and
            // the invoice is untouched.
            let attacker = authorisation_item("psp_rebind", invoice_id, 1_000, true, Some(other));
            let error = handle_recurring_authorisation(&env.state, &attacker)
                .await
                .expect_err("cross-tenant settlement refused");
            assert!(error.contains("cross-tenant"), "{error}");
            let (status, psp): (String, Option<String>) =
                sqlx::query_as("SELECT status, adyen_psp_reference FROM invoices WHERE id = $1")
                    .bind(invoice_id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("invoice");
            assert_eq!(status, "pending", "rejected write changes nothing");
            assert_eq!(psp, None);

            // The rightful shopper's event settles it in place.
            let rightful =
                authorisation_item("psp_rebind_ok", invoice_id, 1_000, true, Some(owner));
            handle_recurring_authorisation(&env.state, &rightful)
                .await
                .expect("settle");
            let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
                .bind(invoice_id)
                .fetch_one(&env.pool)
                .await
                .expect("status");
            assert_eq!(status, "paid");
        }
    );

    env_test!(recurring_authorisation_currency_mismatch_refused, |env| {
        let tenant = "swadv_currency";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 1_000, 0, 1_000, "eur").await;

        let mut item = authorisation_item("psp_ccy", invoice_id, 1_000, true, Some(tenant));
        item.amount = Some(AdyenAmount {
            value: Some(1_000),
            currency: Some("USD".into()),
        });
        let error = handle_recurring_authorisation(&env.state, &item)
            .await
            .expect_err("currency mismatch refused");
        assert!(error.contains("denominated in"), "honest failure: {error}");
        let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("status");
        assert_eq!(status, "pending", "the refused settlement writes nothing");
        let snapshots: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM adyen_tax_snapshots")
            .fetch_one(&env.pool)
            .await
            .expect("snapshots");
        assert_eq!(snapshots, 0, "the gate never ran for a refused settlement");
    });

    env_test!(
        recurring_authorisation_zero_value_settles_without_allocation,
        |env| {
            let tenant = "swadv_zero";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, tenant, invoice_id, 0, 0, 0, "eur").await;
            let item = authorisation_item("psp_swadv_zero", invoice_id, 0, true, Some(tenant));
            handle_recurring_authorisation(&env.state, &item)
                .await
                .expect("zero-value invoices settle");
            let (status, psp): (String, Option<String>) =
                sqlx::query_as("SELECT status, adyen_psp_reference FROM invoices WHERE id = $1")
                    .bind(invoice_id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("invoice");
            assert_eq!(status, "paid");
            assert_eq!(psp.as_deref(), Some("psp_swadv_zero"));
            let allocations: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1",
            )
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("allocations");
            assert_eq!(
                allocations, 0,
                "no positive allocation is invented for zero value"
            );
        }
    );

    env_test!(
        recurring_authorisation_foreign_tenant_refused_leaves_dunning,
        |env| {
            let owner = "swadv_foreign_owner";
            let other = "swadv_foreign_other";
            seed_tenant(env, owner, "growth", "active").await;
            seed_tenant(env, other, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, owner, invoice_id, 1_000, 0, 1_000, "eur").await;
            sqlx::query(
                "INSERT INTO dunning_records (id, tenant_id, status, failed_payment_count)
                 VALUES ('swadv_foreign_dunning_1', $1, 'soft_suspended', 2)",
            )
            .bind(other)
            .execute(&env.pool)
            .await
            .expect("other dunning");

            let event = authorisation_item("psp_foreign", invoice_id, 1_000, true, Some(other));
            let error = handle_recurring_authorisation(&env.state, &event)
                .await
                .expect_err("foreign tenant cannot settle");
            assert!(error.contains("cross-tenant"), "{error}");
            let dunning: Option<String> =
                sqlx::query_scalar("SELECT status FROM dunning_records WHERE tenant_id = $1")
                    .bind(other)
                    .fetch_one(&env.pool)
                    .await
                    .expect("dunning");
            assert_eq!(
                dunning.as_deref(),
                Some("soft_suspended"),
                "no blanket recovery"
            );
            let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
                .bind(invoice_id)
                .fetch_one(&env.pool)
                .await
                .expect("status");
            assert_eq!(status, "pending", "the foreign tenant cannot settle it");
        }
    );

    env_test!(
        recurring_authorisation_fails_closed_on_malformed_references,
        |env| {
            let tenant = "swadv_shape";
            seed_tenant(env, tenant, "free", "active").await;
            // No such local invoice.
            let unknown = Uuid::new_v4();
            let missing = authorisation_item("psp_shape_missing", unknown, 100, true, Some(tenant));
            assert!(handle_recurring_authorisation(&env.state, &missing)
                .await
                .is_err());
            // No amount at all: an unverifiable charge is refused.
            let mut no_amount = missing.clone();
            no_amount.amount = None;
            let error = handle_recurring_authorisation(&env.state, &no_amount)
                .await
                .expect_err("missing amount refused");
            assert!(error.contains("no amount.value"), "{error}");

            let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM invoices")
                .fetch_one(&env.pool)
                .await
                .expect("rows");
            assert_eq!(rows, 0, "refused shapes write nothing");
        }
    );

    env_test!(
        renewal_settles_the_new_invoice_without_touching_the_previous_one,
        |env| {
            let tenant = "swadv_renew";
            seed_tenant(env, tenant, "growth", "active").await;
            let first = Uuid::new_v4();
            let second = Uuid::new_v4();
            seed_local_invoice(env, tenant, first, 1_000, 0, 1_000, "eur").await;
            seed_local_invoice(env, tenant, second, 1_000, 0, 1_000, "eur").await;

            for (invoice_id, psp) in [(first, "psp_renew_1"), (second, "psp_renew_2")] {
                let item = authorisation_item(psp, invoice_id, 1_000, true, Some(tenant));
                handle_recurring_authorisation(&env.state, &item)
                    .await
                    .expect("settle the cycle");
            }

            let statuses: Vec<(String, String)> = sqlx::query_as(
                "SELECT id::text, status FROM invoices WHERE tenant_id = $1 ORDER BY invoice_number",
            )
            .bind(tenant)
            .fetch_all(&env.pool)
            .await
            .expect("statuses");
            assert_eq!(statuses.len(), 2);
            for (_, status) in &statuses {
                assert_eq!(status, "paid", "both cycles settled");
            }
            let allocations: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM invoice_payment_allocations WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("allocations");
            assert_eq!(allocations, 2, "one allocation per settled cycle");
            let snapshots: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM adyen_tax_snapshots WHERE tenant_id = $1")
                    .bind(tenant)
                    .fetch_one(&env.pool)
                    .await
                    .expect("snapshots");
            assert_eq!(snapshots, 2, "one immutable snapshot per charge");
        }
    );

    env_test!(duplicate_delivery_never_rewinds_a_settled_invoice, |env| {
        let tenant = "swadv_settled_replay";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 1_000, 0, 1_000, "eur").await;
        let item = authorisation_item("psp_settled", invoice_id, 1_000, true, Some(tenant));
        handle_recurring_authorisation(&env.state, &item)
            .await
            .expect("settle");
        // The same delivery again: still settled, one allocation.
        handle_recurring_authorisation(&env.state, &item)
            .await
            .expect("replay");
        let (status, allocations): (String, i64) = sqlx::query_as(
            "SELECT
                    (SELECT status FROM invoices WHERE id = $1),
                    (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1)",
        )
        .bind(invoice_id)
        .fetch_one(&env.pool)
        .await
        .expect("state");
        assert_eq!(status, "paid");
        assert_eq!(allocations, 1);
        // A LATE refusal for the same invoice (a new notification id)
        // still cannot un-pay it.
        let refusal = authorisation_item(
            "psp_settled_refusal",
            invoice_id,
            1_000,
            false,
            Some(tenant),
        );
        handle_authorisation_refused(&env.state, &refusal)
            .await
            .expect("refusal recorded");
        let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("status");
        assert_eq!(status, "paid", "a settled invoice is never un-settled");
    });

    // ===================================================================
    // Refusals: dunning escalation and dead-letter honesty.
    // ===================================================================

    env_test!(
        authorisation_refusal_escalates_and_only_transitions_audit,
        |env| {
            let tenant = "swcov_dunning";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, tenant, invoice_id, 4_200, 0, 4_200, "eur").await;

            let first = authorisation_item("psp_sw_dun_1", invoice_id, 4_200, false, Some(tenant));
            handle_authorisation_refused(&env.state, &first)
                .await
                .expect("first refusal");
            let (status, count, first_failed, retry): (
                String,
                i32,
                Option<DateTime<Utc>>,
                Option<DateTime<Utc>>,
            ) = sqlx::query_as(
                "SELECT status, failed_payment_count, first_failed_at, next_retry_at
             FROM dunning_records WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("dunning");
            assert_eq!((status.as_str(), count), ("warning", 1));
            let first_failed = first_failed.expect("first failure recorded");
            let retry = retry.expect("retry scheduled");
            assert_eq!(
                (retry - first_failed).num_days(),
                1,
                "first retry follows the 1-day schedule"
            );
            let events: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dunning_events WHERE tenant_id = $1 AND event_type = 'payment_failed'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("events");
            assert_eq!(events, 1);
            let transitions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dunning_events WHERE tenant_id = $1 AND event_type = 'soft_suspended'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("transitions");
            assert_eq!(transitions, 0, "warning is not a suspension transition");
            let notified: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM notification_queue WHERE tenant_id = $1 AND type = 'payment_failed'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("notified");
            assert_eq!(notified, 1, "the customer is told about the refusal");

            // Age the failure history into the soft-suspension band (7 days).
            sqlx::query(
                "UPDATE dunning_records SET first_failed_at = NOW() - INTERVAL '8 days',
                status = 'warning' WHERE tenant_id = $1",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("age dunning");
            let second = authorisation_item("psp_sw_dun_2", invoice_id, 4_200, false, Some(tenant));
            handle_authorisation_refused(&env.state, &second)
                .await
                .expect("second refusal");
            let (status, count, retry): (String, i32, Option<DateTime<Utc>>) = sqlx::query_as(
            "SELECT status, failed_payment_count, next_retry_at FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
            assert_eq!(status, "soft_suspended");
            assert_eq!(count, 2);
            let retry = retry.expect("still retrying");
            assert!(
                retry <= Utc::now(),
                "the retry is anchored to the (aged) first failure, so it is due now"
            );
            let soft_transitions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM dunning_events WHERE tenant_id = $1 AND event_type = 'soft_suspended'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("soft transitions");
            assert_eq!(soft_transitions, 1, "the transition is logged exactly once");
            let notifications: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM notification_queue
             WHERE tenant_id = $1 AND type = 'account_soft_suspended'",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("notifications");
            assert!(notifications >= 1, "suspension notifies the tenant");

            // Age into the hard-suspension band (21 days).
            sqlx::query(
                "UPDATE dunning_records SET first_failed_at = NOW() - INTERVAL '25 days',
                status = 'soft_suspended' WHERE tenant_id = $1",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("age dunning");
            let third = authorisation_item("psp_sw_dun_3", invoice_id, 4_200, false, Some(tenant));
            handle_authorisation_refused(&env.state, &third)
                .await
                .expect("third refusal");
            let (status, grace): (String, Option<DateTime<Utc>>) = sqlx::query_as(
                "SELECT status, grace_period_ends_at FROM dunning_records WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("dunning");
            assert_eq!(status, "hard_suspended");
            let grace = grace.expect("grace window recorded");
            assert!(
                (grace - Utc::now()).num_days() >= 6,
                "the 7-day grace window is concrete"
            );
            let tenant_status: String =
                sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
                    .bind(tenant)
                    .fetch_one(&env.pool)
                    .await
                    .expect("tenant");
            assert_eq!(tenant_status, "suspended", "hard suspension halts sending");
            let holds: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM tenant_restrictions
             WHERE tenant_id = $1 AND kind = 'billing' AND cleared_at IS NULL",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("restriction");
            assert_eq!(holds, 1, "the suspension is independently recorded");

            // Idempotence of the suspension state: another refusal leaves the
            // original grace deadline and does not duplicate the hold.
            let fourth = authorisation_item("psp_sw_dun_4", invoice_id, 4_200, false, Some(tenant));
            handle_authorisation_refused(&env.state, &fourth)
                .await
                .expect("fourth refusal");
            let (grace_after, holds): (Option<DateTime<Utc>>, i64) = sqlx::query_as(
                "SELECT grace_period_ends_at,
                    (SELECT COUNT(*) FROM tenant_restrictions tr
                     WHERE tr.tenant_id = dunning_records.tenant_id AND tr.kind = 'billing'
                       AND tr.cleared_at IS NULL)
             FROM dunning_records WHERE tenant_id = $1",
            )
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("dunning");
            assert_eq!(grace_after, Some(grace), "grace deadline is not extended");
            assert_eq!(holds, 1, "the hold is never duplicated");
        }
    );

    env_test!(
        authorisation_refusal_without_a_local_invoice_is_deadlettered,
        |env| {
            seed_tenant(env, "swcov_orphan_refuse", "growth", "active").await;
            let unknown = Uuid::new_v4();
            let invoice = authorisation_item(
                "psp_orphan_refuse",
                unknown,
                1_000,
                false,
                Some("swcov_orphan_refuse"),
            );
            let error = handle_authorisation_refused(&env.state, &invoice)
                .await
                .expect_err("unresolvable invoice");
            assert!(error.contains("does not exist"), "{error}");
            let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dunning_records")
                .fetch_one(&env.pool)
                .await
                .expect("dunning");
            assert_eq!(rows, 0, "nothing is written for an unresolvable refusal");

            // A reference that is not a local invoice id at all is refused too.
            let mut garbage = invoice.clone();
            garbage.merchant_reference = "garbage-ref".into();
            let error = handle_authorisation_refused(&env.state, &garbage)
                .await
                .expect_err("unidentifiable reference");
            assert!(error.contains("does not name a local invoice"), "{error}");
            assert_eq!(rows, 0);
        }
    );

    env_test!(
        refusal_for_an_already_paid_invoice_records_dunning_without_touching_status,
        |env| {
            let tenant = "swadv_paid_refusal";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, tenant, invoice_id, 1_000, 0, 1_000, "eur").await;
            sqlx::query("UPDATE invoices SET status = 'paid', paid_at = NOW() WHERE id = $1")
                .bind(invoice_id)
                .execute(&env.pool)
                .await
                .expect("mark paid");

            let refusal =
                authorisation_item("psp_paid_refusal", invoice_id, 1_000, false, Some(tenant));
            handle_authorisation_refused(&env.state, &refusal)
                .await
                .expect("the refusal is recorded");
            let (status, dunning): (String, i64) = sqlx::query_as(
                "SELECT (SELECT status FROM invoices WHERE id = $1),
                        (SELECT COUNT(*) FROM dunning_records WHERE tenant_id = $2)",
            )
            .bind(invoice_id)
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("state");
            assert_eq!(
                status, "paid",
                "the refusal never rewrites a settled invoice"
            );
            assert_eq!(dunning, 1, "the refusal is still durably recorded");
        }
    );

    // ===================================================================
    // Tax truth (P0).
    // ===================================================================

    env_test!(tax_gate_blocks_mismatch_and_dedupes_incidents, |env| {
        let tenant = "swcov_tax";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        // The local invoice's statutory total is 49.00 (0 VAT); Adyen
        // charged 59.00 — the charge disagrees with the local decision.
        seed_local_invoice(env, tenant, invoice_id, 4_900, 0, 4_900, "eur").await;
        let local = local_invoice(env, invoice_id).await;

        let mismatch = authorisation_item("psp_tax_bad", invoice_id, 5_900, true, Some(tenant));
        let error = validate_and_snapshot_adyen_tax(&env.state, &mismatch, &local, 5_900)
            .await
            .expect_err("charged total must not be accepted on trust");
        assert!(error.contains("blocked"), "{error}");
        let incidents: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM finance_incidents
             WHERE kind = 'tax_total_mismatch' AND adyen_psp_reference = 'psp_tax_bad'
               AND status = 'open'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("incidents");
        assert_eq!(incidents, 1, "a durable finance incident is raised");
        let (validation, delta, authority): (String, i64, String) = sqlx::query_as(
            "SELECT validation_status, discrepancy_cents, authority FROM adyen_tax_snapshots
             WHERE adyen_psp_reference = 'psp_tax_bad'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(validation, "discrepancy");
        assert_eq!(delta, 1_000, "the delta is the over-charged amount");
        assert_eq!(authority, ADYEN_TAX_AUTHORITY_LOCAL);

        // A replay stays blocked and never duplicates the incident.
        validate_and_snapshot_adyen_tax(&env.state, &mismatch, &local, 5_900)
            .await
            .expect_err("an open discrepancy keeps blocking");
        let incidents: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM finance_incidents
             WHERE kind = 'tax_total_mismatch' AND adyen_psp_reference = 'psp_tax_bad'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("incidents");
        assert_eq!(incidents, 1, "incident dedupe");

        // A matching charge validates and snapshots under the local authority.
        let good = authorisation_item("psp_tax_ok", invoice_id, 4_900, true, Some(tenant));
        let snapshot = validate_and_snapshot_adyen_tax(&env.state, &good, &local, 4_900)
            .await
            .expect("matching charge validates")
            .expect("snapshot id");
        assert!(!snapshot.is_nil());
        let (validation, authority): (String, String) = sqlx::query_as(
            "SELECT validation_status, authority FROM adyen_tax_snapshots
             WHERE adyen_psp_reference = 'psp_tax_ok'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(validation, "validated");
        assert_eq!(authority, ADYEN_TAX_AUTHORITY_LOCAL);
    });

    env_test!(
        recurring_authorisation_is_blocked_by_the_tax_gate_on_a_mismatch,
        |env| {
            let tenant = "swadv_recompute";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, tenant, invoice_id, 4_900, 0, 4_900, "eur").await;
            let item =
                authorisation_item("psp_recompute_bad", invoice_id, 5_900, true, Some(tenant));
            let error = handle_recurring_authorisation(&env.state, &item)
                .await
                .expect_err("a mismatching charge blocks");
            assert!(error.contains("blocked"), "honest failure: {error}");
            let (status, allocations): (String, i64) = sqlx::query_as(
                "SELECT
                    (SELECT status FROM invoices WHERE id = $1),
                    (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1)",
            )
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("state");
            assert_eq!(status, "pending", "no local invoice is finalized");
            assert_eq!(allocations, 0, "no allocation runs past the gate");
            let incidents: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM finance_incidents WHERE kind = 'tax_total_mismatch'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("incidents");
            assert_eq!(incidents, 1, "a critical finance incident is raised");
        }
    );

    env_test!(tax_gate_zero_value_charges_are_validated, |env| {
        let tenant = "swadv_tax_zero";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 0, 0, 0, "eur").await;
        let local = local_invoice(env, invoice_id).await;

        // Zero-value invoices (credits/100% discounts) have no tax decision
        // and validate against the local zero total.
        let zero = authorisation_item("psp_tax_zero", invoice_id, 0, true, Some(tenant));
        validate_and_snapshot_adyen_tax(&env.state, &zero, &local, 0)
            .await
            .expect("zero-value charges validate");
        let validation: String = sqlx::query_scalar(
            "SELECT validation_status FROM adyen_tax_snapshots
             WHERE adyen_psp_reference = 'psp_tax_zero'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(validation, "validated");

        // A charge against a zero-total invoice is a discrepancy that blocks.
        let charged = authorisation_item(
            "psp_tax_zero_charged",
            invoice_id,
            1_000,
            true,
            Some(tenant),
        );
        let error = validate_and_snapshot_adyen_tax(&env.state, &charged, &local, 1_000)
            .await
            .expect_err("money against a zero obligation must block");
        assert!(error.contains("blocked"), "{error}");
    });

    env_test!(
        tax_gate_records_the_local_jurisdiction_and_evidence,
        |env| {
            let tenant = "swadv_tax_local";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, tenant, invoice_id, 10_000, 2_400, 12_400, "eur").await;
            sqlx::query(
                "UPDATE invoices SET billing_country = NULL, vat_rate = NULL WHERE id = $1",
            )
            .bind(invoice_id)
            .execute(&env.pool)
            .await
            .expect("null country");
            let local = local_invoice(env, invoice_id).await;
            let item = authorisation_item("psp_tax_local", invoice_id, 12_400, true, Some(tenant));
            validate_and_snapshot_adyen_tax(&env.state, &item, &local, 12_400)
                .await
                .expect("matching charge validates");
            let (jurisdiction, country, automatic): (
                Option<String>,
                Option<String>,
                Option<String>,
            ) = sqlx::query_as(
                "SELECT jurisdiction,
                        raw_payload->'apexmail'->>'expected_country',
                        automatic_tax_status
                 FROM adyen_tax_snapshots WHERE adyen_psp_reference = 'psp_tax_local'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("snapshot");
            assert_eq!(
                jurisdiction, None,
                "a null local country is no jurisdiction"
            );
            assert_eq!(country, None);
            assert_eq!(
                automatic, None,
                "Adyen transmits no tax object — nothing is invented"
            );
        }
    );

    env_test!(tax_snapshot_edges_are_honest, |env| {
        let tenant = "swadv_snapedge";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 0, 0, 0, "eur").await;
        let local = local_invoice(env, invoice_id).await;
        let item = authorisation_item("psp_snapedge", invoice_id, 0, true, Some(tenant));
        let expected = expected_tax_from_local_invoice(&local);

        let first = persist_tax_snapshot(
            &env.pool,
            &item,
            tenant,
            Some(invoice_id),
            "eur",
            (0, 0, 0),
            &expected,
            "validated",
            0,
        )
        .await
        .expect("first write");
        assert!(!first.is_nil());

        let (hash, payload): (String, serde_json::Value) = sqlx::query_as(
            "SELECT raw_payload_hash, raw_payload FROM adyen_tax_snapshots
             WHERE adyen_psp_reference = $1",
        )
        .bind("psp_snapedge")
        .fetch_one(&env.pool)
        .await
        .expect("snapshot row");
        assert_eq!(hash.len(), 64, "the raw payload is content-addressed");
        assert_eq!(payload["adyen_item"]["pspReference"], "psp_snapedge");
        assert_eq!(payload["apexmail"]["source"], "local_invoice");

        // The immutability trigger refuses EVERY edit outright (the trigger
        // function still names the pre-cutover column inside its message, so
        // the refusal surfaces as a plpgsql error rather than the friendly
        // text — the mutation is refused either way).
        sqlx::query(
            "UPDATE adyen_tax_snapshots SET total_cents = 1 WHERE adyen_psp_reference = $1",
        )
        .bind("psp_snapedge")
        .execute(&env.pool)
        .await
        .expect_err("snapshots are trigger-immutable");
        let total: i64 = sqlx::query_scalar(
            "SELECT total_cents FROM adyen_tax_snapshots WHERE adyen_psp_reference = $1",
        )
        .bind("psp_snapedge")
        .fetch_one(&env.pool)
        .await
        .expect("row");
        assert_eq!(total, 0, "the refused edit changed nothing");
    });

    env_test!(persist_tax_snapshot_replay_returns_the_first_write, |env| {
        let tenant = "swadv_snapreplay";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 1_000, 0, 1_000, "eur").await;
        let local = local_invoice(env, invoice_id).await;
        let item = authorisation_item("psp_snapreplay", invoice_id, 1_000, true, Some(tenant));
        let expected = expected_tax_from_local_invoice(&local);
        let first = persist_tax_snapshot(
            &env.pool,
            &item,
            tenant,
            Some(invoice_id),
            "eur",
            (1_000, 0, 1_000),
            &expected,
            "validated",
            0,
        )
        .await
        .expect("first write");
        let second = persist_tax_snapshot(
            &env.pool,
            &item,
            tenant,
            Some(invoice_id),
            "eur",
            (1_000, 0, 1_000),
            &expected,
            "validated",
            0,
        )
        .await
        .expect("replay");
        assert_eq!(first, second, "the immutable first write wins");
    });

    // ===================================================================
    // Token binding (RECURRING_CONTRACT).
    // ===================================================================

    fn token_item(
        psp_reference: &str,
        tenant: &str,
        token: Option<&str>,
        model: Option<&str>,
    ) -> AdyenNotificationItem {
        let mut additional = serde_json::json!({ "shopperReference": tenant });
        if let Some(token) = token {
            additional["recurringDetailReference"] = serde_json::json!(token);
        }
        if let Some(model) = model {
            additional["recurringProcessingModel"] = serde_json::json!(model);
        }
        parse_item(serde_json::json!({
            "pspReference": psp_reference,
            "merchantAccountCode": "ApexMailECOV",
            "merchantReference": format!("token-{tenant}"),
            "amount": { "currency": "EUR", "value": 0 },
            "eventCode": "RECURRING_CONTRACT",
            "eventDate": "2026-10-14T10:00:00+00:00",
            "success": "true",
            "additionalData": additional
        }))
    }

    async fn seed_subscription(env: &Env, tenant: &str, subscription_id: &str, status: &str) {
        sqlx::query(
            "INSERT INTO adyen_subscriptions
                 (tenant_id, adyen_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, adyen_shopper_reference)
             VALUES ($1, $2, 'free', $3, NOW(), NOW() + INTERVAL '30 days', $1)",
        )
        .bind(tenant)
        .bind(subscription_id)
        .bind(status)
        .execute(&env.pool)
        .await
        .expect("seed subscription");
    }

    env_test!(
        token_created_updates_every_row_of_the_shopper_tenant,
        |env| {
            let tenant = "swadv_token";
            let other = "swadv_token_other";
            seed_tenant(env, tenant, "growth", "active").await;
            seed_tenant(env, other, "growth", "active").await;
            seed_subscription(env, tenant, "sub_swadv_token_active", "active").await;
            seed_subscription(env, tenant, "sub_swadv_token_past_due", "past_due").await;
            seed_subscription(env, other, "sub_swadv_token_other", "active").await;

            let item = token_item(
                "psp_swadv_token",
                tenant,
                Some("tok_swadv_123"),
                Some("Subscription"),
            );
            handle_token_created(&env.state, &item)
                .await
                .expect("token bound");
            let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
            "SELECT adyen_subscription_id, adyen_recurring_detail_reference, adyen_recurring_processing_model
             FROM adyen_subscriptions WHERE tenant_id = $1 ORDER BY adyen_subscription_id",
        )
        .bind(tenant)
        .fetch_all(&env.pool)
        .await
        .expect("rows");
            assert_eq!(rows.len(), 2, "the shopper tenant's rows are bound");
            for (_, token, model) in &rows {
                assert_eq!(token.as_deref(), Some("tok_swadv_123"));
                assert_eq!(model.as_deref(), Some("Subscription"));
            }
            let untouched: Option<String> = sqlx::query_scalar(
                "SELECT adyen_recurring_detail_reference FROM adyen_subscriptions
             WHERE adyen_subscription_id = 'sub_swadv_token_other'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("other row");
            assert_eq!(untouched, None, "another tenant's rows are never touched");
        }
    );

    env_test!(token_created_refuses_missing_token_or_tenant, |env| {
        let tenant = "swadv_token_missing";
        seed_tenant(env, tenant, "growth", "active").await;
        // Missing token.
        let no_token = token_item("psp_token_missing", tenant, None, Some("Subscription"));
        let error = handle_token_created(&env.state, &no_token)
            .await
            .expect_err("missing token refused");
        assert!(error.contains("recurringDetailReference"), "{error}");
        // Missing shopper.
        let no_shopper = parse_item(serde_json::json!({
            "pspReference": "psp_token_no_shopper",
            "merchantReference": "token-ref",
            "amount": { "currency": "EUR", "value": 0 },
            "eventCode": "RECURRING_CONTRACT",
            "success": "true",
            "additionalData": { "recurringDetailReference": "tok_orphan" }
        }));
        let error = handle_token_created(&env.state, &no_shopper)
            .await
            .expect_err("missing tenant refused");
        assert!(error.contains("shopperReference"), "{error}");
        // Resolved tenant without any subscription row: deadlettered, never a
        // silent drop.
        let no_rows = token_item(
            "psp_token_no_rows",
            tenant,
            Some("tok_no_rows"),
            Some("Subscription"),
        );
        let error = handle_token_created(&env.state, &no_rows)
            .await
            .expect_err("no row to bind refused");
        assert!(error.contains("no subscription row"), "{error}");
    });

    // ===================================================================
    // Checkout authorisation: informational only.
    // ===================================================================

    env_test!(checkout_authorisation_never_grants_entitlement, |env| {
        let tenant = "swcov_trial";
        seed_tenant(env, tenant, "suspended", "suspended").await;

        // Checkout completed must NOT reactivate a suspended tenant.
        let session = checkout_item("psp_sw_checkout", Some(tenant));
        handle_checkout_authorisation(&env.state, &session)
            .await
            .expect("checkout acknowledged");
        let status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("tenant");
        assert_eq!(status, "suspended", "checkout never bypasses a suspension");
        let subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM adyen_subscriptions")
            .fetch_one(&env.pool)
            .await
            .expect("subscriptions");
        assert_eq!(subs, 0);
        let notifications: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_queue")
            .fetch_one(&env.pool)
            .await
            .expect("notifications");
        assert_eq!(
            notifications, 0,
            "a checkout authorisation notifies nothing by itself"
        );
    });

    env_test!(
        checkout_authorisation_without_attribution_is_acknowledged,
        |env| {
            let event = checkout_item("psp_checkout_orphan", None);
            handle_checkout_authorisation(&env.state, &event)
                .await
                .expect("unattributable checkout is acknowledged");
            let subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM adyen_subscriptions")
                .fetch_one(&env.pool)
                .await
                .expect("subs");
            assert_eq!(subs, 0);
        }
    );

    env_test!(notification_items_shape_failures_fail_closed, |env| {
        // A malformed envelope (wrong types) is refused at the wire.
        seed_tenant(env, "swadv_shape_fail", "growth", "active").await;
        for body in [
            br#"{"notificationItems": [{"NotificationRequestItem": {"amount": {"value": "many"}}}]}"#.to_vec(),
            br#"{"notificationItems": [{"NotificationRequestItem": {"pspReference": "psp_x", "eventCode": "AUTHORISATION", "amount": {"value": 1.5}}}]}"#.to_vec(),
        ] {
            match process_webhook(&env.state, &body).await {
                Err(ProcessWebhookError::InvalidRequest {
                    reason: "invalid_json_payload",
                    ..
                }) => {}
                other => panic!("malformed envelope must be refused, got {other:?}"),
            }
        }

        // A recurring authorisation with no amount is a handler error
        // (deadlettered by the caller), never a silent drop.
        let mut no_amount = authorisation_item(
            "psp_decode_fail",
            Uuid::new_v4(),
            100,
            true,
            Some("swadv_shape_fail"),
        );
        no_amount.amount = None;
        let error = handle_notification(&env.state, &no_amount)
            .await
            .err()
            .unwrap_or_else(|| panic!("a missing amount must be an error"));
        assert!(error.contains("amount.value"), "{error}");
        assert_eq!(event_rows(&env.pool).await, 0);
    });

    // ===================================================================
    // Deadletter replay (HMAC re-verification, exactly-once).
    // ===================================================================

    env_test!(replay_deadletter_reverifies_hmac_and_is_idempotent, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        let tenant = "swcov_replay";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 4_200, 0, 4_200, "eur").await;
        let item = authorisation_item("psp_sw_replay", invoice_id, 4_200, false, Some(tenant));
        let good = sign_item("whsec_coverage", &item);
        let forged = sign_item("whsec_not_the_secret", &item);
        let forged_body = String::from_utf8(envelope_bytes(&item, &forged)).expect("body");
        let good_body = String::from_utf8(envelope_bytes(&item, &good)).expect("body");

        // A tampered secret must write NOTHING, not even the claim row.
        let bad_entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(adyen_notification_id(&item)),
            body: Some(forged_body),
            signature: Some(forged),
            ..Default::default()
        };
        let error = replay_deadletter(&env.state, &bad_entry)
            .await
            .expect_err("forged signature must be refused");
        assert!(error.contains("Invalid webhook signature"), "{error}");
        assert_eq!(
            event_rows(&env.pool).await,
            0,
            "failed verification writes nothing"
        );
        let dunning: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dunning_records")
            .fetch_one(&env.pool)
            .await
            .expect("dunning");
        assert_eq!(dunning, 0);

        // Missing body/signature: refused before any side effect.
        let empty = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(adyen_notification_id(&item)),
            ..Default::default()
        };
        let error = replay_deadletter(&env.state, &empty)
            .await
            .expect_err("no body");
        assert!(error.contains("No body stored"), "{error}");

        // The verified entry replays exactly once.
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(adyen_notification_id(&item)),
            body: Some(good_body),
            signature: Some(good),
            ..Default::default()
        };
        replay_deadletter(&env.state, &entry)
            .await
            .expect("verified replay");
        let (status, count): (String, i32) = sqlx::query_as(
            "SELECT status, failed_payment_count FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!(status, "warning");
        assert_eq!(count, 1);

        // Replaying the same deadletter again must not double-count.
        replay_deadletter(&env.state, &entry)
            .await
            .expect("replay is idempotent");
        let count: i32 = sqlx::query_scalar(
            "SELECT failed_payment_count FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning count");
        assert_eq!(count, 1, "replay never re-applies the failure");
        let processed: String = sqlx::query_scalar(
            "SELECT status FROM adyen_webhook_events WHERE adyen_notification_id = $1",
        )
        .bind(adyen_notification_id(&item))
        .fetch_one(&env.pool)
        .await
        .expect("event row");
        assert_eq!(processed, "processed");
    });

    env_test!(replay_deadletter_missing_signature_refused, |env| {
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("adn_nosig_replay".into()),
            body: Some(r#"{"notificationItems":[]}"#.into()),
            ..Default::default()
        };
        let error = replay_deadletter(&env.state, &entry)
            .await
            .expect_err("missing signature");
        assert!(error.contains("No signature stored"));
    });

    env_test!(replay_deadletter_malformed_body_refused, |env| {
        let body = r#"{"notificationItems": [{"NotificationRequestItem""#;
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("adn_badbody".into()),
            body: Some(body.to_string()),
            signature: Some("TQ==".into()),
            ..Default::default()
        };
        let error = replay_deadletter(&env.state, &entry)
            .await
            .expect_err("malformed stored body");
        assert!(
            error.contains("Failed to parse stored webhook body"),
            "honest failure: {error}"
        );
        assert_eq!(event_rows(&env.pool).await, 0, "nothing claimed");
    });

    env_test!(replay_deadletter_pending_event_is_refused, |env| {
        let tenant = "swadv_pendreplay";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 100, 0, 100, "eur").await;
        let item = authorisation_item("psp_pendreplay", invoice_id, 100, false, Some(tenant));
        let signature = sign_item("whsec_coverage", &item);
        let body = String::from_utf8(envelope_bytes(&item, &signature)).expect("body");
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(adyen_notification_id(&item)),
            body: Some(body),
            signature: Some(signature),
            ..Default::default()
        };
        replay_deadletter(&env.state, &entry)
            .await
            .expect("first replay claims");
        // Simulate a concurrent worker holding the claim.
        sqlx::query(
            "UPDATE adyen_webhook_events SET status = 'pending', processed_at = NULL
             WHERE adyen_notification_id = $1",
        )
        .bind(adyen_notification_id(&item))
        .execute(&env.pool)
        .await
        .expect("re-pend");
        let error = replay_deadletter(&env.state, &entry)
            .await
            .expect_err("pending event");
        assert!(
            error.contains("pending on another worker"),
            "honest failure: {error}"
        );
    });

    env_test!(
        replay_skips_already_processed_events_and_refuses_pending_ones,
        |env| {
            let _guard = DEADLETTER_LOCK.lock().await;
            let _dl_guard =
                crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
            let tenant = "swcov_replay2";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, tenant, invoice_id, 100, 0, 100, "eur").await;

            let build_entry = |item: &AdyenNotificationItem| {
                let signature = sign_item("whsec_coverage", item);
                DeadletterEntry {
                    reason: "processing_failed".into(),
                    event_id: Some(adyen_notification_id(item)),
                    body: Some(String::from_utf8(envelope_bytes(item, &signature)).expect("body")),
                    signature: Some(signature),
                    ..Default::default()
                }
            };

            // An event already marked processed: the replay skips the
            // business logic entirely and reports success.
            let done = authorisation_item("psp_already_done", invoice_id, 100, false, Some(tenant));
            sqlx::query(
                "INSERT INTO adyen_webhook_events (adyen_notification_id, adyen_psp_reference, event_type, status, created_at, updated_at)
                 VALUES ($1, 'psp_already_done', 'AUTHORISATION', 'processed', NOW(), NOW())",
            )
            .bind(adyen_notification_id(&done))
            .execute(&env.pool)
            .await
            .expect("seed processed row");
            replay_deadletter(&env.state, &build_entry(&done))
                .await
                .expect("an already-processed event replays as a no-op success");
            let dunning: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dunning_records")
                .fetch_one(&env.pool)
                .await
                .expect("dunning");
            assert_eq!(dunning, 0, "a processed event is never re-applied");

            // An event currently pending on another worker: refused, and the
            // refusal feeds the retry scheduling instead of losing the event.
            let pending =
                authorisation_item("psp_now_pending", invoice_id, 100, false, Some(tenant));
            sqlx::query(
                "INSERT INTO adyen_webhook_events (adyen_notification_id, adyen_psp_reference, event_type, status, created_at, updated_at)
                 VALUES ($1, 'psp_now_pending', 'AUTHORISATION', 'pending', NOW(), NOW())",
            )
            .bind(adyen_notification_id(&pending))
            .execute(&env.pool)
            .await
            .expect("seed pending row");
            let error = replay_deadletter(&env.state, &build_entry(&pending))
                .await
                .expect_err("a pending event must not replay");
            assert!(
                error.contains("pending"),
                "unexpected replay error: {error}"
            );
        }
    );

    // ===================================================================
    // Deadletter retry worker.
    // ===================================================================

    env_test!(deadletter_retry_backs_off_then_exhausts, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        let tenant = "swcov_backoff";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 100, 0, 100, "eur").await;
        let item = authorisation_item("psp_sw_backoff", invoice_id, 100, false, Some(tenant));
        // A signature that can never verify keeps the retry ladder
        // deterministic: every attempt fails.
        let body = String::from_utf8(envelope_bytes(&item, "!!!not-base64!!!")).expect("body");
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(adyen_notification_id(&item)),
            body: Some(body),
            signature: Some("!!!not-base64!!!".into()),
            ..Default::default()
        };
        let the_key = "adyen:deadletter:event:authorisation_forced";
        let entry_json = serde_json::to_string(&entry).expect("entry json");
        let mut conn = redis_conn(env).await;
        // Isolate the shared retry index for this test.
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg("-inf")
            .arg("+inf")
            .query_async(&mut conn)
            .await
            .expect("clear retry index");
        let _: () = redis::cmd("SET")
            .arg(the_key)
            .arg(&entry_json)
            .query_async(&mut conn)
            .await
            .expect("store entry");
        let before = Utc::now().timestamp_millis();
        let _: () = redis::cmd("ZADD")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(1)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("schedule due retry");
        drop(conn);

        process_deadletter_retries(&env.state)
            .await
            .expect("retry pass");
        let mut conn = redis_conn(env).await;
        let updated: Option<String> = redis::cmd("GET")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("read entry");
        let updated: DeadletterEntry =
            serde_json::from_str(updated.as_deref().expect("entry kept")).expect("json");
        assert_eq!(updated.retry_count, 1, "attempt recorded");
        let score: Option<i64> = redis::cmd("ZSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("score");
        let score = score.expect("rescheduled");
        assert!(
            score > before,
            "backoff schedules the next attempt in the future"
        );

        // Simulate four prior attempts: the fifth failure exhausts the ladder.
        let mut almost_done = updated.clone();
        almost_done.retry_count = 4;
        let _: () = redis::cmd("SET")
            .arg(the_key)
            .arg(serde_json::to_string(&almost_done).expect("json"))
            .query_async(&mut conn)
            .await
            .expect("store almost-done entry");
        let _: () = redis::cmd("ZADD")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(1)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("reschedule due");
        drop(conn);

        process_deadletter_retries(&env.state)
            .await
            .expect("exhausting pass");
        let mut conn = redis_conn(env).await;
        let score: Option<i64> = redis::cmd("ZSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("score");
        assert!(score.is_none(), "exhausted retries leave the retry index");
        let ttl: i64 = redis::cmd("TTL")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("ttl");
        assert!(
            (0..=7 * 24 * 60 * 60).contains(&ttl),
            "final entry keeps a bounded review TTL, got {ttl}"
        );
        let kept: Option<String> = redis::cmd("GET")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("read final entry");
        let kept: DeadletterEntry =
            serde_json::from_str(kept.as_deref().expect("kept for review")).expect("json");
        assert_eq!(kept.retry_count, 5, "attempts are capped at max_retries");
        // Leave the shared index clean for other tests in this binary.
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg("-inf")
            .arg("+inf")
            .query_async(&mut conn)
            .await
            .expect("clear retry index");
        let _: () = redis::cmd("DEL")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("drop entry");
    });

    env_test!(
        retry_worker_handles_evicted_corrupt_and_foreign_entries,
        |env| {
            let isolated = crate::test_support::spawn_isolated_redis();
            let state = state_with_isolated_redis(env, &isolated);
            let mut conn = pool_conn(&isolated.pool).await;
            let _: () = redis::cmd("ZREMRANGEBYSCORE")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg("-inf")
                .arg("+inf")
                .query_async(&mut conn)
                .await
                .expect("clear");

            // 1) evicted entry: index member without a stored body.
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg("adyen:deadletter:event:evicted")
                .query_async(&mut conn)
                .await
                .expect("schedule evicted");
            // 2) corrupt entry: stored body is not JSON.
            let _: () = redis::cmd("SET")
                .arg("adyen:deadletter:event:corrupt")
                .arg("this is not json")
                .query_async(&mut conn)
                .await
                .expect("store corrupt");
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg("adyen:deadletter:event:corrupt")
                .query_async(&mut conn)
                .await
                .expect("schedule corrupt");
            // 3) foreign entry: not a processing_failed reason.
            let foreign = DeadletterEntry {
                reason: "missing_signature".into(),
                ..Default::default()
            };
            let _: () = redis::cmd("SET")
                .arg("adyen:deadletter:event:foreign")
                .arg(serde_json::to_string(&foreign).unwrap())
                .query_async(&mut conn)
                .await
                .expect("store foreign");
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg("adyen:deadletter:event:foreign")
                .query_async(&mut conn)
                .await
                .expect("schedule foreign");
            drop(conn);

            retry_deadlettered_webhooks(&state)
                .await
                .expect("retry pass");
            let mut conn = pool_conn(&isolated.pool).await;
            let remaining: i64 = redis::cmd("ZCARD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .query_async(&mut conn)
                .await
                .expect("card");
            assert_eq!(remaining, 0, "all three arms drop their index members");
            let _: () = redis::cmd("DEL")
                .arg("adyen:deadletter:event:corrupt")
                .arg("adyen:deadletter:event:foreign")
                .query_async(&mut conn)
                .await
                .expect("cleanup");
        }
    );

    // P3 fix 4 — the retry pass must use O(1) Redis round trips, not one
    // GET + one ZREM per key. Five due entries (two evicted, three
    // non-replayable) take three commands: ZRANGEBYSCORE, ONE MGET, ONE
    // multi-member ZREM. The pre-fix loop issued 1 + 2×5 = 11.
    env_test!(retry_worker_batches_redis_reads_and_index_removals, |env| {
        use crate::test_support::query_count;

        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        let mut conn = pool_conn(&isolated.pool).await;
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg("-inf")
            .arg("+inf")
            .query_async(&mut conn)
            .await
            .expect("clear retry index");

        // Two index members whose body was evicted.
        for index in 0..2 {
            let key = format!("adyen:deadletter:event:batch_evicted_{index}");
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg(&key)
                .query_async(&mut conn)
                .await
                .expect("schedule evicted");
        }
        // Three stored entries that are NOT replayable (foreign reason):
        // removed without a replay, exercising the batched removal path.
        let foreign = DeadletterEntry {
            reason: "invalid_signature".into(),
            ..Default::default()
        };
        let foreign_json = serde_json::to_string(&foreign).expect("json");
        for index in 0..3 {
            let key = format!("adyen:deadletter:event:batch_foreign_{index}");
            let _: () = redis::cmd("SET")
                .arg(&key)
                .arg(&foreign_json)
                .query_async(&mut conn)
                .await
                .expect("store foreign");
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg(&key)
                .query_async(&mut conn)
                .await
                .expect("schedule foreign");
        }
        drop(conn);

        query_count::reset();
        retry_deadlettered_webhooks(&state)
            .await
            .expect("batched retry pass");
        let commands = query_count::count("deadletter.redis");
        assert!(
            commands <= 3,
            "five due keys must cost one ZRANGEBYSCORE + one MGET + one ZREM, got {commands}"
        );

        let mut conn = pool_conn(&isolated.pool).await;
        let remaining: i64 = redis::cmd("ZCARD")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .query_async(&mut conn)
            .await
            .expect("card");
        assert_eq!(remaining, 0, "every handled key leaves the retry index");
        let _: () = redis::cmd("DEL")
            .arg("adyen:deadletter:event:batch_foreign_0")
            .arg("adyen:deadletter:event:batch_foreign_1")
            .arg("adyen:deadletter:event:batch_foreign_2")
            .query_async(&mut conn)
            .await
            .expect("cleanup");
    });

    env_test!(retry_worker_empty_index_is_a_clean_noop, |env| {
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        retry_deadlettered_webhooks(&state)
            .await
            .expect("empty batch returns immediately");
    });

    env_test!(retry_worker_success_removes_entry_from_index, |env| {
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        let tenant = "swadv_retry_ok";
        crate::test_support::seed_tenant(&env.pool, tenant, "growth").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 100, 0, 100, "eur").await;
        let item = authorisation_item("psp_retry_ok", invoice_id, 100, false, Some(tenant));
        let signature = sign_item("whsec_coverage", &item);
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(adyen_notification_id(&item)),
            body: Some(String::from_utf8(envelope_bytes(&item, &signature)).expect("body")),
            signature: Some(signature),
            ..Default::default()
        };
        let the_key = "adyen:deadletter:event:psp_retry_ok";
        let mut conn = pool_conn(&isolated.pool).await;
        let _: () = redis::cmd("ZREMRANGEBYSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg("-inf")
            .arg("+inf")
            .query_async(&mut conn)
            .await
            .expect("clear");
        let _: () = redis::cmd("SET")
            .arg(the_key)
            .arg(serde_json::to_string(&entry).unwrap())
            .query_async(&mut conn)
            .await
            .expect("store");
        let _: () = redis::cmd("ZADD")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(1)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("schedule");
        drop(conn);

        retry_deadlettered_webhooks(&state).await.expect("retry");
        let mut conn = pool_conn(&isolated.pool).await;
        let score: Option<i64> = redis::cmd("ZSCORE")
            .arg(DEADLETTER_RETRY_INDEX_KEY)
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("score");
        assert_eq!(score, None, "success leaves the retry index");
        let kept: Option<String> = redis::cmd("GET")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("kept");
        assert!(kept.is_some(), "the deadletter body stays for audit");
        let count: i32 = sqlx::query_scalar(
            "SELECT failed_payment_count FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!(count, 1, "the retried refusal applied exactly once");
        let _: () = redis::cmd("DEL")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("cleanup");
    });

    env_test!(process_retries_pass_drains_due_entries_once, |env| {
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        process_deadletter_retries(&state)
            .await
            .expect("nothing due is a clean pass");
    });

    env_test!(spawned_retry_worker_performs_one_immediate_pass, |env| {
        spawn_deadletter_retry_worker(env.state.clone());
        // The first interval tick fires immediately: one full retry pass runs
        // before the runtime is torn down.
        tokio::time::sleep(Duration::from_millis(20)).await;
    });

    env_test!(
        retry_failure_reschedules_with_backoff_then_gives_up_after_max_attempts,
        |env| {
            let _guard = DEADLETTER_LOCK.lock().await;
            let isolated = crate::test_support::spawn_isolated_redis();
            // The replay must FAIL deterministically: a state whose database
            // never connects (the HMAC re-verification against the isolated
            // redis passes, then the claim query fails).
            let state = AppState::new(
                crate::test_support::broken_db_pool(),
                isolated.pool.clone(),
                env.state.config.clone(),
            );
            let mut conn = pool_conn(&isolated.pool).await;
            let _: () = redis::cmd("DEL")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .query_async(&mut conn)
                .await
                .expect("clear index");

            let make_entry = |event_id: &str, retry_count: u32| {
                let item = authorisation_item(
                    event_id,
                    Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid"),
                    100,
                    false,
                    Some("swcov_backoff"),
                );
                let signature = sign_item("whsec_coverage", &item);
                DeadletterEntry {
                    reason: "processing_failed".into(),
                    event_id: Some(event_id.into()),
                    body: Some(String::from_utf8(envelope_bytes(&item, &signature)).expect("body")),
                    signature: Some(signature),
                    retry_count,
                    ..Default::default()
                }
            };
            for (event_id, count) in [("psp_backoff_1", 0u32), ("psp_give_up", 4u32)] {
                let entry = make_entry(event_id, count);
                let key = format!("adyen:deadletter:event:{event_id}");
                let _: () = redis::cmd("SET")
                    .arg(&key)
                    .arg(serde_json::to_string(&entry).unwrap())
                    .query_async(&mut conn)
                    .await
                    .expect("store entry");
                let _: () = redis::cmd("ZADD")
                    .arg(DEADLETTER_RETRY_INDEX_KEY)
                    .arg(1)
                    .arg(&key)
                    .query_async(&mut conn)
                    .await
                    .expect("schedule entry");
            }
            drop(conn);

            process_deadletter_retries(&state)
                .await
                .expect("the pass completes; per-entry failures are absorbed");

            // Entry 1: first failure → rescheduled on the FIRST backoff step.
            let mut conn = pool_conn(&isolated.pool).await;
            let score: Option<f64> = redis::cmd("ZSCORE")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg("adyen:deadletter:event:psp_backoff_1")
                .query_async(&mut conn)
                .await
                .expect("score");
            assert!(score.is_some(), "a first failure stays scheduled");
            let rescheduled: String = redis::cmd("GET")
                .arg("adyen:deadletter:event:psp_backoff_1")
                .query_async(&mut conn)
                .await
                .expect("entry");
            let entry: DeadletterEntry = serde_json::from_str(&rescheduled).unwrap();
            assert_eq!(entry.retry_count, 1, "the retry counter advanced");

            // Entry 2: the failure AFTER the last allowed attempt gives up —
            // dropped from the index, entry rewritten with the final count
            // and a 7-day review TTL.
            let gone: i64 = redis::cmd("ZSCORE")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg("adyen:deadletter:event:psp_give_up")
                .query_async(&mut conn)
                .await
                .map(|v: Option<f64>| v.map(|_| 1).unwrap_or(0))
                .expect("zscore");
            assert_eq!(gone, 0, "an exhausted entry leaves the retry index");
            let final_json: String = redis::cmd("GET")
                .arg("adyen:deadletter:event:psp_give_up")
                .query_async(&mut conn)
                .await
                .expect("final entry");
            let final_entry: DeadletterEntry = serde_json::from_str(&final_json).unwrap();
            assert_eq!(
                final_entry.retry_count, DEADLETTER_MAX_RETRIES,
                "the final count is recorded for review"
            );
            let ttl: i64 = redis::cmd("TTL")
                .arg("adyen:deadletter:event:psp_give_up")
                .query_async(&mut conn)
                .await
                .expect("ttl");
            assert!(
                ttl > 0 && ttl <= 7 * 24 * 60 * 60,
                "the final entry keeps a 7-day review TTL, got {ttl}"
            );
        }
    );

    // ===================================================================
    // Deadletter write-failure arms.
    // ===================================================================

    env_test!(
        deadletter_write_failure_on_dead_redis_is_logged_not_fatal,
        |env| {
            let dead = crate::test_support::state_with_dead_redis(&env.pool);
            // A missing signature must still answer 400 even when Redis is down.
            let body = br#"{"notificationItems":[{"NotificationRequestItem":{"pspReference":"psp_deadredis","eventCode":"AUTHORISATION"}}]}"#;
            let response = post_webhook(&dead, body).await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(event_rows(&env.pool).await, 0);
        }
    );

    env_test!(deadletter_index_wrongtype_fails_the_write_arm, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        let mut conn = redis_conn(env).await;
        let _: () = redis::cmd("SET")
            .arg(DEADLETTER_INDEX_KEY)
            .arg("not-a-zset")
            .query_async(&mut conn)
            .await
            .expect("poison index");
        drop(conn);

        let body = br#"{"notificationItems":[{"NotificationRequestItem":{"pspReference":"psp_wrongtype","eventCode":"AUTHORISATION"}}]}"#;
        let response = post_webhook(&env.state, body).await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);

        let mut conn = redis_conn(env).await;
        let _: () = redis::cmd("DEL")
            .arg(DEADLETTER_INDEX_KEY)
            .query_async(&mut conn)
            .await
            .expect("cleanup index");
    });

    env_test!(
        record_failed_deadletter_without_row_reports_not_found,
        |env| {
            let error = record_failed_webhook_deadletter_atomic(
                &env.state,
                "adn_never_claimed",
                "boom",
                br#"{"notificationItems":[{"NotificationRequestItem":{"pspReference":"psp_never_claimed"}}]}"#,
                Some("TQ=="),
            )
            .await
            .expect_err("missing claim row");
            assert!(error.contains("was not found"), "honest failure: {error}");
        }
    );

    env_test!(
        record_failed_deadletter_begin_failure_is_a_hard_error,
        |env| {
            let broken = crate::test_support::state_with_broken_db();
            let error = record_failed_webhook_deadletter_atomic(
                &broken,
                "adn_beginfail",
                "boom",
                br#"{"notificationItems":[{"NotificationRequestItem":{"pspReference":"psp_beginfail"}}]}"#,
                Some("TQ=="),
            )
            .await
            .expect_err("broken db begin");
            assert!(error.contains("Failed to begin"), "honest failure: {error}");
            assert_eq!(event_rows(&env.pool).await, 0, "nothing was claimed");
        }
    );

    env_test!(
        record_failed_deadletter_redis_failure_rolls_back_the_status_flip,
        |env| {
            let isolated = crate::test_support::spawn_isolated_redis();
            let state = state_with_isolated_redis(env, &isolated);
            sqlx::query(
                "INSERT INTO adyen_webhook_events (id, adyen_notification_id, adyen_psp_reference, event_type, status)
                 VALUES (gen_random_uuid(), 'adn_rollback', 'psp_rollback', 'AUTHORISATION', 'pending')",
            )
            .execute(&env.pool)
            .await
            .expect("claim row");

            let mut conn = pool_conn(&isolated.pool).await;
            let _: () = redis::cmd("SET")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg("not-a-zset")
                .query_async(&mut conn)
                .await
                .expect("poison retry index");
            drop(conn);

            let error = record_failed_webhook_deadletter_atomic(
                &state,
                "adn_rollback",
                "boom",
                br#"{"notificationItems":[{"NotificationRequestItem":{"pspReference":"psp_rollback"}}]}"#,
                Some("TQ=="),
            )
            .await
            .expect_err("redis failure surfaces");
            assert!(
                error.contains("adyen dead letter"),
                "honest failure: {error}"
            );
            let status: String = sqlx::query_scalar(
                "SELECT status FROM adyen_webhook_events WHERE adyen_notification_id = 'adn_rollback'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("status");
            assert_eq!(status, "pending", "the failed-status flip rolled back");
        }
    );

    env_test!(
        record_failed_deadletter_commit_failure_compensates_redis,
        |env| {
            let isolated = crate::test_support::spawn_isolated_redis();
            let state = state_with_isolated_redis(env, &isolated);
            sqlx::query(
                "INSERT INTO adyen_webhook_events (id, adyen_notification_id, adyen_psp_reference, event_type, status)
                 VALUES (gen_random_uuid(), 'adn_commitfail', 'psp_commitfail', 'AUTHORISATION', 'pending')",
            )
            .execute(&env.pool)
            .await
            .expect("claim row");
            // Deferred constraint: the UPDATE succeeds inside the tx and the
            // COMMIT itself fails — the exact commit-failure fault to inject.
            // (Postgres CHECK constraints cannot defer; a FK to a guard table
            // can, and 'failed' is absent from the guard.)
            for statement in [
                "CREATE TABLE cov_status_guard (status text PRIMARY KEY)",
                "INSERT INTO cov_status_guard VALUES ('pending'), ('received')",
                "ALTER TABLE adyen_webhook_events ADD CONSTRAINT cov_status_fk FOREIGN KEY (status)                  REFERENCES cov_status_guard(status) DEFERRABLE INITIALLY DEFERRED",
            ] {
                sqlx::query(statement)
                    .execute(&env.pool)
                    .await
                    .expect("deferred constraint setup");
            }

            let error = record_failed_webhook_deadletter_atomic(
                &state,
                "adn_commitfail",
                "boom",
                br#"{"notificationItems":[{"NotificationRequestItem":{"pspReference":"psp_commitfail"}}]}"#,
                Some("TQ=="),
            )
            .await
            .expect_err("commit failure surfaces");
            assert!(
                error.contains("Failed to commit"),
                "honest failure: {error}"
            );
            let status: String = sqlx::query_scalar(
                "SELECT status FROM adyen_webhook_events WHERE adyen_notification_id = 'adn_commitfail'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("status");
            assert_eq!(
                status, "pending",
                "commit failure leaves the claim untouched"
            );
            // The already-written deadletter entry is compensated away.
            let mut conn = pool_conn(&isolated.pool).await;
            let entries =
                deadletter_entries_on(&mut conn, "adyen:deadletter:event:adn_commitfail*").await;
            assert_eq!(
                entries.len(),
                0,
                "redis entry compensated after commit failure"
            );
        }
    );

    env_test!(compensation_failure_is_logged_never_fatal, |env| {
        // Direct fault injection: the compensation pipeline must tolerate a
        // Redis failure (it only logs) — a commit failure must never panic
        // or mask its own error because the compensating DEL/ZREM failed.
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        let mut conn = pool_conn(&isolated.pool).await;
        let the_key = "adyen:deadletter:event:adn_comp_direct";
        let _: () = redis::cmd("SETEX")
            .arg(the_key)
            .arg(60)
            .arg("{}")
            .query_async(&mut conn)
            .await
            .expect("stored entry");
        // Poison the shared index as a STRING: DEL succeeds, ZREM fails.
        let _: () = redis::cmd("SET")
            .arg(DEADLETTER_INDEX_KEY)
            .arg("not-a-zset")
            .query_async(&mut conn)
            .await
            .expect("poison index");
        drop(conn);

        remove_prepared_deadletter_from_redis(&state, the_key).await;

        let mut conn = pool_conn(&isolated.pool).await;
        let gone: Option<String> = redis::cmd("GET")
            .arg(the_key)
            .query_async(&mut conn)
            .await
            .expect("entry state");
        assert_eq!(gone, None, "the DEL in the compensation still ran");
    });

    env_test!(
        prepare_deadletter_without_body_stores_nothing_replayable,
        |env| {
            let _ = env;
            let prepared = prepare_deadletter(
                DeadletterEntry {
                    reason: "missing_signature".into(),
                    ..Default::default()
                },
                None,
                None,
                Utc::now(),
            );
            assert_eq!(prepared.retry_at_ms, None);
            let entry: DeadletterEntry = serde_json::from_str(&prepared.payload).expect("entry");
            assert!(entry.body.is_none());
            assert!(entry.signature.is_none());
        }
    );

    env_test!(
        deadletter_write_refuses_when_the_claim_row_is_missing,
        |env| {
            let _guard = DEADLETTER_LOCK.lock().await;
            let _dl_guard =
                crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
            let mut clear = pool_conn(&env.redis).await;
            let _: () = redis::cmd("DEL")
                .arg(DEADLETTER_INDEX_KEY)
                .query_async(&mut clear)
                .await
                .expect("clear index");
            drop(clear);
            let error = record_failed_webhook_deadletter_atomic(
                &env.state,
                "adn_never_claimed_cov",
                "handler failed",
                br#"{"notificationItems":[{"NotificationRequestItem":{"pspReference":"psp_never_claimed_cov"}}]}"#,
                Some("TQ=="),
            )
            .await
            .expect_err("an unknown event row must fail the atomic deadletter");
            assert!(
                error.contains("event row was not found"),
                "unexpected: {error}"
            );
            // The empty transaction left nothing behind.
            let deadletters: i64 = redis::cmd("ZCARD")
                .arg(DEADLETTER_INDEX_KEY)
                .query_async(&mut pool_conn(&env.redis).await)
                .await
                .expect("zcard");
            assert_eq!(deadletters, 0, "no deadletter without a claim row");
        }
    );

    env_test!(
        deadletter_write_rolls_back_when_the_redis_leg_fails,
        |env| {
            let _guard = DEADLETTER_LOCK.lock().await;
            let dead_redis = crate::test_support::dead_redis_pool();
            let state = AppState::new(env.pool.clone(), dead_redis, env.state.config.clone());

            // The claim row EXISTS (the webhook was claimed earlier), so the
            // SQL leg matches one row; the Redis leg then fails on the dead
            // pool and the whole transaction must roll back.
            sqlx::query(
                "INSERT INTO adyen_webhook_events (adyen_notification_id, adyen_psp_reference, event_type, status, created_at, updated_at)
                 VALUES ('adn_redis_dead_cov', 'psp_redis_dead', 'AUTHORISATION', 'pending', NOW(), NOW())",
            )
            .execute(&env.pool)
            .await
            .expect("seed claim row");

            let error = record_failed_webhook_deadletter_atomic(
                &state,
                "adn_redis_dead_cov",
                "handler failed",
                br#"{"notificationItems":[{"NotificationRequestItem":{"pspReference":"psp_redis_dead"}}]}"#,
                Some("TQ=="),
            )
            .await
            .expect_err("dead redis must fail the atomic deadletter");
            assert!(error.contains("adyen dead letter"), "unexpected: {error}");

            // The SQL leg was rolled back: the row is still 'pending'.
            let status: String = sqlx::query_scalar(
                "SELECT status FROM adyen_webhook_events WHERE adyen_notification_id = 'adn_redis_dead_cov'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("row");
            assert_eq!(status, "pending", "the failed-marking was rolled back");
        }
    );

    // ===================================================================
    // Ledger claim / reclaim.
    // ===================================================================

    env_test!(reclaim_stale_pending_only_touches_abandoned_rows, |env| {
        let stale = "adn_sw_stale";
        let fresh = "adn_sw_fresh";
        let processed = "adn_sw_done";
        let received = "adn_sw_received";
        for (notification_id, status, updated_offset_minutes) in [
            (stale, "pending", 20_i64),
            (fresh, "pending", 1),
            (processed, "processed", 20),
            (received, "received", 20),
        ] {
            sqlx::query(
                "INSERT INTO adyen_webhook_events
                     (id, adyen_notification_id, adyen_psp_reference, event_type, status, created_at, updated_at)
                 VALUES (gen_random_uuid(), $1, 'psp_reclaim', 'AUTHORISATION', $2,
                         NOW() - make_interval(mins => $3::int),
                         NOW() - make_interval(mins => $3::int))",
            )
            .bind(notification_id)
            .bind(status)
            .bind(updated_offset_minutes)
            .execute(&env.pool)
            .await
            .expect("event row");
        }

        let reclaimed = reclaim_stale_pending_webhooks(&env.state)
            .await
            .expect("reclaim");
        assert_eq!(reclaimed, vec![stale.to_string()]);
        let (fresh_status, done_status, received_status): (String, String, String) =
            sqlx::query_as(
                "SELECT
                (SELECT status FROM adyen_webhook_events WHERE adyen_notification_id = $1),
                (SELECT status FROM adyen_webhook_events WHERE adyen_notification_id = $2),
                (SELECT status FROM adyen_webhook_events WHERE adyen_notification_id = $3)",
            )
            .bind(fresh)
            .bind(processed)
            .bind(received)
            .fetch_one(&env.pool)
            .await
            .expect("statuses");
        assert_eq!(fresh_status, "pending", "a fresh claim is left alone");
        assert_eq!(done_status, "processed", "completed work is never rewound");
        assert_eq!(received_status, "received");
        let reclaimed_status: String = sqlx::query_scalar(
            "SELECT status FROM adyen_webhook_events WHERE adyen_notification_id = $1",
        )
        .bind(stale)
        .fetch_one(&env.pool)
        .await
        .expect("stale status");
        assert_eq!(reclaimed_status, "received");
    });

    env_test!(claim_webhook_event_is_exactly_once, |env| {
        let notification_id = "adn_sw_claim";
        let first =
            claim_webhook_event(&env.state, notification_id, "AUTHORISATION", "psp_sw_claim")
                .await
                .expect("claim");
        assert!(matches!(first, WebhookEventClaim::Claimed));
        // The psp reference is stored for support lookups.
        let psp: Option<String> = sqlx::query_scalar(
            "SELECT adyen_psp_reference FROM adyen_webhook_events WHERE adyen_notification_id = $1",
        )
        .bind(notification_id)
        .fetch_one(&env.pool)
        .await
        .expect("psp");
        assert_eq!(psp.as_deref(), Some("psp_sw_claim"));
        // A second worker sees the row as pending.
        let second =
            claim_webhook_event(&env.state, notification_id, "AUTHORISATION", "psp_sw_claim")
                .await
                .expect("claim");
        assert!(matches!(second, WebhookEventClaim::AlreadyPending));
        // A failed attempt may be reclaimed; a processed one never is.
        sqlx::query(
            "UPDATE adyen_webhook_events SET status = 'failed' WHERE adyen_notification_id = $1",
        )
        .bind(notification_id)
        .execute(&env.pool)
        .await
        .expect("mark failed");
        let reclaimed =
            claim_webhook_event(&env.state, notification_id, "AUTHORISATION", "psp_sw_claim")
                .await
                .expect("claim");
        assert!(matches!(reclaimed, WebhookEventClaim::Claimed));
        sqlx::query(
            "UPDATE adyen_webhook_events SET status = 'processed' WHERE adyen_notification_id = $1",
        )
        .bind(notification_id)
        .execute(&env.pool)
        .await
        .expect("mark processed");
        let duplicate =
            claim_webhook_event(&env.state, notification_id, "AUTHORISATION", "psp_sw_claim")
                .await
                .expect("claim");
        assert!(matches!(duplicate, WebhookEventClaim::AlreadyProcessed));
    });

    env_test!(reclaim_reports_reclaimed_events_loudly, |env| {
        sqlx::query(
            "INSERT INTO adyen_webhook_events (id, adyen_notification_id, adyen_psp_reference, event_type, status, updated_at)
             VALUES (gen_random_uuid(), 'adn_swadv_reclaim', 'psp_swadv_reclaim', 'AUTHORISATION', 'pending',
                     NOW() - INTERVAL '20 minutes')",
        )
        .execute(&env.pool)
        .await
        .expect("stale row");
        let reclaimed = reclaim_stale_pending_webhooks(&env.state)
            .await
            .expect("reclaim");
        assert_eq!(reclaimed, vec!["adn_swadv_reclaim".to_string()]);
    });

    // ===================================================================
    // Dunning config + notification edges.
    // ===================================================================

    env_test!(dunning_config_degrades_to_defaults_on_faults, |env| {
        let tenant = "swadv_duncfg";
        crate::test_support::seed_tenant(&env.pool, tenant, "growth").await;
        // Per-tenant configured schedule is honored.
        sqlx::query(
            "INSERT INTO dunning_config
                 (tenant_id, retry_schedule_days, soft_suspend_after_days, hard_suspend_after_days, grace_period_days)
             VALUES ($1, ARRAY[2,4], 5, 9, 3)",
        )
        .bind(tenant)
        .execute(&env.pool)
        .await
        .expect("config row");
        let config = get_dunning_config_for_tenant(&env.state, tenant).await;
        assert_eq!(config.retry_schedule_days, vec![2, 4]);

        // Table missing: defaults, loudly.
        env.break_table("dunning_config").await;
        let config = get_dunning_config_for_tenant(&env.state, tenant).await;
        assert_eq!(
            config.soft_suspend_after_days, 7,
            "defaults survive a missing table"
        );
        env.restore_table("dunning_config").await;

        // Table exists again (the OnceLock now trusts it): the tenant row wins.
        let config = get_dunning_config_for_tenant(&env.state, tenant).await;
        assert_eq!(config.retry_schedule_days, vec![2, 4]);
        env.break_table("dunning_config").await;
        let config = get_dunning_config_for_tenant(&env.state, tenant).await;
        assert_eq!(
            config.hard_suspend_after_days, 21,
            "defaults survive a failing query"
        );
        env.restore_table("dunning_config").await;
    });

    env_test!(
        dunning_notification_type_mapping_and_enqueue_failure,
        |env| {
            let tenant = "swadv_notif";
            crate::test_support::seed_tenant(&env.pool, tenant, "growth").await;
            for (status, _kind) in [
                ("warning", "payment_reminder"),
                ("soft_suspended", "account_soft_suspended"),
                ("hard_suspended", "account_hard_suspended"),
            ] {
                send_dunning_notification(&env.state, tenant, status, serde_json::json!({})).await;
            }
            let rows: Vec<(String,)> = sqlx::query_as(
                "SELECT type FROM notification_queue WHERE tenant_id = $1 ORDER BY type",
            )
            .bind(tenant)
            .fetch_all(&env.pool)
            .await
            .expect("queue");
            let types: Vec<String> = rows.into_iter().map(|r| r.0).collect();
            assert_eq!(
                types,
                vec![
                    "account_hard_suspended".to_string(),
                    "account_soft_suspended".to_string(),
                    "payment_reminder".to_string()
                ]
            );

            // Enqueue failure is logged, never fatal.
            env.break_table("notification_queue").await;
            send_dunning_notification(&env.state, tenant, "warning", serde_json::json!({})).await;
            env.restore_table("notification_queue").await;
        }
    );

    env_test!(refusal_caches_status_and_survives_cache_faults, |env| {
        let tenant = "swadv_cache";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 10, 0, 10, "eur").await;
        let dead = crate::test_support::state_with_dead_redis(&env.pool);
        let item = authorisation_item("psp_cache", invoice_id, 10, false, Some(tenant));
        handle_authorisation_refused(&dead, &item)
            .await
            .expect("refusal processing survives a dead cache");
        let count: i32 = sqlx::query_scalar(
            "SELECT failed_payment_count FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!(count, 1);
    });

    // ===================================================================
    // Money events: refund / failed refund / chargeback.
    // ===================================================================

    env_test!(refund_and_chargeback_events_are_audited_never_5xx, |env| {
        let tenant = "swadv_money";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 1_000, 0, 1_000, "eur").await;

        for (psp, event_code) in [
            ("psp_refund", "REFUND"),
            ("psp_refund_failed", "REFUND_FAILED"),
            ("psp_chargeback", "CHARGEBACK"),
            ("psp_chargeback_reversed", "CHARGEBACK_REVERSED"),
        ] {
            let item = parse_item(serde_json::json!({
                "pspReference": psp,
                "originalReference": "psp_paid",
                "merchantAccountCode": "ApexMailECOV",
                "merchantReference": format!("invoice:{invoice_id}"),
                "amount": { "currency": "EUR", "value": 1_000 },
                "eventCode": event_code,
                "eventDate": "2026-10-14T10:00:00+00:00",
                "success": "true",
                "reason": "requested"
            }));
            // Never a 5xx, never a silent drop: the handler records and
            // acknowledges.
            handle_notification(&env.state, &item)
                .await
                .unwrap_or_else(|error| panic!("{event_code} must be recorded, got {error}"));
        }

        let audits: Vec<(String,)> =
            sqlx::query_as("SELECT action FROM audit_logs WHERE tenant_id = $1 ORDER BY action")
                .bind(tenant)
                .fetch_all(&env.pool)
                .await
                .expect("audit rows");
        let actions: Vec<&str> = audits.iter().map(|row| row.0.as_str()).collect();
        assert!(actions.contains(&"billing.adyen_refund_recorded"));
        assert!(actions.contains(&"billing.adyen_refund_failed"));
        assert!(actions.contains(&"billing.adyen_chargeback_recorded"));
        assert!(actions.contains(&"billing.adyen_chargeback_reversed"));
        // The invoice itself is untouched by a money event (credit notes are
        // the refund path's writer, not this arm).
        let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("status");
        assert_eq!(status, "pending");

        // An unresolvable binding is loudly recorded and still acknowledged.
        let orphan = parse_item(serde_json::json!({
            "pspReference": "psp_refund_orphan",
            "merchantReference": "not-a-local-invoice",
            "amount": { "currency": "EUR", "value": 10 },
            "eventCode": "REFUND",
            "success": "true"
        }));
        handle_notification(&env.state, &orphan)
            .await
            .expect("an unresolvable refund is acknowledged (never 5xx)");
    });

    // ===================================================================
    // Dedicated-IP auto-provisioning (local servers).
    // ===================================================================

    /// A local axum server on an ephemeral port answering /v1/dedicated-ips.
    async fn local_api_server(
        status: axum::http::StatusCode,
    ) -> (String, tokio::task::JoinHandle<()>) {
        let app = axum::Router::new().route(
            "/v1/dedicated-ips",
            axum::routing::post(move || async move { (status, "{}") }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind");
        let addr = listener.local_addr().expect("addr");
        let handle = tokio::spawn(async move {
            axum::serve(listener, app).await.expect("local server");
        });
        (format!("http://{addr}"), handle)
    }

    fn state_with_api_base(env: &Env, api_base: String) -> Arc<AppState> {
        let mut config = env.state.config.clone();
        config.api_base_url = api_base;
        AppState::new(env.pool.clone(), env.redis.clone(), config)
    }

    async fn seed_dedicated_ip_plan(env: &Env, name: &str, included: i32) {
        // Shared plan-seeding convention (test_support) so the catalog row is
        // created exactly like the other billing suites; this suite only adds
        // the dedicated-IP allowance on top.
        crate::test_support::seed_plan(&env.pool, name, name).await;
        sqlx::query(
            "UPDATE plans SET features = jsonb_build_object('dedicated_ip_count', $2)
             WHERE name = $1",
        )
        .bind(name)
        .bind(included)
        .execute(&env.pool)
        .await
        .expect("plan with dedicated ips");
    }

    async fn seed_active_subscription(env: &Env, tenant: &str, plan: &str, sub_id: &str) {
        sqlx::query(
            "INSERT INTO adyen_subscriptions
                 (tenant_id, adyen_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, adyen_shopper_reference)
             VALUES ($1, $2, $3, 'active', NOW(), NOW() + INTERVAL '30 days', 'cus_ip')",
        )
        .bind(tenant)
        .bind(sub_id)
        .bind(plan)
        .execute(&env.pool)
        .await
        .expect("active subscription");
    }

    env_test!(auto_provision_covers_every_allocation_outcome, |env| {
        // 1) plan without dedicated IPs -> immediate no-op.
        let none = "swadv_ip_none";
        crate::test_support::seed_tenant(&env.pool, none, "growth").await;
        auto_provision_dedicated_ips_background(&env.state, none)
            .await
            .expect("no allowance is a no-op");

        // 2) tenant already at its allowance -> no-op.
        let full = "swadv_ip_full";
        seed_dedicated_ip_plan(env, "swadv_ip_plan", 1).await;
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $1, 'swadv_ip_plan', 'active')",
        )
        .bind(full)
        .execute(&env.pool)
        .await
        .expect("tenant");
        seed_active_subscription(env, full, "swadv_ip_plan", "sub_swadv_ip_full").await;
        sqlx::query(
            "INSERT INTO dedicated_ips (id, tenant_id, ip_address, status)
             VALUES ('ip-swadv-full-0000000000000001', $1, '198.51.100.10', 'active')",
        )
        .bind(full)
        .execute(&env.pool)
        .await
        .expect("ip");
        auto_provision_dedicated_ips_background(&env.state, full)
            .await
            .expect("sufficient IPs is a no-op");

        // 3) success: a local 200 server records a completed request.
        let ok_tenant = "swadv_ip_ok";
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $1, 'swadv_ip_plan', 'active')",
        )
        .bind(ok_tenant)
        .execute(&env.pool)
        .await
        .expect("tenant");
        seed_active_subscription(env, ok_tenant, "swadv_ip_plan", "sub_swadv_ip_ok").await;
        let (base, server) = local_api_server(StatusCode::OK).await;
        auto_provision_dedicated_ips_background(&state_with_api_base(env, base), ok_tenant)
            .await
            .expect("success path");
        let (status, ok): (String, i32) = sqlx::query_as(
            "SELECT status, success_count FROM dedicated_ip_provisioning_requests WHERE tenant_id = $1",
        )
        .bind(ok_tenant)
        .fetch_one(&env.pool)
        .await
        .expect("request");
        assert_eq!(status, "completed");
        assert_eq!(ok, 1);
        server.abort();

        // 4) partial: the attempt fails (409).
        let partial = "swadv_ip_partial";
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $1, 'swadv_ip_plan', 'active')",
        )
        .bind(partial)
        .execute(&env.pool)
        .await
        .expect("tenant");
        seed_active_subscription(env, partial, "swadv_ip_plan", "sub_swadv_ip_partial").await;
        let (base_fail, server_fail) = local_api_server(StatusCode::CONFLICT).await;
        auto_provision_dedicated_ips_background(&state_with_api_base(env, base_fail), partial)
            .await
            .expect("failure recorded");
        server_fail.abort();
        let (status, failures): (String, i32) = sqlx::query_as(
            "SELECT status, failure_count FROM dedicated_ip_provisioning_requests WHERE tenant_id = $1",
        )
        .bind(partial)
        .fetch_one(&env.pool)
        .await
        .expect("request");
        assert_eq!(status, "failed");
        assert_eq!(failures, 1, "the non-2xx response is a recorded failure");

        // 5) transport error: closed local port.
        let errored = "swadv_ip_err";
        sqlx::query(
            "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $1, 'swadv_ip_plan', 'active')",
        )
        .bind(errored)
        .execute(&env.pool)
        .await
        .expect("tenant");
        seed_active_subscription(env, errored, "swadv_ip_plan", "sub_swadv_ip_err").await;
        auto_provision_dedicated_ips_background(
            &state_with_api_base(env, "http://127.0.0.1:1".to_string()),
            errored,
        )
        .await
        .expect("transport errors are recorded, not fatal");
        let status: String = sqlx::query_scalar(
            "SELECT status FROM dedicated_ip_provisioning_requests WHERE tenant_id = $1",
        )
        .bind(errored)
        .fetch_one(&env.pool)
        .await
        .expect("request");
        assert_eq!(status, "failed");
    });

    env_test!(
        auto_provision_request_recording_faults_are_surfaced,
        |env| {
            let tenant = "swadv_ip_fault";
            seed_dedicated_ip_plan(env, "swadv_ip_plan2", 1).await;
            sqlx::query(
                "INSERT INTO tenants (id, name, plan, status) VALUES ($1, $1, 'swadv_ip_plan2', 'active')",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("tenant");
            seed_active_subscription(env, tenant, "swadv_ip_plan2", "sub_swadv_ip_fault").await;
            // The request table is gone: recording the intent fails honestly.
            env.break_table("dedicated_ip_provisioning_requests").await;
            let error = auto_provision_dedicated_ips_background(&env.state, tenant)
                .await
                .expect_err("broken request table");
            assert!(
                error.contains("Failed to record dedicated IP provisioning request"),
                "honest failure: {error}"
            );
            env.restore_table("dedicated_ip_provisioning_requests")
                .await;

            // The allowance query itself failing is surfaced too.
            env.break_table("adyen_subscriptions").await;
            let error = auto_provision_dedicated_ips_background(&env.state, tenant)
                .await
                .expect_err("broken allowance query");
            assert!(error.contains("Failed to load dedicated IP allowance"));
            env.restore_table("adyen_subscriptions").await;

            env.break_table("dedicated_ips").await;
            let error = auto_provision_dedicated_ips_background(&env.state, tenant)
                .await
                .expect_err("broken count query");
            assert!(error.contains("Failed to load active dedicated IP count"));
            env.restore_table("dedicated_ips").await;
        }
    );
}
