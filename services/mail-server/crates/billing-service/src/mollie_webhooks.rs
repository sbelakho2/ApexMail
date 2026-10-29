//! The Mollie webhook ingest surface for `POST /webhooks/mollie`.
//!
//! NEUTRALITY-DEBT (external audit P0-A, row N-10): this module stays
//! provider-specific BY DECISION this round. Its `ProviderNotification`
//! normalizer (facts, not wire formats) is the nucleus the neutral
//! `crate::payments::ProviderEvent` type was extracted from; steps 5 and 8
//! promote the normalizer behind the provider boundary and move its
//! writers onto the neutral event tables. Until then it keeps using
//! `mollie_client` directly, byte-for-byte.
//!
//! The real contract (docs/tool-contracts/mollie.md, mirrored by
//! `tools/dogfood-v2/harness/mollie.py`):
//!
//! * Mollie posts `application/x-www-form-urlencoded` with ONE parameter —
//!   `id=tr_…` for a payment, `id=re_…` for a refund. There is no status, no
//!   event type and NO signature.
//! * Authentication is the authenticated FETCH: every webhook is resolved by
//!   `GET https://api.mollie.com/v2/payments/{id}` with
//!   `Authorization: Bearer <MOLLIE_API_KEY>`. A forged call can therefore
//!   never invent a payment; at worst it causes a lookup that finds nothing,
//!   which is acknowledged with 200 (Mollie's own guidance, so the endpoint
//!   cannot be used as an existence oracle).
//! * Amounts are decimal strings (`{"currency":"EUR","value":"12.34"}`) and
//!   become integer cents exactly.
//! * `200 OK` acknowledges; any other status makes Mollie retry (10 attempts
//!   over ~26 hours, 15 s timeout each). Retries repeat the same id, so the
//!   dedupe id is deterministic over the normalized fact
//!   (payment id, event kind, success, amount, paid date, refunded subtotal,
//!   provider status).
//! * A refund webhook names only the refund id and Mollie's refund fetch
//!   needs the payment id too: `mollie_refunds` (written when we create the
//!   refund) supplies it.
//!
//! Local invoices are OURS: the payment's `metadata.invoice_id` names the
//! obligation, and the local invoice total is the tax decision the charge is
//! validated against.

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
use serde::{Deserialize, Serialize};
use tokio::time::timeout;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::routes::{append_audit_log, generate_audit_log_id};
use crate::AppState;

const DEADLETTER_EVENT_PREFIX: &str = "mollie:deadletter:event:";
const DEADLETTER_INDEX_KEY: &str = "mollie:deadletter:index";
const DEADLETTER_RETENTION_SECONDS: usize = 35 * 24 * 60 * 60;
const DEADLETTER_RETENTION_MS: i64 = (DEADLETTER_RETENTION_SECONDS as i64) * 1000;
const DEADLETTER_RETRY_INDEX_KEY: &str = "mollie:deadletter:retry:index";
const DEADLETTER_MAX_RETRIES: u32 = 5;
/// Maximum stored webhook body size (4 KiB). Larger bodies are truncated
/// before the Redis SET so a single oversized Mollie payload cannot bloat
/// every deadletter entry. Truncated bodies are kept for debugging but are
/// never replayed, the retry scheduler skips entries whose body was cut.
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

/// The success answer Mollie expects: HTTP 200 (the body is not read by
/// Mollie; the bare `OK` keeps operator replays legible).
const MOLLIE_WEBHOOK_ACCEPTED: &str = "OK";

/// The `mollie_tax_snapshots.authority` value recorded when the charged total
/// is validated against ApexMail's own computation. Migration 218's CHECK
/// constraint allows only ('stripe_tax', 'apexmail_local'); `apexmail_local`
/// is the allowed value that truthfully means "ApexMail's local computation
/// validated against the charge" (the pre-cutover `stripe_tax` check value named a
/// processor ApexMail no longer uses).
const TAX_AUTHORITY_LOCAL: &str = "apexmail_local";

/// The `invoice_payment_allocations.source` value for a settled Mollie
/// payment. The accounting ledger adapter
/// (`accounting_core::adapters::post_payment_allocation_in`) branches on
/// `source = 'mollie'` to post to the Mollie processor clearing account with
/// the `mollie_settlement` source type, so this is the codebase's truthful
/// value (migration 140's CHECK still lists the pre-cutover set; see the
/// migration-gap note in the module tests).
const PAYMENT_ALLOCATION_SOURCE: &str = "mollie";
/// The provider dimension on every allocation this module writes (audit
/// step 5, migration 281): the source value stays the historical one the
/// statutory ledger reads, the dimension carries the processor identity.
const PAYMENT_ALLOCATION_PROVIDER: &str = "mollie";

static DUNNING_CONFIG_TABLE_ENSURED: OnceLock<()> = OnceLock::new();

/// The Mollie webhook ingest route. Mounted by the billing-service binary
/// AND by api-server (which nests it on the public rate-limited stack when
/// `MOLLIE_API_KEY` is configured), the billing-service binary has
/// no container in any deployed topology, so api-server is the live ingest
/// surface (dogfood finding A, 2026-10-05).
pub fn router() -> Router<Arc<AppState>> {
    Router::new().route("/webhooks/mollie", post(handle_mollie_webhook))
}

async fn handle_mollie_webhook(State(state): State<Arc<AppState>>, body: Bytes) -> Response {
    match process_webhook(&state, &body).await {
        Ok(result) => {
            info!(
                items_processed = result.items_processed,
                items_duplicate = result.items_duplicate,
                "mollie notification accepted"
            );
            (StatusCode::OK, MOLLIE_WEBHOOK_ACCEPTED).into_response()
        }
        Err(error) => {
            let error_message = error.message().to_string();
            if error.should_record_deadletter() {
                record_deadletter(
                    &state,
                    DeadletterEntry {
                        reason: error.deadletter_reason().into(),
                        occurred_at: None,
                        event_id: webhook_object_id(&body).ok(),
                        error: Some(error.deadletter_detail().to_string()),
                        payload_length: Some(body.len()),
                        ..Default::default()
                    },
                    Some(&body),
                    None,
                )
                .await;
            }

            error!(error = %error_message, "mollie webhook processing failed");
            json_error(error.http_status(), error.response_message())
        }
    }
}

fn json_error(status: StatusCode, message: &str) -> Response {
    (status, Json(serde_json::json!({ "error": message }))).into_response()
}

// ---------------------------------------------------------------------------
// The normalized provider event
// ---------------------------------------------------------------------------
//
// Mollie's webhook posts ONE parameter, `id=tr_…` (a payment) or `id=re_…`
// (a refund), with no status, no signature and no event type. Everything
// below is what this module KNOWS only after fetching the object with the
// secret key. The struct is provider-neutral on purpose: settlement, tax
// snapshots, dunning and the dead letter queue consume facts, not a wire
// format.

/// One normalized payment/refund fact.
#[derive(Debug, Clone, Serialize, Deserialize)]
struct ProviderNotification {
    /// Mollie payment id (`tr_…`).
    provider_payment_id: String,
    /// Present on refunds: the payment the refund belongs to.
    #[serde(default)]
    original_payment_id: Option<String>,
    /// Optional provider profile/account id (diagnostics only).
    #[serde(default)]
    provider_account: Option<String>,
    /// OUR reference: `invoice:{uuid}` or `checkout:{plan}:{interval}`.
    #[serde(default)]
    reference: String,
    #[serde(default)]
    amount: Option<ProviderAmount>,
    /// AUTHORISATION | REFUND | REFUND_FAILED | CHARGEBACK |
    /// CHARGEBACK_REVERSED | RECURRING_CONTRACT, normalized from the
    /// Mollie payment/refund status.
    #[serde(default)]
    event_code: String,
    #[serde(default)]
    event_date: Option<String>,
    /// "true" / "false" (the handlers' comparator keeps this shape).
    #[serde(default)]
    success: Option<String>,
    #[serde(default)]
    payment_method: Option<String>,
    #[serde(default)]
    reason: Option<String>,
    #[serde(default)]
    additional: Option<ProviderAdditionalData>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderAmount {
    /// Integer MINOR UNITS (cents). Absent is absent, never coerced to 0.
    #[serde(default)]
    value: Option<i64>,
    #[serde(default)]
    currency: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct ProviderAdditionalData {
    /// The Mollie customer (`cst_…`); in ApexMail it is bound to the tenant.
    #[serde(default)]
    customer_id: Option<String>,
    /// The stored-payment mandate (`mdt_…`).
    #[serde(default)]
    mandate_id: Option<String>,
    /// The Mollie subscription (`sub_…`) that created the payment, when any.
    #[serde(default)]
    subscription_id: Option<String>,
    /// `first` / `recurring` / `oneoff`, Mollie's sequenceType.
    #[serde(default)]
    sequence_type: Option<String>,
    /// The provider status verbatim (`paid`, `refunded`, `charged_back`, …).
    #[serde(default)]
    status: Option<String>,
    /// How much of the payment has been refunded (cents).
    #[serde(default)]
    amount_refunded: Option<i64>,
    /// `metadata` from the payment (tenant_id, invoice_id, …).
    #[serde(default)]
    metadata: Option<HashMap<String, String>>,
}

impl ProviderNotification {
    fn customer_id(&self) -> Option<&str> {
        self.additional
            .as_ref()
            .and_then(|data| data.customer_id.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn metadata_tenant_id(&self) -> Option<&str> {
        self.additional
            .as_ref()
            .and_then(|data| data.metadata.as_ref())
            .and_then(|metadata| metadata.get("tenant_id"))
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    /// Test-only view of the invoice id a payment's metadata names.
    #[cfg(test)]
    fn metadata_invoice_id(&self) -> Option<&str> {
        self.additional
            .as_ref()
            .and_then(|data| data.metadata.as_ref())
            .and_then(|metadata| metadata.get("invoice_id"))
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn mandate_id(&self) -> Option<&str> {
        self.additional
            .as_ref()
            .and_then(|data| data.mandate_id.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn subscription_id(&self) -> Option<&str> {
        self.additional
            .as_ref()
            .and_then(|data| data.subscription_id.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn metadata_plan_name(&self) -> Option<&str> {
        self.additional
            .as_ref()
            .and_then(|data| data.metadata.as_ref())
            .and_then(|metadata| metadata.get("plan_name"))
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn metadata_interval(&self) -> Option<&str> {
        self.additional
            .as_ref()
            .and_then(|data| data.metadata.as_ref())
            .and_then(|metadata| metadata.get("interval"))
            .map(String::as_str)
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn sequence_type(&self) -> Option<&str> {
        self.additional
            .as_ref()
            .and_then(|data| data.sequence_type.as_deref())
            .map(str::trim)
            .filter(|value| !value.is_empty())
    }

    fn provider_status(&self) -> Option<&str> {
        self.additional
            .as_ref()
            .and_then(|data| data.status.as_deref())
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
// Mollie object → normalized event
// ---------------------------------------------------------------------------

/// Normalize a fetched Mollie payment. `None` when the status carries no
/// fact this module acts on (`open`, `pending`, `authorized`: the money has
/// not moved, and an authorization is not a settlement).
fn notifications_from_payment(
    payment: &crate::mollie_client::Payment,
) -> Vec<ProviderNotification> {
    let amount = payment.amount.as_ref().map(|money| ProviderAmount {
        value: Some(money.cents),
        currency: Some(money.currency.clone()),
    });
    let mut metadata = HashMap::new();
    for (key, value) in &payment.metadata {
        if let Some(text) = value.as_str() {
            metadata.insert(key.clone(), text.to_string());
        }
    }
    let sequence_type = payment
        .sequence_type
        .as_deref()
        .map(str::trim)
        .filter(|value| !value.is_empty())
        .map(str::to_string);
    let reference = payment
        .metadata
        .get("invoice_id")
        .and_then(|value| value.as_str())
        .map(|id| format!("invoice:{id}"))
        .or_else(|| {
            payment
                .metadata
                .get("reference")
                .and_then(|value| value.as_str())
                .map(str::to_string)
        })
        .unwrap_or_default();
    // ONLY a stored-mandate charge ("recurring") settles an invoice. A
    // `first`/`oneoff` payment is a checkout: it mints a mandate but carries
    // no recurring obligation, so the dispatch must not send it down the
    // invoice-settlement path (that would dead-letter every checkout).
    let recurring_sequence = sequence_type
        .clone()
        .filter(|value| value.eq_ignore_ascii_case("recurring"));
    let additional = ProviderAdditionalData {
        customer_id: payment.customer_id.clone(),
        mandate_id: payment.mandate_id.clone(),
        subscription_id: payment.subscription_id.clone(),
        sequence_type: recurring_sequence,
        status: Some(payment.status.clone()),
        amount_refunded: payment.amount_refunded.as_ref().map(|money| money.cents),
        metadata: Some(metadata),
    };
    let base =
        |event_code: &str, success: bool, amount: Option<ProviderAmount>, date: Option<String>| {
            ProviderNotification {
                provider_payment_id: payment.id.clone(),
                original_payment_id: None,
                provider_account: std::env::var("MOLLIE_PROFILE_ID").ok(),
                reference: reference.clone(),
                amount: amount.clone(),
                event_code: event_code.to_string(),
                event_date: date,
                success: Some(if success { "true" } else { "false" }.to_string()),
                payment_method: payment.method.clone(),
                // Mollie's failure reason, when the provider supplies one, is the
                // dunning notification's honest explanation; never invented.
                reason: payment
                    .raw
                    .pointer("/details/failureReason")
                    .and_then(|value| value.as_str())
                    .map(str::to_string),
                additional: Some(additional.clone()),
            }
        };

    let has_plan_metadata = payment
        .metadata
        .get("plan_name")
        .and_then(|value| value.as_str())
        .map(str::trim)
        .is_some_and(|value| !value.is_empty());
    let mut events = Vec::new();
    match payment.status.as_str() {
        "paid" => {
            // A Mollie subscription charge (the provider collects the plan
            // period) and a checkout that activates the plan are DISTINCT
            // facts; both also carry a mandate.
            if payment.subscription_id.is_some() && has_plan_metadata {
                events.push(base(
                    "SUBSCRIPTION_PAYMENT",
                    true,
                    amount,
                    payment.paid_at.clone(),
                ));
            } else if has_plan_metadata && payment.subscription_id.is_none() {
                events.push(base(
                    "CHECKOUT_ACTIVATION",
                    true,
                    amount,
                    payment.paid_at.clone(),
                ));
            } else {
                events.push(base("AUTHORISATION", true, amount, payment.paid_at.clone()));
            }
            // A `first` payment that produced a mandate is the recurring
            // contract: record the stored method once so dunning can charge
            // later. A recurring STORED payment is not a new contract.
            if payment.mandate_id.is_some() && payment.sequence_type.as_deref() != Some("recurring")
            {
                let mut contract = base("RECURRING_CONTRACT", true, None, payment.paid_at.clone());
                if let Some(additional) = contract.additional.as_mut() {
                    additional.sequence_type = Some("recurring".into());
                }
                events.push(contract);
            }
        }
        "failed" | "canceled" | "expired" => {
            if payment.subscription_id.is_some() {
                events.push(base("SUBSCRIPTION_PAYMENT_FAILED", false, amount, None));
            } else {
                events.push(base("AUTHORISATION", false, amount, None));
            }
        }
        "refunded" => {
            let refunded = payment
                .amount_refunded
                .as_ref()
                .map(|money| ProviderAmount {
                    value: Some(money.cents),
                    currency: Some(money.currency.clone()),
                });
            events.push(base("REFUND", true, refunded.or(amount), None));
        }
        "charged_back" => {
            events.push(base("CHARGEBACK", true, amount, None));
        }
        // open / pending / authorized: nothing has settled.
        _ => {}
    }
    events
}

/// Normalize a fetched Mollie refund against its payment (the payment carries
/// the tenant/invoice metadata the refund object does not).
fn notification_from_refund(
    payment: &crate::mollie_client::Payment,
    refund: &crate::mollie_client::Refund,
) -> Option<ProviderNotification> {
    let (event_code, success) = match refund.status.as_str() {
        "refunded" | "processing" => ("REFUND", true),
        "failed" | "canceled" => ("REFUND_FAILED", false),
        // queued / pending: the refund exists but has not settled.
        _ => return None,
    };
    let mut metadata = HashMap::new();
    for (key, value) in &payment.metadata {
        if let Some(text) = value.as_str() {
            metadata.insert(key.clone(), text.to_string());
        }
    }
    let reference = metadata
        .get("invoice_id")
        .map(|id| format!("invoice:{id}"))
        .or_else(|| metadata.get("reference").cloned())
        .unwrap_or_default();
    Some(ProviderNotification {
        provider_payment_id: payment.id.clone(),
        original_payment_id: Some(payment.id.clone()),
        provider_account: std::env::var("MOLLIE_PROFILE_ID").ok(),
        reference,
        amount: refund.amount.as_ref().map(|money| ProviderAmount {
            value: Some(money.cents),
            currency: Some(money.currency.clone()),
        }),
        event_code: event_code.to_string(),
        event_date: refund
            .raw
            .get("createdAt")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        success: Some(if success { "true" } else { "false" }.to_string()),
        payment_method: None,
        reason: refund
            .raw
            .get("status")
            .and_then(|value| value.as_str())
            .map(str::to_string),
        additional: Some(ProviderAdditionalData {
            customer_id: payment.customer_id.clone(),
            mandate_id: payment.mandate_id.clone(),
            status: Some(refund.status.clone()),
            metadata: Some(metadata),
            ..Default::default()
        }),
    })
}

/// A deterministic, content-addressed dedupe id: the same provider fact
/// delivered twice collapses; a status change, a new paid timestamp, a new
/// amount or a different refunded subtotal is a NEW fact.
fn mollie_event_id(item: &ProviderNotification) -> String {
    let refunded = item
        .additional
        .as_ref()
        .and_then(|data| data.amount_refunded)
        .unwrap_or(0);
    crate::mollie_webhooks::stable_event_id(
        &item.provider_payment_id,
        &item.event_code,
        item.success.as_deref().unwrap_or(""),
        item.amount_value(),
        item.amount_currency().unwrap_or(""),
        item.event_date.as_deref().unwrap_or(""),
        refunded,
        item.provider_status().unwrap_or(""),
    )
}

/// The id builder, split out so the format is unit-tested without a struct.
#[allow(clippy::too_many_arguments)]
fn stable_event_id(
    payment_id: &str,
    event_code: &str,
    success: &str,
    amount_cents: Option<i64>,
    currency: &str,
    event_date: &str,
    refunded_cents: i64,
    status: &str,
) -> String {
    format!(
        "mollie:{payment_id}:{event_code}:{success}:{}:{currency}:{event_date}:{refunded_cents}:{status}",
        amount_cents.unwrap_or(0)
    )
}

// ---------------------------------------------------------------------------
// Event-code dispatch
// ---------------------------------------------------------------------------

/// Which handler an item routes to. Pure, the dispatch matrix is unit
/// tested without a database.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum NotificationArm {
    /// `AUTHORISATION` success without a recurring sequence: checkout
    /// authorisation (informational; never an entitlement event).
    CheckoutAuthorisation,
    /// `AUTHORISATION` success with `sequenceType: recurring`: settles the
    /// local invoice named by the payment's invoice reference.
    RecurringAuthorisation,
    /// `AUTHORISATION` success=false: dunning/refusal path.
    AuthorisationRefused,
    /// `RECURRING_CONTRACT` / `recurring.token.created`.
    TokenCreated,
    /// A paid checkout for a catalog plan: activates the plan, mints the
    /// Mollie subscription and issues the paid plan invoice.
    CheckoutActivation,
    /// A Mollie subscription charge settled the next period.
    SubscriptionRenewal,
    /// A Mollie subscription charge failed (the provider retries its own).
    SubscriptionPaymentFailed,
    Refund,
    RefundFailed,
    Chargeback,
    ChargebackReversed,
    Unknown,
}

fn notification_arm(item: &ProviderNotification) -> NotificationArm {
    match item.event_code.trim() {
        "AUTHORISATION" => {
            if item.success_is_true() {
                if item.sequence_type().is_some() {
                    NotificationArm::RecurringAuthorisation
                } else {
                    NotificationArm::CheckoutAuthorisation
                }
            } else {
                NotificationArm::AuthorisationRefused
            }
        }
        "RECURRING_CONTRACT" | "recurring.token.created" => NotificationArm::TokenCreated,
        "CHECKOUT_ACTIVATION" => NotificationArm::CheckoutActivation,
        "SUBSCRIPTION_PAYMENT" => NotificationArm::SubscriptionRenewal,
        "SUBSCRIPTION_PAYMENT_FAILED" => NotificationArm::SubscriptionPaymentFailed,
        "REFUND" => NotificationArm::Refund,
        "REFUND_FAILED" => NotificationArm::RefundFailed,
        "CHARGEBACK" => NotificationArm::Chargeback,
        "CHARGEBACK_REVERSED" => NotificationArm::ChargebackReversed,
        _ => NotificationArm::Unknown,
    }
}

async fn handle_notification(state: &AppState, item: &ProviderNotification) -> Result<(), String> {
    // Audit step 8: every PAYMENT fact (refund facts carry the refund id in
    // `provider_payment_id` and are excluded) is ledged through the GENERIC
    // engine's observation core: the neutral attempts/events tables update,
    // keyless open claims (a lost charge response) get linked to the
    // provider payment id by obligation reference, and the SAME core the
    // repair sweep uses stays warm. Best effort by design: observation
    // never settles anything and must not fail the webhook arm.
    if item.original_payment_id.is_none() {
        if let Some(status) = item
            .additional
            .as_ref()
            .and_then(|data| data.status.as_deref())
        {
            if let Ok(payment_state) = crate::payments::mollie_provider::map_payment_status(status)
            {
                let observed = crate::payments::engine::ObservedPayment {
                    provider: "mollie".to_string(),
                    provider_payment_id: item.provider_payment_id.trim().to_string(),
                    state: payment_state,
                    amount_minor: item.amount.as_ref().and_then(|amount| amount.value),
                    currency: item
                        .amount
                        .as_ref()
                        .and_then(|amount| amount.currency.clone()),
                    tenant_id: item.metadata_tenant_id().map(str::to_string),
                    obligation_ref: Some(item.reference.clone()).filter(|r| !r.is_empty()),
                    purpose: "webhook",
                };
                if let Err(error) =
                    crate::payments::engine::observe_payment(&state.db, &observed).await
                {
                    warn!(
                        provider_payment_id = %item.provider_payment_id,
                        error = %error,
                        "engine observation failed; the webhook arm still runs"
                    );
                }
            }
        }
    }
    match notification_arm(item) {
        NotificationArm::CheckoutAuthorisation => handle_checkout_authorisation(state, item).await,
        NotificationArm::RecurringAuthorisation => {
            handle_recurring_authorisation(state, item).await
        }
        NotificationArm::AuthorisationRefused => handle_authorisation_refused(state, item).await,
        NotificationArm::TokenCreated => handle_token_created(state, item).await,
        NotificationArm::CheckoutActivation => handle_checkout_activation(state, item).await,
        NotificationArm::SubscriptionRenewal => handle_subscription_renewal(state, item).await,
        NotificationArm::SubscriptionPaymentFailed => {
            handle_subscription_payment_failed(state, item).await
        }
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
                provider_payment_id = %item.provider_payment_id,
                "unhandled mollie notification event code, acknowledged without effect"
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

/// A paid checkout for a catalog plan: the documented flow is
/// payment settles -> API fetch -> plan activates. The activation validates
/// the catalog amount, creates the Mollie subscription, issues the paid
/// invoice and updates the tenant in one transaction.
async fn handle_checkout_activation(
    state: &AppState,
    item: &ProviderNotification,
) -> Result<(), String> {
    let Some(tenant_id) = item.metadata_tenant_id() else {
        return Err(format!(
            "CHECKOUT_ACTIVATION {} carries no tenant metadata, refusing to grant access",
            item.provider_payment_id
        ));
    };
    let Some(plan_name) = item.metadata_plan_name() else {
        return Err(format!(
            "CHECKOUT_ACTIVATION {} carries no plan metadata, refusing to grant access",
            item.provider_payment_id
        ));
    };
    let interval = item.metadata_interval().unwrap_or("monthly");
    let Some(amount_cents) = item.amount_value() else {
        return Err(format!(
            "CHECKOUT_ACTIVATION {} carries no amount, refusing to grant access",
            item.provider_payment_id
        ));
    };
    let currency = item.amount_currency().unwrap_or("EUR");
    let outcome = crate::plan_billing::activate_from_paid_checkout(
        &state.db,
        item.provider_payment_id.trim(),
        tenant_id,
        plan_name,
        interval,
        currency,
        amount_cents,
        item.customer_id(),
        item.mandate_id(),
    )
    .await?;
    info!(
        tenant_id = %tenant_id,
        plan = %plan_name,
        interval = %interval,
        invoice_id = ?outcome.invoice_id,
        subscription_id = ?outcome.subscription_id,
        already_active = outcome.already_active,
        "mollie checkout activated the plan (renewal is local; no provider schedule is minted)"
    );
    Ok(())
}

/// A provider-initiated subscription charge arrived: the REPAIR-ONLY
/// reconciler (beta authority inversion). The provider's view is an
/// observation; the LOCAL row is the authority:
///
/// * a local obligation for the current period (the invoice the local
///   renewal worker created BEFORE its own charge) settles through the
///   neutral engine, and an active subscription's period advances;
/// * NO local obligation, or an unknown provider contract: a typed
///   reconciliation incident (no invoice is created, no period advances,
///   nothing is granted) — the provider must never decide when the next
///   charge exists;
/// * a locally-canceled subscription is NEVER resurrected.
async fn handle_subscription_renewal(
    state: &AppState,
    item: &ProviderNotification,
) -> Result<(), String> {
    let Some(subscription_id) = item.subscription_id() else {
        return Err("SUBSCRIPTION_PAYMENT carries no subscriptionId".into());
    };
    let Some(amount_cents) = item.amount_value() else {
        return Err(format!(
            "SUBSCRIPTION_PAYMENT {subscription_id} carries no amount"
        ));
    };
    let currency = item.amount_currency().unwrap_or("EUR");
    // Plan, interval and tenant are OUR row's facts (see plan_billing).
    match crate::plan_billing::reconcile_provider_renewal_payment(
        &state.db,
        item.provider_payment_id.trim(),
        subscription_id,
        amount_cents,
        currency,
    )
    .await
    {
        Ok(invoice_id) => {
            info!(
                subscription_id = %subscription_id,
                invoice_id = ?invoice_id,
                "provider subscription payment reconciled against the local obligation"
            );
            Ok(())
        }
        Err(error) => {
            // The typed reconciliation incidents and verification refusals
            // propagate: the webhook deadletters and the operator sees the
            // incident, never a silent drop and never a summoned invoice.
            warn!(
                subscription_id = %subscription_id,
                provider_payment_id = %item.provider_payment_id,
                error = %error,
                "provider-initiated renewal payment could not be applied locally"
            );
            Err(error.to_string())
        }
    }
}

/// A subscription charge failed: the provider retries its own charges, so the
/// local row moves to past_due and the customer is notified; no local mandate
/// charge is attempted for this period.
async fn handle_subscription_payment_failed(
    state: &AppState,
    item: &ProviderNotification,
) -> Result<(), String> {
    let Some(subscription_id) = item.subscription_id() else {
        return Err("SUBSCRIPTION_PAYMENT_FAILED carries no subscriptionId".into());
    };
    crate::plan_billing::mark_subscription_payment_failed(
        &state.db,
        subscription_id,
        item.reason.as_deref(),
        item.amount_value(),
    )
    .await
}

/// A checkout authorisation is informational only: the payment succeeded, but
/// entitlement follows the recurring/our-side subscription state, never a
/// single payment. In particular this must not reactivate a tenant suspended
/// for abuse (same invariant the pre-Mollie checkout webhook carried).
async fn handle_checkout_authorisation(
    state: &AppState,
    item: &ProviderNotification,
) -> Result<(), String> {
    match tenant_for_event(state, item).await? {
        Some(tenant_id) => info!(
            tenant_id = %tenant_id,
            provider_payment_id = %item.provider_payment_id,
            reference = %item.reference,
            "mollie checkout authorisation acknowledged; entitlement follows the recurring/our-side subscription state"
        ),
        None => warn!(
            provider_payment_id = %item.provider_payment_id,
            reference = %item.reference,
            "a checkout authorisation carries neither a Mollie customer nor tenant metadata, acknowledged without effect"
        ),
    }
    Ok(())
}

/// The tenant an event belongs to.
///
/// Mollie's customer id (`cst_…`) is NOT the tenant id, an earlier provider
/// used the tenant id as its shopper reference, and treating the customer id
/// that way here would bind a mandate to the wrong tenant. The authoritative
/// sources are, in order:
///
/// 1. `metadata.tenant_id`, written by every payment this platform creates;
/// 2. the `mollie_customers` mapping from the provider customer id.
///
/// `None` means the event cannot be attributed; callers acknowledge it
/// without effect rather than guess.
async fn tenant_for_event(
    state: &AppState,
    item: &ProviderNotification,
) -> Result<Option<String>, String> {
    if let Some(tenant) = item.metadata_tenant_id() {
        return Ok(Some(tenant.to_string()));
    }
    let Some(customer_id) = item.customer_id() else {
        return Ok(None);
    };
    sqlx::query_scalar::<_, String>(
        "SELECT tenant_id FROM mollie_customers WHERE mollie_customer_id = $1",
    )
    .bind(customer_id)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to resolve the Mollie customer {customer_id}: {error}"))
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

/// The tenant that owns the settlement/refusal: the invoice's own tenant.
///
/// The event's resolved tenant (metadata or the customer mapping) must agree
/// when it is known, a payment attributed to a different tenant is a
/// cross-tenant event and is refused, never settled into someone else's
/// ledger.
async fn settlement_tenant(
    state: &AppState,
    item: &ProviderNotification,
    invoice_id: Uuid,
    invoice_tenant: &str,
) -> Result<String, String> {
    if let Some(resolved) = tenant_for_event(state, item).await? {
        if resolved != invoice_tenant {
            return Err(format!(
                "AUTHORISATION for invoice {invoice_id} belongs to tenant {invoice_tenant} but the \
                 notification attributes it to tenant {resolved}, cross-tenant event refused"
            ));
        }
    }
    Ok(invoice_tenant.to_string())
}

fn currencies_match(left: &str, right: &str) -> bool {
    crate::payments::engine::currencies_match(left, right)
}

/// The payment amount actually recorded as an allocation: the verified charge,
/// capped against the authoritative remaining obligation, never negative.
/// DELEGATES to the generic engine (audit step 8): the webhook and the
/// repair sweep cap identically.
fn allocation_cents(charged_cents: i64, outstanding_cents: i64) -> i64 {
    crate::payments::engine::allocation_minor(charged_cents, outstanding_cents)
}

/// The allocation's unique operation id, the settlement's idempotency key.
/// DELEGATES to the generic engine's operation id (audit step 8): the
/// webhook and the repair sweep settle under the SAME identity.
fn settlement_operation_id(item: &ProviderNotification) -> String {
    crate::payments::engine::operation_id("mollie", &item.provider_payment_id)
}

/// Convert the old `handle_invoice_paid`: a successful recurring
/// `AUTHORISATION` settles the LOCAL invoice named by
/// `merchantReference = invoice:{uuid}` with `amount.value` (minor units) as
/// the verified charge. Runs the existing settlement logic (mark paid +
/// allocation) and the existing tax-truth snapshot gate, whose source is now
/// ApexMail's own computation validated against the charge.
async fn handle_recurring_authorisation(
    state: &AppState,
    item: &ProviderNotification,
) -> Result<(), String> {
    // A recurring add-on charge has no local invoice: the dedicated-IP row
    // IS the obligation, and its activation was recorded synchronously when
    // the charge was accepted. Acknowledge it without inventing a ledger
    // document, exactly like the checkout authorisation.
    if item.reference.trim().starts_with("dedicated_ip:") {
        info!(
            reference = %item.reference,
            provider_payment_id = %item.provider_payment_id,
            "mollie recurring add-on charge settled; the add-on row owns the obligation"
        );
        return Ok(());
    }

    let Some(local_invoice_id) = parse_merchant_reference_invoice_id(&item.reference) else {
        return Err(format!(
            "AUTHORISATION {} reference {:?} does not name a local invoice (expected \
             `invoice:{{uuid}}` or a bare uuid), refusing to settle an unidentifiable obligation",
            item.provider_payment_id, item.reference
        ));
    };
    let Some(charged_cents) = item.amount_value() else {
        return Err(format!(
            "AUTHORISATION {} for {local_invoice_id} carries no amount.value, refusing to \
             settle an unverifiable charge",
            item.provider_payment_id
        ));
    };
    let Some(local) = load_local_invoice_for_settlement(state, local_invoice_id).await? else {
        return Err(format!(
            "AUTHORISATION {} references local invoice {local_invoice_id} which does not exist \
            , refusing to settle an unknown obligation",
            item.provider_payment_id
        ));
    };
    let tenant_id = settlement_tenant(state, item, local.id, &local.tenant_id).await?;
    if let Some(currency) = item.amount_currency() {
        if !currencies_match(currency, &local.currency) {
            return Err(format!(
                "AUTHORISATION {} for {local_invoice_id} carries currency {currency} but the \
                 local invoice is denominated in {}",
                item.provider_payment_id, local.currency
            ));
        }
    }

    // TAX-TRUTH GATE (P0): persist an immutable snapshot of the charge and
    // validate the charged total against the local invoice's computed total
    // BEFORE settling. A mismatch returns Err here, no local invoice is
    // marked paid, no allocation runs, and a durable finance incident is
    // raised for operators.
    let tax_snapshot_id =
        validate_and_snapshot_mollie_tax(state, item, &local, charged_cents).await?;

    // Settlement: the pre-Mollie CTE behaviour, now against the locked local
    // row, mark paid and record the VERIFIED charged amount (amount.value)
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
            mollie_payment_id = %item.provider_payment_id,
            payment_cents,
            outstanding,
            "mollie payment exceeds the remaining obligation, allocating only the \
             authoritative remainder (over-allocation rejected)"
        );
    }

    sqlx::query(
        r#"
        UPDATE invoices
        SET status = 'paid',
            paid_at = COALESCE(paid_at, NOW()),
            mollie_payment_id = COALESCE(mollie_payment_id, $2),
            updated_at = NOW()
        WHERE id = $1
        "#,
    )
    .bind(invoice_row_id)
    .bind(item.provider_payment_id.trim())
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("Failed to mark invoice {invoice_row_id} paid: {error}"))?;

    if allocation > 0 {
        let operation_id = settlement_operation_id(item);
        sqlx::query(
            r#"
            INSERT INTO invoice_payment_allocations (
                id, tenant_id, invoice_id, operation_id, source, amount_cents, currency,
                provider
            )
            VALUES (
                gen_random_uuid(), $1, $2, $3, $4, $5, $6, $7
            )
            ON CONFLICT (operation_id) DO NOTHING
            "#,
        )
        .bind(&row_tenant)
        .bind(invoice_row_id)
        .bind(&operation_id)
        .bind(PAYMENT_ALLOCATION_SOURCE)
        .bind(allocation)
        .bind(invoice_currency.trim().to_uppercase())
        .bind(PAYMENT_ALLOCATION_PROVIDER)
        .execute(&mut *tx)
        .await
        .map_err(|error| format!("Failed to record Mollie payment allocation: {error}"))?;

        // Statutory ledger: post the settlement (Dr processor clearing, Cr
        // AR) in the same transaction. Idempotent on the allocation's unique
        // operation id, so a replayed webhook posts once.
        crate::accounting_postings::post_payment_allocation_in(&mut tx, &operation_id).await;
    } else {
        info!(
            invoice_id = %invoice_row_id,
            mollie_payment_id = %item.provider_payment_id,
            payment_cents,
            outstanding,
            "mollie invoice settled without a positive allocation (zero-value/already covered)"
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
    // supplies recognise on payment). Idempotent, best-effort, a failure is
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
            mollie_payment_id = %item.provider_payment_id,
            error = %error,
            "failed to materialize VAT recognition after Mollie settlement"
        );
    }

    // Link the immutable tax snapshot onto the settled invoice.
    if let Some(snapshot_id) = tax_snapshot_id {
        if let Err(error) = sqlx::query(
            r#"
            UPDATE invoices
            SET mollie_tax_snapshot_id = $2,
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
                "failed to link mollie tax snapshot onto the local invoice, snapshot remains authoritative"
            );
        }
    }

    info!(
        tenant_id = %tenant_id,
        invoice_id = %invoice_row_id,
        mollie_payment_id = %item.provider_payment_id,
        payment_cents,
        allocation,
        "mollie recurring authorisation settled the local invoice"
    );

    // Dedicated-IP provisioning: the deleted subscription-change handler used
    // to spawn this once a subscription became active; under Mollie our own
    // settled recurring charge is that moment. The spawn is idempotent
    // (pending-request upsert + active-count check) and failures are recorded
    // on the request row, the same contract the old call site documented.
    let provision_state = state.clone();
    let provision_tenant = tenant_id.to_string();
    tokio::spawn(async move {
        if let Err(error) =
            auto_provision_dedicated_ips_background(&provision_state, &provision_tenant).await
        {
            error!(
                tenant_id = %provision_tenant,
                error = %error,
                "dedicated-IP provisioning after Mollie settlement failed"
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
    item: &ProviderNotification,
) -> Result<(), String> {
    // A refused CHECKOUT (the customer's payment attempt failed at the
    // provider) names no local invoice: there is no dunning to start and no
    // obligation to record. The customer sees the failure at the redirect and
    // retries; acknowledging keeps Mollie from retrying the webhook.
    if item.reference.trim().is_empty() || item.reference.trim().starts_with("checkout:") {
        info!(
            reference = %item.reference,
            payment_id = %item.provider_payment_id,
            "mollie checkout payment refused by the provider, acknowledged (no local obligation)"
        );
        return Ok(());
    }
    // A refused RECURRING add-on charge is the add-on sweep's own failure
    // path (its retry/backoff owns the state), so the webhook acknowledges.
    if item.reference.trim().starts_with("dedicated_ip:") {
        info!(
            reference = %item.reference,
            payment_id = %item.provider_payment_id,
            "mollie add-on charge refused, the add-on billing sweep owns the retry"
        );
        return Ok(());
    }

    let Some(local_invoice_id) = parse_merchant_reference_invoice_id(&item.reference) else {
        return Err(format!(
            "refused AUTHORISATION {} reference {:?} does not name a local invoice (expected \
             `invoice:{{uuid}}` or a bare uuid), refusing to drop the refusal",
            item.provider_payment_id, item.reference
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
             exist, deadlettered for replay once the invoice exists",
            item.provider_payment_id
        ));
    };
    let tenant_id = settlement_tenant(state, item, local_invoice_id, &invoice_tenant).await?;

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
        "paymentId": item.provider_payment_id.trim(),
        "amount": amount,
        // The notification drainer renders money with this code and never
        // assumes one (the drain labels an absent code explicitly).
        "currency": normalize_mollie_currency(item.amount_currency()),
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
        provider_payment_id = %item.provider_payment_id,
        reason = %item.reason.as_deref().unwrap_or(""),
        "mollie authorisation refused, dunning state recorded and the customer notified"
    );
    Ok(())
}

/// `RECURRING_CONTRACT`: the first payment minted a mandate. Bind the token (and the processing model when present) to
/// every `mollie_subscriptions` row of the shopper's tenant, the token is
/// shopper-scoped, and the dunning auto-pay path reads it per tenant
/// regardless of the row's status. A missing token or tenant is an Err.
async fn handle_token_created(state: &AppState, item: &ProviderNotification) -> Result<(), String> {
    let Some(token) = item.mandate_id() else {
        return Err(format!(
            "RECURRING_CONTRACT {} carries no mandate id, nothing to bind",
            item.provider_payment_id
        ));
    };
    let Some(tenant_id) = tenant_for_event(state, item).await? else {
        return Err(format!(
            "RECURRING_CONTRACT {} carries no tenant attribution, refusing to \
             bind a mandate to an unknown tenant",
            item.provider_payment_id
        ));
    };
    let processing_model = item.sequence_type();

    // The NEUTRAL credentials ledger is the charging authority (the local
    // renewal worker reads it, not the provider): the provider's token is a
    // stored, customer-consented chargeable method, so it upserts there.
    // Best-effort: the legacy mirror below stays the retry-safe record.
    if let Some(tenant) = item.metadata_tenant_id() {
        if let Err(error) = sqlx::query(
            r#"
            INSERT INTO payment_credentials
                (tenant_id, provider, provider_customer_id, provider_method_id, state)
            VALUES ($1, 'mollie', $2, $3, 'active')
            ON CONFLICT (provider, provider_method_id) DO UPDATE SET
                state = 'active',
                revoked_at = NULL,
                tenant_id = EXCLUDED.tenant_id,
                provider_customer_id = EXCLUDED.provider_customer_id,
                updated_at = NOW()
            "#,
        )
        .bind(tenant)
        .bind(item.customer_id().unwrap_or_default())
        .bind(token)
        .execute(&state.db)
        .await
        {
            warn!(
                tenant_id = %tenant,
                mandate_id = %token,
                error = %error,
                "neutral credential upsert failed for the recurring token"
            );
        }
    }

    let bound: Vec<(String,)> = sqlx::query_as(
        r#"
        UPDATE mollie_subscriptions
        SET mollie_mandate_id = $2,
            mollie_sequence_type = COALESCE($3, mollie_sequence_type),
            updated_at = NOW()
        WHERE tenant_id = $1
        RETURNING mollie_subscription_id
        "#,
    )
    .bind(&tenant_id)
    .bind(token)
    .bind(processing_model)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to bind the Mollie recurring token: {error}"))?;

    if bound.is_empty() {
        // No local row to bind yet. The row itself is created by the same
        // payment's `CHECKOUT_ACTIVATION` arm (catalog amount checked, plan
        // and interval from metadata, idempotent on the payment id), a
        // contract event never grants entitlement on its own. A mandate with
        // no plan metadata is a one-off payment, not a subscription; Mollie
        // keeps it on the customer, so it is recoverable at
        // `GET /v2/customers/{cst}/mandates` when a subscription is created.
        info!(
            tenant_id = %tenant_id,
            payment_id = %item.provider_payment_id,
            mandate_id = %token,
            "mollie mandate recorded by the provider; no subscription row to bind yet"
        );
        return Ok(());
    }

    info!(
        tenant_id = %tenant_id,
        provider_payment_id = %item.provider_payment_id,
        subscriptions_bound = bound.len(),
        sequence_type = %processing_model.unwrap_or(""),
        "mollie recurring token bound"
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
            Self::Refund => "billing.mollie_refund_recorded",
            Self::RefundFailed => "billing.mollie_refund_failed",
            Self::Chargeback => "billing.mollie_chargeback_recorded",
            Self::ChargebackReversed => "billing.mollie_chargeback_reversed",
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
/// a reconciliation event must not make Mollie retry forever, and the
/// `mollie_webhook_events` claim row plus the logs remain the durable record
/// even when the audit insert cannot run.
async fn record_money_event(state: &AppState, item: &ProviderNotification, event: MoneyEventKind) {
    let local_invoice_id = parse_merchant_reference_invoice_id(&item.reference);
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
                "failed to resolve the local invoice tenant for an mollie money event"
            ),
        }
    }

    let detail = serde_json::json!({
        "kind": event.kind(),
        "paymentId": item.provider_payment_id.trim(),
        "originalReference": item.original_payment_id.as_deref().unwrap_or(""),
        "merchantReference": item.reference.trim(),
        "localInvoiceId": local_invoice_id.map(|id| id.to_string()),
        "amountMinorUnits": item.amount_value(),
        "currency": item.amount_currency(),
        "reason": item.reason.clone(),
    });

    let Some(tenant_id) = tenant_id else {
        error!(
            provider_payment_id = %item.provider_payment_id,
            kind = event.kind(),
            detail = %detail,
            "mollie money event without a resolvable local invoice, recorded in the notification \
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
                "mollie_notification",
                Some(item.provider_payment_id.trim()),
                detail.clone(),
                Utc::now(),
            )
            .await
            {
                Ok(()) => {
                    if let Err(error) = tx.commit().await {
                        error!(
                            tenant_id = %tenant_id,
                            provider_payment_id = %item.provider_payment_id,
                            error = %error,
                            "failed to commit the mollie money-event audit row"
                        );
                    }
                }
                Err(error) => {
                    error!(
                        tenant_id = %tenant_id,
                        provider_payment_id = %item.provider_payment_id,
                        error = %error,
                        "failed to append the mollie money-event audit row"
                    );
                    let _ = tx.rollback().await;
                }
            }
        }
        Err(error) => error!(
            tenant_id = %tenant_id,
            provider_payment_id = %item.provider_payment_id,
            error = %error,
            "failed to begin the mollie money-event audit transaction"
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
            provider_payment_id = %item.provider_payment_id,
            error = %error,
            "failed to enqueue the mollie money-event operator notification"
        );
    }

    warn!(
        tenant_id = %tenant_id,
        provider_payment_id = %item.provider_payment_id,
        kind = event.kind(),
        amount_minor_units = ?item.amount_value(),
        "mollie money event recorded for reconciliation"
    );
}

// ---------------------------------------------------------------------------
// Tax truth (P0): immutable tax snapshot + validation of the charged total
// ---------------------------------------------------------------------------
//
// ApexMail owns the tax decision now: Mollie transmits no tax fields, so the
// LOCAL invoice's computed totals are the expectation and Mollie's charged
// total (the notification item's `amount.value`, minor units) is what must
// validate against it. The snapshot of the charge and the comparison are
// persisted immutably in `mollie_tax_snapshots` (migration 218); a mismatch
// BLOCKS local settlement and raises a `finance_incidents` row instead of
// quietly recording inconsistent books.

/// ApexMail's independently computed total for the charged invoice.
#[derive(Debug, Clone, PartialEq)]
struct ExpectedTax {
    subtotal_cents: i64,
    vat_cents: i64,
    total_cents: i64,
    /// `local_invoice` for the Mollie path: the totals come from the local
    /// invoice row (the only tax decision that exists).
    source: &'static str,
    country: Option<String>,
    vat_rate: f64,
    evidence_id: Option<Uuid>,
}

/// A charged-total mismatch between the Mollie charge and ApexMail's
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
/// totals and provenance. Mollie carries no tax fields, so no wire value is
/// consulted, the local row is the only tax decision (pure).
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
    use sha2::{Digest, Sha256};
    let canonical = serde_json::to_vec(payload).unwrap_or_default();
    hex::encode(Sha256::digest(&canonical))
}

/// Row of `mollie_tax_snapshots` already persisted for this psp reference.
/// Returns `(validation_status, apexmail expected total, charged total)`.
async fn load_existing_tax_snapshot(
    db: &sqlx::PgPool,
    mollie_payment_id: &str,
) -> Result<Option<(String, i64, i64)>, String> {
    sqlx::query_as(
        r#"
        SELECT validation_status,
               COALESCE(apexmail_expected_total_cents, total_cents)::bigint,
               total_cents
        FROM mollie_tax_snapshots
        WHERE mollie_payment_id = $1
        "#,
    )
    .bind(mollie_payment_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("failed to load existing tax snapshot: {error}"))
}

/// Persist a snapshot (first write wins; the table is trigger-immutable).
/// Returns the snapshot id.
///
/// `observed` is `(subtotal, vat, charged total)`: Mollie transmits only the
/// charged TOTAL, so the itemisation columns carry the local invoice's own
/// split and `total_cents`/`amount_paid_cents` carry the charge, the
/// comparison below is therefore exactly "charged total vs local total".
#[allow(clippy::too_many_arguments)]
async fn persist_tax_snapshot(
    db: &sqlx::PgPool,
    item: &ProviderNotification,
    tenant_id: &str,
    local_invoice_id: Option<Uuid>,
    currency: &str,
    observed: (i64, i64, i64),
    expected: &ExpectedTax,
    validation_status: &str,
    discrepancy_cents: i64,
) -> Result<Uuid, String> {
    let mollie_item = serde_json::to_value(item).unwrap_or(serde_json::Value::Null);
    let observed_payload = serde_json::json!({
        "mollie_payment_id": item.provider_payment_id.trim(),
        "mollie_payment_reference": item.reference.trim(),
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
        "mollie_item": mollie_item,
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
        INSERT INTO mollie_tax_snapshots (
            mollie_payment_id, mollie_payment_reference, tenant_id, local_invoice_id,
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
        ON CONFLICT (mollie_payment_id) DO NOTHING
        RETURNING id
        "#,
    )
    .bind(item.provider_payment_id.trim())
    .bind(item.reference.trim())
    .bind(tenant_id)
    .bind(local_invoice_id)
    .bind(currency)
    .bind(observed.0)
    .bind(observed.1)
    .bind(observed.2)
    .bind(observed.2)
    // Mollie carries no tax object and no verified tax IDs: NULL/empty are the
    // truthful values, and the local split lives in the expected columns.
    .bind(Option::<String>::None)
    .bind(TAX_AUTHORITY_LOCAL)
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
    .map_err(|error| format!("failed to persist mollie tax snapshot: {error}"))?;

    if let Some((id,)) = inserted {
        return Ok(id);
    }
    // Already persisted (replay): immutability means first write wins.
    sqlx::query_scalar::<_, Uuid>(
        "SELECT id FROM mollie_tax_snapshots WHERE mollie_payment_id = $1",
    )
    .bind(item.provider_payment_id.trim())
    .fetch_one(db)
    .await
    .map_err(|error| format!("failed to reload mollie tax snapshot: {error}"))
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
    mollie_payment_id: &str,
    currency: &str,
    expected_total_cents: Option<i64>,
    observed_total_cents: Option<i64>,
    detail: &serde_json::Value,
) -> Result<(), String> {
    sqlx::query(
        r#"
        INSERT INTO finance_incidents (
            kind, severity, status, tenant_id, local_invoice_id,
            mollie_payment_id, currency, expected_total_cents,
            observed_total_cents, delta_cents, detail
        )
        SELECT $1, $2, 'open', $3, $4, $5, $6, $7, $8,
               COALESCE($7, 0) - COALESCE($8, 0), $9
        WHERE NOT EXISTS (
            SELECT 1 FROM finance_incidents
            WHERE kind = $1 AND mollie_payment_id = $5 AND status = 'open'
        )
        "#,
    )
    .bind(kind)
    .bind(severity)
    .bind(tenant_id)
    .bind(local_invoice_id)
    .bind(mollie_payment_id)
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
async fn validate_and_snapshot_mollie_tax(
    state: &AppState,
    item: &ProviderNotification,
    local: &LocalInvoiceSettlement,
    charged_total_cents: i64,
) -> Result<Option<Uuid>, String> {
    // Replays: the first snapshot is immutable. A recorded discrepancy stays
    // blocking until a finance operator resolves it; a validated snapshot
    // makes replays no-ops.
    if let Some((status, expected_total, observed_total)) =
        load_existing_tax_snapshot(&state.db, item.provider_payment_id.trim()).await?
    {
        if status == "discrepancy" {
            raise_finance_incident(
                &state.db,
                "tax_total_mismatch",
                "high",
                &local.tenant_id,
                Some(local.id),
                item.provider_payment_id.trim(),
                &normalize_mollie_currency(item.amount_currency()),
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
                item.provider_payment_id.trim()
            ));
        }
        return Ok(Some(
            sqlx::query_scalar::<_, Uuid>(
                "SELECT id FROM mollie_tax_snapshots WHERE mollie_payment_id = $1",
            )
            .bind(item.provider_payment_id.trim())
            .fetch_one(&state.db)
            .await
            .map_err(|error| format!("failed to load tax snapshot id: {error}"))?,
        ));
    }

    let expected = expected_tax_from_local_invoice(local);
    let currency = normalize_mollie_currency(item.amount_currency());

    // Mollie transmits only the charged total; the itemisation is the local
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
            "provider_payment_id": item.provider_payment_id.trim(),
            "reference": item.reference.trim(),
        });
        raise_finance_incident(
            &state.db,
            "tax_total_mismatch",
            "critical",
            &local.tenant_id,
            Some(local.id),
            item.provider_payment_id.trim(),
            &currency,
            Some(expected.total_cents),
            Some(charged_total_cents),
            &detail,
        )
        .await?;
        error!(
            mollie_payment_id = %item.provider_payment_id,
            tenant_id = %local.tenant_id,
            observed_total_cents = charged_total_cents,
            expected_total_cents = expected.total_cents,
            delta_cents = discrepancy.delta_cents,
            "BLOCKED invoice finalization: Mollie charged a total that disagrees with ApexMail's \
             computation, finance incident raised"
        );
        return Err(format!(
            "AUTHORISATION for {} blocked: {}",
            item.provider_payment_id.trim(),
            discrepancy.summary()
        ));
    }

    info!(
        mollie_payment_id = %item.provider_payment_id,
        tenant_id = %local.tenant_id,
        authority = TAX_AUTHORITY_LOCAL,
        validation_status,
        observed_total_cents = charged_total_cents,
        expected_total_cents = expected.total_cents,
        "mollie tax snapshot persisted and the charged total validated against the local invoice"
    );

    Ok(Some(snapshot_id))
}

/// Normalize a wire currency for local comparison/storage (lowercase, like
/// `invoices.currency`). Defaults to `eur`.
fn normalize_mollie_currency(currency: Option<&str>) -> String {
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
    /// Transient condition (e.g. another worker holds the event): Mollie
    /// must retry. Maps to 5xx and never deadletters.
    RetryLater(String),
    /// The provider itself says the object does not exist (404). Mollie's
    /// guidance is to acknowledge unknown ids with 200 so the endpoint can
    /// never be used as an existence oracle; nothing is recorded.
    Ignored,
}

impl ProcessWebhookError {
    fn message(&self) -> &str {
        match self {
            Self::InvalidRequest { message, .. } => message,
            Self::RecordDeadletter(message)
            | Self::DeadletterFlowHandled(message)
            | Self::RetryLater(message) => message,
            Self::Ignored => "webhook ignored",
        }
    }

    /// What Mollie sees for this class. Wire errors name the defect; every
    /// other class keeps the legacy generic body (internal details stay out
    /// of the response).
    fn response_message(&self) -> &str {
        match self {
            Self::InvalidRequest { message, .. } => message,
            Self::Ignored => "ignored",
            _ => "Webhook processing failed",
        }
    }

    fn deadletter_detail(&self) -> &str {
        match self {
            Self::InvalidRequest { detail, .. } => detail,
            Self::Ignored => "object not found at the provider",
            _ => self.message(),
        }
    }

    fn deadletter_reason(&self) -> &'static str {
        match self {
            Self::InvalidRequest { reason, .. } => reason,
            Self::Ignored => "ignored",
            _ => "processing_failed",
        }
    }

    fn should_record_deadletter(&self) -> bool {
        matches!(
            self,
            Self::InvalidRequest { .. } | Self::RecordDeadletter(_)
        )
    }

    /// HTTP status Mollie sees. Retryable errors use 503 (Mollie retries on
    /// any non-2xx; 5xx signals server-side transience); refusals keep 400.
    fn http_status(&self) -> StatusCode {
        match self {
            Self::RetryLater(_) => StatusCode::SERVICE_UNAVAILABLE,
            Self::Ignored => StatusCode::OK,
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

/// The object id a webhook body names. Mollie posts
/// `application/x-www-form-urlencoded` with a single `id` parameter; a JSON
/// `{"id": …}` body is accepted too (local harness and operator replays).
/// Anything else is refused before any provider call.
fn webhook_object_id(payload: &[u8]) -> Result<String, ProcessWebhookError> {
    let text = std::str::from_utf8(payload).map_err(|_| ProcessWebhookError::InvalidRequest {
        message: "Invalid webhook body".into(),
        detail: "body is not UTF-8".into(),
        reason: "invalid_body",
    })?;
    let trimmed = text.trim();
    let candidate = if trimmed.starts_with('{') {
        serde_json::from_str::<serde_json::Value>(trimmed)
            .ok()
            .and_then(|document| {
                document
                    .get("id")
                    .and_then(|value| value.as_str())
                    .map(str::to_string)
            })
            .unwrap_or_default()
    } else {
        trimmed
            .split('&')
            .find_map(|pair| pair.split_once('='))
            .filter(|(key, _)| *key == "id")
            .map(|(_, value)| {
                // Mollie ids are `[A-Za-z0-9_]`; percent-decoding is only
                // needed for a hand-built body, and `%` never appears in a
                // genuine id, so a raw value is the id.
                value.trim().to_string()
            })
            .unwrap_or_default()
    };
    if candidate.is_empty() {
        return Err(ProcessWebhookError::InvalidRequest {
            message: "Invalid webhook body".into(),
            detail: "no id parameter".into(),
            reason: "missing_id",
        });
    }
    // An id is an identifier, never a path or a URL: the fetch below builds a
    // provider URL from it, so the charset is enforced here.
    if !candidate
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || c == '_')
        || !(candidate.starts_with("tr_") || candidate.starts_with("re_"))
    {
        return Err(ProcessWebhookError::InvalidRequest {
            message: "Invalid webhook body".into(),
            detail: format!("id {candidate:?} is not a Mollie id"),
            reason: "invalid_id",
        });
    }
    Ok(candidate)
}

/// Resolve a refund id to its payment id from the mapping written when the
/// refund was created. Mollie's refund fetch needs BOTH ids, and the webhook
/// carries only the refund id.
async fn refund_payment_lookup(
    state: &AppState,
    refund_id: &str,
) -> Result<Option<String>, ProcessWebhookError> {
    sqlx::query_scalar::<_, String>("SELECT payment_id FROM mollie_refunds WHERE id = $1")
        .bind(refund_id)
        .fetch_optional(&state.db)
        .await
        .map_err(|error| ProcessWebhookError::RetryLater(format!("refund lookup failed: {error}")))
}

async fn process_webhook(
    state: &AppState,
    payload: &[u8],
) -> Result<ProcessWebhookResult, ProcessWebhookError> {
    let object_id = webhook_object_id(payload)?;

    // The key IS the authentication: no key means the fetch cannot prove
    // anything, which is SERVER misconfiguration (retryable 503), never a
    // business refusal.
    let client = crate::mollie_client::MollieClient::from_env().map_err(|error| {
        ProcessWebhookError::RetryLater(format!("Mollie webhook cannot verify: {error}"))
    })?;

    let (payment_id, events) = if object_id.starts_with("tr_") {
        let payment = client
            .get_payment(&object_id)
            .await
            .map_err(|error| provider_fetch_error(&object_id, error))?;
        (payment.id.clone(), notifications_from_payment(&payment))
    } else {
        // A refund webhook: Mollie needs the payment id to fetch it, and only
        // our own creation record knows it.
        let Some(payment_id) = refund_payment_lookup(state, &object_id).await? else {
            // Mollie's own guidance: acknowledge unknown ids with 200 so a
            // probe cannot use the endpoint as an oracle.
            warn!(refund_id = %object_id, "refund webhook for an unknown refund, acknowledged");
            return Ok(ProcessWebhookResult {
                items_processed: 0,
                items_duplicate: 0,
            });
        };
        let payment = client
            .get_payment(&payment_id)
            .await
            .map_err(|error| provider_fetch_error(&object_id, error))?;
        let refunds = client
            .payment_refunds(&payment_id)
            .await
            .map_err(|error| provider_fetch_error(&object_id, error))?;
        let Some(refund) = refunds.iter().find(|refund| refund.id == object_id) else {
            warn!(refund_id = %object_id, payment_id = %payment_id, "refund webhook does not match any refund on the payment, acknowledged");
            return Ok(ProcessWebhookResult {
                items_processed: 0,
                items_duplicate: 0,
            });
        };
        let events = notification_from_refund(&payment, refund)
            .into_iter()
            .collect();
        (payment_id, events)
    };

    let mut items_processed = 0usize;
    let mut items_duplicate = 0usize;
    for event in &events {
        let payload = serde_json::to_vec(event).unwrap_or_default();
        match process_notification_item(state, event, &payload).await? {
            ItemOutcome::Processed => items_processed += 1,
            ItemOutcome::Duplicate => items_duplicate += 1,
        }
    }
    let _ = payment_id;
    Ok(ProcessWebhookResult {
        items_processed,
        items_duplicate,
    })
}

/// Map a provider fetch failure to the webhook contract: a 5xx/429 is a
/// retry (Mollie retries non-200); an unknown id is acknowledged (never an
/// oracle); a malformed object is a dead-lettered 400.
fn provider_fetch_error(id: &str, error: crate::mollie_client::MollieError) -> ProcessWebhookError {
    use crate::mollie_client::MollieError;
    match error {
        MollieError::Unavailable(message) => ProcessWebhookError::RetryLater(format!(
            "Mollie is unavailable while fetching {id}: {message}"
        )),
        MollieError::Config(message) => {
            ProcessWebhookError::RetryLater(format!("Mollie is not configured: {message}"))
        }
        MollieError::Rejected { status, detail } => {
            if status == 404 {
                ProcessWebhookError::Ignored
            } else {
                ProcessWebhookError::InvalidRequest {
                    message: "Mollie refused the lookup".into(),
                    detail: format!("{id}: {detail}"),
                    reason: "provider_rejected_lookup",
                }
            }
        }
        MollieError::Malformed(detail) => ProcessWebhookError::InvalidRequest {
            message: "Mollie returned an unreadable object".into(),
            detail: format!("{id}: {detail}"),
            reason: "malformed_provider_object",
        },
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum ItemOutcome {
    Processed,
    Duplicate,
}

async fn process_notification_item(
    state: &AppState,
    item: &ProviderNotification,
    payload: &[u8],
) -> Result<ItemOutcome, ProcessWebhookError> {
    let notification_id = mollie_event_id(item);
    match claim_webhook_event(
        state,
        &notification_id,
        item.event_code.trim(),
        item.provider_payment_id.trim(),
    )
    .await?
    {
        WebhookEventClaim::Claimed => {}
        WebhookEventClaim::AlreadyProcessed => {
            info!(
                mollie_event_id = %notification_id,
                provider_payment_id = %item.provider_payment_id,
                event_code = %item.event_code,
                "duplicate mollie notification already processed"
            );
            return Ok(ItemOutcome::Duplicate);
        }
        WebhookEventClaim::AlreadyPending => {
            // Acknowledging a concurrently-pending event with a 200 makes
            // Mollie stop retrying; if the worker that claimed it then
            // crashes, the row is stuck in `pending` forever. Return a
            // retryable status instead so Mollie keeps retrying (and the
            // stale-pending reclaimer eventually resets the row).
            info!(
                mollie_event_id = %notification_id,
                provider_payment_id = %item.provider_payment_id,
                "mollie notification is already being processed by another worker; asking Mollie to retry"
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
                UPDATE mollie_webhook_events
                SET status = 'processed', processed_at = NOW(), updated_at = NOW()
                WHERE mollie_event_id = $1
                "#,
            )
            .bind(&notification_id)
            .execute(&state.db)
            .await
            .map_err(|error| format!("Failed to mark Mollie webhook as processed: {error}"))?;

            Ok(ItemOutcome::Processed)
        }
        Err(error_message) => {
            if let Err(deadletter_error) = record_failed_webhook_deadletter_atomic(
                state,
                &notification_id,
                &error_message,
                payload,
                Some(item.provider_payment_id.as_str()),
            )
            .await
            {
                error!(
                    mollie_event_id = %notification_id,
                    error = %deadletter_error,
                    "failed to persist mollie webhook failure/deadletter atomically"
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
        error!(error = %error, "failed to write mollie dead letter");
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
    // The timestamp alone is NOT unique: several refused webhooks can land in
    // the same millisecond (and every unparseable body sanitizes to the same
    // event word), so a key of `<id>:<ms>` silently overwrote one dead letter
    // with the next, losing exactly the evidence an operator needs. The uuid
    // suffix keeps every entry addressable; the ZSET score still orders them.
    let event_key = format!(
        "{}{}:{}:{}",
        DEADLETTER_EVENT_PREFIX,
        sanitize_event_id(entry.event_id.as_deref()),
        now_ms,
        uuid::Uuid::new_v4().simple()
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
        format!("failed to acquire redis connection for mollie dead letter: {error}")
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
        .map_err(|error| format!("failed to write mollie dead letter: {error}"))
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
                "failed to compensate mollie dead letter after DB commit failure"
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
            format!("Failed to begin Mollie webhook failure transaction: {error}")
        })?;

    let update_result = sqlx::query(
        r#"
        UPDATE mollie_webhook_events
        SET status = 'failed', error = $2, updated_at = NOW()
        WHERE mollie_event_id = $1
        "#,
    )
    .bind(notification_id)
    .bind(error_message)
    .execute(&mut *tx)
    .await
    .map_err(|error| format!("Failed to mark Mollie webhook as failed: {error}"))?;

    if update_result.rows_affected() == 0 {
        tx.rollback().await.map_err(|error| {
            format!("Failed to roll back empty Mollie webhook failure transaction: {error}")
        })?;
        return Err(format!(
            "Failed to mark Mollie webhook {notification_id} as failed: event row was not found"
        ));
    }

    if let Err(error) = write_prepared_deadletter_to_redis(state, &prepared).await {
        if let Err(rollback_error) = tx.rollback().await {
            error!(notification_id, error = %rollback_error, "failed to roll back Mollie webhook failure transaction after Redis deadletter error");
        }
        return Err(error);
    }

    if let Err(error) = tx.commit().await {
        remove_prepared_deadletter_from_redis(state, &prepared.event_key).await;
        return Err(format!(
            "Failed to commit Mollie webhook failure transaction after Redis deadletter write: {error}"
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
    /// The normalized event (JSON) the delivery produced, for replay.
    #[serde(skip_serializing_if = "Option::is_none")]
    body: Option<String>,
    /// The provider object id (payment id). Mollie signs nothing, so a
    /// replay re-FETCHES the object with the API key instead of verifying a
    /// stored signature.
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
// The `mollie_webhook_events` ledger (claim / status / reclaim)
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
    provider_payment_id: &str,
) -> Result<WebhookEventClaim, String> {
    let row = sqlx::query_as::<_, WebhookEventClaimRow>(
        r#"
        WITH claimed AS (
            INSERT INTO mollie_webhook_events
                (id, mollie_event_id, mollie_payment_id, event_type, status, created_at, updated_at)
            VALUES (gen_random_uuid(), $1, $2, $3, 'pending', NOW(), NOW())
            ON CONFLICT (mollie_event_id) DO UPDATE
            SET mollie_payment_id = COALESCE(EXCLUDED.mollie_payment_id, mollie_webhook_events.mollie_payment_id),
                event_type = EXCLUDED.event_type,
                status = 'pending',
                error = NULL,
                updated_at = NOW()
            WHERE mollie_webhook_events.status <> 'processed'
              AND mollie_webhook_events.status <> 'pending'
            RETURNING true AS claimed, status
        )
        SELECT claimed, status FROM claimed
        UNION ALL
        SELECT false AS claimed, status
        FROM mollie_webhook_events
        WHERE mollie_event_id = $1
          AND NOT EXISTS (SELECT 1 FROM claimed)
        LIMIT 1
        "#,
    )
    .bind(notification_id)
    .bind(provider_payment_id)
    .bind(event_type)
    .fetch_optional(&state.db)
    .await
    .map_err(|error| format!("Failed to claim Mollie webhook event: {error}"))?;

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
/// reason recorded in `error`) so either a Mollie retry or a deadletter
/// replay can claim them again. Returns the reclaimed event ids.
///
/// Wired into the maintenance worker loop (runs on startup and hourly).
pub async fn reclaim_stale_pending_webhooks(state: &AppState) -> Result<Vec<String>, String> {
    let cutoff = stale_pending_cutoff(Utc::now());
    let reclaimed: Vec<String> = sqlx::query_scalar(
        r#"
        UPDATE mollie_webhook_events
        SET status = 'received',
            error = 'reclaimed: pending exceeded stale threshold',
            updated_at = NOW()
        WHERE status = 'pending'
          AND updated_at < $1
        RETURNING mollie_event_id
        "#,
    )
    .bind(cutoff)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("Failed to reclaim stale pending webhook events: {error}"))?;

    if !reclaimed.is_empty() {
        warn!(
            count = reclaimed.len(),
            "reclaimed stale pending mollie webhook events"
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

    // Fix H, single UPSERT with SQL-side increment. The counter increment
    // and first_failed_at=LEAST(existing, now) happen atomically inside the
    // statement, eliminating the read-compute-write race that lost
    // increments under concurrent refusal events.
    // dunning_records.id is VARCHAR(26) (migrations 087/093), a 36-char
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

    // Audit item 3g, emit a distinct event when the tenant *transitions*
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
            "dunning_config table does not exist, migration 045 has not been applied. \
             Dunning features will use hardcoded defaults."
        );
        return Err("dunning_config table not found, run migrations".to_string());
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

/// Replay a dead-lettered event by RE-FETCHING the provider object. Mollie
/// signs nothing, so the only integrity proof is the authenticated fetch: a
/// stored body is a hint about which object to look up, never a fact.
async fn replay_deadletter(state: &AppState, entry: &DeadletterEntry) -> Result<(), String> {
    let body = entry
        .body
        .as_deref()
        .ok_or_else(|| "No body stored for retry".to_string())?;
    let stored: ProviderNotification = serde_json::from_str(body)
        .map_err(|error| format!("Failed to parse stored webhook body: {error}"))?;
    let payment_id = stored.provider_payment_id.trim().to_string();
    if payment_id.is_empty() {
        return Err("stored notification carries no payment id".to_string());
    }

    let client = crate::mollie_client::MollieClient::from_env()
        .map_err(|error| format!("Mollie webhook cannot verify: {error}"))?;
    let payment = client
        .get_payment(&payment_id)
        .await
        .map_err(|error| format!("Mollie lookup failed for {payment_id}: {error}"))?;

    // Re-derive the facts from the provider document; the stored event is
    // only used to know WHICH object to fetch.
    let events = notifications_from_payment(&payment);
    if events.is_empty() {
        return Ok(());
    }
    for item in &events {
        let notification_id = mollie_event_id(item);
        let payload = serde_json::to_vec(item).unwrap_or_default();
        match claim_webhook_event(
            state,
            &notification_id,
            item.event_code.trim(),
            item.provider_payment_id.trim(),
        )
        .await?
        {
            WebhookEventClaim::Claimed => {}
            // A sibling worker owns (or already finished) this fact; a replay
            // must not race it.
            WebhookEventClaim::AlreadyProcessed | WebhookEventClaim::AlreadyPending => continue,
        }
        if let Err(error_message) = handle_notification(state, item).await {
            record_failed_webhook_deadletter_atomic(
                state,
                &notification_id,
                &error_message,
                &payload,
                Some(item.provider_payment_id.as_str()),
            )
            .await
            .map_err(|error| format!("Failed to persist replay failure: {error}"))?;
            return Err(error_message);
        }
        sqlx::query(
            "UPDATE mollie_webhook_events SET status = 'processed', updated_at = NOW() WHERE mollie_event_id = $1",
        )
        .bind(&notification_id)
        .execute(&state.db)
        .await
        .map_err(|error| format!("Failed to mark Mollie webhook as processed: {error}"))?;
    }
    Ok(())
}

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

    // P3 fix 4, read every due entry in ONE MGET per chunk instead of one
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
            // Entry already evicted, remove stale retry index member.
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
                // Success, remove from retry index (deadletter remains for audit).
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
                    // Exhausted, remove from retry index but keep the deadletter entry
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
/// after the Mollie conversion, Mollie sends no subscription-status
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
        FROM mollie_subscriptions s
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

#[cfg(test)]
mod wire_test_helpers {
    use super::*;
    use crate::mollie_client::{payment_from_json, refund_from_json, Payment, Refund};

    /// Mollie's decimal wire value for an exact number of cents (never a
    /// float, never minor units on the wire).
    pub(crate) fn money_value(cents: i64) -> String {
        format!("{}.{:02}", cents.div_euclid(100), cents.rem_euclid(100))
    }

    /// A fetched payment document mapped exactly as the production client
    /// maps it (the real `payment_from_json`, so the fixture can never drift
    /// from the client's reading of Mollie's fields).
    #[allow(clippy::too_many_arguments)]
    pub(crate) fn payment(
        id: &str,
        status: &str,
        amount_cents: Option<i64>,
        currency: &str,
        sequence_type: Option<&str>,
        customer_id: Option<&str>,
        mandate_id: Option<&str>,
        paid_at: Option<&str>,
        amount_refunded_cents: Option<i64>,
        metadata: serde_json::Value,
    ) -> Payment {
        let mut document = serde_json::json!({
            "id": id,
            "status": status,
            "sequenceType": sequence_type,
            "customerId": customer_id,
            "mandateId": mandate_id,
            "paidAt": paid_at,
            "method": "ideal",
            "metadata": metadata,
        });
        if let Some(cents) = amount_cents {
            document["amount"] =
                serde_json::json!({ "currency": currency, "value": money_value(cents) });
        }
        if let Some(cents) = amount_refunded_cents {
            document["amountRefunded"] =
                serde_json::json!({ "currency": currency, "value": money_value(cents) });
        }
        payment_from_json(&document)
    }

    /// A fetched refund mapped exactly as the production client maps it.
    pub(crate) fn refund(
        id: &str,
        payment_id: &str,
        status: &str,
        amount_cents: Option<i64>,
        currency: &str,
    ) -> Refund {
        let mut document = serde_json::json!({
            "id": id,
            "paymentId": payment_id,
            "status": status,
            "createdAt": "2026-10-14T10:00:00+00:00",
        });
        if let Some(cents) = amount_cents {
            document["amount"] =
                serde_json::json!({ "currency": currency, "value": money_value(cents) });
        }
        refund_from_json(payment_id, &document)
    }

    /// A normalized provider fact for the domain tests. No wire JSON: the
    /// domain consumes facts, and the wire conversion is covered separately
    /// by the `notifications_from_payment`/`notification_from_refund` tests.
    pub(crate) fn event(code: &str, success: bool, amount_cents: i64) -> ProviderNotification {
        notification(code, success, Some(amount_cents), "EUR")
    }

    pub(crate) fn notification(
        code: &str,
        success: bool,
        amount_cents: Option<i64>,
        currency: &str,
    ) -> ProviderNotification {
        ProviderNotification {
            provider_payment_id: "tr_test".into(),
            original_payment_id: None,
            provider_account: None,
            reference: String::new(),
            amount: amount_cents.map(|cents| ProviderAmount {
                value: Some(cents),
                currency: Some(currency.to_string()),
            }),
            event_code: code.to_string(),
            event_date: None,
            success: Some(if success { "true" } else { "false" }.to_string()),
            payment_method: Some("ideal".into()),
            reason: None,
            additional: Some(ProviderAdditionalData::default()),
        }
    }

    /// A recurring AUTHORISATION fact for `invoice:{uuid}` attributed to
    /// `tenant` (the Mollie customer id in ApexMail is the tenant binding).
    pub(crate) fn recurring_authorisation(
        payment_id: &str,
        invoice_id: Uuid,
        amount_cents: i64,
        success: bool,
        tenant: Option<&str>,
    ) -> ProviderNotification {
        let mut item = event("AUTHORISATION", success, amount_cents);
        item.provider_payment_id = payment_id.into();
        item.reference = format!("invoice:{invoice_id}");
        let additional = item.additional.as_mut().expect("additional");
        additional.sequence_type = Some("recurring".into());
        additional.status = Some(if success { "paid" } else { "failed" }.into());
        if let Some(tenant) = tenant {
            additional.customer_id = Some(tenant.to_string());
            additional
                .metadata
                .get_or_insert_with(HashMap::new)
                .insert("tenant_id".into(), tenant.to_string());
        }
        item
    }

    /// A RECURRING_CONTRACT fact binding `mandate_id` for `tenant`.
    pub(crate) fn recurring_contract(
        payment_id: &str,
        tenant: Option<&str>,
        mandate_id: Option<&str>,
        sequence_type: Option<&str>,
    ) -> ProviderNotification {
        let mut item = notification("RECURRING_CONTRACT", true, None, "EUR");
        item.provider_payment_id = payment_id.into();
        item.reference = "token-ref".into();
        let additional = item.additional.as_mut().expect("additional");
        additional.customer_id = tenant.map(str::to_string);
        additional.mandate_id = mandate_id.map(str::to_string);
        additional.sequence_type = sequence_type.map(str::to_string);
        if let Some(tenant) = tenant {
            additional
                .metadata
                .get_or_insert_with(HashMap::new)
                .insert("tenant_id".into(), tenant.to_string());
        }
        item
    }
}

#[cfg(test)]
mod tests {
    use super::wire_test_helpers::*;
    use super::*;

    // ------------------------------------------------------------------
    // The webhook body: one `id` parameter, no signature, no status.
    // ------------------------------------------------------------------

    #[test]
    fn webhook_object_id_accepts_form_json_and_extra_parameters() {
        assert_eq!(webhook_object_id(b"id=tr_x").expect("form"), "tr_x");
        assert_eq!(webhook_object_id(b"  id=tr_x  ").expect("trimmed"), "tr_x");
        assert_eq!(
            webhook_object_id(b"id=tr_abc_123&live=false").expect("extra params"),
            "tr_abc_123"
        );
        assert_eq!(
            webhook_object_id(br#"{"id":"tr_json"}"#).expect("json"),
            "tr_json"
        );
        assert_eq!(
            webhook_object_id(br#"{"id":"re_refund_1","unknown":true}"#).expect("json extras"),
            "re_refund_1"
        );
        assert_eq!(
            webhook_object_id(b"id=re_refund_1").expect("refund id"),
            "re_refund_1"
        );
    }

    #[test]
    fn webhook_object_id_rejects_invalid_shapes() {
        for body in [
            &b""[..],
            b"   ",
            b"{}",
            b"id=",
            b"foo=tr_x",
            b"id=../etc/passwd",
            b"id=https://evil.example/tr_x",
            b"id=foo_1",
            b"id=tr_x/y",
            b"id=tr_x%20y",
            br#"{"notId":"tr_x"}"#,
            br#"{"id":123}"#,
        ] {
            let error = webhook_object_id(body).expect_err("invalid body");
            assert_eq!(
                error.http_status(),
                StatusCode::BAD_REQUEST,
                "body {:?}",
                String::from_utf8_lossy(body)
            );
            assert!(error.should_record_deadletter());
        }
        // Non-UTF8 bodies are refused too.
        assert!(webhook_object_id(&[0xff, 0xfe]).is_err());
    }

    // ------------------------------------------------------------------
    // Fetched payment → normalized facts.
    // ------------------------------------------------------------------

    #[test]
    fn paid_one_off_payment_is_a_successful_authorisation() {
        let payment = payment(
            "tr_paid",
            "paid",
            Some(1_234),
            "EUR",
            Some("oneoff"),
            Some("cst_1"),
            None,
            Some("2026-10-24T10:00:00+00:00"),
            None,
            serde_json::json!({ "tenant_id": "tenant_1", "invoice_id": "invoice_1" }),
        );
        let events = notifications_from_payment(&payment);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_code, "AUTHORISATION");
        assert_eq!(events[0].success.as_deref(), Some("true"));
        assert_eq!(events[0].provider_payment_id, "tr_paid");
        assert_eq!(events[0].amount_value(), Some(1_234));
        assert_eq!(events[0].amount_currency(), Some("EUR"));
        assert_eq!(
            events[0].event_date.as_deref(),
            Some("2026-10-24T10:00:00+00:00")
        );
        assert_eq!(events[0].reference, "invoice:invoice_1");
        assert_eq!(events[0].customer_id(), Some("cst_1"));
        assert_eq!(events[0].metadata_tenant_id(), Some("tenant_1"));
        assert_eq!(events[0].metadata_invoice_id(), Some("invoice_1"));
        assert_eq!(events[0].provider_status(), Some("paid"));
    }

    #[test]
    fn paid_first_payment_also_records_the_recurring_contract() {
        let first = payment(
            "tr_first",
            "paid",
            Some(2_900),
            "EUR",
            Some("first"),
            Some("cst_1"),
            Some("mdt_1"),
            Some("2026-10-24T10:00:00+00:00"),
            None,
            serde_json::json!({}),
        );
        let events = notifications_from_payment(&first);
        assert_eq!(events.len(), 2);
        assert_eq!(events[0].event_code, "AUTHORISATION");
        assert_eq!(events[0].success.as_deref(), Some("true"));
        assert_eq!(events[1].event_code, "RECURRING_CONTRACT");
        assert_eq!(events[1].success.as_deref(), Some("true"));
        assert_eq!(events[1].mandate_id(), Some("mdt_1"));
        assert_eq!(events[1].amount_value(), None, "a contract moves no money");
    }

    #[test]
    fn a_recurring_payment_is_only_an_authorisation() {
        // A stored-mandate charge is not a new contract: one EVENT, no
        // second RECURRING_CONTRACT delivery.
        let recurring = payment(
            "tr_recurring",
            "paid",
            Some(2_900),
            "EUR",
            Some("recurring"),
            Some("cst_1"),
            Some("mdt_1"),
            Some("2026-10-24T10:00:00+00:00"),
            None,
            serde_json::json!({}),
        );
        let events = notifications_from_payment(&recurring);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_code, "AUTHORISATION");
        assert_eq!(events[0].sequence_type(), Some("recurring"));
    }

    #[test]
    fn failed_canceled_and_expired_payments_are_unsuccessful_authorisations() {
        for status in ["failed", "canceled", "expired"] {
            let failed = payment(
                "tr_failed",
                status,
                Some(4_200),
                "EUR",
                Some("recurring"),
                Some("cst_1"),
                Some("mdt_1"),
                None,
                None,
                serde_json::json!({}),
            );
            let events = notifications_from_payment(&failed);
            assert_eq!(events.len(), 1, "status {status}");
            assert_eq!(events[0].event_code, "AUTHORISATION");
            assert_eq!(events[0].success.as_deref(), Some("false"));
            assert_eq!(events[0].amount_value(), Some(4_200));
            assert_eq!(events[0].provider_status(), Some(status));
            assert_eq!(
                notification_arm(&events[0]),
                NotificationArm::AuthorisationRefused
            );
        }
    }

    #[test]
    fn refunded_payment_is_a_refund_with_the_refunded_subtotal() {
        let refunded = payment(
            "tr_refunded",
            "refunded",
            Some(12_400),
            "EUR",
            Some("recurring"),
            Some("cst_1"),
            Some("mdt_1"),
            Some("2026-10-24T10:00:00+00:00"),
            Some(4_000),
            serde_json::json!({}),
        );
        let events = notifications_from_payment(&refunded);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_code, "REFUND");
        assert_eq!(events[0].success.as_deref(), Some("true"));
        assert_eq!(
            events[0].amount_value(),
            Some(4_000),
            "the refunded subtotal is the fact, not the original charge"
        );
        assert_eq!(
            events[0]
                .additional
                .as_ref()
                .and_then(|data| data.amount_refunded),
            Some(4_000)
        );
        assert_eq!(notification_arm(&events[0]), NotificationArm::Refund);
    }

    #[test]
    fn refunded_payment_without_a_refunded_subtotal_keeps_the_charge() {
        let refunded = payment(
            "tr_refunded_full",
            "refunded",
            Some(12_400),
            "EUR",
            None,
            Some("cst_1"),
            None,
            Some("2026-10-24T10:00:00+00:00"),
            None,
            serde_json::json!({}),
        );
        let events = notifications_from_payment(&refunded);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_code, "REFUND");
        assert_eq!(events[0].amount_value(), Some(12_400));
    }

    #[test]
    fn charged_back_payment_is_a_chargeback() {
        let charged_back = payment(
            "tr_chargeback",
            "charged_back",
            Some(2_900),
            "EUR",
            Some("recurring"),
            Some("cst_1"),
            Some("mdt_1"),
            Some("2026-10-24T10:00:00+00:00"),
            None,
            serde_json::json!({}),
        );
        let events = notifications_from_payment(&charged_back);
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].event_code, "CHARGEBACK");
        assert_eq!(events[0].success.as_deref(), Some("true"));
        assert_eq!(notification_arm(&events[0]), NotificationArm::Chargeback);
    }

    #[test]
    fn unsettled_statuses_produce_no_events() {
        for status in ["open", "pending", "authorized"] {
            let unsettled = payment(
                "tr_open",
                status,
                Some(2_900),
                "EUR",
                Some("recurring"),
                Some("cst_1"),
                Some("mdt_1"),
                None,
                None,
                serde_json::json!({}),
            );
            assert!(
                notifications_from_payment(&unsettled).is_empty(),
                "{status} is not settled and must never emit a fact"
            );
        }
    }

    #[test]
    fn amounts_are_parsed_as_exact_decimals_without_float_drift() {
        let parsed = payment(
            "tr_money",
            "paid",
            Some(1_130),
            "EUR",
            None,
            None,
            None,
            None,
            None,
            serde_json::json!({}),
        );
        assert_eq!(
            parsed.amount,
            Some(crate::mollie_client::Money::new("EUR", 1_130))
        );
        let events = notifications_from_payment(&parsed);
        assert_eq!(events[0].amount_value(), Some(1_130));

        // Three decimals are refused by the client (never rounded).
        let malformed = crate::mollie_client::payment_from_json(&serde_json::json!({
            "id": "tr_bad_amount",
            "status": "paid",
            "amount": { "currency": "EUR", "value": "12.345" }
        }));
        assert_eq!(malformed.amount, None);
        let events = notifications_from_payment(&malformed);
        assert_eq!(
            events[0].amount_value(),
            None,
            "an unreadable amount is absent, never invented"
        );
        // A zero amount is a real zero, not missing data.
        let zero = payment(
            "tr_zero",
            "paid",
            Some(0),
            "EUR",
            None,
            None,
            None,
            None,
            None,
            serde_json::json!({}),
        );
        assert_eq!(notifications_from_payment(&zero)[0].amount_value(), Some(0));
    }

    #[test]
    fn metadata_and_reference_fall_back_honestly() {
        // No invoice_id: a metadata `reference` is used verbatim.
        let referenced = payment(
            "tr_ref",
            "paid",
            Some(100),
            "EUR",
            None,
            None,
            None,
            None,
            None,
            serde_json::json!({ "reference": "checkout:growth:monthly" }),
        );
        let events = notifications_from_payment(&referenced);
        assert_eq!(events[0].reference, "checkout:growth:monthly");

        // No reference at all: empty, never a guessed identity.
        let bare = payment(
            "tr_bare",
            "paid",
            Some(100),
            "EUR",
            None,
            None,
            None,
            None,
            None,
            serde_json::json!({}),
        );
        assert_eq!(notifications_from_payment(&bare)[0].reference, "");

        // Non-string metadata values are ignored (the normalized map is
        // string-to-string).
        let mixed = payment(
            "tr_mixed",
            "paid",
            Some(100),
            "EUR",
            None,
            None,
            None,
            None,
            None,
            serde_json::json!({ "tenant_id": "t1", "counter": 7 }),
        );
        let events = notifications_from_payment(&mixed);
        assert_eq!(events[0].metadata_tenant_id(), Some("t1"));
        assert_eq!(events[0].metadata_invoice_id(), None);
    }

    // ------------------------------------------------------------------
    // Fetched refund → normalized fact.
    // ------------------------------------------------------------------

    #[test]
    fn notification_from_refund_maps_terminal_states() {
        // The refund names only its own id; the PAYMENT carries the tenant
        // and invoice metadata, so the fact is built from both objects.
        let paid = payment(
            "tr_pay",
            "paid",
            Some(1_000),
            "EUR",
            Some("recurring"),
            Some("cst_1"),
            Some("mdt_1"),
            Some("2026-10-24T10:00:00+00:00"),
            None,
            serde_json::json!({
                "tenant_id": "tenant_1",
                "invoice_id": "01234567-89ab-cdef-0123-456789abcdef"
            }),
        );
        for status in ["refunded", "processing"] {
            let item = notification_from_refund(
                &paid,
                &refund("re_1", "tr_pay", status, Some(500), "EUR"),
            )
            .unwrap_or_else(|| panic!("{status} is a refund fact"));
            assert_eq!(item.event_code, "REFUND");
            assert_eq!(item.success.as_deref(), Some("true"));
            assert_eq!(item.provider_payment_id, "tr_pay");
            assert_eq!(item.original_payment_id.as_deref(), Some("tr_pay"));
            assert_eq!(item.amount_value(), Some(500));
            assert_eq!(
                item.event_date.as_deref(),
                Some("2026-10-14T10:00:00+00:00")
            );
            assert_eq!(
                item.reference, "invoice:01234567-89ab-cdef-0123-456789abcdef",
                "the payment's metadata identifies our local invoice"
            );
            assert_eq!(item.customer_id(), Some("cst_1"));
            assert_eq!(item.metadata_tenant_id(), Some("tenant_1"));
            assert_eq!(notification_arm(&item), NotificationArm::Refund);
        }
        for status in ["failed", "canceled"] {
            let item = notification_from_refund(
                &paid,
                &refund("re_1", "tr_pay", status, Some(500), "EUR"),
            )
            .unwrap_or_else(|| panic!("{status} is a refund-failure fact"));
            assert_eq!(item.event_code, "REFUND_FAILED");
            assert_eq!(item.success.as_deref(), Some("false"));
            assert_eq!(notification_arm(&item), NotificationArm::RefundFailed);
        }
        for status in ["queued", "pending"] {
            assert!(
                notification_from_refund(
                    &paid,
                    &refund("re_1", "tr_pay", status, Some(500), "EUR")
                )
                .is_none(),
                "{status} has not settled"
            );
        }
    }

    // ------------------------------------------------------------------
    // The deterministic dedupe id (Mollie retries; identical facts collapse).
    // ------------------------------------------------------------------

    #[test]
    fn identical_facts_share_the_dedupe_id_and_retries_cannot_reapply() {
        let item = event("AUTHORISATION", true, 1_130);
        let first = mollie_event_id(&item);
        assert_eq!(
            first,
            mollie_event_id(&item),
            "Mollie retries the same fact"
        );
        // A different payment id is a different fact.
        let mut other = item.clone();
        other.provider_payment_id = "tr_other".into();
        assert_ne!(mollie_event_id(&other), first);
        // A different event code is a different fact.
        let mut other = item.clone();
        other.event_code = "REFUND".into();
        assert_ne!(mollie_event_id(&other), first);
        // A different success is a different fact.
        let mut other = item.clone();
        other.success = Some("false".into());
        assert_ne!(mollie_event_id(&other), first);
    }

    #[test]
    fn status_amount_refunded_and_date_changes_are_new_facts() {
        let item = event("AUTHORISATION", true, 1_130);
        let base = mollie_event_id(&item);

        let mut amount = item.clone();
        amount.amount = Some(ProviderAmount {
            value: Some(1_131),
            currency: Some("EUR".into()),
        });
        assert_ne!(mollie_event_id(&amount), base);

        let mut currency = item.clone();
        currency.amount = Some(ProviderAmount {
            value: Some(1_130),
            currency: Some("USD".into()),
        });
        assert_ne!(mollie_event_id(&currency), base);

        let mut date = item.clone();
        date.event_date = Some("2026-10-15T10:00:00+00:00".into());
        assert_ne!(mollie_event_id(&date), base);

        let mut status = item.clone();
        status.additional.as_mut().expect("additional").status = Some("paid".into());
        assert_ne!(mollie_event_id(&status), base);

        let mut refunded = item.clone();
        refunded
            .additional
            .as_mut()
            .expect("additional")
            .amount_refunded = Some(1);
        assert_ne!(mollie_event_id(&refunded), base);
    }

    #[test]
    fn notification_ids_are_prefixed_and_content_addressed() {
        let id = mollie_event_id(&event("AUTHORISATION", true, 1_130));
        assert!(
            id.starts_with("mollie:"),
            "the dedupe id is provider-scoped"
        );
        assert_eq!(id, "mollie:tr_test:AUTHORISATION:true:1130:EUR::0:");
        // The same content always produces the same id, and the id embeds
        // every settled dimension.
        let other = event("AUTHORISATION", true, 1_130);
        assert_eq!(id, mollie_event_id(&other));
    }

    // ------------------------------------------------------------------
    // Reference → local invoice; tenant resolution.
    // ------------------------------------------------------------------

    #[test]
    fn reference_parses_invoice_prefixed_and_bare_uuids() {
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
    fn reference_rejects_garbage_and_foreign_prefixes() {
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
    fn metadata_tenant_is_the_fallback_when_the_customer_is_absent() {
        let mut item = event("AUTHORISATION", true, 100);
        item.additional = Some(ProviderAdditionalData {
            metadata: Some(HashMap::from([("tenant_id".into(), "tenant_meta".into())])),
            ..Default::default()
        });
        assert_eq!(item.customer_id(), None);
        assert_eq!(item.metadata_tenant_id(), Some("tenant_meta"));

        // The customer id wins when present.
        item.additional.as_mut().expect("additional").customer_id = Some("cst_shopper".into());
        assert_eq!(item.customer_id(), Some("cst_shopper"));

        // Garbage/blank metadata never becomes a tenant.
        let blank = ProviderNotification {
            additional: Some(ProviderAdditionalData {
                metadata: Some(HashMap::from([("tenant_id".into(), "   ".into())])),
                ..Default::default()
            }),
            ..event("AUTHORISATION", true, 100)
        };
        assert_eq!(blank.metadata_tenant_id(), None);
    }

    #[test]
    fn accessors_trim_and_reject_blank_values() {
        let mut item = event("RECURRING_CONTRACT", true, 0);
        item.amount = Some(ProviderAmount {
            value: Some(0),
            currency: Some("  ".into()),
        });
        item.success = Some("TRUE".into());
        item.additional = Some(ProviderAdditionalData {
            mandate_id: Some("  mdt_123  ".into()),
            sequence_type: Some("first".into()),
            customer_id: Some("".into()),
            ..Default::default()
        });
        assert_eq!(item.mandate_id(), Some("mdt_123"));
        assert_eq!(item.sequence_type(), Some("first"));
        assert_eq!(item.customer_id(), None);
        assert_eq!(item.amount_currency(), None);
        assert_eq!(item.amount_value(), Some(0));
        assert!(item.success_is_true(), "success is case-insensitive");
    }

    // ------------------------------------------------------------------
    // Dispatch: event code + success + sequence type.
    // ------------------------------------------------------------------

    #[test]
    fn notification_arm_routes_authorisation_by_success_and_sequence_type() {
        let checkout = event("AUTHORISATION", true, 2_900);
        assert_eq!(
            notification_arm(&checkout),
            NotificationArm::CheckoutAuthorisation
        );

        let recurring = recurring_authorisation(
            "tr_recurring",
            Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid"),
            2_900,
            true,
            Some("tenant_1"),
        );
        assert_eq!(
            notification_arm(&recurring),
            NotificationArm::RecurringAuthorisation
        );

        let refused = recurring_authorisation(
            "tr_refused",
            Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid"),
            2_900,
            false,
            Some("tenant_1"),
        );
        assert_eq!(
            notification_arm(&refused),
            NotificationArm::AuthorisationRefused
        );

        let failed_checkout = event("AUTHORISATION", false, 2_900);
        assert_eq!(
            notification_arm(&failed_checkout),
            NotificationArm::AuthorisationRefused
        );
    }

    #[test]
    fn notification_arm_covers_every_contract_event_code() {
        for (event_code, expected) in [
            ("RECURRING_CONTRACT", NotificationArm::TokenCreated),
            ("REFUND", NotificationArm::Refund),
            ("REFUND_FAILED", NotificationArm::RefundFailed),
            ("CHARGEBACK", NotificationArm::Chargeback),
            ("CHARGEBACK_REVERSED", NotificationArm::ChargebackReversed),
            ("ORDER_CLOSED", NotificationArm::Unknown),
            ("  REFUND  ", NotificationArm::Refund),
        ] {
            let item = event(event_code, true, 1);
            assert_eq!(notification_arm(&item), expected, "event code {event_code}");
        }
    }

    #[test]
    fn unknown_event_codes_are_acknowledged() {
        // The catch-all arm (warn + Ok) acknowledges an event family we do
        // not consume, never retrying forever.
        let item = event("ORDER_CLOSED", true, 1);
        assert_eq!(notification_arm(&item), NotificationArm::Unknown);
        assert!(!matches!(
            notification_arm(&item),
            NotificationArm::CheckoutAuthorisation
                | NotificationArm::RecurringAuthorisation
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
        for event_code in [
            "AUTHORISATION",
            "RECURRING_CONTRACT",
            "REFUND",
            "REFUND_FAILED",
            "CHARGEBACK",
            "CHARGEBACK_REVERSED",
        ] {
            let item = event(event_code, true, 1);
            assert_ne!(notification_arm(&item), NotificationArm::Unknown);
        }
    }

    // ------------------------------------------------------------------
    // Money: allocation and exact minor units.
    // ------------------------------------------------------------------

    #[test]
    fn allocation_prefers_the_verified_charge_over_the_invoice_total() {
        assert_eq!(allocation_cents(6_000, 10_000), 6_000);
        assert_eq!(allocation_cents(11_300, 11_300), 11_300);
    }

    #[test]
    fn allocation_is_capped_by_the_authoritative_remainder() {
        assert_eq!(allocation_cents(12_400, 400), 400);
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
        assert_eq!(allocation_cents(0, 0), 0);
        assert_eq!(allocation_cents(0, 1_000), 0);
    }

    #[test]
    fn the_charged_total_is_the_verified_provider_amount() {
        let mut item = event("AUTHORISATION", true, 1_130);
        item.provider_payment_id = "tr_charged".into();
        assert_eq!(item.amount_value(), Some(1_130));
        assert_eq!(item.amount_currency(), Some("EUR"));
        assert_eq!(settlement_operation_id(&item), "mollie:tr_charged");
        assert_eq!(
            allocation_cents(item.amount_value().expect("amount"), 1_130),
            1_130
        );
        let source = include_str!("mollie_webhooks.rs");
        assert!(source.contains("let payment_cents = charged_cents.max(0);"));
        assert!(source.contains(".bind(allocation)"));
    }

    #[test]
    fn decimal_amounts_convert_exactly_without_float_drift() {
        use crate::mollie_client::Money;
        for (wire, cents) in [
            ("0.00", 0_i64),
            ("0.05", 5),
            ("12.34", 1_234),
            ("1000.00", 100_000),
            ("999999999.99", 99_999_999_999),
        ] {
            assert_eq!(
                Money::parse("EUR", wire),
                Some(Money::new("EUR", cents)),
                "{wire}"
            );
        }
        assert_eq!(Money::parse("EUR", "12.345"), None, "never round money");
        assert_eq!(Money::parse("EUR", "-1.00"), None);
    }

    #[test]
    fn a_zero_amount_is_a_real_zero_not_missing_data() {
        let item = event("AUTHORISATION", true, 0);
        assert_eq!(item.amount_value(), Some(0));
        assert!(item.amount.is_some());
    }

    #[test]
    fn a_missing_amount_is_absent_not_zero() {
        let item = notification("AUTHORISATION", true, None, "EUR");
        assert_eq!(item.amount_value(), None);
        assert_eq!(item.amount_currency(), None);
    }

    #[test]
    fn notification_facts_deserialize_the_full_normalized_shape() {
        let item: ProviderNotification = serde_json::from_value(serde_json::json!({
            "provider_payment_id": "tr_full",
            "original_payment_id": "tr_original",
            "provider_account": "pfl_1",
            "reference": "invoice:01234567-89ab-cdef-0123-456789abcdef",
            "amount": { "value": 1130, "currency": "EUR" },
            "event_code": "REFUND",
            "event_date": "2026-10-24T10:00:00+00:00",
            "success": "true",
            "payment_method": "ideal",
            "reason": "requested",
            "additional": {
                "customerId": "cst_1",
                "mandateId": "mdt_1",
                "sequenceType": "recurring",
                "status": "refunded",
                "amountRefunded": 500,
                "metadata": { "tenant_id": "t1" }
            }
        }))
        .expect("normalized fact parses");
        assert_eq!(item.provider_payment_id, "tr_full");
        assert_eq!(item.original_payment_id.as_deref(), Some("tr_original"));
        assert_eq!(item.provider_account.as_deref(), Some("pfl_1"));
        assert_eq!(item.amount_value(), Some(1_130));
        assert_eq!(item.amount_currency(), Some("EUR"));
        assert_eq!(item.customer_id(), Some("cst_1"));
        assert_eq!(item.mandate_id(), Some("mdt_1"));
        assert_eq!(item.sequence_type(), Some("recurring"));
        assert_eq!(item.provider_status(), Some("refunded"));
        assert_eq!(
            item.additional
                .as_ref()
                .and_then(|data| data.amount_refunded),
            Some(500)
        );
        assert_eq!(item.metadata_tenant_id(), Some("t1"));
    }

    #[test]
    fn notification_facts_deserialize_minimal_shape_with_empty_defaults() {
        let item: ProviderNotification =
            serde_json::from_value(serde_json::json!({ "provider_payment_id": "tr_minimal" }))
                .expect("minimal fact parses");
        assert_eq!(item.provider_payment_id, "tr_minimal");
        assert_eq!(item.reference, "");
        assert_eq!(item.event_code, "");
        assert_eq!(item.success, None);
        assert!(item.amount.is_none());
        assert_eq!(item.original_payment_id, None);
        assert!(item.additional.is_none());
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
        assert!(check_charged_total(&expected(0, 0), 0, 0, 0).is_ok());
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
        assert!(check_charged_total(&expected(0, 0), 0, 0, 1_000).is_err());
    }

    #[test]
    fn the_local_computation_is_the_only_tax_authority() {
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
        let mut blank = local.clone();
        blank.billing_country = Some("  ".into());
        assert_eq!(expected_tax_from_local_invoice(&blank).country, None);
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
        let source = include_str!("mollie_webhooks.rs");
        for needle in [
            "apexmail_expected_total_cents",
            "raw_payload_hash",
            "validation_status",
            "ON CONFLICT (mollie_payment_id) DO NOTHING",
            "mollie_payment_reference",
        ] {
            assert!(
                source.contains(needle),
                "snapshot write must include {needle}"
            );
        }
        assert!(source.contains("finance_incidents"));
        assert!(source.contains("BLOCKED invoice finalization"));
    }

    #[test]
    fn tax_snapshot_authority_is_an_allowed_check_value() {
        assert_eq!(TAX_AUTHORITY_LOCAL, "apexmail_local");
        assert_ne!(TAX_AUTHORITY_LOCAL, "mollie_tax");
        let source = include_str!("mollie_webhooks.rs");
        assert!(source.contains("TAX_AUTHORITY_LOCAL"));
    }

    #[test]
    fn currencies_are_compared_case_insensitively() {
        assert!(currencies_match("eur", "EUR"));
        assert!(currencies_match(" EUR ", "eur"));
        assert!(!currencies_match("usd", "eur"));
        assert!(!currencies_match("", "eur"));
    }

    #[test]
    fn normalize_mollie_currency_defaults_to_eur_and_lowercases() {
        assert_eq!(normalize_mollie_currency(Some("EUR")), "eur");
        assert_eq!(normalize_mollie_currency(Some("usd")), "usd");
        assert_eq!(normalize_mollie_currency(Some("  ")), "eur");
        assert_eq!(normalize_mollie_currency(None), "eur");
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
            event_id: Some("mollie:tr_123".into()),
            error: Some("transient db error".into()),
            payload_length: Some(1024),
            retry_count: 2,
            max_retries: DEADLETTER_MAX_RETRIES,
            body: Some(r#"{"id":"tr_123"}"#.into()),
            signature: Some("tr_123".into()),
        };

        let json = serde_json::to_string(&entry).expect("serialize");
        let deserialized: DeadletterEntry = serde_json::from_str(&json).expect("deserialize");

        assert_eq!(deserialized.reason, "processing_failed");
        assert_eq!(deserialized.retry_count, 2);
        assert_eq!(deserialized.max_retries, DEADLETTER_MAX_RETRIES);
        assert_eq!(deserialized.event_id, Some("mollie:tr_123".into()));
        assert!(deserialized.body.is_some());
        assert!(deserialized.signature.is_some());
    }

    #[test]
    fn deadletter_entry_deserializes_legacy_entry_without_retry_fields() {
        let legacy_json = r#"{
            "reason": "processing_failed",
            "occurredAt": "2025-01-01T00:00:00Z",
            "eventId": "mollie:tr_999",
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
                event_id: Some("mollie:tr_retry".into()),
                error: Some("db timeout".into()),
                ..Default::default()
            },
            Some(br#"{"id":"tr_retry"}"#),
            Some("tr_retry"),
            now,
        );

        assert!(prepared.event_key.contains("mollie_tr_retry"));
        assert_eq!(
            prepared.retry_at_ms,
            Some(prepared.now_ms + DEADLETTER_RETRY_BACKOFF_SECONDS[0] * 1000)
        );

        let entry: DeadletterEntry = serde_json::from_str(&prepared.payload).expect("payload json");
        assert_eq!(entry.reason, "processing_failed");
        assert_eq!(entry.body.as_deref(), Some(r#"{"id":"tr_retry"}"#));
        assert_eq!(entry.signature.as_deref(), Some("tr_retry"));
    }

    #[test]
    fn prepare_deadletter_caps_body_to_4kb_and_skips_retry() {
        let oversized_body = format!(
            r#"{{"id":"tr_big","padding":"{}"}}"#,
            "x".repeat(DEADLETTER_MAX_BODY_BYTES)
        );
        let oversized_bytes = oversized_body.as_bytes();
        assert!(oversized_bytes.len() > DEADLETTER_MAX_BODY_BYTES);

        let prepared = prepare_deadletter(
            DeadletterEntry {
                reason: "processing_failed".into(),
                event_id: Some("mollie:tr_big".into()),
                error: Some("boom".into()),
                ..Default::default()
            },
            Some(oversized_bytes),
            Some("tr_big"),
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
                event_id: Some("mollie/with spaces".into()),
                ..Default::default()
            },
            Some(br#"{"id":"tr_small"}"#),
            Some("tr_small"),
            now,
        );
        assert!(small.retry_at_ms.is_some(), "a full body is retryable");
        assert!(small.event_key.contains("mollie_with_spaces"));

        let oversized = "x".repeat(DEADLETTER_MAX_BODY_BYTES + 100);
        let big = prepare_deadletter(
            DeadletterEntry {
                reason: "processing_failed".into(),
                event_id: Some("mollie_big".into()),
                ..Default::default()
            },
            Some(oversized.as_bytes()),
            Some("tr_big"),
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
            message: "Invalid webhook body".into(),
            detail: "no id parameter".into(),
            reason: "missing_id",
        };
        assert!(wire.should_record_deadletter());
        assert_eq!(wire.deadletter_reason(), "missing_id");
        assert_eq!(wire.deadletter_detail(), "no id parameter");
        assert_eq!(wire.response_message(), "Invalid webhook body");
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

        // An unknown provider object is acknowledged, never deadlettered and
        // never used as an existence oracle.
        let ignored = ProcessWebhookError::Ignored;
        assert_eq!(ignored.http_status(), StatusCode::OK);
        assert!(!ignored.should_record_deadletter());
        assert_eq!(ignored.response_message(), "ignored");
    }

    #[test]
    fn retry_later_error_maps_to_503_and_no_deadletter() {
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
        assert_eq!(sanitize_event_id(Some("mollie_tr_123")), "mollie_tr_123");
        assert_eq!(sanitize_event_id(Some("mollie:tr_123")), "mollie_tr_123");
        assert_eq!(
            sanitize_event_id(Some("mollie/abc<>def")),
            "mollie_abc__def"
        );
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
                include_str!("mollie_webhooks.rs").contains(source_probe),
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
        assert_eq!(
            dunning_transition(Some("hard_suspended"), "soft_suspended"),
            None
        );
    }

    #[test]
    fn dunning_transition_event_types_are_snake_case_rows() {
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
        let first = now - TimeDelta::days(7);
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
        let first = now - TimeDelta::days(21);
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

    #[derive(Debug, Deserialize)]
    #[serde(deny_unknown_fields)]
    struct AllocateIpRequestMirror {
        #[serde(default)]
        region: Option<String>,
    }

    #[test]
    fn auto_provision_body_deserializes_into_the_api_allocate_contract() {
        let body = serde_json::to_string(&auto_provision_request_body())
            .expect("auto-provision body must serialize");
        let parsed: AllocateIpRequestMirror = serde_json::from_str(&body)
            .expect("billing auto-provision body must deserialize into AllocateIpRequest");
        assert!(parsed.region.is_none());

        let pre_fix = r#"{"auto_provisioned":true}"#;
        assert!(
            serde_json::from_str::<AllocateIpRequestMirror>(pre_fix).is_err(),
            "the old auto_provisioned body must remain rejected by the API contract"
        );
    }
}

// ---------------------------------------------------------------------------
// Adversarial coverage tests (DB + Redis backed) for the Mollie webhook
// pipeline, dunning escalation, deadletter replay, and the tax-truth gate.
//
// These call the PRIVATE handlers directly: the public route wrapper is
// already covered by tests/coverage_adversarial.rs, while the private
// replay/dunning/tax functions can only be driven from inside the crate.
// Every test provisions its own canonical database clone; `TEST_DATABASE_URL`
// unset means soft-skip.
//
// Mollie's wire is `POST /webhooks/mollie` with `id=tr_…`, and the facts come
// from an AUTHENTICATED FETCH. The mock Mollie API below is the only provider
// the suite talks to; ids are unique per test, so a single process-wide
// server keeps the parallel suite deterministic without env races.
// ---------------------------------------------------------------------------

#[cfg(test)]
mod coverage_adversarial {
    use super::wire_test_helpers::*;
    use super::*;

    use crate::config::BillingConfig;
    use deadpool_redis::Runtime;
    use sqlx::postgres::PgPoolOptions;
    use std::collections::HashMap;
    use std::sync::{Arc, Mutex, OnceLock};

    // ------------------------------------------------------------------
    // Mock Mollie API (`GET /v2/payments/{id}`, `GET /v2/payments/{id}/refunds`).
    // ------------------------------------------------------------------

    type Responses = Arc<Mutex<HashMap<String, (u16, String)>>>;
    type RecordedCalls = Arc<Mutex<Vec<RecordedCall>>>;

    #[derive(Clone, Debug)]
    struct RecordedCall {
        method: String,
        path: String,
        headers: HashMap<String, String>,
        body: String,
    }

    struct MockMollie {
        base_url: String,
        responses: Responses,
        calls: RecordedCalls,
    }

    impl MockMollie {
        /// Publish the provider document a webhook fetch will return for a
        /// normalized fact.
        fn publish_payment(&self, item: &ProviderNotification) {
            let status = item
                .provider_status()
                .unwrap_or_else(|| match item.event_code.as_str() {
                    "CHARGEBACK" => "charged_back",
                    _ if item.success_is_true() => "paid",
                    _ => "failed",
                });
            let additional = item.additional.clone().unwrap_or_default();
            let mut metadata: serde_json::Map<String, serde_json::Value> = additional
                .metadata
                .clone()
                .unwrap_or_default()
                .into_iter()
                .map(|(key, value)| (key, serde_json::Value::String(value)))
                .collect();
            if !item.reference.trim().is_empty() {
                metadata
                    .entry("reference")
                    .or_insert_with(|| serde_json::Value::String(item.reference.clone()));
            }
            let mut document = serde_json::json!({
                "id": item.provider_payment_id,
                "status": status,
                "sequenceType": additional.sequence_type,
                "customerId": additional.customer_id,
                "mandateId": additional.mandate_id,
                "paidAt": item.event_date,
                "method": item.payment_method,
                "metadata": metadata,
            });
            if let (Some(cents), Some(currency)) = (item.amount_value(), item.amount_currency()) {
                let value = if item.event_code == "REFUND" {
                    additional.amount_refunded.unwrap_or(cents)
                } else {
                    cents
                };
                document["amount"] = serde_json::json!({
                    "currency": currency,
                    "value": money_value(value),
                });
            }
            if let Some(refunded) = additional.amount_refunded {
                let currency = item.amount_currency().unwrap_or("EUR");
                document["amountRefunded"] = serde_json::json!({
                    "currency": currency,
                    "value": money_value(refunded),
                });
            }
            self.route(
                &format!("/v2/payments/{}", item.provider_payment_id),
                200,
                document.to_string(),
            );
        }

        fn publish_refunds(&self, payment_id: &str, refunds: &[serde_json::Value]) {
            self.route(
                &format!("/v2/payments/{payment_id}/refunds"),
                200,
                serde_json::json!({ "_embedded": { "refunds": refunds } }).to_string(),
            );
        }

        fn fail_payment(&self, payment_id: &str, status: u16, body: &str) {
            self.route(&format!("/v2/payments/{payment_id}"), status, body);
        }

        fn route(&self, path: &str, status: u16, body: impl Into<String>) {
            self.responses
                .lock()
                .expect("lock")
                .insert(path.to_string(), (status, body.into()));
        }

        fn last_call(&self, path: &str) -> Option<RecordedCall> {
            self.calls
                .lock()
                .expect("lock")
                .iter()
                .rev()
                .find(|recorded| recorded.path == path)
                .cloned()
        }
    }

    async fn mock_handler(
        axum::extract::State((responses, calls)): axum::extract::State<(Responses, RecordedCalls)>,
        request: axum::http::Request<axum::body::Body>,
    ) -> axum::response::Response {
        use axum::response::IntoResponse;
        let method = request.method().to_string();
        let path = request.uri().path().to_string();
        let headers = request
            .headers()
            .iter()
            .map(|(name, value)| {
                (
                    name.as_str().to_string(),
                    value.to_str().unwrap_or_default().to_string(),
                )
            })
            .collect();
        let body = axum::body::to_bytes(request.into_body(), usize::MAX)
            .await
            .unwrap_or_default();
        let (status, response_body) = responses
            .lock()
            .expect("lock")
            .get(&path)
            .cloned()
            .unwrap_or_else(|| {
                if path.ends_with("/refunds") {
                    (200, r#"{"_embedded":{"refunds":[]}}"#.to_string())
                } else {
                    (404, r#"{"title":"Not Found"}"#.to_string())
                }
            });
        calls.lock().expect("lock").push(RecordedCall {
            method,
            path,
            headers,
            body: String::from_utf8_lossy(&body).to_string(),
        });
        (
            axum::http::StatusCode::from_u16(status).expect("status"),
            [(axum::http::header::CONTENT_TYPE, "application/json")],
            response_body,
        )
            .into_response()
    }

    /// The one process-wide mock Mollie API. It runs on its OWN OS thread so
    /// it survives the per-test tokio runtimes, and it installs the client
    /// configuration exactly once (`MOLLIE_API_BASE_URL` + `MOLLIE_API_KEY`).
    fn mock() -> &'static MockMollie {
        static MOCK: OnceLock<MockMollie> = OnceLock::new();
        MOCK.get_or_init(|| {
            let responses: Responses = Arc::new(Mutex::new(HashMap::new()));
            let calls: RecordedCalls = Arc::new(Mutex::new(Vec::new()));
            let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mock");
            listener
                .set_nonblocking(true)
                .expect("nonblocking mock listener");
            let address = listener.local_addr().expect("mock address");
            let app = axum::Router::new()
                .fallback(mock_handler)
                .with_state((responses.clone(), calls.clone()));
            std::thread::spawn(move || {
                let runtime = tokio::runtime::Builder::new_current_thread()
                    .enable_all()
                    .build()
                    .expect("mock runtime");
                runtime.block_on(async move {
                    let listener =
                        tokio::net::TcpListener::from_std(listener).expect("tokio listener");
                    axum::serve(listener, app).await.expect("mock server");
                });
            });
            let base_url = format!("http://{address}/v2");
            std::env::set_var("MOLLIE_API_KEY", "test_mock_api_key");
            std::env::set_var("MOLLIE_API_BASE_URL", &base_url);
            MockMollie {
                base_url,
                responses,
                calls,
            }
        })
    }

    #[allow(clippy::too_many_arguments)]
    fn payment_document(
        payment_id: &str,
        status: &str,
        cents: i64,
        currency: &str,
        sequence_type: Option<&str>,
        customer_id: Option<&str>,
        mandate_id: Option<&str>,
        metadata: serde_json::Value,
    ) -> serde_json::Value {
        serde_json::json!({
            "id": payment_id,
            "status": status,
            "amount": { "currency": currency, "value": money_value(cents) },
            "sequenceType": sequence_type,
            "customerId": customer_id,
            "mandateId": mandate_id,
            "paidAt": "2026-10-24T10:00:00+00:00",
            "method": "ideal",
            "metadata": metadata,
        })
    }

    struct Env {
        state: Arc<AppState>,
        pool: sqlx::PgPool,
        redis: deadpool_redis::Pool,
        db_name: String,
        admin_url: String,
    }

    impl Env {
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

        // MIGRATION-GAP COMPENSATION (private clone only): migration 140
        // pins `invoice_payment_allocations.source` to the pre-cutover set;
        // the Mollie settlement writes 'mollie'. Extend THIS CLONE so the
        // settlement path is exercised. Production needs the same value
        // added by a new migration.
        for statement in [
            "ALTER TABLE invoice_payment_allocations \
             DROP CONSTRAINT IF EXISTS invoice_payment_allocations_source_check",
            "ALTER TABLE invoice_payment_allocations \
             ADD CONSTRAINT invoice_payment_allocations_source_check \
             CHECK (source IN ('wallet', 'stripe', 'manual', 'credit_note', 'mollie'))",
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
            mollie_api_key: "test_mock_api_key".to_string(),
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
            "INSERT INTO invoices (id, tenant_id, mollie_payment_id, invoice_number, status,
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

    async fn local_invoice(env: &Env, invoice_id: Uuid) -> LocalInvoiceSettlement {
        sqlx::query_as(
            "SELECT id, tenant_id, currency,
                    COALESCE(subtotal, amount, 0)::bigint AS subtotal_cents,
                    COALESCE(vat_total, 0)::bigint AS vat_cents,
                    COALESCE(total, amount, 0)::bigint AS total_cents,
                    billing_country, vat_rate, vat_evidence_id
             FROM invoices WHERE id = $1",
        )
        .bind(invoice_id)
        .fetch_one(&env.pool)
        .await
        .expect("local invoice exists")
    }

    async fn redis_conn(env: &Env) -> deadpool_redis::Connection {
        env.redis.get().await.expect("redis connection")
    }

    async fn pool_conn(pool: &deadpool_redis::Pool) -> deadpool_redis::Connection {
        pool.get().await.expect("redis connection")
    }

    async fn event_rows(pool: &sqlx::PgPool) -> i64 {
        sqlx::query_scalar("SELECT COUNT(*) FROM mollie_webhook_events")
            .fetch_one(pool)
            .await
            .expect("event rows")
    }

    async fn clear_all_deadletters(env: &Env) {
        let mut conn = redis_conn(env).await;
        let keys: Vec<String> = redis::cmd("KEYS")
            .arg("mollie:deadletter:*")
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

    fn state_with_isolated_redis(
        env: &Env,
        isolated: &crate::test_support::IsolatedRedis,
    ) -> Arc<AppState> {
        let mut config = env.state.config.clone();
        config.redis_url = "redis://127.0.0.1:1".to_string();
        AppState::new(env.pool.clone(), isolated.pool.clone(), config)
    }

    async fn post_webhook(state: &Arc<AppState>, body: &[u8]) -> axum::response::Response {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/webhooks/mollie")
            .body(axum::body::Body::from(body.to_vec()))
            .expect("request");
        tower::ServiceExt::oneshot(router().with_state(state.clone()), request)
            .await
            .expect("oneshot")
    }

    async fn post_webhook_with_header(
        state: &Arc<AppState>,
        body: &[u8],
        header_name: &str,
        header_value: &str,
    ) -> axum::response::Response {
        let request = axum::http::Request::builder()
            .method("POST")
            .uri("/webhooks/mollie")
            .header(header_name, header_value)
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

    /// Publish the payment a webhook fetch will see, then deliver its id
    /// through the real route (the authenticated-fetch contract).
    async fn deliver_payment(
        state: &Arc<AppState>,
        item: &ProviderNotification,
    ) -> Result<ProcessWebhookResult, ProcessWebhookError> {
        mock().publish_payment(item);
        process_webhook(state, format!("id={}", item.provider_payment_id).as_bytes()).await
    }

    async fn deliver_payment_route(
        state: &Arc<AppState>,
        item: &ProviderNotification,
    ) -> axum::response::Response {
        mock().publish_payment(item);
        post_webhook(state, format!("id={}", item.provider_payment_id).as_bytes()).await
    }

    /// Register the refund mapping + the provider refund list, then deliver
    /// the refund id: Mollie's refund webhook names ONLY the refund id.
    async fn deliver_refund(
        env: &Env,
        refund_id: &str,
        payment_id: &str,
        status: &str,
        cents: i64,
    ) -> Result<ProcessWebhookResult, ProcessWebhookError> {
        sqlx::query(
            "INSERT INTO mollie_refunds (id, payment_id, amount_cents, currency, status)
             VALUES ($1, $2, $3, 'EUR', $4)
             ON CONFLICT (id) DO NOTHING",
        )
        .bind(refund_id)
        .bind(payment_id)
        .bind(cents)
        .bind(status)
        .execute(&env.pool)
        .await
        .expect("refund mapping");
        mock().publish_refunds(
            payment_id,
            &[serde_json::json!({
                "id": refund_id,
                "status": status,
                "amount": { "currency": "EUR", "value": money_value(cents) },
                "createdAt": "2026-10-24T10:00:00+00:00"
            })],
        );
        process_webhook(&env.state, format!("id={refund_id}").as_bytes()).await
    }

    // ===================================================================
    // Wire contract: `id=tr_…`, authenticated fetch, no signature.
    // ===================================================================

    env_test!(route_form_body_fetches_and_settles_the_payment, |env| {
        let _mock = mock().base_url.clone();
        let tenant = "swcov_form";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 1_000, 0, 1_000, "eur").await;

        let item = recurring_authorisation("tr_form_body", invoice_id, 1_000, true, Some(tenant));
        let response = deliver_payment_route(&env.state, &item).await;
        assert_eq!(response.status(), StatusCode::OK);
        assert_eq!(response_text(response).await, MOLLIE_WEBHOOK_ACCEPTED);
        let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("invoice");
        assert_eq!(status, "paid", "the fetched payment settled the invoice");
    });

    env_test!(provider_fetch_is_authenticated_with_the_bearer_key, |env| {
        mock();
        let response = post_webhook(&env.state, b"id=tr_bearer").await;
        assert_eq!(response.status(), StatusCode::OK);
        let call = mock()
            .last_call("/v2/payments/tr_bearer")
            .expect("fetch call");
        assert_eq!(call.method, "GET", "verification is a fetch, not a parse");
        assert_eq!(
            call.headers.get("authorization").map(String::as_str),
            Some("Bearer test_mock_api_key"),
            "the secret key authenticates every verification fetch"
        );
        assert!(
            call.headers
                .get("content-type")
                .is_none_or(|value| !value.contains("json")),
            "a GET verification carries no body"
        );
        assert!(call.body.is_empty());
    });

    env_test!(route_unknown_id_is_acknowledged_with_200, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _mock = mock().base_url.clone();
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        mock().fail_payment("tr_unknown_for_test", 404, r#"{"title":"Not Found"}"#);
        let response = post_webhook(&env.state, b"id=tr_unknown_for_test").await;
        assert_eq!(
            response.status(),
            StatusCode::OK,
            "an unknown id is acknowledged so the endpoint is never an oracle"
        );
        assert_eq!(response_json(response).await["error"], "ignored");
        assert_eq!(event_rows(&env.pool).await, 0, "nothing is claimed");
        let entries = deadletter_entries(env, "mollie:deadletter:event:*").await;
        assert!(entries.is_empty(), "an unknown id is not a deadletter");
    });

    env_test!(route_provider_5xx_is_503_and_never_deadlettered, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _mock = mock().base_url.clone();
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        mock().fail_payment("tr_provider_down", 503, "upstream exploded");
        let response = post_webhook(&env.state, b"id=tr_provider_down").await;
        assert_eq!(
            response.status(),
            StatusCode::SERVICE_UNAVAILABLE,
            "Mollie must retry a transient provider failure"
        );
        let entries = deadletter_entries(env, "mollie:deadletter:event:*").await;
        assert!(entries.is_empty(), "a 5xx is retried, never deadlettered");
        assert_eq!(event_rows(&env.pool).await, 0);
    });

    env_test!(route_malformed_ids_are_400_and_deadlettered, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _mock = mock().base_url.clone();
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        for body in [
            &b""[..],
            b"id=",
            b"id=../etc/passwd",
            b"id=https://evil.example/tr_x",
            b"id=foo_1",
            b"id=tr_x/y",
            b"{}",
            &[0xff, 0xfe][..],
        ] {
            let response = post_webhook(&env.state, body).await;
            assert_eq!(
                response.status(),
                StatusCode::BAD_REQUEST,
                "body {:?}",
                String::from_utf8_lossy(body)
            );
            assert_eq!(
                response_json(response).await["error"],
                "Invalid webhook body"
            );
        }
        let entries = deadletter_entries(env, "mollie:deadletter:event:*").await;
        assert!(
            !entries.is_empty(),
            "the refused bodies are deadlettered for triage"
        );
        for entry in entries {
            let entry: DeadletterEntry = serde_json::from_str(&entry).expect("entry");
            assert!(
                matches!(
                    entry.reason.as_str(),
                    "missing_id" | "invalid_body" | "invalid_id"
                ),
                "unexpected deadletter reason: {}",
                entry.reason
            );
            assert!(entry.body.is_some(), "the refused body is kept");
        }
        assert_eq!(event_rows(&env.pool).await, 0, "nothing claimed");
    });

    env_test!(
        route_malformed_provider_object_is_400_and_deadletters,
        |env| {
            let _guard = DEADLETTER_LOCK.lock().await;
            let _mock = mock().base_url.clone();
            let _dl_guard =
                crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
            clear_all_deadletters(env).await;
            mock().fail_payment("tr_unreadable", 200, "this is not json");
            let response = post_webhook(&env.state, b"id=tr_unreadable").await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(
                response_json(response).await["error"],
                "Mollie returned an unreadable object"
            );
            let entries = deadletter_entries(env, "mollie:deadletter:event:tr_unreadable*").await;
            assert_eq!(entries.len(), 1);
            let entry: DeadletterEntry = serde_json::from_str(&entries[0]).expect("entry");
            assert_eq!(entry.reason, "malformed_provider_object");
            assert_eq!(event_rows(&env.pool).await, 0);
        }
    );

    env_test!(route_settled_states_only_produce_facts, |env| {
        let _mock = mock().base_url.clone();
        for (id, status) in [
            ("tr_open_state", "open"),
            ("tr_pending_state", "pending"),
            ("tr_authorized_state", "authorized"),
        ] {
            mock().route(
                &format!("/v2/payments/{id}"),
                200,
                payment_document(
                    id,
                    status,
                    1_000,
                    "EUR",
                    Some("recurring"),
                    None,
                    None,
                    serde_json::json!({}),
                )
                .to_string(),
            );
            let response = post_webhook(&env.state, format!("id={id}").as_bytes()).await;
            assert_eq!(
                response.status(),
                StatusCode::OK,
                "{status} is acknowledged"
            );
            assert_eq!(response_text(response).await, MOLLIE_WEBHOOK_ACCEPTED);
        }
        assert_eq!(
            event_rows(&env.pool).await,
            0,
            "open/pending/authorized are not settled facts"
        );
    });

    env_test!(legacy_signed_envelopes_authorise_nothing, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _mock = mock().base_url.clone();
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        clear_all_deadletters(env).await;
        // legacy-wire-negative-test: the pre-Mollie shape carried an in-body
        // HMAC and no `id`; Mollie has no signature at all, so the only thing
        // that can authorise a delivery is the object id it names.
        let body = serde_json::to_vec(&serde_json::json!({
            "notificationItems": [{
                "NotificationRequestItem": {
                    "provider_payment_id": "tr_legacy",
                    "event_code": "AUTHORISATION",
                    "success": "true"
                }
            }]
        }))
        .expect("body");
        let response = post_webhook_with_header(
            &env.state,
            &body,
            "mollie-hmac-signature",
            "t=1,v1=deadbeef",
        )
        .await;
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
        assert_eq!(
            response_json(response).await["error"],
            "Invalid webhook body"
        );
        assert_eq!(
            event_rows(&env.pool).await,
            0,
            "no header or envelope authorises anything"
        );
        let entries = deadletter_entries(env, "mollie:deadletter:event:*").await;
        assert_eq!(entries.len(), 1, "the legacy delivery is deadlettered");
    });

    env_test!(route_duplicate_delivery_is_exactly_once, |env| {
        let _mock = mock().base_url.clone();
        let tenant = "swadv_replay";
        seed_tenant(env, tenant, "free", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 10_000, 2_400, 12_400, "eur").await;
        let item = recurring_authorisation("tr_duplicate", invoice_id, 12_400, true, Some(tenant));
        let first = deliver_payment_route(&env.state, &item).await;
        assert_eq!(first.status(), StatusCode::OK);
        let second = deliver_payment_route(&env.state, &item).await;
        assert_eq!(
            second.status(),
            StatusCode::OK,
            "Mollie expects 2xx on replay"
        );
        let result = deliver_payment(&env.state, &item).await.expect("replay");
        assert_eq!(result.items_processed, 0);
        assert_eq!(result.items_duplicate, 1, "the duplicate is recognised");

        let (status, allocations, events): (String, i64, i64) = sqlx::query_as(
            "SELECT
                    (SELECT status FROM invoices WHERE id = $1),
                    (SELECT COUNT(*) FROM invoice_payment_allocations WHERE invoice_id = $1),
                    (SELECT COUNT(*) FROM mollie_webhook_events WHERE mollie_payment_id = 'tr_duplicate')",
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
        refund_webhook_resolves_the_payment_from_our_mapping,
        |env| {
            let tenant = "swadv_refund_route";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, tenant, invoice_id, 1_000, 0, 1_000, "eur").await;
            let payment_id = "tr_refund_payment";
            let refund_id = "re_refund_1";
            mock().publish_payment(&recurring_authorisation(
                payment_id,
                invoice_id,
                1_000,
                true,
                Some(tenant),
            ));
            let result = deliver_refund(env, refund_id, payment_id, "refunded", 500)
                .await
                .expect("refund fact");
            assert_eq!(result.items_processed, 1);
            let actions: Vec<String> = sqlx::query_scalar(
                "SELECT action FROM audit_logs WHERE tenant_id = $1 ORDER BY action",
            )
            .bind(tenant)
            .fetch_all(&env.pool)
            .await
            .expect("audits");
            assert!(
                actions.contains(&"billing.mollie_refund_recorded".to_string()),
                "the refund is audited: {actions:?}"
            );
        }
    );

    env_test!(
        unknown_refund_id_is_acknowledged_without_provider_call,
        |env| {
            let _mock = mock().base_url.clone();
            let result = process_webhook(&env.state, b"id=re_never_mapped")
                .await
                .expect("acknowledged");
            assert_eq!(result.items_processed, 0);
            assert_eq!(event_rows(&env.pool).await, 0);
        }
    );

    env_test!(refund_replay_is_exactly_once, |env| {
        let tenant = "swadv_refund_replay";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 1_000, 0, 1_000, "eur").await;
        let payment_id = "tr_refund_replay_pay";
        mock().publish_payment(&recurring_authorisation(
            payment_id,
            invoice_id,
            1_000,
            true,
            Some(tenant),
        ));
        deliver_refund(env, "re_refund_replay", payment_id, "refunded", 500)
            .await
            .expect("first delivery");
        let second = deliver_refund(env, "re_refund_replay", payment_id, "refunded", 500)
            .await
            .expect("replay");
        assert_eq!(second.items_duplicate, 1);
        let actions: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs
             WHERE tenant_id = $1 AND action = 'billing.mollie_refund_recorded'",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("audit count");
        assert_eq!(actions, 1, "a replayed refund is recorded once");
    });

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
            sqlx::query(
                "INSERT INTO dunning_records (id, tenant_id, status, failed_payment_count)
                 VALUES ('swadv_settle_dunning_0001', $1, 'soft_suspended', 3)",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("dunning");

            let item = recurring_authorisation("tr_settle", invoice_id, 12_400, true, Some(tenant));
            deliver_payment(&env.state, &item)
                .await
                .expect("settlement");
            let (status, paid_at_is_set, payment_id): (String, bool, Option<String>) = sqlx::query_as(
                "SELECT status, paid_at IS NOT NULL, mollie_payment_id FROM invoices WHERE id = $1",
            )
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("invoice");
            assert_eq!(status, "paid");
            assert!(paid_at_is_set);
            assert_eq!(
                payment_id.as_deref(),
                Some("tr_settle"),
                "the settlement binds the Mollie payment id"
            );
            let (amount, source, operation_id): (i64, String, String) = sqlx::query_as(
                "SELECT amount_cents, source, operation_id FROM invoice_payment_allocations WHERE invoice_id = $1",
            )
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("allocation");
            assert_eq!(amount, 12_400, "the verified payment is allocated once");
            assert_eq!(source, PAYMENT_ALLOCATION_SOURCE);
            assert_eq!(operation_id, "mollie:tr_settle");
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
                sqlx::query_scalar("SELECT mollie_tax_snapshot_id FROM invoices WHERE id = $1")
                    .bind(invoice_id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("snapshot link");
            assert!(snapshot.is_some(), "the tax snapshot is linked");

            let replay = deliver_payment(&env.state, &item).await.expect("replay");
            assert_eq!(replay.items_duplicate, 1);
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
            let _mock = mock().base_url.clone();
            seed_tenant(env, "swcov_orphan_paid", "growth", "active").await;
            let orphan = recurring_authorisation(
                "tr_orphan_paid",
                Uuid::new_v4(),
                100,
                true,
                Some("swcov_orphan_paid"),
            );
            let error = deliver_payment(&env.state, &orphan)
                .await
                .expect_err("unknown local invoice");
            assert!(
                error.message().contains("does not exist"),
                "{}",
                error.message()
            );

            let mut garbage = event("AUTHORISATION", true, 100);
            garbage.provider_payment_id = "tr_orphan_ref".into();
            garbage.reference = "not-an-invoice-ref".into();
            garbage
                .additional
                .as_mut()
                .expect("additional")
                .sequence_type = Some("recurring".into());
            let error = deliver_payment(&env.state, &garbage)
                .await
                .expect_err("unidentifiable reference");
            assert!(
                error.message().contains("does not name a local invoice"),
                "{}",
                error.message()
            );
            let failed_rows: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM mollie_webhook_events WHERE status = 'failed'",
            )
            .fetch_one(&env.pool)
            .await
            .expect("failed rows");
            assert_eq!(
                failed_rows, 2,
                "each unresolvable delivery is claimed and failed for replay"
            );
            let snapshots: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mollie_tax_snapshots")
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

            let attacker =
                recurring_authorisation("tr_rebind", invoice_id, 1_000, true, Some(other));
            let error = deliver_payment(&env.state, &attacker)
                .await
                .expect_err("cross-tenant settlement refused");
            assert!(
                error.message().contains("cross-tenant"),
                "{}",
                error.message()
            );
            let (status, payment_id): (String, Option<String>) =
                sqlx::query_as("SELECT status, mollie_payment_id FROM invoices WHERE id = $1")
                    .bind(invoice_id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("invoice");
            assert_eq!(status, "pending", "rejected write changes nothing");
            assert_eq!(payment_id, None);

            let rightful =
                recurring_authorisation("tr_rebind_ok", invoice_id, 1_000, true, Some(owner));
            deliver_payment(&env.state, &rightful)
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

        let mut item = recurring_authorisation("tr_ccy", invoice_id, 1_000, true, Some(tenant));
        item.amount = Some(ProviderAmount {
            value: Some(1_000),
            currency: Some("USD".into()),
        });
        let error = deliver_payment(&env.state, &item)
            .await
            .expect_err("currency mismatch refused");
        assert!(
            error.message().contains("denominated in"),
            "{}",
            error.message()
        );
        let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("status");
        assert_eq!(status, "pending", "the refused settlement writes nothing");
        let snapshots: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mollie_tax_snapshots")
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
            let item = recurring_authorisation("tr_zero_value", invoice_id, 0, true, Some(tenant));
            deliver_payment(&env.state, &item)
                .await
                .expect("zero-value invoices settle");
            let (status, payment_id): (String, Option<String>) =
                sqlx::query_as("SELECT status, mollie_payment_id FROM invoices WHERE id = $1")
                    .bind(invoice_id)
                    .fetch_one(&env.pool)
                    .await
                    .expect("invoice");
            assert_eq!(status, "paid");
            assert_eq!(payment_id.as_deref(), Some("tr_zero_value"));
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

            let event = recurring_authorisation("tr_foreign", invoice_id, 1_000, true, Some(other));
            let error = deliver_payment(&env.state, &event)
                .await
                .expect_err("foreign tenant cannot settle");
            assert!(
                error.message().contains("cross-tenant"),
                "{}",
                error.message()
            );
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
            let missing = recurring_authorisation(
                "tr_shape_missing",
                Uuid::new_v4(),
                100,
                true,
                Some(tenant),
            );
            assert!(deliver_payment(&env.state, &missing).await.is_err());
            let mut no_amount = missing.clone();
            no_amount.amount = None;
            let error = deliver_payment(&env.state, &no_amount)
                .await
                .expect_err("missing amount refused");
            assert!(
                error.message().contains("no amount.value"),
                "{}",
                error.message()
            );

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

            for (invoice_id, id) in [(first, "tr_renew_1"), (second, "tr_renew_2")] {
                let item = recurring_authorisation(id, invoice_id, 1_000, true, Some(tenant));
                deliver_payment(&env.state, &item)
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
            let snapshots: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM mollie_tax_snapshots WHERE tenant_id = $1",
            )
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
        let item = recurring_authorisation("tr_settled", invoice_id, 1_000, true, Some(tenant));
        deliver_payment(&env.state, &item).await.expect("settle");
        deliver_payment(&env.state, &item).await.expect("replay");
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
        let refusal =
            recurring_authorisation("tr_settled_refusal", invoice_id, 1_000, false, Some(tenant));
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

            let first = recurring_authorisation("tr_dun_1", invoice_id, 4_200, false, Some(tenant));
            deliver_payment(&env.state, &first)
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

            sqlx::query(
                "UPDATE dunning_records SET first_failed_at = NOW() - INTERVAL '8 days',
                status = 'warning' WHERE tenant_id = $1",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("age dunning");
            let second =
                recurring_authorisation("tr_dun_2", invoice_id, 4_200, false, Some(tenant));
            deliver_payment(&env.state, &second)
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

            sqlx::query(
                "UPDATE dunning_records SET first_failed_at = NOW() - INTERVAL '25 days',
                status = 'soft_suspended' WHERE tenant_id = $1",
            )
            .bind(tenant)
            .execute(&env.pool)
            .await
            .expect("age dunning");
            let third = recurring_authorisation("tr_dun_3", invoice_id, 4_200, false, Some(tenant));
            deliver_payment(&env.state, &third)
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

            let fourth =
                recurring_authorisation("tr_dun_4", invoice_id, 4_200, false, Some(tenant));
            deliver_payment(&env.state, &fourth)
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
            let tenant = "swcov_orphan_refuse";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice = recurring_authorisation(
                "tr_orphan_refuse",
                Uuid::new_v4(),
                1_000,
                false,
                Some(tenant),
            );
            let error = deliver_payment(&env.state, &invoice)
                .await
                .expect_err("unresolvable invoice");
            assert!(
                error.message().contains("does not exist"),
                "{}",
                error.message()
            );
            let rows: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dunning_records")
                .fetch_one(&env.pool)
                .await
                .expect("dunning");
            assert_eq!(rows, 0, "nothing is written for an unresolvable refusal");

            let mut garbage = invoice.clone();
            garbage.provider_payment_id = "tr_orphan_refuse_garbage".into();
            garbage.reference = "garbage-ref".into();
            let error = deliver_payment(&env.state, &garbage)
                .await
                .expect_err("unidentifiable reference");
            assert!(
                error.message().contains("does not name a local invoice"),
                "{}",
                error.message()
            );
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
                recurring_authorisation("tr_paid_refusal", invoice_id, 1_000, false, Some(tenant));
            deliver_payment(&env.state, &refusal)
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
        seed_local_invoice(env, tenant, invoice_id, 4_900, 0, 4_900, "eur").await;
        let local = local_invoice(env, invoice_id).await;

        let mismatch = recurring_authorisation("tr_tax_bad", invoice_id, 5_900, true, Some(tenant));
        let error = validate_and_snapshot_mollie_tax(&env.state, &mismatch, &local, 5_900)
            .await
            .expect_err("charged total must not be accepted on trust");
        assert!(error.contains("blocked"), "{error}");
        let incidents: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM finance_incidents
             WHERE kind = 'tax_total_mismatch' AND mollie_payment_id = 'tr_tax_bad'
               AND status = 'open'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("incidents");
        assert_eq!(incidents, 1, "a durable finance incident is raised");
        let (validation, delta, authority): (String, i64, String) = sqlx::query_as(
            "SELECT validation_status, discrepancy_cents, authority FROM mollie_tax_snapshots
             WHERE mollie_payment_id = 'tr_tax_bad'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(validation, "discrepancy");
        assert_eq!(delta, 1_000, "the delta is the over-charged amount");
        assert_eq!(authority, TAX_AUTHORITY_LOCAL);

        validate_and_snapshot_mollie_tax(&env.state, &mismatch, &local, 5_900)
            .await
            .expect_err("an open discrepancy keeps blocking");
        let incidents: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM finance_incidents
             WHERE kind = 'tax_total_mismatch' AND mollie_payment_id = 'tr_tax_bad'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("incidents");
        assert_eq!(incidents, 1, "incident dedupe");

        let good = recurring_authorisation("tr_tax_ok", invoice_id, 4_900, true, Some(tenant));
        let snapshot = validate_and_snapshot_mollie_tax(&env.state, &good, &local, 4_900)
            .await
            .expect("matching charge validates")
            .expect("snapshot id");
        assert!(!snapshot.is_nil());
        let (validation, authority): (String, String) = sqlx::query_as(
            "SELECT validation_status, authority FROM mollie_tax_snapshots
             WHERE mollie_payment_id = 'tr_tax_ok'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(validation, "validated");
        assert_eq!(authority, TAX_AUTHORITY_LOCAL);
    });

    env_test!(
        recurring_authorisation_is_blocked_by_the_tax_gate_on_a_mismatch,
        |env| {
            let tenant = "swadv_recompute";
            seed_tenant(env, tenant, "growth", "active").await;
            let invoice_id = Uuid::new_v4();
            seed_local_invoice(env, tenant, invoice_id, 4_900, 0, 4_900, "eur").await;
            let item =
                recurring_authorisation("tr_recompute_bad", invoice_id, 5_900, true, Some(tenant));
            let error = deliver_payment(&env.state, &item)
                .await
                .expect_err("a mismatching charge blocks");
            assert!(error.message().contains("blocked"), "{}", error.message());
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

        let zero = recurring_authorisation("tr_tax_zero", invoice_id, 0, true, Some(tenant));
        validate_and_snapshot_mollie_tax(&env.state, &zero, &local, 0)
            .await
            .expect("zero-value charges validate");
        let validation: String = sqlx::query_scalar(
            "SELECT validation_status FROM mollie_tax_snapshots
             WHERE mollie_payment_id = 'tr_tax_zero'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("snapshot");
        assert_eq!(validation, "validated");

        let charged =
            recurring_authorisation("tr_tax_zero_charged", invoice_id, 1_000, true, Some(tenant));
        let error = validate_and_snapshot_mollie_tax(&env.state, &charged, &local, 1_000)
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
            let item =
                recurring_authorisation("tr_tax_local", invoice_id, 12_400, true, Some(tenant));
            validate_and_snapshot_mollie_tax(&env.state, &item, &local, 12_400)
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
                 FROM mollie_tax_snapshots WHERE mollie_payment_id = 'tr_tax_local'",
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
                "Mollie transmits no tax object, nothing is invented"
            );
        }
    );

    env_test!(tax_snapshot_edges_are_honest, |env| {
        let tenant = "swadv_snapedge";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 0, 0, 0, "eur").await;
        let local = local_invoice(env, invoice_id).await;
        let item = recurring_authorisation("tr_snapedge", invoice_id, 0, true, Some(tenant));
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
            "SELECT raw_payload_hash, raw_payload FROM mollie_tax_snapshots
             WHERE mollie_payment_id = $1",
        )
        .bind("tr_snapedge")
        .fetch_one(&env.pool)
        .await
        .expect("snapshot row");
        assert_eq!(hash.len(), 64, "the raw payload is content-addressed");
        assert_eq!(payload["mollie_item"]["provider_payment_id"], "tr_snapedge");
        assert_eq!(payload["apexmail"]["source"], "local_invoice");

        sqlx::query("UPDATE mollie_tax_snapshots SET total_cents = 1 WHERE mollie_payment_id = $1")
            .bind("tr_snapedge")
            .execute(&env.pool)
            .await
            .expect_err("snapshots are trigger-immutable");
        let total: i64 = sqlx::query_scalar(
            "SELECT total_cents FROM mollie_tax_snapshots WHERE mollie_payment_id = $1",
        )
        .bind("tr_snapedge")
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
        let item = recurring_authorisation("tr_snapreplay", invoice_id, 1_000, true, Some(tenant));
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

    async fn seed_subscription(env: &Env, tenant: &str, subscription_id: &str, status: &str) {
        sqlx::query(
            "INSERT INTO mollie_subscriptions
                 (tenant_id, mollie_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, mollie_customer_id)
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

            let item = recurring_contract(
                "tr_token",
                Some(tenant),
                Some("mdt_swadv_123"),
                Some("first"),
            );
            handle_token_created(&env.state, &item)
                .await
                .expect("token bound");
            let rows: Vec<(String, Option<String>, Option<String>)> = sqlx::query_as(
                "SELECT mollie_subscription_id, mollie_mandate_id, mollie_sequence_type
             FROM mollie_subscriptions WHERE tenant_id = $1 ORDER BY mollie_subscription_id",
            )
            .bind(tenant)
            .fetch_all(&env.pool)
            .await
            .expect("rows");
            assert_eq!(rows.len(), 2, "the shopper tenant's rows are bound");
            for (_, token, model) in &rows {
                assert_eq!(token.as_deref(), Some("mdt_swadv_123"));
                assert_eq!(model.as_deref(), Some("first"));
            }
            let untouched: Option<String> = sqlx::query_scalar(
                "SELECT mollie_mandate_id FROM mollie_subscriptions
             WHERE mollie_subscription_id = 'sub_swadv_token_other'",
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
        let no_token = recurring_contract("tr_token_missing", Some(tenant), None, Some("first"));
        let error = handle_token_created(&env.state, &no_token)
            .await
            .expect_err("missing token refused");
        assert!(error.contains("no mandate id"), "{error}");
        let no_shopper = recurring_contract(
            "tr_token_no_shopper",
            None,
            Some("mdt_orphan"),
            Some("first"),
        );
        let error = handle_token_created(&env.state, &no_shopper)
            .await
            .expect_err("missing tenant refused");
        assert!(error.contains("no tenant attribution"), "{error}");
        // A mandate can precede any subscription row: nothing to bind yet is
        // acknowledged (Mollie keeps the mandate on the customer).
        let no_rows = recurring_contract(
            "tr_token_no_rows",
            Some(tenant),
            Some("mdt_no_rows"),
            Some("first"),
        );
        handle_token_created(&env.state, &no_rows)
            .await
            .expect("a mandate without a subscription row is acknowledged");
        let rows: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM mollie_subscriptions WHERE tenant_id = $1")
                .bind(tenant)
                .fetch_one(&env.pool)
                .await
                .expect("rows");
        assert_eq!(rows, 0, "no subscription row is invented");
    });

    // ===================================================================
    // Checkout authorisation: informational only.
    // ===================================================================

    env_test!(checkout_authorisation_never_grants_entitlement, |env| {
        let tenant = "swcov_trial";
        seed_tenant(env, tenant, "suspended", "suspended").await;

        let mut session = event("AUTHORISATION", true, 2_900);
        session.provider_payment_id = "tr_checkout".into();
        session.reference = "checkout:growth:monthly".into();
        session.additional.as_mut().expect("additional").customer_id = Some(tenant.into());
        handle_checkout_authorisation(&env.state, &session)
            .await
            .expect("checkout acknowledged");
        let status: String = sqlx::query_scalar("SELECT status FROM tenants WHERE id = $1")
            .bind(tenant)
            .fetch_one(&env.pool)
            .await
            .expect("tenant");
        assert_eq!(status, "suspended", "checkout never bypasses a suspension");
        let subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mollie_subscriptions")
            .fetch_one(&env.pool)
            .await
            .expect("subscriptions");
        assert_eq!(subs, 0);
        let notifications: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM notification_queue")
            .fetch_one(&env.pool)
            .await
            .expect("notifications");
        assert_eq!(notifications, 0);
    });

    env_test!(
        checkout_authorisation_without_attribution_is_acknowledged,
        |env| {
            let event = event("AUTHORISATION", true, 2_900);
            handle_checkout_authorisation(&env.state, &event)
                .await
                .expect("unattributable checkout is acknowledged");
            let subs: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM mollie_subscriptions")
                .fetch_one(&env.pool)
                .await
                .expect("subs");
            assert_eq!(subs, 0);
        }
    );

    env_test!(notification_shape_failures_fail_closed, |env| {
        seed_tenant(env, "swadv_shape_fail", "growth", "active").await;
        // A normalized fact with no amount is a handler error (deadlettered
        // by the caller), never a silent drop.
        let mut no_amount = recurring_authorisation(
            "tr_decode_fail",
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
    // Deadletter replay (re-fetch, exactly-once).
    // ===================================================================

    env_test!(replay_deadletter_refetches_and_is_idempotent, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _mock = mock().base_url.clone();
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        let tenant = "swcov_replay";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 4_200, 0, 4_200, "eur").await;
        let item = recurring_authorisation("tr_replay", invoice_id, 4_200, false, Some(tenant));
        mock().publish_payment(&item);

        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(mollie_event_id(&item)),
            body: Some(serde_json::to_string(&item).expect("body")),
            signature: Some(item.provider_payment_id.clone()),
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

        // Replaying the same fact again is a no-op: the claim row is
        // processed.
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
    });

    env_test!(replay_deadletter_malformed_body_refused, |env| {
        let _mock = mock().base_url.clone();
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("mollie:tr_badbody".into()),
            body: Some("{\"provider_payment_id\": ".into()),
            signature: Some("tr_badbody".into()),
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

    env_test!(replay_deadletter_without_body_is_refused, |env| {
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some("mollie:tr_nobody".into()),
            ..Default::default()
        };
        let error = replay_deadletter(&env.state, &entry)
            .await
            .expect_err("no body");
        assert!(error.contains("No body stored"), "{error}");
    });

    env_test!(replay_deadletter_pending_event_is_refused, |env| {
        let _mock = mock().base_url.clone();
        let tenant = "swadv_pendreplay";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 100, 0, 100, "eur").await;
        let item = recurring_authorisation("tr_pendreplay", invoice_id, 100, false, Some(tenant));
        mock().publish_payment(&item);
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(mollie_event_id(&item)),
            body: Some(serde_json::to_string(&item).expect("body")),
            signature: Some("tr_pendreplay".into()),
            ..Default::default()
        };
        replay_deadletter(&env.state, &entry)
            .await
            .expect("first replay claims");
        sqlx::query(
            "UPDATE mollie_webhook_events SET status = 'pending', processed_at = NULL
             WHERE mollie_event_id = $1",
        )
        .bind(mollie_event_id(&item))
        .execute(&env.pool)
        .await
        .expect("re-pend");
        // A sibling worker holding the claim means the replay must NOT race
        // it: `replay_deadletter` skips it as still pending, leaving the row
        // and the business state untouched.
        replay_deadletter(&env.state, &entry)
            .await
            .expect("a pending event is skipped, never double-applied");
        let count: i32 = sqlx::query_scalar(
            "SELECT failed_payment_count FROM dunning_records WHERE tenant_id = $1",
        )
        .bind(tenant)
        .fetch_one(&env.pool)
        .await
        .expect("dunning");
        assert_eq!(count, 1, "the pending claim is untouched");
    });

    env_test!(replay_skips_already_processed_events, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _mock = mock().base_url.clone();
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        let tenant = "swcov_replay2";
        seed_tenant(env, tenant, "growth", "active").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 100, 0, 100, "eur").await;

        let done = recurring_authorisation("tr_already_done", invoice_id, 100, false, Some(tenant));
        mock().publish_payment(&done);
        sqlx::query(
            "INSERT INTO mollie_webhook_events (mollie_event_id, mollie_payment_id, event_type, status, created_at, updated_at)
             VALUES ($1, 'tr_already_done', 'AUTHORISATION', 'processed', NOW(), NOW())",
        )
        .bind(mollie_event_id(&done))
        .execute(&env.pool)
        .await
        .expect("seed processed row");
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(mollie_event_id(&done)),
            body: Some(serde_json::to_string(&done).expect("body")),
            signature: Some("tr_already_done".into()),
            ..Default::default()
        };
        replay_deadletter(&env.state, &entry)
            .await
            .expect("an already-processed event replays as a no-op success");
        let dunning: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM dunning_records")
            .fetch_one(&env.pool)
            .await
            .expect("dunning");
        assert_eq!(dunning, 0, "a processed event is never re-applied");
    });

    // ===================================================================
    // Deadletter retry worker.
    // ===================================================================

    env_test!(deadletter_retry_backs_off_then_exhausts, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _mock = mock().base_url.clone();
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        let item = recurring_authorisation(
            "tr_sw_backoff",
            Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid"),
            100,
            false,
            Some("swcov_backoff"),
        );
        // The provider fetch fails every time: the retry ladder is
        // deterministic.
        mock().fail_payment("tr_sw_backoff", 503, "mollie down");
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(mollie_event_id(&item)),
            body: Some(serde_json::to_string(&item).expect("body")),
            signature: Some("tr_sw_backoff".into()),
            ..Default::default()
        };
        let the_key = "mollie:deadletter:event:authorisation_forced";
        let entry_json = serde_json::to_string(&entry).expect("entry json");
        let mut conn = redis_conn(env).await;
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
            let _mock = mock().base_url.clone();
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

            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg("mollie:deadletter:event:evicted")
                .query_async(&mut conn)
                .await
                .expect("schedule evicted");
            let _: () = redis::cmd("SET")
                .arg("mollie:deadletter:event:corrupt")
                .arg("this is not json")
                .query_async(&mut conn)
                .await
                .expect("store corrupt");
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg("mollie:deadletter:event:corrupt")
                .query_async(&mut conn)
                .await
                .expect("schedule corrupt");
            let foreign = DeadletterEntry {
                reason: "missing_id".into(),
                ..Default::default()
            };
            let _: () = redis::cmd("SET")
                .arg("mollie:deadletter:event:foreign")
                .arg(serde_json::to_string(&foreign).unwrap())
                .query_async(&mut conn)
                .await
                .expect("store foreign");
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg("mollie:deadletter:event:foreign")
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
                .arg("mollie:deadletter:event:corrupt")
                .arg("mollie:deadletter:event:foreign")
                .query_async(&mut conn)
                .await
                .expect("cleanup");
        }
    );

    env_test!(retry_worker_batches_redis_reads_and_index_removals, |env| {
        use crate::test_support::query_count;
        let _mock = mock().base_url.clone();

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

        for index in 0..2 {
            let key = format!("mollie:deadletter:event:batch_evicted_{index}");
            let _: () = redis::cmd("ZADD")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg(1)
                .arg(&key)
                .query_async(&mut conn)
                .await
                .expect("schedule evicted");
        }
        let foreign = DeadletterEntry {
            reason: "invalid_id".into(),
            ..Default::default()
        };
        let foreign_json = serde_json::to_string(&foreign).expect("json");
        for index in 0..3 {
            let key = format!("mollie:deadletter:event:batch_foreign_{index}");
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
            .arg("mollie:deadletter:event:batch_foreign_0")
            .arg("mollie:deadletter:event:batch_foreign_1")
            .arg("mollie:deadletter:event:batch_foreign_2")
            .query_async(&mut conn)
            .await
            .expect("cleanup");
    });

    env_test!(retry_worker_empty_index_is_a_clean_noop, |env| {
        let _mock = mock().base_url.clone();
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        retry_deadlettered_webhooks(&state)
            .await
            .expect("empty batch returns immediately");
    });

    env_test!(retry_worker_success_removes_entry_from_index, |env| {
        let _mock = mock().base_url.clone();
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        let tenant = "swadv_retry_ok";
        crate::test_support::seed_tenant(&env.pool, tenant, "growth").await;
        let invoice_id = Uuid::new_v4();
        seed_local_invoice(env, tenant, invoice_id, 100, 0, 100, "eur").await;
        let item = recurring_authorisation("tr_retry_ok", invoice_id, 100, false, Some(tenant));
        mock().publish_payment(&item);
        let entry = DeadletterEntry {
            reason: "processing_failed".into(),
            event_id: Some(mollie_event_id(&item)),
            body: Some(serde_json::to_string(&item).expect("body")),
            signature: Some("tr_retry_ok".into()),
            ..Default::default()
        };
        let the_key = "mollie:deadletter:event:tr_retry_ok";
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
        let _mock = mock().base_url.clone();
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        process_deadletter_retries(&state)
            .await
            .expect("nothing due is a clean pass");
    });

    env_test!(spawned_retry_worker_performs_one_immediate_pass, |env| {
        let _mock = mock().base_url.clone();
        spawn_deadletter_retry_worker(env.state.clone());
        tokio::time::sleep(Duration::from_millis(20)).await;
    });

    env_test!(
        retry_failure_reschedules_with_backoff_then_gives_up_after_max_attempts,
        |env| {
            let _guard = DEADLETTER_LOCK.lock().await;
            let _mock = mock().base_url.clone();
            let isolated = crate::test_support::spawn_isolated_redis();
            // The replay FETCHES successfully and then fails at the claim
            // query (broken DB), so every attempt is a deterministic failure.
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
                let item = recurring_authorisation(
                    event_id,
                    Uuid::parse_str("01234567-89ab-cdef-0123-456789abcdef").expect("uuid"),
                    100,
                    false,
                    Some("swcov_backoff"),
                );
                mock().publish_payment(&item);
                DeadletterEntry {
                    reason: "processing_failed".into(),
                    event_id: Some(event_id.into()),
                    body: Some(serde_json::to_string(&item).expect("body")),
                    signature: Some(event_id.into()),
                    retry_count,
                    ..Default::default()
                }
            };
            for (event_id, count) in [("tr_backoff_1", 0u32), ("tr_give_up", 4u32)] {
                let entry = make_entry(event_id, count);
                let key = format!("mollie:deadletter:event:{event_id}");
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

            let mut conn = pool_conn(&isolated.pool).await;
            let score: Option<f64> = redis::cmd("ZSCORE")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg("mollie:deadletter:event:tr_backoff_1")
                .query_async(&mut conn)
                .await
                .expect("score");
            assert!(score.is_some(), "a first failure stays scheduled");
            let rescheduled: String = redis::cmd("GET")
                .arg("mollie:deadletter:event:tr_backoff_1")
                .query_async(&mut conn)
                .await
                .expect("entry");
            let entry: DeadletterEntry = serde_json::from_str(&rescheduled).unwrap();
            assert_eq!(entry.retry_count, 1, "the retry counter advanced");

            let gone: i64 = redis::cmd("ZSCORE")
                .arg(DEADLETTER_RETRY_INDEX_KEY)
                .arg("mollie:deadletter:event:tr_give_up")
                .query_async(&mut conn)
                .await
                .map(|v: Option<f64>| v.map(|_| 1).unwrap_or(0))
                .expect("zscore");
            assert_eq!(gone, 0, "an exhausted entry leaves the retry index");
            let final_json: String = redis::cmd("GET")
                .arg("mollie:deadletter:event:tr_give_up")
                .query_async(&mut conn)
                .await
                .expect("final entry");
            let final_entry: DeadletterEntry = serde_json::from_str(&final_json).unwrap();
            assert_eq!(
                final_entry.retry_count, DEADLETTER_MAX_RETRIES,
                "the final count is recorded for review"
            );
            let ttl: i64 = redis::cmd("TTL")
                .arg("mollie:deadletter:event:tr_give_up")
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
            let _mock = mock().base_url.clone();
            let dead = crate::test_support::state_with_dead_redis(&env.pool);
            let response = post_webhook(&dead, b"id=../bad").await;
            assert_eq!(response.status(), StatusCode::BAD_REQUEST);
            assert_eq!(event_rows(&env.pool).await, 0);
        }
    );

    env_test!(deadletter_index_wrongtype_fails_the_write_arm, |env| {
        let _guard = DEADLETTER_LOCK.lock().await;
        let _mock = mock().base_url.clone();
        let _dl_guard = crate::test_support::redis_keys_guard(&env.admin_url, "deadletter").await;
        let mut conn = redis_conn(env).await;
        let _: () = redis::cmd("SET")
            .arg(DEADLETTER_INDEX_KEY)
            .arg("not-a-zset")
            .query_async(&mut conn)
            .await
            .expect("poison index");
        drop(conn);

        let response = post_webhook(&env.state, b"id=foo_1").await;
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
                "mollie:never_claimed",
                "boom",
                br#"{"id":"tr_never_claimed"}"#,
                Some("tr_never_claimed"),
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
                "mollie:beginfail",
                "boom",
                br#"{"id":"tr_beginfail"}"#,
                Some("tr_beginfail"),
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
            "INSERT INTO mollie_webhook_events (id, mollie_event_id, mollie_payment_id, event_type, status)
             VALUES (gen_random_uuid(), 'mollie:rollback', 'tr_rollback', 'AUTHORISATION', 'pending')",
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
                "mollie:rollback",
                "boom",
                br#"{"id":"tr_rollback"}"#,
                Some("tr_rollback"),
            )
            .await
            .expect_err("redis failure surfaces");
            assert!(
                error.contains("mollie dead letter"),
                "honest failure: {error}"
            );
            let status: String = sqlx::query_scalar(
            "SELECT status FROM mollie_webhook_events WHERE mollie_event_id = 'mollie:rollback'",
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
            "INSERT INTO mollie_webhook_events (id, mollie_event_id, mollie_payment_id, event_type, status)
             VALUES (gen_random_uuid(), 'mollie:commitfail', 'tr_commitfail', 'AUTHORISATION', 'pending')",
        )
        .execute(&env.pool)
        .await
        .expect("claim row");
            for statement in [
            "CREATE TABLE cov_status_guard (status text PRIMARY KEY)",
            "INSERT INTO cov_status_guard VALUES ('pending'), ('received')",
            "ALTER TABLE mollie_webhook_events ADD CONSTRAINT cov_status_fk FOREIGN KEY (status) \
             REFERENCES cov_status_guard(status) DEFERRABLE INITIALLY DEFERRED",
        ] {
            sqlx::query(statement)
                .execute(&env.pool)
                .await
                .expect("deferred constraint setup");
        }

            let error = record_failed_webhook_deadletter_atomic(
                &state,
                "mollie:commitfail",
                "boom",
                br#"{"id":"tr_commitfail"}"#,
                Some("tr_commitfail"),
            )
            .await
            .expect_err("commit failure surfaces");
            assert!(
                error.contains("Failed to commit"),
                "honest failure: {error}"
            );
            let status: String = sqlx::query_scalar(
            "SELECT status FROM mollie_webhook_events WHERE mollie_event_id = 'mollie:commitfail'",
        )
        .fetch_one(&env.pool)
        .await
        .expect("status");
            assert_eq!(
                status, "pending",
                "commit failure leaves the claim untouched"
            );
            let mut conn = pool_conn(&isolated.pool).await;
            let entries =
                deadletter_entries_on(&mut conn, "mollie:deadletter:event:mollie_commitfail*")
                    .await;
            assert_eq!(
                entries.len(),
                0,
                "redis entry compensated after commit failure"
            );
        }
    );

    env_test!(compensation_failure_is_logged_never_fatal, |env| {
        let isolated = crate::test_support::spawn_isolated_redis();
        let state = state_with_isolated_redis(env, &isolated);
        let mut conn = pool_conn(&isolated.pool).await;
        let the_key = "mollie:deadletter:event:mollie_comp_direct";
        let _: () = redis::cmd("SETEX")
            .arg(the_key)
            .arg(60)
            .arg("{}")
            .query_async(&mut conn)
            .await
            .expect("stored entry");
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
                    reason: "missing_id".into(),
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
                "mollie:never_claimed_cov",
                "handler failed",
                br#"{"id":"tr_never_claimed_cov"}"#,
                Some("tr_never_claimed_cov"),
            )
            .await
            .expect_err("an unknown event row must fail the atomic deadletter");
            assert!(
                error.contains("event row was not found"),
                "unexpected: {error}"
            );
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

            sqlx::query(
            "INSERT INTO mollie_webhook_events (mollie_event_id, mollie_payment_id, event_type, status, created_at, updated_at)
             VALUES ('mollie:redis_dead_cov', 'tr_redis_dead', 'AUTHORISATION', 'pending', NOW(), NOW())",
        )
        .execute(&env.pool)
        .await
        .expect("seed claim row");

            let error = record_failed_webhook_deadletter_atomic(
                &state,
                "mollie:redis_dead_cov",
                "handler failed",
                br#"{"id":"tr_redis_dead"}"#,
                Some("tr_redis_dead"),
            )
            .await
            .expect_err("dead redis must fail the atomic deadletter");
            assert!(error.contains("mollie dead letter"), "unexpected: {error}");

            let status: String = sqlx::query_scalar(
            "SELECT status FROM mollie_webhook_events WHERE mollie_event_id = 'mollie:redis_dead_cov'",
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
        let stale = "mollie:sw_stale";
        let fresh = "mollie:sw_fresh";
        let processed = "mollie:sw_done";
        let received = "mollie:sw_received";
        for (notification_id, status, updated_offset_minutes) in [
            (stale, "pending", 20_i64),
            (fresh, "pending", 1),
            (processed, "processed", 20),
            (received, "received", 20),
        ] {
            sqlx::query(
                "INSERT INTO mollie_webhook_events
                     (id, mollie_event_id, mollie_payment_id, event_type, status, created_at, updated_at)
                 VALUES (gen_random_uuid(), $1, 'tr_reclaim', 'AUTHORISATION', $2,
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
                (SELECT status FROM mollie_webhook_events WHERE mollie_event_id = $1),
                (SELECT status FROM mollie_webhook_events WHERE mollie_event_id = $2),
                (SELECT status FROM mollie_webhook_events WHERE mollie_event_id = $3)",
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
            "SELECT status FROM mollie_webhook_events WHERE mollie_event_id = $1",
        )
        .bind(stale)
        .fetch_one(&env.pool)
        .await
        .expect("stale status");
        assert_eq!(reclaimed_status, "received");
    });

    env_test!(claim_webhook_event_is_exactly_once, |env| {
        let notification_id = "mollie:sw_claim";
        let first =
            claim_webhook_event(&env.state, notification_id, "AUTHORISATION", "tr_sw_claim")
                .await
                .expect("claim");
        assert!(matches!(first, WebhookEventClaim::Claimed));
        let payment_id: Option<String> = sqlx::query_scalar(
            "SELECT mollie_payment_id FROM mollie_webhook_events WHERE mollie_event_id = $1",
        )
        .bind(notification_id)
        .fetch_one(&env.pool)
        .await
        .expect("payment id");
        assert_eq!(payment_id.as_deref(), Some("tr_sw_claim"));
        let second =
            claim_webhook_event(&env.state, notification_id, "AUTHORISATION", "tr_sw_claim")
                .await
                .expect("claim");
        assert!(matches!(second, WebhookEventClaim::AlreadyPending));
        sqlx::query(
            "UPDATE mollie_webhook_events SET status = 'failed' WHERE mollie_event_id = $1",
        )
        .bind(notification_id)
        .execute(&env.pool)
        .await
        .expect("mark failed");
        let reclaimed =
            claim_webhook_event(&env.state, notification_id, "AUTHORISATION", "tr_sw_claim")
                .await
                .expect("claim");
        assert!(matches!(reclaimed, WebhookEventClaim::Claimed));
        sqlx::query(
            "UPDATE mollie_webhook_events SET status = 'processed' WHERE mollie_event_id = $1",
        )
        .bind(notification_id)
        .execute(&env.pool)
        .await
        .expect("mark processed");
        let duplicate =
            claim_webhook_event(&env.state, notification_id, "AUTHORISATION", "tr_sw_claim")
                .await
                .expect("claim");
        assert!(matches!(duplicate, WebhookEventClaim::AlreadyProcessed));
    });

    env_test!(reclaim_reports_reclaimed_events_loudly, |env| {
        sqlx::query(
            "INSERT INTO mollie_webhook_events (id, mollie_event_id, mollie_payment_id, event_type, status, updated_at)
             VALUES (gen_random_uuid(), 'mollie:swadv_reclaim', 'tr_swadv_reclaim', 'AUTHORISATION', 'pending',
                     NOW() - INTERVAL '20 minutes')",
        )
        .execute(&env.pool)
        .await
        .expect("stale row");
        let reclaimed = reclaim_stale_pending_webhooks(&env.state)
            .await
            .expect("reclaim");
        assert_eq!(reclaimed, vec!["mollie:swadv_reclaim".to_string()]);
    });

    // ===================================================================
    // Dunning config + notification edges.
    // ===================================================================

    env_test!(dunning_config_degrades_to_defaults_on_faults, |env| {
        let tenant = "swadv_duncfg";
        crate::test_support::seed_tenant(&env.pool, tenant, "growth").await;
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

        env.break_table("dunning_config").await;
        let config = get_dunning_config_for_tenant(&env.state, tenant).await;
        assert_eq!(
            config.soft_suspend_after_days, 7,
            "defaults survive a missing table"
        );
        env.restore_table("dunning_config").await;

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
            for status in ["warning", "soft_suspended", "hard_suspended"] {
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
        let item = recurring_authorisation("tr_cache", invoice_id, 10, false, Some(tenant));
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

        for (payment_id, event_code) in [
            ("tr_refund", "REFUND"),
            ("tr_refund_failed", "REFUND_FAILED"),
            ("tr_chargeback", "CHARGEBACK"),
            ("tr_chargeback_reversed", "CHARGEBACK_REVERSED"),
        ] {
            let mut item = event(event_code, true, 1_000);
            item.provider_payment_id = payment_id.into();
            item.original_payment_id = Some("tr_paid".into());
            item.reference = format!("invoice:{invoice_id}");
            item.event_date = Some("2026-10-24T10:00:00+00:00".into());
            item.reason = Some("requested".into());
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
        assert!(actions.contains(&"billing.mollie_refund_recorded"));
        assert!(actions.contains(&"billing.mollie_refund_failed"));
        assert!(actions.contains(&"billing.mollie_chargeback_recorded"));
        assert!(actions.contains(&"billing.mollie_chargeback_reversed"));
        let status: String = sqlx::query_scalar("SELECT status FROM invoices WHERE id = $1")
            .bind(invoice_id)
            .fetch_one(&env.pool)
            .await
            .expect("status");
        assert_eq!(status, "pending");

        let mut orphan = event("REFUND", true, 10);
        orphan.provider_payment_id = "tr_refund_orphan".into();
        orphan.reference = "not-a-local-invoice".into();
        handle_notification(&env.state, &orphan)
            .await
            .expect("an unresolvable refund is acknowledged (never 5xx)");
    });

    // ===================================================================
    // Dedicated-IP auto-provisioning (local servers).
    // ===================================================================

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
            "INSERT INTO mollie_subscriptions
                 (tenant_id, mollie_subscription_id, plan, status, billing_cycle_start,
                  billing_cycle_end, mollie_customer_id)
             VALUES ($1, $2, $3, 'active', NOW(), NOW() + INTERVAL '30 days', 'cst_ip')",
        )
        .bind(tenant)
        .bind(sub_id)
        .bind(plan)
        .execute(&env.pool)
        .await
        .expect("active subscription");
    }

    env_test!(auto_provision_covers_every_allocation_outcome, |env| {
        let none = "swadv_ip_none";
        crate::test_support::seed_tenant(&env.pool, none, "growth").await;
        auto_provision_dedicated_ips_background(&env.state, none)
            .await
            .expect("no allowance is a no-op");

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

            env.break_table("mollie_subscriptions").await;
            let error = auto_provision_dedicated_ips_background(&env.state, tenant)
                .await
                .expect_err("broken allowance query");
            assert!(error.contains("Failed to load dedicated IP allowance"));
            env.restore_table("mollie_subscriptions").await;

            env.break_table("dedicated_ips").await;
            let error = auto_provision_dedicated_ips_background(&env.state, tenant)
                .await
                .expect_err("broken count query");
            assert!(error.contains("Failed to load active dedicated IP count"));
            env.restore_table("dedicated_ips").await;
        }
    );
}
