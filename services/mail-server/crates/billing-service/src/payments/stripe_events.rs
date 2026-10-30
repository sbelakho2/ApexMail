//! Stripe webhook signature verification and NEUTRAL event normalization —
//! the follow-up agent's HTTP-route contract (external audit item 15).
//!
//! # The HTTP route contract (STABLE — implement the route against exactly this)
//!
//! `POST /v1/webhooks/stripe`, body = the RAW request bytes (never
//! re-serialized JSON), header = `Stripe-Signature: t=<unix>,v1=<hex>`:
//!
//! 1. `verify_signature(&STRIPE_WEBHOOK_SECRET, &raw_body, header)` — reject
//!    with 400 on `Err` (a tampered/replayed/unparseable delivery must never
//!    enter the fact pipeline).
//! 2. Parse the body as `serde_json::Value`; the dedupe id is
//!    [`event_dedup_id`] (`event.id`, Stripe's `evt_…`); a delivery whose id
//!    was already processed is acknowledged without effect.
//! 3. `normalize_event("stripe", &event)` — unknown event types answer
//!    `Ok(vec![])` (accepted and ignored, like the house webhook pattern);
//!    an `Err` is a malformed KNOWN event (dead-letter / 500 so Stripe
//!    retries).
//! 4. Dispatch each [`NormalizedFact`] through the SAME engine paths the
//!    Mollie webhook uses — never a Stripe-specific writer:
//!    * [`NormalizedFact::Payment`] -> `payments::engine::observe_payment`
//!      -> `verify_against_obligation` -> `settle_verified` (the
//!      verify-then-settle core);
//!    * [`NormalizedFact::Refund`] -> `payments::engine::record_refund_fact`;
//!    * [`NormalizedFact::Dispute`] -> `payments::engine::observe_dispute`;
//!    * [`NormalizedFact::Settlement`] -> `payments::engine::record_settlement_fact`.
//!
//! Wire notification BODIES are never trusted as settlement authority by
//! themselves: the engine re-verifies every fact against the LOCAL invoice,
//! and the repair sweep re-fetches the intent with provider authentication.

use chrono::{TimeZone, Utc};
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::engine::ObservedPayment;
use super::stripe_provider::{
    map_dispute_status, map_payment_status, map_refund_status, map_session_status, PROVIDER_NAME,
};
use super::{Dispute, ProviderError, Refund, Settlement};

/// Replay-window tolerance for the `Stripe-Signature` timestamp (Stripe's
/// own SDK default): a header older (or further in the future) than five
/// minutes is rejected, so a captured delivery cannot be replayed later.
pub const SIGNATURE_TOLERANCE_SECS: i64 = 300;

/// One normalized provider-event fact. The variants are the neutral money
/// shapes; the event id that dedupes the DELIVERY is read separately via
/// [`event_dedup_id`] (one id, any number of facts).
#[derive(Debug, Clone)]
pub enum NormalizedFact {
    Payment(ObservedPayment),
    Refund(Refund),
    Dispute(Dispute),
    Settlement(Settlement),
}

/// Verify a `Stripe-Signature` header over the RAW payload bytes.
///
/// Header grammar: comma-separated `key=value` pairs — `t=<unix seconds>`
/// plus one or more `v1=<hex HMAC>` signatures (key rotation). The signed
/// payload is `"{t}.{raw_body}"`; the MAC is HMAC-SHA256 keyed with the
/// webhook signing secret (`whsec_…`). A delivery passes only when the
/// timestamp is inside [`SIGNATURE_TOLERANCE_SECS`] of now AND at least one
/// `v1` matches; comparisons are constant time (`hmac::Mac::verify_slice`).
///
/// Every failure is a fail-closed [`ProviderError`]:
/// * unparseable header / missing `t` / non-numeric `t` / missing `v1` ->
///   `Malformed` (the request cannot be read as a Stripe delivery),
/// * timestamp outside the window -> `Malformed` naming the replay window,
/// * signature mismatch -> `Malformed` (tampered or wrong secret).
pub fn verify_signature(secret: &str, payload: &[u8], header: &str) -> Result<(), ProviderError> {
    let mut timestamp: Option<i64> = None;
    let mut signatures: Vec<Vec<u8>> = Vec::new();
    for element in header.split(',') {
        let element = element.trim();
        if element.is_empty() {
            continue;
        }
        let Some((key, value)) = element.split_once('=') else {
            return Err(ProviderError::Malformed(format!(
                "Stripe-Signature element {element:?} is not key=value"
            )));
        };
        match key.trim() {
            "t" => {
                timestamp = Some(value.trim().parse::<i64>().map_err(|_| {
                    ProviderError::Malformed(format!(
                        "Stripe-Signature timestamp {value:?} is not a number"
                    ))
                })?);
            }
            "v1" => {
                let hex = value.trim();
                let decoded = hex::decode(hex).map_err(|_| {
                    ProviderError::Malformed(format!(
                        "Stripe-Signature signature {hex:?} is not hex"
                    ))
                })?;
                signatures.push(decoded);
            }
            // Unknown scheme keys (e.g. a future `v2`) are ignored, not
            // fatal: the v1 scheme decides.
            _ => {}
        }
    }
    let Some(timestamp) = timestamp else {
        return Err(ProviderError::Malformed(
            "Stripe-Signature carries no t= timestamp".to_string(),
        ));
    };
    if signatures.is_empty() {
        return Err(ProviderError::Malformed(
            "Stripe-Signature carries no v1= signature".to_string(),
        ));
    }
    let now = Utc::now().timestamp();
    if (now - timestamp).abs() > SIGNATURE_TOLERANCE_SECS {
        return Err(ProviderError::Malformed(format!(
            "Stripe-Signature timestamp is outside the {SIGNATURE_TOLERANCE_SECS}s replay window \
             (t={timestamp}, now={now})"
        )));
    }
    let signed_payload = format!("{timestamp}.");
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes())
        .map_err(|error| ProviderError::Config(format!("webhook secret: {error}")))?;
    mac.update(signed_payload.as_bytes());
    mac.update(payload);
    for signature in &signatures {
        // `verify_slice` is the constant-time comparison.
        if mac.clone().verify_slice(signature).is_ok() {
            return Ok(());
        }
    }
    Err(ProviderError::Malformed(
        "Stripe-Signature v1 does not match the payload (tampered or wrong secret)".to_string(),
    ))
}

/// The provider's dedupe id for the event (`event.id`, Stripe's `evt_…`).
/// The route reads this once per delivery and acknowledges repeats without
/// effect; the facts themselves do not carry it (one delivery, many facts).
pub fn event_dedup_id(event: &serde_json::Value) -> Option<String> {
    event
        .get("id")
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .filter(|id| !id.is_empty())
}

/// Normalize one Stripe event into neutral facts. UNKNOWN event types are
/// ACCEPTED AND IGNORED (`Ok(vec![])` — the house webhook pattern: an
/// unknown notification must never fail the delivery); a KNOWN event whose
/// object is unreadable (no id, unmapped status) is an `Err` so the route
/// dead-letters it for retry. The provider name is the ADAPTER's stable
/// name (`"stripe"`), never hardcoded here.
pub fn normalize_event(
    provider_name: &str,
    event: &serde_json::Value,
) -> Result<Vec<NormalizedFact>, String> {
    let event_type = event
        .get("type")
        .and_then(|value| value.as_str())
        .unwrap_or_default();
    let object = event
        .pointer("/data/object")
        .cloned()
        .unwrap_or(serde_json::Value::Null);
    match event_type {
        "checkout.session.completed" => {
            let payment = observed_from_document(provider_name, &object, "checkout session")?;
            Ok(vec![NormalizedFact::Payment(payment)])
        }
        "payment_intent.succeeded"
        | "payment_intent.processing"
        | "payment_intent.payment_failed" => {
            let payment = observed_from_document(provider_name, &object, "payment intent")?;
            Ok(vec![NormalizedFact::Payment(payment)])
        }
        "charge.refunded" | "charge.refund.updated" => {
            let refund = refund_from_document(provider_name, &object)?;
            Ok(vec![NormalizedFact::Refund(refund)])
        }
        "charge.dispute.created" | "charge.dispute.updated" | "charge.dispute.closed" => {
            let dispute = dispute_from_document(provider_name, &object)?;
            Ok(vec![NormalizedFact::Dispute(dispute)])
        }
        "payout.paid" => {
            let settlement = settlement_from_document(provider_name, &object)?;
            Ok(vec![NormalizedFact::Settlement(settlement)])
        }
        // Accepted and ignored: Stripe may deliver event types this
        // integration never asked for (billing, connect, …).
        _ => Ok(Vec::new()),
    }
}

/// The neutral `ObservedPayment` for a payment-shaped event object (a
/// PaymentIntent or a `mode=payment` Checkout Session). The tenant and
/// obligation attribution ride the SAME metadata keys every ApexMail charge
/// writes (`metadata.tenant_id`, `metadata.reference` — the Mollie
/// contract), so the engine's repair-link works provider-blind.
fn observed_from_document(
    provider_name: &str,
    object: &serde_json::Value,
    kind: &'static str,
) -> Result<ObservedPayment, String> {
    let id = string_at(object, "/id").filter(|id| !id.is_empty());
    let Some(id) = id else {
        return Err(format!("a {kind} event object carries no id"));
    };
    let status = string_at(object, "/status").unwrap_or_default();
    // Checkout sessions (complete/expired/open) and payment intents
    // (succeeded/…/canceled) have disjoint state vocabularies; each maps
    // through its own total function and an unmapped status fails the fact.
    let state = if kind == "checkout session" {
        map_session_status(&status)
    } else {
        map_payment_status(&status)
    }
    .map_err(|error| format!("{kind} {id}: {error}"))?;
    let amount_minor = object.get("amount_total").and_then(|value| value.as_i64());
    let amount_minor = match amount_minor {
        Some(amount) => Some(amount),
        None => object.get("amount").and_then(|value| value.as_i64()),
    };
    let currency = string_at(object, "/currency")
        .map(|text| text.trim().to_ascii_uppercase())
        .filter(|text| !text.is_empty());
    Ok(ObservedPayment {
        provider: provider_name.to_string(),
        provider_payment_id: id,
        state,
        amount_minor,
        currency,
        tenant_id: metadata_string(object, "tenant_id"),
        obligation_ref: metadata_string(object, "reference"),
        purpose: "webhook",
    })
}

fn refund_from_document(provider_name: &str, object: &serde_json::Value) -> Result<Refund, String> {
    let id = string_at(object, "/id").filter(|id| !id.is_empty());
    let Some(id) = id else {
        return Err("a refund event object carries no id".to_string());
    };
    let state = map_refund_status(&string_at(object, "/status").unwrap_or_default())
        .map_err(|error| format!("refund {id}: {error}"))?;
    let amount_minor = object.get("amount").and_then(|value| value.as_i64());
    let Some(amount_minor) = amount_minor else {
        return Err(format!("refund {id} carries no amount"));
    };
    let currency = string_at(object, "/currency")
        .map(|text| text.trim().to_ascii_uppercase())
        .filter(|text| !text.is_empty());
    Ok(Refund {
        provider: provider_name.to_string(),
        provider_refund_id: id,
        provider_payment_id: string_at(object, "/payment_intent").unwrap_or_default(),
        state,
        amount_minor,
        currency: currency.unwrap_or_default(),
        created_at: seconds_at(object.get("created")),
    })
}

fn dispute_from_document(
    provider_name: &str,
    object: &serde_json::Value,
) -> Result<Dispute, String> {
    let id = string_at(object, "/id").filter(|id| !id.is_empty());
    let Some(id) = id else {
        return Err("a dispute event object carries no id".to_string());
    };
    let state = map_dispute_status(&string_at(object, "/status").unwrap_or_default())
        .map_err(|error| format!("dispute {id}: {error}"))?;
    let amount_minor = object.get("amount").and_then(|value| value.as_i64());
    let Some(amount_minor) = amount_minor else {
        return Err(format!("dispute {id} carries no amount"));
    };
    let currency = string_at(object, "/currency")
        .map(|text| text.trim().to_ascii_uppercase())
        .filter(|text| !text.is_empty());
    // The attempts ledger keys payments by the INTENT id; a dispute object
    // names it directly (`payment_intent`) and only a legacy shape names
    // the bare charge.
    let payment_id = string_at(object, "/payment_intent")
        .filter(|id| !id.is_empty())
        .or_else(|| string_at(object, "/charge"))
        .unwrap_or_default();
    Ok(Dispute {
        provider: provider_name.to_string(),
        provider_dispute_id: id,
        provider_payment_id: payment_id,
        state,
        amount_minor,
        currency: currency.unwrap_or_default(),
        reason: string_at(object, "/reason").filter(|reason| !reason.is_empty()),
        opened_at: seconds_at(object.get("created")),
    })
}

fn settlement_from_document(
    provider_name: &str,
    object: &serde_json::Value,
) -> Result<Settlement, String> {
    let id = string_at(object, "/id").filter(|id| !id.is_empty());
    let Some(id) = id else {
        return Err("a payout event object carries no id".to_string());
    };
    let amount_minor = object.get("amount").and_then(|value| value.as_i64());
    let Some(amount_minor) = amount_minor else {
        return Err(format!("payout {id} carries no amount"));
    };
    let currency = string_at(object, "/currency")
        .map(|text| text.trim().to_ascii_uppercase())
        .filter(|text| !text.is_empty());
    Ok(Settlement {
        provider: provider_name.to_string(),
        provider_settlement_id: id,
        amount_minor,
        currency: currency.unwrap_or_default(),
        settled_at: seconds_at(object.get("arrival_date")),
    })
}

fn string_at(document: &serde_json::Value, pointer: &str) -> Option<String> {
    document
        .pointer(pointer)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn metadata_string(document: &serde_json::Value, key: &str) -> Option<String> {
    document
        .pointer("/metadata")
        .and_then(|metadata| metadata.get(key))
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .filter(|text| !text.is_empty())
}

fn seconds_at(value: Option<&serde_json::Value>) -> Option<chrono::DateTime<Utc>> {
    value
        .and_then(|value| value.as_i64())
        .and_then(|seconds| chrono::Utc.timestamp_opt(seconds, 0).single())
}

/// The adapter's stable name, re-exported for the route's dispatch call
/// (`normalize_event(stripe_events::PROVIDER, &event)`).
pub const PROVIDER: &str = PROVIDER_NAME;
