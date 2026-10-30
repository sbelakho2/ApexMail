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
    /// A COMPLETED hosted checkout: the fact the activation consumes. It
    /// carries the provider payment (PaymentIntent), the checkout session,
    /// the provider customer and OUR metadata (tenant/plan/interval), so the
    /// activation can grant the plan and store the reusable card exactly as
    /// the Mollie completed-checkout path does.
    CheckoutCompleted(CheckoutCompleted),
}

/// The neutral completed-checkout fact (V34).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct CheckoutCompleted {
    pub provider: String,
    /// The provider PAYMENT id (Stripe PaymentIntent; the session id only
    /// when the session has no intent yet).
    pub provider_payment_id: String,
    /// The hosted checkout session id.
    pub provider_checkout_id: String,
    pub tenant_id: Option<String>,
    pub plan_name: Option<String>,
    pub interval: Option<String>,
    pub amount_minor: Option<i64>,
    pub currency: Option<String>,
    pub provider_customer_id: Option<String>,
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
            let mut facts = vec![NormalizedFact::Payment(payment.clone())];
            if payment.state == super::PaymentState::Succeeded {
                facts.push(NormalizedFact::CheckoutCompleted(
                    checkout_completed_from_document(
                        provider_name,
                        &object,
                        &payment.provider_payment_id,
                    )?,
                ));
            }
            Ok(facts)
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
/// Read an id that Stripe may deliver either as a bare string or as an
/// expanded object (`/payment_intent/id`, `/customer/id`).
fn expandable_id(object: &serde_json::Value, field: &str) -> Option<String> {
    let value = object.get(field)?;
    if let Some(id) = value.as_str() {
        return Some(id).filter(|id| !id.is_empty()).map(str::to_string);
    }
    value
        .get("id")
        .and_then(|id| id.as_str())
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

fn observed_from_document(
    provider_name: &str,
    object: &serde_json::Value,
    kind: &'static str,
) -> Result<ObservedPayment, String> {
    let id = string_at(object, "/id").filter(|id| !id.is_empty());
    let Some(mut id) = id else {
        return Err(format!("a {kind} event object carries no id"));
    };
    // A checkout session is a CONTAINER for the actual payment: the
    // PaymentIntent id is the money object a refund and the settlement
    // allocate against, so it is the id the engine must record (a second
    // `payment_intent.succeeded` event then dedupes on the same operation
    // id). The session id is only a fallback for an intent-less session.
    if kind == "checkout session" {
        if let Some(intent_id) = expandable_id(object, "payment_intent") {
            id = intent_id;
        }
    }
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

/// The activation's fact: the completed checkout session's payment id,
/// customer and OUR metadata. The tenant/plan/interval keys are the SAME
/// keys every ApexMail checkout writes (`metadata.tenant_id`,
/// `metadata.plan_name`, `metadata.interval`), so activation is
/// provider-blind. Missing payment/customer ids are represented as `None`
/// and the dispatch refuses/refunds — never invented.
fn checkout_completed_from_document(
    provider_name: &str,
    object: &serde_json::Value,
    provider_payment_id: &str,
) -> Result<CheckoutCompleted, String> {
    let checkout_id = string_at(object, "/id").filter(|id| !id.is_empty());
    let Some(checkout_id) = checkout_id else {
        return Err("a checkout session event object carries no id".to_string());
    };
    let amount_minor = object
        .get("amount_total")
        .and_then(|value| value.as_i64())
        .or_else(|| object.get("amount").and_then(|value| value.as_i64()));
    let currency = string_at(object, "/currency")
        .map(|text| text.trim().to_ascii_uppercase())
        .filter(|text| !text.is_empty());
    Ok(CheckoutCompleted {
        provider: provider_name.to_string(),
        provider_payment_id: provider_payment_id.to_string(),
        provider_checkout_id: checkout_id,
        tenant_id: metadata_string(object, "tenant_id"),
        plan_name: metadata_string(object, "plan_name"),
        interval: metadata_string(object, "interval"),
        amount_minor,
        currency,
        provider_customer_id: expandable_id(object, "customer"),
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

#[cfg(test)]
mod tests {
    use super::*;

    /// A completed checkout yields BOTH the settlement fact (the money) and
    /// the activation fact (the plan grant). The payment id is the
    /// PaymentIntent — the object a refund and the settlement allocate
    /// against — not the container session id.
    #[test]
    fn checkout_session_completed_yields_the_activation_fact() {
        let event = serde_json::json!({
            "id": "evt_1",
            "type": "checkout.session.completed",
            "data": { "object": {
                "id": "cs_test_1",
                "object": "checkout.session",
                "status": "complete",
                "amount_total": 2480,
                "currency": "eur",
                "payment_intent": "pi_test_1",
                "customer": "cus_test_1",
                "metadata": {
                    "tenant_id": "tenant_1",
                    "plan_name": "starter",
                    "interval": "monthly"
                }
            }}
        });
        let facts = normalize_event(PROVIDER, &event).expect("normalizes");
        assert_eq!(facts.len(), 2, "payment + completed-checkout fact");
        match &facts[0] {
            NormalizedFact::Payment(payment) => {
                assert_eq!(payment.provider_payment_id, "pi_test_1");
                assert_eq!(payment.state, super::super::PaymentState::Succeeded);
                assert_eq!(payment.tenant_id.as_deref(), Some("tenant_1"));
                assert_eq!(payment.amount_minor, Some(2_480));
            }
            other => panic!("expected a payment fact, got {other:?}"),
        }
        match &facts[1] {
            NormalizedFact::CheckoutCompleted(checkout) => {
                assert_eq!(checkout.provider_payment_id, "pi_test_1");
                assert_eq!(checkout.provider_checkout_id, "cs_test_1");
                assert_eq!(checkout.tenant_id.as_deref(), Some("tenant_1"));
                assert_eq!(checkout.plan_name.as_deref(), Some("starter"));
                assert_eq!(checkout.interval.as_deref(), Some("monthly"));
                assert_eq!(checkout.amount_minor, Some(2_480));
                assert_eq!(checkout.currency.as_deref(), Some("EUR"));
                assert_eq!(checkout.provider_customer_id.as_deref(), Some("cus_test_1"));
            }
            other => panic!("expected a completed-checkout fact, got {other:?}"),
        }
    }

    /// An expanded payment_intent object still resolves to its id (Stripe
    /// may deliver either shape).
    #[test]
    fn expanded_payment_intent_and_customer_objects_resolve_to_ids() {
        let event = serde_json::json!({
            "id": "evt_2",
            "type": "checkout.session.completed",
            "data": { "object": {
                "id": "cs_test_2",
                "status": "complete",
                "amount_total": 1000,
                "currency": "eur",
                "payment_intent": { "id": "pi_test_2", "object": "payment_intent" },
                "customer": { "id": "cus_test_2", "object": "customer" },
                "metadata": { "tenant_id": "t2", "plan_name": "pro" }
            }}
        });
        let facts = normalize_event(PROVIDER, &event).expect("normalizes");
        match &facts[1] {
            NormalizedFact::CheckoutCompleted(checkout) => {
                assert_eq!(checkout.provider_payment_id, "pi_test_2");
                assert_eq!(checkout.provider_customer_id.as_deref(), Some("cus_test_2"));
                assert_eq!(checkout.interval, None);
            }
            other => panic!("expected a completed-checkout fact, got {other:?}"),
        }
    }
}
