//! Stripe webhook signature verification and the REFETCH-FIRST event
//! pipeline (external audit item 15, re-audit of 30 Oct: "signed does not
//! mean current").
//!
//! # The HTTP route contract (STABLE — implement the route against exactly this)
//!
//! `POST /v1/webhooks/stripe`, body = the RAW request bytes (never
//! re-serialized JSON), header = `Stripe-Signature: t=<unix>,v1=<hex>`:
//!
//! 1. `verify_signature(&STRIPE_WEBHOOK_SECRET, &raw_body, header)` — reject
//!    with 400 on `Err` (a tampered/replayed/unparseable delivery must never
//!    enter the fact pipeline). The replay window is unchanged.
//! 2. Parse the body as `serde_json::Value`; the dedupe id is
//!    [`event_dedup_id`] (`event.id`, Stripe's `evt_…`). Dedup answers "did
//!    we process this TRIGGER"; the money facts are idempotent per provider
//!    object id, so a redelivery is acknowledged without a second effect.
//! 3. [`normalize_event`] treats the verified delivery as a TRIGGER ONLY:
//!    it extracts the OBJECT IDS the event names and calls the adapter's
//!    AUTHENTICATED fetch to obtain the authoritative object, then
//!    normalizes THAT object into facts. The signed body never supplies a
//!    state, amount, currency or attribution — a signed event whose body
//!    lies cannot settle anything.
//! 4. Dispatch each [`NormalizedFact`] through the SAME engine paths the
//!    Mollie webhook uses — never a Stripe-specific writer:
//!    * [`NormalizedFact::Payment`] -> `payments::engine::observe_payment`
//!      -> `verify_against_obligation` -> `settle_verified` (the
//!      verify-then-settle core);
//!    * [`NormalizedFact::Refund`] -> `payments::engine::record_refund_fact`;
//!    * [`NormalizedFact::Dispute`] -> `payments::engine::observe_dispute`;
//!    * [`NormalizedFact::Settlement`] -> `payments::engine::record_settlement_fact`.
//!
//! The fetch map per trigger:
//!
//! | event family | ids extracted | authenticated fetch |
//! |--------------|---------------|---------------------|
//! | `payment_intent.*` | PaymentIntent id | `fetch_payment_details` |
//! | `checkout.session.completed` | session id, PaymentIntent id | `fetch_payment_details` (the SESSION NEVER decides the money state) |
//! | `charge.refunded` / `charge.refund.updated` | refund id, payment id | `fetch_refund` |
//! | `charge.dispute.*` | dispute id, payment id (or charge id) | `resolve_charge_payment_id` (charge→payment) then `list_disputes` |
//! | `payout.paid` | payout id | `fetch_settlement` |
//!
//! Unknown event types stay ACCEPTED AND IGNORED (`Ok(vec![])`).

use chrono::Utc;
use hmac::{Hmac, Mac};
use sha2::Sha256;

use super::engine::ObservedPayment;
use super::stripe_provider::PROVIDER_NAME;
use super::{
    Dispute, FetchedPayment, PaymentProvider, PaymentState, ProviderError, Refund, Settlement,
};

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
    /// the Mollie completed-checkout path does. Only a fetched PaymentIntent
    /// in state `succeeded` produces this fact (the Session lifecycle never
    /// does).
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

/// One verified delivery reduced to the object IDS it names. A trigger is
/// never a fact: money, state and attribution always come from the adapter's
/// authenticated fetch.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum WebhookTrigger {
    /// A `payment_intent.*` event: fetch the PaymentIntent.
    Payment { payment_id: String },
    /// `checkout.session.completed`: fetch the session's PaymentIntent (the
    /// session's own `status`/`payment_status` are lifecycle hints, never
    /// settlement evidence).
    CheckoutSession {
        session_id: String,
        payment_intent_id: Option<String>,
    },
    /// A refund event: fetch the refund (the payment id is the fetch's
    /// fallback identity).
    Refund {
        refund_id: String,
        payment_id: Option<String>,
    },
    /// A dispute event: the dispute id plus the payment intent it attaches
    /// to (or the charge, resolved to the payment through an authenticated
    /// fetch).
    Dispute {
        dispute_id: String,
        payment_intent_id: Option<String>,
        charge_id: Option<String>,
    },
    /// `payout.paid`: fetch the payout.
    Settlement { payout_id: String },
}

impl WebhookTrigger {
    /// Reduce one verified event to the ids it names. `Ok(None)` is an
    /// unknown (accepted-and-ignored) event type; an `Err` is a KNOWN event
    /// whose identifiers are unreadable (the route dead-letters it for
    /// retry). This function NEVER reads a state, amount or currency.
    pub fn from_event(event: &serde_json::Value) -> Result<Option<Self>, String> {
        let event_type = event
            .get("type")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        let object = event
            .pointer("/data/object")
            .cloned()
            .unwrap_or(serde_json::Value::Null);
        let object_type = object
            .get("object")
            .and_then(|value| value.as_str())
            .unwrap_or_default();
        match event_type {
            "payment_intent.succeeded"
            | "payment_intent.processing"
            | "payment_intent.payment_failed" => {
                let payment_id = required_id(&object, "a payment intent event object")?;
                Ok(Some(WebhookTrigger::Payment { payment_id }))
            }
            "checkout.session.completed" => {
                let session_id = required_id(&object, "a checkout session event object")?;
                Ok(Some(WebhookTrigger::CheckoutSession {
                    session_id,
                    payment_intent_id: expandable_id(&object, "payment_intent"),
                }))
            }
            "charge.refunded" | "charge.refund.updated" => {
                // `charge.refund.updated` delivers the REFUND object;
                // `charge.refunded` delivers the CHARGE (its refunds list
                // names the newest refund). Either way only the id is read.
                let refund_id = if object_type == "refund" {
                    required_id(&object, "a refund event object")?
                } else {
                    string_at(&object, "/refunds/data/0/id")
                        .filter(|id| !id.is_empty())
                        .or_else(|| {
                            string_at(&object, "/latest_refund/id").filter(|id| !id.is_empty())
                        })
                        .ok_or_else(|| {
                            "a charge refund event carries no refund id; the refund cannot be \
                             fetched with provider authentication"
                                .to_string()
                        })?
                };
                Ok(Some(WebhookTrigger::Refund {
                    refund_id,
                    payment_id: expandable_id(&object, "payment_intent"),
                }))
            }
            "charge.dispute.created" | "charge.dispute.updated" | "charge.dispute.closed" => {
                let dispute_id = required_id(&object, "a dispute event object")?;
                Ok(Some(WebhookTrigger::Dispute {
                    dispute_id,
                    payment_intent_id: expandable_id(&object, "payment_intent"),
                    charge_id: expandable_id(&object, "charge"),
                }))
            }
            "payout.paid" => {
                let payout_id = required_id(&object, "a payout event object")?;
                Ok(Some(WebhookTrigger::Settlement { payout_id }))
            }
            // Accepted and ignored: Stripe may deliver event types this
            // integration never asked for (billing, connect, …).
            _ => Ok(None),
        }
    }
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

/// REFETCH-FIRST normalization: extract the verified delivery's object ids,
/// obtain each AUTHORITATIVE object with the adapter's authenticated fetch,
/// and normalize THAT object into neutral facts.
///
/// Unknown event types are ACCEPTED AND IGNORED (`Ok(vec![])`); a KNOWN
/// event whose ids or fetch are unusable is an `Err` so the route
/// dead-letters it for retry. A fetch failure is always an `Err` — the
/// signed body is never a fallback fact source.
pub async fn normalize_event(
    provider: &dyn PaymentProvider,
    event: &serde_json::Value,
) -> Result<Vec<NormalizedFact>, String> {
    let Some(trigger) = WebhookTrigger::from_event(event)? else {
        return Ok(Vec::new());
    };
    let provider_name = provider.provider_name();
    match trigger {
        WebhookTrigger::Payment { payment_id } => {
            let fetched = provider
                .fetch_payment_details(&payment_id)
                .await
                .map_err(|error| {
                    format!("the authenticated refetch of payment {payment_id} failed: {error}")
                })?;
            Ok(vec![NormalizedFact::Payment(observed_from_fetched(
                &fetched,
            ))])
        }
        WebhookTrigger::CheckoutSession {
            session_id,
            payment_intent_id,
        } => {
            // Item 2: the SESSION lifecycle never means money Succeeded. The
            // fact's money state is the fetched PaymentIntent's state; with
            // no PaymentIntent yet the flow is still processing and the fact
            // is Processing (it can never activate or settle).
            let Some(payment_intent_id) = payment_intent_id else {
                return Ok(vec![NormalizedFact::Payment(ObservedPayment {
                    provider: provider_name.to_string(),
                    provider_payment_id: session_id,
                    state: PaymentState::Processing,
                    amount_minor: None,
                    currency: None,
                    // No authenticated object exists to attribute yet.
                    tenant_id: None,
                    obligation_ref: None,
                    purpose: "webhook",
                })]);
            };
            let fetched = provider
                .fetch_payment_details(&payment_intent_id)
                .await
                .map_err(|error| {
                    format!(
                        "the authenticated refetch of checkout session {session_id}'s payment \
                         {payment_intent_id} failed: {error}"
                    )
                })?;
            let mut facts = vec![NormalizedFact::Payment(observed_from_fetched(&fetched))];
            // The settlement evidence is the PaymentIntent. Only a fetched
            // `succeeded` intent produces the activation fact; a `processing`
            // or `requires_action` one stays a Payment fact and activates
            // nothing.
            if fetched.payment.state == PaymentState::Succeeded {
                facts.push(NormalizedFact::CheckoutCompleted(
                    checkout_completed_from_fetched(&session_id, &fetched),
                ));
            }
            Ok(facts)
        }
        WebhookTrigger::Refund {
            refund_id,
            payment_id,
        } => {
            let Some(payment_id) = payment_id.filter(|id| !id.is_empty()) else {
                return Err(format!(
                    "refund event names refund {refund_id} with no payment intent; the refund \
                     cannot be fetched with provider authentication"
                ));
            };
            let refund = provider
                .fetch_refund(&payment_id, &refund_id)
                .await
                .map_err(|error| {
                    format!("the authenticated refetch of refund {refund_id} failed: {error}")
                })?;
            Ok(vec![NormalizedFact::Refund(refund)])
        }
        WebhookTrigger::Dispute {
            dispute_id,
            payment_intent_id,
            charge_id,
        } => {
            // Item 1: a dispute event names its charge; the payment intent
            // the ledger keys on is resolved with an AUTHENTICATED charge
            // fetch, never assumed from the body.
            let payment_id = match payment_intent_id.filter(|id| !id.is_empty()) {
                Some(payment_id) => payment_id,
                None => match charge_id.filter(|id| !id.is_empty()) {
                    Some(charge_id) => provider
                        .resolve_charge_payment_id(&charge_id)
                        .await
                        .map_err(|error| {
                            format!(
                                "resolving dispute {dispute_id}'s charge {charge_id} to a \
                                 payment failed: {error}"
                            )
                        })?
                        .ok_or_else(|| {
                            format!(
                                "dispute {dispute_id}: charge {charge_id} carries no payment \
                                 intent; the dispute cannot be attributed"
                            )
                        })?,
                    None => {
                        return Err(format!(
                            "dispute {dispute_id} names neither a payment intent nor a charge"
                        ))
                    }
                },
            };
            let disputes = provider.list_disputes(&payment_id).await.map_err(|error| {
                format!("the authenticated dispute fetch for {payment_id} failed: {error}")
            })?;
            // The fetched object is the fact source: a dispute the provider
            // does not return is not recorded (and the delivery retries).
            let dispute = disputes
                .into_iter()
                .find(|dispute| dispute.provider_dispute_id == dispute_id)
                .ok_or_else(|| {
                    format!(
                        "dispute {dispute_id} is not visible on the authenticated payment \
                         {payment_id}; refusing to record an unverified dispute"
                    )
                })?;
            Ok(vec![NormalizedFact::Dispute(dispute)])
        }
        WebhookTrigger::Settlement { payout_id } => {
            let settlement = provider
                .fetch_settlement(&payout_id)
                .await
                .map_err(|error| {
                    format!("the authenticated refetch of payout {payout_id} failed: {error}")
                })?;
            Ok(vec![NormalizedFact::Settlement(settlement)])
        }
    }
}

/// The neutral payment fact for one AUTHENTICATED object. Tenant/obligation
/// attribution rides the object's own metadata (`metadata.tenant_id`,
/// `metadata.reference` — the keys every create writes on the session AND
/// the PaymentIntent).
fn observed_from_fetched(fetched: &FetchedPayment) -> ObservedPayment {
    ObservedPayment {
        provider: fetched.payment.provider.clone(),
        provider_payment_id: fetched.payment.provider_payment_id.clone(),
        state: fetched.payment.state,
        amount_minor: Some(fetched.payment.amount_minor),
        currency: Some(fetched.payment.currency.clone()),
        tenant_id: metadata_string(&fetched.metadata, "tenant_id"),
        obligation_ref: metadata_string(&fetched.metadata, "reference"),
        purpose: "webhook",
    }
}

/// The activation's fact, built from the FETCHED PaymentIntent (money, state,
/// customer) and the session id the trigger named. The tenant/plan/interval
/// keys are the same metadata the checkout mirrored onto the PaymentIntent
/// (item 9); missing ones stay `None` and the dispatch refuses/refunds —
/// never invented.
fn checkout_completed_from_fetched(
    session_id: &str,
    fetched: &FetchedPayment,
) -> CheckoutCompleted {
    CheckoutCompleted {
        provider: fetched.payment.provider.clone(),
        provider_payment_id: fetched.payment.provider_payment_id.clone(),
        provider_checkout_id: session_id.to_string(),
        tenant_id: metadata_string(&fetched.metadata, "tenant_id"),
        plan_name: metadata_string(&fetched.metadata, "plan_name"),
        interval: metadata_string(&fetched.metadata, "interval"),
        amount_minor: Some(fetched.payment.amount_minor),
        currency: Some(fetched.payment.currency.clone()),
        provider_customer_id: fetched.provider_customer_id.clone(),
    }
}

/// A required object id: the event's identifier is the ONE thing a trigger
/// may trust from the body (it is how the authenticated object is named).
fn required_id(object: &serde_json::Value, kind: &str) -> Result<String, String> {
    string_at(object, "/id")
        .filter(|id| !id.is_empty())
        .ok_or_else(|| format!("{kind} carries no id"))
}

/// Read an id that Stripe may deliver either as a bare string or as an
/// expanded object (`/payment_intent` vs `/payment_intent/id`).
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

fn string_at(document: &serde_json::Value, pointer: &str) -> Option<String> {
    document
        .pointer(pointer)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

fn metadata_string(metadata: &serde_json::Value, key: &str) -> Option<String> {
    metadata
        .get(key)
        .and_then(|value| value.as_str())
        .map(str::to_string)
        .filter(|text| !text.is_empty())
}

/// The adapter's stable name, re-exported for the route's dispatch call.
pub const PROVIDER: &str = PROVIDER_NAME;

#[cfg(test)]
mod tests {
    use super::*;

    /// Trigger extraction reads ONLY ids: a payment event's amount/status in
    /// the body never reaches a fact (that is the whole refetch-first
    /// contract; the fetched object is the only money source).
    #[test]
    fn payment_triggers_extract_only_the_object_id() {
        let event = serde_json::json!({
            "id": "evt_1",
            "type": "payment_intent.succeeded",
            "data": { "object": {
                "id": "pi_body",
                "object": "payment_intent",
                "status": "succeeded",
                "amount": 1,
                "currency": "xxx"
            }}
        });
        assert_eq!(
            WebhookTrigger::from_event(&event).expect("trigger"),
            Some(WebhookTrigger::Payment {
                payment_id: "pi_body".to_string()
            })
        );
    }

    #[test]
    fn checkout_trigger_carries_the_session_and_intent_ids() {
        let event = serde_json::json!({
            "id": "evt_2",
            "type": "checkout.session.completed",
            "data": { "object": {
                "id": "cs_1",
                "object": "checkout.session",
                "status": "complete",
                "payment_status": "unpaid",
                "amount_total": 1,
                "payment_intent": { "id": "pi_1", "object": "payment_intent" }
            }}
        });
        assert_eq!(
            WebhookTrigger::from_event(&event).expect("trigger"),
            Some(WebhookTrigger::CheckoutSession {
                session_id: "cs_1".to_string(),
                payment_intent_id: Some("pi_1".to_string()),
            })
        );
    }

    #[test]
    fn refund_triggers_read_the_refund_id_from_charge_or_refund_shapes() {
        let charge_event = serde_json::json!({
            "type": "charge.refunded",
            "data": { "object": {
                "id": "ch_1",
                "object": "charge",
                "payment_intent": "pi_1",
                "refunds": { "data": [ { "id": "re_1", "object": "refund" } ] }
            }}
        });
        assert_eq!(
            WebhookTrigger::from_event(&charge_event).expect("trigger"),
            Some(WebhookTrigger::Refund {
                refund_id: "re_1".to_string(),
                payment_id: Some("pi_1".to_string()),
            })
        );
        let refund_event = serde_json::json!({
            "type": "charge.refund.updated",
            "data": { "object": {
                "id": "re_2",
                "object": "refund",
                "payment_intent": "pi_2",
                "amount": 1
            }}
        });
        assert_eq!(
            WebhookTrigger::from_event(&refund_event).expect("trigger"),
            Some(WebhookTrigger::Refund {
                refund_id: "re_2".to_string(),
                payment_id: Some("pi_2".to_string()),
            })
        );
    }

    #[test]
    fn dispute_triggers_carry_the_charge_for_authenticated_resolution() {
        let event = serde_json::json!({
            "type": "charge.dispute.created",
            "data": { "object": {
                "id": "dp_1",
                "object": "dispute",
                "charge": "ch_1",
                "amount": 1
            }}
        });
        assert_eq!(
            WebhookTrigger::from_event(&event).expect("trigger"),
            Some(WebhookTrigger::Dispute {
                dispute_id: "dp_1".to_string(),
                payment_intent_id: None,
                charge_id: Some("ch_1".to_string()),
            })
        );
    }

    #[test]
    fn payout_and_unknown_events_are_id_only_and_accepted() {
        let payout = serde_json::json!({
            "type": "payout.paid",
            "data": { "object": { "id": "po_1", "object": "payout", "amount": 1 } }
        });
        assert_eq!(
            WebhookTrigger::from_event(&payout).expect("trigger"),
            Some(WebhookTrigger::Settlement {
                payout_id: "po_1".to_string()
            })
        );
        for event_type in [
            "invoice.created",
            "customer.subscription.created",
            "charge.succeeded",
            "totally.unknown.event",
        ] {
            let event = serde_json::json!({
                "type": event_type,
                "data": { "object": { "id": "x", "amount": 999 } }
            });
            assert_eq!(
                WebhookTrigger::from_event(&event).expect("accepted"),
                None,
                "{event_type} must be accepted and ignored"
            );
        }
    }

    #[test]
    fn a_known_event_without_ids_fails_the_trigger() {
        let no_id = serde_json::json!({
            "type": "payment_intent.succeeded",
            "data": { "object": { "status": "succeeded", "amount": 1 } }
        });
        assert!(WebhookTrigger::from_event(&no_id).is_err());
        let no_refund = serde_json::json!({
            "type": "charge.refunded",
            "data": { "object": { "id": "ch_1", "object": "charge" } }
        });
        assert!(WebhookTrigger::from_event(&no_refund).is_err());
    }

    #[test]
    fn the_event_dedup_id_is_the_provider_event_id() {
        let event = serde_json::json!({ "id": "evt_conf_1", "type": "payout.paid" });
        assert_eq!(event_dedup_id(&event).as_deref(), Some("evt_conf_1"));
        assert_eq!(event_dedup_id(&serde_json::json!({ "type": "x" })), None);
    }
}
