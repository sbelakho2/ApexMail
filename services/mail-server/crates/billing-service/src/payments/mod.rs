//! The provider-neutral payments domain (external audit, P0-A, step 1 of the
//! 18-step order; steps 5-8 added the execution ledger and the
//! verify-then-settle engine, see [`engine`]).
//!
//! Everything here describes payments the way the BILLING ENGINE understands
//! them: a payment has a normalized state machine, a minor-unit amount, an
//! ISO 4217 currency and a provider-assigned opaque id. Nothing in this
//! module knows any provider's id grammar: the neutral vocabulary never
//! embeds a provider object prefix, and a unit test pins that property by
//! scanning this file's own source. The adapters are
//! [`mollie_provider::MollieProvider`] and [`stripe_provider::StripeProvider`]
//! (Stripe is PAYMENTS-ONLY: no provider-owned subscription objects —
//! ApexMail owns scheduling), selected through [`registry::from_env`].
//!
//! The trait follows repository patterns: callers hand over neutral request
//! records and receive neutral facts; every fetch is an AUTHENTICATED
//! provider fetch (the engine never trusts a wire notification body), and
//! the idempotency key is part of the request identity because a retry is a
//! provider-side replay contract, not a caller afterthought.
//!
//! Amounts are integer minor units end to end (the crate's money invariant);
//! no float participates anywhere in this module.
//!
//! Couplings deliberately KEPT this round (pure inversion of control,
//! behavior identical) are inventoried in `src/payments/NEUTRALITY_DEBT.md`,
//! each naming the follow-up step (5-10) that removes it.

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};

/// The shared provider conformance harness (audit step 9, expanded in the
/// eighth pass): one eighteen-arm matrix every adapter must pass, plus the
/// scriptable [`conformance::ConformanceProvider`] double used to prove the
/// harness has teeth.
pub mod conformance;
pub mod engine;
pub mod mollie_provider;
pub mod registry;
pub mod stripe_events;
pub mod stripe_provider;

pub use registry::{from_env, kind_from_env, RegistryError, SUPPORTED_PROVIDERS};

// ---------------------------------------------------------------------------
// Neutral state machines
// ---------------------------------------------------------------------------

/// The normalized life of one payment attempt.
///
/// The variant set is provider-union: `RequiresAction` exists for providers
/// whose checkout can park on a customer action; an adapter whose provider
/// has no such concept simply never emits it.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum PaymentState {
    /// Created, nothing decided yet.
    Pending,
    /// Parked on a customer action the provider cannot perform for them.
    RequiresAction,
    /// The provider is moving the money; no outcome yet.
    Processing,
    /// The money arrived.
    Succeeded,
    /// The provider refused the charge; the money will not arrive.
    Failed,
    /// Abandoned before an outcome (customer abort or expiry).
    Canceled,
}

/// The normalized life of one refund.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum RefundState {
    /// Accepted, not yet moving.
    Pending,
    /// The provider is returning the money.
    Processing,
    /// The customer has the money back.
    Succeeded,
    /// The refund will not happen (refused, failed or withdrawn).
    Failed,
}

/// The normalized life of one stored payment credential (a saved,
/// customer-consented chargeable method).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum CredentialState {
    /// Chargeable now.
    Active,
    /// Was chargeable, no longer is (lapsed by time).
    Expired,
    /// Not chargeable: never confirmed, refused, or revoked.
    Failed,
}

/// What kind of fact a provider event carries. The event pipeline (a later
/// step of the staged plan) consumes these; the neutral type exists now so
/// adapters have a target to normalize into.
///
/// Recurring-schedule facts are deliberately ABSENT (beta authority
/// inversion): core renewal is ApexMail-local, so no provider schedule
/// lifecycle exists for an adapter to report.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum ProviderEventKind {
    PaymentStateChange,
    RefundStateChange,
    DisputeOpened,
    DisputeClosed,
    SettlementCompleted,
    Other,
}

// ---------------------------------------------------------------------------
// Neutral facts
// ---------------------------------------------------------------------------

/// One payment as the billing engine models it.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Payment {
    /// The adapter's [`PaymentProvider::provider_name`] value.
    pub provider: String,
    /// The provider-assigned payment id, opaque to everything above the
    /// adapter.
    pub provider_payment_id: String,
    pub state: PaymentState,
    /// Integer minor units (cents). Absent facts are never coerced to zero
    /// by fetches; request echoes carry the requested amount.
    pub amount_minor: i64,
    pub currency: String,
    pub created_at: Option<DateTime<Utc>>,
}

/// One recorded charge attempt against an obligation. Persisted by the
/// neutral ledger (migration 279); produced by adapters as facts arrive.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentAttempt {
    pub provider: String,
    pub provider_payment_id: String,
    pub state: PaymentState,
    pub amount_minor: i64,
    pub currency: String,
    pub created_at: Option<DateTime<Utc>>,
}

/// A stored, customer-consented chargeable method bound to a provider
/// customer object.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct PaymentCredential {
    pub provider: String,
    /// The provider customer object the method belongs to.
    pub provider_customer_id: String,
    /// The provider method object id, opaque above the adapter.
    pub provider_method_id: String,
    pub state: CredentialState,
    /// Provider method family (for operator display only, never a decision
    /// input).
    pub method_kind: Option<String>,
    pub created_at: Option<DateTime<Utc>>,
}

/// A hosted checkout the customer must complete in a browser.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Checkout {
    pub provider: String,
    pub provider_payment_id: String,
    pub state: PaymentState,
    /// Where the customer completes the payment; a provider that confirms
    /// synchronously may have none.
    pub redirect_url: Option<String>,
    pub amount_minor: i64,
    pub currency: String,
    pub created_at: Option<DateTime<Utc>>,
}

/// One refund of a payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Refund {
    pub provider: String,
    pub provider_refund_id: String,
    pub provider_payment_id: String,
    pub state: RefundState,
    pub amount_minor: i64,
    pub currency: String,
    pub created_at: Option<DateTime<Utc>>,
}

/// The normalized life of one dispute (chargeback). The set is the
/// provider-union minimum the reconciliation needs: a dispute is opened,
/// then it is either lost (the money leaves) or won/reversed (the money
/// comes back). A provider that models more states maps them onto these
/// three; the neutral ledger fact records which of the three landed.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum DisputeState {
    /// The dispute is open: evidence may still change the outcome.
    Opened,
    /// The dispute was decided against us: the money is (being) taken back.
    Lost,
    /// The dispute was decided for us / reversed: the money stays or
    /// returns.
    Won,
}

/// One dispute (chargeback) against a payment.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Dispute {
    pub provider: String,
    pub provider_dispute_id: String,
    pub provider_payment_id: String,
    /// The normalized dispute state (the generic reconciliation keys on
    /// this: opened records the fact, lost debits, won restores).
    pub state: DisputeState,
    pub amount_minor: i64,
    pub currency: String,
    pub reason: Option<String>,
    pub opened_at: Option<DateTime<Utc>>,
}

/// One payout settlement from the provider.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Settlement {
    pub provider: String,
    pub provider_settlement_id: String,
    pub amount_minor: i64,
    pub currency: String,
    pub settled_at: Option<DateTime<Utc>>,
}

/// The neutral trait-object handles domain modules may hold: a shared
/// provider (renewal worker, request state) and a borrowed one (a function
/// that only calls the boundary). Naming these aliases keeps the neutral
/// vocabulary OUTSIDE the adapter layer free of `dyn ...Provider`
/// construction syntax (the neutrality lint reserves it for `payments/`).
pub type SharedProvider = std::sync::Arc<dyn PaymentProvider>;
pub type ProviderRef<'a> = &'a dyn PaymentProvider;

/// One normalized provider event fact. This is the promotion target of the
/// webhook normalizer nucleus; adapters emit these once the event pipeline
/// lands (a later staged step).
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ProviderEvent {
    pub provider: String,
    /// The provider's dedupe id for the event, when one exists.
    pub event_id: Option<String>,
    pub kind: ProviderEventKind,
    pub provider_payment_id: Option<String>,
    pub provider_refund_id: Option<String>,
    pub amount_minor: Option<i64>,
    pub currency: Option<String>,
    pub occurred_at: Option<DateTime<Utc>>,
}

// ---------------------------------------------------------------------------
// Provider capabilities
// ---------------------------------------------------------------------------

/// What one provider can do. Domain code branches on these flags, never on
/// the provider name.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ProviderCapabilities {
    /// The provider can host a customer-completed checkout page.
    pub hosted_checkout: bool,
    /// The provider can charge a stored credential on demand.
    pub saved_method_charging: bool,
    /// The provider can return money for a payment.
    pub refunds: bool,
    /// The provider surfaces disputes (chargebacks) as RETRIEVABLE objects:
    /// [`PaymentProvider::list_disputes`] answers with real facts. A
    /// provider whose wire offers no dispute retrieval must declare false
    /// AND refuse `list_disputes` visibly (`Err`), never answer a silent
    /// empty list — silence would hide chargebacks from reconciliation.
    pub disputes: bool,
    /// The provider settles payouts that must be reconciled.
    pub payouts: bool,
    /// The provider honors an idempotency key on mutating calls.
    pub idempotency_keys: bool,
}

// ---------------------------------------------------------------------------
// Neutral requests
// ---------------------------------------------------------------------------

/// Create a hosted checkout the customer completes in a browser.
#[derive(Debug, Clone)]
pub struct CheckoutRequest {
    pub amount_minor: i64,
    pub currency: String,
    pub description: String,
    /// Where the provider returns the customer's browser afterwards.
    pub redirect_url: Option<String>,
    /// Override the webhook callback the adapter would otherwise derive.
    pub webhook_url: Option<String>,
    pub metadata: serde_json::Value,
    /// Optional provider method family hint (provider vocabulary, passed
    /// through verbatim by the adapter).
    pub method_hint: Option<String>,
    pub provider_customer_id: Option<String>,
    pub provider_method_id: Option<String>,
    /// Ask the provider to capture a REUSABLE method for later off-session
    /// charges (V34). Mollie uses the `first` sequence (a mandate); Stripe
    /// sets `payment_intent_data[setup_future_usage]=off_session`. Without
    /// this the renewal worker has nothing to charge.
    pub save_method: bool,
    pub idempotency_key: String,
}

/// Create (or resolve) a provider customer object bound to a tenant.
#[derive(Debug, Clone)]
pub struct CustomerRequest {
    pub tenant_id: String,
    pub name: String,
    pub email: String,
    pub idempotency_key: String,
}

/// The provider customer object a tenant's saved methods belong to.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ProviderCustomer {
    pub provider: String,
    pub provider_customer_id: String,
}

/// The reusable credential a completed checkout captured (the pair the
/// renewal worker charges off-session).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SavedMethodRef {
    pub provider_customer_id: String,
    pub provider_method_id: String,
}

/// Charge a stored credential now, with no browser involved.
#[derive(Debug, Clone)]
pub struct SavedMethodCharge {
    pub provider_customer_id: String,
    pub provider_method_id: String,
    pub amount_minor: i64,
    pub currency: String,
    pub description: String,
    pub metadata: serde_json::Value,
    pub idempotency_key: String,
}

/// Return money for a payment.
#[derive(Debug, Clone)]
pub struct RefundRequest {
    pub provider_payment_id: String,
    pub amount_minor: i64,
    pub currency: String,
    pub description: String,
    pub idempotency_key: String,
}

// ---------------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------------

/// Every adapter failure, normalized. `Unavailable` means retry later;
/// everything else is a refusal the caller must treat as a decision, never
/// as a transient state.
#[derive(Debug, Clone, thiserror::Error)]
pub enum ProviderError {
    /// Transport / 5xx / 429: retry later, never a business refusal.
    #[error("the payment provider is unavailable (retry later): {0}")]
    Unavailable(String),
    /// 4xx with a provider explanation.
    #[error("the payment provider refused the request ({status}): {detail}")]
    Refused { status: u16, detail: String },
    #[error("the payment provider returned a body this engine cannot read: {0}")]
    Malformed(String),
    #[error("the payment provider is not configured: {0}")]
    Config(String),
    #[error("no {kind} object {id} exists at the payment provider")]
    NotFound { kind: &'static str, id: String },
    /// An unmapped provider status: the engine refuses to GUESS a money
    /// state. This is fail-closed by construction.
    #[error("unmapped provider {kind} status {status:?}; refusing to guess a money state")]
    UnmappedStatus { kind: &'static str, status: String },
}

// ---------------------------------------------------------------------------
// The boundary
// ---------------------------------------------------------------------------

/// The one interface the billing engine speaks to a payment processor.
///
/// The first seven methods are the audit-mandated core. The boundary is
/// deliberately FINITE (beta authority inversion, external audit #8): core
/// subscription renewal is an APEXMAIL-LOCAL scheduler (plan_billing's
/// `renew_due_subscriptions` — local invoice first, then a claimed
/// `charge_saved_method` attempt per period), so the trait carries NO
/// recurring-schedule surface. A PSP adapter MAY expose provider-specific
/// recurring functionality for an unrelated feature, but core renewal never
/// depends on it — and a dead abstraction is debt too, so none is kept here.
#[async_trait::async_trait]
pub trait PaymentProvider: Send + Sync {
    /// The adapter's stable name (a config value, not a class name).
    fn provider_name(&self) -> &'static str;

    /// What this provider can do; domain code branches on these flags.
    fn capabilities(&self) -> ProviderCapabilities;

    /// Create a hosted checkout for a customer to complete in a browser.
    async fn create_checkout(&self, request: CheckoutRequest) -> Result<Checkout, ProviderError>;

    /// Create (or resolve) the provider customer object a tenant's saved
    /// methods belong to. Providers that create the customer as part of the
    /// checkout itself may refuse; providers that need a customer before the
    /// checkout (Mollie mandates) implement it. The caller persists the
    /// returned id in the neutral `payment_provider_customers` table.
    async fn ensure_customer(
        &self,
        request: CustomerRequest,
    ) -> Result<ProviderCustomer, ProviderError> {
        let _ = request;
        Err(ProviderError::Config(format!(
            "{}: provider customers are not created before checkout by this adapter",
            self.provider_name()
        )))
    }

    /// The reusable credential a COMPLETED checkout captured, for the
    /// activation to store in `payment_credentials`. Providers whose payment
    /// fact already carries the method (Mollie's mandate) answer `Ok(None)`
    /// and the caller uses the fact's own ids.
    async fn fetch_saved_method_for_payment(
        &self,
        provider_payment_id: &str,
    ) -> Result<Option<SavedMethodRef>, ProviderError> {
        let _ = provider_payment_id;
        Ok(None)
    }

    /// Charge a stored credential now (no browser, no checkout page).
    async fn charge_saved_method(
        &self,
        request: SavedMethodCharge,
    ) -> Result<Payment, ProviderError>;

    /// Return money for a payment. Settling may be asynchronous; the
    /// returned [`Refund`] carries the provider id the reconciliation will
    /// name.
    async fn refund(&self, request: RefundRequest) -> Result<Refund, ProviderError>;

    /// Fetch one payment object WITH PROVIDER AUTHENTICATION. This is the
    /// only source of truth for a payment state; notification bodies are
    /// never trusted.
    async fn fetch_payment_object(
        &self,
        provider_payment_id: &str,
    ) -> Result<Payment, ProviderError>;

    /// AUTHENTICATED provider-side search for a charge by the idempotency
    /// key the caller sent with it. The stale-claim reconciliation's fact
    /// source: when a claimed charge's response was lost, the engine asks
    /// the provider what became of the operation BEFORE it decides
    /// anything (a lost webhook can no longer strand money or trigger a
    /// blind second charge).
    ///
    /// # Contract (absence must be PROVABLE)
    ///
    /// * `Ok(Some(payment))` — the provider knows this charge; the payment
    ///   carries its authoritative state and id.
    /// * `Ok(None)` — the provider PROVABLY does not know this charge:
    ///   the search space was enumerated COMPLETELY and the key is not in
    ///   it. Only providers with real search semantics (a complete
    ///   enumeration or a keyed lookup) may return `None`.
    /// * `Err(..)` — the answer is UNKNOWN (truncated listing, search not
    ///   offered, transport failure). A truncated or partial listing is
    ///   ALWAYS `Err`, never `None`: guessing absence double-charges.
    async fn search_payment_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<Payment>, ProviderError>;

    /// Fetch one refund object WITH PROVIDER AUTHENTICATION.
    async fn fetch_refund(
        &self,
        provider_payment_id: &str,
        provider_refund_id: &str,
    ) -> Result<Refund, ProviderError>;

    /// Revoke a stored credential so it can never be charged again. The
    /// only provider-side guarantee that a canceled account stops being
    /// debited.
    async fn revoke_saved_method(
        &self,
        provider_customer_id: &str,
        provider_method_id: &str,
    ) -> Result<(), ProviderError>;

    /// Fetch one payout settlement WITH PROVIDER AUTHENTICATION (the
    /// payout-reconciliation fact source; capabilities().payouts).
    async fn fetch_settlement(
        &self,
        provider_settlement_id: &str,
    ) -> Result<Settlement, ProviderError>;

    /// List payout settlements newest-first from the provider.
    async fn list_settlements(&self) -> Result<Vec<Settlement>, ProviderError>;

    /// Enumerate the disputes (chargebacks) recorded against one payment,
    /// WITH PROVIDER AUTHENTICATION ([`ProviderCapabilities::disputes`]).
    /// A provider whose wire offers no dispute retrieval must refuse
    /// visibly with `Err` — never a silent empty list, which would hide a
    /// chargeback from the reconciliation.
    async fn list_disputes(&self, provider_payment_id: &str)
        -> Result<Vec<Dispute>, ProviderError>;
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The neutrality gate: NOTHING in the neutral module's source may name
    /// a provider id grammar. The forbidden prefixes are assembled at run
    /// time from bare stems so this test's own source cannot contain the
    /// literals it bans. The neutral module is the vocabulary contract every
    /// future adapter (steps 11-18) will be written against; if one of these
    /// prefixes ever appears here, the abstraction has already leaked.
    #[test]
    fn neutral_source_never_names_a_provider_id_grammar() {
        let separator: char = '_';
        let banned_stems = ["pi", "pm", "cus", "tr", "mdt", "sub"];
        let banned: Vec<String> = banned_stems
            .iter()
            .map(|stem| format!("{stem}{separator}"))
            .collect();
        let neutral_module_source = include_str!("mod.rs");
        let registry_source = include_str!("registry.rs");
        for source in [neutral_module_source, registry_source] {
            for prefix in &banned {
                assert!(
                    !source.contains(prefix.as_str()),
                    "the neutral payments module must never name a provider id grammar \
                     (found {prefix:?}); provider vocabulary belongs to the adapter layer"
                );
            }
        }
    }

    #[test]
    fn payment_states_serialize_camel_case_and_round_trip() {
        let states = [
            PaymentState::Pending,
            PaymentState::RequiresAction,
            PaymentState::Processing,
            PaymentState::Succeeded,
            PaymentState::Failed,
            PaymentState::Canceled,
        ];
        let encoded: Vec<String> = states
            .iter()
            .map(|state| serde_json::to_string(state).expect("encode state"))
            .collect();
        let mut distinct = encoded.clone();
        distinct.sort();
        distinct.dedup();
        assert_eq!(
            distinct.len(),
            encoded.len(),
            "state encodings must be unique"
        );
        assert_eq!(encoded[0], "\"pending\"");
        assert_eq!(encoded[1], "\"requiresAction\"");
        for (state, text) in states.iter().zip(&encoded) {
            let decoded: PaymentState = serde_json::from_str(text).expect("decode state");
            assert_eq!(&decoded, state);
        }
    }

    #[test]
    fn refund_and_credential_states_round_trip_camel_case() {
        let refunds = [
            RefundState::Pending,
            RefundState::Processing,
            RefundState::Succeeded,
            RefundState::Failed,
        ];
        for state in refunds {
            let text = serde_json::to_string(&state).expect("encode refund state");
            assert_eq!(
                serde_json::from_str::<RefundState>(&text).expect("decode refund state"),
                state
            );
        }
        assert_eq!(
            serde_json::to_string(&CredentialState::Active).expect("encode"),
            "\"active\""
        );
        assert_eq!(
            serde_json::to_string(&CredentialState::Expired).expect("encode"),
            "\"expired\""
        );
        assert_eq!(
            serde_json::to_string(&CredentialState::Failed).expect("encode"),
            "\"failed\""
        );
        // The recurring-schedule state machine is retired (the local renewal
        // authority): no provider schedule vocabulary round-trips here.
    }

    #[test]
    fn neutral_facts_round_trip_through_serde_camel_case() {
        let payment = Payment {
            provider: "mollie".into(),
            provider_payment_id: "opaque-provider-id".into(),
            state: PaymentState::RequiresAction,
            amount_minor: 1234,
            currency: "EUR".into(),
            created_at: Some(
                DateTime::parse_from_rfc3339("2026-10-29T12:00:00Z")
                    .expect("fixed timestamp")
                    .with_timezone(&Utc),
            ),
        };
        let value = serde_json::to_value(&payment).expect("encode payment");
        // The camelCase contract the neutral ledger (migration 279) and any
        // future provider-union API will read.
        assert!(value.get("providerPaymentId").is_some());
        assert!(value.get("amountMinor").is_some());
        assert_eq!(value["state"], "requiresAction");
        assert_eq!(
            serde_json::from_value::<Payment>(value).expect("decode payment"),
            payment
        );

        let refund = Refund {
            provider: "mollie".into(),
            provider_refund_id: "opaque-refund-id".into(),
            provider_payment_id: "opaque-provider-id".into(),
            state: RefundState::Processing,
            amount_minor: 500,
            currency: "EUR".into(),
            created_at: None,
        };
        let value = serde_json::to_value(&refund).expect("encode refund");
        assert!(value.get("providerRefundId").is_some());
        assert_eq!(
            serde_json::from_value::<Refund>(value).expect("decode refund"),
            refund
        );

        let dispute = Dispute {
            provider: "mollie".into(),
            provider_dispute_id: "opaque-dispute-id".into(),
            provider_payment_id: "opaque-provider-id".into(),
            state: DisputeState::Opened,
            amount_minor: 1234,
            currency: "EUR".into(),
            reason: Some("fraudulent".into()),
            opened_at: None,
        };
        let value = serde_json::to_value(&dispute).expect("encode dispute");
        assert_eq!(value["state"], "opened");
        assert_eq!(
            serde_json::from_value::<Dispute>(value).expect("decode dispute"),
            dispute
        );
        let lost: DisputeState = serde_json::from_str("\"lost\"").expect("decode");
        let won: DisputeState = serde_json::from_str("\"won\"").expect("decode");
        assert_eq!(lost, DisputeState::Lost);
        assert_eq!(won, DisputeState::Won);

        let credential = PaymentCredential {
            provider: "mollie".into(),
            provider_customer_id: "opaque-customer-id".into(),
            provider_method_id: "opaque-method-id".into(),
            state: CredentialState::Active,
            method_kind: Some("direct-debit".into()),
            created_at: None,
        };
        let value = serde_json::to_value(&credential).expect("encode credential");
        assert!(value.get("providerMethodId").is_some());
        assert_eq!(
            serde_json::from_value::<PaymentCredential>(value).expect("decode credential"),
            credential
        );

        let event = ProviderEvent {
            provider: "mollie".into(),
            event_id: Some("opaque-event-id".into()),
            kind: ProviderEventKind::PaymentStateChange,
            provider_payment_id: Some("opaque-provider-id".into()),
            provider_refund_id: None,
            amount_minor: Some(1234),
            currency: Some("EUR".into()),
            occurred_at: None,
        };
        let value = serde_json::to_value(&event).expect("encode event");
        assert_eq!(value["kind"], "paymentStateChange");
        assert_eq!(
            serde_json::from_value::<ProviderEvent>(value).expect("decode event"),
            event
        );
    }

    #[test]
    fn provider_capabilities_are_six_independent_flags() {
        let all_off = ProviderCapabilities {
            hosted_checkout: false,
            saved_method_charging: false,
            refunds: false,
            disputes: false,
            payouts: false,
            idempotency_keys: false,
        };
        assert!(!all_off.hosted_checkout);
        let refunds_only = ProviderCapabilities {
            refunds: true,
            ..all_off
        };
        assert!(refunds_only.refunds);
        assert!(!refunds_only.payouts);
    }

    #[test]
    fn provider_error_is_fail_closed_on_unmapped_status() {
        let error = ProviderError::UnmappedStatus {
            kind: "payment",
            status: "brand-new-status".into(),
        };
        let message = error.to_string();
        assert!(message.contains("refusing to guess"));
        assert!(message.contains("brand-new-status"));
    }
}
