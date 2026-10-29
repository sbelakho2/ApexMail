//! The Mollie adapter (external audit, P0-A, step 2).
//!
//! [`MollieProvider`] implements the neutral [`PaymentProvider`] boundary by
//! DELEGATING to [`crate::mollie_client::MollieClient`]: no HTTP is
//! duplicated here, the wire client stays the one place this repository
//! speaks to the provider, and this file is where Mollie's vocabulary
//! (`tr_…` payments, `mdt_…` mandates, `sub_…` subscriptions, decimal-string
//! amounts) is translated into the neutral domain's opaque ids, state
//! machines and integer minor units.
//!
//! The status mappings below are exhaustive over the statuses the wire
//! client documents, and unit-tested for totality: an UNKNOWN status is a
//! typed [`ProviderError::UnmappedStatus`] (fail closed), except the
//! recurring-schedule map, which has an `Other` arm because the
//! reconciliation sweep's contract is total (a provider state the engine
//! does not model must still resolve the tenant to Free, exactly as the
//! pre-inversion string comparisons did).

use chrono::{DateTime, Utc};

use crate::mollie_client::{
    self, CreatePayment, CreateSubscription, MollieClient, MollieError, Money,
};

use super::{
    Checkout, CheckoutRequest, CredentialState, Payment, PaymentProvider, PaymentState,
    ProviderCapabilities, ProviderError, RecurringSchedule, RecurringScheduleRequest,
    RecurringScheduleState, Refund, RefundRequest, RefundState, SavedMethodCharge, Settlement,
};

/// The adapter's stable name (the registry's `mollie` value).
pub const PROVIDER_NAME: &str = "mollie";

/// The first (and, this round, only) adapter: a thin translation over the
/// wire client.
pub struct MollieProvider {
    client: MollieClient,
}

impl std::fmt::Debug for MollieProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The wrapped client already redacts the key; nothing else is secret.
        formatter
            .debug_tuple("MollieProvider")
            .field(&self.client)
            .finish()
    }
}

impl MollieProvider {
    /// Resolve the adapter from the same environment the wire client reads
    /// (`MOLLIE_API_KEY` and friends), so an inversion through the registry
    /// changes NOTHING about when provider setup fails.
    pub fn from_env() -> Result<Self, MollieError> {
        Ok(Self {
            client: MollieClient::from_env()?,
        })
    }

    /// Explicit construction (tests and future explicit wiring).
    pub fn new(
        api_key: String,
        base_url: String,
        webhook_url: Option<String>,
    ) -> Result<Self, MollieError> {
        Ok(Self {
            client: MollieClient::new(api_key, base_url, webhook_url)?,
        })
    }

    #[cfg(test)]
    pub fn for_tests(base_url: String) -> Self {
        Self {
            client: MollieClient::for_tests(base_url),
        }
    }
}

// ---------------------------------------------------------------------------
// Wire -> neutral translation (pure, exhaustively tested)
// ---------------------------------------------------------------------------

/// Map one Mollie payment status to the neutral state machine.
///
/// * `open` -> [`PaymentState::Pending`]: the hosted checkout exists, the
///   customer has not acted.
/// * `pending` / `authorized` -> [`PaymentState::Processing`]: the provider
///   is moving (or has reserved) the money with no outcome yet.
/// * `paid` -> [`PaymentState::Succeeded`].
/// * `refunded` / `charged_back` -> [`PaymentState::Succeeded`]: THE CHARGE
///   SUCCEEDED. Returning the money is a separate fact owned by
///   [`Refund`] / [`Dispute`] objects; relabeling the payment would erase
///   the revenue event the accounting ledger already posted.
/// * `expired` -> [`PaymentState::Canceled`]: the customer never acted and
///   the window closed; the engine has no separate Expired terminal.
/// * anything else -> [`ProviderError::UnmappedStatus`]: the engine refuses
///   to guess a money state.
pub(crate) fn map_payment_status(status: &str) -> Result<PaymentState, ProviderError> {
    match status.trim() {
        "open" => Ok(PaymentState::Pending),
        "pending" | "authorized" => Ok(PaymentState::Processing),
        "paid" | "refunded" | "charged_back" => Ok(PaymentState::Succeeded),
        "failed" => Ok(PaymentState::Failed),
        "canceled" | "expired" => Ok(PaymentState::Canceled),
        other => Err(ProviderError::UnmappedStatus {
            kind: "payment",
            status: other.to_string(),
        }),
    }
}

/// Map one Mollie refund status to the neutral machine. A `canceled` refund
/// did not succeed, so it lands in [`RefundState::Failed`] (the neutral set
/// has no withdrawn arm; the idempotency key prevents re-issuing it).
pub(crate) fn map_refund_status(status: &str) -> Result<RefundState, ProviderError> {
    match status.trim() {
        "queued" | "pending" => Ok(RefundState::Pending),
        "processing" => Ok(RefundState::Processing),
        "refunded" => Ok(RefundState::Succeeded),
        "failed" | "canceled" => Ok(RefundState::Failed),
        other => Err(ProviderError::UnmappedStatus {
            kind: "refund",
            status: other.to_string(),
        }),
    }
}

/// Map one Mollie mandate status to the neutral credential machine. A
/// `pending` mandate is NOT chargeable yet: the engine records it as
/// [`CredentialState::Failed`] (fail closed, "cannot charge now") rather
/// than guessing that confirmation will arrive.
#[allow(dead_code)] // stage 2 of the staged neutrality plan wires credential
                    // writes through the adapter; the exhaustive mapping +
                    // tests stay so the wiring cannot arrive without parity
pub(crate) fn map_credential_status(status: &str) -> Result<CredentialState, ProviderError> {
    match status.trim() {
        "valid" => Ok(CredentialState::Active),
        "invalid" => Ok(CredentialState::Failed),
        "pending" => Ok(CredentialState::Failed),
        other => Err(ProviderError::UnmappedStatus {
            kind: "credential",
            status: other.to_string(),
        }),
    }
}

/// Map one Mollie subscription status to the neutral schedule machine.
/// TOTAL by design (see the module doc): an unmodeled status resolves to
/// [`RecurringScheduleState::Other`], which grants nothing, mirroring the
/// pre-inversion sweep where any status other than `active` resolved the
/// tenant to Free.
pub(crate) fn map_schedule_status(status: &str) -> RecurringScheduleState {
    match status.trim() {
        "active" => RecurringScheduleState::Active,
        "pending" => RecurringScheduleState::Pending,
        "canceled" => RecurringScheduleState::Canceled,
        "suspended" => RecurringScheduleState::Suspended,
        "completed" => RecurringScheduleState::Completed,
        _ => RecurringScheduleState::Other,
    }
}

/// Mollie subscription interval strings are fixed: `1 month`, `12 months`.
/// Moved here from plan billing with the inversion: interval GRAMMAR is
/// provider vocabulary.
pub fn interval_string(months: u32) -> String {
    if months == 1 {
        "1 month".to_string()
    } else {
        format!("{months} months")
    }
}

fn map_error(error: MollieError) -> ProviderError {
    match error {
        MollieError::Config(message) => ProviderError::Config(message),
        MollieError::Unavailable(message) => ProviderError::Unavailable(message),
        MollieError::Rejected { status, detail } => ProviderError::Refused { status, detail },
        MollieError::Malformed(message) => ProviderError::Malformed(message),
    }
}

/// A payment object's ISO timestamp, or `None` (the field is diagnostic on
/// the neutral type; the state is authoritative, the timestamp is not).
fn wire_timestamp(raw: &serde_json::Value, pointer: &str) -> Option<DateTime<Utc>> {
    raw.pointer(pointer)
        .and_then(|value| value.as_str())
        .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
        .map(|time| time.with_timezone(&Utc))
}

fn neutral_payment(payment: mollie_client::Payment) -> Result<Payment, ProviderError> {
    let amount = payment.amount.ok_or_else(|| {
        ProviderError::Malformed(format!(
            "payment {} carries no amount; refusing to coerce absence to zero",
            payment.id
        ))
    })?;
    Ok(Payment {
        provider: PROVIDER_NAME.to_string(),
        provider_payment_id: payment.id,
        state: map_payment_status(&payment.status)?,
        amount_minor: amount.cents,
        currency: amount.currency,
        created_at: wire_timestamp(&payment.raw, "/createdAt"),
    })
}

fn neutral_refund(refund: mollie_client::Refund) -> Result<Refund, ProviderError> {
    let amount = refund.amount.ok_or_else(|| {
        ProviderError::Malformed(format!(
            "refund {} carries no amount; refusing to coerce absence to zero",
            refund.id
        ))
    })?;
    Ok(Refund {
        provider: PROVIDER_NAME.to_string(),
        provider_refund_id: refund.id,
        provider_payment_id: refund.payment_id,
        state: map_refund_status(&refund.status)?,
        amount_minor: amount.cents,
        currency: amount.currency,
        created_at: wire_timestamp(&refund.raw, "/createdAt"),
    })
}

/// A Mollie settlement object becomes a neutral payout fact: the settled
/// amount in minor units and the settle date; a settlement that has not
/// paid out yet simply carries no date (the fact is not a payout until it
/// is one).
fn neutral_settlement(settlement: mollie_client::Settlement) -> Settlement {
    Settlement {
        provider: PROVIDER_NAME.to_string(),
        provider_settlement_id: settlement.id,
        amount_minor: settlement
            .amount
            .as_ref()
            .map(|amount| amount.cents)
            .unwrap_or(0),
        currency: settlement
            .amount
            .as_ref()
            .map(|amount| amount.currency.clone())
            .unwrap_or_default(),
        settled_at: settlement
            .settled_at
            .as_deref()
            .and_then(|text| DateTime::parse_from_rfc3339(text).ok())
            .map(|time| time.with_timezone(&Utc)),
    }
}

fn neutral_schedule(
    schedule: mollie_client::Subscription,
) -> Result<RecurringSchedule, ProviderError> {
    Ok(RecurringSchedule {
        provider: PROVIDER_NAME.to_string(),
        provider_schedule_id: schedule.id,
        provider_customer_id: schedule.customer_id,
        state: map_schedule_status(&schedule.status),
        amount_minor: schedule.amount.as_ref().map(|amount| amount.cents),
        currency: schedule
            .amount
            .as_ref()
            .map(|amount| amount.currency.clone()),
        next_charge_date: schedule.next_payment_date,
    })
}

// ---------------------------------------------------------------------------
// The boundary implementation
// ---------------------------------------------------------------------------

#[async_trait::async_trait]
impl PaymentProvider for MollieProvider {
    fn provider_name(&self) -> &'static str {
        PROVIDER_NAME
    }

    /// Mollie's surface: hosted checkout pages, stored-mandate charging,
    /// refunds, chargeback facts (disputes arrive as payment states, not a
    /// fetchable dispute object), settlement payouts, and an
    /// `Idempotency-Key` honored on every mutating call.
    fn capabilities(&self) -> ProviderCapabilities {
        ProviderCapabilities {
            hosted_checkout: true,
            saved_method_charging: true,
            refunds: true,
            disputes: true,
            payouts: true,
            idempotency_keys: true,
        }
    }

    async fn create_checkout(&self, request: CheckoutRequest) -> Result<Checkout, ProviderError> {
        let link = self
            .client
            .create_payment(CreatePayment {
                amount: Money::new(&request.currency, request.amount_minor),
                description: request.description,
                redirect_url: request.redirect_url.unwrap_or_default(),
                webhook_url: request.webhook_url,
                metadata: request.metadata,
                method: request.method_hint,
                customer_id: request.provider_customer_id,
                mandate_id: request.provider_method_id,
                // A checkout is by definition customer-initiated.
                sequence_type: None,
                idempotency_key: request.idempotency_key,
            })
            .await
            .map_err(map_error)?;
        // A freshly created checkout is open awaiting the customer; a mock
        // or proxy that reports no status is still "nothing decided".
        let state = if link.status.trim().is_empty() {
            PaymentState::Pending
        } else {
            map_payment_status(&link.status)?
        };
        Ok(Checkout {
            provider: PROVIDER_NAME.to_string(),
            provider_payment_id: link.id,
            state,
            redirect_url: link.checkout_url,
            amount_minor: request.amount_minor,
            currency: request.currency.to_ascii_uppercase(),
            created_at: None,
        })
    }

    async fn charge_saved_method(
        &self,
        request: SavedMethodCharge,
    ) -> Result<Payment, ProviderError> {
        let link = self
            .client
            .create_payment(CreatePayment {
                amount: Money::new(&request.currency, request.amount_minor),
                description: request.description,
                // API-initiated: no browser redirect exists (an empty
                // redirectUrl would be rejected as an invalid URL).
                redirect_url: String::new(),
                webhook_url: None,
                metadata: request.metadata,
                method: None,
                customer_id: Some(request.provider_customer_id),
                mandate_id: Some(request.provider_method_id),
                sequence_type: Some("recurring".into()),
                idempotency_key: request.idempotency_key,
            })
            .await
            .map_err(map_error)?;
        // The create response is a payment LINK: it carries no amount back,
        // so the authoritative requested amount is echoed, exactly as the
        // pre-inversion caller recorded what it asked for.
        let state = if link.status.trim().is_empty() {
            PaymentState::Pending
        } else {
            map_payment_status(&link.status)?
        };
        Ok(Payment {
            provider: PROVIDER_NAME.to_string(),
            provider_payment_id: link.id,
            state,
            amount_minor: request.amount_minor,
            currency: request.currency.to_ascii_uppercase(),
            created_at: None,
        })
    }

    async fn refund(&self, request: RefundRequest) -> Result<Refund, ProviderError> {
        let refund = self
            .client
            .create_refund(
                &request.provider_payment_id,
                Money::new(&request.currency, request.amount_minor),
                &request.description,
                &request.idempotency_key,
            )
            .await
            .map_err(map_error)?;
        neutral_refund(refund)
    }

    async fn fetch_payment_object(
        &self,
        provider_payment_id: &str,
    ) -> Result<Payment, ProviderError> {
        let payment = self
            .client
            .get_payment(provider_payment_id)
            .await
            .map_err(map_error)?;
        neutral_payment(payment)
    }

    async fn fetch_refund(
        &self,
        provider_payment_id: &str,
        provider_refund_id: &str,
    ) -> Result<Refund, ProviderError> {
        // Mollie has no single-refund fetch: enumerate the payment's
        // refunds (the wire client owns that pagination) and select.
        let refunds = self
            .client
            .payment_refunds(provider_payment_id)
            .await
            .map_err(map_error)?;
        refunds
            .into_iter()
            .find(|refund| refund.id == provider_refund_id)
            .map(neutral_refund)
            .transpose()?
            .ok_or_else(|| ProviderError::NotFound {
                kind: "refund",
                id: provider_refund_id.to_string(),
            })
    }

    async fn create_recurring_schedule(
        &self,
        request: RecurringScheduleRequest,
    ) -> Result<RecurringSchedule, ProviderError> {
        let schedule = self
            .client
            .create_subscription(CreateSubscription {
                customer_id: request.provider_customer_id,
                mandate_id: request.provider_method_id,
                amount: Money::new(&request.currency, request.amount_minor),
                interval: interval_string(request.interval_months),
                description: request.description,
                // None lets the wire client derive the webhook from its own
                // environment, exactly as the pre-inversion caller did.
                webhook_url: None,
                metadata: request.metadata,
                start_date: request.first_charge_date,
                idempotency_key: request.idempotency_key,
            })
            .await
            .map_err(map_error)?;
        neutral_schedule(schedule)
    }

    async fn fetch_recurring_schedule(
        &self,
        provider_customer_id: &str,
        provider_schedule_id: &str,
    ) -> Result<RecurringSchedule, ProviderError> {
        let schedule = self
            .client
            .get_subscription(provider_customer_id, provider_schedule_id)
            .await
            .map_err(map_error)?;
        neutral_schedule(schedule)
    }

    async fn list_recurring_schedules(
        &self,
        provider_customer_id: &str,
    ) -> Result<Vec<RecurringSchedule>, ProviderError> {
        let schedules = self
            .client
            .list_subscriptions(provider_customer_id)
            .await
            .map_err(map_error)?;
        schedules.into_iter().map(neutral_schedule).collect()
    }

    async fn cancel_recurring_schedule(
        &self,
        provider_customer_id: &str,
        provider_schedule_id: &str,
    ) -> Result<(), ProviderError> {
        // The id grammar lives HERE, in the adapter: a legacy/local
        // sentinel that is not a provider object is a no-op, and a provider
        // object it already forgot is the desired end state (mirroring the
        // pre-inversion semantics byte for byte).
        if !provider_schedule_id.starts_with("sub_") || provider_customer_id.trim().is_empty() {
            return Ok(());
        }
        match self
            .client
            .cancel_subscription(provider_customer_id, provider_schedule_id)
            .await
        {
            Ok(()) => Ok(()),
            Err(MollieError::Rejected { status: 404, .. }) => Ok(()),
            Err(error) => Err(map_error(error)),
        }
    }

    async fn fetch_settlement(
        &self,
        provider_settlement_id: &str,
    ) -> Result<Settlement, ProviderError> {
        let settlement = self
            .client
            .get_settlement(provider_settlement_id)
            .await
            .map_err(map_error)?;
        Ok(neutral_settlement(settlement))
    }

    async fn list_settlements(&self) -> Result<Vec<Settlement>, ProviderError> {
        let settlements = self
            .client
            .list_settlements(None)
            .await
            .map_err(map_error)?;
        Ok(settlements.into_iter().map(neutral_settlement).collect())
    }

    async fn revoke_saved_method(
        &self,
        provider_customer_id: &str,
        provider_method_id: &str,
    ) -> Result<(), ProviderError> {
        // Deliberately NO 404 swallowing: the pre-inversion caller learned
        // about revocation failures (including "already gone") from the
        // error string, and the sweep's retry decision depends on it.
        self.client
            .revoke_mandate(provider_customer_id, provider_method_id)
            .await
            .map_err(map_error)
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Every payment status the wire client documents maps, and each maps
    /// to exactly one neutral state (exhaustiveness: adding a Mollie status
    /// without a mapping fails HERE, not in production).
    #[test]
    fn payment_status_mapping_is_exhaustive() {
        let expected = [
            ("open", PaymentState::Pending),
            ("pending", PaymentState::Processing),
            ("authorized", PaymentState::Processing),
            ("paid", PaymentState::Succeeded),
            ("refunded", PaymentState::Succeeded),
            ("charged_back", PaymentState::Succeeded),
            ("failed", PaymentState::Failed),
            ("canceled", PaymentState::Canceled),
            ("expired", PaymentState::Canceled),
        ];
        for (wire, state) in expected {
            assert_eq!(map_payment_status(wire).unwrap(), state, "{wire}");
        }
        // Every documented status resolves: the mapping is total over the
        // documented vocabulary.
        let documented = [
            "open",
            "pending",
            "authorized",
            "paid",
            "failed",
            "canceled",
            "expired",
            "refunded",
            "charged_back",
        ];
        for status in documented {
            assert!(map_payment_status(status).is_ok(), "{status} must map");
        }
    }

    #[test]
    fn unknown_payment_status_fails_closed() {
        let error = map_payment_status("brand-new-status").unwrap_err();
        match &error {
            ProviderError::UnmappedStatus { kind, status } => {
                assert_eq!(*kind, "payment");
                assert_eq!(status, "brand-new-status");
            }
            other => panic!("expected UnmappedStatus, got {other:?}"),
        }
        assert!(map_payment_status("").is_err());
    }

    #[test]
    fn refund_status_mapping_is_exhaustive_and_fail_closed() {
        let expected = [
            ("queued", RefundState::Pending),
            ("pending", RefundState::Pending),
            ("processing", RefundState::Processing),
            ("refunded", RefundState::Succeeded),
            ("failed", RefundState::Failed),
            ("canceled", RefundState::Failed),
        ];
        for (wire, state) in expected {
            assert_eq!(map_refund_status(wire).unwrap(), state, "{wire}");
        }
        assert!(map_refund_status("who-knows").is_err());
    }

    #[test]
    fn credential_status_mapping_is_exhaustive_and_fail_closed() {
        assert_eq!(
            map_credential_status("valid").unwrap(),
            CredentialState::Active
        );
        // Not chargeable now is Failed, fail closed: the engine never
        // charges on a credential state it is not certain about.
        assert_eq!(
            map_credential_status("pending").unwrap(),
            CredentialState::Failed
        );
        assert_eq!(
            map_credential_status("invalid").unwrap(),
            CredentialState::Failed
        );
        assert!(map_credential_status("brand-new").is_err());
    }

    /// The schedule map is TOTAL: the reconciliation sweep's contract
    /// (anything not active grants nothing) survives unknown statuses.
    #[test]
    fn schedule_status_mapping_is_total_with_other_for_unmodeled() {
        let expected = [
            ("active", RecurringScheduleState::Active),
            ("pending", RecurringScheduleState::Pending),
            ("canceled", RecurringScheduleState::Canceled),
            ("suspended", RecurringScheduleState::Suspended),
            ("completed", RecurringScheduleState::Completed),
            ("something-new", RecurringScheduleState::Other),
            ("", RecurringScheduleState::Other),
        ];
        for (wire, state) in expected {
            assert_eq!(map_schedule_status(wire), state, "{wire}");
        }
    }

    #[test]
    fn interval_strings_are_the_fixed_provider_grammar() {
        assert_eq!(interval_string(1), "1 month");
        assert_eq!(interval_string(12), "12 months");
        assert_eq!(interval_string(3), "3 months");
    }

    #[test]
    fn wire_errors_map_one_to_one_onto_the_neutral_error() {
        assert!(matches!(
            map_error(MollieError::Config("no key".into())),
            ProviderError::Config(_)
        ));
        assert!(matches!(
            map_error(MollieError::Unavailable("down".into())),
            ProviderError::Unavailable(_)
        ));
        assert!(matches!(
            map_error(MollieError::Rejected {
                status: 422,
                detail: "nope".into()
            }),
            ProviderError::Refused { status: 422, .. }
        ));
        assert!(matches!(
            map_error(MollieError::Malformed("garbage".into())),
            ProviderError::Malformed(_)
        ));
    }

    #[test]
    fn a_payment_without_an_amount_is_refused_not_coerced() {
        let payment = mollie_client::Payment {
            id: "tr_example".into(),
            status: "paid".into(),
            amount: None,
            ..Default::default()
        };
        match neutral_payment(payment) {
            Err(ProviderError::Malformed(message)) => {
                assert!(message.contains("refusing to coerce"))
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn neutral_payment_translates_state_amount_and_timestamp() {
        let payment = mollie_client::payment_from_json(&serde_json::json!({
            "id": "tr_example",
            "status": "paid",
            "amount": { "currency": "EUR", "value": "49.00" },
            "createdAt": "2026-10-29T10:00:00+00:00",
        }));
        let neutral = neutral_payment(payment).expect("maps");
        assert_eq!(neutral.provider, "mollie");
        assert_eq!(neutral.provider_payment_id, "tr_example");
        assert_eq!(neutral.state, PaymentState::Succeeded);
        assert_eq!(neutral.amount_minor, 4900);
        assert_eq!(neutral.currency, "EUR");
        assert!(neutral.created_at.is_some());
    }

    #[test]
    fn settlement_documents_map_to_neutral_payout_facts() {
        let settlement = mollie_client::Settlement {
            id: "stl_cov_1".into(),
            status: "paid".into(),
            amount: Some(Money::new("EUR", 113_000)),
            settled_at: Some("2026-10-28T12:00:00+00:00".into()),
            raw: serde_json::Value::Null,
        };
        let neutral = neutral_settlement(settlement);
        assert_eq!(neutral.provider, "mollie");
        assert_eq!(neutral.provider_settlement_id, "stl_cov_1");
        assert_eq!(neutral.amount_minor, 113_000);
        assert_eq!(neutral.currency, "EUR");
        assert!(neutral.settled_at.is_some());
        // An unsettled payout carries no date and no invented amount.
        let pending = neutral_settlement(mollie_client::Settlement {
            id: "stl_cov_2".into(),
            status: "open".into(),
            amount: None,
            settled_at: None,
            raw: serde_json::Value::Null,
        });
        assert!(pending.settled_at.is_none());
        assert_eq!(pending.amount_minor, 0);
    }

    #[test]
    fn capabilities_advertise_the_documented_surface() {
        let provider = MollieProvider::for_tests("http://127.0.0.1:1/v2".into());
        assert_eq!(provider.provider_name(), "mollie");
        let capabilities = provider.capabilities();
        assert!(capabilities.hosted_checkout);
        assert!(capabilities.saved_method_charging);
        assert!(capabilities.refunds);
        assert!(capabilities.disputes);
        assert!(capabilities.payouts);
        assert!(capabilities.idempotency_keys);
    }
}
