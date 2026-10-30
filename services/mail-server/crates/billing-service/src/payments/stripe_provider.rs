//! The Stripe adapter (external audit item 15): a PAYMENTS-ONLY
//! implementation of the neutral [`PaymentProvider`] boundary.
//!
//! PAYMENTS ONLY, BY CONTRACT: ApexMail owns the subscription schedule (the
//! local renewal worker, `plan_billing::renew_due_subscriptions`). This
//! adapter therefore creates NO Stripe Subscription objects, NO Stripe
//! Billing prices, NO mode=subscription checkout sessions and NO
//! Customers-as-subscription-owner — the provider only executes SINGLE
//! payments (`checkout/sessions` with `mode=payment`,
//! `payment_intents` with `confirm=true, off_session=true`, `refunds`,
//! `payment_methods/{id}/detach` and `payouts`). The wire map:
//!
//! | trait method | Stripe endpoint |
//! |--------------|-----------------|
//! | [`PaymentProvider::create_checkout`] | `POST /v1/checkout/sessions` (`mode=payment`, never subscription) |
//! | [`PaymentProvider::charge_saved_method`] | `POST /v1/payment_intents` (`confirm=true`, `off_session=true`, `Idempotency-Key`) |
//! | [`PaymentProvider::refund`] | `POST /v1/refunds` (`payment_intent=…`, `Idempotency-Key`) |
//! | [`PaymentProvider::fetch_payment_object`] | `GET /v1/payment_intents/{id}` |
//! | [`PaymentProvider::fetch_payment_details`] | `GET /v1/payment_intents/{id}` (plus the object's metadata + customer) |
//! | [`PaymentProvider::search_payment_by_idempotency_key`] | identical `POST /v1/payment_intents` replay when the original request was journaled; the keyed metadata search is INVESTIGATION only, never absence proof |
//! | [`PaymentProvider::fetch_refund`] | `GET /v1/refunds/{id}` |
//! | [`PaymentProvider::revoke_saved_method`] | `POST /v1/payment_methods/{id}/detach` |
//! | [`PaymentProvider::fetch_settlement`] | `GET /v1/payouts/{id}` |
//! | [`PaymentProvider::list_settlements`] | `GET /v1/payouts` (paid payouts) |
//! | [`PaymentProvider::list_disputes`] | `GET /v1/payment_intents/{id}?expand[]=latest_charge` (disputes attach to charges) |
//!
//! The idempotency metadata contract mirrors the Mollie adapter exactly
//! (`metadata.idempotency_key`, `metadata.reference` = the obligation ref,
//! `metadata.tenant_id`) so the engine's stale-claim search and the webhook
//! normalizer's tenant/obligation attribution work identically across
//! providers.
//!
//! # Absence is PROVEN by replay, never by an empty search
//!
//! Stripe's Search API is eventually consistent: an empty result does NOT
//! prove that a charge does not exist, and treating it as absence is a
//! duplicate-charge path. An UNCERTAIN create (a lost response) is instead
//! recovered by REPLAYING the identical `POST /v1/payment_intents` with the
//! SAME `Idempotency-Key` (Stripe stores and replays the first result for 24
//! hours). This adapter journals the exact wire form of every saved-method
//! charge per idempotency key, so
//! [`PaymentProvider::search_payment_by_idempotency_key`] can perform that
//! replay. The contract is deliberately narrow:
//!
//! * `Ok(Some(payment))` — the replay (or the investigation search) found the
//!   one provider object for this key.
//! * `Ok(None)` — the REPLAY was refused by the provider (400/409): the
//!   original create never minted a payment. This is the only absence proof
//!   this adapter accepts; an empty search is NEVER `None`.
//! * `Err(..)` — the original request is not replayable (another process,
//!   a restart, the 24 h retention elapsed) and the search is empty or
//!   unavailable: absence is UNPROVABLE, the engine parks the attempt
//!   `unresolved`.
//!
//! The charge request journal is in-process and bounded; an entry evicted or
//! lost across a restart simply makes the recovery unprovable (`Err`), never
//! a blind second charge.
//!
//! All HTTP goes through [`StripeClient`] with the same discipline as
//! `MollieClient`: one bearer client, strict timeouts, 5xx/429 map to
//! [`ProviderError::Unavailable`], 4xx to [`ProviderError::Refused`], and
//! NO transport retries — retries are safe only where an Idempotency-Key is
//! sent, so the caller (engine) owns them. An UNKNOWN wire status is a
//! typed [`ProviderError::UnmappedStatus`] (fail closed), unit-tested for
//! totality over the documented vocabulary.

use std::collections::HashMap;
use std::sync::{Mutex, OnceLock};
use std::time::{Duration, Instant};

use chrono::{DateTime, TimeZone, Utc};

use super::{
    Checkout, CheckoutRequest, CustomerRequest, Dispute, DisputeState, FetchedPayment, Payment,
    PaymentProvider, PaymentState, ProviderCapabilities, ProviderCustomer, ProviderError, Refund,
    RefundRequest, RefundState, SavedMethodCharge, SavedMethodRef, Settlement,
};

/// The adapter's stable name (the registry's `stripe` value).
pub const PROVIDER_NAME: &str = "stripe";

const DEFAULT_BASE_URL: &str = "https://api.stripe.com/v1";
const REQUEST_TIMEOUT: Duration = Duration::from_secs(30);

/// The page size of the recent-payment-intents fallback window (the
/// no-keyed-search path of the stale-claim reconcile). Mirrors the Mollie
/// adapter's truncation-honest window size.
const FALLBACK_LIST_LIMIT: u32 = 100;

/// Stripe stores an idempotency key's first result for 24 hours. A replay
/// after that window could create a SECOND object for the same operation, so
/// the adapter never replays older requests (their absence stays unprovable:
/// `Err`, never `Ok(None)`).
const IDEMPOTENCY_RETENTION: Duration = Duration::from_secs(24 * 60 * 60);

/// The in-process journal's capacity. An evicted request only makes a later
/// recovery unprovable (fail closed); it can never cause a second charge.
const CHARGE_JOURNAL_CAPACITY: usize = 4_096;

/// The exact wire form of one saved-method charge, journaled per idempotency
/// key so an uncertain create can be recovered by replaying the identical
/// POST with the same `Idempotency-Key`.
#[derive(Clone)]
struct ChargeReplay {
    pairs: Vec<(String, String)>,
    issued: Instant,
}

type ChargeJournal = Mutex<HashMap<String, ChargeReplay>>;

/// The process-wide charge request journal. Stripe constructs a fresh
/// adapter per registry resolution, so the journal must outlive one adapter
/// instance to make the sweep's recovery replay possible.
fn charge_journal() -> &'static ChargeJournal {
    static JOURNAL: OnceLock<ChargeJournal> = OnceLock::new();
    JOURNAL.get_or_init(|| Mutex::new(HashMap::new()))
}

/// Journal one charge's exact wire form under its idempotency key. Expired
/// entries are pruned first; at capacity the oldest entry is evicted (an
/// evicted request is simply no longer replayable: fail closed).
fn journal_charge(key: &str, pairs: Vec<(String, String)>) {
    let mut journal = charge_journal().lock().expect("charge replay journal");
    journal.retain(|_, entry| entry.issued.elapsed() < IDEMPOTENCY_RETENTION);
    if journal.len() >= CHARGE_JOURNAL_CAPACITY && !journal.contains_key(key) {
        if let Some(oldest) = journal
            .iter()
            .min_by_key(|(_, entry)| entry.issued)
            .map(|(key, _)| key.clone())
        {
            journal.remove(&oldest);
        }
    }
    journal.insert(
        key.to_string(),
        ChargeReplay {
            pairs,
            issued: Instant::now(),
        },
    );
}

/// The journaled request for one key, when it is still inside Stripe's
/// idempotency retention window.
fn journaled_charge(key: &str) -> Option<Vec<(String, String)>> {
    let journal = charge_journal().lock().expect("charge replay journal");
    journal
        .get(key)
        .filter(|entry| entry.issued.elapsed() < IDEMPOTENCY_RETENTION)
        .map(|entry| entry.pairs.clone())
}

/// Whether the journal remembers the key AT ALL (an expired entry included):
/// an expired journaled request is never replaced by a fresh replay, which
/// could mint a second charge.
fn journal_holds(key: &str) -> bool {
    charge_journal()
        .lock()
        .expect("charge replay journal")
        .contains_key(key)
}

// ---------------------------------------------------------------------------
// The wire client
// ---------------------------------------------------------------------------

/// The one place this repository speaks the Stripe wire protocol: bearer
/// auth (`Authorization: Bearer sk_…`), form-encoded bodies (the current
/// Stripe wire format), `Idempotency-Key` on the mutating calls that carry
/// one.
pub struct StripeClient {
    http: reqwest::Client,
    base_url: String,
    secret_key: String,
    webhook_url: Option<String>,
}

impl std::fmt::Debug for StripeClient {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        formatter
            .debug_struct("StripeClient")
            .field("base_url", &self.base_url)
            // The secret key never reaches a log line.
            .field("secret_key", &"[redacted]")
            .field("webhook_url", &self.webhook_url)
            .finish()
    }
}

impl StripeClient {
    /// Resolve the client from the environment (`STRIPE_SECRET_KEY`,
    /// optional `STRIPE_API_BASE_URL`, optional `STRIPE_WEBHOOK_URL`).
    pub fn from_env() -> Result<Self, ProviderError> {
        let secret_key = std::env::var("STRIPE_SECRET_KEY")
            .ok()
            .map(|key| key.trim().to_string())
            .filter(|key| !key.is_empty())
            .ok_or_else(|| ProviderError::Config("STRIPE_SECRET_KEY is not set".to_string()))?;
        let base_url = std::env::var("STRIPE_API_BASE_URL")
            .ok()
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| DEFAULT_BASE_URL.to_string());
        let webhook_url = std::env::var("STRIPE_WEBHOOK_URL")
            .ok()
            .map(|value| value.trim().to_string())
            .filter(|value| !value.is_empty());
        Self::new(secret_key, base_url, webhook_url)
    }

    /// Explicit construction (the registry and the conformance lane).
    pub fn new(
        secret_key: String,
        base_url: String,
        webhook_url: Option<String>,
    ) -> Result<Self, ProviderError> {
        // A production deployment must never drive real customer billing
        // through a test key or a loopback base URL: refuse unless the
        // operator deliberately opts in (the local stack does). Mirrors the
        // MollieClient production guard.
        let environment = std::env::var("ENVIRONMENT").unwrap_or_default();
        let production = environment.eq_ignore_ascii_case("production")
            || std::env::var("APP_ENV")
                .map(|value| value.eq_ignore_ascii_case("production"))
                .unwrap_or(false);
        if production {
            let test_base = base_url.contains("localhost") || base_url.contains("127.0.0.1");
            // Stripe test secret keys are `sk_test_…`; live keys `sk_live_…`.
            let test_key = secret_key.starts_with("sk_test_");
            let opted_in = std::env::var("STRIPE_ALLOW_TEST_KEY").as_deref() == Ok("true");
            if (test_base || test_key) && !opted_in {
                return Err(ProviderError::Config(
                    "Stripe test credentials in production: set the live key and \
                     https://api.stripe.com/v1, or STRIPE_ALLOW_TEST_KEY=true deliberately"
                        .to_string(),
                ));
            }
        }
        let http = reqwest::Client::builder()
            .timeout(REQUEST_TIMEOUT)
            .build()
            .map_err(|error| ProviderError::Config(format!("HTTP client: {error}")))?;
        Ok(Self {
            http,
            base_url,
            secret_key,
            webhook_url,
        })
    }

    /// The webhook endpoint Stripe will call (`STRIPE_WEBHOOK_URL`, else
    /// `APP_BASE_URL`/`PUBLIC_BASE_URL` + `/v1/webhooks/stripe`; absent
    /// means "do not advertise one" — local stacks drive the webhook
    /// themselves).
    pub fn webhook_url(&self) -> Option<String> {
        if let Some(url) = &self.webhook_url {
            return Some(url.clone());
        }
        let base = std::env::var("APP_BASE_URL")
            .or_else(|_| std::env::var("PUBLIC_BASE_URL"))
            .ok()
            .map(|value| value.trim().trim_end_matches('/').to_string())
            .filter(|value| !value.is_empty())?;
        Some(format!("{base}/v1/webhooks/stripe"))
    }

    fn url(&self, path: &str) -> String {
        format!(
            "{}/{}",
            self.base_url.trim_end_matches('/'),
            path.trim_start_matches('/')
        )
    }

    /// One authenticated request. Mapping discipline (identical to
    /// `MollieClient::send`): transport/5xx/429 -> `Unavailable`, other
    /// non-success -> `Refused`, unreadable JSON -> `Malformed`. NO retry
    /// happens here.
    async fn send(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<serde_json::Value, ProviderError> {
        let response = request
            .header("Authorization", format!("Bearer {}", self.secret_key))
            .header("Accept", "application/json")
            .send()
            .await
            .map_err(|error| ProviderError::Unavailable(format!("request failed: {error}")))?;
        let status = response.status();
        let body = response.text().await.unwrap_or_default();
        if status.is_server_error() || status.as_u16() == 429 {
            return Err(ProviderError::Unavailable(format!(
                "{status}: {}",
                truncate(&body, 300)
            )));
        }
        if !status.is_success() {
            return Err(ProviderError::Refused {
                status: status.as_u16(),
                detail: truncate(&body, 300),
            });
        }
        serde_json::from_str(&body)
            .map_err(|error| ProviderError::Malformed(format!("{error}: {}", truncate(&body, 200))))
    }

    fn post_form(
        &self,
        path: &str,
        pairs: Vec<(String, String)>,
        idempotency_key: Option<&str>,
    ) -> reqwest::RequestBuilder {
        let request = self
            .http
            .post(self.url(path))
            .header("Content-Type", "application/x-www-form-urlencoded");
        let request = match idempotency_key {
            Some(key) => request.header("Idempotency-Key", key),
            None => request,
        };
        request.form(&pairs)
    }

    // ---- payments -------------------------------------------------------

    /// `POST /v1/checkout/sessions`. `pairs` MUST carry `mode=payment` (the
    /// caller's contract: never a subscription session).
    pub(crate) async fn create_checkout_session(
        &self,
        pairs: Vec<(String, String)>,
        idempotency_key: &str,
    ) -> Result<serde_json::Value, ProviderError> {
        self.send(self.post_form("checkout/sessions", pairs, Some(idempotency_key)))
            .await
    }

    /// `POST /v1/customers` — the provider customer object saved methods
    /// belong to. `Idempotency-Key` is our per-tenant customer key, so a
    /// retried checkout cannot mint two customers.
    pub(crate) async fn create_customer(
        &self,
        name: &str,
        email: &str,
        idempotency_key: &str,
    ) -> Result<serde_json::Value, ProviderError> {
        let pairs = vec![
            ("name".to_string(), name.to_string()),
            ("email".to_string(), email.to_string()),
        ];
        self.send(self.post_form("customers", pairs, Some(idempotency_key)))
            .await
    }

    /// `POST /v1/payment_intents` (create + confirm in one call for the
    /// saved-method/MITO charge). `pairs` MUST carry `confirm=true` and
    /// `off_session=true` when charging a stored method.
    pub(crate) async fn create_payment_intent(
        &self,
        pairs: Vec<(String, String)>,
        idempotency_key: &str,
    ) -> Result<serde_json::Value, ProviderError> {
        self.send(self.post_form("payment_intents", pairs, Some(idempotency_key)))
            .await
    }

    /// `GET /v1/payment_intents/{id}`; optionally `?expand[]=latest_charge`
    /// so disputes (which attach to CHARGES, not intents) arrive inline.
    pub(crate) async fn get_payment_intent(
        &self,
        id: &str,
        expand_latest_charge: bool,
    ) -> Result<serde_json::Value, ProviderError> {
        let mut request = self.http.get(self.url(&format!("payment_intents/{id}")));
        if expand_latest_charge {
            request = request.query(&[("expand[]", "latest_charge")]);
        }
        self.send(request).await
    }

    /// `GET /v1/payment_intents/search?query=…` — the keyed metadata
    /// search (a complete enumeration over the account's payment intents).
    /// Returns the raw `search_result` document.
    pub(crate) async fn search_payment_intents(
        &self,
        query: &str,
    ) -> Result<serde_json::Value, ProviderError> {
        self.send(
            self.http
                .get(self.url("payment_intents/search"))
                .query(&[("query", query)]),
        )
        .await
    }

    /// `GET /v1/payment_intents?limit=N` — the newest-first fallback
    /// listing used when the search API is not enabled on the account.
    pub(crate) async fn list_payment_intents(
        &self,
        limit: u32,
    ) -> Result<serde_json::Value, ProviderError> {
        self.send(
            self.http
                .get(self.url("payment_intents"))
                .query(&[("limit", limit.to_string())]),
        )
        .await
    }

    /// `POST /v1/refunds`.
    pub(crate) async fn create_refund(
        &self,
        pairs: Vec<(String, String)>,
        idempotency_key: &str,
    ) -> Result<serde_json::Value, ProviderError> {
        self.send(self.post_form("refunds", pairs, Some(idempotency_key)))
            .await
    }

    /// `GET /v1/refunds/{id}`.
    pub(crate) async fn get_refund(&self, id: &str) -> Result<serde_json::Value, ProviderError> {
        self.send(self.http.get(self.url(&format!("refunds/{id}"))))
            .await
    }

    /// `GET /v1/charges/{id}` — the fallback fetch when
    /// `latest_charge` arrives as a bare id (expand not honored): disputes
    /// attach to charges, so the dispute is read on the charge object.
    pub(crate) async fn get_charge(&self, id: &str) -> Result<serde_json::Value, ProviderError> {
        self.send(self.http.get(self.url(&format!("charges/{id}"))))
            .await
    }

    /// `POST /v1/payment_methods/{id}/detach` — revocation. After this the
    /// stored credential can never be charged again.
    pub(crate) async fn detach_payment_method(
        &self,
        id: &str,
    ) -> Result<serde_json::Value, ProviderError> {
        self.send(self.post_form(&format!("payment_methods/{id}/detach"), Vec::new(), None))
            .await
    }

    /// `GET /v1/payouts/{id}`.
    pub(crate) async fn get_payout(&self, id: &str) -> Result<serde_json::Value, ProviderError> {
        self.send(self.http.get(self.url(&format!("payouts/{id}"))))
            .await
    }

    /// `GET /v1/payouts?limit=N` — newest first.
    pub(crate) async fn list_payouts(
        &self,
        limit: u32,
    ) -> Result<serde_json::Value, ProviderError> {
        self.send(
            self.http
                .get(self.url("payouts"))
                .query(&[("limit", limit.to_string())]),
        )
        .await
    }
}

// ---------------------------------------------------------------------------
// Wire -> neutral translation (pure, exhaustively tested)
// ---------------------------------------------------------------------------

/// Map one Stripe PaymentIntent status to the neutral state machine.
///
/// * `succeeded` -> [`PaymentState::Succeeded`]: the money arrived.
/// * `processing` -> [`PaymentState::Processing`]: the provider is moving
///   the money with no outcome yet.
/// * `requires_action` -> [`PaymentState::RequiresAction`]: parked on a
///   customer action the provider cannot perform for them. NEVER entitled —
///   the engine refuses it (`VerifyError::NotSuccessful`), and the
///   conformance matrix pins that no state but `succeeded` settles.
/// * `requires_payment_method` -> [`PaymentState::Failed`]: the confirmed
///   charge was refused (the intent fell back to its default payment
///   method); a definitive failure.
/// * `canceled` -> [`PaymentState::Canceled`]: abandoned/expired before an
///   outcome.
/// * anything else -> [`ProviderError::UnmappedStatus`]: the engine refuses
///   to guess a money state. (The manual-capture vocabulary
///   `requires_capture`/`requires_confirmation` is deliberately UNMAPPED:
///   this adapter never creates manual-capture intents, so meeting one is a
///   contract breach, not a state to guess about.)
pub(crate) fn map_payment_status(status: &str) -> Result<PaymentState, ProviderError> {
    match status.trim() {
        "succeeded" => Ok(PaymentState::Succeeded),
        "processing" => Ok(PaymentState::Processing),
        "requires_action" => Ok(PaymentState::RequiresAction),
        "requires_payment_method" => Ok(PaymentState::Failed),
        "canceled" => Ok(PaymentState::Canceled),
        other => Err(ProviderError::UnmappedStatus {
            kind: "payment",
            status: other.to_string(),
        }),
    }
}

/// Map one Stripe refund status to the neutral machine. A `canceled` refund
/// did not succeed, so it lands in [`RefundState::Failed`] (the neutral set
/// has no withdrawn arm; the idempotency key prevents re-issuing it).
pub(crate) fn map_refund_status(status: &str) -> Result<RefundState, ProviderError> {
    match status.trim() {
        "pending" => Ok(RefundState::Pending),
        "succeeded" => Ok(RefundState::Succeeded),
        "failed" | "canceled" => Ok(RefundState::Failed),
        other => Err(ProviderError::UnmappedStatus {
            kind: "refund",
            status: other.to_string(),
        }),
    }
}

/// Map one Stripe dispute status to the neutral machine
/// ([`DisputeState`]): every open/reviewable state is [`DisputeState::Opened`]
/// (evidence may still change the outcome), `lost` is the terminal debit,
/// and every resolved-in-our-favor state (`won`, and the closed early-warning
/// inquiry where the chargeback never materialized) is [`DisputeState::Won`].
pub(crate) fn map_dispute_status(status: &str) -> Result<DisputeState, ProviderError> {
    match status.trim() {
        "needs_response" | "warning_needs_response" | "under_review" | "warning_under_review" => {
            Ok(DisputeState::Opened)
        }
        "won" | "warning_closed" => Ok(DisputeState::Won),
        "lost" => Ok(DisputeState::Lost),
        other => Err(ProviderError::UnmappedStatus {
            kind: "dispute",
            status: other.to_string(),
        }),
    }
}

/// Map one Stripe Checkout Session status to the neutral CONTROLLER lifecycle
/// (whether the hosted page flow finished), never the money state.
///
/// Stripe distinguishes Session completion from PAYMENT completion: a
/// `mode=payment` Session can be `complete` while its PaymentIntent is still
/// `processing` (or `requires_action`). Mapping `complete` to
/// [`PaymentState::Succeeded`] would settle money that has not arrived, so
/// the session vocabulary deliberately tops out at
/// [`PaymentState::Processing`]: the settlement evidence is ALWAYS the
/// PaymentIntent the caller fetches with provider authentication.
pub(crate) fn map_session_status(status: &str) -> Result<PaymentState, ProviderError> {
    match status.trim() {
        "open" => Ok(PaymentState::Pending),
        // The flow finished; the money is not confirmed by this fact. Only a
        // fetched PaymentIntent.status == "succeeded" may say Succeeded.
        "complete" => Ok(PaymentState::Processing),
        "expired" => Ok(PaymentState::Canceled),
        other => Err(ProviderError::UnmappedStatus {
            kind: "checkout session",
            status: other.to_string(),
        }),
    }
}

fn truncate(text: &str, max: usize) -> String {
    let mut text = text.to_string();
    if text.len() > max {
        // Never split a UTF-8 code point.
        let mut end = max;
        while end > 0 && !text.is_char_boundary(end) {
            end -= 1;
        }
        text.truncate(end);
        text.push('…');
    }
    text
}

fn string_at(document: &serde_json::Value, pointer: &str) -> Option<String> {
    document
        .pointer(pointer)
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

/// Stripe timestamps are UNIX seconds (integer).
pub(crate) fn seconds_at(value: Option<&serde_json::Value>) -> Option<DateTime<Utc>> {
    value
        .and_then(|value| value.as_i64())
        .and_then(|seconds| chrono::Utc.timestamp_opt(seconds, 0).single())
}

fn currency_at(document: &serde_json::Value) -> Option<String> {
    document
        .get("currency")
        .and_then(|value| value.as_str())
        .map(|text| text.trim().to_ascii_uppercase())
        .filter(|text| !text.is_empty())
}

fn amount_at(document: &serde_json::Value) -> Option<i64> {
    document.get("amount").and_then(|value| value.as_i64())
}

/// Flatten the neutral metadata (a JSON object of scalars) into Stripe's
/// form encoding: `metadata[<key>]=<value>`. Values are stringified
/// verbatim (Stripe metadata values are strings); nested JSON values are
/// compact-encoded rather than silently dropped.
pub(crate) fn metadata_form_pairs(metadata: &serde_json::Value) -> Vec<(String, String)> {
    let mut pairs = Vec::new();
    if let Some(map) = metadata.as_object() {
        for (key, value) in map {
            let rendered = match value {
                serde_json::Value::Null => continue,
                serde_json::Value::String(text) => text.clone(),
                other => other.to_string(),
            };
            pairs.push((format!("metadata[{key}]"), rendered));
        }
    }
    pairs
}

/// One payment-intent document as the neutral [`Payment`]. STRICT: the
/// authenticated truth must carry amount AND currency (absence is a
/// [`ProviderError::Malformed`], never a coercion to zero) and a mapped
/// state (unknown -> [`ProviderError::UnmappedStatus`]).
pub(crate) fn neutral_payment(document: &serde_json::Value) -> Result<Payment, ProviderError> {
    let id = string_at(document, "/id").filter(|id| !id.is_empty());
    let Some(id) = id else {
        return Err(ProviderError::Malformed(
            "payment intent carries no id; refusing to ledger an unidentifiable charge".to_string(),
        ));
    };
    let state = map_payment_status(&string_at(document, "/status").unwrap_or_default())?;
    let Some(amount_minor) = amount_at(document) else {
        return Err(ProviderError::Malformed(format!(
            "payment intent {id} carries no amount; refusing to coerce absence to zero"
        )));
    };
    let Some(currency) = currency_at(document) else {
        return Err(ProviderError::Malformed(format!(
            "payment intent {id} carries no currency; refusing to coerce absence"
        )));
    };
    Ok(Payment {
        provider: PROVIDER_NAME.to_string(),
        provider_payment_id: id,
        state,
        amount_minor,
        currency,
        created_at: seconds_at(document.get("created")),
    })
}

/// One refund document as the neutral [`Refund`]. `fallback_payment_id` is
/// the payment the refund was created against (used when the document omits
/// `payment_intent`, e.g. a minimal proxy response).
pub(crate) fn neutral_refund(
    document: &serde_json::Value,
    fallback_payment_id: &str,
) -> Result<Refund, ProviderError> {
    let id = string_at(document, "/id").filter(|id| !id.is_empty());
    let Some(id) = id else {
        return Err(ProviderError::Malformed(
            "refund carries no id; refusing to ledger an unidentifiable refund".to_string(),
        ));
    };
    let state = map_refund_status(&string_at(document, "/status").unwrap_or_default())?;
    let Some(amount_minor) = amount_at(document) else {
        return Err(ProviderError::Malformed(format!(
            "refund {id} carries no amount; refusing to coerce absence to zero"
        )));
    };
    let Some(currency) = currency_at(document) else {
        return Err(ProviderError::Malformed(format!(
            "refund {id} carries no currency; refusing to coerce absence"
        )));
    };
    let payment_id = string_at(document, "/payment_intent")
        .filter(|id| !id.is_empty())
        .unwrap_or_else(|| fallback_payment_id.to_string());
    Ok(Refund {
        provider: PROVIDER_NAME.to_string(),
        provider_refund_id: id,
        provider_payment_id: payment_id,
        state,
        amount_minor,
        currency,
        created_at: seconds_at(document.get("created")),
    })
}

/// One dispute document as the neutral [`Dispute`].
pub(crate) fn neutral_dispute(
    document: &serde_json::Value,
    provider_payment_id: &str,
) -> Result<Dispute, ProviderError> {
    let id = string_at(document, "/id").filter(|id| !id.is_empty());
    let Some(id) = id else {
        return Err(ProviderError::Malformed(
            "dispute carries no id; refusing to ledger an unidentifiable dispute".to_string(),
        ));
    };
    let state = map_dispute_status(&string_at(document, "/status").unwrap_or_default())?;
    let Some(amount_minor) = amount_at(document) else {
        return Err(ProviderError::Malformed(format!(
            "dispute {id} carries no amount; refusing to coerce absence to zero"
        )));
    };
    let Some(currency) = currency_at(document) else {
        return Err(ProviderError::Malformed(format!(
            "dispute {id} carries no currency; refusing to coerce absence"
        )));
    };
    Ok(Dispute {
        provider: PROVIDER_NAME.to_string(),
        provider_dispute_id: id,
        provider_payment_id: provider_payment_id.to_string(),
        state,
        amount_minor,
        currency,
        reason: string_at(document, "/reason").filter(|reason| !reason.is_empty()),
        opened_at: seconds_at(document.get("created")),
    })
}

/// One payout document as the neutral [`Settlement`]: the settled amount in
/// minor units and `arrival_date` as the settle date. A payout that has not
/// arrived carries no date (the fact is not a settlement until it is one).
pub(crate) fn neutral_settlement(
    document: &serde_json::Value,
) -> Result<Settlement, ProviderError> {
    let id = string_at(document, "/id").filter(|id| !id.is_empty());
    let Some(id) = id else {
        return Err(ProviderError::Malformed(
            "payout carries no id; refusing to ledger an unidentifiable settlement".to_string(),
        ));
    };
    let paid = string_at(document, "/status").as_deref() == Some("paid");
    Ok(Settlement {
        provider: PROVIDER_NAME.to_string(),
        provider_settlement_id: id,
        amount_minor: amount_at(document).unwrap_or(0),
        currency: currency_at(document).unwrap_or_default(),
        settled_at: if paid {
            seconds_at(document.get("arrival_date"))
        } else {
            None
        },
    })
}

/// The data array of a Stripe list/search document.
fn data_of(document: &serde_json::Value) -> Vec<serde_json::Value> {
    document
        .get("data")
        .and_then(|value| value.as_array())
        .cloned()
        .unwrap_or_default()
}

/// The exact metadata value at `metadata[key]` (a string).
fn metadata_string(document: &serde_json::Value, key: &str) -> Option<String> {
    document
        .pointer("/metadata")
        .and_then(|metadata| metadata.get(key))
        .and_then(|value| value.as_str())
        .map(str::to_string)
}

/// Read an id that Stripe may deliver either as a bare string or as an
/// expanded object (`"customer": "cus_…"` or `{"id": "cus_…"}`).
fn expandable_id(document: &serde_json::Value, field: &str) -> Option<String> {
    let value = document.get(field)?;
    if let Some(id) = value.as_str() {
        return Some(id).filter(|id| !id.is_empty()).map(str::to_string);
    }
    value
        .get("id")
        .and_then(|id| id.as_str())
        .filter(|id| !id.is_empty())
        .map(str::to_string)
}

/// Case-insensitive ISO 4217 comparison (never parses, never converts).
fn currencies_equal(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

/// The one refusal shape for "the search could not prove absence": a typed
/// [`ProviderError::Config`] whose message says absence is unprovable (the
/// engine parks the attempt `unresolved`). Never `Ok(None)`.
fn absence_unprovable(detail: &str) -> ProviderError {
    ProviderError::Config(format!(
        "stripe: absence of the charge cannot be proven — {detail}; the original request is \
         not available for an idempotent replay, so the attempt stays unresolved"
    ))
}

/// The form body of a `POST /v1/payment_intents` saved-method charge: the
/// card pair, the money, `confirm=true`/`off_session=true`, and OUR metadata
/// (including `idempotency_key`). Pure, so the EXACT wire form can be
/// journaled for the idempotent replay and pinned by a test.
pub(crate) fn charge_form_pairs(request: &SavedMethodCharge) -> Vec<(String, String)> {
    let mut metadata = request.metadata.clone();
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "idempotency_key".to_string(),
            // The SAME trimmed key the `Idempotency-Key` header carries and
            // the search looks up: a replay must be byte-identical, and the
            // keyed search must find the object by this exact value.
            serde_json::Value::String(request.idempotency_key.trim().to_string()),
        );
    }
    let mut pairs = vec![
        (
            "payment_method".to_string(),
            request.provider_method_id.trim().to_string(),
        ),
        (
            "customer".to_string(),
            request.provider_customer_id.trim().to_string(),
        ),
        ("amount".to_string(), request.amount_minor.to_string()),
        (
            "currency".to_string(),
            request.currency.trim().to_ascii_lowercase(),
        ),
        ("confirm".to_string(), "true".to_string()),
        ("off_session".to_string(), "true".to_string()),
        ("description".to_string(), request.description.clone()),
    ];
    pairs.extend(metadata_form_pairs(&metadata));
    pairs
}

/// The form body of a `POST /v1/checkout/sessions` request. Pure (and
/// unit-tested) so the V34 wire shape is pinned without HTTP:
///
/// * `mode=payment` — NEVER a Stripe subscription (ApexMail owns the
///   schedule);
/// * `payment_intent_data[setup_future_usage]=off_session` whenever the
///   caller asks to save the method, so the completed checkout leaves a
///   card the renewal worker can charge with no browser;
/// * a pre-created customer rides `customer=<id>`; otherwise
///   `customer_creation=always` makes Stripe create one (the two fields are
///   mutually exclusive on Stripe's wire);
/// * the SAME metadata rides the Session AND its PaymentIntent
///   (`metadata[...]` and `payment_intent_data[metadata][...]`). The
///   authenticated POST-CHECKOUT object the activation fetches is the
///   PaymentIntent, so the tenant/plan/interval attribution (and the
///   `checkout_id` identity, once the local checkout authority lands) must
///   already be on it — propagating the keys here is what makes the
///   refetch-first webhook attributable without trusting the event body.
pub(crate) fn checkout_form_pairs(
    request: &CheckoutRequest,
) -> Result<Vec<(String, String)>, ProviderError> {
    // Stripe refuses a session without a success URL: the neutral
    // request's redirect IS that URL, and its absence is a caller
    // contract breach (fail closed, never an invented URL).
    let success_url = request
        .redirect_url
        .as_deref()
        .map(str::trim)
        .filter(|url| !url.is_empty())
        .ok_or_else(|| {
            ProviderError::Config(
                "stripe: a checkout session requires a success (redirect) URL; \
                 refusing to invent one"
                    .to_string(),
            )
        })?;
    let mut metadata = request.metadata.clone();
    if let Some(object) = metadata.as_object_mut() {
        object.insert(
            "idempotency_key".to_string(),
            serde_json::Value::String(request.idempotency_key.clone()),
        );
    }
    // OUR reference for the obligation (`invoice:{uuid}`), also in the
    // dedicated `client_reference_id` field for provider-side joins.
    let client_reference_id = metadata_string(&metadata, "reference")
        .filter(|reference| !reference.is_empty())
        .unwrap_or_else(|| request.idempotency_key.clone());
    let mut pairs = vec![
        ("mode".to_string(), "payment".to_string()),
        ("success_url".to_string(), success_url.to_string()),
        ("client_reference_id".to_string(), client_reference_id),
        ("line_items[0][quantity]".to_string(), "1".to_string()),
        (
            "line_items[0][price_data][currency]".to_string(),
            request.currency.trim().to_ascii_lowercase(),
        ),
        (
            "line_items[0][price_data][unit_amount]".to_string(),
            request.amount_minor.to_string(),
        ),
        (
            "line_items[0][price_data][product_data][name]".to_string(),
            request.description.clone(),
        ),
    ];
    if request.save_method {
        pairs.push((
            "payment_intent_data[setup_future_usage]".to_string(),
            "off_session".to_string(),
        ));
    }
    match request
        .provider_customer_id
        .as_deref()
        .map(str::trim)
        .filter(|id| !id.is_empty())
    {
        Some(customer) => pairs.push(("customer".to_string(), customer.to_string())),
        None => pairs.push(("customer_creation".to_string(), "always".to_string())),
    }
    pairs.extend(metadata_form_pairs(&metadata));
    // Item 9: the PaymentIntent must carry the SAME identity as the Session.
    // The refetch-first webhook normalizes the fetched PaymentIntent, so the
    // tenant/plan/interval/reference — and a `checkout_id` when the caller
    // supplies one — have to be on that object, not only on the container.
    pairs.extend(
        metadata_form_pairs(&metadata)
            .into_iter()
            .map(|(key, value)| {
                (
                    key.replacen("metadata[", "payment_intent_data[metadata][", 1),
                    value,
                )
            }),
    );
    Ok(pairs)
}

// ---------------------------------------------------------------------------
// The boundary implementation
// ---------------------------------------------------------------------------

/// The Stripe adapter: a thin translation over [`StripeClient`].
pub struct StripeProvider {
    client: StripeClient,
}

impl std::fmt::Debug for StripeProvider {
    fn fmt(&self, formatter: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // The wrapped client already redacts the key; nothing else is secret.
        formatter
            .debug_tuple("StripeProvider")
            .field(&self.client)
            .finish()
    }
}

impl StripeProvider {
    /// Resolve the adapter from the same environment the wire client reads
    /// (`STRIPE_SECRET_KEY` and friends), so an inversion through the
    /// registry changes NOTHING about when provider setup fails.
    pub fn from_env() -> Result<Self, ProviderError> {
        Ok(Self {
            client: StripeClient::from_env()?,
        })
    }

    /// Explicit construction (the registry, tests and the conformance lane).
    pub fn new(
        secret_key: String,
        base_url: String,
        webhook_url: Option<String>,
    ) -> Result<Self, ProviderError> {
        Ok(Self {
            client: StripeClient::new(secret_key, base_url, webhook_url)?,
        })
    }

    /// The client (the webhook route reads the advertised webhook URL).
    pub fn client(&self) -> &StripeClient {
        &self.client
    }

    /// Resolve a create/replay response to the AUTHORITATIVE neutral
    /// [`Payment`]. Amount and currency are never borrowed from the request:
    /// a minimal response (a proxy that omits them) gets ONE authenticated
    /// refetch by id; if the fetched object still lacks them, the answer is
    /// [`ProviderError::Malformed`].
    async fn authoritative_payment(
        &self,
        document: &serde_json::Value,
    ) -> Result<Payment, ProviderError> {
        match neutral_payment(document) {
            Ok(payment) => Ok(payment),
            Err(ProviderError::Malformed(first)) => {
                let Some(id) = string_at(document, "/id").filter(|id| !id.is_empty()) else {
                    return Err(ProviderError::Malformed(first));
                };
                let fetched = self.client.get_payment_intent(id.trim(), false).await?;
                neutral_payment(&fetched).map_err(|error| match error {
                    ProviderError::Malformed(second) => ProviderError::Malformed(format!(
                        "{second} (the create response was also unreadable: {first})"
                    )),
                    other => other,
                })
            }
            Err(other) => Err(other),
        }
    }

    /// Recover an UNCERTAIN create (a lost response) by replaying the
    /// identical `POST /v1/payment_intents` with the SAME
    /// `Idempotency-Key`: Stripe stores and replays the first result, so the
    /// replay returns the original PaymentIntent (never a second charge).
    ///
    /// Contract:
    /// * `Ok(Some(payment))` — the one provider object for this key (the
    ///   replayed original, or the single intent a replay minted because the
    ///   original never executed).
    /// * `Ok(None)` — the replay was REFUSED (400/409), which proves the
    ///   original create never minted a payment. The ONLY legal absence
    ///   answer.
    /// * `Err(..)` — no replayable request (unknown key, retention elapsed,
    ///   transport/provider failure): absence is UNPROVABLE.
    pub async fn recover_uncertain_charge(
        &self,
        request: &SavedMethodCharge,
    ) -> Result<Option<Payment>, ProviderError> {
        let key = request.idempotency_key.trim();
        if key.is_empty() {
            return Err(ProviderError::Config(
                "stripe: an empty idempotency key cannot be replayed".to_string(),
            ));
        }
        // Replay the ORIGINAL wire form when it was journaled; a re-supplied
        // request is used only when no journal entry survives (a different
        // body under the same key is an idempotency conflict, never what we
        // want to send). A journaled-but-EXPIRED entry is never replaced: a
        // replay after Stripe's retention could mint a second object.
        let pairs = match journaled_charge(key) {
            Some(pairs) => pairs,
            None if journal_holds(key) => {
                return Err(ProviderError::Config(format!(
                    "stripe: the journaled request for {key} is outside Stripe's 24h \
                     idempotency retention; replaying it could mint a second charge and \
                     absence cannot be proven"
                )));
            }
            None => {
                let pairs = charge_form_pairs(request);
                journal_charge(key, pairs.clone());
                pairs
            }
        };
        self.replay_charge(key, pairs).await
    }

    /// The idempotent replay itself: the identical POST with the identical
    /// key. `Ok(None)` only when Stripe REFUSES the replay (400/409) — the
    /// replay-proven absence. Everything else that is not a readable payment
    /// is an error (unprovable).
    async fn replay_charge(
        &self,
        key: &str,
        pairs: Vec<(String, String)>,
    ) -> Result<Option<Payment>, ProviderError> {
        match self.client.create_payment_intent(pairs, key).await {
            Ok(document) => self.authoritative_payment(&document).await.map(Some),
            // Stripe replays the stored first result, INCLUDING an error
            // response: a replayed 400/409 is the provider saying the create
            // never minted a PaymentIntent. This is the ONLY absence proof
            // the adapter accepts.
            Err(ProviderError::Refused {
                status: 400 | 409, ..
            }) => Ok(None),
            Err(error) => Err(error),
        }
    }
}

#[async_trait::async_trait]
impl PaymentProvider for StripeProvider {
    fn provider_name(&self) -> &'static str {
        PROVIDER_NAME
    }

    /// Stripe's surface: hosted checkout pages, stored-method charging
    /// (off-session PaymentIntents), refunds, REAL retrievable disputes
    /// (unlike Mollie — disputes attach to charges and are expandable),
    /// payout settlements, and an `Idempotency-Key` honored on the mutating
    /// calls this adapter makes.
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

    /// `POST /v1/checkout/sessions` with `mode=payment` — NEVER
    /// `mode=subscription` (ApexMail owns the schedule). The metadata
    /// contract mirrors the Mollie adapter exactly (`reference`,
    /// `tenant_id`, `idempotency_key`) so the engine's reconciliation is
    /// provider-blind.
    async fn create_checkout(&self, request: CheckoutRequest) -> Result<Checkout, ProviderError> {
        let pairs = checkout_form_pairs(&request)?;
        let session = self
            .client
            .create_checkout_session(pairs, &request.idempotency_key)
            .await?;
        let state = map_session_status(&string_at(&session, "/status").unwrap_or_default())?;
        Ok(Checkout {
            provider: PROVIDER_NAME.to_string(),
            provider_payment_id: string_at(&session, "/id").unwrap_or_default(),
            state,
            redirect_url: string_at(&session, "/url").filter(|url| !url.is_empty()),
            amount_minor: request.amount_minor,
            currency: request.currency.to_ascii_uppercase(),
            created_at: seconds_at(session.get("created")),
        })
    }

    /// `POST /v1/customers` (our per-tenant idempotency key).
    async fn ensure_customer(
        &self,
        request: CustomerRequest,
    ) -> Result<ProviderCustomer, ProviderError> {
        let document = self
            .client
            .create_customer(
                &request.name,
                &request.email,
                &format!("customer_{}", request.tenant_id),
            )
            .await?;
        let id = string_at(&document, "/id").filter(|id| !id.is_empty());
        let Some(id) = id else {
            return Err(ProviderError::Malformed(
                "stripe returned a customer without an id".to_string(),
            ));
        };
        Ok(ProviderCustomer {
            provider: PROVIDER_NAME.to_string(),
            provider_customer_id: id,
        })
    }

    /// Read the reusable card a COMPLETED checkout captured: the
    /// PaymentIntent's `payment_method` + `customer` (the pair the renewal
    /// worker charges off-session). A session/`mode=payment` checkout saves
    /// the card only when `setup_future_usage=off_session` was requested;
    /// absence is an honest `None` (the activation refunds and reports).
    async fn fetch_saved_method_for_payment(
        &self,
        provider_payment_id: &str,
    ) -> Result<Option<SavedMethodRef>, ProviderError> {
        let intent = self
            .client
            .get_payment_intent(provider_payment_id.trim(), false)
            .await?;
        let customer = string_at(&intent, "/customer").filter(|id| !id.is_empty());
        let method = string_at(&intent, "/payment_method").filter(|id| !id.is_empty());
        Ok(customer
            .zip(method)
            .map(|(customer, method)| SavedMethodRef {
                provider_customer_id: customer,
                provider_method_id: method,
            }))
    }

    /// `POST /v1/payment_intents` with `payment_method=…`, `confirm=true`,
    /// `off_session=true` (the saved-method/MITO charge) and
    /// `Idempotency-Key=<the charge's key>`. The key ALSO rides the
    /// metadata (mirroring the Mollie adapter) so the stale-claim
    /// reconciliation can find the charge provider-side even when the
    /// search API is not enabled on the account.
    ///
    /// The EXACT wire form is journaled under the idempotency key BEFORE the
    /// request is sent: a lost response can then be recovered by replaying
    /// the identical POST (Stripe replays its stored first result), which is
    /// the only absence proof this adapter accepts.
    async fn charge_saved_method(
        &self,
        request: SavedMethodCharge,
    ) -> Result<Payment, ProviderError> {
        let pairs = charge_form_pairs(&request);
        journal_charge(request.idempotency_key.trim(), pairs.clone());
        let document = self
            .client
            .create_payment_intent(pairs, request.idempotency_key.trim())
            .await?;
        // Item 5: a Succeeded PaymentIntent missing an authoritative amount
        // or currency is Malformed — the adapter NEVER borrows the request's
        // amount/currency as if it were settlement evidence. One authenticated
        // refetch is allowed (a minimal create echo), then it is an error.
        self.authoritative_payment(&document).await
    }

    /// `POST /v1/refunds` (`payment_intent=…`, `amount=…`,
    /// `Idempotency-Key`). Stripe's create-refund API has NO `currency`
    /// parameter (sending one can 400), so it never rides the wire; the
    /// returned refund's currency is nevertheless validated against the
    /// expected one (a mismatched fact is Malformed, never recorded).
    async fn refund(&self, request: RefundRequest) -> Result<Refund, ProviderError> {
        let pairs = vec![
            (
                "payment_intent".to_string(),
                request.provider_payment_id.trim().to_string(),
            ),
            ("amount".to_string(), request.amount_minor.to_string()),
        ];
        let document = self
            .client
            .create_refund(pairs, &request.idempotency_key)
            .await?;
        let refund = neutral_refund(&document, request.provider_payment_id.trim())?;
        if !currencies_equal(&refund.currency, &request.currency) {
            return Err(ProviderError::Malformed(format!(
                "refund {} returned currency {} but the refund was requested in {}; \
                 refusing to record a currency the request never named",
                refund.provider_refund_id, refund.currency, request.currency
            )));
        }
        Ok(refund)
    }

    async fn fetch_payment_object(
        &self,
        provider_payment_id: &str,
    ) -> Result<Payment, ProviderError> {
        let intent = self
            .client
            .get_payment_intent(provider_payment_id.trim(), false)
            .await?;
        neutral_payment(&intent)
    }

    /// The webhook refetch's fact source: the authenticated PaymentIntent
    /// PLUS the attribution metadata our create wrote on it (item 9 puts the
    /// same identity on the Session and the PaymentIntent) and the provider
    /// customer. A signed event body never supplies any of this.
    async fn fetch_payment_details(
        &self,
        provider_payment_id: &str,
    ) -> Result<FetchedPayment, ProviderError> {
        let intent = self
            .client
            .get_payment_intent(provider_payment_id.trim(), false)
            .await?;
        Ok(FetchedPayment {
            payment: neutral_payment(&intent)?,
            metadata: intent
                .get("metadata")
                .cloned()
                .unwrap_or(serde_json::Value::Null),
            provider_customer_id: expandable_id(&intent, "customer"),
        })
    }

    /// A dispute event may name only the CHARGE: resolve it to the payment
    /// id (the neutral ledger keys disputes by the payment) with the
    /// authenticated charge fetch, never from the event body.
    async fn resolve_charge_payment_id(
        &self,
        charge_id: &str,
    ) -> Result<Option<String>, ProviderError> {
        let charge = self.client.get_charge(charge_id.trim()).await?;
        Ok(expandable_id(&charge, "payment_intent"))
    }

    /// The stale-claim reconciliation's fact source.
    ///
    /// The ONLY absence proof is the IDEMPOTENT REPLAY of the original
    /// create (the adapter journals every charge's exact wire form, so a
    /// lost response is recovered by re-sending the identical POST with the
    /// same `Idempotency-Key`). Stripe's Search API is EVENTUALLY
    /// CONSISTENT: an empty keyed search is investigation evidence only and
    /// must never permit a second charge, so this method never answers
    /// `Ok(None)` on an empty search.
    ///
    /// * journaled key -> [`Self::replay_charge`] decides
    ///   (`Ok(Some)` recovered, `Ok(None)` replay-refused proven absence,
    ///   `Err` unprovable);
    /// * no journaled key -> the keyed search (or the recent-list window
    ///   when the account has no Search API) may FIND the charge, never
    ///   prove it absent: a hit is `Ok(Some)`, an empty/truncated/unavailable
    ///   investigation is `Err` (the engine parks the attempt `unresolved`).
    async fn search_payment_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<Payment>, ProviderError> {
        let key = idempotency_key.trim();
        if key.is_empty() {
            return Err(ProviderError::Config(
                "stripe: an empty idempotency key cannot be searched".to_string(),
            ));
        }
        if key.contains('\'') {
            // The search query is `metadata['…']:'…'`; a quote in the key
            // would alter the query grammar. Refuse, never mangle.
            return Err(ProviderError::Config(
                "stripe: the idempotency key contains a quote and cannot be searched safely"
                    .to_string(),
            ));
        }
        // The replay path is the ONLY thing allowed to answer `Ok(None)`.
        if let Some(pairs) = journaled_charge(key) {
            return self.replay_charge(key, pairs).await;
        }
        // No replayable request survives: the search may FIND a charge, but
        // its emptiness proves nothing.
        let query = format!("metadata['idempotency_key']:'{key}'");
        match self.client.search_payment_intents(&query).await {
            Ok(document) => {
                for intent in data_of(&document) {
                    if metadata_string(&intent, "idempotency_key").as_deref() == Some(key) {
                        return neutral_payment(&intent).map(Some);
                    }
                }
                Err(absence_unprovable(
                    "the keyed search returned no payment, but Stripe Search is eventually \
                     consistent and its emptiness is not evidence",
                ))
            }
            Err(ProviderError::Refused { status, .. }) if (400..500).contains(&status) => {
                // The search API is not enabled on this account: the recent
                // list can still FIND the charge (presence), never prove
                // absence.
                let listing = self
                    .client
                    .list_payment_intents(FALLBACK_LIST_LIMIT)
                    .await?;
                for intent in data_of(&listing) {
                    if metadata_string(&intent, "idempotency_key").as_deref() == Some(key) {
                        return neutral_payment(&intent).map(Some);
                    }
                }
                if data_of(&listing).len() as u32 >= FALLBACK_LIST_LIMIT {
                    return Err(absence_unprovable(&format!(
                        "the recent-payment-intents listing is full ({FALLBACK_LIST_LIMIT}) \
                         and the search API is unavailable"
                    )));
                }
                Err(absence_unprovable(
                    "the recent-payment-intents listing does not carry the key, but the \
                     search API is unavailable",
                ))
            }
            Err(error) => Err(error),
        }
    }

    async fn fetch_refund(
        &self,
        provider_payment_id: &str,
        provider_refund_id: &str,
    ) -> Result<Refund, ProviderError> {
        let document = self.client.get_refund(provider_refund_id.trim()).await?;
        neutral_refund(&document, provider_payment_id.trim())
    }

    /// `POST /v1/payment_methods/{id}/detach`. Deliberately NO 404
    /// swallowing: the caller learns about revocation failures (including
    /// "already gone") from the error, and the sweep's retry decision
    /// depends on it.
    async fn revoke_saved_method(
        &self,
        _provider_customer_id: &str,
        provider_method_id: &str,
    ) -> Result<(), ProviderError> {
        self.client
            .detach_payment_method(provider_method_id.trim())
            .await
            .map(|_| ())
    }

    async fn fetch_settlement(
        &self,
        provider_settlement_id: &str,
    ) -> Result<Settlement, ProviderError> {
        let payout = self
            .client
            .get_payout(provider_settlement_id.trim())
            .await?;
        neutral_settlement(&payout)
    }

    async fn list_settlements(&self) -> Result<Vec<Settlement>, ProviderError> {
        let listing = self.client.list_payouts(FALLBACK_LIST_LIMIT).await?;
        data_of(&listing)
            .iter()
            // Only PAID payouts are settlements (in-flight payouts are not
            // facts yet).
            .filter(|payout| string_at(payout, "/status").as_deref() == Some("paid"))
            .map(neutral_settlement)
            .collect()
    }

    /// Stripe disputes attach to CHARGES, not intents: the intent is
    /// fetched with `expand[]=latest_charge` and the dispute read off the
    /// charge. When the expansion is not honored (`latest_charge` arrives
    /// as a bare id), the charge is fetched explicitly — a dispute is never
    /// hidden behind a wire quirk (silence would hide a chargeback from
    /// reconciliation). A payment with no dispute answers an HONEST empty
    /// list (retrieval exists; there is simply nothing to report).
    async fn list_disputes(
        &self,
        provider_payment_id: &str,
    ) -> Result<Vec<Dispute>, ProviderError> {
        let intent = self
            .client
            .get_payment_intent(provider_payment_id.trim(), true)
            .await?;
        let payment_id = string_at(&intent, "/id")
            .filter(|id| !id.is_empty())
            .unwrap_or_else(|| provider_payment_id.trim().to_string());
        let latest_charge = intent.get("latest_charge").cloned().unwrap_or_default();
        let charge = match &latest_charge {
            serde_json::Value::Null | serde_json::Value::Object(_) => latest_charge,
            // `latest_charge` as a bare string id: the expansion was not
            // honored — fetch the charge to read its dispute.
            serde_json::Value::String(charge_id) if !charge_id.is_empty() => {
                self.client.get_charge(charge_id).await?
            }
            _ => serde_json::Value::Null,
        };
        match charge.get("dispute") {
            Some(dispute) if dispute.is_object() => {
                Ok(vec![neutral_dispute(dispute, &payment_id)?])
            }
            _ => Ok(Vec::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// Every PaymentIntent status this adapter's flow produces maps, and
    /// each maps to exactly one neutral state (exhaustiveness over the
    /// documented charge vocabulary).
    #[test]
    fn payment_status_mapping_is_exhaustive() {
        let expected = [
            ("succeeded", PaymentState::Succeeded),
            ("processing", PaymentState::Processing),
            ("requires_action", PaymentState::RequiresAction),
            ("requires_payment_method", PaymentState::Failed),
            ("canceled", PaymentState::Canceled),
        ];
        for (wire, state) in expected {
            assert_eq!(map_payment_status(wire).unwrap(), state, "{wire}");
        }
    }

    #[test]
    fn unknown_payment_status_fails_closed() {
        // Manual-capture vocabulary is deliberately unmapped: this adapter
        // never creates manual-capture intents.
        for status in [
            "requires_capture",
            "requires_confirmation",
            "brand-new-status",
            "",
        ] {
            let error = map_payment_status(status).unwrap_err();
            match &error {
                ProviderError::UnmappedStatus { kind, status: wire } => {
                    assert_eq!(*kind, "payment");
                    assert_eq!(wire, status);
                }
                other => panic!("expected UnmappedStatus, got {other:?}"),
            }
        }
    }

    #[test]
    fn refund_status_mapping_is_exhaustive_and_fail_closed() {
        let expected = [
            ("pending", RefundState::Pending),
            ("succeeded", RefundState::Succeeded),
            ("failed", RefundState::Failed),
            ("canceled", RefundState::Failed),
        ];
        for (wire, state) in expected {
            assert_eq!(map_refund_status(wire).unwrap(), state, "{wire}");
        }
        assert!(map_refund_status("who-knows").is_err());
    }

    #[test]
    fn dispute_status_mapping_is_exhaustive_and_fail_closed() {
        let expected = [
            ("needs_response", DisputeState::Opened),
            ("warning_needs_response", DisputeState::Opened),
            ("under_review", DisputeState::Opened),
            ("warning_under_review", DisputeState::Opened),
            ("won", DisputeState::Won),
            ("warning_closed", DisputeState::Won),
            ("lost", DisputeState::Lost),
        ];
        for (wire, state) in expected {
            assert_eq!(map_dispute_status(wire).unwrap(), state, "{wire}");
        }
        assert!(map_dispute_status("who-knows").is_err());
    }

    #[test]
    fn session_status_mapping_never_means_money_succeeded() {
        assert_eq!(map_session_status("open").unwrap(), PaymentState::Pending);
        // A COMPLETE session is a finished flow, not arrived money: the
        // fetched PaymentIntent is the only settlement evidence.
        assert_eq!(
            map_session_status("complete").unwrap(),
            PaymentState::Processing
        );
        assert_eq!(
            map_session_status("expired").unwrap(),
            PaymentState::Canceled
        );
        assert!(map_session_status("who-knows").is_err());
        // The forbidden mapping: no session status may say Succeeded.
        for status in ["open", "complete", "expired"] {
            assert_ne!(map_session_status(status).unwrap(), PaymentState::Succeeded);
        }
    }

    fn checkout_request(save_method: bool, customer: Option<&str>) -> CheckoutRequest {
        CheckoutRequest {
            amount_minor: 12_400,
            currency: "EUR".to_string(),
            description: "ApexMail Developer".to_string(),
            redirect_url: Some("https://app.apexmail.ee/settings/billing".to_string()),
            webhook_url: None,
            metadata: serde_json::json!({"tenant_id": "t1", "reference": "checkout:t1"}),
            method_hint: None,
            provider_customer_id: customer.map(str::to_string),
            provider_method_id: None,
            save_method,
            idempotency_key: "checkout_t1_starter".to_string(),
        }
    }

    /// V34 wire shape: a checkout that saves the method MUST ask Stripe for
    /// off-session future usage and MUST create (or reuse) a customer; it
    /// must never become a subscription session.
    #[test]
    fn checkout_wire_shape_saves_the_card_and_creates_a_customer() {
        let pairs = checkout_form_pairs(&checkout_request(true, None)).expect("pairs");
        let has = |key: &str, value: &str| pairs.iter().any(|(k, v)| k == key && v == value);
        assert!(has("mode", "payment"));
        assert!(has(
            "payment_intent_data[setup_future_usage]",
            "off_session"
        ));
        assert!(has("customer_creation", "always"));
        assert!(
            !pairs.iter().any(|(k, _)| k == "customer"),
            "customer_creation and customer are mutually exclusive"
        );
        assert!(
            !pairs.iter().any(|(_, v)| v == "subscription"),
            "Stripe is payments-only: never mode=subscription"
        );

        // A pre-created customer is reused; customer_creation disappears.
        let pairs = checkout_form_pairs(&checkout_request(true, Some("cus_123"))).expect("pairs");
        let has = |key: &str, value: &str| pairs.iter().any(|(k, v)| k == key && v == value);
        assert!(has("customer", "cus_123"));
        assert!(!pairs.iter().any(|(k, _)| k == "customer_creation"));
        assert!(has(
            "payment_intent_data[setup_future_usage]",
            "off_session"
        ));

        // A checkout that does not save the method asks for neither.
        let pairs = checkout_form_pairs(&checkout_request(false, None)).expect("pairs");
        assert!(!pairs
            .iter()
            .any(|(k, _)| k == "payment_intent_data[setup_future_usage]"));
        assert!(!pairs
            .iter()
            .any(|(k, _)| k == "payment_intent_data[setup_future_usage][0]"));
    }

    /// Item 9: the checkout identity rides the PaymentIntent too. The
    /// refetch-first webhook reads the authenticated PaymentIntent, so every
    /// session metadata key (including `checkout_id` when the caller
    /// supplies one) must be mirrored under
    /// `payment_intent_data[metadata][…]`.
    #[test]
    fn checkout_identity_reaches_the_payment_intent_metadata() {
        let mut request = checkout_request(true, None);
        request.metadata = serde_json::json!({
            "tenant_id": "t1",
            "reference": "invoice:abc",
            "plan_name": "starter",
            "interval": "monthly",
            "checkout_id": "local_checkout_42",
        });
        let pairs = checkout_form_pairs(&request).expect("pairs");
        let has = |key: &str, value: &str| pairs.iter().any(|(k, v)| k == key && v == value);
        // The session metadata still rides `metadata[…]: idempotency_key is
        // injected by the adapter.
        assert!(has("metadata[tenant_id]", "t1"));
        assert!(has("metadata[idempotency_key]", "checkout_t1_starter"));
        assert!(has("metadata[checkout_id]", "local_checkout_42"));
        // The SAME identity is mirrored onto the PaymentIntent.
        assert!(has("payment_intent_data[metadata][tenant_id]", "t1"));
        assert!(has(
            "payment_intent_data[metadata][reference]",
            "invoice:abc"
        ));
        assert!(has("payment_intent_data[metadata][plan_name]", "starter"));
        assert!(has("payment_intent_data[metadata][interval]", "monthly"));
        // The key name `checkout_id` passes through unchanged.
        assert!(has(
            "payment_intent_data[metadata][checkout_id]",
            "local_checkout_42"
        ));
        assert!(has(
            "payment_intent_data[metadata][idempotency_key]",
            "checkout_t1_starter"
        ));
    }

    #[test]
    fn capabilities_advertise_the_documented_surface() {
        let provider =
            StripeProvider::new("sk_test_dummy".into(), "http://127.0.0.1:1/v1".into(), None)
                .expect("provider");
        assert_eq!(provider.provider_name(), "stripe");
        let capabilities = provider.capabilities();
        // Unlike Mollie, Stripe has REAL retrievable disputes.
        assert!(capabilities.disputes);
        assert!(capabilities.hosted_checkout);
        assert!(capabilities.saved_method_charging);
        assert!(capabilities.refunds);
        assert!(capabilities.payouts);
        assert!(capabilities.idempotency_keys);
    }

    #[test]
    fn metadata_form_encoding_is_flat_and_stringified() {
        let pairs = metadata_form_pairs(&serde_json::json!({
            "reference": "invoice:abc",
            "tenant_id": "t1",
            "count": 2,
            "nested": { "a": 1 },
            "nothing": null,
        }));
        assert!(pairs.contains(&("metadata[reference]".to_string(), "invoice:abc".to_string())));
        assert!(pairs.contains(&("metadata[tenant_id]".to_string(), "t1".to_string())));
        assert!(pairs.contains(&("metadata[count]".to_string(), "2".to_string())));
        assert!(pairs.contains(&("metadata[nested]".to_string(), r#"{"a":1}"#.to_string())));
        // A null is skipped, not stringified into "null".
        assert!(!pairs.iter().any(|(key, _)| key == "metadata[nothing]"));
    }

    #[test]
    fn a_payment_intent_without_amount_is_refused_not_coerced() {
        let document = serde_json::json!({
            "id": "pi_example",
            "status": "succeeded",
            "currency": "eur",
        });
        match neutral_payment(&document) {
            Err(ProviderError::Malformed(message)) => {
                assert!(message.contains("refusing to coerce"))
            }
            other => panic!("expected Malformed, got {other:?}"),
        }
    }

    #[test]
    fn neutral_payment_translates_state_amount_currency_and_timestamp() {
        let document = serde_json::json!({
            "id": "pi_example",
            "object": "payment_intent",
            "status": "succeeded",
            "amount": 1130,
            "currency": "eur",
            "created": 1761763200,
        });
        let neutral = neutral_payment(&document).expect("maps");
        assert_eq!(neutral.provider, "stripe");
        assert_eq!(neutral.provider_payment_id, "pi_example");
        assert_eq!(neutral.state, PaymentState::Succeeded);
        assert_eq!(neutral.amount_minor, 1130);
        assert_eq!(neutral.currency, "EUR");
        assert!(neutral.created_at.is_some());
    }

    #[test]
    fn neutral_refund_maps_state_and_falls_back_to_the_request_payment() {
        let document = serde_json::json!({
            "id": "re_example",
            "object": "refund",
            "status": "pending",
            "amount": 300,
            "currency": "eur",
            "payment_intent": "pi_example",
        });
        let neutral = neutral_refund(&document, "pi_requested").expect("maps");
        assert_eq!(neutral.provider, "stripe");
        assert_eq!(neutral.provider_refund_id, "re_example");
        assert_eq!(neutral.provider_payment_id, "pi_example");
        assert_eq!(neutral.state, RefundState::Pending);
        assert_eq!(neutral.amount_minor, 300);

        let minimal = serde_json::json!({
            "id": "re_min",
            "status": "succeeded",
            "amount": 500,
            "currency": "eur",
        });
        let neutral = neutral_refund(&minimal, "pi_requested").expect("maps");
        assert_eq!(neutral.provider_payment_id, "pi_requested");
        assert_eq!(neutral.state, RefundState::Succeeded);
    }

    #[test]
    fn neutral_dispute_maps_every_declared_state_family() {
        for (status, state) in [
            ("under_review", DisputeState::Opened),
            ("warning_closed", DisputeState::Won),
            ("lost", DisputeState::Lost),
        ] {
            let document = serde_json::json!({
                "id": "dp_example",
                "object": "dispute",
                "status": status,
                "amount": 1130,
                "currency": "eur",
                "reason": "fraudulent",
                "created": 1761763200,
            });
            let neutral = neutral_dispute(&document, "pi_example").expect("maps");
            assert_eq!(neutral.provider_dispute_id, "dp_example");
            assert_eq!(neutral.provider_payment_id, "pi_example");
            assert_eq!(neutral.state, state);
            assert_eq!(neutral.amount_minor, 1130);
            assert_eq!(neutral.currency, "EUR");
            assert_eq!(neutral.reason.as_deref(), Some("fraudulent"));
            assert!(neutral.opened_at.is_some());
        }
    }

    #[test]
    fn neutral_settlement_reads_only_paid_payout_dates() {
        let paid = serde_json::json!({
            "id": "po_example",
            "object": "payout",
            "status": "paid",
            "amount": 113000,
            "currency": "eur",
            "arrival_date": 1761763200,
        });
        let neutral = neutral_settlement(&paid).expect("maps");
        assert_eq!(neutral.provider_settlement_id, "po_example");
        assert_eq!(neutral.amount_minor, 113_000);
        assert_eq!(neutral.currency, "EUR");
        assert!(neutral.settled_at.is_some());
        // An in-flight payout is not a settlement yet: no date is invented.
        let in_flight = serde_json::json!({
            "id": "po_pending",
            "status": "in_transit",
            "amount": 1000,
            "currency": "eur",
            "arrival_date": 1761763200,
        });
        let neutral = neutral_settlement(&in_flight).expect("maps");
        assert!(neutral.settled_at.is_none());
    }

    #[tokio::test]
    async fn empty_and_unsearchable_keys_refuse_before_any_http() {
        let provider =
            StripeProvider::new("sk_test_dummy".into(), "http://127.0.0.1:1/v1".into(), None)
                .expect("provider");
        match provider.search_payment_by_idempotency_key("   ").await {
            Err(ProviderError::Config(message)) => {
                assert!(message.contains("cannot be searched"), "{message}")
            }
            other => panic!("expected a Config refusal, got {other:?}"),
        }
        // A quote would alter the search-query grammar: refuse, never mangle.
        match provider
            .search_payment_by_idempotency_key("key' OR '1'='1")
            .await
        {
            Err(ProviderError::Config(message)) => {
                assert!(message.contains("cannot be searched safely"), "{message}")
            }
            other => panic!("expected a Config refusal, got {other:?}"),
        }
        // The loopback address refuses connections: the search surfaces the
        // transport failure instead of inventing an answer.
        assert!(provider
            .search_payment_by_idempotency_key("payment:invoice:1:1")
            .await
            .is_err());
    }

    #[test]
    fn base_url_joining_never_doubles_slashes() {
        // Construction is exercised for the URL grammar only.
        let client = StripeClient::new(
            "sk_test_dummy".into(),
            "http://127.0.0.1:1/v1/".into(),
            None,
        )
        .expect("client");
        assert_eq!(
            client.url("payment_intents"),
            "http://127.0.0.1:1/v1/payment_intents"
        );
        assert_eq!(
            client.url("/payouts/po_1"),
            "http://127.0.0.1:1/v1/payouts/po_1"
        );
    }

    #[test]
    fn debug_never_leaks_the_secret() {
        let client = StripeClient::new(
            "sk_test_SUPERSECRET".into(),
            "http://127.0.0.1:1/v1".into(),
            None,
        )
        .expect("client");
        let rendered = format!("{client:?}");
        assert!(!rendered.contains("SUPERSECRET"));
        assert!(rendered.contains("[redacted]"));
    }
}
