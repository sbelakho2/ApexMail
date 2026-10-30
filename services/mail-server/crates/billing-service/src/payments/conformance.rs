//! The shared provider conformance harness (external audit, seventh pass,
//! P0-A, step 9 of the mandated 18-step order; expanded to the
//! financial-correctness matrix in the eighth pass).
//!
//! ONE matrix, ONE harness, every adapter. [`run_provider_conformance`]
//! drives the audit's eighteen-arm matrix against any
//! [`PaymentProvider`] plus the neutral engine, so a new processor (Stripe,
//! steps 11-18) proves itself against the SAME gates Mollie passes today
//! instead of writing its own idea of correct.
//!
//! The matrix (ids are stable; the report names them):
//!
//! | arm | audit statement |
//! |-----|-----------------|
//! | 1 | wrong tenant (cross-tenant obligation) refuses, nothing settles |
//! | 2 | wrong exact amount REFUSES ([`VerifyError::AmountMismatch`]): absent
//!     never mints, over- AND under-charge never allocate, never cap — the
//!     attempt stays open for human reconciliation |
//! | 3 | wrong currency refuses |
//! | 4 | requires_action grants nothing and blocks blind retry |
//! | 5 | failed charge closes the claim failed, no entitlement |
//! | 6 | duplicate webhook settles exactly once |
//! | 7 | out-of-order events never regress the verified terminal |
//! | 8 | timeout after a successful charge: claim stays open, no second
//!      charge, the repair sweep settles it |
//! | 9 | timeout with NO provider confirmation: the search cannot prove
//!      absence, so the attempt parks `unresolved`, is never auto-retried
//!      and never settles |
//! | 10 | attempt 2 after a definitive failure: a NEW immutable row with
//!      attempt_no = 2 and a distinct idempotency key; attempt 1 untouched |
//! | 11 | scheduler race: two concurrent claims, exactly one wins |
//! | 12 | partial + full refund produce distinct neutral refund facts |
//! | 13 | dispute opened: the neutral fact and the dispute row land |
//! | 14 | dispute lost: the terminal debit posts |
//! | 15 | dispute won/reversed: the restoration entry posts |
//! | 16 | missed webhook: the repair sweep settles from the authenticated
//!      fetch |
//! | 17 | payout/settlement facts land as neutral settlement facts |
//! | 18 | cancel-at-period-end prevents new local renewal: the local flag
//!      ends the subscription with no invoice and no charge |
//!
//! Arms 13-15 are capability-gated ([`ProviderCapabilities::disputes`]): a
//! provider that declares no dispute retrieval passes by REFUSING
//! `list_disputes` visibly (never a silent empty list that would hide a
//! chargeback); a provider that declares the capability must prove the
//! full fact -> row -> ledger -> journal path.
//!
//! [`ConformanceProvider`] is the scriptable double used to develop against
//! and to prove the harness has teeth: seeding a [`Defect`] into the double
//! must FAIL the mapped arm (see the `mutation_teeth_*` tests). A REAL
//! adapter runs the same matrix against a loopback wire stub (the Mollie
//! lane lives in `tests/coverage_adversarial.rs`, copying the maintenance
//! mock pattern).
//!
//! This module is a conformance kit: it has no production callers and moves
//! no money; it exists so "every adapter passes the same matrix" is one
//! function call, not a convention.

use std::collections::{HashMap, VecDeque};
use std::sync::Mutex;

use chrono::Utc;
use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;

use super::engine::{
    claim_attempt, claim_next_attempt, confirm_attempt, dunning_key, has_open_attempt,
    observe_dispute, observe_payment, record_refund_fact, record_settlement_fact, settle_verified,
    sweep_open_attempts_with, verify_against_obligation, ObservedPayment, UNRESOLVED_ATTEMPT_STATE,
};
use super::{
    Checkout, CheckoutRequest, CustomerRequest, Dispute, DisputeState, Payment, PaymentProvider,
    PaymentState, ProviderCapabilities, ProviderCustomer, ProviderError, Refund, RefundRequest,
    RefundState, SavedMethodCharge, SavedMethodRef, Settlement,
};

/// The deterministic ids the checkout/activation harness stores.
pub const CONFORMANCE_CUSTOMER_ID: &str = "conf_customer";
pub const CONFORMANCE_METHOD_ID: &str = "conf_method";

/// The matrix ids and names, in report order.
pub const MATRIX: [(u8, &str); 18] = [
    (1, "wrong tenant refuses"),
    (2, "wrong exact amount refuses, attempt stays open"),
    (3, "wrong currency refuses"),
    (4, "requires_action grants nothing"),
    (5, "failed charge closes the claim, no entitlement"),
    (6, "duplicate webhook settles exactly once"),
    (7, "out-of-order events stay terminal"),
    (8, "timeout after charge: no second charge, repair settles"),
    (9, "timeout without confirmation: unresolved, never retried"),
    (10, "attempt 2 is a new immutable row"),
    (11, "scheduler race: one claim wins"),
    (12, "partial and full refunds are distinct facts"),
    (13, "dispute opened: fact and dispute row land"),
    (14, "dispute lost: terminal debit posts"),
    (15, "dispute won: restoration posts"),
    (16, "missed webhook repaired by the sweep"),
    (17, "settlement facts land on the neutral ledger"),
    (18, "cancel-at-period-end prevents new local renewal"),
];

// The recurring-schedule arms are retired with the provider-owned schedule
// surface itself (beta authority inversion): the local renewal worker owns
// period advancement, and arm 18 pins the cancel-at-period-end authority.

// ---------------------------------------------------------------------------
// The scriptable double
// ---------------------------------------------------------------------------

/// A contract defect the double can be seeded with, to prove the harness
/// FAILS a defective provider (mutation teeth). Each variant names the arm
/// it must break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Defect {
    /// A charge that should surface the lost response as an error instead
    /// reports success. Must fail arm 8 (the timeout is hidden).
    HideTimeout,
    /// The authenticated fetch lies about the state (paid reported failed).
    /// Must fail arm 16 (the repair sweep cannot settle a "failed" charge).
    FetchLiesAboutState,
    /// The authenticated fetch reports the wrong currency. Must fail arm 6
    /// (verification refuses, so the exactly-once settle never happens).
    FetchReportsWrongCurrency,
    /// Two distinct refunds answer with the same refund id. Must fail arm
    /// 12 (the second refund collapses onto the first ledger row).
    RefundIdCollision,
    /// Settlement amounts are misreported. Must fail arm 17 (the recorded
    /// neutral fact carries the wrong money).
    SettlementAmountWrong,
    /// A dispute decided AGAINST us is reported as won. Must fail arm 14
    /// (the terminal debit never posts, so the loss is invisible to the
    /// statutory ledger).
    DisputeStateLies,
}

impl Defect {
    /// The arm a seeded defect must break (the teeth mapping).
    pub fn breaks_arm(self) -> u8 {
        match self {
            Defect::HideTimeout => 8,
            Defect::FetchLiesAboutState => 16,
            Defect::FetchReportsWrongCurrency => 6,
            Defect::RefundIdCollision => 12,
            Defect::SettlementAmountWrong => 17,
            Defect::DisputeStateLies => 14,
        }
    }
}

#[derive(Default)]
struct Script {
    charges: VecDeque<Result<Payment, ProviderError>>,
    charge_calls: u64,
    refunds: VecDeque<Result<Refund, ProviderError>>,
    payments: HashMap<String, Payment>,
    /// The answers [`ConformanceProvider::fetch_payment_details`] serves: the
    /// authenticated object INCLUDING the attribution metadata the webhook
    /// refetch reads (tenant/plan/interval). Scripted via
    /// [`ConformanceProvider::publish_payment_details`]; a payment published
    /// only through [`ConformanceProvider::publish_payment`] still answers
    /// the plain fetch.
    fetched: HashMap<String, super::FetchedPayment>,
    settlements: VecDeque<Settlement>,
    /// The idempotency-key search answers, keyed by the searched key. The
    /// outer `Option` distinguishes "scripted" from "unscripted"; the inner
    /// one is the answer (`Some(None)` = provable absence, `Some(Some(p))`
    /// = the provider knows the charge).
    searches: HashMap<String, Option<Option<Payment>>>,
    /// Scripted dispute facts per provider payment id.
    disputes: HashMap<String, Vec<Dispute>>,
    defect: Option<Defect>,
}

/// A scriptable [`PaymentProvider`] double. All behavior is injected; the
/// default script answers nothing, so an unscripted call fails closed.
pub struct ConformanceProvider {
    name: &'static str,
    script: Mutex<Script>,
}

impl ConformanceProvider {
    pub fn new(name: &'static str) -> Self {
        Self {
            name,
            script: Mutex::new(Script::default()),
        }
    }

    /// Queue one charge outcome. `amount_minor`/`currency` echo the request
    /// (the authoritative requested amount, like a create response).
    pub fn script_charge(&self, provider_payment_id: &str, state: PaymentState) {
        let mut script = self.script.lock().expect("script lock");
        let payment = Payment {
            provider: self.name.to_string(),
            provider_payment_id: provider_payment_id.to_string(),
            state,
            amount_minor: 0,
            currency: "EUR".to_string(),
            created_at: None,
        };
        script.charges.push_back(Ok(payment));
    }

    /// Queue one charge transport failure (the lost-response timeout).
    pub fn script_charge_error(&self, error: ProviderError) {
        self.script
            .lock()
            .expect("script lock")
            .charges
            .push_back(Err(error));
    }

    /// Charge echoes the request amount once the harness calls it; the
    /// double needs the intended money for the fetch map, so the harness
    /// publishes the authoritative payment object separately.
    pub fn publish_payment(&self, payment: Payment) {
        self.script
            .lock()
            .expect("script lock")
            .payments
            .insert(payment.provider_payment_id.clone(), payment);
    }

    /// Publish the ATTRIBUTED payment object the webhook refetch reads (the
    /// neutral money facts plus the metadata the provider object carries).
    pub fn publish_payment_details(&self, fetched: super::FetchedPayment) {
        self.script
            .lock()
            .expect("script lock")
            .fetched
            .insert(fetched.payment.provider_payment_id.clone(), fetched);
    }

    /// Queue one refund outcome.
    pub fn script_refund(
        &self,
        provider_refund_id: &str,
        provider_payment_id: &str,
        state: RefundState,
        amount_minor: i64,
    ) {
        let refund = Refund {
            provider: self.name.to_string(),
            provider_refund_id: provider_refund_id.to_string(),
            provider_payment_id: provider_payment_id.to_string(),
            state,
            amount_minor,
            currency: "EUR".to_string(),
            created_at: None,
        };
        self.script
            .lock()
            .expect("script lock")
            .refunds
            .push_back(Ok(refund));
    }

    /// Queue one payout settlement fact.
    pub fn script_settlement(&self, settlement: Settlement) {
        self.script
            .lock()
            .expect("script lock")
            .settlements
            .push_back(settlement);
    }

    /// Script the idempotency-key search answer for one key:
    /// `Some(Some(payment))` = the provider knows the charge;
    /// `Some(None)` = the provider provably does not; unscripted keys
    /// fail closed with [`ProviderError::Config`].
    pub fn script_search(&self, idempotency_key: &str, answer: Option<Payment>) {
        self.script
            .lock()
            .expect("script lock")
            .searches
            .insert(idempotency_key.to_string(), Some(answer));
    }

    /// Script one dispute fact against a provider payment.
    pub fn script_dispute(&self, provider_payment_id: &str, dispute: Dispute) {
        self.script
            .lock()
            .expect("script lock")
            .disputes
            .entry(provider_payment_id.to_string())
            .or_default()
            .push(dispute);
    }

    /// Seed a contract defect (teeth).
    pub fn seed_defect(&self, defect: Defect) {
        self.script.lock().expect("script lock").defect = Some(defect);
    }

    /// How many charge calls the double received (teeth assertions).
    pub fn charge_calls(&self) -> u64 {
        self.script.lock().expect("script lock").charge_calls
    }
}

#[async_trait::async_trait]
impl PaymentProvider for ConformanceProvider {
    fn provider_name(&self) -> &'static str {
        self.name
    }

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
        let id = format!("checkout_{}", Uuid::new_v4().simple());
        Ok(Checkout {
            provider: self.name.to_string(),
            provider_payment_id: id,
            state: PaymentState::Pending,
            redirect_url: Some("https://conformance.invalid/checkout".to_string()),
            amount_minor: request.amount_minor,
            currency: request.currency.to_ascii_uppercase(),
            created_at: None,
        })
    }

    /// Deterministic customer for the checkout/activation harness: the
    /// double records nothing provider-side, it only answers the two ids the
    /// activation stores.
    async fn ensure_customer(
        &self,
        _request: CustomerRequest,
    ) -> Result<ProviderCustomer, ProviderError> {
        Ok(ProviderCustomer {
            provider: self.name.to_string(),
            provider_customer_id: CONFORMANCE_CUSTOMER_ID.to_string(),
        })
    }

    /// The completed checkout's reusable card for the activation harness.
    async fn fetch_saved_method_for_payment(
        &self,
        _provider_payment_id: &str,
    ) -> Result<Option<SavedMethodRef>, ProviderError> {
        Ok(Some(SavedMethodRef {
            provider_customer_id: CONFORMANCE_CUSTOMER_ID.to_string(),
            provider_method_id: CONFORMANCE_METHOD_ID.to_string(),
        }))
    }

    async fn charge_saved_method(
        &self,
        request: SavedMethodCharge,
    ) -> Result<Payment, ProviderError> {
        let mut script = self.script.lock().expect("script lock");
        script.charge_calls += 1;
        let scripted = script
            .charges
            .pop_front()
            .unwrap_or(Err(ProviderError::Config(
                "conformance: unscripted charge".into(),
            )));
        // The defect replaces the OUTCOME, whatever the script queued: the
        // defective provider hides a lost response (scripted Unavailable)
        // behind a Pending success — applying it after `scripted?` would
        // never fire and the mutation tooth would be a no-op.
        let mut payment = if script.defect == Some(Defect::HideTimeout) {
            Payment {
                provider: self.name.to_string(),
                provider_payment_id: format!("conf_hidden_{}", request.idempotency_key),
                state: PaymentState::Pending,
                amount_minor: request.amount_minor,
                currency: request.currency.to_ascii_uppercase(),
                created_at: None,
            }
        } else {
            scripted?
        };
        // The create response echoes the authoritative requested amount.
        payment.amount_minor = request.amount_minor;
        payment.currency = request.currency.to_ascii_uppercase();
        Ok(payment)
    }

    async fn refund(&self, request: RefundRequest) -> Result<Refund, ProviderError> {
        let mut script = self.script.lock().expect("script lock");
        let mut refund = script
            .refunds
            .pop_front()
            .unwrap_or(Err(ProviderError::Config(
                "conformance: unscripted refund".into(),
            )))?;
        refund.amount_minor = request.amount_minor;
        if script.defect == Some(Defect::RefundIdCollision) {
            // Both refunds answer with the SAME id: the second fact must
            // collapse and the harness must notice.
            refund.provider_refund_id = "re_conformance_collision".to_string();
        }
        Ok(refund)
    }

    async fn fetch_payment_object(
        &self,
        provider_payment_id: &str,
    ) -> Result<Payment, ProviderError> {
        let script = self.script.lock().expect("script lock");
        let mut payment = script
            .payments
            .get(provider_payment_id)
            .cloned()
            .ok_or_else(|| ProviderError::NotFound {
                kind: "payment",
                id: provider_payment_id.to_string(),
            })?;
        match script.defect {
            Some(Defect::FetchLiesAboutState) => payment.state = PaymentState::Failed,
            Some(Defect::FetchReportsWrongCurrency) => payment.currency = "USD".to_string(),
            _ => {}
        }
        Ok(payment)
    }

    /// The attributed object the webhook refetch reads. A scripted
    /// [`ConformanceProvider::publish_payment_details`] answer wins; a plain
    /// published payment answers without metadata (the default contract).
    async fn fetch_payment_details(
        &self,
        provider_payment_id: &str,
    ) -> Result<super::FetchedPayment, ProviderError> {
        if let Some(fetched) = self
            .script
            .lock()
            .expect("script lock")
            .fetched
            .get(provider_payment_id)
            .cloned()
        {
            return Ok(fetched);
        }
        Ok(super::FetchedPayment {
            payment: self.fetch_payment_object(provider_payment_id).await?,
            metadata: serde_json::Value::Null,
            provider_customer_id: None,
        })
    }

    /// The double resolves no charge id (fail closed); dispute-event tests
    /// script the payment id directly.
    async fn resolve_charge_payment_id(
        &self,
        _charge_id: &str,
    ) -> Result<Option<String>, ProviderError> {
        Ok(None)
    }

    /// The scripted idempotency-key search: a key with no scripted answer
    /// fails closed (absence is never guessed by the double either).
    async fn search_payment_by_idempotency_key(
        &self,
        idempotency_key: &str,
    ) -> Result<Option<Payment>, ProviderError> {
        let script = self.script.lock().expect("script lock");
        match script.searches.get(idempotency_key) {
            Some(Some(answer)) => Ok(answer.clone()),
            _ => Err(ProviderError::Config(format!(
                "conformance: unscripted idempotency-key search for {idempotency_key}"
            ))),
        }
    }

    async fn fetch_refund(
        &self,
        provider_payment_id: &str,
        provider_refund_id: &str,
    ) -> Result<Refund, ProviderError> {
        let script = self.script.lock().expect("script lock");
        script
            .refunds
            .iter()
            .find(|refund| match refund {
                Ok(refund) => {
                    refund.provider_payment_id == provider_payment_id
                        && refund.provider_refund_id == provider_refund_id
                }
                Err(_) => false,
            })
            .cloned()
            .unwrap_or(Err(ProviderError::NotFound {
                kind: "refund",
                id: provider_refund_id.to_string(),
            }))
    }

    async fn revoke_saved_method(
        &self,
        _provider_customer_id: &str,
        _provider_method_id: &str,
    ) -> Result<(), ProviderError> {
        Ok(())
    }

    async fn fetch_settlement(
        &self,
        provider_settlement_id: &str,
    ) -> Result<Settlement, ProviderError> {
        let mut settlement = self
            .script
            .lock()
            .expect("script lock")
            .settlements
            .front()
            .cloned()
            .ok_or_else(|| ProviderError::NotFound {
                kind: "settlement",
                id: provider_settlement_id.to_string(),
            })?;
        if self.script.lock().expect("script lock").defect == Some(Defect::SettlementAmountWrong) {
            settlement.amount_minor += 1;
        }
        settlement.provider_settlement_id = provider_settlement_id.to_string();
        Ok(settlement)
    }

    async fn list_settlements(&self) -> Result<Vec<Settlement>, ProviderError> {
        let mut script = self.script.lock().expect("script lock");
        let mut out: Vec<Settlement> = script.settlements.drain(..).collect();
        if script.defect == Some(Defect::SettlementAmountWrong) {
            for settlement in &mut out {
                settlement.amount_minor += 1;
            }
        }
        Ok(out)
    }

    /// The scripted dispute facts for one payment. Unscripted payments
    /// fail closed. The DisputeStateLies defect reports a Lost dispute as
    /// Won, so the terminal debit never posts (the tooth for arm 14).
    async fn list_disputes(
        &self,
        provider_payment_id: &str,
    ) -> Result<Vec<Dispute>, ProviderError> {
        let script = self.script.lock().expect("script lock");
        let facts = script
            .disputes
            .get(provider_payment_id)
            .cloned()
            .ok_or_else(|| {
                ProviderError::Config(format!(
                    "conformance: unscripted dispute search for {provider_payment_id}"
                ))
            })?;
        if script.defect == Some(Defect::DisputeStateLies) {
            return Ok(facts
                .into_iter()
                .map(|mut dispute| {
                    if dispute.state == DisputeState::Lost {
                        dispute.state = DisputeState::Won;
                    }
                    dispute
                })
                .collect());
        }
        Ok(facts)
    }
}

// ---------------------------------------------------------------------------
// The harness
// ---------------------------------------------------------------------------

/// Per-arm context handed to the lane's scripting hook: everything needed
/// to route a wire stub or script the double for the arm about to run.
pub struct ConformanceCtx<'a> {
    pub arm: u8,
    pub provider_name: &'a str,
    pub tenant_id: &'a str,
    pub invoice_id: Uuid,
    pub obligation_ref: &'a str,
    pub amount_minor: i64,
    pub currency: &'a str,
    /// The provider payment id this arm's charge/published payment uses.
    pub provider_payment_hint: &'a str,
}

/// Lane scripting: prepare the provider's environment for one arm. The
/// Mollie lane routes a loopback wire stub; the double lane scripts the
/// double; engine-only arms need nothing.
pub trait ConformanceScripting: Send + Sync {
    fn arm_setup(&self, ctx: &ConformanceCtx<'_>) -> Result<(), String>;
}

/// Scripting for lanes that need no per-arm provider environment.
pub struct NoScripting;
impl ConformanceScripting for NoScripting {
    fn arm_setup(&self, _ctx: &ConformanceCtx<'_>) -> Result<(), String> {
        Ok(())
    }
}

/// One arm's outcome.
#[derive(Debug, Clone)]
pub struct ConformanceArm {
    pub arm: u8,
    pub name: &'static str,
    pub passed: bool,
    pub detail: String,
}

/// The full matrix result.
#[derive(Debug, Clone)]
pub struct ConformanceReport {
    pub provider: String,
    pub arms: Vec<ConformanceArm>,
}

impl ConformanceReport {
    pub fn all_passed(&self) -> bool {
        self.arms.iter().all(|arm| arm.passed)
    }

    /// `Err` naming every failed arm (the caller's test/lane fails on it).
    pub fn assert_all_passed(&self) -> Result<(), String> {
        if self.all_passed() {
            return Ok(());
        }
        let failures: Vec<String> = self
            .arms
            .iter()
            .filter(|arm| !arm.passed)
            .map(|arm| format!("arm {} ({}): {}", arm.arm, arm.name, arm.detail))
            .collect();
        Err(format!(
            "provider {} failed conformance:\n  - {}",
            self.provider,
            failures.join("\n  - ")
        ))
    }
}

/// The invoice total every arm bills (minor units): a non-round number so
/// an accidental echo of the total is distinguishable from a real charge.
const ARM_AMOUNT: i64 = 1130;
const ARM_CURRENCY: &str = "EUR";

fn arm_record(arm: u8, passed: bool, detail: String, out: &mut Vec<ConformanceArm>) {
    let (_, name) = MATRIX
        .iter()
        .find(|(id, _)| *id == arm)
        .expect("arm id in matrix");
    out.push(ConformanceArm {
        arm,
        name,
        passed,
        detail,
    });
}

async fn seed_arm_world(pool: &PgPool, arm: u8) -> Result<(String, Uuid, String), String> {
    let suffix = Uuid::new_v4().simple().to_string()[..8].to_string();
    let tenant = format!("conf{arm}_{suffix}");
    sqlx::query("INSERT INTO tenants (id, name, plan, status) VALUES ($1, $2, 'growth', 'active')")
        .bind(&tenant)
        .bind(format!("Conformance {arm}"))
        .execute(pool)
        .await
        .map_err(|error| format!("arm {arm}: tenant seed failed: {error}"))?;
    let invoice_id = Uuid::new_v4();
    sqlx::query(
        "INSERT INTO invoices (id, tenant_id, amount, currency, status, invoice_number, \
                               subtotal, vat_total, total, issued_at, due_at, \
                               period_start, period_end, created_at, updated_at) \
         VALUES ($1, $2, $3, $4, 'pending', 'CONF-' || gen_random_uuid()::text, \
                 $3, 0, $3, NOW(), NOW(), NOW(), NOW(), NOW(), NOW())",
    )
    .bind(invoice_id)
    .bind(&tenant)
    .bind(ARM_AMOUNT)
    .bind(ARM_CURRENCY)
    .execute(pool)
    .await
    .map_err(|error| format!("arm {arm}: invoice seed failed: {error}"))?;
    let obligation = format!("invoice:{invoice_id}");
    Ok((tenant, invoice_id, obligation))
}

async fn allocation_count(pool: &PgPool, invoice_id: Uuid) -> i64 {
    sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(SUM(amount_cents), 0)::bigint FROM invoice_payment_allocations \
         WHERE invoice_id = $1",
    )
    .bind(invoice_id)
    .fetch_one(pool)
    .await
    .unwrap_or(0)
}

fn observed(
    provider_name: &str,
    payment_id: &str,
    state: PaymentState,
    amount_minor: Option<i64>,
    currency: Option<&str>,
    tenant_id: Option<&str>,
    obligation_ref: &str,
) -> ObservedPayment {
    ObservedPayment {
        provider: provider_name.to_string(),
        provider_payment_id: payment_id.to_string(),
        state,
        amount_minor,
        currency: currency.map(str::to_string),
        tenant_id: tenant_id.map(str::to_string),
        obligation_ref: Some(obligation_ref.to_string()),
        purpose: "conformance",
    }
}

/// Run the full seventeen-arm conformance matrix against one provider plus
/// the neutral engine. Never panics: every arm's outcome lands in the
/// report.
pub async fn run_provider_conformance(
    state: &AppState,
    provider: std::sync::Arc<dyn PaymentProvider>,
    scripting: &dyn ConformanceScripting,
) -> ConformanceReport {
    let pool = &state.db;
    let provider_name = provider.provider_name();
    let mut arms: Vec<ConformanceArm> = Vec::new();
    for (arm, _) in MATRIX {
        let (tenant, invoice_id, obligation) = match seed_arm_world(pool, arm).await {
            Ok(world) => world,
            Err(error) => {
                arm_record(arm, false, error, &mut arms);
                continue;
            }
        };
        let payment_hint = format!(
            "pay_conf_{arm}_{}",
            &Uuid::new_v4().simple().to_string()[..8]
        );
        let ctx = ConformanceCtx {
            arm,
            provider_name,
            tenant_id: &tenant,
            invoice_id,
            obligation_ref: &obligation,
            amount_minor: ARM_AMOUNT,
            currency: ARM_CURRENCY,
            provider_payment_hint: &payment_hint,
        };
        if let Err(error) = scripting.arm_setup(&ctx) {
            arm_record(arm, false, format!("scripting failed: {error}"), &mut arms);
            continue;
        }
        let detail = match run_arm(state, &provider, &ctx).await {
            Ok(()) => String::new(),
            Err(error) => error,
        };
        arm_record(arm, detail.is_empty(), detail, &mut arms);
    }
    ConformanceReport {
        provider: provider_name.to_string(),
        arms,
    }
}

async fn run_arm(
    state: &AppState,
    provider: &std::sync::Arc<dyn PaymentProvider>,
    ctx: &ConformanceCtx<'_>,
) -> Result<(), String> {
    let pool = &state.db;
    let arm = ctx.arm;
    let name = provider.provider_name();
    match arm {
        1 => {
            // Wrong tenant: a cross-tenant fact must refuse and settle
            // nothing, ever.
            let fact = observed(
                name,
                ctx.provider_payment_hint,
                PaymentState::Succeeded,
                Some(ARM_AMOUNT),
                Some(ARM_CURRENCY),
                Some("a-different-tenant"),
                ctx.obligation_ref,
            );
            match verify_against_obligation(pool, &fact).await {
                Err(super::engine::VerifyError::CrossTenant { .. }) => {}
                other => return Err(format!("expected a cross-tenant refusal, got {other:?}")),
            }
            if allocation_count(pool, ctx.invoice_id).await != 0 {
                return Err("a refused fact must not allocate".into());
            }
            Ok(())
        }
        2 => {
            // Wrong exact amount: an absent amount refuses outright, and an
            // over-charge AND an under-charge are AmountMismatch
            // reconciliation incidents — no entitlement, no paid
            // transition, no allocation, NO capping, and the attempt stays
            // open for human reconciliation (never closed failed: the money
            // may exist).
            let absent = observed(
                name,
                ctx.provider_payment_hint,
                PaymentState::Succeeded,
                None,
                Some(ARM_CURRENCY),
                Some(ctx.tenant_id),
                ctx.obligation_ref,
            );
            match verify_against_obligation(pool, &absent).await {
                Err(super::engine::VerifyError::NotSuccessful(_)) => {}
                other => return Err(format!("absent amount must refuse, got {other:?}")),
            }
            for (label, charged) in [
                ("over-charge", Some(ARM_AMOUNT * 10)),
                ("under-charge", Some(ARM_AMOUNT / 2)),
            ] {
                let fact = observed(
                    name,
                    ctx.provider_payment_hint,
                    PaymentState::Succeeded,
                    charged,
                    Some(ARM_CURRENCY),
                    Some(ctx.tenant_id),
                    ctx.obligation_ref,
                );
                // The authenticated fact lands on the attempt ledger first
                // (exactly what the webhook path does), then verification
                // refuses.
                observe_payment(pool, &fact)
                    .await
                    .map_err(|error| format!("{label}: observe failed: {error}"))?;
                match verify_against_obligation(pool, &fact).await {
                    Err(super::engine::VerifyError::AmountMismatch {
                        expected_minor,
                        actual_minor,
                        ..
                    }) => {
                        if expected_minor != ARM_AMOUNT || Some(actual_minor) != charged {
                            return Err(format!(
                                "{label}: the refusal must carry the true evidence \
                                 (expected {expected_minor}, actual {actual_minor})"
                            ));
                        }
                    }
                    other => {
                        return Err(format!(
                            "{label} must refuse with AmountMismatch, never cap: got {other:?}"
                        ))
                    }
                }
                let state: String = sqlx::query_scalar(
                    "SELECT state FROM payment_attempts \
                     WHERE provider = $1 AND provider_payment_id = $2",
                )
                .bind(name)
                .bind(ctx.provider_payment_hint)
                .fetch_one(pool)
                .await
                .map_err(|error| format!("{label}: attempt read failed: {error}"))?;
                if state == "failed" {
                    return Err(format!(
                        "{label}: the mismatched attempt must stay OPEN for reconciliation, \
                         never be closed failed"
                    ));
                }
            }
            if allocation_count(pool, ctx.invoice_id).await != 0 {
                return Err("a refused amount must not allocate".into());
            }
            let status: String =
                sqlx::query_scalar("SELECT status::text FROM invoices WHERE id = $1")
                    .bind(ctx.invoice_id)
                    .fetch_one(pool)
                    .await
                    .map_err(|error| format!("invoice status read failed: {error}"))?;
            if status == "paid" {
                return Err("a mismatched charge must never mark the obligation paid".into());
            }
            Ok(())
        }
        3 => {
            // Wrong currency refuses.
            let fact = observed(
                name,
                ctx.provider_payment_hint,
                PaymentState::Succeeded,
                Some(ARM_AMOUNT),
                Some("USD"),
                Some(ctx.tenant_id),
                ctx.obligation_ref,
            );
            match verify_against_obligation(pool, &fact).await {
                Err(super::engine::VerifyError::CurrencyMismatch { .. }) => {}
                other => return Err(format!("expected a currency refusal, got {other:?}")),
            }
            Ok(())
        }
        6 => {
            // Duplicate webhook: the authenticated fetch feeds observe ->
            // settle twice; exactly one allocation.
            let payment = provider
                .fetch_payment_object(ctx.provider_payment_hint)
                .await
                .map_err(|error| format!("fetch failed: {error}"))?;
            let fact = observed(
                name,
                &payment.provider_payment_id,
                payment.state,
                Some(payment.amount_minor),
                Some(&payment.currency),
                Some(ctx.tenant_id),
                ctx.obligation_ref,
            );
            observe_payment(pool, &fact)
                .await
                .map_err(|error| format!("observe 1 failed: {error}"))?;
            let verified = verify_against_obligation(pool, &fact)
                .await
                .map_err(|error| format!("verify failed: {error}"))?;
            let first = settle_verified(pool, name, &verified)
                .await
                .map_err(|error| format!("settle 1 failed: {error}"))?;
            observe_payment(pool, &fact)
                .await
                .map_err(|error| format!("observe 2 failed: {error}"))?;
            let second = settle_verified(pool, name, &verified)
                .await
                .map_err(|error| format!("settle 2 failed: {error}"))?;
            if !first || second {
                return Err(format!(
                    "exactly-once violated (first={first}, replay={second})"
                ));
            }
            if allocation_count(pool, ctx.invoice_id).await != ARM_AMOUNT {
                return Err("the duplicate delivery must not double-allocate".into());
            }
            Ok(())
        }
        7 => {
            // Out-of-order: failed arrives, then succeeded (truth), then a
            // stale failed again. The verified terminal must hold.
            let failed = observed(
                name,
                ctx.provider_payment_hint,
                PaymentState::Failed,
                Some(ARM_AMOUNT),
                Some(ARM_CURRENCY),
                Some(ctx.tenant_id),
                ctx.obligation_ref,
            );
            let succeeded = observed(
                name,
                ctx.provider_payment_hint,
                PaymentState::Succeeded,
                Some(ARM_AMOUNT),
                Some(ARM_CURRENCY),
                Some(ctx.tenant_id),
                ctx.obligation_ref,
            );
            observe_payment(pool, &failed)
                .await
                .map_err(|error| format!("observe failed-fact: {error}"))?;
            observe_payment(pool, &succeeded)
                .await
                .map_err(|error| format!("observe success-fact: {error}"))?;
            observe_payment(pool, &failed)
                .await
                .map_err(|error| format!("observe stale-fact: {error}"))?;
            let state_now: String = sqlx::query_scalar(
                "SELECT state FROM payment_attempts WHERE provider = $1 \
                   AND provider_payment_id = $2",
            )
            .bind(name)
            .bind(ctx.provider_payment_hint)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("attempt read failed: {error}"))?;
            if state_now != "succeeded" {
                return Err(format!(
                    "a stale failure regressed the terminal success: {state_now}"
                ));
            }
            let verified = verify_against_obligation(pool, &succeeded)
                .await
                .map_err(|error| format!("verify failed: {error}"))?;
            settle_verified(pool, name, &verified)
                .await
                .map_err(|error| format!("settle failed: {error}"))?;
            Ok(())
        }
        8 => {
            // Timeout after a successful charge: the claim stays open, a
            // second tick opens NO second charge (the transport retry
            // reuses the SAME key and row), the repair settles.
            let key = format!("conf{arm}_{}", ctx.invoice_id.simple());
            let claimed = claim_attempt(
                pool,
                name,
                &key,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("claim failed: {error}"))?;
            if !claimed {
                return Err("the first claim must win".into());
            }
            let charge = provider
                .charge_saved_method(SavedMethodCharge {
                    provider_customer_id: format!("customer_{arm}"),
                    provider_method_id: format!("method_{arm}"),
                    amount_minor: ARM_AMOUNT,
                    currency: ARM_CURRENCY.to_string(),
                    description: format!("conformance arm {arm}"),
                    metadata: serde_json::json!({
                        "reference": ctx.obligation_ref,
                        "tenant_id": ctx.tenant_id,
                    }),
                    idempotency_key: key.clone(),
                })
                .await;
            match charge {
                Err(super::ProviderError::Unavailable(_)) => {}
                other => {
                    return Err(format!(
                        "the lost response must surface as Unavailable, got {other:?}"
                    ))
                }
            }
            if !has_open_attempt(pool, name, &key)
                .await
                .map_err(|error| format!("open probe failed: {error}"))?
            {
                return Err("the claim must stay open after the timeout".into());
            }
            let second = claim_attempt(
                pool,
                name,
                &key,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("second claim failed: {error}"))?;
            if second {
                return Err("a second tick opened a second charge".into());
            }
            // The provider's own callback names the charge the lost
            // response hid: the observation links the open claim.
            let fact = observed(
                name,
                ctx.provider_payment_hint,
                PaymentState::Succeeded,
                Some(ARM_AMOUNT),
                Some(ARM_CURRENCY),
                Some(ctx.tenant_id),
                ctx.obligation_ref,
            );
            observe_payment(pool, &fact)
                .await
                .map_err(|error| format!("linking observation failed: {error}"))?;
            // The sweep is the minutes-later backstop, not the inline
            // settle: age the attempt past the repair threshold.
            sqlx::query(
                "UPDATE payment_attempts SET updated_at = NOW() - INTERVAL '10 minutes' \
                 WHERE provider = $1 AND provider_payment_id = $2",
            )
            .bind(name)
            .bind(ctx.provider_payment_hint)
            .execute(pool)
            .await
            .map_err(|error| format!("aging failed: {error}"))?;
            let stats = sweep_open_attempts_with(state, provider.as_ref())
                .await
                .map_err(|error| format!("repair sweep failed: {error}"))?;
            if stats.settled == 0 {
                return Err("the repair sweep must settle the in-flight charge".into());
            }
            if allocation_count(pool, ctx.invoice_id).await != ARM_AMOUNT {
                return Err("the repaired charge must settle exactly its obligation".into());
            }
            Ok(())
        }
        4 => {
            // RequiresAction grants nothing and blocks a blind retry (a
            // retry with the SAME key conflicts on the open attempt; a
            // legitimate dunning retry is a NEW attempt, arm 10).
            let fact = observed(
                name,
                ctx.provider_payment_hint,
                PaymentState::RequiresAction,
                Some(ARM_AMOUNT),
                Some(ARM_CURRENCY),
                Some(ctx.tenant_id),
                ctx.obligation_ref,
            );
            match verify_against_obligation(pool, &fact).await {
                Err(super::engine::VerifyError::NotSuccessful(_)) => {}
                other => return Err(format!("requires_action must refuse, got {other:?}")),
            }
            observe_payment(pool, &fact)
                .await
                .map_err(|error| format!("observe failed: {error}"))?;
            let key = format!("conf{arm}_{}", ctx.invoice_id.simple());
            claim_attempt(
                pool,
                name,
                &key,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("claim failed: {error}"))?;
            confirm_attempt(
                pool,
                name,
                &key,
                ctx.provider_payment_hint,
                PaymentState::RequiresAction,
            )
            .await
            .map_err(|error| format!("confirm failed: {error}"))?;
            let retry = claim_attempt(
                pool,
                name,
                &key,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("retry claim failed: {error}"))?;
            if retry {
                return Err("a requires_action attempt must block blind retry".into());
            }
            if allocation_count(pool, ctx.invoice_id).await != 0 {
                return Err("requires_action must settle nothing".into());
            }
            Ok(())
        }
        5 => {
            // Failed charge: the claim closes failed definitively and
            // settles nothing. (The retry ladder is arm 10's business: a
            // dunning retry is a NEW immutable attempt, never a reopen.)
            let key = format!("conf{arm}_{}", ctx.invoice_id.simple());
            claim_attempt(
                pool,
                name,
                &key,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("claim failed: {error}"))?;
            let payment = provider
                .charge_saved_method(SavedMethodCharge {
                    provider_customer_id: format!("customer_{arm}"),
                    provider_method_id: format!("method_{arm}"),
                    amount_minor: ARM_AMOUNT,
                    currency: ARM_CURRENCY.to_string(),
                    description: format!("conformance arm {arm}"),
                    metadata: serde_json::json!({
                        "reference": ctx.obligation_ref,
                        "tenant_id": ctx.tenant_id,
                    }),
                    idempotency_key: key.clone(),
                })
                .await
                .map_err(|error| format!("charge failed: {error}"))?;
            if payment.state != PaymentState::Failed {
                return Err(format!(
                    "the scripted failure must reach the engine as Failed, got {:?}",
                    payment.state
                ));
            }
            confirm_attempt(
                pool,
                name,
                &key,
                &payment.provider_payment_id,
                payment.state,
            )
            .await
            .map_err(|error| format!("confirm failed: {error}"))?;
            if has_open_attempt(pool, name, &key)
                .await
                .map_err(|error| format!("open probe failed: {error}"))?
            {
                return Err("a failed claim must be closed".into());
            }
            if allocation_count(pool, ctx.invoice_id).await != 0 {
                return Err("a failed charge must settle nothing".into());
            }
            Ok(())
        }
        9 => {
            // Timeout with NO provider confirmation: the stale-claim
            // reconcile asks the provider (authenticated search); when
            // absence cannot be PROVEN, the attempt parks `unresolved` —
            // never closed failed, never auto-retried, never settled.
            let key = dunning_key(ctx.obligation_ref, 1);
            let claimed = claim_attempt(
                pool,
                name,
                &key,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("claim failed: {error}"))?;
            if !claimed {
                return Err("the first claim must win".into());
            }
            let charge = provider
                .charge_saved_method(SavedMethodCharge {
                    provider_customer_id: format!("customer_{arm}"),
                    provider_method_id: format!("method_{arm}"),
                    amount_minor: ARM_AMOUNT,
                    currency: ARM_CURRENCY.to_string(),
                    description: format!("conformance arm {arm}"),
                    metadata: serde_json::json!({
                        "reference": ctx.obligation_ref,
                        "tenant_id": ctx.tenant_id,
                    }),
                    idempotency_key: key.clone(),
                })
                .await;
            match charge {
                Err(super::ProviderError::Unavailable(_)) => {}
                other => {
                    return Err(format!(
                        "the lost response must surface as Unavailable, got {other:?}"
                    ))
                }
            }
            if !has_open_attempt(pool, name, &key)
                .await
                .map_err(|error| format!("open probe failed: {error}"))?
            {
                return Err("the claim must stay open after the timeout".into());
            }
            // Age the claim past the stale-claim window, then sweep.
            sqlx::query(
                "UPDATE payment_attempts SET created_at = NOW() - INTERVAL '2 hours' \
                 WHERE provider = $1 AND idempotency_key = $2",
            )
            .bind(name)
            .bind(&key)
            .execute(pool)
            .await
            .map_err(|error| format!("aging failed: {error}"))?;
            let stats = sweep_open_attempts_with(state, provider.as_ref())
                .await
                .map_err(|error| format!("repair sweep failed: {error}"))?;
            let state_now: String = sqlx::query_scalar(
                "SELECT state FROM payment_attempts WHERE provider = $1 AND idempotency_key = $2",
            )
            .bind(name)
            .bind(&key)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("attempt read failed: {error}"))?;
            if state_now != UNRESOLVED_ATTEMPT_STATE {
                return Err(format!(
                    "absence unprovable must park the attempt `unresolved`, got {state_now}"
                ));
            }
            if stats.settled != 0 {
                return Err("an unconfirmed timeout must never settle".into());
            }
            if allocation_count(pool, ctx.invoice_id).await != 0 {
                return Err("an unresolved attempt must never allocate".into());
            }
            // And it is NEVER auto-retried: the dunning gate refuses while
            // the obligation's attempt sits in `unresolved`.
            let retry = claim_next_attempt(
                pool,
                name,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("dunning probe failed: {error}"))?;
            if retry.is_some() {
                return Err("an unresolved attempt must never be auto-retried".into());
            }
            Ok(())
        }
        10 => {
            // Attempt 2 after a definitive failure: a NEW immutable row
            // with attempt_no = 2 and a DISTINCT idempotency key; attempt
            // 1's row is untouched (closed attempts are never reopened).
            let key1 = dunning_key(ctx.obligation_ref, 1);
            let claimed = claim_attempt(
                pool,
                name,
                &key1,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("claim 1 failed: {error}"))?;
            if !claimed {
                return Err("the first claim must win".into());
            }
            // The definitive failure closes attempt 1.
            confirm_attempt(
                pool,
                name,
                &key1,
                ctx.provider_payment_hint,
                PaymentState::Failed,
            )
            .await
            .map_err(|error| format!("confirm failed: {error}"))?;
            let before: (String, Option<String>, i64) = sqlx::query_as(
                "SELECT state, provider_payment_id, attempt_no::bigint FROM payment_attempts \
                 WHERE provider = $1 AND idempotency_key = $2",
            )
            .bind(name)
            .bind(&key1)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("attempt 1 read failed: {error}"))?;
            if before.0 != "failed" {
                return Err(format!("attempt 1 must be closed failed, got {}", before.0));
            }
            // The SAME key can never reopen it: closed attempts are
            // immutable.
            let reopen = claim_attempt(
                pool,
                name,
                &key1,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("same-key retry failed: {error}"))?;
            if reopen {
                return Err("a closed attempt must never reopen under the same key".into());
            }
            // The dunning ladder opens attempt 2: a new row, a new key.
            let (attempt_no, key2) = claim_next_attempt(
                pool,
                name,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("dunning claim failed: {error}"))?
            .ok_or_else(|| "the dunning ladder must open attempt 2".to_string())?;
            if attempt_no != 2 {
                return Err(format!("the retry must be attempt 2, got {attempt_no}"));
            }
            if key2 == key1 {
                return Err("attempt 2 must carry a distinct idempotency key".into());
            }
            if key2 != dunning_key(ctx.obligation_ref, 2) {
                return Err(format!(
                    "the dunning key must follow the shared scheme, got {key2}"
                ));
            }
            let after: (String, Option<String>, i64) = sqlx::query_as(
                "SELECT state, provider_payment_id, attempt_no::bigint FROM payment_attempts \
                 WHERE provider = $1 AND idempotency_key = $2",
            )
            .bind(name)
            .bind(&key1)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("attempt 1 reread failed: {error}"))?;
            if after != before {
                return Err(format!(
                    "attempt 1's immutable row was mutated: {before:?} -> {after:?}"
                ));
            }
            let second: (String, i64) = sqlx::query_as(
                "SELECT state, attempt_no::bigint FROM payment_attempts \
                 WHERE provider = $1 AND idempotency_key = $2",
            )
            .bind(name)
            .bind(&key2)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("attempt 2 read failed: {error}"))?;
            if second.0 != "pending" || second.1 != 2 {
                return Err(format!(
                    "attempt 2 must be a fresh pending row with attempt_no 2, got {second:?}"
                ));
            }
            Ok(())
        }
        11 => {
            // Scheduler race: two concurrent claims on one key, exactly one
            // wins (the loser never charges) and the winning row is
            // attempt 1 of the obligation's chain.
            let key = dunning_key(ctx.obligation_ref, 1);
            let (first, second) = tokio::join!(
                claim_attempt(
                    pool,
                    name,
                    &key,
                    ctx.tenant_id,
                    ctx.obligation_ref,
                    "conformance",
                    ARM_AMOUNT,
                    ARM_CURRENCY,
                ),
                claim_attempt(
                    pool,
                    name,
                    &key,
                    ctx.tenant_id,
                    ctx.obligation_ref,
                    "conformance",
                    ARM_AMOUNT,
                    ARM_CURRENCY,
                )
            );
            let first = first.map_err(|error| format!("claim A failed: {error}"))?;
            let second = second.map_err(|error| format!("claim B failed: {error}"))?;
            if first == second {
                return Err(format!(
                    "exactly one scheduler must win the claim (A={first}, B={second})"
                ));
            }
            let (rows, attempt_no): (i64, i64) = sqlx::query_as(
                "SELECT COUNT(*), MIN(attempt_no)::bigint FROM payment_attempts \
                 WHERE provider = $1 AND idempotency_key = $2",
            )
            .bind(name)
            .bind(&key)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("race ledger read failed: {error}"))?;
            if rows != 1 || attempt_no != 1 {
                return Err(format!(
                    "the race must leave exactly one attempt row, attempt_no 1 \
                     (rows={rows}, attempt_no={attempt_no})"
                ));
            }
            Ok(())
        }
        12 => {
            // Partial then full refund: distinct neutral refund facts.
            let partial = provider
                .refund(RefundRequest {
                    provider_payment_id: ctx.provider_payment_hint.to_string(),
                    amount_minor: 300,
                    currency: ARM_CURRENCY.to_string(),
                    description: "conformance partial refund".into(),
                    idempotency_key: format!("conf{arm}_partial_{}", ctx.invoice_id.simple()),
                })
                .await
                .map_err(|error| format!("partial refund failed: {error}"))?;
            let full = provider
                .refund(RefundRequest {
                    provider_payment_id: ctx.provider_payment_hint.to_string(),
                    amount_minor: ARM_AMOUNT - 300,
                    currency: ARM_CURRENCY.to_string(),
                    description: "conformance full refund".into(),
                    idempotency_key: format!("conf{arm}_full_{}", ctx.invoice_id.simple()),
                })
                .await
                .map_err(|error| format!("full refund failed: {error}"))?;
            record_refund_fact(pool, &partial)
                .await
                .map_err(|error| format!("partial fact failed: {error}"))?;
            record_refund_fact(pool, &full)
                .await
                .map_err(|error| format!("full fact failed: {error}"))?;
            let rows: Vec<(String, String, i64)> = sqlx::query_as(
                "SELECT provider_refund_id, state, amount_minor FROM payment_provider_refunds \
                 WHERE provider = $1 AND provider_payment_id = $2 ORDER BY amount_minor",
            )
            .bind(name)
            .bind(ctx.provider_payment_hint)
            .fetch_all(pool)
            .await
            .map_err(|error| format!("refund rows read failed: {error}"))?;
            if rows.len() != 2 {
                return Err(format!(
                    "partial and full refunds must be two distinct facts, got {}",
                    rows.len()
                ));
            }
            let refunded_total: i64 = rows.iter().map(|(_, _, amount)| *amount).sum();
            if refunded_total != ARM_AMOUNT {
                return Err(format!(
                    "the refunds must sum to the charge, got {refunded_total}"
                ));
            }
            Ok(())
        }
        16 => {
            // Missed webhook: a confirmed-but-unsettled attempt is repaired
            // from the AUTHENTICATED fetch.
            let key = format!("conf{arm}_{}", ctx.invoice_id.simple());
            claim_attempt(
                pool,
                name,
                &key,
                ctx.tenant_id,
                ctx.obligation_ref,
                "conformance",
                ARM_AMOUNT,
                ARM_CURRENCY,
            )
            .await
            .map_err(|error| format!("claim failed: {error}"))?;
            confirm_attempt(
                pool,
                name,
                &key,
                ctx.provider_payment_hint,
                PaymentState::Pending,
            )
            .await
            .map_err(|error| format!("confirm failed: {error}"))?;
            // Age the attempt past the repair threshold.
            sqlx::query(
                "UPDATE payment_attempts SET updated_at = NOW() - INTERVAL '10 minutes' \
                 WHERE provider = $1 AND idempotency_key = $2",
            )
            .bind(name)
            .bind(&key)
            .execute(pool)
            .await
            .map_err(|error| format!("aging failed: {error}"))?;
            let stats = sweep_open_attempts_with(state, provider.as_ref())
                .await
                .map_err(|error| format!("repair sweep failed: {error}"))?;
            if stats.settled == 0 {
                return Err("the missed webhook must be repaired by the sweep".into());
            }
            if allocation_count(pool, ctx.invoice_id).await != ARM_AMOUNT {
                return Err("the repaired charge must settle exactly its obligation".into());
            }
            Ok(())
        }
        13..=15 => {
            // Dispute reconciliation (arms 13/14/15): the neutral fact and
            // the dispute row land, a LOST dispute posts the terminal
            // debit the refund writer uses, a WON/REVERSED dispute posts
            // the restoration. Capability-gated: a provider that declares
            // no dispute retrieval passes by refusing `list_disputes`
            // VISIBLY (an Err) — never a silent empty list, which would
            // hide a chargeback from reconciliation.
            if !provider.capabilities().disputes {
                return match provider.list_disputes(ctx.provider_payment_hint).await {
                    Err(_) => Ok(()),
                    Ok(facts) => Err(format!(
                        "a provider without dispute retrieval must refuse list_disputes, \
                         never answer a silent list ({})",
                        facts.len()
                    )),
                };
            }
            let disputes = provider
                .list_disputes(ctx.provider_payment_hint)
                .await
                .map_err(|error| format!("dispute list failed: {error}"))?;
            if disputes.is_empty() {
                return Err("the scripted dispute must arrive as a fact".into());
            }
            for dispute in &disputes {
                observe_dispute(pool, name, dispute)
                    .await
                    .map_err(|error| format!("dispute observe failed: {error}"))?;
            }
            let dispute = &disputes[0];
            let expected_state = match arm {
                13 => "opened",
                14 => "lost",
                _ => "won",
            };
            let row_state: String = sqlx::query_scalar(
                "SELECT state FROM payment_disputes \
                 WHERE provider = $1 AND provider_dispute_id = $2",
            )
            .bind(name)
            .bind(&dispute.provider_dispute_id)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("dispute row read failed: {error}"))?;
            if row_state != expected_state {
                return Err(format!(
                    "the dispute row must be {expected_state:?}, got {row_state:?}"
                ));
            }
            let event_kind = format!(
                "dispute{}",
                match arm {
                    13 => "Opened",
                    14 => "Lost",
                    _ => "Won",
                }
            );
            let facts: i64 = sqlx::query_scalar(
                "SELECT COUNT(*) FROM payment_provider_events \
                 WHERE provider = $1 AND event_kind = $2 AND provider_payment_id = $3",
            )
            .bind(name)
            .bind(&event_kind)
            .bind(ctx.provider_payment_hint)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("dispute fact read failed: {error}"))?;
            if facts == 0 {
                return Err(format!(
                    "the neutral ledger must carry the {event_kind} fact"
                ));
            }
            // Money movement: an OPENED dispute moves nothing; a LOST
            // dispute posts the terminal debit; a WON dispute posts the
            // restoration. Both journals are idempotent on the dispute id.
            let lost_key = format!("dispute:{}:lost", dispute.provider_dispute_id);
            let won_key = format!("dispute:{}:won", dispute.provider_dispute_id);
            let (debits, credits): (i64, i64) = sqlx::query_as(
                "SELECT COALESCE(SUM(l.debit_cents), 0)::bigint, COALESCE(SUM(l.credit_cents), 0)::bigint \
                 FROM journal_entries e JOIN journal_lines l ON l.entry_id = e.id \
                 WHERE e.idempotency_key = $1",
            )
            .bind(if arm == 14 { &lost_key } else { &won_key })
            .fetch_one(pool)
            .await
            .map_err(|error| format!("dispute journal read failed: {error}"))?;
            match arm {
                13 => {
                    let lost_debits: i64 = sqlx::query_scalar(
                        "SELECT COALESCE(SUM(l.debit_cents), 0)::bigint \
                         FROM journal_entries e JOIN journal_lines l ON l.entry_id = e.id \
                         WHERE e.idempotency_key = $1",
                    )
                    .bind(&lost_key)
                    .fetch_one(pool)
                    .await
                    .map_err(|error| format!("opened-dispute journal read failed: {error}"))?;
                    if lost_debits != 0 {
                        return Err("an OPENED dispute must not move money".into());
                    }
                }
                14 => {
                    if debits != dispute.amount_minor || credits != dispute.amount_minor {
                        return Err(format!(
                            "a LOST dispute must post the terminal debit for the full amount \
                             (debited {debits}, credited {credits}, expected {})",
                            dispute.amount_minor
                        ));
                    }
                }
                _ => {
                    if debits != dispute.amount_minor || credits != dispute.amount_minor {
                        return Err(format!(
                            "a WON dispute must post the restoration for the full amount \
                             (debited {debits}, credited {credits}, expected {})",
                            dispute.amount_minor
                        ));
                    }
                }
            }
            Ok(())
        }
        17 => {
            // Payout/settlement facts land on the neutral ledger.
            let settlements = provider
                .list_settlements()
                .await
                .map_err(|error| format!("settlement list failed: {error}"))?;
            if settlements.len() != 1 {
                return Err(format!(
                    "the scripted payout must arrive as one fact, got {}",
                    settlements.len()
                ));
            }
            for settlement in &settlements {
                record_settlement_fact(pool, name, settlement)
                    .await
                    .map_err(|error| format!("settlement fact failed: {error}"))?;
            }
            let payload: serde_json::Value = sqlx::query_scalar(
                "SELECT payload FROM payment_provider_events \
                 WHERE provider = $1 AND event_kind = 'settlementCompleted' \
                 ORDER BY received_at DESC LIMIT 1",
            )
            .bind(name)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("settlement row read failed: {error}"))?;
            // Asserted against the HARNESS's amount (ctx), not the
            // provider's echo: a provider that misreports payout money
            // must fail here (teeth).
            if payload["amountMinor"].as_i64() != Some(ctx.amount_minor) {
                return Err(format!(
                    "the neutral settlement fact must carry the true amount: {payload}"
                ));
            }
            Ok(())
        }
        18 => {
            // The reserved cancel-at-period-end arm (beta authority
            // inversion): the LOCAL flag is the authority. A subscription
            // seeded at current_period_end with cancel_at_period_end = true
            // is ended by the local renewal worker — NO new invoice, NO
            // charge claim (the double counts charge calls and stays at
            // zero for this arm), NO allocation, and the local vocabulary
            // (status `canceled`, flag cleared, tenant downgraded) applies.
            let suffix = Uuid::new_v4().simple().to_string()[..8].to_string();
            let subscription_id = format!("local_conf18_{suffix}");
            // The period end seeds a second BEHIND the wall clock: the worker's
            // due-comparison receives the TEST PROCESS's Utc::now() while the
            // seed reads the DATABASE's NOW() — on a VM whose clock runs even
            // tens of milliseconds ahead of the host, a bare NOW() boundary
            // makes the subscription "not yet due" and the arm flakes.
            sqlx::query(
                "INSERT INTO subscription_state \
                     (tenant_id, provider_contract_id, plan, status, billing_interval, \
                      billing_cycle_start, billing_cycle_end, cancel_at_period_end) \
                 VALUES ($1, $2, 'growth', 'active', 'monthly', \
                         NOW() - INTERVAL '1 month', NOW() - INTERVAL '1 second', true)",
            )
            .bind(ctx.tenant_id)
            .bind(&subscription_id)
            .execute(pool)
            .await
            .map_err(|error| format!("arm 18: subscription seed failed: {error}"))?;
            let invoices_before: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE tenant_id = $1")
                    .bind(ctx.tenant_id)
                    .fetch_one(pool)
                    .await
                    .map_err(|error| format!("arm 18: invoice count failed: {error}"))?;

            let renewed = crate::plan_billing::renew_due_subscriptions_with(
                state,
                provider.clone(),
                Utc::now(),
            )
            .await
            .map_err(|error| format!("arm 18: renewal worker failed: {error}"))?;
            if renewed != 0 {
                return Err(format!(
                    "a cancel-at-period-end subscription must not renew, worker renewed {renewed}"
                ));
            }
            let invoices_after: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM invoices WHERE tenant_id = $1")
                    .bind(ctx.tenant_id)
                    .fetch_one(pool)
                    .await
                    .map_err(|error| format!("arm 18: invoice recount failed: {error}"))?;
            if invoices_after != invoices_before {
                return Err(format!(
                    "cancel-at-period-end must not create an invoice \
                     (before {invoices_before}, after {invoices_after})"
                ));
            }
            let attempts: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM payment_attempts WHERE tenant_id = $1")
                    .bind(ctx.tenant_id)
                    .fetch_one(pool)
                    .await
                    .map_err(|error| format!("arm 18: attempt count failed: {error}"))?;
            if attempts != 0 {
                return Err("cancel-at-period-end must never claim a charge attempt".into());
            }
            if allocation_count(pool, ctx.invoice_id).await != 0 {
                return Err("cancel-at-period-end must settle nothing".into());
            }
            let (status, cancel_flag): (String, bool) = sqlx::query_as(
                "SELECT status, cancel_at_period_end FROM subscription_state \
                 WHERE tenant_id = $1",
            )
            .bind(ctx.tenant_id)
            .fetch_one(pool)
            .await
            .map_err(|error| format!("arm 18: subscription read failed: {error}"))?;
            if status != "canceled" || cancel_flag {
                return Err(format!(
                    "the subscription must end per the local vocabulary \
                     (canceled, flag cleared), got status={status:?} flag={cancel_flag}"
                ));
            }
            let plan: String = sqlx::query_scalar("SELECT plan FROM tenants WHERE id = $1")
                .bind(ctx.tenant_id)
                .fetch_one(pool)
                .await
                .map_err(|error| format!("arm 18: tenant read failed: {error}"))?;
            if plan != "free" {
                return Err(format!(
                    "an ended subscription must downgrade the tenant to free, got {plan}"
                ));
            }
            Ok(())
        }
        other => Err(format!("unknown arm {other}")),
    }
}

// ---------------------------------------------------------------------------
// Tests: the double passes the matrix; defects break their mapped arm
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    /// The double lane's scripting: each arm scripts the double exactly as
    /// the matrix expects a WELL-BEHAVED provider to behave.
    struct DoubleScripting {
        provider: std::sync::Arc<ConformanceProvider>,
    }

    impl ConformanceScripting for DoubleScripting {
        fn arm_setup(&self, ctx: &ConformanceCtx<'_>) -> Result<(), String> {
            match ctx.arm {
                5 => {
                    self.provider
                        .script_charge(ctx.provider_payment_hint, PaymentState::Failed);
                }
                6 => {
                    self.provider.publish_payment(Payment {
                        provider: ctx.provider_name.to_string(),
                        provider_payment_id: ctx.provider_payment_hint.to_string(),
                        state: PaymentState::Succeeded,
                        amount_minor: ARM_AMOUNT,
                        currency: ARM_CURRENCY.to_string(),
                        created_at: None,
                    });
                }
                8 => {
                    // The charge's response is LOST; the provider's own
                    // record (fetched later) shows the charge succeeded.
                    self.provider
                        .script_charge_error(ProviderError::Unavailable("lost response".into()));
                    self.provider.publish_payment(Payment {
                        provider: ctx.provider_name.to_string(),
                        provider_payment_id: ctx.provider_payment_hint.to_string(),
                        state: PaymentState::Succeeded,
                        amount_minor: ARM_AMOUNT,
                        currency: ARM_CURRENCY.to_string(),
                        created_at: None,
                    });
                }
                9 => {
                    // The charge's response is lost AND the provider-side
                    // search cannot prove absence: the stale-claim
                    // reconcile must park the attempt `unresolved`.
                    self.provider
                        .script_charge_error(ProviderError::Unavailable("lost response".into()));
                }
                12 => {
                    self.provider.script_refund(
                        "re_conf_partial",
                        ctx.provider_payment_hint,
                        RefundState::Succeeded,
                        300,
                    );
                    self.provider.script_refund(
                        "re_conf_full",
                        ctx.provider_payment_hint,
                        RefundState::Pending,
                        ARM_AMOUNT - 300,
                    );
                }
                13..=15 => {
                    // The dispute the arm reconciles: opened / lost / won.
                    // The per-run dispute id follows the payout arm's
                    // rule: provider fact ids are provider-unique, so a
                    // reused id would let the ledger's ON CONFLICT hide a
                    // later run's fact (exactly the false-pass the
                    // DisputeStateLies tooth probes).
                    let state = match ctx.arm {
                        13 => DisputeState::Opened,
                        14 => DisputeState::Lost,
                        _ => DisputeState::Won,
                    };
                    self.provider.script_dispute(
                        ctx.provider_payment_hint,
                        Dispute {
                            provider: ctx.provider_name.to_string(),
                            provider_dispute_id: format!(
                                "disp_conf_{}_{}",
                                ctx.arm,
                                ctx.invoice_id.simple()
                            ),
                            provider_payment_id: ctx.provider_payment_hint.to_string(),
                            state,
                            amount_minor: ARM_AMOUNT,
                            currency: ARM_CURRENCY.to_string(),
                            reason: Some("conformance".into()),
                            opened_at: None,
                        },
                    );
                }
                16 => {
                    // The charge SUCCEEDED at the provider; only the webhook
                    // was missed. The repair sweep must find the fact via the
                    // authenticated fetch, not a "never knew this payment".
                    self.provider.publish_payment(Payment {
                        provider: ctx.provider_name.to_string(),
                        provider_payment_id: ctx.provider_payment_hint.to_string(),
                        state: PaymentState::Succeeded,
                        amount_minor: ARM_AMOUNT,
                        currency: ARM_CURRENCY.to_string(),
                        created_at: None,
                    });
                }
                17 => {
                    // The payout id is per-RUN (keyed off the fresh invoice):
                    // provider fact ids are provider-unique, and a reused id
                    // would let the ledger's ON CONFLICT hide a later run's
                    // fact behind an earlier run's row — which is exactly the
                    // false-pass the SettlementAmountWrong tooth probes.
                    self.provider.script_settlement(Settlement {
                        provider: ctx.provider_name.to_string(),
                        provider_settlement_id: format!("stl_conf_{}", ctx.invoice_id.simple()),
                        amount_minor: ARM_AMOUNT,
                        currency: ARM_CURRENCY.to_string(),
                        settled_at: None,
                    });
                }
                _ => {}
            }
            Ok(())
        }
    }

    async fn provision(tag: &str) -> Option<crate::test_support::TestEnv> {
        crate::test_support::provision(tag).await
    }

    #[tokio::test]
    async fn the_scriptable_double_passes_the_full_matrix() {
        let Some(env) = provision("payments_conformance_matrix").await else {
            return;
        };
        let double = std::sync::Arc::new(ConformanceProvider::new("conformance"));
        let scripting = DoubleScripting {
            provider: double.clone(),
        };
        let report = run_provider_conformance(&env.state, double, &scripting).await;
        assert_all_arms(&report);
        env.finish().await;
    }

    fn assert_all_arms(report: &ConformanceReport) {
        if let Err(failures) = report.assert_all_passed() {
            panic!("{failures}");
        }
        assert_eq!(report.arms.len(), MATRIX.len());
    }

    /// Mutation teeth: every defect breaks exactly its mapped arm.
    #[tokio::test]
    async fn seeded_defects_fail_their_mapped_arms() {
        let Some(env) = provision("payments_conformance_teeth").await else {
            return;
        };
        for defect in [
            Defect::HideTimeout,
            Defect::FetchLiesAboutState,
            Defect::FetchReportsWrongCurrency,
            Defect::RefundIdCollision,
            Defect::SettlementAmountWrong,
            Defect::DisputeStateLies,
        ] {
            let double = std::sync::Arc::new(ConformanceProvider::new("conformance"));
            double.seed_defect(defect);
            let scripting = DoubleScripting {
                provider: double.clone(),
            };
            let report = run_provider_conformance(&env.state, double, &scripting).await;
            let mapped = report
                .arms
                .iter()
                .find(|arm| arm.arm == defect.breaks_arm())
                .expect("mapped arm ran");
            assert!(
                !mapped.passed,
                "defect {defect:?} must break arm {}: {}",
                defect.breaks_arm(),
                mapped.detail
            );
        }
        env.finish().await;
    }

    /// Arm 8's no-second-charge guarantee is literal: the double receives
    /// exactly the scripted charge calls even though the sweeps and retries
    /// run (arms 5, 8 and 9 each charge once; no arm ever charges twice).
    #[tokio::test]
    async fn the_timeout_arm_never_charges_twice() {
        let Some(env) = provision("payments_conformance_timeout").await else {
            return;
        };
        let double = std::sync::Arc::new(ConformanceProvider::new("conformance"));
        let scripting = DoubleScripting {
            provider: double.clone(),
        };
        let report = run_provider_conformance(&env.state, double.clone(), &scripting).await;
        assert_all_arms(&report);
        assert_eq!(
            double.charge_calls(),
            3,
            "exactly the scripted charges (arm 8 timeout + arm 9 unconfirmed timeout \
             + arm 5 failure), never a retry"
        );
        env.finish().await;
    }

    #[test]
    fn the_matrix_ids_are_stable_and_complete() {
        for (expected, (id, _)) in MATRIX.iter().enumerate() {
            assert_eq!(*id, expected as u8 + 1);
        }
        for defect in [
            Defect::HideTimeout,
            Defect::FetchLiesAboutState,
            Defect::FetchReportsWrongCurrency,
            Defect::RefundIdCollision,
            Defect::SettlementAmountWrong,
            Defect::DisputeStateLies,
        ] {
            let arm = defect.breaks_arm();
            assert!((1..=MATRIX.len() as u8).contains(&arm));
        }
    }
}
