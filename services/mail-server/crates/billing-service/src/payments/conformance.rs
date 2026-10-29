//! The shared provider conformance harness (external audit, seventh pass,
//! P0-A, step 9 of the mandated 18-step order).
//!
//! ONE matrix, ONE harness, every adapter. [`run_provider_conformance`]
//! drives the audit's exact twelve-arm matrix against any
//! [`PaymentProvider`] plus the neutral engine, so a new processor (Stripe,
//! steps 11-18) proves itself against the SAME gates Mollie passes today
//! instead of writing its own idea of correct.
//!
//! The matrix (ids are stable; the report names them):
//!
//! | arm | audit statement |
//! |-----|-----------------|
//! | 1 | wrong tenant (cross-tenant obligation) refuses, nothing settles |
//! | 2 | wrong amount refuses: absent/zero never mints, over-charge never over-settles |
//! | 3 | wrong currency refuses |
//! | 4 | duplicate webhook settles exactly once |
//! | 5 | out-of-order events never regress the verified terminal |
//! | 6 | timeout after a successful charge: claim stays open, no second
//!      charge, the repair sweep settles it |
//! | 7 | requires_action grants nothing and blocks blind retry |
//! | 8 | failed charge closes the claim failed and stays retryable |
//! | 9 | scheduler race: two concurrent claims, exactly one wins |
//! | 10 | partial + full refund produce distinct neutral refund facts |
//! | 11 | missed webhook: the repair sweep settles from the authenticated fetch |
//! | 12 | payout/settlement facts land as neutral settlement facts |
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

use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;

use super::engine::{
    claim_attempt, confirm_attempt, has_open_attempt, observe_payment, record_refund_fact,
    record_settlement_fact, settle_verified, sweep_open_attempts_with, verify_against_obligation,
    ObservedPayment,
};
use super::{
    Checkout, CheckoutRequest, Payment, PaymentProvider, PaymentState, ProviderCapabilities,
    ProviderError, RecurringSchedule, RecurringScheduleRequest, RecurringScheduleState, Refund,
    RefundRequest, RefundState, SavedMethodCharge, Settlement,
};

/// The matrix ids and names, in report order.
pub const MATRIX: [(u8, &str); 12] = [
    (1, "wrong tenant refuses"),
    (2, "wrong amount refuses"),
    (3, "wrong currency refuses"),
    (4, "duplicate webhook settles exactly once"),
    (5, "out-of-order events stay terminal"),
    (6, "timeout after charge: no second charge, repair settles"),
    (7, "requires_action grants nothing"),
    (8, "failed charge closes the claim, retryable"),
    (9, "scheduler race: one claim wins"),
    (10, "partial and full refunds are distinct facts"),
    (11, "missed webhook repaired by the sweep"),
    (12, "settlement facts land on the neutral ledger"),
];

// ---------------------------------------------------------------------------
// The scriptable double
// ---------------------------------------------------------------------------

/// A contract defect the double can be seeded with, to prove the harness
/// FAILS a defective provider (mutation teeth). Each variant names the arm
/// it must break.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Defect {
    /// A charge that should surface the lost response as an error instead
    /// reports success. Must fail arm 6 (the timeout is hidden).
    HideTimeout,
    /// The authenticated fetch lies about the state (paid reported failed).
    /// Must fail arm 11 (the repair sweep cannot settle a "failed" charge).
    FetchLiesAboutState,
    /// The authenticated fetch reports the wrong currency. Must fail arm 4
    /// (verification refuses, so the exactly-once settle never happens).
    FetchReportsWrongCurrency,
    /// Two distinct refunds answer with the same refund id. Must fail arm
    /// 10 (the second refund collapses onto the first ledger row).
    RefundIdCollision,
    /// Settlement amounts are misreported. Must fail arm 12 (the recorded
    /// neutral fact carries the wrong money).
    SettlementAmountWrong,
}

impl Defect {
    /// The arm a seeded defect must break (the teeth mapping).
    pub fn breaks_arm(self) -> u8 {
        match self {
            Defect::HideTimeout => 6,
            Defect::FetchLiesAboutState => 11,
            Defect::FetchReportsWrongCurrency => 4,
            Defect::RefundIdCollision => 10,
            Defect::SettlementAmountWrong => 12,
        }
    }
}

#[derive(Default)]
struct Script {
    charges: VecDeque<Result<Payment, ProviderError>>,
    charge_calls: u64,
    refunds: VecDeque<Result<Refund, ProviderError>>,
    payments: HashMap<String, Payment>,
    settlements: VecDeque<Settlement>,
    schedule_counter: u64,
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

    async fn create_recurring_schedule(
        &self,
        request: RecurringScheduleRequest,
    ) -> Result<RecurringSchedule, ProviderError> {
        let mut script = self.script.lock().expect("script lock");
        script.schedule_counter += 1;
        Ok(RecurringSchedule {
            provider: self.name.to_string(),
            provider_schedule_id: format!("sched_{}", script.schedule_counter),
            provider_customer_id: request.provider_customer_id,
            state: RecurringScheduleState::Active,
            amount_minor: Some(request.amount_minor),
            currency: Some(request.currency),
            next_charge_date: None,
        })
    }

    async fn fetch_recurring_schedule(
        &self,
        provider_customer_id: &str,
        provider_schedule_id: &str,
    ) -> Result<RecurringSchedule, ProviderError> {
        Ok(RecurringSchedule {
            provider: self.name.to_string(),
            provider_schedule_id: provider_schedule_id.to_string(),
            provider_customer_id: provider_customer_id.to_string(),
            state: RecurringScheduleState::Active,
            amount_minor: None,
            currency: None,
            next_charge_date: None,
        })
    }

    async fn list_recurring_schedules(
        &self,
        provider_customer_id: &str,
    ) -> Result<Vec<RecurringSchedule>, ProviderError> {
        Ok(vec![RecurringSchedule {
            provider: self.name.to_string(),
            provider_schedule_id: "sched_1".to_string(),
            provider_customer_id: provider_customer_id.to_string(),
            state: RecurringScheduleState::Active,
            amount_minor: None,
            currency: None,
            next_charge_date: None,
        }])
    }

    async fn cancel_recurring_schedule(
        &self,
        _provider_customer_id: &str,
        _provider_schedule_id: &str,
    ) -> Result<(), ProviderError> {
        Ok(())
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

/// Run the full twelve-arm conformance matrix against one provider plus the
/// neutral engine. Never panics: every arm's outcome lands in the report.
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
        let detail = match run_arm(state, provider.as_ref(), &ctx).await {
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
    provider: &dyn PaymentProvider,
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
            // Wrong amount: an absent amount refuses outright, and an
            // over-charge can never settle more than the obligation.
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
            let over = observed(
                name,
                ctx.provider_payment_hint,
                PaymentState::Succeeded,
                Some(ARM_AMOUNT * 10),
                Some(ARM_CURRENCY),
                Some(ctx.tenant_id),
                ctx.obligation_ref,
            );
            let verified = verify_against_obligation(pool, &over)
                .await
                .map_err(|error| format!("over-charge should cap, not refuse: {error}"))?;
            if verified.allocation_minor != ARM_AMOUNT {
                return Err(format!(
                    "the allocation must cap at the obligation, got {}",
                    verified.allocation_minor
                ));
            }
            settle_verified(pool, name, &verified)
                .await
                .map_err(|error| format!("settle failed: {error}"))?;
            let allocated = allocation_count(pool, ctx.invoice_id).await;

            if allocated != ARM_AMOUNT {
                return Err(format!(
                    "the ledger must never exceed the obligation: {allocated}"
                ));
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
        4 => {
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
        5 => {
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
        6 => {
            // Timeout after a successful charge: the claim stays open, a
            // second tick opens NO second charge, the repair settles.
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
            let stats = sweep_open_attempts_with(state, provider)
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
        7 => {
            // RequiresAction grants nothing and blocks a blind retry.
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
        8 => {
            // Failed charge: the claim closes failed and stays retryable.
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
                return Err("a failed claim must not block the retry ladder".into());
            }
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
            if !retry {
                return Err("the dunning ladder must be able to retry a failed charge".into());
            }
            Ok(())
        }
        9 => {
            // Scheduler race: two concurrent claims on one key, exactly one
            // wins (the loser never charges).
            let key = format!("conf{arm}_{}", ctx.invoice_id.simple());
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
            Ok(())
        }
        10 => {
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
        11 => {
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
            let stats = sweep_open_attempts_with(state, provider)
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
        12 => {
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
                4 => {
                    self.provider.publish_payment(Payment {
                        provider: ctx.provider_name.to_string(),
                        provider_payment_id: ctx.provider_payment_hint.to_string(),
                        state: PaymentState::Succeeded,
                        amount_minor: ARM_AMOUNT,
                        currency: ARM_CURRENCY.to_string(),
                        created_at: None,
                    });
                }
                6 => {
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
                8 => {
                    self.provider
                        .script_charge(ctx.provider_payment_hint, PaymentState::Failed);
                }
                10 => {
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
                11 => {
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
                12 => {
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

    /// Arm 6's no-second-charge guarantee is literal: the double receives
    /// exactly one charge call even though two ticks ran.
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
            2,
            "exactly the scripted charges (arm 6 timeout + arm 8 failure), never a retry"
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
        ] {
            let arm = defect.breaks_arm();
            assert!((1..=MATRIX.len() as u8).contains(&arm));
        }
    }
}
