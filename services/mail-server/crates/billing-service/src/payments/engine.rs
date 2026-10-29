//! The generic payment engine: claim, verify, settle, repair (external
//! audit, mandated steps 7 and 8).
//!
//! ONE core that every provider charge path and every reconciliation path
//! shares, so the audit's exactly-once gates are structural, not per-module
//! conventions:
//!
//! * **Claim before charge** ([`claim_attempt`]): the scheduler INSERTs a
//!   `pending` attempt row under a UNIQUE (provider, idempotency_key)
//!   index BEFORE calling the provider. A concurrent tick's INSERT hits
//!   the constraint and skips, so two schedulers can never open two
//!   charges for one operation ("scheduler race -> one payment attempt").
//! * **Confirm after charge** ([`confirm_attempt`]): the provider payment
//!   id and normalized state land on the claimed row. A LOST RESPONSE
//!   (timeout after a successful provider charge) leaves the claim open
//!   with no payment id; the next tick's claim is rejected, so no second
//!   charge is ever minted, and the webhook's
//!   [`observe_payment`] links the provider's own callback to the open
//!   claim by obligation reference.
//! * **Verify then settle** ([`verify_against_obligation`] +
//!   [`settle_verified`]): a provider fact settles an obligation only
//!   after tenant, amount, currency and state are checked against the
//!   LOCAL invoice, and the allocation is idempotent on the operation id,
//!   so a replayed webhook or a repair sweep settles exactly once.
//! * **Repair** ([`sweep_open_attempts`], audit gate E): attempts still
//!   open are re-fetched WITH PROVIDER AUTHENTICATION and driven through
//!   the same verify-then-settle core the webhook uses; a missed webhook
//!   can no longer strand a paid charge.
//!
//! Money is integer minor units end to end; no float participates.

use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;

use super::{PaymentProvider, PaymentState};

/// The states that mean "a charge may be moving money right now". A new
/// claim for an operation in one of these states is refused (the gates).
pub const OPEN_ATTEMPT_STATES_SQL: &str = "('pending','processing')";

/// A provider payment fact as the engine consumes it: everything the
/// verify-then-settle core needs, nothing provider-shaped. Built by
/// adapters (the Mollie webhook normalizer) or by repair fetches.
#[derive(Debug, Clone)]
pub struct ObservedPayment {
    pub provider: String,
    pub provider_payment_id: String,
    pub state: PaymentState,
    pub amount_minor: Option<i64>,
    pub currency: Option<String>,
    /// The tenant the provider fact attributes the payment to; `None`
    /// means unattributed (the engine will not settle, only ledger).
    pub tenant_id: Option<String>,
    /// OUR reference for the obligation (`invoice:{uuid}`).
    pub obligation_ref: Option<String>,
    /// What this payment is for (attempts ledger labeling).
    pub purpose: &'static str,
}

/// The allocation's unique operation id, the settlement idempotency key.
/// Provider name + provider payment id: stable, collision-free, and the
/// same shape the pre-engine settlement used.
pub fn operation_id(provider: &str, provider_payment_id: &str) -> String {
    format!("{provider}:{}", provider_payment_id.trim())
}

/// Case-insensitive ISO 4217 comparison (never parses, never converts).
pub fn currencies_match(left: &str, right: &str) -> bool {
    left.trim().eq_ignore_ascii_case(right.trim())
}

/// The amount actually recorded as an allocation: the verified charge,
/// capped against the authoritative remaining obligation, never negative.
pub fn allocation_minor(charged_minor: i64, outstanding_minor: i64) -> i64 {
    charged_minor.min(outstanding_minor).max(0)
}

/// Parse an obligation reference into the local invoice id
/// (`invoice:{uuid}` or a bare uuid). Garbage is refused, never guessed.
pub fn obligation_invoice_id(obligation_ref: &str) -> Option<Uuid> {
    let reference = obligation_ref.trim();
    let candidate = reference
        .strip_prefix("invoice:")
        .map(str::trim)
        .unwrap_or(reference);
    Uuid::parse_str(candidate).ok()
}

// ---------------------------------------------------------------------------
// The execution ledger (payment_attempts)
// ---------------------------------------------------------------------------

/// Atomically CLAIM the right to execute one charge: inserts a `pending`
/// attempt row, or RE-OPENS a claim whose attempt already reached a
/// terminal failure (the retry ladder). `Ok(false)` means another tick
/// already owns the operation, an attempt is unresolved in flight, or the
/// charge already succeeded: NO second charge may be opened.
///
/// The insert commits on the caller's executor; when called on the pool it
/// is visible immediately, which is what makes the claim a cross-tick lock.
#[allow(clippy::too_many_arguments)]
pub async fn claim_attempt(
    db: &PgPool,
    provider: &str,
    idempotency_key: &str,
    tenant_id: &str,
    obligation_ref: &str,
    purpose: &str,
    amount_minor: i64,
    currency: &str,
) -> Result<bool, sqlx::Error> {
    let claimed = sqlx::query(
        r#"
        INSERT INTO payment_attempts
            (tenant_id, provider, provider_payment_id, state, amount_minor, currency,
             purpose, obligation_ref, idempotency_key)
        VALUES ($1, $2, NULL, 'pending', $3, $4, $5, $6, $7)
        ON CONFLICT (provider, idempotency_key) WHERE idempotency_key IS NOT NULL DO UPDATE SET
            state = 'pending',
            provider_payment_id = NULL,
            tenant_id = EXCLUDED.tenant_id,
            amount_minor = EXCLUDED.amount_minor,
            currency = EXCLUDED.currency,
            purpose = EXCLUDED.purpose,
            obligation_ref = EXCLUDED.obligation_ref,
            updated_at = NOW()
        WHERE payment_attempts.state IN ('failed', 'canceled')
        "#,
    )
    .bind(tenant_id)
    .bind(provider)
    .bind(amount_minor)
    .bind(currency.trim().to_ascii_uppercase())
    .bind(purpose)
    .bind(obligation_ref)
    .bind(idempotency_key)
    .execute(db)
    .await?;
    Ok(claimed.rows_affected() > 0)
}

/// Record the outcome of a claimed charge: the provider payment id and the
/// normalized state land on the claim. Idempotent (a replay updates the
/// same row); a terminal state closes the claim so future ticks may retry.
pub async fn confirm_attempt(
    db: &PgPool,
    provider: &str,
    idempotency_key: &str,
    provider_payment_id: &str,
    state: PaymentState,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE payment_attempts
        -- NULLIF: an EMPTY payment id (the caller refuses to bind an
        -- unidentifiable charge) stays NULL, so the row remains the
        -- keyless shape fail_claim and the reopen gate key on.
        SET provider_payment_id = NULLIF($3, ''),
            state = $4,
            updated_at = NOW()
        WHERE provider = $1
          AND idempotency_key = $2
          AND state = 'pending'
          AND provider_payment_id IS NULL
          -- The unique (provider, provider_payment_id) key means ONE
          -- attempt row per provider payment object: when another claim
          -- already recorded this payment, a blind retry's confirm is a
          -- NO-OP (the existing row owns the object), never a violation.
          AND NOT EXISTS (
              SELECT 1 FROM payment_attempts other
              WHERE other.provider = payment_attempts.provider
                AND other.provider_payment_id = NULLIF($3, '')
                AND other.idempotency_key IS DISTINCT FROM payment_attempts.idempotency_key
          )
        "#,
    )
    .bind(provider)
    .bind(idempotency_key)
    .bind(provider_payment_id.trim())
    .bind(state_str(state))
    .execute(db)
    .await?;
    Ok(())
}

/// Close a claim as FAILED without a provider payment id (the provider
/// refused before minting one). The claim row keeps `provider_payment_id`
/// NULL, so it can never collide with another keyless claim.
pub async fn fail_claim(
    db: &PgPool,
    provider: &str,
    idempotency_key: &str,
) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        UPDATE payment_attempts
        SET state = 'failed', updated_at = NOW()
        WHERE provider = $1
          AND idempotency_key = $2
          AND state = 'pending'
          AND provider_payment_id IS NULL
        "#,
    )
    .bind(provider)
    .bind(idempotency_key)
    .execute(db)
    .await?;
    Ok(())
}

/// `true` while an operation's attempt is unresolved in flight. Kept for
/// callers that probe without claiming (observability, tests).
pub async fn has_open_attempt(
    db: &PgPool,
    provider: &str,
    idempotency_key: &str,
) -> Result<bool, sqlx::Error> {
    sqlx::query_scalar::<_, bool>(
        r#"
        SELECT EXISTS(
            SELECT 1 FROM payment_attempts
            WHERE provider = $1
              AND idempotency_key = $2
              AND state IN ('pending', 'processing')
        )
        "#,
    )
    .bind(provider)
    .bind(idempotency_key)
    .fetch_one(db)
    .await
}

/// Expire claim rows that can never be confirmed: a KEYLESS pending claim
/// older than the window is marked failed so the obligation may retry (the
/// provider charge either never happened or, if it did, the webhook's
/// [`observe_payment`] will have linked a payment id by now, which unblocks
/// the repair sweep instead).
pub async fn expire_stale_pending_claims(db: &PgPool) -> Result<u64, sqlx::Error> {
    let expired = sqlx::query(
        r#"
        UPDATE payment_attempts
        SET state = 'failed', updated_at = NOW()
        WHERE provider_payment_id IS NULL
          AND state = 'pending'
          AND created_at < NOW() - INTERVAL '1 hour'
        "#,
    )
    .execute(db)
    .await?;
    Ok(expired.rows_affected())
}

/// Observe one provider payment fact (the webhook path and the repair
/// sweep both arrive here):
///
/// 1. link the fact's payment id onto any KEYLESS open claim for the same
///    obligation (the "timeout after a successful provider charge" repair:
///    the provider's own callback names the charge our lost response hid);
/// 2. upsert the attempt row by (provider, provider_payment_id) with the
///    normalized state;
/// 3. append the neutral event ledger row (idempotent on the fact id).
///
/// Never settles anything: settlement is [`verify_against_obligation`] +
/// [`settle_verified`], so observation alone can never move money.
pub async fn observe_payment(db: &PgPool, observed: &ObservedPayment) -> Result<(), String> {
    let payment_id = observed.provider_payment_id.trim();
    if payment_id.is_empty() {
        return Ok(());
    }
    let Some(tenant_id) = observed
        .tenant_id
        .as_deref()
        .map(str::trim)
        .filter(|t| !t.is_empty())
    else {
        // Unattributed facts are ledged nowhere: the webhook acknowledges
        // them without effect, the engine does the same.
        return Ok(());
    };

    // 1. Repair-link keyless open claims for this obligation.
    if let Some(obligation_ref) = observed
        .obligation_ref
        .as_deref()
        .map(str::trim)
        .filter(|r| !r.is_empty())
    {
        sqlx::query(
            r#"
            UPDATE payment_attempts
            SET provider_payment_id = $3, updated_at = NOW()
            WHERE provider = $1
              AND provider_payment_id IS NULL
              AND obligation_ref = $2
              AND state IN ('pending', 'processing')
            "#,
        )
        .bind(&observed.provider)
        .bind(obligation_ref)
        .bind(payment_id)
        .execute(db)
        .await
        .map_err(|error| format!("attempt link failed: {error}"))?;
    }

    // 2. Attempt upsert by provider payment id.
    sqlx::query(
        r#"
        INSERT INTO payment_attempts
            (tenant_id, provider, provider_payment_id, state, amount_minor, currency,
             purpose, obligation_ref)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8)
        ON CONFLICT (provider, provider_payment_id) DO UPDATE SET
            state = EXCLUDED.state,
            amount_minor = COALESCE(EXCLUDED.amount_minor, payment_attempts.amount_minor),
            currency = COALESCE(EXCLUDED.currency, payment_attempts.currency),
            obligation_ref = COALESCE(EXCLUDED.obligation_ref, payment_attempts.obligation_ref),
            updated_at = NOW()
        -- State is monotonic over the verified terminal (conformance arm 5):
        -- once a payment is SUCCEEDED, a stale out-of-order failure fact
        -- refreshes nothing. The money arrived; a late sad fact cannot
        -- un-arrive it.
        WHERE NOT (payment_attempts.state = 'succeeded'
                   AND EXCLUDED.state <> 'succeeded')
        "#,
    )
    .bind(tenant_id)
    .bind(&observed.provider)
    .bind(payment_id)
    .bind(state_str(observed.state))
    .bind(observed.amount_minor)
    .bind(observed.currency.as_deref().map(str::to_uppercase))
    .bind(observed.purpose)
    .bind(observed.obligation_ref.clone())
    .execute(db)
    .await
    .map_err(|error| format!("attempt upsert failed: {error}"))?;

    // 3. The neutral event ledger: one row per distinct provider fact.
    sqlx::query(
        r#"
        INSERT INTO payment_provider_events
            (provider, provider_event_id, event_kind, provider_payment_id, payload)
        VALUES ($1, $2, 'paymentStateChange', $3, $4)
        ON CONFLICT (provider, provider_event_id) DO NOTHING
        "#,
    )
    .bind(&observed.provider)
    .bind(format!("{payment_id}:{}", state_str(observed.state)))
    .bind(payment_id)
    .bind(serde_json::json!({
        "state": state_str(observed.state),
        "amountMinor": observed.amount_minor,
        "currency": observed.currency,
        "obligationRef": observed.obligation_ref,
        "purpose": observed.purpose,
    }))
    .execute(db)
    .await
    .map_err(|error| format!("event ledger insert failed: {error}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Verify then settle
// ---------------------------------------------------------------------------

/// A verified settlement: what the core proved and what settling writes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerifiedSettlement {
    pub invoice_id: Uuid,
    pub tenant_id: String,
    pub currency: String,
    /// The capped allocation amount (integer minor units).
    pub allocation_minor: i64,
    /// The settlement idempotency key.
    pub operation_id: String,
}

/// Why a provider fact did not settle. Every variant is a REFUSAL with the
/// evidence attached; the engine never settles on a doubt.
#[derive(Debug, thiserror::Error)]
pub enum VerifyError {
    #[error("the fact names no obligation reference")]
    NoObligation,
    #[error("obligation reference {0:?} names no local invoice")]
    ObligationNotFound(String),
    #[error("payment belongs to tenant {invoice_tenant} but the fact attributes it to {fact_tenant}, cross-tenant event refused")]
    CrossTenant {
        invoice_tenant: String,
        fact_tenant: String,
    },
    #[error(
        "invoice {invoice_id} is billed in {invoice_currency} but the charge is {fact_currency}"
    )]
    CurrencyMismatch {
        invoice_id: Uuid,
        invoice_currency: String,
        fact_currency: String,
    },
    #[error("payment state {0:?} is not a settlement")]
    NotSuccessful(PaymentState),
    #[error("verification read failed: {0}")]
    Db(String),
}

pub(crate) fn state_str(state: PaymentState) -> &'static str {
    match state {
        PaymentState::Pending => "pending",
        PaymentState::RequiresAction => "requiresAction",
        PaymentState::Processing => "processing",
        PaymentState::Succeeded => "succeeded",
        PaymentState::Failed => "failed",
        PaymentState::Canceled => "canceled",
    }
}

/// The outstanding remainder of an invoice in minor units: the invoice's
/// own total minus every allocation already recorded.
#[derive(Debug, sqlx::FromRow)]
struct ObligationRow {
    tenant_id: String,
    currency: String,
    total_minor: i64,
    allocated_minor: i64,
}

async fn load_obligation(
    db: &PgPool,
    invoice_id: Uuid,
) -> Result<Option<ObligationRow>, VerifyError> {
    sqlx::query_as::<_, ObligationRow>(
        r#"
        SELECT i.tenant_id,
               i.currency,
               COALESCE(i.total, i.amount, 0)::bigint AS total_minor,
               COALESCE((SELECT SUM(a.amount_cents) FROM invoice_payment_allocations a
                         WHERE a.invoice_id = i.id), 0)::bigint AS allocated_minor
        FROM invoices i
        WHERE i.id = $1
        "#,
    )
    .bind(invoice_id)
    .fetch_optional(db)
    .await
    .map_err(|error| VerifyError::Db(error.to_string()))
}

/// Verify a provider fact against the LOCAL obligation: the reference must
/// name our invoice, the fact's tenant must agree with the invoice's
/// tenant when known, the currency must match, the state must be
/// [`PaymentState::Succeeded`], and the allocation is capped against the
/// remaining obligation. Nothing here talks to the provider: the fact is
/// already the AUTHENTICATED provider truth the caller fetched.
pub async fn verify_against_obligation(
    db: &PgPool,
    observed: &ObservedPayment,
) -> Result<VerifiedSettlement, VerifyError> {
    let Some(obligation_ref) = observed.obligation_ref.as_deref() else {
        return Err(VerifyError::NoObligation);
    };
    let Some(invoice_id) = obligation_invoice_id(obligation_ref) else {
        return Err(VerifyError::ObligationNotFound(obligation_ref.to_string()));
    };
    if observed.state != PaymentState::Succeeded {
        return Err(VerifyError::NotSuccessful(observed.state));
    }
    let Some(row) = load_obligation(db, invoice_id).await? else {
        return Err(VerifyError::ObligationNotFound(obligation_ref.to_string()));
    };
    if let Some(fact_tenant) = observed.tenant_id.as_deref() {
        if !fact_tenant.trim().is_empty() && fact_tenant.trim() != row.tenant_id {
            return Err(VerifyError::CrossTenant {
                invoice_tenant: row.tenant_id,
                fact_tenant: fact_tenant.trim().to_string(),
            });
        }
    }
    let Some(fact_currency) = observed
        .currency
        .as_deref()
        .map(str::trim)
        .filter(|c| !c.is_empty())
    else {
        return Err(VerifyError::CurrencyMismatch {
            invoice_id,
            invoice_currency: row.currency.clone(),
            fact_currency: "(absent)".to_string(),
        });
    };
    if !currencies_match(fact_currency, &row.currency) {
        return Err(VerifyError::CurrencyMismatch {
            invoice_id,
            invoice_currency: row.currency,
            fact_currency: fact_currency.to_string(),
        });
    }
    let Some(charged) = observed.amount_minor else {
        return Err(VerifyError::NotSuccessful(observed.state));
    };
    let outstanding = row.total_minor - row.allocated_minor;
    Ok(VerifiedSettlement {
        invoice_id,
        tenant_id: row.tenant_id,
        currency: row.currency.to_ascii_uppercase(),
        allocation_minor: allocation_minor(charged, outstanding),
        operation_id: operation_id(&observed.provider, &observed.provider_payment_id),
    })
}

/// Settle a VERIFIED fact exactly once: the allocation insert is idempotent
/// on the operation id, the invoice flips to paid only when the obligation
/// is fully covered, and the statutory posting runs in the same
/// transaction (idempotent on the same operation id). Returns `true` when
/// this call performed the settlement (replays return `false`).
pub async fn settle_verified(
    db: &PgPool,
    provider: &str,
    verified: &VerifiedSettlement,
) -> Result<bool, String> {
    if verified.allocation_minor <= 0 {
        // A zero allocation settles nothing (already covered or a nothing
        // charge); idempotent no-op.
        return Ok(false);
    }
    let mut tx = db
        .begin()
        .await
        .map_err(|error| format!("settle transaction failed: {error}"))?;
    let settled_now = settle_verified_in_tx(&mut tx, provider, verified).await?;
    tx.commit()
        .await
        .map_err(|error| format!("settle commit failed: {error}"))?;
    Ok(settled_now)
}

/// The in-transaction core of [`settle_verified`], for callers that already
/// hold the settlement transaction.
pub async fn settle_verified_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    provider: &str,
    verified: &VerifiedSettlement,
) -> Result<bool, String> {
    let inserted = sqlx::query(
        r#"
        INSERT INTO invoice_payment_allocations
            (id, tenant_id, invoice_id, operation_id, source, amount_cents, currency, provider)
        -- source is the GENERIC processor role (the statutory vocabulary);
        -- the provider name rides the dedicated provider dimension column.
        VALUES (gen_random_uuid(), $1, $2, $3, 'processor', $5, $6, $4)
        ON CONFLICT (operation_id) DO NOTHING
        "#,
    )
    .bind(&verified.tenant_id)
    .bind(verified.invoice_id)
    .bind(&verified.operation_id)
    .bind(provider)
    .bind(verified.allocation_minor)
    .bind(&verified.currency)
    .execute(&mut **tx)
    .await
    .map_err(|error| format!("settlement allocation failed: {error}"))?;
    let settled_now = inserted.rows_affected() > 0;
    if settled_now {
        // Paid exactly when the obligation is fully covered by allocations.
        sqlx::query(
            r#"
            UPDATE invoices
            SET status = 'paid', paid_at = COALESCE(paid_at, NOW()), updated_at = NOW()
            WHERE id = $1
              AND status IN ('draft', 'pending')
              AND COALESCE(total, amount, 0)::bigint <= (
                    SELECT COALESCE(SUM(amount_cents), 0) FROM invoice_payment_allocations
                    WHERE invoice_id = $1)
            "#,
        )
        .bind(verified.invoice_id)
        .execute(&mut **tx)
        .await
        .map_err(|error| format!("invoice paid transition failed: {error}"))?;
        // Statutory ledger, same transaction, idempotent on the operation id.
        crate::accounting_postings::post_payment_allocation_in(tx, &verified.operation_id).await;
    }
    Ok(settled_now)
}

/// Record one refund FACT on the neutral refunds ledger, idempotent on
/// (provider, refund id) and monotonic to the terminal success (a stale
/// sad fact never un-refunds a completed refund).
pub async fn record_refund_fact(db: &PgPool, refund: &super::Refund) -> Result<(), String> {
    let state = match refund.state {
        super::RefundState::Pending => "pending",
        super::RefundState::Processing => "processing",
        super::RefundState::Succeeded => "succeeded",
        super::RefundState::Failed => "failed",
    };
    sqlx::query(
        r#"
        INSERT INTO payment_provider_refunds
            (provider, provider_refund_id, provider_payment_id, state,
             amount_minor, currency)
        VALUES ($1, $2, $3, $4, $5, $6)
        ON CONFLICT (provider, provider_refund_id) DO UPDATE SET
            state = EXCLUDED.state,
            amount_minor = EXCLUDED.amount_minor,
            updated_at = NOW()
        WHERE NOT (payment_provider_refunds.state = 'succeeded'
                   AND EXCLUDED.state <> 'succeeded')
        "#,
    )
    .bind(&refund.provider)
    .bind(&refund.provider_refund_id)
    .bind(&refund.provider_payment_id)
    .bind(state)
    .bind(refund.amount_minor)
    .bind(&refund.currency)
    .execute(db)
    .await
    .map_err(|error| format!("refund fact write failed: {error}"))?;
    Ok(())
}

/// Record one payout/settlement FACT. The neutral event ledger is the row
/// today (kind `settlementCompleted` carries the settlement fields); a
/// dedicated payouts table lands with the accounting-core provider
/// switchover (debt N-12), which is when reconciliation consumes these.
pub async fn record_settlement_fact(
    db: &PgPool,
    provider: &str,
    settlement: &super::Settlement,
) -> Result<(), String> {
    sqlx::query(
        r#"
        INSERT INTO payment_provider_events
            (provider, provider_event_id, event_kind, provider_payment_id, payload)
        VALUES ($1, $2, 'settlementCompleted', NULL, $3)
        ON CONFLICT (provider, provider_event_id) DO NOTHING
        "#,
    )
    .bind(provider)
    .bind(format!("settlement:{}", settlement.provider_settlement_id))
    .bind(serde_json::json!({
        "settlementId": settlement.provider_settlement_id,
        "amountMinor": settlement.amount_minor,
        "currency": settlement.currency,
        "settledAt": settlement.settled_at,
    }))
    .execute(db)
    .await
    .map_err(|error| format!("settlement fact write failed: {error}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Repair (audit gate E): missed webhooks
// ---------------------------------------------------------------------------

/// One repair pass over the open attempts: every unresolved attempt with a
/// known provider payment id is re-fetched WITH PROVIDER AUTHENTICATION and
/// driven through the same observe -> verify -> settle core the webhook
/// uses. A missed webhook can no longer strand a paid charge.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AttemptSweepStats {
    pub examined: u64,
    pub settled: u64,
    pub closed_failed: u64,
}

pub async fn sweep_open_attempts(state: &AppState) -> Result<AttemptSweepStats, String> {
    let Ok(provider) = super::registry::from_env() else {
        return Ok(AttemptSweepStats::default());
    };
    sweep_open_attempts_with(state, provider.as_ref()).await
}

/// The repair core with the provider INJECTED: the maintenance loop runs it
/// with the registry-resolved adapter, the conformance harness runs it with
/// a scripted double. Same verify-then-settle path either way.
pub async fn sweep_open_attempts_with(
    state: &AppState,
    provider: &dyn PaymentProvider,
) -> Result<AttemptSweepStats, String> {
    // Stale keyless claims can never be fetched: expire them first so the
    // obligations they block may retry.
    let _ = expire_stale_pending_claims(&state.db).await;
    let provider_name = provider.provider_name();
    // Two repair classes share the loop (gate E):
    // * OPEN attempts (pending/processing) whose outcome is unknown;
    // * SUCCEEDED attempts whose settlement never landed (a webhook that
    //   observed the fact and died before verify/settle). Both are driven
    //   through the same observe -> verify -> settle core.
    let open: Vec<(String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT tenant_id, provider_payment_id, obligation_ref
        FROM payment_attempts
        WHERE provider = $1
          AND provider_payment_id IS NOT NULL
          AND provider_payment_id <> ''
          AND updated_at < NOW() - INTERVAL '2 minutes'
          AND (
                state IN ('pending', 'processing')
                OR (
                    state = 'succeeded'
                    AND obligation_ref IS NOT NULL
                    AND NOT EXISTS (
                        SELECT 1 FROM invoice_payment_allocations a
                        WHERE a.operation_id = $1 || ':' || payment_attempts.provider_payment_id
                    )
                )
          )
        ORDER BY updated_at
        LIMIT 100
        "#,
    )
    .bind(provider_name)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("repair sweep load failed: {error}"))?;

    let mut stats = AttemptSweepStats {
        examined: open.len() as u64,
        ..AttemptSweepStats::default()
    };
    for (tenant_id, payment_id, obligation_ref) in open {
        let payment = match provider.fetch_payment_object(&payment_id).await {
            Ok(payment) => payment,
            Err(super::ProviderError::Refused { status: 404, .. })
            | Err(super::ProviderError::NotFound { .. }) => {
                // The provider never knew this payment: the attempt closes
                // failed, the obligation may retry.
                close_attempt(&state.db, provider_name, &payment_id, "failed").await?;
                stats.closed_failed += 1;
                continue;
            }
            Err(error) => {
                tracing::warn!(
                    payment_id = %payment_id,
                    error = %error,
                    "repair fetch failed; attempt left open for the next pass"
                );
                continue;
            }
        };
        let observed = ObservedPayment {
            provider: provider_name.to_string(),
            provider_payment_id: payment.provider_payment_id.clone(),
            state: payment.state,
            amount_minor: Some(payment.amount_minor),
            currency: Some(payment.currency.clone()),
            tenant_id: Some(tenant_id.clone()),
            obligation_ref: obligation_ref.clone(),
            purpose: "repair",
        };
        // The same observation core the webhook uses.
        observe_payment(&state.db, &observed).await?;
        match verify_against_obligation(&state.db, &observed).await {
            Ok(verified) => {
                if settle_verified(&state.db, provider_name, &verified).await? {
                    stats.settled += 1;
                }
            }
            Err(VerifyError::NotSuccessful(PaymentState::Failed))
            | Err(VerifyError::NotSuccessful(PaymentState::Canceled)) => {
                close_attempt(
                    &state.db,
                    provider_name,
                    &payment_id,
                    state_str(payment.state),
                )
                .await?;
                if payment.state == PaymentState::Failed {
                    stats.closed_failed += 1;
                }
            }
            Err(VerifyError::ObligationNotFound(_)) | Err(VerifyError::NoObligation) => {
                // Not an obligation payment (e.g. a checkout): the attempt
                // state was still refreshed by observe; nothing to settle.
            }
            Err(error) => {
                tracing::warn!(
                    payment_id = %payment_id,
                    error = %error,
                    "repair verification refused; attempt state refreshed, no settlement"
                );
            }
        }
    }
    Ok(stats)
}

async fn close_attempt(
    db: &PgPool,
    provider: &str,
    provider_payment_id: &str,
    state: &str,
) -> Result<(), String> {
    sqlx::query(
        "UPDATE payment_attempts SET state = $3, updated_at = NOW() \
         WHERE provider = $1 AND provider_payment_id = $2",
    )
    .bind(provider)
    .bind(provider_payment_id)
    .bind(state)
    .execute(db)
    .await
    .map_err(|error| format!("attempt close failed: {error}"))?;
    Ok(())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn operation_ids_are_provider_scoped_and_stable() {
        assert_eq!(operation_id("mollie", "tr_cov_1"), "mollie:tr_cov_1");
        assert_eq!(operation_id("mollie", " tr_cov_2 "), "mollie:tr_cov_2");
        // Distinct providers can never collide on one operation id.
        assert_ne!(operation_id("mollie", "x"), operation_id("adyen", "x"));
    }

    #[test]
    fn currency_comparison_is_case_insensitive_and_trimmed() {
        assert!(currencies_match("eur", "EUR"));
        assert!(currencies_match(" EUR ", "eur"));
        assert!(!currencies_match("", "eur"));
        assert!(!currencies_match("usd", "eur"));
    }

    #[test]
    fn allocation_is_capped_against_the_obligation_and_never_negative() {
        assert_eq!(allocation_minor(500, 1_130), 500);
        assert_eq!(allocation_minor(2_000, 1_130), 1_130);
        assert_eq!(allocation_minor(-5, 100), 0);
        assert_eq!(allocation_minor(0, 100), 0);
    }

    #[test]
    fn obligation_references_parse_invoice_ids_only() {
        let id = Uuid::new_v4();
        assert_eq!(obligation_invoice_id(&format!("invoice:{id}")), Some(id));
        assert_eq!(obligation_invoice_id(&id.to_string()), Some(id));
        assert_eq!(obligation_invoice_id("checkout:pro:monthly"), None);
        assert_eq!(obligation_invoice_id("garbage"), None);
    }

    #[test]
    fn state_strings_are_the_camel_case_state_machine() {
        assert_eq!(state_str(PaymentState::Pending), "pending");
        assert_eq!(state_str(PaymentState::RequiresAction), "requiresAction");
        assert_eq!(state_str(PaymentState::Processing), "processing");
        assert_eq!(state_str(PaymentState::Succeeded), "succeeded");
        assert_eq!(state_str(PaymentState::Failed), "failed");
        assert_eq!(state_str(PaymentState::Canceled), "canceled");
    }
}
