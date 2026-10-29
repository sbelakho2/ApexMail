//! The generic payment engine: claim, verify, settle, repair (external
//! audit, mandated steps 7 and 8; attempt semantics and strict
//! exact-amount settlement from the eighth pass).
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
//!   * **The two-retry distinction (immutable attempts):** a TRANSPORT
//!     retry of the same attempt (provider call uncertain, response lost)
//!     reuses the SAME idempotency key and therefore the SAME row while it
//!     is open; a BUSINESS/dunning retry (the previous attempt reached a
//!     definitive failure) NEVER mutates that closed row — closed attempts
//!     are immutable — the caller opens attempt N+1 with a fresh key
//!     `payment:{obligation_ref}:{attempt_no}` ([`dunning_key`],
//!     [`claim_next_attempt`]). Each attempt row keeps its own financial
//!     history: attempt_no, key and outcome are never rewritten.
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
//!   LOCAL invoice. The amount check is EXACT for ordinary obligations:
//!   a charge that is not exactly the outstanding amount is a
//!   `VerifyError::AmountMismatch` reconciliation incident — no
//!   entitlement, no paid transition, no allocation, no silent min()
//!   capping. (The capped allocation exists only behind an obligation's
//!   explicit `allow_partial` flag; nothing sets it today.) The
//!   allocation is idempotent on the operation id, so a replayed webhook
//!   or a repair sweep settles exactly once.
//! * **Repair** ([`sweep_open_attempts`], audit gate E): attempts still
//!   open are driven through the same verify-then-settle core the webhook
//!   uses — those with a payment id by an AUTHENTICATED provider fetch,
//!   stale KEYLESS claims by an authenticated provider-side search
//!   ([`PaymentProvider::search_payment_by_idempotency_key`]) that either
//!   repairs the charge or, when absence cannot be proven, parks the
//!   attempt in the `unresolved` state for human reconciliation. A missed
//!   webhook can no longer strand a paid charge, and a lost response can
//!   never be blindly retried.
//!
//! Money is integer minor units end to end; no float participates.

use sqlx::PgPool;
use uuid::Uuid;

use crate::AppState;

use super::{PaymentProvider, PaymentState};

/// The states that mean "a charge may be moving money right now". A new
/// claim for an operation in one of these states is refused (the gates).
pub const OPEN_ATTEMPT_STATES_SQL: &str = "('pending','processing')";

/// The attempt state for a stale claim whose provider-side search could
/// not prove the charge absent (lost webhooks, truncated listings): the
/// money MAY exist, so the attempt is never closed failed and never
/// auto-retried — it waits for human reconciliation. Alerting: a row in
/// this state is a reconciliation incident; page the billing on-call.
pub const UNRESOLVED_ATTEMPT_STATE: &str = "unresolved";

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

/// The amount actually recorded as an allocation when an obligation opts
/// into partial allocation (`invoices.allow_partial = true`): the verified
/// charge, capped against the authoritative remaining obligation, never
/// negative.
///
/// For the DEFAULT strict world this function is NOT consulted:
/// `verify_against_obligation` requires the charge to equal the
/// outstanding obligation exactly and refuses any mismatch with
/// [`VerifyError::AmountMismatch`] (an over- or under-charge is a
/// reconciliation incident for a human, never a silent cap).
pub fn allocation_minor(charged_minor: i64, outstanding_minor: i64) -> i64 {
    charged_minor.min(outstanding_minor).max(0)
}

/// The dunning-retry idempotency key scheme shared by every caller:
/// `payment:{obligation_ref}:{attempt_no}`. A business retry of a
/// definitively failed attempt claims attempt N+1 under THIS key, so each
/// attempt owns an immutable row and a distinct provider-side replay
/// identity; a transport retry of the SAME attempt reuses the SAME key
/// instead (see [`claim_attempt`]).
pub fn dunning_key(obligation_ref: &str, attempt_no: i64) -> String {
    format!("payment:{}:{}", obligation_ref.trim(), attempt_no)
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
/// attempt row under the UNIQUE (provider, idempotency_key) index, or
/// refuses. `Ok(false)` means the operation already has an attempt row —
/// an open attempt in flight, a `unresolved` row awaiting human
/// reconciliation, or a charge that already succeeded — so NO second
/// charge may be opened under this key.
///
/// # The two-retry distinction (attempts are IMMUTABLE)
///
/// * **Transport retry** (the provider call is uncertain: timeout, lost
///   response): the caller retries with the SAME `idempotency_key`. The
///   INSERT conflicts and the open row stays exactly as it is — the
///   caller must treat `Ok(false)` as "do not charge again; the webhook
///   or the repair sweep settles the in-flight attempt".
/// * **Business/dunning retry** (the previous attempt reached a
///   definitive `failed`/`canceled`): the caller does NOT reuse the key
///   — closed attempts are immutable and are never reopened, so a retry
///   cannot mutate attempt 1's financial history. The caller opens the
///   NEXT attempt with [`claim_next_attempt`], which inserts a NEW row
///   (`attempt_no = max+1` per `(provider, obligation_ref)`) under the
///   fresh key [`dunning_key`] produces.
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
             purpose, obligation_ref, idempotency_key, attempt_no)
        VALUES ($1, $2, NULL, 'pending', $3, $4, $5, $6, $7,
                COALESCE((SELECT MAX(attempt_no) FROM payment_attempts prior
                          WHERE prior.provider = $2
                            AND prior.obligation_ref IS NOT DISTINCT FROM $6), 0) + 1)
        ON CONFLICT (provider, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
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

/// Open the NEXT dunning attempt for an obligation: a NEW immutable
/// `pending` row with `attempt_no = max(attempt_no) + 1` for
/// `(provider, obligation_ref)`, claimed under the shared
/// [`dunning_key`] scheme. This is the ONLY legitimate way to retry after
/// a definitive failure; mutating a closed attempt row is impossible by
/// construction.
///
/// Returns `Ok(Some((attempt_no, key)))` when the new attempt row was
/// inserted, `Ok(None)` when the retry is REFUSED: the obligation already
/// has an attempt that is open (`pending`/`processing`), parked on the
/// customer (`requiresAction`), parked for human reconciliation
/// (`unresolved`), or already `succeeded` — any of which means a second
/// concurrent charge could double-bill, so none may be opened. Two
/// concurrent callers racing for the same attempt_no collide on the
/// unique key and exactly one wins.
pub async fn claim_next_attempt(
    db: &PgPool,
    provider: &str,
    tenant_id: &str,
    obligation_ref: &str,
    purpose: &str,
    amount_minor: i64,
    currency: &str,
) -> Result<Option<(i64, String)>, sqlx::Error> {
    let max: i64 = sqlx::query_scalar(
        r#"
        SELECT COALESCE(MAX(attempt_no), 0)::bigint FROM payment_attempts
        WHERE provider = $1 AND obligation_ref IS NOT DISTINCT FROM $2
        "#,
    )
    .bind(provider)
    .bind(obligation_ref)
    .fetch_one(db)
    .await?;
    let attempt_no = max + 1;
    let key = dunning_key(obligation_ref, attempt_no);
    let claimed = sqlx::query(
        r#"
        INSERT INTO payment_attempts
            (tenant_id, provider, provider_payment_id, state, amount_minor, currency,
             purpose, obligation_ref, idempotency_key, attempt_no)
        SELECT $1, $2, NULL, 'pending', $3, $4, $5, $6, $7, $8
        WHERE NOT EXISTS (
            -- The dunning gate: some attempt for this obligation is not a
            -- definitive terminal failure, so a second charge could
            -- double-bill (or fight a charge awaiting human
            -- reconciliation). `unresolved` is deliberately included: an
            -- unresolved attempt is NEVER auto-retried.
            SELECT 1 FROM payment_attempts open_row
            WHERE open_row.provider = $2
              AND open_row.obligation_ref IS NOT DISTINCT FROM $6
              AND open_row.state NOT IN ('failed', 'canceled')
        )
        ON CONFLICT (provider, idempotency_key) WHERE idempotency_key IS NOT NULL DO NOTHING
        "#,
    )
    .bind(tenant_id)
    .bind(provider)
    .bind(amount_minor)
    .bind(currency.trim().to_ascii_uppercase())
    .bind(purpose)
    .bind(obligation_ref)
    .bind(&key)
    .bind(attempt_no)
    .execute(db)
    .await?;
    if claimed.rows_affected() > 0 {
        Ok(Some((attempt_no, key)))
    } else {
        Ok(None)
    }
}

/// Record the outcome of a claimed charge: the provider payment id and the
/// normalized state land on the claim. Idempotent (a replay updates the
/// same row while it is still a keyless pending claim); a terminal state
/// CLOSES the row permanently — closed attempts are immutable, so a retry
/// after a definitive failure opens attempt N+1 via [`claim_next_attempt`],
/// never this row.
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
/// NULL, so it can never collide with another keyless claim. The row is
/// then CLOSED and immutable: the caller's retry ladder opens attempt N+1
/// with [`claim_next_attempt`].
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

/// Reconcile ONE stale keyless pending claim (past the window) by asking
/// the PROVIDER what became of the operation — an AUTHENTICATED search by
/// the claim's own idempotency key, never an assumption. The old blind
/// expiry (mark failed after one hour) is gone: webhooks can be lost or
/// delayed, and a provider that cannot prove the charge absent may still
/// be holding the customer's money.
///
/// * `Ok(Some(Succeeded))` — the money moved: link the payment id and run
///   the observe -> verify -> settle core (the repair).
/// * `Ok(Some(other))` — the charge exists: link the payment id so the
///   authenticated-fetch sweep class owns it from here on.
/// * `Ok(Some(Failed/Canceled))` — the provider definitively refused:
///   close the attempt failed (the dunning ladder may then open attempt
///   N+1).
/// * `Ok(None)` — the provider PROVABLY does not know the charge: close
///   failed (safe: no money moved; a dunning retry opens a NEW row).
/// * `Err(_)` — absence could not be proven (truncated listing, search
///   unavailable): park the attempt in [`UNRESOLVED_ATTEMPT_STATE`]. It is
///   NEVER auto-retried and NEVER closed; it requires manual
///   reconciliation (a reconciliation incident is logged).
async fn reconcile_stale_claim(
    db: &PgPool,
    provider: &dyn PaymentProvider,
    tenant_id: &str,
    idempotency_key: &str,
    obligation_ref: Option<String>,
    stats: &mut AttemptSweepStats,
) -> Result<(), String> {
    let provider_name = provider.provider_name();
    match provider
        .search_payment_by_idempotency_key(idempotency_key)
        .await
    {
        Ok(Some(payment)) => {
            // The provider knows the charge: link THIS claim (by its own
            // key — the obligation-wide link in observe_payment covers the
            // rest), then run the same observe -> verify -> settle core
            // the webhook uses.
            sqlx::query(
                r#"
                UPDATE payment_attempts
                SET provider_payment_id = $3, updated_at = NOW()
                WHERE provider = $1
                  AND idempotency_key = $2
                  AND provider_payment_id IS NULL
                  AND state = 'pending'
                  -- ONE attempt row per provider payment object (the
                  -- unique key): when another claim already recorded this
                  -- payment, this link is a NO-OP, never a violation.
                  AND NOT EXISTS (
                      SELECT 1 FROM payment_attempts other
                      WHERE other.provider = payment_attempts.provider
                        AND other.provider_payment_id = $3
                  )
                "#,
            )
            .bind(provider_name)
            .bind(idempotency_key)
            .bind(payment.provider_payment_id.trim())
            .execute(db)
            .await
            .map_err(|error| format!("stale-claim link failed: {error}"))?;
            let observed = ObservedPayment {
                provider: provider_name.to_string(),
                provider_payment_id: payment.provider_payment_id.clone(),
                state: payment.state,
                amount_minor: Some(payment.amount_minor),
                currency: Some(payment.currency.clone()),
                tenant_id: Some(tenant_id.to_string()),
                obligation_ref: obligation_ref.clone(),
                purpose: "repair",
            };
            observe_payment(db, &observed).await?;
            match payment.state {
                PaymentState::Succeeded => match verify_against_obligation(db, &observed).await {
                    Ok(verified) => {
                        if settle_verified(db, provider_name, &verified).await? {
                            stats.settled += 1;
                        }
                    }
                    Err(error) => {
                        // A verified-but-refused fact (wrong tenant/currency/
                        // amount) keeps the linked attempt open for human
                        // reconciliation — the sweep's generic refusal path
                        // below logs the incident for the fetch class; log it
                        // here too so the search class is covered.
                        tracing::warn!(
                            provider = %provider_name,
                            idempotency_key = %idempotency_key,
                            provider_payment_id = %payment.provider_payment_id,
                            error = %error,
                            "stale-claim search repaired the link but verification refused; \
                             the attempt stays open for reconciliation, no settlement"
                        );
                    }
                },
                PaymentState::Failed | PaymentState::Canceled => {
                    close_claim(db, provider_name, idempotency_key, state_str(payment.state))
                        .await?;
                    stats.closed_failed += 1;
                }
                // Pending/processing/requiresAction: the charge is moving at
                // the provider; the link is recorded, the fetch class of the
                // sweep takes it from here.
                _ => {}
            }
            Ok(())
        }
        Ok(None) => {
            // The provider provably does not know this charge: no money
            // moved, the attempt closes failed and the dunning ladder may
            // open attempt N+1.
            close_claim(db, provider_name, idempotency_key, "failed").await?;
            stats.closed_failed += 1;
            Ok(())
        }
        Err(error) => {
            // Absence unprovable: the money MAY exist. Never close it as
            // failed, never retry it blind — human reconciliation.
            sqlx::query(
                r#"
                UPDATE payment_attempts
                SET state = $3, updated_at = NOW()
                WHERE provider = $1
                  AND idempotency_key = $2
                  AND provider_payment_id IS NULL
                  AND state = 'pending'
                "#,
            )
            .bind(provider_name)
            .bind(idempotency_key)
            .bind(UNRESOLVED_ATTEMPT_STATE)
            .execute(db)
            .await
            .map_err(|error| format!("unresolved park failed: {error}"))?;
            stats.unresolved += 1;
            tracing::warn!(
                provider = %provider_name,
                idempotency_key = %idempotency_key,
                obligation_ref = ?obligation_ref,
                error = %error,
                "RECONCILIATION INCIDENT: a stale payment claim could not be proven absent at \
                 the provider; the attempt is parked `unresolved` and requires manual \
                 reconciliation — it is never auto-retried"
            );
            Ok(())
        }
    }
}

/// Close a KEYLESS claim by its idempotency key (the search-reconcile
/// path's terminal writer; the row keeps `provider_payment_id` NULL).
async fn close_claim(
    db: &PgPool,
    provider: &str,
    idempotency_key: &str,
    state: &str,
) -> Result<(), String> {
    sqlx::query(
        r#"
        UPDATE payment_attempts
        SET state = $3, updated_at = NOW()
        WHERE provider = $1
          AND idempotency_key = $2
          AND provider_payment_id IS NULL
          AND state IN ('pending', 'processing')
        "#,
    )
    .bind(provider)
    .bind(idempotency_key)
    .bind(state)
    .execute(db)
    .await
    .map_err(|error| format!("claim close failed: {error}"))?;
    Ok(())
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
    /// The allocation amount (integer minor units): exactly the charge in
    /// the strict world (the amount gate refuses anything else); the
    /// capped allocation only behind an obligation's `allow_partial` flag.
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
    /// The charge's amount is not exactly the obligation's expected amount
    /// (over- AND under-charges refuse). The attempt is left open for
    /// HUMAN reconciliation — the money may exist, so it is never closed
    /// failed and never retried blind. ALERTING: every
    /// [`VerifyError::AmountMismatch`] is a reconciliation incident; the
    /// caller must log it as such and page the billing on-call.
    #[error(
        "RECONCILIATION INCIDENT: payment {payment_id} charged {actual_minor} but the \
         obligation expects exactly {expected_minor} (strict exact-amount gate); no \
         entitlement, no settlement — the attempt stays open for manual reconciliation"
    )]
    AmountMismatch {
        payment_id: String,
        expected_minor: i64,
        actual_minor: i64,
    },
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
    /// The obligation-level escape from the strict exact-amount gate
    /// (migration 282). Default `false`: the strict world. Nothing in the
    /// codebase sets it `true`.
    allow_partial: bool,
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
                         WHERE a.invoice_id = i.id), 0)::bigint AS allocated_minor,
               i.allow_partial
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
/// [`PaymentState::Succeeded`], and — for ordinary obligations
/// (`invoices.allow_partial = false`, the default) — the charge must be
/// EXACTLY the obligation's expected amount. An over-charge AND an
/// under-charge are [`VerifyError::AmountMismatch`]: no entitlement, no
/// paid transition, no allocation, and the caller (webhook observe path +
/// repair sweep) must log a reconciliation-incident warn and leave the
/// attempt open — the money may exist and must be human-reconciled, never
/// silently capped and never closed as failed. Nothing here talks to the
/// provider: the fact is already the AUTHENTICATED provider truth the
/// caller fetched.
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
    let outstanding = (row.total_minor - row.allocated_minor).max(0);
    let allocation = if row.allow_partial {
        // The obligation's EXPLICIT escape hatch (migration 282): the
        // legacy capped allocation. Nothing in the codebase opts in.
        allocation_minor(charged, outstanding)
    } else {
        // STRICT (the default world): the charge must equal the
        // obligation's expected amount EXACTLY. A replay of the same
        // settled fact passes this equality (the amount is still the
        // invoice total) and idempotently settles nothing below.
        if charged != row.total_minor {
            return Err(VerifyError::AmountMismatch {
                payment_id: observed.provider_payment_id.trim().to_string(),
                expected_minor: row.total_minor,
                actual_minor: charged,
            });
        }
        // Never allocate beyond the outstanding remainder (the ledger must
        // not exceed the obligation even on a pathological already-partial
        // history); the equality check above is the gate, this is the
        // floor.
        charged.min(outstanding).max(0)
    };
    Ok(VerifiedSettlement {
        invoice_id,
        tenant_id: row.tenant_id,
        currency: row.currency.to_ascii_uppercase(),
        allocation_minor: allocation,
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
// Disputes (chargebacks): the generic reconciliation path
// ---------------------------------------------------------------------------

/// The DB state string for a neutral dispute state (`payment_disputes.state`).
fn dispute_state_str(state: super::DisputeState) -> &'static str {
    match state {
        super::DisputeState::Opened => "opened",
        super::DisputeState::Lost => "lost",
        super::DisputeState::Won => "won",
    }
}

/// The neutral ledger fact kind for one dispute state.
fn dispute_event_kind(state: super::DisputeState) -> &'static str {
    match state {
        super::DisputeState::Opened => "disputeOpened",
        super::DisputeState::Lost => "disputeLost",
        super::DisputeState::Won => "disputeWon",
    }
}

/// Proportional VAT split over the invoice's own total/VAT ratio (the same
/// rounding shape the statutory refund writer uses: round-half-to-even on
/// the ratio, remainder to net). Disputes without a resolvable local
/// invoice carry no VAT split (net only, never a guessed rate).
fn split_vat_proportional(amount_minor: i64, invoice_total: i64, invoice_vat: i64) -> (i64, i64) {
    if amount_minor <= 0 {
        return (0, 0);
    }
    if invoice_total <= 0 || invoice_vat <= 0 {
        return (amount_minor, 0);
    }
    let vat = ((i128::from(amount_minor) * i128::from(invoice_vat) + i128::from(invoice_total) / 2)
        / i128::from(invoice_total)) as i64;
    let vat = vat.clamp(0, amount_minor);
    (amount_minor - vat, vat)
}

/// Observe one dispute fact (the generic dispute reconciliation path):
///
/// 1. upsert `payment_disputes` keyed by (provider, provider_dispute_id),
///    tenant-attributed from the attempts ledger when the payment maps to
///    one;
/// 2. append the neutral event ledger fact (`disputeOpened` /
///    `disputeLost` / `disputeWon`), mirroring the settlement-fact writer's
///    shape, idempotent on the fact id;
/// 3. LOST — the money is taken back: post the accounting debit the refund
///    writer uses (Dr refunds / Dr output VAT / Cr processor clearing),
///    idempotent on `dispute:{provider}:{id}:lost`;
///    WON/REVERSED — the money stays or returns: post the restoration
///    entry (the debit's mirror), idempotent on
///    `dispute:{provider}:{id}:won`.
///
/// Idempotent end to end: a replayed dispute fact upserts the same row,
/// records no second ledger fact and posts no second journal entry.
pub async fn observe_dispute(
    db: &PgPool,
    provider: &str,
    dispute: &super::Dispute,
) -> Result<(), String> {
    let dispute_id = dispute.provider_dispute_id.trim();
    if dispute_id.is_empty() {
        return Ok(());
    }
    let payment_id = dispute.provider_payment_id.trim();

    // Tenant attribution: the dispute's payment may map to an attempt row.
    let tenant_id: Option<String> = sqlx::query_scalar(
        "SELECT tenant_id FROM payment_attempts \
         WHERE provider = $1 AND provider_payment_id = $2 LIMIT 1",
    )
    .bind(provider)
    .bind(payment_id)
    .fetch_optional(db)
    .await
    .map_err(|error| format!("dispute tenant lookup failed: {error}"))?;

    // 1. The dispute row (upsert, monotonic to a resolved terminal).
    let state = dispute_state_str(dispute.state);
    let resolved_now = matches!(
        dispute.state,
        super::DisputeState::Lost | super::DisputeState::Won
    );
    sqlx::query(
        r#"
        INSERT INTO payment_disputes
            (tenant_id, provider, provider_dispute_id, provider_payment_id, state,
             reason, amount_minor, currency, opened_at, resolved_at)
        VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9,
                CASE WHEN $5 IN ('lost', 'won') THEN NOW() END)
        ON CONFLICT (provider, provider_dispute_id) DO UPDATE SET
            state = EXCLUDED.state,
            reason = COALESCE(EXCLUDED.reason, payment_disputes.reason),
            amount_minor = EXCLUDED.amount_minor,
            resolved_at = COALESCE(payment_disputes.resolved_at, EXCLUDED.resolved_at)
        "#,
    )
    .bind(&tenant_id)
    .bind(provider)
    .bind(dispute_id)
    .bind(payment_id)
    .bind(state)
    .bind(&dispute.reason)
    .bind(dispute.amount_minor)
    .bind(dispute.currency.trim().to_ascii_uppercase())
    .bind(dispute.opened_at)
    .execute(db)
    .await
    .map_err(|error| format!("dispute upsert failed: {error}"))?;

    // 2. The neutral event ledger: one row per distinct dispute fact.
    sqlx::query(
        r#"
        INSERT INTO payment_provider_events
            (provider, provider_event_id, event_kind, provider_payment_id, payload)
        VALUES ($1, $2, $3, $4, $5)
        ON CONFLICT (provider, provider_event_id) DO NOTHING
        "#,
    )
    .bind(provider)
    .bind(format!(
        "dispute:{dispute_id}:{}",
        dispute_event_kind(dispute.state)
    ))
    .bind(dispute_event_kind(dispute.state))
    .bind(payment_id)
    .bind(serde_json::json!({
        "disputeId": dispute_id,
        "state": state,
        "amountMinor": dispute.amount_minor,
        "currency": dispute.currency,
        "reason": dispute.reason,
        "openedAt": dispute.opened_at,
        "resolvedNow": resolved_now,
    }))
    .execute(db)
    .await
    .map_err(|error| format!("dispute event write failed: {error}"))?;

    // 3. The statutory entries (best-effort like every accounting hook:
    // the dispute fact above is committed; an unconfigured ledger logs and
    // replays, it never loses the fact).
    post_dispute_accounting(db, provider, dispute).await;
    Ok(())
}

/// Post the dispute's statutory entry. LOST mirrors the refund writer's
/// debit (Dr refunds contra-revenue, Dr output VAT, Cr processor clearing
/// — the provider pulls the money from the clearing balance); WON posts
/// the restoration (the debit's mirror). Idempotent per dispute outcome;
/// the entry carries no source document because the source-document
/// allowlist has no dispute type yet (NEUTRALITY-DEBT, N-13).
async fn post_dispute_accounting(db: &PgPool, provider: &str, dispute: &super::Dispute) {
    if dispute.amount_minor <= 0 || dispute.state == super::DisputeState::Opened {
        return; // nothing to debit or restore; an opened dispute moves no money
    }
    match post_dispute_accounting_in(db, provider, dispute).await {
        Ok(Some(outcome)) => {
            tracing::debug!(
                provider = %provider,
                dispute_id = %dispute.provider_dispute_id,
                status = ?outcome.status,
                entry_id = ?outcome.entry_id,
                "dispute accounting posting completed"
            );
        }
        Ok(None) => {}
        Err(error) => {
            metrics::counter!("accounting_postings_skipped_total").increment(1);
            tracing::error!(
                provider = %provider,
                dispute_id = %dispute.provider_dispute_id,
                error = %error,
                "dispute accounting posting failed, the dispute fact is committed; replay it \
                 once the ledger is configured (the posting is idempotent on the dispute id)"
            );
        }
    }
}

/// The in-transaction dispute posting; `Ok(None)` means nothing was posted
/// (a replayed outcome whose entry already exists lands as `AlreadyPosted`
/// and is returned as `Some`).
async fn post_dispute_accounting_in(
    db: &PgPool,
    provider: &str,
    dispute: &super::Dispute,
) -> Result<Option<accounting_core::types::PostOutcome>, accounting_core::AccountingError> {
    use accounting_core::types::{
        EntryType, JournalLine, PostJournalRequest, ROLE_PAYMENT_CLEARING, ROLE_REFUNDS,
        ROLE_VAT_OUTPUT,
    };

    let outcome_state = dispute_state_str(dispute.state);
    let idempotency_key = format!("dispute:{}:{}", dispute.provider_dispute_id, outcome_state);
    let mut tx = db
        .begin()
        .await
        .map_err(accounting_core::AccountingError::Db)?;
    let legal_entity_id = accounting_core::provisioning::ensure_default_entity_in(&mut tx).await?;
    let document_date = dispute
        .opened_at
        .map(|time| time.date_naive())
        .unwrap_or_else(|| chrono::Utc::now().date_naive());
    let fiscal_period_id = accounting_core::provisioning::ensure_open_period_in(
        &mut tx,
        legal_entity_id,
        document_date,
    )
    .await?;
    let currency = dispute.currency.trim().to_ascii_uppercase();

    // The invoice's VAT ratio when the disputed payment maps to a local
    // obligation; without one the entry is net-only (no guessed rate). The
    // regex guard keeps the uuid cast total (a malformed reference resolves
    // no split, it never errors the posting).
    let invoice_split: Option<(i64, i64)> = sqlx::query_as(
        r#"
        SELECT COALESCE(i.total, i.amount, 0)::bigint, COALESCE(i.vat_total, 0)::bigint
        FROM payment_attempts pa
        JOIN invoices i ON i.id = CAST(SUBSTRING(pa.obligation_ref FROM 9) AS uuid)
        WHERE pa.provider = $1
          AND pa.provider_payment_id = $2
          AND pa.obligation_ref ~ '^invoice:[0-9a-fA-F-]{36}$'
        LIMIT 1
        "#,
    )
    .bind(provider)
    .bind(dispute.provider_payment_id.trim())
    .fetch_optional(&mut *tx)
    .await
    .map_err(accounting_core::AccountingError::Db)?;
    let (net, vat) = match invoice_split {
        Some((total, vat_total)) => split_vat_proportional(dispute.amount_minor, total, vat_total),
        None => (dispute.amount_minor, 0),
    };

    // The processor clearing account: the provider-dimension row first
    // (the generic settlement shape), the chart's generic clearing role as
    // the fallback.
    let clearing: Option<Uuid> = sqlx::query_scalar(
        "SELECT clearing_account_id FROM processor_clearing_accounts \
         WHERE legal_entity_id = $1 AND provider = $2 AND currency = $3 \
           AND is_active LIMIT 1",
    )
    .bind(legal_entity_id)
    .bind(provider)
    .bind(&currency)
    .fetch_optional(&mut *tx)
    .await
    .map_err(accounting_core::AccountingError::Db)?;
    let clearing = match clearing {
        Some(account) => account,
        None => {
            accounting_core::chart::resolve_account_role(
                &mut tx,
                legal_entity_id,
                ROLE_PAYMENT_CLEARING,
            )
            .await?
        }
    };
    let refunds =
        accounting_core::chart::resolve_account_role(&mut tx, legal_entity_id, ROLE_REFUNDS)
            .await?;
    let vat_account = accounting_core::chart::resolve_tax_account(
        &mut tx,
        legal_entity_id,
        "vat_output",
        ROLE_VAT_OUTPUT,
        document_date,
    )
    .await?;

    // LOST = the refund writer's debit against the clearing balance.
    // WON/REVERSED = the restoration (the debit's mirror). Each is a
    // self-contained balanced entry, idempotent on its own key. The lines
    // are built per outcome (never tuple-then-filter): a zero-VAT entry
    // must drop the VAT line, not the counterpart line.
    let mut lines = Vec::with_capacity(3);
    match dispute.state {
        super::DisputeState::Lost => {
            if net > 0 {
                lines.push(
                    JournalLine::debit(refunds, net, &currency)
                        .with_description("Chargeback lost, revenue reversal"),
                );
            }
            if vat > 0 {
                lines.push(
                    JournalLine::debit(vat_account, vat, &currency)
                        .with_vat(net, vat, None, Some("OUTPUT".to_string()))
                        .with_description("Chargeback lost, output VAT reversal"),
                );
            }
            lines.push(
                JournalLine::credit(clearing, dispute.amount_minor, &currency)
                    .with_description("Chargeback lost, processor clearing"),
            );
        }
        super::DisputeState::Won => {
            lines.push(
                JournalLine::debit(clearing, dispute.amount_minor, &currency)
                    .with_description("Chargeback won, processor clearing restored"),
            );
            if net > 0 {
                lines.push(
                    JournalLine::credit(refunds, net, &currency)
                        .with_description("Chargeback won, revenue restoration"),
                );
            }
            if vat > 0 {
                lines.push(
                    JournalLine::credit(vat_account, vat, &currency)
                        .with_vat(net, vat, None, Some("OUTPUT".to_string()))
                        .with_description("Chargeback won, output VAT restoration"),
                );
            }
        }
        super::DisputeState::Opened => return Ok(None),
    }

    let request = PostJournalRequest {
        legal_entity_id,
        fiscal_period_id,
        entry_date: document_date,
        entry_type: EntryType::Standard,
        memo: format!(
            "Dispute {} ({}, {}) for payment {}",
            dispute.provider_dispute_id, outcome_state, currency, dispute.provider_payment_id
        ),
        posted_by: "engine:dispute-reconciliation".to_string(),
        idempotency_key,
        // No source document: the accounting_source_documents allowlist has
        // no dispute source_type yet (debt N-13); the evidence hash is the
        // manual-entry content hash and the idempotency key is the dispute
        // identity.
        source: None,
        reversal_of_entry_id: None,
        lines,
    };
    let outcome = accounting_core::posting::post_journal_entry_in(&mut tx, &request).await?;
    tx.commit()
        .await
        .map_err(accounting_core::AccountingError::Db)?;
    Ok(Some(outcome))
}

// ---------------------------------------------------------------------------
// Repair (audit gate E): missed webhooks
// ---------------------------------------------------------------------------

/// One repair pass over the open attempts:
///
/// * every unresolved attempt with a known provider payment id is
///   re-fetched WITH PROVIDER AUTHENTICATION and driven through the same
///   observe -> verify -> settle core the webhook uses;
/// * every stale KEYLESS pending claim (past the window) is reconciled by
///   an AUTHENTICATED provider-side search on its idempotency key —
///   repaired when the money moved, closed failed when absence is
///   provable, parked `unresolved` (never retried) when absence cannot be
///   proven. The old blind one-hour expiry is gone: a lost webhook can no
///   longer strand a paid charge and can no longer trigger a blind second
///   charge either.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct AttemptSweepStats {
    pub examined: u64,
    pub settled: u64,
    pub closed_failed: u64,
    /// Stale claims parked `unresolved` this pass (absence unprovable at
    /// the provider): each one is a reconciliation incident for a human.
    pub unresolved: u64,
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
    let provider_name = provider.provider_name();
    // Stale keyless claims (the lost-response class): ask the provider
    // what became of the charge BEFORE deciding anything. Succeeded claims
    // are repaired, provable absences close failed, unprovable ones park
    // `unresolved` for human reconciliation — nothing is blindly retried.
    let stale: Vec<(String, String, Option<String>)> = sqlx::query_as(
        r#"
        SELECT tenant_id, idempotency_key, obligation_ref
        FROM payment_attempts
        WHERE provider = $1
          AND provider_payment_id IS NULL
          AND idempotency_key IS NOT NULL
          AND state = 'pending'
          AND created_at < NOW() - INTERVAL '1 hour'
        ORDER BY created_at
        LIMIT 100
        "#,
    )
    .bind(provider_name)
    .fetch_all(&state.db)
    .await
    .map_err(|error| format!("stale claim load failed: {error}"))?;

    let mut stats = AttemptSweepStats::default();
    for (tenant_id, idempotency_key, obligation_ref) in stale {
        stats.examined += 1;
        reconcile_stale_claim(
            &state.db,
            provider,
            &tenant_id,
            &idempotency_key,
            obligation_ref,
            &mut stats,
        )
        .await?;
    }

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

    stats.examined += open.len() as u64;
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
            Err(VerifyError::AmountMismatch {
                payment_id,
                expected_minor,
                actual_minor,
            }) => {
                // The provider's authenticated fact disagrees with the
                // obligation's expected amount (over- or under-charge):
                // NEVER close it as failed (the money may exist), never
                // allocate, never cap. The attempt stays open for HUMAN
                // reconciliation.
                tracing::warn!(
                    provider = %provider_name,
                    payment_id = %payment_id,
                    expected_minor,
                    actual_minor,
                    "RECONCILIATION INCIDENT: authenticated charge amount != obligation amount; \
                     no entitlement, no settlement — the attempt stays open for manual \
                     reconciliation (alert the billing on-call)"
                );
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
        // The capped allocation is ONLY the allow_partial escape hatch (and
        // the never-exceed-outstanding floor); the strict path never calls
        // it for a mismatched charge.
        assert_eq!(allocation_minor(500, 1_130), 500);
        assert_eq!(allocation_minor(2_000, 1_130), 1_130);
        assert_eq!(allocation_minor(-5, 100), 0);
        assert_eq!(allocation_minor(0, 100), 0);
    }

    #[test]
    fn dunning_keys_follow_one_shared_scheme() {
        let id = Uuid::new_v4();
        let reference = format!("invoice:{id}");
        assert_eq!(dunning_key(&reference, 1), format!("payment:{reference}:1"));
        assert_eq!(dunning_key(&reference, 2), format!("payment:{reference}:2"));
        // The ref is trimmed; the ordinal is verbatim.
        assert_eq!(
            dunning_key(&format!(" {reference} "), 3),
            format!("payment:{reference}:3")
        );
        // A dunning key differs from any transport-retry key: attempt 2's
        // identity can never collide with attempt 1's.
        assert_ne!(dunning_key(&reference, 1), dunning_key(&reference, 2));
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
