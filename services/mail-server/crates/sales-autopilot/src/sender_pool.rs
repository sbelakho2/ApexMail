//! Sender-pool selection — the reputation-isolation invariant and the
//! per-sender daily capacity reservation.
//!
//! Sales reputation must never be able to reach the transactional/customer
//! pools (and vice versa): a complaint against sales outreach would otherwise
//! degrade delivery for customer-critical mail. This is a policy invariant
//! enforced **in code here** and **by the database**:
//!
//! * `sales_sender_identities.pool` has
//!   `CHECK (pool IN ('transactional_customer', 'internal_transactional',
//!   'sales_outbound', 'sales_warmup'))`;
//! * every selection query below additionally filters `pool` to a sales pool
//!   and `status = 'active'`;
//! * a caller that asks for a non-sales pool gets a loud
//!   [`SalesError::PolicyDenied`] — never a silent coercion, because asking a
//!   sales path for a transactional sender is a bug that must not hide.
//!
//! Release gate: **no sales action can select a transactional/customer sender
//! pool.** The unit tests at the bottom of this file assert the pure
//! predicates behind that gate.
//!
//! # Daily capacity is a reservation, not a check
//!
//! `sales_sender_identities.daily_limit` used to be decorative: selection read
//! the column and then chose `ORDER BY from_email ASC LIMIT 1`, and nothing in
//! production ever consumed the limit. Selection is now a **capacity
//! reservation** built on `sales_sender_daily_usage` (migration 206):
//!
//! 1. candidates are the identities in the requested sales pool with
//!    `status = 'active'`, no `quarantined`/`paused` health state, and
//!    `sales_sender_daily_usage.sent` for the current **UTC** day below
//!    `daily_limit`. A `NULL` `daily_limit` means **unlimited capacity**: the
//!    identity is never excluded for capacity and its utilisation ranks as
//!    `0.0`. A limit of `0` excludes the identity for the whole day;
//! 2. the remaining candidates are ranked by [`rank_sender_candidates`] — the
//!    single pure ranking rule — instead of alphabetically;
//! 3. for each candidate in rank order the atomic upsert of
//!    `sales_sender_daily_usage` is attempted. That upsert is the decision:
//!    `INSERT ... ON CONFLICT DO UPDATE SET sent = sent + 1 ... WHERE sent <
//!    daily_limit RETURNING sent` returns a row only when the reservation was
//!    granted, so two concurrent selectors can never both take the last slot
//!    and no caller can exceed the limit by pre-checking. A candidate that
//!    returns no row is full (someone else took the last slot); selection
//!    retries with the next-ranked candidate and only fails when every
//!    candidate in every permitted pool is full.
//!
//! ## Reservation lifecycle
//!
//! * **reserve** — [`reserve_sales_sender`] / [`reserve_sales_sender_with_fallback`]
//!   perform the atomic upsert before returning the identity. The returned
//!   identity is already consuming one daily slot.
//! * **settle** — when the send happens, nothing else is required: the
//!   reservation row *is* the consumption. There is deliberately no separate
//!   settle call (the table carries no state; a second writer would only add a
//!   race).
//! * **release** — when the send does not happen after selection (a refusal
//!   downstream: decision denied/shadowed/awaiting approval, dispatcher
//!   failure, lease loss), the caller must call
//!   [`release_sender_reservation`] so the slot returns to the pool. The
//!   release decrements only a positive count and is tenant-scoped.
//!
//! The sequence worker is the production caller of the resolver; its call
//! site must release on every non-send exit path (see the report accompanying
//! this change — this crate file cannot own the worker).

use chrono::{DateTime, NaiveDate, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::{SalesError, SenderIdentity, SenderPool};

/// Environment switch permitting fallback from the preferred sales pool to
/// the other sales pool when the preferred one has no active identity.
///
/// Defaults to **off** (production posture). Sandbox/development deployments
/// may set `SALES_ALLOW_SENDER_POOL_FALLBACK=1`; even then the fallback can
/// only ever be the *other sales pool* — never a transactional pool.
pub const SENDER_POOL_FALLBACK_ENV: &str = "SALES_ALLOW_SENDER_POOL_FALLBACK";

/// Pure predicate: may a sales action use this pool at all?
pub fn is_permitted_for_sales(pool: SenderPool) -> bool {
    pool.is_sales_pool()
}

/// The other sales pool, used only when fallback is explicitly enabled.
/// Returns `None` for every non-sales pool — there is no cross-class fallback.
pub fn fallback_pool(preferred: SenderPool) -> Option<SenderPool> {
    match preferred {
        SenderPool::SalesOutbound => Some(SenderPool::SalesWarmup),
        SenderPool::SalesWarmup => Some(SenderPool::SalesOutbound),
        SenderPool::TransactionalCustomer | SenderPool::InternalTransactional => None,
    }
}

/// Fail loudly when a caller asks a sales path for a non-sales pool.
pub fn ensure_sales_pool(pool: SenderPool) -> Result<(), SalesError> {
    if is_permitted_for_sales(pool) {
        Ok(())
    } else {
        Err(SalesError::PolicyDenied(format!(
            "sender pool '{}' is not a sales pool; sales sending must never use \
             transactional/customer sender infrastructure (reputation isolation invariant)",
            pool
        )))
    }
}

/// Is sender-pool fallback permitted in this deployment? Only an explicit
/// sandbox/development opt-in enables it; unset (production) means off.
pub fn fallback_allowed() -> bool {
    match std::env::var(SENDER_POOL_FALLBACK_ENV) {
        Ok(value) => matches!(
            value.trim().to_ascii_lowercase().as_str(),
            "1" | "true" | "yes" | "on"
        ),
        Err(_) => false,
    }
}

/// The UTC day a reservation is booked under.
///
/// `sales_sender_daily_usage.usage_day` is a `DATE`; the budget boundary is
/// UTC so an identity's allowance does not move with the server's local time
/// zone or with DST.
pub fn utc_usage_day(now: DateTime<Utc>) -> NaiveDate {
    now.date_naive()
}

#[derive(sqlx::FromRow)]
struct SenderIdentityRow {
    id: Uuid,
    tenant_id: String,
    pool: String,
    from_email: String,
    from_name: Option<String>,
    domain: String,
    status: String,
    daily_limit: Option<i32>,
    /// Projected as `host(source_ip)`: the column is Postgres `INET`, which
    /// does not decode into a Rust string/IpAddr directly. The text form is
    /// parsed in [`SenderIdentityRow::into_sales_identity`].
    source_ip: Option<String>,
    provider: Option<String>,
    /// `COALESCE(sales_sender_daily_usage.sent, 0)` for the selection day.
    sent_today: i64,
    /// `sales_sender_health.state`; `None` when the identity has never been
    /// assessed (the pre-send health gate fails closed for those).
    health_state: Option<String>,
    /// `sales_sender_health.health_score` in `[0, 1]`; `None` when unassessed.
    health_score: Option<f64>,
}

impl SenderIdentityRow {
    /// Converting a database row into the domain type is itself a gate: a row
    /// whose pool cannot be parsed, or parses to a non-sales pool, is refused.
    /// The CHECK constraint makes that unreachable, but a drifted schema must
    /// fail closed rather than hand a transactional sender to a sales action.
    fn into_sales_identity(self) -> Result<SenderIdentity, SalesError> {
        let pool = SenderPool::parse(&self.pool).ok_or_else(|| {
            SalesError::PolicyDenied(format!(
                "sender identity {} has unrecognized pool '{}'; refusing to send",
                self.id, self.pool
            ))
        })?;
        ensure_sales_pool(pool)?;
        // `host()` returns canonical INET text; a value that does not parse is
        // impossible for a real INET column, and a NULL stays `None` rather
        // than failing the send over a cosmetic field.
        let source_ip = self.source_ip.as_deref().and_then(|ip| ip.parse().ok());
        Ok(SenderIdentity {
            id: self.id,
            tenant_id: self.tenant_id,
            pool,
            from_email: self.from_email,
            from_name: self.from_name,
            domain: self.domain,
            status: self.status,
            daily_limit: self.daily_limit,
            source_ip,
            provider: self.provider,
        })
    }
}

/// One selectable sender identity plus the signals the pure ranking consumes.
///
/// Kept separate from [`SenderIdentity`] (and from the Postgres row) so the
/// ranking rule is a pure, unit-testable function that cannot touch the
/// database or the clock.
#[derive(Debug, Clone, PartialEq)]
pub struct SenderCandidate {
    pub id: Uuid,
    pub from_email: String,
    /// `sales_sender_identities.daily_limit`; `None` = unlimited capacity.
    pub daily_limit: Option<i32>,
    /// `sales_sender_daily_usage.sent` for the UTC day, `0` when no row.
    pub sent_today: i64,
    /// `sales_sender_health.state`; `None` when never assessed.
    pub health_state: Option<String>,
    /// `sales_sender_health.health_score`; `None` when never assessed.
    pub health_score: Option<f64>,
}

/// How much of the daily capacity a candidate has already consumed.
///
/// * `daily_limit == None` → `0.0`: an **unlimited** identity has no capacity
///   pressure, so it ranks as if untouched (documented NULL semantics).
/// * a non-positive limit → `f64::INFINITY`: no capacity at all. The SQL
///   selection already excludes `sent >= daily_limit` (and a `0` limit always),
///   so this is a defence for callers that construct candidates directly.
/// * otherwise `sent / limit`, clamped at 0 from below. Never `NaN`.
pub fn sender_utilisation(daily_limit: Option<i32>, sent_today: i64) -> f64 {
    match daily_limit {
        None => 0.0,
        Some(limit) if limit <= 0 => f64::INFINITY,
        Some(limit) => sent_today.max(0) as f64 / f64::from(limit),
    }
}

/// Health ordering tier: lower is better.
///
/// `healthy` (0) > `warming` (1) > never assessed (2) > `throttled` (3) >
/// everything unrecognised, including a drifted `paused`/`quarantined` that
/// somehow reached the ranking (4). The SQL candidate query excludes
/// `paused`/`quarantined` outright; this tier only orders what remains.
pub fn health_tier(state: Option<&str>) -> u8 {
    match state.map(str::trim) {
        Some("healthy") => 0,
        Some("warming") => 1,
        Some("throttled") => 3,
        None | Some("") => 2,
        Some(_) => 4,
    }
}

/// THE ranking rule, as one pure function.
///
/// Order (best first):
///
/// 1. [`health_tier`] — prefer `healthy` over `warming` over unassessed over
///    `throttled`/unrecognised;
/// 2. [`sender_utilisation`] — prefer the identity that has consumed the
///    smallest fraction of its daily capacity (a `NULL` limit counts as 0.0),
///    which spreads a day's volume across the pool instead of exhausting one
///    identity;
/// 3. higher `health_score` first;
/// 4. `from_email`, then id, as a stable deterministic tie-break — never the
///    primary key (the defect this replaced).
///
/// The function is total: it never panics, and `f64::total_cmp` gives a strict
/// deterministic order even for the `INFINITY` produced by a zero limit.
pub fn rank_sender_candidates(mut candidates: Vec<SenderCandidate>) -> Vec<SenderCandidate> {
    candidates.sort_by(|a, b| {
        health_tier(a.health_state.as_deref())
            .cmp(&health_tier(b.health_state.as_deref()))
            .then_with(|| {
                sender_utilisation(a.daily_limit, a.sent_today)
                    .total_cmp(&sender_utilisation(b.daily_limit, b.sent_today))
            })
            .then_with(|| {
                b.health_score
                    .unwrap_or(0.0)
                    .total_cmp(&a.health_score.unwrap_or(0.0))
            })
            .then_with(|| a.from_email.cmp(&b.from_email))
            .then_with(|| a.id.cmp(&b.id))
    });
    candidates
}

/// The atomic capacity reservation (migration 206's documented upsert).
///
/// A single statement decides and consumes: `INSERT ... ON CONFLICT DO UPDATE
/// SET sent = sent + 1 ... WHERE sent < daily_limit RETURNING sent`. It returns
/// `true` only when the row was returned, i.e. the reservation was granted;
/// `false` means the identity's day is already at its limit (the insert was
/// suppressed by the guard). Because the guard is part of the same statement
/// as the increment, concurrent selectors cannot both take the final slot.
///
/// The `WHERE` guard is expressed for both branches: the fresh-insert branch
/// refuses a `0` limit (`$3::integer IS NULL OR $3 > 0`), the conflict branch
/// refuses once `sent >= $3`, and a `NULL` limit (unlimited) always grants.
pub const RESERVE_SENDER_CAPACITY_SQL: &str = "INSERT INTO sales_sender_daily_usage \
     (sender_identity_id, usage_day, sent, updated_at) \
     SELECT $1, $2, 1, NOW() \
     WHERE $3::integer IS NULL OR $3::integer > 0 \
     ON CONFLICT (sender_identity_id, usage_day) DO UPDATE \
     SET sent = sales_sender_daily_usage.sent + 1, updated_at = NOW() \
     WHERE $3::integer IS NULL OR sales_sender_daily_usage.sent < $3::integer \
     RETURNING sent";

async fn reserve_sender_capacity_on(
    conn: &mut sqlx::PgConnection,
    sender_identity_id: Uuid,
    usage_day: NaiveDate,
    daily_limit: Option<i32>,
) -> Result<bool, SalesError> {
    let sent: Option<i32> = sqlx::query_scalar(RESERVE_SENDER_CAPACITY_SQL)
        .bind(sender_identity_id)
        .bind(usage_day)
        .bind(daily_limit)
        .fetch_optional(&mut *conn)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    Ok(sent.is_some())
}

/// [`reserve_sender_capacity_on`] on the caller's transaction, for admission
/// decisions that must roll back with the rest of the work.
pub async fn reserve_sender_capacity_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    sender_identity_id: Uuid,
    usage_day: NaiveDate,
    daily_limit: Option<i32>,
) -> Result<bool, SalesError> {
    reserve_sender_capacity_on(&mut *tx, sender_identity_id, usage_day, daily_limit).await
}

/// Reserve one slot of `daily_limit` for the sender on `usage_day`.
pub async fn reserve_sender_capacity(
    db: &PgPool,
    sender_identity_id: Uuid,
    usage_day: NaiveDate,
    daily_limit: Option<i32>,
) -> Result<bool, SalesError> {
    let mut conn = db
        .acquire()
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;
    reserve_sender_capacity_on(&mut conn, sender_identity_id, usage_day, daily_limit).await
}

/// Give a reserved daily slot back because the send did not happen.
///
/// Decrements a strictly positive counter for the sender's current UTC day and
/// only when the identity belongs to `tenant_id`; returns `true` when a slot
/// was returned, `false` when there was nothing to release (never a negative
/// count). Settlement needs no counterpart call: a reservation that results in
/// a send is already the consumption.
pub async fn release_sender_reservation(
    db: &PgPool,
    tenant_id: &str,
    sender_identity_id: Uuid,
) -> Result<bool, SalesError> {
    release_sender_reservation_on_day(db, tenant_id, sender_identity_id, utc_usage_day(Utc::now()))
        .await
}

/// [`release_sender_reservation`] for an explicit day (tests, and writers that
/// reserved just before a UTC midnight boundary).
pub async fn release_sender_reservation_on_day(
    db: &PgPool,
    tenant_id: &str,
    sender_identity_id: Uuid,
    usage_day: NaiveDate,
) -> Result<bool, SalesError> {
    let affected = sqlx::query(
        "UPDATE sales_sender_daily_usage AS u \
         SET sent = GREATEST(u.sent - 1, 0), updated_at = NOW() \
         WHERE u.sender_identity_id = $1 \
           AND u.usage_day = $2 \
           AND u.sent > 0 \
           AND EXISTS ( \
               SELECT 1 FROM sales_sender_identities i \
               WHERE i.id = u.sender_identity_id AND i.tenant_id = $3 \
           )",
    )
    .bind(sender_identity_id)
    .bind(usage_day)
    .bind(tenant_id)
    .execute(db)
    .await
    .map_err(|error| SalesError::Database(error.to_string()))?
    .rows_affected();
    Ok(affected == 1)
}

/// Every candidate in one permitted sales pool: selectable, not at its daily
/// limit, and not health-blocked. Ordering is applied in Rust by
/// [`rank_sender_candidates`] so the rule is testable without a database.
const SELECT_RANKABLE_CANDIDATES: &str = "SELECT i.id, i.tenant_id, i.pool, i.from_email, \
     i.from_name, i.domain, i.status, i.daily_limit, host(i.source_ip) AS source_ip, \
     i.provider, COALESCE(u.sent, 0)::bigint AS sent_today, \
     h.state AS health_state, h.health_score \
     FROM sales_sender_identities i \
     LEFT JOIN sales_sender_daily_usage u \
            ON u.sender_identity_id = i.id AND u.usage_day = $3 \
     LEFT JOIN sales_sender_health h \
            ON h.sender_identity_id = i.id AND h.tenant_id = i.tenant_id \
     WHERE i.tenant_id = $1 AND i.pool = $2 \
       AND i.status = 'active' \
       AND (i.daily_limit IS NULL OR COALESCE(u.sent, 0) < i.daily_limit) \
       AND COALESCE(h.state, '') NOT IN ('quarantined', 'paused')";

/// A single identity by id, with the SAME projection as the ranking query.
///
/// `SenderIdentityRow` carries `sent_today` and the health signals, so a
/// narrower select here fails to decode at runtime — which is exactly how this
/// broke the dispatcher's sealed-sender path. One struct demands one column
/// set.
const SELECT_BY_ID: &str = "SELECT i.id, i.tenant_id, i.pool, i.from_email, i.from_name, \
     i.domain, i.status, i.daily_limit, host(i.source_ip) AS source_ip, i.provider, \
     COALESCE(u.sent, 0)::bigint AS sent_today, h.state AS health_state, h.health_score \
     FROM sales_sender_identities i \
     LEFT JOIN sales_sender_daily_usage u \
            ON u.sender_identity_id = i.id AND u.usage_day = $3 \
     LEFT JOIN sales_sender_health h \
            ON h.sender_identity_id = i.id AND h.tenant_id = i.tenant_id \
     WHERE i.id = $1 AND i.tenant_id = $2";

/// Fetch, rank and reserve one identity from a single sales pool.
///
/// Returns `None` when the pool has no identity with remaining capacity (or
/// none selectable at all). Each candidate that loses its last slot to a
/// concurrent reservation is skipped, and the next-ranked candidate is tried;
/// the caller-level fallback to the other sales pool therefore only happens
/// after the *whole* preferred pool is genuinely exhausted.
async fn reserve_from_pool(
    db: &PgPool,
    tenant_id: &str,
    pool: SenderPool,
    usage_day: NaiveDate,
) -> Result<Option<SenderIdentityRow>, SalesError> {
    let rows: Vec<SenderIdentityRow> = sqlx::query_as(SELECT_RANKABLE_CANDIDATES)
        .bind(tenant_id)
        .bind(pool.as_str())
        .bind(usage_day)
        .fetch_all(db)
        .await
        .map_err(|error| SalesError::Database(error.to_string()))?;

    let candidates = rank_sender_candidates(
        rows.iter()
            .map(|row| SenderCandidate {
                id: row.id,
                from_email: row.from_email.clone(),
                daily_limit: row.daily_limit,
                sent_today: row.sent_today,
                health_state: row.health_state.clone(),
                health_score: row.health_score,
            })
            .collect(),
    );

    let mut rows = rows;
    for candidate in candidates {
        let reserved =
            reserve_sender_capacity(db, candidate.id, usage_day, candidate.daily_limit).await?;
        if reserved {
            // `rows` holds exactly one row per id (PK of the identity).
            if let Some(index) = rows.iter().position(|row| row.id == candidate.id) {
                return Ok(Some(rows.swap_remove(index)));
            }
        } else {
            tracing::debug!(
                sender_identity_id = %candidate.id,
                tenant = tenant_id,
                pool = %pool,
                usage_day = %usage_day,
                "sender hit its daily capacity between selection and reservation; \
                 trying the next-ranked identity"
            );
        }
    }
    Ok(None)
}

/// Reserve a sender identity for a sales send. REFUSES any non-sales pool.
///
/// Selection order:
/// 1. a selectable identity in `preferred_pool` with remaining daily capacity,
///    ranked by [`rank_sender_candidates`] and reserved atomically;
/// 2. the other sales pool, **only** when [`fallback_allowed`] is enabled by
///    the sandbox/development configuration, under the same capacity rules;
/// 3. otherwise [`SalesError::ServiceUnavailable`] naming the missing pool.
///
/// There is no third step: a transactional/shared pool is never considered.
///
/// The returned identity has already consumed one slot of its daily limit. If
/// the send is subsequently refused, the caller MUST call
/// [`release_sender_reservation`]; if it sends, the reservation is the
/// settlement.
pub async fn reserve_sales_sender(
    db: &PgPool,
    tenant_id: &str,
    preferred_pool: SenderPool,
) -> Result<SenderIdentity, SalesError> {
    reserve_sales_sender_with_fallback(db, tenant_id, preferred_pool, fallback_allowed()).await
}

/// [`reserve_sales_sender`] with the fallback decision supplied explicitly —
/// used by tests and by callers that own their configuration.
pub async fn reserve_sales_sender_with_fallback(
    db: &PgPool,
    tenant_id: &str,
    preferred_pool: SenderPool,
    allow_fallback: bool,
) -> Result<SenderIdentity, SalesError> {
    // Loud refusal before any database work: a sales path asking for a
    // transactional pool is a caller bug, not something to paper over.
    ensure_sales_pool(preferred_pool)?;

    let usage_day = utc_usage_day(Utc::now());

    if let Some(row) = reserve_from_pool(db, tenant_id, preferred_pool, usage_day).await? {
        return row.into_sales_identity();
    }

    if allow_fallback {
        if let Some(other) = fallback_pool(preferred_pool) {
            if let Some(row) = reserve_from_pool(db, tenant_id, other, usage_day).await? {
                return row.into_sales_identity();
            }
            return Err(SalesError::ServiceUnavailable(format!(
                "no sales sender identity with remaining daily capacity in pool '{}' or \
                 fallback pool '{}' for tenant '{}'; provision capacity before sending",
                preferred_pool, other, tenant_id
            )));
        }
    }

    Err(SalesError::ServiceUnavailable(format!(
        "no selectable sales sender identity with remaining daily capacity in pool '{}' for \
         tenant '{}'; provision a sales sender or raise its daily_limit before sending \
         (cross-class fallback to a transactional pool is never permitted)",
        preferred_pool, tenant_id
    )))
}

/// Resolve a sender identity for a sales send — the sequence worker's entry
/// point. Since the capacity-reservation change this name **reserves**: it is
/// an alias of [`reserve_sales_sender`] kept for existing callers.
///
/// Callers must release the reservation whenever the send does not happen:
/// [`release_sender_reservation`].
pub async fn resolve_sales_sender(
    db: &PgPool,
    tenant_id: &str,
    preferred_pool: SenderPool,
) -> Result<SenderIdentity, SalesError> {
    reserve_sales_sender(db, tenant_id, preferred_pool).await
}

/// [`resolve_sales_sender`] with the fallback decision supplied explicitly.
/// Alias of [`reserve_sales_sender_with_fallback`]; reserves.
pub async fn resolve_sales_sender_with_fallback(
    db: &PgPool,
    tenant_id: &str,
    preferred_pool: SenderPool,
    allow_fallback: bool,
) -> Result<SenderIdentity, SalesError> {
    reserve_sales_sender_with_fallback(db, tenant_id, preferred_pool, allow_fallback).await
}

/// Fetch one sender identity by id, enforcing that it is a sales pool.
///
/// The row must belong to `tenant_id` and be in `sales_outbound` or
/// `sales_warmup`; anything else (including a missing row) is a
/// [`SalesError::PolicyDenied`]. `status` is deliberately not enforced here —
/// the sender-health gate owns pause/quarantine semantics and produces a
/// better operator explanation. This is a **read**: it does not reserve daily
/// capacity (the reservation happens at selection time).
pub async fn load_sales_sender(
    db: &PgPool,
    tenant_id: &str,
    sender_identity_id: Uuid,
) -> Result<SenderIdentity, SalesError> {
    let row: Option<SenderIdentityRow> = sqlx::query_as(SELECT_BY_ID)
        .bind(sender_identity_id)
        .bind(tenant_id)
        .bind(chrono::Utc::now().date_naive())
        .fetch_optional(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

    let row = row.ok_or_else(|| {
        SalesError::PolicyDenied(format!(
            "sender identity {sender_identity_id} not found for tenant '{tenant_id}'; \
             refusing to send"
        ))
    })?;
    row.into_sales_identity()
}

#[cfg(test)]
mod tests {
    use super::*;

    // -----------------------------------------------------------------------
    // Pure pool-isolation predicates (release gate)
    // -----------------------------------------------------------------------

    #[test]
    fn every_non_sales_pool_is_refused() {
        for pool in [
            SenderPool::TransactionalCustomer,
            SenderPool::InternalTransactional,
        ] {
            assert!(
                !is_permitted_for_sales(pool),
                "{pool} must never be permitted for a sales action"
            );
            let err = ensure_sales_pool(pool).unwrap_err();
            assert!(matches!(err, SalesError::PolicyDenied(_)));
            assert!(err.to_string().contains("not a sales pool"));
        }
    }

    #[test]
    fn sales_pools_are_permitted() {
        for pool in [SenderPool::SalesOutbound, SenderPool::SalesWarmup] {
            assert!(is_permitted_for_sales(pool));
            assert!(ensure_sales_pool(pool).is_ok());
        }
    }

    #[test]
    fn fallback_only_ever_targets_the_other_sales_pool() {
        assert_eq!(
            fallback_pool(SenderPool::SalesOutbound),
            Some(SenderPool::SalesWarmup)
        );
        assert_eq!(
            fallback_pool(SenderPool::SalesWarmup),
            Some(SenderPool::SalesOutbound)
        );
        // No fallback for transactional pools — this is the isolation invariant.
        assert_eq!(fallback_pool(SenderPool::TransactionalCustomer), None);
        assert_eq!(fallback_pool(SenderPool::InternalTransactional), None);
    }

    // -----------------------------------------------------------------------
    // Pure ranking rule
    // -----------------------------------------------------------------------

    fn candidate(
        email: &str,
        limit: Option<i32>,
        sent: i64,
        health_state: Option<&str>,
        health_score: Option<f64>,
    ) -> SenderCandidate {
        SenderCandidate {
            id: Uuid::new_v4(),
            from_email: email.to_string(),
            daily_limit: limit,
            sent_today: sent,
            health_state: health_state.map(str::to_string),
            health_score,
        }
    }

    #[test]
    fn health_tiers_order_healthy_over_warming_over_unassessed_over_throttled() {
        assert_eq!(health_tier(Some("healthy")), 0);
        assert_eq!(health_tier(Some("warming")), 1);
        assert_eq!(health_tier(None), 2);
        assert_eq!(health_tier(Some("throttled")), 3);
        assert_eq!(health_tier(Some("some-future-state")), 4);
        assert_eq!(health_tier(Some("")), 2);
        assert!(health_tier(Some("healthy")) < health_tier(Some("warming")));
        assert!(health_tier(Some("warming")) < health_tier(None));
        assert!(health_tier(None) < health_tier(Some("throttled")));
    }

    #[test]
    fn utilisation_documents_null_limit_as_unlimited() {
        assert_eq!(sender_utilisation(None, 0), 0.0);
        assert_eq!(sender_utilisation(None, 10_000), 0.0);
        assert_eq!(sender_utilisation(Some(10), 0), 0.0);
        assert!((sender_utilisation(Some(10), 5) - 0.5).abs() < f64::EPSILON);
        assert!(sender_utilisation(Some(0), 0).is_infinite());
        assert!(sender_utilisation(Some(-1), 0).is_infinite());
        // Never NaN, even for a corrupt negative count.
        assert_eq!(sender_utilisation(Some(10), -5), 0.0);
        assert!(!sender_utilisation(Some(10), -5).is_nan());
    }

    #[test]
    fn ranking_prefers_health_then_lowest_utilisation_not_the_alphabet() {
        let ranked = rank_sender_candidates(vec![
            // Alphabetically first, but throttled and nearly exhausted.
            candidate("aaa@example.com", Some(10), 9, Some("throttled"), Some(0.2)),
            // Alphabetically last, healthy and untouched.
            candidate("zzz@example.com", Some(10), 0, Some("healthy"), Some(0.9)),
            // Middle: healthy but half consumed.
            candidate("mmm@example.com", Some(10), 5, Some("healthy"), Some(0.9)),
        ]);
        assert_eq!(
            ranked
                .iter()
                .map(|c| c.from_email.as_str())
                .collect::<Vec<_>>(),
            vec!["zzz@example.com", "mmm@example.com", "aaa@example.com"],
            "health and utilisation must outrank from_email"
        );
    }

    #[test]
    fn ranking_breaks_health_ties_by_score_then_email() {
        let ranked = rank_sender_candidates(vec![
            candidate("b@example.com", Some(10), 0, Some("healthy"), Some(0.5)),
            candidate("a@example.com", Some(10), 0, Some("healthy"), Some(0.5)),
            candidate("c@example.com", Some(10), 0, Some("healthy"), Some(0.8)),
        ]);
        assert_eq!(
            ranked
                .iter()
                .map(|c| c.from_email.as_str())
                .collect::<Vec<_>>(),
            vec!["c@example.com", "a@example.com", "b@example.com"],
            "higher health score wins, then from_email is only a tie-break"
        );
    }

    #[test]
    fn unlimited_capacity_ranks_as_unused_and_never_nan() {
        let ranked = rank_sender_candidates(vec![
            candidate(
                "limited@example.com",
                Some(4),
                1,
                Some("healthy"),
                Some(0.9),
            ),
            candidate(
                "unlimited@example.com",
                None,
                1000,
                Some("healthy"),
                Some(0.9),
            ),
        ]);
        // Equal health and score: the unlimited identity ranks as utilisation
        // 0.0, ahead of the 25%-consumed limited one.
        assert_eq!(ranked[0].from_email, "unlimited@example.com");
    }

    #[test]
    fn ranking_is_deterministic_for_equal_candidates() {
        let mut a = candidate("x@example.com", Some(10), 0, Some("healthy"), Some(1.0));
        a.id = Uuid::from_u128(1);
        let mut b = candidate("x@example.com", Some(10), 0, Some("healthy"), Some(1.0));
        b.id = Uuid::from_u128(2);
        let first = rank_sender_candidates(vec![b.clone(), a.clone()]);
        let second = rank_sender_candidates(vec![a.clone(), b.clone()]);
        assert_eq!(first[0].id, Uuid::from_u128(1));
        assert_eq!(first[1].id, Uuid::from_u128(2));
        assert_eq!(
            first.iter().map(|c| c.id).collect::<Vec<_>>(),
            second.iter().map(|c| c.id).collect::<Vec<_>>()
        );
    }

    /// `sales_sender_identities.source_ip` is `INET`: it must be projected as
    /// `host(source_ip)` in EVERY select, or Decode fails at runtime.
    #[test]
    fn every_select_decodes_source_ip_as_text_and_carries_provider() {
        for sql in [SELECT_RANKABLE_CANDIDATES, SELECT_BY_ID] {
            assert!(
                (sql.contains("host(source_ip)") || sql.contains("host(i.source_ip)"))
                    && sql.contains("AS source_ip"),
                "INET must be decoded with host(...) AS source_ip: {sql}"
            );
            assert!(
                !sql.contains("SELECT id, tenant_id, pool, from_email, from_name, domain, status, daily_limit, source_ip"),
                "raw INET select must not reappear: {sql}"
            );
            assert!(sql.contains("provider"), "provider must be selected: {sql}");
        }
        // Pool isolation semantics are unchanged.
        assert!(
            SELECT_RANKABLE_CANDIDATES.contains("i.pool = $2")
                && SELECT_RANKABLE_CANDIDATES.contains("i.status = 'active'"),
            "selection must keep the sales-pool + active-status filters"
        );
        // Capacity and health are part of the same selection.
        assert!(
            SELECT_RANKABLE_CANDIDATES
                .contains("(i.daily_limit IS NULL OR COALESCE(u.sent, 0) < i.daily_limit)"),
            "at-limit identities must be excluded by the selection"
        );
        assert!(
            SELECT_RANKABLE_CANDIDATES.contains("NOT IN ('quarantined', 'paused')"),
            "quarantined/paused health must be excluded by the selection"
        );
        assert!(
            SELECT_BY_ID.contains("WHERE i.id = $1 AND i.tenant_id = $2")
                || SELECT_BY_ID.contains("WHERE id = $1 AND tenant_id = $2"),
            "the by-id lookup must stay tenant-scoped: {SELECT_BY_ID}"
        );
        // Both queries feed the same row struct, so both must project the same
        // columns — a narrower select decodes as a runtime error rather than a
        // compile error, which is exactly how it broke the sealed-sender path.
        assert!(
            SELECT_BY_ID.contains("AS sent_today") && SELECT_BY_ID.contains("health_score"),
            "SELECT_BY_ID must project the same capacity/health columns as the ranking query"
        );
    }

    /// The reservation SQL must be a single guarded statement: the limit check
    /// is part of the same upsert that increments, for both the insert and the
    /// conflict branch, and a NULL limit is explicitly unlimited.
    #[test]
    fn reservation_sql_is_atomic_and_handles_null_limits() {
        assert!(RESERVE_SENDER_CAPACITY_SQL.contains("ON CONFLICT (sender_identity_id, usage_day)"));
        assert!(RESERVE_SENDER_CAPACITY_SQL.contains("sent = sales_sender_daily_usage.sent + 1"));
        assert!(
            RESERVE_SENDER_CAPACITY_SQL.contains("sales_sender_daily_usage.sent < $3::integer"),
            "the conflict branch must refuse at the limit"
        );
        assert!(
            RESERVE_SENDER_CAPACITY_SQL.contains("$3::integer IS NULL OR $3::integer > 0"),
            "the insert branch must refuse a zero limit and allow NULL (unlimited)"
        );
        assert!(RESERVE_SENDER_CAPACITY_SQL.contains("RETURNING sent"));
    }

    /// The async resolver must refuse a requested transactional pool before it
    /// touches the database. `connect_lazy` builds a pool that never connects,
    /// so this proves the refusal happens in the policy check, not in SQL.
    #[tokio::test]
    async fn resolve_refuses_a_requested_transactional_pool() {
        let pool = sqlx::postgres::PgPoolOptions::new()
            .connect_lazy("postgres://sales:sales@127.0.0.1:1/never_connects")
            .expect("lazy pool construction cannot fail");
        for requested in [
            SenderPool::TransactionalCustomer,
            SenderPool::InternalTransactional,
        ] {
            let err = reserve_sales_sender(&pool, "tenant-a", requested)
                .await
                .unwrap_err();
            assert!(
                matches!(err, SalesError::PolicyDenied(_)),
                "requested {requested} must be a loud PolicyDenied, got {err:?}"
            );
            // The legacy alias must refuse identically.
            let err = resolve_sales_sender(&pool, "tenant-a", requested)
                .await
                .unwrap_err();
            assert!(matches!(err, SalesError::PolicyDenied(_)));
        }
        let err = load_sales_sender(&pool, "tenant-a", Uuid::nil()).await;
        // load_sales_sender does hit the database for a sales-pool lookup, so
        // this only asserts it does not panic; the pool error is a Database
        // error, never a silent success.
        assert!(err.is_err());
    }

    // -----------------------------------------------------------------------
    // Live-database tests
    //
    // Canonical provisioned pool (`crate::test_db::canonical_test_pool`);
    // SOFT-SKIP only when no test database is configured.
    // -----------------------------------------------------------------------

    /// Insert one sender identity (plus an optional healthy health row) and
    /// return its id.
    async fn seed_sender(
        pool: &PgPool,
        tenant: &str,
        pool_name: &str,
        from_email: &str,
        status: &str,
        daily_limit: Option<i32>,
        health_state: Option<&str>,
        health_score: f64,
    ) -> Uuid {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO sales_sender_identities \
                 (id, tenant_id, pool, from_email, from_name, domain, status, daily_limit) \
             VALUES ($1, $2, $3, $4, 'Fixture Sender', 'fixture.example', $5, $6)",
        )
        .bind(id)
        .bind(tenant)
        .bind(pool_name)
        .bind(from_email)
        .bind(status)
        .bind(daily_limit)
        .execute(pool)
        .await
        .expect("insert sales_sender_identities fixture");

        if let Some(state) = health_state {
            sqlx::query(
                "INSERT INTO sales_sender_health \
                     (id, tenant_id, sender_identity_id, health_score, state) \
                 VALUES (gen_random_uuid(), $1, $2, $3, $4)",
            )
            .bind(tenant)
            .bind(id)
            .bind(health_score)
            .bind(state)
            .execute(pool)
            .await
            .expect("insert sales_sender_health fixture");
        }
        id
    }

    async fn cleanup_senders(pool: &PgPool, tenant: &str) {
        // usage rows cascade with the identities.
        sqlx::query("DELETE FROM sales_sender_health WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup sender health");
        sqlx::query("DELETE FROM sales_sender_identities WHERE tenant_id = $1")
            .bind(tenant)
            .execute(pool)
            .await
            .expect("cleanup sender identities");
    }

    async fn sent_today(pool: &PgPool, sender_id: Uuid, day: NaiveDate) -> i64 {
        let sent: Option<i64> = sqlx::query_scalar(
            "SELECT sent::bigint FROM sales_sender_daily_usage \
             WHERE sender_identity_id = $1 AND usage_day = $2",
        )
        .bind(sender_id)
        .bind(day)
        .fetch_optional(pool)
        .await
        .expect("read sales_sender_daily_usage");
        sent.unwrap_or(0)
    }

    /// A sender with no remaining capacity must not be selected; a NULL limit
    /// is unlimited; a paused/quarantined identity is excluded regardless of
    /// capacity. Live path: the real resolver, against the real schema.
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    #[tokio::test]
    async fn selection_excludes_at_limit_and_unhealthy_identities() {
        let Some(pool) = crate::test_db::canonical_test_pool("sender_capacity_exclusions").await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("senderexcl");
        let day = utc_usage_day(Utc::now());

        // At its limit: excluded.
        let spent = seed_sender(
            &pool,
            &tenant,
            "sales_outbound",
            "spent@fixture.example",
            "active",
            Some(5),
            Some("healthy"),
            0.99,
        )
        .await;
        sqlx::query(
            "INSERT INTO sales_sender_daily_usage (sender_identity_id, usage_day, sent) \
             VALUES ($1, $2, 5)",
        )
        .bind(spent)
        .bind(day)
        .execute(&pool)
        .await
        .expect("seed consumed capacity");

        // NULL limit: unlimited, selected even with a large existing count.
        let unlimited = seed_sender(
            &pool,
            &tenant,
            "sales_outbound",
            "unlimited@fixture.example",
            "active",
            None,
            Some("healthy"),
            0.99,
        )
        .await;
        sqlx::query(
            "INSERT INTO sales_sender_daily_usage (sender_identity_id, usage_day, sent) \
             VALUES ($1, $2, 1000)",
        )
        .bind(unlimited)
        .bind(day)
        .execute(&pool)
        .await
        .expect("seed unlimited usage");

        let chosen = reserve_sales_sender(&pool, &tenant, SenderPool::SalesOutbound)
            .await
            .expect("the unlimited identity must be selectable");
        assert_eq!(chosen.id, unlimited, "NULL limit means unlimited");
        assert_eq!(
            sent_today(&pool, unlimited, day).await,
            1001,
            "the reservation must increment the unlimited identity"
        );
        assert_eq!(
            sent_today(&pool, spent, day).await,
            5,
            "the at-limit identity must not be touched"
        );

        cleanup_senders(&pool, &tenant).await;
    }

    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    #[tokio::test]
    async fn paused_and_quarantined_identities_are_never_selected() {
        let Some(pool) = crate::test_db::canonical_test_pool("sender_health_exclusions").await
        else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("senderhealth");

        // Identity status still says `active` (mirror lag) but health says
        // quarantined: the selection must exclude it.
        seed_sender(
            &pool,
            &tenant,
            "sales_outbound",
            "quarantined@fixture.example",
            "active",
            Some(100),
            Some("quarantined"),
            0.1,
        )
        .await;

        let err = reserve_sales_sender(&pool, &tenant, SenderPool::SalesOutbound)
            .await
            .expect_err("a quarantined health state must block selection");
        assert!(matches!(err, SalesError::ServiceUnavailable(_)));

        // Paused identity status (mirrored) is excluded too.
        seed_sender(
            &pool,
            &tenant,
            "sales_outbound",
            "paused@fixture.example",
            "paused",
            Some(100),
            Some("paused"),
            0.1,
        )
        .await;
        let err = reserve_sales_sender(&pool, &tenant, SenderPool::SalesOutbound)
            .await
            .expect_err("a paused identity must block selection");
        assert!(matches!(err, SalesError::ServiceUnavailable(_)));

        cleanup_senders(&pool, &tenant).await;
    }

    /// Ten concurrent selections against two identities with `daily_limit = 5`
    /// each: every call gets a reservation and neither identity exceeds five.
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn concurrent_selections_never_exceed_each_identity_daily_limit() {
        let Some(pool) = crate::test_db::canonical_test_pool("sender_capacity_race").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("senderrace");
        let day = utc_usage_day(Utc::now());

        let first = seed_sender(
            &pool,
            &tenant,
            "sales_outbound",
            "race-a@fixture.example",
            "active",
            Some(5),
            Some("healthy"),
            0.99,
        )
        .await;
        let second = seed_sender(
            &pool,
            &tenant,
            "sales_outbound",
            "race-b@fixture.example",
            "active",
            Some(5),
            Some("healthy"),
            0.99,
        )
        .await;

        let mut handles = Vec::new();
        for _ in 0..10 {
            let pool = pool.clone();
            let tenant = tenant.clone();
            handles.push(tokio::spawn(async move {
                reserve_sales_sender(&pool, &tenant, SenderPool::SalesOutbound).await
            }));
        }
        let mut chosen: Vec<Uuid> = Vec::new();
        for handle in handles {
            let sender = handle
                .await
                .expect("selection task must not panic")
                .expect("all ten reservations must be granted");
            chosen.push(sender.id);
        }
        assert_eq!(chosen.len(), 10);
        assert!(
            chosen.iter().all(|id| *id == first || *id == second),
            "only the two provisioned sales identities may be selected"
        );

        let first_sent = sent_today(&pool, first, day).await;
        let second_sent = sent_today(&pool, second, day).await;
        assert_eq!(
            first_sent + second_sent,
            10,
            "every reservation must be persisted"
        );
        assert!(
            first_sent <= 5,
            "identity A exceeded its limit: {first_sent}"
        );
        assert!(
            second_sent <= 5,
            "identity B exceeded its limit: {second_sent}"
        );

        // The pool is now genuinely full: an eleventh call is refused rather
        // than overselling.
        let err = reserve_sales_sender(&pool, &tenant, SenderPool::SalesOutbound)
            .await
            .expect_err("a full pool must refuse");
        assert!(matches!(err, SalesError::ServiceUnavailable(_)));

        cleanup_senders(&pool, &tenant).await;
    }

    /// Releasing a reservation for a refused send returns the slot, and the
    /// next selection can reuse it. Double release never goes negative.
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    #[tokio::test]
    async fn released_reservation_is_reusable_and_never_negative() {
        let Some(pool) = crate::test_db::canonical_test_pool("sender_release").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("senderrelease");
        let day = utc_usage_day(Utc::now());

        let only = seed_sender(
            &pool,
            &tenant,
            "sales_outbound",
            "release@fixture.example",
            "active",
            Some(1),
            Some("healthy"),
            0.99,
        )
        .await;

        let first = reserve_sales_sender(&pool, &tenant, SenderPool::SalesOutbound)
            .await
            .expect("the single slot must be reserved");
        assert_eq!(first.id, only);
        assert_eq!(sent_today(&pool, only, day).await, 1);

        // The limit is reached: a second selection without release is refused.
        let err = reserve_sales_sender(&pool, &tenant, SenderPool::SalesOutbound)
            .await
            .expect_err("the daily limit is spent");
        assert!(matches!(err, SalesError::ServiceUnavailable(_)));

        // The send was refused downstream: release returns the slot.
        assert!(release_sender_reservation(&pool, &tenant, only)
            .await
            .expect("release"));
        assert_eq!(sent_today(&pool, only, day).await, 0);

        let second = reserve_sales_sender(&pool, &tenant, SenderPool::SalesOutbound)
            .await
            .expect("the released slot must be reusable");
        assert_eq!(second.id, only);

        // A wrong tenant cannot release, and a second release of the same slot
        // finds nothing (never negative).
        assert!(!release_sender_reservation(&pool, "another-tenant", only)
            .await
            .expect("cross-tenant release must be a no-op"));
        assert_eq!(sent_today(&pool, only, day).await, 1);
        assert!(release_sender_reservation(&pool, &tenant, only)
            .await
            .expect("release"));
        assert!(
            !release_sender_reservation(&pool, &tenant, only)
                .await
                .expect("double release must be a no-op"),
            "a release must never drive the counter below zero"
        );
        assert_eq!(sent_today(&pool, only, day).await, 0);

        cleanup_senders(&pool, &tenant).await;
    }

    /// A transaction that rolls back releases a capacity reservation made
    /// inside it: the counter row is exactly as it was before.
    #[ignore = "live Postgres: set SALES_TEST_DATABASE_URL"]
    #[tokio::test]
    async fn transaction_rollback_releases_sender_capacity() {
        let Some(pool) = crate::test_db::canonical_test_pool("sender_rollback").await else {
            return;
        };
        let tenant = crate::test_db::unique_test_tenant("senderrollback");
        let day = utc_usage_day(Utc::now());

        let sender = seed_sender(
            &pool,
            &tenant,
            "sales_outbound",
            "rollback@fixture.example",
            "active",
            Some(5),
            Some("healthy"),
            0.99,
        )
        .await;

        let mut tx = pool.begin().await.expect("begin");
        let reserved = reserve_sender_capacity_in_tx(&mut tx, sender, day, Some(5))
            .await
            .expect("reserve in tx");
        assert!(reserved, "the reservation inside the tx must be granted");
        // Visible inside the transaction...
        let inside: i64 = sqlx::query_scalar(
            "SELECT sent::bigint FROM sales_sender_daily_usage \
             WHERE sender_identity_id = $1 AND usage_day = $2",
        )
        .bind(sender)
        .bind(day)
        .fetch_one(&mut *tx)
        .await
        .expect("usage row in tx");
        assert_eq!(inside, 1);
        tx.rollback().await.expect("rollback");

        // ...and gone after the rollback.
        assert_eq!(
            sent_today(&pool, sender, day).await,
            0,
            "a rolled-back transaction must release the sender capacity reservation"
        );

        cleanup_senders(&pool, &tenant).await;
    }
}
