//! Sender-pool selection — the reputation-isolation invariant.
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
        Ok(SenderIdentity {
            id: self.id,
            tenant_id: self.tenant_id,
            pool,
            from_email: self.from_email,
            from_name: self.from_name,
            domain: self.domain,
            status: self.status,
            daily_limit: self.daily_limit,
        })
    }
}

const SELECT_ACTIVE_POOL: &str = "SELECT id, tenant_id, pool, from_email, from_name, domain, \
     status, daily_limit \
     FROM sales_sender_identities \
     WHERE tenant_id = $1 AND pool = $2 AND status = 'active' \
     ORDER BY from_email ASC \
     LIMIT 1";

/// Resolve a sender identity for a sales send. REFUSES any non-sales pool.
///
/// Selection order:
/// 1. an active identity in `preferred_pool`;
/// 2. the other sales pool, **only** when [`fallback_allowed`] is enabled by
///    the sandbox/development configuration;
/// 3. otherwise [`SalesError::ServiceUnavailable`] naming the missing pool.
///
/// There is no third step: a transactional/shared pool is never considered.
pub async fn resolve_sales_sender(
    db: &PgPool,
    tenant_id: &str,
    preferred_pool: SenderPool,
) -> Result<SenderIdentity, SalesError> {
    resolve_sales_sender_with_fallback(db, tenant_id, preferred_pool, fallback_allowed()).await
}

/// [`resolve_sales_sender`] with the fallback decision supplied explicitly —
/// used by tests and by callers that own their configuration.
pub async fn resolve_sales_sender_with_fallback(
    db: &PgPool,
    tenant_id: &str,
    preferred_pool: SenderPool,
    allow_fallback: bool,
) -> Result<SenderIdentity, SalesError> {
    // Loud refusal before any database work: a sales path asking for a
    // transactional pool is a caller bug, not something to paper over.
    ensure_sales_pool(preferred_pool)?;

    let row: Option<SenderIdentityRow> = sqlx::query_as(SELECT_ACTIVE_POOL)
        .bind(tenant_id)
        .bind(preferred_pool.as_str())
        .fetch_optional(db)
        .await
        .map_err(|e| SalesError::Database(e.to_string()))?;

    if let Some(row) = row {
        return row.into_sales_identity();
    }

    if allow_fallback {
        if let Some(other) = fallback_pool(preferred_pool) {
            let fallback: Option<SenderIdentityRow> = sqlx::query_as(SELECT_ACTIVE_POOL)
                .bind(tenant_id)
                .bind(other.as_str())
                .fetch_optional(db)
                .await
                .map_err(|e| SalesError::Database(e.to_string()))?;
            if let Some(row) = fallback {
                return row.into_sales_identity();
            }
            return Err(SalesError::ServiceUnavailable(format!(
                "no active sender identity in pool '{}' and fallback pool '{}' for tenant '{}'; \
                 provision a sales sender before sending",
                preferred_pool, other, tenant_id
            )));
        }
    }

    Err(SalesError::ServiceUnavailable(format!(
        "no active sender identity in pool '{}' for tenant '{}'; \
         provision a sales sender before sending (cross-class fallback to a \
         transactional pool is never permitted)",
        preferred_pool, tenant_id
    )))
}

/// Fetch one sender identity by id, enforcing that it is a sales pool.
///
/// The row must belong to `tenant_id` and be in `sales_outbound` or
/// `sales_warmup`; anything else (including a missing row) is a
/// [`SalesError::PolicyDenied`]. `status` is deliberately not enforced here —
/// the sender-health gate owns pause/quarantine semantics and produces a
/// better operator explanation.
pub async fn load_sales_sender(
    db: &PgPool,
    tenant_id: &str,
    sender_identity_id: Uuid,
) -> Result<SenderIdentity, SalesError> {
    let row: Option<SenderIdentityRow> = sqlx::query_as(
        "SELECT id, tenant_id, pool, from_email, from_name, domain, status, daily_limit \
         FROM sales_sender_identities \
         WHERE id = $1 AND tenant_id = $2",
    )
    .bind(sender_identity_id)
    .bind(tenant_id)
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
            let err = resolve_sales_sender(&pool, "tenant-a", requested)
                .await
                .unwrap_err();
            assert!(
                matches!(err, SalesError::PolicyDenied(_)),
                "requested {requested} must be a loud PolicyDenied, got {err:?}"
            );
        }
        let err = load_sales_sender(&pool, "tenant-a", Uuid::nil()).await;
        // load_sales_sender does hit the database for a sales-pool lookup, so
        // this only asserts it does not panic; the pool error is a Database
        // error, never a silent success.
        assert!(err.is_err());
    }
}
