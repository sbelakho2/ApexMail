//! Seven-year retention class helpers.
//!
//! Migration 220 gives every accounting record a `retention_class` and a
//! BEFORE DELETE trigger that refuses to remove `legal_7y`/`legal_10y` rows
//! unless the deleting session explicitly opts into an authorized purge.
//! Ordinary customer-deletion paths (GDPR erasure, tenant offboarding,
//! `DELETE FROM customers WHERE ...`) therefore fail closed instead of
//! silently destroying statutory evidence.

use sqlx::PgConnection;

use crate::error::Result;
use crate::types::{RETENTION_LEGAL_10Y, RETENTION_LEGAL_7Y};

/// Session/transaction setting that an authorized retention-expiry purge sets
/// to `on`. Set through [`set_retention_override`]; never set implicitly.
pub const RETENTION_OVERRIDE_SETTING: &str = "apexmail.accounting.retention_override";

/// True when the class carries a statutory retention floor.
pub fn is_statutory(retention_class: &str) -> bool {
    matches!(retention_class, RETENTION_LEGAL_7Y | RETENTION_LEGAL_10Y)
}

/// Enable the explicit retention override on this session/transaction
/// (authorized, audited purge only). `SET LOCAL` semantics are the caller's
/// choice: when a transaction is open, set it inside the transaction.
pub async fn set_retention_override(conn: &mut PgConnection) -> Result<()> {
    sqlx::query("SELECT set_config($1, 'on', false)")
        .bind(RETENTION_OVERRIDE_SETTING)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Clear the override again.
pub async fn clear_retention_override(conn: &mut PgConnection) -> Result<()> {
    sqlx::query("SELECT set_config($1, '', false)")
        .bind(RETENTION_OVERRIDE_SETTING)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// The retention class catalogue (code → retention years).
pub async fn retention_classes(conn: &mut PgConnection) -> Result<Vec<(String, i32)>> {
    let rows: Vec<(String, i32)> = sqlx::query_as(
        "SELECT code, retention_years FROM accounting_retention_classes ORDER BY code",
    )
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows)
}

/// Count retained posted journals per retention class for an entity.
pub async fn retained_journal_counts(
    conn: &mut PgConnection,
    legal_entity_id: uuid::Uuid,
) -> Result<Vec<(String, i64)>> {
    let rows: Vec<(String, i64)> = sqlx::query_as(
        "SELECT retention_class, COUNT(*)::bigint FROM journal_entries \
         WHERE legal_entity_id = $1 AND posted_at IS NOT NULL \
         GROUP BY retention_class ORDER BY retention_class",
    )
    .bind(legal_entity_id)
    .fetch_all(&mut *conn)
    .await?;
    Ok(rows)
}
