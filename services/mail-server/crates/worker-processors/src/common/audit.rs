//! Canonical `audit_logs` append for worker-owned audit writes.
//!
//! Worker audit writers (the pre-send DLP hold/refusal and warmup graduation
//! reconciler) used to read the newest `audit_logs` row and chain onto it
//! directly. That forks the platform hash chain: two concurrent writers can
//! both link onto the same `previous_hash`, and the canonical sequencer
//! (`audit_chain_head`, migration 105, advanced by api-server/billing) never
//! sees the worker's rows — chain verification against the head table cannot
//! validate them. Migration 105 replaced exactly that pattern with a single
//! `INSERT ... ON CONFLICT (chain_id) DO UPDATE ... RETURNING prev_hash`
//! statement.
//!
//! This module is the worker's one canonical appender: it hashes through the
//! shared byte contract ([`apexmail_lib::audit`]), advances the head row in
//! the SAME transaction as the insert (so a rollback releases the advance),
//! and signs the chain link with the deployment's `AUDIT_SIGNING_KEY` —
//! fail-closed in production, exactly like api-server/billing/compliance.
#![deny(unsafe_code)]

use chrono::Utc;
use serde_json::Value;
use sqlx::PgConnection;

/// The single platform-wide chain id (the same constant api-server uses).
const AUDIT_CHAIN_GLOBAL: &str = "global";

/// The pinned development fallback key. Byte-identical to api-server's so a
/// non-production deployment's rows verify with one key; production REFUSES
/// to sign with it.
const AUDIT_SIGNING_FALLBACK_KEY: &str = "apexmail-audit-fallback-key";

/// Advance the audit hash-chain head to `new_hash` and return the hash it
/// replaced (the `previous_hash` the new entry links to; `None` on the
/// chain's first entry).
///
/// Mirrors api-server's `audit_log::advance_chain_head` statement: the
/// `ON CONFLICT` row lock on the single head row is the only serialization
/// point, and it is held for the short append inside the caller's
/// transaction.
const AUDIT_CHAIN_HEAD_ADVANCE_SQL: &str = r#"
INSERT INTO audit_chain_head (chain_id, head_hash, prev_hash, head_seq, updated_at)
VALUES ($1, $2, NULL, 1, NOW())
ON CONFLICT (chain_id) DO UPDATE SET
    prev_hash  = audit_chain_head.head_hash,
    head_hash  = EXCLUDED.head_hash,
    head_seq   = audit_chain_head.head_seq + 1,
    updated_at = NOW()
RETURNING prev_hash
"#;

/// One canonical audit entry. `user_id`, `ip_address` and `user_agent` are
/// deliberately absent: worker rows are machine actions with no request
/// identity, and NULL segments contribute the empty string to the hash.
pub struct AuditEntry<'a> {
    pub tenant_id: Option<&'a str>,
    pub action: &'a str,
    pub resource: &'a str,
    pub resource_id: Option<&'a str>,
    pub details: Value,
    pub outcome: &'a str,
}

/// Append one hash-chained `audit_logs` row on the caller's transaction
/// connection: hash (canonical 7-segment contract) → advance
/// `audit_chain_head` → insert with the HMAC chain-link signature.
///
/// Runs on `&mut PgConnection` so callers can pass `&mut *tx` and keep the
/// business write and its evidence atomic. A missing `AUDIT_SIGNING_KEY` in
/// production is an `Err` (fail closed) rather than a silently forgeable
/// development signature.
pub(crate) async fn append_audit_log(
    conn: &mut PgConnection,
    entry: AuditEntry<'_>,
) -> Result<(), sqlx::Error> {
    let timestamp = apexmail_lib::audit::truncate_timestamp_to_micros(Utc::now());
    let hash = apexmail_lib::audit::audit_hash(
        entry.tenant_id,
        None,
        entry.action,
        entry.resource,
        entry.resource_id,
        &entry.details,
        timestamp,
    );

    // Advance the head in the same transaction as the insert: the loser of a
    // concurrent append links onto the winner, and a rollback releases the
    // advance so no `audit_logs` row is ever skipped.
    let previous_hash: Option<String> = sqlx::query_scalar(AUDIT_CHAIN_HEAD_ADVANCE_SQL)
        .bind(AUDIT_CHAIN_GLOBAL)
        .bind(&hash)
        .fetch_optional(&mut *conn)
        .await?
        .flatten();

    let signing_key = audit_signing_key()?;
    let signature =
        apexmail_lib::audit::audit_log_signature(previous_hash.as_deref(), &hash, &signing_key)
            .map_err(sqlx::Error::Protocol)?;

    sqlx::query(
        r#"
        INSERT INTO audit_logs
            (id, tenant_id, user_id, action, resource, resource_id, details,
             outcome, timestamp, hash, previous_hash, signature, created_at)
        VALUES (gen_random_uuid(), $1, NULL, $2, $3, $4, $5::jsonb, $6, $7, $8, $9, $10, $7)
        "#,
    )
    .bind(entry.tenant_id)
    .bind(entry.action)
    .bind(entry.resource)
    .bind(entry.resource_id)
    .bind(&entry.details)
    .bind(entry.outcome)
    .bind(timestamp)
    .bind(&hash)
    .bind(&previous_hash)
    .bind(&signature)
    .execute(&mut *conn)
    .await
    .map(|_| ())
}

/// Resolve the chain signing key. Production REQUIRES `AUDIT_SIGNING_KEY`
/// (the same key api-server/billing/compliance sign with); elsewhere the
/// public fallback key is used with a loud warning, matching api-server's
/// documented policy.
fn audit_signing_key() -> Result<zeroize::Zeroizing<String>, sqlx::Error> {
    let production = std::env::var("NODE_ENV")
        .map(|value| {
            matches!(
                value.trim().to_ascii_lowercase().as_str(),
                "production" | "prod"
            )
        })
        .unwrap_or(false);
    match std::env::var("AUDIT_SIGNING_KEY") {
        Ok(key) if !key.is_empty() => Ok(zeroize::Zeroizing::new(key)),
        Ok(_) | Err(_) if production => Err(sqlx::Error::Io(std::io::Error::other(
            "AUDIT_SIGNING_KEY must be configured in production",
        ))),
        Ok(_) | Err(_) => {
            tracing::warn!(
                "AUDIT_SIGNING_KEY not set — using the development fallback for worker audit \
                 signatures"
            );
            Ok(zeroize::Zeroizing::new(
                AUDIT_SIGNING_FALLBACK_KEY.to_string(),
            ))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The head-advance template is the canonical migration-105 statement —
    /// no read of `audit_logs`, the head row is the only lock.
    #[test]
    fn head_advance_sql_never_scans_audit_logs() {
        assert!(AUDIT_CHAIN_HEAD_ADVANCE_SQL.contains("audit_chain_head"));
        assert!(AUDIT_CHAIN_HEAD_ADVANCE_SQL.contains("ON CONFLICT (chain_id) DO UPDATE"));
        assert!(AUDIT_CHAIN_HEAD_ADVANCE_SQL.contains("RETURNING prev_hash"));
        assert!(
            !AUDIT_CHAIN_HEAD_ADVANCE_SQL.contains("audit_logs"),
            "the advance must never touch the log table"
        );
    }
}
