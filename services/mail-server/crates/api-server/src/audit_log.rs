//! Canonical audit_logs writer.
//!
//! Production `audit_logs` is a partitioned, hash-chained table with the
//! compliance crate's shape: `resource` + `details` + NOT NULL
//! `outcome`/`hash`/`signature`. Every writer must produce that shape; legacy
//! `resource_type`/`metadata` INSERTs fail at runtime.

use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use serde_json::Value;
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use uuid::Uuid;

/// HMAC-SHA256 signature over the audit hash (and its chain link), keyed
/// with the same `AUDIT_SIGNING_KEY` the compliance crate uses for chain
/// verification. In production the key MUST be configured — a
/// publicly-known fallback would make every signature forgeable — so the
/// function fails closed there. Development keeps a fallback with a warning.
///
/// `is_production` must come from the loaded `Config::environment`, NOT a
/// raw env read: deployments that set production mode in the config file
/// (while `ENVIRONMENT` stays unset) would otherwise silently sign with the
/// public fallback key. The [`state_is_production`] legacy wrapper exists
/// only for the deprecated delegating writers below.
fn audit_log_signature(
    hash: &str,
    previous_hash: &str,
    is_production: bool,
) -> Result<String, sqlx::Error> {
    type HmacSha256 = Hmac<Sha256>;
    let key = match std::env::var("AUDIT_SIGNING_KEY") {
        Ok(k) if !k.is_empty() => k,
        Ok(_) | Err(_) => {
            if is_production {
                return Err(sqlx::Error::Io(std::io::Error::other(
                    "AUDIT_SIGNING_KEY must be configured in production",
                )));
            }
            tracing::warn!(
                "AUDIT_SIGNING_KEY not set — using development fallback for audit signatures"
            );
            "apexmail-audit-fallback-key".to_string()
        }
    };
    let mut mac = HmacSha256::new_from_slice(key.as_bytes())
        .map_err(|_| sqlx::Error::Io(std::io::Error::other("audit HMAC init failed")))?;
    mac.update(previous_hash.as_bytes());
    mac.update(b"|");
    mac.update(hash.as_bytes());
    Ok(hex::encode(mac.finalize().into_bytes()))
}

/// Legacy production probe: reads the raw `ENVIRONMENT` env var.
///
/// Kept ONLY so the signature-compatible delegating writers
/// ([`insert_audit_log`], [`insert_audit_log_in_tx`],
/// [`insert_audit_log_best_effort`]) keep their historical behaviour for
/// call sites that have not been migrated to pass the config's environment
/// flag. New callers must thread `Config::environment.is_production()`
/// through the `*_with_env` variants instead: this probe cannot see
/// config-file production deployments and defaults to `false` (the
/// permissive dev fallback key) when the env var is absent.
fn state_is_production() -> bool {
    std::env::var("ENVIRONMENT")
        .map(|v| v.eq_ignore_ascii_case("production"))
        .unwrap_or(false)
}

fn compute_hash(
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    resource: &str,
    resource_id: Option<&str>,
    details: &Value,
    timestamp: DateTime<Utc>,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(tenant_id.unwrap_or_default().as_bytes());
    hasher.update(b"|");
    hasher.update(user_id.unwrap_or_default().as_bytes());
    hasher.update(b"|");
    hasher.update(action.as_bytes());
    hasher.update(b"|");
    hasher.update(resource.as_bytes());
    hasher.update(b"|");
    hasher.update(resource_id.unwrap_or_default().as_bytes());
    hasher.update(b"|");
    hasher.update(details.to_string().as_bytes());
    hasher.update(b"|");
    hasher.update(timestamp.to_rfc3339().as_bytes());
    hex::encode(hasher.finalize())
}

/// Insert one audit log entry in the canonical (hash-chained) shape.
///
/// The entry is chained to the most recent prior entry (`previous_hash`).
/// Chain linking goes through the dedicated `audit_chain_head` single-row
/// table (migration 105), advanced atomically in the same transaction as the
/// insert, so tampering, deletion, or reordering breaks the chain instead of
/// passing silently — without serialising writers on `audit_logs` rows.
///
/// DEPRECATED call shape: resolves "production" via the raw `ENVIRONMENT`
/// env var, which misses config-file production deployments (see
/// [`state_is_production`]). Migrate to [`insert_audit_log_with_env`] with
/// the loaded config's `environment.is_production()`.
#[allow(clippy::too_many_arguments)]
pub async fn insert_audit_log(
    db: &PgPool,
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    resource: &str,
    resource_id: Option<&str>,
    details: Value,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    insert_audit_log_with_env(
        db,
        state_is_production(),
        tenant_id,
        user_id,
        action,
        resource,
        resource_id,
        details,
        ip_address,
        user_agent,
    )
    .await
}

/// Canonical standalone audit write. `is_production` MUST come from the
/// loaded config (`Config::environment.is_production()`), never from a raw
/// env read — in production the signature step fails closed without
/// `AUDIT_SIGNING_KEY`, and a false negative here would silently sign audit
/// evidence with the public development fallback key.
#[allow(clippy::too_many_arguments)]
pub async fn insert_audit_log_with_env(
    db: &PgPool,
    is_production: bool,
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    resource: &str,
    resource_id: Option<&str>,
    details: Value,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) -> Result<(), sqlx::Error> {
    let mut tx = db.begin().await?;
    insert_audit_log_in_tx_with_env(
        &mut tx,
        is_production,
        tenant_id,
        user_id,
        action,
        resource,
        resource_id,
        details,
        ip_address,
        user_agent,
        Utc::now(),
    )
    .await?;
    tx.commit().await?;
    Ok(())
}

/// The single platform-wide audit chain. The current writer design links
/// every entry into one global chain (the legacy selector had no tenant
/// scope either); the column keeps the door open for per-tenant chains
/// without another migration.
const AUDIT_CHAIN_GLOBAL: &str = "global";

/// Advance the audit hash-chain head to `new_hash` and return the hash it
/// replaced (the `previous_hash` the new entry must link to; `None` when this
/// is the first entry of the chain).
///
/// M-10: this replaces `SELECT hash FROM audit_logs ORDER BY timestamp DESC,
/// id DESC LIMIT 1 FOR UPDATE`, which serialised every audit writer
/// platform-wide on the newest row of a big partitioned table. The
/// `ON CONFLICT DO UPDATE` row lock on the single head row is the only
/// serialization point now: it touches no `audit_logs` rows (verification
/// readers and retention jobs are never blocked) and it is held only for the
/// short append inside the caller's transaction, never across the event's
/// other work.
pub(crate) async fn advance_chain_head(
    executor: impl sqlx::Executor<'_, Database = sqlx::Postgres>,
    new_hash: &str,
) -> Result<Option<String>, sqlx::Error> {
    // `prev_hash` is NULL for a chain's FIRST entry — decode the scalar as
    // nullable (Option<Option<String>> distinguishes no-row from NULL
    // column), otherwise every fresh database's first audit insert fails
    // to decode and is silently dropped by the best-effort writer.
    let previous: Option<Option<String>> = sqlx::query_scalar(AUDIT_CHAIN_HEAD_ADVANCE_SQL)
        .bind(AUDIT_CHAIN_GLOBAL)
        .bind(new_hash)
        .fetch_optional(executor)
        .await?;
    Ok(previous.flatten())
}

/// Kept as a named constant so tests can pin the exact template (no
/// `FOR UPDATE` against `audit_logs`; the head table is the only lock).
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

/// Transaction-scoped variant of [`insert_audit_log`] for callers that
/// already hold a transaction (e.g. billing flows that audit atomically
/// with the business write).
///
/// DEPRECATED call shape: resolves "production" via the raw `ENVIRONMENT`
/// env var (see [`state_is_production`]). Migrate to
/// [`insert_audit_log_in_tx_with_env`] with the config's production flag.
#[allow(clippy::too_many_arguments)]
pub async fn insert_audit_log_in_tx(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    resource: &str,
    resource_id: Option<&str>,
    details: Value,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    timestamp: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    insert_audit_log_in_tx_with_env(
        tx,
        state_is_production(),
        tenant_id,
        user_id,
        action,
        resource,
        resource_id,
        details,
        ip_address,
        user_agent,
        timestamp,
    )
    .await
}

/// Canonical transaction-scoped audit write. `is_production` MUST come from
/// the loaded config (`Config::environment.is_production()`); the signature
/// step fails closed in production without `AUDIT_SIGNING_KEY`, and a raw
/// env probe would default a config-file production deployment to the
/// forgeable development fallback key.
#[allow(clippy::too_many_arguments)]
pub async fn insert_audit_log_in_tx_with_env(
    tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
    is_production: bool,
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    resource: &str,
    resource_id: Option<&str>,
    details: Value,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
    timestamp: DateTime<Utc>,
) -> Result<(), sqlx::Error> {
    let id = Uuid::new_v4().to_string();
    let hash = compute_hash(
        tenant_id,
        user_id,
        action,
        resource,
        resource_id,
        &details,
        timestamp,
    );

    // Chain the audit entry: advance the head (atomically capturing the hash
    // it replaced) in the same transaction as the insert. Concurrent appenders
    // serialise on the single head row; the loser links onto the winner. A
    // failure here means migration 105 has not been applied — propagate
    // rather than silently unlinking the chain.
    let previous_hash: Option<String> = advance_chain_head(&mut **tx, &hash).await?;
    let signature = audit_log_signature(
        &hash,
        previous_hash.as_deref().unwrap_or_default(),
        is_production,
    )?;

    sqlx::query(
        "INSERT INTO audit_logs (
            id, tenant_id, user_id, session_id, action, resource, resource_id,
            details, ip_address, user_agent, outcome, error_message,
            timestamp, hash, previous_hash, signature, created_at
         ) VALUES (
            $1, $2, $3, NULL, $4, $5, $6,
            $7::jsonb, $8, $9, 'success', NULL,
            $10, $11, $12, $13, $10
         )",
    )
    .bind(&id)
    .bind(tenant_id)
    .bind(user_id)
    .bind(action)
    .bind(resource)
    .bind(resource_id)
    .bind(details)
    .bind(ip_address)
    .bind(user_agent)
    .bind(timestamp)
    .bind(&hash)
    .bind(&previous_hash)
    .bind(&signature)
    .execute(&mut **tx)
    .await?;

    Ok(())
}

/// Fire-and-forget variant for admin routes that must not fail the request
/// when audit logging fails (logged instead).
///
/// DEPRECATED call shape: resolves "production" via the raw `ENVIRONMENT`
/// env var (see [`state_is_production`]). Migrate to
/// [`insert_audit_log_best_effort_with_env`] with the config's production
/// flag.
#[allow(clippy::too_many_arguments)]
pub async fn insert_audit_log_best_effort(
    db: &PgPool,
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    resource: &str,
    resource_id: Option<&str>,
    details: Value,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) {
    insert_audit_log_best_effort_with_env(
        db,
        state_is_production(),
        tenant_id,
        user_id,
        action,
        resource,
        resource_id,
        details,
        ip_address,
        user_agent,
    )
    .await
}

/// Canonical fire-and-forget audit write. `is_production` MUST come from
/// the loaded config (`Config::environment.is_production()`); same fail
/// closed invariant as [`insert_audit_log_with_env`].
#[allow(clippy::too_many_arguments)]
pub async fn insert_audit_log_best_effort_with_env(
    db: &PgPool,
    is_production: bool,
    tenant_id: Option<&str>,
    user_id: Option<&str>,
    action: &str,
    resource: &str,
    resource_id: Option<&str>,
    details: Value,
    ip_address: Option<&str>,
    user_agent: Option<&str>,
) {
    if let Err(error) = insert_audit_log_with_env(
        db,
        is_production,
        tenant_id,
        user_id,
        action,
        resource,
        resource_id,
        details,
        ip_address,
        user_agent,
    )
    .await
    {
        tracing::warn!(
            action = %action,
            resource = %resource,
            error = %error,
            "Failed to write audit log"
        );
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use sqlx::postgres::PgPoolOptions;
    use std::time::Duration;

    /// SQL template pin (M-10): the append path must never lock `audit_logs`
    /// rows; the single `audit_chain_head` row is the only serialization
    /// point.
    #[test]
    fn audit_append_sql_never_locks_audit_logs_rows() {
        assert!(
            AUDIT_CHAIN_HEAD_ADVANCE_SQL.contains("audit_chain_head"),
            "chain linking must go through the head table"
        );
        assert!(
            AUDIT_CHAIN_HEAD_ADVANCE_SQL.contains("ON CONFLICT (chain_id) DO UPDATE"),
            "appends must advance the head atomically"
        );
        assert!(
            AUDIT_CHAIN_HEAD_ADVANCE_SQL.contains("RETURNING prev_hash"),
            "the advance must return the replaced hash for linking"
        );
        assert!(
            !AUDIT_CHAIN_HEAD_ADVANCE_SQL
                .to_ascii_uppercase()
                .contains("FOR UPDATE"),
            "the head advance must not take explicit row locks"
        );

        // Source-level pin: the legacy serialized latest-hash read is gone.
        // (The needle is assembled from parts so this test's own source does
        // not contain the literal it is checking for.)
        let source = include_str!("audit_log.rs");
        let legacy_selector = [
            "ORDER BY timestamp DESC, id DESC ",
            "LIMIT 1 ",
            "FOR UPDATE",
        ]
        .concat();
        assert!(
            !source.contains(&legacy_selector),
            "the legacy FOR UPDATE latest-hash selector must not come back"
        );
    }

    #[test]
    fn audit_hash_and_signature_are_deterministic() {
        let details = serde_json::json!({"event": "login"});
        let timestamp = Utc::now();
        let hash_a = compute_hash(
            Some("tenant-1"),
            Some("user-1"),
            "login",
            "auth",
            None,
            &details,
            timestamp,
        );
        let hash_b = compute_hash(
            Some("tenant-1"),
            Some("user-1"),
            "login",
            "auth",
            None,
            &details,
            timestamp,
        );
        assert_eq!(hash_a, hash_b);
        assert_eq!(hash_a.len(), 64, "SHA-256 hex digest");
        let hash_c = compute_hash(
            Some("tenant-2"),
            Some("user-1"),
            "login",
            "auth",
            None,
            &details,
            timestamp,
        );
        assert_ne!(hash_a, hash_c, "tenant is part of the hashed payload");
    }

    /// Canonical audit_logs shape (migration 050's columns, unpartitioned for
    /// test simplicity) plus the migration-105 head table.
    const CANONICAL_AUDIT_DDL: &str = r#"
CREATE TABLE IF NOT EXISTS audit_logs (
    id            TEXT        NOT NULL,
    tenant_id     TEXT,
    user_id       TEXT,
    session_id    TEXT,
    action        TEXT        NOT NULL,
    resource      TEXT        NOT NULL,
    resource_id   TEXT,
    details       JSONB       NOT NULL DEFAULT '{}'::jsonb,
    ip_address    TEXT,
    user_agent    TEXT,
    outcome       TEXT        NOT NULL,
    error_message TEXT,
    timestamp     TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    hash          TEXT        NOT NULL,
    previous_hash TEXT,
    signature     TEXT        NOT NULL,
    created_at    TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (id, timestamp)
);
CREATE TABLE IF NOT EXISTS audit_chain_head (
    chain_id   TEXT        PRIMARY KEY,
    head_hash  TEXT        NOT NULL,
    prev_hash  TEXT,
    head_seq   BIGINT      NOT NULL DEFAULT 1,
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);
"#;

    /// Dedicated per-test database (the compliance crate's 50-way test
    /// pattern): the shared `<db>_api` database carries the tools/migrations
    /// legacy audit_logs shape, which is incompatible with the canonical
    /// writer. Skips unless TEST_DATABASE_URL is set (workspace convention).
    async fn audit_chain_test_pool(db_suffix: &str) -> Option<PgPool> {
        let database_url = std::env::var("TEST_DATABASE_URL")
            .ok()
            .filter(|value| !value.trim().is_empty())?;
        let (server_part, db_part) = database_url.rsplit_once('/')?;
        let db_only = db_part.split('?').next().unwrap_or(db_part);
        let isolated_db = format!("{db_only}_api_audit_{db_suffix}");
        let isolated_url = format!("{server_part}/{isolated_db}");
        let admin_url = format!("{server_part}/postgres");

        let admin = PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(Duration::from_secs(3))
            .connect(&admin_url)
            .await
            .ok()?;
        let _ = sqlx::query(&format!(
            r#"DROP DATABASE IF EXISTS "{isolated_db}" WITH (FORCE)"#
        ))
        .execute(&admin)
        .await;
        let created = sqlx::query(&format!(r#"CREATE DATABASE "{isolated_db}""#))
            .execute(&admin)
            .await;
        admin.close().await;
        created.ok()?;

        let pool = PgPoolOptions::new()
            .max_connections(8)
            .acquire_timeout(Duration::from_secs(5))
            .connect(&isolated_url)
            .await
            .ok()?;
        sqlx::query(CANONICAL_AUDIT_DDL).execute(&pool).await.ok()?;
        Some(pool)
    }

    #[derive(sqlx::FromRow)]
    struct AuditRow {
        #[allow(dead_code)]
        id: String,
        tenant_id: Option<String>,
        user_id: Option<String>,
        action: String,
        resource: String,
        resource_id: Option<String>,
        details: Value,
        timestamp: DateTime<Utc>,
        hash: String,
        previous_hash: Option<String>,
        signature: String,
    }

    /// Walk the chain from the head backwards through `previous_hash` links,
    /// re-hashing and re-signing every entry. Returns the number of entries
    /// verified; panics on the first inconsistency.
    async fn verify_chain_from_head(pool: &PgPool) -> usize {
        let head: Option<(String, Option<String>, i64)> = sqlx::query_as(
            "SELECT head_hash, prev_hash, head_seq FROM audit_chain_head WHERE chain_id = 'global'",
        )
        .fetch_optional(pool)
        .await
        .expect("head row readable");

        // Start at the newest appended row and follow previous_hash links
        // down to the chain root.
        let mut current: Option<String> = head.as_ref().map(|(hash, _, _)| hash.clone());
        let mut verified = 0usize;

        while let Some(hash) = current.clone() {
            let row: AuditRow = sqlx::query_as(
                "SELECT id, tenant_id, user_id, action, resource, resource_id, details,
                        timestamp, hash, previous_hash, signature
                 FROM audit_logs WHERE hash = $1",
            )
            .bind(&hash)
            .fetch_optional(pool)
            .await
            .expect("chain row readable")
            .unwrap_or_else(|| panic!("hash {hash} has no matching row"));

            let recomputed = compute_hash(
                row.tenant_id.as_deref(),
                row.user_id.as_deref(),
                &row.action,
                &row.resource,
                row.resource_id.as_deref(),
                &row.details,
                row.timestamp,
            );
            assert_eq!(recomputed, row.hash, "hash mismatch for entry {}", row.id);
            let expected_sig = audit_log_signature(
                &row.hash,
                row.previous_hash.as_deref().unwrap_or_default(),
                false,
            )
            .expect("signature computable");
            assert_eq!(
                expected_sig, row.signature,
                "signature mismatch for entry {}",
                row.id
            );
            if verified == 0 {
                // Newest entry must agree with the head bookkeeping.
                let (_, head_prev, _) = head.as_ref().expect("walk started from a head");
                assert_eq!(
                    &row.previous_hash, head_prev,
                    "newest entry's link must match the head's prev_hash"
                );
            }
            current = row.previous_hash;
            verified += 1;
        }

        if let Some((_, _, head_seq)) = head {
            assert!(verified > 0, "head exists but chain walk found nothing");
            assert_eq!(
                head_seq, verified as i64,
                "head_seq must count the chained entries"
            );
        }
        verified
    }

    /// M-10 (compliance-crate E-1 pattern replicated here): 50 concurrent
    /// appends must produce one verifiable chain via the head table, with no
    /// FOR UPDATE serialization on audit_logs.
    #[tokio::test]
    async fn concurrent_appends_produce_a_verifiable_chain() {
        std::env::set_var("AUDIT_SIGNING_KEY", "audit-chain-test-key-0123456789");
        let Some(pool) = audit_chain_test_pool("concurrency").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        let mut handles = Vec::new();
        for i in 0..50 {
            let pool = pool.clone();
            handles.push(tokio::spawn(async move {
                insert_audit_log(
                    &pool,
                    Some(&format!("tenant-{i}")),
                    Some(&format!("user-{i}")),
                    "login",
                    "auth",
                    None,
                    serde_json::json!({"attempt": i}),
                    Some("203.0.113.1"),
                    Some("test-agent"),
                )
                .await
                .expect("audit append must succeed")
            }));
        }
        for handle in handles {
            handle.await.expect("join");
        }

        let verified = verify_chain_from_head(&pool).await;
        assert_eq!(verified, 50, "all concurrent entries must chain");
        let count: i64 = sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs")
            .fetch_one(&pool)
            .await
            .expect("count readable");
        assert_eq!(count, 50);
        pool.close().await;
    }

    /// Migration-105 backfill: appends after the migration must chain onto
    /// the pre-existing newest row instead of starting a NULL-rooted chain.
    #[tokio::test]
    async fn head_backfill_links_new_appends_onto_legacy_history() {
        std::env::set_var("AUDIT_SIGNING_KEY", "audit-chain-test-key-0123456789");
        let Some(pool) = audit_chain_test_pool("backfill").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };

        // One "legacy" row exactly as the pre-105 writer produced it.
        let legacy_ts = Utc::now();
        let legacy_hash = compute_hash(
            Some("legacy-tenant"),
            None,
            "rotate",
            "auth",
            None,
            &serde_json::json!({}),
            legacy_ts,
        );
        sqlx::query(
            r#"INSERT INTO audit_logs (id, tenant_id, action, resource, details,
               outcome, timestamp, hash, previous_hash, signature, created_at)
               VALUES ('legacy-1', 'legacy-tenant', 'rotate', 'auth', '{}'::jsonb,
               'success', $1, $2, NULL, 'legacy', $1)"#,
        )
        .bind(legacy_ts)
        .bind(&legacy_hash)
        .execute(&pool)
        .await
        .expect("legacy row inserted");

        // The migration's backfill statement (105_audit_chain_head.sql).
        sqlx::query(
            r#"INSERT INTO audit_chain_head (chain_id, head_hash, prev_hash, head_seq)
               SELECT 'global', latest.hash, latest.previous_hash, 1
               FROM (SELECT hash, previous_hash FROM audit_logs
                     ORDER BY timestamp DESC, id DESC LIMIT 1) AS latest
               ON CONFLICT (chain_id) DO NOTHING"#,
        )
        .execute(&pool)
        .await
        .expect("backfill ran");

        insert_audit_log(
            &pool,
            Some("new-tenant"),
            Some("new-user"),
            "login",
            "auth",
            None,
            serde_json::json!({"after": "migration"}),
            None,
            None,
        )
        .await
        .expect("post-migration append");

        let verified = verify_chain_from_head(&pool).await;
        assert_eq!(verified, 2, "legacy row + new append form one chain");
        let linked: Option<String> =
            sqlx::query_scalar("SELECT previous_hash FROM audit_logs WHERE id <> 'legacy-1'")
                .fetch_one(&pool)
                .await
                .expect("new row readable");
        assert_eq!(
            linked.as_deref(),
            Some(legacy_hash.as_str()),
            "the first post-migration append must link to the legacy head"
        );
        pool.close().await;
    }
}
