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
fn audit_log_signature(hash: &str, previous_hash: &str) -> Result<String, sqlx::Error> {
    type HmacSha256 = Hmac<Sha256>;
    let key = match std::env::var("AUDIT_SIGNING_KEY") {
        Ok(k) if !k.is_empty() => k,
        Ok(_) | Err(_) => {
            if state_is_production() {
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
/// The entry is chained to the most recent prior entry (`previous_hash`),
/// selected in the same transaction as the insert (`FOR UPDATE` serialises
/// concurrent writers) so tampering, deletion, or reordering breaks the
/// chain instead of passing silently.
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
    let mut tx = db.begin().await?;
    insert_audit_log_in_tx(
        &mut tx,
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

/// Transaction-scoped variant of [`insert_audit_log`] for callers that
/// already hold a transaction (e.g. billing flows that audit atomically
/// with the business write).
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

    // Chain the audit entry: link it to the most recent prior entry's hash
    // (by timestamp, then id), chosen in the same transaction as the insert
    // to close the concurrent-writer race.
    let previous_hash: Option<String> = sqlx::query_scalar(
        "SELECT hash FROM audit_logs ORDER BY timestamp DESC, id DESC LIMIT 1 FOR UPDATE",
    )
    .fetch_optional(&mut **tx)
    .await?;
    let signature = audit_log_signature(&hash, previous_hash.as_deref().unwrap_or_default())?;

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
    if let Err(error) = insert_audit_log(
        db,
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
