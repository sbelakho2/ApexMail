//! Audit logs repository.
//!
//! F6 convergence: the canonical `audit_logs` shape is the tamper-evident
//! hash-chain table from migration 038 (+ 055's `created_at`). The former
//! UUID-shaped INSERT (id UUID, actor_id, resource_type, metadata) targeted a
//! table no migration in the chain creates and failed on every
//! canonical-schema database.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::AuditLog;

/// Repository for audit log operations.
pub struct AuditRepo;

impl AuditRepo {
    /// Record an audit event (canonical 038 shape). `hash`, `previous_hash`
    /// and `signature` are supplied by the caller — the hash chain is the
    /// writer's responsibility, not the repo's.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        tenant_id: Option<&str>,
        user_id: Option<&str>,
        action: &str,
        resource: &str,
        resource_id: Option<&str>,
        details: serde_json::Value,
        ip: Option<&str>,
        outcome: &str,
        hash: &str,
        previous_hash: Option<&str>,
        signature: &str,
    ) -> Result<AuditLog, sqlx::Error> {
        sqlx::query_as::<_, AuditLog>(
            "INSERT INTO audit_logs \
             (id, tenant_id, user_id, session_id, action, resource, resource_id, details, \
              ip_address, user_agent, outcome, error_message, timestamp, hash, previous_hash, signature, created_at) \
             VALUES ($1, $2, $3, NULL, $4, $5, $6, $7, $8, NULL, $9, NULL, NOW(), $10, $11, $12, NOW()) \
             RETURNING id, tenant_id, user_id, session_id, action, resource, resource_id, details, \
                       ip_address, user_agent, outcome, error_message, timestamp, hash, previous_hash, signature",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(tenant_id)
        .bind(user_id)
        .bind(action)
        .bind(resource)
        .bind(resource_id)
        .bind(details)
        .bind(ip)
        .bind(outcome)
        .bind(hash)
        .bind(previous_hash)
        .bind(signature)
        .fetch_one(pool)
        .await
    }

    /// List audit logs for a tenant with pagination.
    pub async fn list(
        pool: &PgPool,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLog>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        let offset = offset.clamp(0, 100_000);
        sqlx::query_as::<_, AuditLog>(
            "SELECT id, tenant_id, user_id, session_id, action, resource, resource_id, details, \
                    ip_address, user_agent, outcome, error_message, timestamp, hash, previous_hash, signature \
             FROM audit_logs WHERE tenant_id = $1 ORDER BY timestamp DESC LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_audit_repo_is_stateless() {
        let _repo = AuditRepo;
    }

    #[test]
    fn test_audit_log_mock() {
        let log = AuditLog {
            id: Uuid::new_v4().to_string(),
            tenant_id: Some(crate::types::short_id('t')),
            user_id: Some(crate::types::short_id('u')),
            session_id: None,
            action: "domain.create".into(),
            resource: "domain".into(),
            resource_id: Some("example.com".into()),
            details: serde_json::json!({"verified": false}),
            ip_address: Some("192.168.1.1".into()),
            user_agent: None,
            outcome: "success".into(),
            error_message: None,
            timestamp: Utc::now(),
            hash: "abc123".into(),
            previous_hash: None,
            signature: "sig".into(),
        };
        assert_eq!(log.action, "domain.create");
        assert!(log.user_id.is_some());
    }

    #[test]
    fn test_audit_log_without_user() {
        let log = AuditLog {
            id: Uuid::new_v4().to_string(),
            tenant_id: None,
            user_id: None,
            session_id: None,
            action: "system.cleanup".into(),
            resource: "messages".into(),
            resource_id: None,
            details: serde_json::json!({}),
            ip_address: None,
            user_agent: None,
            outcome: "success".into(),
            error_message: None,
            timestamp: Utc::now(),
            hash: "abc123".into(),
            previous_hash: None,
            signature: "sig".into(),
        };
        assert!(log.user_id.is_none());
        assert!(log.ip_address.is_none());
    }
}
