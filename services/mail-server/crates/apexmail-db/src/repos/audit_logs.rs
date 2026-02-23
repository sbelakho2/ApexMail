//! Audit logs repository.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::AuditLog;

/// Repository for audit log operations.
pub struct AuditRepo;

impl AuditRepo {
    /// Record an audit event.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        actor_id: Option<Uuid>,
        action: &str,
        resource_type: &str,
        resource_id: Option<&str>,
        metadata: Option<serde_json::Value>,
        ip: Option<&str>,
    ) -> Result<AuditLog, sqlx::Error> {
        sqlx::query_as::<_, AuditLog>(
            "INSERT INTO audit_logs (id, tenant_id, actor_id, action, resource_type, resource_id, metadata, ip_address, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, NOW()) \
             RETURNING id, tenant_id, actor_id, action, resource_type, resource_id, metadata, ip_address, created_at"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(actor_id)
        .bind(action)
        .bind(resource_type)
        .bind(resource_id)
        .bind(metadata)
        .bind(ip)
        .fetch_one(pool)
        .await
    }

    /// List audit logs for a tenant with pagination.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLog>, sqlx::Error> {
        sqlx::query_as::<_, AuditLog>(
            "SELECT id, tenant_id, actor_id, action, resource_type, resource_id, metadata, ip_address, created_at \
             FROM audit_logs WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
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
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            actor_id: Some(Uuid::new_v4()),
            action: "domain.create".into(),
            resource_type: "domain".into(),
            resource_id: Some("example.com".into()),
            metadata: Some(serde_json::json!({"verified": false})),
            ip_address: Some("192.168.1.1".into()),
            created_at: Utc::now(),
        };
        assert_eq!(log.action, "domain.create");
        assert!(log.actor_id.is_some());
    }

    #[test]
    fn test_audit_log_without_actor() {
        let log = AuditLog {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            actor_id: None,
            action: "system.cleanup".into(),
            resource_type: "messages".into(),
            resource_id: None,
            metadata: None,
            ip_address: None,
            created_at: Utc::now(),
        };
        assert!(log.actor_id.is_none());
        assert!(log.ip_address.is_none());
    }
}
