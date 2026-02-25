//! API keys repository.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::ApiKey;

/// Repository for API key operations.
pub struct ApiKeysRepo;

impl ApiKeysRepo {
    /// Look up an API key by its hash (for authentication).
    pub async fn find_by_hash(pool: &PgPool, hash: &str) -> Result<Option<ApiKey>, sqlx::Error> {
        sqlx::query_as::<_, ApiKey>(
            "SELECT id, tenant_id, name, key_hash, key_prefix, scopes, last_used_at, expires_at, created_at \
             FROM api_keys WHERE key_hash = $1"
        )
        .bind(hash)
        .fetch_optional(pool)
        .await
    }

    /// Create a new API key.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
        key_hash: &str,
        key_prefix: &str,
        scopes: serde_json::Value,
    ) -> Result<ApiKey, sqlx::Error> {
        sqlx::query_as::<_, ApiKey>(
            "INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, NOW()) \
             RETURNING id, tenant_id, name, key_hash, key_prefix, scopes, last_used_at, expires_at, created_at"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(name)
        .bind(key_hash)
        .bind(key_prefix)
        .bind(scopes)
        .fetch_one(pool)
        .await
    }

    /// List API keys for a tenant with pagination.
    /// #226: Added limit/offset parameters
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<ApiKey>, sqlx::Error> {
        let limit = limit.clamp(1, 100);
        let offset = offset.max(0);
        sqlx::query_as::<_, ApiKey>(
            "SELECT id, tenant_id, name, key_hash, key_prefix, scopes, last_used_at, expires_at, created_at \
             FROM api_keys WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Delete an API key (scoped to tenant).
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM api_keys WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Update the last-used timestamp for an API key.
    pub async fn update_last_used(pool: &PgPool, id: Uuid) -> Result<(), sqlx::Error> {
        sqlx::query("UPDATE api_keys SET last_used_at = NOW() WHERE id = $1")
            .bind(id)
            .execute(pool)
            .await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;

    #[test]
    fn test_api_keys_repo_is_stateless() {
        let _repo = ApiKeysRepo;
        // Repo has no fields — purely a method namespace.
    }

    #[test]
    fn test_api_key_mock_construction() {
        let key = ApiKey {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "CI Key".into(),
            key_hash: "sha256_deadbeef".into(),
            key_prefix: "am_live_abc".into(),
            scopes: serde_json::json!(["messages:send"]),
            last_used_at: None,
            expires_at: None,
            created_at: Utc::now(),
        };
        assert_eq!(key.name, "CI Key");
        assert!(key.last_used_at.is_none());
    }

    #[test]
    fn test_api_key_scopes_parsing() {
        let scopes = serde_json::json!(["messages:send", "messages:read", "domains:manage"]);
        let arr = scopes.as_array().unwrap();
        assert_eq!(arr.len(), 3);
    }
}
