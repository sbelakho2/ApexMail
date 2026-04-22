//! Suppressions repository.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::Suppression;

/// Repository for email suppression operations.
pub struct SuppressionsRepo;

impl SuppressionsRepo {
/// Add an email to the suppression list.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        email: &str,
        reason: &str,
        source: &str,
    ) -> Result<Suppression, sqlx::Error> {
        sqlx::query_as::<_, Suppression>(
            "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at) \
             VALUES ($1, $2, $3, $4, $5, NOW()) \
             ON CONFLICT (tenant_id, email) DO UPDATE SET reason = EXCLUDED.reason, source = EXCLUDED.source \
             RETURNING id, tenant_id, email, reason, source, created_at"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(email)
        .bind(reason)
        .bind(source)
        .fetch_one(pool)
        .await
    }

/// Find suppression entry by email.
    pub async fn find_by_email(
        pool: &PgPool,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<Option<Suppression>, sqlx::Error> {
        sqlx::query_as::<_, Suppression>(
            "SELECT id, tenant_id, email, reason, source, created_at \
             FROM suppressions WHERE tenant_id = $1 AND email = $2"
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(pool)
        .await
    }

/// List suppressions for a tenant with pagination.
/// #221:Added limit/offset parameters to prevent unbounded queries
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Suppression>, sqlx::Error> {
        let limit = limit.clamp(1, 1000);
        let offset = offset.max(0);
        sqlx::query_as::<_, Suppression>(
            "SELECT id, tenant_id, email, reason, source, created_at \
             FROM suppressions WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

/// Remove an email from the suppression list.
    pub async fn delete(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM suppressions WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

/// Check whether an email is suppressed (fast boolean check).
    pub async fn is_suppressed(
        pool: &PgPool,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<bool, sqlx::Error> {
        let row: (bool,) = sqlx::query_as(
            "SELECT EXISTS(SELECT 1 FROM suppressions WHERE tenant_id = $1 AND email = $2)"
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_one(pool)
        .await?;
        Ok(row.0)
    }

/// Bulk-create suppressions (upsert).
    pub async fn bulk_create(
        pool: &PgPool,
        tenant_id: Uuid,
        entries: &[(&str, &str, &str)], // (email, reason, source)
    ) -> Result<Vec<Suppression>, sqlx::Error> {
// #213:Return early on empty input to avoid invalid SQL
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let mut query = String::from(
            "INSERT INTO suppressions (id, tenant_id, email, reason, source, created_at) VALUES "
        );
        let mut param_idx = 1u32;

        for (i, _) in entries.iter().enumerate() {
            if i > 0 {
                query.push_str(", ");
            }
            query.push_str(&format!(
                "(${}, ${}, ${}, ${}, ${}, NOW())",
                param_idx, param_idx + 1, param_idx + 2, param_idx + 3, param_idx + 4,
            ));
            param_idx += 5;
        }
        query.push_str(
            " ON CONFLICT (tenant_id, email) DO UPDATE SET reason = EXCLUDED.reason, source = EXCLUDED.source \
             RETURNING id, tenant_id, email, reason, source, created_at"
        );

        let mut q = sqlx::query_as::<_, Suppression>(&query);
        for (email, reason, source) in entries {
            q = q
                .bind(Uuid::new_v4())
                .bind(tenant_id)
                .bind(*email)
                .bind(*reason)
                .bind(*source);
        }

        q.fetch_all(pool).await
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Suppression;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_suppression_mock() {
        let s = Suppression {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "bounced@example.com".into(),
            reason: "hard_bounce".into(),
            source: "system".into(),
            created_at: Utc::now(),
        };
        assert_eq!(s.reason, "hard_bounce");
    }

    #[test]
    fn test_suppression_manual_source() {
        let s = Suppression {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "unsubscribed@example.com".into(),
            reason: "unsubscribe".into(),
            source: "manual".into(),
            created_at: Utc::now(),
        };
        assert_eq!(s.source, "manual");
    }

    #[test]
    fn test_suppressions_repo_is_stateless() {
        let _repo = super::SuppressionsRepo;
    }
}
