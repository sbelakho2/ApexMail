//! Domains repository.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::Domain;

/// Repository for domain operations.
pub struct DomainsRepo;

impl DomainsRepo {
    /// Create a new domain for a tenant.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Domain, sqlx::Error> {
        sqlx::query_as::<_, Domain>(
            "INSERT INTO domains (id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified, \
             return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified, created_at, updated_at) \
             VALUES ($1, $2, $3, 'pending', false, false, false, false, false, false, false, NOW(), NOW()) \
             RETURNING *"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(name)
        .fetch_one(pool)
        .await
    }

    /// Find a domain by ID (scoped to tenant).
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Domain>, sqlx::Error> {
        sqlx::query_as::<_, Domain>(
            "SELECT * FROM domains WHERE id = $1 AND tenant_id = $2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a domain by name across all tenants (for inbound routing).
    pub async fn find_by_name(pool: &PgPool, name: &str) -> Result<Option<Domain>, sqlx::Error> {
        sqlx::query_as::<_, Domain>(
            "SELECT * FROM domains WHERE name = $1"
        )
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List domains for a tenant with pagination.
    /// #227: Added limit/offset parameters
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Domain>, sqlx::Error> {
        let limit = limit.clamp(1, 100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Domain>(
            "SELECT * FROM domains WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Update domain verification status.
    pub async fn update_verification(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
        spf: bool,
        dkim: bool,
        dmarc: bool,
    ) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE domains SET status = $1, spf_verified = $2, dkim_verified = $3, dmarc_verified = $4, \
             updated_at = NOW() WHERE id = $5 AND tenant_id = $6"
        )
        .bind(status)
        .bind(spf)
        .bind(dkim)
        .bind(dmarc)
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Delete a domain.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM domains WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Domain;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_domain_mock_pending() {
        let d = Domain {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "mail.example.com".into(),
            status: "pending".into(),
            spf_verified: false,
            dkim_verified: false,
            dmarc_verified: false,
            return_path_verified: false,
            mta_sts_verified: false,
            bimi_verified: false,
            tlsrpt_verified: false,
            dkim_selector: None,
            dkim_public_key: None,
            dkim_private_key: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(d.status, "pending");
        assert!(!d.spf_verified);
    }

    #[test]
    fn test_domain_mock_verified() {
        let d = Domain {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "example.com".into(),
            status: "verified".into(),
            spf_verified: true,
            dkim_verified: true,
            dmarc_verified: true,
            return_path_verified: true,
            mta_sts_verified: false,
            bimi_verified: false,
            tlsrpt_verified: false,
            dkim_selector: Some("apexmail".into()),
            dkim_public_key: Some("pk_abc".into()),
            dkim_private_key: None,
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(d.status, "verified");
        assert!(d.spf_verified && d.dkim_verified && d.dmarc_verified);
    }

    #[test]
    fn test_domains_repo_is_stateless() {
        let _repo = super::DomainsRepo;
    }
}
