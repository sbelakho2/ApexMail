//! Domains repository.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use thiserror::Error;
use uuid::Uuid;

use crate::types::Domain;

#[derive(Debug, Error)]
pub enum DomainRepoError {
    #[error(transparent)]
    Database(#[from] sqlx::Error),
    #[error(transparent)]
    Dkim(#[from] apexmail_lib::dkim::DkimKeyError),
    #[error("invalid domain name")]
    InvalidDomainName,
    #[error("the repository cannot mark a domain verified; use the DNS and transport readiness verifier")]
    UnsafeVerificationTransition,
}

/// Repository for domain operations.
pub struct DomainsRepo;

impl DomainsRepo {
    /// Create a pending domain with its complete per-domain signing material.
    ///
    /// The private key is encrypted before it reaches the database. This path
    /// intentionally fails closed when the shared DKIM encryption key is not
    /// configured, rather than creating a row the worker can never sign for.
    pub async fn create(
        pool: &PgPool,
        tenant_id: &str,
        name: &str,
    ) -> Result<Domain, DomainRepoError> {
        let name = name.trim().trim_end_matches('.').to_ascii_lowercase();
        if !apexmail_lib::validation::is_valid_domain(&name) {
            return Err(DomainRepoError::InvalidDomainName);
        }

        let id = Uuid::new_v4();
        let selector = format!("am-{}", Uuid::new_v4().simple());
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair()?;
        let aad = apexmail_lib::dkim::dkim_private_key_aad(tenant_id, &id.to_string());
        let encrypted_private_key =
            apexmail_lib::dkim::encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)?;

        sqlx::query_as::<_, Domain>(
            "INSERT INTO domains (id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified, \
             return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified, dkim_selector, dkim_public_key, \
             dkim_private_key, dkim_enabled, ses_verified, verified, created_at, updated_at) \
             VALUES ($1, $2, $3, 'pending', false, false, false, false, false, false, false, $4, $5, $6, true, false, false, NOW(), NOW()) \
             RETURNING id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified, \
                      return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified, \
                      dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled, ses_verified, created_at, updated_at"
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&name)
        .bind(&selector)
        .bind(&key_pair.public_key)
        .bind(&encrypted_private_key)
        .fetch_one(pool)
        .await
        .map_err(Into::into)
    }

    /// Find a domain by ID (scoped to tenant).
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<Domain>, sqlx::Error> {
        sqlx::query_as::<_, Domain>(
            "SELECT id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified, \
             return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified, \
             dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled, ses_verified, created_at, updated_at \
             FROM domains WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a domain by name across all tenants (for inbound routing).
    pub async fn find_by_name(pool: &PgPool, name: &str) -> Result<Option<Domain>, sqlx::Error> {
        sqlx::query_as::<_, Domain>(
            "SELECT id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified, \
             return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified, \
             dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled, ses_verified, created_at, updated_at \
             FROM domains WHERE name = $1",
        )
        .bind(name)
        .fetch_optional(pool)
        .await
    }

    /// List domains for a tenant with pagination.
    /// #227:Added limit/offset parameters
    pub async fn list(
        pool: &PgPool,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Domain>, sqlx::Error> {
        let limit = limit.clamp(1, 100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Domain>(
            "SELECT id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified, \
             return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified, \
             dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled, ses_verified, created_at, updated_at \
             FROM domains WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List domains for a tenant using keyset (cursor-based) pagination.
    /// Uses `(created_at, id)` tuple comparison for stable, efficient pagination.
    pub async fn list_keyset(
        pool: &PgPool,
        tenant_id: &str,
        limit: i64,
        cursor_created_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
    ) -> Result<Vec<Domain>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        let fetch_limit = limit + 1;
        match (cursor_created_at, cursor_id) {
            (Some(created_at), Some(id)) => sqlx::query_as::<_, Domain>(
                "SELECT id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified, \
                     return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified, \
                     dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled, ses_verified, created_at, updated_at \
                     FROM domains WHERE tenant_id = $1 AND (created_at, id) < ($2, $3) \
                     ORDER BY created_at DESC, id DESC LIMIT $4",
            )
            .bind(tenant_id)
            .bind(created_at)
            .bind(id)
            .bind(fetch_limit)
            .fetch_all(pool)
            .await,
            _ => {
                // First page — no cursor
                sqlx::query_as::<_, Domain>(
                    "SELECT id, tenant_id, name, status, spf_verified, dkim_verified, dmarc_verified, \
                     return_path_verified, mta_sts_verified, bimi_verified, tlsrpt_verified, \
                     dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled, ses_verified, created_at, updated_at \
                     FROM domains WHERE tenant_id = $1 \
                     ORDER BY created_at DESC, id DESC LIMIT $2"
                )
                .bind(tenant_id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Record DNS check observations without bypassing the active sender
    /// readiness verifier. This repository has no DNS, SES, or key-match
    /// context and therefore cannot safely mark a domain as verified.
    pub async fn record_dns_check(
        pool: &PgPool,
        tenant_id: &str,
        id: Uuid,
        spf: bool,
        dkim: bool,
        dmarc: bool,
    ) -> Result<bool, DomainRepoError> {
        let result = sqlx::query(
            "UPDATE domains SET status = 'pending', verified = false, ses_verified = false, \
             spf_verified = $1, dkim_verified = $2, dmarc_verified = $3, updated_at = NOW() \
             WHERE id = $4 AND tenant_id = $5"
        )
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
    pub async fn delete(pool: &PgPool, tenant_id: &str, id: Uuid) -> Result<bool, sqlx::Error> {
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
            tenant_id: "tenant_test_00000000000001".into(),
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
            dkim_enabled: false,
            ses_verified: false,
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
            tenant_id: "tenant_test_00000000000001".into(),
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
            dkim_private_key: Some("dkim:v1:encrypted-test-envelope".into()),
            dkim_enabled: true,
            ses_verified: false,
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
