//! Tenants repository.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::Tenant;

/// Repository for tenant operations.
pub struct TenantsRepo;

impl TenantsRepo {
/// Create a new tenant.
    pub async fn create(
        pool: &PgPool,
        name: &str,
        slug: &str,
        plan: &str,
    ) -> Result<Tenant, sqlx::Error> {
        sqlx::query_as::<_, Tenant>(
            "INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, 'active', NOW(), NOW()) \
             RETURNING id, name, slug, plan, status, created_at, updated_at"
        )
        .bind(Uuid::new_v4())
        .bind(name)
        .bind(slug)
        .bind(plan)
        .fetch_one(pool)
        .await
    }

/// Find a tenant by ID.
    pub async fn find_by_id(pool: &PgPool, id: Uuid) -> Result<Option<Tenant>, sqlx::Error> {
        sqlx::query_as::<_, Tenant>(
            "SELECT id, name, slug, plan, status, created_at, updated_at FROM tenants WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(pool)
        .await
    }

/// Find a tenant by slug.
    pub async fn find_by_slug(pool: &PgPool, slug: &str) -> Result<Option<Tenant>, sqlx::Error> {
        sqlx::query_as::<_, Tenant>(
            "SELECT id, name, slug, plan, status, created_at, updated_at FROM tenants WHERE slug = $1"
        )
        .bind(slug)
        .fetch_optional(pool)
        .await
    }

/// Update tenant details.
    pub async fn update(
        pool: &PgPool,
        id: Uuid,
        name: &str,
        plan: &str,
        status: &str,
    ) -> Result<Option<Tenant>, sqlx::Error> {
        sqlx::query_as::<_, Tenant>(
            "UPDATE tenants SET name = $1, plan = $2, status = $3, updated_at = NOW() \
             WHERE id = $4 \
             RETURNING id, name, slug, plan, status, created_at, updated_at"
        )
        .bind(name)
        .bind(plan)
        .bind(status)
        .bind(id)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Tenant;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_tenant_mock() {
        let t = Tenant {
            id: Uuid::new_v4(),
            name: "Acme Inc".into(),
            slug: "acme-inc".into(),
            plan: "pro".into(),
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(t.plan, "pro");
        assert_eq!(t.status, "active");
    }

    #[test]
    fn test_tenant_slug_format() {
        let slug = "my-company";
        assert!(slug.chars().all(|c| c.is_alphanumeric() || c == '-'));
    }

    #[test]
    fn test_tenants_repo_is_stateless() {
        let _repo = super::TenantsRepo;
    }
}
