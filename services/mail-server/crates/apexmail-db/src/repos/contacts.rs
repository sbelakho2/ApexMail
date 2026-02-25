//! Contacts repository.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::Contact;

/// Repository for contact operations.
pub struct ContactsRepo;

impl ContactsRepo {
    /// Create a new contact.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        email: &str,
        name: Option<&str>,
        tags: Option<serde_json::Value>,
        metadata: Option<serde_json::Value>,
    ) -> Result<Contact, sqlx::Error> {
        sqlx::query_as::<_, Contact>(
            "INSERT INTO contacts (id, tenant_id, email, name, tags, metadata, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 'active', NOW(), NOW()) \
             RETURNING *"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(email)
        .bind(name)
        .bind(tags)
        .bind(metadata)
        .fetch_one(pool)
        .await
    }

    /// Find a contact by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Contact>, sqlx::Error> {
        sqlx::query_as::<_, Contact>(
            "SELECT * FROM contacts WHERE id = $1 AND tenant_id = $2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a contact by email.
    pub async fn find_by_email(
        pool: &PgPool,
        tenant_id: Uuid,
        email: &str,
    ) -> Result<Option<Contact>, sqlx::Error> {
        sqlx::query_as::<_, Contact>(
            "SELECT * FROM contacts WHERE tenant_id = $1 AND email = $2"
        )
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    /// List contacts for a tenant.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Contact>, sqlx::Error> {
        sqlx::query_as::<_, Contact>(
            "SELECT * FROM contacts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// Update a contact.
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        name: Option<&str>,
        tags: Option<serde_json::Value>,
        metadata: Option<serde_json::Value>,
        status: &str,
    ) -> Result<Option<Contact>, sqlx::Error> {
        sqlx::query_as::<_, Contact>(
            "UPDATE contacts SET name = $1, tags = $2, metadata = $3, status = $4, updated_at = NOW() \
             WHERE id = $5 AND tenant_id = $6 RETURNING *"
        )
        .bind(name)
        .bind(tags)
        .bind(metadata)
        .bind(status)
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Delete a contact.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM contacts WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Bulk-create contacts (skip conflicts on email within tenant).
    pub async fn bulk_create(
        pool: &PgPool,
        tenant_id: Uuid,
        entries: &[(&str, Option<&str>)], // (email, name)
    ) -> Result<Vec<Contact>, sqlx::Error> {
        // #214: Return early on empty input to avoid invalid SQL
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        let mut query = String::from(
            "INSERT INTO contacts (id, tenant_id, email, name, status, created_at, updated_at) VALUES "
        );
        let mut param_idx = 1u32;

        for (i, _) in entries.iter().enumerate() {
            if i > 0 {
                query.push_str(", ");
            }
            query.push_str(&format!(
                "(${}, ${}, ${}, ${}, 'active', NOW(), NOW())",
                param_idx, param_idx + 1, param_idx + 2, param_idx + 3,
            ));
            param_idx += 4;
        }
        query.push_str(
            " ON CONFLICT (tenant_id, email) DO NOTHING RETURNING *"
        );

        let mut q = sqlx::query_as::<_, Contact>(&query);
        for (email, name) in entries {
            q = q
                .bind(Uuid::new_v4())
                .bind(tenant_id)
                .bind(*email)
                .bind(*name);
        }

        q.fetch_all(pool).await
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Contact;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_contact_mock() {
        let c = Contact {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "alice@example.com".into(),
            name: Some("Alice".into()),
            tags: Some(serde_json::json!(["vip", "enterprise"])),
            metadata: None,
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(c.email, "alice@example.com");
        assert_eq!(c.tags.unwrap().as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_contact_minimal() {
        let c = Contact {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            email: "bob@example.com".into(),
            name: None,
            tags: None,
            metadata: None,
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert!(c.name.is_none());
    }

    #[test]
    fn test_contacts_repo_is_stateless() {
        let _repo = super::ContactsRepo;
    }
}
