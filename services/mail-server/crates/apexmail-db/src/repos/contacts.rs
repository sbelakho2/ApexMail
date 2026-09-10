//! Contacts repository.
//!
//! Canonical shape (audit F07): `contacts.id` is UUID (migration 068),
//! `contacts.tags` is NOT NULL `'[]'::jsonb` (migration 150), and
//! `contacts.metadata` is object-or-NULL JSONB (migration 171). Ids are
//! `uuid::Uuid` end to end — parsed at the API boundary, bound as UUIDs,
//! stringified only in response DTOs. A `None` tag argument means "use the
//! canonical empty array" on create and "keep the stored value" on update,
//! so the NOT NULL column can never be violated through this repo.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use uuid::Uuid;

use crate::types::Contact;

/// Column list every reader in this repo selects — one canonical projection
/// including tags (coalesced to '[]' for pre-150 databases) and metadata.
const CONTACT_COLUMNS: &str =
    "id, tenant_id, email, name, COALESCE(tags, '[]'::jsonb) AS tags, metadata, status, created_at, updated_at";

/// Repository for contact operations.
pub struct ContactsRepo;

impl ContactsRepo {
    /// Create a new contact.
    pub async fn create(
        pool: &PgPool,
        tenant_id: &str,
        email: &str,
        name: Option<&str>,
        tags: Option<serde_json::Value>,
        metadata: Option<serde_json::Value>,
    ) -> Result<Contact, sqlx::Error> {
        sqlx::query_as::<_, Contact>(
            "INSERT INTO contacts (id, tenant_id, email, name, tags, metadata, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, COALESCE($5, '[]'::jsonb), $6, 'active', NOW(), NOW()) \
             RETURNING id, tenant_id, email, name, COALESCE(tags, '[]'::jsonb) AS tags, metadata, status, created_at, updated_at",
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
        tenant_id: &str,
        id: Uuid,
    ) -> Result<Option<Contact>, sqlx::Error> {
        sqlx::query_as::<_, Contact>(&format!(
            "SELECT {CONTACT_COLUMNS} \
             FROM contacts WHERE id = $1 AND tenant_id = $2",
        ))
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

    /// Find a contact by email.
    pub async fn find_by_email(
        pool: &PgPool,
        tenant_id: &str,
        email: &str,
    ) -> Result<Option<Contact>, sqlx::Error> {
        sqlx::query_as::<_, Contact>(&format!(
            "SELECT {CONTACT_COLUMNS} \
             FROM contacts WHERE tenant_id = $1 AND email = $2",
        ))
        .bind(tenant_id)
        .bind(email)
        .fetch_optional(pool)
        .await
    }

    /// List contacts for a tenant.
    pub async fn list(
        pool: &PgPool,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Contact>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        let offset = offset.clamp(0, 100_000);
        sqlx::query_as::<_, Contact>(&format!(
            "SELECT {CONTACT_COLUMNS} \
             FROM contacts WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        ))
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

    /// List contacts using keyset (cursor-based) pagination.
    ///
    /// This is an alternative to [`list()`] that avoids the OFFSET performance cliff.
    /// Instead of skipping rows, it uses `(created_at, id)` tuple comparison to find
    /// the starting point. The first page is requested by passing `None` for both
    /// cursor parameters. Subsequent pages pass the `created_at` and `id` from the
    /// last item of the previous page.
    ///
    /// Returns up to `limit + 1` rows so the caller can detect if there are more
    /// results (the extra row serves as the "has_more" indicator).
    pub async fn list_keyset(
        pool: &PgPool,
        tenant_id: &str,
        limit: i64,
        cursor_created_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
    ) -> Result<Vec<Contact>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        let fetch_limit = limit + 1; // +1 for has_more detection

        match (cursor_created_at, cursor_id) {
            (Some(created_at), Some(id)) => {
                sqlx::query_as::<_, Contact>(&format!(
                    "SELECT {CONTACT_COLUMNS} \
                     FROM contacts WHERE tenant_id = $1 AND (created_at, id) < ($2, $3) \
                     ORDER BY created_at DESC, id DESC LIMIT $4",
                ))
                .bind(tenant_id)
                .bind(created_at)
                .bind(id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
            _ => {
                // First page — no cursor
                sqlx::query_as::<_, Contact>(&format!(
                    "SELECT {CONTACT_COLUMNS} \
                     FROM contacts WHERE tenant_id = $1 \
                     ORDER BY created_at DESC, id DESC LIMIT $2",
                ))
                .bind(tenant_id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Update a contact.
    ///
    /// `None` tags/metadata keep the stored values (the canonical columns
    /// are NOT NULL tags / object-or-NULL metadata — a SQL NULL write would
    /// violate the contract, so absent means unchanged).
    pub async fn update(
        pool: &PgPool,
        tenant_id: &str,
        id: Uuid,
        name: Option<&str>,
        tags: Option<serde_json::Value>,
        metadata: Option<serde_json::Value>,
        status: &str,
    ) -> Result<Option<Contact>, sqlx::Error> {
        sqlx::query_as::<_, Contact>(
            "UPDATE contacts SET name = COALESCE($1, contacts.name), \
                 tags = COALESCE($2, contacts.tags), \
                 metadata = COALESCE($3, contacts.metadata), \
                 status = $4, updated_at = NOW() \
             WHERE id = $5 AND tenant_id = $6 \
             RETURNING id, tenant_id, email, name, COALESCE(tags, '[]'::jsonb) AS tags, metadata, status, created_at, updated_at",
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
    pub async fn delete(pool: &PgPool, tenant_id: &str, id: Uuid) -> Result<bool, sqlx::Error> {
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
        tenant_id: &str,
        entries: &[(&str, Option<&str>)], // (email, name)
    ) -> Result<Vec<Contact>, sqlx::Error> {
        // #214:Return early on empty input to avoid invalid SQL
        if entries.is_empty() {
            return Ok(Vec::new());
        }

        // 4 bind params per row would exceed Postgres' 65,535-parameter
        // statement limit above ~16,383 rows — insert in chunks instead of
        // failing (or being unusable) on large imports.
        const PARAMS_PER_ROW: usize = 4;
        const MAX_BINDS: usize = 65_535;
        let chunk_size = MAX_BINDS / PARAMS_PER_ROW;

        let mut all = Vec::with_capacity(entries.len());
        for chunk in entries.chunks(chunk_size) {
            let mut query = String::from(
                "INSERT INTO contacts (id, tenant_id, email, name, status, created_at, updated_at) VALUES "
            );
            let mut param_idx = 1u32;

            for (i, _) in chunk.iter().enumerate() {
                if i > 0 {
                    query.push_str(", ");
                }
                query.push_str(&format!(
                    "(${}, ${}, ${}, ${}, 'active', NOW(), NOW())",
                    param_idx,
                    param_idx + 1,
                    param_idx + 2,
                    param_idx + 3,
                ));
                param_idx += 4;
            }
            query.push_str(" ON CONFLICT (tenant_id, email) DO NOTHING RETURNING id, tenant_id, email, name, COALESCE(tags, '[]'::jsonb) AS tags, metadata, status, created_at, updated_at");

            let mut q = sqlx::query_as::<_, Contact>(&query);
            for (email, name) in chunk {
                q = q
                    .bind(Uuid::new_v4())
                    .bind(tenant_id)
                    .bind(*email)
                    .bind(*name);
            }

            all.extend(q.fetch_all(pool).await?);
        }
        Ok(all)
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
            tenant_id: crate::types::short_id('t'),
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
            tenant_id: crate::types::short_id('t'),
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
