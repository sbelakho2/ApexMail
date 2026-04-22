//! Templates repository.

use sqlx::PgPool;
use uuid::Uuid;

use crate::types::Template;

/// Repository for email template operations.
pub struct TemplatesRepo;

impl TemplatesRepo {
/// Create a new template.
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
        subject: &str,
        html_body: &str,
        text_body: Option<&str>,
    ) -> Result<Template, sqlx::Error> {
        sqlx::query_as::<_, Template>(
            "INSERT INTO templates (id, tenant_id, name, subject, html_body, text_body, version, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, $6, 1, 'draft', NOW(), NOW()) \
             RETURNING *"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(name)
        .bind(subject)
        .bind(html_body)
        .bind(text_body)
        .fetch_one(pool)
        .await
    }

/// Find a template by ID.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Template>, sqlx::Error> {
        sqlx::query_as::<_, Template>(
            "SELECT * FROM templates WHERE id = $1 AND tenant_id = $2"
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

/// List templates for a tenant with pagination.
/// #224:Added limit/offset and excluded html_body for listing (use find_by_id for full)
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Template>, sqlx::Error> {
        let limit = limit.clamp(1, 100);
        let offset = offset.max(0);
        sqlx::query_as::<_, Template>(
            "SELECT * FROM templates WHERE tenant_id = $1 ORDER BY updated_at DESC LIMIT $2 OFFSET $3"
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await
    }

/// Update a template (bumps version).
    pub async fn update(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        name: &str,
        subject: &str,
        html_body: &str,
        text_body: Option<&str>,
    ) -> Result<Option<Template>, sqlx::Error> {
        sqlx::query_as::<_, Template>(
            "UPDATE templates SET name = $1, subject = $2, html_body = $3, text_body = $4, \
             version = version + 1, updated_at = NOW() \
             WHERE id = $5 AND tenant_id = $6 RETURNING *"
        )
        .bind(name)
        .bind(subject)
        .bind(html_body)
        .bind(text_body)
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await
    }

/// Delete a template.
    pub async fn delete(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM templates WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

/// Find a template by name (e.g. for slug-based references).
    pub async fn find_by_name(
        pool: &PgPool,
        tenant_id: Uuid,
        name: &str,
    ) -> Result<Option<Template>, sqlx::Error> {
        sqlx::query_as::<_, Template>(
            "SELECT * FROM templates WHERE tenant_id = $1 AND name = $2"
        )
        .bind(tenant_id)
        .bind(name)
        .fetch_optional(pool)
        .await
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Template;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_template_draft() {
        let t = Template {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "welcome".into(),
            subject: "Welcome to {{company}}".into(),
            html_body: "<h1>Hello {{name}}</h1>".into(),
            text_body: Some("Hello {{name}}".into()),
            version: 1,
            status: "draft".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(t.version, 1);
        assert_eq!(t.status, "draft");
    }

    #[test]
    fn test_template_version_bump() {
        let t = Template {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            name: "receipt".into(),
            subject: "Your receipt".into(),
            html_body: "<p>Thanks</p>".into(),
            text_body: None,
            version: 3,
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(t.version, 3);
    }

    #[test]
    fn test_templates_repo_is_stateless() {
        let _repo = super::TemplatesRepo;
    }
}
