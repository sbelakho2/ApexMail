//! Messages repository.

use chrono::{DateTime, Utc};
use sqlx::{PgPool, Postgres, QueryBuilder};
use uuid::Uuid;

use crate::types::Message;

/// Repository for message operations.
pub struct MessagesRepo;

impl MessagesRepo {
    /// Create a new message.
    #[allow(clippy::too_many_arguments)]
    pub async fn create(
        pool: &PgPool,
        tenant_id: Uuid,
        from_email: &str,
        to_emails: serde_json::Value,
        cc_emails: Option<serde_json::Value>,
        bcc_emails: Option<serde_json::Value>,
        subject: &str,
        html_body: Option<&str>,
        text_body: Option<&str>,
        tags: Option<serde_json::Value>,
        metadata: Option<serde_json::Value>,
        scheduled_at: Option<chrono::DateTime<chrono::Utc>>,
    ) -> Result<Message, sqlx::Error> {
        sqlx::query_as::<_, Message>(
            "INSERT INTO messages \
             (id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, html_body, text_body, \
              status, tags, metadata, scheduled_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, 'queued', $10, $11, $12, NOW()) \
             RETURNING id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, html_body, text_body, status, tags, metadata, scheduled_at, sent_at, created_at"
        )
        .bind(Uuid::new_v4())
        .bind(tenant_id)
        .bind(from_email)
        .bind(to_emails)
        .bind(cc_emails)
        .bind(bcc_emails)
        .bind(subject)
        .bind(html_body)
        .bind(text_body)
        .bind(tags)
        .bind(metadata)
        .bind(scheduled_at)
        .fetch_one(pool)
        .await
    }

    /// Find a message by ID (scoped to tenant).
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
    ) -> Result<Option<Message>, sqlx::Error> {
        sqlx::query_as::<_, Message>(
            "SELECT id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, html_body, text_body, \
             status, tags, metadata, scheduled_at, sent_at, created_at \
             FROM messages WHERE id = $1 AND tenant_id = $2"
        )
            .bind(id)
            .bind(tenant_id)
            .fetch_optional(pool)
            .await
    }

    /// List messages for a tenant with optional status filter and pagination.
    pub async fn list(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        offset: i64,
        status: Option<&str>,
    ) -> Result<Vec<Message>, sqlx::Error> {
        match status {
            Some(s) => {
                sqlx::query_as::<_, Message>(
                    "SELECT id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, html_body, text_body, \
                     status, tags, metadata, scheduled_at, sent_at, created_at \
                     FROM messages WHERE tenant_id = $1 AND status = $2 \
                     ORDER BY created_at DESC LIMIT $3 OFFSET $4",
                )
                .bind(tenant_id)
                .bind(s)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
            }
            None => {
                sqlx::query_as::<_, Message>(
                    "SELECT id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, html_body, text_body, \
                     status, tags, metadata, scheduled_at, sent_at, created_at \
                     FROM messages WHERE tenant_id = $1 \
                     ORDER BY created_at DESC LIMIT $2 OFFSET $3",
                )
                .bind(tenant_id)
                .bind(limit)
                .bind(offset)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// List messages for a tenant using keyset (cursor-based) pagination.
    /// Uses `(created_at, id)` tuple comparison for stable, efficient pagination.
    /// Returns up to `limit` rows; the caller should request `limit + 1` and use
    /// the extra row as a "has_more" indicator.
    pub async fn list_keyset(
        pool: &PgPool,
        tenant_id: Uuid,
        limit: i64,
        cursor_created_at: Option<DateTime<Utc>>,
        cursor_id: Option<Uuid>,
        status: Option<&str>,
    ) -> Result<Vec<Message>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        let fetch_limit = limit + 1;
        match (cursor_created_at, cursor_id, status) {
            (Some(created_at), Some(id), Some(s)) => {
                sqlx::query_as::<_, Message>(
                    "SELECT id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, html_body, text_body, \
                     status, tags, metadata, scheduled_at, sent_at, created_at \
                     FROM messages WHERE tenant_id = $1 AND status = $2 AND (created_at, id) < ($3, $4) \
                     ORDER BY created_at DESC, id DESC LIMIT $5",
                )
                .bind(tenant_id)
                .bind(s)
                .bind(created_at)
                .bind(id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
            (_, _, Some(s)) => {
                // First page with status filter — no cursor
                sqlx::query_as::<_, Message>(
                    "SELECT id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, html_body, text_body, \
                     status, tags, metadata, scheduled_at, sent_at, created_at \
                     FROM messages WHERE tenant_id = $1 AND status = $2 \
                     ORDER BY created_at DESC, id DESC LIMIT $3",
                )
                .bind(tenant_id)
                .bind(s)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
            (Some(created_at), Some(id), None) => {
                sqlx::query_as::<_, Message>(
                    "SELECT id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, html_body, text_body, \
                     status, tags, metadata, scheduled_at, sent_at, created_at \
                     FROM messages WHERE tenant_id = $1 AND (created_at, id) < ($2, $3) \
                     ORDER BY created_at DESC, id DESC LIMIT $4",
                )
                .bind(tenant_id)
                .bind(created_at)
                .bind(id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
            _ => {
                // First page without status filter — no cursor
                sqlx::query_as::<_, Message>(
                    "SELECT id, tenant_id, from_email, to_emails, cc_emails, bcc_emails, subject, html_body, text_body, \
                     status, tags, metadata, scheduled_at, sent_at, created_at \
                     FROM messages WHERE tenant_id = $1 \
                     ORDER BY created_at DESC, id DESC LIMIT $2",
                )
                .bind(tenant_id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await
            }
        }
    }

    /// Update message status.
    pub async fn update_status(
        pool: &PgPool,
        tenant_id: Uuid,
        id: Uuid,
        status: &str,
    ) -> Result<bool, sqlx::Error> {
        let result =
            sqlx::query("UPDATE messages SET status = $1 WHERE id = $2 AND tenant_id = $3")
                .bind(status)
                .bind(id)
                .bind(tenant_id)
                .execute(pool)
                .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Cancel a queued or scheduled message.
    pub async fn cancel(pool: &PgPool, tenant_id: Uuid, id: Uuid) -> Result<bool, sqlx::Error> {
        let result = sqlx::query(
            "UPDATE messages SET status = 'cancelled' \
             WHERE id = $1 AND tenant_id = $2 AND status IN ('queued', 'scheduled')",
        )
        .bind(id)
        .bind(tenant_id)
        .execute(pool)
        .await?;
        Ok(result.rows_affected() > 0)
    }

    /// Batch-create multiple messages in a single INSERT.
    #[allow(clippy::type_complexity)]
    pub async fn batch_create(
        pool: &PgPool,
        tenant_id: Uuid,
        messages: &[(
            String,
            serde_json::Value,
            String,
            Option<String>,
            Option<String>,
        )],
    ) -> Result<Vec<Message>, sqlx::Error> {
        // #212:Return early on empty input to avoid invalid SQL
        if messages.is_empty() {
            return Ok(Vec::new());
        }

        let mut query_builder = QueryBuilder::<Postgres>::new(
            "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, created_at) ",
        );

        query_builder.push_values(messages, |mut builder, (from, to, subject, html, text)| {
            builder
                .push_bind(Uuid::new_v4())
                .push_bind(tenant_id)
                .push_bind(from.as_str())
                .push_bind(to.clone())
                .push_bind(subject.as_str())
                .push_bind(html.as_deref())
                .push_bind(text.as_deref())
                .push("'queued'")
                .push("NOW()");
        });
        query_builder.push(" RETURNING id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, created_at");

        query_builder
            .build_query_as::<Message>()
            .fetch_all(pool)
            .await
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Message;
    use chrono::Utc;
    use uuid::Uuid;

    #[test]
    fn test_message_mock_queued() {
        let m = Message {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            from_email: "noreply@example.com".into(),
            to_emails: serde_json::json!(["user@test.com"]),
            cc_emails: None,
            bcc_emails: None,
            subject: "Welcome".into(),
            html_body: Some("<h1>Hi</h1>".into()),
            text_body: None,
            status: "queued".into(),
            tags: None,
            metadata: None,
            scheduled_at: None,
            sent_at: None,
            created_at: Utc::now(),
        };
        assert_eq!(m.status, "queued");
    }

    #[test]
    fn test_message_with_tags() {
        let m = Message {
            id: Uuid::new_v4(),
            tenant_id: Uuid::new_v4(),
            from_email: "noreply@example.com".into(),
            to_emails: serde_json::json!(["a@b.com"]),
            cc_emails: None,
            bcc_emails: None,
            subject: "Update".into(),
            html_body: None,
            text_body: Some("plain".into()),
            status: "sent".into(),
            tags: Some(serde_json::json!(["onboarding", "transactional"])),
            metadata: Some(serde_json::json!({"campaign": "welcome"})),
            scheduled_at: None,
            sent_at: Some(Utc::now()),
            created_at: Utc::now(),
        };
        let tags = m.tags.unwrap();
        assert_eq!(tags.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_messages_repo_is_stateless() {
        let _repo = super::MessagesRepo;
    }
}
