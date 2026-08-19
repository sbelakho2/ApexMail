//! Internal system-mail sender readiness and queueing.
//!
//! Authentication and account-recovery messages are sent from the platform's
//! own domain. They must use the same per-domain DKIM readiness rules as tenant
//! mail, rather than bypassing them with a global key or an unsigned fallback.

use apexmail_lib::dkim::{
    decrypt_dkim_private_key, dkim_private_key_aad, dkim_public_keys_match,
    is_encrypted_dkim_private_key, public_key_base64_from_private_key_pem,
};
use sqlx::{PgPool, Postgres};
use uuid::Uuid;

use crate::config::Config;
use crate::error::ApiError;

pub const SYSTEM_TENANT_ID: &str = "system_internal_tenant01";
pub const SYSTEM_DOMAIN: &str = "apexmail.ee";
pub const SYSTEM_DOMAIN_ID: &str = "00000000-0000-0000-0000-0000000000d1";
pub const SYSTEM_FROM_ADDRESS: &str = "noreply@apexmail.ee";

#[derive(sqlx::FromRow)]
struct SystemSenderRow {
    id: String,
    tenant_id: String,
    dkim_selector: Option<String>,
    dkim_public_key: Option<String>,
    dkim_private_key: Option<String>,
}

fn not_ready_error() -> ApiError {
    ApiError::ServiceUnavailable(
        "system email delivery is unavailable because the ApexMail sender domain is not ready"
            .into(),
    )
}

fn validate_system_sender_material(row: &SystemSenderRow) -> Result<(), ApiError> {
    let selector = row
        .dkim_selector
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(not_ready_error)?;
    if selector.len() > 63
        || selector.starts_with('-')
        || selector.ends_with('-')
        || !selector
            .bytes()
            .all(|byte| byte.is_ascii_lowercase() || byte.is_ascii_digit() || byte == b'-')
    {
        return Err(not_ready_error());
    }

    let public_key = row
        .dkim_public_key
        .as_deref()
        .filter(|value| !value.trim().is_empty())
        .ok_or_else(not_ready_error)?;
    let encrypted_private_key = row
        .dkim_private_key
        .as_deref()
        .filter(|value| is_encrypted_dkim_private_key(value))
        .ok_or_else(not_ready_error)?;
    let aad = dkim_private_key_aad(&row.tenant_id, &row.id);
    let private_key = decrypt_dkim_private_key(encrypted_private_key, &aad)
        .map_err(|_| not_ready_error())?;
    let derived_public_key = public_key_base64_from_private_key_pem(&private_key)
        .map_err(|_| not_ready_error())?;

    if !dkim_public_keys_match(public_key, &derived_public_key) {
        return Err(not_ready_error());
    }

    Ok(())
}

async fn fetch_system_sender(
    executor: impl sqlx::Executor<'_, Database = Postgres>,
    for_share: bool,
) -> Result<SystemSenderRow, ApiError> {
    let requires_ses = Config::ses_transport_enabled();
    let lock_clause = if for_share { " FOR SHARE" } else { "" };
    let query = format!(
        "SELECT id::text AS id, tenant_id::text AS tenant_id, dkim_selector, \
                dkim_public_key, dkim_private_key \
         FROM domains \
         WHERE tenant_id = $1 AND name = $2 \
           AND status = 'verified' \
           AND dkim_enabled = true \
           AND dkim_selector IS NOT NULL \
           AND dkim_public_key IS NOT NULL \
           AND dkim_private_key IS NOT NULL \
           AND dkim_private_key LIKE 'dkim:v1:%' \
           AND ($3::boolean = false OR ses_verified = true)\
         {lock_clause}",
    );

    let row = sqlx::query_as::<_, SystemSenderRow>(&query)
        .bind(SYSTEM_TENANT_ID)
        .bind(SYSTEM_DOMAIN)
        .bind(requires_ses)
        .fetch_optional(executor)
        .await?
        .ok_or_else(not_ready_error)?;

    validate_system_sender_material(&row)?;
    Ok(row)
}

/// Reject a request before it mutates account state when a required system
/// email cannot be delivered. Queueing performs this check again under a share
/// lock so a concurrent domain revoke cannot create a doomed message.
pub(crate) async fn ensure_system_sender_ready(db: &PgPool) -> Result<(), ApiError> {
    fetch_system_sender(db, false).await.map(|_| ())
}

/// Atomically persist the message audit row and worker queue row after proving
/// that the system sender is currently authorized for the selected transport.
pub(crate) async fn queue_system_email(
    db: &PgPool,
    recipient: &str,
    subject: &str,
    html_body: &str,
    text_body: &str,
    tags: Vec<String>,
) -> Result<Uuid, ApiError> {
    let mut tx = db.begin().await?;
    let message_id = queue_system_email_in_transaction(
        &mut tx,
        recipient,
        subject,
        html_body,
        text_body,
        tags,
    )
    .await?;
    tx.commit().await?;
    Ok(message_id)
}

/// Queue a platform email within an existing transaction. Callers that first
/// mutate account state (such as issuing a password-reset token) must use this
/// helper so the state transition and deliverable message either commit
/// together or both roll back.
pub(crate) async fn queue_system_email_in_transaction(
    tx: &mut sqlx::Transaction<'_, Postgres>,
    recipient: &str,
    subject: &str,
    html_body: &str,
    text_body: &str,
    tags: Vec<String>,
) -> Result<Uuid, ApiError> {
    let sender = fetch_system_sender(&mut **tx, true).await?;
    let message_id = Uuid::new_v4();
    let now = chrono::Utc::now();

    sqlx::query(
        "INSERT INTO messages (id, tenant_id, from_email, to_emails, subject, html_body, text_body, status, tags, created_at) \
         VALUES ($1, $2, $3, $4::jsonb, $5, $6, $7, 'queued', $8::jsonb, NOW())",
    )
    .bind(message_id)
    .bind(SYSTEM_TENANT_ID)
    .bind(SYSTEM_FROM_ADDRESS)
    .bind(serde_json::json!([recipient]))
    .bind(subject)
    .bind(html_body)
    .bind(text_body)
    .bind(serde_json::json!(tags))
    .execute(&mut **tx)
    .await?;

    sqlx::query(
        "INSERT INTO email_queue (\
            id, message_id, tenant_id, domain_id, from_address, to_addresses, subject, \
            \"from\", \"to\", html, text, tags, metadata, scheduled_at, priority, status, created_at, updated_at\
         ) VALUES (\
            $1, $2, $3, $4::uuid, $5, ARRAY[$6], $7, \
            $5, $6, $8, $9, $10, $11, $12, 5, 'pending', $13, $13\
         )",
    )
    .bind(Uuid::new_v4())
    .bind(message_id)
    .bind(SYSTEM_TENANT_ID)
    .bind(&sender.id)
    .bind(SYSTEM_FROM_ADDRESS)
    .bind(recipient)
    .bind(subject)
    .bind(html_body)
    .bind(text_body)
    .bind(tags)
    .bind(Option::<serde_json::Value>::None)
    .bind(Option::<chrono::DateTime<chrono::Utc>>::None)
    .bind(now)
    .execute(&mut **tx)
    .await?;

    Ok(message_id)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn platform_sender_identity_is_consistent() {
        assert_eq!(SYSTEM_FROM_ADDRESS.rsplit_once('@').unwrap().1, SYSTEM_DOMAIN);
        assert_eq!(SYSTEM_TENANT_ID, "system_internal_tenant01");
        assert_eq!(SYSTEM_DOMAIN_ID, "00000000-0000-0000-0000-0000000000d1");
    }

    #[test]
    fn malformed_selector_is_not_ready() {
        let row = SystemSenderRow {
            id: Uuid::nil().to_string(),
            tenant_id: SYSTEM_TENANT_ID.into(),
            dkim_selector: Some("not a selector".into()),
            dkim_public_key: Some("public".into()),
            dkim_private_key: Some("dkim:v1:encrypted".into()),
        };

        assert!(validate_system_sender_material(&row).is_err());
    }
}
