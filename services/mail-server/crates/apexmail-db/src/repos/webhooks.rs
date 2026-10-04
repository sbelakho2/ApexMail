//! Webhooks repository.
//!
//! # Signing-secret handling (audit F4)
//!
//! The webhook signing secret is a credential: anyone holding it can forge
//! delivery callbacks the tenant will trust. It is therefore stored
//! ENCRYPTED AT REST via `apexmail_lib::secret_at_rest` (AES-256-GCM,
//! AAD = `webhook={id}` so a ciphertext cannot be relocated between rows)
//! and never projected in full by the list/find reads:
//!
//! * [`WebhooksRepo::create`] encrypts before the INSERT (production fails
//!   closed when no at-rest key is configured);
//! * [`WebhooksRepo::find_by_id`], [`WebhooksRepo::list`],
//!   [`WebhooksRepo::list_keyset`], [`WebhooksRepo::list_by_event_type`] and
//!   [`WebhooksRepo::update`] project only a MASKED PREFIX of the secret
//!   into [`crate::types::Webhook::secret`];
//! * legacy plaintext rows are migrated to envelopes on read;
//! * [`WebhooksRepo::secret_for_signing`] is the single authorized fetch
//!   returning the plaintext — for the outbound-signing path only.

use chrono::{DateTime, Utc};
use sqlx::PgPool;

use crate::types::Webhook;

/// How many leading characters of a webhook secret are visible in the
/// masked projections (audit F4). Enough to correlate a row in a UI, far
/// short of the ~70-char generated secret's entropy.
const MASKED_PREFIX_CHARS: usize = 8;

/// The masked placeholder substituted for the hidden part of a secret.
const MASK_TAIL: &str = "…";

/// AAD scope binding for a webhook secret: ties the ciphertext to its row
/// so envelopes cannot be swapped between webhooks.
fn webhook_aad(webhook_id: &str) -> Vec<u8> {
    format!("webhook={webhook_id}").into_bytes()
}

/// Mask a plaintext secret down to its display prefix (audit F4).
///
/// Secrets no longer than the prefix length reveal nothing at all — a fixed
/// placeholder keeps even the length class from being obvious.
pub(crate) fn mask_secret(plaintext: &str) -> String {
    if plaintext.chars().count() > MASKED_PREFIX_CHARS {
        let prefix: String = plaintext.chars().take(MASKED_PREFIX_CHARS).collect();
        format!("{prefix}{MASK_TAIL}")
    } else {
        "••••••••".to_string()
    }
}

/// Map an at-rest secret error onto the repo's `sqlx::Error` surface,
/// failing closed (production with a missing key must never store
/// plaintext).
fn secret_error(error: apexmail_lib::secret_at_rest::SecretEncryptionError) -> sqlx::Error {
    sqlx::Error::Io(std::io::Error::new(
        std::io::ErrorKind::InvalidData,
        format!("webhook secret at-rest failure: {error}"),
    ))
}

/// Repository for webhook operations.
pub struct WebhooksRepo;

impl WebhooksRepo {
    /// Create a new webhook. `secret` is stored as an encrypted envelope
    /// (AAD = `webhook={id}`); the returned [`Webhook`] carries only the
    /// MASKED prefix — the caller already holds the plaintext it passed in.
    pub async fn create(
        pool: &PgPool,
        tenant_id: &str,
        url: &str,
        events: serde_json::Value,
        secret: &str,
    ) -> Result<Webhook, sqlx::Error> {
        let id = crate::types::short_id('w');
        let stored = apexmail_lib::secret_at_rest::encrypt_at_rest(secret, &webhook_aad(&id))
            .map_err(secret_error)?;
        let webhook = sqlx::query_as::<_, Webhook>(
            "INSERT INTO webhooks (id, tenant_id, url, events, secret, status, created_at, updated_at) \
             VALUES ($1, $2, $3, $4, $5, 'active', NOW(), NOW()) \
             RETURNING id, tenant_id, url, events, secret, status, created_at, updated_at"
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(url)
        .bind(events)
        .bind(stored)
        .fetch_one(pool)
        .await?;
        Ok(mask_webhook(&webhook))
    }

    /// Find a webhook by ID. The `secret` field is a masked prefix only.
    pub async fn find_by_id(
        pool: &PgPool,
        tenant_id: &str,
        id: &str,
    ) -> Result<Option<Webhook>, sqlx::Error> {
        let webhook = sqlx::query_as::<_, Webhook>(
            "SELECT id, tenant_id, url, events, secret, status, created_at, updated_at \
             FROM webhooks WHERE id = $1 AND tenant_id = $2",
        )
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;
        match webhook {
            Some(webhook) => {
                migrate_stored_secret(pool, &webhook).await?;
                Ok(Some(mask_webhook(&webhook)))
            }
            None => Ok(None),
        }
    }

    /// THE authorized plaintext fetch (audit F4): decrypts the stored
    /// envelope for the outbound-signing path. Scoped by tenant like every
    /// other read; a tampered or wrong-AAD envelope fails closed.
    ///
    /// Legacy plaintext rows are transparently decrypted and migrated to an
    /// envelope (best-effort: a failed rewrite is logged, not fatal).
    pub async fn secret_for_signing(
        pool: &PgPool,
        tenant_id: &str,
        id: &str,
    ) -> Result<Option<String>, sqlx::Error> {
        let stored: Option<String> =
            sqlx::query_scalar("SELECT secret FROM webhooks WHERE id = $1 AND tenant_id = $2")
                .bind(id)
                .bind(tenant_id)
                .fetch_optional(pool)
                .await?;
        let Some(stored) = stored else {
            return Ok(None);
        };
        let plaintext = apexmail_lib::secret_at_rest::decrypt_at_rest(&stored, &webhook_aad(id))
            .map_err(secret_error)?;
        migrate_stored_secret_raw(pool, id, &stored).await;
        Ok(Some(plaintext))
    }

    /// List webhooks for a tenant with pagination. Secrets are masked.
    /// #225:Added limit/offset parameters
    pub async fn list(
        pool: &PgPool,
        tenant_id: &str,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<Webhook>, sqlx::Error> {
        let limit = limit.clamp(1, 100);
        let offset = offset.max(0);
        let rows = sqlx::query_as::<_, Webhook>(
            "SELECT id, tenant_id, url, events, secret, status, created_at, updated_at \
             FROM webhooks WHERE tenant_id = $1 ORDER BY created_at DESC LIMIT $2 OFFSET $3",
        )
        .bind(tenant_id)
        .bind(limit)
        .bind(offset)
        .fetch_all(pool)
        .await?;
        mask_all(pool, rows).await
    }

    /// List webhooks for a tenant using keyset (cursor-based) pagination.
    /// Uses `(created_at, id)` tuple comparison for stable, efficient pagination.
    /// Secrets are masked.
    ///
    /// `cursor_id` is the VARCHAR(26) short id of the last row of the
    /// previous page (migration 075) — bind it as text, never as a UUID.
    pub async fn list_keyset(
        pool: &PgPool,
        tenant_id: &str,
        limit: i64,
        cursor_created_at: Option<DateTime<Utc>>,
        cursor_id: Option<&str>,
    ) -> Result<Vec<Webhook>, sqlx::Error> {
        let limit = limit.clamp(1, 200);
        let fetch_limit = limit + 1;
        let rows =
            match (cursor_created_at, cursor_id) {
                (Some(created_at), Some(id)) => sqlx::query_as::<_, Webhook>(
                    "SELECT id, tenant_id, url, events, secret, status, created_at, updated_at \
                     FROM webhooks WHERE tenant_id = $1 AND (created_at, id) < ($2, $3) \
                     ORDER BY created_at DESC, id DESC LIMIT $4",
                )
                .bind(tenant_id)
                .bind(created_at)
                .bind(id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await?,
                _ => {
                    // First page — no cursor
                    sqlx::query_as::<_, Webhook>(
                    "SELECT id, tenant_id, url, events, secret, status, created_at, updated_at \
                     FROM webhooks WHERE tenant_id = $1 \
                     ORDER BY created_at DESC, id DESC LIMIT $2",
                )
                .bind(tenant_id)
                .bind(fetch_limit)
                .fetch_all(pool)
                .await?
                }
            };
        mask_all(pool, rows).await
    }

    /// Update a webhook. The returned row's `secret` is masked.
    pub async fn update(
        pool: &PgPool,
        tenant_id: &str,
        id: &str,
        url: &str,
        events: serde_json::Value,
        status: &str,
    ) -> Result<Option<Webhook>, sqlx::Error> {
        let webhook = sqlx::query_as::<_, Webhook>(
            "UPDATE webhooks SET url = $1, events = $2, status = $3, updated_at = NOW() \
             WHERE id = $4 AND tenant_id = $5 RETURNING id, tenant_id, url, events, secret, status, created_at, updated_at",
        )
        .bind(url)
        .bind(events)
        .bind(status)
        .bind(id)
        .bind(tenant_id)
        .fetch_optional(pool)
        .await?;
        Ok(webhook.as_ref().map(mask_webhook))
    }

    /// Delete a webhook.
    ///
    /// `id` is the VARCHAR(26) short id stored by [`create`] (migration
    /// 075) — binding it as text matches the column type.
    pub async fn delete(pool: &PgPool, tenant_id: &str, id: &str) -> Result<bool, sqlx::Error> {
        let result = sqlx::query("DELETE FROM webhooks WHERE id = $1 AND tenant_id = $2")
            .bind(id)
            .bind(tenant_id)
            .execute(pool)
            .await?;
        Ok(result.rows_affected() > 0)
    }

    /// List all webhooks subscribed to a specific event type. Secrets are
    /// masked (delivery signing goes through [`secret_for_signing`]).
    pub async fn list_by_event_type(
        pool: &PgPool,
        tenant_id: &str,
        event_type: &str,
    ) -> Result<Vec<Webhook>, sqlx::Error> {
        let rows = sqlx::query_as::<_, Webhook>(
            "SELECT id, tenant_id, url, events, secret, status, created_at, updated_at \
             FROM webhooks WHERE tenant_id = $1 AND status = 'active' \
             AND events @> $2::jsonb ORDER BY created_at ASC",
        )
        .bind(tenant_id)
        .bind(serde_json::json!([event_type]))
        .fetch_all(pool)
        .await?;
        mask_all(pool, rows).await
    }
}

/// Project every row's stored secret down to the masked prefix.
///
/// Legacy plaintext rows (and `plain:v1:` dev markers) are migrated to
/// encrypted envelopes on read; an already-encrypted row is untouched.
async fn mask_all(pool: &PgPool, rows: Vec<Webhook>) -> Result<Vec<Webhook>, sqlx::Error> {
    for row in &rows {
        migrate_stored_secret(pool, row).await?;
    }
    Ok(rows.iter().map(mask_webhook).collect())
}

/// Replace a row's stored-secret field with the masked display prefix.
fn mask_webhook(webhook: &Webhook) -> Webhook {
    let mut masked = webhook.clone();
    masked.secret = mask_stored_secret(&webhook.secret, &webhook.id);
    masked
}

/// Mask whatever the DB returned: decrypt (transparently accepting legacy
/// plaintext), then reduce to the display prefix.
///
/// This is a DISPLAY projection: a decryption failure (tampered envelope, or
/// a keyless dev process reading an `enc:` row) can never be answered with
/// something secret-like, so it degrades to the full placeholder and logs —
/// the authoritative `secret_for_signing` path fails closed instead.
fn mask_stored_secret(stored: &str, webhook_id: &str) -> String {
    match apexmail_lib::secret_at_rest::decrypt_at_rest(stored, &webhook_aad(webhook_id)) {
        Ok(plaintext) => mask_secret(&plaintext),
        Err(error) => {
            tracing::warn!(%error, webhook_id, "webhook secret display projection could not decrypt — masking fully");
            "••••••••".to_string()
        }
    }
}

/// Migrate-on-read: rewrite a legacy plaintext secret as an encrypted
/// envelope (audit F4). Errors are logged, never fatal for the read.
async fn migrate_stored_secret(pool: &PgPool, webhook: &Webhook) -> Result<(), sqlx::Error> {
    migrate_stored_secret_raw(pool, &webhook.id, &webhook.secret).await;
    Ok(())
}

async fn migrate_stored_secret_raw(pool: &PgPool, webhook_id: &str, stored: &str) {
    match apexmail_lib::secret_at_rest::migrate_at_rest(stored, &webhook_aad(webhook_id)) {
        Ok(Some(encrypted)) => {
            if let Err(error) =
                sqlx::query("UPDATE webhooks SET secret = $1, updated_at = NOW() WHERE id = $2")
                    .bind(&encrypted)
                    .bind(webhook_id)
                    .execute(pool)
                    .await
            {
                tracing::warn!(%error, webhook_id, "failed to persist migrated webhook secret envelope");
            }
        }
        Ok(None) => {}
        Err(error) => {
            tracing::warn!(%error, webhook_id, "webhook secret migrate-on-read failed");
        }
    }
}

#[cfg(test)]
mod tests {
    use crate::types::Webhook;
    use chrono::Utc;

    #[test]
    fn test_webhook_mock() {
        let w = Webhook {
            id: crate::types::short_id('w'),
            tenant_id: crate::types::short_id('w'),
            url: "https://example.com/hooks".into(),
            events: serde_json::json!(["delivered", "bounced"]),
            secret: "whsec_abc123".into(),
            status: "active".into(),
            created_at: Utc::now(),
            updated_at: Utc::now(),
        };
        assert_eq!(w.status, "active");
        assert_eq!(w.events.as_array().unwrap().len(), 2);
    }

    #[test]
    fn test_webhook_event_contains() {
        let events = serde_json::json!(["delivered", "bounced", "opened"]);
        let arr = events.as_array().unwrap();
        assert!(arr.iter().any(|v| v == "delivered"));
    }

    #[test]
    fn test_webhooks_repo_is_stateless() {
        let _repo = super::WebhooksRepo;
    }

    // ── Audit F4: masking contract ─────────────────────────────────

    #[test]
    fn mask_secret_shows_only_a_short_prefix() {
        let secret = "whsec_0f3a9b7c5d2e4a6188f0deadbeef1234";
        let masked = super::mask_secret(secret);
        assert_eq!(masked, "whsec_0f…", "exactly the 8-char prefix + tail");
        assert!(
            !masked.contains("f3a9b7c"),
            "nothing beyond the prefix may leak: {masked}"
        );
        assert_ne!(masked, secret);
    }

    #[test]
    fn mask_secret_hides_short_secrets_entirely() {
        for secret in ["", "abc", "whsec_ab"] {
            let masked = super::mask_secret(secret);
            assert_eq!(
                masked, "••••••••",
                "short secrets must reveal nothing: {secret:?}"
            );
        }
        // A boundary-length secret (exactly the prefix size) reveals nothing
        // either — the masked form is only for LONGER secrets.
        assert_eq!(super::mask_secret("whsec_0f"), "••••••••");
    }

    #[test]
    fn webhook_aad_binds_the_row_identity() {
        assert_eq!(super::webhook_aad("wABC"), b"webhook=wABC".to_vec());
        assert_ne!(
            super::webhook_aad("wONE"),
            super::webhook_aad("wTWO"),
            "different webhooks must not share an AAD"
        );
    }

    /// Round-trip through the at-rest layer with the webhook AAD: encrypt →
    /// decrypt returns the plaintext; the same envelope under a DIFFERENT
    /// webhook's AAD fails (relocation defense).
    #[test]
    fn secret_round_trips_through_the_at_rest_envelope() {
        use apexmail_lib::secret_at_rest::{decrypt_at_rest, encrypt_at_rest};
        let secret = "whsec_roundtrip_4f8d2ab90ce1";
        let id = crate::types::short_id('w');
        let envelope = encrypt_at_rest(secret, &super::webhook_aad(&id))
            .expect("dev/test at-rest encryption must be available");
        assert!(
            apexmail_lib::secret_at_rest::is_encrypted(&envelope) || envelope != secret,
            "stored form must differ from the plaintext"
        );
        assert_eq!(
            decrypt_at_rest(&envelope, &super::webhook_aad(&id)).unwrap(),
            secret
        );
        // AAD mismatch (different webhook) fails closed.
        assert!(decrypt_at_rest(&envelope, &super::webhook_aad("wother")).is_err());
    }
}
