use crate::types::*;
use sqlx::PgPool;
use uuid::Uuid;
use chrono::Utc as ChronoUtc;

/// Keywords in failure reasons that indicate a permanent (non-transient)
/// condition requiring operator intervention rather than automatic retry.
const PERMANENT_FAILURE_KEYWORDS: &[&str] = &[
    "authentication failed",
    "auth failed",
    "invalid credentials",
    "login rejected",
    "account disabled",
    "mailbox not found",
    "user unknown",
    "no IMAP password configured",
    "permission denied",
    "application-specific password required",
];

/// Base backoff delay in seconds for transient health-check failures.
const BACKOFF_BASE_SECS: i64 = 300; // 5 minutes
/// Maximum backoff delay in seconds for transient failures.
const BACKOFF_MAX_SECS: i64 = 86_400; // 24 hours

/// Returns `true` when the failure reason indicates a permanent condition
/// that should lead to immediate auto-disable rather than exponential backoff.
fn is_permanent_failure(reason: &str) -> bool {
    let lower = reason.to_lowercase();
    PERMANENT_FAILURE_KEYWORDS.iter().any(|kw| lower.contains(kw))
}

/// Compute the exponential backoff delay for a given number of consecutive
/// failures: `min(BACKOFF_BASE_SECS * 2^(failures - 1), BACKOFF_MAX_SECS)`.
fn backoff_seconds(consecutive_failures: u32) -> i64 {
    let exponent = consecutive_failures.saturating_sub(1);
    // Cap shifting to avoid overflow on very large exponents
    let delay = if exponent >= 31 {
        BACKOFF_MAX_SECS
    } else {
        BACKOFF_BASE_SECS.saturating_mul(1i64 << exponent)
    };
    delay.min(BACKOFF_MAX_SECS)
}

#[derive(Debug, Clone)]
pub struct SeedManager {
    db: PgPool,
}

impl SeedManager {
    pub fn new(db: PgPool) -> Self {
        Self { db }
    }

    // ── Providers ───────────────────────────────────────────────

    pub async fn list_providers(&self) -> Result<Vec<ProviderResponse>, sqlx::Error> {
        let providers = sqlx::query_as::<_, SeedProvider>(
            "SELECT id, name, display_name, inbox_types, icon_url, created_at FROM seed_providers ORDER BY display_name"
        )
        .fetch_all(&self.db)
        .await?;

        let mut responses = Vec::with_capacity(providers.len());
        for p in providers {
            let count: (i64,) = sqlx::query_as(
                "SELECT COUNT(*) FROM seed_accounts WHERE provider_id = $1 AND is_active = true"
            )
            .bind(p.id)
            .fetch_one(&self.db)
            .await
            .unwrap_or((0,));

            responses.push(ProviderResponse {
                id: p.id,
                name: p.name,
                display_name: p.display_name,
                active_accounts: count.0,
                inbox_types: p.inbox_types,
            });
        }
        Ok(responses)
    }

    pub async fn get_provider(&self, id: Uuid) -> Result<Option<SeedProvider>, sqlx::Error> {
        sqlx::query_as::<_, SeedProvider>(
            "SELECT id, name, display_name, inbox_types, icon_url, created_at FROM seed_providers WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
    }

    pub async fn get_provider_by_name(&self, name: &str) -> Result<Option<SeedProvider>, sqlx::Error> {
        sqlx::query_as::<_, SeedProvider>(
            "SELECT id, name, display_name, inbox_types, icon_url, created_at FROM seed_providers WHERE name = $1"
        )
        .bind(name)
        .fetch_optional(&self.db)
        .await
    }

    // ── Seed Accounts ───────────────────────────────────────────

    pub async fn list_active_accounts(&self) -> Result<Vec<SeedAccount>, sqlx::Error> {
        sqlx::query_as::<_, SeedAccount>(
            r#"SELECT id, provider_id, email, imap_host, imap_port, imap_username, 
               is_active, last_checked_at, health_status, created_at
               FROM seed_accounts WHERE is_active = true ORDER BY email"#
        )
        .fetch_all(&self.db)
        .await
    }

    pub async fn list_accounts_by_provider(&self, provider_id: Uuid) -> Result<Vec<SeedAccount>, sqlx::Error> {
        sqlx::query_as::<_, SeedAccount>(
            r#"SELECT id, provider_id, email, imap_host, imap_port, imap_username,
               is_active, last_checked_at, health_status, created_at
               FROM seed_accounts WHERE provider_id = $1 AND is_active = true ORDER BY email"#
        )
        .bind(provider_id)
        .fetch_all(&self.db)
        .await
    }

    pub async fn get_account(&self, id: Uuid) -> Result<Option<SeedAccount>, sqlx::Error> {
        sqlx::query_as::<_, SeedAccount>(
            r#"SELECT id, provider_id, email, imap_host, imap_port, imap_username,
               is_active, last_checked_at, health_status, created_at
               FROM seed_accounts WHERE id = $1"#
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
    }

    pub async fn count_active_accounts(&self) -> Result<i64, sqlx::Error> {
        let row: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM seed_accounts WHERE is_active = true"
        )
        .fetch_one(&self.db)
        .await?;
        Ok(row.0)
    }

    /// Get seed accounts filtered by provider names (e.g. ["gmail", "outlook"])
    pub async fn get_accounts_by_provider_names(&self, providers: &[String]) -> Result<Vec<SeedAccount>, sqlx::Error> {
        if providers.is_empty() {
            return self.list_active_accounts().await;
        }
        
        // Build a query with provider name filter
        // Using a simple approach: get all providers first, then filter
        let providers_rows = sqlx::query_as::<_, SeedProvider>(
            "SELECT id, name, display_name, inbox_types, icon_url, created_at FROM seed_providers WHERE name = ANY($1)"
        )
        .bind(providers)
        .fetch_all(&self.db)
        .await?;

        let provider_ids: Vec<Uuid> = providers_rows.into_iter().map(|p| p.id).collect();
        
        if provider_ids.is_empty() {
            return Ok(Vec::new());
        }

        sqlx::query_as::<_, SeedAccount>(
            r#"SELECT id, provider_id, email, imap_host, imap_port, imap_username,
               is_active, last_checked_at, health_status, created_at
               FROM seed_accounts WHERE provider_id = ANY($1) AND is_active = true ORDER BY email"#
        )
        .bind(&provider_ids)
        .fetch_all(&self.db)
        .await
    }

    /// Update account health status after IMAP check
    pub async fn update_account_health(
        &self,
        account_id: Uuid,
        health_status: &str,
        last_checked_at: chrono::DateTime<chrono::Utc>,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE seed_accounts SET health_status = $1, last_checked_at = $2 WHERE id = $3"
        )
        .bind(health_status)
        .bind(last_checked_at)
        .bind(account_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Record a successful IMAP health check: clears the consecutive-failure
    /// counter and marks the account `ok`.
    pub async fn record_health_success(
        &self,
        account_id: Uuid,
    ) -> Result<(), sqlx::Error> {
        sqlx::query(
            "UPDATE seed_accounts \
             SET health_status = 'ok', \
                 last_checked_at = NOW(), \
                 consecutive_failures = 0, \
                 last_failure_reason = NULL \
             WHERE id = $1",
        )
        .bind(account_id)
        .execute(&self.db)
        .await?;
        Ok(())
    }

    /// Record a failed IMAP health check.
    ///
    /// Differentiates **permanent** failures (auth errors, account disabled,
    /// mailbox not found) from **transient** failures (network timeouts,
    /// connection resets, DNS issues).
    ///
    /// - **Permanent** failures: auto-disable the account once the configured
    ///   `failure_threshold` is reached.
    /// - **Transient** failures: apply exponential backoff by setting
    ///   `last_checked_at` to a future timestamp so the health-check scheduler
    ///   skips the account until the backoff window expires. The account is
    ///   only auto-disabled if transient failures exceed the threshold.
    ///
    /// Returns `true` when the account was disabled by this call.
    pub async fn record_health_failure(
        &self,
        account_id: Uuid,
        reason: &str,
        failure_threshold: u32,
    ) -> Result<bool, sqlx::Error> {
        // Atomically bump the counter and capture the new value.
        let row: Option<(i32,)> = sqlx::query_as(
            "UPDATE seed_accounts \
             SET health_status = 'error', \
                 consecutive_failures = consecutive_failures + 1, \
                 last_failure_reason = $1 \
             WHERE id = $2 \
             RETURNING consecutive_failures",
        )
        .bind(reason)
        .bind(account_id)
        .fetch_optional(&self.db)
        .await?;

        let Some((failures,)) = row else {
            return Ok(false);
        };
        let failures_u32 = failures as u32;

        if is_permanent_failure(reason) || failures_u32 >= failure_threshold {
            // Permanent failure or threshold exceeded → disable the account.
            sqlx::query(
                "UPDATE seed_accounts \
                 SET is_active = false, disabled_at = NOW(), \
                     last_checked_at = NOW() \
                 WHERE id = $1 AND is_active = true",
            )
            .bind(account_id)
            .execute(&self.db)
            .await?;
            tracing::warn!(
                account_id = %account_id,
                failures = failures,
                threshold = failure_threshold,
                reason = %reason,
                permanent = is_permanent_failure(reason),
                "Seed account auto-disabled after IMAP failures"
            );
            return Ok(true);
        }

        // Transient failure → apply exponential backoff so the health-check
        // scheduler won't pick this account again until after the backoff
        // window expires. This avoids hammering a flaky IMAP server.
        let backoff = backoff_seconds(failures_u32);
        let backoff_until = ChronoUtc::now() + chrono::Duration::seconds(backoff);
        sqlx::query(
            "UPDATE seed_accounts \
             SET last_checked_at = $1 \
             WHERE id = $2",
        )
        .bind(backoff_until)
        .bind(account_id)
        .execute(&self.db)
        .await?;

        tracing::info!(
            account_id = %account_id,
            failures = failures,
            backoff_seconds = backoff,
            reason = %reason,
            "Transient seed account health failure; applying exponential backoff"
        );

        Ok(false)
    }

    /// List active seed accounts whose last health check is older than
    /// `older_than_secs`, ordered oldest-first. Used by the placement
    /// scheduler's periodic health-check loop.
    pub async fn list_accounts_due_for_health_check(
        &self,
        older_than_secs: i64,
        limit: i64,
    ) -> Result<Vec<SeedAccount>, sqlx::Error> {
        let cutoff = chrono::Utc::now() - chrono::Duration::seconds(older_than_secs);
        sqlx::query_as::<_, SeedAccount>(
            r#"SELECT id, provider_id, email, imap_host, imap_port, imap_username,
                       is_active, last_checked_at, health_status, created_at
               FROM seed_accounts
               WHERE is_active = true
                 AND (last_checked_at IS NULL OR last_checked_at < $1)
               ORDER BY last_checked_at NULLS FIRST
               LIMIT $2"#,
        )
        .bind(cutoff)
        .bind(limit)
        .fetch_all(&self.db)
        .await
    }

    // ── Field Encryption ─────────────────────────────────────────

    /// Encrypt a plaintext password and store it in `imap_password_encrypted`
    /// for the given seed account.
    pub async fn encrypt_account_password(
        &self,
        account_id: Uuid,
        password: &str,
        encryptor: &enterprise::field_encryption::FieldEncryptor,
    ) -> Result<(), sqlx::Error> {
        let encrypted = encryptor.encrypt(password).map_err(|e| {
            sqlx::Error::Protocol(format!("password encryption failed: {e}"))
        })?;

        sqlx::query(
            "UPDATE seed_accounts SET imap_password_encrypted = $1 WHERE id = $2",
        )
        .bind(&encrypted)
        .bind(account_id)
        .execute(&self.db)
        .await?;

        Ok(())
    }

    /// Decrypt the stored encrypted password for a seed account.
    /// Returns `None` if no encrypted password is found.
    pub async fn decrypt_account_password(
        &self,
        account_id: Uuid,
        encryptor: &enterprise::field_encryption::FieldEncryptor,
    ) -> Result<Option<String>, sqlx::Error> {
        let row: Result<(String,), _> = sqlx::query_as(
            "SELECT imap_password_encrypted FROM seed_accounts WHERE id = $1",
        )
        .bind(account_id)
        .fetch_one(&self.db)
        .await;

        match row {
            Ok((pw,)) => {
                if pw.is_empty() {
                    return Ok(None);
                }
                let decrypted = encryptor.decrypt(&pw).map_err(|e| {
                    sqlx::Error::Protocol(format!("password decryption failed: {e}"))
                })?;
                Ok(Some(decrypted))
            }
            Err(sqlx::Error::RowNotFound) => Ok(None),
            Err(e) => Err(e),
        }
    }
}
