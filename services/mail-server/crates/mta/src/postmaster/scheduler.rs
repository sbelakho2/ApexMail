//! Periodic poller for Google Postmaster + Microsoft SNDS.
//!
//! Spawned from the MTA binary at startup; does not block service init.
//! Each tick:
//!   1. Polls each configured Google credential.
//!   2. Polls each configured SNDS credential.
//!   3. Runs `aggregator::recompute()` to refresh summaries / emit events.
//!   4. Updates `postmaster_credentials.last_polled_at` / `last_error`.
//!
//! Failure of a single credential never aborts the whole tick — partial data
//! is still useful and the next tick will retry.

use std::time::Duration;

use sqlx::PgPool;
use tokio::time::{interval, MissedTickBehavior};
use tracing::{error, info, warn};

use super::{aggregator, google, snds};

/// Configuration knob — defaults to 6 hours.
#[derive(Debug, Clone)]
pub struct ScheduleConfig {
    pub interval: Duration,
}

impl Default for ScheduleConfig {
    fn default() -> Self {
        Self {
            interval: Duration::from_secs(6 * 60 * 60),
        }
    }
}

/// One row from `postmaster_credentials`.
#[derive(Debug, Clone, sqlx::FromRow)]
pub struct CredentialRow {
    pub id: String,
    pub provider: String,
    pub label: String,
    pub secret_ref: String,
    pub enabled: bool,
}

/// Function the caller supplies for resolving a `secret_ref` to plaintext.
/// Typically delegates to `compliance::secret_manager::SecretManager::get_secret`.
pub type SecretResolver = std::sync::Arc<
    dyn Fn(String) -> futures::future::BoxFuture<'static, Result<String, String>> + Send + Sync,
>;

/// Spawn the poller.  Returns the `JoinHandle`; callers can drop it to detach.
pub fn spawn(
    db: PgPool,
    config: ScheduleConfig,
    resolver: SecretResolver,
) -> tokio::task::JoinHandle<()> {
    tokio::spawn(async move {
        let mut tick = interval(config.interval);
        tick.set_missed_tick_behavior(MissedTickBehavior::Skip);
        loop {
            tick.tick().await;
            if let Err(e) = run_once(&db, &resolver).await {
                error!(error = %e, "postmaster scheduler tick failed");
            }
        }
    })
}

/// Single tick — public so tests / on-demand admin endpoints can invoke it.
pub async fn run_once(db: &PgPool, resolver: &SecretResolver) -> Result<(), String> {
    let creds: Vec<CredentialRow> = sqlx::query_as(
        "SELECT id, provider, label, secret_ref, enabled
         FROM postmaster_credentials WHERE enabled = TRUE",
    )
    .fetch_all(db)
    .await
    .map_err(|e| format!("DB error: {e}"))?;

    if creds.is_empty() {
        info!("postmaster scheduler: no enabled credentials, skipping");
        return Ok(());
    }

    for c in &creds {
        let res = match c.provider.as_str() {
            "google" => poll_google(db, c, resolver).await,
            "microsoft" => poll_snds(db, c, resolver).await,
            other => Err(format!("unknown provider {other}")),
        };
        match res {
            Ok(n) => {
                let _ = sqlx::query(
                    "UPDATE postmaster_credentials
                     SET last_polled_at = NOW(),
                         last_error = NULL,
                         consecutive_failures = 0,
                         updated_at = NOW()
                     WHERE id = $1",
                )
                .bind(&c.id)
                .execute(db)
                .await;
                info!(provider = %c.provider, label = %c.label, rows = n, "poll ok");
            }
            Err(e) => {
                warn!(provider = %c.provider, label = %c.label, error = %e, "poll failed");
                let _ = sqlx::query(
                    "UPDATE postmaster_credentials
                     SET last_polled_at = NOW(),
                         last_error = $1,
                         consecutive_failures = consecutive_failures + 1,
                         updated_at = NOW()
                     WHERE id = $2",
                )
                .bind(&e)
                .bind(&c.id)
                .execute(db)
                .await;
            }
        }
    }

    let (domains, ips, events) = aggregator::recompute(db).await?;
    info!(domains, ips, events, "postmaster aggregator complete");
    Ok(())
}

async fn poll_google(
    db: &PgPool,
    c: &CredentialRow,
    resolver: &SecretResolver,
) -> Result<usize, String> {
    let plaintext = resolver(c.secret_ref.clone()).await?;
    // Stored secret JSON: {"client_id":..., "client_secret":..., "refresh_token":...}
    let value: serde_json::Value =
        serde_json::from_str(&plaintext).map_err(|e| format!("secret JSON: {e}"))?;
    let creds = google::GoogleCredentials {
        client_id: value
            .get("client_id")
            .and_then(|v| v.as_str())
            .ok_or("missing client_id")?
            .to_string(),
        client_secret: value
            .get("client_secret")
            .and_then(|v| v.as_str())
            .ok_or("missing client_secret")?
            .to_string(),
        refresh_token: value
            .get("refresh_token")
            .and_then(|v| v.as_str())
            .ok_or("missing refresh_token")?
            .to_string(),
    };
    let client = google::GoogleClient::new(creds)?;
    google::ingest_all(db, &client).await
}

async fn poll_snds(
    db: &PgPool,
    c: &CredentialRow,
    resolver: &SecretResolver,
) -> Result<usize, String> {
    let plaintext = resolver(c.secret_ref.clone()).await?;
    // Stored secret: either raw access key or {"access_key": "..."}
    let access_key = if plaintext.trim_start().starts_with('{') {
        let v: serde_json::Value =
            serde_json::from_str(&plaintext).map_err(|e| format!("secret JSON: {e}"))?;
        v.get("access_key")
            .and_then(|x| x.as_str())
            .ok_or("missing access_key")?
            .to_string()
    } else {
        plaintext.trim().to_string()
    };
    let client = snds::SndsClient::new(snds::SndsCredentials { access_key })?;
    snds::ingest_all(db, &client).await
}
