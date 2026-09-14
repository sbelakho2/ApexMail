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

#[cfg(test)]
mod tests {
    //! Adversarial scheduler tests: every poll outcome (no creds, unknown
    //! provider, secret-resolution failure, malformed secret JSON, missing
    //! keys) must be recorded on the credential row and must never abort the
    //! tick. DB-backed via the canonical schema; TEST_DATABASE_URL unset
    //! soft-skips, a configured provisioning failure panics.

    use super::*;
    use std::sync::Arc;

    async fn test_pool(test_name: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    fn resolver_returning(value: Result<&'static str, &'static str>) -> SecretResolver {
        Arc::new(move |_secret_ref: String| {
            let value = value.map(str::to_string).map_err(str::to_string);
            Box::pin(async move { value })
        })
    }

    async fn insert_credential(
        pool: &PgPool,
        id: &str,
        provider: &str,
        secret_ref: &str,
        enabled: bool,
    ) {
        sqlx::query(
            "INSERT INTO postmaster_credentials (id, provider, label, secret_ref, enabled)
             VALUES ($1, $2, $3, $4, $5)",
        )
        .bind(id)
        .bind(provider)
        .bind(format!("label-{id}"))
        .bind(secret_ref)
        .bind(enabled)
        .execute(pool)
        .await
        .expect("insert credential");
    }

    async fn credential_state(pool: &PgPool, id: &str) -> (Option<String>, i32) {
        sqlx::query_as::<_, (Option<String>, i32)>(
            "SELECT last_error, consecutive_failures FROM postmaster_credentials WHERE id = $1",
        )
        .bind(id)
        .fetch_one(pool)
        .await
        .expect("credential row")
    }

    #[tokio::test]
    async fn run_once_with_no_enabled_credentials_is_ok_and_touches_nothing() {
        let Some(pool) = test_pool("scheduler_empty").await else {
            return;
        };
        insert_credential(&pool, "disabled", "google", "does-not-matter", false).await;
        run_once(&pool, &resolver_returning(Ok("{}")))
            .await
            .expect("an empty poll set is a successful tick");
        let (last_error, failures) = credential_state(&pool, "disabled").await;
        assert_eq!(last_error, None, "disabled credentials are never polled");
        assert_eq!(failures, 0);
    }

    #[tokio::test]
    async fn unknown_provider_is_recorded_and_does_not_abort_the_tick() {
        let Some(pool) = test_pool("scheduler_unknown").await else {
            return;
        };
        insert_credential(&pool, "weird", "carrier-pigeon", "ref", true).await;
        run_once(&pool, &resolver_returning(Ok("{}")))
            .await
            .expect("a per-credential failure must not fail the tick");
        let (last_error, failures) = credential_state(&pool, "weird").await;
        assert!(
            last_error
                .clone()
                .unwrap_or_default()
                .contains("unknown provider"),
            "unknown providers must be recorded: {last_error:?}"
        );
        assert_eq!(failures, 1, "consecutive_failures increments");
    }

    #[tokio::test]
    async fn google_secret_failures_are_recorded_without_network_access() {
        let Some(pool) = test_pool("scheduler_google_errors").await else {
            return;
        };
        insert_credential(&pool, "g-missing", "google", "ref-missing", true).await;
        insert_credential(&pool, "g-badjson", "google", "ref-badjson", true).await;
        insert_credential(&pool, "g-halfjson", "google", "ref-halfjson", true).await;

        let resolver: SecretResolver = Arc::new(|secret_ref: String| {
            Box::pin(async move {
                match secret_ref.as_str() {
                    "ref-missing" => Err("secret_ref not found".to_string()),
                    "ref-badjson" => Ok("not json at all".to_string()),
                    _ => Ok("{\"client_id\":\"only\"}".to_string()),
                }
            })
        });
        run_once(&pool, &resolver)
            .await
            .expect("tick must survive every per-credential failure");

        let (err_missing, failures_missing) = credential_state(&pool, "g-missing").await;
        assert_eq!(err_missing.as_deref(), Some("secret_ref not found"));
        assert_eq!(failures_missing, 1);

        let (err_json, failures_json) = credential_state(&pool, "g-badjson").await;
        assert!(
            err_json.unwrap_or_default().starts_with("secret JSON"),
            "malformed secret JSON is reported as such"
        );
        assert_eq!(failures_json, 1);

        let (err_half, _) = credential_state(&pool, "g-halfjson").await;
        assert_eq!(
            err_half.as_deref(),
            Some("missing client_secret"),
            "a JSON object missing required keys is refused before any HTTP call"
        );
    }

    #[tokio::test]
    async fn snds_secret_shapes_are_validated_before_any_network_call() {
        let Some(pool) = test_pool("scheduler_snds_errors").await else {
            return;
        };
        insert_credential(&pool, "m-resolverr", "microsoft", "ref-err", true).await;
        insert_credential(&pool, "m-badjson", "microsoft", "ref-badjson", true).await;
        insert_credential(&pool, "m-nokey", "microsoft", "ref-nokey", true).await;

        let resolver: SecretResolver = Arc::new(|secret_ref: String| {
            Box::pin(async move {
                match secret_ref.as_str() {
                    "ref-err" => Err("vault unavailable".to_string()),
                    "ref-badjson" => Ok("{ not json".to_string()),
                    _ => Ok("{\"other\":\"value\"}".to_string()),
                }
            })
        });
        run_once(&pool, &resolver).await.expect("tick survives");

        assert_eq!(
            credential_state(&pool, "m-resolverr").await.0.as_deref(),
            Some("vault unavailable")
        );
        assert!(credential_state(&pool, "m-badjson")
            .await
            .0
            .unwrap_or_default()
            .starts_with("secret JSON"));
        assert_eq!(
            credential_state(&pool, "m-nokey").await.0.as_deref(),
            Some("missing access_key"),
            "JSON without access_key is refused before the HTTP client is built"
        );
    }

    #[tokio::test]
    async fn spawn_ticks_and_can_be_aborted() {
        let Some(pool) = test_pool("scheduler_spawn").await else {
            return;
        };
        let handle = spawn(
            pool,
            ScheduleConfig {
                interval: Duration::from_millis(10),
            },
            resolver_returning(Ok("{}")),
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
        assert!(
            !handle.is_finished(),
            "spawned scheduler runs until aborted"
        );
        handle.abort();
        let default_cfg = ScheduleConfig::default();
        assert_eq!(default_cfg.interval, Duration::from_secs(6 * 60 * 60));
    }
}
