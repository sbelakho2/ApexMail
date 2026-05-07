use std::sync::Arc;
use std::time::Duration;

use tokio_util::sync::CancellationToken;
use uuid::Uuid;

use crate::engine::PlacementEngine;
use crate::config::PlacementConfig;
use crate::imap_poller::ImapPoller;

/// Background task that periodically polls for pending placement tests and
/// executes them.
///
/// The scheduler runs a `tokio::spawn`ed loop that:
/// - Queries `placement_tests` for rows with status `'Pending'` or `'Running'`
///   at every `config.polling_interval_secs` interval.
/// - Invokes [`PlacementEngine::execute_test`] for each pending test.
/// - Respects the `max_tests_per_hour` rate limit by not starting more tests
///   than the configured ceiling would allow in the current sliding window.
/// - Logs progress via `tracing`.
/// - Continues until [`shutdown`](PlacementScheduler::shutdown) is called.
#[derive(Debug)]
pub struct PlacementScheduler {
    engine: Arc<PlacementEngine>,
    config: PlacementConfig,
    cancel_token: CancellationToken,
}

impl PlacementScheduler {
    /// Create a new scheduler wrapping the provided engine.
    pub fn new(engine: Arc<PlacementEngine>) -> Self {
        Self {
            config: engine.config.clone(),
            engine,
            cancel_token: CancellationToken::new(),
        }
    }

    /// Start the background polling loop.
    ///
    /// This method returns immediately after spawning the task.  The loop
    /// runs until [`shutdown`](PlacementScheduler::shutdown) is called or the
    /// application shuts down.
    pub async fn start(self: Arc<Self>) {
        // Spawn the test-execution loop and the seed-account health-check loop
        // as independent tasks so a stuck IMAP probe never blocks placement
        // test execution (and vice versa).
        self.clone().spawn_execution_loop();
        self.spawn_health_check_loop();
    }

    fn spawn_execution_loop(self: Arc<Self>) {
        let engine = self.engine.clone();
        let config = self.config.clone();
        let cancel = self.cancel_token.clone();

        tokio::spawn(async move {
            tracing::info!(
                polling_interval_secs = config.polling_interval_secs,
                max_tests_per_hour = config.max_tests_per_hour,
                "Placement scheduler started"
            );

            loop {
                tokio::select! {
                    _ = cancel.cancelled() => {
                        tracing::info!("Placement scheduler received shutdown signal");
                        break;
                    }
                    _ = tokio::time::sleep(Duration::from_secs(config.polling_interval_secs)) => {}
                }

                // Check cancellation again after sleep.
                if cancel.is_cancelled() {
                    break;
                }

                // Query for pending / running tests.
                let tests = match Self::fetch_pending_tests(&engine, &config).await {
                    Ok(t) => t,
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to fetch pending placement tests");
                        continue;
                    }
                };

                if tests.is_empty() {
                    continue;
                }

                tracing::info!(
                    count = tests.len(),
                    "Found pending placement tests to execute"
                );

                for test_id in &tests {
                    if cancel.is_cancelled() {
                        break;
                    }

                    tracing::info!(test_id = %test_id, "Executing placement test");
                    if let Err(e) = engine.execute_test(*test_id).await {
                        tracing::error!(
                            test_id = %test_id,
                            error = %e,
                            "Placement test execution failed"
                        );
                    }
                }
            }

            tracing::info!("Placement scheduler stopped");
        });
    }

    /// Spawn the periodic seed-account IMAP health-check loop.
    ///
    /// Every `health_check_interval_secs` seconds the loop pulls active seed
    /// accounts whose `last_checked_at` is older than the interval, attempts an
    /// IMAP login + INBOX SELECT, and updates the per-account health record.
    /// Accounts that fail `seed_account_failure_threshold` consecutive checks
    /// are atomically disabled.
    fn spawn_health_check_loop(self: Arc<Self>) {
        let engine = self.engine.clone();
        let config = self.config.clone();
        let cancel = self.cancel_token.clone();

        if config.health_check_interval_secs == 0 {
            tracing::info!("Placement health-check loop disabled by config");
            return;
        }

        tokio::spawn(async move {
            tracing::info!(
                interval_secs = config.health_check_interval_secs,
                failure_threshold = config.seed_account_failure_threshold,
                "Placement seed-account health checker started"
            );

            // Stagger the first run by 30s so it doesn't collide with startup.
            let initial_delay = Duration::from_secs(30);
            tokio::select! {
                _ = cancel.cancelled() => return,
                _ = tokio::time::sleep(initial_delay) => {}
            }

            loop {
                if cancel.is_cancelled() {
                    break;
                }

                let due = match engine
                    .seed_manager
                    .list_accounts_due_for_health_check(
                        config.health_check_interval_secs as i64,
                        50,
                    )
                    .await
                {
                    Ok(accounts) => accounts,
                    Err(e) => {
                        tracing::warn!(error = %e, "Failed to query seed accounts for health check");
                        Vec::new()
                    }
                };

                if !due.is_empty() {
                    tracing::info!(count = due.len(), "Running seed account health checks");
                    let poller = ImapPoller::new(config.clone());
                    for account in due {
                        if cancel.is_cancelled() {
                            break;
                        }
                        Self::check_one_account(&engine, &poller, &config, account).await;
                    }
                }

                tokio::select! {
                    _ = cancel.cancelled() => break,
                    _ = tokio::time::sleep(Duration::from_secs(config.health_check_interval_secs)) => {}
                }
            }

            tracing::info!("Placement seed-account health checker stopped");
        });
    }

    /// Probe one seed account's IMAP connectivity and record success/failure.
    /// Auto-disables the account after the configured failure threshold.
    async fn check_one_account(
        engine: &PlacementEngine,
        poller: &ImapPoller,
        config: &PlacementConfig,
        account: crate::types::SeedAccount,
    ) {
        // Pull the (possibly encrypted) password through the engine so the
        // same decryption path is exercised here as during a real test.
        let password = match engine.fetch_account_password_for_health(account.id).await {
            Some(p) => p,
            None => {
                let _ = engine
                    .seed_manager
                    .record_health_failure(
                        account.id,
                        "no IMAP password configured",
                        config.seed_account_failure_threshold,
                    )
                    .await;
                return;
            }
        };

        match poller.health_check(&account, &password).await {
            Ok(()) => {
                let _ = engine.seed_manager.record_health_success(account.id).await;
            }
            Err(e) => {
                let reason = format!("imap probe failed: {e}");
                tracing::warn!(account_id = %account.id, email = %account.email, reason = %reason, "Seed account health probe failed");
                let _ = engine
                    .seed_manager
                    .record_health_failure(
                        account.id,
                        &reason,
                        config.seed_account_failure_threshold,
                    )
                    .await;
            }
        }
    }

    /// Signal the background loop to shut down gracefully.
    pub async fn shutdown(&self) {
        tracing::info!("Shutting down placement scheduler...");
        self.cancel_token.cancel();
    }

    /// Query the database for tests that need execution.
    async fn fetch_pending_tests(
        engine: &PlacementEngine,
        config: &PlacementConfig,
    ) -> Result<Vec<Uuid>, sqlx::Error> {
        // Count how many tests have been started in the last hour (rate limit).
        let one_hour_ago = chrono::Utc::now() - chrono::Duration::hours(1);
        let active_count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM placement_tests \
             WHERE status IN ('Running', 'Pending') \
             AND created_at >= $1",
        )
        .bind(one_hour_ago)
        .fetch_one(&engine.db)
        .await?;

        if active_count.0 >= config.max_tests_per_hour as i64 {
            tracing::debug!(
                active_count = active_count.0,
                max_tests_per_hour = config.max_tests_per_hour,
                "Rate limit reached; skipping scheduler cycle"
            );
            return Ok(Vec::new());
        }

        // Allow room for more tests within the rate limit.
        let remaining = (config.max_tests_per_hour as i64).saturating_sub(active_count.0);

        let rows: Vec<(Uuid,)> = sqlx::query_as(
            "SELECT id FROM placement_tests \
             WHERE status = 'Pending' \
             ORDER BY created_at ASC \
             LIMIT $1",
        )
        .bind(remaining)
        .fetch_all(&engine.db)
        .await?;

        Ok(rows.into_iter().map(|r| r.0).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_scheduler_creation() {
        // Just verify that the struct can be constructed (integration-style
        // tests requiring a DB pool belong in the integration test suite).
        let config = PlacementConfig::default();
        // We can't construct a PlacementEngine without a PgPool in unit tests,
        // but we can check that PlacementScheduler is Send + Sync, and that the
        // default config exposes a usable polling interval.
        fn assert_send_sync<T: Send + Sync>() {}
        assert_send_sync::<PlacementScheduler>();
        assert!(
            config.polling_interval_secs > 0,
            "default polling interval must be positive"
        );
    }
}
