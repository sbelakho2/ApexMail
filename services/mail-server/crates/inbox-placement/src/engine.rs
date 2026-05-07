use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use enterprise::field_encryption::{encryptor_from_secret, FieldEncryptor};
use sqlx::PgPool;
use uuid::Uuid;

use crate::classifier::{classify_folder, delivery_category};
use crate::config::PlacementConfig;
use crate::imap_poller::{ImapPoller, InboxPollResult};
use crate::seed_manager::SeedManager;
use crate::sender::send_test_email;
use crate::types::*;

/// Core orchestration engine for inbox placement testing.
///
/// Coordinates the full lifecycle: test creation, email dispatch via SMTP,
/// delivery detection via IMAP polling, folder classification, result
/// persistence, and score computation.
#[derive(Clone)]
pub struct PlacementEngine {
    pub config: PlacementConfig,
    pub db: PgPool,
    pub seed_manager: SeedManager,
    /// Optional analytics service for ClickHouse-powered trend queries.
    pub analytics: Option<Arc<analytics::inbox_placement::InboxPlacementService>>,
    /// Optional field encryptor used to decrypt stored IMAP passwords. When
    /// `None`, passwords are read as plaintext (development only — not
    /// recommended for production).
    encryptor: Option<Arc<FieldEncryptor>>,
}

impl std::fmt::Debug for PlacementEngine {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("PlacementEngine")
            .field("config", &self.config)
            .field("seed_manager", &self.seed_manager)
            .field("analytics", &self.analytics.is_some())
            .field("encryptor", &self.encryptor.is_some())
            .finish()
    }
}

impl PlacementEngine {
    pub fn new(config: PlacementConfig, db: PgPool) -> Self {
        let encryptor = build_encryptor(&config);
        Self {
            config: config.clone(),
            db: db.clone(),
            seed_manager: SeedManager::new(db),
            analytics: None,
            encryptor,
        }
    }

    /// Construct an engine with an optional analytics client.
    pub fn with_analytics(
        config: PlacementConfig,
        db: PgPool,
        analytics: Option<Arc<analytics::inbox_placement::InboxPlacementService>>,
    ) -> Self {
        let encryptor = build_encryptor(&config);
        Self {
            config: config.clone(),
            db: db.clone(),
            seed_manager: SeedManager::new(db),
            analytics,
            encryptor,
        }
    }

    /// Borrow the field encryptor (if configured). Used by the seed-account
    /// health checker and admin endpoints that need to decrypt passwords.
    pub fn encryptor(&self) -> Option<&Arc<FieldEncryptor>> {
        self.encryptor.as_ref()
    }

    /// Crate-internal accessor used by the scheduler's health-check loop to
    /// reuse the engine's decryption pathway (so encrypted-password handling
    /// stays in one place).
    pub(crate) async fn fetch_account_password_for_health(
        &self,
        account_id: Uuid,
    ) -> Option<String> {
        self.fetch_account_password(account_id).await
    }

    // ── Create Test ──────────────────────────────────────────────

    /// Validate a test request, resolve seed accounts, enforce rate limits,
    /// and persist a new [`PlacementTest`].
    pub async fn create_test(
        &self,
        request: CreateTestRequest,
        tenant_id: Uuid,
    ) -> Result<PlacementTest, sqlx::Error> {
        // 1. Resolve target providers → seed accounts.
        let providers = request.target_providers.unwrap_or_default();
        let accounts = self
            .seed_manager
            .get_accounts_by_provider_names(&providers)
            .await?;

        if accounts.is_empty() {
            return Err(sqlx::Error::Protocol(
                "no active seed accounts available for the requested providers".into(),
            ));
        }

        // Cap to max seeds per test.
        let used_accounts: Vec<Uuid> = accounts
            .iter()
            .take(self.config.max_seeds_per_test)
            .map(|a| a.id)
            .collect();
        let total_accounts = used_accounts.len() as i32;

        // 2. Rate-limit check: count tests created in the last hour.
        let one_hour_ago = Utc::now() - chrono::Duration::hours(1);
        let count: (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM placement_tests \
             WHERE tenant_id = $1 AND created_at >= $2",
        )
        .bind(tenant_id)
        .bind(one_hour_ago)
        .fetch_one(&self.db)
        .await?;

        if count.0 >= self.config.max_tests_per_hour as i64 {
            return Err(sqlx::Error::Protocol(format!(
                "rate limit exceeded: max {} tests per hour",
                self.config.max_tests_per_hour
            )));
        }

        // 3. Insert the test.
        let id = Uuid::new_v4();
        let now = Utc::now();
        let status = "Pending";

        let seed_uuids: Vec<Uuid> = used_accounts.clone();

        sqlx::query(
            "INSERT INTO placement_tests \
             (id, tenant_id, name, status, from_email, subject, \
              total_accounts, completed_accounts, seed_accounts_used, \
              scheduled_for, completed_at, created_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
        )
        .bind(id)
        .bind(tenant_id)
        .bind(&request.name)
        .bind(status)
        .bind(&request.from_email)
        .bind(&request.subject)
        .bind(total_accounts)
        .bind(0i32)
        .bind(&seed_uuids)
        .bind(request.schedule_at)
        .bind(Option::<chrono::DateTime<Utc>>::None)
        .bind(now)
        .execute(&self.db)
        .await?;

        Ok(PlacementTest {
            id,
            tenant_id,
            name: request.name,
            status: status.to_string(),
            from_email: request.from_email,
            subject: request.subject,
            total_accounts,
            completed_accounts: 0,
            seed_accounts_used: seed_uuids,
            scheduled_for: request.schedule_at,
            completed_at: None,
            created_at: now,
        })
    }

    // ── Execute Test ─────────────────────────────────────────────

    /// Run the full test lifecycle:
    /// 1. Mark test as `Running`.
    /// 2. For each seed account, send a test email via SMTP.
    /// 3. Poll the account's IMAP inbox to detect delivery.
    /// 4. Classify the delivery folder.
    /// 5. Persist each [`PlacementResult`].
    /// 6. Mark test as `Completed` (or `Failed` if no accounts succeeded).
    pub async fn execute_test(&self, test_id: Uuid) -> Result<(), sqlx::Error> {
        // 1. Load the test.
        let test = sqlx::query_as::<_, PlacementTest>(
            "SELECT id, tenant_id, name, status, from_email, subject, \
             total_accounts, completed_accounts, seed_accounts_used, \
             scheduled_for, completed_at, created_at \
             FROM placement_tests WHERE id = $1",
        )
        .bind(test_id)
        .fetch_optional(&self.db)
        .await?
        .ok_or_else(|| {
            sqlx::Error::Protocol(format!("placement test {} not found", test_id))
        })?;

        // 2. Mark as Running.
        sqlx::query(
            "UPDATE placement_tests SET status = 'Running' WHERE id = $1",
        )
        .bind(test_id)
        .execute(&self.db)
        .await?;

        let imp = ImapPoller::new(self.config.clone());
        let mut completed = 0i32;
        let total = test.seed_accounts_used.len() as i32;

        // 3. Process each seed account.
        for &account_id in &test.seed_accounts_used {
            // Load account details.
            let account = match self.seed_manager.get_account(account_id).await {
                Ok(Some(a)) => a,
                Ok(None) => {
                    tracing::warn!(test_id = %test_id, account_id = %account_id, "Seed account not found; skipping");
                    continue;
                }
                Err(e) => {
                    tracing::warn!(test_id = %test_id, account_id = %account_id, error = %e, "Failed to load seed account; skipping");
                    continue;
                }
            };

            // Fetch the account password (stored encrypted in DB).
            let password = match self.fetch_account_password(account_id).await {
                Some(p) => p,
                None => {
                    tracing::warn!(test_id = %test_id, account_id = %account_id, "No password found for seed account; skipping");
                    continue;
                }
            };

            // 3a. Send test email.
            if let Err(e) = send_test_email(&account, &password, test_id).await {
                tracing::warn!(
                    test_id = %test_id,
                    account = %account.email,
                    error = %e,
                    "Failed to send test email; continuing with remaining accounts"
                );
                // Record as absent (no result).
                let _ = self
                    .insert_placement_result(
                        test_id,
                        account_id,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                    )
                    .await;
                completed += 1;
                continue;
            }

            // 3b. Poll IMAP inbox.
            let poll_result: InboxPollResult = match imp
                .poll_inbox(
                    &account,
                    &password,
                    test_id,
                    self.config.max_polling_attempts,
                )
                .await
            {
                Ok(r) => r,
                Err(e) => {
                    tracing::warn!(
                        test_id = %test_id,
                        account = %account.email,
                        error = %e,
                        "IMAP polling failed; recording as absent"
                    );
                    let _ = self
                        .insert_placement_result(test_id, account_id, None, None, None, None, None, None)
                        .await;
                    completed += 1;
                    continue;
                }
            };

            // 3c. Classify delivery folder.
            let provider_name = self.resolve_provider_name(account_id).await;
            let inbox_type = poll_result.folder.as_deref().map(|f| {
                let folder = classify_folder(f, &provider_name);
                delivery_category(&folder).to_string()
            });

            // 3d. Persist result.
            if let Err(e) = self
                .insert_placement_result(
                    test_id,
                    account_id,
                    inbox_type.as_deref(),
                    poll_result.response_time_ms,
                    None,  // raw_headers
                    None,  // spf_pass
                    None,  // dkim_pass
                    None,  // dmarc_pass
                )
                .await
            {
                tracing::warn!(
                    test_id = %test_id,
                    account_id = %account_id,
                    error = %e,
                    "Failed to persist placement result"
                );
            }

            completed += 1;
        }

        // 4. Finalise test status.
        let now = Utc::now();
        let new_status = if completed > 0 { "Completed" } else { "Failed" };

        sqlx::query(
            "UPDATE placement_tests SET status = $1, completed_accounts = $2, completed_at = $3 WHERE id = $4",
        )
        .bind(new_status)
        .bind(completed)
        .bind(now)
        .bind(test_id)
        .execute(&self.db)
        .await?;

        // 5. Update health status for each account.
        for &account_id in &test.seed_accounts_used {
            let health = if completed > 0 { "ok" } else { "error" };
            let _ = self
                .seed_manager
                .update_account_health(account_id, health, Utc::now())
                .await;
        }

        tracing::info!(
            test_id = %test_id,
            completed_accounts = completed,
            total_accounts = total,
            status = new_status,
            "Inbox placement test finished"
        );

        // 6. Emit webhook event for subscribers.
        // Failures here are logged but never abort the test transition — webhook
        // delivery is asynchronous and best-effort.
        if let Err(e) = self
            .emit_test_completed_webhook(&test, new_status, completed, total)
            .await
        {
            tracing::warn!(
                test_id = %test_id,
                error = %e,
                "Failed to enqueue placement_test.completed webhook (non-fatal)"
            );
        }

        Ok(())
    }

    /// Enqueue a `placement_test.completed` webhook event for every webhook
    /// subscription on the tenant that is interested in the event (or in `*`).
    async fn emit_test_completed_webhook(
        &self,
        test: &PlacementTest,
        final_status: &str,
        completed_accounts: i32,
        total_accounts: i32,
    ) -> Result<(), sqlx::Error> {
        // Resolve subscribed webhook IDs for this tenant. Matches the same
        // selector contract used by tracking-service::unsubscribe.
        let webhook_ids: Vec<(String,)> = sqlx::query_as(
            r#"SELECT id FROM webhooks
               WHERE tenant_id = $1
                 AND status = 'enabled'
                 AND (events @> '"placement_test.completed"'::jsonb
                      OR events @> '"*"'::jsonb)"#,
        )
        .bind(test.tenant_id.to_string())
        .fetch_all(&self.db)
        .await
        .unwrap_or_default();

        if webhook_ids.is_empty() {
            return Ok(());
        }

        // Pull the per-provider summary so subscribers receive the score
        // alongside the event without an extra round-trip.
        let summary = match self
            .get_test_results(test.id, test.tenant_id)
            .await
        {
            Ok(results) => {
                let score = PlacementScore::calculate(&results);
                serde_json::json!({
                    "results": results,
                    "score": score,
                })
            }
            Err(e) => {
                tracing::warn!(test_id = %test.id, error = %e, "Could not load results for webhook payload");
                serde_json::json!({ "results": [], "score": null })
            }
        };

        let event_id = format!("evt_placement_{}", Uuid::new_v4().simple());
        let payload = serde_json::json!({
            "id": event_id,
            "type": "placement_test.completed",
            "tenantId": test.tenant_id.to_string(),
            "timestamp": Utc::now().to_rfc3339(),
            "data": {
                "test_id": test.id.to_string(),
                "name": test.name,
                "from_email": test.from_email,
                "subject": test.subject,
                "status": final_status,
                "total_accounts": total_accounts,
                "completed_accounts": completed_accounts,
                "results": summary["results"],
                "score": summary["score"],
            }
        });
        let payload_str = payload.to_string();

        let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
            "INSERT INTO webhook_queue \
             (id, webhook_id, tenant_id, event_type, payload, status, attempt, created_at) ",
        );
        let tenant_id_str = test.tenant_id.to_string();
        builder.push_values(&webhook_ids, |mut b, (wid,)| {
            b.push_bind(format!("whj_{}", Uuid::new_v4().simple()))
                .push_bind(wid)
                .push_bind(&tenant_id_str)
                .push_bind("placement_test.completed")
                .push_bind(&payload_str)
                .push_bind("pending")
                .push_bind(1i32)
                .push_unseparated(", NOW()");
        });
        builder.build().execute(&self.db).await?;
        Ok(())
    }

    // ── Get Test Results ─────────────────────────────────────────

    /// Load placement results for a test, group by provider, and compute
    /// per-provider aggregates.
    pub async fn get_test_results(
        &self,
        test_id: Uuid,
        tenant_id: Uuid,
    ) -> Result<Vec<ProviderResult>, sqlx::Error> {
        // Load raw placement results joined with account + provider info.
        // Tenant scoping: join through placement_tests to filter by tenant_id.
        let rows = sqlx::query_as::<_, PlacementResultRow>(
            r#"SELECT pr.id, pr.test_id, pr.seed_account_id, pr.inbox_type,
                      pr.delivery_time_ms, pr.raw_headers,
                      pr.spf_pass, pr.dkim_pass, pr.dmarc_pass, pr.checked_at,
                      sp.name AS provider_name
               FROM placement_results pr
               JOIN placement_tests pt ON pt.id = pr.test_id
               JOIN seed_accounts sa ON sa.id = pr.seed_account_id
               JOIN seed_providers sp ON sp.id = sa.provider_id
               WHERE pr.test_id = $1 AND pt.tenant_id = $2
               ORDER BY sp.name"#,
        )
        .bind(test_id)
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await?;

        if rows.is_empty() {
            return Ok(Vec::new());
        }

        // Group by provider.
        let mut grouped: HashMap<String, Vec<&PlacementResultRow>> = HashMap::new();
        for row in &rows {
            grouped
                .entry(row.provider_name.clone())
                .or_default()
                .push(row);
        }

        let mut results = Vec::with_capacity(grouped.len());
        for (provider, group) in grouped {
            let accounts_tested = group.len() as i32;
            let mut inbox = 0i32;
            let mut promotions = 0i32;
            let mut spam = 0i32;
            let mut absent = 0i32;
            let mut total_delivery_ms: f64 = 0.0;
            let mut delivery_count = 0i32;
            let mut spf_ok = 0i32;
            let mut dkim_ok = 0i32;
            let mut dmarc_ok = 0i32;
            let mut auth_count = 0i32;

            for row in &group {
                match row.inbox_type.as_deref() {
                    Some("inbox") => inbox += 1,
                    Some("promotions") => promotions += 1,
                    Some("spam") => spam += 1,
                    _ => absent += 1,
                }

                if let Some(ms) = row.delivery_time_ms {
                    total_delivery_ms += ms as f64;
                    delivery_count += 1;
                }

                // Authentication checks (only count if we have data).
                if row.spf_pass.is_some() {
                    if row.spf_pass == Some(true) {
                        spf_ok += 1;
                    }
                    auth_count += 1;
                }
                if row.dkim_pass.is_some() {
                    if row.dkim_pass == Some(true) {
                        dkim_ok += 1;
                    }
                }
                if row.dmarc_pass.is_some() {
                    if row.dmarc_pass == Some(true) {
                        dmarc_ok += 1;
                    }
                }
            }

            let avg_delivery_time_ms = if delivery_count > 0 {
                total_delivery_ms / delivery_count as f64
            } else {
                0.0
            };

            let spf_pass_rate = if auth_count > 0 {
                spf_ok as f64 / auth_count as f64
            } else {
                0.0
            };
            let dkim_pass_rate = if auth_count > 0 {
                dkim_ok as f64 / auth_count as f64
            } else {
                0.0
            };
            let dmarc_pass_rate = if auth_count > 0 {
                dmarc_ok as f64 / auth_count as f64
            } else {
                0.0
            };

            let recommendation = generate_recommendation(
                inbox as f64 / accounts_tested as f64,
                &provider,
            );

            results.push(ProviderResult {
                provider,
                accounts_tested,
                inbox,
                promotions,
                spam,
                absent,
                avg_delivery_time_ms,
                spf_pass_rate,
                dkim_pass_rate,
                dmarc_pass_rate,
                recommendation,
            });
        }

        Ok(results)
    }

    // ── Get Placement Score ──────────────────────────────────────

    /// Compute the aggregate [`PlacementScore`] for a completed test.
    pub async fn get_placement_score(
        &self,
        test_id: Uuid,
        _tenant_id: Uuid,
    ) -> Result<PlacementScore, sqlx::Error> {
        let results = self.get_test_results(test_id, _tenant_id).await?;
        Ok(PlacementScore::calculate(&results))
    }

    // ── Get Trends ───────────────────────────────────────────────

    /// Retrieve historical placement trends by querying the
    /// `placement_results` table, grouped by date.
    pub async fn get_trends(
        &self,
        tenant_id: Uuid,
        days: i32,
        provider: Option<ProviderName>,
    ) -> Result<Vec<PlacementTrend>, sqlx::Error> {
        let since = Utc::now() - chrono::Duration::days(days as i64);

        let rows = if let Some(ref prov) = provider {
            sqlx::query_as::<_, TrendRow>(
                r#"SELECT DATE(pr.checked_at)::text AS day,
                          pr.inbox_type,
                          COUNT(*) AS cnt
                   FROM placement_results pr
                   JOIN placement_tests pt ON pt.id = pr.test_id
                   JOIN seed_accounts sa ON sa.id = pr.seed_account_id
                   JOIN seed_providers sp ON sp.id = sa.provider_id
                   WHERE pt.tenant_id = $1
                     AND pr.checked_at >= $2
                     AND LOWER(sp.name) = LOWER($3)
                   GROUP BY day, pr.inbox_type
                   ORDER BY day"#,
            )
            .bind(tenant_id)
            .bind(since)
            .bind(prov.to_string())
            .fetch_all(&self.db)
            .await?
        } else {
            sqlx::query_as::<_, TrendRow>(
                r#"SELECT DATE(pr.checked_at)::text AS day,
                          pr.inbox_type,
                          COUNT(*) AS cnt
                   FROM placement_results pr
                   JOIN placement_tests pt ON pt.id = pr.test_id
                   WHERE pt.tenant_id = $1
                     AND pr.checked_at >= $2
                   GROUP BY day, pr.inbox_type
                   ORDER BY day"#,
            )
            .bind(tenant_id)
            .bind(since)
            .fetch_all(&self.db)
            .await?
        };

        // Group by day and compute percentages.
        let mut by_day: std::collections::BTreeMap<String, (f64, f64, f64, f64)> =
            std::collections::BTreeMap::new(); // (inbox, promotions, spam, absent) counts

        for row in &rows {
            let entry = by_day
                .entry(row.day.clone())
                .or_insert((0.0, 0.0, 0.0, 0.0));
            let cnt = row.cnt as f64;
            match row.inbox_type.as_deref() {
                Some("inbox") => entry.0 += cnt,
                Some("promotions") => entry.1 += cnt,
                Some("spam") => entry.2 += cnt,
                _ => entry.3 += cnt,
            }
        }

        Ok(by_day
            .into_iter()
            .map(|(date, (inbox, promotions, spam, absent))| {
                let total = inbox + promotions + spam + absent;
                let (inbox_pct, promotions_pct, spam_pct, _absent_pct) = if total > 0.0 {
                    (
                        (inbox / total) * 100.0,
                        (promotions / total) * 100.0,
                        (spam / total) * 100.0,
                        (absent / total) * 100.0,
                    )
                } else {
                    (0.0, 0.0, 0.0, 0.0)
                };
                PlacementTrend {
                    date,
                    inbox_pct,
                    promotions_pct,
                    spam_pct,
                }
            })
            .collect())
    }

    // ── Internal Helpers ─────────────────────────────────────────

    /// Fetch the account password from `seed_accounts.imap_password_encrypted`.
    ///
    /// When a [`FieldEncryptor`] is configured, the value is decrypted via the
    /// envelope-encryption scheme defined in
    /// [`enterprise::field_encryption`].  Plaintext values (without the
    /// `ENC:v1:` prefix) are returned as-is to support gradual migration of
    /// legacy seed accounts.
    async fn fetch_account_password(&self, account_id: Uuid) -> Option<String> {
        let row: Result<(Option<String>,), _> = sqlx::query_as(
            "SELECT imap_password_encrypted FROM seed_accounts WHERE id = $1",
        )
        .bind(account_id)
        .fetch_one(&self.db)
        .await;

        let raw = match row {
            Ok((Some(pw),)) if !pw.is_empty() => pw,
            Ok(_) => {
                tracing::warn!(account_id = %account_id, "Seed account has no stored IMAP password");
                return None;
            }
            Err(e) => {
                tracing::warn!(account_id = %account_id, error = %e, "Could not fetch account password");
                return None;
            }
        };

        match self.encryptor.as_ref() {
            Some(enc) => match enc.decrypt(&raw) {
                Ok(plain) => Some(plain),
                Err(e) => {
                    tracing::error!(
                        account_id = %account_id,
                        error = %e,
                        "Failed to decrypt IMAP password; check PLACEMENT_ENCRYPTION_SECRET"
                    );
                    None
                }
            },
            None => {
                if raw.starts_with("ENC:") {
                    tracing::error!(
                        account_id = %account_id,
                        "Encrypted IMAP password found but no PLACEMENT_ENCRYPTION_SECRET configured"
                    );
                    return None;
                }
                Some(raw)
            }
        }
    }

    /// Resolve the provider name for a seed account by joining through
    /// `seed_accounts.provider_id → seed_providers.name`.
    async fn resolve_provider_name(&self, account_id: Uuid) -> ProviderName {
        let row: Result<(String,), _> = sqlx::query_as(
            "SELECT sp.name FROM seed_accounts sa \
             JOIN seed_providers sp ON sp.id = sa.provider_id \
             WHERE sa.id = $1",
        )
        .bind(account_id)
        .fetch_one(&self.db)
        .await;

        match row {
            Ok((name,)) => ProviderName::from_str(&name),
            Err(_) => ProviderName::Other("unknown".into()),
        }
    }

    /// Insert a single placement result row.
    #[allow(clippy::too_many_arguments)]
    async fn insert_placement_result(
        &self,
        test_id: Uuid,
        seed_account_id: Uuid,
        inbox_type: Option<&str>,
        delivery_time_ms: Option<i64>,
        raw_headers: Option<&str>,
        spf_pass: Option<bool>,
        dkim_pass: Option<bool>,
        dmarc_pass: Option<bool>,
    ) -> Result<(), sqlx::Error> {
        let id = Uuid::new_v4();
        let now = Utc::now();

        sqlx::query(
            "INSERT INTO placement_results \
             (id, test_id, seed_account_id, inbox_type, delivery_time_ms, \
              raw_headers, spf_pass, dkim_pass, dmarc_pass, checked_at) \
             VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)",
        )
        .bind(id)
        .bind(test_id)
        .bind(seed_account_id)
        .bind(inbox_type)
        .bind(delivery_time_ms.map(|v| v as i32))
        .bind(raw_headers)
        .bind(spf_pass)
        .bind(dkim_pass)
        .bind(dmarc_pass)
        .bind(now)
        .execute(&self.db)
        .await?;

        Ok(())
    }
}

// ── Internal Row Types ──────────────────────────────────────────────

/// Query row that joins `placement_results` with provider info.
#[derive(Debug, Clone, sqlx::FromRow)]
#[allow(dead_code)]
struct PlacementResultRow {
    pub id: Uuid,
    pub test_id: Uuid,
    pub seed_account_id: Uuid,
    pub inbox_type: Option<String>,
    pub delivery_time_ms: Option<i32>,
    pub raw_headers: Option<String>,
    pub spf_pass: Option<bool>,
    pub dkim_pass: Option<bool>,
    pub dmarc_pass: Option<bool>,
    pub checked_at: chrono::DateTime<Utc>,
    pub provider_name: String,
}

/// Query row for trend aggregation.
#[derive(Debug, Clone, sqlx::FromRow)]
struct TrendRow {
    pub day: String,
    pub inbox_type: Option<String>,
    pub cnt: i64,
}

// ── ProviderName helper ────────────────────────────────────────────

impl ProviderName {
    /// Construct a [`ProviderName`] from a string (case-insensitive).
    pub fn from_str(s: &str) -> Self {
        match s.to_lowercase().as_str() {
            "gmail" => ProviderName::Gmail,
            "outlook" => ProviderName::Outlook,
            "yahoo" => ProviderName::Yahoo,
            "icloud" => ProviderName::Icloud,
            "aol" => ProviderName::Aol,
            "zoho" => ProviderName::Zoho,
            "protonmail" => ProviderName::Protonmail,
            "gmx" => ProviderName::Gmx,
            "yandex" => ProviderName::Yandex,
            other => ProviderName::Other(other.to_string()),
        }
    }
}

impl std::fmt::Display for ProviderName {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProviderName::Gmail => write!(f, "gmail"),
            ProviderName::Outlook => write!(f, "outlook"),
            ProviderName::Yahoo => write!(f, "yahoo"),
            ProviderName::Icloud => write!(f, "icloud"),
            ProviderName::Aol => write!(f, "aol"),
            ProviderName::Zoho => write!(f, "zoho"),
            ProviderName::Protonmail => write!(f, "protonmail"),
            ProviderName::Gmx => write!(f, "gmx"),
            ProviderName::Yandex => write!(f, "yandex"),
            ProviderName::Other(s) => write!(f, "{}", s),
        }
    }
}

// ── Recommendation Logic ──────────────────────────────────────────

/// Generate a brief recommendation for a provider based on inbox rate.
fn generate_recommendation(inbox_rate: f64, provider: &str) -> String {
    if inbox_rate >= 0.95 {
        format!(
            "Excellent inbox placement ({}%) for {}. No action needed.",
            (inbox_rate * 100.0) as u32,
            provider
        )
    } else if inbox_rate >= 0.85 {
        format!(
            "Good inbox placement ({}%) for {}. Monitor for changes.",
            (inbox_rate * 100.0) as u32,
            provider
        )
    } else if inbox_rate >= 0.70 {
        format!(
            "Moderate inbox placement ({}%) for {}. Review authentication and content practices.",
            (inbox_rate * 100.0) as u32,
            provider
        )
    } else {
        format!(
            "Poor inbox placement ({}%) for {}. Check SPF/DKIM/DMARC, sender reputation, and email content.",
            (inbox_rate * 100.0) as u32,
            provider
        )
    }
}

// ── Encryption Bootstrap ─────────────────────────────────────────────

/// Build a [`FieldEncryptor`] from the configured `PLACEMENT_ENCRYPTION_SECRET`,
/// or `None` when no secret is supplied.
///
/// Errors during KEK derivation are logged and treated as "no encryptor"
/// so the engine still starts in development without a secret. Production
/// deployments should always set the secret.
fn build_encryptor(config: &PlacementConfig) -> Option<Arc<FieldEncryptor>> {
    let secret = config.encryption_secret.as_deref()?;
    if !config.encrypt_stored_passwords {
        return None;
    }
    match encryptor_from_secret(secret, "inbox-placement::imap-password") {
        Ok(enc) => Some(Arc::new(enc)),
        Err(e) => {
            tracing::error!(error = %e, "Failed to derive PLACEMENT_ENCRYPTION_SECRET; password decryption disabled");
            None
        }
    }
}
