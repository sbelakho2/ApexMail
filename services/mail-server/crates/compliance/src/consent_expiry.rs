//! Consent expiry enforcement background job.
//!
//! Periodically scans the `consent_records` table for consents whose
//! `expires_at` has passed, revokes them, and writes audit log entries.
//! Marketing → analytics → profiling cascade is also enforced.
//!
//! P3 (perf): the sweep is BATCHED and set-based. The pre-fix job selected
//! every expired row unbounded, then opened one transaction per row (UPDATE +
//! up to two cascade UPDATEs + an upsert + commit), O(rows) round trips and
//! row locks held one row at a time. Now each pass revokes up to
//! [`CONSENT_EXPIRY_BATCH`] rows with ONE `UPDATE … WHERE id IN (SELECT id …
//! ORDER BY id LIMIT n) RETURNING …`, then runs ONE set-based cascade UPDATE
//! and a chunked cascade upsert, all in the SAME transaction as the
//! revocation. Audit logging stays per row (the hash-chained audit trail is
//! not the storage path being fixed).
//!
//! Index this path relies on (sibling migration; the query is correct without
//! it, just slower on large tables):
//!
//! ```sql
//! CREATE INDEX IF NOT EXISTS idx_consent_records_expiry
//!     ON consent_records (granted, expires_at)
//!     WHERE granted = true AND expires_at IS NOT NULL;
//! ```
//!
//! # Scheduling (dead-by-omission fix)
//!
//! This module used to be an orphan: `lib.rs` declared `pub mod consent_expiry`
//! but no production code ever constructed the job, so expired consents were
//! never revoked. The ONE production driver is now the compliance server's
//! cron loop (`crates/compliance/src/bin/server.rs`, cron job 10): it owns a
//! single [`ConsentExpiryJob`] and calls [`ConsentExpiryJob::check_and_revoke_expired`]
//! every [`check_interval_secs`] (the live `CONSENT_EXPIRY_CHECK_INTERVAL_SECS`
//! setting, defaulting to [`DEFAULT_CONSENT_EXPIRY_INTERVAL_SECS`]). There is
//! no second sweeping loop: `check_and_revoke_expired` is also the documented
//! one-shot/standalone entry (used by tests and by operators for a manual
//! pass), and the job holds no timer of its own.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tracing::{info, warn};
use uuid::Uuid;

use crate::audit_logger::{AuditBatchEntry, AuditLogger};
use crate::types::{AuditAction, AuditOutcome, AuditResource, LogContext};

/// Rows revoked per pass (P3): bounds the lock window and the statement size.
const CONSENT_EXPIRY_BATCH: i64 = 5_000;

/// Rows per cascade-upsert INSERT.
///
/// One expired `marketing` row cascades to [`MARKETING_CASCADE_TARGETS`], so a
/// full 5,000-row batch wants up to 10,000 upsert rows. The upsert binds 6
/// parameters per row (id, tenant, subscriber, email, type, revoked_at), and
/// PostgreSQL rejects statements above 65,535 bound parameters, an unbounded
/// `push_values` silently failed the whole cascade while the revoke reported
/// success. 5,000 rows = 30,000 binds stays under the ceiling.
const CASCADE_UPSERT_CHUNK_ROWS: usize = 5_000;

/// Cascade targets of an expired `marketing` consent, the consent hierarchy.
const MARKETING_CASCADE_TARGETS: &[&str] = &["analytics", "profiling"];

/// Default tick period for the consent-expiry cron arm, in seconds.
pub const DEFAULT_CONSENT_EXPIRY_INTERVAL_SECS: u64 = 3600;

/// The environment variable that holds the consent-expiry tick period.
pub const CONSENT_EXPIRY_INTERVAL_ENV: &str = "CONSENT_EXPIRY_CHECK_INTERVAL_SECS";

/// The LIVE cron tick period for the consent-expiry arm.
///
/// `CONSENT_EXPIRY_CHECK_INTERVAL_SECS` is read at process start (the cron
/// loop is built once): a positive integer number of seconds, anything else
/// falls back to [`DEFAULT_CONSENT_EXPIRY_INTERVAL_SECS`]. Zero is rejected —
/// `tokio::time::interval` panics on a zero period, which would take the whole
/// cron loop (and every other job) down.
pub fn check_interval_secs() -> u64 {
    parse_check_interval_secs(std::env::var(CONSENT_EXPIRY_INTERVAL_ENV).ok().as_deref())
}

/// The pure parsing rule behind [`check_interval_secs`] (unit-testable
/// without mutating the process environment).
pub fn parse_check_interval_secs(raw: Option<&str>) -> u64 {
    raw.and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|secs| *secs > 0)
        .unwrap_or(DEFAULT_CONSENT_EXPIRY_INTERVAL_SECS)
}

pub struct ConsentExpiryJob {
    db: PgPool,
    audit_logger: Arc<AuditLogger>,
    /// Rows revoked per pass, [`CONSENT_EXPIRY_BATCH`] in production; the
    /// tests shrink it to exercise the multi-batch loop on a small fixture.
    batch_rows: i64,
    /// Rows per cascade-upsert INSERT, [`CASCADE_UPSERT_CHUNK_ROWS`] in
    /// production; tests shrink it to cross the parameter-boundary fixture.
    cascade_chunk_rows: usize,
    /// Number of upsert statements the last pass issued (tests prove the
    /// chunk boundary was crossed; not used in production).
    #[cfg(test)]
    cascade_upsert_statements: std::sync::atomic::AtomicUsize,
}

impl ConsentExpiryJob {
    /// Build the job. The tick period is owned by the server's cron loop
    /// (`check_interval_secs`), not by the job: this type is the sweep, not a
    /// second timer.
    pub fn new(db: PgPool, audit_logger: Arc<AuditLogger>) -> Self {
        Self {
            db,
            audit_logger,
            batch_rows: CONSENT_EXPIRY_BATCH,
            cascade_chunk_rows: CASCADE_UPSERT_CHUNK_ROWS,
            #[cfg(test)]
            cascade_upsert_statements: std::sync::atomic::AtomicUsize::new(0),
        }
    }

    /// Test-only: run the same loop with a smaller batch. The loop and the
    /// SQL are identical; only the LIMIT changes, so a small fixture still
    /// proves the sweep drains more than one batch.
    #[cfg(test)]
    fn with_batch_rows(db: PgPool, audit_logger: Arc<AuditLogger>, batch_rows: i64) -> Self {
        let mut job = Self::new(db, audit_logger);
        job.batch_rows = batch_rows.max(1);
        job
    }

    /// Test-only: shrink the cascade-upsert chunk so a small fixture crosses
    /// the chunk boundary (the production constant is pinned by a test).
    #[cfg(test)]
    fn with_cascade_chunk_rows(mut self, cascade_chunk_rows: usize) -> Self {
        self.cascade_chunk_rows = cascade_chunk_rows.max(1);
        self
    }

    /// Revoke every expired consent, one bounded batch at a time. This is the
    /// one-shot/standalone entry: the compliance cron loop calls it on every
    /// tick, and tests/operators call it directly for a single pass. Returns
    /// the number of consents revoked by this pass.
    pub async fn check_and_revoke_expired(&self) -> Result<usize, String> {
        let now = Utc::now();
        let mut total = 0usize;
        loop {
            let revoked = self.revoke_expired_batch(now).await?;
            if revoked == 0 {
                break;
            }
            total += revoked;
        }
        if total > 0 {
            info!(count = total, "Revoking expired consents");
        }
        Ok(total)
    }

    /// One batch: revoke up to [`CONSENT_EXPIRY_BATCH`] expired consents and
    /// run the cascade for the batch, then write the per-row audit entries.
    /// Returns the number of rows actually revoked (0 = nothing left).
    ///
    /// The revocation, the set-based cascade UPDATE **and the chunked cascade
    /// upsert** share ONE transaction: a crash (or a failed upsert) can never
    /// leave revoked consents without their cascade rows, and the caller sees
    /// the error instead of a silently-skipped cascade. Audit logging stays
    /// post-commit (best-effort, as before).
    async fn revoke_expired_batch(&self, now: DateTime<Utc>) -> Result<usize, String> {
        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("DB begin: {e}"))?;

        // ONE statement revokes the whole batch. `granted = true` appears both
        // in the selecting subquery and on the outer UPDATE: a concurrent
        // revoker's row is re-checked under the row lock (EvalPlanQual) and
        // simply not returned, the same "already revoked → skip and write no
        // audit entry" behavior the per-row `rows_affected == 0` guard had.
        let revoked: Vec<ExpiredConsent> = sqlx::query_as(
            "UPDATE consent_records
                SET granted = false, revoked_at = $2
              WHERE granted = true
                AND id IN (
                    SELECT id FROM consent_records
                     WHERE granted = true AND expires_at < $1
                     ORDER BY id
                     LIMIT $3
                )
              RETURNING id, tenant_id, subscriber_id, email, consent_type",
        )
        .bind(now)
        .bind(now)
        .bind(self.batch_rows)
        .fetch_all(&mut *tx)
        .await
        .map_err(|e| format!("Revoke expired consents: {e}"))?;

        if revoked.is_empty() {
            tx.commit().await.map_err(|e| format!("DB commit: {e}"))?;
            return Ok(0);
        }

        // Cascade: marketing → analytics → profiling, set-based for the batch
        // and atomic with the revocation above (same transaction). The chunked
        // upsert is INSIDE the transaction too (it was a warned-and-ignored
        // post-commit statement before): its failure rolls the whole batch
        // back and propagates to the caller.
        let cascaded = self.cascade_revocations_tx(&mut tx, &revoked, now).await?;
        self.cascade_upsert_tx(&mut tx, &revoked, &cascaded, now)
            .await?;
        tx.commit().await.map_err(|e| format!("DB commit: {e}"))?;

        // Audit trail: ONE batched append per revoked batch (P2). The batch
        // writer groups by tenant, takes each tenant's advisory chain lock
        // once, reads the chain head once, computes the chained hashes in
        // memory and writes a chunked multi-row INSERT, instead of
        // BEGIN + lock + head read + INSERT + COMMIT per revoked consent.
        let audit_entries: Vec<AuditBatchEntry> = revoked
            .iter()
            .map(|consent| {
                let cascade_targets = cascade_targets_for(&consent.consent_type);

                info!(
                    id = %consent.id,
                    tenant_id = %consent.tenant_id,
                    email = %mail_common::pii::redact_email(&consent.email),
                    consent_type = %consent.consent_type,
                    "Consent auto-revoked (expired)"
                );

                AuditBatchEntry {
                    action: AuditAction::Update,
                    resource: AuditResource::Consent,
                    resource_id: Some(consent.tenant_id.clone()),
                    details: serde_json::json!({
                        "consent_id": consent.id,
                        "consent_type": consent.consent_type,
                        "email": consent.email,
                        "action": "auto_revoked",
                        "reason": "consent_expired",
                        "cascade": cascade_targets,
                        "revoked_at": now.to_rfc3339(),
                    }),
                    outcome: AuditOutcome::Success,
                    error_message: None,
                    context: LogContext {
                        tenant_id: Some(consent.tenant_id.clone()),
                        user_id: None,
                        session_id: None,
                        ip_address: None,
                        user_agent: None,
                    },
                }
            })
            .collect();

        if !audit_entries.is_empty() {
            if let Err(e) = self.audit_logger.log_batch(&audit_entries).await {
                warn!(
                    error = %e,
                    revoked = audit_entries.len(),
                    "Failed to write batched audit log for consent expiry"
                );
            }
        }

        Ok(revoked.len())
    }

    /// The `marketing` cascade for a whole batch: ONE set-based `UPDATE`
    /// revoking every `analytics`/`profiling` row belonging to the batch's
    /// `(tenant_id, email)` pairs (the pre-fix code ran this once per row ×
    /// target), returning which `(tenant, email, target)` pairs actually had
    /// rows revoked. Runs inside the batch transaction.
    async fn cascade_revocations_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        revoked: &[ExpiredConsent],
        now: DateTime<Utc>,
    ) -> Result<Vec<(String, String, String)>, String> {
        let marketing: Vec<&ExpiredConsent> = revoked
            .iter()
            .filter(|consent| consent.consent_type == "marketing")
            .collect();
        if marketing.is_empty() {
            return Ok(Vec::new());
        }

        let tenants: Vec<String> = marketing.iter().map(|c| c.tenant_id.clone()).collect();
        let emails: Vec<String> = marketing.iter().map(|c| c.email.clone()).collect();
        let targets: Vec<String> = MARKETING_CASCADE_TARGETS
            .iter()
            .map(|target| (*target).to_string())
            .collect();

        let cascaded: Vec<(String, String, String)> = sqlx::query_as(
            "UPDATE consent_records c
                SET granted = false, revoked_at = $3
               FROM (
                   SELECT DISTINCT tenant_id, email
                     FROM unnest($1::text[], $2::text[]) AS m(tenant_id, email)
               ) AS m
              WHERE c.tenant_id = m.tenant_id
                AND c.email = m.email
                AND c.consent_type = ANY($4)
                AND c.granted = true
              RETURNING c.tenant_id, c.email, c.consent_type",
        )
        .bind(&tenants)
        .bind(&emails)
        .bind(now)
        .bind(&targets)
        .fetch_all(&mut **tx)
        .await
        .map_err(|e| format!("Cascade revocation: {e}"))?;

        for (tenant_id, email, cascade_type) in &cascaded {
            info!(
                tenant_id = %tenant_id,
                email = %mail_common::pii::redact_email(email),
                cascade_type = %cascade_type,
                "Consent cascaded (auto-revoked from expired marketing)"
            );
        }

        Ok(cascaded)
    }

    /// The upsert the pre-fix code ran per (row × target) whose cascade
    /// UPDATE hit: guarantee a revoked row EXISTS for every
    /// `(tenant_id, subscriber_id, target)` of the cascaded pairs.
    ///
    /// Runs INSIDE the batch transaction and in
    /// [`CASCADE_UPSERT_CHUNK_ROWS`]-row statements: one unbounded
    /// `push_values` (up to 10,000 rows × 6 binds) exceeded PostgreSQL's
    /// 65,535-parameter ceiling, and running it after COMMIT meant that
    /// failure only produced a warning while the revocation stood.
    async fn cascade_upsert_tx(
        &self,
        tx: &mut sqlx::Transaction<'_, sqlx::Postgres>,
        revoked: &[ExpiredConsent],
        cascaded: &[(String, String, String)],
        now: DateTime<Utc>,
    ) -> Result<(), String> {
        if cascaded.is_empty() {
            return Ok(());
        }
        let marketing: Vec<&ExpiredConsent> = revoked
            .iter()
            .filter(|consent| consent.consent_type == "marketing")
            .collect();

        // (tenant_id, subscriber_id, email, consent_type) for every cascade
        // hit, carrying the expired marketing row's subscriber identity and
        // address (exactly the row the per-row upsert used to write). The
        // (tenant, email) subscriber index keeps this O(rows) instead of
        // scanning every marketing row per cascade hit.
        let mut subscribers: HashMap<(&str, &str), Vec<&str>> = HashMap::new();
        for consent in &marketing {
            subscribers
                .entry((consent.tenant_id.as_str(), consent.email.as_str()))
                .or_default()
                .push(consent.subscriber_id.as_str());
        }
        let mut wanted: Vec<(String, String, String, String)> = Vec::new();
        for (tenant, email, target) in cascaded {
            let Some(subscriber_ids) = subscribers.get(&(tenant.as_str(), email.as_str())) else {
                continue;
            };
            for subscriber_id in subscriber_ids {
                wanted.push((
                    tenant.clone(),
                    (*subscriber_id).to_string(),
                    email.clone(),
                    target.clone(),
                ));
            }
        }
        wanted.sort();
        wanted.dedup();

        // Atomicity + chunking: every chunk is its own INSERT ... ON CONFLICT
        // statement inside the SAME transaction, so a failure in any chunk
        // rolls back the revocations and cascades with it.
        for chunk in wanted.chunks(self.cascade_chunk_rows.max(1)) {
            #[cfg(test)]
            self.cascade_upsert_statements
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            let mut builder = sqlx::QueryBuilder::<sqlx::Postgres>::new(
                "INSERT INTO consent_records
                 (id, tenant_id, subscriber_id, email, consent_type, granted,
                  granted_at, revoked_at, source, expires_at, metadata)
                 ",
            );
            builder.push_values(
                chunk,
                |mut b, (tenant_id, subscriber_id, email, consent_type)| {
                    b.push_bind(Uuid::new_v4().to_string())
                        .push_bind(tenant_id.clone())
                        .push_bind(subscriber_id.clone())
                        .push_bind(email.clone())
                        .push_bind(consent_type.clone())
                        .push_bind(false)
                        .push("NULL")
                        .push_bind(now)
                        .push_bind("system")
                        .push("NULL")
                        .push("'{}'::jsonb");
                },
            );
            builder.push(
                " ON CONFLICT (tenant_id, subscriber_id, consent_type) DO UPDATE SET
                    granted = false,
                    source = 'system',
                    revoked_at = EXCLUDED.revoked_at,
                    expires_at = NULL",
            );
            builder
                .build()
                .execute(&mut **tx)
                .await
                .map_err(|e| format!("Cascade upsert: {e}"))?;
        }

        Ok(())
    }
}

/// The cascade targets for a consent type (empty for everything but
/// `marketing`), shared by the cascade and the audit entry.
fn cascade_targets_for(consent_type: &str) -> Vec<&'static str> {
    if consent_type == "marketing" {
        MARKETING_CASCADE_TARGETS.to_vec()
    } else {
        Vec::new()
    }
}

#[derive(sqlx::FromRow)]
struct ExpiredConsent {
    id: String,
    tenant_id: String,
    subscriber_id: String,
    email: String,
    consent_type: String,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::config::AuditConfig;

    /// A canonical database for the DB-gated consent-expiry tests (same
    /// fixture contract as the rest of the crate: the production migrator's
    /// chain, soft-skip only when TEST_DATABASE_URL is unset).
    async fn consent_db(test_name: &str) -> Option<PgPool> {
        match migrator::test_support::fresh_canonical_pool(test_name, test_name).await {
            Ok(pool) => pool,
            Err(error) => panic!("{}", error.panic_message()),
        }
    }

    async fn quiet_audit(pool: &PgPool) -> AuditLogger {
        let logger = AuditLogger::new(
            pool.clone(),
            AuditConfig {
                retention_days: 365,
                hash_chain_enabled: true,
                signing_key: "consent-expiry-test-key".into(),
            },
        );
        logger.initialize().await.expect("audit init");
        logger
    }

    /// Seed one consent row. `expires_in_hours` < 0 ⇒ already expired.
    async fn seed_consent(
        pool: &PgPool,
        tenant: &str,
        subscriber: &str,
        email: &str,
        consent_type: &str,
        granted: bool,
        expires_in_hours: Option<i64>,
    ) {
        sqlx::query(
            "INSERT INTO consent_records
               (id, tenant_id, subscriber_id, email, consent_type, granted,
                granted_at, source, expires_at)
             VALUES ($1, $2, $3, $4, $5, $6, NOW(), 'api',
                     CASE WHEN $7::bigint IS NULL THEN NULL
                          ELSE NOW() + ($7 || ' hours')::interval END)",
        )
        .bind(Uuid::new_v4().to_string())
        .bind(tenant)
        .bind(subscriber)
        .bind(email)
        .bind(consent_type)
        .bind(granted)
        .bind(expires_in_hours.map(|h| h.to_string()))
        .execute(pool)
        .await
        .expect("seed consent");
    }

    async fn cascade_state(
        pool: &PgPool,
        tenant: &str,
        subscriber: &str,
        email: &str,
    ) -> Vec<(String, bool, bool)> {
        sqlx::query_as(
            "SELECT consent_type, granted, revoked_at IS NOT NULL
               FROM consent_records
              WHERE tenant_id = $1 AND subscriber_id = $2 AND email = $3
              ORDER BY consent_type",
        )
        .bind(tenant)
        .bind(subscriber)
        .bind(email)
        .fetch_all(pool)
        .await
        .expect("cascade state")
    }

    /// P3 item 8, equivalence: an expired marketing consent revokes itself
    /// and cascades to analytics + profiling, an expired non-marketing consent
    /// revokes only itself, a live consent is untouched, and the audit trail
    /// gets one entry per revoked row (all exactly as the per-row job did).
    #[tokio::test]
    async fn batched_expiry_preserves_the_cascade_and_audit_effects() {
        let Some(pool) = consent_db("consent_expiry_equiv").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let tenant = "t_consent_equiv_a";
        let email = "cascade@example.test";
        // Marketing: expired. Analytics/profiling for the same subject:
        // granted, NO expiry (they only leave through the cascade).
        seed_consent(&pool, tenant, "sub-1", email, "marketing", true, Some(-1)).await;
        seed_consent(&pool, tenant, "sub-1", email, "analytics", true, None).await;
        seed_consent(&pool, tenant, "sub-1", email, "profiling", true, None).await;
        // A second subject's analytics row must NOT cascade (different email).
        seed_consent(
            &pool,
            tenant,
            "sub-2",
            "other@example.test",
            "analytics",
            true,
            None,
        )
        .await;
        // An expired non-marketing consent: revoked, no cascade.
        seed_consent(
            &pool,
            tenant,
            "sub-3",
            "news@example.test",
            "newsletter",
            true,
            Some(-5),
        )
        .await;
        // A live, still-valid consent: untouched.
        seed_consent(
            &pool,
            tenant,
            "sub-4",
            "live@example.test",
            "marketing",
            true,
            Some(48),
        )
        .await;

        let audit = Arc::new(quiet_audit(&pool).await);
        let job = ConsentExpiryJob::new(pool.clone(), audit.clone());
        job.check_and_revoke_expired().await.expect("sweep runs");

        let state = cascade_state(&pool, tenant, "sub-1", email).await;
        assert_eq!(
            state,
            vec![
                ("analytics".to_string(), false, true),
                ("marketing".to_string(), false, true),
                ("profiling".to_string(), false, true),
            ],
            "marketing cascades to analytics + profiling, all revoked"
        );
        assert_eq!(
            cascade_state(&pool, tenant, "sub-2", "other@example.test").await,
            vec![("analytics".to_string(), true, false)],
            "a different subject's consent is not cascaded"
        );
        assert_eq!(
            cascade_state(&pool, tenant, "sub-3", "news@example.test").await,
            vec![("newsletter".to_string(), false, true)],
            "an expired non-marketing consent is revoked without a cascade"
        );
        assert_eq!(
            cascade_state(&pool, tenant, "sub-4", "live@example.test").await,
            vec![("marketing".to_string(), true, false)],
            "a live consent is untouched"
        );

        // One audit entry per revoked consent (2), matching the per-row job.
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE resource_id = $1 AND action = 'update'",
        )
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("audit rows");
        assert_eq!(audited, 2, "one audit entry per revoked consent");

        // Idempotent: a second pass revokes nothing and writes no new entry.
        job.check_and_revoke_expired().await.expect("second pass");
        let audited_again: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE resource_id = $1 AND action = 'update'",
        )
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("audit rows");
        assert_eq!(audited_again, 2);
    }

    /// P3 item 8, >1 batch: with more expired rows than one batch holds, the
    /// sweep loops until the table is drained, leaving nothing behind and
    /// auditing every revoked row. The job is run with a shrunken batch (the
    /// loop and SQL are identical, only the LIMIT differs) so the fixture stays
    /// small: 7 expired rows / batch 2 = four passes (2+2+2+1). The production
    /// constant is pinned separately.
    #[tokio::test]
    async fn batched_expiry_drains_multiple_batches() {
        let Some(pool) = consent_db("consent_expiry_batches").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let tenant = "t_consent_batches";
        assert_eq!(
            CONSENT_EXPIRY_BATCH, 5_000,
            "the production batch is 5,000 rows"
        );
        let rows = 7; // > 3 batches at batch_rows = 2
        for i in 0..rows {
            seed_consent(
                &pool,
                tenant,
                &format!("sub-{i}"),
                &format!("batch-{i}@example.test"),
                "newsletter",
                true,
                Some(-2),
            )
            .await;
        }
        // A live row that must survive both passes.
        seed_consent(
            &pool,
            tenant,
            "sub-live",
            "live@example.test",
            "newsletter",
            true,
            Some(24),
        )
        .await;

        let audit = Arc::new(quiet_audit(&pool).await);
        let job = ConsentExpiryJob::with_batch_rows(pool.clone(), audit.clone(), 2);
        job.check_and_revoke_expired().await.expect("sweep runs");

        let still_granted: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM consent_records WHERE tenant_id = $1 AND granted = true",
        )
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("granted left");
        assert_eq!(still_granted, 1, "only the live consent remains granted");
        let revoked: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM consent_records WHERE tenant_id = $1 AND granted = false",
        )
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("revoked");
        assert_eq!(
            revoked, rows,
            "every expired row revoked across both batches"
        );
    }

    /// F-audit P2 (65,535-parameter ceiling): the cascade upsert must chunk.
    /// One marketing row cascades to analytics + profiling, so a full batch
    /// wants up to 10,000 upsert rows. With the chunk shrunk to 2, three
    /// marketing rows produce 6 upsert rows = 3 statements; every cascade row
    /// is revoked and the production chunk stays under the bind ceiling.
    ///
    /// Fail-before: one unbounded `push_values` issues exactly ONE statement
    /// (and at production scale exceeds the parameter limit).
    #[tokio::test]
    async fn cascade_upsert_chunks_above_the_parameter_boundary() {
        use std::sync::atomic::Ordering;

        let Some(pool) = consent_db("consent_expiry_cascade_chunks").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let tenant = "t_consent_cascade_chunks";
        for index in 0..3 {
            let subscriber = format!("chunk-sub-{index}");
            let email = format!("chunk-{index}@example.test");
            seed_consent(
                &pool,
                tenant,
                &subscriber,
                &email,
                "marketing",
                true,
                Some(-1),
            )
            .await;
            seed_consent(&pool, tenant, &subscriber, &email, "analytics", true, None).await;
            seed_consent(&pool, tenant, &subscriber, &email, "profiling", true, None).await;
        }

        let audit = Arc::new(quiet_audit(&pool).await);
        let job =
            ConsentExpiryJob::with_batch_rows(pool.clone(), audit, 100).with_cascade_chunk_rows(2);
        let revoked = job.check_and_revoke_expired().await.expect("sweep runs");
        assert_eq!(revoked, 3, "one expired marketing row per subject");

        // 3 cascade hits x 2 targets = 6 upsert rows, 2 per statement.
        assert_eq!(
            job.cascade_upsert_statements.load(Ordering::SeqCst),
            3,
            "6 cascade rows at 2 per chunk = 3 upsert statements"
        );
        for index in 0..3 {
            let subscriber = format!("chunk-sub-{index}");
            let email = format!("chunk-{index}@example.test");
            assert_eq!(
                cascade_state(&pool, tenant, &subscriber, &email).await,
                vec![
                    ("analytics".to_string(), false, true),
                    ("marketing".to_string(), false, true),
                    ("profiling".to_string(), false, true),
                ],
                "every cascade row for {email} is revoked"
            );
        }

        // Production chunk stays inside the 65,535-bind ceiling (6 binds/row).
        const {
            assert!(CASCADE_UPSERT_CHUNK_ROWS * 6 <= 65_535);
        }
    }

    /// F-audit P2 (atomic cascade): the cascade upsert now shares the revoke
    /// transaction. A forced upsert failure must (a) propagate out of
    /// `check_and_revoke_expired` instead of being warned away and (b) roll
    /// the revocations/cascades back, no revoked consent is ever left
    /// without its cascade rows.
    ///
    /// Fail-before: the upsert ran post-commit and its error was logged, so
    /// the sweep returned Ok and the revoked rows stayed revoked.
    #[tokio::test]
    async fn cascade_failure_rolls_back_the_revocation_and_propagates() {
        let Some(pool) = consent_db("consent_expiry_cascade_atomic").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let tenant = "t_consent_cascade_atomic";
        let email = "atomic@example.test";
        seed_consent(
            &pool,
            tenant,
            "atomic-sub",
            email,
            "marketing",
            true,
            Some(-1),
        )
        .await;
        seed_consent(&pool, tenant, "atomic-sub", email, "analytics", true, None).await;
        seed_consent(&pool, tenant, "atomic-sub", email, "profiling", true, None).await;

        // Force the cascade upsert's INSERT to fail inside the transaction.
        sqlx::query(
            "CREATE OR REPLACE FUNCTION test_fail_consent_cascade() RETURNS trigger AS $fn$ \
             BEGIN \
                 IF NEW.email = 'atomic@example.test' THEN \
                     RAISE EXCEPTION 'forced cascade failure'; \
                 END IF; \
                 RETURN NEW; \
             END; \
             $fn$ LANGUAGE plpgsql",
        )
        .execute(&pool)
        .await
        .expect("create cascade failure function");
        sqlx::query(
            "CREATE TRIGGER test_fail_consent_cascade BEFORE INSERT ON consent_records \
             FOR EACH ROW EXECUTE FUNCTION test_fail_consent_cascade()",
        )
        .execute(&pool)
        .await
        .expect("create cascade failure trigger");

        let audit = Arc::new(quiet_audit(&pool).await);
        let job = ConsentExpiryJob::new(pool.clone(), audit);
        let error = job
            .check_and_revoke_expired()
            .await
            .expect_err("a failed cascade upsert must fail the sweep, not warn");
        assert!(
            error.contains("Cascade upsert") && error.contains("forced cascade failure"),
            "the upsert error must propagate: {error}"
        );

        // Atomicity: the revoke AND the cascade UPDATE rolled back together.
        assert_eq!(
            cascade_state(&pool, tenant, "atomic-sub", email).await,
            vec![
                ("analytics".to_string(), true, false),
                ("marketing".to_string(), true, false),
                ("profiling".to_string(), true, false),
            ],
            "a failed cascade must leave no revoked consent behind"
        );
        // The post-commit audit pass never ran.
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE resource_id = $1 AND action = 'update'",
        )
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("audit rows");
        assert_eq!(audited, 0, "no audit entry for a rolled-back batch");
    }

    /// P2 consent-expiry audit chain: the pre-fix job called
    /// `AuditLogger::log` once per revoked consent, BEGIN + advisory lock +
    /// chain-head read + INSERT + COMMIT each. The batch writer must take the
    /// per-tenant lock once, read the head once and write one multi-row
    /// INSERT, so the statement count is CONSTANT in the number of revoked
    /// consents.
    ///
    /// Fail-before: 5 revoked consents -> (lock, head, insert) == (5, 5, 5).
    #[tokio::test]
    async fn consent_expiry_audit_statements_are_constant_in_batch_size() {
        use crate::audit_logger::query_count;

        let Some(pool) = consent_db("consent_expiry_audit_batch").await else {
            eprintln!("skipping: set TEST_DATABASE_URL to run DB-backed test");
            return;
        };
        let tenant = "t_consent_audit_batch";
        let audit = Arc::new(quiet_audit(&pool).await);
        let job = ConsentExpiryJob::new(pool.clone(), audit.clone());

        async fn seed_expired(pool: &PgPool, tenant: &str, from: usize, to: usize) {
            for index in from..to {
                seed_consent(
                    pool,
                    tenant,
                    &format!("audit-sub-{index}"),
                    &format!("audit-{index}@example.test"),
                    "newsletter",
                    true,
                    Some(-1),
                )
                .await;
            }
        }
        let counts = || {
            (
                query_count::count("audit.db.lock"),
                query_count::count("audit.db.head"),
                query_count::count("audit.db.insert"),
            )
        };

        // First batch: 5 revoked consents -> 5 audit entries.
        seed_expired(&pool, tenant, 0, 5).await;
        query_count::reset();
        let revoked = job.check_and_revoke_expired().await.expect("first pass");
        assert_eq!(revoked, 5);
        let small = counts();
        assert_eq!(
            small,
            (1, 1, 1),
            "one advisory lock, one head read, one multi-row INSERT per tenant"
        );

        // Second batch: 20 MORE revoked consents -> the SAME statement count.
        seed_expired(&pool, tenant, 5, 25).await;
        query_count::reset();
        let revoked = job.check_and_revoke_expired().await.expect("second pass");
        assert_eq!(revoked, 20);
        assert_eq!(
            counts(),
            small,
            "audit statement count is constant in the revoked-consent count"
        );

        // The chain re-derives from the stored columns (25 entries total).
        let validation = audit
            .verify_chain(Some(tenant), None, None)
            .await
            .expect("verify chain");
        assert!(validation.valid, "{validation:?}");
        assert_eq!(validation.entries_checked, 25);
        let audited: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM audit_logs WHERE resource_id = $1 AND action = 'update'",
        )
        .bind(tenant)
        .fetch_one(&pool)
        .await
        .expect("audit rows");
        assert_eq!(audited, 25, "one audit entry per revoked consent");
    }

    /// The interval setting is LIVE and fails safe: a positive integer is
    /// honored; unset/blank/garbage/zero falls back to the 3600s default
    /// (zero would panic `tokio::time::interval` and kill the cron loop).
    #[test]
    fn consent_expiry_interval_setting_parses_live_values_and_fails_safe() {
        assert_eq!(parse_check_interval_secs(Some("600")), 600);
        assert_eq!(parse_check_interval_secs(Some("  15 ")), 15);
        assert_eq!(
            parse_check_interval_secs(None),
            DEFAULT_CONSENT_EXPIRY_INTERVAL_SECS
        );
        assert_eq!(
            parse_check_interval_secs(Some("")),
            DEFAULT_CONSENT_EXPIRY_INTERVAL_SECS
        );
        assert_eq!(
            parse_check_interval_secs(Some("garbage")),
            DEFAULT_CONSENT_EXPIRY_INTERVAL_SECS
        );
        assert_eq!(
            parse_check_interval_secs(Some("0")),
            DEFAULT_CONSENT_EXPIRY_INTERVAL_SECS,
            "a zero tick period must never reach tokio::time::interval"
        );
        assert_eq!(
            parse_check_interval_secs(Some("-5")),
            DEFAULT_CONSENT_EXPIRY_INTERVAL_SECS
        );
        assert_eq!(
            CONSENT_EXPIRY_INTERVAL_ENV, "CONSENT_EXPIRY_CHECK_INTERVAL_SECS",
            "the server reads this exact variable name"
        );
        assert_eq!(DEFAULT_CONSENT_EXPIRY_INTERVAL_SECS, 3600);
    }
}
