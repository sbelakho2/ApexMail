//! Retention sweep — enforcement for the RET-001..023 registry (audit H-6).
//!
//! The registry in [`crate::retention`] was previously declarative-only:
//! nothing deleted data when a category's duration elapsed. This module is
//! the enforcement pass for the stores the compliance crate actually owns
//! data for, plus an honest per-run report:
//!
//! 1. Purge expired `message_events` / `tracking_events` / `engagement_events`
//!    per the registry's category durations (default plan tier).
//! 2. Purge expired `gdpr_exports` (`export_expiration_days`, 7 by default —
//!    same window as [`GdprAutomation::enforce_retention`]).
//! 3. Trim `audit_logs` per `AUDIT_RETENTION_DAYS` via the existing
//!    [`AuditLogger::archive`] (rows only leave the live table when they
//!    verifiably landed in `audit_logs_archive`; conflicting originals stay).
//! 4. Purge stale `dsr_verification_outbox` rows once their request window
//!    (`request_expiration_days`) has passed — the raw token must not linger.
//! 5. Insert one `retention_report` row per run so the policy is observable.
//!
//! Stores this crate cannot reach (ClickHouse analytics, backups, mailstore
//! blobs) are NOT silently ignored — the report lists them as out-of-scope
//! with their registry durations and who enforces them.
//!
//! Legal holds: tenants with `tenants.legal_hold = true` (canonical schema,
//! `tools/migrations/001_initial_schema.sql`) are skipped and counted.

use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tracing::{info, warn};

use crate::audit_logger::AuditLogger;
use crate::retention::{seed_retention_registry, RetentionRegistry};

/// DDL for the per-run retention report. Applied by [`RetentionSweeper::apply_migration`]
/// (the compliance crate owns no numbered migration files).
pub const RETENTION_REPORT_MIGRATION: &str = r#"
CREATE TABLE IF NOT EXISTS retention_report (
    id TEXT PRIMARY KEY,
    ran_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    plan_tier TEXT NOT NULL DEFAULT 'default',
    report JSONB NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_retention_report_ran_at
    ON retention_report (ran_at DESC);
"#;

/// One event store the sweep purges, mapped to its registry categories.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SweepTarget {
    /// Logical store name used in reports.
    pub store: &'static str,
    /// Postgres table.
    pub table: &'static str,
    /// Timestamp column the retention window is measured against.
    pub timestamp_column: &'static str,
    /// Registry category ids governing this store's retention.
    pub category_ids: &'static [&'static str],
}

impl SweepTarget {
    /// The effective retention (default plan tier) is the MINIMUM of the
    /// mapped categories' `default_retention_days` — never keep data past the
    /// shortest applicable policy.
    pub fn retention_days(&self, registry: &RetentionRegistry) -> Option<u32> {
        self.category_ids
            .iter()
            .filter_map(|id| registry.get(id))
            .map(|def| def.default_retention_days)
            .min()
    }
}

/// The stores this crate sweeps. `message_events`/`tracking_events`/
/// `engagement_events` are the event stores the compliance crate's own
/// access-export and erasure data map reads and deletes
/// (`gdpr_automation::erasure_stores`).
pub fn sweep_targets() -> Vec<SweepTarget> {
    vec![
        SweepTarget {
            store: "message_events",
            table: "message_events",
            timestamp_column: "created_at",
            category_ids: &["RET-007"],
        },
        SweepTarget {
            store: "tracking_events",
            table: "tracking_events",
            timestamp_column: "created_at",
            // One table holds both open and click rows; both categories share
            // the same defaults — the minimum is applied either way.
            category_ids: &["RET-009", "RET-010"],
        },
        SweepTarget {
            store: "engagement_events",
            table: "engagement_events",
            timestamp_column: "created_at",
            category_ids: &["RET-009", "RET-010"],
        },
    ]
}

/// A store the sweep cannot reach, reported with its registry duration so the
/// gap is visible instead of silent.
#[derive(Debug, Clone, serde::Serialize)]
pub struct OutOfScopeStore {
    pub store: &'static str,
    pub category_ids: &'static [&'static str],
    pub registry_default_days: Vec<u32>,
    pub enforcement_note: &'static str,
}

/// Out-of-scope stores, with registry durations resolved from the seeded
/// registry (not hardcoded numbers).
pub fn out_of_scope_stores(registry: &RetentionRegistry) -> Vec<OutOfScopeStore> {
    let specs: Vec<(&'static str, &'static [&'static str], &'static str)> = vec![
        (
            "clickhouse_analytics",
            &["RET-007", "RET-009", "RET-010"],
            "Analytics store owned by the analytics pipeline; the compliance crate cannot purge it. Registry durations apply and must be enforced by the owning service.",
        ),
        (
            "backups",
            &["RET-021"],
            "Backup retention is enforced by the ha service (BACKUP_RETENTION_DAYS, default 90) and scripts/clickhouse-backup.sh (default 30). Listed here with the registry duration only.",
        ),
        (
            "mailstore_blobs",
            &["RET-001", "RET-006", "RET-023"],
            "Message bodies, attachments and inbound content blobs live in the mailstore; enforced by the mail pipeline, not this crate.",
        ),
    ];
    specs
        .into_iter()
        .map(|(store, category_ids, note)| OutOfScopeStore {
            store,
            category_ids,
            registry_default_days: category_ids
                .iter()
                .filter_map(|id| registry.get(id))
                .map(|def| def.default_retention_days)
                .collect(),
            enforcement_note: note,
        })
        .collect()
}

/// Per-target sweep outcome.
#[derive(Debug, Clone, PartialEq, Eq, serde::Serialize)]
pub enum SweepStatus {
    /// Expired rows were deleted (possibly zero).
    Deleted,
    /// Table or timestamp column absent in this deployment — reported, not
    /// counted as deleted.
    SkippedMissingStore,
    /// The sweep failed for this store (recorded with the error).
    Failed,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CategorySweepResult {
    pub store: &'static str,
    pub category_ids: &'static [&'static str],
    pub retention_days: u32,
    pub cutoff: DateTime<Utc>,
    /// Rows past the cutoff before deletion (includes legal-held rows).
    pub considered: i64,
    pub deleted: i64,
    /// Considered rows belonging to tenants on legal hold — never deleted.
    pub skipped_legal_hold: i64,
    /// How legal holds were determined.
    pub legal_hold_check: LegalHoldCheck,
    pub status: SweepStatus,
    pub error: Option<String>,
}

/// Whether the tenants table (and thus holds) could be consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum LegalHoldCheck {
    /// `tenants.legal_hold` consulted; held tenants skipped.
    TenantsTable,
    /// No `tenants` table in this deployment — no hold exclusion possible.
    TenantsTableMissing,
}

/// The full per-run report persisted to `retention_report`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionSweepReport {
    pub ran_at: DateTime<Utc>,
    pub plan_tier: &'static str,
    pub categories: Vec<CategorySweepResult>,
    pub gdpr_exports_deleted: u64,
    pub dsr_outbox_purged: u64,
    pub audit_logs_considered: i64,
    pub audit_logs_archived: i64,
    pub out_of_scope: Vec<OutOfScopeStore>,
}

pub struct RetentionSweeper {
    db: PgPool,
    registry: RetentionRegistry,
    export_expiration_days: i64,
    request_expiration_days: i64,
    audit_retention_days: i64,
}

impl RetentionSweeper {
    pub fn new(
        db: PgPool,
        export_expiration_days: i64,
        request_expiration_days: i64,
        audit_retention_days: i64,
    ) -> Self {
        Self {
            db,
            registry: seed_retention_registry(),
            export_expiration_days,
            request_expiration_days,
            audit_retention_days,
        }
    }

    /// Ensure the `retention_report` table exists (idempotent).
    pub async fn apply_migration(&self) -> Result<(), String> {
        sqlx::raw_sql(RETENTION_REPORT_MIGRATION)
            .execute(&self.db)
            .await
            .map_err(|e| format!("retention_report migration error: {e}"))?;
        info!("retention_report table ensured");
        Ok(())
    }

    /// Run one full sweep and persist a `retention_report` row.
    ///
    /// `audit_logger` is used for step 3 (audit trim via `archive()`), so the
    /// sweeper shares the logger's hash-chain state with the rest of the
    /// service instead of keeping a second chain cache.
    pub async fn run_sweep(&self, audit_logger: &AuditLogger) -> Result<RetentionSweepReport, String> {
        let now = Utc::now();
        let mut categories = Vec::new();

        for target in sweep_targets() {
            let result = self.sweep_target(&target, now).await;
            categories.push(result);
        }

        // gdpr_exports — same window as GdprAutomation::enforce_retention
        // (created_at + export_expiration_days, NOT expires_at).
        let exports_deleted = sqlx::query("DELETE FROM gdpr_exports WHERE created_at < $1")
            .bind(now - chrono::Duration::days(self.export_expiration_days))
            .execute(&self.db)
            .await
            .map(|r| r.rows_affected())
            .unwrap_or_else(|e| {
                warn!(error = %e, "retention sweep: gdpr_exports purge failed");
                0
            });

        // dsr_verification_outbox — raw verification tokens must not outlive
        // the request window they are valid for.
        let outbox_purged =
            sqlx::query("DELETE FROM dsr_verification_outbox WHERE created_at < $1")
                .bind(now - chrono::Duration::days(self.request_expiration_days))
                .execute(&self.db)
                .await
                .map(|r| r.rows_affected())
                .unwrap_or_else(|e| {
                    warn!(error = %e, "retention sweep: dsr outbox purge failed");
                    0
                });

        // audit_logs — trimmed via the existing archive() (transactional
        // copy-then-verify-delete; conflicting originals stay in the live
        // table by design, see audit_logger E-2).
        let audit_cutoff = now - chrono::Duration::days(self.audit_retention_days);
        let audit_considered: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE timestamp < $1")
                .bind(audit_cutoff)
                .fetch_one(&self.db)
                .await
                .unwrap_or(-1);
        let audit_archived = audit_logger.archive(audit_cutoff).await.unwrap_or_else(|e| {
            warn!(error = %e, "retention sweep: audit archive failed");
            -1
        });

        let report = RetentionSweepReport {
            ran_at: now,
            plan_tier: "default",
            categories,
            gdpr_exports_deleted: exports_deleted,
            dsr_outbox_purged: outbox_purged,
            audit_logs_considered: audit_considered,
            audit_logs_archived: audit_archived,
            out_of_scope: out_of_scope_stores(&self.registry),
        };

        self.persist_report(&report).await?;
        Ok(report)
    }

    /// Sweep one event store: count considered, exclude legal-held tenants,
    /// delete the rest. Missing tables/columns are reported as skipped.
    async fn sweep_target(&self, target: &SweepTarget, now: DateTime<Utc>) -> CategorySweepResult {
        let Some(retention_days) = target.retention_days(&self.registry) else {
            return CategorySweepResult {
                store: target.store,
                category_ids: target.category_ids,
                retention_days: 0,
                cutoff: now,
                considered: 0,
                deleted: 0,
                skipped_legal_hold: 0,
                legal_hold_check: LegalHoldCheck::TenantsTableMissing,
                status: SweepStatus::Failed,
                error: Some("registry categories missing".into()),
            };
        };
        let cutoff = now - chrono::Duration::days(retention_days as i64);
        let table = target.table;
        let ts = target.timestamp_column;

        let considered: i64 = match sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {table} WHERE {ts} < $1"
        ))
        .bind(cutoff)
        .fetch_one(&self.db)
        .await
        {
            Ok(c) => c,
            Err(e) if is_missing_store(&e) => {
                return skipped_result(target, retention_days, cutoff, &e);
            }
            Err(e) => {
                return failed_result(target, retention_days, cutoff, &e);
            }
        };

        // Legal holds — consult tenants.legal_hold when the table exists.
        // Fetched once and reused for the skip count and the delete.
        let held = match self.held_tenant_ids().await {
            Ok(held) => held,
            Err(e) => return failed_result(target, retention_days, cutoff, &e),
        };
        let legal_hold_check = if held.is_some() {
            LegalHoldCheck::TenantsTable
        } else {
            LegalHoldCheck::TenantsTableMissing
        };

        let (skipped_hold, deleted): (i64, Result<u64, sqlx::Error>) = match held.as_ref() {
            Some(held_ids) if !held_ids.is_empty() => {
                let skipped: i64 = sqlx::query_scalar(&format!(
                    "SELECT COUNT(*) FROM {table} WHERE {ts} < $1 AND tenant_id = ANY($2)"
                ))
                .bind(cutoff)
                .bind(held_ids)
                .fetch_one(&self.db)
                .await
                .unwrap_or(0);
                let deleted = sqlx::query(&format!(
                    "DELETE FROM {table} WHERE {ts} < $1 AND NOT (tenant_id = ANY($2))"
                ))
                .bind(cutoff)
                .bind(held_ids)
                .execute(&self.db)
                .await
                .map(|r| r.rows_affected());
                (skipped, deleted)
            }
            // No tenants table, or no tenants on hold — plain delete.
            _ => {
                let deleted = sqlx::query(&format!("DELETE FROM {table} WHERE {ts} < $1"))
                    .bind(cutoff)
                    .execute(&self.db)
                    .await
                    .map(|r| r.rows_affected());
                (0, deleted)
            }
        };

        match deleted {
            Ok(deleted) => CategorySweepResult {
                store: target.store,
                category_ids: target.category_ids,
                retention_days,
                cutoff,
                considered,
                deleted: deleted as i64,
                skipped_legal_hold: skipped_hold,
                legal_hold_check,
                status: SweepStatus::Deleted,
                error: None,
            },
            Err(e) if is_missing_store(&e) => {
                skipped_result(target, retention_days, cutoff, &e)
            }
            Err(e) => failed_result(target, retention_days, cutoff, &e),
        }
    }

    /// Active legal-hold tenant ids, or None when the `tenants` table is
    /// absent in this deployment.
    async fn held_tenant_ids(&self) -> Result<Option<Vec<String>>, sqlx::Error> {
        match sqlx::query_scalar("SELECT id FROM tenants WHERE legal_hold = true")
            .fetch_all(&self.db)
            .await
        {
            Ok(ids) => Ok(Some(ids)),
            Err(e) if is_missing_table(&e) => Ok(None),
            Err(e) => Err(e),
        }
    }

    async fn persist_report(&self, report: &RetentionSweepReport) -> Result<(), String> {
        let json = serde_json::to_value(report).map_err(|e| format!("JSON: {e}"))?;
        sqlx::query(
            "INSERT INTO retention_report (id, ran_at, plan_tier, report)
             VALUES ($1, $2, $3, $4)",
        )
        .bind(uuid::Uuid::new_v4().to_string())
        .bind(report.ran_at)
        .bind(report.plan_tier)
        .bind(&json)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error writing retention_report: {e}"))?;
        Ok(())
    }
}

fn skipped_result(
    target: &SweepTarget,
    retention_days: u32,
    cutoff: DateTime<Utc>,
    err: &sqlx::Error,
) -> CategorySweepResult {
    warn!(store = target.store, error = %err, "retention sweep: store absent — skipped");
    CategorySweepResult {
        store: target.store,
        category_ids: target.category_ids,
        retention_days,
        cutoff,
        considered: 0,
        deleted: 0,
        skipped_legal_hold: 0,
        legal_hold_check: LegalHoldCheck::TenantsTableMissing,
        status: SweepStatus::SkippedMissingStore,
        error: Some(err.to_string()),
    }
}

fn failed_result(
    target: &SweepTarget,
    retention_days: u32,
    cutoff: DateTime<Utc>,
    err: &sqlx::Error,
) -> CategorySweepResult {
    warn!(store = target.store, error = %err, "retention sweep failed");
    CategorySweepResult {
        store: target.store,
        category_ids: target.category_ids,
        retention_days,
        cutoff,
        considered: 0,
        deleted: 0,
        skipped_legal_hold: 0,
        legal_hold_check: LegalHoldCheck::TenantsTableMissing,
        status: SweepStatus::Failed,
        error: Some(err.to_string()),
    }
}

/// Postgres undefined_table (42P01) or undefined_column (42703).
fn is_missing_store(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c == "42P01" || c == "42703")
        .unwrap_or(false)
}

fn is_missing_table(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c == "42P01")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sweep_targets_cover_the_three_event_stores() {
        let targets = sweep_targets();
        let stores: Vec<&str> = targets.iter().map(|t| t.store).collect();
        assert_eq!(stores, vec!["message_events", "tracking_events", "engagement_events"]);
    }

    /// Registry durations actually drive the cutoffs — message events use
    /// RET-007's 30 days, tracking/engagement the 30-day minimum of
    /// RET-009/RET-010.
    #[test]
    fn test_target_durations_come_from_the_registry() {
        let registry = seed_retention_registry();
        let targets = sweep_targets();
        let me = targets.iter().find(|t| t.store == "message_events").unwrap();
        assert_eq!(me.retention_days(&registry), Some(30), "RET-007 default");
        let te = targets.iter().find(|t| t.store == "tracking_events").unwrap();
        assert_eq!(te.retention_days(&registry), Some(30), "min(RET-009, RET-010)");
    }

    /// If a mapped category's default ever drops, the sweep follows the
    /// registry (minimum), not a hardcoded number.
    #[test]
    fn test_minimum_of_mapped_categories_wins() {
        let mut registry = seed_retention_registry();
        let mut def = registry.get("RET-010").unwrap().clone();
        def.default_retention_days = 14;
        registry.register(def);
        let target = SweepTarget {
            store: "tracking_events",
            table: "tracking_events",
            timestamp_column: "created_at",
            category_ids: &["RET-009", "RET-010"],
        };
        assert_eq!(target.retention_days(&registry), Some(14));
    }

    /// Out-of-scope stores are listed with their REGISTRY durations — the
    /// report never invents numbers.
    #[test]
    fn test_out_of_scope_stores_carry_registry_durations() {
        let registry = seed_retention_registry();
        let oos = out_of_scope_stores(&registry);
        let stores: Vec<&str> = oos.iter().map(|s| s.store).collect();
        assert_eq!(
            stores,
            vec!["clickhouse_analytics", "backups", "mailstore_blobs"]
        );

        let backups = oos.iter().find(|s| s.store == "backups").unwrap();
        assert_eq!(backups.category_ids, &["RET-021"]);
        assert_eq!(backups.registry_default_days, vec![30], "RET-021 default is 30d");

        let blobs = oos.iter().find(|s| s.store == "mailstore_blobs").unwrap();
        assert_eq!(blobs.registry_default_days, vec![7, 7, 7], "RET-001/006/023 defaults");

        let ch = oos.iter().find(|s| s.store == "clickhouse_analytics").unwrap();
        assert_eq!(ch.registry_default_days, vec![30, 30, 30]);

        for s in &oos {
            assert!(!s.enforcement_note.is_empty(), "note required for {}", s.store);
            assert_eq!(
                s.category_ids.len(),
                s.registry_default_days.len(),
                "every mapped category resolves to a registry duration"
            );
        }
    }

    #[test]
    fn test_missing_registry_category_fails_the_target() {
        let empty = RetentionRegistry::new();
        let target = SweepTarget {
            store: "message_events",
            table: "message_events",
            timestamp_column: "created_at",
            category_ids: &["RET-007"],
        };
        assert_eq!(target.retention_days(&empty), None);
    }
}
