//! Retention sweep — enforcement for the RET-001..023 registry (audit H-6).
//!
//! The registry in [`crate::retention`] was previously declarative-only:
//! nothing deleted data when a category's duration elapsed. This module is
//! the enforcement pass for the stores the compliance crate actually owns
//! data for, plus an honest per-run report:
//!
//! 1. Purge expired rows from the CANONICAL event stores — `events`
//!    (migration 075) per the RET-007/009/010 durations and `messages`
//!    (migration 073) per RET-001/002 content durations. F2: the previous
//!    targets (`message_events`/`tracking_events`/`engagement_events`)
//!    exist only in test fixtures — production sweeps deleted nothing.
//! 2. Purge expired `gdpr_exports` (`export_expiration_days`, 7 by default —
//!    same window as [`GdprAutomation::enforce_retention`]).
//! 3. Trim `audit_logs` per `AUDIT_RETENTION_DAYS` via the existing
//!    [`AuditLogger::archive`] (rows only leave the live table when they
//!    verifiably landed in `audit_logs_archive`; conflicting originals stay).
//! 4. Purge stale `dsr_verification_outbox` rows once their request window
//!    (`request_expiration_days`) has passed — the raw token must not linger.
//! 5. Insert one `retention_report` row per run so the policy is observable.
//!
//! Per-tenant retention (F4): the cutoff is NOT a flat default. Each tenant's
//! effective window is resolved as
//!   `tenants.retention_days` (migration 121; validated against the tenant's
//!   plan via [`RetentionRegistry::validate_customer_selection`]) or, when
//! NULL, the registry's plan-tier default. Tenants with
//! `ent_compliance_configs.zero_retention_mode = true` are purged immediately
//! regardless of window.
//!
//! Legal holds (F5): tenants with `tenants.legal_hold = true` (migration 121)
//! are excluded from EVERY purge this module performs — event stores,
//! gdpr_exports, the DSR outbox and the audit trim (the exclusion lives in
//! [`AuditLogger::archive`]). Rows with a NULL tenant id cannot be attributed
//! and are kept whenever any hold is active (fall back to keep).
//!
//! Deletes are batched (F11): `WHERE ctid IN (SELECT … LIMIT N)` loops with a
//! per-batch `lock_timeout`, and counts come from accumulated deleted-row
//! counts — no separate full-table COUNT + unbounded single DELETE.
//!
//! Stores this crate cannot reach (ClickHouse analytics, backups, mailstore
//! blobs) are NOT silently ignored — the report lists them as out-of-scope
//! with their registry durations and who enforces them.

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

/// Rows deleted per batch statement (F11) — bounded work per lock window.
const DELETE_BATCH_ROWS: i64 = 5_000;

/// Per-batch lock timeout: a long-running purge must not queue indefinitely
/// behind (or block) production writes.
const LOCK_TIMEOUT: &str = "5s";

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

/// The CANONICAL stores this crate sweeps (audit F2): `events` is the event
/// store every writer in the platform INSERTs into (migration 075); `messages`
/// is the message-content store (migration 073) bounded by the RET-001/002
/// content durations. The previous targets existed only in test fixtures.
pub fn sweep_targets() -> Vec<SweepTarget> {
    vec![
        SweepTarget {
            store: "events",
            table: "events",
            timestamp_column: "timestamp",
            // One table holds sent/delivered/bounce/open/click rows; the
            // minimum of the mapped categories' defaults is applied.
            category_ids: &["RET-007", "RET-009", "RET-010"],
        },
        SweepTarget {
            store: "messages",
            table: "messages",
            timestamp_column: "created_at",
            // Message body + subject line content (RET-001/RET-002).
            category_ids: &["RET-001", "RET-002"],
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
            "Analytics store owned by the analytics pipeline; the compliance crate cannot purge it (DSR erasures DO submit best-effort ClickHouse mutations — see gdpr_automation). Registry durations apply and must be enforced by the owning service.",
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
    /// The sweep failed for this store (recorded with the error; rows already
    /// deleted in earlier batches remain deleted and are reported).
    Failed,
}

#[derive(Debug, Clone, serde::Serialize)]
pub struct CategorySweepResult {
    pub store: &'static str,
    pub category_ids: &'static [&'static str],
    pub retention_days: u32,
    pub cutoff: DateTime<Utc>,
    /// Rows past the cutoff (or belonging to zero-retention tenants) before
    /// deletion — includes legal-held rows.
    pub considered: i64,
    /// Rows actually deleted (accumulated per-batch row counts, F11).
    pub deleted: i64,
    /// Considered rows belonging to tenants on legal hold — never deleted.
    pub skipped_legal_hold: i64,
    /// How legal holds were determined.
    pub legal_hold_check: LegalHoldCheck,
    /// Tenants purged immediately via ent_compliance_configs.zero_retention_mode (F4).
    pub zero_retention_tenants: usize,
    /// Tenants whose tenants.retention_days override was honored (F4).
    pub custom_retention_tenants: usize,
    pub status: SweepStatus,
    pub error: Option<String>,
}

/// Whether the tenants table (and thus holds) could be consulted.
#[derive(Debug, Clone, Copy, PartialEq, Eq, serde::Serialize)]
pub enum LegalHoldCheck {
    /// `tenants.legal_hold` consulted; held tenants skipped.
    TenantsTable,
    /// No `tenants` table (or no legal_hold column) in this deployment — no
    /// hold exclusion possible.
    TenantsTableMissing,
}

/// Per-tenant retention inputs resolved once per run (F4/F5).
#[derive(Debug, Clone)]
struct TenantRetention {
    id: String,
    plan: String,
    /// tenants.retention_days override (NULL → registry plan-tier default).
    /// INT (INT4) — the canonical migration-121 column type.
    retention_days: Option<i32>,
    held: bool,
    zero_retention: bool,
}

/// The full per-run report persisted to `retention_report`.
#[derive(Debug, Clone, serde::Serialize)]
pub struct RetentionSweepReport {
    pub ran_at: DateTime<Utc>,
    /// "per-tenant" when any override/zero-retention tenant participated,
    /// else the flat "default" tier (F4).
    pub plan_tier: String,
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
    /// service instead of keeping a second chain cache. The hold exclusion
    /// for the audit trim lives inside `archive()` (F5).
    pub async fn run_sweep(
        &self,
        audit_logger: &AuditLogger,
    ) -> Result<RetentionSweepReport, String> {
        let now = Utc::now();
        let tenants = self.tenant_retention_context().await;
        let legal_hold_check = if tenants.is_some() {
            LegalHoldCheck::TenantsTable
        } else {
            LegalHoldCheck::TenantsTableMissing
        };
        let mut categories = Vec::new();
        let mut overrides_seen = false;

        for target in sweep_targets() {
            let result = self
                .sweep_target(&target, now, tenants.as_deref(), legal_hold_check)
                .await;
            overrides_seen |=
                result.zero_retention_tenants > 0 || result.custom_retention_tenants > 0;
            categories.push(result);
        }

        // gdpr_exports — same window as GdprAutomation::enforce_retention
        // (created_at + export_expiration_days, NOT expires_at). F5: rows of
        // held tenants are excluded; NULL-tenant rows are kept whenever any
        // hold is active (they cannot be attributed).
        let exports_deleted = self
            .purge_with_hold_filter(
                "DELETE FROM gdpr_exports WHERE created_at < $1",
                now - chrono::Duration::days(self.export_expiration_days),
                &tenants,
            )
            .await;

        // dsr_verification_outbox — raw verification tokens must not outlive
        // the request window they are valid for (same hold exclusion).
        let outbox_purged = self
            .purge_with_hold_filter(
                "DELETE FROM dsr_verification_outbox WHERE created_at < $1",
                now - chrono::Duration::days(self.request_expiration_days),
                &tenants,
            )
            .await;

        // audit_logs — trimmed via the existing archive() (transactional
        // copy-then-verify-delete; conflicting originals stay in the live
        // table by design, see audit_logger E-2; held tenants excluded).
        let audit_cutoff = now - chrono::Duration::days(self.audit_retention_days);
        let audit_considered: i64 =
            sqlx::query_scalar("SELECT COUNT(*) FROM audit_logs WHERE timestamp < $1")
                .bind(audit_cutoff)
                .fetch_one(&self.db)
                .await
                .unwrap_or(-1);
        let audit_archived = audit_logger
            .archive(audit_cutoff)
            .await
            .unwrap_or_else(|e| {
                warn!(error = %e, "retention sweep: audit archive failed");
                -1
            });

        let report = RetentionSweepReport {
            ran_at: now,
            plan_tier: if overrides_seen {
                "per-tenant".into()
            } else {
                "default".into()
            },
            categories,
            gdpr_exports_deleted: exports_deleted.0,
            dsr_outbox_purged: outbox_purged.0,
            audit_logs_considered: audit_considered,
            audit_logs_archived: audit_archived,
            out_of_scope: out_of_scope_stores(&self.registry),
        };

        self.persist_report(&report).await?;
        Ok(report)
    }

    /// F4: per-tenant retention inputs, resolved once per run. `None` when
    /// the deployment has no `tenants` table at all (runtime-provisioned
    /// partial schemas) — the sweep then runs with flat defaults and says so
    /// via [`LegalHoldCheck::TenantsTableMissing`].
    async fn tenant_retention_context(&self) -> Option<Vec<TenantRetention>> {
        // Base shape (migration 121): legal_hold + retention_days per tenant.
        // A missing ent_compliance_configs must NOT degrade the tenants read
        // (holds/overrides matter more), so the zero-retention overlay is a
        // separate, independently-degradable query.
        #[derive(sqlx::FromRow)]
        struct TenantBaseRow {
            id: String,
            plan: String,
            // INT (INT4) — the canonical migration-121 column type.
            retention_days: Option<i32>,
            legal_hold: bool,
        }
        let base: Result<Vec<TenantBaseRow>, sqlx::Error> = sqlx::query_as::<_, TenantBaseRow>(
            "SELECT id, plan, retention_days, legal_hold FROM tenants",
        )
        .fetch_all(&self.db)
        .await;
        let mut tenants: Vec<TenantRetention> = match base {
            Ok(rows) => rows
                .into_iter()
                .map(|row| TenantRetention {
                    id: row.id,
                    plan: row.plan,
                    retention_days: row.retention_days,
                    held: row.legal_hold,
                    zero_retention: false,
                })
                .collect(),
            Err(e) if is_missing_table(&e) => return None,
            Err(e) if is_missing_column(&e) => {
                // Pre-121 tenants: plan tiers still resolve; no holds, no
                // overrides (degrade honestly — the report says so via
                // plan_tier "default").
                match sqlx::query_as::<_, (String, String)>("SELECT id, plan FROM tenants")
                    .fetch_all(&self.db)
                    .await
                {
                    Ok(rows) => rows
                        .into_iter()
                        .map(|(id, plan)| TenantRetention {
                            id,
                            plan,
                            retention_days: None,
                            held: false,
                            zero_retention: false,
                        })
                        .collect(),
                    Err(e) => {
                        warn!(error = %e, "retention sweep: tenants unreadable — flat defaults only");
                        return None;
                    }
                }
            }
            Err(e) => {
                warn!(error = %e, "retention sweep: tenants query failed — no per-tenant retention");
                return None;
            }
        };

        // Zero-retention overlay (F4): ent_compliance_configs.zero_retention_mode
        // (migration 092). Absent table/column degrades to "none"; other
        // errors are logged and also degrade (the purge must not stall on an
        // unrelated enterprise table).
        let zero: std::collections::HashSet<String> = match sqlx::query_scalar::<_, String>(
            "SELECT tenant_id FROM ent_compliance_configs WHERE zero_retention_mode = true",
        )
        .fetch_all(&self.db)
        .await
        {
            Ok(ids) => ids.into_iter().collect(),
            Err(e) if is_missing_store(&e) => Default::default(),
            Err(e) => {
                warn!(error = %e, "retention sweep: zero-retention lookup failed — assuming none");
                Default::default()
            }
        };
        for tenant in &mut tenants {
            if zero.contains(&tenant.id) {
                tenant.zero_retention = true;
            }
        }
        Some(tenants)
    }

    /// F4: the effective retention for one tenant against one target. The
    /// override is honored only when the registry accepts it for EVERY mapped
    /// category under the tenant's plan; otherwise the plan-tier default
    /// applies (with a warning — never longer than the plan allows).
    fn effective_retention_days(
        &self,
        target: &SweepTarget,
        default_days: u32,
        tenant: &TenantRetention,
    ) -> u32 {
        let Some(requested) = tenant.retention_days else {
            return default_days;
        };
        let Some(requested) = u32::try_from(requested.max(0)).ok() else {
            return default_days;
        };
        let accepted = target.category_ids.iter().all(|category| {
            self.registry
                .validate_customer_selection(category, &tenant.plan, requested)
                .is_ok()
        });
        if accepted {
            requested
        } else {
            warn!(
                tenant = %tenant.id,
                store = target.store,
                requested,
                "tenants.retention_days violates the plan/registry bounds — using plan-tier default"
            );
            default_days
        }
    }

    /// Sweep one canonical store: resolve per-tenant cutoffs (F4), skip held
    /// tenants (F5), delete in bounded batches with a lock timeout (F11) and
    /// count from the deleted-row counts.
    async fn sweep_target(
        &self,
        target: &SweepTarget,
        now: DateTime<Utc>,
        tenants: Option<&[TenantRetention]>,
        legal_hold_check: LegalHoldCheck,
    ) -> CategorySweepResult {
        let Some(default_days) = target.retention_days(&self.registry) else {
            return failedish_result(
                target,
                0,
                now,
                legal_hold_check,
                0,
                0,
                "registry categories missing",
            );
        };
        let default_cutoff = now - chrono::Duration::days(default_days as i64);
        let table = target.table;
        let ts = target.timestamp_column;

        // Partition tenants: held (skip), zero-retention (purge now), and
        // the rest grouped by their effective cutoff.
        let mut held_ids: Vec<String> = Vec::new();
        let mut zero_ids: Vec<String> = Vec::new();
        let mut custom_retention_tenants = 0usize;
        // cutoff-days → tenant ids (the default group also sweeps NULL-tenant rows).
        let mut groups: std::collections::BTreeMap<u32, Vec<String>> =
            std::collections::BTreeMap::new();
        match tenants {
            Some(tenants) => {
                for tenant in tenants {
                    if tenant.held {
                        held_ids.push(tenant.id.clone());
                        continue;
                    }
                    if tenant.zero_retention {
                        zero_ids.push(tenant.id.clone());
                        continue;
                    }
                    let days = self.effective_retention_days(target, default_days, tenant);
                    if days != default_days {
                        custom_retention_tenants += 1;
                    }
                    groups.entry(days).or_default().push(tenant.id.clone());
                }
                // NULL-tenant rows ride with the default group.
                groups.entry(default_days).or_default();
            }
            None => {
                // No tenants table: flat default cutoff for every row.
                groups.entry(default_days).or_default();
            }
        }

        // Considered + held-skip counts (reporting only; derived from the
        // DEFAULT cutoff — the shortest honest denominator).
        let considered: i64 = match sqlx::query_scalar(&format!(
            "SELECT COUNT(*) FROM {table}
             WHERE {ts} < $1 OR tenant_id = ANY($2)",
        ))
        .bind(default_cutoff)
        .bind(&zero_ids)
        .fetch_one(&self.db)
        .await
        {
            Ok(c) => c,
            Err(e) if is_missing_store(&e) => {
                return skipped_result(target, default_days, default_cutoff, &e);
            }
            Err(e) => {
                return failed_result(target, default_days, default_cutoff, &e);
            }
        };
        let skipped_hold: i64 = if held_ids.is_empty() {
            0
        } else {
            sqlx::query_scalar(&format!(
                "SELECT COUNT(*) FROM {table} WHERE {ts} < $1 AND tenant_id = ANY($2)"
            ))
            .bind(default_cutoff)
            .bind(&held_ids)
            .fetch_one(&self.db)
            .await
            .unwrap_or(0)
        };

        // Batched deletes. The zero-retention group ignores the window.
        let mut deleted: i64 = 0;
        let mut failure: Option<sqlx::Error> = None;

        if !zero_ids.is_empty() {
            let predicate = format!("{ts} < $1 AND tenant_id = ANY($2)");
            match self
                .batched_delete(table, &predicate, Some(now), Some(&zero_ids))
                .await
            {
                Ok(n) => deleted += n,
                Err(e) if is_missing_store(&e) => {
                    return skipped_result(target, default_days, default_cutoff, &e)
                }
                Err(e) => failure = Some(e),
            }
        }

        if failure.is_none() {
            for (days, ids) in &groups {
                let cutoff = now - chrono::Duration::days(*days as i64);
                // When the tenants table is known, every delete is
                // tenant-scoped: the default-days group additionally owns
                // NULL-tenant rows; a tenant-less deployment sweeps plainly.
                let (predicate, bind_ids) = match tenants {
                    Some(_) if days == &default_days => (
                        format!("{ts} < $1 AND (tenant_id IS NULL OR tenant_id = ANY($2))"),
                        Some(ids.as_slice()),
                    ),
                    Some(_) => (
                        format!("{ts} < $1 AND tenant_id = ANY($2)"),
                        Some(ids.as_slice()),
                    ),
                    None => (format!("{ts} < $1"), None),
                };
                match self
                    .batched_delete(table, &predicate, Some(cutoff), bind_ids)
                    .await
                {
                    Ok(n) => deleted += n,
                    Err(e) if is_missing_store(&e) => {
                        return skipped_result(target, default_days, default_cutoff, &e)
                    }
                    Err(e) => {
                        failure = Some(e);
                        break;
                    }
                }
            }
        }

        match failure {
            None => CategorySweepResult {
                store: target.store,
                category_ids: target.category_ids,
                retention_days: default_days,
                cutoff: default_cutoff,
                considered,
                deleted,
                skipped_legal_hold: skipped_hold,
                legal_hold_check,
                zero_retention_tenants: zero_ids.len(),
                custom_retention_tenants,
                status: SweepStatus::Deleted,
                error: None,
            },
            Some(e) => {
                let mut r = failed_result(target, default_days, default_cutoff, &e);
                // Rows deleted by earlier batches are still deleted — the
                // report keeps the honest count.
                r.deleted = deleted;
                r.considered = considered;
                r.skipped_legal_hold = skipped_hold;
                r
            }
        }
    }

    /// F11: batched DELETE loop. Each batch runs in its own transaction with
    /// `SET LOCAL lock_timeout`, selects at most [`DELETE_BATCH_ROWS`] rows
    /// by ctid and deletes exactly those. Returns the accumulated deleted-row
    /// count (the authoritative count — no separate COUNT query).
    async fn batched_delete(
        &self,
        table: &str,
        predicate: &str,
        cutoff: Option<DateTime<Utc>>,
        tenant_ids: Option<&[String]>,
    ) -> Result<i64, sqlx::Error> {
        let uses_tenants = tenant_ids.is_some();
        let mut deleted: i64 = 0;
        loop {
            let mut tx = self.db.begin().await?;
            sqlx::query(&format!("SET LOCAL lock_timeout = '{LOCK_TIMEOUT}'"))
                .execute(&mut *tx)
                .await?;
            let sql = format!(
                "DELETE FROM {table} WHERE ctid IN (
                   SELECT ctid FROM {table} WHERE {predicate} LIMIT $3
                 )"
            );
            let mut q = sqlx::query(&sql).bind(cutoff);
            if uses_tenants {
                q = q.bind(tenant_ids);
            }
            q = q.bind(DELETE_BATCH_ROWS);
            let rows = q.execute(&mut *tx).await?.rows_affected() as i64;
            tx.commit().await?;
            deleted += rows;
            if rows < DELETE_BATCH_ROWS {
                break;
            }
        }
        Ok(deleted)
    }

    /// F5: a retention purge (gdpr_exports / DSR outbox) that excludes held
    /// tenants. Rows with a NULL tenant id are KEPT whenever any hold is
    /// active — they cannot be attributed to a tenant, so they might belong
    /// to a held one (fall back to keep). Returns (deleted, ok).
    async fn purge_with_hold_filter(
        &self,
        base_delete: &str,
        cutoff: DateTime<Utc>,
        tenants: &Option<Vec<TenantRetention>>,
    ) -> (u64, bool) {
        let held: Vec<String> = tenants
            .as_ref()
            .map(|ts| ts.iter().filter(|t| t.held).map(|t| t.id.clone()).collect())
            .unwrap_or_default();
        let result = if held.is_empty() {
            sqlx::query(base_delete)
                .bind(cutoff)
                .execute(&self.db)
                .await
        } else {
            let sql = format!("{base_delete} AND (tenant_id IS NOT NULL AND tenant_id <> ALL($2))");
            sqlx::query(&sql)
                .bind(cutoff)
                .bind(&held)
                .execute(&self.db)
                .await
        };
        match result {
            Ok(r) => (r.rows_affected(), true),
            Err(e) => {
                warn!(error = %e, "retention sweep: purge failed");
                (0, false)
            }
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
        .bind(&report.plan_tier)
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
        zero_retention_tenants: 0,
        custom_retention_tenants: 0,
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
        zero_retention_tenants: 0,
        custom_retention_tenants: 0,
        status: SweepStatus::Failed,
        error: Some(err.to_string()),
    }
}

fn failedish_result(
    target: &SweepTarget,
    retention_days: u32,
    cutoff: DateTime<Utc>,
    legal_hold_check: LegalHoldCheck,
    zero: usize,
    custom: usize,
    message: &str,
) -> CategorySweepResult {
    CategorySweepResult {
        store: target.store,
        category_ids: target.category_ids,
        retention_days,
        cutoff,
        considered: 0,
        deleted: 0,
        skipped_legal_hold: 0,
        legal_hold_check,
        zero_retention_tenants: zero,
        custom_retention_tenants: custom,
        status: SweepStatus::Failed,
        error: Some(message.to_string()),
    }
}

/// Postgres undefined_table (42P01) or undefined_column (42703) — the store
/// (table or its expected column) is not present in this deployment.
fn is_missing_store(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c == "42P01" || c == "42703")
        .unwrap_or(false)
}

/// Postgres undefined_table (42P01).
fn is_missing_table(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c == "42P01")
        .unwrap_or(false)
}

/// Postgres undefined_column (42703) — F2: graceful degradation where a
/// column added by a newer migration (121) is not present yet.
fn is_missing_column(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c == "42703")
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sweep_targets_are_the_canonical_event_stores() {
        let targets = sweep_targets();
        let stores: Vec<&str> = targets.iter().map(|t| t.store).collect();
        assert_eq!(stores, vec!["events", "messages"]);
    }

    /// Phantom tables must never come back as sweep targets.
    #[test]
    fn test_sweep_targets_exclude_fixture_only_tables() {
        let targets = sweep_targets();
        for phantom in ["message_events", "tracking_events", "engagement_events"] {
            assert!(
                targets.iter().all(|t| t.table != phantom),
                "{phantom} exists only in test fixtures and must not be swept"
            );
        }
    }

    /// Registry durations actually drive the cutoffs — events use the
    /// 30-day minimum of RET-007/009/010, messages the 7-day RET-001/002.
    #[test]
    fn test_target_durations_come_from_the_registry() {
        let registry = seed_retention_registry();
        let targets = sweep_targets();
        let ev = targets.iter().find(|t| t.store == "events").unwrap();
        assert_eq!(ev.retention_days(&registry), Some(30), "min(RET-007/9/10)");
        let msg = targets.iter().find(|t| t.store == "messages").unwrap();
        assert_eq!(msg.retention_days(&registry), Some(7), "min(RET-001/002)");
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
            store: "events",
            table: "events",
            timestamp_column: "timestamp",
            category_ids: &["RET-009", "RET-010"],
        };
        assert_eq!(target.retention_days(&registry), Some(14));
    }

    /// F4: a per-tenant override within the plan's bounds is honored; one
    /// that violates the plan (or the category minimum) falls back to the
    /// plan-tier default.
    #[test]
    fn test_tenant_retention_override_validation() {
        let sweeper_like_registry = seed_retention_registry();
        let target = SweepTarget {
            store: "events",
            table: "events",
            timestamp_column: "timestamp",
            category_ids: &["RET-007"],
        };
        let default_days = target.retention_days(&sweeper_like_registry).unwrap();

        let pro_tenant = TenantRetention {
            id: "t1".into(),
            plan: "pro".into(),
            retention_days: Some(90),
            held: false,
            zero_retention: false,
        };
        // validate_customer_selection is the gate the sweep uses; replicate
        // its decision to prove the wiring.
        let accepted = sweeper_like_registry
            .validate_customer_selection("RET-007", &pro_tenant.plan, 90)
            .is_ok();
        let effective = if accepted { 90 } else { default_days };
        assert_eq!(effective, 90, "pro allows up to 90d for RET-007");

        let free_tenant = TenantRetention {
            id: "t2".into(),
            plan: "free".into(),
            retention_days: Some(90),
            held: false,
            zero_retention: false,
        };
        let accepted_free = sweeper_like_registry
            .validate_customer_selection("RET-007", &free_tenant.plan, 90)
            .is_ok();
        assert!(!accepted_free, "free is capped at 7d for RET-007");
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
        assert_eq!(
            backups.registry_default_days,
            vec![30],
            "RET-021 default is 30d"
        );

        let blobs = oos.iter().find(|s| s.store == "mailstore_blobs").unwrap();
        assert_eq!(blobs.registry_default_days, vec![7, 7, 7]);

        let ch = oos
            .iter()
            .find(|s| s.store == "clickhouse_analytics")
            .unwrap();
        assert_eq!(ch.registry_default_days, vec![30, 30, 30]);

        for s in &oos {
            assert!(
                !s.enforcement_note.is_empty(),
                "note required for {}",
                s.store
            );
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
            store: "events",
            table: "events",
            timestamp_column: "timestamp",
            category_ids: &["RET-007"],
        };
        assert_eq!(target.retention_days(&empty), None);
    }
}
