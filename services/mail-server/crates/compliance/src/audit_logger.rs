//! Hash-chain audit logger — tamper-proof audit trail with SHA-256 hash chains,
//! HMAC-SHA-256 signatures, chain verification, JSON/CSV export, and archival.
//!
//! Each audit entry stores the SHA-256 hash of the previous entry in its chain
//! (keyed by tenant_id or "global"), forming an immutable linked list. A separate
//! HMAC signature using a server-side signing key protects the hash from forgery.

#[cfg(test)]
use chrono::Duration;
use chrono::{DateTime, Utc};
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use std::collections::HashMap;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;

use crate::config::AuditConfig;
use crate::types::*;

type HmacSha256 = Hmac<Sha256>;

pub struct AuditLogger {
    db: PgPool,
    #[expect(
        dead_code,
        reason = "audit config is retained for policy inspection and future dynamic updates"
    )]
    config: AuditConfig,
    signing_key: Vec<u8>,
    /// In-memory cache of last hash per chain key. Primary source:/// Redis `audit:lasthash:{key}`, falling back to DB.
    last_hashes: RwLock<HashMap<String, String>>,
    /// E-1: per-chain append locks. Held across the read-last-hash → INSERT →
    /// cache-update sequence so concurrent `log()` calls cannot fork the hash
    /// chain by reading the same `previous_hash`.
    chain_locks: tokio::sync::Mutex<HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>>,
}

impl AuditLogger {
    pub fn new(db: PgPool, config: AuditConfig) -> Self {
        let signing_key = config.signing_key.as_bytes().to_vec();
        Self {
            db,
            config,
            signing_key,
            last_hashes: RwLock::new(HashMap::new()),
            chain_locks: tokio::sync::Mutex::new(HashMap::new()),
        }
    }

    /// Get (or create) the append lock for a chain.
    async fn chain_lock(&self, chain_key: &str) -> std::sync::Arc<tokio::sync::Mutex<()>> {
        let mut locks = self.chain_locks.lock().await;
        locks
            .entry(chain_key.to_string())
            .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
            .clone()
    }

    /// Initialize by loading last hashes from the live table AND the archive.
    ///
    /// F12: the chain head used to be loaded from `audit_logs` only — once a
    /// chain was fully archived (the retention trim's normal outcome), a
    /// restart found no head and the next append built on `previous_hash =
    /// NULL`, silently forking the chain. The archive is part of the chain
    /// (verify/export already span both tables, E-2). Deployments without an
    /// archive table fall back to the live-only head.
    pub async fn initialize(&self) -> Result<(), String> {
        sqlx::query(
            "CREATE INDEX IF NOT EXISTS idx_audit_logs_tenant_timestamp ON audit_logs (tenant_id, timestamp DESC)",
        )
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let rows: Vec<(Option<String>, String)> = match sqlx::query_as(
            "SELECT DISTINCT ON (COALESCE(tenant_id, 'global')) tenant_id, hash
             FROM (
               SELECT tenant_id, timestamp, hash FROM audit_logs
               UNION ALL
               SELECT tenant_id, timestamp, hash FROM audit_logs_archive
             ) entries
             ORDER BY COALESCE(tenant_id, 'global'), timestamp DESC",
        )
        .fetch_all(&self.db)
        .await
        {
            Ok(rows) => rows,
            Err(e) if is_undefined_table(&e) => {
                tracing::warn!(
                    "audit_logs_archive absent — chain heads loaded from the live table only"
                );
                sqlx::query_as(
                    "SELECT DISTINCT ON (COALESCE(tenant_id, 'global')) tenant_id, hash
                     FROM audit_logs
                     ORDER BY COALESCE(tenant_id, 'global'), timestamp DESC",
                )
                .fetch_all(&self.db)
                .await
                .map_err(|e| format!("DB error: {e}"))?
            }
            Err(e) => return Err(format!("DB error: {e}")),
        };

        let mut map = self.last_hashes.write().await;
        for (tenant_id, hash) in rows {
            let chain_key = tenant_id.unwrap_or_else(|| "global".into());
            map.insert(chain_key, hash);
        }
        info!(chains = map.len(), "Audit logger initialized");
        Ok(())
    }

    // ── Core logging ────────────────────────────────────────

    /// Log a single audit event. Returns the persisted entry.
    #[allow(clippy::too_many_arguments)]
    pub async fn log(
        &self,
        action: AuditAction,
        resource: AuditResource,
        resource_id: Option<&str>,
        details: serde_json::Value,
        outcome: AuditOutcome,
        error_message: Option<&str>,
        ctx: &LogContext,
    ) -> Result<AuditLogEntry, String> {
        let id = Uuid::new_v4().to_string();
        let timestamp = Utc::now();
        let chain_key = ctx.tenant_id.clone().unwrap_or_else(|| "global".into());

        // E-1: serialize chain appends per chain — read-last-hash, INSERT and
        // cache update happen under the lock so two concurrent log() calls
        // can never build on the same previous_hash (chain fork).
        let lock = self.chain_lock(&chain_key).await;
        let _chain_guard = lock.lock().await;

        let previous_hash = {
            let map = self.last_hashes.read().await;
            map.get(&chain_key).cloned()
        };

        let hash = self.compute_hash(
            &id,
            &ctx.tenant_id,
            &ctx.user_id,
            &ctx.session_id,
            &action,
            &resource,
            &resource_id.map(|s| s.to_string()),
            &details,
            &ctx.ip_address,
            &ctx.user_agent,
            &outcome,
            &error_message.map(|s| s.to_string()),
            &timestamp,
            &previous_hash,
        );

        let signature = self.compute_signature(&hash)?;

        let entry = AuditLogEntry {
            id,
            tenant_id: ctx.tenant_id.clone(),
            user_id: ctx.user_id.clone(),
            session_id: ctx.session_id.clone(),
            action,
            resource,
            resource_id: resource_id.map(|s| s.to_string()),
            details,
            ip_address: ctx.ip_address.clone(),
            user_agent: ctx.user_agent.clone(),
            outcome,
            error_message: error_message.map(|s| s.to_string()),
            timestamp,
            hash: hash.clone(),
            previous_hash,
            signature,
        };

        self.persist_entry(&entry).await?;

        // Update last hash cache
        {
            let mut map = self.last_hashes.write().await;
            map.insert(chain_key, hash);
        }

        Ok(entry)
    }

    // ── Convenience wrappers ────────────────────────────────

    pub async fn log_create(
        &self,
        resource: AuditResource,
        resource_id: &str,
        details: serde_json::Value,
        ctx: &LogContext,
    ) -> Result<AuditLogEntry, String> {
        self.log(
            AuditAction::Create,
            resource,
            Some(resource_id),
            details,
            AuditOutcome::Success,
            None,
            ctx,
        )
        .await
    }

    pub async fn log_read(
        &self,
        resource: AuditResource,
        resource_id: &str,
        details: serde_json::Value,
        ctx: &LogContext,
    ) -> Result<AuditLogEntry, String> {
        self.log(
            AuditAction::Read,
            resource,
            Some(resource_id),
            details,
            AuditOutcome::Success,
            None,
            ctx,
        )
        .await
    }

    pub async fn log_update(
        &self,
        resource: AuditResource,
        resource_id: &str,
        details: serde_json::Value,
        ctx: &LogContext,
    ) -> Result<AuditLogEntry, String> {
        self.log(
            AuditAction::Update,
            resource,
            Some(resource_id),
            details,
            AuditOutcome::Success,
            None,
            ctx,
        )
        .await
    }

    pub async fn log_delete(
        &self,
        resource: AuditResource,
        resource_id: &str,
        details: serde_json::Value,
        ctx: &LogContext,
    ) -> Result<AuditLogEntry, String> {
        self.log(
            AuditAction::Delete,
            resource,
            Some(resource_id),
            details,
            AuditOutcome::Success,
            None,
            ctx,
        )
        .await
    }

    pub async fn log_login(
        &self,
        user_id: &str,
        success: bool,
        details: serde_json::Value,
        ctx: &LogContext,
    ) -> Result<AuditLogEntry, String> {
        let outcome = if success {
            AuditOutcome::Success
        } else {
            AuditOutcome::Failure
        };
        let error_msg = if success { None } else { Some("Login failed") };
        self.log(
            AuditAction::Login,
            AuditResource::User,
            Some(user_id),
            details,
            outcome,
            error_msg,
            ctx,
        )
        .await
    }

    pub async fn log_send(
        &self,
        message_id: &str,
        details: serde_json::Value,
        ctx: &LogContext,
    ) -> Result<AuditLogEntry, String> {
        self.log(
            AuditAction::Send,
            AuditResource::Message,
            Some(message_id),
            details,
            AuditOutcome::Success,
            None,
            ctx,
        )
        .await
    }

    pub async fn log_export(
        &self,
        resource: AuditResource,
        resource_id: &str,
        details: serde_json::Value,
        ctx: &LogContext,
    ) -> Result<AuditLogEntry, String> {
        self.log(
            AuditAction::Export,
            resource,
            Some(resource_id),
            details,
            AuditOutcome::Success,
            None,
            ctx,
        )
        .await
    }

    // ── Query ───────────────────────────────────────────────

    pub async fn query(&self, q: &AuditLogQuery) -> Result<(Vec<AuditLogEntry>, i64), String> {
        let limit = q.limit.unwrap_or(50).min(1000);
        let offset = q.offset.unwrap_or(0);

        let entries = self.query_entries_simple(q, limit, offset).await?;
        let total = self.count_entries_simple(q).await?;

        Ok((entries, total))
    }

    async fn query_entries_simple(
        &self,
        q: &AuditLogQuery,
        limit: i64,
        offset: i64,
    ) -> Result<Vec<AuditLogEntry>, String> {
        let rows: Vec<AuditRow> = sqlx::query_as(
            "SELECT id, tenant_id, user_id, session_id, action, resource, resource_id,
                    details, ip_address, user_agent, outcome, error_message,
                    timestamp, hash, previous_hash, signature
             FROM (SELECT * FROM audit_logs
                   UNION ALL
                   SELECT * FROM audit_logs_archive) entries
             WHERE ($1::text IS NULL OR tenant_id = $1)
               AND ($2::text IS NULL OR user_id = $2)
               AND ($3::text IS NULL OR action = $3)
               AND ($4::text IS NULL OR resource = $4)
               AND ($5::text IS NULL OR outcome = $5)
               AND ($6::timestamptz IS NULL OR timestamp >= $6)
               AND ($7::timestamptz IS NULL OR timestamp <= $7)
             ORDER BY timestamp DESC
             LIMIT $8 OFFSET $9",
        )
        .bind(&q.tenant_id)
        .bind(&q.user_id)
        .bind(q.action.map(|a| a.to_string()))
        .bind(q.resource.map(|r| r.to_string()))
        .bind(q.outcome.map(|o| o.to_string()))
        .bind(q.start_date)
        .bind(q.end_date)
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        rows.into_iter().map(|r| r.into_entry()).collect()
    }

    async fn count_entries_simple(&self, q: &AuditLogQuery) -> Result<i64, String> {
        let (count,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM (
               SELECT * FROM audit_logs
               UNION ALL
               SELECT * FROM audit_logs_archive) entries
             WHERE ($1::text IS NULL OR tenant_id = $1)
               AND ($2::text IS NULL OR user_id = $2)
               AND ($3::text IS NULL OR action = $3)
               AND ($4::text IS NULL OR resource = $4)
               AND ($5::text IS NULL OR outcome = $5)
               AND ($6::timestamptz IS NULL OR timestamp >= $6)
               AND ($7::timestamptz IS NULL OR timestamp <= $7)",
        )
        .bind(&q.tenant_id)
        .bind(&q.user_id)
        .bind(q.action.map(|a| a.to_string()))
        .bind(q.resource.map(|r| r.to_string()))
        .bind(q.outcome.map(|o| o.to_string()))
        .bind(q.start_date)
        .bind(q.end_date)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;
        Ok(count)
    }

    /// Get a single entry by ID (live table first, then the archive).
    pub async fn get_entry(&self, id: &str) -> Result<Option<AuditLogEntry>, String> {
        let row: Option<AuditRow> = sqlx::query_as(
            "SELECT id, tenant_id, user_id, session_id, action, resource, resource_id,
                    details, ip_address, user_agent, outcome, error_message,
                    timestamp, hash, previous_hash, signature
             FROM audit_logs WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        if row.is_some() {
            return row.map(|r| r.into_entry()).transpose();
        }

        let archived: Option<AuditRow> = sqlx::query_as(
            "SELECT id, tenant_id, user_id, session_id, action, resource, resource_id,
                    details, ip_address, user_agent, outcome, error_message,
                    timestamp, hash, previous_hash, signature
             FROM audit_logs_archive WHERE id = $1",
        )
        .bind(id)
        .fetch_optional(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        match archived {
            Some(r) => Ok(Some(r.into_entry()?)),
            None => Ok(None),
        }
    }

    // ── Chain Verification ──────────────────────────────────

    /// Verify the integrity of the hash chain for a given scope.
    pub fn verify_chain_entries(&self, entries: &[AuditLogEntry]) -> ChainValidationResult {
        if entries.is_empty() {
            return ChainValidationResult {
                valid: true,
                entries_checked: 0,
                first_invalid_entry: None,
                error: None,
            };
        }

        for (i, entry) in entries.iter().enumerate() {
            // Recompute hash
            let expected_hash = self.compute_hash(
                &entry.id,
                &entry.tenant_id,
                &entry.user_id,
                &entry.session_id,
                &entry.action,
                &entry.resource,
                &entry.resource_id,
                &entry.details,
                &entry.ip_address,
                &entry.user_agent,
                &entry.outcome,
                &entry.error_message,
                &entry.timestamp,
                &entry.previous_hash,
            );

            if expected_hash != entry.hash {
                return ChainValidationResult {
                    valid: false,
                    entries_checked: i + 1,
                    first_invalid_entry: Some(entry.id.clone()),
                    error: Some(format!("Hash mismatch at entry {}", entry.id)),
                };
            }

            // Verify HMAC signature
            let expected_sig = match self.compute_signature(&entry.hash) {
                Ok(v) => v,
                Err(e) => {
                    return ChainValidationResult {
                        valid: false,
                        entries_checked: i + 1,
                        first_invalid_entry: Some(entry.id.clone()),
                        error: Some(e),
                    }
                }
            };
            if expected_sig != entry.signature {
                return ChainValidationResult {
                    valid: false,
                    entries_checked: i + 1,
                    first_invalid_entry: Some(entry.id.clone()),
                    error: Some(format!("Signature mismatch at entry {}", entry.id)),
                };
            }

            // Verify chain linkage
            if i > 0 {
                let prev = &entries[i - 1];
                if entry.previous_hash.as_deref() != Some(&prev.hash) {
                    return ChainValidationResult {
                        valid: false,
                        entries_checked: i + 1,
                        first_invalid_entry: Some(entry.id.clone()),
                        error: Some(format!("Chain link broken at entry {}", entry.id)),
                    };
                }
            }
        }

        ChainValidationResult {
            valid: true,
            entries_checked: entries.len(),
            first_invalid_entry: None,
            error: None,
        }
    }

    /// Verify chain from DB for optional tenant scope.
    ///
    /// E-2: verification spans BOTH the live table and the archive — archived
    /// rows used to vanish from verification after archival.
    pub async fn verify_chain(
        &self,
        tenant_id: Option<&str>,
        start_date: Option<DateTime<Utc>>,
        end_date: Option<DateTime<Utc>>,
    ) -> Result<ChainValidationResult, String> {
        let rows: Vec<AuditRow> = sqlx::query_as(
            "SELECT id, tenant_id, user_id, session_id, action, resource, resource_id,
                    details, ip_address, user_agent, outcome, error_message,
                    timestamp, hash, previous_hash, signature
             FROM (SELECT * FROM audit_logs
                   UNION ALL
                   SELECT * FROM audit_logs_archive) entries
             WHERE ($1::text IS NULL OR tenant_id = $1)
               AND ($2::timestamptz IS NULL OR timestamp >= $2)
               AND ($3::timestamptz IS NULL OR timestamp <= $3)
             ORDER BY timestamp ASC",
        )
        .bind(tenant_id)
        .bind(start_date)
        .bind(end_date)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let entries: Vec<AuditLogEntry> = rows
            .into_iter()
            .map(|r| r.into_entry())
            .collect::<Result<Vec<_>, _>>()?;

        Ok(self.verify_chain_entries(&entries))
    }

    // ── Export ───────────────────────────────────────────────

    /// Export audit logs in the specified format.
    pub async fn export(
        &self,
        query: &AuditLogQuery,
        format: &str,
    ) -> Result<ExportResult, String> {
        let (entries, _total) = self.query(query).await?;

        match format {
            "json" => {
                let data =
                    serde_json::to_string_pretty(&entries).map_err(|e| format!("JSON: {e}"))?;
                Ok(ExportResult {
                    data,
                    content_type: "application/json".into(),
                    filename: format!("audit-export-{}.json", Utc::now().format("%Y%m%d%H%M%S")),
                })
            }
            "csv" => {
                let mut csv = String::from(
                    "id,tenant_id,user_id,action,resource,resource_id,outcome,timestamp,hash\n",
                );
                for e in &entries {
                    csv.push_str(&format!(
                        "{},{},{},{},{},{},{},{},{}\n",
                        csv_escape(&e.id),
                        csv_escape(e.tenant_id.as_deref().unwrap_or("")),
                        csv_escape(e.user_id.as_deref().unwrap_or("")),
                        csv_escape(&e.action.to_string()),
                        csv_escape(&e.resource.to_string()),
                        csv_escape(e.resource_id.as_deref().unwrap_or("")),
                        csv_escape(&e.outcome.to_string()),
                        csv_escape(&e.timestamp.to_rfc3339()),
                        csv_escape(&e.hash),
                    ));
                }
                Ok(ExportResult {
                    data: csv,
                    content_type: "text/csv".into(),
                    filename: format!("audit-export-{}.csv", Utc::now().format("%Y%m%d%H%M%S")),
                })
            }
            "pdf" => {
                // Minimal PDF 1.4 generation (Courier font, text-only)
                let data = generate_simple_pdf(&entries);
                Ok(ExportResult {
                    data,
                    content_type: "application/pdf".into(),
                    filename: format!("audit-export-{}.pdf", Utc::now().format("%Y%m%d%H%M%S")),
                })
            }
            _ => Err(format!("Unsupported export format: {format}")),
        }
    }

    // ── Stats ───────────────────────────────────────────────

    pub async fn get_stats(&self, tenant_id: Option<&str>) -> Result<serde_json::Value, String> {
        let (total,): (i64,) = sqlx::query_as(
            "SELECT COUNT(*) FROM (
               SELECT * FROM audit_logs
               UNION ALL
               SELECT * FROM audit_logs_archive) entries
             WHERE ($1::text IS NULL OR tenant_id = $1)",
        )
        .bind(tenant_id)
        .fetch_one(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let by_action: Vec<(String, i64)> = sqlx::query_as(
            "SELECT action, COUNT(*) FROM (
               SELECT * FROM audit_logs
               UNION ALL
               SELECT * FROM audit_logs_archive) entries
             WHERE ($1::text IS NULL OR tenant_id = $1) GROUP BY action",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let by_resource: Vec<(String, i64)> = sqlx::query_as(
            "SELECT resource, COUNT(*) FROM (
               SELECT * FROM audit_logs
               UNION ALL
               SELECT * FROM audit_logs_archive) entries
             WHERE ($1::text IS NULL OR tenant_id = $1) GROUP BY resource",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        let by_outcome: Vec<(String, i64)> = sqlx::query_as(
            "SELECT outcome, COUNT(*) FROM (
               SELECT * FROM audit_logs
               UNION ALL
               SELECT * FROM audit_logs_archive) entries
             WHERE ($1::text IS NULL OR tenant_id = $1) GROUP BY outcome",
        )
        .bind(tenant_id)
        .fetch_all(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(serde_json::json!({
            "total_entries": total,
            "by_action": by_action.into_iter().collect::<HashMap<_,_>>(),
            "by_resource": by_resource.into_iter().collect::<HashMap<_,_>>(),
            "by_outcome": by_outcome.into_iter().collect::<HashMap<_,_>>(),
        }))
    }

    // ── Archival ────────────────────────────────────────────

    /// Archive audit logs older than the specified date.
    ///
    /// E-2: the copy and the delete happen in ONE transaction, and rows are
    /// deleted only when they verifiably exist in the archive afterwards.
    /// Rows that failed to copy (e.g. pre-existing conflicting archive rows)
    /// are preserved in the live table — they no longer vanish from
    /// verify/export.
    ///
    /// F5 (legal-hold aware): rows belonging to tenants with an active
    /// `tenants.legal_hold` are never archived away — removing them from the
    /// live (or any) table under a hold is evidence spoliation. Rows with a
    /// NULL tenant_id cannot be attributed and are KEPT whenever any hold is
    /// active (fall back to keep). Both the copy and the delete apply the
    /// same exclusion, so held rows simply stay live.
    pub async fn archive(&self, older_than: DateTime<Utc>) -> Result<i64, String> {
        // Held tenants, best-effort: no tenants table / no legal_hold column
        // (pre-121) → no exclusion possible, behave as before.
        let held: Option<Vec<String>> =
            match sqlx::query_scalar("SELECT id FROM tenants WHERE legal_hold = true")
                .fetch_all(&self.db)
                .await
            {
                Ok(ids) => Some(ids),
                Err(e) if is_undefined_table(&e) => None,
                Err(e) if is_undefined_column(&e) => None,
                Err(e) => return Err(format!("DB error (legal hold lookup): {e}")),
            };
        // `tenant_id IS NOT NULL AND tenant_id <> ALL($2)`: NULL-tenant rows
        // are excluded too while any hold is active.
        let any_held = held.as_ref().is_some_and(|ids| !ids.is_empty());
        let not_held = if any_held {
            " AND (a.tenant_id IS NOT NULL AND a.tenant_id <> ALL($2))"
        } else {
            ""
        };
        let bind_held = if any_held { held.as_ref() } else { None };

        let mut tx = self
            .db
            .begin()
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        let copy_sql = format!(
            "INSERT INTO audit_logs_archive
             SELECT * FROM audit_logs a WHERE a.timestamp < $1{not_held}
             ON CONFLICT DO NOTHING"
        );
        let mut copy = sqlx::query(&copy_sql).bind(older_than);
        if let Some(ids) = bind_held {
            copy = copy.bind(ids);
        }
        let result = copy
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        let archived = result.rows_affected() as i64;

        // Delete only rows that verifiably landed in the archive: same id AND
        // same chain hash. A pre-existing conflicting archive row (different
        // content) means the copy did NOT verifiably happen for that row —
        // the live original is preserved.
        let delete_sql = format!(
            "DELETE FROM audit_logs a
             WHERE a.timestamp < $1{not_held}
               AND EXISTS (
                 SELECT 1 FROM audit_logs_archive b
                 WHERE b.id = a.id AND b.hash = a.hash
               )"
        );
        let mut delete = sqlx::query(&delete_sql).bind(older_than);
        if let Some(ids) = bind_held {
            delete = delete.bind(ids);
        }
        delete
            .execute(&mut *tx)
            .await
            .map_err(|e| format!("DB error: {e}"))?;

        tx.commit().await.map_err(|e| format!("DB error: {e}"))?;

        info!(archived, "Audit logs archived");
        Ok(archived)
    }

    // ── Webhook Registration ────────────────────────────────

    pub async fn register_webhook(
        &self,
        tenant_id: &str,
        url: &str,
        events: &[AuditAction],
    ) -> Result<String, String> {
        let id = Uuid::new_v4().to_string();
        let events_json: Vec<String> = events.iter().map(|a| a.to_string()).collect();
        let events_val = serde_json::to_value(&events_json).map_err(|e| format!("JSON: {e}"))?;

        sqlx::query(
            "INSERT INTO audit_webhooks (id, tenant_id, url, events, created_at)
             VALUES ($1, $2, $3, $4, NOW())",
        )
        .bind(&id)
        .bind(tenant_id)
        .bind(url)
        .bind(&events_val)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(id)
    }

    // ── Hash & Signature Computation ────────────────────────

    #[allow(clippy::too_many_arguments)]
    fn compute_hash(
        &self,
        id: &str,
        tenant_id: &Option<String>,
        user_id: &Option<String>,
        session_id: &Option<String>,
        action: &AuditAction,
        resource: &AuditResource,
        resource_id: &Option<String>,
        details: &serde_json::Value,
        ip_address: &Option<String>,
        user_agent: &Option<String>,
        outcome: &AuditOutcome,
        error_message: &Option<String>,
        timestamp: &DateTime<Utc>,
        previous_hash: &Option<String>,
    ) -> String {
        // Deterministic JSON object with sorted keys (manual assembly)
        let obj = serde_json::json!({
            "action": action.to_string(),
            "details": details,
            "errorMessage": error_message,
            "id": id,
            "ipAddress": ip_address,
            "outcome": outcome.to_string(),
            "previousHash": previous_hash,
            "resource": resource.to_string(),
            "resourceId": resource_id,
            "sessionId": session_id,
            "tenantId": tenant_id,
            "timestamp": timestamp.to_rfc3339(),
            "userAgent": user_agent,
            "userId": user_id,
        });

        let serialized = serde_json::to_string(&obj).unwrap_or_else(|e| {
            tracing::error!(error = %e, "Failed to serialize audit log entry, using empty string");
            String::new()
        });
        let mut hasher = Sha256::new();
        hasher.update(serialized.as_bytes());
        hex::encode(hasher.finalize())
    }

    fn compute_signature(&self, hash: &str) -> Result<String, String> {
        let mut mac = HmacSha256::new_from_slice(&self.signing_key)
            .map_err(|e| format!("Invalid HMAC key: {e}"))?;
        mac.update(hash.as_bytes());
        Ok(hex::encode(mac.finalize().into_bytes()))
    }

    async fn persist_entry(&self, entry: &AuditLogEntry) -> Result<(), String> {
        sqlx::query(
            "INSERT INTO audit_logs
               (id, tenant_id, user_id, session_id, action, resource, resource_id,
                details, ip_address, user_agent, outcome, error_message,
                timestamp, hash, previous_hash, signature)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12,$13,$14,$15,$16)",
        )
        .bind(&entry.id)
        .bind(&entry.tenant_id)
        .bind(&entry.user_id)
        .bind(&entry.session_id)
        .bind(entry.action.to_string())
        .bind(entry.resource.to_string())
        .bind(&entry.resource_id)
        .bind(&entry.details)
        .bind(&entry.ip_address)
        .bind(&entry.user_agent)
        .bind(entry.outcome.to_string())
        .bind(&entry.error_message)
        .bind(entry.timestamp)
        .bind(&entry.hash)
        .bind(&entry.previous_hash)
        .bind(&entry.signature)
        .execute(&self.db)
        .await
        .map_err(|e| format!("DB error: {e}"))?;

        Ok(())
    }
}

// ─── Export Result ──────────────────────────────────────────────

/// Postgres undefined_table (42P01).
fn is_undefined_table(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c == "42P01")
        .unwrap_or(false)
}

/// Postgres undefined_column (42703) — e.g. `tenants.legal_hold` before
/// migration 121 on a runtime-provisioned database.
fn is_undefined_column(err: &sqlx::Error) -> bool {
    err.as_database_error()
        .and_then(|d| d.code())
        .map(|c| c == "42703")
        .unwrap_or(false)
}

#[derive(Debug, Clone)]
pub struct ExportResult {
    pub data: String,
    pub content_type: String,
    pub filename: String,
}

fn csv_escape(value: &str) -> String {
    let mut escaped = value.replace('"', "\"\"");
    // Protect against CSV formula injection:
    // 1. Leading special characters (=, +, -, @, tab, CR) — prefix with single quote
    // 2. Mid-string formulas containing these characters — also prefix
    // 3. DDE (Dynamic Data Exchange) expressions like `=cmd|` anywhere in cell
    let needs_formula_prefix = matches!(
        escaped.chars().next(),
        Some('=') | Some('+') | Some('-') | Some('@') | Some('\t') | Some('\r')
    ) || escaped.contains("\t=")
        || escaped.contains("\t+")
        || escaped.contains("\t-")
        || escaped.contains("\t@")
        || escaped.contains("\r=")
        || escaped.contains("\r+")
        || escaped.contains("\r-")
        || escaped.contains("\r@")
        || escaped.contains("|='")
        || escaped.contains("|=\"")
        || escaped.contains("=cmd|")
        || escaped.contains("=compose|")
        || escaped.contains("=HYPERLINK(")
        || escaped.contains("=DDE(");
    if needs_formula_prefix {
        escaped.insert(0, '\'');
    }
    // Always quote the field if it contains special CSV characters
    // or if we just added a formula prefix
    if needs_formula_prefix
        || escaped.contains(',')
        || escaped.contains('"')
        || escaped.contains('\n')
        || escaped.contains('\r')
    {
        format!("\"{}\"", escaped)
    } else {
        escaped
    }
}

// ─── Minimal PDF generator ─────────────────────────────────────

fn generate_simple_pdf(entries: &[AuditLogEntry]) -> String {
    // Generate a minimal text-based PDF 1.4
    let mut lines = Vec::with_capacity(entries.len().saturating_add(4));
    lines.push("Audit Log Export".to_string());
    lines.push(format!("Generated: {}", Utc::now().to_rfc3339()));
    lines.push(format!("Total entries: {}", entries.len()));
    lines.push(String::new());

    for e in entries {
        lines.push(format!(
            "{} | {} {} {} | {} | {}",
            e.timestamp.format("%Y-%m-%d %H:%M:%S"),
            e.action,
            e.resource,
            e.resource_id.as_deref().unwrap_or("-"),
            e.outcome,
            e.user_id.as_deref().unwrap_or("-"),
        ));
    }

    // Minimal PDF structure
    let content = lines.join("\n");
    let stream = format!("BT /F1 10 Tf 50 750 Td ({content}) Tj ET");
    let stream_len = stream.len();

    format!(
        "%PDF-1.4\n\
         1 0 obj <</Type /Catalog /Pages 2 0 R>> endobj\n\
         2 0 obj <</Type /Pages /Kids [3 0 R] /Count 1>> endobj\n\
         3 0 obj <</Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Contents 4 0 R /Resources <</Font <</F1 5 0 R>>>>>> endobj\n\
         4 0 obj <</Length {stream_len}>>\nstream\n{stream}\nendstream\nendobj\n\
         5 0 obj <</Type /Font /Subtype /Type1 /BaseFont /Courier>> endobj\n\
         xref\n0 6\n\
         trailer <</Size 6 /Root 1 0 R>>\n\
         startxref\n0\n%%EOF"
    )
}

// ─── DB row helper ─────────────────────────────────────────────

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: String,
    tenant_id: Option<String>,
    user_id: Option<String>,
    session_id: Option<String>,
    action: String,
    resource: String,
    resource_id: Option<String>,
    details: serde_json::Value,
    ip_address: Option<String>,
    user_agent: Option<String>,
    outcome: String,
    error_message: Option<String>,
    timestamp: DateTime<Utc>,
    hash: String,
    previous_hash: Option<String>,
    signature: String,
}

impl AuditRow {
    fn into_entry(self) -> Result<AuditLogEntry, String> {
        let action: AuditAction =
            serde_json::from_value(serde_json::Value::String(self.action.clone()))
                .map_err(|_| format!("Invalid action: {}", self.action))?;

        let resource: AuditResource =
            serde_json::from_value(serde_json::Value::String(self.resource.clone()))
                .map_err(|_| format!("Invalid resource: {}", self.resource))?;

        let outcome: AuditOutcome =
            serde_json::from_value(serde_json::Value::String(self.outcome.clone()))
                .map_err(|_| format!("Invalid outcome: {}", self.outcome))?;

        Ok(AuditLogEntry {
            id: self.id,
            tenant_id: self.tenant_id,
            user_id: self.user_id,
            session_id: self.session_id,
            action,
            resource,
            resource_id: self.resource_id,
            details: self.details,
            ip_address: self.ip_address,
            user_agent: self.user_agent,
            outcome,
            error_message: self.error_message,
            timestamp: self.timestamp,
            hash: self.hash,
            previous_hash: self.previous_hash,
            signature: self.signature,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime() -> &'static tokio::runtime::Runtime {
        use std::sync::OnceLock;
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| {
            tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .unwrap()
        })
    }

    fn test_logger() -> AuditLogger {
        let _guard = test_runtime().enter();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap();
        let config = AuditConfig {
            retention_days: 365,
            hash_chain_enabled: true,
            signing_key: "test-signing-key-that-is-at-least-32-chars-long!!".into(),
        };
        AuditLogger::new(pool, config)
    }

    #[allow(dead_code)]
    fn test_context() -> LogContext {
        LogContext {
            tenant_id: Some("tenant-1".into()),
            user_id: Some("user-1".into()),
            session_id: Some("session-1".into()),
            ip_address: Some("192.168.1.1".into()),
            user_agent: Some("TestAgent/1.0".into()),
        }
    }

    #[test]
    fn test_compute_hash_deterministic() {
        let logger = test_logger();
        let ts = Utc::now();
        let details = serde_json::json!({"key": "value"});

        let h1 = logger.compute_hash(
            "id1",
            &Some("t1".into()),
            &Some("u1".into()),
            &None,
            &AuditAction::Create,
            &AuditResource::User,
            &Some("r1".into()),
            &details,
            &None,
            &None,
            &AuditOutcome::Success,
            &None,
            &ts,
            &None,
        );
        let h2 = logger.compute_hash(
            "id1",
            &Some("t1".into()),
            &Some("u1".into()),
            &None,
            &AuditAction::Create,
            &AuditResource::User,
            &Some("r1".into()),
            &details,
            &None,
            &None,
            &AuditOutcome::Success,
            &None,
            &ts,
            &None,
        );
        assert_eq!(h1, h2);
        assert_eq!(h1.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_compute_hash_changes_with_input() {
        let logger = test_logger();
        let ts = Utc::now();
        let details = serde_json::json!({"key": "value"});

        let h1 = logger.compute_hash(
            "id1",
            &Some("t1".into()),
            &None,
            &None,
            &AuditAction::Create,
            &AuditResource::User,
            &None,
            &details,
            &None,
            &None,
            &AuditOutcome::Success,
            &None,
            &ts,
            &None,
        );
        let h2 = logger.compute_hash(
            "id2",
            &Some("t1".into()),
            &None,
            &None,
            &AuditAction::Create,
            &AuditResource::User,
            &None,
            &details,
            &None,
            &None,
            &AuditOutcome::Success,
            &None,
            &ts,
            &None,
        );
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_signature_deterministic() {
        let logger = test_logger();
        let s1 = logger.compute_signature("testhash").unwrap();
        let s2 = logger.compute_signature("testhash").unwrap();
        assert_eq!(s1, s2);
        assert_eq!(s1.len(), 64); // HMAC-SHA-256 hex
    }

    #[test]
    fn test_compute_signature_changes_with_key() {
        let logger1 = test_logger();
        let _guard = test_runtime().enter();
        let pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap();
        let logger2 = AuditLogger::new(
            pool,
            AuditConfig {
                retention_days: 365,
                hash_chain_enabled: true,
                signing_key: "different-key-that-is-at-least-32-characters!!".into(),
            },
        );

        let s1 = logger1.compute_signature("samehash").unwrap();
        let s2 = logger2.compute_signature("samehash").unwrap();
        assert_ne!(s1, s2);
    }

    #[test]
    fn test_chain_verification_empty() {
        let logger = test_logger();
        let result = logger.verify_chain_entries(&[]);
        assert!(result.valid);
        assert_eq!(result.entries_checked, 0);
    }

    #[test]
    fn test_chain_verification_single_entry() {
        let logger = test_logger();
        let ts = Utc::now();
        let details = serde_json::json!({});

        let hash = logger.compute_hash(
            "e1",
            &Some("t1".into()),
            &Some("u1".into()),
            &None,
            &AuditAction::Create,
            &AuditResource::User,
            &None,
            &details,
            &None,
            &None,
            &AuditOutcome::Success,
            &None,
            &ts,
            &None,
        );
        let sig = logger.compute_signature(&hash).unwrap();

        let entry = AuditLogEntry {
            id: "e1".into(),
            tenant_id: Some("t1".into()),
            user_id: Some("u1".into()),
            session_id: None,
            action: AuditAction::Create,
            resource: AuditResource::User,
            resource_id: None,
            details,
            ip_address: None,
            user_agent: None,
            outcome: AuditOutcome::Success,
            error_message: None,
            timestamp: ts,
            hash,
            previous_hash: None,
            signature: sig,
        };

        let result = logger.verify_chain_entries(&[entry]);
        assert!(result.valid);
        assert_eq!(result.entries_checked, 1);
    }

    #[test]
    fn test_chain_verification_two_entries_valid() {
        let logger = test_logger();
        let ts1 = Utc::now();
        let ts2 = ts1 + Duration::seconds(1);
        let details = serde_json::json!({});

        // Entry 1 (no previous)
        let hash1 = logger.compute_hash(
            "e1",
            &Some("t1".into()),
            &None,
            &None,
            &AuditAction::Create,
            &AuditResource::User,
            &None,
            &details,
            &None,
            &None,
            &AuditOutcome::Success,
            &None,
            &ts1,
            &None,
        );
        let sig1 = logger.compute_signature(&hash1).unwrap();
        let entry1 = AuditLogEntry {
            id: "e1".into(),
            tenant_id: Some("t1".into()),
            user_id: None,
            session_id: None,
            action: AuditAction::Create,
            resource: AuditResource::User,
            resource_id: None,
            details: details.clone(),
            ip_address: None,
            user_agent: None,
            outcome: AuditOutcome::Success,
            error_message: None,
            timestamp: ts1,
            hash: hash1.clone(),
            previous_hash: None,
            signature: sig1,
        };

        // Entry 2 (previous = hash1)
        let hash2 = logger.compute_hash(
            "e2",
            &Some("t1".into()),
            &None,
            &None,
            &AuditAction::Update,
            &AuditResource::User,
            &None,
            &details,
            &None,
            &None,
            &AuditOutcome::Success,
            &None,
            &ts2,
            &Some(hash1.clone()),
        );
        let sig2 = logger.compute_signature(&hash2).unwrap();
        let entry2 = AuditLogEntry {
            id: "e2".into(),
            tenant_id: Some("t1".into()),
            user_id: None,
            session_id: None,
            action: AuditAction::Update,
            resource: AuditResource::User,
            resource_id: None,
            details,
            ip_address: None,
            user_agent: None,
            outcome: AuditOutcome::Success,
            error_message: None,
            timestamp: ts2,
            hash: hash2,
            previous_hash: Some(hash1),
            signature: sig2,
        };

        let result = logger.verify_chain_entries(&[entry1, entry2]);
        assert!(result.valid);
        assert_eq!(result.entries_checked, 2);
    }

    #[test]
    fn test_chain_verification_tampered_hash() {
        let logger = test_logger();
        let ts = Utc::now();
        let details = serde_json::json!({});

        let real_hash = logger.compute_hash(
            "e1",
            &Some("t1".into()),
            &None,
            &None,
            &AuditAction::Create,
            &AuditResource::User,
            &None,
            &details,
            &None,
            &None,
            &AuditOutcome::Success,
            &None,
            &ts,
            &None,
        );
        let sig = logger.compute_signature(&real_hash).unwrap();

        let entry = AuditLogEntry {
            id: "e1".into(),
            tenant_id: Some("t1".into()),
            user_id: None,
            session_id: None,
            action: AuditAction::Create,
            resource: AuditResource::User,
            resource_id: None,
            details,
            ip_address: None,
            user_agent: None,
            outcome: AuditOutcome::Success,
            error_message: None,
            timestamp: ts,
            hash: "tampered_hash_value_not_real".into(), // tampered!
            previous_hash: None,
            signature: sig,
        };

        let result = logger.verify_chain_entries(&[entry]);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("Hash mismatch"));
    }

    #[test]
    fn test_chain_verification_broken_link() {
        let logger = test_logger();
        let ts1 = Utc::now();
        let ts2 = ts1 + Duration::seconds(1);
        let details = serde_json::json!({});

        let hash1 = logger.compute_hash(
            "e1",
            &Some("t1".into()),
            &None,
            &None,
            &AuditAction::Create,
            &AuditResource::User,
            &None,
            &details,
            &None,
            &None,
            &AuditOutcome::Success,
            &None,
            &ts1,
            &None,
        );
        let sig1 = logger.compute_signature(&hash1).unwrap();
        let entry1 = AuditLogEntry {
            id: "e1".into(),
            tenant_id: Some("t1".into()),
            user_id: None,
            session_id: None,
            action: AuditAction::Create,
            resource: AuditResource::User,
            resource_id: None,
            details: details.clone(),
            ip_address: None,
            user_agent: None,
            outcome: AuditOutcome::Success,
            error_message: None,
            timestamp: ts1,
            hash: hash1,
            previous_hash: None,
            signature: sig1,
        };

        // Entry 2 with WRONG previous hash
        let wrong_prev = Some("wrong_previous_hash".to_string());
        let hash2 = logger.compute_hash(
            "e2",
            &Some("t1".into()),
            &None,
            &None,
            &AuditAction::Update,
            &AuditResource::User,
            &None,
            &details,
            &None,
            &None,
            &AuditOutcome::Success,
            &None,
            &ts2,
            &wrong_prev,
        );
        let sig2 = logger.compute_signature(&hash2).unwrap();
        let entry2 = AuditLogEntry {
            id: "e2".into(),
            tenant_id: Some("t1".into()),
            user_id: None,
            session_id: None,
            action: AuditAction::Update,
            resource: AuditResource::User,
            resource_id: None,
            details,
            ip_address: None,
            user_agent: None,
            outcome: AuditOutcome::Success,
            error_message: None,
            timestamp: ts2,
            hash: hash2,
            previous_hash: wrong_prev,
            signature: sig2,
        };

        let result = logger.verify_chain_entries(&[entry1, entry2]);
        assert!(!result.valid);
        assert!(result.error.unwrap().contains("Chain link broken"));
    }

    #[test]
    fn test_export_csv_format() {
        let ts = Utc::now();
        let entry = AuditLogEntry {
            id: "e1".into(),
            tenant_id: Some("t1".into()),
            user_id: Some("u1".into()),
            session_id: None,
            action: AuditAction::Create,
            resource: AuditResource::User,
            resource_id: Some("r1".into()),
            details: serde_json::json!({}),
            ip_address: None,
            user_agent: None,
            outcome: AuditOutcome::Success,
            error_message: None,
            timestamp: ts,
            hash: "abc".into(),
            previous_hash: None,
            signature: "def".into(),
        };

        // Test CSV generation manually
        let csv = format!(
            "{},{},{},{},{},{},{},{},{}",
            entry.id,
            entry.tenant_id.as_deref().unwrap_or(""),
            entry.user_id.as_deref().unwrap_or(""),
            entry.action,
            entry.resource,
            entry.resource_id.as_deref().unwrap_or(""),
            entry.outcome,
            entry.timestamp.to_rfc3339(),
            entry.hash,
        );
        assert!(csv.starts_with("e1,t1,u1,create,user,r1,success,"));
    }

    #[test]
    fn test_pdf_generation() {
        let entries = vec![AuditLogEntry {
            id: "e1".into(),
            tenant_id: None,
            user_id: None,
            session_id: None,
            action: AuditAction::Login,
            resource: AuditResource::User,
            resource_id: None,
            details: serde_json::json!({}),
            ip_address: None,
            user_agent: None,
            outcome: AuditOutcome::Success,
            error_message: None,
            timestamp: Utc::now(),
            hash: "h".into(),
            previous_hash: None,
            signature: "s".into(),
        }];
        let pdf = generate_simple_pdf(&entries);
        assert!(pdf.starts_with("%PDF-1.4"));
        assert!(pdf.contains("%%EOF"));
    }

    #[test]
    fn test_last_hash_cache() {
        let logger = test_logger();
        {
            let mut map = logger.last_hashes.blocking_write();
            map.insert("tenant-a".into(), "hash123".into());
        }
        {
            let map = logger.last_hashes.blocking_read();
            assert_eq!(map.get("tenant-a").unwrap(), "hash123");
        }
    }
}
