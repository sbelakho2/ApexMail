//! Audit logging with buffered writes and hash-chain integrity.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use chrono::{Duration, Utc};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use sqlx::PgPool;
use tokio::sync::RwLock;
use tracing::info;
use uuid::Uuid;
use zeroize::Zeroizing;

use crate::config::SecurityConfig;
use crate::types::*;

// ── Audit Service ──────────────────────────────────────────

/// HKDF info label for the audit-log HMAC subkey.
const AUDIT_HMAC_INFO: &[u8] = b"apexmail-isolation/audit-hmac/v1";

/// Derive a dedicated HMAC subkey from the master encryption key via
/// HKDF-SHA256. The master key itself must never be used directly as an HMAC
/// key:compromise of one usage must not imply compromise of the other, and
/// the audit hash chain must be verifiable without exposing the KEK.
fn derive_audit_hmac_key(master_key: &str) -> Zeroizing<String> {
    let hk = Hkdf::<Sha256>::new(None, master_key.as_bytes());
    let mut okm = [0u8; 32];
    // 32 bytes is a valid HKDF-SHA256 output length, expand cannot fail.
    hk.expand(AUDIT_HMAC_INFO, &mut okm)
        .expect("32-byte HKDF-SHA256 output is always valid");
    Zeroizing::new(hex::encode(okm))
}

pub struct AuditService {
    db: PgPool,
    config: SecurityConfig,
    signing_key: Zeroizing<String>,
    buffer: RwLock<Vec<AuditEvent>>,
    /// Registry of per-org flush locks (F12). Two concurrent flushes for the
    /// same org both read the SAME "latest hash" before either inserts, so
    /// the chain forks into two heads. Each org's flush is serialized
    /// in-process; multi-org batches acquire the org locks in SORTED order
    /// so overlapping batches can never deadlock.
    flush_locks: tokio::sync::Mutex<
        std::collections::HashMap<String, std::sync::Arc<tokio::sync::Mutex<()>>>,
    >,
}

impl AuditService {
    pub fn new(db: PgPool, config: SecurityConfig) -> Self {
        let signing_key = derive_audit_hmac_key(&config.encryption_key);
        Self {
            db,
            config,
            signing_key,
            buffer: RwLock::new(Vec::new()),
            flush_locks: tokio::sync::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Log an audit event. Critical events are flushed immediately.
    pub async fn log(&self, event: AuditEvent) -> anyhow::Result<AuditEvent> {
        let is_critical = event.severity == AuditSeverity::Critical;

        {
            let mut buf = self.buffer.write().await;
            buf.push(event.clone());

            if is_critical || buf.len() >= 100 {
                let events: Vec<AuditEvent> = buf.drain(..).collect();
                drop(buf);
                self.flush_events(events).await?;
            }
        }

        Ok(event)
    }

    /// Create a new audit event with auto-generated ID and timestamp.
    #[allow(clippy::too_many_arguments)]
    pub fn create_event(
        &self,
        organization_id: &str,
        workspace_id: Option<&str>,
        event_type: AuditEventType,
        severity: AuditSeverity,
        actor_id: &str,
        actor_type: &str,
        resource: Option<&str>,
        resource_id: Option<&str>,
        action: &str,
        details: serde_json::Value,
    ) -> AuditEvent {
        AuditEvent {
            id: Uuid::new_v4().to_string(),
            organization_id: organization_id.into(),
            workspace_id: workspace_id.map(Into::into),
            event_type,
            severity,
            actor_id: actor_id.into(),
            actor_type: actor_type.into(),
            actor_ip: None,
            actor_user_agent: None,
            resource: resource.map(Into::into),
            resource_id: resource_id.map(Into::into),
            action: action.into(),
            details,
            metadata: serde_json::json!({}),
            timestamp: Utc::now(),
        }
    }

    /// Verify the hash chain for an organization's audit logs.
    pub async fn verify_hash_chain(
        &self,
        organization_id: &str,
        start_time: Option<chrono::DateTime<Utc>>,
        end_time: Option<chrono::DateTime<Utc>>,
    ) -> anyhow::Result<HashChainResult> {
        let mut query = String::from(
            "SELECT id, organization_id, workspace_id, event_type, severity, actor_id, actor_type,
             actor_ip, actor_user_agent, resource, resource_id, action, details, metadata, created_at
             FROM iso_audit_logs WHERE organization_id = $1"
        );
        let mut param_idx = 2;

        if start_time.is_some() {
            query.push_str(&format!(" AND created_at >= ${}", param_idx));
            param_idx += 1;
        }
        if end_time.is_some() {
            query.push_str(&format!(" AND created_at <= ${}", param_idx));
        }
        query.push_str(" ORDER BY created_at ASC");

        let mut q = sqlx::query_as::<_, AuditRow>(&query).bind(organization_id);
        if let Some(st) = start_time {
            q = q.bind(st);
        }
        if let Some(et) = end_time {
            q = q.bind(et);
        }

        let rows: Vec<AuditRow> = q.fetch_all(&self.db).await?;

        // F12:verify in CHAIN order. The SQL created_at ordering does not
        // necessarily reflect chain order (interleaved flushes, windowed
        // queries), so the traversal follows previous_hash links and only
        // falls back to created_at for the start points.
        verify_chain_rows(&rows, &self.signing_key)
    }

    /// Query audit events with pagination and filtering.
    pub async fn query(&self, q: &AuditQuery) -> anyhow::Result<(Vec<AuditEvent>, i64)> {
        let limit = q.limit.unwrap_or(50).min(1000);
        let offset = q.offset.unwrap_or(0);
        self.query_with_limit_offset(q, limit, offset).await
    }

    async fn query_with_limit_offset(
        &self,
        q: &AuditQuery,
        limit: i64,
        offset: i64,
    ) -> anyhow::Result<(Vec<AuditEvent>, i64)> {
        let mut conditions = vec!["organization_id = $1".to_string()];
        let mut param_count = 1;

        if q.workspace_id.is_some() {
            param_count += 1;
            conditions.push(format!("workspace_id = ${}", param_count));
        }
        if q.severity.is_some() {
            param_count += 1;
            conditions.push(format!("severity = ${}", param_count));
        }
        if q.actor_id.is_some() {
            param_count += 1;
            conditions.push(format!("actor_id = ${}", param_count));
        }
        if q.resource.is_some() {
            param_count += 1;
            conditions.push(format!("resource = ${}", param_count));
        }
        if q.start_time.is_some() {
            param_count += 1;
            conditions.push(format!("created_at >= ${}", param_count));
        }
        if q.end_time.is_some() {
            param_count += 1;
            conditions.push(format!("created_at <= ${}", param_count));
        }

        let where_clause = conditions.join(" AND ");
        let limit_param = param_count + 1;
        let offset_param = param_count + 2;
        let count_sql = format!("SELECT COUNT(*) FROM iso_audit_logs WHERE {}", where_clause);
        let select_sql = format!(
            "SELECT id, organization_id, workspace_id, event_type, severity, actor_id, actor_type,
             actor_ip, actor_user_agent, resource, resource_id, action, details, metadata, created_at
             FROM iso_audit_logs WHERE {} ORDER BY created_at DESC LIMIT ${} OFFSET ${}",
            where_clause, limit_param, offset_param
        );

        // Build count query
        let mut count_q = sqlx::query_scalar::<_, i64>(&count_sql).bind(&q.organization_id);
        let mut select_q = sqlx::query_as::<_, AuditRow>(&select_sql).bind(&q.organization_id);

        if let Some(ref ws) = q.workspace_id {
            count_q = count_q.bind(ws);
            select_q = select_q.bind(ws);
        }
        if let Some(ref sev) = q.severity {
            count_q = count_q.bind(sev);
            select_q = select_q.bind(sev);
        }
        if let Some(ref actor) = q.actor_id {
            count_q = count_q.bind(actor);
            select_q = select_q.bind(actor);
        }
        if let Some(ref res) = q.resource {
            count_q = count_q.bind(res);
            select_q = select_q.bind(res);
        }
        if let Some(st) = q.start_time {
            count_q = count_q.bind(st);
            select_q = select_q.bind(st);
        }
        if let Some(et) = q.end_time {
            count_q = count_q.bind(et);
            select_q = select_q.bind(et);
        }

        select_q = select_q.bind(limit).bind(offset);

        let total = count_q.fetch_one(&self.db).await?;
        let rows = select_q.fetch_all(&self.db).await?;

        let events: Vec<AuditEvent> = rows.into_iter().map(|r| r.into_event()).collect();
        Ok((events, total))
    }

    /// Get audit statistics for an organization.
    pub async fn get_stats(&self, organization_id: &str, days: i64) -> anyhow::Result<AuditStats> {
        let since = Utc::now() - Duration::days(days);

        let total: i64 = sqlx::query_scalar(
            "SELECT COUNT(*) FROM iso_audit_logs WHERE organization_id=$1 AND created_at >= $2",
        )
        .bind(organization_id)
        .bind(since)
        .fetch_one(&self.db)
        .await?;

        let by_type: Vec<(String, i64)> = sqlx::query_as(
            "SELECT event_type, COUNT(*) FROM iso_audit_logs
             WHERE organization_id=$1 AND created_at >= $2
             GROUP BY event_type ORDER BY count DESC",
        )
        .bind(organization_id)
        .bind(since)
        .fetch_all(&self.db)
        .await?;

        let by_severity: Vec<(String, i64)> = sqlx::query_as(
            "SELECT severity, COUNT(*) FROM iso_audit_logs
             WHERE organization_id=$1 AND created_at >= $2
             GROUP BY severity ORDER BY count DESC",
        )
        .bind(organization_id)
        .bind(since)
        .fetch_all(&self.db)
        .await?;

        let by_day: Vec<(String, i64)> = sqlx::query_as(
            "SELECT TO_CHAR(created_at, 'YYYY-MM-DD'), COUNT(*) FROM iso_audit_logs
             WHERE organization_id=$1 AND created_at >= $2
             GROUP BY 1 ORDER BY 1",
        )
        .bind(organization_id)
        .bind(since)
        .fetch_all(&self.db)
        .await?;

        let top_actors: Vec<(String, i64)> = sqlx::query_as(
            "SELECT actor_id, COUNT(*) FROM iso_audit_logs
             WHERE organization_id=$1 AND created_at >= $2
             GROUP BY actor_id ORDER BY count DESC LIMIT 10",
        )
        .bind(organization_id)
        .bind(since)
        .fetch_all(&self.db)
        .await?;

        Ok(AuditStats {
            total_events: total,
            by_type: by_type.into_iter().collect(),
            by_severity: by_severity.into_iter().collect(),
            by_day: by_day.into_iter().collect(),
            top_actors: top_actors.into_iter().collect(),
        })
    }

    /// Export audit logs as JSON or CSV.
    pub async fn export(&self, query: &AuditQuery, format: &str) -> anyhow::Result<String> {
        let (events, _) = self.query_with_limit_offset(query, 10_000, 0).await?;

        match format {
            "csv" => Ok(export_csv(&events)),
            _ => Ok(serde_json::to_string_pretty(&events)?),
        }
    }

    /// Delete audit logs older than retention period.
    pub async fn cleanup(&self) -> anyhow::Result<i64> {
        let cutoff = Utc::now() - Duration::days(self.config.audit_retention_days);
        let result = sqlx::query("DELETE FROM iso_audit_logs WHERE created_at < $1")
            .bind(cutoff)
            .execute(&self.db)
            .await?;

        let deleted = result.rows_affected() as i64;
        if deleted > 0 {
            info!(deleted = deleted, "Audit log cleanup completed");
        }
        Ok(deleted)
    }

    /// Flush remaining buffer.
    pub async fn flush(&self) -> anyhow::Result<()> {
        let events = {
            let mut buf = self.buffer.write().await;
            buf.drain(..).collect::<Vec<_>>()
        };
        if !events.is_empty() {
            self.flush_events(events).await?;
        }
        Ok(())
    }

    // ── Private ────────────────────────────────────────────

    async fn flush_events(&self, events: Vec<AuditEvent>) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        // F12:serialize per-org flushes. The "read latest hash → compute →
        // insert" sequence below is the chain's critical section; without
        // the lock two concurrent flushes forked the chain.
        let mut org_ids: Vec<String> = events
            .iter()
            .map(|e| e.organization_id.clone())
            .collect::<std::collections::HashSet<_>>()
            .into_iter()
            .collect();
        org_ids.sort(); // sorted acquisition ⇒ no deadlock between batches

        let locks: Vec<std::sync::Arc<tokio::sync::Mutex<()>>> = {
            let mut registry = self.flush_locks.lock().await;
            org_ids
                .iter()
                .map(|org| {
                    registry
                        .entry(org.clone())
                        .or_insert_with(|| std::sync::Arc::new(tokio::sync::Mutex::new(())))
                        .clone()
                })
                .collect()
        };
        let mut guards = Vec::with_capacity(locks.len());
        for lock in &locks {
            guards.push(lock.lock().await);
        }

        let result = self.flush_events_locked(events).await;

        drop(guards);
        result
    }

    /// Critical section of [`Self::flush_events`] — caller holds the
    /// per-org locks.
    async fn flush_events_locked(&self, events: Vec<AuditEvent>) -> anyhow::Result<()> {
        if events.is_empty() {
            return Ok(());
        }

        let mut previous_by_org: std::collections::HashMap<String, String> =
            std::collections::HashMap::new();
        let mut enriched_metadata: Vec<serde_json::Value> = Vec::with_capacity(events.len());

        for event in &events {
            let org_id = event.organization_id.clone();

            let prev = if let Some(cached) = previous_by_org.get(&org_id) {
                cached.clone()
            } else {
                let row: Option<(Option<String>,)> = sqlx::query_as(
                    "SELECT metadata->>'hash' FROM iso_audit_logs WHERE organization_id = $1 ORDER BY created_at DESC LIMIT 1",
                )
                .bind(&org_id)
                .fetch_optional(&self.db)
                .await?;
                let existing = row.and_then(|r| r.0).unwrap_or_default();
                previous_by_org.insert(org_id.clone(), existing.clone());
                existing
            };

            let hash = compute_event_hash(
                &event.id,
                &event.event_type.to_string(),
                &event.details,
                &prev,
            );
            let signature = sign_data(&self.signing_key, &hash)?;

            let mut metadata = event.metadata.clone();
            let obj = metadata
                .as_object_mut()
                .ok_or_else(|| anyhow::anyhow!("Audit metadata must be an object"))?;
            obj.insert("previous_hash".to_string(), serde_json::Value::String(prev));
            obj.insert("hash".to_string(), serde_json::Value::String(hash.clone()));
            obj.insert(
                "signature".to_string(),
                serde_json::Value::String(signature),
            );

            previous_by_org.insert(org_id, hash);
            enriched_metadata.push(metadata);
        }

        let mut query = String::from(
            "INSERT INTO iso_audit_logs (id, organization_id, workspace_id, event_type, severity,
             actor_id, actor_type, actor_ip, actor_user_agent, resource, resource_id, action,
             details, metadata, created_at) VALUES ",
        );

        for (i, _) in events.iter().enumerate() {
            let base = i * 15;
            if i > 0 {
                query.push(',');
            }
            query.push_str(&format!(
                "(${},${},${},${},${},${},${},${},${},${},${},${},${},${},${})",
                base + 1,
                base + 2,
                base + 3,
                base + 4,
                base + 5,
                base + 6,
                base + 7,
                base + 8,
                base + 9,
                base + 10,
                base + 11,
                base + 12,
                base + 13,
                base + 14,
                base + 15,
            ));
        }

        let mut q = sqlx::query(&query);
        for (event, metadata) in events.iter().zip(enriched_metadata.iter()) {
            q = q
                .bind(&event.id)
                .bind(&event.organization_id)
                .bind(&event.workspace_id)
                .bind(event.event_type.to_string())
                .bind(event.severity.to_string())
                .bind(&event.actor_id)
                .bind(&event.actor_type)
                .bind(&event.actor_ip)
                .bind(&event.actor_user_agent)
                .bind(&event.resource)
                .bind(&event.resource_id)
                .bind(&event.action)
                .bind(&event.details)
                .bind(metadata)
                .bind(event.timestamp);
        }

        match q.execute(&self.db).await {
            Ok(_) => {
                info!(count = events.len(), "Audit events flushed");
            }
            Err(e) => {
                tracing::error!(err = %e, count = events.len(), "Failed to flush audit events");
                // Requeue events
                let mut buf = self.buffer.write().await;
                let mut requeue = events;
                requeue.extend(buf.drain(..));
                *buf = requeue;
            }
        }
        Ok(())
    }
}

// ── Supporting Types ───────────────────────────────────────

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HashChainResult {
    pub valid: bool,
    pub broken_at: Option<usize>,
    pub entries_checked: usize,
}

use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditStats {
    pub total_events: i64,
    pub by_type: Vec<(String, i64)>,
    pub by_severity: Vec<(String, i64)>,
    pub by_day: Vec<(String, i64)>,
    pub top_actors: Vec<(String, i64)>,
}

#[derive(sqlx::FromRow)]
struct AuditRow {
    id: String,
    organization_id: String,
    workspace_id: Option<String>,
    event_type: String,
    severity: String,
    actor_id: String,
    actor_type: String,
    actor_ip: Option<String>,
    actor_user_agent: Option<String>,
    resource: Option<String>,
    resource_id: Option<String>,
    action: String,
    details: serde_json::Value,
    metadata: serde_json::Value,
    created_at: chrono::DateTime<Utc>,
}

impl AuditRow {
    fn into_event(self) -> AuditEvent {
        AuditEvent {
            id: self.id,
            organization_id: self.organization_id,
            workspace_id: self.workspace_id,
            event_type: AuditEventType::parse(&self.event_type).unwrap_or(AuditEventType::DataRead),
            severity: AuditSeverity::parse(&self.severity).unwrap_or(AuditSeverity::Info),
            actor_id: self.actor_id,
            actor_type: self.actor_type,
            actor_ip: self.actor_ip,
            actor_user_agent: self.actor_user_agent,
            resource: self.resource,
            resource_id: self.resource_id,
            action: self.action,
            details: self.details,
            metadata: self.metadata,
            timestamp: self.created_at,
        }
    }
}

// ── Helpers ────────────────────────────────────────────────

/// (previous_hash, hash, signature) stored in a row's chain metadata.
/// Missing fields read as "".
fn chain_meta(row: &AuditRow) -> (&str, &str, &str) {
    let get = |key: &str| row.metadata.get(key).and_then(|v| v.as_str()).unwrap_or("");
    (get("previous_hash"), get("hash"), get("signature"))
}

/// Verify an organization's audit hash chain by TRAVERSING the
/// previous_hash links rather than trusting row order (F12).
///
/// - Rows WITHOUT chain metadata (`hash` empty) are legacy rows that
///   predate hashing:they are counted but carry nothing to verify, and
///   created_at order is only used to order the chain's start points
///   (multiple independent starts arise from legacy gaps and from windowed
///   queries whose parent row lies outside the fetched range).
/// - Two chained rows claiming the same previous_hash are a FORK → invalid.
/// - Each chained row's hash and HMAC signature are recomputed and checked.
/// - A chained row unreachable by traversal (dangling previous_hash into a
///   visited region) marks the chain invalid.
///
/// `broken_at` indexes the created_at-ordered input slice, matching the
/// previous implementation's semantics.
fn verify_chain_rows(rows: &[AuditRow], signing_key: &str) -> anyhow::Result<HashChainResult> {
    let invalid = |at: usize| {
        Ok(HashChainResult {
            valid: false,
            broken_at: Some(at),
            entries_checked: rows.len(),
        })
    };

    let chained: Vec<usize> = rows
        .iter()
        .enumerate()
        .filter(|(_, row)| !chain_meta(row).1.is_empty())
        .map(|(i, _)| i)
        .collect();
    if chained.is_empty() {
        return Ok(HashChainResult {
            valid: true,
            broken_at: None,
            entries_checked: rows.len(),
        });
    }

    // Index chained rows by claimed parent. More than one claimant per
    // parent is a fork (two heads grown from one link).
    let mut by_prev: std::collections::HashMap<&str, Vec<usize>> = std::collections::HashMap::new();
    for &i in &chained {
        let (prev, _, _) = chain_meta(&rows[i]);
        by_prev.entry(prev).or_default().push(i);
    }
    for claimants in by_prev.values() {
        if claimants.len() > 1 {
            let first = *claimants.iter().min().expect("non-empty claimants");
            return invalid(first);
        }
    }

    // Chain starts:genesis (empty previous_hash) or a gap start whose
    // parent lies outside this row set (legacy gap / query window).
    let hashes: std::collections::HashSet<&str> =
        chained.iter().map(|&i| chain_meta(&rows[i]).1).collect();
    let mut starts: Vec<usize> = chained
        .iter()
        .copied()
        .filter(|&i| {
            let (prev, _, _) = chain_meta(&rows[i]);
            prev.is_empty() || !hashes.contains(prev)
        })
        .collect();
    starts.sort_unstable(); // created_at order among starts

    let mut visited: std::collections::HashSet<usize> = std::collections::HashSet::new();
    for start in starts {
        let mut current = start;
        loop {
            if !visited.insert(current) {
                return invalid(current); // cycle or reachable from two starts
            }
            let (prev, stored_hash, stored_sig) = chain_meta(&rows[current]);
            let computed = compute_event_hash(
                &rows[current].id,
                &rows[current].event_type,
                &rows[current].details,
                prev,
            );
            if computed != stored_hash {
                return invalid(current);
            }
            if sign_data(signing_key, stored_hash)? != stored_sig {
                return invalid(current);
            }
            match by_prev.get(stored_hash) {
                Some(next) if !next.is_empty() => current = next[0],
                _ => break, // tail of this segment
            }
        }
    }

    // Every chained row must have been visited exactly once.
    if visited.len() != chained.len() {
        let dangling = chained
            .iter()
            .copied()
            .find(|i| !visited.contains(i))
            .expect("visited ⊂ chained when lengths differ");
        return invalid(dangling);
    }

    Ok(HashChainResult {
        valid: true,
        broken_at: None,
        entries_checked: rows.len(),
    })
}

fn compute_event_hash(
    id: &str,
    event_type: &str,
    details: &serde_json::Value,
    previous_hash: &str,
) -> String {
    let mut hasher = Sha256::new();
    hasher.update(id.as_bytes());
    hasher.update(event_type.as_bytes());
    hasher.update(details.to_string().as_bytes());
    hasher.update(previous_hash.as_bytes());
    B64.encode(hasher.finalize())
}

fn sign_data(key: &str, data: &str) -> anyhow::Result<String> {
    let mut mac = Hmac::<Sha256>::new_from_slice(key.as_bytes())
        .map_err(|e| anyhow::anyhow!("Invalid HMAC key: {}", e))?;
    mac.update(data.as_bytes());
    Ok(B64.encode(mac.finalize().into_bytes()))
}

fn export_csv(events: &[AuditEvent]) -> String {
    let mut csv = String::from(
        "id,organization_id,workspace_id,event_type,severity,actor_id,action,resource,timestamp\n",
    );
    for e in events {
        csv.push_str(&format!(
            "{},{},{},{},{},{},{},{},{}\n",
            e.id,
            e.organization_id,
            e.workspace_id.as_deref().unwrap_or(""),
            e.event_type,
            e.severity,
            e.actor_id,
            e.action,
            e.resource.as_deref().unwrap_or(""),
            e.timestamp.to_rfc3339(),
        ));
    }
    csv
}

#[cfg(test)]
mod tests {
    use super::*;
    use zeroize::Zeroizing;

    #[test]
    fn test_compute_event_hash_deterministic() {
        let h1 = compute_event_hash("e1", "AUTH_LOGIN", &serde_json::json!({}), "");
        let h2 = compute_event_hash("e1", "AUTH_LOGIN", &serde_json::json!({}), "");
        assert_eq!(h1, h2);
    }

    #[test]
    fn test_compute_event_hash_different_inputs() {
        let h1 = compute_event_hash("e1", "AUTH_LOGIN", &serde_json::json!({}), "");
        let h2 = compute_event_hash("e2", "AUTH_LOGIN", &serde_json::json!({}), "");
        assert_ne!(h1, h2);
    }

    #[test]
    fn test_compute_event_hash_chain() {
        let h1 = compute_event_hash("e1", "AUTH_LOGIN", &serde_json::json!({}), "");
        let h2 = compute_event_hash("e2", "AUTH_LOGOUT", &serde_json::json!({}), &h1);
        let h2_again = compute_event_hash("e2", "AUTH_LOGOUT", &serde_json::json!({}), &h1);
        assert_eq!(h2, h2_again);

        // Changing previous hash changes result
        let h2_diff = compute_event_hash("e2", "AUTH_LOGOUT", &serde_json::json!({}), "tampered");
        assert_ne!(h2, h2_diff);
    }

    #[test]
    fn test_export_csv() {
        let events = vec![AuditEvent {
            id: "e1".into(),
            organization_id: "org1".into(),
            workspace_id: Some("ws1".into()),
            event_type: AuditEventType::AuthLogin,
            severity: AuditSeverity::Info,
            actor_id: "user1".into(),
            actor_type: "user".into(),
            actor_ip: None,
            actor_user_agent: None,
            resource: Some("session".into()),
            resource_id: None,
            action: "login".into(),
            details: serde_json::json!({}),
            metadata: serde_json::json!({}),
            timestamp: Utc::now(),
        }];
        let csv = export_csv(&events);
        assert!(csv.starts_with("id,organization_id"));
        assert!(csv.contains("e1,org1,ws1,AUTH_LOGIN,info,user1,login,session,"));
    }

    #[test]
    fn test_export_csv_empty_optional_fields() {
        let events = vec![AuditEvent {
            id: "e2".into(),
            organization_id: "org2".into(),
            workspace_id: None,
            event_type: AuditEventType::OrgCreated,
            severity: AuditSeverity::Warning,
            actor_id: "admin".into(),
            actor_type: "system".into(),
            actor_ip: None,
            actor_user_agent: None,
            resource: None,
            resource_id: None,
            action: "create".into(),
            details: serde_json::json!({}),
            metadata: serde_json::json!({}),
            timestamp: Utc::now(),
        }];
        let csv = export_csv(&events);
        assert!(csv.contains("e2,org2,,ORG_CREATED,warning,admin,create,,"));
    }

    #[test]
    fn test_audit_row_into_event() {
        let row = AuditRow {
            id: "a1".into(),
            organization_id: "org1".into(),
            workspace_id: Some("ws1".into()),
            event_type: "AUTH_LOGIN".into(),
            severity: "info".into(),
            actor_id: "user1".into(),
            actor_type: "user".into(),
            actor_ip: Some("1.2.3.4".into()),
            actor_user_agent: Some("test".into()),
            resource: None,
            resource_id: None,
            action: "login".into(),
            details: serde_json::json!({"method": "password"}),
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
        };
        let event = row.into_event();
        assert_eq!(event.event_type, AuditEventType::AuthLogin);
        assert_eq!(event.severity, AuditSeverity::Info);
        assert_eq!(event.actor_ip, Some("1.2.3.4".into()));
    }

    #[test]
    fn test_audit_row_unknown_types() {
        let row = AuditRow {
            id: "a2".into(),
            organization_id: "org1".into(),
            workspace_id: None,
            event_type: "UNKNOWN_EVENT".into(),
            severity: "unknown".into(),
            actor_id: "x".into(),
            actor_type: "x".into(),
            actor_ip: None,
            actor_user_agent: None,
            resource: None,
            resource_id: None,
            action: "x".into(),
            details: serde_json::json!({}),
            metadata: serde_json::json!({}),
            created_at: Utc::now(),
        };
        let event = row.into_event();
        // Defaults applied
        assert_eq!(event.event_type, AuditEventType::DataRead);
        assert_eq!(event.severity, AuditSeverity::Info);
    }

    #[test]
    fn test_create_event() {
        let svc = test_service();
        let event = svc.create_event(
            "org1",
            Some("ws1"),
            AuditEventType::AuthLogin,
            AuditSeverity::Info,
            "user1",
            "user",
            Some("session"),
            None,
            "login",
            serde_json::json!({"method": "password"}),
        );
        assert_eq!(event.organization_id, "org1");
        assert_eq!(event.event_type, AuditEventType::AuthLogin);
        assert!(!event.id.is_empty());
    }

    #[test]
    fn test_buffer_accumulation() {
        let svc = test_service();
        let rt = test_runtime();
        rt.block_on(async {
            let mut buf = svc.buffer.write().await;
            buf.push(svc.create_event(
                "o",
                None,
                AuditEventType::DataRead,
                AuditSeverity::Info,
                "u",
                "user",
                None,
                None,
                "read",
                serde_json::json!({}),
            ));
            buf.push(svc.create_event(
                "o",
                None,
                AuditEventType::DataRead,
                AuditSeverity::Info,
                "u",
                "user",
                None,
                None,
                "read",
                serde_json::json!({}),
            ));
            assert_eq!(buf.len(), 2);
        });
    }

    #[test]
    fn test_audit_hmac_key_is_derived_not_master() {
        let master = "test-key-for-audit-at-least-32-chars!!";
        let derived = derive_audit_hmac_key(master);
        // The HMAC subkey must NOT be the master KEK itself.
        assert_ne!(derived.as_str(), master);
        // Deterministic derivation:the same master yields the same subkey.
        assert_eq!(derived.as_str(), derive_audit_hmac_key(master).as_str());
        // Different master → different subkey.
        assert_ne!(
            derived.as_str(),
            derive_audit_hmac_key("another-key-also-at-least-32-characters").as_str()
        );
        // 32 bytes hex-encoded.
        assert_eq!(derived.len(), 64);
        assert!(derived.chars().all(|c| c.is_ascii_hexdigit()));
    }

    #[test]
    fn test_audit_service_uses_derived_signing_key() {
        let svc = test_service();
        assert_ne!(
            svc.signing_key.as_str(),
            "test-key-for-audit-at-least-32-chars!!",
            "AuditService must not use the master KEK directly as its HMAC key"
        );
    }

    // ── F12:chain verification follows previous_hash links ──────────────

    const CHAIN_TEST_KEY: &str = "unit-test-hmac-key";

    fn chain_row(id: &str, created_at: chrono::DateTime<Utc>, prev: &str) -> AuditRow {
        let details = serde_json::json!({ "seq": id });
        let hash = compute_event_hash(id, "AUTH_LOGIN", &details, prev);
        let signature = sign_data(CHAIN_TEST_KEY, &hash).unwrap();
        AuditRow {
            id: id.into(),
            organization_id: "org1".into(),
            workspace_id: None,
            event_type: "AUTH_LOGIN".into(),
            severity: "info".into(),
            actor_id: "user1".into(),
            actor_type: "user".into(),
            actor_ip: None,
            actor_user_agent: None,
            resource: None,
            resource_id: None,
            action: "login".into(),
            details,
            metadata: serde_json::json!({
                "previous_hash": prev,
                "hash": hash,
                "signature": signature,
            }),
            created_at,
        }
    }

    fn legacy_row(id: &str, created_at: chrono::DateTime<Utc>) -> AuditRow {
        AuditRow {
            id: id.into(),
            organization_id: "org1".into(),
            workspace_id: None,
            event_type: "AUTH_LOGIN".into(),
            severity: "info".into(),
            actor_id: "user1".into(),
            actor_type: "user".into(),
            actor_ip: None,
            actor_user_agent: None,
            resource: None,
            resource_id: None,
            action: "login".into(),
            details: serde_json::json!({}),
            metadata: serde_json::json!({}), // no chain metadata
            created_at,
        }
    }

    #[test]
    fn test_verify_chain_rows_walks_links_not_row_order() {
        let t0 = Utc::now();
        let r1 = chain_row("e1", t0, "");
        let h1 = chain_meta(&r1).1.to_string();
        let r2 = chain_row("e2", t0 + Duration::seconds(1), &h1);
        let h2 = chain_meta(&r2).1.to_string();
        let r3 = chain_row("e3", t0 + Duration::seconds(2), &h2);

        // Rows delivered in NON-chain order plus a legacy row interleaved:
        // traversal must follow previous_hash links (not slice order) and
        // tolerate the legacy row.
        let rows = vec![r3, legacy_row("old", t0 - Duration::seconds(5)), r1, r2];
        let result = verify_chain_rows(&rows, CHAIN_TEST_KEY).unwrap();
        assert!(result.valid, "chain is intact regardless of row order");
        assert_eq!(result.entries_checked, 4);
        assert_eq!(result.broken_at, None);
    }

    #[test]
    fn test_verify_chain_rows_detects_tampering() {
        let t0 = Utc::now();
        let r1 = chain_row("e1", t0, "");
        let h1 = chain_meta(&r1).1.to_string();
        let mut r2 = chain_row("e2", t0 + Duration::seconds(1), &h1);
        // Tamper with the row contents WITHOUT updating the stored hash.
        r2.details = serde_json::json!({ "seq": "tampered" });

        let result = verify_chain_rows(&[r1, r2], CHAIN_TEST_KEY).unwrap();
        assert!(!result.valid, "tampered row must invalidate the chain");
        assert_eq!(result.broken_at, Some(1));
    }

    #[test]
    fn test_verify_chain_rows_detects_fork() {
        // Two rows claiming the same parent — what concurrent unserialized
        // flushes used to produce.
        let t0 = Utc::now();
        let r1 = chain_row("e1", t0, "");
        let h1 = chain_meta(&r1).1.to_string();
        let r2 = chain_row("e2", t0 + Duration::seconds(1), &h1);
        let r2b = chain_row("e2-prime", t0 + Duration::seconds(2), &h1);

        let result = verify_chain_rows(&[r1, r2, r2b], CHAIN_TEST_KEY).unwrap();
        assert!(!result.valid, "two claimants of one parent are a fork");
    }

    #[test]
    fn test_verify_chain_rows_detects_wrong_signature() {
        let t0 = Utc::now();
        let r1 = chain_row("e1", t0, "");
        // Same chain, signed with a DIFFERENT key:hashes link up but the
        // HMAC does not verify.
        let h1 = chain_meta(&r1).1.to_string();
        let r2 = chain_row("e2", t0 + Duration::seconds(1), &h1);

        let result = verify_chain_rows(&[r1, r2], "a-different-signing-key").unwrap();
        assert!(
            !result.valid,
            "rows signed with a foreign key must not verify"
        );
    }

    #[test]
    fn test_verify_chain_rows_legacy_only_is_valid() {
        let t0 = Utc::now();
        let rows = vec![
            legacy_row("a", t0),
            legacy_row("b", t0 + Duration::seconds(1)),
        ];
        let result = verify_chain_rows(&rows, CHAIN_TEST_KEY).unwrap();
        assert!(result.valid);
        assert_eq!(result.entries_checked, 2);
    }

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

    fn test_pool() -> PgPool {
        let _guard = test_runtime().enter();
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap()
    }

    fn test_service() -> AuditService {
        AuditService::new(
            test_pool(),
            SecurityConfig {
                encryption_key: Zeroizing::new(
                    "test-key-for-audit-at-least-32-chars!!".to_string(),
                ),
                data_key_rotation_days: 90,
                audit_retention_days: 365,
                session_timeout_minutes: 30,
            },
        )
    }
}
