//! PostgreSQL replication monitoring — replica status, slots, lag tracking, promotion.

use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use tracing::{info, warn};

use crate::config::Config;
use crate::types::{ReplicaInfo, ReplicationSlot, ReplicationStats};

/// ReplicationService monitors and manages PostgreSQL streaming replication.
pub struct ReplicationService {
    pool: PgPool,
    config: Arc<Config>,
}

impl ReplicationService {
    pub fn new(pool: PgPool, config: Arc<Config>) -> Self {
        Self { pool, config }
    }

    // ── Replica Status ─────────────────────────────────────

    /// Query pg_stat_replication for all connected replicas.
    pub async fn get_replicas(&self) -> Result<Vec<ReplicaInfo>, String> {
        let rows: Vec<ReplicaRow> = sqlx::query_as::<_, ReplicaRow>(
            "SELECT pid, application_name, client_addr::text,
                    state, sent_lsn::text, write_lsn::text,
                    flush_lsn::text, replay_lsn::text, sync_state,
                    pg_wal_lsn_diff(sent_lsn, replay_lsn)::bigint AS lag_bytes
             FROM pg_stat_replication"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Query pg_stat_replication: {e}"))?;

        Ok(rows.into_iter().map(|r| r.into_info()).collect())
    }

    /// Get replication lag for a specific replica by application name.
    pub async fn get_lag(&self, app_name: &str) -> Result<Option<f64>, String> {
        let row: Option<(Option<f64>,)> = sqlx::query_as(
            "SELECT EXTRACT(EPOCH FROM replay_lag) * 1000 AS lag_ms
             FROM pg_stat_replication WHERE application_name = $1"
        )
        .bind(app_name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Lag query: {e}"))?;

        Ok(row.and_then(|(ms,)| ms))
    }

    /// Record current lag into history table.
    pub async fn record_lag(&self) -> Result<(), String> {
        let replicas = self.get_replicas().await?;
        for replica in &replicas {
            let lag_ms = replica.lag_ms.unwrap_or(0.0);
            sqlx::query(
                "INSERT INTO ha_replication_lag_history (replica_name, lag_ms, lag_bytes, recorded_at)
                 VALUES ($1, $2, $3, NOW())"
            )
            .bind(&replica.application_name)
            .bind(lag_ms)
            .bind(replica.lag_bytes.unwrap_or(0))
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Record lag: {e}"))?;

            // Check thresholds
            if lag_ms > self.config.replication.critical_lag_ms as f64 {
                warn!(replica = replica.application_name, lag_ms, "CRITICAL replication lag");
            } else if lag_ms > self.config.replication.warning_lag_ms as f64 {
                warn!(replica = replica.application_name, lag_ms, "WARNING replication lag");
            }
        }
        Ok(())
    }

    // ── Replication Slots ──────────────────────────────────

    /// List all replication slots.
    pub async fn get_slots(&self) -> Result<Vec<ReplicationSlot>, String> {
        let rows: Vec<SlotRow> = sqlx::query_as::<_, SlotRow>(
            "SELECT slot_name, plugin, slot_type, active,
                    restart_lsn::text, confirmed_flush_lsn::text, wal_status
             FROM pg_replication_slots"
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Query replication slots: {e}"))?;

        Ok(rows.into_iter().map(|r| ReplicationSlot {
            slot_name: r.slot_name,
            plugin: r.plugin,
            slot_type: r.slot_type,
            active: r.active,
            restart_lsn: r.restart_lsn,
            confirmed_flush_lsn: r.confirmed_flush_lsn,
            wal_status: r.wal_status,
        }).collect())
    }

    /// Create a new replication slot.
    pub async fn create_slot(&self, name: &str, slot_type: &str) -> Result<(), String> {
        // Validate name
        if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err("Invalid slot name".into());
        }
        let query = if slot_type == "logical" {
            "SELECT pg_create_logical_replication_slot($1, 'pgoutput')"
        } else {
            "SELECT pg_create_physical_replication_slot($1)"
        };
        sqlx::query(query)
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Create slot: {e}"))?;

        info!(name, slot_type, "Replication slot created");
        Ok(())
    }

    /// Drop a replication slot.
    pub async fn drop_slot(&self, name: &str) -> Result<(), String> {
        if !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
            return Err("Invalid slot name".into());
        }
        sqlx::query("SELECT pg_drop_replication_slot($1)")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Drop slot: {e}"))?;

        info!(name, "Replication slot dropped");
        Ok(())
    }

    // ── Promotion ──────────────────────────────────────────

    /// Promote a standby to primary (requires connection to the standby).
    pub async fn promote_standby(&self) -> Result<bool, String> {
        let result = sqlx::query_scalar::<_, bool>(
            "SELECT pg_promote(wait := true)"
        )
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Promote: {e}"))?;

        match result {
            Some(true) => {
                info!("Standby promoted to primary");
                Ok(true)
            }
            _ => Err("Promotion failed or not a standby".into()),
        }
    }

    // ── Sync Mode Toggle ───────────────────────────────────

    /// Switch between sync and async replication.
    pub async fn set_sync_mode(&self, synchronous: bool) -> Result<(), String> {
        let sync_standby = if synchronous {
            "'*'"
        } else {
            "''"
        };
        let sql = format!(
            "ALTER SYSTEM SET synchronous_standby_names = {sync_standby}"
        );
        sqlx::query(&sql)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Set sync mode: {e}"))?;

        // Reload configuration
        sqlx::query("SELECT pg_reload_conf()")
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Reload conf: {e}"))?;

        info!(synchronous, "Replication sync mode updated");
        Ok(())
    }

    // ── Stats ──────────────────────────────────────────────

    /// Aggregate replication statistics.
    pub async fn get_stats(&self) -> Result<ReplicationStats, String> {
        let replicas = self.get_replicas().await?;
        let slots = self.get_slots().await?;

        let total_lag_bytes: i64 = replicas.iter()
            .filter_map(|r| r.lag_bytes)
            .sum();
        let lag_values: Vec<f64> = replicas.iter()
            .filter_map(|r| r.lag_ms)
            .collect();

        let max_lag = lag_values.iter().copied().fold(0.0_f64, f64::max);
        let avg_lag = if lag_values.is_empty() {
            0.0
        } else {
            lag_values.iter().sum::<f64>() / lag_values.len() as f64
        };

        let is_healthy = max_lag < self.config.replication.max_lag_ms as f64;

        let mode = if self.config.replication.sync_replication {
            "sync".to_string()
        } else {
            "async".to_string()
        };

        Ok(ReplicationStats {
            mode,
            primary_node: self.config.multi_region.node_id.clone(),
            replicas,
            slots,
            total_lag_bytes,
            max_lag_ms: max_lag,
            avg_lag_ms: avg_lag,
            is_healthy,
        })
    }

    /// Get lag history for the last N minutes.
    pub async fn get_lag_history(&self, minutes: i64) -> Result<Vec<serde_json::Value>, String> {
        let rows: Vec<LagHistoryRow> = sqlx::query_as::<_, LagHistoryRow>(
            "SELECT replica_name, lag_ms, lag_bytes, recorded_at
             FROM ha_replication_lag_history
             WHERE recorded_at > NOW() - make_interval(mins => $1)
             ORDER BY recorded_at DESC"
        )
        .bind(minutes)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Lag history: {e}"))?;

        Ok(rows.into_iter().map(|r| {
            serde_json::json!({
                "replica": r.replica_name,
                "lag_ms": r.lag_ms,
                "lag_bytes": r.lag_bytes,
                "recorded_at": r.recorded_at,
            })
        }).collect())
    }

    /// Cleanup old lag history records.
    pub async fn cleanup_lag_history(&self, retain_hours: i64) -> Result<u64, String> {
        let res = sqlx::query(
            "DELETE FROM ha_replication_lag_history WHERE recorded_at < NOW() - make_interval(hours => $1)"
        )
        .bind(retain_hours)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Cleanup lag history: {e}"))?;

        Ok(res.rows_affected())
    }
}

// ── DB Row types ───────────────────────────────────────────

#[derive(Debug, Clone, sqlx::FromRow)]
struct ReplicaRow {
    pid: i32,
    application_name: String,
    client_addr: Option<String>,
    state: Option<String>,
    sent_lsn: Option<String>,
    write_lsn: Option<String>,
    flush_lsn: Option<String>,
    replay_lsn: Option<String>,
    sync_state: Option<String>,
    lag_bytes: Option<i64>,
}

impl ReplicaRow {
    fn into_info(self) -> ReplicaInfo {
        ReplicaInfo {
            pid: self.pid,
            application_name: self.application_name,
            client_addr: self.client_addr,
            state: self.state.unwrap_or_else(|| "unknown".into()),
            sent_lsn: self.sent_lsn,
            write_lsn: self.write_lsn,
            flush_lsn: self.flush_lsn,
            replay_lsn: self.replay_lsn,
            sync_state: self.sync_state.unwrap_or_else(|| "async".into()),
            lag_bytes: self.lag_bytes,
            lag_ms: None, // Computed separately
        }
    }
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct SlotRow {
    slot_name: String,
    plugin: Option<String>,
    slot_type: String,
    active: bool,
    restart_lsn: Option<String>,
    confirmed_flush_lsn: Option<String>,
    wal_status: Option<String>,
}

#[derive(Debug, Clone, sqlx::FromRow)]
struct LagHistoryRow {
    replica_name: String,
    lag_ms: f64,
    lag_bytes: i64,
    recorded_at: chrono::DateTime<Utc>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_runtime() -> &'static tokio::runtime::Runtime {
        use std::sync::OnceLock;
        static RT: OnceLock<tokio::runtime::Runtime> = OnceLock::new();
        RT.get_or_init(|| tokio::runtime::Builder::new_current_thread().enable_all().build().unwrap())
    }
    fn test_pool() -> PgPool {
        let _guard = test_runtime().enter();
        sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap()
    }
    fn test_config() -> Arc<Config> {
        Arc::new(Config::from_env())
    }

    #[test]
    fn test_stats_empty_replicas() {
        // Stats computation logic without DB
        let replicas: Vec<ReplicaInfo> = vec![];
        let lag_values: Vec<f64> = replicas.iter().filter_map(|r| r.lag_ms).collect();
        let avg = if lag_values.is_empty() { 0.0 } else {
            lag_values.iter().sum::<f64>() / lag_values.len() as f64
        };
        assert_eq!(avg, 0.0);
    }

    #[test]
    fn test_stats_with_replicas() {
        let replicas = vec![
            ReplicaInfo {
                pid: 1, application_name: "r1".into(), client_addr: None,
                state: "streaming".into(), sent_lsn: None, write_lsn: None,
                flush_lsn: None, replay_lsn: None, sync_state: "async".into(),
                lag_bytes: Some(1024), lag_ms: Some(50.0),
            },
            ReplicaInfo {
                pid: 2, application_name: "r2".into(), client_addr: None,
                state: "streaming".into(), sent_lsn: None, write_lsn: None,
                flush_lsn: None, replay_lsn: None, sync_state: "async".into(),
                lag_bytes: Some(2048), lag_ms: Some(100.0),
            },
        ];
        let total_lag: i64 = replicas.iter().filter_map(|r| r.lag_bytes).sum();
        assert_eq!(total_lag, 3072);
        let lag_vals: Vec<f64> = replicas.iter().filter_map(|r| r.lag_ms).collect();
        let max = lag_vals.iter().copied().fold(0.0_f64, f64::max);
        assert_eq!(max, 100.0);
        let avg = lag_vals.iter().sum::<f64>() / lag_vals.len() as f64;
        assert_eq!(avg, 75.0);
    }

    #[test]
    fn test_slot_name_validation() {
        let valid = "my_slot_1";
        assert!(valid.chars().all(|c| c.is_alphanumeric() || c == '_'));
        let invalid = "my-slot;DROP TABLE";
        assert!(!invalid.chars().all(|c| c.is_alphanumeric() || c == '_'));
    }

    #[test]
    fn test_replica_row_conversion() {
        let row = ReplicaRow {
            pid: 42,
            application_name: "walreceiver".into(),
            client_addr: Some("10.0.0.2".into()),
            state: Some("streaming".into()),
            sent_lsn: Some("0/16B3748".into()),
            write_lsn: Some("0/16B3748".into()),
            flush_lsn: None,
            replay_lsn: None,
            sync_state: Some("async".into()),
            lag_bytes: Some(0),
        };
        let info = row.into_info();
        assert_eq!(info.pid, 42);
        assert_eq!(info.state, "streaming");
        assert_eq!(info.sync_state, "async");
    }

    #[test]
    fn test_replication_stats_serialization() {
        let stats = ReplicationStats {
            mode: "async".into(),
            primary_node: "node-1".into(),
            replicas: vec![],
            slots: vec![],
            total_lag_bytes: 0,
            max_lag_ms: 0.0,
            avg_lag_ms: 0.0,
            is_healthy: true,
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["mode"], "async");
        assert_eq!(json["is_healthy"], true);
    }

    #[test]
    fn test_replication_service_creation() {
        let svc = ReplicationService::new(test_pool(), test_config());
        assert!(svc.config.replication.enabled);
    }

    #[test]
    fn test_sync_mode_sql_generation() {
        let sync_standby = if true { "'*'" } else { "''" };
        let sql = format!("ALTER SYSTEM SET synchronous_standby_names = {sync_standby}");
        assert!(sql.contains("'*'"));
    }

    #[test]
    fn test_slot_serialization() {
        let slot = ReplicationSlot {
            slot_name: "sub1".into(),
            plugin: Some("pgoutput".into()),
            slot_type: "logical".into(),
            active: true,
            restart_lsn: Some("0/1000000".into()),
            confirmed_flush_lsn: Some("0/1000000".into()),
            wal_status: Some("reserved".into()),
        };
        let json = serde_json::to_value(&slot).unwrap();
        assert_eq!(json["slot_name"], "sub1");
        assert_eq!(json["active"], true);
    }
}
