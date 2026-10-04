//! PostgreSQL replication monitoring — replica status, slots, lag tracking, promotion.

use axum::http::StatusCode;
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
    /// Test seam (external audit #2): overrides the `pg_stat_replication`
    /// streaming-standby probe so the synchronous-transition guard is
    /// deterministically exercisable without a live standby.
    #[cfg(test)]
    streaming_overrides: tokio::sync::RwLock<Option<Vec<String>>>,
}

impl ReplicationService {
    pub fn new(pool: PgPool, config: Arc<Config>) -> Self {
        Self {
            pool,
            config,
            #[cfg(test)]
            streaming_overrides: tokio::sync::RwLock::new(None),
        }
    }

    // ── Replica Status ─────────────────────────────────────

    /// Query pg_stat_replication for all connected replicas.
    ///
    /// `lag_ms` is computed from `replay_lag` in the SAME query — the
    /// service is connected to the primary, whose `pg_stat_replication`
    /// view carries each replica's replay lag directly. Previously
    /// `lag_ms` was hard-coded `None`, so monitoring recorded 0.0 for
    /// every replica and health was always reported as true.
    pub async fn get_replicas(&self) -> Result<Vec<ReplicaInfo>, String> {
        let rows: Vec<ReplicaRow> = sqlx::query_as::<_, ReplicaRow>(
            "SELECT pid, application_name, client_addr::text,
                    state, sent_lsn::text, write_lsn::text,
                    flush_lsn::text, replay_lsn::text, sync_state,
                    pg_wal_lsn_diff(sent_lsn, replay_lsn)::bigint AS lag_bytes,
                    (EXTRACT(EPOCH FROM replay_lag) * 1000)::float8 AS lag_ms
             FROM pg_stat_replication",
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
             FROM pg_stat_replication WHERE application_name = $1",
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
                warn!(
                    replica = replica.application_name,
                    lag_ms, "CRITICAL replication lag"
                );
            } else if lag_ms > self.config.replication.warning_lag_ms as f64 {
                warn!(
                    replica = replica.application_name,
                    lag_ms, "WARNING replication lag"
                );
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
             FROM pg_replication_slots",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Query replication slots: {e}"))?;

        Ok(rows
            .into_iter()
            .map(|r| ReplicationSlot {
                slot_name: r.slot_name,
                plugin: r.plugin,
                slot_type: r.slot_type,
                active: r.active,
                restart_lsn: r.restart_lsn,
                confirmed_flush_lsn: r.confirmed_flush_lsn,
                wal_status: r.wal_status,
            })
            .collect())
    }

    /// Create a new replication slot.
    pub async fn create_slot(&self, name: &str, slot_type: &str) -> Result<(), String> {
        // Validate name. An EMPTY name must be rejected explicitly:
        // `chars().all(..)` on an empty iterator is vacuously true, so the
        // old check let "" through to the replication-slot SQL.
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
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
        if name.is_empty() || !name.chars().all(|c| c.is_alphanumeric() || c == '_') {
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
        let result = sqlx::query_scalar::<_, bool>("SELECT pg_promote(wait := true)")
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

    // ── Sync Mode Toggle (external audits #2 and #10) ──────────

    /// The standby topology this deployment intends to run (audit #2 a):
    /// the `DB_REPLICA_HOSTS` list plus the legacy singular
    /// `DB_REPLICA_HOST` / `DB_STANDBY_HOST` entries — de-duplicated,
    /// order-stable.
    pub fn configured_standbys(&self) -> Vec<String> {
        let mut hosts: Vec<String> = Vec::new();
        let push = |host: &Option<String>, hosts: &mut Vec<String>| {
            if let Some(h) = host {
                if !h.trim().is_empty() && !hosts.iter().any(|existing| existing == h) {
                    hosts.push(h.clone());
                }
            }
        };
        for host in &self.config.database.replica_hosts {
            if !host.trim().is_empty() && !hosts.iter().any(|existing| existing == host) {
                hosts.push(host.clone());
            }
        }
        push(&self.config.database.replica_host, &mut hosts);
        push(&self.config.database.standby_host, &mut hosts);
        hosts
    }

    /// The `application_name`s currently connected in a VALID replication
    /// state (`streaming`) — audit #2 b.
    pub async fn streaming_standbys(&self) -> Result<Vec<String>, String> {
        #[cfg(test)]
        if let Some(overridden) = self.streaming_overrides.read().await.as_ref() {
            return Ok(overridden.clone());
        }
        let rows: Vec<(String,)> = sqlx::query_as(
            "SELECT application_name FROM pg_stat_replication WHERE state = 'streaming'",
        )
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Query streaming standbys: {e}"))?;
        Ok(rows.into_iter().map(|(name,)| name).collect())
    }

    /// The LIVE `synchronous_standby_names` value — the PostgreSQL runtime
    /// truth the status endpoint exposes (external audit #7).
    pub async fn show_synchronous_standby_names(&self) -> Result<String, String> {
        let (value,): (String,) = sqlx::query_as("SHOW synchronous_standby_names")
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("SHOW synchronous_standby_names: {e}"))?;
        Ok(value)
    }

    /// Apply a `synchronous_standby_names` value and reload the config.
    ///
    /// The value is spliced into the statement text (utility statements
    /// cannot take bind parameters), so it is restricted beforehand: this
    /// service only ever writes the EMPTY value, a NAMED list built from
    /// [`valid_standby_name`]s, or a rollback value that passed
    /// [`is_restorable_setting_value`] — and NEVER the `'*'` wildcard.
    async fn apply_synchronous_standby_names(&self, value: &str) -> Result<(), String> {
        if value.trim() == "*" {
            return Err("refusing to write the '*' wildcard to synchronous_standby_names".into());
        }
        let sql = format!(
            "ALTER SYSTEM SET synchronous_standby_names = '{}'",
            value.replace('\'', "")
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
        Ok(())
    }

    /// Switch between synchronous and asynchronous replication (external
    /// audits #2 and #10).
    ///
    /// Audit #2 — the synchronous direction is guarded BEFORE anything is
    /// mutated: the request must NAME the exact standby(s) (the `'*'`
    /// wildcard form is refused), each name must belong to the configured
    /// topology, and each named standby must be currently connected in a
    /// streaming state. Refusals are deterministic
    /// ([`SetSyncModeError::Refused`] → 409/422).
    ///
    /// Audit #10 — the mode is explicit durable configuration: the desired
    /// state is persisted in Redis (namespaced per cluster) BEFORE the
    /// PostgreSQL mutation, the previous live value is recorded for the
    /// rollback, the applied value is always a NAMED list (never `'*'`),
    /// and `reconcile_sync_mode` repairs drift after a crash between the
    /// persist and the apply. Disabling restores the recorded previous
    /// value (idempotent rollback); an explicit apply ERROR removes the
    /// persisted intent (a CRASH deliberately keeps it).
    pub async fn set_sync_mode(
        &self,
        synchronous: bool,
        standbys: Vec<String>,
    ) -> Result<(), SetSyncModeError> {
        // 1. Validate the candidates FIRST (audit #2) — nothing mutated yet.
        if synchronous {
            let configured = self.configured_standbys();
            let streaming = self
                .streaming_standbys()
                .await
                .map_err(SetSyncModeError::Failed)?;
            validate_sync_standbys(&standbys, &configured, &streaming)
                .map_err(SetSyncModeError::Refused)?;
        }

        // 2. Observe the previous live value — the rollback source (#10).
        let previous = self
            .show_synchronous_standby_names()
            .await
            .map_err(SetSyncModeError::Failed)?;

        // 3. Compute the exact target value. The disable direction is the
        //    idempotent rollback: restore the recorded previous value.
        let existing = if synchronous {
            None
        } else {
            Some(
                self.read_desired_state()
                    .await
                    .map_err(SetSyncModeError::Failed)?,
            )
        };
        let target = if synchronous {
            named_sync_standby_list(&standbys)
        } else {
            match &existing {
                Some(Some(state))
                    if !state.previous_setting.trim().is_empty()
                        && is_restorable_setting_value(&state.previous_setting) =>
                {
                    state.previous_setting.clone()
                }
                Some(_)
                    if !previous.trim().is_empty() && is_restorable_setting_value(&previous) =>
                {
                    previous.clone()
                }
                _ => String::new(),
            }
        };

        // 4. Persist the durable intent BEFORE mutating PostgreSQL (#10).
        let desired = SyncModeDesiredState {
            desired_setting: target.clone(),
            synchronous,
            standbys: if synchronous {
                standbys.clone()
            } else {
                Vec::new()
            },
            previous_setting: if synchronous {
                previous.clone()
            } else {
                existing
                    .as_ref()
                    .and_then(|state| state.as_ref())
                    .map(|state| state.previous_setting.clone())
                    .unwrap_or_else(|| previous.clone())
            },
            updated_at: Utc::now(),
        };
        self.write_desired_state(&desired)
            .await
            .map_err(SetSyncModeError::Failed)?;

        // 5. Apply the named list and reload.
        if let Err(apply_error) = self.apply_synchronous_standby_names(&target).await {
            // An explicit failure must not leave durable intent behind —
            // the reconcile loop would otherwise retry a transition the
            // operator saw fail. (A crash between steps 4 and 5 keeps the
            // intent; that is exactly what reconcile repairs.)
            if let Err(cleanup_error) = self.clear_desired_state().await {
                warn!(
                    error = %cleanup_error,
                    "failed to clear the desired sync-mode state after an apply error"
                );
            }
            return Err(SetSyncModeError::Failed(apply_error));
        }

        // 6. Bounded verification that the reload took effect
        //    (pg_reload_conf returns before the postmaster re-reads the
        //    config). Warn-only: the reconcile loop repairs any residual
        //    drift.
        for _ in 0..10 {
            match self.show_synchronous_standby_names().await {
                Ok(live) if live == target => break,
                Ok(_) | Err(_) => {
                    tokio::time::sleep(std::time::Duration::from_millis(100)).await;
                }
            }
        }
        match self.show_synchronous_standby_names().await {
            Ok(live) if live != target => {
                warn!(
                    live = %live,
                    desired = %target,
                    "synchronous_standby_names not yet reloaded — the reconcile loop keeps watching"
                );
            }
            Ok(_) => {}
            Err(e) => warn!(error = %e, "could not verify the reloaded synchronous_standby_names"),
        }

        info!(
            synchronous,
            standbys = ?desired.standbys,
            previous = %previous,
            applied = %target,
            "Replication sync mode updated"
        );
        Ok(())
    }

    // ── Durable desired state (external audit #10) ─────────────────────

    async fn redis_conn(&self) -> Result<redis::aio::MultiplexedConnection, String> {
        let client = redis::Client::open(self.config.redis.url().as_str())
            .map_err(|e| format!("Redis client: {e}"))?;
        client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| format!("Redis connect: {e}"))
    }

    /// Read the durable desired sync-mode state (audit #10). `Ok(None)` —
    /// no explicit mode change has been recorded.
    pub async fn read_desired_state(&self) -> Result<Option<SyncModeDesiredState>, String> {
        let mut conn = self.redis_conn().await?;
        let raw: Option<String> = redis::cmd("GET")
            .arg(sync_mode_state_key(&self.config.multi_region.cluster_id))
            .query_async(&mut conn)
            .await
            .map_err(|e| format!("GET desired sync-mode state: {e}"))?;
        raw.map(|raw| {
            serde_json::from_str(&raw).map_err(|e| format!("Parse desired sync-mode state: {e}"))
        })
        .transpose()
    }

    /// Persist the durable desired sync-mode state (audit #10) — written
    /// BEFORE the PostgreSQL mutation so a crash leaves the operator's
    /// intent behind. Deliberately NO TTL: this is configuration, not an
    /// ephemeral claim.
    pub async fn write_desired_state(&self, desired: &SyncModeDesiredState) -> Result<(), String> {
        let mut conn = self.redis_conn().await?;
        let payload = serde_json::to_string(desired)
            .map_err(|e| format!("Serialize desired sync-mode state: {e}"))?;
        redis::cmd("SET")
            .arg(sync_mode_state_key(&self.config.multi_region.cluster_id))
            .arg(payload)
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| format!("SET desired sync-mode state: {e}"))?;
        Ok(())
    }

    /// Remove the durable desired state (explicit-failure cleanup).
    pub async fn clear_desired_state(&self) -> Result<(), String> {
        let mut conn = self.redis_conn().await?;
        redis::cmd("DEL")
            .arg(sync_mode_state_key(&self.config.multi_region.cluster_id))
            .query_async::<()>(&mut conn)
            .await
            .map_err(|e| format!("DEL desired sync-mode state: {e}"))?;
        Ok(())
    }

    /// External audit #10 — reconcile the durable desired mode against the
    /// LIVE PostgreSQL setting. Returns `Ok(true)` when drift was detected
    /// and repaired. A missing desired state means nothing to reconcile.
    pub async fn reconcile_sync_mode(&self) -> Result<bool, String> {
        let Some(desired) = self.read_desired_state().await? else {
            return Ok(false);
        };
        let live = self.show_synchronous_standby_names().await?;
        if live == desired.desired_setting {
            return Ok(false);
        }
        warn!(
            live = %live,
            desired = %desired.desired_setting,
            desired_updated_at = %desired.updated_at,
            "replication sync-mode drift detected — repairing from the durable desired state"
        );
        self.apply_synchronous_standby_names(&desired.desired_setting)
            .await?;
        Ok(true)
    }

    /// Bounded reconcile loop (audit #10) — the same cron pattern the other
    /// background jobs in `ha-server` use. Wired by the server binary.
    pub async fn run_sync_mode_reconcile_loop(&self, interval: std::time::Duration) {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            if let Err(e) = self.reconcile_sync_mode().await {
                warn!(error = %e, "sync-mode reconciliation failed");
            }
        }
    }

    // ── Stats ──────────────────────────────────────────────

    /// Aggregate replication statistics.
    ///
    /// External audit #7: `mode` is PostgreSQL RUNTIME truth
    /// (`SHOW synchronous_standby_names`; `current_setting` is the same
    /// read, fetched in one round-trip together with
    /// `synchronous_commit`) — not the immutable startup config. The
    /// configured mode is returned next to it for drift visibility, as is
    /// the durable desired mode from Redis (audit #10).
    ///
    /// External audit #8: health is topology-aware — the empty-replica fold
    /// no longer reports a replica-expected deployment healthy.
    pub async fn get_stats(&self) -> Result<ReplicationStats, String> {
        let replicas = self.get_replicas().await?;
        let slots = self.get_slots().await?;

        let (effective_sync_standby_names, effective_synchronous_commit): (String, String) =
            sqlx::query_as(
                "SELECT current_setting('synchronous_standby_names'), \
                        current_setting('synchronous_commit')",
            )
            .fetch_one(&self.pool)
            .await
            .map_err(|e| format!("Read live replication settings: {e}"))?;

        // Audit #10: desired↔actual drift visibility. An unreadable Redis
        // degrades to "no desired state recorded" — the status endpoint
        // stays available.
        let (desired_sync_mode, desired_drift) = match self.read_desired_state().await {
            Ok(desired) => {
                let drift = desired
                    .as_ref()
                    .is_some_and(|state| state.desired_setting != effective_sync_standby_names);
                (desired.map(|state| state.to_string()), drift)
            }
            Err(e) => {
                warn!(
                    error = %e,
                    "unable to read the desired sync-mode state — drift unknown"
                );
                (None, false)
            }
        };

        let total_lag_bytes: i64 = replicas.iter().filter_map(|r| r.lag_bytes).sum();
        let lag_values: Vec<f64> = replicas.iter().filter_map(|r| r.lag_ms).collect();

        let max_lag = lag_values.iter().copied().fold(0.0_f64, f64::max);
        let avg_lag = if lag_values.is_empty() {
            0.0
        } else {
            lag_values.iter().sum::<f64>() / lag_values.len() as f64
        };

        // Audit #8: topology-aware health. Standalone (nothing expected,
        // nothing observed) is healthy; a replica-expected deployment with
        // nothing connected is UNHEALTHY; a partial topology is DEGRADED.
        let expected_replicas = self.configured_standbys().len();
        let topology = classify_topology(expected_replicas, replicas.len());
        let lag_ok = max_lag < self.config.replication.max_lag_ms as f64;
        let is_healthy = topology.is_operational() && lag_ok;

        let mode = effective_mode(&effective_sync_standby_names).to_string();
        let configured_mode = if self.config.replication.sync_replication {
            "sync".to_string()
        } else {
            "async".to_string()
        };

        Ok(ReplicationStats {
            config_drift: configured_mode != mode,
            mode,
            configured_mode,
            effective_sync_standby_names,
            effective_synchronous_commit,
            desired_sync_mode,
            desired_drift,
            expected_replicas,
            topology_status: topology.as_str().to_string(),
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
             WHERE recorded_at > NOW() - make_interval(mins => $1::int)
             ORDER BY recorded_at DESC",
        )
        .bind(minutes)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("Lag history: {e}"))?;

        Ok(rows
            .into_iter()
            .map(|r| {
                serde_json::json!({
                    "replica": r.replica_name,
                    "lag_ms": r.lag_ms,
                    "lag_bytes": r.lag_bytes,
                    "recorded_at": r.recorded_at,
                })
            })
            .collect())
    }

    /// Cleanup old lag history records.
    pub async fn cleanup_lag_history(&self, retain_hours: i64) -> Result<u64, String> {
        let res = sqlx::query(
            "DELETE FROM ha_replication_lag_history WHERE recorded_at < NOW() - make_interval(hours => $1::int)"
        )
        .bind(retain_hours)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Cleanup lag history: {e}"))?;

        Ok(res.rows_affected())
    }
}

// ── Sync-mode policy types (external audits #2 and #10) ────

/// Redis key holding the DURABLE desired replication-mode state (audit
/// #10), namespaced per cluster so multiple clusters can share one Redis.
/// The value is a JSON [`SyncModeDesiredState`].
fn sync_mode_state_key(cluster_id: &str) -> String {
    format!("ha:replication:sync-mode:{cluster_id}")
}

/// The durable desired replication-mode state persisted by
/// [`ReplicationService::set_sync_mode`] BEFORE any PostgreSQL mutation
/// (external audit #10) and reconciled against the live setting on a
/// bounded interval.
#[derive(Debug, Clone, PartialEq, serde::Serialize, serde::Deserialize)]
pub struct SyncModeDesiredState {
    /// The exact `synchronous_standby_names` value the desired mode
    /// implies. Always a NAMED list (or the empty async value) — never
    /// `'*'`.
    pub desired_setting: String,
    /// Whether the desired mode is synchronous replication.
    pub synchronous: bool,
    /// The named standbys of the synchronous list (empty for async).
    pub standbys: Vec<String>,
    /// The live value observed immediately before the ENABLE transition;
    /// restored verbatim by the idempotent rollback on disable.
    pub previous_setting: String,
    /// When the desired state was last written.
    pub updated_at: chrono::DateTime<Utc>,
}

impl SyncModeDesiredState {
    /// The mode name this desired state stands for (`"sync"`/`"async"`),
    /// as exposed on the status endpoint.
    fn as_mode(&self) -> &'static str {
        if self.synchronous {
            "sync"
        } else {
            "async"
        }
    }
}

impl std::fmt::Display for SyncModeDesiredState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_mode())
    }
}

/// External audit #2 — deterministic policy refusals for a
/// `synchronous=true` transition. Mapped onto 409/422 at the route; never
/// a 500.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SyncModeRefusal {
    /// `synchronous=true` without naming standbys — the `'*'` wildcard
    /// form is refused; the request must name the exact standby(s).
    WildcardFormRefused,
    /// A named standby is not a syntactically valid standby name.
    InvalidStandbyName(Vec<String>),
    /// `synchronous=true` although no standby is configured at all.
    NoStandbyConfigured,
    /// Named standbys outside the configured topology.
    UnknownStandbys(Vec<String>),
    /// Named standbys not currently connected in a streaming state.
    NotStreaming(Vec<String>),
}

impl SyncModeRefusal {
    /// HTTP status for the route: 422 for a malformed REQUEST (wildcard
    /// form / bad name), 409 for a request that conflicts with the CURRENT
    /// topology reality (nothing configured / unknown / not connected).
    pub fn status_code(&self) -> StatusCode {
        match self {
            Self::WildcardFormRefused | Self::InvalidStandbyName(_) => {
                StatusCode::UNPROCESSABLE_ENTITY
            }
            Self::NoStandbyConfigured | Self::UnknownStandbys(_) | Self::NotStreaming(_) => {
                StatusCode::CONFLICT
            }
        }
    }

    /// The human-readable refusal reason (logged and returned in the body).
    pub fn message(&self) -> String {
        match self {
            Self::WildcardFormRefused => {
                "synchronous=true must NAME the exact standby(s) — the '*' wildcard form \
                 is refused"
                    .into()
            }
            Self::InvalidStandbyName(names) => format!("invalid standby name(s): {names:?}"),
            Self::NoStandbyConfigured => {
                "no standby is configured (DB_REPLICA_HOSTS) — synchronous replication \
                 requires at least one configured standby"
                    .into()
            }
            Self::UnknownStandbys(names) => format!(
                "standby(s) {names:?} are not part of the configured topology \
                 (DB_REPLICA_HOSTS)"
            ),
            Self::NotStreaming(names) => format!(
                "standby(s) {names:?} are not currently connected in a streaming \
                 replication state"
            ),
        }
    }
}

/// Outcome of a [`ReplicationService::set_sync_mode`] attempt.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SetSyncModeError {
    /// Deterministic policy refusal (audit #2) — 409/422 at the route.
    Refused(SyncModeRefusal),
    /// Infrastructure failure (PostgreSQL/Redis) — 500 at the route.
    Failed(String),
}

impl std::fmt::Display for SetSyncModeError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Refused(refusal) => {
                write!(f, "sync-mode transition refused: {}", refusal.message())
            }
            Self::Failed(e) => write!(f, "sync-mode transition failed: {e}"),
        }
    }
}

impl std::error::Error for SetSyncModeError {}

/// Audit #2 — pure gate for a `synchronous=true` transition, applied
/// BEFORE any mutation: the request must name the exact standby(s) (no
/// `'*'` wildcard), every name must be part of the configured topology,
/// and every named standby must be currently connected in a streaming
/// state.
fn validate_sync_standbys(
    requested: &[String],
    configured: &[String],
    streaming: &[String],
) -> Result<(), SyncModeRefusal> {
    if requested.is_empty() {
        return Err(SyncModeRefusal::WildcardFormRefused);
    }
    let invalid: Vec<String> = requested
        .iter()
        .filter(|name| !valid_standby_name(name))
        .cloned()
        .collect();
    if !invalid.is_empty() {
        return Err(SyncModeRefusal::InvalidStandbyName(invalid));
    }
    if configured.is_empty() {
        return Err(SyncModeRefusal::NoStandbyConfigured);
    }
    let unknown: Vec<String> = requested
        .iter()
        .filter(|name| !configured.contains(name))
        .cloned()
        .collect();
    if !unknown.is_empty() {
        return Err(SyncModeRefusal::UnknownStandbys(unknown));
    }
    let not_streaming: Vec<String> = requested
        .iter()
        .filter(|name| !streaming.contains(name))
        .cloned()
        .collect();
    if !not_streaming.is_empty() {
        return Err(SyncModeRefusal::NotStreaming(not_streaming));
    }
    Ok(())
}

/// A standby name may only carry hostname-like characters — it is spliced
/// into the `synchronous_standby_names` setting string.
fn valid_standby_name(name: &str) -> bool {
    !name.is_empty()
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, '-' | '_' | '.'))
}

/// Format a NAMED synchronous list — PostgreSQL's explicit-priority form,
/// e.g. `FIRST 2 ("db-replica-1", "db-replica-2")`. Never `'*'`.
///
/// Each name is DOUBLE-QUOTED: standby names follow SQL identifier rules,
/// and host names routinely contain characters (`-`, `.`) that an
/// unquoted identifier cannot carry. [`valid_standby_name`] has already
/// excluded `"` itself from the names.
fn named_sync_standby_list(names: &[String]) -> String {
    let quoted: Vec<String> = names.iter().map(|name| format!("\"{name}\"")).collect();
    format!("FIRST {} ({})", names.len(), quoted.join(", "))
}

/// A rollback (restored) `synchronous_standby_names` value may only
/// contain the characters a legal name-list/quorum form is made of — it is
/// written into postgresql.auto.conf via ALTER SYSTEM. `'*'` is excluded:
/// this service never reintroduces the wildcard.
fn is_restorable_setting_value(value: &str) -> bool {
    !value.contains('*')
        && value
            .chars()
            .all(|c| c.is_alphanumeric() || matches!(c, ' ' | ',' | '-' | '_' | '.' | '(' | ')'))
}

/// The effective replication mode implied by a live
/// `synchronous_standby_names` value (external audit #7).
fn effective_mode(sync_standby_names: &str) -> &'static str {
    if sync_standby_names.trim().is_empty() {
        "async"
    } else {
        "sync"
    }
}

// ── Topology-aware health (external audit #8) ──────────────

/// Topology classification for the replication stats (external audit #8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TopologyStatus {
    /// No replicas expected, none connected — a healthy standalone.
    Standalone,
    /// Replicas expected and all present.
    Healthy,
    /// Fewer replicas connected than configured.
    Degraded,
    /// Replicas expected but NONE connected.
    Unhealthy,
}

impl TopologyStatus {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Standalone => "standalone",
            Self::Healthy => "healthy",
            Self::Degraded => "degraded",
            Self::Unhealthy => "unhealthy",
        }
    }

    /// Standalone and fully-replicated topologies are operational; a
    /// partial or absent replica topology is not.
    pub fn is_operational(&self) -> bool {
        matches!(self, Self::Standalone | Self::Healthy)
    }
}

/// Pure classifier so the four topology quadrants are unit-testable
/// (external audit #8):
/// - expected == 0 && observed == 0 → healthy standalone;
/// - expected > 0 && observed == 0 → unhealthy;
/// - observed < expected → degraded;
/// - observed >= expected > 0 → healthy.
fn classify_topology(expected_replicas: usize, observed_replicas: usize) -> TopologyStatus {
    match (expected_replicas, observed_replicas) {
        (0, 0) => TopologyStatus::Standalone,
        (_, 0) => TopologyStatus::Unhealthy,
        (expected, observed) if observed < expected => TopologyStatus::Degraded,
        _ => TopologyStatus::Healthy,
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
    /// Replay lag in milliseconds from pg_stat_replication.replay_lag.
    lag_ms: Option<f64>,
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
            lag_ms: self.lag_ms,
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
    fn test_config() -> Arc<Config> {
        Arc::new(Config::from_env().expect("HA config must load in development"))
    }

    #[test]
    fn test_stats_empty_replicas() {
        // Stats computation logic without DB
        let replicas: Vec<ReplicaInfo> = vec![];
        let lag_values: Vec<f64> = replicas.iter().filter_map(|r| r.lag_ms).collect();
        let avg = if lag_values.is_empty() {
            0.0
        } else {
            lag_values.iter().sum::<f64>() / lag_values.len() as f64
        };
        assert_eq!(avg, 0.0);
    }

    #[test]
    #[allow(clippy::useless_vec)]
    fn test_stats_with_replicas() {
        let replicas = vec![
            ReplicaInfo {
                pid: 1,
                application_name: "r1".into(),
                client_addr: None,
                state: "streaming".into(),
                sent_lsn: None,
                write_lsn: None,
                flush_lsn: None,
                replay_lsn: None,
                sync_state: "async".into(),
                lag_bytes: Some(1024),
                lag_ms: Some(50.0),
            },
            ReplicaInfo {
                pid: 2,
                application_name: "r2".into(),
                client_addr: None,
                state: "streaming".into(),
                sent_lsn: None,
                write_lsn: None,
                flush_lsn: None,
                replay_lsn: None,
                sync_state: "async".into(),
                lag_bytes: Some(2048),
                lag_ms: Some(100.0),
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
            lag_ms: Some(12.5),
        };
        let info = row.into_info();
        assert_eq!(info.pid, 42);
        assert_eq!(info.state, "streaming");
        assert_eq!(info.sync_state, "async");
        // lag_ms now flows through from pg_stat_replication.replay_lag
        // instead of being hard-coded to None.
        assert_eq!(info.lag_ms, Some(12.5));
    }

    #[test]
    fn test_replication_stats_serialization() {
        let stats = ReplicationStats {
            mode: "async".into(),
            configured_mode: "sync".into(),
            config_drift: true,
            effective_sync_standby_names: String::new(),
            effective_synchronous_commit: "on".into(),
            desired_sync_mode: Some("sync".into()),
            desired_drift: true,
            expected_replicas: 0,
            topology_status: "standalone".into(),
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
        assert_eq!(json["configured_mode"], "sync");
        assert_eq!(json["config_drift"], true);
        assert_eq!(json["desired_sync_mode"], "sync");
        assert_eq!(json["desired_drift"], true);
        assert_eq!(json["topology_status"], "standalone");
        assert_eq!(json["is_healthy"], true);
    }

    #[test]
    fn test_replication_service_creation() {
        let svc = ReplicationService::new(test_pool(), test_config());
        assert!(svc.config.replication.enabled);
    }

    // ── External audit #8: topology-aware health quadrants ─────────────

    #[test]
    fn test_topology_quadrants() {
        // expected == 0 && observed == 0 → healthy standalone.
        assert_eq!(
            classify_topology(0, 0),
            TopologyStatus::Standalone,
            "an explicitly standalone deployment is healthy"
        );
        // expected > 0 && observed == 0 → unhealthy.
        assert_eq!(classify_topology(2, 0), TopologyStatus::Unhealthy);
        // observed < expected → degraded.
        assert_eq!(classify_topology(2, 1), TopologyStatus::Degraded);
        // observed == expected > 0 → healthy.
        assert_eq!(classify_topology(2, 2), TopologyStatus::Healthy);
        assert_eq!(classify_topology(1, 2), TopologyStatus::Healthy);
        // Only the standalone/healthy classifications are operational.
        assert!(TopologyStatus::Standalone.is_operational());
        assert!(TopologyStatus::Healthy.is_operational());
        assert!(!TopologyStatus::Degraded.is_operational());
        assert!(!TopologyStatus::Unhealthy.is_operational());
    }

    #[test]
    fn test_effective_mode_from_live_setting() {
        // External audit #7: the runtime truth decides, not the config.
        assert_eq!(effective_mode(""), "async");
        assert_eq!(effective_mode("   "), "async");
        assert_eq!(effective_mode("*"), "sync");
        assert_eq!(effective_mode("FIRST 1 (db-replica-1)"), "sync");
    }

    // ── External audit #2: the synchronous-transition guard ────────────

    fn names(values: &[&str]) -> Vec<String> {
        values.iter().map(|v| v.to_string()).collect()
    }

    #[test]
    fn test_sync_transition_wildcard_form_is_refused() {
        let configured = names(&["db-replica-1"]);
        let streaming = names(&["db-replica-1"]);
        let error = validate_sync_standbys(&[], &configured, &streaming)
            .expect_err("the unnamed ('*' wildcard) form must be refused");
        assert_eq!(error, SyncModeRefusal::WildcardFormRefused);
        assert_eq!(error.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
        assert!(error.message().contains("NAME"), "{}", error.message());
    }

    #[test]
    fn test_sync_transition_invalid_names_are_refused() {
        let configured = names(&["db-replica-1"]);
        let streaming = names(&["db-replica-1"]);
        let error = validate_sync_standbys(
            &names(&["db-replica-1", "bad name; ALTER SYSTEM"]),
            &configured,
            &streaming,
        )
        .expect_err("names that cannot appear in the setting string are refused");
        assert_eq!(
            error,
            SyncModeRefusal::InvalidStandbyName(names(&["bad name; ALTER SYSTEM"]))
        );
        assert_eq!(error.status_code(), StatusCode::UNPROCESSABLE_ENTITY);
    }

    #[test]
    fn test_sync_transition_requires_a_configured_standby() {
        let error = validate_sync_standbys(&names(&["db-replica-1"]), &[], &[])
            .expect_err("synchronous=true without any configured standby is refused");
        assert_eq!(error, SyncModeRefusal::NoStandbyConfigured);
        assert_eq!(error.status_code(), StatusCode::CONFLICT);
    }

    #[test]
    fn test_sync_transition_rejects_unknown_standbys() {
        let configured = names(&["db-replica-1", "db-replica-2"]);
        let streaming = names(&["db-replica-1", "db-replica-2"]);
        let error = validate_sync_standbys(
            &names(&["db-replica-1", "impostor"]),
            &configured,
            &streaming,
        )
        .expect_err("a standby outside the configured topology is refused");
        assert_eq!(
            error,
            SyncModeRefusal::UnknownStandbys(names(&["impostor"]))
        );
        assert_eq!(error.status_code(), StatusCode::CONFLICT);
    }

    #[test]
    fn test_sync_transition_requires_streaming_standbys() {
        let configured = names(&["db-replica-1", "db-replica-2"]);
        let error = validate_sync_standbys(
            &names(&["db-replica-1", "db-replica-2"]),
            &configured,
            &names(&["db-replica-2"]),
        )
        .expect_err("a named standby that is not streaming is refused");
        assert_eq!(
            error,
            SyncModeRefusal::NotStreaming(names(&["db-replica-1"]))
        );
        assert_eq!(error.status_code(), StatusCode::CONFLICT);
        assert!(error.message().contains("streaming"), "{}", error.message());
    }

    #[test]
    fn test_sync_transition_accepts_valid_named_standbys() {
        let configured = names(&["db-replica-1", "db-replica-2"]);
        let streaming = names(&["db-replica-1", "db-replica-2"]);
        validate_sync_standbys(
            &names(&["db-replica-1", "db-replica-2"]),
            &configured,
            &streaming,
        )
        .expect("naming exact, configured, streaming standbys passes the guard");
    }

    #[test]
    fn test_named_sync_standby_list_is_never_a_wildcard() {
        let list = named_sync_standby_list(&names(&["db-replica-1", "db-replica-2"]));
        assert_eq!(
            list, "FIRST 2 (\"db-replica-1\", \"db-replica-2\")",
            "hyphenated host names need SQL-identifier quoting"
        );
        assert!(!list.contains('*'));
        let single = named_sync_standby_list(&names(&["db-replica-1"]));
        assert_eq!(single, "FIRST 1 (\"db-replica-1\")");
    }

    #[test]
    fn test_restorable_setting_values_exclude_the_wildcard() {
        assert!(is_restorable_setting_value(""));
        assert!(is_restorable_setting_value("FIRST 1 (db-replica-1)"));
        assert!(is_restorable_setting_value("db-replica-1, db-replica-2"));
        assert!(!is_restorable_setting_value("*"));
        assert!(!is_restorable_setting_value("FIRST 1 (*)"));
        assert!(!is_restorable_setting_value("x'; DELETE FROM t; --"));
    }

    #[test]
    fn test_configured_standbys_collects_all_topology_sources() {
        let mut config = (*test_config()).clone();
        config.database.replica_hosts = vec!["r1".into(), "r2".into(), "r1".into()];
        config.database.replica_host = Some("legacy-replica".into());
        config.database.standby_host = Some("r1".into()); // duplicate → dropped
        let svc = ReplicationService::new(test_pool(), Arc::new(config));
        assert_eq!(
            svc.configured_standbys(),
            vec![
                "r1".to_string(),
                "r2".to_string(),
                "legacy-replica".to_string()
            ]
        );
    }

    #[tokio::test]
    async fn test_streaming_probe_seam_feeds_the_guard() {
        let svc = ReplicationService::new(test_pool(), test_config());
        *svc.streaming_overrides.write().await = Some(names(&["seam-standby"]));
        let streaming = svc.streaming_standbys().await.expect("seam");
        assert_eq!(streaming, names(&["seam-standby"]));
    }

    /// External audit #10: the durable desired state outlives the service
    /// object — written through one instance, read back through a FRESH
    /// instance (a simulated restart), then cleared. Skipped (like the
    /// fence-guard test) when no local redis-server is available.
    #[tokio::test]
    async fn test_desired_state_persists_across_service_restart() {
        let listener = match std::net::TcpListener::bind(("127.0.0.1", 0)) {
            Ok(l) => l,
            Err(_) => {
                eprintln!("skipping: cannot allocate port");
                return;
            }
        };
        let port = listener.local_addr().unwrap().port();
        drop(listener);
        let mut child = match std::process::Command::new("redis-server")
            .args([
                "--port",
                &port.to_string(),
                "--save",
                "",
                "--appendonly",
                "no",
                "--daemonize",
                "no",
            ])
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .spawn()
        {
            Ok(child) => child,
            Err(_) => {
                eprintln!("skipping: redis-server not available");
                return;
            }
        };
        let mut ready = false;
        for _ in 0..50 {
            if let Ok(client) = redis::Client::open(format!("redis://127.0.0.1:{port}").as_str()) {
                if let Ok(mut conn) = client.get_connection() {
                    if redis::cmd("PING")
                        .query::<String>(&mut conn)
                        .map(|r| r == "PONG")
                        .unwrap_or(false)
                    {
                        ready = true;
                        break;
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        if !ready {
            let _ = child.kill();
            let _ = child.wait();
            eprintln!("skipping: redis-server did not become ready");
            return;
        }

        let mut config = (*test_config()).clone();
        config.redis.host = "127.0.0.1".into();
        config.redis.port = port;
        // Unique cluster namespace: no collision with sibling tests sharing
        // the ephemeral server.
        config.multi_region.cluster_id = format!("sync-test-{}", uuid::Uuid::new_v4().simple());

        let first = ReplicationService::new(test_pool(), Arc::new(config.clone()));
        assert!(
            first
                .read_desired_state()
                .await
                .expect("empty read")
                .is_none(),
            "a fresh cluster has no recorded desired state"
        );

        let desired = SyncModeDesiredState {
            desired_setting: "FIRST 1 (db-replica-1)".into(),
            synchronous: true,
            standbys: names(&["db-replica-1"]),
            previous_setting: String::new(),
            updated_at: Utc::now(),
        };
        first
            .write_desired_state(&desired)
            .await
            .expect("persist the durable intent");

        // Simulated restart: a NEW service object over the same config.
        let restarted = ReplicationService::new(test_pool(), Arc::new(config.clone()));
        let read_back = restarted
            .read_desired_state()
            .await
            .expect("read after restart")
            .expect("the desired state must survive the service object");
        assert_eq!(read_back, desired);
        assert_eq!(read_back.as_mode(), "sync");

        restarted
            .clear_desired_state()
            .await
            .expect("cleanup after the test");
        assert!(
            restarted
                .read_desired_state()
                .await
                .expect("empty again")
                .is_none(),
            "the desired state is gone after the cleanup"
        );

        let _ = child.kill();
        let _ = child.wait();
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
