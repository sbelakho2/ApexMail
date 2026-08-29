//! Failover & failback service with state-machine, split-brain detection, and STONITH fencing.

use chrono::Utc;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::Config;
use crate::types::{FailoverConfigInfo, FailoverEvent, FailoverRow, FailoverState, FailoverType};

/// Distributed lock key in Redis for failover coordination.
const FAILOVER_LOCK_KEY: &str = "ha:failover:lock";
const FAILOVER_LOCK_TTL: u64 = 60; // seconds
const STATE_KEY: &str = "ha:failover:state";
/// B.2: TTL (seconds) for primary claim keys (`ha:primary:{node}`).
pub const PRIMARY_CLAIM_TTL_SECS: u64 = 300;

/// Fix #10: atomic compare-and-delete — the key is deleted only if it
/// still holds our owner token. Built once (SHA-1 is computed per
/// `Script::new`).
const COMPARE_DELETE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('DEL', KEYS[1])
else
    return 0
end
"#;

fn compare_delete_script() -> &'static redis::Script {
    static SCRIPT: std::sync::OnceLock<redis::Script> = std::sync::OnceLock::new();
    SCRIPT.get_or_init(|| redis::Script::new(COMPARE_DELETE_SCRIPT))
}

/// Fix #12: atomic compare-and-expire — the TTL is extended only if the
/// key still holds our owner token, so a claim lost to (or overwritten
/// by) another node is never resurrected by our refresh.
const COMPARE_EXPIRE_SCRIPT: &str = r#"
if redis.call('GET', KEYS[1]) == ARGV[1] then
    return redis.call('EXPIRE', KEYS[1], ARGV[2])
else
    return 0
end
"#;

fn compare_expire_script() -> &'static redis::Script {
    static SCRIPT: std::sync::OnceLock<redis::Script> = std::sync::OnceLock::new();
    SCRIPT.get_or_init(|| redis::Script::new(COMPARE_EXPIRE_SCRIPT))
}

/// Health probe outcome for a failover candidate (fix #13).
#[derive(Debug, Clone, PartialEq)]
enum ReplicaHealth {
    /// Replication row found; lag in milliseconds verified.
    Replicating(f64),
    /// Database reachable but NO replication row — the candidate is not
    /// replicating (wrong role / broken replication): verifiably unhealthy.
    NotReplicating,
    /// The probe itself failed (monitoring DB unreachable): candidate
    /// health UNKNOWN — kept as a last-resort failover target.
    Unknown,
}

/// FailoverService manages the failover state machine.
pub struct FailoverService {
    pool: PgPool,
    config: Arc<Config>,
    state: Arc<RwLock<FailoverState>>,
    primary_node: Arc<RwLock<String>>,
    /// B.6: per-component failure counters so one flapping component cannot
    /// be pushed over the threshold by failures of another.
    failure_counts: Arc<RwLock<HashMap<String, u32>>>,
    /// Test seam: forces `fence_node` to fail so the abort-on-fencing-failure
    /// path is deterministically exercisable.
    #[cfg(test)]
    fencing_inject_failure: std::sync::atomic::AtomicBool,
    /// Test seam (fix #13): overrides `probe_replica_health` per replica so
    /// the health-aware failover-target selection is deterministically
    /// testable without a live `pg_stat_replication` view.
    #[cfg(test)]
    probe_results: tokio::sync::RwLock<HashMap<String, ReplicaHealth>>,
}

impl FailoverService {
    pub fn new(pool: PgPool, config: Arc<Config>) -> Self {
        let node = config.multi_region.node_id.clone();
        Self {
            pool,
            config,
            state: Arc::new(RwLock::new(FailoverState::Normal)),
            primary_node: Arc::new(RwLock::new(node)),
            failure_counts: Arc::new(RwLock::new(HashMap::new())),
            #[cfg(test)]
            fencing_inject_failure: std::sync::atomic::AtomicBool::new(false),
            #[cfg(test)]
            probe_results: tokio::sync::RwLock::new(HashMap::new()),
        }
    }

    /// Get current failover state.
    pub async fn get_state(&self) -> FailoverState {
        self.state.read().await.clone()
    }

    /// Get the full failover configuration/status info.
    pub async fn get_config_info(&self) -> FailoverConfigInfo {
        let state = self.state.read().await;
        let primary = self.primary_node.read().await;
        FailoverConfigInfo {
            enabled: self.config.failover.enabled,
            mode: if self.config.failover.failback_enabled {
                "automatic".into()
            } else {
                "manual".into()
            },
            threshold: self.config.failover.threshold,
            failback_enabled: self.config.failover.failback_enabled,
            current_state: state.to_string(),
            primary_node: primary.clone(),
            replica_nodes: self.config.database.replica_hosts.clone(),
        }
    }

    /// Report a health check failure from a component. Once the component's
    /// OWN failure count exceeds the threshold, automatic failover is
    /// triggered (B.6: counters are per-component and isolated).
    pub async fn report_failure(&self, component: &str) -> Result<(), String> {
        if !self.config.failover.enabled {
            return Ok(());
        }
        let mut counts = self.failure_counts.write().await;
        let cnt = counts.entry(component.to_string()).or_insert(0);
        *cnt += 1;
        let count = *cnt;
        warn!(
            component,
            count,
            threshold = self.config.failover.threshold,
            "Failure reported"
        );
        let mut trigger = false;
        if count >= self.config.failover.threshold {
            let mut state = self.state.write().await;
            if *state == FailoverState::Normal {
                *state = FailoverState::Detecting;
                trigger = true;
            }
        }
        drop(counts);
        if trigger {
            info!("Failure threshold reached — initiating automatic failover");
            if let Err(e) = self
                .initiate_failover(
                    FailoverType::Automatic,
                    Some(format!("Component {component} failures exceeded threshold")),
                )
                .await
            {
                // The failed attempt must not leave the machine stuck in
                // Detecting — subsequent failures can re-trigger.
                let mut s = self.state.write().await;
                if *s == FailoverState::Detecting {
                    *s = FailoverState::Normal;
                }
                return Err(e);
            }
        }
        Ok(())
    }

    /// Reset all failure counters (e.g., after a successful health check).
    pub async fn reset_failures(&self) {
        let mut counts = self.failure_counts.write().await;
        counts.clear();
    }

    /// Reset the failure counter of a single recovering component, leaving
    /// other components' counters intact (B.6).
    pub async fn reset_failures_for(&self, component: &str) {
        let mut counts = self.failure_counts.write().await;
        counts.remove(component);
    }

    /// Initiate a failover to the next replica.
    ///
    /// B.1/B.4/B.5: the distributed lock is acquired BEFORE any state
    /// transition (the loser restores the prior state and errors out), a
    /// STONITH fencing failure ABORTS the failover (never "proceed anyway"),
    /// and the lock is released on every completion and failure path.
    pub async fn initiate_failover(
        &self,
        failover_type: FailoverType,
        reason: Option<String>,
    ) -> Result<FailoverEvent, String> {
        let started_at = Utc::now();
        // Validate the transition and capture the state to restore on abort.
        let prior_state = {
            let mut s = self.state.write().await;
            match s.clone() {
                FailoverState::Normal => {
                    *s = FailoverState::Detecting;
                    FailoverState::Normal
                }
                FailoverState::Detecting => FailoverState::Detecting,
                FailoverState::FailedOver if failover_type == FailoverType::Manual => {
                    // Allow manual re-failover
                    *s = FailoverState::Detecting;
                    FailoverState::FailedOver
                }
                other => return Err(format!("Cannot initiate failover in state: {other}")),
            }
        };

        // B.5: acquire the distributed lock FIRST, then transition.
        if !self.try_acquire_lock().await {
            let mut s = self.state.write().await;
            *s = prior_state;
            return Err("Failed to acquire failover lock — another failover in progress?".into());
        }

        // Move to FailingOver (lock held).
        {
            let mut s = self.state.write().await;
            *s = FailoverState::FailingOver;
        }

        info!(failover_type = %failover_type, "Failover initiated");

        // Determine target node (fix #13: health-probed selection).
        let current_primary = self.primary_node.read().await.clone();
        let (target, verified_lag_ms) = match self.select_failover_target(&current_primary).await {
            Ok(t) => t,
            Err(e) => {
                self.abort_failover(prior_state).await;
                return Err(e);
            }
        };

        // Run STONITH fencing on old primary — B.1: failure ABORTS.
        if let Err(e) = self.fence_node(&current_primary).await {
            error!(
                node = %current_primary,
                error = %e,
                "STONITH fencing failed — aborting failover (staying on current state)"
            );
            self.abort_failover(prior_state).await;
            return Err(format!(
                "STONITH fencing of '{current_primary}' failed — failover aborted (unsafe to proceed): {e}"
            ));
        }

        // B.2: record the promoted node's primary claim (SET NX EX) so
        // `detect_split_brain` can see conflicting claims, and drop the
        // fenced node's claim.
        if let Err(e) = self.claim_primary(&target).await {
            self.abort_failover(prior_state).await;
            return Err(format!(
                "Failed to record primary claim for '{target}' — failover aborted: {e}"
            ));
        }
        self.release_primary_claim(&current_primary).await;

        // Record the event
        let event_id = Uuid::new_v4();
        let completed_at = Utc::now();
        let duration_ms = (completed_at - started_at).num_milliseconds().max(0);
        // Fix #13: `data_loss` must reflect VERIFIED lag, not a constant.
        // - lag verified and within the configured threshold → false;
        // - lag verified but beyond the threshold → true (promoting a
        //   lagging replica discards the delta);
        // - lag unverifiable → true (no evidence of zero loss).
        let lag_threshold = self.config.replication.lag_threshold_ms as f64;
        let data_loss = !matches!(verified_lag_ms, Some(lag) if lag <= lag_threshold);
        let event = FailoverEvent {
            id: event_id,
            from_node: current_primary.clone(),
            to_node: target.clone(),
            failover_type: failover_type.to_string(),
            state: "completed".into(),
            reason,
            started_at,
            completed_at: Some(completed_at),
            duration_ms: Some(duration_ms),
            data_loss,
            metadata: Some(serde_json::json!({
                "fenced": [current_primary],
                "primary_claim_ttl_secs": PRIMARY_CLAIM_TTL_SECS,
                "lag_verified_ms": verified_lag_ms,
                "lag_threshold_ms": self.config.replication.lag_threshold_ms,
                "lag_unverified": verified_lag_ms.is_none(),
            })),
        };

        if let Err(e) = self.record_event(&event).await {
            tracing::warn!(error = %e, event_id = %event_id, "Failed to record failover event — audit trail gap");
        }

        // Update primary
        {
            let mut p = self.primary_node.write().await;
            *p = target.clone();
        }

        // Transition to FailedOver
        {
            let mut s = self.state.write().await;
            *s = FailoverState::FailedOver;
        }

        // Reset failure counter
        self.reset_failures().await;

        // Publish state to Redis
        if let Err(e) = self.publish_state_change("failed_over").await {
            tracing::warn!(error = %e, "Failed to publish failover state change to Redis");
        }

        info!(from = current_primary, to = target, "Failover completed");

        // B.4: release the lock on completion.
        self.release_lock().await;
        Ok(event)
    }

    /// Restore the prior state and release the distributed lock after a
    /// failed failover attempt (B.4/B.5).
    async fn abort_failover(&self, prior_state: FailoverState) {
        {
            let mut s = self.state.write().await;
            *s = prior_state;
        }
        self.release_lock().await;
    }

    /// Initiate failback to the original primary.
    ///
    /// B.3: failback now (1) requires replication-lag evidence below the
    /// configured threshold (an explicit `force` flag overrides — auditable),
    /// (2) acquires the distributed lock before any state transition, and
    /// (3) only records `data_loss: false` when the lag was actually
    /// verified.
    pub async fn initiate_failback(&self) -> Result<FailoverEvent, String> {
        self.initiate_failback_opt(false).await
    }

    /// Failback with an explicit force override for the lag precondition.
    pub async fn initiate_failback_opt(&self, force: bool) -> Result<FailoverEvent, String> {
        let started_at = Utc::now();
        if !self.config.failover.failback_enabled {
            return Err("Failback is disabled".into());
        }
        let prior_state = self.state.read().await.clone();
        if prior_state != FailoverState::FailedOver {
            return Err(format!("Cannot failback from state: {prior_state}"));
        }

        let current = self.primary_node.read().await.clone();
        let original = self.config.multi_region.node_id.clone();

        // B.3: verify replication lag on the target BEFORE promoting it.
        // `pg_stat_replication.replay_lag` is the lag source used by
        // `ReplicationService::get_lag` in this crate.
        let lag_verified = match self.verify_replication_lag(&original).await {
            Ok(Some(lag_ms)) if lag_ms <= self.config.replication.lag_threshold_ms as f64 => {
                Some(lag_ms)
            }
            Ok(Some(lag_ms)) => {
                if !force {
                    return Err(format!(
                        "Replication lag {lag_ms}ms exceeds threshold {}ms — failback refused \
                         (pass force=true to override)",
                        self.config.replication.lag_threshold_ms
                    ));
                }
                None
            }
            Ok(None) => {
                if !force {
                    return Err(
                        "unable to verify replication lag (no pg_stat_replication row) — \
                         failback refused (pass force=true to override)"
                            .into(),
                    );
                }
                None
            }
            Err(e) => {
                if !force {
                    return Err(format!(
                        "unable to verify replication lag ({e}) — failback refused \
                         (pass force=true to override)"
                    ));
                }
                None
            }
        };

        // Acquire the distributed lock (B.3, same as failover).
        if !self.try_acquire_lock().await {
            return Err("Failed to acquire failover lock — another failover in progress?".into());
        }

        {
            let mut s = self.state.write().await;
            *s = FailoverState::FailingBack;
        }

        info!(from = current, to = original, force, "Failback initiated");

        // Demote the interim primary: drop its claim, claim for the original,
        // and clear the fence placed on the original during failover.
        self.release_primary_claim(&current).await;
        if let Err(e) = self.claim_primary(&original).await {
            error!(error = %e, "Failed to record primary claim during failback — aborting");
            let mut s = self.state.write().await;
            *s = prior_state;
            self.release_lock().await;
            return Err(format!(
                "Failed to record primary claim for '{original}' — failback aborted: {e}"
            ));
        }
        self.unfence_node(&original).await;

        let completed_at = Utc::now();
        let duration_ms = (completed_at - started_at).num_milliseconds().max(0);
        // B.3: data_loss is only reported as false WITH lag evidence; a
        // forced failback records the missing evidence in metadata instead
        // of silently claiming zero loss. The flag matches
        // `initiate_failover`'s semantics (true when lag was NOT verified)
        // — it was previously inverted, so a verified-good failback was
        // recorded as lossy and a forced, unverified one as loss-free.
        let event = FailoverEvent {
            id: Uuid::new_v4(),
            from_node: current,
            to_node: original.clone(),
            failover_type: "failback".into(),
            state: "completed".into(),
            reason: Some("Failback to original primary".into()),
            started_at,
            completed_at: Some(completed_at),
            duration_ms: Some(duration_ms),
            data_loss: lag_verified.is_none(),
            metadata: Some(serde_json::json!({
                "forced": force && lag_verified.is_none(),
                "lag_verified_ms": lag_verified,
                "lag_threshold_ms": self.config.replication.lag_threshold_ms,
            })),
        };

        if let Err(error) = self.record_event(&event).await {
            warn!(error = %error, "Failed to record failback event");
        }

        {
            let mut p = self.primary_node.write().await;
            *p = original;
        }
        {
            let mut s = self.state.write().await;
            *s = FailoverState::Normal;
        }

        if let Err(error) = self.publish_state_change("normal").await {
            warn!(error = %error, "Failed to publish failback state change");
        }
        info!("Failback completed");

        // B.4: release the lock on completion.
        self.release_lock().await;
        Ok(event)
    }

    /// Replication lag (milliseconds) for the node's `pg_stat_replication`
    /// row, if any. `Ok(None)` means no row was found — no evidence.
    async fn verify_replication_lag(&self, node: &str) -> Result<Option<f64>, String> {
        let row: Option<(Option<f64>,)> = sqlx::query_as(
            "SELECT EXTRACT(EPOCH FROM replay_lag) * 1000 AS lag_ms
             FROM pg_stat_replication WHERE application_name = $1",
        )
        .bind(node)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| e.to_string())?;
        Ok(row.and_then(|(ms,)| ms))
    }

    /// Detect split-brain by checking Redis for conflicting primary claims.
    pub async fn detect_split_brain(&self) -> Result<bool, String> {
        let url = self.config.redis.url();
        let client = redis::Client::open(url.as_str()).map_err(|e| e.to_string())?;
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| e.to_string())?;

        // Look for multiple nodes claiming primary via SCAN
        let keys = Self::scan_keys(&mut conn, "ha:primary:*").await?;

        if keys.len() > 1 {
            warn!(
                primaries = keys.len(),
                "Split-brain detected: multiple primary claims"
            );
            let mut s = self.state.write().await;
            *s = FailoverState::SplitBrain;
            return Ok(true);
        }
        Ok(false)
    }

    /// Resolve split-brain by fencing all but one node.
    pub async fn resolve_split_brain(&self, winner_node: &str) -> Result<(), String> {
        info!(winner = winner_node, "Resolving split-brain");
        let url = self.config.redis.url();
        let client = redis::Client::open(url.as_str()).map_err(|e| e.to_string())?;
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| e.to_string())?;

        // Remove all primary claims
        let keys = Self::scan_keys(&mut conn, "ha:primary:*").await?;

        for key in &keys {
            let _: () = redis::cmd("DEL")
                .arg(key)
                .query_async(&mut conn)
                .await
                .unwrap_or_default();
        }

        // Set the winner
        let _: () = redis::cmd("SET")
            .arg(format!("ha:primary:{winner_node}"))
            .arg("1")
            .arg("EX")
            .arg(300u64)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        {
            let mut p = self.primary_node.write().await;
            *p = winner_node.to_string();
        }
        {
            let mut s = self.state.write().await;
            *s = FailoverState::Normal;
        }

        info!("Split-brain resolved");
        Ok(())
    }

    async fn scan_keys(
        conn: &mut redis::aio::MultiplexedConnection,
        pattern: &str,
    ) -> Result<Vec<String>, String> {
        let mut cursor: u64 = 0;
        let mut keys: Vec<String> = Vec::new();
        loop {
            let (next, batch): (u64, Vec<String>) = redis::cmd("SCAN")
                .arg(cursor)
                .arg("MATCH")
                .arg(pattern)
                .arg("COUNT")
                .arg(200u64)
                .query_async(conn)
                .await
                .map_err(|e| e.to_string())?;
            keys.extend(batch);
            if next == 0 {
                break;
            }
            cursor = next;
        }
        Ok(keys)
    }

    /// Get failover event history from DB.
    pub async fn get_history(&self, limit: i64) -> Result<Vec<FailoverEvent>, sqlx::Error> {
        let rows: Vec<FailoverRow> = sqlx::query_as::<_, FailoverRow>(
            "SELECT id, from_node, to_node, failover_type, state, reason,
                    started_at, completed_at, duration_ms, data_loss, metadata
             FROM ha_failover_events ORDER BY started_at DESC LIMIT $1",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_event()).collect())
    }

    // ── Internal helpers ───────────────────────────────────

    /// Fix #13: probe a replica's health/role. Reuses the failback lag
    /// logic (`pg_stat_replication` row presence IS the role probe — a
    /// replica that is replicating has a row; a promoted/standalone node
    /// does not).
    async fn probe_replica_health(&self, replica: &str) -> ReplicaHealth {
        #[cfg(test)]
        {
            let overrides = self.probe_results.read().await;
            if let Some(health) = overrides.get(replica) {
                return health.clone();
            }
        }
        match self.verify_replication_lag(replica).await {
            Ok(Some(lag_ms)) => ReplicaHealth::Replicating(lag_ms),
            Ok(None) => ReplicaHealth::NotReplicating,
            Err(_) => ReplicaHealth::Unknown,
        }
    }

    /// Fix #13: choose the failover target by HEALTH, not list order.
    ///
    /// Priority:
    /// 1. the first replica with a VERIFIED replication row (healthy);
    /// 2. the first replica whose health is UNKNOWN (probe failed — e.g.
    ///    the monitoring DB is unreachable; refusing to fail over at all
    ///    would trade availability for information);
    /// 3. replicas that are verifiably NOT replicating are SKIPPED.
    ///
    /// Returns the target and the verified lag (if any) so the caller can
    /// record a truthful `data_loss` flag.
    async fn select_failover_target(
        &self,
        current_primary: &str,
    ) -> Result<(String, Option<f64>), String> {
        let replicas = &self.config.database.replica_hosts;
        if replicas.is_empty() {
            return Err("No replica hosts configured for failover".into());
        }

        let mut first_unknown: Option<String> = None;
        for r in replicas {
            if r == current_primary {
                continue;
            }
            match self.probe_replica_health(r).await {
                ReplicaHealth::Replicating(lag_ms) => {
                    info!(
                        replica = r,
                        lag_ms, "failover target selected (verified replica)"
                    );
                    return Ok((r.clone(), Some(lag_ms)));
                }
                ReplicaHealth::NotReplicating => {
                    warn!(
                        replica = r,
                        "replica is not replicating (no pg_stat_replication row) — skipping"
                    );
                }
                ReplicaHealth::Unknown => {
                    warn!(
                        replica = r,
                        "replica health unknown (probe failed) — fallback candidate"
                    );
                    if first_unknown.is_none() {
                        first_unknown = Some(r.clone());
                    }
                }
            }
        }
        if let Some(r) = first_unknown {
            return Ok((r, None));
        }
        // Everything was verifiably unhealthy (or only the primary is
        // configured): refuse — promoting a non-replicating node is a
        // guaranteed data-loss split.
        Err("No healthy failover target: every replica is verifiably not replicating".into())
    }

    async fn try_acquire_lock(&self) -> bool {
        use tokio::time::timeout;

        const LOCK_ACQUIRE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
        let url = self.config.redis.url();
        let Ok(client) = redis::Client::open(url.as_str()) else {
            return false;
        };
        let Ok(Ok(mut conn)) = timeout(
            LOCK_ACQUIRE_TIMEOUT,
            client.get_multiplexed_async_connection(),
        )
        .await
        else {
            return false;
        };

        let result: Result<bool, _> = match timeout(
            LOCK_ACQUIRE_TIMEOUT,
            redis::cmd("SET")
                .arg(FAILOVER_LOCK_KEY)
                .arg(&self.config.multi_region.node_id)
                .arg("NX")
                .arg("EX")
                .arg(FAILOVER_LOCK_TTL)
                .query_async(&mut conn),
        )
        .await
        {
            Ok(result) => result,
            Err(_) => return false,
        };

        result.unwrap_or(false)
    }

    /// B.4: release the failover lock — COMPARE-AND-DELETE (fix #10).
    ///
    /// The previous GET-then-DEL pair was non-atomic: if the lock expired
    /// after our GET (which matched us as owner) and was REACQUIRED by
    /// another node, our subsequent DEL deleted the new owner's lock,
    /// allowing two coordinators to run failovers concurrently. The Lua
    /// script below makes the ownership check and the delete one atomic
    /// Redis operation: the key is deleted only when it still holds OUR
    /// owner token at deletion time.
    async fn release_lock(&self) {
        let mut conn = match self.redis_conn().await {
            Ok(conn) => conn,
            Err(e) => {
                warn!(error = %e, "Failed to connect to Redis to release failover lock");
                return;
            }
        };
        let deleted: Result<i64, _> = compare_delete_script()
            .key(FAILOVER_LOCK_KEY)
            .arg(&self.config.multi_region.node_id)
            .invoke_async(&mut conn)
            .await;
        if let Err(e) = deleted {
            warn!(error = %e, "Failed to release failover lock (compare-and-delete)");
        }
    }

    async fn redis_conn(&self) -> Result<redis::aio::MultiplexedConnection, String> {
        let url = self.config.redis.url();
        let client = redis::Client::open(url.as_str()).map_err(|e| e.to_string())?;
        client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| e.to_string())
    }

    /// B.1/B.2: STONITH fencing — mark the node as fenced in Redis. Every
    /// write-acceptance point in this service refuses to serve while the
    /// node's fence key exists (see [`FailoverService::ensure_not_fenced`]).
    async fn fence_node(&self, node_id: &str) -> Result<(), String> {
        #[cfg(test)]
        if self
            .fencing_inject_failure
            .load(std::sync::atomic::Ordering::SeqCst)
        {
            return Err("injected fencing failure (test)".into());
        }
        info!(node = node_id, "STONITH fencing node");
        let mut conn = self.redis_conn().await?;
        let _: () = redis::cmd("SET")
            .arg(format!("ha:fenced:{node_id}"))
            .arg("1")
            .arg("EX")
            .arg(3600u64)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }

    /// Clear a node's fence key (used when the node is promoted back).
    async fn unfence_node(&self, node_id: &str) {
        let Ok(mut conn) = self.redis_conn().await else {
            warn!(
                node = node_id,
                "Failed to connect to Redis to clear fence key"
            );
            return;
        };
        let _: () = redis::cmd("DEL")
            .arg(format!("ha:fenced:{node_id}"))
            .query_async(&mut conn)
            .await
            .unwrap_or(());
    }

    /// Whether the given node currently has a fence key in Redis.
    pub async fn is_fenced_node(&self, node_id: &str) -> Result<bool, String> {
        let mut conn = self.redis_conn().await?;
        let value: Option<String> = redis::cmd("GET")
            .arg(format!("ha:fenced:{node_id}"))
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(value.is_some())
    }

    /// B.1 enforcement: write-acceptance guard. Must be consulted before
    /// serving any mutating request; refuses while `ha:fenced:{self}` exists.
    ///
    /// Fix #9: an UNREADABLE fence status (Redis down / error) fails
    /// CLOSED. The previous fail-open behavior let a fenced-but-
    /// unobservable node keep accepting writes — during a Redis outage a
    /// fenced node would silently keep serving, defeating STONITH exactly
    /// when coordination is degraded.
    pub async fn ensure_not_fenced(&self) -> Result<(), String> {
        let node = self.config.multi_region.node_id.clone();
        match self.is_fenced_node(&node).await {
            Ok(true) => Err(format!(
                "node '{node}' is fenced (ha:fenced:{node} present) — writes refused"
            )),
            Ok(false) => Ok(()),
            Err(e) => {
                error!(
                    node = %node,
                    error = %e,
                    "CRITICAL: fence status unreadable — failing CLOSED, writes refused \
                     (cannot prove this node is not fenced)"
                );
                Err(format!(
                    "fence status for '{node}' unreadable ({e}) — failing closed, writes refused"
                ))
            }
        }
    }

    /// B.2: create this node's primary claim key. The claim is what makes
    /// `detect_split_brain` able to see two simultaneous primaries.
    ///
    /// Fix #11: a FAILED `SET NX` (another claimant already holds the key)
    /// is an ERROR carrying the current holder — the previous `()` reply
    /// type silently discarded Redis's nil and reported success, so a
    /// competing coordinator believed it had recorded its claim.
    async fn claim_primary(&self, node: &str) -> Result<(), String> {
        let mut conn = self.redis_conn().await?;
        let key = format!("ha:primary:{node}");
        let set: Option<String> = redis::cmd("SET")
            .arg(&key)
            .arg(&self.config.multi_region.node_id)
            .arg("NX")
            .arg("EX")
            .arg(PRIMARY_CLAIM_TTL_SECS)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        if set.is_none() {
            let holder: Option<String> = redis::cmd("GET")
                .arg(&key)
                .query_async(&mut conn)
                .await
                .unwrap_or(None);
            return Err(format!(
                "primary claim for '{node}' is already held by '{}' — competing claim detected",
                holder.unwrap_or_else(|| "unknown".into())
            ));
        }
        Ok(())
    }

    /// Fix #12: refresh the primary claim's TTL (compare-and-expire) so
    /// `PRIMARY_CLAIM_TTL_SECS` no longer blinds split-brain detection after
    /// one TTL window on a healthy primary.
    ///
    /// Returns `Ok(true)` when the claim was refreshed, `Ok(false)` when
    /// this node no longer holds the claim (another claimant took it —
    /// the caller should treat that as a split-brain signal), `Err` when
    /// Redis could not be reached.
    pub async fn refresh_primary_claim(&self, node: &str) -> Result<bool, String> {
        let mut conn = self.redis_conn().await?;
        let refreshed: i64 = compare_expire_script()
            .key(format!("ha:primary:{node}"))
            .arg(&self.config.multi_region.node_id)
            .arg(PRIMARY_CLAIM_TTL_SECS)
            .invoke_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;
        Ok(refreshed > 0)
    }

    /// Fix #12: periodically refresh the current primary's claim so it
    /// does not expire while the primary is healthy. Started with the
    /// coordinator's background jobs (see `ha-server`).
    pub async fn run_claim_refresh_loop(&self, interval: std::time::Duration) {
        let mut ticker = tokio::time::interval(interval);
        loop {
            ticker.tick().await;
            let primary = self.primary_node.read().await.clone();
            match self.refresh_primary_claim(&primary).await {
                Ok(true) => {}
                Ok(false) => {
                    warn!(
                        primary = %primary,
                        "our primary claim was taken by another node — flagging split-brain"
                    );
                    let mut s = self.state.write().await;
                    *s = FailoverState::SplitBrain;
                }
                Err(e) => {
                    warn!(error = %e, "failed to refresh primary claim");
                }
            }
        }
    }

    /// B.2: delete a demoted node's primary claim.
    async fn release_primary_claim(&self, node: &str) {
        let Ok(mut conn) = self.redis_conn().await else {
            warn!(
                node = node,
                "Failed to connect to Redis to release primary claim"
            );
            return;
        };
        let _: () = redis::cmd("DEL")
            .arg(format!("ha:primary:{node}"))
            .query_async(&mut conn)
            .await
            .unwrap_or(());
    }

    async fn record_event(&self, event: &FailoverEvent) -> Result<(), sqlx::Error> {
        sqlx::query(
            "INSERT INTO ha_failover_events
             (id, from_node, to_node, failover_type, state, reason, started_at, completed_at, duration_ms, data_loss, metadata)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)"
        )
        .bind(event.id)
        .bind(&event.from_node)
        .bind(&event.to_node)
        .bind(&event.failover_type)
        .bind(&event.state)
        .bind(&event.reason)
        .bind(event.started_at)
        .bind(event.completed_at)
        .bind(event.duration_ms)
        .bind(event.data_loss)
        .bind(&event.metadata)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    async fn publish_state_change(&self, new_state: &str) -> Result<(), String> {
        let url = self.config.redis.url();
        let client = redis::Client::open(url.as_str()).map_err(|e| e.to_string())?;
        let mut conn = client
            .get_multiplexed_async_connection()
            .await
            .map_err(|e| e.to_string())?;

        let _: () = redis::cmd("SET")
            .arg(STATE_KEY)
            .arg(new_state)
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        let _: () = redis::cmd("PUBLISH")
            .arg("ha:failover:events")
            .arg(
                serde_json::json!({
                    "state": new_state,
                    "node_id": self.config.multi_region.node_id,
                    "timestamp": Utc::now().to_rfc3339(),
                })
                .to_string(),
            )
            .query_async(&mut conn)
            .await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
}

/// Fix #14: idempotently create the HA tables this crate writes to.
///
/// `ha_failover_events` (failover.rs `record_event`/`get_history`) and
/// `ha_replication_lag_history` (replication.rs `record_lag`) do NOT
/// exist in any migration in the chain, so every runtime INSERT failed.
/// The shapes below are intentionally minimal and match the exact bind
/// order of the prepared statements; they should be folded into the
/// migration chain later (this function is `IF NOT EXISTS`, so a future
/// migration simply takes over).
///
/// Called from the coordinator startup (`ha-server`); failures are LOUD —
/// the caller aborts startup.
pub async fn bootstrap_tables(pool: &PgPool) -> Result<(), sqlx::Error> {
    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ha_failover_events (
            id            UUID PRIMARY KEY,
            from_node     VARCHAR(255) NOT NULL,
            to_node       VARCHAR(255) NOT NULL,
            failover_type VARCHAR(50)  NOT NULL,
            state         VARCHAR(50)  NOT NULL,
            reason        TEXT,
            started_at    TIMESTAMPTZ  NOT NULL,
            completed_at  TIMESTAMPTZ,
            duration_ms   BIGINT,
            data_loss     BOOLEAN      NOT NULL DEFAULT FALSE,
            metadata      JSONB
        )"#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_ha_failover_events_started_at
         ON ha_failover_events (started_at DESC)",
    )
    .execute(pool)
    .await?;

    sqlx::query(
        r#"
        CREATE TABLE IF NOT EXISTS ha_replication_lag_history (
            id           BIGSERIAL PRIMARY KEY,
            replica_name VARCHAR(255)     NOT NULL,
            lag_ms       DOUBLE PRECISION NOT NULL DEFAULT 0,
            lag_bytes    BIGINT           NOT NULL DEFAULT 0,
            recorded_at  TIMESTAMPTZ      NOT NULL DEFAULT NOW()
        )"#,
    )
    .execute(pool)
    .await?;
    sqlx::query(
        "CREATE INDEX IF NOT EXISTS idx_ha_replication_lag_history_recorded_at
         ON ha_replication_lag_history (recorded_at DESC)",
    )
    .execute(pool)
    .await?;

    Ok(())
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
        Arc::new(Config::from_env())
    }

    #[test]
    fn test_initial_state() {
        test_runtime().block_on(async {
            let svc = FailoverService::new(test_pool(), test_config());
            assert_eq!(svc.get_state().await, FailoverState::Normal);
        });
    }

    #[test]
    fn test_config_info() {
        test_runtime().block_on(async {
            let svc = FailoverService::new(test_pool(), test_config());
            let info = svc.get_config_info().await;
            assert!(info.enabled);
            assert_eq!(info.current_state, "normal");
        });
    }

    #[test]
    fn test_failure_count_reset() {
        test_runtime().block_on(async {
            let svc = FailoverService::new(test_pool(), test_config());
            {
                let mut counts = svc.failure_counts.write().await;
                counts.insert("db".into(), 5);
            }
            svc.reset_failures().await;
            let counts = svc.failure_counts.read().await;
            assert!(counts.is_empty());
        });
    }

    #[test]
    fn test_cannot_failover_from_failing_over() {
        test_runtime().block_on(async {
            let svc = FailoverService::new(test_pool(), test_config());
            {
                let mut s = svc.state.write().await;
                *s = FailoverState::FailingOver;
            }
            let res = svc.initiate_failover(FailoverType::Manual, None).await;
            assert!(res.is_err());
            assert!(res.unwrap_err().contains("Cannot initiate failover"));
        });
    }

    #[test]
    fn test_failback_requires_failed_over() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            // G.8: failback is opt-in since the manual-default change.
            cfg.failover.failback_enabled = true;
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));
            let res = svc.initiate_failback().await;
            assert!(res.is_err());
            assert!(res.unwrap_err().contains("Cannot failback"));
            // Force flag does not bypass the state-machine precondition.
            let res = svc.initiate_failback_opt(true).await;
            assert!(res.is_err());
            assert!(res.unwrap_err().contains("Cannot failback"));
        });
    }

    #[test]
    fn test_failback_disabled_by_default() {
        test_runtime().block_on(async {
            // G.8: automatic failback must be off unless explicitly enabled.
            let cfg = Config::from_env();
            if std::env::var("FAILBACK_ENABLED").is_ok() {
                eprintln!("skipping: FAILBACK_ENABLED explicitly set in environment");
                return;
            }
            assert!(!cfg.failover.failback_enabled);
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));
            let res = svc.initiate_failback().await;
            assert!(res.unwrap_err().contains("Failback is disabled"));
        });
    }

    #[test]
    fn test_select_failover_target_no_replicas() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            cfg.database.replica_hosts = vec![];
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));
            let res = svc.select_failover_target("node-1").await;
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_select_failover_target_picks_different() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            cfg.database.replica_hosts = vec!["replica-1".into(), "replica-2".into()];
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));
            // The fake pool cannot probe health: both replicas are
            // Unknown → first non-primary candidate wins, lag unverified.
            let (target, lag) = svc.select_failover_target("replica-1").await.unwrap();
            assert_eq!(target, "replica-2");
            assert_eq!(lag, None);
        });
    }

    #[test]
    fn test_select_failover_target_skips_unhealthy_replica() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            cfg.database.replica_hosts = vec!["replica-sick".into(), "replica-good".into()];
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));
            {
                let mut probes = svc.probe_results.write().await;
                // First candidate: reachable DB but no replication row →
                // verifiably unhealthy, must be SKIPPED (fix #13).
                probes.insert("replica-sick".into(), ReplicaHealth::NotReplicating);
                probes.insert("replica-good".into(), ReplicaHealth::Replicating(42.0));
            }
            let (target, lag) = svc
                .select_failover_target("node-primary")
                .await
                .expect("a healthy replica exists");
            assert_eq!(target, "replica-good");
            assert_eq!(lag, Some(42.0));
        });
    }

    #[test]
    fn test_select_failover_target_all_unhealthy_refuses() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            cfg.database.replica_hosts = vec!["replica-1".into(), "replica-2".into()];
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));
            {
                let mut probes = svc.probe_results.write().await;
                probes.insert("replica-1".into(), ReplicaHealth::NotReplicating);
                probes.insert("replica-2".into(), ReplicaHealth::NotReplicating);
            }
            let res = svc.select_failover_target("node-primary").await;
            assert!(
                res.is_err(),
                "must refuse when every replica is verifiably unhealthy"
            );
        });
    }

    #[test]
    fn test_select_failover_target_unknown_probe_falls_back() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            cfg.database.replica_hosts = vec!["replica-1".into(), "replica-2".into()];
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));
            {
                let mut probes = svc.probe_results.write().await;
                probes.insert("replica-1".into(), ReplicaHealth::NotReplicating);
                // Probe broken for replica-2: unknown health beats refusal.
                probes.insert("replica-2".into(), ReplicaHealth::Unknown);
            }
            let (target, lag) = svc.select_failover_target("node-primary").await.unwrap();
            assert_eq!(target, "replica-2");
            assert_eq!(lag, None);
        });
    }

    #[test]
    fn test_failover_disabled_report_failure() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            cfg.failover.enabled = false;
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));
            let res = svc.report_failure("db").await;
            assert!(res.is_ok());
        });
    }

    #[test]
    fn test_failover_event_serialization() {
        let event = FailoverEvent {
            id: Uuid::new_v4(),
            from_node: "node-1".into(),
            to_node: "node-2".into(),
            failover_type: "automatic".into(),
            state: "completed".into(),
            reason: Some("test".into()),
            started_at: Utc::now(),
            completed_at: Some(Utc::now()),
            duration_ms: Some(150),
            data_loss: false,
            metadata: None,
        };
        let json = serde_json::to_value(&event).unwrap();
        assert_eq!(json["from_node"], "node-1");
        assert_eq!(json["data_loss"], false);
    }

    #[test]
    fn test_failover_state_display() {
        assert_eq!(FailoverState::SplitBrain.to_string(), "split_brain");
        assert_eq!(FailoverState::FailingBack.to_string(), "failing_back");
    }

    // ── B: fencing / lock / split-brain / failback tests ───────────────────

    /// Config with an unreachable Redis (deterministic failure paths).
    fn dead_redis_config() -> Arc<Config> {
        let mut cfg = Config::from_env();
        cfg.redis.host = "127.0.0.1".into();
        cfg.redis.port = 1; // nothing listens here
        cfg.database.replica_hosts = vec!["replica-1".into()];
        Arc::new(cfg)
    }

    /// Ephemeral throwaway `redis-server` on a random port for live fencing /
    /// claim / lock assertions. Returns None when no binary is available.
    struct TestRedis {
        port: u16,
        child: std::process::Child,
    }
    impl Drop for TestRedis {
        fn drop(&mut self) {
            let _ = self.child.kill();
            let _ = self.child.wait();
        }
    }
    fn spawn_test_redis() -> Option<TestRedis> {
        let listener = std::net::TcpListener::bind(("127.0.0.1", 0)).ok()?;
        let port = listener.local_addr().ok()?.port();
        drop(listener);
        let mut child = std::process::Command::new("redis-server")
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
            .ok()?;
        let url = format!("redis://127.0.0.1:{port}");
        for _ in 0..50 {
            if let Ok(client) = redis::Client::open(url.as_str()) {
                if let Ok(mut conn) = client.get_connection() {
                    if redis::cmd("PING")
                        .query::<String>(&mut conn)
                        .map(|r| r == "PONG")
                        .unwrap_or(false)
                    {
                        return Some(TestRedis { port, child });
                    }
                }
            }
            std::thread::sleep(std::time::Duration::from_millis(100));
        }
        let _ = child.kill();
        let _ = child.wait();
        None
    }

    fn live_redis_config(port: u16) -> Arc<Config> {
        let mut cfg = Config::from_env();
        cfg.redis.host = "127.0.0.1".into();
        cfg.redis.port = port;
        cfg.multi_region.node_id = "node-primary".into();
        cfg.database.replica_hosts = vec!["node-replica".into()];
        // G.8 made failback opt-in; these tests exercise the failback path.
        cfg.failover.failback_enabled = true;
        Arc::new(cfg)
    }

    async fn redis_get(port: u16, key: &str) -> Option<String> {
        let mut conn = redis::Client::open(format!("redis://127.0.0.1:{port}").as_str())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        redis::cmd("GET")
            .arg(key)
            .query_async(&mut conn)
            .await
            .unwrap_or(None)
    }

    async fn redis_set(port: u16, key: &str, value: &str) {
        let mut conn = redis::Client::open(format!("redis://127.0.0.1:{port}").as_str())
            .unwrap()
            .get_multiplexed_async_connection()
            .await
            .unwrap();
        let _: () = redis::cmd("SET")
            .arg(key)
            .arg(value)
            .query_async(&mut conn)
            .await
            .unwrap();
    }

    #[test]
    fn test_per_component_counters_isolated() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            cfg.failover.threshold = 10; // never trigger in this test
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));

            svc.report_failure("db").await.unwrap();
            svc.report_failure("db").await.unwrap();
            svc.report_failure("redis").await.unwrap();
            {
                let counts = svc.failure_counts.read().await;
                assert_eq!(counts.get("db"), Some(&2), "db failures counted separately");
                assert_eq!(counts.get("redis"), Some(&1));
            }

            // Resetting the recovering 'db' component must not clear 'redis'.
            svc.reset_failures_for("db").await;
            {
                let counts = svc.failure_counts.read().await;
                assert!(!counts.contains_key("db"));
                assert_eq!(counts.get("redis"), Some(&1));
            }

            svc.report_failure("redis").await.unwrap();
            svc.report_failure("redis").await.unwrap();
            {
                let counts = svc.failure_counts.read().await;
                assert_eq!(counts.get("redis"), Some(&3));
                assert_eq!(svc.get_state().await, FailoverState::Normal);
            }
        });
    }

    #[test]
    fn test_threshold_reached_triggers_failover_attempt_and_restores_state() {
        test_runtime().block_on(async {
            // Dead Redis: the triggered failover must fail at the lock stage
            // (lock-first) and the machine must return to Normal, not Detecting.
            let mut cfg = Config::from_env();
            cfg.failover.threshold = 2;
            cfg.redis.host = "127.0.0.1".into();
            cfg.redis.port = 1; // nothing listens here
            cfg.database.replica_hosts = vec!["replica-1".into()];
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));
            svc.report_failure("db").await.unwrap();
            let res = svc.report_failure("db").await;
            assert!(
                res.is_err(),
                "triggered failover with unreachable Redis must error"
            );
            assert!(res.unwrap_err().contains("failover lock"));
            assert_eq!(svc.get_state().await, FailoverState::Normal);
            // Counters survive a failed attempt so the next failure re-triggers.
            {
                let counts = svc.failure_counts.read().await;
                assert_eq!(counts.get("db"), Some(&2));
            }
        });
    }

    #[test]
    fn test_failover_with_unreachable_redis_aborts_and_restores_state() {
        test_runtime().block_on(async {
            let svc = FailoverService::new(test_pool(), dead_redis_config());
            let res = svc.initiate_failover(FailoverType::Manual, None).await;
            assert!(res.is_err(), "failover must abort when coordination fails");
            // State and primary must be unchanged (lock-first, restore on loss).
            assert_eq!(svc.get_state().await, FailoverState::Normal);
            let primary = svc.primary_node.read().await.clone();
            assert_eq!(primary, svc.config.multi_region.node_id);
        });
    }

    #[test]
    fn test_fencing_failure_aborts_failover() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let cfg = live_redis_config(redis.port);
            let svc = FailoverService::new(test_pool(), cfg);
            svc.fencing_inject_failure
                .store(true, std::sync::atomic::Ordering::SeqCst);

            let res = svc.initiate_failover(FailoverType::Manual, None).await;
            let err = res.expect_err("fencing failure must abort the failover");
            assert!(
                err.contains("STONITH fencing") && err.contains("aborted"),
                "unexpected error: {err}"
            );
            // Stayed on the current state; primary unchanged.
            assert_eq!(svc.get_state().await, FailoverState::Normal);
            let primary = svc.primary_node.read().await.clone();
            assert_eq!(primary, "node-primary");
            // No promotion happened: no claim for the replica, no fence on us.
            assert!(redis_get(redis.port, "ha:primary:node-replica")
                .await
                .is_none());
            assert!(redis_get(redis.port, "ha:fenced:node-primary")
                .await
                .is_none());
            // B.4: the lock was released on the failure path.
            assert!(redis_get(redis.port, FAILOVER_LOCK_KEY).await.is_none());
        });
    }

    #[test]
    fn test_fenced_node_refuses_writes_and_unfence_re_allows() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let cfg = live_redis_config(redis.port);
            let svc = FailoverService::new(test_pool(), cfg);

            assert!(svc.ensure_not_fenced().await.is_ok());
            redis_set(redis.port, "ha:fenced:node-primary", "1").await;
            let refusal = svc
                .ensure_not_fenced()
                .await
                .expect_err("fenced node must refuse writes");
            assert!(refusal.contains("fenced"), "unexpected refusal: {refusal}");

            svc.unfence_node("node-primary").await;
            assert!(svc.ensure_not_fenced().await.is_ok());
        });
    }

    #[test]
    fn test_lock_not_released_when_owned_by_other_node() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let cfg = live_redis_config(redis.port);
            let svc = FailoverService::new(test_pool(), cfg);
            redis_set(redis.port, FAILOVER_LOCK_KEY, "someone-else").await;
            let res = svc.initiate_failover(FailoverType::Manual, None).await;
            assert!(res.is_err());
            assert!(res.unwrap_err().contains("failover lock"));
            // We must not delete another holder's lock.
            assert_eq!(
                redis_get(redis.port, FAILOVER_LOCK_KEY).await.as_deref(),
                Some("someone-else")
            );
            assert_eq!(svc.get_state().await, FailoverState::Normal);
        });
    }

    #[test]
    fn test_promotion_creates_claim_and_split_brain_detected() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let cfg = live_redis_config(redis.port);
            let svc = FailoverService::new(test_pool(), cfg);

            let event = svc
                .initiate_failover(FailoverType::Manual, Some("test".into()))
                .await
                .expect("failover with live redis");
            assert_eq!(event.to_node, "node-replica");
            assert_eq!(svc.get_state().await, FailoverState::FailedOver);
            assert_eq!(*svc.primary_node.read().await, "node-replica");

            // B.2: claim created for the promoted node, old primary claim gone,
            // old primary fenced, and the lock released (B.4).
            assert!(redis_get(redis.port, "ha:primary:node-replica")
                .await
                .is_some());
            assert!(redis_get(redis.port, "ha:primary:node-primary")
                .await
                .is_none());
            assert!(redis_get(redis.port, "ha:fenced:node-primary")
                .await
                .is_some());
            assert!(redis_get(redis.port, FAILOVER_LOCK_KEY).await.is_none());

            // A second claim appearing elsewhere is a split brain.
            assert!(!svc.detect_split_brain().await.unwrap());
            redis_set(redis.port, "ha:primary:rogue-node", "rogue").await;
            assert!(svc.detect_split_brain().await.unwrap());
            assert_eq!(svc.get_state().await, FailoverState::SplitBrain);
        });
    }

    #[test]
    fn test_failback_without_lag_evidence_refuses_and_force_proceeds() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let cfg = live_redis_config(redis.port);
            let svc = FailoverService::new(test_pool(), cfg);

            svc.initiate_failover(FailoverType::Manual, None)
                .await
                .expect("failover first");

            // The fake pool cannot answer pg_stat_replication: no lag evidence.
            let refusal = svc
                .initiate_failback()
                .await
                .expect_err("failback without lag evidence must refuse");
            assert!(
                refusal.contains("unable to verify replication lag"),
                "unexpected refusal: {refusal}"
            );
            assert_eq!(svc.get_state().await, FailoverState::FailedOver);

            // Force overrides the precondition and completes the failback.
            let event = svc
                .initiate_failback_opt(true)
                .await
                .expect("forced failback");
            assert_eq!(svc.get_state().await, FailoverState::Normal);
            assert_eq!(*svc.primary_node.read().await, "node-primary");
            // Forced failback has no lag evidence: data_loss must be TRUE.
            // (Updated for the F6 inversion fix — this assertion previously
            // pinned the inverted `lag_verified.is_some()` value, which
            // contradicted its own "must NOT be claimed false" comment.)
            assert!(
                event.data_loss,
                "forced failback without verified lag must be recorded as data loss"
            );
            assert_eq!(event.metadata.unwrap()["forced"], serde_json::json!(true));
            // Claims swapped and the original's fence cleared; lock released.
            assert!(redis_get(redis.port, "ha:primary:node-primary")
                .await
                .is_some());
            assert!(redis_get(redis.port, "ha:primary:node-replica")
                .await
                .is_none());
            assert!(redis_get(redis.port, "ha:fenced:node-primary")
                .await
                .is_none());
            assert!(redis_get(redis.port, FAILOVER_LOCK_KEY).await.is_none());
        });
    }

    // ── Fix #9: fence check fails CLOSED on store errors ────────────────

    #[test]
    fn test_ensure_not_fenced_fails_closed_on_store_error() {
        test_runtime().block_on(async {
            // Redis unreachable: is_fenced_node errors — writes must be
            // REFUSED (previously the error path returned Ok, letting a
            // fenced-but-unobservable node keep serving).
            let svc = FailoverService::new(test_pool(), dead_redis_config());
            let res = svc.ensure_not_fenced().await;
            let err = res.expect_err("unreadable fence status must fail closed");
            assert!(err.contains("failing closed"), "unexpected error: {err}");
        });
    }

    // ── Fix #10: compare-and-delete lock release ───────────────────────

    #[test]
    fn test_release_lock_reacquired_lock_survives_old_owner_release() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let cfg = live_redis_config(redis.port); // node_id = node-primary
            let svc = FailoverService::new(test_pool(), cfg);

            // Our lock expired and node-b REACQUIRED it.
            redis_set(redis.port, FAILOVER_LOCK_KEY, "node-b").await;
            // Our (stale) release must not delete node-b's lock.
            svc.release_lock().await;
            assert_eq!(
                redis_get(redis.port, FAILOVER_LOCK_KEY).await.as_deref(),
                Some("node-b"),
                "reacquired lock must survive the old owner's release"
            );

            // Releasing a lock we DO own still works.
            redis_set(redis.port, FAILOVER_LOCK_KEY, "node-primary").await;
            svc.release_lock().await;
            assert!(
                redis_get(redis.port, FAILOVER_LOCK_KEY).await.is_none(),
                "own lock must be released"
            );
        });
    }

    #[test]
    fn test_compare_and_delete_script_semantics() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let mut conn =
                redis::Client::open(format!("redis://127.0.0.1:{}", redis.port).as_str())
                    .unwrap()
                    .get_multiplexed_async_connection()
                    .await
                    .unwrap();

            // The atomic compare-and-delete: token mismatch → no delete.
            let _: () = redis::cmd("SET")
                .arg("cad:test")
                .arg("owner-b")
                .query_async(&mut conn)
                .await
                .unwrap();
            let n: i64 = compare_delete_script()
                .key("cad:test")
                .arg("owner-a")
                .invoke_async(&mut conn)
                .await
                .unwrap();
            assert_eq!(n, 0, "mismatched token must not delete");
            let v: Option<String> = redis::cmd("GET")
                .arg("cad:test")
                .query_async(&mut conn)
                .await
                .unwrap();
            assert_eq!(v.as_deref(), Some("owner-b"));

            // Matching token → atomically deleted.
            let n: i64 = compare_delete_script()
                .key("cad:test")
                .arg("owner-b")
                .invoke_async(&mut conn)
                .await
                .unwrap();
            assert_eq!(n, 1);
            let v: Option<String> = redis::cmd("GET")
                .arg("cad:test")
                .query_async(&mut conn)
                .await
                .unwrap();
            assert!(v.is_none());
        });
    }

    // ── Fix #11: competing primary claim surfaces as an error ──────────

    #[test]
    fn test_claim_primary_competing_claim_surfaces() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let cfg = live_redis_config(redis.port);
            let svc = FailoverService::new(test_pool(), cfg);

            // Another coordinator already claimed the same target node.
            redis_set(redis.port, "ha:primary:node-replica", "rogue-coordinator").await;

            let err = svc
                .claim_primary("node-replica")
                .await
                .expect_err("competing claim must surface as an error");
            assert!(
                err.contains("rogue-coordinator"),
                "error must carry the current holder: {err}"
            );
            // The rogue's claim must be intact.
            assert_eq!(
                redis_get(redis.port, "ha:primary:node-replica")
                    .await
                    .as_deref(),
                Some("rogue-coordinator")
            );

            // With no competing claim, claiming succeeds.
            let _: () = redis::cmd("DEL")
                .arg("ha:primary:node-replica")
                .query_async(
                    &mut redis::Client::open(format!("redis://127.0.0.1:{}", redis.port).as_str())
                        .unwrap()
                        .get_multiplexed_async_connection()
                        .await
                        .unwrap(),
                )
                .await
                .unwrap();
            assert!(svc.claim_primary("node-replica").await.is_ok());
        });
    }

    // ── Fix #12: primary claim refresh (compare-and-expire) ─────────────

    #[test]
    fn test_refresh_primary_claim_extends_ttl_and_detects_second_claim() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let cfg = live_redis_config(redis.port); // node_id = node-primary
            let svc = FailoverService::new(test_pool(), cfg);

            let mut conn =
                redis::Client::open(format!("redis://127.0.0.1:{}", redis.port).as_str())
                    .unwrap()
                    .get_multiplexed_async_connection()
                    .await
                    .unwrap();

            // Claim about to expire.
            let _: () = redis::cmd("SET")
                .arg("ha:primary:node-primary")
                .arg("node-primary")
                .arg("EX")
                .arg(5u64)
                .query_async(&mut conn)
                .await
                .unwrap();

            // Refresh (compare-and-expire) extends the TTL to ~300s.
            assert!(svc.refresh_primary_claim("node-primary").await.unwrap());
            let ttl: i64 = redis::cmd("TTL")
                .arg("ha:primary:node-primary")
                .query_async(&mut conn)
                .await
                .unwrap();
            assert!(
                ttl > 200,
                "claim TTL must be refreshed toward PRIMARY_CLAIM_TTL_SECS (300), got {ttl}"
            );

            // A second claimant takes the key: our refresh must detect it
            // (return false) and must NOT resurrect our claim.
            redis_set(redis.port, "ha:primary:node-primary", "rogue-node").await;
            assert!(
                !svc.refresh_primary_claim("node-primary").await.unwrap(),
                "refresh must report a lost claim"
            );
            let ttl: i64 = redis::cmd("TTL")
                .arg("ha:primary:node-primary")
                .query_async(&mut conn)
                .await
                .unwrap();
            assert!(
                ttl < 200,
                "lost claim must not be re-expired by the old owner (got TTL {ttl})"
            );
            assert_eq!(
                redis_get(redis.port, "ha:primary:node-primary")
                    .await
                    .as_deref(),
                Some("rogue-node")
            );
        });
    }

    // ── Fix #13: data_loss reflects verified lag ────────────────────────

    #[test]
    fn test_failover_data_loss_reflects_verified_lag() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let mut cfg = Config::from_env();
            cfg.redis.host = "127.0.0.1".into();
            cfg.redis.port = redis.port;
            cfg.multi_region.node_id = "node-primary".into();
            cfg.database.replica_hosts = vec!["node-replica".into()];
            cfg.replication.lag_threshold_ms = 5_000;
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));

            // Verified lag within the threshold → data_loss must be FALSE.
            {
                let mut probes = svc.probe_results.write().await;
                probes.insert("node-replica".into(), ReplicaHealth::Replicating(250.0));
            }
            let event = svc
                .initiate_failover(FailoverType::Manual, None)
                .await
                .expect("failover with verified healthy replica");
            assert!(
                !event.data_loss,
                "verified lag 250ms < 5000ms threshold must NOT claim data loss"
            );
            assert_eq!(
                event.metadata.as_ref().unwrap()["lag_verified_ms"],
                serde_json::json!(250.0)
            );

            // Reset for the second scenario.
            {
                let mut s = svc.state.write().await;
                *s = FailoverState::Normal;
            }
            {
                let mut p = svc.primary_node.write().await;
                *p = "node-primary".into();
            }
            let mut conn =
                redis::Client::open(format!("redis://127.0.0.1:{}", redis.port).as_str())
                    .unwrap()
                    .get_multiplexed_async_connection()
                    .await
                    .unwrap();
            let _: () = redis::cmd("DEL")
                .arg("ha:fenced:node-primary")
                .arg("ha:fenced:node-replica")
                .arg("ha:primary:node-replica")
                .arg(FAILOVER_LOCK_KEY)
                .query_async(&mut conn)
                .await
                .unwrap();

            // Verified lag BEYOND the threshold → data_loss must be TRUE.
            {
                let mut probes = svc.probe_results.write().await;
                probes.insert("node-replica".into(), ReplicaHealth::Replicating(60_000.0));
            }
            let event = svc
                .initiate_failover(FailoverType::Manual, None)
                .await
                .expect("failover proceeds (lagging but replicating)");
            assert!(
                event.data_loss,
                "verified lag 60000ms > 5000ms threshold must be recorded as data loss"
            );
        });
    }

    #[test]
    fn test_failover_data_loss_true_when_lag_unverified() {
        let Some(redis) = spawn_test_redis() else {
            eprintln!("skipping: redis-server not available");
            return;
        };
        test_runtime().block_on(async move {
            let mut cfg = Config::from_env();
            cfg.redis.host = "127.0.0.1".into();
            cfg.redis.port = redis.port;
            cfg.multi_region.node_id = "node-primary".into();
            cfg.database.replica_hosts = vec!["node-replica".into()];
            let svc = FailoverService::new(test_pool(), Arc::new(cfg));

            // Health unknown (probe failed): the old code hard-coded
            // data_loss=false; now the missing evidence is truthful.
            let event = svc
                .initiate_failover(FailoverType::Manual, None)
                .await
                .expect("failover proceeds on unknown health");
            assert!(
                event.data_loss,
                "unverifiable lag must be recorded as data loss (no zero-loss evidence)"
            );
            assert_eq!(
                event.metadata.as_ref().unwrap()["lag_unverified"],
                serde_json::json!(true)
            );
        });
    }

    // ── Fix #14: idempotent HA table bootstrap + round trip ────────────

    #[test]
    fn test_bootstrap_tables_round_trip() {
        let Ok(url) = std::env::var("HA_TEST_DATABASE_URL") else {
            eprintln!("skipping: HA_TEST_DATABASE_URL not set");
            return;
        };
        test_runtime().block_on(async {
            let pool = sqlx::postgres::PgPoolOptions::new()
                .max_connections(2)
                .connect(&url)
                .await
                .expect("connect HA_TEST_DATABASE_URL");

            // Idempotent: run twice.
            bootstrap_tables(&pool).await.expect("bootstrap (1st run)");
            bootstrap_tables(&pool).await.expect("bootstrap (2nd run, idempotent)");

            // Round-trip a failover event through record_event/get_history
            // — this INSERT failed at runtime before the tables existed.
            let mut cfg = Config::from_env();
            cfg.multi_region.node_id = "roundtrip-node".into();
            let svc = FailoverService::new(pool.clone(), Arc::new(cfg));
            let event = FailoverEvent {
                id: Uuid::new_v4(),
                from_node: "node-a".into(),
                to_node: "node-b".into(),
                failover_type: "manual".into(),
                state: "completed".into(),
                reason: Some("bootstrap round-trip".into()),
                started_at: Utc::now(),
                completed_at: Some(Utc::now()),
                duration_ms: Some(7),
                data_loss: true,
                metadata: Some(serde_json::json!({"test": true})),
            };
            svc.record_event(&event).await.expect("record_event insert");

            let history = svc.get_history(5).await.expect("get_history read");
            let found = history.iter().find(|e| e.id == event.id).expect("round-tripped event");
            assert!(found.data_loss);
            assert_eq!(found.to_node, "node-b");

            // And the replication lag history table accepts inserts.
            let inserted = sqlx::query(
                "INSERT INTO ha_replication_lag_history (replica_name, lag_ms, lag_bytes, recorded_at)
                 VALUES ($1, $2, $3, NOW())",
            )
            .bind("roundtrip-replica")
            .bind(12.5_f64)
            .bind(1024_i64)
            .execute(&pool)
            .await
            .expect("lag history insert");
            assert_eq!(inserted.rows_affected(), 1);

            // Cleanup our rows.
            let _ = sqlx::query("DELETE FROM ha_failover_events WHERE id = $1")
                .bind(event.id)
                .execute(&pool)
                .await;
            let _ = sqlx::query("DELETE FROM ha_replication_lag_history WHERE replica_name = $1")
                .bind("roundtrip-replica")
                .execute(&pool)
                .await;
        });
    }
}
