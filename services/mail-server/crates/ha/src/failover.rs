//! Failover & failback service with state-machine, split-brain detection, and STONITH fencing.

use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};
use uuid::Uuid;

use crate::config::Config;
use crate::types::{FailoverEvent, FailoverRow, FailoverState, FailoverType, FailoverConfigInfo};

/// Distributed lock key in Redis for failover coordination.
const FAILOVER_LOCK_KEY: &str = "ha:failover:lock";
const FAILOVER_LOCK_TTL: u64 = 60; // seconds
const STATE_KEY: &str = "ha:failover:state";

/// FailoverService manages the failover state machine.
pub struct FailoverService {
    pool: PgPool,
    config: Arc<Config>,
    state: Arc<RwLock<FailoverState>>,
    primary_node: Arc<RwLock<String>>,
    failure_count: Arc<RwLock<u32>>,
}

impl FailoverService {
    pub fn new(pool: PgPool, config: Arc<Config>) -> Self {
        let node = config.multi_region.node_id.clone();
        Self {
            pool,
            config,
            state: Arc::new(RwLock::new(FailoverState::Normal)),
            primary_node: Arc::new(RwLock::new(node)),
            failure_count: Arc::new(RwLock::new(0)),
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

/// Report a health check failure from a component. Once threshold is exceeded,
/// automatic failover is triggered.
    pub async fn report_failure(&self, component: &str) -> Result<(), String> {
        if !self.config.failover.enabled {
            return Ok(());
        }
        let mut cnt = self.failure_count.write().await;
        *cnt += 1;
        warn!(component, count = *cnt, threshold = self.config.failover.threshold, "Failure reported");
        let mut trigger = false;
        if *cnt >= self.config.failover.threshold {
            let mut state = self.state.write().await;
            if *state == FailoverState::Normal {
                *state = FailoverState::Detecting;
                trigger = true;
            }
        }
        drop(cnt);
        if trigger {
            info!("Failure threshold reached — initiating automatic failover");
            self.initiate_failover(FailoverType::Automatic, Some(format!("Component {component} failures exceeded threshold"))).await?;
        }
        Ok(())
    }

/// Reset the failure counter (e.g., after a successful health check).
    pub async fn reset_failures(&self) {
        let mut cnt = self.failure_count.write().await;
        *cnt = 0;
    }

/// Initiate a failover to the next replica.
    pub async fn initiate_failover(
        &self,
        failover_type: FailoverType,
        reason: Option<String>,
    ) -> Result<FailoverEvent, String> {
        let started_at = Utc::now();
// Transition state:Normal/Detecting → Detecting → FailingOver
        {
            let mut s = self.state.write().await;
            match *s {
                FailoverState::Normal => *s = FailoverState::Detecting,
                FailoverState::Detecting => {},
                FailoverState::FailedOver if failover_type == FailoverType::Manual => {
// Allow manual re-failover
                    *s = FailoverState::Detecting;
                }
                _ => return Err(format!("Cannot initiate failover in state: {}", *s)),
            }
        }

// Move to FailingOver
        {
            let mut s = self.state.write().await;
            *s = FailoverState::FailingOver;
        }

        info!(failover_type = %failover_type, "Failover initiated");

// Determine target node
        let current_primary = self.primary_node.read().await.clone();
        let target = self.select_failover_target(&current_primary).await?;

// Acquire distributed lock
        let lock_acquired = self.try_acquire_lock().await;
        if !lock_acquired {
            let mut s = self.state.write().await;
            *s = FailoverState::Normal;
            return Err("Failed to acquire failover lock — another failover in progress?".into());
        }

// Run STONITH fencing on old primary
        if let Err(e) = self.fence_node(&current_primary).await {
            warn!(error = %e, "STONITH fencing failed, proceeding anyway");
        }

// Record the event
        let event_id = Uuid::new_v4();
        let completed_at = Utc::now();
        let duration_ms = (completed_at - started_at).num_milliseconds().max(0);
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
            data_loss: false,
            metadata: None,
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
        Ok(event)
    }

/// Initiate failback to the original primary.
    pub async fn initiate_failback(&self) -> Result<FailoverEvent, String> {
        let started_at = Utc::now();
        if !self.config.failover.failback_enabled {
            return Err("Failback is disabled".into());
        }
        let current_state = self.state.read().await.clone();
        if current_state != FailoverState::FailedOver {
            return Err(format!("Cannot failback from state: {current_state}"));
        }

        {
            let mut s = self.state.write().await;
            *s = FailoverState::FailingBack;
        }

        let current = self.primary_node.read().await.clone();
        let original = self.config.multi_region.node_id.clone();

        info!(from = current, to = original, "Failback initiated");

        let completed_at = Utc::now();
        let duration_ms = (completed_at - started_at).num_milliseconds().max(0);
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
            data_loss: false,
            metadata: None,
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
        Ok(event)
    }

/// Detect split-brain by checking Redis for conflicting primary claims.
    pub async fn detect_split_brain(&self) -> Result<bool, String> {
        let url = self.config.redis.url();
        let client = redis::Client::open(url.as_str()).map_err(|e| e.to_string())?;
        let mut conn = client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;

// Look for multiple nodes claiming primary via SCAN
        let keys = Self::scan_keys(&mut conn, "ha:primary:*").await?;

        if keys.len() > 1 {
            warn!(primaries = keys.len(), "Split-brain detected: multiple primary claims");
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
        let mut conn = client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;

// Remove all primary claims
        let keys = Self::scan_keys(&mut conn, "ha:primary:*").await?;

        for key in &keys {
            let _: () = redis::cmd("DEL").arg(key)
                .query_async(&mut conn).await
                .unwrap_or_default();
        }

// Set the winner
        let _: () = redis::cmd("SET")
            .arg(format!("ha:primary:{winner_node}"))
            .arg("1")
            .arg("EX").arg(300u64)
            .query_async(&mut conn).await
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
             FROM ha_failover_events ORDER BY started_at DESC LIMIT $1"
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows.into_iter().map(|r| r.into_event()).collect())
    }

// ── Internal helpers ───────────────────────────────────

    async fn select_failover_target(&self, current_primary: &str) -> Result<String, String> {
        let replicas = &self.config.database.replica_hosts;
        if replicas.is_empty() {
            return Err("No replica hosts configured for failover".into());
        }
// Pick the first replica that isn't the current primary
        for r in replicas {
            if r != current_primary {
                return Ok(r.clone());
            }
        }
// Otherwise just use the first one
        Ok(replicas[0].clone())
    }

    async fn try_acquire_lock(&self) -> bool {
        use tokio::time::timeout;

        const LOCK_ACQUIRE_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(3);
        let url = self.config.redis.url();
        let Ok(client) = redis::Client::open(url.as_str()) else { return false };
        let Ok(Ok(mut conn)) = timeout(LOCK_ACQUIRE_TIMEOUT, client.get_multiplexed_async_connection()).await else {
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

    async fn fence_node(&self, node_id: &str) -> Result<(), String> {
// STONITH fencing:mark node as fenced in Redis
        info!(node = node_id, "STONITH fencing node");
        let url = self.config.redis.url();
        let client = redis::Client::open(url.as_str()).map_err(|e| e.to_string())?;
        let mut conn = client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;

        let _: () = redis::cmd("SET")
            .arg(format!("ha:fenced:{node_id}"))
            .arg("1")
            .arg("EX").arg(3600u64)
            .query_async(&mut conn).await
            .map_err(|e| e.to_string())?;

        Ok(())
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
        let mut conn = client.get_multiplexed_async_connection().await
            .map_err(|e| e.to_string())?;

        let _: () = redis::cmd("SET")
            .arg(STATE_KEY)
            .arg(new_state)
            .query_async(&mut conn).await
            .map_err(|e| e.to_string())?;

        let _: () = redis::cmd("PUBLISH")
            .arg("ha:failover:events")
            .arg(serde_json::json!({
                "state": new_state,
                "node_id": self.config.multi_region.node_id,
                "timestamp": Utc::now().to_rfc3339(),
            }).to_string())
            .query_async(&mut conn).await
            .map_err(|e| e.to_string())?;

        Ok(())
    }
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
                let mut cnt = svc.failure_count.write().await;
                *cnt = 5;
            }
            svc.reset_failures().await;
            let cnt = svc.failure_count.read().await;
            assert_eq!(*cnt, 0);
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
            let svc = FailoverService::new(test_pool(), test_config());
            let res = svc.initiate_failback().await;
            assert!(res.is_err());
            assert!(res.unwrap_err().contains("Cannot failback"));
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
            let target = svc.select_failover_target("replica-1").await.unwrap();
            assert_eq!(target, "replica-2");
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
}
