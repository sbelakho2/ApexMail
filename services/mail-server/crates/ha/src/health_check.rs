//! Health checking service — monitors DB, Redis, replication lag, and external services.

use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use std::time::Instant;
use sysinfo::{ProcessesToUpdate, System};
use tracing::warn;

use crate::config::Config;
use crate::types::{ClusterHealth, ComponentHealth, HealthStatus};

/// Checks a single component and returns its health.
async fn check_component(
    name: &str,
    f: impl std::future::Future<Output = Result<(HealthStatus, Option<String>), String>>,
) -> ComponentHealth {
    let start = Instant::now();
    match f.await {
        Ok((status, msg)) => ComponentHealth {
            name: name.into(),
            status,
            latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            message: msg,
            last_check: Utc::now(),
            metadata: None,
        },
        Err(e) => ComponentHealth {
            name: name.into(),
            status: HealthStatus::Unhealthy,
            latency_ms: Some(start.elapsed().as_secs_f64() * 1000.0),
            message: Some(e),
            last_check: Utc::now(),
            metadata: None,
        },
    }
}

/// HealthCheckService monitors the cluster's overall health.
pub struct HealthCheckService {
    pool: PgPool,
    config: Arc<Config>,
    start_time: Instant,
    redis_client: Option<redis::Client>,
}

impl HealthCheckService {
    pub fn new(pool: PgPool, config: Arc<Config>) -> Self {
        let redis_client = redis::Client::open(config.redis.url().as_str()).ok();
        Self {
            pool,
            config,
            start_time: Instant::now(),
            redis_client,
        }
    }

    /// Run all health checks and produce a cluster health report.
    pub async fn check_all(&self) -> ClusterHealth {
        let mut components = Vec::with_capacity(5);

        // 1. Database primary
        components.push(self.check_database().await);

        // 2. Redis
        components.push(self.check_redis().await);

        // 3. Replication lag
        components.push(self.check_replication_lag().await);

        // 4. Disk space (simulated check via DB)
        components.push(self.check_disk_space().await);

        // 5. Memory (in-process)
        components.push(self.check_memory().await);

        // Compute overall status
        let overall = Self::compute_overall(&components);

        // Record in DB (best effort)
        if let Err(error) = self.record_health_check(&overall, &components).await {
            warn!(error = %error, "Failed to persist health check result");
        }

        ClusterHealth {
            overall,
            node_id: self.config.multi_region.node_id.clone(),
            region: self.config.multi_region.region.clone(),
            components,
            uptime_secs: self.start_time.elapsed().as_secs_f64(),
            checked_at: Utc::now(),
        }
    }

    async fn check_database(&self) -> ComponentHealth {
        let pool = self.pool.clone();
        check_component("database", async move {
            sqlx::query_scalar::<_, i32>("SELECT 1")
                .fetch_one(&pool)
                .await
                .map(|_| (HealthStatus::Healthy, None))
                .map_err(|e| format!("DB ping failed: {e}"))
        }).await
    }

    async fn check_redis(&self) -> ComponentHealth {
        let client = self.redis_client.clone();
        check_component("redis", async move {
            let client = client.ok_or_else(|| "Redis client not configured".to_string())?;
            let mut conn = client.get_multiplexed_async_connection().await
                .map_err(|e| format!("Redis connect: {e}"))?;
            let pong: String = redis::cmd("PING").query_async(&mut conn).await
                .map_err(|e| format!("Redis PING: {e}"))?;
            if pong == "PONG" {
                Ok((HealthStatus::Healthy, None))
            } else {
                Ok((HealthStatus::Degraded, Some(format!("Unexpected PING response: {pong}"))))
            }
        }).await
    }

    async fn check_replication_lag(&self) -> ComponentHealth {
        let pool = self.pool.clone();
        let threshold = self.config.replication.lag_threshold_ms as f64;
        let warning = self.config.replication.warning_lag_ms as f64;
        check_component("replication", async move {
            // pg_last_wal_receive_lsn / pg_last_wal_replay_lsn
            let row: Option<(Option<f64>,)> = sqlx::query_as(
                "SELECT EXTRACT(EPOCH FROM (now() - pg_last_xact_replay_timestamp())) * 1000 AS lag_ms"
            )
            .fetch_optional(&pool)
            .await
            .map_err(|e| format!("Replication lag query: {e}"))?;

            match row {
                Some((Some(lag_ms),)) if lag_ms > threshold => {
                    Ok((HealthStatus::Unhealthy, Some(format!("Replication lag: {lag_ms:.0}ms"))))
                }
                Some((Some(lag_ms),)) if lag_ms > warning => {
                    Ok((HealthStatus::Degraded, Some(format!("Replication lag: {lag_ms:.0}ms"))))
                }
                Some((Some(lag_ms),)) => {
                    Ok((HealthStatus::Healthy, Some(format!("Lag: {lag_ms:.0}ms"))))
                }
                _ => {
                    // No replication configured is fine on standalone
                    Ok((HealthStatus::Healthy, Some("Standalone / no replication timestamp".into())))
                }
            }
        }).await
    }

    async fn check_disk_space(&self) -> ComponentHealth {
        let pool = self.pool.clone();
        check_component("disk", async move {
            let row: Option<(i64,)> = sqlx::query_as(
                "SELECT pg_database_size(current_database())"
            )
            .fetch_optional(&pool)
            .await
            .map_err(|e| format!("Disk check: {e}"))?;

            match row {
                Some((size,)) => {
                    let gb = size as f64 / (1024.0 * 1024.0 * 1024.0);
                    Ok((HealthStatus::Healthy, Some(format!("DB size: {gb:.2} GB"))))
                }
                None => Ok((HealthStatus::Unknown, Some("Could not determine DB size".into()))),
            }
        }).await
    }

    async fn check_memory(&self) -> ComponentHealth {
        check_component("memory", async {
            let pid = sysinfo::Pid::from_u32(std::process::id());
            let mut sys = System::new();
            sys.refresh_processes(ProcessesToUpdate::All, false);
            sys.refresh_memory();

            if let Some(process) = sys.process(pid) {
                let rss_kb = process.memory();
                let total_kb = sys.total_memory();
                Ok((
                    HealthStatus::Healthy,
                    Some(format!("RSS: {} KB / {} KB", rss_kb, total_kb)),
                ))
            } else {
                Ok((HealthStatus::Unknown, Some("Process not found for memory check".into())))
            }
        }).await
    }

    fn compute_overall(components: &[ComponentHealth]) -> HealthStatus {
        let any_unhealthy = components.iter().any(|c| c.status == HealthStatus::Unhealthy);
        let any_degraded = components.iter().any(|c| c.status == HealthStatus::Degraded);
        if any_unhealthy {
            HealthStatus::Unhealthy
        } else if any_degraded {
            HealthStatus::Degraded
        } else {
            HealthStatus::Healthy
        }
    }

    async fn record_health_check(
        &self,
        overall: &HealthStatus,
        components: &[ComponentHealth],
    ) -> Result<(), sqlx::Error> {
        let comp_json = serde_json::to_value(components)
            .map_err(|e| sqlx::Error::Protocol(format!("serialization: {e}")))?;
        sqlx::query(
            "INSERT INTO ha_health_checks (node_id, region, status, components, checked_at)
             VALUES ($1, $2, $3, $4, NOW())
             ON CONFLICT DO NOTHING"
        )
        .bind(&self.config.multi_region.node_id)
        .bind(&self.config.multi_region.region)
        .bind(overall.to_string())
        .bind(&comp_json)
        .execute(&self.pool)
        .await?;
        Ok(())
    }

    /// Get the latest health checks for all nodes.
    pub async fn get_cluster_status(&self) -> Result<Vec<serde_json::Value>, sqlx::Error> {
        let rows: Vec<(String, String, String, serde_json::Value, chrono::DateTime<Utc>)> =
            sqlx::query_as(
                "SELECT node_id, region, status, components, checked_at
                 FROM ha_health_checks
                 WHERE checked_at > NOW() - INTERVAL '5 minutes'
                 ORDER BY checked_at DESC"
            )
            .fetch_all(&self.pool)
            .await?;

        Ok(rows.into_iter().map(|(node_id, region, status, components, checked_at)| {
            serde_json::json!({
                "node_id": node_id,
                "region": region,
                "status": status,
                "components": components,
                "checked_at": checked_at,
            })
        }).collect())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compute_overall_healthy() {
        let components = vec![
            ComponentHealth {
                name: "db".into(), status: HealthStatus::Healthy,
                latency_ms: Some(1.0), message: None,
                last_check: Utc::now(), metadata: None,
            },
            ComponentHealth {
                name: "redis".into(), status: HealthStatus::Healthy,
                latency_ms: Some(2.0), message: None,
                last_check: Utc::now(), metadata: None,
            },
        ];
        assert_eq!(HealthCheckService::compute_overall(&components), HealthStatus::Healthy);
    }

    #[test]
    fn test_compute_overall_degraded() {
        let components = vec![
            ComponentHealth {
                name: "db".into(), status: HealthStatus::Healthy,
                latency_ms: Some(1.0), message: None,
                last_check: Utc::now(), metadata: None,
            },
            ComponentHealth {
                name: "repl".into(), status: HealthStatus::Degraded,
                latency_ms: Some(5.0), message: Some("high lag".into()),
                last_check: Utc::now(), metadata: None,
            },
        ];
        assert_eq!(HealthCheckService::compute_overall(&components), HealthStatus::Degraded);
    }

    #[test]
    fn test_compute_overall_unhealthy() {
        let components = vec![
            ComponentHealth {
                name: "db".into(), status: HealthStatus::Unhealthy,
                latency_ms: Some(3000.0), message: Some("timeout".into()),
                last_check: Utc::now(), metadata: None,
            },
        ];
        assert_eq!(HealthCheckService::compute_overall(&components), HealthStatus::Unhealthy);
    }

    #[test]
    fn test_compute_overall_empty() {
        assert_eq!(HealthCheckService::compute_overall(&[]), HealthStatus::Healthy);
    }

    #[test]
    fn test_component_health_serialization() {
        let c = ComponentHealth {
            name: "db".into(),
            status: HealthStatus::Healthy,
            latency_ms: Some(1.5),
            message: None,
            last_check: Utc::now(),
            metadata: None,
        };
        let json = serde_json::to_string(&c).unwrap();
        assert!(json.contains("\"name\":\"db\""));
        assert!(json.contains("\"healthy\""));
    }

    #[test]
    fn test_cluster_health_serialization() {
        let ch = ClusterHealth {
            overall: HealthStatus::Healthy,
            node_id: "node-1".into(),
            region: "us-east-1".into(),
            components: vec![],
            uptime_secs: 3600.0,
            checked_at: Utc::now(),
        };
        let json = serde_json::to_value(&ch).unwrap();
        assert_eq!(json["node_id"], "node-1");
        assert_eq!(json["overall"], "healthy");
    }
}
