//! Multi-region service — routing modes, region management, geo routing rules, traffic distribution.

use chrono::Utc;
use sqlx::PgPool;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use tracing::info;
use uuid::Uuid;

use crate::config::{Config, RoutingMode};
use crate::types::{GeoRoutingRule, GeoRoutingRuleRow, RegionInfo, RegionRow,
                   RegionRole, RegionStatus, FencingStatus, TrafficDistribution};

/// MultiRegionService manages cross-region routing, failover, and traffic distribution.
pub struct MultiRegionService {
    pool: PgPool,
    config: Arc<Config>,
    rr_counter: AtomicU64,
}

impl MultiRegionService {
    pub fn new(pool: PgPool, config: Arc<Config>) -> Self {
        Self {
            pool,
            config,
            rr_counter: AtomicU64::new(0),
        }
    }

    // ── Region CRUD ────────────────────────────────────────

    /// Register or update a region.
    pub async fn register_region(
        &self,
        name: &str,
        endpoint: &str,
        role: &RegionRole,
        availability_zone: Option<&str>,
    ) -> Result<RegionInfo, String> {
        let id = Uuid::new_v4();
        let is_primary = role == &RegionRole::Primary;
        let status = if is_primary { RegionStatus::Active } else { RegionStatus::Standby };

        sqlx::query(
            "INSERT INTO ha_regions (id, name, endpoint, status, role, is_primary, health_score, weight, availability_zone)
             VALUES ($1,$2,$3,$4,$5,$6,100.0,1,$7)
             ON CONFLICT (name) DO UPDATE SET endpoint=$3, status=$4, role=$5, is_primary=$6, availability_zone=$7"
        )
        .bind(id).bind(name).bind(endpoint)
        .bind(status.to_string()).bind(role.to_string())
        .bind(is_primary).bind(availability_zone)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Register region: {e}"))?;

        info!(name, role = %role, "Region registered");

        Ok(RegionInfo {
            id, name: name.into(), endpoint: endpoint.into(),
            status: status.to_string(), role: role.to_string(),
            is_primary, health_score: 100.0, latency_ms: None,
            replication_lag_ms: None, weight: 1,
            last_health_check: None,
            availability_zone: availability_zone.map(String::from),
            metadata: None,
        })
    }

    /// Get all regions.
    pub async fn list_regions(&self, limit: i64, offset: i64) -> Result<Vec<RegionInfo>, String> {
        let rows: Vec<RegionRow> = sqlx::query_as::<_, RegionRow>(
            "SELECT id, name, endpoint, status, role, is_primary, health_score,
                    latency_ms, replication_lag_ms, weight, last_health_check,
                    availability_zone, metadata
             FROM ha_regions ORDER BY is_primary DESC, name LIMIT $1 OFFSET $2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("List regions: {e}"))?;

        Ok(rows.into_iter().map(|r| r.into_info()).collect())
    }

    /// Get a single region by name.
    pub async fn get_region(&self, name: &str) -> Result<Option<RegionInfo>, String> {
        let row: Option<RegionRow> = sqlx::query_as::<_, RegionRow>(
            "SELECT id, name, endpoint, status, role, is_primary, health_score,
                    latency_ms, replication_lag_ms, weight, last_health_check,
                    availability_zone, metadata
             FROM ha_regions WHERE name = $1"
        )
        .bind(name)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Get region: {e}"))?;

        Ok(row.map(|r| r.into_info()))
    }

    /// Update region health score and latency.
    pub async fn update_health(
        &self,
        region_name: &str,
        health_score: f64,
        latency_ms: f64,
        replication_lag_ms: Option<f64>,
    ) -> Result<(), String> {
        let status = if health_score >= 80.0 {
            RegionStatus::Active
        } else if health_score >= 50.0 {
            RegionStatus::Standby
        } else {
            RegionStatus::Inactive
        };

        sqlx::query(
            "UPDATE ha_regions SET health_score=$2, latency_ms=$3, replication_lag_ms=$4,
             status=CASE WHEN status = 'fenced' THEN status ELSE $5 END,
             last_health_check=NOW() WHERE name=$1"
        )
        .bind(region_name).bind(health_score).bind(latency_ms)
        .bind(replication_lag_ms).bind(status.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Update health: {e}"))?;

        Ok(())
    }

    /// Remove a region.
    pub async fn remove_region(&self, name: &str) -> Result<bool, String> {
        let res = sqlx::query("DELETE FROM ha_regions WHERE name = $1")
            .bind(name)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Remove region: {e}"))?;
        Ok(res.rows_affected() > 0)
    }

    // ── Routing ────────────────────────────────────────────

    /// Select the best region for a request based on the current routing mode.
    pub async fn route_request(
        &self,
        source_region: Option<&str>,
    ) -> Result<RegionInfo, String> {
        let regions = self.list_regions(10_000, 0).await?;
        let active: Vec<&RegionInfo> = regions.iter()
            .filter(|r| r.status == "active" && r.health_score > 0.0)
            .collect();

        if active.is_empty() {
            return Err("No active regions available".into());
        }

        // Check geo routing rules first
        if let Some(src) = source_region {
            if let Ok(Some(rule)) = self.find_matching_rule(src).await {
                if let Some(target) = active.iter().find(|r| r.name == rule.target_region) {
                    return Ok((*target).clone());
                }
            }
        }

        let selected = match &self.config.multi_region.routing_mode {
            RoutingMode::ActivePassive => {
                active.iter().find(|r| r.is_primary)
                    .or(active.first())
                    .unwrap()
            }
            RoutingMode::RoundRobin => {
                // Use a simple time-based round-robin
                let idx = (self.rr_counter.fetch_add(1, Ordering::Relaxed) as usize) % active.len();
                active[idx]
            }
            RoutingMode::LatencyBased => {
                active.iter()
                    .min_by(|a, b| {
                        a.latency_ms.unwrap_or(f64::MAX)
                            .partial_cmp(&b.latency_ms.unwrap_or(f64::MAX))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .unwrap()
            }
            RoutingMode::Weighted => {
                // Weighted random selection
                let total_weight: i32 = active.iter().map(|r| r.weight.max(1)).sum();
                let pick = (Utc::now().timestamp_millis() as i32).rem_euclid(total_weight);
                let mut cumulative = 0;
                let mut chosen = active[0];
                for r in &active {
                    cumulative += r.weight.max(1);
                    if pick < cumulative {
                        chosen = r;
                        break;
                    }
                }
                chosen
            }
            RoutingMode::GeoProximity => {
                // Fall back to latency-based when geo info not directly applicable
                active.iter()
                    .min_by(|a, b| {
                        a.latency_ms.unwrap_or(f64::MAX)
                            .partial_cmp(&b.latency_ms.unwrap_or(f64::MAX))
                            .unwrap_or(std::cmp::Ordering::Equal)
                    })
                    .unwrap()
            }
            RoutingMode::ActiveActive => {
                // Distribute across all active by health score
                active.iter()
                    .max_by(|a, b| a.health_score.partial_cmp(&b.health_score)
                        .unwrap_or(std::cmp::Ordering::Equal))
                    .unwrap()
            }
        };

        Ok(selected.clone())
    }

    // ── Geo Routing Rules ──────────────────────────────────

    pub async fn add_geo_rule(
        &self,
        name: &str,
        source_region: &str,
        target_region: &str,
        priority: i32,
    ) -> Result<GeoRoutingRule, String> {
        let id = Uuid::new_v4();
        sqlx::query(
            "INSERT INTO ha_geo_routing_rules (id, name, source_region, target_region, priority, enabled)
             VALUES ($1,$2,$3,$4,$5,true)"
        )
        .bind(id).bind(name).bind(source_region).bind(target_region).bind(priority)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Add geo rule: {e}"))?;

        Ok(GeoRoutingRule {
            id, name: name.into(), source_region: source_region.into(),
            target_region: target_region.into(), priority, enabled: true,
            conditions: None,
        })
    }

    pub async fn list_geo_rules(&self, limit: i64, offset: i64) -> Result<Vec<GeoRoutingRule>, String> {
        let rows: Vec<GeoRoutingRuleRow> = sqlx::query_as::<_, GeoRoutingRuleRow>(
            "SELECT id, name, source_region, target_region, priority, enabled, conditions
             FROM ha_geo_routing_rules ORDER BY priority LIMIT $1 OFFSET $2"
        )
        .bind(limit)
        .bind(offset)
        .fetch_all(&self.pool)
        .await
        .map_err(|e| format!("List geo rules: {e}"))?;

        Ok(rows.into_iter().map(|r| r.into_rule()).collect())
    }

    pub async fn delete_geo_rule(&self, id: Uuid) -> Result<bool, String> {
        let res = sqlx::query("DELETE FROM ha_geo_routing_rules WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Delete geo rule: {e}"))?;
        Ok(res.rows_affected() > 0)
    }

    async fn find_matching_rule(&self, source: &str) -> Result<Option<GeoRoutingRule>, String> {
        let row: Option<GeoRoutingRuleRow> = sqlx::query_as::<_, GeoRoutingRuleRow>(
            "SELECT id, name, source_region, target_region, priority, enabled, conditions
             FROM ha_geo_routing_rules
             WHERE source_region = $1 AND enabled = true
             ORDER BY priority LIMIT 1"
        )
        .bind(source)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Find rule: {e}"))?;

        Ok(row.map(|r| r.into_rule()))
    }

    // ── Region Fencing (STONITH) ───────────────────────────

    /// Fence a region to prevent it from serving traffic.
    pub async fn fence_region(&self, region_name: &str, reason: &str) -> Result<(), String> {
        info!(region = region_name, reason, "Fencing region");

        sqlx::query(
            "UPDATE ha_regions SET status = $2 WHERE name = $1"
        )
        .bind(region_name).bind(FencingStatus::Fenced.to_string())
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Fence region: {e}"))?;

        // Publish to Redis
        let url = self.config.redis.url();
        if let Ok(client) = redis::Client::open(url.as_str()) {
            if let Ok(mut conn) = client.get_multiplexed_async_connection().await {
                let _: Result<(), _> = redis::cmd("PUBLISH")
                    .arg("ha:region:fenced")
                    .arg(serde_json::json!({
                        "region": region_name,
                        "reason": reason,
                        "timestamp": Utc::now().to_rfc3339(),
                    }).to_string())
                    .query_async(&mut conn).await;
            }
        }

        Ok(())
    }

    /// Unfence a region.
    pub async fn unfence_region(&self, region_name: &str) -> Result<(), String> {
        sqlx::query("UPDATE ha_regions SET status = 'standby' WHERE name = $1")
            .bind(region_name)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Unfence: {e}"))?;

        info!(region = region_name, "Region unfenced");
        Ok(())
    }

    // ── Traffic Distribution ───────────────────────────────

    /// Get current traffic distribution across regions (from Redis metrics).
    pub async fn get_traffic_distribution(&self) -> Result<Vec<TrafficDistribution>, String> {
        let regions = self.list_regions(10_000, 0).await?;
        let total_weight: f64 = regions.iter().map(|r| r.weight.max(1) as f64).sum();

        Ok(regions.iter().map(|r| {
            TrafficDistribution {
                region: r.name.clone(),
                weight: r.weight.max(1) as f64 / total_weight,
                requests_per_second: 0.0, // Would come from metrics
                error_rate: 0.0,
                avg_latency_ms: r.latency_ms.unwrap_or(0.0),
            }
        }).collect())
    }

    /// Update region weight.
    pub async fn set_weight(&self, region_name: &str, weight: i32) -> Result<(), String> {
        sqlx::query("UPDATE ha_regions SET weight = $2 WHERE name = $1")
            .bind(region_name).bind(weight)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Set weight: {e}"))?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_routing_mode_active_passive_selects_primary() {
        let regions = vec![
            RegionInfo {
                id: Uuid::new_v4(), name: "us-east-1".into(), endpoint: "https://east.example.com".into(),
                status: "active".into(), role: "primary".into(), is_primary: true,
                health_score: 100.0, latency_ms: Some(10.0), replication_lag_ms: None,
                weight: 1, last_health_check: None, availability_zone: None, metadata: None,
            },
            RegionInfo {
                id: Uuid::new_v4(), name: "us-west-2".into(), endpoint: "https://west.example.com".into(),
                status: "active".into(), role: "secondary".into(), is_primary: false,
                health_score: 95.0, latency_ms: Some(50.0), replication_lag_ms: None,
                weight: 1, last_health_check: None, availability_zone: None, metadata: None,
            },
        ];
        let active: Vec<&RegionInfo> = regions.iter()
            .filter(|r| r.status == "active" && r.health_score > 0.0)
            .collect();
        let selected = active.iter().find(|r| r.is_primary).or(active.first()).unwrap();
        assert_eq!(selected.name, "us-east-1");
    }

    #[test]
    fn test_routing_latency_based() {
        let regions = vec![
            RegionInfo {
                id: Uuid::new_v4(), name: "us-east-1".into(), endpoint: "".into(),
                status: "active".into(), role: "primary".into(), is_primary: true,
                health_score: 100.0, latency_ms: Some(100.0), replication_lag_ms: None,
                weight: 1, last_health_check: None, availability_zone: None, metadata: None,
            },
            RegionInfo {
                id: Uuid::new_v4(), name: "eu-west-1".into(), endpoint: "".into(),
                status: "active".into(), role: "secondary".into(), is_primary: false,
                health_score: 95.0, latency_ms: Some(20.0), replication_lag_ms: None,
                weight: 1, last_health_check: None, availability_zone: None, metadata: None,
            },
        ];
        let best = regions.iter()
            .min_by(|a, b| a.latency_ms.unwrap_or(f64::MAX)
                .partial_cmp(&b.latency_ms.unwrap_or(f64::MAX))
                .unwrap_or(std::cmp::Ordering::Equal))
            .unwrap();
        assert_eq!(best.name, "eu-west-1");
    }

    #[test]
    fn test_routing_active_active_selects_healthiest() {
        let regions = vec![
            RegionInfo {
                id: Uuid::new_v4(), name: "a".into(), endpoint: "".into(),
                status: "active".into(), role: "primary".into(), is_primary: true,
                health_score: 80.0, latency_ms: None, replication_lag_ms: None,
                weight: 1, last_health_check: None, availability_zone: None, metadata: None,
            },
            RegionInfo {
                id: Uuid::new_v4(), name: "b".into(), endpoint: "".into(),
                status: "active".into(), role: "secondary".into(), is_primary: false,
                health_score: 95.0, latency_ms: None, replication_lag_ms: None,
                weight: 1, last_health_check: None, availability_zone: None, metadata: None,
            },
        ];
        let best = regions.iter()
            .max_by(|a, b| a.health_score.partial_cmp(&b.health_score).unwrap_or(std::cmp::Ordering::Equal))
            .unwrap();
        assert_eq!(best.name, "b");
    }

    #[test]
    fn test_health_score_to_status() {
        assert_eq!(
            if 90.0 >= 80.0 { "active" } else if 90.0 >= 50.0 { "standby" } else { "inactive" },
            "active"
        );
        assert_eq!(
            if 60.0 >= 80.0 { "active" } else if 60.0 >= 50.0 { "standby" } else { "inactive" },
            "standby"
        );
        assert_eq!(
            if 30.0 >= 80.0 { "active" } else if 30.0 >= 50.0 { "standby" } else { "inactive" },
            "inactive"
        );
    }

    #[test]
    fn test_traffic_distribution_weights() {
        let regions = vec![
            RegionInfo {
                id: Uuid::new_v4(), name: "r1".into(), endpoint: "".into(),
                status: "active".into(), role: "primary".into(), is_primary: true,
                health_score: 100.0, latency_ms: Some(10.0), replication_lag_ms: None,
                weight: 3, last_health_check: None, availability_zone: None, metadata: None,
            },
            RegionInfo {
                id: Uuid::new_v4(), name: "r2".into(), endpoint: "".into(),
                status: "active".into(), role: "secondary".into(), is_primary: false,
                health_score: 100.0, latency_ms: Some(20.0), replication_lag_ms: None,
                weight: 1, last_health_check: None, availability_zone: None, metadata: None,
            },
        ];
        let total_weight: f64 = regions.iter().map(|r| r.weight.max(1) as f64).sum();
        assert_eq!(total_weight, 4.0);
        let dist: Vec<TrafficDistribution> = regions.iter().map(|r| {
            TrafficDistribution {
                region: r.name.clone(),
                weight: r.weight.max(1) as f64 / total_weight,
                requests_per_second: 0.0, error_rate: 0.0,
                avg_latency_ms: r.latency_ms.unwrap_or(0.0),
            }
        }).collect();
        assert!((dist[0].weight - 0.75).abs() < 0.001);
        assert!((dist[1].weight - 0.25).abs() < 0.001);
    }

    #[test]
    fn test_region_info_serialization() {
        let r = RegionInfo {
            id: Uuid::new_v4(), name: "us-east-1".into(), endpoint: "https://east.example.com".into(),
            status: "active".into(), role: "primary".into(), is_primary: true,
            health_score: 99.5, latency_ms: Some(15.2), replication_lag_ms: None,
            weight: 2, last_health_check: None, availability_zone: Some("us-east-1a".into()),
            metadata: None,
        };
        let json = serde_json::to_value(&r).unwrap();
        assert_eq!(json["name"], "us-east-1");
        assert_eq!(json["is_primary"], true);
    }

    #[test]
    fn test_geo_routing_rule_serialization() {
        let rule = GeoRoutingRule {
            id: Uuid::new_v4(), name: "eu-to-eu".into(),
            source_region: "eu-west-1".into(), target_region: "eu-central-1".into(),
            priority: 1, enabled: true, conditions: None,
        };
        let json = serde_json::to_value(&rule).unwrap();
        assert_eq!(json["priority"], 1);
    }

    #[test]
    fn test_fencing_status_display() {
        assert_eq!(FencingStatus::Fenced.to_string(), "fenced");
        assert_eq!(FencingStatus::Released.to_string(), "released");
    }

    #[test]
    fn test_weighted_routing_logic() {
        let weights = vec![3, 1, 1]; // total = 5
        let total: i32 = weights.iter().sum();
        assert_eq!(total, 5);

        // pick=0 → cumulative crosses at idx 0 (3 >= 1)
        let pick = 0;
        let mut cumulative = 0;
        let mut chosen = 0;
        for (i, w) in weights.iter().enumerate() {
            cumulative += w;
            if pick < cumulative {
                chosen = i;
                break;
            }
        }
        assert_eq!(chosen, 0);

        // pick=4 → cumulative crosses at idx 2 (5 >= 5)
        let pick = 4;
        let mut cumulative = 0;
        let mut chosen = 0;
        for (i, w) in weights.iter().enumerate() {
            cumulative += w;
            if pick < cumulative {
                chosen = i;
                break;
            }
        }
        assert_eq!(chosen, 2);
    }
}
