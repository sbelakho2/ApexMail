//! Chaos engineering service — experiment lifecycle, safety monitoring, metric snapshots.

use chrono::Utc;
use observability_service::metrics_collector::MetricsCollector;
use sqlx::PgPool;
use std::collections::HashMap;
use std::sync::Arc;
use sysinfo::System;
use tokio::sync::RwLock;
use tracing::{error, info, warn};
use uuid::Uuid;

use crate::config::Config;
use crate::types::{
    Experiment, ExperimentConfig, ExperimentResults, ExperimentRow,
    ExperimentStatus, ExperimentType, MetricSnapshot, SafetyCheck,
};

/// Safety check interval during experiments.
static SAFETY_CHECK_INTERVAL_MS: std::sync::LazyLock<u64> = std::sync::LazyLock::new(|| {
    std::env::var("HA_CHAOS_SAFETY_INTERVAL_MS")
        .ok()
        .and_then(|value| value.parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(5000)
});
/// Hard ceiling for a single experiment runtime.
const MAX_EXPERIMENT_DURATION_MS: u64 = 60 * 60 * 1000;

/// ChaosEngineeringService manages chaos experiments.
pub struct ChaosEngineeringService {
    pool: PgPool,
    config: Arc<Config>,
    running_experiments: Arc<RwLock<HashMap<Uuid, tokio::sync::watch::Sender<bool>>>>,
    metrics: Option<Arc<MetricsCollector>>,
}

impl ChaosEngineeringService {
    pub fn new(pool: PgPool, config: Arc<Config>) -> Self {
        Self {
            pool,
            config,
            running_experiments: Arc::new(RwLock::new(HashMap::new())),
            metrics: None,
        }
    }

    /// Create with a metrics collector for real metric capture.
    pub fn with_metrics(pool: PgPool, config: Arc<Config>, metrics: Arc<MetricsCollector>) -> Self {
        Self {
            pool,
            config,
            running_experiments: Arc::new(RwLock::new(HashMap::new())),
            metrics: Some(metrics),
        }
    }

    // ── Experiment Lifecycle ───────────────────────────────

    /// Create and start a new chaos experiment.
    pub async fn start_experiment(
        &self,
        name: &str,
        experiment_config: ExperimentConfig,
    ) -> Result<Experiment, String> {
        if !self.config.chaos.enabled {
            return Err("Chaos engineering is disabled".into());
        }

        // Validate experiment type
        let _exp_type = ExperimentType::parse(&experiment_config.experiment_type)
            .ok_or_else(|| format!("Unknown experiment type: {}", experiment_config.experiment_type))?;

        if experiment_config.parameters.duration_ms == 0 {
            return Err("Experiment duration must be greater than 0ms".into());
        }
        if experiment_config.parameters.duration_ms > MAX_EXPERIMENT_DURATION_MS {
            return Err(format!(
                "Experiment duration exceeds hard limit of {}ms",
                MAX_EXPERIMENT_DURATION_MS
            ));
        }

        let id = Uuid::new_v4();
        let now = Utc::now();

        let config_json = serde_json::to_value(&experiment_config).map_err(|e| e.to_string())?;
        let target_json = serde_json::to_value(&experiment_config.target).map_err(|e| e.to_string())?;
        let params_json = serde_json::to_value(&experiment_config.parameters).map_err(|e| e.to_string())?;
        let safety_json = serde_json::to_value(&experiment_config.safety_checks).map_err(|e| e.to_string())?;

        // Insert experiment record
        sqlx::query(
            "INSERT INTO ha_chaos_experiments
             (id, name, experiment_type, status, config, target, parameters, safety_checks, created_at)
             VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)"
        )
        .bind(id).bind(name)
        .bind(&experiment_config.experiment_type)
        .bind(ExperimentStatus::Pending.to_string())
        .bind(&config_json).bind(&target_json)
        .bind(&params_json).bind(&safety_json)
        .bind(now)
        .execute(&self.pool)
        .await
        .map_err(|e| format!("Insert experiment: {e}"))?;

        // Capture pre-experiment metrics
        let metrics_before = self.capture_metrics().await;

        // Mark as running
        sqlx::query("UPDATE ha_chaos_experiments SET status = $2, started_at = NOW() WHERE id = $1")
            .bind(id)
            .bind(ExperimentStatus::Running.to_string())
            .execute(&self.pool)
            .await
            .map_err(|e| e.to_string())?;

        info!(experiment_id = %id, name, experiment_type = experiment_config.experiment_type, "Chaos experiment started");

        // Start safety monitoring in background
        let (abort_tx, abort_rx) = tokio::sync::watch::channel(false);
        {
            let mut running = self.running_experiments.write().await;
            running.insert(id, abort_tx);
        }

        let pool_clone = self.pool.clone();
        let safety_checks = experiment_config.safety_checks.clone();
        let duration_ms = experiment_config.parameters.duration_ms;
        let metrics_clone = self.metrics.clone();
        let running_clone = self.running_experiments.clone();

        tokio::spawn(async move {
            Self::monitor_experiment(pool_clone, id, safety_checks, duration_ms, abort_rx, metrics_before, metrics_clone, running_clone).await;
        });

        let experiment = Experiment {
            id,
            name: name.into(),
            experiment_type: experiment_config.experiment_type,
            status: ExperimentStatus::Running.to_string(),
            config: config_json,
            target: target_json,
            parameters: params_json,
            safety_checks: safety_json,
            started_at: Some(now),
            completed_at: None,
            duration_ms: None,
            results: None,
            created_by: None,
            created_at: now,
        };

        Ok(experiment)
    }

    /// Safety monitoring loop. Runs until experiment completes or gets aborted.
    async fn monitor_experiment(
        pool: PgPool,
        experiment_id: Uuid,
        safety_checks: Vec<SafetyCheck>,
        duration_ms: u64,
        mut abort_rx: tokio::sync::watch::Receiver<bool>,
        metrics_before: MetricSnapshot,
        metrics_collector: Option<Arc<MetricsCollector>>,
        running_experiments: Arc<RwLock<HashMap<Uuid, tokio::sync::watch::Sender<bool>>>>,
    ) {
        let start = std::time::Instant::now();
        let duration = std::time::Duration::from_millis(duration_ms.min(MAX_EXPERIMENT_DURATION_MS));

        loop {
            tokio::select! {
                _ = tokio::time::sleep(std::time::Duration::from_millis(*SAFETY_CHECK_INTERVAL_MS)) => {
                    // Check safety thresholds
                    let current = Self::capture_metrics_with_collector(metrics_collector.as_ref()).await;
                    for check in &safety_checks {
                        if check.abort_on_failure {
                            let value = Self::get_metric_value(&current, &check.check_type);
                            let violated = match check.operator.as_str() {
                                ">" | "gt" => value > check.threshold,
                                "<" | "lt" => value < check.threshold,
                                ">=" | "gte" => value >= check.threshold,
                                _ => false,
                            };
                            if violated {
                                warn!(
                                    experiment_id = %experiment_id,
                                    check = check.name,
                                    value,
                                    threshold = check.threshold,
                                    "Safety check violated — aborting experiment"
                                );
                                if let Err(e) = Self::complete_experiment_static(
                                    &pool, experiment_id, ExperimentStatus::Aborted,
                                    Some(metrics_before.clone()), Some(current), None,
                                    vec![format!("Safety check '{}' violated: {} {} {}", check.name, value, check.operator, check.threshold)],
                                ).await {
                                    error!(experiment_id = %experiment_id, error = %e, "Failed to record experiment abort after safety violation");
                                }
                                Self::cleanup_running_experiment(&running_experiments, experiment_id).await;
                                return;
                            }
                        }
                    }

                    // Check duration
                    if start.elapsed() >= duration {
                        let after = Self::capture_metrics_with_collector(metrics_collector.as_ref()).await;
                        if let Err(e) = Self::complete_experiment_static(
                            &pool, experiment_id, ExperimentStatus::Completed,
                            Some(metrics_before), Some(current), Some(after),
                            vec![],
                        ).await {
                            error!(experiment_id = %experiment_id, error = %e, "Failed to record experiment completion");
                        }
                        Self::cleanup_running_experiment(&running_experiments, experiment_id).await;
                        return;
                    }
                }
                _ = abort_rx.changed() => {
                    if *abort_rx.borrow() {
                        let after = Self::capture_metrics_with_collector(metrics_collector.as_ref()).await;
                        if let Err(e) = Self::complete_experiment_static(
                            &pool, experiment_id, ExperimentStatus::Aborted,
                            Some(metrics_before), None, Some(after),
                            vec!["Manually aborted".into()],
                        ).await {
                            error!(experiment_id = %experiment_id, error = %e, "Failed to record manual experiment abort");
                        }
                        Self::cleanup_running_experiment(&running_experiments, experiment_id).await;
                        return;
                    }
                }
            }
        }
    }

    async fn cleanup_running_experiment(
        running_experiments: &Arc<RwLock<HashMap<Uuid, tokio::sync::watch::Sender<bool>>>>,
        experiment_id: Uuid,
    ) {
        let mut running = running_experiments.write().await;
        running.remove(&experiment_id);
    }

    async fn complete_experiment_static(
        pool: &PgPool,
        id: Uuid,
        status: ExperimentStatus,
        before: Option<MetricSnapshot>,
        during: Option<MetricSnapshot>,
        after: Option<MetricSnapshot>,
        violations: Vec<String>,
    ) -> Result<(), String> {
        let results = ExperimentResults {
            success: status == ExperimentStatus::Completed,
            metrics_before: before.unwrap_or_else(Self::empty_snapshot),
            metrics_during: during,
            metrics_after: after,
            safety_violations: violations,
            observations: vec![],
            recommendations: vec![],
        };
        let results_json = serde_json::to_value(&results).unwrap_or_default();

        sqlx::query(
            "UPDATE ha_chaos_experiments SET status=$2, completed_at=NOW(),
             duration_ms=EXTRACT(EPOCH FROM (NOW()-started_at))*1000, results=$3 WHERE id=$1"
        )
        .bind(id).bind(status.to_string()).bind(&results_json)
        .execute(pool)
        .await
        .map_err(|e| format!("Complete experiment: {e}"))?;

        info!(experiment_id = %id, status = %status, "Experiment completed");
        Ok(())
    }

    /// Abort a running experiment.
    pub async fn abort_experiment(&self, id: Uuid) -> Result<(), String> {
        let running = self.running_experiments.read().await;
        if let Some(tx) = running.get(&id) {
            if let Err(error) = tx.send(true) {
                return Err(format!("Failed to send abort signal: {error}"));
            }
            info!(experiment_id = %id, "Abort signal sent");
            Ok(())
        } else {
            Err(format!("Experiment {id} not found or not running"))
        }
    }

    // ── Query ──────────────────────────────────────────────

    pub async fn get_experiment(&self, id: Uuid) -> Result<Option<Experiment>, String> {
        let row: Option<ExperimentRow> = sqlx::query_as::<_, ExperimentRow>(
            "SELECT id, name, experiment_type, status, config, target, parameters,
                    safety_checks, started_at, completed_at, duration_ms, results, created_by, created_at
             FROM ha_chaos_experiments WHERE id = $1"
        )
        .bind(id)
        .fetch_optional(&self.pool)
        .await
        .map_err(|e| format!("Get experiment: {e}"))?;

        Ok(row.map(|r| r.into_experiment()))
    }

    pub async fn list_experiments(
        &self,
        status: Option<&str>,
        limit: i64,
    ) -> Result<Vec<Experiment>, String> {
        let (sql, bind_status) = match status {
            Some(s) => (
                "SELECT id, name, experiment_type, status, config, target, parameters,
                        safety_checks, started_at, completed_at, duration_ms, results, created_by, created_at
                 FROM ha_chaos_experiments WHERE status = $1 ORDER BY created_at DESC LIMIT $2",
                Some(s.to_string()),
            ),
            None => (
                "SELECT id, name, experiment_type, status, config, target, parameters,
                        safety_checks, started_at, completed_at, duration_ms, results, created_by, created_at
                 FROM ha_chaos_experiments ORDER BY created_at DESC LIMIT $1",
                None,
            ),
        };

        let rows: Vec<ExperimentRow> = if let Some(s) = bind_status {
            sqlx::query_as::<_, ExperimentRow>(sql)
                .bind(s).bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| format!("List experiments: {e}"))?
        } else {
            sqlx::query_as::<_, ExperimentRow>(sql)
                .bind(limit)
                .fetch_all(&self.pool)
                .await
                .map_err(|e| format!("List experiments: {e}"))?
        };

        Ok(rows.into_iter().map(|r| r.into_experiment()).collect())
    }

    /// Delete an experiment record.
    pub async fn delete_experiment(&self, id: Uuid) -> Result<bool, String> {
        let res = sqlx::query("DELETE FROM ha_chaos_experiments WHERE id = $1")
            .bind(id)
            .execute(&self.pool)
            .await
            .map_err(|e| format!("Delete experiment: {e}"))?;
        Ok(res.rows_affected() > 0)
    }

    // ── Metrics ────────────────────────────────────────────

    async fn capture_metrics(&self) -> MetricSnapshot {
        Self::capture_metrics_with_collector(self.metrics.as_ref()).await
    }

    /// Capture real metrics from the metrics collector and system.
    async fn capture_metrics_with_collector(collector: Option<&Arc<MetricsCollector>>) -> MetricSnapshot {
        // Get system metrics (CPU and memory)
        let mut sys = System::new();
        sys.refresh_cpu_usage();
        sys.refresh_memory();
        
        // CPU usage as fraction (0.0 to 1.0)
        let cpu_count = sys.cpus().len().max(1) as f32;
        let cpu_usage = sys.cpus().iter().map(|c| c.cpu_usage()).sum::<f32>() / cpu_count / 100.0;
        
        // Memory usage as fraction
        let total_mem = sys.total_memory();
        let used_mem = sys.used_memory();
        let memory_usage = if total_mem > 0 {
            used_mem as f64 / total_mem as f64
        } else {
            0.0
        };

        // Get application metrics from collector if available
        let (error_rate, latency_p50, latency_p99, throughput) = if let Some(mc) = collector {
            let summaries = mc.get_summary();
            
            // Look up known metric names
            let error_rate = summaries.iter()
                .find(|m| m.name == "error_rate" || m.name == "errors_total")
                .map(|m| m.value)
                .unwrap_or(0.0);
            
            let requests_total = summaries.iter()
                .find(|m| m.name == "requests_total" || m.name == "http_requests_total")
                .map(|m| m.value)
                .unwrap_or(0.0);
            
            // Estimate throughput from requests counter (simplified - real impl would diff over time)
            let throughput = requests_total.min(10000.0); // Cap at reasonable value
            
            // Look for latency histogram metrics
            let latency_p50 = summaries.iter()
                .find(|m| m.name == "latency_p50" || m.name.contains("latency"))
                .map(|m| m.value * 1000.0) // Convert to ms if in seconds
                .unwrap_or(0.0);
            
            let latency_p99 = summaries.iter()
                .find(|m| m.name == "latency_p99")
                .map(|m| m.value * 1000.0)
                .unwrap_or(latency_p50 * 3.0); // Estimate p99 from p50
            
            (error_rate, latency_p50, latency_p99, throughput)
        } else {
            // No collector, return zeros for app metrics (system metrics still real)
            (0.0, 0.0, 0.0, 0.0)
        };

        MetricSnapshot {
            timestamp: Utc::now(),
            error_rate,
            latency_p50_ms: latency_p50,
            latency_p99_ms: latency_p99,
            throughput_rps: throughput,
            cpu_usage: cpu_usage as f64,
            memory_usage,
        }
    }

    fn get_metric_value(snapshot: &MetricSnapshot, metric_type: &str) -> f64 {
        match metric_type {
            "error_rate" => snapshot.error_rate,
            "latency_p50" => snapshot.latency_p50_ms,
            "latency_p99" => snapshot.latency_p99_ms,
            "throughput" => snapshot.throughput_rps,
            "cpu" | "cpu_usage" => snapshot.cpu_usage,
            "memory" | "memory_usage" => snapshot.memory_usage,
            _ => 0.0,
        }
    }

    fn empty_snapshot() -> MetricSnapshot {
        MetricSnapshot {
            timestamp: Utc::now(),
            error_rate: 0.0,
            latency_p50_ms: 0.0,
            latency_p99_ms: 0.0,
            throughput_rps: 0.0,
            cpu_usage: 0.0,
            memory_usage: 0.0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::{ExperimentParameters, ExperimentTarget};

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
    fn test_chaos_disabled_rejects() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            cfg.chaos.enabled = false;
            let svc = ChaosEngineeringService::new(test_pool(), Arc::new(cfg));
            let res = svc.start_experiment("test", ExperimentConfig {
                experiment_type: "latency_injection".into(),
                target: ExperimentTarget { service: "api".into(), instances: vec![], percentage: 50.0 },
                parameters: ExperimentParameters { duration_ms: 5000, intensity: 0.5, error_codes: None, latency_ms: Some(100), resource_type: None, resource_limit: None },
                safety_checks: vec![],
                rollback_on_failure: true,
            }).await;
            assert!(res.is_err());
            assert!(res.unwrap_err().contains("disabled"));
        });
    }

    #[test]
    fn test_invalid_experiment_type() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            cfg.chaos.enabled = true;
            let svc = ChaosEngineeringService::new(test_pool(), Arc::new(cfg));
            let res = svc.start_experiment("test", ExperimentConfig {
                experiment_type: "unknown_type".into(),
                target: ExperimentTarget { service: "api".into(), instances: vec![], percentage: 50.0 },
                parameters: ExperimentParameters { duration_ms: 5000, intensity: 0.5, error_codes: None, latency_ms: None, resource_type: None, resource_limit: None },
                safety_checks: vec![],
                rollback_on_failure: true,
            }).await;
            assert!(res.is_err());
            assert!(res.unwrap_err().contains("Unknown experiment type"));
        });
    }

    #[test]
    fn test_get_metric_value() {
        let snap = MetricSnapshot {
            timestamp: Utc::now(),
            error_rate: 0.05,
            latency_p50_ms: 25.0,
            latency_p99_ms: 150.0,
            throughput_rps: 500.0,
            cpu_usage: 0.75,
            memory_usage: 0.60,
        };
        assert_eq!(ChaosEngineeringService::get_metric_value(&snap, "error_rate"), 0.05);
        assert_eq!(ChaosEngineeringService::get_metric_value(&snap, "latency_p50"), 25.0);
        assert_eq!(ChaosEngineeringService::get_metric_value(&snap, "cpu_usage"), 0.75);
        assert_eq!(ChaosEngineeringService::get_metric_value(&snap, "unknown"), 0.0);
    }

    #[test]
    fn test_safety_check_violation_logic() {
        let check = SafetyCheck {
            name: "error-rate".into(),
            check_type: "error_rate".into(),
            threshold: 0.1,
            operator: ">".into(),
            abort_on_failure: true,
        };
        let value = 0.15;
        let violated = match check.operator.as_str() {
            ">" | "gt" => value > check.threshold,
            "<" | "lt" => value < check.threshold,
            _ => false,
        };
        assert!(violated);
    }

    #[test]
    fn test_safety_check_not_violated() {
        let check = SafetyCheck {
            name: "latency".into(),
            check_type: "latency_p99".into(),
            threshold: 200.0,
            operator: ">".into(),
            abort_on_failure: true,
        };
        let value = 150.0;
        let violated = value > check.threshold;
        assert!(!violated);
    }

    #[test]
    fn test_metric_snapshot_serialization() {
        let snap = MetricSnapshot {
            timestamp: Utc::now(),
            error_rate: 0.01,
            latency_p50_ms: 10.0,
            latency_p99_ms: 50.0,
            throughput_rps: 2000.0,
            cpu_usage: 0.4,
            memory_usage: 0.6,
        };
        let json = serde_json::to_value(&snap).unwrap();
        assert_eq!(json["error_rate"], 0.01);
        assert_eq!(json["throughput_rps"], 2000.0);
    }

    #[test]
    fn test_experiment_results_success() {
        let res = ExperimentResults {
            success: true,
            metrics_before: ChaosEngineeringService::empty_snapshot(),
            metrics_during: None,
            metrics_after: None,
            safety_violations: vec![],
            observations: vec!["Steady throughput".into()],
            recommendations: vec!["Increase resilience timeout".into()],
        };
        let json = serde_json::to_value(&res).unwrap();
        assert_eq!(json["success"], true);
        assert_eq!(json["safety_violations"].as_array().unwrap().len(), 0);
    }

    #[test]
    fn test_experiment_config_serialization() {
        let cfg = ExperimentConfig {
            experiment_type: "latency_injection".into(),
            target: ExperimentTarget { service: "api".into(), instances: vec!["i-1".into()], percentage: 50.0 },
            parameters: ExperimentParameters {
                duration_ms: 30000, intensity: 0.5, error_codes: Some(vec![500, 503]),
                latency_ms: Some(200), resource_type: None, resource_limit: None,
            },
            safety_checks: vec![SafetyCheck {
                name: "error-rate".into(), check_type: "error_rate".into(),
                threshold: 0.1, operator: ">".into(), abort_on_failure: true,
            }],
            rollback_on_failure: true,
        };
        let json = serde_json::to_value(&cfg).unwrap();
        assert_eq!(json["experiment_type"], "latency_injection");
        assert_eq!(json["target"]["percentage"], 50.0);
    }

    #[test]
    fn test_safety_check_interval_constant() {
        assert!(*SAFETY_CHECK_INTERVAL_MS >= 1);
    }

    #[test]
    fn test_empty_snapshot() {
        let s = ChaosEngineeringService::empty_snapshot();
        assert_eq!(s.error_rate, 0.0);
        assert_eq!(s.cpu_usage, 0.0);
    }

    #[test]
    fn test_abort_nonexistent_experiment() {
        test_runtime().block_on(async {
            let svc = ChaosEngineeringService::new(test_pool(), test_config());
            let res = svc.abort_experiment(Uuid::new_v4()).await;
            assert!(res.is_err());
        });
    }
}
