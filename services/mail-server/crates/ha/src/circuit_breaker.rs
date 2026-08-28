//! Circuit breaker pattern — CLOSED → OPEN → HALF_OPEN state machine.
//! Tracks per-circuit failure/success counts, enforces thresholds.

use chrono::Utc;
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{info, warn};

use crate::config::Config;
use crate::types::{CircuitConfig, CircuitState, CircuitStats};

/// Per-circuit runtime state.
#[derive(Debug, Clone)]
struct CircuitRuntime {
    config: CircuitConfig,
    state: CircuitState,
    failure_count: u64,
    success_count: u64,
    total_calls: u64,
    half_open_calls: u64,
    last_failure: Option<chrono::DateTime<Utc>>,
    last_success: Option<chrono::DateTime<Utc>>,
    state_changed_at: chrono::DateTime<Utc>,
}

impl CircuitRuntime {
    fn new(config: CircuitConfig) -> Self {
        Self {
            config,
            state: CircuitState::Closed,
            failure_count: 0,
            success_count: 0,
            total_calls: 0,
            half_open_calls: 0,
            last_failure: None,
            last_success: None,
            state_changed_at: Utc::now(),
        }
    }

    fn to_stats(&self) -> CircuitStats {
        let error_rate = if self.total_calls > 0 {
            self.failure_count as f64 / self.total_calls as f64
        } else {
            0.0
        };
        CircuitStats {
            name: self.config.name.clone(),
            state: self.state.to_string(),
            failure_count: self.failure_count,
            success_count: self.success_count,
            total_calls: self.total_calls,
            last_failure: self.last_failure,
            last_success: self.last_success,
            state_changed_at: self.state_changed_at,
            error_rate,
        }
    }
}

/// Default circuits created at startup.
const DEFAULT_CIRCUITS: &[(&str, u32, u32, u64)] = &[
    ("database", 5, 2, 30000),
    ("redis", 5, 2, 30000),
    ("external-api", 10, 3, 60000),
    ("email-sender", 5, 2, 30000),
    ("webhook-delivery", 8, 3, 45000),
];

/// CircuitBreakerService manages multiple named circuits.
pub struct CircuitBreakerService {
    circuits: Arc<RwLock<HashMap<String, CircuitRuntime>>>,
    #[expect(
        dead_code,
        reason = "config is retained for circuit policy inspection and future reload support"
    )]
    config: Arc<Config>,
}

impl CircuitBreakerService {
    pub fn new(config: Arc<Config>) -> Self {
        let mut map = HashMap::new();
        for &(name, fail_thresh, succ_thresh, timeout) in DEFAULT_CIRCUITS {
            map.insert(
                name.into(),
                CircuitRuntime::new(CircuitConfig {
                    name: name.into(),
                    failure_threshold: fail_thresh,
                    success_threshold: succ_thresh,
                    timeout_ms: timeout,
                    half_open_max_calls: 3,
                    enabled: config.circuit_breaker.enabled,
                }),
            );
        }
        Self {
            circuits: Arc::new(RwLock::new(map)),
            config,
        }
    }

    /// Check if a call to `circuit_name` is allowed.
    pub async fn allow_request(&self, circuit_name: &str) -> Result<bool, String> {
        let mut circuits = self.circuits.write().await;
        let circuit = circuits
            .get_mut(circuit_name)
            .ok_or_else(|| format!("Circuit not found: {circuit_name}"))?;

        if !circuit.config.enabled {
            return Ok(true);
        }

        match circuit.state {
            CircuitState::Closed => Ok(true),
            CircuitState::Open => {
                // Check if timeout has elapsed → transition to HalfOpen
                let elapsed = (Utc::now() - circuit.state_changed_at)
                    .num_milliseconds()
                    .max(0) as u64;
                if elapsed >= circuit.config.timeout_ms {
                    circuit.state = CircuitState::HalfOpen;
                    circuit.half_open_calls = 0;
                    circuit.success_count = 0;
                    circuit.failure_count = 0;
                    circuit.state_changed_at = Utc::now();
                    info!(circuit = circuit_name, "Circuit transitioned to half-open");
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
            CircuitState::HalfOpen => {
                if circuit.half_open_calls < circuit.config.half_open_max_calls as u64 {
                    circuit.half_open_calls += 1;
                    Ok(true)
                } else {
                    Ok(false)
                }
            }
        }
    }

    /// Report a successful call.
    ///
    /// Fix #15: in the CLOSED state each success RETIRES one prior
    /// failure (count-based decay, 1:1). Previously `failure_count` only
    /// ever grew in Closed — five lifetime errors (however long ago, with
    /// any number of healthy calls in between) tripped a healthy
    /// dependency. With the decay, `threshold` CONSECUTIVE failures (no
    /// interleaved success) are still required to open the circuit.
    /// Half-open recovery semantics are unchanged (a success_threshold
    /// run closes and zeroes the counter).
    pub async fn report_success(&self, circuit_name: &str) -> Result<(), String> {
        let mut circuits = self.circuits.write().await;
        let circuit = circuits
            .get_mut(circuit_name)
            .ok_or_else(|| format!("Circuit not found: {circuit_name}"))?;

        circuit.success_count += 1;
        circuit.total_calls += 1;
        circuit.last_success = Some(Utc::now());

        if circuit.state == CircuitState::HalfOpen
            && circuit.success_count >= circuit.config.success_threshold as u64
        {
            circuit.state = CircuitState::Closed;
            circuit.failure_count = 0;
            circuit.state_changed_at = Utc::now();
            info!(circuit = circuit_name, "Circuit closed after recovery");
            return Ok(());
        }

        // Fix #15: successes age out prior failures while Closed.
        if circuit.state == CircuitState::Closed {
            circuit.failure_count = circuit.failure_count.saturating_sub(1);
        }
        Ok(())
    }

    /// Report a failed call.
    pub async fn report_failure(&self, circuit_name: &str) -> Result<(), String> {
        let mut circuits = self.circuits.write().await;
        let circuit = circuits
            .get_mut(circuit_name)
            .ok_or_else(|| format!("Circuit not found: {circuit_name}"))?;

        circuit.failure_count += 1;
        circuit.total_calls += 1;
        circuit.last_failure = Some(Utc::now());

        match circuit.state {
            CircuitState::Closed => {
                if circuit.failure_count >= circuit.config.failure_threshold as u64 {
                    circuit.state = CircuitState::Open;
                    circuit.state_changed_at = Utc::now();
                    warn!(
                        circuit = circuit_name,
                        failures = circuit.failure_count,
                        "Circuit opened"
                    );
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open → back to open
                circuit.state = CircuitState::Open;
                circuit.state_changed_at = Utc::now();
                warn!(circuit = circuit_name, "Circuit re-opened from half-open");
            }
            _ => {}
        }
        Ok(())
    }

    /// Get stats for all circuits.
    pub async fn get_all_stats(&self) -> Vec<CircuitStats> {
        let circuits = self.circuits.read().await;
        circuits.values().map(|c| c.to_stats()).collect()
    }

    /// Get stats for a specific circuit.
    pub async fn get_stats(&self, circuit_name: &str) -> Option<CircuitStats> {
        let circuits = self.circuits.read().await;
        circuits.get(circuit_name).map(|c| c.to_stats())
    }

    /// Reset a circuit to closed state.
    pub async fn reset(&self, circuit_name: &str) -> Result<(), String> {
        let mut circuits = self.circuits.write().await;
        let circuit = circuits
            .get_mut(circuit_name)
            .ok_or_else(|| format!("Circuit not found: {circuit_name}"))?;

        circuit.state = CircuitState::Closed;
        circuit.failure_count = 0;
        circuit.success_count = 0;
        circuit.total_calls = 0;
        circuit.half_open_calls = 0;
        circuit.state_changed_at = Utc::now();

        info!(circuit = circuit_name, "Circuit reset");
        Ok(())
    }

    /// Add or update a circuit configuration.
    pub async fn configure(&self, config: CircuitConfig) -> Result<(), String> {
        let mut circuits = self.circuits.write().await;
        let name = config.name.clone();
        circuits.insert(name.clone(), CircuitRuntime::new(config));
        info!(circuit = name, "Circuit configured");
        Ok(())
    }

    /// Remove a circuit.
    pub async fn remove(&self, circuit_name: &str) -> Result<bool, String> {
        let mut circuits = self.circuits.write().await;
        Ok(circuits.remove(circuit_name).is_some())
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
    fn test_config() -> Arc<Config> {
        Arc::new(Config::from_env())
    }

    #[test]
    fn test_default_circuits_created() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config());
            let stats = svc.get_all_stats().await;
            assert_eq!(stats.len(), 5);
            let names: Vec<&str> = stats.iter().map(|s| s.name.as_str()).collect();
            assert!(names.contains(&"database"));
            assert!(names.contains(&"redis"));
        });
    }

    #[test]
    fn test_circuit_starts_closed() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config());
            let allowed = svc.allow_request("database").await.unwrap();
            assert!(allowed);
            let stats = svc.get_stats("database").await.unwrap();
            assert_eq!(stats.state, "closed");
        });
    }

    #[test]
    fn test_circuit_opens_after_threshold() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config());
            // database threshold is 5
            for _ in 0..5 {
                svc.report_failure("database").await.unwrap();
            }
            let stats = svc.get_stats("database").await.unwrap();
            assert_eq!(stats.state, "open");
            // Allow request should be false (timeout hasn't elapsed)
            let allowed = svc.allow_request("database").await.unwrap();
            assert!(!allowed);
        });
    }

    /// Fix #15 (fail-first): scattered failures must NOT accumulate into
    /// an open circuit — 4 failures + enough successes to retire them +
    /// 1 more failure stays CLOSED (the old code opened here: 5 lifetime
    /// failures tripped the breaker regardless of intervening successes).
    #[test]
    fn test_failures_decay_with_successes_in_closed_state() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config()); // threshold 5
            for _ in 0..4 {
                svc.report_failure("database").await.unwrap();
            }
            for _ in 0..20 {
                svc.report_success("database").await.unwrap();
            }
            // All four prior failures have been retired by successes.
            {
                let circuits = svc.circuits.read().await;
                assert_eq!(circuits.get("database").unwrap().failure_count, 0);
            }
            svc.report_failure("database").await.unwrap();
            let stats = svc.get_stats("database").await.unwrap();
            assert_eq!(
                stats.state, "closed",
                "4 retired failures + 1 fresh failure must not open the circuit"
            );
            assert_eq!(stats.failure_count, 1);
        });
    }

    /// Fix #15: the decay must not weaken protection against CLUSTERED
    /// failures — 5 failures with no interleaved success still open.
    #[test]
    fn test_clustered_failures_still_open_circuit() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config()); // threshold 5
                                                                 // Interleave successes so each failure is immediately retired…
            for _ in 0..4 {
                svc.report_failure("database").await.unwrap();
                svc.report_success("database").await.unwrap();
            }
            assert_eq!(svc.get_stats("database").await.unwrap().state, "closed");
            // …then 5 failures back-to-back (no success between them).
            for _ in 0..5 {
                svc.report_failure("database").await.unwrap();
            }
            assert_eq!(svc.get_stats("database").await.unwrap().state, "open");
        });
    }

    #[test]
    fn test_circuit_success_keeps_closed() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config());
            for _ in 0..10 {
                svc.report_success("database").await.unwrap();
            }
            let stats = svc.get_stats("database").await.unwrap();
            assert_eq!(stats.state, "closed");
            assert_eq!(stats.success_count, 10);
        });
    }

    #[test]
    fn test_circuit_half_open_recovery() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config());
            // Force into half-open
            {
                let mut circuits = svc.circuits.write().await;
                let c = circuits.get_mut("database").unwrap();
                c.state = CircuitState::HalfOpen;
                c.success_count = 0;
            }
            // Two successes should close it (threshold = 2)
            svc.report_success("database").await.unwrap();
            svc.report_success("database").await.unwrap();
            let stats = svc.get_stats("database").await.unwrap();
            assert_eq!(stats.state, "closed");
        });
    }

    #[test]
    fn test_circuit_half_open_failure_reopens() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config());
            {
                let mut circuits = svc.circuits.write().await;
                let c = circuits.get_mut("database").unwrap();
                c.state = CircuitState::HalfOpen;
            }
            svc.report_failure("database").await.unwrap();
            let stats = svc.get_stats("database").await.unwrap();
            assert_eq!(stats.state, "open");
        });
    }

    #[test]
    fn test_circuit_reset() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config());
            for _ in 0..5 {
                svc.report_failure("database").await.unwrap();
            }
            assert_eq!(svc.get_stats("database").await.unwrap().state, "open");
            svc.reset("database").await.unwrap();
            let stats = svc.get_stats("database").await.unwrap();
            assert_eq!(stats.state, "closed");
            assert_eq!(stats.failure_count, 0);
        });
    }

    #[test]
    fn test_unknown_circuit() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config());
            let res = svc.allow_request("nonexistent").await;
            assert!(res.is_err());
        });
    }

    #[test]
    fn test_circuit_configure() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config());
            svc.configure(CircuitConfig {
                name: "custom-circuit".into(),
                failure_threshold: 3,
                success_threshold: 1,
                timeout_ms: 10000,
                half_open_max_calls: 2,
                enabled: true,
            })
            .await
            .unwrap();
            let stats = svc.get_stats("custom-circuit").await;
            assert!(stats.is_some());
            assert_eq!(stats.unwrap().state, "closed");
        });
    }

    #[test]
    fn test_circuit_remove() {
        test_runtime().block_on(async {
            let svc = CircuitBreakerService::new(test_config());
            let removed = svc.remove("database").await.unwrap();
            assert!(removed);
            assert!(svc.get_stats("database").await.is_none());
            let removed2 = svc.remove("database").await.unwrap();
            assert!(!removed2);
        });
    }

    #[test]
    fn test_error_rate_calculation() {
        let rt = CircuitRuntime {
            config: CircuitConfig::default(),
            state: CircuitState::Closed,
            failure_count: 3,
            success_count: 7,
            total_calls: 10,
            half_open_calls: 0,
            last_failure: None,
            last_success: None,
            state_changed_at: Utc::now(),
        };
        let stats = rt.to_stats();
        assert!((stats.error_rate - 0.3).abs() < 0.001);
    }

    #[test]
    fn test_circuit_stats_serialization() {
        let stats = CircuitStats {
            name: "database".into(),
            state: "closed".into(),
            failure_count: 0,
            success_count: 100,
            total_calls: 100,
            last_failure: None,
            last_success: Some(Utc::now()),
            state_changed_at: Utc::now(),
            error_rate: 0.0,
        };
        let json = serde_json::to_value(&stats).unwrap();
        assert_eq!(json["name"], "database");
        assert_eq!(json["error_rate"], 0.0);
    }

    #[test]
    fn test_disabled_circuit_allows_all() {
        test_runtime().block_on(async {
            let mut cfg = Config::from_env();
            cfg.circuit_breaker.enabled = false;
            let svc = CircuitBreakerService::new(Arc::new(cfg));
            // Even after failures, disabled circuit allows requests
            for _ in 0..100 {
                svc.report_failure("database").await.unwrap();
            }
            let allowed = svc.allow_request("database").await.unwrap();
            assert!(allowed);
        });
    }
}
