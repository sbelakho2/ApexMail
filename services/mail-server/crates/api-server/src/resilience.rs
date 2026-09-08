//! Graceful degradation patterns — Circuit Breaker and Bulkhead.
//!
//! Protects upstream dependency calls (database, Redis, ClickHouse) from cascading
//! failures by failing fast when a dependency is unhealthy (circuit breaker) and
//! isolating failure domains with bounded concurrency (bulkhead).

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};
use tokio::sync::{OwnedSemaphorePermit, RwLock, Semaphore};
use tracing::{error, warn};

// ─── Circuit Breaker ─────────────────────────────────────────────

/// Configuration for a [`CircuitBreaker`].
#[derive(Debug, Clone, Copy)]
pub struct CircuitBreakerConfig {
    /// Number of consecutive failures before the circuit opens (e.g. 5).
    pub failure_threshold: u64,
    /// Number of consecutive successes in half-open state before closing (e.g. 2).
    pub success_threshold: u64,
    /// How long the circuit stays open before transitioning to half-open (e.g. 30s).
    pub open_duration: Duration,
    /// Maximum number of concurrent probe requests allowed in half-open state (e.g. 3).
    pub half_open_max_requests: u32,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            success_threshold: 2,
            open_duration: Duration::from_secs(30),
            half_open_max_requests: 3,
        }
    }
}

/// Current state of a [`CircuitBreaker`].
#[derive(Debug, Clone, Copy)]
pub enum CircuitState {
    /// Normal operation — requests are passed through.
    Closed,
    /// Failing fast — requests are rejected immediately.
    Open {
        /// Timestamp when the circuit was opened.
        opened_at: Instant,
    },
    /// Probing — a limited number of requests are allowed to test recovery.
    HalfOpen,
}

/// Error returned when a circuit breaker rejects a call.
#[derive(Debug, Clone, thiserror::Error)]
pub enum CircuitBreakerError<E: std::fmt::Display + std::fmt::Debug> {
    /// The circuit is open — the dependency is considered unhealthy.
    #[error("circuit breaker is open for {name}")]
    CircuitOpen {
        /// Human-readable name for the protected dependency.
        name: &'static str,
    },
    /// The underlying operation failed.
    #[error("{0}")]
    Inner(E),
}

impl<E: std::fmt::Display + std::fmt::Debug> CircuitBreakerError<E> {
    /// Returns `true` if this error is a circuit-open rejection (fast-fail).
    pub fn is_circuit_open(&self) -> bool {
        matches!(self, Self::CircuitOpen { .. })
    }
}

struct CircuitBreakerInner {
    state: RwLock<CircuitState>,
    failure_count: AtomicU64,
    success_count: AtomicU64,
    half_open_probes: AtomicU32,
    config: CircuitBreakerConfig,
    name: &'static str,
}

/// A circuit breaker that protects calls to an upstream dependency.
///
/// State machine:
/// - **Closed** → normal operation. Failures increment a counter; when ≥ `failure_threshold`, transitions to Open.
/// - **Open** → requests are fast-failed. After `open_duration`, transitions to HalfOpen on the next call.
/// - **HalfOpen** → limited probes allowed. Successes increment a counter; when ≥ `success_threshold`, transitions to Closed. Any failure transitions back to Open.
#[derive(Clone)]
pub struct CircuitBreaker {
    inner: Arc<CircuitBreakerInner>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration.
    pub fn new(config: CircuitBreakerConfig, name: &'static str) -> Self {
        Self {
            inner: Arc::new(CircuitBreakerInner {
                state: RwLock::new(CircuitState::Closed),
                failure_count: AtomicU64::new(0),
                success_count: AtomicU64::new(0),
                half_open_probes: AtomicU32::new(0),
                config,
                name,
            }),
        }
    }

    /// Returns the current circuit state (for metrics / logging).
    pub async fn state(&self) -> CircuitState {
        *self.inner.state.read().await
    }

    /// Record a successful call (resets failure counter in Closed state,
    /// increments success counter in HalfOpen state).
    async fn record_success(&self) {
        let state = self.inner.state.read().await;
        match *state {
            CircuitState::Closed => {
                // Success in closed state — reset failure count
                self.inner.failure_count.store(0, Ordering::Release);
            }
            CircuitState::HalfOpen => {
                let prev = self.inner.success_count.fetch_add(1, Ordering::AcqRel);
                // Check if we've reached the success threshold
                if prev + 1 >= self.inner.config.success_threshold {
                    drop(state); // release read lock before acquiring write lock
                    self.transition_to_closed().await;
                }
            }
            CircuitState::Open { .. } => {
                // Should not happen — call() gates on state before executing.
            }
        }
    }

    /// Record a failed call (increments failure counter; may trigger open).
    async fn record_failure(&self) {
        let state = self.inner.state.read().await;
        match *state {
            CircuitState::Closed => {
                let prev = self.inner.failure_count.fetch_add(1, Ordering::AcqRel);
                if prev + 1 >= self.inner.config.failure_threshold {
                    drop(state);
                    self.transition_to_open().await;
                }
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open → back to open
                drop(state);
                self.transition_to_open().await;
            }
            CircuitState::Open { .. } => {
                // Already open — nothing to do
            }
        }
    }

    async fn transition_to_open(&self) {
        let mut state = self.inner.state.write().await;
        // Double-check that no one else transitioned first
        if matches!(*state, CircuitState::Open { .. }) {
            return;
        }
        *state = CircuitState::Open {
            opened_at: Instant::now(),
        };
        self.inner.failure_count.store(0, Ordering::Release);
        self.inner.success_count.store(0, Ordering::Release);
        self.inner.half_open_probes.store(0, Ordering::Release);
        warn!(
            name = self.inner.name,
            "circuit breaker opened — dependency considered unhealthy"
        );
    }

    async fn transition_to_half_open(&self) {
        let mut state = self.inner.state.write().await;
        if !matches!(*state, CircuitState::Open { .. }) {
            return;
        }
        *state = CircuitState::HalfOpen;
        self.inner.failure_count.store(0, Ordering::Release);
        self.inner.success_count.store(0, Ordering::Release);
        self.inner.half_open_probes.store(0, Ordering::Release);
        warn!(
            name = self.inner.name,
            "circuit breaker half-open — allowing probe requests"
        );
    }

    async fn transition_to_closed(&self) {
        let mut state = self.inner.state.write().await;
        if !matches!(*state, CircuitState::HalfOpen) {
            return;
        }
        *state = CircuitState::Closed;
        self.inner.failure_count.store(0, Ordering::Release);
        self.inner.success_count.store(0, Ordering::Release);
        self.inner.half_open_probes.store(0, Ordering::Release);
        warn!(
            name = self.inner.name,
            "circuit breaker closed — dependency recovered"
        );
    }

    /// Execute the given async closure through the circuit breaker.
    ///
    /// If the circuit is **Open**, the call is rejected immediately with
    /// [`CircuitBreakerError::CircuitOpen`].
    ///
    /// If the circuit is **HalfOpen**, only `half_open_max_requests` concurrent
    /// probes are allowed — excess calls are rejected.
    ///
    /// If the circuit is **Closed**, the closure is executed and success/failure
    /// is recorded accordingly.
    pub async fn call<F, Fut, T, E>(&self, f: F) -> Result<T, CircuitBreakerError<E>>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
        E: std::fmt::Display + std::fmt::Debug,
    {
        let current_state = *self.inner.state.read().await;

        match current_state {
            CircuitState::Open { opened_at } => {
                if opened_at.elapsed() >= self.inner.config.open_duration {
                    self.transition_to_half_open().await;
                } else {
                    return Err(CircuitBreakerError::CircuitOpen {
                        name: self.inner.name,
                    });
                }
            }
            CircuitState::HalfOpen => {
                let probes = self.inner.half_open_probes.fetch_add(1, Ordering::AcqRel);
                if probes >= self.inner.config.half_open_max_requests {
                    self.inner.half_open_probes.fetch_sub(1, Ordering::AcqRel);
                    return Err(CircuitBreakerError::CircuitOpen {
                        name: self.inner.name,
                    });
                }
                // Permit acquired — will release after call completes
            }
            CircuitState::Closed => {
                // Proceed normally
            }
        }

        // Execute the wrapped call
        let result = f().await;

        // Record outcome and adjust state
        match &result {
            Ok(_) => self.record_success().await,
            Err(_) => self.record_failure().await,
        }

        // Release half-open probe slot if applicable
        if matches!(current_state, CircuitState::HalfOpen) {
            self.inner.half_open_probes.fetch_sub(1, Ordering::AcqRel);
        }

        result.map_err(|e| CircuitBreakerError::Inner(e))
    }
}

// ─── Bulkhead ────────────────────────────────────────────────────

/// Errors that can occur when acquiring a bulkhead permit.
#[derive(Debug, Clone, thiserror::Error)]
pub enum BulkheadError {
    /// The semaphore could not be acquired within `max_wait`.
    #[error("bulkhead {name} timed out after {max_wait:?}")]
    Timeout {
        /// Bulkhead name.
        name: &'static str,
        /// Maximum wait duration.
        max_wait: Duration,
    },
    /// The semaphore is closed (should not happen under normal operation).
    #[error("bulkhead {name} semaphore closed")]
    Closed {
        /// Bulkhead name.
        name: &'static str,
    },
    /// The wrapped closure failed. The inner error is not `Send`-safe to
    /// propagate generically, so it is dropped and logged instead of
    /// panicking the process.
    #[error("bulkhead {name} inner operation failed")]
    Inner {
        /// Bulkhead name.
        name: &'static str,
    },
}

/// A guard that releases a bulkhead semaphore permit when dropped.
#[derive(Debug)]
pub struct BulkheadGuard {
    #[allow(dead_code)]
    permit: Option<OwnedSemaphorePermit>,
    #[allow(dead_code)]
    name: &'static str,
}

impl Drop for BulkheadGuard {
    fn drop(&mut self) {
        // The permit is automatically returned to the semaphore when dropped.
    }
}

/// A semaphore-based isolation boundary that limits concurrent calls to an
/// upstream dependency.
pub struct Bulkhead {
    semaphore: Arc<Semaphore>,
    max_wait: Duration,
    name: &'static str,
}

impl Bulkhead {
    /// Create a new bulkhead that allows up to `max_concurrent` in-flight calls,
    /// with a maximum wait time of `max_wait` for acquiring a permit.
    pub fn new(max_concurrent: usize, max_wait: Duration, name: &'static str) -> Self {
        Self {
            semaphore: Arc::new(Semaphore::new(max_concurrent)),
            max_wait,
            name,
        }
    }

    /// Acquire a permit from the bulkhead semaphore with a timeout.
    ///
    /// Returns a [`BulkheadGuard`] that releases the permit on drop, or a
    /// [`BulkheadError`] if the permit could not be acquired in time.
    pub async fn acquire(&self) -> Result<BulkheadGuard, BulkheadError> {
        let permit = tokio::time::timeout(self.max_wait, self.semaphore.clone().acquire_owned())
            .await
            .map_err(|_| {
                warn!(
                    name = self.name,
                    max_wait_ms = self.max_wait.as_millis() as u64,
                    "bulkhead permit acquisition timed out"
                );
                BulkheadError::Timeout {
                    name: self.name,
                    max_wait: self.max_wait,
                }
            })?
            .map_err(|_| BulkheadError::Closed { name: self.name })?;

        Ok(BulkheadGuard {
            permit: Some(permit),
            name: self.name,
        })
    }

    /// Acquire a permit and execute the given async closure within the bulkhead.
    ///
    /// If the permit cannot be acquired within `max_wait`, returns
    /// [`BulkheadError::Timeout`].
    pub async fn call<F, Fut, T, E>(&self, f: F) -> Result<T, BulkheadError>
    where
        F: FnOnce() -> Fut,
        Fut: std::future::Future<Output = Result<T, E>>,
    {
        let _guard = self.acquire().await?;
        match f().await {
            Ok(value) => Ok(value),
            Err(_error) => {
                error!(
                    name = self.name,
                    error_type = std::any::type_name::<E>(),
                    "bulkhead inner operation failed"
                );
                Err(BulkheadError::Inner { name: self.name })
            }
        }
    }
}

// ─── ResilientClient ─────────────────────────────────────────────

/// A high-level wrapper combining per-dependency circuit breakers and
/// bulkheads for the three main upstream services: Postgres, Redis, and
/// ClickHouse.
pub struct ResilientClient {
    /// Circuit breaker for the primary database.
    pub db: CircuitBreaker,
    /// Circuit breaker for Redis.
    pub redis: CircuitBreaker,
    /// Circuit breaker for ClickHouse.
    pub clickhouse: CircuitBreaker,
    /// Bulkhead for database queries.
    pub db_bulkhead: Bulkhead,
    /// Bulkhead for Redis commands.
    pub redis_bulkhead: Bulkhead,
}

impl ResilientClient {
    /// Create a new `ResilientClient` from the application config, using
    /// sensible defaults for thresholds and timeouts.
    pub fn new_from_config(_config: &crate::config::Config) -> Self {
        Self {
            // DB circuit breaker: 5 failures, 30s open, 2 successes to close
            db: CircuitBreaker::new(
                CircuitBreakerConfig {
                    failure_threshold: 5,
                    open_duration: Duration::from_secs(30),
                    success_threshold: 2,
                    half_open_max_requests: 3,
                },
                "db",
            ),
            // Redis circuit breaker: 3 failures, 15s open, 2 successes to close
            redis: CircuitBreaker::new(
                CircuitBreakerConfig {
                    failure_threshold: 3,
                    open_duration: Duration::from_secs(15),
                    success_threshold: 2,
                    half_open_max_requests: 3,
                },
                "redis",
            ),
            // ClickHouse circuit breaker: 3 failures, 30s open, 2 successes to close
            clickhouse: CircuitBreaker::new(
                CircuitBreakerConfig {
                    failure_threshold: 3,
                    open_duration: Duration::from_secs(30),
                    success_threshold: 2,
                    half_open_max_requests: 3,
                },
                "clickhouse",
            ),
            // DB bulkhead: 32 concurrent, 5s wait
            db_bulkhead: Bulkhead::new(32, Duration::from_secs(5), "db"),
            // Redis bulkhead: 64 concurrent, 2s wait
            redis_bulkhead: Bulkhead::new(64, Duration::from_secs(2), "redis"),
        }
    }
}

// ─── Tests ───────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_circuit_breaker_closed_allows_requests() {
        let cb = CircuitBreaker::new(
            CircuitBreakerConfig {
                failure_threshold: 5,
                success_threshold: 2,
                open_duration: Duration::from_secs(30),
                half_open_max_requests: 3,
            },
            "test",
        );

        // Initially closed
        assert!(matches!(cb.state().await, CircuitState::Closed));

        // Successful calls go through
        let result: Result<i32, CircuitBreakerError<std::io::Error>> =
            cb.call(|| async { Ok::<_, std::io::Error>(42) }).await;
        assert_eq!(result.unwrap(), 42);

        // Still closed after success
        assert!(matches!(cb.state().await, CircuitState::Closed));
    }

    #[tokio::test]
    async fn test_circuit_breaker_opens_after_threshold() {
        let cb = CircuitBreaker::new(
            CircuitBreakerConfig {
                failure_threshold: 3,
                success_threshold: 2,
                open_duration: Duration::from_secs(30),
                half_open_max_requests: 3,
            },
            "test",
        );

        // Fail enough times to open the circuit
        for _ in 0..3 {
            let result: Result<i32, CircuitBreakerError<std::io::Error>> = cb
                .call(|| async { Err::<i32, _>(std::io::Error::other("fail")) })
                .await;
            assert!(result.is_err());
            assert!(!result.as_ref().unwrap_err().is_circuit_open());
        }

        // Circuit should now be open
        assert!(matches!(cb.state().await, CircuitState::Open { .. }));

        // Next call should fast-fail with CircuitOpen
        let result: Result<i32, CircuitBreakerError<std::io::Error>> =
            cb.call(|| async { Ok::<_, std::io::Error>(99) }).await;
        assert!(result.is_err());
        assert!(result.unwrap_err().is_circuit_open());
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_allows_probes() {
        let cb = CircuitBreaker::new(
            CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 2,
                open_duration: Duration::from_millis(50),
                half_open_max_requests: 3,
            },
            "test",
        );

        // Trigger open
        let _: Result<i32, CircuitBreakerError<std::io::Error>> = cb
            .call(|| async { Err::<i32, _>(std::io::Error::other("fail")) })
            .await;

        assert!(matches!(cb.state().await, CircuitState::Open { .. }));

        // Wait for open_duration to elapse
        tokio::time::sleep(Duration::from_millis(100)).await;

        // Should transition to half-open on next call
        let result: Result<i32, CircuitBreakerError<std::io::Error>> =
            cb.call(|| async { Ok::<_, std::io::Error>(42) }).await;
        assert_eq!(result.unwrap(), 42);
        assert!(matches!(cb.state().await, CircuitState::HalfOpen));

        // One more success should close the circuit (success_threshold = 2)
        let result: Result<i32, CircuitBreakerError<std::io::Error>> =
            cb.call(|| async { Ok::<_, std::io::Error>(43) }).await;
        assert_eq!(result.unwrap(), 43);
        assert!(matches!(cb.state().await, CircuitState::Closed));
    }

    #[tokio::test]
    async fn test_circuit_breaker_half_open_failure_goes_back_to_open() {
        let cb = CircuitBreaker::new(
            CircuitBreakerConfig {
                failure_threshold: 1,
                success_threshold: 2,
                open_duration: Duration::from_millis(50),
                half_open_max_requests: 3,
            },
            "test",
        );

        // Trigger open
        let _: Result<i32, CircuitBreakerError<std::io::Error>> = cb
            .call(|| async { Err::<i32, _>(std::io::Error::other("fail")) })
            .await;

        // Wait for open_duration
        tokio::time::sleep(Duration::from_millis(100)).await;

        // First call transitions to half-open — make it fail
        let result: Result<i32, CircuitBreakerError<std::io::Error>> = cb
            .call(|| async { Err::<i32, _>(std::io::Error::other("fail")) })
            .await;
        assert!(result.is_err());
        assert!(!result.as_ref().unwrap_err().is_circuit_open()); // inner error, not circuit open

        // Should be back to open
        assert!(matches!(cb.state().await, CircuitState::Open { .. }));
    }

    #[tokio::test]
    async fn test_bulkhead_limits_concurrency() {
        let bulkhead = Bulkhead::new(2, Duration::from_secs(5), "test");

        // Acquire both permits so the spawned task cannot get one
        let guard1 = bulkhead.acquire().await.unwrap();
        let guard2 = bulkhead.acquire().await.unwrap();

        let handle = tokio::spawn(async move {
            // This should time out because all permits are taken
            let result = tokio::time::timeout(Duration::from_millis(200), bulkhead.acquire()).await;
            // Expect outer timeout (Err(_)) — the inner acquire could not
            // proceed because both permits remain held for 500ms.
            assert!(result.is_err(), "expected timeout, got {result:?}");
        });

        // Hold both permits for 500ms — well past the 200ms timeout
        tokio::time::sleep(Duration::from_millis(500)).await;

        // Now release the permits (the spawned task already timed out)
        drop(guard1);
        drop(guard2);

        handle.await.unwrap();
    }

    #[tokio::test]
    async fn test_bulkhead_times_out() {
        let bulkhead = Bulkhead::new(1, Duration::from_millis(50), "test");

        // Take the only permit
        let _guard = bulkhead.acquire().await.unwrap();

        // Second acquisition should time out
        let result = bulkhead.acquire().await;
        assert!(result.is_err());
        match result.unwrap_err() {
            BulkheadError::Timeout { name, .. } => {
                assert_eq!(name, "test");
            }
            other => panic!("expected Timeout, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_bulkhead_call_success() {
        let bulkhead = Bulkhead::new(1, Duration::from_secs(5), "test");

        let result: Result<i32, BulkheadError> = bulkhead.call(|| async { Ok::<_, ()>(42) }).await;
        assert_eq!(result.unwrap(), 42);
    }

    #[tokio::test]
    async fn test_resilient_client_default_configs() {
        use crate::config::{Config, Environment};
        use std::time::Duration;

        let config = Config {
            port: 3000,
            ai_service_base_url: String::new(),
            host: "0.0.0.0".into(),
            base_url: "http://localhost:3000".into(),
            environment: Environment::Development,
            public_rate_limit_enabled: false,
            db_host: "localhost".into(),
            db_port: 5432,
            db_name: "apexmail".into(),
            db_user: "apexmail".into(),
            db_password: "password".into(),
            db_max_connections: 20,
            api_replica_count: 1,
            db_cluster_connection_budget: None,
            expected_replica_count: 3,
            statement_cache_capacity: 500,
            query_timeout_seconds: 30,
            database_replica_url: None,
            redis_host: "localhost".into(),
            redis_port: 6379,
            redis_password: None,
            redis_db: 0,
            redis_pool_max_size: 40,
            jwt_private_key_pem: "BEGIN TEST".into(),
            jwt_public_key_pem: "BEGIN TEST".into(),
            jwt_previous_public_keys_pem: vec![],
            jwt_expiry: Duration::from_secs(86400),
            api_key_hash_secret: "test-api-key-secret-12345678901234567890".into(),
            rate_limit_window_ms: 60000,
            rate_limit_max_requests: 1000,
            max_inflight_requests: 80,
            cors_origins: vec!["*".into()],
            trusted_proxies: vec![],
            ui_web_hosts: vec!["app.apexmail.ee".into(), "127.0.0.1".into()],
            ui_control_plane_hosts: vec!["admin.apexmail.ee".into(), "localhost".into()],
            ui_marketing_hosts: vec!["apexmail.ee".into()],
            ui_marketing_surface: "marketing-zola".into(),
            ui_default_surface: Some("web".into()),
            webhook_signing_secret: "test-webhook-signing-secret-1234567890".into(),
            webhook_timeout_ms: 5000,
            webhook_max_retries: 10,
            idempotency_ttl_seconds: 86400,
            aws_region: "us-east-1".into(),
            ses_ip_pool_prefix: "apexmail".into(),
            ses_default_warmup_days: 14,
            ses_configuration_set: None,
            google_client_id: None,
            google_client_secret: None,
            github_client_id: None,
            github_client_secret: None,
            oauth_redirect_base_url: "http://localhost:3000".into(),
            session_secret: "test-session-secret-1234567890ab".into(),
            impersonation_secret: "test-impersonation-secret-12345".into(),
            csrf_secret: "test-csrf-secret-1234567890abcd".into(),
            control_plane_api_key: None,
            sales_autopilot_base_url: "http://localhost:3010".into(),
            internal_service_token: None,
            cp_auth: Default::default(),
            tracking_secret_key: "test-tracking-secret-123456789012".into(),
            billing_company_iban: "EE381010220123456789".into(),
            billing_company_phone: "+3721234567".into(),
            metrics_port: 9090,
            grader_enabled: false,
            grader_rate_limit: 10,
            grader_rate_window_seconds: 60,
            grader_cache_ttl_seconds: 300,
            grader_max_body_size: 1048576,
            placement_enabled: false,
            placement_polling_interval_secs: 60,
            placement_max_polling_attempts: 10,
            placement_max_seeds_per_test: 50,
            placement_max_tests_per_hour: 5,
            placement_imap_timeout_secs: 30,
            placement_encrypt_passwords: true,
            placement_encryption_secret: "test-placement-encryption-secret".into(),
            kiwi_enabled: false,
            kiwi_secret_key: "dev".into(),
            waf_enabled: false,
            waf_enforce: false,
            kiwi_algorithm: kiwicaptcha::PoWAlgorithm::Sha256,
            kiwi_argon_m_kib: 0,
            kiwi_argon2_difficulty_bits: 8,
            kiwi_argon_t: 2,
            kiwi_argon_p: 1,
            kiwi_difficulty_bits: 16,
            kiwi_challenge_ttl_secs: 120,
            kiwi_min_duration_ms: None,
            kiwi_enforce_telemetry: true,
            kiwi_argon2_max_concurrent: 2,
            kiwi_auto_tune: false,
            kiwi_auto_tune_min_bits: 10,
            kiwi_auto_tune_max_bits: 20,
            http_client_timeout_secs: 30,
            internal_tls_enabled: false,
            internal_tls_ca_cert_path: None,
            internal_tls_client_cert_path: None,
            internal_tls_client_key_path: None,
        };

        let client = ResilientClient::new_from_config(&config);
        assert!(matches!(client.db.state().await, CircuitState::Closed));
        assert!(matches!(client.redis.state().await, CircuitState::Closed));
        assert!(matches!(
            client.clickhouse.state().await,
            CircuitState::Closed
        ));
    }
}
