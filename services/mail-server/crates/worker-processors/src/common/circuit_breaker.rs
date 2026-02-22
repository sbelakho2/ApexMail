//! Circuit breaker implementation for external service resilience.

use parking_lot::RwLock;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// Circuit breaker state.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CircuitState {
    /// Circuit is closed, requests flow normally.
    Closed,
    /// Circuit is open, requests are rejected.
    Open,
    /// Circuit is half-open, testing if the service has recovered.
    HalfOpen,
}

/// Circuit breaker configuration.
#[derive(Debug, Clone)]
pub struct CircuitBreakerConfig {
    /// Number of failures before opening the circuit.
    pub failure_threshold: u32,
    /// Duration to keep the circuit open before transitioning to half-open.
    pub open_duration: Duration,
    /// Number of successes in half-open state before closing the circuit.
    pub success_threshold: u32,
    /// Rolling window for failure counting.
    pub window_duration: Duration,
}

impl Default for CircuitBreakerConfig {
    fn default() -> Self {
        Self {
            failure_threshold: 5,
            open_duration: Duration::from_secs(30),
            success_threshold: 3,
            window_duration: Duration::from_secs(60),
        }
    }
}

/// Circuit breaker for protecting against cascading failures.
pub struct CircuitBreaker {
    config: CircuitBreakerConfig,
    state: RwLock<CircuitState>,
    failure_count: AtomicU64,
    success_count: AtomicU64,
    last_failure_time: RwLock<Option<Instant>>,
    opened_at: RwLock<Option<Instant>>,
}

impl CircuitBreaker {
    /// Create a new circuit breaker with the given configuration.
    pub fn new(config: CircuitBreakerConfig) -> Self {
        Self {
            config,
            state: RwLock::new(CircuitState::Closed),
            failure_count: AtomicU64::new(0),
            success_count: AtomicU64::new(0),
            last_failure_time: RwLock::new(None),
            opened_at: RwLock::new(None),
        }
    }

    /// Check if a request is allowed through the circuit.
    pub fn is_allowed(&self) -> bool {
        let state = *self.state.read();
        match state {
            CircuitState::Closed => true,
            CircuitState::Open => {
                // Check if we should transition to half-open
                if let Some(opened_at) = *self.opened_at.read() {
                    if opened_at.elapsed() >= self.config.open_duration {
                        *self.state.write() = CircuitState::HalfOpen;
                        self.success_count.store(0, Ordering::SeqCst);
                        return true;
                    }
                }
                false
            }
            CircuitState::HalfOpen => true,
        }
    }

    /// Record a successful operation.
    pub fn record_success(&self) {
        let state = *self.state.read();
        match state {
            CircuitState::Closed => {
                // Reset failure count on success
                self.failure_count.store(0, Ordering::SeqCst);
            }
            CircuitState::HalfOpen => {
                let count = self.success_count.fetch_add(1, Ordering::SeqCst) + 1;
                if count >= self.config.success_threshold as u64 {
                    *self.state.write() = CircuitState::Closed;
                    self.failure_count.store(0, Ordering::SeqCst);
                    self.success_count.store(0, Ordering::SeqCst);
                    *self.opened_at.write() = None;
                }
            }
            CircuitState::Open => {
                // Shouldn't happen, but reset if it does
            }
        }
    }

    /// Record a failed operation.
    pub fn record_failure(&self) {
        let state = *self.state.read();
        match state {
            CircuitState::Closed => {
                // Check if previous failures are within the window
                let now = Instant::now();
                let should_reset = if let Some(last) = *self.last_failure_time.read() {
                    now.duration_since(last) > self.config.window_duration
                } else {
                    true
                };

                let count = if should_reset {
                    self.failure_count.store(1, Ordering::SeqCst);
                    1
                } else {
                    self.failure_count.fetch_add(1, Ordering::SeqCst) + 1
                };

                if count >= self.config.failure_threshold as u64 {
                    *self.state.write() = CircuitState::Open;
                    *self.opened_at.write() = Some(now);
                }

                *self.last_failure_time.write() = Some(now);
            }
            CircuitState::HalfOpen => {
                // Any failure in half-open reopens the circuit
                *self.state.write() = CircuitState::Open;
                *self.opened_at.write() = Some(Instant::now());
                self.success_count.store(0, Ordering::SeqCst);
            }
            CircuitState::Open => {
                // Already open, update timestamp
                *self.opened_at.write() = Some(Instant::now());
            }
        }
    }

    /// Get the current circuit state.
    pub fn state(&self) -> CircuitState {
        *self.state.read()
    }

    /// Reset the circuit breaker to closed state.
    pub fn reset(&self) {
        *self.state.write() = CircuitState::Closed;
        self.failure_count.store(0, Ordering::SeqCst);
        self.success_count.store(0, Ordering::SeqCst);
        *self.last_failure_time.write() = None;
        *self.opened_at.write() = None;
    }
}

impl Default for CircuitBreaker {
    fn default() -> Self {
        Self::new(CircuitBreakerConfig::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_circuit_opens_after_threshold() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 3,
            ..Default::default()
        });

        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::Closed);

        cb.record_failure();
        cb.record_failure();
        assert!(cb.is_allowed());

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);
        assert!(!cb.is_allowed());
    }

    #[test]
    fn test_circuit_closes_after_successes() {
        let cb = CircuitBreaker::new(CircuitBreakerConfig {
            failure_threshold: 1,
            success_threshold: 2,
            open_duration: Duration::from_millis(10),
            ..Default::default()
        });

        cb.record_failure();
        assert_eq!(cb.state(), CircuitState::Open);

        // Wait for open duration
        std::thread::sleep(Duration::from_millis(15));

        assert!(cb.is_allowed());
        assert_eq!(cb.state(), CircuitState::HalfOpen);

        cb.record_success();
        cb.record_success();
        assert_eq!(cb.state(), CircuitState::Closed);
    }
}
