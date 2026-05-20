//! Backpressure and load shedding mechanism for worker processors.
//!
//! SCALE-H-04: Uses a [`tokio::sync::Semaphore`] to bound in-flight work and
//! provides load-shedding (rejection) when the queue backlog exceeds a
//! configurable threshold. This prevents resource exhaustion during traffic
//! spikes and gives upstream clients (load balancers, queues) early feedback
//! so they can retry elsewhere or apply their own backoff.

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Duration;

use tokio::sync::{Semaphore, SemaphorePermit};

/// Configuration for backpressure / load shedding.
#[derive(Debug, Clone)]
pub struct BackpressureConfig {
    /// Maximum number of in-flight (concurrent) jobs.
    pub max_concurrency: usize,
    /// Soft limit for the observed backlog depth. When the backlog (derived
    /// from queue depth metrics) exceeds this, the worker starts shedding load
    /// by rejecting new polls early.
    pub max_backlog: u64,
    /// Cooldown duration once load shedding has been triggered. During cooldown
    /// the worker will skip polling and let the backlog drain.
    pub cooldown: Duration,
}

impl Default for BackpressureConfig {
    fn default() -> Self {
        Self {
            max_concurrency: 20,
            max_backlog: 10_000,
            cooldown: Duration::from_secs(5),
        }
    }
}

/// Runtime state for the backpressure mechanism.
///
/// Each processor should hold one `Arc<Backpressure>` and call
/// [`acquire`](Self::acquire) before starting work on a job. The returned
/// [`SemaphorePermit`] automatically releases capacity when dropped.
pub struct Backpressure {
    /// Semaphore that bounds concurrent in-flight work.
    semaphore: Semaphore,
    /// Maximum concurrency (for metrics / reporting).
    max_concurrency: usize,
    /// Configured soft backlog limit.
    max_backlog: u64,
    /// Cooldown duration.
    cooldown: Duration,
    /// Observed backlog depth (set externally from queue size).
    observed_backlog: AtomicU64,
    /// Timestamp (millis) until which the worker should pause.
    cooldown_until: AtomicU64,
    /// Total jobs rejected due to load shedding (counter).
    total_rejected: AtomicU64,
}

impl Backpressure {
    /// Create a new backpressure controller from the given config.
    pub fn new(config: BackpressureConfig) -> Self {
        Self {
            semaphore: Semaphore::new(config.max_concurrency),
            max_concurrency: config.max_concurrency,
            max_backlog: config.max_backlog,
            cooldown: config.cooldown,
            observed_backlog: AtomicU64::new(0),
            cooldown_until: AtomicU64::new(0),
            total_rejected: AtomicU64::new(0),
        }
    }

    /// Try to acquire a permit for processing a job.
    ///
    /// Returns `None` if the system is overloaded (load shedding active) or
    /// the semaphore has no capacity. The caller should skip processing and
    /// back off when this returns `None`.
    pub async fn acquire(&self) -> Option<SemaphorePermit<'_>> {
        // 1. Check load shedding cooldown
        if self.is_shedding() {
            self.total_rejected.fetch_add(1, Ordering::SeqCst);
            return None;
        }

        // 2. Try to acquire semaphore permit (non-blocking first)
        match self.semaphore.try_acquire() {
            Ok(permit) => Some(permit),
            Err(_) => {
                // All permits are taken — fall through to blocking acquire
                // with a short timeout to avoid unbounded waiting.
                match tokio::time::timeout(Duration::from_millis(500), self.semaphore.acquire()).await
                {
                    Ok(Ok(permit)) => Some(permit),
                    _ => {
                        // Timeout or closed semaphore — treat as overloaded
                        self.total_rejected.fetch_add(1, Ordering::SeqCst);
                        None
                    }
                }
            }
        }
    }

    /// Update the observed backlog (queue depth). This is called by the
    /// processor after each poll to inform the load-shedding decision.
    pub fn observe_backlog(&self, depth: u64) {
        self.observed_backlog.store(depth, Ordering::SeqCst);

        // Trigger cooldown if backlog exceeds threshold
        if depth > self.max_backlog && !self.is_shedding() {
            let deadline = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap_or_default()
                .as_millis() as u64
                + self.cooldown.as_millis() as u64;
            self.cooldown_until.store(deadline, Ordering::SeqCst);
        }
    }

    /// Returns `true` if the worker should pause due to load shedding.
    pub fn is_shedding(&self) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_millis() as u64;
        let until = self.cooldown_until.load(Ordering::SeqCst);
        now < until
    }

    // ── Metrics ─────────────────────────────────────────────────

    /// Current number of in-flight jobs (derived from semaphore capacity).
    pub fn in_flight(&self) -> usize {
        self.max_concurrency.saturating_sub(self.semaphore.available_permits())
    }

    /// Available capacity (permits remaining).
    pub fn available(&self) -> usize {
        self.semaphore.available_permits()
    }

    /// Maximum concurrency.
    pub fn max_concurrency(&self) -> usize {
        self.max_concurrency
    }

    /// Observed backlog depth.
    pub fn backlog(&self) -> u64 {
        self.observed_backlog.load(Ordering::SeqCst)
    }

    /// Total jobs rejected due to load shedding.
    pub fn total_rejected(&self) -> u64 {
        self.total_rejected.load(Ordering::SeqCst)
    }

    /// Utilization ratio (0.0 – 1.0).
    pub fn utilization(&self) -> f64 {
        let in_flight = self.in_flight() as f64;
        let max = self.max_concurrency as f64;
        if max > 0.0 {
            (in_flight / max).clamp(0.0, 1.0)
        } else {
            0.0
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Arc;

    #[test]
    fn test_backpressure_default_config() {
        let config = BackpressureConfig::default();
        assert_eq!(config.max_concurrency, 20);
        assert_eq!(config.max_backlog, 10_000);
    }

    #[test]
    fn test_backpressure_initial_state() {
        let bp = Backpressure::new(BackpressureConfig::default());
        assert_eq!(bp.available(), 20);
        assert_eq!(bp.in_flight(), 0);
        assert_eq!(bp.utilization(), 0.0);
        assert!(!bp.is_shedding());
    }

    #[tokio::test]
    async fn test_backpressure_acquire_release() {
        let bp = Arc::new(Backpressure::new(BackpressureConfig::default()));
        let permit = bp.acquire().await;
        assert!(permit.is_some());
        assert_eq!(bp.in_flight(), 1);
        assert_eq!(bp.available(), 19);

        drop(permit);
        // Semaphore permit release happens on drop — in_flight is derived
        // from semaphore capacity, so it reflects the release automatically.
        assert_eq!(bp.in_flight(), 0);
        assert_eq!(bp.available(), 20);
    }

    #[tokio::test]
    async fn test_backpressure_exhaustion() {
        let config = BackpressureConfig {
            max_concurrency: 2,
            max_backlog: 100,
            cooldown: Duration::from_secs(60),
        };
        let bp = Arc::new(Backpressure::new(config));

        // Acquire both permits
        let p1 = bp.acquire().await.unwrap();
        let p2 = bp.acquire().await.unwrap();
        assert_eq!(bp.available(), 0);

        // Third acquire should fail (timeout is 500ms, so it'll be None)
        let p3 = bp.acquire().await;
        assert!(p3.is_none());

        drop(p1);
        drop(p2);
    }

    #[test]
    fn test_backpressure_load_shedding() {
        let config = BackpressureConfig {
            max_concurrency: 10,
            max_backlog: 50,
            cooldown: Duration::from_millis(100),
        };
        let bp = Backpressure::new(config);

        assert!(!bp.is_shedding());

        // Exceed backlog threshold
        bp.observe_backlog(100);
        assert!(bp.is_shedding());

        // Wait for cooldown to expire
        std::thread::sleep(Duration::from_millis(150));
        assert!(!bp.is_shedding());
    }
}
