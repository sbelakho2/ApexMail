//! In-process inference rate governor.
//!
//! `AiConfig::inference_rate_limit` / `inference_rate_limit_window_secs`
//! were parsed but never enforced. This module implements a sliding-window
//! governor keyed per tenant/user (or any caller-supplied identity), backed
//! by a capped sharded map so unauthenticated key spam cannot grow memory
//! without bound. It is deliberately in-process: the AI service is
//! single-instance per deployment and the control plane remains the outer
//! authorization boundary.
//!
//! Eviction note: dashmap 5.x `iter()` swaps entire shards out of the map,
//! so it must not be used to pick eviction victims. A bounded FIFO of
//! recently inserted keys is used instead — every eviction is O(1).

use std::collections::VecDeque;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use parking_lot::Mutex;

/// Upper bound on tracked identities.
pub const MAX_TRACKED_KEYS: usize = 10_000;

/// How many stale ring candidates one eviction may inspect before giving up
/// (keys can be absent from the map if their window already pruned them).
const MAX_EVICTION_PROBES: usize = 64;

#[derive(Debug)]
pub struct RateGovernor {
    limit: usize,
    window: Duration,
    max_keys: usize,
    events: DashMap<String, Mutex<VecDeque<Instant>>>,
    /// Bounded FIFO of recently inserted keys (insertion order), used to
    /// find eviction victims in O(1).
    insertion_ring: Mutex<VecDeque<String>>,
}

impl RateGovernor {
    pub fn new(limit: usize, window: Duration) -> Self {
        Self::with_caps(limit, window, MAX_TRACKED_KEYS)
    }

    fn with_caps(limit: usize, window: Duration, max_keys: usize) -> Self {
        Self {
            limit: limit.max(1),
            window: window.max(Duration::from_millis(1)),
            max_keys: max_keys.max(1),
            events: DashMap::new(),
            insertion_ring: Mutex::new(VecDeque::new()),
        }
    }

    /// The configured request limit per window.
    pub fn limit(&self) -> usize {
        self.limit
    }

    /// The configured sliding-window length.
    pub fn window(&self) -> Duration {
        self.window
    }

    /// Record an event for `key` if the caller is still within the sliding
    /// window budget. Returns `true` when the request is allowed.
    pub fn allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window);

        if self.events.len() >= self.max_keys && !self.events.contains_key(key) {
            self.evict_one();
        }

        let entry = self
            .events
            .entry(key.to_string())
            .or_insert_with(|| Mutex::new(VecDeque::with_capacity(self.limit + 1)));
        let mut queue = entry.lock();

        // Drop events that slid out of the window.
        while let Some(front) = queue.front() {
            match cutoff {
                Some(c) if *front <= c => {
                    queue.pop_front();
                }
                // Clock moved backwards: keep the event to stay conservative.
                _ => break,
            }
        }

        if queue.len() >= self.limit {
            return false;
        }
        queue.push_back(now);

        // Track insertion order for O(1) eviction, keeping the ring bounded
        // even when keys are re-allowed many times.
        let mut ring = self.insertion_ring.lock();
        ring.push_back(key.to_string());
        while ring.len() > self.max_keys.saturating_mul(2) {
            ring.pop_front();
        }

        true
    }

    /// Peek without recording: is `key` currently within budget?
    pub fn would_allow(&self, key: &str) -> bool {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.window);
        match self.events.get(key) {
            Some(queue) => {
                let queue = queue.lock();
                let live = queue
                    .iter()
                    .filter(|t| cutoff.is_none_or(|c| **t > c))
                    .count();
                live < self.limit
            }
            None => true,
        }
    }

    /// Remove one tracked identity to bound memory. O(1) amortized: pops a
    /// key from the insertion ring and removes it if still present.
    fn evict_one(&self) {
        for _ in 0..MAX_EVICTION_PROBES {
            let victim = self.insertion_ring.lock().pop_front();
            match victim {
                Some(key) => {
                    if self.events.remove(&key).is_some() {
                        return;
                    }
                    // Key already pruned by its window — try the next one.
                }
                None => return,
            }
        }
    }
}

impl Default for RateGovernor {
    fn default() -> Self {
        Self::new(60, Duration::from_secs(60))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_limit_then_rejects_the_next_rapid_call() {
        let governor = RateGovernor::new(3, Duration::from_secs(60));
        for _ in 0..3 {
            assert!(governor.allow("tenant-a"));
        }
        assert!(
            !governor.allow("tenant-a"),
            "call N+1 within the window must be rejected"
        );
    }

    #[test]
    fn keys_are_isolated() {
        let governor = RateGovernor::new(1, Duration::from_secs(60));
        assert!(governor.allow("tenant-a"));
        assert!(!governor.allow("tenant-a"));
        assert!(governor.allow("tenant-b"));
    }

    #[test]
    fn window_slides_and_budget_is_restored() {
        let governor = RateGovernor::new(2, Duration::from_millis(20));
        assert!(governor.allow("k"));
        assert!(governor.allow("k"));
        assert!(!governor.allow("k"));
        std::thread::sleep(Duration::from_millis(30));
        assert!(governor.allow("k"));
    }

    #[test]
    fn capped_map_evicts_instead_of_growing_forever() {
        // Small cap for a fast test; identical code path to the default.
        let governor = RateGovernor::with_caps(1, Duration::from_secs(60), 500);
        for i in 0..1_050 {
            assert!(governor.allow(&format!("key-{i}")));
        }
        assert!(governor.events.len() <= 501, "map must stay bounded");
        // The newest key exhausted its budget of 1; a fresh key still works.
        assert!(!governor.allow("key-1049"));
        assert!(governor.allow("fresh-key"));
    }

    #[test]
    fn would_allow_does_not_consume_budget() {
        let governor = RateGovernor::new(1, Duration::from_secs(60));
        assert!(governor.would_allow("k"));
        assert!(governor.would_allow("k"));
        assert!(governor.allow("k"));
        assert!(!governor.would_allow("k"));
        assert!(!governor.allow("k"));
    }

    #[test]
    fn full_size_cap_stays_fast() {
        // Guards against reintroducing dashmap iter()-based eviction, which
        // swapped whole shards and made this O(n^2).
        let governor = RateGovernor::new(1, Duration::from_secs(60));
        let start = Instant::now();
        for i in 0..(MAX_TRACKED_KEYS + 50) {
            assert!(governor.allow(&format!("key-{i}")));
        }
        let elapsed = start.elapsed();
        assert!(
            elapsed < Duration::from_secs(5),
            "capped-map churn must stay O(1) per call, took {elapsed:?}"
        );
        assert!(governor.events.len() <= MAX_TRACKED_KEYS + 1);
    }
}
