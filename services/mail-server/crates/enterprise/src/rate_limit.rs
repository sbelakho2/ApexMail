//! Fixed-window per-key rate limiter for unauthenticated protocol endpoints.
//!
//! Audit F11: `GET /sso/login/:*` is intentionally unauthenticated (the IdP
//! browser redirect cannot carry our bearer token), but every call INSERTs a
//! staging row (`ent_saml_authn_requests` / `sso_oidc_state`). Without a
//! limit, one client spams unbounded rows into the compliance database. The
//! limiter is deliberately tiny and in-process: a per-IP window counter with
//! no external dependencies, sized so a legitimate login flow (a handful of
//! initiations per user) is never refused while scripted row-fill is.

use std::collections::HashMap;
use std::sync::Mutex;
use std::time::{SystemTime, UNIX_EPOCH};

/// Default window: matches the 10-minute staging-row TTL — a window that
/// outlives the rows it guards keeps the abusive client blocked across the
/// sweep gap.
pub const SSO_LOGIN_WINDOW_SECS: u64 = 600;
/// Default allowance per window: far above any real login flow.
pub const SSO_LOGIN_MAX_PER_WINDOW: u32 = 30;

/// A fixed-window counter per key. Keys fall into `(window_index)` buckets
/// that are pruned lazily on access, so an attacker cycling spoofed keys
/// cannot grow the map without bound (each window switch drops the map).
pub struct FixedWindowRateLimiter {
    max_per_window: u32,
    window_secs: u64,
    /// `(key, window_index) -> hits`
    hits: Mutex<HashMap<(String, u64), u32>>,
}

impl FixedWindowRateLimiter {
    pub fn new(max_per_window: u32, window_secs: u64) -> Self {
        Self {
            max_per_window,
            window_secs: window_secs.max(1),
            hits: Mutex::new(HashMap::new()),
        }
    }

    /// Check-and-consume one slot for `key` at the current wall clock.
    /// `false` means the caller is over the window's allowance.
    pub fn check(&self, key: &str) -> bool {
        let now = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        self.check_at(key, now)
    }

    /// Check-and-consume one slot at an explicit timestamp (test seam).
    pub fn check_at(&self, key: &str, now_secs: u64) -> bool {
        let window = now_secs / self.window_secs;
        let mut hits = self.hits.lock().unwrap_or_else(|poisoned| {
            // A panicked holder must not permanently wedge logins: the guard
            // only ever increments counters.
            poisoned.into_inner()
        });
        // Lazy prune: drop every bucket from a previous window. The map can
        // therefore hold at most one window of distinct keys.
        hits.retain(|entry_key, _| entry_key.1 == window);
        let entry = hits.entry((key.to_string(), window)).or_insert(0);
        if *entry >= self.max_per_window {
            return false;
        }
        *entry += 1;
        true
    }
}

// ── Tests ──────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn allows_up_to_the_cap_then_refuses_within_the_window() {
        // window_secs=1000, base=1_000_000 → window 1000 spans
        // [1_000_000, 1_001_000).
        let limiter = FixedWindowRateLimiter::new(3, 1000);
        for attempt in 1..=3 {
            assert!(
                limiter.check_at("203.0.113.7", 1_000_000),
                "attempt {attempt} under the cap must pass"
            );
        }
        assert!(
            !limiter.check_at("203.0.113.7", 1_000_999),
            "the 4th attempt inside the window must be refused"
        );
    }

    #[test]
    fn the_window_reset_reallows_after_expiry() {
        let limiter = FixedWindowRateLimiter::new(1, 1000);
        assert!(limiter.check_at("203.0.113.9", 1_000_000));
        assert!(!limiter.check_at("203.0.113.9", 1_000_999));
        assert!(
            limiter.check_at("203.0.113.9", 1_001_000),
            "a fresh window grants a new allowance"
        );
    }

    #[test]
    fn keys_are_independent() {
        let limiter = FixedWindowRateLimiter::new(1, 1000);
        assert!(limiter.check_at("203.0.113.1", 1_000_000));
        assert!(!limiter.check_at("203.0.113.1", 1_000_001));
        assert!(
            limiter.check_at("203.0.113.2", 1_000_001),
            "a different IP has its own allowance"
        );
    }

    #[test]
    fn pruned_buckets_keep_the_map_bounded_across_windows() {
        let limiter = FixedWindowRateLimiter::new(2, 10);
        for window in 0..500u64 {
            for key in 0..50u64 {
                limiter.check_at(&format!("ip-{key}"), window * 10 + 1);
            }
        }
        let held = limiter.hits.lock().unwrap().len();
        assert!(
            held <= 50,
            "lazy pruning must drop previous windows, map held {held}"
        );
    }
}
