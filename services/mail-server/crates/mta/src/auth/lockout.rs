//! Shared authentication lockout tracking and timing-equalisation helpers.
//!
//! Both the submission server (port 587) and the inbound server's
//! implicit-TLS AUTH path (port 465) authenticate against the same
//! `users` table. This module gives both servers identical
//! brute-force lockout semantics (per-IP + per-account) and a dummy
//! password verification so that unknown-account lookups take the same
//! time as real-account lookups (user-enumeration side channel).

use std::net::IpAddr;
use std::time::Duration;

use moka::sync::Cache;

/// Maximum failed attempts for one (IP, account) pair before further
/// attempts from that pair are rejected with a lockout response.
pub const MAX_AUTH_FAILURES_PER_ACCOUNT: u32 = 5;

/// Maximum failed attempts from a single IP across all accounts before
/// that IP is locked out. Deliberately higher than the per-account
/// threshold so one compromised account behind a NAT cannot lock out
/// every other user sharing the IP.
pub const MAX_AUTH_FAILURES_PER_IP: u32 = 20;

/// How long failure counters are retained. The cache TTL is the lockout
/// window: once an entry expires the counters reset and legitimate
/// users can authenticate again.
const FAILURE_WINDOW: Duration = Duration::from_secs(300);

/// Outcome of an authentication attempt, so callers can distinguish a
/// plain wrong-credentials failure from an active brute-force lockout.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AuthError {
    /// Credentials were rejected (or the account is disabled).
    Failed,
    /// Too many recent failures; the attempt was rejected without
    /// spending any password-verification time.
    LockedOut,
}

/// Tracks failed authentication attempts per (IP, account) and per IP.
///
/// - Per-account key `(ip, account)`: an attacker rotating through many
///   accounts from one IP accumulates against each account separately,
///   and one account's failures never lock out a different account.
/// - Per-IP key `ip`: a distributed attack across many accounts from a
///   single IP (e.g. a botnet behind one NAT) is still bounded.
pub struct AuthFailTracker {
    per_account: Cache<(IpAddr, String), u32>,
    per_ip: Cache<IpAddr, u32>,
}

impl Default for AuthFailTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl AuthFailTracker {
    pub fn new() -> Self {
        Self {
            per_account: Cache::builder()
                .max_capacity(50_000)
                .time_to_live(FAILURE_WINDOW)
                .build(),
            per_ip: Cache::builder()
                .max_capacity(50_000)
                .time_to_live(FAILURE_WINDOW)
                .build(),
        }
    }

    /// Whether further attempts from `ip` for `account` should be
    /// rejected without verifying credentials.
    pub fn is_locked(&self, ip: IpAddr, account: &str) -> bool {
        let account = normalize_account(account);
        self.per_ip.get(&ip).unwrap_or(0) >= MAX_AUTH_FAILURES_PER_IP
            || self.per_account.get(&(ip, account)).unwrap_or(0) >= MAX_AUTH_FAILURES_PER_ACCOUNT
    }

    /// Record one failed attempt (wrong password, disabled account, or
    /// unknown account) against both the per-account and per-IP keys.
    pub fn record_failure(&self, ip: IpAddr, account: &str) {
        let account = normalize_account(account);
        self.per_ip
            .insert(ip, 1 + self.per_ip.get(&ip).unwrap_or(0));
        self.per_account.insert(
            (ip, account.clone()),
            1 + self.per_account.get(&(ip, account)).unwrap_or(0),
        );
    }

    /// Clear both counters after a successful authentication.
    pub fn reset(&self, ip: IpAddr, account: &str) {
        let account = normalize_account(account);
        self.per_ip.remove(&ip);
        self.per_account.remove(&(ip, account));
    }
}

fn normalize_account(account: &str) -> String {
    account.to_lowercase()
}

/// OWASP-parameter Argon2id hash (m=19456, t=2, p=1) of a random
/// password. It never matches any real credentials; it exists so the
/// server can spend real verification time on unknown accounts.
const DUMMY_PASSWORD_HASH: &str = "$argon2id$v=19$m=19456,t=2,p=1$6KmAIGYKaSBl9ASEUmLo9w$TnUkbLd7Q5pk3BfTXwLOaU6A5wYH6YaBGo9sjWvgvIE";

/// Spend the same password-verification time as a real account lookup,
/// then report failure. Returns `false` unconditionally so an unknown
/// account is indistinguishable (by response time) from a real account
/// presented with a wrong password.
pub fn verify_against_dummy(password: &str) -> bool {
    let _ = apexmail_lib::crypto::verify_password(password, DUMMY_PASSWORD_HASH);
    false
}

#[cfg(test)]
mod tests {
    use std::net::{IpAddr, Ipv4Addr};
    use std::time::{Duration, Instant};

    use super::{verify_against_dummy, AuthError, AuthFailTracker, MAX_AUTH_FAILURES_PER_ACCOUNT};

    fn ip(octet: u8) -> IpAddr {
        IpAddr::V4(Ipv4Addr::new(10, 0, 0, octet))
    }

    #[test]
    fn test_not_locked_below_threshold() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT - 1 {
            tracker.record_failure(ip(1), "alice@example.com");
        }
        assert!(!tracker.is_locked(ip(1), "alice@example.com"));
    }

    #[test]
    fn test_locked_after_five_failures() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "alice@example.com");
        }
        assert!(tracker.is_locked(ip(1), "alice@example.com"));
    }

    #[test]
    fn test_success_resets_counters() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "alice@example.com");
        }
        assert!(tracker.is_locked(ip(1), "alice@example.com"));
        tracker.reset(ip(1), "alice@example.com");
        assert!(!tracker.is_locked(ip(1), "alice@example.com"));
    }

    #[test]
    fn test_wrong_password_for_account_b_does_not_lock_account_a() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "bob@example.com");
        }
        assert!(!tracker.is_locked(ip(1), "alice@example.com"));
    }

    #[test]
    fn test_failures_from_ip_x_do_not_lock_ip_y() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "alice@example.com");
        }
        assert!(!tracker.is_locked(ip(2), "alice@example.com"));
    }

    #[test]
    fn test_unknown_account_attempts_count_toward_lockout() {
        // An unknown email is recorded under the attempted address, so it
        // can never be used to bypass the lockout.
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "ghost@example.com");
        }
        assert!(tracker.is_locked(ip(1), "ghost@example.com"));
        assert_eq!(tracker.is_locked(ip(1), "ghost@example.com"), true);
    }

    #[test]
    fn test_account_insensitive_to_case() {
        let tracker = AuthFailTracker::new();
        for _ in 0..MAX_AUTH_FAILURES_PER_ACCOUNT {
            tracker.record_failure(ip(1), "Alice@Example.COM");
        }
        assert!(tracker.is_locked(ip(1), "alice@example.com"));
    }

    #[test]
    fn test_verify_against_dummy_returns_false() {
        assert!(!verify_against_dummy("any-password"));
    }

    #[test]
    fn test_verify_against_dummy_spends_real_verification_time() {
        // The dummy verify must actually run the Argon2id verification
        // (same parameters as real password hashes), otherwise the
        // unknown-user fast path would leak account existence through
        // response time.
        let start = Instant::now();
        verify_against_dummy("wrong-password");
        let elapsed = start.elapsed();
        assert!(
            elapsed >= Duration::from_millis(1),
            "dummy verify returned in {elapsed:?}; it must run a real Argon2id verification"
        );
    }

    #[test]
    fn test_auth_error_variants_distinguishable() {
        assert_ne!(AuthError::Failed, AuthError::LockedOut);
    }
}
