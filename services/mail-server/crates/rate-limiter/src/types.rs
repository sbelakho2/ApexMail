//! Common types for rate limiting.

use serde::{Deserialize, Serialize};
use std::time::Duration;

/// The result of a rate limit check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum Decision {
/// Request is allowed; includes remaining quota.
    Allowed { remaining: u64 },
/// Request is denied; includes how long to wait.
    Denied { retry_after: Duration },
}

impl Decision {
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allowed { .. })
    }

    pub fn is_denied(&self) -> bool {
        matches!(self, Self::Denied { .. })
    }

    pub fn remaining(&self) -> u64 {
        match self {
            Self::Allowed { remaining } => *remaining,
            Self::Denied { .. } => 0,
        }
    }

    pub fn retry_after(&self) -> Option<Duration> {
        match self {
            Self::Denied { retry_after } => Some(*retry_after),
            Self::Allowed { .. } => None,
        }
    }
}

/// Rate limiter errors.
#[derive(Debug, thiserror::Error)]
pub enum RateLimitError {
    #[error("Rate limiter not initialized")]
    NotInitialized,
    #[error("Invalid configuration: {0}")]
    InvalidConfig(String),
    #[error("Key evicted from limiter")]
    KeyEvicted,
    #[error("Internal error: {0}")]
    Internal(String),
}

/// Snapshot of rate limiter state for diagnostics.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RateLimitStatus {
/// Number of requests remaining in the current window.
    pub remaining: u64,
/// Maximum allowed requests.
    pub limit: u64,
/// When the window resets (epoch millis).
    pub reset_at_ms: i64,
/// Whether the limiter is currently blocking requests.
    pub is_throttled: bool,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_decision_allowed() {
        let d = Decision::Allowed { remaining: 42 };
        assert!(d.is_allowed());
        assert!(!d.is_denied());
        assert_eq!(d.remaining(), 42);
        assert!(d.retry_after().is_none());
    }

    #[test]
    fn test_decision_denied() {
        let d = Decision::Denied {
            retry_after: Duration::from_secs(5),
        };
        assert!(!d.is_allowed());
        assert!(d.is_denied());
        assert_eq!(d.remaining(), 0);
        assert_eq!(d.retry_after(), Some(Duration::from_secs(5)));
    }

    #[test]
    fn test_decision_serialization() {
        let d = Decision::Allowed { remaining: 10 };
        let json = serde_json::to_string(&d).unwrap();
        let parsed: Decision = serde_json::from_str(&json).unwrap();
        assert!(parsed.is_allowed());
        assert_eq!(parsed.remaining(), 10);
    }

    #[test]
    fn test_rate_limit_status() {
        let s = RateLimitStatus {
            remaining: 500,
            limit: 1000,
            reset_at_ms: 1700000000000,
            is_throttled: false,
        };
        assert!(!s.is_throttled);
        assert_eq!(s.remaining, 500);
    }

    #[test]
    fn test_error_display() {
        let e = RateLimitError::InvalidConfig("bad burst".into());
        assert_eq!(e.to_string(), "Invalid configuration: bad burst");
    }
}
