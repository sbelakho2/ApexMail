//! Shared audit log utilities.
//!
//! # Source files replaced
//!
//! | Original location | What was replaced |
//! |---|---|
//! | [`billing-service/src/routes.rs`](services/mail-server/crates/billing-service/src/routes.rs:1095) | `generate_audit_log_id()`, `compute_audit_log_hash()` |
//! | [`api-server/src/routes/billing.rs`](services/mail-server/crates/api-server/src/routes/billing.rs:2201) | duplicate of the above |

use hmac::{Hmac, Mac};
use sha2::Sha256;
use uuid::Uuid;

type HmacSha256 = Hmac<Sha256>;

/// Generate a full-length (32-character hex) audit log entry ID.
///
/// Uses [`Uuid::new_v4()`] and returns the complete 32-character lowercase
/// hex string — **no trimming**.
pub fn generate_audit_log_id() -> String {
    Uuid::new_v4().to_string().replace('-', "")
}

/// Compute an HMAC-SHA256 audit log hash linking consecutive entries.
///
/// The hash is computed over `previous_hash || entry_id || timestamp || action`.
pub fn compute_audit_log_hash(
    previous_hash: &str,
    entry_id: &str,
    timestamp: &str,
    action: &str,
    secret: &[u8],
) -> String {
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC key length should be valid");
    mac.update(previous_hash.as_bytes());
    mac.update(entry_id.as_bytes());
    mac.update(timestamp.as_bytes());
    mac.update(action.as_bytes());
    hex::encode(mac.finalize().into_bytes())
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generate_audit_log_id_returns_full_32_char_hex() {
        let id = generate_audit_log_id();
        // 32 hex characters (no dashes, no truncation)
        assert_eq!(id.len(), 32, "audit log ID must be 32 chars");
        assert!(id.chars().all(|c| c.is_ascii_hexdigit()), "must be hex");
    }

    #[test]
    fn generate_audit_log_id_is_unique() {
        let a = generate_audit_log_id();
        let b = generate_audit_log_id();
        assert_ne!(a, b);
    }

    #[test]
    fn compute_audit_log_hash_deterministic() {
        let secret = b"test-secret-key-32-bytes-long!!";
        let hash1 = compute_audit_log_hash(
            "prev_hash",
            "entry_1",
            "2026-01-01T00:00:00Z",
            "plan_change",
            secret,
        );
        let hash2 = compute_audit_log_hash(
            "prev_hash",
            "entry_1",
            "2026-01-01T00:00:00Z",
            "plan_change",
            secret,
        );
        assert_eq!(hash1, hash2);
    }

    #[test]
    fn compute_audit_log_hash_different_entries_differ() {
        let secret = b"test-secret-key-32-bytes-long!!";
        let hash1 = compute_audit_log_hash(
            "prev_hash",
            "entry_1",
            "2026-01-01T00:00:00Z",
            "plan_change",
            secret,
        );
        let hash2 = compute_audit_log_hash(
            "prev_hash",
            "entry_2",
            "2026-01-01T00:00:00Z",
            "plan_change",
            secret,
        );
        assert_ne!(hash1, hash2);
    }
}
