//! Email hashing helpers for privacy-preserving analytics cache keys.

use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::sync::OnceLock;

/// Env var holding the HMAC key for analytics recipient hashing (D).
pub const ANALYTICS_STO_HMAC_KEY_ENV: &str = "ANALYTICS_STO_HMAC_KEY";

/// HMAC-SHA256 salted hash of an email for privacy (O-11.5).
///
/// When `key` is non-empty, HMAC-SHA256 is used with the key as salt.
/// When `key` is empty, falls back to bare SHA-256 for backward compatibility.
pub fn hash_email(email: &str, key: &str) -> String {
    if key.is_empty() {
        let mut hasher = Sha256::new();
        hasher.update(email.as_bytes());
        format!("{:x}", hasher.finalize())
    } else {
        let mut mac =
            Hmac::<Sha256>::new_from_slice(key.as_bytes()).expect("HMAC key should be valid");
        mac.update(email.as_bytes());
        format!("{:x}", mac.finalize().into_bytes())
    }
}

/// D: the analytics HMAC key. `ANALYTICS_STO_HMAC_KEY` when configured; in
/// development an EPHEMERAL random key is generated with a loud warning —
/// hashed values will not be comparable across restarts. Production must set
/// the env var (see `AnalyticsConfig::validate`).
fn analytics_hmac_key() -> String {
    static KEY: OnceLock<String> = OnceLock::new();
    KEY.get_or_init(|| match std::env::var(ANALYTICS_STO_HMAC_KEY_ENV) {
        Ok(k) if !k.trim().is_empty() => k,
        _ => {
            let generated = format!(
                "{}{}",
                uuid::Uuid::new_v4().simple(),
                uuid::Uuid::new_v4().simple()
            );
            tracing::warn!(
                env = ANALYTICS_STO_HMAC_KEY_ENV,
                "ANALYTICS_STO_HMAC_KEY is not set — using an ephemeral per-process key. \
                 Hashed recipients are stable within this process but will NOT match \
                 values written after a restart. Set the env var in production."
            );
            generated
        }
    })
    .clone()
}

/// D: HMAC-hash a recipient for analytics storage using the configured key.
pub fn hash_for_analytics(recipient: &str) -> String {
    hash_email(recipient, &analytics_hmac_key())
}

/// D: privacy-encode a recipient for the analytics `events` store.
///
/// Returns `h:<hmac>:<redacted>` — the HMAC prefix keeps per-recipient
/// grouping (engagement histograms, funnels) working while only a truncated
/// human-readable form (`a***@example.com`, via `mail_common::pii`) remains
/// visible. Raw recipients are never stored unless a per-tenant raw opt-in
/// exists (none does today).
pub fn recipient_for_analytics(recipient: &str) -> String {
    recipient_for_analytics_with_key(recipient, &analytics_hmac_key())
}

/// Explicit-key variant of [`recipient_for_analytics`] (testable / reusable).
pub fn recipient_for_analytics_with_key(recipient: &str, key: &str) -> String {
    format!(
        "h:{}:{}",
        hash_email(recipient, key),
        mail_common::pii::redact_email(recipient)
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn bare_hash_is_deterministic() {
        let hash = hash_email("user@example.com", "");
        assert_eq!(hash.len(), 64);
        assert_eq!(hash, hash_email("user@example.com", ""));
        assert_ne!(hash, hash_email("other@example.com", ""));
    }

    #[test]
    fn keyed_hash_differs_from_bare_hash() {
        let bare_hash = hash_email("user@example.com", "");
        let keyed_hash = hash_email("user@example.com", "analytics-hmac-key");
        assert_eq!(keyed_hash.len(), 64);
        assert_ne!(bare_hash, keyed_hash);
        assert_eq!(
            keyed_hash,
            hash_email("user@example.com", "analytics-hmac-key")
        );
    }

    #[test]
    fn hash_stable_across_calls_and_differs_per_key() {
        let k1 = recipient_for_analytics_with_key("joanna@example.com", "key-one");
        let k1_again = recipient_for_analytics_with_key("joanna@example.com", "key-one");
        let k2 = recipient_for_analytics_with_key("joanna@example.com", "key-two");
        assert_eq!(k1, k1_again, "stable across calls");
        assert_ne!(k1, k2, "differs per key");
    }

    #[test]
    fn recipient_encoding_masks_local_part_and_groups_deterministically() {
        let encoded = recipient_for_analytics_with_key("joanna@example.com", "k");
        // Human-visible part is redacted: local part masked, no raw recipient.
        assert!(encoded.contains("j***@example.com"), "got {encoded}");
        assert!(
            !encoded.contains("joanna"),
            "raw local part must not appear"
        );
        // Same recipient → same encoding (grouping still works); different
        // recipient → different encoding.
        assert_eq!(
            encoded,
            recipient_for_analytics_with_key("joanna@example.com", "k")
        );
        assert_ne!(
            encoded,
            recipient_for_analytics_with_key("joanne@example.com", "k")
        );
    }
}
