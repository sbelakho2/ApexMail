//! Protection decisions and challenge types

use std::time::Duration;

/// RS-064: Constant-time comparison that does NOT leak length through timing.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let len_matches = a.len() == b.len();
    let diff: u8 = a
        .bytes()
        .zip(b.bytes().chain(std::iter::repeat(0)))
        .fold(0u8, |diff, (x, y)| diff | (x ^ y));
    let tail_diff: u8 = b.bytes().skip(a.len()).fold(0u8, |d, x| d | x);
    len_matches && diff == 0 && tail_diff == 0
}

/// Decision returned by the DDoS protector
#[derive(Debug, Clone)]
pub enum ProtectionDecision {
    /// Request is allowed to proceed
    Allow,

    /// Request requires a challenge
    Challenge(Challenge),

    /// Request is rate limited
    RateLimit {
        /// When to retry
        retry_after: Duration,
    },

    /// Request is blocked
    Block,
}

impl ProtectionDecision {
    /// Check if the decision allows the request
    pub fn is_allowed(&self) -> bool {
        matches!(self, Self::Allow)
    }

    /// Check if a challenge is required
    pub fn is_challenge(&self) -> bool {
        matches!(self, Self::Challenge(_))
    }
}

/// Challenge types for bot detection
#[derive(Debug, Clone)]
pub enum Challenge {
    /// No challenge needed
    None,

    /// JavaScript evaluation challenge
    Js(JsChallenge),

    /// Proof of Work challenge
    Pow(PowChallenge),

    /// Cookie-based challenge
    Cookie(CookieChallenge),

    /// CAPTCHA challenge
    Captcha(CaptchaChallenge),

    /// Request is blocked (no challenge offered)
    Blocked,
}

/// JavaScript challenge - verify JS execution capability
#[derive(Debug, Clone)]
pub struct JsChallenge {
    /// Unique challenge ID
    pub id: String,
    /// JavaScript to execute
    pub script: String,
    /// Expected result
    pub expected_result: String,
    /// Challenge expiration (Unix timestamp)
    pub expires_at: u64,
}

/// Proof of Work challenge - CPU cost for client
#[derive(Debug, Clone)]
pub struct PowChallenge {
    /// Unique challenge ID
    pub id: String,
    /// Challenge data to hash
    pub data: String,
    /// Required leading zero bits
    pub difficulty: u8,
    /// Challenge expiration (Unix timestamp)
    pub expires_at: u64,
    /// Expected solve time in milliseconds
    pub expected_time_ms: u32,
    /// HMAC-SHA256 signature over `(id, data, difficulty, expires_at)`
    /// computed with the server's per-process secret (audit F3). Included so
    /// the client (and any intermediate) can detect tampered parameters;
    /// server-side VERIFICATION always uses the stored issuance-registry
    /// parameters, never these client-visible claims.
    pub signature: String,
}

/// Cookie challenge - verify cookie support
///
/// SECURITY (fix I): the cookie value is HMAC-SHA256 signed with a
/// server-side secret. Verification recomputes the signature and rejects
/// any value that was not issued by this server — previously the value was
/// a plain string compared for equality, so any client that ever observed
/// a valid value (or guessed it) could forge a passed challenge.
#[derive(Debug, Clone)]
pub struct CookieChallenge {
    /// Cookie name
    pub name: String,
    /// Cookie value — `"<challenge_id>:<expires_at>.<hmac_hex>"`
    pub value: String,
    /// Challenge expiration (Unix timestamp)
    pub expires_at: u64,
    /// Server-side signing secret (never sent to the client).
    pub signing_secret: [u8; 32],
}

/// CAPTCHA challenge - human verification
#[derive(Debug, Clone)]
pub struct CaptchaChallenge {
    /// Challenge ID
    pub id: String,
    /// CAPTCHA provider (e.g., "hcaptcha", "turnstile")
    pub provider: String,
    /// Site key for the challenge
    pub site_key: String,
    /// Challenge expiration (Unix timestamp)
    pub expires_at: u64,
}

impl JsChallenge {
    /// Verify a JS challenge response
    pub fn verify(&self, result: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now <= self.expires_at && constant_time_eq(result, &self.expected_result)
    }
}

impl PowChallenge {
    /// Verify a PoW solution
    pub fn verify(&self, nonce: u64) -> bool {
        use sha2::{Digest, Sha256};

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > self.expires_at {
            return false;
        }

        let input = format!("{}:{}", self.data, nonce);
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let hash = hasher.finalize();

        // Check leading zero bits
        let required_bytes = (self.difficulty / 8) as usize;
        let remaining_bits = self.difficulty % 8;

        for byte in &hash[..required_bytes] {
            if *byte != 0 {
                return false;
            }
        }

        if remaining_bits > 0 && required_bytes < 32 {
            let mask = 0xFF << (8 - remaining_bits);
            if hash[required_bytes] & mask != 0 {
                return false;
            }
        }

        true
    }
}

impl CookieChallenge {
    /// Issue an HMAC-signed cookie challenge.
    ///
    /// The value embeds a random challenge id and expiry, signed with the
    /// server secret; clients cannot forge or extend it.
    pub fn issue(secret: [u8; 32]) -> Self {
        let challenge_id = uuid::Uuid::new_v4().to_string();
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);
        let expires_at = now.saturating_add(3600); // 1 hour
        let token = format!("{}:{}", challenge_id, expires_at);
        let signature = hmac_sign(&secret, token.as_bytes());
        Self {
            name: "__apexmail_verify".to_string(),
            value: format!("{}.{}", token, signature),
            expires_at,
            signing_secret: secret,
        }
    }

    /// Verify a presented cookie value against this challenge.
    ///
    /// Accepts only values carrying a valid HMAC signature under this
    /// server's secret and an unexpired token; a bare value copied from the
    /// challenge is rejected unless the signature matches (which it does
    /// for the value we issued, but not for anything mutated).
    pub fn verify(&self, cookie_value: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        if now > self.expires_at {
            return false;
        }

        // Presented value must be "<token>.<signature>"
        let Some((token, signature)) = cookie_value.rsplit_once('.') else {
            return false;
        };
        let expected = hmac_sign(&self.signing_secret, token.as_bytes());
        if !constant_time_eq(signature, &expected) {
            return false;
        }

        // Token must be "<challenge_id>:<expires_at>" and unexpired.
        let Some((_id, expires_str)) = token.rsplit_once(':') else {
            return false;
        };
        match expires_str.parse::<u64>() {
            Ok(expiry) => now <= expiry,
            Err(_) => false,
        }
    }
}

/// HMAC-SHA256 of `data` under `secret`, hex encoded.
fn hmac_sign(secret: &[u8; 32], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

    type HmacSha256 = Hmac<Sha256>;
    let mut mac = HmacSha256::new_from_slice(secret).expect("HMAC-SHA256 accepts any key length");
    mac.update(data);
    hex_encode(&mac.finalize().into_bytes())
}

/// Lowercase hex encoding without an external hex dependency (decision.rs
/// is compiled in core builds where `hex` is feature-gated).
fn hex_encode(bytes: &[u8]) -> String {
    const HEX: &[u8; 16] = b"0123456789abcdef";
    let mut out = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        out.push(HEX[(b >> 4) as usize] as char);
        out.push(HEX[(b & 0x0F) as usize] as char);
    }
    out
}

/// Generate fresh, unpredictable challenge data for a PoW challenge.
///
/// SECURITY (fix I): challenges previously used a constant prefix
/// (`"challenge"`) or a per-IP constant (`"rep_challenge:<ip>"`), so one
/// solved nonce could be replayed forever (and across requests from the
/// same IP). Each issuance now gets 128 bits of randomness from the OS.
pub fn fresh_pow_challenge_data() -> String {
    format!("pow:{}:{}", uuid::Uuid::new_v4(), uuid::Uuid::new_v4())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn js_challenge_uses_exact_constant_time_value_match() {
        let challenge = JsChallenge {
            id: "challenge".into(),
            script: "return 42".into(),
            expected_result: "42".into(),
            expires_at: current_time_secs() + 60,
        };
        assert!(challenge.verify("42"));
        assert!(!challenge.verify("43"));
        assert!(!challenge.verify("420"));
    }

    // NOTE: `cookie_challenge_uses_exact_constant_time_value_match` was
    // replaced — it asserted the pre-fix plain-comparison behavior that let
    // any client that observed a valid value forge a passed challenge.

    #[test]
    fn cookie_challenge_accepts_own_issued_value() {
        let secret = [7u8; 32];
        let challenge = CookieChallenge::issue(secret);
        assert!(
            challenge.verify(&challenge.value),
            "issued signed value must verify"
        );
    }

    #[test]
    fn cookie_challenge_rejects_forged_and_mutated_values() {
        let secret = [7u8; 32];
        let challenge = CookieChallenge::issue(secret);

        // Unsigned value (old format) rejected
        assert!(!challenge.verify("signed-cookie"));
        // Tampered token with stale signature rejected
        let mutated = format!("0{}", challenge.value);
        assert!(!challenge.verify(&mutated));
        // Value signed with a DIFFERENT secret rejected
        let other = CookieChallenge::issue([8u8; 32]);
        assert!(!challenge.verify(&other.value), "cross-secret forgery");
        // Truncated / malformed rejected
        assert!(!challenge.verify("nonsense"));
        assert!(!challenge.verify(""));
        // Right format, wrong signature content
        assert!(!challenge.verify("id:99999999999.deadbeef"));
    }

    #[test]
    fn cookie_challenge_expired_value_rejected() {
        let secret = [7u8; 32];
        let mut challenge = CookieChallenge::issue(secret);
        challenge.expires_at = current_time_secs().saturating_sub(1);
        assert!(!challenge.verify(&challenge.value));
    }

    #[test]
    fn fresh_pow_challenge_data_is_unique_per_issuance() {
        // Fix I: two issuances must never share challenge data (replayable
        // prefix bug).
        let a = fresh_pow_challenge_data();
        let b = fresh_pow_challenge_data();
        assert_ne!(a, b);
        assert!(a.starts_with("pow:"));
    }

    fn current_time_secs() -> u64 {
        std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0)
    }
}
