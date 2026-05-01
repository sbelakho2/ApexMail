//! Protection decisions and challenge types

use std::time::Duration;

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
}

/// Cookie challenge - verify cookie support
#[derive(Debug, Clone)]
pub struct CookieChallenge {
    /// Cookie name
    pub name: String,
    /// Cookie value
    pub value: String,
    /// Challenge expiration (Unix timestamp)
    pub expires_at: u64,
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

        now <= self.expires_at && result == self.expected_result
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
    /// Verify a cookie challenge response
    pub fn verify(&self, cookie_value: &str) -> bool {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|d| d.as_secs())
            .unwrap_or(0);

        now <= self.expires_at && cookie_value == self.value
    }
}
