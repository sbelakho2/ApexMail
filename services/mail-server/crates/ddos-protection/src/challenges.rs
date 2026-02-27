//! Challenge implementations for bot detection
//!
//! Provides various challenge mechanisms to distinguish legitimate users from bots.

use sha2::{Sha256, Digest};
use std::collections::{HashSet, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use rand::{Rng, thread_rng};
use serde::{Deserialize, Serialize};
use subtle::ConstantTimeEq;

/// Verification outcome for replay-aware challenge checks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeVerifyResult {
    /// Whether the submitted solution is valid.
    pub valid: bool,
    /// Whether this submission was replayed.
    pub replayed: bool,
    /// Whether the challenge was expired.
    pub expired: bool,
}

/// Audit event for challenge lifecycle.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ChallengeAuditRecord {
    /// Challenge identifier.
    pub challenge_id: String,
    /// Challenge type label (pow/js/cookie/captcha).
    pub challenge_type: String,
    /// Outcome label (issued/passed/failed/replay/expired).
    pub outcome: String,
    /// Optional client fingerprint or address token.
    pub client_fingerprint: Option<String>,
    /// Event timestamp (unix seconds).
    pub timestamp: u64,
}

/// Challenge types available
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum ChallengeType {
    /// JavaScript execution challenge
    JavaScript(JsChallenge),
    /// Proof of work challenge
    ProofOfWork(PowChallenge),
    /// Cookie-based challenge (simple)
    Cookie(CookieChallenge),
    /// CAPTCHA challenge
    Captcha(CaptchaChallenge),
}

/// JavaScript challenge
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JsChallenge {
    /// Unique challenge ID
    pub challenge_id: String,
    /// JavaScript code to execute
    pub script: String,
    /// Expected result hash
    pub expected_hash: String,
    /// Time limit in seconds
    pub time_limit_secs: u32,
    /// Creation timestamp
    pub created_at: u64,
}

impl JsChallenge {
    /// Generate a new JS challenge
    pub fn generate() -> Self {
        let mut rng = thread_rng();
        let challenge_id = generate_challenge_id();
        
        // Generate random numbers for calculation
        let a: u32 = rng.gen_range(1000..10000);
        let b: u32 = rng.gen_range(1000..10000);
        let expected_result = (a as u64 * b as u64) ^ 0xDEADBEEF;
        
        // Generate expected hash
        let expected_hash = hash_result(&expected_result.to_string());
        
        // Generate variable names ONCE and reuse them so the produced
        // JavaScript actually references the correct variables.
        // Previously every {} placeholder got a fresh random name,
        // causing parseInt to reference non-existent variables (BUG).
        let var_a_str = hex::encode(&rng.gen::<[u8; 4]>());
        let var_a_int = hex::encode(&rng.gen::<[u8; 4]>());
        let var_b_str = hex::encode(&rng.gen::<[u8; 4]>());
        let var_b_int = hex::encode(&rng.gen::<[u8; 4]>());
        
        let script = format!(
            r#"(function(){{
                var _0x{var_a_str}='{hex_a}';
                var _0x{var_a_int}=parseInt(_0x{var_a_str},16);
                var _0x{var_b_str}='{hex_b}';
                var _0x{var_b_int}=parseInt(_0x{var_b_str},16);
                var _result=(_0x{var_a_int}*_0x{var_b_int})^0xDEADBEEF;
                return _result.toString();
            }})()"#,
            var_a_str = var_a_str,
            hex_a = format!("{:x}", a),
            var_a_int = var_a_int,
            var_b_str = var_b_str,
            hex_b = format!("{:x}", b),
            var_b_int = var_b_int,
        );
        
        Self {
            challenge_id,
            script,
            expected_hash,
            time_limit_secs: 10,
            created_at: current_timestamp(),
        }
    }
    
    /// Verify solution
    pub fn verify(&self, solution: &str) -> bool {
        // Check if expired
        if current_timestamp() > self.created_at + self.time_limit_secs as u64 {
            return false;
        }
        
        // Check solution hash
        let solution_hash = hash_result(solution);
        self.expected_hash == solution_hash
    }
}

/// Proof of Work challenge
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PowChallenge {
    /// Challenge ID
    pub challenge_id: String,
    /// Challenge prefix to hash
    pub prefix: String,
    /// Required number of leading zero bits
    pub difficulty: u8,
    /// Time limit in seconds
    pub time_limit_secs: u32,
    /// Creation timestamp
    pub created_at: u64,
}

impl PowChallenge {
    /// Generate a new PoW challenge
    pub fn generate(difficulty: u8) -> Self {
        let challenge_id = generate_challenge_id();
        let prefix = generate_random_hex(16);
        
        Self {
            challenge_id,
            prefix,
            difficulty,
            time_limit_secs: 30,
            created_at: current_timestamp(),
        }
    }
    
    /// Verify solution (nonce)
    pub fn verify(&self, nonce: &str) -> bool {
        // Check if expired
        if current_timestamp() > self.created_at + self.time_limit_secs as u64 {
            return false;
        }
        
        // Compute hash
        let data = format!("{}{}", self.prefix, nonce);
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let hash = hasher.finalize();
        
        // Check leading zeros
        let required_zeros = self.difficulty as usize;
        let required_bytes = required_zeros / 8;
        let remaining_bits = required_zeros % 8;
        
        // Check full bytes
        for i in 0..required_bytes {
            if hash[i] != 0 {
                return false;
            }
        }
        
        // Check remaining bits
        if remaining_bits > 0 {
            let mask = 0xFF << (8 - remaining_bits);
            if hash[required_bytes] & mask != 0 {
                return false;
            }
        }
        
        true
    }
    
    /// Solve the challenge (for testing)
    #[cfg(test)]
    pub fn solve(&self) -> String {
        let mut nonce = 0u64;
        loop {
            let nonce_str = nonce.to_string();
            if self.verify_inner(&nonce_str) {
                return nonce_str;
            }
            nonce += 1;
            if nonce > 100_000_000 {
                return String::new();
            }
        }
    }
    
    #[cfg(test)]
    fn verify_inner(&self, nonce: &str) -> bool {
        let data = format!("{}{}", self.prefix, nonce);
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let hash = hasher.finalize();
        
        let required_zeros = self.difficulty as usize;
        let required_bytes = required_zeros / 8;
        let remaining_bits = required_zeros % 8;
        
        for i in 0..required_bytes {
            if hash[i] != 0 {
                return false;
            }
        }
        
        if remaining_bits > 0 {
            let mask = 0xFF << (8 - remaining_bits);
            if hash[required_bytes] & mask != 0 {
                return false;
            }
        }
        
        true
    }
}

/// Cookie-based challenge
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CookieChallenge {
    /// Challenge ID
    pub challenge_id: String,
    /// Cookie name to set
    pub cookie_name: String,
    /// Cookie value (signed token)
    pub cookie_value: String,
    /// HMAC signature
    pub signature: String,
    /// Expiration timestamp
    pub expires_at: u64,
}

impl CookieChallenge {
    /// Generate a new cookie challenge
    pub fn generate(secret: &[u8; 32]) -> Self {
        let challenge_id = generate_challenge_id();
        let cookie_name = "__apexmail_verify".to_string();
        
        // Create token with timestamp
        let expires_at = current_timestamp() + 3600; // 1 hour
        let token = format!("{}:{}", challenge_id, expires_at);
        
        // Sign token
        let signature = hmac_sign(secret, token.as_bytes());
        let cookie_value = format!("{}.{}", token, signature);
        
        Self {
            challenge_id,
            cookie_name,
            cookie_value,
            signature,
            expires_at,
        }
    }
    
    /// Verify cookie value
    pub fn verify(cookie_value: &str, secret: &[u8; 32]) -> bool {
        let parts: Vec<&str> = cookie_value.rsplitn(2, '.').collect();
        if parts.len() != 2 {
            return false;
        }
        
        let signature = parts[0];
        let token = parts[1];
        
        // Verify signature using constant-time comparison (E-107 fix: prevents timing attacks)
        let expected_sig = hmac_sign(secret, token.as_bytes());
        if signature.as_bytes().ct_eq(expected_sig.as_bytes()).unwrap_u8() != 1 {
            return false;
        }
        
        // Check expiration
        let token_parts: Vec<&str> = token.split(':').collect();
        if token_parts.len() != 2 {
            return false;
        }
        
        if let Ok(expires_at) = token_parts[1].parse::<u64>() {
            if current_timestamp() > expires_at {
                return false;
            }
        } else {
            return false;
        }
        
        true
    }
}

/// CAPTCHA challenge (external service integration)
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct CaptchaChallenge {
    /// Challenge ID
    pub challenge_id: String,
    /// CAPTCHA site key
    pub site_key: String,
    /// CAPTCHA provider
    pub provider: CaptchaProvider,
    /// Time limit in seconds
    pub time_limit_secs: u32,
    /// Creation timestamp
    pub created_at: u64,
}

/// Supported CAPTCHA providers
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub enum CaptchaProvider {
    /// Cloudflare Turnstile
    Turnstile,
    /// hCaptcha
    HCaptcha,
    /// Google reCAPTCHA
    ReCaptcha,
}

impl CaptchaChallenge {
    /// Generate a new CAPTCHA challenge
    pub fn generate(provider: CaptchaProvider, site_key: &str) -> Self {
        Self {
            challenge_id: generate_challenge_id(),
            site_key: site_key.to_string(),
            provider,
            time_limit_secs: 120,
            created_at: current_timestamp(),
        }
    }
    
    /// Check if expired
    pub fn is_expired(&self) -> bool {
        current_timestamp() > self.created_at + self.time_limit_secs as u64
    }
}

/// Challenge manager for issuing and verifying challenges
pub struct ChallengeManager {
    /// Secret key for signing
    secret: [u8; 32],
    /// Default JS challenge timeout
    js_timeout: Duration,
    /// Default PoW difficulty
    pow_difficulty: u8,
    /// CAPTCHA site key (if configured)
    captcha_site_key: Option<String>,
    /// CAPTCHA provider
    captcha_provider: Option<CaptchaProvider>,
    /// Used challenge responses to prevent replay
    used_responses: parking_lot::RwLock<HashSet<String>>,
    /// Bounded in-memory audit log
    audit_log: parking_lot::RwLock<VecDeque<ChallengeAuditRecord>>,
    /// Max records retained in audit log
    max_audit_records: usize,
}

impl ChallengeManager {
    /// Create new challenge manager
    pub fn new(secret: [u8; 32]) -> Self {
        Self {
            secret,
            js_timeout: Duration::from_secs(10),
            pow_difficulty: 16, // ~65K hashes average
            captcha_site_key: None,
            captcha_provider: None,
            used_responses: parking_lot::RwLock::new(HashSet::new()),
            audit_log: parking_lot::RwLock::new(VecDeque::new()),
            max_audit_records: 10_000,
        }
    }
    
    /// Configure CAPTCHA
    pub fn with_captcha(mut self, provider: CaptchaProvider, site_key: String) -> Self {
        self.captcha_provider = Some(provider);
        self.captcha_site_key = Some(site_key);
        self
    }
    
    /// Set PoW difficulty
    pub fn with_pow_difficulty(mut self, difficulty: u8) -> Self {
        self.pow_difficulty = difficulty;
        self
    }
    
    /// Issue JavaScript challenge
    pub fn issue_js_challenge(&self) -> ChallengeType {
        let challenge = JsChallenge::generate();
        self.record_audit(ChallengeAuditRecord {
            challenge_id: challenge.challenge_id.clone(),
            challenge_type: "js".into(),
            outcome: "issued".into(),
            client_fingerprint: None,
            timestamp: current_timestamp(),
        });
        ChallengeType::JavaScript(challenge)
    }
    
    /// Issue Proof of Work challenge
    pub fn issue_pow_challenge(&self) -> ChallengeType {
        let challenge = PowChallenge::generate(self.pow_difficulty);
        self.record_audit(ChallengeAuditRecord {
            challenge_id: challenge.challenge_id.clone(),
            challenge_type: "pow".into(),
            outcome: "issued".into(),
            client_fingerprint: None,
            timestamp: current_timestamp(),
        });
        ChallengeType::ProofOfWork(challenge)
    }
    
    /// Issue cookie challenge
    pub fn issue_cookie_challenge(&self) -> ChallengeType {
        let challenge = CookieChallenge::generate(&self.secret);
        self.record_audit(ChallengeAuditRecord {
            challenge_id: challenge.challenge_id.clone(),
            challenge_type: "cookie".into(),
            outcome: "issued".into(),
            client_fingerprint: None,
            timestamp: current_timestamp(),
        });
        ChallengeType::Cookie(challenge)
    }
    
    /// Issue CAPTCHA challenge
    pub fn issue_captcha_challenge(&self) -> Option<ChallengeType> {
        let (provider, site_key) = match (&self.captcha_provider, &self.captcha_site_key) {
            (Some(p), Some(k)) => (p.clone(), k.clone()),
            _ => return None,
        };
        
        Some(ChallengeType::Captcha(CaptchaChallenge::generate(provider, &site_key)))
    }
    
    /// Verify a cookie challenge
    pub fn verify_cookie(&self, cookie_value: &str) -> bool {
        CookieChallenge::verify(cookie_value, &self.secret)
    }

    /// Verify PoW challenge with replay protection and audit logging.
    pub fn verify_pow_response(
        &self,
        challenge: &PowChallenge,
        nonce: &str,
        client_fingerprint: Option<&str>,
    ) -> ChallengeVerifyResult {
        let response_key = format!("pow:{}:{}", challenge.challenge_id, hash_result(nonce));
        {
            let used = self.used_responses.read();
            if used.contains(&response_key) {
                self.record_audit(ChallengeAuditRecord {
                    challenge_id: challenge.challenge_id.clone(),
                    challenge_type: "pow".into(),
                    outcome: "replay".into(),
                    client_fingerprint: client_fingerprint.map(ToString::to_string),
                    timestamp: current_timestamp(),
                });
                return ChallengeVerifyResult {
                    valid: false,
                    replayed: true,
                    expired: false,
                };
            }
        }

        let now = current_timestamp();
        let expired = now > challenge.created_at + challenge.time_limit_secs as u64;
        let valid = !expired && challenge.verify(nonce);

        if valid {
            self.used_responses.write().insert(response_key);
        }

        self.record_audit(ChallengeAuditRecord {
            challenge_id: challenge.challenge_id.clone(),
            challenge_type: "pow".into(),
            outcome: if expired {
                "expired".into()
            } else if valid {
                "passed".into()
            } else {
                "failed".into()
            },
            client_fingerprint: client_fingerprint.map(ToString::to_string),
            timestamp: now,
        });

        ChallengeVerifyResult {
            valid,
            replayed: false,
            expired,
        }
    }

    /// Verify JS challenge with replay protection and audit logging.
    pub fn verify_js_response(
        &self,
        challenge: &JsChallenge,
        solution: &str,
        client_fingerprint: Option<&str>,
    ) -> ChallengeVerifyResult {
        let response_key = format!("js:{}:{}", challenge.challenge_id, hash_result(solution));
        {
            let used = self.used_responses.read();
            if used.contains(&response_key) {
                self.record_audit(ChallengeAuditRecord {
                    challenge_id: challenge.challenge_id.clone(),
                    challenge_type: "js".into(),
                    outcome: "replay".into(),
                    client_fingerprint: client_fingerprint.map(ToString::to_string),
                    timestamp: current_timestamp(),
                });
                return ChallengeVerifyResult {
                    valid: false,
                    replayed: true,
                    expired: false,
                };
            }
        }

        let now = current_timestamp();
        let expired = now > challenge.created_at + challenge.time_limit_secs as u64;
        let valid = !expired && challenge.verify(solution);

        if valid {
            self.used_responses.write().insert(response_key);
        }

        self.record_audit(ChallengeAuditRecord {
            challenge_id: challenge.challenge_id.clone(),
            challenge_type: "js".into(),
            outcome: if expired {
                "expired".into()
            } else if valid {
                "passed".into()
            } else {
                "failed".into()
            },
            client_fingerprint: client_fingerprint.map(ToString::to_string),
            timestamp: now,
        });

        ChallengeVerifyResult {
            valid,
            replayed: false,
            expired,
        }
    }

    /// Read challenge audit records (oldest to newest).
    pub fn audit_records(&self) -> Vec<ChallengeAuditRecord> {
        self.audit_log.read().iter().cloned().collect()
    }

    fn record_audit(&self, record: ChallengeAuditRecord) {
        let mut audit = self.audit_log.write();
        audit.push_back(record);
        while audit.len() > self.max_audit_records {
            audit.pop_front();
        }
    }
    
    /// Select appropriate challenge based on risk level
    pub fn select_challenge(&self, risk_score: f64) -> ChallengeType {
        if risk_score > 0.9 {
            // Very high risk - require CAPTCHA
            self.issue_captcha_challenge()
                .unwrap_or_else(|| self.issue_pow_challenge())
        } else if risk_score > 0.7 {
            // High risk - PoW
            self.issue_pow_challenge()
        } else if risk_score > 0.5 {
            // Medium risk - JS challenge
            self.issue_js_challenge()
        } else {
            // Low risk - simple cookie
            self.issue_cookie_challenge()
        }
    }
}

// Helper functions

fn generate_challenge_id() -> String {
    let mut rng = thread_rng();
    let bytes: [u8; 16] = rng.gen();
    hex::encode(bytes)
}

fn generate_random_hex(len: usize) -> String {
    let mut rng = thread_rng();
    let bytes: Vec<u8> = (0..len).map(|_| rng.gen()).collect();
    hex::encode(bytes)
}

fn current_timestamp() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn hash_result(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

fn hmac_sign(secret: &[u8; 32], data: &[u8]) -> String {
    use sha2::Sha256;
    use hmac::{Hmac, Mac};
    
    type HmacSha256 = Hmac<Sha256>;
    
    let mut mac = match HmacSha256::new_from_slice(secret) {
        Ok(mac) => mac,
        Err(error) => {
            tracing::error!(?error, "Failed to initialize challenge HMAC");
            return String::new();
        }
    };
    mac.update(data);
    hex::encode(mac.finalize().into_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_js_challenge_generation() {
        let challenge = JsChallenge::generate();
        assert!(!challenge.challenge_id.is_empty());
        assert!(!challenge.script.is_empty());
    }
    
    #[test]
    fn test_pow_challenge() {
        // Use low difficulty for fast testing
        let challenge = PowChallenge::generate(8);
        let nonce = challenge.solve();
        
        // Re-create challenge with same values but fresh timestamp
        let challenge = PowChallenge {
            challenge_id: challenge.challenge_id,
            prefix: challenge.prefix,
            difficulty: 8,
            time_limit_secs: 30,
            created_at: current_timestamp(),
        };
        
        assert!(challenge.verify(&nonce));
    }
    
    #[test]
    fn test_cookie_challenge() {
        let secret = [0u8; 32];
        let challenge = CookieChallenge::generate(&secret);
        
        assert!(CookieChallenge::verify(&challenge.cookie_value, &secret));
    }
    
    #[test]
    fn test_challenge_manager() {
        let secret = [0u8; 32];
        let manager = ChallengeManager::new(secret);
        
        // Test challenge selection
        let low_risk = manager.select_challenge(0.3);
        assert!(matches!(low_risk, ChallengeType::Cookie(_)));
        
        let medium_risk = manager.select_challenge(0.6);
        assert!(matches!(medium_risk, ChallengeType::JavaScript(_)));
        
        let high_risk = manager.select_challenge(0.8);
        assert!(matches!(high_risk, ChallengeType::ProofOfWork(_)));
    }

    #[test]
    fn test_pow_replay_protection() {
        let manager = ChallengeManager::new([1u8; 32]).with_pow_difficulty(8);
        let challenge = match manager.issue_pow_challenge() {
            ChallengeType::ProofOfWork(challenge) => challenge,
            _ => return,
        };

        let nonce = challenge.solve();
        let first = manager.verify_pow_response(&challenge, &nonce, Some("10.0.0.1"));
        assert!(first.valid);
        assert!(!first.replayed);

        let second = manager.verify_pow_response(&challenge, &nonce, Some("10.0.0.1"));
        assert!(!second.valid);
        assert!(second.replayed);
    }

    #[test]
    fn test_audit_log_records_issue_and_verify() {
        let manager = ChallengeManager::new([2u8; 32]).with_pow_difficulty(8);
        let challenge = match manager.issue_pow_challenge() {
            ChallengeType::ProofOfWork(c) => c,
            _ => return,
        };
        let nonce = challenge.solve();
        let _ = manager.verify_pow_response(&challenge, &nonce, Some("client-a"));

        let audit = manager.audit_records();
        assert!(audit.iter().any(|r| r.outcome == "issued"));
        assert!(audit.iter().any(|r| r.outcome == "passed"));
    }
}
