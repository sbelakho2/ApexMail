//! Challenge implementations for bot detection
//!
//! Provides various challenge mechanisms to distinguish legitimate users from bots.

use rand::{thread_rng, Rng};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::{HashMap, VecDeque};
use std::time::{Duration, SystemTime, UNIX_EPOCH};
use subtle::ConstantTimeEq;

const MAX_USED_RESPONSES: usize = 100_000;
const USED_RESPONSE_TTL_SECS: u64 = 3600;

#[derive(Debug, Default)]
struct UsedResponseCache {
    entries: HashMap<String, u64>,
    order: VecDeque<String>,
}

impl UsedResponseCache {
    fn contains(&mut self, key: &str, now: u64) -> bool {
        self.prune(now);
        self.entries.contains_key(key)
    }

    fn insert(&mut self, key: String, now: u64) -> bool {
        self.prune(now);
        if self.entries.contains_key(&key) {
            return false;
        }
        self.entries.insert(key.clone(), now);
        self.order.push_back(key);
        while self.entries.len() > MAX_USED_RESPONSES {
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            } else {
                break;
            }
        }
        true
    }

    fn prune(&mut self, now: u64) {
        while let Some(oldest) = self.order.front() {
            let expired = self
                .entries
                .get(oldest)
                .is_none_or(|seen_at| now.saturating_sub(*seen_at) > USED_RESPONSE_TTL_SECS);
            if !expired {
                break;
            }
            if let Some(oldest) = self.order.pop_front() {
                self.entries.remove(&oldest);
            }
        }
    }
}

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
        self.expected_hash
            .as_bytes()
            .ct_eq(solution_hash.as_bytes())
            .unwrap_u8()
            == 1
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

        // Verify signature using constant-time comparison (E-107 fix:prevents timing attacks)
        let expected_sig = hmac_sign(secret, token.as_bytes());
        if signature
            .as_bytes()
            .ct_eq(expected_sig.as_bytes())
            .unwrap_u8()
            != 1
        {
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
    used_responses: parking_lot::RwLock<UsedResponseCache>,
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
            used_responses: parking_lot::RwLock::new(UsedResponseCache::default()),
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

        Some(ChallengeType::Captcha(CaptchaChallenge::generate(
            provider, &site_key,
        )))
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
        let now = current_timestamp();
        {
            let mut used = self.used_responses.write();
            if used.contains(&response_key, now) {
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

        let expired = now > challenge.created_at + challenge.time_limit_secs as u64;
        let valid = !expired && challenge.verify(nonce);

        let replayed = valid && !self.used_responses.write().insert(response_key, now);
        if replayed {
            self.record_audit(ChallengeAuditRecord {
                challenge_id: challenge.challenge_id.clone(),
                challenge_type: "pow".into(),
                outcome: "replay".into(),
                client_fingerprint: client_fingerprint.map(ToString::to_string),
                timestamp: now,
            });
            return ChallengeVerifyResult {
                valid: false,
                replayed: true,
                expired,
            };
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

    /// Verify a `decision::PowChallenge` response (the challenge type the
    /// middleware hands to clients) with replay protection and audit
    /// logging.
    ///
    /// Fix I: `DdosProtector::evaluate` previously issued challenges with a
    /// constant prefix and no replay cache — a single solved nonce could be
    /// replayed forever. This routes verification through the same
    /// UsedResponseCache as the managed challenges.
    pub fn verify_decision_pow(
        &self,
        challenge: &crate::decision::PowChallenge,
        nonce: u64,
        client_fingerprint: Option<&str>,
    ) -> ChallengeVerifyResult {
        let nonce_str = nonce.to_string();
        let response_key = format!("pow:{}:{}", challenge.id, hash_result(&nonce_str));
        let now = current_timestamp();
        {
            let mut used = self.used_responses.write();
            if used.contains(&response_key, now) {
                self.record_audit(ChallengeAuditRecord {
                    challenge_id: challenge.id.clone(),
                    challenge_type: "pow".into(),
                    outcome: "replay".into(),
                    client_fingerprint: client_fingerprint.map(ToString::to_string),
                    timestamp: now,
                });
                return ChallengeVerifyResult {
                    valid: false,
                    replayed: true,
                    expired: false,
                };
            }
        }

        let expired = now > challenge.expires_at;
        // Hash format matches `decision::PowChallenge::verify`:
        // sha256("<data>:<nonce>") with `difficulty` leading zero bits.
        let valid =
            !expired && decision_pow_hash_valid(&challenge.data, challenge.difficulty, &nonce_str);

        let replayed = valid && !self.used_responses.write().insert(response_key, now);
        if replayed {
            self.record_audit(ChallengeAuditRecord {
                challenge_id: challenge.id.clone(),
                challenge_type: "pow".into(),
                outcome: "replay".into(),
                client_fingerprint: client_fingerprint.map(ToString::to_string),
                timestamp: now,
            });
            return ChallengeVerifyResult {
                valid: false,
                replayed: true,
                expired,
            };
        }

        self.record_audit(ChallengeAuditRecord {
            challenge_id: challenge.id.clone(),
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
        let now = current_timestamp();
        {
            let mut used = self.used_responses.write();
            if used.contains(&response_key, now) {
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

        let expired = now > challenge.created_at + challenge.time_limit_secs as u64;
        let valid = !expired && challenge.verify(solution);

        let replayed = valid && !self.used_responses.write().insert(response_key, now);
        if replayed {
            self.record_audit(ChallengeAuditRecord {
                challenge_id: challenge.challenge_id.clone(),
                challenge_type: "js".into(),
                outcome: "replay".into(),
                client_fingerprint: client_fingerprint.map(ToString::to_string),
                timestamp: now,
            });
            return ChallengeVerifyResult {
                valid: false,
                replayed: true,
                expired,
            };
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

/// Leading-zero-bits check for `decision::PowChallenge` solutions:
/// sha256("<data>:<nonce>") must start with `difficulty` zero bits.
fn decision_pow_hash_valid(data: &str, difficulty: u8, nonce: &str) -> bool {
    let input = format!("{}:{}", data, nonce);
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let hash = hasher.finalize();

    let required_bytes = (difficulty / 8) as usize;
    let remaining_bits = difficulty % 8;
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

fn hash_result(s: &str) -> String {
    let mut hasher = Sha256::new();
    hasher.update(s.as_bytes());
    hex::encode(hasher.finalize())
}

fn hmac_sign(secret: &[u8; 32], data: &[u8]) -> String {
    use hmac::{Hmac, Mac};
    use sha2::Sha256;

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

    #[test]
    fn used_response_cache_evicts_oldest_entries() {
        let mut cache = UsedResponseCache::default();
        for idx in 0..=MAX_USED_RESPONSES {
            assert!(cache.insert(format!("response-{idx}"), 10));
        }
        assert!(!cache.contains("response-0", 10));
        assert!(cache.contains(&format!("response-{MAX_USED_RESPONSES}"), 10));
    }

    #[test]
    fn used_response_cache_expires_old_entries() {
        let mut cache = UsedResponseCache::default();
        assert!(cache.insert("response".to_string(), 10));
        assert!(!cache.contains("response", 10 + USED_RESPONSE_TTL_SECS + 1));
    }

    // ── Fix I:decision::PowChallenge replay protection ──────────────

    fn easy_decision_pow() -> crate::decision::PowChallenge {
        crate::decision::PowChallenge {
            id: "challenge-fixed".to_string(),
            data: "random-prefix-0123456789abcdef".to_string(),
            difficulty: 0, // trivially solvable for test speed
            expires_at: current_timestamp() + 300,
            expected_time_ms: 1,
        }
    }

    #[test]
    fn decision_pow_solved_nonce_rejected_on_replay() {
        let manager = ChallengeManager::new([3u8; 32]);
        let challenge = easy_decision_pow();

        let first = manager.verify_decision_pow(&challenge, 42, Some("10.0.0.1"));
        assert!(first.valid, "first submission must pass");
        assert!(!first.replayed);

        let second = manager.verify_decision_pow(&challenge, 42, Some("10.0.0.1"));
        assert!(
            !second.valid && second.replayed,
            "replayed nonce must be rejected"
        );

        // A different nonce for the same challenge is still fine.
        let third = manager.verify_decision_pow(&challenge, 43, Some("10.0.0.1"));
        assert!(third.valid);
    }

    #[test]
    fn decision_pow_wrong_nonce_fails() {
        let manager = ChallengeManager::new([4u8; 32]);
        let mut challenge = easy_decision_pow();
        challenge.difficulty = 20; // infeasible to hit by luck
        let result = manager.verify_decision_pow(&challenge, 1, None);
        assert!(!result.valid);
        assert!(!result.replayed);
    }

    #[test]
    fn decision_pow_expired_challenge_rejected() {
        let manager = ChallengeManager::new([5u8; 32]);
        let mut challenge = easy_decision_pow();
        challenge.expires_at = current_timestamp().saturating_sub(1);
        let result = manager.verify_decision_pow(&challenge, 42, None);
        assert!(!result.valid);
        assert!(result.expired);
    }
}
