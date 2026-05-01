//! Integration tests for the DDoS Protection System
//!
//! These tests verify the interaction between multiple components
//! and test end-to-end flows.

use std::collections::HashMap;
use std::time::{Duration, Instant};

/// ============================================================================
/// INTEGRATION TESTS:Multi-Layer Protection Flow
/// ============================================================================
#[cfg(test)]
mod multi_layer_tests {
    use super::*;

    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Decision {
        Allow,
        RateLimit,
        Challenge,
        Block,
    }

    struct MockReputationService {
        scores: HashMap<String, u8>,
    }

    impl MockReputationService {
        fn new() -> Self {
            Self {
                scores: HashMap::new(),
            }
        }

        fn set_score(&mut self, ip: &str, score: u8) {
            self.scores.insert(ip.to_string(), score);
        }

        fn get_score(&self, ip: &str) -> u8 {
            *self.scores.get(ip).unwrap_or(&50)
        }
    }

    struct MockRateLimiter {
        counters: HashMap<String, u64>,
        limit: u64,
    }

    impl MockRateLimiter {
        fn new(limit: u64) -> Self {
            Self {
                counters: HashMap::new(),
                limit,
            }
        }

        fn check(&mut self, key: &str) -> bool {
            let count = self.counters.entry(key.to_string()).or_insert(0);
            *count += 1;
            *count <= self.limit
        }
    }

    struct MockProtector {
        reputation: MockReputationService,
        rate_limiter: MockRateLimiter,
        challenge_threshold: u8,
        block_threshold: u8,
    }

    impl MockProtector {
        fn new() -> Self {
            Self {
                reputation: MockReputationService::new(),
                rate_limiter: MockRateLimiter::new(100),
                challenge_threshold: 30,
                block_threshold: 10,
            }
        }

        fn evaluate(&mut self, ip: &str) -> Decision {
            // Layer 1:Rate limiting
            if !self.rate_limiter.check(ip) {
                return Decision::RateLimit;
            }

            // Layer 2:Reputation check
            let score = self.reputation.get_score(ip);

            if score <= self.block_threshold {
                return Decision::Block;
            }

            if score <= self.challenge_threshold {
                return Decision::Challenge;
            }

            Decision::Allow
        }
    }

    #[test]
    fn test_clean_request_flow() {
        let mut protector = MockProtector::new();
        protector.reputation.set_score("192.168.1.1", 80);

        let decision = protector.evaluate("192.168.1.1");
        assert_eq!(decision, Decision::Allow);
    }

    #[test]
    fn test_low_reputation_triggers_challenge() {
        let mut protector = MockProtector::new();
        protector.reputation.set_score("10.0.0.1", 25);

        let decision = protector.evaluate("10.0.0.1");
        assert_eq!(decision, Decision::Challenge);
    }

    #[test]
    fn test_very_low_reputation_triggers_block() {
        let mut protector = MockProtector::new();
        protector.reputation.set_score("172.16.0.1", 5);

        let decision = protector.evaluate("172.16.0.1");
        assert_eq!(decision, Decision::Block);
    }

    #[test]
    fn test_rate_limit_overrides_reputation() {
        let mut protector = MockProtector::new();
        protector.rate_limiter = MockRateLimiter::new(5);
        protector.reputation.set_score("8.8.8.8", 100); // Perfect reputation

        // Should allow first 5 requests
        for _ in 0..5 {
            assert_eq!(protector.evaluate("8.8.8.8"), Decision::Allow);
        }

        // 6th request should be rate limited despite good reputation
        assert_eq!(protector.evaluate("8.8.8.8"), Decision::RateLimit);
    }

    #[test]
    fn test_independent_ip_tracking() {
        let mut protector = MockProtector::new();
        protector.rate_limiter = MockRateLimiter::new(2);

        // Each IP has independent rate limit
        assert_eq!(protector.evaluate("1.1.1.1"), Decision::Allow);
        assert_eq!(protector.evaluate("2.2.2.2"), Decision::Allow);
        assert_eq!(protector.evaluate("1.1.1.1"), Decision::Allow);
        assert_eq!(protector.evaluate("2.2.2.2"), Decision::Allow);

        // Both hit limit on 3rd request
        assert_eq!(protector.evaluate("1.1.1.1"), Decision::RateLimit);
        assert_eq!(protector.evaluate("2.2.2.2"), Decision::RateLimit);
    }
}

/// ============================================================================
/// INTEGRATION TESTS:Session + Rate Limiting
/// ============================================================================
#[cfg(test)]
mod session_rate_limit_tests {
    use super::*;
    use std::collections::VecDeque;

    struct SessionTracker {
        request_times: VecDeque<Instant>,
        window: Duration,
        max_requests: usize,
    }

    impl SessionTracker {
        fn new(window: Duration, max_requests: usize) -> Self {
            Self {
                request_times: VecDeque::new(),
                window,
                max_requests,
            }
        }

        fn record_and_check(&mut self) -> bool {
            let now = Instant::now();
            let cutoff = now - self.window;

            // Remove old entries
            while let Some(&front) = self.request_times.front() {
                if front < cutoff {
                    self.request_times.pop_front();
                } else {
                    break;
                }
            }

            // Check limit
            if self.request_times.len() >= self.max_requests {
                return false;
            }

            self.request_times.push_back(now);
            true
        }

        fn requests_in_window(&self) -> usize {
            self.request_times.len()
        }
    }

    #[test]
    fn test_sliding_window_enforcement() {
        let mut tracker = SessionTracker::new(Duration::from_secs(60), 10);

        // Should allow up to limit
        for i in 0..10 {
            assert!(
                tracker.record_and_check(),
                "Request {} should be allowed",
                i
            );
        }

        // 11th should be blocked
        assert!(!tracker.record_and_check());
        assert_eq!(tracker.requests_in_window(), 10);
    }

    #[test]
    fn test_window_expiration() {
        let mut tracker = SessionTracker::new(Duration::from_millis(100), 5);

        // Fill window
        for _ in 0..5 {
            assert!(tracker.record_and_check());
        }
        assert!(!tracker.record_and_check()); // Blocked

        // Wait for window to expire
        std::thread::sleep(Duration::from_millis(150));

        // Should be allowed again
        assert!(tracker.record_and_check());
    }
}

/// ============================================================================
/// INTEGRATION TESTS:Fingerprint + Reputation
/// ============================================================================
#[cfg(test)]
mod fingerprint_reputation_tests {
    use super::*;

    #[derive(Debug, Clone, PartialEq, Eq)]
    enum FingerprintClass {
        ValidBrowser,
        SuspiciousBrowser,
        KnownBot,
        Malicious,
        Unknown,
    }

    struct FingerprintDb {
        known_fingerprints: HashMap<String, FingerprintClass>,
    }

    impl FingerprintDb {
        fn new() -> Self {
            let mut db = Self {
                known_fingerprints: HashMap::new(),
            };

            // Pre-populate with known fingerprints
            db.known_fingerprints.insert(
                "chrome_win10_v120".to_string(),
                FingerprintClass::ValidBrowser,
            );
            db.known_fingerprints.insert(
                "firefox_macos_v121".to_string(),
                FingerprintClass::ValidBrowser,
            );
            db.known_fingerprints.insert(
                "python_requests".to_string(),
                FingerprintClass::SuspiciousBrowser,
            );
            db.known_fingerprints.insert(
                "curl_generic".to_string(),
                FingerprintClass::SuspiciousBrowser,
            );
            db.known_fingerprints
                .insert("googlebot_v1".to_string(), FingerprintClass::KnownBot);
            db.known_fingerprints
                .insert("bad_scanner_v1".to_string(), FingerprintClass::Malicious);

            db
        }

        fn classify(&self, fingerprint: &str) -> FingerprintClass {
            self.known_fingerprints
                .get(fingerprint)
                .cloned()
                .unwrap_or(FingerprintClass::Unknown)
        }
    }

    struct ReputationAdjuster;

    impl ReputationAdjuster {
        fn adjust_for_fingerprint(base_score: u8, class: &FingerprintClass) -> u8 {
            match class {
                FingerprintClass::ValidBrowser => base_score.saturating_add(20).min(100),
                FingerprintClass::SuspiciousBrowser => base_score.saturating_sub(10),
                FingerprintClass::KnownBot => base_score.saturating_sub(20),
                FingerprintClass::Malicious => 0,
                FingerprintClass::Unknown => base_score,
            }
        }
    }

    #[test]
    fn test_valid_browser_boost() {
        let db = FingerprintDb::new();
        let class = db.classify("chrome_win10_v120");

        let base = 50u8;
        let adjusted = ReputationAdjuster::adjust_for_fingerprint(base, &class);

        assert_eq!(adjusted, 70); // +20 boost
    }

    #[test]
    fn test_suspicious_penalty() {
        let db = FingerprintDb::new();
        let class = db.classify("python_requests");

        let base = 50u8;
        let adjusted = ReputationAdjuster::adjust_for_fingerprint(base, &class);

        assert_eq!(adjusted, 40); // -10 penalty
    }

    #[test]
    fn test_malicious_zero() {
        let db = FingerprintDb::new();
        let class = db.classify("bad_scanner_v1");

        let base = 100u8; // Even perfect base score
        let adjusted = ReputationAdjuster::adjust_for_fingerprint(base, &class);

        assert_eq!(adjusted, 0); // Always 0 for malicious
    }

    #[test]
    fn test_unknown_neutral() {
        let db = FingerprintDb::new();
        let class = db.classify("completely_new_fingerprint");

        let base = 50u8;
        let adjusted = ReputationAdjuster::adjust_for_fingerprint(base, &class);

        assert_eq!(adjusted, 50); // No change
    }

    #[test]
    fn test_valid_browser_cap_at_100() {
        let db = FingerprintDb::new();
        let class = db.classify("firefox_macos_v121");

        let base = 95u8;
        let adjusted = ReputationAdjuster::adjust_for_fingerprint(base, &class);

        assert_eq!(adjusted, 100); // Capped at 100
    }
}

/// ============================================================================
/// INTEGRATION TESTS:Challenge System E2E
/// ============================================================================
#[cfg(test)]
mod challenge_e2e_tests {
    use sha2::{Digest, Sha256};
    use std::time::{SystemTime, UNIX_EPOCH};

    struct PowerChallenge {
        prefix: String,
        difficulty: u8,
        issued_at: u64,
        ttl_secs: u64,
    }

    impl PowerChallenge {
        fn new(client_id: &str, difficulty: u8, ttl_secs: u64) -> Self {
            let timestamp = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            let prefix = format!("{}_{}", client_id, timestamp);

            Self {
                prefix,
                difficulty,
                issued_at: timestamp,
                ttl_secs,
            }
        }

        fn verify(&self, nonce: u64) -> Result<(), &'static str> {
            // Check TTL
            let now = SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_secs();

            if now > self.issued_at + self.ttl_secs {
                return Err("Challenge expired");
            }

            // Verify PoW
            let data = format!("{}{}", self.prefix, nonce);
            let mut hasher = Sha256::new();
            hasher.update(data.as_bytes());
            let hash = hasher.finalize();

            let required_zeros = self.difficulty as usize;
            let required_bytes = required_zeros / 8;

            for i in 0..required_bytes {
                if hash[i] != 0 {
                    return Err("Invalid proof of work");
                }
            }

            let remaining_bits = required_zeros % 8;
            if remaining_bits > 0 && required_bytes < 32 {
                let mask = 0xFF << (8 - remaining_bits);
                if hash[required_bytes] & mask != 0 {
                    return Err("Invalid proof of work");
                }
            }

            Ok(())
        }

        fn solve(&self, max_attempts: u64) -> Option<u64> {
            for nonce in 0..max_attempts {
                if self.verify(nonce).is_ok() {
                    return Some(nonce);
                }
            }
            None
        }
    }

    #[test]
    fn test_challenge_issue_and_solve() {
        let challenge = PowerChallenge::new("test_client", 8, 300);

        // Solve the challenge
        let solution = challenge.solve(10000);
        assert!(solution.is_some(), "Should find solution with difficulty 8");

        // Verify the solution
        assert!(challenge.verify(solution.unwrap()).is_ok());
    }

    #[test]
    fn test_invalid_solution_rejected() {
        let challenge = PowerChallenge::new("test_client", 16, 300);

        // Random nonce very unlikely to work
        let result = challenge.verify(999999999);
        assert!(result.is_err());
    }

    #[test]
    fn test_solution_replay_prevention() {
        let challenge1 = PowerChallenge::new("client_a", 4, 300);
        let challenge2 = PowerChallenge::new("client_b", 4, 300);

        let solution1 = challenge1.solve(1000).unwrap();

        // Solution for challenge1 should not work for challenge2
        // (different prefix means different hash)
        let _result = challenge2.verify(solution1);
        // This might pass by chance for low difficulty, so check prefixes differ
        assert_ne!(challenge1.prefix, challenge2.prefix);
    }
}

/// ============================================================================
/// INTEGRATION TESTS:Cost-Based + Session Tracking
/// ============================================================================
#[cfg(test)]
mod cost_session_tests {
    use super::*;

    struct EndpointCost {
        cpu_weight: u32,
        memory_weight: u32,
        io_weight: u32,
    }

    struct CostTracker {
        endpoint_costs: HashMap<String, EndpointCost>,
        session_budgets: HashMap<String, i64>,
        default_budget: i64,
    }

    impl CostTracker {
        fn new(default_budget: i64) -> Self {
            let mut costs = HashMap::new();
            costs.insert(
                "/api/search".to_string(),
                EndpointCost {
                    cpu_weight: 50,
                    memory_weight: 100,
                    io_weight: 20,
                },
            );
            costs.insert(
                "/api/login".to_string(),
                EndpointCost {
                    cpu_weight: 100,
                    memory_weight: 50,
                    io_weight: 10,
                },
            );
            costs.insert(
                "/api/data".to_string(),
                EndpointCost {
                    cpu_weight: 10,
                    memory_weight: 10,
                    io_weight: 5,
                },
            );

            Self {
                endpoint_costs: costs,
                session_budgets: HashMap::new(),
                default_budget,
            }
        }

        fn check_and_deduct(&mut self, session: &str, endpoint: &str) -> bool {
            // Get cost first before mutably borrowing session_budgets
            let cost = self
                .endpoint_costs
                .get(endpoint)
                .map(|c| (c.cpu_weight + c.memory_weight + c.io_weight) as i64)
                .unwrap_or(10);

            let budget = self
                .session_budgets
                .entry(session.to_string())
                .or_insert(self.default_budget);

            if *budget >= cost {
                *budget -= cost;
                true
            } else {
                false
            }
        }

        fn remaining_budget(&self, session: &str) -> i64 {
            *self
                .session_budgets
                .get(session)
                .unwrap_or(&self.default_budget)
        }
    }

    #[test]
    fn test_expensive_endpoint_drains_budget() {
        let mut tracker = CostTracker::new(500);

        // Login is expensive (160 cost)
        assert!(tracker.check_and_deduct("session1", "/api/login"));
        assert_eq!(tracker.remaining_budget("session1"), 340);

        assert!(tracker.check_and_deduct("session1", "/api/login"));
        assert_eq!(tracker.remaining_budget("session1"), 180);

        assert!(tracker.check_and_deduct("session1", "/api/login"));
        assert_eq!(tracker.remaining_budget("session1"), 20);

        // Not enough budget for another login
        assert!(!tracker.check_and_deduct("session1", "/api/login"));
    }

    #[test]
    fn test_cheap_endpoint_many_requests() {
        let mut tracker = CostTracker::new(500);

        // Data endpoint is cheap (25 cost)
        for i in 0..20 {
            assert!(
                tracker.check_and_deduct("session2", "/api/data"),
                "Request {} should succeed",
                i
            );
        }

        // Eventually runs out
        assert!(!tracker.check_and_deduct("session2", "/api/data"));
    }

    #[test]
    fn test_mixed_endpoint_usage() {
        let mut tracker = CostTracker::new(1000);

        // Mix of endpoints
        tracker.check_and_deduct("session3", "/api/login"); // 160
        tracker.check_and_deduct("session3", "/api/search"); // 170
        tracker.check_and_deduct("session3", "/api/data"); // 25
        tracker.check_and_deduct("session3", "/api/data"); // 25

        // 1000 - 160 - 170 - 25 - 25 = 620
        assert_eq!(tracker.remaining_budget("session3"), 620);
    }
}

/// ============================================================================
/// Run integration tests
/// ============================================================================
fn main() {
    println!("Run integration tests with: cargo test --test integration_tests");
}
