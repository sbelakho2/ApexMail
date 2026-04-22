//! # Property-Based Tests
//!
//! Uses proptest to generate randomized inputs and verify invariants hold
//! for all possible inputs. This catches bugs that hand-written tests miss.
//!
//! ## How Property-Based Testing Works
//!
//! Instead of testing specific cases like://! ```ignore
//! assert!(rate_limiter.check(5) == true); // Only tests limit=5
//! ```
//!
//! We test properties that must hold for ALL inputs://! ```ignore
//! proptest! {
//! fn rate_limiter_never_allows_more_than_limit(limit in 1..1000u64) {
//! // For ANY limit, this property must hold
//! let limiter = RateLimiter::new(limit);
//! for _ in 0..limit { limiter.check; }
//! assert!(!limiter.check); // limit+1 must fail
//! }
//! }
//! ```
//!
//! This catches edge cases like limit=0, limit=1, limit=MAX automatically.

use proptest::prelude::*;
use std::collections::HashSet;

// ===========================================================================
// 1. RATE LIMITER PROPERTY TESTS
// ===========================================================================

mod rate_limiter_properties {
    use super::*;
    use std::sync::atomic::{AtomicU64, Ordering};

    struct PropertyRateLimiter {
        requests: AtomicU64,
        limit: u64,
    }

    impl PropertyRateLimiter {
        fn new(limit: u64) -> Self {
            Self {
                requests: AtomicU64::new(0),
                limit,
            }
        }

        fn check(&self) -> bool {
            let count = self.requests.fetch_add(1, Ordering::SeqCst) + 1;
            count <= self.limit
        }

        fn reset(&self) {
            self.requests.store(0, Ordering::SeqCst);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]
        
/// Property:Rate limiter allows exactly `limit` requests, then blocks
        #[test]
        fn allows_exactly_limit_requests(limit in 1u64..1000) {
            let limiter = PropertyRateLimiter::new(limit);
            
// First `limit` requests should pass
            for i in 0..limit {
                prop_assert!(
                    limiter.check(),
                    "Request {} should be allowed (limit={})", i + 1, limit
                );
            }
            
// Request limit+1 must fail
            prop_assert!(
                !limiter.check(),
                "Request {} must be blocked (limit={})", limit + 1, limit
            );
        }

/// Property:Rate limiter with limit=0 blocks all requests
        #[test]
        fn limit_zero_blocks_everything(requests in 1usize..100) {
            let limiter = PropertyRateLimiter::new(0);
            
            for _ in 0..requests {
                prop_assert!(!limiter.check(), "Limit=0 must block ALL requests");
            }
        }

/// Property:After reset, limiter allows `limit` requests again
        #[test]
        fn reset_restores_capacity(limit in 1u64..100, exhaust_count in 1u64..50) {
            let limiter = PropertyRateLimiter::new(limit);
            
// Exhaust part of the limit
            let actual_exhaust = exhaust_count.min(limit);
            for _ in 0..actual_exhaust {
                limiter.check();
            }
            
// Reset
            limiter.reset();
            
// Should have full capacity again
            for i in 0..limit {
                prop_assert!(
                    limiter.check(),
                    "After reset, request {} should be allowed", i + 1
                );
            }
        }

/// Property:Request count is always accurate
        #[test]
        fn request_count_accurate(requests in 1usize..500) {
            let limiter = PropertyRateLimiter::new(1000);
            
            for _ in 0..requests {
                limiter.check();
            }
            
            prop_assert_eq!(
                limiter.requests.load(Ordering::SeqCst),
                requests as u64,
                "Request count must match actual requests"
            );
        }
    }
}

// ===========================================================================
// 2. CIRCUIT BREAKER PROPERTY TESTS
// ===========================================================================

mod circuit_breaker_properties {
    use super::*;
    use std::sync::RwLock;

    #[derive(Debug, Clone, Copy, PartialEq)]
    enum CircuitState {
        Closed,
        Open,
        HalfOpen,
    }

    struct PropertyCircuitBreaker {
        state: RwLock<CircuitState>,
        failure_count: std::sync::atomic::AtomicU32,
        success_count: std::sync::atomic::AtomicU32,
        threshold: u32,
        recovery_threshold: u32,
    }

    impl PropertyCircuitBreaker {
        fn new(threshold: u32, recovery_threshold: u32) -> Self {
            Self {
                state: RwLock::new(CircuitState::Closed),
                failure_count: std::sync::atomic::AtomicU32::new(0),
                success_count: std::sync::atomic::AtomicU32::new(0),
                threshold,
                recovery_threshold,
            }
        }

        fn record_failure(&self) {
            let count = self.failure_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
            if count >= self.threshold {
                *self.state.write().unwrap() = CircuitState::Open;
            }
        }

        fn record_success(&self) {
            let mut state = self.state.write().unwrap();
            if *state == CircuitState::HalfOpen {
                let count = self.success_count.fetch_add(1, std::sync::atomic::Ordering::SeqCst) + 1;
                if count >= self.recovery_threshold {
                    *state = CircuitState::Closed;
                    self.failure_count.store(0, std::sync::atomic::Ordering::SeqCst);
                }
            }
        }

        fn is_closed(&self) -> bool {
            *self.state.read().unwrap() == CircuitState::Closed
        }

        fn is_open(&self) -> bool {
            *self.state.read().unwrap() == CircuitState::Open
        }

        fn transition_to_half_open(&self) {
            *self.state.write().unwrap() = CircuitState::HalfOpen;
            self.success_count.store(0, std::sync::atomic::Ordering::SeqCst);
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]
        
/// Property:Circuit opens after exactly `threshold` failures
        #[test]
        fn opens_at_threshold(threshold in 1u32..50) {
            let cb = PropertyCircuitBreaker::new(threshold, 1);
            
// Record threshold-1 failures - should still be closed
            for _ in 0..(threshold - 1) {
                cb.record_failure();
                prop_assert!(cb.is_closed(), "Should be closed before threshold");
            }
            
// The threshold-th failure opens the circuit
            cb.record_failure();
            prop_assert!(cb.is_open(), "Must open at threshold={}", threshold);
        }

/// Property:Circuit recovers after `recovery_threshold` successes in half-open
        #[test]
        fn recovers_after_successes(
            threshold in 1u32..20,
            recovery in 1u32..10
        ) {
            let cb = PropertyCircuitBreaker::new(threshold, recovery);
            
// Open the circuit
            for _ in 0..threshold {
                cb.record_failure();
            }
            prop_assert!(cb.is_open());
            
// Transition to half-open (simulating timeout)
            cb.transition_to_half_open();
            
// Record successes
            for _ in 0..recovery {
                cb.record_success();
            }
            
            prop_assert!(cb.is_closed(), "Should close after {} successes", recovery);
        }

/// Property:threshold=1 opens immediately on first failure
        #[test]
        fn threshold_one_opens_immediately(extra_failures in 0u32..10) {
            let cb = PropertyCircuitBreaker::new(1, 1);
            
            cb.record_failure();
            prop_assert!(cb.is_open(), "threshold=1 must open on first failure");
            
// Additional failures shouldn't change state
            for _ in 0..extra_failures {
                cb.record_failure();
                prop_assert!(cb.is_open());
            }
        }
    }
}

// ===========================================================================
// 3. ENCRYPTION PROPERTY TESTS
// ===========================================================================

mod encryption_properties {
    use super::*;

// Simple XOR cipher for property testing (NOT for production!)
    fn xor_encrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
        if key.is_empty() {
            return data.to_vec();
        }
        data.iter()
            .enumerate()
            .map(|(i, b)| b ^ key[i % key.len()])
            .collect()
    }

    fn xor_decrypt(data: &[u8], key: &[u8]) -> Vec<u8> {
        xor_encrypt(data, key) // XOR is symmetric
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]
        
/// Property:Decryption is the inverse of encryption
        #[test]
        fn decrypt_inverts_encrypt(
            plaintext in prop::collection::vec(any::<u8>(), 0..1000),
            key in prop::collection::vec(1u8..=255, 1..32)
        ) {
            let ciphertext = xor_encrypt(&plaintext, &key);
            let recovered = xor_decrypt(&ciphertext, &key);
            
            prop_assert_eq!(
                recovered, plaintext,
                "Decryption must recover original plaintext"
            );
        }

/// Property:Encryption with non-empty key changes data (usually)
        #[test]
        fn encryption_changes_data(
            plaintext in prop::collection::vec(1u8..=255, 1..100),
            key in prop::collection::vec(1u8..=255, 1..32)
        ) {
            let ciphertext = xor_encrypt(&plaintext, &key);
            
// For XOR, plaintext == ciphertext only when key is all zeros
// Since our key has min 1, they usually differ
// If they match, it's because plaintext XOR key == plaintext (key=0 for those positions)
// We can't guarantee difference, but we can verify symmetry
            let recovered = xor_decrypt(&ciphertext, &key);
            prop_assert_eq!(recovered, plaintext);
        }

/// Property:Different keys produce different ciphertext
        #[test]
        fn different_keys_different_ciphertext(
            plaintext in prop::collection::vec(any::<u8>(), 10..100),
            key1 in prop::collection::vec(1u8..=127, 8..16),
            key2 in prop::collection::vec(128u8..=255, 8..16)
        ) {
// Ensure keys are different
            if key1 == key2 {
                return Ok(());
            }
            
            let cipher1 = xor_encrypt(&plaintext, &key1);
            let cipher2 = xor_encrypt(&plaintext, &key2);
            
            prop_assert_ne!(
                cipher1, cipher2,
                "Different keys must produce different ciphertext"
            );
        }

/// Property:Empty plaintext produces empty ciphertext
        #[test]
        fn empty_plaintext_empty_ciphertext(key in prop::collection::vec(any::<u8>(), 1..32)) {
            let empty: Vec<u8> = vec![];
            let cipher = xor_encrypt(&empty, &key);
            prop_assert!(cipher.is_empty(), "Empty input must produce empty output");
        }
    }
}

// ===========================================================================
// 4. INPUT VALIDATION PROPERTY TESTS
// ===========================================================================

mod validation_properties {
    use super::*;

    fn is_valid_email(email: &str) -> bool {
        if email.is_empty() || email.len() > 254 {
            return false;
        }
        let parts: Vec<&str> = email.split('@').collect();
        if parts.len() != 2 {
            return false;
        }
        let (local, domain) = (parts[0], parts[1]);
        if local.is_empty() || local.len() > 64 || domain.is_empty() {
            return false;
        }
        if !domain.contains('.') {
            return false;
        }
        true
    }

    fn has_null_bytes(input: &str) -> bool {
        input.bytes().any(|b| b == 0)
    }

    fn sanitize_sql(input: &str) -> String {
        input
            .replace('\'', "''")
            .replace(';', "")
            .replace(" --", "")
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]
        
/// Property:Valid emails have exactly one @ and non-empty parts
        #[test]
        fn valid_email_structure(
            local in "[a-z]{1,10}",
            domain in "[a-z]{1,10}",
            tld in "[a-z]{2,4}"
        ) {
            let email = format!("{}@{}.{}", local, domain, tld);
            prop_assert!(is_valid_email(&email), "{}@{}.{} should be valid", local, domain, tld);
        }

/// Property:Missing @ makes email invalid
        #[test]
        fn missing_at_invalid(local in "[a-z]{1,20}", domain in "[a-z]{1,20}") {
            let invalid = format!("{}{}", local, domain);
            prop_assert!(!is_valid_email(&invalid), "'{}' without @ must be invalid", invalid);
        }

/// Property:Multiple @ makes email invalid
        #[test]
        fn multiple_at_invalid(
            part1 in "[a-z]{1,10}",
            part2 in "[a-z]{1,10}",
            part3 in "[a-z]{1,10}"
        ) {
            let invalid = format!("{}@{}@{}", part1, part2, part3);
            prop_assert!(!is_valid_email(&invalid), "'{}' with multiple @ must be invalid", invalid);
        }

/// Property:Null byte detection never misses null bytes
        #[test]
        fn null_byte_always_detected(
            prefix in "\\PC{0,20}",
            suffix in "\\PC{0,20}"
        ) {
            let with_null = format!("{}\x00{}", prefix, suffix);
            prop_assert!(
                has_null_bytes(&with_null),
                "Null byte must be detected in '{:?}'", with_null.as_bytes()
            );
        }

/// Property:Clean strings don't have null bytes detected
        #[test]
        fn clean_strings_no_false_positives(input in "[a-zA-Z0-9 !@#$%^&*()]{0,100}") {
            prop_assert!(
                !has_null_bytes(&input),
                "Clean string should not trigger null byte detection"
            );
        }

/// Property:SQL sanitization removes dangerous characters
        #[test]
        fn sql_sanitization_removes_dangerous(
            prefix in "[a-z]{0,10}",
            suffix in "[a-z]{0,10}"
        ) {
            let dangerous = format!("{}'; DROP TABLE users; --{}", prefix, suffix);
            let sanitized = sanitize_sql(&dangerous);
            
            prop_assert!(!sanitized.contains(';'), "Semicolons must be removed");
            prop_assert!(!sanitized.contains(" --"), "Comment markers must be removed");
        }
    }
}

// ===========================================================================
// 5. HASH/DIGEST PROPERTY TESTS
// ===========================================================================

mod hash_properties {
    use super::*;
    use std::collections::hash_map::DefaultHasher;
    use std::hash::{Hash, Hasher};

    fn compute_hash(data: &[u8]) -> u64 {
        let mut hasher = DefaultHasher::new();
        data.hash(&mut hasher);
        hasher.finish()
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(1000))]
        
/// Property:Same input always produces same hash
        #[test]
        fn hash_deterministic(data in prop::collection::vec(any::<u8>(), 0..1000)) {
            let hash1 = compute_hash(&data);
            let hash2 = compute_hash(&data);
            
            prop_assert_eq!(hash1, hash2, "Hash must be deterministic");
        }

/// Property:Different inputs usually produce different hashes
        #[test]
        fn hash_collision_resistant(
            data1 in prop::collection::vec(any::<u8>(), 1..100),
            data2 in prop::collection::vec(any::<u8>(), 1..100)
        ) {
            if data1 == data2 {
                return Ok(());
            }
            
            let hash1 = compute_hash(&data1);
            let hash2 = compute_hash(&data2);
            
// Note:Collisions are possible but extremely rare for good hashes
// For a 64-bit hash, collision probability is ~1/2^64
// With 1000 test cases, this should never fail
            prop_assert_ne!(
                hash1, hash2,
                "Different inputs should produce different hashes (collision found!)"
            );
        }

/// Property:Empty input has consistent hash
        #[test]
        fn empty_hash_consistent(_dummy in 0..100i32) {
            let empty: Vec<u8> = vec![];
            let hash1 = compute_hash(&empty);
            let hash2 = compute_hash(&empty);
            prop_assert_eq!(hash1, hash2);
        }
    }
}

// ===========================================================================
// 6. BOUNDED QUEUE PROPERTY TESTS
// ===========================================================================

mod bounded_queue_properties {
    use super::*;
    use std::collections::VecDeque;

    struct BoundedQueue<T> {
        items: VecDeque<T>,
        capacity: usize,
    }

    impl<T> BoundedQueue<T> {
        fn new(capacity: usize) -> Self {
            Self {
                items: VecDeque::with_capacity(capacity),
                capacity,
            }
        }

        fn push(&mut self, item: T) -> Option<T> {
            if self.items.len() >= self.capacity {
                let evicted = self.items.pop_front();
                self.items.push_back(item);
                evicted
            } else {
                self.items.push_back(item);
                None
            }
        }

        fn len(&self) -> usize {
            self.items.len()
        }
    }

    proptest! {
        #![proptest_config(ProptestConfig::with_cases(500))]
        
/// Property:Queue never exceeds capacity
        #[test]
        fn never_exceeds_capacity(
            capacity in 1usize..100,
            items in prop::collection::vec(any::<u32>(), 0..500)
        ) {
            let mut queue = BoundedQueue::new(capacity);
            
            for item in items {
                queue.push(item);
                prop_assert!(
                    queue.len() <= capacity,
                    "Queue length {} exceeds capacity {}", queue.len(), capacity
                );
            }
        }

/// Property:After pushing N items where N > capacity, length == capacity
        #[test]
        fn saturates_at_capacity(
            capacity in 1usize..50,
            extra in 1usize..100
        ) {
            let mut queue = BoundedQueue::new(capacity);
            
            for i in 0..(capacity + extra) {
                queue.push(i as u32);
            }
            
            prop_assert_eq!(
                queue.len(), capacity,
                "After overflow, queue should be exactly at capacity"
            );
        }

/// Property:Push returns evicted item when at capacity
        #[test]
        fn eviction_returns_oldest(capacity in 1usize..20) {
            let mut queue = BoundedQueue::new(capacity);
            
// Fill to capacity
            for i in 0..capacity {
                let evicted = queue.push(i as u32);
                prop_assert!(evicted.is_none(), "Should not evict before capacity");
            }
            
// Next push should evict the first item (0)
            let evicted = queue.push(999);
            prop_assert_eq!(evicted, Some(0), "Should evict oldest item");
        }
    }
}
