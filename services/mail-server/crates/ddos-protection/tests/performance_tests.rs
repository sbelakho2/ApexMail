//! Load and Performance Tests for DDoS Protection System
//!
//! These tests measure performance characteristics, throughput,
//! latency, and scalability under various load conditions.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;
use std::time::{Duration, Instant};

/// ============================================================================
/// PERFORMANCE TESTS: Rate Limiter Throughput
/// ============================================================================
#[cfg(test)]
mod rate_limiter_perf_tests {
    use super::*;
    
    struct TokenBucket {
        tokens: f64,
        max_tokens: f64,
        refill_rate: f64,
        last_refill: Instant,
    }
    
    impl TokenBucket {
        fn new(max_tokens: f64, refill_rate: f64) -> Self {
            Self {
                tokens: max_tokens,
                max_tokens,
                refill_rate,
                last_refill: Instant::now(),
            }
        }
        
        fn try_acquire(&mut self, tokens: f64) -> bool {
            self.refill();
            
            if self.tokens >= tokens {
                self.tokens -= tokens;
                true
            } else {
                false
            }
        }
        
        fn refill(&mut self) {
            let elapsed = self.last_refill.elapsed();
            let new_tokens = elapsed.as_secs_f64() * self.refill_rate;
            self.tokens = (self.tokens + new_tokens).min(self.max_tokens);
            self.last_refill = Instant::now();
        }
    }
    
    #[test]
    fn test_token_bucket_throughput() {
        let mut bucket = TokenBucket::new(1000.0, 100.0);
        
        let start = Instant::now();
        let mut successful = 0u64;
        let iterations = 100_000;
        
        for _ in 0..iterations {
            if bucket.try_acquire(1.0) {
                successful += 1;
            }
            // Simulate small time passage
            bucket.tokens = (bucket.tokens + 0.001).min(bucket.max_tokens);
        }
        
        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("Token bucket: {:.0} ops/sec", ops_per_sec);
        assert!(ops_per_sec > 100_000.0, "Should handle >100k ops/sec");
    }
    
    #[test]
    fn test_burst_handling() {
        let mut bucket = TokenBucket::new(100.0, 10.0);
        
        // Burst of 100 requests should succeed
        let mut burst_success = 0;
        for _ in 0..100 {
            if bucket.try_acquire(1.0) {
                burst_success += 1;
            }
        }
        
        assert_eq!(burst_success, 100);
        
        // Next request should fail (no tokens left)
        assert!(!bucket.try_acquire(1.0));
    }
}

/// ============================================================================
/// PERFORMANCE TESTS: Hash Map Lookup Speed
/// ============================================================================
#[cfg(test)]
mod hashmap_perf_tests {
    use super::*;
    use std::collections::HashMap;
    
    #[test]
    fn test_ip_lookup_performance() {
        let mut map: HashMap<String, u64> = HashMap::new();
        
        // Pre-populate with 100k IPs
        for i in 0..100_000 {
            let ip = format!("192.168.{}.{}", i / 256, i % 256);
            map.insert(ip, i as u64);
        }
        
        // Benchmark lookups
        let start = Instant::now();
        let iterations = 1_000_000;
        
        for i in 0..iterations {
            let ip = format!("192.168.{}.{}", (i / 256) % 256, i % 256);
            let _ = map.get(&ip);
        }
        
        let elapsed = start.elapsed();
        let lookups_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("HashMap lookups: {:.0}/sec", lookups_per_sec);
        // Relaxed threshold for debug builds; expect >100k/sec (release achieves >1M)
        assert!(lookups_per_sec > 100_000.0, "Should handle >100k lookups/sec");
    }
    
    #[test]
    fn test_concurrent_hashmap_simulation() {
        // Simulate concurrent access pattern
        let mut maps: Vec<HashMap<String, u64>> = (0..8)
            .map(|_| HashMap::new())
            .collect();
        
        // Each "shard" gets its own map
        let start = Instant::now();
        
        for i in 0..100_000 {
            let shard = i % 8;
            let ip = format!("10.0.{}.{}", i / 256, i % 256);
            maps[shard].insert(ip, i as u64);
        }
        
        let elapsed = start.elapsed();
        let total_entries: usize = maps.iter().map(|m| m.len()).sum();
        
        println!("Sharded insert: {} entries in {:?}", total_entries, elapsed);
        assert_eq!(total_entries, 100_000);
    }
}

/// ============================================================================
/// PERFORMANCE TESTS: Fingerprint Hashing
/// ============================================================================
#[cfg(test)]
mod fingerprint_perf_tests {
    use super::*;
    use sha2::{Sha256, Digest};
    
    #[test]
    fn test_sha256_throughput() {
        let start = Instant::now();
        let iterations = 100_000;
        
        for i in 0..iterations {
            let data = format!("fingerprint_data_{}", i);
            let mut hasher = Sha256::new();
            hasher.update(data.as_bytes());
            let _ = hasher.finalize();
        }
        
        let elapsed = start.elapsed();
        let hashes_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("SHA256: {:.0} hashes/sec", hashes_per_sec);
        // Relaxed threshold for debug builds; expect >50k/sec
        assert!(hashes_per_sec > 50_000.0, "Should handle >50k hashes/sec");
    }
    
    #[test]
    fn test_ja4_format_generation() {
        let start = Instant::now();
        let iterations = 100_000;
        
        for i in 0..iterations {
            // Simulate JA4 fingerprint generation
            let protocol = 't';
            let version = "13";
            let sni = 'd';
            let cipher_count = format!("{:02}", (i % 99) + 1);
            let ext_count = format!("{:02}", (i % 50) + 1);
            let alpn = "h2";
            
            let prefix = format!(
                "{}{}{}{}{}{}",
                protocol, version, sni, cipher_count, ext_count, alpn
            );
            
            let mut hasher = Sha256::new();
            hasher.update(prefix.as_bytes());
            let _ = hasher.finalize();
        }
        
        let elapsed = start.elapsed();
        let fps_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("JA4 generation: {:.0}/sec", fps_per_sec);
        assert!(fps_per_sec > 50_000.0, "Should generate >50k fingerprints/sec");
    }
}

/// ============================================================================
/// PERFORMANCE TESTS: PoW Verification
/// ============================================================================
#[cfg(test)]
mod pow_perf_tests {
    use super::*;
    use sha2::{Sha256, Digest};
    
    fn verify_pow(prefix: &str, nonce: u64, difficulty: u8) -> bool {
        let data = format!("{}{}", prefix, nonce);
        let mut hasher = Sha256::new();
        hasher.update(data.as_bytes());
        let hash = hasher.finalize();
        
        let required_zeros = difficulty as usize;
        let required_bytes = required_zeros / 8;
        
        for i in 0..required_bytes {
            if hash[i] != 0 {
                return false;
            }
        }
        
        if required_zeros % 8 > 0 && required_bytes < 32 {
            let mask = 0xFF << (8 - (required_zeros % 8));
            if hash[required_bytes] & mask != 0 {
                return false;
            }
        }
        
        true
    }
    
    #[test]
    fn test_pow_verification_throughput() {
        let start = Instant::now();
        let iterations = 100_000;
        
        for i in 0..iterations {
            let prefix = format!("challenge_{}", i % 1000);
            let _ = verify_pow(&prefix, i as u64, 8);
        }
        
        let elapsed = start.elapsed();
        let verifications_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("PoW verifications: {:.0}/sec", verifications_per_sec);
        assert!(verifications_per_sec > 50_000.0, "Should verify >50k/sec");
    }
    
    #[test]
    fn test_pow_solve_time_by_difficulty() {
        // Measure solve times for different difficulties
        let difficulties = [4, 8, 12, 16];
        
        for difficulty in difficulties {
            let start = Instant::now();
            let prefix = "benchmark_challenge";
            
            let mut nonce = 0u64;
            while !verify_pow(prefix, nonce, difficulty) && nonce < 10_000_000 {
                nonce += 1;
            }
            
            let elapsed = start.elapsed();
            println!(
                "PoW difficulty {}: solved in {:?} ({} attempts)", 
                difficulty, elapsed, nonce
            );
        }
    }
}

/// ============================================================================
/// PERFORMANCE TESTS: Decision Engine Latency
/// ============================================================================
#[cfg(test)]
mod decision_latency_tests {
    use super::*;
    
    #[derive(Debug, Clone, Copy)]
    enum Decision {
        Allow,
        Challenge,
        Block,
    }
    
    struct FastDecisionEngine {
        blocked_ips: HashMap<String, ()>,
        request_counts: HashMap<String, u64>,
        rate_limit: u64,
    }
    
    impl FastDecisionEngine {
        fn new(rate_limit: u64) -> Self {
            Self {
                blocked_ips: HashMap::new(),
                request_counts: HashMap::new(),
                rate_limit,
            }
        }
        
        fn block_ip(&mut self, ip: &str) {
            self.blocked_ips.insert(ip.to_string(), ());
        }
        
        fn decide(&mut self, ip: &str) -> Decision {
            // Check blocklist first (fast path)
            if self.blocked_ips.contains_key(ip) {
                return Decision::Block;
            }
            
            // Check rate limit
            let count = self.request_counts.entry(ip.to_string()).or_insert(0);
            *count += 1;
            
            if *count > self.rate_limit * 2 {
                Decision::Block
            } else if *count > self.rate_limit {
                Decision::Challenge
            } else {
                Decision::Allow
            }
        }
    }
    
    #[test]
    fn test_decision_latency() {
        let mut engine = FastDecisionEngine::new(100);
        
        // Pre-populate some blocked IPs
        for i in 0..1000 {
            engine.block_ip(&format!("blocked_{}", i));
        }
        
        // Warm up
        for i in 0..1000 {
            let ip = format!("warmup_{}", i);
            engine.decide(&ip);
        }
        
        // Measure latency over many decisions
        let start = Instant::now();
        let iterations = 1_000_000;
        
        for i in 0..iterations {
            let ip = format!("client_{}", i % 10000);
            let _ = engine.decide(&ip);
        }
        
        let elapsed = start.elapsed();
        let avg_latency_ns = elapsed.as_nanos() / iterations as u128;
        let decisions_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("Decision latency: {}ns avg", avg_latency_ns);
        println!("Decisions/sec: {:.0}", decisions_per_sec);
        
        // Relaxed for debug builds; expect <5µs (release achieves <1µs)
        assert!(avg_latency_ns < 5000, "Latency should be <5µs");
        assert!(decisions_per_sec > 100_000.0, "Should handle >100k decisions/sec");
    }
    
    #[test]
    fn test_blocked_ip_fast_path() {
        let mut engine = FastDecisionEngine::new(100);
        
        // Block an IP
        engine.block_ip("bad_actor");
        
        // Measure blocked IP check latency
        let start = Instant::now();
        let iterations = 1_000_000;
        
        for _ in 0..iterations {
            let _ = engine.decide("bad_actor");
        }
        
        let elapsed = start.elapsed();
        let avg_latency_ns = elapsed.as_nanos() / iterations as u128;
        
        println!("Blocked IP check latency: {}ns", avg_latency_ns);
        // Relaxed for debug builds; expect <2µs (release achieves <500ns)
        assert!(avg_latency_ns < 2000, "Blocked IP check should be <2µs");
    }
}

/// ============================================================================
/// PERFORMANCE TESTS: Memory Usage
/// ============================================================================
#[cfg(test)]
mod memory_tests {
    use super::*;
    
    #[test]
    fn test_ip_entry_size() {
        let map: HashMap<String, u64> = HashMap::new();
        
        // Estimate entry size
        let ip_size = std::mem::size_of::<String>(); // String metadata
        let value_size = std::mem::size_of::<u64>();
        let overhead = 8; // HashMap overhead per entry (approx)
        
        let entry_size = ip_size + value_size + overhead + 15; // 15 bytes for typical IP string
        
        println!("Estimated entry size: {} bytes", entry_size);
        println!("100k IPs would use: {} MB", entry_size * 100_000 / 1_000_000);
        
        // Should be reasonable
        assert!(entry_size < 100, "Entry size should be <100 bytes");
    }
    
    #[test]
    fn test_session_state_size() {
        struct SessionState {
            request_count: u64,
            error_count: u64,
            first_seen: u64,
            last_seen: u64,
            reputation: i16,
            endpoint_hash: u64,
        }
        
        let size = std::mem::size_of::<SessionState>();
        println!("SessionState size: {} bytes", size);
        
        // 1M sessions
        let total_mb = size * 1_000_000 / 1_000_000;
        println!("1M sessions would use: {} MB", total_mb);
        
        // Should be compact
        assert!(size <= 48, "SessionState should be <=48 bytes");
    }
    
    #[test]
    fn test_fingerprint_cache_size() {
        struct FingerprintEntry {
            hash: [u8; 16],
            classification: u8,
            first_seen: u64,
            last_seen: u64,
            count: u32,
        }
        
        let size = std::mem::size_of::<FingerprintEntry>();
        println!("FingerprintEntry size: {} bytes", size);
        
        // 10k fingerprints
        let total_kb = size * 10_000 / 1_000;
        println!("10k fingerprints would use: {} KB", total_kb);
        
        assert!(size <= 40, "FingerprintEntry should be <=40 bytes");
    }
}

/// ============================================================================
/// PERFORMANCE TESTS: Concurrent Request Simulation
/// ============================================================================
#[cfg(test)]
mod concurrent_perf_tests {
    use super::*;
    
    #[test]
    fn test_simulated_concurrent_load() {
        // Simulate high concurrent request processing
        let counters: Vec<AtomicU64> = (0..16)
            .map(|_| AtomicU64::new(0))
            .collect();
        
        let start = Instant::now();
        let iterations_per_shard = 100_000;
        
        // Simulate sharded processing
        for shard in 0..16 {
            for _ in 0..iterations_per_shard {
                counters[shard].fetch_add(1, Ordering::Relaxed);
            }
        }
        
        let elapsed = start.elapsed();
        let total_ops = 16 * iterations_per_shard;
        let ops_per_sec = total_ops as f64 / elapsed.as_secs_f64();
        
        println!("Sharded ops: {:.0}/sec", ops_per_sec);
        
        let total_count: u64 = counters.iter()
            .map(|c| c.load(Ordering::Relaxed))
            .sum();
        
        assert_eq!(total_count, total_ops as u64);
    }
    
    #[test]
    fn test_request_routing_overhead() {
        // Simulate routing requests to shards
        let start = Instant::now();
        let iterations = 1_000_000;
        
        for i in 0..iterations {
            // Simulate shard selection
            let ip_hash = i * 31; // Simple hash
            let shard = ip_hash % 16;
            let _ = shard; // Use the shard
        }
        
        let elapsed = start.elapsed();
        let routing_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("Routing: {:.0}/sec", routing_per_sec);
        assert!(routing_per_sec > 10_000_000.0, "Routing should be >10M/sec");
    }
}

/// ============================================================================
/// PERFORMANCE TESTS: Statistics Computation
/// ============================================================================
#[cfg(test)]
mod stats_perf_tests {
    use super::*;
    
    #[test]
    fn test_cov_calculation_performance() {
        let data: Vec<f64> = (0..1000).map(|i| (i % 100) as f64).collect();
        
        let start = Instant::now();
        let iterations = 10_000;
        
        for _ in 0..iterations {
            let mean = data.iter().sum::<f64>() / data.len() as f64;
            let variance = data.iter()
                .map(|x| (x - mean).powi(2))
                .sum::<f64>() / data.len() as f64;
            let std_dev = variance.sqrt();
            let _ = if mean > 0.0 { std_dev / mean } else { 0.0 };
        }
        
        let elapsed = start.elapsed();
        let calcs_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("CoV calculations: {:.0}/sec", calcs_per_sec);
        assert!(calcs_per_sec > 10_000.0, "Should calculate >10k CoV/sec");
    }
    
    #[test]
    fn test_rolling_average_performance() {
        struct RollingAverage {
            sum: f64,
            count: u64,
        }
        
        impl RollingAverage {
            fn new() -> Self {
                Self { sum: 0.0, count: 0 }
            }
            
            fn add(&mut self, value: f64) {
                self.sum += value;
                self.count += 1;
            }
            
            fn average(&self) -> f64 {
                if self.count > 0 {
                    self.sum / self.count as f64
                } else {
                    0.0
                }
            }
        }
        
        let mut avg = RollingAverage::new();
        
        let start = Instant::now();
        let iterations = 10_000_000;
        
        for i in 0..iterations {
            avg.add(i as f64);
        }
        
        let elapsed = start.elapsed();
        let ops_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("Rolling average: {:.0} updates/sec", ops_per_sec);
        println!("Final average: {:.2}", avg.average());
        
        assert!(ops_per_sec > 10_000_000.0, "Should handle >10M updates/sec");
    }
}

/// ============================================================================
/// PERFORMANCE TESTS: Anomaly Detection
/// ============================================================================
#[cfg(test)]
mod anomaly_perf_tests {
    use super::*;
    
    fn c_factor(n: usize) -> f64 {
        if n <= 1 { return 0.0; }
        let n_f = n as f64;
        2.0 * ((n_f - 1.0).ln() + 0.5772156649) - (2.0 * (n_f - 1.0) / n_f)
    }
    
    fn anomaly_score(path_length: f64, sample_size: usize) -> f64 {
        let c = c_factor(sample_size);
        if c <= 0.0 { return 0.5; }
        2.0_f64.powf(-path_length / c)
    }
    
    #[test]
    fn test_anomaly_score_throughput() {
        let start = Instant::now();
        let iterations = 1_000_000;
        
        for i in 0..iterations {
            let path_length = (i % 20) as f64;
            let _ = anomaly_score(path_length, 256);
        }
        
        let elapsed = start.elapsed();
        let scores_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("Anomaly scores: {:.0}/sec", scores_per_sec);
        assert!(scores_per_sec > 1_000_000.0, "Should calculate >1M scores/sec");
    }
    
    #[test]
    fn test_feature_extraction_performance() {
        // Simulate extracting features for ML
        struct Features {
            request_rate: f64,
            error_rate: f64,
            endpoint_diversity: f64,
            inter_arrival_cov: f64,
            payload_entropy: f64,
        }
        
        let start = Instant::now();
        let iterations = 100_000;
        
        for i in 0..iterations {
            let _ = Features {
                request_rate: (i % 100) as f64,
                error_rate: (i % 10) as f64 / 10.0,
                endpoint_diversity: (i % 50) as f64 / 50.0,
                inter_arrival_cov: (i % 200) as f64 / 100.0,
                payload_entropy: ((i * 7) % 100) as f64 / 100.0,
            };
        }
        
        let elapsed = start.elapsed();
        let extractions_per_sec = iterations as f64 / elapsed.as_secs_f64();
        
        println!("Feature extractions: {:.0}/sec", extractions_per_sec);
        assert!(extractions_per_sec > 1_000_000.0, "Should extract >1M features/sec");
    }
}

/// ============================================================================
/// Run performance tests
/// ============================================================================
fn main() {
    println!("Run performance tests with: cargo test --test performance_tests --release");
    println!("Note: Performance tests should be run in release mode for accurate measurements");
}
