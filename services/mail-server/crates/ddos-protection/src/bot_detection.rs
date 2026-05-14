//! # Behavioral Bot Detection
//!
//! Analyzes request patterns over time to detect automated (bot) traffic.
//!
//! Detection signals://! - Inter-arrival time regularity (bots are mechanically periodic)
//! - Endpoint diversity (bots tend to hit the same endpoint repeatedly)
//! - Error rate patterns (bots may probe or have zero errors)
//! - Request sequence entropy (bots follow repetitive patterns)
//! - Timing autocorrelation / periodicity detection

use std::collections::{HashMap, HashSet, VecDeque};
use std::time::Instant;

/// Bot probability assessment
#[derive(Debug, Clone)]
pub struct BotAssessment {
    /// Overall probability of being a bot (0.0 = definitely human, 1.0 = definitely bot)
    pub bot_probability: f64,
    /// Individual signal scores
    pub signals: BotSignals,
    /// Whether we have enough data for a confident assessment
    pub has_sufficient_data: bool,
}

/// Individual signal scores for bot detection
#[derive(Debug, Clone, Default)]
pub struct BotSignals {
    /// Inter-arrival time regularity score (0=human-like, 1=bot-like)
    pub timing_regularity: f64,
    /// Periodicity score (0=no periodicity, 1=highly periodic)
    pub periodicity: f64,
    /// Endpoint diversity score (0=diverse, 1=concentrated)
    pub endpoint_concentration: f64,
    /// Error rate anomaly score
    pub error_anomaly: f64,
    /// Sequence entropy score (0=high entropy/human, 1=low entropy/bot)
    pub sequence_predictability: f64,
}

/// Session behavior data for bot analysis
pub struct SessionBehavior {
    /// Request timestamps (only inter-arrival times stored)
    inter_arrival_times: VecDeque<u64>,
    /// Request endpoint hashes
    request_sequence: VecDeque<u64>,
    /// Recent unique endpoints (windowed, tracks last N endpoint hashes)
    recent_endpoints: VecDeque<u64>,
    /// Error count
    error_count: u32,
    /// Total request count
    total_count: u32,
    /// Method distribution
    method_counts: HashMap<String, u32>,
    /// Last request timestamp (None until first request is recorded)
    last_request: Option<Instant>,
    /// Maximum window size
    window_size: usize,
}

impl SessionBehavior {
    /// Create a new session behavior tracker
    pub fn new(window_size: usize) -> Self {
        Self {
            inter_arrival_times: VecDeque::with_capacity(window_size),
            request_sequence: VecDeque::with_capacity(window_size),
            recent_endpoints: VecDeque::with_capacity(window_size),
            error_count: 0,
            total_count: 0,
            method_counts: HashMap::new(),
            last_request: None, // Don't set until first request arrives
            window_size,
        }
    }

    /// Record a new request
    pub fn record_request(&mut self, endpoint_hash: u64, method: &str, is_error: bool) {
        let now = Instant::now();

        // Only record inter-arrival time if we've seen a prior request.
        // This avoids polluting timing analysis with the gap between
        // tracker creation and the first actual request.
        if let Some(last) = self.last_request {
            let inter_arrival = now.duration_since(last).as_millis() as u64;
            if self.inter_arrival_times.len() >= self.window_size {
                self.inter_arrival_times.pop_front();
            }
            self.inter_arrival_times.push_back(inter_arrival);
        }

        if self.request_sequence.len() >= self.window_size {
            self.request_sequence.pop_front();
        }
        self.request_sequence.push_back(endpoint_hash);

        // Windowed unique endpoints:keep only the last window_size entries
        if self.recent_endpoints.len() >= self.window_size {
            self.recent_endpoints.pop_front();
        }
        self.recent_endpoints.push_back(endpoint_hash);

        self.total_count += 1;
        if is_error {
            self.error_count += 1;
        }
        // Normalize method to known HTTP methods to prevent unbounded HashMap growth.
        // Attackers could send arbitrary method strings to cause OOM.
        let normalized_method = match method.to_uppercase().as_str() {
            "GET" => "GET",
            "POST" => "POST",
            "PUT" => "PUT",
            "DELETE" => "DELETE",
            "PATCH" => "PATCH",
            "HEAD" => "HEAD",
            "OPTIONS" => "OPTIONS",
            "CONNECT" => "CONNECT",
            "TRACE" => "TRACE",
            _ => "OTHER",
        };
        *self
            .method_counts
            .entry(normalized_method.to_string())
            .or_insert(0) += 1;
        self.last_request = Some(now);
    }

    /// Analyze the session for bot behavior
    pub fn analyze(&self) -> BotAssessment {
        let has_sufficient_data = self.total_count >= 10 && self.inter_arrival_times.len() >= 10;

        if !has_sufficient_data {
            return BotAssessment {
                bot_probability: 0.0,
                signals: BotSignals::default(),
                has_sufficient_data: false,
            };
        }

        let signals = BotSignals {
            timing_regularity: self.score_timing_regularity(),
            periodicity: self.score_periodicity(),
            endpoint_concentration: self.score_endpoint_concentration(),
            error_anomaly: self.score_error_anomaly(),
            sequence_predictability: self.score_sequence_predictability(),
        };

        // Weighted combination of signals
        let bot_probability = signals.timing_regularity * 0.25
            + signals.periodicity * 0.20
            + signals.endpoint_concentration * 0.20
            + signals.error_anomaly * 0.15
            + signals.sequence_predictability * 0.20;

        BotAssessment {
            bot_probability: bot_probability.clamp(0.0, 1.0),
            signals,
            has_sufficient_data: true,
        }
    }

    /// Score based on coefficient of variation of inter-arrival times.
    /// Bots have very low CoV (mechanical regularity), humans have higher CoV.
    fn score_timing_regularity(&self) -> f64 {
        let cov = self.calculate_cov(&self.inter_arrival_times);
        if cov < 0.1 {
            1.0 // Extremely regular = very likely bot
        } else if cov < 0.3 {
            0.7
        } else if cov < 0.5 {
            0.4
        } else if cov > 1.0 {
            0.0 // High variability = human
        } else {
            0.2
        }
    }

    /// Detect periodicity via autocorrelation analysis
    fn score_periodicity(&self) -> f64 {
        if self.inter_arrival_times.len() < 30 {
            return 0.0;
        }

        let times: Vec<f64> = self.inter_arrival_times.iter().map(|&t| t as f64).collect();
        let n = times.len();
        let mean = times.iter().sum::<f64>() / n as f64;
        let variance = times.iter().map(|t| (t - mean).powi(2)).sum::<f64>() / n as f64;

        if variance <= f64::EPSILON {
            return 1.0; // Zero/near-zero variance = perfectly periodic
        }

        let mut max_corr = 0.0f64;

        for lag in 1..(n / 2) {
            let mut correlation = 0.0;
            let mut count = 0;

            for i in 0..(n - lag) {
                correlation += (times[i] - mean) * (times[i + lag] - mean);
                count += 1;
            }

            if count > 0 {
                let normalized = (correlation / count as f64) / variance;
                if normalized > max_corr {
                    max_corr = normalized;
                }
            }
        }

        if max_corr > 0.8 {
            1.0
        } else if max_corr > 0.6 {
            0.7
        } else if max_corr > 0.4 {
            0.3
        } else {
            0.0
        }
    }

    /// Score based on endpoint diversity.
    /// Bots tend to hit the same endpoint(s) repeatedly.
    fn score_endpoint_concentration(&self) -> f64 {
        if self.total_count == 0 || self.recent_endpoints.is_empty() {
            return 0.0;
        }

        // Count unique endpoints within the recent window
        let unique_in_window: HashSet<u64> = self.recent_endpoints.iter().cloned().collect();
        let diversity = unique_in_window.len() as f64 / self.recent_endpoints.len() as f64;

        if diversity < 0.05 {
            1.0 // Almost no diversity = probably bot
        } else if diversity < 0.15 {
            0.7
        } else if diversity < 0.3 {
            0.4
        } else {
            0.1
        }
    }

    /// Score based on error rate patterns.
    /// - Very high error rate = probing bot
    /// - Zero errors after many requests = possibly automated
    fn score_error_anomaly(&self) -> f64 {
        if self.total_count < 10 {
            return 0.0;
        }

        let error_rate = self.error_count as f64 / self.total_count as f64;

        #[allow(clippy::if_same_then_else)]
        if error_rate > 0.4 {
            0.9 // Very high error rate = probing
        } else if error_rate > 0.2 {
            0.5
        } else if error_rate == 0.0 && self.total_count > 50 {
            0.5 // Suspiciously perfect after many requests
        } else {
            0.1
        }
    }

    /// Score based on request sequence entropy (Shannon entropy of bigram transitions).
    /// Low entropy = predictable/repetitive = bot-like.
    fn score_sequence_predictability(&self) -> f64 {
        if self.request_sequence.len() < 5 {
            return 0.0;
        }

        let entropy = self.sequence_entropy();

        if entropy < 0.5 {
            1.0 // Very low entropy = highly predictable
        } else if entropy < 1.5 {
            0.6
        } else if entropy < 3.0 {
            0.3
        } else {
            0.0 // High entropy = varied behavior
        }
    }

    /// Calculate Shannon entropy of request sequence bigram transitions
    pub fn sequence_entropy(&self) -> f64 {
        let seq: Vec<u64> = self.request_sequence.iter().cloned().collect();
        if seq.len() < 2 {
            return 4.0; // Default high
        }

        let mut transitions: HashMap<(u64, u64), u32> = HashMap::new();
        for window in seq.windows(2) {
            *transitions.entry((window[0], window[1])).or_insert(0) += 1;
        }

        let total: u32 = transitions.values().sum();
        if total == 0 {
            return 4.0; // No transitions to analyze
        }
        transitions
            .values()
            .map(|&count| {
                let p = count as f64 / total as f64;
                if p > 0.0 {
                    -p * p.log2()
                } else {
                    0.0
                }
            })
            .sum()
    }

    /// Calculate coefficient of variation
    fn calculate_cov(&self, data: &VecDeque<u64>) -> f64 {
        if data.len() < 2 {
            return 1.0;
        }
        let values: Vec<f64> = data.iter().map(|&v| v as f64).collect();
        let mean = values.iter().sum::<f64>() / values.len() as f64;
        if mean <= 0.0 {
            return 0.0;
        }
        let variance = values.iter().map(|v| (v - mean).powi(2)).sum::<f64>() / values.len() as f64;
        variance.sqrt() / mean
    }

    /// Get the total request count
    pub fn total_count(&self) -> u32 {
        self.total_count
    }

    /// Get the error count
    pub fn error_count(&self) -> u32 {
        self.error_count
    }

    /// Get unique endpoint count (within the recent window)
    pub fn unique_endpoint_count(&self) -> usize {
        let unique: HashSet<u64> = self.recent_endpoints.iter().cloned().collect();
        unique.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hash_endpoint(path: &str) -> u64 {
        use std::collections::hash_map::DefaultHasher;
        use std::hash::{Hash, Hasher};
        let mut h = DefaultHasher::new();
        path.hash(&mut h);
        h.finish()
    }

    #[test]
    fn test_insufficient_data_returns_neutral() {
        let behavior = SessionBehavior::new(100);
        let assessment = behavior.analyze();
        assert!(!assessment.has_sufficient_data);
        assert_eq!(assessment.bot_probability, 0.0);
    }

    #[test]
    fn test_regular_timing_scores_high() {
        let mut behavior = SessionBehavior::new(100);
        let ep = hash_endpoint("/api/health");

        // Simulate mechanically regular requests
        for _ in 0..20 {
            behavior.record_request(ep, "GET", false);
            // All inter-arrival times will be ~0 (very regular since they're in a loop)
        }

        let assessment = behavior.analyze();
        assert!(assessment.has_sufficient_data);
        // Since all requests hit same endpoint and have very regular timing,
        // bot probability should be elevated
        assert!(
            assessment.bot_probability > 0.3,
            "Bot probability should be elevated for regular timing: {}",
            assessment.bot_probability
        );
    }

    #[test]
    fn test_diverse_behavior_scores_low() {
        let mut behavior = SessionBehavior::new(100);

        // Simulate varied behavior
        let endpoints = [
            "/api/health",
            "/api/messages",
            "/api/templates",
            "/api/domains",
            "/api/settings",
            "/api/analytics",
            "/api/users",
            "/api/billing",
            "/api/keys",
            "/api/logs",
        ];

        for (i, ep) in endpoints.iter().cycle().take(20).enumerate() {
            let is_error = i % 7 == 0; // Some errors
            behavior.record_request(hash_endpoint(ep), "GET", is_error);
        }

        let assessment = behavior.analyze();
        assert!(assessment.has_sufficient_data);
        // Diverse endpoints should score lower on endpoint concentration
        assert!(
            assessment.signals.endpoint_concentration < 0.5,
            "Diverse endpoints should have low concentration: {}",
            assessment.signals.endpoint_concentration
        );
    }

    #[test]
    fn test_high_error_rate_detected() {
        let mut behavior = SessionBehavior::new(100);
        let ep = hash_endpoint("/api/login");

        // High error rate (probing behavior)
        for i in 0..20 {
            behavior.record_request(ep, "POST", i >= 2); // 90% errors
        }

        let assessment = behavior.analyze();
        assert!(
            assessment.signals.error_anomaly > 0.5,
            "High error rate should score high: {}",
            assessment.signals.error_anomaly
        );
    }

    #[test]
    fn test_sequence_entropy_low_for_repetitive() {
        let mut behavior = SessionBehavior::new(100);
        // Same endpoint over and over
        let ep = hash_endpoint("/api/data");
        for _ in 0..30 {
            behavior.record_request(ep, "GET", false);
        }

        let entropy = behavior.sequence_entropy();
        // Single endpoint = zero transitions to other endpoints = zero entropy from transitions
        // But technically only 1 type of bigram (ep -> ep), so entropy = 0
        assert!(
            entropy < 0.1,
            "Repetitive sequence should have near-zero entropy: {}",
            entropy
        );
    }

    #[test]
    fn test_sequence_entropy_high_for_varied() {
        let mut behavior = SessionBehavior::new(100);
        let endpoints: Vec<u64> = (0..10)
            .map(|i| hash_endpoint(&format!("/api/ep{}", i)))
            .collect();

        for ep in endpoints.iter().cycle().take(50) {
            // Cycle through all 10 endpoints
            behavior.record_request(*ep, "GET", false);
        }

        let entropy = behavior.sequence_entropy();
        assert!(
            entropy > 1.0,
            "Varied sequence should have higher entropy: {}",
            entropy
        );
    }

    #[test]
    fn test_cov_zero_for_constant() {
        let behavior = SessionBehavior::new(100);
        let mut data = VecDeque::new();
        for _ in 0..20 {
            data.push_back(100u64);
        }
        let cov = behavior.calculate_cov(&data);
        assert!(cov < 0.001, "Constant data should have ~zero CoV: {}", cov);
    }

    #[test]
    fn test_cov_high_for_variable() {
        let behavior = SessionBehavior::new(100);
        let mut data = VecDeque::new();
        for i in 0..20 {
            data.push_back(if i % 2 == 0 { 10 } else { 1000 });
        }
        let cov = behavior.calculate_cov(&data);
        assert!(cov > 0.5, "Variable data should have high CoV: {}", cov);
    }

    #[test]
    fn test_method_tracking() {
        let mut behavior = SessionBehavior::new(100);
        let ep = hash_endpoint("/api/data");

        behavior.record_request(ep, "GET", false);
        behavior.record_request(ep, "GET", false);
        behavior.record_request(ep, "POST", false);

        assert_eq!(behavior.method_counts.get("GET"), Some(&2));
        assert_eq!(behavior.method_counts.get("POST"), Some(&1));
    }
}
