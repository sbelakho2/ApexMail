//! # Adaptive Rate Limiter with Online Learning
//!
//! Dynamically adjusts rate limit thresholds based on observed traffic patterns.
//!
//! Uses Z-score anomaly detection for attack identification and
//! exponential moving average (EMA) for smooth threshold adjustments.

use std::collections::VecDeque;
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::time::{Duration, Instant};

use parking_lot::RwLock;

/// Traffic observation sample
#[derive(Debug, Clone)]
pub struct TrafficObservation {
    /// When this observation was taken
    pub timestamp: Instant,
    /// Requests per second at sample time
    pub requests_per_second: f64,
    /// Error rate (fraction, 0.0-1.0) at sample time
    pub error_rate: f64,
    /// P99 latency in milliseconds at sample time
    pub latency_p99_ms: f64,
    /// CPU usage fraction (0.0-1.0) at sample time
    pub cpu_usage: f64,
}

/// Attack state tracking
#[derive(Debug, Clone)]
struct AttackDetection {
    /// Is the system under active attack?
    is_under_attack: bool,
    /// When the attack started
    attack_started: Option<Instant>,
    /// Baseline RPS (from pre-attack traffic)
    baseline_rps: f64,
    /// Baseline error rate
    baseline_error_rate: f64,
    /// Consecutive anomaly alerts
    consecutive_alerts: u32,
}

impl Default for AttackDetection {
    fn default() -> Self {
        Self {
            is_under_attack: false,
            attack_started: None,
            baseline_rps: 0.0,
            baseline_error_rate: 0.0,
            consecutive_alerts: 0,
        }
    }
}

/// Configuration for the adaptive rate limiter
#[derive(Debug, Clone)]
pub struct AdaptiveConfig {
    /// Window size for baseline observation history
    pub baseline_window: Duration,
    /// Z-score threshold for anomaly detection
    pub z_threshold: f64,
    /// Z-score to use when standard deviation is zero (all observations identical)
    /// Default is 10.0, which will trigger anomaly detection for any deviation
    pub zero_std_z_score: f64,
    /// Z-score threshold for attack recovery (attack ends when z < this value)
    /// Default is 1.0, meaning traffic must return to within 1 std dev of baseline
    pub recovery_z_threshold: f64,
    /// Minimum threshold (never go below this value)
    pub min_threshold: u64,
    /// Maximum threshold (never go above this value)
    pub max_threshold: u64,
    /// Number of consecutive alerts before declaring attack
    pub consecutive_alert_trigger: u32,
    /// Cooldown period after attack subsides before restoring limits
    pub cooldown: Duration,
    /// EMA alpha factor for smooth threshold adjustment (0-1)
    pub ema_alpha: f64,
    /// Factor of baseline to use under attack (e.g., 0.5 = 50%)
    pub attack_factor: f64,
    /// Headroom factor for normal operation (e.g., 1.5 = 50% headroom)
    pub headroom_factor: f64,
}

impl Default for AdaptiveConfig {
    fn default() -> Self {
        Self {
            baseline_window: Duration::from_secs(300), // 5 minutes
            z_threshold: 3.0,
            zero_std_z_score: 10.0,
            recovery_z_threshold: 1.0,
            min_threshold: 10,
            max_threshold: 100_000,
            consecutive_alert_trigger: 3,
            cooldown: Duration::from_secs(120),
            ema_alpha: 0.1,
            attack_factor: 0.5,
            headroom_factor: 1.5,
        }
    }
}

/// Adaptive rate limiter that adjusts thresholds based on traffic patterns
pub struct AdaptiveRateLimiter {
    /// Current threshold value
    threshold: AtomicU64,
    /// Historical observations
    observations: RwLock<VecDeque<TrafficObservation>>,
    /// Configuration
    config: AdaptiveConfig,
    /// Attack detection state
    attack_state: RwLock<AttackDetection>,
    /// Atomic flag for quick attack check
    under_attack_flag: AtomicBool,
}

impl AdaptiveRateLimiter {
    /// Create a new adaptive rate limiter
    pub fn new(config: AdaptiveConfig) -> Self {
        let initial_threshold = config.max_threshold / 2;
        Self {
            threshold: AtomicU64::new(initial_threshold),
            observations: RwLock::new(VecDeque::with_capacity(1024)),
            config,
            attack_state: RwLock::new(AttackDetection::default()),
            under_attack_flag: AtomicBool::new(false),
        }
    }

    /// Get the current rate limit threshold
    pub fn current_threshold(&self) -> u64 {
        self.threshold.load(Ordering::Relaxed)
    }

    /// Check if the system is under attack
    pub fn is_under_attack(&self) -> bool {
        self.under_attack_flag.load(Ordering::Relaxed)
    }

    /// Update the limiter with a new traffic observation.
    /// This is the main entry point for the online learning loop.
    pub fn update(&self, observation: TrafficObservation) {
        let mut observations = self.observations.write();

        // Remove old observations outside the baseline window
        let cutoff = Instant::now() - self.config.baseline_window;
        while observations.front().map_or(false, |o| o.timestamp < cutoff) {
            observations.pop_front();
        }

        // Not enough data yet for statistical analysis - provide conservative cold-start protection
        // But only if adaptation is enabled (ema_alpha > 0). If ema_alpha is 0, user wants
        // no automatic adaptation at all, so we respect that even during cold-start.
        if observations.len() < 10 {
            if self.config.ema_alpha > 0.0 {
                // During cold-start, use a conservative adaptive threshold based on observed traffic.
                // This prevents attackers from exploiting the learning window.
                let current_rps = observation.requests_per_second as u64;
                // Set threshold to 2x current RPS (conservative headroom) clamped to bounds
                let cold_start_threshold = (current_rps.saturating_mul(2))
                    .clamp(self.config.min_threshold, self.config.max_threshold);
                
                // Only lower threshold if it would be more restrictive than current
                let current = self.threshold.load(Ordering::Relaxed);
                if cold_start_threshold < current {
                    self.threshold.store(cold_start_threshold, Ordering::Relaxed);
                }
            }
            
            observations.push_back(observation);
            return;
        }

        // Compute baseline statistics
        let rps_values: Vec<f64> = observations.iter().map(|o| o.requests_per_second).collect();
        let rps_mean = rps_values.iter().sum::<f64>() / rps_values.len() as f64;
        let rps_std = {
            let variance = rps_values
                .iter()
                .map(|v| (v - rps_mean).powi(2))
                .sum::<f64>()
                / rps_values.len() as f64;
            variance.sqrt()
        };

        // Compute Z-score for current observation
        // When std is zero (all observations identical), any deviation from the mean
        // is infinitely anomalous. We use a configurable sentinel z-score in that case,
        // because std=0 + non-zero deviation means a definite pattern break.
        let z_score = if rps_std > 0.0 {
            (observation.requests_per_second - rps_mean) / rps_std
        } else {
            // Zero standard deviation: if observation differs from mean, it's maximally anomalous
            let deviation = (observation.requests_per_second - rps_mean).abs();
            if deviation > 0.0 {
                // Use configurable z-score to trigger anomaly detection
                self.config.zero_std_z_score * (observation.requests_per_second - rps_mean).signum()
            } else {
                0.0 // Exactly at mean, no anomaly
            }
        };

        let mut attack_state = self.attack_state.write();

        if z_score > self.config.z_threshold {
            // Potential attack — increment alert counter
            attack_state.consecutive_alerts += 1;

            if attack_state.consecutive_alerts >= self.config.consecutive_alert_trigger
                && !attack_state.is_under_attack
            {
                // Declare attack mode
                attack_state.is_under_attack = true;
                attack_state.attack_started = Some(Instant::now());
                attack_state.baseline_rps = rps_mean;
                attack_state.baseline_error_rate = observations
                    .iter()
                    .map(|o| o.error_rate)
                    .sum::<f64>()
                    / observations.len() as f64;

                self.under_attack_flag.store(true, Ordering::Relaxed);

                // Tighten threshold to attack_factor * baseline
                let new_threshold = (rps_mean * self.config.attack_factor) as u64;
                self.threshold.store(
                    new_threshold.clamp(self.config.min_threshold, self.config.max_threshold),
                    Ordering::Relaxed,
                );
            }
        } else if attack_state.is_under_attack {
            // Check if attack has subsided
            if let Some(started) = attack_state.attack_started {
                if started.elapsed() > self.config.cooldown && z_score < self.config.recovery_z_threshold {
                    // Attack subsided — restore normal operation
                    attack_state.is_under_attack = false;
                    attack_state.attack_started = None;
                    attack_state.consecutive_alerts = 0;

                    self.under_attack_flag.store(false, Ordering::Relaxed);

                    // Gradually restore threshold
                    let new_threshold = (rps_mean * self.config.headroom_factor) as u64;
                    self.threshold.store(
                        new_threshold.clamp(self.config.min_threshold, self.config.max_threshold),
                        Ordering::Relaxed,
                    );
                }
            }
        } else {
            // Normal operation — smoothly adjust threshold
            attack_state.consecutive_alerts = 0;

            let current_threshold = self.threshold.load(Ordering::Relaxed) as f64;
            let ideal_threshold = rps_mean * self.config.headroom_factor;

            // EMA adjustment with proper rounding to avoid truncation bias
            let new_threshold =
                current_threshold * (1.0 - self.config.ema_alpha) + ideal_threshold * self.config.ema_alpha;

            self.threshold.store(
                (new_threshold.round() as u64).clamp(self.config.min_threshold, self.config.max_threshold),
                Ordering::Relaxed,
            );
        }

        observations.push_back(observation);
    }

    /// Get baseline statistics from the observation window
    pub fn baseline_stats(&self) -> Option<BaselineStats> {
        let observations = self.observations.read();
        if observations.len() < 10 {
            return None;
        }

        let rps_values: Vec<f64> = observations.iter().map(|o| o.requests_per_second).collect();
        let rps_mean = rps_values.iter().sum::<f64>() / rps_values.len() as f64;
        let rps_std = {
            let variance = rps_values
                .iter()
                .map(|v| (v - rps_mean).powi(2))
                .sum::<f64>()
                / rps_values.len() as f64;
            variance.sqrt()
        };

        let error_mean = observations.iter().map(|o| o.error_rate).sum::<f64>()
            / observations.len() as f64;
        let latency_mean = observations.iter().map(|o| o.latency_p99_ms).sum::<f64>()
            / observations.len() as f64;

        Some(BaselineStats {
            rps_mean,
            rps_std,
            error_rate_mean: error_mean,
            latency_p99_mean: latency_mean,
            sample_count: observations.len(),
        })
    }

    /// Get the attack detection state
    pub fn attack_info(&self) -> AttackInfo {
        let state = self.attack_state.read();
        AttackInfo {
            is_under_attack: state.is_under_attack,
            baseline_rps: state.baseline_rps,
            consecutive_alerts: state.consecutive_alerts,
            attack_duration: state.attack_started.map(|s| s.elapsed()),
        }
    }

    /// Reset the adaptive limiter to initial state
    pub fn reset(&self) {
        self.observations.write().clear();
        let initial = self.config.max_threshold / 2;
        self.threshold.store(initial, Ordering::Relaxed);
        *self.attack_state.write() = AttackDetection::default();
        self.under_attack_flag.store(false, Ordering::Relaxed);
    }
}

/// Baseline traffic statistics
#[derive(Debug, Clone)]
pub struct BaselineStats {
    /// Mean requests per second
    pub rps_mean: f64,
    /// RPS standard deviation
    pub rps_std: f64,
    /// Mean error rate
    pub error_rate_mean: f64,
    /// Mean P99 latency
    pub latency_p99_mean: f64,
    /// Number of samples
    pub sample_count: usize,
}

/// Attack detection info
#[derive(Debug, Clone)]
pub struct AttackInfo {
    /// Is under attack
    pub is_under_attack: bool,
    /// Baseline RPS before attack
    pub baseline_rps: f64,
    /// Consecutive alert count
    pub consecutive_alerts: u32,
    /// Duration of current attack (if any)
    pub attack_duration: Option<Duration>,
}

#[cfg(test)]
mod tests {
    use super::*;

    fn default_config() -> AdaptiveConfig {
        AdaptiveConfig {
            baseline_window: Duration::from_secs(300),
            z_threshold: 3.0,
            zero_std_z_score: 10.0,
            recovery_z_threshold: 1.0,
            min_threshold: 10,
            max_threshold: 10_000,
            consecutive_alert_trigger: 3,
            cooldown: Duration::from_millis(100), // Short for testing
            ema_alpha: 0.1,
            attack_factor: 0.5,
            headroom_factor: 1.5,
        }
    }

    fn make_observation(rps: f64) -> TrafficObservation {
        TrafficObservation {
            timestamp: Instant::now(),
            requests_per_second: rps,
            error_rate: 0.01,
            latency_p99_ms: 50.0,
            cpu_usage: 0.3,
        }
    }

    #[test]
    fn test_initial_state() {
        let limiter = AdaptiveRateLimiter::new(default_config());
        assert_eq!(limiter.current_threshold(), 5000); // max/2
        assert!(!limiter.is_under_attack());
    }

    #[test]
    fn test_insufficient_data_cold_start_protection() {
        let limiter = AdaptiveRateLimiter::new(default_config());
        let initial = limiter.current_threshold();

        // Feed < 10 observations — cold-start protection should provide
        // conservative protection by adjusting threshold based on observed traffic.
        // With RPS=100, cold-start sets threshold to min(2*100=200, current)
        for _ in 0..9 {
            limiter.update(make_observation(100.0));
        }
        
        // Cold-start protection should have tightened the threshold
        let threshold = limiter.current_threshold();
        assert!(threshold <= initial, 
            "Cold-start protection should provide conservative threshold: {} should be <= {}", 
            threshold, initial);
        // Specifically, it should be clamped to 2*100=200
        assert!(threshold <= 200, 
            "Cold-start threshold should be <= 2*RPS (200): {}", threshold);
    }

    #[test]
    fn test_normal_traffic_adjusts_threshold() {
        let limiter = AdaptiveRateLimiter::new(default_config());

        // Feed 20 stable observations
        for _ in 0..20 {
            limiter.update(make_observation(100.0));
        }

        // Threshold should adjust toward 100 * 1.5 = 150
        let threshold = limiter.current_threshold();
        // After EMA: 5000*(0.9) + 150*(0.1) = 4515, then further iterations bring it down
        // It should be moving toward 150 but slowly
        assert!(threshold < 5000, "Threshold should decrease toward ideal: {}", threshold);
    }

    #[test]
    fn test_attack_detection() {
        let mut config = default_config();
        config.consecutive_alert_trigger = 2;
        let limiter = AdaptiveRateLimiter::new(config);

        // Feed normal traffic baseline
        for _ in 0..15 {
            limiter.update(make_observation(100.0));
        }

        assert!(!limiter.is_under_attack());

        // Spike to trigger attack: baseline ~100, std ~0, so any value >> 100 triggers z > 3
        // With zero std, need non-zero std. Let's add some variance first.
        let limiter2 = AdaptiveRateLimiter::new(AdaptiveConfig {
            consecutive_alert_trigger: 2,
            cooldown: Duration::from_millis(100),
            ..default_config()
        });

        // Feed slightly varying traffic to get non-zero std
        for i in 0..20 {
            limiter2.update(make_observation(100.0 + (i as f64 % 3.0)));
        }

        // Now spike well above 3 standard deviations
        limiter2.update(make_observation(1000.0));
        limiter2.update(make_observation(1000.0));

        assert!(limiter2.is_under_attack(), "Should detect attack after spike");

        let info = limiter2.attack_info();
        assert!(info.is_under_attack);
        assert!(info.baseline_rps > 0.0);
    }

    #[test]
    fn test_attack_tightens_threshold() {
        let config = AdaptiveConfig {
            consecutive_alert_trigger: 2,
            cooldown: Duration::from_millis(50),
            attack_factor: 0.5,
            ..default_config()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Build baseline around 100 rps
        for i in 0..20 {
            limiter.update(make_observation(100.0 + (i as f64 % 5.0)));
        }
        let pre_attack = limiter.current_threshold();

        // Trigger attack
        limiter.update(make_observation(2000.0));
        limiter.update(make_observation(2000.0));

        assert!(limiter.is_under_attack());
        let post_attack = limiter.current_threshold();
        assert!(
            post_attack < pre_attack,
            "Threshold should tighten during attack: {} >= {}",
            post_attack,
            pre_attack
        );
    }

    #[test]
    fn test_attack_recovery() {
        let config = AdaptiveConfig {
            consecutive_alert_trigger: 2,
            cooldown: Duration::from_millis(10),
            ..default_config()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Build baseline
        for i in 0..20 {
            limiter.update(make_observation(100.0 + (i as f64 % 5.0)));
        }

        // Trigger attack
        limiter.update(make_observation(2000.0));
        limiter.update(make_observation(2000.0));
        assert!(limiter.is_under_attack());

        // Wait for cooldown
        std::thread::sleep(Duration::from_millis(20));

        // Feed normal traffic with z < 1
        for _ in 0..5 {
            limiter.update(make_observation(100.0));
        }

        assert!(!limiter.is_under_attack(), "Should recover after cooldown + normal traffic");
    }

    #[test]
    fn test_baseline_stats() {
        let limiter = AdaptiveRateLimiter::new(default_config());

        // No data yet
        assert!(limiter.baseline_stats().is_none());

        for i in 0..15 {
            limiter.update(make_observation(100.0 + (i as f64)));
        }

        let stats = limiter.baseline_stats().unwrap();
        assert!(stats.rps_mean > 100.0);
        assert!(stats.rps_std >= 0.0);
        assert_eq!(stats.sample_count, 15);
    }

    #[test]
    fn test_reset() {
        let limiter = AdaptiveRateLimiter::new(default_config());

        for _ in 0..20 {
            limiter.update(make_observation(100.0));
        }

        limiter.reset();
        assert_eq!(limiter.current_threshold(), 5000);
        assert!(!limiter.is_under_attack());
        assert!(limiter.baseline_stats().is_none());
    }

    #[test]
    fn test_threshold_clamped_to_bounds() {
        let config = AdaptiveConfig {
            min_threshold: 50,
            max_threshold: 200,
            ..default_config()
        };
        let limiter = AdaptiveRateLimiter::new(config);

        // Initial is clamped to max/2 = 100
        assert_eq!(limiter.current_threshold(), 100);

        // Feed very low traffic
        for _ in 0..20 {
            limiter.update(make_observation(1.0));
        }

        let threshold = limiter.current_threshold();
        assert!(threshold >= 50, "Threshold should not go below min: {}", threshold);
    }
}
