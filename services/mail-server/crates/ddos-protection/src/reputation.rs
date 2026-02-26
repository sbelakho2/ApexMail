//! Reputation scoring system

use std::time::Instant;

/// IP reputation score with history
#[derive(Debug, Clone)]
pub struct ReputationScore {
    /// Current reputation score (0-100)
    /// - 0-10: Block immediately
    /// - 11-30: Issue challenges
    /// - 31-70: Normal operation
    /// - 71-100: Trusted
    pub score: u8,
    
    /// When this IP was first seen
    pub first_seen: Instant,
    
    /// Total requests from this IP
    pub total_requests: u64,
    
    /// Number of successful challenges
    pub challenges_passed: u32,
    
    /// Number of failed challenges
    pub challenges_failed: u32,
    
    /// Number of rate limit hits
    pub rate_limit_hits: u32,
    
    /// Number of blocked requests
    pub blocked_requests: u32,
    
    /// Is this IP from a known good source (e.g., verified API customer)
    pub is_trusted: bool,
    
    /// Is this IP from a known bad source (e.g., hosting provider abuse)
    pub is_flagged: bool,
}

impl Default for ReputationScore {
    fn default() -> Self {
        Self {
            score: 50,  // Neutral starting point
            first_seen: Instant::now(),
            total_requests: 0,
            challenges_passed: 0,
            challenges_failed: 0,
            rate_limit_hits: 0,
            blocked_requests: 0,
            is_trusted: false,
            is_flagged: false,
        }
    }
}

impl ReputationScore {
    /// Create a new reputation score with default values
    pub fn new() -> Self {
        Self::default()
    }
    
    /// Create a trusted reputation (high score)
    pub fn trusted() -> Self {
        Self {
            score: 90,
            is_trusted: true,
            ..Default::default()
        }
    }
    
    /// Create a flagged reputation (low score)
    pub fn flagged() -> Self {
        Self {
            score: 20,
            is_flagged: true,
            ..Default::default()
        }
    }
    
    /// Record a request
    pub fn record_request(&mut self) {
        self.total_requests = self.total_requests.saturating_add(1);
    }
    
    /// Record a passed challenge
    pub fn record_challenge_passed(&mut self) {
        self.challenges_passed = self.challenges_passed.saturating_add(1);
        // Increase reputation for passing challenges
        self.score = self.score.saturating_add(5).min(100);
    }
    
    /// Record a failed challenge
    pub fn record_challenge_failed(&mut self) {
        self.challenges_failed = self.challenges_failed.saturating_add(1);
        // Decrease reputation for failing challenges
        self.score = self.score.saturating_sub(10);
    }
    
    /// Record a rate limit hit
    pub fn record_rate_limit(&mut self) {
        self.rate_limit_hits = self.rate_limit_hits.saturating_add(1);
        // Slight reputation decrease
        self.score = self.score.saturating_sub(2);
    }
    
    /// Record a blocked request
    pub fn record_blocked(&mut self) {
        self.blocked_requests = self.blocked_requests.saturating_add(1);
        // Reputation decrease
        self.score = self.score.saturating_sub(5);
    }
    
    /// Decay score toward neutral over time
    pub fn decay_toward_neutral(&mut self, decay_amount: u8) {
        if self.is_trusted || self.is_flagged {
            // Trusted/flagged IPs don't decay
            return;
        }
        
        if self.score < 50 {
            self.score = self.score.saturating_add(decay_amount).min(50);
        } else if self.score > 50 {
            self.score = self.score.saturating_sub(decay_amount).max(50);
        }
    }
    
    /// Calculate challenge pass rate
    pub fn challenge_pass_rate(&self) -> f64 {
        let total = self.challenges_passed + self.challenges_failed;
        if total == 0 {
            return 1.0;  // No challenges = neutral
        }
        self.challenges_passed as f64 / total as f64
    }
    
    /// Calculate block rate
    pub fn block_rate(&self) -> f64 {
        if self.total_requests == 0 {
            return 0.0;
        }
        self.blocked_requests as f64 / self.total_requests as f64
    }
    
    /// Get reputation level
    pub fn level(&self) -> ReputationLevel {
        match self.score {
            0..=10 => ReputationLevel::Blocked,
            11..=30 => ReputationLevel::Suspicious,
            31..=70 => ReputationLevel::Normal,
            71..=100 => ReputationLevel::Trusted,
            _ => ReputationLevel::Normal,
        }
    }
}

/// Reputation level categories
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ReputationLevel {
    /// Should be blocked
    Blocked,
    /// Requires challenges
    Suspicious,
    /// Normal operation
    Normal,
    /// Trusted source
    Trusted,
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_default_reputation() {
        let rep = ReputationScore::default();
        assert_eq!(rep.score, 50);
        assert_eq!(rep.level(), ReputationLevel::Normal);
    }
    
    #[test]
    fn test_reputation_changes() {
        let mut rep = ReputationScore::default();
        
        // Fail challenges
        for _ in 0..5 {
            rep.record_challenge_failed();
        }
        assert!(rep.score < 50);
        assert_eq!(rep.level(), ReputationLevel::Blocked);
        
        // Pass challenges
        let mut rep = ReputationScore::default();
        for _ in 0..10 {
            rep.record_challenge_passed();
        }
        assert!(rep.score > 50);
        assert_eq!(rep.level(), ReputationLevel::Trusted);
    }
    
    #[test]
    fn test_decay() {
        let mut rep = ReputationScore::default();
        rep.score = 20;
        rep.decay_toward_neutral(5);
        assert_eq!(rep.score, 25);
        
        rep.score = 80;
        rep.decay_toward_neutral(5);
        assert_eq!(rep.score, 75);
    }
}
