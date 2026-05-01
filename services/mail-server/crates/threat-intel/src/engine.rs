//! Threat intel engine — orchestrates IP/domain blocklist lookups and reputation scoring

use crate::config::{FeedEnforcementMode, ThreatIntelConfig};
use crate::domain_blocklist::DomainBlocklist;
use crate::ip_blocklist::IpBlocklist;
use crate::reputation::{self, ReputationClass, ReputationScore, SourceScore};

/// Threat intel lookup result
#[derive(Debug, Clone)]
pub struct ThreatVerdict {
    /// IP reputation (if IP was checked)
    pub ip_reputation: Option<ReputationScore>,
    /// Domain reputation (if domain was checked)
    pub domain_reputation: Option<ReputationScore>,
    /// Combined action recommendation
    pub action: ThreatAction,
    /// Summary
    pub summary: String,
}

/// Recommended action
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ThreatAction {
    /// No threat detected
    Allow,
    /// Suspicious — flag for monitoring
    Flag,
    /// Known threat — block
    Block,
}

impl std::fmt::Display for ThreatAction {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ThreatAction::Allow => write!(f, "ALLOW"),
            ThreatAction::Flag => write!(f, "FLAG"),
            ThreatAction::Block => write!(f, "BLOCK"),
        }
    }
}

/// The threat intelligence engine
pub struct ThreatIntelEngine {
    config: ThreatIntelConfig,
    ip_blocklist: IpBlocklist,
    domain_blocklist: DomainBlocklist,
}

impl ThreatIntelEngine {
    /// Create engine with default config
    pub fn new() -> Self {
        let config = ThreatIntelConfig::default();
        Self {
            ip_blocklist: IpBlocklist::new(config.max_ip_entries),
            domain_blocklist: DomainBlocklist::new(config.max_domain_entries),
            config,
        }
    }

    /// Create engine with custom config
    pub fn with_config(config: ThreatIntelConfig) -> Self {
        Self {
            ip_blocklist: IpBlocklist::new(config.max_ip_entries),
            domain_blocklist: DomainBlocklist::new(config.max_domain_entries),
            config,
        }
    }

    /// Get a reference to the IP blocklist for loading feeds
    pub fn ip_blocklist(&self) -> &IpBlocklist {
        &self.ip_blocklist
    }

    /// Get a reference to the domain blocklist for loading feeds
    pub fn domain_blocklist(&self) -> &DomainBlocklist {
        &self.domain_blocklist
    }

    /// Look up an IP address for threat intelligence
    pub fn check_ip(&self, ip_str: &str) -> ThreatVerdict {
        let mut sources = Vec::new();
        let mut trust_scores = Vec::new();
        let mut monitor_only = false;

        if let Some(entry) = self.ip_blocklist.lookup_str(ip_str) {
            let (effective_score, is_monitor_only) =
                self.feed_adjusted_score(&entry.source, entry.confidence);
            let trust = self.feed_trust_score(&entry.source);
            monitor_only |= is_monitor_only;
            sources.push(SourceScore {
                source: entry.source.clone(),
                score: effective_score,
                category: entry.category.to_string(),
            });
            trust_scores.push(trust);
        }

        // Use trust-weighted reputation scoring by default
        let ip_rep = reputation::compute_reputation_weighted(
            ip_str,
            sources,
            &trust_scores,
            self.config.flag_threshold,
            self.config.block_threshold,
        );

        let mut action = match ip_rep.classification {
            ReputationClass::Malicious => ThreatAction::Block,
            ReputationClass::Suspicious => ThreatAction::Flag,
            ReputationClass::Clean => ThreatAction::Allow,
        };

        if monitor_only && action == ThreatAction::Block {
            action = ThreatAction::Flag;
        }

        let summary = format!("IP {} — {} (score: {:.1})", ip_str, action, ip_rep.score);

        ThreatVerdict {
            ip_reputation: Some(ip_rep),
            domain_reputation: None,
            action,
            summary,
        }
    }

    /// Look up a domain for threat intelligence
    pub fn check_domain(&self, domain: &str) -> ThreatVerdict {
        let mut sources = Vec::new();
        let mut trust_scores = Vec::new();
        let mut monitor_only = false;

        if let Some(entry) = self.domain_blocklist.lookup(domain) {
            let (effective_score, is_monitor_only) =
                self.feed_adjusted_score(&entry.source, entry.confidence);
            let trust = self.feed_trust_score(&entry.source);
            monitor_only |= is_monitor_only;
            sources.push(SourceScore {
                source: entry.source.clone(),
                score: effective_score,
                category: entry.category.clone(),
            });
            trust_scores.push(trust);
        }

        // Use trust-weighted reputation scoring by default
        let domain_rep = reputation::compute_reputation_weighted(
            domain,
            sources,
            &trust_scores,
            self.config.flag_threshold,
            self.config.block_threshold,
        );

        let mut action = match domain_rep.classification {
            ReputationClass::Malicious => ThreatAction::Block,
            ReputationClass::Suspicious => ThreatAction::Flag,
            ReputationClass::Clean => ThreatAction::Allow,
        };

        if monitor_only && action == ThreatAction::Block {
            action = ThreatAction::Flag;
        }

        let summary = format!(
            "Domain {} — {} (score: {:.1})",
            domain, action, domain_rep.score
        );

        ThreatVerdict {
            ip_reputation: None,
            domain_reputation: Some(domain_rep),
            action,
            summary,
        }
    }

    /// Check both IP and domain, returning the worst verdict
    pub fn check(&self, ip_str: Option<&str>, domain: Option<&str>) -> ThreatVerdict {
        let ip_verdict = ip_str.map(|ip| self.check_ip(ip));
        let domain_verdict = domain.map(|d| self.check_domain(d));

        let ip_action = ip_verdict
            .as_ref()
            .map(|v| v.action)
            .unwrap_or(ThreatAction::Allow);
        let domain_action = domain_verdict
            .as_ref()
            .map(|v| v.action)
            .unwrap_or(ThreatAction::Allow);

        let worst_action = match (ip_action, domain_action) {
            (ThreatAction::Block, _) | (_, ThreatAction::Block) => ThreatAction::Block,
            (ThreatAction::Flag, _) | (_, ThreatAction::Flag) => ThreatAction::Flag,
            _ => ThreatAction::Allow,
        };

        let summary = format!(
            "IP: {} | Domain: {}",
            ip_verdict
                .as_ref()
                .map(|v| v.summary.as_str())
                .unwrap_or("not checked"),
            domain_verdict
                .as_ref()
                .map(|v| v.summary.as_str())
                .unwrap_or("not checked"),
        );

        ThreatVerdict {
            ip_reputation: ip_verdict.and_then(|v| v.ip_reputation),
            domain_reputation: domain_verdict.and_then(|v| v.domain_reputation),
            action: worst_action,
            summary,
        }
    }

    /// Purge all expired entries from both blocklists
    pub fn purge_expired(&self) -> usize {
        self.ip_blocklist.purge_expired() + self.domain_blocklist.purge_expired()
    }

    /// Statistics about current blocklist sizes
    pub fn stats(&self) -> ThreatIntelStats {
        ThreatIntelStats {
            ip_exact_entries: self.ip_blocklist.exact_count(),
            ip_cidr_entries: self.ip_blocklist.cidr_count(),
            domain_entries: self.domain_blocklist.count(),
        }
    }

    /// Check whether blocklist memory pressure is above the configured
    /// threshold and, if so, trigger an immediate purge of expired entries.
    /// Returns the number of entries purged. Call this after every feed
    /// refresh to prevent OOM when feeds grow unexpectedly.
    pub fn purge_if_pressure(&self) -> usize {
        let threshold = self.config.purge_pressure_threshold;
        let ip_load = (self.ip_blocklist.exact_count() + self.ip_blocklist.cidr_count()) as f64
            / self.config.max_ip_entries.max(1) as f64;
        let domain_load =
            self.domain_blocklist.count() as f64 / self.config.max_domain_entries.max(1) as f64;

        if ip_load >= threshold || domain_load >= threshold {
            self.purge_expired()
        } else {
            0
        }
    }

    fn feed_adjusted_score(&self, source_name: &str, raw_confidence: f64) -> (f64, bool) {
        let raw = raw_confidence.clamp(0.0, 10.0);
        let Some(feed) = self
            .config
            .feeds
            .iter()
            .find(|f| f.enabled && f.name.eq_ignore_ascii_case(source_name))
        else {
            return (raw, false);
        };

        let trust = feed.trust_score.clamp(0.0, 10.0);
        let trust_weight = trust / 10.0;
        let adjusted = raw * trust_weight;
        let monitor_only = feed.enforcement_mode == FeedEnforcementMode::Monitor
            || trust < self.config.min_feed_trust_score;

        (adjusted, monitor_only)
    }

    /// Get the configured trust score for a named feed (default 5.0 if unknown).
    fn feed_trust_score(&self, source_name: &str) -> f64 {
        self.config
            .feeds
            .iter()
            .find(|f| f.enabled && f.name.eq_ignore_ascii_case(source_name))
            .map(|f| f.trust_score.clamp(0.0, 10.0))
            // Unknown (unconfigured) feeds receive full trust so that trust-
            // weighting only reduces scores when explicitly configured.
            // Operators must actively set a low trust_score to down-weight a
            // feed; omitting a feed should never silently suppress blocking.
            .unwrap_or(10.0)
    }
}

#[cfg(feature = "events")]
impl ThreatIntelEngine {
    /// Check IP/domain and also produce a normalized security event.
    /// Requires the `events` feature flag (which enables the `mail-common` dep).
    pub fn check_with_event(
        &self,
        ip_str: Option<&str>,
        domain: Option<&str>,
        correlation: Option<mail_common::security::CorrelationContext>,
    ) -> (ThreatVerdict, mail_common::security::SecurityEvent) {
        let verdict = self.check(ip_str, domain);
        let correlation =
            correlation.unwrap_or_else(mail_common::security::CorrelationContext::generated);

        let (action, severity) = match verdict.action {
            ThreatAction::Allow => (
                mail_common::security::SecurityAction::Allow,
                mail_common::security::SecuritySeverity::Info,
            ),
            ThreatAction::Flag => (
                mail_common::security::SecurityAction::Monitor,
                mail_common::security::SecuritySeverity::Medium,
            ),
            ThreatAction::Block => (
                mail_common::security::SecurityAction::Block,
                mail_common::security::SecuritySeverity::High,
            ),
        };

        let ip_score = verdict
            .ip_reputation
            .as_ref()
            .map(|r| r.score)
            .unwrap_or(0.0);
        let domain_score = verdict
            .domain_reputation
            .as_ref()
            .map(|r| r.score)
            .unwrap_or(0.0);
        let risk_score = ip_score.max(domain_score).min(10.0);

        let mut event = mail_common::security::SecurityEvent::new(
            mail_common::security::SecuritySystem::ThreatIntel,
            action,
            severity,
            risk_score,
            verdict.summary.clone(),
            correlation,
        );

        if let Some(ip) = ip_str {
            event.metadata.insert("src_ip".to_string(), ip.to_string());
        }
        if let Some(dom) = domain {
            event.metadata.insert("domain".to_string(), dom.to_string());
        }

        if let Some(alert) = mail_common::security::ingest_security_event(event.clone()) {
            event
                .metadata
                .insert("composite_alert".to_string(), "true".to_string());
            event.metadata.insert(
                "composite_score".to_string(),
                format!("{:.2}", alert.composite_score),
            );
            event.metadata.insert(
                "composite_action".to_string(),
                format!("{:?}", alert.recommended_action),
            );
        }

        (verdict, event)
    }
}

impl Default for ThreatIntelEngine {
    fn default() -> Self {
        Self::new()
    }
}

/// Blocklist statistics
#[derive(Debug, Clone)]
pub struct ThreatIntelStats {
    /// Number of exact IP entries
    pub ip_exact_entries: usize,
    /// Number of CIDR range entries
    pub ip_cidr_entries: usize,
    /// Number of domain entries
    pub domain_entries: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::domain_blocklist::DomainBlockEntry;
    use crate::ip_blocklist::{IpBlockEntry, ThreatCategory};
    use chrono::Utc;

    fn ip_entry(cidr: &str) -> IpBlockEntry {
        IpBlockEntry {
            cidr: cidr.into(),
            source: "test-feed".into(),
            category: ThreatCategory::Spam,
            confidence: 9.0,
            added_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
        }
    }

    fn domain_entry(domain: &str) -> DomainBlockEntry {
        DomainBlockEntry {
            domain: domain.into(),
            source: "test-feed".into(),
            confidence: 9.0,
            category: "phishing".into(),
            added_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
        }
    }

    #[test]
    fn test_clean_ip() {
        let engine = ThreatIntelEngine::new();
        let verdict = engine.check_ip("8.8.8.8");
        assert_eq!(verdict.action, ThreatAction::Allow);
    }

    #[test]
    fn test_blocked_ip() {
        let engine = ThreatIntelEngine::new();
        engine
            .ip_blocklist()
            .add_ip("1.2.3.4".parse().expect("valid"), ip_entry("1.2.3.4"));
        let verdict = engine.check_ip("1.2.3.4");
        assert_eq!(verdict.action, ThreatAction::Block);
    }

    #[test]
    fn test_blocked_cidr() {
        let engine = ThreatIntelEngine::new();
        engine
            .ip_blocklist()
            .add_cidr("10.0.0.0/8", ip_entry("10.0.0.0/8"))
            .expect("valid");
        let verdict = engine.check_ip("10.1.2.3");
        assert_eq!(verdict.action, ThreatAction::Block);
    }

    #[test]
    fn test_blocked_domain() {
        let engine = ThreatIntelEngine::new();
        engine
            .domain_blocklist()
            .add("evil.com", domain_entry("evil.com"));
        let verdict = engine.check_domain("evil.com");
        assert_eq!(verdict.action, ThreatAction::Block);
    }

    #[test]
    fn test_subdomain_blocked() {
        let engine = ThreatIntelEngine::new();
        engine
            .domain_blocklist()
            .add("evil.com", domain_entry("evil.com"));
        let verdict = engine.check_domain("phish.evil.com");
        assert_eq!(verdict.action, ThreatAction::Block);
    }

    #[test]
    fn test_combined_check_worst_wins() {
        let engine = ThreatIntelEngine::new();
        engine
            .domain_blocklist()
            .add("evil.com", domain_entry("evil.com"));
        // IP is clean, domain is blocked → Block wins
        let verdict = engine.check(Some("8.8.8.8"), Some("evil.com"));
        assert_eq!(verdict.action, ThreatAction::Block);
    }

    #[test]
    fn test_stats() {
        let engine = ThreatIntelEngine::new();
        engine
            .ip_blocklist()
            .add_ip("1.2.3.4".parse().expect("valid"), ip_entry("1.2.3.4"));
        engine
            .ip_blocklist()
            .add_cidr("10.0.0.0/8", ip_entry("10.0.0.0/8"))
            .expect("valid");
        engine
            .domain_blocklist()
            .add("evil.com", domain_entry("evil.com"));

        let stats = engine.stats();
        assert_eq!(stats.ip_exact_entries, 1);
        assert_eq!(stats.ip_cidr_entries, 1);
        assert_eq!(stats.domain_entries, 1);
    }

    #[test]
    fn test_action_display() {
        assert_eq!(ThreatAction::Allow.to_string(), "ALLOW");
        assert_eq!(ThreatAction::Flag.to_string(), "FLAG");
        assert_eq!(ThreatAction::Block.to_string(), "BLOCK");
    }

    #[test]
    fn test_monitor_mode_caps_block_to_flag() {
        let mut config = ThreatIntelConfig::default();
        config.feeds = vec![crate::config::FeedSource {
            name: "test-feed".into(),
            url: "https://example.invalid/feed.txt".into(),
            format: crate::config::FeedFormat::PlainText,
            refresh_interval_secs: 3600,
            enabled: true,
            trust_score: 10.0,
            enforcement_mode: FeedEnforcementMode::Monitor,
        }];

        let engine = ThreatIntelEngine::with_config(config);
        engine.ip_blocklist().add_ip(
            "9.9.9.9".parse().expect("valid"),
            IpBlockEntry {
                cidr: "9.9.9.9".into(),
                source: "test-feed".into(),
                category: ThreatCategory::Malware,
                confidence: 10.0,
                added_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );

        let verdict = engine.check_ip("9.9.9.9");
        assert_eq!(verdict.action, ThreatAction::Flag);
    }
}
