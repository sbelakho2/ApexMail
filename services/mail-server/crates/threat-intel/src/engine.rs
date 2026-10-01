//! Threat intel engine — orchestrates IP/domain blocklist lookups and reputation scoring

use crate::config::{FeedEnforcementMode, ThreatIntelConfig};
use crate::domain_blocklist::DomainBlocklist;
use crate::ip_blocklist::{IpBlockEntry, UnifiedIpBlocklist};
use crate::reputation::{self, ReputationClass, ReputationScore, SourceScore};
use chrono::{DateTime, Utc};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Arc;

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
    /// Unified v4+v6 IP blocklist (previously IPv4-only, so every IPv6
    /// lookup failed open — a listed IPv6 attacker was always "clean").
    /// Kept behind a lock so a feed refresh can swap the whole set
    /// atomically; clones share state via internal Arcs.
    ip_blocklist: parking_lot::RwLock<UnifiedIpBlocklist>,
    domain_blocklist: parking_lot::RwLock<DomainBlocklist>,
    /// Consecutive/total feed refresh failures (observability).
    refresh_failures: Arc<AtomicU64>,
    /// Timestamp of the last successful non-empty feed refresh.
    last_refresh_ok: Arc<parking_lot::RwLock<Option<DateTime<Utc>>>>,
}

impl ThreatIntelEngine {
    /// Create engine with default config
    pub fn new() -> Self {
        let config = ThreatIntelConfig::default();
        Self {
            ip_blocklist: parking_lot::RwLock::new(UnifiedIpBlocklist::new(
                config.max_ip_entries,
                config.max_ip_entries / 2,
            )),
            domain_blocklist: parking_lot::RwLock::new(DomainBlocklist::new(
                config.max_domain_entries,
            )),
            config,
            refresh_failures: Arc::new(AtomicU64::new(0)),
            last_refresh_ok: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Create engine with custom config
    pub fn with_config(config: ThreatIntelConfig) -> Self {
        Self {
            ip_blocklist: parking_lot::RwLock::new(UnifiedIpBlocklist::new(
                config.max_ip_entries,
                config.max_ip_entries / 2,
            )),
            domain_blocklist: parking_lot::RwLock::new(DomainBlocklist::new(
                config.max_domain_entries,
            )),
            config,
            refresh_failures: Arc::new(AtomicU64::new(0)),
            last_refresh_ok: Arc::new(parking_lot::RwLock::new(None)),
        }
    }

    /// Get a handle to the unified (v4+v6) IP blocklist for loading feeds.
    /// The blocklist's internals are Arc-backed, so the returned clone
    /// shares state with the engine.
    pub fn ip_blocklist(&self) -> UnifiedIpBlocklist {
        self.ip_blocklist.read().clone()
    }

    /// Record a successful feed refresh.
    pub fn record_refresh_success(&self) {
        self.refresh_failures.store(0, Ordering::Relaxed);
        *self.last_refresh_ok.write() = Some(Utc::now());
    }

    /// Record a failed feed refresh (fetch error, parse error, or refused
    /// empty refresh). Failures are counted and observable instead of
    /// silently leaving stale data.
    pub fn record_refresh_failure(&self, _reason: &str) {
        self.refresh_failures.fetch_add(1, Ordering::Relaxed);
    }

    /// Number of consecutive feed refresh failures since the last success.
    pub fn refresh_failure_count(&self) -> u64 {
        self.refresh_failures.load(Ordering::Relaxed)
    }

    /// Timestamp of the last successful refresh, if any.
    pub fn last_successful_refresh(&self) -> Option<DateTime<Utc>> {
        *self.last_refresh_ok.read()
    }

    /// Merge a freshly loaded feed dataset into the blocklists, PER SOURCE
    /// (audit F6).
    ///
    /// Semantics:
    /// - Only the sources PRESENT in the payload have their entries replaced
    ///   (their old entries are removed first, then the fresh ones added).
    ///   Entries from every other source are kept (last-known per source).
    /// - Refuses (returns `false`, nothing touched) when BOTH inputs are
    ///   empty — a broken feed must not wipe the last-known-good blocklist.
    /// - If [`ThreatIntelConfig::drop_absent_sources_on_refresh`] is set,
    ///   entries of CONFIGURED feeds that are absent from the payload are
    ///   dropped as well (explicit operator opt-in; default is to keep
    ///   last-known-good per source).
    /// - On success indexes are optimized and the refresh is recorded as
    ///   successful.
    pub fn apply_feed_refresh(
        &self,
        ip_entries: Vec<(String, IpBlockEntry)>,
        domain_entries: Vec<(String, crate::domain_blocklist::DomainBlockEntry)>,
    ) -> bool {
        if ip_entries.is_empty() && domain_entries.is_empty() {
            self.record_refresh_failure("refused empty refresh (keeping last-known-good)");
            return false;
        }

        // Sources whose entries this refresh replaces.
        let mut refreshed_sources: Vec<String> = Vec::new();
        let mut push_source = |source: &str| {
            if !refreshed_sources
                .iter()
                .any(|s| s.eq_ignore_ascii_case(source))
            {
                refreshed_sources.push(source.to_string());
            }
        };
        for (_, entry) in &ip_entries {
            push_source(&entry.source);
        }
        for (_, entry) in &domain_entries {
            push_source(&entry.source);
        }

        // Rejection accounting lives OUTSIDE the lock scope so the
        // saturation handling below can see it. The DOMAIN path is counted
        // the same way: `DomainBlocklist::add` returns `false` at the cap,
        // and discarding that result silently is exactly the fail-open the
        // IP-path fix closed (adversarial verification found it still
        // open here).
        let ip_total = ip_entries.len();
        let mut ip_rejected = 0usize;
        let domain_total = domain_entries.len();
        let mut domain_rejected = 0usize;
        {
            let ips = self.ip_blocklist.write();
            let domains = self.domain_blocklist.write();

            // Replace only the refreshed sources' entries; keep the rest.
            for source in &refreshed_sources {
                ips.remove_source(source);
                domains.remove_source(source);
            }

            // Optional opt-in: drop entries of configured feeds that failed
            // to contribute to this refresh (absent from the payload).
            if self.config.drop_absent_sources_on_refresh {
                for feed in &self.config.feeds {
                    if !feed.enabled {
                        continue;
                    }
                    if !refreshed_sources
                        .iter()
                        .any(|s| s.eq_ignore_ascii_case(&feed.name))
                    {
                        ips.remove_source(&feed.name);
                        domains.remove_source(&feed.name);
                    }
                }
            }

            // Audit finding: a full blocklist previously discarded feed
            // entries SILENTLY (`let _ = add_cidr(...)` discards the
            // BlocklistFull error, `add_ip_str`'s false is ignored). Once
            // `max_ip_entries` was reached, every refresh reported success
            // while absorbing zero new IoCs — newly listed attacker
            // infrastructure scored Clean indefinitely. Rejections are now
            // counted, logged, and surfaced: a material drop refuses to
            // report success (degraded state + failure counter) instead of
            // pretending the feed refreshed.
            for (cidr, entry) in ip_entries {
                let accepted = if cidr.contains('/') {
                    ips.add_cidr(&cidr, entry).is_ok()
                } else {
                    ips.add_ip_str(&cidr, entry)
                };
                if !accepted {
                    ip_rejected += 1;
                }
            }
            ips.optimize();

            for (domain, entry) in domain_entries {
                if !domains.add(&domain, entry) {
                    domain_rejected += 1;
                }
            }
        }

        let rejected = ip_rejected + domain_rejected;
        let total = ip_total + domain_total;
        if rejected > 0 {
            FEED_ENTRIES_REJECTED.fetch_add(rejected as u64, Ordering::Relaxed);
            tracing::warn!(
                rejected,
                total,
                ip_rejected,
                domain_rejected,
                "blocklist saturation: feed entries dropped on refresh (they were NOT loaded)"
            );
            let dropped_fraction = rejected as f64 / total.max(1) as f64;
            if dropped_fraction >= FEED_SATURATION_REFUSAL_FRACTION {
                // Material drop: the entries that fit remain loaded
                // (degraded), but the refresh must not read as success —
                // the failure counter increments and
                // `last_successful_refresh` does not advance.
                self.record_refresh_failure(&format!(
                    "blocklist saturated: {rejected} of {total} feed entries dropped — refresh is DEGRADED, not fully applied"
                ));
                return false;
            }
        }

        self.record_refresh_success();
        true
    }

    /// Get a handle to the domain blocklist for loading feeds.
    /// The blocklist's internals are Arc-backed, so the returned clone
    /// shares state with the engine.
    pub fn domain_blocklist(&self) -> DomainBlocklist {
        self.domain_blocklist.read().clone()
    }

    /// Look up an IP address for threat intelligence
    pub fn check_ip(&self, ip_str: &str) -> ThreatVerdict {
        let mut sources = Vec::new();
        let mut trust_scores = Vec::new();
        let mut monitor_only = false;

        let ip_hit = self.ip_blocklist.read().lookup_str(ip_str);
        if let Some(entry) = ip_hit {
            // Entries whose feed is explicitly DISABLED must not score at
            // all — previously they fell through with full trust and could
            // still produce hard blocks.
            if !self.feed_disabled(&entry.source) {
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

        let domain_hit = self.domain_blocklist.read().lookup(domain);
        if let Some(entry) = domain_hit {
            if !self.feed_disabled(&entry.source) {
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
        self.ip_blocklist.read().purge_expired() + self.domain_blocklist.read().purge_expired()
    }

    /// Statistics about current blocklist sizes
    pub fn stats(&self) -> ThreatIntelStats {
        let ips = self.ip_blocklist.read();
        ThreatIntelStats {
            ip_exact_entries: ips.exact_count(),
            ip_cidr_entries: ips.cidr_count(),
            domain_entries: self.domain_blocklist.read().count(),
        }
    }

    /// Check whether blocklist memory pressure is above the configured
    /// threshold and, if so, trigger an immediate purge of expired entries.
    /// Returns the number of entries purged. Call this after every feed
    /// refresh to prevent OOM when feeds grow unexpectedly.
    pub fn purge_if_pressure(&self) -> usize {
        let threshold = self.config.purge_pressure_threshold;
        let ip_counts = {
            let ips = self.ip_blocklist.read();
            (ips.exact_count(), ips.cidr_count())
        };
        let domain_count = self.domain_blocklist.read().count();
        let ip_load = (ip_counts.0 + ip_counts.1) as f64 / self.config.max_ip_entries.max(1) as f64;
        let domain_load = domain_count as f64 / self.config.max_domain_entries.max(1) as f64;

        if ip_load >= threshold || domain_load >= threshold {
            self.purge_expired()
        } else {
            0
        }
    }

    /// Whether the named feed is explicitly configured as disabled.
    /// Unconfigured (legacy) sources are treated as enabled so existing
    /// behavior is preserved; disabled feeds contribute nothing.
    fn feed_disabled(&self, source_name: &str) -> bool {
        self.config
            .feeds
            .iter()
            .any(|f| !f.enabled && f.name.eq_ignore_ascii_case(source_name))
    }

    /// Effective score and monitor-only flag for a hit from `source_name`.
    ///
    /// The RAW confidence is returned unmodified: trust weighting is
    /// applied exactly ONCE, inside
    /// [`reputation::compute_reputation_weighted`]. Pre-scaling here as
    /// well double-applied trust — a confidence-10 hit from a trust-7
    /// feed scored 5.7 instead of 8.2 and fell below the block threshold,
    /// so confirmed-malicious verdicts were silently dampened to Flags.
    ///
    /// UNCONFIGURED sources (audit F6) are always monitor-only: a feed the
    /// operator never vouched for can contribute to scoring but can never
    /// produce an Enforce (Block) outcome — to make a source enforceable it
    /// must be added to `config.feeds` with `Enforce` and sufficient trust.
    fn feed_adjusted_score(&self, source_name: &str, raw_confidence: f64) -> (f64, bool) {
        let raw = raw_confidence.clamp(0.0, 10.0);
        let Some(feed) = self
            .config
            .feeds
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(source_name))
        else {
            return (raw, true);
        };

        let trust = feed.trust_score.clamp(0.0, 10.0);
        let monitor_only = feed.enforcement_mode == FeedEnforcementMode::Monitor
            || trust < self.config.min_feed_trust_score;

        (raw, monitor_only)
    }

    /// Get the configured trust score for a named feed.
    ///
    /// UNCONFIGURED sources (audit F6) receive a LOW default trust
    /// ([`UNCONFIGURED_FEED_TRUST`]) instead of full trust: an operator who
    /// never configured a feed should not be silently granting it the
    /// ability to hard-block traffic. Raise the trust explicitly in config
    /// to weight a feed more strongly.
    fn feed_trust_score(&self, source_name: &str) -> f64 {
        self.config
            .feeds
            .iter()
            .find(|f| f.name.eq_ignore_ascii_case(source_name))
            .map(|f| f.trust_score.clamp(0.0, 10.0))
            .unwrap_or(UNCONFIGURED_FEED_TRUST)
    }
}

/// Default trust granted to sources that are NOT configured in
/// [`ThreatIntelConfig::feeds`] (audit F6). Low on purpose: unconfigured
/// feeds can never produce Enforce (Block) verdicts — see
/// [`ThreatIntelEngine::feed_adjusted_score`].
const UNCONFIGURED_FEED_TRUST: f64 = 3.0;

/// Fraction of a refresh's IP entries that may be dropped because the
/// blocklist is full before the refresh stops reporting success (audit:
/// silent fail-open on saturation). Below this threshold the drop is still
/// counted and logged, but a refresh absorbing almost all of its payload is
/// not treated as failed.
const FEED_SATURATION_REFUSAL_FRACTION: f64 = 0.1;

/// Process-wide total of feed entries DROPPED because a blocklist was at
/// capacity (audit: previously discarded with `let _ = ...`, invisible to
/// operators). Observable via [`feed_entries_rejected_total`].
pub static FEED_ENTRIES_REJECTED: AtomicU64 = AtomicU64::new(0);

/// Total feed entries dropped due to blocklist saturation since process
/// start. A steadily increasing value means the configured
/// `max_ip_entries` cap is too small for the live feeds and verdicts are
/// computed from an incomplete IoC set.
pub fn feed_entries_rejected_total() -> u64 {
    FEED_ENTRIES_REJECTED.load(Ordering::Relaxed)
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

    /// Engine whose config registers "test-feed" as a trusted Enforce feed.
    /// Audit F6 made UNCONFIGURED sources low-trust/monitor-only, so tests
    /// that assert Block verdicts from the test feed must configure it.
    fn configured_engine() -> ThreatIntelEngine {
        let mut config = ThreatIntelConfig::default();
        config.feeds.push(crate::config::FeedSource {
            name: "test-feed".into(),
            url: "https://example.invalid/feed.txt".into(),
            format: crate::config::FeedFormat::PlainText,
            refresh_interval_secs: 3600,
            enabled: true,
            trust_score: 9.5,
            enforcement_mode: FeedEnforcementMode::Enforce,
        });
        ThreatIntelEngine::with_config(config)
    }

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
        let engine = configured_engine();
        engine
            .ip_blocklist()
            .add_ip_str("1.2.3.4", ip_entry("1.2.3.4"));
        let verdict = engine.check_ip("1.2.3.4");
        assert_eq!(verdict.action, ThreatAction::Block);
    }

    #[test]
    fn test_blocked_cidr() {
        let engine = configured_engine();
        engine
            .ip_blocklist()
            .add_cidr("10.0.0.0/8", ip_entry("10.0.0.0/8"))
            .expect("valid");
        let verdict = engine.check_ip("10.1.2.3");
        assert_eq!(verdict.action, ThreatAction::Block);
    }

    #[test]
    fn test_blocked_domain() {
        let engine = configured_engine();
        engine
            .domain_blocklist()
            .add("evil.com", domain_entry("evil.com"));
        let verdict = engine.check_domain("evil.com");
        assert_eq!(verdict.action, ThreatAction::Block);
    }

    #[test]
    fn test_subdomain_blocked() {
        let engine = configured_engine();
        engine
            .domain_blocklist()
            .add("evil.com", domain_entry("evil.com"));
        let verdict = engine.check_domain("phish.evil.com");
        assert_eq!(verdict.action, ThreatAction::Block);
    }

    #[test]
    fn test_combined_check_worst_wins() {
        let engine = configured_engine();
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
            .add_ip_str("1.2.3.4", ip_entry("1.2.3.4"));
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
    fn test_confirmed_malicious_single_source_reaches_block() {
        // Fail-first: trust was applied TWICE — the engine pre-scaled the
        // raw confidence by trust/10 and the reputation composite scaled
        // by trust again. A confidence-10 hit from a trust-7 feed landed
        // at 5.7, below the block threshold (7.0): confirmed-malicious
        // verdicts were dampened to Flags. Trust must be applied once.
        let config = ThreatIntelConfig {
            feeds: vec![crate::config::FeedSource {
                name: "trust7-feed".into(),
                url: "https://example.invalid/feed.txt".into(),
                format: crate::config::FeedFormat::PlainText,
                refresh_interval_secs: 3600,
                enabled: true,
                trust_score: 7.0,
                enforcement_mode: FeedEnforcementMode::Enforce,
            }],
            ..ThreatIntelConfig::default()
        };
        let engine = ThreatIntelEngine::with_config(config);
        engine.ip_blocklist().add_ip_str(
            "203.0.113.7",
            IpBlockEntry {
                cidr: "203.0.113.7".into(),
                source: "trust7-feed".into(),
                category: ThreatCategory::Malware,
                confidence: 10.0,
                added_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );
        let verdict = engine.check_ip("203.0.113.7");
        assert_eq!(
            verdict.action,
            ThreatAction::Block,
            "confidence-10 / trust-7 single-source hit must Block (got score {})",
            verdict
                .ip_reputation
                .as_ref()
                .map(|r| r.score)
                .unwrap_or(0.0)
        );
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
        engine.ip_blocklist().add_ip_str(
            "9.9.9.9",
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

    // ── Security-fix regression tests ──

    #[test]
    fn test_ipv6_lookup_no_longer_fails_open() {
        let engine = configured_engine();
        // A listed IPv6 IOC must produce a Block verdict — previously the
        // engine consulted an IPv4-only blocklist and every IPv6 lookup
        // came back clean.
        engine
            .ip_blocklist()
            .add_ip_str("2001:db8:dead:beef::1", ip_entry("2001:db8:dead:beef::1"));
        let verdict = engine.check_ip("2001:db8:dead:beef::1");
        assert_eq!(
            verdict.action,
            ThreatAction::Block,
            "IPv6 IOC must block IPv6 lookup"
        );

        // IPv6 CIDR too.
        engine
            .ip_blocklist()
            .add_cidr("2620:0:2d0::/48", ip_entry("2620:0:2d0::/48"))
            .expect("valid v6 cidr");
        let verdict = engine.check_ip("2620:0:2d0:9::1");
        assert_eq!(verdict.action, ThreatAction::Block);

        // Unlisted IPv6 stays clean.
        let verdict = engine.check_ip("2001:4860:4860::8888");
        assert_eq!(verdict.action, ThreatAction::Allow);
    }

    #[test]
    fn test_disabled_feed_entry_does_not_score() {
        let mut config = ThreatIntelConfig::default();
        config.feeds = vec![crate::config::FeedSource {
            name: "stale-feed".into(),
            url: "https://example.invalid/feed.txt".into(),
            format: crate::config::FeedFormat::PlainText,
            refresh_interval_secs: 3600,
            enabled: false,
            trust_score: 9.0,
            enforcement_mode: FeedEnforcementMode::Enforce,
        }];
        let engine = ThreatIntelEngine::with_config(config);
        engine.ip_blocklist().add_ip_str(
            "203.0.113.77",
            IpBlockEntry {
                cidr: "203.0.113.77".into(),
                source: "stale-feed".into(),
                category: ThreatCategory::Malware,
                confidence: 10.0,
                added_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );
        let verdict = engine.check_ip("203.0.113.77");
        assert_eq!(
            verdict.action,
            ThreatAction::Allow,
            "entries from a disabled feed must not score (previously full-trust Enforce)"
        );
    }

    #[test]
    fn test_empty_refresh_keeps_last_known_good() {
        let engine = configured_engine();
        engine
            .ip_blocklist()
            .add_ip_str("198.51.100.23", ip_entry("198.51.100.23"));
        engine
            .domain_blocklist()
            .add("evil.example", domain_entry("evil.example"));

        // A feed that suddenly returns nothing must NOT wipe the blocklists.
        let applied = engine.apply_feed_refresh(Vec::new(), Vec::new());
        assert!(!applied, "empty refresh must be refused");
        assert_eq!(engine.check_ip("198.51.100.23").action, ThreatAction::Block);
        assert_eq!(
            engine.check_domain("evil.example").action,
            ThreatAction::Block
        );
        assert!(engine.refresh_failure_count() >= 1, "failure is counted");
        assert!(engine.last_successful_refresh().is_none());
    }

    // ── Audit F6:unconfigured sources & per-source refresh merging ──

    #[test]
    fn test_unconfigured_source_gets_low_default_trust() {
        // A hit from a source that is NOT in config.feeds previously got
        // FULL trust (unwrap_or(10.0)); it must now be down-weighted.
        let engine = ThreatIntelEngine::new(); // default feeds, no "mystery-feed"
        assert_eq!(engine.feed_trust_score("mystery-feed"), 3.0);
        assert_eq!(engine.feed_trust_score("TEST-FEED-CASE"), 3.0);
        // Configured feeds keep their configured trust.
        assert_eq!(engine.feed_trust_score("Spamhaus DROP"), 9.5);
    }

    #[test]
    fn test_unconfigured_source_can_never_block() {
        // Even a confidence-10 hit from an unconfigured source must not
        // produce an Enforce (Block) verdict — it is monitor-only and
        // down-weighted. Previously it blocked with full trust.
        let engine = ThreatIntelEngine::new();
        engine.ip_blocklist().add_ip_str(
            "203.0.113.111",
            IpBlockEntry {
                cidr: "203.0.113.111".into(),
                source: "mystery-feed".into(),
                category: ThreatCategory::Malware,
                confidence: 10.0,
                added_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::hours(1),
            },
        );
        let verdict = engine.check_ip("203.0.113.111");
        assert_ne!(
            verdict.action,
            ThreatAction::Block,
            "unconfigured source must never produce a Block verdict"
        );
        let score = verdict
            .ip_reputation
            .as_ref()
            .map(|r| r.score)
            .unwrap_or(0.0);
        assert!(
            score < engine.config.block_threshold,
            "weighted score must stay below the block threshold, got {score}"
        );
        // The same hit from a configured trusted feed DOES block.
        let engine = configured_engine();
        engine
            .ip_blocklist()
            .add_ip_str("203.0.113.112", ip_entry("203.0.113.112"));
        assert_eq!(engine.check_ip("203.0.113.112").action, ThreatAction::Block);
    }

    #[test]
    fn test_feed_refresh_merges_per_source() {
        // Refreshing source B must replace ONLY B's entries; A's entries and
        // unrelated sources' entries survive (previously refresh REPLACED the
        // whole blocklist, wiping every other feed's data).
        let engine = configured_engine();
        engine
            .ip_blocklist()
            .add_ip_str("198.51.100.10", ip_entry("198.51.100.10")); // source A ("test-feed")

        let refresh_b = vec![(
            "198.51.100.20".to_string(),
            IpBlockEntry {
                cidr: "198.51.100.20".into(),
                source: "feed-b".into(),
                category: ThreatCategory::Spam,
                confidence: 9.0,
                added_at: Utc::now(),
                expires_at: Utc::now() + chrono::Duration::hours(24),
            },
        )];
        assert!(engine.apply_feed_refresh(refresh_b, Vec::new()));

        // A's entry survived; B's entry was added.
        assert_eq!(engine.check_ip("198.51.100.10").action, ThreatAction::Block);
        assert_eq!(engine.check_ip("198.51.100.20").action, ThreatAction::Flag);

        // Refreshing A replaces only A: the old A address disappears, the
        // new A address appears, and B's entry is untouched.
        let refresh_a = vec![(
            "198.51.100.11".to_string(),
            ip_entry("198.51.100.11"), // source "test-feed" = A
        )];
        assert!(engine.apply_feed_refresh(refresh_a, Vec::new()));
        assert_eq!(
            engine.check_ip("198.51.100.10").action,
            ThreatAction::Allow,
            "refreshed source's OLD entry must be replaced"
        );
        assert_eq!(engine.check_ip("198.51.100.11").action, ThreatAction::Block);
        assert_eq!(
            engine.check_ip("198.51.100.20").action,
            ThreatAction::Flag,
            "other sources' entries must survive a per-source refresh"
        );
    }

    // ── Blocklist saturation: dropped entries are counted, never silent ──

    #[test]
    fn saturated_blocklist_refresh_does_not_report_success() {
        // Audit finding: `add_cidr`/`add_ip_str` rejections were discarded
        // with `let _ = ...`, so a saturated blocklist kept reporting every
        // refresh as successful while absorbing zero new IoCs.
        let config = ThreatIntelConfig {
            max_ip_entries: 4, // tiny cap on purpose
            ..ThreatIntelConfig::default()
        };
        let engine = ThreatIntelEngine::with_config(config);
        let entries: Vec<_> = (0..10)
            .map(|i| {
                let ip = format!("198.51.100.{i}");
                (ip.clone(), ip_entry(&ip))
            })
            .collect();
        let rejected_before = feed_entries_rejected_total();

        // 6 of 10 entries cannot fit — a material drop (60% ≥ 10%) must
        // refuse to report success.
        assert!(
            !engine.apply_feed_refresh(entries, Vec::new()),
            "a refresh dropping most of its payload must not report success"
        );
        assert!(
            engine.refresh_failure_count() >= 1,
            "saturation must be recorded as a refresh failure"
        );
        assert!(
            feed_entries_rejected_total() >= rejected_before + 6,
            "every dropped entry must be counted"
        );
        assert_eq!(
            engine.stats().ip_exact_entries,
            4,
            "only the entries that fit are loaded (degraded, not wiped)"
        );
        assert!(
            engine.last_successful_refresh().is_none(),
            "a saturated refresh must not advance last_successful_refresh"
        );
    }

    #[test]
    fn marginal_blocklist_saturation_is_counted_but_refresh_succeeds() {
        // A single dropped entry (≈7.7% < 10%) is logged and counted but is
        // not a failed refresh.
        let config = ThreatIntelConfig {
            max_ip_entries: 12,
            ..ThreatIntelConfig::default()
        };
        let engine = ThreatIntelEngine::with_config(config);
        let entries: Vec<_> = (0..13)
            .map(|i| {
                let ip = format!("203.0.113.{i}");
                (ip.clone(), ip_entry(&ip))
            })
            .collect();
        let rejected_before = feed_entries_rejected_total();
        assert!(
            engine.apply_feed_refresh(entries, Vec::new()),
            "a sub-material drop must not fail the refresh"
        );
        assert!(
            feed_entries_rejected_total() >= rejected_before + 1,
            "the dropped entry must still be counted"
        );
        assert_eq!(
            engine.refresh_failure_count(),
            0,
            "sub-material saturation must not count as a refresh failure"
        );
    }

    #[test]
    fn saturated_domain_blocklist_drops_are_counted_and_refuse_success() {
        // Adversarial verification of the saturation fix: the DOMAIN
        // blocklist has the same saturation semantics
        // (`DomainBlocklist::add` returns `false` at the cap), and its
        // result was still discarded after the IP path was repaired — a
        // saturated domain list silently absorbed zero new IoC domains
        // while every refresh reported success. The same discipline must
        // apply: counted, logged, refused at a material fraction.
        let config = ThreatIntelConfig {
            max_domain_entries: 4, // tiny cap on purpose
            ..ThreatIntelConfig::default()
        };
        let engine = ThreatIntelEngine::with_config(config);
        let entries: Vec<_> = (0..10)
            .map(|i| {
                let domain = format!("evil{i}.example");
                (domain.clone(), domain_entry(&domain))
            })
            .collect();
        let rejected_before = feed_entries_rejected_total();

        // 6 of 10 domain entries cannot fit — a material drop (60% ≥ 10%)
        // must refuse to report success.
        assert!(
            !engine.apply_feed_refresh(Vec::new(), entries),
            "a refresh dropping most of its domain payload must not report success"
        );
        assert!(
            engine.refresh_failure_count() >= 1,
            "domain saturation must be recorded as a refresh failure"
        );
        assert!(
            feed_entries_rejected_total() >= rejected_before + 6,
            "every dropped domain entry must be counted"
        );
        assert_eq!(
            engine.stats().domain_entries,
            4,
            "only the domain entries that fit are loaded (degraded, not wiped)"
        );
        assert!(
            engine.last_successful_refresh().is_none(),
            "a saturated refresh must not advance last_successful_refresh"
        );
    }

    #[test]
    fn test_drop_absent_sources_on_refresh_is_opt_in() {
        fn feed_cfg(drop: bool) -> ThreatIntelConfig {
            let mut config = ThreatIntelConfig {
                drop_absent_sources_on_refresh: drop,
                ..ThreatIntelConfig::default()
            };
            config.feeds.push(crate::config::FeedSource {
                name: "feed-a".into(),
                url: "https://example.invalid/a.txt".into(),
                format: crate::config::FeedFormat::PlainText,
                refresh_interval_secs: 3600,
                enabled: true,
                trust_score: 9.5,
                enforcement_mode: FeedEnforcementMode::Enforce,
            });
            config.feeds.push(crate::config::FeedSource {
                name: "feed-b".into(),
                url: "https://example.invalid/b.txt".into(),
                format: crate::config::FeedFormat::PlainText,
                refresh_interval_secs: 3600,
                enabled: true,
                trust_score: 9.5,
                enforcement_mode: FeedEnforcementMode::Enforce,
            });
            config
        }

        let entry = |source: &str| IpBlockEntry {
            cidr: format!("198.51.100.{source}"),
            source: source.to_string(),
            category: ThreatCategory::Spam,
            confidence: 9.0,
            added_at: Utc::now(),
            expires_at: Utc::now() + chrono::Duration::hours(24),
        };

        // Default (drop = false): a refresh carrying only feed-a's entries
        // KEEPS feed-b's last-known entries.
        let engine = ThreatIntelEngine::with_config(feed_cfg(false));
        engine
            .ip_blocklist()
            .add_ip_str("198.51.100.30", entry("feed-a"));
        engine
            .ip_blocklist()
            .add_ip_str("198.51.100.40", entry("feed-b"));
        let only_a = vec![("198.51.100.31".to_string(), entry("feed-a"))];
        assert!(engine.apply_feed_refresh(only_a, Vec::new()));
        assert_eq!(engine.check_ip("198.51.100.31").action, ThreatAction::Block);
        assert_eq!(
            engine.check_ip("198.51.100.40").action,
            ThreatAction::Block,
            "default: absent source keeps last-known-good entries"
        );

        // Opt-in (drop = true): feed-b (configured but absent) is dropped.
        let engine = ThreatIntelEngine::with_config(feed_cfg(true));
        engine
            .ip_blocklist()
            .add_ip_str("198.51.100.30", entry("feed-a"));
        engine
            .ip_blocklist()
            .add_ip_str("198.51.100.40", entry("feed-b"));
        let only_a = vec![("198.51.100.31".to_string(), entry("feed-a"))];
        assert!(engine.apply_feed_refresh(only_a, Vec::new()));
        assert_eq!(engine.check_ip("198.51.100.31").action, ThreatAction::Block);
        assert_eq!(
            engine.check_ip("198.51.100.40").action,
            ThreatAction::Allow,
            "opt-in: absent configured source entries are dropped"
        );
    }
}
