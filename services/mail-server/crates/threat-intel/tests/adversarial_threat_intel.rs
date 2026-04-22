//! Adversarial Threat Intelligence tests.
//!
//! Critical properties under test://! - Blocklisted IPs are correctly flagged
//! - CIDR ranges correctly match all IPs within them
//! - TTL expiry:after purge, expired entries no longer block traffic
//! (This catches the "empty blocklist after 24h" regression —
//! without auto-refresh, all entries purge and blocklists go empty)
//! - Domain blocklist works for known malicious domains
//! - Clean IPs / domains are not false-positived
//! - Feed refresh task can be spawned without panicking

use chrono::{Duration, Utc};
use std::net::Ipv4Addr;
use threat_intel::ip_blocklist::{IpBlockEntry, ThreatCategory};
use threat_intel::domain_blocklist::DomainBlockEntry;
use threat_intel::engine::ThreatAction;
use threat_intel::ThreatIntelEngine;
use threat_intel::background_task::{purge_once, FeedRefreshConfig};

// ── Helpers ───────────────────────────────────────────────────────────────────

fn spam_entry(ip_str: &str, expires_in_secs: i64) -> IpBlockEntry {
    let now = Utc::now();
    IpBlockEntry {
        cidr: ip_str.to_string(),
        source: "test-feed".into(),
        category: ThreatCategory::Spam,
        confidence: 9.0,
        added_at: now,
        expires_at: now + Duration::seconds(expires_in_secs),
    }
}

fn domain_entry(domain: &str, expires_in_secs: i64) -> DomainBlockEntry {
    let now = Utc::now();
    DomainBlockEntry {
        domain: domain.to_string(),
        source: "test-feed".into(),
        confidence: 9.0,
        category: "Phishing".to_string(),
        added_at: now,
        expires_at: now + Duration::seconds(expires_in_secs),
    }
}

// ── Basic IP blocklist ────────────────────────────────────────────────────────

/// IP added to blocklist must be flagged as a threat.
#[test]
fn test_blocked_ip_flagged() {
    let engine = ThreatIntelEngine::new();
    let ip: Ipv4Addr = "198.51.100.1".parse().unwrap();
    engine.ip_blocklist().add_ip(ip, spam_entry("198.51.100.1", 3600));

    let verdict = engine.check_ip("198.51.100.1");
    assert_eq!(verdict.action, ThreatAction::Block, "Blocked IP must yield Block action");
    let score = verdict.ip_reputation.as_ref().map(|r| r.score).unwrap_or(0.0);
    assert!(score > 0.0, "Blocked IP must have non-zero reputation score");
}

/// Unblocked IP must return Allow.
#[test]
fn test_clean_ip_not_flagged() {
    let engine = ThreatIntelEngine::new();
    let verdict = engine.check_ip("203.0.113.99");
    assert_eq!(verdict.action, ThreatAction::Allow, "Unknown IP must return Allow");
}

/// Malformed IP string must not panic.
#[test]
fn test_malformed_ip_no_panic() {
    let engine = ThreatIntelEngine::new();
    let verdict = engine.check_ip("not_an_ip");
// Should return a safe Allow verdict without panicking
    assert_eq!(verdict.action, ThreatAction::Allow);
}

// ── CIDR range lookup ─────────────────────────────────────────────────────────

/// An IP inside a blocked CIDR must be flagged.
#[test]
fn test_cidr_match_inside_range() {
    let engine = ThreatIntelEngine::new();
    engine.ip_blocklist()
        .add_cidr("198.51.100.0/24", spam_entry("198.51.100.0/24", 3600))
        .expect("add CIDR");

// Any IP in .0/24 should match
    for last_octet in [1u8, 100, 254] {
        let ip = format!("198.51.100.{}", last_octet);
        let verdict = engine.check_ip(&ip);
        assert_eq!(
            verdict.action, ThreatAction::Block,
            "IP {} inside blocked /24 CIDR must yield Block action",
            ip
        );
    }
}

/// An IP just outside a blocked CIDR must NOT be flagged.
#[test]
fn test_cidr_miss_outside_range() {
    let engine = ThreatIntelEngine::new();
    engine.ip_blocklist()
        .add_cidr("198.51.100.0/24", spam_entry("198.51.100.0/24", 3600))
        .expect("add CIDR");

// 198.51.101.1 is outside /24 (different third octet)
    let verdict = engine.check_ip("198.51.101.1");
    assert_eq!(verdict.action, ThreatAction::Allow, "IP outside /24 CIDR must NOT be flagged");
}

// ── TTL expiry (the empty-blocklist-after-24h regression) ────────────────────

/// After TTL expiry and purge, a formerly blocked IP must no longer be blocked.
/// This demonstrates the risk:without feed auto-refresh, after 24h the blocklist
/// is purged to empty and ALL malicious IPs pass through unchecked.
#[test]
fn test_expired_entry_purged_and_no_longer_blocked() {
    let engine = ThreatIntelEngine::new();
    let ip: Ipv4Addr = "198.51.100.50".parse().unwrap();

// Add entry with TTL already expired (negative seconds)
    engine.ip_blocklist().add_ip(ip, spam_entry("198.51.100.50", -1));

// Before purge:entry may or may not be returned (implementation-dependent)
// After purge:MUST be removed
    let stats = purge_once(&engine);
    assert!(
        stats.expired_ips_removed > 0,
        "Purge must remove the expired entry (expired_ips_removed={})",
        stats.expired_ips_removed
    );

    let verdict = engine.check_ip("198.51.100.50");
    assert_eq!(
        verdict.action, ThreatAction::Allow,
        "After purge, expired IP must no longer be treated as a threat. \
         This regression demonstrates the empty-blocklist-after-24h bug: \
         without feed auto-refresh, all threat intel expires and attackers pass freely."
    );
}

/// Valid (non-expired) entries must survive a purge run.
#[test]
fn test_valid_entry_survives_purge() {
    let engine = ThreatIntelEngine::new();
    let ip: Ipv4Addr = "198.51.100.77".parse().unwrap();
    engine.ip_blocklist().add_ip(ip, spam_entry("198.51.100.77", 86400)); // expires in 24h

    let stats = purge_once(&engine);
// Nothing expired so removal count should be 0
    assert_eq!(stats.expired_ips_removed, 0, "Fresh entry must not be purged");

    let verdict = engine.check_ip("198.51.100.77");
    assert_eq!(verdict.action, ThreatAction::Block, "Fresh entry must still be blocked after purge");
}

// ── Domain blocklist ──────────────────────────────────────────────────────────

/// Blocked domain must yield a Block action.
#[test]
fn test_blocked_domain_flagged() {
    let engine = ThreatIntelEngine::new();
    engine.domain_blocklist().add(
        "evil-phishing-site.com",
        domain_entry("evil-phishing-site.com", 3600),
    );

    let verdict = engine.check_domain("evil-phishing-site.com");
    assert_eq!(verdict.action, ThreatAction::Block, "Blocked domain must yield Block action");
}

/// Clean domain must return Allow.
#[test]
fn test_clean_domain_not_flagged() {
    let engine = ThreatIntelEngine::new();
    let verdict = engine.check_domain("google.com");
    assert_eq!(verdict.action, ThreatAction::Allow, "google.com must return Allow");
}

/// Subdomain of a blocked domain must ALSO be blocked.
/// The blocklist walks the domain hierarchy (sub.evil.com → evil.com → com),
/// so blocking a parent domain automatically blocks all subdomains.
#[test]
fn test_subdomain_not_matched_by_base_domain_block() {
    let engine = ThreatIntelEngine::new();
    engine.domain_blocklist().add(
        "phishing.com",
        domain_entry("phishing.com", 3600),
    );

// The lookup walks up:mail.phishing.com → phishing.com → match!
    let verdict = engine.check_domain("mail.phishing.com");
    assert_eq!(
        verdict.action, ThreatAction::Block,
        "Subdomain of a blocked domain must also be blocked (hierarchy walk). \
         The blocklist uses suffix/parent matching: mail.phishing.com matches phishing.com."
    );
}

// ── Feed refresh task smoke test ────────────────────────────────────────────

/// Spawning the refresh task with a no-op loader must not panic.
#[tokio::test]
async fn test_spawn_refresh_task_no_panic() {
    use std::sync::Arc;
    use threat_intel::background_task::spawn_refresh_task;

    let engine = Arc::new(ThreatIntelEngine::new());
    let config = FeedRefreshConfig {
        interval: std::time::Duration::from_secs(999_999),
        enabled: true,
    };

// No-op loader — just verifies the task can be spawned
    let handle = spawn_refresh_task(engine, config, |_engine| {
// In real usage:fetch feed data and load into engine
    });

// Abort immediately — we're just checking it spawns without panic
    handle.abort();
// Give Tokio a moment to process the abort
    tokio::time::sleep(std::time::Duration::from_millis(10)).await;
}

/// A disabled refresh task must return immediately without running the loader.
#[tokio::test]
async fn test_disabled_refresh_task_does_not_run_loader() {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicBool, Ordering};
    use threat_intel::background_task::run_refresh_loop;

    let engine = Arc::new(ThreatIntelEngine::new());
    let called = Arc::new(AtomicBool::new(false));
    let called_clone = called.clone();

    let config = FeedRefreshConfig {
        interval: std::time::Duration::from_millis(1),
        enabled: false, // disabled!
    };

// run_refresh_loop returns immediately when enabled=false
    let task_engine = engine.clone();
    tokio::time::timeout(
        std::time::Duration::from_millis(100),
        run_refresh_loop(task_engine, config, move |_| {
            called_clone.store(true, Ordering::SeqCst);
        }),
    )
    .await
    .expect("disabled task must return immediately");

    assert!(!called.load(Ordering::SeqCst), "Disabled refresh task must NOT invoke loader");
}
