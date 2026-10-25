//! Threat-intelligence feed ingestion (use-all audit, P2).
//!
//! `AppState` used to construct the grader's `DomainBlocklist` EMPTY and no
//! refresh/purge task was ever spawned, so the advertised feed path could
//! never block anything. This module owns the missing production wiring:
//!
//! * `THREAT_INTEL_FEED_URLS`, comma-separated feed URLs (plain domain-per-line
//!   or URL-per-line, e.g. abuse.ch exports). Empty = no feeds.
//! * `THREAT_INTEL_FEED_TTL_SECS`, entry lifetime (default 24h).
//! * `THREAT_INTEL_FEED_REFRESH_SECS`, refresh cadence (default 1h); the first
//!   tick fires immediately at startup.
//!
//! The blocklist instance is SHARED with the grader engine (state.rs passes the
//! same Arc), so a refreshed entry is a grader reputation hit on the next
//! request. Expired entries are purged on a one-minute timer.

use std::sync::Arc;
use std::time::Duration;

use threat_intel::domain_blocklist::{parse_domain_list, parse_url_list_domains, DomainBlocklist};

/// One configured feed.
#[derive(Debug, Clone)]
pub struct FeedSource {
    pub name: String,
    pub url: String,
}

fn feed_name(url: &str, index: usize) -> String {
    url.split("://")
        .nth(1)
        .and_then(|rest| rest.split('/').next())
        .filter(|host| !host.is_empty())
        .map(|host| host.to_string())
        .unwrap_or_else(|| format!("feed-{index}"))
}

/// Feeds configured for this deployment (empty = disabled).
pub fn feeds_from_env() -> Vec<FeedSource> {
    std::env::var("THREAT_INTEL_FEED_URLS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(str::trim)
                .filter(|url| url.starts_with("http://") || url.starts_with("https://"))
                .enumerate()
                .map(|(index, url)| FeedSource {
                    name: feed_name(url, index),
                    url: url.to_string(),
                })
                .collect()
        })
        .unwrap_or_default()
}

fn env_secs(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .filter(|value| *value > 0)
        .unwrap_or(default)
}

/// Entry TTL for feed rows.
pub fn ttl_secs() -> u64 {
    env_secs("THREAT_INTEL_FEED_TTL_SECS", 86_400)
}

/// Refresh cadence for the background loop.
pub fn refresh_secs() -> u64 {
    env_secs("THREAT_INTEL_FEED_REFRESH_SECS", 3_600)
}

/// One refresh pass over every configured feed. Returns the number of entries
/// added. A failed feed is logged and skipped; the other feeds still load.
pub async fn refresh_once(
    client: &reqwest::Client,
    blocklist: &DomainBlocklist,
    feeds: &[FeedSource],
) -> usize {
    let ttl = ttl_secs();
    let mut added = 0usize;
    for feed in feeds {
        let response = match client
            .get(&feed.url)
            .timeout(Duration::from_secs(30))
            .send()
            .await
        {
            Ok(response) => response,
            Err(error) => {
                tracing::warn!(feed = %feed.name, error = %error, "threat feed fetch failed");
                continue;
            }
        };
        if !response.status().is_success() {
            tracing::warn!(
                feed = %feed.name,
                status = %response.status(),
                "threat feed answered non-success"
            );
            continue;
        }
        let body = response.text().await.unwrap_or_default();
        // URL-per-line exports (URLhaus etc.) vs plain domain-per-line lists.
        let entries = if body.lines().any(|line| line.contains("://")) {
            parse_url_list_domains(&body, &feed.name, "threat_feed", ttl)
        } else {
            parse_domain_list(&body, &feed.name, "threat_feed", ttl)
        };
        for entry in entries {
            let domain = entry.domain.clone();
            if blocklist.add(&domain, entry) {
                added += 1;
            }
        }
        tracing::info!(feed = %feed.name, "threat feed refreshed");
    }
    if added > 0 {
        tracing::info!(added, "threat intelligence entries loaded");
    }
    added
}

/// Spawn the refresh + expiry-purge loops when feeds are configured.
///
/// Returns `false` when no feed URLs are configured (no background task is
/// created, which keeps tests and feed-less deployments quiet).
pub fn spawn_if_configured(client: reqwest::Client, blocklist: Arc<DomainBlocklist>) -> bool {
    let feeds = feeds_from_env();
    if feeds.is_empty() {
        return false;
    }
    let refresh = Duration::from_secs(refresh_secs());
    let refresh_client = client.clone();
    let refresh_blocklist = blocklist.clone();
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(refresh);
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let _ = refresh_once(&refresh_client, &refresh_blocklist, &feeds).await;
        }
    });
    tokio::spawn(async move {
        let mut ticker = tokio::time::interval(Duration::from_secs(60));
        ticker.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
        loop {
            ticker.tick().await;
            let removed = blocklist.purge_expired();
            if removed > 0 {
                tracing::info!(removed, "expired threat-intelligence entries purged");
            }
        }
    });
    true
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Utc;
    use threat_intel::domain_blocklist::DomainBlockEntry;

    async fn spawn_feed_server(body: &'static str) -> String {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
            .await
            .expect("bind feed server");
        let addr = listener.local_addr().unwrap();
        let app =
            axum::Router::new().route("/feed.txt", axum::routing::get(move || async move { body }));
        tokio::spawn(async move {
            let _ = axum::serve(listener, app).await;
        });
        format!("http://{addr}/feed.txt")
    }

    #[tokio::test]
    async fn refresh_ingests_plaintext_and_url_feeds_into_the_shared_blocklist() {
        let plain = spawn_feed_server("# comment\nevil.example\nbad.example\n").await;
        let urls =
            spawn_feed_server("https://phish.example/login\nhttp://malware.example/payload\n")
                .await;
        let blocklist = DomainBlocklist::new(100);
        let feeds = vec![
            FeedSource {
                name: "plain".into(),
                url: plain,
            },
            FeedSource {
                name: "urls".into(),
                url: urls,
            },
        ];
        let added = refresh_once(&reqwest::Client::new(), &blocklist, &feeds).await;
        assert_eq!(added, 4, "all four entries from both formats");
        assert!(blocklist.lookup("evil.example").is_some());
        assert!(blocklist.lookup("bad.example").is_some());
        assert!(blocklist.lookup("phish.example").is_some());
        assert!(blocklist.lookup("malware.example").is_some());
    }

    #[tokio::test]
    async fn refresh_skips_a_dead_feed_and_keeps_the_healthy_one() {
        let healthy = spawn_feed_server("kept.example\n").await;
        let blocklist = DomainBlocklist::new(100);
        let feeds = vec![
            FeedSource {
                name: "dead".into(),
                url: "http://127.0.0.1:1/nope".into(),
            },
            FeedSource {
                name: "healthy".into(),
                url: healthy,
            },
        ];
        let added = refresh_once(&reqwest::Client::new(), &blocklist, &feeds).await;
        assert_eq!(added, 1);
        assert!(blocklist.lookup("kept.example").is_some());
    }

    #[test]
    fn expired_entries_are_purged() {
        let blocklist = DomainBlocklist::new(100);
        blocklist.add(
            "stale.example",
            DomainBlockEntry {
                domain: "stale.example".into(),
                source: "test".into(),
                confidence: 8.0,
                category: "threat_feed".into(),
                added_at: Utc::now() - chrono::Duration::hours(2),
                expires_at: Utc::now() - chrono::Duration::hours(1),
            },
        );
        assert_eq!(blocklist.purge_expired(), 1);
        assert!(blocklist.lookup("stale.example").is_none());
    }
}
