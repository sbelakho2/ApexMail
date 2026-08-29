//! High-level cached DNS resolver combining DnsLookup + DnsCache.

use std::time::Duration;
use tracing::debug;

use crate::cache::{CachedResult, DnsCache};
use crate::config::DnsConfig;
use crate::lookup::{DnsError, DnsLookup, DnsLookupResult};
use crate::records::*;

/// High-level cached DNS resolver.
pub struct CachedDnsResolver {
    lookup: DnsLookup,
    cache: DnsCache,
}

/// Cache decision for one MX lookup outcome. Pure (no I/O) so the
/// definitive-vs-transient discipline is unit-testable without a resolver.
#[derive(Debug)]
enum MxCacheAction {
    /// Definitive no-records (Err(NoRecords) or empty answer section):
    /// negative-cache under the negative TTL.
    Negative,
    /// Records exist: positive-cache the serialized form under the
    /// authoritative record TTL.
    Positive(Vec<String>, Duration),
    /// Transient failure: cache nothing, propagate the error.
    None,
}

fn mx_cache_action(outcome: &Result<DnsLookupResult<Vec<MxRecord>>, DnsError>) -> MxCacheAction {
    match outcome {
        Ok(result) if result.records.is_empty() => MxCacheAction::Negative,
        Ok(result) => MxCacheAction::Positive(
            result
                .records
                .iter()
                .map(|r| format!("{} {}", r.priority, r.exchange))
                .collect(),
            result.ttl,
        ),
        Err(DnsError::NoRecords(_)) => MxCacheAction::Negative,
        Err(_) => MxCacheAction::None,
    }
}

impl CachedDnsResolver {
    /// Create a new cached resolver.
    pub fn new(config: &DnsConfig) -> Result<Self, DnsError> {
        Ok(Self {
            lookup: DnsLookup::from_config(config)?,
            cache: DnsCache::new(config),
        })
    }

    /// Create with default configuration.
    pub fn default_resolver() -> Result<Self, DnsError> {
        Self::new(&DnsConfig::default())
    }

    /// Lookup MX records with caching.
    pub async fn mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError> {
        let cache_key = format!("mx:{domain}");

        if let Some(CachedResult::Records(recs)) = self.cache.get(&cache_key) {
            // Replay structurally: the cached form is "<u16 priority> <exchange>"
            // (see mx_cache_action). The priority token MUST validate as u16 and
            // the remainder — spaces included — is the exchange; a malformed
            // entry is dropped with a log instead of silently defaulting its
            // priority to 10, which used to reorder failover.
            let mut records = Vec::with_capacity(recs.len());
            for entry in recs {
                let Some((priority, exchange)) = entry.split_once(' ') else {
                    debug!(cached = %entry, "Dropping malformed cached MX entry: no priority token");
                    continue;
                };
                match priority.parse::<u16>() {
                    Ok(p) => records.push(MxRecord::new(p, exchange)),
                    Err(_) => {
                        debug!(cached = %entry, "Dropping malformed cached MX entry: invalid priority");
                    }
                }
            }
            return Ok(records);
        }

        if let Some(CachedResult::NxDomain) = self.cache.get(&cache_key) {
            return Err(DnsError::NoRecords(domain.to_string()));
        }

        let outcome = self.lookup.lookup_mx_with_ttl(domain).await;
        match mx_cache_action(&outcome) {
            MxCacheAction::Negative => {
                // Definitive NXDOMAIN/NODATA (Err(NoRecords) or an empty
                // answer section): negative-cache under the negative TTL so
                // repeat sends don't re-query; the caller still sees the
                // Err(NoRecords) it saw before.
                self.cache.insert_negative(&cache_key);
            }
            MxCacheAction::Positive(cached, ttl) => {
                self.cache.insert_with_ttl(&cache_key, cached, ttl);
            }
            // E-1:transient lookup errors (timeout, SERVFAIL, network) are
            // NEVER negative-cached — a cached failure turned a blip into a
            // full negative-TTL window in which deliverability checks said
            // "no records". Propagate the error so the caller can retry;
            // only definitive NXDOMAIN/NoRecords results are cached.
            MxCacheAction::None => {}
        }
        outcome.map(|result| result.records)
    }

    /// Lookup SPF record with caching.
    ///
    /// A domain with multiple SPF records surfaces as
    /// [`DnsError::MultipleSpfRecords`] (RFC 7208 §4.5 permerror) and is
    /// cached as neither positive nor negative — the caller re-queries until
    /// the misconfiguration is fixed.
    pub async fn spf(&self, domain: &str) -> Result<Option<SpfRecord>, DnsError> {
        let cache_key = format!("spf:{domain}");

        if let Some(CachedResult::Records(recs)) = self.cache.get(&cache_key) {
            return Ok(recs.first().and_then(|r| SpfRecord::parse(r)));
        }

        match self.lookup.lookup_spf_with_ttl(domain).await? {
            Some(result) => {
                self.cache.insert_with_ttl(
                    &cache_key,
                    vec![result.records.raw.clone()],
                    result.ttl,
                );
                Ok(Some(result.records))
            }
            None => {
                self.cache.insert_negative(&cache_key);
                Ok(None)
            }
        }
    }

    /// Lookup DKIM record with caching.
    pub async fn dkim(&self, selector: &str, domain: &str) -> Result<Option<DkimRecord>, DnsError> {
        let cache_key = format!("dkim:{selector}._domainkey.{domain}");

        if let Some(CachedResult::Records(recs)) = self.cache.get(&cache_key) {
            return Ok(recs.first().and_then(|r| DkimRecord::parse(r)));
        }

        match self.lookup.lookup_dkim_with_ttl(selector, domain).await? {
            Some(result) => {
                self.cache.insert_with_ttl(
                    &cache_key,
                    vec![result.records.raw.clone()],
                    result.ttl,
                );
                Ok(Some(result.records))
            }
            None => {
                self.cache.insert_negative(&cache_key);
                Ok(None)
            }
        }
    }

    /// Lookup DMARC record with caching.
    pub async fn dmarc(&self, domain: &str) -> Result<Option<DmarcPolicy>, DnsError> {
        let cache_key = format!("dmarc:{domain}");

        if let Some(CachedResult::Records(recs)) = self.cache.get(&cache_key) {
            return Ok(recs.first().and_then(|r| DmarcPolicy::parse(r)));
        }

        match self.lookup.lookup_dmarc_with_ttl(domain).await? {
            Some(result) => {
                self.cache.insert_with_ttl(
                    &cache_key,
                    vec![result.records.raw.clone()],
                    result.ttl,
                );
                Ok(Some(result.records))
            }
            None => {
                self.cache.insert_negative(&cache_key);
                Ok(None)
            }
        }
    }

    /// Validate domain can receive email (with cache).
    ///
    /// Transient DNS failures surface as `Err` and are cached NOWHERE (the
    /// old code cached `Ok(false)` under the POSITIVE TTL, turning one
    /// resolver blip into a full TTL of "undeliverable" verdicts). A
    /// definitive no-MX/no-A answer is negative-cached under the negative
    /// TTL.
    pub async fn can_receive_email(&self, domain: &str) -> Result<bool, DnsError> {
        let cache_key = format!("can_receive:{domain}");

        if let Some(CachedResult::Records(recs)) = self.cache.get(&cache_key) {
            return Ok(recs.first().map(|r| r == "true").unwrap_or(false));
        }
        if let Some(CachedResult::NxDomain) = self.cache.get(&cache_key) {
            return Ok(false);
        }

        match self.lookup.can_receive_email(domain).await {
            crate::lookup::Deliverability::Yes => {
                self.cache.insert(&cache_key, vec!["true".to_string()]);
                Ok(true)
            }
            crate::lookup::Deliverability::No => {
                self.cache.insert_negative(&cache_key);
                Ok(false)
            }
            crate::lookup::Deliverability::Transient => Err(DnsError::ResolveFailed(format!(
                "transient DNS failure checking deliverability of {domain}"
            ))),
        }
    }

    /// Invalidate all cached records for a domain.
    /// #184:DKIM cache key uses `dkim:{selector}._domainkey.{domain}` format,
    /// so we cannot simply invalidate `dkim:{domain}`. Instead, perform a broader
    /// invalidation of all keys matching the domain suffix.
    pub fn invalidate_domain(&self, domain: &str) {
        debug!(domain, "Invalidating DNS cache for domain");
        for prefix in &["mx", "spf", "dmarc", "can_receive"] {
            self.cache.invalidate(&format!("{prefix}:{domain}"));
        }
        // DKIM keys are stored as `dkim:{selector}._domainkey.{domain}`,
        // so we need to invalidate by suffix match
        self.cache.invalidate_by_domain_suffix(domain);
    }

    /// Clear entire cache.
    pub fn clear_cache(&self) {
        self.cache.clear();
    }

    /// Cache statistics.
    pub fn cache_size(&self) -> u64 {
        self.cache.len()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_cached_resolver_creation() {
        let resolver = CachedDnsResolver::default_resolver();
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_cached_resolver_from_config() {
        let config = DnsConfig {
            cache_ttl_secs: 60,
            max_cache_entries: 100,
            ..DnsConfig::default()
        };
        let resolver = CachedDnsResolver::new(&config);
        assert!(resolver.is_ok());
    }

    #[test]
    fn test_cached_resolver_invalidate() {
        let resolver = CachedDnsResolver::default_resolver();
        assert!(resolver.is_ok());
        if let Ok(resolver) = resolver {
            resolver.invalidate_domain("example.com");
            // Should not panic
            assert_eq!(resolver.cache_size(), 0);
        }
    }

    #[test]
    fn test_cached_resolver_clear() {
        let resolver = CachedDnsResolver::default_resolver();
        assert!(resolver.is_ok());
        if let Ok(resolver) = resolver {
            resolver.clear_cache();
            assert_eq!(resolver.cache_size(), 0);
        }
    }

    // ── E-1: transient lookup errors are never negative-cached ────────────

    #[tokio::test]
    async fn mx_lookup_errors_are_not_cached() {
        // Point the resolver at an unreachable nameserver with a short
        // timeout so the lookup fails transiently (timeout / io error —
        // NOT an NXDOMAIN). The failure must propagate and leave the cache
        // EMPTY: the old code negative-cached the error, making every
        // deliverability check for that domain fail for a full negative-TTL
        // window after a single network blip.
        let config = crate::config::DnsConfig {
            nameservers: vec!["127.0.0.1:1".to_string()],
            query_timeout_ms: 50,
            retries: 0,
            ..crate::config::DnsConfig::default()
        };
        let resolver = CachedDnsResolver::new(&config).expect("resolver construction");

        let outcome = resolver.mx("example.com").await;
        assert!(
            outcome.is_err(),
            "unreachable nameserver must yield an error"
        );
        assert!(
            resolver.cache_size() == 0,
            "transient errors must not be cached (positive or negative)"
        );

        // A second attempt still consults the (still-failing) resolver
        // instead of being short-circuited by a cached failure.
        let outcome = resolver.mx("example.com").await;
        assert!(outcome.is_err());
        assert!(resolver.cache_size() == 0);
    }

    // ── E-1b: transient can_receive_email failures are errors, never cached ─

    #[tokio::test]
    async fn can_receive_email_transient_failure_is_err_and_uncached() {
        // A SERVFAIL/timeout must NOT be swallowed into Ok(false) — the old
        // behaviour cached "false" under the POSITIVE TTL, turning one
        // resolver blip into a full TTL window of "undeliverable" verdicts
        // (the deliverability check said no records existed).
        let config = crate::config::DnsConfig {
            nameservers: vec!["127.0.0.1:1".to_string()],
            query_timeout_ms: 50,
            retries: 0,
            ..crate::config::DnsConfig::default()
        };
        let resolver = CachedDnsResolver::new(&config).expect("resolver construction");

        let outcome = resolver.can_receive_email("example.com").await;
        assert!(
            outcome.is_err(),
            "a transient lookup failure must surface as Err, got {outcome:?}"
        );
        assert!(
            resolver.cache_size() == 0,
            "a transient failure must not be cached (positive or negative)"
        );

        // A second attempt still consults the resolver instead of being
        // short-circuited by a cached false verdict.
        assert!(resolver.can_receive_email("example.com").await.is_err());
        assert!(resolver.cache_size() == 0);
    }

    // ── definitive no-records vs transient: the pure cache-decision seam ────

    #[test]
    fn mx_outcome_no_records_is_negative_cacheable_transient_is_not() {
        // Genuine NXDOMAIN/NODATA (DnsError::NoRecords, or an Ok with an
        // empty answer section) is definitive: it may be negative-cached
        // (bounded by the negative TTL) so repeat sends don't re-query.
        let no_records: Result<DnsLookupResult<Vec<MxRecord>>, DnsError> =
            Err(DnsError::NoRecords("nx.example".into()));
        assert!(matches!(
            mx_cache_action(&no_records),
            MxCacheAction::Negative
        ));

        let empty_answers: Result<DnsLookupResult<Vec<MxRecord>>, DnsError> = Ok(DnsLookupResult {
            records: Vec::new(),
            ttl: Duration::from_secs(60),
        });
        assert!(matches!(
            mx_cache_action(&empty_answers),
            MxCacheAction::Negative
        ));

        // Transient failures (timeout/SERVFAIL/network) cache NOTHING.
        let transient: Result<DnsLookupResult<Vec<MxRecord>>, DnsError> =
            Err(DnsError::ResolveFailed("query timed out".into()));
        assert!(matches!(mx_cache_action(&transient), MxCacheAction::None));
        let timeout: Result<DnsLookupResult<Vec<MxRecord>>, DnsError> =
            Err(DnsError::Timeout("nx.example".into()));
        assert!(matches!(mx_cache_action(&timeout), MxCacheAction::None));

        // Positive results cache under the authoritative record TTL.
        let positive: Result<DnsLookupResult<Vec<MxRecord>>, DnsError> = Ok(DnsLookupResult {
            records: vec![MxRecord::new(10, "mx.example.com")],
            ttl: Duration::from_secs(120),
        });
        match mx_cache_action(&positive) {
            MxCacheAction::Positive(records, ttl) => {
                assert_eq!(records, vec!["10 mx.example.com".to_string()]);
                assert_eq!(ttl, Duration::from_secs(120));
            }
            other => panic!("expected Positive, got {other:?}"),
        }
    }

    // ── cached-MX replay: structural, never defaults a priority ───────────

    #[tokio::test]
    async fn mx_cache_replay_validates_priority_and_drops_malformed_entries() {
        let resolver = CachedDnsResolver::default_resolver().expect("resolver construction");
        resolver.cache.insert(
            "mx:replay.example",
            vec![
                "20 backup.example.com".into(),
                // Exchange keeps the remainder including spaces.
                "5 primary example com".into(),
                "malformed-no-priority-token".into(),
                "not-a-priority mx.example.com".into(),
            ],
        );

        let records = resolver.mx("replay.example").await.expect("cache replay");
        assert_eq!(
            records.len(),
            2,
            "malformed entries must be dropped, not defaulted: {records:?}"
        );
        assert_eq!(records[0], MxRecord::new(20, "backup.example.com"));
        assert_eq!(records[1], MxRecord::new(5, "primary example com"));
    }

    // ── E-2: invalidate_domain reaches DKIM selector keys ─────────────────    #[test]
    fn invalidate_domain_invalidates_dkim_selector_keys() {
        let resolver = CachedDnsResolver::default_resolver().expect("resolver construction");
        resolver.cache.insert(
            "dkim:sel1._domainkey.example.com",
            vec!["v=DKIM1; k=rsa; p=OLD".into()],
        );
        resolver
            .cache
            .insert("mx:example.com", vec!["10 mx.example.com".into()]);

        resolver.invalidate_domain("example.com");

        assert!(
            resolver
                .cache
                .get("dkim:sel1._domainkey.example.com")
                .is_none(),
            "DKIM selector keys must be invalidated with the domain"
        );
        assert!(
            resolver.cache.get("mx:example.com").is_none(),
            "plain domain keys must be invalidated as before"
        );
    }
}
