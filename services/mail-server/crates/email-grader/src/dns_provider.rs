//! Explicit seam over the DNS lookups the grader performs.
//!
//! The production implementation delegates to
//! [`apexmail_dns_resolver::lookup::DnsLookup`]; tests substitute a scripted
//! stub so every DNS-dependent path runs with zero network egress. The trait
//! is dyn-compatible (boxed futures) because the engine holds it behind an
//! `Arc`.

use std::future::Future;
use std::pin::Pin;

use apexmail_dns_resolver::lookup::DnsLookup;
use apexmail_dns_resolver::records::{DkimRecord, DmarcPolicy, MxRecord, SpfRecord};

/// A boxed lookup future; errors are flattened to strings because every
/// caller treats a failed lookup as "no data" (never a fatal error).
pub type DnsFuture<'a, T> = Pin<Box<dyn Future<Output = Result<T, String>> + Send + 'a>>;

/// The DNS surface used by the grader and its network checks.
pub trait DnsProvider: Send + Sync {
    fn lookup_txt<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<String>>;
    fn lookup_mx<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<MxRecord>>;
    fn lookup_spf<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Option<SpfRecord>>;
    fn lookup_dmarc<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Option<DmarcPolicy>>;
    fn lookup_dkim<'a>(
        &'a self,
        selector: &'a str,
        domain: &'a str,
    ) -> DnsFuture<'a, Option<DkimRecord>>;
    fn lookup_a<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<String>>;
    fn lookup_aaaa<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<String>>;
}

impl DnsProvider for DnsLookup {
    fn lookup_txt<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<String>> {
        Box::pin(async move {
            DnsLookup::lookup_txt(self, name)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn lookup_mx<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<MxRecord>> {
        Box::pin(async move {
            DnsLookup::lookup_mx(self, name)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn lookup_spf<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Option<SpfRecord>> {
        Box::pin(async move {
            DnsLookup::lookup_spf(self, name)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn lookup_dmarc<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Option<DmarcPolicy>> {
        Box::pin(async move {
            DnsLookup::lookup_dmarc(self, name)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn lookup_dkim<'a>(
        &'a self,
        selector: &'a str,
        domain: &'a str,
    ) -> DnsFuture<'a, Option<DkimRecord>> {
        Box::pin(async move {
            DnsLookup::lookup_dkim(self, selector, domain)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn lookup_a<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<String>> {
        Box::pin(async move {
            DnsLookup::lookup_a(self, name)
                .await
                .map_err(|e| e.to_string())
        })
    }

    fn lookup_aaaa<'a>(&'a self, name: &'a str) -> DnsFuture<'a, Vec<String>> {
        Box::pin(async move {
            DnsLookup::lookup_aaaa(self, name)
                .await
                .map_err(|e| e.to_string())
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The real provider is a thin delegation: an impossible DNS name fails
    /// immediately (no network) and every method maps the error to a string.
    #[tokio::test]
    async fn real_provider_delegates_and_maps_errors_without_network() {
        let real = DnsLookup::new().expect("system resolver config");
        // Go through the trait object: inherent methods would bypass the
        // delegation being pinned here.
        let dns: &dyn DnsProvider = &real;
        let impossible = "x".repeat(300); // > 255 bytes → proto error, no query
        assert!(dns.lookup_txt(&impossible).await.is_err());
        assert!(dns.lookup_mx(&impossible).await.is_err());
        assert!(dns.lookup_spf(&impossible).await.is_err());
        assert!(dns.lookup_dmarc(&impossible).await.is_err());
        assert!(dns.lookup_dkim("sel", &impossible).await.is_err());
        assert!(dns.lookup_a(&impossible).await.is_err());
        assert!(dns.lookup_aaaa(&impossible).await.is_err());
    }
}
