//! Low-level DNS lookup utilities.
//!
//! Wraps trust-dns-resolver queries and converts them to our record types.

use std::sync::LazyLock;
use std::time::{Duration, Instant};
use trust_dns_resolver::config::{ResolveHosts, ResolverConfig, ResolverOpts};
use trust_dns_resolver::net::runtime::TokioRuntimeProvider;
use trust_dns_resolver::{Resolver, TokioResolver};

use crate::config::DnsConfig;
use crate::records::*;

/// DNS lookup error.
#[derive(Debug, thiserror::Error)]
pub enum DnsError {
    #[error("DNS resolution failed: {0}")]
    ResolveFailed(String),
    #[error("No records found for {0}")]
    NoRecords(String),
    #[error("Timeout resolving {0}")]
    Timeout(String),
    #[error("Invalid domain: {0}")]
    InvalidDomain(String),
    #[error("Invalid config: {0}")]
    InvalidConfig(String),
}

/// DNS lookup value paired with the resolver-provided validity window.
#[derive(Debug, Clone)]
pub struct DnsLookupResult<T> {
    pub records: T,
    pub ttl: Duration,
}

impl<T> DnsLookupResult<T> {
    fn new(records: T, ttl: Duration) -> Self {
        Self { records, ttl }
    }
}

/// Thin wrapper around trust-dns-resolver for email-specific lookups.
pub struct DnsLookup {
    resolver: TokioResolver,
}

fn build_resolver(config: ResolverConfig, opts: ResolverOpts) -> Result<TokioResolver, DnsError> {
    Resolver::builder_with_config(config, TokioRuntimeProvider::default())
        .with_options(opts)
        .build()
        .map_err(|e| DnsError::InvalidConfig(e.to_string()))
}

static DEFAULT_RESOLVER: LazyLock<TokioResolver> = LazyLock::new(|| {
    build_resolver(ResolverConfig::default(), ResolverOpts::default())
        .expect("system resolver configuration is always buildable")
});

impl DnsLookup {
    /// Create a new resolver with system defaults.
    pub fn new() -> Result<Self, DnsError> {
        Ok(Self {
            resolver: DEFAULT_RESOLVER.clone(),
        })
    }

    /// Create from config, honoring custom nameservers if provided.
    pub fn from_config(config: &DnsConfig) -> Result<Self, DnsError> {
        config.validate().map_err(DnsError::InvalidConfig)?;
        let mut opts = ResolverOpts::default();
        opts.timeout = config.query_timeout();
        opts.attempts = config.retries as usize;
        opts.use_hosts_file = ResolveHosts::Never;

        // #193:Wire custom nameservers from config instead of always using system defaults.
        // UDP+TCP per server so large answers (TXT chains, DNSSEC) fall back to
        // TCP per RFC 5321 §5.3.4 instead of truncating.
        let resolver_config = if config.nameservers.is_empty() {
            ResolverConfig::default()
        } else {
            let mut rc = ResolverConfig::default();
            for ns in &config.nameservers {
                if let Ok(addr) = ns.parse::<std::net::SocketAddr>() {
                    rc.add_name_server(trust_dns_resolver::config::NameServerConfig::udp_and_tcp(
                        addr.ip(),
                    ));
                } else if let Ok(ip) = ns.parse::<std::net::IpAddr>() {
                    rc.add_name_server(trust_dns_resolver::config::NameServerConfig::udp_and_tcp(
                        ip,
                    ));
                } else {
                    tracing::warn!(nameserver = %ns, "Skipping unparseable nameserver");
                }
            }
            rc
        };

        let resolver = build_resolver(resolver_config, opts)?;
        Ok(Self { resolver })
    }

    /// Lookup MX records for a domain.
    pub async fn lookup_mx(&self, domain: &str) -> Result<Vec<MxRecord>, DnsError> {
        Ok(self.lookup_mx_with_ttl(domain).await?.records)
    }

    /// Lookup MX records for a domain, preserving the authoritative TTL.
    pub async fn lookup_mx_with_ttl(
        &self,
        domain: &str,
    ) -> Result<DnsLookupResult<Vec<MxRecord>>, DnsError> {
        let response = self
            .resolver
            .mx_lookup(domain)
            .await
            .map_err(|e| DnsError::ResolveFailed(e.to_string()))?;

        let mut records: Vec<MxRecord> = response
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                trust_dns_resolver::proto::rr::RData::MX(mx) => {
                    Some(MxRecord::new(mx.preference, mx.exchange.to_string()))
                }
                _ => None,
            })
            .collect();

        records.sort();
        Ok(DnsLookupResult::new(
            records,
            ttl_from_valid_until(response.valid_until()),
        ))
    }

    /// Lookup TXT records for a domain.
    pub async fn lookup_txt(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        Ok(self.lookup_txt_with_ttl(domain).await?.records)
    }

    /// Lookup TXT records for a domain, preserving the authoritative TTL.
    pub async fn lookup_txt_with_ttl(
        &self,
        domain: &str,
    ) -> Result<DnsLookupResult<Vec<String>>, DnsError> {
        let response = self
            .resolver
            .txt_lookup(domain)
            .await
            .map_err(|e| DnsError::ResolveFailed(e.to_string()))?;

        let texts: Vec<String> = response
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                trust_dns_resolver::proto::rr::RData::TXT(txt) => Some(
                    txt.txt_data
                        .iter()
                        .map(|d| String::from_utf8_lossy(d).to_string())
                        .collect::<Vec<_>>()
                        .join(""),
                ),
                _ => None,
            })
            .collect();

        Ok(DnsLookupResult::new(
            texts,
            ttl_from_valid_until(response.valid_until()),
        ))
    }

    /// Lookup SPF record for a domain.
    pub async fn lookup_spf(&self, domain: &str) -> Result<Option<SpfRecord>, DnsError> {
        Ok(self
            .lookup_spf_with_ttl(domain)
            .await?
            .map(|result| result.records))
    }

    /// Lookup SPF record for a domain, preserving the TXT lookup TTL.
    pub async fn lookup_spf_with_ttl(
        &self,
        domain: &str,
    ) -> Result<Option<DnsLookupResult<SpfRecord>>, DnsError> {
        let txts = self.lookup_txt_with_ttl(domain).await?;
        Ok(txts
            .records
            .iter()
            .find_map(|txt| SpfRecord::parse(txt))
            .map(|record| DnsLookupResult::new(record, txts.ttl)))
    }

    /// Lookup DKIM record for a selector._domainkey.domain.
    pub async fn lookup_dkim(
        &self,
        selector: &str,
        domain: &str,
    ) -> Result<Option<DkimRecord>, DnsError> {
        Ok(self
            .lookup_dkim_with_ttl(selector, domain)
            .await?
            .map(|result| result.records))
    }

    /// Lookup DKIM record for a selector._domainkey.domain, preserving the TXT lookup TTL.
    pub async fn lookup_dkim_with_ttl(
        &self,
        selector: &str,
        domain: &str,
    ) -> Result<Option<DnsLookupResult<DkimRecord>>, DnsError> {
        let query = format!("{selector}._domainkey.{domain}");
        let txts = self.lookup_txt_with_ttl(&query).await?;
        Ok(txts
            .records
            .iter()
            .find_map(|txt| DkimRecord::parse(txt))
            .map(|record| DnsLookupResult::new(record, txts.ttl)))
    }

    /// Lookup DMARC record for _dmarc.domain.
    pub async fn lookup_dmarc(&self, domain: &str) -> Result<Option<DmarcPolicy>, DnsError> {
        Ok(self
            .lookup_dmarc_with_ttl(domain)
            .await?
            .map(|result| result.records))
    }

    /// Lookup DMARC record for _dmarc.domain, preserving the TXT lookup TTL.
    pub async fn lookup_dmarc_with_ttl(
        &self,
        domain: &str,
    ) -> Result<Option<DnsLookupResult<DmarcPolicy>>, DnsError> {
        let query = format!("_dmarc.{domain}");
        let txts = self.lookup_txt_with_ttl(&query).await?;
        Ok(txts
            .records
            .iter()
            .find_map(|txt| DmarcPolicy::parse(txt))
            .map(|record| DnsLookupResult::new(record, txts.ttl)))
    }

    /// Lookup A records.
    pub async fn lookup_a(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        Ok(self.lookup_a_with_ttl(domain).await?.records)
    }

    /// Lookup A records, preserving the authoritative TTL.
    pub async fn lookup_a_with_ttl(
        &self,
        domain: &str,
    ) -> Result<DnsLookupResult<Vec<String>>, DnsError> {
        let response = self
            .resolver
            .ipv4_lookup(domain)
            .await
            .map_err(|e| DnsError::ResolveFailed(e.to_string()))?;

        let ttl = ttl_from_valid_until(response.valid_until());
        let ips: Vec<String> = response
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                trust_dns_resolver::proto::rr::RData::A(a) => Some(a.0.to_string()),
                _ => None,
            })
            .collect();
        Ok(DnsLookupResult::new(ips, ttl))
    }

    /// Lookup AAAA records.
    pub async fn lookup_aaaa(&self, domain: &str) -> Result<Vec<String>, DnsError> {
        Ok(self.lookup_aaaa_with_ttl(domain).await?.records)
    }

    /// Lookup AAAA records, preserving the authoritative TTL.
    pub async fn lookup_aaaa_with_ttl(
        &self,
        domain: &str,
    ) -> Result<DnsLookupResult<Vec<String>>, DnsError> {
        let response = self
            .resolver
            .ipv6_lookup(domain)
            .await
            .map_err(|e| DnsError::ResolveFailed(e.to_string()))?;

        let ttl = ttl_from_valid_until(response.valid_until());
        let ips: Vec<String> = response
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                trust_dns_resolver::proto::rr::RData::AAAA(aaaa) => Some(aaaa.0.to_string()),
                _ => None,
            })
            .collect();
        Ok(DnsLookupResult::new(ips, ttl))
    }

    /// Reverse DNS lookup.
    pub async fn reverse_lookup(&self, ip: std::net::IpAddr) -> Result<Vec<String>, DnsError> {
        let response = self
            .resolver
            .reverse_lookup(ip)
            .await
            .map_err(|e| DnsError::ResolveFailed(e.to_string()))?;

        let names: Vec<String> = response
            .answers()
            .iter()
            .filter_map(|r| match &r.data {
                trust_dns_resolver::proto::rr::RData::PTR(ptr) => Some(ptr.0.to_string()),
                _ => None,
            })
            .collect();
        Ok(names)
    }

    /// Validate that a domain has MX or A records (can receive email).
    pub async fn can_receive_email(&self, domain: &str) -> Result<bool, DnsError> {
        // Check MX first
        if let Ok(mx) = self.lookup_mx(domain).await {
            if !mx.is_empty() {
                return Ok(true);
            }
        }
        // Fall back to A record (implicit MX per RFC 5321)
        if let Ok(a) = self.lookup_a(domain).await {
            if !a.is_empty() {
                return Ok(true);
            }
        }
        Ok(false)
    }
}

fn ttl_from_valid_until(valid_until: Instant) -> Duration {
    valid_until.saturating_duration_since(Instant::now())
}

#[cfg(test)]
mod tests {
    use super::*;

    // DNS lookups require network; we test construction and error handling.

    #[test]
    fn test_dns_lookup_creation() {
        let lookup = DnsLookup::new();
        assert!(lookup.is_ok());
    }

    #[test]
    fn test_dns_lookup_from_config() {
        let config = DnsConfig::default();
        let lookup = DnsLookup::from_config(&config);
        assert!(lookup.is_ok());
    }

    #[test]
    fn test_dns_error_display() {
        let e = DnsError::NoRecords("example.com".into());
        assert_eq!(e.to_string(), "No records found for example.com");
    }

    #[test]
    fn test_dns_error_timeout() {
        let e = DnsError::Timeout("slow.example.com".into());
        assert!(e.to_string().contains("Timeout"));
    }
}
