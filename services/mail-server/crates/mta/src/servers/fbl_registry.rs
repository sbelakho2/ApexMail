//! Provider-specific FBL (feedback loop) registry.
//!
//! The previous trust model was a hardcoded suffix list (`TRUSTED_FBL_SENDERS`)
//! plus PTR/FCrDNS: any host under e.g. `google.com` that forward-confirmed
//! was treated as an authoritative complaint source, with no per-provider
//! record of the expected source networks, validation method, or registry
//! version. This module replaces it with an explicit provider registry:
//!
//! ```text
//! fbl_provider_registry(
//!     provider, rdns_patterns[], source_networks[], validation_method,
//!     effective_version, enabled
//! )
//! ```
//!
//! Validation rule (fail closed):
//! 1. the source IP's PTR hostname must match an ENABLED provider's
//!    `rdns_patterns` (exact domain or a real subdomain — never a bare
//!    string suffix);
//! 2. the provider's `validation_method` must be evaluable for an SMTP ARF
//!    report (`rdns_fcrcdns` today; webhook/DKIM methods belong to other
//!    ingest paths and are NOT authoritative here);
//! 3. when the provider declares `source_networks`, the client IP must fall
//!    inside one of them.
//!
//! An unregistered or mismatched source is a non-authoritative observation:
//! it may be recorded, but it never suppresses. The registry is seeded with
//! the providers substantiated by the pre-existing code list and their
//! rDNS domains; the source networks are intentionally left empty (to be
//! configured by operators) because the repository contains no substantiated
//! provider network data. An empty `source_networks` means "no network
//! restriction is registered for this provider" — the rDNS/FCrDNS method
//! alone is the registered expectation, which preserves the previously
//! documented behaviour while making it explicit and versioned.
//!
//! Retirement/migration: registry rows carry `effective_version`; raising a
//! provider's method or networks is an UPDATE of that row (and a bump of the
//! version), never a code change.

use std::net::IpAddr;

use sqlx::PgPool;

/// Version stamped on the compiled seed rows. Bump when the seed semantics
/// change (not when an operator edits a row).
pub const FBL_REGISTRY_SEED_VERSION: i32 = 1;

/// How an FBL provider's traffic is authenticated.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FblValidationMethod {
    /// Reverse DNS + forward-confirmed reverse DNS against the provider's
    /// `rdns_patterns` (the only method evaluable for SMTP ARF reports).
    RdnsFcrcdns,
    /// Signed webhook callback (api-server ingest path, not SMTP ARF).
    WebhookHmac,
    /// DKIM/ARC signature of the complaint message.
    DkimSignature,
    /// Explicit source-IP allowlist without rDNS requirements.
    SourceIpAllowlist,
    /// A method string this build does not know: never authoritative.
    Unknown,
}

impl FblValidationMethod {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::RdnsFcrcdns => "rdns_fcrcdns",
            Self::WebhookHmac => "webhook_hmac",
            Self::DkimSignature => "dkim_signature",
            Self::SourceIpAllowlist => "source_ip_allowlist",
            Self::Unknown => "unknown",
        }
    }

    pub fn from_db(value: &str) -> Self {
        match value.trim().to_ascii_lowercase().as_str() {
            "rdns_fcrcdns" => Self::RdnsFcrcdns,
            "webhook_hmac" => Self::WebhookHmac,
            "dkim_signature" => Self::DkimSignature,
            "source_ip_allowlist" => Self::SourceIpAllowlist,
            _ => Self::Unknown,
        }
    }

    /// Whether this method can be evaluated for a complaint arriving over
    /// SMTP (the FBL listener's ingest path). Any other method makes the
    /// provider's SMTP complaint non-authoritative BY DESIGN: it must be
    /// validated on its own channel, not guessed from rDNS.
    pub fn is_evaluable_for_smtp_arf(&self) -> bool {
        matches!(self, Self::RdnsFcrcdns)
    }
}

/// One IPv4/IPv6 network in CIDR form.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct IpNet {
    addr: IpAddr,
    prefix: u8,
}

impl IpNet {
    /// Parse `addr/prefix` (e.g. `203.0.113.0/24`, `2001:db8::/32`). A bare
    /// address is treated as a /32 or /128.
    pub fn parse(value: &str) -> Option<Self> {
        let value = value.trim();
        let (addr_part, prefix_part) = match value.split_once('/') {
            Some((addr, prefix)) => (addr, Some(prefix)),
            None => (value, None),
        };
        let addr: IpAddr = addr_part.parse().ok()?;
        let max_prefix = if addr.is_ipv4() { 32u8 } else { 128u8 };
        let prefix = match prefix_part {
            Some(prefix) => prefix.parse::<u8>().ok()?,
            None => max_prefix,
        };
        if prefix > max_prefix {
            return None;
        }
        Some(Self { addr, prefix })
    }

    pub fn contains(&self, ip: IpAddr) -> bool {
        match (self.addr, ip) {
            (IpAddr::V4(net), IpAddr::V4(ip)) => {
                let mask = if self.prefix == 0 {
                    0u32
                } else {
                    u32::MAX << (32 - u32::from(self.prefix))
                };
                (u32::from(net) & mask) == (u32::from(ip) & mask)
            }
            (IpAddr::V6(net), IpAddr::V6(ip)) => {
                let mask = if self.prefix == 0 {
                    0u128
                } else {
                    u128::MAX << (128 - u32::from(self.prefix))
                };
                (u128::from(net) & mask) == (u128::from(ip) & mask)
            }
            _ => false,
        }
    }
}

/// One registered FBL provider.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FblProvider {
    pub provider: String,
    /// rDNS domains; a PTR hostname matches when it equals a pattern or is a
    /// real subdomain of it.
    pub rdns_patterns: Vec<String>,
    /// Optional source networks (CIDR). Empty = no network restriction.
    pub source_networks: Vec<IpNet>,
    pub validation_method: FblValidationMethod,
    pub effective_version: i32,
    pub enabled: bool,
}

/// Outcome of matching one source IP + PTR set against the registry.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FblAuthority {
    /// Registered, evaluable method, IP within the registered networks.
    /// The caller must still FCrDNS-confirm `matched_hostname`.
    Candidate {
        provider: String,
        method: FblValidationMethod,
        matched_hostname: String,
    },
    /// No enabled provider claims this PTR.
    Unregistered,
    /// A provider matched by PTR but a registered expectation failed.
    Mismatched {
        provider: Option<String>,
        reason: &'static str,
    },
}

impl FblAuthority {
    /// True only for [`FblAuthority::Candidate`] — and even then the caller
    /// must complete FCrDNS confirmation before treating the traffic as
    /// authoritative.
    pub fn is_candidate(&self) -> bool {
        matches!(self, Self::Candidate { .. })
    }
}

/// Compiled seed list — the providers substantiated by the repository's
/// pre-existing FBL sender list (crates/mta/src/servers/feedback_loop.rs,
/// `TRUSTED_FBL_SENDERS`) grouped by operator. Source networks are NOT
/// seeded: nothing in the repository substantiates any provider's network
/// ranges, so those are left to configuration.
pub const SEED_PROVIDERS: &[(&str, &[&str])] = &[
    ("google", &["google.com", "gmail.com"]),
    ("yahoo", &["yahoo.com", "yahoo.net", "yahoodns.net"]),
    (
        "microsoft",
        &["microsoft.com", "outlook.com", "hotmail.com"],
    ),
    ("aol", &["aol.com"]),
    ("comcast", &["comcast.net"]),
    ("cox", &["cox.net"]),
    ("att", &["att.net"]),
    ("verizon", &["verizon.net"]),
    ("mail.ru", &["mail.ru"]),
    ("yandex", &["yandex.net"]),
    ("returnpath", &["returnpath.net"]),
    ("validity", &["validity.com"]),
];

/// Registry of FBL providers.
#[derive(Debug, Clone, Default)]
pub struct FblRegistry {
    providers: Vec<FblProvider>,
}

impl FblRegistry {
    pub fn new(providers: Vec<FblProvider>) -> Self {
        Self { providers }
    }

    /// Registry built from [`SEED_PROVIDERS`] (used as a fallback when the
    /// DB table is empty or unreachable at startup).
    pub fn compiled_seeds() -> Self {
        Self {
            providers: SEED_PROVIDERS
                .iter()
                .map(|(provider, domains)| FblProvider {
                    provider: (*provider).to_string(),
                    rdns_patterns: domains.iter().map(|d| d.to_string()).collect(),
                    source_networks: Vec::new(),
                    validation_method: FblValidationMethod::RdnsFcrcdns,
                    effective_version: FBL_REGISTRY_SEED_VERSION,
                    enabled: true,
                })
                .collect(),
        }
    }

    pub fn providers(&self) -> &[FblProvider] {
        &self.providers
    }

    pub fn is_empty(&self) -> bool {
        self.providers.is_empty()
    }

    /// Load enabled providers from `fbl_provider_registry`. A missing table
    /// or empty result is reported as an empty registry (the caller decides
    /// whether to fall back to the compiled seeds).
    pub async fn load_from_db(pool: &PgPool) -> anyhow::Result<Self> {
        let rows: Vec<(String, Vec<String>, Vec<String>, String, i32)> = sqlx::query_as(
            r#"SELECT provider,
                      COALESCE(rdns_patterns, '{}') AS rdns_patterns,
                      COALESCE(source_networks, '{}') AS source_networks,
                      validation_method,
                      effective_version
               FROM fbl_provider_registry
               WHERE enabled = TRUE
               ORDER BY provider"#,
        )
        .fetch_all(pool)
        .await?;

        Ok(Self {
            providers: rows
                .into_iter()
                .map(
                    |(provider, rdns_patterns, source_networks, method, version)| FblProvider {
                        provider,
                        rdns_patterns: rdns_patterns
                            .into_iter()
                            .map(|p| normalize_pattern(&p))
                            .filter(|p| !p.is_empty())
                            .collect(),
                        source_networks: source_networks
                            .iter()
                            .filter_map(|n| IpNet::parse(n))
                            .collect(),
                        validation_method: FblValidationMethod::from_db(&method),
                        effective_version: version,
                        enabled: true,
                    },
                )
                .collect(),
        })
    }

    /// Match a source IP's PTR hostnames against the registry.
    ///
    /// Returns [`FblAuthority::Candidate`] only when a registered provider's
    /// rDNS pattern matches AND every registered expectation (method,
    /// networks) holds. FCrDNS confirmation is the caller's async step.
    ///
    /// When several providers share a PTR pattern (shared FBL
    /// infrastructure), every match is evaluated and the first fully
    /// matching provider wins; if none matches, the first registered
    /// expectation failure is reported as `Mismatched` (fail closed).
    pub fn authorize(&self, source_ip: IpAddr, ptr_hostnames: &[String]) -> FblAuthority {
        let mut first_mismatch: Option<FblAuthority> = None;
        for provider in self.providers.iter().filter(|p| p.enabled) {
            let matched = ptr_hostnames.iter().find_map(|hostname| {
                let hostname = normalize_pattern(hostname);
                provider
                    .rdns_patterns
                    .iter()
                    .find(|pattern| hostname_matches_pattern(&hostname, pattern))
                    .map(|_| hostname.clone())
            });
            let Some(matched_hostname) = matched else {
                continue;
            };
            if !provider.validation_method.is_evaluable_for_smtp_arf() {
                first_mismatch.get_or_insert(FblAuthority::Mismatched {
                    provider: Some(provider.provider.clone()),
                    reason: "validation_method_not_applicable_to_smtp_arf",
                });
                continue;
            }
            if !provider.source_networks.is_empty()
                && !provider
                    .source_networks
                    .iter()
                    .any(|network| network.contains(source_ip))
            {
                first_mismatch.get_or_insert(FblAuthority::Mismatched {
                    provider: Some(provider.provider.clone()),
                    reason: "source_network_mismatch",
                });
                continue;
            }
            return FblAuthority::Candidate {
                provider: provider.provider.clone(),
                method: provider.validation_method,
                matched_hostname,
            };
        }
        first_mismatch.unwrap_or(FblAuthority::Unregistered)
    }
}

fn normalize_pattern(value: &str) -> String {
    value.trim().trim_end_matches('.').to_ascii_lowercase()
}

/// Strict trusted-domain match: the hostname must equal the pattern or be a
/// real subdomain of it. A bare suffix match (`evil-google.com`) is rejected,
/// and so is `google.com.evil.com`.
pub(crate) fn hostname_matches_pattern(hostname: &str, pattern: &str) -> bool {
    hostname == pattern || hostname.ends_with(&format!(".{pattern}"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn provider(name: &str, domains: &[&str], networks: &[&str]) -> FblProvider {
        FblProvider {
            provider: name.into(),
            rdns_patterns: domains.iter().map(|d| d.to_string()).collect(),
            source_networks: networks.iter().filter_map(|n| IpNet::parse(n)).collect(),
            validation_method: FblValidationMethod::RdnsFcrcdns,
            effective_version: 1,
            enabled: true,
        }
    }

    #[test]
    fn ipnet_parse_and_contains() {
        let net = IpNet::parse("127.0.0.0/8").unwrap();
        assert!(net.contains("127.0.0.1".parse().unwrap()));
        assert!(!net.contains("10.0.0.1".parse().unwrap()));
        let v6 = IpNet::parse("2001:db8::/32").unwrap();
        assert!(v6.contains("2001:db8::1".parse().unwrap()));
        assert!(!v6.contains("2001:db9::1".parse().unwrap()));
        let host = IpNet::parse("203.0.113.9").unwrap();
        assert!(host.contains("203.0.113.9".parse().unwrap()));
        assert!(!host.contains("203.0.113.10".parse().unwrap()));
        assert!(IpNet::parse("10.0.0.0/33").is_none());
        assert!(IpNet::parse("not-a-network").is_none());
    }

    #[test]
    fn expected_source_network_authorizes_and_unexpected_does_not() {
        // Two providers with the SAME rDNS pattern but different registered
        // source networks: the loopback report is authoritative only for the
        // provider that registered 127.0.0.0/8.
        let registry = FblRegistry::new(vec![
            provider("provider-a", &["fbl.test"], &["127.0.0.0/8"]),
            provider("provider-b", &["fbl.test"], &["10.0.0.0/8"]),
        ]);
        let loopback: IpAddr = "127.0.0.1".parse().unwrap();
        let ptr = vec!["mx.fbl.test".to_string()];

        match registry.authorize(loopback, &ptr) {
            FblAuthority::Candidate {
                provider, method, ..
            } => {
                assert_eq!(provider, "provider-a");
                assert_eq!(method, FblValidationMethod::RdnsFcrcdns);
            }
            other => panic!("expected provider-a candidate, got {other:?}"),
        }

        // Provider-b cannot be reached for loopback because ordering hits
        // provider-a first; flip the order to prove the network check itself
        // rejects the mismatch.
        let registry =
            FblRegistry::new(vec![provider("provider-b", &["fbl.test"], &["10.0.0.0/8"])]);
        assert_eq!(
            registry.authorize(loopback, &ptr),
            FblAuthority::Mismatched {
                provider: Some("provider-b".into()),
                reason: "source_network_mismatch",
            },
            "a registered network that excludes the client IP must not be authoritative"
        );
        assert!(!registry.authorize(loopback, &ptr).is_candidate());
    }

    #[test]
    fn a_mismatched_shared_pattern_does_not_shadow_a_matching_provider() {
        // Shared FBL infrastructure: two providers claim the same PTR
        // pattern. The first one's network expectation fails, but the second
        // fully matches and must still authorize.
        let registry = FblRegistry::new(vec![
            provider("shared-mismatch", &["fbl.test"], &["10.0.0.0/8"]),
            provider("shared-match", &["fbl.test"], &["127.0.0.0/8"]),
        ]);
        match registry.authorize("127.0.0.1".parse().unwrap(), &["mx.fbl.test".into()]) {
            FblAuthority::Candidate { provider, .. } => assert_eq!(provider, "shared-match"),
            other => panic!("expected the fully matching provider, got {other:?}"),
        }
    }

    #[test]
    fn unregistered_source_is_not_authoritative() {
        let registry = FblRegistry::new(vec![provider("google", &["google.com"], &[])]);
        assert_eq!(
            registry.authorize("198.51.100.7".parse().unwrap(), &["mx.evil.com".into()]),
            FblAuthority::Unregistered
        );
        // A suffix-spoofed PTR must not match (`evil-google.com`).
        assert_eq!(
            registry.authorize("198.51.100.7".parse().unwrap(), &["evil-google.com".into()]),
            FblAuthority::Unregistered
        );
    }

    #[test]
    fn provider_without_networks_is_authoritative_by_rdns() {
        // Documented choice: an empty source_networks list means "no network
        // restriction registered" (the pre-existing rDNS/FCrDNS expectation).
        let registry = FblRegistry::new(vec![provider("google", &["google.com"], &[])]);
        let authority = registry.authorize(
            "198.51.100.7".parse().unwrap(),
            &["mail-smtp-in.l.google.com".into()],
        );
        assert!(authority.is_candidate());
    }

    #[test]
    fn unimplemented_validation_method_is_mismatched() {
        let mut p = provider("webhook-only", &["fbl.example"], &[]);
        p.validation_method = FblValidationMethod::WebhookHmac;
        let registry = FblRegistry::new(vec![p]);
        assert_eq!(
            registry.authorize("198.51.100.7".parse().unwrap(), &["mx.fbl.example".into()]),
            FblAuthority::Mismatched {
                provider: Some("webhook-only".into()),
                reason: "validation_method_not_applicable_to_smtp_arf",
            },
            "a provider validated on another channel must not suppress on SMTP rDNS alone"
        );
    }

    #[test]
    fn compiled_seeds_only_contain_substantiated_providers() {
        let registry = FblRegistry::compiled_seeds();
        let names: Vec<&str> = registry
            .providers()
            .iter()
            .map(|p| p.provider.as_str())
            .collect();
        assert!(names.contains(&"google"));
        assert!(names.contains(&"microsoft"));
        assert!(names.contains(&"yahoo"));
        // No provider is seeded with invented networks.
        assert!(registry
            .providers()
            .iter()
            .all(|p| p.source_networks.is_empty()));
        assert!(registry
            .providers()
            .iter()
            .all(|p| p.validation_method == FblValidationMethod::RdnsFcrcdns));
    }
}
