//! DNSBL (DNS-based Blackhole List) monitoring for self-hosted outbound IPs.
//!
//! Periodically checks each outbound IP against major blocklists via DNS queries.
//! When a listing is detected, the IP is marked as `Degraded` in the IP pool
//! and an alert event is emitted.
//!
//! ## Supported blocklists
//!
//! - Spamhaus ZEN (SBL + XBL + PBL)
//! - Barracuda BRBL
//! - SpamCop
//! - SORBS DNSBL
//! - UCE-Protect Level 1
//! - Invaluement
//! - Composite Blocking List (CBL)
//! - JustSpam
//! - Truncate
//! - PSBL
//!
//! ## DNS check pattern
//!
//! Reverse the IP's octets and query `{reversed}.{dnsbl-zone}`.
//! If the query returns an A record, the IP is listed. The specific 127.0.0.x
//! return code encodes the listing reason, but we treat any A-record hit as
//! "listed".

use std::fmt;
use std::net::{IpAddr, Ipv4Addr};

use chrono::{DateTime, Utc};
use tracing::{debug, info, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

// ─── DNSBL zones ───────────────────────────────────────────────

/// Well-known DNSBL zones to check.
pub const DNSBL_ZONES: &[DnsblZone] = &[
    DnsblZone {
        name: "Spamhaus ZEN",
        zone: "zen.spamhaus.org",
        severity: Severity::Critical,
    },
    DnsblZone {
        name: "Barracuda BRBL",
        zone: "b.barracudacentral.org",
        severity: Severity::High,
    },
    DnsblZone {
        name: "SpamCop",
        zone: "bl.spamcop.net",
        severity: Severity::High,
    },
    DnsblZone {
        name: "SORBS",
        zone: "dnsbl.sorbs.net",
        severity: Severity::Medium,
    },
    DnsblZone {
        name: "UCE-Protect L1",
        zone: "dnsbl-1.uceprotect.net",
        severity: Severity::Medium,
    },
    DnsblZone {
        name: "Invaluement",
        zone: "dnsbl.invaluement.com",
        severity: Severity::Medium,
    },
    DnsblZone {
        name: "CBL",
        zone: "cbl.abuseat.org",
        severity: Severity::High,
    },
    DnsblZone {
        name: "JustSpam",
        zone: "dnsbl.justspam.org",
        severity: Severity::Low,
    },
    DnsblZone {
        name: "Truncate",
        zone: "truncate.gbudb.net",
        severity: Severity::Low,
    },
    DnsblZone {
        name: "PSBL",
        zone: "psbl.surriel.com",
        severity: Severity::Low,
    },
];

/// A DNSBL zone definition.
#[derive(Debug, Clone)]
pub struct DnsblZone {
    pub name: &'static str,
    pub zone: &'static str,
    pub severity: Severity,
}

/// Severity of a DNSBL listing.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Low,
    Medium,
    High,
    Critical,
}

impl fmt::Display for Severity {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Low => write!(f, "low"),
            Self::Medium => write!(f, "medium"),
            Self::High => write!(f, "high"),
            Self::Critical => write!(f, "critical"),
        }
    }
}

// ─── Check result ──────────────────────────────────────────────

/// Result of checking a single IP against a single DNSBL.
#[derive(Debug, Clone)]
pub struct DnsblCheckResult {
    pub ip: IpAddr,
    pub zone: String,
    pub zone_name: String,
    pub listed: bool,
    pub return_code: Option<Ipv4Addr>,
    pub severity: Severity,
    pub checked_at: DateTime<Utc>,
}

/// Result of checking an IP against ALL configured DNSBLs.
#[derive(Debug, Clone)]
pub struct DnsblReport {
    pub ip: IpAddr,
    pub checked_at: DateTime<Utc>,
    pub results: Vec<DnsblCheckResult>,
}

impl DnsblReport {
/// Whether the IP is listed on any DNSBL.
    pub fn is_listed(&self) -> bool {
        self.results.iter().any(|r| r.listed)
    }

/// Count of DNSBLs where the IP is listed.
    pub fn listing_count(&self) -> usize {
        self.results.iter().filter(|r| r.listed).count()
    }

/// Get the highest severity among all listings.
    pub fn max_severity(&self) -> Option<Severity> {
        self.results
            .iter()
            .filter(|r| r.listed)
            .map(|r| r.severity)
            .max()
    }

/// Get all zones where the IP is listed.
    pub fn listed_zones(&self) -> Vec<&DnsblCheckResult> {
        self.results.iter().filter(|r| r.listed).collect()
    }
}

// ─── Checker ───────────────────────────────────────────────────

/// DNSBL checker that queries DNS to check if IPs are blocklisted.
pub struct DnsblChecker {
    resolver: TokioAsyncResolver,
}

impl DnsblChecker {
/// Create a new DNSBL checker.
    pub fn new() -> Self {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Self { resolver }
    }

/// Reverse an IPv4 address for DNSBL query.
/// Example:192.168.1.2 → "2.1.168.192"
    pub fn reverse_ip(ip: Ipv4Addr) -> String {
        let octets = ip.octets();
        format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
    }

/// Check a single IP against a single DNSBL zone.
    pub async fn check_single(
        &self,
        ip: IpAddr,
        zone: &DnsblZone,
    ) -> DnsblCheckResult {
        let ip_v4 = match ip {
            IpAddr::V4(v4) => v4,
            IpAddr::V6(_) => {
// Most DNSBLs only support IPv4
                return DnsblCheckResult {
                    ip,
                    zone: zone.zone.to_string(),
                    zone_name: zone.name.to_string(),
                    listed: false,
                    return_code: None,
                    severity: zone.severity,
                    checked_at: Utc::now(),
                };
            }
        };

        let query = format!("{}.{}", Self::reverse_ip(ip_v4), zone.zone);

        match self.resolver.lookup_ip(&query).await {
            Ok(lookup) => {
// Any A record response means the IP is listed.
                let return_addr = lookup.iter().next().and_then(|a| match a {
                    IpAddr::V4(v4) => Some(v4),
                    _ => None,
                });
                let listed = return_addr.is_some();
                if listed {
                    warn!(
                        ip = %ip,
                        dnsbl = %zone.name,
                        return_code = ?return_addr,
                        severity = %zone.severity,
                        "IP listed on DNSBL"
                    );
                }
                DnsblCheckResult {
                    ip,
                    zone: zone.zone.to_string(),
                    zone_name: zone.name.to_string(),
                    listed,
                    return_code: return_addr,
                    severity: zone.severity,
                    checked_at: Utc::now(),
                }
            }
            Err(_) => {
// NXDOMAIN or timeout → not listed (this is the normal case)
                DnsblCheckResult {
                    ip,
                    zone: zone.zone.to_string(),
                    zone_name: zone.name.to_string(),
                    listed: false,
                    return_code: None,
                    severity: zone.severity,
                    checked_at: Utc::now(),
                }
            }
        }
    }

/// Check an IP against all configured DNSBL zones.
    pub async fn check_all(&self, ip: IpAddr) -> DnsblReport {
        let mut results = Vec::with_capacity(DNSBL_ZONES.len());

// Run all checks concurrently
        let futures: Vec<_> = DNSBL_ZONES
            .iter()
            .map(|zone| self.check_single(ip, zone))
            .collect();

        let outcomes = futures::future::join_all(futures).await;
        results.extend(outcomes);

        let report = DnsblReport {
            ip,
            checked_at: Utc::now(),
            results,
        };

        if report.is_listed() {
            info!(
                ip = %ip,
                listed_count = report.listing_count(),
                max_severity = %report.max_severity().unwrap_or(Severity::Low),
                "DNSBL check complete — IP is listed"
            );
        } else {
            debug!(ip = %ip, "DNSBL check clean — not listed");
        }

        report
    }

/// Check multiple IPs against all DNSBLs.
    pub async fn check_many(&self, ips: &[IpAddr]) -> Vec<DnsblReport> {
        let futures: Vec<_> = ips.iter().map(|ip| self.check_all(*ip)).collect();
        futures::future::join_all(futures).await
    }
}

impl Default for DnsblChecker {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_reverse_ip() {
        assert_eq!(
            DnsblChecker::reverse_ip(Ipv4Addr::new(192, 168, 1, 2)),
            "2.1.168.192"
        );
        assert_eq!(
            DnsblChecker::reverse_ip(Ipv4Addr::new(10, 0, 0, 1)),
            "1.0.0.10"
        );
        assert_eq!(
            DnsblChecker::reverse_ip(Ipv4Addr::new(1, 2, 3, 4)),
            "4.3.2.1"
        );
    }

    #[test]
    fn test_dnsbl_zones_non_empty() {
        assert!(!DNSBL_ZONES.is_empty());
        assert!(DNSBL_ZONES.len() >= 10);
    }

    #[test]
    fn test_severity_ordering() {
        assert!(Severity::Low < Severity::Medium);
        assert!(Severity::Medium < Severity::High);
        assert!(Severity::High < Severity::Critical);
    }

    #[test]
    fn test_report_not_listed() {
        let report = DnsblReport {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            checked_at: Utc::now(),
            results: vec![
                DnsblCheckResult {
                    ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    zone: "zen.spamhaus.org".into(),
                    zone_name: "Spamhaus ZEN".into(),
                    listed: false,
                    return_code: None,
                    severity: Severity::Critical,
                    checked_at: Utc::now(),
                },
            ],
        };
        assert!(!report.is_listed());
        assert_eq!(report.listing_count(), 0);
        assert!(report.max_severity().is_none());
    }

    #[test]
    fn test_report_listed() {
        let report = DnsblReport {
            ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            checked_at: Utc::now(),
            results: vec![
                DnsblCheckResult {
                    ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    zone: "zen.spamhaus.org".into(),
                    zone_name: "Spamhaus ZEN".into(),
                    listed: true,
                    return_code: Some(Ipv4Addr::new(127, 0, 0, 2)),
                    severity: Severity::Critical,
                    checked_at: Utc::now(),
                },
                DnsblCheckResult {
                    ip: IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
                    zone: "bl.spamcop.net".into(),
                    zone_name: "SpamCop".into(),
                    listed: false,
                    return_code: None,
                    severity: Severity::High,
                    checked_at: Utc::now(),
                },
            ],
        };
        assert!(report.is_listed());
        assert_eq!(report.listing_count(), 1);
        assert_eq!(report.max_severity(), Some(Severity::Critical));
        assert_eq!(report.listed_zones().len(), 1);
    }

    #[test]
    fn test_severity_display() {
        assert_eq!(format!("{}", Severity::Low), "low");
        assert_eq!(format!("{}", Severity::Critical), "critical");
    }
}
