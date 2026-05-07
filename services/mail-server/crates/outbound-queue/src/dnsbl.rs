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

use std::collections::HashMap;
use std::fmt;
use std::net::{IpAddr, Ipv4Addr};
use std::sync::Arc;
use std::time::Duration;

use chrono::{DateTime, Utc};
use parking_lot::Mutex;
use tracing::{debug, info, warn};
use trust_dns_resolver::config::{ResolverConfig, ResolverOpts};
use trust_dns_resolver::TokioAsyncResolver;

/// Default circuit breaker: number of consecutive failures to open the circuit.
const DEFAULT_CB_FAILURE_THRESHOLD: u32 = 5;
/// Default circuit breaker: cooldown duration in seconds while circuit is open.
const DEFAULT_CB_COOLDOWN_SECS: u64 = 30;
/// Default DNSBL full-sweep interval in seconds (15 minutes).
const DEFAULT_DNSBL_CHECK_INTERVAL_SECS: u64 = 900;

/// Tracks circuit breaker state for a single DNSBL zone.
#[derive(Debug)]
struct ZoneCircuitState {
    /// Consecutive failure count.
    consecutive_failures: u32,
    /// Timestamp (seconds since UNIX epoch) when the circuit was opened.
    /// 0 = circuit is closed.
    opened_at: i64,
    /// Whether a cooldown-expired half-open trial query is already in flight.
    half_open_trial_in_progress: bool,
}

impl ZoneCircuitState {
    fn new() -> Self {
        Self {
            consecutive_failures: 0,
            opened_at: 0,
            half_open_trial_in_progress: false,
        }
    }
}

/// Per-DNSBL-zone circuit breaker that prevents cascading failures
/// when a DNS provider is temporarily unreachable.
///
/// # Behavior
///
/// - **CLOSED** (normal): Queries proceed normally.
/// - **OPEN**: After `failure_threshold` consecutive failures, the circuit opens.
///   Queries are skipped (returns "not listed") for `cooldown` duration.
/// - **HALF-OPEN**: After the cooldown expires, the next query is allowed.
///   If it succeeds, the circuit resets to closed. If it fails, the circuit
///   re-opens for another cooldown period.
#[derive(Debug)]
pub struct DnsblCircuitBreaker {
    /// Per-zone circuit state, keyed by zone domain name.
    states: Mutex<HashMap<String, ZoneCircuitState>>,
    /// Number of consecutive failures before the circuit opens.
    failure_threshold: u32,
    /// Cooldown duration while circuit is open.
    cooldown: Duration,
}

impl DnsblCircuitBreaker {
    /// Create a new circuit breaker with the given parameters.
    pub fn new(failure_threshold: u32, cooldown_secs: u64) -> Self {
        Self {
            states: Mutex::new(HashMap::new()),
            failure_threshold,
            cooldown: Duration::from_secs(cooldown_secs),
        }
    }

    /// Create a circuit breaker configured from environment variables (or defaults).
    ///
    /// | Variable | Default | Description |
    /// |----------|---------|-------------|
    /// | `DNSBL_CB_FAILURE_THRESHOLD` | 5 | Consecutive failures before circuit opens |
    /// | `DNSBL_CB_COOLDOWN_SECS` | 30 | Seconds to wait before retrying |
    pub fn from_env() -> Self {
        let threshold = std::env::var("DNSBL_CB_FAILURE_THRESHOLD")
            .ok()
            .and_then(|s| s.parse::<u32>().ok())
            .unwrap_or(DEFAULT_CB_FAILURE_THRESHOLD);
        let cooldown_secs = std::env::var("DNSBL_CB_COOLDOWN_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_CB_COOLDOWN_SECS);
        Self::new(threshold, cooldown_secs)
    }

    /// Check whether queries to the given zone are allowed.
    /// Returns `true` if the circuit is closed or a half-open trial was reserved,
    /// `false` if open or another half-open trial is already in flight.
    pub fn is_allowed(&self, zone: &str) -> bool {
        let mut states = self.states.lock();
        if let Some(state) = states.get_mut(zone) {
            if state.opened_at > 0 {
                let now = chrono::Utc::now().timestamp();
                let elapsed = now - state.opened_at;
                if elapsed < self.cooldown.as_secs() as i64 {
                    // Circuit is still open -- skip
                    return false;
                }
                if state.half_open_trial_in_progress {
                    return false;
                }
                state.half_open_trial_in_progress = true;
            }
        }
        true
    }

    /// Record a successful query to the given zone.
    /// Resets the failure count and closes the circuit.
    pub fn record_success(&self, zone: &str) {
        let mut states = self.states.lock();
        if let Some(state) = states.get_mut(zone) {
            state.consecutive_failures = 0;
            state.opened_at = 0;
            state.half_open_trial_in_progress = false;
        }
    }

    /// Record a failed query to the given zone.
    /// If the failure threshold is reached, the circuit opens.
    pub fn record_failure(&self, zone: &str) {
        let mut states = self.states.lock();
        let state = states
            .entry(zone.to_string())
            .or_insert_with(ZoneCircuitState::new);

        if state.opened_at > 0 && state.half_open_trial_in_progress {
            state.consecutive_failures = state.consecutive_failures.saturating_add(1);
            state.opened_at = chrono::Utc::now().timestamp();
            state.half_open_trial_in_progress = false;
            warn!(
                dnsbl_zone = zone,
                consecutive_failures = state.consecutive_failures,
                cooldown_secs = self.cooldown.as_secs(),
                "DNSBL circuit breaker half-open trial failed; zone reopened"
            );
            return;
        }

        state.consecutive_failures = state.consecutive_failures.saturating_add(1);
        if state.consecutive_failures >= self.failure_threshold {
            if state.opened_at == 0 {
                state.opened_at = chrono::Utc::now().timestamp();
                state.half_open_trial_in_progress = false;
                warn!(
                    dnsbl_zone = zone,
                    consecutive_failures = state.consecutive_failures,
                    cooldown_secs = self.cooldown.as_secs(),
                    "DNSBL circuit breaker opened for zone"
                );
            }
        }
    }

    /// Get the failure threshold.
    pub fn failure_threshold(&self) -> u32 {
        self.failure_threshold
    }

    /// Get the cooldown duration.
    pub fn cooldown(&self) -> Duration {
        self.cooldown
    }
}

impl Default for DnsblCircuitBreaker {
    fn default() -> Self {
        Self::from_env()
    }
}

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
///
/// Includes a per-zone circuit breaker to prevent cascading failures
/// when a DNS provider is temporarily unreachable. Also enforces
/// an explicit per-query timeout so slow DNS cannot block delivery.
pub struct DnsblChecker {
    resolver: TokioAsyncResolver,
    circuit_breaker: Arc<DnsblCircuitBreaker>,
    /// Per-query timeout duration.
    query_timeout: Duration,
}

impl DnsblChecker {
    /// Create a new DNSBL checker with default settings.
    pub fn new() -> Self {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Self {
            resolver,
            circuit_breaker: Arc::new(DnsblCircuitBreaker::from_env()),
            query_timeout: Duration::from_secs(5),
        }
    }

    /// Create a new DNSBL checker with a custom circuit breaker.
    pub fn with_circuit_breaker(circuit_breaker: Arc<DnsblCircuitBreaker>) -> Self {
        let resolver =
            TokioAsyncResolver::tokio(ResolverConfig::default(), ResolverOpts::default());
        Self {
            resolver,
            circuit_breaker,
            query_timeout: Duration::from_secs(5),
        }
    }

    /// Set the per-query timeout.
    pub fn with_query_timeout(mut self, timeout: Duration) -> Self {
        self.query_timeout = timeout;
        self
    }

    /// Get the DNSBL full-sweep interval from environment or default.
    ///
    /// This controls how often the background monitoring loop checks all
    /// outbound IPs against all configured DNSBL zones.
    ///
    /// Reads `DNSBL_CHECK_INTERVAL_SECS` env var (default: 900 = 15 minutes).
    pub fn check_interval() -> Duration {
        let secs = std::env::var("DNSBL_CHECK_INTERVAL_SECS")
            .ok()
            .and_then(|s| s.parse::<u64>().ok())
            .unwrap_or(DEFAULT_DNSBL_CHECK_INTERVAL_SECS);
        Duration::from_secs(secs)
    }

    /// Reverse an IPv4 address for DNSBL query.
    /// Example:192.168.1.2 &#8594; "2.1.168.192"
    pub fn reverse_ip(ip: Ipv4Addr) -> String {
        let octets = ip.octets();
        format!("{}.{}.{}.{}", octets[3], octets[2], octets[1], octets[0])
    }

    /// Check a single IP against a single DNSBL zone.
    ///
    /// If the circuit breaker is open for this zone, the check is skipped
    /// (returns "not listed") and the failure count is not incremented --
    /// the circuit remains open until the cooldown expires.
    ///
    /// DNS server failures (SERVFAIL, REFUSED, timeouts, connection errors)
    /// are recorded in the circuit breaker. NXDOMAIN (normal "not listed") is
    /// not counted as a failure.
    pub async fn check_single(&self, ip: IpAddr, zone: &DnsblZone) -> DnsblCheckResult {
        // Circuit breaker check -- skip if open
        if !self.circuit_breaker.is_allowed(zone.zone) {
            debug!(
                dnsbl = %zone.name,
                "Skipping DNSBL check -- circuit breaker open"
            );
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

        // Use explicit timeout to prevent slow DNS from blocking delivery
        let lookup_result =
            tokio::time::timeout(self.query_timeout, self.resolver.lookup_ip(&query)).await;

        match lookup_result {
            Ok(Ok(lookup)) => {
                // Successful query -- record success in circuit breaker
                self.circuit_breaker.record_success(zone.zone);

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
            Ok(Err(dns_err)) => {
                // DNS error (NXDOMAIN, SERVFAIL, etc.)
                // NXDOMAIN is the normal "not listed" case -- do not count as failure
                let err_str = format!("{}", dns_err);
                let is_server_failure = err_str.contains("SERVFAIL")
                    || err_str.contains("REFUSED")
                    || err_str.contains("timeout")
                    || err_str.contains("connection");
                if is_server_failure {
                    self.circuit_breaker.record_failure(zone.zone);
                    warn!(
                        dnsbl = %zone.name,
                        error = %dns_err,
                        "DNSBL query failed -- recorded in circuit breaker"
                    );
                }
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
            Err(_timeout) => {
                // Query timed out -- count as circuit breaker failure
                self.circuit_breaker.record_failure(zone.zone);
                warn!(
                    dnsbl = %zone.name,
                    timeout_secs = self.query_timeout.as_secs(),
                    "DNSBL query timed out -- recorded in circuit breaker"
                );
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
    ///
    /// Implements multi-provider agreement: if an IP appears listed on
    /// fewer than 2 providers, it is treated as a potential false positive
    /// rather than definitively blacklisted. The report's `is_listed()`
    /// still returns `true` for single-provider results, but callers can
    /// use `listing_count() >= 2` for stricter enforcement (F-012).
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
            let count = report.listing_count();
            if count >= 2 {
                info!(
                    ip = %ip,
                    listed_count = count,
                    max_severity = %report.max_severity().unwrap_or(Severity::Low),
                    "DNSBL check complete -- IP listed on {} provider(s)",
                    count,
                );
            } else {
                // Single-provider listing -- potential false positive per F-012
                warn!(
                    ip = %ip,
                    listed_count = count,
                    "DNSBL check -- IP listed on single provider only (possible false positive)"
                );
            }
        } else {
            debug!(ip = %ip, "DNSBL check clean -- not listed");
        }

        report
    }

    /// Check multiple IPs against all DNSBLs.
    pub async fn check_many(&self, ips: &[IpAddr]) -> Vec<DnsblReport> {
        let futures: Vec<_> = ips.iter().map(|ip| self.check_all(*ip)).collect();
        futures::future::join_all(futures).await
    }

    /// Access the circuit breaker (e.g., for inspection or metrics).
    pub fn circuit_breaker(&self) -> &Arc<DnsblCircuitBreaker> {
        &self.circuit_breaker
    }
}

impl Default for DnsblChecker {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn expire_circuit(cb: &DnsblCircuitBreaker, zone: &str) {
        let mut states = cb.states.lock();
        let state = states.get_mut(zone).expect("zone state should exist");
        state.opened_at = chrono::Utc::now().timestamp() - cb.cooldown().as_secs() as i64 - 1;
    }

    #[test]
    fn test_circuit_breaker_allows_one_half_open_trial() {
        let cb = DnsblCircuitBreaker::new(1, 30);
        let zone = "test.example";

        cb.record_failure(zone);
        assert!(!cb.is_allowed(zone));
        expire_circuit(&cb, zone);

        assert!(cb.is_allowed(zone));
        assert!(!cb.is_allowed(zone));
    }

    #[test]
    fn test_circuit_breaker_reopens_after_failed_half_open_trial() {
        let cb = DnsblCircuitBreaker::new(1, 30);
        let zone = "test.example";

        cb.record_failure(zone);
        expire_circuit(&cb, zone);
        assert!(cb.is_allowed(zone));

        cb.record_failure(zone);
        assert!(!cb.is_allowed(zone));

        expire_circuit(&cb, zone);
        assert!(cb.is_allowed(zone));
    }

    #[test]
    fn test_circuit_breaker_success_closes_half_open_trial() {
        let cb = DnsblCircuitBreaker::new(1, 30);
        let zone = "test.example";

        cb.record_failure(zone);
        expire_circuit(&cb, zone);
        assert!(cb.is_allowed(zone));

        cb.record_success(zone);
        assert!(cb.is_allowed(zone));

        let states = cb.states.lock();
        let state = states.get(zone).expect("zone state should exist");
        assert_eq!(state.consecutive_failures, 0);
        assert_eq!(state.opened_at, 0);
        assert!(!state.half_open_trial_in_progress);
    }
}

/// Test-only constructor allowing injection of a custom DNS resolver.
///
/// This enables tests to use a mock DNS server instead of making real
/// network queries, keeping tests self-contained and deterministic.
#[cfg(test)]
impl DnsblChecker {
    pub fn with_resolver(resolver: TokioAsyncResolver) -> Self {
        Self {
            resolver,
            circuit_breaker: Arc::new(DnsblCircuitBreaker::from_env()),
            query_timeout: Duration::from_secs(5),
        }
    }

    pub fn with_resolver_and_cb(
        resolver: TokioAsyncResolver,
        circuit_breaker: Arc<DnsblCircuitBreaker>,
    ) -> Self {
        Self {
            resolver,
            circuit_breaker,
            query_timeout: Duration::from_secs(5),
        }
    }
}
