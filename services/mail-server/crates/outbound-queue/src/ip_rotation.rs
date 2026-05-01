//! IP rotation and source-binding for the self-hosted SMTP path.
//!
//! When we run our own MTA on Hetzner (or any host with multiple IPs), each
//! tenant may be assigned one or more dedicated IPs. This module://!
//! 1. **IP pool management** — maintains a set of outbound IPs with metadata.
//! 2. **Round-robin rotation** — selects the next IP in the pool for each send.
//! 3. **Source binding** — creates a `TcpSocket` bound to the chosen IP.
//! 4. **Warmup-aware throttling** — respects per-IP daily limits during warmup.
//! 5. **Health tracking** — marks IPs as degraded if DNSBL-listed.
//!
//! ## Integration
//!
//! The `SmtpSender` calls `IpPool::next_outbound_socket` instead of
//! `TcpStream::connect` to get a socket that is pre-bound to the correct
//! source address.

use std::collections::HashMap;
use std::net::{IpAddr, SocketAddr};
use std::sync::atomic::{AtomicU64, AtomicUsize, Ordering};
use std::sync::Arc;

use chrono::{DateTime, Utc};
use mail_common::warmup::WarmupSchedule;
use tokio::net::TcpSocket;
use tracing::debug;

// ─── IP metadata ───────────────────────────────────────────────

/// Health status of an outbound IP.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IpHealth {
    /// Normal operation.
    Healthy,
    /// In warmup period — subject to daily rate limits.
    Warming,
    /// Listed on one or more DNSBLs — should not be used until cleared.
    Degraded,
    /// Manually disabled by operator.
    Disabled,
}

/// Per-IP daily usage counters for warmup enforcement.
#[derive(Debug)]
pub struct IpDailyCounters {
    pub sends_today: AtomicU64,
    pub day_start: DateTime<Utc>,
}

impl IpDailyCounters {
    pub fn new() -> Self {
        Self {
            sends_today: AtomicU64::new(0),
            day_start: Utc::now(),
        }
    }

    pub fn increment(&self) -> u64 {
        self.sends_today.fetch_add(1, Ordering::Relaxed)
    }

    pub fn current(&self) -> u64 {
        self.sends_today.load(Ordering::Relaxed)
    }

    /// Reset if the current day has changed.
    pub fn maybe_reset(&self) {
        let now = Utc::now();
        // Compare ordinal day — if it's a new day, reset.
        if now.date_naive() != self.day_start.date_naive() {
            self.sends_today.store(0, Ordering::Relaxed);
        }
    }
}

impl Default for IpDailyCounters {
    fn default() -> Self {
        Self::new()
    }
}

/// Metadata for a single outbound IP address.
#[derive(Debug)]
pub struct OutboundIp {
    pub addr: IpAddr,
    pub health: IpHealth,
    /// Which tenant owns this IP (None = shared pool).
    pub tenant_id: Option<String>,
    /// Day the IP was allocated (for warmup age calculation).
    pub allocated_at: DateTime<Utc>,
    /// Warmup day limit:number of emails allowed per day.
    /// None = no limit (fully warmed).
    pub daily_limit: Option<u64>,
    /// Per-day counters.
    pub counters: IpDailyCounters,
}

impl OutboundIp {
    /// Create a new outbound IP in warming state.
    pub fn new_warming(addr: IpAddr, tenant_id: Option<String>) -> Self {
        Self {
            addr,
            health: IpHealth::Warming,
            tenant_id,
            allocated_at: Utc::now(),
            daily_limit: Some(WarmupSchedule::limit_for_day(0)),
            counters: IpDailyCounters::new(),
        }
    }

    /// Create a fully warmed outbound IP.
    pub fn new_healthy(addr: IpAddr, tenant_id: Option<String>) -> Self {
        Self {
            addr,
            health: IpHealth::Healthy,
            tenant_id,
            allocated_at: Utc::now(),
            daily_limit: None,
            counters: IpDailyCounters::new(),
        }
    }

    /// Whether this IP can accept another send right now.
    pub fn can_send(&self) -> bool {
        if self.health == IpHealth::Degraded || self.health == IpHealth::Disabled {
            return false;
        }
        self.counters.maybe_reset();
        match self.daily_limit {
            Some(limit) => self.counters.current() < limit,
            None => true,
        }
    }

    /// Record a send and return whether we're still under limit.
    pub fn record_send(&self) -> bool {
        self.counters.maybe_reset();
        let prev = self.counters.increment();
        match self.daily_limit {
            Some(limit) => prev < limit,
            None => true,
        }
    }

    /// Get warmup day number (days since allocation).
    pub fn warmup_day(&self) -> i64 {
        (Utc::now() - self.allocated_at).num_days()
    }

    /// Update the daily limit based on current warmup day.
    pub fn update_warmup_limit(&mut self) {
        let day = self.warmup_day();
        if day >= WarmupSchedule::FULL_WARMUP_DAYS as i64 {
            self.health = IpHealth::Healthy;
            self.daily_limit = None;
        } else {
            self.daily_limit = Some(WarmupSchedule::limit_for_day(day as u32));
        }
    }
}

// ─── IP Pool ───────────────────────────────────────────────────

/// Manages a pool of outbound IPs with round-robin rotation.
pub struct IpPool {
    /// All IPs in the pool, indexed by address.
    ips: HashMap<IpAddr, Arc<OutboundIp>>,
    /// Ordered list for round-robin selection.
    rotation_order: Vec<IpAddr>,
    /// Atomic round-robin counter.
    next_index: AtomicUsize,
    /// Default/shared IP used when no dedicated IPs are assigned.
    default_ip: Option<IpAddr>,
}

impl IpPool {
    /// Create an empty IP pool.
    pub fn new() -> Self {
        Self {
            ips: HashMap::new(),
            rotation_order: Vec::new(),
            next_index: AtomicUsize::new(0),
            default_ip: None,
        }
    }

    /// Create an IP pool with a default shared IP.
    pub fn with_default(default_ip: IpAddr) -> Self {
        Self {
            ips: HashMap::new(),
            rotation_order: Vec::new(),
            next_index: AtomicUsize::new(0),
            default_ip: Some(default_ip),
        }
    }

    /// Add an IP to the pool.
    pub fn add_ip(&mut self, ip: OutboundIp) {
        let addr = ip.addr;
        self.ips.insert(addr, Arc::new(ip));
        self.rotation_order.push(addr);
    }

    /// Remove an IP from the pool.
    pub fn remove_ip(&mut self, addr: &IpAddr) -> Option<Arc<OutboundIp>> {
        self.rotation_order.retain(|a| a != addr);
        self.ips.remove(addr)
    }

    /// Get the IPs assigned to a specific tenant.
    pub fn tenant_ips(&self, tenant_id: &str) -> Vec<&Arc<OutboundIp>> {
        self.ips
            .values()
            .filter(|ip| ip.tenant_id.as_deref() == Some(tenant_id))
            .collect()
    }

    /// Select the next IP for sending (round-robin among healthy IPs).
    /// If `tenant_id` is provided, only consider IPs assigned to that tenant.
    /// Falls back to the default IP if no tenant IPs are available.
    pub fn select_ip(&self, tenant_id: Option<&str>) -> Option<Arc<OutboundIp>> {
        let candidates: Vec<&IpAddr> = if let Some(tid) = tenant_id {
            self.rotation_order
                .iter()
                .filter(|addr| {
                    self.ips.get(addr).map_or(false, |ip| {
                        ip.tenant_id.as_deref() == Some(tid) && ip.can_send()
                    })
                })
                .collect()
        } else {
            self.rotation_order
                .iter()
                .filter(|addr| self.ips.get(addr).map_or(false, |ip| ip.can_send()))
                .collect()
        };

        if candidates.is_empty() {
            // Fall back to default IP
            return self
                .default_ip
                .and_then(|addr| self.ips.get(&addr).cloned());
        }

        let idx = self.next_index.fetch_add(1, Ordering::Relaxed) % candidates.len();
        candidates
            .get(idx)
            .and_then(|addr| self.ips.get(addr).cloned())
    }

    /// Create a TCP socket bound to the selected outbound IP and connect to
    /// the given remote address.
    /// This replaces `TcpStream::connect(remote)` in SmtpSender.
    pub async fn connect_with_source(
        &self,
        remote: SocketAddr,
        tenant_id: Option<&str>,
    ) -> Result<(tokio::net::TcpStream, IpAddr), std::io::Error> {
        let selected = self.select_ip(tenant_id).ok_or_else(|| {
            std::io::Error::new(
                std::io::ErrorKind::AddrNotAvailable,
                "No outbound IP available",
            )
        })?;

        let source_addr = selected.addr;
        let socket = if source_addr.is_ipv4() {
            let sock = TcpSocket::new_v4()?;
            sock.bind(SocketAddr::new(source_addr, 0))?;
            sock
        } else {
            let sock = TcpSocket::new_v6()?;
            sock.bind(SocketAddr::new(source_addr, 0))?;
            sock
        };

        debug!(
            source = %source_addr,
            remote = %remote,
            "Connecting with source-bound socket"
        );

        let stream = socket.connect(remote).await?;
        selected.record_send();

        Ok((stream, source_addr))
    }

    /// Number of IPs in the pool.
    pub fn len(&self) -> usize {
        self.ips.len()
    }

    /// Whether the pool is empty.
    pub fn is_empty(&self) -> bool {
        self.ips.is_empty()
    }

    /// Get all IP addresses in the pool.
    pub fn addresses(&self) -> Vec<IpAddr> {
        self.rotation_order.clone()
    }

    /// Get an IP by its address.
    pub fn get(&self, addr: &IpAddr) -> Option<&Arc<OutboundIp>> {
        self.ips.get(addr)
    }
}

impl Default for IpPool {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Tests ─────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    #[test]
    fn test_warmup_schedule() {
        assert_eq!(WarmupSchedule::limit_for_day(0), 50);
        assert_eq!(WarmupSchedule::limit_for_day(1), 50);
        assert_eq!(WarmupSchedule::limit_for_day(2), 100);
        assert_eq!(WarmupSchedule::limit_for_day(5), 250);
        assert_eq!(WarmupSchedule::limit_for_day(8), 1_000);
        assert_eq!(WarmupSchedule::limit_for_day(15), 5_000);
        assert_eq!(WarmupSchedule::limit_for_day(30), 25_000);
        assert_eq!(WarmupSchedule::limit_for_day(40), 50_000);
        assert_eq!(WarmupSchedule::limit_for_day(45), 75_000);
        assert_eq!(WarmupSchedule::limit_for_day(50), 100_000);
        assert_eq!(WarmupSchedule::limit_for_day(55), 250_000);
        assert_eq!(WarmupSchedule::limit_for_day(60), u64::MAX);
        assert_eq!(WarmupSchedule::limit_for_day(100), u64::MAX);
    }

    #[test]
    fn test_outbound_ip_can_send_healthy() {
        let ip = OutboundIp::new_healthy(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            Some("tenant-1".into()),
        );
        assert!(ip.can_send());
        assert_eq!(ip.health, IpHealth::Healthy);
        assert!(ip.daily_limit.is_none());
    }

    #[test]
    fn test_outbound_ip_warming_limit() {
        let ip = OutboundIp::new_warming(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), None);
        assert_eq!(ip.health, IpHealth::Warming);
        assert_eq!(ip.daily_limit, Some(50)); // Day 0
        assert!(ip.can_send());
    }

    #[test]
    fn test_outbound_ip_disabled() {
        let mut ip = OutboundIp::new_healthy(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 3)), None);
        ip.health = IpHealth::Disabled;
        assert!(!ip.can_send());
    }

    #[test]
    fn test_outbound_ip_degraded() {
        let mut ip = OutboundIp::new_healthy(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 4)), None);
        ip.health = IpHealth::Degraded;
        assert!(!ip.can_send());
    }

    #[test]
    fn test_ip_pool_round_robin() {
        let mut pool = IpPool::new();

        let ip1 = OutboundIp::new_healthy(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)), None);
        let ip2 = OutboundIp::new_healthy(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)), None);

        pool.add_ip(ip1);
        pool.add_ip(ip2);

        let selected_1 = pool.select_ip(None).unwrap();
        let selected_2 = pool.select_ip(None).unwrap();

        // Round-robin should give different IPs
        assert_ne!(selected_1.addr, selected_2.addr);
    }

    #[test]
    fn test_ip_pool_tenant_isolation() {
        let mut pool = IpPool::new();

        let ip1 = OutboundIp::new_healthy(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)),
            Some("tenant-a".into()),
        );
        let ip2 = OutboundIp::new_healthy(
            IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)),
            Some("tenant-b".into()),
        );

        pool.add_ip(ip1);
        pool.add_ip(ip2);

        let selected = pool.select_ip(Some("tenant-a")).unwrap();
        assert_eq!(selected.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1)));

        let selected = pool.select_ip(Some("tenant-b")).unwrap();
        assert_eq!(selected.addr, IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2)));
    }

    #[test]
    fn test_ip_pool_empty_returns_none() {
        let pool = IpPool::new();
        assert!(pool.select_ip(None).is_none());
    }

    #[test]
    fn test_ip_pool_fallback_to_default() {
        let default_addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 100));
        let mut pool = IpPool::with_default(default_addr);

        // Add the default as a healthy IP
        pool.add_ip(OutboundIp::new_healthy(default_addr, None));

        // Request tenant that has no IPs → should fall back to default
        let selected = pool.select_ip(Some("unknown-tenant")).unwrap();
        assert_eq!(selected.addr, default_addr);
    }

    #[test]
    fn test_ip_pool_remove() {
        let mut pool = IpPool::new();
        let addr = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        pool.add_ip(OutboundIp::new_healthy(addr, None));
        assert_eq!(pool.len(), 1);

        pool.remove_ip(&addr);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_warmup_counter_record_send() {
        let ip = OutboundIp::new_warming(IpAddr::V4(Ipv4Addr::new(10, 0, 0, 5)), None);
        // Limit is 50 for day 0
        for _ in 0..50 {
            assert!(ip.record_send());
        }
        // 51st send should exceed limit
        assert!(!ip.record_send());
        assert!(!ip.can_send());
    }

    #[test]
    fn test_warmup_schedule_full_days() {
        assert_eq!(WarmupSchedule::FULL_WARMUP_DAYS, 60);
    }

    #[test]
    fn test_ip_pool_addresses() {
        let mut pool = IpPool::new();
        let addr1 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 1));
        let addr2 = IpAddr::V4(Ipv4Addr::new(10, 0, 0, 2));
        pool.add_ip(OutboundIp::new_healthy(addr1, None));
        pool.add_ip(OutboundIp::new_healthy(addr2, None));

        let addrs = pool.addresses();
        assert_eq!(addrs.len(), 2);
        assert!(addrs.contains(&addr1));
        assert!(addrs.contains(&addr2));
    }
}
