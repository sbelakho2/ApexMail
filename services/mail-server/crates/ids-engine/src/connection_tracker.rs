//! Connection tracking for stateful IDS analysis
//!
//! Tracks TCP/UDP sessions to detect:
//! - Port scans (horizontal and vertical)
//! - SYN floods (half-open connection tracking)
//! - Connection rate anomalies

use std::net::IpAddr;
use std::time::Instant;

use dashmap::DashMap;

/// Connection state
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ConnState {
    /// SYN sent (half-open)
    SynSent,
    /// Connection established
    Established,
    /// Connection closing
    Closing,
    /// Connection closed
    Closed,
}

/// A tracked connection
#[derive(Debug, Clone)]
pub struct TrackedConnection {
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination port
    pub dst_port: u16,
    /// Connection state
    pub state: ConnState,
    /// When this connection was first seen
    pub first_seen: Instant,
    /// Last activity
    pub last_seen: Instant,
    /// Bytes transferred (approximate)
    pub bytes_transferred: u64,
    /// Number of packets
    pub packet_count: u32,
}

/// Port scan tracking per IP
#[derive(Debug, Clone)]
struct PortScanTracker {
    /// Unique ports contacted in the current window
    ports: Vec<(u16, Instant)>,
    /// Whether this IP has been flagged for port scanning
    flagged: bool,
}

/// Connection tracker
pub struct ConnectionTracker {
    /// Active connections: (src_ip, dst_port) -> TrackedConnection
    connections: DashMap<(IpAddr, u16), TrackedConnection>,
    /// Half-open (SYN) connections per IP
    half_open_counts: DashMap<IpAddr, u32>,
    /// Port scan tracking per source IP
    port_scan: DashMap<IpAddr, PortScanTracker>,
    /// Thresholds
    portscan_threshold: u32,
    portscan_window: std::time::Duration,
    syn_flood_threshold: u32,
    max_connections: usize,
}

/// Anomaly detected by connection tracker
#[derive(Debug, Clone)]
pub enum ConnectionAnomaly {
    /// Port scan detected
    PortScan {
        /// Source IP
        ip: IpAddr,
        /// Number of unique ports contacted
        unique_ports: u32,
    },
    /// SYN flood detected
    SynFlood {
        /// Source IP
        ip: IpAddr,
        /// Number of half-open connections
        half_open: u32,
    },
    /// Connection table exhaustion attempt
    ConnectionFlood {
        /// Source IP
        ip: IpAddr,
    },
}

impl ConnectionTracker {
    /// Create a new connection tracker
    pub fn new(
        max_connections: usize,
        portscan_threshold: u32,
        portscan_window_secs: u64,
        syn_flood_threshold: u32,
    ) -> Self {
        Self {
            connections: DashMap::with_capacity(max_connections),
            half_open_counts: DashMap::new(),
            port_scan: DashMap::new(),
            portscan_threshold,
            portscan_window: std::time::Duration::from_secs(portscan_window_secs),
            syn_flood_threshold,
            max_connections,
        }
    }

    /// Record a new connection attempt (SYN).
    /// Returns any detected anomalies.
    pub fn record_syn(&self, src_ip: IpAddr, dst_port: u16) -> Vec<ConnectionAnomaly> {
        let mut anomalies = Vec::new();
        let now = Instant::now();

        // Update connection table
        let key = (src_ip, dst_port);
        self.connections.insert(key, TrackedConnection {
            src_ip,
            dst_port,
            state: ConnState::SynSent,
            first_seen: now,
            last_seen: now,
            bytes_transferred: 0,
            packet_count: 1,
        });

        // Track half-open connections
        let mut half_open = self.half_open_counts.entry(src_ip).or_insert(0);
        *half_open += 1;
        let half_open_val = *half_open;
        drop(half_open);

        if half_open_val > self.syn_flood_threshold {
            anomalies.push(ConnectionAnomaly::SynFlood {
                ip: src_ip,
                half_open: half_open_val,
            });
        }

        // Track port scan
        let mut entry = self.port_scan.entry(src_ip).or_insert(PortScanTracker {
            ports: Vec::new(),
            flagged: false,
        });
        // Evict old entries outside the window
        entry.ports.retain(|(_, t)| now.duration_since(*t) < self.portscan_window);
        // Add new port if not already tracked
        if !entry.ports.iter().any(|(p, _)| *p == dst_port) {
            entry.ports.push((dst_port, now));
        }
        let unique_ports = entry.ports.len() as u32;
        let already_flagged = entry.flagged;

        if unique_ports > self.portscan_threshold && !already_flagged {
            entry.flagged = true;
            anomalies.push(ConnectionAnomaly::PortScan {
                ip: src_ip,
                unique_ports,
            });
        }

        // Check overall capacity
        if self.connections.len() > self.max_connections {
            anomalies.push(ConnectionAnomaly::ConnectionFlood { ip: src_ip });
        }

        anomalies
    }

    /// Record connection established (SYN-ACK-ACK).
    pub fn record_established(&self, src_ip: IpAddr, dst_port: u16) {
        let key = (src_ip, dst_port);
        if let Some(mut conn) = self.connections.get_mut(&key) {
            conn.state = ConnState::Established;
            conn.last_seen = Instant::now();
        }
        // Decrement half-open count
        if let Some(mut count) = self.half_open_counts.get_mut(&src_ip) {
            *count = count.saturating_sub(1);
        }
    }

    /// Record connection close
    pub fn record_close(&self, src_ip: IpAddr, dst_port: u16) {
        let key = (src_ip, dst_port);
        self.connections.remove(&key);
        if let Some(mut count) = self.half_open_counts.get_mut(&src_ip) {
            *count = count.saturating_sub(1);
        }
    }

    /// Cleanup expired connections
    pub fn cleanup(&self, timeout: std::time::Duration) {
        let now = Instant::now();
        self.connections.retain(|_, conn| {
            now.duration_since(conn.last_seen) < timeout
        });
    }

    /// Get current number of tracked connections
    pub fn active_connections(&self) -> usize {
        self.connections.len()
    }

    /// Get half-open count for a specific IP
    pub fn half_open_for(&self, ip: &IpAddr) -> u32 {
        self.half_open_counts.get(ip).map(|v| *v).unwrap_or(0)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_syn_flood_detection() {
        let tracker = ConnectionTracker::new(100_000, 20, 60, 5);
        let ip: IpAddr = "10.0.0.1".parse().expect("valid IP");

        for port in 1..=6 {
            let anomalies = tracker.record_syn(ip, port);
            if port > 5 {
                assert!(anomalies.iter().any(|a| matches!(a, ConnectionAnomaly::SynFlood { .. })));
            }
        }
    }

    #[test]
    fn test_port_scan_detection() {
        let tracker = ConnectionTracker::new(100_000, 3, 60, 100);
        let ip: IpAddr = "10.0.0.2".parse().expect("valid IP");

        for port in 1..=4 {
            let anomalies = tracker.record_syn(ip, port);
            if port > 3 {
                assert!(anomalies.iter().any(|a| matches!(a, ConnectionAnomaly::PortScan { .. })));
            }
        }
    }

    #[test]
    fn test_established_decrements_half_open() {
        let tracker = ConnectionTracker::new(100_000, 20, 60, 100);
        let ip: IpAddr = "10.0.0.3".parse().expect("valid IP");

        tracker.record_syn(ip, 80);
        assert_eq!(tracker.half_open_for(&ip), 1);

        tracker.record_established(ip, 80);
        assert_eq!(tracker.half_open_for(&ip), 0);
    }
}
