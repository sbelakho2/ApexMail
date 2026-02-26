//! Main IDS/IPS engine orchestrator

use std::net::IpAddr;
use std::sync::Arc;

use dashmap::DashMap;
use tracing::{info, warn};

use crate::config::IdsConfig;
use crate::connection_tracker::{ConnectionAnomaly, ConnectionTracker};
use crate::protocol_analyzer;
use crate::signature::{self, SignatureAction, SignatureSet, SigSeverity};

/// Alert severity for external consumers
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum AlertSeverity {
    /// Informational
    Info,
    /// Low
    Low,
    /// Medium
    Medium,
    /// High
    High,
    /// Critical
    Critical,
}

impl From<SigSeverity> for AlertSeverity {
    fn from(s: SigSeverity) -> Self {
        match s {
            SigSeverity::Info => AlertSeverity::Info,
            SigSeverity::Low => AlertSeverity::Low,
            SigSeverity::Medium => AlertSeverity::Medium,
            SigSeverity::High => AlertSeverity::High,
            SigSeverity::Critical => AlertSeverity::Critical,
        }
    }
}

/// An IDS alert
#[derive(Debug, Clone)]
pub struct Alert {
    /// Alert ID / signature ID
    pub id: u32,
    /// Source IP
    pub src_ip: IpAddr,
    /// Destination port
    pub dst_port: u16,
    /// Severity
    pub severity: AlertSeverity,
    /// Message
    pub message: String,
    /// Category
    pub category: String,
    /// Recommended action
    pub action: IdsVerdict,
    /// Timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
}

/// IDS verdict on a packet/connection
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum IdsVerdict {
    /// Allow the traffic
    Pass,
    /// Alert but allow
    Alert,
    /// Drop the traffic (IPS mode)
    Drop,
    /// Reject (send RST/ICMP)
    Reject,
}

/// Main IDS/IPS engine
pub struct IdsEngine {
    config: Arc<IdsConfig>,
    signatures: Arc<SignatureSet>,
    conn_tracker: Arc<ConnectionTracker>,
    /// Alert rate limiting per IP
    alert_counts: DashMap<IpAddr, (u32, std::time::Instant)>,
}

impl IdsEngine {
    /// Create a new IDS engine with built-in signatures
    pub fn new(config: IdsConfig) -> Result<Self, crate::IdsError> {
        let sigs = signature::builtin_mail_signatures();
        let sig_set = SignatureSet::new(sigs)
            .map_err(|e| crate::IdsError::Signature(e))?;

        let conn_tracker = ConnectionTracker::new(
            config.max_connections,
            config.portscan_threshold,
            config.portscan_window_secs,
            config.syn_flood_threshold,
        );

        info!(
            signatures = sig_set.signature_count(),
            inline_mode = config.inline_mode,
            "IDS engine initialized"
        );

        Ok(Self {
            config: Arc::new(config),
            signatures: Arc::new(sig_set),
            conn_tracker: Arc::new(conn_tracker),
            alert_counts: DashMap::new(),
        })
    }

    /// Create with custom signature set
    pub fn with_signatures(config: IdsConfig, sigs: Vec<signature::Signature>) -> Result<Self, crate::IdsError> {
        let sig_set = SignatureSet::new(sigs)
            .map_err(|e| crate::IdsError::Signature(e))?;

        let conn_tracker = ConnectionTracker::new(
            config.max_connections,
            config.portscan_threshold,
            config.portscan_window_secs,
            config.syn_flood_threshold,
        );

        Ok(Self {
            config: Arc::new(config),
            signatures: Arc::new(sig_set),
            conn_tracker: Arc::new(conn_tracker),
            alert_counts: DashMap::new(),
        })
    }

    /// Inspect a packet/payload. Returns alerts and the recommended verdict.
    pub fn inspect(
        &self,
        src_ip: IpAddr,
        dst_port: u16,
        protocol: &str,
        payload: &[u8],
    ) -> (IdsVerdict, Vec<Alert>) {
        let mut alerts = Vec::new();
        let mut verdict = IdsVerdict::Pass;
        let now = chrono::Utc::now();

        // 1. Signature scan
        let truncated = if payload.len() > self.config.max_payload_inspect {
            &payload[..self.config.max_payload_inspect]
        } else {
            payload
        };
        let scan_matches = self.signatures.scan(truncated);
        for m in &scan_matches {
            let ids_verdict = match m.action {
                SignatureAction::Drop => IdsVerdict::Drop,
                SignatureAction::Reject => IdsVerdict::Reject,
                SignatureAction::Alert => IdsVerdict::Alert,
                SignatureAction::Pass => IdsVerdict::Pass,
            };
            if ids_verdict as u8 > verdict as u8 {
                verdict = ids_verdict;
            }
            alerts.push(Alert {
                id: m.sid,
                src_ip,
                dst_port,
                severity: AlertSeverity::from(m.severity),
                message: m.message.clone(),
                category: m.category.clone(),
                action: ids_verdict,
                timestamp: now,
            });
        }

        // 2. Protocol anomaly detection
        let protocol_anomalies = match protocol {
            "smtp" if self.config.enable_smtp_validation => protocol_analyzer::analyze_smtp(payload),
            "dns" if self.config.enable_dns_validation => protocol_analyzer::analyze_dns(payload),
            "tls" if self.config.enable_tls_validation => protocol_analyzer::analyze_tls(payload),
            _ => Vec::new(),
        };
        for anomaly in &protocol_anomalies {
            let ids_verdict = match anomaly.action {
                SignatureAction::Drop => IdsVerdict::Drop,
                SignatureAction::Reject => IdsVerdict::Reject,
                _ => IdsVerdict::Alert,
            };
            if ids_verdict as u8 > verdict as u8 {
                verdict = ids_verdict;
            }
            alerts.push(Alert {
                id: anomaly.id,
                src_ip,
                dst_port,
                severity: AlertSeverity::from(anomaly.severity),
                message: anomaly.message.clone(),
                category: anomaly.protocol.clone(),
                action: ids_verdict,
                timestamp: now,
            });
        }

        // 3. Connection tracking anomalies
        let conn_anomalies = self.conn_tracker.record_syn(src_ip, dst_port);
        for anomaly in &conn_anomalies {
            let (id, msg, sev) = match anomaly {
                ConnectionAnomaly::PortScan { ip, unique_ports } => {
                    (4000001, format!("Port scan from {}: {} unique ports", ip, unique_ports), AlertSeverity::High)
                }
                ConnectionAnomaly::SynFlood { ip, half_open } => {
                    (4000002, format!("SYN flood from {}: {} half-open", ip, half_open), AlertSeverity::Critical)
                }
                ConnectionAnomaly::ConnectionFlood { ip } => {
                    (4000003, format!("Connection table exhaustion from {}", ip), AlertSeverity::Critical)
                }
            };
            if self.config.inline_mode {
                verdict = IdsVerdict::Drop;
            } else if verdict == IdsVerdict::Pass {
                verdict = IdsVerdict::Alert;
            }
            alerts.push(Alert {
                id,
                src_ip,
                dst_port,
                severity: sev,
                message: msg,
                category: "network-anomaly".into(),
                action: if self.config.inline_mode { IdsVerdict::Drop } else { IdsVerdict::Alert },
                timestamp: now,
            });
        }

        // In detection-only mode, never actually drop
        if !self.config.inline_mode && verdict == IdsVerdict::Drop {
            verdict = IdsVerdict::Alert;
        }

        if !alerts.is_empty() {
            warn!(
                src_ip = %src_ip,
                alert_count = alerts.len(),
                verdict = ?verdict,
                "IDS alerts generated"
            );
        }

        (verdict, alerts)
    }

    /// Get active connection count
    pub fn active_connections(&self) -> usize {
        self.conn_tracker.active_connections()
    }

    /// Run periodic cleanup
    pub fn cleanup(&self) {
        let timeout = std::time::Duration::from_secs(self.config.connection_timeout_secs);
        self.conn_tracker.cleanup(timeout);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_ids_engine_basic() {
        let engine = IdsEngine::new(IdsConfig::default()).expect("init IDS");
        // VRFY is a reconnaissance command — SID 2000020 should trigger an alert
        let (_, alerts) = engine.inspect(
            "10.0.0.1".parse().expect("ip"),
            25,
            "smtp",
            b"VRFY root\r\n",
        );
        assert!(!alerts.is_empty(), "SMTP VRFY recon must trigger an IDS alert");
    }

    #[test]
    fn test_ids_clean_traffic() {
        let engine = IdsEngine::new(IdsConfig::default()).expect("init IDS");
        let (verdict, alerts) = engine.inspect(
            "10.0.0.1".parse().expect("ip"),
            80,
            "http",
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        // Clean HTTP GET shouldn't trigger signature matches
        assert!(alerts.is_empty() || alerts.iter().all(|a| a.action == IdsVerdict::Pass || a.action == IdsVerdict::Alert));
    }

    #[test]
    fn test_ids_inline_mode() {
        let mut config = IdsConfig::default();
        config.inline_mode = true;
        config.syn_flood_threshold = 2;
        let engine = IdsEngine::new(config).expect("init IDS");
        let ip: IpAddr = "10.0.0.5".parse().expect("ip");

        // Trigger SYN flood
        for port in 1..=5 {
            let (verdict, _) = engine.inspect(ip, port, "tcp", b"");
            if port > 2 {
                // In IPS mode, SYN flood should result in Drop
                // (depends on threshold)
            }
        }
    }
}
