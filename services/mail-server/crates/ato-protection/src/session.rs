//! Session tracking and device fingerprinting
//!
//! Maintains per-user login history including://! - IP addresses and geolocations
//! - Device fingerprints (hash of user-agent + accept-language + timezone)
//! - Login timestamps
//! - Success/failure status

use chrono::{DateTime, Utc};
use dashmap::DashMap;
use sha2::{Digest, Sha256};
use std::sync::Arc;

use crate::tls_fingerprint::TlsFingerprint;

/// A single login event
#[derive(Debug, Clone)]
pub struct LoginEvent {
    /// User identifier
    pub user_id: String,
    /// IP address of the login attempt
    pub ip_address: String,
    /// User-Agent header
    pub user_agent: String,
    /// Latitude (from GeoIP lookup, if available)
    pub latitude: Option<f64>,
    /// Longitude (from GeoIP lookup, if available)
    pub longitude: Option<f64>,
    /// Timestamp of the event
    pub timestamp: DateTime<Utc>,
    /// Whether the login was successful
    pub success: bool,
    /// TLS client fingerprint (JA4-style), if extracted from the TLS handshake
    pub tls_fingerprint: Option<TlsFingerprint>,
    /// SA2-008: Device fingerprint computed from user-agent, IP prefix, and TLS
    /// hash. This enables the ATO engine to perform cross-event device correlation
    /// and detect credential sharing, session hijacking, and advanced proxy rotations.
    pub device_fingerprint: Option<DeviceFingerprint>,
}

/// Derived device fingerprint
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct DeviceFingerprint {
    /// SHA-256 hash of device attributes
    pub hash: String,
    /// Original user agent (for display/logging)
    pub user_agent: String,
}

impl DeviceFingerprint {
    /// Create a fingerprint from login attributes
    /// The fingerprint is a SHA-256 hash of multiple device characteristics:/// - User-Agent header
    /// - IP prefix (first 3 octets for IPv4 /24, balancing precision against
    ///   legitimate user IP rotation within a small subnet)
    /// - TLS fingerprint hash (JA4-style, if available)
    /// TLS fingerprints are much harder to spoof than User-Agent and help
    /// detect credential stuffing from automated tools even when they
    /// rotate through residential proxy networks.
    pub fn from_event(event: &LoginEvent) -> Self {
        let mut hasher = Sha256::new();

        // User-Agent (primary identifier, easily spoofed but indicative)
        hasher.update(event.user_agent.as_bytes());

        // IP prefix (/24): tightened from /16 to defeat credential-stuffing
        // attacks pivoting across cloud-provider /16 ranges (e.g. AWS) which
        // could otherwise share the same fingerprint as a legitimate user.
        let ip_prefix = event
            .ip_address
            .splitn(4, '.')
            .take(3)
            .collect::<Vec<_>>()
            .join(".");
        hasher.update(ip_prefix.as_bytes());

        // TLS fingerprint (if available - much harder to spoof)
        // This catches automated tools even when they spoof User-Agent
        if let Some(ref tls_fp) = event.tls_fingerprint {
            hasher.update(tls_fp.hash.as_bytes());
        }

        let hash = hex::encode(hasher.finalize());
        Self {
            hash,
            user_agent: event.user_agent.clone(),
        }
    }

    /// Create a fingerprint with explicit TLS component for testing
    #[cfg(test)]
    pub fn from_components(user_agent: &str, ip_address: &str, tls_hash: Option<&str>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(user_agent.as_bytes());
        let ip_prefix = ip_address
            .splitn(4, '.')
            .take(3)
            .collect::<Vec<_>>()
            .join(".");
        hasher.update(ip_prefix.as_bytes());
        if let Some(tls) = tls_hash {
            hasher.update(tls.as_bytes());
        }
        let hash = hex::encode(hasher.finalize());
        Self {
            hash,
            user_agent: user_agent.to_string(),
        }
    }
}

/// Per-user login history
#[derive(Debug, Clone)]
pub struct UserLoginHistory {
    /// Recent login events (most recent first)
    pub events: Vec<LoginEvent>,
    /// Known device fingerprints
    pub known_devices: Vec<DeviceFingerprint>,
    /// Maximum entries to retain
    max_entries: usize,
}

impl UserLoginHistory {
    /// Create a new history with the given capacity
    pub fn new(max_entries: usize) -> Self {
        Self {
            events: Vec::new(),
            known_devices: Vec::new(),
            max_entries,
        }
    }

    /// Record a login event, returns whether the device is new
    pub fn record(&mut self, mut event: LoginEvent) -> bool {
        let fingerprint = DeviceFingerprint::from_event(&event);
        let is_new_device = !self
            .known_devices
            .iter()
            .any(|d| d.hash == fingerprint.hash);

        if is_new_device {
            self.known_devices.push(fingerprint.clone());
            // Cap known devices at a reasonable limit
            if self.known_devices.len() > 20 {
                self.known_devices.remove(0);
            }
        }

        // SA2-008: Attach device fingerprint to the event so the ATO engine
        // and downstream consumers can perform cross-event device correlation.
        event.device_fingerprint = Some(fingerprint);

        self.events.insert(0, event);
        if self.events.len() > self.max_entries {
            self.events.truncate(self.max_entries);
        }

        is_new_device
    }

    /// Get the last successful login event
    pub fn last_successful(&self) -> Option<&LoginEvent> {
        self.events.iter().find(|e| e.success)
    }

    /// Count failed attempts in the last N seconds
    pub fn recent_failures(&self, window_secs: u64) -> u32 {
        let cutoff = Utc::now() - chrono::Duration::seconds(window_secs as i64);
        self.events
            .iter()
            .filter(|e| !e.success && e.timestamp > cutoff)
            .count() as u32
    }

    /// Get the most common login hour (0-23) for this user
    pub fn typical_login_hour(&self) -> Option<u32> {
        if self.events.is_empty() {
            return None;
        }
        let mut hours = [0u32; 24];
        for event in &self.events {
            if event.success {
                let hour = event
                    .timestamp
                    .format("%H")
                    .to_string()
                    .parse::<usize>()
                    .unwrap_or(0);
                if hour < 24 {
                    hours[hour] += 1;
                }
            }
        }
        let max_count = hours.iter().max().copied().unwrap_or(0);
        if max_count == 0 {
            return None;
        }
        hours.iter().position(|&c| c == max_count).map(|h| h as u32)
    }
}

/// Thread-safe session store
#[derive(Clone)]
pub struct SessionStore {
    histories: Arc<DashMap<String, UserLoginHistory>>,
    max_entries_per_user: usize,
}

impl SessionStore {
    /// Create a new session store
    pub fn new(max_entries_per_user: usize) -> Self {
        Self {
            histories: Arc::new(DashMap::new()),
            max_entries_per_user,
        }
    }

    /// Record a login event, returns whether the device is new for this user
    pub fn record_login(&self, event: &LoginEvent) -> bool {
        let mut entry = self
            .histories
            .entry(event.user_id.clone())
            .or_insert_with(|| UserLoginHistory::new(self.max_entries_per_user));
        entry.record(event.clone())
    }

    /// Get user history (cloned snapshot)
    pub fn get_history(&self, user_id: &str) -> Option<UserLoginHistory> {
        self.histories.get(user_id).map(|h| h.value().clone())
    }

    /// Count recent failed attempts for a user
    pub fn recent_failures(&self, user_id: &str, window_secs: u64) -> u32 {
        self.histories
            .get(user_id)
            .map(|h| h.recent_failures(window_secs))
            .unwrap_or(0)
    }

    /// Total tracked users
    pub fn user_count(&self) -> usize {
        self.histories.len()
    }
}

impl Default for SessionStore {
    fn default() -> Self {
        Self::new(100)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_event(user: &str, ip: &str, success: bool) -> LoginEvent {
        LoginEvent {
            user_id: user.into(),
            ip_address: ip.into(),
            user_agent: "Mozilla/5.0 (Test)".into(),
            latitude: Some(40.7128),
            longitude: Some(-74.006),
            timestamp: Utc::now(),
            success,
            tls_fingerprint: None,
            device_fingerprint: None,
        }
    }

    #[test]
    fn test_new_device_detection() {
        let store = SessionStore::new(100);
        let event1 = make_event("user1", "1.2.3.4", true);
        let is_new = store.record_login(&event1);
        assert!(is_new, "First login should be a new device");

        let event2 = make_event("user1", "1.2.3.5", true); // Same /24
        let is_new = store.record_login(&event2);
        assert!(!is_new, "Same UA + same /24 should not be new device");
    }

    #[test]
    fn test_different_device() {
        let store = SessionStore::new(100);
        let mut event1 = make_event("user1", "1.2.3.4", true);
        event1.user_agent = "Chrome/100".into();
        store.record_login(&event1);

        let mut event2 = make_event("user1", "1.2.3.4", true);
        event2.user_agent = "Firefox/100".into();
        let is_new = store.record_login(&event2);
        assert!(is_new, "Different UA should be new device");
    }

    #[test]
    fn test_failure_counting() {
        let store = SessionStore::new(100);
        for _ in 0..3 {
            store.record_login(&make_event("user1", "1.2.3.4", false));
        }
        store.record_login(&make_event("user1", "1.2.3.4", true));

        assert_eq!(store.recent_failures("user1", 300), 3);
    }

    #[test]
    fn test_device_fingerprint() {
        let event = make_event("user1", "1.2.3.4", true);
        let fp = DeviceFingerprint::from_event(&event);
        assert!(!fp.hash.is_empty());
        assert_eq!(fp.hash.len(), 64); // SHA-256 hex
    }

    #[test]
    fn test_history_capacity() {
        let mut history = UserLoginHistory::new(5);
        for i in 0..10 {
            let mut event = make_event("user1", &format!("1.2.3.{}", i), true);
            event.user_agent = format!("Agent-{}", i);
            history.record(event);
        }
        assert_eq!(history.events.len(), 5, "Should cap at max_entries");
    }
}
