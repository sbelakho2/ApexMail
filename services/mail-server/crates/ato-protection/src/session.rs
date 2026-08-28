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
///
/// Identity is `(hash, user_agent)`; `last_seen` records when the device
/// was last observed and is deliberately excluded from equality/hashing so
/// refreshing it never changes the device's identity.
#[derive(Debug, Clone)]
pub struct DeviceFingerprint {
    /// SHA-256 hash of device attributes
    pub hash: String,
    /// Original user agent (for display/logging)
    pub user_agent: String,
    /// Last time this device was observed (for LRU eviction).
    pub last_seen: DateTime<Utc>,
}

impl PartialEq for DeviceFingerprint {
    fn eq(&self, other: &Self) -> bool {
        self.hash == other.hash && self.user_agent == other.user_agent
    }
}

impl Eq for DeviceFingerprint {}

impl std::hash::Hash for DeviceFingerprint {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.hash.hash(state);
        self.user_agent.hash(state);
    }
}

/// Maximum number of known devices retained per user. Eviction is
/// least-recently-seen: a device's `last_seen` is refreshed every time it
/// appears, so an attacker rotating user-agents can only evict devices
/// that have not been seen lately — never the victim's active device
/// (which used to be the case with FIFO eviction).
const MAX_KNOWN_DEVICES: usize = 20;

/// Extract the network prefix used for device correlation.
/// IPv4 → first three octets (/24); IPv6 → first four hextets (/64, the
/// standard single-subscriber allocation). The old implementation blindly
/// split on dots, which mangled IPv6 addresses into a garbage prefix.
fn ip_network_prefix(ip: &str) -> String {
    let trimmed = ip.trim();
    if let Ok(v6) = trimmed.parse::<std::net::Ipv6Addr>() {
        let seg = v6.segments();
        return format!("{:x}:{:x}:{:x}:{:x}::/64", seg[0], seg[1], seg[2], seg[3]);
    }
    if trimmed.contains(':') {
        // IPv6-ish but unparseable — fall back to the whole address.
        return trimmed.to_string();
    }
    // IPv4 /24
    trimmed.splitn(4, '.').take(3).collect::<Vec<_>>().join(".")
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
        Self::from_event_with_pepper(event, &[])
    }

    /// Create a fingerprint salted with a server-side pepper.
    /// Without a pepper, stored fingerprint hashes are vulnerable to
    /// offline dictionary attacks over (UA, IP prefix, TLS hash) tuples —
    /// the pepper must be a per-deployment secret.
    pub fn from_event_with_pepper(event: &LoginEvent, pepper: &[u8]) -> Self {
        let mut hasher = Sha256::new();

        // User-Agent (primary identifier, easily spoofed but indicative)
        hasher.update(event.user_agent.as_bytes());

        // IP prefix:IPv4 /24 (tightened from /16 to defeat credential
        // stuffing pivoting across cloud /16 ranges) or IPv6 /64 — the old
        // code blindly dot-split IPv6 addresses into a garbage prefix.
        let ip_prefix = ip_network_prefix(&event.ip_address);
        hasher.update(ip_prefix.as_bytes());

        // TLS fingerprint (if available - much harder to spoof)
        // This catches automated tools even when they spoof User-Agent
        if let Some(ref tls_fp) = event.tls_fingerprint {
            hasher.update(tls_fp.hash.as_bytes());
        }

        // Server-side pepper
        hasher.update(pepper);

        let hash = hex::encode(hasher.finalize());
        Self {
            hash,
            user_agent: event.user_agent.clone(),
            // The sighting time is the event's timestamp (not wall-clock)
            // so replayed/back-dated events order deterministically.
            last_seen: event.timestamp,
        }
    }

    /// Create a fingerprint with explicit TLS component for testing
    #[cfg(test)]
    pub fn from_components(user_agent: &str, ip_address: &str, tls_hash: Option<&str>) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(user_agent.as_bytes());
        hasher.update(ip_network_prefix(ip_address).as_bytes());
        if let Some(tls) = tls_hash {
            hasher.update(tls.as_bytes());
        }
        let hash = hex::encode(hasher.finalize());
        Self {
            hash,
            user_agent: user_agent.to_string(),
            last_seen: Utc::now(),
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
    pub fn record(&mut self, event: LoginEvent) -> bool {
        self.record_with_pepper(event, &[])
    }

    /// Record a login event whose device fingerprint is salted with a
    /// server-side pepper.
    pub fn record_with_pepper(&mut self, mut event: LoginEvent, pepper: &[u8]) -> bool {
        let fingerprint = DeviceFingerprint::from_event_with_pepper(&event, pepper);

        if let Some(known) = self
            .known_devices
            .iter_mut()
            .find(|d| d.hash == fingerprint.hash)
        {
            // Known device: refresh its last-seen time so LRU eviction
            // tracks activity, not first insertion.
            known.last_seen = fingerprint.last_seen;
            let is_new_device = false;

            // SA2-008: Attach device fingerprint to the event so the ATO engine
            // and downstream consumers can perform cross-event device correlation.
            event.device_fingerprint = Some(fingerprint);

            self.events.insert(0, event);
            if self.events.len() > self.max_entries {
                self.events.truncate(self.max_entries);
            }

            return is_new_device;
        }

        self.known_devices.push(fingerprint.clone());
        if self.known_devices.len() > MAX_KNOWN_DEVICES {
            // Evict the least-recently-seen device. FIFO eviction let an
            // attacker evict the victim's device purely by rotating
            // user-agents, locking the victim into permanent MFA prompts.
            if let Some(lru_idx) = self
                .known_devices
                .iter()
                .enumerate()
                .min_by_key(|(_, d)| d.last_seen)
                .map(|(i, _)| i)
            {
                self.known_devices.remove(lru_idx);
            }
        }

        // SA2-008: Attach device fingerprint to the event so the ATO engine
        // and downstream consumers can perform cross-event device correlation.
        event.device_fingerprint = Some(fingerprint);

        self.events.insert(0, event);
        if self.events.len() > self.max_entries {
            self.events.truncate(self.max_entries);
        }

        true
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
    /// Server-side pepper mixed into every device-fingerprint hash.
    pepper: Arc<Vec<u8>>,
}

impl SessionStore {
    /// Create a new session store (no pepper).
    pub fn new(max_entries_per_user: usize) -> Self {
        Self {
            histories: Arc::new(DashMap::new()),
            max_entries_per_user,
            pepper: Arc::new(Vec::new()),
        }
    }

    /// Create a session store that salts device fingerprints with a
    /// server-side pepper (see `AtoConfig::fingerprint_pepper`).
    pub fn with_pepper(max_entries_per_user: usize, pepper: Option<&str>) -> Self {
        Self {
            histories: Arc::new(DashMap::new()),
            max_entries_per_user,
            pepper: Arc::new(pepper.map(|p| p.as_bytes().to_vec()).unwrap_or_default()),
        }
    }

    /// Record a login event, returns whether the device is new for this user
    pub fn record_login(&self, event: &LoginEvent) -> bool {
        let mut entry = self
            .histories
            .entry(event.user_id.clone())
            .or_insert_with(|| UserLoginHistory::new(self.max_entries_per_user));
        entry.record_with_pepper(event.clone(), &self.pepper)
    }

    /// Atomically record a login event AND count failed attempts in the
    /// window **including this event**.
    /// Count+record run under a single DashMap shard lock, closing the
    /// TOCTOU race where concurrent evaluations each observe "max-1"
    /// failures and all slip past the lockout threshold.
    /// Returns `(is_new_device, failures_including_this_event)`.
    pub fn record_login_counting_failures(
        &self,
        event: &LoginEvent,
        window_secs: u64,
    ) -> (bool, u32) {
        let mut entry = self
            .histories
            .entry(event.user_id.clone())
            .or_insert_with(|| UserLoginHistory::new(self.max_entries_per_user));
        let history = entry.value_mut();
        let prior_failures = history.recent_failures(window_secs);
        let is_new = history.record_with_pepper(event.clone(), &self.pepper);
        let failures = prior_failures + u32::from(!event.success);
        (is_new, failures)
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

    #[test]
    fn test_ipv6_same_slash64_not_new_device() {
        let store = SessionStore::new(100);
        let e1 = make_event("u6", "2001:db8:1:2::a", true);
        assert!(store.record_login(&e1), "first login is new");
        // Same /64, different host bits → same device fingerprint.
        let mut e2 = make_event("u6", "2001:db8:1:2::ffff", true);
        e2.user_agent = e1.user_agent.clone();
        assert!(
            !store.record_login(&e2),
            "same UA + same IPv6 /64 must not be a new device"
        );
        // Different /64 → new device.
        let mut e3 = make_event("u6", "2001:db8:1:3::1", true);
        e3.user_agent = e1.user_agent.clone();
        assert!(
            store.record_login(&e3),
            "different IPv6 /64 is a new device"
        );
    }

    #[test]
    fn test_fingerprint_pepper_changes_hash() {
        let event = make_event("u9", "1.2.3.4", true);
        let plain = DeviceFingerprint::from_event(&event);
        let peppered = DeviceFingerprint::from_event_with_pepper(&event, b"deployment-secret");
        assert_ne!(
            plain.hash, peppered.hash,
            "pepper must change the fingerprint hash (offline-dictionary protection)"
        );
        // Deterministic with the same pepper.
        let again = DeviceFingerprint::from_event_with_pepper(&event, b"deployment-secret");
        assert_eq!(peppered.hash, again.hash);
    }

    #[test]
    fn test_known_devices_lru_not_fifo() {
        // Fail-first: known_devices was a FIFO — an attacker rotating 20
        // user-agents evicted the victim's long-lived device, and every
        // subsequent legitimate login looked "new" (permanent MFA
        // prompts). Eviction must be least-recently-seen, with the
        // last-seen time refreshed whenever a device is observed.
        let mut history = UserLoginHistory::new(100);
        let base = Utc::now() - chrono::Duration::hours(3);
        let event = |ua: &str, minutes: i64| LoginEvent {
            user_id: "lru-user".into(),
            ip_address: "9.9.9.9".into(),
            user_agent: ua.into(),
            latitude: None,
            longitude: None,
            timestamp: base + chrono::Duration::minutes(minutes),
            success: true,
            tls_fingerprint: None,
            device_fingerprint: None,
        };

        // Victim's device (oldest insertion, but seen again later).
        history.record(event("victim-ua", 0));
        // 10 attacker UA rotations.
        for i in 0..10 {
            history.record(event(&format!("rot-a-{i}"), 5 + i));
        }
        // Victim's device is seen again — refresh its last-seen time.
        history.record(event("victim-ua", 30));
        // 10 more rotations: 21 distinct devices, one must be evicted.
        for i in 0..10 {
            history.record(event(&format!("rot-b-{i}"), 40 + i));
        }

        let is_new = history.record(event("victim-ua", 90));
        assert!(
            !is_new,
            "recently-seen victim device must not be evicted by UA rotation"
        );
    }

    #[test]
    fn test_record_login_counting_failures_includes_current() {
        let store = SessionStore::new(100);
        let mut count = 0;
        for _ in 0..5 {
            let (_, failures) =
                store.record_login_counting_failures(&make_event("u10", "1.2.3.4", false), 300);
            count = failures;
        }
        assert_eq!(
            count, 5,
            "5th failing login must count 5 failures incl. itself"
        );
        // A successful login does not add to the count.
        let (_, failures) =
            store.record_login_counting_failures(&make_event("u10", "1.2.3.4", true), 300);
        assert_eq!(failures, 5);
    }
}
