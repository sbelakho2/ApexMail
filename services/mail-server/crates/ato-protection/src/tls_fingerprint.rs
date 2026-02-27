//! TLS Fingerprinting for Account Takeover Protection
//!
//! Implements JA4-style TLS client fingerprinting to detect bot impersonation.
//! TLS fingerprints are much harder to spoof than User-Agent strings because
//! they require implementing the exact TLS stack behavior.
//!
//! ## JA4 Fingerprint Format
//!
//! JA4 = proto_version + cipher_sort + ext_sort + sig_algs
//!
//! Example: `t13d1516h2_002f,0035,009c,009d,1301,1302,1303,c013,c014_0005,000a,000b,000d,0023,4469`
//!
//! ## Design
//!
//! Unlike User-Agent which is a single header, TLS fingerprints are derived from
//! the ClientHello message during handshake. This module provides:
//!
//! 1. **Fingerprint extraction** — Parse TLS ClientHello to extract cipher suites,
//!    extensions, and signature algorithms
//! 2. **Fingerprint storage** — Track known fingerprints per user
//! 3. **Anomaly detection** — Detect sudden changes in TLS stack that indicate
//!    credential theft running on a different system

use sha2::{Digest, Sha256};
use std::collections::{HashSet, VecDeque};

/// A TLS client fingerprint derived from ClientHello
#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct TlsFingerprint {
    /// JA4-style hash
    pub hash: String,
    /// TLS version advertised (e.g., "t13" for TLS 1.3)
    pub tls_version: String,
    /// Cipher suites offered (hex IDs)
    pub cipher_suites: Vec<String>,
    /// Extensions present
    pub extensions: Vec<String>,
    /// Signature algorithms
    pub signature_algorithms: Vec<String>,
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
}

impl TlsFingerprint {
    /// Create a fingerprint from raw ClientHello components
    pub fn from_client_hello(
        tls_version: u16,
        cipher_suites: &[u16],
        extensions: &[u16],
        signature_algorithms: &[u16],
        alpn: &[&str],
    ) -> Self {
        let version_str = match tls_version {
            0x0301 => "t10".to_string(),
            0x0302 => "t11".to_string(),
            0x0303 => "t12".to_string(),
            0x0304 => "t13".to_string(),
            v => format!("t{:02x}", v),
        };

        let mut sorted_ciphers: Vec<String> = cipher_suites
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect();
        sorted_ciphers.sort();

        let mut sorted_exts: Vec<String> = extensions
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect();
        sorted_exts.sort();

        let sig_strs: Vec<String> = signature_algorithms
            .iter()
            .map(|s| format!("{:04x}", s))
            .collect();

        let alpn_strs: Vec<String> = alpn.iter().map(|a| a.to_string()).collect();

        let raw = format!(
            "{}_{}_{}_{}_{}",
            version_str,
            sorted_ciphers.len(),
            sorted_exts.len(),
            sorted_ciphers.join(","),
            sorted_exts.join(",")
        );

        // Hash for compact storage
        let mut hasher = Sha256::new();
        hasher.update(raw.as_bytes());
        let hash = hex::encode(&hasher.finalize()[..12]); // First 12 bytes

        Self {
            hash,
            tls_version: version_str,
            cipher_suites: sorted_ciphers,
            extensions: sorted_exts,
            signature_algorithms: sig_strs,
            alpn_protocols: alpn_strs,
        }
    }

    /// Create from a pre-computed JA4 string (for testing)
    pub fn from_ja4_string(ja4: &str) -> Self {
        let hash = {
            let mut hasher = Sha256::new();
            hasher.update(ja4.as_bytes());
            hex::encode(&hasher.finalize()[..12])
        };

        Self {
            hash,
            tls_version: "t12".to_string(),
            cipher_suites: Vec::new(),
            extensions: Vec::new(),
            signature_algorithms: Vec::new(),
            alpn_protocols: Vec::new(),
        }
    }

    /// Check if this fingerprint is consistent with a "modern browser"
    pub fn is_modern_browser(&self) -> bool {
        // Modern browsers support TLS 1.3 and offer many cipher suites
        let is_tls13 = self.tls_version == "t13";
        let has_enough_ciphers = self.cipher_suites.len() >= 10;
        let has_sni = self.extensions.iter().any(|e| e == "0000"); // SNI extension

        is_tls13 && has_enough_ciphers && has_sni
    }

    /// Check if this looks like a simple bot/script
    pub fn looks_like_bot(&self) -> bool {
        // Bots often have minimal cipher suites or old TLS versions
        let old_tls = self.tls_version == "t10" || self.tls_version == "t11";
        let few_ciphers = self.cipher_suites.len() < 5;
        let no_modern_extensions = self.extensions.len() < 3;

        old_tls || (few_ciphers && no_modern_extensions)
    }
}

/// TLS fingerprint tracking for a user account
#[derive(Debug, Clone)]
pub struct UserTlsHistory {
    /// Insertion-ordered ring buffer of fingerprint hashes (for deterministic FIFO eviction)
    insertion_order: VecDeque<String>,
    /// Fast O(1) membership test
    lookup_set: HashSet<String>,
    /// Most recent fingerprint
    pub last_fingerprint: Option<TlsFingerprint>,
    /// Maximum fingerprints to track
    max_fingerprints: usize,
}

impl UserTlsHistory {
    /// Create a new TLS history tracker
    pub fn new(max_fingerprints: usize) -> Self {
        Self {
            insertion_order: VecDeque::new(),
            lookup_set: HashSet::new(),
            last_fingerprint: None,
            max_fingerprints,
        }
    }

    /// Record a TLS fingerprint, returns true if this is a new fingerprint
    pub fn record(&mut self, fp: &TlsFingerprint) -> bool {
        let is_new = !self.lookup_set.contains(&fp.hash);

        if is_new {
            // Evict the OLDEST entry first (deterministic FIFO, not random HashSet::iter()::next())
            if self.insertion_order.len() >= self.max_fingerprints {
                if let Some(oldest) = self.insertion_order.pop_front() {
                    self.lookup_set.remove(&oldest);
                }
            }
            self.lookup_set.insert(fp.hash.clone());
            self.insertion_order.push_back(fp.hash.clone());
        }

        self.last_fingerprint = Some(fp.clone());
        is_new
    }

    /// Check if a fingerprint is known
    pub fn is_known(&self, fp: &TlsFingerprint) -> bool {
        self.lookup_set.contains(&fp.hash)
    }

    /// Number of known fingerprints stored
    pub fn len(&self) -> usize {
        self.lookup_set.len()
    }

    /// True if no fingerprints recorded yet
    pub fn is_empty(&self) -> bool {
        self.lookup_set.is_empty()
    }

    /// Calculate risk score for a new fingerprint
    pub fn fingerprint_risk(&self, fp: &TlsFingerprint) -> f64 {
        let mut risk: f64 = 0.0;

        // New fingerprint adds risk
        if !self.is_known(fp) {
            risk += 2.0;

            // Brand new user has lower risk for first fingerprint
            if self.is_empty() {
                risk = 0.5; // Expected for first login
            }
        }

        // Bot-like fingerprints are high risk
        if fp.looks_like_bot() {
            risk += 3.0;
        }

        // Check for suspicious fingerprint changes
        if let Some(last) = &self.last_fingerprint {
            // Jumping from modern browser to old TLS is suspicious
            if last.is_modern_browser() && fp.looks_like_bot() {
                risk += 4.0;
            }
        }

        risk.min(10.0)
    }
}

/// Enhanced device fingerprint that includes TLS
#[derive(Debug, Clone)]
pub struct EnhancedDeviceFingerprint {
    /// SHA-256 hash of combined attributes
    pub hash: String,
    /// User-Agent
    pub user_agent: String,
    /// IP prefix (/24 for IPv4)
    pub ip_prefix: String,
    /// TLS fingerprint (if available)
    pub tls_fingerprint: Option<TlsFingerprint>,
}

impl EnhancedDeviceFingerprint {
    /// Create a fingerprint from device attributes
    pub fn new(
        user_agent: &str,
        ip_address: &str,
        tls_fingerprint: Option<TlsFingerprint>,
    ) -> Self {
        let mut hasher = Sha256::new();
        hasher.update(user_agent.as_bytes());

        // IP prefix (first 3 octets for IPv4)
        let ip_prefix: String = ip_address
            .splitn(4, '.')
            .take(3)
            .collect::<Vec<_>>()
            .join(".");
        hasher.update(ip_prefix.as_bytes());

        // Include TLS fingerprint if available
        if let Some(ref tls) = tls_fingerprint {
            hasher.update(tls.hash.as_bytes());
        }

        let hash = hex::encode(hasher.finalize());

        Self {
            hash,
            user_agent: user_agent.to_string(),
            ip_prefix,
            tls_fingerprint,
        }
    }

    /// Check if the fingerprint includes TLS information
    pub fn has_tls(&self) -> bool {
        self.tls_fingerprint.is_some()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_tls_fingerprint_creation() {
        let fp = TlsFingerprint::from_client_hello(
            0x0304, // TLS 1.3
            &[0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0x009f, 0x009e, 0x0033, 0x0067, 0x0039],
            &[0x0000, 0x000b, 0x000d, 0x0017, 0x0023],
            &[0x0401, 0x0501, 0x0601],
            &["h2", "http/1.1"],
        );

        assert_eq!(fp.tls_version, "t13");
        assert_eq!(fp.cipher_suites.len(), 10);
        assert_eq!(fp.extensions.len(), 5);
        assert!(!fp.hash.is_empty());
    }

    #[test]
    fn test_modern_browser_detection() {
        let modern = TlsFingerprint::from_client_hello(
            0x0304,
            &[0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0x009f, 0x009e, 0x0033, 0x0067, 0x0039, 0x002f],
            &[0x0000, 0x000b, 0x000d, 0x0017, 0x0023],
            &[0x0401],
            &["h2"],
        );
        assert!(modern.is_modern_browser());
        assert!(!modern.looks_like_bot());
    }

    #[test]
    fn test_bot_detection() {
        let bot = TlsFingerprint::from_client_hello(
            0x0301, // TLS 1.0 - old!
            &[0x002f, 0x0035], // Only 2 ciphers
            &[], // No extensions
            &[],
            &[],
        );
        assert!(bot.looks_like_bot());
        assert!(!bot.is_modern_browser());
    }

    #[test]
    fn test_user_tls_history() {
        let mut history = UserTlsHistory::new(10);

        let fp1 = TlsFingerprint::from_ja4_string("chrome_fingerprint_abc");
        let fp2 = TlsFingerprint::from_ja4_string("chrome_fingerprint_xyz");

        // First fingerprint is new
        assert!(history.record(&fp1));
        assert!(history.is_known(&fp1));

        // Same fingerprint is not new
        assert!(!history.record(&fp1));

        // Different fingerprint is new
        assert!(history.record(&fp2));
    }

    #[test]
    fn test_fingerprint_risk() {
        let mut history = UserTlsHistory::new(10);

        // First login - low risk
        let normal = TlsFingerprint::from_client_hello(
            0x0304,
            &[0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b, 0x009f, 0x009e, 0x0033, 0x0067, 0x0039],
            &[0x0000, 0x000b],
            &[],
            &[],
        );
        let first_risk = history.fingerprint_risk(&normal);
        assert!(first_risk < 1.0); // Low risk for first login
        history.record(&normal);

        // Same fingerprint again - no risk
        let same_risk = history.fingerprint_risk(&normal);
        assert_eq!(same_risk, 0.0);

        // Bot fingerprint - high risk
        let bot = TlsFingerprint::from_client_hello(
            0x0301,
            &[0x002f],
            &[],
            &[],
            &[],
        );
        let bot_risk = history.fingerprint_risk(&bot);
        assert!(bot_risk >= 5.0); // High risk for bot appearing after browser
    }

    #[test]
    fn test_enhanced_device_fingerprint() {
        let tls = TlsFingerprint::from_ja4_string("test_tls");
        let device = EnhancedDeviceFingerprint::new(
            "Mozilla/5.0 Chrome/120",
            "192.168.1.100",
            Some(tls),
        );

        assert!(device.has_tls());
        assert_eq!(device.ip_prefix, "192.168.1");
        assert!(!device.hash.is_empty());
    }

    #[test]
    fn test_device_fingerprint_without_tls() {
        let device = EnhancedDeviceFingerprint::new(
            "Mozilla/5.0 Chrome/120",
            "10.0.0.50",
            None,
        );

        assert!(!device.has_tls());
    }
}
