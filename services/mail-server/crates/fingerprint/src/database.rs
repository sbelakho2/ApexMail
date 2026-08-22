//! Fingerprint database for storage and lookup
//!
//! Provides storage for fingerprints with classification data,
//! allowing threat intelligence based on observed fingerprints.

use dashmap::DashMap;
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use std::time::{Duration, Instant};

use crate::{Http2Fingerprint, Ja4Fingerprint};

/// Level of suspicion for a fingerprint
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SuspicionLevel {
    /// Normal, trusted fingerprint
    Normal,
    /// Unknown fingerprint
    Unknown,
    /// Suspicious characteristics
    Suspicious,
    /// Known malicious fingerprint
    Malicious,
}

/// Client identity based on fingerprint
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum ClientIdentity {
    /// Known browser
    Browser {
        /// Browser name
        name: String,
        /// Browser version
        version: String,
    },
    /// Known bot
    Bot {
        /// Bot name
        name: String,
    },
    /// HTTP client library
    Library {
        /// Library name
        name: String,
        /// Language
        language: String,
    },
    /// Unknown client
    Unknown,
}

/// Combined fingerprint for matching
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct CombinedFingerprint {
    /// JA4 TLS fingerprint
    pub ja4: Option<String>,
    /// HTTP/2 fingerprint
    pub http2: Option<String>,
}

impl CombinedFingerprint {
    /// Create from components
    pub fn new(ja4: Option<&Ja4Fingerprint>, http2: Option<&Http2Fingerprint>) -> Self {
        Self {
            ja4: ja4.map(|f| f.fingerprint.clone()),
            http2: http2.map(|f| f.fingerprint.clone()),
        }
    }

    /// Create JA4-only fingerprint
    pub fn ja4_only(ja4: &Ja4Fingerprint) -> Self {
        Self {
            ja4: Some(ja4.fingerprint.clone()),
            http2: None,
        }
    }

    /// Create HTTP/2-only fingerprint
    pub fn http2_only(http2: &Http2Fingerprint) -> Self {
        Self {
            ja4: None,
            http2: Some(http2.fingerprint.clone()),
        }
    }
}

/// Classification of a fingerprint
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FingerprintClassification {
    /// Suspicion level
    pub suspicion: SuspicionLevel,
    /// Client identity if known
    pub identity: Option<ClientIdentity>,
    /// Description
    pub description: String,
    /// Known attack patterns this matches
    pub attack_patterns: Vec<String>,
    /// Confidence (0.0 - 1.0)
    pub confidence: f64,
}

impl FingerprintClassification {
    /// Create benign classification
    pub fn benign(identity: ClientIdentity, description: &str) -> Self {
        Self {
            suspicion: SuspicionLevel::Normal,
            identity: Some(identity),
            description: description.to_string(),
            attack_patterns: vec![],
            confidence: 0.9,
        }
    }

    /// Create suspicious classification
    pub fn suspicious(description: &str, patterns: Vec<String>) -> Self {
        Self {
            suspicion: SuspicionLevel::Suspicious,
            identity: None,
            description: description.to_string(),
            attack_patterns: patterns,
            confidence: 0.7,
        }
    }

    /// Create malicious classification
    pub fn malicious(description: &str, patterns: Vec<String>) -> Self {
        Self {
            suspicion: SuspicionLevel::Malicious,
            identity: None,
            description: description.to_string(),
            attack_patterns: patterns,
            confidence: 0.95,
        }
    }
}

/// Observed fingerprint with metadata
#[derive(Debug, Clone)]
pub struct ObservedFingerprint {
    /// The fingerprint itself
    pub fingerprint: CombinedFingerprint,
    /// First seen timestamp
    pub first_seen: Instant,
    /// Last seen timestamp
    pub last_seen: Instant,
    /// Request count
    pub request_count: u64,
    /// Associated IP addresses (sample)
    pub sample_ips: Vec<std::net::IpAddr>,
    /// Classification
    pub classification: Option<FingerprintClassification>,
}

impl ObservedFingerprint {
    /// Create new observation
    pub fn new(fingerprint: CombinedFingerprint) -> Self {
        let now = Instant::now();
        Self {
            fingerprint,
            first_seen: now,
            last_seen: now,
            request_count: 1,
            sample_ips: vec![],
            classification: None,
        }
    }

    /// Update with new observation
    pub fn observe(&mut self, ip: Option<std::net::IpAddr>) {
        self.last_seen = Instant::now();
        self.request_count += 1;

        if let Some(ip) = ip {
            if self.sample_ips.len() < 100 && !self.sample_ips.contains(&ip) {
                self.sample_ips.push(ip);
            }
        }
    }
}

/// Fingerprint database
pub struct FingerprintDb {
    /// Known fingerprint classifications
    known: DashMap<String, FingerprintClassification>,
    /// Observed fingerprints
    observed: DashMap<String, ObservedFingerprint>,
    /// Configuration
    config: FingerprintDbConfig,
}

/// Database configuration
#[derive(Debug, Clone)]
pub struct FingerprintDbConfig {
    /// Maximum observed fingerprints to track
    pub max_observed: usize,
    /// Time to live for observations
    pub observation_ttl: Duration,
    /// Minimum requests before classification
    pub min_requests_for_classification: u64,
}

impl Default for FingerprintDbConfig {
    fn default() -> Self {
        Self {
            max_observed: 100_000,
            observation_ttl: Duration::from_secs(3600),
            min_requests_for_classification: 10,
        }
    }
}

impl FingerprintDb {
    /// Create new fingerprint database
    pub fn new(config: FingerprintDbConfig) -> Self {
        let db = Self {
            known: DashMap::new(),
            observed: DashMap::new(),
            config,
        };

        // Load known fingerprints
        db.load_known_fingerprints();

        db
    }
}

impl Default for FingerprintDb {
    fn default() -> Self {
        Self::new(FingerprintDbConfig::default())
    }
}

impl FingerprintDb {
    /// Create as Arc for sharing
    pub fn new_shared(config: FingerprintDbConfig) -> Arc<Self> {
        Arc::new(Self::new(config))
    }

    /// Load known fingerprints (browser patterns, known bots, etc.)
    ///
    /// Every seed key is a JA4_a component in this crate's own format
    /// (`protocol + sni + cipher_count + ext_count + alpn`, see
    /// [`crate::ja4::is_valid_ja4_a`]) — the previous hardcoded keys had
    /// wrong lengths/alphabets ("t130613h2", "d100200", …) and could never
    /// match a fingerprint produced by [`crate::ja4::Ja4Fingerprint::compute`].
    /// A unit test validates the entire seed table against the crate's own
    /// parser and validator.
    fn load_known_fingerprints(&self) {
        // Chrome (TLS 1.3, SNI domain, ~18 cipher suites, ~17 extensions, h2)
        self.known.insert(
            "td1817h2".to_string(),
            FingerprintClassification::benign(
                ClientIdentity::Browser {
                    name: "Chrome".to_string(),
                    version: "120+".to_string(),
                },
                "Google Chrome browser",
            ),
        );

        // Firefox (TLS 1.3, SNI domain, ~15 cipher suites, ~11 extensions, h2)
        self.known.insert(
            "td1511h2".to_string(),
            FingerprintClassification::benign(
                ClientIdentity::Browser {
                    name: "Firefox".to_string(),
                    version: "120+".to_string(),
                },
                "Mozilla Firefox browser",
            ),
        );

        // Safari (TLS 1.3, SNI domain, ~16 cipher suites, ~14 extensions, h2)
        self.known.insert(
            "td1614h2".to_string(),
            FingerprintClassification::benign(
                ClientIdentity::Browser {
                    name: "Safari".to_string(),
                    version: "17+".to_string(),
                },
                "Apple Safari browser",
            ),
        );

        // Python requests (TLS 1.2 → 'd', SNI domain, ~9 cipher suites,
        // ~8 extensions, no ALPN → "00")
        self.known.insert(
            "dd090800".to_string(),
            FingerprintClassification::suspicious(
                "Python requests library",
                vec!["automation".to_string()],
            ),
        );

        // Known malicious fingerprint pattern:minimal attack-tool stack —
        // TLS 1.2 ('d'), IP-literal SNI ('i', typical of attack tools that
        // connect by address), 2 cipher suites, 2 extensions, no ALPN.
        // ('_' as the SNI marker is not usable in seed keys:it collides
        // with the JA4 field separator and would never round-trip.)
        self.known.insert(
            "di020200".to_string(),
            FingerprintClassification::malicious(
                "Known attack tool fingerprint",
                vec!["credential_stuffing".to_string(), "bruteforce".to_string()],
            ),
        );
    }

    /// Look up a fingerprint
    pub fn lookup(&self, fingerprint: &CombinedFingerprint) -> Option<FingerprintClassification> {
        if let Some(ja4) = &fingerprint.ja4 {
            if let Some(classification) = self.lookup_known_value(ja4) {
                return Some(classification);
            }

            let ja4_a = ja4.split('_').next().unwrap_or("");
            if let Some(classification) = self.lookup_known_value(ja4_a) {
                return Some(classification);
            }
        }

        if let Some(http2) = &fingerprint.http2 {
            if let Some(classification) = self.lookup_known_value(http2) {
                return Some(classification);
            }

            let settings_fingerprint = http2.split('|').next().unwrap_or("");
            if let Some(classification) = self.lookup_known_value(settings_fingerprint) {
                return Some(classification);
            }
        }

        None
    }

    fn lookup_known_value(&self, value: &str) -> Option<FingerprintClassification> {
        self.known
            .get(value)
            .map(|classification| classification.clone())
    }

    /// Record an observation
    pub fn observe(&self, fingerprint: CombinedFingerprint, ip: Option<std::net::IpAddr>) {
        let key = self.fingerprint_key(&fingerprint);

        self.observed
            .entry(key)
            .and_modify(|obs| obs.observe(ip))
            .or_insert_with(|| {
                let mut obs = ObservedFingerprint::new(fingerprint.clone());
                if let Some(ip) = ip {
                    obs.sample_ips.push(ip);
                }
                obs.classification = self.lookup(&fingerprint);
                obs
            });

        if self.observed.len() > self.config.max_observed {
            self.cleanup();
        }
    }

    /// Get observation for a fingerprint
    pub fn get_observation(
        &self,
        fingerprint: &CombinedFingerprint,
    ) -> Option<ObservedFingerprint> {
        let key = self.fingerprint_key(fingerprint);
        self.observed.get(&key).map(|r| r.clone())
    }

    /// Classify a fingerprint based on observations
    pub fn classify(&self, fingerprint: &CombinedFingerprint) -> SuspicionLevel {
        // Check known fingerprints first
        if let Some(classification) = self.lookup(fingerprint) {
            return classification.suspicion;
        }

        // Check observations
        if let Some(obs) = self.get_observation(fingerprint) {
            if obs.request_count < self.config.min_requests_for_classification {
                return SuspicionLevel::Unknown;
            }

            if let Some(classification) = obs.classification {
                return classification.suspicion;
            }

            // High request count from many IPs might indicate botnet
            if obs.request_count > 10000 && obs.sample_ips.len() > 50 {
                return SuspicionLevel::Suspicious;
            }

            // Very new fingerprint with high activity
            let age = obs.first_seen.elapsed();
            if age < Duration::from_secs(60) && obs.request_count > 100 {
                return SuspicionLevel::Suspicious;
            }
        }

        SuspicionLevel::Unknown
    }

    /// Add a known fingerprint classification
    pub fn add_classification(
        &self,
        fingerprint_prefix: &str,
        classification: FingerprintClassification,
    ) {
        self.known
            .insert(fingerprint_prefix.to_string(), classification);
    }

    /// Clean up old observations
    pub fn cleanup(&self) {
        let now = Instant::now();
        let cutoff = now.checked_sub(self.config.observation_ttl).unwrap_or(now);

        self.observed.retain(|_, obs| obs.last_seen > cutoff);

        // If still over limit, remove oldest
        if self.observed.len() > self.config.max_observed {
            // Find oldest entries and remove them
            let mut entries: Vec<_> = self
                .observed
                .iter()
                .map(|r| (r.key().clone(), r.value().last_seen))
                .collect();

            entries.sort_by_key(|(_, seen)| *seen);

            let to_remove = entries.len() - self.config.max_observed;
            for (key, _) in entries.into_iter().take(to_remove) {
                self.observed.remove(&key);
            }
        }
    }

    /// Get statistics
    pub fn stats(&self) -> FingerprintDbStats {
        let mut total_requests = 0u64;
        let mut unique_ips = std::collections::HashSet::new();

        for entry in self.observed.iter() {
            total_requests += entry.request_count;
            for ip in &entry.sample_ips {
                unique_ips.insert(*ip);
            }
        }

        FingerprintDbStats {
            known_fingerprints: self.known.len(),
            observed_fingerprints: self.observed.len(),
            total_requests,
            unique_ips: unique_ips.len(),
        }
    }

    /// Generate fingerprint key for storage
    fn fingerprint_key(&self, fingerprint: &CombinedFingerprint) -> String {
        let ja4 = fingerprint.ja4.as_deref().unwrap_or("_");
        let http2 = fingerprint.http2.as_deref().unwrap_or("_");
        format!("{}|{}", ja4, http2)
    }
}

/// Database statistics
#[derive(Debug, Clone)]
pub struct FingerprintDbStats {
    /// Number of known fingerprint patterns
    pub known_fingerprints: usize,
    /// Number of observed fingerprints
    pub observed_fingerprints: usize,
    /// Total requests processed
    pub total_requests: u64,
    /// Unique IPs observed
    pub unique_ips: usize,
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::IpAddr;

    #[test]
    fn test_fingerprint_db_creation() {
        let db = FingerprintDb::default();
        assert!(!db.known.is_empty());
    }

    #[test]
    fn test_observation() {
        let db = FingerprintDb::default();

        let fp = CombinedFingerprint {
            ja4: Some("t130613h2_abc_def".to_string()),
            http2: None,
        };

        let ip: IpAddr = "192.168.1.1".parse().expect("hardcoded IP");

        db.observe(fp.clone(), Some(ip));
        db.observe(fp.clone(), Some(ip));
        db.observe(fp.clone(), Some(ip));

        let obs = db.get_observation(&fp).expect("observation should exist");
        assert_eq!(obs.request_count, 3);
        assert_eq!(obs.sample_ips.len(), 1);
    }

    #[test]
    fn test_classification() {
        let db = FingerprintDb::default();

        // Add malicious fingerprint
        db.add_classification(
            "t010100",
            FingerprintClassification::malicious(
                "Test malicious fingerprint",
                vec!["test_attack".to_string()],
            ),
        );

        let fp = CombinedFingerprint {
            ja4: Some("t010100_xyz_abc".to_string()),
            http2: None,
        };

        let suspicion = db.classify(&fp);
        assert_eq!(suspicion, SuspicionLevel::Malicious);
    }

    #[test]
    fn test_stats() {
        let db = FingerprintDb::default();

        let fp = CombinedFingerprint {
            ja4: Some("test_fp".to_string()),
            http2: None,
        };

        db.observe(fp, Some("1.2.3.4".parse().expect("hardcoded IP")));

        let stats = db.stats();
        assert_eq!(stats.observed_fingerprints, 1);
        assert_eq!(stats.total_requests, 1);
    }

    #[test]
    fn lookup_matches_http2_only_fingerprints() {
        let db = FingerprintDb::default();
        db.add_classification(
            "settings123",
            FingerprintClassification::suspicious(
                "HTTP/2 scanner settings",
                vec!["automation".to_string()],
            ),
        );

        let fp = CombinedFingerprint {
            ja4: None,
            http2: Some("settings123|frames456|none".to_string()),
        };

        assert_eq!(db.classify(&fp), SuspicionLevel::Suspicious);
    }

    #[test]
    fn observation_classification_honors_minimum_request_threshold() {
        let config = FingerprintDbConfig {
            min_requests_for_classification: 3,
            ..FingerprintDbConfig::default()
        };
        let db = FingerprintDb::new(config);
        let fp = CombinedFingerprint {
            ja4: Some("new_ja4".to_string()),
            http2: None,
        };

        for _ in 0..2 {
            db.observe(
                fp.clone(),
                Some("198.51.100.10".parse().expect("hardcoded IP")),
            );
        }

        assert_eq!(db.classify(&fp), SuspicionLevel::Unknown);
    }

    #[test]
    fn observe_enforces_max_observed_limit() {
        let config = FingerprintDbConfig {
            max_observed: 2,
            ..FingerprintDbConfig::default()
        };
        let db = FingerprintDb::new(config);

        for index in 0..3 {
            db.observe(
                CombinedFingerprint {
                    ja4: Some(format!("fp_{index}")),
                    http2: None,
                },
                None,
            );
        }

        assert_eq!(db.stats().observed_fingerprints, 2);
    }

    // ── Security-fix regression test ──

    #[test]
    fn test_seed_keys_parse_and_validate() {
        // Every hardcoded seed key must be format-valid per the crate's own
        // JA4 validator AND parseable back through Ja4Fingerprint::parse
        // (combined into a full fingerprint string). The old seeds
        // ("t130613h2", "d100200", …) failed both.
        let db = FingerprintDb::default();
        assert!(!db.known.is_empty(), "seed table must not be empty");
        for key in db.known.iter().map(|e| e.key().clone()) {
            assert!(
                crate::ja4::is_valid_ja4_a(&key),
                "seed key {key:?} fails the crate's own JA4_a validator"
            );
            // Round-trip through the parser inside a synthetic full string.
            let synthetic = format!("{key}_abcdef012345_6789abcdef012");
            let parsed = crate::ja4::Ja4Fingerprint::parse(&synthetic)
                .unwrap_or_else(|| panic!("seed key {key:?} must parse as a JA4_a component"));
            assert_eq!(parsed.ja4_a, key);
        }
        // The malicious concept survives with a properly formatted key.
        let malicious = db.known.get("di020200").expect("attack-tool seed present");
        assert_eq!(malicious.suspicion, SuspicionLevel::Malicious);
    }
}
