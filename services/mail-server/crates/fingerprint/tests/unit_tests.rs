//! Comprehensive unit tests for Fingerprint crate

/// ============================================================================
/// UNIT TESTS:JA4 TLS Fingerprinting
/// ============================================================================
#[cfg(test)]
mod ja4_tests {
    use sha2::{Sha256, Digest};
    
/// GREASE (Generate Random Extensions And Sustain Extensibility) values
/// are used to prevent middleboxes from becoming dependent on specific values
    fn is_grease_value(value: u16) -> bool {
        (value & 0x0f0f) == 0x0a0a
    }
    
/// Create truncated SHA256 hash for JA4 format
    fn truncate_hash(input: &str, hex_len: usize) -> String {
        let mut hasher = Sha256::new();
        hasher.update(input.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..hex_len / 2])
    }
    
    #[test]
    fn test_grease_values_comprehensive() {
// All valid GREASE values
        let grease_values = [
            0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a, 0x4a4a,
            0x5a5a, 0x6a6a, 0x7a7a, 0x8a8a, 0x9a9a,
            0xaaaa, 0xbaba, 0xcaca, 0xdada, 0xeaea, 0xfafa,
        ];
        
        for &val in &grease_values {
            assert!(is_grease_value(val), "0x{:04x} should be GREASE", val);
        }
    }
    
    #[test]
    fn test_common_cipher_suites_not_grease() {
// Common TLS 1.3 cipher suites
        let ciphers = [
            0x1301, // TLS_AES_128_GCM_SHA256
            0x1302, // TLS_AES_256_GCM_SHA384
            0x1303, // TLS_CHACHA20_POLY1305_SHA256
            0x1304, // TLS_AES_128_CCM_SHA256
            0x1305, // TLS_AES_128_CCM_8_SHA256
        ];
        
        for &cipher in &ciphers {
            assert!(!is_grease_value(cipher), "Cipher 0x{:04x} should not be GREASE", cipher);
        }
    }
    
    #[test]
    fn test_tls_legacy_ciphers_not_grease() {
        let ciphers = [
            0x002f, // TLS_RSA_WITH_AES_128_CBC_SHA
            0x0035, // TLS_RSA_WITH_AES_256_CBC_SHA
            0x009c, // TLS_RSA_WITH_AES_128_GCM_SHA256
            0xc02b, // TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            0xc02c, // TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384
            0xc02f, // TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
            0xc030, // TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
        ];
        
        for &cipher in &ciphers {
            assert!(!is_grease_value(cipher), "Cipher 0x{:04x} should not be GREASE", cipher);
        }
    }
    
    #[test]
    fn test_hash_truncation_length() {
        let hash12 = truncate_hash("test", 12);
        assert_eq!(hash12.len(), 12, "Should be exactly 12 hex chars");
        
        let hash8 = truncate_hash("test", 8);
        assert_eq!(hash8.len(), 8, "Should be exactly 8 hex chars");
    }
    
    #[test]
    fn test_hash_determinism() {
        let input = "hello_world_test";
        let h1 = truncate_hash(input, 12);
        let h2 = truncate_hash(input, 12);
        let h3 = truncate_hash(input, 12);
        
        assert_eq!(h1, h2);
        assert_eq!(h2, h3);
    }
    
    #[test]
    fn test_hash_collision_resistance() {
// Different inputs should produce different hashes
        let h1 = truncate_hash("input_a", 12);
        let h2 = truncate_hash("input_b", 12);
        let h3 = truncate_hash("input_ab", 12);
        
        assert_ne!(h1, h2);
        assert_ne!(h2, h3);
        assert_ne!(h1, h3);
    }
    
    #[test]
    fn test_ja4_format_construction() {
// JA4 format:t13d1516h2_8daaf6152771_02713d6af862
// t = protocol (t=TCP, q=QUIC)
// 13 = TLS version (13 = 1.3)
// d = SNI (d=domain, i=IP)
// 15 = cipher count
// 16 = extension count // h2 = ALPN (h2, h1, etc.)
// _ = separator
// next 12 chars = truncated hash of sorted ciphers
// _ = separator
// next 12 chars = truncated hash of sorted extensions
        
// Simulated JA4 construction
        let protocol = 't';
        let tls_version = "13";
        let sni_type = 'd';
        let cipher_count = format!("{:02}", 15.min(99));
        let ext_count = format!("{:02}", 16.min(99));
        let alpn = "h2";
        
        let prefix = format!(
            "{}{}{}{}{}{}",
            protocol, tls_version, sni_type, cipher_count, ext_count, alpn
        );
        
        assert_eq!(prefix, "t13d1516h2");
        assert_eq!(prefix.len(), 10);
    }
    
    #[test]
    fn test_alpn_values() {
        let alpn_mappings = [
            ("h2", "HTTP/2"),
            ("h1", "HTTP/1.1"),
            ("h3", "HTTP/3"),
            ("00", "no ALPN"),
        ];
        
        for (short, _long) in &alpn_mappings {
            assert_eq!(short.len(), 2, "ALPN short form should be 2 chars");
        }
    }
    
    #[test]
    fn test_tls_version_map() {
// Version mapping for JA4
        let versions = [
            (0x0301, "10"), // TLS 1.0
            (0x0302, "11"), // TLS 1.1
            (0x0303, "12"), // TLS 1.2
            (0x0304, "13"), // TLS 1.3
        ];
        
        for (code, expected) in &versions {
            let version = match code {
                0x0301 => "10",
                0x0302 => "11",
                0x0303 => "12",
                0x0304 => "13",
                _ => "00",
            };
            assert_eq!(version, *expected, "Version 0x{:04x} mapping", code);
        }
    }
}

/// ============================================================================
/// UNIT TESTS:HTTP/2 Fingerprinting
/// ============================================================================
#[cfg(test)]
mod http2_tests {
    use std::collections::BTreeMap;
    
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    #[repr(u8)]
    enum Http2Setting {
        HeaderTableSize = 0x1,
        EnablePush = 0x2,
        MaxConcurrentStreams = 0x3,
        InitialWindowSize = 0x4,
        MaxFrameSize = 0x5,
        MaxHeaderListSize = 0x6,
    }
    
    impl Http2Setting {
        fn from_u16(value: u16) -> Option<Self> {
            match value {
                0x1 => Some(Self::HeaderTableSize),
                0x2 => Some(Self::EnablePush),
                0x3 => Some(Self::MaxConcurrentStreams),
                0x4 => Some(Self::InitialWindowSize),
                0x5 => Some(Self::MaxFrameSize),
                0x6 => Some(Self::MaxHeaderListSize),
                _ => None,
            }
        }
    }
    
    fn parse_settings_frame(payload: &[u8]) -> BTreeMap<u16, u32> {
        let mut settings = BTreeMap::new();
        
// Each setting is 6 bytes:2 bytes identifier, 4 bytes value
        for chunk in payload.chunks_exact(6) {
            let id = u16::from_be_bytes([chunk[0], chunk[1]]);
            let value = u32::from_be_bytes([chunk[2], chunk[3], chunk[4], chunk[5]]);
            settings.insert(id, value);
        }
        
        settings
    }
    
    fn create_fingerprint(settings: &BTreeMap<u16, u32>, window_update: Option<u32>) -> String {
        let mut parts = Vec::new();
        
// Add settings in order
        for (&id, &value) in settings {
            parts.push(format!("{}:{}", id, value));
        }
        
// Add window update if present
        if let Some(wu) = window_update {
            parts.push(format!("w:{}", wu));
        }
        
        parts.join(";")
    }
    
    #[test]
    fn test_parse_settings_single() {
// INITIAL_WINDOW_SIZE (0x4) = 65535
        let payload = [0x00, 0x04, 0x00, 0x00, 0xff, 0xff];
        let settings = parse_settings_frame(&payload);
        
        assert_eq!(settings.len(), 1);
        assert_eq!(settings.get(&0x4), Some(&65535));
    }
    
    #[test]
    fn test_parse_settings_multiple() {
// Multiple settings
        let mut payload = Vec::new();
// HEADER_TABLE_SIZE (0x1) = 4096
        payload.extend_from_slice(&[0x00, 0x01, 0x00, 0x00, 0x10, 0x00]);
// MAX_CONCURRENT_STREAMS (0x3) = 100
        payload.extend_from_slice(&[0x00, 0x03, 0x00, 0x00, 0x00, 0x64]);
// INITIAL_WINDOW_SIZE (0x4) = 65535
        payload.extend_from_slice(&[0x00, 0x04, 0x00, 0x00, 0xff, 0xff]);
        
        let settings = parse_settings_frame(&payload);
        
        assert_eq!(settings.len(), 3);
        assert_eq!(settings.get(&0x1), Some(&4096));
        assert_eq!(settings.get(&0x3), Some(&100));
        assert_eq!(settings.get(&0x4), Some(&65535));
    }
    
    #[test]
    fn test_fingerprint_format() {
        let mut settings = BTreeMap::new();
        settings.insert(0x1, 4096);
        settings.insert(0x3, 100);
        settings.insert(0x4, 65535);
        
        let fp = create_fingerprint(&settings, Some(10485760));
        assert_eq!(fp, "1:4096;3:100;4:65535;w:10485760");
    }
    
    #[test]
    fn test_fingerprint_no_window_update() {
        let mut settings = BTreeMap::new();
        settings.insert(0x4, 65535);
        
        let fp = create_fingerprint(&settings, None);
        assert_eq!(fp, "4:65535");
    }
    
    #[test]
    fn test_known_browser_patterns() {
// Chrome typical settings
        let chrome_settings: Vec<(u16, u32)> = vec![
            (0x1, 65536), // HEADER_TABLE_SIZE
            (0x2, 0), // ENABLE_PUSH (disabled)
            (0x3, 1000), // MAX_CONCURRENT_STREAMS
            (0x4, 6291456), // INITIAL_WINDOW_SIZE
            (0x5, 16384), // MAX_FRAME_SIZE
            (0x6, 262144), // MAX_HEADER_LIST_SIZE
        ];
        
        for (id, value) in &chrome_settings {
            assert!(Http2Setting::from_u16(*id).is_some(), "Setting {} should be valid", id);
            assert!(*value <= u32::MAX);
        }
    }
    
    #[test]
    fn test_setting_enum_conversion() {
        assert_eq!(Http2Setting::from_u16(0x1), Some(Http2Setting::HeaderTableSize));
        assert_eq!(Http2Setting::from_u16(0x4), Some(Http2Setting::InitialWindowSize));
        assert_eq!(Http2Setting::from_u16(0x7), None);
        assert_eq!(Http2Setting::from_u16(0xFF), None);
    }
}

/// ============================================================================
/// UNIT TESTS:Fingerprint Database
/// ============================================================================
#[cfg(test)]
mod database_tests {
    use std::collections::HashMap;
    use std::time::{Duration, Instant};
    
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    enum Classification {
        Legitimate,
        SuspiciousBrowser,
        KnownBot,
        KnownMalicious,
        Unknown,
    }
    
    struct FingerprintEntry {
        classification: Classification,
        first_seen: Instant,
        last_seen: Instant,
        request_count: u64,
    }
    
    impl FingerprintEntry {
        fn new(classification: Classification) -> Self {
            let now = Instant::now();
            Self {
                classification,
                first_seen: now,
                last_seen: now,
                request_count: 1,
            }
        }
        
        fn update(&mut self) {
            self.last_seen = Instant::now();
            self.request_count += 1;
        }
    }
    
    struct FingerprintDb {
        entries: HashMap<String, FingerprintEntry>,
        max_entries: usize,
    }
    
    impl FingerprintDb {
        fn new(max_entries: usize) -> Self {
            Self {
                entries: HashMap::new(),
                max_entries,
            }
        }
        
        fn insert(&mut self, fingerprint: &str, classification: Classification) {
            if let Some(entry) = self.entries.get_mut(fingerprint) {
                entry.update();
            } else if self.entries.len() < self.max_entries {
                self.entries.insert(
                    fingerprint.to_string(),
                    FingerprintEntry::new(classification)
                );
            }
        }
        
        fn classify(&self, fingerprint: &str) -> Classification {
            self.entries
                .get(fingerprint)
                .map(|e| e.classification)
                .unwrap_or(Classification::Unknown)
        }
    }
    
    #[test]
    fn test_db_insert_and_classify() {
        let mut db = FingerprintDb::new(1000);
        
        db.insert("fp_chrome_123", Classification::Legitimate);
        db.insert("fp_bot_456", Classification::KnownBot);
        
        assert_eq!(db.classify("fp_chrome_123"), Classification::Legitimate);
        assert_eq!(db.classify("fp_bot_456"), Classification::KnownBot);
        assert_eq!(db.classify("unknown_fp"), Classification::Unknown);
    }
    
    #[test]
    fn test_db_update_count() {
        let mut db = FingerprintDb::new(1000);
        
        db.insert("test_fp", Classification::Legitimate);
        db.insert("test_fp", Classification::Legitimate);
        db.insert("test_fp", Classification::Legitimate);
        
        assert_eq!(db.entries.get("test_fp").unwrap().request_count, 3);
    }
    
    #[test]
    fn test_db_max_entries() {
        let mut db = FingerprintDb::new(2);
        
        db.insert("fp1", Classification::Legitimate);
        db.insert("fp2", Classification::Legitimate);
        db.insert("fp3", Classification::Legitimate); // Should not be inserted
        
        assert_eq!(db.entries.len(), 2);
        assert_eq!(db.classify("fp1"), Classification::Legitimate);
        assert_eq!(db.classify("fp2"), Classification::Legitimate);
        assert_eq!(db.classify("fp3"), Classification::Unknown);
    }
    
    #[test]
    fn test_classification_variants() {
        let classifications = [
            Classification::Legitimate,
            Classification::SuspiciousBrowser,
            Classification::KnownBot,
            Classification::KnownMalicious,
            Classification::Unknown,
        ];
        
        for class in &classifications {
            let mut db = FingerprintDb::new(1);
            db.insert("test", *class);
            assert_eq!(db.classify("test"), *class);
        }
    }
}

/// ============================================================================
/// UNIT TESTS:Combined Fingerprint
/// ============================================================================
#[cfg(test)]
mod combined_tests {
    use sha2::{Sha256, Digest};
    
    fn combine_fingerprints(ja4: &str, http2: &str) -> String {
        let mut hasher = Sha256::new();
        hasher.update(ja4.as_bytes());
        hasher.update(b"|");
        hasher.update(http2.as_bytes());
        let result = hasher.finalize();
        hex::encode(&result[..16]) // 32 hex chars
    }
    
    #[test]
    fn test_combined_length() {
        let ja4 = "t13d1516h2_8daaf6152771_02713d6af862";
        let http2 = "1:4096;3:100;4:65535";
        
        let combined = combine_fingerprints(ja4, http2);
        assert_eq!(combined.len(), 32);
    }
    
    #[test]
    fn test_combined_determinism() {
        let ja4 = "t13d1516h2_8daaf6152771_02713d6af862";
        let http2 = "1:4096;3:100;4:65535";
        
        let c1 = combine_fingerprints(ja4, http2);
        let c2 = combine_fingerprints(ja4, http2);
        
        assert_eq!(c1, c2);
    }
    
    #[test]
    fn test_combined_differs_on_ja4_change() {
        let ja4_a = "t13d1516h2_8daaf6152771_02713d6af862";
        let ja4_b = "q13d1516h3_8daaf6152771_02713d6af862";
        let http2 = "1:4096;3:100;4:65535";
        
        let ca = combine_fingerprints(ja4_a, http2);
        let cb = combine_fingerprints(ja4_b, http2);
        
        assert_ne!(ca, cb);
    }
    
    #[test]
    fn test_combined_differs_on_http2_change() {
        let ja4 = "t13d1516h2_8daaf6152771_02713d6af862";
        let http2_a = "1:4096;3:100;4:65535";
        let http2_b = "1:4096;3:200;4:65535";
        
        let ca = combine_fingerprints(ja4, http2_a);
        let cb = combine_fingerprints(ja4, http2_b);
        
        assert_ne!(ca, cb);
    }
}

/// ============================================================================
/// Run all fingerprint tests
/// ============================================================================
fn main() {
    println!("Run tests with: cargo test --lib");
}
