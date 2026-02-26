//! Edge-case and adversarial tests for TLS fingerprinting
//!
//! Tests designed to catch edge cases in TLS fingerprint parsing and risk scoring.

use ato_protection::tls_fingerprint::{
    TlsFingerprint, UserTlsHistory, EnhancedDeviceFingerprint,
};

mod fingerprint_edge_cases {
    use super::*;

    /// Empty cipher suite list
    #[test]
    fn test_empty_cipher_suites() {
        let fp = TlsFingerprint::from_client_hello(
            0x0303, // TLS 1.2
            &[],    // No cipher suites
            &[0x0000, 0x000a],
            &[0x0401],
            &["h2"],
        );
        // Should not panic, hash should still be computed
        assert!(!fp.hash.is_empty());
    }

    /// Empty everything
    #[test]
    fn test_completely_empty() {
        let fp = TlsFingerprint::from_client_hello(
            0x0303,
            &[],
            &[],
            &[],
            &[],
        );
        assert!(!fp.hash.is_empty());
        assert!(fp.cipher_suites.is_empty());
    }

    /// Very many cipher suites (stress test)
    #[test]
    fn test_many_cipher_suites() {
        let ciphers: Vec<u16> = (0..1000).collect();
        let fp = TlsFingerprint::from_client_hello(
            0x0304,
            &ciphers,
            &[0x0017, 0x0000],
            &[0x0401, 0x0501],
            &["h2", "http/1.1"],
        );
        assert_eq!(fp.cipher_suites.len(), 1000);
    }

    /// Unknown TLS version
    #[test]
    fn test_unknown_tls_version() {
        let fp = TlsFingerprint::from_client_hello(
            0x0305, // Future TLS 1.4?
            &[0x1301],
            &[],
            &[],
            &[],
        );
        // Should handle gracefully with hex format
        assert!(fp.tls_version.starts_with('t'));
    }

    /// Very old TLS version
    #[test]
    fn test_old_tls_version() {
        let fp = TlsFingerprint::from_client_hello(
            0x0300, // SSL 3.0
            &[0x0035],
            &[],
            &[],
            &[],
        );
        assert!(fp.tls_version.contains("00"));
    }

    /// Duplicate cipher suites
    #[test]
    fn test_duplicate_ciphers() {
        let fp = TlsFingerprint::from_client_hello(
            0x0303,
            &[0x1301, 0x1301, 0x1301], // Same cipher 3 times
            &[],
            &[],
            &[],
        );
        // Should handle duplicates
        assert_eq!(fp.cipher_suites.len(), 3);
    }

    /// Max value cipher suite
    #[test]
    fn test_max_value_cipher() {
        let fp = TlsFingerprint::from_client_hello(
            0x0303,
            &[0xFFFF],
            &[],
            &[],
            &[],
        );
        assert_eq!(fp.cipher_suites[0], "ffff");
    }

    /// ALPN with special characters
    #[test]
    fn test_alpn_special_chars() {
        let fp = TlsFingerprint::from_client_hello(
            0x0304,
            &[0x1301],
            &[],
            &[],
            &["h2", "http/1.1", "my-protocol\x00with-null"],
        );
        assert_eq!(fp.alpn_protocols.len(), 3);
    }
}

mod user_history_edge_cases {
    use super::*;

    /// Empty history
    #[test]
    fn test_empty_history() {
        let history = UserTlsHistory::new(100);
        assert!(history.is_empty());
    }

    /// Single fingerprint
    #[test]
    fn test_single_fingerprint() {
        let mut history = UserTlsHistory::new(100);
        let fp = TlsFingerprint::from_client_hello(
            0x0303,
            &[0x1301, 0x1302],
            &[0x0000],
            &[0x0401],
            &["h2"],
        );
        let is_new = history.record(&fp);
        // First fingerprint should be new
        assert!(is_new);
        // Risk should be low for first login
        let risk = history.fingerprint_risk(&fp);
        assert!(risk < 5.0);
    }

    /// Many different fingerprints (suspicious)
    #[test]
    fn test_many_different_fingerprints() {
        let mut history = UserTlsHistory::new(100);
        
        for i in 0..20 {
            let fp = TlsFingerprint::from_client_hello(
                0x0303 + (i as u16 % 2),
                &[(0x1301 + i) as u16],
                &[],
                &[],
                &[],
            );
            history.record(&fp);
        }
        
        // New unique fingerprint should be checked
        let new_fp = TlsFingerprint::from_client_hello(
            0x0304,
            &[0xFFFF],
            &[],
            &[],
            &[],
        );
        let risk = history.fingerprint_risk(&new_fp);
        assert!(risk >= 0.0); // Risk should be non-negative
    }

    /// Same fingerprint repeatedly
    #[test]
    fn test_repeated_same_fingerprint() {
        let mut history = UserTlsHistory::new(100);
        let fp = TlsFingerprint::from_client_hello(
            0x0303,
            &[0x1301],
            &[],
            &[],
            &[],
        );
        
        // Record same fingerprint many times
        for _ in 0..100 {
            history.record(&fp);
            let risk = history.fingerprint_risk(&fp);
            assert!(risk <= 10.0); // Risk should be bounded
        }
    }

    /// Fingerprint change detection
    #[test]
    fn test_fingerprint_change() {
        let mut history = UserTlsHistory::new(100);
        
        // Establish baseline with first fingerprint  
        let fp1 = TlsFingerprint::from_client_hello(
            0x0303,
            &[0x1301, 0x1302, 0x1303],
            &[0x0000, 0x000a],
            &[0x0401],
            &["h2"],
        );
        history.record(&fp1);
        
        // Completely different fingerprint (potential ATO)
        let fp2 = TlsFingerprint::from_client_hello(
            0x0302, // Different TLS version
            &[0x002f], // Different ciphers
            &[0x0023],
            &[0x0201],
            &["http/1.1"],
        );
        let risk = history.fingerprint_risk(&fp2);
        
        // Should flag higher risk for new fingerprint
        assert!(risk > 0.0);
    }
}

mod enhanced_fingerprint_edge_cases {
    use super::*;

    /// Create enhanced fingerprint
    #[test]
    fn test_enhanced_fingerprint_creation() {
        let tls_fp = TlsFingerprint::from_client_hello(
            0x0303,
            &[0x1301],
            &[],
            &[],
            &[],
        );
        let enhanced = EnhancedDeviceFingerprint::new(
            "Mozilla/5.0",
            "192.168.1.100",
            Some(tls_fp),
        );
        assert!(!enhanced.hash.is_empty());
    }

    /// Empty user agent
    #[test]
    fn test_empty_user_agent() {
        let tls_fp = TlsFingerprint::from_client_hello(
            0x0303,
            &[0x1301],
            &[],
            &[],
            &[],
        );
        let enhanced = EnhancedDeviceFingerprint::new(
            "",
            "10.0.0.1",
            Some(tls_fp),
        );
        assert!(!enhanced.hash.is_empty());
    }

    /// Very long user agent (potential attack)
    #[test]
    fn test_long_user_agent() {
        let tls_fp = TlsFingerprint::from_client_hello(
            0x0303,
            &[0x1301],
            &[],
            &[],
            &[],
        );
        let long_ua = "A".repeat(100_000);
        let enhanced = EnhancedDeviceFingerprint::new(
            &long_ua,
            "10.0.0.1",
            Some(tls_fp),
        );
        // Should not panic or take too long
        assert!(!enhanced.hash.is_empty());
    }

    /// No TLS fingerprint
    #[test]
    fn test_no_tls_fingerprint() {
        let enhanced = EnhancedDeviceFingerprint::new(
            "Mozilla/5.0",
            "192.168.1.1",
            None,
        );
        assert!(!enhanced.hash.is_empty());
        assert!(!enhanced.has_tls());
    }
}

mod risk_scoring_edge_cases {
    use super::*;

    /// Risk should be bounded
    #[test]
    fn test_risk_bounds() {
        let mut history = UserTlsHistory::new(100);
        
        // Add many suspicious patterns
        for i in 0..100 {
            let fp = TlsFingerprint::from_client_hello(
                (0x0300 + (i % 5)) as u16,
                &[(0x0001 + i) as u16],
                &[(0x0100 + i) as u16],
                &[(0x0200 + i) as u16],
                &[&format!("proto-{}", i)],
            );
            history.record(&fp);
            let risk = history.fingerprint_risk(&fp);
            // Risk should never exceed 10.0
            assert!(risk <= 10.0, "Risk {} exceeded maximum", risk);
            // Risk should never be negative
            assert!(risk >= 0.0, "Risk {} is negative", risk);
        }
    }

    /// NaN/Infinity handling (if any calculations could produce them)
    #[test]
    fn test_no_nan_risk() {
        let mut history = UserTlsHistory::new(100);
        
        let fp = TlsFingerprint::from_client_hello(
            0x0303,
            &[],
            &[],
            &[],
            &[],
        );
        
        let risk = history.fingerprint_risk(&fp);
        assert!(!risk.is_nan(), "Risk is NaN");
        assert!(risk.is_finite(), "Risk is infinite");
    }
}

mod concurrent_history_tests {
    use super::*;
    use std::sync::Arc;
    use parking_lot::RwLock;
    use std::thread;

    /// Concurrent fingerprint recording
    #[test]
    fn test_concurrent_recording() {
        let history = Arc::new(RwLock::new(UserTlsHistory::new(1000)));
        let mut handles = vec![];

        for t in 0..20 {
            let h = Arc::clone(&history);
            handles.push(thread::spawn(move || {
                for i in 0..50 {
                    let fp = TlsFingerprint::from_client_hello(
                        0x0303,
                        &[(0x1301 + ((t * i) % 10)) as u16],
                        &[],
                        &[],
                        &[],
                    );
                    let mut guard = h.write();
                    guard.record(&fp);
                    let risk = guard.fingerprint_risk(&fp);
                    assert!(risk.is_finite());
                }
            }));
        }

        for h in handles {
            h.join().expect("Thread panicked");
        }
    }
}
