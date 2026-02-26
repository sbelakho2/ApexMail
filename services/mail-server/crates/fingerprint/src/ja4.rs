//! JA4 TLS fingerprinting implementation
//!
//! JA4 is designed for TLS 1.3 where JA3 loses effectiveness.
//! Format: JA4_a_JA4_b_JA4_c

use sha2::{Sha256, Digest};
use serde::{Deserialize, Serialize};

/// TLS version enumeration
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TlsVersion {
    /// TLS 1.0
    Tls10,
    /// TLS 1.1
    Tls11,
    /// TLS 1.2
    Tls12,
    /// TLS 1.3
    Tls13,
    /// QUIC
    Quic,
    /// Unknown version
    Unknown,
}

impl TlsVersion {
    /// Get JA4 protocol character
    pub fn ja4_char(&self) -> char {
        match self {
            TlsVersion::Tls13 => 't',
            TlsVersion::Quic => 'q',
            _ => 'd', // downgrade
        }
    }
}

/// Parsed ClientHello for fingerprinting
#[derive(Debug, Clone)]
pub struct ClientHello {
    /// TLS version
    pub version: TlsVersion,
    /// Server name (SNI)
    pub server_name: Option<String>,
    /// Cipher suites (as raw u16 values)
    pub cipher_suites: Vec<u16>,
    /// Extensions (type values)
    pub extensions: Vec<Extension>,
    /// Signature algorithms
    pub signature_algorithms: Vec<u16>,
    /// ALPN protocols
    pub alpn_protocols: Vec<String>,
}

/// TLS extension
#[derive(Debug, Clone)]
pub struct Extension {
    /// Extension type
    pub extension_type: u16,
    /// Extension data (raw bytes)
    pub data: Vec<u8>,
}

/// JA4 fingerprint
#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct Ja4Fingerprint {
    /// Full JA4 fingerprint string
    pub fingerprint: String,
    /// JA4_a component (version, SNI, counts)
    pub ja4_a: String,
    /// JA4_b component (cipher hash)
    pub ja4_b: String,
    /// JA4_c component (extension + sig hash)
    pub ja4_c: String,
    /// TLS protocol character
    pub protocol: char,
    /// SNI indicator
    pub sni: char,
    /// Cipher suite count
    pub cipher_count: u8,
    /// Extension count
    pub extension_count: u8,
    /// First ALPN protocol (truncated)
    pub alpn: String,
}

impl Ja4Fingerprint {
    /// Compute JA4 fingerprint from ClientHello
    pub fn compute(client_hello: &ClientHello) -> Self {
        let protocol = client_hello.version.ja4_char();
        
        let sni = match &client_hello.server_name {
            Some(name) if name.contains('.') => 'd',
            Some(_) => 'i',
            None => '_',
        };
        
        let cipher_count = client_hello.cipher_suites.len().min(99) as u8;
        let extension_count = client_hello.extensions.len().min(99) as u8;
        
        // Filter out GREASE values and sort
        let mut ciphers: Vec<u16> = client_hello.cipher_suites.iter()
            .filter(|c| !is_grease_value(**c))
            .cloned()
            .collect();
        ciphers.sort();
        
        let mut extensions: Vec<u16> = client_hello.extensions.iter()
            .filter(|e| !is_grease_value(e.extension_type))
            .map(|e| e.extension_type)
            .collect();
        extensions.sort();
        
        // Build JA4_a: protocol + SNI + cipher_count + ext_count + ALPN
        let alpn = client_hello.alpn_protocols
            .first()
            .map(|s| s.chars().take(2).collect())
            .unwrap_or_else(|| "00".to_string());
        
        let ja4_a = format!("{}{}{:02}{:02}{}", protocol, sni, cipher_count, extension_count, alpn);
        
        // Build JA4_b: truncated SHA256 of sorted cipher suites
        let cipher_str: String = ciphers.iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
            .join(",");
        let ja4_b = truncated_sha256(&cipher_str, 12);
        
        // Build JA4_c: truncated SHA256 of sorted extensions + signature algorithms
        let ext_str: String = extensions.iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");
        let sig_str: String = client_hello.signature_algorithms.iter()
            .map(|s| format!("{:04x}", s))
            .collect::<Vec<_>>()
            .join(",");
        let ja4_c = truncated_sha256(&format!("{}_{}", ext_str, sig_str), 12);
        
        let fingerprint = format!("{}_{}_{}", ja4_a, ja4_b, ja4_c);
        
        Self {
            fingerprint,
            ja4_a,
            ja4_b,
            ja4_c,
            protocol,
            sni,
            cipher_count,
            extension_count,
            alpn,
        }
    }
    
    /// Parse from a JA4 string
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('_').collect();
        if parts.len() != 3 {
            return None;
        }
        
        let ja4_a = parts[0];
        if ja4_a.len() < 6 {
            return None;
        }
        
        let mut chars = ja4_a.chars();
        let protocol = chars.next()?;
        let sni = chars.next()?;
        let cipher_count: u8 = ja4_a[2..4].parse().ok()?;
        let extension_count: u8 = ja4_a[4..6].parse().ok()?;
        let alpn = ja4_a[6..].to_string();
        
        Some(Self {
            fingerprint: s.to_string(),
            ja4_a: ja4_a.to_string(),
            ja4_b: parts[1].to_string(),
            ja4_c: parts[2].to_string(),
            protocol,
            sni,
            cipher_count,
            extension_count,
            alpn,
        })
    }
    
    /// Check if fingerprint looks anomalous
    pub fn is_anomalous(&self) -> bool {
        // Too few ciphers/extensions is suspicious
        if self.cipher_count < 5 || self.extension_count < 3 {
            return true;
        }
        
        // No ALPN in modern browser is suspicious
        if self.alpn == "00" {
            return true;
        }
        
        false
    }
}

/// Check if a value is a GREASE value
/// GREASE values: 0x0a0a, 0x1a1a, 0x2a2a, etc.
fn is_grease_value(value: u16) -> bool {
    (value & 0x0f0f) == 0x0a0a
}

/// Compute truncated SHA256 hash
fn truncated_sha256(input: &str, hex_len: usize) -> String {
    let mut hasher = Sha256::new();
    hasher.update(input.as_bytes());
    let result = hasher.finalize();
    hex::encode(&result[..hex_len / 2])
}

#[cfg(test)]
mod tests {
    use super::*;
    
    #[test]
    fn test_grease_detection() {
        assert!(is_grease_value(0x0a0a));
        assert!(is_grease_value(0x1a1a));
        assert!(is_grease_value(0x2a2a));
        assert!(!is_grease_value(0x1301));  // TLS_AES_128_GCM_SHA256
        assert!(!is_grease_value(0x0035));  // TLS_RSA_WITH_AES_256_CBC_SHA
    }
    
    #[test]
    fn test_ja4_compute() {
        let client_hello = ClientHello {
            version: TlsVersion::Tls13,
            server_name: Some("example.com".to_string()),
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b],
            extensions: vec![
                Extension { extension_type: 0, data: vec![] },    // server_name
                Extension { extension_type: 10, data: vec![] },   // supported_groups
                Extension { extension_type: 11, data: vec![] },   // ec_point_formats
                Extension { extension_type: 13, data: vec![] },   // signature_algorithms
                Extension { extension_type: 16, data: vec![] },   // alpn
                Extension { extension_type: 43, data: vec![] },   // supported_versions
            ],
            signature_algorithms: vec![0x0401, 0x0501, 0x0601],
            alpn_protocols: vec!["h2".to_string(), "http/1.1".to_string()],
        };
        
        let fp = Ja4Fingerprint::compute(&client_hello);
        
        assert_eq!(fp.protocol, 't');
        assert_eq!(fp.sni, 'd');
        assert_eq!(fp.cipher_count, 5);
        assert_eq!(fp.extension_count, 6);
        assert_eq!(fp.alpn, "h2");
        assert!(!fp.is_anomalous());
    }
    
    #[test]
    fn test_ja4_parse() {
        let fp = Ja4Fingerprint::parse("td0506h2_abc123def456_789012345678");
        assert!(fp.is_some());
        
        let fp = fp.unwrap();
        assert_eq!(fp.protocol, 't');
        assert_eq!(fp.sni, 'd');
        assert_eq!(fp.cipher_count, 5);
        assert_eq!(fp.extension_count, 6);
        assert_eq!(fp.alpn, "h2");
    }
}
