//! JA4 TLS fingerprinting implementation
//!
//! JA4 is designed for TLS 1.3 where JA3 loses effectiveness.
//! Format:JA4_a_JA4_b_JA4_c

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

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

/// Protocol context for anomaly evaluation.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FingerprintContext {
    /// HTTPS/browser-style traffic — ALPN is expected.
    Browser,
    /// Mail protocols (SMTP/IMAP/POP3 over STARTTLS) — missing ALPN is normal.
    Mail,
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

        // Filter out GREASE values and sort FIRST:per the JA4 spec the
        // counts cover only non-GREASE entries, so a client padding its
        // ClientHello with GREASE must produce the SAME fingerprint as one
        // that sends none. (Previously the counts included GREASE.)
        let mut ciphers: Vec<u16> = client_hello
            .cipher_suites
            .iter()
            .filter(|c| !is_grease_value(**c))
            .cloned()
            .collect();
        ciphers.sort();

        let mut extensions: Vec<u16> = client_hello
            .extensions
            .iter()
            .filter(|e| !is_grease_value(e.extension_type))
            .map(|e| e.extension_type)
            .collect();
        extensions.sort();

        let cipher_count = ciphers.len().min(99) as u8;
        let extension_count = extensions.len().min(99) as u8;

        // Build JA4_a:protocol + SNI + cipher_count + ext_count + ALPN
        let alpn = client_hello
            .alpn_protocols
            .first()
            .map(|s| s.chars().take(2).collect())
            .unwrap_or_else(|| "00".to_string());

        let ja4_a = format!(
            "{}{}{:02}{:02}{}",
            protocol, sni, cipher_count, extension_count, alpn
        );

        // Build JA4_b:truncated SHA256 of sorted cipher suites
        let cipher_str: String = ciphers
            .iter()
            .map(|c| format!("{:04x}", c))
            .collect::<Vec<_>>()
            .join(",");
        let ja4_b = truncated_sha256(&cipher_str, 12);

        // Build JA4_c:truncated SHA256 of sorted extensions + signature algorithms
        let ext_str: String = extensions
            .iter()
            .map(|e| format!("{:04x}", e))
            .collect::<Vec<_>>()
            .join(",");
        let sig_str: String = client_hello
            .signature_algorithms
            .iter()
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

    /// Parse from a JA4 string.
    /// Char-safe:the previous implementation byte-sliced `ja4_a[2..4]`,
    /// which PANICS when the leading characters are multi-byte UTF-8.
    pub fn parse(s: &str) -> Option<Self> {
        let parts: Vec<&str> = s.split('_').collect();
        if parts.len() != 3 {
            return None;
        }

        let ja4_a = parts[0];
        let chars: Vec<char> = ja4_a.chars().collect();
        if chars.len() < 6 {
            return None;
        }

        let protocol = chars[0];
        let sni = chars[1];
        let cipher_digits: String = chars[2..4].iter().collect();
        let extension_digits: String = chars[4..6].iter().collect();
        let cipher_count: u8 = cipher_digits.parse().ok()?;
        let extension_count: u8 = extension_digits.parse().ok()?;
        let alpn: String = chars[6..].iter().collect();

        // Alphabet validation:protocol and SNI must be from the JA4 set and
        // the count fields must be decimal digits (parse already enforces
        // the digits; enforce the char alphabets here).
        if !matches!(protocol, 't' | 'q' | 'd') || !matches!(sni, 'd' | 'i' | '_') {
            return None;
        }

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

    /// Check if fingerprint looks anomalous for a browser/HTTPS context.
    /// Mail protocols (SMTP/IMAP/POP3 over STARTTLS) legitimately omit
    /// ALPN — use [`Self::is_anomalous_in`] with
    /// [`FingerprintContext::Mail`] for those.
    pub fn is_anomalous(&self) -> bool {
        self.is_anomalous_in(FingerprintContext::Browser)
    }

    /// Check if fingerprint looks anomalous for the given protocol context.
    pub fn is_anomalous_in(&self, context: FingerprintContext) -> bool {
        // Too few ciphers/extensions is suspicious in ANY context
        if self.cipher_count < 5 || self.extension_count < 3 {
            return true;
        }

        // No ALPN is only suspicious for browsers/HTTPS — mail clients
        // (SMTP/IMAP/POP3 STARTTLS) almost never negotiate ALPN.
        if context == FingerprintContext::Browser && self.alpn == "00" {
            return true;
        }

        false
    }
}

/// Check if a value is a GREASE value (RFC 8701).
/// GREASE values are of the form 0xNNNN where BOTH bytes are equal and each
/// byte's low nibble is 0x0a:0x0a0a, 0x1a1a, 0x2a2a, … 0xfafa.
/// The old check `(value & 0x0f0f) == 0x0a0a` also matched non-GREASE
/// values such as 0x1a0a and 0x0a1a (bytes differ — never emitted as GREASE).
fn is_grease_value(value: u16) -> bool {
    let hi = (value >> 8) as u8;
    let lo = (value & 0xff) as u8;
    hi == lo && (hi & 0x0f) == 0x0a
}

/// Validate a JA4_a component against this crate's own format:
/// 1 protocol char (t/q/d), 1 SNI char (d/i — NOT '_', which collides with
/// the `_` field separator in full JA4 strings and could never round-trip
/// through [`Ja4Fingerprint::parse`]), two 2-digit decimal counts, then a
/// lowercase alphanumeric ALPN marker ("00" when absent).
/// Used to validate both parsed and seeded fingerprint keys.
pub fn is_valid_ja4_a(s: &str) -> bool {
    let chars: Vec<char> = s.chars().collect();
    if chars.len() < 7 {
        return false;
    }
    if !matches!(chars[0], 't' | 'q' | 'd') {
        return false;
    }
    if !matches!(chars[1], 'd' | 'i') {
        return false;
    }
    for idx in [2, 3, 4, 5] {
        if !chars[idx].is_ascii_digit() {
            return false;
        }
    }
    chars[6..]
        .iter()
        .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
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
        assert!(!is_grease_value(0x1301)); // TLS_AES_128_GCM_SHA256
        assert!(!is_grease_value(0x0035)); // TLS_RSA_WITH_AES_256_CBC_SHA
    }

    #[test]
    fn test_ja4_compute() {
        let client_hello = ClientHello {
            version: TlsVersion::Tls13,
            server_name: Some("example.com".to_string()),
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02c, 0xc02b],
            extensions: vec![
                Extension {
                    extension_type: 0,
                    data: vec![],
                }, // server_name
                Extension {
                    extension_type: 10,
                    data: vec![],
                }, // supported_groups
                Extension {
                    extension_type: 11,
                    data: vec![],
                }, // ec_point_formats
                Extension {
                    extension_type: 13,
                    data: vec![],
                }, // signature_algorithms
                Extension {
                    extension_type: 16,
                    data: vec![],
                }, // alpn
                Extension {
                    extension_type: 43,
                    data: vec![],
                }, // supported_versions
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

        let fp = fp.expect("fingerprint should be parseable");
        assert_eq!(fp.protocol, 't');
        assert_eq!(fp.sni, 'd');
        assert_eq!(fp.cipher_count, 5);
        assert_eq!(fp.extension_count, 6);
        assert_eq!(fp.alpn, "h2");
    }

    // ── Security-fix regression tests ──

    #[test]
    fn test_grease_check_requires_equal_bytes() {
        // True GREASE values (both bytes equal, low nibble 0x0a)
        for v in [0x0a0a, 0x1a1a, 0x2a2a, 0xfafa] {
            assert!(is_grease_value(v), "{v:#06x} is GREASE");
        }
        // Mixed-byte values are NOT GREASE — the old mask check matched them.
        for v in [0x1a0a, 0x0a1a, 0x2a0a, 0x0a2a] {
            assert!(!is_grease_value(v), "{v:#06x} must not be GREASE");
        }
        // Real cipher suites remain untouched
        for v in [0x1301, 0x0035, 0xc02b] {
            assert!(!is_grease_value(v));
        }
    }

    #[test]
    fn test_grease_excluded_from_counts() {
        // A ClientHello padded with GREASE must produce the same counts (and
        // same fingerprint) as the identical hello without GREASE.
        let base = ClientHello {
            version: TlsVersion::Tls13,
            server_name: Some("example.com".to_string()),
            cipher_suites: vec![0x1301, 0x1302, 0x1303, 0xc02b, 0xc02c],
            extensions: vec![
                Extension { extension_type: 0, data: vec![] },
                Extension { extension_type: 10, data: vec![] },
                Extension { extension_type: 11, data: vec![] },
                Extension { extension_type: 43, data: vec![] },
            ],
            signature_algorithms: vec![0x0403, 0x0804],
            alpn_protocols: vec!["h2".to_string()],
        };
        let mut greased = base.clone();
        greased.cipher_suites.push(0x0a0a); // GREASE cipher
        greased.extensions.push(Extension { extension_type: 0x1a1a, data: vec![] }); // GREASE ext

        let fp_base = Ja4Fingerprint::compute(&base);
        let fp_greased = Ja4Fingerprint::compute(&greased);
        assert_eq!(fp_base.cipher_count, fp_greased.cipher_count);
        assert_eq!(fp_base.extension_count, fp_greased.extension_count);
        assert_eq!(
            fp_base.fingerprint, fp_greased.fingerprint,
            "GREASE padding must not change the JA4 fingerprint"
        );
    }

    #[test]
    fn test_parse_multibyte_first_chars_no_panic() {
        // Byte-slicing ja4_a[2..4] panicked on multibyte UTF-8 leaders.
        assert!(Ja4Fingerprint::parse("éà0506h2_deadbeefcafe_0123456789ab").is_none());
        assert!(Ja4Fingerprint::parse("🦀🦀0506h2_deadbeefcafe_0123456789ab").is_none());
        // ASCII input still parses.
        assert!(Ja4Fingerprint::parse("td0506h2_deadbeefcafe_0123456789ab").is_some());
    }

    #[test]
    fn test_parse_validates_alphabet() {
        // Invalid protocol/SNI chars are rejected.
        assert!(Ja4Fingerprint::parse("xd0506h2_deadbeefcafe_0123456789ab").is_none());
        assert!(Ja4Fingerprint::parse("tz0506h2_deadbeefcafe_0123456789ab").is_none());
        // Valid one parses.
        let fp = Ja4Fingerprint::parse("td0506h2_deadbeefcafe_0123456789ab").unwrap();
        assert_eq!(fp.protocol, 't');
        assert_eq!(fp.sni, 'd');
        assert_eq!(fp.cipher_count, 5);
        assert_eq!(fp.extension_count, 6);
    }

    #[test]
    fn test_missing_alpn_ok_for_mail_context() {
        // Mail (SMTP/IMAP STARTTLS) clients legitimately omit ALPN —
        // missing ALPN must not flag them anomalous.
        let mut fp = Ja4Fingerprint::parse("td1008h2_deadbeefcafe_0123456789ab")
            .expect("valid ja4");
        fp.alpn = "00".to_string();
        assert!(
            !fp.is_anomalous_in(crate::ja4::FingerprintContext::Mail),
            "mail context must tolerate missing ALPN"
        );
        assert!(
            fp.is_anomalous_in(crate::ja4::FingerprintContext::Browser),
            "browser context still requires ALPN"
        );
        assert!(fp.is_anomalous(), "default context is browser");
    }

    #[test]
    fn test_is_valid_ja4_a_format() {
        assert!(is_valid_ja4_a("td1817h2"));
        assert!(is_valid_ja4_a("di020200"));
        assert!(is_valid_ja4_a("dd090800"));
        assert!(!is_valid_ja4_a("d_020200"), "'_' SNI collides with the separator");
        assert!(!is_valid_ja4_a("t130613h2"), "wrong alphabet (old seed)");
        assert!(!is_valid_ja4_a("d100200"), "too short (old seed)");
        assert!(!is_valid_ja4_a("tZ0506h2"), "bad SNI char");
        assert!(!is_valid_ja4_a("td5b06h2"), "non-digit count");
    }
}
