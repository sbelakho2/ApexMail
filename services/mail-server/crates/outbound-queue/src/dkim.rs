//! DKIM Signing
//!
//! Signs outbound emails with DKIM for authentication.
//!
//! # Security
//!
//! The DKIM private key is zeroized on drop to prevent exposure via memory dumps.
//! Keys can be loaded from:
//! - A PEM file via [`from_file`](DkimSigner::from_file)
//! - The `DKIM_PRIVATE_KEY` environment variable via [`from_env`](DkimSigner::from_env)

use std::fmt;

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::traits::PublicKeyParts;
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use sha2::{Digest, Sha256};
use tracing::debug;
use zeroize::{Zeroize, Zeroizing};

const MIN_DKIM_RSA_BITS: usize = 2048;

/// DKIM Configuration
///
/// Uses `Zeroizing<String>` for the private key PEM to ensure the key material
/// is zeroized in memory when the config is dropped, protecting against
/// memory-dump attacks.
#[derive(Debug, Clone)]
pub struct DkimConfig {
    pub domain: String,
    pub selector: String,
    /// Private key PEM, wrapped in `Zeroizing` for automatic zeroization on drop.
    pub private_key_pem: Zeroizing<String>,
    pub headers_to_sign: Vec<String>,
}

impl Drop for DkimConfig {
    fn drop(&mut self) {
        // Zeroizing<String> automatically zeroizes on drop;
        // explicit zeroize() call as defense-in-depth.
        self.private_key_pem.zeroize();
    }
}

impl Default for DkimConfig {
    fn default() -> Self {
        Self {
            domain: "apexmail.ee".to_string(),
            selector: "apexmail2026".to_string(),
            private_key_pem: Zeroizing::new(String::new()),
            headers_to_sign: vec![
                "from".to_string(),
                "to".to_string(),
                "subject".to_string(),
                "date".to_string(),
                "message-id".to_string(),
                "content-type".to_string(),
                "mime-version".to_string(),
            ],
        }
    }
}

/// DKIM Signer
///
/// Implements manual `Debug` to avoid leaking the private key via debug formatting
/// while still satisfying the `T: Debug` bound required by `Result::unwrap_err()`.
pub struct DkimSigner {
    config: DkimConfig,
    /// The RSA private key automatically zeroizes its sensitive key material
    /// on drop via `ZeroizeOnDrop` (enabled by the `zeroize` feature on the
    /// `rsa` crate in the workspace Cargo.toml).
    private_key: RsaPrivateKey,
}

impl fmt::Debug for DkimSigner {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DkimSigner")
            .field("domain", &self.config.domain)
            .field("selector", &self.config.selector)
            .field("private_key", &"[REDACTED]")
            .finish()
    }
}

impl Drop for DkimSigner {
    fn drop(&mut self) {
        // Zeroize the PEM string before dropping
        self.config.private_key_pem.zeroize();
        // `RsaPrivateKey` auto-zeroizes on drop via `ZeroizeOnDrop`
        // (the `rsa` crate bundles `zeroize` as a required dependency).
    }
}

impl DkimSigner {
    /// Create a new DKIM signer
    pub fn new(config: DkimConfig) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(&config.private_key_pem)
            .map_err(|e| anyhow!("Failed to parse DKIM private key: {}", e))?;
        let key_bits = private_key.n().bits();
        if key_bits < MIN_DKIM_RSA_BITS {
            return Err(anyhow!(
                "DKIM RSA private key is too small: {} bits (minimum: {} bits)",
                key_bits,
                MIN_DKIM_RSA_BITS
            ));
        }

        debug!(domain = %config.domain, selector = %config.selector, "DKIM signer initialized");

        Ok(Self {
            config,
            private_key,
        })
    }

    /// Load DKIM signer from file
    pub async fn from_file(domain: &str, selector: &str, key_path: &str) -> Result<Self> {
        // Warn if key file has overly permissive permissions (world-readable)
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            if let Ok(meta) = tokio::fs::metadata(key_path).await {
                let mode = meta.mode();
                // Check for group/other read permission.
                if dkim_key_mode_is_group_or_world_readable(mode) {
                    tracing::warn!(
                        path = %key_path,
                        mode = format!("{:o}", mode),
                        "DKIM private key file is group/world-readable; recommend chmod 600"
                    );
                }
            }
        }

        let private_key_pem = tokio::fs::read_to_string(key_path)
            .await
            .map_err(|e| anyhow!("Failed to read DKIM key file: {}", e))?;

        // Build config explicitly (cannot use ..Default::default() with Drop)
        let config = DkimConfig {
            domain: domain.to_string(),
            selector: selector.to_string(),
            private_key_pem: Zeroizing::new(private_key_pem),
            headers_to_sign: vec![
                "from".to_string(),
                "to".to_string(),
                "subject".to_string(),
                "date".to_string(),
                "message-id".to_string(),
                "content-type".to_string(),
                "mime-version".to_string(),
            ],
        };

        Self::new(config)
    }

    /// Load DKIM signer from the `DKIM_PRIVATE_KEY` environment variable.
    ///
    /// This avoids writing the private key to disk entirely, reducing the
    /// risk of accidental exposure.
    pub fn from_env(domain: &str, selector: &str) -> Result<Self> {
        let private_key_pem = std::env::var("DKIM_PRIVATE_KEY")
            .map_err(|_| anyhow!("DKIM_PRIVATE_KEY environment variable is not set"))?;

        if private_key_pem.is_empty() {
            return Err(anyhow!("DKIM_PRIVATE_KEY environment variable is empty"));
        }

        // Build config explicitly (cannot use ..Default::default() with Drop)
        let config = DkimConfig {
            domain: domain.to_string(),
            selector: selector.to_string(),
            private_key_pem: Zeroizing::new(private_key_pem),
            headers_to_sign: vec![
                "from".to_string(),
                "to".to_string(),
                "subject".to_string(),
                "date".to_string(),
                "message-id".to_string(),
                "content-type".to_string(),
                "mime-version".to_string(),
            ],
        };

        Self::new(config)
    }

    /// Sign an email message
    ///
    /// Operates on raw BYTES end-to-end: the message is never round-tripped
    /// through `String::from_utf8_lossy` (which rewrites invalid UTF-8 bytes
    /// to U+FFFD and would change the body hash of 8-bit payloads). Only the
    /// header NAMES — which are ASCII by definition — go through &str.
    pub fn sign(&self, message: &[u8]) -> Result<String> {
        // Split headers and body on the first empty line (CRLF CRLF).
        let header_end = message
            .windows(4)
            .position(|w| w == b"\r\n\r\n");
        let (headers_section, body): (&[u8], &[u8]) = match header_end {
            Some(pos) => (&message[..pos], &message[pos + 4..]),
            None => (message, &[]),
        };

        // Parse headers (names are ASCII; values stay raw bytes)
        let headers = self.parse_headers(headers_section);

        // Compute body hash (relaxed canonicalization, over raw bytes)
        let canonical_body = self.canonicalize_body_relaxed(body);
        let body_hash = {
            let mut hasher = Sha256::new();
            hasher.update(&canonical_body);
            BASE64.encode(hasher.finalize())
        };

        // Build DKIM-Signature header (without b= value)
        // #110:Safe fallback if system clock is before epoch
        let timestamp = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs();

        // #111:Use lowercased header names in h= tag (RFC 6376 §3.5)
        let signed_headers: Vec<String> = self
            .config
            .headers_to_sign
            .iter()
            .filter(|h| headers.contains_key(h.to_lowercase().as_str()))
            .map(|h| h.to_lowercase())
            .collect();

        let dkim_header = format!(
            "v=1; a=rsa-sha256; c=relaxed/relaxed; d={}; s={}; t={}; bh={}; h={}; b=",
            self.config.domain,
            self.config.selector,
            timestamp,
            body_hash,
            signed_headers.join(":")
        );

        // Canonicalize headers for signing
        let mut headers_to_hash: Vec<u8> = Vec::new();
        for header_name in &signed_headers {
            // header_name is already lowercased from #111 fix above
            if let Some(value) = headers.get(header_name.as_str()) {
                headers_to_hash.extend_from_slice(&self.canonicalize_header_relaxed(
                    header_name,
                    value,
                ));
            }
        }

        // Add DKIM-Signature header for signing:// #109:Only lowercase the header name per relaxed canonicalization (RFC 6376 §3.4.2)
        // Do NOT lowercase the header value — bh= contains case-sensitive base64
        let dkim_value_canonical = dkim_header.split_whitespace().collect::<Vec<_>>().join(" ");
        headers_to_hash.extend_from_slice(format!("dkim-signature:{}", dkim_value_canonical).as_bytes());

        // Sign
        let signing_key: SigningKey<Sha256> = SigningKey::new(self.private_key.clone());
        let signature = signing_key.sign(&headers_to_hash);
        let signature_b64 = BASE64.encode(signature.to_bytes());

        // Return complete DKIM-Signature header
        Ok(format!("DKIM-Signature: {}{}", dkim_header, signature_b64))
    }

    /// Parse headers into a map of lowercase name → raw value bytes.
    fn parse_headers(&self, headers_section: &[u8]) -> std::collections::HashMap<String, Vec<u8>> {
        let mut headers = std::collections::HashMap::new();
        let mut current_name = String::new();
        let mut current_value: Vec<u8> = Vec::new();

        for line in byte_lines(headers_section) {
            if line.first() == Some(&b' ') || line.first() == Some(&b'\t') {
                // Continuation of previous header (unfold with a single SP)
                current_value.push(b' ');
                current_value.extend_from_slice(trim_ascii_wsp(line));
            } else if let Some(colon_pos) = line.iter().position(|&b| b == b':') {
                // Save previous header
                if !current_name.is_empty() {
                    headers.insert(current_name.to_lowercase(), std::mem::take(&mut current_value));
                }
                // Start new header. Header names are ASCII; lossy conversion
                // never rewrites them.
                current_name = String::from_utf8_lossy(&line[..colon_pos]).into_owned();
                current_value = trim_ascii_wsp(&line[colon_pos + 1..]).to_vec();
            }
        }

        // Save last header
        if !current_name.is_empty() {
            headers.insert(current_name.to_lowercase(), current_value);
        }

        headers
    }

    /// Relaxed canonicalization for headers (RFC 6376 §3.4.2), byte-based.
    fn canonicalize_header_relaxed(&self, name: &str, value: &[u8]) -> Vec<u8> {
        let mut out = Vec::with_capacity(name.len() + value.len() + 4);
        out.extend_from_slice(name.to_lowercase().as_bytes());
        out.push(b':');
        // Collapse internal WSP runs to a single SP; drop leading/trailing WSP.
        out.extend_from_slice(&collapse_wsp(value));
        out.extend_from_slice(b"\r\n");
        out
    }

    /// Relaxed canonicalization for bodies (RFC 6376 §3.4.5), byte-based.
    ///
    /// Per line: (1) reduce every run of WSP (SP/TAB only — NOT other
    /// Unicode whitespace) to a single SP, including leading runs; (2) strip
    /// all trailing WSP. Lines are re-joined with CRLF; trailing empty lines
    /// are removed and the body always ends with exactly one CRLF (an empty
    /// body canonicalizes to a single CRLF).
    fn canonicalize_body_relaxed(&self, body: &[u8]) -> Vec<u8> {
        let mut result = Vec::with_capacity(body.len() + 2);

        for line in byte_lines(body) {
            result.extend_from_slice(&collapse_wsp_preserve_leading(line));
            result.extend_from_slice(b"\r\n");
        }

        // Remove trailing empty lines (all but the final CRLF).
        while result.ends_with(b"\r\n\r\n") {
            result.truncate(result.len() - 2);
        }
        // Ensure the canonical body ends with exactly one CRLF (also covers
        // the empty-body → CRLF case).
        if !result.ends_with(b"\r\n") {
            result.extend_from_slice(b"\r\n");
        }

        result
    }

    /// Get the DNS TXT record for this DKIM configuration
    pub fn get_dns_record(&self) -> String {
        format!("{}._domainkey.{}", self.config.selector, self.config.domain)
    }
}

#[cfg(unix)]
fn dkim_key_mode_is_group_or_world_readable(mode: u32) -> bool {
    mode & 0o044 != 0
}

/// Split raw bytes into lines (LF-separated, tolerating CRLF). Line
/// terminators are not included in the yielded slices; a trailing CR is
/// stripped so both CRLF and bare-LF inputs work.
fn byte_lines(input: &[u8]) -> Vec<&[u8]> {
    input
        .split(|&b| b == b'\n')
        .map(|line| {
            // Drop the last element if it is a CR.
            match line.split_last() {
                Some((&b'\r', rest)) => rest,
                _ => line,
            }
        })
        .collect()
}

/// Strip leading and trailing WSP (SP/TAB only — no Unicode whitespace).
fn trim_ascii_wsp(input: &[u8]) -> &[u8] {
    let start = input
        .iter()
        .position(|b| *b != b' ' && *b != b'\t')
        .unwrap_or(input.len());
    let end = input
        .iter()
        .rposition(|b| *b != b' ' && *b != b'\t')
        .map(|p| p + 1)
        .unwrap_or(start);
    &input[start..end]
}

/// Collapse WSP runs to a single SP, stripping leading/trailing WSP
/// (RFC 6376 §3.4.2 header value canonicalization).
fn collapse_wsp(input: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(input.len());
    let mut in_wsp = false;
    let mut emitted = false;
    for &b in trim_ascii_wsp(input) {
        if b == b' ' || b == b'\t' {
            in_wsp = true;
        } else {
            if in_wsp && emitted {
                out.push(b' ');
            }
            in_wsp = false;
            emitted = true;
            out.push(b);
        }
    }
    out
}

/// Collapse WSP runs to a single SP while PRESERVING a collapsed leading SP
/// (RFC 6376 §3.4.5 body canonicalization — leading WSP runs reduce to one
/// SP, they are not deleted) and stripping trailing WSP.
fn collapse_wsp_preserve_leading(line: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(line.len());
    let mut in_wsp = false;
    for &b in line {
        if b == b' ' || b == b'\t' {
            in_wsp = true;
        } else {
            if in_wsp {
                out.push(b' ');
                in_wsp = false;
            }
            out.push(b);
        }
    }
    out
}

/// Generate a new DKIM key pair
///
/// The private key is returned as a `Zeroizing<String>` to ensure the key
/// material is zeroized in memory when it goes out of scope.
pub fn generate_dkim_keypair() -> Result<(Zeroizing<String>, String)> {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::pkcs8::EncodePublicKey;
    use rsa::rand_core::OsRng;

    let mut rng = OsRng;
    let bits = 2048;

    let private_key = RsaPrivateKey::new(&mut rng, bits)
        .map_err(|e| anyhow!("Failed to generate RSA key: {}", e))?;

    let public_key = private_key.to_public_key();

    let private_pem = private_key
        .to_pkcs8_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| anyhow!("Failed to encode private key: {}", e))?;

    let public_pem = public_key
        .to_public_key_pem(rsa::pkcs8::LineEnding::LF)
        .map_err(|e| anyhow!("Failed to encode public key: {}", e))?;

    Ok((Zeroizing::new(private_pem.to_string()), public_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_body_relaxed() {
        let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048);
        assert!(private_key.is_ok());
        let Some(private_key) = private_key.ok() else {
            return;
        };
        let signer = DkimSigner {
            config: DkimConfig::default(),
            private_key,
        };

        let body = b"Hello  World\r\nThis is   a test  \r\n\r\n";
        let canonical = signer.canonicalize_body_relaxed(body);

        assert_eq!(canonical, b"Hello World\r\nThis is a test\r\n");
    }

    #[test]
    fn test_canonicalize_body_relaxed_rfc_6376() {
        let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let signer = DkimSigner {
            config: DkimConfig::default(),
            private_key,
        };

        // Leading WSP runs collapse to a single SP (NOT removed).
        assert_eq!(
            signer.canonicalize_body_relaxed(b" \t  indented\r\n"),
            b" indented\r\n"
        );
        // Tabs collapse like spaces.
        assert_eq!(
            signer.canonicalize_body_relaxed(b"a\t\tb\r\n"),
            b"a b\r\n"
        );
        // Empty body → single CRLF.
        assert_eq!(signer.canonicalize_body_relaxed(b""), b"\r\n");
        // Body of only empty lines → single CRLF.
        assert_eq!(signer.canonicalize_body_relaxed(b"\r\n\r\n\r\n"), b"\r\n");
        // Trailing empty lines removed, final CRLF kept exactly once.
        assert_eq!(
            signer.canonicalize_body_relaxed(b"body\r\n\r\n\r\n"),
            b"body\r\n"
        );
        // Non-breaking space (0xA0 / Unicode whitespace) is NOT WSP per RFC
        // and must be preserved byte-for-byte (fix for split_whitespace()
        // which collapsed Unicode whitespace).
        assert_eq!(
            signer.canonicalize_body_relaxed(b"caf\xc3\xa9\r\n"),
            b"caf\xc3\xa9\r\n"
        );
    }

    #[test]
    fn test_sign_handles_non_utf8_body_bytes() {
        // Invalid-UTF-8 body bytes must hash losslessly (no U+FFFD rewrite).
        let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap();
        let signer = DkimSigner {
            config: DkimConfig::default(),
            private_key,
        };
        let message = b"From: a@b.com\r\nSubject: s\r\n\r\n\xFF\xFE raw 8bit";
        assert!(signer.sign(message).is_ok());
    }

    #[test]
    fn test_dkim_config_implements_drop() {
        // Verify DkimConfig can be dropped without panic
        let config = DkimConfig {
            domain: "test.com".into(),
            selector: "sel".into(),
            private_key_pem: Zeroizing::new("test-key".to_string()),
            headers_to_sign: vec!["from".into()],
        };
        let _signer = DkimSigner {
            config,
            private_key: RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 2048).unwrap(),
        };
        // Drop is called here — should not panic
    }

    #[test]
    fn test_from_env_missing_var() {
        // Temporarily remove DKIM_PRIVATE_KEY if set
        let prev = std::env::var("DKIM_PRIVATE_KEY").ok();
        std::env::remove_var("DKIM_PRIVATE_KEY");

        let result = DkimSigner::from_env("test.com", "sel");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("DKIM_PRIVATE_KEY environment variable is not set"));

        // Restore
        if let Some(val) = prev {
            std::env::set_var("DKIM_PRIVATE_KEY", val);
        }
    }

    #[test]
    fn test_dkim_signer_rejects_rsa_keys_under_2048_bits() {
        use rsa::pkcs8::{EncodePrivateKey, LineEnding};

        let private_key = RsaPrivateKey::new(&mut rsa::rand_core::OsRng, 1024).unwrap();
        let private_key_pem = private_key
            .to_pkcs8_pem(LineEnding::LF)
            .unwrap()
            .to_string();
        let result = DkimSigner::new(DkimConfig {
            domain: "test.com".into(),
            selector: "sel".into(),
            private_key_pem: Zeroizing::new(private_key_pem),
            headers_to_sign: vec!["from".into()],
        });

        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("minimum: 2048 bits"));
    }

    #[cfg(unix)]
    #[test]
    fn test_dkim_key_mode_warns_on_group_or_world_readable() {
        assert!(!dkim_key_mode_is_group_or_world_readable(0o600));
        assert!(dkim_key_mode_is_group_or_world_readable(0o640));
        assert!(dkim_key_mode_is_group_or_world_readable(0o604));
        assert!(dkim_key_mode_is_group_or_world_readable(0o644));
    }
}
