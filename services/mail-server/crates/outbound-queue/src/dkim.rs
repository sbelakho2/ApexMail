//! DKIM Signing
//!
//! Signs outbound emails with DKIM for authentication.

use anyhow::{anyhow, Result};
use base64::{engine::general_purpose::STANDARD as BASE64, Engine as _};
use rsa::pkcs1v15::SigningKey;
use rsa::signature::{SignatureEncoding, Signer};
use rsa::{pkcs8::DecodePrivateKey, RsaPrivateKey};
use sha2::{Digest, Sha256};
use tracing::debug;

/// DKIM Configuration
#[derive(Debug, Clone)]
pub struct DkimConfig {
    pub domain: String,
    pub selector: String,
    pub private_key_pem: String,
    pub headers_to_sign: Vec<String>,
}

impl Default for DkimConfig {
    fn default() -> Self {
        Self {
            domain: "apexmail.ee".to_string(),
            selector: "apexmail2026".to_string(),
            private_key_pem: String::new(),
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
pub struct DkimSigner {
    config: DkimConfig,
    private_key: RsaPrivateKey,
}

impl DkimSigner {
    /// Create a new DKIM signer
    pub fn new(config: DkimConfig) -> Result<Self> {
        let private_key = RsaPrivateKey::from_pkcs8_pem(&config.private_key_pem)
            .map_err(|e| anyhow!("Failed to parse DKIM private key: {}", e))?;

        debug!(domain = %config.domain, selector = %config.selector, "DKIM signer initialized");

        Ok(Self {
            config,
            private_key,
        })
    }

    /// Load DKIM signer from file
    pub async fn from_file(domain: &str, selector: &str, key_path: &str) -> Result<Self> {
        let private_key_pem = tokio::fs::read_to_string(key_path)
            .await
            .map_err(|e| anyhow!("Failed to read DKIM key file: {}", e))?;

        let config = DkimConfig {
            domain: domain.to_string(),
            selector: selector.to_string(),
            private_key_pem,
            ..Default::default()
        };

        Self::new(config)
    }

    /// Sign an email message
    pub fn sign(&self, message: &[u8]) -> Result<String> {
        let message_str = String::from_utf8_lossy(message);

        // Split headers and body
        let (headers_section, body) = match message_str.find("\r\n\r\n") {
            Some(pos) => (&message_str[..pos], &message_str[pos + 4..]),
            None => (message_str.as_ref(), ""),
        };

        // Parse headers
        let headers = self.parse_headers(headers_section);

        // Compute body hash (relaxed canonicalization)
        let canonical_body = self.canonicalize_body_relaxed(body);
        let body_hash = {
            let mut hasher = Sha256::new();
            hasher.update(canonical_body.as_bytes());
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
        let mut headers_to_hash = String::new();
        for header_name in &signed_headers {
            // header_name is already lowercased from #111 fix above
            if let Some(value) = headers.get(header_name.as_str()) {
                let canonical = self.canonicalize_header_relaxed(header_name, value);
                headers_to_hash.push_str(&canonical);
            }
        }

        // Add DKIM-Signature header for signing:// #109:Only lowercase the header name per relaxed canonicalization (RFC 6376 §3.4.2)
        // Do NOT lowercase the header value — bh= contains case-sensitive base64
        let dkim_value_canonical = dkim_header.split_whitespace().collect::<Vec<_>>().join(" ");
        headers_to_hash.push_str(&format!("dkim-signature:{}", dkim_value_canonical));

        // Sign
        let signing_key: SigningKey<Sha256> = SigningKey::new(self.private_key.clone());
        let signature = signing_key.sign(headers_to_hash.as_bytes());
        let signature_b64 = BASE64.encode(signature.to_bytes());

        // Return complete DKIM-Signature header
        Ok(format!("DKIM-Signature: {}{}", dkim_header, signature_b64))
    }

    /// Parse headers into a map
    fn parse_headers(&self, headers_section: &str) -> std::collections::HashMap<String, String> {
        let mut headers = std::collections::HashMap::new();
        let mut current_name = String::new();
        let mut current_value = String::new();

        for line in headers_section.lines() {
            if line.starts_with(' ') || line.starts_with('\t') {
                // Continuation of previous header
                current_value.push(' ');
                current_value.push_str(line.trim());
            } else if let Some(colon_pos) = line.find(':') {
                // Save previous header
                if !current_name.is_empty() {
                    headers.insert(current_name.to_lowercase(), current_value);
                }
                // Start new header
                current_name = line[..colon_pos].to_string();
                current_value = line[colon_pos + 1..].trim().to_string();
            }
        }

        // Save last header
        if !current_name.is_empty() {
            headers.insert(current_name.to_lowercase(), current_value);
        }

        headers
    }

    /// Relaxed canonicalization for headers
    fn canonicalize_header_relaxed(&self, name: &str, value: &str) -> String {
        let canonical_name = name.to_lowercase();
        let canonical_value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        format!("{}:{}\r\n", canonical_name, canonical_value)
    }

    /// Relaxed canonicalization for body
    fn canonicalize_body_relaxed(&self, body: &str) -> String {
        let mut result = String::new();

        for line in body.lines() {
            // Remove trailing whitespace from each line
            let trimmed = line.trim_end();
            // Reduce sequences of whitespace to single space
            let canonical: String = trimmed.split_whitespace().collect::<Vec<_>>().join(" ");
            result.push_str(&canonical);
            result.push_str("\r\n");
        }

        // Remove trailing empty lines, but ensure at least one CRLF
        let trimmed = result.trim_end_matches("\r\n");
        if trimmed.is_empty() {
            "\r\n".to_string()
        } else {
            format!("{}\r\n", trimmed)
        }
    }

    /// Get the DNS TXT record for this DKIM configuration
    pub fn get_dns_record(&self) -> String {
        format!("{}._domainkey.{}", self.config.selector, self.config.domain)
    }
}

/// Generate a new DKIM key pair
pub fn generate_dkim_keypair() -> Result<(String, String)> {
    use rsa::pkcs8::EncodePrivateKey;
    use rsa::pkcs8::EncodePublicKey;

    let mut rng = rand::thread_rng();
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

    Ok((private_pem.to_string(), public_pem))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_canonicalize_body_relaxed() {
        let private_key = RsaPrivateKey::new(&mut rand::thread_rng(), 2048);
        assert!(private_key.is_ok());
        let Some(private_key) = private_key.ok() else {
            return;
        };
        let signer = DkimSigner {
            config: DkimConfig::default(),
            private_key,
        };

        let body = "Hello  World\r\nThis is   a test  \r\n\r\n";
        let canonical = signer.canonicalize_body_relaxed(body);

        assert_eq!(canonical, "Hello World\r\nThis is a test\r\n");
    }
}
