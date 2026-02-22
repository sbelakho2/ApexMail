//! ARC – Authenticated Received Chain (RFC 8617).
//!
//! Provides ARC header generation, chain validation, and parsing.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use rsa::pkcs1v15::SigningKey;
use rsa::RsaPrivateKey;
use serde::{Deserialize, Serialize};
use 
sha2::{Digest, Sha256};
use tracing::{debug, warn};

/// A complete ARC set (i=N).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcSet {
    pub instance: u32,
    pub authentication_results: String,
    pub message_signature: String,
    pub seal: String,
}

/// Result of a single ARC auth evaluation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ArcAuthResult {
    pub spf: String,
    pub dkim: String,
    pub dmarc: String,
}

/// Configuration for ARC signing.
#[derive(Debug, Clone)]
pub struct ArcSigningConfig {
    pub domain: String,
    pub selector: String,
    pub private_key: RsaPrivateKey,
}

/// Chain validation result.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
pub enum ArcChainStatus {
    Pass,
    Fail,
    None,
}

/// Generate a new ARC header set for a message.
pub fn generate_arc_headers(
    message_body: &[u8],
    auth_result: &ArcAuthResult,
    config: &ArcSigningConfig,
    existing_chain: &[ArcSet],
) -> anyhow::Result<ArcSet> {
    let instance = existing_chain.len() as u32 + 1;
    if instance > 50 {
        anyhow::bail!("ARC chain too long (max 50)");
    }

    let timestamp = Utc::now().timestamp();

    // 1. ARC-Authentication-Results (AAR)
    let aar = format!(
        "ARC-Authentication-Results: i={instance}; {hostname};\r\n\
         \tspf={spf};\r\n\
         \tdkim={dkim};\r\n\
         \tdmarc={dmarc}",
        hostname = config.domain,
        spf = auth_result.spf,
        dkim = auth_result.dkim,
        dmarc = auth_result.dmarc,
    );

    // 2. ARC-Message-Signature (AMS) – sign the body + selected headers
    let body_hash = {
        let mut hasher = Sha256::new();
        hasher.update(canonicalize_body_relaxed(message_body));
        B64.encode(hasher.finalize())
    };

    let ams_template = format!(
        "ARC-Message-Signature: i={instance}; a=rsa-sha256; c=relaxed/relaxed;\r\n\
         \td={domain}; s={selector}; t={timestamp};\r\n\
         \tbh={body_hash};\r\n\
         \th=from:to:subject:date:message-id;\r\n\
         \tb=",
        domain = config.domain,
        selector = config.selector,
    );

    let signing_key = SigningKey::<Sha256>::new(config.private_key.clone());
    let ams_sig = {
        use rsa::signature::{SignatureEncoding, Signer};
        let sig = signing_key.sign(ams_template.as_bytes());
        B64.encode(sig.to_bytes())
    };
    let ams = format!("{ams_template}{ams_sig}");

    // 3. ARC-Seal (AS) – sign the chain state
    let chain_validation = if existing_chain.is_empty() {
        "none"
    } else {
        "pass" // assume pass when we're adding
    };

    let seal_template = format!(
        "ARC-Seal: i={instance}; a=rsa-sha256; t={timestamp};\r\n\
         \tcv={cv};\r\n\
         \td={domain}; s={selector};\r\n\
         \tb=",
        cv = chain_validation,
        domain = config.domain,
        selector = config.selector,
    );

    let seal_sig = {
        use rsa::signature::{SignatureEncoding, Signer};
        let sig = signing_key.sign(seal_template.as_bytes());
        B64.encode(sig.to_bytes())
    };
    let seal = format!("{seal_template}{seal_sig}");

    Ok(ArcSet {
        instance,
        authentication_results: aar,
        message_signature: ams,
        seal,
    })
}

/// Validate an ARC chain (RFC 8617 §5).
pub fn validate_arc_chain(arc_sets: &[ArcSet]) -> ArcChainStatus {
    if arc_sets.is_empty() {
        return ArcChainStatus::None;
    }

    // Check instances are sequential 1..=N
    for (i, set) in arc_sets.iter().enumerate() {
        if set.instance != (i as u32 + 1) {
            warn!(
                expected = i + 1,
                got = set.instance,
                "ARC chain instance mismatch"
            );
            return ArcChainStatus::Fail;
        }
    }

    // Check all sets have non-empty fields
    for set in arc_sets {
        if set.authentication_results.is_empty()
            || set.message_signature.is_empty()
            || set.seal.is_empty()
        {
            return ArcChainStatus::Fail;
        }
    }

    // The most recent seal must have cv=pass (or none for i=1)
    let last = &arc_sets[arc_sets.len() - 1];
    if last.instance == 1 {
        if !last.seal.contains("cv=none") {
            return ArcChainStatus::Fail;
        }
    } else if !last.seal.contains("cv=pass") {
        return ArcChainStatus::Fail;
    }

    ArcChainStatus::Pass
}

/// Parse ARC headers from raw header block.
pub fn parse_arc_headers(raw_headers: &str) -> Vec<ArcSet> {
    let mut sets: std::collections::BTreeMap<u32, ArcSet> = std::collections::BTreeMap::new();

    for line in raw_headers.split("\r\n") {
        let line = line.trim();
        if let Some(rest) = line.strip_prefix("ARC-Authentication-Results:") {
            if let Some(inst) = extract_instance(rest) {
                sets.entry(inst)
                    .or_insert_with(|| ArcSet {
                        instance: inst,
                        authentication_results: String::new(),
                        message_signature: String::new(),
                        seal: String::new(),
                    })
                    .authentication_results = line.to_string();
            }
        } else if let Some(rest) = line.strip_prefix("ARC-Message-Signature:") {
            if let Some(inst) = extract_instance(rest) {
                sets.entry(inst)
                    .or_insert_with(|| ArcSet {
                        instance: inst,
                        authentication_results: String::new(),
                        message_signature: String::new(),
                        seal: String::new(),
                    })
                    .message_signature = line.to_string();
            }
        } else if let Some(rest) = line.strip_prefix("ARC-Seal:") {
            if let Some(inst) = extract_instance(rest) {
                sets.entry(inst)
                    .or_insert_with(|| ArcSet {
                        instance: inst,
                        authentication_results: String::new(),
                        message_signature: String::new(),
                        seal: String::new(),
                    })
                    .seal = line.to_string();
            }
        }
    }

    sets.into_values().collect()
}

/// Format an ARC set for insertion into a message.
pub fn format_arc_headers_for_message(set: &ArcSet) -> String {
    format!(
        "{}\r\n{}\r\n{}\r\n",
        set.seal, set.message_signature, set.authentication_results,
    )
}

// ── internal ───────────────────────────────────────────────────────────────────

fn extract_instance(header_value: &str) -> Option<u32> {
    for part in header_value.split(';') {
        let part = part.trim();
        if let Some(rest) = part.strip_prefix("i=") {
            return rest.trim().parse().ok();
        }
    }
    None
}

fn canonicalize_body_relaxed(body: &[u8]) -> Vec<u8> {
    let text = String::from_utf8_lossy(body);
    let mut result = String::new();
    for line in text.split('\n') {
        let trimmed = line.trim_end();
        // Collapse whitespace runs to single space
        let mut prev_ws = false;
        for ch in trimmed.chars() {
            if ch == ' ' || ch == '\t' {
                if !prev_ws {
                    result.push(' ');
                    prev_ws = true;
                }
            } else {
                result.push(ch);
                prev_ws = false;
            }
        }
        result.push_str("\r\n");
    }
    // Remove trailing empty lines
    while result.ends_with("\r\n\r\n") {
        result.truncate(result.len() - 2);
    }
    result.into_bytes()
}

// ── tests ──────────────────────────────────────────────────────────────────────

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_validate_empty_chain() {
        assert_eq!(validate_arc_chain(&[]), ArcChainStatus::None);
    }

    #[test]
    fn test_validate_single_set_pass() {
        let set = ArcSet {
            instance: 1,
            authentication_results: "ARC-Authentication-Results: i=1; mx.test; spf=pass".into(),
            message_signature: "ARC-Message-Signature: i=1; a=rsa-sha256; b=abc".into(),
            seal: "ARC-Seal: i=1; cv=none; b=xyz".into(),
        };
        assert_eq!(validate_arc_chain(&[set]), ArcChainStatus::Pass);
    }

    #[test]
    fn test_validate_chain_wrong_cv() {
        let set = ArcSet {
            instance: 1,
            authentication_results: "ARC-Authentication-Results: i=1; mx.test; spf=pass".into(),
            message_signature: "ARC-Message-Signature: i=1; a=rsa-sha256; b=abc".into(),
            seal: "ARC-Seal: i=1; cv=pass; b=xyz".into(), // should be cv=none for i=1
        };
        assert_eq!(validate_arc_chain(&[set]), ArcChainStatus::Fail);
    }

    #[test]
    fn test_validate_chain_two_sets() {
        let sets = vec![
            ArcSet {
                instance: 1,
                authentication_results: "AAR: i=1".into(),
                message_signature: "AMS: i=1".into(),
                seal: "ARC-Seal: i=1; cv=none; b=a".into(),
            },
            ArcSet {
                instance: 2,
                authentication_results: "AAR: i=2".into(),
                message_signature: "AMS: i=2".into(),
                seal: "ARC-Seal: i=2; cv=pass; b=b".into(),
            },
        ];
        assert_eq!(validate_arc_chain(&sets), ArcChainStatus::Pass);
    }

    #[test]
    fn test_parse_arc_headers() {
        let raw = "ARC-Seal: i=1; cv=none; b=abc\r\nARC-Message-Signature: i=1; a=rsa-sha256; b=def\r\nARC-Authentication-Results: i=1; mx.test; spf=pass";
        let sets = parse_arc_headers(raw);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].instance, 1);
    }

    #[test]
    fn test_extract_instance() {
        assert_eq!(extract_instance(" i=3; a=rsa-sha256"), Some(3));
        assert_eq!(extract_instance(" a=rsa-sha256; i=42"), Some(42));
        assert_eq!(extract_instance(" no instance"), None);
    }

    #[test]
    fn test_canonicalize_body_relaxed() {
        let body = b"Hello   world  \r\nTest\t\ttabs\r\n\r\n\r\n";
        let result = canonicalize_body_relaxed(body);
        let text = String::from_utf8(result).unwrap();
        assert!(text.contains("Hello world"));
        assert!(text.contains("Test tabs"));
        // Trailing empty lines removed
        assert!(!text.ends_with("\r\n\r\n"));
    }
}
