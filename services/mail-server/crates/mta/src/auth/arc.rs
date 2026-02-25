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
use tracing::warn;

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
    message_headers: &str,     // #123: Raw message headers for AMS signing
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

    // 2. ARC-Message-Signature (AMS) – sign canonicalized message headers + body hash
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

    // #123: Build proper AMS signing input – canonicalized headers listed in h= tag,
    // then the AMS header itself (with empty b=) per RFC 8617 §5.1
    let h_list = ["from", "to", "subject", "date", "message-id"];
    let canonicalized_headers = extract_signing_headers(message_headers, &h_list);
    let ams_signing_input = if canonicalized_headers.is_empty() {
        ams_template.clone()
    } else {
        format!("{}\r\n{}", canonicalized_headers, ams_template)
    };

    let ams_sig = {
        use rsa::signature::{SignatureEncoding, Signer};
        let sig = signing_key.sign(ams_signing_input.as_bytes());
        B64.encode(sig.to_bytes())
    };
    let ams = format!("{ams_template}{ams_sig}");

    // #125: Actually validate existing chain instead of hardcoding "pass"
    let chain_validation = if existing_chain.is_empty() {
        "none"
    } else {
        match validate_arc_chain(existing_chain) {
            ArcChainStatus::Pass => "pass",
            _ => "fail",
        }
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

    // #124: Build proper seal signing input – all previous ARC headers + current AAR/AMS
    // + seal template (with empty b=) per RFC 8617 §5.1.2
    let mut seal_signing_parts = Vec::new();
    for prev in existing_chain {
        seal_signing_parts.push(canonicalize_header_relaxed(&prev.authentication_results));
        seal_signing_parts.push(canonicalize_header_relaxed(&prev.message_signature));
        seal_signing_parts.push(canonicalize_header_relaxed(&prev.seal));
    }
    seal_signing_parts.push(canonicalize_header_relaxed(&aar));
    seal_signing_parts.push(canonicalize_header_relaxed(&ams));
    seal_signing_parts.push(canonicalize_header_relaxed(&seal_template));
    let seal_signing_input = seal_signing_parts.join("\r\n");

    let seal_sig = {
        use rsa::signature::{SignatureEncoding, Signer};
        let sig = signing_key.sign(seal_signing_input.as_bytes());
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
        let expected = i as u32 + 1;
        if set.instance != expected {
            warn!(
                expected = expected,
                got = set.instance,
                "ARC chain instance mismatch"
            );
            return ArcChainStatus::Fail;
        }
    }

    // Check all sets have non-empty fields and valid structure
    for set in arc_sets {
        if set.authentication_results.is_empty()
            || set.message_signature.is_empty()
            || set.seal.is_empty()
        {
            return ArcChainStatus::Fail;
        }

        // #126: Verify AMS b= tag is present and valid base64
        match extract_tag_value(&set.message_signature, "b") {
            Some(sig) if !sig.is_empty() => {
                let clean: String = sig.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                if B64.decode(&clean).is_err() {
                    warn!(instance = set.instance, "AMS b= is not valid base64");
                    return ArcChainStatus::Fail;
                }
            }
            _ => {
                warn!(instance = set.instance, "AMS missing b= tag");
                return ArcChainStatus::Fail;
            }
        }

        // #126: Verify seal b= tag is present and valid base64
        match extract_tag_value(&set.seal, "b") {
            Some(sig) if !sig.is_empty() => {
                let clean: String = sig.chars().filter(|c| !c.is_ascii_whitespace()).collect();
                if B64.decode(&clean).is_err() {
                    warn!(instance = set.instance, "ARC-Seal b= is not valid base64");
                    return ArcChainStatus::Fail;
                }
            }
            _ => {
                warn!(instance = set.instance, "ARC-Seal missing b= tag");
                return ArcChainStatus::Fail;
            }
        }

        // #126: Verify cv= values throughout the chain
        let cv = extract_tag_value(&set.seal, "cv");
        if set.instance == 1 {
            if cv != Some("none") {
                warn!("ARC chain i=1 should have cv=none");
                return ArcChainStatus::Fail;
            }
        } else if cv != Some("pass") {
            warn!(instance = set.instance, "ARC chain intermediate seal should have cv=pass");
            return ArcChainStatus::Fail;
        }
    }

    // NOTE: Full cryptographic verification of AMS/AS signatures requires
    // fetching RSA public keys via DNS (selector._domainkey.domain) for each set.
    // Structural + base64 validation only.

    ArcChainStatus::Pass
}

/// Parse ARC headers from raw header block.
/// #127: Handles RFC 2822 header folding (continuation lines starting with whitespace).
pub fn parse_arc_headers(raw_headers: &str) -> Vec<ArcSet> {
    let mut sets: std::collections::BTreeMap<u32, ArcSet> = std::collections::BTreeMap::new();

    // #127: Unfold headers first – join continuation lines starting with whitespace
    let unfolded = unfold_headers(raw_headers);

    for line in unfolded.split("\r\n") {
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

/// #123: Canonicalize a single header field (relaxed algorithm per RFC 6376 §3.4.2).
fn canonicalize_header_relaxed(header_line: &str) -> String {
    if let Some((name, value)) = header_line.split_once(':') {
        let canon_name = name.trim().to_lowercase();
        let canon_value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        format!("{}:{}", canon_name, canon_value)
    } else {
        header_line.to_string()
    }
}

/// #123: Extract and canonicalize headers listed in the h= tag from raw message headers.
fn extract_signing_headers(raw_headers: &str, h_list: &[&str]) -> String {
    let unfolded = unfold_headers(raw_headers);
    let mut result = Vec::new();

    for &name in h_list {
        let lower_name = name.to_lowercase();
        let mut found = None;
        for line in unfolded.split("\r\n") {
            if let Some((hdr_name, _)) = line.split_once(':') {
                if hdr_name.trim().to_lowercase() == lower_name {
                    found = Some(line.to_string());
                }
            }
        }
        if let Some(header_line) = found {
            result.push(canonicalize_header_relaxed(&header_line));
        }
    }

    result.join("\r\n")
}

/// #126: Extract the value of a specific tag (e.g. "b", "cv") from an ARC header.
fn extract_tag_value<'a>(header: &'a str, tag: &str) -> Option<&'a str> {
    let body = header.split_once(':').map(|(_, v)| v).unwrap_or(header);
    let tag_prefix = format!("{}=", tag);
    for part in body.split(';') {
        let trimmed = part.trim();
        if let Some(val) = trimmed.strip_prefix(&tag_prefix) {
            return Some(val.trim());
        }
    }
    None
}

/// #127: Unfold RFC 2822 headers (join continuation lines starting with whitespace).
fn unfold_headers(raw: &str) -> String {
    let mut result = String::with_capacity(raw.len());
    for line in raw.split("\r\n") {
        if line.starts_with(' ') || line.starts_with('\t') {
            // Continuation line – replace fold with single space
            result.push(' ');
            result.push_str(line.trim_start());
        } else {
            if !result.is_empty() {
                result.push_str("\r\n");
            }
            result.push_str(line);
        }
    }
    result
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
    fn test_parse_arc_headers_folded() {
        // #127: Folded header should be unfolded and parsed correctly
        let raw = "ARC-Seal: i=1; cv=none;\r\n\tb=abc\r\nARC-Message-Signature: i=1;\r\n a=rsa-sha256; b=def\r\nARC-Authentication-Results: i=1; mx.test; spf=pass";
        let sets = parse_arc_headers(raw);
        assert_eq!(sets.len(), 1);
        assert_eq!(sets[0].instance, 1);
        assert!(sets[0].seal.contains("b=abc"));
    }

    #[test]
    fn test_extract_tag_value() {
        let header = "ARC-Seal: i=1; cv=none; b=abc123";
        assert_eq!(extract_tag_value(header, "cv"), Some("none"));
        assert_eq!(extract_tag_value(header, "b"), Some("abc123"));
        assert_eq!(extract_tag_value(header, "i"), Some("1"));
        assert_eq!(extract_tag_value(header, "missing"), None);
    }

    #[test]
    fn test_unfold_headers() {
        let raw = "From: test@example.com\r\nARC-Seal: i=1;\r\n\tcv=none;\r\n\tb=abc";
        let unfolded = unfold_headers(raw);
        assert!(unfolded.contains("ARC-Seal: i=1; cv=none; b=abc"));
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
