//! ARC – Authenticated Received Chain (RFC 8617).
//!
//! Provides ARC header generation, chain validation, and parsing.

use base64::{engine::general_purpose::STANDARD as B64, Engine};
use chrono::Utc;
use rsa::pkcs1v15::SigningKey;
use rsa::{RsaPrivateKey, RsaPublicKey};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
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
///
/// `chain_key_lookup` resolves the public keys of the previous ARC sets'
/// domains so the Chain Validation Status (`cv=`) reflects real RFC 8617
/// cryptographic verification instead of failing closed.
pub fn generate_arc_headers(
    message_headers: &str, // #123:Raw message headers for AMS signing
    message_body: &[u8],
    auth_result: &ArcAuthResult,
    config: &ArcSigningConfig,
    existing_chain: &[ArcSet],
    chain_key_lookup: &dyn Fn(&str, &str) -> Option<RsaPublicKey>,
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

    // #123:Build proper AMS signing input – canonicalized headers listed in h= tag,
    // then the AMS header itself (with empty b=) per RFC 8617 §4.1.2 / RFC 6376 §3.7
    let h_list = ["from", "to", "subject", "date", "message-id"];
    let canonicalized_headers = extract_signing_headers(message_headers, &h_list);
    // The AMS header is signed in its relaxed-canonicalized form so that any
    // header folding/whitespace variant verifies identically.
    let canonicalized_ams = canonicalize_header_relaxed(&ams_template);
    let ams_signing_input = if canonicalized_headers.is_empty() {
        canonicalized_ams.clone()
    } else {
        format!("{}\r\n{}", canonicalized_headers, canonicalized_ams)
    };

    let ams_sig = {
        use rsa::signature::{SignatureEncoding, Signer};
        let sig = signing_key.sign(ams_signing_input.as_bytes());
        B64.encode(sig.to_bytes())
    };
    let ams = format!("{ams_template}{ams_sig}");

    // #125:Validate the existing chain with real cryptographic verification
    // (RFC 8617 §5.2). Without resolvable keys the chain fails closed.
    let chain_validation =
        match verify_arc_chain(existing_chain, message_headers, message_body, &|d, s| {
            chain_key_lookup(d, s)
        }) {
            ArcChainStatus::Pass => "pass",
            ArcChainStatus::None => "none",
            ArcChainStatus::Fail => "fail",
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

    // #124:Build proper seal signing input per RFC 8617 §5.1.1/§5.1.2.
    // On a valid prior chain the AS covers all previous ARC sets plus the
    // current AAR/AMS; on a broken chain (§5.1.2) it covers only the current set.
    let mut seal_signing_parts = Vec::new();
    if chain_validation == "pass" {
        for prev in existing_chain {
            seal_signing_parts.push(canonicalize_header_relaxed(&prev.authentication_results));
            seal_signing_parts.push(canonicalize_header_relaxed(&prev.message_signature));
            seal_signing_parts.push(canonicalize_header_relaxed(&prev.seal));
        }
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

/// Validate an ARC chain (RFC 8617 §5) with full cryptographic verification.
///
/// `key_lookup(domain, selector)` returns the DKIM public key for the AMS/AS
/// `d=`/`s=` pair. Any unresolvable key, malformed header, or failed
/// signature makes the whole chain `Fail` (RFC 8617 §5.2.1 – all failures
/// are permanent; the validator fails closed on any error).
pub fn verify_arc_chain(
    arc_sets: &[ArcSet],
    message_headers: &str,
    message_body: &[u8],
    key_lookup: &dyn Fn(&str, &str) -> Option<RsaPublicKey>,
) -> ArcChainStatus {
    if arc_sets.is_empty() {
        return ArcChainStatus::None;
    }

    // RFC 8617 §5.2 steps 1–3: bound the chain, check structure.
    if arc_sets.len() > 50 {
        warn!(count = arc_sets.len(), "ARC chain too long (max 50)");
        return ArcChainStatus::Fail;
    }

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

        if set.authentication_results.is_empty()
            || set.message_signature.is_empty()
            || set.seal.is_empty()
        {
            return ArcChainStatus::Fail;
        }

        // #126:Verify AMS b= tag is present and valid base64
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

        // #126:Verify seal b= tag is present and valid base64
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

        // #126:Verify cv= values throughout the chain (RFC 8617 §5.2 step 3c)
        let cv = extract_tag_value(&set.seal, "cv");
        if set.instance == 1 {
            if cv != Some("none") {
                warn!("ARC chain i=1 should have cv=none");
                return ArcChainStatus::Fail;
            }
        } else if cv != Some("pass") {
            warn!(
                instance = set.instance,
                "ARC chain intermediate seal should have cv=pass"
            );
            return ArcChainStatus::Fail;
        }
    }

    // RFC 8617 §5.2 step 4: cryptographically verify every AMS (we verify all
    // instances, not just the most recent, so any tampered link fails the chain).
    for set in arc_sets {
        if !verify_ams(set, message_headers, message_body, key_lookup) {
            warn!(
                instance = set.instance,
                "ARC AMS signature verification failed"
            );
            return ArcChainStatus::Fail;
        }
    }

    // RFC 8617 §5.2 step 6: cryptographically verify every AS, which covers
    // the prior ARC sets + the current AAR/AMS (RFC 8617 §5.1.1).
    for (idx, _set) in arc_sets.iter().enumerate() {
        if !verify_seal(arc_sets, idx, key_lookup) {
            warn!(
                instance = idx as u32 + 1,
                "ARC seal signature verification failed"
            );
            return ArcChainStatus::Fail;
        }
    }

    ArcChainStatus::Pass
}

/// Validate an ARC chain without a key source (fails closed: no keys → no Pass).
pub fn validate_arc_chain(arc_sets: &[ArcSet]) -> ArcChainStatus {
    verify_arc_chain(arc_sets, "", b"", &|_, _| None)
}

/// Verify one AMS signature (RFC 8617 §4.1.2, DKIM-formatted).
fn verify_ams(
    set: &ArcSet,
    message_headers: &str,
    message_body: &[u8],
    key_lookup: &dyn Fn(&str, &str) -> Option<RsaPublicKey>,
) -> bool {
    let header = &set.message_signature;
    let Some(domain) = extract_tag_value(header, "d") else {
        return false;
    };
    let Some(selector) = extract_tag_value(header, "s") else {
        return false;
    };
    if extract_tag_value(header, "a") != Some("rsa-sha256") {
        return false;
    }
    let Some(bh) = extract_tag_value(header, "bh") else {
        return false;
    };
    let Some(h_tag) = extract_tag_value(header, "h") else {
        return false;
    };
    let Some(sig_b64) = extract_tag_value(header, "b") else {
        return false;
    };

    let Some(public_key) = key_lookup(domain.trim(), selector.trim()) else {
        warn!(domain, selector, "No ARC public key for AMS");
        return false;
    };

    // Body hash check (RFC 6376 §3.7): bh= must match the relaxed-canonicalized body.
    let expected_bh = {
        let mut hasher = Sha256::new();
        hasher.update(canonicalize_body_relaxed(message_body));
        B64.encode(hasher.finalize())
    };
    let clean_bh: String = bh.chars().filter(|c| !c.is_ascii_whitespace()).collect();
    if clean_bh != expected_bh {
        warn!(instance = set.instance, "ARC AMS body hash mismatch");
        return false;
    }

    // Rebuild the signing input exactly as the sealer built it (RFC 8617 §4.1.2):
    // canonicalized h= message headers + relaxed-canonicalized AMS with empty b=.
    let h_names: Vec<&str> = h_tag
        .split(':')
        .map(str::trim)
        .filter(|n| !n.is_empty())
        .collect();
    let canonicalized_headers = extract_signing_headers(message_headers, &h_names);
    let canonicalized_ams = canonicalize_header_relaxed(&strip_b_signature(header));
    let signing_input = if canonicalized_headers.is_empty() {
        canonicalized_ams
    } else {
        format!("{}\r\n{}", canonicalized_headers, canonicalized_ams)
    };

    verify_rsa_sha256(public_key, signing_input.as_bytes(), sig_b64)
}

/// Verify one ARC-Seal signature (RFC 8617 §5.1.1).
fn verify_seal(
    arc_sets: &[ArcSet],
    idx: usize,
    key_lookup: &dyn Fn(&str, &str) -> Option<RsaPublicKey>,
) -> bool {
    let set = &arc_sets[idx];
    let header = &set.seal;
    let Some(domain) = extract_tag_value(header, "d") else {
        return false;
    };
    let Some(selector) = extract_tag_value(header, "s") else {
        return false;
    };
    if extract_tag_value(header, "a") != Some("rsa-sha256") {
        return false;
    }
    let Some(sig_b64) = extract_tag_value(header, "b") else {
        return false;
    };

    let Some(public_key) = key_lookup(domain.trim(), selector.trim()) else {
        warn!(domain, selector, "No ARC public key for seal");
        return false;
    };

    // RFC 8617 §5.1.1: prior sets (AAR, AMS, AS per instance, increasing order)
    // + current AAR + current AMS + AS with empty b=.
    let mut parts = Vec::new();
    for prev in &arc_sets[..idx] {
        parts.push(canonicalize_header_relaxed(&prev.authentication_results));
        parts.push(canonicalize_header_relaxed(&prev.message_signature));
        parts.push(canonicalize_header_relaxed(&prev.seal));
    }
    parts.push(canonicalize_header_relaxed(&set.authentication_results));
    parts.push(canonicalize_header_relaxed(&set.message_signature));
    parts.push(canonicalize_header_relaxed(&strip_b_signature(header)));
    let signing_input = parts.join("\r\n");

    verify_rsa_sha256(public_key, signing_input.as_bytes(), sig_b64)
}

/// Verify an RSA-SHA256 PKCS#1 v1.5 signature.
fn verify_rsa_sha256(public_key: RsaPublicKey, message: &[u8], sig_b64: &str) -> bool {
    use rsa::pkcs1v15::Signature;
    use rsa::pkcs1v15::VerifyingKey;
    use rsa::signature::Verifier;

    let clean: String = sig_b64
        .chars()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let Ok(sig_bytes) = B64.decode(&clean) else {
        return false;
    };
    let Ok(signature) = Signature::try_from(sig_bytes.as_slice()) else {
        return false;
    };
    let verifying_key = VerifyingKey::<Sha256>::new(public_key);
    verifying_key.verify(message, &signature).is_ok()
}

/// Return the header line with the `b=` signature value removed (kept through "b=").
/// The `b=` tag MUST be the last tag (RFC 6376 §3.5); any other layout fails closed.
fn strip_b_signature(header_line: &str) -> String {
    let value_start = header_line.find(':').map(|p| p + 1).unwrap_or(0);
    let mut last_semi = None;
    for (idx, ch) in header_line.char_indices() {
        if ch == ';' {
            last_semi = Some(idx);
        }
    }
    let tag_start = match last_semi {
        Some(idx) if idx + 1 > value_start => idx + 1,
        _ => value_start,
    };
    let tag = header_line[tag_start..].trim_start();
    if tag.starts_with("b=") {
        format!("{} b=", header_line[..tag_start].trim_end())
    } else {
        header_line.to_string()
    }
}

/// Parse ARC headers from raw header block.
/// #127:Handles RFC 2822 header folding (continuation lines starting with whitespace).
pub fn parse_arc_headers(raw_headers: &str) -> Vec<ArcSet> {
    let mut sets: std::collections::BTreeMap<u32, ArcSet> = std::collections::BTreeMap::new();

    // #127:Unfold headers first – join continuation lines starting with whitespace
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

/// #123:Canonicalize a single header field (relaxed algorithm per RFC 6376 §3.4.2).
fn canonicalize_header_relaxed(header_line: &str) -> String {
    if let Some((name, value)) = header_line.split_once(':') {
        let canon_name = name.trim().to_lowercase();
        let canon_value = value.split_whitespace().collect::<Vec<_>>().join(" ");
        format!("{}:{}", canon_name, canon_value)
    } else {
        header_line.to_string()
    }
}

/// #123:Extract and canonicalize headers listed in the h= tag from raw message headers.
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

/// #126:Extract the value of a specific tag (e.g. "b", "cv") from an ARC header.
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

/// #127:Unfold RFC 2822 headers (join continuation lines starting with whitespace).
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
        assert_eq!(validate_arc_chain(&[set]), ArcChainStatus::Fail);
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
        assert_eq!(validate_arc_chain(&sets), ArcChainStatus::Fail);
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
        // #127:Folded header should be unfolded and parsed correctly
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

    // ── FIX-C (H12): real RFC 8617 cryptographic verification ─────────────

    fn test_config(private_key: RsaPrivateKey) -> ArcSigningConfig {
        ArcSigningConfig {
            domain: "example.com".into(),
            selector: "sel1".into(),
            private_key,
        }
    }

    fn test_auth_result() -> ArcAuthResult {
        ArcAuthResult {
            spf: "pass".into(),
            dkim: "pass".into(),
            dmarc: "pass".into(),
        }
    }

    const TEST_HEADERS: &str = "From: alice@example.com\r\nTo: bob@example.org\r\nSubject: hello\r\nDate: Thu, 1 Jan 2026 00:00:00 +0000\r\nMessage-ID: <abc@example.com>";

    fn test_keys() -> (RsaPrivateKey, RsaPublicKey) {
        let mut rng = rsa::rand_core::OsRng;
        let private_key = RsaPrivateKey::new(&mut rng, 2048).expect("generate RSA key");
        let public_key = private_key.to_public_key();
        (private_key, public_key)
    }

    fn test_lookup(public_key: RsaPublicKey) -> impl Fn(&str, &str) -> Option<RsaPublicKey> {
        move |d, s| {
            if d == "example.com" && s == "sel1" {
                Some(public_key.clone())
            } else {
                None
            }
        }
    }

    #[test]
    fn test_verify_arc_chain_signed_chain_passes() {
        let (private_key, public_key) = test_keys();
        let config = test_config(private_key);
        let lookup = test_lookup(public_key);

        let set = generate_arc_headers(
            TEST_HEADERS,
            b"Hello world\r\n",
            &test_auth_result(),
            &config,
            &[],
            &lookup,
        )
        .expect("generate ARC set");
        assert_eq!(set.instance, 1);

        let status = verify_arc_chain(&[set], TEST_HEADERS, b"Hello world\r\n", &lookup);
        assert_eq!(status, ArcChainStatus::Pass);
    }

    #[test]
    fn test_verify_arc_chain_two_sets_seal_covers_prior_set() {
        let (private_key, public_key) = test_keys();
        let config = test_config(private_key);
        let lookup = test_lookup(public_key);

        let set1 = generate_arc_headers(
            TEST_HEADERS,
            b"Hello world\r\n",
            &test_auth_result(),
            &config,
            &[],
            &lookup,
        )
        .expect("generate set 1");
        let set2 = generate_arc_headers(
            TEST_HEADERS,
            b"Hello world\r\n",
            &test_auth_result(),
            &config,
            std::slice::from_ref(&set1),
            &lookup,
        )
        .expect("generate set 2");
        assert_eq!(set2.instance, 2);
        // The generated seal must have validated the prior chain → cv=pass
        assert!(
            set2.seal.contains("cv=pass"),
            "seal cv should be pass for a valid prior chain: {}",
            set2.seal
        );

        let status = verify_arc_chain(&[set1, set2], TEST_HEADERS, b"Hello world\r\n", &lookup);
        assert_eq!(status, ArcChainStatus::Pass);
    }

    #[test]
    fn test_verify_arc_chain_tampered_byte_fails() {
        let (private_key, public_key) = test_keys();
        let config = test_config(private_key);
        let lookup = test_lookup(public_key);

        let set1 = generate_arc_headers(
            TEST_HEADERS,
            b"Hello world\r\n",
            &test_auth_result(),
            &config,
            &[],
            &lookup,
        )
        .expect("generate set 1");
        let set2 = generate_arc_headers(
            TEST_HEADERS,
            b"Hello world\r\n",
            &test_auth_result(),
            &config,
            std::slice::from_ref(&set1),
            &lookup,
        )
        .expect("generate set 2");

        // Tamper one byte of the i=1 AMS signature: set 2's seal covers it,
        // so the whole chain must fail.
        let mut tampered = set1.clone();
        let b_value = extract_tag_value(&tampered.message_signature, "b")
            .unwrap()
            .to_string();
        let mut chars: Vec<char> = b_value.chars().collect();
        let last = chars.last_mut().unwrap();
        *last = if *last == 'A' { 'B' } else { 'A' };
        let new_b: String = chars.into_iter().collect();
        tampered.message_signature = tampered
            .message_signature
            .replace(b_value.as_str(), new_b.as_str());

        assert_ne!(tampered.message_signature, set1.message_signature);

        let status = verify_arc_chain(&[tampered, set2], TEST_HEADERS, b"Hello world\r\n", &lookup);
        assert_eq!(status, ArcChainStatus::Fail);
    }

    #[test]
    fn test_verify_arc_chain_wrong_domain_fails() {
        let (private_key, public_key) = test_keys();
        let config = test_config(private_key);

        let set = generate_arc_headers(
            TEST_HEADERS,
            b"Hello world\r\n",
            &test_auth_result(),
            &config,
            &[],
            &|_, _| None,
        )
        .expect("generate ARC set");

        // Only an unrelated domain has a key → d=example.com lookup returns None.
        let wrong_domain_lookup = move |d: &str, s: &str| {
            if d == "attacker.com" && s == "sel1" {
                Some(public_key.clone())
            } else {
                None
            }
        };
        let status = verify_arc_chain(
            &[set],
            TEST_HEADERS,
            b"Hello world\r\n",
            &wrong_domain_lookup,
        );
        assert_eq!(status, ArcChainStatus::Fail);
    }

    #[test]
    fn test_verify_arc_chain_instance_order_violation_fails() {
        let (private_key, public_key) = test_keys();
        let config = test_config(private_key);
        let lookup = test_lookup(public_key);

        let set1 = generate_arc_headers(
            TEST_HEADERS,
            b"Hello world\r\n",
            &test_auth_result(),
            &config,
            &[],
            &lookup,
        )
        .expect("generate set 1");
        let set2 = generate_arc_headers(
            TEST_HEADERS,
            b"Hello world\r\n",
            &test_auth_result(),
            &config,
            std::slice::from_ref(&set1),
            &lookup,
        )
        .expect("generate set 2");

        // Reversed order: instance 2 appears first → sequence violation.
        let status = verify_arc_chain(&[set2, set1], TEST_HEADERS, b"Hello world\r\n", &lookup);
        assert_eq!(status, ArcChainStatus::Fail);
    }

    #[test]
    fn test_verify_arc_chain_tampered_body_fails() {
        let (private_key, public_key) = test_keys();
        let config = test_config(private_key);
        let lookup = test_lookup(public_key);

        let set = generate_arc_headers(
            TEST_HEADERS,
            b"Hello world\r\n",
            &test_auth_result(),
            &config,
            &[],
            &lookup,
        )
        .expect("generate ARC set");

        // bh= covers the body: a changed body must break the chain.
        let status = verify_arc_chain(&[set], TEST_HEADERS, b"Goodbye world\r\n", &lookup);
        assert_eq!(status, ArcChainStatus::Fail);
    }

    #[test]
    fn test_validate_arc_chain_fails_closed_without_keys() {
        // Without a key source a real (structurally valid) chain must still
        // fail closed — Pass requires cryptographic proof.
        let (private_key, _public_key) = test_keys();
        let config = test_config(private_key);
        let set = generate_arc_headers(
            TEST_HEADERS,
            b"Hello world\r\n",
            &test_auth_result(),
            &config,
            &[],
            &|_, _| None,
        )
        .expect("generate ARC set");
        assert_eq!(validate_arc_chain(&[set]), ArcChainStatus::Fail);
    }
}
