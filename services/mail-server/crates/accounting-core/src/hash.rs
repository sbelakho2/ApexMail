//! Evidence hashing for source documents and journal entries.
//!
//! Every entry and every source document carries a sha256 hex digest. The
//! hash is computed over length-prefixed parts so no concatenation ambiguity
//! exists ("ab" + "c" never collides with "a" + "bc").

use sha2::{Digest, Sha256};

/// sha256 hex over length-prefixed UTF-8 parts.
pub fn evidence_hash(parts: &[&str]) -> String {
    let mut hasher = Sha256::new();
    for part in parts {
        hasher.update((part.len() as u64).to_be_bytes());
        hasher.update(part.as_bytes());
    }
    hex::encode(hasher.finalize())
}

/// sha256 hex over a canonical JSON value. serde_json maps are
/// BTreeMap-backed here, so equal values stringify identically.
pub fn json_evidence_hash(value: &serde_json::Value) -> String {
    evidence_hash(&[&value.to_string()])
}

/// Evidence hash for a manual/adjusting entry with no external source
/// document: the entry's own canonical content.
pub fn entry_content_hash(
    legal_entity_id: &str,
    entry_date: &str,
    entry_type: &str,
    memo: &str,
    lines: &[(String, i64, i64)],
) -> String {
    let mut parts: Vec<String> = vec![
        legal_entity_id.to_string(),
        entry_date.to_string(),
        entry_type.to_string(),
        memo.to_string(),
    ];
    for (account_id, debit, credit) in lines {
        parts.push(account_id.clone());
        parts.push(debit.to_string());
        parts.push(credit.to_string());
    }
    let refs: Vec<&str> = parts.iter().map(String::as_str).collect();
    evidence_hash(&refs)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hash_is_stable_and_length_prefixed() {
        let a = evidence_hash(&["ab", "c"]);
        let b = evidence_hash(&["a", "bc"]);
        assert_ne!(a, b, "length prefixing must separate split points");
        assert_eq!(a, evidence_hash(&["ab", "c"]));
        assert_eq!(a.len(), 64);
        assert!(a.bytes().all(|byte| byte.is_ascii_hexdigit()));
    }

    #[test]
    fn json_hash_is_order_independent_for_objects() {
        let first = serde_json::json!({"b": 2, "a": 1});
        let second = serde_json::json!({"a": 1, "b": 2});
        assert_eq!(json_evidence_hash(&first), json_evidence_hash(&second));
    }
}
