//! The one derivation of a Redis-safe deployment namespace from its raw
//! configured bytes, shared by every risk key family in both languages:
//! this crate and the PHP package `kiwicaptcha-risk-php` (its
//! `DeploymentNamespace` class implements the identical byte-level
//! algorithm, pinned by the shared golden vectors in
//! protocol/risk-v1/fixtures.json).
//!
//! A namespace is an identity discriminator, never a display string.
//! Two derivations are defined, selected by an explicit version:
//!
//!  - [`NamespaceVersion::Legacy`] (1): replacement-sanitization of every
//!    byte outside `[A-Za-z0-9_.-]` to `_`. This is the historical key
//!    shape, so an existing deployment that upgrades the packages keeps
//!    its state. Distinct raw values can fold onto one sanitized value
//!    (`tenant/a` and `tenant:a` both become `tenant_a`), so a new
//!    deployment should not choose it.
//!  - [`NamespaceVersion::Digest`] (2): `n_` plus the first 128 bits
//!    (32 hex chars) of SHA-256 over the complete original bytes.
//!    Injective for every practical input, hex only (safe inside hash
//!    tags and every key grammar), and stable across processes.
//!
//! The version is never inferred from the string: a raw namespace is
//! always derived here, and the resulting encoded value is what key
//! builders interpolate. Switching an existing deployment to
//! [`NamespaceVersion::Digest`] changes its key space, so it is a
//! migration the operator performs deliberately.

use sha2::{Digest, Sha256};

/// The historical sanitized derivation: `[A-Za-z0-9_.-]` kept, every
/// other byte `_`.
pub const NAMESPACE_VERSION_LEGACY: u8 = 1;

/// The digest derivation: `n_` plus the first 128 bits of SHA-256, hex.
pub const NAMESPACE_VERSION_DIGEST: u8 = 2;

/// The key-version contract of a deployment namespace.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum NamespaceVersion {
    /// The historical sanitized key shape (version 1).
    #[default]
    Legacy,
    /// The digest key shape (version 2).
    Digest,
}

impl NamespaceVersion {
    /// The canonical wire value (the PHP `DeploymentNamespace` constants).
    pub fn as_u8(self) -> u8 {
        match self {
            NamespaceVersion::Legacy => NAMESPACE_VERSION_LEGACY,
            NamespaceVersion::Digest => NAMESPACE_VERSION_DIGEST,
        }
    }

    /// The version of a canonical wire value, or `None` for an unknown
    /// version (never silently defaulted).
    pub fn from_u8(value: u8) -> Option<Self> {
        match value {
            NAMESPACE_VERSION_LEGACY => Some(NamespaceVersion::Legacy),
            NAMESPACE_VERSION_DIGEST => Some(NamespaceVersion::Digest),
            _ => None,
        }
    }
}

/// Derive the encoded namespace of a raw configured discriminator.
///
/// # Panics
///
/// Panics when the raw namespace is empty (the PHP derivation throws the
/// mirrored `InvalidArgumentException`).
pub fn deployment_namespace(raw: &str, version: NamespaceVersion) -> String {
    match version {
        NamespaceVersion::Legacy => legacy_namespace(raw),
        NamespaceVersion::Digest => digest_namespace(raw),
    }
}

/// The legacy sanitized namespace: every byte outside `[A-Za-z0-9_.-]`
/// becomes `_` (byte-wise, so a multi-byte character contributes one `_`
/// per byte, exactly like PHP's `preg_replace` without the `/u`
/// modifier).
///
/// # Panics
///
/// Panics when the raw namespace is empty.
pub fn legacy_namespace(raw: &str) -> String {
    assert!(
        !raw.is_empty(),
        "the deployment namespace cannot be empty: derive() needs the raw configured discriminator"
    );
    raw.bytes()
        .map(|b| {
            if b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'-') {
                b as char
            } else {
                '_'
            }
        })
        .collect()
}

/// The digest namespace: `n_` plus the first 128 bits of the SHA-256 of
/// the complete raw bytes, lowercase hex.
///
/// # Panics
///
/// Panics when the raw namespace is empty.
pub fn digest_namespace(raw: &str) -> String {
    assert!(
        !raw.is_empty(),
        "the deployment namespace cannot be empty: derive() needs the raw configured discriminator"
    );
    let digest = Sha256::digest(raw.as_bytes());
    let hex = hex::encode(digest);
    format!("n_{}", &hex[..32])
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn versions_round_trip_their_canonical_wire_values() {
        assert_eq!(NamespaceVersion::Legacy.as_u8(), 1);
        assert_eq!(NamespaceVersion::Digest.as_u8(), 2);
        assert_eq!(NamespaceVersion::from_u8(1), Some(NamespaceVersion::Legacy));
        assert_eq!(NamespaceVersion::from_u8(2), Some(NamespaceVersion::Digest));
        assert_eq!(NamespaceVersion::from_u8(0), None);
        assert_eq!(NamespaceVersion::from_u8(3), None);
        assert_eq!(NamespaceVersion::default(), NamespaceVersion::Legacy);
    }

    #[test]
    fn legacy_sanitization_is_byte_wise_and_identity_on_canonical_bytes() {
        assert_eq!(legacy_namespace("prod"), "prod");
        assert_eq!(legacy_namespace("tenant/a"), "tenant_a");
        assert_eq!(legacy_namespace("tenant:a"), "tenant_a");
        assert_eq!(legacy_namespace("/a/b_c"), "_a_b_c");
        assert_eq!(legacy_namespace("/a_b/c"), "_a_b_c");
        assert_eq!(legacy_namespace("ns{x}"), "ns_x_");
        // A multi-byte character contributes one `_` per byte.
        assert_eq!(legacy_namespace("tä"), "t__");
    }

    #[test]
    fn digest_is_stable_and_hex_only() {
        let derived = digest_namespace("prod");
        assert_eq!(derived, digest_namespace("prod"));
        assert!(derived.starts_with("n_"));
        assert_eq!(derived.len(), 34);
        assert!(derived[2..].bytes().all(|b| b.is_ascii_hexdigit()));
        assert_ne!(digest_namespace("tenant/a"), digest_namespace("tenant:a"));
    }

    #[test]
    #[should_panic(expected = "the deployment namespace cannot be empty")]
    fn empty_raw_namespace_is_refused() {
        let _ = deployment_namespace("", NamespaceVersion::Legacy);
    }

    /// The shared golden vectors (protocol/risk-v1/fixtures.json): the PHP
    /// `DeploymentNamespace` derivation and this module must produce the
    /// identical encoded namespace AND the identical full Redis key set for
    /// every input, in both key versions.
    #[test]
    fn shared_golden_vectors_match_php() {
        let raw = std::fs::read_to_string(concat!(
            env!("CARGO_MANIFEST_DIR"),
            "/../../protocol/risk-v1/fixtures.json"
        ))
        .expect("the shared fixtures must load");
        let value: serde_json::Value = serde_json::from_str(&raw).expect("valid json");
        let vectors = value
            .get("namespace_vectors")
            .expect("the namespace vectors must be recorded")
            .as_array()
            .expect("namespace vectors array")
            .clone();
        assert!(!vectors.is_empty(), "namespace vectors must not be empty");

        for vector in &vectors {
            let raw_namespace = vector["raw"].as_str().expect("raw");
            let version = NamespaceVersion::from_u8(
                u8::try_from(vector["version"].as_u64().expect("version")).expect("u8"),
            )
            .expect("known version");
            let derived = deployment_namespace(raw_namespace, version);
            assert_eq!(
                derived,
                vector["derived"].as_str().expect("derived"),
                "derived namespace mismatch for {raw_namespace:?} v{version:?}"
            );
            let keys = crate::redis::RedisRiskStateStore::keys_for(
                raw_namespace,
                version,
                1_700_000_000,
                "aa11",
                "bb22",
                "cc33",
                1_700_000_900,
                "dd44",
                "ee55",
                "ff66",
                None,
                None,
                "0123abcd",
            );
            let expected: Vec<String> = vector["observation_keys"]
                .as_array()
                .expect("observation_keys")
                .iter()
                .map(|key| key.as_str().expect("key").to_string())
                .collect();
            assert_eq!(
                keys, expected,
                "full key set mismatch for {raw_namespace:?} v{version:?}"
            );
            assert_eq!(
                format!("{{kiwi:{derived}}}:outcome:dec-1"),
                vector["outcome_ledger_key"].as_str().expect("ledger key"),
                "outcome ledger key mismatch for {raw_namespace:?} v{version:?}"
            );
        }
    }
}
