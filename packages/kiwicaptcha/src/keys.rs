//! Purpose-key separation, HKDF-based.
//!
//! Every cryptographic purpose derives its own 32-byte key from the single
//! master secret, so a key compromise in one purpose (challenge signing, IP
//! binding, result tokens) never leaks the others:
//!
//! ```text
//! PRK        = HKDF-Extract(SHA-256, salt = "kiwicaptcha/deploy-salt/v1", ikm = master)
//! K_challenge = HKDF-Expand(PRK, "kiwi/v2/challenge-sign", 32)
//! K_ip_bind   = HKDF-Expand(PRK, "kiwi/v2/ip-bind", 32)
//! K_result    = HKDF-Expand(PRK, "kiwi/v2/result-token", 32)
//! K_server_state = HKDF-Expand(PRK, "kiwi/v2/server-state", 32)
//! ```
//!
//! Tenant-scoped deployments additionally derive a per-tenant root and the
//! three purpose keys under it:
//!
//! ```text
//! tenant_root = HKDF-Expand(PRK, "kiwi/v2/tenant/" + tenant_id, 32)
//! PRK_t       = HKDF-Extract(SHA-256, salt = "", ikm = tenant_root)
//! K_x_tenant  = HKDF-Expand(PRK_t, "kiwi/v2/" + purpose, 32)
//! ```
//!
//! # Cross-language parity (PHP MUST mirror byte-for-byte)
//!
//! The construction above is exactly PHP's `hash_hkdf('sha256', $ikm, 32,
//! $info, $salt)`:
//! - the global keys: `hash_hkdf('sha256', $master, 32, 'kiwi/v2/challenge-sign', 'kiwicaptcha/deploy-salt/v1')` (and the `ip-bind` / `result-token`
//!   infos);
//! - the tenant root: `hash_hkdf('sha256', $master, 32, 'kiwi/v2/tenant/' . $tenant, 'kiwicaptcha/deploy-salt/v1')`;
//! - the tenant purpose keys: `hash_hkdf('sha256', $tenantRoot, 32, 'kiwi/v2/' . $purpose, '')`.
//!
//! The interop tests (`CrossLanguageVerify` / `CrossLanguageIssue`) verify
//! that a challenge signed with these keys on one side verifies on the other.

use hkdf::Hkdf;
use sha2::Sha256;

use std::fmt;
use std::sync::atomic::{AtomicU64, Ordering};

/// The public (non-secret) deployment salt for the HKDF-based extraction
/// step — domain separation shared with the PHP core; the secrecy comes from
/// the master secret, never from this string.
pub const HKDF_DEPLOY_SALT: &[u8] = b"kiwicaptcha/deploy-salt/v1";

/// The minimum master-secret length at the derivation boundary: the same
/// 32-byte core Config contract PHP enforces (`Config::__construct`
/// rejects a secret key shorter than 32 bytes). Every signature, binding
/// and token path routes its length gate through this single constant.
pub const MIN_MASTER_BYTES: usize = 32;

/// The minimum execution-key length at the execution-generation boundary:
/// the same 32-byte contract PHP enforces in
/// `ExecutionChallengeGenerator::validateKey`.
pub const MIN_EXECUTION_KEY_BYTES: usize = 32;

/// The derivation boundary refused the master secret.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DerivedKeysError {
    /// The master secret is shorter than [`MIN_MASTER_BYTES`].
    MasterTooShort {
        /// The supplied length in bytes.
        got: usize,
    },
}

impl fmt::Display for DerivedKeysError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            DerivedKeysError::MasterTooShort { got } => write!(
                f,
                "the master secret must be at least {MIN_MASTER_BYTES} bytes (got {got})"
            ),
        }
    }
}

impl std::error::Error for DerivedKeysError {}

/// Process-wide count of `DerivedKeys::from_master` invocations. A cheap
/// (one relaxed atomic) observability seam proving the per-kid derivation
/// cache works: production verifiers route every signature / IP-binding
/// check through a cached [`DerivedKeys`], so after the first derivation
/// per key id this counter must not grow while verifying. Diagnostic only;
/// not part of the stable API surface.
static FROM_MASTER_CALLS: AtomicU64 = AtomicU64::new(0);

/// The number of [`DerivedKeys::from_master`] calls this process has made
/// (the derivation-cache observability seam — see [`FROM_MASTER_CALLS`]).
#[doc(hidden)]
pub fn from_master_call_count() -> u64 {
    FROM_MASTER_CALLS.load(Ordering::Relaxed)
}

/// Info label for the challenge-signing purpose key.
pub const INFO_CHALLENGE_SIGN: &[u8] = b"kiwi/v2/challenge-sign";
/// Info label for the IP-binding purpose key.
pub const INFO_IP_BIND: &[u8] = b"kiwi/v2/ip-bind";
/// Info label for the result/solution-token purpose key.
pub const INFO_RESULT_TOKEN: &[u8] = b"kiwi/v2/result-token";
/// Info label for the server-state purpose key: the HMAC over the
/// server-written record metadata (`server_mac`) and the committed
/// consumed result (`consumed_result.mac`). See
/// [`crate::challenge::record_meta_mac`].
pub const INFO_SERVER_STATE: &[u8] = b"kiwi/v2/server-state";
/// Prefix of the tenant-root info label: `"kiwi/v2/tenant/" + tenant_id`.
pub const INFO_TENANT_ROOT_PREFIX: &[u8] = b"kiwi/v2/tenant/";

/// Purpose-separated 32-byte keys derived from the master secret.
///
/// All cryptographic primitives in the crate derive their key internally from
/// the master via [`DerivedKeys::from_master`], so callers keep passing the
/// master secret — no existing constructor signature changes.
///
/// `Debug` is implemented manually: the derived formatter would print the
/// raw purpose keys (the effective challenge-signing, IP-binding and
/// result-token key material) into logs, so the manual impl prints the same
/// field set with every key value replaced by `"<redacted>"`.
#[derive(Clone, PartialEq, Eq)]
pub struct DerivedKeys {
    challenge: [u8; 32],
    ip_bind: [u8; 32],
    result: [u8; 32],
    server_state: [u8; 32],
}

impl fmt::Debug for DerivedKeys {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("DerivedKeys")
            .field("challenge", &"<redacted>")
            .field("ip_bind", &"<redacted>")
            .field("result", &"<redacted>")
            .field("server_state", &"<redacted>")
            .finish()
    }
}

impl DerivedKeys {
    /// Derives the purpose keys, refusing a master shorter than the
    /// minimum length at the derivation boundary.
    ///
    /// # Errors
    ///
    /// [`DerivedKeysError::MasterTooShort`] when `master` is shorter
    /// than [`MIN_MASTER_BYTES`].
    pub fn try_from_master(
        master: &str,
        tenant: Option<&str>,
    ) -> Result<DerivedKeys, DerivedKeysError> {
        if master.len() < MIN_MASTER_BYTES {
            return Err(DerivedKeysError::MasterTooShort { got: master.len() });
        }
        Ok(Self::derive(master, tenant))
    }

    /// Derive the three purpose keys from the master secret.
    ///
    /// - `master` — the deployment master secret (the HMAC secret key).
    /// - `tenant` — optional tenant id. When `Some`, the purpose keys are
    ///   derived under the per-tenant root
    ///   (`"kiwi/v2/tenant/" + tenant_id`), so tenants of a shared master
    ///   secret cannot forge each other's challenges, binding tags, or
    ///   result tokens.
    ///
    /// # Panics
    ///
    /// Panics when the master is shorter than [`MIN_MASTER_BYTES`]; use
    /// [`DerivedKeys::try_from_master`] for a fallible path.
    pub fn from_master(master: &str, tenant: Option<&str>) -> DerivedKeys {
        Self::try_from_master(master, tenant).expect(
            "the master secret must be at least 32 bytes; use try_from_master for a fallible path",
        )
    }

    fn derive(master: &str, tenant: Option<&str>) -> DerivedKeys {
        FROM_MASTER_CALLS.fetch_add(1, Ordering::Relaxed);
        let prk = Hkdf::<Sha256>::new(Some(HKDF_DEPLOY_SALT), master.as_bytes());
        match tenant {
            None => DerivedKeys {
                challenge: expand(&prk, INFO_CHALLENGE_SIGN),
                ip_bind: expand(&prk, INFO_IP_BIND),
                result: expand(&prk, INFO_RESULT_TOKEN),
                server_state: expand(&prk, INFO_SERVER_STATE),
            },
            Some(tenant_id) => {
                let mut root_info =
                    Vec::with_capacity(INFO_TENANT_ROOT_PREFIX.len() + tenant_id.len());
                root_info.extend_from_slice(INFO_TENANT_ROOT_PREFIX);
                root_info.extend_from_slice(tenant_id.as_bytes());
                let tenant_root = expand(&prk, &root_info);
                // The tenant root acts as a new key material: re-extract with
                // an empty salt (PHP's `hash_hkdf` with `salt: ''`) so the three
                // purpose keys are independent of both the master PRK and
                // each other.
                let prk_t = Hkdf::<Sha256>::new(None, &tenant_root);
                DerivedKeys {
                    challenge: expand(&prk_t, INFO_CHALLENGE_SIGN),
                    ip_bind: expand(&prk_t, INFO_IP_BIND),
                    result: expand(&prk_t, INFO_RESULT_TOKEN),
                    server_state: expand(&prk_t, INFO_SERVER_STATE),
                }
            }
        }
    }

    /// The challenge-signing key (`K_challenge`): HMAC over the canonical
    /// challenge payload.
    pub fn challenge_key(&self) -> &[u8; 32] {
        &self.challenge
    }

    /// The IP-binding key (`K_ip_bind`): HMAC over the nonce + canonical IP
    /// bytes (the nonce-bound binding tag).
    pub fn ip_bind_key(&self) -> &[u8; 32] {
        &self.ip_bind
    }

    /// The result/solution-token key (`K_result`): MAC for result tokens
    /// issued after a successful verification.
    pub fn result_key(&self) -> &[u8; 32] {
        &self.result
    }

    /// The server-state key (`K_server_state`): HMAC over the
    /// server-written record metadata and the committed consumed result.
    pub fn server_state_key(&self) -> &[u8; 32] {
        &self.server_state
    }
}

/// HKDF-Expand a 32-byte output for the given info (infallible for 32-byte
/// outputs — the SHA-256 output size is exactly 32 bytes).
fn expand(hk: &Hkdf<Sha256>, info: &[u8]) -> [u8; 32] {
    let mut okm = [0u8; 32];
    hk.expand(info, &mut okm)
        .expect("32-byte HKDF expansion cannot exceed the SHA-256 output bound");
    okm
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: &str = "0123456789abcdef0123456789abcdef";

    // Byte-exact vectors computed with the reference construction — Python's
    // hmac-based hkdf-sha256 and PHP hash_hkdf agree on these — the
    // cross-language lock-in: any deviation breaks interop.
    const K_CHALLENGE_HEX: &str =
        "1d5be54d8682c4a6951c62306dd2f3b910366fddd48c45e5a4cc57222565c7bb";
    const K_IP_BIND_HEX: &str = "48018b185abd85485fe9a6b61820b6da00043ef0ac38d0930abd3f55fbe0384d";
    const K_RESULT_HEX: &str = "097f7a8e5189ac814299617c976c89a84301e2425bdf2761eb104ede8b8870eb";
    const TENANT_T1_ROOT_HEX: &str =
        "d60ccd304be02092056c28dd5e25673063e3bb37018feec239166d5fd501b917";

    #[test]
    fn purpose_keys_match_the_shared_reference_vectors() {
        let keys = DerivedKeys::from_master(MASTER, None);
        assert_eq!(hex::encode(keys.challenge_key()), K_CHALLENGE_HEX);
        assert_eq!(hex::encode(keys.ip_bind_key()), K_IP_BIND_HEX);
        assert_eq!(hex::encode(keys.result_key()), K_RESULT_HEX);
    }

    #[test]
    fn tenant_root_matches_the_shared_reference_vector() {
        // The tenant root is not exposed, but the derived keys under it are
        // locked to the reference construction via the PHP-mirror formula.
        let prk = Hkdf::<Sha256>::new(Some(HKDF_DEPLOY_SALT), MASTER.as_bytes());
        let root = expand(&prk, b"kiwi/v2/tenant/t1");
        assert_eq!(hex::encode(root), TENANT_T1_ROOT_HEX);
        // The keys under the t1 root must equal the reference t1 keys.
        let t1 = DerivedKeys::from_master(MASTER, Some("t1"));
        let prk_t = Hkdf::<Sha256>::new(None, &root);
        assert_eq!(
            t1.challenge_key(),
            &expand(&prk_t, INFO_CHALLENGE_SIGN),
            "tenant keys must be derived under the tenant root"
        );
    }

    #[test]
    fn purpose_keys_differ_from_each_other() {
        let keys = DerivedKeys::from_master(MASTER, None);
        assert_ne!(keys.challenge_key(), keys.ip_bind_key());
        assert_ne!(keys.challenge_key(), keys.result_key());
        assert_ne!(keys.ip_bind_key(), keys.result_key());
    }

    #[test]
    fn tenant_keys_differ_and_differ_from_global_keys() {
        let global = DerivedKeys::from_master(MASTER, None);
        let t1 = DerivedKeys::from_master(MASTER, Some("t1"));
        let t2 = DerivedKeys::from_master(MASTER, Some("t2"));
        assert_ne!(t1.challenge_key(), t2.challenge_key());
        assert_ne!(t1.ip_bind_key(), t2.ip_bind_key());
        assert_ne!(t1.result_key(), t2.result_key());
        assert_ne!(t1.challenge_key(), global.challenge_key());
        assert_ne!(t1.ip_bind_key(), global.ip_bind_key());
        assert_ne!(t1.result_key(), global.result_key());
    }

    #[test]
    fn try_from_master_refuses_short_secrets() {
        assert_eq!(
            DerivedKeys::try_from_master("", None).unwrap_err(),
            DerivedKeysError::MasterTooShort { got: 0 }
        );
        assert_eq!(
            DerivedKeys::try_from_master(&"s".repeat(31), None).unwrap_err(),
            DerivedKeysError::MasterTooShort { got: 31 }
        );
        assert!(DerivedKeys::try_from_master(&"s".repeat(31), None).is_err());
        assert!(DerivedKeys::try_from_master(&"s".repeat(32), None).is_ok());
    }

    #[test]
    fn derivation_is_deterministic() {
        let a = DerivedKeys::from_master(MASTER, None);
        let b = DerivedKeys::from_master(MASTER, None);
        assert_eq!(a, b);
        let c = DerivedKeys::from_master("another-master-32-bytes-0123456789", None);
        assert_ne!(a, c, "a different master must derive different keys");
    }

    #[test]
    fn tenant_id_binding_is_exact() {
        // The tenant info is "kiwi/v2/tenant/" + tenant_id verbatim — a
        // different tenant id (including prefixes) must derive different keys.
        let exact = DerivedKeys::from_master(MASTER, Some("acme"));
        let prefixed = DerivedKeys::from_master(MASTER, Some("acme-prod"));
        assert_ne!(exact.challenge_key(), prefixed.challenge_key());
        assert_eq!(DerivedKeys::from_master(MASTER, Some("acme")), exact);
    }

    #[test]
    fn derived_keys_debug_redacts_the_purpose_keys() {
        let keys = DerivedKeys::from_master(MASTER, None);
        // The Debug shape must never print the purpose keys: the derived
        // keys are the effective signing/IP-binding/result-token material.
        assert_eq!(
            format!("{keys:?}"),
            "DerivedKeys { challenge: \"<redacted>\", ip_bind: \"<redacted>\", result: \"<redacted>\", server_state: \"<redacted>\" }"
        );
        assert!(!format!("{keys:?}").contains(MASTER));
    }
}
