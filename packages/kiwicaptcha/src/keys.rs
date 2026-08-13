//! HKDF purpose-key separation (audit #21).
//!
//! Every cryptographic purpose derives its own 32-byte key from the single
//! master secret, so a key compromise in one purpose (challenge signing, IP
//! binding, result tokens) never leaks the others:
//!
//! ```text
//! PRK        = HKDF-Extract(SHA-256, salt = HKDF_DEPLOY_SALT, ikm = master)
//! K_challenge = HKDF-Expand(PRK, "kiwi/v2/challenge-sign", 32)
//! K_ip_bind   = HKDF-Expand(PRK, "kiwi/v2/ip-bind", 32)
//! K_result    = HKDF-Expand(PRK, "kiwi/v2/result-token", 32)
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

/// The public (non-secret) deployment salt for the HKDF extraction step —
/// domain separation shared with the PHP core; the secrecy comes from the
/// master secret, never from this string.
pub const HKDF_DEPLOY_SALT: &[u8] = b"kiwicaptcha/deploy-salt/v1";

/// HKDF info label for the challenge-signing purpose key.
pub const INFO_CHALLENGE_SIGN: &[u8] = b"kiwi/v2/challenge-sign";
/// HKDF info label for the IP-binding purpose key.
pub const INFO_IP_BIND: &[u8] = b"kiwi/v2/ip-bind";
/// HKDF info label for the result/solution-token purpose key.
pub const INFO_RESULT_TOKEN: &[u8] = b"kiwi/v2/result-token";
/// Prefix of the tenant-root info label: `"kiwi/v2/tenant/" + tenant_id`.
pub const INFO_TENANT_ROOT_PREFIX: &[u8] = b"kiwi/v2/tenant/";

/// Purpose-separated 32-byte keys derived from the master secret (audit #21).
///
/// All cryptographic primitives in the crate derive their key internally from
/// the master via [`DerivedKeys::from_master`], so callers keep passing the
/// master secret — no existing constructor signature changes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct DerivedKeys {
    challenge: [u8; 32],
    ip_bind: [u8; 32],
    result: [u8; 32],
}

impl DerivedKeys {
    /// Derive the three purpose keys from the master secret.
    ///
    /// - `master` — the deployment master secret (the HMAC secret key).
    /// - `tenant` — optional tenant id. When `Some`, the purpose keys are
    ///   derived under the per-tenant root
    ///   (`"kiwi/v2/tenant/" + tenant_id`), so tenants of a shared master
    ///   secret cannot forge each other's challenges, binding tags, or
    ///   result tokens.
    pub fn from_master(master: &str, tenant: Option<&str>) -> DerivedKeys {
        let prk = Hkdf::<Sha256>::new(Some(HKDF_DEPLOY_SALT), master.as_bytes());
        match tenant {
            None => DerivedKeys {
                challenge: expand(&prk, INFO_CHALLENGE_SIGN),
                ip_bind: expand(&prk, INFO_IP_BIND),
                result: expand(&prk, INFO_RESULT_TOKEN),
            },
            Some(tenant_id) => {
                let mut root_info =
                    Vec::with_capacity(INFO_TENANT_ROOT_PREFIX.len() + tenant_id.len());
                root_info.extend_from_slice(INFO_TENANT_ROOT_PREFIX);
                root_info.extend_from_slice(tenant_id.as_bytes());
                let tenant_root = expand(&prk, &root_info);
                // The tenant root acts as a new key material: re-extract with
                // an empty salt (PHP `hash_hkdf(..., salt: '')`) so the three
                // purpose keys are independent of both the master PRK and
                // each other.
                let prk_t = Hkdf::<Sha256>::new(None, &tenant_root);
                DerivedKeys {
                    challenge: expand(&prk_t, INFO_CHALLENGE_SIGN),
                    ip_bind: expand(&prk_t, INFO_IP_BIND),
                    result: expand(&prk_t, INFO_RESULT_TOKEN),
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

    // Byte-exact vectors computed with the reference construction (Python
    // hmac-based HKDF-SHA256 and PHP hash_hkdf agree on these) — the
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
    fn derivation_is_deterministic() {
        let a = DerivedKeys::from_master(MASTER, None);
        let b = DerivedKeys::from_master(MASTER, None);
        assert_eq!(a, b);
        let c = DerivedKeys::from_master("another-master-16-bytes!", None);
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
}
