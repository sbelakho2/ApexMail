//! hkdf-sha256 identity keys, derived exactly per the risk-v1 contract:
//!
//! `Hkdf::<Sha256>` with salt `kiwicaptcha-risk-v1` and master input,
//! expanded to 32 bytes per `info` in {source, subnet, session, principal,
//! event, target}. The PHP side derives the same keys with
//! `hash_hkdf('sha256', master, 32, info, 'kiwicaptcha-risk-v1')`.

use hkdf::Hkdf;
use sha2::Sha256;

use crate::RiskError;

/// The six 32-byte keys derived from a master secret.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RiskKeys {
    pub source: [u8; 32],
    pub subnet: [u8; 32],
    pub session: [u8; 32],
    pub principal: [u8; 32],
    /// Dedupe-domain key: HMACs the idempotency normalization, keeping the
    /// Redis dedupe suffix independent of the identity pseudonyms.
    pub event: [u8; 32],
    /// Target-dimension key: HMACs the normalized target identifier
    /// (`crate::target`), independent of every identity pseudonym.
    pub target: [u8; 32],
}

impl RiskKeys {
    /// hkdf salt used by both implementations.
    pub const SALT: &'static [u8] = b"kiwicaptcha-risk-v1";
    pub const INFO_SOURCE: &'static [u8] = b"source";
    pub const INFO_SUBNET: &'static [u8] = b"subnet";
    pub const INFO_SESSION: &'static [u8] = b"session";
    pub const INFO_PRINCIPAL: &'static [u8] = b"principal";
    pub const INFO_EVENT: &'static [u8] = b"event";
    pub const INFO_TARGET: &'static [u8] = b"target";

    /// The minimum master-secret length: the same 16-byte core contract
    /// the PHP `RiskKeys::fromMaster` enforces.
    pub const MIN_MASTER_BYTES: usize = 16;

    /// Derives the five keys with hkdf-sha256 (salt `kiwicaptcha-risk-v1`,
    /// 32-byte output per info), refusing a master shorter than the
    /// 16-byte minimum at the derivation boundary.
    ///
    /// # Errors
    ///
    /// [`RiskError::InvalidMasterLength`] when `master` is shorter than
    /// 16 bytes.
    pub fn try_from_master(master: &[u8]) -> Result<RiskKeys, RiskError> {
        if master.len() < Self::MIN_MASTER_BYTES {
            return Err(RiskError::InvalidMasterLength(master.len()));
        }
        Ok(Self::derive(master))
    }

    /// Derives the five keys with hkdf-sha256 (salt `kiwicaptcha-risk-v1`,
    /// 32-byte output per info).
    ///
    /// # Panics
    ///
    /// Panics when the master is shorter than the 16-byte minimum; use
    /// [`RiskKeys::try_from_master`] for a fallible path.
    pub fn from_master(master: &[u8]) -> RiskKeys {
        Self::try_from_master(master)
            .expect("the risk master secret must be at least 16 bytes; use try_from_master for a fallible path")
    }

    fn derive(master: &[u8]) -> RiskKeys {
        let hk = Hkdf::<Sha256>::new(Some(Self::SALT), master);
        let mut source = [0u8; 32];
        let mut subnet = [0u8; 32];
        let mut session = [0u8; 32];
        let mut principal = [0u8; 32];
        let mut event = [0u8; 32];
        let mut target = [0u8; 32];
        hk.expand(Self::INFO_SOURCE, &mut source)
            .expect("32 bytes is a valid HKDF output length");
        hk.expand(Self::INFO_SUBNET, &mut subnet)
            .expect("32 bytes is a valid HKDF output length");
        hk.expand(Self::INFO_SESSION, &mut session)
            .expect("32 bytes is a valid HKDF output length");
        hk.expand(Self::INFO_PRINCIPAL, &mut principal)
            .expect("32 bytes is a valid HKDF output length");
        hk.expand(Self::INFO_EVENT, &mut event)
            .expect("32 bytes is a valid HKDF output length");
        hk.expand(Self::INFO_TARGET, &mut target)
            .expect("32 bytes is a valid HKDF output length");
        RiskKeys {
            source,
            subnet,
            session,
            principal,
            event,
            target,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hex::ToHex;

    /// Parity anchors computed by the PHP implementation: hash_hkdf of
    /// sha256 over 0x42 repeated 32 times, 32 bytes, info and
    /// 'kiwicaptcha-risk-v1'. The Rust `Hkdf::<Sha256>` derivation must
    /// reproduce these exactly.
    #[test]
    fn try_from_master_refuses_short_secrets() {
        assert!(matches!(
            RiskKeys::try_from_master(&[]),
            Err(RiskError::InvalidMasterLength(0))
        ));
        assert!(matches!(
            RiskKeys::try_from_master(&[0x42; 15]),
            Err(RiskError::InvalidMasterLength(15))
        ));
        assert!(RiskKeys::try_from_master(&[0x42; 16]).is_ok());
    }

    #[test]
    fn hkdf_keys_match_php_parity_anchors() {
        let master = [0x42u8; 32];
        let keys = RiskKeys::from_master(&master);

        let hex_of = |bytes: &[u8; 32]| bytes.encode_hex::<String>();
        assert_eq!(
            hex_of(&keys.source),
            "c353fb1e6c7ceac79f19a45cd92f8dd24597f0c50df92a7f9139fa96e19b5b61"
        );
        assert_eq!(
            hex_of(&keys.subnet),
            "ec675a524f51caf7f85119e309d29d74fa554222ca12e8efc77631a5c8dc2460"
        );
        assert_eq!(
            hex_of(&keys.session),
            "bbb44b7be31ee827d07e8e5079eaca4608bf0c85db54aa9ce8582c777186029f"
        );
        assert_eq!(
            hex_of(&keys.principal),
            "40459f71b2d98dc45f78b2ebe6eea9d7e68b55c3006b5408762f2c6f10e95c48"
        );
        assert_eq!(
            hex_of(&keys.event),
            "10def12a515d1fcaa2a0ca79916eb916197b99af76b98b8317081accd9fb3e1f"
        );
        assert_eq!(
            hex_of(&keys.target),
            "cb0fcb40d7dc9a976acd653cc5f7a60b561598497e516b9aa419bc1c821ab18a"
        );
    }

    #[test]
    fn hkdf_keys_differ_across_infos() {
        let keys = RiskKeys::from_master(&[0x42; 32]);
        assert_ne!(keys.source, keys.subnet);
        assert_ne!(keys.subnet, keys.session);
        assert_ne!(keys.session, keys.principal);
        assert_ne!(keys.principal, keys.event);
        assert_ne!(keys.event, keys.source);
        assert_ne!(keys.event, keys.target);
        assert_ne!(keys.target, keys.source);
    }
}
