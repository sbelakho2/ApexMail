//! The proof-of-work challenge the risk engine would issue for an action.
//!
//! Uses `kiwicaptcha::challenge::PoWAlgorithm` from the core crate. The
//! Argon16/Argon32/Argon64 factories model the escalation ladder as memory
//! cost: 16 / 32 / 64 MiB (the core's browser-solvable ceiling is 65536 KiB
//! = 64 MiB), t = 3, p = 1, targetBits = 1 (memory is the cost; the argon
//! target range is 1..10).

use kiwicaptcha::challenge::PoWAlgorithm;
use thiserror::Error;

/// A validated challenge profile.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeProfile {
    pub algorithm: PoWAlgorithm,
    pub target_bits: u8,
    pub m_kib: u32,
    pub t: u32,
    pub p: u32,
}

impl ChallengeProfile {
    pub const MAX_SHA_TARGET_BITS: u8 = 20;
    pub const MAX_ARGON_TARGET_BITS: u8 = 10;
    pub const MIN_ARGON_T: u32 = 3;
    pub const MAX_ARGON_T: u32 = 6;
    pub const MIN_ARGON_MKIB: u32 = 8;
    pub const MAX_ARGON_MKIB: u32 = 65536;

    pub fn sha(bits: u8) -> ChallengeProfile {
        ChallengeProfile {
            algorithm: PoWAlgorithm::Sha256,
            target_bits: bits,
            m_kib: 0,
            t: 0,
            p: 1,
        }
    }

    pub fn argon16() -> ChallengeProfile {
        ChallengeProfile {
            algorithm: PoWAlgorithm::Argon2id,
            target_bits: 1,
            m_kib: 16384,
            t: 3,
            p: 1,
        }
    }

    pub fn argon32() -> ChallengeProfile {
        ChallengeProfile {
            algorithm: PoWAlgorithm::Argon2id,
            target_bits: 1,
            m_kib: 32768,
            t: 3,
            p: 1,
        }
    }

    pub fn argon64() -> ChallengeProfile {
        ChallengeProfile {
            algorithm: PoWAlgorithm::Argon2id,
            target_bits: 1,
            m_kib: 65536,
            t: 3,
            p: 1,
        }
    }

    /// Enforces the same bounds as the core issuance: SHA target 1..20;
    /// argon target 1..10, t 3..6, p == 1, mKib 8..65536.
    pub fn validate(&self) -> Result<(), ProfileError> {
        match self.algorithm {
            PoWAlgorithm::Sha256 => {
                if !(1..=Self::MAX_SHA_TARGET_BITS).contains(&self.target_bits) {
                    return Err(ProfileError::InvalidShaTargetBits(self.target_bits));
                }
                Ok(())
            }
            PoWAlgorithm::Argon2id => {
                if !(1..=Self::MAX_ARGON_TARGET_BITS).contains(&self.target_bits) {
                    return Err(ProfileError::InvalidArgonTargetBits(self.target_bits));
                }
                if !(Self::MIN_ARGON_T..=Self::MAX_ARGON_T).contains(&self.t) {
                    return Err(ProfileError::InvalidArgonTimeCost(self.t));
                }
                if self.p != 1 {
                    return Err(ProfileError::InvalidArgonParallelism(self.p));
                }
                if !(Self::MIN_ARGON_MKIB..=Self::MAX_ARGON_MKIB).contains(&self.m_kib) {
                    return Err(ProfileError::InvalidArgonMemory(self.m_kib));
                }
                Ok(())
            }
            // The rsw algorithm carries no profile knobs (T and the
            // trapdoor live on the ChallengeConfig), so an rsw profile
            // has nothing to validate; issuance still enforces the
            // configured trapdoor and T bounds.
            PoWAlgorithm::Rsw => Ok(()),
        }
    }
}

/// Challenge profile validation error.
#[derive(Debug, Error, PartialEq, Eq)]
pub enum ProfileError {
    #[error("SHA-256 target bits must be within 1..20 (got {0})")]
    InvalidShaTargetBits(u8),
    #[error("Argon2id target bits must be within 1..10 (got {0})")]
    InvalidArgonTargetBits(u8),
    #[error("Argon2id time cost t must be within 3..6 (got {0})")]
    InvalidArgonTimeCost(u32),
    #[error("Argon2id parallelism p must be exactly 1 (got {0})")]
    InvalidArgonParallelism(u32),
    #[error("Argon2id mKib must be within 8..65536 (got {0})")]
    InvalidArgonMemory(u32),
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn sha_profiles() {
        assert!(ChallengeProfile::sha(1).validate().is_ok());
        assert!(ChallengeProfile::sha(20).validate().is_ok());
        assert_eq!(
            ChallengeProfile::sha(0).validate(),
            Err(ProfileError::InvalidShaTargetBits(0))
        );
        assert_eq!(
            ChallengeProfile::sha(21).validate(),
            Err(ProfileError::InvalidShaTargetBits(21))
        );
    }

    #[test]
    fn argon_factories_validate() {
        assert!(ChallengeProfile::argon16().validate().is_ok());
        assert!(ChallengeProfile::argon32().validate().is_ok());
        assert!(ChallengeProfile::argon64().validate().is_ok());
    }

    #[test]
    fn argon_bounds() {
        let mut profile = ChallengeProfile::argon16();
        profile.target_bits = 0;
        assert_eq!(
            profile.validate(),
            Err(ProfileError::InvalidArgonTargetBits(0))
        );
        profile.target_bits = 11;
        assert_eq!(
            profile.validate(),
            Err(ProfileError::InvalidArgonTargetBits(11))
        );
        profile = ChallengeProfile::argon16();
        profile.t = 2;
        assert_eq!(
            profile.validate(),
            Err(ProfileError::InvalidArgonTimeCost(2))
        );
        profile.t = 7;
        assert_eq!(
            profile.validate(),
            Err(ProfileError::InvalidArgonTimeCost(7))
        );
        profile = ChallengeProfile::argon16();
        profile.p = 2;
        assert_eq!(
            profile.validate(),
            Err(ProfileError::InvalidArgonParallelism(2))
        );
        profile = ChallengeProfile::argon16();
        profile.m_kib = 7;
        assert_eq!(profile.validate(), Err(ProfileError::InvalidArgonMemory(7)));
        profile.m_kib = 65537;
        assert_eq!(
            profile.validate(),
            Err(ProfileError::InvalidArgonMemory(65537))
        );
        profile.m_kib = 8;
        assert!(profile.validate().is_ok());
    }
}
