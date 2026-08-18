//! Adaptive-risk difficulty profiles for KiwiCaptcha issuance.
//!
//! A [`ChallengeProfile`] carries only the proof-of-work parameters
//! (algorithm, difficulty, and for Argon2id the memory/time/parallelism
//! costs) — TTL and minimum-duration policy stay owned by the caller's
//! [`ChallengeConfig`]. [`crate::challenge::issue_challenge_with_profile`]
//! clones the config, overlays the profile, and delegates to
//! [`crate::challenge::issue_challenge`], so the wire format, signing, and
//! storage are identical to a regular issuance — only the parameters differ.
//!
//! [`ChallengeProfile::validate`] enforces the exact bounds issuance (and
//! the PHP `ChallengeProfile`) enforce, so a profile can never mint a
//! challenge the verifier would reject:
//! - SHA-256: `target_bits` within `1..=SOLVER_MAX_TARGET_BITS` (20).
//! - Argon2id: `target_bits` within `1..=SOLVER_MAX_ARGON2_TARGET_BITS`
//!   (10), `t` within `3..=MAX_ARGON_T` (6), `p == 1`, and
//!   `m_kib` within `8..=SOLVER_MAX_ARGON2_M_KIB` (65536).

use crate::challenge::{
    PoWAlgorithm, MAX_ARGON_T, SOLVER_MAX_ARGON2_M_KIB, SOLVER_MAX_ARGON2_TARGET_BITS,
    SOLVER_MAX_TARGET_BITS,
};

/// A named difficulty profile for adaptive-risk issuance.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ChallengeProfile {
    /// The proof-of-work algorithm the profile issues.
    pub algorithm: PoWAlgorithm,
    /// Required leading zero bits. For SHA-256 this is the primary
    /// difficulty (1..=20); for Argon2id it becomes the effective
    /// `argon2_target_bits` (1..=10) because every Argon2 hash is ~1000x
    /// more expensive than SHA-256.
    pub target_bits: u8,
    /// Argon2id memory cost in KiB (16384 = 16 MiB, 32768 = 32 MiB,
    /// 65536 = 64 MiB). Unused for SHA-256.
    pub m_kib: u32,
    /// Argon2id time cost (profile `t`; the argon16/32/64 profiles use 3).
    /// Unused for SHA-256.
    pub t: u32,
    /// Argon2id parallelism (the KiwiCaptcha protocol profile requires
    /// `p == 1` for libsodium cross-verification). Unused for SHA-256.
    pub p: u32,
}

/// Reasons a [`ChallengeProfile`] is invalid.
#[derive(Debug, thiserror::Error, PartialEq, Eq)]
pub enum ProfileError {
    /// SHA-256 difficulty must be `1..=SOLVER_MAX_TARGET_BITS` (20) — 0
    /// means "no work at all" and values above the ceiling can never be
    /// solved by the widget.
    #[error("SHA-256 target bits must be within 1..=20 (got {0})")]
    InvalidShaTargetBits(u8),
    /// Argon2id difficulty must be `1..=SOLVER_MAX_ARGON2_TARGET_BITS` (10).
    #[error("Argon2id target bits must be within 1..=10 (got {0})")]
    InvalidArgonTargetBits(u8),
    /// Argon2id time cost must be `3..=MAX_ARGON_T` (6) — the protocol
    /// profile requires `t >= 3` (libsodium-representable) and caps at 6,
    /// the browser-solver ceiling (distinct from the verifier's structural
    /// ceiling, `MAX_ARGON_TIME` = 16).
    #[error("Argon2id time cost t must be within 3..=6 (got {0})")]
    InvalidArgonT(u32),
    /// Argon2id parallelism must be exactly 1 — libsodium (PHP) only
    /// supports `p == 1`, so other values could never verify.
    #[error("Argon2id parallelism p must be 1 (got {0})")]
    InvalidArgonP(u32),
    /// Argon2id memory must be `8..=SOLVER_MAX_ARGON2_M_KIB` (65536).
    #[error("Argon2id memory m_kib must be within 8..=65536 (got {0})")]
    InvalidArgonMKib(u32),
}

impl ChallengeProfile {
    /// SHA-256 profile at the given difficulty (target_bits 1..=20).
    pub fn sha(bits: u8) -> Self {
        ChallengeProfile {
            algorithm: PoWAlgorithm::Sha256,
            target_bits: bits,
            m_kib: 0,
            t: 0,
            p: 1,
        }
    }

    /// Argon2id profile: 16 MiB, t=3, p=1, target_bits 1.
    pub fn argon16() -> Self {
        ChallengeProfile {
            algorithm: PoWAlgorithm::Argon2id,
            target_bits: 1,
            m_kib: 16 * 1024,
            t: 3,
            p: 1,
        }
    }

    /// Argon2id profile: 32 MiB, t=3, p=1, target_bits 1.
    pub fn argon32() -> Self {
        ChallengeProfile {
            algorithm: PoWAlgorithm::Argon2id,
            target_bits: 1,
            m_kib: 32 * 1024,
            t: 3,
            p: 1,
        }
    }

    /// Argon2id profile: 64 MiB, t=3, p=1, target_bits 1.
    pub fn argon64() -> Self {
        ChallengeProfile {
            algorithm: PoWAlgorithm::Argon2id,
            target_bits: 1,
            m_kib: 64 * 1024,
            t: 3,
            p: 1,
        }
    }

    /// Validate the profile against the same bounds issuance enforces.
    ///
    /// Mirrors the PHP `ChallengeProfile::validate()` exactly.
    pub fn validate(&self) -> Result<(), ProfileError> {
        match self.algorithm {
            PoWAlgorithm::Sha256 => {
                if self.target_bits == 0 || self.target_bits as u32 > SOLVER_MAX_TARGET_BITS {
                    return Err(ProfileError::InvalidShaTargetBits(self.target_bits));
                }
            }
            PoWAlgorithm::Argon2id => {
                if self.target_bits == 0 || self.target_bits as u32 > SOLVER_MAX_ARGON2_TARGET_BITS
                {
                    return Err(ProfileError::InvalidArgonTargetBits(self.target_bits));
                }
                if self.t < 3 || self.t > MAX_ARGON_T {
                    return Err(ProfileError::InvalidArgonT(self.t));
                }
                if self.p != 1 {
                    return Err(ProfileError::InvalidArgonP(self.p));
                }
                if self.m_kib < 8 * self.p || self.m_kib > SOLVER_MAX_ARGON2_M_KIB {
                    return Err(ProfileError::InvalidArgonMKib(self.m_kib));
                }
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn named_profiles_carry_expected_parameters() {
        let sha = ChallengeProfile::sha(16);
        assert_eq!(sha.algorithm, PoWAlgorithm::Sha256);
        assert_eq!(sha.target_bits, 16);
        assert_eq!(sha.m_kib, 0);

        let argon = ChallengeProfile::argon16();
        assert_eq!(argon.algorithm, PoWAlgorithm::Argon2id);
        assert_eq!(argon.m_kib, 16 * 1024);
        assert_eq!(argon.t, 3);
        assert_eq!(argon.p, 1);
        assert_eq!(argon.target_bits, 1);

        assert_eq!(ChallengeProfile::argon32().m_kib, 32 * 1024);
        assert_eq!(ChallengeProfile::argon64().m_kib, 64 * 1024);
    }

    #[test]
    fn sha_profile_validation_boundaries() {
        assert_eq!(
            ChallengeProfile::sha(21).validate(),
            Err(ProfileError::InvalidShaTargetBits(21))
        );
        assert_eq!(
            ChallengeProfile::sha(0).validate(),
            Err(ProfileError::InvalidShaTargetBits(0))
        );
        assert!(ChallengeProfile::sha(20).validate().is_ok());
        assert!(ChallengeProfile::sha(1).validate().is_ok());
    }

    #[test]
    fn argon_profile_validation_boundaries() {
        let base = || ChallengeProfile {
            algorithm: PoWAlgorithm::Argon2id,
            target_bits: 1,
            m_kib: 16 * 1024,
            t: 3,
            p: 1,
        };
        assert_eq!(
            (ChallengeProfile { t: 7, ..base() }).validate(),
            Err(ProfileError::InvalidArgonT(7))
        );
        assert!(ChallengeProfile { t: 6, ..base() }.validate().is_ok());
        assert_eq!(
            (ChallengeProfile { t: 2, ..base() }).validate(),
            Err(ProfileError::InvalidArgonT(2))
        );
        assert_eq!(
            (ChallengeProfile { m_kib: 7, ..base() }).validate(),
            Err(ProfileError::InvalidArgonMKib(7))
        );
        assert!(ChallengeProfile {
            m_kib: 65536,
            ..base()
        }
        .validate()
        .is_ok());
        assert_eq!(
            (ChallengeProfile {
                m_kib: 65537,
                ..base()
            })
            .validate(),
            Err(ProfileError::InvalidArgonMKib(65537))
        );
        assert_eq!(
            (ChallengeProfile {
                target_bits: 11,
                ..base()
            })
            .validate(),
            Err(ProfileError::InvalidArgonTargetBits(11))
        );
        assert_eq!(
            (ChallengeProfile {
                target_bits: 0,
                ..base()
            })
            .validate(),
            Err(ProfileError::InvalidArgonTargetBits(0))
        );
        assert_eq!(
            (ChallengeProfile { p: 2, ..base() }).validate(),
            Err(ProfileError::InvalidArgonP(2))
        );
    }
}
