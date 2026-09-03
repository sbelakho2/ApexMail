//! The RSW time-lock trapdoor and its shared arithmetic.
//!
//! The optional experimental rsw algorithm (Rivest-Shamir-Wagner style)
//! is a sequential time-lock: the client squares a challenge-derived
//! base T times modulo a 2048-bit composite `n`, and the server verifies
//! instantly because it holds the factorization. This module decodes and
//! validates the two operator-configured secrets, the public modulus `n`
//! and the secret `lambda`, the Carmichael value lcm(p-1, q-1) of the two
//! primes, and computes the expected final value through the trapdoor.
//!
//! The math: with the base derived deterministically from the signed
//! challenge bytes, the client's T sequential squarings produce
//! `base^(2^T) mod n`. When `e = 2^T mod lambda`, Euler's theorem gives
//! `base^(2^T) ≡ base^e (mod n)` for every base, because lambda is a
//! multiple of both `p-1` and `q-1`. The exponent e is never below 1:
//! lambda is even with odd cofactors for 1024-bit primes, so lambda
//! never divides a power of two. The verifier therefore computes
//! `base^e mod n` with one modular exponentiation, about 2048 squarings,
//! while the client without the factorization must perform the full T
//! squarings.
//!
//! The server never reveals the factorization. The configuration holds
//! only `n` and `lambda`, never the primes. `n` is public by design
//! (the client squares modulo n), so it also rides the challenge
//! response; lambda never leaves the server configuration.
//!
//! Validation is shape-only: the modulus must be exactly 256 bytes with
//! the top bit set (a genuine 2048-bit composite) and odd, and lambda
//! must decode to 1..=256 bytes and be even (both `p-1` and `q-1` are
//! even, so lambda is even). The lcm relation cannot be checked without
//! the factorization, exactly like an RSA public key cannot be verified
//! against its private exponent. Both values are canonical standard
//! base64 of their big-endian bytes.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};

/// The modulus is a 2048-bit composite: exactly 256 bytes.
pub const MODULUS_BYTES: usize = 256;

/// The fixed 512-hex wire form of a final value: the 256-byte
/// big-endian residue, zero-padded. Both the solver output and the
/// trapdoor expectation render into this exact shape, so the
/// constant-time comparison runs over equal-length strings.
pub const PROOF_HEX_LENGTH: usize = 512;

/// A decoded and validated rsw trapdoor: the public 2048-bit composite
/// modulus `n = p*q` and the secret `lambda = lcm(p-1, q-1)`.
#[derive(Debug, Clone)]
pub struct RswTrapdoor {
    n: BigUint,
    lambda: BigUint,
}

/// Why an rsw trapdoor configuration is refused. Mirrors the PHP
/// `Rsw` validation vocabulary, so both languages reject the same
/// shapes at their configuration boundaries.
#[derive(Debug, Clone, PartialEq, Eq, thiserror::Error)]
pub enum RswError {
    #[error("rsw value must be canonical standard base64")]
    InvalidBase64,
    #[error("rsw_modulus_n must be the base64 of exactly 256 bytes (a 2048-bit composite)")]
    InvalidModulusSize,
    #[error("rsw_modulus_n must have its top bit set (a genuine 2048-bit composite)")]
    InvalidModulusTopBit,
    #[error("rsw_modulus_n must be odd (the product of two odd primes)")]
    InvalidModulusParity,
    #[error("rsw_lambda must be the base64 of 1..=256 bytes")]
    InvalidLambdaSize,
    #[error("rsw_lambda must be even (lcm(p-1, q-1) of two odd primes)")]
    InvalidLambdaParity,
}

impl RswTrapdoor {
    /// Decode and validate the trapdoor pair, mirroring the PHP `Rsw`
    /// constructor: canonical standard base64 of exactly 256 bytes with
    /// the top bit set and odd for the modulus, canonical standard
    /// base64 of 1..=256 even bytes for lambda.
    pub fn new(modulus_b64: &str, lambda_b64: &str) -> Result<Self, RswError> {
        let n_bytes = canonical_base64_bytes(modulus_b64)?;
        if n_bytes.len() != MODULUS_BYTES {
            return Err(RswError::InvalidModulusSize);
        }
        if n_bytes[0] & 0x80 == 0 {
            return Err(RswError::InvalidModulusTopBit);
        }
        if n_bytes[MODULUS_BYTES - 1] & 1 == 0 {
            return Err(RswError::InvalidModulusParity);
        }
        let lambda_bytes = canonical_base64_bytes(lambda_b64)?;
        if lambda_bytes.is_empty() || lambda_bytes.len() > MODULUS_BYTES {
            return Err(RswError::InvalidLambdaSize);
        }
        if lambda_bytes[lambda_bytes.len() - 1] & 1 == 1 {
            return Err(RswError::InvalidLambdaParity);
        }

        Ok(RswTrapdoor {
            n: BigUint::from_bytes_be(&n_bytes),
            lambda: BigUint::from_bytes_be(&lambda_bytes),
        })
    }

    /// The decoded modulus n.
    pub fn modulus(&self) -> &BigUint {
        &self.n
    }

    /// The expected final value of a challenge as the fixed 512-hex wire
    /// form: `base^(2^T mod lambda) mod n`, with the base the
    /// challenge-derived residue. One modular exponentiation replaces
    /// the client's T sequential squarings.
    pub fn expected_proof_hex(&self, prefix: &str, nonce: &str, t: u64) -> String {
        let base = derive_base(prefix, nonce, &self.n);
        let exponent = BigUint::from(2u8).modpow(&BigUint::from(t), &self.lambda);
        proof_hex(&base.modpow(&exponent, &self.n))
    }
}

/// The challenge-derived base: the SHA-256 of the signed prefix bytes
/// concatenated with the nonce bytes, interpreted as a 256-bit
/// big-endian integer and reduced modulo n. The reduction is a no-op
/// for a conforming modulus (n is at least 2^2047 and the digest at
/// most 2^256-1), and it keeps the residue canonical for any n.
pub fn derive_base(prefix: &str, nonce: &str, n: &BigUint) -> BigUint {
    let mut hasher = Sha256::new();
    hasher.update(prefix.as_bytes());
    hasher.update(nonce.as_bytes());
    let digest = hasher.finalize();
    BigUint::from_bytes_be(&digest) % n
}

/// The fixed 512-hex wire form of a residue: 256 bytes of big-endian,
/// zero-padded to the full length.
pub fn proof_hex(value: &BigUint) -> String {
    format!("{value:0>512x}")
}

/// Strict canonical base64 decode: the value must be exactly the
/// canonical padded standard-base64 encoding of its bytes, the same
/// determinism the token wire enforces.
fn canonical_base64_bytes(value: &str) -> Result<Vec<u8>, RswError> {
    if value.is_empty() {
        return Err(RswError::InvalidBase64);
    }
    let bytes = B64.decode(value).map_err(|_| RswError::InvalidBase64)?;
    if B64.encode(&bytes) != value {
        return Err(RswError::InvalidBase64);
    }
    Ok(bytes)
}

#[cfg(feature = "test-fixtures")]
pub mod fixtures {
    //! Test-only rsw fixture keys and the browser-equivalent sequential
    //! solver. The modulus and lambda are a fixed 2048-bit pair
    //! generated for the suites: `n = p*q` with two 1024-bit primes,
    //! and `lambda = lcm(p-1, q-1)`. The primes themselves are not kept
    //! anywhere in the repository, so the trapdoor cannot be
    //! reconstructed from these files; the values are fixtures, never
    //! production secrets. This surface exists because no production
    //! API may solve an rsw challenge: solving is the client's
    //! sequential work. The browser driver performs it in the worker
    //! asset, and the suites need an equivalent to prove the round
    //! trip. The solver here performs the T sequential modular
    //! squarings exactly like the worker, so a fixture token is
    //! byte-equivalent to a browser token.

    use num_bigint::BigUint;

    /// The shared 2048-bit modulus n (canonical standard base64).
    pub const MODULUS_N_B64: &str = "sL1Mk2YZ4BnznBgWe2YB3uOZ+KFN/VETl1T0H9zuWkP54/nAN8sgPhqozDrRCVQxdJc5IDgkh9EemAGzYjku+zqv2fdryfy5iHbtQEhkHJVt+5f/6yxrZDvHUMhgDRAmLe7rRjEIZC8GqcfcbQyVECgxzNfd3FE+ATeuxc8wKafjUtQ/rvizFBJCo5L0r4U67JDooXVt4yTLtRsoFK3WZBOKIOSZ+E0vZJDt2ddeDSluS/qaqZ5C3dSVeaSyaelX8dGpmovr8xClC+9SKsFnMc+6m9WBo2CsCSpJGk3LZM2847HM5/r2gfmNdN5zRecjEY5MLLEQ/34JinuMtMJpuw==";

    /// The shared secret lambda = lcm(p-1, q-1) (canonical standard
    /// base64).
    pub const LAMBDA_B64: &str = "WF6mSbMM8Az5zgwLPbMA73HM/FCm/qiJy6p6D+53LSH88fzgG+WQHw1UZh1ohKoYukuckBwSQ+iPTADZsRyXfZ1X7Pu15P5cxDt2oCQyDkq2/cv/9ZY1sh3jqGQwBogTFvd1oxiEMheDVOPuNoZKiBQY5mvu7iifAJvXYueYFNMcEwMJdHQi8lgNFBJMwNN+267oViuNdvXRtCLx0MeOSiIPOvDNnLU0Ba4bJg5mTXLY9llIMPtOuHU5BiN8E7IY8kKCdYlpJTgGqv+uu5aNS/SPQl3sMR8dIo3zn7wZhcsMyzJ1n/dLZHNSwXs3QX6XQU+Bx8OVz5pmJYPTJUdsEA==";

    /// The trapdoor pair decoded once.
    pub fn trapdoor() -> super::RswTrapdoor {
        super::RswTrapdoor::new(MODULUS_N_B64, LAMBDA_B64).expect("the fixture trapdoor is valid")
    }

    /// The browser-equivalent final value of an rsw challenge: base
    /// squared T times modulo n, rendered as the fixed 512-hex wire
    /// form. The base derivation is the shared challenge-derived rule.
    pub fn sequential_proof(prefix: &str, nonce: &str, t: u64) -> String {
        use base64::Engine;
        let modulus = BigUint::from_bytes_be(
            &base64::engine::general_purpose::STANDARD
                .decode(MODULUS_N_B64)
                .expect("the fixture modulus is base64"),
        );
        let mut value = super::derive_base(prefix, nonce, &modulus);
        for _ in 0..t {
            value = (&value * &value) % &modulus;
        }
        super::proof_hex(&value)
    }
}
