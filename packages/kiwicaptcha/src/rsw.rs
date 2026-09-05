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
//! Validation first proves the shape: the modulus must be exactly 256
//! bytes with the top bit set (a genuine 2048-bit composite) and odd,
//! and lambda must decode to 1..=256 bytes and be even (both `p-1` and
//! `q-1` are even, so lambda is even). Beyond the shape, three weak or
//! inconsistent inputs are refused: a modulus divisible by any prime at
//! or below 1000 (no product of two 1024-bit primes has one), a
//! probable-prime modulus (a genuine modulus is composite), and a
//! lambda that fails the deterministic trapdoor consistency spot-check
//! over the fixed small-prime base set. The spot-check requires
//! `base^lambda == 1` modulo n per base, the exact condition under
//! which the trapdoor shortcut agrees with the client's sequential
//! squaring at every cost T. So a lambda that passes it for every base
//! of the set behaves as the trapdoor at every tested base. It is a
//! spot-check, not a proof: no fixed base set can establish that lambda
//! is the true Carmichael value of n without the factorization, exactly
//! like an RSA public key cannot be verified against its private
//! exponent. Only the first-party generator's p/q construction is
//! guaranteed to produce lambda = lcm(p-1, q-1), so the residual
//! assurance for a deployed pair is its provenance: operators generate
//! the pair with the shipped `tools/rsw-keygen` binary and record the
//! modulus fingerprint. Both values are canonical standard base64 of
//! their big-endian bytes.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use num_bigint::BigUint;
use sha2::{Digest, Sha256};
use std::fmt;

/// The modulus is a 2048-bit composite: exactly 256 bytes.
pub const MODULUS_BYTES: usize = 256;

/// The fixed 512-hex wire form of a final value: the 256-byte
/// big-endian residue, zero-padded. Both the solver output and the
/// trapdoor expectation render into this exact shape, so the
/// constant-time comparison runs over equal-length strings.
pub const PROOF_HEX_LENGTH: usize = 512;

/// A decoded and validated rsw trapdoor: the public 2048-bit composite
/// modulus `n = p*q` and the secret `lambda = lcm(p-1, q-1)`.
///
/// `Debug` is implemented manually: the derived formatter would print the
/// secret `lambda` into logs, so the manual impl prints the same field set
/// with only the lambda value replaced by `"<redacted>"` (the modulus `n`
/// is public material — the client squares modulo `n`).
#[derive(Clone)]
pub struct RswTrapdoor {
    n: BigUint,
    lambda: BigUint,
}

impl fmt::Debug for RswTrapdoor {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.debug_struct("RswTrapdoor")
            .field("n", &self.n)
            .field("lambda", &"<redacted>")
            .finish()
    }
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
    #[error("rsw_modulus_n must not be divisible by a small prime (a genuine 2048-bit modulus has none; found {0})")]
    InvalidModulusSmallFactor(u32),
    #[error("rsw_modulus_n must not itself be a probable prime (a genuine 2048-bit modulus is the product of two large primes)")]
    InvalidModulusProbablyPrime,
    #[error("rsw_lambda is not a matching trapdoor for rsw_modulus_n (the lambda shortcut diverges from sequential squaring)")]
    InvalidLambdaTrapdoor,
}

impl RswTrapdoor {
    /// Decode and validate the trapdoor pair, mirroring the PHP `Rsw`
    /// constructor: canonical standard base64 of exactly 256 bytes with
    /// the top bit set and odd for the modulus, canonical standard
    /// base64 of 1..=256 even bytes for lambda, then the three
    /// weak-input rejections of [`small_prime_factor`],
    /// [`is_probable_prime`] and [`trapdoor_consistent`].
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

        let n = BigUint::from_bytes_be(&n_bytes);
        let lambda = BigUint::from_bytes_be(&lambda_bytes);
        if let Some(factor) = small_prime_factor(&n) {
            return Err(RswError::InvalidModulusSmallFactor(factor));
        }
        if is_probable_prime(&n) {
            return Err(RswError::InvalidModulusProbablyPrime);
        }
        if !trapdoor_consistent(&n, &lambda) {
            return Err(RswError::InvalidLambdaTrapdoor);
        }

        Ok(RswTrapdoor { n, lambda })
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

/// The trial-division ceiling of the weak-modulus rejection: any prime
/// factor at or below this bound marks the modulus as severely
/// weak, because a genuine modulus is the product of two primes of
/// roughly 1024 bits.
pub const SMALL_PRIME_LIMIT: u32 = 1000;

/// The fixed base set of the trapdoor consistency spot-check: the
/// primes 2, 3, 5, 7, 11, 13, 17 and 19. Each stays below the
/// trial-division ceiling, so a conforming modulus shares no factor
/// with any base and the exponent reduction of the trapdoor applies.
pub const SELFTEST_BASES: [u64; 8] = [2, 3, 5, 7, 11, 13, 17, 19];

/// The largest |D| the Lucas parameter search tries before it declares
/// the input composite. The bound exceeds the smallest value that a
/// 2048-bit prime could exhaust, so a genuine candidate always finds a
/// Jacobi symbol of -1 while a perfect square never does (its symbol is
/// 1 for every coprime D).
const LUCAS_D_BOUND: u64 = 3000;

/// The smallest factor of `n` among the primes at or below
/// [`SMALL_PRIME_LIMIT`], or `None` when `n` has none.
pub fn small_prime_factor(n: &BigUint) -> Option<u32> {
    primes_below(SMALL_PRIME_LIMIT as u64 + 1)
        .into_iter()
        .skip(1)
        .find(|p| n % BigUint::from(*p) == BigUint::from(0u8))
        .map(|p| p as u32)
}

/// Is `n` a probable prime? The yardstick is Baillie's composite of a
/// base-2 strong Miller-Rabin round with the strong Lucas test under
/// Selfridge parameters, the same probable-prime notion PHP reaches
/// through `gmp_prob_prime`. No composite is known to pass the pair at
/// any size, so a genuine 2048-bit semiprime never trips the rejection
/// while every prime does.
pub fn is_probable_prime(n: &BigUint) -> bool {
    if n.bits() <= 1 {
        return false;
    }
    if !n.bit(0) {
        return n == &BigUint::from(2u8);
    }
    // Trial division by the primes below 100: an odd input below 2^14
    // that survives is prime, and every surviving input keeps its
    // smallest factor above 100 for the Lucas parameter search.
    let primes = primes_below(100);
    for p in &primes {
        if n % BigUint::from(*p) == BigUint::from(0u8) {
            return n == &BigUint::from(*p);
        }
    }
    if n.bits() <= 13 {
        return true;
    }
    if !miller_rabin(n, &BigUint::from(2u8)) {
        return false;
    }
    strong_lucas(n)
}

/// Does `lambda` act as the trapdoor of `n`? The check is a
/// deterministic consistency spot-check: per base of the fixed
/// [`SELFTEST_BASES`] set, `base^lambda` must equal 1 modulo `n`. Each
/// equality holds exactly when that base's order divides lambda, which
/// is precisely the condition that the lambda shortcut `base^(2^T mod
/// lambda)` matches the T sequential squarings of the base at every
/// cost T. Every genuine pair passes, because lambda is the Carmichael
/// value of the semiprime; a mismatched or fabricated lambda fails the
/// spot-check almost surely, so it is refused at configuration time.
/// Passing every base is not a proof that lambda is exactly the
/// Carmichael value: only the first-party generator's p/q construction
/// guarantees that, and the pass verdict is the strongest consistency
/// evidence a configuration validator without the primes can hold.
pub fn trapdoor_consistent(n: &BigUint, lambda: &BigUint) -> bool {
    SELFTEST_BASES
        .iter()
        .all(|base| BigUint::from(*base).modpow(lambda, n) == BigUint::from(1u8))
}

/// The primes below `limit`, sieve-generated. The two trial-division
/// bounds and the probable-prime prefilter share this list.
fn primes_below(limit: u64) -> Vec<u64> {
    let mut sieve = vec![true; limit.max(2) as usize];
    sieve[0] = false;
    sieve[1] = false;
    let mut p = 2usize;
    while p * p < sieve.len() {
        if sieve[p] {
            let mut m = p * p;
            while m < sieve.len() {
                sieve[m] = false;
                m += p;
            }
        }
        p += 1;
    }
    (0..sieve.len())
        .filter(|&i| sieve[i])
        .map(|i| i as u64)
        .collect()
}

/// A strong Miller-Rabin round to the base `a`: does `n` survive as a
/// probable prime? The round never rejects a prime, and a composite
/// survives at most a quarter of the bases.
fn miller_rabin(n: &BigUint, a: &BigUint) -> bool {
    let n_minus_1 = n - BigUint::from(1u8);
    let s = n_minus_1.trailing_zeros().expect("n is odd and above 1") as usize;
    let d = &n_minus_1 >> s;
    let mut x = a.modpow(&d, n);
    if x == BigUint::from(1u8) || x == n_minus_1 {
        return true;
    }
    for _ in 0..s - 1 {
        x = (&x * &x) % n;
        if x == n_minus_1 {
            return true;
        }
    }
    false
}

/// The strong Lucas probable-prime test with Selfridge parameters, the
/// second half of the probable-prime yardstick. Returns false on a
/// shared factor or on an exhausted parameter search, which is exactly
/// the composite verdict a perfect square deserves.
fn strong_lucas(n: &BigUint) -> bool {
    let (d_mod, q_mod) = match selfridge_parameters(n) {
        Some(params) => params,
        None => return false,
    };
    let n_plus_1 = n + BigUint::from(1u8);
    let s = n_plus_1.trailing_zeros().expect("n is odd") as usize;
    let d_odd = &n_plus_1 >> s;

    // Double-and-add over the bits of the odd index d_odd, tracking
    // (U_k, V_k, Q^k) with the parameter P fixed at 1. The halving of
    // the add steps multiplies by the inverse of 2 modulo the odd n.
    let half = (n + BigUint::from(1u8)) >> 1usize;
    let mut u = BigUint::from(1u8);
    let mut v = BigUint::from(1u8);
    let mut q_pow = q_mod.clone();
    let mut bit = d_odd.bits() - 1;
    while bit > 0 {
        bit -= 1;
        let doubled_u = (&u * &v) % n;
        let doubled_v = double_v(&v, &q_pow, n);
        q_pow = (&q_pow * &q_pow) % n;
        if d_odd.bit(bit) {
            u = ((&doubled_u + &doubled_v) * &half) % n;
            v = ((&d_mod * &doubled_u) + &doubled_v) % n;
            v = (&v * &half) % n;
            q_pow = (&q_pow * &q_mod) % n;
        } else {
            u = doubled_u;
            v = doubled_v;
        }
    }

    // The strong condition: U_d vanishes, or V at the odd index d or
    // at one of its s-1 doublings vanishes.
    if u == BigUint::from(0u8) || v == BigUint::from(0u8) {
        return true;
    }
    let mut v_doubled = v;
    let mut q_doubled = q_pow;
    for _ in 0..s - 1 {
        v_doubled = double_v(&v_doubled, &q_doubled, n);
        q_doubled = (&q_doubled * &q_doubled) % n;
        if v_doubled == BigUint::from(0u8) {
            return true;
        }
    }
    false
}

/// The doubling step V_2k = V_k^2 - 2 Q^k of the Lucas chain.
fn double_v(v: &BigUint, q_pow: &BigUint, n: &BigUint) -> BigUint {
    let twice_q = (q_pow << 1usize) % n;
    let squared = (v * v) % n;
    (squared + n - twice_q) % n
}

/// The Selfridge parameter search: the first D of 5, -7, 9, -11, ...
/// with a Jacobi symbol of -1 against the odd `n`, returned as D mod n
/// and Q = (1 - D) / 4 mod n. A shared factor or an exhausted search
/// (a perfect square, whose symbol is 1 for every coprime D) yields
/// None, the composite verdict.
fn selfridge_parameters(n: &BigUint) -> Option<(BigUint, BigUint)> {
    let mut magnitude = 5u64;
    while magnitude <= LUCAS_D_BOUND {
        let symbol_of_m = jacobi(&BigUint::from(magnitude), n);
        if symbol_of_m == 0 {
            return None;
        }
        let positive = magnitude % 4 == 1;
        let symbol = if positive || !n.bit(1) {
            symbol_of_m
        } else {
            -symbol_of_m
        };
        if symbol == -1 {
            let d_mod = if positive {
                BigUint::from(magnitude)
            } else {
                n - BigUint::from(magnitude)
            };
            let q = if positive {
                n - BigUint::from((magnitude - 1) / 4)
            } else {
                BigUint::from((magnitude + 1) / 4)
            };
            return Some((d_mod, q));
        }
        magnitude += 2;
    }
    None
}

/// The Jacobi symbol of `a` against the odd positive `n`: 1, -1, or 0
/// when the two share a factor. The classic binary algorithm.
fn jacobi(a: &BigUint, n: &BigUint) -> i8 {
    let mut a = a % n;
    let mut n = n.clone();
    let mut result = 1i8;
    while a != BigUint::from(0u8) {
        while !a.bit(0) {
            a >>= 1usize;
            let n_low = low_bits(&n, 3);
            if n_low == 3 || n_low == 5 {
                result = -result;
            }
        }
        std::mem::swap(&mut a, &mut n);
        if low_bits(&a, 2) == 3 && low_bits(&n, 2) == 3 {
            result = -result;
        }
        a = &a % &n;
    }
    if n == BigUint::from(1u8) {
        result
    } else {
        0
    }
}

/// The low `bits` (at most 8) of a big integer, as a small value.
fn low_bits(n: &BigUint, bits: u8) -> u32 {
    let mut value = 0u32;
    for offset in 0..bits {
        if n.bit(offset as u64) {
            value |= 1 << offset;
        }
    }
    value
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn trapdoor_debug_redacts_lambda_but_prints_the_public_modulus() {
        let trapdoor = fixtures::trapdoor();
        let debug = format!("{trapdoor:?}");
        // The secret lambda never prints — the Debug shape shows the
        // public modulus n (as its own decimal digits, like the derived
        // formatter did) with the lambda slot replaced by the marker.
        assert!(debug.starts_with("RswTrapdoor { n: "));
        assert!(debug.ends_with("lambda: \"<redacted>\" }"));
        assert!(!debug.contains(fixtures::LAMBDA_B64));
        assert!(debug.contains(&format!("{}", trapdoor.modulus())));
        assert_eq!(debug.matches("<redacted>").count(), 1);
    }

    use base64::engine::general_purpose::STANDARD as TestB64;
    use base64::Engine;

    /// A real 2048-bit probable prime, generated with openssl for the
    /// probable-prime rejection tests. A genuine modulus must never
    /// look like it: the constant is a prime, so both language cores
    /// refuse it deterministically and cheaply.
    const PROBABLE_PRIME_N_B64: &str = "3QB709I66Q8Ivp2P5RtgD4+ci38dHuAuXfzGL4KtCk34UGX9uOG1FgNV92B9BcVS1iX4JCYdqN9cHg62sqEWx+p0fn7rUCuPYZSFpnwcWpVjHMbigzz2wjWt2mhkqLtbgZ/+nar/ptQu7aHKOrQYVAppYf0txmfwtnUbHSWpyMZhUv10JSnNPRuPL6wrb0cH8TjHex2W90islc3qPAwi9lAZdtX/+OepFBLDkmjnE4yi2SyBZ75kHWn+ve7nXg0352zbPtL3gos658lJsVVdt3IbqeVf1I9wnViRYpIS+EYHK5olWm3+sOxwZfbixlgLh0p3JafQoCnZpkF2j+9Gzw==";

    /// A real 1024-bit prime whose square is a 2048-bit composite with
    /// no small factor: the square path of the probable-prime test.
    const PRIME_1024_B64: &str = "2PBoikMccpiIzz4G2CatF+bwUSHAUCsY31/vtWRzn2niSrjQDA7VZiv2W2Q3dwKlp2rtHp8irvTOxrCpyt1WoHB3epXlGi9BenmaFenwufyghc4/UIk30jERCOb5zvo+scyQVrBZjGYgROIe5zgVhmMfXnbvCxaTqpPTyFckqcc=";

    /// The classic strong pseudoprimes to the first small prime bases:
    /// each survives the matching Miller-Rabin rounds and must still
    /// read as composite under the full probable-prime yardstick.
    const STRONG_PSEUDOPRIMES: [u64; 4] = [1373653, 25326001, 3215031751, 3825123056546413051];

    fn decode_b64(value: &str) -> Vec<u8> {
        TestB64.decode(value).expect("the constant is base64")
    }

    fn big_from_b64(value: &str) -> BigUint {
        BigUint::from_bytes_be(&decode_b64(value))
    }

    fn modulus_b64(value: &BigUint) -> String {
        let bytes = value.to_bytes_be();
        assert!(bytes.len() <= MODULUS_BYTES, "test modulus fits 256 bytes");
        let mut padded = vec![0u8; MODULUS_BYTES - bytes.len()];
        padded.extend_from_slice(&bytes);
        TestB64.encode(&padded)
    }

    /// The odd 2048-bit multiple factor * (2^b + 1) with the top bit
    /// set: exactly the shape of a genuine modulus, severely
    /// weak underneath it.
    fn weak_modulus_with_factor(factor: u64) -> BigUint {
        let factor_bits = 64 - factor.leading_zeros();
        let shift = 2048 - factor_bits;
        BigUint::from(factor) * ((BigUint::from(1u8) << shift) + BigUint::from(1u8))
    }

    #[test]
    fn fixture_trapdoor_pair_still_validates() {
        assert!(RswTrapdoor::new(fixtures::MODULUS_N_B64, fixtures::LAMBDA_B64).is_ok());
    }

    #[test]
    fn even_modulus_is_refused() {
        let mut bytes = decode_b64(fixtures::MODULUS_N_B64);
        bytes[MODULUS_BYTES - 1] &= !1;
        assert!(matches!(
            RswTrapdoor::new(&TestB64.encode(&bytes), fixtures::LAMBDA_B64),
            Err(RswError::InvalidModulusParity)
        ));
    }

    #[test]
    fn short_modulus_is_refused() {
        let short = TestB64.encode(&decode_b64(fixtures::MODULUS_N_B64)[..128]);
        assert!(matches!(
            RswTrapdoor::new(&short, fixtures::LAMBDA_B64),
            Err(RswError::InvalidModulusSize)
        ));
    }

    #[test]
    fn high_bit_clear_modulus_is_refused() {
        let mut bytes = vec![0xffu8; MODULUS_BYTES];
        bytes[0] = 0x7f;
        assert!(matches!(
            RswTrapdoor::new(&TestB64.encode(&bytes), fixtures::LAMBDA_B64),
            Err(RswError::InvalidModulusTopBit)
        ));
    }

    #[test]
    fn odd_lambda_is_refused() {
        let mut bytes = decode_b64(fixtures::LAMBDA_B64);
        let last = bytes.len() - 1;
        bytes[last] |= 1;
        assert!(matches!(
            RswTrapdoor::new(fixtures::MODULUS_N_B64, &TestB64.encode(&bytes)),
            Err(RswError::InvalidLambdaParity)
        ));
    }

    #[test]
    fn small_prime_factor_of_the_modulus_is_refused() {
        let weak = weak_modulus_with_factor(3);
        assert_eq!(small_prime_factor(&weak), Some(3));
        assert!(matches!(
            RswTrapdoor::new(&modulus_b64(&weak), fixtures::LAMBDA_B64),
            Err(RswError::InvalidModulusSmallFactor(3))
        ));
        // The even exponent keeps 2^2044 + 1 away from the factor 3, so
        // the smallest factor of the multiple really is 5.
        let by_five = BigUint::from(5u8) * ((BigUint::from(1u8) << 2044usize) + BigUint::from(1u8));
        assert_eq!(small_prime_factor(&by_five), Some(5));
        assert_eq!(
            small_prime_factor(&big_from_b64(fixtures::MODULUS_N_B64)),
            None
        );
    }

    #[test]
    fn probable_prime_modulus_is_refused() {
        assert!(is_probable_prime(&big_from_b64(PROBABLE_PRIME_N_B64)));
        assert!(matches!(
            RswTrapdoor::new(PROBABLE_PRIME_N_B64, fixtures::LAMBDA_B64),
            Err(RswError::InvalidModulusProbablyPrime)
        ));
    }

    #[test]
    fn mismatched_lambda_is_refused() {
        let lambda = big_from_b64(fixtures::LAMBDA_B64);
        let shifted = &lambda - BigUint::from(2u8);
        assert!(matches!(
            RswTrapdoor::new(
                fixtures::MODULUS_N_B64,
                &TestB64.encode(shifted.to_bytes_be())
            ),
            Err(RswError::InvalidLambdaTrapdoor)
        ));
        assert!(!trapdoor_consistent(
            &big_from_b64(fixtures::MODULUS_N_B64),
            &shifted
        ));
        assert!(trapdoor_consistent(
            &big_from_b64(fixtures::MODULUS_N_B64),
            &lambda
        ));
    }

    #[test]
    fn probable_prime_verdicts_match_known_primes_and_pseudoprimes() {
        let primes = primes_below(5000);
        for p in primes.iter().filter(|p| **p >= 3) {
            assert!(is_probable_prime(&BigUint::from(*p)), "{p} is prime");
        }
        for composite in STRONG_PSEUDOPRIMES {
            assert!(
                !is_probable_prime(&BigUint::from(composite)),
                "{composite} is a strong pseudoprime, never a probable prime"
            );
        }
        assert!(!is_probable_prime(&BigUint::from(9u8)));
        assert!(!is_probable_prime(&big_from_b64(fixtures::MODULUS_N_B64)));
        assert!(!is_probable_prime(&big_from_b64(PRIME_1024_B64).pow(2u32)));
    }

    #[test]
    fn shifted_lambda_fails_the_euler_test_at_a_second_base() {
        // The mutated lambda diverges from the genuine Carmichael
        // value: the consistency spot-check fails at every base of the
        // fixed set, not just the cheapest one. The assertion probes
        // base 3 directly.
        let n = big_from_b64(fixtures::MODULUS_N_B64);
        let shifted = big_from_b64(fixtures::LAMBDA_B64) - BigUint::from(2u8);
        assert_ne!(BigUint::from(3u8).modpow(&shifted, &n), BigUint::from(1u8));
    }

    #[test]
    fn jacobi_symbol_agrees_with_small_tables() {
        assert_eq!(jacobi(&BigUint::from(5u16), &BigUint::from(2047u16)), -1);
        assert_eq!(jacobi(&BigUint::from(5u16), &BigUint::from(89u16)), 1);
        assert_eq!(jacobi(&BigUint::from(3u8), &BigUint::from(11u8)), 1);
        assert_eq!(jacobi(&BigUint::from(2u8), &BigUint::from(7u8)), 1);
        assert_eq!(jacobi(&BigUint::from(0u8), &BigUint::from(7u8)), 0);
        assert_eq!(jacobi(&BigUint::from(3u8), &BigUint::from(9u8)), 0);
        // (5|21) = (5|3) * (5|7) = -1 * -1 = 1
        assert_eq!(jacobi(&BigUint::from(5u16), &BigUint::from(21u16)), 1);
    }
}
