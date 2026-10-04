//! Fuzz / property-based test helpers.
//!
//! Generates random inputs of various shapes (strings, emails, ASCII, unicode,
//! raw bytes, floats) for use in property-based fuzz tests.
//!
//! # Reproducibility (SM12 F12)
//!
//! Every generator draws from [`fuzz_rng`], a `StdRng` seeded from the
//! `FUZZ_SEED` environment variable (default: a fixed constant). The seed in
//! effect is printed once per process on first use, so a failing fuzz
//! iteration can be replayed exactly:
//!
//! ```sh
//! FUZZ_SEED=42 cargo test -p fuzz-tests
//! ```
//!
//! Before this change every helper constructed `rand::rng()` (fresh OS
//! entropy per call): failures were irreproducible and could not be
//! shrunk or re-run.

#![deny(unsafe_code)]

use rand::rngs::StdRng;
use rand::Rng;
use rand::SeedableRng;
use std::sync::OnceLock;

/// Default seed when `FUZZ_SEED` is unset. Fixed so CI failures without an
/// explicit seed are still reproducible across runs.
pub const DEFAULT_FUZZ_SEED: u64 = 0x5EED_A9E3_1A11_5EED;

/// The seed every [`fuzz_rng`] instance uses in this process: `FUZZ_SEED`
/// (parsed as u64) when set, [`DEFAULT_FUZZ_SEED`] otherwise.
pub fn fuzz_seed() -> u64 {
    static SEED: OnceLock<u64> = OnceLock::new();
    *SEED.get_or_init(|| {
        let seed = std::env::var("FUZZ_SEED")
            .ok()
            .and_then(|raw| raw.trim().parse::<u64>().ok())
            .unwrap_or(DEFAULT_FUZZ_SEED);
        eprintln!("fuzz-tests: RNG seed = {seed} (set FUZZ_SEED=<u64> to reproduce a failure)");
        seed
    })
}

/// A deterministic RNG for all fuzz input generation in this process.
///
/// Each call returns a FRESH generator at the process seed, so a test's
/// input stream depends only on the sequence of draws, not on unrelated
/// tests that happened to run first (each `tests/*.rs` binary is its own
/// process under cargo-test, and its own process under nextest).
pub fn fuzz_rng() -> StdRng {
    StdRng::seed_from_u64(fuzz_seed())
}

/// splitmix64 — the standard bijective 64-bit mixer (Steele et al.); used
/// to spread the `(seed, nonce)` pair evenly across the 64-bit seed space.
fn splitmix64(z: u64) -> u64 {
    let mut z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
    z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
    z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
    z ^ (z >> 31)
}

/// Seed for the Nth generator call of this process: `splitmix(seed, N)`.
///
/// A fresh generator per call must NOT restart at the same seed — two
/// consecutive `random_bytes(32)` calls would otherwise return identical
/// buffers. The per-call nonce makes every call a distinct deterministic
/// stream, so the whole process replay is reproducible from `FUZZ_SEED`
/// alone. (Under parallel `cargo test`, thread interleaving decides which
/// test consumes which nonce; CI runs nextest — one test per process —
/// where each test's input stream is fully deterministic.)
fn next_stream_seed() -> u64 {
    static NONCE: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let n = NONCE.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
    splitmix64(fuzz_seed().wrapping_add(n.wrapping_mul(0x9E37_79B9_7F4A_7C15)))
}

/// A generator for one helper call: deterministic and distinct per call.
fn stream_rng() -> StdRng {
    StdRng::seed_from_u64(next_stream_seed())
}

/// Generate a random alphanumeric string of the given length.
pub fn random_string(len: usize) -> String {
    let mut rng = stream_rng();
    (0..len)
        .map(|_| {
            let idx = rng.random_range(0..36);
            if idx < 10 {
                (b'0' + idx) as char
            } else {
                (b'a' + idx - 10) as char
            }
        })
        .collect()
}

/// Generate a random email-like string (may or may not be valid).
pub fn random_email() -> String {
    let mut rng = stream_rng();
    let local_len = rng.random_range(1..30);
    let domain_len = rng.random_range(1..20);
    let tld_len = rng.random_range(2..6);
    format!(
        "{}@{}.{}",
        random_string(local_len),
        random_string(domain_len),
        random_string(tld_len)
    )
}

/// Generate a random printable ASCII string of the given length.
pub fn random_ascii(len: usize) -> String {
    let mut rng = stream_rng();
    (0..len)
        .map(|_| rng.random_range(0x20u8..0x7F) as char)
        .collect()
}

/// Generate a random Unicode string of the given length (code-points).
///
/// # Design note (O-28.1)
/// This intentionally allows a subset of control characters (`\n`, `\t`) to
/// exercise edge-cases in downstream parsers.  Surrogate code points are
/// excluded because they are invalid in Rust's `char` type, and other C0/C1
/// control characters (0x7F DEL, 0x80–0x9F) are filtered out by the range
/// start at 0x0020 (space) combined with the `!c.is_control()` guard.
/// This is a deliberate choice for fuzz coverage — **no change needed** per
/// the audit recommendation.
pub fn random_unicode(len: usize) -> String {
    let mut rng = stream_rng();
    (0..len)
        .map(|_| loop {
            let cp = rng.random_range(0x0020..0x10000u32);
            if let Some(c) = char::from_u32(cp) {
                // Skip surrogates
                if !c.is_control() || c == '\n' || c == '\t' {
                    return c;
                }
            }
        })
        .collect()
}

/// Generate random bytes of the given length.
pub fn random_bytes(len: usize) -> Vec<u8> {
    let mut rng = stream_rng();
    (0..len).map(|_| rng.random::<u8>()).collect()
}

/// Generate a random f64 in [min, max).
pub fn random_f64_range(min: f64, max: f64) -> f64 {
    let mut rng = stream_rng();
    rng.random_range(min..max)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn helper_streams_are_distinct_per_call() {
        // The F12 regression this guards against: a fresh generator at the
        // SAME seed per call would make consecutive buffers identical and
        // every "random keys differ" fuzz assertion vacuous.
        let a = random_bytes(32);
        let b = random_bytes(32);
        assert_ne!(a, b, "two random 32-byte buffers must differ");
        let s1 = random_string(24);
        let s2 = random_string(24);
        assert_ne!(s1, s2, "two random 24-char strings must differ");
    }

    #[test]
    fn test_seed_is_deterministic_by_default() {
        // Same process, no FUZZ_SEED → the printed seed is the default and
        // two fresh generators produce identical streams.
        let a = fuzz_rng().random::<u64>();
        let b = fuzz_rng().random::<u64>();
        assert_eq!(a, b, "fresh generators at one seed must agree");
    }

    #[test]
    fn test_random_string_length() {
        assert_eq!(random_string(0).len(), 0);
        assert_eq!(random_string(100).len(), 100);
    }

    #[test]
    fn test_random_email_has_at() {
        let email = random_email();
        assert!(email.contains('@'));
    }

    #[test]
    fn test_random_bytes_length() {
        assert_eq!(random_bytes(256).len(), 256);
    }

    #[test]
    fn test_random_f64_range_bounded() {
        for _ in 0..1000 {
            let v = random_f64_range(0.0, 1.0);
            assert!((0.0..1.0).contains(&v));
        }
    }
}
