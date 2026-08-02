//! # KiwiCaptcha
//!
//! A native Rust, memory-hard proof-of-work CAPTCHA engine.
//!
//! KiwiCaptcha replaces external/self-hosted CAPTCHA services (mCaptcha) with a
//! first-party, fully-Rust implementation. It uses **Argon2id** (memory-hard) to
//! neutralize GPU/ASIC brute-forcing, **HMAC-signed + single-use + IP-bound**
//! challenges to defeat token replay and relay attacks, and an inline widget
//! script (no external JS, no iframes) to avoid the same-origin CSP cascade
//! that made mCaptcha unfixable.
//!
//! ## Threat model (2024-2026 evasion research)
//!
//! | Threat | Defense |
//! |---|---|
//! | GPU/ASIC brute-force | Argon2id at 64-128 MiB collapses GPU advantage to ~1.5× |
//! | Token replay | HMAC-signed, single-use (Redis DEL on verify), 120s TTL, IP-bound |
//! | ML-based solvers | PoW is mathematical and unlearnable — no visual pattern |
//! | CAPTCHA-solving farms | PoW can't be outsourced to humans (no perceptual task) |
//! | Browser automation | Passive telemetry bundle scored as a composite risk |
//! | Timing attacks | Reject solves below theoretical Argon2id minimum |
//!
//! ## Protocol
//!
//! 1. Client `POST /api/kcaptcha/challenge {scope}` → server mints + signs a
//!    challenge, stores state in Redis, returns [`token::IssuedChallenge`].
//! 2. Client brute-forces a `counter` so the Argon2id output has
//!    `target_bits` leading zeros, reports via `kiwi__token`.
//! 3. Server [`verify::verify_solution`] re-derives the hash, checks leading
//!    zeros + TTL + signature + IP + duration, marks consumed.

pub mod challenge;
pub mod logo;
pub mod token;
pub mod verify;

pub use challenge::{
    hash_ip, issue_challenge, payload_from_record, sign_payload, verify_signature,
    ChallengeConfig, ChallengePayload, ChallengeRecord, Issued,
};
pub use logo::{kiwi_lockup_svg, kiwi_logo_svg, kiwi_mark_svg};
pub use token::{DecodeError, IssuedChallenge, SolutionToken};
pub use verify::{solve_for_test, verify_solution, VerifyContext, VerifyError, VerifyOutcome};
