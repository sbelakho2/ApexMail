//! # KiwiCaptcha
//!
//! A native Rust proof-of-work anti-abuse engine.
//!
//! KiwiCaptcha provides **privacy-preserving proof-of-work anti-abuse
//! protection** with first-party behavioral heuristics as a supplementary
//! signal. It is **not** a reliable human-vs-bot discriminator: a human never
//! solves the challenge — their CPU does, and a bot's CPU can do the same.
//! The core value is that every signup/login/reset/scraping attempt carries a
//! real, tunable computational cost, making mass abuse uneconomical.
//!
//! The engine combines **SHA-256 proof-of-work** (quantum-safe — a hash
//! function, not a factoring or discrete-log scheme that quantum computers
//! could break) with an optional **Argon2id mode** (memory-hard, ASIC/GPU
//! resistant; issued only with libsodium-representable parameters,
//! `t >= 3 && p == 1`, so cross-language verification always works),
//! **HMAC-signed, IP-bound challenges** (the challenge records an HMAC hash of
//! the issuing client IP and verification compares the current request's IP
//! hash — a best-effort relay mitigation, not a guarantee, since IPs change
//! behind NAT/proxies), and an **inline widget** (no external JS, no iframes,
//! no third-party hosts, optional CSP nonce) to avoid the same-origin CSP
//! cascade that made hosted CAPTCHAs unfixable.
//!
//! The proof-of-work algorithm is carried explicitly on every challenge
//! (see [`challenge::PoWAlgorithm`]), so the solver and the verifier can never
//! disagree about which computation to run.
//!
//! There is no third-party tracking and no third-party requests: behavioral
//! signals (input events, hardware/screen info) are collected and stored
//! first-party only, and are scored as a supplementary signal — they are
//! client-controlled and forgeable.
//!
//! License: **MIT**

pub mod challenge;
pub mod logo;
pub mod token;
pub mod verify;
pub mod widget;

pub use challenge::{
    hash_ip, issue_challenge, now_epoch_micros, payload_from_record, sign_payload,
    verify_signature, ChallengeCache, ChallengeConfig, ChallengePayload, ChallengeRecord, Issued,
    PoWAlgorithm, SOLVER_MAX_ARGON2_M_KIB, SOLVER_MAX_ARGON2_TARGET_BITS, SOLVER_MAX_TARGET_BITS,
};
pub use logo::{kiwi_lockup_svg, kiwi_logo_svg, kiwi_mark_svg, kiwi_shield_svg};
pub use token::{DecodeError, IssuedChallenge, SolutionToken};
pub use verify::{
    score_telemetry, solve_for_test, verify_solution, VerifyContext, VerifyError, VerifyOutcome,
};
pub use widget::{kiwi_widget_html, kiwi_widget_html_default};
