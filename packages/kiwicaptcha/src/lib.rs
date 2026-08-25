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
//! The engine combines **SHA-256 proof-of-work** (CPU-bound, extremely cheap
//! server verification) with an optional **Argon2id mode** (memory-hard,
//! increases the cost of massively parallel and specialized solving; issued
//! only with libsodium-representable parameters, `t >= 3 && p == 1`, so
//! cross-language verification always works), **HMAC-signed challenges with a
//! nonce-bound IP binding** (the record stores `binding_tag`, an HMAC over
//! the nonce + canonical IP bytes — a different tag per challenge, so there
//! is no stable IP-derived identifier; the binding is a best-effort relay
//! mitigation, not a guarantee, since IPs change behind NAT/proxies), and an
//! **inline widget** (no external JS, no iframes, no third-party hosts,
//! optional CSP nonce) to avoid the same-origin CSP cascade that made hosted
//! CAPTCHAs unfixable.
//!
//! The proof-of-work algorithm is carried explicitly on every challenge
//! (see [`challenge::PoWAlgorithm`]), so the solver and the verifier can never
//! disagree about which computation to run.
//!
//! There is no third-party tracking and no third-party requests. Behavioral
//! telemetry is off by default: the widget collects signal fields only in
//! the mode the page opts into (`minimal`/`full` interaction telemetry,
//! first-party only). Device-capability and screen-size signals are absent
//! unless the separate coarse client-context opt-in is enabled, and even
//! then the descriptor is deliberately coarse (viewport class, pointer
//! class, language family, timezone class) — no canvas, audio, font-list,
//! or GPU fingerprints are ever collected. Telemetry is scored only as a
//! supplementary signal: it is client-controlled and forgeable.
//!
//! License: **MIT**

pub mod challenge;
pub mod keys;
pub mod logo;
pub mod profile;
#[cfg(feature = "redis")]
pub mod redis_verify;
pub mod siteverify;
pub mod token;
pub mod verify;
pub mod widget;

pub use challenge::{
    binding_tag, hash_ip, issue_challenge, now_epoch_micros, payload_from_record, sign_payload,
    verify_signature, verify_signature_v2, BindingMode, ChallengeCache, ChallengeConfig,
    ChallengePayload, ChallengeRecord, Issued, PoWAlgorithm, MAX_ARGON_MEMORY_KIB, MAX_ARGON_TIME,
    MAX_CLOCK_SKEW_SECS, MAX_DIFFICULTY, MAX_PARALLELISM, MIN_ARGON_MEMORY_KIB, MIN_ARGON_TIME,
    MIN_DIFFICULTY, MIN_PARALLELISM, SOLVER_MAX_ARGON2_M_KIB, SOLVER_MAX_ARGON2_TARGET_BITS,
    SOLVER_MAX_HASHES, SOLVER_MAX_TARGET_BITS,
};
pub use keys::{DerivedKeys, HKDF_DEPLOY_SALT};
pub use logo::{kiwi_lockup_svg, kiwi_logo_svg, kiwi_mark_svg, kiwi_shield_svg};
pub use profile::{ChallengeProfile, ProfileError};
pub use token::{DecodeError, IssuedChallenge, SolutionToken, MAX_TOKEN_RAW_BYTES};
pub use verify::{
    score_telemetry, solve_for_test, validate_record, verify_solution, VerifyContext, RequestBindingExpectation, VerifyError,
    VerifyOutcome,
};
pub use widget::{kiwi_widget_html, kiwi_widget_html_default};
