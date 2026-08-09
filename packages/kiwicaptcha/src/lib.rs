//! # KiwiCaptcha
//!
//! A native Rust proof-of-work CAPTCHA engine.
//!
//! KiwiCaptcha combines **SHA-256 proof-of-work** (quantum-safe — a hash
//! function, not a factoring or discrete-log scheme that quantum computers
//! could break), **HMAC-signed single-use IP-bound challenges** to defeat
//! token replay and relay attacks, and an **inline widget** (no external JS,
//! no iframes, no third-party hosts) to avoid the same-origin CSP cascade
//! that made hosted CAPTCHAs unfixable.
//!
//! License: **MIT**

pub mod challenge;
pub mod logo;
pub mod token;
pub mod verify;
pub mod widget;

pub use challenge::{
    hash_ip, issue_challenge, payload_from_record, sign_payload, verify_signature,
    ChallengeCache, ChallengeConfig, ChallengePayload, ChallengeRecord, Issued,
    SOLVER_MAX_TARGET_BITS,
};
pub use logo::{kiwi_lockup_svg, kiwi_logo_svg, kiwi_mark_svg, kiwi_shield_svg};
pub use token::{DecodeError, IssuedChallenge, SolutionToken};
pub use verify::{score_telemetry, solve_for_test, verify_solution, VerifyContext, VerifyError, VerifyOutcome};
pub use widget::kiwi_widget_html;
