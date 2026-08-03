//! # KiwiCaptcha
//!
//! A native Rust, zero-dependency proof-of-work CAPTCHA engine.
//!
//! KiwiCaptcha uses **PBKDF2-HMAC-SHA256** as the client-side hash function
//! (native WebCrypto API in every modern browser, zero JS dependencies),
//! **HMAC-signed + single-use + IP-bound** challenges to defeat token replay
//! and relay attacks, and an inline widget script (no external JS, no iframes)
//! to avoid the same-origin CSP cascade that made third-party CAPTCHAs
//! unfixable. The client solver uses the browser's native
//! WebCrypto API (`crypto.subtle.deriveBits`).
//!
//! License: **MIT** — owned by [Bel Consulting OÜ](https://apexmail.ee)
//!
//! ## Threat model
//!
//! | Threat | Defense |
//! |---|---|
//! | GPU/ASIC brute-force | PBKDF2 at 50,000 iterations — sequential CPU work |
//! | Token replay | HMAC-signed, single-use (Redis DEL), 120s TTL, IP-bound |
//! | ML-based solvers | PoW is mathematical and unlearnable |
//! | CAPTCHA-solving farms | PoW can't be outsourced to humans |
//! | Browser automation | Telemetry scoring: webdriver flag, interaction metrics |
//! | Timing attacks | Reject solves below configurable min_duration_ms |
//! | Cross-scope replay | Scope validation rejects tokens from different flows |

pub mod challenge;
pub mod logo;
pub mod token;
pub mod verify;
pub mod widget;

pub use challenge::{
    hash_ip, issue_challenge, payload_from_record, sign_payload, verify_signature,
    ChallengeConfig, ChallengePayload, ChallengeRecord, Issued,
};
pub use logo::{kiwi_lockup_svg, kiwi_logo_svg, kiwi_mark_svg};
pub use token::{DecodeError, IssuedChallenge, SolutionToken};
pub use verify::{score_telemetry, solve_for_test, verify_solution, VerifyContext, VerifyError, VerifyOutcome};
pub use widget::{kiwi_widget_html, KIWI_WIDGET_HTML};
