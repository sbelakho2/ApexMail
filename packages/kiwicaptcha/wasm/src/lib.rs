//! KiwiCaptcha WASM solver — browser-side proof-of-work in Rust.
//!
//! This crate compiles to WebAssembly and replaces the inline JavaScript
//! PBKDF2 brute-force loop.  The host page loads the `.wasm` binary and
//! calls `solve_challenge()` to find a valid counter.

use base64::Engine;
use hmac::Hmac;
use pbkdf2::pbkdf2;
use sha2::Sha256;
use wasm_bindgen::prelude::*;

/// Solve a KiwiCaptcha challenge by brute-forcing a PBKDF2 counter.
///
/// Returns a JSON string `{"counter":N,"duration_ms":M}` on success,
/// or `null` if no solution is found within the safety cap.
///
/// # Arguments
/// * `prefix`    — the challenge prefix (`challenge|salt|`) used as the PBKDF2 preimage
/// * `salt_b64`  — the base64-encoded salt from the challenge response
/// * `iterations`— PBKDF2 iteration count (`mKib` from the challenge response)
/// * `target_bits`— required leading zero bits in the hash output
#[wasm_bindgen]
pub fn solve_challenge(
    prefix: &str,
    salt_b64: &str,
    iterations: u32,
    target_bits: u32,
) -> Option<String> {
    let salt = base64::engine::general_purpose::STANDARD
        .decode(salt_b64)
        .ok()?;

    let start = web_time();
    let cap = 500_000u64;

    for counter in 0u64.. {
        let password = format!("{prefix}{counter}");
        let mut out = [0u8; 32];
        pbkdf2::<Hmac<Sha256>>(password.as_bytes(), &salt, iterations, &mut out);

        if leading_zeros(&out) >= target_bits {
            let duration = web_time() - start;
            let json = format!(r#"{{"counter":{counter},"duration_ms":{duration}}}"#);
            return Some(json);
        }

        if counter > cap {
            break;
        }
    }

    None
}

/// Count leading zero bits in a byte slice (big-endian).
fn leading_zeros(bytes: &[u8]) -> u32 {
    let mut count = 0u32;
    for &byte in bytes {
        if byte == 0 {
            count += 8;
        } else {
            count += byte.leading_zeros();
            break;
        }
    }
    count
}

/// Milliseconds since page load (browser `performance.now()`).
#[wasm_bindgen]
extern "C" {
    #[wasm_bindgen(js_namespace = performance, js_name = now)]
    fn web_time() -> f64;
}
