//! Token structures for KiwiCaptcha challenge issuance and solution submission.
//!
//! The protocol has two phases:
//! 1. **Challenge** — the server mints an [`IssuedChallenge`] (HMAC-signed,
//!    nonce-stamped, IP-bound) and the client must solve it.
//! 2. **Solution** — the client submits a [`SolutionToken`] containing the
//!    nonce, the winning counter, the solve duration, and a telemetry bundle.
//!
//! Both structures are designed to be JSON-serializable so they can flow over
//! HTTP between the inline widget script and the `/api/kcaptcha/*` routes.

use base64::engine::general_purpose::STANDARD as B64;
use base64::Engine;
use serde::{Deserialize, Serialize};

use crate::challenge::PoWAlgorithm;

/// A single issued challenge, returned by `POST /api/kcaptcha/challenge`.
///
/// The `challenge` field is the HMAC-signed challenge string the client must
/// fold into the proof-of-work. The difficulty target and algorithm are
/// included so the client solver and the server verifier run identical
/// computations.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct IssuedChallenge {
    /// Single-use nonce (base64, 32 random bytes). The client must include this
    /// in the solution token so the server can look up the stored challenge record.
    pub nonce: String,
    /// Opaque challenge string (base64 of the signed payload). The client
    /// passes this verbatim into the hash preimage.
    pub challenge: String,
    /// Base64-encoded salt (16 bytes). Folded into the hash input so that
    /// identical challenge + counter pairs still vary across challenges.
    pub salt: String,
    /// The proof-of-work algorithm. The solver MUST dispatch on this field,
    /// never on a numeric heuristic.
    pub algorithm: PoWAlgorithm,
    /// Memory cost in KiB for Argon2id challenges (0 for SHA-256 challenges).
    pub m_kib: u32,
    /// Time cost for Argon2id challenges.
    pub t: u32,
    /// Parallelism for Argon2id challenges.
    pub p: u32,
    /// Number of leading zero bits required in the hash output (difficulty).
    pub target_bits: u32,
    /// Challenge lifetime in seconds (for client-side countdown display).
    pub ttl_secs: u64,
    /// Minimum plausible solve duration in ms (server-enforced).
    pub min_duration_ms: u64,
    /// The prefix the client must prepend to the counter when forming inputs
    /// (bound to the challenge so the solver cannot reuse a counter from a
    /// different challenge).
    pub prefix: String,
    /// The server-issued decoy (honeypot) form-field name armed for this
    /// challenge, when the deployment enables the decoy surface: a random
    /// name from the crate's server-side pool (CSPRNG-picked per issuance,
    /// matching `[A-Za-z0-9_-]{1,64}`). The widget driver renders a hidden
    /// text input with exactly this name next to the token input and never
    /// auto-fills it — a submission that carries a value in it is bot
    /// evidence (the risk engine's `DecoyFieldSubmitted` event /
    /// `honeypot_hit` signal). The name is authenticated: it is signed
    /// into the protocol v3 canonical payload as the final
    /// `|<decoy_field>` segment (see
    /// [`crate::challenge::canonical_signing_input_v2`]), so a client
    /// cannot strip or swap it without breaking the signature the
    /// verifier re-checks. An armed challenge is issued as
    /// `protocol_version == 3`.
    ///
    /// Wire compatibility: unarmed challenges are byte-identical to the
    /// pre-decoy format — the key is absent from the JSON when no decoy
    /// is armed (`skip_serializing_if = "Option::is_none"`), which is the
    /// old behavior, and old payloads (no key) deserialize with `None`. A
    /// decoy-armed challenge is protocol v3 and requires a v3-capable
    /// verifier (an old verifier rejects version 3 as unknown — the
    /// capability is inferable from `protocol_version`).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decoy_field: Option<String>,
}

/// The client-submitted solution, decoded from the `kiwi__token` hidden input.
///
/// The wire format is `base64(nonce || "." || counter || "." || duration_ms || "." || telemetry_json)`.
/// Hard ceiling for the client-reported duration (telemetry only): 1 hour.
pub const MAX_DURATION_MS: u64 = 3_600_000;

/// Hard ceiling on the RAW token length (bytes) accepted by
/// [`SolutionToken::decode`]. The canonical wire form of a
/// legitimate token is a few hundred bytes (32-byte nonce + counter +
/// duration + a small telemetry object); 32 KiB is far beyond any of them.
/// The bound is enforced before the base64 decode, so an oversized token is
/// rejected with [`DecodeError::TooLarge`] without spending any work on —
/// or allocating for — a decode of attacker-supplied bytes.
pub const MAX_TOKEN_RAW_BYTES: usize = 32_768;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SolutionToken {
    /// The nonce from the original challenge (base64, 32 bytes).
    pub nonce: String,
    /// The winning counter value.
    pub counter: u64,
    /// Wall-clock solve duration in milliseconds, reported by the client.
    pub duration_ms: u64,
    /// Raw telemetry JSON (browser/environment signals), opaque to the token
    /// layer — scored by the verifier.
    pub telemetry: serde_json::Value,
}

impl SolutionToken {
    /// Encode the token into the compact wire format stored in `kiwi__token`.
    pub fn encode(&self) -> String {
        let telemetry_str = serde_json::to_string(&self.telemetry).unwrap_or_default();
        let plain = format!(
            "{}.{}.{}.{}",
            self.nonce, self.counter, self.duration_ms, telemetry_str
        );
        B64.encode(plain)
    }

    /// Decode a token from the `kiwi__token` hidden-input value.
    pub fn decode(raw: &str) -> Result<Self, DecodeError> {
        // Early bound: never even attempt to base64-decode an oversized input.
        // 32 KiB is far beyond any legitimate token (a real token is a few
        // hundred bytes), so anything larger is rejected before any work is
        // spent on it.
        if raw.len() > MAX_TOKEN_RAW_BYTES {
            return Err(DecodeError::TooLarge);
        }
        // Strict canonical decode: the input must be exactly the
        // canonical padded standard-base64 encoding of the decoded bytes.
        // Any deviation — url-safe alphabet, missing/loose padding, trailing
        // bits, surrounding whitespace — re-encodes to a different string, so
        // the byte-exact re-encode comparison enforces the single accepted
        // encoding; whitespace is not part of the wire language.
        let plain = B64.decode(raw).map_err(|_| DecodeError::InvalidBase64)?;
        if B64.encode(&plain) != raw {
            return Err(DecodeError::InvalidBase64);
        }
        let plain = String::from_utf8(plain).map_err(|_| DecodeError::InvalidUtf8)?;

        // The telemetry segment is JSON which may itself contain dots, so split
        // only on the first three dots.
        let mut parts = plain.splitn(4, '.');
        let nonce = parts.next().ok_or(DecodeError::Malformed)?;
        let counter_str = parts.next().ok_or(DecodeError::Malformed)?;
        let duration_str = parts.next().ok_or(DecodeError::Malformed)?;
        let telemetry_str = parts.next().ok_or(DecodeError::Malformed)?;

        // The nonce must be exactly the standard-base64 encoding of 32 bytes
        // (44 characters): a well-formed nonce is what the issuer mints, so
        // any deviation means the token did not come from a real challenge.
        // The canonicality check below enforces the single accepted encoding
        // (padded, standard alphabet) — a 43-char unpadded or url-safe
        // variant is rejected.
        if nonce.len() != 44 {
            return Err(DecodeError::Malformed);
        }
        match B64.decode(nonce) {
            Ok(bytes) if bytes.len() == 32 && B64.encode(&bytes) == nonce => {}
            _ => return Err(DecodeError::Malformed),
        }

        let counter: u64 = counter_str
            .parse()
            .map_err(|_| DecodeError::InvalidCounter)?;
        // The counter must be within what any solver can produce: the JS
        // solver searches counters below the solver maximum (5,000,000
        // attempts), so the largest legitimate counter is 4,999,999 — anything >= 5M
        // was not minted by a real solve (matches PHP exactly).
        if counter >= crate::challenge::SOLVER_MAX_HASHES {
            return Err(DecodeError::InvalidCounter);
        }
        let duration_ms: u64 = duration_str
            .parse()
            .map_err(|_| DecodeError::InvalidDuration)?;
        // The client-reported duration is telemetry only, but the wire
        // protocol bounds it (0 .. 3_600_000 ms = 1 hour) so both
        // implementations accept exactly the same language.
        if duration_ms > MAX_DURATION_MS {
            return Err(DecodeError::InvalidDuration);
        }
        let telemetry: serde_json::Value =
            serde_json::from_str(telemetry_str).map_err(|_| DecodeError::Malformed)?;
        // Telemetry must be a JSON object in both implementations ({} for an
        // off widget, {v,mode,me,ke,...} otherwise) — arrays, strings,
        // numbers, booleans and null are not part of the wire language.
        if !telemetry.is_object() {
            return Err(DecodeError::Malformed);
        }

        Ok(Self {
            nonce: nonce.to_string(),
            counter,
            duration_ms,
            telemetry,
        })
    }
}

/// Error returned when a [`SolutionToken`] cannot be decoded.
#[derive(Debug, Clone, Copy, PartialEq, Eq, thiserror::Error)]
pub enum DecodeError {
    #[error("token is not valid base64")]
    InvalidBase64,
    #[error("token payload is not valid UTF-8")]
    InvalidUtf8,
    #[error("token is too large")]
    TooLarge,
    #[error("token is malformed (expected nonce.counter.duration.telemetry)")]
    Malformed,
    #[error("counter is invalid or exceeds the solver maximum (5_000_000)")]
    InvalidCounter,
    #[error("duration segment is not a valid integer")]
    InvalidDuration,
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Base64 encoding of 32 zero bytes — a well-formed issuer nonce.
    const VALID_NONCE: &str = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=";

    #[test]
    fn token_roundtrips_through_encode_decode() {
        let token = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 42,
            duration_ms: 850,
            telemetry: serde_json::json!({"wd": true, "hc": 8}),
        };
        let encoded = token.encode();
        let decoded = SolutionToken::decode(&encoded).unwrap();
        assert_eq!(decoded.nonce, VALID_NONCE);
        assert_eq!(decoded.counter, 42);
        assert_eq!(decoded.duration_ms, 850);
        assert_eq!(decoded.telemetry["wd"], true);
        assert_eq!(decoded.telemetry["hc"], 8);
    }

    #[test]
    fn decode_rejects_garbage() {
        assert!(SolutionToken::decode("!!!not-base64!!!").is_err());
    }

    #[test]
    fn telemetry_with_embedded_dots_is_preserved() {
        // A JSON string value containing dots must not break the splitn(4).
        let token = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({"ua": "Mozilla/5.0 (X11; Linux x86_64)"}),
        };
        let encoded = token.encode();
        let decoded = SolutionToken::decode(&encoded).unwrap();
        assert_eq!(decoded.telemetry["ua"], "Mozilla/5.0 (X11; Linux x86_64)");
    }

    #[test]
    fn decode_rejects_oversized_token() {
        // Raw input beyond the 32 KiB bound must be rejected without decoding.
        let huge = "A".repeat(MAX_TOKEN_RAW_BYTES + 1);
        assert!(
            matches!(SolutionToken::decode(&huge), Err(DecodeError::TooLarge)),
            ">32 KiB token must be rejected with TooLarge"
        );
        // Exactly at the bound: not too large (may still fail base64/utf8,
        // but must NOT be a TooLarge error).
        let boundary = "A".repeat(MAX_TOKEN_RAW_BYTES);
        assert!(
            !matches!(SolutionToken::decode(&boundary), Err(DecodeError::TooLarge)),
            "32 KiB token must not be rejected as TooLarge"
        );
    }

    #[test]
    fn decode_rejects_megabyte_token_by_length_cap() {
        // A 1 MB token is rejected by the length cap before any
        // base64 decode — no large allocation, no decode work, and no panic.
        let mega = "A".repeat(1_000_000);
        assert!(
            matches!(SolutionToken::decode(&mega), Err(DecodeError::TooLarge)),
            "a 1 MB token must be rejected by the pre-decode length cap"
        );
    }

    #[test]
    fn decode_rejects_recursively_nested_telemetry() {
        // The telemetry JSON parse respects serde_json's default
        // recursion limit (the crate never disables it) — a telemetry object
        // nested deeper than the limit is rejected with Malformed (a clean
        // error), never a stack overflow. 200 levels exceed the 128-level
        // default while staying far inside the token length cap.
        let mut telemetry = serde_json::json!({});
        for _ in 0..200 {
            telemetry = serde_json::json!({"a": telemetry});
        }
        let token = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 1,
            duration_ms: 2,
            telemetry,
        };
        assert!(
            matches!(
                SolutionToken::decode(&token.encode()),
                Err(DecodeError::Malformed)
            ),
            "recursively nested telemetry must be rejected with Malformed, never a crash"
        );
    }

    #[test]
    fn decode_rejects_counter_at_and_beyond_solver_max() {
        // The JS solver searches counters below the solver maximum
        // (5,000,000 attempts), so the largest legitimate counter is
        // 4,999,999 — the cap value itself is never minted by a real solve
        // (off-by-one parity with PHP).
        for counter in [
            crate::challenge::SOLVER_MAX_HASHES,
            crate::challenge::SOLVER_MAX_HASHES + 1,
        ] {
            let token = SolutionToken {
                nonce: VALID_NONCE.to_string(),
                counter,
                duration_ms: 2,
                telemetry: serde_json::json!({}),
            };
            assert!(
                matches!(
                    SolutionToken::decode(&token.encode()),
                    Err(DecodeError::InvalidCounter)
                ),
                "counter {counter} must be rejected"
            );
        }
    }

    #[test]
    fn decode_accepts_counter_just_below_solver_max() {
        let token = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: crate::challenge::SOLVER_MAX_HASHES - 1,
            duration_ms: 2,
            telemetry: serde_json::json!({}),
        };
        assert!(SolutionToken::decode(&token.encode()).is_ok());
    }

    #[test]
    fn decode_rejects_non_object_telemetry() {
        // Wire parity with PHP: telemetry must be a JSON object — arrays,
        // strings, numbers, booleans and null are not part of the language.
        for bad in [
            serde_json::json!([]),
            serde_json::json!("hello"),
            serde_json::json!(123),
            serde_json::json!(true),
            serde_json::Value::Null,
        ] {
            let token = SolutionToken {
                nonce: VALID_NONCE.to_string(),
                counter: 1,
                duration_ms: 2,
                telemetry: bad,
            };
            assert!(
                matches!(
                    SolutionToken::decode(&token.encode()),
                    Err(DecodeError::Malformed)
                ),
                "non-object telemetry must be rejected"
            );
        }
    }

    #[test]
    fn decode_rejects_duration_beyond_protocol_bound() {
        let token = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 1,
            duration_ms: MAX_DURATION_MS + 1,
            telemetry: serde_json::json!({}),
        };
        assert!(
            matches!(
                SolutionToken::decode(&token.encode()),
                Err(DecodeError::InvalidDuration)
            ),
            "duration above MAX_DURATION_MS must be rejected"
        );
        let ok = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 1,
            duration_ms: MAX_DURATION_MS,
            telemetry: serde_json::json!({}),
        };
        assert!(SolutionToken::decode(&ok.encode()).is_ok());
    }

    #[test]
    fn decode_rejects_nonce_with_wrong_length() {
        let token = SolutionToken {
            nonce: "abc123".to_string(), // 6 chars, not the 44-char issuer format
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({}),
        };
        assert!(
            matches!(
                SolutionToken::decode(&token.encode()),
                Err(DecodeError::Malformed)
            ),
            "short nonce must be rejected as Malformed"
        );
    }

    #[test]
    fn decode_rejects_nonce_that_is_not_valid_base64() {
        // 44 characters but not decodable standard base64.
        let bad_nonce = "!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!";
        assert_eq!(bad_nonce.len(), 44);
        let token = SolutionToken {
            nonce: bad_nonce.to_string(),
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({}),
        };
        assert!(
            matches!(
                SolutionToken::decode(&token.encode()),
                Err(DecodeError::Malformed)
            ),
            "non-base64 nonce must be rejected as Malformed"
        );
    }

    #[test]
    fn decode_rejects_nonce_that_decodes_to_wrong_byte_count() {
        // 44 valid base64 chars that decode to something other than 32 bytes.
        let mut bytes = vec![0u8; 33];
        bytes[0] = 0xFF;
        let bad_nonce = B64.encode(&bytes);
        assert_eq!(bad_nonce.len(), 44);
        let token = SolutionToken {
            nonce: bad_nonce,
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({}),
        };
        assert!(
            matches!(
                SolutionToken::decode(&token.encode()),
                Err(DecodeError::Malformed)
            ),
            "nonce decoding to != 32 bytes must be rejected as Malformed"
        );
    }

    // ── exactly one canonical encoding ─────────────────────────────────

    fn valid_token() -> SolutionToken {
        // Nonce whose base64 contains both '+' and '/' (0xFF×3 → "////",
        // 0xFB 0xEF 0xBE → "++++") so the url-safe substitution is
        // meaningful.
        let nonce_bytes: [u8; 32] = [
            0xFF, 0xFF, 0xFF, 0xFB, 0xEF, 0xBE, 0x01, 0x23, 0x45, 0x67, 0x89, 0xAB, 0xCD, 0xEF,
            0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10, 0x0F, 0xF1, 0xE2, 0xD3, 0xC4, 0xB5,
            0xA6, 0x97, 0x88, 0x69,
        ];
        SolutionToken {
            nonce: B64.encode(nonce_bytes),
            counter: 42,
            duration_ms: 850,
            telemetry: serde_json::json!({"wd": true}),
        }
    }

    #[test]
    fn decode_rejects_url_safe_base64_variants() {
        let encoded = valid_token().encode();
        // The chosen nonce guarantees the decoded payload itself contains
        // both '+' and '/', and the outer token is standard base64: any
        // '-'/'_' character is outside the standard alphabet, so swapping
        // one in must break the decode.
        let swapped = encoded.replacen(&encoded[0..1], "-", 1);
        assert_ne!(swapped, encoded);
        assert!(
            matches!(
                SolutionToken::decode(&swapped),
                Err(DecodeError::InvalidBase64)
            ),
            "url-safe alphabet must be rejected"
        );
        // A '-' substituted into the middle of the token is equally invalid.
        let mid = format!("{}{}{}", &encoded[..20], "-", &encoded[21..]);
        assert!(
            matches!(SolutionToken::decode(&mid), Err(DecodeError::InvalidBase64)),
            "a url-safe character anywhere must be rejected"
        );
    }

    #[test]
    fn decode_rejects_missing_padding() {
        // Telemetry {"a":1} makes the plain payload 59 bytes (59 % 3 == 2),
        // so the canonical outer encoding carries exactly one padding '='.
        let token = SolutionToken {
            nonce: valid_token().nonce,
            counter: 42,
            duration_ms: 850,
            telemetry: serde_json::json!({"a": 1}),
        };
        let encoded = token.encode();
        assert_eq!(encoded.len() % 4, 0);
        assert!(encoded.ends_with('='), "payload length forces one '=' pad");
        let unpadded = encoded.trim_end_matches('=');
        assert!(
            matches!(
                SolutionToken::decode(unpadded),
                Err(DecodeError::InvalidBase64)
            ),
            "an unpadded token is not the canonical encoding"
        );
    }

    #[test]
    fn decode_rejects_loose_padding() {
        // One extra padding character beyond the canonical amount.
        let token = SolutionToken {
            nonce: valid_token().nonce,
            counter: 42,
            duration_ms: 850,
            telemetry: serde_json::json!({"a": 1}),
        };
        let encoded = token.encode();
        assert!(encoded.ends_with('='));
        let loose = format!("{encoded}=");
        assert!(
            matches!(
                SolutionToken::decode(&loose),
                Err(DecodeError::InvalidBase64)
            ),
            "extra padding must be rejected"
        );
    }

    #[test]
    fn decode_rejects_surrounding_whitespace() {
        let encoded = valid_token().encode();
        for wrapped in [format!(" {encoded}"), format!("{encoded}\n")] {
            assert!(
                matches!(
                    SolutionToken::decode(&wrapped),
                    Err(DecodeError::InvalidBase64)
                ),
                "surrounding whitespace must be rejected (no trim)"
            );
        }
    }

    #[test]
    fn decode_rejects_noncanonical_nonce_inside_the_payload() {
        // The inner nonce must itself be the canonical 44-char padded
        // standard-base64 encoding of 32 bytes: an unpadded 43-char nonce is
        // rejected even though the outer token is properly padded.
        let token = valid_token();
        let unpadded_nonce = token.nonce.trim_end_matches('=');
        assert_eq!(unpadded_nonce.len(), 43);
        let plain = format!(
            "{unpadded_nonce}.{}.{}.{{}}",
            token.counter, token.duration_ms
        );
        let wrapped = B64.encode(plain);
        assert!(
            matches!(SolutionToken::decode(&wrapped), Err(DecodeError::Malformed)),
            "a non-canonical nonce segment must be rejected"
        );

        // Url-safe chars inside the nonce segment.
        let url_nonce = token.nonce.replace('+', "-").replace('/', "_");
        assert_ne!(url_nonce, token.nonce);
        let plain2 = format!("{url_nonce}.{}.{}.{{}}", token.counter, token.duration_ms);
        let wrapped2 = B64.encode(plain2);
        assert!(
            matches!(
                SolutionToken::decode(&wrapped2),
                Err(DecodeError::Malformed)
            ),
            "a url-safe nonce segment must be rejected"
        );
    }
}
