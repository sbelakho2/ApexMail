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
    /// The ExecutionChallengeV1 program (base64 of the bytecode blob)
    /// armed for this challenge; `None` = no execution dimension (the
    /// legacy shape — the key is absent from the JSON). The driver runs
    /// it in its sandboxed ephemeral interpreter and presents the
    /// resulting execution digest with the solution token.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub execution_program: Option<String>,
    /// The rsw modulus n (canonical standard base64 of the 2048-bit
    /// composite), present only when the challenge algorithm is rsw:
    /// the client solver squares modulo n. The key is omitted when
    /// `None`, so every other response keeps its exact byte shape. The
    /// trapdoor lambda never rides this surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rsw_modulus: Option<String>,
}

/// The client-submitted solution, decoded from the `kiwi__token` hidden input.
///
/// The wire format is `base64(nonce || "." || counter || "." || duration_ms
/// || "." || telemetry_json || ["." digest[":" trace]] || ["." rsw_proof])`.
/// The telemetry segment may itself contain dots; the optional suffix
/// segments (execution evidence, then the rsw final value) are peeled
/// right-to-left, so an armed rsw challenge carries both independently.
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
    /// The ExecutionChallengeV1 execution digest (64 lowercase hex
    /// characters) presented for an execution-armed challenge; `None` on
    /// the unarmed shape. The digest is computed by the browser
    /// interpreter from the issued program and binds the submission to
    /// the challenge context; the verifier recomputes the expected
    /// digest from the stored program and rejects a mismatch with the
    /// deterministic `ExecutionMismatch` outcome.
    pub execution_digest: Option<String>,
    /// The base64url (unpadded) executed-trace wire string presented
    /// behind the digest (`digest:trace`) for an execution-armed
    /// challenge; `None` on the digest-only and unarmed shapes. The
    /// field holds the wire form verbatim (the caller passes the
    /// driver's base64url encoding), so [`SolutionToken::encode`]
    /// appends it unchanged and [`SolutionToken::decode`] returns it
    /// unchanged.
    pub execution_trace: Option<String>,
    /// The rsw final value (512 lowercase hex) presented for an rsw
    /// challenge; `None` on every other shape. The verifier compares it
    /// constant-time against the trapdoor expectation.
    pub rsw_proof: Option<String>,
}

impl SolutionToken {
    /// Encode the token into the compact wire format stored in `kiwi__token`.
    pub fn encode(&self) -> String {
        let telemetry_str = serde_json::to_string(&self.telemetry).unwrap_or_default();
        let mut plain = format!(
            "{}.{}.{}.{}",
            self.nonce, self.counter, self.duration_ms, telemetry_str
        );
        // The execution digest is an optional fifth segment: an unarmed
        // token stays byte-identical to the four-segment shape. The
        // trace rides behind the digest as `digest:trace` — the field
        // already holds the base64url (unpadded) wire form, so it is
        // appended verbatim after the colon, never re-encoded.
        if let Some(digest) = &self.execution_digest {
            plain.push('.');
            plain.push_str(digest);
            if let Some(trace) = &self.execution_trace {
                plain.push(':');
                plain.push_str(trace);
            }
        }
        // The rsw final value rides as the final segment, after the
        // execution evidence: an armed rsw challenge carries both, and
        // the 512-hex discriminator reads the last part.
        if let Some(proof) = &self.rsw_proof {
            plain.push('.');
            plain.push_str(proof);
        }
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

        // The wire grammar splits on ALL dots: the first three segments
        // are nonce/counter/duration, and everything from the fourth
        // segment onward is telemetry plus — at the tail — the optional
        // execution-evidence segment and the optional rsw final value.
        // The suffix peels run independently, right-to-left: the rsw
        // final value is peeled first exactly when the last segment is
        // 512 lowercase hex (the shape the sequential solver produces),
        // then the execution-evidence segment (`digest` or
        // `digest:trace`) is peeled from the segment that precedes it,
        // so an armed rsw challenge carrying both stays one
        // unambiguous grammar. A JSON telemetry object can never end
        // with a hex tail (it must close with '}'), so each
        // discriminator is unambiguous, and a tail matching neither
        // stays part of the telemetry and fails the JSON parse below
        // (fail closed, PHP parity).
        let parts: Vec<&str> = plain.split('.').collect();
        if parts.len() < 4 {
            return Err(DecodeError::Malformed);
        }
        let nonce = parts[0];
        let counter_str = parts[1];
        let duration_str = parts[2];
        let mut end = parts.len();
        let mut execution_digest = None;
        let mut execution_trace = None;
        let mut rsw_proof = None;
        if end >= 5 {
            // The rsw final value is the last segment exactly when it is
            // 512 lowercase hex (the shape the sequential solver
            // produces): the wire discriminator reads the last part, and
            // a JSON telemetry object can never end with a hex tail (it
            // must close with '}'), so the split is unambiguous.
            let last = parts[end - 1];
            let rsw_ok = last.len() == 512
                && last
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if rsw_ok {
                rsw_proof = Some(last.to_string());
                end -= 1;
            }
        }
        if end >= 5 {
            // The segment preceding the (optional) rsw final value is
            // `digest` or `digest:trace`: the digest is exactly 64
            // lowercase hex characters (the shape the driver's
            // interpreter produces) and the trace is canonical unpadded
            // base64url ([A-Za-z0-9_-], non-empty, at most 10924
            // characters — the base64 of an 8 KiB trace, and byte-exact
            // with the re-encode of its own decoded bytes, the PHP trace
            // gate). A malformed trace on an armed token is rejected
            // outright, exactly like the PHP decoder throws for the same
            // shape; a segment whose digest part is not 64 lowercase
            // hex is not execution evidence and stays in the telemetry
            // (fail closed).
            let segment = parts[end - 1];
            let colon = segment.find(':');
            let digest_part = match colon {
                Some(i) => &segment[..i],
                None => segment,
            };
            let digest_ok = digest_part.len() == 64
                && digest_part
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b));
            if digest_ok {
                execution_digest = Some(digest_part.to_string());
                execution_trace = match colon {
                    Some(i) => {
                        let trace = &segment[i + 1..];
                        let trace_ok = !trace.is_empty()
                            && trace.len() <= 10924
                            && trace
                                .bytes()
                                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
                            && trace_is_canonical_base64url(trace);
                        if !trace_ok {
                            return Err(DecodeError::Malformed);
                        }
                        Some(trace.to_string())
                    }
                    None => None,
                };
                end -= 1;
            }
        }
        let telemetry_str = parts[3..end].join(".");

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
            serde_json::from_str(&telemetry_str).map_err(|_| DecodeError::Malformed)?;
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
            execution_digest,
            execution_trace,
            rsw_proof,
        })
    }
}

/// True when `trace` is the canonical unpadded base64url encoding of
/// its own decoded bytes, the exact gate the PHP decoder applies to
/// the `digest:trace` tail (SolutionToken::decode throws
/// DecodeError::malformed for any divergence).
///
/// The PHP gate round-trips the trace: translate the base64url
/// alphabet to the standard one ('-' to '+', '_' to '/'), re-pad with
/// '=' to a multiple of 4, strict-decode (a failure rejects), then
/// re-encode the bytes, translate back to base64url and strip the
/// padding, and compare byte-exact with the submitted trace. The
/// caller of this function has already enforced the non-empty, at
/// most 10924 characters, [A-Za-z0-9_-] fast path, so the remaining
/// rejections are exactly the non-canonical encodings: an unpadded
/// length of 4k+1 (the re-padded form carries a one-data-char final
/// group with three '=' signs, which both the crate engine and the
/// PHP strict decoder refuse) and final groups whose low residual
/// bits are non-zero (the crate engine rejects them in the strict
/// decode; PHP decodes them and the re-encode comparison diverges,
/// so both implementations reject).
///
/// Engine behavior notes (verified against base64 0.22): the crate
/// `STANDARD` engine used here requires canonical padding, so unpadded
/// input fails with InvalidPadding (the input is re-padded first,
/// which makes that moot), rejects non-zero trailing bits with
/// InvalidLastSymbol, and rejects a data char followed by three pad
/// signs with InvalidByte. Those verdicts match PHP 8.5 strict
/// base64_decode on every shape tested, so the decode + re-encode
/// comparison below accepts exactly the trace strings PHP accepts.
fn trace_is_canonical_base64url(trace: &str) -> bool {
    let mut padded = Vec::with_capacity(trace.len() + 3);
    padded.extend(trace.bytes().map(|b| match b {
        b'-' => b'+',
        b'_' => b'/',
        b => b,
    }));
    // Re-pad with '=' to a multiple of 4, the PHP str_pad step.
    match padded.len() % 4 {
        1 => padded.extend_from_slice(b"==="),
        2 => padded.extend_from_slice(b"=="),
        3 => padded.push(b'='),
        _ => {}
    }
    let Ok(bytes) = B64.decode(padded.as_slice()) else {
        return false;
    };
    // Canonical re-encode, translated back to base64url with the
    // padding stripped, compared byte-exact with the submitted trace
    // (the PHP rtrim and strtr round trip). A canonical encode pads
    // only at the tail, so dropping every '=' is the rtrim.
    let mut canonical = Vec::with_capacity(trace.len());
    for b in B64.encode(bytes).into_bytes() {
        match b {
            b'+' => canonical.push(b'-'),
            b'/' => canonical.push(b'_'),
            b'=' => {}
            b => canonical.push(b),
        }
    }
    canonical == trace.as_bytes()
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
                execution_digest: None,
                execution_trace: None,
                rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
                execution_digest: None,
                execution_trace: None,
                rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
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

    #[test]
    fn execution_digest_round_trips_as_the_final_segment() {
        let digest = "f".repeat(64);
        let token = SolutionToken {
            nonce: valid_token().nonce,
            counter: 42,
            duration_ms: 850,
            telemetry: serde_json::json!({"wd": true}),
            execution_digest: Some(digest.clone()),
            execution_trace: None,
            rsw_proof: None,
        };
        let encoded = token.encode();
        let plain = B64.decode(&encoded).unwrap();
        assert_eq!(
            String::from_utf8_lossy(&plain),
            format!("{}.42.850.{{\"wd\":true}}.{digest}", valid_token().nonce)
        );
        let decoded = SolutionToken::decode(&encoded).unwrap();
        assert_eq!(decoded.execution_digest.as_deref(), Some(digest.as_str()));
    }

    #[test]
    fn execution_digest_survives_dotted_telemetry() {
        // The digest is the final segment; dotted telemetry stays whole.
        let digest = "0".repeat(64);
        let token = SolutionToken {
            nonce: valid_token().nonce,
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({"ua": "Mozilla/5.0 (X11; Linux x86_64)"}),
            execution_digest: Some(digest.clone()),
            execution_trace: None,
            rsw_proof: None,
        };
        let decoded = SolutionToken::decode(&token.encode()).unwrap();
        assert_eq!(decoded.execution_digest.as_deref(), Some(digest.as_str()));
        assert_eq!(decoded.telemetry["ua"], "Mozilla/5.0 (X11; Linux x86_64)");
    }

    #[test]
    fn execution_digest_must_be_64_hex() {
        // A malformed digest tail (not 64 lowercase hex) is not the wire
        // language: it parses as part of the telemetry and fails the JSON
        // object requirement (fail closed).
        let token = SolutionToken {
            nonce: valid_token().nonce,
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({}),
            execution_digest: Some("XYZ".to_string()),
            execution_trace: None,
            rsw_proof: None,
        };
        assert!(matches!(
            SolutionToken::decode(&token.encode()),
            Err(DecodeError::Malformed)
        ));
    }

    #[test]
    fn execution_digest_only_round_trips_with_no_trace() {
        // The digest-only shape: the fifth segment is exactly the 64
        // lowercase hex digest with no colon tail, and the decode
        // recovers the digest with execution_trace = None (PHP parity
        // for the unarmed-trace form).
        let digest = "a1b2c3d4e5f60718293a4b5c6d7e8f90a1b2c3d4e5f60718293a4b5c6d7e8f90";
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b)));
        let token = SolutionToken {
            nonce: valid_token().nonce,
            counter: 42,
            duration_ms: 850,
            telemetry: serde_json::json!({"wd": true}),
            execution_digest: Some(digest.to_string()),
            execution_trace: None,
            rsw_proof: None,
        };
        let encoded = token.encode();
        let decoded = SolutionToken::decode(&encoded).unwrap();
        assert_eq!(decoded.execution_digest.as_deref(), Some(digest));
        assert_eq!(
            decoded.execution_trace, None,
            "a digest-only token carries no trace"
        );
        // The plain payload ends with the digest and nothing else.
        let plain = String::from_utf8(B64.decode(&encoded).unwrap()).unwrap();
        assert!(plain.ends_with(&format!(".{digest}")));
    }

    #[test]
    fn execution_digest_with_trace_round_trips_both_fields() {
        // The digest:trace shape: the trace is appended verbatim after
        // the colon (the field already holds the unpadded base64url
        // wire form) and the decode recovers both fields, byte-exact.
        let digest = "f".repeat(64);
        let trace_b64 = "Y2hlY2stdHJhY2Uta2V5XzEyMzQ1Ng";
        assert!(trace_b64
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'));
        let token = SolutionToken {
            nonce: valid_token().nonce,
            counter: 42,
            duration_ms: 850,
            telemetry: serde_json::json!({"wd": true}),
            execution_digest: Some(digest.clone()),
            execution_trace: Some(trace_b64.to_string()),
            rsw_proof: None,
        };
        let encoded = token.encode();
        let plain = String::from_utf8(B64.decode(&encoded).unwrap()).unwrap();
        assert_eq!(
            plain,
            format!(
                "{}.42.850.{{\"wd\":true}}.{digest}:{trace_b64}",
                valid_token().nonce
            ),
            "the trace rides behind the digest, colon-joined, verbatim"
        );
        let decoded = SolutionToken::decode(&encoded).unwrap();
        assert_eq!(decoded.execution_digest.as_deref(), Some(digest.as_str()));
        assert_eq!(
            decoded.execution_trace.as_deref(),
            Some(trace_b64),
            "the base64url trace survives byte-exact"
        );
    }

    #[test]
    fn execution_digest_with_trace_survives_dotted_telemetry() {
        // The dotted-telemetry discrimination holds with a trace too:
        // only the final segment is examined, and the digest:trace
        // shape keeps the telemetry between the third dot and the
        // digest whole.
        let digest = "0".repeat(64);
        let trace_b64 = "ZG90dGVkX3RyYWNlX3dpdGhfdW5kZXJzY29yZXM";
        let token = SolutionToken {
            nonce: valid_token().nonce,
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({"ua": "Mozilla/5.0 (X11; Linux x86_64)"}),
            execution_digest: Some(digest.clone()),
            execution_trace: Some(trace_b64.to_string()),
            rsw_proof: None,
        };
        let decoded = SolutionToken::decode(&token.encode()).unwrap();
        assert_eq!(decoded.execution_digest.as_deref(), Some(digest.as_str()));
        assert_eq!(decoded.execution_trace.as_deref(), Some(trace_b64));
        assert_eq!(decoded.telemetry["ua"], "Mozilla/5.0 (X11; Linux x86_64)");
    }

    #[test]
    fn execution_trace_with_bad_charset_fails_the_decode_closed() {
        // A tampered trace charset is fail closed: the token is
        // rejected outright with the DecodeError::Malformed variant, so
        // no execution evidence and no telemetry can ever be claimed
        // from it. PHP throws DecodeError::malformed for the same
        // shape.
        let digest = "e".repeat(64);
        for bad_trace in ["aGk=", "aGk+", "aGk/", "a:b", "ab.cd", "a b"] {
            let token = SolutionToken {
                nonce: valid_token().nonce,
                counter: 1,
                duration_ms: 2,
                telemetry: serde_json::json!({}),
                execution_digest: Some(digest.clone()),
                execution_trace: Some(bad_trace.to_string()),
                rsw_proof: None,
            };
            assert!(
                matches!(
                    SolutionToken::decode(&token.encode()),
                    Err(DecodeError::Malformed)
                ),
                "a trace with characters outside [A-Za-z0-9_-] must fail the decode: {bad_trace:?}"
            );
        }
    }

    #[test]
    fn execution_trace_over_the_length_cap_fails_the_decode() {
        // The trace cap is 10924 characters (the unpadded base64url of
        // an 8 KiB plain trace); a longer tail is rejected with
        // Malformed before any further processing.
        let digest = "d".repeat(64);
        let token = SolutionToken {
            nonce: valid_token().nonce,
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({}),
            execution_digest: Some(digest.clone()),
            execution_trace: Some("a".repeat(10925)),
            rsw_proof: None,
        };
        assert!(matches!(
            SolutionToken::decode(&token.encode()),
            Err(DecodeError::Malformed)
        ));
        // Exactly at the cap: accepted (the charset is valid).
        let at_cap = SolutionToken {
            nonce: valid_token().nonce,
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({}),
            execution_digest: Some(digest),
            execution_trace: Some("a".repeat(10924)),
            rsw_proof: None,
        };
        assert!(SolutionToken::decode(&at_cap.encode()).is_ok());
    }

    #[test]
    fn execution_digest_with_empty_trace_after_colon_fails_the_decode() {
        // `digest:` with nothing after the colon is not the wire
        // language: PHP throws for an empty trace, so the Rust decode
        // rejects the shape with Malformed instead of accepting a
        // half-armed token.
        let plain = format!("{}.1.2.{{}}.{}:", valid_token().nonce, "0".repeat(64));
        let wrapped = B64.encode(plain);
        assert!(matches!(
            SolutionToken::decode(&wrapped),
            Err(DecodeError::Malformed)
        ));
    }

    #[test]
    fn execution_digest_in_uppercase_hex_fails_the_decode() {
        // The digest is 64 lowercase hex in both implementations: an
        // uppercase tail is not digest-shaped and falls through to the
        // telemetry parse, which rejects it (PHP parity — its
        // /^[0-9a-f]{64}$/D gate refuses the same token).
        let token = SolutionToken {
            nonce: valid_token().nonce,
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({}),
            execution_digest: Some("A".repeat(64)),
            execution_trace: None,
            rsw_proof: None,
        };
        assert!(matches!(
            SolutionToken::decode(&token.encode()),
            Err(DecodeError::Malformed)
        ));
    }

    // ── digest:trace canonicality differential vectors ──────────────────

    /// The fixed 64-lowercase-hex execution digest every differential
    /// vector below rides behind. The PHP verdict of each vector was
    /// confirmed by running the PHP SolutionToken::decode on the
    /// identical wire bytes before the expectation was pinned here.
    const VECTOR_DIGEST: &str = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";

    /// Wrap `trace` (or the digest-only tail when None) behind the
    /// fixed digest in an otherwise valid token, the exact wire shape
    /// SolutionToken::encode emits.
    fn vector_wire(trace: Option<&str>) -> String {
        let tail = match trace {
            Some(t) => format!("{VECTOR_DIGEST}:{t}"),
            None => VECTOR_DIGEST.to_string(),
        };
        B64.encode(format!("{}.1.2.{{}}.{tail}", VALID_NONCE).into_bytes())
    }

    #[test]
    fn execution_trace_canonicality_agrees_with_php_decode() {
        // PHP accepts a trace exactly when it is the canonical
        // unpadded base64url encoding of its own decoded bytes and
        // rejects every other alphabet-valid trace as malformed; the
        // Rust decoder must agree vector for vector.
        let cases: &[(&str, bool)] = &[
            // Canonical unpadded base64url encodings: accepted.
            ("Y2hlY2stdHJhY2Uta2V5XzEyMzQ1Ng", true),
            ("aGk", true),
            ("aA", true),
            ("YWJjZA", true),
            ("----", true),
            ("____", true),
            // An unpadded length of 4k+1 re-pads to a one-data-char
            // final group with three padding signs, a shape both the
            // PHP strict decode and the crate engine refuse.
            ("a", false),
            ("aaaaa", false),
            // Non-zero residual bits in the final group: PHP decodes
            // the bytes but the canonical re-encode diverges, so the
            // trace is rejected as non-canonical.
            ("aGh", false),
            ("aB", false),
            ("aa", false),
            // The 10924-character boundary: the all-a form at the cap
            // is canonical (10924 is a multiple of 4, full groups
            // only) and accepted; one character more is over the cap.
            (&"a".repeat(10924), true),
            (&"a".repeat(10925), false),
        ];
        for (trace, expect_ok) in cases {
            let wire = vector_wire(Some(trace));
            match SolutionToken::decode(&wire) {
                Ok(token) => {
                    assert!(
                        *expect_ok,
                        "a {} char trace must be accepted: PHP accepts it",
                        trace.len()
                    );
                    assert_eq!(token.execution_digest.as_deref(), Some(VECTOR_DIGEST));
                    assert_eq!(token.execution_trace.as_deref(), Some(*trace));
                }
                Err(err) => {
                    assert!(
                        !*expect_ok,
                        "a {} char trace must be rejected: PHP rejects it",
                        trace.len()
                    );
                    assert_eq!(err, DecodeError::Malformed);
                }
            }
        }
    }

    #[test]
    fn digest_only_and_uppercase_hex_digest_keep_their_verdicts() {
        // The digest-only shape (no colon): the fifth segment is
        // exactly the 64-lowercase-hex digest, the decode recovers it
        // with the trace field None. PHP accepts the identical wire
        // bytes.
        let decoded = SolutionToken::decode(&vector_wire(None)).unwrap();
        assert_eq!(decoded.execution_digest.as_deref(), Some(VECTOR_DIGEST));
        assert_eq!(decoded.execution_trace, None);
        // An uppercase-hex digest tail is not digest-shaped: it falls
        // through to the telemetry JSON parse and fails closed with
        // Malformed, exactly like PHP.
        let upper_tail: String = VECTOR_DIGEST
            .chars()
            .map(|c| c.to_ascii_uppercase())
            .collect();
        let upper_plain = format!("{}.1.2.{{}}.{upper_tail}", VALID_NONCE);
        let upper_wire = B64.encode(upper_plain.into_bytes());
        assert!(matches!(
            SolutionToken::decode(&upper_wire),
            Err(DecodeError::Malformed)
        ));
    }

    #[test]
    fn canonical_trace_encode_decode_is_byte_stable() {
        // The trace field holds the base64url wire form verbatim, so
        // for a canonical trace a decode followed by a re-encode
        // returns the exact token bytes.
        let traces: &[&str] = &[
            "Y2hlY2stdHJhY2Uta2V5XzEyMzQ1Ng",
            "aGk",
            "----",
            &"a".repeat(10924),
        ];
        for trace in traces {
            let token = SolutionToken {
                nonce: VALID_NONCE.to_string(),
                counter: 1,
                duration_ms: 2,
                telemetry: serde_json::json!({}),
                execution_digest: Some(VECTOR_DIGEST.to_string()),
                execution_trace: Some(trace.to_string()),
                rsw_proof: None,
            };
            let wire = token.encode();
            let decoded = SolutionToken::decode(&wire).unwrap();
            assert_eq!(decoded.execution_trace.as_deref(), Some(*trace));
            assert_eq!(decoded.encode(), wire);
        }
    }
    // ── rsw proof segment (the optional 512-hex final segment) ────────

    #[test]
    fn rsw_proof_round_trips_as_the_final_segment() {
        let proof = "a".repeat(512);
        let token = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 0,
            duration_ms: 1234,
            telemetry: serde_json::json!({"wd": true}),
            execution_digest: None,
            execution_trace: None,
            rsw_proof: Some(proof.clone()),
        };
        let encoded = token.encode();
        let plain = String::from_utf8(B64.decode(&encoded).unwrap()).unwrap();
        assert_eq!(
            plain,
            format!("{}.0.1234.{{\"wd\":true}}.{proof}", VALID_NONCE),
            "the proof is the final wire segment"
        );
        let decoded = SolutionToken::decode(&encoded).unwrap();
        assert_eq!(decoded.counter, 0, "an rsw token has no search counter");
        assert_eq!(decoded.rsw_proof.as_deref(), Some(proof.as_str()));
        assert_eq!(decoded.execution_digest, None);
        assert_eq!(decoded.telemetry["wd"], true);
    }

    #[test]
    fn rsw_proof_survives_dotted_telemetry() {
        let proof = "0".repeat(512);
        let token = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 0,
            duration_ms: 2,
            telemetry: serde_json::json!({"ua": "Mozilla/5.0 (X11; Linux x86_64)"}),
            execution_digest: None,
            execution_trace: None,
            rsw_proof: Some(proof.clone()),
        };
        let decoded = SolutionToken::decode(&token.encode()).unwrap();
        assert_eq!(decoded.rsw_proof.as_deref(), Some(proof.as_str()));
        assert_eq!(decoded.telemetry["ua"], "Mozilla/5.0 (X11; Linux x86_64)");
    }

    #[test]
    fn rsw_proof_shape_is_exactly_512_lowercase_hex() {
        // Uppercase hex and wrong lengths are not the wire language: the
        // tail falls through to the telemetry JSON parse and fails
        // closed (PHP parity).
        for bad_tail in [
            "A".repeat(512),
            "a".repeat(511),
            "a".repeat(513),
            "g".repeat(512),
        ] {
            let plain = format!("{}.0.2.{{}}.{bad_tail}", VALID_NONCE);
            let wrapped = B64.encode(plain.into_bytes());
            assert!(
                matches!(SolutionToken::decode(&wrapped), Err(DecodeError::Malformed)),
                "a {}-char non-lowercase-hex tail must be rejected",
                bad_tail.len()
            );
        }
        let ok = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 0,
            duration_ms: 2,
            telemetry: serde_json::json!({}),
            execution_digest: None,
            execution_trace: None,
            rsw_proof: Some("0".repeat(512)),
        };
        assert!(SolutionToken::decode(&ok.encode()).is_ok());
    }

    #[test]
    fn rsw_proof_and_execution_shapes_do_not_collide() {
        // The digest shape is 64 hex and the proof shape 512 hex: the
        // discriminator reads the last part, so the two stay disjoint.
        let digest = "f".repeat(64);
        let token = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 42,
            duration_ms: 850,
            telemetry: serde_json::json!({}),
            execution_digest: Some(digest),
            execution_trace: None,
            rsw_proof: None,
        };
        let decoded = SolutionToken::decode(&token.encode()).unwrap();
        assert_eq!(decoded.execution_digest.as_deref().map(str::len), Some(64));
        assert_eq!(decoded.rsw_proof, None);
    }

    #[test]
    fn plain_tokens_carry_no_proof_segment() {
        let token = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 3,
            duration_ms: 1234,
            telemetry: serde_json::json!({}),
            execution_digest: None,
            execution_trace: None,
            rsw_proof: None,
        };
        let decoded = SolutionToken::decode(&token.encode()).unwrap();
        assert_eq!(decoded.rsw_proof, None);
        assert_eq!(decoded.counter, 3);
    }

    // ── the rsw + execution composition (the two suffix segments coexist) ─

    const COMPOSED_DIGEST: &str =
        "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
    /// Canonical unpadded base64url trace (the "check-trace-key_123456" bytes).
    const COMPOSED_TRACE: &str = "Y2hlY2stdHJhY2Uta2V5XzEyMzQ1Ng";

    fn composed_wire(telemetry: &str, tail: &str) -> String {
        B64.encode(format!("{VALID_NONCE}.0.1234.{telemetry}.{tail}").into_bytes())
    }

    #[test]
    fn rsw_proof_and_execution_evidence_round_trip_on_one_token() {
        // The composition the audit broke: the wire carries the
        // execution-evidence segment AND the 512-hex rsw final value,
        // and the decode must recover all three fields independently.
        let proof = "a".repeat(512);
        let token = SolutionToken {
            nonce: VALID_NONCE.to_string(),
            counter: 0,
            duration_ms: 1234,
            telemetry: serde_json::json!({"ua": "Mozilla/5.0 (X11; Linux x86_64)"}),
            execution_digest: Some(COMPOSED_DIGEST.to_string()),
            execution_trace: Some(COMPOSED_TRACE.to_string()),
            rsw_proof: Some(proof.clone()),
        };
        let wire = token.encode();
        let plain = String::from_utf8(B64.decode(&wire).unwrap()).unwrap();
        let telemetry_json =
            serde_json::to_string(&serde_json::json!({"ua": "Mozilla/5.0 (X11; Linux x86_64)"}))
                .unwrap();
        assert_eq!(
            plain,
            format!(
                "{VALID_NONCE}.0.1234.{telemetry_json}.{COMPOSED_DIGEST}:{COMPOSED_TRACE}.{proof}"
            ),
            "the proof rides after the digest:trace segment"
        );
        let decoded = SolutionToken::decode(&wire).unwrap();
        assert_eq!(decoded.rsw_proof.as_deref(), Some(proof.as_str()));
        assert_eq!(
            decoded.execution_digest.as_deref(),
            Some(COMPOSED_DIGEST),
            "the execution digest survives beside the proof"
        );
        assert_eq!(
            decoded.execution_trace.as_deref(),
            Some(COMPOSED_TRACE),
            "the execution trace survives beside the proof"
        );
        assert_eq!(decoded.counter, 0);
        assert_eq!(decoded.telemetry["ua"], "Mozilla/5.0 (X11; Linux x86_64)");
        assert_eq!(decoded.encode(), wire, "decode -> re-encode is byte stable");
    }

    #[test]
    fn rsw_proof_and_digest_only_evidence_round_trip_on_one_token() {
        // The digest-only variant of the composition: no trace, the
        // proof still rides the final segment and the decode recovers
        // the digest beside it.
        let proof = "0".repeat(512);
        let wire = composed_wire("{}", &format!("{COMPOSED_DIGEST}.{proof}"));
        let decoded = SolutionToken::decode(&wire).unwrap();
        assert_eq!(decoded.rsw_proof.as_deref(), Some(proof.as_str()));
        assert_eq!(decoded.execution_digest.as_deref(), Some(COMPOSED_DIGEST));
        assert_eq!(decoded.execution_trace, None);
        assert_eq!(decoded.telemetry, serde_json::json!({}));
    }

    #[test]
    fn token_shape_matrix_accepts_every_algorithm_shape() {
        // The shared PHP/Rust decode matrix — accept rows. The decoder
        // is algorithm-agnostic (the record decides at verification),
        // so the rows assert the same outcomes for the sha256, argon2id
        // and rsw token shapes, with execution evidence off and on.
        // Every row must round-trip encode -> decode.
        let proof = "b".repeat(512);
        // (label, execution on, digest, trace, rsw proof)
        type Row<'a> = (
            &'a str,
            bool,
            Option<&'a str>,
            Option<&'a str>,
            Option<&'a str>,
        );
        let rows: &[Row] = &[
            ("sha256-off", false, None, None, None),
            (
                "sha256-on",
                true,
                Some(COMPOSED_DIGEST),
                Some(COMPOSED_TRACE),
                None,
            ),
            ("argon2id-off", false, None, None, None),
            (
                "argon2id-on",
                true,
                Some(COMPOSED_DIGEST),
                Some(COMPOSED_TRACE),
                None,
            ),
            ("rsw-off", false, None, None, Some(&proof)),
            // The composition row: the rsw proof rides behind the
            // execution evidence on one token.
            (
                "rsw-on",
                true,
                Some(COMPOSED_DIGEST),
                Some(COMPOSED_TRACE),
                Some(&proof),
            ),
        ];
        for &(label, exec_on, digest, trace, rsw) in rows {
            let token = SolutionToken {
                nonce: VALID_NONCE.to_string(),
                counter: 0,
                duration_ms: 1234,
                telemetry: serde_json::json!({"wd": true}),
                execution_digest: digest.map(str::to_string),
                execution_trace: trace.map(str::to_string),
                rsw_proof: rsw.map(str::to_string),
            };
            let decoded = SolutionToken::decode(&token.encode())
                .unwrap_or_else(|e| panic!("{label} (execution={exec_on}) must decode: {e}"));
            assert_eq!(decoded.execution_digest.as_deref(), digest, "{label}");
            assert_eq!(decoded.execution_trace.as_deref(), trace, "{label}");
            assert_eq!(decoded.rsw_proof.as_deref(), rsw, "{label}");
            assert_eq!(decoded.telemetry["wd"], true, "{label}");
            if exec_on && rsw.is_some() {
                // The composition keeps dotted telemetry whole too.
                let dotted = SolutionToken {
                    nonce: VALID_NONCE.to_string(),
                    counter: 0,
                    duration_ms: 2,
                    telemetry: serde_json::json!({"ua": "Mozilla/5.0 (X11; Linux x86_64)"}),
                    execution_digest: digest.map(str::to_string),
                    execution_trace: trace.map(str::to_string),
                    rsw_proof: rsw.map(str::to_string),
                };
                let again = SolutionToken::decode(&dotted.encode()).unwrap();
                assert_eq!(again.telemetry["ua"], "Mozilla/5.0 (X11; Linux x86_64)");
            }
        }
    }

    #[test]
    fn token_shape_matrix_rejects_malformed_composition_tails() {
        // The shared PHP/Rust decode matrix — reject rows. A malformed
        // trace on the digest:trace segment of a composed token fails
        // the decode outright, and a malformed rsw proof (bad alphabet
        // or wrong length) fails closed through the telemetry JSON
        // parse — both deterministically, exactly like PHP.
        for bad_trace in [
            "aGk=",  // padded — not the unpadded wire form
            "aGk+",  // standard-alphabet char
            "aGk/",  // standard-alphabet char
            "a:b",   // colon outside the separator
            "ab.cd", // dot outside the grammar
            "a b",   // whitespace
        ] {
            let wire = composed_wire(
                "{}",
                &format!("{COMPOSED_DIGEST}:{bad_trace}.{}", "a".repeat(512)),
            );
            assert!(
                matches!(SolutionToken::decode(&wire), Err(DecodeError::Malformed)),
                "a composed token with trace {bad_trace:?} must be rejected"
            );
        }
        for bad_proof in [
            "A".repeat(512), // uppercase hex
            "a".repeat(511), // too short
            "a".repeat(513), // too long
            "g".repeat(512), // outside the hex alphabet
        ] {
            let wire = composed_wire(
                "{}",
                &format!("{COMPOSED_DIGEST}:{COMPOSED_TRACE}.{bad_proof}"),
            );
            assert!(
                matches!(SolutionToken::decode(&wire), Err(DecodeError::Malformed)),
                "a composed token with a {}-char non-lowercase-hex proof must be rejected",
                bad_proof.len()
            );
        }
        // A digest-only composition with a malformed proof fails too.
        let upper = composed_wire("{}", &format!("{COMPOSED_DIGEST}.{}", "A".repeat(512)));
        assert!(matches!(
            SolutionToken::decode(&upper),
            Err(DecodeError::Malformed)
        ));
    }
}
