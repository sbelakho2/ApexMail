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

use base64::{engine::general_purpose::STANDARD as B64, Engine};
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
}

/// The client-submitted solution, decoded from the `kiwi__token` hidden input.
///
/// The wire format is `base64(nonce || "." || counter || "." || duration_ms || "." || telemetry_json)`.
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
        let plain = B64
            .decode(raw.trim())
            .map_err(|_| DecodeError::InvalidBase64)?;
        let plain = String::from_utf8(plain).map_err(|_| DecodeError::InvalidUtf8)?;

        // The telemetry segment is JSON which may itself contain dots, so split
        // only on the first three dots.
        let mut parts = plain.splitn(4, '.');
        let nonce = parts.next().ok_or(DecodeError::Malformed)?.to_string();
        let counter_str = parts.next().ok_or(DecodeError::Malformed)?;
        let duration_str = parts.next().ok_or(DecodeError::Malformed)?;
        let telemetry_str = parts.next().ok_or(DecodeError::Malformed)?;

        let counter: u64 = counter_str
            .parse()
            .map_err(|_| DecodeError::InvalidCounter)?;
        let duration_ms: u64 = duration_str
            .parse()
            .map_err(|_| DecodeError::InvalidDuration)?;
        let telemetry: serde_json::Value =
            serde_json::from_str(telemetry_str).map_err(|_| DecodeError::Malformed)?;

        Ok(Self {
            nonce,
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
    #[error("token is malformed (expected nonce.counter.duration.telemetry)")]
    Malformed,
    #[error("counter segment is not a valid integer")]
    InvalidCounter,
    #[error("duration segment is not a valid integer")]
    InvalidDuration,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn token_roundtrips_through_encode_decode() {
        let token = SolutionToken {
            nonce: "abc123".to_string(),
            counter: 42,
            duration_ms: 850,
            telemetry: serde_json::json!({"wd": true, "hc": 8}),
        };
        let encoded = token.encode();
        let decoded = SolutionToken::decode(&encoded).unwrap();
        assert_eq!(decoded.nonce, "abc123");
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
            nonce: "n".to_string(),
            counter: 1,
            duration_ms: 2,
            telemetry: serde_json::json!({"ua": "Mozilla/5.0 (X11; Linux x86_64)"}),
        };
        let encoded = token.encode();
        let decoded = SolutionToken::decode(&encoded).unwrap();
        assert_eq!(decoded.telemetry["ua"], "Mozilla/5.0 (X11; Linux x86_64)");
    }
}
