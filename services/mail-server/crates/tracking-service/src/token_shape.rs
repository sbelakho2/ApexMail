//! Shared tracking-token shape validation and safe log-prefix extraction.
//!
//! A tracking/unsubscribe/preferences token is ALWAYS
//! `base64url(IV||tag||ct)` produced by [`crate::codec::TrackingCodec`] — a
//! strict ASCII alphabet of `[A-Za-z0-9_-]` with no padding. Hoisted here
//! (SM2-F4) from the unsubscribe handlers' F37 guard so EVERY route that
//! slices or logs a client-supplied token shares one implementation:
//!
//! - [`is_valid_token_shape`] rejects anything that can never verify
//!   (multi-byte Unicode, `+`/`/` standard-base64, `=`, control bytes,
//!   out-of-bounds lengths) BEFORE any slicing or logging.
//! - [`token_log_prefix`] is a char-boundary-safe prefix extractor: axum's
//!   `Path<String>` is percent-decoded UTF-8, so a hostile id such as
//!   `aaaaaaaaaaaaaaaaaaaé…` splits a multibyte char at byte 20 and the old
//!   `&token[..token.len().min(n)]` panicked ("byte index 20 is not a char
//!   boundary") inside a `warn!` field — killing the connection task per
//!   request.

/// Minimum accepted token length (bytes). Matches the codec bounds.
pub const TOKEN_MIN_LEN: usize = 10;
/// Maximum accepted token length (bytes). Matches the codec bounds.
pub const TOKEN_MAX_LEN: usize = 4096;

/// F37:a token is valid only if its length is within the codec bounds and
/// every byte is strict base64url ASCII (`[A-Za-z0-9_-]`, no padding).
/// Anything else can never verify, so callers reject it before any slicing
/// or logging; after this check every `&token[..n]` slice is on an ASCII
/// string where byte indices are char boundaries.
pub fn is_valid_token_shape(token: &str) -> bool {
    (TOKEN_MIN_LEN..=TOKEN_MAX_LEN).contains(&token.len())
        && token
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
}

/// SM2-F4:char-boundary-safe prefix of `token` for logging — the honest
/// replacement for `&token[..token.len().min(n)]`, which panics when byte
/// `n` falls inside a multi-byte UTF-8 scalar (e.g. 19 ASCII bytes + `é`).
/// Never panics for any `&str` and any `max`; when truncation would split a
/// character the prefix is shortened to the previous boundary.
pub fn token_log_prefix(token: &str, max: usize) -> &str {
    if token.len() <= max {
        return token;
    }
    let mut end = max;
    while end > 0 && !token.is_char_boundary(end) {
        end -= 1;
    }
    &token[..end]
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prefix_of_ascii_is_the_plain_min_slice() {
        assert_eq!(
            token_log_prefix("abcdefghijklmnopqrst", 20),
            "abcdefghijklmnopqrst"
        );
        assert_eq!(
            token_log_prefix("abcdefghijklmnopqrstXYZ", 20),
            "abcdefghijklmnopqrst"
        );
        assert_eq!(token_log_prefix("short", 20), "short");
        assert_eq!(token_log_prefix("", 20), "");
    }

    /// SM2-F4 regression:19 ASCII bytes + a two-byte `é` puts byte 20 inside
    /// the character — the exact input that panicked the old
    /// `&id[..id.len().min(20)]` logging slices.
    #[test]
    fn prefix_stops_at_char_boundary_on_multibyte_input() {
        let hostile = format!("{}é{}", "a".repeat(19), "x".repeat(30));
        assert_eq!(hostile.len(), 51, "19 + 2 + 30 bytes");
        let prefix = token_log_prefix(&hostile, 20);
        assert_eq!(prefix, "a".repeat(19), "must not split the é");
        assert!(prefix.is_char_boundary(prefix.len()));
    }

    #[test]
    fn prefix_on_all_multibyte_input_shrinks_to_boundary() {
        // Every char here is THREE bytes in UTF-8 (bytes: 3,6,9,…).
        let hostile = "日本語のトークンです";
        assert_eq!(
            token_log_prefix(hostile, 4),
            "日",
            "4 is inside 本 (bytes 3..6)"
        );
        assert_eq!(token_log_prefix(hostile, 3), "日");
        assert_eq!(
            token_log_prefix(hostile, 2),
            "",
            "2 is inside 日 (bytes 0..3)"
        );
        assert_eq!(token_log_prefix(hostile, 1_000), hostile);
    }

    #[test]
    fn zero_max_yields_empty_prefix() {
        assert_eq!(token_log_prefix("whatever", 0), "");
    }

    #[test]
    fn shape_guard_bounds_and_charset() {
        assert!(is_valid_token_shape(&"a".repeat(TOKEN_MIN_LEN)));
        assert!(is_valid_token_shape(&"a".repeat(TOKEN_MAX_LEN)));
        assert!(!is_valid_token_shape(&"a".repeat(TOKEN_MIN_LEN - 1)));
        assert!(!is_valid_token_shape(&"a".repeat(TOKEN_MAX_LEN + 1)));
        // SM2-F4: multibyte content fails the shape guard.
        assert!(!is_valid_token_shape("aaaaaaaaaaaaaaaaaaaé"));
        assert!(!is_valid_token_shape("日本語のトークンです"));
    }
}
