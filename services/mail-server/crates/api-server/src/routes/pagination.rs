//! Shared keyset-based (cursor) pagination types and utilities.
//!
//! This module provides a standardised pagination contract for all bulk
//! API endpoints.  Clients pass an opaque `cursor` value (base64‑encoded)
//! to request the next page.  Servers respond with `CursorPage<T>` which
//! includes the `next_cursor` and `has_more` flag.
//!
//! # Why keyset pagination?
//!
//! Offset‑based pagination (`LIMIT x OFFSET y`) becomes O(n²) for large
//! datasets because PostgreSQL must scan and discard all preceding rows.
//! Keyset pagination (`WHERE id > $1 LIMIT x`) uses the index to start
//! reading directly at the cursor position — O(1) per page.
//!
//! # Usage
//!
//! ```ignore
//! use crate::pagination::{CursorParams, CursorPage, decode_cursor, encode_cursor};
//!
//! async fn list_items(
//!     Query(params): Query<CursorParams>,
//!     State(state): State<AppState>,
//! ) -> Result<Json<CursorPage<Item>>, ApiError> {
//!     let limit = params.limit().unwrap_or(50).min(200) as i64;
//!     let cursor = params.cursor.as_deref().and_then(decode_cursor);
//!
//!     let fetch_limit = limit + 1;  // detect has_more
//!     let rows = if let Some(ref c) = cursor {
//!         sqlx::query_as::<_, ItemRow>(
//!             "SELECT ... FROM items WHERE tenant_id = $1 AND created_at < $2::timestamp
//!              ORDER BY created_at DESC LIMIT $3"
//!         )
//!         .bind(tenant_id).bind(c).bind(fetch_limit).fetch_all(&pool).await?
//!     } else {
//!         // First page — no cursor
//!         sqlx::query_as::<_, ItemRow>(
//!             "SELECT ... FROM items WHERE tenant_id = $1
//!              ORDER BY created_at DESC LIMIT $2"
//!         )
//!         .bind(tenant_id).bind(fetch_limit).fetch_all(&pool).await?
//!     };
//!
//!     let has_more = rows.len() as i64 > limit;
//!     let mut data: Vec<Item> = rows.into_iter().map(|r| r.into()).collect();
//!     if has_more { data.truncate(limit as usize); }
//!
//!     let next_cursor = data.last()
//!         .and_then(|_| /* extract timestamp/id */ None)
//!         .map(|ts| encode_cursor(&ts));
//!
//!     Ok(Json(CursorPage { data, next_cursor, has_more }))
//! }
//! ```

use base64::Engine;
use serde::{Deserialize, Serialize};
use thiserror::Error;

// ─── Response wrapper ────────────────────────────────────────────

/// Cursor‑based pagination response wrapper.
///
/// Every paginated endpoint returns this shape so clients can iterate
/// through pages by passing `next_cursor` as the `?cursor=` parameter.
#[derive(Debug, Serialize)]
pub struct CursorPage<T: Serialize> {
    /// The page of results.
    pub data: Vec<T>,
    /// Opaque cursor for the next page, or `None` if this is the last page.
    pub next_cursor: Option<String>,
    /// Whether there are more results beyond this page.
    pub has_more: bool,
}

// ─── Query parameters ────────────────────────────────────────────

/// Query parameters accepted by cursor‑paginated endpoints.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CursorParams {
    /// Opaque cursor returned by the previous page's `next_cursor`.
    /// When absent, the server returns the first page.
    #[serde(default)]
    pub cursor: Option<String>,
    /// Maximum number of items to return (clamped server‑side).
    #[serde(default)]
    pub limit: Option<u32>,
}

impl CursorParams {
    /// Return the effective page size, defaulting to 50.
    pub fn limit(&self) -> u32 {
        self.limit.unwrap_or(50)
    }

    /// Return the effective page size, capped at `max`.
    pub fn capped_limit(&self, max: u32) -> u32 {
        self.limit().min(max)
    }
}

// ─── Cursor encoding / decoding ──────────────────────────────────

/// Encode a string value into an opaque, URL‑safe cursor.
///
/// The cursor is a base64‑encoded (URL‑safe, no padding) representation
/// of the raw string so clients cannot infer the ordering key.
pub fn encode_cursor(value: &str) -> String {
    base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(value.as_bytes())
}

/// Decode an opaque cursor back into the original string value.
///
/// Returns `None` if the cursor is malformed or not valid UTF‑8.
pub fn decode_cursor(cursor: &str) -> Option<String> {
    let bytes = base64::engine::general_purpose::URL_SAFE_NO_PAD
        .decode(cursor)
        .ok()?;
    String::from_utf8(bytes).ok()
}

// ─── Error type ──────────────────────────────────────────────────

/// Errors that can occur during pagination.
#[derive(Error, Debug)]
pub enum PaginationError {
    /// The cursor value is not valid base64 or cannot be decoded as UTF‑8.
    #[error("Invalid cursor format")]
    InvalidCursor,

    /// A base64 decode error occurred.
    #[error(transparent)]
    Base64(#[from] base64::DecodeError),
}

// ─── Helpers ─────────────────────────────────────────────────────

/// Detect whether more results exist after truncating to `limit`.
///
/// If the result vector has more than `limit` items, the extra item was
/// fetched only for detection purposes and is removed before returning.
///
/// Returns `true` if there is a next page.
pub fn has_more<T>(rows: &mut Vec<T>, limit: usize) -> bool {
    if rows.len() > limit {
        rows.truncate(limit);
        true
    } else {
        false
    }
}

/// Build the standard pagination metadata JSON value.
pub fn pagination_meta(has_more: bool, next_cursor: Option<String>) -> serde_json::Value {
    serde_json::json!({
        "hasMore": has_more,
        "nextCursor": next_cursor,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encode_decode_roundtrip() {
        let values = [
            "2026-05-11T12:00:00Z",
            "550e8400-e29b-41d4-a716-446655440000",
            "simple-string",
            "",
        ];
        for v in &values {
            let encoded = encode_cursor(v);
            let decoded = decode_cursor(&encoded).expect("should decode");
            assert_eq!(decoded, *v, "roundtrip failed for {v:?}");
        }
    }

    #[test]
    fn test_decode_invalid_cursor_returns_none() {
        assert!(decode_cursor("!!!invalid-base64!!!").is_none());
        assert!(decode_cursor("").is_some_and(|s| s.is_empty()));
    }

    #[test]
    fn test_decode_not_utf8_returns_none() {
        // Base64-decodable bytes that are not valid UTF-8 when decoded.
        // \xff\xfe is a BOM but decode_cursor expects valid UTF-8 from the decoded result.
        // We craft the base64 input directly, then verify decode_cursor rejects it.
        // Bytes [0xff, 0xfe] encoded as URL-safe base64 (no pad): _v4
        let cursor = "_v4";
        assert!(decode_cursor(cursor).is_none());
    }

    #[test]
    fn test_has_more_detects_next_page() {
        let mut items = vec![1, 2, 3, 4, 5];
        let more = has_more(&mut items, 3);
        assert!(more, "should have more");
        assert_eq!(items.len(), 3, "should truncate to limit");
    }

    #[test]
    fn test_has_more_no_next_page() {
        let mut items = vec![1, 2, 3];
        let more = has_more(&mut items, 5);
        assert!(!more, "should not have more");
        assert_eq!(items.len(), 3, "should keep all items");
    }

    #[test]
    fn test_cursor_params_defaults() {
        let json = r#"{}"#;
        let params: CursorParams = serde_json::from_str(json).unwrap();
        assert!(params.cursor.is_none());
        assert!(params.limit.is_none());
        assert_eq!(params.limit(), 50);
        assert_eq!(params.capped_limit(200), 50);
    }

    #[test]
    fn test_cursor_params_with_values() {
        let json = r#"{"cursor": "abc123", "limit": 100}"#;
        let params: CursorParams = serde_json::from_str(json).unwrap();
        assert_eq!(params.cursor, Some("abc123".into()));
        assert_eq!(params.limit, Some(100));
        assert_eq!(params.limit(), 100);
        assert_eq!(params.capped_limit(50), 50);
    }

    #[test]
    fn test_cursor_params_denies_unknown_fields() {
        let json = r#"{"unknown": "field"}"#;
        let result: Result<CursorParams, _> = serde_json::from_str(json);
        assert!(result.is_err(), "unknown fields should be rejected");
    }

    #[test]
    fn test_pagination_meta_serialization() {
        let meta = pagination_meta(true, Some("cursor123".into()));
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["hasMore"], true);
        assert_eq!(json["nextCursor"], "cursor123");

        let meta = pagination_meta(false, None::<String>);
        let json = serde_json::to_value(&meta).unwrap();
        assert_eq!(json["hasMore"], false);
        assert!(json["nextCursor"].is_null());
    }

    #[test]
    fn test_cursor_page_serialization() {
        let page = CursorPage {
            data: vec!["a".to_string(), "b".to_string()],
            next_cursor: Some("next".into()),
            has_more: false,
        };
        let json = serde_json::to_value(&page).unwrap();
        assert_eq!(json["data"].as_array().unwrap().len(), 2);
        assert_eq!(json["next_cursor"], "next");
        assert_eq!(json["has_more"], false);
    }

    #[test]
    fn test_encode_cursor_is_url_safe() {
        let encoded = encode_cursor("hello+world/=");
        // URL-safe base64 should not contain '+' or '/' characters
        assert!(!encoded.contains('+'), "should not contain '+'");
        assert!(!encoded.contains('/'), "should not contain '/'");
        assert!(!encoded.contains('='), "should not contain padding");
    }

    #[test]
    fn test_pagination_error_display() {
        let err = PaginationError::InvalidCursor;
        assert_eq!(err.to_string(), "Invalid cursor format");
    }
}
