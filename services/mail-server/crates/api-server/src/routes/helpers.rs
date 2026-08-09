//! Shared helper functions used across multiple route modules.
//!
//! Includes pagination helpers (cursor-based and offset-based),
//! ETag support, and common utilities.

use axum::http::header::{CACHE_CONTROL, IF_NONE_MATCH};
use axum::http::{HeaderMap, HeaderValue};
use base64::Engine;
use sha2::{Digest, Sha256};

pub const TOKEN_BLACKLIST_PREFIX: &str = "apexmail:token_blacklist:";

// ─── Clamp / default ──────────────────────────────────────────

/// Clamp a pagination `limit` to the range `[1, max]`.
pub fn clamp_limit(limit: i64, max: i64) -> i64 {
    limit.clamp(1, max)
}

/// Default pagination limit used by most list endpoints.
pub fn default_limit() -> i64 {
    50
}

// ─── Cursor-based pagination ───────────────────────────────────

/// Encode a cursor value (e.g. a row ID or timestamp) into an opaque
/// hex string that clients can pass back as the `?cursor=` parameter.
pub fn encode_cursor(cursor: &str) -> String {
    use std::fmt::Write;
    let mut hex = String::with_capacity(cursor.len() * 2);
    for b in cursor.bytes() {
        write!(hex, "{b:02x}").ok();
    }
    hex
}

/// Decode a cursor string back to its original value.
/// Returns `None` if the cursor is malformed.
pub fn decode_cursor(cursor: &str) -> Option<String> {
    if !cursor.len().is_multiple_of(2) {
        return None;
    }
    let mut bytes = Vec::with_capacity(cursor.len() / 2);
    for chunk in cursor.as_bytes().chunks(2) {
        let hex_str = std::str::from_utf8(chunk).ok()?;
        let byte = u8::from_str_radix(hex_str, 16).ok()?;
        bytes.push(byte);
    }
    String::from_utf8(bytes).ok()
}

/// Build the `LIMIT $1` part of a cursor-based pagination query.
/// Always fetches `limit + 1` rows so we can detect whether there
/// are more results (the "has_more" flag).
pub fn cursor_limit_sql(limit: i64) -> String {
    format!("LIMIT {}", limit + 1)
}

/// Build a `WHERE` clause for cursor-based pagination on a UUID or
/// timestamp column. The column name is validated against an allowlist
/// to prevent SQL injection.
///
/// # Example
/// ```sql
/// WHERE created_at < $1
/// ```
///
/// Returns `Err` (never panics) when the column is not in the allowlist.
pub fn cursor_where_sql(column: &str) -> Result<String, String> {
    const ALLOWED_COLUMNS: &[&str] = &[
        "id",
        "created_at",
        "updated_at",
        "timestamp",
        "sent_at",
        "scheduled_at",
        "delivered_at",
        "last_event",
        "started_at",
        "completed_at",
        "verified_at",
        "last_accessed",
        "last_rotated",
        "expires_at",
        "published_at",
        "logged_at",
        "date",
        "day",
    ];
    if !ALLOWED_COLUMNS.contains(&column) {
        return Err(format!(
            "column '{column}' is not in the allowlist for cursor_where_sql"
        ));
    }
    Ok(format!("WHERE {column} < $1"))
}

/// Helper to check whether a result batch has a "next page".
///
/// If `rows` has `limit + 1` items, the last item is the cursor for
/// the next page and should be removed before returning.
pub fn has_more<T>(rows: &mut Vec<T>, limit: usize) -> bool {
    if rows.len() > limit {
        rows.truncate(limit);
        true
    } else {
        false
    }
}

/// Build a pagination metadata JSON value for cursor-based responses.
pub fn pagination_meta(has_more: bool, next_cursor: Option<String>) -> serde_json::Value {
    serde_json::json!({
        "hasMore": has_more,
        "nextCursor": next_cursor,
    })
}

/// Build a pagination metadata JSON value for offset-based responses (legacy).
pub fn offset_pagination_meta(total: i64, limit: i64, offset: i64) -> serde_json::Value {
    serde_json::json!({
        "total": total,
        "limit": limit,
        "offset": offset,
    })
}

// ─── ETag / If-None-Match ──────────────────────────────────────

/// Compute a weak ETag from a content hash.
/// Weak ETags (`W/"..."`) are preferred for dynamic JSON responses
/// because content may be semantically equivalent but byte-wise different.
pub fn compute_etag(body: &[u8]) -> String {
    let hash = Sha256::digest(body);
    let b64 = base64::engine::general_purpose::URL_SAFE_NO_PAD.encode(hash);
    format!("W/\"{b64}\"")
}

/// Check the `If-None-Match` header against the current ETag.
/// Returns `true` if the client's cached version is still valid (304).
pub fn is_not_modified(headers: &HeaderMap, current_etag: &str) -> bool {
    headers
        .get_all(IF_NONE_MATCH)
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|v| v.split(',').map(|s| s.trim()))
        .any(|v| v == current_etag || v.trim_matches('"') == current_etag.trim_matches('"'))
}

/// Apply cache-control headers to a response.
pub fn with_cache_control(response: &mut axum::response::Response, max_age_secs: u32) {
    response.headers_mut().insert(
        CACHE_CONTROL,
        HeaderValue::from_str(&format!("public, max-age={max_age_secs}"))
            .expect("invariant: cache-control value is valid ASCII"),
    );
}

/// A simple in-memory response cache keyed by request path.
/// Used to avoid re-serialising the same response body.
pub struct ResponseCache {
    store: parking_lot::Mutex<std::collections::HashMap<String, (String, Vec<u8>)>>,
}

impl ResponseCache {
    /// Create a new empty cache.
    pub fn new() -> Self {
        Self {
            store: parking_lot::Mutex::new(std::collections::HashMap::new()),
        }
    }

    /// Look up a cached response by cache key.
    pub fn get(&self, key: &str) -> Option<(String, Vec<u8>)> {
        let cache = self.store.lock();
        cache.get(key).cloned()
    }

    /// Insert a response into the cache.
    pub fn set(&self, key: &str, etag: String, body: Vec<u8>) {
        let mut cache = self.store.lock();
        cache.insert(key.to_string(), (etag, body));
    }
}

impl Default for ResponseCache {
    fn default() -> Self {
        Self::new()
    }
}

// ─── Cookie extraction ─────────────────────────────────────────

/// Extract a named cookie value from the request headers.
/// Handles multiple `Cookie` headers correctly (per RFC 6265).
pub fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers
        .get_all("cookie")
        .iter()
        .filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';'))
        .map(|pair| pair.trim())
        .find_map(|pair| {
            let (k, v) = pair.split_once('=')?;
            if k.trim() == name {
                Some(v.trim().to_string())
            } else {
                None
            }
        })
}

/// Escape HTML special characters to prevent XSS.
pub fn html_escape(s: &str) -> String {
    let mut escaped = String::with_capacity(s.len());
    for c in s.chars() {
        match c {
            '&' => escaped.push_str("&amp;"),
            '<' => escaped.push_str("&lt;"),
            '>' => escaped.push_str("&gt;"),
            '"' => escaped.push_str("&quot;"),
            '\'' => escaped.push_str("&#x27;"),
            _ => escaped.push(c),
        }
    }
    escaped
}

/// Hash a verification or password-reset token before persisting it.
pub fn hash_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}

/// Build the Redis key used for revoked JWT/session tokens.
pub fn token_blacklist_key(token: &str) -> String {
    format!("{TOKEN_BLACKLIST_PREFIX}{}", hash_token(token))
}

/// Check whether a table exists in the `public` schema.
pub async fn table_exists(db: &sqlx::PgPool, name: &str) -> bool {
    let table_ref = format!("public.{name}");
    sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
        .bind(&table_ref)
        .fetch_one(db)
        .await
        .unwrap_or(false)
}

/// Check whether a column exists on a table in the `public` schema.
pub async fn column_exists(db: &sqlx::PgPool, table: &str, column: &str) -> bool {
    sqlx::query_scalar::<_, bool>(
        "SELECT EXISTS (
            SELECT 1
            FROM information_schema.columns
            WHERE table_schema = 'public'
              AND table_name = $1
              AND column_name = $2
        )",
    )
    .bind(table)
    .bind(column)
    .fetch_one(db)
    .await
    .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use sha2::{Digest, Sha256};

    #[test]
    fn token_blacklist_key_reuses_hash_token() {
        let token = "header.payload.signature";

        assert_eq!(
            token_blacklist_key(token),
            format!("{TOKEN_BLACKLIST_PREFIX}{}", hash_token(token))
        );
    }

    #[test]
    fn token_blacklist_key_hashes_null_bytes_consistently() {
        let token = "abc\0def";

        assert_eq!(
            hash_token(token),
            hex::encode(Sha256::digest(token.as_bytes()))
        );
        assert_eq!(
            token_blacklist_key(token),
            format!("{TOKEN_BLACKLIST_PREFIX}{}", hash_token(token))
        );
    }

    #[test]
    fn cursor_where_sql_accepts_allowlisted_columns() {
        for column in ["id", "created_at", "updated_at", "timestamp", "sent_at"] {
            let where_clause = cursor_where_sql(column).unwrap_or_else(|e| panic!("{e}"));
            assert_eq!(where_clause, format!("WHERE {column} < $1"));
        }
    }

    #[test]
    fn cursor_where_sql_rejects_unknown_columns_without_panicking() {
        let err = cursor_where_sql("id; DROP TABLE messages").unwrap_err();
        assert!(err.contains("allowlist"), "unexpected error: {err}");
        // Arbitrary/user-controlled column names must be rejected, not spliced.
        assert!(cursor_where_sql("from_email").is_err());
        assert!(cursor_where_sql("").is_err());
    }

    #[test]
    fn cursor_limit_sql_fetches_one_extra_row() {
        assert_eq!(cursor_limit_sql(50), "LIMIT 51");
    }

    #[test]
    fn cursor_round_trip_is_lossless() {
        let original = "2026-08-08T18:00:00.000Z";
        assert_eq!(decode_cursor(&encode_cursor(original)).unwrap(), original);
    }
}
