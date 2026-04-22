//! Shared helper functions used across multiple route modules.

use axum::http::HeaderMap;
use sha2::{Digest, Sha256};

/// Clamp a pagination `limit` to the range `[1, max]`.
pub fn clamp_limit(limit: i64, max: i64) -> i64 {
    limit.clamp(1, max)
}

/// Default pagination limit used by most list endpoints.
pub fn default_limit() -> i64 {
    50
}

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

/// Check whether a table exists in the `public` schema.
pub async fn table_exists(db: &sqlx::PgPool, name: &str) -> bool {
    let table_ref = format!("public.{name}");
    sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
        .bind(&table_ref)
        .fetch_one(db)
        .await
        .unwrap_or(false)
}
