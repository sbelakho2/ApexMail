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

// ─── Schema capability probes ──────────────────────────────────
//
// P1 fix (swallowed outages): both probes used to end in
// `.await.unwrap_or(false)`, making "table absent" indistinguishable from
// "database unreachable / pool exhausted / permission denied" — an outage
// masqueraded as a healthy empty state. They now return the probe error and
// every caller decides explicitly:
//
// * `Ok(false)` — genuine absence → the legacy / empty / fallback SQL path;
// * `Err(_)`    — degraded → the caller's honest error contract (a 5xx for
//   admin APIs, a "Data unavailable" render for the web layer), NEVER a
//   fabricated healthy zero.
//
// Hot-path hoisting: in a canonical-migration production environment the
// schema is fixed for the life of the process (the real migrator runs before
// `up`), so a probe result is a *capability*. The first successful probe for
// a given database is memoized in [`CAPABILITY_CACHE`] and every later call
// — including per-request probes on hot admin paths — reads the cached
// capability instead of re-querying the catalog. Probe ERRORS are never
// cached: a degraded database must stay detectable on every call. (The cache
// is populated lazily on first use rather than at state build: `state.rs` is
// outside this fix's ownership boundary, and the observable behavior — one
// catalog query per database per capability per process — is identical.)

/// Memoized schema capabilities keyed by (database identity, probe kind).
static CAPABILITY_CACHE: std::sync::OnceLock<
    parking_lot::Mutex<std::collections::HashMap<(String, String), bool>>,
> = std::sync::OnceLock::new();

fn capability_cache(
) -> &'static parking_lot::Mutex<std::collections::HashMap<(String, String), bool>> {
    CAPABILITY_CACHE.get_or_init(|| parking_lot::Mutex::new(std::collections::HashMap::new()))
}

/// Stable per-database identity for capability caching. Distinct databases
/// (test isolation databases, a dead lazy pool pointed elsewhere) get distinct
/// cache entries; clones of the same pool share one.
pub(crate) fn pool_identity(db: &sqlx::PgPool) -> String {
    let opts = db.connect_options();
    match opts.get_socket() {
        Some(socket) => format!(
            "unix:{}|{}|{}",
            socket.display(),
            opts.get_username(),
            opts.get_database().unwrap_or_default()
        ),
        None => format!(
            "{}:{}/{}|{}",
            opts.get_host(),
            opts.get_port(),
            opts.get_username(),
            opts.get_database().unwrap_or_default()
        ),
    }
}

/// Check whether a table exists in the `public` schema.
///
/// `Ok(false)` is a definitive answer (memoized per process per database);
/// `Err` means the catalog itself could not be consulted — propagate it, do
/// not treat the table as absent.
pub async fn table_exists(db: &sqlx::PgPool, name: &str) -> Result<bool, sqlx::Error> {
    let key = (pool_identity(db), format!("table:{name}"));
    if let Some(cached) = capability_cache().lock().get(&key) {
        return Ok(*cached);
    }
    let table_ref = format!("public.{name}");
    let exists = sqlx::query_scalar::<_, bool>("SELECT to_regclass($1) IS NOT NULL")
        .bind(&table_ref)
        .fetch_one(db)
        .await?;
    capability_cache().lock().insert(key, exists);
    Ok(exists)
}

/// Check whether a column exists on a table in the `public` schema.
///
/// Same contract as [`table_exists`]: `Err` is a degraded database, never a
/// "column missing" verdict.
pub async fn column_exists(
    db: &sqlx::PgPool,
    table: &str,
    column: &str,
) -> Result<bool, sqlx::Error> {
    let key = (pool_identity(db), format!("column:{table}.{column}"));
    if let Some(cached) = capability_cache().lock().get(&key) {
        return Ok(*cached);
    }
    let exists = sqlx::query_scalar::<_, bool>(
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
    .await?;
    capability_cache().lock().insert(key, exists);
    Ok(exists)
}

/// Number of memoized capabilities (test visibility only).
#[cfg(test)]
pub(crate) fn capability_cache_len() -> usize {
    capability_cache().lock().len()
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
    fn offset_pagination_meta_reports_total_limit_and_offset() {
        let meta = offset_pagination_meta(120, 25, 50);
        assert_eq!(meta["total"], 120);
        assert_eq!(meta["limit"], 25);
        assert_eq!(meta["offset"], 50);
    }

    #[test]
    fn with_cache_control_sets_public_max_age() {
        let mut response = axum::response::Response::builder()
            .status(axum::http::StatusCode::OK)
            .body(axum::body::Body::empty())
            .expect("static response");
        with_cache_control(&mut response, 300);
        assert_eq!(
            response
                .headers()
                .get(axum::http::header::CACHE_CONTROL)
                .expect("cache-control header"),
            "public, max-age=300"
        );
    }

    #[test]
    fn response_cache_round_trips_and_overwrites() {
        let cache = ResponseCache::new();
        assert!(cache.get("missing").is_none(), "empty cache misses");

        cache.set("key", "etag-1".to_string(), b"body-1".to_vec());
        let (etag, body) = cache.get("key").expect("hit");
        assert_eq!(etag, "etag-1");
        assert_eq!(body, b"body-1");

        cache.set("key", "etag-2".to_string(), b"body-2".to_vec());
        let (etag, body) = cache.get("key").expect("hit after overwrite");
        assert_eq!(etag, "etag-2");
        assert_eq!(body, b"body-2");

        // `Default` builds the same empty cache — never a shared global.
        let default: ResponseCache = ResponseCache::default();
        assert!(default.get("key").is_none());
    }

    // tokio::test: sqlx 0.8's Pool::connect_options spawns its maintenance
    // machinery, which requires a runtime context even for a lazy pool.
    #[tokio::test]
    async fn pool_identity_distinguishes_unix_sockets_and_defaulted_databases() {
        // A unix-socket endpoint with NO database configured exercises the
        // socket arm AND the `unwrap_or_default()` database fallback.
        let options = sqlx::postgres::PgConnectOptions::new()
            .socket("/tmp/apexmail-capability-probe.sock")
            .username("probe_user");
        let socket_pool = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options.clone());
        let identity = pool_identity(&socket_pool);
        assert_eq!(
            identity, "unix:/tmp/apexmail-capability-probe.sock|probe_user|",
            "socket path, username and (defaulted) database name the identity"
        );

        // The same socket with a database is a DIFFERENT identity.
        let with_db = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy_with(options.database("probe_db"));
        assert_eq!(
            pool_identity(&with_db),
            "unix:/tmp/apexmail-capability-probe.sock|probe_user|probe_db"
        );
        assert_ne!(pool_identity(&with_db), identity);

        // A TCP endpoint never produces a unix-socket identity.
        let tcp = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://probe_user:pw@127.0.0.1:1/probe_db")
            .expect("lazy tcp pool");
        assert!(
            !pool_identity(&tcp).starts_with("unix:"),
            "{}",
            pool_identity(&tcp)
        );
    }

    #[test]
    fn cursor_round_trip_is_lossless() {
        let original = "2026-08-08T18:00:00.000Z";
        assert_eq!(decode_cursor(&encode_cursor(original)).unwrap(), original);
    }

    #[test]
    fn decode_cursor_rejects_odd_length_and_non_hex_input() {
        // An odd-length string can never be split into byte-sized hex pairs.
        assert_eq!(decode_cursor("abc"), None, "odd length is malformed");
        // Even length but not valid hex is refused too — never a panic.
        assert_eq!(decode_cursor("zz"), None, "non-hex pairs are rejected");
        // The empty cursor decodes to the empty string (first page).
        assert_eq!(decode_cursor(""), Some(String::new()));
    }

    #[test]
    fn has_more_truncates_only_when_an_extra_row_arrives() {
        // limit + 1 rows: the last row is the next-page cursor and must be
        // removed before the batch is returned.
        let mut rows = vec![1, 2, 3];
        assert!(has_more(&mut rows, 2), "an extra row signals a next page");
        assert_eq!(rows, vec![1, 2], "the cursor row is truncated away");

        // Exactly `limit` rows: no next page, nothing removed.
        let mut exact = vec![1, 2];
        assert!(!has_more(&mut exact, 2));
        assert_eq!(exact, vec![1, 2], "an exact batch is left untouched");

        // Degenerate shapes stay honest: an empty batch is never "more".
        let mut empty: Vec<u8> = Vec::new();
        assert!(!has_more(&mut empty, 0));
        assert!(empty.is_empty());
    }

    #[test]
    fn extract_cookie_handles_multiple_headers_pairs_and_missing_equals() {
        let mut headers = axum::http::HeaderMap::new();
        headers.append(
            "cookie",
            axum::http::HeaderValue::from_static("theme=dark; session = abc123 "),
        );
        // A second Cookie header (RFC 6265 allows several) containing a
        // pair with NO `=` at all — it must be skipped, never panic.
        headers.append(
            "cookie",
            axum::http::HeaderValue::from_static("junk-noequals"),
        );

        assert_eq!(
            extract_cookie(&headers, "theme").as_deref(),
            Some("dark"),
            "first pair matches; whitespace around key/value is trimmed"
        );
        assert_eq!(
            extract_cookie(&headers, "session").as_deref(),
            Some("abc123"),
            "the matching pair wins across separators"
        );
        // "missing" walks every pair: the two named pairs miss (per-pair
        // None arm) and "junk-noequals" has no `=` (skip arm) — still a
        // clean absence, never a panic.
        assert_eq!(extract_cookie(&headers, "missing"), None);
        assert_eq!(extract_cookie(&headers, "junk-noequals"), None);
    }

    #[test]
    fn html_escape_encodes_every_special_char_and_keeps_plain_text() {
        assert_eq!(
            html_escape("a&b<c>\"d'e"),
            "a&amp;b&lt;c&gt;&quot;d&#x27;e",
            "every HTML-special character is entity-encoded"
        );
        assert_eq!(
            html_escape("plain-text_1.2 (ok)"),
            "plain-text_1.2 (ok)",
            "ordinary characters pass through untouched"
        );
        assert_eq!(html_escape(""), "", "the empty string escapes to itself");
    }

    // tokio::test: sqlx 0.8's Pool::connect_options spawns its maintenance
    // machinery, which requires a runtime context even for a lazy pool.
    #[tokio::test]
    async fn pool_identity_distinguishes_databases_and_shares_clones() {
        let dead_a = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/probe_db_a")
            .expect("lazy pool");
        let dead_a_clone = dead_a.clone();
        let dead_b = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/probe_db_b")
            .expect("lazy pool");

        assert_eq!(
            pool_identity(&dead_a),
            pool_identity(&dead_a_clone),
            "clones of one pool share an identity"
        );
        assert_ne!(
            pool_identity(&dead_a),
            pool_identity(&dead_b),
            "distinct databases must never share a capability cache entry"
        );
    }

    /// Fix (P1 swallowed outages): `Ok` capability verdicts are memoized per
    /// process per database; probe errors are NEVER cached, so a degraded
    /// database stays detectable on every call.
    #[tokio::test]
    async fn capability_probes_cache_ok_and_never_cache_errors() {
        capability_probe_cache_assertions(
            crate::test_db::optional_pg_pool("helpers_capability_cache").await,
        )
        .await;
    }

    /// The soft-skip contract holds without a database too: the probe suite
    /// is a clean skip, never a panic. Exercised directly so the guard arm
    /// stays measured in database-provisioned environments.
    #[tokio::test]
    async fn capability_probe_suite_skips_cleanly_without_a_database() {
        capability_probe_cache_assertions(None).await;
    }

    async fn capability_probe_cache_assertions(pool: Option<sqlx::PgPool>) {
        let Some(pool) = pool else {
            return;
        };
        let unique_table = format!(
            "capability_probe_{}",
            &uuid::Uuid::new_v4().simple().to_string()[..12]
        );

        // Genuine absence is a definitive Ok(false)…
        let before = capability_cache_len();
        assert!(!table_exists(&pool, &unique_table).await.expect("probe"));
        // …and it is memoized (one catalog query for this database + probe).
        assert!(
            capability_cache_len() > before,
            "the Ok verdict must be memoized"
        );
        assert!(!table_exists(&pool, &unique_table).await.expect("cached"));
        assert!(table_exists(&pool, "tenants").await.expect("probe"));

        // Same contract for the COLUMN probe: a live-pool verdict is a
        // definitive Ok (and memoized), and the second call is served from
        // the capability cache instead of re-querying the catalog.
        let before_columns = capability_cache_len();
        assert!(
            column_exists(&pool, "tenants", "id")
                .await
                .expect("column probe"),
            "tenants.id exists in the canonical schema"
        );
        assert!(
            capability_cache_len() > before_columns,
            "the Ok column verdict must be memoized"
        );
        assert!(
            column_exists(&pool, "tenants", "id")
                .await
                .expect("cached column probe"),
            "the cached verdict is served verbatim"
        );

        // A dead (lazy) pool probes to Err, and the error is not cached:
        // both calls re-attempt the catalog query.
        let dead = sqlx::postgres::PgPoolOptions::new()
            .max_connections(1)
            .acquire_timeout(std::time::Duration::from_millis(300))
            .connect_lazy("postgres://apexmail:apexmail@127.0.0.1:1/apexmail")
            .expect("lazy dead pool");
        let key = (pool_identity(&dead), format!("table:{unique_table}"));
        assert!(
            table_exists(&dead, &unique_table).await.is_err(),
            "an unreachable database is Err, never a fabricated absent"
        );
        assert!(
            table_exists(&dead, &unique_table).await.is_err(),
            "a failed probe must not be cached as absence"
        );
        assert!(
            !capability_cache().lock().contains_key(&key),
            "errors must never enter the capability cache"
        );
        assert!(column_exists(&dead, "tenants", "id").await.is_err());
    }
}
