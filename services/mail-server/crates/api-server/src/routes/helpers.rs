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

// ─── Customer-safe delivery detail sanitization ────────────────
//
// Owner rule (third external audit): customers see the EMAIL LIFECYCLE and
// their own data, never ApexMail's internal stores, transports, provider
// internals, or infrastructure state. Raw SMTP transcripts, provider error
// bodies, database errors, hostnames and IP literals are all internal
// plumbing that must not pass through a customer-facing free-text field
// (message timeline details, event metadata summaries). One classifier,
// shared by every route that renders a delivery detail string.

/// A detail that carries internal plumbing is replaced by ONE of these
/// classified summaries. They name the lifecycle fact, never the machinery.
const DETAIL_SUMMARY_SUCCESS: &str = "accepted by recipient server";
const DETAIL_SUMMARY_TEMPORARY: &str = "delivery temporarily refused by recipient server";
const DETAIL_SUMMARY_PERMANENT: &str = "permanent failure: recipient rejected";
const DETAIL_SUMMARY_GENERIC: &str = "delivery attempt failed";

/// Substrings that mark a detail as internal plumbing: provider/transport
/// identities, connection internals, database errors. Lowercase compare.
const LEAKY_SUBSTRINGS: &[&str] = &[
    // provider/transport identities
    "ses.",
    "ses-",
    "amazonses",
    "sendgrid",
    "mailgun",
    "postmark",
    "resend",
    "smtp2go",
    "postfix",
    "opensmtpd",
    // connection internals
    "connect to",
    "connection refused",
    "connection timed out",
    "connection reset",
    "timed out",
    "timeout",
    "unreachable",
    "dns ",
    "mx record",
    "no route to host",
    // database / infrastructure internals
    "sqlstate",
    "relation \"",
    "database error",
    "error returned from database",
    "postgres",
    "deadlock",
    "connection pool",
    // raw transcripts
    "\r\n",
    "\n",
];

/// True when one whitespace-separated token looks like an IPv4 literal,
/// tolerating a trailing `:port` (`1.2.3.4`, `1.2.3.4:25`).
fn token_is_ipv4(token: &str) -> bool {
    let host = token.split_once(':').map_or(token, |(host, _)| host);
    let mut groups = host.split('.');
    let mut count = 0usize;
    for group in groups.by_ref() {
        if group.is_empty() || !group.bytes().all(|b| b.is_ascii_digit()) {
            return false;
        }
        count += 1;
    }
    count == 4
}

/// True when a token looks like an IPv6 literal or IPv4-mapped form:
/// only hex digits and colons, at least two colons, and either a hex letter
/// (fe80::1) or a leading/trailing compression colon (::1, 1::). Clock
/// times like `12:00:00` (no hex letters, no compression colon) are not
/// addresses and must survive.
fn token_is_ipv6(token: &str) -> bool {
    if !token.bytes().all(|b| b.is_ascii_hexdigit() || b == b':') {
        return false;
    }
    let colons = token.bytes().filter(|b| *b == b':').count();
    if colons < 2 {
        return false;
    }
    let has_hex_letter = token
        .bytes()
        .any(|b| b.is_ascii_hexdigit() && !b.is_ascii_digit());
    has_hex_letter || token.starts_with(':') || token.ends_with(':')
}

/// True when a token looks like a hostname: it contains a dot and a
/// alphabetic character, and carries no `:`/`/`/`@` (ports, URLs and email
/// addresses are handled by other shapes or are the customer's own data).
/// Numeric-only dot groups (SMTP status codes like `2.0.0`) are not
/// hostnames.
fn token_is_hostname(token: &str) -> bool {
    let trimmed = token.trim_matches(|c: char| !c.is_alphanumeric() && c != '.' && c != '-');
    if !trimmed.contains('.') || trimmed.contains([':', '/', '@']) {
        return false;
    }
    trimmed.chars().any(|c| c.is_alphabetic())
}

/// Does this detail string carry internal plumbing that a customer must
/// never see verbatim?
fn detail_is_leaky(detail: &str) -> bool {
    let lower = detail.to_lowercase();
    if LEAKY_SUBSTRINGS.iter().any(|needle| lower.contains(needle)) {
        return true;
    }
    lower
        .split_whitespace()
        .any(|token| token_is_ipv4(token) || token_is_ipv6(token) || token_is_hostname(token))
}

/// Classify a leaky detail into a lifecycle summary (see the summaries'
/// doc comments for the intent of each class).
fn classify_leaky_detail(detail: &str) -> &'static str {
    let lower = detail.to_lowercase();
    // Success first: a 2xx response that mentions internal machinery is
    // still a success, it must not read as a failure.
    let starts_with_success_code = lower.split_whitespace().next().is_some_and(|first| {
        (first.starts_with("25") && first.len() == 3) || first.starts_with("2.") || first == "200"
    });
    if starts_with_success_code {
        return DETAIL_SUMMARY_SUCCESS;
    }
    let permanent = [
        "550",
        "551",
        "552",
        "553",
        "5.1.",
        "5.4.",
        "5.7.",
        "reject",
        "permanent",
        "no such user",
        "unknown user",
        "user unknown",
        "does not exist",
        "mailbox unavailable",
        "blacklist",
        "blocked",
    ];
    if permanent.iter().any(|needle| lower.contains(needle)) {
        return DETAIL_SUMMARY_PERMANENT;
    }
    let temporary = [
        "450",
        "451",
        "452",
        "4.2.",
        "4.7.",
        "greylist",
        "temporar",
        "defer",
        "timed out",
        "timeout",
        "connect",
        "unreachable",
        "try again",
        "busy",
        "throttl",
        "full",
    ];
    if temporary.iter().any(|needle| lower.contains(needle)) {
        return DETAIL_SUMMARY_TEMPORARY;
    }
    DETAIL_SUMMARY_GENERIC
}

/// Render a delivery detail string for a customer-facing response.
///
/// House-generated lifecycle details ("attempt 1/5", "A/B arm 0",
/// "250 2.0.0 OK", "greylisted") pass through unchanged; anything carrying
/// internal plumbing (IP literals, hostnames, provider identities, raw SMTP
/// transcripts, database errors, connection internals) is replaced with a
/// generic classified summary that names the lifecycle fact only.
pub(crate) fn sanitize_delivery_detail(detail: &str) -> String {
    if detail_is_leaky(detail) {
        classify_leaky_detail(detail).to_string()
    } else {
        detail.to_string()
    }
}

/// [`sanitize_delivery_detail`] over an optional detail: `None` stays
/// `None`, a present detail is always returned sanitized.
pub(crate) fn sanitize_delivery_detail_opt(detail: Option<&str>) -> Option<String> {
    detail.map(sanitize_delivery_detail)
}

// ─── Schema capability probes ──────────────────────────────────
//
// P1 fix (swallowed outages): both probes used to end in
// `.await.unwrap_or(false)`, making "table absent" indistinguishable from
// "database unreachable / pool exhausted / permission denied", an outage
// masqueraded as a healthy empty state. They now return the probe error and
// every caller decides explicitly:
//
// * `Ok(false)`, genuine absence → the legacy / empty / fallback SQL path;
// * `Err(_)`   , degraded → the caller's honest error contract (a 5xx for
//   admin APIs, a "Data unavailable" render for the web layer), NEVER a
//   fabricated healthy zero.
//
// Hot-path hoisting: in a canonical-migration production environment the
// schema is fixed for the life of the process (the real migrator runs before
// `up`), so a probe result is a *capability*. The first successful probe for
// a given database is memoized in [`CAPABILITY_CACHE`] and every later call
//, including per-request probes on hot admin paths, reads the cached
// capability instead of re-querying the catalog. Probe ERRORS are never
// cached: a degraded database must stay detectable on every call. (The cache
// is populated lazily on first use rather than at state build: `state.rs` is
// outside this fix's ownership boundary, and the observable behavior, one
// catalog query per database per capability per process, is identical.)

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
/// `Err` means the catalog itself could not be consulted, propagate it, do
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

        // `Default` builds the same empty cache, never a shared global.
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
        // Even length but not valid hex is refused too, never a panic.
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
        // pair with NO `=` at all, it must be skipped, never panic.
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
        // None arm) and "junk-noequals" has no `=` (skip arm), still a
        // clean absence, never a panic.
        assert_eq!(extract_cookie(&headers, "missing"), None);
        assert_eq!(extract_cookie(&headers, "junk-noequals"), None);
    }

    // ── Customer-safe delivery detail sanitization ───────────────

    #[test]
    fn sanitize_keeps_house_lifecycle_details_verbatim() {
        // House-generated details name lifecycle facts only; they must pass
        // through byte for byte or the console loses real information.
        for detail in [
            "attempt 1/5",
            "A/B arm 0",
            "250 2.0.0 OK",
            "greylisted",
            "soft_bounce",
            "hard_bounce",
            "scheduled for 2026-10-25T12:00:00+00:00",
            "every recipient copy was confirmed delivered",
            "permanent failure: recipient rejected",
        ] {
            assert_eq!(
                sanitize_delivery_detail(detail),
                detail,
                "house detail must survive: {detail}"
            );
        }
    }

    #[test]
    fn sanitize_generalizes_the_audit_examples() {
        // The audit's named shapes: an IP literal, a provider identity, a
        // connection transcript fragment.
        for detail in [
            "connect to 1.2.3.4:25 timed out",
            "450 4.2.1 greylisted, retry via ses.amazonses.com",
            "connect to internal.example:25: Connection refused",
        ] {
            let sanitized = sanitize_delivery_detail(detail);
            assert_ne!(sanitized, detail, "{detail} must be generalized");
            assert!(
                !sanitized.contains("1.2.3.4")
                    && !sanitized.contains("ses.")
                    && !sanitized.contains("internal.example"),
                "leak survived: {sanitized}"
            );
        }
    }

    #[test]
    fn sanitize_classifies_by_lifecycle_outcome() {
        // Temporary refusals.
        for detail in [
            "connect to 1.2.3.4:25 timed out",
            "451 4.7.1 greylisted, try again later from mail.example.com",
            "450 mx record lookup deferred for recipient.host",
        ] {
            assert_eq!(
                sanitize_delivery_detail(detail),
                "delivery temporarily refused by recipient server",
                "{detail}"
            );
        }
        // Permanent rejections.
        for detail in [
            "550 5.1.1 user unknown (bounces+123@bounce.ses.example.com)",
            "553 mailbox unavailable at internal-relay.example",
        ] {
            assert_eq!(
                sanitize_delivery_detail(detail),
                "permanent failure: recipient rejected",
                "{detail}"
            );
        }
        // A success response naming internal machinery stays a success.
        assert_eq!(
            sanitize_delivery_detail("250 2.0.0 OK via ses.amazonses.com"),
            "accepted by recipient server"
        );
        // Unclassifiable plumbing gets the generic summary.
        assert_eq!(
            sanitize_delivery_detail("error returned from database: deadlock detected"),
            "delivery attempt failed"
        );
    }

    #[test]
    fn sanitize_covers_ipv6_hostnames_and_transcripts() {
        assert_eq!(
            sanitize_delivery_detail("connect to fe80::1:25 refused"),
            "delivery temporarily refused by recipient server"
        );
        assert_eq!(
            sanitize_delivery_detail("relay mail-wm1-f43.google.com said: 550 blocked"),
            "permanent failure: recipient rejected"
        );
        // Multi-line SMTP transcripts never pass through whole.
        let transcript = "220 internal-relay.example ESMTP\r\n250 OK\r\n550 denied";
        let sanitized = sanitize_delivery_detail(transcript);
        assert!(!sanitized.contains('\n') && !sanitized.contains('\r'));
        assert!(!sanitized.contains("internal-relay.example"));
        // Optional wrapper: None stays None, present values are sanitized.
        assert_eq!(sanitize_delivery_detail_opt(None), None);
        assert_eq!(
            sanitize_delivery_detail_opt(Some("connect to 1.2.3.4 refused")).as_deref(),
            Some("delivery temporarily refused by recipient server")
        );
    }

    #[test]
    fn address_token_detectors_do_not_swallow_times_or_status_codes() {
        // The detectors back the sanitizer; their false-positive surface is
        // the part that would mangle house details.
        assert!(token_is_ipv4("1.2.3.4"));
        assert!(token_is_ipv4("1.2.3.4:25"));
        assert!(!token_is_ipv4("2.0.0"));
        assert!(!token_is_ipv4("12:00:00"));
        assert!(token_is_ipv6("fe80::1"));
        assert!(token_is_ipv6("::1"));
        assert!(!token_is_ipv6("12:00:00"));
        assert!(!token_is_ipv6("2026-10-25T12:00:00+00:00"));
        assert!(token_is_hostname("internal.example"));
        assert!(token_is_hostname("mail-wm1-f43.google.com"));
        assert!(!token_is_hostname("2.0.0"));
        assert!(!token_is_hostname("https://example.com/click"));
        assert!(!token_is_hostname("user@example.com"));
        // Fractional RFC 3339 timestamps carry a dot and an alpha `T` but
        // also colons: they are not hostnames.
        assert!(!token_is_hostname("2026-10-25T12:00:00.123456+00:00"));
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
