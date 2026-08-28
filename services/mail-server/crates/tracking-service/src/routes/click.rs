//! Click-tracking redirect handler.
//!
//! GET `{click_path}/:tracking_id`
//!
//! Security properties:
//! - Prefers `originalUrl` from inside the encrypted token over `?r=` query
//!   param (-041) — query params can be tampered with, token content cannot.
//! - Only allows redirects to http/https URLs whose hostname is explicitly
//!   authorised for the tenant (blocks open-redirect attacks).
//! - Adds a locked-down `Content-Security-Policy` to prevent click-jacking and
//!   script/style execution around redirect responses (-500-455).

use std::net::SocketAddr;

use axum::{
    extract::{ConnectInfo, Path, Query, State},
    http::{HeaderMap, StatusCode},
    response::Response,
};
use serde::Deserialize;
use tracing::{debug, error, info, warn};

use crate::processor::ClickData;
use crate::routes::extract_client_ip;
use crate::state::AppState;

const TRACKING_CSP: &str = "default-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'none'; img-src 'self' data:; script-src 'none'; style-src 'none'; object-src 'none'";

#[derive(Deserialize)]
pub struct ClickQuery {
    /// Optional override URL (used when originalUrl was not baked into the
    /// token). NOTE:axum's `Query` extractor has ALREADY percent-decoded
    /// this value exactly once (serde_urlencoded form decoding) — use it
    /// verbatim, never decode it again.
    r: Option<String>,
}

pub async fn handle_click(
    State(state): State<AppState>,
    ConnectInfo(addr): ConnectInfo<SocketAddr>,
    headers: HeaderMap,
    Path(tracking_id): Path<String>,
    Query(q): Query<ClickQuery>,
) -> Response {
    let fallback = state.config.tracking.fallback_url.clone();
    let redirect_status = state.config.tracking.redirect_status;

    // E-148:Length guard
    if tracking_id.len() < 10 || tracking_id.len() > 4096 {
        warn!(len = tracking_id.len(), "Click: invalid trackingId length");
        return csp_redirect(&fallback, redirect_status);
    }

    let user_agent = headers
        .get("user-agent")
        .and_then(|v| v.to_str().ok())
        .map(str::to_owned);
    let ip = extract_client_ip(&headers, addr.ip(), &state);

    // E-190 (parity with pixel.rs): bots and security scanners still get
    // their click-through served — never break the user's redirect — but
    // their hits must not pollute click analytics.
    let is_bot = state.bot_detector.is_bot(user_agent.as_deref(), Some(&ip));
    if is_bot {
        info!("E-190: Bot detected on click redirect, skipping recording");
    }

    debug!(
        id_prefix = &tracking_id[..tracking_id.len().min(20)],
        has_r = q.r.is_some(),
        is_bot,
        "Click tracking request"
    );

    let data = state.codec.decode(&tracking_id);

    let redirect_url = determine_redirect_url(&data, q.r.as_deref(), &fallback);

    // Validate protocol and domain. `validated` keeps the outcome so the
    // click is only RECORDED when the redirect was actually authorised —
    // recording a blocked link as a "click on the fallback URL" would
    // poison click analytics and the per-link URL cache.
    let validated = validate_redirect_url(&redirect_url, data.as_ref(), &state).await;
    let redirect_url = match &validated {
        Ok(url) => url.clone(),
        Err(_) => {
            // The block reason is warn!'d inside validate_redirect_url;
            // the counter feeds blocked-link dashboards separately.
            metrics::counter!("apexmail_tracking_click_redirects_blocked_total").increment(1);
            fallback.clone()
        }
    };

    // Record click asynchronously (fire-and-forget) — only for valid tokens,
    // non-bot clients, and redirects that passed domain validation.
    if let Some(d) = &data {
        if validated.is_ok() && !is_bot {
            let processor = state.processor.clone();
            let click_data = ClickData {
                tenant_id: d.tenant_id.clone(),
                message_id: d.message_id.clone(),
                recipient: d.recipient.clone(),
                link_id: d.link_id.clone().unwrap_or_else(|| "unknown".into()),
                link_url: redirect_url.clone(),
                user_agent: user_agent.clone(),
                ip_address: Some(ip.clone()),
            };

            // Store link URL in Redis for analytics (F-213, 90 day TTL)
            if let Some(link_id) = &d.link_id {
                let redis = state.redis.clone();
                let link_key = format!("links:{}:{}", d.tenant_id, d.message_id);
                let lid = link_id.clone();
                let url2 = redirect_url.clone();
                tokio::spawn(async move {
                    if let Ok(mut conn) = redis.get().await {
                        if let Err(error) = redis::pipe()
                            .hset(&link_key, &lid, &url2)
                            .expire(&link_key, 86400 * 90)
                            .query_async::<()>(&mut *conn)
                            .await
                        {
                            warn!(link_key = %link_key, link_id = %lid, error = %error, "Failed to cache click-tracking link metadata");
                        }
                    }
                });
            }

            tokio::spawn(async move {
                if let Err(e) = processor.record_click(click_data).await {
                    error!(error = %e, "Failed to record click event");
                }
            });
        }
    } else {
        warn!(
            id_prefix = &tracking_id[..tracking_id.len().min(20)],
            "Click: invalid tracking token"
        );
    }

    csp_redirect(&redirect_url, redirect_status)
}

// ── Helpers ───────────────────────────────────────────────────────────────────

fn determine_redirect_url(
    data: &Option<crate::codec::TrackingData>,
    r_param: Option<&str>,
    fallback: &str,
) -> String {
    if let Some(d) = data {
        if let Some(url) = &d.original_url {
            return url.clone();
        }
        if let Some(r) = r_param {
            // F-211:the `?r=` value was percent-decoded exactly ONCE by
            // axum's `Query` extractor (which also maps `+` to space, so
            // producers must encode a literal `+` as `%2B`). Use it as
            // received: a second decode would silently rewrite URLs that
            // legitimately contain `%2F`-style sequences
            // (`https://x/a%2Fb` → `https://x/a/b`).
            return r.to_owned();
        }
    }
    fallback.to_owned()
}

async fn validate_redirect_url(
    url: &str,
    data: Option<&crate::codec::TrackingData>,
    state: &AppState,
) -> Result<String, ()> {
    // O-6.2: Enforce max redirect URL length
    let max_len = state.config.tracking.max_redirect_url_len;
    if url.len() > max_len {
        warn!(
            url_len = url.len(),
            max_len = max_len,
            "Click: redirect URL exceeds max length"
        );
        return Err(());
    }

    let parsed = parse_allowed_redirect_url(url)?;

    if let Some(d) = data {
        let domain = parsed.host_str().unwrap_or("").to_owned();
        let allowed = verify_redirect_domain(state, &d.tenant_id, &domain).await;
        if !allowed {
            warn!(
                domain = %domain,
                tenant_id = %d.tenant_id,
                "Click: blocked unauthorized redirect domain"
            );
            return Err(());
        }
    }

    Ok(url.to_owned())
}

fn parse_allowed_redirect_url(url: &str) -> Result<url::Url, ()> {
    let parsed = url.parse::<url::Url>().map_err(|_| ())?;

    match parsed.scheme() {
        "http" | "https" => Ok(parsed),
        scheme => {
            warn!(scheme, "Click: blocked non-http redirect");
            Err(())
        }
    }
}

/// Check if `domain` is authorised for `tenant_id`.
/// Cache hierarchy:/// 1. moka in-memory cache (60 s TTL, 10 000 entries)
/// 2. Redis (300 s TTL)
/// 3. Postgres (domains + tenant_settings tables)
async fn verify_redirect_domain(state: &AppState, tenant_id: &str, domain: &str) -> bool {
    let cache_key = format!("{tenant_id}:{domain}");

    // 1. moka
    if let Some(r) = state.domain_cache.get(&cache_key).await {
        return r;
    }

    // Allow fallback domain without DB round-trip
    if let Ok(fallback) = state.config.tracking.fallback_url.parse::<url::Url>() {
        if fallback.host_str() == Some(domain) {
            state.domain_cache.insert(cache_key.clone(), true).await;
            return true;
        }
    }

    // 2. Redis
    let redis_key = format!("redirect_domain:{cache_key}");
    if let Ok(mut conn) = state.redis.get().await {
        if let Ok(cached) = redis::cmd("GET")
            .arg(&redis_key)
            .query_async::<Option<String>>(&mut *conn)
            .await
        {
            let result = cached.as_deref() == Some("1");
            state.domain_cache.insert(cache_key.clone(), result).await;
            return result;
        }
    }

    // 3. Postgres:owned domains
    let result: bool = async {
        let row = sqlx::query_as::<_, (i64,)>(
            "SELECT 1 FROM domains WHERE tenant_id = $1 AND domain = $2 LIMIT 1",
        )
        .bind(tenant_id)
        .bind(domain)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        if row.is_some() {
            return true;
        }

        // 4. Postgres:allowed_redirect_domains wildcard patterns
        let row = sqlx::query_as::<_, (Vec<String>,)>(
            "SELECT allowed_redirect_domains FROM tenant_settings WHERE tenant_id = $1",
        )
        .bind(tenant_id)
        .fetch_optional(&state.db)
        .await
        .ok()
        .flatten();

        if let Some((patterns,)) = row {
            for pattern in &patterns {
                if match_domain_pattern(domain, pattern) {
                    return true;
                }
            }
        }
        false
    }
    .await;

    // Cache result in both Redis and moka
    if let Ok(mut conn) = state.redis.get().await {
        let val = if result { "1" } else { "0" };
        let _ = redis::cmd("SETEX")
            .arg(&redis_key)
            .arg(300u64)
            .arg(val)
            .query_async::<()>(&mut *conn)
            .await;
    }
    state.domain_cache.insert(cache_key, result).await;
    result
}

/// Match a domain against a pattern (supports `*.example.com` wildcard prefix).
/// Case-insensitive per RFC 4343 (F-212).
fn match_domain_pattern(domain: &str, pattern: &str) -> bool {
    let d = domain.to_lowercase();
    let p = pattern.to_lowercase();
    if p == d {
        return true;
    }
    if let Some(suffix) = p.strip_prefix("*.") {
        let dot_suffix = format!(".{suffix}");
        return d.ends_with(&dot_suffix) && d.len() > dot_suffix.len();
    }
    false
}

/// Return a redirect response with a locked-down CSP and the exact status code
/// from config (typically 302).
fn csp_redirect(url: &str, status: u16) -> Response {
    let code = StatusCode::from_u16(status).unwrap_or(StatusCode::FOUND);
    axum::http::Response::builder()
        .status(code)
        .header("location", url)
        .header("content-security-policy", TRACKING_CSP)
        .body(axum::body::Body::empty())
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::codec::{TrackingCodec, TrackingData};

    #[test]
    fn determine_redirect_url_prefers_token_original_url() {
        let data = Some(TrackingData {
            tenant_id: "tenant_1".into(),
            message_id: "msg_1".into(),
            recipient: "user@example.com".into(),
            link_id: Some("link_1".into()),
            original_url: Some("https://safe.example.com/path".into()),
        });

        let redirect = determine_redirect_url(
            &data,
            Some("https%3A%2F%2Fevil.example.com"),
            "https://fallback.example.com",
        );

        assert_eq!(redirect, "https://safe.example.com/path");
    }

    /// The `?r=` value arrives here ALREADY percent-decoded exactly once by
    /// axum's `Query` extractor — `determine_redirect_url` must use it
    /// verbatim. A second decode would silently rewrite URLs that
    /// legitimately contain `%2F`-style sequences.
    #[test]
    fn determine_redirect_url_uses_r_param_verbatim() {
        let data = Some(TrackingData {
            tenant_id: "tenant_1".into(),
            message_id: "msg_1".into(),
            recipient: "user@example.com".into(),
            link_id: Some("link_1".into()),
            original_url: None,
        });

        let redirect = determine_redirect_url(
            &data,
            Some("https://safe.example.com/promo%2Fsale+event"),
            "https://fallback.example.com",
        );

        assert_eq!(redirect, "https://safe.example.com/promo%2Fsale+event");
    }

    #[test]
    fn parse_allowed_redirect_url_rejects_javascript_scheme() {
        assert!(parse_allowed_redirect_url("javascript:alert(1)").is_err());
    }

    #[test]
    fn parse_allowed_redirect_url_accepts_https_scheme() {
        let parsed = parse_allowed_redirect_url("https://app.example.com/path").unwrap();

        assert_eq!(parsed.scheme(), "https");
        assert_eq!(parsed.host_str(), Some("app.example.com"));
    }

    #[test]
    fn csp_redirect_uses_locked_down_policy() {
        let response = csp_redirect("https://app.example.com/path", 302);
        let csp = response
            .headers()
            .get("content-security-policy")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default();

        assert!(csp.contains("default-src 'none'"));
        assert!(csp.contains("frame-ancestors 'none'"));
        assert!(csp.contains("script-src 'none'"));
    }

    // ── Handler-level tests (drive the real axum Query extractor) ─────────
    //
    // These issue real HTTP requests through [`build_router`] so the `?r=`
    // parameter goes through axum's `Query` extraction (serde_urlencoded
    // form decoding) exactly as in production. They need the live test
    // Redis (`TEST_REDIS_URL`, workspace convention) to authorise redirect
    // domains and to observe the WAL side effects; they soft-skip without
    // it. Postgres is never contacted (the domain cache is seeded in Redis).

    mod handler {
        use super::*;
        use crate::processor::REDIS_WAL_KEY;
        use crate::routes::{build_router, test_support};
        use std::time::Duration;

        const NORMAL_UA: &str = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/124.0.0.0 Safari/537.36";
        const PREFETCHER_UA: &str = "Mozilla/5.0 (compatible; LinkPreviewer/prefetch)";

        fn click_token(tenant: &str, message_id: &str) -> String {
            TrackingCodec::new(test_support::TEST_SECRET)
                .encode(&TrackingData {
                    tenant_id: tenant.into(),
                    message_id: message_id.into(),
                    recipient: "user@example.com".into(),
                    link_id: Some(format!("lnk_{message_id}")),
                    original_url: None,
                })
                .expect("encode token")
        }

        async fn click_server(state: &AppState) -> axum_test::TestServer {
            axum_test::TestServer::new(
                build_router(state.clone()).into_make_service_with_connect_info::<SocketAddr>(),
            )
            .expect("test server")
        }

        async fn seed_domain(
            pool: &deadpool_redis::Pool,
            tenant: &str,
            domain: &str,
            allowed: bool,
        ) {
            let mut conn = pool.get().await.expect("redis conn");
            redis::cmd("SETEX")
                .arg(format!("redirect_domain:{tenant}:{domain}"))
                .arg(300u64)
                .arg(if allowed { "1" } else { "0" })
                .query_async::<()>(&mut *conn)
                .await
                .expect("seed domain cache entry");
        }

        async fn wal_entries_for(pool: &deadpool_redis::Pool, needle: &str) -> Vec<String> {
            let Ok(mut conn) = pool.get().await else {
                return Vec::new();
            };
            redis::cmd("LRANGE")
                .arg(REDIS_WAL_KEY)
                .arg(0)
                .arg(-1)
                .query_async::<Vec<String>>(&mut *conn)
                .await
                .unwrap_or_default()
                .into_iter()
                .filter(|entry| entry.contains(needle))
                .collect()
        }

        /// Give the fire-and-forget recorder time to (wrongly) enqueue.
        async fn settle() {
            tokio::time::sleep(Duration::from_millis(400)).await;
        }

        async fn cleanup(pool: &deadpool_redis::Pool, tenant: &str, message_id: &str) {
            let Ok(mut conn) = pool.get().await else {
                return;
            };
            for entry in wal_entries_for(pool, message_id).await {
                let _: Result<(), _> = redis::cmd("LREM")
                    .arg(REDIS_WAL_KEY)
                    .arg(1)
                    .arg(&entry)
                    .query_async(&mut *conn)
                    .await;
            }
            let _: Result<(), _> = redis::cmd("DEL")
                .arg(format!("links:{tenant}:{message_id}"))
                .query_async(&mut *conn)
                .await;
        }

        /// Query-extractor path: the link rewriter percent-encodes the
        /// original URL exactly once (`%` → `%25`, `+` → `%2B`), and axum's
        /// `Query` extractor decodes it exactly once. `%2F` and `+` in the
        /// original URL must therefore survive verbatim in the redirect.
        /// (`add_query_param` performs the same serde_urlencoded form
        /// encoding the real producer uses, so the request drives the
        /// genuine extractor path.)
        #[tokio::test]
        async fn click_r_param_not_decoded_twice_percent_and_plus_survive() {
            let Some((state, redis)) = test_support::live_redis_state(&[]).await else {
                eprintln!("skipping: set TEST_REDIS_URL to run handler test");
                return;
            };
            let tenant = test_support::unique_tenant("dbldecode");
            let message_id = format!("msg_{tenant}");
            seed_domain(&redis, &tenant, "allowed.example.test", true).await;

            let token = click_token(&tenant, &message_id);
            let server = click_server(&state).await;
            let response = server
                .get(&format!("/c/{token}"))
                .add_query_param("r", "https://allowed.example.test/promo%2Fsale+event")
                .add_header(
                    axum::http::HeaderName::from_static("user-agent"),
                    NORMAL_UA.parse().expect("ua"),
                )
                .await;

            assert_eq!(response.status_code().as_u16(), 302);
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert_eq!(
                location, "https://allowed.example.test/promo%2Fsale+event",
                "the extractor-decoded value must be used verbatim (no second decode)"
            );

            // The recorder is fire-and-forget; settle before cleanup so the
            // eventual WAL entry is actually removed.
            settle().await;
            cleanup(&redis, &tenant, &message_id).await;
        }

        /// E-190 parity with pixel.rs: a known prefetcher UA still gets its
        /// click-through (302 to the original URL) but records NOTHING.
        #[tokio::test]
        async fn click_from_prefetcher_bot_records_nothing_but_still_redirects() {
            let Some((state, redis)) = test_support::live_redis_state(&[]).await else {
                eprintln!("skipping: set TEST_REDIS_URL to run handler test");
                return;
            };
            let tenant = test_support::unique_tenant("botclick");
            let message_id = format!("msg_{tenant}");
            seed_domain(&redis, &tenant, "allowed.example.test", true).await;

            let token = click_token(&tenant, &message_id);
            let server = click_server(&state).await;
            let response = server
                .get(&format!("/c/{token}"))
                .add_query_param("r", "https://allowed.example.test/landing")
                .add_header(
                    axum::http::HeaderName::from_static("user-agent"),
                    PREFETCHER_UA.parse().expect("ua"),
                )
                .await;

            assert_eq!(response.status_code().as_u16(), 302);
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert_eq!(location, "https://allowed.example.test/landing");

            settle().await;
            let recorded = wal_entries_for(&redis, &message_id).await;
            assert!(
                recorded.is_empty(),
                "bot click must not be recorded, got: {recorded:?}"
            );

            cleanup(&redis, &tenant, &message_id).await;
        }

        /// Normal UA on an authorised domain → the click IS recorded.
        #[tokio::test]
        async fn click_from_normal_user_is_recorded() {
            let Some((state, redis)) = test_support::live_redis_state(&[]).await else {
                eprintln!("skipping: set TEST_REDIS_URL to run handler test");
                return;
            };
            let tenant = test_support::unique_tenant("human");
            let message_id = format!("msg_{tenant}");
            seed_domain(&redis, &tenant, "allowed.example.test", true).await;

            let token = click_token(&tenant, &message_id);
            let server = click_server(&state).await;
            let response = server
                .get(&format!("/c/{token}"))
                .add_query_param("r", "https://allowed.example.test/landing")
                .add_header(
                    axum::http::HeaderName::from_static("user-agent"),
                    NORMAL_UA.parse().expect("ua"),
                )
                .await;
            assert_eq!(response.status_code().as_u16(), 302);

            settle().await;
            let recorded = wal_entries_for(&redis, &message_id).await;
            assert_eq!(
                recorded.len(),
                1,
                "normal-UA click must be recorded exactly once, got: {recorded:?}"
            );

            cleanup(&redis, &tenant, &message_id).await;
        }

        /// A blocked redirect domain must NOT produce a click row/event on
        /// the fallback URL — the user is redirected, the analytics are not
        /// poisoned.
        #[tokio::test]
        async fn click_on_blocked_domain_records_nothing_and_falls_back() {
            let Some((state, redis)) = test_support::live_redis_state(&[]).await else {
                eprintln!("skipping: set TEST_REDIS_URL to run handler test");
                return;
            };
            let tenant = test_support::unique_tenant("blocked");
            let message_id = format!("msg_{tenant}");
            seed_domain(&redis, &tenant, "evil.example.test", false).await;

            let token = click_token(&tenant, &message_id);
            let server = click_server(&state).await;
            let response = server
                .get(&format!("/c/{token}"))
                .add_query_param("r", "https://evil.example.test/phish")
                .add_header(
                    axum::http::HeaderName::from_static("user-agent"),
                    NORMAL_UA.parse().expect("ua"),
                )
                .await;

            assert_eq!(response.status_code().as_u16(), 302);
            let location = response
                .headers()
                .get("location")
                .and_then(|v| v.to_str().ok())
                .unwrap_or_default();
            assert_eq!(location, "https://fallback.test.example/");

            settle().await;
            let recorded = wal_entries_for(&redis, &message_id).await;
            assert!(
                recorded.is_empty(),
                "blocked-domain click must not be recorded, got: {recorded:?}"
            );

            // The per-link URL cache must not record the blocked link either.
            let mut conn = redis.get().await.expect("redis conn");
            let cached_link: Option<String> = redis::cmd("HGET")
                .arg(format!("links:{tenant}:{message_id}"))
                .arg(format!("lnk_{message_id}"))
                .query_async(&mut *conn)
                .await
                .expect("hget links cache");
            assert_eq!(
                cached_link, None,
                "blocked-domain link must not land in the links cache"
            );

            cleanup(&redis, &tenant, &message_id).await;
        }

        /// Allowed domain → recorded with the ORIGINAL url (not the fallback
        /// and not a re-decoded variant).
        #[tokio::test]
        async fn click_on_allowed_domain_records_original_url() {
            let Some((state, redis)) = test_support::live_redis_state(&[]).await else {
                eprintln!("skipping: set TEST_REDIS_URL to run handler test");
                return;
            };
            let tenant = test_support::unique_tenant("allowed");
            let message_id = format!("msg_{tenant}");
            seed_domain(&redis, &tenant, "allowed.example.test", true).await;

            let token = click_token(&tenant, &message_id);
            let server = click_server(&state).await;
            let response = server
                .get(&format!("/c/{token}"))
                .add_query_param("r", "https://allowed.example.test/promo%2Fsale+event")
                .add_header(
                    axum::http::HeaderName::from_static("user-agent"),
                    NORMAL_UA.parse().expect("ua"),
                )
                .await;
            assert_eq!(response.status_code().as_u16(), 302);

            settle().await;
            let recorded = wal_entries_for(&redis, &message_id).await;
            assert_eq!(recorded.len(), 1, "got: {recorded:?}");
            assert!(
                recorded[0]
                    .contains("\"linkUrl\":\"https://allowed.example.test/promo%2Fsale+event\""),
                "click must be recorded with the ORIGINAL url, got: {}",
                recorded[0]
            );

            cleanup(&redis, &tenant, &message_id).await;
        }
    }
}
