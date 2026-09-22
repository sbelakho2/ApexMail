//! Adversarial tests for the SSE stream endpoint (routes/sse.rs).
//!
//! Drives the real handler and the real pub/sub-backed event stream:
//! - token validation refuses hostile/expired/wrong-scope/wrong-algorithm
//!   JWTs,
//! - the per-tenant connection cap holds in both the Redis and the local
//!   fallback counter, and the rejected probe is rolled back,
//! - the stream cannot skip or spoof frames: the `connected` frame is always
//!   first, only events passing BOTH the type and the message_id filter are
//!   delivered, and non-JSON payloads are forwarded verbatim,
//! - the connection slot is released exactly once on every exit path.
//!
//! Redis comes from `TEST_REDIS_URL` (logical database 9, dedicated to this
//! suite so pub/sub traffic and conn-count keys never touch other suites);
//! tests that need no broker use a dead port. Everything soft-skips when
//! `TEST_REDIS_URL` is unset.

use super::*;
use std::time::Duration;

use crate::bot::BotDetector;
use crate::codec::TrackingCodec;
use crate::config::{
    ClickHouseConfig, Config, DatabaseConfig, MetricsConfig, RateLimitConfig, RedisConfig,
    ServerConfig, TrackingConfig,
};
use crate::processor::EventProcessor;
use crate::state::AppState;

const SECRET: &str = "sse-adversarial-secret-32-bytes-min!";
const PRIVATE_PEM: &str = include_str!("../../../../tests/fixtures/sse_test_key.pem");
const PUBLIC_PEM: &str = include_str!("../../../../tests/fixtures/sse_test_pub.pem");

/// This suite's dedicated Redis logical database (raw pub/sub + conn keys).
const REDIS_DB: u8 = 9;
const DEAD_REDIS_URL: &str = "redis://127.0.0.1:1";

fn redis_url_in_db(base: &str, db: u8) -> String {
    match url::Url::parse(base) {
        Ok(mut parsed) => {
            parsed.set_path(&db.to_string());
            parsed.to_string()
        }
        Err(_) => format!("{}/{}", base.trim_end_matches('/'), db),
    }
}

fn live_redis_url() -> Option<String> {
    Some(redis_url_in_db(
        &std::env::var("TEST_REDIS_URL").ok()?,
        REDIS_DB,
    ))
}

fn live_pool() -> Option<deadpool_redis::Pool> {
    let url = live_redis_url()?;
    deadpool_redis::Config::from_url(&url)
        .builder()
        .ok()?
        .max_size(4)
        .runtime(deadpool_redis::Runtime::Tokio1)
        .build()
        .ok()
}

fn dead_pool() -> deadpool_redis::Pool {
    deadpool_redis::Config::from_url(DEAD_REDIS_URL)
        .builder()
        .expect("dead redis builder")
        .max_size(1)
        .runtime(deadpool_redis::Runtime::Tokio1)
        .build()
        .expect("dead redis pool")
}

fn config(redis_url: &str, jwt_public_key_pem: &str) -> Config {
    Config {
        server: ServerConfig {
            addr: "127.0.0.1:0".parse().expect("addr"),
        },
        database: DatabaseConfig {
            url: "postgresql://offline@127.0.0.1:1/offline".into(),
            max_connections: 1,
        },
        redis: RedisConfig {
            url: redis_url.to_string(),
            key_prefix: "tracking:".into(),
            pool_size: 4,
        },
        clickhouse: ClickHouseConfig {
            url: "http://127.0.0.1:1".into(),
            database: "apexmail".into(),
            user: "default".into(),
            password: String::new(),
            insert_timeout_seconds: 1,
        },
        tracking: TrackingConfig {
            base_url: "https://track.test.example".into(),
            pixel_path: "/o".into(),
            click_path: "/c".into(),
            unsubscribe_path: "/u".into(),
            preferences_path: "/p".into(),
            fallback_url: "https://fallback.test.example/".into(),
            confirmation_url: "https://fallback.test.example/unsubscribed".into(),
            redirect_status: 302,
            trusted_proxies: Vec::new(),
            max_redirect_url_len: 2048,
        },
        rate_limit: RateLimitConfig {
            enabled: false,
            max_per_minute: 1000,
        },
        metrics: MetricsConfig {
            enabled: false,
            port: 9092,
        },
        secret_key: zeroize::Zeroizing::new(SECRET.into()),
        jwt_public_key_pem: jwt_public_key_pem.to_string(),
    }
}

fn state_with_url(redis: deadpool_redis::Pool, redis_url: &str, pem: &str) -> AppState {
    let cfg = config(redis_url, pem);
    let db = sqlx::postgres::PgPoolOptions::new()
        .max_connections(1)
        .connect_lazy("postgresql://offline@127.0.0.1:1/offline")
        .expect("lazy pool");
    let processor = std::sync::Arc::new(EventProcessor::new(
        db.clone(),
        redis.clone(),
        clickhouse::Client::default(),
        Duration::from_millis(100),
    ));
    AppState::new(
        TrackingCodec::new(SECRET),
        db,
        redis,
        processor,
        BotDetector::new(),
        cfg,
    )
}

fn bearer_state(pem: &str) -> AppState {
    state_with_url(dead_pool(), DEAD_REDIS_URL, pem)
}

fn sse_token(tenant: &str, scopes: &[&str], exp_offset_secs: i64) -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let claims = serde_json::json!({
        "tenant_id": tenant,
        "sub": "user-1",
        "scopes": scopes,
        "exp": jsonwebtoken::get_current_timestamp() as i64 + exp_offset_secs,
    });
    encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(PRIVATE_PEM.as_bytes()).expect("test private key"),
    )
    .expect("sign token")
}

fn hs256_token() -> String {
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let claims = serde_json::json!({
        "tenant_id": "t",
        "sub": "user-1",
        "scopes": ["stream"],
        "exp": jsonwebtoken::get_current_timestamp() as i64 + 600,
    });
    encode(
        &Header::new(Algorithm::HS256),
        &claims,
        &EncodingKey::from_secret(b"attacker-controlled-key"),
    )
    .expect("hs256 token")
}

fn authed(value: &str) -> HeaderMap {
    let mut headers = HeaderMap::new();
    headers.insert(
        axum::http::header::AUTHORIZATION,
        value.parse().expect("header value"),
    );
    headers
}

fn no_query() -> Query<StreamQuery> {
    Query(StreamQuery {
        events: None,
        message_id: None,
    })
}

async fn redis_int(pool: &deadpool_redis::Pool, cmd: &str, key: &str) -> i64 {
    let Ok(mut conn) = pool.get().await else {
        return -1;
    };
    redis::cmd(cmd)
        .arg(key)
        .query_async::<i64>(&mut *conn)
        .await
        .unwrap_or(-1)
}

async fn redis_del(pool: &deadpool_redis::Pool, key: &str) {
    if let Ok(mut conn) = pool.get().await {
        let _: Result<(), _> = redis::cmd("DEL").arg(key).query_async(&mut *conn).await;
    }
}

async fn publish(pool: &deadpool_redis::Pool, channel: &str, payload: &str) {
    let mut conn = pool.get().await.expect("publisher conn");
    redis::cmd("PUBLISH")
        .arg(channel)
        .arg(payload)
        .query_async::<i64>(&mut *conn)
        .await
        .expect("publish");
}

async fn wait_slot_released(pool: &deadpool_redis::Pool, key: &str) {
    for _ in 0..100 {
        if redis_int(pool, "GET", key).await <= 0 {
            return;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}

fn unique_tenant(label: &str) -> String {
    let hex = uuid::Uuid::new_v4().simple().to_string();
    format!("sse_{label}_{}", &hex[..10])
}

// ── Token validation (SEC-119) ──────────────────────────────────────────────

#[tokio::test]
async fn stream_rejects_missing_garbage_and_wrong_algorithm_tokens() {
    let state = bearer_state(PUBLIC_PEM);

    // No Authorization header at all.
    let resp = handle_stream(State(state.clone()), HeaderMap::new(), no_query()).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Wrong scheme.
    let resp = handle_stream(
        State(state.clone()),
        authed("Basic dXNlcjpwYXNz"),
        no_query(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Bearer with an unparseable token.
    let resp = handle_stream(State(state.clone()), authed("Bearer not.a.jwt"), no_query()).await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);

    // Algorithm confusion: an HS256 token signed with an attacker-chosen key
    // must be refused (RS256 only, SEC-119).
    let resp = handle_stream(
        State(state.clone()),
        authed(&format!("Bearer {}", hs256_token())),
        no_query(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
}

#[tokio::test]
async fn stream_token_validation_arm_coverage() {
    // Broken PEM in config → configuration error before any verification.
    let state = bearer_state("not a pem");
    let err = validate_stream_token(&sse_token("t", &["stream"], 600), &state).unwrap_err();
    assert!(
        err.contains("Invalid JWT public key configuration"),
        "{err}"
    );

    // Expired token (exp validation is on).
    let state = bearer_state(PUBLIC_PEM);
    let err = validate_stream_token(&sse_token("t", &["stream"], -1_000), &state).unwrap_err();
    assert!(err.contains("Invalid stream token"), "{err}");

    // Missing the stream scope.
    let err = validate_stream_token(&sse_token("t", &["read"], 600), &state).unwrap_err();
    assert!(err.contains("missing 'stream' scope"), "{err}");

    // Empty tenant refused even with the right scope.
    let err = validate_stream_token(&sse_token("", &["stream"], 600), &state).unwrap_err();
    assert!(err.contains("missing tenant_id"), "{err}");

    // The wildcard scope grants streaming; so does an explicit stream scope.
    let claims = validate_stream_token(&sse_token("t", &["*"], 600), &state).expect("valid");
    assert_eq!(claims.tenant_id, "t");
    let claims =
        validate_stream_token(&sse_token("t", &["read", "stream"], 600), &state).expect("valid");
    assert_eq!(claims.sub, "user-1");
}

// ── Per-tenant connection cap ───────────────────────────────────────────────

#[tokio::test]
async fn per_tenant_connection_cap_holds_in_redis_and_releases_on_drop() {
    let Some(pool) = live_pool() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let url = live_redis_url().expect("url");
    let tenant = unique_tenant("cap");
    let key = format!("sse:conns:{tenant}");
    redis_del(&pool, &key).await;

    let state = state_with_url(pool.clone(), &url, PUBLIC_PEM);
    let token = sse_token(&tenant, &["stream"], 600);

    let mut bodies = Vec::new();
    // MAX_CONNS_PER_TENANT live connections are admitted…
    for i in 0..MAX_CONNS_PER_TENANT {
        let resp = handle_stream(
            State(state.clone()),
            authed(&format!("Bearer {token}")),
            no_query(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "connection {i}");
        assert_eq!(
            redis_int(&pool, "GET", &key).await,
            i as i64 + 1,
            "each admitted stream holds exactly one slot"
        );
        bodies.push(resp);
    }
    // …one past the cap is refused with 429 and its probe is rolled back.
    let resp = handle_stream(
        State(state.clone()),
        authed(&format!("Bearer {token}")),
        no_query(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);
    assert_eq!(
        redis_int(&pool, "GET", &key).await,
        MAX_CONNS_PER_TENANT as i64,
        "the rejected probe must be decremented back"
    );

    // Dropping the response bodies releases every slot exactly once (the
    // RAII guard fires through the spawned decrement).
    drop(bodies);
    drop(state);
    wait_slot_released(&pool, &key).await;
    assert_eq!(
        redis_int(&pool, "GET", &key).await,
        0,
        "guard drop must release every Redis slot"
    );
    redis_del(&pool, &key).await;
}

#[tokio::test]
async fn local_fallback_cap_returns_429_when_redis_is_down() {
    // Dead Redis → the in-process counter is the cap of last resort: the
    // outage must not remove the cap (bounded fail-over, never fail-open).
    let state = bearer_state(PUBLIC_PEM);
    let tenant = unique_tenant("localcap");
    let token = sse_token(&tenant, &["stream"], 600);

    let mut held = Vec::new();
    for i in 0..MAX_CONNS_PER_TENANT {
        let resp = handle_stream(
            State(state.clone()),
            authed(&format!("Bearer {token}")),
            no_query(),
        )
        .await;
        assert_eq!(resp.status(), StatusCode::OK, "local connection {i}");
        held.push(resp);
    }
    let resp = handle_stream(
        State(state.clone()),
        authed(&format!("Bearer {token}")),
        no_query(),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::TOO_MANY_REQUESTS);

    drop(held);
    // The local counter drains on drop of each stream body.
    for _ in 0..100 {
        let drained = {
            let counts = LOCAL_CONN_COUNTS
                .lock()
                .unwrap_or_else(|poisoned| poisoned.into_inner());
            !counts.contains_key(&tenant)
        };
        if drained {
            break;
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    }
    assert!(
        !LOCAL_CONN_COUNTS
            .lock()
            .unwrap_or_else(|poisoned| poisoned.into_inner())
            .contains_key(&tenant),
        "local slot must be released after the streams drop"
    );
}

// ── Stream content: filters, forwarding, ordering ───────────────────────────

#[tokio::test]
async fn stream_delivers_connected_then_applies_both_filters_exactly() {
    let Some(pool) = live_pool() else {
        eprintln!("skipping: set TEST_REDIS_URL");
        return;
    };
    let url = live_redis_url().expect("url");
    let tenant = unique_tenant("filters");
    let channel = format!("events:{tenant}");
    let key = format!("sse:conns:{tenant}");
    redis_del(&pool, &key).await;

    let state = state_with_url(pool.clone(), &url, PUBLIC_PEM);
    let token = sse_token(&tenant, &["stream"], 600);

    // events=opened AND message_id=msg_ok — both filters must hold. The
    // filter string also proves trimming and empty-segment handling.
    let resp = handle_stream(
        State(state.clone()),
        authed(&format!("Bearer {token}")),
        Query(StreamQuery {
            events: Some("OPENED, ,".into()),
            message_id: Some("msg_ok".into()),
        }),
    )
    .await;
    assert_eq!(resp.status(), StatusCode::OK);
    let content_type = resp
        .headers()
        .get("content-type")
        .and_then(|v| v.to_str().ok())
        .unwrap_or_default()
        .to_string();
    assert!(
        content_type.starts_with("text/event-stream"),
        "{content_type}"
    );

    // The stream generator is lazily polled: drive the body from a spawned
    // reader task (as the HTTP server does) so the pub/sub subscription
    // completes and frames keep flowing while the test waits.
    let (tx, mut rx) = tokio::sync::mpsc::unbounded_channel::<String>();
    let reader = tokio::spawn(async move {
        let mut body = resp.into_body().into_data_stream();
        while let Ok(Some(Ok(bytes))) =
            tokio::time::timeout(Duration::from_millis(2_000), body.next()).await
        {
            let s = String::from_utf8_lossy(&bytes).into_owned();
            if !s.trim().is_empty() && tx.send(s).is_err() {
                break;
            }
        }
    });

    // Frame 1 is always `connected` — nothing can be delivered before the
    // subscription handshake frame.
    let connected = tokio::time::timeout(Duration::from_millis(1_000), rx.recv())
        .await
        .expect("connected frame")
        .expect("stream open");
    assert!(connected.contains("event: connected"), "{connected}");
    assert!(connected.contains(&tenant), "{connected}");
    assert!(connected.contains("msg_ok"), "{connected}");

    // Deterministic handshake: wait until the broker reports a live
    // subscriber for the channel (publishes before this are lost).
    let mut subscribed = false;
    for _ in 0..100 {
        let (_, count): (String, i64) = {
            let mut conn = pool.get().await.expect("conn");
            redis::cmd("PUBSUB")
                .arg("NUMSUB")
                .arg(&channel)
                .query_async(&mut *conn)
                .await
                .expect("numsub")
        };
        if count >= 1 {
            subscribed = true;
            break;
        }
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
    assert!(subscribed, "the stream must subscribe before delivering");

    // (1) wrong type → filtered out.
    publish(
        &pool,
        &channel,
        r#"{"type":"clicked","messageId":"msg_ok"}"#,
    )
    .await;
    // (2) right type, wrong message → filtered out.
    publish(
        &pool,
        &channel,
        r#"{"type":"opened","messageId":"msg_other"}"#,
    )
    .await;
    // (3) both match → delivered under the event's type name.
    publish(
        &pool,
        &channel,
        r#"{"type":"opened","messageId":"msg_ok","recipient":"r@example.com"}"#,
    )
    .await;
    // (4) non-JSON payload → forwarded verbatim as a generic `event`
    //     (filters can only apply to parseable payloads).
    publish(&pool, &channel, "raw-broker-noise-not-json").await;

    let mut got_open = None;
    let mut got_raw = None;
    for _ in 0..100 {
        let Some(frame) = tokio::time::timeout(Duration::from_millis(250), rx.recv())
            .await
            .ok()
            .flatten()
        else {
            break;
        };
        if got_open.is_none() && frame.contains("event: opened") && frame.contains("msg_ok") {
            got_open = Some(frame);
        } else if got_raw.is_none() && frame.contains("raw-broker-noise-not-json") {
            got_raw = Some(frame);
        }
        if got_open.is_some() && got_raw.is_some() {
            break;
        }
    }
    let opened = got_open.expect("the matching event must be delivered");
    assert!(opened.contains("r@example.com"), "{opened}");
    let raw = got_raw.expect("the non-JSON payload must be forwarded verbatim");
    assert!(raw.contains("event: event"), "{raw}");

    // Stop the reader; dropping the body releases the connection slot.
    reader.abort();
    drop(state);
    wait_slot_released(&pool, &key).await;
    assert_eq!(
        redis_int(&pool, "GET", &key).await,
        0,
        "slot released exactly once after the stream ends"
    );
    redis_del(&pool, &key).await;
}
