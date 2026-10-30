//! The Stripe adapter's conformance proof (external audit item 15): the
//! SAME eighteen-arm matrix + mutation teeth the MollieProvider passes,
//! driven through a REAL [`StripeProvider`] against a loopback Stripe wire
//! stub (the coverage_adversarial Mollie pattern, copied — the file is
//! deliberately NOT edited).
//!
//! The stub serves the exact endpoints the adapter's wire map names
//! (`checkout/sessions`, `payment_intents` create/fetch/search/list,
//! `refunds`, `payment_methods/{id}/detach`, `payouts`), scripted per arm
//! through the harness's [`ConformanceScripting`] hook, and reproduces each
//! DEFECT's wire behavior (HideTimeout, FetchLiesAboutState,
//! FetchReportsWrongCurrency, RefundIdCollision, SettlementAmountWrong,
//! DisputeStateLies) so the teeth are proven at the WIRE level, not only
//! against the scriptable double.
//!
//! The file also carries the unit gates for the webhook module
//! (`verify_signature`: valid / tampered / expired / wrong secret / missing
//! v1 / rotation; `normalize_event`: every mapped event type +
//! unknown-event acceptance), and the N-14 widening proof for the Mollie
//! search (five-page truncation-honest window).
//!
//! The wire stubs are process-wide singletons: run this suite under
//! cargo-nextest (one process per test), exactly like the
//! coverage_adversarial lane this pattern was copied from.

use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::time::Duration;

use billing_service::config::BillingConfig;
use billing_service::payments::conformance::{
    run_provider_conformance, ConformanceCtx, ConformanceScripting, Defect, MATRIX,
};
use billing_service::payments::mollie_provider::MollieProvider;
use billing_service::payments::stripe_events::{
    event_dedup_id, normalize_event, verify_signature, SIGNATURE_TOLERANCE_SECS,
};
use billing_service::payments::stripe_provider::StripeProvider;
use billing_service::payments::{
    CheckoutRequest, PaymentProvider, PaymentState, ProviderError, RefundRequest, RefundState,
    SavedMethodCharge,
};
use billing_service::AppState;
use chrono::Utc;
use deadpool_redis::Runtime;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use sqlx::postgres::PgPoolOptions;
use sqlx::PgPool;

// ---------------------------------------------------------------------------
// Provisioning harness (the workspace convention, as in coverage_adversarial)
// ---------------------------------------------------------------------------

fn ensure_trace_sink() {
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    if INSTALLED.set(()).is_ok() {
        let subscriber = tracing_subscriber::fmt()
            .with_max_level(tracing::Level::TRACE)
            .with_writer(std::io::sink)
            .finish();
        let _ = tracing::subscriber::set_global_default(subscriber);
    }
}

const MAX_DB_NAME_LEN: usize = 63;

fn assert_soft_skip_allowed(env_var: &str) {
    if std::env::var(env_var)
        .map(|value| !value.trim().is_empty())
        .unwrap_or(false)
    {
        return;
    }
    if std::env::var("APEXMAIL_RELEASE_TEST_MODE").as_deref() == Ok("1") {
        panic!(
            "APEXMAIL_RELEASE_TEST_MODE: required variable {env_var} is missing, \
             release CI must not skip infrastructure tests"
        );
    }
}

fn test_database_url() -> Option<String> {
    assert_soft_skip_allowed("TEST_DATABASE_URL");
    std::env::var("TEST_DATABASE_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
}

fn admin_database_url(server_part: &str) -> String {
    std::env::var("TEST_DATABASE_ADMIN_URL")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| format!("{server_part}/postgres"))
}

fn canonical_chain_shape() -> (usize, i64) {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../migrations");
    let mut count = 0_usize;
    let mut newest = 0_i64;
    for entry in std::fs::read_dir(&dir).expect("read migrations dir") {
        let name = entry.expect("migrations dir entry").file_name();
        let name = name.to_string_lossy().to_string();
        if let Some(prefix) = name.split('_').next() {
            if let Ok(version) = prefix.parse::<i64>() {
                count += 1;
                newest = newest.max(version);
            }
        }
    }
    (count, newest)
}

struct Harness {
    state: Arc<AppState>,
    pool: PgPool,
    db_name: String,
    admin_url: String,
}

impl Harness {
    async fn finish(self) {
        self.pool.close().await;
        if let Ok(admin) = PgPoolOptions::new()
            .max_connections(1)
            .connect(&self.admin_url)
            .await
        {
            let _ = sqlx::query(&format!(
                r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
                self.db_name
            ))
            .execute(&admin)
            .await;
            admin.close().await;
        }
    }
}

async fn provision(test_name: &str) -> Option<Harness> {
    ensure_trace_sink();
    let url = test_database_url()?;
    let (server_part, db_part) = url
        .rsplit_once('/')
        .expect("TEST_DATABASE_URL has a database segment");
    let db_only = db_part.split('?').next().unwrap_or(db_part);
    let mut digest: u64 = 0xcbf2_9ce4_8422_2325;
    for byte in test_name.bytes() {
        digest ^= u64::from(byte);
        digest = digest.wrapping_mul(0x0000_0100_0000_01b3);
    }
    let db_name = format!("{db_only}_bstr_{:08x}", digest & 0xffff_ffff);
    assert!(
        db_name.len() <= MAX_DB_NAME_LEN,
        "test db name too long: {db_name}"
    );

    let admin_url = admin_database_url(server_part);
    let admin = PgPoolOptions::new()
        .max_connections(1)
        .acquire_timeout(Duration::from_secs(30))
        .connect(&admin_url)
        .await
        .unwrap_or_else(|error| panic!("connect admin {admin_url}: {error}"));

    let (count, newest) = canonical_chain_shape();
    let prefix = format!("apexmail_canonical_tpl_{count}_{newest}_");
    let template: Option<String> = sqlx::query_scalar(
        "SELECT datname FROM pg_database WHERE datname LIKE $1 ORDER BY datname DESC LIMIT 1",
    )
    .bind(format!("{prefix}%"))
    .fetch_optional(&admin)
    .await
    .expect("list canonical templates");
    let template = template.unwrap_or_else(|| {
        panic!(
            "no canonical template for chain ({count} migrations, newest {newest}); \
             provision by running a DB-backed test in a crate that uses migrator::test_support"
        )
    });

    sqlx::query(&format!(
        r#"DROP DATABASE IF EXISTS "{}" WITH (FORCE)"#,
        db_name
    ))
    .execute(&admin)
    .await
    .unwrap_or_else(|error| panic!("drop {db_name}: {error}"));
    sqlx::query(&format!(
        r#"CREATE DATABASE "{}" TEMPLATE "{}""#,
        db_name, template
    ))
    .execute(&admin)
    .await
    .unwrap_or_else(|error| panic!("clone {db_name} from {template}: {error}"));
    admin.close().await;

    let pool = PgPoolOptions::new()
        .max_connections(4)
        .acquire_timeout(Duration::from_secs(10))
        .connect(&format!("{server_part}/{db_name}"))
        .await
        .unwrap_or_else(|error| panic!("connect {db_name}: {error}"));

    let redis_url = std::env::var("TEST_REDIS_URL")
        .ok()
        .filter(|value| !value.trim().is_empty())
        .expect("TEST_REDIS_URL must be set for the Stripe conformance lane");
    let redis = deadpool_redis::Config::from_url(redis_url)
        .create_pool(Some(Runtime::Tokio1))
        .expect("create redis pool");

    let config = BillingConfig {
        database_url: format!("{server_part}/{db_name}"),
        redis_url: "redis://127.0.0.1:6379".to_string(),
        service_auth_token: "stripe-conformance-token".to_string(),
        mollie_api_key: "test_mock_api_key".to_string(),
        api_base_url: "http://127.0.0.1:9".to_string(),
        ..BillingConfig::default()
    };
    let state = AppState::new(pool.clone(), redis.clone(), config);

    Some(Harness {
        state,
        pool,
        db_name,
        admin_url,
    })
}

/// Run `body` with a fresh DB/Redis environment, soft-skipping when
/// `TEST_DATABASE_URL` is unset.
macro_rules! db_test {
    ($name:ident, |$h:ident| $body:block) => {
        #[tokio::test]
        async fn $name() {
            let Some($h) = provision(stringify!($name)).await else {
                return;
            };
            $body
            $h.finish().await;
        }
    };
}

// ---------------------------------------------------------------------------
// The Stripe wire stub
// ---------------------------------------------------------------------------

/// Fixed UNIX-seconds timestamp stamped on every stub document (Stripe wire
/// timestamps are integers; any valid value serves).
const STUB_TS: i64 = 1761763200;

struct StripeStub {
    routes: Mutex<HashMap<String, (u16, String)>>,
    seq: AtomicU64,
    defect: Mutex<Option<Defect>>,
}

impl StripeStub {
    fn route(&self, key: &str, status: u16, body: impl Into<String>) {
        self.routes
            .lock()
            .expect("stub routes")
            .insert(key.to_string(), (status, body.into()));
    }

    fn current_defect(&self) -> Option<Defect> {
        *self.defect.lock().expect("stub defect")
    }

    fn seed_defect(&self, defect: Option<Defect>) {
        *self.defect.lock().expect("stub defect") = defect;
    }

    fn next_seq(&self) -> u64 {
        self.seq.fetch_add(1, Ordering::SeqCst)
    }
}

fn percent_decode(text: &str) -> String {
    let bytes = text.as_bytes();
    let mut output = Vec::with_capacity(bytes.len());
    let mut index = 0;
    while index < bytes.len() {
        if bytes[index] == b'%' && index + 2 < bytes.len() {
            let hi = (bytes[index + 1] as char).to_digit(16);
            let lo = (bytes[index + 2] as char).to_digit(16);
            if let (Some(hi), Some(lo)) = (hi, lo) {
                output.push((hi * 16 + lo) as u8);
                index += 3;
                continue;
            }
        }
        output.push(if bytes[index] == b'+' {
            b' '
        } else {
            bytes[index]
        });
        index += 1;
    }
    String::from_utf8_lossy(&output).into_owned()
}

fn form_fields(body: &[u8]) -> Vec<(String, String)> {
    String::from_utf8_lossy(body)
        .split('&')
        .filter_map(|pair| {
            let (key, value) = pair.split_once('=')?;
            Some((percent_decode(key), percent_decode(value)))
        })
        .collect()
}

fn field<'a>(fields: &'a [(String, String)], key: &str) -> Option<&'a str> {
    fields
        .iter()
        .find(|(name, _)| name == key)
        .map(|(_, value)| value.as_str())
}

fn json_response(status: u16, body: String) -> axum::response::Response {
    use axum::response::IntoResponse;
    (
        axum::http::StatusCode::from_u16(status).expect("status"),
        [(axum::http::header::CONTENT_TYPE, "application/json")],
        body,
    )
        .into_response()
}

async fn stripe_stub_handler(
    axum::extract::State(state): axum::extract::State<&'static StripeStub>,
    request: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let body_bytes = axum::body::to_bytes(request.into_body(), 256 * 1024)
        .await
        .unwrap_or_default();
    let n = state.next_seq();
    let error = |status: u16, message: &str| {
        json_response(
            status,
            serde_json::json!({
                "error": { "type": "invalid_request_error", "message": message }
            })
            .to_string(),
        )
    };

    // Checkout sessions: the PAYMENTS-ONLY contract tooth. The stub REFUSES
    // any session that is not mode=payment, so a subscription-mode adapter
    // cannot even pass its own wire test.
    if method == axum::http::Method::POST && path == "/v1/checkout/sessions" {
        let fields = form_fields(&body_bytes);
        if field(&fields, "mode") != Some("payment") {
            return error(
                400,
                "the conformance stub accepts mode=payment sessions only",
            );
        }
        let Some(success_url) = field(&fields, "success_url") else {
            return error(400, "success_url is required");
        };
        // The metadata contract mirrors the Mollie adapter: the
        // idempotency key MUST ride the session metadata (the stale-claim
        // search contract), not only the header.
        if !fields
            .iter()
            .any(|(key, _)| key == "metadata[idempotency_key]")
        {
            return error(
                400,
                "checkout sessions must carry metadata[idempotency_key] (the search contract)",
            );
        }
        // Item 9 wire tooth: every session metadata key must also ride the
        // PaymentIntent (`payment_intent_data[metadata][…]`). The activation
        // fetches the PaymentIntent, so an identity only on the Session is
        // invisible to the refetch-first webhook.
        for (key, _) in fields
            .iter()
            .filter(|(key, _)| key.starts_with("metadata["))
        {
            let mirrored = format!(
                "payment_intent_data[metadata][{}",
                key.trim_start_matches("metadata[")
            );
            if !fields.iter().any(|(name, _)| *name == mirrored) {
                return error(
                    400,
                    &format!("checkout metadata {key} is not mirrored onto the PaymentIntent"),
                );
            }
        }
        let session = serde_json::json!({
            "id": format!("cs_{n}"),
            "object": "checkout.session",
            "mode": field(&fields, "mode"),
            "status": "open",
            "payment_status": "unpaid",
            "url": format!("https://checkout.stripe.com/c/pay/cs_{n}"),
            "success_url": success_url,
            "client_reference_id": field(&fields, "client_reference_id"),
            "amount_total": field(&fields, "line_items[0][price_data][unit_amount]")
                .and_then(|amount| amount.parse::<i64>().ok())
                .unwrap_or(0),
            "currency": field(&fields, "line_items[0][price_data][currency]"),
            "created": STUB_TS,
        });
        return json_response(200, session.to_string());
    }

    // Refunds: a scripted "POST /v1/refunds" route wins (the currency-lie
    // test); otherwise echo the requested amount and mint a DISTINCT refund
    // id per call (the refunds ledger's unique key made shared ids a fixture
    // lie) — unless the RefundIdCollision defect is seeded, which is the
    // whole point of that tooth.
    if method == axum::http::Method::POST && path == "/v1/refunds" {
        let fields = form_fields(&body_bytes);
        // Stripe's create-refund API has NO currency parameter: sending one
        // can 400. The stub enforces the wire contract.
        if fields.iter().any(|(key, _)| key == "currency") {
            return error(
                400,
                "the Stripe refund API has no currency parameter; the wire request must not carry one",
            );
        }
        let scripted = {
            let routes = state.routes.lock().expect("stub routes");
            routes.get(&format!("{method} {path}")).cloned()
        };
        if let Some((status, body)) = scripted {
            return json_response(status, body.replace("{seq}", &n.to_string()));
        }
        let refund_id = if state.current_defect() == Some(Defect::RefundIdCollision) {
            "re_conf_collision".to_string()
        } else {
            format!("re_conf_{n}")
        };
        let refund = serde_json::json!({
            "id": refund_id,
            "object": "refund",
            "status": "pending",
            "payment_intent": field(&fields, "payment_intent"),
            "amount": field(&fields, "amount")
                .and_then(|amount| amount.parse::<i64>().ok())
                .unwrap_or(0),
            "currency": "eur",
            "created": STUB_TS,
        });
        return json_response(200, refund.to_string());
    }

    // Static routes: "METHOD /path" first (a charge POST and a listing GET
    // on one path answer differently), then the bare path.
    let method_key = format!("{method} {path}");
    let routed = {
        let routes = state.routes.lock().expect("stub routes");
        routes
            .get(&method_key)
            .or_else(|| routes.get(&path))
            .cloned()
    };
    if let Some((status, body)) = routed {
        let body = body.replace("{seq}", &n.to_string());
        return json_response(status, body);
    }
    error(404, &format!("Unrecognized request URL {method} {path}"))
}

/// The one process-wide Stripe stub (own OS thread, own runtime).
fn stripe_stub_api() -> (&'static StripeStub, String) {
    static STUB: std::sync::OnceLock<(&'static StripeStub, String)> = std::sync::OnceLock::new();
    STUB.get_or_init(|| {
        let state: &'static StripeStub = Box::leak(Box::new(StripeStub {
            routes: Mutex::new(HashMap::new()),
            seq: AtomicU64::new(0),
            defect: Mutex::new(None),
        }));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind stripe stub");
        listener
            .set_nonblocking(true)
            .expect("nonblocking stripe listener");
        let address = listener.local_addr().expect("stripe stub address");
        let app = axum::Router::new()
            .fallback(stripe_stub_handler)
            .with_state(state);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("stripe stub runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
                axum::serve(listener, app).await.expect("stripe stub");
            });
        });
        (state, format!("http://{address}/v1"))
    })
    .clone()
}

// ---------------------------------------------------------------------------
// Stub document builders (Stripe wire shapes)
// ---------------------------------------------------------------------------

fn intent_doc_json(id: &str, status: &str, amount_minor: i64, currency: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "object": "payment_intent",
        "status": status,
        "amount": amount_minor,
        "currency": currency,
        "created": STUB_TS,
    })
}

fn full_intent_list(count: usize, currency: &str) -> serde_json::Value {
    let items: Vec<serde_json::Value> = (0..count)
        .map(|index| {
            serde_json::json!({
                "id": format!("pi_conf9_{index}"),
                "object": "payment_intent",
                "status": "succeeded",
                "amount": 100,
                "currency": currency,
                "metadata": { "reference": "somebody-else" },
            })
        })
        .collect();
    serde_json::json!({
        "object": "list",
        "data": items,
        "has_more": true,
    })
}

fn dispute_intent_doc_json(
    intent_id: &str,
    dispute_id: &str,
    dispute_status: &str,
    amount_minor: i64,
    currency: &str,
) -> serde_json::Value {
    serde_json::json!({
        "id": intent_id,
        "object": "payment_intent",
        "status": "succeeded",
        "amount": amount_minor,
        "currency": currency,
        "created": STUB_TS,
        "latest_charge": {
            "id": "ch_conf",
            "object": "charge",
            "dispute": {
                "id": dispute_id,
                "object": "dispute",
                "status": dispute_status,
                "amount": amount_minor,
                "currency": currency,
                "reason": "fraudulent",
                "created": STUB_TS,
            },
        },
    })
}

fn payout_doc_json(id: &str, amount_minor: i64, currency: &str) -> serde_json::Value {
    serde_json::json!({
        "id": id,
        "object": "payout",
        "status": "paid",
        "amount": amount_minor,
        "currency": currency,
        "arrival_date": STUB_TS,
    })
}

fn stripe_error_body(message: &str) -> String {
    serde_json::json!({
        "error": { "type": "api_error", "message": message }
    })
    .to_string()
}

// ---------------------------------------------------------------------------
// The Stripe lane's scripting: route the stub exactly as the real provider
// would answer for each matrix arm (mirroring the Mollie lane)
// ---------------------------------------------------------------------------

struct StripeConformanceScripting {
    stub: &'static StripeStub,
}

impl ConformanceScripting for StripeConformanceScripting {
    fn arm_setup(&self, ctx: &ConformanceCtx<'_>) -> Result<(), String> {
        let defect = self.stub.current_defect();
        let amount = ctx.amount_minor;
        let currency = ctx.currency.to_ascii_lowercase();
        let intent_route = format!("GET /v1/payment_intents/{}", ctx.provider_payment_hint);
        match ctx.arm {
            5 => {
                // The charge is definitively refused: the confirmed intent
                // fell back to requires_payment_method (neutral Failed).
                self.stub.route(
                    "POST /v1/payment_intents",
                    200,
                    intent_doc_json("{seq}", "requires_payment_method", amount, &currency)
                        .to_string(),
                );
            }
            6 => {
                // The authenticated fetch answers with the paid intent —
                // unless FetchReportsWrongCurrency is seeded, in which case
                // the wire reports USD against a EUR invoice.
                let wire_currency = if defect == Some(Defect::FetchReportsWrongCurrency) {
                    "usd".to_string()
                } else {
                    currency.clone()
                };
                self.stub.route(
                    &intent_route,
                    200,
                    intent_doc_json(
                        ctx.provider_payment_hint,
                        "succeeded",
                        amount,
                        &wire_currency,
                    )
                    .to_string(),
                );
            }
            8 => {
                // The charge's response is LOST (503 maps to the neutral
                // Unavailable); the provider's own record shows it paid.
                // The method key overrides arm 5's POST route (routes
                // persist across arms of the shared stub). The HideTimeout
                // defect REPLACES the lost response with a success — the
                // wire-level reproduction of the defect.
                let (post_status, post_body) = if defect == Some(Defect::HideTimeout) {
                    (
                        200,
                        intent_doc_json("{seq}", "succeeded", amount, &currency).to_string(),
                    )
                } else {
                    (503, stripe_error_body("upstream down"))
                };
                self.stub
                    .route("POST /v1/payment_intents", post_status, post_body);
                self.stub.route(
                    &intent_route,
                    200,
                    intent_doc_json(ctx.provider_payment_hint, "succeeded", amount, &currency)
                        .to_string(),
                );
            }
            9 => {
                // The charge's response is LOST AND the keyed search API is
                // not enabled on the account (a 4xx feature refusal), so
                // the adapter falls back to the recent-list window — which
                // is FULL (100 intents, none carrying our metadata key):
                // absence cannot be proven, so the stale-claim reconcile
                // must park the attempt `unresolved`.
                self.stub.route(
                    "POST /v1/payment_intents",
                    503,
                    stripe_error_body("upstream down"),
                );
                self.stub.route(
                    "GET /v1/payment_intents/search",
                    400,
                    stripe_error_body("Search is not enabled on this account"),
                );
                self.stub.route(
                    "GET /v1/payment_intents",
                    200,
                    full_intent_list(100, &currency).to_string(),
                );
            }
            12 => {
                // POST /v1/refunds: the handler echoes the requested amount
                // and mints distinct ids (or collides them under the
                // RefundIdCollision defect).
            }
            13..=15 => {
                // The dispute the arm reconciles: opened / lost / won,
                // attached to the intent's EXPANDED latest_charge. The
                // per-run dispute id is keyed off the fresh invoice:
                // provider fact ids are provider-unique, so a reused id
                // would let the ledger's ON CONFLICT hide a later run's
                // fact. DisputeStateLies reports the lost dispute as won —
                // the wire-level reproduction.
                let dispute_status = match (ctx.arm, defect) {
                    (13, _) => "under_review",
                    (14, Some(Defect::DisputeStateLies)) => "won",
                    (14, _) => "lost",
                    _ => "won",
                };
                let dispute_id = format!("dp_conf_{}_{}", ctx.arm, ctx.invoice_id.simple());
                self.stub.route(
                    &intent_route,
                    200,
                    dispute_intent_doc_json(
                        ctx.provider_payment_hint,
                        &dispute_id,
                        dispute_status,
                        amount,
                        &currency,
                    )
                    .to_string(),
                );
            }
            16 => {
                // The charge SUCCEEDED at the provider; only the webhook
                // was missed. The repair sweep must find the fact via the
                // authenticated fetch. FetchLiesAboutState reports the
                // intent failed instead — the wire-level reproduction.
                let status = if defect == Some(Defect::FetchLiesAboutState) {
                    "requires_payment_method"
                } else {
                    "succeeded"
                };
                self.stub.route(
                    &intent_route,
                    200,
                    intent_doc_json(ctx.provider_payment_hint, status, amount, &currency)
                        .to_string(),
                );
            }
            17 => {
                // One PAID payout, whose id is per-RUN (keyed off the fresh
                // invoice) and whose amount is the harness's amount —
                // unless SettlementAmountWrong misreports the money, which
                // must fail the recorded-fact assertion.
                let payout_amount = if defect == Some(Defect::SettlementAmountWrong) {
                    amount + 1
                } else {
                    amount
                };
                let payout = payout_doc_json(
                    &format!("po_conf_{}", ctx.invoice_id.simple()),
                    payout_amount,
                    &currency,
                );
                self.stub.route(
                    "GET /v1/payouts",
                    200,
                    serde_json::json!({ "object": "list", "data": [payout] }).to_string(),
                );
            }
            _ => {}
        }
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// The matrix: the REAL StripeProvider passes the SAME 18 arms Mollie passes
// ---------------------------------------------------------------------------

db_test!(stripe_provider_passes_the_shared_conformance_matrix, |h| {
    let (stub, base_url) = stripe_stub_api();
    stub.seed_defect(None);
    let provider = StripeProvider::new("sk_test_conformance".to_string(), base_url, None)
        .expect("conformance provider");
    let scripting = StripeConformanceScripting { stub };
    let report = run_provider_conformance(&h.state, Arc::new(provider), &scripting).await;
    assert_eq!(report.provider, "stripe");
    assert_eq!(report.arms.len(), MATRIX.len(), "every arm ran");
    if let Err(failures) = report.assert_all_passed() {
        panic!("StripeProvider must pass the shared conformance matrix:\n{failures}");
    }
});

// Mutation teeth at the WIRE level: each defect's wire behavior is
// reproduced by the stub and must fail exactly its mapped arm.
db_test!(seeded_wire_defects_fail_their_mapped_arms, |h| {
    let (stub, base_url) = stripe_stub_api();
    let provider = Arc::new(
        StripeProvider::new("sk_test_conformance".to_string(), base_url, None)
            .expect("conformance provider"),
    );
    for defect in [
        Defect::HideTimeout,
        Defect::FetchLiesAboutState,
        Defect::FetchReportsWrongCurrency,
        Defect::RefundIdCollision,
        Defect::SettlementAmountWrong,
        Defect::DisputeStateLies,
    ] {
        stub.seed_defect(Some(defect));
        let scripting = StripeConformanceScripting { stub };
        let report = run_provider_conformance(&h.state, provider.clone(), &scripting).await;
        let mapped = report
            .arms
            .iter()
            .find(|arm| arm.arm == defect.breaks_arm())
            .expect("mapped arm ran");
        assert!(
            !mapped.passed,
            "wire defect {defect:?} must break arm {}: {}",
            defect.breaks_arm(),
            mapped.detail
        );
    }
    stub.seed_defect(None);
});

// ---------------------------------------------------------------------------
// Stripe adapter wire behavior (endpoint-level, no DB)
// ---------------------------------------------------------------------------

fn test_provider(base_url: &str) -> StripeProvider {
    StripeProvider::new("sk_test_wire".to_string(), base_url.to_string(), None)
        .expect("wire provider")
}

fn charge_request(amount_minor: i64, key: &str) -> SavedMethodCharge {
    SavedMethodCharge {
        provider_customer_id: "cus_conf_1".to_string(),
        provider_method_id: "pm_conf_1".to_string(),
        amount_minor,
        currency: "EUR".to_string(),
        description: "conformance charge".to_string(),
        metadata: serde_json::json!({
            "reference": "invoice:abc",
            "tenant_id": "t1",
        }),
        idempotency_key: key.to_string(),
    }
}

/// THE PAYMENTS-ONLY tooth: the stub refuses any checkout session that is
/// not mode=payment, and the session maps into the neutral Checkout shape
/// with the mirrored metadata contract.
#[tokio::test]
async fn checkout_sessions_are_payment_mode_with_the_metadata_contract() {
    let (_stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    let checkout = provider
        .create_checkout(CheckoutRequest {
            amount_minor: 1234,
            currency: "EUR".to_string(),
            description: "Growth plan".to_string(),
            redirect_url: Some("https://app.example/billing/return".to_string()),
            webhook_url: None,
            metadata: serde_json::json!({
                "reference": "invoice:abc-123",
                "tenant_id": "t1",
            }),
            method_hint: None,
            provider_customer_id: None,
            provider_method_id: None,
            save_method: true,
            idempotency_key: "checkout_key_1".to_string(),
        })
        .await
        .expect("mode=payment session must be accepted");
    assert_eq!(checkout.provider, "stripe");
    assert_eq!(checkout.state, PaymentState::Pending);
    assert!(
        checkout
            .redirect_url
            .as_deref()
            .is_some_and(|url| url.starts_with("https://checkout.stripe.com/c/pay/cs_")),
        "the session's hosted url maps into the neutral Checkout: {:?}",
        checkout.redirect_url
    );
    assert_eq!(checkout.amount_minor, 1234);
    assert_eq!(checkout.currency, "EUR");
}

/// A checkout without a redirect URL refuses (Stripe requires success_url;
/// the adapter must not invent one).
#[tokio::test]
async fn a_checkout_without_a_redirect_url_refuses() {
    let (_stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    match provider
        .create_checkout(CheckoutRequest {
            amount_minor: 1234,
            currency: "EUR".to_string(),
            description: "Growth plan".to_string(),
            redirect_url: None,
            webhook_url: None,
            metadata: serde_json::json!({}),
            method_hint: None,
            provider_customer_id: None,
            provider_method_id: None,
            save_method: false,
            idempotency_key: "checkout_key_2".to_string(),
        })
        .await
    {
        Err(ProviderError::Config(message)) => {
            assert!(message.contains("requires a success"), "{message}")
        }
        other => panic!("expected a Config refusal, got {other:?}"),
    }
}

/// The saved-method charge maps EVERY documented intent status onto the
/// neutral machine over the wire, echoes the amount, and an unknown status
/// fails closed.
#[tokio::test]
async fn charge_saved_method_maps_every_intent_status_over_the_wire() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    for (wire_status, expected) in [
        ("succeeded", PaymentState::Succeeded),
        ("processing", PaymentState::Processing),
        ("requires_action", PaymentState::RequiresAction),
        ("requires_payment_method", PaymentState::Failed),
        ("canceled", PaymentState::Canceled),
    ] {
        stub.route(
            "POST /v1/payment_intents",
            200,
            intent_doc_json("pi_wire", wire_status, 1130, "eur").to_string(),
        );
        let payment = provider
            .charge_saved_method(charge_request(1130, "charge_key_1"))
            .await
            .unwrap_or_else(|error| panic!("{wire_status} must map: {error:?}"));
        assert_eq!(payment.provider, "stripe");
        assert_eq!(payment.provider_payment_id, "pi_wire");
        assert_eq!(payment.state, expected, "{wire_status}");
        assert_eq!(payment.amount_minor, 1130);
        assert_eq!(payment.currency, "EUR");
    }
    // An unmapped status is a typed refusal, never a guessed money state.
    stub.route(
        "POST /v1/payment_intents",
        200,
        intent_doc_json("pi_wire", "requires_capture", 1130, "eur").to_string(),
    );
    match provider
        .charge_saved_method(charge_request(1130, "charge_key_2"))
        .await
    {
        Err(ProviderError::UnmappedStatus { kind, status }) => {
            assert_eq!(kind, "payment");
            assert_eq!(status, "requires_capture");
        }
        other => panic!("expected UnmappedStatus, got {other:?}"),
    }
}

/// Item 5: a Succeeded PaymentIntent missing an authoritative amount or
/// currency is NEVER filled in from the request. One authenticated refetch is
/// allowed; if the fetched object still lacks the money, it is Malformed.
#[tokio::test]
async fn a_charge_never_borrows_request_money() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    // The create echo is minimal (no amount); the authenticated refetch
    // carries the REAL money, which DIFFERS from the requested 1130.
    stub.route(
        "POST /v1/payment_intents",
        200,
        serde_json::json!({
            "id": "pi_minimal",
            "object": "payment_intent",
            "status": "succeeded",
            "currency": "eur",
        })
        .to_string(),
    );
    stub.route(
        "GET /v1/payment_intents/pi_minimal",
        200,
        intent_doc_json("pi_minimal", "succeeded", 990, "eur").to_string(),
    );
    let payment = provider
        .charge_saved_method(charge_request(1130, "charge_money_1"))
        .await
        .expect("one refetch is allowed");
    assert_eq!(
        payment.amount_minor, 990,
        "the fetched authoritative amount, never the requested 1130"
    );

    // A refetch that ALSO lacks the money is Malformed — not a request echo.
    stub.route(
        "POST /v1/payment_intents",
        200,
        serde_json::json!({
            "id": "pi_still_minimal",
            "object": "payment_intent",
            "status": "succeeded",
            "currency": "eur",
        })
        .to_string(),
    );
    stub.route(
        "GET /v1/payment_intents/pi_still_minimal",
        200,
        serde_json::json!({
            "id": "pi_still_minimal",
            "object": "payment_intent",
            "status": "succeeded",
            "currency": "eur",
        })
        .to_string(),
    );
    match provider
        .charge_saved_method(charge_request(1130, "charge_money_2"))
        .await
    {
        Err(ProviderError::Malformed(message)) => {
            assert!(message.contains("refusing to coerce"), "{message}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }
}

/// A lost charge response (5xx) surfaces as `Unavailable` — the arm-8
/// contract — never as a business refusal.
#[tokio::test]
async fn a_lost_charge_response_surfaces_unavailable() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "POST /v1/payment_intents",
        503,
        stripe_error_body("upstream down"),
    );
    match provider
        .charge_saved_method(charge_request(1130, "charge_key_3"))
        .await
    {
        Err(ProviderError::Unavailable(_)) => {}
        other => panic!("expected Unavailable, got {other:?}"),
    }
}

/// The authenticated fetch is the only truth: it maps amount/currency/state
/// and refuses to coerce absent money.
#[tokio::test]
async fn fetch_payment_object_maps_the_authenticated_truth() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "GET /v1/payment_intents/pi_truth",
        200,
        intent_doc_json("pi_truth", "succeeded", 1130, "eur").to_string(),
    );
    let payment = provider
        .fetch_payment_object("pi_truth")
        .await
        .expect("fetch");
    assert_eq!(payment.provider_payment_id, "pi_truth");
    assert_eq!(payment.state, PaymentState::Succeeded);
    assert_eq!(payment.amount_minor, 1130);
    assert_eq!(payment.currency, "EUR");
    assert!(payment.created_at.is_some());

    // Absent money is Malformed, never zero.
    stub.route(
        "GET /v1/payment_intents/pi_broken",
        200,
        serde_json::json!({
            "id": "pi_broken",
            "object": "payment_intent",
            "status": "succeeded",
            "currency": "eur",
        })
        .to_string(),
    );
    match provider.fetch_payment_object("pi_broken").await {
        Err(ProviderError::Malformed(message)) => {
            assert!(message.contains("refusing to coerce"), "{message}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }

    // An unknown id is a typed 404 refusal (the repair sweep's "the
    // provider never knew this payment" class).
    match provider.fetch_payment_object("pi_missing").await {
        Err(ProviderError::Refused { status: 404, .. }) => {}
        other => panic!("expected Refused 404, got {other:?}"),
    }
}

/// The keyed metadata search can FIND a charge, but its emptiness is
/// eventually-consistent evidence — NEVER proof of absence (audit item 3).
#[tokio::test]
async fn search_finds_presence_but_an_empty_search_proves_nothing() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    let key = "payment:invoice:11111111-1111-1111-1111-111111111111:1";
    let match_doc = serde_json::json!({
        "id": "pi_keyed",
        "object": "payment_intent",
        "status": "succeeded",
        "amount": 1130,
        "currency": "eur",
        "metadata": { "idempotency_key": key },
    });
    let other_doc = serde_json::json!({
        "id": "pi_other",
        "object": "payment_intent",
        "status": "succeeded",
        "amount": 100,
        "currency": "eur",
        "metadata": { "idempotency_key": "someone-elses-key" },
    });
    stub.route(
        "GET /v1/payment_intents/search",
        200,
        serde_json::json!({
            "object": "search_result",
            "data": [other_doc, match_doc],
        })
        .to_string(),
    );
    let found = provider
        .search_payment_by_idempotency_key(key)
        .await
        .expect("keyed search");
    let found = found.expect("the charge is present");
    assert_eq!(found.provider_payment_id, "pi_keyed");
    assert_eq!(found.state, PaymentState::Succeeded);

    // An EMPTY keyed search is NOT absence: without the original request to
    // replay, the answer is unprovable (the engine parks the attempt).
    stub.route(
        "GET /v1/payment_intents/search",
        200,
        serde_json::json!({ "object": "search_result", "data": [] }).to_string(),
    );
    match provider.search_payment_by_idempotency_key(key).await {
        Err(ProviderError::Config(message)) => {
            assert!(
                message.contains("cannot be proven") && message.contains("unresolved"),
                "an empty search must refuse as unprovable, not answer None: {message}"
            )
        }
        other => panic!("expected the unprovable refusal, got {other:?}"),
    }
}

/// With the Search API disabled, the recent-list window is investigation
/// evidence only: a hit is a fact, an empty (or full) window is unprovable —
/// never `Ok(None)`.
#[tokio::test]
async fn search_without_the_api_is_investigation_only() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    let key = "autopay_conf_9";
    stub.route(
        "GET /v1/payment_intents/search",
        400,
        stripe_error_body("Search is not enabled on this account"),
    );

    // A short window without the key: still unprovable.
    stub.route(
        "GET /v1/payment_intents",
        200,
        serde_json::json!({
            "object": "list",
            "data": [{
                "id": "pi_fb_1",
                "object": "payment_intent",
                "status": "succeeded",
                "amount": 100,
                "currency": "eur",
                "metadata": { "idempotency_key": "someone-else" },
            }],
            "has_more": false,
        })
        .to_string(),
    );
    assert!(matches!(
        provider.search_payment_by_idempotency_key(key).await,
        Err(ProviderError::Config(_))
    ));

    // A FULL window: truncation, still unprovable.
    stub.route(
        "GET /v1/payment_intents",
        200,
        full_intent_list(100, "eur").to_string(),
    );
    match provider.search_payment_by_idempotency_key(key).await {
        Err(ProviderError::Config(message)) => {
            assert!(message.contains("cannot be proven"), "{message}")
        }
        other => panic!("expected the truncation refusal, got {other:?}"),
    }

    // The window can also FIND the charge.
    let match_doc = serde_json::json!({
        "id": "pi_fb_match",
        "object": "payment_intent",
        "status": "processing",
        "amount": 1130,
        "currency": "eur",
        "metadata": { "idempotency_key": key },
    });
    stub.route(
        "GET /v1/payment_intents",
        200,
        serde_json::json!({ "object": "list", "data": [match_doc] }).to_string(),
    );
    let found = provider
        .search_payment_by_idempotency_key(key)
        .await
        .expect("fallback match")
        .expect("the charge is in the window");
    assert_eq!(found.provider_payment_id, "pi_fb_match");
    assert_eq!(found.state, PaymentState::Processing);
}

/// Audit item 3: an UNCERTAIN create is recovered by REPLAYING the identical
/// POST with the same Idempotency-Key. A Search-empty result must not turn
/// the recovery into `None`: the replay returns the recovered payment.
#[tokio::test]
async fn a_search_empty_with_a_successful_replay_recovers_the_payment() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    let key = "recover_ok_key";
    // The create's response is lost; the request is journaled.
    stub.route(
        "POST /v1/payment_intents",
        503,
        stripe_error_body("upstream down"),
    );
    match provider
        .charge_saved_method(charge_request(1130, key))
        .await
    {
        Err(ProviderError::Unavailable(_)) => {}
        other => panic!("expected the lost response, got {other:?}"),
    }
    // Search is eventually consistent and answers NOTHING.
    stub.route(
        "GET /v1/payment_intents/search",
        200,
        serde_json::json!({ "object": "search_result", "data": [] }).to_string(),
    );
    // The replay answers the one intent the key minted.
    stub.route(
        "POST /v1/payment_intents",
        200,
        intent_doc_json("pi_recovered", "succeeded", 1130, "eur").to_string(),
    );
    let recovered = provider
        .search_payment_by_idempotency_key(key)
        .await
        .expect("the idempotent replay must not fail")
        .expect("the replay recovers the payment; an empty search is never None");
    assert_eq!(recovered.provider_payment_id, "pi_recovered");
    assert_eq!(recovered.state, PaymentState::Succeeded);
    assert_eq!(recovered.amount_minor, 1130);
}

/// The same recovery through the explicit adapter method, with a supplied
/// request (no journal entry for this key yet).
#[tokio::test]
async fn recover_uncertain_charge_replays_the_identical_request() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    let key = "recover_supplied_key";
    stub.route(
        "POST /v1/payment_intents",
        200,
        intent_doc_json("pi_supplied", "processing", 1130, "eur").to_string(),
    );
    let recovered = provider
        .recover_uncertain_charge(&charge_request(1130, key))
        .await
        .expect("replay runs")
        .expect("the replay minted/replayed the one intent");
    assert_eq!(recovered.provider_payment_id, "pi_supplied");
    assert_eq!(recovered.state, PaymentState::Processing);
}

/// A Search-empty + an UNRECONSTRUCTABLE request (no journaled wire form) is
/// UNPROVABLE: an error, never `None`.
#[tokio::test]
async fn a_search_empty_without_a_replayable_request_is_unprovable() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "GET /v1/payment_intents/search",
        200,
        serde_json::json!({ "object": "search_result", "data": [] }).to_string(),
    );
    match provider
        .search_payment_by_idempotency_key("never_charged_key")
        .await
    {
        Err(ProviderError::Config(message)) => {
            assert!(message.contains("cannot be proven"), "{message}")
        }
        other => panic!("expected Err (unprovable), never Ok(None), got {other:?}"),
    }
}

/// Only a REPLAYED refusal proves absence; a replay transport failure does
/// not.
#[tokio::test]
async fn only_a_replayed_refusal_proves_absence() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    // Prime two journals with lost creates.
    stub.route(
        "POST /v1/payment_intents",
        503,
        stripe_error_body("upstream down"),
    );
    for key in ["recover_absent_key", "recover_unknown_key"] {
        assert!(matches!(
            provider
                .charge_saved_method(charge_request(1130, key))
                .await,
            Err(ProviderError::Unavailable(_))
        ));
    }
    // The replay of the first is REFUSED (the original create never minted a
    // payment): that is presence-absence proof -> Ok(None).
    stub.route(
        "POST /v1/payment_intents",
        400,
        stripe_error_body("this idempotency key was never used successfully"),
    );
    assert_eq!(
        provider
            .search_payment_by_idempotency_key("recover_absent_key")
            .await
            .expect("a replay refusal is a decision"),
        None,
        "a replayed 400 proves the create never minted a payment"
    );
    // A transport failure during the replay proves NOTHING -> Err.
    stub.route(
        "POST /v1/payment_intents",
        503,
        stripe_error_body("upstream down"),
    );
    assert!(matches!(
        provider
            .search_payment_by_idempotency_key("recover_unknown_key")
            .await,
        Err(ProviderError::Unavailable(_))
    ));
}

/// Refunds map the wire document and carry DISTINCT provider ids. Item 6:
/// the wire request carries NO `currency` (the stub 400s if it does), while
/// the returned refund's currency is validated against the requested one.
#[tokio::test]
async fn refunds_send_no_currency_and_validate_the_returned_one() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    let first = provider
        .refund(RefundRequest {
            provider_payment_id: "pi_refunded".to_string(),
            amount_minor: 300,
            currency: "EUR".to_string(),
            description: "partial".to_string(),
            idempotency_key: "refund_key_1".to_string(),
        })
        .await
        .expect("partial refund");
    assert!(
        first.provider_refund_id.starts_with("re_conf_"),
        "{}",
        first.provider_refund_id
    );
    assert_eq!(first.provider_payment_id, "pi_refunded");
    assert_eq!(first.state, RefundState::Pending);
    assert_eq!(first.amount_minor, 300);
    assert_eq!(first.currency, "EUR");
    let second = provider
        .refund(RefundRequest {
            provider_payment_id: "pi_refunded".to_string(),
            amount_minor: 830,
            currency: "EUR".to_string(),
            description: "full".to_string(),
            idempotency_key: "refund_key_2".to_string(),
        })
        .await
        .expect("full refund");
    assert_ne!(
        first.provider_refund_id, second.provider_refund_id,
        "two refunds are two distinct provider facts"
    );

    // A refund returned in a DIFFERENT currency than requested is Malformed:
    // the neutral fact never records a currency the request did not name.
    stub.route(
        "POST /v1/refunds",
        200,
        serde_json::json!({
            "id": "re_currency_lie",
            "object": "refund",
            "status": "succeeded",
            "payment_intent": "pi_refunded",
            "amount": 300,
            "currency": "usd",
            "created": STUB_TS,
        })
        .to_string(),
    );
    match provider
        .refund(RefundRequest {
            provider_payment_id: "pi_refunded".to_string(),
            amount_minor: 300,
            currency: "EUR".to_string(),
            description: "lying refund".to_string(),
            idempotency_key: "refund_key_3".to_string(),
        })
        .await
    {
        Err(ProviderError::Malformed(message)) => {
            assert!(message.contains("currency"), "{message}")
        }
        other => panic!("expected Malformed, got {other:?}"),
    }

    // The single-refund fetch (GET /v1/refunds/{id}).
    stub.route(
        "GET /v1/refunds/re_conf_1",
        200,
        serde_json::json!({
            "id": "re_conf_1",
            "object": "refund",
            "status": "succeeded",
            "payment_intent": "pi_refunded",
            "amount": 300,
            "currency": "eur",
            "created": STUB_TS,
        })
        .to_string(),
    );
    let fetched = provider
        .fetch_refund("pi_refunded", "re_conf_1")
        .await
        .expect("refund fetch");
    assert_eq!(fetched.state, RefundState::Succeeded);

    // A refund the provider never knew is a typed refusal.
    match provider.fetch_refund("pi_refunded", "re_missing").await {
        Err(ProviderError::Refused { status: 404, .. }) => {}
        other => panic!("expected Refused 404, got {other:?}"),
    }
}

/// Disputes arrive from the intent's expanded latest_charge; when the
/// expansion is not honored, the charge is fetched explicitly — a dispute
/// is never hidden behind a wire quirk. No dispute answers an honest empty
/// list (retrieval exists).
#[tokio::test]
async fn disputes_arrive_from_the_expanded_charge() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);

    // Expanded: the dispute rides the charge object.
    stub.route(
        "GET /v1/payment_intents/pi_disputed",
        200,
        dispute_intent_doc_json(
            "pi_disputed",
            "dp_under_review",
            "under_review",
            1130,
            "eur",
        )
        .to_string(),
    );
    let disputes = provider
        .list_disputes("pi_disputed")
        .await
        .expect("dispute list");
    assert_eq!(disputes.len(), 1);
    assert_eq!(disputes[0].provider_dispute_id, "dp_under_review");
    assert_eq!(disputes[0].provider_payment_id, "pi_disputed");
    assert_eq!(
        disputes[0].state,
        billing_service::payments::DisputeState::Opened
    );
    assert_eq!(disputes[0].amount_minor, 1130);

    // NOT expanded (latest_charge is a bare id): the adapter fetches the
    // charge and still surfaces the dispute.
    stub.route(
        "GET /v1/payment_intents/pi_bare_charge",
        200,
        serde_json::json!({
            "id": "pi_bare_charge",
            "object": "payment_intent",
            "status": "succeeded",
            "amount": 1130,
            "currency": "eur",
            "latest_charge": "ch_bare",
        })
        .to_string(),
    );
    stub.route(
        "GET /v1/charges/ch_bare",
        200,
        serde_json::json!({
            "id": "ch_bare",
            "object": "charge",
            "dispute": {
                "id": "dp_lost",
                "object": "dispute",
                "status": "lost",
                "amount": 1130,
                "currency": "eur",
                "reason": "fraudulent",
                "created": STUB_TS,
            },
        })
        .to_string(),
    );
    let disputes = provider
        .list_disputes("pi_bare_charge")
        .await
        .expect("dispute list via the charge fetch");
    assert_eq!(disputes.len(), 1);
    assert_eq!(
        disputes[0].state,
        billing_service::payments::DisputeState::Lost
    );

    // No dispute on the payment: an honest empty list.
    stub.route(
        "GET /v1/payment_intents/pi_clean",
        200,
        intent_doc_json("pi_clean", "succeeded", 1130, "eur").to_string(),
    );
    let disputes = provider
        .list_disputes("pi_clean")
        .await
        .expect("dispute list");
    assert!(disputes.is_empty(), "a clean payment has no dispute facts");
}

/// Revocation detaches the stored method; a refusal stays visible (no 404
/// swallowing — the sweep's retry decision depends on the error).
#[tokio::test]
async fn revocation_detaches_and_refuses_visibly() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "POST /v1/payment_methods/pm_live/detach",
        200,
        serde_json::json!({
            "id": "pm_live",
            "object": "payment_method",
            "deleted": true,
        })
        .to_string(),
    );
    provider
        .revoke_saved_method("cus_conf_1", "pm_live")
        .await
        .expect("detach");
    // An unknown method is a visible refusal.
    match provider.revoke_saved_method("cus_conf_1", "pm_gone").await {
        Err(ProviderError::Refused { status: 404, .. }) => {}
        other => panic!("expected Refused 404, got {other:?}"),
    }
}

/// Paid payouts map to neutral settlements; in-flight payouts are not
/// settlement facts.
#[tokio::test]
async fn payouts_map_to_settlements() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "GET /v1/payouts",
        200,
        serde_json::json!({
            "object": "list",
            "data": [
                payout_doc_json("po_paid", 113_000, "eur"),
                {
                    "id": "po_transit",
                    "object": "payout",
                    "status": "in_transit",
                    "amount": 5_000,
                    "currency": "eur",
                    "arrival_date": STUB_TS,
                },
            ],
        })
        .to_string(),
    );
    let settlements = provider.list_settlements().await.expect("payout list");
    assert_eq!(settlements.len(), 1, "only PAID payouts are settlements");
    assert_eq!(settlements[0].provider_settlement_id, "po_paid");
    assert_eq!(settlements[0].amount_minor, 113_000);
    assert_eq!(settlements[0].currency, "EUR");
    assert!(settlements[0].settled_at.is_some());

    stub.route(
        "GET /v1/payouts/po_paid",
        200,
        payout_doc_json("po_paid", 113_000, "eur").to_string(),
    );
    let fetched = provider
        .fetch_settlement("po_paid")
        .await
        .expect("payout fetch");
    assert_eq!(fetched.provider_settlement_id, "po_paid");
    assert_eq!(fetched.amount_minor, 113_000);
    assert!(fetched.settled_at.is_some());
}

// ---------------------------------------------------------------------------
// Webhook verification + normalization unit gates
// ---------------------------------------------------------------------------

fn sign(secret: &str, timestamp: i64, payload: &[u8]) -> String {
    let mut mac = Hmac::<Sha256>::new_from_slice(secret.as_bytes()).expect("hmac key");
    mac.update(format!("{timestamp}.").as_bytes());
    mac.update(payload);
    let signature = hex::encode(mac.finalize().into_bytes());
    format!("t={timestamp},v1={signature}")
}

#[test]
fn a_valid_signature_verifies() {
    let secret = "whsec_main";
    let payload = br#"{"id":"evt_1","type":"payment_intent.succeeded"}"#;
    let header = sign(secret, Utc::now().timestamp(), payload);
    assert!(verify_signature(secret, payload, &header).is_ok());
}

#[test]
fn a_tampered_payload_fails_verification() {
    let secret = "whsec_main";
    let payload = br#"{"id":"evt_1","type":"payment_intent.succeeded"}"#;
    let header = sign(secret, Utc::now().timestamp(), payload);
    let tampered = br#"{"id":"evt_1","type":"payout.paid","amount":999999}"#;
    assert!(verify_signature(secret, tampered, &header).is_err());
}

#[test]
fn an_expired_timestamp_is_rejected_replay_window() {
    let secret = "whsec_main";
    let payload = br#"{"id":"evt_1","type":"payment_intent.succeeded"}"#;
    let stale = sign(
        secret,
        Utc::now().timestamp() - SIGNATURE_TOLERANCE_SECS - 1,
        payload,
    );
    match verify_signature(secret, payload, &stale) {
        Err(ProviderError::Malformed(message)) => {
            assert!(message.contains("replay window"), "{message}")
        }
        other => panic!("expected the replay-window refusal, got {other:?}"),
    }
    // A timestamp in the future beyond the tolerance is equally refused.
    let future = sign(
        secret,
        Utc::now().timestamp() + SIGNATURE_TOLERANCE_SECS + 1,
        payload,
    );
    assert!(verify_signature(secret, payload, &future).is_err());
}

#[test]
fn a_wrong_secret_fails_verification() {
    let payload = br#"{"id":"evt_1","type":"payment_intent.succeeded"}"#;
    let header = sign("whsec_attacker", Utc::now().timestamp(), payload);
    assert!(verify_signature("whsec_main", payload, &header).is_err());
}

#[test]
fn a_header_without_v1_fails_verification() {
    let payload = br#"{"id":"evt_1"}"#;
    let header = format!("t={}", Utc::now().timestamp());
    match verify_signature("whsec_main", payload, &header) {
        Err(ProviderError::Malformed(message)) => {
            assert!(message.contains("no v1"), "{message}")
        }
        other => panic!("expected the missing-v1 refusal, got {other:?}"),
    }
    // A non-numeric and an unparseable header fail closed too.
    assert!(verify_signature("whsec_main", payload, "t=not-a-number,v1=deadbeef").is_err());
    assert!(verify_signature("whsec_main", payload, "garbage").is_err());
    assert!(verify_signature("whsec_main", payload, "t=1,v1=not-hex!").is_err());
}

#[test]
fn key_rotation_matches_any_valid_v1() {
    let secret = "whsec_main";
    let payload = br#"{"id":"evt_1","type":"payout.paid"}"#;
    let now = Utc::now().timestamp();
    // The helper returns a full header; extract the bare v1 hex for the
    // rotation case.
    let valid = sign(secret, now, payload)
        .split(',')
        .find_map(|element| element.strip_prefix("v1="))
        .expect("the helper emits a v1 entry")
        .to_string();
    // Two v1 entries (key rotation): the first is stale-key garbage, the
    // second proves the delivery.
    let rotated = format!("t={now},v1={},v1={valid}", "a".repeat(64));
    assert!(verify_signature(secret, payload, &rotated).is_ok());
    // Multiple entries with NONE valid still fail.
    let rotated = format!(
        "t={now},v1={first},v1={second}",
        first = "a".repeat(64),
        second = "b".repeat(64)
    );
    assert!(verify_signature(secret, payload, &rotated).is_err());
}

fn stripe_event(event_type: &str, object: serde_json::Value) -> serde_json::Value {
    serde_json::json!({
        "id": "evt_conf_1",
        "object": "event",
        "type": event_type,
        "created": STUB_TS,
        "data": { "object": object },
    })
}

/// Payment events: the fact's state/amount/currency/metadata come from the
/// AUTHENTICATED fetched PaymentIntent. The event body here LIES about all
/// of them; only the fetch is believed.
#[tokio::test]
async fn payment_intent_events_normalize_from_the_fetched_object() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "GET /v1/payment_intents/pi_evt",
        200,
        serde_json::json!({
            "id": "pi_evt",
            "object": "payment_intent",
            "status": "succeeded",
            "amount": 1130,
            "currency": "eur",
            "metadata": { "tenant_id": "t1", "reference": "invoice:abc" },
        })
        .to_string(),
    );
    let lying_body = serde_json::json!({
        "id": "pi_evt",
        "object": "payment_intent",
        "status": "succeeded",
        "amount": 1,
        "currency": "xxx",
        "metadata": { "tenant_id": "attacker", "reference": "invoice:evil" },
    });
    let facts = normalize_event(
        &provider,
        &stripe_event("payment_intent.succeeded", lying_body),
    )
    .await
    .expect("normalizes");
    assert_eq!(facts.len(), 1);
    match &facts[0] {
        billing_service::payments::stripe_events::NormalizedFact::Payment(payment) => {
            assert_eq!(payment.provider, "stripe");
            assert_eq!(payment.provider_payment_id, "pi_evt");
            assert_eq!(payment.state, PaymentState::Succeeded);
            assert_eq!(
                payment.amount_minor,
                Some(1130),
                "fetched, never the body's 1"
            );
            assert_eq!(payment.currency.as_deref(), Some("EUR"));
            assert_eq!(payment.tenant_id.as_deref(), Some("t1"));
            assert_eq!(payment.obligation_ref.as_deref(), Some("invoice:abc"));
            assert_eq!(payment.purpose, "webhook");
        }
        other => panic!("expected a Payment fact, got {other:?}"),
    }

    // The other payment event types normalize to the fetched state.
    for (event_type, intent_id, wire_status, expected) in [
        (
            "payment_intent.processing",
            "pi_evt_processing",
            "processing",
            PaymentState::Processing,
        ),
        (
            "payment_intent.payment_failed",
            "pi_evt_failed",
            "requires_payment_method",
            PaymentState::Failed,
        ),
    ] {
        stub.route(
            &format!("GET /v1/payment_intents/{intent_id}"),
            200,
            intent_doc_json(intent_id, wire_status, 1130, "eur").to_string(),
        );
        let event = stripe_event(
            event_type,
            serde_json::json!({ "id": intent_id, "object": "payment_intent", "amount": 1 }),
        );
        let facts = normalize_event(&provider, &event)
            .await
            .unwrap_or_else(|error| panic!("{event_type} must normalize: {error}"));
        match &facts[0] {
            billing_service::payments::stripe_events::NormalizedFact::Payment(payment) => {
                assert_eq!(payment.state, expected, "{event_type}");
            }
            other => panic!("expected a Payment fact, got {other:?}"),
        }
    }
}

/// A fetch failure is a retryable Err — the signed body is NEVER a fallback
/// fact source.
#[tokio::test]
async fn a_failed_refetch_never_falls_back_to_the_signed_body() {
    let (_stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    let event = stripe_event(
        "payment_intent.succeeded",
        serde_json::json!({
            "id": "pi_unfetchable",
            "object": "payment_intent",
            "status": "succeeded",
            "amount": 1500,
            "currency": "usd",
            "metadata": { "tenant_id": "t1", "reference": "invoice:abc" },
        }),
    );
    assert!(normalize_event(&provider, &event).await.is_err());
}

/// Item 2: a COMPLETE session activates only when the FETCHED PaymentIntent
/// says `succeeded`. The session metadata is mirrored on the PaymentIntent
/// (item 9), so the fetched object carries the attribution.
#[tokio::test]
async fn a_complete_session_with_a_succeeded_payment_intent_activates() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "GET /v1/payment_intents/pi_cs",
        200,
        serde_json::json!({
            "id": "pi_cs",
            "object": "payment_intent",
            "status": "succeeded",
            "amount": 2480,
            "currency": "eur",
            "customer": "cus_cs",
            "metadata": {
                "tenant_id": "tenant_1",
                "plan_name": "starter",
                "interval": "monthly",
                "reference": "invoice:abc",
                "checkout_id": "co_42",
            },
        })
        .to_string(),
    );
    let event = stripe_event(
        "checkout.session.completed",
        serde_json::json!({
            "id": "cs_evt",
            "object": "checkout.session",
            "status": "complete",
            "payment_status": "paid",
            "amount_total": 1,
            "currency": "xxx",
            "payment_intent": "pi_cs",
            "customer": "cus_body",
            "metadata": { "tenant_id": "attacker", "plan_name": "scale" },
        }),
    );
    let facts = normalize_event(&provider, &event)
        .await
        .expect("normalizes");
    assert_eq!(facts.len(), 2, "payment + completed-checkout fact");
    match &facts[0] {
        billing_service::payments::stripe_events::NormalizedFact::Payment(payment) => {
            assert_eq!(payment.provider_payment_id, "pi_cs");
            assert_eq!(payment.state, PaymentState::Succeeded);
            assert_eq!(payment.amount_minor, Some(2_480));
            assert_eq!(payment.tenant_id.as_deref(), Some("tenant_1"));
        }
        other => panic!("expected a payment fact, got {other:?}"),
    }
    match &facts[1] {
        billing_service::payments::stripe_events::NormalizedFact::CheckoutCompleted(checkout) => {
            assert_eq!(checkout.provider_payment_id, "pi_cs");
            assert_eq!(checkout.provider_checkout_id, "cs_evt");
            assert_eq!(checkout.tenant_id.as_deref(), Some("tenant_1"));
            assert_eq!(checkout.plan_name.as_deref(), Some("starter"));
            assert_eq!(checkout.interval.as_deref(), Some("monthly"));
            assert_eq!(checkout.amount_minor, Some(2_480));
            assert_eq!(checkout.currency.as_deref(), Some("EUR"));
            assert_eq!(checkout.provider_customer_id.as_deref(), Some("cus_cs"));
        }
        other => panic!("expected a completed-checkout fact, got {other:?}"),
    }
}

/// Item 2 (the defect this audit found): Session `complete` is NOT money
/// `Succeeded`. A complete session whose fetched PaymentIntent is still
/// PROCESSING produces no activation fact at all.
#[tokio::test]
async fn a_complete_session_with_a_processing_intent_activates_nothing() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "GET /v1/payment_intents/pi_cs_pending",
        200,
        serde_json::json!({
            "id": "pi_cs_pending",
            "object": "payment_intent",
            "status": "processing",
            "amount": 2480,
            "currency": "eur",
            "metadata": { "tenant_id": "tenant_1", "plan_name": "starter" },
        })
        .to_string(),
    );
    let event = stripe_event(
        "checkout.session.completed",
        serde_json::json!({
            "id": "cs_evt_pending",
            "object": "checkout.session",
            "status": "complete",
            "payment_status": "unpaid",
            "amount_total": 2480,
            "currency": "eur",
            "payment_intent": "pi_cs_pending",
            "metadata": { "tenant_id": "tenant_1", "plan_name": "starter" },
        }),
    );
    let facts = normalize_event(&provider, &event)
        .await
        .expect("normalizes");
    assert_eq!(
        facts.len(),
        1,
        "a processing intent produces NO activation fact"
    );
    match &facts[0] {
        billing_service::payments::stripe_events::NormalizedFact::Payment(payment) => {
            assert_eq!(payment.state, PaymentState::Processing);
            assert_ne!(payment.state, PaymentState::Succeeded);
        }
        other => panic!("expected a processing payment fact, got {other:?}"),
    }
}

/// Item 2: a complete session with NO PaymentIntent yet is still processing —
/// never Succeeded, no activation (there is no money object to fetch).
#[tokio::test]
async fn a_complete_session_without_an_intent_is_processing_never_succeeded() {
    let (_stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    let event = stripe_event(
        "checkout.session.completed",
        serde_json::json!({
            "id": "cs_evt_no_pi",
            "object": "checkout.session",
            "status": "complete",
            "payment_status": "paid",
            "amount_total": 2480,
            "currency": "eur",
            "metadata": { "tenant_id": "tenant_1", "plan_name": "starter" },
        }),
    );
    let facts = normalize_event(&provider, &event)
        .await
        .expect("normalizes");
    assert_eq!(facts.len(), 1);
    match &facts[0] {
        billing_service::payments::stripe_events::NormalizedFact::Payment(payment) => {
            assert_eq!(payment.state, PaymentState::Processing);
            assert_eq!(payment.amount_minor, None, "no fetched money exists");
        }
        other => panic!("expected a processing payment fact, got {other:?}"),
    }
}

/// Refund events fetch the authoritative refund; the body's amount is
/// ignored.
#[tokio::test]
async fn refund_events_normalize_from_the_fetched_refund() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "GET /v1/refunds/re_evt",
        200,
        serde_json::json!({
            "id": "re_evt",
            "object": "refund",
            "status": "pending",
            "payment_intent": "pi_evt",
            "amount": 300,
            "currency": "eur",
            "created": STUB_TS,
        })
        .to_string(),
    );
    for event_type in ["charge.refunded", "charge.refund.updated"] {
        // `charge.refund.updated` carries the refund object;
        // `charge.refunded` carries the charge whose refunds list names it.
        let object = if event_type == "charge.refund.updated" {
            serde_json::json!({
                "id": "re_evt",
                "object": "refund",
                "payment_intent": "pi_evt",
                "amount": 1,
                "status": "succeeded",
            })
        } else {
            serde_json::json!({
                "id": "ch_evt",
                "object": "charge",
                "payment_intent": "pi_evt",
                "refunds": { "data": [ { "id": "re_evt", "object": "refund" } ] },
            })
        };
        let facts = normalize_event(&provider, &stripe_event(event_type, object))
            .await
            .expect("normalizes");
        match &facts[0] {
            billing_service::payments::stripe_events::NormalizedFact::Refund(refund) => {
                assert_eq!(refund.provider, "stripe");
                assert_eq!(refund.provider_refund_id, "re_evt");
                assert_eq!(refund.provider_payment_id, "pi_evt");
                assert_eq!(
                    refund.state,
                    billing_service::payments::RefundState::Pending
                );
                assert_eq!(refund.amount_minor, 300, "the fetched amount wins");
                assert_eq!(refund.currency, "EUR");
                assert!(refund.created_at.is_some());
            }
            other => panic!("expected a Refund fact, got {other:?}"),
        }
    }
}

/// Dispute events fetch the authoritative dispute. The payment id may arrive
/// directly or as a CHARGE that is resolved with an authenticated fetch.
#[tokio::test]
async fn dispute_events_normalize_from_the_fetched_dispute() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "GET /v1/payment_intents/pi_evt",
        200,
        dispute_intent_doc_json("pi_evt", "dp_evt", "under_review", 1130, "eur").to_string(),
    );
    let event = stripe_event(
        "charge.dispute.created",
        serde_json::json!({
            "id": "dp_evt",
            "object": "dispute",
            "status": "won",
            "payment_intent": "pi_evt",
            "amount": 1,
        }),
    );
    let facts = normalize_event(&provider, &event)
        .await
        .expect("normalizes");
    match &facts[0] {
        billing_service::payments::stripe_events::NormalizedFact::Dispute(dispute) => {
            assert_eq!(dispute.provider_dispute_id, "dp_evt");
            assert_eq!(dispute.provider_payment_id, "pi_evt");
            assert_eq!(
                dispute.state,
                billing_service::payments::DisputeState::Opened,
                "the fetched dispute state wins over the body's 'won'"
            );
            assert!(dispute.opened_at.is_some());
        }
        other => panic!("expected a Dispute fact, got {other:?}"),
    }

    // Charge-only dispute: the charge→payment resolution is authenticated.
    stub.route(
        "GET /v1/charges/ch_only",
        200,
        serde_json::json!({
            "id": "ch_only",
            "object": "charge",
            "payment_intent": "pi_from_charge",
        })
        .to_string(),
    );
    stub.route(
        "GET /v1/payment_intents/pi_from_charge",
        200,
        dispute_intent_doc_json("pi_from_charge", "dp_closed", "lost", 1130, "eur").to_string(),
    );
    let event = stripe_event(
        "charge.dispute.closed",
        serde_json::json!({
            "id": "dp_closed",
            "object": "dispute",
            "charge": "ch_only",
            "status": "won",
            "amount": 1,
        }),
    );
    let facts = normalize_event(&provider, &event)
        .await
        .expect("normalizes");
    match &facts[0] {
        billing_service::payments::stripe_events::NormalizedFact::Dispute(dispute) => {
            assert_eq!(dispute.provider_payment_id, "pi_from_charge");
            assert_eq!(dispute.state, billing_service::payments::DisputeState::Lost);
        }
        other => panic!("expected a Dispute fact, got {other:?}"),
    }
}

/// Payout events fetch the authoritative payout.
#[tokio::test]
async fn payout_events_normalize_from_the_fetched_payout() {
    let (stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    stub.route(
        "GET /v1/payouts/po_evt",
        200,
        payout_doc_json("po_evt", 113_000, "eur").to_string(),
    );
    let event = stripe_event(
        "payout.paid",
        serde_json::json!({ "id": "po_evt", "object": "payout", "status": "paid", "amount": 1 }),
    );
    let facts = normalize_event(&provider, &event)
        .await
        .expect("normalizes");
    match &facts[0] {
        billing_service::payments::stripe_events::NormalizedFact::Settlement(settlement) => {
            assert_eq!(settlement.provider, "stripe");
            assert_eq!(settlement.provider_settlement_id, "po_evt");
            assert_eq!(settlement.amount_minor, 113_000);
            assert_eq!(settlement.currency, "EUR");
            assert!(settlement.settled_at.is_some());
        }
        other => panic!("expected a Settlement fact, got {other:?}"),
    }
}

#[tokio::test]
async fn unknown_event_types_are_accepted_and_ignored() {
    let (_stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    for event_type in [
        "invoice.created",
        "customer.subscription.created",
        "customer.subscription.deleted",
        "price.updated",
        "charge.succeeded",
        "totally.unknown.event",
    ] {
        let facts = normalize_event(
            &provider,
            &stripe_event(event_type, serde_json::json!({ "id": "x", "amount": 999 })),
        )
        .await
        .unwrap_or_else(|error| panic!("{event_type} must be accepted: {error}"));
        assert!(facts.is_empty(), "{event_type} must produce no facts");
    }
}

#[tokio::test]
async fn a_known_event_with_an_unreadable_object_fails_the_delivery() {
    let (_stub, base_url) = stripe_stub_api();
    let provider = test_provider(&base_url);
    // No id: the delivery must be dead-lettered (Err), not silently dropped.
    let facts = normalize_event(
        &provider,
        &stripe_event(
            "payment_intent.succeeded",
            serde_json::json!({ "status": "succeeded", "amount": 1, "currency": "eur" }),
        ),
    )
    .await;
    assert!(facts.is_err());
    // A refund event with no refund id cannot be fetched: Err too.
    let facts = normalize_event(
        &provider,
        &stripe_event(
            "charge.refunded",
            serde_json::json!({ "id": "ch_x", "object": "charge", "payment_intent": "pi_x" }),
        ),
    )
    .await;
    assert!(facts.is_err());
}

#[test]
fn the_event_dedup_id_is_the_provider_event_id() {
    let event = stripe_event("payout.paid", serde_json::json!({ "id": "po_x" }));
    assert_eq!(event_dedup_id(&event).as_deref(), Some("evt_conf_1"));
    assert_eq!(
        event_dedup_id(&serde_json::json!({ "type": "payout.paid" })),
        None
    );
}

// ---------------------------------------------------------------------------
// N-14: the Mollie search window is FIVE truncation-honest pages
// ---------------------------------------------------------------------------

struct MollieStub {
    routes: Mutex<HashMap<String, (u16, String)>>,
}

async fn mollie_stub_handler(
    axum::extract::State(state): axum::extract::State<&'static MollieStub>,
    request: axum::http::Request<axum::body::Body>,
) -> axum::response::Response {
    use axum::response::IntoResponse;
    let method = request.method().clone();
    let path = request.uri().path().to_string();
    let query = request.uri().query().unwrap_or_default().to_string();
    let json_header = [(axum::http::header::CONTENT_TYPE, "application/json")];
    // The listing reader keys pages by their from= cursor (the same cursor
    // the client extracts from _links.next.href).
    let from = query.split('&').find_map(|pair| pair.strip_prefix("from="));
    let page_key = match from {
        Some(cursor) => format!("{method} {path}?from={cursor}"),
        None => format!("{method} {path}"),
    };
    let routed = {
        let routes = state.routes.lock().expect("mollie stub routes");
        routes.get(&page_key).or_else(|| routes.get(&path)).cloned()
    };
    if let Some((status, body)) = routed {
        return (
            axum::http::StatusCode::from_u16(status).expect("status"),
            json_header,
            body,
        )
            .into_response();
    }
    (
        axum::http::StatusCode::NOT_FOUND,
        json_header,
        r#"{"title":"Not Found"}"#.to_string(),
    )
        .into_response()
}

fn mollie_stub_api() -> (&'static MollieStub, String) {
    static STUB: std::sync::OnceLock<(&'static MollieStub, String)> = std::sync::OnceLock::new();
    STUB.get_or_init(|| {
        let state: &'static MollieStub = Box::leak(Box::new(MollieStub {
            routes: Mutex::new(HashMap::new()),
        }));
        let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind mollie stub");
        listener
            .set_nonblocking(true)
            .expect("nonblocking mollie listener");
        let address = listener.local_addr().expect("mollie stub address");
        let app = axum::Router::new()
            .fallback(mollie_stub_handler)
            .with_state(state);
        std::thread::spawn(move || {
            let runtime = tokio::runtime::Builder::new_current_thread()
                .enable_all()
                .build()
                .expect("mollie stub runtime");
            runtime.block_on(async move {
                let listener = tokio::net::TcpListener::from_std(listener).expect("tokio listener");
                axum::serve(listener, app).await.expect("mollie stub");
            });
        });
        (state, format!("http://{address}/v2"))
    })
    .clone()
}

fn mollie_payment_doc(id: &str, key: Option<&str>) -> serde_json::Value {
    let mut metadata = serde_json::Map::new();
    if let Some(key) = key {
        metadata.insert("idempotency_key".to_string(), serde_json::json!(key));
    }
    serde_json::json!({
        "id": id,
        "status": "paid",
        "amount": { "currency": "EUR", "value": "11.30" },
        "metadata": metadata,
    })
}

fn mollie_page(items: Vec<serde_json::Value>, next_cursor: Option<&str>) -> String {
    let mut page = serde_json::json!({ "_embedded": { "payments": items } });
    if let Some(cursor) = next_cursor {
        page["_links"] = serde_json::json!({
            "next": { "href": format!("https://api.mollie.test/v2/payments?from={cursor}") }
        });
    }
    page.to_string()
}

fn mollie_test_provider(base_url: &str) -> MollieProvider {
    MollieProvider::new("test_n14_key".to_string(), base_url.to_string(), None)
        .expect("mollie provider")
}

/// A short page is the listing's end: absence is provable (`Ok(None)`).
#[tokio::test]
async fn mollie_short_page_proves_absence() {
    let (stub, base_url) = mollie_stub_api();
    stub.routes.lock().expect("routes").insert(
        "GET /v2/payments".to_string(),
        (
            200,
            mollie_page(
                vec![
                    mollie_payment_doc("tr_a", None),
                    mollie_payment_doc("tr_b", None),
                ],
                None,
            ),
        ),
    );
    let provider = mollie_test_provider(&base_url);
    let absent = provider
        .search_payment_by_idempotency_key("usageinv_n14_a")
        .await
        .expect("short-page search");
    assert_eq!(absent, None);
}

/// A full page without a continuation cursor cannot prove absence.
#[tokio::test]
async fn mollie_full_page_without_a_cursor_refuses() {
    let (stub, base_url) = mollie_stub_api();
    let items: Vec<serde_json::Value> = (0..100)
        .map(|index| mollie_payment_doc(&format!("tr_full_{index}"), None))
        .collect();
    stub.routes.lock().expect("routes").insert(
        "GET /v2/payments".to_string(),
        (200, mollie_page(items, None)),
    );
    let provider = mollie_test_provider(&base_url);
    match provider
        .search_payment_by_idempotency_key("usageinv_n14_b")
        .await
    {
        Err(ProviderError::Config(message)) => {
            assert!(message.contains("cannot be proven"), "{message}")
        }
        other => panic!("expected the truncation refusal, got {other:?}"),
    }
}

/// Five full pages (500 payments) walked by cursor still refuse: the
/// widened window is truncation-honest end to end.
#[tokio::test]
async fn mollie_five_full_pages_are_exhaustion_refusal() {
    let (stub, base_url) = mollie_stub_api();
    let first_page: Vec<serde_json::Value> = (0..100)
        .map(|index| mollie_payment_doc(&format!("tr_walk_{index}"), None))
        .collect();
    let walk_page: Vec<serde_json::Value> = (0..100)
        .map(|index| mollie_payment_doc(&format!("tr_loop_{index}"), None))
        .collect();
    // Every walked page is FULL and its continuation cursor loops back onto
    // the (full) walk page: the search visits five full pages, then refuses.
    {
        let mut routes = stub.routes.lock().expect("routes");
        routes.insert(
            "GET /v2/payments".to_string(),
            (200, mollie_page(first_page, Some("tr_cursor_loop"))),
        );
        routes.insert(
            "GET /v2/payments?from=tr_cursor_loop".to_string(),
            (200, mollie_page(walk_page, Some("tr_cursor_loop"))),
        );
    }
    let provider = mollie_test_provider(&base_url);
    match provider
        .search_payment_by_idempotency_key("usageinv_n14_c")
        .await
    {
        Err(ProviderError::Config(message)) => {
            assert!(message.contains("window is exhausted"), "{message}")
        }
        other => panic!("expected the exhaustion refusal, got {other:?}"),
    }
}

/// The cursor walk reaches a match on a LATER page (the widening actually
/// widened the search, it did not just re-read page one).
#[tokio::test]
async fn mollie_cursor_walk_finds_a_page_two_match() {
    let (stub, base_url) = mollie_stub_api();
    let key = "usageinv_n14_d";
    let first_page: Vec<serde_json::Value> = (0..100)
        .map(|index| mollie_payment_doc(&format!("tr_p1_{index}"), None))
        .collect();
    {
        let mut routes = stub.routes.lock().expect("routes");
        routes.insert(
            "GET /v2/payments".to_string(),
            (200, mollie_page(first_page, Some("tr_cursor_2"))),
        );
        routes.insert(
            "GET /v2/payments?from=tr_cursor_2".to_string(),
            (
                200,
                mollie_page(vec![mollie_payment_doc("tr_p2_match", Some(key))], None),
            ),
        );
    }
    let provider = mollie_test_provider(&base_url);
    let found = provider
        .search_payment_by_idempotency_key(key)
        .await
        .expect("cursor walk")
        .expect("the charge is on page two");
    assert_eq!(found.provider_payment_id, "tr_p2_match");
    assert_eq!(found.state, PaymentState::Succeeded);
    assert_eq!(found.amount_minor, 1130);
}
