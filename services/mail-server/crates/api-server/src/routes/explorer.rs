//! Public zero-JS API sandbox + pricing calculator (server-driven).
//!
//! The marketing site's API Explorer and Pricing Calculator are plain HTML
//! forms that POST here. This module:
//!
//! 1. lazily provisions a dedicated SANDBOX TENANT (tenant + api key +
//!    example.com verified domain) — a REAL tenant, so every request runs
//!    the REAL v1 handlers with a REAL api key;
//! 2. executes each lane by dispatching IN-PROCESS through the app router
//!    (`build_app` + `tower::ServiceExt::oneshot`) — genuine validation,
//!    idempotency, queue inserts and worker pickup: a send really flows and
//!    delivery is genuinely attempted (the Messages lane shows the full
//!    queued → attempted → bounced lifecycle);
//! 3. guards abuse with a per-IP rate limit (Redis, fail-open with a warn —
//!    a public playground must not hard-fail on a Redis blip), an 8 KiB
//!    body cap, and a recipient policy for the send lane: every to/cc/bcc
//!    address must end in @example.com (RFC 2606 reserved — real delivery
//!    attempt, harmless by construction, no relay potential);
//! 4. renders the full result page via ui_foundation (zero JS anywhere).
//!
//! The calculator computes with `billing_service::plans` — the canonical
//! pricing source — so this surface can never drift from billing.

use axum::{
    extract::{Form, State},
    http::{HeaderName, HeaderValue, Method, Request, StatusCode},
    response::{Html, IntoResponse, Response},
    Router,
};
use serde::Deserialize;
use std::sync::OnceLock;
use tower::ServiceExt;

use crate::state::AppState;

/// HTML body cap for the explorer request textarea.
const MAX_BODY_BYTES: usize = 8 * 1024;
/// Per-IP requests per minute on the public explorer endpoints.
const RATE_LIMIT_PER_MINUTE: i64 = 12;

// ─────────────────────────────────────────────────────────────────────────────
// Sandbox tenancy
// ─────────────────────────────────────────────────────────────────────────────

struct Sandbox {
    api_key: String,
}

/// The sandbox tenant id is a fixed 26-char value (VARCHAR(26) per migration
/// 064; charset follows the existing lowercase-alphanumeric nanoid style).
const SANDBOX_TENANT_ID: &str = "sbx0explorer0000000000000x";

static SANDBOX: OnceLock<Sandbox> = OnceLock::new();

/// Provision (idempotently) and memoize the sandbox tenant + api key.
async fn sandbox(state: &AppState) -> Result<&'static Sandbox, String> {
    if let Some(s) = SANDBOX.get() {
        return Ok(s);
    }
    let now = chrono::Utc::now();

    // Tenant (VARCHAR(26) id, plan-free).
    sqlx::query(
        "INSERT INTO tenants (id, name, plan, status, created_at, updated_at)
         VALUES ($1, 'API Explorer Sandbox', 'free', 'active', $2, $2)
         ON CONFLICT (id) DO NOTHING",
    )
    .bind(SANDBOX_TENANT_ID)
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| format!("sandbox tenant provision failed: {e}"))?;

    // Verified example.com domain for the tenant (direct insert mirrors the
    // real create-domain INSERT shape in routes/domains.rs:369, with the
    // verification flags set so the real send path accepts it).
    let existing_domain: Option<String> = sqlx::query_scalar(
        "SELECT name FROM domains WHERE tenant_id = $1 AND name = 'example.com' LIMIT 1",
    )
    .bind(SANDBOX_TENANT_ID)
    .fetch_optional(&state.db)
    .await
    .map_err(|e| format!("sandbox domain check failed: {e}"))?;
    if existing_domain.is_none() {
        // Real DKIM keypair, encrypted exactly like the real create-domain
        // handler (routes/domains.rs) — the REAL send path requires
        // dkim_private_key LIKE 'dkim:v1:%' and dkim_enabled to accept a send.
        let domain_id = uuid::Uuid::new_v4();
        let key_pair = apexmail_lib::dkim::generate_dkim_keypair()
            .map_err(|e| format!("sandbox dkim keypair failed: {e}"))?;
        let aad =
            apexmail_lib::dkim::dkim_private_key_aad(SANDBOX_TENANT_ID, &domain_id.to_string());
        let encrypted =
            apexmail_lib::dkim::encrypt_dkim_private_key(&key_pair.private_key_pem, &aad)
                .map_err(|e| format!("sandbox dkim encrypt failed: {e}"))?;
        sqlx::query(
            "INSERT INTO domains (id, tenant_id, name, status, spf_verified, dkim_verified,
             dmarc_verified, return_path_verified, mta_sts_verified, bimi_verified,
             tlsrpt_verified, dkim_selector, dkim_public_key, dkim_private_key, dkim_enabled,
             ses_verified, verified, created_at, updated_at)
             VALUES ($1,$2,'example.com','verified',true,true,true,true,true,true,true,
             'sbx', $4, $5, true, true, true, $3, $3)
             ON CONFLICT DO NOTHING",
        )
        .bind(domain_id)
        .bind(SANDBOX_TENANT_ID)
        .bind(now)
        .bind(&key_pair.public_key)
        .bind(&encrypted)
        .execute(&state.db)
        .await
        .map_err(|e| format!("sandbox domain provision failed: {e}"))?;
    }

    // API key: generate fresh only when the tenant has none.
    let raw_key = apexmail_lib::id::generate_api_key(false);
    let key_hash =
        apexmail_lib::hash_api_key_with_secret(&raw_key, &state.config.api_key_hash_secret);
    let has_key: bool = sqlx::query_scalar(
        "SELECT EXISTS(SELECT 1 FROM api_keys WHERE tenant_id = $1 AND revoked_at IS NULL)",
    )
    .bind(SANDBOX_TENANT_ID)
    .fetch_one(&state.db)
    .await
    .map_err(|e| format!("sandbox key check failed: {e}"))?;
    let api_key = if has_key {
        // A previous process created the key but its plaintext is lost
        // (hashed at rest). Rotate: revoke old, insert new — the explorer is
        // stateless so rotation is invisible.
        sqlx::query(
            "UPDATE api_keys SET revoked_at = $2 WHERE tenant_id = $1 AND revoked_at IS NULL",
        )
        .bind(SANDBOX_TENANT_ID)
        .bind(now)
        .execute(&state.db)
        .await
        .map_err(|e| format!("sandbox key rotation failed: {e}"))?;
        insert_key(state, &key_hash, now).await?;
        raw_key
    } else {
        insert_key(state, &key_hash, now).await?;
        raw_key
    };

    let _ = SANDBOX.set(Sandbox { api_key });
    Ok(SANDBOX.get().expect("just set"))
}

async fn insert_key(
    state: &AppState,
    key_hash: &str,
    now: chrono::DateTime<chrono::Utc>,
) -> Result<(), String> {
    let prefix: String = "sbx_".to_string();
    sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, name, key_prefix, key_hash, scopes, expires_at, created_at, updated_at)
         VALUES ($1, $2, 'explorer', $3, $4, $5, NULL, $6, $6)",
    )
    .bind(uuid::Uuid::new_v4())
    .bind(SANDBOX_TENANT_ID)
    .bind(&prefix)
    .bind(key_hash)
    .bind(serde_json::json!(["*"]))
    .bind(now)
    .execute(&state.db)
    .await
    .map_err(|e| format!("sandbox key insert failed: {e}"))?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Rate limiting (public endpoints)
// ─────────────────────────────────────────────────────────────────────────────

async fn rate_limit(state: &AppState, ip: &str) -> bool {
    // Fail OPEN when Redis is unavailable (warn) — availability of a public
    // playground outranks a hard fail on cache blips.
    redis_rate_limit(state, &format!("explorer_rl:{ip}")).await
}

async fn redis_rate_limit(state: &AppState, key: &str) -> bool {
    let mut conn = match state.redis.get().await {
        Ok(c) => c,
        Err(e) => {
            tracing::warn!(error = %e, "explorer rate-limit redis unavailable — allowing");
            return true;
        }
    };
    let (count,): (i64,) = match redis::pipe()
        .atomic()
        .incr(key, 1)
        .expire(key, 60)
        .ignore()
        .query_async(&mut conn)
        .await
    {
        Ok(v) => v,
        Err(e) => {
            tracing::warn!(error = %e, "explorer rate-limit incr failed — allowing");
            return true;
        }
    };
    count <= RATE_LIMIT_PER_MINUTE
}

/// Rate-limit bucket key for a sandbox request. Delegates to the shared
/// trusted-proxy walk (`extract_public_client_ip`): X-Forwarded-For is
/// only honoured when the DIRECT peer is a configured trusted proxy, and
/// then only the rightmost untrusted entry — the raw first-XFF read let
/// any caller pick an arbitrary bucket identity.
fn client_ip(
    req_headers: &axum::http::HeaderMap,
    socket_ip: std::net::IpAddr,
    trusted_proxies: &[String],
) -> String {
    crate::middleware::rate_limiter::extract_public_client_ip(
        req_headers,
        socket_ip,
        trusted_proxies,
    )
}

// ─────────────────────────────────────────────────────────────────────────────
// In-process dispatch through the REAL router
// ─────────────────────────────────────────────────────────────────────────────

static API_ROUTER: OnceLock<Router> = OnceLock::new();

fn api_router(state: &AppState) -> &'static Router {
    API_ROUTER.get_or_init(|| crate::app::build_app(state.clone()))
}

/// Dispatch a request through the real application router and capture the
/// verbatim status + body.
async fn dispatch(
    state: &AppState,
    method: Method,
    uri: &str,
    api_key: &str,
    json_body: Option<&str>,
) -> (u16, serde_json::Value) {
    let mut builder = Request::builder().method(method).uri(uri).header(
        "x-api-key",
        HeaderValue::from_str(api_key).expect("api key is ascii"),
    );
    if json_body.is_some() {
        builder = builder.header("content-type", "application/json");
    }
    let body = match json_body {
        Some(b) => axum::body::Body::from(b.to_string()),
        None => axum::body::Body::empty(),
    };
    let request = builder.body(body).expect("valid request");
    let response = match api_router(state).clone().oneshot(request).await {
        Ok(r) => r,
        Err(e) => {
            // Public endpoint: log the detail, return a generic message —
            // the raw in-process dispatch error can carry internal routes
            // and infrastructure detail.
            tracing::error!(error = %e, "explorer dispatch failed");
            return (
                500,
                serde_json::json!({"error": {"code": "internal_error", "message": "The sandbox request could not be processed. Please try again shortly."}}),
            );
        }
    };
    let status = response.status().as_u16();
    let bytes = axum::body::to_bytes(response.into_body(), 1024 * 1024)
        .await
        .unwrap_or_default();
    let value = serde_json::from_slice(&bytes).unwrap_or_else(
        |_| serde_json::json!({"raw": String::from_utf8_lossy(&bytes).to_string()}),
    );
    (status, value)
}

// ─────────────────────────────────────────────────────────────────────────────
// Recipient policy (send lane)
// ─────────────────────────────────────────────────────────────────────────────

fn all_recipients_example_com(body: &serde_json::Value) -> Result<(), String> {
    let check = |addr: &str| -> Result<(), String> {
        let lower = addr.trim().to_ascii_lowercase();
        if lower.ends_with("@example.com") {
            Ok(())
        } else {
            Err(format!(
                "recipient {addr:?} is outside the sandbox — explorer recipients must end in @example.com (the RFC 2606 reserved domain)"
            ))
        }
    };
    let check_list = |field: &str| -> Result<(), String> {
        match body.get(field) {
            None | Some(serde_json::Value::Null) => Ok(()),
            Some(serde_json::Value::String(s)) => check(s),
            Some(serde_json::Value::Array(items)) => {
                for item in items {
                    let s = item
                        .as_str()
                        .ok_or_else(|| format!("{field} entries must be strings"))?;
                    check(s)?;
                }
                Ok(())
            }
            Some(_) => Err(format!("{field} must be a string or array of strings")),
        }
    };
    check_list("to")?;
    check_list("cc")?;
    check_list("bcc")?;
    Ok(())
}

// ─────────────────────────────────────────────────────────────────────────────
// Handlers
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug)]
pub struct ExplorerForm {
    #[serde(default)]
    pub lane: String,
    #[serde(default)]
    pub body: String,
}

pub async fn exec(
    State(state): State<AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: axum::http::HeaderMap,
    Form(form): Form<ExplorerForm>,
) -> Response {
    // Untrusted direct peer: the socket address IS the client. (Without
    // ConnectInfo — e.g. an exotic service wrapper — bucket on "unknown"
    // rather than trusting headers.)
    let bucket_ip = match connect_info {
        Some(axum::extract::ConnectInfo(addr)) => {
            client_ip(&headers, addr.ip(), &state.config.trusted_proxies)
        }
        None => "unknown".to_string(),
    };
    if !rate_limit(&state, &bucket_ip).await {
        return error_page(
            StatusCode::TOO_MANY_REQUESTS,
            "Too many sandbox requests — try again in a minute.",
        );
    }
    if form.body.len() > MAX_BODY_BYTES {
        return error_page(
            StatusCode::PAYLOAD_TOO_LARGE,
            "Request body exceeds the 8 KiB sandbox limit.",
        );
    }
    let sandbox = match sandbox(&state).await {
        Ok(s) => s,
        Err(e) => {
            // Public endpoint: the provisioning error carries database
            // detail (table names, driver errors) — log it at ERROR and
            // show a generic page instead of propagating it.
            tracing::error!(error = %e, "explorer sandbox provisioning failed");
            return error_page(
                StatusCode::INTERNAL_SERVER_ERROR,
                "The API sandbox is temporarily unavailable. Please try again shortly.",
            );
        }
    };

    let started = std::time::Instant::now();
    let (method, path, status, body) = match form.lane.as_str() {
        "send" => match serde_json::from_str::<serde_json::Value>(&form.body) {
            Err(e) => {
                let body = serde_json::json!({"error": {"code": "invalid_json", "message": format!("{e}")}});
                ("POST", "/v1/messages", 400u16, body)
            }
            Ok(parsed) => match all_recipients_example_com(&parsed) {
                Ok(()) => {
                    // Force from= the sandbox domain when absent (the real
                    // handler enforces ownership of example.com anyway).
                    let mut payload = parsed;
                    if payload
                        .get("from")
                        .and_then(|f| f.as_str())
                        .is_none_or(|f| f.trim().is_empty())
                    {
                        payload["from"] = serde_json::json!("sandbox@example.com");
                    }
                    let json = payload.to_string();
                    let (status, body) = dispatch(
                        &state,
                        Method::POST,
                        "/v1/messages",
                        &sandbox.api_key,
                        Some(&json),
                    )
                    .await;
                    ("POST", "/v1/messages", status, body)
                }
                Err(reason) => {
                    let body = serde_json::json!({"error": {"code": "sandbox_recipient_policy", "message": reason}});
                    ("POST", "/v1/messages", 422, body)
                }
            },
        },
        "messages" => {
            let (status, body) = dispatch(
                &state,
                Method::GET,
                "/v1/messages?limit=20",
                &sandbox.api_key,
                None,
            )
            .await;
            ("GET", "/v1/messages?limit=20", status, body)
        }
        "domains" => {
            let (status, body) =
                dispatch(&state, Method::GET, "/v1/domains", &sandbox.api_key, None).await;
            ("GET", "/v1/domains", status, body)
        }
        "add_domain" => match serde_json::from_str::<serde_json::Value>(&form.body) {
            Err(e) => {
                let body = serde_json::json!({"error": {"code": "invalid_json", "message": format!("{e}")}});
                ("POST", "/v1/domains", 400u16, body)
            }
            Ok(parsed) => {
                if !is_example_com_domain(&parsed) {
                    let body = serde_json::json!({"error": {"code": "sandbox_domain_policy", "message": "The explorer sandbox registers subdomains of example.com only."}});
                    ("POST", "/v1/domains", 422, body)
                } else {
                    let json = parsed.to_string();
                    let (status, body) = dispatch(
                        &state,
                        Method::POST,
                        "/v1/domains",
                        &sandbox.api_key,
                        Some(&json),
                    )
                    .await;
                    ("POST", "/v1/domains", status, body)
                }
            }
        },
        other => {
            let body = serde_json::json!({"error": {"code": "unknown_lane", "message": format!("unknown lane {other:?}")}});
            ("POST", "/explorer/exec", 400, body)
        }
    };
    let latency = started.elapsed().as_millis();
    let outcome = ui_foundation::explorer::ExplorerOutcome {
        method,
        path,
        status,
        latency_ms: latency,
        body,
        request_body: form.body,
    };
    Html(ui_foundation::explorer::explorer_response_page(&outcome)).into_response()
}

fn is_example_com_domain(body: &serde_json::Value) -> bool {
    match body
        .get("name")
        .or_else(|| body.get("domain"))
        .and_then(|n| n.as_str())
    {
        Some(n) => {
            let lower = n.trim().to_ascii_lowercase();
            lower == "example.com" || lower.ends_with(".example.com")
        }
        None => false,
    }
}

fn error_page(status: StatusCode, message: &str) -> Response {
    let outcome = ui_foundation::explorer::ExplorerOutcome {
        method: "POST",
        path: "/explorer/exec",
        status: status.as_u16(),
        latency_ms: 0,
        body: serde_json::json!({"error": {"message": message}}),
        request_body: String::new(),
    };
    (
        status,
        Html(ui_foundation::explorer::explorer_response_page(&outcome)),
    )
        .into_response()
}

// ─────────────────────────────────────────────────────────────────────────────
// Pricing calculator
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Deserialize, Debug, Default)]
pub struct CalculatorForm {
    #[serde(default = "calc_default_volume")]
    pub volume: i64,
    #[serde(default = "calc_default_peak")]
    pub peak_daily: i64,
    #[serde(default = "calc_default_domains")]
    pub domains: i64,
    #[serde(default = "calc_default_users")]
    pub team_users: i64,
    #[serde(default)]
    pub dedicated_ips: i64,
    #[serde(default)]
    pub support: Option<String>,
    #[serde(default = "calc_default_cycle")]
    pub billing_cycle: String,
}
fn calc_default_cycle() -> String {
    "monthly".to_string()
}
fn calc_default_volume() -> i64 {
    50_000
}
fn calc_default_peak() -> i64 {
    2_500
}
fn calc_default_domains() -> i64 {
    2
}
fn calc_default_users() -> i64 {
    3
}

pub async fn calculate(
    State(_state): State<AppState>,
    Form(form): Form<CalculatorForm>,
) -> Response {
    let form = sanitize_calculator(form);
    let lines = compute_calculator(&form);
    let note = format!(
        "Computed with billing-service plan tables (the same source of truth as invoicing). Estimates assume {} sends/month with a {} peak day; plan switches are prorated.",
        format_int(form.volume),
        format_int(form.peak_daily),
    );
    let mut inputs = vec![
        ("volume".to_string(), format_int(form.volume)),
        ("peak daily".to_string(), format_int(form.peak_daily)),
        ("domains".to_string(), format_int(form.domains)),
        ("team users".to_string(), format_int(form.team_users)),
        ("dedicated IPs".to_string(), format_int(form.dedicated_ips)),
        ("billing".to_string(), form.billing_cycle.clone()),
    ];
    if let Some(s) = form.support.as_deref() {
        inputs.push(("support".to_string(), s.to_string()));
    }
    let ui_lines: Vec<ui_foundation::explorer::CalculatorLine> = lines
        .into_iter()
        .map(|l| ui_foundation::explorer::CalculatorLine {
            label: l.0,
            value: l.1,
            emphasis: l.2,
        })
        .collect();
    Html(ui_foundation::explorer::calculator_response_page(
        &inputs, &ui_lines, &note,
    ))
    .into_response()
}

fn sanitize_calculator(mut f: CalculatorForm) -> CalculatorForm {
    f.volume = f.volume.clamp(0, 100_000_000);
    f.peak_daily = f.peak_daily.clamp(0, 50_000_000);
    f.domains = f.domains.clamp(1, 1_000);
    f.team_users = f.team_users.clamp(1, 5_000);
    f.dedicated_ips = f.dedicated_ips.clamp(0, 100);
    if f.billing_cycle != "annual" {
        f.billing_cycle = "monthly".to_string();
    }
    f
}

/// (label, value, emphasized) rows derived from billing_service::plans.
fn compute_calculator(f: &CalculatorForm) -> Vec<(String, String, bool)> {
    let plans = billing_service::plans::default_plans();
    // Cheapest plan whose included volume fits; overage applies beyond it.
    let mut fitting: Vec<&billing_service::plans::PlanSeed> = plans
        .iter()
        .filter(|p| (p.email_limit >= f.volume || p.name == "free") && p.name != "enterprise")
        .collect();
    fitting.sort_by_key(|p| p.price_monthly);
    let chosen: Option<&billing_service::plans::PlanSeed> = fitting
        .iter()
        .find(|p| p.email_limit >= f.volume)
        .copied()
        .or_else(|| plans.iter().find(|p| p.name == "scale"))
        .or_else(|| plans.iter().find(|p| p.name == "free"));
    let mut rows = Vec::new();
    if let Some(plan) = chosen {
        let limit = plan.email_limit.max(0);
        let base = plan.price_monthly;
        let overage = billing_service::plans::calculate_overage_cost(f.volume, limit);
        rows.push((
            format!("Plan — {}", title(plan.name)),
            format!("€{:.2}", base as f64 / 100.0),
            false,
        ));
        rows.push((
            "Included emails / month".to_string(),
            format_int(limit),
            false,
        ));
        if overage > 0 {
            rows.push((
                "Overage".to_string(),
                format!("€{:.2}", overage as f64 / 100.0),
                false,
            ));
        }
        let total = base + overage;
        // Dedicated IP add-on (2026-09-08 pricing): first managed IP
        // €49/mo, each additional €69/mo — on Pro and above.
        let ip_fee = if f.dedicated_ips > 0 && plan.name != "free" && plan.name != "starter" {
            4_900 + (f.dedicated_ips.saturating_sub(1)) * 6_900
        } else {
            0
        };
        if ip_fee > 0 {
            let ip_label = if f.dedicated_ips == 1 {
                "Dedicated IP (1× €49)".to_string()
            } else {
                format!("Dedicated IPs (1× €49 + {}× €69)", f.dedicated_ips - 1)
            };
            rows.push((ip_label, format!("€{:.2}", ip_fee as f64 / 100.0), false));
        } else if f.dedicated_ips > 0 {
            rows.push((
                "Dedicated IPs".to_string(),
                "available on Pro+".to_string(),
                false,
            ));
        }
        let grand = total + ip_fee;
        if f.billing_cycle == "annual" {
            rows.push((
                "Monthly equivalent".to_string(),
                format!("€{:.2}", grand as f64 / 100.0),
                false,
            ));
            rows.push((
                "Annual total (2 months free)".to_string(),
                format!("€{:.2}", (grand * 10) as f64 / 100.0),
                true,
            ));
        } else {
            rows.push((
                "Monthly total".to_string(),
                format!("€{:.2}", grand as f64 / 100.0),
                true,
            ));
            rows.push((
                "Annual alternative".to_string(),
                format!("€{:.2}", (grand * 10) as f64 / 100.0),
                false,
            ));
        }
    } else {
        rows.push((
            "Plan".to_string(),
            "Contact us — Enterprise".to_string(),
            true,
        ));
    }
    rows.push(("Sending domains".to_string(), format_int(f.domains), false));
    rows.push(("Team users".to_string(), format_int(f.team_users), false));
    rows
}

fn title(s: &str) -> String {
    let mut c = s.chars();
    match c.next() {
        Some(f) => f.to_uppercase().collect::<String>() + c.as_str(),
        None => String::new(),
    }
}

fn format_int(n: i64) -> String {
    let mut s = n.to_string();
    let mut i = s.len() as isize - 3;
    while i > 0 {
        s.insert(i as usize, ',');
        i -= 3;
    }
    s
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/explorer/exec", axum::routing::post(exec))
        .route("/explorer/calculate", axum::routing::post(calculate))
        .route("/explorer/grade", axum::routing::post(grade_domain))
}

// ─────────────────────────────────────────────────────────────────────────────
// Email Grader (zero-JS form wrapper)
// ─────────────────────────────────────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct GradeDomainForm {
    #[serde(default)]
    pub domain: String,
}

/// Strip the noise users paste into a "your domain" box: schemes, paths,
/// ports, credentials, surrounding dots. Lowercased.
fn clean_domain_input(raw: &str) -> String {
    let mut d = raw.trim().to_ascii_lowercase();
    for scheme in ["https://", "http://"] {
        if let Some(rest) = d.strip_prefix(scheme) {
            d = rest.to_string();
            break;
        }
    }
    // Pasted email / MAIL FROM shape: keep only the host.
    if let Some((_, host)) = d.rsplit_once('@') {
        d = host.to_string();
    }
    for sep in ['/', ':', '?', '#'] {
        if let Some((host, _)) = d.split_once(sep) {
            d = host.to_string();
        }
    }
    d.trim_matches('.').trim().to_string()
}

pub async fn grade_domain(
    State(state): State<AppState>,
    connect_info: Option<axum::extract::ConnectInfo<std::net::SocketAddr>>,
    headers: axum::http::HeaderMap,
    Form(form): Form<GradeDomainForm>,
) -> Response {
    // Same trusted-proxy IP walk and Redis budget as the sandbox lanes.
    let bucket_ip = match connect_info {
        Some(axum::extract::ConnectInfo(addr)) => {
            client_ip(&headers, addr.ip(), &state.config.trusted_proxies)
        }
        None => "unknown".to_string(),
    };
    if !rate_limit(&state, &bucket_ip).await {
        return grader_error_page(
            StatusCode::TOO_MANY_REQUESTS,
            "",
            "RATE_LIMITED",
            "Too many checks — try again in a minute.",
        );
    }
    let domain = clean_domain_input(&form.domain);
    if domain.is_empty()
        || domain.len() > 253
        || !domain.contains('.')
        || domain.chars().any(|c| c.is_whitespace())
    {
        return grader_error_page(
            StatusCode::BAD_REQUEST,
            &domain,
            "INVALID_INPUT",
            "Enter a real domain you send from, like yourcompany.com.",
        );
    }
    let gs = match state.grader_state.clone() {
        Some(s) => s,
        None => {
            return grader_error_page(
                StatusCode::SERVICE_UNAVAILABLE,
                &domain,
                "GRADER_DISABLED",
                "The Email Grader is temporarily unavailable.",
            )
        }
    };
    let client_ip_addr: std::net::IpAddr = bucket_ip
        .parse()
        .unwrap_or_else(|_| "0.0.0.0".parse().expect("static ip literal"));
    // Delegate to the canonical transport-agnostic handler — enabled flag,
    // per-IP engine rate limit, error mapping and scoring all stay in ONE
    // place, identical to the /v1/grader/check JSON API.
    let (status, axum::Json(value)) = email_grader::routes::check_domain(
        gs,
        client_ip_addr,
        email_grader::DomainCheckRequest {
            domain: domain.clone(),
            selectors: Vec::new(),
        },
    )
    .await;
    if status == StatusCode::OK {
        Html(ui_foundation::explorer::grader_response_page(&value)).into_response()
    } else {
        let code = value
            .pointer("/error/code")
            .and_then(|v| v.as_str())
            .unwrap_or("GRADER_ERROR");
        // Public endpoint: the engine's messages are already
        // user-facing (map_grader_error), but never leak anything raw.
        let message = value
            .pointer("/error/message")
            .and_then(|v| v.as_str())
            .unwrap_or("The check could not be completed.");
        grader_error_page(status, &domain, code, message)
    }
}

fn grader_error_page(status: StatusCode, domain: &str, code: &str, message: &str) -> Response {
    (
        status,
        Html(ui_foundation::explorer::grader_error_page(
            domain, code, message,
        )),
    )
        .into_response()
}

// A HeaderName import keeps clippy from flagging the unused-headers path.
#[allow(unused)]
fn _header_guard(n: HeaderName) -> HeaderValue {
    HeaderValue::from_static("x")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn client_ip_ignores_forwarded_for_from_untrusted_peers() {
        // A spoofed X-Forwarded-For from a directly-connected (untrusted)
        // peer must NOT choose the rate-limit bucket: the socket address
        // is the only honest signal when the peer is not a configured
        // proxy.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("6.6.6.6, 7.7.7.7"),
        );
        let bucket = client_ip(
            &headers,
            "203.0.113.9:44321"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .ip(),
            &[],
        );
        assert_eq!(
            bucket, "203.0.113.9",
            "spoofed XFF must not pick the bucket"
        );

        // From a TRUSTED proxy, the rightmost untrusted XFF entry wins.
        let mut headers = axum::http::HeaderMap::new();
        headers.insert(
            "x-forwarded-for",
            axum::http::HeaderValue::from_static("6.6.6.6, 198.51.100.7"),
        );
        let bucket = client_ip(
            &headers,
            "10.0.0.2:44321"
                .parse::<std::net::SocketAddr>()
                .unwrap()
                .ip(),
            &["10.0.0.0/8".to_string()],
        );
        assert_eq!(bucket, "198.51.100.7");
    }

    #[test]
    fn recipient_policy_accepts_only_example_com() {
        let ok =
            serde_json::json!({"to": ["a@example.com", "B@Example.COM"], "cc": ["c@example.com"]});
        assert!(all_recipients_example_com(&ok).is_ok());
        let bad = serde_json::json!({"to": ["a@evil.com"]});
        assert!(all_recipients_example_com(&bad).is_err());
        let bad_cc = serde_json::json!({"to": ["a@example.com"], "bcc": ["x@gmail.com"]});
        assert!(all_recipients_example_com(&bad_cc).is_err());
        let missing = serde_json::json!({"subject": "hi"});
        assert!(all_recipients_example_com(&missing).is_ok()); // real handler rejects missing to
    }

    #[test]
    fn domain_policy_rejects_non_example() {
        assert!(is_example_com_domain(
            &serde_json::json!({"name": "shop.example.com"})
        ));
        assert!(is_example_com_domain(
            &serde_json::json!({"name": "example.com"})
        ));
        assert!(!is_example_com_domain(
            &serde_json::json!({"name": "evil.com"})
        ));
        assert!(!is_example_com_domain(
            &serde_json::json!({"name": "evilexample.com"})
        ));
    }

    #[test]
    fn calculator_clamps_and_formats() {
        let f = sanitize_calculator(CalculatorForm {
            volume: -5,
            peak_daily: 10_000_000_000,
            domains: 0,
            dedicated_ips: 0,
            support: None,
            billing_cycle: String::new(),
            team_users: 99_999,
        });
        assert_eq!(f.volume, 0);
        assert_eq!(f.peak_daily, 50_000_000);
        assert_eq!(f.domains, 1);
        assert_eq!(f.team_users, 5_000);
        assert_eq!(format_int(1_234_567), "1,234,567");
    }

    #[test]
    fn calculator_picks_cheapest_fitting_plan() {
        let f = CalculatorForm {
            volume: 40_000,
            peak_daily: 2_000,
            domains: 1,
            team_users: 1,
            ..Default::default()
        };
        let rows = compute_calculator(&f);
        let plan_row = rows
            .iter()
            .find(|r| r.0.starts_with("Plan —"))
            .expect("plan row");
        assert!(
            plan_row.0.contains("Starter") || plan_row.0.contains("Free"),
            "{plan_row:?}"
        );
        let total = rows.iter().find(|r| r.0 == "Monthly total").expect("total");
        assert!(total.1.starts_with("€"));
    }

    #[test]
    fn grade_form_strips_pasted_url_noise() {
        assert_eq!(clean_domain_input("  YourCompany.COM "), "yourcompany.com");
        assert_eq!(
            clean_domain_input("https://yourcompany.com/pricing"),
            "yourcompany.com"
        );
        assert_eq!(
            clean_domain_input("http://user@sub.yourcompany.com:8443/x?q=1"),
            "sub.yourcompany.com"
        );
        assert_eq!(
            clean_domain_input("news@yourcompany.com"),
            "yourcompany.com"
        );
        assert_eq!(clean_domain_input(".yourcompany.com."), "yourcompany.com");
        // Empty stays empty — the handler rejects it with INVALID_INPUT.
        assert_eq!(clean_domain_input("   "), "");
    }
}
