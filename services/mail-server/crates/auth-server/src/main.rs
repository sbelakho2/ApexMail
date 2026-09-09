//! ApexMail status server (deployed as the public `status.apexmail.ee`
//! backend, image `status-server`).
//!
//! SECURITY: this binary is exposed to the public internet through nginx
//! (`location /` on the status vhost) and on the internal Docker networks.
//! The router must expose ONLY the status page (`/status`), the status API
//! (`/status/api`), the status history (`/status/history`) and the health
//! probe (`/v1/health`). The former auth / register / MFA / API-key /
//! billing / admin / sandbox routes were removed from the router on
//! purpose — do NOT re-add them here. Interactive auth lives in the
//! api-server crate; nginx additionally refuses every other path.

use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Json},
    routing::get,
    Router,
};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use std::net::SocketAddr;

#[derive(Clone)]
struct AppState {
    db: sqlx::PgPool,
    session_secret: String,
}

// ─── Session tokens ────────────────────────────────────────
//
// These helpers (and the login/register handlers further down) are retained
// with their security fixes applied, but they are intentionally NOT wired
// into the router — see the crate docs above. `#[allow(dead_code)]` marks
// everything that is only kept for the day a route is deliberately
// re-exposed.

/// Maximum age of a session token (24h), matching the cookie Max-Age.
/// The token carries a mint timestamp that is signed but MUST also be
/// checked: without the expiry check below a leaked token was valid forever.
const SESSION_MAX_AGE_SECS: u64 = 24 * 60 * 60;

/// Tolerated clock skew for tokens stamped slightly in the future
/// (container clock drift). Anything further ahead is rejected.
const SESSION_MAX_CLOCK_SKEW_SECS: u64 = 300;

#[allow(dead_code)]
#[derive(Deserialize)]
struct LoginForm {
    username_or_email: String,
    password: String,
}

#[allow(dead_code)]
#[derive(Deserialize)]
struct RegisterForm {
    name: Option<String>,
    email: String,
    password: String,
}

#[allow(dead_code)]
fn extract_session_email(headers: &axum::http::HeaderMap, secret: &str) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if let Some(token) = part.strip_prefix("apexmail_session=") {
            return verify_session_token(token, secret);
        }
    }
    None
}

fn verify_session_token(token: &str, secret: &str) -> Option<String> {
    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() != 3 {
        return None;
    }
    let email = parts[0];
    let ts_raw = parts[1];
    let sig = parts[2];

    // Enforce the token's lifetime: reject expired (and far-future) tokens.
    let ts: u64 = ts_raw.parse().ok()?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default()
        .as_secs();
    if now.saturating_sub(ts) > SESSION_MAX_AGE_SECS {
        return None;
    }
    if ts.saturating_sub(now) > SESSION_MAX_CLOCK_SKEW_SECS {
        return None;
    }

    use sha2::{Digest, Sha256};
    let mut h = Sha256::new();
    h.update(format!("{email}:{ts_raw}:{secret}").as_bytes());
    let expected = hex::encode(h.finalize());
    // Constant-time MAC comparison — a plain `==` short-circuits and leaks a
    // byte-by-byte timing oracle on the signature.
    if apexmail_lib::timing_safe_compare(&expected, sig) {
        Some(email.to_string())
    } else {
        None
    }
}

fn create_session_token(email: &str, secret: &str) -> String {
    use sha2::{Digest, Sha256};
    let ts = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut h = Sha256::new();
    h.update(format!("{email}:{ts}:{secret}").as_bytes());
    format!("{email}:{ts}:{}", hex::encode(h.finalize()))
}

/// True when running with ENVIRONMENT=production|prod (the convention used
/// by api-server's config; dev defaults to development).
fn is_production_env() -> bool {
    matches!(
        std::env::var("ENVIRONMENT")
            .unwrap_or_default()
            .to_lowercase()
            .as_str(),
        "production" | "prod"
    )
}

fn session_cookie(token: &str) -> String {
    // `Secure` in production so the cookie is never sent over plain HTTP.
    let secure = if is_production_env() { "; Secure" } else { "" };
    format!("apexmail_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age={SESSION_MAX_AGE_SECS}{secure}")
}

// ─── Auth endpoints (NOT routed — see crate docs) ──────────

#[allow(dead_code)]
async fn login_post(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(form): axum::Json<LoginForm>,
) -> impl IntoResponse {
    let identifier = form.username_or_email.trim().to_lowercase();
    let is_cp = headers
        .get("x-apexmail-surface")
        .and_then(|v| v.to_str().ok())
        .map(|v| v == "control-plane")
        .unwrap_or(false);
    // Look up by email ONLY — the `users` table has no `username` column, so
    // the old `WHERE username = $1 OR email = $1` made every login fail with
    // a database error (column does not exist).
    let row = sqlx::query_as::<_, (sqlx::types::Uuid, String, String, String)>(
        "SELECT id, password_hash, role, email FROM users WHERE email = $1 LIMIT 1",
    )
    .bind(&identifier)
    .fetch_optional(&state.db)
    .await;

    let (email, valid) = match row {
        Ok(Some((_, hash, _, email))) => (
            email,
            argon2::PasswordHash::new(&hash)
                .and_then(|h| Argon2::default().verify_password(form.password.as_bytes(), &h))
                .is_ok(),
        ),
        _ => (String::new(), false),
    };

    if valid {
        let token = create_session_token(&email, &state.session_secret);
        let cookie = session_cookie(&token);
        let redirect = if is_cp {
            "/cp-admin/dashboard/"
        } else {
            "/dashboard"
        };
        let mut resp = Json(serde_json::json!({
            "message": "Login successful",
            "redirect": redirect,
            "user": {"email": email}
        }))
        .into_response();
        resp.headers_mut()
            .insert(header::SET_COOKIE, cookie.parse().unwrap());
        resp
    } else {
        (
            StatusCode::UNAUTHORIZED,
            Json(serde_json::json!({"error": "Invalid username or password"})),
        )
            .into_response()
    }
}

#[allow(dead_code)]
async fn register_post(
    State(state): State<AppState>,
    axum::Json(form): axum::Json<RegisterForm>,
) -> impl IntoResponse {
    let email = form.email.trim().to_lowercase();
    if !email.contains('@') || !email.contains('.') {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Invalid email"})),
        )
            .into_response();
    }
    if form.password.len() < 12 {
        return (
            StatusCode::BAD_REQUEST,
            Json(serde_json::json!({"error": "Password must be 12+ characters"})),
        )
            .into_response();
    }
    if let Ok(Some(_)) = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE email = $1")
        .bind(&email)
        .fetch_optional(&state.db)
        .await
    {
        return (
            StatusCode::CONFLICT,
            Json(serde_json::json!({"error": "Email already registered"})),
        )
            .into_response();
    }

    // Enforce Free plan quota: reject new free plan registrations if global free tenant
    // count exceeds the 30,000 email/month aggregate safety threshold. This is a blunt
    // gate — per-tenant usage is enforced by the billing_usage endpoint.
    let free_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenants WHERE plan = 'free' AND status = 'active'",
    )
    .fetch_one(&state.db)
    .await
    .unwrap_or(0);
    let free_limit: i64 = std::env::var("FREE_TENANT_LIMIT")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(50000);
    if free_count >= free_limit {
        return (StatusCode::SERVICE_UNAVAILABLE,
            Json(serde_json::json!({"error": "Free plan is at capacity. Please try again later or contact sales for a paid plan."}))
        ).into_response();
    }

    let salt = SaltString::generate(&mut OsRng);
    let hash = Argon2::default()
        .hash_password(form.password.as_bytes(), &salt)
        .unwrap()
        .to_string();
    let user_id = sqlx::types::Uuid::new_v4();
    let tenant_id = &uuid::Uuid::new_v4().to_string()[..26];

    let _ = sqlx::query("INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) VALUES ($1, $2, $3, 'free', 'active', NOW(), NOW()) ON CONFLICT DO NOTHING")
        .bind(tenant_id).bind(email.split('@').next().unwrap_or("user")).bind(tenant_id).execute(&state.db).await;
    let _ = sqlx::query("INSERT INTO users (id, tenant_id, email, password_hash, role, mfa_enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, 'owner', false, NOW(), NOW())")
        .bind(user_id).bind(tenant_id).bind(&email).bind(&hash).execute(&state.db).await;

    let token = create_session_token(&email, &state.session_secret);
    let cookie = session_cookie(&token);
    let mut resp = Json(serde_json::json!({
        "message": "Account created",
        "redirect": "/login"
    }))
    .into_response();
    resp.headers_mut()
        .insert(header::SET_COOKIE, cookie.parse().unwrap());
    resp
}

// ─── Probe helpers ─────────────────────────────────────────

/// Extract (host, port) from a service URL such as
/// `redis://:password@redis:6379/0`, falling back to `default_port` when the
/// URL carries no explicit port.
#[allow(dead_code)]
fn url_host_port(raw: &str, default_port: u16) -> Option<(String, u16)> {
    let parsed = url::Url::parse(raw).ok()?;
    let host = parsed.host_str()?.to_string();
    if host.is_empty() {
        return None;
    }
    let port = parsed.port().unwrap_or(default_port);
    Some((host, port))
}

/// Real TCP connectivity probe: true when a connection to `host:port` can be
/// established within `timeout`.
async fn tcp_connect_ok(host: &str, port: u16, timeout: std::time::Duration) -> bool {
    match tokio::time::timeout(timeout, tokio::net::TcpStream::connect((host, port))).await {
        Ok(Ok(_)) => true,
        Ok(Err(_)) | Err(_) => false,
    }
}

// ─── Status page ───────────────────────────────────────────

async fn status_page(State(state): State<AppState>) -> impl IntoResponse {
    // SSR the REAL probe state (review SS42/SS52): the crawler/first paint
    // sees actual health and a last-checked timestamp — never "Loading…".
    // The inline script only refreshes periodically; if its fetch fails the
    // server-rendered state remains visible with the original timestamp.
    let (services, all_operational) = probe_services(&state).await;
    let updated = chrono::Utc::now().format("%Y-%m-%d %H:%M UTC");

    let esc = |v: &str| -> String {
        v.replace('&', "&amp;")
            .replace('<', "&lt;")
            .replace('>', "&gt;")
    };
    let mut cards = String::new();
    let mut operational = 0usize;
    for svc in &services {
        let name = svc["name"].as_str().unwrap_or("service");
        let status = svc["status"].as_str().unwrap_or("unknown");
        let cls = match status {
            "operational" | "connected" => {
                operational += 1;
                "ok"
            }
            "degraded" => "warn",
            _ => "err",
        };
        cards.push_str(&format!(
            "<div class=card><h3>{}</h3><div class=\"status {}\">{}</div><div class=meta>checked {}</div></div>",
            esc(name), cls, esc(status), updated
        ));
    }
    let total = services.len().max(1);
    let pct = (operational * 100 / total) as i64;
    let (overall_msg, overall_cls) = if pct == 100 {
        ("All systems operational", "ok")
    } else if pct >= 80 {
        ("Minor degradation", "warn")
    } else {
        ("Service disruption", "err")
    };

    let html = format!(
        r##"<!DOCTYPE html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>ApexMail Status</title>
<style>:root{{--brand:#ef4444;--bg:#f8f9fa;--card:#fff;--border:#e9ecef;--text:#0f1117;--muted:#6b7280;--success:#059669;--warning:#d97706;--error:#dc2626}}*,*::before,*::after{{box-sizing:border-box;margin:0;padding:0}}body{{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);max-width:900px;margin:0 auto;padding:40px 20px}}h1{{font-size:22px;font-weight:700;margin-bottom:4px}}h1 span{{color:var(--brand)}}h1+p{{color:var(--muted);font-size:14px;margin-bottom:32px}}.grid{{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}}.card{{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px}}.card h3{{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:8px}}.card .status{{font-size:14px;font-weight:600;margin-bottom:4px}}.card .meta{{font-size:12px;color:var(--muted)}}.ok{{color:var(--success)}}.warn{{color:var(--warning)}}.err{{color:var(--error)}}.overall{{text-align:center;margin-bottom:24px;padding:20px;background:var(--card);border:1px solid var(--border);border-radius:10px}}.overall .big{{font-size:36px;font-weight:700}}.bar{{height:4px;background:var(--border);border-radius:2px;margin-top:12px;overflow:hidden}}.bar-fill{{height:100%;border-radius:2px;transition:width .3s}}footer{{text-align:center;margin-top:40px;font-size:12px;color:var(--muted)}}</style></head><body>
<h1><span>Apex</span>Mail Status</h1><p>Live service health — probes run every 60 seconds. <span id=updated style=color:var(--muted)>Last checked {updated}</span></p>
<div class=overall id=overall><div class="big {overall_cls}" id=big>{pct}%</div><div id=msg style=font-size:14px;color:var(--muted)>{overall_msg}</div></div>
<div class=grid id=grid>{cards}</div>
<div class=bar><div class=bar-fill id=bar style=width:{pct}%></div></div>
<footer>ApexMail — Bel Consulting OÜ, Registry 16588745</footer>
<script>
async function check(){{try{{var r=await fetch("/status/api"),d=await r.json();var ok=0,g=document.getElementById("grid"),h="";d.services.forEach(function(s){{var cls=s.status==="operational"||s.status==="connected"?"ok":s.status==="degraded"?"warn":"err";if(cls==="ok"||cls==="warn")ok++;h+="<div class=card><h3>"+s.name+"</h3><div class=\"status "+cls+"\">"+s.status+"</div><div class=meta>checked "+d.updated+"</div></div>"}});g.innerHTML=h;var pct=(ok/d.services.length*100).toFixed(0);document.getElementById("big").textContent=pct+"%";document.getElementById("bar").style.width=pct+"%";document.getElementById("big").className="big "+(pct==100?"ok":pct>=80?"warn":"err");document.getElementById("msg").textContent=pct==100?"All systems operational":pct>=80?"Minor degradation":"Service disruption";document.getElementById("updated").textContent="Last checked "+d.updated}}catch(ex){{/* keep the server-rendered state visible */}}}}
check();setInterval(check,60000)
</script></body></html>"##,
        updated = updated,
        overall_cls = overall_cls,
        overall_msg = overall_msg,
        pct = pct,
        cards = cards,
    );
    (
        StatusCode::OK,
        [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")],
        html,
    )
        .into_response()
}

// ─── Health endpoint ─────────────────────────────────────
//
// G.6: /v1/health is reachable from the public internet via nginx, so the
// payload must NOT leak queue internals (email_queue depth, backlog state).
// It reports ok/error + version only; richer (still non-sensitive) service
// probes live on /status/api, which is the status page's purpose.

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    // Database connectivity check — the only dependency whose failure makes
    // the service itself unable to answer authoritatively.
    let db_ok = sqlx::query_scalar::<_, i64>("SELECT 1::bigint")
        .fetch_one(&state.db)
        .await
        .is_ok();

    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": if db_ok { "ok" } else { "error" },
            "version": env!("CARGO_PKG_VERSION"),
        })),
    )
        .into_response()
}

async fn status_api(State(state): State<AppState>) -> impl IntoResponse {
    let (services, all_operational) = probe_services(&state).await;
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "status": if all_operational { "operational" } else { "degraded" },
            "services": services,
            "updated": chrono::Utc::now().to_rfc3339()
        })),
    )
        .into_response()
}

/// The shared probe set (review 2026-09-09 SS42/SS52): consumed by BOTH the
/// JSON API and the server-rendered status page so the SSR output is real
/// health, never a Loading placeholder.
async fn probe_services(state: &AppState) -> (Vec<serde_json::Value>, bool) {
    let mut services = Vec::new();
    let mut all_operational = true;

    // Probe database connectivity with a lightweight query.
    // `SELECT 1::bigint` (not `SELECT 1`): sqlx 0.8 type-checks scalars and
    // i64 is incompatible with the INT4 column type of a bare `SELECT 1`.
    let db_ok = sqlx::query_scalar::<_, i64>("SELECT 1::bigint")
        .fetch_one(&state.db)
        .await
        .is_ok();
    services.push(serde_json::json!({
        "name": "Database", "status": if db_ok { "operational" } else { "degraded" }
    }));
    if !db_ok {
        all_operational = false;
    }

    // Probe tenant table health
    let tenants_ok =
        sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tenants WHERE status = 'active'")
            .fetch_one(&state.db)
            .await
            .is_ok();
    services.push(serde_json::json!({
        "name": "Tenants API", "status": if tenants_ok { "operational" } else { "degraded" }
    }));
    if !tenants_ok {
        all_operational = false;
    }

    // Probe message throughput (last 5 minutes)
    let messages_ok = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM messages WHERE created_at > NOW() - INTERVAL '5 minutes'",
    )
    .fetch_one(&state.db)
    .await
    .is_ok();
    services.push(serde_json::json!({
        "name": "Message Pipeline", "status": if messages_ok { "operational" } else { "degraded" }
    }));
    if !messages_ok {
        all_operational = false;
    }

    // Probe auth functionality by checking user count
    let auth_ok = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db)
        .await
        .is_ok();
    services.push(serde_json::json!({
        "name": "Auth Server", "status": if auth_ok { "operational" } else { "degraded" }
    }));
    if !auth_ok {
        all_operational = false;
    }

    // Probe billing/subscription data
    let billing_ok = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM plans")
        .fetch_one(&state.db)
        .await
        .is_ok();
    services.push(serde_json::json!({
        "name": "Billing API", "status": if billing_ok { "operational" } else { "degraded" }
    }));
    if !billing_ok {
        all_operational = false;
    }

    // Probe message delivery stats (analytics)
    let analytics_ok = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM messages WHERE status = 'delivered' AND created_at > NOW() - INTERVAL '1 hour'"
    ).fetch_one(&state.db).await.is_ok();
    services.push(serde_json::json!({
        "name": "Analytics API", "status": if analytics_ok { "operational" } else { "degraded" }
    }));
    if !analytics_ok {
        all_operational = false;
    }

    // Real SMTP probe: attempt a TCP connection to the configured mail host
    // (MAIL_HOST env, default mail.apexmail.ee) on port 25 within 3s.
    let smtp_host = std::env::var("MAIL_HOST")
        .ok()
        .filter(|s| !s.is_empty())
        .unwrap_or_else(|| "mail.apexmail.ee".to_string());
    let smtp_ok = tcp_connect_ok(&smtp_host, 25, std::time::Duration::from_secs(3)).await;
    services.push(serde_json::json!({
        "name": "Mail Server (SMTP)", "status": if smtp_ok { "operational" } else { "degraded" }
    }));
    if !smtp_ok {
        all_operational = false;
    }

    (services, all_operational)
}

async fn status_history() -> impl IntoResponse {
    (
        StatusCode::OK,
        Json(serde_json::json!({
            "history": [],
            "updated": chrono::Utc::now().to_rfc3339()
        })),
    )
        .into_response()
}

#[tokio::main]
async fn main() {
    // G.6: DATABASE_URL must be provided — the previous embedded default
    // (postgres://apexmail@127.0.0.1:5432/apexmail) silently pointed
    // misconfigured deployments at a host that may not exist.
    let db_url = resolve_database_url();
    let session_secret = resolve_session_secret();

    let pool = PgPoolOptions::new()
        .max_connections(5)
        .connect(&db_url)
        .await
        .unwrap();

    let state = AppState {
        db: pool,
        session_secret,
    };

    // SECURITY: status-only surface. Every route added here is reachable
    // from the public internet via nginx — see the crate docs.
    let app = Router::new()
        .route("/v1/health", get(health_check))
        .route("/status", get(status_page))
        .route("/status/api", get(status_api))
        .route("/status/history", get(status_history))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Status server on {addr}");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app)
        .await
        .unwrap();
}

/// G.6: require DATABASE_URL — no credential-bearing embedded fallback.
fn resolve_database_url() -> String {
    match std::env::var("DATABASE_URL") {
        Ok(url) if !url.trim().is_empty() => url,
        _ => panic!("DATABASE_URL must be set (no embedded default is provided)"),
    }
}

/// G.6: SESSION_SECRET is REQUIRED in production (the random-UUID fallback
/// invalidated all sessions on every restart and was never operator
/// controlled); development keeps the fallback with a loud warning.
fn resolve_session_secret() -> String {
    match std::env::var("SESSION_SECRET") {
        Ok(secret) if !secret.trim().is_empty() => secret,
        _ => {
            if is_production_env() {
                panic!("SESSION_SECRET must be set in production (ENVIRONMENT=production)");
            }
            let fallback = uuid::Uuid::new_v4().to_string();
            eprintln!(
                "WARNING: SESSION_SECRET is not set — using a random per-process value. \
                 All sessions are invalidated on restart; set SESSION_SECRET for stability."
            );
            fallback
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes env-mutating tests.
    static ENV_LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());

    fn fake_state() -> AppState {
        let db = PgPoolOptions::new()
            .max_connections(1)
            .connect_lazy("postgres://fake:fake@localhost:1/fake")
            .unwrap();
        AppState {
            db,
            session_secret: "test-secret".into(),
        }
    }

    /// G.6: the public /v1/health payload must contain ONLY ok/error status
    /// and the version — no queue depth, no service internals.
    #[tokio::test]
    async fn health_payload_has_no_queue_internals() {
        let response = health_check(State(fake_state())).await.into_response();
        assert_eq!(response.status(), StatusCode::OK);
        let body = axum::body::to_bytes(response.into_body(), 64 * 1024)
            .await
            .unwrap();
        let json: serde_json::Value = serde_json::from_slice(&body).unwrap();
        assert!(json.get("status").is_some(), "status required");
        assert!(json.get("version").is_some(), "version required");
        for banned in ["queue_depth", "services", "depth", "timestamp"] {
            assert!(json.get(banned).is_none(), "{banned} must not appear");
        }
    }

    /// G.6: no embedded DATABASE_URL fallback.
    #[test]
    fn database_url_is_required() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved = std::env::var("DATABASE_URL").ok();
        std::env::remove_var("DATABASE_URL");
        let result = std::panic::catch_unwind(resolve_database_url);
        if let Some(value) = saved {
            std::env::set_var("DATABASE_URL", value);
        }
        assert!(
            result.is_err(),
            "missing DATABASE_URL must be a hard startup error"
        );
    }

    /// G.6: SESSION_SECRET is required in production, random fallback only
    /// in development.
    #[test]
    fn session_secret_required_in_production() {
        let _guard = ENV_LOCK.lock().unwrap_or_else(|e| e.into_inner());
        let saved_secret = std::env::var("SESSION_SECRET").ok();
        let saved_env = std::env::var("ENVIRONMENT").ok();
        std::env::remove_var("SESSION_SECRET");

        std::env::set_var("ENVIRONMENT", "production");
        let prod = std::panic::catch_unwind(resolve_session_secret);
        assert!(prod.is_err(), "production must refuse the UUID fallback");

        std::env::set_var("ENVIRONMENT", "development");
        let dev = resolve_session_secret();
        assert!(!dev.is_empty(), "dev keeps the warned fallback");

        match saved_secret {
            Some(v) => std::env::set_var("SESSION_SECRET", v),
            None => std::env::remove_var("SESSION_SECRET"),
        }
        match saved_env {
            Some(v) => std::env::set_var("ENVIRONMENT", v),
            None => std::env::remove_var("ENVIRONMENT"),
        }
    }
}
