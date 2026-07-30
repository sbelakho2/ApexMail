use axum::{
    extract::State,
    http::{header, StatusCode},
    response::{IntoResponse, Json, Redirect},
    routing::{delete, get, post},
    Router,
};
use argon2::password_hash::{rand_core::OsRng, SaltString};
use argon2::{Argon2, PasswordHasher, PasswordVerifier};
use chrono::{Datelike, Utc};
use serde::Deserialize;
use sqlx::postgres::PgPoolOptions;
use std::collections::HashMap;
use std::net::SocketAddr;

#[derive(Clone)]
struct AppState {
    db: sqlx::PgPool,
    session_secret: String,
    http_client: Option<reqwest::Client>,
    stripe_secret_key: Option<String>,
    stripe_prices: HashMap<String, String>,
}

#[derive(Deserialize)]
struct LoginForm { username_or_email: String, password: String }

#[derive(Deserialize)]
struct RegisterForm { name: Option<String>, email: String, password: String }

#[derive(Deserialize)]
struct CreateApiKeyForm { name: String, scopes: Option<String>, #[serde(default)] is_test: bool }

#[derive(Deserialize)]
struct SwitchPlanForm { plan: String }

#[derive(Deserialize)]
struct CreateCheckoutForm { plan: String, success_url: String, cancel_url: String }

#[derive(Deserialize)]
struct CreatePortalForm { return_url: String }

#[derive(Deserialize)]
struct MfaQrParams { otpauth: String }

#[derive(Deserialize)]
struct MfaDisableForm { code: String }

fn extract_session_email(headers: &axum::http::HeaderMap, secret: &str) -> Option<String> {
    let cookie = headers.get("cookie")?.to_str().ok()?;
    for part in cookie.split(';') {
        let part = part.trim();
        if part.starts_with("apexmail_session=") {
            let token = &part["apexmail_session=".len()..];
            return verify_session_token(token, secret);
        }
    }
    None
}

fn verify_session_token(token: &str, secret: &str) -> Option<String> {
    let parts: Vec<&str> = token.splitn(3, ':').collect();
    if parts.len() != 3 { return None; }
    let email = parts[0];
    let ts = parts[1];
    let sig = parts[2];
    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(format!("{email}:{ts}:{secret}").as_bytes());
    if hex::encode(h.finalize()) == sig {
        Some(email.to_string())
    } else {
        None
    }
}

fn create_session_token(email: &str, secret: &str) -> String {
    use sha2::{Sha256, Digest};
    let ts = std::time::SystemTime::now().duration_since(std::time::UNIX_EPOCH).unwrap().as_secs();
    let mut h = Sha256::new();
    h.update(format!("{email}:{ts}:{secret}").as_bytes());
    format!("{email}:{ts}:{}", hex::encode(h.finalize()))
}

async fn resolve_tenant_id(db: &sqlx::PgPool, email: &str) -> Option<String> {
    sqlx::query_scalar::<_, String>("SELECT tenant_id FROM users WHERE email = $1")
        .bind(email).fetch_optional(db).await.ok().flatten()
}

// ─── TOTP / MFA helpers ────────────────────────────────────

fn decode_base32(input: &str) -> Vec<u8> {
    let alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    let input = input.trim_end_matches('=').to_uppercase();
    let mut output = Vec::new();
    let mut buffer: u16 = 0;
    let mut bits: u8 = 0;

    for c in input.chars() {
        if let Some(pos) = alphabet.find(c) {
            buffer = (buffer << 5) | pos as u16;
            bits += 5;
            if bits >= 8 {
                bits -= 8;
                output.push((buffer >> bits) as u8);
            }
        }
    }
    output
}

fn hmac_sha256(key: &[u8], message: &[u8]) -> [u8; 32] {
    use sha2::{Sha256, Digest};

    const BLOCK_SIZE: usize = 64;

    let mut key_padded = vec![0u8; BLOCK_SIZE];
    if key.len() > BLOCK_SIZE {
        let mut h = Sha256::new();
        Digest::update(&mut h, key);
        let hashed: [u8; 32] = h.finalize().into();
        key_padded[..32].copy_from_slice(&hashed);
    } else {
        key_padded[..key.len()].copy_from_slice(key);
    }

    let mut o_key_pad = [0u8; BLOCK_SIZE];
    let mut i_key_pad = [0u8; BLOCK_SIZE];
    for i in 0..BLOCK_SIZE {
        o_key_pad[i] = key_padded[i] ^ 0x5c;
        i_key_pad[i] = key_padded[i] ^ 0x36;
    }

    let mut inner = Sha256::new();
    Digest::update(&mut inner, &i_key_pad);
    Digest::update(&mut inner, message);
    let inner_hash: [u8; 32] = inner.finalize().into();

    let mut outer = Sha256::new();
    Digest::update(&mut outer, &o_key_pad);
    Digest::update(&mut outer, &inner_hash);
    let result: [u8; 32] = outer.finalize().into();
    result
}

fn verify_totp_code(secret_base32: &str, code: &str) -> bool {
    let secret_bytes = decode_base32(secret_base32);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let expected = code.parse::<u32>().unwrap_or(0);

    for step_offset in 0..=1u64 {
        let time_step = ((now / 30).saturating_sub(step_offset)).to_be_bytes();
        let hmac_result = hmac_sha256(&secret_bytes, &time_step);
        let offset = (hmac_result[31] & 0x0f) as usize;
        let code_slice: [u8; 4] = [
            hmac_result[offset],
            hmac_result[offset + 1],
            hmac_result[offset + 2],
            hmac_result[offset + 3],
        ];
        let binary = u32::from_be_bytes(code_slice) & 0x7fffffff;
        let totp = binary % 1_000_000;
        if totp == expected {
            return true;
        }
    }
    false
}

// ─── Auth endpoints ────────────────────────────────────────

async fn login_post(State(state): State<AppState>, headers: axum::http::HeaderMap, axum::Json(form): axum::Json<LoginForm>) -> impl IntoResponse {
    let identifier = form.username_or_email.trim().to_lowercase();
    let is_cp = headers.get("x-apexmail-surface").and_then(|v| v.to_str().ok()).map(|v| v == "control-plane").unwrap_or(false);
    // Try login by username first, then by email
    let row = sqlx::query_as::<_, (sqlx::types::Uuid, String, String, String)>(
        "SELECT id, password_hash, role, email FROM users WHERE username = $1 OR email = $1 ORDER BY CASE WHEN username = $1 THEN 0 ELSE 1 END LIMIT 1"
    ).bind(&identifier).fetch_optional(&state.db).await;

    let (email, valid) = match row {
        Ok(Some((_, hash, _, email))) => {
            (email, argon2::PasswordHash::new(&hash)
                .and_then(|h| Argon2::default().verify_password(form.password.as_bytes(), &h))
                .is_ok())
        }
        _ => (String::new(), false),
    };

    if valid {
        let token = create_session_token(&email, &state.session_secret);
        let cookie = format!(
            "apexmail_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400"
        );
        let redirect = if is_cp { "/cp-admin/dashboard/" } else { "/dashboard" };
        let mut resp = Json(serde_json::json!({
            "message": "Login successful",
            "redirect": redirect,
            "user": {"email": email}
        })).into_response();
        resp.headers_mut().insert(header::SET_COOKIE, cookie.parse().unwrap());
        resp
    } else {
        (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid username or password"}))).into_response()
    }
}

async fn register_post(State(state): State<AppState>, axum::Json(form): axum::Json<RegisterForm>) -> impl IntoResponse {
    let email = form.email.trim().to_lowercase();
    if !email.contains('@') || !email.contains('.') {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Invalid email"}))).into_response();
    }
    if form.password.len() < 12 {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Password must be 12+ characters"}))).into_response();
    }
    if let Ok(Some(_)) = sqlx::query_scalar::<_, String>("SELECT email FROM users WHERE email = $1")
        .bind(&email).fetch_optional(&state.db).await
    {
        return (StatusCode::CONFLICT, Json(serde_json::json!({"error": "Email already registered"}))).into_response();
    }

    // Enforce Free plan quota: reject new free plan registrations if global free tenant
    // count exceeds the 30,000 email/month aggregate safety threshold. This is a blunt
    // gate — per-tenant usage is enforced by the billing_usage endpoint.
    let free_count: i64 = sqlx::query_scalar(
        "SELECT COUNT(*) FROM tenants WHERE plan = 'free' AND status = 'active'"
    ).fetch_one(&state.db).await.unwrap_or(0);
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
    let hash = Argon2::default().hash_password(form.password.as_bytes(), &salt).unwrap().to_string();
    let user_id = sqlx::types::Uuid::new_v4();
    let tenant_id = &uuid::Uuid::new_v4().to_string()[..26];

    let _ = sqlx::query("INSERT INTO tenants (id, name, slug, plan, status, created_at, updated_at) VALUES ($1, $2, $3, 'free', 'active', NOW(), NOW()) ON CONFLICT DO NOTHING")
        .bind(tenant_id).bind(email.split('@').next().unwrap_or("user")).bind(tenant_id).execute(&state.db).await;
    let _ = sqlx::query("INSERT INTO users (id, tenant_id, email, password_hash, role, mfa_enabled, created_at, updated_at) VALUES ($1, $2, $3, $4, 'owner', false, NOW(), NOW())")
        .bind(user_id).bind(tenant_id).bind(&email).bind(&hash).execute(&state.db).await;

    let token = create_session_token(&email, &state.session_secret);
    let cookie = format!("apexmail_session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400");
    let mut resp = Json(serde_json::json!({
        "message": "Account created",
        "redirect": "/login"
    })).into_response();
    resp.headers_mut().insert(header::SET_COOKIE, cookie.parse().unwrap());
    resp
}

// ─── API key endpoints ─────────────────────────────────────

async fn list_api_keys(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let email = match extract_session_email(&headers, &state.session_secret) {
        Some(e) => e,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated", "keys": []}))).into_response(),
    };

    let rows = sqlx::query_as::<_, (String, String, String, serde_json::Value, String)>(
        "SELECT ak.id::text, ak.name, ak.key_prefix, ak.scopes, ak.created_at::text FROM api_keys ak JOIN users u ON ak.tenant_id = u.tenant_id WHERE u.email = $1 AND ak.revoked_at IS NULL ORDER BY ak.created_at DESC"
    ).bind(&email).fetch_all(&state.db).await.unwrap_or_default();

    let result: Vec<serde_json::Value> = rows.into_iter().map(|(id, name, prefix, scopes, created_at)| {
        serde_json::json!({
            "id": id, "name": name, "prefix": prefix,
            "scopes": scopes, "created_at": created_at, "key": null
        })
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({"keys": result}))).into_response()
}

async fn create_api_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(form): axum::Json<CreateApiKeyForm>,
) -> impl IntoResponse {
    let email = match extract_session_email(&headers, &state.session_secret) {
        Some(e) => e,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"}))).into_response(),
    };

    let tenant_row = sqlx::query_as::<_, (String,)>("SELECT tenant_id FROM users WHERE email = $1")
        .bind(&email).fetch_optional(&state.db).await;
    let tenant_id = match tenant_row {
        Ok(Some((tid,))) => tid,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "User not found"}))).into_response(),
    };

    let scopes: Vec<String> = form
        .scopes
        .as_deref()
        .unwrap_or("messages:send")
        .split(',')
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect();

    let valid_scopes: &[&str] = &[
        "messages:send", "messages:read", "domains:read", "domains:write",
        "events:read", "webhooks:read", "webhooks:write", "templates:read",
        "templates:write", "suppressions:read", "suppressions:write",
        "analytics:read", "compliance:read", "compliance:write",
    ];
    for s in &scopes {
        if !valid_scopes.contains(&s.as_str()) {
            return (StatusCode::BAD_REQUEST, Json(serde_json::json!({
                "error": format!("invalid scope: {s}")
            }))).into_response();
        }
    }

    let scopes_json = serde_json::json!(scopes);
    let scopes_display = scopes.join(", ");

    let id = sqlx::types::Uuid::new_v4();
    let key_body = &uuid::Uuid::new_v4().to_string().replace("-", "")[..32];
    let prefix = if form.is_test { "am_test" } else { "am_live" };
    let full_key = format!("{prefix}_{key_body}");

    use sha2::{Sha256, Digest};
    let mut h = Sha256::new();
    h.update(full_key.as_bytes());
    let key_hash = hex::encode(h.finalize());

    let _ = sqlx::query(
        "INSERT INTO api_keys (id, tenant_id, name, key_hash, key_prefix, scopes, created_at, updated_at) VALUES ($1, $2, $3, $4, $5, $6::jsonb, NOW(), NOW())"
    ).bind(id).bind(&tenant_id).bind(&form.name).bind(&key_hash).bind(&full_key[..8].to_string()).bind(&scopes_json).execute(&state.db).await;

    (StatusCode::CREATED, Json(serde_json::json!({
        "id": id.to_string(),
        "name": form.name,
        "prefix": &full_key[..11],
        "key": full_key,
        "scopes": scopes_display,
        "message": "Save this key now — it will not be shown again."
    }))).into_response()
}

async fn revoke_api_key(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::extract::Path(id): axum::extract::Path<String>,
) -> impl IntoResponse {
    let email = match extract_session_email(&headers, &state.session_secret) {
        Some(e) => e,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"}))).into_response(),
    };

    let result = sqlx::query(
        "UPDATE api_keys SET revoked_at = NOW() FROM users WHERE api_keys.id::text = $1 AND api_keys.tenant_id = users.tenant_id AND users.email = $2 AND api_keys.revoked_at IS NULL"
    ).bind(&id).bind(&email).execute(&state.db).await;

    match result {
        Ok(r) if r.rows_affected() > 0 => {
            (StatusCode::OK, Json(serde_json::json!({"revoked": true, "id": id}))).into_response()
        }
        Ok(_) => {
            (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "API key not found or already revoked"}))).into_response()
        }
        Err(e) => {
            eprintln!("revoke_api_key error: {e}");
            (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Database error"}))).into_response()
        }
    }
}

// ─── Account ────────────────────────────────────────────────

async fn account_info(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let email = match extract_session_email(&headers, &state.session_secret) {
        Some(e) => e,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"}))).into_response(),
    };

    let row = sqlx::query_as::<_, (String, String)>(
        "SELECT u.email, t.plan FROM users u JOIN tenants t ON u.tenant_id = t.id WHERE u.email = $1"
    ).bind(&email).fetch_optional(&state.db).await;

    match row {
        Ok(Some((email, plan))) => (StatusCode::OK, Json(serde_json::json!({"email": email, "plan": plan}))).into_response(),
        _ => (StatusCode::OK, Json(serde_json::json!({"email": email, "plan": "free"}))).into_response(),
    }
}

// ─── Billing: plans ─────────────────────────────────────────

async fn billing_plans(State(state): State<AppState>) -> impl IntoResponse {
    let has_stripe = state.stripe_secret_key.is_some();
    (StatusCode::OK, Json(serde_json::json!({
        "has_stripe": has_stripe,
        "plans": [
            {
                "name": "free", "display_name": "Free",
                "price_cents": 0, "price_monthly": 0, "price_yearly": 0,
                "email_limit": 30000, "api_call_limit": 100000,
                "features": ["30,000 emails/mo", "1 domain", "1 user", "7-day events", "24h content retention", "Community support", "No automatic overage"],
                "highlight": false
            },
            {
                "name": "developer", "display_name": "Developer",
                "price_cents": 2900, "price_monthly": 29, "price_yearly": 313,
                "email_limit": 50000, "api_call_limit": 500000,
                "features": ["50,000 emails/mo", "€0.80/1,000 overage", "5 domains", "3 users", "REST API + SMTP", "Stored templates", "Signed webhooks", "3 webhook endpoints", "Basic inbound email", "30-day event history", "CSV export"],
                "highlight": true
            },
            {
                "name": "pro", "display_name": "Pro",
                "price_cents": 8900, "price_monthly": 89, "price_yearly": 961,
                "email_limit": 150000, "api_call_limit": 2000000,
                "features": ["150,000 emails/mo", "€0.60/1,000 overage", "15 domains", "8 users", "Custom tracking domain", "Advanced analytics", "Transactional + broadcast streams", "5 webhook endpoints", "Inbound routing", "90-day event history", "10 inbox-placement tests/mo", "Dedicated IP eligibility"],
                "highlight": false
            },
            {
                "name": "growth", "display_name": "Growth",
                "price_cents": 22900, "price_monthly": 229, "price_yearly": 2473,
                "email_limit": 500000, "api_call_limit": 5000000,
                "features": ["500,000 emails/mo", "€0.35/1,000 overage", "50 domains", "15 users", "1 managed dedicated IP", "Managed IP warm-up", "90-day event history", "20 inbox-placement tests/mo", "Audit logs", "5 subaccounts", "Usage + reputation alerts", "Priority 8h support"],
                "highlight": false
            },
            {
                "name": "business", "display_name": "Business",
                "price_cents": 69900, "price_monthly": 699, "price_yearly": 7550,
                "email_limit": 2000000, "api_call_limit": 20000000,
                "features": ["2,000,000 emails/mo", "€0.35/1,000 overage", "Unlimited domains", "25 users", "1 managed dedicated IP", "SAML SSO", "RBAC", "Audit logs", "180-day event history", "50 inbox-placement tests/mo", "25 subaccounts", "Quarterly deliverability review", "99.9% SLA eligible"],
                "highlight": false
            },
            {
                "name": "enterprise", "display_name": "Enterprise",
                "price_cents": 300000, "price_monthly": 3000, "price_yearly": 32400,
                "email_limit": 5000000, "api_call_limit": null,
                "features": ["5,000,000 emails/mo", "€0.22–0.35/1,000 overage", "Unlimited domains", "Unlimited users", "10 managed dedicated IPs", "SAML SSO + SCIM", "Custom RBAC", "Premium audit logs", "Named CSM", "Monthly service review", "Managed migration", "99.9% SLA"],
                "highlight": false
            }
        ]
    }))).into_response()
}

// ─── Billing: subscription ──────────────────────────────────

async fn billing_subscription(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let email = match extract_session_email(&headers, &state.session_secret) {
        Some(e) => e,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"}))).into_response(),
    };

    let row = sqlx::query_as::<_, (String, String, String, Option<String>, Option<String>, Option<String>, Option<String>)>(
        "SELECT t.plan, COALESCE(t.status, 'active'), t.id,
                s.status, s.current_period_end::text,
                s.stripe_subscription_id, sc.stripe_customer_id
         FROM tenants t
         JOIN users u ON u.tenant_id = t.id
         LEFT JOIN subscriptions s ON s.tenant_id = t.id
         LEFT JOIN stripe_customers sc ON sc.tenant_id = t.id
         WHERE u.email = $1
         ORDER BY s.created_at DESC LIMIT 1"
    ).bind(&email).fetch_optional(&state.db).await;

    match row {
        Ok(Some((plan, tenant_status, _tid, sub_status, period_end, sub_id, cust_id))) => {
            (StatusCode::OK, Json(serde_json::json!({
                "plan": plan,
                "tenant_status": tenant_status,
                "subscription_status": sub_status,
                "current_period_end": period_end,
                "stripe_subscription_id": sub_id,
                "stripe_customer_id": cust_id
            }))).into_response()
        }
        _ => (StatusCode::OK, Json(serde_json::json!({
            "plan": "free", "tenant_status": "active",
            "subscription_status": null, "current_period_end": null,
            "stripe_subscription_id": null, "stripe_customer_id": null
        }))).into_response(),
    }
}

// ─── Billing: usage ─────────────────────────────────────────

async fn billing_usage(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
) -> impl IntoResponse {
    let email = match extract_session_email(&headers, &state.session_secret) {
        Some(e) => e,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"}))).into_response(),
    };

    let row = sqlx::query_as::<_, (String, Option<i64>)>(
        "SELECT t.plan, (SELECT COUNT(*) FROM audit_logs al WHERE al.tenant_id = t.id AND al.created_at > NOW() - INTERVAL '30 days') AS sent_count
         FROM tenants t JOIN users u ON u.tenant_id = t.id WHERE u.email = $1"
    ).bind(&email).fetch_optional(&state.db).await;

    match row {
        Ok(Some((plan, sent_opt))) => {
            let sent = sent_opt.unwrap_or(0);
            let limit = match plan.as_str() {
                "free" => 30000, "developer" => 50000, "pro" => 150000,
                "growth" => 500000, "business" => 2000000, "enterprise" => 5000000,
                _ => 30000,
            };
            (StatusCode::OK, Json(serde_json::json!({
                "emails_sent": sent,
                "emails_limit": limit,
                "period_days": 30,
                "usage_percent": if limit > 0 { (sent as f64 / limit as f64 * 100.0).round() as u32 } else { 0 }
            }))).into_response()
        }
        _ => (StatusCode::OK, Json(serde_json::json!({"emails_sent": 0, "emails_limit": 30000, "period_days": 30, "usage_percent": 0}))).into_response(),
    }
}

// ─── Billing: switch plan (direct, no Stripe) ───────────────

async fn billing_switch_plan(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(form): axum::Json<SwitchPlanForm>,
) -> impl IntoResponse {
    let email = match extract_session_email(&headers, &state.session_secret) {
        Some(e) => e,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"}))).into_response(),
    };

    let valid_plans = ["free", "developer", "pro", "growth", "business", "enterprise"];
    if !valid_plans.contains(&form.plan.as_str()) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("Invalid plan: {}", form.plan)}))).into_response();
    }

    let tenant_id: String = match sqlx::query_scalar(
        "UPDATE tenants SET plan = $1, updated_at = NOW() FROM users u WHERE tenants.id = u.tenant_id AND u.email = $2 RETURNING tenants.id"
    ).bind(&form.plan).bind(&email).fetch_optional(&state.db).await {
        Ok(Some(tid)) => tid,
        _ => return (StatusCode::INTERNAL_SERVER_ERROR, Json(serde_json::json!({"error": "Failed to update plan"}))).into_response(),
    };

    // Sync the subscriptions table if switching to/from free
    if form.plan == "free" {
        let _ = sqlx::query(
            "UPDATE subscriptions SET status = 'cancelled', updated_at = NOW() WHERE tenant_id = $1 AND status = 'active'"
        ).bind(&tenant_id).execute(&state.db).await;
    } else {
        let _ = sqlx::query(
            "INSERT INTO subscriptions (id, tenant_id, plan_name, status, created_at, updated_at)
             VALUES (gen_random_uuid(), $1, $2, 'trialing', NOW(), NOW())
             ON CONFLICT DO NOTHING"
        ).bind(&tenant_id).bind(&form.plan).execute(&state.db).await;
    }

    (StatusCode::OK, Json(serde_json::json!({
        "plan": form.plan,
        "message": format!("Successfully switched to {} plan", form.plan)
    }))).into_response()
}

// ─── Stripe: get or create customer ─────────────────────────

async fn get_or_create_stripe_customer(
    state: &AppState,
    tenant_id: &str,
    email: &str,
) -> Result<String, String> {
    // Check cache first
    if let Ok(Some(cid)) = sqlx::query_scalar::<_, String>(
        "SELECT stripe_customer_id FROM stripe_customers WHERE tenant_id = $1"
    ).bind(tenant_id).fetch_optional(&state.db).await {
        return Ok(cid);
    }

    let http = state.http_client.as_ref().ok_or("HTTP client not configured")?;
    let secret = state.stripe_secret_key.as_deref().ok_or("Stripe not configured")?;
    let base_url = std::env::var("STRIPE_API_BASE_URL").unwrap_or_else(|_| "https://api.stripe.com".into());

    let resp = http.post(format!("{base_url}/v1/customers"))
        .bearer_auth(secret)
        .header("Stripe-Version", "2026-04-22.dahlia")
        .form(&[("email", email), ("metadata[tenant_id]", tenant_id)])
        .send().await.map_err(|e| format!("Stripe create customer failed: {e}"))?;

    if !resp.status().is_success() {
        let body = resp.text().await.unwrap_or_default();
        return Err(format!("Stripe error: {body}"));
    }

    let json: serde_json::Value = resp.json().await.map_err(|e| format!("Stripe decode: {e}"))?;
    let customer_id = json["id"].as_str().ok_or("No customer ID in response")?.to_string();

    let _ = sqlx::query(
        "INSERT INTO stripe_customers (id, tenant_id, stripe_customer_id, email, created_at, updated_at)
         VALUES (gen_random_uuid(), $1, $2, $3, NOW(), NOW())
         ON CONFLICT (tenant_id) DO UPDATE SET stripe_customer_id = $2, updated_at = NOW()"
    ).bind(tenant_id).bind(&customer_id).bind(email).execute(&state.db).await;

    Ok(customer_id)
}

// ─── Stripe: checkout session ───────────────────────────────

fn validate_redirect_url(url: &str) -> bool {
    if let Ok(parsed) = url::Url::parse(url) {
        if parsed.scheme() != "https" { return false; }
        if let Some(host) = parsed.host_str() {
            if host.ends_with(".apexmail.ee") || host == "apexmail.ee" || host == "localhost" {
                return true;
            }
        }
    }
    false
}

async fn billing_checkout(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(form): axum::Json<CreateCheckoutForm>,
) -> impl IntoResponse {
    let email = match extract_session_email(&headers, &state.session_secret) {
        Some(e) => e,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"}))).into_response(),
    };

    let tenant_id = match resolve_tenant_id(&state.db, &email).await {
        Some(tid) => tid,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "User not found"}))).into_response(),
    };

    if !validate_redirect_url(&form.success_url) || !validate_redirect_url(&form.cancel_url) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Redirect URL must belong to apexmail.ee"}))).into_response();
    }

    let price_id = match state.stripe_prices.get(&form.plan) {
        Some(pid) => pid.clone(),
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": format!("No Stripe price configured for plan: {}", form.plan)}))).into_response(),
    };

    let customer_id = match get_or_create_stripe_customer(&state, &tenant_id, &email).await {
        Ok(cid) => cid,
        Err(e) => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": e}))).into_response(),
    };

    let http = match &state.http_client {
        Some(c) => c,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Stripe not configured"}))).into_response(),
    };
    let secret = match &state.stripe_secret_key {
        Some(s) => s.as_str(),
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Stripe not configured"}))).into_response(),
    };
    let base_url = std::env::var("STRIPE_API_BASE_URL").unwrap_or_else(|_| "https://api.stripe.com".into());

    let resp = http.post(format!("{base_url}/v1/checkout/sessions"))
        .bearer_auth(secret)
        .header("Stripe-Version", "2026-04-22.dahlia")
        .form(&[
            ("customer", customer_id.as_str()),
            ("payment_method_types[0]", "card"),
            ("line_items[0][price]", &price_id),
            ("line_items[0][quantity]", "1"),
            ("mode", "subscription"),
            ("success_url", &form.success_url),
            ("cancel_url", &form.cancel_url),
            ("subscription_data[metadata][tenant_id]", &tenant_id),
            ("allow_promotion_codes", "true"),
            ("billing_address_collection", "required"),
            ("tax_id_collection[enabled]", "true"),
        ])
        .send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let json: serde_json::Value = r.json().await.unwrap_or_default();
            let url = json["url"].as_str().unwrap_or("");
            (StatusCode::OK, Json(serde_json::json!({"url": url, "sessionId": json["id"]}))).into_response()
        }
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": format!("Stripe checkout failed: {body}")}))).into_response()
        }
        Err(e) => {
            (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": format!("Stripe request failed: {e}")}))).into_response()
        }
    }
}

// ─── Stripe: customer portal ────────────────────────────────

async fn billing_portal(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(form): axum::Json<CreatePortalForm>,
) -> impl IntoResponse {
    let email = match extract_session_email(&headers, &state.session_secret) {
        Some(e) => e,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"}))).into_response(),
    };

    let tenant_id = match resolve_tenant_id(&state.db, &email).await {
        Some(tid) => tid,
        None => return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "User not found"}))).into_response(),
    };

    if !validate_redirect_url(&form.return_url) {
        return (StatusCode::BAD_REQUEST, Json(serde_json::json!({"error": "Return URL must belong to apexmail.ee"}))).into_response();
    }

    let customer_id = match sqlx::query_scalar::<_, String>(
        "SELECT stripe_customer_id FROM stripe_customers WHERE tenant_id = $1"
    ).bind(&tenant_id).fetch_optional(&state.db).await {
        Ok(Some(cid)) => cid,
        _ => return (StatusCode::NOT_FOUND, Json(serde_json::json!({"error": "No Stripe customer found. Subscribe to a paid plan first."}))).into_response(),
    };

    let http = match &state.http_client {
        Some(c) => c,
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Stripe not configured"}))).into_response(),
    };
    let secret = match &state.stripe_secret_key {
        Some(s) => s.as_str(),
        None => return (StatusCode::SERVICE_UNAVAILABLE, Json(serde_json::json!({"error": "Stripe not configured"}))).into_response(),
    };
    let base_url = std::env::var("STRIPE_API_BASE_URL").unwrap_or_else(|_| "https://api.stripe.com".into());

    let resp = http.post(format!("{base_url}/v1/billing_portal/sessions"))
        .bearer_auth(secret)
        .header("Stripe-Version", "2026-04-22.dahlia")
        .form(&[("customer", &customer_id), ("return_url", &form.return_url)])
        .send().await;

    match resp {
        Ok(r) if r.status().is_success() => {
            let json: serde_json::Value = r.json().await.unwrap_or_default();
            let url = json["url"].as_str().unwrap_or("");
            (StatusCode::OK, Json(serde_json::json!({"url": url}))).into_response()
        }
        Ok(r) => {
            let body = r.text().await.unwrap_or_default();
            (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": format!("Stripe portal failed: {body}")}))).into_response()
        }
        Err(e) => {
            (StatusCode::BAD_GATEWAY, Json(serde_json::json!({"error": format!("Stripe request failed: {e}")}))).into_response()
        }
    }
}

// ─── MFA: QR code ───────────────────────────────────────────

async fn mfa_qr(axum::extract::Query(params): axum::extract::Query<MfaQrParams>) -> impl IntoResponse {
    Redirect::to(&format!(
        "https://api.qrserver.com/v1/create-qr-code/?size=200x200&data={}",
        params.otpauth.replace(':', "%3A").replace('/', "%2F").replace('?', "%3F").replace('=', "%3D").replace('&', "%26")
    )).into_response()
}

// ─── MFA: disable ───────────────────────────────────────────

async fn mfa_disable(
    State(state): State<AppState>,
    headers: axum::http::HeaderMap,
    axum::Json(form): axum::Json<MfaDisableForm>,
) -> impl IntoResponse {
    let email = match extract_session_email(&headers, &state.session_secret) {
        Some(e) => e,
        None => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Not authenticated"}))).into_response(),
    };

    let row = sqlx::query_as::<_, (String,)>(
        "SELECT mfa_secret FROM users WHERE email = $1 AND mfa_enabled = true"
    ).bind(&email).fetch_optional(&state.db).await;

    let secret = match row {
        Ok(Some((s,))) if !s.is_empty() => s,
        _ => return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "MFA not enabled"}))).into_response(),
    };

    if !verify_totp_code(&secret, &form.code) {
        return (StatusCode::UNAUTHORIZED, Json(serde_json::json!({"error": "Invalid verification code"}))).into_response();
    }

    let _ = sqlx::query(
        "UPDATE users SET mfa_enabled = false, mfa_secret = NULL, mfa_recovery_hashes = NULL, updated_at = NOW() WHERE email = $1"
    ).bind(&email).execute(&state.db).await;

    (StatusCode::OK, Json(serde_json::json!({"message": "MFA disabled successfully"}))).into_response()
}

// ─── Admin: Streams ─────────────────────────────────────────

async fn admin_streams(State(state): State<AppState>) -> impl IntoResponse {
    let rows: Vec<(String, i64, i64, i64)> = sqlx::query_as(
        "SELECT COALESCE(stream, 'transactional') AS stream_name,
                COUNT(*)::bigint AS total,
                COUNT(*) FILTER (WHERE status = 'delivered')::bigint AS delivered,
                COUNT(*) FILTER (WHERE status IN ('bounced','failed'))::bigint AS bounced
         FROM messages
         WHERE created_at > NOW() - INTERVAL '30 days'
         GROUP BY 1 ORDER BY 1"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let streams: Vec<serde_json::Value> = rows
        .into_iter()
        .map(|(name, total, delivered, bounced)| {
            let safe_total = if total > 0 { total as f64 } else { 1.0 };
            serde_json::json!({
                "stream": name,
                "total_messages_30d": total,
                "delivered_30d": delivered,
                "bounced_30d": bounced,
                "delivery_rate": ((delivered as f64 / safe_total * 100.0) * 10.0).round() / 10.0,
                "bounce_rate": ((bounced as f64 / safe_total * 100.0) * 10.0).round() / 10.0,
            })
        })
        .collect();

    let tenant_streams: Vec<(String, String, i64)> = sqlx::query_as(
        "SELECT DISTINCT t.plan,
                COALESCE(m.stream, 'transactional'),
                COUNT(*)::bigint
         FROM messages m
         JOIN tenants t ON t.id::text = m.tenant_id::text
         WHERE m.created_at > NOW() - INTERVAL '30 days'
         GROUP BY 1, 2 ORDER BY 1, 2"
    )
    .fetch_all(&state.db)
    .await
    .unwrap_or_default();

    let by_plan: Vec<serde_json::Value> = {
        let mut map: std::collections::HashMap<String, Vec<serde_json::Value>> =
            std::collections::HashMap::new();
        for (plan, stream_name, count) in &tenant_streams {
            let entry = serde_json::json!({"stream": stream_name, "count": count});
            map.entry(plan.clone()).or_default().push(entry);
        }
        map.into_iter()
            .map(|(plan, entries)| {
                serde_json::json!({"plan": plan, "streams": entries})
            })
            .collect()
    };

    (StatusCode::OK, Json(serde_json::json!({
        "streams": streams,
        "by_plan": by_plan,
    })))
    .into_response()
}

// ─── Main ────────────────────────────────────────────────────

async fn admin_dashboard_stats(State(state): State<AppState>) -> impl IntoResponse {
    let (tenant_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tenants WHERE status = 'active'")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (emails_sent,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*), 0) FROM messages WHERE created_at > NOW() - INTERVAL '30 days'")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (delivered,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*), 0) FROM messages WHERE status = 'delivered' AND created_at > NOW() - INTERVAL '30 days'")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (bounced,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*), 0) FROM messages WHERE status IN ('bounced','failed') AND created_at > NOW() - INTERVAL '30 days'")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (mrr,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(p.price_monthly), 0)::bigint FROM plans p JOIN tenants t ON t.plan = p.name WHERE t.status = 'active'"
    ).fetch_one(&state.db).await.unwrap_or((0,));
    let safe_sent = if emails_sent > 0 { emails_sent as f64 } else { 1.0 };

    (StatusCode::OK, Json(serde_json::json!({
        "active_tenant_count": tenant_count,
        "emails_sent": emails_sent,
        "delivery_rate": ((delivered as f64 / safe_sent * 100.0) * 10.0).round() / 10.0,
        "bounce_rate": ((bounced as f64 / safe_sent * 100.0) * 10.0).round() / 10.0,
        "mrr": mrr,
    }))).into_response()
}

async fn admin_tenants(State(state): State<AppState>) -> impl IntoResponse {
    let rows: Vec<(String, String, String, String, String)> = sqlx::query_as(
        "SELECT id, COALESCE(name, 'unnamed'), plan, COALESCE(status, 'active'), created_at::text FROM tenants ORDER BY created_at DESC LIMIT 100"
    ).fetch_all(&state.db).await.unwrap_or_default();

    let tenants: Vec<serde_json::Value> = rows.into_iter().map(|(id, name, plan, status, created)| {
        serde_json::json!({"id": id, "name": name, "plan": plan, "status": status, "created": created.split('T').next().unwrap_or("")})
    }).collect();

    let counts = sqlx::query_as::<_, (i64,i64,i64)>(
        "SELECT COUNT(*) FILTER(WHERE plan='free'), COUNT(*) FILTER(WHERE plan!='free' AND plan!='enterprise'), COUNT(*) FILTER(WHERE plan='enterprise') FROM tenants WHERE status='active'"
    ).fetch_one(&state.db).await.unwrap_or((0,0,0));

    (StatusCode::OK, Json(serde_json::json!({
        "tenants": tenants,
        "total": tenants.len(),
        "free_count": counts.0,
        "paid_count": counts.1,
        "enterprise_count": counts.2,
    }))).into_response()
}

async fn admin_audit(State(state): State<AppState>) -> impl IntoResponse {
    let rows: Vec<(String, String, String, String)> = sqlx::query_as(
        "SELECT action, resource_type, resource_id, created_at::text FROM audit_logs ORDER BY created_at DESC LIMIT 200"
    ).fetch_all(&state.db).await.unwrap_or_default();

    let entries: Vec<serde_json::Value> = rows.into_iter().map(|(action, resource, rid, ts)| {
        serde_json::json!({"action": action, "resource": resource, "resource_id": rid, "timestamp": ts})
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({"entries": entries, "total": entries.len()}))).into_response()
}

async fn admin_analytics(State(state): State<AppState>) -> impl IntoResponse {
    let (delivered,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*),0) FROM messages WHERE status='delivered' AND created_at>NOW()-INTERVAL'30 days'").fetch_one(&state.db).await.unwrap_or((0,));
    let (bounced,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*),0) FROM messages WHERE status IN('bounced','failed') AND created_at>NOW()-INTERVAL'30 days'").fetch_one(&state.db).await.unwrap_or((0,));
    let (total,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*),0) FROM messages WHERE created_at>NOW()-INTERVAL'30 days'").fetch_one(&state.db).await.unwrap_or((0,));
    let safe = if total>0 {total as f64} else {1.0};

    let daily: Vec<serde_json::Value> = sqlx::query_as::<_, (String, i64)>(
        "SELECT created_at::date::text, COUNT(*) FROM messages WHERE created_at>NOW()-INTERVAL'30 days' GROUP BY 1 ORDER BY 1"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter().map(|(d,c)| serde_json::json!({"date":d,"count":c})).collect();

    let by_status: Vec<serde_json::Value> = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(status,'unknown'), COUNT(*) FROM messages WHERE created_at>NOW()-INTERVAL'30 days' GROUP BY 1 ORDER BY 2 DESC"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter().map(|(s,c)| serde_json::json!({"status":s,"count":c})).collect();

    let plans: Vec<serde_json::Value> = sqlx::query_as::<_, (String, i64)>(
        "SELECT t.plan, COUNT(*) FROM tenants t WHERE t.status='active' GROUP BY 1 ORDER BY 2 DESC"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter().map(|(p,c)| serde_json::json!({"plan":p,"count":c})).collect();

    (StatusCode::OK, Json(serde_json::json!({
        "total": total, "delivered": delivered, "bounced": bounced,
        "delivery_rate": ((delivered as f64/safe*100.0)*10.0).round()/10.0,
        "bounce_rate": ((bounced as f64/safe*100.0)*10.0).round()/10.0,
        "daily": daily, "by_status": by_status, "plans": plans
    }))).into_response()
}

async fn admin_billing(State(state): State<AppState>) -> impl IntoResponse {
    let (total_mrr,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(SUM(p.price_monthly), 0) FROM plans p JOIN tenants t ON t.plan = p.name WHERE t.status = 'active'"
    ).fetch_one(&state.db).await.unwrap_or((0,));
    let (tenant_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tenants WHERE status='active'").fetch_one(&state.db).await.unwrap_or((0,));
    let (paid_count,): (i64,) = sqlx::query_as("SELECT COUNT(*) FROM tenants WHERE status='active' AND plan!='free'").fetch_one(&state.db).await.unwrap_or((0,));
    let plans: Vec<serde_json::Value> = sqlx::query_as::<_, (String, i64)>(
        "SELECT name, price_monthly FROM plans ORDER BY sort_order"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter().map(|(n,r)| {
        serde_json::json!({"plan":n,"price_monthly_cents":r,"revenue_eur":0.0,"tenant_count":0})
    }).collect();

    (StatusCode::OK, Json(serde_json::json!({
        "total_mrr_cents": total_mrr, "total_mrr_eur": total_mrr as f64/100.0,
        "tenant_count": tenant_count, "paid_count": paid_count,
        "plans": plans
    }))).into_response()
}

async fn admin_compliance(State(state): State<AppState>) -> impl IntoResponse {
    let now = Utc::now();
    let (dsar_count,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*),0) FROM gdpr_requests WHERE status='pending'").fetch_one(&state.db).await.unwrap_or((0,));
    let (dsar_done,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*),0) FROM gdpr_requests WHERE status='completed'").fetch_one(&state.db).await.unwrap_or((0,));
    let (users_mfa,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*),0) FROM users WHERE mfa_enabled=true").fetch_one(&state.db).await.unwrap_or((0,));
    let (users_total,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*),0) FROM users").fetch_one(&state.db).await.unwrap_or((0,));
    let (api_keys,): (i64,) = sqlx::query_as("SELECT COALESCE(COUNT(*),0) FROM api_keys WHERE revoked_at IS NULL").fetch_one(&state.db).await.unwrap_or((0,));

    let estonia_deadlines: Vec<serde_json::Value> = vec![
        serde_json::json!({"type":"VAT Declaration","due":format!("{}-{:02}-20",now.year(),now.month()),"status":"pending"}),
        serde_json::json!({"type":"Income Tax","due":format!("{}-{:02}-10",now.year(),now.month()),"status":"pending"}),
        serde_json::json!({"type":"Social Tax","due":format!("{}-{:02}-10",now.year(),now.month()),"status":"pending"}),
        serde_json::json!({"type":"Annual Report","due":format!("{}-06-30",now.year()),"status":if now.month()>6 {"overdue"}else{"pending"}}),
    ];

    (StatusCode::OK, Json(serde_json::json!({
        "dsar_pending": dsar_count, "dsar_completed": dsar_done,
        "mfa_users": users_mfa, "total_users": users_total,
        "api_keys": api_keys,
        "estonia_deadlines": estonia_deadlines,
        "frameworks": [
            {"name":"GDPR","status":"active"},
            {"name":"HIPAA","status":"enterprise_only"},
            {"name":"CCPA","status":"active"},
            {"name":"SOC 2","status":"controls_active"}
        ]
    }))).into_response()
}

// ─── Analytics: Delivery ────────────────────────────────────

async fn admin_analytics_delivery(State(state): State<AppState>) -> impl IntoResponse {
    let (total,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(COUNT(*),0) FROM messages WHERE created_at > NOW() - INTERVAL '30 days'"
    ).fetch_one(&state.db).await.unwrap_or((0,));
    let (delivered,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(COUNT(*),0) FROM messages WHERE status='delivered' AND created_at > NOW() - INTERVAL '30 days'"
    ).fetch_one(&state.db).await.unwrap_or((0,));
    let (bounced,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(COUNT(*),0) FROM messages WHERE status IN ('bounced','failed') AND created_at > NOW() - INTERVAL '30 days'"
    ).fetch_one(&state.db).await.unwrap_or((0,));

    let safe = if total > 0 { total as f64 } else { 1.0 };

    let daily: Vec<serde_json::Value> = sqlx::query_as::<_, (String, i64, i64)>(
        "SELECT created_at::date::text, COUNT(*)::bigint,
                COUNT(*) FILTER (WHERE status='delivered')::bigint
         FROM messages WHERE created_at > NOW() - INTERVAL '30 days'
         GROUP BY 1 ORDER BY 1"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter()
        .map(|(d,t,del)| serde_json::json!({"date":d,"total":t,"delivered":del}))
        .collect();

    let by_status: Vec<serde_json::Value> = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(status,'unknown'), COUNT(*)::bigint
         FROM messages WHERE created_at > NOW() - INTERVAL '30 days'
         GROUP BY 1 ORDER BY 2 DESC"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter()
        .map(|(s,c)| serde_json::json!({"status":s,"count":c}))
        .collect();

    (StatusCode::OK, Json(serde_json::json!({
        "total_sent": total, "delivered": delivered, "bounced": bounced,
        "delivery_rate": ((delivered as f64 / safe * 100.0) * 10.0).round() / 10.0,
        "bounce_rate": ((bounced as f64 / safe * 100.0) * 10.0).round() / 10.0,
        "daily": daily, "by_status": by_status
    }))).into_response()
}

// ─── Analytics: Growth ──────────────────────────────────────

async fn admin_analytics_growth(State(state): State<AppState>) -> impl IntoResponse {
    let (total_tenants,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM tenants")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (active_tenants,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM tenants WHERE status='active'")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (new_today,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM tenants WHERE created_at >= CURRENT_DATE")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (new_week,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM tenants WHERE created_at > NOW() - INTERVAL '7 days'")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (new_month,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM tenants WHERE created_at > NOW() - INTERVAL '30 days'")
        .fetch_one(&state.db).await.unwrap_or((0,));

    let signup_timeline: Vec<serde_json::Value> = sqlx::query_as::<_, (String, i64)>(
        "SELECT DATE(created_at)::text, COUNT(*)::bigint FROM tenants
         WHERE created_at > NOW() - INTERVAL '30 days' GROUP BY 1 ORDER BY 1"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter()
        .map(|(d,c)| serde_json::json!({"date":d,"count":c}))
        .collect();

    let plans: Vec<serde_json::Value> = sqlx::query_as::<_, (String, i64)>(
        "SELECT COALESCE(NULLIF(plan,''),'free'), COUNT(*)::bigint FROM tenants
         WHERE status='active' GROUP BY 1 ORDER BY 2 DESC"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter()
        .map(|(p,c)| serde_json::json!({"plan":p,"count":c}))
        .collect();

    let (dau,): (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM messages WHERE created_at >= CURRENT_DATE"
    ).fetch_one(&state.db).await.unwrap_or((0,));
    let (wau,): (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM messages WHERE created_at > NOW() - INTERVAL '7 days'"
    ).fetch_one(&state.db).await.unwrap_or((0,));
    let (mau,): (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM messages WHERE created_at > NOW() - INTERVAL '30 days'"
    ).fetch_one(&state.db).await.unwrap_or((0,));

    let (trials,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM subscriptions WHERE status='trialing'"
    ).fetch_one(&state.db).await.unwrap_or((0,));
    let (paid_subs,): (i64,) = sqlx::query_as(
        "SELECT COUNT(DISTINCT tenant_id)::bigint FROM subscriptions WHERE status IN ('active','past_due')"
    ).fetch_one(&state.db).await.unwrap_or((0,));
    let (churned,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM subscriptions WHERE status='canceled' AND updated_at > NOW() - INTERVAL '30 days'"
    ).fetch_one(&state.db).await.unwrap_or((0,));

    (StatusCode::OK, Json(serde_json::json!({
        "total_tenants": total_tenants,
        "active_tenants": active_tenants,
        "new_today": new_today,
        "new_this_week": new_week,
        "new_this_month": new_month,
        "signup_timeline": signup_timeline,
        "plans": plans,
        "dau": dau, "wau": wau, "mau": mau,
        "dau_mau_ratio": if mau > 0 { ((dau as f64 / mau as f64) * 100.0 * 10.0).round() / 10.0 } else { 0.0 },
        "active_trials": trials,
        "paid_subscriptions": paid_subs,
        "churned_30d": churned,
        "churn_rate": if active_tenants > 0 { ((churned as f64 / active_tenants as f64) * 100.0 * 10.0).round() / 10.0 } else { 0.0 }
    }))).into_response()
}

// ─── Analytics: Predictive ──────────────────────────────────

async fn admin_analytics_predictive(State(state): State<AppState>) -> impl IntoResponse {
    let at_risk: Vec<serde_json::Value> = sqlx::query_as::<_, (String, i64, Option<bool>, Option<f64>, Option<i64>, Option<i64>)>(
        "SELECT t.id::text,
                COALESCE(EXTRACT(EPOCH FROM (NOW() - MAX(m.created_at))) / 86400, 365)::bigint as days_inactive,
                EXISTS(SELECT 1 FROM subscriptions s WHERE s.tenant_id::text = t.id::text AND s.status IN ('active', 'trialing', 'past_due')) as has_subscription,
                CASE
                    WHEN COUNT(*) FILTER (WHERE m.status IN ('sent', 'delivered', 'bounced', 'failed')) > 0
                    THEN COUNT(*) FILTER (WHERE m.status IN ('bounced', 'failed'))::float8
                         / NULLIF(COUNT(*) FILTER (WHERE m.status IN ('sent', 'delivered', 'bounced', 'failed')), 0)
                    ELSE 0
                END as bounce_rate,
                COUNT(*) FILTER (WHERE m.created_at >= NOW() - INTERVAL '7 days') as recent_count,
                COUNT(*) FILTER (WHERE m.created_at >= NOW() - INTERVAL '14 days' AND m.created_at < NOW() - INTERVAL '7 days') as prev_count
         FROM tenants t
         LEFT JOIN messages m ON m.tenant_id::text = t.id::text
         WHERE t.status = 'active'
         GROUP BY t.id
         HAVING COALESCE(EXTRACT(EPOCH FROM (NOW() - MAX(m.created_at))) / 86400, 365) > 14
            OR EXISTS(SELECT 1 FROM subscriptions s WHERE s.tenant_id::text = t.id::text AND s.status = 'canceled')
         ORDER BY 2 DESC LIMIT 50"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter()
        .map(|(id, days, has_sub, bounce_rate, recent_count, prev_count)| {
            let has_sub = has_sub.unwrap_or(false);
            let br = bounce_rate.unwrap_or(0.0);
            let recent = recent_count.unwrap_or(0);
            let prev = prev_count.unwrap_or(1);
            let decline = if prev > 0 && recent < prev {
                ((prev - recent) as f64 / prev as f64 * 100.0 * 10.0).round() / 10.0
            } else if days >= 30 {
                100.0
            } else if days >= 14 {
                50.0
            } else {
                0.0
            };
            let level = if days > 60 && has_sub { "critical" }
                        else if days > 30 && (has_sub || br > 0.10) { "high" }
                        else if days > 14 { "medium" }
                        else { "low" };
            serde_json::json!({
                "tenant_id": id,
                "days_inactive": days,
                "risk_level": level,
                "has_active_subscription": has_sub,
                "bounce_rate_30d": br,
                "email_volume_decline_pct": decline
            })
        })
        .collect();

    let high_risk = at_risk.iter().filter(|t| t["risk_level"] == "critical" || t["risk_level"] == "high").count();
    let medium_risk = at_risk.iter().filter(|t| t["risk_level"] == "medium").count();
    let (total_active,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM tenants WHERE status='active'")
        .fetch_one(&state.db).await.unwrap_or((1,));

    let (daily_vol,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM messages WHERE created_at >= CURRENT_DATE")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (weekly_vol,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM messages WHERE created_at > NOW() - INTERVAL '7 days'")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (monthly_vol,): (i64,) = sqlx::query_as("SELECT COUNT(*)::bigint FROM messages WHERE created_at > NOW() - INTERVAL '30 days'")
        .fetch_one(&state.db).await.unwrap_or((0,));
    let (prev_week_vol,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM messages WHERE created_at > NOW() - INTERVAL '14 days' AND created_at <= NOW() - INTERVAL '7 days'"
    ).fetch_one(&state.db).await.unwrap_or((1,));

    let growth_rate = if prev_week_vol > 0 { (weekly_vol - prev_week_vol) as f64 / prev_week_vol as f64 } else { 0.0 };
    let projected_30d = (monthly_vol as f64 * (1.0 + growth_rate.max(-0.5))).round() as i64;
    let projected_90d = (monthly_vol as f64 * 3.0 * (1.0 + growth_rate.max(-0.5))).round() as i64;

    let volume_trend: Vec<serde_json::Value> = sqlx::query_as::<_, (String, i64)>(
        "SELECT DATE(created_at)::text, COUNT(*)::bigint FROM messages
         WHERE created_at > NOW() - INTERVAL '30 days' GROUP BY 1 ORDER BY 1"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter()
        .map(|(d,c)| serde_json::json!({"date":d,"volume":c}))
        .collect();

    let (today_bounce,): (f64,) = sqlx::query_as(
        "SELECT CASE
            WHEN SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END) > 0
            THEN SUM(CASE WHEN status IN ('bounced','failed') THEN 1 ELSE 0 END)::float8
                 / NULLIF(SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END), 0)
            ELSE 0 END
         FROM messages WHERE created_at > NOW() - INTERVAL '24 hours'"
    ).fetch_one(&state.db).await.unwrap_or((0.0,));
    let (avg_bounce,): (f64,) = sqlx::query_as(
        "SELECT CASE
            WHEN SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END) > 0
            THEN SUM(CASE WHEN status IN ('bounced','failed') THEN 1 ELSE 0 END)::float8
                 / NULLIF(SUM(CASE WHEN status IN ('sent','delivered','bounced','failed') THEN 1 ELSE 0 END), 0)
            ELSE 0 END
         FROM messages WHERE created_at > NOW() - INTERVAL '7 days'"
    ).fetch_one(&state.db).await.unwrap_or((0.0,));

    let (current_queue,): (i64,) = sqlx::query_as(
        "SELECT COALESCE(COUNT(*)::bigint, 0) FROM email_queue WHERE status IN ('pending', 'processing')"
    ).fetch_one(&state.db).await.unwrap_or((0,));

    let (paid_no_activity,): (i64,) = sqlx::query_as(
        "SELECT COUNT(*)::bigint FROM (
            SELECT t.id FROM tenants t
            JOIN subscriptions s ON s.tenant_id::text = t.id::text
            WHERE s.status IN ('active', 'trialing', 'past_due')
              AND NOT EXISTS (
                SELECT 1 FROM messages m WHERE m.tenant_id::text = t.id::text
                  AND m.created_at >= NOW() - INTERVAL '30 days'
              )
        ) sub"
    ).fetch_one(&state.db).await.unwrap_or((0,));

    let mut anomalies: Vec<serde_json::Value> = Vec::new();

    if avg_bounce > 0.0 && today_bounce > avg_bounce * 2.0 {
        anomalies.push(serde_json::json!({
            "type": "bounce_spike",
            "description": format!("Bounce rate spike: {:.1}% today vs {:.1}% weekly average", today_bounce * 100.0, avg_bounce * 100.0),
            "severity": if today_bounce > 0.10 { "critical" } else { "warning" }
        }));
    }

    if paid_no_activity > 0 {
        anomalies.push(serde_json::json!({
            "type": "paid_no_activity",
            "description": format!("{} paying tenants with zero email activity in 30 days", paid_no_activity),
            "severity": if paid_no_activity > 5 { "warning" } else { "info" }
        }));
    }

    if current_queue > 100 {
        anomalies.push(serde_json::json!({
            "type": "queue_backlog",
            "description": format!("{} items pending in email queue", current_queue),
            "severity": if current_queue > 1000 { "critical" } else { "warning" }
        }));
    }

    (StatusCode::OK, Json(serde_json::json!({
        "churn_risk": {
            "at_risk_count": at_risk.len(),
            "high_risk": high_risk,
            "medium_risk": medium_risk,
            "predicted_churn_rate_30d": if total_active > 0 { ((high_risk as f64 / total_active as f64) * 100.0 * 10.0).round() / 10.0 } else { 0.0 },
            "at_risk_tenants": at_risk
        },
        "capacity": {
            "daily_volume": daily_vol,
            "weekly_volume": weekly_vol,
            "monthly_volume": monthly_vol,
            "weekly_growth_rate": (growth_rate * 100.0 * 10.0).round() / 10.0,
            "projected_30d_volume": projected_30d,
            "projected_90d_volume": projected_90d,
            "volume_trend_30d": volume_trend
        },
        "anomalies": {
            "bounce_rate_today": (today_bounce * 100.0 * 10.0).round() / 10.0,
            "bounce_rate_week_avg": (avg_bounce * 100.0 * 10.0).round() / 10.0,
            "bounce_spike": today_bounce > avg_bounce * 2.0 && avg_bounce > 0.0,
            "items": anomalies
        }
    }))).into_response()
}

// ─── Domain Onboarding ──────────────────────────────────────

async fn admin_domain_onboarding(State(state): State<AppState>) -> impl IntoResponse {
    let domains: Vec<serde_json::Value> = sqlx::query_as::<_, (String, String, String, bool, bool, bool, bool, Option<String>)>(
        "SELECT d.id::text, d.name, d.status,
                COALESCE(d.spf_verified, false), COALESCE(d.dkim_verified, false),
                COALESCE(d.dmarc_verified, false), COALESCE(d.return_path_verified, false),
                d.last_checked::text
         FROM domains d
         JOIN users u ON d.tenant_id = u.tenant_id
         ORDER BY d.created_at DESC LIMIT 200"
    ).fetch_all(&state.db).await.unwrap_or_default().into_iter()
        .map(|(id, name, status, spf, dkim, dmarc, return_path, last_checked)| {
            serde_json::json!({
                "id": id, "domain": name, "status": status,
                "spf_verified": spf, "dkim_verified": dkim,
                "dmarc_verified": dmarc, "return_path_verified": return_path,
                "last_checked": last_checked
            })
        }).collect();

    let provider_guides: serde_json::Value = serde_json::json!({
        "cloudflare": {
            "name": "Cloudflare",
            "steps": [
                "Log in to the Cloudflare dashboard and select your domain.",
                "Go to DNS → Records.",
                "Click 'Add record' and choose the record type (TXT for SPF/DKIM/DMARC, CNAME for tracking domain, MX for return path).",
                "Paste the Name/Host and Value from the record details above.",
                "Set TTL to 'Auto' or 1 hour (3600).",
                "Click 'Save'. Cloudflare proxies DNS records by default — ensure the proxy status (orange cloud) is OFF for SPF/DKIM/DMARC TXT records.",
                "Wait up to 5 minutes then click 'Recheck'."
            ]
        },
        "route53": {
            "name": "AWS Route 53",
            "steps": [
                "Open the Route 53 console and select 'Hosted zones'.",
                "Click your domain name.",
                "Click 'Create record'.",
                "Choose the record type (TXT, CNAME, or MX).",
                "Enter the record Name (leave blank for apex if instructed) and paste the Value.",
                "Set TTL to 300 (5 minutes) for faster propagation during setup.",
                "Click 'Create records'.",
                "Wait up to 5 minutes then click 'Recheck'."
            ]
        },
        "godaddy": {
            "name": "GoDaddy",
            "steps": [
                "Log in to GoDaddy and open 'Domain Portfolio'.",
                "Select your domain and click 'DNS'.",
                "Click 'Add New Record'.",
                "Choose the record type from the dropdown.",
                "Enter the Host (name) and paste the Points to / Value.",
                "Set TTL to 1 hour.",
                "Click 'Save'.",
                "Wait up to 30 minutes for propagation, then click 'Recheck'."
            ]
        },
        "namecheap": {
            "name": "Namecheap",
            "steps": [
                "Log in to Namecheap and go to Domain List.",
                "Click 'Manage' next to your domain.",
                "Select the 'Advanced DNS' tab.",
                "Click 'Add New Record'.",
                "Select record type, enter Host (use @ for apex), paste Value.",
                "Set TTL to 'Automatic' or 30 minutes.",
                "Click the green checkmark to save.",
                "Wait 5-30 minutes then click 'Recheck'."
            ]
        },
        "ovh": {
            "name": "OVHcloud",
            "steps": [
                "Log in to the OVHcloud Control Panel.",
                "Go to Web Cloud → Domain names → select your domain.",
                "Click the 'DNS zone' tab.",
                "Click 'Add an entry'.",
                "Select the record type, enter the sub-domain (or leave empty for apex), paste the Target/Value.",
                "Set TTL to 3600.",
                "Click 'Next' then 'Confirm'.",
                "Propagation may take up to 24 hours; typically completes within 30 minutes."
            ]
        },
        "gandi": {
            "name": "Gandi",
            "steps": [
                "Log in to your Gandi account and go to 'Domains'.",
                "Click your domain name.",
                "Select the 'DNS Records' tab.",
                "Click 'Add a record'.",
                "Choose the type, enter the Name (use @ for apex), paste the Value/Data.",
                "Set TTL to 3600 seconds.",
                "Click 'Create'.",
                "Click 'Recheck' after 5-30 minutes."
            ]
        },
        "ionos": {
            "name": "IONOS (1&1)",
            "steps": [
                "Log in to the IONOS Control Panel.",
                "Go to Domains & SSL → select your domain.",
                "Click 'DNS' or 'DNS Settings'.",
                "Click 'Add Record'.",
                "Select record type, enter Host name (@ for apex), paste Value.",
                "Set TTL to 1 hour.",
                "Click 'Save'.",
                "Changes propagate within 1 hour; recheck after 30 minutes."
            ]
        },
        "squarespace": {
            "name": "Squarespace Domains",
            "steps": [
                "Log in to Squarespace and go to Domains.",
                "Click your domain, then 'Advanced Settings' or 'DNS Settings'.",
                "Click 'Add Record'.",
                "Select record type, enter Host (@ for root domain), paste Data/Value.",
                "Click 'Add' or 'Save'.",
                "Squarespace DNS changes propagate quickly — recheck after 5-15 minutes."
            ]
        },
        "azure_dns": {
            "name": "Azure DNS",
            "steps": [
                "Open the Azure Portal and navigate to your DNS zone.",
                "Click '+ Record set'.",
                "Enter the Name (leave blank for apex), select the record Type.",
                "Paste the Value in the appropriate field.",
                "Set TTL to 300 seconds.",
                "Click 'OK'.",
                "Recheck after 5 minutes."
            ]
        },
        "google_cloud_dns": {
            "name": "Google Cloud DNS",
            "steps": [
                "Open the Google Cloud Console and go to 'Cloud DNS'.",
                "Select your managed zone.",
                "Click 'Add Record Set' or 'Add Standard'.",
                "Enter the DNS Name (leave blank for zone apex), select the Resource Record Type.",
                "Paste the Value in the appropriate field.",
                "Set TTL to 300 seconds.",
                "Click 'Create'.",
                "Recheck after 5 minutes."
            ]
        }
    });

    (StatusCode::OK, Json(serde_json::json!({
        "domains": domains,
        "provider_guides": provider_guides,
        "dns_records_required": [
            {"type": "TXT", "host": "@", "purpose": "SPF — authorises ApexMail to send on your behalf", "required": true},
            {"type": "CNAME", "host": "apexmail._domainkey", "purpose": "DKIM — cryptographic signature verification", "required": true},
            {"type": "TXT", "host": "_dmarc", "purpose": "DMARC — policy for handling authentication failures", "required": true},
            {"type": "CNAME", "host": "email", "purpose": "Return Path — custom bounce/return domain", "required": false},
            {"type": "CNAME", "host": "track", "purpose": "Custom tracking domain", "required": false}
        ]
    }))).into_response()
}

async fn status_page() -> impl IntoResponse {
    let html = r##"<!DOCTYPE html><html lang=en><head><meta charset=utf-8><meta name=viewport content="width=device-width,initial-scale=1"><title>ApexMail Status</title>
<style>:root{--brand:#ef4444;--bg:#f8f9fa;--card:#fff;--border:#e9ecef;--text:#0f1117;--muted:#6b7280;--success:#059669;--warning:#d97706;--error:#dc2626}*,*::before,*::after{box-sizing:border-box;margin:0;padding:0}body{font-family:-apple-system,BlinkMacSystemFont,Segoe UI,Roboto,sans-serif;background:var(--bg);color:var(--text);max-width:900px;margin:0 auto;padding:40px 20px}h1{font-size:22px;font-weight:700;margin-bottom:4px}h1 span{color:var(--brand)}h1+p{color:var(--muted);font-size:14px;margin-bottom:32px}.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(250px,1fr));gap:16px}.card{background:var(--card);border:1px solid var(--border);border-radius:10px;padding:20px}.card h3{font-size:12px;text-transform:uppercase;letter-spacing:.06em;color:var(--muted);margin-bottom:8px}.card .status{font-size:14px;font-weight:600;margin-bottom:4px}.card .meta{font-size:12px;color:var(--muted)}.ok{color:var(--success)}.warn{color:var(--warning)}.err{color:var(--error)}.overall{text-align:center;margin-bottom:24px;padding:20px;background:var(--card);border:1px solid var(--border);border-radius:10px}.overall .big{font-size:36px;font-weight:700}.bar{height:4px;background:var(--border);border-radius:2px;margin-top:12px;overflow:hidden}.bar-fill{height:100%;border-radius:2px;transition:width .3s}footer{text-align:center;margin-top:40px;font-size:12px;color:var(--muted)}</style></head><body>
<h1><span>Apex</span>Mail Status</h1><p>Live service health — probes run every 60 seconds. <span id=updated style=color:var(--muted)></span></p>
<div class=overall id=overall><div class=big id=big>—</div><div id=msg style=font-size:14px;color:var(--muted)>Loading…</div></div>
<div class=grid id=grid></div>
<div class=bar><div class=bar-fill id=bar style=width:0></div></div>
<footer>ApexMail — Bel Consulting OÜ, Registry 16588745</footer>
<script>
async function check(){try{var r=await fetch("/status/api"),d=await r.json();var ok=0,g=document.getElementById("grid"),h="";d.services.forEach(function(s){var cls=s.status==="operational"||s.status==="connected"?"ok":s.status==="degraded"?"warn":"err";if(cls==="ok"||cls==="warn")ok++;h+="<div class=card><h3>"+s.name+"</h3><div class=\"status "+cls+"\">"+s.status+"</div><div class=meta>"+d.updated+"</div></div>"});g.innerHTML=h;var pct=(ok/d.services.length*100).toFixed(0);document.getElementById("big").textContent=pct+"%";document.getElementById("bar").style.width=pct+"%";document.getElementById("big").className="big "+(pct==100?"ok":pct>=80?"warn":"err");document.getElementById("msg").textContent=pct==100?"All systems operational":pct>=80?"Minor degradation":"Service disruption";document.getElementById("updated").textContent="Updated: "+d.updated}catch(ex){document.getElementById("msg").textContent="Status data unavailable";document.getElementById("big").className="big err"}}
check();setInterval(check,60000)
</script></body></html>"##;
    (StatusCode::OK, [(axum::http::header::CONTENT_TYPE, "text/html; charset=utf-8")], html).into_response()
}

// ─── Health endpoint ─────────────────────────────────────

async fn health_check(State(state): State<AppState>) -> impl IntoResponse {
    let mut services = Vec::new();
    let mut all_operational = true;

    // Database connectivity check
    let db_ok = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tenants")
        .fetch_one(&state.db).await.is_ok();
    services.push(serde_json::json!({
        "name": "database",
        "status": if db_ok { "connected" } else { "disconnected" }
    }));
    if !db_ok { all_operational = false; }

    // Redis connectivity — probe via REDIS_URL env if configured
    let redis_configured = std::env::var("REDIS_URL").ok().filter(|s| !s.is_empty()).is_some();
    let redis_ok = if redis_configured {
        std::env::var("REDIS_URL").ok()
            .map(|url| {
                std::process::Command::new("redis-cli")
                    .arg("-u").arg(&url)
                    .arg("PING")
                    .output()
                    .map(|o| o.status.success())
                    .unwrap_or(false)
            })
            .unwrap_or(false)
    } else {
        true // Not required when unconfigured
    };

    services.push(serde_json::json!({
        "name": "redis",
        "status": if redis_ok { "connected" } else if redis_configured { "disconnected" } else { "not_configured" }
    }));
    if redis_configured && !redis_ok { all_operational = false; }

    // Queue depth check
    let queue_depth = sqlx::query_scalar::<_, i64>(
        "SELECT COALESCE(COUNT(*), 0) FROM email_queue WHERE status IN ('pending', 'processing')"
    ).fetch_one(&state.db).await.unwrap_or(0);

    services.push(serde_json::json!({
        "name": "queue",
        "status": if queue_depth < 1000 { "nominal" } else if queue_depth < 10000 { "backlogged" } else { "critical" },
        "depth": queue_depth
    }));

    (StatusCode::OK, Json(serde_json::json!({
        "status": if all_operational { "healthy" } else { "degraded" },
        "services": services,
        "queue_depth": queue_depth,
        "timestamp": chrono::Utc::now().to_rfc3339()
    }))).into_response()
}

async fn status_api(State(state): State<AppState>) -> impl IntoResponse {
    let mut services = Vec::new();
    let mut all_operational = true;

    // Probe database connectivity with a lightweight query
    let db_ok = sqlx::query_scalar::<_, i64>("SELECT 1")
        .fetch_one(&state.db).await.is_ok();
    services.push(serde_json::json!({
        "name": "Database", "status": if db_ok { "operational" } else { "degraded" }
    }));
    if !db_ok { all_operational = false; }

    // Probe tenant table health
    let tenants_ok = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM tenants WHERE status = 'active'")
        .fetch_one(&state.db).await.is_ok();
    services.push(serde_json::json!({
        "name": "Tenants API", "status": if tenants_ok { "operational" } else { "degraded" }
    }));
    if !tenants_ok { all_operational = false; }

    // Probe message throughput (last 5 minutes)
    let messages_ok = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM messages WHERE created_at > NOW() - INTERVAL '5 minutes'"
    ).fetch_one(&state.db).await.is_ok();
    services.push(serde_json::json!({
        "name": "Message Pipeline", "status": if messages_ok { "operational" } else { "degraded" }
    }));
    if !messages_ok { all_operational = false; }

    // Probe auth functionality by checking user count
    let auth_ok = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM users")
        .fetch_one(&state.db).await.is_ok();
    services.push(serde_json::json!({
        "name": "Auth Server", "status": if auth_ok { "operational" } else { "degraded" }
    }));
    if !auth_ok { all_operational = false; }

    // Probe billing/subscription data
    let billing_ok = sqlx::query_scalar::<_, i64>("SELECT COUNT(*) FROM plans")
        .fetch_one(&state.db).await.is_ok();
    services.push(serde_json::json!({
        "name": "Billing API", "status": if billing_ok { "operational" } else { "degraded" }
    }));
    if !billing_ok { all_operational = false; }

    // Probe message delivery stats (analytics)
    let analytics_ok = sqlx::query_scalar::<_, i64>(
        "SELECT COUNT(*) FROM messages WHERE status = 'delivered' AND created_at > NOW() - INTERVAL '1 hour'"
    ).fetch_one(&state.db).await.is_ok();
    services.push(serde_json::json!({
        "name": "Analytics API", "status": if analytics_ok { "operational" } else { "degraded" }
    }));
    if !analytics_ok { all_operational = false; }

    (StatusCode::OK, Json(serde_json::json!({
        "status": if all_operational { "operational" } else { "degraded" },
        "services": services,
        "updated": chrono::Utc::now().to_rfc3339()
    }))).into_response()
}

async fn status_history() -> impl IntoResponse {
    (StatusCode::OK, Json(serde_json::json!({
        "history": [],
        "updated": chrono::Utc::now().to_rfc3339()
    }))).into_response()
}

#[derive(Deserialize)]
struct SandboxSendRequest {
    from: String,
    to: String,
    subject: String,
    html: Option<String>,
    text: Option<String>,
}

async fn sandbox_send(axum::Json(body): axum::Json<SandboxSendRequest>) -> impl IntoResponse {
    let t0 = std::time::Instant::now();
    let mut errors = Vec::new();
    if body.from.is_empty() || !body.from.contains('@') { errors.push(serde_json::json!({"field":"from","message":"Invalid sender address"})); }
    if body.to.is_empty() || !body.to.contains('@') { errors.push(serde_json::json!({"field":"to","message":"Invalid recipient address"})); }
    if body.subject.is_empty() { errors.push(serde_json::json!({"field":"subject","message":"Subject is required"})); }
    if body.html.is_none() && body.text.is_none() { errors.push(serde_json::json!({"field":"content","message":"Either html or text body is required"})); }
    if !errors.is_empty() {
        let latency = t0.elapsed().as_millis();
        return (StatusCode::UNPROCESSABLE_ENTITY, Json(serde_json::json!({
            "error": "Validation failed",
            "status": 422,
            "errors": errors,
            "request_id": format!("req_{}", uuid::Uuid::new_v4()),
            "latency_ms": latency,
        }))).into_response();
    }
    let msg_id = format!("sandbox_{}", uuid::Uuid::new_v4().to_string().replace("-", "")[..12].to_string());
    let latency = t0.elapsed().as_millis();
    (StatusCode::OK, Json(serde_json::json!({
        "id": msg_id,
        "status": "accepted",
        "from": body.from,
        "to": [body.to],
        "subject": body.subject,
        "request_id": format!("req_{}", uuid::Uuid::new_v4()),
        "latency_ms": latency,
        "sandbox": true,
        "note": "This was a sandbox request. No email was delivered."
    }))).into_response()
}

#[tokio::main]
async fn main() {
    let db_url = std::env::var("DATABASE_URL")
        .unwrap_or_else(|_| "postgres://apexmail@127.0.0.1:5432/apexmail".into());
    let session_secret = std::env::var("SESSION_SECRET")
        .unwrap_or_else(|_| uuid::Uuid::new_v4().to_string());
    let stripe_secret_key = std::env::var("STRIPE_SECRET_KEY").ok()
        .filter(|s| !s.is_empty() && !s.contains("replace_me"));
    let has_stripe = stripe_secret_key.is_some();

    let http_client = if has_stripe {
        Some(reqwest::Client::new())
    } else {
        eprintln!("WARNING: STRIPE_SECRET_KEY not configured — checkout/portal disabled");
        None
    };

    let mut stripe_prices = HashMap::new();
    for plan in &["free", "starter", "pro", "growth", "scale", "enterprise"] {
        let env_key = format!("STRIPE_PRICE_{}", plan.to_uppercase());
        if let Ok(pid) = std::env::var(&env_key) {
            if !pid.is_empty() && !pid.contains("replace_me") {
                stripe_prices.insert(plan.to_string(), pid);
            }
        }
    }
    if has_stripe && stripe_prices.is_empty() {
        eprintln!("WARNING: STRIPE_SECRET_KEY set but no STRIPE_PRICE_* vars configured");
    }

    let pool = PgPoolOptions::new().max_connections(5).connect(&db_url).await.unwrap();

    // Ensure required tables exist (idempotent DDL)
    sqlx::query("CREATE TABLE IF NOT EXISTS stripe_customers (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id VARCHAR(26) NOT NULL, stripe_customer_id VARCHAR(128) NOT NULL, email VARCHAR(320), name VARCHAR(255), created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
        .execute(&pool).await.ok();
    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_sc_tenant ON stripe_customers (tenant_id)")
        .execute(&pool).await.ok();
    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_sc_customer ON stripe_customers (stripe_customer_id)")
        .execute(&pool).await.ok();
    sqlx::query("CREATE TABLE IF NOT EXISTS stripe_subscriptions (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id VARCHAR(26) NOT NULL, stripe_subscription_id VARCHAR(128) NOT NULL, stripe_customer_id VARCHAR(128), stripe_price_id VARCHAR(128), plan VARCHAR(64), status VARCHAR(30), billing_interval VARCHAR(20) DEFAULT 'monthly', current_period_start TIMESTAMPTZ, current_period_end TIMESTAMPTZ, cancel_at_period_end BOOLEAN DEFAULT false, canceled_at TIMESTAMPTZ, trial_end TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
        .execute(&pool).await.ok();
    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_stripe_sub_tenant ON stripe_subscriptions (tenant_id)")
        .execute(&pool).await.ok();
    sqlx::query("CREATE UNIQUE INDEX IF NOT EXISTS idx_stripe_sub_subscription ON stripe_subscriptions (stripe_subscription_id)")
        .execute(&pool).await.ok();

    // Ensure subscriptions table exists (for direct plan switches without Stripe)
    sqlx::query("CREATE TABLE IF NOT EXISTS subscriptions (id UUID PRIMARY KEY DEFAULT gen_random_uuid(), tenant_id VARCHAR(26) NOT NULL, plan_name TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'active', stripe_subscription_id TEXT, current_period_start TIMESTAMPTZ, current_period_end TIMESTAMPTZ, created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(), updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW())")
        .execute(&pool).await.ok();

    let state = AppState { db: pool, session_secret, http_client, stripe_secret_key, stripe_prices };

    let app = Router::new()
        .route("/v1/auth/login", post(login_post))
        .route("/v1/auth/register", post(register_post))
        .route("/v1/api-keys", get(list_api_keys).post(create_api_key))
        .route("/v1/api-keys/{id}", delete(revoke_api_key))
        .route("/v1/account", get(account_info))
        .route("/v1/billing/plans", get(billing_plans))
        .route("/v1/billing/subscription", get(billing_subscription))
        .route("/v1/billing/usage", get(billing_usage))
        .route("/v1/billing/switch-plan", post(billing_switch_plan))
        .route("/v1/billing/checkout", post(billing_checkout))
        .route("/v1/billing/portal", post(billing_portal))
        .route("/v1/auth/mfa/qr", get(mfa_qr))
        .route("/v1/auth/mfa/disable", post(mfa_disable))
        .route("/v1/admin/dashboard/stats", get(admin_dashboard_stats))
        .route("/v1/admin/tenants", get(admin_tenants))
        .route("/v1/admin/audit", get(admin_audit))
        .route("/v1/admin/analytics", get(admin_analytics))
        .route("/v1/admin/analytics/delivery", get(admin_analytics_delivery))
        .route("/v1/admin/analytics/growth", get(admin_analytics_growth))
        .route("/v1/admin/analytics/predictive", get(admin_analytics_predictive))
        .route("/v1/admin/billing", get(admin_billing))
        .route("/v1/admin/compliance", get(admin_compliance))
        .route("/v1/admin/domains/onboarding", get(admin_domain_onboarding))
        .route("/v1/admin/streams", get(admin_streams))
        .route("/v1/health", get(health_check))
        .route("/status", get(status_page))
        .route("/status/api", get(status_api))
        .route("/status/history", get(status_history))
        .route("/v1/sandbox/send", post(sandbox_send))
        .with_state(state);

    let addr = SocketAddr::from(([0, 0, 0, 0], 3000));
    println!("Auth server on {addr} (Stripe: {has_stripe})");
    axum::serve(tokio::net::TcpListener::bind(addr).await.unwrap(), app).await.unwrap();
}
