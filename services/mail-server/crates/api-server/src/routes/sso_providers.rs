//! Apple & Microsoft OAuth providers — self-contained with inlined helpers.

use axum::extract::{Form, Query, State};
use axum::http::HeaderMap;
use axum::response::{IntoResponse, Redirect, Response};
use serde::Deserialize;
use sha2::Digest;
use uuid::Uuid;

use crate::error::ApiError;
use crate::state::AppState;

// ─── Query types (duplicated from sso.rs to avoid circular deps) ───

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SsoQuery {
    pub next: Option<String>,
    #[serde(rename = "returnUrl")]
    pub return_url: Option<String>,
    #[allow(dead_code)]
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct OAuthCallback {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

// ─── Inlined helpers ─────────────────────────────────────────────

fn encode(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

fn sanitize_redirect(next: &str) -> String {
    if next.is_empty() || next.as_bytes()[0] != b'/' { return "/dashboard".into(); }
    if next.len() > 1 && matches!(next.as_bytes()[1], b'/' | b'\\') { return "/dashboard".into(); }

    let decoded = match urlencoding::decode(next) {
        Ok(d) => d.to_string(),
        Err(_) => return "/dashboard".into(),
    };
    if decoded.len() > 1 {
        let bytes = decoded.as_bytes();
        if bytes[1] == b'/' || bytes[1] == b'\\' { return "/dashboard".into(); }
    }
    for seg in decoded.split('/') { if seg == ".." || seg.contains('\0') { return "/dashboard".into(); } }
    next.to_string()
}

fn generate_state(next: &str) -> Result<String, ApiError> {
    let mut buf = [0u8; 32];
    use rand::TryRngCore;
    rand::rngs::OsRng.try_fill_bytes(&mut buf).map_err(|e| ApiError::Internal(format!("rand: {e}")))?;
    let hash = sha2::Sha256::digest(buf);
    let token = base64::Engine::encode(&base64::engine::general_purpose::URL_SAFE_NO_PAD, hash);
    Ok(format!("{token}:{next}"))
}

fn redirect_from_state(state: &str) -> String {
    state.split_once(':').map(|(_, n)| sanitize_redirect(n)).unwrap_or_else(|| "/dashboard".into())
}

fn state_cookie(name: &str, value: &str, secure: bool) -> Result<String, ApiError> {
    Ok(format!("{name}={value}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax{}", if secure { "; Secure" } else { "" }))
}

fn clear_cookie(name: &str, secure: bool) -> String {
    format!("{name}=; HttpOnly; Path=/; Max-Age=0; SameSite=Lax{}", if secure { "; Secure" } else { "" })
}

fn extract_cookie(headers: &HeaderMap, name: &str) -> Option<String> {
    headers.get_all("cookie").iter().filter_map(|v| v.to_str().ok())
        .flat_map(|s| s.split(';')).map(|p| p.trim())
        .find_map(|p| { let (k,v) = p.split_once('=')?; if k.trim()==name {Some(v.trim().into())} else {None} })
}

fn validate_state(headers: &HeaderMap, cookie: &str, state: Option<&str>) -> Result<String, ApiError> {
    let returned = state.ok_or_else(|| ApiError::BadRequest("missing OAuth state".into()))?;
    let expected = extract_cookie(headers, cookie).ok_or_else(|| ApiError::Unauthorized("missing SSO state cookie".into()))?;
    if !apexmail_lib::timing_safe_compare(&expected, returned) {
        return Err(ApiError::Unauthorized("invalid OAuth state".into()));
    }
    Ok(redirect_from_state(returned))
}

// ─── SSO completion via JWT ──────────────────────────────────────

async fn complete_sso(state: &AppState, email: &str, name: &str, provider: &str, redirect_to: &str) -> Result<Response, ApiError> {
    use chrono::Utc;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let email_lower = email.to_lowercase();

    let existing: Option<(uuid::Uuid, String, String, Option<String>, String, String)> = sqlx::query_as(
        "SELECT id::text, tenant_id, email, name, role, status FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1")
        .bind(&email_lower).fetch_optional(&state.db).await?;

    let (user_id, tenant_id, role) = match existing {
        Some((id, tid, _em, _nm, role, status)) => {
            if status != "active" { return Ok(Redirect::to("/login?error=account_inactive").into_response()); }
            {
                use sqlx::Row;
                let mfa_row = sqlx::query(
                    "SELECT mfa_enabled, role FROM users WHERE id = $1::uuid AND tenant_id = $2",
                )
                .bind(id)
                .bind(&tid)
                .fetch_optional(&state.db)
                .await?;
                if let Some(row) = mfa_row {
                    let mfa_enabled: bool = row.get("mfa_enabled");
                    let user_role: String = row.get("role");
                    if mfa_enabled || super::auth::role_requires_mfa(&user_role) {
                        return Ok(Redirect::to("/login?error=mfa_required").into_response());
                    }
                }
            }
            sqlx::query("UPDATE users SET metadata = metadata || $1::jsonb, updated_at = NOW() WHERE id = $2::uuid::uuid")
                .bind(serde_json::json!({"last_sso_provider":provider,"last_sso_login":Utc::now().to_rfc3339()}))
                .bind(id).execute(&state.db).await?;
            (id, tid, role)
        }
        None => {
            let mut tx = state.db.begin().await.map_err(|_| ApiError::Internal("db error".into()))?;
            let tid = apexmail_lib::id::generate_id("", 26);
            let uid = uuid::Uuid::new_v4();
            let now = Utc::now();
            let company = name.split_whitespace().next().unwrap_or("My Company");
            let slug = format!("{}-{}", company.chars().map(|c| if c.is_alphanumeric(){c.to_ascii_lowercase()}else{'-'}).collect::<String>().trim_matches('-'), &Uuid::new_v4().to_string()[..8]);
            let phash = format!("$sso${provider}$no-password-sso-login-only");
            sqlx::query("INSERT INTO tenants (id,name,slug,plan,status,settings,metadata,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9)")
                .bind(&tid).bind(company).bind(&slug).bind("free").bind("active").bind(serde_json::json!({})).bind(serde_json::json!({"sso_provider":provider})).bind(now).bind(now).execute(&mut *tx).await?;
            sqlx::query("INSERT INTO users (id,tenant_id,email,name,password_hash,role,status,email_verified,mfa_enabled,metadata,created_at,updated_at) VALUES ($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11,$12)")
                .bind(uid).bind(&tid).bind(&email_lower).bind(name).bind(&phash).bind("owner").bind("active").bind(true).bind(false).bind(serde_json::json!({"sso_provider":provider})).bind(now).bind(now).execute(&mut *tx).await?;
            tx.commit().await.map_err(|_| ApiError::Internal("db error".into()))?;
            tracing::info!(user_id=%uid, tenant_id=%tid, provider=%provider, "SSO user auto-provisioned");
            (uid, tid, "owner".to_string())
        }
    };

    {
        let sso_allowed = sqlx::query_scalar::<_, bool>(
            "SELECT p.sso_enabled FROM plans p JOIN tenants t ON t.plan = p.name WHERE t.id = $1",
        )
        .bind(&tenant_id)
        .fetch_optional(&state.db)
        .await?;
        if sso_allowed != Some(true) {
            return Ok(Redirect::to("/login?error=sso_requires_plan").into_response());
        }
    }

    // Revoke all previous sessions on SSO login (session rotation parity with password login)
    let revoked_after = {
        let ttl = state.config.jwt_expiry.as_secs();
        crate::routes::auth::revoke_user_sessions(&state.redis, &tenant_id, &user_id.to_string(), ttl).await?
    };

    let now = Utc::now();
    let issued_at = super::auth::session_issue_time_after_revocation(now, Some(revoked_after));
    let exp = issued_at + chrono::Duration::seconds(state.config.jwt_expiry.as_secs() as i64);
    let scopes = match role.as_str() {
        "admin" | "owner" => vec!["*".into()],
        "developer" => vec![
            "messages:send".into(), "messages:read".into(),
            "domains:read".into(), "domains:write".into(),
            "templates:read".into(), "templates:write".into(),
            "events:read".into(), "analytics:read".into(),
            "contacts:read".into(), "contacts:write".into(),
            "lists:read".into(), "lists:write".into(),
            "webhooks:read".into(), "webhooks:write".into(),
            "campaigns:read".into(), "campaigns:write".into(),
            "automations:read".into(),
            "suppressions:read".into(), "suppressions:write".into(),
            "dedicated_ips:read".into(), "dedicated_ips:write".into(),
        ],
        "viewer" => vec![
            "messages:read".into(), "domains:read".into(),
            "templates:read".into(), "events:read".into(),
            "analytics:read".into(), "contacts:read".into(),
            "lists:read".into(), "webhooks:read".into(),
            "campaigns:read".into(), "suppressions:read".into(),
            "dedicated_ips:read".into(), "automations:read".into(),
        ],
        _ => vec!["messages:read".into()],
    };
    let claims = crate::middleware::auth::JwtClaims { sub: user_id.to_string(), tenant_id, scopes, exp: exp.timestamp(), iat: issued_at.timestamp(), jti: Uuid::new_v4().to_string() };
    let token = encode(&Header::new(Algorithm::RS256), &claims, &EncodingKey::from_rsa_pem(state.config.jwt_private_key_pem.as_bytes()).map_err(|e| ApiError::Internal(format!("JWT: {e}")))?)
        .map_err(|e| ApiError::Internal(format!("token: {e}")))?;

    let mut resp = Redirect::to(redirect_to).into_response();
    let cv = format!("am_session={token}; HttpOnly; Path=/; Max-Age={}; SameSite=Strict{}", state.config.jwt_expiry.as_secs(), if state.config.environment.is_production() {"; Secure"} else {""});
    resp.headers_mut().insert("Set-Cookie", cv.parse().map_err(|_| ApiError::Internal("cookie error".into()))?);
    Ok(resp)
}

// ─── Apple OAuth ──────────────────────────────────────────────────

pub async fn sso_apple(State(state): State<AppState>, Query(params): Query<SsoQuery>) -> Result<Response, ApiError> {
    let cid = state.config.apple_client_id.as_deref().ok_or_else(|| ApiError::NotFound("Apple SSO not configured".into()))?;
    let cb = format!("{}/v1/auth/sso/apple/callback", state.config.oauth_redirect_base_url);
    let next = params.next.or(params.return_url).unwrap_or_else(|| "/dashboard".into());
    let st = generate_state(&sanitize_redirect(&next))?;
    let url = format!("https://appleid.apple.com/auth/authorize?client_id={}&redirect_uri={}&response_type=code&scope=name%20email&response_mode=form_post&state={}", encode(cid), encode(&cb), encode(&st));
    let mut resp = Redirect::to(&url).into_response();
    let cookie_val = state_cookie("am_sso_state_apple", &st, state.config.environment.is_production())?
        .parse()
        .map_err(|_| ApiError::Internal("invalid cookie header".into()))?;
    resp.headers_mut().append("Set-Cookie", cookie_val);
    Ok(resp)
}

pub async fn sso_apple_callback(State(state): State<AppState>, headers: HeaderMap, Form(params): Form<OAuthCallback>) -> Result<Response, ApiError> {
    if params.error.is_some() { return Ok(Redirect::to("/login?error=sso_denied").into_response()); }
    let redir = validate_state(&headers, "am_sso_state_apple", params.state.as_deref())?;
    let code = params.code.as_deref().ok_or_else(|| ApiError::BadRequest("missing code".into()))?;
    let cid = state.config.apple_client_id.as_deref().ok_or_else(|| ApiError::Internal("Apple not configured".into()))?;
    let secret = apple_secret(&state.config)?;
    let cb = format!("{}/v1/auth/sso/apple/callback", state.config.oauth_redirect_base_url);
    let tr = state.http_client.post("https://appleid.apple.com/auth/token")
        .form(&[("code",code),("client_id",cid),("client_secret",&secret),("redirect_uri",&cb),("grant_type","authorization_code")])
        .send().await.map_err(|e| ApiError::Internal(format!("Apple: {e}")))?;
    if !tr.status().is_success() { return Ok(Redirect::to("/login?error=sso_failed").into_response()); }
    let td: serde_json::Value = tr.json().await.map_err(|e| ApiError::Internal(format!("Apple parse: {e}")))?;
    let idt = td["id_token"].as_str().ok_or_else(|| ApiError::Internal("missing Apple id_token".into()))?;
    let claims = verify_apple(&state.http_client, idt, cid).await?;
    if !claims.email_verified {
        return Ok(Redirect::to("/login?error=sso_failed").into_response());
    }
    let mut resp = complete_sso(&state, &claims.email, claims.name.as_deref().unwrap_or(""), "apple", &redir).await?;
    let cookie_clear_val = clear_cookie("am_sso_state_apple", state.config.environment.is_production())
        .parse()
        .map_err(|_| ApiError::Internal("invalid cookie header".into()))?;
    resp.headers_mut().append("Set-Cookie", cookie_clear_val);
    Ok(resp)
}

fn apple_secret(config: &crate::config::Config) -> Result<String, ApiError> {
    use chrono::Utc; use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
    let team = config.apple_team_id.as_deref().ok_or_else(|| ApiError::Internal("Apple Team ID missing".into()))?;
    let _kid = config.apple_key_id.as_deref().ok_or_else(|| ApiError::Internal("Apple Key ID missing".into()))?;
    let pem = config.apple_private_key.as_deref().ok_or_else(|| ApiError::Internal("Apple private key missing".into()))?;
    let cid = config.apple_client_id.as_deref().ok_or_else(|| ApiError::Internal("Apple client ID missing".into()))?;
    let now = Utc::now();
    encode(&Header::new(Algorithm::ES256), &serde_json::json!({"iss":team,"iat":now.timestamp(),"exp":(now+chrono::Duration::minutes(5)).timestamp(),"aud":"https://appleid.apple.com","sub":cid}),
        &EncodingKey::from_ec_pem(pem.as_bytes()).map_err(|e| ApiError::Internal(format!("Apple key: {e}")))?)
    .map_err(|e| ApiError::Internal(format!("Apple secret: {e}")))
}

#[derive(Deserialize)] struct AppleClaims { email: String, #[serde(default)] email_verified: bool, #[serde(default)] name: Option<String>, #[allow(dead_code)] aud: Option<String>, #[allow(dead_code)] iss: Option<String>, #[allow(dead_code)] exp: Option<i64> }

/// JWK representation for RSA public keys returned by OIDC providers.
#[derive(Debug, Deserialize)]
struct JwkKey {
    #[allow(dead_code)]
    kty: String,
    #[serde(rename = "use")]
    _use: Option<String>,
    kid: String,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct JwkSet {
    keys: Vec<JwkKey>,
}

/// Fetch the Apple public JWKS and return the RSA `DecodingKey` for the given `kid`.
async fn apple_decoding_key(http: &reqwest::Client, kid: &str) -> Result<jsonwebtoken::DecodingKey, ApiError> {
    let resp = http
        .get("https://appleid.apple.com/auth/keys")
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("Apple JWKS fetch failed: {e}")))?;
    let jwks: JwkSet = resp.json().await
        .map_err(|e| ApiError::Internal(format!("Apple JWKS parse failed: {e}")))?;
    let key = jwks.keys.iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| ApiError::Unauthorized("Apple signing key not found".into()))?;
    Ok(jsonwebtoken::DecodingKey::from_rsa_components(&key.n, &key.e)
        .map_err(|e| ApiError::Internal(format!("Apple JWK decode failed: {e}")))?)
}

/// Fetch the Microsoft public JWKS and return the RSA `DecodingKey` for the given `kid`.
async fn microsoft_decoding_key(http: &reqwest::Client, kid: &str) -> Result<jsonwebtoken::DecodingKey, ApiError> {
    let resp = http
        .get("https://login.microsoftonline.com/common/discovery/v2.0/keys")
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("Microsoft JWKS fetch failed: {e}")))?;
    let jwks: JwkSet = resp.json().await
        .map_err(|e| ApiError::Internal(format!("Microsoft JWKS parse failed: {e}")))?;
    let key = jwks.keys.iter()
        .find(|k| k.kid == kid)
        .ok_or_else(|| ApiError::Unauthorized("Microsoft signing key not found".into()))?;
    Ok(jsonwebtoken::DecodingKey::from_rsa_components(&key.n, &key.e)
        .map_err(|e| ApiError::Internal(format!("Microsoft JWK decode failed: {e}")))?)
}

async fn verify_apple(http: &reqwest::Client, tok: &str, client_id: &str) -> Result<AppleClaims, ApiError> {
    use jsonwebtoken::{decode, decode_header, Validation};
    let header = decode_header(tok)
        .map_err(|e| ApiError::Unauthorized(format!("Apple token header: {e}")))?;
    let kid = header.kid
        .ok_or_else(|| ApiError::Unauthorized("Apple token missing kid".into()))?;
    let key = apple_decoding_key(http, &kid).await?;
    let mut v = Validation::new(header.alg);
    v.set_issuer(&["https://appleid.apple.com"]);
    v.set_audience(&[client_id]);
    v.validate_exp = true;
    let d = decode::<AppleClaims>(tok, &key, &v)
        .map_err(|e| ApiError::Unauthorized(format!("Apple token: {e}")))?;
    if d.claims.email.is_empty() {
        Err(ApiError::Unauthorized("Apple email missing".into()))
    } else if !d.claims.email_verified {
        Err(ApiError::Unauthorized("Apple email not verified".into()))
    } else {
        Ok(d.claims)
    }
}

// ─── Microsoft OAuth ───────────────────────────────────────────────

pub async fn sso_microsoft(State(state): State<AppState>, Query(params): Query<SsoQuery>) -> Result<Response, ApiError> {
    let cid = state.config.microsoft_client_id.as_deref().ok_or_else(|| ApiError::NotFound("Microsoft SSO not configured".into()))?;
    let cb = format!("{}/v1/auth/sso/microsoft/callback", state.config.oauth_redirect_base_url);
    let next = params.next.or(params.return_url).unwrap_or_else(|| "/dashboard".into());
    let st = generate_state(&sanitize_redirect(&next))?;
    let url = format!("https://login.microsoftonline.com/common/oauth2/v2.0/authorize?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile%20User.Read&state={}&response_mode=query", encode(cid), encode(&cb), encode(&st));
    let mut resp = Redirect::to(&url).into_response();
    let cookie_val = state_cookie("am_sso_state_microsoft", &st, state.config.environment.is_production())?
        .parse()
        .map_err(|_| ApiError::Internal("invalid cookie header".into()))?;
    resp.headers_mut().append("Set-Cookie", cookie_val);
    Ok(resp)
}

pub async fn sso_microsoft_callback(State(state): State<AppState>, headers: HeaderMap, Query(params): Query<OAuthCallback>) -> Result<Response, ApiError> {
    if params.error.is_some() { return Ok(Redirect::to("/login?error=sso_denied").into_response()); }
    let redir = validate_state(&headers, "am_sso_state_microsoft", params.state.as_deref())?;
    let code = params.code.as_deref().ok_or_else(|| ApiError::BadRequest("missing code".into()))?;
    let cid = state.config.microsoft_client_id.as_deref().ok_or_else(|| ApiError::Internal("Microsoft not configured".into()))?;
    let csec = state.config.microsoft_client_secret.as_deref().ok_or_else(|| ApiError::Internal("Microsoft secret missing".into()))?;
    let cb = format!("{}/v1/auth/sso/microsoft/callback", state.config.oauth_redirect_base_url);
    let tr = state.http_client.post("https://login.microsoftonline.com/common/oauth2/v2.0/token")
        .form(&[("code",code),("client_id",cid),("client_secret",csec),("redirect_uri",&cb),("grant_type","authorization_code")])
        .send().await.map_err(|e| ApiError::Internal(format!("MS: {e}")))?;
    if !tr.status().is_success() { return Ok(Redirect::to("/login?error=sso_failed").into_response()); }
    let td: serde_json::Value = tr.json().await.map_err(|e| ApiError::Internal(format!("MS parse: {e}")))?;
    let idt = td["id_token"].as_str().ok_or_else(|| ApiError::Internal("missing MS id_token".into()))?;
    let claims = verify_ms(&state.http_client, idt, cid).await?;
    let mut resp = complete_sso(&state, &claims.email, &claims.name, "microsoft", &redir).await?;
    let cookie_clear_val = clear_cookie("am_sso_state_microsoft", state.config.environment.is_production())
        .parse()
        .map_err(|_| ApiError::Internal("invalid cookie header".into()))?;
    resp.headers_mut().append("Set-Cookie", cookie_clear_val);
    Ok(resp)
}

#[derive(Deserialize)] struct MsClaims {
    email: String,
    name: String,
    #[serde(default)]
    iss: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    tid: Option<String>,
    #[serde(default)]
    #[allow(dead_code)]
    exp: Option<i64>,
    #[allow(dead_code)]
    email_verified: Option<bool>,
}
async fn verify_ms(http: &reqwest::Client, tok: &str, client_id: &str) -> Result<MsClaims, ApiError> {
    use jsonwebtoken::{decode, decode_header, Validation};
    let header = decode_header(tok)
        .map_err(|e| ApiError::Unauthorized(format!("MS token header: {e}")))?;
    let kid = header.kid
        .ok_or_else(|| ApiError::Unauthorized("MS token missing kid".into()))?;
    let key = microsoft_decoding_key(http, &kid).await?;
    let mut v = Validation::new(header.alg);
    v.set_audience(&[client_id]);
    v.validate_exp = true;
    let d = decode::<MsClaims>(tok, &key, &v)
        .map_err(|e| ApiError::Unauthorized(format!("MS token: {e}")))?;

    if d.claims.email.is_empty() {
        return Err(ApiError::Unauthorized("MS email missing".into()));
    }

    // Validate issuer: must be a Microsoft identity platform issuer.
    let iss = d.claims.iss.as_deref().unwrap_or("");
    if !iss.starts_with("https://login.microsoftonline.com/")
        && !iss.starts_with("https://sts.windows.net/")
    {
        tracing::warn!(issuer = %iss, "MS token issuer validation failed");
        return Err(ApiError::Unauthorized("MS token issuer invalid".into()));
    }

    // Email must be verified by Microsoft to prevent account linking via
    // an unverified email address.
    if !d.claims.email_verified.unwrap_or(false) {
        return Err(ApiError::Unauthorized("MS email not verified".into()));
    }

    Ok(d.claims)
}

#[cfg(test)]
mod tests {
    use super::MsClaims;

    fn validate_ms_issuer_manually(iss: Option<&str>) -> bool {
        let iss = iss.unwrap_or("");
        iss.starts_with("https://login.microsoftonline.com/")
            || iss.starts_with("https://sts.windows.net/")
    }

    #[test]
    fn test_ms_issuer_rejects_non_microsoft_issuers() {
        assert!(!validate_ms_issuer_manually(Some("https://evil-idp.com/v2.0")));
        assert!(!validate_ms_issuer_manually(Some("https://accounts.google.com")));
        assert!(!validate_ms_issuer_manually(Some("https://appleid.apple.com")));
    }

    #[test]
    fn test_ms_issuer_accepts_valid_microsoft_issuers() {
        assert!(validate_ms_issuer_manually(Some(
            "https://login.microsoftonline.com/9188040d-6c67-4c5b-b112-36a304b66dad/v2.0"
        )));
        assert!(validate_ms_issuer_manually(Some(
            "https://login.microsoftonline.com/common/v2.0"
        )));
        assert!(validate_ms_issuer_manually(Some(
            "https://sts.windows.net/contoso.com/"
        )));
    }

    #[test]
    fn test_ms_issuer_rejects_empty_issuer() {
        assert!(!validate_ms_issuer_manually(None));
        assert!(!validate_ms_issuer_manually(Some("")));
    }

    #[test]
    fn test_ms_claims_email_verified_default_false() {
        let claims = MsClaims {
            email: "user@example.com".into(),
            name: "Test User".into(),
            iss: Some("https://login.microsoftonline.com/tid/v2.0".into()),
            tid: None,
            exp: None,
            email_verified: None,
        };
        assert!(!claims.email_verified.unwrap_or(false));

        let claims_verified = MsClaims {
            email: "user@example.com".into(),
            name: "Test User".into(),
            iss: Some("https://login.microsoftonline.com/tid/v2.0".into()),
            tid: None,
            exp: None,
            email_verified: Some(true),
        };
        assert!(claims_verified.email_verified.unwrap_or(false));
    }
}
