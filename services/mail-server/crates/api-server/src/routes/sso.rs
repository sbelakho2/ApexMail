//! OAuth / SSO initiation endpoints.
//!
//! Migrated from:
//!   - apps/web/src/app/api/auth/sso/google/route.ts
//!   - apps/web/src/app/api/auth/sso/github/route.ts
//!
//! These endpoints generate OAuth state tokens, set state cookies,
//! and redirect to the OAuth provider authorization URLs.

use axum::extract::{Query, State};
use axum::response::{IntoResponse, Redirect, Response};
use axum::routing::get;
use axum::Router;
use serde::Deserialize;

use crate::error::ApiError;
use crate::state::AppState;

/// Percent-encode a string for use in URL query parameters.
fn encode_uri_component(s: &str) -> String {
    url::form_urlencoded::byte_serialize(s.as_bytes()).collect()
}

pub fn router() -> Router<AppState> {
    Router::new()
        .route("/google", get(sso_google))
        .route("/github", get(sso_github))
        .route("/google/callback", get(sso_google_callback))
        .route("/github/callback", get(sso_github_callback))
}

// ─── Query params ──────────────────────────────────────────────

#[derive(Debug, Deserialize)]
pub struct SsoInitQuery {
    /// Where to redirect after successful auth
    #[serde(default)]
    pub next: Option<String>,
    /// Return URL passed by frontend
    #[serde(rename = "returnUrl")]
    #[serde(default)]
    pub return_url: Option<String>,
    /// OAuth state parameter
    #[serde(default)]
    pub state: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct OAuthCallbackQuery {
    pub code: Option<String>,
    pub state: Option<String>,
    pub error: Option<String>,
}

// ─── SSO Initiation Handlers ──────────────────────────────────

async fn sso_google(
    State(state): State<AppState>,
    Query(params): Query<SsoInitQuery>,
) -> Result<Response, ApiError> {
    let client_id = state
        .config
        .google_client_id
        .as_deref()
        .ok_or_else(|| ApiError::ServiceUnavailable("Google SSO is not configured".into()))?;

    let redirect_base = &state.config.oauth_redirect_base_url;
    let callback_url = format!("{redirect_base}/v1/auth/sso/google/callback");

    let next = params
        .next
        .or(params.return_url)
        .unwrap_or_else(|| "/dashboard".into());
    let safe_next = sanitize_redirect(&next);

    let oauth_state = generate_oauth_state(&safe_next);

    let auth_url = format!(
        "https://accounts.google.com/o/oauth2/v2/auth?client_id={}&redirect_uri={}&response_type=code&scope=openid%20email%20profile&state={}&access_type=offline&prompt=consent",
        encode_uri_component(client_id),
        encode_uri_component(&callback_url),
        encode_uri_component(&oauth_state),
    );

    // Set state cookie and redirect
    let mut response = Redirect::to(&auth_url).into_response();
    set_state_cookie(&mut response, "am_sso_state_google", &oauth_state, state.config.environment.is_production());
    Ok(response)
}

async fn sso_github(
    State(state): State<AppState>,
    Query(params): Query<SsoInitQuery>,
) -> Result<Response, ApiError> {
    let client_id = state
        .config
        .github_client_id
        .as_deref()
        .ok_or_else(|| ApiError::ServiceUnavailable("GitHub SSO is not configured".into()))?;

    let redirect_base = &state.config.oauth_redirect_base_url;
    let callback_url = format!("{redirect_base}/v1/auth/sso/github/callback");

    let next = params
        .next
        .or(params.return_url)
        .unwrap_or_else(|| "/dashboard".into());
    let safe_next = sanitize_redirect(&next);

    let oauth_state = generate_oauth_state(&safe_next);

    let auth_url = format!(
        "https://github.com/login/oauth/authorize?client_id={}&redirect_uri={}&scope=read:user%20user:email&state={}",
        encode_uri_component(client_id),
        encode_uri_component(&callback_url),
        encode_uri_component(&oauth_state),
    );

    let mut response = Redirect::to(&auth_url).into_response();
    set_state_cookie(&mut response, "am_sso_state_github", &oauth_state, state.config.environment.is_production());
    Ok(response)
}

// ─── OAuth Callback Handlers ──────────────────────────────────

async fn sso_google_callback(
    State(state): State<AppState>,
    Query(params): Query<OAuthCallbackQuery>,
) -> Result<Response, ApiError> {
    if let Some(error) = &params.error {
        tracing::warn!(error = %error, "Google OAuth error");
        return Ok(Redirect::to("/login?error=sso_denied").into_response());
    }

    let code = params
        .code
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("missing authorization code".into()))?;

    let client_id = state
        .config
        .google_client_id
        .as_deref()
        .ok_or_else(|| ApiError::Internal("Google SSO not configured".into()))?;
    let client_secret = state
        .config
        .google_client_secret
        .as_deref()
        .ok_or_else(|| ApiError::Internal("Google SSO secret not configured".into()))?;

    let redirect_base = &state.config.oauth_redirect_base_url;
    let callback_url = format!("{redirect_base}/v1/auth/sso/google/callback");

    // Exchange code for tokens
    let token_resp = state
        .http_client
        .post("https://oauth2.googleapis.com/token")
        .form(&[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
            ("redirect_uri", &callback_url),
            ("grant_type", "authorization_code"),
        ])
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("Google token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        tracing::error!("Google token exchange returned {}", token_resp.status());
        return Ok(Redirect::to("/login?error=sso_failed").into_response());
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("Google token parse failed: {e}")))?;

    let id_token = token_data["id_token"]
        .as_str()
        .ok_or_else(|| ApiError::Internal("missing id_token from Google".into()))?;

    // Decode the ID token (we trust Google's signing)
    let parts: Vec<&str> = id_token.split('.').collect();
    if parts.len() != 3 {
        return Err(ApiError::Internal("invalid Google ID token format".into()));
    }
    let payload = base64::Engine::decode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        parts[1],
    )
    .map_err(|_| ApiError::Internal("invalid Google ID token encoding".into()))?;

    let claims: serde_json::Value = serde_json::from_slice(&payload)
        .map_err(|_| ApiError::Internal("invalid Google ID token payload".into()))?;

    let google_email = claims["email"]
        .as_str()
        .ok_or_else(|| ApiError::Internal("email not in Google ID token".into()))?;
    let google_name = claims["name"].as_str().unwrap_or("");

    // Find or create user
    complete_sso_login(&state, google_email, google_name, "google").await
}

async fn sso_github_callback(
    State(state): State<AppState>,
    Query(params): Query<OAuthCallbackQuery>,
) -> Result<Response, ApiError> {
    if let Some(error) = &params.error {
        tracing::warn!(error = %error, "GitHub OAuth error");
        return Ok(Redirect::to("/login?error=sso_denied").into_response());
    }

    let code = params
        .code
        .as_deref()
        .ok_or_else(|| ApiError::BadRequest("missing authorization code".into()))?;

    let client_id = state
        .config
        .github_client_id
        .as_deref()
        .ok_or_else(|| ApiError::Internal("GitHub SSO not configured".into()))?;
    let client_secret = state
        .config
        .github_client_secret
        .as_deref()
        .ok_or_else(|| ApiError::Internal("GitHub SSO secret not configured".into()))?;

    // Exchange code for access token
    let token_resp = state
        .http_client
        .post("https://github.com/login/oauth/access_token")
        .header("Accept", "application/json")
        .form(&[
            ("code", code),
            ("client_id", client_id),
            ("client_secret", client_secret),
        ])
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("GitHub token exchange failed: {e}")))?;

    if !token_resp.status().is_success() {
        return Ok(Redirect::to("/login?error=sso_failed").into_response());
    }

    let token_data: serde_json::Value = token_resp
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("GitHub token parse failed: {e}")))?;

    let access_token = token_data["access_token"]
        .as_str()
        .ok_or_else(|| ApiError::Internal("missing access_token from GitHub".into()))?;

    // Fetch user profile
    let user_resp = state
        .http_client
        .get("https://api.github.com/user")
        .header("Authorization", format!("Bearer {access_token}"))
        .header("User-Agent", "ApexMail/1.0")
        .send()
        .await
        .map_err(|e| ApiError::Internal(format!("GitHub user fetch failed: {e}")))?;

    let user_data: serde_json::Value = user_resp
        .json()
        .await
        .map_err(|e| ApiError::Internal(format!("GitHub user parse failed: {e}")))?;

    // Fetch user emails (may not be public)
    let email = if let Some(email) = user_data["email"].as_str() {
        email.to_string()
    } else {
        // Fetch from /user/emails endpoint
        let emails_resp = state
            .http_client
            .get("https://api.github.com/user/emails")
            .header("Authorization", format!("Bearer {access_token}"))
            .header("User-Agent", "ApexMail/1.0")
            .send()
            .await
            .map_err(|e| ApiError::Internal(format!("GitHub emails fetch failed: {e}")))?;

        let emails: Vec<serde_json::Value> = emails_resp
            .json()
            .await
            .unwrap_or_default();

        emails
            .iter()
            .find(|e| e["primary"].as_bool() == Some(true))
            .and_then(|e| e["email"].as_str())
            .or_else(|| emails.first().and_then(|e| e["email"].as_str()))
            .ok_or_else(|| ApiError::Internal("no email found for GitHub user".into()))?
            .to_string()
    };

    let name = user_data["name"]
        .as_str()
        .or_else(|| user_data["login"].as_str())
        .unwrap_or("");

    complete_sso_login(&state, &email, name, "github").await
}

// ─── Shared SSO completion ────────────────────────────────────

async fn complete_sso_login(
    state: &AppState,
    email: &str,
    name: &str,
    provider: &str,
) -> Result<Response, ApiError> {
    use chrono::Utc;
    use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};

    let email_lower = email.to_lowercase();

    // Look up existing user
    let existing: Option<(uuid::Uuid, uuid::Uuid, String, Option<String>, String, String)> =
        sqlx::query_as(
            "SELECT id, tenant_id, email, name, role, status FROM users WHERE LOWER(email) = LOWER($1) LIMIT 1",
        )
        .bind(&email_lower)
        .fetch_optional(&state.db)
        .await?;

    let (user_id, tenant_id, role) = match existing {
        Some((id, tid, _email, _name, role, status)) => {
            if status != "active" {
                return Ok(Redirect::to("/login?error=account_inactive").into_response());
            }
            // Update SSO metadata
            sqlx::query(
                "UPDATE users SET metadata = metadata || $1::jsonb, updated_at = NOW() WHERE id = $2",
            )
            .bind(serde_json::json!({
                "last_sso_provider": provider,
                "last_sso_login": Utc::now().to_rfc3339(),
            }))
            .bind(id)
            .execute(&state.db)
            .await?;

            (id, tid, role)
        }
        None => {
            // Auto-provision: create tenant + user for SSO-first signup
            let tenant_id = uuid::Uuid::new_v4();
            let user_id = uuid::Uuid::new_v4();
            let now = Utc::now();
            let company_name = name.split_whitespace().next().unwrap_or("My Company");
            let slug = format!(
                "{}-{}",
                company_name
                    .chars()
                    .map(|c| if c.is_alphanumeric() { c.to_ascii_lowercase() } else { '-' })
                    .collect::<String>()
                    .trim_matches('-'),
                &uuid::Uuid::new_v4().to_string()[..8]
            );

            // Create placeholder password hash for SSO-only accounts
            let sso_placeholder_hash = format!("$sso${provider}$no-password-sso-login-only");

            sqlx::query(
                "INSERT INTO tenants (id, name, slug, plan, status, settings, metadata, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9)",
            )
            .bind(tenant_id)
            .bind(company_name)
            .bind(&slug)
            .bind("free")
            .bind("active")
            .bind(serde_json::json!({}))
            .bind(serde_json::json!({"sso_provider": provider}))
            .bind(now)
            .bind(now)
            .execute(&state.db)
            .await?;

            sqlx::query(
                "INSERT INTO users (id, tenant_id, email, name, password_hash, role, status, email_verified, mfa_enabled, metadata, created_at, updated_at)
                 VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)",
            )
            .bind(user_id)
            .bind(tenant_id)
            .bind(&email_lower)
            .bind(name)
            .bind(&sso_placeholder_hash)
            .bind("owner")
            .bind("active")
            .bind(true) // SSO emails are pre-verified
            .bind(false)
            .bind(serde_json::json!({"sso_provider": provider}))
            .bind(now)
            .bind(now)
            .execute(&state.db)
            .await?;

            tracing::info!(
                user_id = %user_id,
                tenant_id = %tenant_id,
                provider = %provider,
                "SSO user auto-provisioned"
            );

            (user_id, tenant_id, "owner".to_string())
        }
    };

    // Generate JWT
    let expiry_secs = state.config.jwt_expiry.as_secs() as i64;
    let now = Utc::now();
    let exp = now + chrono::Duration::seconds(expiry_secs);

    let scopes = match role.as_str() {
        "admin" | "owner" => vec!["*".into()],
        "developer" => vec![
            "messages:send".into(), "messages:read".into(), "domains:read".into(),
            "templates:read".into(), "templates:write".into(), "events:read".into(),
            "analytics:read".into(), "contacts:read".into(), "contacts:write".into(),
        ],
        "viewer" => vec![
            "messages:read".into(), "domains:read".into(), "templates:read".into(),
            "events:read".into(), "analytics:read".into(), "contacts:read".into(),
        ],
        _ => vec!["messages:read".into()],
    };

    let claims = crate::middleware::auth::JwtClaims {
        sub: user_id.to_string(),
        tenant_id: tenant_id.to_string(),
        scopes,
        exp: exp.timestamp(),
        iat: now.timestamp(),
    };

    let token = encode(
        &Header::new(Algorithm::RS256),
        &claims,
        &EncodingKey::from_rsa_pem(state.config.jwt_private_key_pem.as_bytes())
            .map_err(|e| ApiError::Internal(format!("JWT key error: {e}")))?,
    )
    .map_err(|e| ApiError::Internal(format!("token generation failed: {e}")))?;

    // Redirect to dashboard with token in cookie
    let mut response = Redirect::to("/dashboard").into_response();
    let cookie_value = format!(
        "am_session={token}; HttpOnly; Path=/; Max-Age={expiry_secs}; SameSite=Lax{}",
        if state.config.environment.is_production() { "; Secure" } else { "" }
    );
    response.headers_mut().insert(
        "Set-Cookie",
        cookie_value.parse().unwrap_or_else(|_| "".parse().unwrap()),
    );

    Ok(response)
}

// ─── Helpers ───────────────────────────────────────────────────

fn generate_oauth_state(next: &str) -> String {
    use sha2::Digest;
    let random_bytes: [u8; 32] = rand_bytes();
    let hash = sha2::Sha256::digest(&random_bytes);
    let state_token = base64::Engine::encode(
        &base64::engine::general_purpose::URL_SAFE_NO_PAD,
        &hash,
    );
    // Encode the return path into the state so we can redirect back
    format!("{state_token}:{next}")
}

fn rand_bytes() -> [u8; 32] {
    use std::collections::hash_map::RandomState;
    use std::hash::{BuildHasher, Hasher};
    let mut buf = [0u8; 32];
    for chunk in buf.chunks_mut(8) {
        let s = RandomState::new();
        let mut h = s.build_hasher();
        h.write_u64(std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_nanos() as u64);
        let val = h.finish().to_ne_bytes();
        let len = chunk.len().min(8);
        chunk[..len].copy_from_slice(&val[..len]);
    }
    buf
}

fn sanitize_redirect(next: &str) -> String {
    // Only allow relative paths starting with /
    if next.starts_with('/') && !next.starts_with("//") {
        next.to_string()
    } else {
        "/dashboard".to_string()
    }
}

fn set_state_cookie(response: &mut Response, name: &str, value: &str, secure: bool) {
    let cookie = format!(
        "{name}={value}; HttpOnly; Path=/; Max-Age=600; SameSite=Lax{}",
        if secure { "; Secure" } else { "" }
    );
    if let Ok(val) = cookie.parse() {
        response.headers_mut().append("Set-Cookie", val);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sanitize_redirect() {
        assert_eq!(sanitize_redirect("/dashboard"), "/dashboard");
        assert_eq!(sanitize_redirect("/settings/billing"), "/settings/billing");
        assert_eq!(sanitize_redirect("https://evil.com"), "/dashboard");
        assert_eq!(sanitize_redirect("//evil.com"), "/dashboard");
        assert_eq!(sanitize_redirect(""), "/dashboard");
    }

    #[test]
    fn test_generate_oauth_state() {
        let state = generate_oauth_state("/dashboard");
        assert!(state.contains("/dashboard"));
        assert!(state.len() > 10);
    }
}
